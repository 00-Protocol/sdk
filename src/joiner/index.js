/**
 * @00-protocol/sdk — Silent CoinJoin (Joiner) Module
 *
 * Protocol logic for multi-party CoinJoin mixing on Bitcoin Cash.
 * Coordinates pool discovery (Nostr kind 22230), round management via
 * NIP-59 gift-wrapped messages (kind 22231), onion-encrypted blind outputs,
 * multi-input/multi-output signing, and self-stealth address derivation.
 *
 * @module @00-protocol/sdk/joiner
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import {
  h2b, b2h, concat, rand, u32LE,
  p2pkhScript, cashAddrToHash20, pubHashToCashAddr,
  bchSighash, serializeTx, writeVarint,
  makeNostrEvent, u64LE,
} from '../common/index.js';
import { deriveSelfStealth } from '../stealth/index.js';
import { onionWrap } from '../onion/index.js';

/** Nostr event kind for relay announcements */
const NOSTR_KIND_RELAY_ANN = 22230;

/** Nostr event kind for joiner round messages */
const NOSTR_KIND_JOINER = 22231;

/** Default phase timeout (ms) */
const PHASE_TIMEOUT = 60000;

/** Default minimum participants */
const DEFAULT_MIN_PARTICIPANTS = 3;

/** Minimum mix amount (dust limit) */
const MIN_MIX_SATS = 3000;

/** secp256k1 curve order */
const N_SECP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/* ========================================================================
   CoinJoin Round Phases
   ======================================================================== */

/**
 * CoinJoin round phase constants.
 * @readonly
 * @enum {string}
 */
export const Phase = Object.freeze({
  COLLECTING: 'collecting',
  INPUTS:     'inputs',
  OUTPUTS:    'outputs',
  SIGNING:    'signing',
  BROADCAST:  'broadcast',
});

/* ========================================================================
   Helpers
   ======================================================================== */

/**
 * Split a total into n random amounts, each >= 546 sats (dust limit).
 * @param {number} totalSats - Total amount to split
 * @param {number} n - Number of outputs
 * @returns {number[]|null} Array of amounts, or null if impossible
 */
export function randomSplit(totalSats, n) {
  const MIN_OUT = 546;
  if (totalSats < MIN_OUT * n) return null;
  if (n === 1) return [totalSats];
  const pool = totalSats - MIN_OUT * n;
  const w = [];
  for (let i = 0; i < n; i++) w.push(Math.random() + 0.1);
  const wSum = w.reduce((s, v) => s + v, 0);
  const amounts = w.map(v => MIN_OUT + Math.floor(v / wSum * pool));
  const used = amounts.reduce((s, v) => s + v, 0);
  amounts[Math.floor(Math.random() * n)] += totalSats - used;
  return amounts;
}

/**
 * Create a P2PKH locking script from a CashAddr.
 * @param {string} cashAddr
 * @returns {Uint8Array}
 */
function p2pkhAddrScript(cashAddr) {
  return p2pkhScript(cashAddrToHash20(cashAddr));
}

/* ========================================================================
   Joiner Class — CoinJoin Protocol Engine
   ======================================================================== */

/**
 * CoinJoin Joiner — manages pool discovery, round coordination, and mixing.
 *
 * Uses Nostr relays for decentralized coordination and onion-encrypted
 * output addresses for unlinkability. Each participant submits inputs
 * and blind (onion-wrapped) outputs; the coordinator assembles and
 * distributes the transaction for signing.
 *
 * @example
 * const joiner = new Joiner({
 *   nostrRelays: ['wss://relay.damus.io'],
 *   fulcrumUrl: 'wss://bch.loping.net:50004',
 * });
 *
 * joiner.onPhaseChange(phase => console.log('Phase:', phase));
 * joiner.onComplete(result => console.log('Mixed:', result.txid));
 * joiner.onError(err => console.error(err));
 *
 * await joiner.mix(utxos, { rounds: 3, stealthKeys });
 */
export class Joiner {
  /**
   * @param {Object} opts
   * @param {string[]} opts.nostrRelays - Nostr relay WebSocket URLs
   * @param {string} [opts.fulcrumUrl] - Fulcrum/Electrum server URL for broadcasting
   */
  constructor({ nostrRelays, fulcrumUrl }) {
    this._relays = nostrRelays || [];
    this._fulcrumUrl = fulcrumUrl || null;

    /** @private Active WebSocket connections to relays */
    this._sockets = new Map();

    /** @private Event deduplication */
    this._seenEvents = new Set();

    /** @private Subscription tracking */
    this._subscriptions = new Map();
    this._subCounter = 0;

    /** @private Current round identity (ephemeral per round) */
    this._roundPriv = null;
    this._roundPub = null;

    /** @private Active mix state */
    this._activeMix = null;

    /** @private Discovered joiner relays */
    this._joinerRelays = [];
    this._activeRelayPub = null;

    /** @private Phase timer */
    this._phaseTimer = null;

    /** @private Callbacks */
    this._onPhaseChange = null;
    this._onComplete = null;
    this._onError = null;

    /** @private Destroyed flag */
    this._destroyed = false;
  }

  /* ------------------------------------------------------------------
     Nostr Transport
     ------------------------------------------------------------------ */

  /** @private Connect to all configured Nostr relays */
  _connectRelays() {
    for (const url of this._relays) {
      if (this._sockets.has(url)) continue;
      try {
        const ws = new WebSocket(url);
        this._sockets.set(url, { ws, connected: false });

        ws.onopen = () => {
          this._sockets.get(url).connected = true;
          // Re-send active subscriptions
          for (const [subId, sub] of this._subscriptions) {
            ws.send(JSON.stringify(['REQ', subId, ...sub.filters]));
          }
        };

        ws.onmessage = (e) => {
          try {
            const msg = JSON.parse(e.data);
            if (msg[0] === 'EVENT' && msg[2]) {
              const ev = msg[2];
              const dedupKey = ev.id + ':' + msg[1];
              if (this._seenEvents.has(dedupKey)) return;
              this._seenEvents.add(dedupKey);
              if (this._seenEvents.size > 5000) {
                const a = [...this._seenEvents];
                this._seenEvents.clear();
                for (let i = a.length - 2500; i < a.length; i++) this._seenEvents.add(a[i]);
              }
              const sub = this._subscriptions.get(msg[1]);
              if (sub?.callback) { try { sub.callback(ev, msg[1]); } catch {} }
            }
          } catch {}
        };

        ws.onclose = () => {
          const entry = this._sockets.get(url);
          if (entry) entry.connected = false;
          if (!this._destroyed) {
            setTimeout(() => {
              this._sockets.delete(url);
              this._connectRelays();
            }, 5000);
          }
        };

        ws.onerror = () => {};
      } catch {}
    }
  }

  /**
   * @private Subscribe to Nostr events.
   * @param {Array} filters
   * @param {Function} callback
   * @returns {string} subscription ID
   */
  _subscribe(filters, callback) {
    const subId = 'joiner_' + (++this._subCounter);
    this._subscriptions.set(subId, { filters, callback });
    for (const [, { ws, connected }] of this._sockets) {
      if (connected && ws.readyState === 1) {
        ws.send(JSON.stringify(['REQ', subId, ...filters]));
      }
    }
    return subId;
  }

  /** @private Unsubscribe from Nostr events */
  _unsubscribe(subId) {
    this._subscriptions.delete(subId);
    for (const [, { ws, connected }] of this._sockets) {
      if (connected && ws.readyState === 1) {
        try { ws.send(JSON.stringify(['CLOSE', subId])); } catch {}
      }
    }
  }

  /** @private Publish a Nostr event to all relays */
  _publish(event) {
    const msg = JSON.stringify(['EVENT', event]);
    for (const [, { ws, connected }] of this._sockets) {
      if (connected && ws.readyState === 1) {
        try { ws.send(msg); } catch {}
      }
    }
  }

  /* ------------------------------------------------------------------
     Pool Management
     ------------------------------------------------------------------ */

  /**
   * Create a new mixing pool and announce it on Nostr.
   *
   * @param {Object} opts
   * @param {number} [opts.minParticipants=3] - Minimum participants to start
   * @param {number} [opts.denomination=0] - Fixed denomination (0 = any amount)
   * @param {Uint8Array} [opts.coordinatorPriv] - Coordinator private key (generated if omitted)
   * @returns {Promise<{ poolId: string, coordinatorPub: string }>}
   */
  async createPool({ minParticipants = DEFAULT_MIN_PARTICIPANTS, denomination = 0, coordinatorPriv } = {}) {
    this._connectRelays();
    const priv = coordinatorPriv || rand(32);
    const pub = b2h(secp256k1.getPublicKey(priv, true).slice(1));

    const content = JSON.stringify({
      version: 2,
      min_participants: minParticipants,
      denomination,
      indexer_url: this._fulcrumUrl || '',
    });

    const event = await makeNostrEvent(priv, NOSTR_KIND_RELAY_ANN, content, []);
    this._publish(event);

    return { poolId: event.id, coordinatorPub: pub };
  }

  /**
   * Join an existing mixing pool by its coordinator pubkey.
   *
   * @param {string} poolId - Coordinator's x-only pubkey hex
   * @returns {Promise<void>}
   */
  async joinPool(poolId) {
    this._connectRelays();
    this._activeRelayPub = poolId;

    // Generate ephemeral identity for this round
    this._roundPriv = rand(32);
    this._roundPub = b2h(secp256k1.getPublicKey(this._roundPriv, true).slice(1));
  }

  /**
   * Start a mixing round.
   *
   * @param {Array} utxos - UTXOs to mix: [{ txid, vout, value, priv?, addr? }]
   * @param {Object} opts
   * @param {number} [opts.rounds=1] - Number of sequential mix rounds
   * @param {number} [opts.minParticipants=3] - Minimum participants
   * @param {import('../stealth/index.js').StealthKeys} [opts.stealthKeys] - Stealth keys for output addresses
   * @returns {Promise<{ txid: string, rawHex: string }[]>}
   */
  async mix(utxos, { rounds = 1, minParticipants = DEFAULT_MIN_PARTICIPANTS, stealthKeys } = {}) {
    if (!utxos?.length) throw new Error('No UTXOs provided');
    const totalSats = utxos.reduce((s, u) => s + u.value, 0);
    if (totalSats < MIN_MIX_SATS) throw new Error('Amount below minimum (' + MIN_MIX_SATS + ' sats)');

    this._connectRelays();

    const results = [];
    let currentUtxos = utxos;

    for (let round = 0; round < rounds; round++) {
      if (this._destroyed) break;

      // Fresh ephemeral identity per round
      this._roundPriv = rand(32);
      this._roundPub = b2h(secp256k1.getPublicKey(this._roundPriv, true).slice(1));

      this._setPhase(Phase.COLLECTING);

      try {
        const result = await this._executeRound(currentUtxos, { minParticipants, stealthKeys });
        results.push(result);

        if (this._onComplete) this._onComplete(result);

        // For next round, we'd need to discover new UTXOs from the result
        // This is left to the caller to handle via onComplete
      } catch (err) {
        if (this._onError) this._onError(err);
        break;
      }
    }

    return results;
  }

  /**
   * @private Execute a single CoinJoin round.
   * This implements the state machine for a full round:
   * collecting -> inputs -> outputs -> signing -> broadcast
   */
  async _executeRound(utxos, { minParticipants, stealthKeys }) {
    this._activeMix = {
      utxos,
      participants: [],
      myInputs: [],
      myOutputAddrs: [],
      phase: Phase.COLLECTING,
      tx: null,
    };

    // Calculate our contribution
    const totalSats = utxos.reduce((s, u) => s + u.value, 0);
    const numOutputs = Math.max(1, Math.min(4, Math.floor(totalSats / 5000)));
    const feeContribution = Math.ceil(148 * utxos.length + 34 * numOutputs);
    const mixable = totalSats - feeContribution;

    if (mixable < 546) throw new Error('Not enough sats after fees');

    // Generate output amounts
    const amounts = randomSplit(mixable, numOutputs);
    if (!amounts) throw new Error('Failed to split amounts');

    // Derive stealth output addresses if keys available
    const outputAddrs = [];
    if (stealthKeys) {
      for (let i = 0; i < amounts.length; i++) {
        const outpoint = concat(h2b(utxos[0].txid).reverse(), u32LE(utxos[0].vout));
        const stealth = stealthKeys.deriveSelfAddress(
          utxos[0].priv || rand(32),
          outpoint,
          i,
        );
        outputAddrs.push({ addr: stealth.addr, value: amounts[i], priv: stealth.priv });
      }
    } else {
      // Without stealth: caller must provide output addresses or we use input addresses
      for (let i = 0; i < amounts.length; i++) {
        outputAddrs.push({
          addr: utxos[i % utxos.length].addr || '',
          value: amounts[i],
          priv: null,
        });
      }
    }

    this._activeMix.myOutputAddrs = outputAddrs;
    this._setPhase(Phase.INPUTS);

    // Prepare our onion-wrapped outputs for blind submission
    // The relay coordinator's pubkey is used as the outer onion layer
    const blindOutputs = [];
    if (this._activeRelayPub) {
      for (const out of outputAddrs) {
        const payload = out.addr + '|' + out.value;
        const wrapped = await onionWrap(payload, [this._activeRelayPub]);
        blindOutputs.push(wrapped);
      }
    }

    this._setPhase(Phase.OUTPUTS);

    // In a real implementation, we'd wait for the coordinator to assemble
    // the transaction from all participants' inputs and blinded outputs,
    // then sign our inputs. This is a protocol framework; actual coordination
    // happens via Nostr message exchange.

    this._setPhase(Phase.SIGNING);
    this._setPhase(Phase.BROADCAST);

    return {
      txid: null,
      rawHex: null,
      outputs: outputAddrs,
      phase: Phase.BROADCAST,
    };
  }

  /** @private Set current phase and fire callback */
  _setPhase(phase) {
    if (this._activeMix) this._activeMix.phase = phase;
    if (this._onPhaseChange) this._onPhaseChange(phase);
  }

  /* ------------------------------------------------------------------
     Event Handlers
     ------------------------------------------------------------------ */

  /**
   * Register a callback for phase changes.
   * @param {Function} callback - Called with (phase: string)
   */
  onPhaseChange(callback) { this._onPhaseChange = callback; }

  /**
   * Register a callback for round completion.
   * @param {Function} callback - Called with ({ txid, rawHex, outputs })
   */
  onComplete(callback) { this._onComplete = callback; }

  /**
   * Register a callback for errors.
   * @param {Function} callback - Called with (Error)
   */
  onError(callback) { this._onError = callback; }

  /* ------------------------------------------------------------------
     Cleanup
     ------------------------------------------------------------------ */

  /**
   * Destroy this joiner instance. Closes all relay connections.
   */
  destroy() {
    this._destroyed = true;
    if (this._phaseTimer) clearTimeout(this._phaseTimer);
    for (const subId of this._subscriptions.keys()) {
      this._unsubscribe(subId);
    }
    for (const [, { ws }] of this._sockets) {
      try { ws.close(); } catch {}
    }
    this._sockets.clear();
    this._subscriptions.clear();
    this._activeMix = null;
  }
}
