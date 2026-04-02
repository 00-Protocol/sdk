/**
 * @00-protocol/sdk — BIP352 Stealth Address Module
 *
 * ECDH-based stealth addresses for Bitcoin Cash.
 * v2 — BIP352 aggregated ECDH: sender sums all input private keys,
 * receiver sums all input public keys → 1 ECDH per TX.
 *
 * @module @00-protocol/sdk/stealth
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import {
  h2b, b2h, concat, u32LE, rand,
  bip32Master, bip32Child, deriveBip352Node,
  pubHashToCashAddr, cashAddrToHash20,
} from '../common/index.js';

/** secp256k1 curve order */
const N_SECP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/* ========================================================================
   Internal helpers
   ======================================================================== */

/** Lexicographic byte comparison. Returns negative / 0 / positive. */
function _compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/* ========================================================================
   Low-Level Stealth Primitives
   ======================================================================== */

/**
 * Derive a one-time stealth public key (sender side, single-input).
 *
 * ECDH: senderPriv x recipScanPub => shared secret
 * Tweak: c = SHA256( SHA256(sharedX) || tweakData )
 * Stealth pubkey: recipSpendPub + c*G
 *
 * @param {Uint8Array} senderPriv - Sender's private key (32 bytes)
 * @param {Uint8Array} recipScanPub - Recipient's scan public key (33 bytes compressed)
 * @param {Uint8Array} recipSpendPub - Recipient's spend public key (33 bytes compressed)
 * @param {Uint8Array} tweakData - Additional tweak data
 * @returns {{ pub: Uint8Array, cBig: bigint }} Stealth public key and tweak scalar
 */
export function stealthDerive(senderPriv, recipScanPub, recipSpendPub, tweakData) {
  const sharedPoint = secp256k1.getSharedSecret(senderPriv, recipScanPub);
  const sharedX = sharedPoint.slice(1, 33);
  const c = sha256(concat(sha256(sharedX), tweakData));
  const cBig = BigInt('0x' + b2h(c)) % N_SECP;
  const spendPoint = secp256k1.ProjectivePoint.fromHex(recipSpendPub);
  const tweakPoint = secp256k1.ProjectivePoint.BASE.multiply(cBig);
  const stealthPoint = spendPoint.add(tweakPoint);
  const stealthPub = stealthPoint.toRawBytes(true);
  return { pub: stealthPub, cBig };
}

/**
 * Scan for a stealth payment (receiver side, single pubkey).
 *
 * @param {Uint8Array} scanPriv - Receiver's scan private key (32 bytes)
 * @param {Uint8Array} senderPub - Sender's public key from TX input (33 bytes)
 * @param {Uint8Array} spendPub - Receiver's spend public key (33 bytes)
 * @param {Uint8Array} tweakData - Tweak data
 * @returns {{ pub: Uint8Array, cBig: bigint }}
 */
export function stealthScan(scanPriv, senderPub, spendPub, tweakData) {
  const sharedPoint = secp256k1.getSharedSecret(scanPriv, senderPub);
  const sharedX = sharedPoint.slice(1, 33);
  const c = sha256(concat(sha256(sharedX), tweakData));
  const cBig = BigInt('0x' + b2h(c)) % N_SECP;
  const spendPoint = secp256k1.ProjectivePoint.fromHex(spendPub);
  const tweakPoint = secp256k1.ProjectivePoint.BASE.multiply(cBig);
  const stealthPoint = spendPoint.add(tweakPoint);
  return { pub: stealthPoint.toRawBytes(true), cBig };
}

/**
 * Compute the private spending key for a stealth output.
 *
 * spendingKey = spendPriv + c  (mod N)
 *
 * @param {Uint8Array} spendPriv - Receiver's spend private key (32 bytes)
 * @param {bigint} cBig - Tweak scalar from stealthScan or scanForStealthPayments
 * @returns {Uint8Array} 32-byte private key for the stealth output
 */
export function stealthSpendingKey(spendPriv, cBig) {
  const bBig = BigInt('0x' + b2h(spendPriv));
  return h2b(((bBig + cBig) % N_SECP).toString(16).padStart(64, '0'));
}

/**
 * Convert a stealth public key to a BCH CashAddr.
 * @param {Uint8Array} stealthPub - Compressed stealth public key (33 bytes)
 * @returns {string} BCH CashAddr
 */
export function stealthPubToAddr(stealthPub) {
  return pubHashToCashAddr(ripemd160(sha256(stealthPub)));
}

/**
 * Encode scan + spend public keys as a stealth code string.
 * Format: "stealth:" + hex(scanPub) + hex(spendPub)
 *
 * @param {Uint8Array} scanPub - Scan public key (33 bytes)
 * @param {Uint8Array} spendPub - Spend public key (33 bytes)
 * @returns {string}
 */
export function encodeStealthCode(scanPub, spendPub) {
  return 'stealth:' + b2h(scanPub) + b2h(spendPub);
}

/**
 * Decode a stealth code string into scan and spend public keys.
 * @param {string} code - Stealth code ("stealth:" + 132 hex chars)
 * @returns {{ scanPub: Uint8Array, spendPub: Uint8Array }}
 */
export function decodeStealthCode(code) {
  const hex = code.replace(/^stealth:/, '');
  if (hex.length !== 132) throw new Error('invalid stealth code length');
  return {
    scanPub: h2b(hex.slice(0, 66)),
    spendPub: h2b(hex.slice(66, 132)),
  };
}

/**
 * Check if a TX output matches our stealth address.
 *
 * @param {Uint8Array} scanPriv - Receiver's scan private key
 * @param {Uint8Array} spendPub - Receiver's spend public key
 * @param {Uint8Array} senderInputPub - Sender's input public key
 * @param {Uint8Array} outputHash160 - Hash160 of the TX output
 * @param {Uint8Array} tweakData - Tweak data
 * @returns {boolean} true if the output belongs to us
 */
export function checkStealthMatch(scanPriv, spendPub, senderInputPub, outputHash160, tweakData) {
  const { pub } = stealthScan(scanPriv, senderInputPub, spendPub, tweakData);
  const expectedHash = ripemd160(sha256(pub));
  return b2h(expectedHash) === b2h(outputHash160);
}

/* ========================================================================
   BIP352 Aggregated ECDH — Send
   ======================================================================== */

/**
 * Derive a stealth address for sending to a recipient (BIP352 aggregated ECDH).
 *
 * The sender aggregates all input private keys into a_sum, derives the
 * corresponding public key A_sum, then computes:
 *   input_hash = SHA256(smallest_outpoint || A_sum)
 *   shared     = (a_sum × input_hash) × B_scan
 *   t_k        = SHA256(sharedX || ser_32(k))
 *   P_k        = B_spend + t_k × G
 *
 * Backward compatible: if no outpoints provided, falls back to single-input
 * ECDH (useful for testing / legacy support).
 *
 * @param {Uint8Array}              recipScanPub   - Recipient scan pubkey (33 bytes)
 * @param {Uint8Array}              recipSpendPub  - Recipient spend pubkey (33 bytes)
 * @param {Uint8Array|Uint8Array[]} senderPrivKeys - All sender input private keys
 * @param {Array}                   [outpoints]    - [{ txid: string (big-endian hex), vout: number }]
 * @param {number}                  [outputIndex]  - Output index k (default 0)
 * @returns {{ addr: string, pub: Uint8Array, A_sum: Uint8Array }}
 */
export function deriveStealthSendAddr(recipScanPub, recipSpendPub, senderPrivKeys, outpoints, outputIndex = 0) {
  if (!Array.isArray(senderPrivKeys)) senderPrivKeys = [senderPrivKeys];

  // ── Legacy fallback: no outpoints ────────────────────────────────────────
  if (!outpoints || outpoints.length === 0) {
    const priv = typeof senderPrivKeys[0] === 'string' ? h2b(senderPrivKeys[0]) : senderPrivKeys[0];
    const senderPub = secp256k1.getPublicKey(priv, true);
    const shared = secp256k1.getSharedSecret(priv, recipScanPub);
    const sharedX = shared.slice(1, 33);
    const c = sha256(concat(sha256(sharedX), senderPub));
    const cBig = BigInt('0x' + b2h(c)) % N_SECP;
    const spendPoint = secp256k1.ProjectivePoint.fromHex(recipSpendPub);
    const stealthPoint = spendPoint.add(secp256k1.ProjectivePoint.BASE.multiply(cBig));
    const stealthPubBytes = stealthPoint.toRawBytes(true);
    return {
      addr: pubHashToCashAddr(ripemd160(sha256(stealthPubBytes))),
      pub: stealthPubBytes,
      A_sum: senderPub,
    };
  }

  // ── BIP352 aggregation ────────────────────────────────────────────────────

  // 1. a_sum = Σ a_i  mod N
  let a_sum = 0n;
  for (const priv of senderPrivKeys) {
    const privBytes = typeof priv === 'string' ? h2b(priv) : priv;
    a_sum = (a_sum + BigInt('0x' + b2h(privBytes))) % N_SECP;
  }
  const a_sum_bytes = h2b(a_sum.toString(16).padStart(64, '0'));
  const A_sum = secp256k1.getPublicKey(a_sum_bytes, true); // A_sum = a_sum × G

  // 2. Smallest outpoint: lex-min of (txid_LE || vout_LE 4-byte)
  //    Wallet txids are big-endian (human-readable) → reverse to wire LE
  let smallest = null;
  for (const op of outpoints) {
    const txidHex = typeof op.txid === 'string' ? op.txid : b2h(op.txid);
    const txidLE = h2b(txidHex).reverse();
    const outpoint = concat(txidLE, u32LE(op.vout || 0));
    if (!smallest || _compareBytes(outpoint, smallest) < 0) smallest = outpoint;
  }

  // 3. input_hash = SHA256(smallest_outpoint || A_sum)
  const input_hash = sha256(concat(smallest, A_sum));
  const input_hash_big = BigInt('0x' + b2h(input_hash)) % N_SECP;

  // 4. Tweaked ECDH: shared = (a_sum × input_hash) × B_scan
  const tweaked_a = (a_sum * input_hash_big) % N_SECP;
  const tweaked_a_bytes = h2b(tweaked_a.toString(16).padStart(64, '0'));
  const shared = secp256k1.getSharedSecret(tweaked_a_bytes, recipScanPub);
  const sharedX = shared.slice(1, 33);

  // 5. t_k = SHA256(sharedX || ser_32(k))
  const t = sha256(concat(sharedX, u32LE(outputIndex)));
  const tBig = BigInt('0x' + b2h(t)) % N_SECP;

  // 6. P_k = B_spend + t_k × G
  const spendPoint = secp256k1.ProjectivePoint.fromHex(recipSpendPub);
  const stealthPoint = spendPoint.add(secp256k1.ProjectivePoint.BASE.multiply(tBig));
  const stealthPubBytes = stealthPoint.toRawBytes(true);

  return {
    addr: pubHashToCashAddr(ripemd160(sha256(stealthPubBytes))),
    pub: stealthPubBytes,
    A_sum,
  };
}

/* ========================================================================
   BIP352 Aggregated ECDH — Scan
   ======================================================================== */

/**
 * Scan indexer entries for stealth payments addressed to us (BIP352 aggregated).
 *
 * Groups entries by txid. For each TX:
 *   A_sum       = Σ input pubkeys (EC point addition)
 *   input_hash  = SHA256(smallest_outpoint || A_sum)
 *   shared      = (b_scan × input_hash) × A_sum   [1 ECDH per TX]
 *   t_k         = SHA256(sharedX || ser_32(k))
 *   P_k         = B_spend + t_k × G
 *
 * Falls back to legacy single-input ECDH when entries lack outpoint data (v1 compat).
 *
 * @param {Object} keys    - { scanPriv, spendPub, spendPriv? } as Uint8Array or hex strings
 * @param {Array}  entries - [{ txid, pubkey, height, outpointTxid?, outpointVout? }]
 * @param {Function} [fetchTx] - Async fn(txid) => rawHex. Required for output matching.
 * @returns {Promise<Array>} Found payments [{ txid, height, value, outputIdx, addr, tBig }]
 */
export async function scanForStealthPayments(keys, entries, fetchTx) {
  const scanPriv = typeof keys.scanPriv === 'string' ? h2b(keys.scanPriv) : keys.scanPriv;
  const spendPub = typeof keys.spendPub === 'string' ? h2b(keys.spendPub) : keys.spendPub;
  if (!scanPriv || !spendPub) throw new Error('scanForStealthPayments: scanPriv and spendPub required');
  if (!fetchTx) throw new Error('scanForStealthPayments: fetchTx callback required');

  const scanPrivBig = BigInt('0x' + b2h(scanPriv)) % N_SECP;

  // Group by txid
  const txMap = new Map();
  for (const e of entries) {
    if (!e.pubkey || !e.txid) continue;
    if (!txMap.has(e.txid)) txMap.set(e.txid, []);
    txMap.get(e.txid).push(e);
  }

  const found = [];

  for (const [txid, inputs] of txMap) {
    const hasOutpoints = inputs.some(inp => inp.outpointTxid != null);

    if (!hasOutpoints) {
      // Legacy: single-input ECDH (v1 compat)
      let rawHex;
      try { rawHex = await fetchTx(txid); } catch { continue; }
      if (!rawHex) continue;

      const seenPubs = new Set();
      for (const inp of inputs) {
        const pubHex = typeof inp.pubkey === 'string' ? inp.pubkey : b2h(inp.pubkey);
        if (seenPubs.has(pubHex)) continue;
        seenPubs.add(pubHex);
        try {
          const senderPub = h2b(pubHex);
          const shared = secp256k1.getSharedSecret(scanPriv, senderPub);
          const sharedX = shared.slice(1, 33);
          const c = sha256(concat(sha256(sharedX), senderPub));
          const cBig = BigInt('0x' + b2h(c)) % N_SECP;
          const spendPoint = secp256k1.ProjectivePoint.fromHex(spendPub);
          const stealthPubBytes = spendPoint.add(secp256k1.ProjectivePoint.BASE.multiply(cBig)).toRawBytes(true);
          const expectedHash = b2h(ripemd160(sha256(stealthPubBytes)));
          const addr = pubHashToCashAddr(ripemd160(sha256(stealthPubBytes)));
          for (const m of _matchOutputs(rawHex, expectedHash)) {
            found.push({ txid, height: inp.height, value: m.value, outputIdx: m.idx, addr, tBig: cBig });
          }
        } catch { /* invalid pubkey */ }
      }
      continue;
    }

    // BIP352 path
    let A_sum = null;
    for (const inp of inputs) {
      const pubHex = typeof inp.pubkey === 'string' ? inp.pubkey : b2h(inp.pubkey);
      try {
        const pt = secp256k1.ProjectivePoint.fromHex(pubHex);
        A_sum = A_sum ? A_sum.add(pt) : pt;
      } catch { continue; }
    }
    if (!A_sum) continue;
    const A_sum_bytes = A_sum.toRawBytes(true);

    let smallest = null;
    for (const inp of inputs) {
      if (inp.outpointTxid == null) continue;
      const txidHex = typeof inp.outpointTxid === 'string' ? inp.outpointTxid : b2h(inp.outpointTxid);
      const txidLE = h2b(txidHex).reverse();
      const outpoint = concat(txidLE, u32LE(inp.outpointVout || 0));
      if (!smallest || _compareBytes(outpoint, smallest) < 0) smallest = outpoint;
    }
    if (!smallest) continue;

    const input_hash = sha256(concat(smallest, A_sum_bytes));
    const input_hash_big = BigInt('0x' + b2h(input_hash)) % N_SECP;

    const tweakedScanPrivBig = (scanPrivBig * input_hash_big) % N_SECP;
    const tweakedScanPriv = h2b(tweakedScanPrivBig.toString(16).padStart(64, '0'));

    const shared = secp256k1.getSharedSecret(tweakedScanPriv, A_sum_bytes);
    const sharedX = shared.slice(1, 33);

    let rawHex;
    try { rawHex = await fetchTx(txid); } catch { continue; }
    if (!rawHex) continue;

    for (let k = 0; k < 3; k++) {
      const t = sha256(concat(sharedX, u32LE(k)));
      const tBig = BigInt('0x' + b2h(t)) % N_SECP;

      const spendPoint = secp256k1.ProjectivePoint.fromHex(spendPub);
      const stealthPubBytes = spendPoint.add(secp256k1.ProjectivePoint.BASE.multiply(tBig)).toRawBytes(true);
      const expectedHash = b2h(ripemd160(sha256(stealthPubBytes)));
      const addr = pubHashToCashAddr(ripemd160(sha256(stealthPubBytes)));

      const matches = _matchOutputs(rawHex, expectedHash);
      if (matches.length === 0) break;

      for (const m of matches) {
        found.push({
          txid,
          height: inputs[0]?.height,
          value: m.value,
          outputIdx: m.idx,
          addr,
          tBig,
        });
      }
    }
  }

  return found;
}

/* ========================================================================
   Self-Stealth (Fusion outputs / stealth change)
   ======================================================================== */

/**
 * Derive a self-stealth address for CoinJoin fusion outputs or stealth change.
 *
 * @param {Uint8Array} inputPriv - Private key of the input being spent (32 bytes)
 * @param {Uint8Array} scanPub - Own stealth scan public key (33 bytes)
 * @param {Uint8Array} spendPub - Own stealth spend public key (33 bytes)
 * @param {Uint8Array} spendPriv - Own stealth spend private key (32 bytes)
 * @param {Uint8Array} outpoint - TXID:vout of the input (36 bytes)
 * @param {number} outputIdx - Output index in the transaction
 * @returns {{ addr: string, pub: Uint8Array, priv: Uint8Array }}
 */
export function deriveSelfStealth(inputPriv, scanPub, spendPub, spendPriv, outpoint, outputIdx) {
  const shared = secp256k1.getSharedSecret(inputPriv, scanPub);
  const sharedX = shared.slice(1, 33);

  const nonce = concat(outpoint, u32LE(outputIdx));
  const c = sha256(concat(sha256(sharedX), nonce));
  const cBig = BigInt('0x' + b2h(c)) % N_SECP;

  const spendPoint = secp256k1.ProjectivePoint.fromHex(spendPub);
  const stealthPoint = spendPoint.add(secp256k1.ProjectivePoint.BASE.multiply(cBig));
  const stealthPubBytes = stealthPoint.toRawBytes(true);

  const addr = pubHashToCashAddr(ripemd160(sha256(stealthPubBytes)));

  const bBig = BigInt('0x' + b2h(spendPriv));
  const pBig = (bBig + cBig) % N_SECP;
  const privKey = h2b(pBig.toString(16).padStart(64, '0'));

  return { addr, pub: stealthPubBytes, priv: privKey };
}

/* ========================================================================
   Raw TX Parser — input pubkeys + outpoints
   ======================================================================== */

/**
 * Parse a raw transaction hex and extract all P2PKH input pubkeys + outpoints.
 * Returns entries compatible with scanForStealthPayments.
 *
 * @param {string} rawHex - Raw transaction hex string
 * @param {string} [txid] - Transaction ID (big-endian hex). Computed if omitted.
 * @returns {Array} [{ txid, vin, pubkey, outpointTxid, outpointVout, height }]
 */
export function parseRawTxInputs(rawHex, txid) {
  const results = [];
  try {
    const raw = h2b(rawHex);

    if (!txid) {
      const h1 = sha256(raw);
      const h2 = sha256(h1);
      txid = b2h(new Uint8Array([...h2].reverse()));
    }

    let offset = 4; // version
    const { value: inputCount, next: afterCount } = _readVarInt(raw, offset);
    offset = afterCount;

    for (let vin = 0; vin < inputCount; vin++) {
      const prevTxidLE = raw.slice(offset, offset + 32);
      offset += 32;
      const vout = raw[offset] | (raw[offset+1] << 8) | (raw[offset+2] << 16) | (raw[offset+3] << 24);
      offset += 4;

      const { value: scriptLen, next: afterScriptLen } = _readVarInt(raw, offset);
      offset = afterScriptLen;
      const script = raw.slice(offset, offset + scriptLen);
      offset += scriptLen;
      offset += 4; // sequence

      // P2PKH scriptSig: <sigPush><DER_sig+sighash><0x21><33-byte-pubkey>
      if (script.length >= 35) {
        const sigLen = script[0];
        if (sigLen >= 0x47 && sigLen <= 0x49 && script[sigLen + 1] === 0x21) {
          const pk = script.slice(sigLen + 2, sigLen + 2 + 33);
          if ((pk[0] === 0x02 || pk[0] === 0x03) && pk.length === 33) {
            results.push({
              txid,
              vin,
              pubkey: b2h(pk),
              outpointTxid: b2h(new Uint8Array([...prevTxidLE].reverse())),
              outpointVout: vout,
              height: 0,
            });
          }
        }
      }
    }
  } catch { /* partial parse ok */ }
  return results;
}

/* ========================================================================
   StealthKeys Class — High-Level API
   ======================================================================== */

/**
 * High-level stealth key management class.
 *
 * Encapsulates BIP352 scan/spend keypairs and provides methods for
 * deriving receive addresses, sending to stealth codes, and scanning
 * for incoming payments.
 *
 * @example
 * const sk = StealthKeys.fromSeed(seedHex);
 * const code = sk.stealthCode;           // share with payers
 * const { addr } = StealthKeys.deriveSendAddress(code, [privKey], [outpoint]);
 * const found = await sk.scan(entries, fetchTxFn);
 */
export class StealthKeys {
  /**
   * @param {Uint8Array} scanPriv - Scan private key (32 bytes)
   * @param {Uint8Array} scanPub - Scan public key (33 bytes compressed)
   * @param {Uint8Array} spendPriv - Spend private key (32 bytes)
   * @param {Uint8Array} spendPub - Spend public key (33 bytes compressed)
   */
  constructor(scanPriv, scanPub, spendPriv, spendPub) {
    this.scanPriv = scanPriv;
    this.scanPub = scanPub;
    this.spendPriv = spendPriv;
    this.spendPub = spendPub;
  }

  /**
   * Derive stealth keys from a BIP39 seed at the BIP352 path:
   * m/352'/145'/0'/0'/0 (spend) and m/352'/145'/0'/1'/0 (scan)
   *
   * @param {string|Uint8Array} seed - Hex string or raw seed bytes (64 bytes)
   * @returns {StealthKeys}
   */
  static fromSeed(seed) {
    const seedBytes = typeof seed === 'string' ? h2b(seed) : seed;
    const stealthNode = deriveBip352Node(seedBytes);

    const spend = bip32Child(stealthNode.priv, stealthNode.chain, 0x80000000, true);
    const spendKey = bip32Child(spend.priv, spend.chain, 0, false);

    const scan = bip32Child(stealthNode.priv, stealthNode.chain, 0x80000001, true);
    const scanKey = bip32Child(scan.priv, scan.chain, 0, false);

    return new StealthKeys(
      scanKey.priv,
      secp256k1.getPublicKey(scanKey.priv, true),
      spendKey.priv,
      secp256k1.getPublicKey(spendKey.priv, true),
    );
  }

  /**
   * Stealth code for sharing with payers.
   * Format: "stealth:" + hex(scanPub) + hex(spendPub)
   * @returns {string}
   */
  get stealthCode() {
    return encodeStealthCode(this.scanPub, this.spendPub);
  }

  /**
   * Static: derive a one-time send address from a stealth code (BIP352).
   *
   * @param {string}              stealthCode    - Recipient's stealth code
   * @param {Uint8Array|Uint8Array[]} senderPrivKeys - Sender input private key(s)
   * @param {Array}               [outpoints]    - [{ txid, vout }] — enables BIP352 aggregation
   * @param {number}              [outputIndex]  - Output index k (default 0)
   * @returns {{ addr: string, pub: Uint8Array, A_sum: Uint8Array }}
   */
  static deriveSendAddress(stealthCode, senderPrivKeys, outpoints, outputIndex = 0) {
    const { scanPub, spendPub } = decodeStealthCode(stealthCode);
    return deriveStealthSendAddr(scanPub, spendPub, senderPrivKeys, outpoints, outputIndex);
  }

  /**
   * Scan indexer entries for incoming stealth payments (BIP352 aggregated).
   *
   * @param {Array}    entries - [{ txid, pubkey, height, outpointTxid?, outpointVout? }]
   * @param {Function} fetchTx - Async fn(txid) => rawHex
   * @returns {Promise<Array>} Found payments
   */
  scan(entries, fetchTx) {
    return scanForStealthPayments(
      { scanPriv: this.scanPriv, spendPub: this.spendPub, spendPriv: this.spendPriv },
      entries,
      fetchTx,
    );
  }

  /**
   * Derive a self-stealth address (for CoinJoin outputs or change).
   *
   * @param {Uint8Array} inputPriv - Private key of the input being spent
   * @param {Uint8Array} outpoint - TXID:vout of the input (36 bytes)
   * @param {number} outputIdx - Output index in the transaction
   * @returns {{ addr: string, pub: Uint8Array, priv: Uint8Array }}
   */
  deriveSelfAddress(inputPriv, outpoint, outputIdx) {
    return deriveSelfStealth(
      inputPriv, this.scanPub, this.spendPub, this.spendPriv,
      outpoint, outputIdx,
    );
  }
}

/* ========================================================================
   Internal TX output parser
   ======================================================================== */

function _matchOutputs(rawHex, targetHash160) {
  const matches = [];
  try {
    const raw = h2b(rawHex);
    let offset = 4;

    let inputCount = raw[offset++];
    if (inputCount === 0) { offset++; inputCount = raw[offset++]; }
    for (let i = 0; i < inputCount; i++) {
      offset += 36;
      const { value: scriptLen, next } = _readVarInt(raw, offset);
      offset = next + scriptLen + 4;
    }

    const { value: outputCount, next: afterOutputCount } = _readVarInt(raw, offset);
    offset = afterOutputCount;
    for (let i = 0; i < outputCount; i++) {
      const valueLo = raw[offset] | (raw[offset+1]<<8) | (raw[offset+2]<<16) | (raw[offset+3]<<24);
      const valueHi = raw[offset+4] | (raw[offset+5]<<8) | (raw[offset+6]<<16) | (raw[offset+7]<<24);
      const value = valueLo + valueHi * 0x100000000;
      offset += 8;

      const { value: scriptLen, next } = _readVarInt(raw, offset);
      offset = next;
      const script = raw.slice(offset, offset + scriptLen);
      offset += scriptLen;

      if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 &&
          script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
        if (b2h(script.slice(3, 23)) === targetHash160) {
          matches.push({ idx: i, value });
        }
      }
    }
  } catch {}
  return matches;
}

function _readVarInt(buf, offset) {
  const first = buf[offset];
  if (first < 0xfd) return { value: first, next: offset + 1 };
  if (first === 0xfd) return { value: buf[offset+1] | (buf[offset+2] << 8), next: offset + 3 };
  if (first === 0xfe) return { value: buf[offset+1] | (buf[offset+2]<<8) | (buf[offset+3]<<16) | (buf[offset+4]<<24), next: offset + 5 };
  return { value: 0, next: offset + 9 };
}
