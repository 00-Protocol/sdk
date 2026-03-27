/**
 * @00-protocol/sdk — WizardConnect Module
 *
 * BCH HD Wallet Connection Protocol, compatible with RiftenLabs WizardConnect
 * (hdwalletv1). Uses Nostr NIP-17 encrypted messages via WebSocket relay for
 * transport. Enables xpub exchange and transaction signing between wallets
 * and dapps.
 *
 * Implements BOTH sides:
 * - WALLET: external dapps connect to receive xpubs and request TX signing
 * - DAPP: connect to external wallets to derive addresses and request signatures
 *
 * Also defines the WizardConnect Extensions standard for BIP352 stealth
 * addresses and BIP47 RPA paths.
 *
 * @module @00-protocol/sdk/wizconnect
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import {
  h2b, b2h, concat, rand, utf8,
  bip32ChildPub, base58Check, base58Decode, dsha256,
  makeNostrEvent,
} from '../common/index.js';
import { nip04Encrypt, nip04Decrypt } from '../onion/index.js';

/* ========================================================================
   Protocol Constants
   ======================================================================== */

/** WizardConnect protocol identifier */
export const WIZ_PROTOCOL = 'hdwalletv1';

/** WizardConnect protocol version */
export const WIZ_VERSION = '1.0';

/** Protocol action types */
export const WIZ_ACTION = Object.freeze({
  DAPP_READY:           'dapp_ready',
  WALLET_READY:         'wallet_ready',
  SIGN_TX_REQUEST:      'sign_transaction_request',
  SIGN_TX_RESPONSE:     'sign_transaction_response',
  SIGN_CANCEL:          'sign_cancel',
  DISCONNECT:           'disconnect',
});

/** Standard BIP44 path indices (under account node m/44'/145'/0') */
export const WIZ_PATH_INDEX = Object.freeze({
  receive: 0,   // m/44'/145'/0'/0
  change:  1,   // m/44'/145'/0'/1
  defi:    7,   // m/44'/145'/0'/7  (RiftenLabs standard)
});

/**
 * WizardConnect Extensions standard — privacy protocol path definitions.
 * Each extension defines its own BIP tree (NOT under BIP44).
 * Wallets export xpubs at the hardened gate; dapps derive the final
 * non-hardened child locally.
 */
export const WIZ_EXTENSIONS = Object.freeze({
  bch_stealth_bip352: {
    spend_path: "m/352'/145'/0'/0'",
    scan_path:  "m/352'/145'/0'/1'",
  },
  rpa_bip47: {
    spend_path: "m/47'/145'/0'/0'",
    scan_path:  "m/47'/145'/0'/1'",
  },
});

/** Default Nostr relay for WizardConnect */
export const WIZ_DEFAULT_RELAY = 'wss://relay.cauldron.quest:443';

/* ========================================================================
   URI Encoding / Decoding (wiz:// scheme)
   ======================================================================== */

const _BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/** @private Bech32 encode raw bytes (no checksum, just base32) */
function _bech32Encode(data) {
  const bits = [];
  for (const b of data) { for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1); }
  const out = [];
  for (let i = 0; i < bits.length; i += 5) {
    let v = 0;
    for (let j = 0; j < 5; j++) v = (v << 1) | (bits[i + j] || 0);
    out.push(_BECH32_CHARSET[v]);
  }
  return out.join('');
}

/** @private Bech32 decode to raw bytes */
function _bech32Decode(str) {
  const bits = [];
  for (const c of str.toLowerCase()) {
    const v = _BECH32_CHARSET.indexOf(c);
    if (v === -1) throw new Error('Invalid bech32 char: ' + c);
    for (let i = 4; i >= 0; i--) bits.push((v >> i) & 1);
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    bytes.push(b);
  }
  return new Uint8Array(bytes);
}

/**
 * Encode a WizardConnect wiz:// URI.
 *
 * @param {string} pubkeyHex - X-only public key (32 bytes hex)
 * @param {string} secretHex - Shared secret (8 bytes hex)
 * @param {string} [relayUrl] - Nostr relay URL (omit for default)
 * @returns {string} wiz:// URI
 */
export function wizEncodeURI(pubkeyHex, secretHex, relayUrl) {
  const pubBech32 = _bech32Encode(h2b(pubkeyHex));
  const secBech32 = _bech32Encode(h2b(secretHex));
  if (!relayUrl || relayUrl === WIZ_DEFAULT_RELAY) {
    return `wiz://?p=${pubBech32}&s=${secBech32}`;
  }
  const m = relayUrl.match(/^(wss?):\/\/([^:\/]+)(?::(\d+))?/);
  if (!m) return `wiz://?p=${pubBech32}&s=${secBech32}`;
  const host = m[2];
  const port = m[3] ? ':' + m[3] : '';
  let uri = `wiz://${host}${port}?p=${pubBech32}&s=${secBech32}`;
  if (m[1] === 'ws') uri += '&pr=ws';
  return uri;
}

/**
 * Decode a WizardConnect wiz:// URI.
 *
 * @param {string} uri - wiz:// URI string
 * @returns {{ publicKey: string, secret: string, hostname: string, port: number, protocol: string }}
 */
export function wizDecodeURI(uri) {
  const lower = uri.toLowerCase();
  const isQR = lower.includes('%3f') && !lower.includes('?');
  const normalized = isQR
    ? lower.replace('%3f', '?').replace(/%3d/g, '=').replace(/%26/g, '&')
    : lower;
  const url = new URL(normalized);
  if (url.protocol !== 'wiz:') throw new Error('Not a wiz:// URI');
  const pBech32 = url.searchParams.get('p');
  const sBech32 = url.searchParams.get('s');
  if (!pBech32 || !sBech32) throw new Error('Missing p or s param');
  const publicKey = b2h(_bech32Decode(pBech32));
  const secret = b2h(_bech32Decode(sBech32));
  const hostname = url.hostname || 'relay.cauldron.quest';
  const protocol = url.searchParams.get('pr') || 'wss';
  const port = url.port ? parseInt(url.port) : (protocol === 'wss' ? 443 : 80);
  return { publicKey, secret, hostname, port, protocol };
}

/* ========================================================================
   Base58Check for xpub encoding
   ======================================================================== */

const _B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** @private Base58Check encode an xpub payload */
function _base58CheckEncode(payload) {
  const checksum = dsha256(payload).slice(0, 4);
  const full = new Uint8Array(payload.length + 4);
  full.set(payload);
  full.set(checksum, payload.length);
  let num = 0n;
  for (const b of full) num = num * 256n + BigInt(b);
  let str = '';
  while (num > 0n) { str = _B58_ALPHABET[Number(num % 58n)] + str; num /= 58n; }
  for (const b of full) { if (b === 0) str = '1' + str; else break; }
  return str;
}

/** @private Base58Check decode an xpub string */
function _base58CheckDecode(str) {
  let num = 0n;
  for (const c of str) {
    const idx = _B58_ALPHABET.indexOf(c);
    if (idx === -1) return null;
    num = num * 58n + BigInt(idx);
  }
  const hex = num.toString(16).padStart(164, '0');
  const bytes = h2b(hex.slice(hex.length - 164));
  const payload = bytes.slice(0, 78);
  const checksum = bytes.slice(78, 82);
  const computed = dsha256(payload).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== computed[i]) return null;
  }
  return payload;
}

/* ========================================================================
   WizRelay — Nostr NIP-17 Transport Layer
   ======================================================================== */

/**
 * @private Internal Nostr relay transport for WizardConnect.
 * Uses NIP-04 encrypted kind 21059 events for messaging.
 */
class WizRelay {
  constructor(relayUrl, myPrivHex, sessionId) {
    this._relayUrl = relayUrl;
    this._myPriv = h2b(myPrivHex);
    this._myPrivHex = myPrivHex;
    this._myPub = null;
    this._sessionId = sessionId;
    this._peerPubHex = null;
    this._ws = null;
    this._connected = false;
    this._onMessage = null;
    this._onStatus = null;
    this._reconnectTimer = null;
  }

  setMyPub(pubHex32) { this._myPub = pubHex32; }
  setPeerPub(pubHex32) { this._peerPubHex = pubHex32; }

  connect() {
    if (this._ws) { try { this._ws.close(); } catch {} }
    const ws = new WebSocket(this._relayUrl);
    this._ws = ws;

    ws.onopen = () => {
      this._connected = true;
      if (this._onStatus) this._onStatus('connected');
      ws.send(JSON.stringify(['REQ', 'wiz-' + this._sessionId, {
        kinds: [21059],
        '#p': [this._myPub],
        since: Math.floor(Date.now() / 1000) - 300,
      }]));
    };

    ws.onmessage = async (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg[0] !== 'EVENT' || !msg[2]) return;
        const ev = msg[2];
        if (ev.kind !== 21059) return;
        const senderPub = ev.pubkey;
        const plaintext = await nip04Decrypt(this._myPriv, senderPub, ev.content);
        if (!plaintext) return;
        const payload = JSON.parse(plaintext);
        if (!this._peerPubHex && senderPub) {
          this._peerPubHex = senderPub;
        }
        if (this._onMessage) this._onMessage(payload, senderPub);
      } catch (err) {
        // Decryption failure is normal for messages not for us
      }
    };

    ws.onerror = () => {
      this._connected = false;
      if (this._onStatus) this._onStatus('error');
    };

    ws.onclose = () => {
      this._connected = false;
      if (this._onStatus) this._onStatus('disconnected');
      this._reconnectTimer = setTimeout(() => this.connect(), 5000);
    };
  }

  async send(payload) {
    if (!this._ws || this._ws.readyState !== 1) return;
    if (!this._peerPubHex) return;
    const content = await nip04Encrypt(this._myPriv, this._peerPubHex, JSON.stringify(payload));
    const ev = await makeNostrEvent(this._myPriv, 21059, content, [['p', this._peerPubHex]]);
    this._ws.send(JSON.stringify(['EVENT', ev]));
  }

  disconnect(reason) {
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    this._reconnectTimer = null;
    if (this._ws) {
      try {
        this.send({ action: WIZ_ACTION.DISCONNECT, time: Date.now(), reason: reason || 'user_disconnect' });
      } catch {}
      setTimeout(() => { try { this._ws.close(); } catch {} }, 200);
    }
    this._connected = false;
  }

  onMessage(cb) { this._onMessage = cb; }
  onStatus(cb) { this._onStatus = cb; }
  isConnected() { return this._connected; }
}

/* ========================================================================
   WizardConnect Class — Unified Wallet + Dapp API
   ======================================================================== */

/**
 * WizardConnect protocol handler — supports both wallet and dapp roles.
 *
 * Wallet side: generate QR connection URI, listen for dapp connections,
 * respond with xpubs, handle signing requests.
 *
 * Dapp side: connect to wallet via wiz:// URI, receive xpubs, request
 * transaction signing.
 *
 * @example
 * // Wallet side
 * const wc = new WizardConnect({ role: 'wallet', nostrRelays: ['wss://relay.damus.io'] });
 * const { uri } = await wc.generateQR();
 * wc.onConnected((name, icon) => console.log('Dapp connected:', name));
 * wc.onSignRequest(req => { wc.approveSign(req.sequence, signedTxHex); });
 *
 * // Dapp side
 * const wc = new WizardConnect({ role: 'dapp', nostrRelays: ['wss://relay.damus.io'] });
 * await wc.connectToWallet(wizUri);
 * wc.onConnected((name, icon, paths) => { console.log('Wallet:', name); });
 * const signedTx = await wc.requestSign(txHex);
 */
export class WizardConnect {
  /**
   * @param {Object} opts
   * @param {'wallet'|'dapp'} opts.role - Operating role
   * @param {string[]} [opts.nostrRelays] - Nostr relay URLs
   * @param {string} [opts.dappName='00 Protocol'] - Dapp display name
   * @param {string} [opts.dappIcon] - Dapp icon URL
   */
  constructor({ role, nostrRelays, dappName, dappIcon }) {
    this._role = role;
    this._relayUrls = nostrRelays || [WIZ_DEFAULT_RELAY];
    this._dappName = dappName || '00 Protocol';
    this._dappIcon = dappIcon || '';

    this._relay = null;
    this._credentials = null;
    this._connected = false;

    // Wallet-side state
    this._dappDiscovered = false;
    this._peerName = '';
    this._peerIcon = '';
    this._pendingSignRequests = new Map();

    // Dapp-side state
    this._paths = [];
    this._extensions = {};
    this._signSequence = 0;
    this._pendingSignCallbacks = new Map();
    this._stealthSpendPub = null;
    this._stealthScanPub = null;

    // Event callbacks
    this._onConnected = null;
    this._onSignRequest = null;
    this._onDisconnect = null;
  }

  /* ------------------------------------------------------------------
     Wallet Side
     ------------------------------------------------------------------ */

  /**
   * Generate a connection QR code URI (wallet side).
   *
   * Creates ephemeral keypair and shared secret, encodes them as a wiz:// URI.
   *
   * @param {string} [relayUrl] - Override relay URL
   * @returns {Promise<{ uri: string, qrUri: string, credentials: Object }>}
   */
  async generateQR(relayUrl) {
    const privBytes = rand(32);
    const privHex = b2h(privBytes);
    const secretBytes = rand(8);
    const secretHex = b2h(secretBytes);

    const fullPub = secp256k1.getPublicKey(privBytes, true);
    const pubHex32 = b2h(fullPub.slice(1));

    this._credentials = { privateKey: privHex, publicKey: pubHex32, secret: secretHex };
    const url = relayUrl || this._relayUrls[0];
    const uri = wizEncodeURI(pubHex32, secretHex, url);
    const qrUri = uri.toUpperCase().replace('?', '%3F').replace(/=/g, '%3D').replace(/&/g, '%26');

    return { uri, qrUri, credentials: this._credentials };
  }

  /**
   * Wait for a dapp to connect (wallet side).
   *
   * Starts listening on the Nostr relay for incoming dapp_ready messages.
   * Call generateQR first.
   *
   * @param {Object} [xpubData] - xpub data to send to dapp
   * @param {Array} [xpubData.paths] - Array of { name, xpub }
   * @param {Object} [xpubData.extensions] - Extensions object
   * @returns {Promise<void>}
   */
  async waitForDapp(xpubData) {
    if (!this._credentials) throw new Error('Call generateQR first');

    const relayUrl = this._relayUrls[0];
    const relay = new WizRelay(
      relayUrl,
      this._credentials.privateKey,
      'wallet-' + this._credentials.secret.slice(0, 8),
    );
    relay.setMyPub(this._credentials.publicKey);
    this._relay = relay;

    relay.onMessage((payload, senderPub) => {
      if (payload.action === WIZ_ACTION.DAPP_READY) {
        this._dappDiscovered = true;
        this._peerName = payload.dapp_name || '';
        this._peerIcon = payload.dapp_icon || '';
        relay.setPeerPub(senderPub);

        // Send WalletReady with xpubs
        const walletReady = {
          action: WIZ_ACTION.WALLET_READY,
          time: Date.now(),
          wallet_name: this._dappName,
          wallet_icon: this._dappIcon,
          dapp_discovered: true,
          supported_protocols: [WIZ_PROTOCOL],
          session: {
            [WIZ_PROTOCOL]: {
              paths: xpubData?.paths || [],
              extensions: xpubData?.extensions,
            },
          },
          public_key: this._credentials.publicKey,
          secret: this._credentials.secret,
        };
        relay.send(walletReady);
        this._connected = true;

        if (this._onConnected) this._onConnected(this._peerName, this._peerIcon);
      } else if (payload.action === WIZ_ACTION.SIGN_TX_REQUEST) {
        this._pendingSignRequests.set(payload.sequence, payload);
        if (this._onSignRequest) this._onSignRequest(payload);
      } else if (payload.action === WIZ_ACTION.DISCONNECT) {
        this._connected = false;
        if (this._onDisconnect) this._onDisconnect(payload.reason);
      }
    });

    relay.connect();
  }

  /**
   * Send xpubs to the connected dapp (wallet side).
   *
   * @param {Array} paths - Array of { name, xpub } path entries
   * @param {Object} [extensions] - Extensions object (e.g., stealth, RPA paths)
   */
  async sendXpubs(paths, extensions) {
    if (!this._relay || !this._connected) throw new Error('Not connected');
    this._relay.send({
      action: WIZ_ACTION.WALLET_READY,
      time: Date.now(),
      session: {
        [WIZ_PROTOCOL]: { paths, extensions },
      },
    });
  }

  /**
   * Approve a signing request (wallet side).
   *
   * @param {number} sequence - Request sequence number
   * @param {string} signedTxHex - Signed transaction hex
   */
  approveSign(sequence, signedTxHex) {
    if (!this._relay) return;
    this._pendingSignRequests.delete(sequence);
    this._relay.send({
      action: WIZ_ACTION.SIGN_TX_RESPONSE,
      time: Date.now(),
      sequence,
      signedTransaction: signedTxHex,
    });
  }

  /**
   * Reject a signing request (wallet side).
   *
   * @param {number} sequence - Request sequence number
   * @param {string} [reason='user_rejected']
   */
  rejectSign(sequence, reason) {
    if (!this._relay) return;
    this._pendingSignRequests.delete(sequence);
    this._relay.send({
      action: WIZ_ACTION.SIGN_CANCEL,
      time: Date.now(),
      sequence,
      reason: reason || 'user_rejected',
    });
  }

  /* ------------------------------------------------------------------
     Dapp Side
     ------------------------------------------------------------------ */

  /**
   * Connect to a wallet via wiz:// URI (dapp side).
   *
   * Decodes the URI, connects to the relay, and sends a dapp_ready message.
   * The wallet will respond with xpubs.
   *
   * @param {string} wizUri - wiz:// URI from QR code
   * @returns {Promise<void>}
   */
  async connectToWallet(wizUri) {
    const decoded = wizDecodeURI(wizUri);
    const relayUrl = `${decoded.protocol}://${decoded.hostname}:${decoded.port}`;

    const privBytes = rand(32);
    const privHex = b2h(privBytes);
    const fullPub = secp256k1.getPublicKey(privBytes, true);
    const pubHex32 = b2h(fullPub.slice(1));

    const peerPubHex = decoded.publicKey;
    const peerSecret = decoded.secret;

    const relay = new WizRelay(relayUrl, privHex, 'dapp-' + decoded.secret.slice(0, 8));
    relay.setMyPub(pubHex32);
    relay.setPeerPub(peerPubHex);
    this._relay = relay;

    relay.onMessage((payload, senderPub) => {
      if (payload.action === WIZ_ACTION.WALLET_READY) {
        // Verify secret (MITM prevention)
        if (payload.secret !== peerSecret) return;

        this._peerName = payload.wallet_name || 'Unknown Wallet';
        this._peerIcon = payload.wallet_icon || '';
        this._connected = true;

        const session = payload.session?.[WIZ_PROTOCOL];
        if (session) {
          this._paths = session.paths || [];
          this._extensions = session.extensions || {};

          // Derive stealth pubkeys from xpubs
          const spendPath = this._paths.find(p => p.name === 'stealth_spend');
          const scanPath = this._paths.find(p => p.name === 'stealth_scan');

          if (spendPath) {
            const decoded = _base58CheckDecode(spendPath.xpub);
            if (decoded) {
              const child = bip32ChildPub(decoded.slice(45, 78), decoded.slice(13, 45), 0);
              if (child) this._stealthSpendPub = child.pub;
            }
          }
          if (scanPath) {
            const decoded = _base58CheckDecode(scanPath.xpub);
            if (decoded) {
              const child = bip32ChildPub(decoded.slice(45, 78), decoded.slice(13, 45), 0);
              if (child) this._stealthScanPub = child.pub;
            }
          }
        }

        // Acknowledge
        relay.send({
          action: WIZ_ACTION.DAPP_READY,
          time: Date.now(),
          supported_protocols: [WIZ_PROTOCOL],
          selected_protocol: WIZ_PROTOCOL,
          wallet_discovered: true,
          dapp_name: this._dappName,
          dapp_icon: this._dappIcon,
        });

        if (this._onConnected) this._onConnected(this._peerName, this._peerIcon, this._paths);
      } else if (payload.action === WIZ_ACTION.SIGN_TX_RESPONSE) {
        const cb = this._pendingSignCallbacks.get(payload.sequence);
        if (cb) {
          this._pendingSignCallbacks.delete(payload.sequence);
          if (payload.error) cb.reject(new Error(payload.error));
          else cb.resolve(payload.signedTransaction);
        }
      } else if (payload.action === WIZ_ACTION.SIGN_CANCEL) {
        const cb = this._pendingSignCallbacks.get(payload.sequence);
        if (cb) {
          this._pendingSignCallbacks.delete(payload.sequence);
          cb.reject(new Error('Sign cancelled: ' + (payload.reason || 'unknown')));
        }
      } else if (payload.action === WIZ_ACTION.DISCONNECT) {
        this._connected = false;
        if (this._onDisconnect) this._onDisconnect(payload.reason);
      }
    });

    relay.onStatus((status) => {
      if (status === 'connected') {
        // Send initial DappReady
        relay.send({
          action: WIZ_ACTION.DAPP_READY,
          time: Date.now(),
          supported_protocols: [WIZ_PROTOCOL],
          wallet_discovered: false,
          dapp_name: this._dappName,
          dapp_icon: this._dappIcon,
        });
      }
    });

    relay.connect();
  }

  /**
   * Request the wallet to sign a transaction (dapp side).
   *
   * @param {string} txHex - Unsigned transaction hex
   * @param {Array} [inputPaths] - Array of [inputIndex, pathName, addressIndex]
   * @returns {Promise<string>} Signed transaction hex
   */
  async requestSign(txHex, inputPaths) {
    if (!this._relay || !this._connected) throw new Error('Not connected to wallet');

    return new Promise((resolve, reject) => {
      const seq = ++this._signSequence;
      this._pendingSignCallbacks.set(seq, { resolve, reject });

      this._relay.send({
        action: WIZ_ACTION.SIGN_TX_REQUEST,
        time: Date.now(),
        transaction: txHex,
        sequence: seq,
        inputPaths: inputPaths || [],
      });

      // 5 minute timeout
      setTimeout(() => {
        if (this._pendingSignCallbacks.has(seq)) {
          this._pendingSignCallbacks.delete(seq);
          reject(new Error('Sign request timed out'));
        }
      }, 300000);
    });
  }

  /**
   * Derive a public key from the wallet's xpub (dapp side).
   *
   * @param {string} pathName - Path name (e.g., 'receive', 'change', 'defi')
   * @param {number} index - Address index
   * @returns {Uint8Array|null} Compressed public key (33 bytes) or null
   */
  derivePubkey(pathName, index) {
    const path = this._paths.find(p => p.name === pathName);
    if (!path) return null;
    const decoded = _base58CheckDecode(path.xpub);
    if (!decoded) return null;
    const chain = decoded.slice(13, 45);
    const pub = decoded.slice(45, 78);
    const child = bip32ChildPub(pub, chain, index);
    return child ? child.pub : null;
  }

  /* ------------------------------------------------------------------
     Event Handlers
     ------------------------------------------------------------------ */

  /**
   * Register a callback for successful connection.
   * @param {Function} callback - Called with (peerName, peerIcon, [paths])
   */
  onConnected(callback) { this._onConnected = callback; }

  /**
   * Register a callback for signing requests (wallet side only).
   * @param {Function} callback - Called with (request)
   */
  onSignRequest(callback) { this._onSignRequest = callback; }

  /**
   * Register a callback for disconnection.
   * @param {Function} callback - Called with (reason)
   */
  onDisconnect(callback) { this._onDisconnect = callback; }

  /* ------------------------------------------------------------------
     State Getters
     ------------------------------------------------------------------ */

  /** Whether currently connected to a peer */
  get isConnected() { return this._connected; }

  /** Connected peer's display name */
  get peerName() { return this._peerName; }

  /** Connected peer's icon URL */
  get peerIcon() { return this._peerIcon; }

  /** Available xpub paths (dapp side) */
  get paths() { return this._paths; }

  /** Negotiated extensions */
  get extensions() { return this._extensions; }

  /** Stealth spend public key (derived from xpub, dapp side) */
  get stealthSpendPub() { return this._stealthSpendPub; }

  /** Stealth scan public key (derived from xpub, dapp side) */
  get stealthScanPub() { return this._stealthScanPub; }

  /* ------------------------------------------------------------------
     Cleanup
     ------------------------------------------------------------------ */

  /**
   * Disconnect from the peer and clean up.
   */
  disconnect() {
    if (this._relay) this._relay.disconnect('user_disconnect');
    this._connected = false;
  }

  /** Extensions standard (static reference) */
  static EXTENSIONS = WIZ_EXTENSIONS;
}
