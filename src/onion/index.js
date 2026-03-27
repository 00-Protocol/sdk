/**
 * @00-protocol/sdk — Onion Relay Module
 *
 * Layered encryption for relay routing using secp256k1 ECDH + AES-256-GCM.
 * Each onion layer wraps the payload with an ephemeral key exchange so only
 * the designated relay node can peel its layer. Supports multi-hop routing
 * where each node sees only the next hop.
 *
 * Also provides NIP-04, NIP-44, and NIP-59 Nostr encryption for relay transport.
 *
 * @module @00-protocol/sdk/onion
 */

import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf';
import {
  h2b, b2h, concat, rand, utf8,
  makeNostrEvent,
} from '../common/index.js';

/** Standard padding size for joiner onion payloads */
export const JOINER_PAD_SIZE = 80;

/* ========================================================================
   Onion Layer Encryption (secp256k1 ECDH + AES-256-GCM)
   ========================================================================
   Wire format per layer: ephPub(33) || nonce(12) || ciphertext+tag
   ======================================================================== */

/**
 * Add one onion encryption layer around data, keyed to a specific peeler.
 *
 * Creates an ephemeral ECDH keypair, derives AES-256-GCM key from the
 * shared secret, encrypts the data, and prepends the ephemeral pubkey + nonce.
 *
 * @param {Uint8Array} data - Data to encrypt
 * @param {string} peelerPubHex - Target peeler's x-only public key (32 hex chars)
 * @returns {Promise<Uint8Array>} Encrypted blob: ephPub(33) || nonce(12) || ct+tag
 */
export async function onionLayer(data, peelerPubHex) {
  const eph = rand(32);
  const ephPub = secp256k1.getPublicKey(eph, true);
  const shared = secp256k1.getSharedSecret(eph, h2b('02' + peelerPubHex)).slice(1, 33);
  const aesKey = sha256(shared);
  const iv = rand(12);
  const key = await crypto.subtle.importKey('raw', aesKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data));
  return concat(ephPub, iv, ct);
}

/**
 * Peel one onion layer using the peeler's private key.
 *
 * Recovers the shared secret from the ephemeral pubkey in the blob,
 * derives the AES key, and decrypts the inner payload.
 *
 * @param {Uint8Array} blob - Encrypted onion blob
 * @param {Uint8Array} myPriv - Peeler's private key (32 bytes)
 * @returns {Promise<Uint8Array>} Decrypted inner data
 */
export async function onionPeel(blob, myPriv) {
  const ephPub = blob.slice(0, 33);
  const iv = blob.slice(33, 45);
  const ct = blob.slice(45);
  const shared = secp256k1.getSharedSecret(myPriv, ephPub).slice(1, 33);
  const aesKey = sha256(shared);
  const key = await crypto.subtle.importKey('raw', aesKey, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct));
}

/**
 * Wrap a payload in multiple onion layers (innermost = last peeler, outermost = first).
 *
 * The payload is padded to JOINER_PAD_SIZE bytes with a 0x01 delimiter,
 * then wrapped in layers from last to first so the first peeler peels first.
 *
 * Payload format: "addr|value_sats" padded to 80 bytes.
 *
 * @param {string} payload - Plaintext payload (e.g., "bitcoincash:qz...|10000")
 * @param {string[]} peelerPubHexes - Array of peeler x-only pubkeys (peel order)
 * @returns {Promise<Uint8Array>} Multi-layered onion blob
 */
export async function onionWrap(payload, peelerPubHexes) {
  const raw = utf8(payload);
  const padded = new Uint8Array(JOINER_PAD_SIZE);
  padded.set(raw);
  padded[raw.length] = 0x01;
  let data = padded;
  for (let i = peelerPubHexes.length - 1; i >= 0; i--) {
    data = await onionLayer(data, peelerPubHexes[i]);
  }
  return data;
}

/**
 * Unpad an onion-peeled payload and parse the "addr|value" format.
 *
 * @param {Uint8Array} data - Decrypted (fully peeled) payload
 * @returns {{ addr: string, value: number }}
 */
export function onionUnpad(data) {
  const idx = data.indexOf(0x01);
  const str = new TextDecoder().decode(data.slice(0, idx > 0 ? idx : data.length));
  const sep = str.lastIndexOf('|');
  if (sep > 0) {
    return { addr: str.slice(0, sep), value: parseInt(str.slice(sep + 1)) || 0 };
  }
  return { addr: str, value: 0 };
}

/* ========================================================================
   NIP-04 Encryption (secp256k1 ECDH + AES-CBC)
   ======================================================================== */

/**
 * Encrypt a message using NIP-04 (AES-CBC with shared secret).
 *
 * @param {Uint8Array} myPriv - Sender's private key (32 bytes)
 * @param {string} theirPubHex - Recipient's x-only pubkey (32 hex chars)
 * @param {string} msg - Plaintext message
 * @returns {Promise<string>} NIP-04 encrypted content: base64(ct) + "?iv=" + base64(iv)
 */
export async function nip04Encrypt(myPriv, theirPubHex, msg) {
  const shared = secp256k1.getSharedSecret(myPriv, h2b('02' + theirPubHex)).slice(1, 33);
  const iv = rand(16);
  const key = await crypto.subtle.importKey('raw', shared, { name: 'AES-CBC' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, utf8(msg));
  return btoa(String.fromCharCode(...new Uint8Array(ct))) + '?iv=' + btoa(String.fromCharCode(...iv));
}

/**
 * Decrypt a NIP-04 encrypted message.
 *
 * @param {Uint8Array} myPriv - Recipient's private key (32 bytes)
 * @param {string} senderPubHex - Sender's x-only pubkey (32 hex chars)
 * @param {string} encContent - NIP-04 encrypted string
 * @returns {Promise<string|null>} Decrypted plaintext, or null on failure
 */
export async function nip04Decrypt(myPriv, senderPubHex, encContent) {
  try {
    const [ctB64, ivB64] = encContent.split('?iv=');
    const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const shared = secp256k1.getSharedSecret(myPriv, h2b('02' + senderPubHex)).slice(1, 33);
    const key = await crypto.subtle.importKey('raw', shared, { name: 'AES-CBC' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return null; }
}

/* ========================================================================
   NIP-44 Encryption (ChaCha20 + HKDF + HMAC-SHA256)
   ========================================================================
   Note: ChaCha20 requires @noble/ciphers at runtime. If unavailable,
   these functions will throw. Install with: npm i @noble/ciphers
   ======================================================================== */

const NIP44_SALT = utf8('nip44-v2');

/**
 * Derive a NIP-44 conversation key from ECDH shared secret.
 * @param {Uint8Array} myPriv
 * @param {string} theirPubHex
 * @returns {Uint8Array}
 */
function nip44ConversationKey(myPriv, theirPubHex) {
  const shared = secp256k1.getSharedSecret(myPriv, h2b('02' + theirPubHex)).slice(1, 33);
  return hkdfExtract(sha256, shared, NIP44_SALT);
}

/** @private Calculate padded length for NIP-44 */
function nip44CalcPaddedLen(len) {
  if (len <= 32) return 32;
  return 1 << (32 - Math.clz32(len - 1));
}

/** @private Pad plaintext per NIP-44 */
function nip44Pad(plaintext) {
  const raw = utf8(plaintext);
  if (raw.length < 1 || raw.length > 65535) throw new Error('invalid plaintext length');
  const padded = new Uint8Array(2 + nip44CalcPaddedLen(raw.length));
  new DataView(padded.buffer).setUint16(0, raw.length);
  padded.set(raw, 2);
  return padded;
}

/** @private Unpad NIP-44 ciphertext */
function nip44Unpad(padded) {
  const len = new DataView(padded.buffer, padded.byteOffset).getUint16(0);
  if (len < 1 || len > padded.length - 2) throw new Error('invalid padding');
  return new TextDecoder().decode(padded.slice(2, 2 + len));
}

/**
 * Encrypt a message using NIP-44 v2 (ChaCha20 + HKDF + HMAC).
 *
 * Requires @noble/ciphers to be installed.
 *
 * @param {Uint8Array} myPriv - Sender's private key
 * @param {string} theirPubHex - Recipient's x-only pubkey
 * @param {string} msg - Plaintext
 * @returns {Promise<string>} Base64-encoded NIP-44 payload
 */
export async function nip44Encrypt(myPriv, theirPubHex, msg) {
  const { chacha20 } = await import('@noble/ciphers/chacha');
  const convKey = nip44ConversationKey(myPriv, theirPubHex);
  const nonce = rand(32);
  const keys = hkdfExpand(sha256, convKey, nonce, 76);
  const chachaKey = keys.slice(0, 32);
  const chaChaNonce = keys.slice(32, 44);
  const hmacKey = keys.slice(44, 76);
  const padded = nip44Pad(msg);
  const ciphertext = chacha20(chachaKey, chaChaNonce, padded);
  const mac = hmac(sha256, hmacKey, concat(nonce, ciphertext));
  const payload = concat(new Uint8Array([2]), nonce, ciphertext, mac);
  return btoa(String.fromCharCode(...payload));
}

/**
 * Decrypt a NIP-44 v2 encrypted payload.
 *
 * Requires @noble/ciphers to be installed.
 *
 * @param {Uint8Array} myPriv - Recipient's private key
 * @param {string} senderPubHex - Sender's x-only pubkey
 * @param {string} b64payload - Base64-encoded NIP-44 payload
 * @returns {Promise<string|null>} Decrypted plaintext, or null on failure
 */
export async function nip44Decrypt(myPriv, senderPubHex, b64payload) {
  try {
    const { chacha20 } = await import('@noble/ciphers/chacha');
    const raw = Uint8Array.from(atob(b64payload), c => c.charCodeAt(0));
    if (raw[0] !== 2) throw new Error('unsupported version');
    const nonce = raw.slice(1, 33);
    const ciphertext = raw.slice(33, raw.length - 32);
    const mac = raw.slice(raw.length - 32);
    const convKey = nip44ConversationKey(myPriv, senderPubHex);
    const keys = hkdfExpand(sha256, convKey, nonce, 76);
    const hmacKey = keys.slice(44, 76);
    const expectedMac = hmac(sha256, hmacKey, concat(nonce, ciphertext));
    let ok = expectedMac.length === mac.length ? 1 : 0;
    for (let i = 0; i < expectedMac.length; i++) ok &= (expectedMac[i] === mac[i]) ? 1 : 0;
    if (!ok) throw new Error('bad mac');
    const chachaKey = keys.slice(0, 32);
    const chaChaNonce = keys.slice(32, 44);
    const padded = chacha20(chachaKey, chaChaNonce, ciphertext);
    return nip44Unpad(padded);
  } catch { return null; }
}

/* ========================================================================
   NIP-59 Gift Wrap (Rumor -> Seal -> Wrap)
   ========================================================================
   Three-layer metadata protection for Nostr:
   Layer 1 (Rumor): unsigned inner event for deniability
   Layer 2 (Seal): NIP-44 encrypted to recipient, signed by author
   Layer 3 (Wrap): NIP-44 encrypted with ephemeral key, kind 1059
   ======================================================================== */

const TWO_DAYS = 2 * 24 * 60 * 60;

/** @private Random time offset for metadata obfuscation */
function randomTimeShift() {
  const buf = rand(4);
  return (buf[0] | (buf[1] << 8) | (buf[2] << 16) | ((buf[3] & 0x01) << 24)) % TWO_DAYS;
}

/** @private Compute Nostr event ID hash */
function eventId(pub, created_at, kind, tags, content) {
  return b2h(sha256(utf8(JSON.stringify([0, pub, created_at, kind, tags, content]))));
}

/**
 * Create an unsigned rumor (Layer 1 of NIP-59).
 *
 * @param {string} authorPubHex - Author's x-only pubkey
 * @param {number} kind - Inner event kind
 * @param {string} content - Event content
 * @param {Array} [tags] - Event tags
 * @returns {Object} Unsigned rumor event (no sig field, intentional for deniability)
 */
export function createRumor(authorPubHex, kind, content, tags = []) {
  const created_at = Math.floor(Date.now() / 1000);
  const id = eventId(authorPubHex, created_at, kind, tags, content);
  return { id, pubkey: authorPubHex, created_at, kind, tags, content };
}

/**
 * Full NIP-59 gift wrap: rumor -> seal -> gift wrap.
 *
 * Hides sender, recipient, and timestamp metadata from Nostr relays.
 *
 * @param {Uint8Array} authorPriv - Author's real private key (32 bytes)
 * @param {string} recipientPubHex - Recipient's x-only pubkey hex
 * @param {number} innerKind - Kind for the inner rumor
 * @param {string} innerContent - Content for the rumor
 * @param {Array} [innerTags] - Tags for the rumor
 * @returns {Promise<Object>} Kind 1059 Nostr event ready to publish
 */
export async function giftWrap(authorPriv, recipientPubHex, innerKind, innerContent, innerTags = []) {
  const authorPub = b2h(secp256k1.getPublicKey(authorPriv, true).slice(1));
  const rumor = createRumor(authorPub, innerKind, innerContent, innerTags);

  // Layer 2: Seal (kind 13)
  const sealContent = await nip44Encrypt(authorPriv, recipientPubHex, JSON.stringify(rumor));
  const sealCreatedAt = Math.floor(Date.now() / 1000) - randomTimeShift();
  const sealTags = [];
  const sealIdHash = sha256(utf8(JSON.stringify([0, authorPub, sealCreatedAt, 13, sealTags, sealContent])));
  const sealSig = b2h(await schnorr.sign(sealIdHash, authorPriv));
  const seal = {
    id: b2h(sealIdHash), pubkey: authorPub, created_at: sealCreatedAt,
    kind: 13, tags: sealTags, content: sealContent, sig: sealSig,
  };

  // Layer 3: Gift Wrap (kind 1059)
  const ephPriv = rand(32);
  const ephPub = b2h(secp256k1.getPublicKey(ephPriv, true).slice(1));
  const wrapContent = await nip44Encrypt(ephPriv, recipientPubHex, JSON.stringify(seal));
  const wrapCreatedAt = Math.floor(Date.now() / 1000) - randomTimeShift();
  const wrapTags = [['p', recipientPubHex]];
  const wrapIdHash = sha256(utf8(JSON.stringify([0, ephPub, wrapCreatedAt, 1059, wrapTags, wrapContent])));
  const wrapSig = b2h(await schnorr.sign(wrapIdHash, ephPriv));

  return {
    id: b2h(wrapIdHash), pubkey: ephPub, created_at: wrapCreatedAt,
    kind: 1059, tags: wrapTags, content: wrapContent, sig: wrapSig,
  };
}

/**
 * Unwrap a NIP-59 gift wrap: wrap -> seal -> rumor.
 *
 * @param {Uint8Array} myPriv - Recipient's private key (32 bytes)
 * @param {Object} wrapEvent - Kind 1059 Nostr event
 * @returns {Promise<{ rumor: Object, sealPubkey: string }|null>} Inner rumor + real sender, or null
 */
export async function giftUnwrap(myPriv, wrapEvent) {
  try {
    if (wrapEvent.kind !== 1059) return null;

    // Verify wrap signature
    const wrapIdHash = sha256(utf8(JSON.stringify([0, wrapEvent.pubkey, wrapEvent.created_at, 1059, wrapEvent.tags, wrapEvent.content])));
    if (!schnorr.verify(h2b(wrapEvent.sig), wrapIdHash, h2b(wrapEvent.pubkey))) return null;

    // Unwrap Layer 3
    const sealJson = await nip44Decrypt(myPriv, wrapEvent.pubkey, wrapEvent.content);
    if (!sealJson) return null;
    const seal = JSON.parse(sealJson);
    if (seal.kind !== 13) return null;

    // Verify seal signature
    const sealIdHash = sha256(utf8(JSON.stringify([0, seal.pubkey, seal.created_at, 13, seal.tags, seal.content])));
    if (!schnorr.verify(h2b(seal.sig), sealIdHash, h2b(seal.pubkey))) return null;

    // Unwrap Layer 2
    const rumorJson = await nip44Decrypt(myPriv, seal.pubkey, seal.content);
    if (!rumorJson) return null;
    const rumor = JSON.parse(rumorJson);

    return { rumor, sealPubkey: seal.pubkey };
  } catch { return null; }
}

/* ========================================================================
   OnionRelay Class — Relay Node
   ======================================================================== */

/**
 * Onion relay node that peels layers and forwards payloads.
 *
 * Listens for encrypted blobs on Nostr, peels its layer, and forwards
 * the inner blob to the next hop. Announces itself on Nostr for
 * discoverability.
 *
 * @example
 * const relay = new OnionRelay({ nostrRelays: ['wss://relay.damus.io'] });
 * relay.onBlob((inner, from) => console.log('Relayed blob'));
 * await relay.start();
 */
export class OnionRelay {
  /**
   * @param {Object} opts
   * @param {string[]} opts.nostrRelays - Nostr relay WebSocket URLs
   * @param {Uint8Array} [opts.privateKey] - Relay's private key (generated if omitted)
   */
  constructor({ nostrRelays, privateKey }) {
    this._relays = nostrRelays || [];
    this._priv = privateKey || rand(32);
    this._pub = b2h(secp256k1.getPublicKey(this._priv, true).slice(1));
    this._sockets = new Map();
    this._running = false;
    this._startTime = 0;
    this._relayedCount = 0;
    this._onBlob = null;
    this._subIds = [];
  }

  /**
   * The relay's x-only public key (for clients to encrypt layers to).
   * @returns {string}
   */
  get publicKey() { return this._pub; }

  /**
   * Start the relay: connect to Nostr relays and listen for onion blobs.
   * @returns {Promise<void>}
   */
  async start() {
    if (this._running) return;
    this._running = true;
    this._startTime = Date.now();

    for (const url of this._relays) {
      try {
        const ws = new WebSocket(url);
        this._sockets.set(url, ws);

        ws.onopen = () => {
          const subId = 'onion_' + this._pub.slice(0, 8);
          this._subIds.push(subId);
          ws.send(JSON.stringify(['REQ', subId, {
            kinds: [22231],
            '#p': [this._pub],
            since: Math.floor(Date.now() / 1000) - 600,
          }]));
        };

        ws.onmessage = async (e) => {
          try {
            const msg = JSON.parse(e.data);
            if (msg[0] !== 'EVENT' || !msg[2]) return;
            const ev = msg[2];
            if (!ev.content) return;

            // Attempt to peel our layer
            const blob = h2b(ev.content);
            const inner = await onionPeel(blob, this._priv);
            this._relayedCount++;

            if (this._onBlob) this._onBlob(inner, ev.pubkey);
          } catch {}
        };

        ws.onclose = () => {
          this._sockets.delete(url);
          if (this._running) {
            setTimeout(() => this.start(), 5000);
          }
        };
      } catch {}
    }
  }

  /**
   * Stop the relay: close all connections.
   */
  stop() {
    this._running = false;
    for (const [, ws] of this._sockets) {
      try { ws.close(); } catch {}
    }
    this._sockets.clear();
    this._subIds = [];
  }

  /**
   * Announce this relay on Nostr for discoverability.
   * @returns {Promise<void>}
   */
  async announce() {
    const content = JSON.stringify({
      version: 2,
      pubkey: this._pub,
      uptime: this.stats.uptime,
      relayed: this._relayedCount,
    });
    const event = await makeNostrEvent(this._priv, 22230, content, []);
    const msg = JSON.stringify(['EVENT', event]);
    for (const [, ws] of this._sockets) {
      if (ws.readyState === 1) {
        try { ws.send(msg); } catch {}
      }
    }
  }

  /**
   * Register a callback for received blobs.
   * @param {Function} callback - Called with (innerBlob: Uint8Array, senderPub: string)
   */
  onBlob(callback) { this._onBlob = callback; }

  /**
   * Relay statistics.
   * @returns {{ relayed: number, uptime: number, publicKey: string }}
   */
  get stats() {
    return {
      relayed: this._relayedCount,
      uptime: this._running ? Math.floor((Date.now() - this._startTime) / 1000) : 0,
      publicKey: this._pub,
    };
  }
}
