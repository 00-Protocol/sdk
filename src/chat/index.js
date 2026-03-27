/**
 * @00-protocol/sdk — CCSH Encrypted Chat Module
 *
 * Chat Cash (CCSH) protocol for end-to-end encrypted messaging over
 * Bitcoin Cash transactions and Nostr relays. Supports two protocol versions:
 *
 * - v1: Single-channel X25519 ECDH + AES-256-GCM
 * - v2: Split-knowledge — ciphertext is XOR-split between on-chain (BCH)
 *        and off-chain (Nostr relay) channels, requiring both to decrypt.
 *
 * Protocol-compatible with the 00 Wallet's CCSH implementation.
 *
 * @module @00-protocol/sdk/chat
 */

import { x25519 } from '@noble/curves/ed25519';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import {
  h2b, b2h, concat, rand, utf8,
  bip32Master, bip32Child, deriveBchPriv,
  pubHashToCashAddr,
  makeNostrEvent,
} from '../common/index.js';

/* ========================================================================
   Protocol Constants
   ======================================================================== */

/** CCSH magic bytes: "CCSH" in ASCII */
export const CCSH_MAGIC = new Uint8Array([0x43, 0x43, 0x53, 0x48]);

/** Protocol version identifiers */
export const CCSH_V1 = 0x01;
export const CCSH_V2 = 0x02;

/** Message types for v2 split-knowledge */
export const MSG_SPLIT_CHAIN = 0x10;
export const MSG_SPLIT_RELAY = 0x11;

/** Flags */
export const FLAG_SPLIT = 0x01;

/** Nostr event kind for CCSH messages */
export const NOSTR_KIND_CCSH = 21059;

/* ========================================================================
   V1 Packet Encoding / Decoding
   ======================================================================== */

/**
 * Pack a CCSH v1 packet into binary format.
 *
 * Wire format:
 *   CCSH(4) | version(1) | msg_type(1) | flags(1) |
 *   msg_id(16) | sender_pub(32) |
 *   chunk_index(2) | chunk_total(2) | chunk_len(2) | ciphertext_chunk(...)
 *
 * @param {Object} pkt - Packet fields
 * @param {Uint8Array} pkt.msg_id - 16-byte message ID
 * @param {Uint8Array} pkt.sender_pub - 32-byte X25519 sender public key
 * @param {number} pkt.chunk_index - Chunk index (0-based)
 * @param {number} pkt.chunk_total - Total chunks
 * @param {Uint8Array} pkt.ciphertext_chunk - Encrypted payload
 * @param {number} [pkt.msg_type=0x01] - Message type
 * @param {number} [pkt.flags=0] - Flags
 * @returns {Uint8Array}
 */
export function packPacket(pkt) {
  const c = pkt.ciphertext_chunk;
  return concat(
    CCSH_MAGIC,
    new Uint8Array([0x01, pkt.msg_type || 0x01, pkt.flags || 0]),
    pkt.msg_id, pkt.sender_pub,
    new Uint8Array([(pkt.chunk_index >> 8) & 0xff, pkt.chunk_index & 0xff]),
    new Uint8Array([(pkt.chunk_total >> 8) & 0xff, pkt.chunk_total & 0xff]),
    new Uint8Array([(c.length >> 8) & 0xff, c.length & 0xff]),
    c
  );
}

/**
 * Unpack a CCSH v1 packet from binary.
 *
 * @param {Uint8Array} raw - Raw binary packet
 * @returns {Object} Parsed packet fields
 */
export function unpackPacket(raw) {
  if (raw.length < 61) throw new Error('packet too short');
  if (raw[0] !== 0x43 || raw[1] !== 0x43 || raw[2] !== 0x53 || raw[3] !== 0x48) throw new Error('bad magic');
  if (raw[4] !== 0x01) throw new Error('bad version');
  let pos = 7;
  const msg_id = raw.slice(pos, pos + 16); pos += 16;
  const sender_pub = raw.slice(pos, pos + 32); pos += 32;
  const chunk_index = (raw[pos] << 8) | raw[pos + 1]; pos += 2;
  const chunk_total = (raw[pos] << 8) | raw[pos + 1]; pos += 2;
  const clen = (raw[pos] << 8) | raw[pos + 1]; pos += 2;
  return {
    msg_type: raw[5], msg_id, sender_pub, chunk_index, chunk_total,
    ciphertext_chunk: raw.slice(pos, pos + clen),
  };
}

/**
 * Pack a CCSH v2 packet (split-knowledge).
 * Same wire format as v1 but with version byte 0x02 and FLAG_SPLIT.
 *
 * @param {Object} pkt - Same fields as packPacket
 * @returns {Uint8Array}
 */
export function packV2(pkt) {
  const c = pkt.ciphertext_chunk;
  return concat(
    CCSH_MAGIC,
    new Uint8Array([CCSH_V2, pkt.msg_type, pkt.flags || FLAG_SPLIT]),
    pkt.msg_id, pkt.sender_pub,
    new Uint8Array([(pkt.chunk_index >> 8) & 0xff, pkt.chunk_index & 0xff]),
    new Uint8Array([(pkt.chunk_total >> 8) & 0xff, pkt.chunk_total & 0xff]),
    new Uint8Array([(c.length >> 8) & 0xff, c.length & 0xff]),
    c
  );
}

/**
 * Unpack any CCSH packet (v1 or v2), returning version info.
 *
 * @param {Uint8Array} raw
 * @returns {Object} Parsed packet with version, msg_type, flags
 */
export function unpackAny(raw) {
  if (raw.length < 61) throw new Error('packet too short');
  if (raw[0] !== 0x43 || raw[1] !== 0x43 || raw[2] !== 0x53 || raw[3] !== 0x48) throw new Error('bad magic');
  let pos = 7;
  const msg_id = raw.slice(pos, pos + 16); pos += 16;
  const sender_pub = raw.slice(pos, pos + 32); pos += 32;
  const chunk_index = (raw[pos] << 8) | raw[pos + 1]; pos += 2;
  const chunk_total = (raw[pos] << 8) | raw[pos + 1]; pos += 2;
  const clen = (raw[pos] << 8) | raw[pos + 1]; pos += 2;
  return {
    version: raw[4], msg_type: raw[5], flags: raw[6], msg_id, sender_pub,
    chunk_index, chunk_total, ciphertext_chunk: raw.slice(pos, pos + clen),
  };
}

/* ========================================================================
   V1 Encryption / Decryption (X25519 ECDH + AES-256-GCM)
   ======================================================================== */

/**
 * Encrypt a message using CCSH v1 protocol.
 *
 * Uses ephemeral X25519 ECDH to derive an AES-256-GCM key, encrypts the
 * plaintext, and packs it into a CCSH packet ready for on-chain or relay delivery.
 *
 * @param {string} text - Plaintext message
 * @param {string} recipientPubHex - Recipient's X25519 public key (64 hex chars)
 * @param {Uint8Array} senderPriv32 - Sender's X25519 private key (32 bytes)
 * @param {Uint8Array} senderPub32 - Sender's X25519 public key (32 bytes)
 * @param {number} [msgType=0x01] - Message type
 * @returns {Promise<Uint8Array>} Packed CCSH v1 binary packet
 */
export async function ccshEncryptMsg(text, recipientPubHex, senderPriv32, senderPub32, msgType = 0x01) {
  const recipientPub = h2b(recipientPubHex);
  const ephPriv = rand(32);
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPub);
  const aesKey = sha256(shared);
  const iv = rand(12);
  const ck = await crypto.subtle.importKey('raw', aesKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, ck, new TextEncoder().encode(text)));
  const ciphertext_chunk = concat(ephPub, iv, ct);
  const msg_id = rand(16);
  return packPacket({
    msg_id, sender_pub: senderPub32, chunk_index: 0, chunk_total: 1,
    ciphertext_chunk, msg_type: msgType, flags: 0,
  });
}

/**
 * Decrypt a CCSH v1 packet.
 *
 * @param {Uint8Array} raw - Binary CCSH packet
 * @param {Uint8Array} myPriv32 - Recipient's X25519 private key (32 bytes)
 * @returns {Promise<{ text: string, senderPubHex: string, msgType: number }>}
 */
export async function ccshDecryptPacket(raw, myPriv32) {
  const pkt = unpackPacket(raw);
  const cc = pkt.ciphertext_chunk;
  const shared = x25519.getSharedSecret(myPriv32, cc.slice(0, 32));
  const aesKey = sha256(shared);
  const ck = await crypto.subtle.importKey('raw', aesKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: cc.slice(32, 44), tagLength: 128 }, ck, cc.slice(44)));
  return { text: new TextDecoder().decode(pt), senderPubHex: b2h(pkt.sender_pub), msgType: pkt.msg_type };
}

/* ========================================================================
   V2 Split-Knowledge Encryption / Decryption
   ======================================================================== */

/**
 * XOR split data into two shards.
 * @param {Uint8Array} data
 * @returns {[Uint8Array, Uint8Array]} [shard, pad]
 */
export function xorSplit(data) {
  const pad = rand(data.length);
  const shard = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) shard[i] = data[i] ^ pad[i];
  return [shard, pad];
}

/**
 * XOR merge two shards back into the original data.
 * @param {Uint8Array} shard
 * @param {Uint8Array} pad
 * @returns {Uint8Array}
 */
export function xorMerge(shard, pad) {
  if (shard.length !== pad.length) throw new Error('XOR length mismatch');
  const out = new Uint8Array(shard.length);
  for (let i = 0; i < shard.length; i++) out[i] = shard[i] ^ pad[i];
  return out;
}

/**
 * Derive the chain-channel AES key from ECDH shared secret.
 * @param {Uint8Array} shared - ECDH shared secret
 * @returns {Uint8Array} 32-byte AES key
 */
export function deriveKeyChain(shared) {
  return sha256(concat(shared, utf8('ccsh-chain')));
}

/**
 * Derive the relay-channel AES key from ECDH shared secret.
 * @param {Uint8Array} shared - ECDH shared secret
 * @returns {Uint8Array} 32-byte AES key
 */
export function deriveKeyRelay(shared) {
  return sha256(concat(shared, utf8('ccsh-relay')));
}

/**
 * AES-256-GCM wrap: encrypt data with a key.
 * @param {Uint8Array} data
 * @param {Uint8Array} key - 32-byte AES key
 * @returns {Promise<Uint8Array>} nonce(12) || ciphertext+tag
 */
export async function aesWrap(data, key) {
  const nonce = rand(12);
  const ck = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, ck, data));
  return concat(nonce, ct);
}

/**
 * AES-256-GCM unwrap: decrypt data with a key.
 * @param {Uint8Array} blob - nonce(12) || ciphertext+tag
 * @param {Uint8Array} key - 32-byte AES key
 * @returns {Promise<Uint8Array>} Decrypted data
 */
export async function aesUnwrap(blob, key) {
  if (blob.length < 12) throw new Error('blob too short');
  const ck = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.slice(0, 12), tagLength: 128 }, ck, blob.slice(12)));
}

/**
 * Split-knowledge encrypt: split ciphertext between chain and relay channels.
 *
 * Inner encryption: X25519 ECDH + AES-256-GCM
 * Split: XOR into two shards
 * Outer encryption: each shard wrapped with channel-specific derived key
 *
 * @param {string} plaintext - Message to encrypt
 * @param {string} recipientPubHex - Recipient's X25519 public key (64 hex chars)
 * @returns {Promise<{ chainBlob: Uint8Array, relayBlob: Uint8Array, ephPub: Uint8Array }>}
 */
export async function splitEncrypt(plaintext, recipientPubHex) {
  const recipientPub = h2b(recipientPubHex);
  const ephPriv = rand(32);
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPub);

  // Inner encryption
  const innerKey = sha256(shared);
  const innerNonce = rand(12);
  const ck = await crypto.subtle.importKey('raw', innerKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const innerCt = concat(innerNonce, new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: innerNonce, tagLength: 128 }, ck, new TextEncoder().encode(plaintext))));

  // XOR split
  const [shard, pad] = xorSplit(innerCt);

  // Channel-specific wrapping
  const chainBlob = await aesWrap(shard, deriveKeyChain(shared));
  const relayBlob = await aesWrap(pad, deriveKeyRelay(shared));

  return { chainBlob, relayBlob, ephPub };
}

/**
 * Split-knowledge decrypt: recombine chain and relay shards.
 *
 * @param {Uint8Array} chainBlob - Chain-channel shard (from on-chain OP_RETURN)
 * @param {Uint8Array} relayBlob - Relay-channel shard (from Nostr)
 * @param {Uint8Array} ephPub - Sender's ephemeral X25519 public key
 * @param {Uint8Array} myPriv32 - Recipient's X25519 private key (32 bytes)
 * @returns {Promise<string>} Decrypted plaintext
 */
export async function splitDecrypt(chainBlob, relayBlob, ephPub, myPriv32) {
  const shared = x25519.getSharedSecret(myPriv32, ephPub);
  const shard = await aesUnwrap(chainBlob, deriveKeyChain(shared));
  const pad = await aesUnwrap(relayBlob, deriveKeyRelay(shared));
  const innerCt = xorMerge(shard, pad);
  const innerKey = sha256(shared);
  const ck = await crypto.subtle.importKey('raw', innerKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: innerCt.slice(0, 12), tagLength: 128 }, ck, innerCt.slice(12)));
  return new TextDecoder().decode(pt);
}

/* ========================================================================
   CCSHChat Class — High-Level API
   ======================================================================== */

/**
 * High-level CCSH chat session. Manages X25519 keys and provides
 * convenient methods for sending and receiving encrypted messages
 * over both v1 and v2 protocols.
 *
 * @example
 * const chat = CCSHChat.fromSeed(seedHex);
 * console.log('My chat pubkey:', chat.publicKey);
 *
 * // Send v1 message
 * const packet = await chat.encryptV1('Hello!', recipientPubHex);
 *
 * // Send v2 split-knowledge message
 * const { chainBlob, relayBlob, ephPub } = await chat.splitSend('Secret!', recipientPubHex);
 *
 * // Decrypt v1
 * const { text } = await chat.decryptV1(packet);
 *
 * // Decrypt v2
 * const plaintext = await chat.decryptV2(chainBlob, relayBlob, ephPub);
 */
export class CCSHChat {
  /**
   * @param {string} x25519PrivHex - X25519 private key (64 hex chars)
   * @param {string} x25519PubHex - X25519 public key (64 hex chars)
   */
  constructor(x25519PrivHex, x25519PubHex) {
    this._privHex = x25519PrivHex;
    this._pubHex = x25519PubHex;
    this._priv = h2b(x25519PrivHex);
    this._pub = h2b(x25519PubHex);
  }

  /**
   * Derive chat keys from a BIP39 seed.
   * Uses the first 32 bytes of the seed as the X25519 private key.
   *
   * @param {string|Uint8Array} seed - Hex string or raw seed bytes (64 bytes)
   * @returns {CCSHChat}
   */
  static fromSeed(seed) {
    const seedBytes = typeof seed === 'string' ? h2b(seed) : seed;
    const x25519Priv = seedBytes.slice(0, 32);
    const x25519Pub = x25519.getPublicKey(x25519Priv);
    return new CCSHChat(b2h(x25519Priv), b2h(x25519Pub));
  }

  /**
   * X25519 public key hex (for sharing with contacts).
   * @returns {string}
   */
  get publicKey() { return this._pubHex; }

  /**
   * Derive a BCH chat address from the seed (for receiving on-chain messages).
   * Uses the BIP44 BCH address at m/44'/145'/0'/0/0.
   *
   * @param {string|Uint8Array} seed - Full 64-byte seed
   * @returns {string} BCH CashAddr
   */
  static chatAddressFromSeed(seed) {
    const seedBytes = typeof seed === 'string' ? h2b(seed) : seed;
    const { priv } = deriveBchPriv(seedBytes);
    const pub = secp256k1.getPublicKey(priv, true);
    return pubHashToCashAddr(Array.from(ripemd160(sha256(pub))));
  }

  /**
   * Derive the Nostr private key for CCSH relay transport.
   * @returns {Uint8Array} 32-byte Nostr private key
   */
  get nostrPrivKey() {
    return sha256(concat(this._priv, utf8('ccsh-nostr')));
  }

  /**
   * Derive the Nostr public key (x-only) for CCSH relay transport.
   * @returns {string} 64 hex char x-only pubkey
   */
  get nostrPubKey() {
    return b2h(secp256k1.getPublicKey(this.nostrPrivKey, true).slice(1));
  }

  /* ------------------------------------------------------------------
     V1 Methods
     ------------------------------------------------------------------ */

  /**
   * Encrypt a message using CCSH v1 (single-channel AES-GCM).
   *
   * @param {string} text - Plaintext message
   * @param {string} recipientPubHex - Recipient's X25519 public key hex
   * @param {number} [msgType=0x01] - Message type
   * @returns {Promise<Uint8Array>} Packed CCSH v1 binary packet
   */
  async encryptV1(text, recipientPubHex, msgType = 0x01) {
    return ccshEncryptMsg(text, recipientPubHex, this._priv, this._pub, msgType);
  }

  /**
   * Decrypt a CCSH v1 packet.
   *
   * @param {Uint8Array} packet - Binary CCSH v1 packet
   * @returns {Promise<{ text: string, senderPubHex: string, msgType: number }>}
   */
  async decryptV1(packet) {
    return ccshDecryptPacket(packet, this._priv);
  }

  /* ------------------------------------------------------------------
     V2 Split-Knowledge Methods
     ------------------------------------------------------------------ */

  /**
   * Encrypt using v2 split-knowledge protocol.
   *
   * Returns two blobs: one for on-chain delivery (OP_RETURN) and one
   * for relay delivery (Nostr). Both are required to decrypt.
   *
   * @param {string} text - Plaintext message
   * @param {string} recipientPubHex - Recipient's X25519 public key hex
   * @returns {Promise<{ chainBlob: Uint8Array, relayBlob: Uint8Array, ephPub: Uint8Array }>}
   */
  async splitSend(text, recipientPubHex) {
    return splitEncrypt(text, recipientPubHex);
  }

  /**
   * Decrypt a v2 split-knowledge message.
   *
   * @param {Uint8Array} chainBlob - Chain shard (from OP_RETURN)
   * @param {Uint8Array} relayBlob - Relay shard (from Nostr)
   * @param {Uint8Array} ephPub - Sender's ephemeral X25519 pubkey
   * @returns {Promise<string>} Decrypted plaintext
   */
  async decryptV2(chainBlob, relayBlob, ephPub) {
    return splitDecrypt(chainBlob, relayBlob, ephPub, this._priv);
  }

  /* ------------------------------------------------------------------
     Full Send Flow (v2: on-chain + relay)
     ------------------------------------------------------------------ */

  /**
   * Full send: encrypt, split, and publish on both channels.
   *
   * This method handles the complete v2 send flow:
   * 1. Split-encrypt the message
   * 2. Return the blobs for the caller to handle delivery
   *
   * The caller is responsible for:
   * - Embedding chainBlob in a BCH TX OP_RETURN
   * - Publishing relayBlob via Nostr (kind 21059)
   *
   * @param {string} recipientPubHex - Recipient's X25519 public key
   * @param {string} text - Plaintext message
   * @returns {Promise<{ chainBlob: Uint8Array, relayBlob: Uint8Array, ephPub: Uint8Array, senderPub: Uint8Array }>}
   */
  async send(recipientPubHex, text) {
    const { chainBlob, relayBlob, ephPub } = await splitEncrypt(text, recipientPubHex);
    return { chainBlob, relayBlob, ephPub, senderPub: this._pub };
  }

  /* ------------------------------------------------------------------
     Static Protocol Helpers
     ------------------------------------------------------------------ */

  /** @see packPacket */
  static packPacket = packPacket;

  /** @see unpackPacket */
  static unpackPacket = unpackPacket;

  /** @see splitEncrypt */
  static splitEncrypt = splitEncrypt;

  /** @see splitDecrypt */
  static splitDecrypt = splitDecrypt;
}
