/**
 * @00-protocol/sdk — Common crypto primitives and utilities
 *
 * Shared building blocks used by all SDK modules: byte encoding, hashing,
 * BIP32 HD key derivation, CashAddr encoding, BCH transaction construction,
 * and Nostr event signing.
 *
 * @module @00-protocol/sdk/common
 */

import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { secp256k1 } from '@noble/curves/secp256k1';
import { schnorr } from '@noble/curves/secp256k1';

/** secp256k1 curve order */
const N_SECP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/* ========================================================================
   Byte Utilities
   ======================================================================== */

/**
 * Hex string to Uint8Array.
 * @param {string} hex - Hex-encoded string (even length)
 * @returns {Uint8Array}
 */
export function h2b(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  return arr;
}

/**
 * Uint8Array to hex string.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function b2h(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Concatenate multiple Uint8Arrays.
 * @param {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
export function concat(...arrays) {
  const len = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

/**
 * Cryptographically secure random bytes.
 * @param {number} n - Number of bytes
 * @returns {Uint8Array}
 */
export function rand(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * UTF-8 encode a string.
 * @param {string} str
 * @returns {Uint8Array}
 */
export function utf8(str) {
  return new TextEncoder().encode(str);
}

/**
 * Encode a number as unsigned 32-bit little-endian.
 * @param {number} n
 * @returns {Uint8Array}
 */
export function u32LE(n) {
  const b = new Uint8Array(4);
  b[0] = n & 0xff; b[1] = (n >> 8) & 0xff;
  b[2] = (n >> 16) & 0xff; b[3] = (n >> 24) & 0xff;
  return b;
}

/**
 * Encode a number as unsigned 64-bit little-endian.
 * @param {number} n
 * @returns {Uint8Array}
 */
export function u64LE(n) {
  const b = new Uint8Array(8);
  const v = new DataView(b.buffer);
  v.setUint32(0, n >>> 0, true);
  v.setUint32(4, Math.floor(n / 0x100000000) >>> 0, true);
  return b;
}

/**
 * Encode a Bitcoin-style variable-length integer.
 * @param {number} n
 * @returns {Uint8Array}
 */
export function writeVarint(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n < 0x10000) return concat(new Uint8Array([0xfd]), new Uint8Array([n & 0xff, (n >> 8) & 0xff]));
  return concat(new Uint8Array([0xfe]), u32LE(n));
}

/**
 * Read a Bitcoin-style variable-length integer from a buffer.
 * @param {Uint8Array} b - Buffer
 * @param {number} [o=0] - Offset
 * @returns {{ v: number, l: number }} value and byte length consumed
 */
export function readVarint(b, o = 0) {
  const f = b[o];
  if (f < 0xfd) return { v: f, l: 1 };
  if (f === 0xfd) return { v: b[o + 1] | (b[o + 2] << 8), l: 3 };
  return { v: b[o + 1] | (b[o + 2] << 8) | (b[o + 3] << 16) | (b[o + 4] * 16777216), l: 5 };
}

/**
 * Double SHA-256 hash (used in Bitcoin for TXIDs, sighash, etc.).
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function dsha256(data) {
  return sha256(sha256(data));
}

/**
 * Convert satoshis to BCH decimal string.
 * @param {number} s - Satoshis
 * @returns {string}
 */
export function satsToBch(s) {
  return (s / 1e8).toFixed(8);
}

/**
 * Convert BCH decimal string to satoshis.
 * @param {string|number} b - BCH amount
 * @returns {number}
 */
export function bchToSats(b) {
  return Math.round(parseFloat(b) * 1e8);
}

/* ========================================================================
   CashAddr Encoding / Decoding
   ======================================================================== */

const _caCharset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/** @private CashAddr polymod checksum */
function _caPolymod(v) {
  const G = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let c = 1n;
  for (const d of v) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    if (c0 & 1n) c ^= G[0]; if (c0 & 2n) c ^= G[1];
    if (c0 & 4n) c ^= G[2]; if (c0 & 8n) c ^= G[3]; if (c0 & 16n) c ^= G[4];
  }
  return c ^ 1n;
}

/** @private hash-to-CashAddr with version byte */
function _hashToCashAddr(hash20, versionByte, prefix = 'bitcoincash') {
  const payload = new Uint8Array([versionByte, ...hash20]);
  const d5 = []; let acc = 0, bits = 0;
  for (const b of payload) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; d5.push((acc >> bits) & 31); } }
  if (bits > 0) d5.push((acc << (5 - bits)) & 31);
  const pe = [...prefix.split('').map(c => c.charCodeAt(0) & 31), 0];
  const mod = _caPolymod([...pe, ...d5, 0, 0, 0, 0, 0, 0, 0, 0]);
  const cs = []; for (let i = 7; i >= 0; i--) cs.push(Number((mod >> (BigInt(i) * 5n)) & 31n));
  return prefix + ':' + [...d5, ...cs].map(v => _caCharset[v]).join('');
}

/**
 * Encode a public key hash (hash160) as a BCH CashAddr P2PKH address.
 * @param {Uint8Array|number[]} hash20 - 20-byte hash
 * @returns {string} CashAddr string with "bitcoincash:" prefix
 */
export function pubHashToCashAddr(hash20) {
  return _hashToCashAddr(hash20, 0x00);
}

/**
 * Encode a script hash as a BCH CashAddr P2SH address.
 * @param {Uint8Array|number[]} hash20 - 20-byte script hash
 * @returns {string}
 */
export function scriptHashToCashAddr(hash20) {
  return _hashToCashAddr(hash20, 0x08);
}

/**
 * Decode a BCH CashAddr address to its 20-byte hash160.
 * @param {string} addr - CashAddr string (with or without prefix)
 * @returns {Uint8Array} 20-byte hash
 */
export function cashAddrToHash20(addr) {
  const raw = addr.toLowerCase().replace(/^bitcoincash:/, '');
  const data = [];
  for (const c of raw) {
    const v = _caCharset.indexOf(c);
    if (v === -1) throw new Error('invalid cashaddr character: ' + c);
    data.push(v);
  }
  const payload = data.slice(0, -8);
  const bytes = []; let acc = 0, bits = 0;
  for (const v of payload) { acc = (acc << 5) | v; bits += 5; while (bits >= 8) { bits -= 8; bytes.push((acc >> bits) & 0xff); } }
  return new Uint8Array(bytes.slice(1, 21));
}

/* ========================================================================
   Base58Check Encoding / Decoding
   ======================================================================== */

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Base58Check encode a payload.
 * @param {Uint8Array} payload
 * @returns {string}
 */
export function base58Check(payload) {
  const input = concat(payload, dsha256(payload).slice(0, 4));
  let n = BigInt('0x' + b2h(input));
  let str = '';
  while (n > 0n) { str = B58_ALPHABET[Number(n % 58n)] + str; n = n / 58n; }
  for (const b of input) { if (b === 0) str = '1' + str; else break; }
  return str;
}

/**
 * Base58Check decode a string, verifying the checksum.
 * @param {string} str - Base58Check encoded string
 * @returns {Uint8Array} payload bytes (without checksum)
 */
export function base58Decode(str) {
  let n = 0n;
  for (const c of str) {
    const idx = B58_ALPHABET.indexOf(c);
    if (idx === -1) throw new Error('invalid base58 char: ' + c);
    n = n * 58n + BigInt(idx);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  for (const c of str) { if (c === '1') bytes.unshift(0); else break; }
  const data = new Uint8Array(bytes);
  const payload = data.slice(0, -4);
  const checksum = data.slice(-4);
  const expected = dsha256(payload).slice(0, 4);
  if (!expected.every((b, i) => b === checksum[i])) throw new Error('bad checksum');
  return payload;
}

/* ========================================================================
   BIP32 HD Key Derivation
   ======================================================================== */

/**
 * Derive BIP32 master key and chain code from a seed.
 * @param {Uint8Array} seed - BIP39 seed (typically 64 bytes)
 * @returns {{ priv: Uint8Array, chain: Uint8Array }}
 */
export function bip32Master(seed) {
  const I = hmac(sha512, utf8('Bitcoin seed'), seed);
  return { priv: I.slice(0, 32), chain: I.slice(32) };
}

/**
 * Derive a BIP32 child private key (hardened or normal).
 * @param {Uint8Array} priv - Parent private key (32 bytes)
 * @param {Uint8Array} chain - Parent chain code (32 bytes)
 * @param {number} idx - Child index (set high bit for hardened)
 * @param {boolean} hard - Whether this is a hardened derivation
 * @returns {{ priv: Uint8Array, chain: Uint8Array }}
 */
export function bip32Child(priv, chain, idx, hard) {
  const ib = new Uint8Array([idx >>> 24, (idx >>> 16) & 0xff, (idx >>> 8) & 0xff, idx & 0xff]);
  const data = hard
    ? concat(new Uint8Array([0]), priv, ib)
    : concat(secp256k1.getPublicKey(priv, true), ib);
  const I = hmac(sha512, chain, data);
  const child = ((BigInt('0x' + b2h(I.slice(0, 32))) + BigInt('0x' + b2h(priv))) % N_SECP)
    .toString(16).padStart(64, '0');
  return { priv: h2b(child), chain: I.slice(32) };
}

/**
 * Derive a BIP32 child public key (non-hardened only).
 * @param {Uint8Array} parentPub - Parent compressed public key (33 bytes)
 * @param {Uint8Array} parentChain - Parent chain code (32 bytes)
 * @param {number} index - Child index (must be non-hardened)
 * @returns {{ pub: Uint8Array, chain: Uint8Array }}
 */
export function bip32ChildPub(parentPub, parentChain, index) {
  const ib = new Uint8Array([index >>> 24, (index >>> 16) & 0xff, (index >>> 8) & 0xff, index & 0xff]);
  const data = concat(parentPub, ib);
  const I = hmac(sha512, parentChain, data);
  const il = I.slice(0, 32);
  const childPoint = secp256k1.ProjectivePoint.fromHex(b2h(parentPub))
    .add(secp256k1.ProjectivePoint.BASE.multiply(BigInt('0x' + b2h(il))));
  return { pub: childPoint.toRawBytes(true), chain: I.slice(32) };
}

/**
 * Derive the BIP44 BCH account node: m/44'/145'/0'
 * @param {Uint8Array} seed64 - BIP39 seed (64 bytes)
 * @returns {{ priv: Uint8Array, chain: Uint8Array }}
 */
export function deriveAccountNode(seed64) {
  let n = bip32Master(seed64);
  n = bip32Child(n.priv, n.chain, 0x8000002c, true);  // 44'
  n = bip32Child(n.priv, n.chain, 0x80000091, true);  // 145' (BCH)
  n = bip32Child(n.priv, n.chain, 0x80000000, true);  // 0'
  return n;
}

/**
 * Derive the BIP352 stealth account node: m/352'/145'/0'
 * @param {Uint8Array} seed64 - BIP39 seed (64 bytes)
 * @returns {{ priv: Uint8Array, chain: Uint8Array }}
 */
export function deriveBip352Node(seed64) {
  let n = bip32Master(seed64);
  n = bip32Child(n.priv, n.chain, 0x80000160, true);  // 352'
  n = bip32Child(n.priv, n.chain, 0x80000091, true);  // 145' (BCH)
  n = bip32Child(n.priv, n.chain, 0x80000000, true);  // 0'
  return n;
}

/**
 * Derive the BCH private key at m/44'/145'/0'/0/0 from seed.
 * @param {Uint8Array} seed64 - BIP39 seed (64 bytes)
 * @returns {{ priv: Uint8Array, acctPriv: Uint8Array, acctChain: Uint8Array }}
 */
export function deriveBchPriv(seed64) {
  const acct = deriveAccountNode(seed64);
  let n = bip32Child(acct.priv, acct.chain, 0, false);  // external
  n = bip32Child(n.priv, n.chain, 0, false);              // index 0
  return { priv: n.priv, acctPriv: acct.priv, acctChain: acct.chain };
}

/**
 * Derive a BCH CashAddr address from a private key.
 * @param {Uint8Array} priv32 - 32-byte private key
 * @returns {string} CashAddr
 */
export function privToBchAddr(priv32) {
  const pub = secp256k1.getPublicKey(priv32, true);
  return pubHashToCashAddr(Array.from(ripemd160(sha256(pub))));
}

/**
 * Hash a public key to hash160 (RIPEMD160(SHA256(pub))).
 * @param {Uint8Array} pub - Compressed public key (33 bytes)
 * @returns {Uint8Array} 20-byte hash
 */
export function pubToHash160(pub) {
  return ripemd160(sha256(pub));
}

/* ========================================================================
   BCH Transaction Building
   ======================================================================== */

/**
 * Create a P2PKH locking script from a hash160.
 * @param {Uint8Array} hash20 - 20-byte public key hash
 * @returns {Uint8Array} Script: OP_DUP OP_HASH160 <hash20> OP_EQUALVERIFY OP_CHECKSIG
 */
export function p2pkhScript(hash20) {
  return concat(new Uint8Array([0x76, 0xa9, 0x14]), hash20, new Uint8Array([0x88, 0xac]));
}

/**
 * Create a P2SH locking script from a script hash.
 * @param {Uint8Array} hash20 - 20-byte script hash
 * @returns {Uint8Array}
 */
export function p2shScript(hash20) {
  return concat(new Uint8Array([0xa9, 0x14]), hash20, new Uint8Array([0x87]));
}

/**
 * Create an OP_RETURN output script.
 * @param {Uint8Array} data - Payload data
 * @returns {Uint8Array}
 */
export function opReturnScript(data) {
  if (data.length <= 75) return concat(new Uint8Array([0x6a, data.length]), data);
  if (data.length <= 255) return concat(new Uint8Array([0x6a, 0x4c, data.length]), data);
  return concat(new Uint8Array([0x6a, 0x4d, data.length & 0xff, (data.length >> 8) & 0xff]), data);
}

/**
 * Create a P2PKH locking script from a CashAddr address.
 * @param {string} cashAddr - BCH CashAddr address
 * @returns {Uint8Array}
 */
export function p2pkhAddrScript(cashAddr) {
  return p2pkhScript(cashAddrToHash20(cashAddr));
}

/**
 * Compute BIP143 sighash for BCH (SIGHASH_ALL | SIGHASH_FORKID).
 * @param {number} version - Transaction version
 * @param {number} locktime - Transaction locktime
 * @param {Array} inputs - Array of { txidLE, vout, sequence }
 * @param {Array} outputs - Array of { value, script }
 * @param {number} i - Index of the input being signed
 * @param {Uint8Array} utxoScript - Locking script of the UTXO being spent
 * @param {number} utxoValue - Value in satoshis of the UTXO being spent
 * @returns {Uint8Array} 32-byte sighash
 */
export function bchSighash(version, locktime, inputs, outputs, i, utxoScript, utxoValue) {
  const prevouts = concat(...inputs.map(x => concat(x.txidLE, u32LE(x.vout))));
  const seqs = concat(...inputs.map(x => u32LE(x.sequence)));
  const outsData = concat(...outputs.map(o => concat(u64LE(o.value), writeVarint(o.script.length), o.script)));
  const inp = inputs[i];
  return dsha256(concat(
    u32LE(version), dsha256(prevouts), dsha256(seqs),
    inp.txidLE, u32LE(inp.vout),
    writeVarint(utxoScript.length), utxoScript,
    u64LE(utxoValue), u32LE(inp.sequence),
    dsha256(outsData), u32LE(locktime),
    u32LE(0x41)
  ));
}

/**
 * Sign a sighash with a private key and append SIGHASH_ALL|FORKID byte.
 * @param {Uint8Array} sighash - 32-byte sighash
 * @param {Uint8Array} privKey - 32-byte private key
 * @returns {Uint8Array} DER-encoded signature with hashtype byte
 */
export function signInput(sighash, privKey) {
  const sig = secp256k1.sign(sighash, privKey);
  const der = sig.toDERRawBytes();
  return concat(der, new Uint8Array([0x41]));
}

/**
 * Build a P2PKH scriptSig from signature and public key.
 * @param {Uint8Array} sig - DER signature with hashtype byte
 * @param {Uint8Array} pubkey - Compressed public key (33 bytes)
 * @returns {Uint8Array}
 */
export function p2pkhScriptSig(sig, pubkey) {
  return concat(
    new Uint8Array([sig.length]), sig,
    new Uint8Array([pubkey.length]), pubkey
  );
}

/**
 * Serialize a full Bitcoin transaction.
 * @param {number} version
 * @param {number} locktime
 * @param {Array} inputs - Array of { txidLE, vout, scriptSig, sequence }
 * @param {Array} outputs - Array of { value, script }
 * @returns {Uint8Array}
 */
export function serializeTx(version, locktime, inputs, outputs) {
  return concat(
    u32LE(version), writeVarint(inputs.length),
    ...inputs.flatMap(inp => [
      inp.txidLE, u32LE(inp.vout),
      writeVarint(inp.scriptSig.length), inp.scriptSig,
      u32LE(inp.sequence)
    ]),
    writeVarint(outputs.length),
    ...outputs.flatMap(o => [
      u64LE(o.value), writeVarint(o.script.length), o.script
    ]),
    u32LE(locktime)
  );
}

/**
 * Build, sign, and serialize a BCH transaction (BIP143 sighash).
 *
 * @param {Array} inputs - UTXOs: [{ txid, vout, value, ... }]
 * @param {Array} outputs - Outputs: [{ value, script }]
 * @param {Function} getKeyForInput - (utxo, index) => { priv: Uint8Array, pub: Uint8Array }
 * @returns {string} Signed raw transaction hex
 */
export function buildSignedTx(inputs, outputs, getKeyForInput) {
  const hashPrevouts = dsha256(concat(...inputs.map(u => concat(h2b(u.txid).reverse(), u32LE(u.vout)))));
  const hashSequence = dsha256(concat(...inputs.map(() => u32LE(0xffffffff))));
  const hashOutputs = dsha256(concat(...outputs.map(o => concat(u64LE(o.value), writeVarint(o.script.length), o.script))));

  const rawParts = [u32LE(2)];
  rawParts.push(writeVarint(inputs.length));

  for (let i = 0; i < inputs.length; i++) {
    const u = inputs[i];
    const { priv, pub } = getKeyForInput(u, i);
    const iHash160 = ripemd160(sha256(pub));
    const scriptCode = p2pkhScript(iHash160);

    const preimage = concat(
      u32LE(2), hashPrevouts, hashSequence,
      h2b(u.txid).reverse(), u32LE(u.vout),
      writeVarint(scriptCode.length), scriptCode,
      u64LE(u.value), u32LE(0xffffffff),
      hashOutputs, u32LE(0), u32LE(0x41)
    );
    const sighash = dsha256(preimage);
    const sig = secp256k1.sign(sighash, priv);
    const derSig = sig.toDERRawBytes();
    const sigWithHash = concat(derSig, new Uint8Array([0x41]));
    const scriptSig = concat(writeVarint(sigWithHash.length), sigWithHash, writeVarint(pub.length), pub);

    rawParts.push(h2b(u.txid).reverse());
    rawParts.push(u32LE(u.vout));
    rawParts.push(writeVarint(scriptSig.length));
    rawParts.push(scriptSig);
    rawParts.push(u32LE(0xffffffff));
  }

  rawParts.push(writeVarint(outputs.length));
  for (const o of outputs) {
    rawParts.push(u64LE(o.value));
    rawParts.push(writeVarint(o.script.length));
    rawParts.push(o.script);
  }
  rawParts.push(u32LE(0));

  return b2h(concat(...rawParts));
}

/**
 * Estimate transaction size for fee calculation.
 * @param {number} numInputs - Number of P2PKH inputs
 * @param {number} numOutputs - Number of outputs
 * @returns {number} Estimated byte size
 */
export function estimateTxSize(numInputs, numOutputs) {
  return 10 + (numInputs * 148) + (numOutputs * 34);
}

/**
 * Select UTXOs using a largest-first greedy algorithm.
 * @param {Array} utxos - Available UTXOs with .value
 * @param {number} targetSats - Target amount in satoshis
 * @param {number} [feePerByte=1] - Fee rate in sat/byte
 * @returns {{ utxos: Array, total: number, fee: number }|null} null if insufficient
 */
export function selectUtxos(utxos, targetSats, feePerByte = 1) {
  const sorted = [...utxos].sort((a, b) => b.value - a.value);
  const selected = [];
  let total = 0;

  for (const u of sorted) {
    selected.push(u);
    total += u.value;
    const estFee = estimateTxSize(selected.length, 2) * feePerByte;
    if (total >= targetSats + estFee) {
      return { utxos: selected, total, fee: estFee };
    }
  }

  return null;
}

/**
 * Parse a raw transaction hex and extract outputs.
 * @param {string} hex - Raw transaction hex
 * @returns {Array|null} Array of { value, script } or null on failure
 */
export function parseTxHex(hex) {
  try {
    const b = h2b(hex); let p = 0;
    const rB = n => { const s = b.slice(p, p + n); p += n; return s; };
    const rLE = n => { let r = 0; for (let i = 0; i < n; i++) r |= b[p + i] << (i * 8); p += n; return r >>> 0; };
    const rVI = () => { const f = b[p++]; if (f < 0xfd) return f; if (f === 0xfd) return rLE(2); if (f === 0xfe) return rLE(4); return rLE(8); };
    const rLE8 = () => { let lo = rLE(4), hi = rLE(4); return hi * 0x100000000 + lo; };
    rLE(4);
    const inCount = rVI();
    for (let i = 0; i < inCount; i++) { rB(32); rLE(4); rB(rVI()); rLE(4); }
    const outCount = rVI();
    const outputs = [];
    for (let i = 0; i < outCount; i++) {
      const value = rLE8();
      const script = b2h(rB(rVI()));
      outputs.push({ value, script });
    }
    return outputs;
  } catch { return null; }
}

/**
 * Parse OP_RETURN data payloads from a raw transaction hex.
 * @param {string} rawHex - Raw transaction hex
 * @returns {Uint8Array[]} Array of OP_RETURN data payloads
 */
export function parseTxOpReturns(rawHex) {
  try {
    const raw = h2b(rawHex); let pos = 4;
    let { v: inCount, l } = readVarint(raw, pos); pos += l;
    for (let i = 0; i < inCount; i++) {
      pos += 36;
      const { v: sLen, l: sl } = readVarint(raw, pos); pos += sl + sLen + 4;
    }
    const { v: outCount, l: ol } = readVarint(raw, pos); pos += ol;
    const opReturns = [];
    for (let i = 0; i < outCount; i++) {
      pos += 8;
      const { v: sLen, l: sl } = readVarint(raw, pos); pos += sl;
      const script = raw.slice(pos, pos + sLen); pos += sLen;
      if (script[0] === 0x6a) {
        let pay = null;
        if (script[1] <= 75) pay = script.slice(2, 2 + script[1]);
        else if (script[1] === 0x4c) pay = script.slice(3, 3 + script[2]);
        else if (script[1] === 0x4d) { const dlen = script[2] | (script[3] << 8); pay = script.slice(4, 4 + dlen); }
        if (pay?.length) opReturns.push(pay);
      }
    }
    return opReturns;
  } catch { return []; }
}

/**
 * Compute TXID from raw transaction hex (double-SHA256, byte-reversed).
 * @param {string} rawHex - Raw transaction hex
 * @returns {string} TXID hex
 */
export function txidFromRaw(rawHex) {
  const hash = dsha256(h2b(rawHex));
  return b2h(hash.reverse());
}

/* ========================================================================
   Nostr Event Helpers
   ======================================================================== */

/**
 * Create and sign a Nostr event (NIP-01).
 * @param {Uint8Array} privBytes - 32-byte Schnorr private key
 * @param {number} kind - Event kind number
 * @param {string} content - Event content
 * @param {Array} tags - Event tags array
 * @returns {Promise<Object>} Signed Nostr event
 */
export async function makeNostrEvent(privBytes, kind, content, tags = []) {
  const pub = b2h(secp256k1.getPublicKey(privBytes, true).slice(1));
  const created_at = Math.floor(Date.now() / 1000);
  const idHash = sha256(utf8(JSON.stringify([0, pub, created_at, kind, tags, content])));
  const sig = b2h(await schnorr.sign(idHash, privBytes));
  return { id: b2h(idHash), pubkey: pub, created_at, kind, tags, content, sig };
}

/* ========================================================================
   Re-exports (for downstream convenience)
   ======================================================================== */

export { secp256k1, schnorr, sha256, ripemd160, hmac, sha512, N_SECP };
