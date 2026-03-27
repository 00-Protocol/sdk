/**
 * @00-protocol/sdk — BIP352 Stealth Address Module
 *
 * ECDH-based stealth addresses for Bitcoin Cash. Allows senders to derive
 * one-time addresses for recipients without any on-chain address reuse.
 * Implements the full lifecycle: key derivation, address generation,
 * sending, scanning, and spending.
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
   Low-Level Stealth Primitives
   ======================================================================== */

/**
 * Derive a one-time stealth public key (sender side).
 *
 * ECDH: senderPriv x recipScanPub => shared secret
 * Tweak: c = SHA256( SHA256(sharedX) || tweakData )
 * Stealth pubkey: recipSpendPub + c*G
 *
 * @param {Uint8Array} senderPriv - Sender's private key (32 bytes)
 * @param {Uint8Array} recipScanPub - Recipient's scan public key (33 bytes compressed)
 * @param {Uint8Array} recipSpendPub - Recipient's spend public key (33 bytes compressed)
 * @param {Uint8Array} tweakData - Additional tweak data (e.g., ephPub or nonce)
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
 * Scan for a stealth payment (receiver side).
 *
 * ECDH: scanPriv x senderPub => shared secret
 * Derives the expected stealth pubkey and returns it for comparison.
 *
 * @param {Uint8Array} scanPriv - Receiver's scan private key (32 bytes)
 * @param {Uint8Array} senderPub - Sender's public key from TX input (33 bytes)
 * @param {Uint8Array} spendPub - Receiver's spend public key (33 bytes)
 * @param {Uint8Array} tweakData - Tweak data (e.g., ephPub from OP_RETURN)
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
 * @param {bigint} cBig - Tweak scalar from stealthScan
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
  const hash = ripemd160(sha256(stealthPub));
  return pubHashToCashAddr(hash);
}

/**
 * Encode scan + spend public keys as a stealth code string.
 * Format: "stealth:" + hex(scanPub) + hex(spendPub) = 132 hex chars after prefix.
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

/**
 * Derive a stealth address for sending to a recipient using an ephemeral keypair.
 *
 * The sender generates ephemeral keys, performs ECDH with the recipient's scan
 * pubkey, and derives a one-time address. The ephemeral public key is published
 * in an OP_RETURN output so the recipient can scan for it.
 *
 * @param {Uint8Array} recipScanPub - Recipient scan pubkey (33 bytes)
 * @param {Uint8Array} recipSpendPub - Recipient spend pubkey (33 bytes)
 * @returns {{ addr: string, pub: Uint8Array, ephPriv: Uint8Array, ephPub: Uint8Array }}
 */
export function deriveStealthSendAddr(recipScanPub, recipSpendPub) {
  const ephPriv = secp256k1.utils.randomPrivateKey();
  const ephPub = secp256k1.getPublicKey(ephPriv, true);

  const shared = secp256k1.getSharedSecret(ephPriv, recipScanPub);
  const sharedX = shared.slice(1, 33);

  const c = sha256(concat(sha256(sharedX), ephPub));
  const cBig = BigInt('0x' + b2h(c)) % N_SECP;

  const spendPoint = secp256k1.ProjectivePoint.fromHex(recipSpendPub);
  const tweakPoint = secp256k1.ProjectivePoint.BASE.multiply(cBig);
  const stealthPoint = spendPoint.add(tweakPoint);
  const stealthPubBytes = stealthPoint.toRawBytes(true);

  const addr = pubHashToCashAddr(ripemd160(sha256(stealthPubBytes)));

  return { addr, pub: stealthPubBytes, ephPriv, ephPub };
}

/**
 * Derive a self-stealth address for CoinJoin fusion outputs or stealth change.
 *
 * Uses ECDH: inputPriv x scanPub (symmetric: scanPriv x inputPub)
 * Nonce: outpoint || outputIndex
 * P = B_spend + c*G
 * Spending key: b_spend + c
 *
 * @param {Uint8Array} inputPriv - Private key of the input being spent (32 bytes)
 * @param {Uint8Array} scanPub - Own stealth scan public key (33 bytes)
 * @param {Uint8Array} spendPub - Own stealth spend public key (33 bytes)
 * @param {Uint8Array} spendPriv - Own stealth spend private key (32 bytes)
 * @param {Uint8Array} outpoint - TXID:vout of the input (36 bytes)
 * @param {number} outputIdx - Index of this output in the TX
 * @returns {{ addr: string, pub: Uint8Array, priv: Uint8Array }}
 */
export function deriveSelfStealth(inputPriv, scanPub, spendPub, spendPriv, outpoint, outputIdx) {
  const shared = secp256k1.getSharedSecret(inputPriv, scanPub);
  const sharedX = shared.slice(1, 33);

  const idxBytes = u32LE(outputIdx);
  const nonce = concat(outpoint, idxBytes);

  const c = sha256(concat(sha256(sharedX), nonce));
  const cBig = BigInt('0x' + b2h(c)) % N_SECP;

  const spendPoint = secp256k1.ProjectivePoint.fromHex(spendPub);
  const tweakPoint = secp256k1.ProjectivePoint.BASE.multiply(cBig);
  const stealthPoint = spendPoint.add(tweakPoint);
  const stealthPubBytes = stealthPoint.toRawBytes(true);

  const addr = pubHashToCashAddr(ripemd160(sha256(stealthPubBytes)));

  const bBig = BigInt('0x' + b2h(spendPriv));
  const pBig = (bBig + cBig) % N_SECP;
  const privKey = h2b(pBig.toString(16).padStart(64, '0'));

  return { addr, pub: stealthPubBytes, priv: privKey };
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
 * const { addr, ephPub } = StealthKeys.deriveSendAddress(code);  // payer derives
 * const matches = sk.scanBlock(pubkeys); // receiver scans
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

    // m/352'/145'/0'/0' -- spend branch
    const spend = bip32Child(stealthNode.priv, stealthNode.chain, 0x80000000, true);
    const spendKey = bip32Child(spend.priv, spend.chain, 0, false);

    // m/352'/145'/0'/1' -- scan branch
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
   * Generate a fresh stealth receive address (for displaying to a payer).
   * This creates an ephemeral keypair internally and returns the one-time address.
   *
   * @returns {{ addr: string, pub: Uint8Array, ephPriv: Uint8Array, ephPub: Uint8Array }}
   */
  deriveReceiveAddress() {
    return deriveStealthSendAddr(this.scanPub, this.spendPub);
  }

  /**
   * Static: derive a one-time send address from a stealth code (payer side).
   * The payer calls this with the recipient's stealth code.
   *
   * @param {string} stealthCode - Recipient's stealth code
   * @returns {{ addr: string, pub: Uint8Array, ephPriv: Uint8Array, ephPub: Uint8Array }}
   */
  static deriveSendAddress(stealthCode) {
    const { scanPub, spendPub } = decodeStealthCode(stealthCode);
    return deriveStealthSendAddr(scanPub, spendPub);
  }

  /**
   * Check if a given input pubkey + tweak data corresponds to a payment to us.
   *
   * @param {Uint8Array} inputPubkey - Sender's input public key (33 bytes) or ephemeral pub
   * @param {Uint8Array} [tweakData] - Optional tweak data; defaults to inputPubkey
   * @returns {{ address: string, privKey: Uint8Array, pub: Uint8Array }|null}
   */
  scanPubkey(inputPubkey, tweakData) {
    const tw = tweakData || inputPubkey;
    const { pub, cBig } = stealthScan(this.scanPriv, inputPubkey, this.spendPub, tw);
    const privKey = stealthSpendingKey(this.spendPriv, cBig);
    const address = stealthPubToAddr(pub);
    return { address, privKey, pub };
  }

  /**
   * Batch scan: check multiple pubkeys for incoming stealth payments.
   *
   * @param {Uint8Array[]} pubkeys - Array of sender pubkeys to check
   * @param {Uint8Array[]} [tweakDatas] - Optional per-pubkey tweak data
   * @returns {Array<{ address: string, privKey: Uint8Array, pub: Uint8Array, index: number }>}
   */
  scanBlock(pubkeys, tweakDatas) {
    const matches = [];
    for (let i = 0; i < pubkeys.length; i++) {
      const tw = tweakDatas ? tweakDatas[i] : pubkeys[i];
      try {
        const result = this.scanPubkey(pubkeys[i], tw);
        if (result) {
          matches.push({ ...result, index: i });
        }
      } catch {
        // Invalid pubkey, skip
      }
    }
    return matches;
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
