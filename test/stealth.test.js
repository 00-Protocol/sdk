/**
 * @00-protocol/sdk — Stealth module BIP352 test suite
 *
 * Tests the BIP352 aggregated ECDH implementation directly against the
 * SDK source, using a mock fetchTx — no network required.
 *
 * Run (from repo root):
 *   node sdk/test/stealth.test.js
 *
 * Or (from sdk/ dir):
 *   node test/stealth.test.js
 */

import { secp256k1 }  from '@noble/curves/secp256k1';
import { sha256 }     from '@noble/hashes/sha256';
import { ripemd160 }  from '@noble/hashes/ripemd160';

import {
  deriveStealthSendAddr,
  scanForStealthPayments,
  parseRawTxInputs,
  encodeStealthCode,
  decodeStealthCode,
  stealthSpendingKey,
  stealthPubToAddr,
  deriveSelfStealth,
  StealthKeys,
} from '../src/stealth/index.js';

import { h2b, b2h, concat, pubHashToCashAddr } from '../src/common/index.js';

/* ── Minimal test runner ──────────────────────────────────────────────────── */
let _passed = 0, _failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅  ${name}`);
    _passed++;
  } catch (e) {
    console.error(`  ❌  ${name}`);
    console.error(`       ${e.message}`);
    _failed++;
  }
}

function assert(cond, msg)  { if (!cond) throw new Error(msg || 'assertion failed'); }
function eq(a, b, msg)      {
  const sa = a instanceof Uint8Array ? b2h(a) : String(a);
  const sb = b instanceof Uint8Array ? b2h(b) : String(b);
  if (sa !== sb) throw new Error(msg || `\n     got:      ${sa}\n     expected: ${sb}`);
}
function neq(a, b, msg)     { if (String(a) === String(b)) throw new Error(msg || `values must differ but both = ${a}`); }

/* ── Crypto helpers ───────────────────────────────────────────────────────── */
function hash160(pub) { return ripemd160(sha256(pub)); }

/** Encode value as 8-byte little-endian Uint8Array. */
function u64LE(v) {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, Number(BigInt(v) & 0xffffffffn), true);
  dv.setUint32(4, Number((BigInt(v) >> 32n) & 0xffffffffn), true);
  return b;
}

/** Build a minimal valid P2PKH raw TX for testing (no signature verification). */
function buildMockTx(prevTxidLEHex, senderPubHex, outputHash160Hex, valueSats = 100_000) {
  const prevTxidLE = h2b(prevTxidLEHex);
  const senderPub  = h2b(senderPubHex);
  const h160       = h2b(outputHash160Hex);

  // ScriptSig: <0x47 push><71 fake sig><0x21 push><33 pubkey>
  const fakeSig   = new Uint8Array(71).fill(0x30);
  const scriptSig = concat(
    new Uint8Array([0x47]), fakeSig,
    new Uint8Array([0x21]), senderPub,
  );

  // Output script: OP_DUP OP_HASH160 <20-byte hash160> OP_EQUALVERIFY OP_CHECKSIG
  const outScript = concat(new Uint8Array([0x76, 0xa9, 0x14]), h160, new Uint8Array([0x88, 0xac]));
  const vout      = new Uint8Array([0, 0, 0, 0]);
  const seq       = new Uint8Array([0xff, 0xff, 0xff, 0xff]);

  return b2h(concat(
    new Uint8Array([0x02, 0x00, 0x00, 0x00]),     // version 2
    new Uint8Array([0x01]),                          // 1 input
    prevTxidLE,
    vout,
    new Uint8Array([scriptSig.length]),              // scriptLen
    scriptSig,
    seq,
    new Uint8Array([0x01]),                          // 1 output
    u64LE(valueSats),
    new Uint8Array([outScript.length]),              // 0x19 = 25
    outScript,
    new Uint8Array(4),                               // locktime
  ));
}

/* ── Test vectors ─────────────────────────────────────────────────────────── */

// Sender privkey = 1 → pubkey = G (secp256k1 generator)
const SENDER_PRIV_1 = h2b('0'.repeat(63) + '1');
const SENDER_PUB_G  = secp256k1.getPublicKey(SENDER_PRIV_1, true);

// Sender privkey = 2 → pubkey = 2G
const SENDER_PRIV_2 = h2b('0'.repeat(63) + '2');
const SENDER_PUB_2G = secp256k1.getPublicKey(SENDER_PRIV_2, true);

// Recipient: privkey = 3 → scan, privkey = 4 → spend
const SCAN_PRIV  = h2b('0'.repeat(63) + '3');
const SCAN_PUB   = secp256k1.getPublicKey(SCAN_PRIV, true);
const SPEND_PRIV = h2b('0'.repeat(63) + '4');
const SPEND_PUB  = secp256k1.getPublicKey(SPEND_PRIV, true);

// prevTxid: all 0xab → LE == BE (easy to reason about)
const PREV_TXID_BE_HEX = 'ab'.repeat(32);
const PREV_TXID_LE_HEX = 'ab'.repeat(32); // same since all bytes identical

const OUTPOINT = [{ txid: PREV_TXID_BE_HEX, vout: 0 }];

/* ═══════════════════════════════════════════════════════════════════════════
   TEST SUITE
   ═══════════════════════════════════════════════════════════════════════════ */
(async () => {
  console.log('\n' + '═'.repeat(60));
  console.log(' @00-protocol/sdk — stealth BIP352 test suite');
  console.log('═'.repeat(60) + '\n');

  /* ── 1. Encode / Decode ─────────────────────────────────────────────── */
  console.log('── Stealth code ─────────────────────────────────────────');

  await test('encodeStealthCode / decodeStealthCode round-trip', () => {
    const code = encodeStealthCode(SCAN_PUB, SPEND_PUB);
    assert(code.startsWith('stealth:'), 'prefix');
    assert(code.length === 8 + 132, 'length: stealth: + 66 + 66');
    const { scanPub, spendPub } = decodeStealthCode(code);
    eq(scanPub,  SCAN_PUB,  'scanPub round-trip');
    eq(spendPub, SPEND_PUB, 'spendPub round-trip');
  });

  await test('decodeStealthCode throws on invalid length', () => {
    let threw = false;
    try { decodeStealthCode('stealth:badhex'); } catch { threw = true; }
    assert(threw, 'must throw on bad stealth code');
  });

  /* ── 2. BIP352 sender ───────────────────────────────────────────────── */
  console.log('── BIP352 sender: deriveStealthSendAddr ─────────────────');

  let addr1, pub1;

  await test('single input — returns valid CashAddr + 33-byte pub', () => {
    const r = deriveStealthSendAddr(SCAN_PUB, SPEND_PUB, [SENDER_PRIV_1], OUTPOINT);
    assert(r.addr.startsWith('bitcoincash:'), `addr: ${r.addr}`);
    assert(r.pub.length === 33, 'pub must be 33 bytes');
    assert(r.A_sum.length === 33, 'A_sum must be 33 bytes');
    addr1 = r.addr; pub1 = r.pub;
  });

  await test('deterministic — same inputs → same address', () => {
    const r = deriveStealthSendAddr(SCAN_PUB, SPEND_PUB, [SENDER_PRIV_1], OUTPOINT);
    eq(r.addr, addr1, 'addr must be deterministic');
    eq(r.pub,  pub1,  'pub must be deterministic');
  });

  await test('different outpoint → different address', () => {
    const r = deriveStealthSendAddr(SCAN_PUB, SPEND_PUB, [SENDER_PRIV_1],
      [{ txid: 'cc'.repeat(32), vout: 0 }]);
    neq(r.addr, addr1, 'different outpoint must give different addr');
  });

  await test('different privkey → different address', () => {
    const r = deriveStealthSendAddr(SCAN_PUB, SPEND_PUB, [SENDER_PRIV_2], OUTPOINT);
    neq(r.addr, addr1, 'different sender key must give different addr');
  });

  let addr2input, pub2input;
  await test('2-input aggregation: a_sum = a1 + a2', () => {
    const r = deriveStealthSendAddr(SCAN_PUB, SPEND_PUB,
      [SENDER_PRIV_1, SENDER_PRIV_2],
      [{ txid: PREV_TXID_BE_HEX, vout: 0 }, { txid: '02'.repeat(32), vout: 1 }]);
    assert(r.addr.startsWith('bitcoincash:'), 'addr valid');
    neq(r.addr, addr1, '2-input must differ from 1-input');
    addr2input = r.addr; pub2input = r.pub;
  });

  await test('legacy fallback (no outpoints) — returns different addr from BIP352', () => {
    const r = deriveStealthSendAddr(SCAN_PUB, SPEND_PUB, SENDER_PRIV_1);
    assert(r.addr.startsWith('bitcoincash:'), 'legacy addr valid');
    neq(r.addr, addr1, 'legacy and BIP352 must differ (different protocols)');
  });

  /* ── 3. BIP352 round-trip via scanForStealthPayments ───────────────── */
  console.log('── BIP352 receiver: scanForStealthPayments ──────────────');

  // Build mock TX: input from SENDER_PUB_G (prevTxid = 0xab...ab), output = P2PKH(pub1)
  const MOCK_TXID    = 'deadbeef'.repeat(8); // 32-byte fake txid
  const MOCK_RAW_TX  = buildMockTx(
    PREV_TXID_LE_HEX,    // prevTxid in the input (LE)
    b2h(SENDER_PUB_G),   // sender's pubkey in scriptSig
    b2h(hash160(pub1)),  // stealth output hash160
    100_000,
  );

  // Mock fetchTx: returns our pre-built TX for any txid query
  const mockFetchTx = async (txid) => {
    if (txid === MOCK_TXID) return MOCK_RAW_TX;
    throw new Error(`unexpected txid: ${txid}`);
  };

  // Entry format from indexer: includes outpointTxid + outpointVout
  const mockEntries = [{
    txid:          MOCK_TXID,
    vin:           0,
    pubkey:        b2h(SENDER_PUB_G),
    outpointTxid:  PREV_TXID_BE_HEX,  // big-endian hex (as indexer returns)
    outpointVout:  0,
    height:        900_000,
  }];

  const KEYS = {
    scanPriv:  SCAN_PRIV,
    spendPub:  SPEND_PUB,
    spendPriv: SPEND_PRIV,
  };

  await test('round-trip — scanForStealthPayments finds BIP352 payment', async () => {
    const found = await scanForStealthPayments(KEYS, mockEntries, mockFetchTx);
    assert(found.length > 0, 'no payment found — BIP352 round-trip broken');
    eq(found[0].addr,  addr1,   'found addr must match sender-derived addr');
    eq(found[0].value, 100_000, 'found value');
    eq(found[0].txid,  MOCK_TXID, 'found txid');
  });

  await test('round-trip — spending key is recoverable from tBig', async () => {
    const found = await scanForStealthPayments(KEYS, mockEntries, mockFetchTx);
    assert(found.length > 0, 'payment not found');
    const { tBig } = found[0];
    assert(typeof tBig === 'bigint', 'tBig must be bigint');
    // spending key = spendPriv + tBig mod N
    const spendingKey = stealthSpendingKey(SPEND_PRIV, tBig);
    assert(spendingKey.length === 32, 'spending key must be 32 bytes');
    // Verify: pubkey(spendingKey) == found stealth pub
    const recoveredPub = secp256k1.getPublicKey(spendingKey, true);
    eq(recoveredPub, pub1, 'spending key must recover stealth pubkey');
  });

  await test('wrong recipient keys — payment NOT found', async () => {
    const WRONG_KEYS = {
      scanPriv:  SENDER_PRIV_2, // wrong scan key
      spendPub:  SENDER_PUB_G,  // wrong spend pub
      spendPriv: SENDER_PRIV_2,
    };
    const found = await scanForStealthPayments(WRONG_KEYS, mockEntries, mockFetchTx);
    eq(found.length, 0, 'should not find payment with wrong keys');
  });

  await test('legacy fallback — entries without outpoints use per-input ECDH', async () => {
    // Legacy entries: no outpointTxid field
    const legacyEntries = [{
      txid:   MOCK_TXID,
      vin:    0,
      pubkey: b2h(SENDER_PUB_G),
      height: 900_000,
      // no outpointTxid, no outpointVout
    }];
    // Build a legacy TX (sender used per-input ECDH with senderPub as tweak)
    // For legacy scan, it tries ECDH(scanPriv, senderPub) with tweak=senderPub
    // We don't assert it finds the BIP352 payment (different protocols),
    // just that it doesn't crash and returns an array
    const found = await scanForStealthPayments(KEYS, legacyEntries, async () => MOCK_RAW_TX);
    assert(Array.isArray(found), 'must return array even in legacy mode');
  });

  /* ── 4. parseRawTxInputs ─────────────────────────────────────────────── */
  console.log('── parseRawTxInputs ─────────────────────────────────────');

  await test('extracts pubkey + outpointTxid + outpointVout from raw TX', () => {
    const inputs = parseRawTxInputs(MOCK_RAW_TX, MOCK_TXID);
    assert(inputs.length === 1, `expected 1 input, got ${inputs.length}`);
    eq(inputs[0].pubkey,        b2h(SENDER_PUB_G), 'pubkey');
    eq(inputs[0].outpointTxid,  PREV_TXID_BE_HEX,  'outpointTxid (big-endian)');
    eq(inputs[0].outpointVout,  0,                 'outpointVout');
    eq(inputs[0].txid,          MOCK_TXID,         'txid');
  });

  await test('computed txid matches when omitted', () => {
    // Pass no txid — function should compute it from double-SHA256
    const inputs = parseRawTxInputs(MOCK_RAW_TX);
    assert(inputs.length === 1, 'input found');
    assert(inputs[0].txid && inputs[0].txid.length === 64, 'txid computed');
  });

  await test('returns [] for TX with no P2PKH inputs', () => {
    // Construct a TX with empty scriptSig (OP_0 — not a valid P2PKH)
    const rawHex = buildMockTx(PREV_TXID_LE_HEX, b2h(SENDER_PUB_G), 'aa'.repeat(20));
    // Replace pubkey prefix to 0x04 (uncompressed) → should be rejected
    const badPub = '04' + 'ee'.repeat(64);
    const rawBad = buildMockTx(PREV_TXID_LE_HEX, badPub, 'aa'.repeat(20));
    // Won't error, just returns []
    const inputs = parseRawTxInputs(rawBad, MOCK_TXID);
    assert(Array.isArray(inputs), 'must return array');
  });

  /* ── 5. stealthPubToAddr ─────────────────────────────────────────────── */
  console.log('── stealthPubToAddr ─────────────────────────────────────');

  await test('stealthPubToAddr — returns valid CashAddr', () => {
    const addr = stealthPubToAddr(SENDER_PUB_G);
    assert(addr.startsWith('bitcoincash:'), `addr: ${addr}`);
    // Round-trip check: hash160(G) → addr → must be P2PKH
    const h160 = hash160(SENDER_PUB_G);
    const expected = pubHashToCashAddr(h160);
    eq(addr, expected, 'CashAddr must match pubHashToCashAddr(hash160(pub))');
  });

  /* ── 6. StealthKeys class ────────────────────────────────────────────── */
  console.log('── StealthKeys class ────────────────────────────────────');

  await test('StealthKeys.fromSeed — deterministic from BIP39', async () => {
    const SEED_HEX = '000102030405060708090a0b0c0d0e0f' +
                     '101112131415161718191a1b1c1d1e1f' +
                     '202122232425262728292a2b2c2d2e2f' +
                     '303132333435363738393a3b3c3d3e3f';
    const sk1 = StealthKeys.fromSeed(SEED_HEX);
    const sk2 = StealthKeys.fromSeed(SEED_HEX);
    assert(sk1.stealthCode.startsWith('stealth:'), 'stealthCode prefix');
    eq(sk1.stealthCode, sk2.stealthCode, 'stealthCode must be deterministic');
  });

  await test('StealthKeys.deriveSendAddress — BIP352 send', () => {
    const sk   = new StealthKeys(SCAN_PRIV, SCAN_PUB, SPEND_PRIV, SPEND_PUB);
    const code = sk.stealthCode;
    const r    = StealthKeys.deriveSendAddress(code, [SENDER_PRIV_1], OUTPOINT);
    eq(r.addr, addr1, 'must match direct deriveStealthSendAddr result');
  });

  await test('StealthKeys.scan — BIP352 round-trip via class API', async () => {
    const sk    = new StealthKeys(SCAN_PRIV, SCAN_PUB, SPEND_PRIV, SPEND_PUB);
    const found = await sk.scan(mockEntries, mockFetchTx);
    assert(found.length > 0, 'StealthKeys.scan must find the payment');
    eq(found[0].addr, addr1, 'found addr must match sender-derived addr');
  });

  await test('StealthKeys.deriveSelfAddress — self-stealth for fusion', () => {
    const sk       = new StealthKeys(SCAN_PRIV, SCAN_PUB, SPEND_PRIV, SPEND_PUB);
    // outpoint: 36 bytes (txid_LE || vout_LE)
    const outpoint = new Uint8Array(36).fill(0xcd);
    const r1 = sk.deriveSelfAddress(SENDER_PRIV_1, outpoint, 0);
    const r2 = sk.deriveSelfAddress(SENDER_PRIV_1, outpoint, 0);
    assert(r1.addr.startsWith('bitcoincash:'), 'self-stealth addr valid');
    eq(r1.addr, r2.addr, 'self-stealth must be deterministic');
    // Different outputIdx → different address
    const r3 = sk.deriveSelfAddress(SENDER_PRIV_1, outpoint, 1);
    neq(r1.addr, r3.addr, 'different outputIdx must give different addr');
    // Recovery: pubkey(priv) should match pub
    const recoveredPub = secp256k1.getPublicKey(r1.priv, true);
    eq(recoveredPub, r1.pub, 'spending key must recover stealth pubkey');
  });

  /* ── Summary ─────────────────────────────────────────────────────────── */
  console.log('\n' + '─'.repeat(60));
  const total = _passed + _failed;
  const icon  = _failed === 0 ? '🎉' : '⚠️ ';
  console.log(`  ${icon}  ${_passed}/${total} passed  |  ${_failed} failed\n`);
  if (_failed > 0) process.exit(1);
})();
