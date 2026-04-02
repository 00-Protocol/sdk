/**
 * @00-protocol/sdk — Chipnet E2E Stealth Test
 *
 * Sends a REAL stealth payment on BCH chipnet (testnet) and verifies
 * that the receiver can detect it using BIP352 aggregated ECDH.
 *
 * Flow:
 *   1. Connect to chipnet Fulcrum
 *   2. Fetch UTXOs for the sender's test wallet
 *   3. Derive BIP352 stealth address for the test recipient
 *   4. Build + sign + broadcast P2PKH stealth TX
 *   5. Fetch the raw TX from Fulcrum
 *   6. Run scanForStealthPayments → assert payment detected
 *   7. Verify spending key recovers the stealth pubkey
 *
 * Run locally:
 *   CHIPNET_SENDER_PRIV=<hex> CHIPNET_SCAN_PRIV=<hex> CHIPNET_SPEND_PRIV=<hex> \
 *   node sdk/test/stealth.chipnet.test.js
 *
 * In CI: secrets are injected by GitHub Actions (see stealth-tests.yml).
 * Get free chipnet BCH: https://tbch.googol.cash
 */

import { secp256k1 }    from '@noble/curves/secp256k1';
import { sha256 }       from '@noble/hashes/sha256';
import { ripemd160 }    from '@noble/hashes/ripemd160';
import WebSocket        from 'ws';

import {
  deriveStealthSendAddr,
  scanForStealthPayments,
  parseRawTxInputs,
  stealthSpendingKey,
} from '../src/stealth/index.js';

import { h2b, b2h, concat } from '../src/common/index.js';

/* ── Config from environment ──────────────────────────────────────────────── */
const SENDER_PRIV_HEX = process.env.CHIPNET_SENDER_PRIV;
const SCAN_PRIV_HEX   = process.env.CHIPNET_SCAN_PRIV;
const SPEND_PRIV_HEX  = process.env.CHIPNET_SPEND_PRIV;
const FULCRUM_URL     = process.env.CHIPNET_FULCRUM || 'wss://chipnet.imaginary.cash:50004';

if (!SENDER_PRIV_HEX || !SCAN_PRIV_HEX || !SPEND_PRIV_HEX) {
  console.error('Missing env vars: CHIPNET_SENDER_PRIV, CHIPNET_SCAN_PRIV, CHIPNET_SPEND_PRIV');
  process.exit(1);
}

/* ── Minimal test runner ──────────────────────────────────────────────────── */
let _passed = 0, _failed = 0;
function ok(name)         { console.log(`  ✅  ${name}`); _passed++; }
function fail(name, msg)  { console.error(`  ❌  ${name}\n       ${msg}`); _failed++; }
function assert(c, msg)   { if (!c) throw new Error(msg || 'assertion failed'); }
function eq(a, b, msg)    {
  const sa = a instanceof Uint8Array ? b2h(a) : String(a);
  const sb = b instanceof Uint8Array ? b2h(b) : String(b);
  if (sa !== sb) throw new Error(msg || `\n  got: ${sa}\n  exp: ${sb}`);
}

/* ── Crypto helpers ───────────────────────────────────────────────────────── */
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
function hash160(pub)   { return ripemd160(sha256(pub)); }
function dsha256(d)     { return sha256(sha256(d)); }
function u32LE(v)       { const b = new Uint8Array(4); b[0]=v&0xff; b[1]=(v>>8)&0xff; b[2]=(v>>16)&0xff; b[3]=(v>>24)&0xff; return b; }
function u64LE(v)       { const b = new Uint8Array(8); const lo=Number(BigInt(v)&0xffffffffn), hi=Number(BigInt(v)>>32n); b[0]=lo&0xff;b[1]=(lo>>8)&0xff;b[2]=(lo>>16)&0xff;b[3]=(lo>>24)&0xff;b[4]=hi&0xff;b[5]=(hi>>8)&0xff;b[6]=(hi>>16)&0xff;b[7]=(hi>>24)&0xff; return b; }
function writeVI(v)     { if (v<0xfd) return new Uint8Array([v]); const b=new Uint8Array(3); b[0]=0xfd; b[1]=v&0xff; b[2]=(v>>8)&0xff; return b; }
function p2pkhScript(h160) { return concat(new Uint8Array([0x76,0xa9,0x14]),h160,new Uint8Array([0x88,0xac])); }

/** Compute BCH scripthash (reversed sha256 of scriptPubKey) for Fulcrum */
function toScriptHash(pubKeyBytes) {
  const script = p2pkhScript(hash160(pubKeyBytes));
  const h = sha256(script);
  return b2h(new Uint8Array([...h].reverse()));
}

/* ── Minimal Fulcrum JSON-RPC client ─────────────────────────────────────── */
class Fulcrum {
  constructor(url) {
    this.url = url;
    this.ws  = null;
    this.id  = 1;
    this.pending = new Map();
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.on('open',    ()  => resolve());
      this.ws.on('error',   (e) => reject(e));
      this.ws.on('message', (d) => {
        try {
          const msg = JSON.parse(d.toString());
          const cb  = this.pending.get(msg.id);
          if (cb) { this.pending.delete(msg.id); msg.error ? cb.reject(new Error(msg.error.message)) : cb.resolve(msg.result); }
        } catch {}
      });
    });
  }

  call(method, params = []) {
    return new Promise((resolve, reject) => {
      const id = this.id++;
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.has(id)) { this.pending.delete(id); reject(new Error(`Timeout: ${method}`)); }
      }, 30_000);
    });
  }

  close() { this.ws?.close(); }
}

/* ── Build + sign a BCH P2PKH transaction (BIP143 sighash) ──────────────── */
function buildSignedTx(inputs, outputs, getKeyForInput) {
  const hashPrevouts = dsha256(concat(...inputs.map(u =>
    concat(h2b(u.txid).reverse(), u32LE(u.vout)))));
  const hashSequence = dsha256(concat(...inputs.map(() => u32LE(0xffffffff))));
  const hashOutputs  = dsha256(concat(...outputs.map(o =>
    concat(u64LE(o.value), writeVI(o.script.length), o.script))));

  const rawParts = [u32LE(2)];
  rawParts.push(writeVI(inputs.length));

  for (let i = 0; i < inputs.length; i++) {
    const u = inputs[i];
    const { priv, pub } = getKeyForInput(u, i);
    const h160       = hash160(pub);
    const scriptCode = p2pkhScript(h160);
    const preimage   = concat(
      u32LE(2), hashPrevouts, hashSequence,
      h2b(u.txid).reverse(), u32LE(u.vout),
      writeVI(scriptCode.length), scriptCode,
      u64LE(u.value), u32LE(0xffffffff),
      hashOutputs, u32LE(0), u32LE(0x41),
    );
    const sighash     = dsha256(preimage);
    const sig         = secp256k1.sign(sighash, priv);
    const derSig      = sig.toDERRawBytes();
    const sigWithHash = concat(derSig, new Uint8Array([0x41]));
    const scriptSig   = concat(writeVI(sigWithHash.length), sigWithHash, writeVI(pub.length), pub);

    rawParts.push(h2b(u.txid).reverse(), u32LE(u.vout),
      writeVI(scriptSig.length), scriptSig, u32LE(0xffffffff));
  }

  rawParts.push(writeVI(outputs.length));
  for (const o of outputs) {
    rawParts.push(u64LE(o.value), writeVI(o.script.length), o.script);
  }
  rawParts.push(u32LE(0));

  return b2h(concat(...rawParts));
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN E2E TEST
   ═══════════════════════════════════════════════════════════════════════════ */
(async () => {
  console.log('\n' + '═'.repeat(60));
  console.log(' 00 Protocol — Chipnet BIP352 E2E test');
  console.log(` Fulcrum: ${FULCRUM_URL}`);
  console.log('═'.repeat(60) + '\n');

  // ── Keys ────────────────────────────────────────────────────────────────
  const senderPriv = h2b(SENDER_PRIV_HEX.padStart(64, '0'));
  const senderPub  = secp256k1.getPublicKey(senderPriv, true);
  const scanPriv   = h2b(SCAN_PRIV_HEX.padStart(64, '0'));
  const scanPub    = secp256k1.getPublicKey(scanPriv, true);
  const spendPriv  = h2b(SPEND_PRIV_HEX.padStart(64, '0'));
  const spendPub   = secp256k1.getPublicKey(spendPriv, true);

  console.log(`  Sender:  ${b2h(senderPub)}`);
  console.log(`  ScanPub: ${b2h(scanPub)}`);
  console.log();

  const fulcrum = new Fulcrum(FULCRUM_URL);

  try {
    // ── 1. Connect ──────────────────────────────────────────────────────
    console.log('── Connecting to Fulcrum ────────────────────────────────');
    await fulcrum.connect();
    const tip = await fulcrum.call('blockchain.headers.subscribe');
    const height = tip?.height || tip;
    console.log(`  ✅  Connected — tip block: ${height}\n`);

    // ── 2. Fetch UTXOs ──────────────────────────────────────────────────
    console.log('── Fetching UTXOs ───────────────────────────────────────');
    const scriptHash = toScriptHash(senderPub);
    const utxos = await fulcrum.call('blockchain.scripthash.listunspent', [scriptHash]);

    if (!utxos?.length) {
      console.warn('  ⚠️   No UTXOs found — fund the sender address with chipnet BCH first:');
      console.warn(`       https://tbch.googol.cash`);
      // Don't fail CI — just skip the test gracefully
      console.log('\n  ℹ️   Chipnet e2e skipped (no funds). Unit tests cover the crypto.\n');
      process.exit(0);
    }

    const totalSats = utxos.reduce((s, u) => s + u.value, 0);
    console.log(`  ✅  ${utxos.length} UTXO(s) — total: ${totalSats} sats\n`);

    // ── 3. BIP352 stealth address derivation ────────────────────────────
    console.log('── BIP352 sender: derive stealth address ────────────────');
    const outpoints = utxos.map(u => ({ txid: u.tx_hash, vout: u.tx_pos }));
    const { addr: stealthAddr, pub: stealthPub } = deriveStealthSendAddr(
      scanPub, spendPub, [senderPriv], outpoints,
    );
    console.log(`  ✅  Stealth addr: ${stealthAddr}\n`);

    // ── 4. Build + broadcast TX ─────────────────────────────────────────
    console.log('── Building + broadcasting stealth TX ───────────────────');

    const SEND_SATS = 1000;
    const FEE_SATS  = 250;
    const changeSats = totalSats - SEND_SATS - FEE_SATS;

    const inputs = utxos.map(u => ({
      txid: u.tx_hash, vout: u.tx_pos, value: u.value,
    }));

    const outputs = [
      // Stealth output
      { value: SEND_SATS, script: p2pkhScript(hash160(stealthPub)) },
    ];
    if (changeSats >= 546) {
      // Change back to sender
      outputs.push({ value: changeSats, script: p2pkhScript(hash160(senderPub)) });
    }

    const rawTxHex = buildSignedTx(inputs, outputs, () => ({ priv: senderPriv, pub: senderPub }));

    let broadcastedTxid;
    try {
      broadcastedTxid = await fulcrum.call('blockchain.transaction.broadcast', [rawTxHex]);
      assert(broadcastedTxid?.length === 64, `broadcast returned: ${broadcastedTxid}`);
      console.log(`  ✅  TX broadcast: ${broadcastedTxid}\n`);
      ok('TX broadcast accepted by chipnet node');
    } catch (e) {
      fail('TX broadcast', e.message);
      throw e;
    }

    // ── 5. Fetch raw TX + parse inputs ──────────────────────────────────
    console.log('── Fetching raw TX + parsing inputs ─────────────────────');

    // Small delay to ensure mempool propagation
    await new Promise(r => setTimeout(r, 1500));

    let fetchedRawHex;
    try {
      fetchedRawHex = await fulcrum.call('blockchain.transaction.get', [broadcastedTxid]);
      assert(fetchedRawHex?.length > 0, 'empty raw TX');
      ok('Raw TX fetched from Fulcrum mempool');
    } catch (e) {
      fail('Fetch raw TX', e.message);
      throw e;
    }

    const parsedInputs = parseRawTxInputs(fetchedRawHex, broadcastedTxid);
    try {
      assert(parsedInputs.length > 0, 'no inputs parsed from TX');
      assert(parsedInputs[0].outpointTxid, 'missing outpointTxid');
      assert(parsedInputs[0].outpointVout != null, 'missing outpointVout');
      console.log(`  ✅  ${parsedInputs.length} input(s) parsed, outpointTxid: ${parsedInputs[0].outpointTxid.slice(0, 20)}…\n`);
      ok('parseRawTxInputs extracts pubkeys + outpoints');
    } catch (e) {
      fail('parseRawTxInputs', e.message);
      throw e;
    }

    // ── 6. BIP352 receiver scan ──────────────────────────────────────────
    console.log('── BIP352 receiver: scanForStealthPayments ──────────────');

    const mockFetchTx = async (txid) => {
      if (txid === broadcastedTxid) return fetchedRawHex;
      // For other txids, fetch from Fulcrum (outpoint inputs)
      return fulcrum.call('blockchain.transaction.get', [txid]);
    };

    const KEYS = { scanPriv, spendPub, spendPriv };
    let found;
    try {
      found = await scanForStealthPayments(KEYS, parsedInputs, mockFetchTx);
      assert(found.length > 0, 'scanForStealthPayments found nothing — BIP352 round-trip broken');
      ok('BIP352 round-trip — payment detected by receiver');
    } catch (e) {
      fail('scanForStealthPayments', e.message);
      throw e;
    }

    // ── 7. Verify address + spending key ─────────────────────────────────
    console.log('── Verifying detected payment ───────────────────────────');
    try {
      const detected = found[0];
      eq(detected.addr, stealthAddr, 'detected addr must match sender-derived addr');
      ok(`Detected addr matches sender-derived addr`);

      eq(detected.value, SEND_SATS, 'detected value must equal sent amount');
      ok(`Value correct: ${detected.value} sats`);

      // Spending key recovery
      const spendingKey = stealthSpendingKey(spendPriv, detected.tBig);
      assert(spendingKey.length === 32, 'spending key must be 32 bytes');
      const recoveredPub = secp256k1.getPublicKey(spendingKey, true);
      eq(recoveredPub, stealthPub, 'spending key must recover stealth pubkey');
      ok('Spending key recovers stealth pubkey — funds are spendable');
    } catch (e) {
      fail('Payment verification', e.message);
    }

  } finally {
    fulcrum.close();
  }

  /* ── Summary ──────────────────────────────────────────────────────────── */
  console.log('\n' + '─'.repeat(60));
  const total = _passed + _failed;
  const icon  = _failed === 0 ? '🎉' : '⚠️ ';
  console.log(`  ${icon}  ${_passed}/${total} passed  |  ${_failed} failed\n`);
  if (_failed > 0) process.exit(1);
})().catch(e => {
  console.error(`\nFatal: ${e.message}`);
  process.exit(1);
});
