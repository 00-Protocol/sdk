# @00-protocol/sdk

Privacy toolkit for Bitcoin Cash. Stealth addresses, silent CoinJoin, onion routing, encrypted chat, and wallet connection protocol.

## Installation

```bash
npm install @00-protocol/sdk
```

Dependencies (`@noble/curves` and `@noble/hashes`) are installed automatically.

For NIP-44 encryption (used by onion/giftwrap), also install:
```bash
npm install @noble/ciphers
```

## Quick Start

### Stealth Addresses (BIP352)

Derive stealth keys from a BIP39 seed and generate one-time addresses that prevent on-chain address reuse.

```javascript
import { StealthKeys } from '@00-protocol/sdk/stealth';

// Receiver: derive keys from seed
const sk = StealthKeys.fromSeed(seedHex);
const code = sk.stealthCode;  // share this with payers

// Sender: derive a one-time address from the stealth code
const { addr, ephPub } = StealthKeys.deriveSendAddress(code);
// Send BCH to `addr`, publish `ephPub` in OP_RETURN

// Receiver: scan for incoming payments
const matches = sk.scanBlock(ephemeralPubkeys);
for (const m of matches) {
  console.log('Found payment at', m.address);
  // m.privKey can spend this output
}
```

### Silent CoinJoin (Joiner)

Multi-party mixing with onion-encrypted blind outputs for unlinkable CoinJoin transactions.

```javascript
import { Joiner } from '@00-protocol/sdk/joiner';
import { StealthKeys } from '@00-protocol/sdk/stealth';

const joiner = new Joiner({
  nostrRelays: ['wss://relay.damus.io', 'wss://nos.lol'],
  fulcrumUrl: 'wss://bch.loping.net:50004',
});

joiner.onPhaseChange(phase => console.log('Phase:', phase));
joiner.onComplete(result => console.log('Mixed:', result));
joiner.onError(err => console.error('Mix error:', err));

const sk = StealthKeys.fromSeed(seedHex);
await joiner.mix(utxos, { rounds: 3, stealthKeys: sk });
```

### Onion Relay

Layered encryption for relay routing. Each hop can only see the next destination.

```javascript
import { onionWrap, onionPeel, onionUnpad, OnionRelay } from '@00-protocol/sdk/onion';

// Wrap a payload for multi-hop routing
const payload = 'bitcoincash:qz...|10000';
const relayPubs = [relay1PubHex, relay2PubHex, relay3PubHex];
const blob = await onionWrap(payload, relayPubs);

// Each relay peels its layer
const inner = await onionPeel(blob, relay1PrivKey);
// Final relay parses the payload
const { addr, value } = onionUnpad(inner);

// Run a relay node
const relay = new OnionRelay({
  nostrRelays: ['wss://relay.damus.io'],
});
relay.onBlob((inner, from) => {
  console.log('Relayed blob from', from);
});
await relay.start();
```

### Encrypted Chat (CCSH)

End-to-end encrypted messaging with split-knowledge: half the ciphertext goes on-chain, half via Nostr relay.

```javascript
import { CCSHChat } from '@00-protocol/sdk/chat';

const chat = CCSHChat.fromSeed(seedHex);
console.log('Chat pubkey:', chat.publicKey);

// V1: single-channel encrypted message
const packet = await chat.encryptV1('Hello!', recipientPubHex);
const { text } = await chat.decryptV1(packet);

// V2: split-knowledge (requires both channels to decrypt)
const { chainBlob, relayBlob, ephPub } = await chat.splitSend('Secret!', recipientPubHex);
// Embed chainBlob in BCH TX OP_RETURN, send relayBlob via Nostr
const plaintext = await chat.decryptV2(chainBlob, relayBlob, ephPub);
```

### WizardConnect

HD wallet connection protocol. Connect dapps to wallets for xpub exchange and transaction signing.

```javascript
import { WizardConnect } from '@00-protocol/sdk/wizconnect';

// Wallet side: generate QR and wait for dapp
const wallet = new WizardConnect({ role: 'wallet', nostrRelays: ['wss://relay.damus.io'] });
const { uri, qrUri } = await wallet.generateQR();
// Display qrUri as QR code
wallet.onConnected((name, icon) => console.log('Dapp connected:', name));
wallet.onSignRequest(req => {
  // Review and approve/reject
  wallet.approveSign(req.sequence, signedTxHex);
});
await wallet.waitForDapp({ paths, extensions });

// Dapp side: scan QR and connect
const dapp = new WizardConnect({ role: 'dapp', nostrRelays: ['wss://relay.damus.io'] });
await dapp.connectToWallet(wizUri);
dapp.onConnected((walletName, icon, paths) => {
  const receivePub = dapp.derivePubkey('receive', 0);
});
const signedTx = await dapp.requestSign(unsignedTxHex);
```

### Common Utilities

Low-level crypto primitives shared across all modules.

```javascript
import {
  h2b, b2h, concat, rand,
  bip32Master, bip32Child, deriveBchPriv,
  pubHashToCashAddr, cashAddrToHash20,
  buildSignedTx, p2pkhScript, opReturnScript,
  makeNostrEvent,
} from '@00-protocol/sdk/common';

// BIP32 HD key derivation
const { priv, chain } = bip32Master(seed);
const child = bip32Child(priv, chain, 0, false);

// CashAddr encoding
const addr = pubHashToCashAddr(hash160);
const hash = cashAddrToHash20(addr);

// Build and sign a BCH transaction
const rawHex = buildSignedTx(utxos, outputs, (utxo, i) => ({
  priv: privKey,
  pub: pubKey,
}));
```

## Architecture

```
@00-protocol/sdk
  |
  +-- common/       Byte utils, hashing, BIP32, CashAddr, TX builder, Nostr
  |
  +-- stealth/      BIP352 stealth addresses (ECDH + tweak derivation)
  |
  +-- joiner/       CoinJoin protocol engine (pool, round, onion outputs)
  |
  +-- onion/        Layered encryption (AES-GCM), NIP-04/44/59, relay node
  |
  +-- chat/         CCSH v1 (X25519+AES) and v2 (split-knowledge XOR)
  |
  +-- wizconnect/   WizardConnect hdwalletv1 (xpub exchange + TX signing)
```

## Module Exports

| Import path | Key exports |
|---|---|
| `@00-protocol/sdk` | All modules as namespaces |
| `@00-protocol/sdk/stealth` | `StealthKeys`, `stealthDerive`, `deriveStealthSendAddr` |
| `@00-protocol/sdk/joiner` | `Joiner`, `Phase`, `randomSplit` |
| `@00-protocol/sdk/onion` | `onionWrap`, `onionPeel`, `OnionRelay`, `giftWrap`, `nip04Encrypt` |
| `@00-protocol/sdk/chat` | `CCSHChat`, `splitEncrypt`, `splitDecrypt`, `packPacket` |
| `@00-protocol/sdk/wizconnect` | `WizardConnect`, `wizEncodeURI`, `wizDecodeURI`, `WIZ_EXTENSIONS` |
| `@00-protocol/sdk/common` | `h2b`, `b2h`, `bip32Child`, `buildSignedTx`, `makeNostrEvent`, ... |

## Specifications

- [BCH Stealth Protocol (BIP352 adaptation)](https://github.com/00-Protocol/BCH-Stealth-Protocol)
- [WizardConnect hdwalletv1](https://github.com/AustinKelsworthy/wizardconnect)
- [CCSH Chat Protocol](https://github.com/AustinKelsworthy/CCSH-Messaging-Protocol)
- [Nostr NIPs](https://github.com/nostr-protocol/nips) (NIP-01, NIP-04, NIP-44, NIP-59)

## License

MIT
