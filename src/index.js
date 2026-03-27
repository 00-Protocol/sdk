/**
 * @00-protocol/sdk
 *
 * 00 Protocol SDK — application-layer privacy primitives.
 *
 * Modules (current):
 *   - chat       : CCSHChat — split-knowledge encrypted messaging (OP_RETURN + Nostr)
 *   - wizconnect : WizardConnect — BCH dapp/wallet connection protocol (NIP-04)
 *   - common     : Shared crypto primitives
 *
 * Modules (coming soon):
 *   - pay        : 00 Pay — payment terminal & QR invoices
 *   - vault      : 00 Vault — MuSig2 stealth multisig
 *   - subscription: 00 Subscription — recurring BCH payments
 *   - dex        : 00 DEX — on-chain CashToken swaps
 *   - swap       : 00 Swap — atomic cross-chain swaps (BCH/BTC/XMR)
 *
 * BCH stealth/joiner/onion/indexer primitives live in @BCHStealthProtocol/sdk
 *
 * @module @00-protocol/sdk
 */

export * from './chat/index.js';
export * from './wizconnect/index.js';
export * from './common/index.js';
