/**
 * @BCHStealthProtocol/sdk — BCHPubkeyIndexer Client
 *
 * Lightweight client for the BCH Pubkey Indexer API. Fetches P2PKH input
 * pubkeys for a block range, enabling client-side stealth address scanning
 * without revealing which addresses you control to any server.
 *
 * The indexer server returns ALL compressed pubkeys for a block range —
 * equivalent privacy to downloading full blocks, ~90% less data.
 *
 * Desktop wallets can also self-host the indexer (BCH-Stealth-Protocol repo).
 * Lightweight clients connect to a hosted indexer over HTTP or Tor.
 *
 * @module @BCHStealthProtocol/sdk/indexer
 */

/**
 * A single pubkey entry returned by the indexer.
 * @typedef {Object} PubkeyEntry
 * @property {number}  height       - Block height
 * @property {string}  txid         - Transaction ID (hex)
 * @property {number}  vin          - Input index within the transaction
 * @property {string}  pubkey       - Compressed public key (33 bytes, hex)
 * @property {string}  outpointTxid - Outpoint TXID (hex)
 * @property {number}  outpointVout - Outpoint vout index
 */

/**
 * BCHPubkeyIndexer — client for the BCH Pubkey Indexer HTTP API.
 *
 * Connects to a hosted indexer server and fetches pubkeys for block ranges.
 * The server is never told which pubkeys you care about — you receive all of
 * them and filter locally using ECDH.
 *
 * @example
 * import { BCHPubkeyIndexer } from '@BCHStealthProtocol/sdk/indexer';
 *
 * const indexer = new BCHPubkeyIndexer('https://indexer.0penw0rld.com');
 *
 * // Scan blocks 943000–943100 for stealth payments
 * for await (const entry of indexer.scan(943000, 943100)) {
 *   const shared = ecdh(scanPriv, hexToBytes(entry.pubkey));
 *   // ... check if derived address is in UTXO set
 * }
 */
export class BCHPubkeyIndexer {
  /**
   * @param {string} serverUrl - Base URL of the indexer server (no trailing slash)
   *   e.g. "https://indexer.0penw0rld.com" or "http://localhost:3847"
   * @param {object} [opts]
   * @param {number} [opts.maxRange=100]  - Max blocks per request (server-enforced)
   * @param {number} [opts.retries=3]     - Retry attempts on network error
   */
  constructor(serverUrl, opts = {}) {
    this.serverUrl = serverUrl.replace(/\/$/, '');
    this.maxRange = opts.maxRange ?? 100;
    this.retries = opts.retries ?? 3;
  }

  /**
   * Fetch pubkey entries for a block range (single request, ≤ maxRange blocks).
   *
   * @param {number} from - Start block height (inclusive)
   * @param {number} to   - End block height (inclusive)
   * @returns {Promise<PubkeyEntry[]>}
   */
  async getPubkeys(from, to) {
    const url = `${this.serverUrl}/api/pubkeys?from=${from}&to=${to}`;
    let attempt = 0;
    while (attempt <= this.retries) {
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
        const data = await res.json();
        return data.entries ?? [];
      } catch (err) {
        attempt++;
        if (attempt > this.retries) throw err;
        await new Promise(r => setTimeout(r, 500 * attempt));
      }
    }
  }

  /**
   * Async generator: stream pubkeys across a large block range, chunked
   * automatically to respect the server's maxRange limit.
   *
   * @param {number} from - Start block height (inclusive)
   * @param {number} to   - End block height (inclusive)
   * @yields {PubkeyEntry}
   *
   * @example
   * for await (const entry of indexer.scan(943000, 943500)) {
   *   // process each pubkey entry
   * }
   */
  async *scan(from, to) {
    for (let start = from; start <= to; start += this.maxRange) {
      const end = Math.min(start + this.maxRange - 1, to);
      const entries = await this.getPubkeys(start, end);
      yield* entries;
    }
  }

  /**
   * Check server health.
   * @returns {Promise<object>} Health status from the indexer server
   */
  async health() {
    const res = await fetch(`${this.serverUrl}/api/health`);
    return res.json();
  }

  /**
   * Get indexer statistics (cached block range, entry counts).
   * @returns {Promise<object>}
   */
  async stats() {
    const res = await fetch(`${this.serverUrl}/api/stats`);
    return res.json();
  }
}
