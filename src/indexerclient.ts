/**
 * The indexer, as this service uses it.
 *
 * One call: what has become of a transaction hash. That is deliberately the whole of it — settlement
 * does not watch addresses, does not read activity and does not ask the indexer anything about
 * money. AD-07 records why the estate split the two: forge-pay's watcher polls every address row on
 * every tick and reads a BALANCE, which is why its deposits have no transaction hashes and why a
 * balance regression can freeze crediting for an account permanently. A service that both watches
 * the chain and moves the money is a service where a bug in the first half spends the second half.
 *
 * ## Why the indexer AND the node, and which one wins
 *
 * The indexer is the estate's declared reader of chain state and it applies the same
 * `contracts-chain` confirmation depths this service does, so where it has an answer, its answer is
 * the one to use. But it is a FOLLOWER: its worker walks blocks, so a transaction broadcast four
 * seconds ago is not in it yet, and "the indexer has never heard of this hash" is emphatically not
 * "the chain does not have it". Reading that as an absence would mark every fresh broadcast
 * unknown, re-send it every tick, and — because the stuck clock runs from the broadcast — declare a
 * perfectly healthy payment stuck an hour later.
 *
 * So the rule in `outbound.ts` is: **the indexer when it has the transaction, the node when it does
 * not, and neither is allowed to be silently absent.** The node is also the only one that can
 * answer the question the adjudication path actually turns on — `eth_getTransactionCount` at
 * `latest`, which is not chain data the indexer stores.
 */

import { HttpClient, HttpError } from '@cloudsforge/http'
import type { Network } from '@cloudsforge/contracts-chain'
import type { ChainId } from './chains.ts'

export const INDEXER_SCOPES: readonly string[] = Object.freeze(['indexer:read'])

export class IndexerUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'IndexerUnavailableError'
  }
}

/**
 * One transaction as the indexer holds it.
 *
 * `status` is the indexer's normalised vocabulary from 04-domain-model §4.1 — `pending · success ·
 * failed · dropped · orphaned` — and the mapping onto this service's `OutboundStatus` is in
 * `outbound.ts` rather than here, because it is a decision about money and belongs where the rest
 * of those decisions are.
 *
 * `confirmations` is nullable and null is **not zero**: it means the indexer knows the transaction
 * but cannot currently say how deep it is, which happens while a chain's tip is being re-read after
 * a reorg. A caller that read null as zero would treat a confirmed payment as fresh.
 */
export interface IndexedTransaction {
  readonly hash: string
  readonly status: string
  readonly blockHeight: number | null
  readonly confirmations: number | null
  readonly from: string | null
  readonly to: string | null
  readonly value: string
  readonly fee: string | null
}

export interface IndexerClient {
  /** Null when the indexer has never seen this hash. Never an exception for a 404. */
  transaction(chain: ChainId, network: Network, hash: string): Promise<IndexedTransaction | null>
}

export interface IndexerClientOptions {
  readonly baseUrl: string
  readonly token: () => Promise<string | undefined> | string | undefined
  readonly deadlineMs: number
  readonly fetch?: typeof globalThis.fetch
}

export function httpIndexerClient(options: IndexerClientOptions): IndexerClient {
  const client = new HttpClient({
    baseUrl: options.baseUrl,
    name: 'indexer',
    defaultDeadlineMs: options.deadlineMs,
    token: options.token,
    ...(options.fetch ? { fetch: options.fetch } : {}),
  })

  return {
    async transaction(chain, network, hash) {
      try {
        return await client.get<IndexedTransaction>(
          `/v1/transactions/${chain}/${network}/${encodeURIComponent(hash)}`,
        )
      } catch (err) {
        // A 404 is an ANSWER — "not indexed yet" — and the caller falls through to the node. Any
        // other 4xx is a fault in the request itself and any 5xx is an outage; both become an
        // unavailability, which the caller treats as "ask the node" rather than as "not on chain".
        if (err instanceof HttpError && err.status === 404) return null
        throw new IndexerUnavailableError(err instanceof Error ? err.message : String(err))
      }
    },
  }
}
