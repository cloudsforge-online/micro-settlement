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
import type { ChainId, OutpointCandidate } from './chains.ts'
import type { LiveScope } from '@cloudsforge/contracts-auth'

/**
 * The scopes this service's token must carry to call this peer.
 *
 * `readonly LiveScope[]` rather than `readonly string[]`: see the header of `custodyclient.ts`.
 * This is an outbound demand, `derive-grants.mjs` reads it into the estate's grant list, and
 * identity
 * refuses to boot on a name the registry does not have — or has deprecated, which `Scope` alone
 * would not have caught.
 */
export const INDEXER_SCOPES: readonly LiveScope[] = Object.freeze(['indexer:read', 'indexer:write'])

/**
 * The label prefix that makes an address part of the indexer's CUSTODY SET.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS PREFIX IS A CROSS-SERVICE CONTRACT AND IT HAS NEVER BEEN HONOURED BY ANYBODY.**
 *
 * `GET /v1/custody/:chain/:network/total` is the number `micro-ledger` reconciles the platform's
 * solvency against, and its set is `watched_addresses` filtered by
 * `INDEXER_CUSTODY_LABEL_PREFIXES` — default `deposit:,treasury:`
 * (`indexer/src/store.ts` `custodyAddresses`). `micro-wallet` writes the first prefix for every
 * deposit address it assigns. **Nothing in fifty-eight repositories has ever written the second**,
 * and this service is precisely the one that moves coin from an address carrying the first into an
 * address that should carry the second.
 *
 * The consequence is not subtle and it is not rare: every sweep shrinks the aggregate while the
 * ledger's custody total is unchanged, which is a POSITIVE drift, which FREEZES WITHDRAWALS. The
 * safe direction, and a certainty rather than a risk — consolidating deposits is what a treasury is
 * FOR.
 *
 * The suffix is the chain and network rather than an id, because the operator use of this label is
 * reading `watched_addresses` beside a freeze and asking which set was summed. `micro-indexer`
 * truncates a label to 200 characters (`indexer/src/server.ts`), which this cannot approach.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function treasuryLabel(chain: ChainId, network: Network): string {
  return `treasury:${chain}:${network}`
}

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
  /**
   * Register an address as one the platform holds, under `label`.
   *
   * Idempotent on the far side — the store does `on conflict (chain, network, address) do update
   * set label = excluded.label` — so a re-registration is a no-op rather than a second row, and the
   * job that calls this may safely run again after a partial failure.
   *
   * **Throws rather than returning a status.** A registration that silently failed is a treasury
   * the aggregate cannot see, which is the defect this method exists to close; the caller must be
   * able to tell "registered" from "tried", because it writes the former down.
   *
   * `freshlyDerived` is a STATEMENT ABOUT THE ADDRESS'S PAST and the caller must be entitled to
   * make it: "nothing can have paid this, because it did not exist until a moment ago". On a UTXO
   * chain the indexer will not call a derived balance a balance without one (micro-org#252), and
   * without a balance the treasury can be neither registered nor booked. `treasury.ts` holds the
   * rule for when this service is entitled — only for an address it minted through custody itself
   * — and it is `false` here by default so that reaching for it has to be deliberate.
   *
   * A boolean and not a height: the indexer resolves it against its own canonical tip, which is
   * the only height comparable with the record its derivation reads.
   */
  watch(
    chain: ChainId,
    network: Network,
    address: string,
    label: string,
    freshlyDerived?: boolean,
  ): Promise<void>
  /**
   * What the indexer will count for one address, measured the way it will count it.
   *
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * **THIS SERVICE DOES NOT MEASURE CHAIN BALANCES FOR THE LEDGER, AND THAT IS THE POINT.**
   *
   * It has an adapter that could: `chainFor(chain).spendableBalance(...)` is one call away and
   * reads `eth_getBalance` at `latest`. Using it here would be wrong in a way that is invisible
   * until it freezes an asset. The indexer's aggregate reads at `head − confirmations + 1` — 60
   * blocks deep on EMBER — so a balance read at `latest` includes coin the aggregate will not
   * count for another fifteen minutes. Book that number and the ledger is high by exactly the
   * recent arrivals, and a zero-tolerance asset refuses every withdrawal until someone works out
   * why. `spendableBalance` is also not even the same QUESTION on two families: Solana subtracts
   * the rent-exempt minimum and Bitcoin sums confirmed UTXOs, and neither is what the aggregate
   * sums.
   *
   * So the amount booked is not this service's opinion about the chain. It is the reconciler's own
   * measurement, at the reconciler's own depth, against a block hash the reconciler proved before
   * and after reading — asked for by name, one address at a time.
   *
   * **Throws rather than returning null.** There is no absence here: an account always has a
   * balance, so an indexer that will not state one has told us nothing, and nothing is not zero. A
   * zero booked as an opening balance is a permanent understatement of custody that no later run
   * can detect, which is the incident this whole path exists to prevent, inverted.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   */
  custodyBalance(chain: ChainId, network: Network, address: string): Promise<ObservedBalance>
  /**
   * Which outpoints an address may still hold — the CANDIDATES a bitcoin-family spend is built
   * from, on chains where no node will list them.
   *
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * **`listunspent` IS A WALLET RPC AND THIS ESTATE'S NODES HAVE NO WALLET.** bitcoind and
   * litecoind both run `disablewallet=1` — correct for a node that is not a custodian, since a
   * wallet it does not need is a key it might lose — and the method answers `-32601 Method not
   * found`. Every bitcoin-family withdrawal this service could otherwise build dies there
   * (micro-org#382).
   *
   * The indexer walked every block, so it can answer from its own record. **But this is a list of
   * CANDIDATES, not authority to spend**, and the difference is load-bearing: `bitcoin.ts`
   * re-reads each one with `gettxout`, which a wallet-less node does answer, and takes the node's
   * word for whether the coin still exists and what it is worth. A candidate the node no longer
   * serves is dropped in silence, because that is the ordinary case — our own in-flight spend.
   *
   * So the failure this call can cause is a list that is too LONG, which the verification pass
   * corrects. A list that is too SHORT would be uncorrectable, and the indexer's route refuses
   * with a fault rather than serving one; every one of those refusals arrives here as an
   * `IndexerUnavailableError`, and a build that cannot enumerate its coins must not proceed to
   * select from a subset of them.
   *
   * **Throws rather than returning null, and an empty list is a real answer.** An address the
   * indexer answers for with `[]` has been swept — nothing to spend, and the caller refuses the
   * withdrawal for insufficient funds, which is true. That is why the difference between "empty"
   * and "could not say" may never be flattened here.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   */
  outpoints(chain: ChainId, network: Network, address: string): Promise<ObservedOutpoints>
}

/**
 * The candidate set, and the anchor it was read at.
 *
 * The rows are `OutpointCandidate` from `chains.ts` — the SAME type the `UtxoCandidateSource` port
 * hands the bitcoin adapter, not a copy of it. A copy would be two places to state that `amount`
 * is informational and never signed against, and the day they disagreed the disagreement would be
 * invisible: both shapes are `{txid, vout, amount, blockHeight}` and TypeScript would accept
 * either for the other.
 */
export interface ObservedOutpoints {
  readonly outpoints: readonly OutpointCandidate[]
  readonly observedAtBlock: number
  readonly observedAtBlockHash: string
  readonly requiredConfirmations: number
}

/** One address as the indexer's custody arithmetic sees it. */
export interface ObservedBalance {
  /** Smallest units. Parsed from the decimal string the indexer sends, never from a JSON number. */
  readonly balance: bigint
  /** The height it was read at. Recorded beside the booking so the two can be compared later. */
  readonly observedAtBlock: number
  readonly observedAtBlockHash: string
  readonly requiredConfirmations: number
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

    async watch(chain, network, address, label, freshlyDerived = false) {
      try {
        await client.request(`/v1/watch/${chain}/${network}/${encodeURIComponent(address)}`, {
          method: 'POST',
          // The key is OMITTED rather than sent as `false`. The indexer reads
          // `body['freshlyDerived'] === true`, so the two spellings behave identically today — but
          // the field is a claim, and a request that carries `freshlyDerived: false` reads in a
          // capture as this service having considered the question and answered no about an
          // address it simply knows nothing about. Absent is the accurate spelling of "no claim".
          body: freshlyDerived ? { label, freshlyDerived: true } : { label },
          // An upsert on the far side, so a retry is a no-op rather than a second row. Supplied
          // because `HttpClient` will not retry a POST without one, and this POST is idempotent by
          // construction — the whole request is derived from the pin.
          //
          // The claim is deliberately NOT in the key. A retry of a claimed registration must reach
          // the same stored row as the original, and the far side keeps the LOWEST claim either
          // call made (`watchAddress`, `least`), so a repeat can only ever leave it where it was.
          idempotencyKey: `settlement:watch:${chain}:${network}:${address.toLowerCase()}`,
        })
      } catch (err) {
        // No 404 case and no swallowing. Every failure here — a missing `indexer:write` grant, an
        // indexer that is down, a 400 on an address the indexer will not accept — means the
        // treasury is still invisible to the custody aggregate, and the caller must not record it
        // as registered. It retries on the next pass of a leased job.
        throw new IndexerUnavailableError(err instanceof Error ? err.message : String(err))
      }
    },

    async custodyBalance(chain, network, address) {
      let answer: {
        balance?: unknown
        observedAtBlock?: unknown
        observedAtBlockHash?: unknown
        requiredConfirmations?: unknown
      }
      try {
        answer = await client.get(
          `/v1/custody/${chain}/${network}/addresses/${encodeURIComponent(address)}`,
        )
      } catch (err) {
        // No 404 case, deliberately, and it is the same argument the indexer's own route makes: a
        // 404 read as "this address holds nothing" is a zero wearing a status code, and a zero
        // booked here is a permanent understatement. Every failure is an unavailability, the
        // caller does not book, does not mark the registration complete, and the leased job
        // retries.
        throw new IndexerUnavailableError(err instanceof Error ? err.message : String(err))
      }

      // Parsed, not trusted. `balance` is a decimal STRING because an 18-decimal amount does not
      // survive a JSON number — and the digits a float drops are precisely the digits a drift is
      // made of. `BigInt('')` is `0n`, which is why the shape is checked before it is converted:
      // an empty string arriving here would otherwise become a zero opening balance.
      const raw = answer.balance
      if (typeof raw !== 'string' || !/^\d+$/.test(raw)) {
        throw new IndexerUnavailableError(
          `the indexer answered a balance for ${address} that is not a decimal string: ${JSON.stringify(raw)}`,
        )
      }
      const height = answer.observedAtBlock
      const hash = answer.observedAtBlockHash
      if (typeof height !== 'number' || typeof hash !== 'string') {
        throw new IndexerUnavailableError(
          `the indexer answered a balance for ${address} with no height it was read at`,
        )
      }
      return {
        balance: BigInt(raw),
        observedAtBlock: height,
        observedAtBlockHash: hash,
        requiredConfirmations:
          typeof answer.requiredConfirmations === 'number' ? answer.requiredConfirmations : 0,
      }
    },

    async outpoints(chain, network, address) {
      let answer: {
        outpoints?: unknown
        observedAtBlock?: unknown
        observedAtBlockHash?: unknown
        requiredConfirmations?: unknown
      }
      try {
        answer = await client.get(
          `/v1/custody/${chain}/${network}/addresses/${encodeURIComponent(address)}/outpoints`,
        )
      } catch (err) {
        // No 404 case, for a sharper reason than `custodyBalance` has. There a 404 read as zero
        // understates a book; here a 404 read as `[]` states that an address has been SWEPT, and
        // the caller would refuse a fully funded withdrawal — or, if some coins were listed and
        // others were not, build a transaction spending part of the address and send the rest to
        // change. Every failure is an unavailability and no transaction is built.
        throw new IndexerUnavailableError(err instanceof Error ? err.message : String(err))
      }

      const rows = answer.outpoints
      if (!Array.isArray(rows)) {
        // An absent key is NOT an empty list. A response shaped differently from the contract —
        // an older indexer, a proxy serving an error page with a 200 — must not be read as "this
        // address holds nothing", which is the one wrong answer that looks like a right one.
        throw new IndexerUnavailableError(
          `the indexer answered no outpoint list for ${address} on ${chain}:${network}`,
        )
      }
      const height = answer.observedAtBlock
      const hash = answer.observedAtBlockHash
      if (typeof height !== 'number' || typeof hash !== 'string') {
        throw new IndexerUnavailableError(
          `the indexer answered outpoints for ${address} with no height they were read at`,
        )
      }

      const outpoints: OutpointCandidate[] = []
      for (const entry of rows) {
        // Every row is validated and NONE is skipped. `listunspent`'s parser skips a malformed
        // entry because the node is the authority there and a row it will not describe is a row
        // it will not let us spend; here the authority is `gettxout`, so a row dropped at this
        // layer is a coin that never reaches the only check that could have vouched for it — a
        // short list, built quietly, which is the exact outcome this whole path is arranged to
        // prevent.
        const row = (typeof entry === 'object' && entry !== null ? entry : {}) as Record<
          string,
          unknown
        >
        const amount = row['amount']
        if (
          typeof row['txid'] !== 'string' ||
          typeof row['vout'] !== 'number' ||
          !Number.isInteger(row['vout']) ||
          typeof amount !== 'string' ||
          !/^\d+$/.test(amount)
        ) {
          throw new IndexerUnavailableError(
            `the indexer answered an outpoint for ${address} this service cannot read: ` +
              JSON.stringify(entry),
          )
        }
        outpoints.push({
          txid: row['txid'],
          vout: row['vout'],
          // A decimal string, never a JSON number. `BigInt('')` is `0n`, which is why the shape is
          // proved above rather than after the conversion.
          amount: BigInt(amount),
          blockHeight: typeof row['blockHeight'] === 'number' ? row['blockHeight'] : 0,
        })
      }

      return {
        outpoints,
        observedAtBlock: height,
        observedAtBlockHash: hash,
        requiredConfirmations:
          typeof answer.requiredConfirmations === 'number' ? answer.requiredConfirmations : 0,
      }
    },
  }
}
