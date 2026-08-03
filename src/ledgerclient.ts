/**
 * The ledger, as this service uses it.
 *
 * **This service does not refund anybody through the ledger, and that is the design.** A
 * withdrawal's money is in the user's `reserved` account, put there by wallet before the event that
 * started any of this; wallet holds the `reservationEntryId` and wallet is what releases it. All
 * settlement does is state, in an event, whether the payment is known **not** to have reached the
 * chain — `refundable`, the single most important field in the boundary contract. "We do not know"
 * is not a refund; it is a `stuck` transaction and an operator.
 *
 * Routing the refund through here instead would put the release of a user's reservation in the same
 * process that holds the signing credential, which is precisely the coupling the split exists to
 * remove: forge-pay debits the balance outright and repairs failures with hand-written compensating
 * credits.
 *
 * ## What it IS for: the network fee
 *
 * Every confirmed outbound transaction burns a fee the platform absorbed, out of an address the
 * platform controls. 04-domain-model §11 — "no 'user balance' column anywhere outside the ledger's
 * projection" — applies to the platform's own money as much as to a user's, and forge-pay records
 * this nowhere at all: the treasury's balance simply goes down and no entry anywhere says why. So
 * one entry per confirmed transaction, `treasury_spend`, debiting the platform's fee expense and
 * crediting the custody treasury asset it left. It balances by construction because it is the same
 * number on both sides.
 *
 * Its failure is **never fatal to the transaction**. The payment is on chain whatever the ledger
 * says, and a service that could not mark a confirmed payment confirmed because a bookkeeping entry
 * failed would re-broadcast it and eventually call it stuck. The entry is retried by its own leased
 * job, and it carries an idempotency key derived from the transaction id, so a retry that lands
 * twice posts once.
 */

import { HttpClient, HttpError } from '@cloudsforge/http'
import type { Actor, EntryKind, LedgerAssetCode } from '@cloudsforge/contracts-money'
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
export const LEDGER_SCOPES: readonly LiveScope[] = Object.freeze(['ledger:post'])

/** The ledger refused on the state of the world. Never retried with the same request. */
export class LedgerRefusedError extends Error {
  readonly code: string
  readonly status: number
  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'LedgerRefusedError'
    this.code = code
    this.status = status
  }
}

/** The ledger could not be reached, or answered 5xx. Retry with the same idempotency key. */
export class LedgerUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'LedgerUnavailableError'
  }
}

export interface AccountRef {
  readonly subject: string
  readonly assetCode: LedgerAssetCode
  readonly purpose: 'available' | 'reserved' | 'escrow' | 'treasury' | 'fees' | 'payout_due' | 'suspense'
  readonly type: 'liability' | 'asset' | 'revenue' | 'expense' | 'equity' | 'clearing'
}

export interface PostingRequest {
  readonly direction: 'debit' | 'credit'
  readonly amount: bigint
  readonly assetCode: LedgerAssetCode
  readonly sequence: number
  readonly account: AccountRef
}

export interface PostEntryRequest {
  readonly kind: EntryKind
  readonly actor: Actor
  readonly correlationId: string
  readonly idempotencyKey: string
  readonly description?: string
  readonly postings: readonly PostingRequest[]
}

export interface PostedEntry {
  readonly id: string
  readonly kind: string
  readonly recordedAt: string
  /** True when the ledger answered from a stored response rather than by posting. */
  readonly replayed: boolean
}

export interface LedgerClient {
  postEntry(request: PostEntryRequest): Promise<PostedEntry>
}

export interface LedgerClientOptions {
  readonly baseUrl: string
  readonly token: () => Promise<string | undefined> | string | undefined
  readonly deadlineMs: number
  readonly originatingService: string
  readonly fetch?: typeof globalThis.fetch
}

export function httpLedgerClient(options: LedgerClientOptions): LedgerClient {
  const client = new HttpClient({
    baseUrl: options.baseUrl,
    name: 'ledger',
    defaultDeadlineMs: options.deadlineMs,
    token: options.token,
    ...(options.fetch ? { fetch: options.fetch } : {}),
  })

  return {
    async postEntry(request) {
      try {
        // The key is in the body AND on the request, and both matter. In the body it is what the
        // ledger stores and dedupes on; on the request it is what makes the POST retriable at all,
        // because `HttpClient` attempts a non-idempotent method exactly once without one.
        const body = await client.request<{ entry: RawEntry; replayed: boolean }>('/entries', {
          method: 'POST',
          body: {
            kind: request.kind,
            originatingService: options.originatingService,
            actor: request.actor,
            correlationId: request.correlationId,
            idempotencyKey: request.idempotencyKey,
            ...(request.description !== undefined ? { description: request.description } : {}),
            postings: request.postings.map((posting) => ({
              direction: posting.direction,
              // Smallest units as a decimal STRING, in both directions. A JSON number is an IEEE
              // 754 double, and an 18-decimal amount does not survive one — it does not fail
              // either, it comes back subtly wrong.
              amount: posting.amount.toString(),
              assetCode: posting.assetCode,
              sequence: posting.sequence,
              account: posting.account,
            })),
          },
          idempotencyKey: request.idempotencyKey,
        })
        return {
          id: body.entry.id,
          kind: body.entry.kind,
          recordedAt: body.entry.recordedAt,
          replayed: body.replayed,
        }
      } catch (err) {
        throw translate(err)
      }
    },
  }
}

interface RawEntry {
  readonly id: string
  readonly kind: string
  readonly recordedAt: string
}

function translate(err: unknown): Error {
  if (err instanceof HttpError && err.peerDecided) {
    const parsed = parseError(err.body)
    return new LedgerRefusedError(err.status, parsed.code, parsed.message)
  }
  return new LedgerUnavailableError(err instanceof Error ? err.message : String(err))
}

function parseError(body: string): { code: string; message: string } {
  try {
    const parsed: unknown = JSON.parse(body)
    const error = (parsed as { error?: { code?: unknown; message?: unknown } }).error
    return {
      code: typeof error?.code === 'string' ? error.code : 'ledger_error',
      message: typeof error?.message === 'string' ? error.message : body.slice(0, 500),
    }
  } catch {
    return { code: 'ledger_error', message: body.slice(0, 500) }
  }
}
