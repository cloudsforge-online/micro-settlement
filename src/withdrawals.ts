/**
 * Withdrawals: the event in, the events out, and what a build failure means.
 *
 * Everything between those is `worker.ts`, because a withdrawal and a sweep are the same state
 * machine over the same table and giving them two would give this chain two independent notions of
 * "is anything in flight".
 *
 * ## What arrives, and what it is safe to assume about it
 *
 * `wallet.withdrawal.requested` arrives with the user's money already in their `reserved` ledger
 * account. That is the safety property of the whole handover: between the request and whatever this
 * service concludes, the money is not spendable, not lost, and visible in a trial balance. A
 * settlement that never happens leaves a reservation an operator can release. forge-pay debits the
 * balance outright at request time, so a withdrawal that fails has to be repaired by writing a
 * compensating credit by hand.
 *
 * It follows that **this service never moves money in the ledger to refund anybody.** It states, in
 * an event, whether the payment is known not to have reached the chain, and wallet releases the
 * reservation. `refundable` is the single most important field in the contract and its default —
 * everywhere, including on a parse failure — is false.
 *
 * ## The one event per withdrawal rule
 *
 * A withdrawal produces exactly one terminal event to wallet: `settlement.outbound.confirmed` or
 * `settlement.outbound.failed`. `stuck` produces neither. That is deliberate: `stuck` is not a
 * terminal state, it is a state waiting on a human, and a `.failed` emitted there would either have
 * to lie about `refundable` or be followed by a second terminal event for the same withdrawal when
 * the operator adjudicates it. `settlement.withdrawal.stuck` exists for the operator surfaces and
 * for notify, and nothing that settles money subscribes to it.
 */

import type { AssetCode, Network } from '@cloudsforge/contracts-chain'
import {
  AddressError,
  FeeOutOfBandError,
  InsufficientTreasuryError,
  NotImplementedError,
  UnsupportedDestinationError,
  chainForAsset,
  isChainId,
  isNetwork,
  type ChainId,
} from './chains.ts'
import { chainFor, NoEndpointError } from './registry.ts'
import { CustodySignRefusedError, CustodyUnavailableError } from './custodyclient.ts'
import { NoTreasuryPinnedError, TreasuryDisagreementError, requireTreasury, type TreasuryDeps } from './treasury.ts'
import { planOutbound, type OutboundTransaction } from './outbound.ts'
import {
  SETTLEMENT_OUTBOUND_CONFIRMED,
  SETTLEMENT_OUTBOUND_FAILED,
  SETTLEMENT_WITHDRAWAL_COMPLETED,
  SETTLEMENT_WITHDRAWAL_STUCK,
  WALLET_WITHDRAWAL_REQUESTED,
  withInbox,
  type Db,
  type DomainEvent,
  type Tx,
} from './outbox.ts'

/**
 * The payload of `wallet.withdrawal.requested`, as wallet declares it.
 *
 * Copied from `wallet/src/settlement.ts` rather than imported, because it is a WIRE contract and
 * not a shared type: importing it would couple this repository's build to wallet's source tree,
 * which is the thing the polyrepo split exists to stop. Additive-only, versioned per topic — a
 * field may be added, never removed or repurposed.
 */
export interface WithdrawalRequestedPayload {
  readonly withdrawalId: string
  readonly userId: string
  readonly chain: string
  readonly network: string
  readonly assetCode: string
  readonly destination: string
  /** Smallest units, decimal strings. A uint256 does not fit in a JSON number. */
  readonly amount: string
  readonly fee: string
  readonly net: string
  readonly reservationEntryId: string
  readonly idempotencyKey: string
  readonly requestedAt: string
}

export class MalformedEventError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'MalformedEventError'
  }
}

/**
 * Read the payload into the values this service acts on, refusing anything it cannot account for.
 *
 * Pure, and separate from the effects, so every refusal is assertable without a database. The
 * refusals are strict on purpose: a malformed event is a permanent fault, and a service that
 * coerced its way past one would build a payment out of a number it guessed at.
 */
export function parseWithdrawalRequested(payload: Record<string, unknown>): {
  readonly withdrawalId: string
  readonly userId: string
  readonly chain: ChainId
  readonly network: Network
  readonly assetCode: AssetCode
  readonly destination: string
  readonly amount: bigint
  readonly fee: bigint
  readonly net: bigint
  readonly reservationEntryId: string
  readonly idempotencyKey: string
} {
  const text = (field: string): string => {
    const value = payload[field]
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new MalformedEventError(`${field} must be a non-empty string`)
    }
    return value.trim()
  }
  const units = (field: string): bigint => {
    const value = payload[field]
    // A decimal STRING and never a number. Accepting a number here would silently accept an
    // 18-decimal amount that a JSON round trip had already rounded, and the rounding is invisible.
    if (typeof value !== 'string' || !/^\d+$/.test(value)) {
      throw new MalformedEventError(`${field} must be a decimal string of smallest units`)
    }
    return BigInt(value)
  }

  const chain = text('chain')
  if (!isChainId(chain)) throw new MalformedEventError(`chain '${chain}' is not one this service settles`)
  const network = text('network')
  if (!isNetwork(network)) throw new MalformedEventError(`network must be mainnet or testnet`)
  const assetCode = text('assetCode')
  if (chainForAsset(assetCode) !== chain) {
    throw new MalformedEventError(`assetCode ${assetCode} does not settle on ${chain}`)
  }

  const amount = units('amount')
  const fee = units('fee')
  const net = units('net')
  // The arithmetic is wallet's and it is restated here rather than trusted, because these three
  // numbers are what leaves an address and a disagreement between them is either a bug upstream or
  // a forged event. `net` is what the destination receives; `amount` is what left the user.
  if (net + fee !== amount) {
    throw new MalformedEventError(`net (${net}) plus fee (${fee}) is not amount (${amount})`)
  }
  if (net <= 0n) throw new MalformedEventError('net must be positive — there is nothing to send')

  return {
    withdrawalId: text('withdrawalId'),
    userId: text('userId'),
    chain,
    network,
    assetCode: assetCode as AssetCode,
    destination: text('destination'),
    amount,
    fee,
    net,
    reservationEntryId: text('reservationEntryId'),
    idempotencyKey: text('idempotencyKey'),
  }
}

export type WithdrawalDecision =
  | { readonly kind: 'planned'; readonly outboundId: string }
  | { readonly kind: 'duplicate'; readonly outboundId: string | null }
  | { readonly kind: 'ignored'; readonly reason: string }

export interface WithdrawalDeps extends TreasuryDeps {
  readonly producer: string
}

/**
 * Take one `wallet.withdrawal.requested` and turn it into a `planned` outbound transaction.
 *
 * **Two independent dedupes, and they catch different things.** `withInbox` on `(topic, eventId)`
 * stops a REDELIVERY of the same event: the relay is at-least-once and will resend anything it
 * could not confirm. The unique constraint on `idempotency_key` stops two DIFFERENT events that
 * name the same withdrawal, which is what a wallet retry after a lost response produces. Either one
 * alone leaves a hole; the headline requirement — "the same withdrawal request delivered twice
 * produces one outbound transaction" — needs both.
 *
 * It plans and does not build. Building holds the chain's nonce, and the nonce is claimed under a
 * lease by a worker, never on the HTTP thread of an event delivery: a build here would mean the
 * relay's retry policy decided how many transactions got signed.
 */
export async function handleWithdrawalRequested(
  deps: WithdrawalDeps,
  input: {
    readonly eventId: string
    readonly payload: Record<string, unknown>
    readonly correlationId: string
  },
): Promise<WithdrawalDecision> {
  const request = parseWithdrawalRequested(input.payload)

  if (request.network !== deps.network) {
    // A different network from the one this deployment settles. Ignored rather than failed: a
    // testnet withdrawal reaching a mainnet settlement is a routing mistake, and failing it would
    // release a reservation in a wallet that is not this deployment's either.
    return { kind: 'ignored', reason: 'other_network' }
  }

  const outcome = await withInbox(deps.sql, WALLET_WITHDRAWAL_REQUESTED, input.eventId, async (tx: Tx) => {
    const treasury = await resolveSource(deps, request.chain, request.network, tx)
    const { outbound, created } = await planOutbound(tx, {
      purpose: 'withdrawal',
      chain: request.chain,
      network: request.network,
      from: treasury,
      to: request.destination,
      assetCode: request.assetCode,
      // `amount` on the row is what the DESTINATION receives, which is wallet's `net`. The user's
      // `amount` is wallet's number and stays wallet's; storing it here as well would be a second
      // copy of a total that this service does not own.
      amount: request.net,
      fee: request.fee,
      idempotencyKey: request.idempotencyKey,
      sourceRef: request.withdrawalId,
      userId: request.userId,
      reservationEntryId: request.reservationEntryId,
      correlationId: input.correlationId,
    })
    return { outbound, created }
  })

  if (outcome.status === 'duplicate') return { kind: 'duplicate', outboundId: null }
  return outcome.value.created
    ? { kind: 'planned', outboundId: outcome.value.outbound.id }
    : { kind: 'duplicate', outboundId: outcome.value.outbound.id }
}

/**
 * The address this withdrawal will be paid out of.
 *
 * Resolved at PLANNING time and written onto the row, not looked up at build time. A treasury that
 * rotates between the plan and the build would otherwise silently move a payment onto an address
 * the user's fee was never quoted against — and, worse, the binding restated at signing time is
 * derived from the chain and network alone, so a rotation would produce a 403 whose message says
 * nothing about which address it was for.
 *
 * A chain with no pinned treasury throws here, inside the inbox transaction, so the event is NOT
 * marked received and the relay redelivers it once an operator has provisioned one. That is the
 * right failure: the alternative is a `planned` row on a chain that cannot pay it, which is a
 * withdrawal that quietly refunds itself at the stuck deadline.
 */
async function resolveSource(
  deps: WithdrawalDeps,
  chain: ChainId,
  network: Network,
  tx: Tx,
): Promise<string> {
  const treasury = await requireTreasury({ ...deps, sql: tx as unknown as Db }, chain, network)
  return treasury.address
}

/* ------------------------------------------------------------------ classifying a failure */

/**
 * What to do with a transaction whose build threw, before anything was signed.
 *
 * **EVERY BUILD FAILURE HAS AN EXIT**, and the only question this answers is whether it is
 * immediate or bounded. That is the whole of the frozen CF-24: the classified refusals each ended
 * the withdrawal and everything else — a treasury custody could not be reached for, a node that
 * answers nothing — fell through to a bare "will retry" with no deadline on the retrying. A
 * withdrawal that could never be built then sat queued for ever with the user's money reserved, and
 * because a chain starts only its oldest queued row, it took every other withdrawal on that chain
 * down with it.
 *
 * **THE EXIT IS A REFUND AND NEVER `stuck`.** `stuck` means "a signed payment needs a human" and
 * `markStuck` is gated on `signed`/`broadcast` precisely so that meaning cannot drift. Nothing on
 * this path has been signed — the signature is made and committed after the build, and one made and
 * not committed is discarded unbroadcast — so giving the money back is safe.
 *
 * Pure, and separate from the effects, so the policy can be asserted per error shape without a
 * database or a chain.
 */
export interface BuildFailurePlan {
  /** Which shape this is. On the log line, on the metric label, and load-bearing in a test. */
  readonly classification:
    | 'chain_unsupported'
    | 'destination'
    | 'fee'
    | 'refused'
    | 'treasury'
    | 'endpoint'
    | 'malformed'
    | 'unclassified'
  /** The log line. Kept distinct per shape so a log search can still tell them apart. */
  readonly message: string
  /**
   * `now` for a refusal that cannot change — a destination with code at it, a signer that says no,
   * a chain this service does not speak. `at-deadline` for one that plausibly clears on its own,
   * which is retried until the stuck deadline passes and then given up on.
   */
  readonly refund: 'now' | 'at-deadline'
  /** What the user is told when the money goes back. */
  readonly reason: string
}

export function planBuildFailure(err: unknown): BuildFailurePlan {
  if (err instanceof NotImplementedError) {
    // Permanent by construction: the phase that brings this chain has not shipped, and no number of
    // retries changes that. Refunding immediately is what stops a BTC or SOL withdrawal sitting
    // queued for a quarter with a user's balance reserved against it.
    return {
      classification: 'chain_unsupported',
      message: 'withdrawal refused: this service cannot send on this chain yet',
      refund: 'now',
      reason: `${err.chain.toUpperCase()} withdrawals are not available yet, so this has been returned to your balance`,
    }
  }
  if (err instanceof UnsupportedDestinationError || err instanceof AddressError) {
    // The only refusal here whose cause is something the USER can act on, so the message is theirs
    // rather than the generic one. Code at an address does not go away.
    return {
      classification: 'destination',
      message: 'withdrawal destination refused',
      refund: 'now',
      reason: err.message,
    }
  }
  if (err instanceof FeeOutOfBandError) {
    // The fee was locked when the user agreed to it and re-quoting would sign a transaction that
    // does not match the row. So the row is the thing that is wrong, permanently, and the user
    // resubmits at today's price rather than waiting for a price that will never be asked again.
    return {
      classification: 'fee',
      message: 'withdrawal refused: the locked fee is outside the bounds this service will build for',
      refund: 'now',
      reason:
        'the network fee quoted for this withdrawal is no longer one we will send at, so it has ' +
        'been returned to your balance — please request it again at the current fee',
    }
  }
  if (err instanceof CustodySignRefusedError) {
    // `no_treasury_pinned` is an operator's omission and it clears without a deploy. Every other
    // refusal is custody looking at this exact request and saying no, which is deterministic in the
    // request: nothing about it changes between two ticks, so a retry produces the identical 403.
    if (err.code === 'no_treasury_pinned') {
      return {
        classification: 'treasury',
        message: 'withdrawal waiting: custody has no treasury pinned for this chain',
        refund: 'at-deadline',
        reason: 'this withdrawal could not be funded in time and has been returned to your balance',
      }
    }
    return {
      classification: 'refused',
      message: `withdrawal refused before signing: ${err.code}`,
      refund: 'now',
      reason: 'this withdrawal could not be signed and has been returned to your balance',
    }
  }
  if (
    err instanceof InsufficientTreasuryError ||
    err instanceof NoTreasuryPinnedError ||
    err instanceof TreasuryDisagreementError
  ) {
    // Not the user's fault and not a permanent refusal: the treasury needs funding, sweeping or
    // an operator. The transaction stays queued and is retried, and only gives up — with a refund,
    // since nothing was signed — once the stuck deadline passes.
    return {
      classification: 'treasury',
      message: 'withdrawal waiting: the treasury cannot cover it yet',
      refund: 'at-deadline',
      reason: 'this withdrawal could not be funded in time and has been returned to your balance',
    }
  }
  if (err instanceof NoEndpointError) {
    return {
      classification: 'endpoint',
      message: 'withdrawal waiting: no node is configured for this chain',
      refund: 'at-deadline',
      reason: 'this withdrawal could not be prepared in time and has been returned to your balance',
    }
  }
  if (err instanceof MalformedEventError) {
    return {
      classification: 'malformed',
      message: 'withdrawal refused: the request this was built from does not describe a payment',
      refund: 'now',
      reason: 'this withdrawal could not be prepared and has been returned to your balance',
    }
  }
  if (err instanceof CustodyUnavailableError) {
    // **Explicitly transient, and it is the one that must not be got wrong.** An unavailability is
    // "we do not know whether custody signed". Treating it as a refusal would refund a withdrawal
    // whose signature may exist — but nothing has been COMMITTED, so the bytes (if any) are
    // unbroadcast and unrecoverable by anyone including us, which is why a deadline is still an
    // acceptable exit. It just must not be an immediate one.
    return {
      classification: 'unclassified',
      message: 'withdrawal build failed: custody could not be reached — will retry until the deadline',
      refund: 'at-deadline',
      reason: 'this withdrawal could not be prepared in time and has been returned to your balance',
    }
  }
  // Unclassified: assume transient, because most of them are, and BOUND the assumption.
  return {
    classification: 'unclassified',
    message: 'withdrawal build failed — will retry until the stuck deadline',
    refund: 'at-deadline',
    reason: 'this withdrawal could not be prepared in time and has been returned to your balance',
  }
}

/* ------------------------------------------------------------------ the events */

function base(row: OutboundTransaction): Record<string, unknown> {
  return {
    outboundId: row.id,
    purpose: row.purpose,
    chain: row.chain,
    network: row.network,
    assetCode: row.assetCode,
    from: row.fromAddress,
    to: row.toAddress,
    amount: row.amount.toString(),
    fee: row.fee.toString(),
    txHash: row.txHash,
  }
}

/**
 * The events a confirmed withdrawal produces.
 *
 * Two topics for one fact, and `outbox.ts` says why: `settlement.outbound.confirmed` is wallet's
 * name and is deliberately narrow — everything wallet needs to settle a reservation and nothing
 * else — while `settlement.withdrawal.completed` carries the outbound transaction for notify,
 * activity and the operator surfaces. A subscription is per topic, so no consumer sees both.
 *
 * A `sweep` produces neither: nobody's reservation is waiting on it. It gets
 * `settlement.sweep.completed`, from `sweeps.ts`.
 */
export function confirmedEvents(row: OutboundTransaction): readonly DomainEvent[] {
  if (row.purpose !== 'withdrawal' || !row.sourceRef) return []
  const confirmedAt = (row.confirmedAt ?? new Date()).toISOString()
  return [
    {
      topic: SETTLEMENT_OUTBOUND_CONFIRMED,
      key: row.sourceRef,
      payload: {
        withdrawalId: row.sourceRef,
        txHash: row.txHash ?? '',
        confirmedAt,
      },
      ...(row.correlationId ? { correlationId: row.correlationId } : {}),
    },
    {
      topic: SETTLEMENT_WITHDRAWAL_COMPLETED,
      key: row.sourceRef,
      payload: {
        ...base(row),
        withdrawalId: row.sourceRef,
        userId: row.userId,
        reservationEntryId: row.reservationEntryId,
        confirmations: row.confirmations,
        confirmedAt,
      },
      ...(row.correlationId ? { correlationId: row.correlationId } : {}),
    },
  ]
}

/**
 * The event a failed withdrawal produces, and the one field that matters.
 *
 * `refundable` is stated by the CALLER rather than inferred here, because the two callers know two
 * different things: `markFailed` is only ever reached from `planned` or `building`, where nothing
 * was signed and a refund is unconditionally safe; `resolveStuck` reaches it only with a proof from
 * the chain. There is no third caller, and adding one that could not say which of those it was
 * would be the bug this whole service is arranged around.
 */
export function failedEvents(
  row: OutboundTransaction,
  reason: string,
  refundable: boolean,
): readonly DomainEvent[] {
  if (row.purpose !== 'withdrawal' || !row.sourceRef) return []
  return [
    {
      topic: SETTLEMENT_OUTBOUND_FAILED,
      key: row.sourceRef,
      payload: { withdrawalId: row.sourceRef, reason, refundable },
      ...(row.correlationId ? { correlationId: row.correlationId } : {}),
    },
  ]
}

/**
 * The event a stuck transaction produces. **It settles nothing.**
 *
 * No consumer that moves money subscribes to this topic, and that is the design: a stuck
 * transaction has bytes that may still land, so anything that acted on it financially would be
 * acting without evidence. This pages an operator and tells the user their withdrawal is late.
 *
 * ## The name was wrong, and the fix was NOT to emit both names
 *
 * `settlement.withdrawal.stuck` is the REGISTERED name — `@cloudsforge/contracts-events` owns it,
 * keyed `chain:network` — and **this service was not emitting it.** It emitted
 * `settlement.outbound.stuck`, keyed by the outbound row id, which no registry names and nothing
 * subscribes to. `activity/src/classify.ts:383` and `notify/src/catalogue.ts:433` both classify the
 * registered name, the latter at `priority: 'high'` because "Silence here is a user who believes
 * their money has vanished" — so both were dead code, and a stuck withdrawal notified nobody. The
 * one event in this file whose entire purpose is to reach a person reached none. It is the same
 * defect as `wallet.deposit.credited` against `wallet.deposit.confirmed`.
 *
 * **The first fix emitted both, and it was refused, correctly.** `micro-contracts` was asked to
 * register the second name and declined: the two carried ONE payload and differed only in their
 * partition, no subscriber existed for the narrow one, and the row id it was keyed by is already on
 * the payload as `outboundId`. Registering it would have put two official names on one fact —
 * which is `wallet.deposit.credited` again, deliberately this time. So the second emit is gone
 * rather than quarantined: a quarantine entry for something that has been refused is a lie the
 * self-emptying check can never resolve.
 *
 * The operator surfaces lose nothing. They read `GET /v1/outbound?state=stuck`, not a subscription.
 *
 * The payload carries the fields its two consumers actually read — `notify` looks for
 * `withdrawalId`, `amount`, `assetCode` and `reason`, and `activity`'s `userFromPayload` looks for
 * `userId` — which is why it is `base(row)` plus those rather than something narrower.
 */
export function stuckEvents(row: OutboundTransaction, reason: string): readonly DomainEvent[] {
  return [
    {
      topic: SETTLEMENT_WITHDRAWAL_STUCK,
      // `chain:network`, as the registry declares. NOT the row id: `keyedBy` is the ordering
      // partition, so it is contract, and a producer that picks its own key silently reorders every
      // consumer's view of the topic. Keyed by the row, every event would be a partition of one and
      // the ordering guarantee would say nothing at all.
      key: `${row.chain}:${row.network}`,
      payload: {
        ...base(row),
        withdrawalId: row.purpose === 'withdrawal' ? row.sourceRef : null,
        userId: row.userId,
        reason,
        signedNonce: row.signedNonce,
        broadcastAt: row.broadcastAt?.toISOString() ?? null,
        // Named so the page is actionable rather than a notification. The route is the one thing an
        // operator needs and it was curl-only in the estate this replaces.
        adjudicateWith: `POST /v1/outbound/${row.id}/adjudicate`,
      },
      ...(row.correlationId ? { correlationId: row.correlationId } : {}),
    },
  ]
}

/** Does this chain's adapter exist yet? Read before anything else, so the refusal is classified. */
export function unsupportedReason(chain: ChainId): string | null {
  return chainFor(chain).unimplementedPhase
}
