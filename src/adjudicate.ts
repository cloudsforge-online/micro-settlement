/**
 * Adjudicating a stuck transaction: the one operator action that can credit a user's balance back
 * while a valid signature for the same money is sitting in `raw_tx`.
 *
 * **It is the mistake this service cannot undo.** Refunding a payment that then lands pays the user
 * twice, and there is no compensating action — the coins are on somebody else's chain, in somebody
 * else's wallet. Every rule below exists because of that one sentence.
 *
 * ## Absence never refunds
 *
 * Until the frozen CF-06 the whole safety of the equivalent route was a single question — "does a
 * node have a receipt for the txid on the row?" — and that question has two holes, both of which
 * pay the user twice:
 *
 *   * **NO RECEIPT IS NOT NO TRANSACTION.** On an EVM chain `unknown` means exactly "this node has
 *     no receipt for that hash". The signed bytes are untouched by it: the nonce is unconsumed, a
 *     legacy transaction has no expiry, and any node still holding them can mine them months after
 *     the refund. The only proof they can never be mined is that the sending account's nonce has
 *     moved past the one inside them.
 *   * **A NULL TXID WAS READ AS THE SAFE CASE AND IS THE DANGEROUS ONE.** Bytes with no known id
 *     are bytes nothing has ever settled, which is the opposite of safe. Here the id is DERIVED
 *     from the bytes, so a null column costs nothing.
 *
 * So `OutboundChain.proveDead` must return a POSITIVE proof, and this file will not refund without
 * one. An unreachable node is a refusal too, and for the same reason: it is the state in which the
 * least is known about where the payment got to.
 *
 * ## Why it has a route at all
 *
 * Because in the estate this replaces it is curl-only with no UI, which means the one action that
 * has to be taken carefully, under time pressure, by somebody who has just been paged, is taken by
 * hand-editing a shell command. `server.ts` gives it `POST /v1/outbound/:id/adjudicate`, admin-only,
 * and every attempt — including every refusal — is written to `outbound_adjudications` with the
 * evidence it rested on.
 */

import type { Logger, Metrics } from '@cloudsforge/telemetry'
import { chainFor } from './registry.ts'
import {
  callFor,
  chainStatusOf,
  findOutbound,
  markBroadcast,
  recordRefusal,
  resolveWithProof,
  type OutboundDeps,
  type OutboundTransaction,
} from './outbound.ts'
import { confirmedEvents, failedEvents } from './withdrawals.ts'
import { sweepCompletedEvents, matureSweepFor } from './sweeps.ts'

export interface AdjudicateDeps extends OutboundDeps {
  readonly metrics: Metrics
  readonly logger: Logger
}

export type AdjudicateAction = 'refund' | 'confirm'

export interface AdjudicateInput {
  readonly id: string
  readonly action: AdjudicateAction
  readonly actor: string
  readonly correlationId: string | null
}

export type AdjudicateOutcome =
  | { readonly kind: 'not_found' }
  /** The row is not `stuck`. Adjudication is only ever for a transaction that has stopped moving. */
  | { readonly kind: 'not_stuck'; readonly state: string }
  | { readonly kind: 'refused'; readonly code: string; readonly reason: string }
  | { readonly kind: 'resolved'; readonly action: AdjudicateAction; readonly proof: string; readonly row: OutboundTransaction }

/**
 * Judge one stuck transaction and, if the chain allows it, resolve it.
 *
 * Note what an operator is NOT given: a way to say "refund it anyway". There is no force flag and
 * there should not be one. The genuine break-glass case — bytes this service cannot read, a chain
 * behaving in a way no rule here anticipated — is not a flag, it is an engineer looking at the row,
 * and giving it a button would make it the path of least resistance at exactly the moment somebody
 * is under pressure to clear an alert.
 */
export async function adjudicate(
  deps: AdjudicateDeps,
  input: AdjudicateInput,
): Promise<AdjudicateOutcome> {
  const row = await findOutbound(deps.sql, input.id)
  if (!row) return { kind: 'not_found' }
  if (row.state !== 'stuck') return { kind: 'not_stuck', state: row.state }

  const refuse = async (code: string, reason: string): Promise<AdjudicateOutcome> => {
    await recordRefusal(deps.sql, {
      id: row.id,
      code,
      reason,
      actor: input.actor,
      correlationId: input.correlationId,
    })
    deps.metrics.increment('settlement_adjudications_total', { action: input.action, outcome: `refused:${code}` })
    deps.logger.warn('adjudication refused', {
      outboundId: row.id,
      action: input.action,
      code,
      actor: input.actor,
    })
    return { kind: 'refused', code, reason }
  }

  if (input.action === 'confirm') return confirmIt(deps, row, input, refuse)

  // ── refund ────────────────────────────────────────────────────────────────
  if (!row.rawTx) {
    // No bytes were ever committed, so nothing can be on chain. That is not a hole, it is the one
    // case that needs no chain evidence — but it should be impossible to reach, because `markStuck`
    // only ever moves a row that has been signed. Reaching it means the row was hand-edited, and
    // that is worth refusing over rather than treating as a shortcut.
    return refuse(
      'unprovable',
      'this transaction is stuck with no committed bytes, which the state machine cannot produce. ' +
        'Nothing is refunded on a row whose history does not make sense; an engineer has to look at it.',
    )
  }

  const adapter = chainFor(row.chain)
  if (adapter.unimplementedPhase) {
    return refuse(
      'unprovable',
      `this service cannot ask the ${row.chain} chain anything (${adapter.unimplementedPhase}), so ` +
        'it cannot show that these signed bytes have become unapplicable and will not refund them.',
    )
  }

  let verdict
  try {
    verdict = await adapter.proveDead(callFor(deps, row.chain), {
      from: row.fromAddress,
      rawTx: row.rawTx,
      txHash: row.txHash,
      signedNonce: row.signedNonce,
      signedExpiry: row.signedExpiry,
    })
  } catch (err) {
    // An unreachable node is a REFUSAL, never a refund. It is the state in which the least is known
    // about where the payment got to, and "we could not ask" is the weakest possible basis for
    // giving a user money that may also be leaving on chain.
    return refuse(
      'unprovable',
      `the ${row.chain} chain could not be asked whether these bytes are dead ` +
        `(${err instanceof Error ? err.message : String(err)}), so nothing is refunded. Try again ` +
        'when the node is reachable.',
    )
  }

  if (!verdict.ok) return refuse(verdict.code, verdict.error)

  const resolved = await resolveWithProof(deps.sql, deps.producer, {
    id: row.id,
    action: 'refund',
    proof: verdict.proof,
    actor: input.actor,
    correlationId: input.correlationId,
    // Only from `stuck`. A live `signed` row is deliberately out of reach here: it has not yet had
    // its full deadline to land, and the automatic path in `worker.ts` is the only thing allowed to
    // refund one of those, and only on a chain-reported rejection.
    fromStates: ['stuck'],
    events: (r) =>
      failedEvents(
        r,
        'this payment did not reach the network and has been returned to your balance',
        true,
      ),
  })
  if (!resolved) return { kind: 'not_stuck', state: 'moved' }

  deps.metrics.increment('settlement_adjudications_total', { action: 'refund', outcome: 'resolved' })
  deps.logger.warn('a stuck outbound transaction was refunded on positive proof', {
    outboundId: row.id,
    chain: row.chain,
    actor: input.actor,
    proof: verdict.proof,
  })
  return { kind: 'resolved', action: 'refund', proof: verdict.proof, row: resolved }
}

/**
 * The other half, and the half that is easy to forget: a stuck transaction that actually LANDED.
 *
 * It is not symmetrical with the refund. A refund needs proof of absence and this needs proof of
 * presence, which is the cheaper of the two — the chain either has the transaction at depth or it
 * does not. The operator still does not get to assert it: the chain is asked, and an operator who
 * believes a payment landed and finds it refused is an operator looking at the right hash.
 */
async function confirmIt(
  deps: AdjudicateDeps,
  row: OutboundTransaction,
  input: AdjudicateInput,
  refuse: (code: string, reason: string) => Promise<AdjudicateOutcome>,
): Promise<AdjudicateOutcome> {
  let status
  try {
    status = await chainStatusOf(deps, row)
  } catch (err) {
    return refuse(
      'unprovable',
      `the ${row.chain} chain could not be asked about this transaction ` +
        `(${err instanceof Error ? err.message : String(err)}).`,
    )
  }
  if (status.kind !== 'confirmed') {
    return refuse(
      'unprovable',
      status.kind === 'rejected'
        ? `the chain says this transaction failed: ${status.reason}. It cannot be confirmed; refund it instead.`
        : `the chain reports this transaction as '${status.kind}', not confirmed. It cannot be marked settled on that.`,
    )
  }

  const proof = `the chain has ${row.txHash ?? 'these bytes'} confirmed at ${status.confirmations} confirmations`
  if (row.txHash) await markBroadcast(deps.sql, row.id, row.txHash)
  const resolved = await resolveWithProof(deps.sql, deps.producer, {
    id: row.id,
    action: 'confirm',
    proof,
    actor: input.actor,
    correlationId: input.correlationId,
    fromStates: ['stuck'],
    events: (r) => (r.purpose === 'sweep' ? sweepCompletedEvents(r) : confirmedEvents(r)),
  })
  if (!resolved) return { kind: 'not_stuck', state: 'moved' }
  if (resolved.purpose === 'sweep') await matureSweepFor(deps, resolved)

  deps.metrics.increment('settlement_adjudications_total', { action: 'confirm', outcome: 'resolved' })
  deps.logger.warn('a stuck outbound transaction was confirmed from the chain', {
    outboundId: row.id,
    chain: row.chain,
    actor: input.actor,
    proof,
  })
  return { kind: 'resolved', action: 'confirm', proof, row: resolved }
}
