/**
 * Driving one chain, one step.
 *
 * **This whole file runs under a lease keyed `chain:network`, and that is where the correctness
 * lives.** Not under a lease keyed on the transaction id, and the difference is the defect this
 * service exists to fix.
 *
 * The frozen withdrawal worker guards itself with `hasUnsettledOutbound()`, an UNLOCKED read, so
 * two workers both pass it. `markWithdrawalSigned` protects a single row and does so correctly —
 * but the contended resource is not the row, **it is the chain's nonce**. Two DIFFERENT pending
 * withdrawals, each with its own row, each passing its own conditional update, both read
 * `eth_getTransactionCount` and both get the same answer, so both are signed against one nonce. At
 * most one can ever be mined and the other is a payment that has been debited, signed, broadcast
 * and lost. A per-row lease would not have stopped it; a per-row lease is what it already had.
 *
 * So the lease names the chain. One in-flight outbound transaction per chain per network, and
 * `outbound_in_flight_uniq` in the schema is the same statement made by the database, for the case
 * where the lease has already failed.
 *
 * ## The order of operations, which is the other half
 *
 *     claim the row → read the nonce → ask custody → COMMIT THE BYTES → broadcast
 *
 * A crash before the commit has broadcast nothing: the signature is discarded UNBROADCAST and the
 * next tick starts again from a fresh nonce read. A crash after it leaves a `signed` row with
 * `raw_tx` populated, and `advance` below RESUMES AT BROADCAST — there is no path anywhere in this
 * file from `signed` back to `building`, so the same withdrawal can never be signed twice.
 *
 * ## Serial per chain, and the one thing that may follow a row
 *
 * A tick advances the in-flight transaction and then, only if nothing is in flight, starts the
 * oldest queued one. It may move past a queued row only when that row was RETIRED having signed
 * nothing — a permanent build failure, refunded from `planned`. That is safe for exactly the reason
 * the frozen worker gives: the treasury is untouched, no nonce was read, and the serial rule is not
 * being broken. Anything that signed is this chain's turn used up.
 */

import type { Network } from '@cloudsforge/contracts-chain'
import type { Logger, Metrics } from '@cloudsforge/telemetry'
import { custodyChainOf, custodyFamilyOf, type ChainId, type OutboundShape } from './chains.ts'
import { chainFor } from './registry.ts'
import {
  callFor,
  chainStatusOf,
  claimForBuilding,
  findOutbound,
  inFlightOnChain,
  markBroadcast,
  markConfirmations,
  markConfirmed,
  markFailed,
  markSigned,
  markStuck,
  nextPlanned,
  releaseToPlanned,
  resolveWithProof,
  stuckDeadlinePassed,
  type OutboundDeps,
  type OutboundPurpose,
  type OutboundTransaction,
} from './outbound.ts'
import { treasuryBinding } from './treasury.ts'
import { sweepBindingFor, matureSweepFor, sweepCompletedEvents } from './sweeps.ts'
import { confirmedEvents, failedEvents, planBuildFailure, stuckEvents } from './withdrawals.ts'

export interface WorkerDeps extends OutboundDeps {
  readonly metrics: Metrics
  readonly logger: Logger
}

/** What one tick of one chain did. Returned so the job can log it and a test can assert it. */
export interface DriveResult {
  readonly chain: ChainId
  readonly network: Network
  readonly advanced: string | null
  readonly signed: string | null
  readonly retired: readonly string[]
}

/** How many retired rows one tick will walk past before giving the chain back. */
const MAX_RETIREMENTS_PER_TICK = 25

/**
 * One step for one chain. **Call this only from a handler holding the `chain:network` lease.**
 */
export async function driveChain(
  deps: WorkerDeps,
  chain: ChainId,
  network: Network,
  heartbeat: () => Promise<boolean> = async () => true,
): Promise<DriveResult> {
  const retired: string[] = []
  let advanced: string | null = null

  const inFlight = await inFlightOnChain(deps.sql, chain, network)
  if (inFlight) {
    await advance(deps, inFlight)
    advanced = inFlight.id
    await heartbeat()
    // Whatever `advance` concluded, re-read rather than reasoning about it: it may have confirmed,
    // failed, gone stuck or simply moved a confirmation count, and only the database knows which.
    const still = await inFlightOnChain(deps.sql, chain, network)
    if (still) return { chain, network, advanced, signed: null, retired }
  }

  for (let i = 0; i < MAX_RETIREMENTS_PER_TICK; i += 1) {
    const queued = await nextPlanned(deps.sql, chain, network)
    if (!queued) break
    const outcome = await start(deps, queued)
    await heartbeat()
    if (outcome === 'signed') return { chain, network, advanced, signed: queued.id, retired }
    if (outcome === 'held') return { chain, network, advanced, signed: null, retired }
    // 'retired': the row was refunded from `planned` having signed nothing, so the treasury is
    // exactly as it was found and the next queued row may have this tick. Without this, a chain
    // whose head can never be built clears one row per poll and fifty such rows take an hour.
    retired.push(queued.id)
  }

  return { chain, network, advanced, signed: null, retired }
}

/* ------------------------------------------------------------------ starting */

type StartOutcome = 'signed' | 'held' | 'retired'

/**
 * Build, sign, COMMIT and broadcast one queued transaction.
 *
 * `held` is returned whenever the chain's turn is used up without a retirement — the claim was
 * lost, the build failed transiently, or somebody else committed a signature first.
 */
async function start(deps: WorkerDeps, row: OutboundTransaction): Promise<StartOutcome> {
  // The claim. False means either the state moved under us or the partial unique index refused
  // because something else on this chain is already in flight. Both mean "not my turn".
  if (!(await claimForBuilding(deps.sql, row.id))) return 'held'

  const adapter = chainFor(row.chain)
  const call = callFor(deps, row.chain)

  let signedTx: string
  let auditId: string | null
  let unsigned: Awaited<ReturnType<typeof adapter.build>>
  try {
    if (adapter.unimplementedPhase) {
      // Read before anything is asked of a node, so an unimplemented chain costs one branch rather
      // than a round trip. `NotImplementedError` is what the classifier keys on.
      await adapter.estimateFee(call, deps.bounds)
    }
    const binding = await bindingFor(deps, row)
    unsigned = await adapter.build(call, {
      from: row.fromAddress,
      to: row.toAddress,
      value: row.amount,
      fee: row.fee,
      bounds: deps.bounds,
      // Read off the SAME object that carries the purpose claimed to custody. See `signingPolicy`.
      shape: binding.shape,
    })
    const result = await deps.custody.sign({
      address: row.fromAddress,
      chain: custodyChainOf(row.chain),
      network: row.network,
      family: custodyFamilyOf(row.chain),
      purpose: binding.purpose,
      userId: binding.userId,
      orderId: binding.orderId,
      payload: unsigned.payload,
      correlationId: row.correlationId ?? row.id,
    })
    signedTx = result.signedTx
    auditId = result.auditId ?? null
  } catch (err) {
    return failBuild(deps, row, err)
  }

  // ────────────────────────────────────────────────────────────────────────────────────────────
  // THE COMMIT. Everything after this line is recoverable; everything before it is discardable.
  //
  // If another worker got here first this returns false and the signature just made is discarded
  // UNBROADCAST — which is precisely why it was safe to have made it at all. Nothing was sent, so
  // nothing moved, and the row keeps whatever state the winner put it in.
  // ────────────────────────────────────────────────────────────────────────────────────────────
  const committed = await markSigned(deps.sql, row.id, {
    rawTx: signedTx,
    txHash: adapter.txIdOf(signedTx),
    nonce: unsigned.nonce,
    expiry: unsigned.expiry,
    custodyAuditId: auditId,
  })
  if (!committed) {
    deps.logger.warn('a signature was discarded unbroadcast: the row was already signed elsewhere', {
      outboundId: row.id,
      chain: row.chain,
    })
    return 'held'
  }
  deps.metrics.increment('settlement_signatures_total', { chain: row.chain, purpose: row.purpose })
  deps.logger.info('outbound transaction signed', {
    outboundId: row.id,
    chain: row.chain,
    network: row.network,
    purpose: row.purpose,
    nonce: unsigned.nonce,
    txHash: adapter.txIdOf(signedTx),
  })

  await send(deps, { ...row, state: 'signed', rawTx: signedTx })
  return 'signed'
}

/**
 * **THE PURPOSE CLAIMED TO CUSTODY AND THE SHAPE THE BYTES ARE BUILT FOR ARE ONE DECISION.**
 *
 * They are returned together, from one function, because a disagreement between them is not a bug
 * that shows up as a wrong answer — it is a 403 arriving after the row is committed and this
 * chain's single outbound slot is claimed, with a message that deliberately will not say which
 * field was wrong.
 *
 * custody picks its signing policy from the PURPOSE of the address (`solanaShapeForPurpose`,
 * `bitcoinShapeForPurpose`), so `deposit` gets the pinned-destination shape and nothing else does.
 * On Bitcoin that is a whole output's difference: a `sweep` PSBT may carry no change output at all,
 * and the withdrawal builder's change output back to the deposit address is refused WHOLE.
 *
 * Pure, and separate from the row lookup, so the mapping can be asserted without a database — the
 * same reason custody's own gates live away from its route.
 */
export function signingPolicy(purpose: OutboundPurpose): {
  readonly custodyPurpose: 'treasury' | 'deposit'
  readonly shape: OutboundShape
} {
  return purpose === 'sweep'
    ? { custodyPurpose: 'deposit', shape: 'sweep' }
    : // A withdrawal, a treasury move and a deploy all spend the TREASURY and all name their own
      // destination, which is custody's `payment`/`transfer` shape. There is deliberately no
      // fallback to `sweep` here, unlike custody's own `…ShapeForPurpose`: custody fails toward the
      // shape it cannot resolve a pin for, and therefore signs nothing, whereas this service
      // failing toward `sweep` would build a change-free PSBT for a withdrawal and silently pay the
      // user's whole balance minus a fee to a single output. Failing toward `payment` produces
      // bytes custody REFUSES, which is the direction that costs a retry rather than money.
      { custodyPurpose: 'treasury', shape: 'payment' }
}

/** Which binding custody will demand be restated for the address this row spends from. */
async function bindingFor(
  deps: WorkerDeps,
  row: OutboundTransaction,
): Promise<{
  readonly purpose: 'treasury' | 'deposit'
  readonly shape: OutboundShape
  readonly userId: string
  readonly orderId: string
}> {
  const policy = signingPolicy(row.purpose)
  if (policy.custodyPurpose === 'deposit') {
    const binding = await sweepBindingFor(deps, row)
    return { purpose: policy.custodyPurpose, shape: policy.shape, ...binding }
  }
  // The treasury's binding is DERIVED from the chain and network alone — the same derivation
  // custody used when it minted the address, so the two are byte-identical without either side
  // remembering anything.
  const binding = treasuryBinding(row.chain, row.network)
  return { purpose: policy.custodyPurpose, shape: policy.shape, ...binding }
}

/**
 * A build that threw, classified and acted on.
 *
 * The row is in `building`, which is in the IN-FLIGHT set, so doing nothing here would leave the
 * chain blocked by a transaction that has not even been signed. Every arm therefore ends in one of
 * two places: back on the queue (`releaseToPlanned`) or terminally failed with a refund. There is
 * no third.
 */
async function failBuild(
  deps: WorkerDeps,
  row: OutboundTransaction,
  err: unknown,
): Promise<StartOutcome> {
  const plan = planBuildFailure(err)
  deps.metrics.increment('settlement_build_failures_total', {
    chain: row.chain,
    classification: plan.classification,
  })
  deps.logger.error(plan.message, {
    outboundId: row.id,
    chain: row.chain,
    network: row.network,
    purpose: row.purpose,
    classification: plan.classification,
    err,
  })

  const now = deps.now?.() ?? Date.now()
  if (plan.refund === 'at-deadline' && !stuckDeadlinePassed(row, deps.stuckMinutes, now)) {
    // Still inside the window in which this plausibly clears on its own. Back on the queue, keeping
    // its place — and, critically, out of the in-flight set, so a treasury that cannot cover the
    // head of the queue does not stop every other payment on the chain.
    await releaseToPlanned(deps.sql, row.id)
    return 'held'
  }

  const failed = await markFailed(deps.sql, deps.producer, row.id, plan.reason, (r) =>
    // `refundable: true` unconditionally, and it is safe unconditionally: `markFailed` cannot reach
    // a row past `building`, so by construction nothing on this path has committed a signature.
    failedEvents(r, plan.reason, true),
  )
  if (!failed) {
    // The row moved out from under us between the failed build and the refund. Nothing was signed
    // here; leave it alone and let the next tick read whatever it became.
    deps.logger.warn('an outbound transaction was no longer refundable when its build failed', {
      outboundId: row.id,
    })
    return 'held'
  }
  deps.logger.warn('outbound transaction refunded before signing', {
    outboundId: row.id,
    chain: row.chain,
    classification: plan.classification,
  })
  return 'retired'
}

/* ------------------------------------------------------------------ broadcasting */

/**
 * Put committed bytes on the wire.
 *
 * A failure here is logged and NOT thrown: the row stays `signed`, which is exactly where the next
 * tick picks it up and re-sends the same bytes. A broadcast that failed has moved nothing.
 */
async function send(deps: WorkerDeps, row: OutboundTransaction): Promise<void> {
  if (!row.rawTx) return
  const adapter = chainFor(row.chain)
  try {
    const txHash = await adapter.broadcast(callFor(deps, row.chain), row.rawTx)
    await markBroadcast(deps.sql, row.id, txHash)
    deps.metrics.increment('settlement_broadcasts_total', { chain: row.chain, purpose: row.purpose })
    deps.logger.info('outbound transaction broadcast', {
      outboundId: row.id,
      chain: row.chain,
      network: row.network,
      txHash,
    })
  } catch (err) {
    deps.logger.error('broadcast failed — the committed bytes will be re-sent next tick', {
      outboundId: row.id,
      chain: row.chain,
      err,
    })
  }
}

/* ------------------------------------------------------------------ advancing */

/**
 * Ask the chain where an already-signed transaction has got to, and move it on.
 *
 * **There is no path from here back to `building`.** That is what makes a crash between signing and
 * broadcasting recoverable rather than a second signature: a `signed` row with `raw_tx` on it goes
 * straight to `send`, which re-broadcasts the identical bytes.
 */
export async function advance(deps: WorkerDeps, row: OutboundTransaction): Promise<void> {
  const status = await chainStatusOf(deps, row)
  const now = deps.now?.() ?? Date.now()

  if (status.kind === 'confirmed') {
    const confirmed = await markConfirmed(
      deps.sql,
      deps.producer,
      row.id,
      status.confirmations,
      (r) => (r.purpose === 'sweep' ? sweepCompletedEvents(r) : confirmedEvents(r)),
    )
    if (confirmed) {
      deps.metrics.increment('settlement_confirmed_total', { chain: row.chain, purpose: row.purpose })
      deps.logger.info('outbound transaction confirmed', {
        outboundId: row.id,
        chain: row.chain,
        txHash: row.txHash,
        confirmations: status.confirmations,
      })
      // A sweep's accounting is gated on DEPTH and this is the depth. See `matureSweepFor`.
      if (confirmed.purpose === 'sweep') await matureSweepFor(deps, confirmed)
    }
    return
  }

  if (status.kind === 'rejected') {
    // ────────────────────────────────────────────────────────────────────────────────────────
    // THE ONE MACHINE-READABLE PROOF. The chain applied these bytes and they did not deliver, so
    // they can never apply again and the money is provably still in the treasury. This is the only
    // automatic path by which a SIGNED transaction is refunded, and it still goes through
    // `resolveWithProof` and still writes an adjudication row — the proof is stored whether a
    // human or the chain produced it.
    // ────────────────────────────────────────────────────────────────────────────────────────
    const proof = `the chain applied ${row.txHash ?? 'these bytes'} and it did not deliver: ${status.reason}`
    const resolved = await resolveWithProof(deps.sql, deps.producer, {
      id: row.id,
      action: 'refund',
      proof,
      actor: 'system',
      correlationId: row.correlationId,
      fromStates: ['signed', 'broadcast'],
      events: (r) => failedEvents(r, status.reason, true),
    })
    if (resolved) {
      deps.metrics.increment('settlement_rejected_total', { chain: row.chain, purpose: row.purpose })
      deps.logger.error('outbound transaction rejected on chain and refunded', {
        outboundId: row.id,
        chain: row.chain,
        txHash: row.txHash,
        reason: status.reason,
      })
    }
    return
  }

  if (status.kind === 'pending') {
    // Seen on chain, so it is definitively broadcast whatever this row last recorded — which is the
    // recovery for a crash between `eth_sendRawTransaction` returning and the row being written.
    if (row.txHash) await markBroadcast(deps.sql, row.id, row.txHash)
    await markConfirmations(deps.sql, row.id, status.confirmations, status.minedHeight)
    if (stuckDeadlinePassed(row, deps.stuckMinutes, now)) {
      await goStuck(
        deps,
        row,
        `this payment has been on chain at ${status.confirmations} confirmations for longer than ` +
          'the settlement deadline and has not reached its required depth',
      )
    }
    return
  }

  // `unknown`: not on chain and not in this node's mempool, as far as anyone can tell. Re-send the
  // same bytes. **Not a refund and not a rejection** — an absence of a receipt is not an absence of
  // a transaction, and the bytes are untouched by it: the nonce is unconsumed and any node still
  // holding them can mine them months later.
  await send(deps, row)
  if (stuckDeadlinePassed(row, deps.stuckMinutes, now)) {
    await goStuck(deps, row, 'this payment has not been seen on chain since it was broadcast')
  }
}

/**
 * Park a signed transaction for a human. **Never a refund.**
 *
 * `markStuck` is gated on `signed`/`broadcast` in its WHERE clause, so a `planned` row reaching
 * here is a silent no-op rather than a state change — which is what keeps `stuck` meaning "bytes
 * exist and may still land" as call sites are added.
 */
async function goStuck(deps: WorkerDeps, row: OutboundTransaction, reason: string): Promise<void> {
  const stuck = await markStuck(deps.sql, deps.producer, row.id, reason, (r) => stuckEvents(r, reason))
  if (!stuck) return
  deps.metrics.increment('settlement_stuck_total', { chain: row.chain, purpose: row.purpose })
  deps.logger.error('outbound transaction stuck — it needs an operator and will NOT be auto-refunded', {
    outboundId: row.id,
    chain: row.chain,
    network: row.network,
    purpose: row.purpose,
    txHash: row.txHash,
    signedNonce: row.signedNonce,
    reason,
    adjudicateWith: `POST /v1/outbound/${row.id}/adjudicate`,
  })
}

/** Re-read a row after a drive, for a caller that wants to assert on it. */
export async function reload(deps: WorkerDeps, id: string): Promise<OutboundTransaction | null> {
  return findOutbound(deps.sql, id)
}
