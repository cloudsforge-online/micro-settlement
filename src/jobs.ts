/**
 * Background work.
 *
 * Rule 8 of docs/ecosystem/03 §2: every background timer is a leased job. There is no `setInterval`
 * in this repository doing domain work and CI greps for one — the estate runs eight of them today,
 * each guarded only by a module-local boolean, which is a variable that by construction cannot be
 * seen by a second process. That is why two withdrawal workers can sign against one nonce.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE LEASE KEY NAMES THE CONTENDED RESOURCE, NOT THE ROW.**
 *
 * This is the single decision most likely to be got wrong by someone extending this file, and it is
 * where the correctness of the whole service lives. Ask: what would break if two of these ran at
 * once? Whatever the answer names, that is the key.
 *
 *   | Work            | Key             | Why                                                     |
 *   |-----------------|-----------------|---------------------------------------------------------|
 *   | chain.outbound  | `chain:network` | **The chain's nonce.** Not the transaction id. Keying on |
 *   |                 |                 | the row is what the frozen withdrawer effectively does — |
 *   |                 |                 | `markWithdrawalSigned` protects one row perfectly — and  |
 *   |                 |                 | it does not help: two DIFFERENT withdrawals each pass    |
 *   |                 |                 | their own guard, both read the same pending nonce, and   |
 *   |                 |                 | one of the two payments is permanently lost.             |
 *   | chain.sweep     | `chain:network` | The same treasury and the same chain. It shares a key    |
 *   |                 |                 | with `chain.outbound` and that is SAFE FOR ONE REASON    |
 *   |                 |                 | ONLY: it never signs. See the note below, which is the   |
 *   |                 |                 | most dangerous thing on this page.                       |
 *   | outbox.relay    | `stream`        | The outbox stream. Keying on the event id would let two  |
 *   |                 |                 | relays deliver one batch to one subscriber twice.        |
 *   | ledger.fee      | `stream`        | The backlog of unbooked fees. Two runs cannot double-post|
 *   |                 |                 | — the ledger dedupes on the idempotency key — so the key |
 *   |                 |                 | bounds the load, not the correctness.                    |
 *
 * **A KEY IS NOT A LOCK ACROSS KINDS.** The jobs table is unique on `(kind, key)`, so
 * `chain.sweep / ember:testnet` and `chain.outbound / ember:testnet` are two rows and two workers
 * may hold them at the same instant. That is only tolerable because `chain.sweep` writes `planned`
 * rows and does nothing else: `planned` is not in the in-flight set, no nonce is read, and no
 * signature is requested. **The moment anything in `chain.sweep` signs, it must be merged into
 * `chain.outbound` rather than given its own key** — sharing a key with a different kind buys
 * nothing at all. The partial unique index `outbound_in_flight_uniq` would catch the mistake, but
 * catching it in the database is the last line, not the design.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Note what is NOT here: nothing polls a chain looking for money, and nothing probes a balance on a
 * schedule. Incoming money is the indexer's, per AD-07. The only balance this service reads is the
 * one it is about to spend, at the moment it is about to spend it.
 */

import { JobRunner, type Job, type JobQueue, type RunnerEvent } from '@cloudsforge/jobs'
import type { Network } from '@cloudsforge/contracts-chain'
import type { Logger, Metrics } from '@cloudsforge/telemetry'
import { isChainId, isNetwork, type ChainId } from './chains.ts'
import { implementedChains } from './registry.ts'
import { createRelay, type Db, type RelayDeps } from './outbox.ts'
import { bookFee, unbookedFees, type FeeDeps } from './fees.ts'
import { planSweep, type SweepDeps } from './sweeps.ts'
import { driveChain, type WorkerDeps } from './worker.ts'
import { NoTreasuryPinnedError, TreasuryDisagreementError } from './treasury.ts'
import { NoEndpointError } from './registry.ts'

export const RELAY_KIND = 'outbox.relay'
/** The only job that ever asks custody for a signature. */
export const OUTBOUND_KIND = 'chain.outbound'
/** Plans sweeps. Writes `planned` rows and never signs — see the note in the header. */
export const SWEEP_KIND = 'chain.sweep'
export const FEE_KIND = 'ledger.fee'

export interface Recurring {
  readonly kind: string
  readonly key: string
  readonly everyMs: number
  readonly payload?: Record<string, unknown>
}

/**
 * Jobs that must exist whether or not anything enqueued them, and how often they repeat.
 *
 * The chain jobs are seeded for every IMPLEMENTED chain rather than for every chain with work, and
 * that is deliberate: a job that only exists once there is something to do is a job whose absence
 * looks exactly like a job that is stuck. Seeding them all means `jobs_overdue` is a real signal —
 * a chain that has stopped ticking is visible in a table an operator can query, on a chain that is
 * currently idle.
 *
 * A recurring job is a producer plus a leased job, never a timer. The producer is the boot seed plus
 * the reschedule on completion, so the interval survives a restart and is claimed by exactly one
 * replica.
 */
export function recurringFor(network: Network): readonly Recurring[] {
  const chains = implementedChains()
  return Object.freeze([
    { kind: RELAY_KIND, key: 'stream', everyMs: 1_000 },
    ...chains.map((chain) => ({
      kind: OUTBOUND_KIND,
      key: `${chain}:${network}`,
      // Fast, because this is the loop a user is waiting on: it advances confirmations, resumes a
      // crashed broadcast and starts the next queued payment.
      everyMs: 5_000,
      payload: { chain, network },
    })),
    ...chains.map((chain) => ({
      kind: SWEEP_KIND,
      key: `${chain}:${network}`,
      // Slow, because a sweep is a response to a shortfall that a confirmation depth will take
      // minutes to clear anyway, and because each pass costs one balance probe per candidate.
      everyMs: 60_000,
      payload: { chain, network },
    })),
    { kind: FEE_KIND, key: 'stream', everyMs: 30_000 },
  ])
}

/** Enqueue the recurring set at boot. `keep` means N replicas booting together produce one row. */
export async function seedRecurring(queue: JobQueue, network: Network): Promise<void> {
  for (const job of recurringFor(network)) {
    await queue.enqueue({
      kind: job.kind,
      key: job.key,
      onConflict: 'keep',
      ...(job.payload ? { payload: job.payload } : {}),
    })
  }
}

/**
 * Re-arm a recurring job once it has finished.
 *
 * It cannot re-arm itself from inside its own handler: the runner deletes the row on success AFTER
 * the handler returns, so a self-enqueue would be deleted a moment later and the schedule would
 * stop. Doing it from the completion event is the only point at which the row is gone.
 *
 * A dead-lettered recurring job is deliberately **not** re-armed. The row stays, `jobs_dead_total`
 * increments and `jobs_overdue` climbs, which is how an operator finds out. Silently rescheduling a
 * job that has failed its full attempt budget hides a permanent fault behind a busy loop — and in
 * this service a permanently failing `chain.outbound` means every payment on that chain has stopped.
 */
export function rescheduleRecurring(
  queue: JobQueue,
  network: Network,
  logger: Logger,
): (event: RunnerEvent) => void {
  const byKey = new Map(recurringFor(network).map((r) => [`${r.kind}\u0000${r.key}`, r]))
  return (event) => {
    if (event.type !== 'completed') return
    const recurring = event.kind && event.key ? byKey.get(`${event.kind}\u0000${event.key}`) : undefined
    if (!recurring) return
    void queue
      .enqueue({
        kind: recurring.kind,
        key: recurring.key,
        runAt: new Date(Date.now() + recurring.everyMs),
        onConflict: 'earliest',
        ...(recurring.payload ? { payload: recurring.payload } : {}),
      })
      .catch((err: unknown) =>
        logger.error('failed to re-arm recurring job', { kind: recurring.kind, key: recurring.key, err }),
      )
  }
}

export interface JobDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly metrics: Metrics
  readonly signingSecret: string
  readonly worker: WorkerDeps
  readonly sweeps: SweepDeps
  readonly fees: FeeDeps
}

/** How many rows one pass of a backlog job takes. Bounded so a pass fits inside its lease. */
const BATCH = 50

/**
 * The `(chain, network)` a chain job is for, taken from its payload and VALIDATED.
 *
 * From the payload rather than parsed out of the key, because a key is a string an operator can
 * type into the jobs table and a payload is structured. Both are checked anyway: an unrecognised
 * chain throws, which dead-letters the job rather than silently doing nothing for ever.
 */
function scopeOf(job: Job<{ chain?: unknown; network?: unknown }>): {
  readonly chain: ChainId
  readonly network: Network
} {
  const chain = job.payload.chain
  const network = job.payload.network
  if (typeof chain !== 'string' || !isChainId(chain)) {
    throw new Error(`${job.kind} was enqueued for an unknown chain: ${String(chain)}`)
  }
  if (typeof network !== 'string' || !isNetwork(network)) {
    throw new Error(`${job.kind} was enqueued for an unknown network: ${String(network)}`)
  }
  return { chain, network }
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  const relayDeps: RelayDeps = {
    sql: deps.sql,
    logger: deps.logger.child({ job: RELAY_KIND }),
    signingSecret: deps.signingSecret,
  }
  runner.register(RELAY_KIND, createRelay(relayDeps))

  /**
   * The chain's turn. **The only handler in this service that can cause a signature.**
   *
   * One lease, one chain, one step: advance whatever is in flight, then start the oldest queued
   * transaction if nothing is. The handler heartbeats between steps because a chain that is slow to
   * answer must not let this lease expire while a signature is in the air — a second worker picking
   * the chain up mid-signature is the whole failure this is arranged to prevent, and although the
   * partial unique index would still refuse it, relying on that would be relying on the last line.
   */
  runner.register<{ chain?: unknown; network?: unknown }>(OUTBOUND_KIND, async (job, ctx) => {
    const { chain, network } = scopeOf(job)
    const result = await driveChain(deps.worker, chain, network, ctx.heartbeat)
    if (result.advanced || result.signed || result.retired.length > 0) {
      deps.logger.info('chain advanced', {
        chain,
        network,
        advanced: result.advanced,
        signed: result.signed,
        retired: result.retired.length,
      })
    }
  })

  /**
   * Plan a sweep if the treasury is short. **Writes `planned` rows and never signs.**
   *
   * That property is what makes it safe to share a lease key with `chain.outbound`, and it is
   * stated here as well as in the header because the two statements are the same fact and a change
   * to one without the other is how the invariant is lost.
   *
   * The three configuration refusals — no pin, a pin that disagrees with the payout row, no node —
   * are caught rather than thrown. Throwing would burn the attempt budget and dead-letter a
   * recurring job, so an operator who has not pinned a treasury yet would find sweeping silently
   * off for the life of the deployment rather than starting the moment they pin one.
   */
  runner.register<{ chain?: unknown; network?: unknown }>(SWEEP_KIND, async (job) => {
    const { chain, network } = scopeOf(job)
    try {
      const outcome = await planSweep(deps.sweeps, chain, network)
      if (outcome.kind === 'planned') {
        deps.metrics.increment('settlement_sweeps_planned_total', { chain })
        deps.logger.info('sweep planned', {
          chain,
          network,
          outboundId: outcome.outboundId,
          amount: outcome.amount.toString(),
        })
      }
    } catch (err) {
      if (
        err instanceof NoTreasuryPinnedError ||
        err instanceof TreasuryDisagreementError ||
        err instanceof NoEndpointError
      ) {
        deps.metrics.increment('settlement_sweeps_blocked_total', { chain })
        deps.logger.error('sweeping is blocked on this chain', { chain, network, err })
        return
      }
      throw err
    }
  })

  /**
   * Journal the network fees of confirmed transactions.
   *
   * A backlog job rather than part of the confirmation, because the payment is on chain whatever
   * the ledger says: a bookkeeping outage must not become a money outage. A failure here is logged
   * and left, and the row stays in the query.
   */
  runner.register(FEE_KIND, async (_job, ctx) => {
    const pending = await unbookedFees(deps.sql, BATCH)
    for (const row of pending) {
      if (ctx.signal.aborted) return
      try {
        await bookFee(deps.fees, row)
      } catch (err) {
        deps.logger.error('could not journal a network fee', { outboundId: row.id, err })
      }
      await ctx.heartbeat()
    }
    deps.metrics.set('settlement_fees_unbooked', pending.length)
  })

  return runner
}
