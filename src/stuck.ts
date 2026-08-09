/**
 * `withdrawal_stuck` — the number the estate's loudest page reads.
 *
 * `WithdrawalStuck` fires on `withdrawal_stuck >= 1` for 5m at severity `page`, sev 1, and
 * `MoneyMetricContractMissing` names the same string inside an `absent()`. Measured on the mainnet
 * Prometheus on 2026-08-09: `MoneyMetricContractMissing` was firing, and firing on exactly this one
 * of its three disjuncts — `ledger_trial_balance_delta` and `indexer_lag_blocks` both had series and
 * `withdrawal_stuck` had never existed. So the page has never been able to fire either. This
 * module is the missing exporter.
 *
 * ── WHAT COUNTS AS STUCK, AND WHY IT IS NOT SIMPLY "OPEN" ─────────────────────────────────────
 *
 * A withdrawal is counted stuck when its `purpose` is `withdrawal` and EITHER
 *
 *   (a) `state = 'stuck'` — the worker has already parked it. This is a real state in the schema,
 *       constrained by `outbound_transactions_state_ck` and reachable only through `markStuck`,
 *       which moves only `signed` and `broadcast` rows. A row in it is never auto-refunded and
 *       leaves only through `adjudicate.ts` on positive proof; or
 *
 *   (b) `state in ('signed','broadcast')` and `coalesce(broadcast_at, created_at)` is older than
 *       `SETTLEMENT_STUCK_MINUTES` — the deadline has passed and the worker has NOT parked it.
 *
 * Arm (b) is not redundant with arm (a) and is the reason this is worth exporting at all. The only
 * thing in the estate that can produce `state = 'stuck'` is the worker; if the worker is dead,
 * wedged on a node, or not claiming because a deploy left `shouldClaim` false, then arm (a) counts
 * zero forever no matter how many customers are waiting. That is the failure a page is FOR, and a
 * metric derived purely from the worker's own bookkeeping is blind to precisely it. Arm (b) reads
 * the timestamps instead, which are written by the transitions themselves.
 *
 * Both arms deliberately land in the SAME series rather than in two, so that the count does not dip
 * to zero at the moment the worker catches up and moves a row from (b) into (a). `for: 5m` requires
 * the expression to be continuously true; a definition that flickered across the handover would
 * reset the clock and could postpone the page indefinitely under exactly the load that causes the
 * handover to be slow.
 *
 * ── WHY `planned` AND `building` ARE EXCLUDED (THE CRY-WOLF DEFENCE) ──────────────────────────
 *
 * `>= 1` is the threshold, so any definition that counts an ordinary in-flight withdrawal pages on
 * day one and gets the rule muted, which is strictly worse than not having it. The excluded states
 * are the queue, and the queue is legitimately long: `outbound_in_flight_uniq` admits at most one
 * in-flight row per `(chain, network)`, so withdrawals behind it wait by design. On ETC that wait is
 * not small — the pinned contract's depth is 7,500 confirmations, roughly 28.5 hours at ~13.7s
 * blocks, all of it with the single in-flight slot held. A queued row on ETC would therefore be
 * older than any sane `SETTLEMENT_STUCK_MINUTES` while nothing whatever is wrong.
 *
 * The excluded states are also the states in which nothing has been signed. Nothing has left
 * custody, no bytes exist that a node could mine, and `markFailed` — not an operator — is what
 * moves them. A `planned` row that never builds is a queue problem and shows up as `jobs_overdue`;
 * it is not a payment in an unknown state, which is what this page means and what its runbook
 * ("freeze before diagnosing") is written for.
 *
 * Sweeps, treasury moves, gas top-ups and deploys are excluded for the same reason in reverse: they
 * are the estate's own money moving between the estate's own addresses. A stuck sweep costs an
 * operator a morning; it does not leave a customer's withdrawal in an unknown state at 3am. The
 * alert is named `WithdrawalStuck` and 13-operational-model's Tier 1 line is "zero withdrawals
 * `stuck` at end of day, 100% of days, no budget", so `purpose = 'withdrawal'` is the contract.
 *
 * ── THE NAME SAYS COUNTER AND THE RULE READS A LEVEL. IT IS A GAUGE. ──────────────────────────
 *
 * These two disagree and the disagreement is in the deployed artefacts, so it is stated here rather
 * than quietly resolved. `_total` conventionally suffixes a monotonic counter, and Prometheus
 * tooling — `rate()`, `increase()`, the Grafana unit picker — assumes it. But the deployed rule is
 * `withdrawal_stuck >= 1`, which is a level: it asks "are any withdrawals stuck right now",
 * and its runbook expects the page to CLEAR once an operator adjudicates. A monotonic counter can
 * never clear, so exporting one under that expression would produce a page that fires on the first
 * stuck withdrawal the estate ever has and can then never be resolved without editing Prometheus.
 *
 * So the suffix went, rather than the gauge. The metric is `withdrawal_stuck`, registered
 * `kind: 'gauge'`, and `alerts.yaml` reads `withdrawal_stuck >= 1` — renamed in the same release
 * this metric first ships in, which is the only moment the rename is free. It had never been
 * scraped anywhere: the rule has been deployed since the alerting plane was written and has been
 * evaluating against no series the whole time, so there is no dashboard history to break and no
 * recording rule to migrate. Every later moment costs a migration; this one costs an edit.
 *
 * Note that the increase-shaped signal already exists and is unaffected:
 * `settlement_stuck_total{chain,purpose}` is a genuine monotonic transition counter incremented by
 * `markStuck`, and it is emphatically NOT what this rule should be repointed at — `>= 1` against a
 * counter is a page that fires on the estate's first stuck withdrawal and can never be cleared.
 *
 * ── ZEROS ARE PUBLISHED, WHICH IS HALF THE POINT ──────────────────────────────────────────────
 *
 * `MoneyMetricContractMissing` is an `absent()`, so a metric that appears only when something is
 * wrong answers it with "missing" on every healthy day. Every implemented chain on this
 * deployment's network is therefore seeded at 0 on every scrape, which both silences that alert
 * honestly and makes the healthy state legible: a `withdrawal_stuck{chain="btc"} 0` is a
 * positive statement that this service looked and found none, which absence never is.
 */

import type { Network } from '@cloudsforge/contracts-chain'
import type { ChainId } from './chains.ts'
import { implementedChains } from './registry.ts'
import { stuckCutoff } from './outbound.ts'
import type { Db } from './outbox.ts'

/** The exact string `alerts.yaml` names, in both `WithdrawalStuck` and `MoneyMetricContractMissing`. */
export const WITHDRAWAL_STUCK = 'withdrawal_stuck'

export interface StuckWithdrawals {
  readonly chain: ChainId
  readonly network: Network
  readonly count: number
}

/**
 * Count withdrawals in the two stuck arms, grouped by the labels the alert carries.
 *
 * Grouped in the database rather than by pulling rows back: this runs on the scrape path, and the
 * only bound on the row count is how badly things have already gone wrong.
 */
export async function countStuckWithdrawals(
  sql: Db,
  stuckMinutes: number,
  now: number = Date.now(),
): Promise<readonly StuckWithdrawals[]> {
  const cutoff = stuckCutoff(stuckMinutes, now)
  const rows = await sql<{ chain: string; network: string; stuck: string }[]>`
    select chain, network, count(*) as stuck
      from outbound_transactions
     where purpose = 'withdrawal'
       and (
             -- (a) the worker parked it. Exits only through adjudication, on proof.
             state = 'stuck'
             -- (b) the deadline passed and the worker did NOT park it, which is the arm that still
             -- reports when the worker is the thing that is broken.
             or (state in ('signed','broadcast') and coalesce(broadcast_at, created_at) < ${cutoff})
           )
     group by chain, network
  `
  return rows.map((row) => ({
    chain: row.chain as ChainId,
    network: row.network as Network,
    count: Number(row.stuck),
  }))
}

export interface StuckMetricDeps {
  readonly sql: Db
  readonly network: Network
  readonly stuckMinutes: number
  /** Only `set` is used. Typed structurally so a test can pass a `Metrics` without the whole facade. */
  readonly metrics: { set(name: string, value: number, labels?: Record<string, string>): void }
  readonly now?: () => number
}

/**
 * Sample the count onto the gauge. Called from the `/metrics` route's `beforeScrape`.
 *
 * At scrape time and not on a timer — rule 8, and CI greps for `setInterval`. That is the right
 * shape here anyway: the number is a query against live rows, so sampling it when someone asks
 * makes it exactly as fresh as the scrape and costs nothing when nobody is scraping.
 *
 * Every implemented chain is written every time, zeros included, before the counts are laid over
 * the top. Writing the zeros is what keeps a series alive after the last stuck withdrawal is
 * adjudicated — omit it and the series simply stops being reported, which Prometheus renders as a
 * gap rather than as a zero and which `>= 1` would keep matching from the stale sample until it
 * ages out.
 */
export async function publishStuckWithdrawals(deps: StuckMetricDeps): Promise<void> {
  const now = deps.now?.() ?? Date.now()
  for (const chain of implementedChains()) {
    deps.metrics.set(WITHDRAWAL_STUCK, 0, { chain, network: deps.network })
  }
  for (const row of await countStuckWithdrawals(deps.sql, deps.stuckMinutes, now)) {
    deps.metrics.set(WITHDRAWAL_STUCK, row.count, { chain: row.chain, network: row.network })
  }
}
