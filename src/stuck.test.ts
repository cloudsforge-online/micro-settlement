/**
 * `withdrawal_stuck_total` — the metric behind the estate's loudest page.
 *
 * `WithdrawalStuck` is `withdrawal_stuck_total >= 1` for 5m at severity page, sev 1, and its
 * runbook opens "freeze before diagnosing". `MoneyMetricContractMissing` names the same string in
 * an `absent()` and on 2026-08-09 was firing on exactly that disjunct and no other. So there are
 * two ways to get this wrong and they fail in opposite directions:
 *
 *   * export nothing, or export it only when something is wrong, and the page never fires and the
 *     contract alert never clears — the state micro-org#310 measured;
 *   * count anything that is merely IN FLIGHT, and `>= 1` pages on the first withdrawal the estate
 *     ever makes, and the rule gets muted, which is worse than not having it.
 *
 * The tests below are pinned to the second of those as hard as to the first, because it is the one
 * that looks like success while it is being written.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { Metrics } from '@cloudsforge/telemetry'
import { adjudicate } from './adjudicate.ts'
import { findOutbound, planOutbound } from './outbound.ts'
import { implementedChains } from './registry.ts'
import { registerServiceMetrics } from './server.ts'
import { driveChain } from './worker.ts'
import type { Db } from './outbox.ts'
import {
  TEST_FEE,
  enabled,
  fakeCustody,
  fakeNode,
  harness,
  migrateTestDb,
  openDb,
  resetSettlement,
  skip,
  testAddress,
} from './testsupport.ts'

/*
 * The metric name is a LITERAL here and not the module's constant, deliberately.
 *
 * `prometheus/rules/alerts.yaml` names a string. Renaming the constant on both sides at once would
 * keep every assertion below green while the deployed page stopped matching anything — the exact
 * silent, green-to-green breakage this file exists to prevent. One assertion pins the module's
 * constant to the literal, so there is still exactly one spelling in the source.
 */
const STUCK = 'withdrawal_stuck_total'

/**
 * `./stuck.ts`, imported per case rather than at the top of the file.
 *
 * A static import of a module that is not there is a resolution error, and a resolution error takes
 * the whole file down as one anonymous failure — which is no use at all when what has to be shown
 * is WHICH property regressed. Reached this way, each case below fails on its own and says so.
 */
const stuckModule = (): Promise<typeof import('./stuck.ts')> => import('./stuck.ts')

/** The value of one series, or null when the series is not in the exposition at all. */
function gauge(metrics: Metrics, chain: string, network: string): number | null {
  const prefix = `${STUCK}{chain="${chain}",network="${network}"} `
  for (const line of metrics.render().split('\n')) {
    if (line.startsWith(prefix)) return Number(line.slice(prefix.length))
  }
  return null
}

/* ================================================================== without a database */

describe('the shape withdrawal_stuck_total is exported in', () => {
  /** A database with no stuck withdrawals to report: the healthy day the zeros have to survive. */
  const emptyDb = ((): readonly unknown[] => []) as unknown as Db

  it('is a gauge, because the deployed rule reads a level and must be able to clear', async () => {
    // The name says counter and the rule says level, and this is where that is decided. `_total`
    // conventionally suffixes a monotonic counter, but `WithdrawalStuck` is `>= 1` and its runbook
    // expects the page to go away when an operator adjudicates. A counter can never go down, so a
    // counter under this expression is a page that fires once and then cannot be cleared without
    // editing Prometheus. The suffix loses; the deployed expression wins.
    const text = registerServiceMetrics(new Metrics()).render()
    assert.ok(text.includes(`# TYPE ${STUCK} gauge`), 'the rule reads a level')
    assert.ok(!text.includes(`# TYPE ${STUCK} counter`))
    const { WITHDRAWAL_STUCK } = await stuckModule()
    assert.equal(WITHDRAWAL_STUCK, STUCK, 'the module must spell the name the rule asks for')
  })

  it('publishes a zero for every implemented chain, which is what answers absent()', async () => {
    // `MoneyMetricContractMissing` is an `absent()`, so a metric that only appears when something
    // is wrong reports "missing" on every healthy day — and a zero is a positive statement that
    // this service looked and found none, which an absence never is.
    const { publishStuckWithdrawals } = await stuckModule()
    const metrics = registerServiceMetrics(new Metrics())
    await publishStuckWithdrawals({
      sql: emptyDb,
      metrics,
      network: 'mainnet',
      stuckMinutes: 60,
    })

    for (const chain of implementedChains()) {
      assert.equal(gauge(metrics, chain, 'mainnet'), 0, `${chain} has no series to be absent about`)
    }
    // XRP has no adapter on this deployment, and a series for a chain this service cannot move
    // money on would be a permanent zero that means nothing.
    assert.equal(gauge(metrics, 'xrp', 'mainnet'), null)
  })
})

/* ================================================================== against real rows */

describe('counting stuck withdrawals', { skip }, () => {
  let sql: postgres.Sql
  const TREASURY = testAddress(0x7)
  const ALICE = testAddress(0xa1)
  const DEPOSIT = testAddress(0xd1)
  const OPERATOR = 'operator:00000000-0000-4000-8000-000000000001'

  before(async () => {
    if (!enabled) return
    sql = openDb()
    await migrateTestDb(sql)
  })
  after(async () => {
    if (enabled) await sql.end({ timeout: 5 })
  })
  beforeEach(async () => {
    if (enabled) await resetSettlement(sql)
  })

  /** A withdrawal driven to `broadcast`, with the clock under the test's control. */
  async function broadcastWithdrawal(purpose: 'withdrawal' | 'sweep' = 'withdrawal') {
    let now = Date.now()
    const node = fakeNode()
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    node.setBalance(DEPOSIT, 100n * 10n ** 18n)
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = harness(sql, { node, custody, stuckMinutes: 60, now: () => now })

    // A sweep signs with the DEPOSIT key, and custody will only do that against a binding this
    // service can restate — so `sourceRef` has to name a real `sweep_sources` row rather than a
    // string. Seeding it is what makes the sweep below a real sweep and not a mislabelled one.
    const sourceRef =
      purpose === 'sweep'
        ? (
            await sql<Array<{ id: string }>>`
              insert into sweep_sources (
                chain, network, address, address_key, custody_chain, custody_family,
                custody_user_id, custody_order_id
              ) values (
                'ember', 'testnet', ${DEPOSIT}, ${DEPOSIT}, 'ember', 'evm', 'user-1', 'order-1'
              ) returning id
            `
          )[0]!.id
        : 'withdrawal-1'

    await planOutbound(deps.sql, {
      purpose,
      chain: 'ember',
      network: 'testnet',
      from: purpose === 'sweep' ? DEPOSIT : TREASURY,
      to: purpose === 'sweep' ? TREASURY : ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 17n,
      fee: TEST_FEE,
      idempotencyKey: `wallet:${purpose}:1`,
      sourceRef,
      userId: 'user-1',
    })
    await driveChain(deps.worker, 'ember', 'testnet')
    const id = (await sql<Array<{ id: string }>>`select id from outbound_transactions`)[0]!.id
    return {
      deps,
      node,
      id,
      at: () => now,
      advance: (minutes: number) => (now += minutes * 60_000),
      /** Let the worker look again. This is what moves a row into `state = 'stuck'`. */
      tick: () => driveChain(deps.worker, 'ember', 'testnet'),
      count: async () => {
        const { countStuckWithdrawals } = await stuckModule()
        return (await countStuckWithdrawals(deps.sql, 60, now)).reduce((n, row) => n + row.count, 0)
      },
    }
  }

  it('counts nothing while a withdrawal is merely in flight', async () => {
    // The cry-wolf guard, and the assertion most worth keeping. `>= 1` is the page threshold, so a
    // definition that counts an ordinary broadcast pages on the estate's first real withdrawal.
    // The queue behind it is legitimately long: `outbound_in_flight_uniq` admits one in-flight row
    // per (chain, network), and on ETC the pinned depth is 7,500 confirmations — about 28.5 hours
    // holding that slot with nothing at all wrong.
    const w = await broadcastWithdrawal()
    assert.equal((await findOutbound(w.deps.sql, w.id))?.state, 'broadcast')

    assert.equal(await w.count(), 0)
    // And still nothing one minute short of the deadline. The boundary is the operator's agreed
    // wait, not an approximation of it.
    w.advance(59)
    assert.equal(await w.count(), 0)
  })

  it('counts a withdrawal the worker has parked', async () => {
    const w = await broadcastWithdrawal()
    w.advance(61)
    await w.tick()
    assert.equal((await findOutbound(w.deps.sql, w.id))?.state, 'stuck')

    const { countStuckWithdrawals } = await stuckModule()
    const rows = await countStuckWithdrawals(w.deps.sql, 60, w.at())
    assert.deepEqual([...rows], [{ chain: 'ember', network: 'testnet', count: 1 }])
  })

  it('counts a withdrawal past the deadline that no worker has parked', async () => {
    // The arm that exists because the worker is one of the things that breaks. `state = 'stuck'`
    // can only be written by `markStuck`, so a metric derived from it alone reports zero forever
    // when the worker is dead, wedged on a node, or draining with `shouldClaim` false — which is
    // precisely the failure a page is for. Here the clock passes the deadline and the worker never
    // runs again; the row is still `broadcast` and it still has to be counted.
    const w = await broadcastWithdrawal()
    w.advance(61)
    assert.equal((await findOutbound(w.deps.sql, w.id))?.state, 'broadcast')

    assert.equal(await w.count(), 1)
    // Both arms land in the SAME series, so the count does not dip when the worker catches up. A
    // definition that flickered across that handover would restart `for: 5m` and could postpone
    // the page indefinitely under exactly the load that makes the handover slow.
    await w.tick()
    assert.equal((await findOutbound(w.deps.sql, w.id))?.state, 'stuck')
    assert.equal(await w.count(), 1)
  })

  it('does not count a sweep, however stuck it is', async () => {
    // A stuck sweep is the estate's own money between the estate's own addresses: it costs an
    // operator a morning. A stuck withdrawal is a customer's payment in an unknown state, which is
    // what "freeze before diagnosing" is written for. The alert is named `WithdrawalStuck` and
    // 13-operational-model's Tier 1 line is "zero withdrawals `stuck` at end of day".
    const s = await broadcastWithdrawal('sweep')
    s.advance(61)
    await s.tick()
    assert.equal((await findOutbound(s.deps.sql, s.id))?.state, 'stuck')

    assert.equal(await s.count(), 0)
    // Not silence, though — the sweep is visible on the counter that is about transitions.
    assert.match(s.deps.metrics.render(), /settlement_stuck_total\{chain="ember",purpose="sweep"\} 1/)
  })

  it('falls back to zero once an operator has adjudicated', async () => {
    // The property that decides gauge-versus-counter, stated as a test rather than left to the
    // register call. The page has to CLEAR: the runbook's whole shape is freeze, diagnose,
    // adjudicate, unfreeze, and a monotonic counter under `>= 1` would leave it firing forever.
    const w = await broadcastWithdrawal()
    w.advance(61)
    await w.tick()
    const { publishStuckWithdrawals } = await stuckModule()
    const metrics = registerServiceMetrics(new Metrics())
    const publish = () =>
      publishStuckWithdrawals({
        sql: w.deps.sql,
        metrics,
        network: 'testnet',
        stuckMinutes: 60,
        now: w.at,
      })

    await publish()
    assert.equal(gauge(metrics, 'ember', 'testnet'), 1)

    // The nonce in the bytes has been consumed by something else: positive proof they can never be
    // mined, which is the only thing that unlocks a refund.
    w.node.setNonce(TREASURY, 1)
    const outcome = await adjudicate(w.deps.adjudication, {
      id: w.id,
      action: 'refund',
      actor: OPERATOR,
      correlationId: 'req-1',
    })
    assert.equal(outcome.kind, 'resolved')

    await publish()
    assert.equal(gauge(metrics, 'ember', 'testnet'), 0, 'the page must be able to clear')
  })
})
