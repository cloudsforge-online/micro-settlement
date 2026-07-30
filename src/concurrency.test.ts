/**
 * **THE HEADLINE TEST. Two concurrent workers on one chain: exactly one signs.**
 *
 * This is the defect the service exists to fix, reproduced against the real machinery and then
 * shown not to happen. The frozen withdrawal worker guards itself with `hasUnsettledOutbound()`,
 * an unlocked read; `markWithdrawalSigned` then protects a single row perfectly, and that is not
 * enough, because **the contended resource is not the row — it is the chain's nonce.** Two
 * DIFFERENT pending withdrawals each pass their own guard, each read `eth_getTransactionCount`,
 * each get the same answer, and one of the two payments is permanently lost.
 *
 * There are two defences in this service and this file tests them separately, because they fail
 * separately:
 *
 *   1. **The lease**, keyed `chain:network`. `@cloudsforge/jobs` claims with `for update skip
 *      locked`, so of two workers polling for `chain.outbound / ember:testnet` exactly one gets it.
 *   2. **`outbound_in_flight_uniq`**, a partial unique index on `(chain, network)` over the
 *      in-flight states. It is what stands when the lease has already failed — a clock skew past
 *      `locked_until`, a handler that outran its lease, an operator running a script beside the
 *      workers. The second test below deletes the lease from the picture entirely and drives two
 *      workers straight at `driveChain`, which is the strictly harder case.
 *
 * The assertion in both is on `custody.signatures.length`, not on row states. A row state is what
 * this service believes; a signature is what actually happened to a nonce.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import { JobQueue, JobRunner } from '@cloudsforge/jobs'
import type { Sql as JobsSql } from '@cloudsforge/jobs'
import type postgres from 'postgres'
import { planOutbound } from './outbound.ts'
import { driveChain } from './worker.ts'
import { registerHandlers } from './jobs.ts'
import { OUTBOUND_KIND } from './jobs.ts'
import {
  TEST_FEE,
  enabled,
  fakeCustody,
  fakeNode,
  harness,
  migrateTestDb,
  openDb,
  quietLogger,
  resetSettlement,
  skip,
  testAddress,
  type FakeCustody,
} from './testsupport.ts'

describe('two concurrent workers on one chain', { skip }, () => {
  let sql: postgres.Sql
  const TREASURY = testAddress(0x7)
  const ALICE = testAddress(0xa1)
  const BOB = testAddress(0xb0)

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

  /**
   * Two pending withdrawals, both payable, both on `ember:testnet`. If the guard were the row, both
   * would sign. The chain lease means one worker never even sees the queue.
   */
  async function twoQueuedWithdrawals(node: ReturnType<typeof fakeNode>) {
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    for (const [i, destination] of [ALICE, BOB].entries()) {
      await planOutbound(sql as never, {
        purpose: 'withdrawal',
        chain: 'ember',
        network: 'testnet',
        from: TREASURY,
        to: destination,
        assetCode: 'EMBER',
        amount: 10n ** 17n,
        fee: TEST_FEE,
        idempotencyKey: `wallet:withdrawal:${i}`,
        sourceRef: `withdrawal-${i}`,
        userId: `user-${i}`,
      })
    }
  }

  it('under the chain lease, exactly one of two job runners signs', async () => {
    const node = fakeNode()
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    await twoQueuedWithdrawals(node)

    // Two runners with DIFFERENT owners, exactly as two replicas would be. One queue row, keyed
    // `ember:testnet`, is all there is for either of them to claim.
    const runners = ['replica-a', 'replica-b'].map((owner) => {
      const queue = new JobQueue(sql as unknown as JobsSql, { owner, leaseMs: 60_000 })
      const runner = new JobRunner({ queue, concurrency: 4, pollMs: 1_000 })
      const deps = harness(sql, { node, custody })
      registerHandlers(runner, {
        sql: deps.sql,
        logger: quietLogger(),
        metrics: deps.metrics,
        signingSecret: 'test-signing-secret-000000000000',
        worker: deps.worker,
        sweeps: deps.sweeps,
        fees: { sql: deps.sql, ledger: deps.ledger, logger: quietLogger(), producer: 'settlement' },
      })
      return { queue, runner }
    })

    await runners[0]!.queue.enqueue({
      kind: OUTBOUND_KIND,
      key: 'ember:testnet',
      payload: { chain: 'ember', network: 'testnet' },
    })

    // Both tick at the same instant. `for update skip locked` is what makes this deterministic:
    // the loser skips the row rather than waiting on it, so neither runner serialises behind the
    // other and neither is handed the same job.
    await Promise.all(runners.map((r) => r.runner.tick()))

    assert.equal(
      custody.signatures.length,
      1,
      'two workers each signed against the same nonce — the lease did not hold',
    )
    const inFlight = await sql`
      select count(*)::int as n from outbound_transactions
       where chain = 'ember' and network = 'testnet' and state in ('building','signed','broadcast')
    `
    assert.equal(inFlight[0]!.n, 1)
  })

  /**
   * The same proof with the lease taken away.
   *
   * Both workers are driven straight at `driveChain` with no queue between them, which is what a
   * lease failure looks like from the inside. `custody.onSign` holds the first signature open until
   * the second worker has had its chance to reach the same point, so the two are genuinely
   * overlapping rather than accidentally sequential — without that hook this test would pass on a
   * fast machine for the wrong reason.
   *
   * What stops the second one is `outbound_in_flight_uniq`: `claimForBuilding` catches the 23505 and
   * answers "not my turn", so **no second signature is requested at all**. Note what is being
   * asserted — not that the second signature was discarded after the fact, but that custody was
   * never asked for it.
   */
  it('without the lease, the in-flight index still allows exactly one signature', async () => {
    const node = fakeNode()
    const custody: FakeCustody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    await twoQueuedWithdrawals(node)

    let releaseFirst: (() => void) | null = null
    const firstReached = new Promise<void>((resolve) => {
      custody.onSign = async () => {
        resolve()
        // Hold the first worker inside custody until the second has been given its chance.
        await new Promise<void>((release) => {
          releaseFirst = release
        })
        custody.onSign = undefined
      }
    })

    const a = harness(sql, { node, custody })
    const b = harness(sql, { node, custody })

    const first = driveChain(a.worker, 'ember', 'testnet')
    await firstReached
    // The second worker runs to completion while the first is suspended mid-signature.
    const secondResult = await driveChain(b.worker, 'ember', 'testnet')
    releaseFirst!()
    const firstResult = await first

    assert.equal(
      custody.signatures.length,
      1,
      'custody was asked for a second signature while one was already in flight on this chain',
    )
    assert.equal(custody.requests.length, 1, 'a second signature was requested and then discarded')
    assert.ok(firstResult.signed, 'the worker that got there first should have signed')
    assert.equal(secondResult.signed, null, 'the second worker must not sign')

    const states = await sql<Array<{ state: string }>>`
      select state from outbound_transactions order by created_at
    `
    // One in flight, one still queued. Not one in flight and one failed: losing the race is not a
    // failure, it is a turn that has not come yet.
    assert.deepEqual(
      states.map((r) => r.state).sort(),
      ['broadcast', 'planned'],
    )
  })

  /**
   * The index itself, stated as a constraint rather than inferred from behaviour.
   *
   * If this ever goes red the schema has drifted, and everything above it is testing a lease with
   * nothing underneath it.
   */
  it('the database refuses a second in-flight transaction on one chain outright', async () => {
    const { sql: db } = harness(sql)
    const a = await planOutbound(db, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 1n,
      fee: TEST_FEE,
      idempotencyKey: 'k-a',
    })
    const b = await planOutbound(db, {
      purpose: 'sweep',
      chain: 'ember',
      network: 'testnet',
      from: testAddress(0xdd),
      to: TREASURY,
      assetCode: 'EMBER',
      amount: 1n,
      fee: TEST_FEE,
      idempotencyKey: 'k-b',
    })

    await sql`update outbound_transactions set state = 'building' where id = ${a.outbound.id}`
    await assert.rejects(
      // A SWEEP, deliberately: the index is per chain and not per purpose, because a sweep and a
      // withdrawal on one chain are two transactions competing for one account's nonce whenever
      // they share a source — and keying it per purpose would be a rule that is only correct while
      // nothing else on the chain shares an address.
      sql`update outbound_transactions set state = 'building' where id = ${b.outbound.id}`,
      (err: { code?: string; constraint_name?: string }) =>
        err.code === '23505' && err.constraint_name === 'outbound_in_flight_uniq',
    )

    // Another network is a different resource and must NOT be refused. Without this the index would
    // be serialising the whole estate on one chain name.
    const c = await planOutbound(db, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'mainnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 1n,
      fee: TEST_FEE,
      idempotencyKey: 'k-c',
    })
    await sql`update outbound_transactions set state = 'building' where id = ${c.outbound.id}`
  })
})
