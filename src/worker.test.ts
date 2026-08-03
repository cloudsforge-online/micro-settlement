/**
 * The state machine, driven end to end against a fake node.
 *
 * Three properties are load-bearing and each has a test whose failure would mean lost money:
 *
 *   1. **A crash between signing and broadcasting is recoverable.** The bytes are on disk and the
 *      next tick RESUMES rather than re-signing.
 *   2. **A build failure refunds; a signed-and-stuck transaction does not.**
 *   3. **A rejected transaction is the one automatic refund, and it records its proof.**
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { findOutbound, planOutbound, type OutboundPurpose, type OutboundTransaction } from './outbound.ts'
import { driveChain, signingPolicy } from './worker.ts'
import { evmTxHash, legacyNonce } from './evm.ts'
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

/**
 * **The purpose claimed to custody and the shape the bytes are built for, pinned together.**
 *
 * No database, because this is exactly the kind of negative property that gets deleted when it
 * needs one. A disagreement between these two is not a wrong answer anywhere — it is a 403 arriving
 * after the row is committed and the chain's single outbound slot is claimed, with a message that
 * deliberately will not say which field was wrong.
 */
describe('the signing policy a row selects', () => {
  it('pairs every purpose with the custody purpose and the shape that policy wants', () => {
    // `deposit` is the only purpose whose destination custody chooses, so it is the only one that
    // gets the pinned shape — and on Bitcoin that shape is a PSBT with no change output at all.
    assert.deepEqual(signingPolicy('sweep'), { custodyPurpose: 'deposit', shape: 'sweep' })
    for (const purpose of ['withdrawal', 'treasury_move', 'deploy'] as const) {
      assert.deepEqual(
        signingPolicy(purpose),
        { custodyPurpose: 'treasury', shape: 'payment' },
        `${purpose} spends the treasury and names its own destination`,
      )
    }
  })

  it('never pairs a treasury purpose with a sweep shape, or the reverse', () => {
    // The two failure directions are not symmetrical and that is why this is stated separately.
    // `treasury` + `sweep` builds a change-free transaction for a withdrawal, which on Bitcoin pays
    // the user's whole treasury balance minus a fee to one output. `deposit` + `payment` builds a
    // change output custody refuses whole. The first loses money; the second costs a retry.
    const purposes: readonly OutboundPurpose[] = ['withdrawal', 'sweep', 'treasury_move', 'deploy']
    for (const purpose of purposes) {
      const policy = signingPolicy(purpose)
      assert.equal(
        policy.shape === 'sweep',
        policy.custodyPurpose === 'deposit',
        `${purpose}: the shape and the custody purpose disagree`,
      )
    }
  })
})

describe('the outbound worker', { skip }, () => {
  let sql: postgres.Sql
  const TREASURY = testAddress(0x7)
  const ALICE = testAddress(0xa1)

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

  async function queueWithdrawal(
    deps: ReturnType<typeof harness>,
    overrides: { readonly to?: string; readonly fee?: bigint; readonly key?: string } = {},
  ): Promise<OutboundTransaction> {
    const { outbound } = await planOutbound(deps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: overrides.to ?? ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 17n,
      fee: overrides.fee ?? TEST_FEE,
      idempotencyKey: overrides.key ?? 'wallet:withdrawal:1',
      sourceRef: 'withdrawal-1',
      userId: 'user-1',
    })
    return outbound
  }

  function funded(options: Parameters<typeof harness>[1] = {}) {
    const node = options.node ?? fakeNode()
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const custody = options.custody ?? fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    return harness(sql, { ...options, node, custody })
  }

  it('builds, signs, commits the bytes and only then broadcasts', async () => {
    const deps = funded()
    const row = await queueWithdrawal(deps)

    await driveChain(deps.worker, 'ember', 'testnet')

    const after = await findOutbound(deps.sql, row.id)
    assert.equal(after?.state, 'broadcast')
    assert.ok(after?.rawTx, 'the signed bytes must be on the row')
    assert.equal(deps.custody.signatures.length, 1)
    assert.equal(deps.node.broadcast.length, 1)
    // The nonce is committed AND derivable from the bytes, and the two agree. If they ever did not,
    // the adjudication path would be judging a different transaction from the one that was signed.
    assert.equal(after?.signedNonce, '0')
    assert.equal(legacyNonce(after!.rawTx!), 0n)
    assert.equal(after?.txHash, evmTxHash(after!.rawTx!))
    assert.equal(after?.custodyAuditId, 'audit-1')
  })

  /**
   * **A crash between the commit and the broadcast.**
   *
   * Modelled by failing `eth_sendRawTransaction` once, which leaves exactly the state a killed
   * process leaves: `signed`, with `raw_tx` populated and no `broadcast_at`. The next tick must
   * re-send the IDENTICAL bytes and must NOT ask custody for a second signature — there is no path
   * in `advance` from `signed` back to `building`, and this is the test of that.
   */
  it('resumes a crashed broadcast from the committed bytes without re-signing', async () => {
    const deps = funded()
    const row = await queueWithdrawal(deps)
    deps.node.failNext('eth_sendRawTransaction', 'connection reset')

    await driveChain(deps.worker, 'ember', 'testnet')
    const crashed = await findOutbound(deps.sql, row.id)
    assert.equal(crashed?.state, 'signed', 'a failed broadcast must leave the row signed, not failed')
    assert.ok(crashed?.rawTx)
    assert.equal(crashed?.broadcastAt, null)
    assert.equal(deps.node.broadcast.length, 0, 'nothing reached the wire')
    const committedBytes = crashed!.rawTx!

    await driveChain(deps.worker, 'ember', 'testnet')

    const resumed = await findOutbound(deps.sql, row.id)
    assert.equal(resumed?.state, 'broadcast')
    assert.equal(resumed?.rawTx, committedBytes, 'the resumed broadcast must send the same bytes')
    assert.equal(
      deps.custody.signatures.length,
      1,
      'the recovery asked custody for a second signature — a second nonce would have been read',
    )
    assert.deepEqual(deps.node.broadcast, [committedBytes])
  })

  /** A node that already holds the bytes answers with an ERROR, and that is the success case. */
  it('treats "already known" from a re-broadcast as success', async () => {
    const deps = funded()
    const row = await queueWithdrawal(deps)
    await driveChain(deps.worker, 'ember', 'testnet')
    const first = await findOutbound(deps.sql, row.id)

    // Force a re-send: the indexer has never heard of it and the node has no receipt, so `advance`
    // re-broadcasts. The fake node throws 'already known' for bytes it holds.
    await driveChain(deps.worker, 'ember', 'testnet')

    const second = await findOutbound(deps.sql, row.id)
    assert.equal(second?.state, 'broadcast')
    assert.equal(second?.txHash, first?.txHash, 'the derived hash must survive a re-broadcast')
    assert.equal(deps.custody.signatures.length, 1)
  })

  it('confirms once the chain has it at the asset declared depth', async () => {
    const deps = funded()
    const row = await queueWithdrawal(deps)
    await driveChain(deps.worker, 'ember', 'testnet')
    const broadcast = await findOutbound(deps.sql, row.id)

    deps.node.mine(deps.node.broadcast[0]!)
    // EMBER's declared depth is 60 and it is read from contracts-chain, never restated here.
    deps.node.advance(2)
    await driveChain(deps.worker, 'ember', 'testnet')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'broadcast', 'not deep enough yet')

    deps.node.advance(100)
    await driveChain(deps.worker, 'ember', 'testnet')
    const confirmed = await findOutbound(deps.sql, row.id)
    assert.equal(confirmed?.state, 'confirmed')
    assert.ok(confirmed!.confirmations >= 60)
    assert.ok(broadcast?.txHash)

    // The events wallet's contract requires, in the outbox, written in the same transaction.
    const events = await sql<Array<{ topic: string; payload: Record<string, unknown> }>>`
      select topic, payload from outbox order by occurred_at
    `
    const topics = events.map((e) => e.topic)
    assert.ok(topics.includes('settlement.outbound.confirmed'))
    assert.ok(topics.includes('settlement.withdrawal.completed'))
    const confirmedEvent = events.find((e) => e.topic === 'settlement.outbound.confirmed')!
    assert.equal(confirmedEvent.payload['withdrawalId'], 'withdrawal-1')
  })

  /* ------------------------------------------------------------------ refunds */

  it('refunds a build failure from planned, with refundable true', async () => {
    const deps = funded()
    // A destination with code at it. Permanent, and the user can act on it.
    const contract = testAddress(0xc0)
    const node = fakeNode({ contracts: [contract] })
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const withCode = harness(sql, { node, custody: deps.custody })
    const row = await queueWithdrawal(withCode, { to: contract })

    await driveChain(withCode.worker, 'ember', 'testnet')

    const failed = await findOutbound(withCode.sql, row.id)
    assert.equal(failed?.state, 'failed')
    assert.equal(withCode.custody.signatures.length, 0, 'nothing was signed, so a refund is safe')
    const events = await sql<Array<{ topic: string; payload: Record<string, unknown> }>>`
      select topic, payload from outbox
    `
    const event = events.find((e) => e.topic === 'settlement.outbound.failed')
    assert.ok(event, 'a build failure must tell wallet to release the reservation')
    assert.equal(event!.payload['refundable'], true)
  })

  it('refunds an out-of-band fee immediately and never asks custody', async () => {
    const deps = funded()
    // Ten times the ceiling. Refused before a single node call, because the fee is a property of
    // the row and finding that out after four round trips is four round trips wasted.
    const row = await queueWithdrawal(deps, { fee: 10n * 10n ** 18n })

    await driveChain(deps.worker, 'ember', 'testnet')

    const failed = await findOutbound(deps.sql, row.id)
    assert.equal(failed?.state, 'failed')
    assert.equal(deps.custody.requests.length, 0)
    assert.equal(deps.node.calls.length, 0, 'the node should not have been asked anything')
  })

  it('holds a transient failure on the queue instead of refunding it', async () => {
    const deps = funded()
    const row = await queueWithdrawal(deps)
    // An underfunded treasury: not the user's fault and not permanent.
    deps.node.setBalance(TREASURY, 1n)

    await driveChain(deps.worker, 'ember', 'testnet')

    const held = await findOutbound(deps.sql, row.id)
    assert.equal(held?.state, 'planned', 'a transient failure must go back on the queue, not fail')
    // And critically it must NOT be left in `building`, which is an in-flight state: a row abandoned
    // there holds the partial unique index and blocks every other payment on the chain.
    const inFlight = await sql`
      select count(*)::int as n from outbound_transactions
       where state in ('building','signed','broadcast')
    `
    assert.equal(inFlight[0]!.n, 0)
  })

  it('gives up on a transient failure once the deadline has passed, and refunds', async () => {
    // Based on the real clock, because the rows below get their created_at from the database.
    let now = Date.now()
    const node = fakeNode()
    node.setBalance(TREASURY, 1n)
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = harness(sql, { node, custody, stuckMinutes: 60, now: () => now })
    const row = await queueWithdrawal(deps)

    await driveChain(deps.worker, 'ember', 'testnet')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'planned')

    now += 61 * 60_000
    await driveChain(deps.worker, 'ember', 'testnet')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'failed')
  })

  /* ------------------------------------------------------------------ stuck */

  /**
   * **A signed-and-stuck transaction is never auto-refunded.**
   *
   * The clock is pushed past the deadline with a broadcast transaction the chain has no record of —
   * which is the ambiguous case, and the dangerous one. An absence of a receipt is not an absence
   * of a transaction: the nonce is unconsumed and any node still holding the bytes can mine them
   * months later. So the row goes `stuck` and emits nothing that settles money.
   */
  it('marks a signed transaction stuck past the deadline and does NOT refund it', async () => {
    // Based on the real clock, because the rows below get their created_at from the database.
    let now = Date.now()
    const node = fakeNode()
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = harness(sql, { node, custody, stuckMinutes: 60, now: () => now })
    const row = await queueWithdrawal(deps)

    await driveChain(deps.worker, 'ember', 'testnet')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'broadcast')

    now += 61 * 60_000
    await driveChain(deps.worker, 'ember', 'testnet')

    const stuck = await findOutbound(deps.sql, row.id)
    assert.equal(stuck?.state, 'stuck')
    assert.ok(stuck?.rawTx, 'the bytes stay on the row — they are the evidence any refund needs')

    const topics = (
      await sql<Array<{ topic: string }>>`select topic from outbox`
    ).map((e) => e.topic)
    assert.ok(topics.includes('settlement.outbound.stuck'), 'an operator must be paged')
    assert.ok(
      !topics.includes('settlement.outbound.failed'),
      'a stuck transaction must not emit anything that releases a reservation',
    )
    // And it stays stuck however many ticks run. Nothing in the worker moves a stuck row.
    await driveChain(deps.worker, 'ember', 'testnet')
    await driveChain(deps.worker, 'ember', 'testnet')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'stuck')
  })

  /**
   * The one automatic refund of a signed transaction, and the proof it rests on.
   *
   * A mined-and-reverted receipt is the chain itself saying the value did not move, so the money is
   * provably still in the treasury. It still goes through `resolveWithProof` and still writes an
   * adjudication row — the proof is stored whether a human or the chain produced it.
   */
  it('refunds automatically when the chain says the transaction reverted, and records the proof', async () => {
    const deps = funded()
    const row = await queueWithdrawal(deps)
    await driveChain(deps.worker, 'ember', 'testnet')
    deps.node.mine(deps.node.broadcast[0]!, { reverted: true })

    await driveChain(deps.worker, 'ember', 'testnet')

    const failed = await findOutbound(deps.sql, row.id)
    assert.equal(failed?.state, 'failed')
    const adjudications = await sql<Array<{ action: string; proof: string; actor: string }>>`
      select action, proof, actor from outbound_adjudications
    `
    assert.equal(adjudications.length, 1)
    assert.equal(adjudications[0]!.action, 'refund')
    assert.equal(adjudications[0]!.actor, 'system')
    assert.match(adjudications[0]!.proof, /did not deliver/)

    const event = (
      await sql<Array<{ topic: string; payload: Record<string, unknown> }>>`
        select topic, payload from outbox where topic = 'settlement.outbound.failed'
      `
    )[0]
    assert.equal(event?.payload['refundable'], true)
  })

  /* ------------------------------------------------------------------ serial per chain */

  it('walks past a retired row but stops at the first signature', async () => {
    const contract = testAddress(0xc0)
    const node = fakeNode({ contracts: [contract] })
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = harness(sql, { node, custody })

    // The head of the queue can never be built; the two behind it can. Without walking past a
    // retired row, a chain whose head is permanently broken clears one row per poll.
    await queueWithdrawal(deps, { to: contract, key: 'k-0' })
    await queueWithdrawal(deps, { key: 'k-1' })
    await queueWithdrawal(deps, { key: 'k-2' })

    const result = await driveChain(deps.worker, 'ember', 'testnet')

    assert.equal(result.retired.length, 1, 'the unbuildable head is retired within the same tick')
    assert.ok(result.signed, 'and the next row gets the chain immediately')
    assert.equal(deps.custody.signatures.length, 1, 'but only ONE signature per chain per tick')
  })
})
