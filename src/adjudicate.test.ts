/**
 * Adjudicating a stuck transaction.
 *
 * The property under test is a negative one, and it is the most expensive negative in the estate:
 * **a stuck transaction is not refunded unless the chain positively asserts the bytes are dead.**
 * Every refusal path below would, if it returned `ok`, pay a user twice for a payment that then
 * landed — and that is the one mistake this service cannot undo.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { adjudicate } from './adjudicate.ts'
import { findOutbound, planOutbound, type OutboundTransaction } from './outbound.ts'
import { driveChain } from './worker.ts'
import { legacyNonce } from './evm.ts'
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

describe('adjudicating a stuck transaction', { skip }, () => {
  let sql: postgres.Sql
  const TREASURY = testAddress(0x7)
  const ALICE = testAddress(0xa1)
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

  /** Drive a withdrawal all the way to `stuck`: signed, broadcast, and never seen again. */
  async function stuckWithdrawal(): Promise<{
    readonly deps: ReturnType<typeof harness>
    readonly row: OutboundTransaction
    readonly node: ReturnType<typeof fakeNode>
    advanceClock(minutes: number): void
  }> {
    let now = Date.now()
    const node = fakeNode()
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = harness(sql, { node, custody, stuckMinutes: 60, now: () => now })

    await planOutbound(deps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 17n,
      fee: TEST_FEE,
      idempotencyKey: 'wallet:withdrawal:1',
      sourceRef: 'withdrawal-1',
      userId: 'user-1',
    })
    await driveChain(deps.worker, 'ember', 'testnet')
    now += 61 * 60_000
    await driveChain(deps.worker, 'ember', 'testnet')
    const rows = await sql<Array<{ id: string }>>`select id from outbound_transactions`
    const row = (await findOutbound(deps.sql, rows[0]!.id))!
    assert.equal(row.state, 'stuck')
    return { deps, row, node, advanceClock: (minutes) => (now += minutes * 60_000) }
  }

  /**
   * **NO RECEIPT IS NOT NO TRANSACTION.**
   *
   * The node has never heard of the hash — which is exactly the state a stuck transaction is in —
   * and the account's nonce has NOT moved past the one in the bytes. Any node still holding them
   * can mine them months from now. This is the case the frozen code got wrong: its whole safety was
   * "does a node have a receipt", and the answer here is no, and refunding on it pays twice.
   */
  it('refuses to refund while the nonce in the bytes is still unconsumed', async () => {
    const { deps, row } = await stuckWithdrawal()

    const outcome = await adjudicate(deps.adjudication, {
      id: row.id,
      action: 'refund',
      actor: OPERATOR,
      correlationId: 'req-1',
    })

    assert.equal(outcome.kind, 'refused')
    assert.equal(outcome.kind === 'refused' && outcome.code, 'still_applicable')
    assert.match(
      outcome.kind === 'refused' ? outcome.reason : '',
      /Retire the nonce first/,
      'the refusal must tell the operator what to do next, not merely say no',
    )
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'stuck')
    // Refusals are recorded too. The record that somebody tried is as much a part of the audit as
    // the record that somebody succeeded.
    const audit = await sql<Array<{ action: string; refusal_code: string; actor: string }>>`
      select action, refusal_code, actor from outbound_adjudications
    `
    assert.equal(audit.length, 1)
    assert.deepEqual(
      { action: audit[0]!.action, code: audit[0]!.refusal_code, actor: audit[0]!.actor },
      { action: 'refused', code: 'still_applicable', actor: OPERATOR },
    )
  })

  /**
   * The positive proof, and the only thing that unlocks a refund.
   *
   * The account's nonce has moved past the one inside the bytes, which means another transaction
   * took that slot and these bytes can never be mined. Read at `latest` and never at `pending`: a
   * pending count includes this node's own mempool, and "somebody is holding something at that
   * nonce" is the opposite of proof.
   */
  it('refunds once the nonce has been consumed by something else, and stores the proof', async () => {
    const { deps, row, node } = await stuckWithdrawal()
    assert.equal(legacyNonce(row.rawTx!), 0n)
    node.setNonce(TREASURY, 1)

    const outcome = await adjudicate(deps.adjudication, {
      id: row.id,
      action: 'refund',
      actor: OPERATOR,
      correlationId: 'req-2',
    })

    assert.equal(outcome.kind, 'resolved')
    assert.match(outcome.kind === 'resolved' ? outcome.proof : '', /the slot was taken by another transaction/)
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'failed')

    const audit = await sql<Array<{ action: string; proof: string; actor: string }>>`
      select action, proof, actor from outbound_adjudications where action = 'refund'
    `
    assert.equal(audit.length, 1)
    assert.equal(audit[0]!.actor, OPERATOR)
    assert.match(audit[0]!.proof, /no node has a receipt/)

    const event = (
      await sql<Array<{ payload: Record<string, unknown> }>>`
        select payload from outbox where topic = 'settlement.outbound.failed'
      `
    )[0]
    assert.equal(event?.payload['refundable'], true)
    assert.equal(event?.payload['withdrawalId'], 'withdrawal-1')
  })

  /** A transaction the chain still has cannot be refunded on any grounds. */
  it('refuses to refund a transaction that is on chain', async () => {
    const { deps, row, node } = await stuckWithdrawal()
    node.mine(row.rawTx!)
    node.setNonce(TREASURY, 1)

    const outcome = await adjudicate(deps.adjudication, {
      id: row.id,
      action: 'refund',
      actor: OPERATOR,
      correlationId: 'req-3',
    })

    assert.equal(outcome.kind === 'refused' && outcome.code, 'on_chain')
    assert.match(outcome.kind === 'refused' ? outcome.reason : '', /it settles itself/)
  })

  /**
   * **An unreachable node is a refusal, never a refund.**
   *
   * It is the state in which the least is known about where the payment got to, and "we could not
   * ask" is the weakest possible basis for giving a user money that may also be leaving on chain.
   */
  it('refuses when the chain cannot be asked at all', async () => {
    const { deps, row, node } = await stuckWithdrawal()
    node.setUnreachable(true)

    const outcome = await adjudicate(deps.adjudication, {
      id: row.id,
      action: 'refund',
      actor: OPERATOR,
      correlationId: 'req-4',
    })

    assert.equal(outcome.kind === 'refused' && outcome.code, 'unprovable')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'stuck')
  })

  /** The other half: a stuck transaction that actually landed. Proof of presence, not of absence. */
  it('confirms a stuck transaction the chain has at depth', async () => {
    const { deps, row, node } = await stuckWithdrawal()
    node.mine(row.rawTx!)
    node.advance(100)

    const outcome = await adjudicate(deps.adjudication, {
      id: row.id,
      action: 'confirm',
      actor: OPERATOR,
      correlationId: 'req-5',
    })

    assert.equal(outcome.kind, 'resolved')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'confirmed')
    const topics = (await sql<Array<{ topic: string }>>`select topic from outbox`).map((e) => e.topic)
    assert.ok(topics.includes('settlement.outbound.confirmed'))
  })

  it('refuses to confirm one the chain does not have at depth', async () => {
    const { deps, row, node } = await stuckWithdrawal()
    node.mine(row.rawTx!)
    // Mined but shallow. An operator who believes it landed and finds this refused is an operator
    // looking at the right hash.
    node.advance(2)

    const outcome = await adjudicate(deps.adjudication, {
      id: row.id,
      action: 'confirm',
      actor: OPERATOR,
      correlationId: 'req-6',
    })
    assert.equal(outcome.kind === 'refused' && outcome.code, 'unprovable')
    assert.equal((await findOutbound(deps.sql, row.id))?.state, 'stuck')
  })

  /**
   * Only a stuck transaction is adjudicated.
   *
   * A live `signed` row has not yet had its full deadline to land, and letting an operator refund
   * one would put the most dangerous action in the system one request away from an ordinary payment
   * that was merely taking a while.
   */
  it('refuses to adjudicate a transaction that is still being driven', async () => {
    const node = fakeNode()
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = harness(sql, { node, custody })
    const { outbound } = await planOutbound(deps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 17n,
      fee: TEST_FEE,
      idempotencyKey: 'k',
      sourceRef: 'withdrawal-1',
    })
    await driveChain(deps.worker, 'ember', 'testnet')

    const outcome = await adjudicate(deps.adjudication, {
      id: outbound.id,
      action: 'refund',
      actor: OPERATOR,
      correlationId: 'req-7',
    })
    assert.equal(outcome.kind, 'not_stuck')
    assert.equal((await findOutbound(deps.sql, outbound.id))?.state, 'broadcast')
  })

  it('is a not_found rather than a 500 for an id that does not exist', async () => {
    const deps = harness(sql)
    const outcome = await adjudicate(deps.adjudication, {
      id: '00000000-0000-4000-8000-000000000000',
      action: 'refund',
      actor: OPERATOR,
      correlationId: 'req-8',
    })
    assert.equal(outcome.kind, 'not_found')
  })
})
