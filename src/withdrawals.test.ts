/**
 * The event in, and what a build failure means.
 *
 * The classification table is pure and is tested without a database, because it is the policy that
 * decides whether a user's money goes back now, in an hour, or not at all — and a policy that can
 * only be exercised against a live chain is a policy nobody exercises.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import { randomUUID } from 'node:crypto'
import type postgres from 'postgres'
import {
  AddressError,
  FeeOutOfBandError,
  InsufficientTreasuryError,
  NotImplementedError,
  UnsupportedDestinationError,
} from './chains.ts'
import { NoEndpointError } from './registry.ts'
import { CustodySignRefusedError, CustodyUnavailableError } from './custodyclient.ts'
import { NoTreasuryPinnedError, TreasuryDisagreementError } from './treasury.ts'
import {
  MalformedEventError,
  handleWithdrawalRequested,
  parseWithdrawalRequested,
  planBuildFailure,
} from './withdrawals.ts'
import { findByIdempotencyKey } from './outbound.ts'
import {
  enabled,
  harness,
  migrateTestDb,
  openDb,
  resetSettlement,
  skip,
  testAddress,
  withdrawalPayload,
} from './testsupport.ts'

describe('reading a withdrawal request', () => {
  it('accepts a well-formed payload', () => {
    const parsed = parseWithdrawalRequested(withdrawalPayload())
    assert.equal(parsed.chain, 'ember')
    assert.equal(parsed.assetCode, 'EMBER')
    assert.equal(parsed.net + parsed.fee, parsed.amount)
  })

  it('refuses an amount that is not a decimal string', () => {
    // A JSON NUMBER is refused, not coerced. One EMBER is 1e18 and a number that far past 2^53 has
    // already been rounded by the time it gets here — silently, and in a direction nobody chose.
    assert.throws(
      () => parseWithdrawalRequested(withdrawalPayload({ net: 500000000000000000 })),
      MalformedEventError,
    )
    assert.throws(
      () => parseWithdrawalRequested(withdrawalPayload({ fee: '0x10' })),
      MalformedEventError,
    )
  })

  it("restates wallet's own arithmetic rather than trusting it", () => {
    // net + fee must equal amount. A disagreement is either a bug upstream or a forged event, and
    // both are things this service must refuse rather than build a payment out of.
    assert.throws(
      () => parseWithdrawalRequested(withdrawalPayload({ fee: '1' })),
      /is not amount/,
    )
    assert.throws(() => parseWithdrawalRequested(withdrawalPayload({ net: '0', amount: '1', fee: '1' })), /positive/)
  })

  it('refuses an asset that does not settle on the named chain', () => {
    assert.throws(
      () => parseWithdrawalRequested(withdrawalPayload({ assetCode: 'ETH' })),
      /does not settle on ember/,
    )
    assert.throws(() => parseWithdrawalRequested(withdrawalPayload({ chain: 'doge' })), MalformedEventError)
  })
})

describe('classifying a build failure', () => {
  /**
   * The split that matters: immediate versus bounded, and it is decided by whether the cause can
   * change on its own. Everything on the `at-deadline` side is retried and then given up on with a
   * refund; nothing anywhere falls through with no exit, which is the defect this table replaces.
   */
  const immediate = [
    new NotImplementedError('btc', 'phase 8', 'building', 'no output policy'),
    new UnsupportedDestinationError('ember', testAddress(0xc0)),
    new AddressError('address fails its EIP-55 checksum'),
    new FeeOutOfBandError('ember', 'above', 1n, 0n),
    new CustodySignRefusedError(403, 'binding_mismatch', 'sign request does not match this address'),
    new CustodySignRefusedError(403, 'purpose_forbidden', 'this address carries a purpose'),
    new CustodySignRefusedError(403, 'shape_refused', '`data` must be empty on a value transfer'),
    new MalformedEventError('net must be positive'),
  ]
  const bounded = [
    new InsufficientTreasuryError('ember', 1n, 2n),
    new NoTreasuryPinnedError('ember', 'testnet'),
    new TreasuryDisagreementError('ember', 'testnet', 'a', 'b'),
    new NoEndpointError('ember'),
    new CustodySignRefusedError(403, 'no_treasury_pinned', 'no treasury is pinned'),
    new CustodyUnavailableError('socket hang up'),
    new Error('something nobody has seen before'),
  ]

  it('refunds a permanent refusal immediately', () => {
    for (const err of immediate) {
      assert.equal(planBuildFailure(err).refund, 'now', `${err.name} should refund immediately`)
    }
  })

  it('bounds a plausibly-transient failure with the stuck deadline', () => {
    for (const err of bounded) {
      assert.equal(planBuildFailure(err).refund, 'at-deadline', `${err.name} should be retried`)
    }
  })

  /**
   * The one that must not be got wrong.
   *
   * `CustodyUnavailableError` means "we do not know whether custody signed". It is NOT a refusal,
   * and treating it as one would refund a withdrawal whose signature may exist. It is still safe to
   * refund at the deadline, because nothing was COMMITTED — bytes that were never committed are
   * unbroadcast and unrecoverable by anyone including us — but it must not be immediate.
   */
  it('never treats an unreachable custody as a refusal', () => {
    const plan = planBuildFailure(new CustodyUnavailableError('socket hang up'))
    assert.equal(plan.refund, 'at-deadline')
    assert.match(plan.message, /custody could not be reached/)
  })

  it('gives a user-facing reason only where the user can act on it', () => {
    const destination = planBuildFailure(new UnsupportedDestinationError('ember', testAddress(0xc0)))
    assert.equal(destination.classification, 'destination')
    assert.match(destination.reason, /Withdraw to an address you hold the key to/)
    // A signer refusal is a platform fact and the user is told nothing about it.
    const refused = planBuildFailure(new CustodySignRefusedError(403, 'binding_mismatch', 'no'))
    assert.match(refused.reason, /could not be signed/)
    assert.doesNotMatch(refused.reason, /binding/)
  })
})

describe('taking wallet.withdrawal.requested', { skip }, () => {
  let sql: postgres.Sql
  const TREASURY = testAddress(0x7)

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

  function pinned() {
    const deps = harness(sql)
    deps.custody.pin('ember', 'testnet', TREASURY)
    return deps
  }

  it('plans one outbound transaction against the pinned treasury', async () => {
    const deps = pinned()
    const decision = await handleWithdrawalRequested(deps.withdrawals, {
      eventId: randomUUID(),
      payload: withdrawalPayload(),
      correlationId: 'req-1',
    })
    assert.equal(decision.kind, 'planned')

    const row = await findByIdempotencyKey(deps.sql, 'wallet:withdrawal:1')
    assert.equal(row?.state, 'planned')
    assert.equal(row?.purpose, 'withdrawal')
    assert.equal(row?.fromAddress, TREASURY, 'the source is resolved at planning time, not at build time')
    // `amount` on the row is what the DESTINATION receives — wallet's `net`. The user's `amount` is
    // wallet's number and stays wallet's; a second copy here would be a total this service does not
    // own.
    assert.equal(row?.amount, 5n * 10n ** 17n)
    assert.equal(row?.reservationEntryId, 'entry-1')
  })

  /**
   * **The headline idempotency requirement, and it needs both halves.**
   *
   * The same event id twice is a REDELIVERY and the inbox catches it. Two different event ids
   * naming the same withdrawal is a wallet retry after a lost response, and only the unique
   * constraint on `idempotency_key` catches that. Either alone leaves a hole.
   */
  it('produces one outbound transaction however the request is duplicated', async () => {
    const deps = pinned()
    const eventId = randomUUID()
    const payload = withdrawalPayload()

    const first = await handleWithdrawalRequested(deps.withdrawals, { eventId, payload, correlationId: 'r1' })
    // The same event, redelivered by the relay.
    const redelivered = await handleWithdrawalRequested(deps.withdrawals, { eventId, payload, correlationId: 'r1' })
    // A DIFFERENT event carrying the same withdrawal — a wallet retry, which the inbox cannot see.
    const retried = await handleWithdrawalRequested(deps.withdrawals, {
      eventId: randomUUID(),
      payload,
      correlationId: 'r2',
    })

    assert.equal(first.kind, 'planned')
    assert.equal(redelivered.kind, 'duplicate')
    assert.equal(retried.kind, 'duplicate')
    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 1)
  })

  it('ignores a withdrawal for a network this deployment does not settle', async () => {
    const deps = pinned()
    const decision = await handleWithdrawalRequested(deps.withdrawals, {
      eventId: randomUUID(),
      payload: withdrawalPayload({ network: 'mainnet' }),
      correlationId: 'r',
    })
    // Ignored rather than failed: failing it would release a reservation in a wallet that is not
    // this deployment's either.
    assert.deepEqual(decision, { kind: 'ignored', reason: 'other_network' })
    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 0)
  })

  /**
   * A chain with no pinned treasury must NOT leave a planned row.
   *
   * The throw happens inside the inbox transaction, so the event is not marked received and the
   * relay redelivers it once an operator has provisioned one. A planned row on a chain that cannot
   * pay it is a withdrawal that quietly refunds itself at the stuck deadline instead.
   */
  it('refuses the event outright when no treasury is pinned, leaving nothing behind', async () => {
    const deps = harness(sql)
    await assert.rejects(
      handleWithdrawalRequested(deps.withdrawals, {
        eventId: randomUUID(),
        payload: withdrawalPayload(),
        correlationId: 'r',
      }),
      NoTreasuryPinnedError,
    )
    const outbound = await sql`select count(*)::int as n from outbound_transactions`
    const inbox = await sql`select count(*)::int as n from inbox`
    assert.equal(outbound[0]!.n, 0)
    assert.equal(inbox[0]!.n, 0, 'the event must stay redeliverable')
  })
})
