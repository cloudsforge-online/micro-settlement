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
import { buildEnvelope } from './outbox.ts'
import { driveChain } from './worker.ts'
import {
  enabled,
  estateRecipient,
  fakeNode,
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
   * ════════════════════════════════════════════════════════════════════════════════════════════
   * **A CHAIN WITH NO TREASURY REFUSES AND REFUNDS. IT DOES NOT QUEUE THE USER'S MONEY.**
   *
   * This asserted the opposite until today: `NoTreasuryPinnedError` was allowed out of the inbox
   * transaction so the event stayed redeliverable, on the argument that an operator pinning a
   * treasury a minute later would get the withdrawal paid rather than refunded. Measured on the
   * mainnet estate, that argument cost three things:
   *
   *   * the user saw 201 `queued` and then nothing, with the balance reserved, for an hour — and
   *     wallet's deadline moves it to `stuck`, which is an operator page and NOT a refund;
   *   * this branch does not fire for a transient fault. Custody being down or a credential being
   *     wrong raises `CustodyUnavailableError` / `CustodySignRefusedError`, which still throw and
   *     are still redelivered. It fires only for "nobody ever provisioned this chain";
   *   * wallet's relay opens a circuit breaker per subscriber, so one unplannable withdrawal
   *     returning 500 on every redelivery — 1,315 attempts, `circuit open for
   *     subscriber:settlement:4000` — held the channel carrying EVERY wallet event to this service.
   *
   * `refundable: true` is a proof rather than an assumption here: nothing was planned, so nothing
   * was built, so nothing was signed, so nothing can be in a mempool.
   * ════════════════════════════════════════════════════════════════════════════════════════════
   */
  it('refuses and refunds when no treasury is pinned, rather than queueing for ever', async () => {
    const deps = harness(sql)
    const decision = await handleWithdrawalRequested(deps.withdrawals, {
      eventId: randomUUID(),
      payload: withdrawalPayload(),
      correlationId: 'r',
    })

    assert.equal(decision.kind, 'refused')
    const outbound = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(outbound[0]!.n, 0, 'no row that can never be built')

    // ACCEPTED, so the relay stops retrying and its circuit breaker closes.
    const inbox = await sql`select count(*)::int as n from inbox`
    assert.equal(inbox[0]!.n, 1)

    // The terminal event wallet refunds on. Same topic, same shape, same consumers as every other
    // failure — a refusal is not a new contract.
    const events = await sql<{ topic: string; key: string; payload: Record<string, unknown> }[]>`
      select topic, key, payload from outbox
    `
    assert.equal(events.length, 1)
    assert.equal(events[0]!.topic, 'settlement.outbound.failed')
    assert.equal(events[0]!.key, '11111111-1111-4111-8111-111111111111')
    assert.equal(events[0]!.payload['refundable'], true)
    // The field without which the event reaches nobody: `activity` and `notify` both resolve the
    // person from the payload, never from the key — which is also a uuid and would be wrong.
    assert.equal(events[0]!.payload['userId'], '22222222-2222-4222-8222-222222222222')
    assert.match(String(events[0]!.payload['reason']), /returned to your balance/)
  })

  it('refunds once however often the refusal is redelivered', async () => {
    const deps = harness(sql)
    const eventId = randomUUID()
    const payload = withdrawalPayload()
    const first = await handleWithdrawalRequested(deps.withdrawals, { eventId, payload, correlationId: 'r' })
    const again = await handleWithdrawalRequested(deps.withdrawals, { eventId, payload, correlationId: 'r' })

    assert.equal(first.kind, 'refused')
    // The inbox row and the emit share one transaction, so a redelivery cannot refund a second time.
    assert.equal(again.kind, 'duplicate')
    const events = await sql`select count(*)::int as n from outbox`
    assert.equal(events[0]!.n, 1)
  })

  /**
   * The transient half, and it must stay transient. A custody that cannot be reached is not a chain
   * with no treasury: the pin may well exist, and refunding on "we could not ask" would give money
   * back for a withdrawal that is about to be perfectly payable.
   */
  it('still redelivers when custody could not be asked', async () => {
    const deps = harness(sql)
    deps.custody.failTreasuryPin(new CustodyUnavailableError('custody is down'))
    await assert.rejects(
      handleWithdrawalRequested(deps.withdrawals, {
        eventId: randomUUID(),
        payload: withdrawalPayload(),
        correlationId: 'r',
      }),
      CustodyUnavailableError,
    )
    const inbox = await sql`select count(*)::int as n from inbox`
    const events = await sql`select count(*)::int as n from outbox`
    assert.equal(inbox[0]!.n, 0, 'the event must stay redeliverable')
    assert.equal(events[0]!.n, 0, 'and nothing may be refunded on a fault')
  })

  /**
   * ════════════════════════════════════════════════════════════════════════════════════════════
   * **A USER WHOSE WITHDRAWAL FAILS MUST BE REACHABLE, AND FOR THE LIFE OF THIS SERVICE NOBODY WAS.**
   *
   * `settlement.outbound.failed` is the ONLY event a failure produces — there is no
   * `settlement.withdrawal.failed`, and `wallet.withdrawal.refunded` is unregistered and fires only
   * on the refundable branch — and it went out as `{ withdrawalId, reason, refundable }`. Every
   * reader that turns an event into something a person sees resolves the person from the payload, so
   * the one event in this file whose subject is somebody's missing money named nobody at all.
   *
   * This runs the WHOLE path rather than the emitter: wallet's real event in, a real build failure,
   * the real outbox row, the relay's own `buildEnvelope`, a JSON round trip, and only then the
   * question — is the person whose money did not arrive reachable? Every earlier step is a place the
   * user id can be lost, and `handleWithdrawalRequested` writing it onto the row is one of them.
   *
   * The JSON round trip is load-bearing. A field assigned `undefined` is indistinguishable from an
   * absent one after it, which is exactly how "the payload has a userId" can be true in a test and
   * false on the wire.
   * ════════════════════════════════════════════════════════════════════════════════════════════
   */
  it('tells the person their withdrawal failed — from wallet\'s event to the wire', async () => {
    const payload = withdrawalPayload()
    const destination = String(payload['destination'])
    // Code at the destination: a permanent, refund-now refusal, and the shortest honest path from
    // an accepted request to a failed withdrawal.
    const node = fakeNode({ contracts: [destination] })
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const deps = harness(sql, { node })
    deps.custody.pin('ember', 'testnet', TREASURY)

    const decision = await handleWithdrawalRequested(deps.withdrawals, {
      eventId: randomUUID(),
      payload,
      correlationId: 'req-1',
    })
    assert.equal(decision.kind, 'planned')

    await driveChain(deps.worker, 'ember', 'testnet')
    const row = await findByIdempotencyKey(deps.sql, 'wallet:withdrawal:1')
    assert.equal(row?.state, 'failed', 'a destination with code at it is permanent, and refunds now')

    const rows = await sql<
      Array<{
        id: string
        topic: string
        key: string
        occurred_at: Date
        producer: string
        version: number
        actor: string | null
        correlation_id: string | null
        payload: Record<string, unknown>
      }>
    >`
      select id, topic, key, occurred_at, producer, version, actor, correlation_id, payload
        from outbox where topic = 'settlement.outbound.failed'
    `
    assert.equal(rows.length, 1, 'a failed withdrawal must produce exactly one terminal event')

    const delivered = JSON.parse(JSON.stringify(buildEnvelope(rows[0]!))) as {
      topic: string
      key: string
      actor: string
      payload: Record<string, unknown>
    }
    // **THE ASSERTION.** Not "the payload has a userId" — the restated readers of `activity` and
    // `notify`, run on the delivered bytes, hand back the person wallet said this money belonged to.
    assert.equal(
      estateRecipient(delivered),
      payload['userId'],
      'the user whose withdrawal failed is told nothing at all — this event reaches nobody',
    )
    // And they are told WHICH failure it was. Nothing was signed here, so the money is genuinely
    // coming back and a reader splitting on `refundable === true` says so.
    assert.equal(delivered.payload['refundable'], true)
    assert.equal(delivered.key, payload['withdrawalId'], 'keyed by the withdrawal, as the registry says')
    // The recipient came from the payload and could not have come from anywhere else: the actor is
    // the service, and the key is the withdrawal id.
    assert.equal(delivered.actor, 'service:settlement')
    assert.notEqual(payload['withdrawalId'], payload['userId'])
  })
})
