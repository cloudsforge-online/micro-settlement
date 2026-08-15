/**
 * Funding a per-order deployer.
 *
 * Four properties, and three of them are about NOT sending money:
 *
 *   1. **A refusal is accepted, never thrown.** Every branch that cannot fund returns a decision.
 *      A throw here 500s the delivery, and wallet's relay opens a per-subscriber circuit breaker on
 *      one repeatedly-failing event — so one unfundable order would stop every event reaching this
 *      service, including withdrawals.
 *   2. **An amount over the cap is refused, not truncated.** Half a top-up funds nothing and costs
 *      a fee to deliver money that then needs sweeping back.
 *   3. **One ask is one transfer.** A redelivery is a duplicate; a genuinely new ask is a new
 *      attempt number and therefore a new key.
 *   4. And the happy path plans exactly one `gas_topup` from the treasury to the deployer.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import {
  handleDeployFundingRequested,
  parseDeployFundingRequested,
} from './deployerfunding.ts'
import { MalformedEventError } from './withdrawals.ts'
import { findOutbound, planOutbound } from './outbound.ts'
import {
  TEST_FEE,
  enabled,
  harness,
  migrateTestDb,
  openDb,
  resetSettlement,
  skip,
  testAddress,
} from './testsupport.ts'

const TOKEN = '33333333-3333-4333-8333-333333333333'
const TREASURY = testAddress(0x7)
const DEPLOYER = testAddress(0xde)

/** The inbox keys on `(topic, event_id)` and the column is a uuid, so these have to be well formed. */
function eventId(n: number): string {
  return `44444444-4444-4444-8444-${n.toString().padStart(12, '0')}`
}

/** A well-formed `mint.deploy.funding_requested` payload, as `fundingRequestedPayload` writes it. */
function fundingPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    tokenId: TOKEN,
    chain: 'ember',
    network: 'testnet',
    deployerAddress: DEPLOYER,
    requiredWei: '10000000000000000',
    balanceWei: '0',
    // required × 1.5, less the balance. Deliberately NOT `required - balance`; see the field's
    // documentation in `deployerfunding.ts`.
    amountWei: '15000000000000000',
    attempt: 1,
    ...overrides,
  }
}

describe('reading a deployer funding request', () => {
  it('accepts a well-formed payload', () => {
    const parsed = parseDeployFundingRequested(fundingPayload())
    assert.equal(parsed.chain, 'ember')
    assert.equal(parsed.network, 'testnet')
    assert.equal(parsed.amount, 15_000_000_000_000_000n)
    assert.equal(parsed.attempt, 1)
  })

  it('refuses an amount that is not a decimal string', () => {
    // A JSON NUMBER is refused, not coerced: 1.5e16 is already past 2^53 by the time it lands here
    // only for larger asks, but the rounding is invisible in both directions and this is the value
    // the treasury pays out verbatim.
    assert.throws(
      () => parseDeployFundingRequested(fundingPayload({ amountWei: 15000000000000000 })),
      MalformedEventError,
    )
    assert.throws(
      () => parseDeployFundingRequested(fundingPayload({ requiredWei: '0x10' })),
      MalformedEventError,
    )
    assert.throws(
      () => parseDeployFundingRequested(fundingPayload({ balanceWei: '-1' })),
      MalformedEventError,
    )
  })

  it('refuses a chain or a network it cannot settle', () => {
    assert.throws(() => parseDeployFundingRequested(fundingPayload({ chain: 'hearth' })), /is not one/)
    assert.throws(() => parseDeployFundingRequested(fundingPayload({ network: 'devnet' })), /mainnet or testnet/)
  })

  it('refuses an attempt that is not a positive integer', () => {
    // The attempt is half the idempotency key. An unreadable one would collapse every ask for a
    // token onto one key, so mint's second, larger ask would come back as a duplicate of the first
    // and the order would wait for money nobody sent.
    for (const attempt of ['1', 0, -1, 1.5, null, undefined]) {
      assert.throws(
        () => parseDeployFundingRequested(fundingPayload({ attempt })),
        MalformedEventError,
        `attempt ${String(attempt)} must be refused`,
      )
    }
  })
})

describe('funding a per-order deployer', { skip }, () => {
  let sql: postgres.Sql

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

  function funded(options: Parameters<typeof harness>[1] = {}) {
    const deps = harness(sql, options)
    deps.custody.pin('ember', 'testnet', TREASURY)
    return deps
  }

  it('plans one gas_topup from the treasury to the deployer', async () => {
    const deps = funded()

    const decision = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })

    assert.equal(decision.kind, 'planned')
    const row = await findOutbound(deps.sql, decision.kind === 'planned' ? decision.outboundId : '')
    assert.equal(row?.purpose, 'gas_topup')
    assert.equal(row?.fromAddress, TREASURY)
    assert.equal(row?.toAddress, DEPLOYER)
    assert.equal(row?.assetCode, 'EMBER')
    // Sent verbatim. This service has no gas estimate for a creation it is not building, so it
    // cannot second-guess the figure — including the headroom mint deliberately added.
    assert.equal(row?.amount, 15_000_000_000_000_000n)
    // The fee is what THIS transfer costs, priced here against the node. Not mint's number, which
    // was for a contract creation from a different address.
    assert.equal(row?.fee, TEST_FEE)
    assert.equal(row?.state, 'planned')
    // `source_ref` names a row in mint's database, so there is no foreign key. It is what the
    // per-token bound counts and what an operator greps when an order is stuck.
    assert.equal(row?.sourceRef, TOKEN)
    assert.equal(row?.idempotencyKey, `settlement:deployerfund:${TOKEN}:1`)
    // Nobody's balance moved and no reservation is held: this is the platform paying for its own
    // deploy, not a withdrawal.
    assert.equal(row?.userId, null)
    assert.equal(row?.reservationEntryId, null)
  })

  it('answers a redelivery with the same transfer, not a second one', async () => {
    const deps = funded()
    const first = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })
    assert.equal(first.kind, 'planned')

    // The inbox catches this one: same topic, same event id.
    const again = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })
    assert.equal(again.kind, 'duplicate')

    // And a DIFFERENT event naming the same ask is caught by the idempotency key instead. The two
    // dedupes catch different things and both are needed: mint re-emitting after a crash produces
    // a new event id for an attempt that has already been paid.
    const reemitted = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(2),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })
    assert.equal(reemitted.kind, 'duplicate')

    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 1)
  })

  it('treats a second attempt as a second transfer', async () => {
    // mint only raises the attempt when it is asking again after its cooldown, for an order still
    // short of gas. Folding that onto the first key would leave the order waiting forever.
    const deps = funded()
    await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })
    const second = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(2),
      payload: fundingPayload({ attempt: 2, amountWei: '20000000000000000' }),
      correlationId: 'corr-1',
    })

    assert.equal(second.kind, 'planned')
    const row = await findOutbound(deps.sql, second.kind === 'planned' ? second.outboundId : '')
    assert.equal(row?.idempotencyKey, `settlement:deployerfund:${TOKEN}:2`)
  })

  it('ignores an order belonging to the other network', async () => {
    // Ignored and not refused: the row it names is in a database this process cannot see, and the
    // other deployment is the one that will fund it.
    const deps = funded()
    const decision = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload({ network: 'mainnet' }),
      correlationId: 'corr-1',
    })

    assert.deepEqual(decision, { kind: 'ignored', reason: 'other_network' })
    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 0)
  })

  it('refuses an amount over the cap rather than sending part of it', async () => {
    // mint prices the ask against the same node, so on a healthy chain this is a fraction of a
    // coin. The cap is here because that price is an RPC answer: a node quoting a nonsense gas
    // price would otherwise move an arbitrary amount of treasury out on mint's say-so.
    const deps = funded({ deployerTopUpMaxWei: 10n ** 16n })
    const decision = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })

    assert.deepEqual(decision, { kind: 'refused', reason: 'amount_over_cap' })
    // **Nothing partial.** A truncated top-up still cannot pay for the deploy, and it has spent a
    // fee to strand money in an address that now needs sweeping.
    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 0)
  })

  it('refuses an amount that is not positive', async () => {
    const deps = funded()
    assert.deepEqual(
      await handleDeployFundingRequested(deps.deployerFunding, {
        eventId: eventId(1),
        payload: fundingPayload({ amountWei: '0' }),
        correlationId: 'corr-1',
      }),
      { kind: 'refused', reason: 'amount_not_positive' },
    )
  })

  it('stops paying for one token once its allowance is spent', async () => {
    const deps = funded({ deployerTopUpMaxPerToken: 1 })
    const first = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })
    assert.equal(first.kind, 'planned')

    // A genuinely new ask, which the idempotency key would happily let through. This bound is the
    // one that stops it: mint bounds how often it ASKS, out of its own database, and this bounds
    // how often the treasury PAYS, counted over rows this service wrote. A bug on either side of
    // the wire is contained by the other.
    const second = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(2),
      payload: fundingPayload({ attempt: 2 }),
      correlationId: 'corr-1',
    })
    assert.deepEqual(second, { kind: 'refused', reason: 'topup_limit_reached' })

    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 1)
  })

  it('does not count a top-up that failed against the allowance', async () => {
    // A rejected transaction moved nothing: the money is still in the treasury and the order still
    // cannot deploy. Counting it would spend a token's whole allowance on transfers that never
    // landed, and the order would then need a human.
    const deps = funded({ deployerTopUpMaxPerToken: 1 })
    const dead = await planOutbound(deps.sql, {
      purpose: 'gas_topup',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: DEPLOYER,
      assetCode: 'EMBER',
      amount: 10n ** 16n,
      fee: TEST_FEE,
      idempotencyKey: `settlement:deployerfund:${TOKEN}:1`,
      sourceRef: TOKEN,
    })
    await sql`update outbound_transactions set state = 'failed', failure_reason = 'test' where id = ${dead.outbound.id}`

    const decision = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(2),
      payload: fundingPayload({ attempt: 2 }),
      correlationId: 'corr-1',
    })
    assert.equal(decision.kind, 'planned')
  })

  it('counts a top-up that is still only planned', async () => {
    // Committed-but-unsigned money is still committed. A burst of redeliveries must not plan five
    // transfers before the first one broadcasts.
    const deps = funded({ deployerTopUpMaxPerToken: 2 })
    await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })
    await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(2),
      payload: fundingPayload({ attempt: 2 }),
      correlationId: 'corr-1',
    })

    const third = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(3),
      payload: fundingPayload({ attempt: 3 }),
      correlationId: 'corr-1',
    })
    assert.deepEqual(third, { kind: 'refused', reason: 'topup_limit_reached' })
  })

  it('accepts a chain nobody has pinned a treasury for, rather than throwing', async () => {
    // The one that would otherwise 500 on every redelivery until an operator provisions the chain,
    // and take the whole event channel with it. mint keeps the order at `awaiting_funds` — where
    // it would be anyway — and asks again after its cooldown.
    const deps = harness(sql)
    const decision = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload(),
      correlationId: 'corr-1',
    })

    assert.deepEqual(decision, { kind: 'refused', reason: 'no_treasury' })
  })

  it('accepts a chain this service cannot move a coin on', async () => {
    const deps = funded()
    const decision = await handleDeployFundingRequested(deps.deployerFunding, {
      eventId: eventId(1),
      payload: fundingPayload({ chain: 'xrp', deployerAddress: 'rAlice1111111111111111111111' }),
      correlationId: 'corr-1',
    })

    assert.deepEqual(decision, { kind: 'refused', reason: 'no_adapter:xrp' })
  })
})
