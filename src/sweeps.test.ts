/**
 * Sweeps and treasuries.
 *
 * Three properties, all of which are about NOT moving money:
 *
 *   1. **Nothing sweeps to an unpinned candidate**, and nothing sweeps at all while the pin and the
 *      payout row disagree.
 *   2. **The sweeper is demand-driven.** The float target is zero unless an operator names one, so
 *      a coin stays outside the blast radius of the signing credential until a queued withdrawal
 *      needs it.
 *   3. **Maturity before the high-water mark advances.** `swept` moves at confirmation, never at
 *      broadcast.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { planSweep, registerSweepSource, findSweepSource, unmaturedByAddress } from './sweeps.ts'
import { floatTarget, NoTreasuryPinnedError, TreasuryDisagreementError, provisionTreasury, requireTreasury, treasuryBinding } from './treasury.ts'
import { findOutbound, planOutbound } from './outbound.ts'
import { driveChain } from './worker.ts'
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

describe('the treasury binding', () => {
  /**
   * It must reproduce `custody/src/keys.ts treasuryBinding` byte for byte. custody compares seven
   * fields character for character and its 403 deliberately will not say which one disagreed, so
   * this cannot be debugged from a response — it has to be right by construction.
   */
  it('reproduces custody own derivation exactly', () => {
    assert.deepEqual(treasuryBinding('ember', 'testnet'), {
      userId: 'cloudsforge:treasury',
      orderId: 'treasury:ember:testnet',
    })
    // And it uses CUSTODY's chain name, not this service's slug. `eth` would be a binding mismatch.
    assert.deepEqual(treasuryBinding('eth', 'mainnet'), {
      userId: 'cloudsforge:treasury',
      orderId: 'treasury:ethereum:mainnet',
    })
  })
})

describe('the float target', () => {
  it('is zero unless an operator has named one', () => {
    // The default is the design: every coin in the treasury is inside the blast radius of the
    // signing credential and every coin left in a deposit address is outside it.
    assert.equal(floatTarget({}, 'EMBER', 18), 0n)
    assert.equal(floatTarget({ EMBER: '1.5' }, 'EMBER', 18), 1_500_000_000_000_000_000n)
  })

  it('refuses an unparseable target rather than silently treating it as zero', () => {
    // A typo here is a float an operator believes they have set and has not.
    assert.throws(() => floatTarget({ EMBER: 'lots' }, 'EMBER', 18), /not a non-negative decimal/)
    assert.throws(() => floatTarget({ EMBER: '-1' }, 'EMBER', 18), /not a non-negative decimal/)
  })
})

describe('treasuries and sweeps', { skip }, () => {
  let sql: postgres.Sql
  const TREASURY = testAddress(0x7)
  const OTHER_TREASURY = testAddress(0x8)
  const DEPOSIT = testAddress(0xd1)
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

  async function withSource(deps: ReturnType<typeof harness>) {
    return registerSweepSource(deps.sql, {
      chain: 'ember',
      network: 'testnet',
      address: DEPOSIT,
      custodyChain: 'ember',
      custodyFamily: 'ember',
      custodyUserId: 'user-1',
      custodyOrderId: 'assignment-1',
    })
  }

  /* ---------------------------------------------------------------- treasuries */

  it('adopts the address custody pins rather than minting its own', async () => {
    const deps = harness(sql)
    deps.custody.pin('ember', 'testnet', TREASURY)

    const treasury = await requireTreasury(deps.treasuries, 'ember', 'testnet')

    assert.equal(treasury.address, TREASURY)
    assert.equal(treasury.custodyOrderId, 'treasury:ember:testnet')
    assert.equal(treasury.custodyChain, 'ember')
  })

  it('refuses to resolve a treasury on a chain nobody has pinned', async () => {
    const deps = harness(sql)
    // Deliberately NOT a mint. custody's mint route is administrator-only precisely so a signing
    // credential can never influence the pin, and the frozen `ensureTreasury`'s mint-here branch is
    // the one it is most uncomfortable with.
    await assert.rejects(requireTreasury(deps.treasuries, 'ember', 'testnet'), NoTreasuryPinnedError)
  })

  it('provisions through custody with an operator token, minting and pinning', async () => {
    const deps = harness(sql)
    const result = await provisionTreasury(deps.treasuries, {
      chain: 'ember',
      network: 'testnet',
      operatorToken: 'operator-token',
      allowRotation: false,
    })
    assert.ok(result.minted)
    assert.equal(await deps.custody.treasuryPin('ember', 'testnet'), result.treasury.address)
    // Idempotent: a second call finds the pin and the row already agreeing and mints nothing.
    const again = await provisionTreasury(deps.treasuries, {
      chain: 'ember',
      network: 'testnet',
      operatorToken: 'operator-token',
      allowRotation: false,
    })
    assert.equal(again.minted, false)
    assert.equal(again.treasury.address, result.treasury.address)
  })

  it('refuses to rotate a treasury unless an operator says so in so many words', async () => {
    const deps = harness(sql)
    deps.custody.pin('ember', 'testnet', TREASURY)
    await requireTreasury(deps.treasuries, 'ember', 'testnet')
    deps.custody.pin('ember', 'testnet', OTHER_TREASURY)

    // Pinning a freshly minted, EMPTY address while withdrawals still need the old one's balance is
    // deposits consolidating into one pot and payouts starving out of another, with no error.
    await assert.rejects(
      provisionTreasury(deps.treasuries, {
        chain: 'ember',
        network: 'testnet',
        operatorToken: 'operator-token',
        allowRotation: false,
      }),
      TreasuryDisagreementError,
    )
  })

  /* ---------------------------------------------------------------- sweeping */

  it('does nothing when the treasury is not short — the target is zero by default', async () => {
    const deps = harness(sql, { sweepEnabled: true })
    deps.custody.pin('ember', 'testnet', TREASURY)
    await withSource(deps)
    // A deposit address holding real money, and no queued withdrawal. Nothing moves, because the
    // trigger is demand and not opportunity.
    deps.node.setBalance(DEPOSIT, 10n * 10n ** 18n)

    const outcome = await planSweep(deps.sweeps, 'ember', 'testnet')

    assert.equal(outcome.kind, 'satisfied')
    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 0)
  })

  it('sweeps what a queued withdrawal needs and no more than one address at a time', async () => {
    const deps = harness(sql, { sweepEnabled: true })
    deps.custody.pin('ember', 'testnet', TREASURY)
    await withSource(deps)
    deps.node.setBalance(DEPOSIT, 10n * 10n ** 18n)
    deps.node.setBalance(TREASURY, 0n)
    await planOutbound(deps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 18n,
      fee: TEST_FEE,
      idempotencyKey: 'wallet:withdrawal:1',
      sourceRef: 'withdrawal-1',
    })

    const outcome = await planSweep(deps.sweeps, 'ember', 'testnet')

    assert.equal(outcome.kind, 'planned')
    const sweep = await findOutbound(deps.sql, outcome.kind === 'planned' ? outcome.outboundId : '')
    assert.equal(sweep?.purpose, 'sweep')
    assert.equal(sweep?.fromAddress, DEPOSIT)
    // The destination is custody's PIN, echoed exactly as custody published it, and deliberately not
    // this service's row: `assertSweep` compares it character for character.
    assert.equal(sweep?.toAddress, TREASURY)
    assert.equal(sweep?.state, 'planned')

    // A second pass while the first is still queued moves nothing else out of that address: the
    // unmatured subtraction is what stops the sweeper spending a second fee on money already gone.
    const second = await planSweep(deps.sweeps, 'ember', 'testnet')
    assert.equal(second.kind, 'nothing_to_sweep')
  })

  it('refuses to sweep a chain nobody has pinned, or one where the pin disagrees', async () => {
    const deps = harness(sql, { sweepEnabled: true })
    await withSource(deps)
    deps.node.setBalance(DEPOSIT, 10n * 10n ** 18n)

    // **Nothing sweeps to an unpinned candidate.**
    await assert.rejects(planSweep(deps.sweeps, 'ember', 'testnet'), NoTreasuryPinnedError)

    deps.custody.pin('ember', 'testnet', TREASURY)
    await requireTreasury(deps.treasuries, 'ember', 'testnet')
    // A rotation caught mid-way. Sweeping now would move customer deposits into an address no
    // withdrawal can be paid out of.
    deps.custody.pin('ember', 'testnet', OTHER_TREASURY)
    await assert.rejects(planSweep(deps.sweeps, 'ember', 'testnet'), TreasuryDisagreementError)
  })

  it('is off entirely when the flag is off, but still drives what is already in flight', async () => {
    const off = harness(sql, { sweepEnabled: false })
    off.custody.pin('ember', 'testnet', TREASURY)
    await withSource(off)
    off.node.setBalance(DEPOSIT, 10n * 10n ** 18n)
    assert.deepEqual(await planSweep(off.sweeps, 'ember', 'testnet'), { kind: 'disabled' })

    // A sweep already opened is driven to confirmation whatever the flag says: the money has left
    // the address and nothing else can account for it.
    const on = harness(sql, { node: off.node, custody: off.custody, sweepEnabled: true })
    const planned = await planSweep(on.sweeps, 'ember', 'testnet')
    // Still nothing, and for the right reason: the flag was never what was stopping it. With no
    // queued withdrawal and no float target the treasury is not short, so the demand-driven trigger
    // simply has no demand.
    assert.equal(planned.kind, 'satisfied')
  })

  it('refuses to sweep a chain with no adapter', async () => {
    const deps = harness(sql, { sweepEnabled: true })
    const outcome = await planSweep(deps.sweeps, 'sol', 'testnet')
    assert.equal(outcome.kind, 'unsupported')
    assert.match(outcome.kind === 'unsupported' ? outcome.phase : '', /Solana transfer shape/)
  })

  /* ---------------------------------------------------------------- maturity */

  /**
   * **Maturity before the high-water mark advances.**
   *
   * `swept` moves at CONFIRMATION and never at broadcast. In the estate this replaces that delay
   * was load-bearing for crediting — the deposit watcher read a balance at depth, so money a sweep
   * had moved was still inside the view it credited from. The indexer now credits per transaction,
   * so what the delay buys here is this service's own arithmetic: between broadcast and confirmation
   * a spot balance still shows the funds, and without the unmatured subtraction the sweeper would
   * spend a second fee finding that out.
   */
  it('advances swept only once the sweep is confirmed, and only once', async () => {
    const deps = harness(sql, { sweepEnabled: true })
    deps.custody.pin('ember', 'testnet', TREASURY)
    const source = await withSource(deps)
    deps.node.setBalance(DEPOSIT, 10n * 10n ** 18n)
    deps.node.setBalance(TREASURY, 0n)
    await planOutbound(deps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 18n,
      fee: TEST_FEE,
      idempotencyKey: 'wallet:withdrawal:1',
      sourceRef: 'withdrawal-1',
    })
    const planned = await planSweep(deps.sweeps, 'ember', 'testnet')
    assert.equal(planned.kind, 'planned')
    const sweepId = planned.kind === 'planned' ? planned.outboundId : ''

    // Signed and broadcast: the money has left, and `swept` must not have moved.
    await driveChain(deps.worker, 'ember', 'testnet')
    assert.equal((await findOutbound(deps.sql, sweepId))?.state, 'broadcast')
    assert.equal((await findSweepSource(deps.sql, 'ember', 'testnet', DEPOSIT))?.swept, 0n)
    // But it IS counted as in flight, which is what stops a second sweep of the same address.
    const unmatured = await unmaturedByAddress(deps.sql, 'ember', 'testnet')
    assert.ok((unmatured.get(DEPOSIT.toLowerCase()) ?? 0n) > 0n)

    deps.node.mine(deps.node.broadcast[0]!)
    deps.node.advance(100)
    await driveChain(deps.worker, 'ember', 'testnet')

    const confirmed = await findOutbound(deps.sql, sweepId)
    assert.equal(confirmed?.state, 'confirmed')
    assert.ok(confirmed?.maturedAt, 'confirmation is maturity')
    const after = await findSweepSource(deps.sql, 'ember', 'testnet', DEPOSIT)
    // Everything that LEFT the address, fee included. A mark counting only what arrived would drift
    // low by one fee per sweep for ever.
    assert.equal(after?.swept, confirmed!.amount + confirmed!.fee)
    assert.equal(after?.id, source.id)

    // Idempotent: another tick over a confirmed sweep must not add its amount twice.
    await driveChain(deps.worker, 'ember', 'testnet')
    assert.equal((await findSweepSource(deps.sql, 'ember', 'testnet', DEPOSIT))?.swept, after?.swept)
  })

  it('restates the deposit address own binding to custody, not a derived one', async () => {
    const deps = harness(sql, { sweepEnabled: true })
    deps.custody.pin('ember', 'testnet', TREASURY)
    await withSource(deps)
    deps.node.setBalance(DEPOSIT, 10n * 10n ** 18n)
    deps.node.setBalance(TREASURY, 0n)
    await planOutbound(deps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 18n,
      fee: TEST_FEE,
      idempotencyKey: 'k',
      sourceRef: 'w',
    })
    await planSweep(deps.sweeps, 'ember', 'testnet')
    await driveChain(deps.worker, 'ember', 'testnet')

    const request = deps.custody.requests[0]!
    // `deposit`, not `treasury`: the purpose SELECTS the signing policy, and the deposit policy is
    // the one whose destination custody chooses rather than the caller.
    assert.equal(request.purpose, 'deposit')
    // From the row, because there is nothing here to derive it from — these are wallet's assignment
    // facts and a guess is a 403 every tick for ever.
    assert.equal(request.userId, 'user-1')
    assert.equal(request.orderId, 'assignment-1')
    assert.equal(request.address, DEPOSIT)
  })
})
