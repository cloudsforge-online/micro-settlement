/**
 * The two-phase ERC-20 sweep: a gas top-up, and the token sweep that depends on it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE PROPERTY UNDER TEST IS AN ORDERING, AND AN ORDERING CANNOT BE PROVED BY A HAPPY PATH.**
 *
 * A token balance at a deposit address cannot move until the address holds native coin to pay for
 * moving it, so the sweep is two transactions with a confirmation between them. Everything that can
 * go wrong here goes wrong in the GAP:
 *
 *   * the sweep is built before its gas has landed — a signature over bytes no node will accept,
 *     and a signature is permanent;
 *   * the planner funds the same address again on the next tick, because the token balance it keys
 *     on did not change when the gas arrived — `signing.ts` rule 2, "fund once";
 *   * the top-up fails and its sweep waits for ever in a queue nothing will drain.
 *
 * So most of what is below drives the worker to a specific point and then asserts what is NOT
 * possible from there. The chain is `fakeNode`, which models `eth_call` and `eth_getCode` rather
 * than stubbing the adapter, so the calldata asserted here is the calldata that would be broadcast.
 *
 * **CUSTODY IS NOT MOCKED AWAY AT THE INTERESTING SEAM.** `assertsLikeCustody` below reimplements
 * `custody/src/signing.ts assertTokenSweep`'s checks against the payload this service produces —
 * the 68-byte length, the selector, the zero left-pad, the pinned recipient, `value == 0` and the
 * gas band. That is the closest a test in this repository can get to "custody will sign this"
 * without holding a key, and it is the check that matters: bytes custody refuses are bytes that
 * fail AFTER the row is committed and this chain's single outbound slot is claimed.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import {
  addressesInFlight,
  planTokenSweep,
  registerSweepSource,
  tokenAssetCode,
  tokensFor,
} from './sweeps.ts'
import { findOutbound, nextPlanned, markFailed, planOutbound } from './outbound.ts'
import { chainFor } from './registry.ts'
import { InsufficientTreasuryError } from './chains.ts'
import { driveChain, signingPolicy } from './worker.ts'
import {
  TOKEN_TRANSFER_GAS,
  TRANSFER_GAS,
  erc20BalanceOfCalldata,
  erc20TransferCalldata,
  decodeUint256,
  gasPriceForLockedFee,
} from './evm.ts'
import { keccak256 } from './keccak.ts'
import { failedEvents } from './withdrawals.ts'
import {
  enabled,
  fakeNode,
  harness,
  migrateTestDb,
  openDb,
  resetSettlement,
  skip,
  testAddress,
  type Harness,
} from './testsupport.ts'

/* ------------------------------------------------------------------ fixtures */

const CHAIN = 'ember' as const
const NETWORK = 'testnet' as const
const TREASURY = testAddress(0x7e)
const DEPOSIT = testAddress(0xd0)
/** Lower-cased, exactly as both schemas store it. */
const USDT = testAddress(0xc0).toLowerCase()

const BINDING = { custodyUserId: 'user-1', custodyOrderId: 'order-1' }

/** Enough native coin in the treasury to fund a top-up and pay for sending it. */
const TREASURY_FUNDS = 10n ** 18n

/**
 * Custody's `assertTokenSweep`, reimplemented against the payload this service builds.
 *
 * Every clause is a line of `custody/src/signing.ts`. It is a COPY and that is deliberate: the
 * alternative is importing custody into settlement's test suite, which would couple two services'
 * build graphs to make one assertion, and custody's own `signing.test.ts` already proves the
 * original. What this proves is the direction that is not covered anywhere else — that the bytes
 * THIS service emits satisfy the policy THAT service enforces.
 */
function assertsLikeCustody(
  payload: Record<string, unknown>,
  options: { readonly pin: string; readonly allowlist: ReadonlySet<string> },
): void {
  const to = String(payload.to)
  assert.ok(options.allowlist.has(to.toLowerCase()), '`to` must be a registered token contract')
  assert.equal(BigInt(String(payload.value ?? 0)), 0n, '`value` must be zero on a token sweep')

  const data = String(payload.data)
  assert.match(data, /^0x[0-9a-fA-F]+$/, '`data` must be 0x-hex calldata')
  const body = data.slice(2)
  assert.equal(body.length, 68 * 2, '`data` must be exactly 68 bytes, nothing appended')
  assert.equal(body.slice(0, 8).toLowerCase(), 'a9059cbb', '`data` must call transfer(address,uint256)')

  const recipientWord = body.slice(8, 72)
  assert.match(recipientWord, /^0{24}[0-9a-fA-F]{40}$/, 'the recipient word must be a left-padded address')
  assert.equal(
    `0x${recipientWord.slice(24).toLowerCase()}`,
    options.pin.toLowerCase(),
    'the calldata must pay the pinned treasury and nothing else',
  )

  const amount = BigInt(`0x${body.slice(72)}`)
  assert.ok(amount > 0n, '`data` must transfer a positive amount')

  const gasLimit = BigInt(String(payload.gasLimit))
  assert.ok(gasLimit >= 21_000n && gasLimit <= 200_000n, 'gasLimit must sit in custody band')
}

/** Set the estate up: a pinned treasury, a registered deposit address, a registered token. */
async function setUp(
  h: Harness,
  options: { readonly tokenBalance?: bigint; readonly nativeBalance?: bigint } = {},
): Promise<void> {
  // The pin is custody's, and `assertSweepable` adopts the treasury row from it — the same path
  // `planSweep`'s own tests use, so this exercises the real adoption rather than a shortcut.
  h.custody.pin(CHAIN, NETWORK, TREASURY)
  await registerSweepSource(h.sql, {
    chain: CHAIN,
    network: NETWORK,
    address: DEPOSIT,
    custodyChain: 'ember',
    custodyFamily: 'ember',
    ...BINDING,
  })
  h.custody.registerToken({
    // CUSTODY'S chain name, not this service's slug. For `ember` they agree; the translation is
    // asserted separately below on `eth`, where they do not.
    chain: 'ember',
    network: NETWORK,
    contract: USDT,
    symbol: 'USDT',
    decimals: 6,
  })
  h.node.setBalance(TREASURY, options.nativeBalance ?? TREASURY_FUNDS)
  h.node.setTokenBalance(USDT, DEPOSIT, options.tokenBalance ?? 5_000_000n)
}

/** Drive the chain until nothing moves, mining and confirming whatever gets broadcast. */
async function settle(h: Harness, ticks = 8): Promise<void> {
  for (let i = 0; i < ticks; i += 1) {
    await driveChain(h.worker, CHAIN, NETWORK)
    for (const rawTx of h.node.broadcast) h.node.mine(rawTx)
    h.node.advance(100)
    await driveChain(h.worker, CHAIN, NETWORK)
  }
}

/* ------------------------------------------------------------------ pure: the calldata */

describe('the ERC-20 calldata this service builds', () => {
  /**
   * **THE SELECTOR IS CHECKED AGAINST A REAL KECCAK, NOT ASSERTED AGAINST ITSELF.**
   *
   * `a9059cbb` is written as a literal in `evm.ts` so a reader can see the constant that is
   * broadcast. That is only safe if something proves the literal is the right four bytes — a typo
   * would otherwise call a different function on a real contract, and custody would accept it,
   * because custody holds a literal copy of the SAME constant and compares the two. Two copies of
   * one typo agree perfectly. This is the check neither service can make about the other.
   */
  it('calls the function it says it calls', () => {
    const selector = Buffer.from(keccak256(Buffer.from('transfer(address,uint256)', 'ascii')))
      .toString('hex')
      .slice(0, 8)
    assert.equal(selector, 'a9059cbb')
    assert.ok(erc20TransferCalldata(TREASURY, 1n).startsWith(`0x${selector}`))

    const balanceOf = Buffer.from(keccak256(Buffer.from('balanceOf(address)', 'ascii')))
      .toString('hex')
      .slice(0, 8)
    assert.equal(balanceOf, '70a08231')
    assert.ok(erc20BalanceOfCalldata(DEPOSIT).startsWith(`0x${balanceOf}`))
  })

  it('is exactly 68 bytes, with a zero left-pad and the amount in the second word', () => {
    const data = erc20TransferCalldata(TREASURY, 123_456n)
    assert.equal(data.length, 2 + 68 * 2)
    const body = data.slice(2)
    assert.equal(body.slice(8, 32), '0'.repeat(24), 'the twelve-byte left pad must be zero')
    assert.equal(`0x${body.slice(32, 72)}`, TREASURY.toLowerCase())
    assert.equal(BigInt(`0x${body.slice(72)}`), 123_456n)
  })

  /**
   * A truncated uint256 is a transfer of the WRONG AMOUNT, signed, that nothing downstream would
   * notice — the calldata would be well-formed, custody's decode checks the shape rather than the
   * arithmetic, and the chain would move whatever the low 32 bytes happened to say.
   */
  it('refuses an amount that does not fit a uint256 rather than truncating it', () => {
    const max = (1n << 256n) - 1n
    assert.ok(erc20TransferCalldata(TREASURY, max).length === 2 + 68 * 2)
    assert.throws(() => erc20TransferCalldata(TREASURY, max + 1n), /uint256/)
  })

  it('refuses a zero or negative amount, because a signature is permanent', () => {
    assert.throws(() => erc20TransferCalldata(TREASURY, 0n), /non-positive/)
    assert.throws(() => erc20TransferCalldata(TREASURY, -1n), /non-positive/)
  })

  /**
   * An empty `0x` is what a node returns for a call to an address with NO CODE — a mistyped
   * contract, or the right contract on the wrong network. Reading it as zero would make every such
   * misconfiguration indistinguishable from "this address holds no tokens": silent, permanent, and
   * discovered only when somebody asks why a registered token has never been swept.
   */
  it('refuses an empty eth_call result rather than reading it as a zero balance', () => {
    assert.equal(decodeUint256(`0x${(42n).toString(16).padStart(64, '0')}`, 'x'), 42n)
    for (const bad of ['0x', '', null, undefined, '0x2a', 42]) {
      assert.throws(() => decodeUint256(bad, 'balanceOf'), /uint256/, `${String(bad)} was accepted`)
    }
  })
})

describe('the locked fee divisor', () => {
  /**
   * A token sweep's fee divided by 21,000 recovers a gas price nearly five times the real one,
   * which sails past `maxGasPriceWei` and refuses a perfectly good sweep as out of band — with a
   * message pointing at the wrong number. The divisor has to be the gas the fee was quoted at.
   */
  it('recovers the gas price the fee was actually quoted at, per gas limit', () => {
    const bounds = { minGasPriceWei: 1n, maxGasPriceWei: 10n ** 12n, maxFeeWei: 10n ** 18n }
    const price = 20_000_000_000n

    assert.equal(gasPriceForLockedFee(price * TRANSFER_GAS, bounds, CHAIN), price)
    assert.equal(
      gasPriceForLockedFee(price * TOKEN_TRANSFER_GAS, bounds, CHAIN, TOKEN_TRANSFER_GAS),
      price,
    )
    // And the cross case is REFUSED rather than silently mispriced: a token fee read with the
    // native divisor is not divisible by it in general, and where it is, it is the wrong price.
    assert.throws(
      () => gasPriceForLockedFee(price * TOKEN_TRANSFER_GAS, bounds, CHAIN),
      /below|above/,
      'a token fee must not be readable under the native divisor',
    )
  })
})

describe('the registry translation', () => {
  /**
   * Custody stores `ethereum` where this service's slug is `eth` — the one disagreement of five.
   * Filtering custody's rows by this service's slug silently matches nothing on Ethereum, which is
   * the only chain that has tokens, so the bug presents as "tokens are registered and nothing is
   * ever swept" rather than as an error.
   */
  it('matches custody chain name and not this service slug', () => {
    const rows = [
      { chain: 'ethereum', network: 'testnet', contract: USDT, symbol: 'USDT', decimals: 6 },
      { chain: 'eth', network: 'testnet', contract: USDT, symbol: 'FAKE', decimals: 6 },
      { chain: 'ethereum', network: 'mainnet', contract: USDT, symbol: 'USDT', decimals: 6 },
    ]
    const found = tokensFor(rows, 'eth', 'testnet')
    assert.equal(found.length, 1, 'exactly the ethereum testnet row')
    assert.equal(found[0]?.symbol, 'USDT')
    // And it comes back under THIS service's slug, because that is what the outbound row is keyed by.
    assert.equal(found[0]?.chain, 'eth')
  })

  it('never writes a bare symbol as an asset code', () => {
    const code = tokenAssetCode({
      chain: 'eth',
      network: 'mainnet',
      contract: USDT,
      symbol: 'USDT',
      decimals: 6,
    })
    // A single `USDT` code forces one decimals value onto a token that has six on Ethereum and
    // eighteen on BSC — a balance wrong by 10^12.
    assert.equal(code, `TOKEN:eth:mainnet:${USDT}`)
    assert.notEqual(code, 'USDT')
    assert.ok(code.includes(USDT), 'the code must name the deployment, not the brand')
  })
})

describe('the signing policy for the new purposes', () => {
  it('claims deposit for a token sweep and treasury for its gas top-up', () => {
    // A token sweep claims `deposit`, exactly as a native one does. There is no `token_sweep`
    // purpose on custody's side to claim and there must not be: custody refines the shape out of
    // the PAYLOAD so the choice between two policies is never a caller-supplied field.
    assert.deepEqual(signingPolicy('token_sweep'), { custodyPurpose: 'deposit', shape: 'token_sweep' })
    assert.deepEqual(signingPolicy('gas_topup'), { custodyPurpose: 'treasury', shape: 'payment' })
  })

  it('never gives a gas top-up a sweep shape', () => {
    // A top-up SPENDS the treasury and names its own destination. Pairing it with `sweep` would
    // build a change-free PSBT on a UTXO chain and, on EVM, claim a purpose whose pin it does not
    // pay.
    assert.notEqual(signingPolicy('gas_topup').shape, 'sweep')
    assert.notEqual(signingPolicy('gas_topup').custodyPurpose, 'deposit')
  })
})

describe('what the token build refuses before it asks custody for anything', () => {
  const bounds = { minGasPriceWei: 1n, maxGasPriceWei: 10n ** 12n, maxFeeWei: 10n ** 18n }
  const price = 20_000_000_000n
  const fee = price * TOKEN_TRANSFER_GAS

  const buildToken = (h: Harness, over: { readonly from?: string } = {}) =>
    chainFor(CHAIN).build(
      { network: NETWORK, rpc: h.node.rpc },
      {
        from: over.from ?? DEPOSIT,
        to: TREASURY,
        value: 5_000_000n,
        fee,
        bounds,
        shape: 'token_sweep',
        token: { contract: USDT },
      },
    )

  /**
   * **THE `eth_getCode` CHECK IS INVERTED FOR A TOKEN SWEEP, AND THE INVERSION IS THE POINT.**
   *
   * A native transfer refuses a destination that RUNS code. A token sweep requires one, because a
   * `transfer(...)` call sent to an address with no code does not fail — it is a plain value
   * transfer of zero, it succeeds, and the receipt says `0x1`. So the gas the top-up just paid for
   * is burnt, the tokens do not move, and every downstream check reports success. A registered
   * contract with no code is a wrong address or the right address on the wrong network, and both
   * are permanent.
   */
  it('refuses a token contract that holds no code, rather than reporting a successful no-op', async () => {
    const h = harness(undefined as never, {})
    h.node.setBalance(DEPOSIT, fee * 2n)
    // Deliberately NOT registered with `setTokenBalance`, which is what gives a contract its code.
    await assert.rejects(buildToken(h), /contract|is a contract|withdrawals are plain/)
  })

  /**
   * The check that makes the whole ordering self-healing. A sweep whose gas has not arrived fails
   * its build as an `InsufficientTreasuryError`, which the classifier releases back to `planned`
   * rather than refunding — so the sweep WAITS for its gas instead of being abandoned.
   */
  it('refuses to build a token sweep at an address that cannot pay for it', async () => {
    const h = harness(undefined as never, {})
    h.node.setTokenBalance(USDT, DEPOSIT, 5_000_000n)
    h.node.setBalance(DEPOSIT, fee - 1n)
    await assert.rejects(buildToken(h), InsufficientTreasuryError)

    // One wei more and it builds. The boundary is exact, so a mutation that loosens the comparison
    // is a mutation that shows up here.
    h.node.setBalance(DEPOSIT, fee)
    const unsigned = await buildToken(h)
    const payload = unsigned.payload as Record<string, unknown>
    assert.equal(BigInt(String(payload.value)), 0n)
    assert.equal(String(payload.to).toLowerCase(), USDT)
  })

  /**
   * The chain id is bound independently of custody on the token path too. A token sweep that
   * skipped it would be the one transaction shape in this service whose signature could be made
   * against the wrong network with only custody standing behind it.
   */
  it('refuses a node whose chain id is not the one this build is pinned to', async () => {
    const h = harness(undefined as never, { node: fakeNode({ chainId: 999 }) })
    h.node.setTokenBalance(USDT, DEPOSIT, 5_000_000n)
    h.node.setBalance(DEPOSIT, fee * 2n)
    await assert.rejects(buildToken(h), /chain id/)
  })
})

/* ------------------------------------------------------------------ the sequencing */

describe('planning and driving the pair', { skip }, () => {
  let sql: postgres.Sql
  let h: Harness

  before(async () => {
    if (!enabled) return
    sql = openDb()
    await migrateTestDb(sql)
  })
  after(async () => {
    if (enabled) await sql.end({ timeout: 5 })
  })
  beforeEach(async () => {
    await resetSettlement(sql)
    h = harness(sql)
  })

  it('plans a top-up and a sweep together, with the sweep depending on the top-up', async () => {
    await setUp(h)
    const outcome = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(outcome.kind, 'planned')
    if (outcome.kind !== 'planned') return

    const topUp = await findOutbound(sql, outcome.topUpId)
    const sweep = await findOutbound(sql, outcome.sweepId)
    assert.ok(topUp && sweep)

    assert.equal(topUp.purpose, 'gas_topup')
    assert.equal(topUp.fromAddress, TREASURY, 'gas comes OUT of the treasury')
    assert.equal(topUp.toAddress, DEPOSIT, 'and goes TO the address that cannot pay')
    assert.equal(topUp.tokenContract, null, 'a top-up is a plain native transfer')

    assert.equal(sweep.purpose, 'token_sweep')
    assert.equal(sweep.fromAddress, DEPOSIT)
    assert.equal(sweep.toAddress, TREASURY, '`to` is WHO IS PAID, not the contract')
    assert.equal(sweep.tokenContract, USDT, 'the contract has a column of its own')
    assert.equal(sweep.amount, 5_000_000n, 'the whole token balance')
    assert.equal(sweep.assetCode, `TOKEN:${CHAIN}:${NETWORK}:${USDT}`)
    assert.equal(sweep.dependsOn, topUp.id, 'the sweep waits for the gas')

    /*
     * THE SEQUENCING CONTRACT, AS ONE EQUALITY. The top-up delivers exactly what the sweep's locked
     * fee will be divided by `TOKEN_TRANSFER_GAS` to recover a gas price from. Too little and the
     * sweep runs out of gas — the fee is burnt and the tokens do not move. Too much and gas is
     * parked at a deposit address, becoming dust that must itself be swept later, at a fee.
     */
    assert.equal(topUp.amount, sweep.fee, 'the top-up delivers exactly the sweep locked fee')
  })

  /**
   * **THE CENTRAL ORDERING PROPERTY.** Until the gas has CONFIRMED, the sweep is not queued.
   *
   * Not "not broadcast" and not "not signed" — not offered to the worker at all, because a worker
   * that were offered it would claim the chain's single outbound slot, fail the build on the
   * balance check, and release it, once per tick, for as long as the top-up takes to confirm.
   */
  it('will not offer the sweep to the worker until the top-up has confirmed', async () => {
    await setUp(h)
    const outcome = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(outcome.kind, 'planned')
    if (outcome.kind !== 'planned') return

    const first = await nextPlanned(sql, CHAIN, NETWORK)
    assert.equal(first?.id, outcome.topUpId, 'the top-up is what is queued')

    // Walk the top-up all the way to `broadcast` — which is NOT far enough. A node that has
    // accepted bytes can still drop them, so building against a balance that is only probably
    // there is the mistake this ordering exists to prevent.
    await driveChain(h.worker, CHAIN, NETWORK)
    const broadcastTopUp = await findOutbound(sql, outcome.topUpId)
    assert.ok(
      ['signed', 'broadcast'].includes(broadcastTopUp!.state),
      `the top-up should be in flight, was ${broadcastTopUp!.state}`,
    )
    assert.equal(
      await nextPlanned(sql, CHAIN, NETWORK),
      null,
      'nothing is queued while the top-up is merely in flight',
    )

    // Mine and deepen it, but do NOT tick: the row still says `broadcast`, because only a drive
    // reads the chain. The queue must still be empty, which proves the gate is on the ROW's state
    // rather than on anything the node happens to know.
    for (const rawTx of h.node.broadcast) h.node.mine(rawTx)
    h.node.advance(100)
    assert.equal(await nextPlanned(sql, CHAIN, NETWORK), null)

    // Now tick. This single tick both confirms the top-up and — because the sweep becomes eligible
    // the instant it does — starts the sweep, so asserting on `nextPlanned` afterwards would find
    // an empty queue for the OPPOSITE reason. Assert the state instead, which is the stronger
    // statement: the sweep moved off the queue only after its dependency reached `confirmed`.
    await driveChain(h.worker, CHAIN, NETWORK)
    assert.equal((await findOutbound(sql, outcome.topUpId))!.state, 'confirmed')
    const sweep = await findOutbound(sql, outcome.sweepId)
    assert.notEqual(sweep!.state, 'planned', 'the sweep is released the moment its gas confirms')
    assert.ok(
      ['building', 'signed', 'broadcast', 'confirmed'].includes(sweep!.state),
      `the sweep should be in flight, was ${sweep!.state}`,
    )
  })

  /**
   * The database's own statement of the same rule, for everything that reaches a row by another
   * route — an operator re-queueing by hand, a future call site that selects by id, a lost lease.
   * `nextPlanned` is the design; this is the last line, exactly as `outbound_in_flight_uniq` is to
   * the chain lease.
   */
  it('refuses the transition into building at the database, not only in the query', async () => {
    await setUp(h)
    const outcome = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(outcome.kind, 'planned')
    if (outcome.kind !== 'planned') return

    await assert.rejects(
      sql`update outbound_transactions set state = 'building' where id = ${outcome.sweepId}`,
      /depends on|confirmed/,
      'the trigger must refuse a build while the dependency is unconfirmed',
    )

    // The same statement succeeds once the dependency confirms, which proves the trigger is
    // discriminating rather than simply refusing everything.
    await sql`update outbound_transactions set state = 'confirmed' where id = ${outcome.topUpId}`
    await sql`update outbound_transactions set state = 'building' where id = ${outcome.sweepId}`
    assert.equal((await findOutbound(sql, outcome.sweepId))!.state, 'building')
  })

  /**
   * `signing.ts` rule 2, as a test: **fund once.** The token balance does not change when gas
   * arrives, so a planner keyed only on that balance would compute the same decision every tick and
   * fund the address again each time.
   */
  it('does not fund the same address twice while a pair is outstanding', async () => {
    await setUp(h)
    const first = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(first.kind, 'planned')

    for (let i = 0; i < 5; i += 1) {
      const again = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
      assert.equal(again.kind, 'nothing_to_sweep', `pass ${i} planned a second pair`)
    }

    const rows = await sql<{ count: string }[]>`
      select count(*)::text as count from outbound_transactions where purpose = 'gas_topup'
    `
    assert.equal(rows[0]!.count, '1', 'exactly one gas top-up exists')
  })

  /** And it stays true across the whole life of the pair, including the gap that used to double-fund. */
  it('does not fund again in the gap between the top-up confirming and the sweep starting', async () => {
    await setUp(h)
    await planTokenSweep(h.sweeps, CHAIN, NETWORK)

    await driveChain(h.worker, CHAIN, NETWORK)
    for (const rawTx of h.node.broadcast) h.node.mine(rawTx)
    h.node.advance(100)
    await driveChain(h.worker, CHAIN, NETWORK)

    // THE GAP: the top-up is confirmed and the sweep has not started. This is the exact moment a
    // "plan the sweep when the top-up confirms" design would re-observe an unchanged token balance
    // and fund the address a second time.
    const topUps = await sql<{ count: string }[]>`
      select count(*)::text as count from outbound_transactions where purpose = 'gas_topup'
    `
    assert.equal(topUps[0]!.count, '1')
    const again = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(again.kind, 'nothing_to_sweep')
    const after2 = await sql<{ count: string }[]>`
      select count(*)::text as count from outbound_transactions where purpose = 'gas_topup'
    `
    assert.equal(after2[0]!.count, '1', 'the gap must not produce a second top-up')
  })

  /**
   * The whole loop, and the assertion that matters at the end of it: what custody was asked to sign
   * is a transaction custody would accept.
   */
  it('drives the pair to confirmation and asks custody for bytes it would sign', async () => {
    await setUp(h)
    const outcome = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(outcome.kind, 'planned')
    if (outcome.kind !== 'planned') return

    await settle(h)

    const topUp = await findOutbound(sql, outcome.topUpId)
    const sweep = await findOutbound(sql, outcome.sweepId)
    assert.equal(topUp!.state, 'confirmed', 'the gas landed')
    assert.equal(sweep!.state, 'confirmed', 'and then the tokens moved')

    // TWO signatures, and no more. One per phase.
    assert.equal(h.custody.signatures.length, 2, 'exactly one signature per phase')

    const topUpRequest = h.custody.requests[0]!
    assert.equal(topUpRequest.purpose, 'treasury', 'the top-up spends the treasury')

    const sweepRequest = h.custody.requests[1]!
    assert.equal(sweepRequest.purpose, 'deposit', 'the sweep spends the deposit address')
    assert.equal(sweepRequest.userId, BINDING.custodyUserId, 'the binding is restated from the row')
    assert.equal(sweepRequest.orderId, BINDING.custodyOrderId)

    // ── THE CROSS-SERVICE CHECK ────────────────────────────────────────────────────────────────
    assertsLikeCustody(sweepRequest.payload as Record<string, unknown>, {
      pin: TREASURY,
      allowlist: new Set([USDT]),
    })
  })

  /**
   * The calldata pays the PIN, and the pin is the vault's choice rather than the caller's. This is
   * `assertSweep`'s security property moved one ABI word deeper, so it is asserted the same way:
   * by pointing at what the bytes actually say.
   */
  it('pays the pinned treasury inside the calldata, never the contract and never anything else', async () => {
    await setUp(h)
    await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    await settle(h)

    const payload = h.custody.requests[1]!.payload as Record<string, unknown>
    assert.equal(String(payload.to).toLowerCase(), USDT, 'the transaction goes to the contract')
    const body = String(payload.data).slice(2)
    const recipient = `0x${body.slice(32, 72)}`
    assert.equal(recipient, TREASURY.toLowerCase(), 'and the calldata pays the pin')
    assert.notEqual(recipient, USDT, 'never the contract')
    assert.notEqual(recipient, DEPOSIT.toLowerCase(), 'never back to the source')
  })

  /* ---------------------------------------------------------------- failure and recovery */

  /**
   * A sweep whose gas can never arrive must not sit in a queue nothing will drain. Left `planned`
   * it is invisible to `nextPlanned` (the dependency clause) and refused by the trigger, so it
   * would look exactly like a sweep that is merely slow — for ever.
   */
  it('fails the sweep with its top-up, in the same transaction', async () => {
    await setUp(h)
    const outcome = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(outcome.kind, 'planned')
    if (outcome.kind !== 'planned') return

    await markFailed(sql, 'settlement', outcome.topUpId, 'the treasury cannot cover it', (r) =>
      failedEvents(r, 'the treasury cannot cover it', true),
    )

    const sweep = await findOutbound(sql, outcome.sweepId)
    assert.equal(sweep!.state, 'failed', 'the dependent must fail with its dependency')
    assert.match(String(sweep!.failureReason), /depended on/)
  })

  /**
   * The cascade must not be able to retire something that has already signed. It cannot, and the
   * reason is structural rather than careful: a dependent reaches `building` only when its
   * dependency is `confirmed`, and `markFailed` cannot reach a `confirmed` row at all.
   */
  it('cannot cascade over a dependent that has already signed', async () => {
    await setUp(h)
    const outcome = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(outcome.kind, 'planned')
    if (outcome.kind !== 'planned') return

    await settle(h)
    assert.equal((await findOutbound(sql, outcome.sweepId))!.state, 'confirmed')

    // The dependency is confirmed, so `markFailed` matches no row and the cascade never runs.
    const failed = await markFailed(sql, 'settlement', outcome.topUpId, 'too late', (r) =>
      failedEvents(r, 'too late', true),
    )
    assert.equal(failed, null, 'a confirmed row is not failable')
    assert.equal(
      (await findOutbound(sql, outcome.sweepId))!.state,
      'confirmed',
      'and the swept tokens stay swept',
    )
  })

  /**
   * A crash between the pair being planned and the top-up being signed leaves two `planned` rows,
   * which the next tick simply picks up. Modelled by planning and then driving from cold.
   */
  it('recovers from a crash between planning and the first signature', async () => {
    await setUp(h)
    const outcome = await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    assert.equal(outcome.kind, 'planned')
    if (outcome.kind !== 'planned') return

    // A fresh harness over the same database: a new process, with none of the old one's state.
    const restarted = harness(sql, { custody: h.custody, node: h.node })
    await settle(restarted)

    assert.equal((await findOutbound(sql, outcome.topUpId))!.state, 'confirmed')
    assert.equal((await findOutbound(sql, outcome.sweepId))!.state, 'confirmed')
    assert.equal(h.custody.signatures.length, 2, 'still exactly two signatures')
  })

  /* ---------------------------------------------------------------- the refusals */

  it('sweeps nothing when no token is registered', async () => {
    h.custody.pin(CHAIN, NETWORK, TREASURY)
    await registerSweepSource(h.sql, {
      chain: CHAIN,
      network: NETWORK,
      address: DEPOSIT,
      custodyChain: 'ember',
      custodyFamily: 'ember',
      ...BINDING,
    })
    h.node.setBalance(TREASURY, TREASURY_FUNDS)
    // A balance exists and nobody registered the contract. The allowlist refuses by default, and
    // this is what that default does here.
    h.node.setTokenBalance(USDT, DEPOSIT, 5_000_000n)

    assert.equal((await planTokenSweep(h.sweeps, CHAIN, NETWORK)).kind, 'no_tokens')
    const rows = await sql<{ count: string }[]>`select count(*)::text as count from outbound_transactions`
    assert.equal(rows[0]!.count, '0')
  })

  /**
   * The flag `env.ts` argues for at length. It is separate from `SWEEP_ENABLED` because a
   * deployment that sweeps native coin correctly has said nothing about tokens, and until wallet
   * credits a token deposit a token sweep moves customer money the ledger has no liability for.
   */
  it('sweeps no tokens when token sweeping is off, even with native sweeping on', async () => {
    const off = harness(sql, { tokenSweepEnabled: false })
    await setUp(off)
    assert.equal(off.sweeps.enabled, true, 'native sweeping is on')
    assert.equal((await planTokenSweep(off.sweeps, CHAIN, NETWORK)).kind, 'disabled')
    const rows = await sql<{ count: string }[]>`select count(*)::text as count from outbound_transactions`
    assert.equal(rows[0]!.count, '0')
  })

  it('leaves a balance below the operator floor alone', async () => {
    const floored = harness(sql, { minTokenSweep: 10_000_000n })
    await setUp(floored, { tokenBalance: 9_999_999n })
    assert.equal((await planTokenSweep(floored.sweeps, CHAIN, NETWORK)).kind, 'nothing_to_sweep')

    floored.node.setTokenBalance(USDT, DEPOSIT, 10_000_000n)
    assert.equal((await planTokenSweep(floored.sweeps, CHAIN, NETWORK)).kind, 'planned')
  })

  it('never sweeps the treasury into itself', async () => {
    await setUp(h, { tokenBalance: 0n })
    // The treasury is also a registered sweep source in some deployments; it holds tokens too.
    await registerSweepSource(h.sql, {
      chain: CHAIN,
      network: NETWORK,
      address: TREASURY,
      custodyChain: 'ember',
      custodyFamily: 'ember',
      custodyUserId: 'cloudsforge:treasury',
      custodyOrderId: `treasury:${CHAIN}:${NETWORK}`,
    })
    h.node.setTokenBalance(USDT, TREASURY, 900_000_000n)
    assert.equal((await planTokenSweep(h.sweeps, CHAIN, NETWORK)).kind, 'nothing_to_sweep')
  })

  /* ---------------------------------------------------------------- the in-flight set */

  /**
   * **THIS TEST EXISTS BECAUSE A MUTATION SURVIVED.**
   *
   * The first version asserted the set after a whole pair had been planned — and a pair always
   * contains a `token_sweep` whose FROM is the deposit address, so dropping `to_address_key`
   * entirely changed nothing and the assertion passed either way. It was a check that could not
   * fail, which is the thing this suite is meant to be free of.
   *
   * The guarantee is really "an address being FUNDED is not funded again, however the funding row
   * came to exist" — and a lone `gas_topup` is exactly that state. It is reachable: an operator
   * queueing one by hand, or a future caller that tops an address up for some other reason. Keyed
   * only by its source, such a row puts the TREASURY in the set — true and useless — while leaving
   * the address it funds looking untouched.
   */
  it('counts the destination of a funding row, not only its source', async () => {
    await setUp(h)
    // A gas top-up with NO paired sweep. Nothing in this service plans one today; the column exists
    // so that if anything ever does, the address it funds is still protected.
    await planOutbound(sql, {
      purpose: 'gas_topup',
      chain: CHAIN,
      network: NETWORK,
      from: TREASURY,
      to: DEPOSIT,
      assetCode: 'EMBER',
      amount: 1_000n,
      fee: 21_000n,
      idempotencyKey: 'lone-topup',
    })

    const keys = await addressesInFlight(sql, CHAIN, NETWORK)
    assert.ok(keys.has(DEPOSIT.toLowerCase()), 'the address being FUNDED must be in the set')
    assert.ok(keys.has(TREASURY.toLowerCase()), 'and so must the treasury paying for it')
  })

  it('counts both ends of a planned pair', async () => {
    await setUp(h)
    await planTokenSweep(h.sweeps, CHAIN, NETWORK)

    const keys = await addressesInFlight(sql, CHAIN, NETWORK)
    assert.ok(keys.has(DEPOSIT.toLowerCase()), 'the address being swept')
    assert.ok(keys.has(TREASURY.toLowerCase()), 'and the treasury on the other end')
  })

  /**
   * A native sweep and a token sweep of one address must not be planned against each other. The
   * in-flight index would serialise them anyway, but the address-level skip is what stops a native
   * quote being taken of a balance that is about to change by exactly the gas the pair delivers.
   */
  it('keeps the native sweeper off an address with a token pair outstanding', async () => {
    await setUp(h)
    await planTokenSweep(h.sweeps, CHAIN, NETWORK)
    h.node.setBalance(DEPOSIT, 5n * 10n ** 17n)

    const keys = await addressesInFlight(sql, CHAIN, NETWORK)
    assert.ok(keys.has(DEPOSIT.toLowerCase()))
  })

  /* ---------------------------------------------------------------- schema invariants */

  it('refuses a token contract on a purpose that is not a token sweep', async () => {
    await setUp(h)
    await assert.rejects(
      planOutbound(sql, {
        purpose: 'withdrawal',
        chain: CHAIN,
        network: NETWORK,
        from: TREASURY,
        to: DEPOSIT,
        assetCode: 'EMBER',
        amount: 1n,
        fee: 1n,
        idempotencyKey: 'x:1',
        tokenContract: USDT,
      }),
      /outbound_token_contract_ck/,
      'a contract on a native purpose must be refused by the database',
    )
  })

  it('refuses a token sweep with no contract', async () => {
    await setUp(h)
    await assert.rejects(
      planOutbound(sql, {
        purpose: 'token_sweep',
        chain: CHAIN,
        network: NETWORK,
        from: DEPOSIT,
        to: TREASURY,
        assetCode: `TOKEN:${CHAIN}:${NETWORK}:${USDT}`,
        amount: 1n,
        fee: 1n,
        idempotencyKey: 'x:2',
      }),
      /outbound_token_contract_ck/,
      'a token sweep with nowhere to send the call must be refused',
    )
  })

  it('refuses a zero-amount token sweep', async () => {
    await setUp(h)
    await assert.rejects(
      planOutbound(sql, {
        purpose: 'token_sweep',
        chain: CHAIN,
        network: NETWORK,
        from: DEPOSIT,
        to: TREASURY,
        assetCode: `TOKEN:${CHAIN}:${NETWORK}:${USDT}`,
        amount: 0n,
        fee: 1n,
        idempotencyKey: 'x:3',
        tokenContract: USDT,
      }),
      /outbound_token_amount_ck/,
      'a zero-amount token sweep is a signature over a no-op that costs a real fee',
    )
  })

  /**
   * EVM addresses have three valid spellings and custody's allowlist stores exactly one. A
   * checksummed contract reaching the row is a sweep custody will refuse at signing time, after the
   * chain's slot has been claimed — so it is normalised on the way in and the database insists.
   */
  it('stores one spelling of a contract, the one custody allowlist stores', async () => {
    await setUp(h)
    const checksummed = testAddress(0xc0)
    assert.notEqual(checksummed, USDT, 'the fixture must actually differ in case')
    const { outbound } = await planOutbound(sql, {
      purpose: 'token_sweep',
      chain: CHAIN,
      network: NETWORK,
      from: DEPOSIT,
      to: TREASURY,
      assetCode: `TOKEN:${CHAIN}:${NETWORK}:${USDT}`,
      amount: 1n,
      fee: 1n,
      idempotencyKey: 'x:4',
      tokenContract: checksummed,
    })
    assert.equal(outbound.tokenContract, USDT, 'stored lower-cased')
  })
})
