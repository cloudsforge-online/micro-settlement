/**
 * The treasury, as the indexer's custody set sees it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * ## The defect
 *
 * `micro-indexer` serves `GET /v1/custody/:chain/:network/total` — the number `micro-ledger`
 * reconciles the platform's solvency against, and the only thing that can prove the estate's
 * economics are valid from the chain. Its set is `watched_addresses` filtered by label prefix,
 * default `deposit:,treasury:`.
 *
 * `micro-wallet` writes the first prefix for every deposit address it assigns. **Nothing in the
 * estate has ever written the second** — grepping all 58 repositories for a caller of the watch
 * route returns two lines, both wallet's, both `deposit:`. And this service is the one that SWEEPS:
 * it consolidates deposits out of addresses the aggregate counts and into one it does not.
 *
 * So every successful sweep made the aggregate smaller while the ledger's custody total stayed
 * where it was. That is a positive drift — "the ledger claims coin the chain does not show" — and
 * positive drift FREEZES WITHDRAWALS. The direction is the safe one, which is why nobody would have
 * found it by losing money; it would have been found by the platform quietly refusing to pay
 * anybody, some weeks after the first sweep.
 *
 * ## What this file asserts, and what it deliberately does not
 *
 * The registration itself is one POST and is not interesting. What is interesting, and what every
 * case below is about, is the three ways a fix like this is usually WRONG:
 *
 *   1. it records the attempt rather than the acceptance, so an outage produces a row that says a
 *      treasury is visible when it is not — the original defect, wearing the repair's clothes;
 *   2. it registers once and never again, so a rotation leaves the new treasury invisible for ever
 *      while the row insists the job is done;
 *   3. it writes the wrong label, which is indistinguishable from not registering at all except
 *      that it looks like it worked.
 *
 * It does not assert that the indexer sums the address afterwards. That is
 * `indexer/src/custody.test.ts`'s and `chainbacking.test.ts`'s, against a real chain.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { custodyAccount, treasuryEquityAccount } from './fees.ts'
import { treasuryLabel } from './indexerclient.ts'
import {
  assertSweepable,
  findTreasury,
  provisionTreasury,
  registerTreasuryWithIndexer,
  TreasuryNotBookedError,
} from './treasury.ts'
import {
  enabled,
  fakeCustody,
  harness,
  migrateTestDb,
  openDb,
  resetSettlement,
  skip,
  testAddress,
} from './testsupport.ts'

const TREASURY = testAddress(0xaa)
const ROTATED = testAddress(0xbb)
const OPERATOR = 'an-operator-token-0000000000000000'

/**
 * The float the mainnet treasury actually held when it froze the asset: 24.1 EMBER in the treasury
 * plus 0.900021 stranded in an unswept deposit address. The number is used verbatim so a failure
 * here names the incident rather than an invented amount.
 */
const FLOAT = 25_000_021_000_000_000_000n

/**
 * A harness whose indexer will answer a balance for both addresses this file uses.
 *
 * Armed explicitly, and never defaulted, because the fake follows the real client's rule: an
 * address with no balance armed is an indexer that REFUSES, not one that reports zero. A test that
 * forgets gets an outage, which is the honest failure for it to get.
 */
function armed(deps: ReturnType<typeof harness>, balance = FLOAT): ReturnType<typeof harness> {
  deps.indexer.setBalance(TREASURY, balance)
  deps.indexer.setBalance(ROTATED, balance)
  return deps
}

let sql: postgres.Sql

before(async () => {
  if (!enabled) return
  sql = openDb(4)
  await migrateTestDb(sql)
})

after(async () => {
  if (!enabled) return
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (!enabled) return
  await resetSettlement(sql)
})

describe('the label', () => {
  it('carries the prefix the indexer custody set is defined by', () => {
    // If this ever stops starting `treasury:` the address is registered, is visible in
    // `watched_addresses`, and is NOT in the custody set — the failure that looks most like a fix.
    assert.ok(treasuryLabel('ember', 'testnet').startsWith('treasury:'))
    assert.equal(treasuryLabel('ember', 'testnet'), 'treasury:ember:testnet')
    assert.equal(treasuryLabel('btc', 'mainnet'), 'treasury:btc:mainnet')
  })
})

describe('registering the treasury with the indexer', () => {
  it('THE FIX: a pinned treasury is registered under a treasury: label', { skip }, async () => {
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))

    const outcome = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(outcome.kind, 'registered')
    assert.deepEqual([...deps.indexer.watched], [
      { chain: 'ember', network: 'testnet', address: TREASURY, label: 'treasury:ember:testnet' },
    ])
    // The DISPLAY form custody published, not the lowercase comparison key. An operator reading
    // `watched_addresses` beside a freeze compares it against custody's pin by eye.
    assert.equal(deps.indexer.watched[0]?.address, TREASURY)
  })

  it('adopts a treasury pinned long before this code existed — no backfill is needed', { skip }, async () => {
    // The migration path, and there is deliberately no migration. `requireTreasury` adopts from
    // custody's pin when this service has no row, and the aggregate reads a live balance at a
    // confirmed height rather than replaying movements — so an address that has been quietly
    // accumulating swept coin for months becomes fully visible on the next observation.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    assert.equal(await findTreasury(deps.sql, 'ember', 'testnet'), null)

    const outcome = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(outcome.kind, 'registered')
    const row = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.equal(row?.address, TREASURY)
    assert.equal(row?.indexerWatchedKey, row?.addressKey)
  })

  it('is idempotent: a second pass makes no call at all', { skip }, async () => {
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))

    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')
    const second = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(second.kind, 'already_registered')
    // The job runs every five minutes for the life of the deployment. One POST per pass per chain
    // for ever is a real cost, and the reason the key is stored rather than the call repeated.
    assert.equal(deps.indexer.watched.length, 1)
  })

  it('an operator who has pinned nothing is not a fault, and must not dead-letter the job', { skip }, async () => {
    const deps = armed(harness(sql, { custody: fakeCustody() }))

    const outcome = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(outcome.kind, 'no_treasury')
    assert.equal(deps.indexer.watched.length, 0)
  })

  /* ------------------------------------------------------------ the three ways to get it wrong */

  it('THE FAILURE THAT MATTERS: a refused registration is NOT recorded as done', { skip }, async () => {
    // A missing `indexer:write` grant, or an indexer that is down. Writing the row here would say
    // "this treasury is in the custody set" about a treasury that is not — the exact shape of the
    // defect being repaired, and one nothing downstream could ever detect.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    deps.indexer.setWatchFails(true)

    await assert.rejects(() => registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet'))

    const row = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.equal(row?.indexerWatchedKey, null, 'a failed registration was recorded as successful')

    // And the next pass retries rather than believing the row. The work is deferred, never lost.
    deps.indexer.setWatchFails(false)
    const retry = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')
    assert.equal(retry.kind, 'registered')
    assert.equal((await findTreasury(deps.sql, 'ember', 'testnet'))?.indexerWatchedKey, row?.addressKey)
  })

  it('A ROTATION RE-REGISTERS, which a timestamp column could not have expressed', { skip }, async () => {
    // The reason migration 7 stores the KEY that was registered rather than the time it happened.
    // A rotation overwrites `address` and `address_key` in place, so `indexer_watched_at is null`
    // would report the NEW treasury as already registered and it would be invisible for ever —
    // the original defect surviving its own fix, on the address holding the most money.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    // An operator moves the balance and re-provisions. `allowRotation` is their statement that the
    // middle step is done.
    custody.pin('ember', 'testnet', ROTATED)
    await provisionTreasury(deps.treasuries, {
      chain: 'ember',
      network: 'testnet',
      operatorToken: OPERATOR,
      allowRotation: true,
    })
    const rotated = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.notEqual(rotated?.addressKey, undefined)
    assert.notEqual(rotated?.indexerWatchedKey, rotated?.addressKey)

    const outcome = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(outcome.kind, 'registered')
    assert.equal(deps.indexer.watched.length, 2)
    assert.equal(deps.indexer.watched[1]?.address, rotated?.address)
    // **The old address is never un-watched.** It is still an address the platform holds and it may
    // still hold dust; dropping it from the set would recreate this defect for whatever is left.
    assert.equal(deps.indexer.watched[0]?.address, TREASURY)
  })

  it('a rotation IN PROGRESS registers the address the balance is still at', { skip }, async () => {
    // `requireTreasury` deliberately does not adopt a pin that disagrees with the payout row, so
    // this returns the OLD treasury — and registering it is right, because that is where the money
    // is. The new one registers when the operator finishes the rotation, on the pass after.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    custody.pin('ember', 'testnet', ROTATED)
    const midRotation = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(midRotation.kind, 'already_registered')
    assert.equal(midRotation.kind === 'already_registered' ? midRotation.address : null, TREASURY)
    assert.equal(deps.indexer.watched.length, 1)
  })

  it('every implemented chain gets its own registration, keyed per chain and network', { skip }, async () => {
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    custody.pin('ethereum', 'testnet', ROTATED)
    const deps = armed(harness(sql, { custody }))

    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')
    await registerTreasuryWithIndexer(deps.treasuryWatch, 'eth', 'testnet')

    // custody's vocabulary is `ethereum`; the indexer's and this service's slug is `eth`. The label
    // and the path must both use the INDEXER's, or the address lands under a scope nothing sums.
    assert.deepEqual(
      deps.indexer.watched.map((w) => `${w.chain}|${w.label}`),
      ['ember|treasury:ember:testnet', 'eth|treasury:eth:testnet'],
    )
  })
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE OPENING BALANCE — micro-org#248
 *
 * The block above proves the address ends up in the aggregate. Every case below is about the half
 * that was missing, and the reason EMBER froze for three days while the platform held MORE coin
 * than it owed: **watching an address raises one side of the solvency comparison and nothing
 * raises the other.** Registering is not the operation. Registering AND booking is the operation,
 * and the tests that matter are the ones that pin down what is booked, when it is measured, and
 * what happens to a pass that dies half way.
 *
 * `docs/ecosystem/35-chain-solvency-invariant.md` is the design. Its Step 2 asks for a test that
 * fails without the fix, in as many words: *"a fix that nothing asserts is a fix that will be
 * undone"*.
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

describe('the treasury opening balance', () => {
  it('THE REGRESSION: registering float books it, so the aggregate and the ledger rise together', { skip }, async () => {
    // Without the fix this test's ledger stays empty, the indexer's custody total rises by FLOAT,
    // and `micro-ledger` records `drift -25000020999999996000` and freezes the asset. That is not
    // a hypothetical: it is micro-org#247, replayed at the amount it actually happened at.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))

    const outcome = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(outcome.kind, 'registered')
    assert.equal(deps.ledger.entries.length, 1)
    const entry = deps.ledger.entries[0]
    // Outside `WITHDRAWAL_KINDS`, which is what lets this entry post into a FROZEN asset — the
    // state the estate is in when this code first reaches it.
    assert.equal(entry?.kind, 'reconciliation_correction')
    assert.equal(entry?.idempotencyKey, `settlement:treasury-opening:ember:testnet:${TREASURY.toLowerCase()}`)
    assert.deepEqual(
      entry?.postings.map((p) => ({ direction: p.direction, amount: p.amount, account: p.account })),
      [
        // The custody ASSET, which is the side `micro-ledger` sums for the ledger half of the
        // comparison (`ledger/src/reconcile.ts`, `totalFor`). Any other account and the entry
        // balances perfectly while reconciliation stays exactly as broken as it was.
        { direction: 'debit', amount: FLOAT, account: custodyAccount('EMBER') },
        // Platform EQUITY, not a user liability. Booking the float as something owed would say a
        // customer could withdraw it, which converts an imaginary shortfall into a real one.
        { direction: 'credit', amount: FLOAT, account: treasuryEquityAccount('EMBER') },
      ],
    )

    const row = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.equal(row?.openingAmount, FLOAT)
    assert.equal(row?.openingEntryId, 'entry-1')
    assert.notEqual(row?.openingBookedAt, null)
  })

  it('books the ADDRESS’S OWN BALANCE, to the wei, and never a rounded or aggregate figure', { skip }, async () => {
    // The design's whole safety property. A service that books "the drift" papers over the exact
    // loss the check exists to find; a service that books a measurement of one named address
    // leaves a genuine shortfall exactly as visible as it was.
    const odd = 900_020_999_999_996_001n
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }), odd)

    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(deps.ledger.entries[0]?.postings[0]?.amount, odd)
    assert.equal((await findTreasury(deps.sql, 'ember', 'testnet'))?.openingAmount, odd)
  })

  it('MEASURES BEFORE IT WATCHES, so a failed watch leaves nothing to reconcile against', { skip }, async () => {
    // The ordering is the difference between a crash that heals and a crash that reproduces the
    // incident. Measure-then-watch: a failure leaves the aggregate untouched and no row written.
    // Watch-then-measure: the aggregate counts an address the ledger knows nothing about, which is
    // precisely the window EMBER froze in.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    deps.indexer.setWatchFails(true)

    await assert.rejects(() => registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet'))

    assert.deepEqual([...deps.indexer.measured], [TREASURY], 'the balance was not read before watching')
    assert.equal(deps.indexer.watched.length, 0)
    assert.equal(deps.ledger.entries.length, 0, 'coin was booked that the aggregate never counted')
    const row = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.equal(row?.indexerWatchedKey, null)
    assert.equal(row?.openingBookedAt, null)
  })

  it('A CRASH BETWEEN WATCHING AND BOOKING HEALS on the next pass, and does not re-watch', { skip }, async () => {
    // The half-done state is the dangerous one — it IS the incident, held open — so the row must
    // remember that it owes an opening and the job must finish it without being told.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    deps.ledger.failNext(new Error('the ledger is down'))

    await assert.rejects(() => registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet'))

    const half = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.equal(half?.indexerWatchedKey, half?.addressKey, 'the watch was accepted and must be recorded')
    assert.equal(half?.openingBookedAt, null, 'a failed booking was recorded as done')

    const healed = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    // Its own outcome, and its own metric in `jobs.ts`, because an operator wants to know the
    // estate spent a pass in the window the incident lives in — not merely that it has left it.
    assert.equal(healed.kind, 'booked')
    assert.equal(healed.kind === 'booked' ? healed.openingAmount : null, FLOAT)
    assert.equal(deps.indexer.watched.length, 1, 'a healed pass re-registered an address it already had')
    assert.equal(deps.ledger.entries.length, 1)
    const row = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.equal(row?.openingAmount, FLOAT)
    assert.notEqual(row?.openingBookedAt, null)

    // And it settles. A third pass is the steady state the job spends the rest of its life in.
    assert.equal((await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')).kind, 'already_registered')
    assert.equal(deps.indexer.measured.length, 2, 'the steady state is still reading balances')
  })

  it('an address holding nothing books NO ENTRY, and is still recorded as booked', { skip }, async () => {
    // The ledger refuses a zero posting and is right to: an entry that moves nothing is a row
    // claiming something happened. But the row must still be marked, or every pass for the life of
    // the deployment would re-measure and the sweep guard below would refuse for ever.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }), 0n)

    const outcome = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(outcome.kind, 'registered')
    assert.equal(outcome.kind === 'registered' ? outcome.openingAmount : -1n, 0n)
    assert.equal(outcome.kind === 'registered' ? outcome.openingEntryId : 'x', null)
    assert.equal(deps.ledger.entries.length, 0)
    const row = await findTreasury(deps.sql, 'ember', 'testnet')
    assert.equal(row?.openingAmount, 0n)
    assert.equal(row?.openingEntryId, null)
    assert.notEqual(row?.openingBookedAt, null)
    assert.equal((await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')).kind, 'already_registered')
  })

  it('A ROTATION WATCHES THE NEW ADDRESS AND BOOKS NOTHING, because that coin is booked already', { skip }, async () => {
    // The mirror-image error, and the one that involves the most money. A rotation's documented
    // middle step is MOVE THE BALANCE, so the new address holds coin that came out of an address
    // the aggregate already counts and the ledger already booked. The aggregate does not move —
    // the old address is never un-watched — so booking again doubles the ledger's custody total
    // and freezes the asset from the other side, with a wrong number standing in the books.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    custody.pin('ember', 'testnet', ROTATED)
    await provisionTreasury(deps.treasuries, {
      chain: 'ember',
      network: 'testnet',
      operatorToken: OPERATOR,
      allowRotation: true,
    })
    const outcome = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(outcome.kind, 'registered')
    assert.equal(outcome.kind === 'registered' ? outcome.openingAmount : 0n, null)
    assert.equal(deps.indexer.watched.length, 2, 'the rotated address must still enter the aggregate')
    assert.equal(deps.ledger.entries.length, 1, 'the float was booked twice')
    // It does not even ASK. A rotation that failed on an indexer outage would leave the new
    // treasury out of the custody set for the length of the outage, which is the original defect.
    assert.deepEqual([...deps.indexer.measured], [TREASURY])
  })

  it('a replayed post does not overwrite the row with a second entry id', { skip }, async () => {
    // The lost-response case: the ledger posted, the answer never arrived, the job runs again. The
    // idempotency key makes the LEDGER post once; `where opening_booked_at is null` makes this
    // service record it once.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))

    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')
    // Force a second booking pass over a row that is already booked, exactly as a crash between
    // the post and the update would produce.
    // All four columns, because `treasury_opening_is_whole` refuses any other combination — an
    // amount without a booking time is a row that says it measured something and never wrote it
    // down. Step 4 sets the four in one statement, so a crash before it leaves exactly this.
    await deps.sql`
      update treasuries
         set opening_booked_at = null, opening_entry_id = null,
             opening_amount = null, opening_observed_block = null
       where chain = 'ember'
    `
    const again = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(again.kind, 'booked')
    assert.equal(deps.ledger.keys.length, 2, 'the second pass did not attempt a post at all')
    assert.equal(deps.ledger.entries.length, 1, 'the same opening was booked twice')
    assert.equal((await findTreasury(deps.sql, 'ember', 'testnet'))?.openingEntryId, 'entry-1')
  })
})

describe('sweeping into a treasury that is not booked yet', () => {
  it('IS REFUSED, because a sweep in that window is counted twice and the count is the freeze', { skip }, async () => {
    // Watched and unbooked is the half-done state. A sweep into it moves customer coin from a
    // deposit address the aggregate counts into a treasury the aggregate ALSO counts, so the chain
    // side is unchanged — but the ledger side is about to gain an opening entry measured AFTER the
    // sweep landed, which books the swept customer coin as platform float on top of the deposit
    // credit that already booked it. Refusing costs one sweep cycle. Not refusing invents money.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))
    deps.ledger.failNext(new Error('the ledger is down'))
    await assert.rejects(() => registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet'))

    await assert.rejects(
      () => assertSweepable(deps.treasuries, 'ember', 'testnet'),
      TreasuryNotBookedError,
    )

    // And it opens again the moment the opening is booked, without an operator touching anything.
    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')
    const { treasury } = await assertSweepable(deps.treasuries, 'ember', 'testnet')
    assert.equal(treasury.address, TREASURY)
  })

  it('is PERMITTED into a treasury nobody has registered yet, which is not the same state', { skip }, async () => {
    // Unwatched means the treasury is not in the aggregate at all, so a sweep into it shrinks the
    // chain side and leaves the ledger side alone — the ORIGINAL defect, which is bad but is not
    // double counting, and which the opening entry repairs when registration finally happens
    // because it measures whatever is there by then. Refusing here would stop sweeping outright on
    // any estate whose indexer is down, and stopping sweeps is how deposits strand.
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    const deps = armed(harness(sql, { custody }))

    const { treasury } = await assertSweepable(deps.treasuries, 'ember', 'testnet')

    assert.equal(treasury.indexerWatchedKey, null)
    assert.equal(treasury.openingBookedAt, null)
  })
})
