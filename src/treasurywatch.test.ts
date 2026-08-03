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
import { treasuryLabel } from './indexerclient.ts'
import { findTreasury, provisionTreasury, registerTreasuryWithIndexer } from './treasury.ts'
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
    const deps = harness(sql, { custody })

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
    const deps = harness(sql, { custody })
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
    const deps = harness(sql, { custody })

    await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')
    const second = await registerTreasuryWithIndexer(deps.treasuryWatch, 'ember', 'testnet')

    assert.equal(second.kind, 'already_registered')
    // The job runs every five minutes for the life of the deployment. One POST per pass per chain
    // for ever is a real cost, and the reason the key is stored rather than the call repeated.
    assert.equal(deps.indexer.watched.length, 1)
  })

  it('an operator who has pinned nothing is not a fault, and must not dead-letter the job', { skip }, async () => {
    const deps = harness(sql, { custody: fakeCustody() })

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
    const deps = harness(sql, { custody })
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
    const deps = harness(sql, { custody })
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
    const deps = harness(sql, { custody })
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
    const deps = harness(sql, { custody })

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
