/**
 * Right to erasure, settlement's half.
 *
 * The assertions that matter are the ones about what erasure must NOT break. This service is the
 * only holder of the signed bytes behind a payment and of the custody binding that makes a deposit
 * address sweepable, and an erasure that quietly damages either has cost somebody real money in
 * the name of protecting them.
 */

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { eraseUser, erasureInstant, userIdForms, UUID } from './erasure.ts'
import { enabled, migrateTestDb, openDb, resetSettlement, skip, testAddress } from './testsupport.ts'
import type { Db, Tx } from './outbox.ts'

let sql: postgres.Sql

const ALICE = '11111111-1111-4111-8111-111111111111'
const BOB = '22222222-2222-4222-8222-222222222222'
const TOMBSTONE = '2026-09-01T00:00:00.000Z'

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

async function erase(
  userId: string,
  at = new Date(TOMBSTONE),
): Promise<Awaited<ReturnType<typeof eraseUser>>> {
  const outcome = await (sql as unknown as Db).begin(async (tx) => ({
    value: await eraseUser(tx as unknown as Tx, userId, at),
  }))
  return outcome.value
}

async function seedOutbound(
  userId: string | null,
  state: string,
  key: string,
): Promise<string> {
  const rows = await sql<Array<{ id: string }>>`
    insert into outbound_transactions (
      purpose, chain, network, from_address, from_address_key, to_address, to_address_key,
      asset_code, amount, fee, state, raw_tx, tx_hash, source_ref, user_id,
      reservation_entry_id, idempotency_key
    )
    values (
      'withdrawal', 'eth', 'testnet', ${testAddress(1)}, ${testAddress(1)},
      ${testAddress(2)}, ${testAddress(2)}, 'ETH', 1000, 21, ${state},
      '0xdeadbeef', ${`0xhash-${key}`}, ${`withdrawal-${key}`}, ${userId},
      ${`reservation-${key}`}, ${`idem-${key}`}
    )
    returning id
  `
  return rows[0]!.id
}

async function seedSweepSource(custodyUserId: string, key: string): Promise<string> {
  const rows = await sql<Array<{ id: string }>>`
    insert into sweep_sources (
      chain, network, address, address_key, custody_chain, custody_family, custody_user_id,
      custody_order_id, swept
    )
    values (
      'eth', 'testnet', ${`0xdeposit${key}`}, ${`0xdeposit${key}`}, 'ethereum', 'evm',
      ${custodyUserId}, ${`order-${key}`}, 500
    )
    returning id
  `
  return rows[0]!.id
}

test('both spellings of a user id are matched, bare first', { skip }, () => {
  // Bare is the live form here — it comes straight off wallet's withdrawal event — but the register
  // route takes `custodyUserId` as an opaque string, so the other form is matched too.
  assert.deepEqual(userIdForms(ALICE), [ALICE, `user:${ALICE}`])
})

test('the erasure is anchored at the event"s tombstone, not at delivery time', { skip }, () => {
  // The retention clock an auditor checks runs from the deletion request, not from whenever a relay
  // happened to succeed.
  assert.deepEqual(erasureInstant(TOMBSTONE), new Date(TOMBSTONE))
  const fallback = new Date('2026-01-01T00:00:00.000Z')
  assert.deepEqual(erasureInstant(undefined, fallback), fallback)
  assert.deepEqual(erasureInstant('not a date', fallback), fallback)
  // Never null: a null would be indistinguishable from a row that was never erased at all.
  assert.notEqual(erasureInstant('', fallback), null)
})

test('an erased outbound transaction names nobody and keeps its evidence', { skip }, async () => {
  const id = await seedOutbound(ALICE, 'confirmed', 'a')
  const counts = await erase(ALICE)
  assert.equal(counts.outbound, 1)

  const row = await sql<
    Array<{
      user_id: string | null
      erased_at: Date | null
      raw_tx: string | null
      tx_hash: string | null
      to_address: string
      reservation_entry_id: string | null
      source_ref: string | null
    }>
  >`
    select user_id, erased_at, raw_tx, tx_hash, to_address, reservation_entry_id, source_ref
      from outbound_transactions where id = ${id}
  `
  assert.equal(row[0]?.user_id, null)
  assert.deepEqual(row[0]?.erased_at, new Date(TOMBSTONE))
  // THE EVIDENCE. These are what prove the withdrawal was authorised and where it went, and they
  // are on a public chain whatever this database says.
  assert.equal(row[0]?.raw_tx, '0xdeadbeef')
  assert.equal(row[0]?.tx_hash, '0xhash-a')
  assert.equal(row[0]?.to_address, testAddress(2))
  // And these are what settle the money. Nothing about the settlement path reads `user_id`.
  assert.equal(row[0]?.reservation_entry_id, 'reservation-a')
  assert.equal(row[0]?.source_ref, 'withdrawal-a')
})

test('erasure is distinguishable from a row that never had a user id', { skip }, async () => {
  // `withdrawals.ts:544` documents a null user_id as "a row that predates the column being
  // written". Without `erased_at` the two states would be the same row, and an audit could not tell
  // an erasure that happened from one that never did.
  const legacy = await seedOutbound(null, 'confirmed', 'legacy')
  const mine = await seedOutbound(ALICE, 'confirmed', 'mine')
  await erase(ALICE)

  const rows = await sql<Array<{ id: string; erased_at: Date | null }>>`
    select id, erased_at from outbound_transactions order by idempotency_key
  `
  const byId = new Map(rows.map((row) => [row.id, row.erased_at]))
  assert.equal(byId.get(legacy), null)
  assert.notEqual(byId.get(mine), null)
})

test('THE ONE THAT WOULD STRAND MONEY: the custody binding survives', { skip }, async () => {
  const id = await seedSweepSource(ALICE, 'a')
  const counts = await erase(ALICE)
  assert.equal(counts.sweepSources, 1)

  const row = await sql<
    Array<{
      custody_user_id: string
      custody_order_id: string
      swept: string
      active: boolean
      erased_at: Date | null
    }>
  >`
    select custody_user_id, custody_order_id, swept, active, erased_at
      from sweep_sources where id = ${id}
  `
  // custody compares these character for character before it will sign. Null either one and every
  // coin at this address is unreachable for ever.
  assert.equal(row[0]?.custody_user_id, ALICE)
  assert.equal(row[0]?.custody_order_id, 'order-a')
  // The high-water mark is monotonic. Resetting it would make the next pass pay a fee to re-sweep
  // what has already moved.
  assert.equal(row[0]?.swept, '500')
  // Still swept: a deposit address whose owner has gone must still be drained, or the coin sitting
  // at it is confiscated by inaction.
  assert.equal(row[0]?.active, true)
  assert.notEqual(row[0]?.erased_at, null)
})

test('an erased row cannot be re-attributed or un-erased, even from psql', { skip }, async () => {
  const outbound = await seedOutbound(ALICE, 'confirmed', 'a')
  const source = await seedSweepSource(ALICE, 'a')
  await erase(ALICE)

  await assert.rejects(
    () => sql`update outbound_transactions set user_id = ${BOB} where id = ${outbound}`,
    /cannot be re-attributed/,
  )
  await assert.rejects(
    () => sql`update outbound_transactions set erased_at = null where id = ${outbound}`,
    /cannot be un-erased/,
  )
  await assert.rejects(
    () => sql`update sweep_sources set custody_user_id = ${BOB} where id = ${source}`,
    /cannot be re-attributed/,
  )
})

test('the schema refuses a half-finished erasure', { skip }, async () => {
  const id = await seedOutbound(ALICE, 'confirmed', 'a')
  // A handler that stamped the timestamp and forgot to clear the user id would look like it worked.
  await assert.rejects(
    () => sql`update outbound_transactions set erased_at = now() where id = ${id}`,
    /outbound_erased_names_no_user/,
  )
})

test('an in-flight withdrawal is erased and left running', { skip }, async () => {
  // Deferring until the chain confirms would mean holding the identifier for an unbounded time
  // decided by a third party, and would need a job — a second place to forget the work.
  const id = await seedOutbound(ALICE, 'broadcast', 'a')
  const counts = await erase(ALICE)
  assert.equal(counts.outbound, 1)
  assert.equal(counts.outboundInFlight, 1)

  const row = await sql<Array<{ state: string; raw_tx: string | null; user_id: string | null }>>`
    select state, raw_tx, user_id from outbound_transactions where id = ${id}
  `
  assert.equal(row[0]?.state, 'broadcast')
  assert.equal(row[0]?.raw_tx, '0xdeadbeef')
  assert.equal(row[0]?.user_id, null)
})

test('a treasury is untouched, because it belongs to nobody', { skip }, async () => {
  // The issue listed treasuries.custody_user_id as an owner reference. It is the literal
  // 'cloudsforge:treasury' — the platform's own custody account for its own address.
  await sql`
    insert into treasuries (
      chain, network, address, address_key, custody_chain, custody_family, custody_user_id,
      custody_order_id
    )
    values (
      'eth', 'testnet', ${testAddress(9)}, ${testAddress(9)}, 'ethereum', 'evm',
      'cloudsforge:treasury', 'treasury-order'
    )
  `
  await erase(ALICE)
  const row = await sql<Array<{ custody_user_id: string }>>`select custody_user_id from treasuries`
  assert.equal(row[0]?.custody_user_id, 'cloudsforge:treasury')
})

test('erasing one person does not touch another', { skip }, async () => {
  await seedOutbound(ALICE, 'confirmed', 'a')
  await seedOutbound(BOB, 'confirmed', 'b')
  await seedSweepSource(BOB, 'b')

  const counts = await erase(ALICE)
  assert.equal(counts.outbound, 1)
  assert.equal(counts.sweepSources, 0)

  const bob = await sql<Array<{ user_id: string | null; erased_at: Date | null }>>`
    select user_id, erased_at from outbound_transactions where idempotency_key = 'idem-b'
  `
  assert.equal(bob[0]?.user_id, BOB)
  assert.equal(bob[0]?.erased_at, null)
})

test('a redelivery erases nothing a second time', { skip }, async () => {
  await seedOutbound(ALICE, 'confirmed', 'a')
  await seedSweepSource(ALICE, 'a')
  await erase(ALICE)
  // `withInbox` makes this unreachable in production. Asserted anyway: at-least-once delivery plus
  // a handler that is not idempotent is a bug waiting for a relay retry.
  const again = await erase(ALICE)
  assert.deepEqual(again, { outbound: 0, sweepSources: 0, outboundInFlight: 0 })
})

/**
 * THE REGRESSION THAT SHIPPED, AND WHY EVERY TEST IN THIS FILE MISSED IT.
 *
 * `UUID` constrained the version nibble to `[1-5]` and the variant to `[89ab]` —
 * the RFC 4122 shape for versions 1 to 5. Every user id in this estate is a
 * **UUIDv7**: 04-domain-model section 0 requires it, and `identity/src/ids.ts`
 * mints them. So the handler answered 400 to every real erasure event, the relay
 * retried the same event for ever, and the person's rows stayed exactly where
 * they were while the account service reported the deletion as complete.
 *
 * Every test in this file passed the whole time, because the fixtures are v4
 * uuids. Both sides of the test agreed with each other and neither agreed with
 * the producer, which is the failure mode a fixture shared between a test and
 * the code under test cannot detect.
 *
 * The literal below is a real UUIDv7 as identity emits it: 48 bits of Unix
 * milliseconds, then the version nibble `7`. It is not derived from anything in
 * this repository on purpose — a fixture generated by this test would drift back
 * to whatever this repository believes an id looks like, which is the bug.
 *
 * No database. It runs on every checkout, including one with no Postgres.
 */
test('the uuid pattern accepts a UUIDv7, which is the only kind identity mints', () => {
  assert.ok(UUID.test('019fd1a6-c82c-7000-9951-445d80d64a45'), 'a v7 user id must be accepted')
  // v4 stays accepted: event ids come from `gen_random_uuid()` and are v4.
  assert.ok(UUID.test('11111111-1111-4111-8111-111111111111'), 'a v4 event id must be accepted')
  // Still a uuid and nothing else — the shape is checked, the version is not.
  assert.ok(!UUID.test('not-a-uuid'))
  assert.ok(!UUID.test('019fd1a6-c82c-7000-9951-445d80d64a4'), 'one hex short is not a uuid')
  assert.ok(!UUID.test('019fd1a6c82c70009951445d80d64a45'), 'unhyphenated is not this shape')
})
