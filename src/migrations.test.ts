/**
 * The schema, exercised as a migrator on an empty database.
 *
 * Not a fixture schema built by the test suite: a fixture would let the constraints drift out of
 * the tests that are supposed to prove they fire, and one of them —
 * `outbound_in_flight_uniq` — is the single most important line in this repository.
 */

import assert from 'node:assert/strict'
import { after, before, describe, it } from 'node:test'
import type postgres from 'postgres'
import { assertSchemaAtLeast, migrate, type Sql as DbSql } from '@cloudsforge/db'
import { BASELINE_VERSION, MIGRATIONS, SCHEMA_VERSION, TABLES } from './migrations.ts'
import { enabled, migrateTestDb, openDb, resetSettlement, skip } from './testsupport.ts'

describe('the migration set', () => {
  it('has monotonically increasing, unique versions', () => {
    const versions = MIGRATIONS.map((m) => m.version)
    assert.deepEqual(versions, [...versions].sort((a, b) => a - b))
    assert.equal(new Set(versions).size, versions.length)
    assert.equal(SCHEMA_VERSION, Math.max(...versions))
  })

  it('has no baseline, because this service has no predecessor database', () => {
    // forge-pay's withdrawal and sweep rows live in `pay`, which this service does not connect to
    // and will not adopt: the state machines differ, so migrating that data is a one-off backfill
    // and not a baseline.
    assert.equal(BASELINE_VERSION, 0)
  })
})

describe('running the migrator', { skip }, () => {
  let sql: postgres.Sql

  before(async () => {
    if (!enabled) return
    sql = openDb(2)
    await migrateTestDb(sql)
    await resetSettlement(sql)
  })
  after(async () => {
    if (enabled) await sql.end({ timeout: 5 })
  })

  it('is idempotent and reaches the version the service asserts', async () => {
    const again = await migrate(sql as unknown as DbSql, MIGRATIONS, { service: 'settlement-test' })
    assert.deepEqual(again.applied, [], 'a second run must apply nothing')
    assert.equal(again.nowAt, SCHEMA_VERSION)
    // The assertion `index.ts` makes at boot, which is what stops a replica of the new code serving
    // against a schema whose in-flight index may not exist.
    await assertSchemaAtLeast(sql as unknown as DbSql, SCHEMA_VERSION)
  })

  it('creates every table the harness truncates', async () => {
    const rows = await sql<Array<{ table_name: string }>>`
      select table_name from information_schema.tables where table_schema = 'public'
    `
    const present = new Set(rows.map((r) => r.table_name))
    for (const table of [...TABLES, 'jobs', 'schema_migrations']) {
      assert.ok(present.has(table), `${table} is missing from the schema`)
    }
  })

  /**
   * The lease's own foundation.
   *
   * A jobs table missing the `(kind, key)` unique constraint would silently turn the chain lease
   * into no lease at all: two `chain.outbound / ember:testnet` rows would both be claimable and two
   * workers would sign against one nonce.
   */
  it('carries the jobs unique constraint the lease depends on', async () => {
    const rows = await sql<Array<{ conname: string }>>`
      select conname from pg_constraint where conrelid = 'jobs'::regclass and contype = 'u'
    `
    assert.ok(rows.some((r) => r.conname === 'jobs_kind_key_uniq'))
  })

  it('carries the in-flight index, partial over exactly the in-flight states', async () => {
    const rows = await sql<Array<{ indexdef: string }>>`
      select indexdef from pg_indexes
       where tablename = 'outbound_transactions' and indexname = 'outbound_in_flight_uniq'
    `
    assert.equal(rows.length, 1, 'the invariant is missing from the schema')
    const definition = rows[0]!.indexdef
    assert.match(definition, /CREATE UNIQUE INDEX/)
    assert.match(definition, /\(chain, network\)/)
    // `planned` must NOT be in the predicate: it is the queue, and a chain may have any number of
    // payments waiting. In flight begins at `building`, the moment a nonce is about to be read.
    assert.match(definition, /building/)
    assert.match(definition, /signed/)
    assert.match(definition, /broadcast/)
    assert.doesNotMatch(definition, /'planned'/)
  })

  it('carries the idempotency constraint that makes a redelivered request one payment', async () => {
    const rows = await sql<Array<{ conname: string }>>`
      select conname from pg_constraint
       where conrelid = 'outbound_transactions'::regclass and contype = 'u'
    `
    assert.ok(rows.some((r) => r.conname === 'outbound_transactions_idempotency_uniq'))
  })

  it('refuses a state or a purpose outside the closed sets', async () => {
    // The check constraints are the schema's own statement of the state machine. A row that reached
    // an unlisted state would be a row no worker knows how to advance and no operator can find.
    await assert.rejects(
      sql`
        insert into outbound_transactions
          (purpose, chain, network, from_address, from_address_key, to_address, to_address_key,
           asset_code, amount, fee, state, idempotency_key)
        values ('withdrawal','ember','testnet','a','a','b','b','EMBER',1,1,'settled','k1')
      `,
      /outbound_transactions_state_ck/,
    )
    await assert.rejects(
      sql`
        insert into outbound_transactions
          (purpose, chain, network, from_address, from_address_key, to_address, to_address_key,
           asset_code, amount, fee, state, idempotency_key)
        values ('refund','ember','testnet','a','a','b','b','EMBER',1,1,'planned','k2')
      `,
      /outbound_transactions_purpose_ck/,
    )
  })

  /**
   * numeric(78,0) holds a uint256 exactly. A float would lose the least significant digits, which
   * is where a reconciliation drift shows up — and 18-decimal amounts spend most of their life in
   * that range.
   */
  it('stores a uint256 amount exactly', async () => {
    const huge = (2n ** 255n).toString()
    await sql`
      insert into outbound_transactions
        (purpose, chain, network, from_address, from_address_key, to_address, to_address_key,
         asset_code, amount, fee, state, idempotency_key)
      values ('withdrawal','eth','mainnet','a','a','b','b','ETH',${huge},0,'planned','k3')
    `
    const rows = await sql<Array<{ amount: string }>>`
      select amount::text as amount from outbound_transactions where idempotency_key = 'k3'
    `
    assert.equal(rows[0]!.amount, huge)
    await resetSettlement(sql)
  })
})
