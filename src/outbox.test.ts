/**
 * Outbox, relay and inbox.
 *
 * The property that matters here is the one word in rule 5: an event is written **in the same
 * transaction as the change**. A publish after commit is skipped when the process dies in between,
 * and a publish before commit is a publish of something that never happened. Both are silent.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import {
  EVENT_ID_HEADER,
  SIGNATURE_HEADER,
  classifyEnvelope,
  verifyDelivery,
} from '@cloudsforge/contracts-events'
import { createRelay, signEvent, verifyEventSignature, withInbox, withOutbox, type Db } from './outbox.ts'
import { enabled, migrateTestDb, openDb, quietLogger, resetSettlement, skip } from './testsupport.ts'

const SECRET = 'an-event-signing-secret-00000000'

describe('event signatures', () => {
  it('verifies the exact bytes and refuses anything else', () => {
    const body = '{"id":"1"}'
    assert.ok(verifyEventSignature(body, SECRET, signEvent(body, SECRET)))
    assert.equal(verifyEventSignature(body, SECRET, signEvent(body, 'other-secret')), false)
    assert.equal(verifyEventSignature(`${body} `, SECRET, signEvent(body, SECRET)), false)
    // Length-mismatched input must be a plain false and never reach `timingSafeEqual`, which throws
    // on unequal lengths — a throw here would be a 500 on an event route reachable pre-auth.
    assert.equal(verifyEventSignature(body, SECRET, 'sha256=short'), false)
    assert.equal(verifyEventSignature(body, SECRET, ''), false)
  })
})

describe('the outbox', { skip }, () => {
  let sql: postgres.Sql
  let db: Db

  before(async () => {
    if (!enabled) return
    sql = openDb()
    db = sql as unknown as Db
    await migrateTestDb(sql)
  })
  after(async () => {
    if (enabled) await sql.end({ timeout: 5 })
  })
  beforeEach(async () => {
    if (enabled) await resetSettlement(sql)
  })

  it('writes the event with the change, or writes neither', async () => {
    await assert.rejects(
      withOutbox(db, 'settlement', async (tx, emit) => {
        await tx`insert into treasuries (chain, network, address, address_key, custody_chain,
                 custody_family, custody_user_id, custody_order_id)
                 values ('ember','testnet','0x1','0x1','ember','ember','u','o')`
        emit({ topic: 'settlement.test', key: 'k', payload: {} })
        throw new Error('the change failed after the emit')
      }),
      /the change failed after the emit/,
    )
    // Neither. An event for a change that was rolled back is a lie that nothing downstream can
    // detect.
    assert.equal((await sql`select count(*)::int as n from outbox`)[0]!.n, 0)
    assert.equal((await sql`select count(*)::int as n from treasuries`)[0]!.n, 0)
  })

  it('delivers to the live subscription set and marks published only when nothing is outstanding', async () => {
    const delivered: Array<{ body: Record<string, unknown>; headers: Record<string, string> }> = []
    await withOutbox(db, 'settlement', async (_tx, emit) => {
      emit({ topic: 'settlement.outbound.confirmed', key: 'w1', payload: { withdrawalId: 'w1' } })
    })
    await sql`
      insert into event_subscriptions (topic, url)
      values ('settlement.outbound.confirmed', 'http://wallet/v1/events')
    `

    const relay = createRelay({
      sql: db,
      logger: quietLogger(),
      signingSecret: SECRET,
      clientFor: () => ({
        async request(_path, options) {
          delivered.push({
            body: options!.body as Record<string, unknown>,
            headers: (options!.headers ?? {}) as Record<string, string>,
          })
          return undefined as never
        },
      }),
    })
    await relay({ id: 'j', kind: 'outbox.relay', key: 'stream', attempts: 1, maxAttempts: 5, payload: {} }, {
      heartbeat: async () => true,
      signal: new AbortController().signal,
    })

    assert.equal(delivered.length, 1)
    const sent = delivered[0]!
    // A subscriber added AFTER the event was written still receives it: the delivery set is computed
    // from the live subscription list on every pass rather than fixed when the event was produced.
    assert.equal(sent.body['topic'], 'settlement.outbound.confirmed')

    // ── WHAT ACTUALLY GOES ON THE WIRE ──────────────────────────────────────────────────────────
    // Every one of these was wrong, and every one of them was invisible because this suite only
    // ever looked at the topic. A consumer refuses the delivery before it parses the body, so the
    // symptom is not a wrong answer — it is silence.
    assert.equal(sent.headers[SIGNATURE_HEADER], sent.headers['cf-signature'])
    assert.match(sent.headers['cf-signature'] ?? '', /^t=\d+,v1=[0-9a-f]{64}$/)
    assert.equal(sent.headers['cf-event-id'], sent.body['id'])
    assert.equal(sent.headers[EVENT_ID_HEADER], sent.body['id'])
    // The pre-contract names must be gone, not merely accompanied.
    assert.equal(sent.headers['x-cloudsforge-signature'], undefined)
    assert.equal(sent.headers['x-event-id'], undefined)
    // "major.minor", never the stored integer. `actor` and `correlationId` are never null.
    assert.equal(sent.body['version'], '1.0')
    assert.equal(sent.body['actor'], 'service:settlement')
    assert.equal(sent.body['correlationId'], sent.body['id'])
    // And the whole envelope is one the contract's own verifier accepts, signed over exactly the
    // bytes `HttpClient` will send.
    assert.equal(classifyEnvelope(sent.body).ok, true)
    assert.equal(verifyDelivery(JSON.stringify(sent.body), sent.headers['cf-signature']!, SECRET).ok, true)

    const published = await sql<Array<{ published_at: Date | null }>>`select published_at from outbox`
    assert.ok(published[0]!.published_at)
  })

  /**
   * A handler that FAILS must leave no inbox row.
   *
   * The insert and the handler share one transaction, so the redelivery is processed rather than
   * swallowed — which is the mistake that makes a naive "record then handle" dedupe lose events. In
   * this service losing one is a user whose balance is reserved and whose payment is never built.
   */
  it('runs a handler exactly once, and not at all when it fails', async () => {
    const eventId = '33333333-3333-4333-8333-333333333333'
    let runs = 0
    await assert.rejects(
      withInbox(db, 'wallet.withdrawal.requested', eventId, async () => {
        runs += 1
        throw new Error('handler failed')
      }),
      /handler failed/,
    )
    assert.equal((await sql`select count(*)::int as n from inbox`)[0]!.n, 0)

    const first = await withInbox(db, 'wallet.withdrawal.requested', eventId, async () => {
      runs += 1
      return 'ok'
    })
    const second = await withInbox(db, 'wallet.withdrawal.requested', eventId, async () => {
      runs += 1
      return 'ok'
    })
    assert.equal(first.status, 'processed')
    assert.equal(second.status, 'duplicate')
    assert.equal(runs, 2, 'the failed attempt and the successful one; never the redelivery')
  })
})
