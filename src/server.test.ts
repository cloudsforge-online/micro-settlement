/**
 * The HTTP surface, over a real socket.
 *
 * The two routes worth the most attention are the ones the estate this replaces does worst: the
 * EVENT INTAKE, whose signature is verified before the body is parsed, and the ADJUDICATION ROUTE,
 * which is curl-only with no list and no audit in forge-pay.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import { createHmac, randomUUID } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import type postgres from 'postgres'
import { Lifecycle } from '@cloudsforge/lifecycle'
import { TokenError, type Principal } from '@cloudsforge/auth'
import { createServer } from './server.ts'
import { signEvent } from './outbox.ts'
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
  quietLogger,
  resetSettlement,
  skip,
  testAddress,
  withdrawalPayload,
} from './testsupport.ts'

const SECRET = 'an-event-signing-secret-00000000'
const TREASURY = testAddress(0x7)
const ALICE = testAddress(0xa1)

/** Principals by token string. No JWKS: the verifier is the seam and a test does not need one. */
const PRINCIPALS: Readonly<Record<string, Principal>> = {
  admin: { kind: 'user', userId: 'op-1', handle: 'op', roles: ['admin'] },
  user: { kind: 'user', userId: 'u-1', handle: 'u', roles: ['player'] },
  wallet: { kind: 'service', service: 'wallet', scopes: ['settlement:read', 'settlement:register'] },
  unscoped: { kind: 'service', service: 'nosy', scopes: [] },
}

describe('the HTTP surface', { skip }, () => {
  let sql: postgres.Sql
  let server: Server
  let base: string
  let deps: ReturnType<typeof harness>

  before(async () => {
    if (!enabled) return
    sql = openDb()
    await migrateTestDb(sql)
  })
  after(async () => {
    if (!enabled) return
    await new Promise<void>((resolve) => server.close(() => resolve()))
    await sql.end({ timeout: 5 })
  })

  beforeEach(async () => {
    if (!enabled) return
    await resetSettlement(sql)
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()))
    const node = fakeNode()
    node.setBalance(TREASURY, 100n * 10n ** 18n)
    const custody = fakeCustody()
    custody.pin('ember', 'testnet', TREASURY)
    deps = harness(sql, { node, custody, stuckMinutes: 60 })
    const lifecycle = new Lifecycle()
    lifecycle.markReady()
    server = createServer({
      lifecycle,
      logger: quietLogger(),
      metrics: deps.metrics,
      verifier: {
        async principal(token) {
          const principal = PRINCIPALS[token]
          if (!principal) throw new TokenError('unknown test token', 'invalid')
          return principal
        },
      },
      network: 'testnet',
    networks: ['testnet'] as const,
      outbound: deps.outbound,
      adjudication: deps.adjudication,
      withdrawals: deps.withdrawals,
      deployerFunding: deps.deployerFunding,
      treasuries: deps.treasuries,
      sweeps: deps.sweeps,
      eventSigningSecret: SECRET,
    })
    await new Promise<void>((resolve) => server.listen(0, () => resolve()))
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  })

  const call = async (
    path: string,
    options: { method?: string; token?: string; body?: unknown; headers?: Record<string, string> } = {},
  ): Promise<{ status: number; body: Record<string, unknown> }> => {
    const response = await fetch(`${base}${path}`, {
      method: options.method ?? 'GET',
      headers: {
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
        ...(options.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(options.headers ?? {}),
      },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    })
    const text = await response.text()
    return { status: response.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} }
  }

  /* ---------------------------------------------------------------- health */

  it('serves livez, readyz and metrics', async () => {
    assert.equal((await call('/livez')).status, 200)
    assert.equal((await call('/readyz')).status, 200)
    const metrics = await fetch(`${base}/metrics`)
    assert.equal(metrics.status, 200)
    assert.match(await metrics.text(), /settlement_signatures_total/)
  })

  it('echoes a request id and never caches an answer about money', async () => {
    const response = await fetch(`${base}/livez`, { headers: { 'x-request-id': 'abc-123' } })
    assert.equal(response.headers.get('x-request-id'), 'abc-123')
    assert.equal(response.headers.get('cache-control'), 'no-store')
  })

  /* ---------------------------------------------------------------- auth */

  it('maps a missing token to 401 and an unscoped one to 403', async () => {
    assert.equal((await call('/v1/outbound')).status, 401)
    assert.equal((await call('/v1/outbound', { token: 'nope' })).status, 401)
    assert.equal((await call('/v1/outbound', { token: 'unscoped' })).status, 403)
    assert.equal((await call('/v1/outbound', { token: 'user' })).status, 403)
    assert.equal((await call('/v1/outbound', { token: 'admin' })).status, 200)
  })

  /* ---------------------------------------------------------------- fees */

  it('quotes a live fee in the shape wallet already expects', async () => {
    const { status, body } = await call('/v1/fees/ember/testnet/EMBER', { token: 'wallet' })
    assert.equal(status, 200)
    // A decimal STRING. An 18-decimal fee does not survive a JSON number, and it does not fail —
    // it comes back subtly wrong.
    assert.equal(typeof body['fee'], 'string')
    assert.equal(BigInt(body['fee'] as string), 40_000_000_000n * 21_000n)
  })

  it('answers 501 for a chain with no adapter, naming the phase', async () => {
    // XRP, and it is the last one. BTC and SOL both had adapters withheld on the strength of
    // claims about custody that turned out to be wrong or stale; XRP is the honest case, where
    // custody signs it today and this service does not speak XRPL.
    const { status, body } = await call('/v1/fees/xrp/testnet/XRP', { token: 'wallet' })
    assert.equal(status, 501)
    assert.match(String((body['error'] as Record<string, unknown>)['message']), /XRPL adapter/)
  })

  it('refuses an asset that does not settle on the named chain', async () => {
    assert.equal((await call('/v1/fees/ember/testnet/ETH', { token: 'wallet' })).status, 400)
  })

  /* ---------------------------------------------------------------- events */

  /**
   * A delivery as one of the two producers on the wire today would actually make it.
   *
   * `'legacy'` is what `micro-wallet`'s relay sends RIGHT NOW — `wallet/src/outbox.ts,168`, a
   * local `x-cloudsforge-signature` carrying `sha256=<hmac over the body>`. It is the default here
   * for exactly that reason: the default has to be the thing that is really arriving, or this suite
   * would prove that the migration works and nothing about whether withdrawals still get in.
   *
   * `'contract'` is what every producer sends once it adopts `signDelivery`, and what THIS service
   * now sends. Both are exercised; see `verifyInbound` for why both are accepted and what deletes
   * the legacy arm.
   */
  const deliveryHeaders = (
    raw: string,
    secret: string,
    eventId: string,
    scheme: 'legacy' | 'contract',
  ): Record<string, string> =>
    scheme === 'contract'
      ? { 'cf-signature': signEvent(raw, secret), 'cf-event-id': eventId }
      : {
          'x-cloudsforge-signature': `sha256=${createHmac('sha256', secret).update(raw).digest('hex')}`,
          'x-event-id': eventId,
        }

  const post = async (
    payload: Record<string, unknown>,
    options: { secret?: string; scheme?: 'legacy' | 'contract' } = {},
  ) => {
    const envelope = {
      id: randomUUID(),
      topic: 'wallet.withdrawal.requested',
      key: 'w1',
      occurredAt: new Date().toISOString(),
      producer: 'wallet',
      version: 1,
      actor: null,
      correlationId: null,
      payload,
    }
    const raw = JSON.stringify(envelope)
    const response = await fetch(`${base}/v1/events`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...deliveryHeaders(raw, options.secret ?? SECRET, envelope.id, options.scheme ?? 'legacy'),
      },
      body: raw,
    })
    return { status: response.status, body: JSON.parse(await response.text()) as Record<string, unknown> }
  }

  it('plans a withdrawal from a correctly signed event', async () => {
    const { status, body } = await post(withdrawalPayload())
    assert.equal(status, 200)
    assert.deepEqual((body['decision'] as Record<string, unknown>)['kind'], 'planned')
    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 1)
  })

  /**
   * The same event under the CONTRACT's scheme, which is what wallet's relay sends once it adopts
   * `signDelivery`. Both arms are exercised at the HTTP layer, because the day one of them stops
   * working is a day every withdrawal request is a 401 and nothing else in this suite would say so.
   */
  it('plans a withdrawal from an event signed the contract way too', async () => {
    const { status, body } = await post(withdrawalPayload(), { scheme: 'contract' })
    assert.equal(status, 200)
    assert.deepEqual((body['decision'] as Record<string, unknown>)['kind'], 'planned')
  })

  /**
   * The signature is verified BEFORE the body is parsed. An unauthenticated body never reaches a
   * JSON parser, let alone the path that plans a payment.
   */
  it('refuses an event whose signature does not verify, and plans nothing', async () => {
    for (const scheme of ['legacy', 'contract'] as const) {
      const { status } = await post(withdrawalPayload(), {
        secret: 'the-wrong-secret-0000000000000000',
        scheme,
      })
      assert.equal(status, 401, `a forged ${scheme} signature must be refused`)
      const rows = await sql`select count(*)::int as n from outbound_transactions`
      assert.equal(rows[0]!.n, 0)
    }
  })

  it('refuses a delivery with no signature header at all', async () => {
    // Neither header present is not "no opinion", it is unauthenticated. Accepting the two schemes
    // must not have turned an absent header into a third, silent one.
    const raw = JSON.stringify({ id: randomUUID(), topic: 'wallet.withdrawal.requested', payload: {} })
    const response = await fetch(`${base}/v1/events`, { method: 'POST', body: raw })
    assert.equal(response.status, 401)
  })

  /**
   * A topic this service does not consume is 202, not 404.
   *
   * The relay treats any non-2xx as a delivery failure and retries for ever, so a 404 here would
   * pin a subscriber in a permanent retry loop over something neither side is wrong about.
   */
  it('answers 202 for a topic it does not consume', async () => {
    const id = randomUUID()
    const raw = JSON.stringify({ id, topic: 'indexer.deposit.confirmed', payload: {} })
    const response = await fetch(`${base}/v1/events`, {
      method: 'POST',
      headers: deliveryHeaders(raw, SECRET, id, 'contract'),
      body: raw,
    })
    assert.equal(response.status, 202)
  })

  /* ---------------------------------------------------------------- erasure */

  /**
   * The SECOND topic this service consumes, on the SAME route.
   *
   * These exercise the seam rather than the handler — `erasure.test.ts` covers what erasure does to
   * each table. What is asserted here is that the erasure reaches the database through the same
   * signature check and the same inbox as the withdrawal path, because a subscriber that verifies
   * differently on its second topic is a subscriber with two security postures.
   */
  const postErasure = async (
    userId: string,
    options: { id?: string; tombstoneAt?: string } = {},
  ) => {
    const id = options.id ?? randomUUID()
    const raw = JSON.stringify({
      id,
      topic: 'identity.user.deleted',
      key: userId,
      occurredAt: new Date().toISOString(),
      producer: 'identity',
      version: 1,
      actor: null,
      correlationId: null,
      payload: {
        userId,
        tombstoneAt: options.tombstoneAt ?? '2026-09-01T00:00:00.000Z',
        reason: 'user_requested',
      },
    })
    const response = await fetch(`${base}/v1/events`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...deliveryHeaders(raw, SECRET, id, 'contract'),
      },
      body: raw,
    })
    return {
      status: response.status,
      body: JSON.parse(await response.text()) as Record<string, unknown>,
      id,
    }
  }

  const ERASED_USER = '33333333-3333-4333-8333-333333333333'

  it('erases a user from a correctly signed identity.user.deleted', async () => {
    await post(withdrawalPayload({ userId: ERASED_USER }))
    const before = await sql<Array<{ n: number }>>`
      select count(*)::int as n from outbound_transactions where user_id = ${ERASED_USER}
    `
    assert.equal(before[0]!.n, 1)

    const { status, body } = await postErasure(ERASED_USER)
    assert.equal(status, 202)
    assert.equal(body['status'], 'erased')

    const after = await sql<Array<{ user_id: string | null; erased_at: Date | null; raw_tx: string | null }>>`
      select user_id, erased_at, raw_tx from outbound_transactions
    `
    assert.equal(after[0]?.user_id, null)
    assert.notEqual(after[0]?.erased_at, null)
  })

  it('dedupes a redelivered erasure through the inbox', async () => {
    await post(withdrawalPayload({ userId: ERASED_USER }))
    const first = await postErasure(ERASED_USER)
    assert.equal(first.body['status'], 'erased')
    // The same envelope id, as an at-least-once relay would resend it.
    const again = await postErasure(ERASED_USER, { id: first.id })
    assert.equal(again.status, 202)
    assert.equal(again.body['status'], 'duplicate')
  })

  it('refuses a forged erasure, and erases nothing', async () => {
    await post(withdrawalPayload({ userId: ERASED_USER }))
    const id = randomUUID()
    const raw = JSON.stringify({
      id,
      topic: 'identity.user.deleted',
      payload: { userId: ERASED_USER },
    })
    const response = await fetch(`${base}/v1/events`, {
      method: 'POST',
      headers: deliveryHeaders(raw, 'the-wrong-secret-0000000000000000', id, 'contract'),
      body: raw,
    })
    assert.equal(response.status, 401)
    const rows = await sql<Array<{ n: number }>>`
      select count(*)::int as n from outbound_transactions where user_id = ${ERASED_USER}
    `
    assert.equal(rows[0]!.n, 1)
  })

  it('a malformed erasure is 400 and stays visible, never absorbed into a 202', async () => {
    // The relay will retry it for ever, which is correct: an erasure this service cannot read is a
    // person whose data is still here while the deletion is being reported as done.
    const id = randomUUID()
    const raw = JSON.stringify({ id, topic: 'identity.user.deleted', payload: { userId: 'nope' } })
    const response = await fetch(`${base}/v1/events`, {
      method: 'POST',
      headers: deliveryHeaders(raw, SECRET, id, 'contract'),
      body: raw,
    })
    assert.equal(response.status, 400)
  })

  /* ---------------------------------------------------------------- adjudication */

  async function aStuckTransaction(): Promise<string> {
    let now = Date.now()
    const stuckDeps = harness(sql, {
      node: deps.node,
      custody: deps.custody,
      stuckMinutes: 60,
      now: () => now,
    })
    const { outbound } = await planOutbound(stuckDeps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 17n,
      fee: TEST_FEE,
      idempotencyKey: 'wallet:withdrawal:stuck',
      sourceRef: 'withdrawal-stuck',
    })
    await driveChain(stuckDeps.worker, 'ember', 'testnet')
    now += 61 * 60_000
    await driveChain(stuckDeps.worker, 'ember', 'testnet')
    assert.equal((await findOutbound(sql as never, outbound.id))?.state, 'stuck')
    return outbound.id
  }

  it('lists the stuck queue by default and never publishes the signed bytes', async () => {
    const id = await aStuckTransaction()
    const { status, body } = await call('/v1/outbound', { token: 'admin' })
    assert.equal(status, 200)
    const rows = body['transactions'] as Array<Record<string, unknown>>
    assert.equal(rows.length, 1)
    assert.equal(rows[0]!['id'], id)
    // The NONCE is published because an operator adjudicating this needs the number the whole death
    // proof turns on. The BYTES are not: a signed transaction in a response body is a submittable
    // payment.
    assert.equal(rows[0]!['signedNonce'], '0')
    assert.equal(rows[0]!['hasCommittedBytes'], true)
    assert.ok(!('rawTx' in rows[0]!))
  })

  /**
   * **The route that had to exist.** In the estate this replaces it is curl-only with no UI, so the
   * one decision that has to be taken carefully, under time pressure, by somebody who has just been
   * paged, is taken by hand-editing a shell command.
   */
  it('refuses a refund with 409 and an actionable reason, and records the attempt', async () => {
    const id = await aStuckTransaction()
    const { status, body } = await call(`/v1/outbound/${id}/adjudicate`, {
      method: 'POST',
      token: 'admin',
      body: { action: 'refund' },
    })

    // A 409, not a 400: the request was well formed and the operator was entitled to make it — the
    // CHAIN said no. A 400 would read as "you typed it wrong".
    assert.equal(status, 409)
    const refusal = body['refusal'] as Record<string, unknown>
    assert.equal(refusal['code'], 'still_applicable')
    assert.match(String(refusal['reason']), /Retire the nonce first/)
    assert.equal((await findOutbound(sql as never, id))?.state, 'stuck')
    const audit = await sql`select count(*)::int as n from outbound_adjudications where action = 'refused'`
    assert.equal(audit[0]!.n, 1)
  })

  it('refunds once the chain proves the bytes dead', async () => {
    const id = await aStuckTransaction()
    deps.node.setNonce(TREASURY, 1)
    const { status, body } = await call(`/v1/outbound/${id}/adjudicate`, {
      method: 'POST',
      token: 'admin',
      body: { action: 'refund' },
    })
    assert.equal(status, 200)
    assert.match(String(body['proof']), /the slot was taken by another transaction/)
    assert.equal((await findOutbound(sql as never, id))?.state, 'failed')
  })

  it('is administrator only — there is no service path to a settlement decision', async () => {
    const id = await aStuckTransaction()
    for (const token of ['wallet', 'user', 'unscoped']) {
      const { status } = await call(`/v1/outbound/${id}/adjudicate`, {
        method: 'POST',
        token,
        body: { action: 'refund' },
      })
      assert.equal(status, 403, `${token} must not be able to adjudicate`)
    }
  })

  it('refuses an action that is not refund or confirm', async () => {
    const id = await aStuckTransaction()
    const { status } = await call(`/v1/outbound/${id}/adjudicate`, {
      method: 'POST',
      token: 'admin',
      body: { action: 'force' },
    })
    // There is no force flag and there should not be one: it would be the path of least resistance
    // at exactly the moment somebody is under pressure to clear an alert.
    assert.equal(status, 400)
  })

  /* ---------------------------------------------------------------- treasuries and sources */

  it('reports the in-flight transaction for a chain, at most one by construction', async () => {
    await planOutbound(deps.sql, {
      purpose: 'withdrawal',
      chain: 'ember',
      network: 'testnet',
      from: TREASURY,
      to: ALICE,
      assetCode: 'EMBER',
      amount: 10n ** 17n,
      fee: TEST_FEE,
      idempotencyKey: 'k',
      sourceRef: 'w',
    })
    await driveChain(deps.worker, 'ember', 'testnet')
    const { status, body } = await call('/v1/chains/ember/testnet/in-flight', { token: 'admin' })
    assert.equal(status, 200)
    assert.equal((body['inFlight'] as Record<string, unknown>)['state'], 'broadcast')
  })

  it('registers a deposit address for sweeping, with its custody binding', async () => {
    const { status, body } = await call('/v1/sweep-sources', {
      method: 'POST',
      token: 'wallet',
      body: {
        chain: 'ember',
        network: 'testnet',
        address: testAddress(0xd1),
        custodyChain: 'ember',
        custodyFamily: 'ember',
        custodyUserId: 'user-1',
        custodyOrderId: 'assignment-1',
      },
    })
    assert.equal(status, 201)
    assert.equal((body['sweepSource'] as Record<string, unknown>)['swept'], '0')
  })

  it('refuses to register an address on the other network', async () => {
    // Storing it would only make it look as though it might one day be swept, and a float target on
    // a go-live deployment is otherwise enough to drain every address left over from testnet.
    const { status, body } = await call('/v1/sweep-sources', {
      method: 'POST',
      token: 'wallet',
      body: {
        chain: 'ember',
        network: 'mainnet',
        address: testAddress(0xd2),
        custodyChain: 'ember',
        custodyFamily: 'ember',
        custodyUserId: 'user-1',
        custodyOrderId: 'assignment-2',
      },
    })
    assert.equal(status, 409)
    assert.equal((body['error'] as Record<string, unknown>)['code'], 'other_network')
  })

  it('provisions a treasury only for an administrator', async () => {
    assert.equal(
      (await call('/v1/treasuries/eth/testnet/provision', { method: 'POST', token: 'wallet', body: {} })).status,
      403,
    )
    const { status, body } = await call('/v1/treasuries/eth/testnet/provision', {
      method: 'POST',
      token: 'admin',
      body: {},
    })
    assert.equal(status, 200)
    assert.equal(body['minted'], true)
    const listed = await call('/v1/treasuries', { token: 'admin' })
    assert.equal((listed.body['treasuries'] as unknown[]).length, 1)
  })

  it('answers 404 for an unknown route rather than leaking a route table', async () => {
    const { status } = await call('/v1/nope', { token: 'admin' })
    assert.equal(status, 404)
  })
})
