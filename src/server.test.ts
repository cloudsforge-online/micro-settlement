/**
 * The HTTP surface, over a real socket.
 *
 * The two routes worth the most attention are the ones the estate this replaces does worst: the
 * EVENT INTAKE, whose signature is verified before the body is parsed, and the ADJUDICATION ROUTE,
 * which is curl-only with no list and no audit in forge-pay.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import { randomUUID } from 'node:crypto'
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
      outbound: deps.outbound,
      adjudication: deps.adjudication,
      withdrawals: deps.withdrawals,
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
    const { status, body } = await call('/v1/fees/btc/testnet/BTC', { token: 'wallet' })
    assert.equal(status, 501)
    assert.match(String((body['error'] as Record<string, unknown>)['message']), /Bitcoin output policy/)
  })

  it('refuses an asset that does not settle on the named chain', async () => {
    assert.equal((await call('/v1/fees/ember/testnet/ETH', { token: 'wallet' })).status, 400)
  })

  /* ---------------------------------------------------------------- events */

  const post = async (payload: Record<string, unknown>, options: { secret?: string } = {}) => {
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
        'x-cloudsforge-signature': signEvent(raw, options.secret ?? SECRET),
        'x-event-id': envelope.id,
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
   * The signature is verified BEFORE the body is parsed. An unauthenticated body never reaches a
   * JSON parser, let alone the path that plans a payment.
   */
  it('refuses an event whose signature does not verify, and plans nothing', async () => {
    const { status } = await post(withdrawalPayload(), { secret: 'the-wrong-secret-0000000000000000' })
    assert.equal(status, 401)
    const rows = await sql`select count(*)::int as n from outbound_transactions`
    assert.equal(rows[0]!.n, 0)
  })

  /**
   * A topic this service does not consume is 202, not 404.
   *
   * The relay treats any non-2xx as a delivery failure and retries for ever, so a 404 here would
   * pin a subscriber in a permanent retry loop over something neither side is wrong about.
   */
  it('answers 202 for a topic it does not consume', async () => {
    const envelope = { id: randomUUID(), topic: 'indexer.deposit.confirmed', payload: {} }
    const raw = JSON.stringify(envelope)
    const response = await fetch(`${base}/v1/events`, {
      method: 'POST',
      headers: { 'x-cloudsforge-signature': signEvent(raw, SECRET) },
      body: raw,
    })
    assert.equal(response.status, 202)
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
