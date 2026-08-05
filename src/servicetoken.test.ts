/**
 * **The ten-minute cliff, end to end, through the wiring this service actually uses.**
 *
 * `@cloudsforge/auth` proves the provider in isolation. This file proves the ADOPTION, which is a
 * different claim and the one that was wrong here:
 *
 *     const token = () => env.serviceToken        // src/index.ts:83, before this change
 *
 * A function called per request, so that a short-TTL token could rotate without a restart —
 * returning a string read once at boot from a token that dies in 600 seconds
 * (`identity/src/tokens.ts:28`). Every call to custody, the indexer and the ledger began failing
 * ten minutes into every deployment.
 *
 * **The call modelled below is `custody.treasuryPin`, and that is not an arbitrary choice.** It is
 * the exact call the mainnet estate was failing every five minutes when `micro-org#174` was filed:
 *
 *     CustodySignRefusedError: a valid bearer token is required
 *       at translateSign (/app/src/custodyclient.ts:268)
 *       at Object.treasuryPin (/app/src/custodyclient.ts:213)
 *
 * A settlement that cannot read the pin cannot pay a withdrawal even once an operator has pinned
 * one, so this seam is on the money path rather than beside it.
 *
 * WHY THE REST OF THIS SUITE COULD NOT SEE IT. Every other test here builds a client against a fake
 * peer and calls it immediately. A token minted at the top of such a test is seconds old when it is
 * used, so it is never asked to survive its own lifetime. **A test that mints a token and
 * immediately uses it proves nothing about this defect.** The test below moves a simulated clock
 * eleven minutes past a token it already holds, asserts that token is now REFUSED BY A REAL
 * `Verifier`, and only then asserts the custody client still works.
 */

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, exportJWK, generateKeyPair, type JWK } from 'jose'
import { AUDIENCE, Verifier, serviceTokenProbe } from '@cloudsforge/auth'
import { httpCustodyClient } from './custodyclient.ts'
import { buildUpstreams, type UpstreamEnv } from './upstreams.ts'

const ISSUER = 'https://identity.test'
const IDENTITY = 'http://identity:4000'
const CUSTODY = 'http://custody:4000'
const CREDENTIAL = 'cfsc_TToR-eOeVTDnqhX1-nu6-u7DoCr4MCfa86g4g6kd404'

/** The scopes identity grants `service:settlement`. `deploy` IDENTITY_SERVICE_TOKEN_GRANTS. */
const SCOPES = [
  'custody:sign:deposit',
  'custody:sign:treasury',
  'custody:treasury:read',
  'indexer:read',
  'indexer:write',
  'ledger:post',
]

/** identity/src/tokens.ts:28. Unchanged by this fix, and it must stay unchanged. */
const SERVICE_TTL_SECONDS = 600

/** The address custody pins. A public value; nothing here is key material. */
const PIN = '0x51B3edA40820265E5C29803cfEFd36ce1347f8f7'

const T0 = Date.UTC(2026, 7, 5, 12, 0, 0)

/** Move the whole world — the provider's clock and jose's expiry check — to `T0 + ms`. */
function clockAt(ms: number): void {
  mock.timers.reset()
  mock.timers.enable({ apis: ['Date'], now: new Date(T0 + ms) })
}

interface World {
  readonly fetch: typeof globalThis.fetch
  exchanges: number
  custodyCalls: Array<{ token: string | null; status: number }>
  identityDown: boolean
}

/**
 * A real identity and a real custody, in the sense that matters: identity signs RS256 tokens with a
 * 600-second expiry against the simulated clock, and custody hands whatever it is given to a real
 * `Verifier` and answers 401 when jose says the token is bad. Nothing here decides expiry by hand —
 * which is the point, because deciding it by hand is how a test agrees with the code it is meant to
 * be checking.
 */
async function world(): Promise<World> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }
  void jwk
  const keySet = (async () => publicKey) as never
  const verifier = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })

  // RS256 is deterministic, so two tokens signed from the same payload at the same simulated instant
  // are the same string. identity mints a uuidv7 jti per token; the counter restores that.
  let jti = 0

  const self: World = {
    exchanges: 0,
    custodyCalls: [],
    identityDown: false,
    fetch: (async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url

      if (url.startsWith(IDENTITY)) {
        if (self.identityDown) throw new TypeError('fetch failed: ECONNREFUSED')
        if (new Headers(init?.headers).get('authorization') !== `Bearer ${CREDENTIAL}`) {
          return new Response('{"error":"unauthenticated"}', { status: 401 })
        }
        self.exchanges += 1
        const token = await new SignJWT({ typ: 'service', scopes: SCOPES, jti: `t-${++jti}` })
          .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
          .setIssuedAt()
          .setIssuer(ISSUER)
          .setAudience(AUDIENCE)
          .setSubject('service:settlement')
          .setExpirationTime(Math.floor(Date.now() / 1000) + SERVICE_TTL_SECONDS)
          .sign(privateKey)
        return new Response(
          JSON.stringify({
            token,
            service: 'settlement',
            scopes: SCOPES,
            expiresIn: SERVICE_TTL_SECONDS,
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        )
      }

      if (self.custodyCalls.length > 32) throw new Error('the 401 replay is looping')
      const presented = new Headers(init?.headers).get('authorization')?.replace(/^Bearer /, '') ?? null
      if (presented === null) {
        self.custodyCalls.push({ token: null, status: 401 })
        return new Response('{"error":"unauthenticated"}', { status: 401 })
      }
      try {
        await verifier.principal(presented)
        self.custodyCalls.push({ token: presented, status: 200 })
        return new Response(JSON.stringify({ chain: 'ember', network: 'mainnet', address: PIN }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      } catch {
        self.custodyCalls.push({ token: presented, status: 401 })
        return new Response(
          JSON.stringify({ error: 'unauthenticated', message: 'a valid bearer token is required' }),
          { status: 401, headers: { 'content-type': 'application/json' } },
        )
      }
    }) as typeof globalThis.fetch,
  }
  return self
}

/**
 * **`buildUpstreams`, not a hand-rolled client.** This is the whole point of the file.
 *
 * A test that constructs its own `ServiceTokenProvider` and its own `httpCustodyClient` proves the
 * provider works, which is `@cloudsforge/auth`'s job. It proves nothing about whether THIS service
 * uses it, and "this service does not use it" was the defect. Going through the real factory means
 * reverting `upstreams.ts` to `const token = () => env.serviceToken` turns the test below red.
 */
function upstreamsFor(w: World, options: { credential: string | null; onMinted?: () => void }) {
  const env: UpstreamEnv = {
    identityUrl: IDENTITY,
    identityCredential: options.credential,
    custodyUrl: CUSTODY,
    indexerUrl: 'http://indexer:4000',
    ledgerUrl: 'http://ledger:4000',
    upstreamDeadlineMs: 8_000,
  }
  return buildUpstreams(env, {
    originatingService: 'settlement',
    fetch: w.fetch,
    onEvent: (event) => {
      if (event.kind === 'minted') options.onMinted?.()
    },
  })
}

/* ────────────────────────────────────────────────────────────────────────────────────────────────
 * THE REGRESSION TEST.
 * ──────────────────────────────────────────────────────────────────────────────────────────────── */

test('the treasury pin is still readable ELEVEN MINUTES after boot — the ten-minute cliff', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())

  clockAt(0)
  const { identityTokens: provider, custody } = upstreamsFor(w, { credential: CREDENTIAL })
  assert.ok(provider, 'buildUpstreams must build a provider when a credential is configured')

  // T+0. Every existing test in this repository stops looking here, and everything is fine.
  assert.equal(await custody.treasuryPin('ember', 'mainnet'), PIN)
  const atBoot = w.custodyCalls.at(-1)?.token
  assert.equal(w.custodyCalls.at(-1)?.status, 200)
  assert.ok(atBoot)

  // T+11min.
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)

  // FIRST — the old seam, modelled exactly and wired to the real HttpClient. `token: () =>
  // env.serviceToken` is a supplier that returns the same string for ever, and there is no
  // authorizedFetch behind it because there was none before this change. It fails, against a real
  // Verifier, for the reason `micro-org#174` recorded from the live estate.
  const stale = httpCustodyClient({
    baseUrl: CUSTODY,
    token: () => atBoot,
    deadlineMs: 8_000,
    fetch: w.fetch,
  })
  await assert.rejects(
    () => stale.treasuryPin('ember', 'mainnet'),
    (err: unknown) => err instanceof Error && /valid bearer token/.test(err.message),
    'a token read once at boot MUST be dead by now',
  )
  assert.equal(w.custodyCalls.at(-1)?.status, 401)

  // SECOND — the fix, through the same factory `src/index.ts` uses. A 200 here can only mean the
  // service obtained a live token for itself: no operator, no restart, no redeploy.
  const before = w.exchanges
  assert.equal(await custody.treasuryPin('ember', 'mainnet'), PIN)
  assert.equal(w.custodyCalls.at(-1)?.status, 200, 'settlement must still reach custody past the first expiry')
  assert.notEqual(w.custodyCalls.at(-1)?.token, atBoot, 'and with a genuinely new token')
  assert.equal(w.exchanges, before + 1, 'which it minted from the credential')
})

test('a token refreshed mid-life is never presented expired, and never costs a request latency', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())

  clockAt(0)
  let minted = 0
  const { identityTokens: provider, custody } = upstreamsFor(w, {
    credential: CREDENTIAL,
    onMinted: () => (minted += 1),
  })
  assert.ok(provider, 'buildUpstreams must build a provider when a credential is configured')
  await custody.treasuryPin('ember', 'mainnet')
  const first = w.custodyCalls.at(-1)?.token

  // 90% through: past the TOP of the provider's jitter band, which is [75%, 85%] of the lifetime.
  // Not 80% — the fraction is drawn per token from `Math.random`, so a clock at exactly the middle
  // of the band refreshes only about half the time. 90% is still comfortably inside the token's
  // life: 540s of 600s.
  //
  // The refresh runs BEHIND the request: this call still uses the old — and still valid — token,
  // which is the whole reason for refreshing early rather than at expiry.
  clockAt(SERVICE_TTL_SECONDS * 1000 * 0.9)
  await custody.treasuryPin('ember', 'mainnet')
  assert.equal(w.custodyCalls.at(-1)?.token, first, 'the caller did not wait for the mint')
  assert.equal(w.custodyCalls.at(-1)?.status, 200)

  // Wait for the refresh to SETTLE, and wait on the provider's OWN completion signal. `w.exchanges`
  // counts requests that have arrived at identity, which increments before the token is signed, so
  // waiting on it resumes while the new token is still being minted.
  for (let tick = 0; tick < 2_000 && minted < 2; tick++) {
    await new Promise((resolve) => setImmediate(resolve))
  }
  assert.equal(minted, 2, 'the background refresh never ran')

  await custody.treasuryPin('ember', 'mainnet')
  assert.notEqual(w.custodyCalls.at(-1)?.token, first, 'and the next one is on the new token')
  assert.equal(w.custodyCalls.at(-1)?.status, 200)
})

test('an unreachable identity is a 503 to the caller, never an unauthenticated custody call', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())

  clockAt(0)
  const { identityTokens: provider, custody } = upstreamsFor(w, { credential: CREDENTIAL })
  assert.ok(provider, 'buildUpstreams must build a provider when a credential is configured')
  await custody.treasuryPin('ember', 'mainnet')

  w.identityDown = true
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)
  const callsBefore = w.custodyCalls.length

  await assert.rejects(() => custody.treasuryPin('ember', 'mainnet'))
  // Custody was never dialled. Sending the expired token, or sending none, would have produced a
  // 401 from a perfectly healthy custody — pointing an operator at the service that holds the
  // estate's signing keys for a fault in the one that issues tokens.
  assert.equal(w.custodyCalls.length, callsBefore, 'no unauthenticated or stale call reached custody')
})

test('with no credential configured the service is NOT ready, and calls fail closed', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())
  clockAt(0)

  // `src/index.ts` builds no provider when neither variable carries a `cfsc_` credential. That is
  // the state this asserts: the image can boot without one so CI can smoke-test /livez, and /readyz
  // is where the absence is enforced.
  const probe = serviceTokenProbe(null)
  assert.equal(probe.kind, 'hard')
  assert.equal((await probe.check()).state, 'fail', 'an unconfigured replica must not take traffic')

  const { custody } = upstreamsFor(w, { credential: null })
  await assert.rejects(() => custody.treasuryPin('ember', 'mainnet'))
  assert.equal(w.custodyCalls.length, 0, 'and nothing was sent unauthenticated')
})
