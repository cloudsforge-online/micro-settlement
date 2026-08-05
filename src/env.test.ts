/**
 * Configuration.
 *
 * Every case here is a way a deployment goes wrong that this file turns into a refusal to start,
 * and each one names itself. The alternative is `undefined` propagating into a connection string
 * and surfacing four layers later as an unreadable driver error.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

/**
 * A valid environment, applied to the process BEFORE `./env.ts` is imported.
 *
 * The import is itself a test: `env.ts` validates eagerly and calls `process.exit(1)` on a bad
 * configuration, so if these values were insufficient this file would not run at all — it would
 * exit, with one structured fatal line and no test results. Every failure case below goes through
 * `loadEnv`, which is pure over its source and therefore testable without a child process.
 */
/**
 * A credential, not a token. The `cfsc_` prefix is what tells the two apart, and it is the whole of
 * the decision `loadEnv` makes below — so the literal has to carry it.
 */
const CREDENTIAL = 'cfsc_TToR-eOeVTDnqhX1-nu6-u7DoCr4MCfa86g4g6kd404'
/** A JWT-shaped value. Identity's tokens begin `eyJ`; this is the thing that dies in ten minutes. */
const LEGACY_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.a-real-service-token-00000000000.sig'

const BASE: Record<string, string> = {
  SETTLEMENT_DATABASE_URL: 'postgres://settlement@localhost/settlement',
  IDENTITY_JWKS_URL: 'http://127.0.0.1:4001/.well-known/jwks.json',
  IDENTITY_ISSUER: 'http://127.0.0.1:4001',
  OUTBOX_SIGNING_SECRET: 'a-real-outbox-secret-000000000000',
  CUSTODY_URL: 'http://127.0.0.1:4005',
  INDEXER_URL: 'http://127.0.0.1:4006',
  LEDGER_URL: 'http://127.0.0.1:4004',
  SETTLEMENT_IDENTITY_CREDENTIAL: CREDENTIAL,
}
for (const [key, value] of Object.entries(BASE)) process.env[key] = value

/**
 * Two obviously-fake secrets, long enough to pass the 24-character rule. They stand for "the new
 * one" and "the one being rotated out" in the acceptance-list cases below.
 */
const NEW_SECRET = 'fake-new-outbox-secret-0000000000'
const OLD_SECRET = 'fake-old-outbox-secret-1111111111'

const { EnvError, SERVICE, env: liveEnv, loadEnv, parseSecretList } = await import('./env.ts')

describe('loadEnv', () => {
  it('loads a complete environment, and importing the module did not exit', () => {
    assert.equal(SERVICE, 'settlement')
    assert.equal(liveEnv.network, 'testnet')
    const env = loadEnv(BASE, 'host-1')
    assert.equal(env.network, 'testnet')
    assert.equal(env.instanceId, 'host-1')
    // The float target is empty by default, which is what makes the sweeper demand-driven.
    assert.deepEqual(env.treasuryTargets, {})
    // And sweeping is OFF by default: moving a coin from a deposit address into the treasury moves
    // it into the blast radius of the signing credential, so it is an operator's decision.
    assert.equal(env.sweepEnabled, false)
    assert.deepEqual(env.rpcUrls, {})
  })

  it('names the variable that is missing', () => {
    for (const name of Object.keys(BASE)) {
      // The credential is deliberately OPTIONAL — the image must boot without one so CI's startup
      // smoke test can read /livez. `/readyz` is where its absence is enforced, as a hard probe.
      if (name === 'SETTLEMENT_IDENTITY_CREDENTIAL') continue
      const source = { ...BASE }
      delete source[name]
      assert.throws(
        () => loadEnv(source),
        (err: unknown) => err instanceof EnvError && err.message.includes(name),
        `a missing ${name} must name itself`,
      )
    }
  })

  /**
   * **The ten-minute cliff, at the only place it can still be reintroduced.**
   *
   * `index.ts:83` read `SETTLEMENT_SERVICE_TOKEN` — a 600-second JWT — once at boot and presented
   * it to custody, the indexer and the ledger for the life of the process. On the mainnet estate
   * that meant one exchange ever, on 2026-08-04, and every treasury-pin read since answering 401.
   * What `loadEnv` now decides is which of the two variables holds a CREDENTIAL, and it decides it
   * from the prefix rather than from the variable's name.
   */
  describe('the identity credential', () => {
    it('takes SETTLEMENT_IDENTITY_CREDENTIAL when it is set', () => {
      const env = loadEnv({ ...BASE, SETTLEMENT_SERVICE_TOKEN: LEGACY_TOKEN })
      assert.equal(env.identityCredential, CREDENTIAL)
      // Still reported, because an operator who leaves the retired variable set should hear so.
      assert.equal(env.legacyServiceTokenPresent, true)
    })

    it('accepts a credential carried in SETTLEMENT_SERVICE_TOKEN', () => {
      // Settlement's compose block passes only this variable, so this is how the live estate closes
      // the cliff without a deploy edit. See `Env.identityCredential`.
      const source: Record<string, string> = { ...BASE, SETTLEMENT_SERVICE_TOKEN: CREDENTIAL }
      delete source['SETTLEMENT_IDENTITY_CREDENTIAL']
      const env = loadEnv(source)
      assert.equal(env.identityCredential, CREDENTIAL)
      assert.equal(env.legacyServiceTokenPresent, false)
    })

    it('IGNORES a SETTLEMENT_SERVICE_TOKEN that is an actual token, and says so', () => {
      const source: Record<string, string> = { ...BASE, SETTLEMENT_SERVICE_TOKEN: LEGACY_TOKEN }
      delete source['SETTLEMENT_IDENTITY_CREDENTIAL']
      const env = loadEnv(source)
      // Never presented to a peer. Using it IS the defect — it would work for ten minutes.
      assert.equal(env.identityCredential, null)
      assert.equal(env.legacyServiceTokenPresent, true)
    })

    it('boots with neither, because the image must be startable', () => {
      const source = { ...BASE }
      delete source['SETTLEMENT_IDENTITY_CREDENTIAL']
      const env = loadEnv(source)
      assert.equal(env.identityCredential, null)
      assert.equal(env.legacyServiceTokenPresent, false)
    })

    it('defaults the exchange URL to the issuer, and lets IDENTITY_URL override it', () => {
      assert.equal(loadEnv(BASE).identityUrl, BASE['IDENTITY_ISSUER'])
      assert.equal(
        loadEnv({ ...BASE, IDENTITY_URL: 'http://identity:4000' }).identityUrl,
        'http://identity:4000',
      )
    })
  })

  it('refuses a placeholder secret outright', () => {
    // A default secret in source is not convenient, it is catastrophic: everything derived from it
    // is forgeable by anyone who can read the repository.
    assert.throws(
      () => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: 'changeme' }),
      /known placeholder/,
    )
    assert.throws(() => loadEnv({ ...BASE, SETTLEMENT_SERVICE_TOKEN: 'short' }), /at least 24/)
  })

  /**
   * The two fee bounds are the numbers that decide whether a signature is asked for, and both
   * directions cost money. A floor above the ceiling would make every quote simultaneously too low
   * and too high, so no transaction could ever be built — an outage that presents as "withdrawals
   * do not work" with nothing in any log to say why.
   */
  it('refuses fee bounds that cross', () => {
    assert.throws(
      () =>
        loadEnv({
          ...BASE,
          SETTLEMENT_MIN_GAS_PRICE_WEI: '100',
          SETTLEMENT_MAX_GAS_PRICE_WEI: '10',
        }),
      /exceeds SETTLEMENT_MAX_GAS_PRICE_WEI/,
    )
  })

  it('reads wei as an exact bigint and never as a number', () => {
    const env = loadEnv({ ...BASE, SETTLEMENT_MAX_FEE_WEI: '1234567890123456789' })
    // Nineteen digits, past 2^53. A double would have rounded it silently.
    assert.equal(env.maxFeeWei, 1_234_567_890_123_456_789n)
    assert.throws(() => loadEnv({ ...BASE, SETTLEMENT_MAX_FEE_WEI: '1.5' }), /whole number of wei/)
  })

  it('refuses an RPC map that is not a JSON object of strings', () => {
    // Silently empty would present as "every chain is refused for want of an endpoint", which is a
    // long way from the typo that caused it.
    assert.throws(() => loadEnv({ ...BASE, SETTLEMENT_RPC_URLS: 'not json' }), /must be a JSON object/)
    assert.throws(() => loadEnv({ ...BASE, SETTLEMENT_RPC_URLS: '{"ember": 1}' }), /non-empty string/)
    const env = loadEnv({ ...BASE, SETTLEMENT_RPC_URLS: '{"ember":"http://127.0.0.1:8545"}' })
    assert.equal(env.rpcUrls['ember'], 'http://127.0.0.1:8545')
  })

  it('refuses a network that is neither mainnet nor testnet', () => {
    assert.throws(() => loadEnv({ ...BASE, SETTLEMENT_NETWORK: 'devnet' }), /mainnet or testnet/)
  })

  it('bounds the stuck deadline', () => {
    assert.throws(() => loadEnv({ ...BASE, SETTLEMENT_STUCK_MINUTES: '1' }), /between 5 and 10080/)
    assert.equal(loadEnv({ ...BASE, SETTLEMENT_STUCK_MINUTES: '90' }).stuckMinutes, 90)
  })

  /**
   * OUTBOX_ACCEPT_SECRETS — the overlap window that makes rotating the shared HMAC key survivable.
   *
   * `OUTBOX_SIGNING_SECRET` is one key shared across the estate. Replacing it is only possible as a
   * rolling change if every RECEIVER can hold more than one candidate at once; otherwise the moment
   * wallet's relay moves, every `wallet.withdrawal.requested` 401s and this service's only inbound
   * path is gone while `/livez` stays green.
   */
  it('accepts only the signing secret when OUTBOX_ACCEPT_SECRETS is absent', () => {
    // The default is what makes deploying this change a no-op, which is what makes the rotation
    // stageable one service at a time.
    assert.deepEqual(loadEnv(BASE).outboxAcceptSecrets, [BASE['OUTBOX_SIGNING_SECRET']])
  })

  it('reads OUTBOX_ACCEPT_SECRETS newest first, and still signs with the single secret', () => {
    const env = loadEnv({
      ...BASE,
      OUTBOX_SIGNING_SECRET: NEW_SECRET,
      OUTBOX_ACCEPT_SECRETS: `${NEW_SECRET}, ${OLD_SECRET}`,
    })
    assert.deepEqual(env.outboxAcceptSecrets, [NEW_SECRET, OLD_SECRET])
    // Verification widens; signing does not. A service that signed with the whole list would have
    // no defined answer to "which key did this go out under".
    assert.equal(env.outboxSigningSecret, NEW_SECRET)
  })

  it('validates every entry in OUTBOX_ACCEPT_SECRETS exactly as it validates the signing secret', () => {
    assert.throws(
      () => loadEnv({ ...BASE, OUTBOX_ACCEPT_SECRETS: `${NEW_SECRET},changeme` }),
      /known placeholder/,
    )
    assert.throws(() => loadEnv({ ...BASE, OUTBOX_ACCEPT_SECRETS: `${NEW_SECRET},hunter2` }), /at least 24/)
    // A duplicate makes "which key verified this" ambiguous, and that answer is how an operator
    // knows a rotation has finished.
    assert.throws(
      () => loadEnv({ ...BASE, OUTBOX_ACCEPT_SECRETS: `${NEW_SECRET},${NEW_SECRET}` }),
      /same secret twice/,
    )
    // A list that is empty or all blanks accepts nothing at all, which is a silent partition.
    assert.throws(() => parseSecretList(' , , ', 'X'), EnvError)
    assert.throws(() => parseSecretList('', 'X'), EnvError)
    // A single entry is a list of one, not a special case.
    assert.deepEqual(parseSecretList(` ${OLD_SECRET} `, 'X'), [OLD_SECRET])
  })
})
