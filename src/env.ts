/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — "a repo declares the variables it needs; the deploy provides
 * exactly those" — is a property of this file. Every variable this service reads is named here and
 * nowhere else, so the deploy manifest can be derived from it and `env_file: .env` fan-out (which
 * hands every container the whole estate's secrets) has nothing to justify it.
 *
 * Two behaviours are copied deliberately from custody:
 *
 *   1. **A missing variable names itself.** `undefined` propagating into a connection string
 *      surfaces four layers later as an unreadable driver error.
 *   2. **A placeholder is refused outright.** A default secret in source is not convenient, it is
 *      catastrophic, and a placeholder that boots is a placeholder that reaches production. What
 *      makes that refusal real rather than decorative is that `@cloudsforge/secrets` checks the
 *      SHAPE of a generated value rather than membership of a list of exact strings — see the
 *      block where this file's own `PLACEHOLDERS` set used to be.
 *
 * THE FEE BOUNDS ARE NOT TUNING KNOBS. `minGasPriceWei` and `maxGasPriceWei` are the two numbers
 * that decide whether this service will put a signature on a transaction, and both directions cost
 * money. A floor of zero lets a node quoting nothing produce a transaction that underbids its own
 * chain and then sits in a mempool being neither paid nor refunded; a ceiling that is too high lets
 * a misbehaving node spend a user's whole balance on gas. Custody has its own ceiling
 * (`MAX_FEE_WEI`, 2e18) and refuses past it, so a bound set above that is not a wider policy — it
 * is a 403 at the moment of signing, which is a worse way to discover the same limit.
 */

import { hostname } from 'node:os'
import { CREDENTIAL_PREFIX } from '@cloudsforge/auth'
import type { Network } from '@cloudsforge/contracts-chain'
import {
  SecretError,
  assertGeneratedSecret,
  assertServiceCredential,
  parseSecretList as parseSharedSecretList,
} from '@cloudsforge/secrets'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment, and making it configurable is how two services end up sharing a migration
 * advisory lock.
 */
export const SERVICE = 'settlement'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

/**
 * THE `PLACEHOLDERS` SET THAT USED TO BE HERE IS GONE, AND ITS ABSENCE IS THE FIX.
 *
 * It held nine exact strings and was paired with a 24-character floor. Neither could fail for the
 * value that actually reached 44 containers on both networks: micro-org #142's
 * `estate-only-outbox-secret-00000000000000` is 40 characters and was on nobody's list. A check
 * that cannot fail is worse than no check, because the absence of an alarm gets read as the
 * absence of a problem — and this service signs and broadcasts transactions.
 *
 * A deny-list of exact strings is structurally unable to work: the next placeholder somebody
 * writes is, by definition, not on it. `@cloudsforge/secrets` asserts the SHAPE of a generated
 * value instead, which is the property a placeholder cannot have. It is imported rather than
 * copied so that this service cannot drift from the other sixteen.
 */

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * Re-wrap the shared guard's `SecretError` as this service's `EnvError`.
 *
 * `loadEnv` documents a single error class for every configuration failure, and the boot path
 * catches that one class. The message is preserved verbatim — it already names the variable and
 * the command that fixes it, and it never contains the value.
 */
function asEnvError<T>(run: () => T): T {
  try {
    return run()
  } catch (err) {
    if (err instanceof SecretError) throw new EnvError(err.message)
    throw err
  }
}

/**
 * The estate's shared event-bus HMAC key — the one key behind every service-to-service POST,
 * including the `wallet.withdrawal.requested` delivery that starts a payout.
 *
 * `assertGeneratedSecret` asserts what a placeholder cannot have: the base64 or hex alphabet (no
 * hyphens — every placeholder this estate wrote had one), 32 decoded BYTES rather than 24
 * keystrokes, and a measured Shannon entropy floor. The old `minLength` parameter is gone rather
 * than kept in front: it is a strict subset of the shape check, and running it first answers a
 * 40-character placeholder with "must be at least 24 characters" — true, useless, and about the
 * wrong property.
 */
function requiredSigningSecret(source: Source, name: string): string {
  const value = required(source, name)
  asEnvError(() => assertGeneratedSecret(name, value))
  return value
}

/**
 * A SERVICE CREDENTIAL that may be absent, but must be real if present.
 *
 * ── ABSENCE IS A SUPPORTED MODE, AND IT STAYS ONE ──────────────────────────────────────────────
 *
 * Absent is a deployment that has not been granted a credential yet; it returns `null`, `/readyz`
 * reports it as a HARD failure, and the service boots. Turning that into `exit(1)` would convert a
 * gap into an outage on the service that broadcasts transactions.
 *
 * This paragraph used to end "and settlement's compose block does not pass
 * `SETTLEMENT_IDENTITY_CREDENTIAL` at all, so on the live estate absence is the NORMAL case rather
 * than an edge one". That stopped being true with micro-org#191: both the `settlement` and
 * `settlement-migrate` blocks now pass `${SETTLEMENT_IDENTITY_CREDENTIAL:-}`. Absence is an
 * ordinary case again rather than the usual one — a deployment not yet granted a credential, or an
 * image booted for CI's startup smoke test — and every reason below for tolerating it is unchanged.
 * The empty check therefore stays AHEAD of the assertion,
 * because compose interpolates `${X:-}` and an unset variable arrives as the empty string; that is
 * the supported mode, not a malformed one.
 *
 * What is not supported is a value that is present and rubbish: a 20-character placeholder is a
 * deployment that believes it HAS a credential, and it fails on its first call to custody with a
 * 401 that reads as "identity rejected settlement" rather than "nobody set this variable".
 *
 * ── WHY NOT `assertGeneratedSecret` ────────────────────────────────────────────────────────────
 *
 * Because it would refuse every credential this estate has ever minted, and settlement would exit 1
 * at boot on BOTH networks. A credential is `cfsc_` + base64url, which is neither wholly base64 nor
 * wholly hex — the underscore in its own prefix disqualifies it. Measured live on 2026-08-05:
 * `SETTLEMENT_IDENTITY_CREDENTIAL` and `SETTLEMENT_SERVICE_TOKEN` are both `cfsc_` + 43 characters,
 * 48 in total, and the testnet one CONTAINS A HYPHEN while the mainnet one does not — so the "no
 * hyphens" instinct that is correct for the signing key above would have booted mainnet and killed
 * testnet.
 */
function optionalCredential(source: Source, name: string): string | null {
  const value = source[name]?.trim()
  if (!value) return null
  asEnvError(() => assertServiceCredential(name, value))
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

function boolean(source: Source, name: string, fallback: boolean): boolean {
  const raw = source[name]?.trim().toLowerCase()
  if (!raw) return fallback
  if (raw === 'true' || raw === '1') return true
  if (raw === 'false' || raw === '0') return false
  throw new EnvError(`${name} must be true or false (got ${raw})`)
}

/**
 * The secrets the inbound event route accepts, newest first.
 *
 * A LIST, not a value, because rotation without an overlap window means every producer must change
 * secret in the same instant as this service does, and that instant does not exist during a rolling
 * deploy. Each entry gets the checks `requiredSigningSecret` applies to one. The same shape as
 * `devplatform`'s `parseSecretList` and `activity`'s `ACTIVITY_INGEST_SECRETS`.
 */
export function parseSecretList(raw: string, name: string): readonly string[] {
  // Argument order is flipped on the way through: this service's exported signature is
  // `(raw, name)` and the shared one is `(name, raw)`. Kept rather than changed because the
  // signature is part of this module's public surface, and a silent flip of two `string`
  // parameters is a change the type checker cannot catch.
  //
  // EVERY ENTRY FACES THE FULL RULE, INCLUDING THE OUTGOING ONE. In a rotation overlap window the
  // outgoing key is the one an attacker already holds if it leaked, and "just for the drain" is
  // exactly how a placeholder survives the rotation that was meant to remove it. The duplicate
  // check that used to live here moved with it, unchanged.
  return asEnvError(() => parseSharedSecretList(name, raw))
}

/**
 * A wei quantity as a decimal string.
 *
 * Never a number. One EMBER is 1e18 wei, four orders of magnitude past what a double holds
 * exactly, so a gas bound read through `Number()` would be silently rounded — and a rounded bound
 * is a bound that does not hold at the value it was written for.
 */
function wei(source: Source, name: string, fallback: bigint): bigint {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  if (!/^\d+$/.test(raw)) throw new EnvError(`${name} must be a whole number of wei (got ${raw})`)
  return BigInt(raw)
}

/*
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * `SETTLEMENT_RPC_URLS` IS A SECRET NOW, AND THE COMMENT AT THE FOOT OF THIS FILE USED TO BE
 * WRONG ABOUT IT.
 *
 * That comment says the fatal line emitted at import is "the one `loadEnv` produced, which by
 * construction never contains a value of a secret". `jsonMap` was the exception, and it became one
 * the moment Bitcoin-family endpoints arrived: Core authenticates JSON-RPC with HTTP Basic and
 * nothing else, so the endpoint an operator configures is `http://rpcuser:rpcpassword@host:8332`
 * and the map that holds it holds a password. `registry.ts` now reads that userinfo and sends it
 * (see `basicAuthorization` there); before this change it was parsed and dropped, and every
 * Litecoin call took a 401.
 *
 * The failure that made this worth fixing is a one-character one. `SETTLEMENT_RPC_URLS` with a
 * trailing comma does not parse, and the branch below echoed the first sixty characters of the raw
 * value to explain why — which for that variable is the scheme, the username and most of the
 * password, printed by the hand-built fatal line at the foot of this file, into the collector,
 * on every restart of a container that will never start. The password would then be in a log
 * store, which is a rotation rather than a redeploy.
 *
 * REDACT FIRST, THEN SLICE. The other order is worse than not redacting: a sixty-character cut
 * lands mid-userinfo about as often as not, and the pattern below would no longer match the
 * fragment left over — so the truncation would be doing the leaking.
 *
 * The pattern is deliberately not `new URL`: the raw string is a JSON blob that did not parse, so
 * there may be no URL in it to construct, and there may be several. `@cloudsforge/http`'s
 * `redactUrl` is the right tool one layer down, on a single well-formed URL, and is what
 * `HttpError` and `TimeoutError` already use.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const USERINFO = /(\/\/)[^/?#\s"'@]*@/g

/** Replaces `//user:pass@` with `//***:***@` anywhere in a string, however malformed the rest is. */
function redactUserinfo(text: string): string {
  return text.replace(USERINFO, '$1***:***@')
}

/**
 * A JSON object of `chain → value`, refused rather than defaulted when it will not parse.
 *
 * A silently-empty map here is an outage that presents as "every withdrawal on every chain is
 * refused for want of an endpoint", which is a long way from the typo that caused it.
 */
function jsonMap(source: Source, name: string, fallback: string): Readonly<Record<string, string>> {
  const raw = optional(source, name, fallback)
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new EnvError(`${name} must be a JSON object (got ${redactUserinfo(raw).slice(0, 60)})`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new EnvError(`${name} must be a JSON object of string keys to string values`)
  }
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new EnvError(`${name}.${key} must be a non-empty string`)
    }
    out[key] = value
  }
  return Object.freeze(out)
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  /**
   * Rule 1: one database, named by this service's own variable. The CI check greps for any other
   * connection-string variable, so adding a second one here fails the build rather than review.
   */
  readonly databaseUrl: string
  readonly databasePoolMax: number
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  /** HMAC key for outbound event signatures. Signing only; the accept list below verifies. */
  readonly outboxSigningSecret: string

  /**
   * The secrets `POST /v1/events` ACCEPTS, newest first — under BOTH inbound schemes.
   *
   * `OUTBOX_SIGNING_SECRET` is one HMAC key shared by every service in the estate, and replacing it
   * is only possible as a rolling change if each receiver holds more than one candidate for the
   * length of the cutover. With one, the instant wallet's relay adopts the new key every delivery
   * of `wallet.withdrawal.requested` answers 401 — and that is this service's ONLY inbound path,
   * so the symptom is withdrawals that are reserved and never built, with a green `/livez` and a
   * relay retrying for ever. Silent, which is why the window has to be configurable rather than
   * coordinated.
   *
   * `OUTBOX_ACCEPT_SECRETS` is OPTIONAL and defaults to `[OUTBOX_SIGNING_SECRET]`, so a deployment
   * that has not been given it behaves exactly as it does today. That is deliberate: it makes
   * shipping this a no-op, which is what lets the rotation itself be staged one service at a time.
   *
   * `verifyInbound` tries every candidate on the contract arm AND on the legacy arm. Not doing the
   * second would partition precisely the path its own header says wallet still uses.
   */
  readonly outboxAcceptSecrets: readonly string[]
  /**
   * Names this replica in `jobs.locked_by`. Defaults to the hostname, which is the container id
   * under compose and the pod name under Kubernetes — in both cases the thing an operator would
   * search for after finding a stuck lease.
   */
  readonly instanceId: string

  /**
   * The one network this deployment settles on.
   *
   * A single value rather than a per-request parameter, because a service that can be asked to
   * sweep on either network is a service one bad request away from consolidating a testnet float
   * into a mainnet treasury. The frozen sweeper carries the same rule and the comment explaining
   * why it is silent about skipping the other network.
   */
  readonly network: Network

  readonly custodyUrl: string
  readonly indexerUrl: string
  readonly ledgerUrl: string

  /**
   * Where identity is, for `POST /service-tokens/exchange`.
   *
   * Defaults to `IDENTITY_ISSUER`, which is already required and is identity's own base URL — the
   * issuer of a token is by definition where the token came from. `IDENTITY_URL` overrides it for a
   * deployment where the two genuinely differ (an issuer behind a public name, dialled internally).
   * Deriving rather than demanding a fourth identity variable keeps the two in step: a deployment
   * that pointed the exchange at one identity and trusted the JWKS of another would fail with a
   * signature error nobody would read as a configuration mistake.
   */
  readonly identityUrl: string

  /**
   * **The long-lived credential this service exchanges for short-lived tokens. SD-05: not shared.**
   *
   * It replaces `SETTLEMENT_SERVICE_TOKEN`, which was a 600-second token read once at boot. Ten
   * minutes into every deployment it expired and every call to custody, the indexer and the ledger
   * failed 401 — measured live, see `upstreams.ts`. A credential is not a token: it confers nothing
   * by itself, it is revocable, and it survives a restart.
   *
   * **Read from `SETTLEMENT_IDENTITY_CREDENTIAL` first, then from `SETTLEMENT_SERVICE_TOKEN` when
   * that value carries the `cfsc_` prefix.** The second was not sloppiness: settlement's compose
   * block passed only `SETTLEMENT_SERVICE_TOKEN`, so the credential the bootstrap minted reached no
   * container, and accepting it under either name let the cliff be closed by changing one VALUE
   * rather than by waiting for a deploy edit. The prefix decides, and it is unambiguous: identity's
   * credentials begin `cfsc_` and its tokens are JWTs beginning `eyJ`.
   *
   * **THE DEPLOY EDIT HAS NOW LANDED** — micro-org#191, both blocks passing
   * `${SETTLEMENT_IDENTITY_CREDENTIAL:-}` — so the estate no longer depends on the second read.
   * It is kept anyway, and not out of sentiment: a deploy cannot change the image and the compose
   * block in the same instant, so the container that comes up with the new image and the old block
   * has to boot. Deleting the fallback would make a rollback of that compose file a settlement that
   * cannot authenticate to anything. It costs one `??` and it is what makes the transition
   * survivable in both directions.
   *
   * Whichever name carries it, the value is held to `assertServiceCredential` — the SERVICE
   * CREDENTIAL class, not the generated-key class. Measured live on 2026-08-05 both variables hold
   * `cfsc_` + 43 characters, 48 in total. Pointing them at `assertGeneratedSecret` instead would
   * refuse every credential identity has ever minted, because `cfsc_`'s own underscore is in
   * neither the base64 nor the hex alphabet.
   *
   * OPTIONAL, AND THAT IS DELIBERATE — but it is not "unconfigured is fine". Everything this
   * service does crosses a service boundary, so settlement with no credential can sign nothing and
   * broadcast nothing. It is optional because it must be possible to BOOT the image without one:
   * CI's startup smoke test builds the container, migrates it and reads `/livez` with a fixed
   * environment. `/readyz` is where the absence is enforced, as a HARD probe.
   */
  readonly identityCredential: string | null

  /**
   * Whether `SETTLEMENT_SERVICE_TOKEN` is still carrying an actual TOKEN rather than a credential.
   *
   * Read for exactly one purpose: to say so at boot. An operator who redeploys with the old value
   * would otherwise get a service that looks configured and is not — which is the same defect,
   * arriving ten minutes later and looking like custody's fault.
   */
  readonly legacyServiceTokenPresent: boolean
  readonly upstreamDeadlineMs: number

  /**
   * `chain → JSON-RPC endpoint`. Empty by default, which makes a chain with no endpoint refuse
   * rather than fall back to a public node nobody chose.
   *
   * **A CHAIN IS ADDED HERE AND NOWHERE ELSE — THERE IS NO PER-CHAIN VARIABLE AND THERE MUST NOT
   * BE.** `doge` and `etc` became buildable on 2026-08-09 and neither needed a new variable: this
   * map's keys are the chain slugs, so a deployment points at a Dogecoin node by growing a key. A
   * `DOGE_RPC_URL` beside it would be a second place a chain can be configured and a second place
   * it can be forgotten, and under rule 9 it would also be a variable this service declares and
   * only sometimes reads. An absent key is not an error at boot: the chain reports `no_endpoint`
   * (see `chainStatuses` in `registry.ts`) and every call on it ends at a classified
   * `NoEndpointError`, refunded at the deadline.
   *
   * **THIS MAP CAN HOLD A PASSWORD.** Bitcoin, Litecoin and Dogecoin Core speak HTTP Basic and
   * have no anonymous mode, so their entries are `http://rpcuser:rpcpassword@host:8332` and
   * `registry.ts` turns that userinfo into an `Authorization` header. Nothing may print a value
   * from this map: `index.ts` reports a per-chain STATUS at boot and never a URL, and the parse
   * failure above is redacted before it is sliced.
   */
  readonly rpcUrls: Readonly<Record<string, string>>
  readonly rpcDeadlineMs: number

  readonly withdrawalsEnabled: boolean
  readonly sweepEnabled: boolean
  /**
   * The float this deployment wants sitting in each treasury, as a decimal string per asset.
   *
   * **Zero by default, and that default is the design.** Every coin in the treasury is inside the
   * blast radius of the signing credential and every coin left in a deposit address is outside it,
   * so the sweeper is demand-driven: it moves what queued withdrawals need and nothing else unless
   * an operator asks for a float in so many words.
   */
  readonly treasuryTargets: Readonly<Record<string, string>>
  /**
   * A sweep is only worth making when the balance is this many times the fee. Sweeping an address
   * holding barely more than the fee spends most of the customer's deposit on moving it.
   */
  readonly sweepMinFeeMultiple: number
  /**
   * Whether this deployment sweeps ERC-20 balances out of deposit addresses.
   *
   * ══════════════════════════════════════════════════════════════════════════════════════════
   * **OFF BY DEFAULT, AND IT MUST STAY OFF UNTIL TOKEN DEPOSITS ARE CREDITED.** This is not a
   * performance switch and it is not caution for its own sake; it is the one precondition that
   * cannot be checked from inside this service.
   *
   * `micro-wallet` currently REFUSES to credit a token deposit — `deposits.ts`, the
   * `token_deposit_unsupported` branch — because the amount is denominated in a token whose
   * decimals it has no registry for, and crediting a six-decimal stablecoin as an eighteen-decimal
   * coin is a balance wrong by 10^12. That refusal is correct.
   *
   * The consequence for THIS service is the part that matters. Sweeping is not neutral: it moves a
   * coin out of an address only custody can sign for and into the treasury, which is inside the
   * blast radius of `custody:sign:treasury`. Doing that to a balance the platform has NOT recorded
   * a liability for means the user's money is in the treasury, the ledger does not know it is owed,
   * and there is no withdrawal path in this service that could pay it back — a token withdrawal
   * needs a treasury-side token shape that does not exist. **Leaving the tokens where they are is
   * strictly safer than sweeping them**, because the deposit address is the one place they cannot
   * be spent from by anything but a pinned sweep.
   *
   * So the order of operations is fixed: wallet learns to credit `TOKEN:` deposits, the ledger
   * learns to hold them, a token withdrawal path exists — and only then is this turned on. An
   * operator turning it on early does not lose money, but they do move customer funds into a place
   * the platform cannot account for, and that is the state this flag exists to make deliberate.
   * ══════════════════════════════════════════════════════════════════════════════════════════
   */
  readonly tokenSweepEnabled: boolean
  /**
   * The smallest token balance worth two transactions, in the token's own smallest units.
   *
   * A token sweep costs a gas top-up AND a sweep, both paid by the platform in native coin, so the
   * economics are worse than a native sweep's by a whole transaction. Zero disables the floor and
   * is the default: a number nobody has chosen must not silently strand a real deposit, and the
   * right value differs by three orders of magnitude between a six-decimal stablecoin and an
   * eighteen-decimal one. It is one number rather than a per-token map because a deployment that
   * needs two of them needs `micro-policy`'s per-asset table, not a second env var.
   */
  readonly minTokenSweep: bigint

  readonly minGasPriceWei: bigint
  readonly maxGasPriceWei: bigint
  /**
   * The most one transaction's `gasLimit × gasPrice` may come to.
   *
   * Below custody's own `MAX_FEE_WEI` on purpose: this service should refuse a transaction it
   * would otherwise ask custody to refuse, so an operator sees a classified build failure with a
   * refund rather than a 403 from a service they do not run.
   */
  readonly maxFeeWei: bigint

  /** How long an unsettled outbound transaction may go unresolved before it becomes `stuck`. */
  readonly stuckMinutes: number
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

/**
 * Pure over its source so the failure paths are testable without mutating the process. The eager
 * export below is what makes the service fail fast.
 */
export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }
  const network = optional(source, 'SETTLEMENT_NETWORK', 'testnet')
  if (network !== 'mainnet' && network !== 'testnet') {
    throw new EnvError(`SETTLEMENT_NETWORK must be mainnet or testnet (got ${network})`)
  }

  const minGasPriceWei = wei(source, 'SETTLEMENT_MIN_GAS_PRICE_WEI', 1_000_000_000n)
  const maxGasPriceWei = wei(source, 'SETTLEMENT_MAX_GAS_PRICE_WEI', 500_000_000_000n)
  if (minGasPriceWei > maxGasPriceWei) {
    throw new EnvError(
      'SETTLEMENT_MIN_GAS_PRICE_WEI exceeds SETTLEMENT_MAX_GAS_PRICE_WEI — every fee quote would ' +
        'be simultaneously too low and too high, so no transaction could ever be built',
    )
  }
  // 1e18 wei. Custody refuses above 2e18 and this service must refuse first, so the failure is a
  // classified build failure with a refund rather than a 403 from a service the operator does not
  // run. See `Env.maxFeeWei`.
  const maxFeeWei = wei(source, 'SETTLEMENT_MAX_FEE_WEI', 10n ** 18n)

  // Read before the literal below, because the accept list defaults to it. Note the order: the
  // signing secret is validated first, so a deployment with a bad one is told about THAT rather
  // than about a list it never set.
  const outboxSigningSecret = requiredSigningSecret(source, 'OUTBOX_SIGNING_SECRET')

  // ── The credential, from either name, and the CLASS is decided by the value ──────────────────
  //
  // See `Env.identityCredential` for why the second name is read at all, and `upstreams.ts` for
  // what reading only the first would have cost on the live estate.
  //
  // `SETTLEMENT_SERVICE_TOKEN` IS THE TRAP THIS WHOLE CHANGE EXISTS FOR. Measured live on
  // 2026-08-05 it holds `cfsc_` + 43 characters — a CREDENTIAL, despite a name whose suffix it
  // shares with `ADMIN_API_SERVICE_TOKEN`, which on the same estate holds a 701-byte JWT that
  // expired 26 hours before it was read. Four variables in this estate carry `*_SERVICE_TOKEN` and
  // they are not one class. So the guard is chosen from the PREFIX, which is the only thing that
  // actually distinguishes them, and never from the variable's name.
  //
  // The prefix test comes BEFORE the assertion rather than after it, and that ordering is the
  // supported-absence rule applied to a second axis. A value without the prefix is the retired
  // ten-minute token: it is reported at boot and presented to nobody, so asserting it would exit 1
  // over a value that confers nothing — on the service that broadcasts payouts, and on every
  // deployment still carrying compose's `${SETTLEMENT_SERVICE_TOKEN:-estate-placeholder-token-…}`
  // default. That is wallet's treatment of the retired `WALLET_SERVICE_TOKEN` exactly: report
  // presence, confer nothing, require nothing. A value WITH the prefix is about to be presented to
  // custody as this service's identity, and it faces the full rule.
  const declared = optionalCredential(source, 'SETTLEMENT_IDENTITY_CREDENTIAL')
  const carriedRaw = source['SETTLEMENT_SERVICE_TOKEN']?.trim() ?? ''
  const carriesCredential = carriedRaw.startsWith(CREDENTIAL_PREFIX)
  const carried = carriesCredential ? optionalCredential(source, 'SETTLEMENT_SERVICE_TOKEN') : null
  const identityCredential = declared ?? carried
  // A `SETTLEMENT_SERVICE_TOKEN` that is not a credential is the retired ten-minute token. Kept
  // only so `index.ts` can say so at boot; it is never presented to a peer.
  const legacyTokenPresent = !carriesCredential && carriedRaw.length > 0

  return {
    port: integer(source, 'PORT', 4000, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'SETTLEMENT_DATABASE_URL'),
    // A pool larger than the database's own connection budget divided by the replica count is a
    // service that exhausts Postgres for everything else the moment it scales.
    databasePoolMax: integer(source, 'SETTLEMENT_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    outboxSigningSecret,
    // Absent means "accept exactly what we sign with", which is today's behaviour precisely.
    outboxAcceptSecrets: parseSecretList(
      optional(source, 'OUTBOX_ACCEPT_SECRETS', outboxSigningSecret),
      'OUTBOX_ACCEPT_SECRETS',
    ),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),

    network,

    custodyUrl: required(source, 'CUSTODY_URL'),
    indexerUrl: required(source, 'INDEXER_URL'),
    ledgerUrl: required(source, 'LEDGER_URL'),
    identityUrl: optional(source, 'IDENTITY_URL', required(source, 'IDENTITY_ISSUER')),
    identityCredential,
    legacyServiceTokenPresent: legacyTokenPresent,
    upstreamDeadlineMs: integer(source, 'SETTLEMENT_UPSTREAM_DEADLINE_MS', 8_000, 250, 60_000),

    rpcUrls: jsonMap(source, 'SETTLEMENT_RPC_URLS', '{}'),
    rpcDeadlineMs: integer(source, 'SETTLEMENT_RPC_DEADLINE_MS', 10_000, 250, 60_000),

    withdrawalsEnabled: boolean(source, 'SETTLEMENT_WITHDRAWALS_ENABLED', true),
    sweepEnabled: boolean(source, 'SETTLEMENT_SWEEP_ENABLED', false),
    treasuryTargets: jsonMap(source, 'SETTLEMENT_TREASURY_TARGETS', '{}'),
    sweepMinFeeMultiple: integer(source, 'SETTLEMENT_SWEEP_MIN_FEE_MULTIPLE', 3, 1, 1_000),
    tokenSweepEnabled: boolean(source, 'SETTLEMENT_TOKEN_SWEEP_ENABLED', false),
    minTokenSweep: wei(source, 'SETTLEMENT_MIN_TOKEN_SWEEP', 0n),

    minGasPriceWei,
    maxGasPriceWei,
    maxFeeWei,

    stuckMinutes: integer(source, 'SETTLEMENT_STUCK_MINUTES', 60, 5, 10_080),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and
 * the only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand. It is built from a literal rather than routed through
 * the telemetry package: nothing that can itself fail may sit between a configuration error and
 * the report of it. The message is the one `loadEnv` produced, and this line is the reason every
 * message in this file is written the way it is: it goes to the collector verbatim, so a value
 * echoed for diagnosis is a value stored for as long as the log store keeps it.
 *
 * "By construction never contains a value of a secret" is what this comment used to claim, and it
 * was false for exactly one branch — `jsonMap` echoed the head of the raw value, and
 * `SETTLEMENT_RPC_URLS` holds `http://rpcuser:rpcpassword@host:8332`. See `redactUserinfo` above.
 * The claim is worth keeping as an invariant precisely because it is the kind that goes quietly
 * stale when a variable changes what it carries.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
