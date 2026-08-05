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
 *   2. **A known placeholder is refused outright.** A default secret in source is not convenient,
 *      it is catastrophic, and a placeholder that boots is a placeholder that reaches production.
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
import type { Network } from '@cloudsforge/contracts-chain'

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
 * Values that must never be accepted. The list holds the strings that actually appear in this
 * repository's own `.env.example` and compose files, because those are the ones that get copied
 * into a deployment by someone in a hurry.
 */
const PLACEHOLDERS = new Set([
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'token',
  'dev-secret',
  'dev-outbox-signing-secret',
  'replace-with-a-real-secret',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

function requiredSecret(source: Source, name: string, minLength = 24): string {
  const value = required(source, name)
  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new EnvError(`${name} is set to a known placeholder — generate a real secret`)
  }
  // Length is a proxy for entropy and the only one available here. It is set above the point at
  // which a human-chosen string is plausible, so a memorable password fails this check too.
  if (value.length < minLength) {
    throw new EnvError(`${name} must be at least ${minLength} characters (got ${value.length})`)
  }
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
 * deploy. Each entry gets the checks `requiredSecret` applies to one. The same shape as
 * `devplatform`'s `parseSecretList` and `activity`'s `ACTIVITY_INGEST_SECRETS`.
 */
export function parseSecretList(raw: string, name: string): readonly string[] {
  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
  if (entries.length === 0) throw new EnvError(`${name} is required — at least one secret`)
  for (const entry of entries) {
    if (PLACEHOLDERS.has(entry.toLowerCase())) {
      throw new EnvError(`${name} contains a known placeholder — generate real secrets`)
    }
    if (entry.length < 24) {
      throw new EnvError(`${name} entries must each be at least 24 characters`)
    }
  }
  if (new Set(entries).size !== entries.length) {
    // A duplicated secret in the list makes the "which key verified this" answer ambiguous, and
    // that answer is what tells an operator whether a rotation has finished.
    throw new EnvError(`${name} lists the same secret twice`)
  }
  return Object.freeze(entries)
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
    throw new EnvError(`${name} must be a JSON object (got ${raw.slice(0, 60)})`)
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
  /** The scoped service credential. Not shared: SD-05. */
  readonly serviceToken: string
  readonly upstreamDeadlineMs: number

  /**
   * `chain → JSON-RPC endpoint`. Empty by default, which makes a chain with no endpoint refuse
   * rather than fall back to a public node nobody chose.
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
  const outboxSigningSecret = requiredSecret(source, 'OUTBOX_SIGNING_SECRET')

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
    serviceToken: requiredSecret(source, 'SETTLEMENT_SERVICE_TOKEN'),
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
 * the report of it. The message is the one `loadEnv` produced, which by construction never
 * contains a value of a secret.
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
