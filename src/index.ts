/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this file.
 *
 * What this file deliberately does **not** do: run migrations. That is `src/migrator.ts`, a separate
 * one-shot process — AD-17 and rule 7. In this service that is more than hygiene: below
 * `SCHEMA_VERSION` the partial unique index that makes two in-flight transactions on one chain
 * impossible may not exist, and a service that could create it at boot is a service that could start
 * without it.
 *
 * Traces are exported by the OpenTelemetry SDK loaded ahead of this module —
 * `NODE_OPTIONS=--import @opentelemetry/auto-instrumentations-node/register` in the deploy, which
 * reads `OTEL_EXPORTER_OTLP_ENDPOINT` and friends from the environment itself. That is why no
 * `OTEL_*` variable appears in `src/env.ts`: the service does not read them, so under rule 9 it must
 * not declare them.
 */

import postgres from 'postgres'
import { assertSchemaAtLeast, type Sql as DbSql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Verifier, serviceTokenProbe } from '@cloudsforge/auth'
import { Lifecycle, httpProbe, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, registerServiceMetrics } from './server.ts'
import { registerHandlers, rescheduleRecurring, seedRecurring } from './jobs.ts'
import { chainStatuses, rpcFactory } from './registry.ts'
import { buildUpstreams } from './upstreams.ts'
import type { Db } from './outbox.ts'
import type { OutboundDeps } from './outbound.ts'
import type { WorkerDeps } from './worker.ts'
import { tokensFor, type TokenSweepDeps } from './sweeps.ts'
import { publishStuckWithdrawals } from './stuck.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder secret has already
//    exited with a structured line naming the variable.

// 2. Telemetry, before anything that can fail. A logger that exists before the pool means the
//    pool's failure is a structured, searchable, redacted line rather than a bare V8 stack the
//    collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
})
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
logger.info('starting', {
  version: env.version,
  schemaVersion: SCHEMA_VERSION,
  network: env.network,
  // Said at boot rather than discovered from a refused withdrawal an hour later. A chain with an
  // adapter but no endpoint is the failure most likely to be a deploy mistake.
  //
  // **EVERY chain, not only the implemented ones, and each with a status rather than a boolean.**
  // It listed `implementedChains()` alone, which answered the question "is this deploy wired up"
  // and left the more common one unanswerable: an operator looking for DOGE saw no DOGE row and
  // could not tell whether this build lacks the adapter or the deploy lacks the endpoint. Those
  // are two different tickets, filed against two different repositories. The three statuses are
  // exhaustive over `CHAIN_IDS` and are the three real conditions:
  //
  //   * `ready` — there is an adapter and an endpoint. Withdrawals work.
  //   * `no_endpoint` — there is an adapter and no `SETTLEMENT_RPC_URLS` entry. Every call ends at
  //     `NoEndpointError`, which is classified and refunded at the deadline. **The service starts
  //     anyway**: refusing to boot for a chain nobody is using would take down the chains that do
  //     work, and pretending it works would leave a user's balance reserved for a quarter.
  //   * `unimplemented` — no adapter in this build, whatever the deploy supplies.
  //
  // `Boolean(...)` IS THE WHOLE LINE'S SAFETY AND IT IS NOT AN ABBREVIATION. A UTXO endpoint is
  // `http://rpcuser:rpcpassword@host:8332` — Core has no anonymous JSON-RPC — so the value here is
  // a credential, and this line is emitted on every start of every replica. Report that an
  // endpoint exists; never report which one. `redactUserinfo` in env.ts is the same rule at the
  // only other place a raw entry from this map could have reached a log.
  chains: chainStatuses(env.rpcUrls),
})

// 3. The database pool. Opened before the schema assertion for the obvious reason that the
//    assertion is a query, and before the Lifecycle because the readiness probe closes over it.
const sql = postgres(env.databaseUrl, {
  max: env.databasePoolMax,
  // postgres.js writes notices to stderr as unstructured text by default, which is how a connection
  // string ends up in a log the collector cannot parse.
  onnotice: () => {},
})

// 4. Assert the schema. This does NOT migrate. Failing here rather than serving is the point: a
//    replica of the new code answering against the old schema is a replica whose in-flight index
//    may not exist, which is two workers signing against one nonce with nothing to stop them.
try {
  await assertSchemaAtLeast(sql as unknown as DbSql, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. The upstreams, and the credential that authenticates every call to them. Constructed before
//    the Lifecycle so its probes can close over them, and all three take the same scoped credential
//    — never a shared one (SD-05). The wiring itself lives in `./upstreams.ts` and is covered by
//    `servicetoken.test.ts`: it was untestable here, and what was untestable here was wrong for
//    months. See that file.
const { identityTokens, custody, indexer, ledger } = buildUpstreams(env, {
  originatingService: SERVICE,
  onEvent: (event) => {
    if (event.kind === 'exchange_failed') {
      // `warn`, not `error`, while a usable token is still held: the 20% slack after the refresh
      // point exists precisely so a few of these are survivable and uninteresting.
      const level = event.hadUsableToken ? 'warn' : 'error'
      logger[level]('service token exchange failed', {
        err: event.err,
        hadUsableToken: event.hadUsableToken,
      })
    } else if (event.kind === 'minted') {
      logger.info('service token minted', {
        service: event.service,
        expiresIn: event.expiresIn,
        refreshInMs: event.refreshInMs,
      })
    } else {
      logger.warn('service token', { event: event.kind, url: event.url })
    }
  },
})

if (!identityTokens) {
  // Not `fatal` and exit: the image must be able to boot without this so CI's startup smoke test
  // can read /livez, and a service that refuses to start is a service whose logs nobody reads.
  // `/readyz` is where the absence is enforced — the `identity-credential` probe below is hard, so
  // an unconfigured replica takes no traffic.
  logger.error('no identity credential is configured; every call to a peer will fail 503', {
    hint:
      'set SETTLEMENT_IDENTITY_CREDENTIAL, or put the cfsc_… credential in SETTLEMENT_SERVICE_TOKEN. ' +
      'deploy/scripts/estate-bootstrap.sh already mints it into compose/estate/tokens.env',
  })
}
if (env.legacyServiceTokenPresent) {
  logger.error('SETTLEMENT_SERVICE_TOKEN carries a TOKEN, not a credential, and is IGNORED', {
    hint: 'it is a 600-second token read once at boot; a cfsc_… credential replaces it',
  })
}

const rpc = rpcFactory({ urls: env.rpcUrls, deadlineMs: env.rpcDeadlineMs })

// 6. The Lifecycle and its probes, before the routes, because `/readyz` is a route and it needs
//    something to report.
const lifecycle = new Lifecycle({
  // Must exceed one load-balancer probe interval or the balancer is still sending traffic when the
  // process stops accepting it.
  drainDelayMs: 5_000,
  // Generous, because a drain must not cut a worker between a signature and its commit. The runner
  // is given 20 seconds below and this is the ceiling around it.
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})

lifecycle
  .addProbe(
    postgresProbe('postgres', (signal) =>
      // Racing the signal is what turns "the database is not answering" into a failed probe rather
      // than a hung readiness endpoint.
      Promise.race([
        sql`select 1`,
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
        }),
      ]),
    ),
  )
  .addProbe(httpProbe('identity-jwks', env.identityJwksUrl, { kind: 'soft' }))
  // HARD, and the only hard probe here besides the database. Unlike the three below, this does not
  // report a peer having a bad minute — it fails only when no credential is configured at all,
  // which is a deployment that can neither sign nor broadcast and will not fix itself. An identity
  // OUTAGE returns warn, deliberately, so one bad minute in identity does not empty every balancer
  // in the estate at once.
  .addProbe(serviceTokenProbe(identityTokens))
  // SOFT, all three, and deliberately. Custody being down means no new signature can be made — but
  // this service must stay in its balancer to keep ADVANCING transactions that are already signed,
  // which is the state where a user's money is actually at risk. Marking any of them hard would
  // remove settlement from rotation for the duration of somebody else's incident, which is a
  // cascade, not a safety measure.
  .addProbe(httpProbe('custody', `${env.custodyUrl}/livez`, { kind: 'soft' }))
  .addProbe(httpProbe('indexer', `${env.indexerUrl}/livez`, { kind: 'soft' }))
  .addProbe(httpProbe('ledger', `${env.ledgerUrl}/livez`, { kind: 'soft' }))

// 7. The dependency bundles. Built once and shared, so the worker, the sweeper, the adjudicator and
//    the routes cannot disagree about which network they are on or which bounds they are enforcing.
const db = sql as unknown as Db
const bounds = {
  minGasPriceWei: env.minGasPriceWei,
  maxGasPriceWei: env.maxGasPriceWei,
  maxFeeWei: env.maxFeeWei,
}
const outbound: OutboundDeps = {
  sql: db,
  producer: SERVICE,
  network: env.network,
  custody,
  indexer,
  rpc,
  bounds,
  stuckMinutes: env.stuckMinutes,
  logger,
}
const worker: WorkerDeps = { ...outbound, metrics, logger: logger.child({ component: 'worker' }) }
const treasuries = { sql: db, custody, network: env.network }
const sweeps: TokenSweepDeps = {
  ...outbound,
  ...treasuries,
  treasuryTargets: env.treasuryTargets,
  minFeeMultiple: env.sweepMinFeeMultiple,
  probeLimit: 10,
  enabled: env.sweepEnabled,
  tokenSweepEnabled: env.tokenSweepEnabled,
  minimumTokenSweep: env.minTokenSweep,
  // Read from custody on every pass rather than cached at boot. A token an operator registers must
  // become sweepable without a redeploy, and — the direction that matters more — one they REMOVE
  // must stop being swept immediately. A cache here would be this service's own second copy of the
  // allowlist, which is the exact thing reading from custody exists to avoid.
  tokens: async (chain, network) => tokensFor(await custody.tokenContracts(), chain, network),
  logger: logger.child({ component: 'sweeper' }),
}

// 8. Routes. After the Lifecycle so the health handlers report real state, and after the pool so the
//    stores are real rather than a lazily-connected surprise on the first request.
const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })
const server = createServer({
  lifecycle,
  logger,
  metrics,
  verifier,
  network: env.network,
  outbound,
  adjudication: { ...outbound, metrics, logger: logger.child({ component: 'adjudication' }) },
  withdrawals: { ...treasuries, producer: SERVICE },
  treasuries,
  sweeps,
  // The ACCEPT list, not the signing key: verification widens for the rotation window, signing
  // does not. Absent `OUTBOX_ACCEPT_SECRETS` this is `[env.outboxSigningSecret]`, i.e. unchanged.
  eventSigningSecret: env.outboxAcceptSecrets,
  // Queue depth is sampled at scrape time rather than on a timer. There is no `setInterval` in this
  // repository, and CI greps for one — rule 8.
  beforeScrape: async () => {
    const stats = await queue.stats()
    metrics.set('jobs_pending', stats.pending)
    metrics.set('jobs_overdue', stats.overdue)
    // `withdrawal_stuck_total` joins them here rather than being incremented by the worker, and
    // that is the whole design: a tally the worker keeps cannot report a dead worker, and a dead
    // worker is one of the two ways a withdrawal gets stuck. The route logs and continues if this
    // throws, so a scrape never fails on it. See `stuck.ts`.
    await publishStuckWithdrawals({
      sql: db,
      metrics,
      network: env.network,
      stuckMinutes: env.stuckMinutes,
    })
  },
})

// 9. The job runner, started before `listen()`. Background work is claimed under a lease, so a
//    replica that is draining stops claiming before it stops serving — `shouldClaim` is wired to the
//    Lifecycle for exactly that.
const queue = new JobQueue(sql as unknown as JobsSql, {
  owner: env.instanceId,
  // Longer than the default 60 seconds because a chain job holds its lease across a node round
  // trip, a custody round trip and a broadcast. The handler heartbeats between steps, so this is
  // the ceiling on a step rather than on the job — but it must still exceed the slowest single
  // step, or a second worker takes the chain while a signature is in the air.
  leaseMs: 120_000,
})
const reschedule = rescheduleRecurring(queue, env.network, logger)
const runner = new JobRunner({
  queue,
  concurrency: 4,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    if (event.kind) {
      if (event.type === 'claimed') metrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') metrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') metrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') metrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) {
        metrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
      }
    }
    if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
      logger.error('job failure', { ...event })
    }
    reschedule(event)
  },
})

registerHandlers(runner, {
  sql: db,
  logger,
  metrics,
  signingSecret: env.outboxSigningSecret,
  worker,
  sweeps,
  fees: { sql: db, ledger, logger: logger.child({ component: 'fees' }), producer: SERVICE },
  // What makes swept coin visible to the platform's solvency check. Built from `treasuries` rather
  // than from `sweeps`, because the treasury must be registered whether or not `SWEEP_ENABLED` is
  // set: it is the address every withdrawal is paid from either way.
  // `ledger` and `producer` because registering an address and booking it are one operation — an
  // address the indexer counts and the ledger does not is drift, and EMBER reconciles at zero
  // tolerance. See the correction in `registerTreasuryWithIndexer`.
  treasuryWatch: {
    ...treasuries,
    indexer,
    ledger,
    producer: SERVICE,
    logger: logger.child({ component: 'treasury-watch' }),
  },
})
await seedRecurring(queue, env.network)
runner.start()

// 10. Listen. Last of the construction steps, because a socket that accepts before its dependencies
//     exist is a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 11. Ready. Only now does `/readyz` start answering 200 and the balancer send traffic.
lifecycle.markReady()

// 12. Signal handlers, last of all. Hooks run in reverse registration order, so the server closes
//     first, then the runner stops claiming and DRAINS — which is the step that matters here: a
//     SIGTERM between a signature and its commit would otherwise discard bytes that had already
//     been made, and although that is safe (nothing was broadcast), it wastes a custody signature
//     and a nonce read on every deploy. Then the pool closes with nothing left to use it.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      // Idle keep-alive sockets hold the server open past the drain budget.
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
