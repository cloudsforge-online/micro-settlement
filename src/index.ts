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
import { Verifier } from '@cloudsforge/auth'
import { Lifecycle, httpProbe, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, implementedChains, registerServiceMetrics } from './server.ts'
import { registerHandlers, rescheduleRecurring, seedRecurring } from './jobs.ts'
import { rpcFactory } from './registry.ts'
import { httpCustodyClient } from './custodyclient.ts'
import { httpIndexerClient } from './indexerclient.ts'
import { httpLedgerClient } from './ledgerclient.ts'
import type { Db } from './outbox.ts'
import type { OutboundDeps } from './outbound.ts'
import type { WorkerDeps } from './worker.ts'
import type { SweepDeps } from './sweeps.ts'

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
  chains: implementedChains().map((chain) => ({ chain, endpoint: Boolean(env.rpcUrls[chain]) })),
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

// 5. The upstreams. Constructed before the Lifecycle so its probes can close over their URLs, and
//    all three take the same scoped service token — never a shared one (SD-05).
const token = () => env.serviceToken
const custody = httpCustodyClient({
  baseUrl: env.custodyUrl,
  token,
  deadlineMs: env.upstreamDeadlineMs,
})
const indexer = httpIndexerClient({
  baseUrl: env.indexerUrl,
  token,
  deadlineMs: env.upstreamDeadlineMs,
})
const ledger = httpLedgerClient({
  baseUrl: env.ledgerUrl,
  token,
  deadlineMs: env.upstreamDeadlineMs,
  originatingService: SERVICE,
})
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
const sweeps: SweepDeps = {
  ...outbound,
  ...treasuries,
  treasuryTargets: env.treasuryTargets,
  minFeeMultiple: env.sweepMinFeeMultiple,
  probeLimit: 10,
  enabled: env.sweepEnabled,
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
  eventSigningSecret: env.outboxSigningSecret,
  // Queue depth is sampled at scrape time rather than on a timer. There is no `setInterval` in this
  // repository, and CI greps for one — rule 8.
  beforeScrape: async () => {
    const stats = await queue.stats()
    metrics.set('jobs_pending', stats.pending)
    metrics.set('jobs_overdue', stats.overdue)
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
  treasuryWatch: { ...treasuries, indexer, logger: logger.child({ component: 'treasury-watch' }) },
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
