/**
 * The one-shot migrator.
 *
 * A separate process, run as an init container or a Kubernetes Job, and **never** called from
 * `index.ts`. Three reasons, in increasing order of seriousness:
 *
 *   1. A slow migration would stall every service that waits on this one's health.
 *   2. Two replicas booting together race on `pg_type`, one raises 23505 and crash-loops — which is
 *      why the estate cannot scale a service past one replica today.
 *   3. Migrating from inside the service means the service decides when the schema changes, so a
 *      rollback of the image is not a rollback of the database.
 *
 * And one that is specific to this service: `outbound_in_flight_uniq` is the constraint that makes
 * two in-flight transactions on one chain impossible. A service that could create it at boot is a
 * service that could start without it, and starting without it is two workers signing against one
 * nonce with nothing but a lease between them.
 *
 * Safe to run concurrently from N processes: `@cloudsforge/db` serialises them on an advisory lock
 * derived from the service name, and the losers observe an empty pending set.
 */

import postgres from 'postgres'
import { migrate, type Sql } from '@cloudsforge/db'
import { Logger } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { BASELINE_VERSION, MIGRATIONS } from './migrations.ts'

const log = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
}).child({ step: 'migrate' })

// A tiny pool: the whole run happens on one reserved connection, and a wide pool here only makes a
// migration that has to wait for a lock hold more of the database's connection budget.
const sql = postgres(env.databaseUrl, { max: 2, onnotice: () => {} })

try {
  const result = await migrate(sql as unknown as Sql, MIGRATIONS, {
    service: SERVICE,
    baselineVersion: BASELINE_VERSION,
    onLog: (message, fields) => log.info(message, fields),
  })
  log.info('migrations complete', {
    from: result.alreadyAt,
    to: result.nowAt,
    applied: result.applied.map((a) => `${a.version}:${a.name}`),
  })
  await sql.end({ timeout: 5 })
  process.exit(0)
} catch (err) {
  // Exit non-zero and loudly. The deploy must stop here: a service started against a schema its
  // migrator could not reach is the failure this whole arrangement exists to prevent.
  log.fatal('migration failed', { err })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}
