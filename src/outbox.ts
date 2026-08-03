/**
 * Outbox, relay and inbox.
 *
 * Rule 5 of docs/ecosystem/03 §2: every state change others care about writes an outbox row **in
 * the same transaction as the change**. That single word is the whole design. A publish after
 * commit is a publish that is skipped when the process dies in between, and a publish before commit
 * is a publish of something that never happened; both failure modes are silent and both are
 * unrecoverable after the fact. Writing the event with the change makes the outbox row and the
 * domain row succeed or fail together, and turns delivery into a retry problem, which is a problem
 * with a solution.
 *
 * Delivery is at-least-once. The consumer is what makes it effectively-once: `withInbox` inserts
 * `(topic, event_id)` and runs the handler only if that insert was the one that won — AD-10. In
 * this service that is not a nicety, it is the idempotency requirement in wallet's boundary
 * contract: "a redelivered event must not produce a second payment".
 *
 * No broker. Postgres already has transactions and `SKIP LOCKED`.
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import type { Sql, TransactionSql } from 'postgres'
import {
  EVENT_ID_HEADER,
  SIGNATURE_HEADER,
  serviceActor,
  signDelivery,
  verifyDelivery,
  type EventVersion,
} from '@cloudsforge/contracts-events'
import { HttpClient } from '@cloudsforge/http'
import type { Logger } from '@cloudsforge/telemetry'
import type { Handler } from '@cloudsforge/jobs'

export type Db = Sql
export type Tx = TransactionSql

/* ------------------------------------------------------------------ the topics */

/**
 * What this service consumes. One topic, and it is the whole of the handover.
 *
 * wallet validates the destination, quotes the fee, **reserves through the ledger**, writes a
 * `queued` row and emits this. Everything after it is settlement's, which is what makes the chain
 * lease enforceable at all: the lease has to live where the state lives.
 */
export const WALLET_WITHDRAWAL_REQUESTED = 'wallet.withdrawal.requested'

/**
 * What this service emits, and why there are three names for what looks like two events.
 *
 * `settlement.outbound.confirmed` and `.failed` are **wallet's** names, spelled in
 * `wallet/src/settlement.ts` before this repository existed, and wallet's event route already
 * branches on them. They are the contract and they are not renamed.
 *
 * `settlement.withdrawal.completed` is the topic 03-repository-responsibilities gives this service
 * for the same fact, and it carries the outbound transaction as well as the withdrawal — the id,
 * the chain, the hash, the fee actually burned. It exists because `settlement.outbound.confirmed`
 * is deliberately narrow (a withdrawal id, a hash, a timestamp: everything wallet needs to settle a
 * reservation and nothing else), and notify, activity and the operator surfaces want the rest.
 * Emitting both is additive: a subscription is per topic, so a consumer takes whichever it needs
 * and no consumer sees a duplicate.
 */
export const SETTLEMENT_WITHDRAWAL_COMPLETED = 'settlement.withdrawal.completed'
export const SETTLEMENT_OUTBOUND_CONFIRMED = 'settlement.outbound.confirmed'
export const SETTLEMENT_OUTBOUND_FAILED = 'settlement.outbound.failed'
/**
 * **THE REGISTERED NAME FOR A STUCK WITHDRAWAL, AND IT WAS NOT BEING EMITTED.**
 *
 * `@cloudsforge/contracts-events` owns `settlement.withdrawal.stuck`, keyed `chain:network`, with
 * the description "An outbound transaction passed its deadline unconfirmed. Pages on one." Both
 * consumers classify that name — `activity/src/classify.ts:383` and `notify/src/catalogue.ts:433`,
 * the latter at `priority: 'high'` with the reason "Silence here is a user who believes their money
 * has vanished".
 *
 * This service emitted `settlement.outbound.stuck` instead, keyed by the outbound row id. Nothing
 * in the estate has ever subscribed to that name, so **both consumers were dead code and a stuck
 * withdrawal notified nobody** — which is precisely the failure their rules were written for. It is
 * the same defect wallet had with `wallet.deposit.credited` against `wallet.deposit.confirmed`.
 *
 * **`settlement.outbound.stuck` IS GONE, AND NOT BECAUSE IT WAS TIDIER.** The first fix emitted
 * both names, and `micro-contracts` refused to register the second: one payload, one fact, two
 * partitions, no subscriber, and the row id it was keyed by is already on the payload as
 * `outboundId`. Two official names for one fact is exactly the defect being repaired here, so
 * keeping it — even quarantined — would have been a proposal that could never be resolved. See
 * `stuckEvents`.
 */
export const SETTLEMENT_WITHDRAWAL_STUCK = 'settlement.withdrawal.stuck'
export const SETTLEMENT_SWEEP_COMPLETED = 'settlement.sweep.completed'

/* ------------------------------------------------------------------ writing */

/** What a caller emits. The envelope's `id`, `occurredAt` and `producer` are added here. */
export interface DomainEvent {
  /** `<service>.<aggregate>.<past-tense-verb>`. */
  readonly topic: string
  /** Ordering is per `(topic, key)` only. Choose the aggregate id, never a timestamp. */
  readonly key: string
  readonly payload: Record<string, unknown>
  readonly actor?: string
  readonly correlationId?: string
  readonly version?: number
}

/**
 * The wire version, in the CONTRACT's shape.
 *
 * `@cloudsforge/contracts-events` types `EventEnvelope.version` as `` `${number}.${number}` `` — a
 * "major.minor" STRING — and `validateEnvelope` refuses anything else with "version: missing". This
 * service typed it `number` end to end and sent `1`, so **every event it ever relayed was thrown
 * away at the envelope, before a consumer looked at a payload.** The suite stayed green throughout
 * because it tested against its own fake of the other side.
 *
 * The stored column stays an integer — storage records the major — and the mapping to the wire
 * happens here, in one place. The return type is the contract's own `EventVersion`, IMPORTED rather
 * than restated: a local copy of a contract type is a copy that can drift, which is the whole
 * reason this exists.
 */
const wireVersion = (v: number): EventVersion => `${v}.0` as EventVersion

/**
 * The wire envelope. Additive-only, versioned per topic, schema-diff enforced — AD-02.
 *
 * **`actor` and `correlationId` are `string`, not `string | null`.** They were nullable here
 * because the columns are nullable, and that was the version defect wearing two more hats:
 * `validateEnvelope` refuses a null actor ("actor: missing") and a null correlation id
 * ("correlationId: missing; a cross-service investigation stops here"). A nullable column is a
 * storage fact; the wire has no such freedom, and `buildEnvelope` is where the two meet.
 */
export interface EventEnvelope {
  readonly id: string
  readonly topic: string
  readonly key: string
  readonly occurredAt: string
  readonly producer: string
  readonly version: EventVersion
  readonly actor: string
  readonly correlationId: string
  readonly payload: Record<string, unknown>
}

export type Emit = (event: DomainEvent) => void

/** Write events inside a transaction a caller already holds. */
export async function emitInto(
  tx: Tx,
  producer: string,
  events: readonly DomainEvent[],
): Promise<void> {
  for (const event of events) {
    await tx`
      insert into outbox (topic, key, producer, version, actor, correlation_id, payload)
      values (
        ${event.topic},
        ${event.key},
        ${producer},
        ${event.version ?? 1},
        ${event.actor ?? null},
        ${event.correlationId ?? null},
        ${tx.json(event.payload as Record<string, never>)}
      )
    `
  }
}

/**
 * Run a domain change and its events in one transaction.
 *
 * `emit` collects rather than writes, so the events land after the handler has succeeded and a
 * caller cannot accidentally publish an event for a change it then rolled back.
 */
export async function withOutbox<T>(
  sql: Db,
  producer: string,
  fn: (tx: Tx, emit: Emit) => Promise<T>,
): Promise<T> {
  const outcome = await sql.begin(async (tx) => {
    const pending: DomainEvent[] = []
    const value = await fn(tx, (event) => {
      pending.push(event)
    })
    await emitInto(tx, producer, pending)
    // Wrapped so postgres.js does not treat an array-shaped result as a list of promises to
    // unwrap, which would rewrite the caller's return type.
    return { value }
  })
  return outcome.value
}

/* ------------------------------------------------------------------ signing */

/**
 * **THE CONTRACT SIGNS, NOT THIS FILE.**
 *
 * This was a local implementation — `sha256=<hmac over the body>` under a locally-declared
 * `x-cloudsforge-signature` — and five producers carried the same drifted copy. The contract signs
 * `t=<seconds>,v1=<hmac over "<seconds>.<body>">` under `cf-signature`, and every consumer that
 * imports it verifies exactly that. So every delivery this service made was refused: first as
 * "signature: missing" for the header name, and once that was aligned as `malformed_header` for the
 * scheme.
 *
 * The exported names stay, so no call site changes; the implementations are the contract's, so they
 * cannot drift again. The scheme is also STRICTLY stronger than what it replaces — the timestamp is
 * inside the signed message, so a captured delivery stops being a lasting credential after
 * `DELIVERY_TOLERANCE_MS`.
 */
export function signEvent(body: string, secret: string): string {
  return signDelivery(body, secret)
}

/** Timing-safety and the freshness window both live in the contract's verifier. */
export function verifyEventSignature(body: string, secret: string, presented: string): boolean {
  return verifyDelivery(body, presented, secret).ok
}

/* ------------------------------------------------------------------ the inbound seam */

/** The header and the scheme `micro-wallet`'s relay still uses. Deleted with `verifyInbound`'s arm. */
export const LEGACY_SIGNATURE_HEADER = 'x-cloudsforge-signature'
export const LEGACY_EVENT_ID_HEADER = 'x-event-id'

/** `sha256=<hex>` over the body, with no timestamp. The scheme this repository used to sign with. */
function verifyLegacyDelivery(body: string, secret: string, presented: string): boolean {
  const expected = Buffer.from(`sha256=${createHmac('sha256', secret).update(body).digest('hex')}`)
  const actual = Buffer.from(presented)
  // Length first: `timingSafeEqual` throws on a mismatch, and a digest length is public knowledge.
  if (expected.length !== actual.length) return false
  return timingSafeEqual(expected, actual)
}

export type InboundScheme = 'contract' | 'legacy'

/**
 * Verify a delivery this service RECEIVES, under either scheme, and say which one matched.
 *
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS IS A MIGRATION, AND IT IS DELIBERATELY ASYMMETRIC WITH WHAT THIS SERVICE SENDS.**
 *
 * The producer half above is unconditional: everything this service emits is signed the contract's
 * way, because every consumer of it imports the contract. The CONSUMER half cannot be, and the
 * reason is a fact about another repository rather than a preference: this service consumes exactly
 * one topic, `wallet.withdrawal.requested`, and `micro-wallet`'s relay still signs the old way —
 * `wallet/src/outbox.ts:165,168`, a local `x-cloudsforge-signature` and a local `sha256=<hmac>`.
 *
 * Switching only the verifier would 401 every withdrawal request the instant this deploys. That is
 * not a smaller outage than the one being fixed; it is the same service's only inbound path.
 *
 * **THE LEGACY ARM IS NOT A WEAKENING.** It is the same HMAC over the same body under the same
 * secret — the property in force today, unchanged. What it lacks is the contract's timestamp
 * binding, so a captured delivery stays replayable; and a replay is already a no-op here, because
 * `withInbox` dedupes on `(topic, event_id)` and a redelivered withdrawal must not produce a second
 * payment. So the exposure the legacy arm leaves is exactly the one the inbox already closes.
 *
 * **WHAT DELETES IT.** `micro-wallet`'s relay adopting `signDelivery`. `outbox.test.ts` asserts the
 * legacy arm still verifies, so this cannot be removed silently while wallet still needs it — and
 * the scheme is REPORTED on every accepted delivery, so an operator can see the legacy count reach
 * zero before anyone deletes anything, rather than deleting on a belief.
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 */
export function verifyInbound(
  body: string,
  secret: string,
  headers: { readonly contract: string; readonly legacy: string },
): InboundScheme | null {
  if (headers.contract.length > 0 && verifyDelivery(body, headers.contract, secret).ok) return 'contract'
  if (headers.legacy.length > 0 && verifyLegacyDelivery(body, secret, headers.legacy)) return 'legacy'
  return null
}

/* ------------------------------------------------------------------ relay */

export interface RelayDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly signingSecret: string
  readonly batchSize?: number
  readonly deadlineMs?: number
  /** Test seam. Production builds one `HttpClient` per subscription URL. */
  readonly clientFor?: (url: string) => Pick<HttpClient, 'request'>
}

interface OutboxRow {
  readonly id: string
  readonly topic: string
  readonly key: string
  readonly occurred_at: Date
  readonly producer: string
  readonly version: number
  readonly actor: string | null
  readonly correlation_id: string | null
  readonly payload: Record<string, unknown>
}

interface SubscriptionRow {
  readonly id: string
  readonly url: string
}

/**
 * One outbox row → one wire envelope. **The only place an envelope is built.**
 *
 * Exported so `topics.test.ts` can hand the real thing to the contract's own `classifyEnvelope`
 * rather than to a copy. That distinction is the whole point: this service's suite was green while
 * every event it emitted was refused, because both sides tested against imagined counterparts. A
 * guard that builds its own envelope proves only that the guard can build an envelope.
 *
 * The two defaults are the contract's own semantics, not inventions:
 *
 *   - **`correlationId` falls back to the event id.** `makeEvent` does exactly this — "an event
 *     that starts a story rather than continuing one is its own correlation root". A null would be
 *     refused outright, and refusing an event because nobody handed it a request id would lose the
 *     event rather than the trace. In this service the fallback is the common case rather than the
 *     rare one: a sweep, a confirmation and a stuck page all originate in a leased job with no
 *     inbound request behind them.
 *   - **`actor` falls back to `service:settlement`.** An emit with no actor was this service acting
 *     on its own behalf, which is precisely what `serviceActor` spells. `null` is not an actor the
 *     contract has a word for.
 */
export function buildEnvelope(row: OutboxRow): EventEnvelope {
  return {
    id: row.id,
    topic: row.topic,
    key: row.key,
    occurredAt: row.occurred_at.toISOString(),
    producer: row.producer,
    version: wireVersion(row.version),
    actor: row.actor ?? serviceActor('settlement'),
    correlationId: row.correlation_id ?? row.id,
    payload: row.payload,
  }
}

/**
 * The relay job.
 *
 * A leased job rather than a `setInterval`: two replicas running an interval-driven relay both read
 * the same unpublished rows and every subscriber receives every event twice. The lease key names
 * the contended resource — the outbox stream — so exactly one replica relays at a time whatever the
 * replica count is.
 */
export function createRelay(deps: RelayDeps): Handler {
  const batchSize = deps.batchSize ?? 50
  const deadlineMs = deps.deadlineMs ?? 5_000
  // Clients are cached for the life of the process so a circuit breaker accumulates state across
  // ticks. A fresh client per tick has a permanently closed circuit and hammers a dead subscriber.
  const clients = new Map<string, Pick<HttpClient, 'request'>>()
  const clientFor =
    deps.clientFor ??
    ((url: string) => {
      const existing = clients.get(url)
      if (existing) return existing
      const parsed = new URL(url)
      const client = new HttpClient({ baseUrl: parsed.origin, name: `subscriber:${parsed.host}` })
      clients.set(url, client)
      return client
    })

  return async (_job, ctx) => {
    const events = await deps.sql<OutboxRow[]>`
      select id, topic, key, occurred_at, producer, version, actor, correlation_id, payload
        from outbox
       where published_at is null
       order by occurred_at
       limit ${batchSize}
    `

    for (const event of events) {
      if (ctx.signal.aborted) return

      const subscriptions = await deps.sql<SubscriptionRow[]>`
        select id, url from event_subscriptions where topic = ${event.topic} and active = true
      `

      const envelope = buildEnvelope(event)
      // Signed over the exact bytes `HttpClient` will send: it stringifies the same object with the
      // same key order, so the MAC a subscriber recomputes over the received body matches.
      const signature = signEvent(JSON.stringify(envelope), deps.signingSecret)

      for (const subscription of subscriptions) {
        await deliver(deps, clientFor, subscription, envelope, signature, deadlineMs)
      }

      // Only when nothing is outstanding.
      //
      // THE GUARANTEE THIS USED TO CLAIM IS FALSE, and it was carried verbatim by eighteen
      // repositories. It said "a subscriber added after the event was written still receives it",
      // which holds only while some OTHER subscriber is still undelivered. With no active
      // subscription for the topic — the ordinary case for a new event type — the count below is
      // zero on the first pass, the row is published immediately, and it is never reconsidered. A
      // subscriber added afterwards gets nothing.
      //
      // The behaviour is right: an outbox row that stays unpublished because nobody is listening
      // is a backlog that grows for ever. It is the promise that was wrong, and a false guarantee
      // is worse than none, because an integrator plans around it — "register the subscription
      // whenever, the outbox will catch up" is a reasonable thing to believe from the old wording
      // and will silently lose every event published before the subscription existed.
      //
      // Delivery rows ARE computed from the live subscription set on every pass, which is what
      // makes a subscriber added mid-flight receive the remainder. That is the true half.
      const outstanding = await deps.sql<{ n: number }[]>`
        select count(*)::int as n
          from event_subscriptions s
          left join outbox_deliveries d
            on d.subscription_id = s.id and d.event_id = ${event.id}
         where s.topic = ${event.topic}
           and s.active = true
           and d.delivered_at is null
      `
      if ((outstanding[0]?.n ?? 0) === 0) {
        await deps.sql`update outbox set published_at = now() where id = ${event.id}`
      }

      // A long backlog must not outlive the lease and hand the same events to a second replica.
      await ctx.heartbeat()
    }
  }
}

async function deliver(
  deps: RelayDeps,
  clientFor: (url: string) => Pick<HttpClient, 'request'>,
  subscription: SubscriptionRow,
  envelope: EventEnvelope,
  signature: string,
  deadlineMs: number,
): Promise<boolean> {
  const claimed = await deps.sql<{ delivered_at: Date | null }[]>`
    insert into outbox_deliveries (event_id, subscription_id, attempts)
    values (${envelope.id}, ${subscription.id}, 0)
    on conflict (event_id, subscription_id) do update set attempts = outbox_deliveries.attempts + 1
    returning delivered_at
  `
  if (claimed[0]?.delivered_at) return true

  const parsed = new URL(subscription.url)
  try {
    await clientFor(subscription.url).request(`${parsed.pathname}${parsed.search}`, {
      method: 'POST',
      body: envelope,
      deadlineMs,
      // The event id is the idempotency key, which is what makes this POST safe to retry and is the
      // same value the subscriber dedupes on.
      idempotencyKey: envelope.id,
      // Both header names are the CONTRACT's exported constants. `'x-event-id'` was a literal here
      // and `EVENT_ID_HEADER` is `cf-event-id`, so a consumer reading the contract's name found
      // nothing — the same class of drift as the signature scheme, one field along.
      headers: { [SIGNATURE_HEADER]: signature, [EVENT_ID_HEADER]: envelope.id },
      requestId: envelope.correlationId,
    })
    await deps.sql`
      update outbox_deliveries set delivered_at = now(), last_error = null
       where event_id = ${envelope.id} and subscription_id = ${subscription.id}
    `
    return true
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    await deps.sql`
      update outbox_deliveries set last_error = ${message.slice(0, 2_000)}
       where event_id = ${envelope.id} and subscription_id = ${subscription.id}
    `
    // Logged, not thrown: one unreachable subscriber must not stop the other subscribers or the
    // rest of the batch. The job succeeds; the undelivered row is the durable record.
    deps.logger.warn('event delivery failed', {
      topic: envelope.topic,
      eventId: envelope.id,
      subscriptionId: subscription.id,
      err: message,
    })
    return false
  }
}

/* ------------------------------------------------------------------ inbox */

export type InboxOutcome<T> =
  | { readonly status: 'processed'; readonly value: T }
  | { readonly status: 'duplicate' }

/**
 * Run an inbound event's handler exactly once.
 *
 * The insert and the handler share one transaction, so a handler that FAILS leaves no inbox row and
 * the redelivery is processed rather than swallowed — which is the mistake that makes a naive
 * "record then handle" dedupe lose events. In this service losing one would mean a user whose
 * balance is reserved and whose payment is never built.
 */
export { EVENT_ID_HEADER, SIGNATURE_HEADER }

export async function withInbox<T>(
  sql: Db,
  topic: string,
  eventId: string,
  handle: (tx: Tx) => Promise<T>,
): Promise<InboxOutcome<T>> {
  const outcome = await sql.begin(async (tx) => {
    const claimed = await tx<{ event_id: string }[]>`
      insert into inbox (topic, event_id) values (${topic}, ${eventId})
      on conflict (topic, event_id) do nothing
      returning event_id
    `
    if (claimed.length === 0) return { result: { status: 'duplicate' } as InboxOutcome<T> }
    const value = await handle(tx)
    return { result: { status: 'processed', value } as InboxOutcome<T> }
  })
  return outcome.result
}
