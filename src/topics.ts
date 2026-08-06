/**
 * The producer half of the bus contract: what this service puts on the wire, and whether the estate
 * can read it.
 *
 * ## The defect this file exists to close
 *
 * Every consumer in the estate is pinned to `@cloudsforge/contracts-events`. `activity` declares its
 * classifier table `satisfies Readonly<Record<TopicName, _>>`; `notify` asserts it has a rule for
 * every registry topic. **The producer was pinned to nothing at all** — not to the topic names and,
 * worse, not to the shape of the envelope it wrote them into.
 *
 * Three instances of that one class were live in this repository, and together they mean **nothing
 * this service has ever emitted reached anyone**:
 *
 *   - **A version stamped wrong.** `EventEnvelope.version` is `` `${number}.${number}` `` in the
 *     contract — a "major.minor" STRING. This service typed it `number` end to end and sent `1`,
 *     and `validateEnvelope` refuses that with "version: missing". `actor` and `correlationId` went
 *     out as `null`, which it refuses too. The delivery arrived and the consumer threw it away at
 *     the envelope, before anything looked at a payload.
 *   - **A signature scheme drifted from the contract.** A local `sha256=<hmac>` under a local
 *     `x-cloudsforge-signature`, where the contract signs `t=…,v1=…` under `cf-signature`. Refused
 *     as "signature: missing", then as `malformed_header` once the name was aligned.
 *   - **A topic renamed on the wire.** The registry owns `settlement.withdrawal.stuck` keyed
 *     `chain:network`; this service emitted `settlement.outbound.stuck` keyed by the row id.
 *     `activity/src/classify.ts` and `notify/src/catalogue.ts` both classify the registered
 *     name, so both were dead code and a stuck withdrawal notified nobody.
 *
 * These are one defect wearing three hats: **the producer is free and the consumer is pinned.** So
 * this file pins the producer, in both directions and two ways:
 *
 *   1. **At compile time.** `EventEnvelope.version` in `outbox.ts` is the contract's `EventVersion`,
 *      imported rather than restated. Assigning the stored integer to it is a type error, which is
 *      `pnpm typecheck`, which is the build.
 *   2. **At test time, against the source rather than against this list.** `topics.test.ts` reads
 *      every topic literal out of `src/` and reconciles that set with the registry, and it builds a
 *      real envelope through the relay's own `buildEnvelope` and hands it to the contract's own
 *      `classifyEnvelope`. A test that compared this list with the registry would agree with itself
 *      for ever while the emit sites drifted underneath it — which is exactly what happened.
 */

import {
  classifyEnvelope,
  isRegisteredTopic,
  isValidTopicName,
  topicsProducedBy,
  type TopicName,
  type TopicSpec,
} from '@cloudsforge/contracts-events'
import {
  SETTLEMENT_OUTBOUND_CONFIRMED,
  SETTLEMENT_OUTBOUND_FAILED,
  SETTLEMENT_SWEEP_COMPLETED,
  SETTLEMENT_WITHDRAWAL_COMPLETED,
  SETTLEMENT_WITHDRAWAL_STUCK,
} from './outbox.ts'

/** This service's own name, and the namespace it is the only permitted producer under. */
export const SERVICE = 'settlement'

/**
 * Every topic this service emits.
 *
 * The constants are imported from the module that declares them rather than redeclared, so this
 * list cannot name a topic whose spelling has since changed under it. `topics.test.ts` additionally
 * reads the literals back out of `src/`, so it cannot name one that no emit site produces either.
 */
export const EMITTED_TOPICS = Object.freeze([
  SETTLEMENT_WITHDRAWAL_COMPLETED,
  SETTLEMENT_WITHDRAWAL_STUCK,
  SETTLEMENT_OUTBOUND_CONFIRMED,
  SETTLEMENT_OUTBOUND_FAILED,
  SETTLEMENT_SWEEP_COMPLETED,
] as const)

export interface ProposedTopic {
  /** Why the fact belongs on the bus at all. Read by a human reviewing the contracts change. */
  readonly reason: string
  /** The entry to add to `TOPICS` in `@cloudsforge/contracts-events`, verbatim. */
  readonly spec: TopicSpec
}

/**
 * Topics this service emits that the shared registry does not yet name.
 *
 * A quarantine, not an exemption, with three properties that keep it honest:
 *
 *   - An entry carries the exact `TopicSpec` it is asking for, so adopting it into
 *     `contracts/packages/events/src/index.ts` is a copy rather than a fresh design.
 *   - `topics.test.ts` asserts every entry is **genuinely absent** from the registry. The moment
 *     contracts registers one, this file fails until the entry is deleted — so the quarantine
 *     empties itself rather than rotting into a permanent allow-list.
 *   - An emit site whose topic is in neither the registry nor here fails the test.
 *
 * `keyedBy` on each is read off the emit site, never chosen here: the key is the ordering
 * partition, so it is contract rather than a producer's private preference.
 *
 * ## IT IS EMPTY, AND IT EMPTIED ITSELF — both halves matter
 *
 * Four topics were proposed here and none is left, by two different routes, and the difference
 * between them is the reason this is a quarantine rather than an allow-list:
 *
 *   - **`settlement.outbound.confirmed`, `settlement.outbound.failed` and
 *     `settlement.sweep.completed` were ADOPTED.** `micro-contracts` registered all three, and the
 *     "a pending proposal disappears once contracts adopts it" test went red until the entries were
 *     deleted. Adoption changed one of them: `sweep.completed` was proposed keyed by the outbound
 *     row and registered keyed by `sweep_source_id`. **The registry won and the emit site moved** —
 *     see `sweepCompletedEvents`. That is what "keyedBy is contract" costs when it costs something.
 *   - **`settlement.outbound.stuck` was REFUSED**, and that is a different state from pending. It
 *     was the per-row twin of `settlement.withdrawal.stuck`: one payload, one fact, two partitions,
 *     no subscriber anywhere, and the row id it was keyed by already on the payload as `outboundId`.
 *     Registering it would have put two official names on one fact, which is the
 *     `wallet.deposit.credited` defect this whole file exists to close. So the SECOND EMIT was
 *     deleted rather than the proposal being left here: an entry for something that has been
 *     refused is a proposal the self-emptying check can never resolve, and it would sit here
 *     looking like work in progress for ever.
 *
 * An empty quarantine is the correct end state, not a reason to delete the machinery. The next
 * topic this service invents lands here before it lands in the registry.
 */
export const AWAITING_REGISTRATION: Readonly<Record<string, ProposedTopic>> = Object.freeze({})

/**
 * The field of the outbound row each emitted topic uses as its ordering partition.
 *
 * **This exists so that "the key is the registry's, not the producer's" is a test rather than a
 * sentence.** `topics.test.ts` calls the real emit functions with a fixture row and asserts each
 * event's key is the value named here — and separately asserts this table agrees with
 * `topicSpec(topic).keyedBy` for every registered topic. A regex over the emit site would have
 * proved only that a line of code looks a certain way.
 *
 * The registry's `keyedBy` is a NAME for a value, not a column of this service's table, so the
 * translation is spelled out rather than inferred: `withdrawal_id` is `sourceRef` on a withdrawal
 * row, `sweep_source_id` is `sourceRef` on a sweep row, and `chain:network` is composed.
 */
export const KEYED_BY: Readonly<Record<string, string>> = Object.freeze({
  'settlement.withdrawal.completed': 'withdrawal_id',
  'settlement.withdrawal.stuck': 'chain:network',
  'settlement.outbound.confirmed': 'withdrawal_id',
  'settlement.outbound.failed': 'withdrawal_id',
  'settlement.sweep.completed': 'sweep_source_id',
})

/* ------------------------------------------------------------------ reconciliation */

/** Topics this service emits that no registry names and no proposal explains — always a defect. */
export function undeclaredTopics(emitted: readonly string[]): readonly string[] {
  return emitted
    .filter((topic) => !isRegisteredTopic(topic) && !Object.hasOwn(AWAITING_REGISTRATION, topic))
    .sort()
}

/**
 * Registry topics this service owns and never emits — a feature that can never fire.
 *
 * The direction that is easiest to miss, because nothing breaks and nothing logs: consumers
 * classify the topic, the code path renders it, and nothing ever arrives. It is the direction
 * `settlement.withdrawal.stuck` was wrong in, for the life of this service.
 */
export function unemittedOwnedTopics(emitted: readonly string[]): readonly TopicName[] {
  const seen = new Set(emitted)
  return topicsProducedBy(SERVICE).filter((topic) => !seen.has(topic))
}

/** Proposals the registry has since adopted. Non-empty means delete the entry from the quarantine. */
export function adoptedProposals(): readonly string[] {
  return Object.keys(AWAITING_REGISTRATION).filter(isRegisteredTopic).sort()
}

/** A proposal that could not be pasted into the registry as it stands. */
export function malformedProposals(): readonly string[] {
  return Object.entries(AWAITING_REGISTRATION)
    .filter(([topic, proposal]) => {
      if (!isValidTopicName(topic) || !topic.startsWith(`${SERVICE}.`)) return true
      if (proposal.spec.producer !== SERVICE) return true
      if (proposal.spec.keyedBy.trim() === '') return true
      if (proposal.reason.trim().length < 20) return true
      return false
    })
    .map(([topic]) => topic)
    .sort()
}

/* ------------------------------------------------------------------ the envelope */

/**
 * Every reason a contract-following consumer would refuse this envelope.
 *
 * The check itself is `classifyEnvelope`, and it is the contract's — the exact check `activity`'s
 * ingest and `notify` run on a delivered body. Running it here, on an envelope this service's relay
 * actually built, is the only way a producer finds out it is unreadable without waiting for two
 * services to be composed. Composing two services is how the integer-version defect was found, and
 * it was found months late.
 *
 * ## Why `classifyEnvelope` and not the contract's own `envelopeDefects(value, awaiting)`
 *
 * The wrapper ships beside `classifyEnvelope`, takes this file's quarantine list as its second
 * argument, and looks exactly like a drop-in for this function. It carried a defect: it flattened
 * the verdict to `string[]` and in flattening it DROPPED `unregisteredTopic` whenever any other
 * defect was present, so an envelope on a topic nobody proposed that was ALSO malformed reported
 * only the malformation — the author fixed one thing, re-ran, and only then learned about the
 * topic. That contradicted the contract's own documentation of the verdict type ("an envelope can
 * be both and hiding half of it would send the author to fix one thing twice").
 *
 * **`micro-contracts` has since fixed it (contracts@b79348e), so the wrapper is correct today and
 * this paragraph is history rather than a live warning.** It is kept because the reason to use
 * `classifyEnvelope` outlived the bug: `unregisteredTopic` is a FIELD on the verdict, not a
 * sentence in a list, so there is nothing to drift and nothing a future flattening can drop. Five
 * repositories previously carried the contract's error SENTENCE byte for byte and would all have
 * stopped excusing anything the day it was reworded.
 *
 * The test named "an unproposed topic AND a broken version are reported together" is the durable
 * part. It passes under both the old wrapper's replacement and the fixed one, and it is what would
 * go red if the collapse ever came back — every other assertion in that suite stays green through
 * it, which is the point of writing it separately.
 *
 * ## What this file still decides, and the contract cannot
 *
 * **Which** unregistered topics are excused: the ones `AWAITING_REGISTRATION` proposes. A consumer
 * lagging its producers is normal when twenty-two services deploy independently. Everything else
 * the contract found is returned — a version in the wrong shape, a missing correlation id, an id
 * that is not a UUID, a producer that does not own its topic — because each of those is this
 * service emitting the unreadable.
 */
export function envelopeDefects(envelope: unknown): readonly string[] {
  const verdict = classifyEnvelope(envelope)
  // Reported FIRST, where `validateEnvelope` has always put it, so a reader of a failure sees the
  // registry question before the envelope's own faults.
  const unexplained =
    verdict.unregisteredTopic !== null &&
    !Object.hasOwn(AWAITING_REGISTRATION, verdict.unregisteredTopic)
      ? [
          `topic: "${verdict.unregisteredTopic}" is not in the registry, and AWAITING_REGISTRATION does not propose it`,
        ]
      : []
  return [...unexplained, ...verdict.defects]
}
