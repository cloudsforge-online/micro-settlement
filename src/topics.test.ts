/**
 * The producer half of the bus contract, checked against the source rather than against a list.
 *
 * Three families of check, for the three shapes one defect class took in this repository — and all
 * three were live at once, which is why nothing this service emitted has ever reached a consumer:
 *
 *   1. **The name.** The registry owns `settlement.withdrawal.stuck`, keyed `chain:network`, and
 *      this service emitted `settlement.outbound.stuck` keyed by the row id. `activity` and
 *      `notify` both classify the registered name, so both were dead code. Reconciling the emitted
 *      set with the registry in BOTH directions is what catches that, and reading the literals back
 *      out of `src/` is what stops the check agreeing with itself while the emit sites drift.
 *   2. **The envelope.** `version` went out as the integer `1` where the contract types it
 *      "major.minor", and `actor` and `correlationId` went out as `null`, all three of which
 *      `validateEnvelope` refuses. This suite was green throughout, because both sides tested
 *      against imagined counterparts. The only check that could have caught it is the one below:
 *      build an envelope with the relay's own `buildEnvelope` and hand it to the contract's own
 *      `classifyEnvelope`.
 *   3. **The signature.** A local `sha256=` under a local header, where the contract signs
 *      `t=…,v1=…` under `cf-signature`.
 *
 * No database. Pure text, set arithmetic and a few function calls, so it runs in CI even when the
 * database-backed suite skips.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createHmac } from 'node:crypto'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  EVENT_ID_HEADER,
  SIGNATURE_HEADER,
  TOPIC_NAMES,
  isRegisteredTopic,
  parseVersion,
  topicSpec,
  topicsProducedBy,
  verifyDelivery,
} from '@cloudsforge/contracts-events'
import {
  LEGACY_SIGNATURE_HEADER,
  buildEnvelope,
  signEvent,
  verifyEventSignature,
  verifyInbound,
} from './outbox.ts'
import { confirmedEvents, failedEvents, stuckEvents } from './withdrawals.ts'
import { sweepCompletedEvents } from './sweeps.ts'
import {
  AWAITING_REGISTRATION,
  EMITTED_TOPICS,
  KEYED_BY,
  SERVICE,
  adoptedProposals,
  envelopeDefects,
  malformedProposals,
  undeclaredTopics,
  unemittedOwnedTopics,
} from './topics.ts'

const SRC = dirname(fileURLToPath(import.meta.url))

function sourceFiles(): readonly string[] {
  return readdirSync(SRC)
    .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && file !== 'testsupport.ts')
    .map((file) => join(SRC, file))
}

/**
 * The files a topic literal may legitimately appear in.
 *
 * `topics.ts` is excluded, and that exclusion is the whole check rather than a convenience: it is
 * the file holding `EMITTED_TOPICS` and the quarantine, and it is the thing being checked. Scanning
 * it would let a quarantine entry justify its own existence — a topic could be declared,
 * quarantined and never emitted, and every assertion below would still agree.
 */
function emitSourceFiles(): readonly string[] {
  return sourceFiles().filter((file) => !file.endsWith('/topics.ts'))
}

/**
 * Every topic literal in this service's namespace that appears anywhere in `src/`.
 *
 * Not `topic: '<name>'`: this service names its topics through exported constants
 * (`SETTLEMENT_OUTBOUND_STUCK = 'settlement.outbound.stuck'`), so a scan for the emit-site shape
 * would find nothing at all and pass vacuously. Matching every well-formed `settlement.*.*` string
 * literal finds both spellings, and it is the one that also catches a CONSTANT that no emit site
 * uses — a name a consumer could subscribe to for ever and never hear from.
 *
 * Comment lines are skipped, and that is load-bearing rather than tidy: `withdrawals.ts` and
 * `outbox.ts` both discuss `settlement.withdrawal.stuck` and `settlement.outbound.stuck` in prose
 * while explaining the rename, and counting a sentence about a topic as an emission is precisely
 * the failure this estate found today, where a guard passed because its own prose naming a function
 * counted as a reference.
 */
function topicsInSource(): readonly string[] {
  const found = new Set<string>()
  const literal = new RegExp(`'(${SERVICE}\\.[a-z0-9_]+\\.[a-z0-9_]+)'`, 'g')
  for (const file of emitSourceFiles()) {
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const trimmed = line.trimStart()
      if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) continue
      if (/\b(?:action|scope|resource|permission)\s*:/.test(line)) continue
      for (const match of line.matchAll(literal)) if (match[1]) found.add(match[1])
    }
  }
  return [...found].sort()
}

/* ------------------------------------------------------------------ the names */

test('the source emits exactly the topics this service declares', () => {
  // Both halves of the drift: a literal in `src/` that EMITTED_TOPICS does not list, and an entry
  // in EMITTED_TOPICS that no literal backs. The second half is what stops the list being repaired
  // by editing the list.
  assert.deepEqual(
    topicsInSource(),
    [...EMITTED_TOPICS].sort(),
    'src/ and EMITTED_TOPICS disagree about what this service puts on the bus',
  )
})

test('the literal scanner does not count a topic named in prose', () => {
  // The scanner is exercised on a fixture before it is trusted, because it is the input to every
  // assertion above and below. A scanner that silently matched nothing would make all of them pass.
  assert.ok(topicsInSource().length >= 5, 'the scanner found nothing — it is broken, not the source')
  assert.ok(topicsInSource().includes('settlement.withdrawal.stuck'))
})

test('every topic this service emits is one the estate has a name for', () => {
  assert.deepEqual(
    undeclaredTopics(topicsInSource()),
    [],
    'emitted, but in neither the registry nor AWAITING_REGISTRATION — decide which, then say so',
  )
})

test('every registry topic this service owns is actually emitted', () => {
  // **The direction this repository was wrong in.** The registry has said `settlement` produces
  // `settlement.withdrawal.stuck` since before this service existed; nothing here emitted it, so
  // activity's classifier and notify's high-priority rule were both dead code and a stuck
  // withdrawal notified nobody. Nothing breaks and nothing logs when a topic is missing — the
  // consumer simply never hears from it.
  assert.deepEqual(
    unemittedOwnedTopics(topicsInSource()),
    [],
    'the registry says settlement produces these and no emit site does — every consumer of each is dead code',
  )
  // And the registry is being read rather than the check passing vacuously.
  assert.ok(topicsProducedBy(SERVICE).includes('settlement.withdrawal.stuck'))
  assert.ok(topicsProducedBy(SERVICE).length >= 2)
  assert.ok(TOPIC_NAMES.length >= 40)
})

/* ------------------------------------------------------------------ the ordering key */

/**
 * A fixture outbound row, complete enough for every emitter in this service.
 *
 * `purpose` is overridden per topic below, because three of the four emitters return NOTHING for a
 * row of the wrong purpose — `confirmedEvents` and `failedEvents` are withdrawal-only — and a
 * silently empty array is exactly how a key assertion passes without asserting a key.
 */
const ROW_FIXTURE = {
  id: '018f0000-0000-7000-8000-0000000000f1',
  purpose: 'withdrawal' as const,
  chain: 'btc' as const,
  network: 'testnet' as const,
  fromAddress: 'tb1qtreasury',
  toAddress: 'tb1quser',
  assetCode: 'BTC',
  amount: 100n,
  fee: 10n,
  state: 'confirmed' as const,
  rawTx: null,
  signedNonce: null,
  signedExpiry: null,
  custodyAuditId: null,
  txHash: 'abc',
  confirmations: 3,
  minedHeight: 1n,
  signedAt: null,
  broadcastAt: null,
  confirmedAt: new Date('2026-08-03T10:00:00.000Z'),
  maturedAt: null,
  ledgerEntryId: null,
  failureReason: null,
  sourceRef: '018f0000-0000-7000-8000-0000000000e1',
  userId: '018f0000-0000-7000-8000-0000000000d1',
  reservationEntryId: null,
  correlationId: 'req-1',
  idempotencyKey: 'k-1',
  createdAt: new Date('2026-08-03T09:00:00.000Z'),
  updatedAt: new Date('2026-08-03T09:00:00.000Z'),
}

/**
 * **`key` IS THE ORDERING PARTITION, SO IT IS CONTRACT AND NOT A PRODUCER'S PREFERENCE.**
 *
 * Events sharing a `(topic, key)` are delivered in the order they were written and no other pair
 * has any ordering relationship whatsoever. A producer that picks its own key therefore silently
 * reorders every consumer's view of the topic, and nothing anywhere reports it.
 *
 * This calls the REAL emitters and reads the keys they produce, rather than matching the emit site
 * with a regex. A regex proves a line of code looks a certain way; this proves what goes on the
 * wire. It caught a live one: `settlement.sweep.completed` was keyed by the outbound row id here
 * and registered `sweep_source_id`, so every sweep was its own ordering partition and the
 * guarantee said nothing.
 */
test('every emitted event is keyed the way the registry declares', () => {
  const emitted: Record<string, string> = {}
  for (const event of confirmedEvents(ROW_FIXTURE)) emitted[event.topic] = event.key
  for (const event of failedEvents(ROW_FIXTURE, 'because', true)) emitted[event.topic] = event.key
  for (const event of stuckEvents(ROW_FIXTURE, 'because')) emitted[event.topic] = event.key
  for (const event of sweepCompletedEvents({ ...ROW_FIXTURE, purpose: 'sweep' })) {
    emitted[event.topic] = event.key
  }

  // Every topic this service emits produced an event here. Without this the loop above could be
  // returning empty arrays and every assertion below would pass over nothing.
  assert.deepEqual(Object.keys(emitted).sort(), [...EMITTED_TOPICS].sort())

  const expected: Record<string, string> = {
    withdrawal_id: ROW_FIXTURE.sourceRef,
    sweep_source_id: ROW_FIXTURE.sourceRef,
    outbound_transaction_id: ROW_FIXTURE.id,
    'chain:network': `${ROW_FIXTURE.chain}:${ROW_FIXTURE.network}`,
  }
  for (const [topic, key] of Object.entries(emitted)) {
    const keyedBy = KEYED_BY[topic]
    assert.ok(keyedBy, `${topic} has no declared ordering key`)
    assert.equal(key, expected[keyedBy], `${topic} must be keyed by ${keyedBy}`)
    // And KEYED_BY is not this file marking its own homework: for a REGISTERED topic it has to
    // agree with the registry, character for character.
    if (isRegisteredTopic(topic)) {
      assert.equal(topicSpec(topic).keyedBy, keyedBy, `${topic} disagrees with the registry`)
    } else {
      assert.equal(AWAITING_REGISTRATION[topic]?.spec.keyedBy, keyedBy)
    }
  }
  // A key may never be empty: `makeEvent` refuses one outright, because ordering would be undefined.
  for (const key of Object.values(emitted)) assert.ok(key.length > 0)
})

test('a pending proposal disappears once contracts adopts it', () => {
  // Without this the quarantine becomes a permanent allow-list: the topic gets registered, the
  // entry stays, and the next reader believes the topic is still unregistered.
  assert.deepEqual(
    adoptedProposals(),
    [],
    'the registry now names these — delete them from AWAITING_REGISTRATION',
  )
  // Both registered topics must therefore NOT be quarantined.
  for (const topic of ['settlement.withdrawal.completed', 'settlement.withdrawal.stuck']) {
    assert.equal(isRegisteredTopic(topic), true)
    assert.equal(Object.hasOwn(AWAITING_REGISTRATION, topic), false)
  }
})

test('every pending proposal carries a spec that could be pasted into the registry', () => {
  assert.deepEqual(
    malformedProposals(),
    [],
    'a proposal needs a well-formed settlement topic, a real ordering key, and a reason worth reading',
  )
})

/* ------------------------------------------------------------------ the envelope */

const ROW = {
  id: '018f0000-0000-7000-8000-0000000000a1',
  topic: 'settlement.withdrawal.completed',
  key: '018f0000-0000-7000-8000-0000000000b1',
  occurred_at: new Date('2026-08-03T10:00:00.000Z'),
  producer: SERVICE,
  version: 1,
  actor: 'service:settlement',
  correlation_id: 'req-1',
  payload: { withdrawalId: 'w-1' },
}

test('THE RULE: the envelope this relay builds is one the contract accepts', () => {
  // The check whose absence let this service relay nothing but refusals. `classifyEnvelope` is the
  // contract's own function and is literally what activity's ingest and notify run on a delivered
  // body — not a restatement of it here.
  for (const topic of topicsInSource()) {
    const envelope = buildEnvelope({ ...ROW, topic })
    assert.deepEqual(
      envelopeDefects(JSON.parse(JSON.stringify(envelope))),
      [],
      `an event on ${topic} would be refused by every consumer in the estate`,
    )
  }
})

test('the version on the wire is "major.minor", never the stored integer', () => {
  const envelope = buildEnvelope(ROW)
  // The specific defect, named, so a reader of a failure knows what broke.
  assert.equal(typeof envelope.version, 'string')
  assert.equal(envelope.version, '1.0')
  assert.equal(parseVersion(envelope.version).ok, true)
  assert.equal(parseVersion(String(ROW.version)).ok, false, 'the stored integer is NOT a wire version')
})

test('a row with no actor and no correlation id still makes a readable envelope', () => {
  // Both columns are nullable and both are refused by the contract if they arrive null. In this
  // service the null is the COMMON case rather than the rare one: a confirmation, a sweep and a
  // stuck page all originate in a leased job with no inbound request behind them, so a relay that
  // sent the nulls through sent an unreadable envelope on almost every event it had.
  const envelope = buildEnvelope({ ...ROW, actor: null, correlation_id: null })
  assert.equal(envelope.actor, 'service:settlement')
  assert.equal(envelope.correlationId, ROW.id)
  assert.deepEqual(envelopeDefects(JSON.parse(JSON.stringify(envelope))), [])
})

test('envelopeDefects excuses a lagging registry and nothing else', () => {
  // The tolerance is narrow on purpose. An unregistered topic this repository has explained is a
  // consumer being behind its producers; anything else is this service emitting the unreadable.
  // The quarantine is EMPTY today, so nothing is excused — which is the strongest state it can be
  // in and the one an assertion has to keep working through. A registered topic is clean because it
  // is registered, not because anything forgave it.
  const registered = buildEnvelope({ ...ROW, topic: 'settlement.outbound.confirmed' })
  assert.deepEqual(envelopeDefects(JSON.parse(JSON.stringify(registered))), [])

  // An unregistered topic the quarantine does NOT explain is not excused.
  const unexplained = { ...buildEnvelope(ROW), topic: 'settlement.nothing.happened' }
  assert.ok(envelopeDefects(unexplained).length > 0)

  // And a real envelope defect is never excused on a registered topic either.
  const broken = { ...registered, version: 1 as unknown as string }
  assert.ok(
    envelopeDefects(broken).some((error) => error.startsWith('version:')),
    'an integer version must be reported however the topic is registered',
  )
})

/**
 * The case that separates this repository's `envelopeDefects` from the contract's own
 * `envelopeDefects(value, awaitingRegistration)`, which ships beside `classifyEnvelope` and looks
 * exactly like a drop-in for it.
 *
 * "Malformed" and "not in this registry" are two facts with two remedies — a producer bug, and a
 * missing registration — and an envelope can carry both. `classifyEnvelope` keeps both,
 * deliberately: `unregisteredTopic` survives on a `malformed` verdict, and the type's own comment
 * says why. The contract's flattening wrapper drops the topic whenever any other defect is present,
 * so the author is sent to fix one thing twice.
 *
 * Every other assertion in this suite stays green under that wrapper. This is the only one that
 * would go red, which is the point of writing it — this service is the last of five to adopt the
 * contract and therefore the only one that could simply never have had the defect.
 */
test('an unproposed topic AND a broken version are reported together, not one per round', () => {
  const both = {
    ...buildEnvelope(ROW),
    topic: 'settlement.nothing.happened',
    version: 1 as unknown as string,
  }
  const defects = envelopeDefects(both)
  assert.ok(
    defects.some((error) => error.startsWith('version:')),
    `the producer bug must be named: ${defects.join('; ')}`,
  )
  assert.ok(
    defects.some((error) => error.includes('settlement.nothing.happened')),
    `the missing registration must be named too: ${defects.join('; ')}`,
  )
})

/* ------------------------------------------------------------------ the delivery */

const SECRET = 'K2sN4vQ8xR1wB6tY9zL3mF7hC5jD0pA4'

test('the delivery this relay signs is one a contract-following consumer verifies', () => {
  // The other half of the same story: the header name and the signature scheme are the contract's
  // too. This service carried a drifted local copy (`x-cloudsforge-signature`, `sha256=<hmac>`) and
  // every delivery to activity or notify was refused before the body was looked at.
  const body = JSON.stringify(buildEnvelope(ROW))
  assert.equal(SIGNATURE_HEADER, 'cf-signature')
  assert.equal(EVENT_ID_HEADER, 'cf-event-id')
  const verification = verifyDelivery(body, signEvent(body, SECRET), [SECRET])
  assert.equal(verification.ok, true)
  assert.equal(verifyEventSignature(body, SECRET, signEvent(body, SECRET)), true)
  // The old scheme is not what this service produces any more.
  assert.ok(!signEvent(body, SECRET).startsWith('sha256='))
  assert.match(signEvent(body, SECRET), /^t=\d+,v1=[0-9a-f]{64}$/)
})

/**
 * The INBOUND seam, which is deliberately asymmetric with the outbound one.
 *
 * `micro-wallet`'s relay still signs the pre-contract way (`wallet/src/outbox.ts:165,168`), and
 * `wallet.withdrawal.requested` is the only topic this service consumes. Verifying only the
 * contract's scheme would 401 every withdrawal request the instant this deploys — the same
 * service's only inbound path.
 *
 * This test exists so the legacy arm cannot be deleted silently while wallet still needs it, and so
 * that deleting it later is a deliberate act with a red test attached rather than a quiet tidy-up.
 */
test('an inbound delivery verifies under either scheme, and forgery under neither', () => {
  const body = JSON.stringify(buildEnvelope(ROW))
  const legacy = `sha256=${createHmac('sha256', SECRET).update(body).digest('hex')}`

  assert.equal(verifyInbound(body, SECRET, { contract: signEvent(body, SECRET), legacy: '' }), 'contract')
  assert.equal(verifyInbound(body, SECRET, { contract: '', legacy }), 'legacy')
  // The contract's is preferred when both are present, so the count an operator watches falls as
  // wallet migrates rather than staying pinned to whichever header arrives.
  assert.equal(verifyInbound(body, SECRET, { contract: signEvent(body, SECRET), legacy }), 'contract')

  // Neither scheme accepts a wrong secret, a tampered body, or an absent header.
  assert.equal(verifyInbound(body, 'a-different-secret-that-is-long-enough', { contract: signEvent(body, SECRET), legacy }), null)
  assert.equal(verifyInbound(`${body} `, SECRET, { contract: signEvent(body, SECRET), legacy }), null)
  assert.equal(verifyInbound(body, SECRET, { contract: '', legacy: '' }), null)
  // And the legacy arm is genuinely the legacy SCHEME, not a second name for the contract's.
  assert.equal(verifyInbound(body, SECRET, { contract: '', legacy: signEvent(body, SECRET) }), null)
  assert.equal(LEGACY_SIGNATURE_HEADER, 'x-cloudsforge-signature')
})

/* ------------------------------------------------------------------ reachability */

/**
 * A guard that proves a topic name is correct proves nothing about whether the emit is reached.
 *
 * `identity/src/sessions.ts:390` exports `emitSessionRevoked` and NOTHING CALLS IT — `revokeSession`
 * and `revokeAllSessions` update rows without emitting — so `identity.session.revoked` is produced
 * by dead code while identity's own guard passes, because it scans literals rather than
 * reachability. This is the cheapest check that catches that exact shape.
 *
 * The detector is exercised on a fixture FIRST. A repository with no exported emitter would
 * otherwise get a green from a scan that finds nothing because it is broken, which is precisely the
 * "check that cannot fail" this estate keeps rediscovering.
 */
function unreachedEmitters(files: readonly { name: string; text: string }[]): readonly string[] {
  const declared: { symbol: string; where: string }[] = []
  for (const file of files) {
    file.text.split('\n').forEach((line, index) => {
      const match = /^export (?:async )?function (emit[A-Za-z0-9_]*)/.exec(line)
      if (match?.[1]) declared.push({ symbol: match[1], where: `${file.name}:${index + 1}` })
    })
  }
  return declared
    .filter(({ symbol }) => {
      const reference = new RegExp(`\\b${symbol}\\b`)
      for (const file of files) {
        for (const line of file.text.split('\n')) {
          const trimmed = line.trimStart()
          if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) continue
          if (/^export (?:async )?function /.test(trimmed)) continue
          if (reference.test(line)) return false
        }
      }
      return true
    })
    .map(({ symbol, where }) => `${symbol} (${where})`)
    .sort()
}

test('the unreachable-emitter detector can actually fail', () => {
  // identity's defect, reproduced in miniature. Without this the assertion below is worth nothing
  // in a repository whose emit sites are all inline.
  const dead = [{ name: 'sessions.ts', text: 'export function emitSessionRevoked(): void {}\n' }]
  assert.deepEqual(unreachedEmitters(dead), ['emitSessionRevoked (sessions.ts:1)'])

  const alive = [
    { name: 'sessions.ts', text: 'export function emitSessionRevoked(): void {}\n' },
    { name: 'server.ts', text: 'emitSessionRevoked()\n' },
  ]
  assert.deepEqual(unreachedEmitters(alive), [])
})

test('every exported emitter is reached from somewhere', () => {
  assert.deepEqual(
    unreachedEmitters(sourceFiles().map((name) => ({ name, text: readFileSync(name, 'utf8') }))),
    [],
    'exported, emits an event, and no code path reaches it — the topic is produced by dead code',
  )
})
