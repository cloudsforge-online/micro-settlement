/**
 * Local fakes for the three upstreams and for the chain itself, plus the database harness.
 *
 * ## No test in this repository broadcasts to a real network
 *
 * That is an absolute rule and this file is how it is kept. Every chain call in every test goes
 * through `fakeNode`, an in-memory EVM node. The local Hearth testnet on `127.0.0.1:8545` may be
 * READ — it is a useful sanity check that the adapter speaks the same dialect — and nothing here
 * ever sends to it.
 *
 * ## The seam is the JSON-RPC transport, not the chain adapter
 *
 * `fakeNode` implements `JsonRpc`, so the code under test is the REAL `evmChain`: its nonce
 * handling, its fee bounds, its transaction-id derivation, its receipt reading and its death proof
 * are all exercised, and only the wire is imaginary. Faking `OutboundChain` instead would have made
 * every test a test of the fake.
 *
 * ## `fakeCustody` returns REAL RLP
 *
 * It assembles an actual legacy transaction — `rlp([nonce, gasPrice, gasLimit, to, value, data, v,
 * r, s])` — out of the payload it is given. That matters because two production functions read
 * those bytes back: `evmTxHash` derives the id a chain will know them by, and `legacyNonce` reads
 * the nonce out for the death proof. A fake that returned `'0xdeadbeef'` would let both of them be
 * wrong in a way no test could see, and the second of them is the fact an operator refunds a user's
 * money on.
 *
 * It signs nothing, of course. The `v`, `r` and `s` items are structurally valid and
 * cryptographically meaningless, which is exactly right: this service never verifies a signature,
 * it only commits and broadcasts one.
 */

import { createHash } from 'node:crypto'
import postgres from 'postgres'
import { migrate, type Sql as DbSql } from '@cloudsforge/db'
import { Logger, Metrics } from '@cloudsforge/telemetry'
import type { Network } from '@cloudsforge/contracts-chain'
import type { ChainId, FeeBounds, JsonRpc } from './chains.ts'
import { canonicaliseEvm, evmTxHash, TRANSFER_GAS } from './evm.ts'
import { registerServiceMetrics } from './server.ts'
import { MIGRATIONS, TABLES } from './migrations.ts'
import type { CustodyClient, SignRequest, SignedResult, TreasuryCandidate } from './custodyclient.ts'
import type { IndexedTransaction, IndexerClient } from './indexerclient.ts'
import type { LedgerClient, PostEntryRequest, PostedEntry } from './ledgerclient.ts'
import type { Db } from './outbox.ts'
import type { OutboundDeps } from './outbound.ts'
import type { SweepDeps } from './sweeps.ts'
import type { WorkerDeps } from './worker.ts'
import type { AdjudicateDeps } from './adjudicate.ts'
import type { WithdrawalDeps } from './withdrawals.ts'
import type { TreasuryWatchDeps } from './treasury.ts'

/* ------------------------------------------------------------------ RLP, for the fake signer */

function toBytes(value: bigint): Buffer {
  if (value === 0n) return Buffer.alloc(0)
  let hex = value.toString(16)
  if (hex.length % 2) hex = `0${hex}`
  return Buffer.from(hex, 'hex')
}

function rlpItem(payload: Buffer): Buffer {
  if (payload.length === 1 && payload[0]! <= 0x7f) return payload
  if (payload.length <= 55) return Buffer.concat([Buffer.from([0x80 + payload.length]), payload])
  const length = toBytes(BigInt(payload.length))
  return Buffer.concat([Buffer.from([0xb7 + length.length]), length, payload])
}

function rlpList(items: readonly Buffer[]): Buffer {
  const body = Buffer.concat(items)
  if (body.length <= 55) return Buffer.concat([Buffer.from([0xc0 + body.length]), body])
  const length = toBytes(BigInt(body.length))
  return Buffer.concat([Buffer.from([0xf7 + length.length]), length, body])
}

/** A structurally valid legacy transaction. See the file header for why this is not a stub string. */
export function fakeLegacyTx(payload: Record<string, unknown>): string {
  const quantity = (value: unknown): bigint => BigInt(String(value ?? 0))
  const to = String(payload['to'] ?? '').replace(/^0x/, '')
  // A bigint in the payload is a caller passing one directly rather than through custody, which the
  // pure tests do. `JSON.stringify` throws on one, so it is stringified here — the value only has
  // to be a stable function of the payload, not a signature.
  const fingerprint = JSON.stringify(payload, (_key, value: unknown) =>
    typeof value === 'bigint' ? value.toString() : value,
  )
  const items = [
    rlpItem(toBytes(quantity(payload['nonce']))),
    rlpItem(toBytes(quantity(payload['gasPrice']))),
    rlpItem(toBytes(quantity(payload['gasLimit']))),
    rlpItem(Buffer.from(to, 'hex')),
    rlpItem(toBytes(quantity(payload['value']))),
    rlpItem(Buffer.alloc(0)),
    // v, r, s. Structurally valid and cryptographically meaningless: this service never verifies a
    // signature, it commits and broadcasts one. `r` is derived from the payload so two different
    // transactions produce two different transaction ids, which several tests rely on.
    rlpItem(toBytes(BigInt(2 * Number(payload['chainId'] ?? 1) + 35))),
    rlpItem(createHash('sha256').update(fingerprint).digest()),
    rlpItem(createHash('sha256').update(`s:${fingerprint}`).digest()),
  ]
  return `0x${rlpList(items).toString('hex')}`
}

/* ------------------------------------------------------------------ the fake node */

export interface FakeNodeOptions {
  readonly chainId?: number
  readonly gasPriceWei?: bigint
  readonly balances?: Readonly<Record<string, bigint>>
  /** Addresses that have code at them. A withdrawal to one of these is refused. */
  readonly contracts?: readonly string[]
  readonly startingNonce?: number
  readonly head?: bigint
}

export interface FakeNode {
  readonly rpc: JsonRpc
  /** Every method called, in order. Several tests assert on what was NOT asked. */
  readonly calls: ReadonlyArray<{ method: string; params: readonly unknown[] }>
  /** Every set of bytes that reached `eth_sendRawTransaction`. */
  readonly broadcast: readonly string[]
  setBalance(address: string, value: bigint): void
  setGasPrice(value: bigint): void
  setNonce(address: string, value: number): void
  /** Put a broadcast transaction in a block, so a receipt appears. */
  mine(rawTxOrHash: string, options?: { readonly reverted?: boolean }): void
  /** Advance the head, which is what turns confirmations into depth. */
  advance(blocks: number): void
  /** Make the next call of a method throw, once. For the broadcast-failure tests. */
  failNext(method: string, message: string): void
  /** Refuse every call, for the "an unreachable node never refunds" test. */
  setUnreachable(value: boolean): void
}

const hexQuantity = (value: bigint): string => `0x${value.toString(16)}`

export function fakeNode(options: FakeNodeOptions = {}): FakeNode {
  const calls: Array<{ method: string; params: readonly unknown[] }> = []
  const broadcast: string[] = []
  const balances = new Map<string, bigint>()
  const nonces = new Map<string, number>()
  const contracts = new Set((options.contracts ?? []).map((a) => a.toLowerCase()))
  const receipts = new Map<string, { block: bigint; reverted: boolean }>()
  const failures = new Map<string, string>()
  let gasPrice = options.gasPriceWei ?? 20_000_000_000n
  let head = options.head ?? 1_000n
  let unreachable = false

  for (const [address, value] of Object.entries(options.balances ?? {})) {
    balances.set(address.toLowerCase(), value)
  }

  /**
   * The id a real node would know these bytes by, which IS keccak256 of exactly the bytes.
   *
   * It uses the production `evmTxHash` on purpose, and that is not the tests asserting a hash
   * against itself: it is the fake modelling the chain's actual rule. The whole recovery path turns
   * on the derived id matching the one the network uses, so a fake that hashed differently would
   * make every re-broadcast, every receipt lookup and every death proof miss — and the tests would
   * pass only for adapters that never looked a transaction up twice.
   */
  const hashOf = (rawTx: string): string => {
    const derived = evmTxHash(rawTx)
    if (!derived) throw new Error('the fake node was sent something that is not a hex transaction')
    return derived
  }

  const node: FakeNode = {
    calls,
    broadcast,
    setBalance(address, value) {
      balances.set(address.toLowerCase(), value)
    },
    setGasPrice(value) {
      gasPrice = value
    },
    setNonce(address, value) {
      nonces.set(address.toLowerCase(), value)
    },
    mine(rawTxOrHash, mineOptions = {}) {
      const hash = rawTxOrHash.length > 70 ? hashOf(rawTxOrHash) : rawTxOrHash
      receipts.set(hash.toLowerCase(), { block: head, reverted: mineOptions.reverted === true })
    },
    advance(blocks) {
      head += BigInt(blocks)
    },
    failNext(method, message) {
      failures.set(method, message)
    },
    setUnreachable(value) {
      unreachable = value
    },
    rpc: async (method, params) => {
      calls.push({ method, params })
      if (unreachable) throw new Error(`fake node is unreachable (${method})`)
      const failure = failures.get(method)
      if (failure !== undefined) {
        failures.delete(method)
        throw new Error(failure)
      }
      switch (method) {
        case 'eth_chainId':
          return hexQuantity(BigInt(options.chainId ?? 7412))
        case 'eth_gasPrice':
          return hexQuantity(gasPrice)
        case 'eth_blockNumber':
          return hexQuantity(head)
        case 'eth_getBalance': {
          const address = String(params[0]).toLowerCase()
          return hexQuantity(balances.get(address) ?? 0n)
        }
        case 'eth_getTransactionCount': {
          const address = String(params[0]).toLowerCase()
          return hexQuantity(BigInt(nonces.get(address) ?? options.startingNonce ?? 0))
        }
        case 'eth_getCode': {
          const address = String(params[0]).toLowerCase()
          return contracts.has(address) ? '0x60006000' : '0x'
        }
        case 'eth_sendRawTransaction': {
          const rawTx = String(params[0])
          const hash = hashOf(rawTx)
          if (broadcast.includes(rawTx)) {
            // What a real node says for bytes it already holds. The recovery path depends on this
            // being an ERROR rather than a hash, which is exactly why it is modelled.
            throw new Error('already known')
          }
          broadcast.push(rawTx)
          return hash
        }
        case 'eth_getTransactionReceipt': {
          const hash = String(params[0]).toLowerCase()
          const receipt = receipts.get(hash)
          if (!receipt) return null
          return {
            blockNumber: hexQuantity(receipt.block),
            status: receipt.reverted ? '0x0' : '0x1',
          }
        }
        default:
          throw new Error(`the fake node was asked for ${method}, which it does not implement`)
      }
    },
  }
  return node
}

/** A factory that serves one fake node for every chain. */
export function fakeRpc(node: FakeNode): (chain: ChainId) => JsonRpc {
  return () => node.rpc
}

/* ------------------------------------------------------------------ custody */

export interface FakeCustody extends CustodyClient {
  readonly requests: readonly SignRequest[]
  /** How many signatures were actually produced. **The headline test asserts this is 1.** */
  readonly signatures: readonly string[]
  pin(chain: string, network: Network, address: string): void
  unpin(chain: string, network: Network): void
  /** Refuse the next N sign calls with this code. */
  refuseSigning(code: string, message: string): void
  failSigning(err: Error): void
  /**
   * Called just before each signature is produced. The concurrency test uses it to interleave two
   * workers deliberately, so the proof is not an accident of scheduling.
   *
   * Explicitly `| undefined` because `exactOptionalPropertyTypes` is on: clearing the hook by
   * assigning `undefined` is a different thing from the property being absent, and the compiler is
   * right to insist the difference be stated.
   */
  onSign?: ((request: SignRequest) => Promise<void>) | undefined
}

export function fakeCustody(options: { readonly mint?: string } = {}): FakeCustody {
  const requests: SignRequest[] = []
  const signatures: string[] = []
  const pins = new Map<string, string>()
  let refusal: { code: string; message: string } | null = null
  let failure: Error | null = null
  let minted = 0

  const fake: FakeCustody = {
    requests,
    signatures,
    pin(chain, network, address) {
      pins.set(`${chain}:${network}`, address)
    },
    unpin(chain, network) {
      pins.delete(`${chain}:${network}`)
    },
    refuseSigning(code, message) {
      refusal = { code, message }
    },
    failSigning(err) {
      failure = err
    },
    async sign(request: SignRequest): Promise<SignedResult> {
      requests.push(request)
      await fake.onSign?.(request)
      if (failure) {
        const err = failure
        failure = null
        throw err
      }
      if (refusal) {
        const { code, message } = refusal
        refusal = null
        const { CustodySignRefusedError } = await import('./custodyclient.ts')
        throw new CustodySignRefusedError(403, code, message)
      }
      // Real custody asserts the payload shape per family before it signs — `signEvm` wants a
      // field map and `signBitcoin` wants a base64 string — so the fake refuses the wrong shape
      // rather than coercing it. A fake that is laxer than the thing it stands in for is a fake
      // that passes tests production would fail.
      if (typeof request.payload !== 'object' || request.payload === null) {
        throw new Error('the EVM signer was handed a payload that is not a field map')
      }
      const signedTx = fakeLegacyTx(request.payload as Record<string, unknown>)
      signatures.push(signedTx)
      return { signedTx, auditId: `audit-${signatures.length}` }
    },
    async treasuryPin(chain, network) {
      return pins.get(`${chain}:${network}`) ?? null
    },
    async mintTreasury(chain, network): Promise<TreasuryCandidate> {
      minted += 1
      const address =
        options.mint ?? canonicaliseEvm(`0x${minted.toString(16).padStart(40, 'c')}`)
      return { address, reused: false }
    },
    async pinTreasury(chain, network, address) {
      const previous = pins.get(`${chain}:${network}`) ?? null
      pins.set(`${chain}:${network}`, address)
      return { address, supersededAddress: previous }
    },
  }
  return fake
}

/* ------------------------------------------------------------------ indexer */

export interface FakeIndexer extends IndexerClient {
  set(hash: string, transaction: IndexedTransaction | null): void
  setUnavailable(value: boolean): void
  readonly asked: readonly string[]
  /**
   * Every address this service has asked the indexer to WATCH, with the label it sent.
   *
   * Recorded rather than discarded because the label is the whole of the fix: an address registered
   * under the wrong prefix is not in the custody set, and the failure would be indistinguishable
   * from not registering at all — silent, and visible only as a withdrawal freeze weeks later.
   */
  readonly watched: readonly { readonly chain: string; readonly network: string; readonly address: string; readonly label: string }[]
  /** Refuse the next `watch`, as a missing `indexer:write` grant or an outage would. */
  setWatchFails(value: boolean): void
}

/**
 * Empty by default, which is the state that matters most: a transaction the indexer has never seen.
 * That is what a fresh broadcast looks like, and reading it as "not on chain" is the mistake
 * `chainStatusOf` exists to avoid.
 */
export function fakeIndexer(): FakeIndexer {
  const known = new Map<string, IndexedTransaction>()
  const asked: string[] = []
  const watched: { chain: string; network: string; address: string; label: string }[] = []
  let unavailable = false
  let watchFails = false
  return {
    asked,
    watched,
    setWatchFails(value) {
      watchFails = value
    },
    async watch(chain, network, address, label) {
      if (watchFails) {
        const { IndexerUnavailableError } = await import('./indexerclient.ts')
        throw new IndexerUnavailableError('the fake indexer refused the registration')
      }
      watched.push({ chain, network, address, label })
    },
    set(hash, transaction) {
      if (transaction) known.set(hash.toLowerCase(), transaction)
      else known.delete(hash.toLowerCase())
    },
    setUnavailable(value) {
      unavailable = value
    },
    async transaction(_chain, _network, hash) {
      asked.push(hash)
      if (unavailable) {
        const { IndexerUnavailableError } = await import('./indexerclient.ts')
        throw new IndexerUnavailableError('the fake indexer is unavailable')
      }
      return known.get(hash.toLowerCase()) ?? null
    },
  }
}

/* ------------------------------------------------------------------ ledger */

export interface FakeLedger extends LedgerClient {
  readonly entries: readonly PostEntryRequest[]
  /** Every idempotency key it has seen, in order. The double-post test reads this. */
  readonly keys: readonly string[]
  failNext(err: Error): void
}

export function fakeLedger(): FakeLedger {
  const entries: PostEntryRequest[] = []
  const keys: string[] = []
  const byKey = new Map<string, PostedEntry>()
  let failure: Error | null = null
  let counter = 0
  return {
    entries,
    keys,
    failNext(err) {
      failure = err
    },
    async postEntry(request) {
      keys.push(request.idempotencyKey)
      if (failure) {
        const err = failure
        failure = null
        throw err
      }
      const replay = byKey.get(request.idempotencyKey)
      if (replay) return { ...replay, replayed: true }
      counter += 1
      entries.push(request)
      const entry: PostedEntry = {
        id: `entry-${counter}`,
        kind: request.kind,
        recordedAt: new Date(counter).toISOString(),
        replayed: false,
      }
      byKey.set(request.idempotencyKey, entry)
      return entry
    },
  }
}

/* ------------------------------------------------------------------ the estate's readers */

/**
 * **The two user-facing consumers' recipient resolution, restated — a fake, like the others here.**
 *
 * It stands in for the same class of thing `fakeNode` and `fakeCustody` do: the far side of a seam
 * this repository cannot import. It exists because "the payload has a `userId` field" is a much
 * weaker assertion than "the person whose money did not arrive is reachable", and this service spent
 * its whole life emitting a failure that satisfied no reader at all.
 *
 *   - `notify/src/catalogue.ts:120` (`userIdOf`) — `payload.user_id` or `payload.userId`; failing
 *     that the envelope KEY, but only where the registry keys that topic by `user_id`; failing that
 *     an `actor` of `user:<id>`.
 *   - `activity/src/classify.ts:112` (`userFromPayload`) — `payload.userId`, and it must be a uuid.
 *     Deliberately NOT the key: on `settlement.outbound.failed` the key is the withdrawal id and is
 *     also a uuid, so a key fallback returns a well-formed, queryable, wrong "user".
 *
 * Both fallbacks are dead ends for everything this service emits — the registry keys its topics by
 * `withdrawal_id`, `chain:network` and `sweep_source_id`, and `buildEnvelope` stamps
 * `service:settlement` as the actor for every emit here, because a confirmation, a failure and a
 * stuck page all originate in a leased job or an operator's adjudication rather than in the user's
 * own request. **The payload is the only route that exists.**
 *
 * The uuid demand is applied to both, i.e. the stricter reader wins: an id notify would accept and
 * activity would not is a person reached by one surface and not the other, which is not a state this
 * service should be able to produce.
 */
const READER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function estateRecipient(
  envelope: {
    readonly topic: string
    readonly key: string
    readonly actor: string
    readonly payload: Record<string, unknown>
  },
  keyedByUserId: (topic: string) => boolean = () => false,
): string | null {
  const fromPayload = envelope.payload['user_id'] ?? envelope.payload['userId']
  if (typeof fromPayload === 'string' && fromPayload.length > 0) {
    return READER_UUID.test(fromPayload) ? fromPayload : null
  }
  if (keyedByUserId(envelope.topic)) return READER_UUID.test(envelope.key) ? envelope.key : null
  if (envelope.actor.startsWith('user:')) {
    const id = envelope.actor.slice('user:'.length)
    return READER_UUID.test(id) ? id : null
  }
  return null
}

/* ------------------------------------------------------------------ the database harness */

/**
 * **A database test runs only against a database whose name says it is a test database.**
 *
 * Not a convenience: `resetSettlement` truncates every table this service owns, and requiring
 * "test" in the name is the difference between a red build and an emptied environment. This service
 * holds the only record of which signed bytes exist for which payment; the wrong connection string
 * here destroys the evidence every stuck transaction would ever be adjudicated on.
 *
 * Only a `settlement_test` database is ever created or written by this suite.
 */
const url = process.env['SETTLEMENT_TEST_DATABASE_URL']

/** Both halves are required: a URL, and a URL that names a test database. */
export const enabled = Boolean(url && /test/i.test(url))

export const skip = enabled ? false : 'set SETTLEMENT_TEST_DATABASE_URL (name must contain "test")'

export function openDb(max = 8): postgres.Sql {
  if (!enabled) throw new Error('database tests are disabled')
  return postgres(url!, { max, onnotice: () => {} })
}

/**
 * Bring the schema up. Idempotent, so every test file may call it and only the first does work.
 *
 * Deliberately runs the real `MIGRATIONS` rather than a hand-written fixture schema. A fixture would
 * let the constraints drift out of the tests that are supposed to prove they fire — and one of them,
 * `outbound_in_flight_uniq`, is the single most important line in this repository.
 */
export async function migrateTestDb(sql: postgres.Sql): Promise<void> {
  await migrate(sql as unknown as DbSql, MIGRATIONS, { service: 'settlement-test' })
}

/** Empty every table this service owns. `jobs` included, so a lease cannot leak between files. */
export async function resetSettlement(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`truncate ${[...TABLES, 'jobs'].join(', ')} restart identity cascade`)
}

/** Logs are discarded rather than silenced, so a serialisation failure still throws. */
export function quietLogger(): Logger {
  return new Logger({ service: 'settlement-test', sink: () => {} })
}

export const TEST_BOUNDS: FeeBounds = Object.freeze({
  minGasPriceWei: 1_000_000_000n,
  maxGasPriceWei: 500_000_000_000n,
  maxFeeWei: 10n ** 18n,
})

/** The fee a test withdrawal is locked at: exactly `gasPrice × TRANSFER_GAS` at the fake's price. */
export const TEST_FEE = 40_000_000_000n * TRANSFER_GAS

export interface Harness {
  readonly sql: Db
  readonly node: FakeNode
  readonly custody: FakeCustody
  readonly indexer: FakeIndexer
  readonly ledger: FakeLedger
  readonly metrics: Metrics
  readonly outbound: OutboundDeps
  readonly worker: WorkerDeps
  readonly adjudication: AdjudicateDeps
  readonly sweeps: SweepDeps
  readonly withdrawals: WithdrawalDeps
  readonly treasuries: { readonly sql: Db; readonly custody: FakeCustody; readonly network: Network }
  readonly treasuryWatch: TreasuryWatchDeps
}

export interface HarnessOptions {
  readonly network?: Network
  readonly node?: FakeNode
  readonly custody?: FakeCustody
  readonly stuckMinutes?: number
  readonly bounds?: FeeBounds
  readonly sweepEnabled?: boolean
  readonly treasuryTargets?: Readonly<Record<string, string>>
  readonly now?: () => number
}

/** The deps bundle every test needs, wired to fakes and one pool. */
export function harness(sql: postgres.Sql, options: HarnessOptions = {}): Harness {
  const db = sql as unknown as Db
  const node = options.node ?? fakeNode()
  const custody = options.custody ?? fakeCustody()
  const indexer = fakeIndexer()
  const ledger = fakeLedger()
  const metrics = registerServiceMetrics(new Metrics())
  const logger = quietLogger()
  const network = options.network ?? 'testnet'

  const outbound: OutboundDeps = {
    sql: db,
    producer: 'settlement',
    network,
    custody,
    indexer,
    rpc: fakeRpc(node),
    bounds: options.bounds ?? TEST_BOUNDS,
    stuckMinutes: options.stuckMinutes ?? 60,
    logger,
    ...(options.now ? { now: options.now } : {}),
  }
  const treasuries = { sql: db, custody, network }
  return {
    sql: db,
    node,
    custody,
    indexer,
    ledger,
    metrics,
    outbound,
    worker: { ...outbound, metrics, logger },
    adjudication: { ...outbound, metrics, logger },
    sweeps: {
      ...outbound,
      ...treasuries,
      treasuryTargets: options.treasuryTargets ?? {},
      minFeeMultiple: 3,
      probeLimit: 10,
      enabled: options.sweepEnabled ?? true,
    },
    withdrawals: { ...treasuries, producer: 'settlement' },
    treasuries,
    treasuryWatch: { ...treasuries, indexer, logger },
  }
}

/** A deterministic EVM address, so a failure names the same account every run. */
export function testAddress(n: number): string {
  return canonicaliseEvm(`0x${n.toString(16).padStart(40, '0')}`)
}

/** A well-formed `wallet.withdrawal.requested` payload, with the awkward fields already right. */
export function withdrawalPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const fee = TEST_FEE
  const net = 5n * 10n ** 17n
  return {
    withdrawalId: '11111111-1111-4111-8111-111111111111',
    userId: '22222222-2222-4222-8222-222222222222',
    chain: 'ember',
    network: 'testnet',
    assetCode: 'EMBER',
    destination: testAddress(0xd1),
    amount: (net + fee).toString(),
    fee: fee.toString(),
    net: net.toString(),
    reservationEntryId: 'entry-1',
    idempotencyKey: 'wallet:withdrawal:1',
    requestedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
}
