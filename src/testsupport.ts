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
import type {
  CustodyClient,
  CustodyTokenContract,
  SignRequest,
  SignedResult,
  TreasuryCandidate,
} from './custodyclient.ts'
import type { IndexedTransaction, IndexerClient } from './indexerclient.ts'
import type { LedgerClient, PostEntryRequest, PostedEntry } from './ledgerclient.ts'
import type { Db } from './outbox.ts'
import type { OutboundDeps } from './outbound.ts'
import { tokensFor, type TokenSweepDeps } from './sweeps.ts'
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
  /**
   * ERC-20 balances, as `contract → owner → amount`.
   *
   * Modelled at the `eth_call` seam rather than by stubbing the adapter, for the reason the file
   * header gives: the code under test stays the REAL `evmChain`, so its calldata encoding, its
   * selector and its result decoding are all exercised and only the wire is imaginary. A contract
   * present here also HAS CODE, because a token address with no code is a different failure and the
   * adapter refuses it — see `tokenBalances` handling in the `eth_getCode` branch.
   */
  readonly tokenBalances?: Readonly<Record<string, Readonly<Record<string, bigint>>>>
}

export interface FakeNode {
  readonly rpc: JsonRpc
  /** Every method called, in order. Several tests assert on what was NOT asked. */
  readonly calls: ReadonlyArray<{ method: string; params: readonly unknown[] }>
  /** Every set of bytes that reached `eth_sendRawTransaction`. */
  readonly broadcast: readonly string[]
  setBalance(address: string, value: bigint): void
  /** Give an owner a token balance, and give the contract code at the same time. */
  setTokenBalance(contract: string, owner: string, value: bigint): void
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

/**
 * The `to` and `value` of a signed legacy transaction, read straight out of the bytes.
 *
 * **TEST-ONLY, AND IT LIVES HERE RATHER THAN IN `evm.ts` FOR A REASON.** Production needs the nonce
 * out of a signed transaction — `legacyNonce`, for the death proof — and nothing else, so exporting
 * a general decoder from the adapter would be adding a parser to the service that has to be right
 * about money in order to make a test convenient. The fake node is a MODEL OF THE CHAIN, and a
 * chain does read these fields, so this belongs to the model.
 *
 * A legacy transaction is `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`. Anything
 * that is not one — a typed envelope, a truncated body — returns null, and the caller treats null
 * as "not a transfer" rather than as a transfer of zero.
 */
function legacyFields(rawTx: string): { readonly to: Buffer; readonly value: bigint } | null {
  const body = rawTx.startsWith('0x') ? rawTx.slice(2) : rawTx
  if (body.length === 0 || body.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(body)) return null
  const bytes = Buffer.from(body, 'hex')

  // Returns [payloadStart, payloadEnd, isList] for the item at `at`, or null.
  const header = (at: number): readonly [number, number, boolean] | null => {
    if (at >= bytes.length) return null
    const tag = bytes[at]!
    const span = (start: number, length: number, list: boolean): readonly [number, number, boolean] | null =>
      start + length <= bytes.length ? [start, start + length, list] : null
    if (tag <= 0x7f) return [at, at + 1, false]
    if (tag <= 0xb7) return span(at + 1, tag - 0x80, false)
    if (tag <= 0xbf) {
      const size = tag - 0xb7
      if (at + 1 + size > bytes.length) return null
      return span(at + 1 + size, Number(BigInt(`0x${bytes.subarray(at + 1, at + 1 + size).toString('hex')}`)), false)
    }
    if (tag <= 0xf7) return span(at + 1, tag - 0xc0, true)
    const size = tag - 0xf7
    if (at + 1 + size > bytes.length) return null
    return span(at + 1 + size, Number(BigInt(`0x${bytes.subarray(at + 1, at + 1 + size).toString('hex')}`)), true)
  }

  const outer = header(0)
  if (!outer || !outer[2]) return null
  let cursor = outer[0]
  const items: Buffer[] = []
  while (cursor < outer[1] && items.length < 9) {
    const item = header(cursor)
    if (!item) return null
    items.push(bytes.subarray(item[0], item[1]))
    cursor = item[1]
  }
  // [nonce, gasPrice, gasLimit, to, value, ...]
  const to = items[3]
  const value = items[4]
  if (!to || !value) return null
  return { to, value: value.length === 0 ? 0n : BigInt(`0x${value.toString('hex')}`) }
}

export function fakeNode(options: FakeNodeOptions = {}): FakeNode {
  const calls: Array<{ method: string; params: readonly unknown[] }> = []
  const broadcast: string[] = []
  const balances = new Map<string, bigint>()
  const nonces = new Map<string, number>()
  const contracts = new Set((options.contracts ?? []).map((a) => a.toLowerCase()))
  const tokenBalances = new Map<string, Map<string, bigint>>()
  for (const [contract, owners] of Object.entries(options.tokenBalances ?? {})) {
    const key = contract.toLowerCase()
    // A registered token contract HAS CODE. Stated here rather than left to each test to remember,
    // because the adapter refuses a token whose address holds none — a check that exists precisely
    // so a wrong address is not read as a zero balance.
    contracts.add(key)
    tokenBalances.set(key, new Map(Object.entries(owners).map(([o, v]) => [o.toLowerCase(), v])))
  }
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

  /**
   * **A MINED TRANSFER MOVES THE BALANCE, BECAUSE ON A REAL CHAIN IT DOES.**
   *
   * This used to be missing and it made a whole class of test vacuous. The two-phase token sweep is
   * exactly that class: phase A pays gas to a deposit address and phase B can only be built if the
   * address now holds it, so a fake whose balances never change makes phase B fail its balance
   * check for ever — and, far worse, a fake that let phase B build ANYWAY would report the sequence
   * working while proving nothing about the only thing it exists to sequence.
   *
   * So `mine` applies the transfer. `to` and `value` are read out of the signed bytes rather than
   * remembered from the request, for `evmTxHash`'s reason: the fake must model what the chain does
   * with THESE bytes, not what the caller meant by them.
   *
   * **IT CREDITS THE RECIPIENT AND DOES NOT DEBIT THE SENDER**, and that limitation is stated
   * rather than hidden. Debiting would need the sender recovered from the signature, which this
   * fake cannot do — no key exists in this repository. The consequence is that this fake models
   * DELIVERY and not SOLVENCY: it will happily let a treasury pay out more than it holds. Nothing
   * asserted against it may therefore be a claim about the treasury running dry; that property is
   * `InsufficientTreasuryError`'s, and it is tested by setting a balance directly.
   */
  const applyTransfer = (rawTx: string): void => {
    const fields = legacyFields(rawTx)
    if (!fields) return
    // `to` is empty on a creation and a token sweep's `value` is zero — both are no-ops here.
    if (fields.to.length !== 20 || fields.value <= 0n) return
    const recipient = `0x${fields.to.toString('hex')}`
    balances.set(recipient, (balances.get(recipient) ?? 0n) + fields.value)
  }

  const node: FakeNode = {
    calls,
    broadcast,
    setBalance(address, value) {
      balances.set(address.toLowerCase(), value)
    },
    setTokenBalance(contract, owner, value) {
      const key = contract.toLowerCase()
      contracts.add(key)
      const owners = tokenBalances.get(key) ?? new Map<string, bigint>()
      owners.set(owner.toLowerCase(), value)
      tokenBalances.set(key, owners)
    },
    setGasPrice(value) {
      gasPrice = value
    },
    setNonce(address, value) {
      nonces.set(address.toLowerCase(), value)
    },
    mine(rawTxOrHash, mineOptions = {}) {
      const isRaw = rawTxOrHash.length > 70
      const hash = isRaw ? hashOf(rawTxOrHash) : rawTxOrHash
      const already = receipts.has(hash.toLowerCase())
      receipts.set(hash.toLowerCase(), { block: head, reverted: mineOptions.reverted === true })
      // ONCE. Mining is idempotent on a real chain — a transaction is in one block — and the test
      // helpers re-mine the whole broadcast list on every tick, so applying the transfer twice
      // would credit the same gas top-up as many times as the loop runs.
      if (isRaw && !already && mineOptions.reverted !== true) applyTransfer(rawTxOrHash)
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
        case 'eth_call': {
          const request = params[0] as { to?: unknown; data?: unknown }
          const to = String(request.to ?? '').toLowerCase()
          const data = String(request.data ?? '')
          // `balanceOf(address)` — the selector and the one 32-byte argument, decoded by hand for
          // the same reason the production encoder builds it by hand: the fake must model what the
          // chain actually does with these exact bytes, not what an ABI library would like them to
          // mean. A malformed call gets the empty result a real node returns.
          if (!data.startsWith('0x70a08231') || data.length !== 2 + 8 + 64) return '0x'
          const owner = `0x${data.slice(10 + 24)}`.toLowerCase()
          const held = tokenBalances.get(to)?.get(owner) ?? 0n
          // Contracts that exist answer a padded uint256; anything else answers 0x, which is what a
          // node returns for a call to an address with no code.
          if (!contracts.has(to)) return '0x'
          return `0x${held.toString(16).padStart(64, '0')}`
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
  /** Register a token, exactly as an operator would in custody's own table. */
  registerToken(token: CustodyTokenContract): void
  /** Refuse the next N sign calls with this code. */
  refuseSigning(code: string, message: string): void
  failSigning(err: Error): void
  /**
   * Make the next `treasuryPin` read FAIL rather than answer "nothing is pinned".
   *
   * The two are different facts and `handleWithdrawalRequested` now acts on the difference: a 404
   * is "no operator has provisioned this chain", which refuses and refunds, while a fault is "we
   * could not ask", which must be redelivered. A fake that could not tell them apart would let the
   * refund branch be reached by an outage.
   */
  failTreasuryPin(err: Error): void
  /**
   * Called just before each signature is produced. The concurrency test uses it to interleave two
   * workers deliberately, so the proof is not an accident of scheduling.
   *
   * Explicitly `| undefined` because `exactOptionalPropertyTypes` is on: clearing the hook by
   * assigning `undefined` is a different thing from the property being absent, and the compiler is
   * right to insist the difference be stated.
   */
  onSign?: ((request: SignRequest) => Promise<void>) | undefined
  /**
   * What the NEXT mint answers with, replacing whatever `fakeCustody({ mint })` fixed at
   * construction.
   *
   * A rotation is two mints in one test and they must answer different addresses — the point of a
   * rotation is that the pin MOVES. Without this the second provisioning re-mints the first
   * address and the test proves nothing, quietly.
   */
  setMint(address: string): void
}

export function fakeCustody(options: { readonly mint?: string } = {}): FakeCustody {
  const requests: SignRequest[] = []
  const signatures: string[] = []
  const pins = new Map<string, string>()
  const tokens: CustodyTokenContract[] = []
  let refusal: { code: string; message: string } | null = null
  let failure: Error | null = null
  let pinFailure: Error | null = null
  let minted = 0
  let mint = options.mint

  const fake: FakeCustody = {
    requests,
    signatures,
    pin(chain, network, address) {
      pins.set(`${chain}:${network}`, address)
    },
    unpin(chain, network) {
      pins.delete(`${chain}:${network}`)
    },
    registerToken(token) {
      tokens.push(token)
    },
    async tokenContracts() {
      return tokens
    },
    refuseSigning(code, message) {
      refusal = { code, message }
    },
    failSigning(err) {
      failure = err
    },
    failTreasuryPin(err) {
      pinFailure = err
    },
    setMint(address) {
      mint = address
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
      if (pinFailure) throw pinFailure
      return pins.get(`${chain}:${network}`) ?? null
    },
    async mintTreasury(chain, network): Promise<TreasuryCandidate> {
      minted += 1
      const address = mint ?? canonicaliseEvm(`0x${minted.toString(16).padStart(40, 'c')}`)
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
  readonly watched: readonly {
    readonly chain: string
    readonly network: string
    readonly address: string
    readonly label: string
    /**
     * The claim that travelled with the registration, which is a separate assertion from the label.
     *
     * A claim is a statement about an address's past and this service is entitled to make it for
     * exactly one kind of address. Recording it here is what lets a test show that an ADOPTED pin
     * never carries one — a wrong claim is invisible on this side and shows up one repository over
     * as a balance derived over history nobody walked.
     */
    readonly freshlyDerived: boolean
  }[]
  /** Refuse the next `watch`, as a missing `indexer:write` grant or an outage would. */
  setWatchFails(value: boolean): void
  /**
   * Behave like a UTXO chain the indexer walked from a cold-start height rather than from genesis.
   *
   * In that state the real indexer refuses a custody balance for any address for which nobody has
   * stated a height below which it had no activity (micro-org#252, `history_unknown`), and an
   * unwatched address has stated nothing — so the refusal survives every retry until somebody
   * registers the address WITH a claim. That deadlock is the whole reason the derived-here path
   * exists, and a fake that answers a number for an unwatched address cannot express it.
   */
  setColdStarted(value: boolean): void
  /**
   * What the indexer will say one address holds. Absent means it REFUSES, not that it holds zero.
   *
   * That distinction is the file under test one repository over: a zero booked as an opening
   * balance is a permanent understatement of custody, so an indexer that cannot answer must
   * produce an unavailability and not a number.
   */
  setBalance(address: string, balance: bigint): void
  /** Every address whose balance was read, in order. Asserts the measure-before-watch ordering. */
  readonly measured: readonly string[]
}

/**
 * Empty by default, which is the state that matters most: a transaction the indexer has never seen.
 * That is what a fresh broadcast looks like, and reading it as "not on chain" is the mistake
 * `chainStatusOf` exists to avoid.
 */
export function fakeIndexer(): FakeIndexer {
  const known = new Map<string, IndexedTransaction>()
  const asked: string[] = []
  const watched: {
    chain: string
    network: string
    address: string
    label: string
    freshlyDerived: boolean
  }[] = []
  const measured: string[] = []
  const balances = new Map<string, bigint>()
  let unavailable = false
  let watchFails = false
  let coldStarted = false
  return {
    asked,
    watched,
    measured,
    setWatchFails(value) {
      watchFails = value
    },
    setColdStarted(value) {
      coldStarted = value
    },
    setBalance(address, balance) {
      balances.set(address.toLowerCase(), balance)
    },
    async custodyBalance(_chain, _network, address) {
      measured.push(address)
      if (coldStarted) {
        // The claim, and only a claim made on THIS address, lifts the refusal. Checked against the
        // watch log rather than a flag so the ordering is what decides it: a caller that measures
        // before watching gets the refusal no matter how entitled it was to the claim it never
        // made.
        const claimed = watched.some(
          (entry) => entry.address.toLowerCase() === address.toLowerCase() && entry.freshlyDerived,
        )
        if (!claimed) {
          const { IndexerUnavailableError } = await import('./indexerclient.ts')
          throw new IndexerUnavailableError(
            `GET /v1/custody/…/addresses/${address} → 503 history_unknown: nobody has stated from ` +
              'which height this address could have had activity',
          )
        }
      }
      const balance = balances.get(address.toLowerCase())
      if (balance === undefined) {
        // Absent is a REFUSAL, never a zero — the same line the real indexer holds. A test that
        // forgets to arm a balance gets an outage, which is the honest thing for it to get.
        const { IndexerUnavailableError } = await import('./indexerclient.ts')
        throw new IndexerUnavailableError(`the fake indexer has no balance armed for ${address}`)
      }
      return {
        balance,
        observedAtBlock: 41,
        observedAtBlockHash: `0x${'ab'.repeat(32)}`,
        requiredConfirmations: 60,
      }
    },
    async watch(chain, network, address, label, freshlyDerived = false) {
      if (watchFails) {
        const { IndexerUnavailableError } = await import('./indexerclient.ts')
        throw new IndexerUnavailableError('the fake indexer refused the registration')
      }
      watched.push({ chain, network, address, label, freshlyDerived })
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
 *   - `notify/src/catalogue.ts` (`userIdOf`) — `payload.user_id` or `payload.userId`; failing
 *     that the envelope KEY, but only where the registry keys that topic by `user_id`; failing that
 *     an `actor` of `user:<id>`.
 *   - `activity/src/classify.ts` (`userFromPayload`) — `payload.userId`, and it must be a uuid.
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
  readonly sweeps: TokenSweepDeps
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
  readonly tokenSweepEnabled?: boolean
  readonly minTokenSweep?: bigint
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
      // Defaulted ON in tests and OFF in production, and the asymmetry is deliberate: the tests
      // exist to exercise this path, and `env.ts` explains at length why a deployment must not have
      // it until wallet credits token deposits.
      tokenSweepEnabled: options.tokenSweepEnabled ?? true,
      minimumTokenSweep: options.minTokenSweep ?? 0n,
      tokens: async (chain, network) => tokensFor(await custody.tokenContracts(), chain, network),
    },
    withdrawals: { ...treasuries, producer: 'settlement' },
    treasuries,
    treasuryWatch: { ...treasuries, indexer, ledger, producer: 'settlement', logger },
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
