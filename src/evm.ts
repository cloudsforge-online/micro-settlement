/**
 * EVM: Ethereum, Ethereum Classic and Ember, one implementation.
 *
 * Hearth used to need its own everything — a UTXO selector, a change output, a JSON transaction
 * body, a REST broadcast and a REST confirmation lookup, none of which had an Ethereum equivalent.
 * The rebuild (hearth `docs/evm-spec.md`) deleted all of it: an EMBER payment is a legacy (type 0)
 * EVM transaction against a standard `eth_*` endpoint, so the chains are the same six calls and
 * differ only in which node answers them and which chain id the signature commits to.
 *
 * **ETHEREUM CLASSIC COST THIS FILE NOTHING, AND THAT IS A FACT ABOUT THE FILE RATHER THAN ABOUT
 * ETC.** ETC never adopted EIP-1559: there is no base fee, `eth_maxPriorityFeePerGas` is not
 * answered, and a type-2 envelope is not decodable by its clients. A builder that had grown a 1559
 * path would have needed a second one here and a second fee model in `withdrawals.ts`. This one
 * never did — it has only ever emitted `type: 0` with a `gasPrice`, for Ember because its node has
 * no type-2 decoder and for Ethereum because legacy is still accepted there — so the pre-London
 * chain is the case the existing shape already served.
 *
 * The consequence worth stating, because it is what makes ETC cheap rather than merely possible:
 * **a legacy fee is EXACT at plan time.** `gasLimit * gasPrice` is what the sender pays, with no
 * base-fee movement between quoting and mining and no priority-fee refund afterwards, so the amount
 * booked when the withdrawal is planned is the amount that leaves the treasury. Nothing in this
 * service reads a receipt to correct a fee for any chain, and on ETC there is nothing a receipt
 * could correct.
 *
 * **EVERY AMOUNT HERE IS WEI AND EVERY WEI IS A BIGINT.** One EMBER is 1e18 wei, four orders of
 * magnitude past what a double holds exactly, so there is no `Number()` anywhere on a value — not
 * on a balance, not on a gas price, not on a fee. Hex quantities are parsed with `BigInt('0x…')`
 * and emitted with `toString(16)`, which is exact in both directions. `nonce` and `chainId` are the
 * two exceptions and they are genuinely small integers; both are range-checked before they become
 * numbers, because custody's `signEvm` refuses a non-safe-integer rather than rounding it.
 *
 * ## The four reads before a build, each because getting it elsewhere is a known failure
 *
 *   * `eth_chainId`, **not configuration**. Under EIP-155 the chain id is inside the signature and
 *     the node validates against its own. Custody binds it independently from the address's own row
 *     (`gates.resolveChainId`), so a disagreement is a 403 refusal and never a signature on the
 *     wrong network — but the value has to come from the node for that check to mean anything.
 *   * `eth_getTransactionCount` at **pending**, not latest. A latest nonce ignores anything this
 *     treasury already has in the mempool, which produces a second transaction with the same nonce
 *     — at most one of which can ever be mined. The chain lease means this should not arise; this
 *     is the belt to that braces, and the partial unique index in `migrations.ts` is the third.
 *   * `eth_getBalance` at **latest**, to fail early and specifically. Without it an underfunded
 *     treasury is a signature the node refuses with "insufficient funds", which a worker can only
 *     read as a generic broadcast failure and retry for ever. With it the transaction never gets
 *     signed and the withdrawal is refunded from `pending`, where a refund is safe.
 *   * `eth_getCode`, to refuse a destination that runs code. See `UnsupportedDestinationError`.
 */

import {
  chainSpec,
  type ChainFamily,
  type Network,
} from '@cloudsforge/contracts-chain'
import {
  AddressError,
  FeeOutOfBandError,
  InsufficientTreasuryError,
  UnsupportedDestinationError,
  assetOf,
  type BuildInput,
  type ChainCall,
  type ChainId,
  type DeathInput,
  type DeathVerdict,
  type FeeBounds,
  type OutboundChain,
  type OutboundStatus,
  type UnsignedOutbound,
} from './chains.ts'
import { keccak256 } from './keccak.ts'

/**
 * Gas for a plain native-value transfer: the EIP intrinsic cost, exactly.
 *
 * Fixed rather than estimated, and that is a correctness requirement rather than a saving. The fee
 * is quoted once by wallet at request time and LOCKED onto the withdrawal, because the bytes signed
 * minutes later must be derivable from the row alone — a gas limit re-estimated at signing time
 * would make two attempts at the same withdrawal produce two different transactions, which is
 * exactly the state the whole "one signature, ever" rule exists to make impossible.
 *
 * It is also what makes the destination rule necessary: 21,000 covers a transfer to an account with
 * no code and nothing more.
 */
export const TRANSFER_GAS = 21_000n

/**
 * Gas for one ERC-20 `transfer`. Fixed, for `TRANSFER_GAS`'s reason, and the number matters twice.
 *
 * An ERC-20 transfer is the 21,000 intrinsic cost plus the contract's storage work — roughly 14k
 * for a warm recipient slot and up to ~50k for a cold one, with USDT near the top of that band
 * because it writes more than the minimum. 100,000 sits above every real one and below custody's
 * ceiling of 200,000 (`assertTokenSweep` shares `MAX_TRANSFER_GAS` with the treasury's own
 * transfers), so a top-up computed from it is enough and a sweep priced by it is signable.
 *
 * **IT IS ALSO THE DIVISOR THE LOCKED FEE IS RECOVERED WITH.** `gasPriceForLockedFee` reconstructs
 * a gas price by dividing, so a token sweep divided by `TRANSFER_GAS` would recover a price nearly
 * five times too high and refuse the row as out of band. That is why the divisor is a parameter
 * rather than a constant folded into the function.
 *
 * OVER-FUNDING IS THE SAFE DIRECTION AND IT IS NOT FREE. The top-up sends `gas × price` and the
 * transaction spends what it actually uses, so a little native value is left at the deposit address
 * afterwards. `signing.ts` names that as rule 3: it is not a reconciliation break, it is swept by
 * the ordinary native path when it is worth a fee or left as dust when it is not. Under-funding, by
 * contrast, is a signed transaction that runs out of gas — the fee is burnt and the tokens do not
 * move — so the asymmetry is deliberate.
 */
export const TOKEN_TRANSFER_GAS = 100_000n

/**
 * `transfer(address,uint256)`, `balanceOf(address)` — the first four bytes of each keccak-256 hash.
 *
 * Written as literals and CHECKED against a keccak of the signature in the tests, exactly as
 * custody writes its own copy of the transfer selector: the constant a reader can see is the
 * constant that is broadcast, and a typo fails a test rather than silently calling a different
 * function. Custody holds the mirror of the first one (`ERC20_TRANSFER_SELECTOR`) and compares it
 * against the calldata built here, so a divergence between the two is a `shape_refused` rather than
 * a wrong transfer — but the test is what makes it a build failure instead.
 *
 * There is no `transferFrom` here and there must never be, for custody's reason: it moves somebody
 * ELSE's balance, which is not a sweep of this address at all.
 */
const ERC20_TRANSFER_SELECTOR = 'a9059cbb'
const ERC20_BALANCE_OF_SELECTOR = '70a08231'

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
const EVM_SHAPE = /^0x[0-9a-fA-F]{40}$/
const HEX_QUANTITY = /^0x[0-9a-fA-F]+$/

/* ------------------------------------------------------------------ addresses */

/**
 * EIP-55 checksum encoding.
 *
 * The hex digits of the lower-cased address are upper-cased where the corresponding nibble of
 * `keccak256(lowercase address without 0x)` is 8 or above. That is the entire specification, and it
 * is the only typo protection a 20-byte EVM address has.
 */
export function toChecksumAddress(address: string): string {
  const lower = address.toLowerCase().replace(/^0x/, '')
  const hash = Buffer.from(keccak256(Buffer.from(lower, 'ascii'))).toString('hex')
  let out = '0x'
  for (let i = 0; i < lower.length; i++) {
    const character = lower[i]!
    // Digits have no case, so only letters are touched.
    out += Number.parseInt(hash[i]!, 16) >= 8 ? character.toUpperCase() : character
  }
  return out
}

/**
 * Validate and produce the display form, or throw.
 *
 * A mixed-case address is CLAIMING a checksum and is held to it. An all-lowercase or all-uppercase
 * address is not claiming one and is accepted — refusing it would reject the form every block
 * explorer's copy button used to produce and the form the indexer stores.
 */
export function canonicaliseEvm(raw: string): string {
  const trimmed = raw.trim()
  if (!EVM_SHAPE.test(trimmed)) {
    throw new AddressError('address must be 0x followed by 40 hex characters')
  }
  const lower = trimmed.toLowerCase()
  const isAllOneCase = trimmed === lower || trimmed === `0x${trimmed.slice(2).toUpperCase()}`
  if (!isAllOneCase && toChecksumAddress(lower) !== trimmed) {
    throw new AddressError('address fails its EIP-55 checksum; check for a mistyped character')
  }
  return toChecksumAddress(lower)
}

/* ------------------------------------------------------------------ quantities */

/** Hex quantity → BigInt, refusing anything that is not one rather than reading it as zero. */
export function quantity(value: unknown, what: string): bigint {
  if (typeof value !== 'string' || !HEX_QUANTITY.test(value)) {
    throw new Error(`${what}: expected a hex quantity, got ${JSON.stringify(value)}`)
  }
  return BigInt(value)
}

/**
 * The gas price one payment will bid, in wei per gas.
 *
 * Read from the node (`eth_gasPrice`) rather than configured, which is the one improvement the
 * Hearth rebuild hands this service for free: the old chain published no fee anywhere, so a
 * constant mirrored in forge-pay's environment mispriced every payment the day Hearth's own moved.
 *
 * Doubled, because the price is locked when the user submits and the transaction is signed and sent
 * minutes later. A transaction that underbids its own chain does not fail — it sits in a mempool
 * being neither paid nor refunded until an operator looks at it, which is the worst of the three
 * available outcomes.
 *
 * The CEILING IS CHECKED BEFORE THE DOUBLING, deliberately. Checking after would make every payment
 * fail as soon as the real price passed half the ceiling, so the bound would bite at a number
 * nobody configured.
 */
export function gasPriceBid(quoted: bigint, bounds: FeeBounds, chain: ChainId): bigint {
  const base = quoted > bounds.minGasPriceWei ? quoted : bounds.minGasPriceWei
  if (base > bounds.maxGasPriceWei) {
    throw new FeeOutOfBandError(chain, 'above', base * TRANSFER_GAS, bounds.maxGasPriceWei * TRANSFER_GAS)
  }
  const bid = base * 2n
  return bid > bounds.maxGasPriceWei ? bounds.maxGasPriceWei : bid
}

/**
 * Recover the gas price a locked fee encodes, refusing a fee this service will not build for.
 *
 * The fee is `gasPrice × TRANSFER_GAS` and nothing in this file may divide it by anything else. An
 * indivisible fee means the row was not written by a compatible quoter, which is a corruption and
 * not something to round away — rounding it would sign a transaction that does not match the row it
 * came from, and the row is what the user agreed to.
 *
 * Exported and pure, because "an out-of-band fee is refused" is a property that must be assertable
 * without a node.
 */
export function gasPriceForLockedFee(
  fee: bigint,
  bounds: FeeBounds,
  chain: ChainId,
  /**
   * The gas limit the fee was quoted at. `TRANSFER_GAS` for a native movement and
   * `TOKEN_TRANSFER_GAS` for an ERC-20 one.
   *
   * **A PARAMETER RATHER THAN A CONSTANT, AND DEFAULTED TO THE NATIVE ONE.** A token sweep's fee
   * divided by 21,000 recovers a gas price nearly five times the real one, which sails past
   * `maxGasPriceWei` and refuses the row as out of band — a permanent refusal of a perfectly good
   * sweep, with a message pointing at the wrong number. The default keeps every existing native
   * call site reading as it did, so the only rows that take the new divisor are the ones whose
   * purpose demanded it.
   */
  gas: bigint = TRANSFER_GAS,
): bigint {
  // The ABSOLUTE ceiling first, before the divisibility. Ordering matters only for which sentence
  // an operator reads, and this is the more useful one: a fee ten times the ceiling is a repricing
  // or a corrupt row, and telling them it "is not a whole gas price" sends them looking at the
  // wrong digit.
  if (fee > bounds.maxFeeWei) throw new FeeOutOfBandError(chain, 'above', fee, bounds.maxFeeWei)
  if (fee <= 0n) throw new FeeOutOfBandError(chain, 'below', fee, gas * bounds.minGasPriceWei)
  if (fee % gas !== 0n) {
    throw new FeeOutOfBandError(chain, 'below', fee, gas * bounds.minGasPriceWei)
  }
  const gasPrice = fee / gas
  if (gasPrice < bounds.minGasPriceWei) {
    throw new FeeOutOfBandError(chain, 'below', fee, bounds.minGasPriceWei * gas)
  }
  if (gasPrice > bounds.maxGasPriceWei) {
    throw new FeeOutOfBandError(chain, 'above', fee, bounds.maxGasPriceWei * gas)
  }
  return gasPrice
}

/* ------------------------------------------------------------------ ERC-20 calldata */

/**
 * One 32-byte ABI word, as 64 lower-case hex characters and no `0x`.
 *
 * Refuses a value that does not fit rather than truncating it. A silently-truncated uint256 is a
 * transfer of the wrong amount, signed, and nothing downstream would notice — the calldata would be
 * well-formed, custody would accept it (its own decode checks the shape, not the arithmetic), and
 * the chain would move whatever the low 32 bytes happened to say.
 */
function abiWord(value: bigint): string {
  if (value < 0n || value >= 1n << 256n) {
    throw new Error(`${value} does not fit in a uint256 ABI word`)
  }
  return value.toString(16).padStart(64, '0')
}

/**
 * `transfer(recipient, amount)` calldata — exactly 68 bytes, built to what custody will accept.
 *
 * **CONSTRUCTED TO THE BYTE, BECAUSE THE THING THAT VALIDATES IT DECODES BY HAND.** Custody's
 * `assertTokenSweep` does not use an ABI decoder, deliberately: "a decoder's job is to be permissive
 * about encodings that mean the same thing; this function's job is the opposite". It requires the
 * recipient word's twelve-byte left pad to be all zero, the total length to be exactly 68 bytes with
 * nothing appended, and the amount to be positive. So this builder produces that and only that, and
 * an `AbiCoder` is not used here either — an encoder that one day emits an equivalent-but-different
 * encoding would produce calldata custody refuses AFTER the row is committed and the chain's single
 * outbound slot is claimed.
 *
 * The recipient is lower-cased into the word. Custody compares the decoded recipient against the
 * pin lower-cased — the opposite of `assertSweep`'s character-for-character `to` comparison, and
 * right for the opposite reason: an ABI word has no casing at all, so insisting on a spelling would
 * refuse correct calldata for a cosmetic reason.
 */
export function erc20TransferCalldata(recipient: string, amount: bigint): string {
  const address = canonicaliseEvm(recipient).toLowerCase().slice(2)
  if (amount <= 0n) {
    // Custody refuses this outright ("a signature is permanent and a zero-amount transfer is not a
    // sweep of anything"). Refusing here makes it a classified build failure rather than a 403.
    throw new Error('an ERC-20 transfer of a non-positive amount is not a sweep of anything')
  }
  return `0x${ERC20_TRANSFER_SELECTOR}${address.padStart(64, '0')}${abiWord(amount)}`
}

/** `balanceOf(owner)` calldata. A read, and the only other function this service ever encodes. */
export function erc20BalanceOfCalldata(owner: string): string {
  const address = canonicaliseEvm(owner).toLowerCase().slice(2)
  return `0x${ERC20_BALANCE_OF_SELECTOR}${address.padStart(64, '0')}`
}

/**
 * A `uint256` returned by `eth_call`, refusing anything that is not one.
 *
 * An empty `0x` is what a node returns for a call to an address with NO CODE, which is exactly what
 * a mistyped or wrong-network contract address looks like. Reading it as zero would make every such
 * misconfiguration indistinguishable from "this address holds no tokens" — silent, permanent, and
 * discovered only when somebody asks why a registered token has never been swept. So it throws.
 */
export function decodeUint256(result: unknown, what: string): bigint {
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(result)) {
    throw new Error(
      `${what}: expected a 32-byte uint256, got ${JSON.stringify(result)} — an empty result means ` +
        'the address holds no contract code, which is a wrong contract address rather than a zero balance',
    )
  }
  return BigInt(result)
}

/* ------------------------------------------------------------------ the transaction id */

/** Raw bytes of a `0x`-prefixed or bare hex string, or null if it is not one. */
export function hexBytes(rawTx: string): Buffer | null {
  const body = rawTx.startsWith('0x') || rawTx.startsWith('0X') ? rawTx.slice(2) : rawTx
  if (body.length === 0 || body.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(body)) return null
  return Buffer.from(body, 'hex')
}

/**
 * The id a signed EVM transaction will be known by: keccak256 of exactly its bytes.
 *
 * **Derived rather than remembered**, which is what makes it available on the recovery path as well
 * as the happy one. A node answers a re-broadcast of a transaction it already holds with an ERROR,
 * not with the hash — so a crash between broadcasting and recording the hash would otherwise leave
 * a payment that landed on chain with no id to poll, re-sending for ever and going `stuck` an hour
 * later while the money was long since delivered.
 */
export function evmTxHash(rawTx: string): string | null {
  const bytes = hexBytes(rawTx)
  if (!bytes) return null
  return `0x${Buffer.from(keccak256(bytes)).toString('hex')}`
}

/* ------------------------------------------------------------------ the RLP nonce */

interface RlpHeader {
  readonly payloadAt: number
  readonly payloadLength: number
  readonly next: number
  readonly list: boolean
  /** A byte in 0x00–0x7f, which encodes itself: the payload IS the tag. */
  readonly single: boolean
}

/** A big-endian RLP length prefix, refusing a non-canonical one rather than reading it. */
function rlpLength(buf: Buffer, at: number, bytes: number): number | null {
  if (bytes < 1 || bytes > 4 || at + bytes > buf.length || buf[at] === 0) return null
  let value = 0
  for (let i = 0; i < bytes; i += 1) value = value * 256 + buf[at + i]!
  return value
}

function rlpHeader(buf: Buffer, at: number): RlpHeader | null {
  if (at >= buf.length) return null
  const tag = buf[at]!
  const make = (payloadAt: number, payloadLength: number, list: boolean): RlpHeader | null =>
    payloadAt + payloadLength <= buf.length
      ? { payloadAt, payloadLength, next: payloadAt + payloadLength, list, single: false }
      : null
  if (tag <= 0x7f) return { payloadAt: at, payloadLength: 1, next: at + 1, list: false, single: true }
  if (tag <= 0xb7) return make(at + 1, tag - 0x80, false)
  if (tag <= 0xbf) {
    const size = tag - 0xb7
    const length = rlpLength(buf, at + 1, size)
    return length === null ? null : make(at + 1 + size, length, false)
  }
  if (tag <= 0xf7) return make(at + 1, tag - 0xc0, true)
  const size = tag - 0xf7
  const length = rlpLength(buf, at + 1, size)
  return length === null ? null : make(at + 1 + size, length, true)
}

/**
 * The nonce inside a signed legacy EVM transaction, read out of the bytes themselves.
 *
 * DERIVED, NOT REMEMBERED, for the same reason `evmTxHash` is: the value has to describe the bytes
 * that are actually in the row, and a column written beside them can drift from them in a way
 * nothing would ever notice. `outbound_transactions.signed_nonce` exists for an operator to read
 * and for XRP, which has no derivation; the adjudication path prefers this.
 *
 * A legacy transaction is `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`, so this
 * reads two RLP headers and stops. EVERYTHING ELSE IS NULL, and null is a REFUSAL TO ADJUDICATE
 * rather than a nonce of zero: an EIP-2718 typed envelope (whose first byte is the type and never a
 * list tag), an outer list that does not span exactly these bytes, a nonce longer than eight bytes,
 * or any non-canonical integer encoding. This service builds legacy only and custody refuses to
 * sign anything else for Ember, so the null branches are guards and not a fallback.
 */
export function legacyNonce(rawTx: string): bigint | null {
  const bytes = hexBytes(rawTx)
  if (!bytes) return null
  const outer = rlpHeader(bytes, 0)
  if (!outer || !outer.list || outer.next !== bytes.length) return null
  const first = rlpHeader(bytes, outer.payloadAt)
  if (!first || first.list || first.next > outer.next) return null
  const payload = bytes.subarray(first.payloadAt, first.payloadAt + first.payloadLength)
  // 0x00–0x7f encodes itself, except zero: canonical RLP writes zero as the empty string 0x80.
  if (first.single) return payload[0]! === 0 ? null : BigInt(payload[0]!)
  if (payload.length === 0) return 0n
  if (payload.length > 8 || payload[0] === 0) return null
  return BigInt(`0x${payload.toString('hex')}`)
}

/* ------------------------------------------------------------------ node answers */

export interface EvmReceipt {
  readonly blockNumber?: unknown
  readonly status?: unknown
}

/**
 * Errors a node returns for a transaction it has ALREADY accepted or already mined.
 *
 * Both are the SUCCESSFUL outcome of a re-broadcast, which the recovery path does by design: the
 * bytes are committed before they are sent, and anything that dies in between re-sends them. geth's
 * strings are matched because every EVM client copies them verbatim and Hearth's own RPC passes the
 * chain's words through untouched.
 *
 * `nonce too low` is included deliberately and is the subtle one: it is what a node says once our
 * transaction has been MINED, which is the same recovery path arriving slightly later. Treating it
 * as a success lets `status` settle the row from the chain, which is the only thing that can tell
 * "mined" from "replaced".
 */
const ALREADY_SENT = ['already known', 'known transaction', 'nonce too low', 'already imported']

/* ------------------------------------------------------------------ the adapter */

export function evmChain(chain: ChainId): OutboundChain {
  const asset = assetOf(chain)
  const spec = chainSpec(asset)
  const family: ChainFamily = spec.family

  const balanceAt = async (call: ChainCall, address: string): Promise<bigint> =>
    // Always 'latest', deliberately: this answers "will the node accept a transaction I build
    // now?", and a node validates against its own head. Confirmation depth is the indexer's
    // question about incoming money and it has its own reader, so neither can be called for the
    // other's purpose by accident.
    quantity(await call.rpc('eth_getBalance', [address, 'latest']), 'eth_getBalance')

  /**
   * The node's chain id, checked against the one `contracts-chain` publishes.
   *
   * ONE IMPLEMENTATION SHARED BY BOTH BUILD BRANCHES, deliberately. Custody binds the chain id
   * independently from the address's own row and refuses a disagreement with a 403, so this is not
   * redundancy — it turns "custody refused for a reason you cannot see" into "this node is not the
   * chain you configured", which is a different fix. A token sweep that skipped it would be the one
   * transaction shape in this service whose signature could be made against the wrong network with
   * only custody standing behind it.
   */
  const assertChainId = (raw: unknown, network: Network): number => {
    const chainId = Number(quantity(raw, 'eth_chainId'))
    if (!Number.isSafeInteger(chainId) || chainId <= 0) {
      throw new Error('the node reported an unusable chain id')
    }
    const expected = spec.chainId?.[network]
    if (expected !== undefined && expected !== chainId) {
      throw new Error(
        `the ${chain} ${network} node reports chain id ${chainId}, not the ${expected} ` +
          'this build is pinned to — a signature made against it would be valid on the wrong network',
      )
    }
    return chainId
  }

  const assertNonce = (raw: unknown): number => {
    const nonce = Number(quantity(raw, 'eth_getTransactionCount'))
    if (!Number.isSafeInteger(nonce) || nonce < 0) {
      throw new Error('the node reported an unusable nonce')
    }
    return nonce
  }

  const statusOf = async (call: ChainCall, txHash: string): Promise<OutboundStatus> => {
    const receipt = (await call.rpc('eth_getTransactionReceipt', [txHash])) as EvmReceipt | null
    // A receipt is the whole answer: absent means not mined — mempool, dropped, or never accepted,
    // indistinguishable from outside, and all three mean "re-send the same bytes".
    if (!receipt || typeof receipt.blockNumber !== 'string') return { kind: 'unknown' }
    if (receipt.status === '0x0') {
      // Mined and REVERTED. The chain itself saying the value did not move, which is the one proof
      // that makes refunding a SIGNED transaction safe. A plain transfer to an account with no code
      // cannot revert, so in practice this fires only if the destination gained code between the
      // build and the broadcast — but it is the branch that must not be missing, because the
      // alternative to detecting it is a user's money sitting in `stuck` for ever.
      return { kind: 'rejected', reason: 'the transaction was mined but reverted, so nothing was transferred' }
    }
    const head = quantity(await call.rpc('eth_blockNumber', []), 'eth_blockNumber')
    const mined = quantity(receipt.blockNumber, 'receipt.blockNumber')
    // The block containing it is its own first confirmation, the same convention the deposit side
    // counts by — and the depth is the same declared depth, so an outbound payment is only final
    // once it is as deep as an incoming deposit has to be to be credited.
    //
    // `spec.confirmations`, never a constant here, and Ethereum Classic is the chain that makes the
    // rule expensive to break. Its declared depth is very deep on purpose: ETC has been 51%-attacked
    // and had blocks reorganised in the thousands, so finality there is bought with blocks and
    // nothing else. Read as a number in this file it would look like a typo, and the edit that
    // "fixed" it would be a settlement marked final above a reorg that had not finished. The depth
    // belongs to the exact-pinned contract, which is also what the deposit side reads.
    const confirmations = head >= mined ? Number(head - mined) + 1 : 0
    return confirmations >= spec.confirmations
      ? { kind: 'confirmed', confirmations, minedHeight: mined }
      : { kind: 'pending', confirmations, minedHeight: mined }
  }

  return {
    chain,
    family,
    unimplementedPhase: null,

    /**
     * The ERC-20 reads. Two `eth_call`s and nothing else — no state is touched and no key is used.
     *
     * `balanceOf` is asked at **latest**, matching `balanceAt` and for the same reason: it answers
     * "is there something here worth two transactions right now", and a node answers from its own
     * head. The confirmation depth that makes an incoming token deposit real is the indexer's
     * question, asked on the credit path, and the two must not be confused — which is why they are
     * different methods with different block tags rather than one shared read.
     */
    tokens: {
      async balanceOf(call, address, contract) {
        const result = await call.rpc('eth_call', [
          { to: canonicaliseEvm(contract), data: erc20BalanceOfCalldata(address) },
          'latest',
        ])
        return decodeUint256(result, `balanceOf(${address})`)
      },
      async transferFee(call, bounds) {
        const quoted = quantity(await call.rpc('eth_gasPrice', []), 'eth_gasPrice')
        return gasPriceBid(quoted, bounds, chain) * TOKEN_TRANSFER_GAS
      },
    },

    canonicalise: canonicaliseEvm,
    addressKey: (address) => canonicaliseEvm(address).toLowerCase(),
    isValidDestination(address) {
      try {
        // The zero address is well-formed and is where value goes to die. Custody refuses it too
        // (`assertTransfer`), but refusing it here means the withdrawal never gets built rather
        // than being refused at the moment of signing.
        return canonicaliseEvm(address).toLowerCase() !== ZERO_ADDRESS
      } catch {
        return false
      }
    },

    async estimateFee(call, bounds) {
      const quoted = quantity(await call.rpc('eth_gasPrice', []), 'eth_gasPrice')
      return gasPriceBid(quoted, bounds, chain) * TRANSFER_GAS
    },

    spendableBalance(call, address) {
      return balanceAt(call, address)
    },

    /**
     * An EVM sweep moves the whole balance less the one fee it costs to move it.
     *
     * There is no per-address component to an EVM fee — a value transfer is 21,000 gas whatever the
     * account holds — so this is `estimateFee` and `spendableBalance` put together, and it exists
     * here only because Bitcoin's cannot be. Null below the fee, because a sweep that costs more
     * than it moves destroys value.
     */
    async sweepQuote(call, address, bounds) {
      const fee = gasPriceBid(quantity(await call.rpc('eth_gasPrice', []), 'eth_gasPrice'), bounds, chain) * TRANSFER_GAS
      const balance = await balanceAt(call, address)
      const value = balance - fee
      return value > 0n ? { value, fee } : null
    },

    async build(call, input): Promise<UnsignedOutbound> {
      const isToken = input.shape === 'token_sweep'
      const gas = isToken ? TOKEN_TRANSFER_GAS : TRANSFER_GAS
      // Refused BEFORE the node is asked anything: a fee this service will not build for is a
      // permanent property of the row, and finding that out after four round trips is four round
      // trips spent on a refusal. The DIVISOR is the row's own gas limit — see `TOKEN_TRANSFER_GAS`.
      const gasPrice = gasPriceForLockedFee(input.fee, input.bounds, chain, gas)
      const to = canonicaliseEvm(input.to)
      const from = canonicaliseEvm(input.from)
      if (to.toLowerCase() === ZERO_ADDRESS) throw new UnsupportedDestinationError(chain, to)

      if (isToken) {
        // ──────────────────────────────────────────────────────────────────────────────────────
        // THE TOKEN SWEEP. `to` is the treasury pin and it goes INSIDE the calldata; the
        // transaction's own `to` is the contract. `value` is zero, which custody requires.
        //
        // The three checks the native branch makes below are each replaced rather than skipped:
        //
        //   * `eth_getCode` on the destination is INVERTED. A native transfer refuses a
        //     destination that runs code; a token sweep requires one, because a `transfer` call to
        //     an address with no code succeeds silently on chain — it is a plain value transfer of
        //     zero — and would burn the gas the top-up just paid for while moving nothing and
        //     reporting success. A registered contract that has no code is a wrong address or a
        //     wrong network, and both are permanent.
        //   * the balance check is against the FEE ALONE, because the amount is denominated in the
        //     token and the native balance has nothing to do with it. This is the check that fails
        //     when the gas top-up has not landed, and it is why it must be an
        //     `InsufficientTreasuryError` — that classification releases the row back to `planned`
        //     rather than refunding it, so the sweep waits for its gas instead of being abandoned.
        //   * `value > 0` is replaced by the calldata's own positive-amount rule, which
        //     `erc20TransferCalldata` enforces.
        // ──────────────────────────────────────────────────────────────────────────────────────
        const contract = canonicaliseEvm(input.token.contract)
        const data = erc20TransferCalldata(to, input.value)
        const [chainIdHex, nonceHex, balance, contractCode] = await Promise.all([
          call.rpc('eth_chainId', []),
          call.rpc('eth_getTransactionCount', [from, 'pending']),
          balanceAt(call, from),
          call.rpc('eth_getCode', [contract, 'latest']),
        ])
        if (typeof contractCode !== 'string' || contractCode === '0x' || contractCode === '') {
          throw new UnsupportedDestinationError(chain, contract)
        }
        if (balance < input.fee) throw new InsufficientTreasuryError(chain, balance, input.fee)

        const chainId = assertChainId(chainIdHex, call.network)
        const nonce = assertNonce(nonceHex)
        return {
          payload: {
            type: 0,
            chainId,
            nonce,
            to: contract,
            // Zero as a DECIMAL STRING, not the number 0 and not omitted. Custody's `quantity`
            // takes either, but the whole payload is decimal strings for amounts and consistency
            // here is what keeps a reader from wondering whether the omission means something.
            value: '0',
            data,
            gasLimit: TOKEN_TRANSFER_GAS.toString(),
            gasPrice: gasPrice.toString(),
          },
          // The TOKEN amount, unchanged, in the token's own smallest units. Nothing in this service
          // converts it, and nothing should: the decimals live on the registry row.
          value: input.value,
          fee: input.fee,
          nonce: String(nonce),
          expiry: null,
        }
      }

      if (input.value <= 0n) {
        // Custody refuses a non-positive `value` on a transfer, so this would be a 403. Refusing
        // here makes it a classified build failure with a refund instead.
        throw new FeeOutOfBandError(chain, 'above', input.fee, input.fee)
      }

      const [chainIdHex, nonceHex, balance, code] = await Promise.all([
        call.rpc('eth_chainId', []),
        call.rpc('eth_getTransactionCount', [from, 'pending']),
        balanceAt(call, from),
        call.rpc('eth_getCode', [to, 'latest']),
      ])

      if (typeof code === 'string' && code !== '0x' && code !== '') {
        throw new UnsupportedDestinationError(chain, to)
      }

      const needed = input.value + input.fee
      if (balance < needed) throw new InsufficientTreasuryError(chain, balance, needed)

      const chainId = assertChainId(chainIdHex, call.network)
      const nonce = assertNonce(nonceHex)

      return {
        // Exactly custody's `EVM_FIELDS` allowlist and no more. `signEvm` refuses "a field this
        // service does not sign", so an extra key here is a 403 rather than a wider signature.
        //
        // Legacy (type 0), for all three chains and for a different reason on each. Ember v1 has no
        // EIP-1559 and its node has no type-2 decoder; Ethereum Classic never adopted it, so a
        // type-2 envelope is undecodable there too and custody's `LEGACY_GAS_ONLY_CHAINS` names
        // `ethereum-classic` alongside `ember` so it can never be signed; Ethereum has 1559 and
        // still accepts legacy. One shape serves all three, and the two chains that would refuse
        // anything else are the reason it must stay one shape rather than become a choice.
        // Amounts are DECIMAL STRINGS: custody's `quantity` refuses a non-safe-integer
        // number rather than rounding it, which is the fail-closed half of an 18-decimal amount.
        payload: {
          type: 0,
          chainId,
          nonce,
          to,
          value: input.value.toString(),
          gasLimit: TRANSFER_GAS.toString(),
          gasPrice: gasPrice.toString(),
        },
        value: input.value,
        fee: input.fee,
        nonce: String(nonce),
        expiry: null,
      }
    },

    txIdOf: evmTxHash,

    async broadcast(call, rawTx) {
      const derived = evmTxHash(rawTx)
      if (!derived) throw new Error('the committed bytes are not a hex transaction')
      try {
        const hash = await call.rpc('eth_sendRawTransaction', [rawTx])
        return typeof hash === 'string' && hash.length > 2 ? hash : derived
      } catch (err) {
        const message = (err instanceof Error ? err.message : String(err)).toLowerCase()
        if (ALREADY_SENT.some((m) => message.includes(m))) return derived
        throw err
      }
    },

    status: statusOf,

    /**
     * The EVM death proof.
     *
     * Three facts together, and the frozen `judgeAbandon` is where each of them was learned:
     *
     *   1. **No node has a receipt for any id these bytes could be known by.** The DERIVED id is
     *      asked about first, because it is the one that exists when the row's does not.
     *   2. **The sending account's nonce has moved past the nonce in the bytes.** `NO RECEIPT IS
     *      NOT NO TRANSACTION`: on an EVM chain "unknown" means only "this node has no receipt for
     *      that hash", and the bytes are untouched by it — the nonce is unconsumed, a legacy
     *      transaction has no expiry, and any node still holding them can mine them months later.
     *      The nonce having moved is the only fact that says the slot was taken by something else.
     *   3. At `latest` and **never** at `pending`. A pending count includes transactions in this
     *      node's own mempool, and "a node is holding something at that nonce" is the opposite of
     *      proof that the slot has been taken permanently.
     */
    async proveDead(call, input: DeathInput): Promise<DeathVerdict> {
      const ids: string[] = []
      for (const id of [evmTxHash(input.rawTx), input.txHash]) {
        if (id && !ids.includes(id)) ids.push(id)
      }
      for (const id of ids) {
        const status = await statusOf(call, id)
        if (status.kind === 'pending' || status.kind === 'confirmed') {
          return {
            ok: false,
            code: 'on_chain',
            error:
              `the network still has this payment — ${id} is ${status.kind} at ` +
              `${status.confirmations} confirmations. Refunding it now would credit the user money ` +
              'that has already left the treasury. Wait for it to confirm; it settles itself.',
          }
        }
        if (status.kind === 'rejected') {
          return { ok: true, proof: `the chain applied ${id} and it did not deliver: ${status.reason}` }
        }
      }

      const nonce = legacyNonce(input.rawTx)
      if (nonce === null) {
        return {
          ok: false,
          code: 'unprovable',
          error:
            'the signed bytes on this transaction are not a legacy transaction this service can ' +
            'read a nonce out of, so there is no way to show they can never be mined. Nothing is ' +
            'refunded on an unread signature — an engineer has to look at the row.',
        }
      }
      const used = quantity(
        await call.rpc('eth_getTransactionCount', [canonicaliseEvm(input.from), 'latest']),
        'eth_getTransactionCount',
      )
      if (used > nonce) {
        return {
          ok: true,
          proof:
            `no node has a receipt for these bytes and the source has used ${used} nonces, past the ` +
            `${nonce} these bytes carry — the slot was taken by another transaction, so they can ` +
            'never be mined',
        }
      }
      return {
        ok: false,
        code: 'still_applicable',
        error:
          `these signed bytes carry nonce ${nonce} and the source has used only ${used}, so any node ` +
          'still holding them can mine them at any time — a refund now can be followed by the ' +
          'payment landing. Retire the nonce first: send a 0-value transaction from the source to ' +
          `itself at nonce ${nonce} with a higher gas price, and adjudicate this once it is mined.`,
      }
    },
  }
}

/** The network a call is for, restated as a type guard so a caller cannot pass a slug by mistake. */
export type EvmNetwork = Network
