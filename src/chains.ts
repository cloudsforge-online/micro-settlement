/**
 * The outbound chain interface, and the five objects that implement it.
 *
 * **Nothing in `@cloudsforge/contracts-chain` is redefined here.** Decimals, confirmation depths
 * and chain ids are read from that package and never restated, because the whole reason it is
 * exact-pinned is that `settlement` and `custody` disagreeing about a chain id is not a 500 — it is
 * a signature bound to the wrong network, and those bytes are broadcastable on the chain they were
 * not meant for. Custody resolves the chain id independently from the address's own row
 * (`gates.resolveChainId`) and refuses a disagreement, which is the second half of the same rule.
 *
 * ## Four implemented, one real and unimplemented
 *
 * `eth` and `ember` are one implementation — see `evm.ts`. An EMBER payment is a legacy (type 0)
 * EVM transaction against a standard `eth_*` endpoint, so the two differ only in which node answers
 * and which chain id the signature commits to. `btc` is `bitcoin.ts`; `sol` is `solana.ts`.
 *
 * `xrp` is **a real object on this interface that throws `NotImplementedError` naming the phase
 * that brings it**. It is not a stub that returns zero, it is not absent from the registry, and
 * `chainFor('xrp')` does not throw: a caller gets an object it can ask `unimplementedPhase` of,
 * which is what lets the withdrawal path classify the refusal as permanent and refund from
 * `pending` rather than retrying a chain that will never answer. A missing entry would instead be a
 * `TypeError` somewhere in the job handler.
 *
 * custody signs XRP today (`signXrp`, with both a `payment` and a pinned `sweep` shape), so the gap
 * is entirely on this side — this service does not yet speak XRPL. It is unimplemented rather than
 * half-built because an XRP blob carries a `Sequence` and a `LastLedgerSequence` that must be
 * COMMITTED beside the bytes to be abandonable at all, and a half-implementation that signs without
 * recording them produces withdrawals that can never be adjudicated. `outbound_transactions`
 * already has the columns; the adapter is what is missing.
 *
 * ## What this header used to say about BTC and SOL, and how each sentence was wrong
 *
 * A section titled "Why BTC and SOL cannot be withdrawn OR swept, stated once" sat here. **Every
 * claim in it is now false and two of them were false the day they were written.** It is summarised
 * rather than deleted, because the way a claim about another repository goes stale is the part
 * worth keeping — this estate has now found the same failure four times.
 *
 *   * It said `signBitcoin`'s output policy was "specified, not built", so `SWEEPABLE_FAMILIES`
 *     refused a bitcoin `deposit` address and therefore "neither a withdrawal nor a sweep is
 *     possible". **The withdrawal half was never true.** The gate it named is conditioned on
 *     `purpose === 'deposit'` (custody/src/gates.ts), so it never touched a `treasury`-purpose
 *     withdrawal at all. `bitcoin.ts` corrected that half. The sweep half was true and is not any
 *     more: `BitcoinPolicy` (custody/src/signing.ts) is built, and `SWEEPABLE_FAMILIES`
 *     (custody/src/gates.ts) now names `bitcoin` and `solana`.
 *   * It said `signSolana` "allows only the SPL mint-creation instruction set and explicitly
 *     refuses `SystemProgram::Transfer`". That WAS true and is now false: `SolanaPolicy`
 *     (custody/src/signing.ts) has three disjoint shapes, and `transfer` and `sweep` each admit
 *     exactly one System Transfer of native lamports.
 *   * It said admitting SOL would "hand a signing credential `createAccount` over every customer's
 *     SOL deposit key". False in the opposite direction now: `createAccount` is reachable only
 *     under the `mint` shape, which `solanaShapeForPurpose` gives to `deployer` alone — a
 *     `treasury` address LOST it in the same change that gave it a transfer.
 *
 * SPL Transfer is still refused under all three Solana shapes, and this service asks for nothing
 * that needs it: a SOL withdrawal and a SOL sweep are both one System Transfer of native lamports.
 */

import {
  chainSpec,
  type AssetCode,
  type ChainFamily,
  type Network,
} from '@cloudsforge/contracts-chain'

/**
 * The URL-safe slug for a chain: the asset code lowercased, which is also the indexer's `ChainId`
 * and what `txUrn` uses, so a path segment and a cross-service URN cannot drift.
 *
 * `shard` is deliberately absent. SHARD is in `CHAINS` only so that record is total; it never
 * exists on a chain and an outbound transaction for it could only ever be a lie.
 */
export type ChainId = 'ember' | 'eth' | 'btc' | 'sol' | 'xrp' | 'ltc' | 'etc' | 'doge'

export const CHAIN_IDS: readonly ChainId[] = Object.freeze([
  'ember',
  'eth',
  'btc',
  'sol',
  'xrp',
  'ltc',
  'etc',
  'doge',
])

const ASSET_FOR_CHAIN: Readonly<Record<ChainId, AssetCode>> = Object.freeze({
  ember: 'EMBER',
  eth: 'ETH',
  btc: 'BTC',
  sol: 'SOL',
  xrp: 'XRP',
  ltc: 'LTC',
  etc: 'ETC',
  doge: 'DOGE',
})

const CHAIN_FOR_ASSET: Readonly<Partial<Record<AssetCode, ChainId>>> = Object.freeze({
  EMBER: 'ember',
  ETH: 'eth',
  BTC: 'btc',
  SOL: 'sol',
  XRP: 'xrp',
  LTC: 'ltc',
  ETC: 'etc',
  DOGE: 'doge',
})

export function isChainId(value: string): value is ChainId {
  return (CHAIN_IDS as readonly string[]).includes(value)
}

export function isNetwork(value: string): value is Network {
  return value === 'mainnet' || value === 'testnet'
}

export function assetOf(chain: ChainId): AssetCode {
  return ASSET_FOR_CHAIN[chain]
}

/** The chain an asset settles on, or null. Null for SHARD, which has no chain by design. */
export function chainForAsset(assetCode: string): ChainId | null {
  return CHAIN_FOR_ASSET[assetCode as AssetCode] ?? null
}

export function familyOf(chain: ChainId): ChainFamily {
  return chainSpec(assetOf(chain)).family
}

/**
 * The chain name custody stores against an address, which is NOT always this service's slug.
 *
 * Custody's `CHAIN_ASSET` is keyed by chain NAME — `ethereum`, `bitcoin`, `litecoin`, `solana`,
 * `xrp`, `ember` — because those are the values the rows it adopted from forge-keyvault already
 * carry. This service's slug is the asset code lowercased. The two agree on four of the eight
 * chains here and disagree on the other four, and each disagreement is a `binding_mismatch` at
 * signing time: custody compares the caller's restated `chain` against the stored row character for
 * character. So the translation is a table with a name rather than a `toLowerCase()` that happens
 * to work for half of it.
 *
 * **`ltc → 'litecoin'` IS THE SECOND ENTRY THAT EARNS THIS TABLE**, and it earns it twice over.
 * Getting it wrong is not a 500: custody resolves the signing parameters from the row's stored
 * chain name (`custody/src/chains.ts`, `bitcoinNetwork`), so `'ltc'` sent where `'litecoin'` is
 * expected is refused outright, and — worse — a name that resolved to `'bitcoin'` would sign a
 * Litecoin PSBT with a Bitcoin key. The value here is verified against
 * `custody/src/chains.ts:CHAIN_ASSET`, which spells it `litecoin`.
 *
 * ── THE LAST TWO ENTRIES ARE PROPOSALS, AND THIS PARAGRAPH IS WHY THAT IS SAFE ─────────────────
 *
 * **Custody names neither Ethereum Classic nor Dogecoin today.** Read on 2026-08-09: its
 * `CHAIN_ASSET` holds exactly `ethereum`, `bitcoin`, `litecoin`, `solana`, `xrp`, `ember` and the
 * generic `evm`, and `isKnownChain` is a `hasOwn` over that object — so `/v1/addresses` cannot mint
 * an ETC or DOGE key at all, and there is no stored row for either name to be compared against.
 * These two values are therefore what this service WOULD send, not something checked against a row
 * that exists, and they must be confirmed against custody on the day it grows an entry.
 *
 * A name custody does not know is refused, which is the failure this service can afford. The one
 * that must never be written here is `ethereum` for `etc`: an EVM address is the same 20 bytes on
 * both chains, so custody would return the Ethereum treasury's address for an ETC pin and the two
 * positions would be one row in this service's books. The signature itself would still be refused —
 * `expectedEvmChainId('ethereum')` is 1/11155111 against the 61/63 an ETC payload declares, and
 * SD-09 gate 3 compares them — but a treasury address is adopted long before anything is signed
 * with it, and adopting Ethereum's under Ethereum Classic's name is a bookkeeping fault no gate at
 * signing time can undo. `dogecoin` carries the same rule against `bitcoin`, and there the gate
 * does not exist: a UTXO signature is not bound to a chain id.
 *
 * `dogecoin` is the more likely of the two to be right — custody's own suite already spells it that
 * way where it asserts Dogecoin is refused — and it is also the one this service can never send,
 * because `doge` is an unimplemented chain in the registry.
 */
const CUSTODY_CHAIN: Readonly<Record<ChainId, string>> = Object.freeze({
  ember: 'ember',
  eth: 'ethereum',
  btc: 'bitcoin',
  sol: 'solana',
  xrp: 'xrp',
  ltc: 'litecoin',
  etc: 'ethereum-classic',
  doge: 'dogecoin',
})

export function custodyChainOf(chain: ChainId): string {
  return CUSTODY_CHAIN[chain]
}

/**
 * The custody key family for a chain.
 *
 * Read from `contracts-chain` rather than restated, and it is the same string custody's own
 * `familyForChain` derives from the same package — which is the point of the pin. `signForAddress`
 * compares this against the stored row.
 */
export function custodyFamilyOf(chain: ChainId): ChainFamily {
  return familyOf(chain)
}

/** The lease key. `chain:network`, and it is the single most important string in this service. */
export function chainKey(chain: ChainId, network: Network): string {
  return `${chain}:${network}`
}

/* ------------------------------------------------------------------ errors */

export class AddressError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AddressError'
  }
}

/**
 * A chain this service has not built yet, naming the phase that brings it.
 *
 * Thrown from every method of an unimplemented adapter rather than returned as a null, so a caller
 * that forgets to check `unimplementedPhase` fails loudly at the first call instead of quietly
 * treating "no fee" as "free".
 */
export class NotImplementedError extends Error {
  readonly chain: ChainId
  readonly phase: string
  readonly operation: string
  constructor(chain: ChainId, phase: string, operation: string, detail: string) {
    super(`${chain} ${operation} is not implemented (${phase}): ${detail}`)
    this.name = 'NotImplementedError'
    this.chain = chain
    this.phase = phase
    this.operation = operation
  }
}

/** The address this payment would come out of cannot cover it right now. Never a user error. */
export class InsufficientTreasuryError extends Error {
  readonly available: bigint
  readonly needed: bigint
  constructor(chain: ChainId, available: bigint, needed: bigint) {
    super(`the ${chain} source holds ${available} of the ${needed} smallest units this payment needs`)
    this.name = 'InsufficientTreasuryError'
    this.available = available
    this.needed = needed
  }
}

/**
 * The destination runs code, and this service only pays accounts that do not.
 *
 * Permanent, and the only refusal here whose cause is something the USER can act on — so the
 * message is theirs rather than the generic one. A contract destination would need more than the
 * intrinsic 21,000 gas the payment is priced and signed for, and the sender pays for a transaction
 * that runs out of gas. A larger gas limit is not the fix: a gas limit big enough for arbitrary
 * `receive()` code is a gas limit big enough to be worth griefing the treasury with, and the fee
 * has already been quoted to the user by the time we get here.
 */
export class UnsupportedDestinationError extends Error {
  readonly destination: string
  constructor(chain: ChainId, destination: string) {
    super(
      `${destination} is a contract, and ${chain} withdrawals are plain transfers priced at the ` +
        'intrinsic gas of a payment to a wallet. Withdraw to an address you hold the key to.',
    )
    this.name = 'UnsupportedDestinationError'
    this.destination = destination
  }
}

/**
 * The fee on the row is not one this service will build a transaction for.
 *
 * Both directions are refusals and both are permanent for this row, because the fee was LOCKED
 * when the user agreed to it and re-quoting here would sign a transaction that does not match the
 * row it was built from. Too low and the transaction underbids its own chain and sits in a mempool
 * being neither paid nor refunded; too high and a misbehaving node has spent a user's balance on
 * gas. See `env.maxFeeWei` for why the ceiling sits below custody's.
 */
export class FeeOutOfBandError extends Error {
  readonly quoted: bigint
  readonly bound: bigint
  readonly direction: 'below' | 'above'
  constructor(chain: ChainId, direction: 'below' | 'above', quoted: bigint, bound: bigint) {
    super(
      `the locked ${chain} fee of ${quoted} is ${direction} the bound of ${bound} this service ` +
        'will build a transaction for',
    )
    this.name = 'FeeOutOfBandError'
    this.quoted = quoted
    this.bound = bound
    this.direction = direction
  }
}

/* ------------------------------------------------------------------ the node port */

/**
 * The narrowest thing an adapter needs from a node: one JSON-RPC call.
 *
 * A port rather than a `fetch`, and that is what makes the test suite honest. **No test in this
 * repository broadcasts to a real network** — the local Hearth testnet on 127.0.0.1:8545 may be
 * read and is never sent to — and the way that is guaranteed is that every test supplies a fake
 * node here. Faking at this seam rather than at `OutboundChain` means the code under test is the
 * REAL adapter: its nonce handling, its fee bounds, its transaction-id derivation and its receipt
 * reading are all exercised, and only the wire is imaginary.
 */
export type JsonRpc = (method: string, params: readonly unknown[]) => Promise<unknown>

/** One chain call: which network, and the node that answers for it. */
export interface ChainCall {
  readonly network: Network
  readonly rpc: JsonRpc
}

/** The bounds a fee must sit inside. From `env`, passed rather than imported so it is testable. */
export interface FeeBounds {
  readonly minGasPriceWei: bigint
  readonly maxGasPriceWei: bigint
  readonly maxFeeWei: bigint
}

/* ------------------------------------------------------------------ the shapes */

/**
 * What a caller wants moved, before the chain has been asked anything.
 *
 * `value` is what the destination RECEIVES and `fee` is what the network burns on top of it, so
 * `value + fee` is what leaves `from`. The fee comes out of the user's amount rather than on top —
 * that is wallet's arithmetic, not this service's — so a user can always withdraw their whole
 * balance. forge-pay gets this right and the split preserves it.
 */
interface BuildInputBase {
  readonly from: string
  /**
   * **WHO IS PAID**, on every shape including the token one.
   *
   * For a `token_sweep` this is NOT the transaction's `to` — that is the contract, which travels in
   * `token.contract`. This is the address the calldata pays, which is the treasury pin. Keeping the
   * field's meaning constant across shapes is what stops `to_address` in the schema, the `to` on
   * `settlement.sweep.completed`, and the operator surface's "where did it go" column from each
   * meaning something different for one purpose.
   */
  readonly to: string
  readonly value: bigint
  readonly fee: bigint
  readonly bounds: FeeBounds
  /**
   * Which of custody's signing policies these bytes will be judged under.
   *
   * **Not a label, and not derivable from the addresses on the row.** custody picks the policy from
   * the PURPOSE of the address it is signing for, and the two policies want two DIFFERENT
   * transactions. On Bitcoin the difference is a whole output: `assertSweepOutputs`
   * (custody/src/signing.ts) refuses a PSBT any of whose outputs does not pay the pin, change
   * included — and a change output back to the deposit address is exactly what the withdrawal
   * builder produces. An adapter that could not tell the two apart would hand custody bytes it
   * refuses AFTER the row is committed and this chain's single outbound slot is claimed.
   *
   * The two names are custody's own: `BitcoinPolicy` is `payment | sweep`. Solana's `transfer` and
   * `sweep` differ only in whether the destination is checked against the pin, so `payment` maps
   * onto `transfer` there. `treasury_move` and `deploy` are `payment`: they spend the treasury and
   * name their own destination.
   */
  readonly shape: OutboundShape
}

/**
 * What a caller wants moved.
 *
 * **A UNION RATHER THAN A BASE WITH AN OPTIONAL `token`**, for the reason `EvmPolicy` is one in
 * custody: `shape: 'token_sweep'` with no contract must fail at BUILD time rather than fall
 * through to a runtime default. There is no contract this service could default to — the allowlist
 * custody checks against refuses by default and starts empty — so the only two things an optional
 * field could produce here are a crash and a guess, and a guess is a customer's deposit key calling
 * code nobody registered.
 */
export type BuildInput =
  | (BuildInputBase & { readonly shape: 'payment' | 'sweep' })
  | (BuildInputBase & { readonly shape: 'token_sweep'; readonly token: TokenRef })

/** @see BuildInput.shape */
export type OutboundShape = 'payment' | 'sweep' | 'token_sweep'

/**
 * The ERC-20 contract a token sweep calls.
 *
 * **THE CONTRACT AND NOTHING ELSE — no decimals and no symbol, deliberately.** Every amount in this
 * service is already in smallest units and nothing here ever divides one, so a decimals value
 * passed to a builder would be a field that is carried, never read, and therefore free to be wrong.
 * The identity of the token travels on the row as its ledger asset code —
 * `TOKEN:<chain>:<network>:<contract>`, which names the deployment uniquely — and the decimals live
 * on custody's registry row, which is the operator-maintained authority that the wrong value would
 * have to be corrected in anyway. One place holds it; nothing copies it.
 */
export interface TokenRef {
  /** Lower-cased, and both this schema and custody's allowlist enforce that. The transaction `to`. */
  readonly contract: string
}

/**
 * What a sweep of ONE address would move, and what moving it would cost.
 *
 * Its own method on the adapter rather than `estimateFee` plus `spendableBalance`, because on a
 * UTXO chain those two cannot answer it between them: the fee of a Bitcoin sweep depends on how
 * many coins the address holds, and `estimateFee` is not given an address. The sweeper used to
 * quote a one-input two-output spend for every sweep on every chain, and that number is not an
 * estimate for a Bitcoin sweep, it is a wrong answer — a three-coin address quoted at
 * `vsizeOf(1, 2)` pays 141 satoshis of fee for a 246-vbyte transaction, which is 0.57 sat/vB and
 * below the relay floor, so no node would forward it.
 *
 * `null` means "not worth sweeping right now", which is the ordinary recurring state of almost
 * every deposit address, and it is never an error.
 */
export interface SweepQuote {
  /** What the TREASURY gains: the whole spendable balance, less the fee. */
  readonly value: bigint
  /** Burned on top of it. `value + fee` is everything that leaves the address. */
  readonly fee: bigint
}

/**
 * An unsigned transaction, ready to be handed to custody.
 *
 * `payload` is the exact object `POST /v1/sign` receives. It is built to custody's allowlist and
 * nothing else: `signEvm` refuses "a field this service does not sign", so an extra key here is a
 * 403 rather than a wider signature, and that strictness is the reason this type exists instead of
 * a loose record assembled at the call site.
 */
export interface UnsignedOutbound {
  /**
   * `unknown` rather than `Record<string, unknown>`, because not every family's payload is an
   * object. custody's `signEvm` takes a field map and its `signBitcoin` takes a **base64 PSBT
   * string** — a segwit signature commits to the value of each input and only a PSBT carries it,
   * so there is nothing to express as a record. Custody's route reads `body['payload']` untyped
   * and each signer asserts its own shape, so the transport already allowed this; narrowing it
   * here only forced a cast at the one call site that needed the other shape, which is a lie in
   * the type system rather than a check.
   */
  readonly payload: unknown
  readonly value: bigint
  readonly fee: bigint
  /**
   * The account sequence these bytes will consume, as a decimal string.
   *
   * **This is the contended resource the lease exists to protect**, written down so an operator
   * can see which nonce a row holds without decoding its bytes. It is recorded rather than only
   * derived because the adjudication path compares it against `eth_getTransactionCount` and a
   * comparison against a value nobody can read is a comparison nobody can check.
   */
  readonly nonce: string | null
  /**
   * The chain height past which these bytes can NEVER be applied, as a decimal string.
   *
   * Null for EVM and for Bitcoin, and that is not an omission: a signed legacy transaction is
   * valid for ever and only a consumed nonce retires it, and a signed Bitcoin transaction is valid
   * for ever unless its inputs are spent — which is why both of those death proofs are about a
   * resource being taken rather than about time. **Solana is the one chain here where a signature
   * genuinely expires**, and this carries its `lastValidBlockHeight`. XRP's `LastLedgerSequence`
   * goes here too when that adapter lands.
   */
  readonly expiry: string | null
}

/** What a node says about a transaction this service broadcast. */
export type OutboundStatus =
  /** No record of it. In a mempool, or never accepted — indistinguishable from outside. */
  | { readonly kind: 'unknown' }
  /** Seen on chain, not yet at the asset's declared confirmation depth. */
  | { readonly kind: 'pending'; readonly confirmations: number; readonly minedHeight: bigint }
  | { readonly kind: 'confirmed'; readonly confirmations: number; readonly minedHeight: bigint }
  /**
   * Applied and FAILED, or provably unable to ever apply.
   *
   * **The only state in which a signed transaction may be refunded without an operator**, because
   * it is the only one in which the chain itself says the money did not move.
   */
  | { readonly kind: 'rejected'; readonly reason: string }

/** What the adjudication path needs to know about a row before it can judge it. */
export interface DeathInput {
  readonly from: string
  readonly rawTx: string
  readonly txHash: string | null
  /** `outbound_transactions.signed_nonce` and `.signed_expiry`. */
  readonly signedNonce: string | null
  readonly signedExpiry: string | null
}

/**
 * Can these signed bytes still be applied?
 *
 * An `ok: false` is a REFUSAL TO REFUND, and the three codes are three different conversations
 * with an operator. `on_chain` means wait. `still_applicable` means retire the nonce first and
 * says how. `unprovable` means an engineer has to look at the row, and it is what an absence of
 * evidence produces — an absence never refunds.
 */
export type DeathVerdict =
  | { readonly ok: true; readonly proof: string }
  | {
      readonly ok: false
      readonly code: 'on_chain' | 'still_applicable' | 'unprovable'
      readonly error: string
    }

/**
 * Everything this service does to a chain, per chain.
 *
 * The shape is the mirror of the frozen `forge-pay/services/pay/src/outbound.ts` — one small set of
 * operations implemented per family, with the honest answer where a family cannot do them — with
 * one operation the original never had as a first-class method: `proveDead`. There it was a set of
 * loose functions the abandon route assembled by hand, and the assembling was where the two holes
 * were (a null txid read as "no transaction to ask about", and "no receipt" read as "never
 * mined"). Putting it on the interface means a new chain cannot be added without answering it.
 */
/**
 * Reading an ERC-20, for the planner that decides whether a token sweep is worth two transactions.
 *
 * **A CAPABILITY OBJECT RATHER THAN OPTIONAL METHODS ON `OutboundChain`.** A family with no tokens
 * answers `tokens: null`, which a planner reads as "there are no token sweeps here" and skips
 * silently — the ordinary, correct, permanent state of Bitcoin and XRP. The alternative, optional
 * methods, gives every adapter a shape where "not implemented" and "nothing to do" are the same
 * `undefined`, which is the `estimateFee()` returning `0n` mistake `unimplementedChain` exists to
 * refuse.
 *
 * Both methods are READS. Nothing here signs, and nothing here needs a credential the withdrawal
 * path does not already hold.
 */
export interface TokenOperations {
  /** What this address holds of one ERC-20, in the token's own smallest units. */
  balanceOf(call: ChainCall, address: string, contract: string): Promise<bigint>
  /**
   * What one ERC-20 `transfer` costs right now, in native smallest units, bounded.
   *
   * Separate from `estimateFee` because an ERC-20 transfer is not 21,000 gas — it is the intrinsic
   * cost plus the contract's storage work — and quoting a token sweep at a native transfer's gas
   * would under-fund the top-up by roughly four fifths, producing a signed transaction that runs
   * out of gas and burns the fee without moving the tokens.
   */
  transferFee(call: ChainCall, bounds: FeeBounds): Promise<bigint>
}

export interface OutboundChain {
  readonly chain: ChainId
  readonly family: ChainFamily
  /** Null when this chain works. The phase that brings it otherwise. */
  readonly unimplementedPhase: string | null
  /** Null on every family with no token model. @see TokenOperations */
  readonly tokens: TokenOperations | null

  /** The display form of an address, or throw. EIP-55 for EVM; the identity elsewhere. */
  canonicalise(address: string): string
  /** The comparison form. Every `where` clause and every equality uses this and only this. */
  addressKey(address: string): string
  isValidDestination(address: string): boolean

  /** What one transaction on this chain costs right now, in smallest units, bounded. */
  estimateFee(call: ChainCall, bounds: FeeBounds): Promise<bigint>
  /** What this address could send right now, net of anything the chain will not let it move. */
  spendableBalance(call: ChainCall, address: string): Promise<bigint>
  /** What sweeping THIS address would move and cost, or null when it is not worth it. */
  sweepQuote(call: ChainCall, address: string, bounds: FeeBounds): Promise<SweepQuote | null>

  /** Ask the node everything, and assemble the payload custody will sign. Signs nothing. */
  build(call: ChainCall, input: BuildInput): Promise<UnsignedOutbound>
  /** The id these signed bytes will be known by, derived from exactly the bytes. */
  txIdOf(rawTx: string): string | null
  /** Send previously-committed bytes. Idempotent: the same bytes may be sent any number of times. */
  broadcast(call: ChainCall, rawTx: string): Promise<string>
  status(call: ChainCall, txHash: string): Promise<OutboundStatus>
  proveDead(call: ChainCall, input: DeathInput): Promise<DeathVerdict>
}

/* ------------------------------------------------------------------ the unimplemented three */

/**
 * A chain this service does not speak, as a real object on the real interface.
 *
 * Every method throws. That is the whole point: a stub returning `0n` for `estimateFee` and `[]`
 * for a status is a stub that builds a free transaction and then reports it missing, which is
 * indistinguishable from a chain outage and is how a half-built adapter reaches production. The
 * only thing a caller may do with one of these without an exception is read `unimplementedPhase`,
 * which is what `withdrawals.ts` does before it touches anything else.
 */
export function unimplementedChain(
  chain: ChainId,
  phase: string,
  detail: string,
): OutboundChain {
  const refuse = (operation: string): never => {
    throw new NotImplementedError(chain, phase, operation, detail)
  }
  return {
    chain,
    family: familyOf(chain),
    unimplementedPhase: phase,
    // NULL rather than an object whose methods throw, and the distinction is the same one this
    // whole function exists to make. `tokens: null` is read by the planner as "no token sweeps on
    // this chain", which is exactly right for a chain that cannot move a native coin either — a
    // throwing object would instead make every planning pass on an unimplemented chain raise, and
    // `unimplementedPhase` above is already the honest answer to why nothing here works.
    tokens: null,
    canonicalise: () => refuse('address canonicalisation'),
    addressKey: () => refuse('address canonicalisation'),
    isValidDestination: () => refuse('destination validation'),
    estimateFee: () => Promise.reject(new NotImplementedError(chain, phase, 'fee estimation', detail)),
    spendableBalance: () =>
      Promise.reject(new NotImplementedError(chain, phase, 'balance reading', detail)),
    // Rejects rather than answering `null`. `null` is this method's word for "not worth sweeping
    // right now", which the sweeper treats as ordinary and silent — so an unimplemented chain that
    // answered it would look exactly like a chain with nothing to sweep, for ever, at no log level.
    sweepQuote: () => Promise.reject(new NotImplementedError(chain, phase, 'sweep quoting', detail)),
    build: () => Promise.reject(new NotImplementedError(chain, phase, 'transaction building', detail)),
    txIdOf: () => refuse('transaction id derivation'),
    broadcast: () => Promise.reject(new NotImplementedError(chain, phase, 'broadcast', detail)),
    status: () => Promise.reject(new NotImplementedError(chain, phase, 'status lookup', detail)),
    proveDead: () =>
      Promise.reject(new NotImplementedError(chain, phase, 'death adjudication', detail)),
  }
}
