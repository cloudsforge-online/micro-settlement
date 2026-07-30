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
 * ## Two implemented, three real and unimplemented
 *
 * `eth` and `ember` are one implementation — see `evm.ts`. An EMBER payment is a legacy (type 0)
 * EVM transaction against a standard `eth_*` endpoint, so the two differ only in which node answers
 * and which chain id the signature commits to.
 *
 * `btc`, `sol` and `xrp` are **real objects on this interface that throw `NotImplementedError`
 * naming the phase that brings them**. They are not stubs that return zero, they are not absent
 * from the registry, and `chainFor('btc')` does not throw: a caller gets an object it can ask
 * `unimplementedPhase` of, which is what lets the withdrawal path classify the refusal as permanent
 * and refund from `pending` rather than retrying a chain that will never answer. A missing entry
 * would instead be a `TypeError` somewhere in the job handler.
 *
 * ## Why BTC and SOL cannot be withdrawn OR swept, stated once
 *
 * It is not this service's limitation, it is custody's, and it is deliberate on custody's side:
 *
 *   * **BTC** — `signBitcoin` requires a base64 PSBT, because a segwit signature commits to the
 *     VALUE of each input and only a PSBT carries it. The signer is ready; the OUTPUT POLICY is
 *     not. `signing.ts` specifies it (every output of a `deposit`-purpose PSBT must pay the pinned
 *     treasury, change included, and a PSBT carrying anything else is refused whole rather than
 *     partially signed) and does not build it, so `gates.SWEEPABLE_FAMILIES` refuses a
 *     `deposit`-purpose bitcoin address outright. That refusal is the fail-closed half of
 *     "specified, not built" and it must not be worked around from this side.
 *   * **SOL** — `signSolana` allows only the SPL mint-creation instruction set and explicitly
 *     refuses `SystemProgram::Transfer`, which is what moving SOL is. There is no transfer shape,
 *     so there is no sweep shape either. Admitting a `deposit`-purpose SOL address to custody's
 *     signer without one would hand a signing credential `createAccount` over every customer's SOL
 *     deposit key, and `createAccount` can park up to 50,000,000 lamports in a mint account that
 *     nothing in this estate can recover.
 *
 * `xrp` is a third case and a different one: custody signs XRP today (`signXrp`, with both a
 * `payment` and a pinned `sweep` shape), so the gap is entirely on this side — this service does
 * not yet speak XRPL. It is here rather than half-built because an XRP blob carries a `Sequence`
 * and a `LastLedgerSequence` that must be COMMITTED beside the bytes to be abandonable at all, and
 * a half-implementation that signs without recording them produces withdrawals that can never be
 * adjudicated. `outbound_transactions` already has the columns; the adapter is what is missing.
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
export type ChainId = 'ember' | 'eth' | 'btc' | 'sol' | 'xrp'

export const CHAIN_IDS: readonly ChainId[] = Object.freeze(['ember', 'eth', 'btc', 'sol', 'xrp'])

const ASSET_FOR_CHAIN: Readonly<Record<ChainId, AssetCode>> = Object.freeze({
  ember: 'EMBER',
  eth: 'ETH',
  btc: 'BTC',
  sol: 'SOL',
  xrp: 'XRP',
})

const CHAIN_FOR_ASSET: Readonly<Partial<Record<AssetCode, ChainId>>> = Object.freeze({
  EMBER: 'ember',
  ETH: 'eth',
  BTC: 'btc',
  SOL: 'sol',
  XRP: 'xrp',
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
 * Custody's `CHAIN_ASSET` is keyed by chain NAME — `ethereum`, `bitcoin`, `solana`, `xrp`,
 * `ember` — because those are the values the rows it adopted from forge-keyvault already carry.
 * This service's slug is the asset code lowercased. The two agree on four of five and disagree on
 * exactly one, `eth` versus `ethereum`, and that one disagreement is a `binding_mismatch` at
 * signing time: custody compares the caller's restated `chain` against the stored row character
 * for character. So the translation is a table with a name rather than a `toLowerCase()` that
 * happens to work for the other four.
 */
const CUSTODY_CHAIN: Readonly<Record<ChainId, string>> = Object.freeze({
  ember: 'ember',
  eth: 'ethereum',
  btc: 'bitcoin',
  sol: 'solana',
  xrp: 'xrp',
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
export interface BuildInput {
  readonly from: string
  readonly to: string
  readonly value: bigint
  readonly fee: bigint
  readonly bounds: FeeBounds
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
  readonly payload: Record<string, unknown>
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
   * Null for EVM, and that is not an omission: a signed legacy transaction is valid for ever and
   * only a consumed nonce retires it, which is why the EVM half of the death proof is about the
   * nonce and not about time. XRP's `LastLedgerSequence` goes here when that adapter lands.
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
export interface OutboundChain {
  readonly chain: ChainId
  readonly family: ChainFamily
  /** Null when this chain works. The phase that brings it otherwise. */
  readonly unimplementedPhase: string | null

  /** The display form of an address, or throw. EIP-55 for EVM; the identity elsewhere. */
  canonicalise(address: string): string
  /** The comparison form. Every `where` clause and every equality uses this and only this. */
  addressKey(address: string): string
  isValidDestination(address: string): boolean

  /** What one transaction on this chain costs right now, in smallest units, bounded. */
  estimateFee(call: ChainCall, bounds: FeeBounds): Promise<bigint>
  /** What this address could send right now, net of anything the chain will not let it move. */
  spendableBalance(call: ChainCall, address: string): Promise<bigint>

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
    canonicalise: () => refuse('address canonicalisation'),
    addressKey: () => refuse('address canonicalisation'),
    isValidDestination: () => refuse('destination validation'),
    estimateFee: () => Promise.reject(new NotImplementedError(chain, phase, 'fee estimation', detail)),
    spendableBalance: () =>
      Promise.reject(new NotImplementedError(chain, phase, 'balance reading', detail)),
    build: () => Promise.reject(new NotImplementedError(chain, phase, 'transaction building', detail)),
    txIdOf: () => refuse('transaction id derivation'),
    broadcast: () => Promise.reject(new NotImplementedError(chain, phase, 'broadcast', detail)),
    status: () => Promise.reject(new NotImplementedError(chain, phase, 'status lookup', detail)),
    proveDead: () =>
      Promise.reject(new NotImplementedError(chain, phase, 'death adjudication', detail)),
  }
}
