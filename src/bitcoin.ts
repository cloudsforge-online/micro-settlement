/**
 * The Bitcoin outbound adapter: coin selection, PSBT construction, broadcast, and a death proof
 * that is about conflicting spends rather than about a nonce.
 *
 * ## The claim this file corrects
 *
 * `registry.ts` has said, since this service was written, that for Bitcoin "neither a withdrawal
 * nor a sweep is possible until that policy exists". **Half of that is wrong, and it has been
 * blocking a gate item that was never actually blocked.** Read custody's `purposeGate`:
 *
 *     if (row.purpose === 'deposit' && !SWEEPABLE_FAMILIES.has(row.family)) refuse
 *
 * The gate is conditioned on `purpose === 'deposit'`. `SIGNABLE_PURPOSES` is
 * `{deployer, treasury, deposit}`, and `keys.ts` dispatches a `bitcoin` row to `signBitcoin` for
 * any of them. `signBitcoin` signs a PSBT whose every input is a P2WPKH output of the signing
 * address, to **any destination the PSBT names** — its own comment says "the destination is the
 * caller's business, the source is not".
 *
 * So:
 *
 *   * **A withdrawal from a `treasury`-purpose BTC address is signable by custody today.** That is
 *     what this file implements, and it is the whole of gate item 3's withdraw half for BTC.
 *   * **A sweep is not**, because a sweep spends a `deposit`-purpose address and that is exactly
 *     what the gate refuses. The output policy custody's `signing.ts` specifies — every output of
 *     a deposit-purpose PSBT must pay the pinned treasury — is genuinely unbuilt, and it is
 *     unbuilt *in custody*. Nothing in this repository can change it and nothing here tries to
 *     work around it: `buildSweep` below constructs the correct pinned-output PSBT, so the day
 *     that gate opens there is a caller ready for it, and until then custody refuses it at gate 1
 *     which is precisely where a fail-closed refusal belongs.
 *
 * ## Why there is a chain library here now, when package.json says there is not
 *
 * That note's reasoning is: "This service builds ONE transaction shape (a legacy EVM value
 * transfer) and hands it to custody as a JSON object; custody is the only place a private key
 * exists and therefore the only place a serialiser is needed." The premise is true for EVM and
 * **false for Bitcoin**: `signBitcoin` does not take a JSON object, it takes a base64 PSBT, and a
 * PSBT is a serialised transaction plus the value of every input. Something on this side has to
 * encode one.
 *
 * Given that, the choice is between hand-rolling a BIP-174 encoder and using the same library
 * custody decodes with. It is the second, for one reason: a builder and a signer with two
 * independent implementations of one binary format is the exact shape of a bug that pays a
 * stranger. `bitcoinjs-lib` is already custody's dependency at the same major version, so the
 * bytes this file produces are parsed by the parser they were produced for.
 *
 * ## Coin selection, and why it is deliberately dull
 *
 * Largest-first, deterministic, no randomisation and no privacy heuristics. A treasury payout is
 * not a wallet: reproducibility matters more than the change-output fingerprint, because the same
 * row rebuilt after a crash must select the same coins or it is a different transaction spending
 * overlapping inputs — two signed transactions in flight for one payment, which is the failure the
 * whole in-flight lease exists to prevent.
 */

import * as bitcoin from 'bitcoinjs-lib'
import type { Network } from '@cloudsforge/contracts-chain'
import { chainSpec } from '@cloudsforge/contracts-chain'
import {
  AddressError,
  FeeOutOfBandError,
  InsufficientTreasuryError,
  assetOf,
  type BuildInput,
  type ChainCall,
  type ChainId,
  type DeathInput,
  type DeathVerdict,
  type FeeBounds,
  type OutboundChain,
  type OutboundShape,
  type OutboundStatus,
  type SweepQuote,
  type UnsignedOutbound,
} from './chains.ts'

/* ------------------------------------------------------------------ networks */

/**
 * The estate's `testnet` is Bitcoin's `testnet`.
 *
 * `bitcoin.networks.testnet` also covers signet and regtest for address encoding purposes — they
 * share version bytes — so an operator pointing at any of the three gets consistent behaviour.
 * What matters is that mainnet and not-mainnet never mix, and they cannot: the version bytes
 * differ, so a mainnet address simply fails to decode against the testnet network and vice versa.
 * That is the same binding custody enforces from the other side, where `ECPair.fromWIF` throws
 * when the WIF's network byte disagrees.
 */
export function networkFor(network: Network): bitcoin.Network {
  return network === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet
}

/* ------------------------------------------------------------------ amounts and sizes */

/** Satoshis per BTC. Core speaks BTC on the wire for amounts; this service speaks satoshis. */
const SATS_PER_BTC = 100_000_000n

/** 21 million BTC. A value above it did not come from Bitcoin. */
export const MAX_SATOSHIS = 2_100_000_000_000_000n

/**
 * BTC (as Core serialises it) → satoshis.
 *
 * The same argument as the indexer's `btcToSats`, and it has to be made again here because this is
 * a different service: Core reports amounts as JSON numbers, so the decimal has been through an
 * IEEE-754 double before this code runs. The largest valid amount is 21e6 BTC, the ULP of a double
 * there is about 3.7e-9, and scaled by 1e8 that is an error under half a satoshi against a true
 * value that is an exact multiple of one. So `Math.round` recovers the exact amount rather than
 * merely approaching it — inside the valid range, which is therefore checked and not assumed.
 */
export function btcToSats(value: unknown): bigint {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new AddressError(`a bitcoin amount was expected and ${String(value)} arrived`)
  }
  if (value < 0) throw new AddressError(`a bitcoin amount may not be negative: ${value}`)
  const sats = BigInt(Math.round(value * 1e8))
  if (sats > MAX_SATOSHIS) {
    throw new AddressError(`${value} BTC exceeds the 21,000,000 supply cap`)
  }
  return sats
}

/** Satoshis → the BTC number Core expects in a parameter. */
export function satsToBtc(sats: bigint): number {
  return Number(sats) / Number(SATS_PER_BTC)
}

/**
 * The virtual size, in vbytes, of a P2WPKH spend with `inputs` inputs and `outputs` outputs.
 *
 * Every input this service spends is P2WPKH of the treasury address — custody refuses anything
 * else — so the size is exact rather than estimated, and being exact is what lets the fee be
 * checked against the locked quote instead of hoped about:
 *
 *   base: 4 version + 1 segwit marker/flag counted in weight + varint counts + 4 locktime
 *   per input: 32 txid + 4 vout + 1 empty scriptSig + 4 sequence = 41 vbytes of base,
 *              plus a 108-weight-unit witness (1 item count + 1+72 sig + 1+33 pubkey) = 27 vbytes
 *   per output: 8 value + 1 script length + 22 script (OP_0 <20-byte hash>) = 31 vbytes
 *
 * Rounded up, because a fractional vbyte is charged as a whole one.
 */
export function vsizeOf(inputs: number, outputs: number): number {
  const base = 10.5 + inputs * 41 + outputs * 31
  const witness = inputs * 27
  return Math.ceil(base + witness)
}

/* ------------------------------------------------------------------ addresses */

/**
 * Bitcoin addresses are NOT case-normalised.
 *
 * base58check is case-SIGNIFICANT: lower-casing `1BvBMSEY…` produces a string that fails its own
 * checksum and is not an address. bech32 is case-insensitive but canonically lower-case. So the
 * canonical form is the string as given, validated — and `addressKey` is the same, which is why
 * both are the identity here where EVM's are `toLowerCase` and EIP-55.
 *
 * Validation is `toOutputScript`, which is the only honest check: it decodes the address to the
 * script that would actually be paid, so a typo'd checksum, a wrong-network address and an
 * unsupported witness version all fail at the point they would otherwise become an unspendable
 * output.
 */
export function validateAddress(address: string, network: Network): string {
  const trimmed = address.trim()
  if (trimmed.length === 0) throw new AddressError('a bitcoin address may not be empty')
  try {
    bitcoin.address.toOutputScript(trimmed, networkFor(network))
  } catch {
    throw new AddressError(
      `${trimmed} is not a valid bitcoin ${network} address — note that a mainnet address is ` +
        'rejected on testnet and the reverse, which is the binding that stops a payment being ' +
        'broadcastable on the chain it was not meant for',
    )
  }
  return trimmed
}

/* ------------------------------------------------------------------ the node */

export interface Utxo {
  readonly txid: string
  readonly vout: number
  readonly sats: bigint
  readonly scriptPubKey: string
  readonly confirmations: number
}

/** A number Core returned where an integer was expected. */
function integer(value: unknown, method: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new AddressError(`${method} answered ${String(value)} where an integer was expected`)
  }
  return value
}

/**
 * Spendable outputs of one address, newest-confirmation-last.
 *
 * `listunspent` with an explicit address filter and a minimum confirmation depth. The depth is the
 * asset's own `confirmations` from `contracts-chain` and not a local constant: spending an output
 * that is not yet at the depth this estate credits at would build a payment on money it has not
 * itself accepted, and if that input is reorganised out the payment becomes unminable with a user
 * waiting on it.
 */
async function listUnspent(
  call: ChainCall,
  address: string,
  minConfirmations: number,
): Promise<Utxo[]> {
  const raw = await call.rpc('listunspent', [minConfirmations, 9_999_999, [address]])
  if (!Array.isArray(raw)) {
    throw new AddressError('listunspent did not answer with a list')
  }
  const utxos: Utxo[] = []
  for (const entry of raw) {
    if (typeof entry !== 'object' || entry === null) continue
    const row = entry as Record<string, unknown>
    if (row['spendable'] === false) continue
    const script = row['scriptPubKey']
    if (typeof row['txid'] !== 'string' || typeof script !== 'string') continue
    utxos.push({
      txid: row['txid'],
      vout: integer(row['vout'], 'listunspent'),
      sats: btcToSats(row['amount']),
      scriptPubKey: script,
      confirmations: integer(row['confirmations'] ?? 0, 'listunspent'),
    })
  }
  // Largest first, then by outpoint so the order is total and identical on every rebuild. A
  // selection that depends on the node's iteration order is a selection that can differ between
  // the build and the rebuild after a crash, which is two transactions for one payment.
  return utxos.sort(
    (a, b) =>
      (b.sats > a.sats ? 1 : b.sats < a.sats ? -1 : 0) ||
      a.txid.localeCompare(b.txid) ||
      a.vout - b.vout,
  )
}

export interface Selection {
  readonly inputs: readonly Utxo[]
  readonly change: bigint
  readonly fee: bigint
}

/**
 * Choose coins to pay `target` at `feeRate` sat/vB, largest first.
 *
 * The fee is recomputed on every candidate rather than fixed up at the end, because each extra
 * input costs 68 vbytes of fee and an implementation that ignores that underpays by exactly the
 * amount its own inputs cost — a transaction that sits in a mempool unmined, which for a user
 * waiting on a withdrawal is indistinguishable from lost.
 *
 * Change below `dustThreshold` is given to the miner instead of created. A 546-satoshi output
 * costs more to spend than it holds, so creating one manufactures an input that can never
 * economically be used again.
 */
export function selectCoins(
  utxos: readonly Utxo[],
  target: bigint,
  feeRatePerVb: bigint,
  dustThreshold: bigint,
): Selection {
  const chosen: Utxo[] = []
  let total = 0n
  for (const utxo of utxos) {
    chosen.push(utxo)
    total += utxo.sats

    // Two outputs: the payment and the change.
    const withChange = feeRatePerVb * BigInt(vsizeOf(chosen.length, 2))
    if (total >= target + withChange) {
      const change = total - target - withChange
      if (change >= dustThreshold) {
        return { inputs: chosen, change, fee: withChange }
      }
      // Change would be dust. Drop the output and let the difference go to the fee, which is
      // cheaper for everyone than an output nobody can afford to spend.
      const withoutChange = feeRatePerVb * BigInt(vsizeOf(chosen.length, 1))
      if (total >= target + withoutChange) {
        return { inputs: chosen, change: 0n, fee: total - target }
      }
      continue
    }

    // The exact-payment case: no change at all, one output.
    const withoutChange = feeRatePerVb * BigInt(vsizeOf(chosen.length, 1))
    if (total >= target + withoutChange && total - target - withoutChange < dustThreshold) {
      return { inputs: chosen, change: 0n, fee: total - target }
    }
  }
  throw new InsufficientTreasuryError('btc', total, target)
}

export function totalOf(utxos: readonly Utxo[]): bigint {
  return utxos.reduce((sum, utxo) => sum + utxo.sats, 0n)
}

export interface SweepPlan extends SweepQuote {
  readonly inputs: readonly Utxo[]
}

/**
 * **THE ONE PLACE A BITCOIN SWEEP'S ARITHMETIC IS DONE**, used by the quote and by the build.
 *
 * They must agree to the satoshi. `planSweep` writes `value` and `fee` onto the row from the quote
 * and the build is handed both back; if the two computed the same thing two ways they would
 * eventually disagree by a rounding, and the build would refuse a row it had itself quoted. So
 * there is one function and both call it.
 *
 * EVERY coin and ONE output, which is what makes custody's output policy satisfiable at all: a
 * sweep leaves nothing behind, so there is no change output that could pay anywhere but the pin.
 * The fee is therefore not chosen, it is the remainder — `value` is set so the remainder comes out
 * at the quoted rate for the size the transaction will really be, `vsizeOf(n, 1)`, and not for the
 * one-input two-output spend `estimateFee` quotes.
 *
 * Null rather than a throw for "not worth it yet", because that is the ordinary recurring state of
 * almost every deposit address and a throw would make it an incident.
 */
export function sweepPlan(
  utxos: readonly Utxo[],
  feeRatePerVb: bigint,
  dustThreshold: bigint,
): SweepPlan | null {
  if (utxos.length === 0) return null
  const total = totalOf(utxos)
  const fee = feeRatePerVb * BigInt(vsizeOf(utxos.length, 1))
  const value = total - fee
  // Sweeping less than it costs to sweep destroys value, and an output at or below the dust
  // threshold costs more to spend than it holds — it would manufacture a coin nothing can ever
  // economically move again.
  if (value <= dustThreshold) return null
  return { inputs: utxos, value, fee }
}

/**
 * The virtual size custody will measure, taken from the SMALLEST transaction it could finalise
 * this PSBT into.
 *
 * The smallest, deliberately, because a smaller transaction is a HIGHER fee rate and this feeds a
 * ceiling. `vsizeOf` is an upper bound on the size and would therefore be a LOWER bound on the
 * rate, which is the wrong direction for a guard: it would let through exactly the PSBT that
 * measures over the ceiling once the real witnesses are on it.
 *
 * A P2WPKH witness is a DER signature plus its sighash byte and a 33-byte compressed pubkey. 71
 * bytes is the signature length a low-S DER encoding almost always produces; 72 is what bitcoinjs
 * assumes when it predicts one. Shorter ones exist — a leading zero byte drops out of `r` or `s`
 * about once in 256 — and they are covered by the margin between this service's ceiling and
 * custody's rather than by pretending to model them. `bitcoin.test.ts` measures that margin.
 */
export function finalisedVsize(psbt: bitcoin.Psbt): number {
  const tx = new bitcoin.Transaction()
  psbt.txInputs.forEach((input, i) => {
    tx.addInput(input.hash, input.index, input.sequence)
    tx.setWitness(i, [Buffer.alloc(71, 1), Buffer.alloc(33, 2)])
  })
  for (const output of psbt.txOutputs) tx.addOutput(output.script, output.value)
  return tx.virtualSize()
}

/**
 * Refuse a PSBT custody's own ceiling would refuse. See the ceiling block below.
 *
 * The comparison is `>=` and the divisor is the finalised size, because that is character for
 * character what `signBitcoin` does: `psbt.getFeeRate()` is `Math.floor(fee / virtualSize)` and it
 * refuses at `feeRate >= ceiling` (custody/src/signing.ts:700). Reproducing the comparison rather
 * than approximating it is the point — an approximation is a second policy, and the one thing that
 * must not happen here is this service believing a PSBT acceptable that custody will not sign.
 */
export function assertUnderCustodysCeiling(
  psbt: bitcoin.Psbt,
  fee: bigint,
  shape: OutboundShape,
): void {
  const ceiling = shape === 'sweep' ? CUSTODY_MAX_SWEEP_SAT_PER_VB : CUSTODY_MAX_PAYMENT_SAT_PER_VB
  const vsize = BigInt(finalisedVsize(psbt))
  if (fee / vsize >= ceiling) {
    throw new FeeOutOfBandError('btc', 'above', fee, ceiling * vsize)
  }
}

/* ------------------------------------------------------------------ the adapter */

const DEFAULT_DUST = 546n
/** Core's own relay floor. Below it a transaction is not forwarded at all. */
const MIN_RELAY_SAT_PER_VB = 1n
/** How many blocks `estimatesmartfee` is asked to target. */
const FEE_TARGET_BLOCKS = 3

/* ------------------------------------------------------------------ the two fee ceilings */

/**
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 * **CUSTODY'S CEILINGS ARE THE AUTHORITY. THESE ARE A MIRROR OF THEM, AND THE MIRROR IS TIGHTER.**
 *
 * There is one number here that must not be got wrong and it is a RELATIONSHIP, not a value.
 * custody's `signBitcoin` sets `psbt.setMaximumFeeRate(ceiling)` and then refuses outright at
 * `feeRate >= ceiling` (custody/src/signing.ts:700), with two ceilings of its own:
 *
 *     MAX_SWEEP_FEE_RATE   = 1_000   (custody/src/signing.ts:623)
 *     MAX_PAYMENT_FEE_RATE = 5_000   (custody/src/signing.ts:624)
 *
 * Until this block existed, this service carried ONE ceiling, `MAX_SAT_PER_VB = 5_000`, applied to
 * both shapes. Two things were wrong with that and they are different failures:
 *
 *   1. **A sweep this service considered acceptable was refused at signing.** custody binds first
 *      and its sweep ceiling is five times tighter, so during any event above 1000 sat/vB every
 *      sweep would have been built, committed, and 403'd — a `shape_refused`, which
 *      `planBuildFailure` classifies as permanent, from a service the operator does not run.
 *   2. **Equality was not safe even at the payment ceiling.** custody compares `>=` against the
 *      fee rate of the FINALISED transaction, and this service quotes against `vsizeOf`, which is
 *      an UPPER bound on the size (`bitcoin.test.ts` pins it at within two vbytes). A smaller
 *      transaction is a HIGHER rate, so a PSBT built at exactly 5,000 arrives at custody measuring
 *      5,000 or a little more, and is refused.
 *
 * **SO: TWO AUTHORITIES, NOT ONE, AND THE TIGHTER ONE IS BOTH DOCUMENTED AND ASSERTED.** Collapsing
 * them into one number is not available, and it is worth saying why rather than leaving it to look
 * like duplication. custody's ceiling cannot move here: a signing rule enforced only by its caller
 * is a signing rule an attacker bypasses by reaching the signer directly, which is the argument
 * custody's own header makes about the policy service, and the credential this ceiling bounds
 * (`custody:sign:deposit`) is precisely the one this service holds. This service's ceiling cannot
 * move there either: refusing at BUILD time is what turns a 403 with a committed row and a claimed
 * chain slot into a classified build failure that releases the row before anything is signed. Two
 * gates, the same rule, one of them fails cheap and the other fails safe.
 *
 * The relationship is asserted, not asserted about: `bitcoin.test.ts` computes the worst-case rate
 * custody can measure for a transaction this service built at its own ceiling, for input counts
 * from one to fifty, and requires every one of them to stay under custody's. Move either constant
 * and that test goes red.
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 */

/** custody/src/signing.ts:623. Restated so the test can compare, never used as this service's own. */
export const CUSTODY_MAX_SWEEP_SAT_PER_VB = 1_000n
/** custody/src/signing.ts:624. Same. */
export const CUSTODY_MAX_PAYMENT_SAT_PER_VB = 5_000n

/**
 * This service's own ceilings. Strictly below custody's, by more than the vsize slack can consume.
 *
 * A ceiling, not an estimate: above these a node has quoted something absurd and the answer is to
 * wait for a cheaper block rather than to burn a customer's deposit on miner revenue. A sweep is a
 * background job with nobody waiting, so stalling one is self-healing in a way a burn is not; a
 * withdrawal has a user waiting, which is why its ceiling is the looser of the two here exactly as
 * it is in custody.
 */
export const MAX_SWEEP_SAT_PER_VB = 900n
export const MAX_SAT_PER_VB = 4_500n

export interface BitcoinChainOptions {
  readonly dustThreshold?: bigint
}

export function bitcoinChain(options: BitcoinChainOptions = {}): OutboundChain {
  const dust = options.dustThreshold ?? DEFAULT_DUST
  const spec = chainSpec(assetOf('btc'))

  /**
   * sat/vB from the node, bounded by the ceiling for THIS shape.
   *
   * The shape is a parameter rather than one clamp for both, because the two ceilings are five
   * times apart and the tighter one is the one custody will actually apply to a sweep. See the
   * ceiling block above.
   */
  async function feeRate(call: ChainCall, shape: OutboundShape): Promise<bigint> {
    const ceiling = shape === 'sweep' ? MAX_SWEEP_SAT_PER_VB : MAX_SAT_PER_VB
    const answer = await call.rpc('estimatesmartfee', [FEE_TARGET_BLOCKS])
    const row = (answer ?? {}) as Record<string, unknown>
    // `feerate` is BTC per kilovbyte. Absent means the node has too little data to estimate, which
    // is a real state on a fresh node and on testnet — the floor is used rather than guessing high.
    if (typeof row['feerate'] !== 'number') return MIN_RELAY_SAT_PER_VB
    const perKvb = btcToSats(row['feerate'])
    const perVb = perKvb / 1_000n
    if (perVb < MIN_RELAY_SAT_PER_VB) return MIN_RELAY_SAT_PER_VB
    if (perVb > ceiling) return ceiling
    return perVb
  }

  async function statusOf(call: ChainCall, txid: string): Promise<OutboundStatus> {
    let raw: unknown
    try {
      raw = await call.rpc('getrawtransaction', [txid, true])
    } catch {
      // Core answers -5 for a transaction it has never seen. Indistinguishable from a transaction
      // still in another node's mempool, so it is `unknown` and never `rejected` — a `rejected`
      // here would refund a payment that is merely propagating.
      return { kind: 'unknown' }
    }
    if (typeof raw !== 'object' || raw === null) return { kind: 'unknown' }
    const row = raw as Record<string, unknown>
    const confirmations = typeof row['confirmations'] === 'number' ? row['confirmations'] : 0
    if (confirmations <= 0) return { kind: 'unknown' }

    const height = await call.rpc('getblockcount', [])
    const tip = BigInt(integer(height, 'getblockcount'))
    const minedHeight = tip - BigInt(confirmations) + 1n
    // A mined Bitcoin transaction cannot have failed: an invalid one never enters a block. So
    // there is no `rejected` branch here at all, where the EVM adapter needs one for a revert.
    return confirmations >= spec.confirmations
      ? { kind: 'confirmed', confirmations, minedHeight }
      : { kind: 'pending', confirmations, minedHeight }
  }

  /**
   * Build a PSBT spending `inputs` and paying `outputs`, funded by `from`.
   *
   * The one encoder, shared by the withdrawal path and the sweep path, because the two differ only
   * in WHICH coins and WHICH outputs — and sharing the construction is what stops the sweep drifting
   * away from the encoding custody has already validated a withdrawal against.
   */
  function encodePsbt(
    net: bitcoin.Network,
    from: string,
    inputs: readonly Utxo[],
    outputs: readonly { address: string; sats: bigint }[],
  ): bitcoin.Psbt {
    const psbt = new bitcoin.Psbt({ network: net })
    const script = bitcoin.address.toOutputScript(from, net)
    for (const utxo of inputs) {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        // The VALUE is why this is a PSBT and not a raw transaction: a segwit signature commits to
        // the value of each input, and only this field carries it. custody's `signBitcoin` refuses
        // an input without one — "its value is unknown" — and it is right to.
        witnessUtxo: { script, value: Number(utxo.sats) },
        // SIGHASH_ALL only. Anything else leaves part of the transaction editable after signing,
        // and custody refuses it, so stating it here means a mismatch fails at build rather than
        // at the signing request.
        sighashType: bitcoin.Transaction.SIGHASH_ALL,
      })
    }
    for (const output of outputs) {
      psbt.addOutput({ address: output.address, value: Number(output.sats) })
    }
    return psbt
  }

  /**
   * Build one outbound transaction, of either shape.
   *
   * **The two shapes select their coins by two different rules and that is the whole of the
   * branch.** A withdrawal chooses the fewest coins that cover the payment and returns the change
   * to the treasury. A sweep takes EVERY coin and creates no change at all, because custody's
   * `assertSweepOutputs` refuses a PSBT any of whose outputs does not pay the pin — so a sweep with
   * a change output back to the deposit address is refused WHOLE, and that is exactly what routing
   * a sweep through the withdrawal builder used to produce.
   */
  async function buildOutbound(call: ChainCall, input: BuildInput): Promise<UnsignedOutbound> {
    const net = networkFor(call.network)
    validateAddress(input.from, call.network)
    validateAddress(input.to, call.network)
    if (input.value <= 0n) {
      // A zero-value output is refused by the relay as dust and by custody as an output that pays
      // nothing. Refusing here makes it a classified build failure rather than a 403.
      throw new FeeOutOfBandError('btc', 'below', input.value, 1n)
    }
    if (input.fee > input.bounds.maxFeeWei) {
      throw new FeeOutOfBandError('btc', 'above', input.fee, input.bounds.maxFeeWei)
    }

    const rate = await feeRate(call, input.shape)
    const utxos = await listUnspent(call, input.from, spec.confirmations)

    let inputs: readonly Utxo[]
    let fee: bigint
    const outputs: { address: string; sats: bigint }[] = [{ address: input.to, sats: input.value }]

    if (input.shape === 'sweep') {
      const plan = sweepPlan(utxos, rate, dust)
      if (!plan) {
        // Nothing at depth, or not enough to be worth moving. Either way the coins are not there,
        // which classifies as a treasury failure and is retried rather than refunded on the spot.
        throw new InsufficientTreasuryError('btc', totalOf(utxos), input.value + input.fee)
      }
      // **The plan must still be the plan the ROW was written from.** `planSweep` quoted this same
      // UTXO set through this same function; a disagreement means coins arrived or left in between,
      // and the difference between the two numbers is a fee nobody agreed to pay. Refused rather
      // than silently re-quoted, exactly as a withdrawal's locked fee is.
      if (plan.value !== input.value || plan.fee !== input.fee) {
        throw new FeeOutOfBandError('btc', plan.fee > input.fee ? 'below' : 'above', input.fee, plan.fee)
      }
      inputs = plan.inputs
      fee = plan.fee
    } else {
      const selection = selectCoins(utxos, input.value, rate, dust)
      // The locked fee is what the user agreed to. It is checked, never re-quoted: re-quoting here
      // would sign a transaction that does not match the row it was built from, and the fee bounds
      // exist so a node having a bad minute cannot spend a user's balance on miner revenue.
      if (selection.fee > input.fee) {
        throw new FeeOutOfBandError('btc', 'below', input.fee, selection.fee)
      }
      inputs = selection.inputs
      fee = selection.fee
      if (selection.change > 0n) {
        // Change returns to the SOURCE address, never to a fresh one. A fresh change address would
        // be a key this service invented, and every key in this estate is custody's.
        outputs.push({ address: input.from, sats: selection.change })
      }
    }

    const psbt = encodePsbt(net, input.from, inputs, outputs)
    assertUnderCustodysCeiling(psbt, fee, input.shape)

    return {
      // A base64 PSBT string, which is what `signBitcoin` requires. See `UnsignedOutbound.payload`.
      payload: psbt.toBase64(),
      value: input.value,
      fee,
      // Bitcoin has no nonce. The contended resource is the UTXO SET, and it is named by the
      // inputs rather than by a number: two transactions spending one outpoint are the Bitcoin
      // spelling of two transactions at one nonce, and `outbound_in_flight_uniq` is what stops a
      // second one being built while the first is unconfirmed.
      nonce: null,
      // A signed Bitcoin transaction is valid for ever unless its inputs are spent, exactly as a
      // signed legacy EVM transaction is valid for ever unless its nonce is consumed. So there is
      // no expiry, and `proveDead` is about conflicting spends rather than about time.
      expiry: null,
    }
  }

  return {
    chain: 'btc',
    family: 'bitcoin',
    unimplementedPhase: null,
    // Bitcoin has no token model, so there is nothing here and never will be. Null rather than an
    // object whose methods throw: the token planner reads it as "no token sweeps on this chain" and
    // skips silently, which is the permanent, correct, unremarkable state of this chain.
    tokens: null,

    canonicalise(address) {
      // The identity, validated. See `validateAddress` for why lower-casing would be a bug.
      return validateAddress(address, 'mainnet')
    },
    addressKey(address) {
      return address.trim()
    },
    isValidDestination(address) {
      // Valid on EITHER network is the honest answer to a question that does not name one; the
      // network-specific check happens in `build`, where the network is known.
      for (const network of ['mainnet', 'testnet'] as const) {
        try {
          validateAddress(address, network)
          return true
        } catch {
          /* try the other */
        }
      }
      return false
    },

    /**
     * What one payment costs right now: the node's rate times the size of a typical spend.
     *
     * "Typical" is one input and two outputs, and that is quoted rather than measured because the
     * quote is given BEFORE the coins are chosen. `build` re-derives the real size from the real
     * selection and refuses if it exceeds the locked quote, which is what stops the estimate being
     * load-bearing.
     */
    async estimateFee(call, bounds) {
      const rate = await feeRate(call, 'payment')
      const fee = rate * BigInt(vsizeOf(1, 2))
      if (fee > bounds.maxFeeWei) {
        throw new FeeOutOfBandError('btc', 'above', fee, bounds.maxFeeWei)
      }
      return fee
    },

    async spendableBalance(call, address) {
      return totalOf(await listUnspent(call, address, spec.confirmations))
    },

    /**
     * What a sweep of this address would move, from the coins it actually holds.
     *
     * **This is the method `estimateFee` could not be.** A sweep spends every coin at depth, so its
     * size — and therefore its fee — is a property of the address, and `estimateFee` is not given
     * one. Quoting `vsizeOf(1, 2)` for a three-coin address, which is what the sweeper did before
     * this existed, under-quotes the fee by more than half and produces a transaction below the
     * relay floor.
     */
    async sweepQuote(call, address, bounds) {
      const rate = await feeRate(call, 'sweep')
      const plan = sweepPlan(await listUnspent(call, address, spec.confirmations), rate, dust)
      if (!plan) return null
      if (plan.fee > bounds.maxFeeWei) {
        throw new FeeOutOfBandError('btc', 'above', plan.fee, bounds.maxFeeWei)
      }
      return { value: plan.value, fee: plan.fee }
    },

    build: buildOutbound,

    /**
     * The txid of the bytes custody handed back.
     *
     * custody's `signBitcoin` returns a FINALISED RAW TRANSACTION hex, not a PSBT, so this parses
     * a transaction. `getId()` is the txid — the double-SHA256 of the serialisation WITHOUT
     * witness data — and not the wtxid. That distinction is the whole of this method: the wtxid is
     * what `hash` would give, no explorer keys on it, and a status lookup by wtxid finds nothing.
     */
    txIdOf(rawTx) {
      try {
        return bitcoin.Transaction.fromHex(rawTx.startsWith('0x') ? rawTx.slice(2) : rawTx).getId()
      } catch {
        return null
      }
    },

    async broadcast(call, rawTx) {
      const hex = rawTx.startsWith('0x') ? rawTx.slice(2) : rawTx
      try {
        const txid = await call.rpc('sendrawtransaction', [hex])
        if (typeof txid !== 'string') {
          throw new AddressError('sendrawtransaction did not answer with a txid')
        }
        return txid
      } catch (err) {
        // Re-sending bytes already in the mempool or already mined must be a success, not a
        // failure: the broadcast step is retried after a crash and the second attempt is the
        // normal case, not the exception.
        const message = err instanceof Error ? err.message : String(err)
        if (/already in (block chain|mempool)|txn-already|-27\b/i.test(message)) {
          const derived = this.txIdOf(rawTx)
          if (derived) return derived
        }
        throw err
      }
    },

    async status(call, txHash) {
      return statusOf(call, txHash)
    },

    /**
     * Can these signed bytes still be mined?
     *
     * The EVM proof is about a nonce: a higher used nonce means the slot was taken. **Bitcoin has
     * no nonce, so that proof does not exist here** and inventing an analogue would be inventing
     * evidence. The Bitcoin proof is about the coins:
     *
     *   a transaction can only be mined while every outpoint it spends is unspent.
     *
     * So the question asked of the node is `gettxout` for each input, which reports the UTXO set
     * and nothing else. An input that is gone from the UTXO set has been spent by something, and
     * since these bytes are not that something (they are not on chain — checked first), they can
     * never be mined. That is a proof, not an inference.
     *
     * The failure direction is deliberate: `gettxout` returning an entry means the coin is still
     * spendable and the bytes are still live, so this REFUSES to refund. An absence of evidence
     * never refunds; only positive evidence of a conflicting spend does.
     */
    async proveDead(call, input: DeathInput): Promise<DeathVerdict> {
      const ids: string[] = []
      for (const id of [this.txIdOf(input.rawTx), input.txHash]) {
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
      }

      let tx: bitcoin.Transaction
      try {
        const hex = input.rawTx.startsWith('0x') ? input.rawTx.slice(2) : input.rawTx
        tx = bitcoin.Transaction.fromHex(hex)
      } catch {
        return {
          ok: false,
          code: 'unprovable',
          error:
            'the signed bytes on this row are not a transaction this service can parse, so there ' +
            'is no way to show which coins they spend and therefore no way to show they can never ' +
            'be mined. Nothing is refunded on an unread signature — an engineer has to look.',
        }
      }

      for (const vin of tx.ins) {
        // `hash` is stored internally in little-endian; the txid an RPC wants is the reverse.
        const txid = Buffer.from(vin.hash).reverse().toString('hex')
        // `true` includes the mempool, which matters: a conflicting spend that is only in the
        // mempool has NOT settled, and treating the coin as gone on that basis would refund a
        // payment that can still be mined if the conflict is dropped.
        const utxo = await call.rpc('gettxout', [txid, vin.index, false])
        if (utxo === null || utxo === undefined) {
          return {
            ok: true,
            proof:
              `no node has these bytes on chain and the coin they spend — ${txid}:${vin.index} — ` +
              'is no longer in the UTXO set at a confirmed depth, so a different transaction has ' +
              'spent it and these bytes can never be mined',
          }
        }
      }

      return {
        ok: false,
        code: 'still_applicable',
        error:
          'every coin these signed bytes spend is still unspent, so any node holding them can ' +
          'mine them at any time — a refund now can be followed by the payment landing. Retire ' +
          'them first by spending one of their inputs back to the treasury at a higher fee rate, ' +
          'and adjudicate this row once that confirms.',
      }
    },
  }
}

/**
 * The sweep PSBT: every output pays the pinned treasury, and there is only one output.
 *
 * **It was built before it could be signed, and it is wired up now.** custody's `signing.ts` used
 * to SPECIFY the output policy this satisfies — "EVERY output must pay the pinned BTC treasury for
 * the row's (chain, network), including any change output, since a sweep leaves nothing behind" —
 * and `purposeGate` refused a `deposit`-purpose bitcoin address until it had a caller. Both halves
 * have landed: `BitcoinPolicy` is built and `SWEEPABLE_FAMILIES` names `bitcoin`, so the adapter's
 * own `build` routes a `shape: 'sweep'` through the same `sweepPlan` this uses.
 *
 * **This function had no production caller until that happened, and that is the defect worth
 * recording.** `build` served both purposes, so a sweep went through the coin selector, which
 * exists to produce CHANGE — and a change output back to the deposit address is refused whole by
 * `assertSweepOutputs`. It only ever worked for an address holding exactly one coin, by accident:
 * with two or more, `selectCoins` could not cover a one-input-two-output fee out of a target that
 * had already had that fee subtracted, and threw. A tested exported function with no caller is
 * indistinguishable in a suite from one that works.
 *
 * It stays as a named entry point because a sweep is worth being able to build in isolation — an
 * operator reproducing one by hand, and the tests below — and because the shape it produces is the
 * whole of what custody's policy asks for, in six lines, where `build` states it among branches.
 */
export async function buildSweepPsbt(
  call: ChainCall,
  from: string,
  treasury: string,
  feeRatePerVb: bigint,
  minConfirmations: number,
  dustThreshold: bigint = DEFAULT_DUST,
): Promise<{ psbtBase64: string; value: bigint; fee: bigint } | null> {
  const net = networkFor(call.network)
  validateAddress(from, call.network)
  validateAddress(treasury, call.network)

  const plan = sweepPlan(await listUnspent(call, from, minConfirmations), feeRatePerVb, dustThreshold)
  if (plan === null) return null

  const psbt = new bitcoin.Psbt({ network: net })
  const script = bitcoin.address.toOutputScript(from, net)
  for (const utxo of plan.inputs) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script, value: Number(utxo.sats) },
      sighashType: bitcoin.Transaction.SIGHASH_ALL,
    })
  }
  psbt.addOutput({ address: treasury, value: Number(plan.value) })
  assertUnderCustodysCeiling(psbt, plan.fee, 'sweep')

  return { psbtBase64: psbt.toBase64(), value: plan.value, fee: plan.fee }
}
