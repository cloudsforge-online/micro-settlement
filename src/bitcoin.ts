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
 * The chains this one adapter serves. **Three chains, one implementation, and that is the hazard.**
 *
 * Litecoin's `ChainFamily` is `'bitcoin'` and genuinely is: it speaks the same JSON-RPC, has the
 * same transaction structure and the same script language, which is why `listunspent`, the coin
 * selector, the PSBT encoder, the broadcast and the UTXO-based death proof are all reused unchanged.
 * What it does NOT share is the network parameters — see the block below — so every function here
 * that used to close over Bitcoin's now takes the chain.
 *
 * ── DOGECOIN, AND WHAT IT COST TO ADMIT IT ─────────────────────────────────────────────────────
 *
 * This list said, until now, that `doge` was "deliberately not listed here" and that
 * `bitcoinChain('doge')` had to stay a compile error. **That was the right call and it is now
 * discharged rather than reversed**, because the two things it named have both been built:
 *
 *   * `encodePsbt` committed every input as a `witnessUtxo`, which is not a thing a base58 input
 *     can be signed as. It now chooses `witnessUtxo` or `nonWitnessUtxo` from the chain's ADDRESS
 *     KIND (see `ADDRESS_KIND`), which is the same choice custody makes from the same fact.
 *   * `vsizeOf` priced every input with the witness discount. It is now per-kind too: a P2PKH input
 *     is ~148 bytes with no discount, so the old number quoted a Dogecoin fee at well under half
 *     the transaction's real size — a signed payment that every node then drops below the relay
 *     floor. That is the failure that does NOT announce itself, and it is why the two were done
 *     together rather than one at a time.
 *
 * **NOTHING HERE MAY BE DERIVED FROM `ChainFamily`.** The extract is still written out chain by
 * chain, and the reason is stronger now than when it was a refusal: family membership says the RPC
 * and the transaction structure are Bitcoin's, and says nothing whatever about segwit. A fourth
 * bitcoin-family chain added to `contracts-chain` must still be a deliberate edit here, and must
 * still answer the address-kind question before it can be listed.
 */
export type BitcoinFamilyChainId = Extract<ChainId, 'btc' | 'ltc' | 'doge'>

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **LITECOIN'S NETWORK PARAMETERS. THESE ARE CUSTODY'S, RESTATED, AND THE RESTATEMENT IS PINNED.**
 *
 * `bitcoinjs-lib` ships `networks.bitcoin` and `networks.testnet` and nothing else, so an adapter
 * that resolves parameters from the FAMILY answers Bitcoin's for Litecoin. On this side of the
 * estate that produces two failures, and neither of them throws:
 *
 *   * `validateAddress` accepts a `bc1…` destination for an LTC withdrawal, and the coins go to a
 *     Litecoin output nobody holds the key to;
 *   * `encodePsbt` builds the PSBT under Bitcoin's parameters, so `toOutputScript` on a genuine
 *     `ltc1…` address throws and every Litecoin payment fails at build.
 *
 * Every value is from `litecoin-project/litecoin`, `src/chainparams.cpp`, and each is identical to
 * the table custody derives and signs under (`custody/src/chains.ts`, `LITECOIN_MAINNET`). They
 * MUST be identical: custody's `ECPair.fromWIF` binds the key to its own parameters, so a PSBT
 * built here under different ones is refused at signing — after the row is committed and this
 * chain's single outbound slot is claimed. `bitcoin.test.ts` asserts every field of both tables
 * against Litecoin Core's own published address vectors rather than against custody's copy.
 *
 * **`bip32` IS `xpub`/`xprv`, NOT SLIP-0132's `Ltub`/`Ltpv`.** Litecoin Core has used Bitcoin's
 * BIP-32 version bytes in every tag from v0.13.2; `Ltub` is a wallet DISPLAY convention. It makes
 * no difference to an address — these bytes appear only when an extended key is serialised, which
 * this service never does — and it is stated because the belief is common and would make any future
 * xpub export disagree with Core.
 *
 * **`scriptHash` IS 50, NOT 5.** Litecoin has two P2SH prefixes: `key_io.cpp` decodes both 5 (`3…`,
 * byte-identical to Bitcoin's) and 50 (`M…`) and encodes only 50. Carrying 50 here is what makes
 * `toOutputScript` refuse a Bitcoin `3…` address on the Litecoin path, and it is the same narrowing
 * `wallet/src/addresses.ts` makes for the same reason.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const LITECOIN_MAINNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bip32: { public: 0x0488b21e, private: 0x0488ade4 },
  /** `ltc1q…`. The HRP is inside the bech32 checksum, so it is a binding and not a label. */
  bech32: 'ltc',
  /** 48 → `L…`. */
  pubKeyHash: 0x30,
  /** 50 → `M…`, SCRIPT_ADDRESS2, the one Core encodes. */
  scriptHash: 0x32,
  /** 176 → a compressed WIF beginning `T`. Never used here; custody holds the keys. */
  wif: 0xb0,
})

const LITECOIN_TESTNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bip32: { public: 0x043587cf, private: 0x04358394 },
  /** `tltc1q…` — distinct from Bitcoin testnet's `tb1q…`. */
  bech32: 'tltc',
  /** 111. **THE SAME BYTE AS BITCOIN TESTNET'S**, which is a collision in the chains and not a
   * mistake here: a legacy `m…`/`n…` testnet address is byte-for-byte both. It does not exist on
   * mainnet, where 0 and 48 are disjoint. */
  pubKeyHash: 0x6f,
  /** 58 → SCRIPT_ADDRESS2. Core also decodes 196; this encodes and accepts 58 only. */
  scriptHash: 0x3a,
  wif: 0xef,
})

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **DOGECOIN'S NETWORK PARAMETERS. THERE IS NO BECH32 HRP AND THAT IS NOT A GAP IN THIS TABLE.**
 *
 * Every byte is from `dogecoin/dogecoin`, `src/chainparams.cpp`, read at `master` on 2026-08-09,
 * and every one is identical to the table custody derives and signs under (`custody/src/chains.ts`,
 * `DOGECOIN_MAINNET`). They MUST be identical for the reason the Litecoin block gives: custody's
 * `ECPair.fromWIF` binds the key to its own parameters, so a PSBT built here under different ones is
 * refused after the row is committed and this chain's single outbound slot is claimed.
 *
 * Mainnet sets PUBKEY_ADDRESS 30, SCRIPT_ADDRESS 22, SECRET_KEY 158; testnet sets 113, 196, 241.
 * **There is no `bech32_hrp` line in that file for any network** — SegWit exists only as a BIP-9
 * deployment whose timeout is 0, i.e. permanently off — so the field below is the empty string
 * because there is no value, not because one is outstanding.
 *
 * **THE EMPTY HRP IS NOT THE GUARD, AND BELIEVING IT WAS WOULD BE THE BUG.** `bitcoin.Network`
 * makes the field required, so the absence has to be spelled somehow, and an empty string is the
 * only spelling that cannot be mistaken for a real HRP. What it does NOT do is make segwit
 * unreachable: custody measured `payments.p2wpkh` with an empty HRP returning a well-formed-looking
 * string that is an address on no chain, and `bitcoin.address.fromBech32` decodes any HRP at all
 * before anybody compares it to this. So the segwit refusals on this side are explicit —
 * `ADDRESS_KIND` selects the input field and `validateAddress` refuses a bech32 destination by
 * decoding it and saying so — and neither of them reads this field.
 *
 * TWO DIFFERENCES FROM THE LITECOIN BLOCK, both checked rather than carried over:
 *
 *  1. **The BIP-32 version bytes are Dogecoin's own**, `0x02facafd` / `0x02fac398` (`dgub`/`dgpv`),
 *     where Litecoin Core uses Bitcoin's and the distinct `Ltub` pair is only SLIP-0132's display
 *     convention. Here Core itself carries the distinct bytes. As with Litecoin they never appear in
 *     a derived address and this service never serialises an extended key.
 *  2. **There is no SCRIPT_ADDRESS2.** Litecoin has two P2SH prefixes and this chain has one, so
 *     the narrowing argument that makes `scriptHash: 0x32` load-bearing on Litecoin has no
 *     counterpart here.
 *
 * Testnet reuses Bitcoin's `tpub`/`tprv` bytes, which is what the file says — a real collision, not
 * a transcription error, and recorded as read.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const DOGECOIN_MAINNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Dogecoin Signed Message:\n',
  bip32: { public: 0x02facafd, private: 0x02fac398 },
  /** No segwit, therefore no HRP. See the block above for why this is not the refusal. */
  bech32: '',
  /** 30 → `D…`. The only address kind Dogecoin has. */
  pubKeyHash: 0x1e,
  /** 22 → `9…`/`A…`. Recorded for completeness; nothing here creates a P2SH output. */
  scriptHash: 0x16,
  /** 158 → a compressed WIF beginning `Q`. Never used here; custody holds the keys. */
  wif: 0x9e,
})

const DOGECOIN_TESTNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Dogecoin Signed Message:\n',
  bip32: { public: 0x043587cf, private: 0x04358394 },
  bech32: '',
  /** 113 → `n…`. */
  pubKeyHash: 0x71,
  /** 196 → `2…`. **THE SAME BYTE AS BITCOIN TESTNET'S AND AS LITECOIN TESTNET'S DECODE VALUE**,
   * which is a collision in the chains rather than a mistake here. It does not exist on mainnet,
   * where 5, 50 and 22 are disjoint. */
  scriptHash: 0xc4,
  wif: 0xf1,
})

const NETWORKS: Readonly<
  Record<BitcoinFamilyChainId, Readonly<Record<Network, bitcoin.Network>>>
> = Object.freeze({
  btc: Object.freeze({ mainnet: bitcoin.networks.bitcoin, testnet: bitcoin.networks.testnet }),
  ltc: Object.freeze({ mainnet: LITECOIN_MAINNET, testnet: LITECOIN_TESTNET }),
  doge: Object.freeze({ mainnet: DOGECOIN_MAINNET, testnet: DOGECOIN_TESTNET }),
})

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE ADDRESS KIND IS THE CHAIN'S, AND IT IS THE SINGLE FACT EVERY DOGECOIN DIFFERENCE FOLLOWS
 * FROM.**
 *
 * It decides four things, and they used to be four independent hard-coded assumptions scattered
 * through this file:
 *
 *   * which field a PSBT input carries — `witnessUtxo` for P2WPKH, `nonWitnessUtxo` for P2PKH;
 *   * how big an input and an output are, and therefore what a fee rate multiplies (`vsizeOf`);
 *   * what the smallest transaction custody could finalise looks like (`finalisedVsize`);
 *   * whether a bech32 destination can be paid at all (`validateAddress`).
 *
 * **IT IS NOT DERIVABLE FROM THE FAMILY AND IT IS NOT DERIVABLE FROM `bech32` BEING BLANK.** The
 * family is `'bitcoin'` for all three chains. The blank HRP is an artefact of `bitcoin.Network`
 * requiring the field; nothing in bitcoinjs treats it as a refusal. So it is stated once, here, and
 * every one of the four reads it — which is the same shape custody arrived at from the other side
 * (`custody/src/chains.ts`, `bitcoinAddressKind`), for the same reason: when the choice was made
 * three times independently, adding a chain meant remembering three edits and forgetting one meant
 * a transaction that is built one way and priced another.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export type BitcoinAddressKind = 'p2wpkh' | 'p2pkh'

const ADDRESS_KIND: Readonly<Record<BitcoinFamilyChainId, BitcoinAddressKind>> = Object.freeze({
  btc: 'p2wpkh',
  ltc: 'p2wpkh',
  // Not a legacy PREFERENCE. Dogecoin never activated segwit, so this is the only kind it has.
  doge: 'p2pkh',
})

/** The address kind this chain's treasury and deposit addresses are. @see ADDRESS_KIND */
export function addressKindFor(chain: BitcoinFamilyChainId): BitcoinAddressKind {
  const kind = ADDRESS_KIND[chain]
  if (!kind) {
    // The same refusal `networkFor` makes and for the same reason: a default would be `p2wpkh`,
    // which is precisely the wrong answer for the next chain that has no segwit.
    throw new AddressError(
      `no address kind is defined for '${chain}' — refusing to assume segwit, which would price ` +
        "every input at a discount the chain does not give and commit it in a field it cannot sign",
    )
  }
  return kind
}

/**
 * The bitcoinjs network for a (chain, network).
 *
 * The estate's `testnet` is each chain's own `testnet`. Bitcoin's testnet parameters also cover
 * signet and regtest for address-encoding purposes — they share version bytes — so an operator
 * pointing at any of the three gets consistent behaviour. What matters is that mainnet and
 * not-mainnet never mix, and they cannot: the version bytes differ, so a mainnet address simply
 * fails to decode against the testnet network and vice versa. That is the same binding custody
 * enforces from the other side, where `ECPair.fromWIF` throws when the WIF's network byte
 * disagrees.
 *
 * **IT THROWS FOR A CHAIN WITH NO ENTRY RATHER THAN DEFAULTING TO BITCOIN'S.** A default here is
 * the exact defect this table exists to close, one chain later: the next Bitcoin-derived chain
 * would silently accept and build Bitcoin addresses under its own name, every test would stay
 * green, and the first evidence would be a customer's missing coins.
 */
export function networkFor(chain: BitcoinFamilyChainId, network: Network): bitcoin.Network {
  const params = NETWORKS[chain]
  if (!params) {
    throw new AddressError(
      `no bitcoin-family network parameters are defined for '${chain}' — refusing to encode with ` +
        "another chain's, which would be a valid address on the wrong chain",
    )
  }
  return params[network]
}

/* ------------------------------------------------------------------ amounts and sizes */

/** Smallest units per coin. Both chains are 8 decimals; `contracts-chain` is the authority. */
const SATS_PER_BTC = 100_000_000n

/**
 * The `MAX_MONEY` of each chain, in smallest units. **LITECOIN'S IS FOUR TIMES BITCOIN'S AND
 * DOGECOIN'S IS FOUR HUNDRED AND SEVENTY-SIX TIMES LITECOIN'S.**
 *
 * `MAX_MONEY` is `21000000 * COIN` in `bitcoin/src/consensus/amount.h` and `84000000 * COIN` in
 * `litecoin/src/consensus/amount.h`. Reusing Bitcoin's for Litecoin would refuse a genuine node
 * answer as malformed; reusing Litecoin's for Bitcoin would accept an impossible one as real. It is
 * a sanity bound on a number that arrived over JSON, and a sanity bound calibrated to the wrong
 * chain is not one.
 *
 * **DOGECOIN'S IS NOT A SUPPLY CAP AND CALLING IT ONE WOULD BE WRONG IN BOTH DIRECTIONS.**
 * `dogecoin/dogecoin`, `src/amount.h`, read at `master` on 2026-08-09, sets
 * `MAX_MONEY = 10000000000 * COIN` with the comment "maximum of 100B coins (given some randomness),
 * max transaction 10,000,000,000". Dogecoin has no cap — it emits 10,000 DOGE per block for ever —
 * so this number is BELOW the eventual supply and ABOVE any transaction Core will accept, which is
 * exactly what it is for: a per-amount consensus bound, which is the only thing this constant was
 * ever used as. The variable is named for the role rather than for the folklore.
 */
const MAX_UNITS: Readonly<Record<BitcoinFamilyChainId, bigint>> = Object.freeze({
  btc: 2_100_000_000_000_000n,
  ltc: 8_400_000_000_000_000n,
  doge: 1_000_000_000_000_000_000n,
})

/**
 * The largest amount `bitcoinjs-lib` can put in a transaction output.
 *
 * **THIS BITES ON DOGECOIN AND ON NEITHER OF THE OTHER TWO, WHICH IS WHY IT IS CHECKED HERE RATHER
 * THAN TRUSTED TO THE LIBRARY.** `Psbt.addOutput` takes a JavaScript `number`, and
 * `bufferutils.verifuint` refuses anything above `0x1fffffffffffff` with a bare
 * `Error('RangeError: value out of range')` — no chain, no amount, no indication that the value was
 * the problem. Bitcoin's whole `MAX_MONEY` is 2.1e15 and Litecoin's is 8.4e15, both under that
 * ceiling, so on those two chains the branch is unreachable by construction. Dogecoin's is 1e18, and
 * ~90.07 million DOGE in one output is a treasury balance rather than an impossibility.
 *
 * Refused as an `AddressError` so it is a classified build failure that releases the row, instead of
 * a bare `Error` surfacing from inside the encoder with nothing an operator can act on. The fix for
 * an operator who meets it is to split the payment, and the message says so.
 */
const MAX_ENCODABLE_UNITS = 9_007_199_254_740_991n

/** Retained for the existing Bitcoin call sites and tests. @see MAX_UNITS */
export const MAX_SATOSHIS = MAX_UNITS.btc

/**
 * A coin amount as Core serialises it → smallest units.
 *
 * The same argument as the indexer's `btcToSats`, and it has to be made again here because this is
 * a different service: Core reports amounts as JSON numbers, so the decimal has been through an
 * IEEE-754 double before this code runs. `Math.round` therefore has to RECOVER an exact multiple of
 * one smallest unit rather than merely approach it, and whether it can is a property of the
 * magnitude:
 *
 *   * A double's ULP at 21e6 is about 3.7e-9. Scaled by 1e8 that is 0.37, so the representation
 *     error is under half a unit everywhere in Bitcoin's range and `Math.round` is exact. That is
 *     the argument the original comment made and it is still correct **for Bitcoin**.
 *   * **It does not extend to Litecoin's whole range, and it is worth saying so rather than
 *     re-using the sentence.** The error stays under half a unit only while the ULP is under 1e-8,
 *     which holds up to 2^25.4 ≈ 44.7e6 coins. Above that — between roughly 44.7 and 84 million
 *     LTC in ONE output — a returned amount could round to a neighbouring litoshi.
 *
 * That residue is left rather than engineered away, and deliberately: a single UTXO holding 45
 * million LTC is over half the coins that will ever exist, `listunspent` is asked only about this
 * estate's own treasury and deposit addresses, and the alternative — refusing amounts above 44.7e6
 * — would turn an impossible input into an outage on the day somebody tested it. `bitcoin.test.ts`
 * pins the boundary so it is a known limit rather than a surprise.
 */
export function btcToSats(value: unknown, chain: BitcoinFamilyChainId = 'btc'): bigint {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new AddressError(`a ${chain} amount was expected and ${String(value)} arrived`)
  }
  if (value < 0) throw new AddressError(`a ${chain} amount may not be negative: ${value}`)
  const sats = BigInt(Math.round(value * 1e8))
  const cap = MAX_UNITS[chain]
  if (sats > cap) {
    throw new AddressError(`${value} exceeds the ${chain.toUpperCase()} supply cap`)
  }
  return sats
}

/** Smallest units → the coin-denominated number Core expects in a parameter. */
export function satsToBtc(sats: bigint): number {
  return Number(sats) / Number(SATS_PER_BTC)
}

/**
 * The virtual size, in vbytes, of a spend with `inputs` inputs and `outputs` outputs.
 *
 * Every input this service spends is of the treasury address's own kind — custody refuses anything
 * else — so the size is exact rather than estimated, and being exact is what lets the fee be
 * checked against the locked quote instead of hoped about.
 *
 * **P2WPKH** (`btc`, `ltc`):
 *
 *   base: 4 version + 1 segwit marker/flag counted in weight + varint counts + 4 locktime
 *   per input: 32 txid + 4 vout + 1 empty scriptSig + 4 sequence = 41 vbytes of base,
 *              plus a 108-weight-unit witness (1 item count + 1+72 sig + 1+33 pubkey) = 27 vbytes
 *   per output: 8 value + 1 script length + 22 script (OP_0 <20-byte hash>) = 31 vbytes
 *
 * **P2PKH** (`doge`). **THIS IS THE NUMBER THAT MAKES DOGECOIN SAFE TO QUOTE, AND THE OLD ONE WAS
 * NOT MERELY IMPRECISE.** There is no witness, so there is no marker, no flag and no discount:
 *
 *   base: 4 version + varint counts + 4 locktime = 10 bytes — one less than segwit's 10.5,
 *         because the marker and flag are simply absent rather than discounted
 *   per input: 32 txid + 4 vout + 1 script length + 107 scriptSig (1+72 DER sig with its sighash
 *              byte, 1+33 compressed pubkey) + 4 sequence = 148 bytes, all of them charged
 *   per output: 8 value + 1 script length + 25 script (DUP HASH160 <20> EQUALVERIFY CHECKSIG)
 *              = 34 bytes
 *
 * 148 against 68 is why this could not stay one function with one table. A one-input two-output
 * Dogecoin spend is 226 bytes and the segwit arithmetic calls it 141 — so a fee quoted the old way
 * pays 62% of what the transaction needs, and the result is not a rejected build. It is a SIGNED
 * transaction that every node drops for paying under the relay floor, with this chain's single
 * outbound slot claimed and a user waiting on it.
 *
 * Rounded up, because a fractional vbyte is charged as a whole one.
 */
const SIZES: Readonly<
  Record<BitcoinAddressKind, { readonly base: number; readonly input: number; readonly output: number }>
> = Object.freeze({
  p2wpkh: Object.freeze({ base: 10.5, input: 68, output: 31 }),
  p2pkh: Object.freeze({ base: 10, input: 148, output: 34 }),
})

export function vsizeOf(
  inputs: number,
  outputs: number,
  /**
   * Defaulted to `btc` so the Bitcoin call sites and the vectors in `bitcoin.test.ts` read as they
   * did. It is NOT defaulted where it matters: `bitcoinChain` closes over its own chain and passes
   * it at every call, so a new chain cannot pick up Bitcoin's sizes by omission.
   */
  chain: BitcoinFamilyChainId = 'btc',
): number {
  const size = SIZES[addressKindFor(chain)]
  return Math.ceil(size.base + inputs * size.input + outputs * size.output)
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
export function validateAddress(
  chain: BitcoinFamilyChainId,
  address: string,
  network: Network,
): string {
  const trimmed = address.trim()
  if (trimmed.length === 0) throw new AddressError(`a ${chain} address may not be empty`)
  /*
   * ════════════════════════════════════════════════════════════════════════════════════════════
   * **A BECH32 DESTINATION ON A CHAIN WITH NO SEGWIT, REFUSED BY DECODING IT AND SAYING SO.**
   *
   * `toOutputScript` below would refuse a `bc1…` for Dogecoin as well, because `fromBech32`
   * compares the decoded HRP against `network.bech32` and Dogecoin's is the empty string. That
   * refusal is an ACCIDENT of how the absence had to be spelled, and it is the wrong thing to rely
   * on twice over: it produces the generic "not a valid doge address" message, which sends an
   * operator looking for a typo; and it would evaporate the day anybody wrote a plausible-looking
   * HRP into that field to make some other library happy.
   *
   * So the refusal is explicit and it is the chain's ADDRESS KIND that drives it, not the blank
   * field. A Dogecoin address is base58 and there is no second form — no segwit, therefore no
   * bech32, therefore no `doge1…` to add later.
   *
   * **THE MIRROR IMAGE IS THE BUG THIS MUST NOT REINTRODUCE.** A `bc1…` accepted for a Litecoin
   * withdrawal is what the Litecoin network table exists to prevent, and it is prevented by the
   * HRP being inside the bech32 checksum: `ltc` and `bc` decode to different scripts and neither
   * validates against the other's parameters. Nothing here weakens that — this branch is reached
   * only for a chain whose kind is `p2pkh`, and both segwit chains fall straight through to
   * `toOutputScript` exactly as before. `bitcoin.test.ts` asserts both halves.
   * ════════════════════════════════════════════════════════════════════════════════════════════
   */
  if (addressKindFor(chain) === 'p2pkh' && isBech32(trimmed)) {
    throw new AddressError(
      `${trimmed} is a bech32 (segwit) address and ${chain} has no segwit — its addresses are ` +
        'base58 only, so this is not a typo to be corrected but a destination that does not exist ' +
        'on this chain. Paying it would create an output nobody can spend.',
    )
  }
  try {
    bitcoin.address.toOutputScript(trimmed, networkFor(chain, network))
  } catch {
    throw new AddressError(
      `${trimmed} is not a valid ${chain} ${network} address — note that a mainnet address is ` +
        'rejected on testnet and the reverse, and that a Bitcoin address is rejected on Litecoin ' +
        'and the reverse. Both are the binding that stops a payment being broadcastable, or ' +
        'unspendable, on a chain it was not meant for',
    )
  }
  return trimmed
}

/**
 * Is this string a bech32 or bech32m address of ANY human-readable part?
 *
 * The HRP is deliberately not compared against anything. The question this answers is "is this the
 * segwit form at all", asked of a chain that has no segwit form, so `bc1…`, `ltc1…`, `tb1…` and a
 * hypothetical `doge1…` are all equally the wrong shape and must all be named as such.
 *
 * `fromBech32` covers bech32m as well, which is checked rather than assumed: it tries the bech32
 * constant first, falls through to the bech32m one, and rejects the version/encoding pairs that do
 * not go together (`bitcoinjs-lib`, `src/address.js`). So one call answers for witness version 0 and
 * for taproot alike, and a `doge` destination in either form is named for what it is.
 */
function isBech32(address: string): boolean {
  try {
    bitcoin.address.fromBech32(address)
    return true
  } catch {
    return false
  }
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
  /**
   * Names the chain in an operator's `failure_reason` — **and sizes every input**, which it did
   * not do when this parameter was added. A Dogecoin input is more than twice a Litecoin one, so
   * on this chain the argument is the difference between a fee and a rejected broadcast.
   */
  chain: BitcoinFamilyChainId = 'btc',
): Selection {
  const chosen: Utxo[] = []
  let total = 0n
  for (const utxo of utxos) {
    chosen.push(utxo)
    total += utxo.sats

    // Two outputs: the payment and the change.
    const withChange = feeRatePerVb * BigInt(vsizeOf(chosen.length, 2, chain))
    if (total >= target + withChange) {
      const change = total - target - withChange
      if (change >= dustThreshold) {
        return { inputs: chosen, change, fee: withChange }
      }
      // Change would be dust. Drop the output and let the difference go to the fee, which is
      // cheaper for everyone than an output nobody can afford to spend.
      const withoutChange = feeRatePerVb * BigInt(vsizeOf(chosen.length, 1, chain))
      if (total >= target + withoutChange) {
        return { inputs: chosen, change: 0n, fee: total - target }
      }
      continue
    }

    // The exact-payment case: no change at all, one output.
    const withoutChange = feeRatePerVb * BigInt(vsizeOf(chosen.length, 1, chain))
    if (total >= target + withoutChange && total - target - withoutChange < dustThreshold) {
      return { inputs: chosen, change: 0n, fee: total - target }
    }
  }
  throw new InsufficientTreasuryError(chain, total, target)
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
  /** Sizes the inputs. @see vsizeOf — a P2PKH input is 148 bytes against P2WPKH's 68. */
  chain: BitcoinFamilyChainId = 'btc',
): SweepPlan | null {
  if (utxos.length === 0) return null
  const total = totalOf(utxos)
  const fee = feeRatePerVb * BigInt(vsizeOf(utxos.length, 1, chain))
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
 *
 * **THE SAME SIGNATURE GOES IN A DIFFERENT PLACE ON A LEGACY INPUT**, so the kind is read here too.
 * A P2PKH spend has no witness at all and carries `<sig> <pubkey>` in the scriptSig, which is
 * 1 + 71 + 1 + 33 = 106 bytes of transaction that gets no discount. Setting a witness on a legacy
 * input would not merely mis-measure it — it would make the transaction serialise in the segwit
 * format, and `virtualSize` would then divide a witness Dogecoin cannot have by four.
 */
export function finalisedVsize(psbt: bitcoin.Psbt, chain: BitcoinFamilyChainId = 'btc'): number {
  const tx = new bitcoin.Transaction()
  const kind = addressKindFor(chain)
  psbt.txInputs.forEach((input, i) => {
    if (kind === 'p2wpkh') {
      tx.addInput(input.hash, input.index, input.sequence)
      tx.setWitness(i, [Buffer.alloc(71, 1), Buffer.alloc(33, 2)])
    } else {
      // `<push 71><71-byte sig><push 33><33-byte pubkey>`, built as script rather than as a raw
      // buffer so the push opcodes are the ones a real scriptSig would carry.
      tx.addInput(
        input.hash,
        input.index,
        input.sequence,
        bitcoin.script.compile([Buffer.alloc(71, 1), Buffer.alloc(33, 2)]),
      )
    }
  })
  for (const output of psbt.txOutputs) tx.addOutput(output.script, output.value)
  return tx.virtualSize()
}

/**
 * Refuse a PSBT custody's own ceiling would refuse. See the ceiling block below.
 *
 * The comparison is `>=` and the divisor is the finalised size, because that is character for
 * character what `signBitcoin` does: `psbt.getFeeRate()` is `Math.floor(fee / virtualSize)` and it
 * refuses at `feeRate >= ceiling` (custody/src/signing.ts). Reproducing the comparison rather
 * than approximating it is the point — an approximation is a second policy, and the one thing that
 * must not happen here is this service believing a PSBT acceptable that custody will not sign.
 */
export function assertUnderCustodysCeiling(
  psbt: bitcoin.Psbt,
  fee: bigint,
  shape: OutboundShape,
  /**
   * The chain, and it now selects the CEILING as well as naming it in the refusal.
   *
   * **THIS PARAMETER'S DOCUMENTATION USED TO SAY THE OPPOSITE, AND THE SENTENCE WAS TRUE WHEN IT
   * WAS WRITTEN.** It read: "the CEILINGS are deliberately not per-chain, because custody's are
   * not: `signBitcoin` reads one pair of constants whatever the row's chain". That was a correct
   * reading of custody at the time and it stopped being correct on 2026-08-09, when custody made
   * its own pair a per-chain table for Dogecoin's sake (`custody/src/signing.ts`,
   * `FEE_RATE_CEILINGS`). Left alone it would not have failed loudly — it would have refused every
   * Dogecoin sweep, for ever, at build time. See the ceiling block below.
   */
  chain: BitcoinFamilyChainId = 'btc',
): void {
  const ceilings = CUSTODY_CEILINGS[chain]
  const ceiling = shape === 'sweep' ? ceilings.sweep : ceilings.payment
  const vsize = BigInt(finalisedVsize(psbt, chain))
  if (fee / vsize >= ceiling) {
    throw new FeeOutOfBandError(chain, 'above', fee, ceiling * vsize)
  }
}

/* ------------------------------------------------------------------ the encoder */

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE ONE PSBT ENCODER, AND THE ONE PLACE `witnessUtxo` AND `nonWitnessUtxo` ARE CHOSEN BETWEEN.**
 *
 * Shared by the withdrawal path and the sweep path, because the two differ only in WHICH coins and
 * WHICH outputs — and sharing the construction is what stops the sweep drifting away from the
 * encoding custody has already validated a withdrawal against. It used to be shared in intent and
 * duplicated in fact: `buildSweepPsbt` carried its own `addInput` loop, so the field choice existed
 * twice and would have had to be made correctly twice.
 *
 * ── WHY THE CHOICE IS A LOOKUP AND NOT A DEFAULT ───────────────────────────────────────────────
 *
 *   * **P2WPKH → `witnessUtxo`.** A segwit signature COMMITS TO THE VALUE of the input it spends,
 *     and only this field carries it. That is the whole reason custody takes a PSBT rather than a
 *     raw transaction, and its `witnessPrevOut` refuses an input without one — "its value is
 *     unknown".
 *   * **P2PKH → `nonWitnessUtxo`, the whole previous transaction.** A pre-segwit signature does not
 *     commit to the value, so there is no field to put one in: the only way to know what an input
 *     is worth and whose script it pays is to be handed the transaction that created it. bitcoinjs
 *     enforces this and custody's `legacyPrevOut` checks the supplied transaction really is the one
 *     the outpoint names before it believes anything else about the input.
 *
 * **THE WRONG FIELD DOES NOT THROW WHERE ANYONE WOULD SEE IT.** custody measured this against the
 * pinned bitcoinjs on 2026-08-09: a P2PKH input given only a `witnessUtxo` is silently SKIPPED by
 * `signAllInputs`, which then throws `No inputs were signed` — a bare Error naming neither the input
 * nor the reason, arriving at custody's route as a 500 with no audit row. So the field is selected
 * from `ADDRESS_KIND` at the single site that builds an input, and the chain that has no segwit
 * cannot reach the segwit branch at all.
 *
 * ── THE COST OF THE LEGACY BRANCH, WHICH IS A ROUND TRIP PER DISTINCT FUNDING TRANSACTION ───────
 *
 * `listunspent` does not return raw transactions, so each one is fetched. It is cached per call
 * because a treasury paid by one transaction into several outputs is ordinary — three coins from
 * one funding transaction is one `getrawtransaction`, not three.
 *
 * `getrawtransaction` without `txindex` answers for a WALLET transaction, and every input here is
 * one by construction: `listunspent` is filtered to an address, which only returns coins the node's
 * own wallet watches. An operator running a pruned node with no wallet import would fail at this
 * call rather than silently building something unsignable, which is the right end of that trade.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export async function encodePsbt(
  call: ChainCall,
  chain: BitcoinFamilyChainId,
  from: string,
  inputs: readonly Utxo[],
  outputs: readonly { address: string; sats: bigint }[],
): Promise<bitcoin.Psbt> {
  const net = networkFor(chain, call.network)
  const kind = addressKindFor(chain)
  const psbt = new bitcoin.Psbt({ network: net })
  const script = bitcoin.address.toOutputScript(from, net)
  const rawByTxid = new Map<string, Buffer>()

  for (const utxo of inputs) {
    const common = {
      hash: utxo.txid,
      index: utxo.vout,
      // SIGHASH_ALL only. Anything else leaves part of the transaction editable after signing, and
      // custody refuses it, so stating it here means a mismatch fails at build rather than at the
      // signing request.
      sighashType: bitcoin.Transaction.SIGHASH_ALL,
    }
    if (kind === 'p2wpkh') {
      psbt.addInput({ ...common, witnessUtxo: { script, value: encodableValue(chain, utxo.sats) } })
    } else {
      psbt.addInput({ ...common, nonWitnessUtxo: await previousTransaction(call, utxo.txid, rawByTxid) })
    }
  }
  for (const output of outputs) {
    psbt.addOutput({ address: output.address, value: encodableValue(chain, output.sats) })
  }
  return psbt
}

/** The raw bytes of a funding transaction, fetched once per txid per PSBT. @see encodePsbt */
async function previousTransaction(
  call: ChainCall,
  txid: string,
  cache: Map<string, Buffer>,
): Promise<Buffer> {
  const held = cache.get(txid)
  if (held) return held
  // `false` is the default and is stated: the verbose form answers an object, and this needs the
  // bytes. `statusOf` asks the same method the other way for the opposite reason.
  const hex = await call.rpc('getrawtransaction', [txid, false])
  if (typeof hex !== 'string' || hex.length === 0) {
    throw new AddressError(
      `getrawtransaction did not answer with the bytes of ${txid} — a legacy input cannot be ` +
        'signed without the whole transaction it spends, so this is refused rather than built ' +
        'into a PSBT that custody would have to reject',
    )
  }
  const raw = Buffer.from(hex, 'hex')
  cache.set(txid, raw)
  return raw
}

/** An amount as a `number`, or a named refusal. @see MAX_ENCODABLE_UNITS */
function encodableValue(chain: BitcoinFamilyChainId, units: bigint): number {
  if (units > MAX_ENCODABLE_UNITS) {
    throw new AddressError(
      `${units} is more of ${chain} than a transaction output can carry through this encoder ` +
        `(${MAX_ENCODABLE_UNITS} smallest units) — split the payment`,
    )
  }
  return Number(units)
}

/* ------------------------------------------------------------------ the adapter */

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **DUST IS TEN TIMES HIGHER ON LITECOIN, AND THIS IS THE ONE CONSTANT WHERE REUSING BITCOIN'S
 * NUMBER PRODUCES A TRANSACTION NO NODE WILL RELAY.**
 *
 * Core derives the dust threshold of an output from `DUST_RELAY_TX_FEE` and the size of the output
 * plus the input that would one day spend it (`policy.cpp`, `GetDustThreshold`). The fee rate is
 * where the two chains part:
 *
 *     bitcoin/src/policy/policy.h    DUST_RELAY_TX_FEE = 3'000
 *     litecoin/src/policy/policy.h   DUST_RELAY_TX_FEE = 30'000
 *
 * Ten times, because a litoshi is worth a small fraction of a satoshi and the threshold exists to
 * stop outputs that cost more to spend than they hold. The sizes are identical — same serialisation
 * — so the thresholds are simply ten times apart: a P2PKH output is dust below 546 satoshis and
 * below 5,460 litoshi, and a P2WPKH output below 294 and 2,940 respectively.
 *
 * **Using 546 for Litecoin is not conservative, it is wrong in the dangerous direction.** It sits
 * BELOW Litecoin's real threshold, so the coin selector would happily create a 1,000-litoshi change
 * output, and `sendrawtransaction` would answer `dust` — a whole withdrawal refused at broadcast,
 * after signing, with this chain's single outbound slot claimed and the user's money reserved.
 * Every other constant in this file survives the copy from Bitcoin. This one does not, and it is
 * the reason the dust threshold is a per-chain table rather than one number with a comment.
 *
 * The P2PKH figure is used for both segwit chains rather than the P2WPKH one, unchanged from
 * before: every output this service creates on them is P2WPKH, so the higher number is a deliberate
 * margin, and a margin on dust costs a few satoshis of miner fee where being under costs the
 * transaction.
 *
 * **DOGECOIN'S IS NOT DERIVED FROM A SIZE AT ALL, AND THE DIFFERENCE IS A DIFFERENT ALGORITHM AND
 * NOT A DIFFERENT NUMBER.** Read at `master` on 2026-08-09: `dogecoin/dogecoin`,
 * `src/primitives/transaction.h`, defines `IsDust(dustLimit)` as `nValue < dustLimit` — a flat
 * comparison, where Bitcoin and Litecoin scale `DUST_RELAY_TX_FEE` by the size of the output plus
 * the input that would one day spend it. So there is no P2PKH-versus-P2WPKH choice to make here;
 * there is one number, and `src/policy/policy.h` gives it as
 * `DEFAULT_DUST_LIMIT = RECOMMENDED_MIN_TX_FEE` = `COIN / 100` = **1,000,000 koinu** (0.01 DOGE).
 *
 * **THE SOFT LIMIT IS TAKEN AND NOT THE HARD ONE, DELIBERATELY.** The same file sets
 * `DEFAULT_HARD_DUST_LIMIT = DEFAULT_DUST_LIMIT / 10` (100,000 koinu), and `policy.cpp` refuses a
 * transaction as non-standard — `reason = "dust"` — only below the HARD limit. Between the two, an
 * output is relayable but obliges the transaction to pay extra fee for the privilege. Taking the
 * soft limit therefore keeps this service's changes and sweeps out of the band where a node's
 * answer depends on its own `-dustlimit` setting, at a cost of at most 0.009 DOGE of change handed
 * to a miner. Taking the hard one would buy nothing and would put every marginal output at the
 * mercy of an operator's node configuration.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const DEFAULT_DUST: Readonly<Record<BitcoinFamilyChainId, bigint>> = Object.freeze({
  btc: 546n,
  ltc: 5_460n,
  doge: 1_000_000n,
})

/**
 * Core's own relay floor, in smallest units per vbyte. Below it a transaction is not forwarded.
 *
 * **BITCOIN AND LITECOIN AGREE AND DOGECOIN IS A HUNDRED TIMES HIGHER**, and every one of the three
 * was read rather than inferred from the others. `DEFAULT_MIN_RELAY_TX_FEE` is 1000 per kilo-vbyte
 * in `bitcoin/src/validation.h` and 1000 in `litecoin/src/validation.h` — the two agree here even
 * though they differ by a factor of ten on dust, which is exactly why neither was taken on trust.
 * `dogecoin/dogecoin`, `src/validation.h`, read at `master` on 2026-08-09, instead says
 * `DEFAULT_MIN_RELAY_TX_FEE = RECOMMENDED_MIN_TX_FEE / 10` — `COIN / 1000`, i.e. 100,000 koinu per
 * kilo-vbyte, **100 koinu/vB**.
 *
 * **THIS IS A FLOOR AND ITS ONLY USE IS TO REPLACE A MISSING ESTIMATE**, which is what makes the
 * hundredfold difference matter rather than merely be true. `feeRate` falls back to it whenever the
 * node says it has no estimate, and a Dogecoin transaction built at 1 koinu/vB would be a signed
 * transaction no node forwards. The failure would look exactly like a stuck mempool and would be
 * permanent, because a policy floor does not fall the way a fee market does.
 *
 * **ON THIS ESTATE THE FALLBACK IS NOT A FALLBACK, IT IS THE ONLY PATH.** This sentence used to
 * read "the ordinary state of a fresh node and of testnet", which describes something a node grows
 * out of. Nothing here grows out of it. See `NO_ESTIMATE_RPC_MESSAGE` below.
 */
const MIN_RELAY_PER_VB: Readonly<Record<BitcoinFamilyChainId, bigint>> = Object.freeze({
  btc: 1n,
  ltc: 1n,
  doge: 100n,
})
/** How many blocks `estimatesmartfee` is asked to target. */
const FEE_TARGET_BLOCKS = 3

/**
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 * **THE FLOOR IS THIS DEPLOYMENT'S FEE SOURCE, PERMANENTLY AND BY DEPLOYMENT CHOICE. IT IS NOT A
 * DEGRADED MODE AND NOTHING IS WAITING FOR IT TO END.**
 *
 * The note this block replaces — and its twin in `deploy/compose/docker-compose.estate.yml`, above
 * `x-wallet-fee-quotes` — deferred a decision "once `estimatesmartfee` answers". It cannot answer,
 * and the reason is a line in the node's own configuration rather than anything about the chain.
 *
 * ── WHAT WAS MEASURED, ON THE MAINNET ESTATE HOST, 2026-08-09 ───────────────────────────────────
 *
 *     /data/chains/litecoin/litecoin.conf   blocksonly=1  txindex=1  prune=0  par=3
 *     getblockchaininfo    blocks 3156788, initialblockdownload FALSE, 10 peers, up 15h
 *     getmempoolinfo       size 0, bytes 0, mempoolminfee 0.00001
 *     estimatesmartfee 2|3|6|12|24|144
 *                          {"errors":["Insufficient data or no feerate found"],"blocks":0}
 *
 * **"The node is still syncing" is not available as an explanation.** It is at the tip.
 *
 * `blocksonly=1` means the node accepts no loose transactions from peers, so its mempool is empty
 * by construction. Core's estimator learns only by watching a transaction ENTER the mempool and
 * later confirm, so a node with no mempool entries has nothing to learn from and never will. The
 * chain is not quiet — the same 144 blocks carried 30,169 transactions.
 *
 * ── THE REAL CONDITION FOR REVISITING IS `blocksonly=0`, AND IT IS A DEPLOY DECISION ────────────
 *
 * Not a release, not a sync, not a busier chain. Somebody removes `blocksonly` from
 * `litecoin.conf` and restarts the node, and then the estimator needs hours of mempool history
 * before it answers at all. **This repository does not make that change and should not**: relay is
 * the expensive half of running a node, and this box runs three chains beside sixty containers
 * with `par=3` and `maxconnections=32`. micro-org#268 reaches the same conclusion from the
 * operator's side and calls dropping `blocksonly` the wrong trade on this box.
 *
 * ── AND THE FLOOR IS ADEQUATE ON THE ONE CHAIN THIS DEPLOYMENT ACTUALLY RUNS, MEASURED ──────────
 *
 * `getblockstats` reports `feerate_percentiles` from CONFIRMED transactions, so it works fine under
 * `blocksonly`. Over Litecoin mainnet blocks 3,156,645–3,156,788 (144 blocks, 30,169 transactions),
 * read 2026-08-09, in litoshi/vB:
 *
 *     statistic                  median across blocks   p90 across blocks   max
 *     block's 10th-pct feerate            1                     1            10
 *     block's 50th-pct feerate            5                     5            10
 *     block's 90th-pct feerate           11                    44           301
 *     block's average feerate            12                    23            87
 *
 * The row that settles it is the first: in at least nine blocks out of ten, the cheapest tenth of
 * the block's weight paid **1 litoshi/vB** — this floor exactly. Litecoin blocks have room, so a
 * transaction built at the floor is in the band they routinely include. That is a measurement and
 * not a hope, and it is the reason nothing here reaches for a live quote.
 *
 * **If a live quote is ever wanted it comes from `getblockstats`, not from `estimatesmartfee`** —
 * percentiles over a trailing window, from confirmed blocks, available under `blocksonly`.
 *
 * ── THE RESIDUAL, STATED RATHER THAN LEFT TO BE DISCOVERED ──────────────────────────────────────
 *
 * `SETTLEMENT_RPC_URLS` carries `ember` and `ltc` today, so Litecoin is the only chain in this
 * family that this measurement covers. `bitcoind` is running on the same host with the identical
 * `blocksonly=1`, and Bitcoin's blocks are not Litecoin's: a BTC transaction at 1 sat/vB is above
 * the relay floor and would still sit unconfirmed. **Pointing this service at that node is a
 * deploy change that needs its own fee decision first**, and this block is where whoever makes it
 * should stop. Nothing in this file blocks it, because a refusal nobody can test against a live
 * endpoint is a refusal that breaks the day the endpoint appears.
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 */

/**
 * The three ways a bitcoin-family node says **"I have no estimate"**, and they are three because
 * the estate runs three Core lineages that are a decade apart.
 *
 * Every one of them means the same thing and every one of them takes the floor. Until this existed
 * only the first was handled, and the other two came out of `feeRate` as exceptions — so the
 * fallback the block above describes did not happen on two of the three nodes this host runs.
 * Measured on the mainnet estate host, 2026-08-09:
 *
 *   1. **`feerate` absent, with an `errors` array.** `litecoind 0.21.5.6` (Core 0.21 lineage), and
 *      any Core from 0.16. `{"errors":["Insufficient data or no feerate found"],"blocks":0}`.
 *      Handled correctly since this function was written.
 *
 *   2. **`feerate: -1`.** `dogecoind 1.14.9`, whose Core base predates the `errors` array and uses
 *      the old sentinel: `{"feerate":-1,"blocks":25}`. `-1` IS a number, so it passed the type
 *      guard, and `btcToSats` refuses a negative amount — every DOGE fee quote would have thrown
 *      `AddressError` rather than falling back to 100 koinu/vB. `dogecoind` does not even set
 *      `blocksonly`; it simply has no estimate while it is 36% through its initial sync.
 *
 *   3. **A JSON-RPC error, `Fee estimation disabled`.** `bitcoind 27.0`, which does not construct
 *      an estimator AT ALL under `blocksonly`. `bitcoin/bitcoin`, read at `master` on 2026-08-09:
 *      `src/init.cpp` guards the estimator's construction with `if (!peerman_opts.ignore_incoming_txs)`
 *      under the comment "Don't initialize fee estimation with old data if we don't relay
 *      transactions, as they would never get updated", and `src/rpc/server_util.cpp`
 *      `EnsureFeeEstimator` answers a null estimator with
 *      `throw JSONRPCError(RPC_INTERNAL_ERROR, "Fee estimation disabled")`. Measured:
 *      `error code: -32603, error message: Fee estimation disabled`. So on Core 25 and later,
 *      `blocksonly` turns "no estimate" from a value into an exception — and this service's
 *      transport turns a JSON-RPC `error` envelope into a thrown `RpcError` (`registry.ts`).
 *
 * **Only that exact message is caught, and that narrowness is the guarantee.** Every other RPC
 * fault — a node that is down, a wrong credential, a method that does not exist — must still
 * propagate. Swallowing them would build every transaction on the estate at the relay floor during
 * an outage, silently, which is a far worse defect than the one this closes.
 *
 * BTC and DOGE have no endpoint in `SETTLEMENT_RPC_URLS` today, so (2) and (3) are latent rather
 * than live. Both nodes are already running on this host; adding either chain to that variable is
 * a one-line deploy edit, and until this change it was a one-line deploy edit that broke every fee
 * quote on the chain it enabled.
 */
const NO_ESTIMATE_RPC_MESSAGE = 'Fee estimation disabled'

/* ------------------------------------------------------------------ the two fee ceilings */

/**
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 * **CUSTODY'S CEILINGS ARE THE AUTHORITY. THESE ARE A MIRROR OF THEM, AND THE MIRROR IS TIGHTER.**
 *
 * There is one number here that must not be got wrong and it is a RELATIONSHIP, not a value.
 * custody's `signBitcoin` sets `psbt.setMaximumFeeRate(ceiling)` and then refuses outright at
 * `feeRate >= ceiling` (custody/src/signing.ts), reading a per-chain table of its own
 * (`FEE_RATE_CEILINGS`, read on 2026-08-09):
 *
 *     bitcoin   sweep 1_000   payment 5_000
 *     litecoin  sweep 1_000   payment 5_000
 *     dogecoin  sweep 10_000  payment 50_000
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
 * from one to fifty, on every chain, and requires every one of them to stay under custody's. Move
 * either constant and that test goes red.
 *
 * ── AND THEN THE CEILINGS BECAME PER-CHAIN, WHICH IS THE THIRD FAILURE ──────────────────────────
 *
 * **A SINGLE PAIR OF NUMBERS WOULD HAVE REFUSED EVERY DOGECOIN SWEEP THAT EVER EXISTED, AND WOULD
 * HAVE DONE IT WITHOUT EVER LOOKING WRONG.** This block used to argue explicitly that the ceilings
 * should NOT be per-chain, on the grounds that a rate in the chain's own smallest unit is a looser
 * bound in value terms for a cheaper coin, "which is the safe direction for a CEILING". That
 * argument holds for Litecoin and breaks completely on Dogecoin, and the reason is that it assumed
 * the coin was cheaper but the FEE MARKET was the same shape. Dogecoin's is not a market at all:
 *
 *     dogecoin/dogecoin  src/policy/policy.h    RECOMMENDED_MIN_TX_FEE = COIN / 100
 *
 * — 0.01 DOGE per kilobyte, which is **1,000 koinu/vB**, read at `master` on 2026-08-09. That is
 * the rate Core's own wallet pays. It is not a congestion spike, it is the floor of normal
 * operation, and it is set by policy rather than by bidding, so there is no cheaper block to wait
 * for. Against the old shared numbers:
 *
 *   * the SWEEP ceiling of 900 sits BELOW Dogecoin's ordinary fee, so every sweep would have been
 *     refused at build time, on every deposit address, permanently. Not a stall that clears — the
 *     deposits would simply never have been swept, and the only symptom would have been a
 *     `fee_out_of_band` on a chain nobody had a reason to suspect;
 *   * the PAYMENT ceiling of 4,500 would have passed, at four and a half times the normal rate, so
 *     the defect would have been invisible on the withdrawal path that people watch and total on
 *     the sweeper that they do not.
 *
 * custody reached the same conclusion from the other side on the same day and its table is above.
 * These are 90% of custody's, chain by chain, which is the same margin the Bitcoin pair has always
 * carried and is what the input-count assertion actually measures. DOGE's numbers are therefore
 * Core's recommended rate times nine for a sweep and times forty-five for a payment: far enough
 * above normal that no ordinary transaction is refused, far enough below custody's that the vsize
 * slack cannot close the gap, and still bounding a one-input one-output sweep's burn at well under
 * 0.02 DOGE.
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 */

export interface FeeCeilings {
  readonly sweep: bigint
  readonly payment: bigint
}

/**
 * custody/src/signing.ts, `FEE_RATE_CEILINGS`. Restated so the test can compare the two tables and
 * so `assertUnderCustodysCeiling` refuses exactly what custody would. **Never used as this
 * service's own bound** — that is `CEILINGS` below.
 */
const CUSTODY_CEILINGS: Readonly<Record<BitcoinFamilyChainId, FeeCeilings>> = Object.freeze({
  btc: Object.freeze({ sweep: 1_000n, payment: 5_000n }),
  ltc: Object.freeze({ sweep: 1_000n, payment: 5_000n }),
  doge: Object.freeze({ sweep: 10_000n, payment: 50_000n }),
})

/** @see CUSTODY_CEILINGS */
export function custodyCeilings(chain: BitcoinFamilyChainId): FeeCeilings {
  return CUSTODY_CEILINGS[chain]
}

/** Retained for the existing Bitcoin call sites and tests. @see CUSTODY_CEILINGS */
export const CUSTODY_MAX_SWEEP_SAT_PER_VB = CUSTODY_CEILINGS.btc.sweep
/** Same. */
export const CUSTODY_MAX_PAYMENT_SAT_PER_VB = CUSTODY_CEILINGS.btc.payment

/**
 * This service's own ceilings. Strictly below custody's, by more than the vsize slack can consume.
 *
 * A ceiling, not an estimate: above these a node has quoted something absurd and the answer is to
 * wait for a cheaper block rather than to burn a customer's deposit on miner revenue. A sweep is a
 * background job with nobody waiting, so stalling one is self-healing in a way a burn is not; a
 * withdrawal has a user waiting, which is why its ceiling is the looser of the two here exactly as
 * it is in custody.
 *
 * **Dogecoin's pair is the one place "wait for a cheaper block" is not the fallback**, because its
 * rate is policy rather than price. That is why its ceiling is nine times the rate a Dogecoin node
 * will actually quote rather than a whisker above it: the headroom is for a future change to
 * `RECOMMENDED_MIN_TX_FEE`, which has been cut before — `DEFAULT_MIN_RELAY_TX_FEE` is a tenth of it
 * and `DEFAULT_INCREMENTAL_RELAY_FEE` a hundredth, so the constants already span two decades.
 */
const CEILINGS: Readonly<Record<BitcoinFamilyChainId, FeeCeilings>> = Object.freeze({
  btc: Object.freeze({ sweep: 900n, payment: 4_500n }),
  ltc: Object.freeze({ sweep: 900n, payment: 4_500n }),
  doge: Object.freeze({ sweep: 9_000n, payment: 45_000n }),
})

/** This service's own bound for a chain. @see CEILINGS */
export function ceilingsFor(chain: BitcoinFamilyChainId): FeeCeilings {
  return CEILINGS[chain]
}

/** Retained for the existing Bitcoin call sites and tests. @see CEILINGS */
export const MAX_SWEEP_SAT_PER_VB = CEILINGS.btc.sweep
/** Same. */
export const MAX_SAT_PER_VB = CEILINGS.btc.payment

export interface BitcoinChainOptions {
  readonly dustThreshold?: bigint
}

/**
 * The adapter for ONE bitcoin-family chain.
 *
 * **The chain is a parameter and it used not to be.** Everything below that reads a constant reads
 * it through `chain`: the network parameters an address is validated and a PSBT encoded under, the
 * dust threshold, the supply cap, the confirmation depth, and the chain named in every refusal.
 *
 * The depth in particular comes free and must: `chainSpec('LTC').confirmations` is **12**, not
 * Bitcoin's 6, because Litecoin's blocks are ~2.5 minutes rather than ~10 on a fraction of the
 * hashrate. It is read from the exact-pinned `contracts-chain` and never restated, so `listunspent`
 * asks for coins at Litecoin's own depth and `status` calls a payment confirmed at it.
 */
export function bitcoinChain(
  chain: BitcoinFamilyChainId = 'btc',
  options: BitcoinChainOptions = {},
): OutboundChain {
  const dust = options.dustThreshold ?? DEFAULT_DUST[chain]
  const spec = chainSpec(assetOf(chain))
  const ceilings = CEILINGS[chain]
  const floor = MIN_RELAY_PER_VB[chain]

  /**
   * The chain's own base unit per vB from the node, bounded by the ceiling for THIS shape.
   *
   * The shape is a parameter rather than one clamp for both, because the two ceilings are five
   * times apart and the tighter one is the one custody will actually apply to a sweep. See the
   * ceiling block above.
   */
  async function feeRate(call: ChainCall, shape: OutboundShape): Promise<bigint> {
    const ceiling = shape === 'sweep' ? ceilings.sweep : ceilings.payment
    let answer: unknown
    try {
      answer = await call.rpc('estimatesmartfee', [FEE_TARGET_BLOCKS])
    } catch (err) {
      // Spelling three of "I have no estimate", and the only exception this catches. Matched on
      // Core's own words rather than on a code, which is the same rule `broadcast` follows for
      // "transaction already in block chain" — and matched NARROWLY, because every other RPC fault
      // here has to keep propagating. @see NO_ESTIMATE_RPC_MESSAGE
      if (err instanceof Error && err.message.includes(NO_ESTIMATE_RPC_MESSAGE)) return floor
      throw err
    }
    const row = (answer ?? {}) as Record<string, unknown>
    // `feerate` is the coin per kilovbyte. Spellings one and two of "I have no estimate": absent
    // with an `errors` array on Core 0.16 and later, and the `-1` sentinel on the older lineage
    // `dogecoind` still carries. Both take the floor rather than guessing high, and on Dogecoin
    // that floor is a hundred times Bitcoin's. @see NO_ESTIMATE_RPC_MESSAGE, MIN_RELAY_PER_VB
    //
    // `!(quoted > 0)` and not `quoted <= 0`, so a `NaN` — which is a number to `typeof` and
    // compares false against everything — lands on the floor instead of reaching `Math.round`.
    const quoted = row['feerate']
    if (typeof quoted !== 'number' || !(quoted > 0)) return floor
    const perKvb = btcToSats(quoted, chain)
    const perVb = perKvb / 1_000n
    if (perVb < floor) return floor
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
    validateAddress(chain, input.from, call.network)
    validateAddress(chain, input.to, call.network)
    if (input.value <= 0n) {
      // A zero-value output is refused by the relay as dust and by custody as an output that pays
      // nothing. Refusing here makes it a classified build failure rather than a 403.
      throw new FeeOutOfBandError(chain, 'below', input.value, 1n)
    }
    if (input.shape !== 'sweep' && input.value <= dust) {
      /*
       * **A PAYMENT AT OR BELOW THE DUST THRESHOLD, REFUSED AT BUILD RATHER THAN AT BROADCAST.**
       *
       * **THE PAYMENT SHAPE ONLY, AND THE EXCLUSION IS LOAD-BEARING.** A sweep's `value` is
       * `total − fee` of whatever coins the address actually holds, and `sweepPlan` already refuses
       * a plan at or below the threshold from the coins themselves. Applying this guard to a sweep
       * as well would answer "this amount is dust" for an address that simply has nothing at depth
       * yet — turning a TREASURY failure, which is retried, into a fee refusal, which is permanent,
       * for the ordinary recurring state of almost every deposit address.
       *
       * This used to read `input.value <= 0n`, which caught only the degenerate case. Every value
       * between one and the threshold produced a well-formed PSBT that custody signed and that
       * `sendrawtransaction` then answered `dust` to — a refusal from the far side of a signature,
       * with this chain's single outbound slot claimed and the user's money still reserved.
       *
       * It was reachable before Litecoin and is more reachable with it. wallet's floor is
       * `fee × WALLET_WITHDRAWAL_MIN_FEE_MULTIPLE`, which at the relay floor is 141 × 3 = 423
       * smallest units — under Bitcoin's 546 and far under Litecoin's 5,460. So the two services
       * disagreed about the smallest withdrawal that can exist, and the gap between them was a
       * transaction no node would forward.
       *
       * Refused HERE and not only there because this is the service that knows the chain's dust
       * threshold; a build failure is classified, releases the row and refunds, and a broadcast
       * refusal after signing is the state that needs an operator. The message names the number so
       * the refusal is actionable rather than merely correct.
       */
      throw new FeeOutOfBandError(chain, 'below', input.value, dust + 1n)
    }
    if (input.fee > input.bounds.maxFeeWei) {
      throw new FeeOutOfBandError(chain, 'above', input.fee, input.bounds.maxFeeWei)
    }

    const rate = await feeRate(call, input.shape)
    const utxos = await listUnspent(call, input.from, spec.confirmations)

    let inputs: readonly Utxo[]
    let fee: bigint
    const outputs: { address: string; sats: bigint }[] = [{ address: input.to, sats: input.value }]

    if (input.shape === 'sweep') {
      const plan = sweepPlan(utxos, rate, dust, chain)
      if (!plan) {
        // Nothing at depth, or not enough to be worth moving. Either way the coins are not there,
        // which classifies as a treasury failure and is retried rather than refunded on the spot.
        throw new InsufficientTreasuryError(chain, totalOf(utxos), input.value + input.fee)
      }
      // **The plan must still be the plan the ROW was written from.** `planSweep` quoted this same
      // UTXO set through this same function; a disagreement means coins arrived or left in between,
      // and the difference between the two numbers is a fee nobody agreed to pay. Refused rather
      // than silently re-quoted, exactly as a withdrawal's locked fee is.
      if (plan.value !== input.value || plan.fee !== input.fee) {
        throw new FeeOutOfBandError(chain, plan.fee > input.fee ? 'below' : 'above', input.fee, plan.fee)
      }
      inputs = plan.inputs
      fee = plan.fee
    } else {
      const selection = selectCoins(utxos, input.value, rate, dust, chain)
      // The locked fee is what the user agreed to. It is checked, never re-quoted: re-quoting here
      // would sign a transaction that does not match the row it was built from, and the fee bounds
      // exist so a node having a bad minute cannot spend a user's balance on miner revenue.
      if (selection.fee > input.fee) {
        throw new FeeOutOfBandError(chain, 'below', input.fee, selection.fee)
      }
      inputs = selection.inputs
      fee = selection.fee
      if (selection.change > 0n) {
        // Change returns to the SOURCE address, never to a fresh one. A fresh change address would
        // be a key this service invented, and every key in this estate is custody's.
        outputs.push({ address: input.from, sats: selection.change })
      }
    }

    const psbt = await encodePsbt(call, chain, input.from, inputs, outputs)
    assertUnderCustodysCeiling(psbt, fee, input.shape, chain)

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
    chain,
    family: 'bitcoin',
    unimplementedPhase: null,
    // Bitcoin has no token model, so there is nothing here and never will be. Null rather than an
    // object whose methods throw: the token planner reads it as "no token sweeps on this chain" and
    // skips silently, which is the permanent, correct, unremarkable state of this chain.
    tokens: null,

    canonicalise(address) {
      // The identity, validated. See `validateAddress` for why lower-casing would be a bug.
      return validateAddress(chain, address, 'mainnet')
    },
    addressKey(address) {
      return address.trim()
    },
    isValidDestination(address) {
      // Valid on EITHER network is the honest answer to a question that does not name one; the
      // network-specific check happens in `build`, where the network is known.
      for (const network of ['mainnet', 'testnet'] as const) {
        try {
          validateAddress(chain, address, network)
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
      const fee = rate * BigInt(vsizeOf(1, 2, chain))
      if (fee > bounds.maxFeeWei) {
        throw new FeeOutOfBandError(chain, 'above', fee, bounds.maxFeeWei)
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
      const plan = sweepPlan(await listUnspent(call, address, spec.confirmations), rate, dust, chain)
      if (!plan) return null
      if (plan.fee > bounds.maxFeeWei) {
        throw new FeeOutOfBandError(chain, 'above', plan.fee, bounds.maxFeeWei)
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
  /**
   * The chain, last and defaulted so the existing Bitcoin call sites are untouched.
   *
   * Defaulted rather than required ONLY here, and only because this function has no production
   * caller — it is an operator's and a test's entry point. `bitcoinChain` above takes it first and
   * without a default, which is where it matters.
   */
  chain: BitcoinFamilyChainId = 'btc',
  dustThreshold: bigint = DEFAULT_DUST[chain],
): Promise<{ psbtBase64: string; value: bigint; fee: bigint } | null> {
  validateAddress(chain, from, call.network)
  validateAddress(chain, treasury, call.network)

  const plan = sweepPlan(
    await listUnspent(call, from, minConfirmations),
    feeRatePerVb,
    dustThreshold,
    chain,
  )
  if (plan === null) return null

  // **`encodePsbt` RATHER THAN A SECOND `addInput` LOOP**, which is the change that made this
  // function safe to keep. It carried its own loop, hard-coding `witnessUtxo` — so the day a chain
  // with no segwit was admitted, the shape custody's policy asks for would have been built one way
  // by `build` and another way here, and the second one is the entry point an operator reaches for
  // when they are reproducing a sweep by hand at the worst possible moment.
  const psbt = await encodePsbt(call, chain, from, plan.inputs, [
    { address: treasury, sats: plan.value },
  ])
  assertUnderCustodysCeiling(psbt, plan.fee, 'sweep', chain)

  return { psbtBase64: psbt.toBase64(), value: plan.value, fee: plan.fee }
}
