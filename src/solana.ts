/**
 * The Solana outbound adapter: one System Transfer, built to exactly the shape custody now signs.
 *
 * ## The objection this file answers, and why it no longer holds
 *
 * `registry.ts` refused to have this adapter, and the refusal was right at the time:
 *
 *     "custody signs only the SPL mint-creation instruction set and explicitly refuses
 *      SystemProgram::Transfer, which is what moving SOL is. […] Building an adapter here first
 *      would produce bytes custody refuses at gate 2 — after a row is committed and money is in
 *      flight — which is strictly worse than this refusal, which happens before anything is
 *      written."
 *
 * `SolanaPolicy` (custody/src/signing.ts) now has three disjoint shapes and two of them are a
 * System Transfer:
 *
 *     deployer → 'mint'      the SPL mint-creation set, unchanged
 *     treasury → 'transfer'  exactly one System Transfer, to an address the caller names
 *     deposit  → 'sweep'     exactly one System Transfer, to the address CUSTODY pinned
 *
 * So the objection is gone in both directions: a withdrawal has a shape and a sweep has a shape,
 * and the sweep's destination is not this service's to choose. What has NOT changed is the SPL
 * allowlist — SPL Transfer (tag 3), Approve, SetAuthority, Burn and CloseAccount are refused under
 * every shape — and this file asks for none of them. **A SOL withdrawal and a SOL sweep are the
 * same one instruction; only the destination differs, and on a sweep it is checked against the
 * pin.**
 *
 * ## What custody will actually check, and therefore what this file must produce
 *
 * `signSolana` decodes the base64 with `Transaction.from`, so the transaction must survive that
 * round trip unchanged. Then, for either transfer shape, it refuses unless ALL of:
 *
 *   1. `feePayer` is the vault address. It is `accountKeys[0]`, so this is also the first signer.
 *   2. **Exactly ONE instruction.** Not "at most eight" — a batch is what makes a Solana signature
 *      dangerous, because `partialSign` signs the whole message and a second instruction riding
 *      alongside cannot be separated from the first afterwards.
 *   3. The program is the System Program, the data is exactly 12 bytes, and its u32 tag is 2.
 *   4. `keys[0]` is the vault address — the account being SPENT, which is a different key in the
 *      instruction from the fee payer even when they are the same account.
 *   5. `keys[1]` is the destination. On `sweep` it must equal the pin, compared as a decoded key.
 *   6. Lamports are non-zero, and the destination is not the source.
 *   7. **Exactly one required signer, and it is the vault.** So this must serialise with the
 *      signature slot present and empty, never with a second signer declared.
 *
 * Every one of those is asserted in `solana.test.ts` against a transaction decoded back with the
 * same library custody decodes with, which is the closest this side can get to "custody will sign
 * this" without holding a key.
 *
 * ## Why @solana/web3.js is here, when package.json's note says there is no chain library
 *
 * The same argument `bitcoin.ts` makes, and it is stronger here. That note's reasoning is that this
 * service hands custody a JSON object and custody is the only place a serialiser is needed. True
 * for EVM; false for Solana, where `signSolana` takes a **base64 wire transaction**. Something on
 * this side has to encode the message format — a compact-u16 account table, a header, a blockhash
 * and an instruction with account indices — and the choice is between hand-rolling it and using the
 * library custody DECODES with. It is the second: a builder and a signer with two independent
 * implementations of one binary format is the precise shape of a bug that pays a stranger. Same
 * package, same major version as custody's.
 *
 * ## Rent, which is the Solana-specific way to build a transaction that cannot land
 *
 * A Solana account whose balance is driven to zero is deleted, and that is fine. An account left
 * with a balance that is non-zero and BELOW the rent-exempt minimum is not: the runtime rejects the
 * whole transaction with `InsufficientFundsForRent`. So there is a forbidden band, roughly 1 to
 * 890,880 lamports, that a payment must not leave behind — and it is checked here, before the row
 * is signed, because the alternative is a transaction that broadcasts, is rejected, and refunds a
 * user who could have been told immediately. A sweep is exempt by construction: it takes the whole
 * balance, so what it leaves is exactly zero.
 *
 * ## The death proof, which Solana has and the other two chains do not
 *
 * EVM's proof is a consumed nonce and Bitcoin's is a spent coin. **Solana's is time, and it is the
 * cleanest of the three**: a transaction may only enter a block while its `recentBlockhash` is
 * still in the 300-entry recent-blockhash queue, which is about 150 blocks or a little over a
 * minute. Once it has aged out, no validator anywhere can include those bytes — not later, not
 * ever, with no operator action needed to retire anything. `proveDead` reads the blockhash out of
 * the committed BYTES rather than off the row, for `legacyNonce`'s reason: a column written beside
 * the bytes can drift from them and nothing would notice.
 */

import bs58 from 'bs58'
import {
  PublicKey,
  SystemProgram,
  Transaction as SolanaTransaction,
} from '@solana/web3.js'
import { chainSpec } from '@cloudsforge/contracts-chain'
import {
  AddressError,
  FeeOutOfBandError,
  InsufficientTreasuryError,
  UnsupportedDestinationError,
  assetOf,
  type BuildInput,
  type ChainCall,
  type DeathInput,
  type DeathVerdict,
  type FeeBounds,
  type OutboundChain,
  type OutboundStatus,
  type SweepQuote,
  type UnsignedOutbound,
} from './chains.ts'

/* ------------------------------------------------------------------ amounts */

/** A u64 does not go past this, and neither does a lamport quantity custody can encode. */
export const MAX_LAMPORTS = 2n ** 64n - 1n

/**
 * The System Program's own address, which is also the all-zero public key.
 *
 * Solana's spelling of the EVM zero address: well-formed, nameable, and the one destination from
 * which nothing is ever recovered. Refused as a destination here so a withdrawal to it never gets
 * built, rather than being caught at the moment of signing — custody has no equivalent check, so
 * this side is the only side that has one.
 */
export const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111'

/* ------------------------------------------------------------------ addresses */

/**
 * Base58 is case-SIGNIFICANT and a 32-byte key has exactly one encoding, so the canonical form and
 * the comparison form are the same string — which is why both `canonicalise` and `addressKey` are
 * this function, where EVM's are `toChecksumAddress` and `toLowerCase`.
 *
 * Validation is a real decode: `PublicKey` rejects anything that is not 32 bytes of base58, which
 * is the only honest check there is. A shorter or longer string is not an address, and there is no
 * checksum to fall back on — Solana addresses have none, which is why a typo produces a valid
 * address belonging to nobody and why nothing here may ever "repair" one.
 */
export function validateAddress(address: string): string {
  const trimmed = address.trim()
  if (trimmed.length === 0) throw new AddressError('a solana address may not be empty')
  let key: PublicKey
  try {
    key = new PublicKey(trimmed)
  } catch {
    throw new AddressError(`${trimmed.slice(0, 64)} is not a valid solana address — it must be 32 bytes of base58`)
  }
  const canonical = key.toBase58()
  if (canonical !== trimmed) {
    // Reachable only for a spelling that decodes to the same 32 bytes as a different string, which
    // base58 does not otherwise permit. Refused rather than silently rewritten: custody compares
    // the caller's restated `address` against its stored row character for character, so a value
    // this service rewrote would be a `binding_mismatch` whose message will not say which field.
    throw new AddressError(`${trimmed.slice(0, 64)} is not the canonical base58 spelling of ${canonical}`)
  }
  return canonical
}

function publicKey(address: string, what: string): PublicKey {
  try {
    return new PublicKey(validateAddress(address))
  } catch (err) {
    if (err instanceof AddressError) throw err
    throw new AddressError(`${what} is not a valid solana address`)
  }
}

/* ------------------------------------------------------------------ the node */

function record(value: unknown, method: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) {
    throw new AddressError(`${method} answered ${String(value)} where an object was expected`)
  }
  return value as Record<string, unknown>
}

/**
 * A lamport quantity out of a JSON-RPC answer.
 *
 * Solana reports lamports as JSON NUMBERS, and one SOL is 1e9 lamports, so the whole supply is
 * about 6e17 — under `Number.MAX_SAFE_INTEGER` (9.007e15)? **No: it is sixty-six times past it.**
 * A balance above 9,007,199 SOL cannot be read exactly out of a double, which is why this refuses a
 * non-safe integer rather than rounding it. No address in this estate holds anything near that, and
 * that is precisely the argument that stops being true quietly.
 */
function lamports(value: unknown, method: string): bigint {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new AddressError(`${method} answered ${String(value)} where a lamport count was expected`)
  }
  if (!Number.isSafeInteger(value)) {
    throw new AddressError(
      `${method} answered ${value} lamports, which is past the range a JSON number carries exactly`,
    )
  }
  return BigInt(value)
}

/** `{ context, value }` is the envelope every state-reading Solana method uses. */
function contextValue(answer: unknown, method: string): unknown {
  return record(answer, method)['value']
}

/** The confirmed balance of an address, in lamports. */
async function balanceAt(call: ChainCall, address: string, commitment: string): Promise<bigint> {
  const answer = await call.rpc('getBalance', [address, { commitment }])
  return lamports(contextValue(answer, 'getBalance'), 'getBalance')
}

interface Blockhash {
  readonly blockhash: string
  readonly lastValidBlockHeight: bigint
}

async function latestBlockhash(call: ChainCall): Promise<Blockhash> {
  const answer = contextValue(await call.rpc('getLatestBlockhash', [{ commitment: 'finalized' }]), 'getLatestBlockhash')
  const row = record(answer, 'getLatestBlockhash')
  const blockhash = row['blockhash']
  if (typeof blockhash !== 'string' || blockhash.length === 0) {
    throw new AddressError('getLatestBlockhash did not answer with a blockhash')
  }
  const height = row['lastValidBlockHeight']
  if (typeof height !== 'number' || !Number.isSafeInteger(height) || height <= 0) {
    // Without it there is no death proof: `lastValidBlockHeight` is the only number that says when
    // these bytes stop being includable, and a signature nobody can ever prove dead is a signature
    // whose money is stuck until an engineer looks at the row.
    throw new AddressError('getLatestBlockhash did not answer with a usable lastValidBlockHeight')
  }
  return { blockhash, lastValidBlockHeight: BigInt(height) }
}

/**
 * The smallest balance a live account may hold, from the node rather than from a constant.
 *
 * It is 890,880 lamports for a zero-data account under today's rent parameters, and writing that
 * number down here would be writing down a governance parameter as if it were a protocol constant.
 * The node knows it; asking costs one call on a path that already makes four.
 */
async function rentExemptMinimum(call: ChainCall): Promise<bigint> {
  return lamports(await call.rpc('getMinimumBalanceForRentExemption', [0]), 'getMinimumBalanceForRentExemption')
}

/* ------------------------------------------------------------------ the transaction */

/** The base64 wire form `signSolana` takes: unsigned, with the one signature slot present. */
export function encodeTransfer(input: {
  readonly from: PublicKey
  readonly to: PublicKey
  readonly value: bigint
  readonly blockhash: string
  readonly lastValidBlockHeight: bigint
}): string {
  const tx = new SolanaTransaction({
    // `feePayer` is `accountKeys[0]` and therefore the one required signer. Stated rather than
    // inferred, because `Transaction` will otherwise take it from whoever signs first — and nothing
    // signs here.
    feePayer: input.from,
    blockhash: input.blockhash,
    lastValidBlockHeight: Number(input.lastValidBlockHeight),
  })
  tx.add(
    SystemProgram.transfer({
      fromPubkey: input.from,
      toPubkey: input.to,
      // A BIGINT, never a Number. One SOL is 1e9 lamports and the layout writes a u64, so a value
      // that had been through a double would be silently wrong in its low digits — a signature over
      // an amount nobody chose. `SystemProgram.transfer` accepts `number | bigint` and the bigint
      // path is exact.
      lamports: input.value,
    }),
  )
  // ONE instruction and nothing else. `signSolana` refuses anything but exactly one under both
  // transfer shapes, and it is right to: `partialSign` signs the whole message, so a second
  // instruction riding alongside is signed by the same signature and cannot be separated from it.
  return tx
    .serialize({
      // **BOTH OF THESE, AND THE DEFAULT OF EITHER IS A THROW.** `serialize()` defaults both to
      // true, and it only raises "Missing signature for public key" when BOTH are — `serialize`
      // consults `requireAllSignatures` inside a branch gated on `verifySignatures`. So this is not
      // two ways of saying one thing and it is not belt-and-braces: with the defaults, nothing here
      // could produce an unsigned transaction at all, because nothing here holds a key.
      //
      // What neither option changes is the WIRE FORM: `_serialize` always writes one slot per
      // required signer, filled with zeroes where there is no signature. That slot, present and
      // empty, is what makes custody's "exactly one required signature, and it must be the vault
      // address" check pass — and a blob with no slot at all would fail it.
      //
      // The mirror image of this is custody's own comment about the same call: it serialises with
      // the DEFAULTS on the way back out, deliberately, because by then a signature exists and
      // `verifySignatures: true` is what makes any divergence between the bytes it inspected and
      // the bytes it recompiled fail there rather than ship.
      requireAllSignatures: false,
      verifySignatures: false,
    })
    .toString('base64')
}

/**
 * The id a signed Solana transaction is known by: its FIRST signature, base58.
 *
 * **Derived from the bytes, never remembered**, for `evmTxHash`'s reason — a node answers a
 * re-broadcast of a transaction it already holds with an error rather than the signature, so a
 * crash between broadcasting and recording it would otherwise leave a payment on chain with no id
 * to poll.
 *
 * There is no hashing here and that is the whole difference from the other two chains: an EVM
 * transaction id is keccak of its bytes and a Bitcoin txid is a double-SHA of most of them, but a
 * Solana transaction is identified by the signature itself. So this is a decode and an encode, and
 * `solana.test.ts` pins the encoder against `PublicKey.toBase58`, which is @solana/web3.js's own.
 */
export function solanaTxId(rawTx: string): string | null {
  try {
    const tx = SolanaTransaction.from(Buffer.from(rawTx, 'base64'))
    const signature = tx.signature
    // **A REFUSAL, never an id of zeroes.** An unsigned transaction's signature slot is present and
    // all zeroes on the wire, and `Transaction.populate` maps exactly that slot to `null` — so this
    // one branch covers both "no slot" and "an empty slot". An id derived from zeroes would be a
    // string no chain answers to, and every status lookup for the row would miss in silence, for
    // ever, while the worker re-sent the bytes each tick and declared the payment stuck at the
    // deadline. There is deliberately no second, unreachable check for the zero case here: a guard
    // whose only evidence is that it never fires is a guard nobody knows works.
    if (!signature) return null
    return bs58.encode(signature)
  } catch {
    return null
  }
}

/** The `recentBlockhash` inside committed bytes. The whole of the Solana death proof. */
export function blockhashOf(rawTx: string): string | null {
  try {
    return SolanaTransaction.from(Buffer.from(rawTx, 'base64')).recentBlockhash ?? null
  } catch {
    return null
  }
}

/* ------------------------------------------------------------------ node error shapes */

/**
 * What a node says for a transaction it has ALREADY accepted or already landed.
 *
 * Both are the SUCCESSFUL outcome of a re-broadcast, which the recovery path does by design: the
 * bytes are committed before they are sent, and anything that dies in between re-sends them. Agave
 * answers `-32002` with "This transaction has already been processed" from preflight, and some
 * gateways pass the inner `AlreadyProcessed` through instead.
 */
const ALREADY_SENT = ['already been processed', 'alreadyprocessed', 'already processed']

/* ------------------------------------------------------------------ the adapter */

export function solanaChain(): OutboundChain {
  const spec = chainSpec(assetOf('sol'))

  /**
   * The base fee for one signature, from the node.
   *
   * It is 5,000 lamports and has been since launch, and it is still asked for rather than written
   * down: it is a runtime parameter, `getFeeForMessage` is the one call that reports it, and the
   * number that decides what a user is charged should not be a constant in a comment. The message
   * it is asked about is a REAL one-signature System Transfer, because the fee is per signature and
   * the answer for a different message would be an answer to a different question.
   */
  async function baseFee(call: ChainCall, bounds: FeeBounds): Promise<bigint> {
    const { blockhash, lastValidBlockHeight } = await latestBlockhash(call)
    const from = new PublicKey(Buffer.alloc(32, 1))
    const to = new PublicKey(Buffer.alloc(32, 2))
    const wire = encodeTransfer({ from, to, value: 1n, blockhash, lastValidBlockHeight })
    // `getFeeForMessage` takes the MESSAGE, not the transaction: the signature array is stripped.
    const message = SolanaTransaction.from(Buffer.from(wire, 'base64'))
      .compileMessage()
      .serialize()
      .toString('base64')
    const answer = contextValue(
      await call.rpc('getFeeForMessage', [message, { commitment: 'confirmed' }]),
      'getFeeForMessage',
    )
    if (answer === null || answer === undefined) {
      // The blockhash aged out between the two calls, which is ordinary — it lives about a minute.
      // A throw here is retried on the next tick and is far better than a number this service made
      // up, which would be a fee quoted to a user that the chain does not charge.
      throw new AddressError(
        'the solana node could not price a transfer against the blockhash it had just published — ' +
          'this is ordinary blockhash expiry and the next tick asks again',
      )
    }
    const fee = lamports(answer, 'getFeeForMessage')
    if (fee <= 0n) {
      throw new AddressError('the solana node priced a signed transfer at zero, which it never is')
    }
    if (fee > bounds.maxFeeWei) throw new FeeOutOfBandError('sol', 'above', fee, bounds.maxFeeWei)
    return fee
  }

  async function statusOf(call: ChainCall, signature: string): Promise<OutboundStatus> {
    const answer = contextValue(
      // `searchTransactionHistory` because a node's in-memory status cache only covers the last few
      // hundred slots, and a payment this service is asking about may be older than that — reading
      // that absence as "not on chain" would re-send bytes that landed an hour ago.
      await call.rpc('getSignatureStatuses', [[signature], { searchTransactionHistory: true }]),
      'getSignatureStatuses',
    )
    const entry = Array.isArray(answer) ? answer[0] : null
    // Null is "no node has this", which is a mempool, a dropped transaction or one that never
    // arrived — indistinguishable from outside, and all three mean "re-send the same bytes".
    if (entry === null || entry === undefined) return { kind: 'unknown' }
    const row = record(entry, 'getSignatureStatuses')

    const slot = typeof row['slot'] === 'number' ? BigInt(row['slot']) : 0n
    if (row['err'] !== null && row['err'] !== undefined) {
      // **Landed and FAILED.** The chain applied these bytes, charged the fee and moved nothing —
      // which is the one machine-readable proof that makes refunding a SIGNED payment safe. Solana
      // needs this branch for the same reason EVM does and Bitcoin does not: an invalid Bitcoin
      // transaction never enters a block, but a Solana one can land and abort.
      return {
        kind: 'rejected',
        reason: `the chain applied this transaction and it failed (${JSON.stringify(row['err']).slice(0, 200)}), so nothing was transferred`,
      }
    }

    const status = row['confirmationStatus']
    const confirmations = row['confirmations']
    // **FINALITY, NOT DEPTH, AND THAT IS THE SOLANA-SHAPED PART.** `confirmations` is null exactly
    // when the transaction has been rooted by a supermajority, and a rooted slot cannot be
    // reorganised at any distance. So null is the strongest possible answer here and reading it as
    // zero — which is what a depth-counting adapter would do — would reset a payment that is
    // already final back to the beginning of its confirmation count. It is the same rule the
    // indexer's Solana worker follows.
    if (confirmations === null || status === 'finalized') {
      return { kind: 'confirmed', confirmations: spec.confirmations, minedHeight: slot }
    }
    if (typeof confirmations !== 'number' || !Number.isSafeInteger(confirmations) || confirmations < 0) {
      return { kind: 'pending', confirmations: 0, minedHeight: slot }
    }
    return confirmations >= spec.confirmations
      ? { kind: 'confirmed', confirmations, minedHeight: slot }
      : { kind: 'pending', confirmations, minedHeight: slot }
  }

  return {
    chain: 'sol',
    family: 'solana',
    unimplementedPhase: null,
    // SPL is a token model and this is deliberately not it. An SPL sweep needs a custody shape that
    // does not exist — `signSolana` admits exactly one native System Transfer under `sweep`, and SPL
    // Transfer is refused under all three shapes — and an SPL deposit additionally needs an
    // Associated Token Account rent-funded before the money can even arrive. Answering anything but
    // null here would have this service plan sweeps custody cannot sign.
    tokens: null,

    canonicalise: validateAddress,
    // The identity, and deliberately not a case fold. Base58 is case-significant: `toLowerCase` on
    // a Solana address produces a string that decodes to different bytes or does not decode at all.
    addressKey: validateAddress,

    isValidDestination(address) {
      try {
        return validateAddress(address) !== SYSTEM_PROGRAM_ID
      } catch {
        return false
      }
    },

    estimateFee(call, bounds) {
      return baseFee(call, bounds)
    },

    /**
     * What this address could send, net of what the chain will not let it move.
     *
     * The rent-exempt minimum is subtracted because that is exactly what "the chain will not let it
     * move" means on Solana: a payment that would leave a live account below it is rejected whole.
     * Reading `finalized`, which for Solana IS the declared depth — `contracts-chain` says 32
     * confirmations and a rooted slot is 32-odd slots deep by construction — so this is the same
     * number the deposit side credits at, expressed the way the chain expresses it.
     */
    async spendableBalance(call, address) {
      validateAddress(address)
      const [balance, reserve] = await Promise.all([
        balanceAt(call, address, 'finalized'),
        rentExemptMinimum(call),
      ])
      return balance > reserve ? balance - reserve : 0n
    },

    /**
     * A sweep takes the whole balance and leaves the account at exactly zero.
     *
     * **Not `spendableBalance` minus the fee**, and the difference is the point: `spendableBalance`
     * holds back the rent-exempt minimum so a live account stays live, and a swept deposit address
     * is not meant to stay live. An account driven to zero is deleted by the runtime and re-created
     * by the next deposit, at the depositor's expense rather than out of a reserve this platform
     * would otherwise strand on every deposit address it ever mints — 890,880 lamports each, for
     * ever, on addresses whose whole purpose was to be emptied.
     */
    async sweepQuote(call, address, bounds) {
      validateAddress(address)
      const [balance, fee] = await Promise.all([
        balanceAt(call, address, 'finalized'),
        baseFee(call, bounds),
      ])
      const value = balance - fee
      return value > 0n ? { value, fee } : null
    },

    async build(call, input: BuildInput): Promise<UnsignedOutbound> {
      // Refused BEFORE the node is asked anything: these are permanent properties of the row, and
      // finding them out after four round trips is four round trips spent on a refusal.
      if (input.value <= 0n || input.value > MAX_LAMPORTS) {
        // Custody refuses a zero-lamport Transfer as "a fee burn with no effect"; a value past a
        // u64 is not a quantity the instruction can even encode.
        throw new FeeOutOfBandError('sol', 'below', input.value, 1n)
      }
      if (input.fee <= 0n) throw new FeeOutOfBandError('sol', 'below', input.fee, 1n)
      if (input.fee > input.bounds.maxFeeWei) {
        throw new FeeOutOfBandError('sol', 'above', input.fee, input.bounds.maxFeeWei)
      }
      const from = publicKey(input.from, 'the source address')
      const to = publicKey(input.to, 'the destination address')
      if (to.equals(from)) {
        // Custody refuses "a solana Transfer to the vault address itself". On a sweep this is also
        // the symptom of a treasury pinned to the address being swept, which would be a rotation
        // half-done — `assertSweepable` catches that first, and this is the belt to its brace.
        throw new UnsupportedDestinationError('sol', to.toBase58())
      }
      if (to.toBase58() === SYSTEM_PROGRAM_ID) {
        throw new UnsupportedDestinationError('sol', to.toBase58())
      }

      const [{ blockhash, lastValidBlockHeight }, balance, reserve] = await Promise.all([
        latestBlockhash(call),
        // 'confirmed', not 'finalized', and for `eth_getBalance`'s reason: this answers "will the
        // node accept a transaction I build now?", and a node validates against its own head.
        balanceAt(call, input.from, 'confirmed'),
        rentExemptMinimum(call),
      ])

      const needed = input.value + input.fee
      if (balance < needed) throw new InsufficientTreasuryError('sol', balance, needed)
      const residue = balance - needed
      if (residue > 0n && residue < reserve) {
        // **THE RENT BAND.** The account would be left alive and below the rent-exempt minimum, and
        // the runtime rejects the whole transaction for it. Refusing here makes it a classified
        // build failure that is retried and eventually refunded, instead of a broadcast that comes
        // back `InsufficientFundsForRent` with the user's money already committed. To pay this the
        // source must either keep nothing at all or keep the reserve as well.
        throw new InsufficientTreasuryError('sol', balance, needed + reserve)
      }

      return {
        payload: encodeTransfer({ from, to, value: input.value, blockhash, lastValidBlockHeight }),
        value: input.value,
        fee: input.fee,
        // Solana has no nonce. A durable nonce account is the closest thing and nothing in this
        // estate has one — which is exactly why the expiry below exists and is not optional.
        nonce: null,
        // **The chain height past which these bytes can NEVER be applied.** The one adapter here
        // that can fill this in, and it is what makes the Solana death proof a proof rather than an
        // inference. Recorded for an operator to read; `proveDead` prefers the blockhash it derives
        // from the bytes themselves.
        expiry: lastValidBlockHeight.toString(),
      }
    },

    txIdOf: solanaTxId,

    async broadcast(call, rawTx) {
      const derived = solanaTxId(rawTx)
      if (!derived) throw new Error('the committed bytes are not a signed solana transaction')
      try {
        const signature = await call.rpc('sendTransaction', [
          rawTx,
          {
            encoding: 'base64',
            // Preflight ON. It is a simulation against the node's own head and it is what turns
            // "this would fail for rent" or "this account cannot pay" into an error at broadcast
            // rather than a landed-and-failed transaction that has already burned the fee.
            skipPreflight: false,
            preflightCommitment: 'confirmed',
            // The RPC node must not re-send on this service's behalf. Re-broadcast is this
            // service's own recovery path, from committed bytes, on its own tick — a node quietly
            // retrying for a minute is a second sender nothing here can account for.
            maxRetries: 0,
          },
        ])
        return typeof signature === 'string' && signature.length > 0 ? signature : derived
      } catch (err) {
        const message = (err instanceof Error ? err.message : String(err)).toLowerCase()
        if (ALREADY_SENT.some((m) => message.includes(m))) return derived
        throw err
      }
    },

    status: statusOf,

    /**
     * The Solana death proof: the blockhash these bytes carry has aged out of the recent-blockhash
     * queue, so no validator can ever include them.
     *
     * Three facts in order, and the order is the design:
     *
     *   1. **No node reports a status for the signature these bytes carry.** The DERIVED id is
     *      asked about, because it is the one that exists when the row's does not.
     *   2. The bytes name a blockhash this service can read. An unreadable one is `unprovable` —
     *      an absence of evidence never refunds.
     *   3. **`isBlockhashValid` says no.** That is a positive statement by the chain, not an
     *      inference from a clock: the queue holds 300 entries and a blockhash outside it cannot be
     *      used, so the transaction is unincludable for ever. Unlike EVM, no nonce has to be
     *      retired first, and unlike Bitcoin, no conflicting spend has to exist — which makes this
     *      the only one of the three where an abandoned payment resolves itself in about a minute
     *      with nothing for an operator to do.
     *
     * The commitment is `finalized`. At a weaker one the answer could be reversed by a fork, and a
     * proof that can be reversed is not one to refund on.
     */
    async proveDead(call, input: DeathInput): Promise<DeathVerdict> {
      const ids: string[] = []
      for (const id of [solanaTxId(input.rawTx), input.txHash]) {
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

      const blockhash = blockhashOf(input.rawTx)
      if (!blockhash) {
        return {
          ok: false,
          code: 'unprovable',
          error:
            'the signed bytes on this row are not a solana transaction this service can read a ' +
            'recent blockhash out of, so there is no way to show they can never be included. ' +
            'Nothing is refunded on an unread signature — an engineer has to look at the row.',
        }
      }

      const valid = contextValue(
        await call.rpc('isBlockhashValid', [blockhash, { commitment: 'finalized' }]),
        'isBlockhashValid',
      )
      if (valid === false) {
        return {
          ok: true,
          proof:
            `no node has a status for these bytes and the blockhash they carry (${blockhash}) has ` +
            'aged out of the recent-blockhash queue, so no validator can ever include them — a ' +
            'solana transaction is only valid while its blockhash is in that queue',
        }
      }
      if (valid !== true) {
        return {
          ok: false,
          code: 'unprovable',
          error:
            'the solana node did not answer whether this blockhash is still usable, so there is no ' +
            'evidence either way. An absence of evidence never refunds.',
        }
      }
      return {
        ok: false,
        code: 'still_applicable',
        error:
          `the blockhash these signed bytes carry (${blockhash}) is still in the recent-blockhash ` +
          'queue, so any node holding them can include them at any time — a refund now can be ' +
          'followed by the payment landing. Nothing needs retiring: wait about a minute for the ' +
          'blockhash to age out and adjudicate this row again.',
      }
    },
  }
}
