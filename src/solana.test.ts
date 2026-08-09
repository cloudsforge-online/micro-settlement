/**
 * The Solana adapter, without a database and without a network.
 *
 * ## What these tests are actually for
 *
 * **Every transaction built here is decoded back with the same library custody decodes with, and
 * then put through the checks `signSolana` actually makes.** That is the closest this side can get
 * to "custody will sign this" without holding a key, and it is the check that matters: the previous
 * agent's whole reason for not building this adapter was that bytes custody refuses are bytes that
 * fail AFTER a row is committed and the chain's single outbound slot is claimed.
 *
 * `assertCustodyWouldSign` below is a deliberate, line-by-line transcription of
 * custody/src/signing.ts — feePayer, exactly one instruction, System Program, 12 bytes of data, tag
 * 2, keys[0] the payer, keys[1] the destination, non-zero lamports, destination not the payer, and
 * exactly one required signer which must be the vault. It is a copy of another repository's policy
 * and copies go stale, which is why it names the file and the reason for each line: when it goes
 * stale it should be obvious what to re-read.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import bs58 from 'bs58'
import { Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js'
import {
  MAX_LAMPORTS,
  SYSTEM_PROGRAM_ID,
  blockhashOf,
  encodeTransfer,
  solanaTxId,
  validateAddress,
} from './solana.ts'
import {
  AddressError,
  FeeOutOfBandError,
  InsufficientTreasuryError,
  UnsupportedDestinationError,
  type ChainCall,
} from './chains.ts'
import { chainFor, implementedChains } from './registry.ts'

/* ------------------------------------------------------------------ fixtures */

/** Deterministic keys, so a failure names the same account on every run. */
function key(seed: number): PublicKey {
  return new PublicKey(Buffer.alloc(32, seed))
}

const TREASURY = key(0x11).toBase58()
const USER = key(0x22).toBase58()
const PIN = key(0x33).toBase58()
const BLOCKHASH = key(0x44).toBase58()
/** 890,880 lamports: the rent-exempt minimum for a zero-data account under today's parameters. */
const RENT_EXEMPT = 890_880
const BASE_FEE = 5_000

const BOUNDS = { minGasPriceWei: 1n, maxGasPriceWei: 10n ** 12n, maxFeeWei: 10n ** 12n }

interface FakeSolNodeOptions {
  readonly balances?: Readonly<Record<string, number>>
  readonly fee?: number | null
  readonly blockHeight?: number
  readonly rentExempt?: number
  /** `signature → status entry`, as `getSignatureStatuses` reports it. */
  readonly statuses?: Readonly<Record<string, unknown>>
  readonly blockhashValid?: boolean
  readonly sendError?: string
  readonly noLastValidBlockHeight?: boolean
}

function fakeSolNode(options: FakeSolNodeOptions = {}): {
  call: ChainCall
  calls: string[]
  sent: string[]
} {
  const calls: string[] = []
  const sent: string[] = []
  const rpc = async (method: string, params: readonly unknown[]): Promise<unknown> => {
    calls.push(method)
    switch (method) {
      case 'getLatestBlockhash':
        return {
          context: { slot: 100 },
          value: options.noLastValidBlockHeight
            ? { blockhash: BLOCKHASH }
            : { blockhash: BLOCKHASH, lastValidBlockHeight: options.blockHeight ?? 5_000 },
        }
      case 'getFeeForMessage':
        return { context: { slot: 100 }, value: options.fee === null ? null : (options.fee ?? BASE_FEE) }
      case 'getBalance':
        return { context: { slot: 100 }, value: options.balances?.[String(params[0])] ?? 0 }
      case 'getMinimumBalanceForRentExemption':
        return options.rentExempt ?? RENT_EXEMPT
      case 'getSignatureStatuses': {
        const wanted = (params[0] as string[])[0]!
        return { context: { slot: 100 }, value: [options.statuses?.[wanted] ?? null] }
      }
      case 'isBlockhashValid':
        return { context: { slot: 100 }, value: options.blockhashValid ?? true }
      case 'sendTransaction': {
        if (options.sendError) throw new Error(options.sendError)
        const raw = String(params[0])
        sent.push(raw)
        return solanaTxId(raw)
      }
      default:
        throw new Error(`unexpected method ${method}`)
    }
  }
  return { call: { network: 'testnet', rpc }, calls, sent }
}

/**
 * Stand in for custody: sign the transaction and hand back the wire form `signSolana` returns.
 *
 * A REAL signature, from a real keypair, because two production functions read these bytes back —
 * `solanaTxId` derives the id the chain will know them by, and `blockhashOf` reads the fact an
 * operator refunds a user's money on. A stub string would let both be wrong invisibly.
 */
function signLikeCustody(base64Tx: string, signer: Keypair): string {
  const tx = Transaction.from(Buffer.from(base64Tx, 'base64'))
  tx.partialSign(signer)
  // `serialize()`'s defaults, which custody's comment calls load-bearing: `verifySignatures` stays
  // true, so a message that changed between inspection and signing fails here rather than shipping.
  return tx.serialize().toString('base64')
}

/**
 * custody/src/signing.ts `signSolana`, transcribed. Returns the destination it found.
 *
 * Every line names the check it stands for. If custody's policy moves, this is what must be
 * re-read — a copy of somebody else's rules is only honest while it says where it came from.
 */
function assertCustodyWouldSign(
  base64Tx: string,
  vault: PublicKey,
  policy: { shape: 'transfer' } | { shape: 'sweep'; treasuryPin: string },
): PublicKey {
  const tx = Transaction.from(Buffer.from(base64Tx, 'base64'))
  // "solana fee payer must be the vault address"
  assert.ok(tx.feePayer?.equals(vault), 'fee payer is not the vault address')
  // "a solana transfer must be exactly one instruction — nothing may ride alongside it"
  assert.equal(tx.instructions.length, 1, 'a transfer must be exactly one instruction')
  const ix = tx.instructions[0]!
  // "solana program … is not one this service signs transfers for"
  assert.ok(ix.programId instanceof PublicKey)
  assert.equal(ix.programId.toBase58(), SYSTEM_PROGRAM_ID)
  // "the only system-program instruction a solana transfer signs is Transfer" — 12 bytes, tag 2.
  assert.equal(ix.data.length, 12, 'System Transfer data is exactly a u32 tag and a u64')
  assert.equal(ix.data.readUInt32LE(0), 2, 'tag 2 is Transfer; 0 is createAccount')
  const from = ix.keys[0]?.pubkey
  const to = ix.keys[1]?.pubkey
  // "a solana Transfer must name a source and a destination"
  assert.ok(from && to)
  // "a solana Transfer must be funded by the vault address"
  assert.ok(from.equals(vault), 'keys[0] is not the vault address')
  // "a solana Transfer of zero lamports is not signed"
  assert.notEqual(ix.data.readBigUInt64LE(4), 0n)
  // "a solana Transfer to the vault address itself is not signed"
  assert.ok(!to.equals(vault))
  if (policy.shape === 'sweep') {
    // `assertSolanaSweepDestination`: compared as a DECODED key, not as a string.
    assert.ok(to.equals(new PublicKey(policy.treasuryPin)), 'keys[1] is not the pinned treasury')
  }
  // "a solana transfer must require exactly one signature, and it must be the vault address"
  assert.equal(tx.signatures.length, 1, 'exactly one required signer')
  assert.ok(tx.signatures[0]?.publicKey.equals(vault))
  // `partialSign` recompiles from `tx.instructions` and `serialize()` verifies — so if the bytes
  // inspected above are not the bytes that would ship, this throws rather than passing.
  const signer = Keypair.generate()
  assert.throws(() => Transaction.from(Buffer.from(base64Tx, 'base64')).partialSign(signer))
  return to
}

/* ------------------------------------------------------------------ the registry */

describe('the registry', () => {
  it('now reports sol as implemented, and only xrp as not', () => {
    // The previous entry said the blocker was "ENTIRELY CUSTODY-SIDE AND IT BLOCKS BOTH HALVES".
    // `SolanaPolicy` has a transfer shape and a pinned sweep shape now, so it blocks neither.
    assert.equal(chainFor('sol').unimplementedPhase, null)
    assert.deepEqual([...implementedChains()].sort(), ['btc', 'doge', 'ember', 'etc', 'eth', 'ltc', 'sol'])
    assert.match(String(chainFor('xrp').unimplementedPhase), /XRPL adapter/)
    // Dogecoin used to be named here as the second unimplemented chain, on the argument that its
    // blocker was on BOTH sides. Half of that was a claim about custody that had gone stale before
    // it was read, and the other half — this file's P2WPKH-only builder — is built. It is asserted
    // as IMPLEMENTED here rather than removed, so a list that loses it again has to say why.
    assert.equal(chainFor('doge').unimplementedPhase, null)
  })
})

/* ------------------------------------------------------------------ addresses */

describe('addresses', () => {
  it('accepts 32 bytes of base58 and refuses everything else', () => {
    assert.equal(validateAddress(TREASURY), TREASURY)
    assert.equal(validateAddress(` ${TREASURY} `), TREASURY)
    assert.throws(() => validateAddress(''), AddressError)
    // 31 bytes, 33 bytes, and a string that is not base58 at all.
    assert.throws(() => validateAddress(bs58.encode(Buffer.alloc(31, 1))), AddressError)
    assert.throws(() => validateAddress(bs58.encode(Buffer.alloc(33, 1))), AddressError)
    assert.throws(() => validateAddress('0OIl-not-base58'), AddressError)
  })

  it('does NOT case-fold, because base58 is case-significant', () => {
    // An EVM address has three valid spellings and custody accepts one. A Solana address has ONE,
    // and `toLowerCase` on it produces different bytes or nothing at all — so `addressKey` is the
    // identity here where EVM's is a case fold.
    const adapter = chainFor('sol')
    assert.equal(adapter.addressKey(TREASURY), TREASURY)
    assert.equal(adapter.canonicalise(TREASURY), TREASURY)
    const folded = TREASURY.toLowerCase()
    if (folded !== TREASURY) {
      assert.notEqual(adapter.addressKey(TREASURY), folded)
    }
  })

  it('refuses the system program as a destination, which is where value goes to die', () => {
    const adapter = chainFor('sol')
    assert.equal(adapter.isValidDestination(USER), true)
    assert.equal(adapter.isValidDestination(SYSTEM_PROGRAM_ID), false)
    assert.equal(adapter.isValidDestination('not an address'), false)
  })
})

/* ------------------------------------------------------------------ the transaction id */

describe('the transaction id', () => {
  /**
   * The base58 cross-check, and it is not a test asserting an encoder against itself.
   *
   * `bs58@6` is this repository's encoder; `PublicKey.toBase58` is `@solana/web3.js`'s own, which
   * reaches `bs58@4` inside the package custody signs with. Two independent copies of one encoding
   * agreeing on the whole byte range is what makes the id this service derives the id the chain
   * uses — and a status lookup by a wrong id finds nothing, for ever, in silence.
   */
  it('encodes base58 the way @solana/web3.js does, across the byte range', () => {
    for (const fill of [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]) {
      const bytes = Buffer.alloc(32, fill)
      assert.equal(bs58.encode(bytes), new PublicKey(bytes).toBase58(), `fill 0x${fill.toString(16)}`)
    }
    // Leading zero bytes are the case a naive big-integer encoder loses: they must survive as
    // leading '1's rather than being dropped.
    const leading = Buffer.concat([Buffer.alloc(3, 0), Buffer.alloc(29, 9)])
    assert.equal(bs58.encode(leading), new PublicKey(leading).toBase58())
    assert.ok(bs58.encode(leading).startsWith('111'))
  })

  it('is the first signature, and is a refusal rather than a guess when there is none', () => {
    const signer = Keypair.generate()
    const unsigned = encodeTransfer({
      from: signer.publicKey,
      to: key(0x22),
      value: 1_000n,
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 5_000n,
    })
    // Unsigned: the slot is present and all zeroes. An id of zeroes is not an id, so this is null.
    assert.equal(solanaTxId(unsigned), null)
    const signed = signLikeCustody(unsigned, signer)
    const id = solanaTxId(signed)
    assert.ok(id)
    assert.equal(id, bs58.encode(Transaction.from(Buffer.from(signed, 'base64')).signature!))
    assert.equal(solanaTxId('not base64 at all !!!'), null)
    assert.equal(chainFor('sol').txIdOf(signed), id)
  })

  it('reads the blockhash back out of the committed bytes', () => {
    const signer = Keypair.generate()
    const unsigned = encodeTransfer({
      from: signer.publicKey,
      to: key(0x22),
      value: 1_000n,
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 5_000n,
    })
    // Derived, not remembered: `signed_expiry` is for an operator to read and this is what the
    // death proof actually stands on, because a column beside the bytes can drift from them.
    assert.equal(blockhashOf(signLikeCustody(unsigned, signer)), BLOCKHASH)
    assert.equal(blockhashOf('nonsense'), null)
  })
})

/* ------------------------------------------------------------------ build */

describe('build', () => {
  it('produces bytes custody will sign for a WITHDRAWAL, checked against its policy', async () => {
    const signer = Keypair.generate()
    const from = signer.publicKey.toBase58()
    const node = fakeSolNode({ balances: { [from]: 10_000_000 } })
    const unsigned = await chainFor('sol').build(node.call, {
      from,
      to: USER,
      value: 1_000_000n,
      fee: BigInt(BASE_FEE),
      bounds: BOUNDS,
      shape: 'payment',
    })

    assert.equal(typeof unsigned.payload, 'string', 'signSolana takes a base64 transaction')
    const destination = assertCustodyWouldSign(String(unsigned.payload), signer.publicKey, {
      shape: 'transfer',
    })
    assert.equal(destination.toBase58(), USER)
    assert.equal(unsigned.value, 1_000_000n)
    assert.equal(unsigned.fee, BigInt(BASE_FEE))
    // Solana has no nonce and DOES have an expiry — the one adapter here that can fill it in.
    assert.equal(unsigned.nonce, null)
    assert.equal(unsigned.expiry, '5000')
  })

  it('produces bytes custody will sign for a SWEEP, with keys[1] equal to the pin', async () => {
    const signer = Keypair.generate()
    const from = signer.publicKey.toBase58()
    // A sweep leaves the account at exactly zero: value + fee is the whole balance.
    const node = fakeSolNode({ balances: { [from]: 1_005_000 } })
    const unsigned = await chainFor('sol').build(node.call, {
      from,
      to: PIN,
      value: 1_000_000n,
      fee: BigInt(BASE_FEE),
      bounds: BOUNDS,
      shape: 'sweep',
    })
    // The check custody's `sweep` shape adds over `transfer`, and the only one: keys[1] must be the
    // pinned treasury, compared as a decoded key.
    assertCustodyWouldSign(String(unsigned.payload), signer.publicKey, {
      shape: 'sweep',
      treasuryPin: PIN,
    })
    // And it is refused against a DIFFERENT pin, which is what makes the assertion mean something.
    assert.throws(() =>
      assertCustodyWouldSign(String(unsigned.payload), signer.publicKey, {
        shape: 'sweep',
        treasuryPin: USER,
      }),
    )
  })

  it('carries an exact u64 amount, because a double would round one', async () => {
    const signer = Keypair.generate()
    const from = signer.publicKey.toBase58()
    // Past Number.MAX_SAFE_INTEGER. One SOL is 1e9 lamports, so this is ~9.9M SOL — larger than
    // anything here holds, and exactly the amount a `Number()` on the path would silently corrupt.
    const value = 9_876_543_210_987_654_321n
    const node = fakeSolNode({})
    const wire = encodeTransfer({
      from: signer.publicKey,
      to: key(0x22),
      value,
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 5_000n,
    })
    const ix = Transaction.from(Buffer.from(wire, 'base64')).instructions[0]!
    assert.equal(ix.data.readBigUInt64LE(4), value, 'the lamport count did not survive encoding')
    assert.equal(node.calls.length, 0)
  })

  it('refuses a zero or oversized amount before the node is asked anything', async () => {
    const node = fakeSolNode({})
    for (const value of [0n, -1n, MAX_LAMPORTS + 1n]) {
      await assert.rejects(
        chainFor('sol').build(node.call, {
          from: TREASURY,
          to: USER,
          value,
          fee: BigInt(BASE_FEE),
          bounds: BOUNDS,
          shape: 'payment',
        }),
        FeeOutOfBandError,
      )
    }
    assert.equal(node.calls.length, 0, 'a permanent property of the row costs no round trips')
  })

  it('refuses a destination custody would refuse: the source itself, and the system program', async () => {
    const node = fakeSolNode({ balances: { [TREASURY]: 10_000_000 } })
    for (const to of [TREASURY, SYSTEM_PROGRAM_ID]) {
      await assert.rejects(
        chainFor('sol').build(node.call, {
          from: TREASURY,
          to,
          value: 1_000n,
          fee: BigInt(BASE_FEE),
          bounds: BOUNDS,
          shape: 'payment',
        }),
        UnsupportedDestinationError,
      )
    }
  })

  it('fails early and specifically when the source cannot cover it', async () => {
    const node = fakeSolNode({ balances: { [TREASURY]: 100 } })
    await assert.rejects(
      chainFor('sol').build(node.call, {
        from: TREASURY,
        to: USER,
        value: 1_000_000n,
        fee: BigInt(BASE_FEE),
        bounds: BOUNDS,
        shape: 'payment',
      }),
      InsufficientTreasuryError,
    )
  })

  /**
   * **THE RENT BAND**, which is the Solana-specific way to build a transaction that cannot land.
   *
   * An account driven to exactly zero is deleted and that is fine. One left alive below the
   * rent-exempt minimum is not: the runtime rejects the whole transaction with
   * `InsufficientFundsForRent`, so the payment burns nothing and delivers nothing, and the only
   * symptom is a broadcast that keeps failing.
   */
  it('refuses to leave the source alive and below the rent-exempt minimum', async () => {
    const balance = 2_000_000
    const fee = BASE_FEE
    // Leaves 100 lamports: non-zero, and far below 890,880.
    const stranding = BigInt(balance - fee - 100)
    const node = fakeSolNode({ balances: { [TREASURY]: balance } })
    await assert.rejects(
      chainFor('sol').build(node.call, {
        from: TREASURY,
        to: USER,
        value: stranding,
        fee: BigInt(fee),
        bounds: BOUNDS,
        shape: 'payment',
      }),
      InsufficientTreasuryError,
    )

    // Exactly zero is allowed — the account is deleted, which is what a sweep does every time.
    const empty = await chainFor('sol').build(node.call, {
      from: TREASURY,
      to: USER,
      value: BigInt(balance - fee),
      fee: BigInt(fee),
      bounds: BOUNDS,
      shape: 'payment',
    })
    assert.equal(empty.value, BigInt(balance - fee))

    // And so is leaving the reserve behind.
    const keeping = await chainFor('sol').build(node.call, {
      from: TREASURY,
      to: USER,
      value: BigInt(balance - fee - RENT_EXEMPT),
      fee: BigInt(fee),
      bounds: BOUNDS,
      shape: 'payment',
    })
    assert.equal(keeping.value, BigInt(balance - fee - RENT_EXEMPT))
  })

  it('refuses a node that will not publish a lastValidBlockHeight', async () => {
    // Without it there is no death proof at all, and a signature nobody can ever prove dead is a
    // payment stuck until an engineer reads the row.
    const node = fakeSolNode({ balances: { [TREASURY]: 10_000_000 }, noLastValidBlockHeight: true })
    await assert.rejects(
      chainFor('sol').build(node.call, {
        from: TREASURY,
        to: USER,
        value: 1_000n,
        fee: BigInt(BASE_FEE),
        bounds: BOUNDS,
        shape: 'payment',
      }),
      AddressError,
    )
  })
})

/* ------------------------------------------------------------------ fees and balances */

describe('fees and balances', () => {
  it('asks the node what a signature costs rather than writing 5000 down', async () => {
    const node = fakeSolNode({ fee: 7_500 })
    assert.equal(await chainFor('sol').estimateFee(node.call, BOUNDS), 7_500n)
    assert.ok(node.calls.includes('getFeeForMessage'))
  })

  it('refuses rather than guessing when the node cannot price one', async () => {
    // Ordinary blockhash expiry: the next tick asks again. A number made up here is a fee quoted to
    // a user that the chain does not charge.
    const node = fakeSolNode({ fee: null })
    await assert.rejects(chainFor('sol').estimateFee(node.call, BOUNDS), AddressError)
  })

  it('holds back the rent-exempt reserve from a spendable balance', async () => {
    const node = fakeSolNode({ balances: { [TREASURY]: 5_000_000 } })
    assert.equal(await chainFor('sol').spendableBalance(node.call, TREASURY), 5_000_000n - BigInt(RENT_EXEMPT))
    // Below the reserve, nothing is spendable — the account cannot pay anything and stay alive.
    const poor = fakeSolNode({ balances: { [TREASURY]: 1_000 } })
    assert.equal(await chainFor('sol').spendableBalance(poor.call, TREASURY), 0n)
  })

  it('quotes a sweep at the WHOLE balance, reserve included, because the account is closed', async () => {
    // The one place the reserve is deliberately not held back. A swept deposit address is meant to
    // be emptied; holding back 890,880 lamports on every one would strand the reserve for ever on
    // addresses whose whole purpose was to be emptied.
    const node = fakeSolNode({ balances: { [TREASURY]: 5_000_000 } })
    const quote = await chainFor('sol').sweepQuote(node.call, TREASURY, BOUNDS)
    assert.ok(quote)
    assert.equal(quote.value + quote.fee, 5_000_000n)
    assert.equal(quote.fee, BigInt(BASE_FEE))
  })

  it('answers null rather than throwing when a sweep is not worth making', async () => {
    const node = fakeSolNode({ balances: { [TREASURY]: BASE_FEE } })
    assert.equal(await chainFor('sol').sweepQuote(node.call, TREASURY, BOUNDS), null)
  })

  it('refuses a lamport count no JSON number carries exactly', async () => {
    // 2^53 + 1. Reading it as a Number silently gives 2^53, and a balance that is quietly wrong is
    // a transaction built on money that is not there.
    const node = fakeSolNode({ balances: { [TREASURY]: 9_007_199_254_740_993 } })
    await assert.rejects(chainFor('sol').spendableBalance(node.call, TREASURY), AddressError)
  })
})

/* ------------------------------------------------------------------ status */

describe('status', () => {
  const SIG = bs58.encode(Buffer.alloc(64, 3))

  it('is unknown for a signature no node has, and never rejected', async () => {
    // Unknown and rejected are not the same conversation: rejected refunds, and refunding a payment
    // that is merely propagating credits a user money that has left the treasury.
    const node = fakeSolNode({})
    assert.deepEqual(await chainFor('sol').status(node.call, SIG), { kind: 'unknown' })
  })

  it('searches transaction history, because a status cache covers only the last few hundred slots', async () => {
    const node = fakeSolNode({})
    await chainFor('sol').status(node.call, SIG)
    assert.ok(node.calls.includes('getSignatureStatuses'))
  })

  /**
   * **FINALITY, NOT DEPTH.** `confirmations: null` means rooted, which cannot be reorganised at any
   * distance — the strongest answer there is. A depth-counting adapter reads it as zero and resets
   * a payment that is already final to the beginning of its count.
   */
  it('reads a null confirmation count as final rather than as zero', async () => {
    const node = fakeSolNode({
      statuses: { [SIG]: { slot: 77, confirmations: null, err: null, confirmationStatus: 'finalized' } },
    })
    const status = await chainFor('sol').status(node.call, SIG)
    assert.equal(status.kind, 'confirmed')
    assert.equal(status.kind === 'confirmed' && status.minedHeight, 77n)
  })

  it('crosses from pending to confirmed at the depth contracts-chain declares', async () => {
    for (const [confirmations, kind] of [
      [0, 'pending'],
      [31, 'pending'],
      [32, 'confirmed'],
    ] as const) {
      const node = fakeSolNode({
        statuses: { [SIG]: { slot: 77, confirmations, err: null, confirmationStatus: 'confirmed' } },
      })
      const status = await chainFor('sol').status(node.call, SIG)
      assert.equal(status.kind, kind, `${confirmations} confirmations should be ${kind}`)
    }
  })

  it('reports a landed-and-failed transaction as rejected, which is the one automatic refund', async () => {
    // Solana needs this branch for the same reason EVM does and Bitcoin does not: an invalid
    // Bitcoin transaction never enters a block, but a Solana one can land, burn the fee and abort.
    const node = fakeSolNode({
      statuses: { [SIG]: { slot: 77, confirmations: 1, err: { InstructionError: [0, 'Custom'] } } },
    })
    const status = await chainFor('sol').status(node.call, SIG)
    assert.equal(status.kind, 'rejected')
    assert.match(status.kind === 'rejected' ? status.reason : '', /nothing was transferred/)
  })
})

/* ------------------------------------------------------------------ broadcast */

describe('broadcast', () => {
  function signedBytes(): { raw: string; id: string } {
    const signer = Keypair.generate()
    const raw = signLikeCustody(
      encodeTransfer({
        from: signer.publicKey,
        to: key(0x22),
        value: 1_000n,
        blockhash: BLOCKHASH,
        lastValidBlockHeight: 5_000n,
      }),
      signer,
    )
    return { raw, id: solanaTxId(raw)! }
  }

  it('sends base64 with preflight on and no node-side retries', async () => {
    const { raw, id } = signedBytes()
    const node = fakeSolNode({})
    assert.equal(await chainFor('sol').broadcast(node.call, raw), id)
    assert.deepEqual(node.sent, [raw])
  })

  it('treats an already-processed transaction as success, because retry is the normal case', async () => {
    const { raw, id } = signedBytes()
    const again = fakeSolNode({
      sendError: 'failed to send transaction: This transaction has already been processed',
    })
    assert.equal(await chainFor('sol').broadcast(again.call, raw), id)
    // A real failure is still a failure.
    const broken = fakeSolNode({ sendError: 'Blockhash not found' })
    await assert.rejects(chainFor('sol').broadcast(broken.call, raw))
  })

  it('refuses to broadcast bytes that carry no signature', async () => {
    const signer = Keypair.generate()
    const unsigned = encodeTransfer({
      from: signer.publicKey,
      to: key(0x22),
      value: 1_000n,
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 5_000n,
    })
    await assert.rejects(chainFor('sol').broadcast(fakeSolNode({}).call, unsigned))
  })
})

/* ------------------------------------------------------------------ proveDead */

describe('proveDead', () => {
  function signedBytes(): { raw: string; id: string } {
    const signer = Keypair.generate()
    const raw = signLikeCustody(
      encodeTransfer({
        from: signer.publicKey,
        to: key(0x22),
        value: 1_000n,
        blockhash: BLOCKHASH,
        lastValidBlockHeight: 5_000n,
      }),
      signer,
    )
    return { raw, id: solanaTxId(raw)! }
  }

  it('refuses to refund while the payment is on chain', async () => {
    const { raw, id } = signedBytes()
    const node = fakeSolNode({
      statuses: { [id]: { slot: 77, confirmations: 3, err: null, confirmationStatus: 'confirmed' } },
    })
    const verdict = await chainFor('sol').proveDead(node.call, {
      from: TREASURY,
      rawTx: raw,
      txHash: id,
      signedNonce: null,
      signedExpiry: '5000',
    })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.code, 'on_chain')
  })

  it('refuses to refund while the blockhash is still in the recent queue', async () => {
    // The Solana analogue of "the nonce is still available": any node holding these bytes can
    // include them at any time, so a refund now can be followed by the payment landing.
    const { raw } = signedBytes()
    const node = fakeSolNode({ blockhashValid: true })
    const verdict = await chainFor('sol').proveDead(node.call, {
      from: TREASURY,
      rawTx: raw,
      txHash: null,
      signedNonce: null,
      signedExpiry: '5000',
    })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.code, 'still_applicable')
  })

  it('PROVES death once the blockhash has aged out of the queue', async () => {
    // The cleanest of the three death proofs: nothing has to be retired and no conflicting spend
    // has to exist. The chain simply says the bytes can never be included.
    const { raw } = signedBytes()
    const node = fakeSolNode({ blockhashValid: false })
    const verdict = await chainFor('sol').proveDead(node.call, {
      from: TREASURY,
      rawTx: raw,
      txHash: null,
      signedNonce: null,
      signedExpiry: '5000',
    })
    assert.equal(verdict.ok, true)
    assert.match(verdict.ok === true ? verdict.proof : '', /aged out of the recent-blockhash queue/)
  })

  it('says unprovable rather than refunding on bytes it cannot read', async () => {
    // An absence of evidence never refunds.
    const node = fakeSolNode({ blockhashValid: false })
    const verdict = await chainFor('sol').proveDead(node.call, {
      from: TREASURY,
      rawTx: 'not a transaction',
      txHash: null,
      signedNonce: null,
      signedExpiry: null,
    })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.code, 'unprovable')
  })

  it('refunds on the chain own word when the transaction landed and failed', async () => {
    const { raw, id } = signedBytes()
    const node = fakeSolNode({
      statuses: { [id]: { slot: 77, confirmations: 1, err: { InstructionError: [0, 'Custom'] } } },
    })
    const verdict = await chainFor('sol').proveDead(node.call, {
      from: TREASURY,
      rawTx: raw,
      txHash: null,
      signedNonce: null,
      signedExpiry: '5000',
    })
    assert.equal(verdict.ok, true)
  })
})

/* ------------------------------------------------------------------ the encoder, negatively */

describe('what this service never asks custody to sign', () => {
  /**
   * SPL Transfer is refused under all three of custody's shapes and this service has no use for it.
   * The assertion is that nothing here can produce one: the only instruction `encodeTransfer` emits
   * is the System Program's, and it is the only encoder in this file.
   */
  it('emits the System Program and nothing else', () => {
    const signer = Keypair.generate()
    const wire = encodeTransfer({
      from: signer.publicKey,
      to: key(0x22),
      value: 1n,
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 5_000n,
    })
    const tx = Transaction.from(Buffer.from(wire, 'base64'))
    assert.deepEqual(
      tx.instructions.map((ix) => ix.programId.toBase58()),
      [SYSTEM_PROGRAM_ID],
    )
  })

  /**
   * And a batch is refused by custody outright, so this shows what one would look like if this
   * service ever produced one — the check is `!== 1`, not `<= 8`, under both transfer shapes.
   */
  it('would be refused if a second instruction ever rode alongside', () => {
    const signer = Keypair.generate()
    const tx = Transaction.from(
      Buffer.from(
        encodeTransfer({
          from: signer.publicKey,
          to: key(0x22),
          value: 1n,
          blockhash: BLOCKHASH,
          lastValidBlockHeight: 5_000n,
        }),
        'base64',
      ),
    )
    tx.add(SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: key(0x55), lamports: 1n }))
    const batched = tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64')
    assert.throws(
      () => assertCustodyWouldSign(batched, signer.publicKey, { shape: 'transfer' }),
      /exactly one instruction/,
    )
  })
})
