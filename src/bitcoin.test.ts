/**
 * The Bitcoin adapter, without a database and without a network.
 *
 * The PSBTs built here are decoded back with the same library custody decodes with, and asserted
 * against the things `signBitcoin` actually checks — every input a P2WPKH output of the signing
 * address, every input carrying a `witnessUtxo`, and SIGHASH_ALL. That is the closest a test on
 * this side can get to "custody will sign this" without a key, and it is the check that matters:
 * bytes custody refuses are bytes that fail after a row is committed and money is in flight.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import * as bitcoin from 'bitcoinjs-lib'
import { chainSpec } from '@cloudsforge/contracts-chain'
import {
  CUSTODY_MAX_PAYMENT_SAT_PER_VB,
  CUSTODY_MAX_SWEEP_SAT_PER_VB,
  MAX_SAT_PER_VB,
  MAX_SWEEP_SAT_PER_VB,
  addressKindFor,
  assertUnderCustodysCeiling,
  bitcoinChain,
  btcToSats,
  buildSweepPsbt,
  ceilingsFor,
  custodyCeilings,
  finalisedVsize,
  networkFor,
  satsToBtc,
  selectCoins,
  sweepPlan,
  validateAddress,
  vsizeOf,
  type BitcoinFamilyChainId,
  type Utxo,
} from './bitcoin.ts'
import {
  AddressError,
  CUSTODY_CHAIN_DOGE,
  FeeOutOfBandError,
  InsufficientTreasuryError,
  assetOf,
  chainForAsset,
  custodyChainOf,
  custodyFamilyOf,
  type ChainCall,
} from './chains.ts'
import { chainFor, implementedChains } from './registry.ts'

/* ------------------------------------------------------------------ fixtures */

const TESTNET = bitcoin.networks.testnet

/** A deterministic P2WPKH testnet address, derived rather than hard-coded so it is really valid. */
function p2wpkh(seed: number): string {
  const hash = Buffer.alloc(20, seed)
  const address = bitcoin.payments.p2wpkh({ hash, network: TESTNET }).address
  if (!address) throw new Error('could not derive a test address')
  return address
}

const TREASURY = p2wpkh(0x11)
const USER = p2wpkh(0x22)
const OTHER = p2wpkh(0x33)
/** A real mainnet address, for the cross-network binding test. */
const MAINNET_ADDRESS = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'

interface FakeUtxo {
  readonly txid: string
  readonly vout: number
  readonly sats: bigint
  readonly confirmations?: number
}

interface FakeBtcNodeOptions {
  readonly utxos?: readonly FakeUtxo[]
  /** BTC per kvB, as `estimatesmartfee` reports it. Absent means the node cannot estimate. */
  readonly feerate?: number | null
  readonly height?: number
  readonly confirmationsByTxid?: Readonly<Record<string, number>>
  /** Outpoints `gettxout` still reports, as `txid:vout`. Anything else has been spent. */
  readonly unspent?: readonly string[]
  readonly sendError?: string
}

function fakeBtcNode(options: FakeBtcNodeOptions = {}): {
  call: ChainCall
  broadcast: string[]
  calls: string[]
} {
  const broadcast: string[] = []
  const calls: string[] = []
  const utxos = options.utxos ?? []
  const height = options.height ?? 800_000

  const rpc = async (method: string, params: readonly unknown[]): Promise<unknown> => {
    calls.push(method)
    switch (method) {
      case 'estimatesmartfee':
        return options.feerate === null || options.feerate === undefined
          ? {}
          : { feerate: options.feerate, blocks: 3 }
      case 'listunspent': {
        const minConf = Number(params[0])
        return utxos
          .filter((u) => (u.confirmations ?? 6) >= minConf)
          .map((u) => ({
            txid: u.txid,
            vout: u.vout,
            amount: satsToBtc(u.sats),
            scriptPubKey: bitcoin.address.toOutputScript(TREASURY, TESTNET).toString('hex'),
            confirmations: u.confirmations ?? 6,
            spendable: true,
          }))
      }
      case 'getblockcount':
        return height
      case 'getrawtransaction': {
        const txid = String(params[0])
        const confirmations = options.confirmationsByTxid?.[txid]
        if (confirmations === undefined) throw new Error('-5: No such mempool or blockchain transaction')
        return { txid, confirmations }
      }
      case 'gettxout': {
        const key = `${String(params[0])}:${String(params[1])}`
        return (options.unspent ?? []).includes(key) ? { value: 1, confirmations: 10 } : null
      }
      case 'sendrawtransaction': {
        if (options.sendError) throw new Error(options.sendError)
        const hex = String(params[0])
        broadcast.push(hex)
        return bitcoin.Transaction.fromHex(hex).getId()
      }
      default:
        throw new Error(`unexpected method ${method}`)
    }
  }
  return { call: { network: 'testnet', rpc }, broadcast, calls }
}

const BOUNDS = { minGasPriceWei: 1n, maxGasPriceWei: 10n ** 12n, maxFeeWei: 10n ** 12n }

const utxo = (n: number, sats: bigint, confirmations = 6): FakeUtxo & Utxo => ({
  txid: String(n).padStart(64, '0'),
  vout: 0,
  sats,
  confirmations,
  scriptPubKey: bitcoin.address.toOutputScript(TREASURY, TESTNET).toString('hex'),
})

/**
 * Stand in for custody: finalise a PSBT into the raw transaction hex `signBitcoin` hands back.
 *
 * Built from the PSBT's public inputs and outputs rather than by reaching into its cache, so this
 * exercises the same surface a real signer would and does not depend on library internals. The
 * witnesses are fake — no key exists in this repository — but they are the right SIZE, which is
 * what the vsize and therefore the fee assertions depend on.
 */
function finaliseLikeCustody(psbtBase64: string): bitcoin.Transaction {
  const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: TESTNET })
  const tx = new bitcoin.Transaction()
  psbt.txInputs.forEach((input, i) => {
    tx.addInput(input.hash, input.index, input.sequence)
    tx.setWitness(i, [Buffer.alloc(72, 1), Buffer.alloc(33, 2)])
  })
  for (const output of psbt.txOutputs) tx.addOutput(output.script, output.value)
  return tx
}

/* ------------------------------------------------------------------ amounts and sizes */

describe('amounts', () => {
  it('recovers every satoshi from the double Core serialised it as', () => {
    assert.equal(btcToSats(0), 0n)
    assert.equal(btcToSats(0.00000001), 1n)
    assert.equal(btcToSats(1), 100_000_000n)
    assert.equal(btcToSats(21_000_000), 2_100_000_000_000_000n)
    assert.equal(btcToSats(0.1 + 0.2), 30_000_000n, 'the canonical float complaint, round-tripped')
    for (const sats of [1n, 7n, 12_345_678n, 99_999_999n, 1_999_999_999_999_999n]) {
      assert.equal(btcToSats(satsToBtc(sats)), sats, `${sats} did not survive`)
    }
  })

  it('refuses anything it cannot vouch for rather than crediting a guess', () => {
    for (const bad of [null, undefined, '1', Number.NaN, Number.POSITIVE_INFINITY, -1, 21_000_001]) {
      assert.throws(() => btcToSats(bad), AddressError, `${String(bad)} was accepted`)
    }
  })
})

describe('transaction size', () => {
  it('matches what a real P2WPKH spend actually serialises to', () => {
    // The size drives the fee, so a wrong constant is a systematically wrong fee on every payment.
    // Building the real transaction and measuring it is the only check worth having.
    for (const [inputs, outputs] of [
      [1, 1],
      [1, 2],
      [3, 2],
      [5, 1],
    ] as const) {
      const tx = new bitcoin.Transaction()
      for (let i = 0; i < inputs; i++) {
        tx.addInput(Buffer.alloc(32, i + 1), 0)
        // A P2WPKH witness: a 71-72 byte signature and a 33 byte compressed pubkey.
        tx.setWitness(i, [Buffer.alloc(72, 1), Buffer.alloc(33, 2)])
      }
      for (let o = 0; o < outputs; o++) {
        tx.addOutput(bitcoin.address.toOutputScript(TREASURY, TESTNET), 1_000)
      }
      const actual = tx.virtualSize()
      const predicted = vsizeOf(inputs, outputs)
      assert.ok(
        predicted >= actual && predicted - actual <= 2,
        `${inputs}-in ${outputs}-out: predicted ${predicted}, real ${actual} — must be an upper bound and tight`,
      )
    }
  })
})

/* ------------------------------------------------------------------ addresses */

describe('addresses', () => {
  it('binds an address to its network in BOTH directions', () => {
    assert.equal(validateAddress('btc', TREASURY, 'testnet'), TREASURY)
    assert.equal(validateAddress('btc', MAINNET_ADDRESS, 'mainnet'), MAINNET_ADDRESS)
    // The binding that stops a payment being broadcastable on the chain it was not meant for.
    assert.throws(() => validateAddress('btc', MAINNET_ADDRESS, 'testnet'), AddressError)
    assert.throws(() => validateAddress('btc', TREASURY, 'mainnet'), AddressError)
  })

  it('does NOT case-normalise, because base58check is case-significant', () => {
    // Lower-casing this produces a string that fails its own checksum and is not the address.
    assert.equal(chainFor('btc').canonicalise(MAINNET_ADDRESS), MAINNET_ADDRESS)
    assert.equal(chainFor('btc').addressKey(MAINNET_ADDRESS), MAINNET_ADDRESS)
    assert.throws(() => chainFor('btc').canonicalise(MAINNET_ADDRESS.toLowerCase()), AddressError)
  })

  it('refuses a checksum failure and an empty string', () => {
    assert.throws(() => validateAddress('btc', '', 'testnet'), AddressError)
    assert.throws(() => validateAddress('btc', 'tb1qnotanaddress', 'testnet'), AddressError)
    assert.throws(
      () => validateAddress('btc', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3', 'mainnet'),
      AddressError,
    )
  })
})

/* ------------------------------------------------------------------ coin selection */

describe('coin selection', () => {
  it('takes the largest coins first and charges for every input it adds', () => {
    const utxos = [utxo(1, 100_000n), utxo(2, 50_000n), utxo(3, 10_000n)].sort((a, b) =>
      a.sats > b.sats ? -1 : 1,
    )
    const selection = selectCoins(utxos, 120_000n, 10n, 546n)
    assert.equal(selection.inputs.length, 2, 'one coin cannot cover it, two can')
    // The fee is the real size of the real selection, not a fixed guess.
    assert.equal(selection.fee, 10n * BigInt(vsizeOf(2, 2)))
    assert.equal(
      selection.inputs.reduce((s, u) => s + u.sats, 0n),
      120_000n + selection.fee + selection.change,
      'inputs must equal outputs plus fee, exactly',
    )
  })

  it('gives dust change to the miner instead of creating an unspendable output', () => {
    // Chosen so the change after a two-output fee is under the dust threshold.
    const feeWithChange = 10n * BigInt(vsizeOf(1, 2))
    const target = 100_000n - feeWithChange - 100n
    const selection = selectCoins([utxo(1, 100_000n)], target, 10n, 546n)
    assert.equal(selection.change, 0n, 'a 100-satoshi output costs more to spend than it holds')
    assert.equal(selection.inputs.length, 1)
    assert.equal(
      selection.fee,
      100_000n - target,
      'the difference goes to the fee, so the arithmetic still balances',
    )
  })

  it('refuses rather than underpaying when the coins cannot cover the fee too', () => {
    // Enough for the value and not for the value plus its own fee — the case an implementation
    // that fixes the fee up at the end gets wrong, producing a transaction that never mines.
    assert.throws(
      () => selectCoins([utxo(1, 100_000n)], 99_999n, 50n, 546n),
      InsufficientTreasuryError,
    )
    assert.throws(() => selectCoins([], 1n, 1n, 546n), InsufficientTreasuryError)
  })

  it('is deterministic, so a rebuild after a crash selects the same coins', () => {
    // Two transactions spending overlapping inputs for one payment is the failure the in-flight
    // lease exists to prevent; a selection that depended on node iteration order would cause it.
    const utxos = [utxo(3, 50_000n), utxo(1, 50_000n), utxo(2, 50_000n)]
    const a = selectCoins([...utxos].sort((x, y) => x.txid.localeCompare(y.txid)), 90_000n, 5n, 546n)
    const b = selectCoins([...utxos].sort((x, y) => x.txid.localeCompare(y.txid)), 90_000n, 5n, 546n)
    assert.deepEqual(
      a.inputs.map((u) => `${u.txid}:${u.vout}`),
      b.inputs.map((u) => `${u.txid}:${u.vout}`),
    )
  })
})

/* ------------------------------------------------------------------ the adapter */

describe('the registry', () => {
  it('reports btc as implemented', () => {
    assert.equal(chainFor('btc').unimplementedPhase, null)
    assert.ok(implementedChains().includes('btc'))
  })
})

/* ------------------------------------------------------------------ the two fee ceilings */

/**
 * **THE RELATIONSHIP BETWEEN THIS SERVICE'S CEILINGS AND CUSTODY'S, PINNED AS A NUMBER.**
 *
 * Two constants that happen to differ is not a policy. What has to hold is that **no PSBT this
 * service is willing to build can be one custody refuses**, and that is not implied by
 * `900 < 1000`: custody measures the fee rate of the FINALISED transaction and this service quotes
 * against `vsizeOf`, which is an upper bound on the size and therefore a LOWER bound on the rate.
 * A smaller transaction is a higher rate, so the margin has to cover the difference.
 *
 * So the assertion is the worst case, computed rather than asserted about: build at this service's
 * own ceiling, measure the rate custody would see, and require it to stay under custody's for every
 * input count a real sweep could have. Move either constant and this goes red.
 */
describe('the fee ceilings', () => {
  it('is a mirror of custody and the mirror is strictly tighter', () => {
    assert.ok(
      MAX_SWEEP_SAT_PER_VB < CUSTODY_MAX_SWEEP_SAT_PER_VB,
      'this service must refuse before custody does, so the failure is a build failure not a 403',
    )
    assert.ok(MAX_SAT_PER_VB < CUSTODY_MAX_PAYMENT_SAT_PER_VB)
    // The sweep ceiling is the tighter of the two here, as it is in custody: pinning the
    // destination stops a sweep paying an attacker, it does not stop it paying the miner, and the
    // credential that bounds it is the one this service holds.
    assert.ok(MAX_SWEEP_SAT_PER_VB < MAX_SAT_PER_VB)
    assert.ok(CUSTODY_MAX_SWEEP_SAT_PER_VB < CUSTODY_MAX_PAYMENT_SAT_PER_VB)
  })

  it('leaves margin for every input count a real sweep could have', () => {
    for (let inputs = 1; inputs <= 50; inputs += 1) {
      // What this service would charge at its own ceiling, for the size it predicts.
      const fee = MAX_SWEEP_SAT_PER_VB * BigInt(vsizeOf(inputs, 1))
      // What custody would measure, against the SMALLEST transaction it could finalise.
      const psbt = new bitcoin.Psbt({ network: TESTNET })
      for (let i = 0; i < inputs; i += 1) {
        psbt.addInput({
          hash: Buffer.alloc(32, i + 1),
          index: 0,
          witnessUtxo: { script: bitcoin.address.toOutputScript(TREASURY, TESTNET), value: 1_000_000 },
        })
      }
      psbt.addOutput({ address: OTHER, value: 1_000 })
      const measured = fee / BigInt(finalisedVsize(psbt))
      assert.ok(
        measured < CUSTODY_MAX_SWEEP_SAT_PER_VB,
        `${inputs} inputs: custody would measure ${measured} sat/vB against its ${CUSTODY_MAX_SWEEP_SAT_PER_VB} ceiling`,
      )
    }
  })

  it('clamps the node quote to the ceiling for the SHAPE, not one ceiling for both', async () => {
    // A node quoting 0.05 BTC/kvB is 5,000 sat/vB. A payment is clamped to this service's payment
    // ceiling; a sweep is clamped five times tighter, because that is where custody's bites.
    const node = fakeBtcNode({ utxos: [utxo(1, 500_000_000n)], feerate: 0.05 })
    const payment = await chainFor('btc').estimateFee(node.call, BOUNDS)
    assert.equal(payment, MAX_SAT_PER_VB * BigInt(vsizeOf(1, 2)))

    const sweep = await chainFor('btc').sweepQuote(node.call, TREASURY, BOUNDS)
    assert.ok(sweep)
    assert.equal(sweep.fee, MAX_SWEEP_SAT_PER_VB * BigInt(vsizeOf(1, 1)))
  })

  /**
   * The guard that reproduces custody's own comparison, exercised on a PSBT that trips it.
   *
   * The clamp above means production cannot normally reach here — which is exactly why it is worth
   * having, and exactly why it has to be shown firing. A check whose only evidence is that it never
   * fires is a check nobody knows works.
   */
  it('refuses a PSBT whose finalised fee rate reaches custody ceiling', () => {
    const psbt = new bitcoin.Psbt({ network: TESTNET })
    psbt.addInput({
      hash: Buffer.alloc(32, 1),
      index: 0,
      witnessUtxo: { script: bitcoin.address.toOutputScript(TREASURY, TESTNET), value: 10_000_000 },
    })
    psbt.addOutput({ address: OTHER, value: 1_000 })
    const vsize = BigInt(finalisedVsize(psbt))

    // Exactly at the ceiling. custody compares `>=`, so this is refused and one satoshi per vbyte
    // less is not — the boundary is the whole point.
    assert.throws(
      () => assertUnderCustodysCeiling(psbt, CUSTODY_MAX_SWEEP_SAT_PER_VB * vsize, 'sweep'),
      FeeOutOfBandError,
    )
    assert.doesNotThrow(() =>
      assertUnderCustodysCeiling(psbt, (CUSTODY_MAX_SWEEP_SAT_PER_VB - 1n) * vsize, 'sweep'),
    )
    // The payment ceiling is the looser one, so the same fee passes under it.
    assert.doesNotThrow(() =>
      assertUnderCustodysCeiling(psbt, CUSTODY_MAX_SWEEP_SAT_PER_VB * vsize, 'payment'),
    )
    assert.throws(
      () => assertUnderCustodysCeiling(psbt, CUSTODY_MAX_PAYMENT_SAT_PER_VB * vsize, 'payment'),
      FeeOutOfBandError,
    )
  })

  it('measures against the SMALLEST transaction custody could finalise, never the largest', () => {
    // `vsizeOf` is an upper bound and `finalisedVsize` must not exceed it — if it did, the guard
    // would be dividing by a bigger number than custody uses and would let through a PSBT custody
    // refuses, which is the one direction that must not happen.
    for (const [inputs, outputs] of [
      [1, 1],
      [2, 1],
      [3, 2],
      [7, 1],
    ] as const) {
      const psbt = new bitcoin.Psbt({ network: TESTNET })
      for (let i = 0; i < inputs; i += 1) {
        psbt.addInput({
          hash: Buffer.alloc(32, i + 1),
          index: 0,
          witnessUtxo: { script: bitcoin.address.toOutputScript(TREASURY, TESTNET), value: 1_000_000 },
        })
      }
      for (let o = 0; o < outputs; o += 1) psbt.addOutput({ address: OTHER, value: 1_000 })
      assert.ok(
        finalisedVsize(psbt) <= vsizeOf(inputs, outputs),
        `${inputs}-in ${outputs}-out: the guard must divide by no more than the quote assumed`,
      )
    }
  })
})

describe('build', () => {
  it('produces a PSBT custody will accept: own-script inputs, witnessUtxo, SIGHASH_ALL', async () => {
    const node = fakeBtcNode({ utxos: [utxo(1, 500_000n), utxo(2, 300_000n)], feerate: 0.0001 })
    const unsigned = await chainFor('btc').build(node.call, {
      from: TREASURY,
      to: USER,
      value: 600_000n,
      fee: 100_000n,
      bounds: BOUNDS,
          shape: 'payment',
    })

    assert.equal(typeof unsigned.payload, 'string', 'signBitcoin takes a base64 PSBT, not an object')
    const psbt = bitcoin.Psbt.fromBase64(String(unsigned.payload), { network: TESTNET })
    const ownScript = bitcoin.address.toOutputScript(TREASURY, TESTNET)

    assert.equal(psbt.inputCount, 2, 'one coin cannot cover 600,000 plus fee')
    psbt.data.inputs.forEach((input, i) => {
      // Each of these is a thing signBitcoin refuses. Asserting them here is what turns a
      // late 403 with money in flight into a failing test.
      assert.ok(input.witnessUtxo, `input ${i} has no witnessUtxo — its value would be unknown`)
      assert.ok(
        input.witnessUtxo?.script.equals(ownScript),
        `input ${i} does not spend the signing address`,
      )
      assert.equal(input.sighashType, bitcoin.Transaction.SIGHASH_ALL)
    })

    // The user is paid, and the change goes back to the SOURCE — never to a key this service made.
    const outputs = psbt.txOutputs
    const paid = outputs.find((o) => o.address === USER)
    assert.equal(paid?.value, 600_000)
    const change = outputs.find((o) => o.address === TREASURY)
    assert.ok(change, 'change returns to the source address')

    // The arithmetic closes: inputs = outputs + fee.
    const inputTotal = psbt.data.inputs.reduce((s, i) => s + BigInt(i.witnessUtxo?.value ?? 0), 0n)
    const outputTotal = outputs.reduce((s, o) => s + BigInt(o.value), 0n)
    assert.equal(inputTotal - outputTotal, unsigned.fee)
    assert.equal(unsigned.value, 600_000n)

    // Bitcoin has no nonce and no expiry, and both nulls are statements rather than omissions.
    assert.equal(unsigned.nonce, null)
    assert.equal(unsigned.expiry, null)
  })

  it('refuses when the real fee exceeds the fee the user locked', async () => {
    // Re-quoting here would sign a transaction that does not match the row it was built from.
    const node = fakeBtcNode({ utxos: [utxo(1, 5_000_000n)], feerate: 0.01 })
    await assert.rejects(
      () =>
        chainFor('btc').build(node.call, {
          from: TREASURY,
          to: USER,
          value: 100_000n,
          fee: 10n,
          bounds: BOUNDS,
          shape: 'payment',
        }),
      FeeOutOfBandError,
    )
  })

  it('refuses a destination on the wrong network before it asks the node anything', async () => {
    const node = fakeBtcNode({ utxos: [utxo(1, 5_000_000n)], feerate: 0.0001 })
    await assert.rejects(
      () =>
        chainFor('btc').build(node.call, {
          from: TREASURY,
          to: MAINNET_ADDRESS,
          value: 1_000n,
          fee: 100_000n,
          bounds: BOUNDS,
          shape: 'payment',
        }),
      AddressError,
    )
  })

  it('will not spend coins that are not yet at the depth this estate credits at', async () => {
    // BTC's declared depth is 3. Spending a 1-confirmation coin builds a payment on money this
    // estate has not itself accepted, and a reorg would make the payment unminable.
    const node = fakeBtcNode({ utxos: [utxo(1, 5_000_000n, 1)], feerate: 0.0001 })
    await assert.rejects(
      () =>
        chainFor('btc').build(node.call, {
          from: TREASURY,
          to: USER,
          value: 100_000n,
          fee: 100_000n,
          bounds: BOUNDS,
          shape: 'payment',
        }),
      InsufficientTreasuryError,
    )
  })
})

describe('the transaction id', () => {
  it('is the txid and never the wtxid', async () => {
    const node = fakeBtcNode({ utxos: [utxo(1, 5_000_000n)], feerate: 0.0001 })
    const unsigned = await chainFor('btc').build(node.call, {
      from: TREASURY,
      to: USER,
      value: 100_000n,
      fee: 100_000n,
      bounds: BOUNDS,
          shape: 'payment',
    })
    const tx = finaliseLikeCustody(String(unsigned.payload))
    const hex = tx.toHex()

    // The wtxid commits to the witness; no explorer keys on it and a status lookup by it finds
    // nothing. This is the whole reason txIdOf uses getId() rather than getHash().
    assert.equal(chainFor('btc').txIdOf(hex), tx.getId())
    assert.notEqual(tx.getId(), tx.getHash(true).reverse().toString('hex'))
    assert.equal(chainFor('btc').txIdOf('not hex'), null, 'a refusal, never a guess')
  })
})

describe('status', () => {
  const TXID = 'a'.repeat(64)

  it('is unknown for a transaction no node has, and never rejected', async () => {
    // Unknown and rejected are not the same conversation: rejected refunds, and refunding a
    // payment that is merely propagating credits a user money that has left the treasury.
    const node = fakeBtcNode({})
    assert.deepEqual(await chainFor('btc').status(node.call, TXID), { kind: 'unknown' })
  })

  it('is unknown while it sits in a mempool at zero confirmations', async () => {
    const node = fakeBtcNode({ confirmationsByTxid: { [TXID]: 0 } })
    assert.deepEqual(await chainFor('btc').status(node.call, TXID), { kind: 'unknown' })
  })

  /**
   * **THE DEPTH IS READ FROM `contracts-chain`, NEVER RESTATED HERE.**
   *
   * This test used to hardcode three, and it went red the moment BTC's declared depth was raised
   * from 3 to 6 — a change made deliberately in `contracts` because three confirmations is roughly
   * thirty minutes and below what any custodian uses for Bitcoin. The adapter was correct
   * throughout; only the test's copy of the constant was wrong, and it sat red on a deployable
   * branch.
   *
   * A test that restates a constant does not test that the constant is honoured — it tests that two
   * copies agree, and it fails on the correct change rather than on the incorrect one. So the
   * boundary is computed from the same value the adapter reads, and what is asserted is the
   * PROPERTY: below the declared depth is pending, at it and above it is confirmed. That statement
   * stays true and stays meaningful whatever the number becomes.
   */
  it('crosses from pending to confirmed at whatever depth contracts-chain declares', async () => {
    const depth = chainSpec('BTC').confirmations
    assert.ok(depth >= 2, 'a depth below two would make this test vacuous')
    const cases: ReadonlyArray<readonly [number, 'pending' | 'confirmed']> = [
      [1, 'pending'],
      [depth - 1, 'pending'],
      [depth, 'confirmed'],
      [depth + 6, 'confirmed'],
    ]
    for (const [confirmations, kind] of cases) {
      const node = fakeBtcNode({ confirmationsByTxid: { [TXID]: confirmations }, height: 900 })
      const status = await chainFor('btc').status(node.call, TXID)
      assert.equal(status.kind, kind, `${confirmations} confirmations should be ${kind}`)
      if (status.kind === 'pending' || status.kind === 'confirmed') {
        assert.equal(status.minedHeight, BigInt(900 - confirmations + 1))
      }
    }
  })
})

describe('broadcast', () => {
  it('treats re-sending bytes already accepted as success, because retry is the normal case', async () => {
    const node = fakeBtcNode({ utxos: [utxo(1, 5_000_000n)], feerate: 0.0001 })
    const unsigned = await chainFor('btc').build(node.call, {
      from: TREASURY,
      to: USER,
      value: 100_000n,
      fee: 100_000n,
      bounds: BOUNDS,
          shape: 'payment',
    })
    const tx = finaliseLikeCustody(String(unsigned.payload))
    const hex = tx.toHex()

    const again = fakeBtcNode({ sendError: '-27: Transaction already in block chain' })
    assert.equal(
      await chainFor('btc').broadcast(again.call, hex),
      tx.getId(),
      'the second attempt after a crash must succeed, not fail the payment',
    )

    // A real failure is still a failure.
    const broken = fakeBtcNode({ sendError: 'bad-txns-inputs-missingorspent' })
    await assert.rejects(() => chainFor('btc').broadcast(broken.call, hex))
  })
})

describe('proveDead', () => {
  /** A signed transaction spending two known outpoints, for the adjudication tests. */
  function deadBytes(): { hex: string; ins: string[] } {
    const tx = new bitcoin.Transaction()
    const ins: string[] = []
    for (let i = 1; i <= 2; i++) {
      const hash = Buffer.alloc(32, i)
      tx.addInput(hash, 0)
      tx.setWitness(i - 1, [Buffer.alloc(72, 1), Buffer.alloc(33, 2)])
      ins.push(`${Buffer.from(hash).reverse().toString('hex')}:0`)
    }
    tx.addOutput(bitcoin.address.toOutputScript(USER, TESTNET), 90_000)
    return { hex: tx.toHex(), ins }
  }

  it('refuses to refund while the payment is on chain', async () => {
    const { hex } = deadBytes()
    const txid = bitcoin.Transaction.fromHex(hex).getId()
    const node = fakeBtcNode({ confirmationsByTxid: { [txid]: 1 } })
    const verdict = await chainFor('btc').proveDead(node.call, {
      from: TREASURY,
      rawTx: hex,
      txHash: txid,
      signedNonce: null,
      signedExpiry: null,
    })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.code, 'on_chain')
  })

  it('refuses to refund while every coin it spends is still unspent', async () => {
    // The Bitcoin analogue of "the nonce is still available": any node holding these bytes can
    // mine them at any time, so a refund now can be followed by the payment landing.
    const { hex, ins } = deadBytes()
    const node = fakeBtcNode({ unspent: ins })
    const verdict = await chainFor('btc').proveDead(node.call, {
      from: TREASURY,
      rawTx: hex,
      txHash: null,
      signedNonce: null,
      signedExpiry: null,
    })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.code, 'still_applicable')
  })

  it('PROVES death when a coin it spends has been spent by something else', async () => {
    // This is the Bitcoin death proof, and it has no EVM analogue: there is no nonce, so the
    // evidence is the UTXO set. One consumed input is enough — the transaction can never be mined.
    const { hex, ins } = deadBytes()
    const node = fakeBtcNode({ unspent: [ins[0]!] }) // the second input is gone
    const verdict = await chainFor('btc').proveDead(node.call, {
      from: TREASURY,
      rawTx: hex,
      txHash: null,
      signedNonce: null,
      signedExpiry: null,
    })
    assert.equal(verdict.ok, true)
    assert.match(verdict.ok === true ? verdict.proof : '', /no longer in the UTXO set/)
  })

  it('says unprovable rather than refunding on bytes it cannot read', async () => {
    // An absence of evidence never refunds.
    const node = fakeBtcNode({})
    const verdict = await chainFor('btc').proveDead(node.call, {
      from: TREASURY,
      rawTx: '0xnot-a-transaction',
      txHash: null,
      signedNonce: null,
      signedExpiry: null,
    })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.code, 'unprovable')
  })
})

describe('the sweep PSBT', () => {
  it('pays EVERYTHING to the pinned treasury, with no change output at all', async () => {
    // custody's specified policy is that every output of a deposit-purpose PSBT pays the pinned
    // treasury, change included. A sweep with no change output satisfies it by construction, which
    // is why this cannot reuse the coin selector — that exists to produce change.
    const node = fakeBtcNode({ utxos: [utxo(1, 500_000n), utxo(2, 300_000n)] })
    const built = await buildSweepPsbt(node.call, TREASURY, OTHER, 10n, 3)
    assert.ok(built)
    const psbt = bitcoin.Psbt.fromBase64(built.psbtBase64, { network: TESTNET })

    assert.equal(psbt.inputCount, 2, 'a sweep takes every coin')
    assert.equal(psbt.txOutputs.length, 1, 'one output, so nothing can pay anywhere else')
    assert.equal(psbt.txOutputs[0]?.address, OTHER)
    assert.equal(BigInt(psbt.txOutputs[0]?.value ?? 0), built.value)
    assert.equal(built.value + built.fee, 800_000n, 'everything is accounted for')
    psbt.data.inputs.forEach((input) => {
      assert.ok(input.witnessUtxo)
      assert.equal(input.sighashType, bitcoin.Transaction.SIGHASH_ALL)
    })
  })

  it('declines rather than destroying value when the balance is below the cost of moving it', async () => {
    const node = fakeBtcNode({ utxos: [utxo(1, 700n)] })
    assert.equal(await buildSweepPsbt(node.call, TREASURY, OTHER, 50n, 3), null)
    // And nothing to sweep is the same answer, not an error.
    assert.equal(await buildSweepPsbt(fakeBtcNode({}).call, TREASURY, OTHER, 10n, 3), null)
  })
})

/* ------------------------------------------------------------------ the sweep, through build */

/**
 * **THE DEFECT THIS SECTION EXISTS FOR.**
 *
 * `buildSweepPsbt` was written, exported and tested, and had no production caller. `build` served
 * both purposes, so a sweep went through the coin selector — which exists to produce CHANGE. Two
 * things followed and neither had a test:
 *
 *   1. With one coin it produced a single output paying the pin, by accident, and worked.
 *   2. With two or more it threw `InsufficientTreasuryError`, because `selectCoins` cannot cover a
 *      one-input two-output fee out of a target that has already had that fee subtracted. So every
 *      Bitcoin sweep of an address holding more than one coin failed, for ever, at info level.
 *
 * And had it not thrown, the change output would have been refused WHOLE by custody's
 * `assertSweepOutputs` — after the row was committed and the chain's single outbound slot claimed.
 */
describe('build, for a sweep', () => {
  it('takes EVERY coin and creates no change output, on an address holding several', async () => {
    const node = fakeBtcNode({ utxos: [utxo(1, 500_000n), utxo(2, 300_000n), utxo(3, 90_000n)] })
    const quote = await chainFor('btc').sweepQuote(node.call, TREASURY, BOUNDS)
    assert.ok(quote, 'three coins well above the fee is worth sweeping')

    const unsigned = await chainFor('btc').build(node.call, {
      from: TREASURY,
      to: OTHER,
      value: quote.value,
      fee: quote.fee,
      bounds: BOUNDS,
      shape: 'sweep',
    })
    const psbt = bitcoin.Psbt.fromBase64(String(unsigned.payload), { network: TESTNET })

    assert.equal(psbt.inputCount, 3, 'a sweep takes every coin')
    // The check custody's `assertSweepOutputs` makes: EVERY output pays the pin, change included.
    // One output is how that is satisfied by construction.
    assert.equal(psbt.txOutputs.length, 1, 'a change output would be refused whole by custody')
    assert.equal(psbt.txOutputs[0]?.address, OTHER)
    assert.equal(BigInt(psbt.txOutputs[0]?.value ?? 0), quote.value)
    assert.equal(quote.value + quote.fee, 890_000n, 'everything that left is accounted for')
    psbt.data.inputs.forEach((input, i) => {
      assert.ok(input.witnessUtxo, `input ${i} has no witnessUtxo`)
      assert.equal(input.sighashType, bitcoin.Transaction.SIGHASH_ALL)
    })
  })

  it('quotes the fee for the size a sweep really is, not for a one-input two-output spend', async () => {
    // The number that was wrong. `estimateFee` quotes `vsizeOf(1, 2)` = 141 vbytes; a three-coin
    // sweep is `vsizeOf(3, 1)` = 246. At the relay floor of 1 sat/vB the old quote would have paid
    // 141 satoshis for a 246-vbyte transaction — 0.57 sat/vB, which no node forwards.
    const node = fakeBtcNode({ utxos: [utxo(1, 500_000n), utxo(2, 300_000n), utxo(3, 90_000n)] })
    const quote = await chainFor('btc').sweepQuote(node.call, TREASURY, BOUNDS)
    assert.ok(quote)
    assert.equal(quote.fee, 1n * BigInt(vsizeOf(3, 1)))
    assert.ok(quote.fee > 1n * BigInt(vsizeOf(1, 2)), 'the sweep fee must exceed the generic quote')
  })

  it('refuses when the coins have moved since the row was quoted', async () => {
    // The row carries the value and fee `planSweep` computed from a UTXO set; if the set has
    // changed, the difference between the two numbers is a fee nobody agreed to pay. Refused rather
    // than silently re-quoted, exactly as a withdrawal's locked fee is.
    const node = fakeBtcNode({ utxos: [utxo(1, 500_000n), utxo(2, 300_000n)] })
    const quote = await chainFor('btc').sweepQuote(node.call, TREASURY, BOUNDS)
    assert.ok(quote)
    const richer = fakeBtcNode({ utxos: [utxo(1, 500_000n), utxo(2, 300_000n), utxo(4, 40_000n)] })
    await assert.rejects(
      chainFor('btc').build(richer.call, {
        from: TREASURY,
        to: OTHER,
        value: quote.value,
        fee: quote.fee,
        bounds: BOUNDS,
        shape: 'sweep',
      }),
      FeeOutOfBandError,
    )
  })

  it('refuses when there is nothing at depth to sweep', async () => {
    const node = fakeBtcNode({ utxos: [utxo(1, 500_000n, 1)] })
    assert.equal(await chainFor('btc').sweepQuote(node.call, TREASURY, BOUNDS), null)
    await assert.rejects(
      chainFor('btc').build(node.call, {
        from: TREASURY,
        to: OTHER,
        value: 100n,
        fee: 100n,
        bounds: BOUNDS,
        shape: 'sweep',
      }),
      InsufficientTreasuryError,
    )
  })

  it('does the arithmetic in ONE place, so the quote and the build cannot drift', () => {
    // `sweepPlan` is what both call. A second copy of this arithmetic is a build that refuses a row
    // it quoted itself.
    const utxos = [utxo(1, 500_000n), utxo(2, 300_000n)]
    const plan = sweepPlan(utxos, 7n, 546n)
    assert.ok(plan)
    assert.equal(plan.fee, 7n * BigInt(vsizeOf(2, 1)))
    assert.equal(plan.value + plan.fee, 800_000n)
    assert.equal(plan.inputs.length, 2)
    assert.equal(sweepPlan([], 7n, 546n), null)
    assert.equal(sweepPlan([utxo(1, 600n)], 7n, 546n), null, 'a dust-sized sweep destroys value')
  })
})

describe('the network binding', () => {
  it('maps the estate networks onto bitcoin networks and keeps them apart', () => {
    assert.equal(networkFor('btc', 'mainnet'), bitcoin.networks.bitcoin)
    assert.equal(networkFor('btc', 'testnet'), bitcoin.networks.testnet)
    assert.notEqual(networkFor('btc', 'mainnet').bech32, networkFor('btc', 'testnet').bech32)
  })

  /**
   * **DOGECOIN HAS A ROW NOW, AND THE ROW IS THE SMALLEST PART OF ADDING IT.**
   *
   * This test used to assert that `NETWORKS` had NO Dogecoin row and that `networkFor('doge')`
   * threw, on the argument that `NETWORKS` is where Litecoin was added and is therefore the obvious
   * place to add Dogecoin — and that the one-line addition would compile and be wrong, because
   * everything in this file was P2WPKH and Dogecoin has no segwit at all. The failure it named was
   * not a rejected address but `vsizeOf` applying the witness discount to inputs that have no
   * witness, quoting a fee under half the transaction's real size, on a transaction that gets
   * SIGNED and is then dropped by every node below the relay floor.
   *
   * That argument was right and it is why the row was not enough. What is asserted now is the pair:
   * the row exists, and it did not arrive alone. `addressKindFor` is the thing that makes the rest
   * of the file chain-driven rather than incidental, so it is asserted here beside the network —
   * a Dogecoin row with a `p2wpkh` kind would be exactly the change this test was written to stop.
   */
  it('has a Dogecoin row, and a Dogecoin ADDRESS KIND to go with it', () => {
    assert.ok(networkFor('doge', 'mainnet'))
    assert.ok(networkFor('doge', 'testnet'))
    assert.equal(addressKindFor('doge'), 'p2pkh', 'the row without this is the bug it replaced')
    assert.equal(addressKindFor('btc'), 'p2wpkh')
    assert.equal(addressKindFor('ltc'), 'p2wpkh')
    assert.equal(chainFor('doge').unimplementedPhase, null)
    assert.ok(implementedChains().includes('doge'))
    // The mainnet and testnet parameters are distinct, which is the same binding the BTC case above
    // asserts through bech32 — and here it has to be asserted on the base58 bytes, because
    // Dogecoin's HRP is the empty string on both networks and would compare equal.
    assert.notEqual(networkFor('doge', 'mainnet').pubKeyHash, networkFor('doge', 'testnet').pubKeyHash)
    // And not Bitcoin's, which is the whole of what a wrong parameter table would look like.
    assert.notEqual(networkFor('doge', 'mainnet').pubKeyHash, networkFor('btc', 'mainnet').pubKeyHash)
    assert.notEqual(networkFor('doge', 'testnet').pubKeyHash, networkFor('btc', 'testnet').pubKeyHash)
  })
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * LITECOIN — one adapter, two chains, and everything that is NOT shared.
 *
 * The tests above prove the adapter. These prove it is being given Litecoin's parameters rather
 * than Bitcoin's wearing Litecoin's name, which is a different claim and the one that costs money:
 * `family` is `'bitcoin'` for both, so any resolution that goes through the family alone silently
 * answers Bitcoin and produces a `bc1…` address published as a Litecoin destination.
 *
 * ── EVERY ADDRESS BELOW IS A PUBLISHED VECTOR, AND THE SCRIPT IS ASSERTED TOO ─────────────────
 *
 * `litecoin-project/litecoin`, `src/test/data/key_io_valid.json` — the file Litecoin Core's own
 * `key_io_tests` runs against. It gives address AND the script Core decodes it to, so this asserts
 * the full mapping rather than "it did not throw": a parameter table that was wrong in a way that
 * still decoded would produce a different script and be caught. Bitcoin's come from the same file
 * in `bitcoin/bitcoin`.
 *
 * A vector generated in this repository would agree with any mistake this repository makes. That
 * is the whole reason these are quoted rather than derived, and it is why the addresses used for
 * BUILDING below are derived while the addresses used for VALIDATING are not.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/** `litecoin/src/test/data/key_io_valid.json`, chain `main`: address → the script Core decodes. */
const LTC_MAINNET_VECTORS: readonly (readonly [string, string])[] = [
  ['LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA', '76a914558dbca7118cd5894502767c7b2ffc21a22f54db88ac'],
  ['LbfVMz974gbbGFqXF7FZUpSBWSbwBHDwR5', '76a914b4565f467408e9e1c1d2a3b0ccdeff84db3a3b9388ac'],
  ['MHrYRxAiMNBTku3eoDHwhA1LQGDjUStZW2', 'a9146d328a5b2a20d943a641c8d29b6cc3c2d2df85d387'],
  ['M9dw1FAoWpHC6PcMzoCHhqQ9McvTyG5Ywj', 'a914130ef8742ad7492b389509252c6721775fb1127387'],
  ['ltc1qhdhvrwe6rgqns8fz28tee0hphr5x7ulw5exv4w', '0014bb6ec1bb3a1a01381d2251d79cbee1b8e86f73ee'],
  [
    'ltc1qa9dykljtgeayhm8ygx25sc22p0wzgudpe4hw9dyvaz0ye3j5kduq9mf68z',
    '0020e95a4b7e4b467a4bece4419548614a0bdc2471a1cd6ee2b48ce89e4cc654b378',
  ],
] as const

/**
 * Also from Core's file, also perfectly valid, and NOT PAYABLE BY THIS ESTATE — on either chain.
 *
 * `bitcoinjs-lib@6.1.7` routes witness version 1 through its `p2tr` payment, which throws
 * `No ECC Library provided. You must call initEccLib()`. Nothing here calls it: this service has no
 * secp256k1 package at all, and custody has one it never initialises. So a Taproot destination
 * cannot be decoded by the builder OR by the signer. `wallet` refuses it at the boundary now so a
 * user's balance is never reserved against it; this pins the far side of that decision.
 */
const UNPAYABLE_TAPROOT: readonly string[] = [
  'ltc1ppu2gv0tujus0f6eggrk7eqmaf0567x6zer4fcuhz4z7ztzq9u9yseqxltc',
  'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
] as const

/** The same file, chain `test`. */
const LTC_TESTNET_VECTORS: readonly (readonly [string, string])[] = [
  ['tltc1qpftpsvdn6mjp8celrkj0qxqy4jlapl959rlwg9', '00140a561831b3d6e413e33f1da4f01804acbfd0fcb4'],
  ['tltc1quf7ycjczjpjd6u9a8mpa00jl7g9aplhy8e0vf7', '0014e27c4c4b029064dd70bd3ec3d7be5ff20bd0fee4'],
] as const

/** `bitcoin/src/test/data/key_io_valid.json`. All valid Bitcoin; none of them Litecoin. */
const BTC_VECTORS: readonly string[] = [
  '1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo',
  '36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm',
  'bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv',
] as const

const LTC_TESTNET = networkFor('ltc', 'testnet')

/** A deterministic Litecoin testnet P2WPKH address. Derived: it is a fixture, not a claim. */
function ltcP2wpkh(seed: number): string {
  const address = bitcoin.payments.p2wpkh({
    hash: Buffer.alloc(20, seed),
    network: LTC_TESTNET,
  }).address
  if (!address) throw new Error('could not derive a test address')
  return address
}

const LTC_TREASURY = ltcP2wpkh(0x44)
const LTC_USER = ltcP2wpkh(0x55)

/** The Bitcoin fake, re-pointed at Litecoin's parameters. */
function fakeLtcNode(options: FakeBtcNodeOptions = {}): { call: ChainCall; broadcast: string[] } {
  const broadcast: string[] = []
  const utxos = options.utxos ?? []
  const rpc = async (method: string, params: readonly unknown[]): Promise<unknown> => {
    switch (method) {
      case 'estimatesmartfee':
        return options.feerate === null || options.feerate === undefined
          ? {}
          : { feerate: options.feerate, blocks: 3 }
      case 'listunspent': {
        const minConf = Number(params[0])
        return utxos
          .filter((u) => (u.confirmations ?? 12) >= minConf)
          .map((u) => ({
            txid: u.txid,
            vout: u.vout,
            amount: satsToBtc(u.sats),
            scriptPubKey: bitcoin.address.toOutputScript(LTC_TREASURY, LTC_TESTNET).toString('hex'),
            confirmations: u.confirmations ?? 12,
            spendable: true,
          }))
      }
      case 'getblockcount':
        return options.height ?? 3_000_000
      case 'getrawtransaction': {
        const confirmations = options.confirmationsByTxid?.[String(params[0])]
        if (confirmations === undefined) throw new Error('-5: No such mempool or blockchain transaction')
        return { txid: String(params[0]), confirmations }
      }
      case 'sendrawtransaction': {
        const hex = String(params[0])
        broadcast.push(hex)
        return bitcoin.Transaction.fromHex(hex).getId()
      }
      default:
        throw new Error(`unexpected method ${method}`)
    }
  }
  return { call: { network: 'testnet', rpc }, broadcast }
}

describe('litecoin', () => {
  it("decodes Core's own published vectors to Core's own published scripts", () => {
    // NOT "does not throw". The script is asserted, so a parameter table that was wrong in a way
    // that still decoded — a swapped version byte, say — produces a different script and fails.
    for (const [address, script] of LTC_MAINNET_VECTORS) {
      assert.equal(validateAddress('ltc', address, 'mainnet'), address)
      assert.equal(
        bitcoin.address.toOutputScript(address, networkFor('ltc', 'mainnet')).toString('hex'),
        script,
        `${address} decoded to the wrong script`,
      )
    }
    for (const [address, script] of LTC_TESTNET_VECTORS) {
      assert.equal(validateAddress('ltc', address, 'testnet'), address)
      assert.equal(
        bitcoin.address.toOutputScript(address, LTC_TESTNET).toString('hex'),
        script,
        `${address} decoded to the wrong script`,
      )
    }
  })

  it('REFUSES a Bitcoin address as a Litecoin destination, which is the defect that loses coins', () => {
    for (const address of BTC_VECTORS) {
      // Valid Bitcoin — which is what makes it dangerous rather than merely wrong. A rejection
      // that fired on a malformed string would prove nothing.
      assert.equal(validateAddress('btc', address, 'mainnet'), address)
      assert.throws(
        () => validateAddress('ltc', address, 'mainnet'),
        AddressError,
        `${address} is a Bitcoin address and was accepted as a Litecoin destination`,
      )
      assert.equal(chainFor('ltc').isValidDestination(address), false, address)
    }
    // And the reverse, because the rule is symmetric and a one-way check is half a check.
    for (const [address] of LTC_MAINNET_VECTORS) {
      assert.throws(() => validateAddress('btc', address, 'mainnet'), AddressError)
      assert.equal(chainFor('btc').isValidDestination(address), false, address)
      assert.equal(chainFor('ltc').isValidDestination(address), true, address)
    }
  })

  it("uses Litecoin's own confirmation depth of 12, not Bitcoin's 6", async () => {
    // Read from the exact-pinned contracts-chain, so this fails if the package and the adapter
    // ever disagree — which is money credited, or spent, at the wrong depth.
    assert.equal(chainSpec('LTC').confirmations, 12)
    assert.equal(chainSpec('BTC').confirmations, 6)

    // Coins at 6 confirmations are BTC-spendable and NOT LTC-spendable. Same fake, same coins.
    const coins = [{ txid: '1'.repeat(64), vout: 0, sats: 500_000n, confirmations: 6 }]
    assert.equal(await chainFor('ltc').spendableBalance(fakeLtcNode({ utxos: coins }).call, LTC_TREASURY), 0n)
    assert.equal(
      await chainFor('ltc').spendableBalance(
        fakeLtcNode({ utxos: [{ ...coins[0]!, confirmations: 12 }] }).call,
        LTC_TREASURY,
      ),
      500_000n,
    )
  })

  it("uses Litecoin's dust threshold of 5,460 — ten times Bitcoin's, and NOT copied from it", async () => {
    /*
     * `DUST_RELAY_TX_FEE` is 3'000 in Bitcoin and 30'000 in Litecoin, so every dust threshold is ten
     * times apart. This is the one constant in the whole adapter where reusing Bitcoin's number is
     * not merely inaccurate: 546 sits BELOW Litecoin's real threshold, so a change or payment output
     * between the two would be built, signed, and refused by every node as `dust` — a broadcast
     * failure after a signature, which is the state that needs an operator rather than a refund.
     */
    const node = fakeLtcNode({ utxos: [{ txid: '1'.repeat(64), vout: 0, sats: 500_000n }], feerate: 0.00001 })
    const under = chainFor('ltc').build(node.call, {
      from: LTC_TREASURY,
      to: LTC_USER,
      // Above Bitcoin's 546 and below Litecoin's 5,460 — the window that only Litecoin's own
      // number closes. A test at 100 would pass against Bitcoin's threshold too and prove nothing.
      value: 1_000n,
      fee: 10_000n,
      bounds: BOUNDS,
      shape: 'payment',
    })
    await assert.rejects(under, FeeOutOfBandError)

    // And the same payment just above Litecoin's threshold builds, so this is a threshold and not
    // a ban on small withdrawals.
    const over = await chainFor('ltc').build(node.call, {
      from: LTC_TREASURY,
      to: LTC_USER,
      value: 5_461n,
      fee: 10_000n,
      bounds: BOUNDS,
      shape: 'payment',
    })
    assert.ok(over.payload)

    // Bitcoin keeps its own number, so this is a per-chain table and not a global raise.
    const btcNode = fakeBtcNode({ utxos: [{ txid: '1'.repeat(64), vout: 0, sats: 500_000n }], feerate: 0.00001 })
    const btcJustAbove = await chainFor('btc').build(btcNode.call, {
      from: TREASURY,
      to: USER,
      value: 547n,
      fee: 10_000n,
      bounds: BOUNDS,
      shape: 'payment',
    })
    assert.ok(btcJustAbove.payload)
  })

  it('builds a PSBT that decodes under Litecoin parameters and NOT under Bitcoin ones', async () => {
    const node = fakeLtcNode({ utxos: [{ txid: '1'.repeat(64), vout: 0, sats: 500_000n }], feerate: 0.00001 })
    const built = await chainFor('ltc').build(node.call, {
      from: LTC_TREASURY,
      to: LTC_USER,
      value: 100_000n,
      fee: 50_000n,
      bounds: BOUNDS,
      shape: 'payment',
    })

    const psbt = bitcoin.Psbt.fromBase64(built.payload as string, { network: LTC_TESTNET })
    // The payment output pays the Litecoin address that was asked for, byte for byte.
    assert.deepEqual(
      psbt.txOutputs[0]!.script,
      bitcoin.address.toOutputScript(LTC_USER, LTC_TESTNET),
      'the first output must pay the Litecoin destination',
    )
    // Change returns to the source, never to a fresh key this service invented.
    if (psbt.txOutputs.length > 1) {
      assert.deepEqual(
        psbt.txOutputs[1]!.script,
        bitcoin.address.toOutputScript(LTC_TREASURY, LTC_TESTNET),
      )
    }
    // Every input carries its value, which is the only thing that makes a segwit signature
    // possible and the thing custody's `signBitcoin` refuses a PSBT for lacking.
    for (const input of psbt.data.inputs) {
      assert.ok(input.witnessUtxo, 'every input must carry a witnessUtxo')
      assert.equal(input.sighashType, bitcoin.Transaction.SIGHASH_ALL)
    }
    // And the destination is not a Bitcoin address, which is the assertion the whole file is for.
    assert.throws(() => bitcoin.address.toOutputScript(LTC_USER, bitcoin.networks.testnet))
  })

  it('refuses a Bitcoin destination at BUILD, not merely at validation', async () => {
    // The seam that matters: `isValidDestination` is advisory and `build` is where money moves.
    const node = fakeLtcNode({ utxos: [{ txid: '1'.repeat(64), vout: 0, sats: 500_000n }], feerate: 0.00001 })
    await assert.rejects(
      chainFor('ltc').build(node.call, {
        from: LTC_TREASURY,
        to: USER, // a Bitcoin testnet P2WPKH address
        value: 100_000n,
        fee: 50_000n,
        bounds: BOUNDS,
        shape: 'payment',
      }),
      AddressError,
    )
  })

  it('CANNOT pay a Taproot address — on Litecoin OR Bitcoin, and that is a live Bitcoin gap', () => {
    /*
     * Found while adding Litecoin and recorded here rather than quietly worked around, because it
     * is not a Litecoin limitation: the same call fails identically for `bc1p…` and has since this
     * adapter was written. The estate mints P2WPKH, so no deposit address is affected; this bounds
     * only where a user may withdraw TO.
     *
     * Made payable by calling `initEccLib` with a secp256k1 binding HERE and in custody — a native
     * dependency added to the two services that build and sign money movements, to gain a
     * destination form rather than a chain. Deliberately not done in this change.
     */
    for (const address of UNPAYABLE_TAPROOT) {
      const chain = address.startsWith('ltc') ? 'ltc' : 'btc'
      assert.throws(
        () => validateAddress(chain, address, 'mainnet'),
        AddressError,
        `${address} is not payable and was accepted`,
      )
      assert.equal(chainFor(chain).isValidDestination(address), false, address)
    }
    // Version 0 is unaffected on both chains, so this bounds the output type and not segwit.
    assert.equal(chainFor('btc').isValidDestination('bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv'), true)
    assert.equal(chainFor('ltc').isValidDestination('ltc1qhdhvrwe6rgqns8fz28tee0hphr5x7ulw5exv4w'), true)
  })

  it('is an implemented chain, and hands custody the name custody stores', () => {
    assert.equal(chainFor('ltc').unimplementedPhase, null)
    assert.equal(chainFor('ltc').chain, 'ltc')
    assert.equal(chainFor('ltc').family, 'bitcoin')
    // Bitcoin has no token model and neither does Litecoin. Null, not a throwing object.
    assert.equal(chainFor('ltc').tokens, null)
    assert.ok(implementedChains().includes('ltc'))
    // `ltc` is this service's slug; `litecoin` is the string custody compares character for
    // character before it signs. A mismatch is a `binding_mismatch` at signing time.
    assert.equal(custodyChainOf('ltc'), 'litecoin')
    assert.equal(custodyFamilyOf('ltc'), 'bitcoin')
    assert.equal(chainForAsset('LTC'), 'ltc')
    assert.equal(assetOf('ltc'), 'LTC')
  })

  it("bounds the amount by Litecoin's supply cap and not Bitcoin's", () => {
    // 84 million, `litecoin/src/consensus/amount.h`. Reusing Bitcoin's 21 million would refuse a
    // genuine node answer as malformed.
    assert.equal(btcToSats(84_000_000, 'ltc'), 8_400_000_000_000_000n)
    assert.throws(() => btcToSats(84_000_001, 'ltc'), AddressError)
    assert.throws(() => btcToSats(21_000_001, 'btc'), AddressError)
    // And the double round-trip is exact well past Bitcoin's range, up to the boundary the header
    // states: the ULP of a double stays under 1e-8 below 2^25.4 ≈ 44.7 million coins.
    for (const coins of [1, 21_000_000, 44_000_000]) {
      assert.equal(btcToSats(coins, 'ltc'), BigInt(coins) * 100_000_000n, `${coins} did not survive`)
    }
  })
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * DOGECOIN — the same adapter, and the chain where "the same adapter" was nearly a disaster.
 *
 * Litecoin proved this file can be given another chain's PARAMETERS. Dogecoin is the harder claim:
 * it needs another chain's ASSUMPTIONS. Litecoin is Bitcoin with different constants; Dogecoin is
 * Bitcoin without segwit, which changes the shape of an input, the size of a transaction, the way
 * dust is computed, the relay floor, and the fee ceiling — five things, each of which was a single
 * shared value in this file until now.
 *
 * ── THE ONE THAT DOES NOT FAIL LOUDLY IS THE ONE TO TEST HARDEST ───────────────────────────────
 *
 * Three of the five announce themselves. A `witnessUtxo` on a P2PKH input makes bitcoinjs SKIP the
 * input and then throw `No inputs were signed`; a bech32 destination on a chain with no bech32
 * fails to decode; a dust output is refused by `sendrawtransaction`. The vsize model does not: it
 * produces a perfectly valid transaction that is simply under-priced, gets signed, gets broadcast,
 * and is dropped below the relay floor with this chain's single outbound slot claimed. So the size
 * assertions here MEASURE a real serialised legacy transaction rather than compare two constants.
 *
 * ── EVERY ADDRESS BELOW IS A PUBLISHED VECTOR ──────────────────────────────────────────────────
 *
 * `dogecoin/dogecoin`, `src/test/data/base58_keys_valid.json` — the file Dogecoin Core's own
 * `base58_tests` runs against. It gives the address and the HASH Core decodes it to, and the script
 * beside each one here is that hash wrapped in the standard template for its `addrType`, so this
 * asserts the full mapping rather than "it did not throw". A vector generated in this repository
 * would agree with any mistake this repository makes.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/** `dogecoin/src/test/data/base58_keys_valid.json`, mainnet: address → the script Core decodes. */
const DOGE_MAINNET_VECTORS: readonly (readonly [string, string])[] = [
  ['DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE', '76a91456d9b1d684d5abef32134ebc6883d75d3a53e9be88ac'],
  ['DBjW6kna7rUPE4Mj9j4B3oK3xVA1SDHrdt', '76a914485290865b407657e0aedbdbb4aa6618310af50d88ac'],
  ['D77Z1nmgSZxJTmtN65n2MVF9yvLSB4MpiC', '76a91415a585042e96300b5ad4f9d7c7c6cba2d56a098988ac'],
  ['A7HRQk3GFCW2QasvdZxXuYj8kkQK5QrYLs', 'a914a2dd71f34fe73314d6e37c44035513f203aa400b87'],
  ['A3RHoAQLPDSuBewbuvt5NMqEKasqs9ty3C', 'a9147879ea0f1053bcbd4c60c88f922f76d27e622e1e87'],
] as const

/** The same file, testnet. The `n…` prefix is Dogecoin's 0x71, NOT Bitcoin testnet's 0x6f. */
const DOGE_TESTNET_VECTORS: readonly (readonly [string, string])[] = [
  ['nhRsrUaxZou6sewjqaS37cJrMRJRgwVXdk', '76a9149131c29384f000c0d651660eefaf1717c8ca185588ac'],
  ['ngbSgr1dhCqsLg6Z5tpsaCspwrH72x2Zk3', '76a9148808c94daaa2e4f53102703b2c3de534d670e87e88ac'],
] as const

const DOGE_TESTNET = networkFor('doge', 'testnet')

/** A deterministic Dogecoin testnet P2PKH address. Derived: it is a fixture, not a claim. */
function dogeP2pkh(seed: number): string {
  const address = bitcoin.payments.p2pkh({
    hash: Buffer.alloc(20, seed),
    network: DOGE_TESTNET,
  }).address
  if (!address) throw new Error('could not derive a test address')
  return address
}

const DOGE_TREASURY = dogeP2pkh(0x66)
const DOGE_USER = dogeP2pkh(0x77)

/**
 * A real funding transaction paying the Dogecoin treasury, and its real txid.
 *
 * **The txid is DERIVED from the bytes rather than invented**, because that is the property the
 * legacy path depends on: bitcoinjs refuses a `nonWitnessUtxo` whose hash does not match the
 * outpoint the input names, and custody's `legacyPrevOut` checks the same thing before it believes
 * anything else about the input. A fixture with a made-up txid would pass a test that only counted
 * fields and fail the moment a real signer saw it.
 */
function dogeFunding(seed: number, sats: bigint, outputs = 1): { txid: string; hex: string; vout: number } {
  const tx = new bitcoin.Transaction()
  tx.addInput(Buffer.alloc(32, seed), 0, 0xffffffff, Buffer.from([0x51]))
  for (let i = 0; i < outputs; i++) {
    tx.addOutput(bitcoin.address.toOutputScript(DOGE_TREASURY, DOGE_TESTNET), Number(sats))
  }
  return { txid: tx.getId(), hex: tx.toHex(), vout: 0 }
}

interface FakeDogeNodeOptions {
  readonly funding?: readonly { txid: string; hex: string; vout: number; sats: bigint }[]
  readonly feerate?: number | null
  readonly confirmations?: number
  /** Answer `getrawtransaction` with an object instead of hex, as a node with no `txindex` does. */
  readonly withholdRaw?: boolean
}

/**
 * The Dogecoin node fake. Answers `getrawtransaction` with BYTES, which the Bitcoin fake never had
 * to: the segwit path never asks for a previous transaction at all, so this method arriving twice
 * with two different meanings — hex when `verbose` is false, an object when it is true — is itself
 * part of what the legacy branch has to get right.
 */
function fakeDogeNode(options: FakeDogeNodeOptions = {}): { call: ChainCall; calls: string[] } {
  const calls: string[] = []
  const funding = options.funding ?? []
  const rpc = async (method: string, params: readonly unknown[]): Promise<unknown> => {
    calls.push(`${method}${params[1] === true ? ':verbose' : ''}`)
    switch (method) {
      case 'estimatesmartfee':
        return options.feerate === null || options.feerate === undefined
          ? {}
          : { feerate: options.feerate, blocks: 3 }
      case 'listunspent':
        return funding
          .filter(() => (options.confirmations ?? 30) >= Number(params[0]))
          .map((f) => ({
            txid: f.txid,
            vout: f.vout,
            amount: satsToBtc(f.sats),
            scriptPubKey: bitcoin.address.toOutputScript(DOGE_TREASURY, DOGE_TESTNET).toString('hex'),
            confirmations: options.confirmations ?? 30,
            spendable: true,
          }))
      case 'getblockcount':
        return 5_000_000
      case 'getrawtransaction': {
        const row = funding.find((f) => f.txid === String(params[0]))
        if (!row) throw new Error('-5: No such mempool or blockchain transaction')
        if (params[1] === true) return { txid: row.txid, confirmations: options.confirmations ?? 30 }
        return options.withholdRaw ? { txid: row.txid } : row.hex
      }
      default:
        throw new Error(`unexpected method ${method}`)
    }
  }
  return { call: { network: 'testnet', rpc }, calls }
}

describe('dogecoin', () => {
  it("decodes Core's own published vectors to Core's own published scripts", () => {
    for (const [address, script] of DOGE_MAINNET_VECTORS) {
      assert.equal(validateAddress('doge', address, 'mainnet'), address)
      assert.equal(
        bitcoin.address.toOutputScript(address, networkFor('doge', 'mainnet')).toString('hex'),
        script,
        `${address} decoded to the wrong script`,
      )
    }
    for (const [address, script] of DOGE_TESTNET_VECTORS) {
      assert.equal(validateAddress('doge', address, 'testnet'), address)
      assert.equal(
        bitcoin.address.toOutputScript(address, DOGE_TESTNET).toString('hex'),
        script,
        `${address} decoded to the wrong script`,
      )
    }
    // The network binding, in both directions, on the base58 bytes. Dogecoin's HRP is the empty
    // string on both networks, so the bech32 half of the Bitcoin test above has nothing to compare
    // here and the version byte is the whole of the separation.
    assert.throws(() => validateAddress('doge', DOGE_MAINNET_VECTORS[0]![0], 'testnet'), AddressError)
    assert.throws(() => validateAddress('doge', DOGE_TESTNET_VECTORS[0]![0], 'mainnet'), AddressError)
  })

  it('REFUSES a Bitcoin address as a Dogecoin destination, and the reverse', () => {
    for (const address of BTC_VECTORS) {
      assert.equal(validateAddress('btc', address, 'mainnet'), address)
      assert.throws(
        () => validateAddress('doge', address, 'mainnet'),
        AddressError,
        `${address} is a Bitcoin address and was accepted as a Dogecoin destination`,
      )
      assert.equal(chainFor('doge').isValidDestination(address), false, address)
    }
    for (const [address] of DOGE_MAINNET_VECTORS) {
      assert.throws(() => validateAddress('btc', address, 'mainnet'), AddressError)
      assert.throws(() => validateAddress('ltc', address, 'mainnet'), AddressError)
      assert.equal(chainFor('doge').isValidDestination(address), true, address)
    }
  })

  /**
   * **A BECH32 DESTINATION IS REFUSED FOR DOGECOIN, AND STILL ACCEPTED FOR LITECOIN.**
   *
   * Both halves, because each without the other is a different bug. Dogecoin has no segwit and
   * therefore no bech32 at all: `bitcoinjs` would decode `bc1…` or `ltc1…` against Dogecoin's
   * parameters and refuse it on the HRP, which is ALMOST the check — but Dogecoin's `bech32` field
   * is the empty string, and an empty HRP is not a guard, it is an absence. The refusal is
   * therefore explicit and comes from the address KIND rather than from a failed decode.
   *
   * The second half is the mirror-image bug this must not reintroduce. Refusing bech32 globally, or
   * refusing anything that fails to parse as base58, would silently stop every Litecoin and Bitcoin
   * segwit withdrawal — which is the form every deposit address in this estate takes.
   */
  it('refuses a bech32 destination for DOGE and still accepts one for LTC and BTC', () => {
    const bech32Addresses = [
      'ltc1qhdhvrwe6rgqns8fz28tee0hphr5x7ulw5exv4w',
      'bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv',
    ] as const
    for (const address of bech32Addresses) {
      assert.throws(
        () => validateAddress('doge', address, 'mainnet'),
        AddressError,
        `${address} is bech32 and was accepted as a Dogecoin destination`,
      )
      assert.equal(chainFor('doge').isValidDestination(address), false, address)
    }
    // The mirror image, unchanged: each is still payable on its own chain.
    assert.equal(chainFor('ltc').isValidDestination(bech32Addresses[0]), true)
    assert.equal(chainFor('btc').isValidDestination(bech32Addresses[1]), true)
    assert.equal(validateAddress('ltc', bech32Addresses[0], 'mainnet'), bech32Addresses[0])
    assert.equal(validateAddress('btc', bech32Addresses[1], 'mainnet'), bech32Addresses[1])
    // And bech32m, the Taproot encoding, is refused for Dogecoin too rather than falling through a
    // check that only knows about bech32. It is unpayable everywhere in this estate — see the
    // Taproot test above for why — but it must be unpayable HERE for the reason stated in
    // `validateAddress`, not by accident of an uninitialised ECC library.
    for (const address of UNPAYABLE_TAPROOT) {
      assert.throws(() => validateAddress('doge', address, 'mainnet'), AddressError)
    }
  })

  /**
   * **EVERY DOGECOIN INPUT CARRIES `nonWitnessUtxo` AND NO DOGECOIN INPUT CARRIES `witnessUtxo`.**
   *
   * The absence is asserted as hard as the presence. A PSBT carrying BOTH would sign — bitcoinjs
   * prefers the witness field when it is present — and would produce a signature over the segwit
   * digest for a legacy input, which is not a valid signature and is not detectable until a node
   * refuses the finalised bytes.
   */
  it('builds a Dogecoin PSBT whose every input is a nonWitnessUtxo and never a witnessUtxo', async () => {
    const funding = [{ ...dogeFunding(1, 500_000_000n), sats: 500_000_000n }]
    const node = fakeDogeNode({ funding, feerate: 0.01 })
    const built = await chainFor('doge').build(node.call, {
      from: DOGE_TREASURY,
      to: DOGE_USER,
      value: 100_000_000n,
      fee: 100_000_000n,
      bounds: BOUNDS,
      shape: 'payment',
    })

    const psbt = bitcoin.Psbt.fromBase64(built.payload as string, { network: DOGE_TESTNET })
    assert.ok(psbt.data.inputs.length > 0)
    for (const input of psbt.data.inputs) {
      assert.ok(input.nonWitnessUtxo, 'a legacy input must carry the whole previous transaction')
      assert.equal(input.witnessUtxo, undefined, 'a legacy input must NOT carry a witnessUtxo')
      assert.equal(input.sighashType, bitcoin.Transaction.SIGHASH_ALL)
    }
    // The supplied previous transaction really is the one the outpoint names, which is what
    // custody's `legacyPrevOut` re-checks before it believes the input's value.
    const previous = bitcoin.Transaction.fromBuffer(psbt.data.inputs[0]!.nonWitnessUtxo!)
    assert.equal(previous.getId(), psbt.txInputs[0]!.hash.reverse().toString('hex'))
    assert.deepEqual(
      psbt.txOutputs[0]!.script,
      bitcoin.address.toOutputScript(DOGE_USER, DOGE_TESTNET),
    )
    // And the segwit chains are unaffected, which is the half a global change would have broken.
    const ltcNode = fakeLtcNode({ utxos: [{ txid: '1'.repeat(64), vout: 0, sats: 500_000n }], feerate: 0.00001 })
    const ltcBuilt = await chainFor('ltc').build(ltcNode.call, {
      from: LTC_TREASURY,
      to: LTC_USER,
      value: 100_000n,
      fee: 50_000n,
      bounds: BOUNDS,
      shape: 'payment',
    })
    for (const input of bitcoin.Psbt.fromBase64(ltcBuilt.payload as string, { network: LTC_TESTNET }).data.inputs) {
      assert.ok(input.witnessUtxo, 'litecoin must still be segwit')
      assert.equal(input.nonWitnessUtxo, undefined)
    }
  })

  it('fetches each funding transaction once, however many coins came out of it', async () => {
    // Three coins from one funding transaction is one `getrawtransaction`, not three. The cache is
    // per PSBT rather than global on purpose: a global one would hold raw transactions for the life
    // of the process for a chain whose transactions are large and whose treasury is swept often.
    const shared = dogeFunding(9, 400_000_000n, 3)
    const funding = [0, 1, 2].map((vout) => ({ ...shared, vout, sats: 400_000_000n }))
    const node = fakeDogeNode({ funding, feerate: 0.01 })
    await chainFor('doge').build(node.call, {
      from: DOGE_TREASURY,
      to: DOGE_USER,
      value: 900_000_000n,
      fee: 200_000_000n,
      bounds: BOUNDS,
      shape: 'payment',
    })
    assert.equal(node.calls.filter((c) => c === 'getrawtransaction').length, 1)
  })

  it('refuses rather than building a PSBT custody could not sign when the node withholds the bytes', async () => {
    // A pruned node with no wallet import answers this call with something that is not hex. The
    // alternative to refusing is a PSBT with an input custody must reject, discovered after the row
    // is committed and this chain's single outbound slot is claimed.
    const funding = [{ ...dogeFunding(4, 500_000_000n), sats: 500_000_000n }]
    const node = fakeDogeNode({ funding, feerate: 0.01, withholdRaw: true })
    await assert.rejects(
      chainFor('doge').build(node.call, {
        from: DOGE_TREASURY,
        to: DOGE_USER,
        value: 100_000_000n,
        fee: 100_000_000n,
        bounds: BOUNDS,
        shape: 'payment',
      }),
      AddressError,
    )
  })

  /**
   * The size model, measured against a real legacy transaction rather than against a constant.
   *
   * This is the failure that does not announce itself, so it is the one measured end to end: a
   * P2PKH input is ~148 bytes with no witness discount against a P2WPKH input's 68 vbytes, so the
   * shared model under-quotes a Dogecoin spend by more than half.
   */
  it('prices a legacy spend at its REAL size, which is more than twice the segwit model', () => {
    for (const [inputs, outputs] of [
      [1, 1],
      [1, 2],
      [3, 2],
      [5, 1],
    ] as const) {
      const tx = new bitcoin.Transaction()
      for (let i = 0; i < inputs; i++) {
        // A P2PKH scriptSig: a DER signature with its sighash byte, and a 33 byte compressed
        // pubkey, each with its push opcode. No witness, and no discount.
        //
        // 72 bytes and not 71, deliberately: a low-S DER signature is one or the other with roughly
        // even odds, and `vsizeOf` must be an UPPER bound on the size — quoting under the real size
        // is a fee below the rate that was intended, which on a chain with a policy relay floor is
        // a transaction that is never forwarded. So the model is measured against the larger of the
        // two real cases.
        tx.addInput(
          Buffer.alloc(32, i + 1),
          0,
          undefined,
          bitcoin.script.compile([Buffer.alloc(72, 1), Buffer.alloc(33, 2)]),
        )
      }
      for (let o = 0; o < outputs; o++) {
        tx.addOutput(bitcoin.address.toOutputScript(DOGE_TREASURY, DOGE_TESTNET), 1_000)
      }
      const actual = tx.virtualSize()
      const predicted = vsizeOf(inputs, outputs, 'doge')
      assert.ok(
        predicted >= actual && predicted - actual <= 2,
        `${inputs}-in ${outputs}-out: predicted ${predicted}, real ${actual} — must be an upper bound and tight`,
      )
      // And the segwit model would have been WRONG, not merely different. Stated as a ratio so it
      // fails if either model drifts toward the other.
      assert.ok(
        vsizeOf(inputs, outputs, 'doge') > vsizeOf(inputs, outputs, 'btc'),
        'the legacy model must never quote at or below the discounted one',
      )
    }
    assert.ok(vsizeOf(5, 1, 'doge') > 2 * vsizeOf(5, 1, 'btc') - 60, 'the gap is inputs, and it is large')
  })

  /**
   * **THE FEE CEILING IS PER-CHAIN, AND THE SHARED ONE WAS WRONG IN BOTH DIRECTIONS FOR DOGECOIN.**
   *
   * Dogecoin's ordinary fee is ~1000 koinu/vB — `RECOMMENDED_MIN_TX_FEE = COIN / 100` in
   * `dogecoin/dogecoin`, `src/policy/policy.h`. That is not a fee market, it is a policy constant,
   * and it sits ABOVE the shared sweep ceiling of 900 this service used to apply to every chain. So
   * the old bound would have refused every Dogecoin sweep for ever, silently, as a fee that looked
   * too high — while the same bound is a sane ceiling on Bitcoin, where 900 sat/vB is a once-a-year
   * congestion event.
   */
  it('applies a DOGE fee bound that admits a rate the old shared bound would have refused', () => {
    const rateBelowOldBound = 900n
    const dogeOrdinary = 1_000n
    // The old shared numbers, restated from what Bitcoin still carries so this is a comparison
    // against the live values rather than against two literals typed here.
    assert.equal(ceilingsFor('btc').sweep, rateBelowOldBound)
    assert.ok(ceilingsFor('doge').sweep > dogeOrdinary, "Dogecoin's ordinary rate must be BUILDABLE")
    assert.ok(ceilingsFor('doge').payment > ceilingsFor('doge').sweep)
    // Bitcoin and Litecoin are untouched, so this is a per-chain table and not a global raise —
    // the exact failure mode that "make the ceiling bigger" would have been.
    assert.deepEqual(ceilingsFor('ltc'), ceilingsFor('btc'))
    assert.equal(ceilingsFor('btc').payment, MAX_SAT_PER_VB)
    assert.equal(ceilingsFor('btc').sweep, MAX_SWEEP_SAT_PER_VB)

    // Custody's table is the authority and this service's mirror must be strictly tighter, on
    // every chain and on both shapes. Asserted as a relationship rather than as values.
    for (const chain of ['btc', 'ltc', 'doge'] as const) {
      assert.ok(ceilingsFor(chain).sweep < custodyCeilings(chain).sweep, `${chain} sweep`)
      assert.ok(ceilingsFor(chain).payment < custodyCeilings(chain).payment, `${chain} payment`)
    }
    assert.equal(custodyCeilings('btc').payment, CUSTODY_MAX_PAYMENT_SAT_PER_VB)
    assert.equal(custodyCeilings('btc').sweep, CUSTODY_MAX_SWEEP_SAT_PER_VB)
  })

  it('refuses a DOGE fee above the DOGE bound, and accepts one the shared bound would have refused', () => {
    const psbt = new bitcoin.Psbt({ network: DOGE_TESTNET })
    const funding = dogeFunding(7, 500_000_000n)
    psbt.addInput({
      hash: funding.txid,
      index: 0,
      sighashType: bitcoin.Transaction.SIGHASH_ALL,
      nonWitnessUtxo: Buffer.from(funding.hex, 'hex'),
    })
    psbt.addOutput({ address: DOGE_USER, value: 400_000_000 })
    const vsize = BigInt(finalisedVsize(psbt, 'doge'))

    // 10,000 koinu/vB: ten times Dogecoin's ordinary rate, and TWICE the shared payment ceiling of
    // 5,000 that custody applied to every chain before its table became per-chain. This is the rate
    // the old bound would have refused and the new one must admit.
    assert.doesNotThrow(() =>
      assertUnderCustodysCeiling(psbt, 10_000n * vsize, 'payment', 'doge'),
    )
    // The same rate on Bitcoin is still refused, so the bound moved for one chain and not for all.
    assert.throws(
      () => assertUnderCustodysCeiling(psbt, 10_000n * vsize, 'payment', 'btc'),
      FeeOutOfBandError,
    )
    // And Dogecoin still HAS a ceiling. Above it, a node has quoted something absurd and the answer
    // is to wait rather than to burn a customer's deposit on miner revenue.
    assert.throws(
      () => assertUnderCustodysCeiling(psbt, 60_000n * vsize, 'payment', 'doge'),
      FeeOutOfBandError,
    )
    // The sweep shape is the tighter of the two on Dogecoin exactly as it is on Bitcoin.
    assert.throws(
      () => assertUnderCustodysCeiling(psbt, 20_000n * vsize, 'sweep', 'doge'),
      FeeOutOfBandError,
    )
    assert.doesNotThrow(() => assertUnderCustodysCeiling(psbt, 5_000n * vsize, 'sweep', 'doge'))
  })

  it("falls back to Dogecoin's own relay floor, which is a hundred times Bitcoin's", async () => {
    /*
     * `dogecoin/dogecoin`, `src/validation.h`: `DEFAULT_MIN_RELAY_TX_FEE = RECOMMENDED_MIN_TX_FEE /
     * 10` = 100,000 koinu per kvB = 100 koinu/vB, against 1 sat/vB on Bitcoin and Litecoin. The
     * floor is only reached when `estimatesmartfee` has too little data — the ordinary state of a
     * fresh node and of testnet — and a Dogecoin transaction built at 1 koinu/vB is a signed
     * transaction no node forwards, permanently, because a policy floor does not fall the way a fee
     * market does.
     */
    const node = fakeDogeNode({ feerate: null })
    const fee = await chainFor('doge').estimateFee(node.call, BOUNDS)
    assert.equal(fee, 100n * BigInt(vsizeOf(1, 2, 'doge')))

    const btc = await chainFor('btc').estimateFee(fakeBtcNode({ feerate: null }).call, BOUNDS)
    assert.equal(btc, 1n * BigInt(vsizeOf(1, 2, 'btc')))
  })

  it("uses Dogecoin's flat dust limit of 0.01 DOGE, not a size-derived threshold", async () => {
    /*
     * `dogecoin/dogecoin`, `src/primitives/transaction.h` defines `IsDust(dustLimit)` as
     * `nValue < dustLimit` — flat, where Bitcoin and Litecoin scale `DUST_RELAY_TX_FEE` by the size
     * of the output plus the input that would one day spend it. `src/policy/policy.h` gives
     * `DEFAULT_DUST_LIMIT = RECOMMENDED_MIN_TX_FEE = COIN / 100` = 1,000,000 koinu.
     *
     * Bitcoin's 546 is not conservative here, it is wrong in the dangerous direction by a factor of
     * nearly two thousand: a 1,000-koinu change output would be built, signed, and answered `dust`
     * by `sendrawtransaction`, after this chain's single outbound slot was claimed.
     */
    const funding = [{ ...dogeFunding(2, 500_000_000n), sats: 500_000_000n }]
    const node = fakeDogeNode({ funding, feerate: 0.01 })
    const payment = (value: bigint): Promise<unknown> =>
      chainFor('doge').build(node.call, {
        from: DOGE_TREASURY,
        to: DOGE_USER,
        value,
        fee: 100_000_000n,
        bounds: BOUNDS,
        shape: 'payment',
      })
    // Comfortably above Bitcoin's 546 and Litecoin's 5,460, and below Dogecoin's 1,000,000 — the
    // window that only Dogecoin's own number closes. A test at 100 would pass against every
    // threshold in the table and prove nothing.
    await assert.rejects(payment(100_000n), FeeOutOfBandError)
    assert.ok(await payment(1_000_001n), 'just above it is a threshold, not a ban on small payments')
  })

  it("reads Dogecoin's confirmation depth from the registry rather than restating it", async () => {
    // 30, against Bitcoin's 6 — a minute a block against ten. Read from the exact-pinned
    // contracts-chain, so this fails if the package and the adapter ever disagree.
    const depth = chainSpec('DOGE').confirmations
    assert.ok(depth > chainSpec('BTC').confirmations)
    const shallow = dogeFunding(3, 500_000_000n)
    const node = fakeDogeNode({
      funding: [{ ...shallow, sats: 500_000_000n }],
      confirmations: depth - 1,
    })
    assert.equal(await chainFor('doge').spendableBalance(node.call, DOGE_TREASURY), 0n)
    const deep = fakeDogeNode({ funding: [{ ...shallow, sats: 500_000_000n }], confirmations: depth })
    assert.equal(await chainFor('doge').spendableBalance(deep.call, DOGE_TREASURY), 500_000_000n)
  })

  it('is an implemented chain, and hands custody the name custody stores', () => {
    assert.equal(chainFor('doge').unimplementedPhase, null)
    assert.equal(chainFor('doge').chain, 'doge')
    assert.equal(chainFor('doge').family, 'bitcoin')
    assert.equal(chainFor('doge').tokens, null)
    assert.ok(implementedChains().includes('doge'))
    // `doge` is this service's slug; `dogecoin` is the string custody compares character for
    // character before it signs, and it is asserted here against the exported constant rather than
    // against a literal typed a second time. `bitcoin` here would resolve to the wrong treasury,
    // and on a UTXO chain there is no chain id in the signature to catch it afterwards.
    assert.equal(custodyChainOf('doge'), CUSTODY_CHAIN_DOGE)
    assert.notEqual(CUSTODY_CHAIN_DOGE, custodyChainOf('btc'))
    assert.equal(custodyFamilyOf('doge'), 'bitcoin')
    assert.equal(chainForAsset('DOGE'), 'doge')
    assert.equal(assetOf('doge'), 'DOGE')
  })

  it("bounds the amount by Dogecoin's MAX_MONEY, which is not a supply cap", () => {
    // `dogecoin/src/amount.h`: `MAX_MONEY = 10000000000 * COIN`. It is a consensus sanity bound on
    // a single value and Dogecoin has no fixed supply at all, so it is far above anything that
    // exists — which is fine, because the job of this bound is to refuse a node answer that is
    // impossible, not to model economics.
    assert.equal(btcToSats(10_000_000_000, 'doge'), 1_000_000_000_000_000_000n)
    assert.throws(() => btcToSats(10_000_000_001, 'doge'), AddressError)
    // Bitcoin's 21 million would refuse a genuine Dogecoin balance, which is the copy this table
    // exists to stop.
    assert.throws(() => btcToSats(1_000_000_000, 'btc'), AddressError)
    assert.equal(btcToSats(1_000_000_000, 'doge'), 100_000_000_000_000_000n)
  })
})
