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
import {
  CUSTODY_MAX_PAYMENT_SAT_PER_VB,
  CUSTODY_MAX_SWEEP_SAT_PER_VB,
  MAX_SAT_PER_VB,
  MAX_SWEEP_SAT_PER_VB,
  assertUnderCustodysCeiling,
  bitcoinChain,
  btcToSats,
  buildSweepPsbt,
  finalisedVsize,
  networkFor,
  satsToBtc,
  selectCoins,
  sweepPlan,
  validateAddress,
  vsizeOf,
  type Utxo,
} from './bitcoin.ts'
import { AddressError, FeeOutOfBandError, InsufficientTreasuryError, type ChainCall } from './chains.ts'
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
    assert.equal(validateAddress(TREASURY, 'testnet'), TREASURY)
    assert.equal(validateAddress(MAINNET_ADDRESS, 'mainnet'), MAINNET_ADDRESS)
    // The binding that stops a payment being broadcastable on the chain it was not meant for.
    assert.throws(() => validateAddress(MAINNET_ADDRESS, 'testnet'), AddressError)
    assert.throws(() => validateAddress(TREASURY, 'mainnet'), AddressError)
  })

  it('does NOT case-normalise, because base58check is case-significant', () => {
    // Lower-casing this produces a string that fails its own checksum and is not the address.
    assert.equal(chainFor('btc').canonicalise(MAINNET_ADDRESS), MAINNET_ADDRESS)
    assert.equal(chainFor('btc').addressKey(MAINNET_ADDRESS), MAINNET_ADDRESS)
    assert.throws(() => chainFor('btc').canonicalise(MAINNET_ADDRESS.toLowerCase()), AddressError)
  })

  it('refuses a checksum failure and an empty string', () => {
    assert.throws(() => validateAddress('', 'testnet'), AddressError)
    assert.throws(() => validateAddress('tb1qnotanaddress', 'testnet'), AddressError)
    assert.throws(() => validateAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3', 'mainnet'), AddressError)
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

  it('crosses from pending to confirmed at the declared depth of three', async () => {
    for (const [confirmations, kind] of [
      [1, 'pending'],
      [2, 'pending'],
      [3, 'confirmed'],
      [9, 'confirmed'],
    ] as const) {
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
    assert.equal(networkFor('mainnet'), bitcoin.networks.bitcoin)
    assert.equal(networkFor('testnet'), bitcoin.networks.testnet)
    assert.notEqual(networkFor('mainnet').bech32, networkFor('testnet').bech32)
  })
})
