/**
 * The EVM adapter, without a database.
 *
 * Everything here is pure or fake-node-only, because every one of these is a rule that decides
 * whether a signature is asked for at all — and a rule that can only be exercised against a live
 * node is a rule nobody exercises.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { chainSpec } from '@cloudsforge/contracts-chain'
import { keccak256, sha3_256 } from './keccak.ts'
import {
  TRANSFER_GAS,
  canonicaliseEvm,
  evmTxHash,
  gasPriceBid,
  gasPriceForLockedFee,
  legacyNonce,
  quantity,
  toChecksumAddress,
} from './evm.ts'
import { AddressError, FeeOutOfBandError, InsufficientTreasuryError, UnsupportedDestinationError } from './chains.ts'
import { chainFor } from './registry.ts'
import { TEST_BOUNDS, TEST_FEE, fakeLegacyTx, fakeNode, testAddress } from './testsupport.ts'

/**
 * `UnsignedOutbound.payload` is `unknown`, because Bitcoin's is a base64 PSBT string rather than a
 * field map. An EVM payload IS a field map, so these tests narrow it once here — and assert that
 * it is one, which is a check the old `Record<string, unknown>` type quietly assumed.
 */
function fields(payload: unknown): Record<string, unknown> {
  assert.equal(typeof payload, 'object', 'an EVM payload is a field map')
  assert.notEqual(payload, null)
  return payload as Record<string, unknown>
}

describe('keccak256', () => {
  it('matches the published empty-string vector', () => {
    assert.equal(
      Buffer.from(keccak256(Buffer.alloc(0))).toString('hex'),
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    )
  })

  /**
   * The strong check. `sha3_256` is this exact sponge with the NIST padding byte, so agreeing with
   * OpenSSL over hundreds of lengths around the 136-byte rate boundary pins the permutation, the
   * rate, the lane packing and the absorb loop. That leaves precisely one constant — the domain
   * byte — which the vector above fixes.
   */
  it('agrees with OpenSSL SHA3-256 across the rate boundary', async () => {
    const { createHash, randomBytes } = await import('node:crypto')
    for (let length = 0; length < 300; length += 7) {
      const message = randomBytes(length)
      assert.equal(
        Buffer.from(sha3_256(message)).toString('hex'),
        createHash('sha3-256').update(message).digest('hex'),
        `sha3-256 disagreed at length ${length}`,
      )
    }
  })
})

describe('EIP-55 addresses', () => {
  it('produces the checksummed form from the EIP vectors', () => {
    assert.equal(
      toChecksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'),
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    )
    assert.equal(
      toChecksumAddress('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'),
      '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    )
  })

  it('accepts either single case but holds a mixed-case address to its checksum', () => {
    // Not claiming a checksum: accepted, because refusing it would reject the form the indexer
    // stores and the form every explorer copy button used to produce.
    assert.equal(
      canonicaliseEvm('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'),
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    )
    // Claiming one and failing it: a mistyped character, which is exactly what the checksum exists
    // to catch and the only typo protection a 20-byte address has.
    assert.throws(
      () => canonicaliseEvm('0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'),
      AddressError,
    )
    assert.throws(() => canonicaliseEvm('0x1234'), AddressError)
  })
})

describe('hex quantities', () => {
  it('refuses anything that is not a hex quantity rather than reading it as zero', () => {
    assert.equal(quantity('0x1e', 'test'), 30n)
    // A node that answers `null`, `"30"` or `0` for a balance must not be read as an empty account:
    // that is a build that concludes the treasury cannot cover a payment it could.
    for (const value of [null, undefined, 30, '30', '', '0x', {}]) {
      assert.throws(() => quantity(value, 'test'), /expected a hex quantity/)
    }
  })
})

describe('the fee bounds', () => {
  it('applies the floor, doubles, and caps at the ceiling', () => {
    // Below the floor: raised, then doubled.
    assert.equal(gasPriceBid(1n, TEST_BOUNDS, 'ember'), 2_000_000_000n)
    // Ordinary: doubled, because the price is locked at request time and paid minutes later.
    assert.equal(gasPriceBid(20_000_000_000n, TEST_BOUNDS, 'ember'), 40_000_000_000n)
    // The doubling would exceed the ceiling: capped rather than refused.
    assert.equal(gasPriceBid(300_000_000_000n, TEST_BOUNDS, 'ember'), 500_000_000_000n)
  })

  it('refuses a quote above the ceiling BEFORE doubling it', () => {
    // Checked before the doubling deliberately. Checking after would make every payment fail as
    // soon as the real price passed half the ceiling, so the bound would bite at a number nobody
    // configured.
    assert.throws(
      () => gasPriceBid(500_000_000_001n, TEST_BOUNDS, 'ember'),
      (err: unknown) => err instanceof FeeOutOfBandError && err.direction === 'above',
    )
  })

  it('recovers the gas price from a locked fee and refuses one out of band', () => {
    assert.equal(gasPriceForLockedFee(TEST_FEE, TEST_BOUNDS, 'ember'), 40_000_000_000n)

    const cases: ReadonlyArray<[bigint, 'below' | 'above', string]> = [
      [0n, 'below', 'a fee of zero cannot pay for a transaction'],
      // Indivisible by the intrinsic gas: the row was not written by a compatible quoter, which is
      // a corruption and not something to round away.
      [TEST_FEE + 1n, 'below', 'an indivisible fee'],
      [TRANSFER_GAS * 1n, 'below', 'below the gas price floor'],
      [TRANSFER_GAS * 600_000_000_000n, 'above', 'above the gas price ceiling'],
      [10n ** 19n, 'above', 'above the absolute fee ceiling'],
    ]
    for (const [fee, direction, why] of cases) {
      assert.throws(
        () => gasPriceForLockedFee(fee, TEST_BOUNDS, 'ember'),
        (err: unknown) => err instanceof FeeOutOfBandError && err.direction === direction,
        why,
      )
    }
  })
})

describe('the transaction id and the nonce, both derived from the bytes', () => {
  it('derives the id as keccak256 of exactly the bytes', () => {
    const bytes = fakeLegacyTx({ nonce: 7, gasPrice: 1n, gasLimit: 21000n, to: testAddress(1), value: 5n, chainId: 7412 })
    assert.equal(evmTxHash(bytes), `0x${Buffer.from(keccak256(Buffer.from(bytes.slice(2), 'hex'))).toString('hex')}`)
    assert.equal(evmTxHash('not hex'), null)
  })

  it('reads the nonce back out of a real legacy transaction', () => {
    for (const nonce of [0, 1, 127, 128, 255, 256, 65_535, 16_777_216]) {
      const bytes = fakeLegacyTx({
        nonce,
        gasPrice: 40_000_000_000n,
        gasLimit: TRANSFER_GAS,
        to: testAddress(0xa1),
        value: 10n ** 17n,
        chainId: 7412,
      })
      assert.equal(legacyNonce(bytes), BigInt(nonce), `nonce ${nonce} did not survive the round trip`)
    }
  })

  it('refuses to read a nonce out of anything that is not a legacy transaction', () => {
    // Null is a REFUSAL TO ADJUDICATE, never a nonce of zero: the adjudication path compares this
    // against the account's used count, and a wrong zero would prove a live transaction dead.
    assert.equal(legacyNonce('0x'), null)
    assert.equal(legacyNonce('0xdeadbeef'), null, 'not an RLP list')
    // An EIP-2718 typed envelope: its first byte is the type and never a list tag.
    assert.equal(legacyNonce('0x02f8'), null)
    // A list whose outer length does not span exactly these bytes.
    assert.equal(legacyNonce('0xc20102ff'), null)
  })
})

describe('building an EVM transfer', () => {
  const TREASURY = testAddress(0x7)
  const ALICE = testAddress(0xa1)
  const chain = chainFor('ember')

  function call(node = fakeNode({ balances: { [TREASURY.toLowerCase()]: 10n ** 19n } })) {
    return { node, call: { network: 'testnet' as const, rpc: node.rpc } }
  }

  it('assembles exactly the fields custody will sign, and nothing else', async () => {
    const { call: c } = call()
    const unsigned = await chain.build(c, {
      from: TREASURY,
      to: ALICE,
      value: 10n ** 17n,
      fee: TEST_FEE,
      bounds: TEST_BOUNDS,
      shape: 'payment',
    })
    // custody's `signEvm` refuses "a field this service does not sign", so an extra key here is a
    // 403 rather than a wider signature. This asserts the allowlist exactly.
    assert.deepEqual(Object.keys(fields(unsigned.payload)).sort(), [
      'chainId',
      'gasLimit',
      'gasPrice',
      'nonce',
      'to',
      'type',
      'value',
    ])
    assert.equal(fields(unsigned.payload)['type'], 0, 'Ember has no type-2 decoder and custody refuses 1559')
    // Amounts as DECIMAL STRINGS: custody refuses a non-safe-integer number rather than rounding
    // it, and one EMBER is 1e18, four orders of magnitude past what a double holds exactly.
    assert.equal(fields(unsigned.payload)['value'], '100000000000000000')
    assert.equal(fields(unsigned.payload)['gasLimit'], '21000')
    assert.equal(fields(unsigned.payload)['gasPrice'], '40000000000')
    assert.equal(unsigned.nonce, '0')
    // Null because a legacy transaction has no expiry at all: only a consumed nonce retires it.
    assert.equal(unsigned.expiry, null)
  })

  it('reads the nonce at PENDING, not latest', async () => {
    const { node, call: c } = call()
    await chain.build(c, { from: TREASURY, to: ALICE, value: 1n, fee: TEST_FEE, bounds: TEST_BOUNDS, shape: 'payment' })
    const nonceCall = node.calls.find((k) => k.method === 'eth_getTransactionCount')
    // A latest nonce ignores anything already in the mempool, which produces a second transaction
    // with the same nonce — at most one of which can ever be mined.
    assert.equal(nonceCall?.params[1], 'pending')
  })

  it('refuses a destination that runs code', async () => {
    const contract = testAddress(0xc0)
    const node = fakeNode({ balances: { [TREASURY.toLowerCase()]: 10n ** 19n }, contracts: [contract] })
    await assert.rejects(
      chain.build(
        { network: 'testnet', rpc: node.rpc },
        { from: TREASURY, to: contract, value: 1n, fee: TEST_FEE, bounds: TEST_BOUNDS, shape: 'payment' },
      ),
      UnsupportedDestinationError,
    )
  })

  it('refuses the zero address, which is where value goes to die', async () => {
    const { call: c } = call()
    await assert.rejects(
      chain.build(c, {
        from: TREASURY,
        to: '0x0000000000000000000000000000000000000000',
        value: 1n,
        fee: TEST_FEE,
        bounds: TEST_BOUNDS,
        shape: 'payment',
      }),
      UnsupportedDestinationError,
    )
  })

  it('fails early and specifically when the source cannot cover it', async () => {
    const node = fakeNode({ balances: { [TREASURY.toLowerCase()]: 1n } })
    // Specifically, rather than as a node refusing the broadcast with "insufficient funds" — which
    // a worker can only read as a generic broadcast failure and retry for ever.
    await assert.rejects(
      chain.build(
        { network: 'testnet', rpc: node.rpc },
        { from: TREASURY, to: ALICE, value: 10n ** 17n, fee: TEST_FEE, bounds: TEST_BOUNDS, shape: 'payment' },
      ),
      InsufficientTreasuryError,
    )
  })

  it('refuses a node whose chain id is not the one contracts-chain pins', async () => {
    // A signature made against it would be valid on the wrong network, and the bytes are
    // broadcastable there by anybody who sees them.
    const node = fakeNode({ chainId: 1, balances: { [TREASURY.toLowerCase()]: 10n ** 19n } })
    await assert.rejects(
      chain.build(
        { network: 'testnet', rpc: node.rpc },
        { from: TREASURY, to: ALICE, value: 1n, fee: TEST_FEE, bounds: TEST_BOUNDS, shape: 'payment' },
      ),
      /not the 7412 this build is pinned to/,
    )
  })

  it('refuses an out-of-band fee before asking the node anything at all', async () => {
    const { node, call: c } = call()
    await assert.rejects(
      chain.build(c, { from: TREASURY, to: ALICE, value: 1n, fee: 10n ** 19n, bounds: TEST_BOUNDS, shape: 'payment' }),
      FeeOutOfBandError,
    )
    assert.equal(node.calls.length, 0)
  })

  /**
   * **Ethereum Classic is pre-London, and this is the assertion that says so in transaction bytes.**
   *
   * ETC never adopted London: it has no base fee, and a node will reject a transaction carrying
   * `maxFeePerGas` outright rather than ignoring the field. Reusing this builder for it was
   * therefore a claim about what the builder emits, not a preference — so the claim is pinned here.
   * If somebody later teaches `evm.ts` to prefer 1559 when the node advertises a base fee (the
   * obvious optimisation for ETH, and a correct one there), this test fails on ETC before the
   * change reaches a chain that cannot accept it. The `type` key and the ABSENCE of the 1559 keys
   * are both asserted, because a builder that added them alongside `gasPrice` would still leave
   * `type` at 0.
   */
  it('builds ETC as legacy, with no 1559 field, on BOTH networks', async () => {
    const etc = chainFor('etc')
    /*
     * **BOTH NETWORKS, AND THE EXPECTED IDS COME FROM THE CONTRACT RATHER THAN FROM HERE.**
     *
     * 61 is ETC mainnet and 63 is Mordor. Writing them as literals in this file would make the test
     * agree with itself: the value the builder emits is read from the same exact-pinned package the
     * assertion would then restate, so a wrong entry there would move both sides together. What is
     * pinned as a literal instead is the SHAPE of the mistake — that the two networks are different
     * and that neither is Ethereum's — plus the numbers in one place, `chainSpec`, which custody
     * resolves independently and refuses a disagreement with.
     */
    const expected = chainSpec('ETC').chainId!
    assert.notEqual(expected.mainnet, expected.testnet, 'a shared id is a signature valid on both')
    assert.notEqual(expected.mainnet, chainSpec('ETH').chainId!.mainnet)
    assert.equal(expected.mainnet, 61)
    assert.equal(expected.testnet, 63)

    for (const network of ['mainnet', 'testnet'] as const) {
      const node = fakeNode({
        chainId: expected[network],
        balances: { [TREASURY.toLowerCase()]: 10n ** 19n },
      })
      const unsigned = await etc.build(
        { network, rpc: node.rpc },
        { from: TREASURY, to: ALICE, value: 10n ** 17n, fee: TEST_FEE, bounds: TEST_BOUNDS, shape: 'payment' },
      )
      const payload = fields(unsigned.payload)
      assert.equal(payload['type'], 0, network)
      assert.equal(payload['chainId'], expected[network], network)
      assert.equal(payload['maxFeePerGas'], undefined, network)
      assert.equal(payload['maxPriorityFeePerGas'], undefined, network)
      assert.equal(payload['gasPrice'], '40000000000', network)
      // The fee is EXACT at plan time on a legacy chain, and this is where that is visible: what
      // the row books is `gasLimit * gasPrice`, with no base fee to move between the quote and the
      // block and no priority-fee refund afterwards. Nothing in this service reads a receipt to
      // correct a fee, and on ETC there is nothing a receipt could correct.
      assert.equal(unsigned.fee, TEST_FEE, network)
      assert.equal(BigInt(String(payload['gasPrice'])) * TRANSFER_GAS, TEST_FEE, network)
    }

    // The mainnet id on the testnet network and the reverse: the gate is the pair, not the value.
    // A node answering 61 for a Mordor withdrawal is a node whose signature spends mainnet coin.
    for (const [network, wrong] of [
      ['testnet', expected.mainnet],
      ['mainnet', expected.testnet],
    ] as const) {
      const node = fakeNode({ chainId: wrong, balances: { [TREASURY.toLowerCase()]: 10n ** 19n } })
      await assert.rejects(
        etc.build(
          { network, rpc: node.rpc },
          { from: TREASURY, to: ALICE, value: 1n, fee: TEST_FEE, bounds: TEST_BOUNDS, shape: 'payment' },
        ),
        /this build is pinned to/,
        `${network} accepted chain id ${wrong}`,
      )
    }

    // And the same chain-id gate as every other EVM chain: a node answering Ethereum's 1 here is
    // one whose signatures would be replayable on a chain with far more value on it — which is the
    // reason `custodyChainOf('etc')` may never be `ethereum` either. The two guards sit at
    // different times: this one before signing, that one before an address is even adopted.
    const ethereum = fakeNode({ chainId: 1, balances: { [TREASURY.toLowerCase()]: 10n ** 19n } })
    await assert.rejects(
      etc.build(
        { network: 'testnet', rpc: ethereum.rpc },
        { from: TREASURY, to: ALICE, value: 1n, fee: TEST_FEE, bounds: TEST_BOUNDS, shape: 'payment' },
      ),
      /not the 63 this build is pinned to/,
    )
  })
})
