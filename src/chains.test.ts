/**
 * The registry, and the three chains that are real objects and are not implemented.
 *
 * The point of these tests is that an unimplemented chain is not a hole in a lookup table. Every
 * `ChainId` resolves to an object, every method of an unimplemented one throws a
 * `NotImplementedError` naming the phase, and the withdrawal classifier turns that into a permanent
 * refusal with a refund. Without this, a BTC withdrawal is a `TypeError` in a job handler.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  CHAIN_IDS,
  NotImplementedError,
  assetOf,
  chainForAsset,
  chainKey,
  custodyChainOf,
  familyOf,
  isChainId,
  isNetwork,
} from './chains.ts'
import { chainFor, implementedChains } from './registry.ts'
import { planBuildFailure } from './withdrawals.ts'

describe('chain identity', () => {
  it('agrees with contracts-chain about every family, and restates none of it', () => {
    assert.equal(familyOf('ember'), 'ember')
    assert.equal(familyOf('eth'), 'evm')
    assert.equal(familyOf('btc'), 'bitcoin')
    assert.equal(familyOf('sol'), 'solana')
    assert.equal(familyOf('xrp'), 'xrp')
  })

  it('round-trips a chain and its asset', () => {
    for (const chain of CHAIN_IDS) {
      assert.equal(chainForAsset(assetOf(chain)), chain)
    }
    // SHARD has no chain by design: it is a platform unit, and a deposit address for it could only
    // ever be a lie.
    assert.equal(chainForAsset('SHARD'), null)
  })

  /**
   * The one place this service's vocabulary and custody's disagree.
   *
   * custody keys its chains by NAME because those are the values the rows it adopted from
   * forge-keyvault already carry. This service uses the asset code lowercased. They agree on four of
   * five, and getting the fifth wrong is a 403 `binding_mismatch` whose message deliberately will
   * not say which field was wrong — so it is a table with a name rather than a `toLowerCase()` that
   * happens to work for the other four.
   */
  it('translates eth to custody ethereum and leaves the other four alone', () => {
    assert.equal(custodyChainOf('eth'), 'ethereum')
    assert.equal(custodyChainOf('ember'), 'ember')
    assert.equal(custodyChainOf('btc'), 'bitcoin')
    assert.equal(custodyChainOf('sol'), 'solana')
    assert.equal(custodyChainOf('xrp'), 'xrp')
  })

  it('builds the lease key from the contended resource', () => {
    assert.equal(chainKey('ember', 'testnet'), 'ember:testnet')
  })

  it('refuses anything that is not a chain or a network', () => {
    assert.equal(isChainId('ethereum'), false, "custody's name is not this service's slug")
    assert.equal(isChainId('shard'), false)
    assert.equal(isNetwork('devnet'), false)
  })
})

describe('the registry', () => {
  it('is total over every chain id — there is no undefined branch', () => {
    for (const chain of CHAIN_IDS) {
      const adapter = chainFor(chain)
      assert.equal(adapter.chain, chain)
      assert.equal(adapter.family, familyOf(chain))
    }
  })

  it('implements ember, eth, btc and sol today', () => {
    // BTC joined when `bitcoin.ts` landed and SOL when `solana.ts` did. Both were once refused for
    // reasons about custody that this repository had written down and that are no longer true —
    // see the block at the head of `registry.ts` for how each claim was wrong.
    assert.deepEqual([...implementedChains()].sort(), ['btc', 'ember', 'eth', 'sol'])
  })

  /**
   * Every method throws, and each names its phase.
   *
   * A stub returning `0n` for a fee and an empty status would build a free transaction and then
   * report it missing, which is indistinguishable from a chain outage — and is how a half-built
   * adapter reaches production.
   */
  it('throws NotImplementedError from every method of an unimplemented chain', async () => {
    for (const chain of ['xrp'] as const) {
      const adapter = chainFor(chain)
      assert.ok(adapter.unimplementedPhase, `${chain} must name its phase`)
      assert.throws(() => adapter.canonicalise('x'), NotImplementedError)
      assert.throws(() => adapter.addressKey('x'), NotImplementedError)
      assert.throws(() => adapter.isValidDestination('x'), NotImplementedError)
      assert.throws(() => adapter.txIdOf('0x00'), NotImplementedError)
      const call = { network: 'testnet' as const, rpc: async () => null }
      const bounds = { minGasPriceWei: 0n, maxGasPriceWei: 0n, maxFeeWei: 0n }
      await assert.rejects(adapter.estimateFee(call, bounds), NotImplementedError)
      await assert.rejects(adapter.spendableBalance(call, 'x'), NotImplementedError)
      // Rejects rather than answering `null`. `null` is this method's word for "not worth sweeping
      // right now", which the sweeper treats as ordinary and silent — so an unimplemented chain
      // answering it would look exactly like a chain with nothing to sweep, for ever.
      await assert.rejects(adapter.sweepQuote(call, 'x', bounds), NotImplementedError)
      await assert.rejects(
        adapter.build(call, { from: 'a', to: 'b', value: 1n, fee: 1n, bounds, shape: 'payment' }),
        NotImplementedError,
      )
      await assert.rejects(adapter.broadcast(call, '0x00'), NotImplementedError)
      await assert.rejects(adapter.status(call, '0x00'), NotImplementedError)
      await assert.rejects(
        adapter.proveDead(call, { from: 'a', rawTx: '0x00', txHash: null, signedNonce: null, signedExpiry: null }),
        NotImplementedError,
      )
    }
  })

  /**
   * XRP names whose limitation it is, and it is THIS service's.
   *
   * That is the whole content of the remaining entry and it is worth asserting: BTC and SOL were
   * both unimplemented on the strength of claims about CUSTODY, and both claims turned out to be
   * either wrong when written or stale by the time they were read. XRP is the opposite case —
   * custody signs it today, with a payment shape and a pinned sweep shape — so the message must not
   * blame custody for it.
   */
  it('names whose limitation the one unimplemented chain is', () => {
    assert.equal(chainFor('btc').unimplementedPhase, null, 'btc is implemented')
    assert.equal(chainFor('sol').unimplementedPhase, null, 'sol is implemented')
    assert.match(chainFor('xrp').unimplementedPhase!, /XRPL adapter/)
    const message = (() => {
      try {
        chainFor('xrp').canonicalise('x')
        return ''
      } catch (err) {
        return (err as Error).message
      }
    })()
    assert.match(message, /custody already signs XRP/, 'the gap is on this side and must say so')
    assert.match(message, /this side/)
  })

  it('classifies an unimplemented chain as a permanent, immediately refunded build failure', () => {
    const err = new NotImplementedError('btc', 'phase 8', 'building', 'no output policy')
    const plan = planBuildFailure(err)
    assert.equal(plan.classification, 'chain_unsupported')
    // Immediately, not at the deadline: no number of retries brings a phase forward, and a
    // withdrawal that waits for one sits with a user's balance reserved for a quarter.
    assert.equal(plan.refund, 'now')
    assert.match(plan.reason, /BTC withdrawals are not available yet/)
  })
})
