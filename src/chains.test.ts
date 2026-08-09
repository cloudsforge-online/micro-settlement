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
    // The two contracts-chain added on 2026-08-08, and both are asserted because both are the kind
    // of family membership that is easy to argue backwards from the adapter. ETC really is `evm`
    // and really does share `evm.ts`; DOGE really is `bitcoin` and deliberately does NOT share
    // `bitcoin.ts`, because the family says the RPC and the transaction structure are Bitcoin's and
    // says nothing about segwit. A family is not a capability.
    assert.equal(familyOf('etc'), 'evm')
    assert.equal(familyOf('doge'), 'bitcoin')
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
   * The place this service's vocabulary and custody's disagree.
   *
   * custody keys its chains by NAME because those are the values the rows it adopted from
   * forge-keyvault already carry. This service uses the asset code lowercased. Half the table
   * agrees, and getting one of the other half wrong is a 403 `binding_mismatch` whose message
   * deliberately will not say which field was wrong — so it is a table with a name rather than a
   * `toLowerCase()` that happens to work for the ones that match.
   */
  it('translates eth to custody ethereum and leaves the matching ones alone', () => {
    assert.equal(custodyChainOf('eth'), 'ethereum')
    assert.equal(custodyChainOf('ember'), 'ember')
    assert.equal(custodyChainOf('btc'), 'bitcoin')
    assert.equal(custodyChainOf('sol'), 'solana')
    assert.equal(custodyChainOf('xrp'), 'xrp')
  })

  /**
   * The two names custody does not hold yet, and the one value each may never take.
   *
   * `etc` and `doge` are the only entries in that table not checked against a row custody actually
   * stores, because custody's `CHAIN_ASSET` has neither — so what is asserted here is not that the
   * strings are right. It is that they are not the specific wrong ones. `ethereum` for `etc` and
   * `bitcoin` for `doge` would each RESOLVE: custody would answer with the other chain's treasury
   * address, and this service would adopt one position as another's. A name custody does not know
   * is refused and costs a log line; a name it knows for a different chain is a bookkeeping fault
   * that no gate at signing time can undo, because a pin is adopted long before anything is signed.
   */
  it('never lets a new chain borrow an existing chain’s custody name', () => {
    assert.notEqual(custodyChainOf('etc'), 'ethereum')
    assert.notEqual(custodyChainOf('doge'), 'bitcoin')
    // And no two chains share a name, which is the general form of the rule above.
    const names = CHAIN_IDS.map((chain) => custodyChainOf(chain))
    assert.equal(new Set(names).size, names.length, 'two chains translate to one custody name')
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

  it('implements ember, eth, etc, btc, ltc and sol today — xrp and doge are not', () => {
    // BTC joined when `bitcoin.ts` landed and SOL when `solana.ts` did. Both were once refused for
    // reasons about custody that this repository had written down and that are no longer true —
    // see the block at the head of `registry.ts` for how each claim was wrong.
    //
    // LTC joined without an adapter of its own: it is `bitcoinChain('ltc')`, the same code with
    // Litecoin's network parameters, dust threshold and confirmation depth. That it needed no new
    // adapter is exactly why it needed this list to be checked — a chain can be added here with a
    // one-word edit, and the one-word edit is what would have shipped Bitcoin's parameters under
    // Litecoin's name.
    //
    // ETC joined on the same terms and DOGE did not, which is the pair worth reading together.
    // Both are "the same family as a chain already here". ETC's family claim survives contact with
    // the builder — `evm.ts` signs legacy type-0 for `ember` and `eth` alike, and legacy is all a
    // pre-London chain will accept — so there the one-word edit really is the whole change. DOGE's
    // does not: `bitcoin.ts` is P2WPKH from end to end and Dogecoin has no segwit, so the same edit
    // would quote every fee at under half the transaction's real size. Family membership is what
    // the registry consults; whether the adapter's ASSUMPTIONS hold is a separate question, and it
    // has to be asked once per chain.
    assert.deepEqual([...implementedChains()].sort(), ['btc', 'ember', 'etc', 'eth', 'ltc', 'sol'])
  })

  /**
   * Every method throws, and each names its phase.
   *
   * A stub returning `0n` for a fee and an empty status would build a free transaction and then
   * report it missing, which is indistinguishable from a chain outage — and is how a half-built
   * adapter reaches production.
   */
  it('throws NotImplementedError from every method of an unimplemented chain', async () => {
    for (const chain of ['xrp', 'doge'] as const) {
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
  it('names whose limitation each unimplemented chain is', () => {
    assert.equal(chainFor('btc').unimplementedPhase, null, 'btc is implemented')
    assert.equal(chainFor('sol').unimplementedPhase, null, 'sol is implemented')
    assert.match(chainFor('xrp').unimplementedPhase!, /XRPL adapter/)
    const refusal = (chain: 'xrp' | 'doge'): string => {
      try {
        chainFor(chain).canonicalise('x')
        return ''
      } catch (err) {
        return (err as Error).message
      }
    }
    assert.match(refusal('xrp'), /custody already signs XRP/, 'the gap is on this side and must say so')
    assert.match(refusal('xrp'), /this side/)

    // DOGE is the third case: BOTH sides, and the message says both because an operator reading a
    // `failure_reason` column needs to know that pointing this service at a Dogecoin node would
    // not help. The builder's assumption is named first because it is this repository's to fix.
    assert.match(chainFor('doge').unimplementedPhase!, /no segwit/)
    assert.match(refusal('doge'), /witnessUtxo/, 'the message must name what this side assumes')
    assert.match(refusal('doge'), /Custody has no Dogecoin network parameters/)
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
