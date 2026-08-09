/**
 * The registry, and the one chain that is a real object and is not implemented.
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
  CUSTODY_CHAIN_DOGE,
  CUSTODY_CHAIN_ETC,
  NotImplementedError,
  assetOf,
  chainForAsset,
  chainKey,
  custodyChainOf,
  familyOf,
  isChainId,
  isNetwork,
} from './chains.ts'
import { chainFor, chainStatuses, implementedChains } from './registry.ts'
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
    // and shares `evm.ts` unchanged; DOGE really is `bitcoin` and now shares `bitcoin.ts` — but it
    // took a per-chain address kind, prev-out field, vsize model, dust threshold, relay floor and
    // fee ceiling to get there, because the family says the RPC and the transaction structure are
    // Bitcoin's and says nothing about segwit. A family is not a capability.
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
   * The two newest names, and the one value each may never take.
   *
   * These were the only entries in that table not checked against a row custody actually stores,
   * because custody's `CHAIN_ASSET` had neither. It has both now — `dogecoin → 'DOGE'` and
   * `'ethereum-classic' → 'ETC'`, read on 2026-08-09 — so the positive assertion is worth making,
   * and it is made **against the exported constant the table itself reads**, not against a string
   * literal typed a second time. A literal here would agree only with itself: someone editing
   * `CUSTODY_CHAIN` would change the table, this test would go red, and the obvious fix would be to
   * change the literal too, which is a test that ratifies whatever the code says.
   *
   * The negative assertions are the ones that matter most and they are unconditional. `ethereum`
   * for `etc` and `bitcoin` for `doge` would each RESOLVE: custody would answer with the other
   * chain's treasury address, and this service would adopt one position as another's. A name
   * custody does not know is refused and costs a log line; a name it knows for a DIFFERENT chain is
   * a bookkeeping fault that no gate at signing time can undo, because a pin is adopted long before
   * anything is signed. On DOGE there is not even a gate to undo it with — a UTXO signature commits
   * to no chain id at all.
   */
  it('never lets a new chain borrow an existing chain’s custody name', () => {
    assert.equal(custodyChainOf('etc'), CUSTODY_CHAIN_ETC)
    assert.equal(custodyChainOf('doge'), CUSTODY_CHAIN_DOGE)
    assert.notEqual(CUSTODY_CHAIN_ETC, 'ethereum')
    assert.notEqual(CUSTODY_CHAIN_DOGE, 'bitcoin')
    assert.notEqual(custodyChainOf('etc'), custodyChainOf('eth'))
    assert.notEqual(custodyChainOf('doge'), custodyChainOf('btc'))
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

  it('implements everything but xrp today', () => {
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
    // ETC and DOGE joined together and on completely different terms, which is the pair worth
    // reading together. Both are "the same family as a chain already here". ETC's family claim
    // survives contact with the builder — `evm.ts` signs legacy type-0 for `ember` and `eth` alike,
    // and legacy is all a pre-London chain will accept — so there the one-word edit really was the
    // whole change. DOGE's did not: `bitcoin.ts` was P2WPKH from end to end and Dogecoin has no
    // segwit, so the one-word edit would have quoted every fee at under half the transaction's real
    // size and produced signed payments no node relays. It took a per-chain address kind, prev-out
    // field, vsize model, dust threshold, relay floor and fee ceiling before the word could be
    // written. Family membership is what the registry consults; whether the adapter's ASSUMPTIONS
    // hold is a separate question, and it has to be asked once per chain.
    assert.deepEqual([...implementedChains()].sort(), ['btc', 'doge', 'ember', 'etc', 'eth', 'ltc', 'sol'])
  })

  /**
   * A chain with an adapter and no endpoint is UNAVAILABLE, and the service still starts.
   *
   * Three statuses over every `ChainId`, because the two ways a chain does not work are two
   * different tickets against two different repositories. `unimplemented` is this build's
   * limitation and no deploy change fixes it; `no_endpoint` is the deploy's and no release fixes
   * it. The boot line in `index.ts` reports exactly this, which is what makes "why can I not
   * withdraw DOGE" answerable from a log rather than from a refused withdrawal an hour later.
   *
   * **Nothing here may throw for a missing endpoint.** Refusing to boot because one chain is
   * unconfigured takes down the chains that do work; answering `ready` anyway leaves a user's
   * balance reserved until the deadline. Reporting is the only correct third option.
   */
  it('reports an adapter with no endpoint as unavailable rather than throwing', () => {
    // Not URLs. This function reads presence and never a value — see the redaction argument on
    // `rpcUrls` in `env.ts` — and a test carrying a real endpoint here would be the first place a
    // credential-shaped string got written into this repository.
    const statuses = chainStatuses({ ember: 'configured', doge: 'configured' })
    const status = (chain: string): string => statuses.find((s) => s.chain === chain)!.status
    assert.equal(statuses.length, CHAIN_IDS.length, 'every chain is named, including the broken ones')
    assert.equal(status('ember'), 'ready')
    assert.equal(status('doge'), 'ready', 'an endpoint is all DOGE was ever missing')
    assert.equal(status('etc'), 'no_endpoint')
    assert.equal(status('btc'), 'no_endpoint')
    assert.equal(status('xrp'), 'unimplemented', 'no endpoint could make this one work')
    // The empty deploy: every implemented chain unavailable, and this still answers rather than
    // raising. This is the shape of a fresh environment, and a fresh environment must boot.
    const bare = chainStatuses({})
    assert.equal(bare.filter((s) => s.status === 'ready').length, 0)
    assert.equal(bare.filter((s) => s.status === 'unimplemented').length, 1)
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
   * That is the whole content of the remaining entry and it is worth asserting: BTC, SOL and DOGE
   * were each unimplemented at some point on the strength of claims about CUSTODY, and every one of
   * those claims turned out to be either wrong when written or stale by the time it was read. XRP
   * is the opposite case — custody signs it today, with a payment shape and a pinned sweep shape —
   * so the message must not blame custody for it.
   *
   * **The four chains that left this list are asserted to have left it**, because an entry here is
   * a permanent refusal with an immediate refund, and a chain that works while its adapter still
   * says it does not is a withdrawal refunded for a reason that is no longer true.
   */
  it('names whose limitation each unimplemented chain is', () => {
    for (const chain of ['btc', 'sol', 'ltc', 'doge', 'etc'] as const) {
      assert.equal(chainFor(chain).unimplementedPhase, null, `${chain} is implemented`)
    }
    assert.match(chainFor('xrp').unimplementedPhase!, /XRPL adapter/)
    const refusal = (chain: 'xrp'): string => {
      try {
        chainFor(chain).canonicalise('x')
        return ''
      } catch (err) {
        return (err as Error).message
      }
    }
    assert.match(refusal('xrp'), /custody already signs XRP/, 'the gap is on this side and must say so')
    assert.match(refusal('xrp'), /this side/)
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
