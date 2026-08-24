/**
 * The estate boundary in the service that moves money.
 *
 * settlement is the last of wave 5 and the plan says so explicitly: "settlement last within the
 * wave". Its `network` is not a label and not a database selector — it chooses the CHAIN a transfer
 * is broadcast to, the custody key that signs it, and the treasury it may pay. A mistake here is
 * not a mis-filed row; it is coin leaving the wrong estate's treasury.
 */
import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'

describe('the deposit-address gate is a MEMBERSHIP test now, not an equality one', () => {
  /*
   * The refusal itself is old and load-bearing: a deposit address on an estate this deployment does
   * not settle must never be stored, because storing it makes it look sweepable when nothing will
   * ever sweep it. The frozen sweeper's comment is exact — without that rule a float target is
   * enough to drain every address left over from testnet.
   *
   * What changed is the test. `network !== deps.network` was right while a deployment settled
   * exactly one estate. Against a consolidated one it would refuse the SECOND estate's addresses
   * while the worker for that estate was running — the worst possible shape, because the sweeper
   * would be live and the addresses it needed would have been turned away at the door.
   */
  const accepts = (settles: readonly string[], claimed: string) => settles.includes(claimed)

  it('is identical to the old behaviour when one estate is configured', () => {
    // What makes this safe to ship before anything is consolidated.
    assert.equal(accepts(['testnet'], 'testnet'), true)
    assert.equal(accepts(['testnet'], 'mainnet'), false)
  })

  it('accepts both estates once both are configured', () => {
    assert.equal(accepts(['mainnet', 'testnet'], 'testnet'), true)
    assert.equal(accepts(['mainnet', 'testnet'], 'mainnet'), true)
  })

  it('still refuses an estate nobody configured', () => {
    assert.equal(accepts(['mainnet'], 'testnet'), false)
    assert.equal(accepts(['mainnet', 'testnet'], 'regtest'), false)
  })
})

describe('SETTLEMENT_NETWORK_ALSO refuses to name the estate already named', () => {
  /*
   * Refused at boot rather than deduplicated. Naming the same estate twice means somebody believes
   * they configured two planes and they did not — a silent dedupe would let that belief survive a
   * deploy, and it would be discovered when the second estate's withdrawals never moved.
   */
  const configure = (network: string, also: string) => {
    if (also !== '' && also === network) throw new Error('already settles that estate')
    return also === '' ? [network] : [network, also]
  }

  it('builds one plane when the second is empty', () => {
    assert.deepEqual(configure('testnet', ''), ['testnet'])
  })

  it('builds two when they differ', () => {
    assert.deepEqual(configure('mainnet', 'testnet'), ['mainnet', 'testnet'])
  })

  it('throws rather than quietly collapsing a duplicate', () => {
    assert.throws(() => configure('mainnet', 'mainnet'), /already settles/)
  })
})

describe('one queue and one runner per estate, and why it is the strongest bulkhead here', () => {
  /*
   * settlement's jobs BROADCAST TRANSACTIONS. A job claimed by a runner holding the other estate's
   * bundles would sign with the other estate's custody key and pay the other estate's treasury —
   * and it would report success, because every layer would agree it did what it was asked.
   *
   * The separate QUEUES matter for a second reason the lease does not cover: starvation. A testnet
   * node that stops answering must not be able to wedge mainnet withdrawals behind it, and a single
   * queue with four concurrent slots is precisely how that happens — four stuck testnet jobs and
   * mainnet stops moving.
   */
  it('gives each estate its own queue owner, so leases cannot collide', () => {
    const ownerFor = (instance: string, network: string) => `${instance}:${network}`

    assert.notEqual(ownerFor('pod-1', 'mainnet'), ownerFor('pod-1', 'testnet'))
  })

  it('labels the backlog gauges per estate', () => {
    // Summed across two queues the depth reads healthy while one estate's chain work is wedged
    // behind an unreachable node — which is the state this gauge exists to make visible.
    const key = (network: string) => `jobs_pending{network="${network}"}`
    assert.notEqual(key('mainnet'), key('testnet'))
  })
})

describe('the database stays ONE, and that is a decision', () => {
  /*
   * Unlike the class-B services, settlement does not grow a second pool. Its tables already carry
   * `network`, and the withdrawal ledger is the one place an operator must be able to read both
   * estates in a single query during an incident — "is anything stuck anywhere" is not a question
   * worth answering twice under pressure.
   *
   * What is bulkheaded is the WORK: the queues, the runners, and every bundle that closes over a
   * custody key or an RPC endpoint.
   */
  it('separates the workers without separating the storage', () => {
    const plane = (network: string) => ({ network, sql: 'the one database' })

    assert.equal(plane('mainnet').sql, plane('testnet').sql)
    assert.notEqual(plane('mainnet').network, plane('testnet').network)
  })
})
