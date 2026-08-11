/**
 * The HTTP indexer client, at the seam where a JSON body becomes a decision about money.
 *
 * `fetch` is injected, so nothing here reaches a network. That is the same rule the rest of this
 * repository keeps at the JSON-RPC seam, for the same reason: the code under test must be the REAL
 * parser — the one whose reading of `outpoints` decides which coins a withdrawal is built from —
 * and only the wire may be imaginary.
 *
 * ## Why this file exists at all
 *
 * `outpoints` (micro-org#382) is the first method on this client where a MISREADING IS SILENT.
 * `transaction` returning null falls through to the node; a wrong balance is caught by the
 * reconciliation it feeds. But a short outpoint list is indistinguishable from a swept address:
 * the caller builds a transaction over a subset of the coins and sends the rest to change, or
 * tells a funded user they have nothing. Every case below is one way that could happen.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { IndexerUnavailableError, httpIndexerClient } from './indexerclient.ts'

const ADDRESS = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'

/** A client whose every request is answered by `body`, with `status`. */
function clientAnswering(body: unknown, status = 200): ReturnType<typeof httpIndexerClient> {
  return httpIndexerClient({
    baseUrl: 'http://indexer.invalid',
    token: () => 'test-token',
    deadlineMs: 1_000,
    fetch: async () =>
      new Response(typeof body === 'string' ? body : JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
  })
}

const ROW = {
  txid: 'a'.repeat(64),
  vout: 1,
  amount: '600000000',
  blockHeight: 700_001,
}
const ANCHOR = {
  observedAtBlock: 700_010,
  observedAtBlockHash: 'ff'.repeat(32),
  requiredConfirmations: 6,
}

describe('outpoints', () => {
  it('parses every row, keeps the order, and reads the amount as a decimal string', async () => {
    const second = {
      txid: 'b'.repeat(64),
      vout: 0,
      amount: '18446744073709551617',
      blockHeight: 2,
    }
    const client = clientAnswering({ ...ANCHOR, outpoints: [ROW, second] })
    const answer = await client.outpoints('btc', 'mainnet', ADDRESS)

    assert.deepEqual(answer.outpoints, [
      { txid: ROW.txid, vout: 1, amount: 600_000_000n, blockHeight: 700_001 },
      // Past 2^64, which is the number a `Number` would round and a `bigint` will not. The estate
      // has no such coin; the point is that the parser never depends on there not being one.
      {
        txid: second.txid,
        vout: 0,
        amount: 18_446_744_073_709_551_617n,
        blockHeight: 2,
      },
    ])
    assert.equal(answer.observedAtBlock, 700_010)
    assert.equal(answer.observedAtBlockHash, ANCHOR.observedAtBlockHash)
    assert.equal(answer.requiredConfirmations, 6)
  })

  it('an empty list is an ANSWER — a swept address really does hold nothing', async () => {
    const answer = await clientAnswering({
      ...ANCHOR,
      outpoints: [],
    }).outpoints('btc', 'mainnet', ADDRESS)
    assert.deepEqual(answer.outpoints, [])
    assert.equal(answer.observedAtBlock, 700_010)
  })

  it('refuses a body with no list, rather than reading the absence as an empty list', async () => {
    // An older indexer, a proxy serving an error page with a 200, a route renamed. Every one of
    // them produces a body with no `outpoints` key, and "this address holds nothing" is the one
    // wrong answer that looks exactly like a right one.
    for (const body of [
      { ...ANCHOR },
      { ...ANCHOR, outpoints: null },
      { ...ANCHOR, outpoints: {} },
    ]) {
      await assert.rejects(
        () => clientAnswering(body).outpoints('btc', 'mainnet', ADDRESS),
        IndexerUnavailableError,
      )
    }
  })

  it('refuses a list with no height it was read at', async () => {
    // The anchor is what makes the list a reading rather than an opinion. Without it there is no
    // way to say, later, which record a payment was built from — and the indexer never omits it,
    // so a body that does is not an indexer answering.
    for (const body of [
      { outpoints: [ROW], observedAtBlockHash: ANCHOR.observedAtBlockHash },
      { outpoints: [ROW], observedAtBlock: 700_010 },
      {
        outpoints: [ROW],
        observedAtBlock: '700010',
        observedAtBlockHash: ANCHOR.observedAtBlockHash,
      },
    ]) {
      await assert.rejects(
        () => clientAnswering(body).outpoints('btc', 'mainnet', ADDRESS),
        IndexerUnavailableError,
      )
    }
  })

  it('THROWS on a malformed row instead of skipping it', async () => {
    // ══════════════════════════════════════════════════════════════════════════════════════════
    // The most important assertion in this file. `listunspent`'s parser skips a row it cannot
    // read, and that is right there: the node is both the proposer and the authority, so a coin it
    // will not describe is a coin it would not let us spend. Here the authority is `gettxout`, one
    // layer down — so a row dropped at THIS layer is a coin that never reaches the only check that
    // could have vouched for it. The list gets shorter and nothing downstream can tell.
    //
    // Each case pairs the bad row with a good one, so a parser that returned `[good]` — the
    // plausible, tidy-looking failure — fails these tests rather than passing them.
    // ══════════════════════════════════════════════════════════════════════════════════════════
    const broken: readonly unknown[] = [
      { ...ROW, txid: 123 },
      { ...ROW, vout: '1' },
      { ...ROW, vout: 1.5 },
      { ...ROW, amount: 600_000_000 },
      { ...ROW, amount: '600000000.5' },
      { ...ROW, amount: '-1' },
      { ...ROW, amount: '' },
      { ...ROW, amount: '0x10' },
      null,
      'a string',
    ]
    for (const row of broken) {
      await assert.rejects(
        () =>
          clientAnswering({ ...ANCHOR, outpoints: [ROW, row] }).outpoints(
            'btc',
            'mainnet',
            ADDRESS,
          ),
        IndexerUnavailableError,
        `${JSON.stringify(row)} must refuse the whole answer, not shorten it`,
      )
    }
  })

  it('turns every transport failure into an unavailability, and has no 404 case', async () => {
    // `custodyBalance` reads a 404 as an absence; this must not. A 404 read as `[]` states that an
    // address has been SWEPT — so a route that has moved, or a chain the replica does not follow,
    // would refuse a fully funded withdrawal for insufficient funds. Every failure is an outage
    // and no transaction is built.
    for (const status of [400, 401, 403, 404, 500, 501, 503]) {
      await assert.rejects(
        () => clientAnswering({ error: 'nope' }, status).outpoints('btc', 'mainnet', ADDRESS),
        IndexerUnavailableError,
        `${status} must not be an empty coin list`,
      )
    }
  })

  it('sends the address encoded, so an address is never a path', async () => {
    let asked = ''
    const client = httpIndexerClient({
      baseUrl: 'http://indexer.invalid',
      token: () => 'test-token',
      deadlineMs: 1_000,
      fetch: async (input) => {
        asked = String(input)
        return new Response(JSON.stringify({ ...ANCHOR, outpoints: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      },
    })
    await client.outpoints('btc', 'mainnet', '../../v1/admin')
    assert.equal(
      asked,
      'http://indexer.invalid/v1/custody/btc/mainnet/addresses/..%2F..%2Fv1%2Fadmin/outpoints',
    )
  })
})
