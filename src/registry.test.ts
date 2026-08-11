/**
 * The node transport, and the credential it could not send.
 *
 * `rpcFactory` built its `HttpClient` with `baseUrl: parsed.origin`, and `URL.origin` is scheme,
 * host and port — the userinfo was parsed and thrown away. Bitcoin, Litecoin and Dogecoin Core
 * authenticate JSON-RPC with HTTP Basic and have no anonymous mode, so every call to one of them
 * was answered 401. MEASURED from inside `cloudsforge-estate-settlement-1` on the mainnet estate,
 * against the endpoint that service's own boot line already reported as configured: no header →
 * 401 Unauthorized; `Authorization: Basic base64(user:pass)` → 200, `blocks=3156498`,
 * `initialblockdownload=false`. The node was up, synced and reachable the whole time.
 *
 * ## Why these tests may name `rpcFactory` when `ci.yml` forbids it everywhere else
 *
 * `AD — no test can reach a real network` bans the string from every other `*.test.ts`, because
 * `rpcFactory` is the only thing in this repository that can open a socket to a chain. This file
 * is the suite for that transport and cannot exist without naming it, so the control admits this
 * one file and then checks the property that makes the exception safe: every construction here
 * injects `RpcOptions.fetch`, and a transport built on an in-memory fetch has no socket to open.
 * That is enforced per line — see `ci.yml` — which is why `node()` below is the only place a
 * factory is built.
 *
 * ## What is asserted, and what would be worthless to assert
 *
 * The seam is `fetch`, not `HttpClient`. These tests read the headers that actually reach the
 * wire, so what they prove is that `@cloudsforge/http` puts the static `headers` bag where its own
 * precedence comment says it does (runtime/packages/http/src/index.ts:374-393). Stubbing the
 * client and asserting it was constructed with the right options would prove only that this file
 * and the assertion agree, and the whole defect was a disagreement between this file and the
 * transport underneath it.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import type { ChainId, JsonRpc } from './chains.ts'
import { EndpointCredentialsError, NoEndpointError, RpcError, rpcFactory } from './registry.ts'

/** One request the transport made, reduced to the two things this file has anything to say about. */
interface Sent {
  readonly url: string
  readonly headers: Headers
}

/**
 * A transport over an in-memory node.
 *
 * THE ONLY PLACE IN THIS FILE A FACTORY IS BUILT, and the `fetch` on this line is what `ci.yml`
 * greps for. Keep the construction on one line: a per-occurrence check that a line break defeats
 * is not a check, so the control fails loudly rather than quietly if this is ever reflowed.
 */
function node(
  urls: Record<string, string>,
  /**
   * What the node answers, when the test is about the answer rather than about the request.
   *
   * Default: 200 with a result, which is every test above this parameter and the only shape the
   * credential tests care about. A responder returns a whole `Response` — status included —
   * because the defect the failure tests below cover IS a status: Core reports an RPC error in
   * the HTTP status as well as in the body, and a helper that took only a body could not have
   * reproduced it.
   */
  respond?: () => Response,
): { rpc: (chain: ChainId) => JsonRpc; sent: Sent[] } {
  const sent: Sent[] = []
  const fetch: typeof globalThis.fetch = async (input, init) => {
    sent.push({ url: String(input), headers: new Headers(init?.headers) })
    if (respond) return respond()
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { chain: 'ok' } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }
  return { rpc: rpcFactory({ urls, deadlineMs: 1_000, fetch }), sent }
}

/** Exactly what Bitcoin Core sends: the RPC code in the status AND a well-formed envelope. */
function coreError(status: number, code: number, message: string): () => Response {
  return () =>
    new Response(JSON.stringify({ result: null, error: { code, message }, id: 1 }), {
      status,
      headers: { 'content-type': 'application/json' },
    })
}

/** What Core compares against: base64 of the DECODED `user:password`, as UTF-8 bytes. */
function basic(user: string, password: string): string {
  return `Basic ${Buffer.from(`${user}:${password}`, 'utf8').toString('base64')}`
}

describe('the JSON-RPC transport', () => {
  it('turns the userinfo in an endpoint into an HTTP Basic Authorization header', async () => {
    const { rpc, sent } = node({ ltc: 'http://rpcuser:rpcpassword@127.0.0.1:9332/' })
    await rpc('ltc')('getblockchaininfo', [])

    assert.equal(sent.length, 1)
    assert.equal(sent[0]?.headers.get('authorization'), basic('rpcuser', 'rpcpassword'))
    // The credential leaves the URL entirely. `redirect: 'manual'` and a proxy in the path are
    // both reasons a URL travels further than a header does, and `URL.origin` dropping the
    // userinfo is correct — it is only dropping it AND NOT REPLACING IT that was the defect.
    assert.equal(sent[0]?.url, 'http://127.0.0.1:9332/')
  })

  /**
   * The half of this that is not obvious from the header.
   *
   * `@`, `/`, `:`, `?` and `#` are URL syntax, so a password containing one is written
   * percent-encoded and `new URL` hands it back still encoded — measured: `p%40ss%3Aword` stays
   * `p%40ss%3Aword`. Core compares the decoded bytes, so presenting the encoded form is a 401 on a
   * password that is correct, which is indistinguishable from a typo in `bitcoin.conf` and sends
   * an operator to rotate a credential that never needed rotating.
   */
  it('decodes a percent-encoded password before it encodes the credential', async () => {
    const { rpc, sent } = node({ ltc: 'http://rpc%2Fuser:p%40ss%3Aword@127.0.0.1:9332/' })
    await rpc('ltc')('getblockchaininfo', [])

    assert.equal(sent[0]?.headers.get('authorization'), basic('rpc/user', 'p@ss:word'))
    // Explicitly NOT the encoded form. Both would be a `Basic` header and only one authenticates.
    assert.notEqual(sent[0]?.headers.get('authorization'), basic('rpc%2Fuser', 'p%40ss%3Aword'))
  })

  it('sends no authorization header at all when the endpoint carries no userinfo', async () => {
    // An EVM node takes no credential, and an empty `Basic :` would be a credential — one a node
    // with `rpcauth` configured rejects differently from no header at all.
    const { rpc, sent } = node({ ember: 'http://127.0.0.1:8545' })
    await rpc('ember')('eth_blockNumber', [])

    assert.equal(sent[0]?.headers.has('authorization'), false)
  })

  /**
   * **Two chains, one origin, two credentials.**
   *
   * The client cache is keyed on the whole URL string, which was merely tidy while every client
   * was anonymous and is a correctness property now. A deployment that puts Bitcoin Core and
   * Litecoin Core behind one reverse proxy gives both chains the same `parsed.origin` and
   * different `rpcuser`s; a cache keyed on the origin — or on anything else the credential is not
   * part of — would hand the second chain the first chain's header for the life of the process.
   * That failure is not a 401. The proxy answers, as the wrong node, and a Litecoin fee quote
   * comes back priced in Bitcoin.
   */
  it('does not share one client between two chains at the same origin', async () => {
    const { rpc, sent } = node({
      btc: 'http://btcuser:btcpass@127.0.0.1:8332/',
      ltc: 'http://ltcuser:ltcpass@127.0.0.1:8332/',
    })
    await rpc('btc')('getblockchaininfo', [])
    await rpc('ltc')('getblockchaininfo', [])

    assert.equal(sent[0]?.url, sent[1]?.url)
    assert.equal(sent[0]?.headers.get('authorization'), basic('btcuser', 'btcpass'))
    assert.equal(sent[1]?.headers.get('authorization'), basic('ltcuser', 'ltcpass'))
  })

  it('reuses one client for repeated calls on one chain', async () => {
    // The cache is still a cache: the same endpoint must not build a second client, or every
    // chain gets a fresh circuit breaker per call and the breaker stops meaning anything.
    const { rpc, sent } = node({ ltc: 'http://rpcuser:rpcpassword@127.0.0.1:9332/wallet/hot' })
    const ltc = rpc('ltc')
    await ltc('getblockchaininfo', [])
    await rpc('ltc')('getblockcount', [])

    assert.equal(sent.length, 2)
    // The path survives `parsed.origin` because it is passed per request, not baked into baseUrl.
    for (const call of sent) assert.equal(call.url, 'http://127.0.0.1:9332/wallet/hot')
  })

  it('keeps a username with no password, because `user:` is a credential a node may want', async () => {
    const { rpc, sent } = node({ ltc: 'http://rpcuser@127.0.0.1:9332/' })
    await rpc('ltc')('getblockchaininfo', [])

    assert.equal(sent[0]?.headers.get('authorization'), basic('rpcuser', ''))
  })
})

describe('an endpoint whose credentials cannot be read', () => {
  /**
   * A `%` is legal in a Core `rpcpassword` and illegal in a URL unless it is written `%25`, so
   * `50%more` parses (measured: `new URL('http://u:ab%zz@127.0.0.1:1').password` is `'ab%zz'`) and
   * then fails to decode. Refusing is the only honest answer: presenting the undecoded bytes is a
   * 401 that looks exactly like the defect this transport was fixed for.
   */
  it('refuses rather than presenting bytes it could not decode', async () => {
    const { rpc, sent } = node({ ltc: 'http://rpcuser:50%more@127.0.0.1:9332/' })
    await assert.rejects(rpc('ltc')('getblockchaininfo', []), EndpointCredentialsError)

    // Nothing was dialled. A request that cannot be authenticated is not worth a round trip, and
    // half of them would be a wrong password presented to a node that logs failures.
    assert.equal(sent.length, 0)
  })

  it('is classified as a missing endpoint everywhere one already is', async () => {
    const { rpc } = node({ ltc: 'http://rpcuser:50%more@127.0.0.1:9332/' })
    // `jobs.ts`, `server.ts` and `withdrawals.ts` each reach the missing-endpoint classification
    // by `instanceof NoEndpointError`. Subclassing is what stops the fourth caller forgetting.
    await assert.rejects(rpc('ltc')('getblockchaininfo', []), NoEndpointError)
  })

  /**
   * **The redaction, at the place most likely to break it.**
   *
   * This error is thrown while holding the operator's password, it names the chain, and its
   * message reaches an operator through `failure_reason` and through a 503 body. A message built
   * by string-interpolating "the value that failed to decode" would put a password in the
   * database and in an HTTP response, which is a rotation rather than a redeploy. Assert the
   * absence directly, so that adding the value back fails here rather than in a log store.
   */
  it('names the chain and the variable, and never the credential', async () => {
    const { rpc } = node({ ltc: 'http://rpcuser:50%more@127.0.0.1:9332/' })
    await assert.rejects(rpc('ltc')('getblockchaininfo', []), (err: unknown) => {
      assert.ok(err instanceof EndpointCredentialsError)
      assert.match(err.message, /'ltc'/)
      assert.match(err.message, /SETTLEMENT_RPC_URLS/)
      for (const secret of ['rpcuser', '50%more', '127.0.0.1', '9332']) {
        assert.equal(err.message.includes(secret), false, `the message leaked ${secret}`)
      }
      // The stack is what a logger prints when it is handed an Error and not a message.
      assert.equal((err.stack ?? '').includes('50%more'), false)
      return true
    })
  })

  it('still refuses a chain with no endpoint at all, by name', async () => {
    const { rpc } = node({})
    await assert.rejects(rpc('ltc')('getblockchaininfo', []), (err: unknown) => {
      assert.ok(err instanceof NoEndpointError)
      assert.equal(err instanceof EndpointCredentialsError, false)
      assert.equal(err.chain, 'ltc')
      return true
    })
  })
})

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * WHEN THE NODE SAYS NO IN THE STATUS LINE AS WELL AS IN THE BODY.
 *
 * An EVM node answers a failed call 200 with an `error` member. Bitcoin Core answers the same
 * envelope with the RPC code mapped onto the HTTP status — 500 for nearly everything, 404 for an
 * unknown method — and `HttpClient` throws on any non-2xx before the body is read. So on the three
 * chains whose words this service matches on, no `RpcError` was ever constructed and every
 * message-matched recovery in `bitcoin.ts` was unreachable:
 *
 *   * "Fee estimation disabled" → fall back to confirmed blocks. The estate's bitcoind runs
 *     `blocksonly`, so this is not a contingency: it is EVERY BTC fee quote, and all of them
 *     answered 500 on mainnet on 2026-08-11 with deposits already open.
 *   * "already in block chain" / -27 → return the derived txid, which is what makes a retried
 *     broadcast idempotent. A broadcast retried after a crash is the normal case.
 *   * "Method not found" → answer `null` for a node without `getblockstats`.
 *
 * These tests are at the transport because that is where the envelope was discarded. Asserting the
 * three call sites instead would prove each of them matches a string, which was never in doubt —
 * they were matching strings that could not arrive.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
describe('a node that reports its error in the HTTP status', () => {
  it("hands the caller the node's own words for a 500, not the transport's status line", async () => {
    const { rpc } = node(
      { btc: 'http://u:p@127.0.0.1:8332/' },
      coreError(500, -32603, 'Fee estimation disabled'),
    )
    await assert.rejects(rpc('btc')('estimatesmartfee', [6]), (err: unknown) => {
      assert.ok(err instanceof RpcError, `expected RpcError, got ${(err as Error)?.name}`)
      assert.equal(err.message, 'Fee estimation disabled')
      assert.equal(err.method, 'estimatesmartfee')
      return true
    })
  })

  it('translates the 404 Core answers for an unknown method', async () => {
    // `deriveFeeRateFromBlocks` answers `null` on this one and takes the relay floor. Untranslated
    // it threw, and the fee quote it was called from failed with it.
    const { rpc } = node(
      { doge: 'http://u:p@127.0.0.1:22555/' },
      coreError(404, -32601, 'Method not found'),
    )
    await assert.rejects(rpc('doge')('getblockstats', [1]), (err: unknown) => {
      assert.ok(err instanceof RpcError)
      assert.equal(err.message, 'Method not found')
      return true
    })
  })

  it('carries -27 through intact, which is what makes a re-broadcast idempotent', async () => {
    const { rpc } = node(
      { btc: 'http://u:p@127.0.0.1:8332/' },
      coreError(500, -27, 'Transaction already in block chain'),
    )
    await assert.rejects(rpc('btc')('sendrawtransaction', ['00']), (err: unknown) => {
      assert.ok(err instanceof RpcError)
      // The exact predicate `bitcoin.ts` runs on this message. Asserting the regex rather than
      // the string is what ties this test to the recovery it exists to keep alive.
      assert.match(err.message, /already in (block chain|mempool)|txn-already|-27\b/i)
      return true
    })
  })

  it('leaves a transport fault a transport fault', async () => {
    // A 502 from a reverse proxy in front of the node, with an HTML body. Nothing here is the
    // node's opinion about the request, and dressing it as an `RpcError` would let a recovery
    // written for the node's words fire on an outage instead — which for `broadcast` means
    // returning a txid for bytes that were never sent.
    const { rpc } = node({ btc: 'http://u:p@127.0.0.1:8332/' }, () =>
      new Response('<html><body>502 Bad Gateway</body></html>', {
        status: 502,
        headers: { 'content-type': 'text/html' },
      }),
    )
    await assert.rejects(rpc('btc')('getblockcount', []), (err: unknown) => {
      assert.equal(err instanceof RpcError, false, 'an HTML 502 is not an RPC error')
      assert.ok(err instanceof Error)
      assert.equal(err.name, 'HttpError')
      return true
    })
  })

  it('leaves a 401 alone, because a wrong credential is not the node refusing the method', async () => {
    // The single most likely non-2xx on these endpoints, and the one whose repair is a rotation
    // rather than a code change. Core sends it with no JSON body at all.
    const { rpc } = node({ ltc: 'http://u:p@127.0.0.1:9332/' }, () =>
      new Response('', { status: 401 }),
    )
    await assert.rejects(rpc('ltc')('getblockcount', []), (err: unknown) => {
      assert.equal(err instanceof RpcError, false)
      assert.equal((err as Error).name, 'HttpError')
      return true
    })
  })

  it('is not fooled by a failed body that merely parses', async () => {
    // `{"error":null}` is what a node sends alongside a RESULT, and truncation is real: the client
    // keeps the first 2,000 characters of a failed body. Neither is a fault the node described, so
    // neither may become an `RpcError` with an invented message.
    for (const body of ['null', '"Fee estimation disabled"', '{"error":null}', '{"resul']) {
      const { rpc } = node({ btc: 'http://u:p@127.0.0.1:8332/' }, () =>
        new Response(body, { status: 500 }),
      )
      await assert.rejects(rpc('btc')('getblockcount', []), (err: unknown) => {
        assert.equal(err instanceof RpcError, false, `${body} was translated`)
        return true
      })
    }
  })

  it('still reads the envelope a 200 carries, which is every EVM node', async () => {
    // The path that always worked, asserted so that the catch above cannot become the only way an
    // RpcError is ever built.
    const { rpc } = node({ ember: 'http://127.0.0.1:8545' }, () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'nonce too low' } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )
    await assert.rejects(rpc('ember')('eth_sendRawTransaction', ['0x00']), (err: unknown) => {
      assert.ok(err instanceof RpcError)
      assert.equal(err.message, 'nonce too low')
      return true
    })
  })

  it('never lets the endpoint out through the translated error', async () => {
    // The message on this path is chosen by the NODE, and the node cannot know the credential —
    // but the error that carries it is thrown one line from an `HttpError` whose `url` field holds
    // the whole endpoint. Asserted directly, because the difference between throwing `RpcError`
    // and re-wrapping the HttpError with its cause attached is one word and one rotation.
    const { rpc } = node(
      { btc: 'http://rpcuser:rpcpassword@127.0.0.1:8332/' },
      coreError(500, -32603, 'Fee estimation disabled'),
    )
    await assert.rejects(rpc('btc')('estimatesmartfee', [6]), (err: unknown) => {
      const printed = `${(err as Error).message}\n${(err as Error).stack ?? ''}\n${JSON.stringify(err)}`
      for (const secret of ['rpcuser', 'rpcpassword']) {
        assert.equal(printed.includes(secret), false, `the translated error leaked ${secret}`)
      }
      return true
    })
  })
})
