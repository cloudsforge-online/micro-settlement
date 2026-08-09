/**
 * The chain registry, and the node transport.
 *
 * Every chain in `CHAIN_IDS` has an entry here. **There is no `undefined` branch**, which is what
 * makes `chainFor` total: an unimplemented chain is a real object that throws
 * `NotImplementedError`, so a caller reaches a named refusal rather than a `TypeError` in a job
 * handler at three in the morning.
 *
 * The phases named below are the ones in 03-repository-responsibilities, and they are written into
 * the error message rather than into a comment because the message is what an operator reads out of
 * a `failure_reason` column when they ask why a withdrawal was refunded.
 */

import { HttpClient } from '@cloudsforge/http'
import type { Network } from '@cloudsforge/contracts-chain'
import { CHAIN_IDS, unimplementedChain, type ChainCall, type ChainId, type JsonRpc, type OutboundChain } from './chains.ts'
import { evmChain } from './evm.ts'
import { bitcoinChain } from './bitcoin.ts'
import { solanaChain } from './solana.ts'

/*
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE CLAIMS THIS TABLE USED TO MAKE ABOUT CUSTODY, AND HOW EACH ONE WAS WRONG
 *
 * Two entries here carried paragraphs about what custody would and would not sign. Both are now
 * gone from the table because both chains are implemented, and both are summarised here instead —
 * not out of sentiment, but because **this file is the second place in this repository where a
 * confident claim about another repository turned out to be false**, and the pattern is worth
 * being able to recognise the third time.
 *
 *   * **The BTC entry was wrong when it was written.** It said "neither a withdrawal nor a sweep
 *     is possible until that policy exists", citing `SWEEPABLE_FAMILIES`. The gate it cited reads
 *     `if (row.purpose === 'deposit' && !SWEEPABLE_FAMILIES.has(row.family))` — conditioned on
 *     `deposit`, so it never touched a `treasury`-purpose withdrawal at all. The sentence was true
 *     about sweeps and false about withdrawals, and it kept a gate item closed for the half that
 *     was never blocked. It is a REAL LINE misread, not an invented one, which is the failure mode
 *     to watch for: quoting the right file at the right line and drawing the wrong conclusion.
 *   * **The SOL entry was true when it was written and went stale.** It said `signSolana` "refuses
 *     SystemProgram::Transfer for EVERY purpose". It did. It does not now: `SolanaPolicy`
 *     (custody/src/signing.ts) has three disjoint shapes and `transfer` and `sweep` are each
 *     exactly one System Transfer. Nothing announced that; it was found by reading custody again.
 *   * The SOL entry also said admitting SOL "would hand a signing credential createAccount over
 *     every customer's SOL deposit key". That is now false in the OPPOSITE direction as well:
 *     `solanaShapeForPurpose` gives `mint` — the only shape `createAccount` is reachable under —
 *     to `deployer` alone, so a `treasury` address LOST `createAccount` in the same change that
 *     gave it a transfer.
 *
 * What has NOT changed, and what this service therefore still does not ask for: SPL Transfer,
 * Approve, SetAuthority, Burn and CloseAccount are refused under all three Solana shapes. A SOL
 * withdrawal and a SOL sweep are each one System Transfer of native lamports and nothing else.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const CHAINS: Readonly<Record<ChainId, OutboundChain>> = Object.freeze({
  ember: evmChain('ember'),
  eth: evmChain('eth'),
  /*
   * **ETHEREUM CLASSIC NEEDED NO GAS CODE, AND THAT IS A FINDING RATHER THAN AN ASSUMPTION.**
   *
   * contracts-chain says ETC "did not adopt London … there is no base fee, no `maxFeePerGas`, and
   * the effective gas price is the one that was signed", and puts it on EMBER's side of that line
   * rather than ETH's. Checked against what this adapter actually builds instead of taken on
   * trust: `evm.ts` has only ever produced `type: 0` with a `gasPrice`, for `ember` AND for `eth`,
   * because Ember's node has no type-2 decoder and Ethereum still accepts legacy transactions. One
   * shape already served both, and it is exactly the shape ETC requires — so the pre-London
   * property that would have been a blocker on a 1559-only builder costs nothing here.
   *
   * What the chain argument does buy is `assertChainId`, which holds the node to the 61/63 the
   * contract declares before anything is signed, and the 7,500-confirmation depth that `statusOf`
   * reads through `chainSpec`. Neither is restated here.
   *
   * **NO ENDPOINT IS CONFIGURED FOR IT AND NONE SHOULD BE.** The estate runs no Ethereum Classic
   * node; `SETTLEMENT_RPC_URLS` has no `etc` key in any manifest, so every call on this chain ends
   * at `NoEndpointError`, which is classified and refunded at the deadline. The adapter being
   * capable and the deployment being pointed at a node are two decisions, and only the first is
   * made here. The other half — custody holds no Ethereum Classic keys at all — is written up on
   * `CUSTODY_CHAIN` in `chains.ts`.
   */
  etc: evmChain('etc'),
  btc: bitcoinChain('btc'),
  /*
   * **LITECOIN IS THE SAME ADAPTER AND NOT THE SAME PARAMETERS**, and the argument it is given is
   * the whole of the difference. `bitcoinChain` resolves the bech32 HRP, the base58 version bytes,
   * the dust threshold, the supply cap and the confirmation DEPTH from it — 12 for Litecoin against
   * Bitcoin's 6, read from the exact-pinned `contracts-chain` rather than restated.
   *
   * There is no `unimplementedChain` entry for `ltc` and there should not be: Litecoin speaks the
   * same JSON-RPC, so unlike XRP the gap was never the protocol, only the parameters.
   */
  ltc: bitcoinChain('ltc'),
  /*
   * **DOGECOIN IS BITCOIN-FAMILY AND IS NOT `bitcoinChain('doge')`. THE ONE-WORD EDIT IS THE BUG.**
   *
   * `chains.test.ts` says of Litecoin that "a chain can be added here with a one-word edit, and the
   * one-word edit is what would have shipped Bitcoin's parameters under Litecoin's name". Dogecoin
   * is the case where the one-word edit does not even have that excuse: `family: 'bitcoin'` in
   * contracts-chain is true of its RPC and its transaction structure, and false of the only thing
   * this adapter needs.
   *
   * **Dogecoin has no segwit.** Its addresses are base58 only — P2PKH at version byte 0x1e, P2SH at
   * 0x16 — and this builder is P2WPKH from end to end:
   *
   *   * `encodePsbt` adds every input as a `witnessUtxo`. bitcoinjs-lib refuses to sign a
   *     non-witness script presented that way, so a Dogecoin PSBT built here is unsignable — which
   *     is the good half, because it fails loudly.
   *   * `vsizeOf` charges 41 base vbytes plus a 27-vbyte witness per input. A P2PKH input is ~148
   *     bytes with no witness discount, so the fee this service quoted would be under half the
   *     transaction's real size: a payment that is built, signed, broadcast and then dropped by
   *     every node below the relay floor. That one does NOT fail loudly, and it is the reason this
   *     entry exists rather than a row in `NETWORKS`.
   *
   * Custody cannot sign it either, read on 2026-08-09 rather than assumed — the mistake this file's
   * header records four times over. `CHAIN_ASSET` has no `dogecoin`, `BITCOIN_FAMILY_NETWORKS` has
   * no Dogecoin parameters, `bitcoinNetwork` throws for it by design and custody's own suite
   * asserts that it throws, and custody derives P2WPKH and nothing else. So both halves are new
   * work — a non-segwit build path here and a non-segwit derive-and-sign path there — which is
   * 29-native-assets.md's "half an integration each", not a configuration change.
   */
  doge: unimplementedChain(
    'doge',
    'phase 8 — Dogecoin, a UTXO chain with no segwit',
    'Dogecoin is bitcoin-family and this adapter is P2WPKH from end to end: it commits every input ' +
      'as a witnessUtxo, which a base58 Dogecoin input cannot be signed as, and it prices vsize ' +
      'with the witness discount, which would under-quote a Dogecoin fee by more than half and ' +
      'produce a signed payment no node relays. Custody has no Dogecoin network parameters and ' +
      'derives P2WPKH only, so the signing half does not exist either.',
  ),
  sol: solanaChain(),
  xrp: unimplementedChain(
    'xrp',
    'phase 7 — XRPL adapter',
    'custody already signs XRP with both a payment and a pinned sweep shape, so the gap is on this ' +
      'side: an XRP blob carries a Sequence and a LastLedgerSequence that must be committed beside ' +
      'the bytes for it to be adjudicable at all, and a half-built adapter that signs without ' +
      'recording them produces payments no operator can ever settle.',
  ),
})

/** The adapter for a chain. Total over `ChainId`: an unimplemented chain is an object, not a null. */
export function chainFor(chain: ChainId): OutboundChain {
  return CHAINS[chain]
}

/** Chains this deployment can actually move money on. Used by the fee route and by the sweeper. */
export function implementedChains(): readonly ChainId[] {
  return CHAIN_IDS.filter((id) => CHAINS[id].unimplementedPhase === null)
}

/* ------------------------------------------------------------------ the transport */

/**
 * No endpoint is configured for this chain.
 *
 * Its own type because the response differs from every other failure: a missing endpoint is an
 * operator's omission and it is permanent until they act, so retrying costs a round trip per tick
 * for ever and tells nobody. It is classified as a build failure that refunds at the deadline
 * rather than immediately, because "an operator has not configured this yet" is a state that
 * plausibly clears on its own within the hour.
 *
 * `message` is a constructor argument rather than something a subclass assigns afterwards, because
 * V8 snapshots the message into `err.stack` at construction: a subclass that overwrites `message`
 * leaves a stack whose first line still says this one, and the first line of a stack is what most
 * of this estate's logging prints.
 */
export class NoEndpointError extends Error {
  readonly chain: ChainId
  constructor(chain: ChainId, message?: string) {
    super(
      message ??
        `no JSON-RPC endpoint is configured for '${chain}' — add it to SETTLEMENT_RPC_URLS. ` +
          'Nothing on this chain can be built, broadcast or settled until there is one.',
    )
    this.name = 'NoEndpointError'
    this.chain = chain
  }
}

/**
 * The endpoint is configured, and its credentials cannot be read.
 *
 * **A subclass of `NoEndpointError` on purpose.** Every place that already classifies a missing
 * endpoint reaches it by `instanceof` — `jobs.ts:310` (do not retry, this will not clear on a
 * tick), `server.ts:390` (503 `no_endpoint`), `withdrawals.ts:469` (classification `endpoint`,
 * refunded at the deadline rather than immediately) — and the two faults are the same kind: an
 * operator wrote `SETTLEMENT_RPC_URLS` in a way this service cannot use, and nothing on that chain
 * moves until they write it again. Inheriting means the classification is not forgotten in three
 * files by whoever adds the fourth.
 *
 * Why it can happen at all: a Bitcoin Core `rpcpassword` may contain any byte, so a password
 * containing a literal `%` — `50%more` — is a legal password and an illegal percent-escape. `new
 * URL` preserves it verbatim (measured: `new URL('http://u:ab%zz@127.0.0.1:1').password` is
 * `'ab%zz'`) and `decodeURIComponent` then throws `URIError: URI malformed`. The alternative to
 * refusing is presenting the undecoded bytes, which is a 401 indistinguishable from the defect this
 * transport was just fixed for — and it would be one the operator has no way to see.
 *
 * The message names the chain and the variable. It never names the value: see `redactUserinfo` in
 * `env.ts` for the other half of that rule.
 */
export class EndpointCredentialsError extends NoEndpointError {
  constructor(chain: ChainId, field: 'username' | 'password') {
    super(
      chain,
      `the ${field} in the '${chain}' endpoint of SETTLEMENT_RPC_URLS is not valid ` +
        'percent-encoding. A `%` in an RPC password is a literal only when it is written `%25`; ' +
        'until it is, this service refuses rather than presenting the undecoded bytes and taking ' +
        'a 401 that looks like a wrong password.',
    )
    this.name = 'EndpointCredentialsError'
  }
}

/** A JSON-RPC fault, carrying the node's own words so a caller can match on them. */
export class RpcError extends Error {
  readonly method: string
  constructor(method: string, message: string) {
    super(message)
    this.name = 'RpcError'
    this.method = method
  }
}

export interface RpcOptions {
  /** `chain → endpoint`. From `env.rpcUrls`. */
  readonly urls: Readonly<Record<string, string>>
  readonly deadlineMs: number
  readonly fetch?: typeof globalThis.fetch
}

interface RpcEnvelope {
  readonly result?: unknown
  readonly error?: { readonly code?: unknown; readonly message?: unknown }
}

/**
 * A JSON-RPC caller per chain, over `@cloudsforge/http`.
 *
 * `HttpClient` rather than bare `fetch`, for the reason its own header gives: on undici there is no
 * total-request timeout by default, so a hung node pins the calling worker indefinitely — and a
 * worker that is hung is a worker still holding the chain lease, which stops every other payment on
 * that chain until the lease expires.
 *
 * **Retries are zero.** The default would retry a POST only when it carries an idempotency key, so
 * this is belt to a brace, but the brace matters: `eth_sendRawTransaction` is not idempotent from
 * the client's point of view — the same bytes are safe to re-send, but a retry that races the first
 * attempt's response turns "already known" into a broadcast failure and the row goes round again.
 * The recovery path re-sends deliberately, on the next tick, from committed bytes. That is the
 * retry, and it is the one that is safe.
 *
 * **The endpoint may carry a credential, and it is the only way a UTXO node can be reached.** See
 * `basicAuthorization` below for the whole of that argument and for the measurement that motivated
 * it. What it means here is that `options.urls` is a secret: nothing in this function may log,
 * throw or otherwise report a value out of it, and `index.ts` reports `Boolean(env.rpcUrls[chain])`
 * at boot for exactly that reason.
 */
export function rpcFactory(options: RpcOptions): (chain: ChainId) => JsonRpc {
  const clients = new Map<string, HttpClient>()
  let id = 0

  return (chain: ChainId): JsonRpc => {
    const url = options.urls[chain]
    if (!url) {
      return () => Promise.reject(new NoEndpointError(chain))
    }
    const parsed = new URL(url)
    /*
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * THE CACHE KEY IS THE WHOLE URL, INCLUDING THE USERINFO, AND THAT IS LOAD-BEARING NOW.
     *
     * It always read `clients.get(url)` and that was merely tidy while every client was
     * anonymous. With a credential baked into the client below it is the correctness property:
     * a deployment that runs Bitcoin Core and Litecoin Core behind one reverse proxy gives both
     * chains the SAME `parsed.origin` and different `rpcuser`s, and a cache keyed on the origin
     * would hand the second chain the first chain's `Authorization` header for the life of the
     * process. That is not a 401 — the proxy would answer, as the wrong node.
     *
     * `chain` itself would also be a sound key. `url` is kept because it is the thing the
     * client is actually derived from: two chains pointed at one identical endpoint share a
     * circuit breaker, which is right, and nothing has to remember to add a field to the key
     * the next time the client gains one.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */
    let client = clients.get(url)
    if (!client) {
      let authorization: string | undefined
      try {
        authorization = basicAuthorization(parsed, chain)
      } catch (err) {
        // A rejected promise, not a synchronous throw — the same shape as the missing-endpoint
        // branch above and for the same reason. `rpc(chain)` is called by `callFor` while a job
        // handler is assembling its dependencies, so a throw here dies outside the row it belongs
        // to: no `failure_reason`, no classification, no refund at the deadline. Rejecting instead
        // puts the fault where every other endpoint fault already lands.
        return () => Promise.reject(err)
      }
      client = new HttpClient({
        // Deliberately the origin and not `url`: the origin is what the client dials, and the
        // path is passed per request below. Everything the origin drops — the userinfo — has to
        // be carried some other way, which is what the `headers` bag two lines down is.
        baseUrl: parsed.origin,
        name: `chain:${chain}`,
        defaultDeadlineMs: options.deadlineMs,
        defaultRetries: 0,
        /*
         * The STATIC bag, not `token`. `@cloudsforge/http` merges four sources in a fixed order
         * (runtime/packages/http/src/index.ts:374-393): the accept default, this bag, then
         * `token` as a Bearer, then the caller's per-request headers. A node credential is a
         * default for every call to this node and not an instruction for one call, so this is
         * its layer — and `token` is the wrong one twice over: it emits `Bearer`, and it would
         * silently overwrite a per-call credential a future caller supplied.
         */
        ...(authorization ? { headers: { authorization } } : {}),
        ...(options.fetch ? { fetch: options.fetch } : {}),
      })
      clients.set(url, client)
    }
    const path = `${parsed.pathname}${parsed.search}`
    const http = client
    return async (method, params) => {
      id += 1
      const body = await http.post<RpcEnvelope>(path, { jsonrpc: '2.0', id, method, params })
      if (body.error) {
        // The node's own words, verbatim and un-normalised. `broadcast` matches on them to
        // recognise a re-broadcast of bytes the node already holds, and a rewritten message is a
        // recovery path that silently stops working.
        const message = typeof body.error.message === 'string' ? body.error.message : 'unknown error'
        throw new RpcError(method, message)
      }
      return body.result
    }
  }
}

/*
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * WHY THIS FUNCTION EXISTS: `URL.origin` DISCARDS THE USERINFO, AND EVERY UTXO NODE NEEDS IT.
 *
 * Bitcoin, Litecoin and Dogecoin Core authenticate their JSON-RPC with HTTP Basic and nothing
 * else. There is no anonymous mode, and there is no cookie path from this service — `.cookie` is a
 * file inside the node's datadir, which a container on the other side of a network boundary cannot
 * read. So the credential arrives the only way a `chain → endpoint` string map can carry one: in
 * the URL, as `http://rpcuser:rpcpassword@host:8332`.
 *
 * `rpcFactory` built its client with `baseUrl: parsed.origin`, and `URL.origin` is scheme + host +
 * port. The userinfo was parsed, dropped, and never sent. MEASURED on the mainnet estate, from
 * inside `cloudsforge-estate-settlement-1`, against the endpoint its own boot line already reports
 * as configured (`{"chain":"ltc","endpoint":true}`):
 *
 *     origin http://172.20.0.1:50002, userinfo present
 *     no Authorization header (what this file did)      → 401 Unauthorized
 *     Authorization: Basic base64(user:pass)            → 200, blocks=3156498,
 *                                                         initialblockdownload=false
 *
 * That was the whole of the failure. The node is up, synced and reachable; the transport could not
 * say who it was. Every Litecoin withdrawal, every sweep and every fee quote ended at that 401,
 * and BTC and DOGE would have ended at the identical one the day they were pointed at a node.
 *
 * **`decodeURIComponent`, not the raw fields.** A URL cannot carry `@`, `/`, `:`, `?` or `#` in a
 * password literally, so any password containing one is written percent-encoded, and `new URL`
 * hands the encoded form back verbatim (measured: `p%40ss%3Aword` stays `p%40ss%3Aword`). Sending
 * that is not a header bug an operator can see — it is a 401 that looks exactly like a typo in
 * `bitcoin.conf`, on a password that is correct. Core compares the decoded bytes.
 *
 * **`Buffer.from(…, 'utf8')`, not `binary`.** RFC 7617 leaves the charset to the server; Core
 * decodes base64 into a byte string and compares it to the `rpcauth`/`rpcpassword` bytes from its
 * config file, which are whatever the operator's editor wrote — UTF-8 on every platform this
 * estate deploys to. `latin1` would mangle a non-ASCII password into a different credential.
 *
 * A username with an empty password (`http://rpcuser@host:8332`) still gets a header: `user:` is a
 * legal Basic credential and refusing it here would be this function inventing a policy the node
 * does not have. Only a URL with neither is anonymous.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
function basicAuthorization(parsed: URL, chain: ChainId): string | undefined {
  if (parsed.username === '' && parsed.password === '') return undefined
  const username = decodeUserinfo(parsed.username, chain, 'username')
  const password = decodeUserinfo(parsed.password, chain, 'password')
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`
}

/** `decodeURIComponent`, with the `URIError` turned into something an operator can act on. */
function decodeUserinfo(raw: string, chain: ChainId, field: 'username' | 'password'): string {
  try {
    return decodeURIComponent(raw)
  } catch {
    // Replaced rather than wrapped. `URIError: URI malformed` names neither the chain, nor the
    // variable, nor what an operator should do — and attaching it as `cause` would only add a
    // second object for a logger to serialise on a path where the rule is that exactly one
    // message is allowed to describe this fault, and it is the one below.
    throw new EndpointCredentialsError(chain, field)
  }
}

/** Bind a chain adapter to a network and a node. The one place a `ChainCall` is constructed. */
export function callFor(rpc: (chain: ChainId) => JsonRpc, chain: ChainId, network: Network): ChainCall {
  return { network, rpc: rpc(chain) }
}
