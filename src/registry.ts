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
 *     (custody/src/signing.ts:379) has three disjoint shapes and `transfer` and `sweep` are each
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
  btc: bitcoinChain(),
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
 */
export class NoEndpointError extends Error {
  readonly chain: ChainId
  constructor(chain: ChainId) {
    super(
      `no JSON-RPC endpoint is configured for '${chain}' — add it to SETTLEMENT_RPC_URLS. Nothing ` +
        'on this chain can be built, broadcast or settled until there is one.',
    )
    this.name = 'NoEndpointError'
    this.chain = chain
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
    let client = clients.get(url)
    if (!client) {
      client = new HttpClient({
        baseUrl: parsed.origin,
        name: `chain:${chain}`,
        defaultDeadlineMs: options.deadlineMs,
        defaultRetries: 0,
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

/** Bind a chain adapter to a network and a node. The one place a `ChainCall` is constructed. */
export function callFor(rpc: (chain: ChainId) => JsonRpc, chain: ChainId, network: Network): ChainCall {
  return { network, rpc: rpc(chain) }
}
