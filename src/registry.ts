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

const CHAINS: Readonly<Record<ChainId, OutboundChain>> = Object.freeze({
  ember: evmChain('ember'),
  eth: evmChain('eth'),
  // Implemented — see `bitcoin.ts`.
  //
  // The note that used to sit here said "neither a withdrawal nor a sweep is possible until that
  // policy exists". **The withdrawal half of that was wrong**, and it kept a gate item closed that
  // was never actually blocked. custody's `purposeGate` reads:
  //
  //     if (row.purpose === 'deposit' && !SWEEPABLE_FAMILIES.has(row.family)) refuse
  //
  // — conditioned on `deposit`. `SIGNABLE_PURPOSES` is {deployer, treasury, deposit} and
  // `keys.ts` dispatches a bitcoin row to `signBitcoin` for any of them, which signs a PSBT to any
  // destination it names. So a withdrawal from a `treasury`-purpose address has been signable all
  // along. A SWEEP still is not, because a sweep spends a `deposit`-purpose address, and that
  // remains blocked in custody rather than here — `bitcoin.buildSweepPsbt` builds the pinned-output
  // PSBT that policy will want, so the remaining change is custody's alone.
  btc: bitcoinChain(),
  sol: unimplementedChain(
    'sol',
    'phase 8 — Solana transfer shape',
    'custody signs only the SPL mint-creation instruction set and explicitly refuses ' +
      'SystemProgram::Transfer, which is what moving SOL is. There is no transfer shape and ' +
      'therefore no sweep shape; admitting one without a pinned destination would hand a signing ' +
      "credential createAccount over every customer's SOL deposit key. " +
      'THE BLOCKER IS ENTIRELY CUSTODY-SIDE AND IT BLOCKS BOTH HALVES, unlike bitcoin where only ' +
      'the sweep is gated: signSolana refuses a transfer for EVERY purpose, not just deposit, so ' +
      'there is no treasury-purpose path either. Building an adapter here first would produce ' +
      'bytes custody refuses at gate 2 — after a row is committed and money is in flight — which ' +
      'is strictly worse than this refusal, which happens before anything is written.',
  ),
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
