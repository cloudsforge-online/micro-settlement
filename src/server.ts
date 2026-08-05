/**
 * The HTTP surface.
 *
 * Plain `node:http`, following the service template. The parts that matter — request ids, RED
 * metrics, the child logger, the error shape, the auth-fault mapping — are framework-independent.
 *
 * Rule 4 of docs/ecosystem/03 §2: `/livez`, `/readyz` and `/metrics` on every service, or it does
 * not pass CI.
 *
 * A bad token is 401. A verifier that could not reach the JWKS is **503**, never 401 — answering
 * 401 there signs every user in the estate out because identity is having a bad minute.
 *
 * ## The route that had to exist
 *
 * `POST /v1/outbound/:id/adjudicate`. In the estate this replaces, the equivalent action is
 * curl-only with no UI: the one decision that has to be taken carefully, under time pressure, by
 * somebody who has just been paged, is taken by hand-editing a shell command against a service with
 * no list of what is stuck. So there are three routes rather than one — the list an operator works
 * from, the row they read, and the decision — and the decision writes its evidence to
 * `outbound_adjudications` whether it is taken or refused.
 *
 * ## The route that deliberately forwards a credential
 *
 * `POST /v1/treasuries/:chain/:network/provision` is the only place in this service that uses a
 * token other than its own. Custody's mint and pin routes are administrator-only precisely so that
 * a signing credential can never influence the pin — "if that stopped being true the sweep shape
 * would become a total-loss vulnerability" — so this service must NOT be able to provision a
 * treasury with its own credential. It forwards the operator's bearer token verbatim, and custody
 * makes its own decision about it.
 */

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import {
  ForbiddenError,
  TokenError,
  bearerFrom,
  isAdmin,
  requireAdmin,
  requireScope,
  statusFor,
  type Principal,
} from '@cloudsforge/auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { chainSpec, type Network } from '@cloudsforge/contracts-chain'
import {
  AddressError,
  assetOf,
  chainForAsset,
  isChainId,
  isNetwork,
  type ChainId,
} from './chains.ts'
import { chainFor, implementedChains, NoEndpointError } from './registry.ts'
import { adjudicate, type AdjudicateDeps } from './adjudicate.ts'
import { isBooked } from './fees.ts'
import {
  callFor,
  findOutbound,
  inFlightOnChain,
  listByState,
  type OutboundDeps,
  type OutboundState,
  type OutboundTransaction,
} from './outbound.ts'
import {
  registerSweepSource,
  type SweepDeps,
} from './sweeps.ts'
import {
  NoTreasuryPinnedError,
  TreasuryDisagreementError,
  listTreasuries,
  provisionTreasury,
  type TreasuryDeps,
} from './treasury.ts'
import {
  MalformedEventError,
  handleWithdrawalRequested,
  type WithdrawalDeps,
} from './withdrawals.ts'
import {
  EVENT_ID_HEADER,
  LEGACY_EVENT_ID_HEADER,
  LEGACY_SIGNATURE_HEADER,
  SIGNATURE_HEADER,
  WALLET_WITHDRAWAL_REQUESTED,
  verifyInbound,
} from './outbox.ts'

/** The verifier as this file needs it. An interface, so a test does not need a JWKS. */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

/**
 * The scopes a service token must carry to reach this surface.
 *
 * `settlement:register` is separate from `settlement:read` because registering a deposit address
 * for sweeping is a different authority from reading a transaction: the first decides whose money
 * this service will consolidate, and only wallet has any business doing it.
 */
export const READ_SCOPE = 'settlement:read'
export const REGISTER_SCOPE = 'settlement:register'

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  readonly network: Network
  readonly outbound: OutboundDeps
  readonly adjudication: AdjudicateDeps
  readonly withdrawals: WithdrawalDeps
  readonly treasuries: TreasuryDeps
  readonly sweeps: SweepDeps
  /**
   * Verifies the HMAC wallet's relay put on the exact bytes it sent — every secret it may have
   * used, newest first.
   *
   * A LIST as well as a scalar, and the list is the point: `OUTBOX_SIGNING_SECRET` is one key
   * shared across the estate, and it can only be replaced by a rolling change if a receiver
   * accepts both the outgoing and the incoming key for the length of the cutover. `verifyInbound`
   * tries all of them on BOTH schemes. A scalar still behaves exactly as it always has;
   * `env.outboxAcceptSecrets` is what production passes.
   */
  readonly eventSigningSecret: string | readonly string[]
  readonly beforeScrape?: () => Promise<void>
}

const MAX_BODY_BYTES = 128 * 1024
const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/

/** Domain metrics, declared rather than inferred from a log line — AD-20. */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'settlement_signatures_total',
      help: 'Signatures obtained from custody, by chain and purpose. One per outbound transaction, ever.',
      kind: 'counter',
      labels: ['chain', 'purpose'],
    })
    .register({
      name: 'settlement_broadcasts_total',
      help: 'Broadcasts of committed bytes. Exceeds signatures when a re-send recovers a crash.',
      kind: 'counter',
      labels: ['chain', 'purpose'],
    })
    .register({
      name: 'settlement_confirmed_total',
      help: 'Outbound transactions that reached their asset declared confirmation depth.',
      kind: 'counter',
      labels: ['chain', 'purpose'],
    })
    .register({
      name: 'settlement_rejected_total',
      help: 'Transactions the chain applied and did not deliver. The one automatic refund path.',
      kind: 'counter',
      labels: ['chain', 'purpose'],
    })
    .register({
      name: 'settlement_stuck_total',
      help: 'Signed transactions parked for an operator. Never auto-refunded. Alert on any increase.',
      kind: 'counter',
      labels: ['chain', 'purpose'],
    })
    .register({
      name: 'settlement_build_failures_total',
      help: 'Builds that threw, by classification. A shift between classifications is a cause changing.',
      kind: 'counter',
      labels: ['chain', 'classification'],
    })
    .register({
      name: 'settlement_event_signatures_total',
      help:
        'Accepted inbound deliveries by signature scheme. `legacy` reaching zero is the signal ' +
        'that the pre-contract arm in `verifyInbound` can be deleted — see its header.',
      kind: 'counter',
      labels: ['scheme'],
    })
    .register({
      name: 'settlement_adjudications_total',
      help: 'Operator decisions about stuck transactions, including refusals and the reason.',
      kind: 'counter',
      labels: ['action', 'outcome'],
    })
    .register({
      name: 'settlement_sweeps_planned_total',
      help: 'Sweeps opened, by chain.',
      kind: 'counter',
      labels: ['chain'],
    })
    .register({
      name: 'settlement_token_sweeps_planned_total',
      help:
        'ERC-20 sweep PAIRS opened, by chain. One increment is two outbound rows — a gas top-up ' +
        'and the token sweep that depends on it — so this is deliberately not folded into ' +
        'settlement_sweeps_planned_total, which counts one row each.',
      kind: 'counter',
      labels: ['chain'],
    })
    .register({
      name: 'settlement_sweeps_blocked_total',
      help: 'Sweep passes refused for want of a pinned treasury, an agreeing pin, or a node.',
      kind: 'counter',
      labels: ['chain'],
    })
    .register({
      name: 'settlement_fees_unbooked',
      help: 'Confirmed transactions whose network fee has not reached the ledger yet.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'settlement_events_total',
      help: 'Inbound events, by topic and outcome.',
      kind: 'counter',
      labels: ['topic', 'outcome'],
    })
}

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
}

interface Route {
  readonly method: string
  /** `:name` segments become `ctx.params.name`. */
  readonly path: string
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

class NotFoundError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'NotFoundError'
    this.code = code
  }
}

class ConflictError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'ConflictError'
    this.code = code
  }
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()
    // Echoed before anything can fail, so even a 500 carries the id the user will quote.
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const matched = matchRoute(routes, req.method ?? 'GET', url.pathname)
    // Unmatched paths collapse to one label. Using the raw path would let any caller mint unbounded
    // time series and take the scrape target down with cardinality.
    const routeLabel = matched ? matched.route.path : 'unmatched'
    const log = deps.logger.child({ requestId, method: req.method ?? 'GET', route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method: req.method ?? 'GET',
        route: routeLabel,
        status: String(status),
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, {
        method: req.method ?? 'GET',
        route: routeLabel,
      })
    }

    void handle(matched, { req, url, requestId, log, params: matched?.params ?? {} }, deps)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status)
      })
      .catch((err: unknown) => {
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500)
      })
  })
}

function matchRoute(
  routes: readonly Route[],
  method: string,
  pathname: string,
): { route: Route; params: Record<string, string> } | undefined {
  const parts = pathname.split('/').filter((p) => p.length > 0)
  for (const route of routes) {
    if (route.method !== method) continue
    const pattern = route.path.split('/').filter((p) => p.length > 0)
    if (pattern.length !== parts.length) continue
    const params: Record<string, string> = {}
    let ok = true
    for (const [i, segment] of pattern.entries()) {
      const actual = parts[i]!
      if (segment.startsWith(':')) params[segment.slice(1)] = decodeURIComponent(actual)
      else if (segment !== actual) {
        ok = false
        break
      }
    }
    if (ok) return { route, params }
  }
  return undefined
}

async function handle(
  matched: { route: Route; params: Record<string, string> } | undefined,
  ctx: RequestContext,
  deps: ServerDeps,
): Promise<Reply> {
  if (!matched) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    return await matched.route.handle(ctx, deps)
  } catch (err) {
    // `statusFor` is the one place that decides what an auth failure means, so services cannot
    // disagree about it again.
    const authStatus = statusFor(err)
    if (authStatus === 401) {
      // The reason is logged, never returned — "signature verification failed" versus "expired"
      // tells an attacker which half of a forged token to fix.
      ctx.log.info('unauthenticated request', { err })
      return errorReply(401, 'unauthenticated', 'a valid bearer token is required', ctx.requestId)
    }
    if (authStatus === 403) {
      const required = err instanceof ForbiddenError ? err.required : 'unknown'
      ctx.log.info('forbidden request', { required })
      return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
    }
    if (authStatus === 503) {
      ctx.log.error('token verifier unavailable', { err })
      return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    if (err instanceof BadRequestError || err instanceof MalformedEventError || err instanceof AddressError) {
      return errorReply(400, 'bad_request', err.message, ctx.requestId)
    }
    if (err instanceof NotFoundError) return errorReply(404, err.code, err.message, ctx.requestId)
    if (err instanceof ConflictError) return errorReply(409, err.code, err.message, ctx.requestId)
    if (err instanceof NoTreasuryPinnedError) {
      return errorReply(409, 'no_treasury_pinned', err.message, ctx.requestId)
    }
    if (err instanceof TreasuryDisagreementError) {
      return errorReply(409, 'treasury_disagreement', err.message, ctx.requestId)
    }
    if (err instanceof NoEndpointError) {
      return errorReply(503, 'no_endpoint', err.message, ctx.requestId)
    }
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

/* ------------------------------------------------------------------ projection */

/** What a transaction looks like on the wire. **Never `raw_tx`.** */
export function toOutboundView(row: OutboundTransaction): Record<string, unknown> {
  return {
    id: row.id,
    purpose: row.purpose,
    chain: row.chain,
    network: row.network,
    state: row.state,
    from: row.fromAddress,
    to: row.toAddress,
    assetCode: row.assetCode,
    amount: row.amount.toString(),
    fee: row.fee.toString(),
    txHash: row.txHash,
    confirmations: row.confirmations,
    requiredConfirmations: chainSpec(assetOf(row.chain)).confirmations,
    // The nonce is published and the BYTES are not. An operator adjudicating a stuck transaction
    // needs to know which nonce it holds — that is the number the whole death proof turns on — and
    // publishing the signed transaction itself would put a submittable payment in a response body,
    // which is the mistake custody's admin audit route carries a paragraph about avoiding.
    signedNonce: row.signedNonce,
    signedExpiry: row.signedExpiry,
    hasCommittedBytes: row.rawTx !== null,
    custodyAuditId: row.custodyAuditId,
    feeBooked: isBooked(row),
    signedAt: row.signedAt?.toISOString() ?? null,
    broadcastAt: row.broadcastAt?.toISOString() ?? null,
    confirmedAt: row.confirmedAt?.toISOString() ?? null,
    maturedAt: row.maturedAt?.toISOString() ?? null,
    failureReason: row.failureReason,
    withdrawalId: row.purpose === 'withdrawal' ? row.sourceRef : null,
    sourceRef: row.sourceRef,
    userId: row.userId,
    idempotencyKey: row.idempotencyKey,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  }
}

/* ------------------------------------------------------------------ routes */

function buildRoutes(): Route[] {
  return [
    {
      method: 'GET',
      path: '/livez',
      // Static, deliberately. A liveness probe that consults a dependency restarts a healthy
      // process every time the database blinks. Readiness is where dependencies belong.
      handle: async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() }),
    },
    {
      method: 'GET',
      path: '/readyz',
      handle: async (_ctx, deps) => {
        const report = await deps.lifecycle.readyz()
        return { status: report.ready ? 200 : 503, body: report }
      },
    },
    {
      method: 'GET',
      path: '/metrics',
      handle: async (ctx, deps) => {
        try {
          await deps.beforeScrape?.()
        } catch (err) {
          // A gauge that could not be sampled is a stale gauge. Failing the scrape instead would
          // lose every other metric too, and blind the dashboard at the moment it is needed.
          ctx.log.warn('gauge refresh failed; serving the previous values', { err })
        }
        return {
          status: 200,
          text: deps.metrics.render(),
          contentType: 'text/plain; version=0.0.4; charset=utf-8',
        }
      },
    },

    /* ---------------------------------------------------------------- fees */
    {
      method: 'GET',
      path: '/v1/fees/:chain/:network/:assetCode',
      /*
       * The fee wallet quotes to a user, live from the node.
       *
       * The shape is wallet's `httpFeeQuoter`, written in `wallet/src/settlement.ts` before this
       * repository existed: `{ fee }` as a decimal string of smallest units. That interface is the
       * contract and it is not renamed. Wallet then LOCKS the number onto the withdrawal, and this
       * service refuses to build for a fee outside its own bounds — so the two ends of the same
       * bound are `env.maxFeeWei` here and a refusal there, and a quote that would not be buildable
       * is refused at quote time rather than at signing time.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, READ_SCOPE)
        const chain = chainParam(ctx)
        const network = networkParam(ctx)
        const assetCode = ctx.params.assetCode!
        if (chainForAsset(assetCode) !== chain) {
          throw new BadRequestError(`${assetCode} does not settle on ${chain}`)
        }
        const adapter = chainFor(chain)
        if (adapter.unimplementedPhase) {
          return errorReply(
            501,
            'chain_unsupported',
            `${chain} outbound transactions are not implemented yet (${adapter.unimplementedPhase})`,
            ctx.requestId,
          )
        }
        const done = deps.lifecycle.track()
        try {
          const fee = await adapter.estimateFee(callFor(deps.outbound, chain), deps.outbound.bounds)
          return {
            status: 200,
            body: {
              chain,
              network,
              assetCode,
              // A decimal STRING. A JSON number is an IEEE 754 double and an 18-decimal fee does
              // not survive one — it does not fail either, it comes back subtly wrong.
              fee: fee.toString(),
            },
          }
        } finally {
          done()
        }
      },
    },

    /* ---------------------------------------------------------------- events */
    { method: 'POST', path: '/v1/events', handle: handleEvent },

    /* ---------------------------------------------------------------- outbound reads */
    {
      method: 'GET',
      path: '/v1/outbound',
      /*
       * The list an operator works from.
       *
       * Defaults to `stuck`, because that is the only state anybody opens this route for at three
       * in the morning, and because a default of "everything" on a table that grows for ever is a
       * route whose first use is a timeout.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, READ_SCOPE)
        else requireAdmin(principal)
        const state = (ctx.url.searchParams.get('state') ?? 'stuck') as OutboundState
        if (!STATES.has(state)) throw new BadRequestError(`state must be one of ${[...STATES].join(', ')}`)
        const limit = limitFrom(ctx)
        const done = deps.lifecycle.track()
        try {
          const rows = await listByState(deps.outbound.sql, state, limit)
          return { status: 200, body: { state, transactions: rows.map(toOutboundView) } }
        } finally {
          done()
        }
      },
    },
    {
      method: 'GET',
      path: '/v1/outbound/:id',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, READ_SCOPE)
        else if (!isAdmin(principal)) throw new ForbiddenError('admin')
        const row = await findOutbound(deps.outbound.sql, ctx.params.id!)
        if (!row) throw new NotFoundError('not_found', 'no such outbound transaction')
        return { status: 200, body: { transaction: toOutboundView(row) } }
      },
    },
    {
      method: 'GET',
      path: '/v1/chains/:chain/:network/in-flight',
      /*
       * What currently holds this chain's nonce, if anything.
       *
       * The operator-facing view of the invariant. It answers exactly one row or none, by
       * construction — `outbound_in_flight_uniq` makes two impossible — so a caller seeing two here
       * is seeing a schema that was never migrated.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, READ_SCOPE)
        else if (!isAdmin(principal)) throw new ForbiddenError('admin')
        const chain = chainParam(ctx)
        const network = networkParam(ctx)
        const row = await inFlightOnChain(deps.outbound.sql, chain, network)
        return {
          status: 200,
          body: { chain, network, inFlight: row ? toOutboundView(row) : null },
        }
      },
    },

    /* ---------------------------------------------------------------- adjudication */
    {
      method: 'POST',
      path: '/v1/outbound/:id/adjudicate',
      /*
       * THE ONE OPERATOR ACTION THAT CAN CREDIT A USER'S BALANCE BACK while a valid signature for
       * the same money is sitting in `raw_tx`. `adjudicate.ts` is the whole of the reasoning; this
       * is the door.
       *
       * Administrator only, and there is deliberately no service path: a settlement decision taken
       * by a machine on a schedule is the thing `stuck` exists to prevent. The decision is
       * attributed to the operator who made it and stored with the evidence it rested on.
       *
       * A REFUSAL IS A 409, NOT A 400. The request was well-formed and the operator was entitled to
       * make it; the CHAIN said no. A 400 would read as "you typed it wrong" and send an operator
       * looking for a mistake they did not make.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const body = await readJson(ctx.req)
        const action = body['action']
        if (action !== 'refund' && action !== 'confirm') {
          throw new BadRequestError("action must be 'refund' or 'confirm'")
        }
        const done = deps.lifecycle.track()
        try {
          const outcome = await adjudicate(deps.adjudication, {
            id: ctx.params.id!,
            action,
            actor: principal.kind === 'user' ? `operator:${principal.userId}` : `service:${principal.service}`,
            correlationId: ctx.requestId,
          })
          if (outcome.kind === 'not_found') {
            throw new NotFoundError('not_found', 'no such outbound transaction')
          }
          if (outcome.kind === 'not_stuck') {
            throw new ConflictError(
              'not_stuck',
              `this transaction is '${outcome.state}', and only a stuck transaction is adjudicated. ` +
                'A live one is still being driven by the chain worker and will settle itself.',
            )
          }
          if (outcome.kind === 'refused') {
            return {
              status: 409,
              body: {
                error: {
                  code: outcome.code,
                  message: outcome.reason,
                  requestId: ctx.requestId,
                },
                // Repeated outside the error envelope so a UI can render it as the explanation it
                // is rather than as a failure. This is the sentence an operator acts on.
                refusal: { code: outcome.code, reason: outcome.reason },
              },
            }
          }
          return {
            status: 200,
            body: {
              action: outcome.action,
              proof: outcome.proof,
              transaction: toOutboundView(outcome.row),
            },
          }
        } finally {
          done()
        }
      },
    },

    /* ---------------------------------------------------------------- treasuries */
    {
      method: 'GET',
      path: '/v1/treasuries',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, READ_SCOPE)
        else if (!isAdmin(principal)) throw new ForbiddenError('admin')
        const rows = await listTreasuries(deps.treasuries.sql)
        return {
          status: 200,
          body: {
            treasuries: rows.map((t) => ({
              chain: t.chain,
              network: t.network,
              address: t.address,
              custodyChain: t.custodyChain,
              custodyUserId: t.custodyUserId,
              custodyOrderId: t.custodyOrderId,
              pinnedAt: t.pinnedAt?.toISOString() ?? null,
            })),
          },
        }
      },
    },
    {
      method: 'POST',
      path: '/v1/treasuries/:chain/:network/provision',
      /*
       * Mint through custody, pin through custody, record the row. **With the OPERATOR's token.**
       *
       * This service's own credential is deliberately not used and would be refused: custody's mint
       * and pin routes are administrator-only so that a signing credential can never influence the
       * pin. Forwarding the operator's token means custody makes its own decision about who is
       * asking, which is the property that keeps the sweep shape a containment rather than a
       * redirect.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const operatorToken = bearerFrom(headerOf(ctx.req, 'authorization'))
        if (!operatorToken) throw new TokenError('no bearer token presented', 'missing')
        const chain = chainParam(ctx)
        const network = networkParam(ctx)
        const body = await readJson(ctx.req)
        const done = deps.lifecycle.track()
        try {
          const result = await provisionTreasury(deps.treasuries, {
            chain,
            network,
            operatorToken,
            // Rotation is opt-in and loud. Without it, a call against a chain that already has a
            // treasury would pin a freshly minted, EMPTY address while withdrawals still needed the
            // old one's balance — deposits consolidate into one pot and payouts starve out of
            // another, with no error anywhere.
            allowRotation: body['allowRotation'] === true,
          })
          ctx.log.warn('treasury provisioned', {
            audit: 'treasury_provisioned',
            chain,
            network,
            address: result.treasury.address,
            minted: result.minted,
            rotatedFrom: result.rotatedFrom,
          })
          return {
            status: 200,
            body: {
              chain,
              network,
              address: result.treasury.address,
              minted: result.minted,
              rotatedFrom: result.rotatedFrom,
              ...(result.rotatedFrom
                ? {
                    warning:
                      'this rotation does NOT move the old balance. Nothing sweeps to the old ' +
                      'address any more and withdrawals are now paid from the new one, so the ' +
                      'old balance must be moved by hand before this chain can pay anything.',
                  }
                : {}),
            },
          }
        } finally {
          done()
        }
      },
    },

    /* ---------------------------------------------------------------- sweep sources */
    {
      method: 'POST',
      path: '/v1/sweep-sources',
      /*
       * wallet registering a deposit address this service may consolidate.
       *
       * The custody binding travels in the body because there is NOTHING here to derive it from:
       * `userId` and `orderId` are whatever wallet used when it had custody mint the address, and
       * custody compares both character for character with a 403 that will not say which one was
       * wrong. A guessed binding is a sweep refused every tick for ever.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, REGISTER_SCOPE)
        else requireAdmin(principal)
        const body = await readJson(ctx.req)
        const chain = stringField(body, 'chain')
        if (!isChainId(chain)) throw new BadRequestError(`chain '${chain}' is not one this service settles`)
        const network = stringField(body, 'network')
        if (!isNetwork(network)) throw new BadRequestError('network must be mainnet or testnet')
        if (network !== deps.network) {
          // Refused rather than stored. A deposit address on the other network is one this
          // deployment must never sweep — the frozen sweeper's comment is exact: without that rule
          // a float target is enough to drain every address left over from testnet.
          throw new ConflictError(
            'other_network',
            `this deployment settles ${deps.network}; a ${network} address would never be swept ` +
              'and storing it would only make it look as though it might be',
          )
        }
        const done = deps.lifecycle.track()
        try {
          const source = await registerSweepSource(deps.sweeps.sql, {
            chain,
            network,
            address: stringField(body, 'address'),
            custodyChain: stringField(body, 'custodyChain'),
            custodyFamily: stringField(body, 'custodyFamily'),
            custodyUserId: stringField(body, 'custodyUserId'),
            custodyOrderId: stringField(body, 'custodyOrderId'),
          })
          return {
            status: 201,
            body: {
              sweepSource: {
                id: source.id,
                chain: source.chain,
                network: source.network,
                address: source.address,
                swept: source.swept.toString(),
              },
            },
          }
        } finally {
          done()
        }
      },
    },
  ]
}

const STATES = new Set<string>([
  'planned',
  'building',
  'signed',
  'broadcast',
  'confirmed',
  'stuck',
  'failed',
])

/* ------------------------------------------------------------------ events */

/**
 * The event intake.
 *
 * Authenticated by the HMAC the producing service's relay put on the exact bytes it sent, and
 * **verified before the body is parsed**. That ordering is the point: an unauthenticated body never
 * reaches a JSON parser, let alone the path that plans a payment.
 *
 * A topic this service does not subscribe to is a 202 rather than a 404. The relay treats any
 * non-2xx as a delivery failure and retries it for ever, so answering 404 to an event we do not
 * want would pin a subscriber in a permanent retry loop over something neither side is wrong about.
 *
 * A MALFORMED event is a 400 and the relay WILL retry it for ever, which is correct: a payment
 * request this service cannot read is a user whose money is reserved and whose withdrawal is not
 * being built, and it must stay visible rather than being absorbed into a 202.
 */
async function handleEvent(ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  const raw = await readRaw(ctx.req)
  // Both header names are read, and `verifyInbound` says which scheme matched. The contract's is
  // preferred; the legacy one exists because `micro-wallet`'s relay has not adopted `signDelivery`
  // yet, and dropping it would 401 every withdrawal request this service's only producer sends.
  // See `verifyInbound` for why that arm is not a weakening and for what deletes it.
  const scheme = verifyInbound(raw, deps.eventSigningSecret, {
    contract: headerOf(ctx.req, SIGNATURE_HEADER) ?? '',
    legacy: headerOf(ctx.req, LEGACY_SIGNATURE_HEADER) ?? '',
  })
  const presentedEventId =
    headerOf(ctx.req, EVENT_ID_HEADER) ?? headerOf(ctx.req, LEGACY_EVENT_ID_HEADER) ?? null
  if (scheme === null) {
    ctx.log.warn('event rejected: bad signature', { eventId: presentedEventId })
    return errorReply(401, 'bad_signature', 'the event signature did not verify', ctx.requestId)
  }
  // Counted, not just logged, so an operator can watch the legacy count reach zero before anybody
  // deletes the arm that serves it. A migration retired on a belief is a migration retired early.
  deps.metrics.increment('settlement_event_signatures_total', { scheme })

  let envelope: { id?: unknown; topic?: unknown; payload?: unknown }
  try {
    envelope = JSON.parse(raw) as typeof envelope
  } catch {
    return errorReply(400, 'bad_body', 'the event body is not valid JSON', ctx.requestId)
  }
  const eventId = typeof envelope.id === 'string' ? envelope.id : null
  const topic = typeof envelope.topic === 'string' ? envelope.topic : null
  if (!eventId || !topic) {
    return errorReply(400, 'bad_envelope', 'an event needs an id and a topic', ctx.requestId)
  }
  const payload = (envelope.payload ?? {}) as Record<string, unknown>

  const done = deps.lifecycle.track()
  try {
    if (topic === WALLET_WITHDRAWAL_REQUESTED) {
      const decision = await handleWithdrawalRequested(deps.withdrawals, {
        eventId,
        payload,
        correlationId: ctx.requestId,
      })
      deps.metrics.increment('settlement_events_total', { topic, outcome: decision.kind })
      ctx.log.info('withdrawal request handled', { eventId, decision })
      return { status: 200, body: { handled: true, decision } }
    }
    deps.metrics.increment('settlement_events_total', { topic, outcome: 'unsubscribed' })
    return { status: 202, body: { handled: false, reason: 'not a topic this service consumes' } }
  } finally {
    done()
  }
}

/* ------------------------------------------------------------------ helpers */

async function authenticate(ctx: RequestContext, deps: ServerDeps): Promise<Principal> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  // A missing token is a token fault, so it takes the same 401 path as a bad one rather than being
  // a separate branch that can drift away from it.
  if (!token) throw new TokenError('no bearer token presented', 'missing')
  return deps.verifier.principal(token)
}

function chainParam(ctx: RequestContext): ChainId {
  const chain = ctx.params.chain!
  if (!isChainId(chain)) throw new BadRequestError(`chain '${chain}' is not one this service settles`)
  return chain
}

function networkParam(ctx: RequestContext): Network {
  const network = ctx.params.network!
  if (!isNetwork(network)) throw new BadRequestError('network must be mainnet or testnet')
  return network
}

function limitFrom(ctx: RequestContext): number {
  const raw = ctx.url.searchParams.get('limit')
  if (!raw) return 50
  const value = Number(raw)
  if (!Number.isInteger(value) || value < 1 || value > 200) {
    throw new BadRequestError('limit must be a whole number between 1 and 200')
  }
  return value
}

function stringField(body: Record<string, unknown>, name: string): string {
  const value = body[name]
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > 512) {
    throw new BadRequestError(`${name} must be a non-empty string`)
  }
  return value.trim()
}

async function readRaw(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    // Capped before buffering, not after: an unbounded body is a memory-exhaustion primitive that
    // any unauthenticated caller can reach, and this route is reached before authentication.
    if (size > MAX_BODY_BYTES) throw new BadRequestError('request body too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const raw = await readRaw(req)
  if (raw.length === 0) return {}
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new BadRequestError('request body must be a JSON object')
    }
    return parsed as Record<string, unknown>
  } catch (err) {
    if (err instanceof BadRequestError) throw err
    throw new BadRequestError('request body is not valid JSON')
  }
}

/**
 * The error shape, identical on every failure and always carrying the request id.
 *
 * The id in the body rather than only in the header is what makes a support conversation work: it
 * joins to the log line, the trace and the operator's own record of the incident.
 */
function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  if (res.writableEnded) return
  const payload = reply.text ?? `${JSON.stringify(reply.body ?? {})}\n`
  res.writeHead(reply.status, {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    // Health, metrics and the state of a payment are all point-in-time facts. A cached 200 from a
    // replica that has since gone unready is exactly the lie this arrangement exists to stop.
    'cache-control': 'no-store',
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}

/** Chains this build can actually settle. Exported so the boot log can state them. */
export { implementedChains }
