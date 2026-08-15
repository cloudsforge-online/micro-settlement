/**
 * `mint.deploy.funding_requested` — the platform paying for its own deploy.
 *
 * ## Why this event exists at all
 *
 * A paid Forge Create order derives a fresh per-order deployer address and signs the contract
 * creation from it. That address holds zero coin, and mint cannot fix that: it holds
 * `custody:sign:deployer` and nothing else, so it can spend FROM the deployer and has no authority
 * to send TO it. The treasury signer is here. So mint measured the shortfall, wrote
 * `awaiting_funds`, and looped — for every paid order on both networks, with the customer's money
 * already taken and no human watching the row.
 *
 * The handover is one event because 03 §2 rule 5 says so: a state change others care about is an
 * outbox row in the same transaction, not an HTTP call. It also means the request survives this
 * service being down, which a call would not.
 *
 * ## What this is NOT
 *
 * It is not a withdrawal and it must never be mistaken for one. Nobody's balance moved, no
 * reservation is held, and there is no user to refund — `handleWithdrawalRequested`'s entire
 * apparatus of `refundable`, reservations and terminal events is absent here on purpose. What
 * lands is a `gas_topup`, the purpose `planTokenSweep` already uses to fund a deposit address
 * before sweeping it, and `worker.ts` deliberately emits NOTHING when one confirms. The
 * confirmation unblocks a deploy mint is already retrying; it is a database fact, not news.
 *
 * `signingPolicy('gas_topup')` claims custody's `treasury` purpose with the `payment` shape — the
 * one the treasury already has. SDR-05 accepts that a treasury transfer may pay any address, so
 * aiming one at a deployer address adds no capability a holder of `custody:sign:treasury` did not
 * already have. No new scope, no new shape, no new signing surface.
 *
 * ## Every refusal is ACCEPTED
 *
 * A refusal here returns a decision, never a throw. wallet's relay opens a circuit breaker per
 * subscriber, and one unfundable order 500-ing on every redelivery would hold open the channel
 * carrying every event to this service — the head-of-line failure `refuseUnpayable` in
 * `withdrawals.ts` documents at length, on the money path, caused by exactly this shape of mistake.
 * The only things that throw are faults that a retry can genuinely fix: an RPC that did not answer,
 * custody being unreachable, the database.
 */

import type { Network } from '@cloudsforge/contracts-chain'
import { NotImplementedError, assetOf, isChainId, isNetwork, type ChainId } from './chains.ts'
import { chainFor } from './registry.ts'
import { NoTreasuryPinnedError, requireTreasury } from './treasury.ts'
import { callFor, planOutbound, type OutboundDeps } from './outbound.ts'
import { withInbox, type Db, type Tx } from './outbox.ts'
import { MalformedEventError } from './withdrawals.ts'

/** mint's name for it, spelled once. Registered in `@cloudsforge/contracts-events` 1.2.0. */
export const MINT_DEPLOY_FUNDING_REQUESTED = 'mint.deploy.funding_requested'

/**
 * The payload as mint declares it (`mint/src/tokens.ts`, `fundingRequestedPayload`).
 *
 * Copied rather than imported, for the same reason `WithdrawalRequestedPayload` is: it is a WIRE
 * contract, and importing it would couple this build to mint's source tree.
 *
 * There is deliberately no `userId` on it. A customer bought a token; the platform topping up its
 * own deployer out of its own treasury is not a fact about that customer.
 */
export interface DeployFundingRequestedPayload {
  readonly tokenId: string
  readonly chain: string
  readonly network: string
  readonly deployerAddress: string
  /** What the creation costs, measured against the node. Smallest units, decimal string. */
  readonly requiredWei: string
  /** What the deployer holds. Zero on the first ask of every paid deploy. */
  readonly balanceWei: string
  /** What mint is ASKING for: the requirement plus headroom, less the balance. Not the shortfall. */
  readonly amountWei: string
  /** 1 for the first ask. Part of the idempotency key, so a second ask is a second transfer. */
  readonly attempt: number
}

export interface ParsedDeployFunding {
  readonly tokenId: string
  readonly chain: ChainId
  readonly network: Network
  readonly deployerAddress: string
  readonly requiredWei: bigint
  readonly balanceWei: bigint
  readonly amount: bigint
  readonly attempt: number
}

/**
 * Read the payload into the values this service acts on, refusing anything it cannot account for.
 *
 * Pure and strict, exactly like `parseWithdrawalRequested`: a malformed event is a permanent fault,
 * and coercing past one would build a transfer out of a number that was guessed at. The amount in
 * particular is a decimal STRING and never a JSON number — a wei quantity above 2^53 is silently
 * rounded by a round trip, and the rounding is invisible in both directions.
 */
export function parseDeployFundingRequested(
  payload: Record<string, unknown>,
): ParsedDeployFunding {
  const text = (field: string): string => {
    const value = payload[field]
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new MalformedEventError(`${field} must be a non-empty string`)
    }
    return value.trim()
  }
  const units = (field: string): bigint => {
    const value = payload[field]
    if (typeof value !== 'string' || !/^\d+$/.test(value)) {
      throw new MalformedEventError(`${field} must be a decimal string of smallest units`)
    }
    return BigInt(value)
  }

  const chain = text('chain')
  if (!isChainId(chain)) throw new MalformedEventError(`chain '${chain}' is not one this service settles`)
  const network = text('network')
  if (!isNetwork(network)) throw new MalformedEventError('network must be mainnet or testnet')

  const attempt = payload['attempt']
  // A number here, not a string, and it must be a positive integer: it is half of the idempotency
  // key. An attempt this service could not read would collapse every ask for one token onto one
  // key, so the second ask would silently return the first transfer as a duplicate and the order
  // would wait for money that had already been spent on a smaller shortfall.
  if (typeof attempt !== 'number' || !Number.isInteger(attempt) || attempt < 1) {
    throw new MalformedEventError('attempt must be a positive integer')
  }

  return {
    tokenId: text('tokenId'),
    chain,
    network,
    deployerAddress: text('deployerAddress'),
    requiredWei: units('requiredWei'),
    balanceWei: units('balanceWei'),
    amount: units('amountWei'),
    attempt,
  }
}

export type DeployFundingDecision =
  /** A `gas_topup` is on the queue. The worker signs and broadcasts it on its own schedule. */
  | { readonly kind: 'planned'; readonly outboundId: string; readonly amount: string }
  | { readonly kind: 'duplicate'; readonly outboundId: string | null }
  /** Not this deployment's business. No row, no log line worth waking anyone for. */
  | { readonly kind: 'ignored'; readonly reason: string }
  /**
   * Accepted and NOT funded, permanently, for a reason a retry cannot change. There is no event
   * back to mint: mint's own `funding_requests` counter and cooldown already bound how often it
   * asks, and a `.refused` topic would be a second, slower copy of a bound that already exists.
   * The operator surface is `settlement_events_total{topic,outcome}` and this line in the log.
   */
  | { readonly kind: 'refused'; readonly reason: string }

export interface DeployFundingDeps extends OutboundDeps {
  /**
   * The most this service will send to one deployer address in one transfer.
   *
   * A ceiling on a number that arrives over the wire and is spent verbatim. mint computes it from a
   * gas estimate against the same node, so on a healthy chain it is a fraction of a coin — but the
   * estimate is an RPC answer, and a node quoting a nonsense gas price would otherwise move an
   * arbitrary amount of treasury out on mint's say-so.
   *
   * **Over it, the transfer is REFUSED, never truncated.** A truncated top-up buys nothing: the
   * deploy still cannot pay, mint asks again, and the treasury has spent a fee to move money into
   * an address that now needs sweeping. A refusal is legible and costs nothing.
   */
  readonly topUpMaxWei: bigint
  /**
   * How many top-ups one token may ever receive, counted over rows this service wrote.
   *
   * mint bounds its ASKING; this bounds the SPENDING, and the two are deliberately not the same
   * number in the same process. mint's counter lives in mint's database and is reset by anything
   * that rewrites the row; this one is the count of transfers actually planned. A bug on either
   * side of the wire is then bounded by the other.
   */
  readonly topUpMaxPerToken: number
}

/**
 * Take one `mint.deploy.funding_requested` and plan the transfer that answers it.
 *
 * `withInbox` on `(topic, eventId)` stops a REDELIVERY; the unique constraint on
 * `idempotency_key` stops two different events naming the same ask. Both are needed and they catch
 * different things — the same pairing `handleWithdrawalRequested` documents.
 *
 * It plans and does not build. Building claims the chain's nonce under a lease held by a worker,
 * never on the HTTP thread of an event delivery: a build here would let the relay's retry policy
 * decide how many transactions got signed.
 */
export async function handleDeployFundingRequested(
  deps: DeployFundingDeps,
  input: {
    readonly eventId: string
    readonly payload: Record<string, unknown>
    readonly correlationId: string
  },
): Promise<DeployFundingDecision> {
  const request = parseDeployFundingRequested(input.payload)

  if (request.network !== deps.network) {
    // A testnet order reaching the mainnet deployment. Ignored, not refused: the row it names is in
    // a database this process cannot see, and the other deployment is the one that will fund it.
    return { kind: 'ignored', reason: 'other_network' }
  }

  if (request.amount <= 0n) {
    // mint only asks when `fundingAmount` came out positive, so this is a mint that has changed its
    // mind about arithmetic or an event that was not written by mint. Either way there is nothing
    // to send, and sending nothing is a transaction that costs a fee to deliver zero.
    return { kind: 'refused', reason: 'amount_not_positive' }
  }
  if (request.amount > deps.topUpMaxWei) {
    return { kind: 'refused', reason: 'amount_over_cap' }
  }

  const adapter = chainFor(request.chain)
  if (adapter.unimplementedPhase) {
    // A chain this service cannot move a coin on. Permanent until code ships, so redelivering it
    // forever would pin the relay against a fact no retry changes.
    return { kind: 'refused', reason: `no_adapter:${request.chain}` }
  }

  // Counted BEFORE the fee estimate, so a token that has exhausted its allowance costs no RPC.
  const already = await topUpsFor(deps.sql, request.tokenId, request.chain, request.network)
  if (already >= deps.topUpMaxPerToken) {
    return { kind: 'refused', reason: 'topup_limit_reached' }
  }

  let treasury: string
  try {
    treasury = (await requireTreasury(deps, request.chain, request.network)).address
  } catch (err) {
    if (err instanceof NoTreasuryPinnedError) {
      // Nobody has ever provisioned this chain. Permanent until an operator runs
      // `POST /v1/treasuries/:chain/:network/provision`, and accepted for the circuit-breaker
      // reason in this file's header. mint keeps the order at `awaiting_funds`, which is where it
      // would be anyway, and asks again after its cooldown.
      return { kind: 'refused', reason: 'no_treasury' }
    }
    // CustodyUnavailableError, CustodySignRefusedError, a disagreement — all transient or all
    // requiring a human, and all worth a redelivery. They throw.
    throw err
  }

  // What the TOP-UP ITSELF costs to send, on top of what it delivers. Not mint's number: mint
  // estimated a contract creation from the deployer, and this is a plain value transfer from the
  // treasury. An RPC failure here throws and the relay retries, which is correct — the alternative
  // is planning a transfer with a fee this service invented.
  let fee: bigint
  try {
    fee = await adapter.estimateFee(callFor(deps, request.chain), deps.bounds)
  } catch (err) {
    if (err instanceof NotImplementedError) {
      // The adapter answered "this chain has no fee model", which `unimplementedPhase` above did
      // not catch. Permanent, so accepted rather than retried for ever.
      return { kind: 'refused', reason: `no_fee_model:${request.chain}` }
    }
    throw err
  }

  const outcome = await withInbox(deps.sql, MINT_DEPLOY_FUNDING_REQUESTED, input.eventId, (tx: Tx) =>
    planOutbound(tx, {
      purpose: 'gas_topup',
      chain: request.chain,
      network: request.network,
      from: treasury,
      to: request.deployerAddress,
      assetCode: assetOf(request.chain),
      amount: request.amount,
      fee,
      // The ATTEMPT is in the key, and that is the whole of why mint numbers its asks. A key of
      // just the token id would make a second, larger ask a duplicate of the first and the order
      // would sit waiting for money that was never sent.
      idempotencyKey: `settlement:deployerfund:${request.tokenId}:${request.attempt}`,
      // No FK, deliberately — `source_ref` names a row in another service's database. It is what
      // `topUpsFor` counts and what an operator greps when an order is stuck.
      sourceRef: request.tokenId,
      correlationId: input.correlationId,
    }),
  )

  if (outcome.status === 'duplicate') return { kind: 'duplicate', outboundId: null }
  return outcome.value.created
    ? { kind: 'planned', outboundId: outcome.value.outbound.id, amount: request.amount.toString() }
    : { kind: 'duplicate', outboundId: outcome.value.outbound.id }
}

/**
 * How many top-ups this service has planned for one token, ignoring the ones that provably failed.
 *
 * `failed` is excluded because a rejected transaction moved nothing: the money is still in the
 * treasury and the order still cannot deploy, so counting it would spend a token's whole allowance
 * on transfers that never landed. Everything else counts, including rows still `planned` — a
 * top-up that has not been signed yet is money committed, and letting a burst of redeliveries plan
 * five of them before the first one broadcasts is exactly what this bound is for.
 */
async function topUpsFor(sql: Db, tokenId: string, chain: ChainId, network: Network): Promise<number> {
  const rows = await sql<{ count: string }[]>`
    select count(*)::text as count
      from outbound_transactions
     where purpose = 'gas_topup'
       and source_ref = ${tokenId}
       and chain = ${chain}
       and network = ${network}
       and state <> 'failed'
  `
  return Number(rows[0]?.count ?? '0')
}
