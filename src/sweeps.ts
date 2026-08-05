/**
 * Sweeps: deposit address → the pinned treasury.
 *
 * A sweep is an `outbound_transaction` with `purpose: 'sweep'` and it goes through the identical
 * state machine, the identical lease and the identical in-flight index as a withdrawal. That is not
 * economy, it is the correctness property: a sweep out of a deposit address and a payment out of
 * the treasury are two transactions on one chain, and giving them separate tables would give this
 * service two independent notions of "is anything in flight" — which is exactly what forge-pay has,
 * and its two workers each check their own.
 *
 * ## It sweeps to a target, and the target is zero
 *
 * The obvious design — "consolidate any address holding more than the fee is worth" — drains every
 * deposit into the treasury as fast as deposits arrive, and it is the wrong default, because
 * **sweeping is not neutral**. Custody will not sign an arbitrary transfer out of a deposit address
 * and it will sign one out of the treasury to any destination a caller names, so moving a coin from
 * one to the other moves it INTO the blast radius of the signing credential. A leaked token buying
 * the float is a different-sized incident from a leaked token buying every deposit ever made. So
 * the trigger is demand: whatever queued withdrawals cannot be covered, plus a float only if an
 * operator has asked for one by name, and nothing else moves.
 *
 * ## Maturity, and what it is for now
 *
 * `sweep_sources.swept` advances at CONFIRMATION and never at broadcast. In the estate this
 * replaces that delay was load-bearing for CREDITING: the deposit watcher read a balance at
 * confirmation depth, so money a sweep had moved was still inside the view it credited from, and
 * advancing early made the watcher credit the depositor a second time and then freeze the address
 * for ever. The indexer now reports each transaction with a real hash and a direction, so that
 * particular double-credit is gone, and the maturity window collapses to the asset's own declared
 * depth rather than depth-plus-a-window.
 *
 * What the delay still buys is this service's own arithmetic. Between broadcast and confirmation
 * the funds have left but a spot balance read still shows them, so without accounting for what is
 * in flight the sweeper would spend a second fee discovering that the first sweep had already moved
 * the money. `unmaturedByAddress` is that accounting, and it is a SKIP rather than a subtraction:
 * on a UTXO chain a second sweep of a partly-swept address is a second transaction spending the
 * same outpoints, which is not a smaller sweep, it is a conflicting one.
 */

import { chainSpec, type Network } from '@cloudsforge/contracts-chain'
import { assetOf, custodyChainOf, type ChainId } from './chains.ts'
import { chainFor } from './registry.ts'
import { assertSweepable, floatTarget, type TreasuryDeps } from './treasury.ts'
import {
  callFor,
  planOutbound,
  type OutboundDeps,
  type OutboundTransaction,
} from './outbound.ts'
import type { CustodyTokenContract } from './custodyclient.ts'
import { SETTLEMENT_SWEEP_COMPLETED, type Db, type DomainEvent } from './outbox.ts'

/* ------------------------------------------------------------------ sources */

export interface SweepSource {
  readonly id: string
  readonly chain: ChainId
  readonly network: Network
  readonly address: string
  readonly addressKey: string
  readonly custodyChain: string
  readonly custodyFamily: string
  readonly custodyUserId: string
  readonly custodyOrderId: string
  readonly swept: bigint
  readonly observed: bigint | null
  readonly active: boolean
}

interface SourceRow {
  readonly id: string
  readonly chain: string
  readonly network: string
  readonly address: string
  readonly address_key: string
  readonly custody_chain: string
  readonly custody_family: string
  readonly custody_user_id: string
  readonly custody_order_id: string
  readonly swept: string
  readonly observed: string | null
  readonly active: boolean
}

function toSource(row: SourceRow): SweepSource {
  return {
    id: row.id,
    chain: row.chain as ChainId,
    network: row.network as Network,
    address: row.address,
    addressKey: row.address_key,
    custodyChain: row.custody_chain,
    custodyFamily: row.custody_family,
    custodyUserId: row.custody_user_id,
    custodyOrderId: row.custody_order_id,
    swept: BigInt(row.swept),
    observed: row.observed === null ? null : BigInt(row.observed),
    active: row.active,
  }
}

const SOURCE_COLUMNS = `
  id, chain, network, address, address_key, custody_chain, custody_family,
  custody_user_id, custody_order_id, swept::text as swept, observed::text as observed, active
`

export interface RegisterSourceInput {
  readonly chain: ChainId
  readonly network: Network
  readonly address: string
  readonly custodyChain: string
  readonly custodyFamily: string
  /** custody's stored `userId` for this address. There is nothing here to derive it from. */
  readonly custodyUserId: string
  readonly custodyOrderId: string
}

/**
 * Record a deposit address this service may sweep.
 *
 * A ROUTE rather than an inference, and the binding fields are why. Custody compares the caller's
 * restated `userId` and `orderId` against the row it minted, character for character, and its 403
 * deliberately will not say which field disagreed. Those two values are wallet's assignment facts —
 * whichever user the address was assigned to and whichever assignment id it was minted under — and
 * nothing in this service could reconstruct them. Guessing would produce a sweep that is refused
 * every tick for ever with a message nobody can act on.
 *
 * Idempotent on `(chain, network, address_key)`: wallet re-registers freely, and a re-registration
 * that changes the binding UPDATES it, because an address custody re-minted under a different order
 * is an address whose old binding is simply wrong.
 */
export async function registerSweepSource(
  sql: Db,
  input: RegisterSourceInput,
): Promise<SweepSource> {
  const adapter = chainFor(input.chain)
  const display = adapter.canonicalise(input.address)
  await sql`
    insert into sweep_sources (
      chain, network, address, address_key,
      custody_chain, custody_family, custody_user_id, custody_order_id
    ) values (
      ${input.chain}, ${input.network}, ${display}, ${adapter.addressKey(input.address)},
      ${input.custodyChain}, ${input.custodyFamily}, ${input.custodyUserId}, ${input.custodyOrderId}
    )
    on conflict (chain, network, address_key) do update
      set custody_user_id = excluded.custody_user_id,
          custody_order_id = excluded.custody_order_id,
          custody_chain = excluded.custody_chain,
          custody_family = excluded.custody_family,
          active = true,
          updated_at = now()
  `
  const source = await findSweepSource(sql, input.chain, input.network, display)
  if (!source) throw new Error(`sweep source ${display} vanished immediately after registration`)
  return source
}

export async function findSweepSource(
  sql: Db,
  chain: ChainId,
  network: Network,
  address: string,
): Promise<SweepSource | null> {
  const key = chainFor(chain).addressKey(address)
  const rows = await sql<SourceRow[]>`
    select ${sql.unsafe(SOURCE_COLUMNS)} from sweep_sources
     where chain = ${chain} and network = ${network} and address_key = ${key}
  `
  return rows[0] ? toSource(rows[0]) : null
}

export async function findSweepSourceById(sql: Db, id: string): Promise<SweepSource | null> {
  const rows = await sql<SourceRow[]>`
    select ${sql.unsafe(SOURCE_COLUMNS)} from sweep_sources where id = ${id}
  `
  return rows[0] ? toSource(rows[0]) : null
}

/**
 * Candidates for a sweep, best first.
 *
 * `observed desc nulls first`: an address nothing has ever probed is looked at before one known to
 * be nearly empty, because an unprobed address is the one most likely to be holding something
 * unexpected. After that it is largest first, so a given shortfall is covered by the fewest
 * transactions — each sweep costs a fee the platform absorbs and each occupies this chain's single
 * outbound slot for a full confirmation depth.
 */
export async function sweepCandidates(
  sql: Db,
  chain: ChainId,
  network: Network,
  limit: number,
): Promise<readonly SweepSource[]> {
  const rows = await sql<SourceRow[]>`
    select ${sql.unsafe(SOURCE_COLUMNS)} from sweep_sources
     where chain = ${chain} and network = ${network} and active = true
     order by observed desc nulls first, observed_at asc nulls first
     limit ${limit}
  `
  return rows.map(toSource)
}

async function recordObservation(sql: Db, id: string, observed: bigint): Promise<void> {
  await sql`
    update sweep_sources
       set observed = ${observed.toString()}, observed_at = now(), updated_at = now()
     where id = ${id}
  `
}

/* ------------------------------------------------------------------ in-flight arithmetic */

/**
 * What each address has already sent that has not yet matured, in smallest units.
 *
 * A non-zero entry takes the address out of this pass entirely, for the reason in the file header.
 * Includes `planned` as well, so a queued sweep does not cause a second one to be planned for the
 * same address in the same tick.
 *
 * The AMOUNT rather than a boolean, because it is what an operator reads to answer "how much of
 * this address is already moving" — and because a `sum` that is null for an address with nothing
 * in flight is the one shape `BigInt('')` could have been reached through. `sum` over an empty
 * group returns no ROW here, not an empty string, so the map simply has no entry and the caller's
 * `?? 0n` is the whole of it.
 */
export async function unmaturedByAddress(
  sql: Db,
  chain: ChainId,
  network: Network,
): Promise<ReadonlyMap<string, bigint>> {
  const rows = await sql<Array<{ from_address_key: string; total: string }>>`
    select from_address_key, sum(amount + fee)::text as total
      from outbound_transactions
     -- NATIVE SWEEPS ONLY, and the exclusion of 'token_sweep' is deliberate rather than an
     -- oversight. A token sweep's amount is denominated in the TOKEN and its fee in native wei,
     -- so adding it to this total would produce a number in no unit at all — and this total is
     -- read by an operator answering "how much of this address is already moving". A quantity that
     -- is sometimes wei and sometimes six-decimal USDT is worse than no quantity.
     --
     -- The SET of addresses to leave alone is a different question and it is answered by
     -- addressesInFlight, which both planners consult. Splitting the two is what lets this one
     -- keep a meaning.
     where chain = ${chain} and network = ${network} and purpose = 'sweep'
       and state in ('planned','building','signed','broadcast')
     group by from_address_key
  `
  return new Map(rows.map((r) => [r.from_address_key, BigInt(r.total)]))
}

/**
 * Every address with an unretired outbound movement off it, of any purpose.
 *
 * **A SET RATHER THAN A SUM, because the question is "leave this alone?" and not "how much?".**
 * Mixing a token amount into a wei total gives a number in no unit; mixing them into a set gives
 * exactly the right answer, because membership does not have a unit.
 *
 * `planned` is included, which is the clause that makes the two-phase plan safe: from the instant
 * the pair commits, the deposit address is in this set, so no later pass observes it, probes it, or
 * funds it a second time. That is rule 2 of `signing.ts` — fund once — enforced by a query rather
 * than by a planner remembering to.
 */
export async function addressesInFlight(
  sql: Db,
  chain: ChainId,
  network: Network,
): Promise<ReadonlySet<string>> {
  const rows = await sql<Array<{ from_address_key: string; to_address_key: string }>>`
    select from_address_key, to_address_key
      from outbound_transactions
     where chain = ${chain} and network = ${network}
       and purpose in ('sweep','token_sweep','gas_topup')
       and state in ('planned','building','signed','broadcast')
  `
  // BOTH ENDS, and the destination end is the one that matters for a top-up: a `gas_topup` moves
  // FROM the treasury TO the deposit address, so keying it only by its source would put the
  // treasury in the set — true and useless — while leaving the address it funds looking untouched.
  // That is precisely the address a second pass must not fund again.
  const keys = new Set<string>()
  for (const row of rows) {
    keys.add(row.from_address_key)
    keys.add(row.to_address_key)
  }
  return keys
}

/**
 * What this chain's treasury owes but cannot pay: every withdrawal already promised to a user.
 *
 * `planned` and in-flight both count. A withdrawal that has been signed has already taken its money
 * out of the treasury's spendable balance as far as the node is concerned, but it has not left yet,
 * so counting it keeps the sweeper from concluding the treasury is richer than it is.
 */
export async function owedOnChain(sql: Db, chain: ChainId, network: Network): Promise<bigint> {
  const rows = await sql<Array<{ total: string | null }>>`
    select sum(amount + fee)::text as total
      from outbound_transactions
     where chain = ${chain} and network = ${network} and purpose = 'withdrawal'
       and state in ('planned','building','signed','broadcast')
  `
  const total = rows[0]?.total
  return total === null || total === undefined ? 0n : BigInt(total)
}

/**
 * How much this chain's treasury is short right now.
 *
 * Two components answering two different questions. The FLOAT TARGET is "how much should be sitting
 * here so a withdrawal does not have to wait for a sweep to confirm", and it is zero unless an
 * operator sets one. The QUEUED WITHDRAWALS are "how much has already been promised to users and
 * cannot be paid" — always honoured, target or no target, because the alternative is the failure
 * this whole workstream exists to fix: a withdrawal accepted, reserved, and then refunded an hour
 * later for want of a treasury balance.
 *
 * The LARGER of the two, not the sum: the float is what the treasury should hold, and coins already
 * sitting there pay a queued withdrawal just as well as freshly swept ones do.
 */
export async function treasuryShortfall(
  deps: SweepDeps,
  chain: ChainId,
  network: Network,
  treasuryAddress: string,
): Promise<bigint> {
  const asset = assetOf(chain)
  const spec = chainSpec(asset)
  const target = floatTarget(deps.treasuryTargets, asset, spec.decimals)
  const [held, owed] = await Promise.all([
    chainFor(chain).spendableBalance(callFor(deps, chain), treasuryAddress),
    owedOnChain(deps.sql, chain, network),
  ])
  const wanted = target > owed ? target : owed
  return wanted > held ? wanted - held : 0n
}

/* ------------------------------------------------------------------ planning */

export interface SweepDeps extends OutboundDeps, TreasuryDeps {
  readonly treasuryTargets: Readonly<Record<string, string>>
  readonly minFeeMultiple: number
  readonly probeLimit: number
  readonly enabled: boolean
}

export type SweepPlanOutcome =
  | { readonly kind: 'disabled' }
  | { readonly kind: 'unsupported'; readonly phase: string }
  | { readonly kind: 'satisfied' }
  | { readonly kind: 'nothing_to_sweep' }
  | { readonly kind: 'planned'; readonly outboundId: string; readonly amount: bigint }

/**
 * Decide whether anything should be swept on this chain, and plan at most one.
 *
 * **At most one, per tick, per chain**, and it is the same rule the whole service runs on: a second
 * sweep would be built from the same account state, carry the same nonce, and could never land. The
 * address's funds are not a queue and neither is the treasury's inbox.
 *
 * `enabled` gates only the OPENING of new sweeps. One already in flight is always driven to
 * confirmation whatever the flag says, because the money has already left the address and nothing
 * else can account for it — turning the flag off with a sweep in flight used to mean nothing ever
 * matured it, at info level, silently.
 */
export async function planSweep(
  deps: SweepDeps,
  chain: ChainId,
  network: Network,
): Promise<SweepPlanOutcome> {
  if (!deps.enabled) return { kind: 'disabled' }
  const adapter = chainFor(chain)
  if (adapter.unimplementedPhase) return { kind: 'unsupported', phase: adapter.unimplementedPhase }

  // Throws `NoTreasuryPinnedError` or `TreasuryDisagreementError`, and both are correct refusals to
  // sweep: **nothing sweeps to an unpinned candidate**, and nothing sweeps at all while the pin and
  // the payout row disagree. The pin is read fresh here and echoed to custody exactly as published,
  // because custody compares `to` against it character for character.
  const { treasury, pin } = await assertSweepable(deps, chain, network)

  let needed = await treasuryShortfall(deps, chain, network, treasury.address)
  if (needed <= 0n) return { kind: 'satisfied' }

  const call = callFor(deps, chain)
  const multiple = BigInt(Math.max(1, deps.minFeeMultiple))

  const unmatured = await unmaturedByAddress(deps.sql, chain, network)
  const inFlight = await addressesInFlight(deps.sql, chain, network)
  const candidates = await sweepCandidates(deps.sql, chain, network, deps.probeLimit)

  for (const source of candidates) {
    if (source.addressKey === treasury.addressKey) continue
    // Anything moving off OR onto this address, of any purpose. Checked before the probe, because
    // an address with a token sweep pair outstanding is one whose native balance is about to change
    // by exactly the gas that pair delivers — so a native quote taken now is a quote of a number
    // that is already stale.
    if (inFlight.has(source.addressKey)) continue
    // One probe per candidate per pass, bounded by `probeLimit`. Without the bound this is one RPC
    // per deposit address ever created, per tick, for ever — and most of them have never held a
    // coin. That unbounded scan is the shape of forge-pay's watcher, which AD-07 records.
    //
    // **A QUOTE FOR THIS ADDRESS, not a balance and a generic fee.** The two were separate calls
    // until a Bitcoin sweep needed the fee to depend on how many coins the address holds: a sweep
    // spends every one of them, so `estimateFee`'s one-input two-output quote under-priced a
    // three-coin address by more than half and produced a transaction below the relay floor. The
    // adapter answers the whole question or answers null.
    const quote = await adapter.sweepQuote(call, source.address, deps.bounds)
    const balance = quote === null ? 0n : quote.value + quote.fee
    await recordObservation(deps.sql, source.id, balance)
    if (quote === null) continue

    // Anything already moving off this address is a reason to leave it alone entirely, rather than
    // to sweep the difference. Between broadcast and confirmation the coins have gone but a spot
    // read still shows them, so a second sweep would spend a second fee discovering that — and on
    // a UTXO chain it would also be a second transaction spending the same outpoints.
    if ((unmatured.get(source.addressKey) ?? 0n) > 0n) continue

    // Sweeping an address whose balance barely exceeds the fee spends most of the customer's
    // deposit on moving it. The multiple is the whole economics of this worker, and it is applied
    // to THIS sweep's fee rather than to a typical one.
    if (balance < quote.fee * multiple) continue

    // `amount` is what the TREASURY gains and `fee` is burned on top: the whole spendable balance
    // leaves the address. Counting the fee towards the shortfall would leave the treasury a fee
    // short on every sweep.
    const value = quote.value
    if (value <= 0n) continue
    const fee = quote.fee

    const { outbound, created } = await planOutbound(deps.sql, {
      purpose: 'sweep',
      chain,
      network,
      from: source.address,
      // custody's PIN, spelled exactly as custody published it, and deliberately not
      // `treasury.address`. `assertSweep` compares `to` against its own pin character for character
      // and has a refusal of its own for an address that differs only in case — an EVM address has
      // three valid spellings and custody accepts one. `assertSweepable` has already proved the two
      // are the same account.
      to: pin,
      assetCode: assetOf(chain),
      amount: value,
      fee,
      // Deterministic and derived: the source and the balance being moved. Two ticks that observe
      // the same balance produce the same key, so a duplicated planning pass writes one row rather
      // than two sweeps of one address — and a balance that HAS moved produces a different key, so
      // the re-plan is a new row rather than a conflict with a stale one.
      idempotencyKey: `settlement:sweep:${chain}:${network}:${source.id}:${balance.toString()}`,
      sourceRef: source.id,
    })
    if (!created) continue
    needed -= value
    return { kind: 'planned', outboundId: outbound.id, amount: value }
  }

  return { kind: 'nothing_to_sweep' }
}

/* ------------------------------------------------------------------ the token path */

/**
 * A token an operator registered, as this service needs it.
 *
 * Read from CUSTODY rather than configured here, and that is the load-bearing decision. Custody's
 * `custody_token_contracts` is the allowlist `assertTokenSweep` checks a candidate against, so a
 * contract this service planned a sweep for and custody has not registered is a `shape_refused`
 * arriving after the row is committed and the chain's single outbound slot is claimed. One
 * authority, read by the service that must not disagree with it.
 */
export interface RegisteredToken {
  readonly chain: ChainId
  readonly network: Network
  /** Lower-cased. Both sides' schemas enforce that. */
  readonly contract: string
  readonly symbol: string
  readonly decimals: number
}

export interface TokenSweepDeps extends SweepDeps {
  /**
   * Whether this deployment sweeps tokens at all. **Separate from `enabled`, deliberately.**
   *
   * A deployment that sweeps native coin correctly is not thereby ready to sweep tokens: the
   * precondition is that `micro-wallet` credits token deposits, which it does not yet, and until it
   * does a token sweep moves customer money the ledger has recorded no liability for. `env.ts` on
   * `tokenSweepEnabled` carries the whole argument. One flag for both would make that decision by
   * accident.
   */
  readonly tokenSweepEnabled: boolean
  /** The registry, read from custody. Empty is the ordinary state and is never an error. */
  readonly tokens: (chain: ChainId, network: Network) => Promise<readonly RegisteredToken[]>
  /** @see env.minTokenSweep. Zero disables the floor. */
  readonly minimumTokenSweep: bigint
}

/**
 * The ledger asset code a token balance is denominated in.
 *
 * `TOKEN:<chain>:<network>:<contract>` — the urn shape `contracts-money` already defines
 * (`TokenAssetCode`), where two deployments of one brand are two ledger assets PERMANENTLY.
 *
 * **NOTHING HERE MAY EVER WRITE `USDT`.** A single `USDT` asset code forces one decimals value onto
 * a token that has six on Ethereum, six on Tron and eighteen on BSC, and the wrong decimals on a
 * stablecoin is a balance wrong by a factor of 10^12. It also silently asserts that a USDT balance
 * is one thing, when a deposit on one chain cannot be paid out on another without a bridge this
 * platform is not and must never become. "USDT" is a display grouping for a frontend; it is never a
 * code. It is a function rather than an inline template so the one place that spells this is
 * testable in isolation.
 */
export function tokenAssetCode(token: RegisteredToken): string {
  return `TOKEN:${token.chain}:${token.network}:${token.contract}`
}

/**
 * Custody's registry, narrowed to one chain and network and translated into this service's slug.
 *
 * **THE TRANSLATION IS THE WHOLE OF THIS FUNCTION AND IT IS NOT A `toLowerCase()`.** Custody stores
 * `ethereum` where this service's slug is `eth` — the one disagreement of five, and at signing time
 * it is a `binding_mismatch` custody deliberately will not explain. Filtering custody's rows by this
 * service's slug would silently match nothing on Ethereum, which is the only chain that has tokens,
 * so the bug would present as "tokens are registered and nothing is ever swept".
 *
 * The `contract` is lower-cased again on the way out even though custody's CHECK constraint already
 * guarantees it. That is not distrust of the constraint; it is that this value is compared against
 * `outbound_token_contract_ck` and against custody's allowlist by two different mechanisms, and a
 * normalisation that happens in exactly one place cannot be the one that is skipped.
 */
export function tokensFor(
  all: readonly CustodyTokenContract[],
  chain: ChainId,
  network: Network,
): readonly RegisteredToken[] {
  const custodyChain = custodyChainOf(chain)
  return all
    .filter((row) => row.chain === custodyChain && row.network === network)
    .map((row) => ({
      chain,
      network,
      contract: row.contract.toLowerCase(),
      symbol: row.symbol,
      decimals: row.decimals,
    }))
}

export type TokenSweepOutcome =
  | { readonly kind: 'disabled' }
  | { readonly kind: 'no_tokens' }
  | { readonly kind: 'nothing_to_sweep' }
  | {
      readonly kind: 'planned'
      readonly topUpId: string
      readonly sweepId: string
      readonly amount: bigint
      readonly contract: string
    }

/**
 * Plan a gas top-up and the ERC-20 sweep it pays for — **two rows, one transaction, in order**.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * ## Why both rows are written at once, when only the first can run
 *
 * The obvious shape is "top up now, plan the sweep when the top-up confirms". It has a window, and
 * the window costs money every time it is hit: a crash between the top-up confirming and the sweep
 * being planned leaves a deposit address holding gas, with nothing on file saying why. The next
 * pass reads the TOKEN balance — which the top-up did not change — decides a sweep is warranted,
 * and funds the address a second time. `signing.ts` states the rule this breaks as its rule 2:
 * "the top-up and the sweep are two transactions with a confirmation between them; a planner that
 * does not treat the top-up as in-flight will fund the same address on every tick until it
 * confirms."
 *
 * Writing both rows in one transaction removes the window entirely rather than narrowing it. After
 * it commits, the sweep row exists in `planned` with `depends_on` set, and `unmaturedByAddress`
 * — which counts `planned` — takes this address out of every later pass until the pair retires.
 * There is no state in which the top-up is on file and the sweep is not.
 *
 * ## What a crash at each point costs, stated exhaustively
 *
 *   * **Before the commit.** Nothing exists. The next pass re-observes the same token balance and
 *     plans the same pair. No transaction was signed, so nothing moved.
 *   * **After the commit, before the top-up is signed.** Two `planned` rows. The worker claims the
 *     top-up (the sweep is skipped by `nextPlanned`'s dependency clause) and proceeds.
 *   * **Mid top-up.** The ordinary outbound recovery: bytes are committed before they are
 *     broadcast, and a `signed` row re-sends the identical bytes rather than re-signing.
 *   * **After the top-up confirms, before the sweep starts.** The sweep is `planned` and now
 *     unblocked; the next tick picks it up. This is the window the naive design double-funds in,
 *     and here it is simply the queue working.
 *   * **Mid sweep.** The same outbound recovery again.
 *
 * ## Why this cannot double-spend
 *
 * Three independent mechanisms, and they catch different things:
 *
 *   1. **Both idempotency keys are derived from the same tuple**, including the observed token
 *      balance. A second pass that observes the same balance computes the same two keys and
 *      `planOutbound` returns `created: false` for both. A balance that HAS moved is a different
 *      pair of keys, which is a new sweep rather than a conflict with a stale one.
 *   2. **`unmaturedByAddress` counts `planned`**, so the address is out of the candidate set from
 *      the instant the pair commits until the sweep matures.
 *   3. **`outbound_in_flight_uniq`** permits one in-flight transaction per chain, so the top-up and
 *      the sweep cannot be in the air together even if everything above failed.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export async function planTokenSweep(
  deps: TokenSweepDeps,
  chain: ChainId,
  network: Network,
): Promise<TokenSweepOutcome> {
  // BOTH flags, and `tokenSweepEnabled` is the one that is off by default. A deployment that has
  // turned sweeping off entirely must not sweep tokens either; a deployment that sweeps native coin
  // has said nothing about tokens.
  if (!deps.enabled || !deps.tokenSweepEnabled) return { kind: 'disabled' }
  const adapter = chainFor(chain)
  // A family with no token model, or a chain this service cannot move a coin on at all. Both are
  // silent and permanent, and neither is an error: `tokens: null` is Bitcoin's ordinary state.
  if (adapter.unimplementedPhase || !adapter.tokens) return { kind: 'no_tokens' }

  const registered = await deps.tokens(chain, network)
  if (registered.length === 0) return { kind: 'no_tokens' }

  // The pin, read fresh and echoed exactly as custody published it. `assertTokenSweep` compares the
  // calldata's recipient against this same value, so a stale copy is a refusal.
  const { treasury, pin } = await assertSweepable(deps, chain, network)

  const call = callFor(deps, chain)
  const inFlight = await addressesInFlight(deps.sql, chain, network)
  const candidates = await sweepCandidates(deps.sql, chain, network, deps.probeLimit)
  const tokens = adapter.tokens

  for (const source of candidates) {
    if (source.addressKey === treasury.addressKey) continue
    // Anything at all already moving off this address — a native sweep, a token sweep, or the
    // `planned` half of a pair from a previous pass — takes it out of this pass entirely. Checked
    // BEFORE any RPC, because the whole point is to not spend a probe on an address we have already
    // decided about.
    if (inFlight.has(source.addressKey)) continue

    for (const token of registered) {
      const balance = await tokens.balanceOf(call, source.address, token.contract)
      if (balance <= 0n) continue
      // A floor an operator sets, in the token's own smallest units. Below it the two transactions
      // this takes cost more in native gas than the tokens are worth, and sweeping anyway would be
      // spending the platform's coin to move a dust balance into the blast radius of the signing
      // credential. Zero disables the floor, which is the default and is deliberate: a number
      // nobody has chosen must not silently strand a real deposit.
      if (deps.minimumTokenSweep > 0n && balance < deps.minimumTokenSweep) continue

      const gasFee = await tokens.transferFee(call, deps.bounds)
      // What the TOP-UP itself costs to send, on top of what it delivers.
      const topUpFee = await adapter.estimateFee(call, deps.bounds)

      const key = `${chain}:${network}:${source.id}:${token.contract}:${balance.toString()}`
      const planned = await deps.sql.begin(async (tx) => {
        // ── PHASE A ────────────────────────────────────────────────────────────────────────────
        // Treasury → the deposit address, delivering EXACTLY the sweep's locked fee. Not more: gas
        // parked at a deposit address is dust that must itself be swept later, at a fee, from
        // however many addresses accumulated it (`signing.ts`, rule 1 — fund on demand, never in
        // advance). Not less: an under-funded sweep runs out of gas, burns the fee and moves
        // nothing.
        const topUp = await planOutbound(tx, {
          purpose: 'gas_topup',
          chain,
          network,
          from: treasury.address,
          to: source.address,
          assetCode: assetOf(chain),
          amount: gasFee,
          fee: topUpFee,
          idempotencyKey: `settlement:gastopup:${key}`,
          sourceRef: source.id,
        })

        // ── PHASE B ────────────────────────────────────────────────────────────────────────────
        // The deposit address → the treasury, in the token. `to` is the PIN — who is paid — and the
        // contract travels in its own column; the builder puts the first inside the calldata and
        // the second in the transaction's `to`.
        //
        // `fee` is `gasFee`, the identical value phase A delivers. That equality is the whole
        // sequencing contract between the two rows: A sends exactly what B's locked fee will be
        // divided by `TOKEN_TRANSFER_GAS` to recover a gas price from.
        const sweep = await planOutbound(tx, {
          purpose: 'token_sweep',
          chain,
          network,
          from: source.address,
          to: pin,
          assetCode: tokenAssetCode(token),
          amount: balance,
          fee: gasFee,
          idempotencyKey: `settlement:tokensweep:${key}`,
          sourceRef: source.id,
          tokenContract: token.contract,
          dependsOn: topUp.outbound.id,
        })
        return { value: { topUp, sweep } }
      })

      // Neither was created: an identical pair is already on file from a previous pass that
      // observed the same balance. Ordinary, and the address is left alone.
      if (!planned.value.topUp.created && !planned.value.sweep.created) continue

      return {
        kind: 'planned',
        topUpId: planned.value.topUp.outbound.id,
        sweepId: planned.value.sweep.outbound.id,
        amount: balance,
        contract: token.contract,
      }
    }
  }

  return { kind: 'nothing_to_sweep' }
}

/* ------------------------------------------------------------------ maturity */

/**
 * Advance the swept high-water mark, once and only once, and only at depth.
 *
 * Guarded on `matured_at is null` inside the same transaction that increments `swept`, so two
 * workers reaching this for one sweep add its amount once. The increment is `amount + fee`, which is
 * everything that left the address — the fee is burned in between, and a mark that counted only
 * what arrived would drift low by one fee per sweep for ever.
 */
export async function matureSweepFor(
  deps: OutboundDeps,
  row: OutboundTransaction,
): Promise<boolean> {
  if (row.purpose !== 'sweep' || !row.sourceRef) return false
  const outcome = await deps.sql.begin(async (tx) => {
    const claimed = await tx<Array<{ id: string }>>`
      update outbound_transactions set matured_at = now(), updated_at = now()
       where id = ${row.id} and matured_at is null and state = 'confirmed'
      returning id
    `
    if (claimed.length === 0) return { value: false }
    await tx`
      update sweep_sources
         set swept = swept + ${(row.amount + row.fee).toString()},
             -- The observation is now known to be stale by exactly what just left, so it is reset
             -- rather than left to overstate this address on the next ordering pass.
             observed = greatest(0, coalesce(observed, 0) - ${(row.amount + row.fee).toString()}),
             updated_at = now()
       where id = ${row.sourceRef}
    `
    return { value: true }
  })
  if (outcome.value) {
    deps.logger.info('sweep matured: its amount is now recorded against the deposit address', {
      outboundId: row.id,
      sourceRef: row.sourceRef,
      chain: row.chain,
      amount: (row.amount + row.fee).toString(),
    })
  }
  return outcome.value
}

/**
 * The binding custody demands be restated for a sweep.
 *
 * Read from the row rather than derived, because there is nothing to derive it from: `userId` and
 * `orderId` are whatever wallet used when it had custody mint the address. A source that has gone
 * missing throws, and throwing is right — a sweep signed against a guessed binding is a 403 whose
 * message will not say which field was wrong.
 */
export async function sweepBindingFor(
  deps: OutboundDeps,
  row: OutboundTransaction,
): Promise<{ readonly userId: string; readonly orderId: string }> {
  if (!row.sourceRef) throw new Error(`sweep ${row.id} has no source address recorded`)
  const source = await findSweepSourceById(deps.sql, row.sourceRef)
  if (!source) {
    throw new Error(
      `sweep ${row.id} names sweep source ${row.sourceRef}, which no longer exists — custody will ` +
        'not sign for an address this service cannot restate the binding of',
    )
  }
  return { userId: source.custodyUserId, orderId: source.custodyOrderId }
}

/**
 * A confirmed sweep. Nobody's reservation is waiting on it; this is for reconciliation.
 *
 * **KEYED BY THE SWEEP SOURCE, WHICH IS THE REGISTRY'S CHOICE AND NOT THIS SERVICE'S.**
 * `@cloudsforge/contracts-events` registers `settlement.sweep.completed` with
 * `keyedBy: 'sweep_source_id'`. This keyed it by the outbound row id, which was also what this
 * repository proposed when it asked for the topic to be registered — and the registry chose
 * differently, so the emit site moved. The registry is right: `key` is the ORDERING PARTITION, and
 * two sweeps of one deposit address must be ordered against each other, while two sweeps of
 * different addresses have no ordering relationship at all. Keyed by the outbound row every sweep
 * is its own partition and the ordering guarantee says nothing.
 *
 * A row with no `sourceRef` emits NOTHING, exactly as `confirmedEvents` does for a withdrawal with
 * no withdrawal id. There is deliberately no fallback to the row id: a fallback would be a second
 * key shape on one topic, which is the ordering guarantee saying different things about different
 * events, and it would be unreachable anyway — `planSweep` always writes `sourceRef`. The row id
 * is on the payload as `outboundId` for anyone who wants it.
 */
export function sweepCompletedEvents(row: OutboundTransaction): readonly DomainEvent[] {
  if (!row.sourceRef) return []
  return [
    {
      topic: SETTLEMENT_SWEEP_COMPLETED,
      key: row.sourceRef,
      payload: {
        outboundId: row.id,
        sweepSourceId: row.sourceRef,
        chain: row.chain,
        network: row.network,
        assetCode: row.assetCode,
        from: row.fromAddress,
        to: row.toAddress,
        amount: row.amount.toString(),
        fee: row.fee.toString(),
        txHash: row.txHash,
        confirmedAt: (row.confirmedAt ?? new Date()).toISOString(),
      },
      ...(row.correlationId ? { correlationId: row.correlationId } : {}),
    },
  ]
}
