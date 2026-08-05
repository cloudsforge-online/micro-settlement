/**
 * `outbound_transaction`: the store, and the state machine that is the whole of this service.
 *
 *     planned → building → signed → broadcast → confirmed
 *                   ↘ failed              ↘ stuck
 *
 * Two rules run through every line of it, and they are the frozen withdrawer's, carried forward
 * because they were paid for:
 *
 * **ONE SIGNATURE, EVER, AND THE BYTES ARE COMMITTED BEFORE ANYTHING IS BROADCAST.** A process that
 * dies between building and committing has broadcast nothing, so the work is simply redone. One
 * that dies between committing and broadcasting is recovered by re-sending the IDENTICAL bytes,
 * which every chain here deduplicates by transaction id. The order is the property: a crash after
 * broadcast but before the write would leave a transaction on chain that the database does not know
 * about, and that is unrecoverable by inspection — there is no id to poll, nothing to reconcile,
 * and it is indistinguishable from a payment that never happened.
 *
 * **NEVER GIVE MONEY BACK FOR SOMETHING THAT MIGHT STILL LAND.** A signed transaction can sit in a
 * mempool for hours. So the giving-up decision is split by whether a signature exists, and the
 * split is enforced by the two transitions below rather than by discipline at the call sites:
 *
 *   * `markFailed` moves ONLY `planned` and `building`. Nothing was signed on either, so a refund
 *     is safe, and it is the only path that ever sets `refundable`.
 *   * `markStuck` moves ONLY `signed` and `broadcast`. Calling it for a `planned` row updates no
 *     row and returns false — deliberately a silent no-op rather than an error, exactly as the
 *     frozen `markWithdrawalStuck` is gated, so that the meaning of `stuck` ("a signed payment
 *     needs a human") cannot drift as call sites are added.
 *
 * A `stuck` row is **never auto-refunded**. It leaves that state only through
 * `adjudicate.ts`, and only on positive proof that the bytes are dead.
 */

import { chainSpec, type Network } from '@cloudsforge/contracts-chain'
import type { Logger } from '@cloudsforge/telemetry'
import {
  assetOf,
  type ChainCall,
  type ChainId,
  type FeeBounds,
  type JsonRpc,
  type OutboundStatus,
} from './chains.ts'
import { chainFor } from './registry.ts'
import type { CustodyClient } from './custodyclient.ts'
import type { IndexerClient } from './indexerclient.ts'
import { emitInto, type Db, type DomainEvent, type Tx } from './outbox.ts'

/**
 * Why a transaction exists. The purpose picks the signing policy, and for the two the token path
 * adds it also fixes the ORDER the two of them must run in.
 *
 *   * `gas_topup`   — treasury → a deposit address, native value, custody's `transfer` shape. The
 *     treasury already has that shape and SDR-05 already accepts that it may name ANY destination,
 *     so aiming one at a deposit address adds no capability a holder of `custody:sign:treasury`
 *     did not have. Solving the gas problem the other way round — a shape letting the DEPOSIT key
 *     move native value — would have created one, over a customer's key, to save a transaction.
 *   * `token_sweep` — a deposit address → a token contract, calldata `transfer(<pin>, amount)`.
 *     Custody refines this shape out of `sweep` FROM THE PAYLOAD and never from a field a caller
 *     sends, so this value does not select it. What it does is carry the dependency and keep the
 *     operator surface honest about which of two very different transactions a row is.
 */
export type OutboundPurpose =
  | 'withdrawal'
  | 'sweep'
  | 'treasury_move'
  | 'deploy'
  | 'gas_topup'
  | 'token_sweep'
export type OutboundState =
  | 'planned'
  | 'building'
  | 'signed'
  | 'broadcast'
  | 'confirmed'
  | 'stuck'
  | 'failed'

/** The states in which this chain's nonce is spoken for. The partial unique index uses this set. */
export const IN_FLIGHT_STATES: readonly OutboundState[] = Object.freeze([
  'building',
  'signed',
  'broadcast',
])

/** The states a worker still has work to do on. `planned` is the queue; the rest are in flight. */
export const OPEN_STATES: readonly OutboundState[] = Object.freeze([
  'planned',
  ...IN_FLIGHT_STATES,
])

export interface OutboundTransaction {
  readonly id: string
  readonly purpose: OutboundPurpose
  readonly chain: ChainId
  readonly network: Network
  readonly fromAddress: string
  readonly toAddress: string
  readonly assetCode: string
  /** Smallest units. `bigint` at every boundary; the column is numeric(78,0). */
  readonly amount: bigint
  readonly fee: bigint
  readonly state: OutboundState
  readonly rawTx: string | null
  readonly signedNonce: string | null
  readonly signedExpiry: string | null
  readonly custodyAuditId: string | null
  readonly txHash: string | null
  readonly confirmations: number
  readonly minedHeight: bigint | null
  readonly signedAt: Date | null
  readonly broadcastAt: Date | null
  readonly confirmedAt: Date | null
  readonly maturedAt: Date | null
  readonly ledgerEntryId: string | null
  readonly failureReason: string | null
  readonly sourceRef: string | null
  /** The ERC-20 contract, on a `token_sweep` and on nothing else. The schema enforces the iff. */
  readonly tokenContract: string | null
  /**
   * The transaction that must have CONFIRMED before this one may be built.
   *
   * Only a `token_sweep` has one today, naming its `gas_topup`. It is a general column rather than
   * a token-specific one because the ordering constraint is general — "these bytes cannot be
   * broadcast until those ones have landed" — and a second use of it should not need a second
   * mechanism.
   */
  readonly dependsOn: string | null
  readonly userId: string | null
  readonly reservationEntryId: string | null
  readonly correlationId: string | null
  readonly idempotencyKey: string
  readonly createdAt: Date
  readonly updatedAt: Date
}

interface OutboundRow {
  readonly id: string
  readonly purpose: string
  readonly chain: string
  readonly network: string
  readonly from_address: string
  readonly to_address: string
  readonly asset_code: string
  readonly amount: string
  readonly fee: string
  readonly state: string
  readonly raw_tx: string | null
  readonly signed_nonce: string | null
  readonly signed_expiry: string | null
  readonly custody_audit_id: string | null
  readonly tx_hash: string | null
  readonly confirmations: number
  readonly mined_height: string | null
  readonly signed_at: Date | null
  readonly broadcast_at: Date | null
  readonly confirmed_at: Date | null
  readonly matured_at: Date | null
  readonly ledger_entry_id: string | null
  readonly failure_reason: string | null
  readonly source_ref: string | null
  readonly token_contract: string | null
  readonly depends_on: string | null
  readonly user_id: string | null
  readonly reservation_entry_id: string | null
  readonly correlation_id: string | null
  readonly idempotency_key: string
  readonly created_at: Date
  readonly updated_at: Date
}

function toOutbound(row: OutboundRow): OutboundTransaction {
  return {
    id: row.id,
    purpose: row.purpose as OutboundPurpose,
    chain: row.chain as ChainId,
    network: row.network as Network,
    fromAddress: row.from_address,
    toAddress: row.to_address,
    assetCode: row.asset_code,
    amount: BigInt(row.amount),
    fee: BigInt(row.fee),
    state: row.state as OutboundState,
    rawTx: row.raw_tx,
    signedNonce: row.signed_nonce,
    signedExpiry: row.signed_expiry,
    custodyAuditId: row.custody_audit_id,
    txHash: row.tx_hash,
    confirmations: row.confirmations,
    minedHeight: row.mined_height === null ? null : BigInt(row.mined_height),
    signedAt: row.signed_at,
    broadcastAt: row.broadcast_at,
    confirmedAt: row.confirmed_at,
    maturedAt: row.matured_at,
    ledgerEntryId: row.ledger_entry_id,
    failureReason: row.failure_reason,
    sourceRef: row.source_ref,
    tokenContract: row.token_contract,
    dependsOn: row.depends_on,
    userId: row.user_id,
    reservationEntryId: row.reservation_entry_id,
    correlationId: row.correlation_id,
    idempotencyKey: row.idempotency_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

/**
 * Every column, with the numerics cast to text.
 *
 * postgres.js returns `numeric` as a JavaScript string already, but only because it refuses to
 * guess; the explicit `::text` is what makes that a property of the query rather than a property of
 * the driver version. An 18-decimal amount that came back as a number would be wrong from about
 * nine EMBER upwards, and it would not fail — it would be subtly wrong.
 */
const COLUMNS = `
  id, purpose, chain, network, from_address, to_address, asset_code,
  amount::text as amount, fee::text as fee, state, raw_tx, signed_nonce, signed_expiry,
  custody_audit_id, tx_hash, confirmations, mined_height::text as mined_height,
  signed_at, broadcast_at, confirmed_at, matured_at, ledger_entry_id, failure_reason,
  source_ref, token_contract, depends_on, user_id, reservation_entry_id, correlation_id,
  idempotency_key, created_at, updated_at
`

/* ------------------------------------------------------------------ planning */

export interface PlanInput {
  readonly purpose: OutboundPurpose
  readonly chain: ChainId
  readonly network: Network
  readonly from: string
  readonly to: string
  readonly assetCode: string
  readonly amount: bigint
  readonly fee: bigint
  readonly idempotencyKey: string
  readonly sourceRef?: string
  /** Required on a `token_sweep` and refused on everything else. `outbound_token_contract_ck`. */
  readonly tokenContract?: string
  /** @see OutboundTransaction.dependsOn */
  readonly dependsOn?: string
  readonly userId?: string
  readonly reservationEntryId?: string
  readonly correlationId?: string
}

/**
 * Write a `planned` row, or find the one that already exists for this idempotency key.
 *
 * **This is where "the same withdrawal request delivered twice produces one outbound transaction"
 * is true.** `on conflict do nothing` plus a re-read, rather than a read-then-insert: two workers
 * handling the same redelivered event both pass a read, and only one can win an insert.
 *
 * The key is WALLET'S, never one this service mints. Its boundary contract says so in as many
 * words — "the only value both services can agree on is this one" — and the reason is that a key
 * derived here from, say, the event id would differ between the original delivery and the
 * redelivery, which is precisely the case it has to catch.
 */
export async function planOutbound(
  sql: Db | Tx,
  input: PlanInput,
): Promise<{ readonly outbound: OutboundTransaction; readonly created: boolean }> {
  const adapter = chainFor(input.chain)
  const from = adapter.canonicalise(input.from)
  const to = adapter.canonicalise(input.to)
  const inserted = await sql<OutboundRow[]>`
    insert into outbound_transactions (
      purpose, chain, network, from_address, from_address_key, to_address, to_address_key,
      asset_code, amount, fee, state, source_ref, token_contract, depends_on, user_id,
      reservation_entry_id, correlation_id, idempotency_key
    ) values (
      ${input.purpose}, ${input.chain}, ${input.network},
      ${from}, ${adapter.addressKey(from)}, ${to}, ${adapter.addressKey(to)},
      ${input.assetCode}, ${input.amount.toString()}, ${input.fee.toString()}, 'planned',
      ${input.sourceRef ?? null},
      -- Lower-cased on the way in, because outbound_token_contract_ck accepts one spelling and
      -- custody's allowlist stores that same one. A checksummed contract reaching the database is
      -- a 23514 here rather than a shape_refused after the chain's slot has been claimed.
      ${input.tokenContract?.toLowerCase() ?? null}, ${input.dependsOn ?? null},
      ${input.userId ?? null}, ${input.reservationEntryId ?? null},
      ${input.correlationId ?? null}, ${input.idempotencyKey}
    )
    on conflict (idempotency_key) do nothing
    returning ${sql.unsafe(COLUMNS)}
  `
  const created = inserted[0]
  if (created) return { outbound: toOutbound(created), created: true }

  const existing = await findByIdempotencyKey(sql, input.idempotencyKey)
  if (!existing) {
    // Reachable only if the row was deleted between the insert and the re-read, which nothing in
    // this service does. Loud rather than a null, because a silent null here would look to the
    // caller like a withdrawal that was never planned.
    throw new Error(`outbound transaction ${input.idempotencyKey} conflicted and then vanished`)
  }
  return { outbound: existing, created: false }
}

/* ------------------------------------------------------------------ reads */

export async function findOutbound(sql: Db | Tx, id: string): Promise<OutboundTransaction | null> {
  const rows = await sql<OutboundRow[]>`
    select ${sql.unsafe(COLUMNS)} from outbound_transactions where id = ${id}
  `
  return rows[0] ? toOutbound(rows[0]) : null
}

export async function findByIdempotencyKey(
  sql: Db | Tx,
  key: string,
): Promise<OutboundTransaction | null> {
  const rows = await sql<OutboundRow[]>`
    select ${sql.unsafe(COLUMNS)} from outbound_transactions where idempotency_key = ${key}
  `
  return rows[0] ? toOutbound(rows[0]) : null
}

/**
 * The transaction currently holding this chain's nonce, or null.
 *
 * **This read is not a guard and must never be used as one.** forge-pay's `hasUnsettledOutbound()`
 * is exactly this query, used exactly that way, and it is the defect: it is an UNLOCKED read, so
 * two workers both pass it and both go on to sign. What stops that here is the lease on
 * `chain:network` and the partial unique index underneath it, both of which are held by the
 * database. This is for the worker's own sequencing — "is there something to advance before I plan
 * anything new" — and for the operator surface.
 */
export async function inFlightOnChain(
  sql: Db,
  chain: ChainId,
  network: Network,
): Promise<OutboundTransaction | null> {
  const rows = await sql<OutboundRow[]>`
    select ${sql.unsafe(COLUMNS)} from outbound_transactions
     where chain = ${chain} and network = ${network}
       and state in ('building','signed','broadcast')
     order by created_at
     limit 1
  `
  return rows[0] ? toOutbound(rows[0]) : null
}

/**
 * The next queued transaction on a chain. **Sweeps first, then oldest first.**
 *
 * Oldest-first alone deadlocks, and the deadlock is not hypothetical — it is what a strictly
 * chronological queue does the first time the treasury runs dry. A withdrawal that cannot be funded
 * fails its build transiently and goes back to `planned` KEEPING ITS PLACE, so it is at the head
 * again on the next tick; the sweep behind it is the thing that would fund it, and it never gets the
 * chain. Both sit there until the withdrawal's stuck deadline refunds it, at which point the sweep
 * runs and funds a treasury with nothing left to pay.
 *
 * So a sweep overtakes a withdrawal. It is safe to let it, because the two are not competing for
 * the same money: a sweep BRINGS money to the treasury and a withdrawal spends it, so promoting the
 * sweep can only ever make the withdrawal behind it more likely to succeed. Within a purpose the
 * order is strictly chronological, so nothing overtakes anything it is actually competing with.
 *
 * The frozen estate does not have this problem because its sweeper and its withdrawer are two
 * separate workers with two separate loops — which is also why they can both sign at once. Merging
 * them onto one lease is what buys the invariant, and this ordering is the price.
 */
export async function nextPlanned(
  sql: Db,
  chain: ChainId,
  network: Network,
  /**
   * **EVERY PURPOSE THE WORKER DRIVES, AND ADDING ONE HERE IS NOT OPTIONAL.**
   *
   * A purpose missing from this list is a purpose whose rows are planned and then never offered to
   * anybody — they sit in `planned` for ever, invisible to the worker, indistinguishable from a
   * queue that is merely slow, while the metric that counts them says the work was scheduled. That
   * is exactly what happened to `gas_topup` and `token_sweep` the first time they were added: the
   * pair was written correctly, the schema accepted it, the planner reported `planned`, and nothing
   * ever moved. `deploy` is deliberately still absent — it is driven by its own route, not by the
   * chain tick.
   */
  purposes: readonly OutboundPurpose[] = [
    'withdrawal',
    'sweep',
    'treasury_move',
    'gas_topup',
    'token_sweep',
  ],
): Promise<OutboundTransaction | null> {
  const rows = await sql<OutboundRow[]>`
    select ${sql.unsafe(COLUMNS)} from outbound_transactions o
     where o.chain = ${chain} and o.network = ${network} and o.state = 'planned'
       and o.purpose = any(${sql.array(purposes as string[])}::text[])
       -- ────────────────────────────────────────────────────────────────────────────────────────
       -- A ROW BLOCKED ON ITS DEPENDENCY IS NOT QUEUED, IT IS WAITING.
       --
       -- A token_sweep whose gas_topup has not confirmed cannot be built: the deposit address
       -- still holds no native coin, so the build would fail on the balance check, release back to
       -- planned, and be picked again on the very next tick — a hot loop that costs an RPC round
       -- trip per tick and stops the chain making progress on anything behind it.
       --
       -- state = 'confirmed' and not "anything past broadcast". A broadcast top-up has not moved
       -- the money yet; a node that has accepted the bytes can still drop them. Building against a
       -- balance that is only probably there is the mistake this whole ordering exists to avoid.
       --
       -- The trigger outbound_dependency_confirmed_trg says the same thing to anyone who reaches
       -- a row by another route. This clause is what keeps the worker from having to be refused.
       -- ────────────────────────────────────────────────────────────────────────────────────────
       and (
         o.depends_on is null
         or exists (
           select 1 from outbound_transactions d
            where d.id = o.depends_on and d.state = 'confirmed'
         )
       )
     -- A sweep still overtakes a withdrawal, and a token_sweep is a sweep for this purpose: it
     -- brings money to the treasury rather than spending it, so promoting it can only make the
     -- withdrawal behind it more likely to succeed. A gas_topup deliberately does NOT overtake —
     -- it SPENDS the treasury, so letting it jump a queued withdrawal would take money from the
     -- user who is waiting to fund a sweep that has not happened yet.
     order by (o.purpose in ('sweep','token_sweep')) desc, o.created_at
     limit 1
  `
  return rows[0] ? toOutbound(rows[0]) : null
}

/**
 * Every planned row waiting on a dependency that can never confirm, failed with it.
 *
 * **A CASCADE, IN THE SAME TRANSACTION AS THE FAILURE THAT CAUSED IT.** A `token_sweep` whose
 * `gas_topup` was refunded is a row that can never be built — the trigger refuses it and
 * `nextPlanned` will not offer it — so leaving it `planned` leaves a permanent entry in a queue
 * nothing will ever drain, which is indistinguishable from a sweep that is merely slow.
 *
 * GUARDED ON `state = 'planned'`, and the guard is provably sufficient rather than merely careful.
 * A dependent can only be past `planned` if it was allowed into `building`, which the trigger
 * permits only when its dependency is `confirmed` — and `confirmed` is terminal-success, which
 * `markFailed` cannot reach (its WHERE clause is `planned`/`building`). So there is no ordering in
 * which this could retire a row that has signed something.
 */
async function failDependents(
  tx: Tx,
  producer: string,
  id: string,
  reason: string,
  events: (row: OutboundTransaction) => readonly DomainEvent[],
): Promise<readonly OutboundTransaction[]> {
  const rows = await tx<OutboundRow[]>`
    update outbound_transactions
       set state = 'failed',
           failure_reason = ${`the transaction this one depended on failed: ${reason}`.slice(0, 2_000)},
           updated_at = now()
     where depends_on = ${id} and state = 'planned'
    returning ${tx.unsafe(COLUMNS)}
  `
  const failed = rows.map(toOutbound)
  for (const row of failed) await emitInto(tx, producer, events(row))
  return failed
}

/** Every `(chain, network)` with open work, so the tick job knows which leases to ask for. */
export async function chainsWithWork(
  sql: Db,
): Promise<ReadonlyArray<{ readonly chain: ChainId; readonly network: Network }>> {
  const rows = await sql<Array<{ chain: string; network: string }>>`
    select distinct chain, network from outbound_transactions
     where state in ('planned','building','signed','broadcast')
  `
  return rows.map((r) => ({ chain: r.chain as ChainId, network: r.network as Network }))
}

export async function listByState(
  sql: Db,
  state: OutboundState,
  limit: number,
): Promise<readonly OutboundTransaction[]> {
  const rows = await sql<OutboundRow[]>`
    select ${sql.unsafe(COLUMNS)} from outbound_transactions
     where state = ${state} order by updated_at desc limit ${limit}
  `
  return rows.map(toOutbound)
}

export async function findBySource(
  sql: Db,
  sourceRef: string,
): Promise<readonly OutboundTransaction[]> {
  const rows = await sql<OutboundRow[]>`
    select ${sql.unsafe(COLUMNS)} from outbound_transactions
     where source_ref = ${sourceRef} order by created_at
  `
  return rows.map(toOutbound)
}

/* ------------------------------------------------------------------ transitions */

/**
 * A unique-violation on the in-flight index, told apart from every other database error.
 *
 * 23505 on `outbound_in_flight_uniq` means another transaction on this chain reached `building`
 * first. It is the last line of the defence, it fires only when the lease has already failed, and
 * it must be caught rather than propagated — the correct response is "not my turn", not an alarm.
 */
function isInFlightConflict(err: unknown): boolean {
  const e = err as { code?: unknown; constraint_name?: unknown }
  return e?.code === '23505' && e?.constraint_name === 'outbound_in_flight_uniq'
}

/**
 * Take a `planned` row to `building`: the claim on this chain's nonce.
 *
 * False means somebody else has it. Two ways that happens and both are ordinary:
 *
 *   1. The conditional UPDATE matched no row, because the state has already moved.
 *   2. The partial unique index refused, because another transaction on this chain is in flight.
 *      **This is the moment the whole design turns on.** With the lease working it cannot happen;
 *      without the index it would not be caught at all, and the second worker would go on to read
 *      the same nonce and ask custody for a second signature against it.
 */
export async function claimForBuilding(sql: Db, id: string): Promise<boolean> {
  try {
    const rows = await sql<Array<{ id: string }>>`
      update outbound_transactions
         set state = 'building', updated_at = now()
       where id = ${id} and state = 'planned'
      returning id
    `
    return rows.length > 0
  } catch (err) {
    if (isInFlightConflict(err)) return false
    throw err
  }
}

/**
 * Give a `building` row back to the queue, having signed nothing.
 *
 * Necessary rather than tidy: `building` is in the in-flight set, so a row abandoned there holds
 * the partial unique index and blocks every other payment on that chain until a human notices. A
 * transient build failure — an unreachable node, a treasury that cannot cover it yet — must
 * therefore put the row back, and only a PERMANENT failure calls `markFailed`.
 */
export async function releaseToPlanned(sql: Db, id: string): Promise<boolean> {
  const rows = await sql<Array<{ id: string }>>`
    update outbound_transactions
       set state = 'planned', updated_at = now()
     where id = ${id} and state = 'building'
    returning id
  `
  return rows.length > 0
}

export interface SignedBytes {
  readonly rawTx: string
  readonly txHash: string | null
  readonly nonce: string | null
  readonly expiry: string | null
  readonly custodyAuditId: string | null
}

/**
 * **THE COMMIT.** Write the signed bytes, before anything is broadcast.
 *
 * Conditional on `building`, so a signature made by a worker that has since lost its claim is
 * discarded UNBROADCAST — which is exactly why it was safe to have made it at all: nothing was
 * sent, so nothing moved, and the next tick builds again from a fresh nonce read.
 *
 * Everything after this point is recoverable. A crash here leaves a `signed` row with `raw_tx`
 * populated and no `broadcast_at`, and the next tick RESUMES AT BROADCAST rather than re-signing —
 * `advance` below has no path from `signed` back to `building`.
 */
export async function markSigned(sql: Db, id: string, bytes: SignedBytes): Promise<boolean> {
  const rows = await sql<Array<{ id: string }>>`
    update outbound_transactions
       set state = 'signed',
           raw_tx = ${bytes.rawTx},
           tx_hash = coalesce(${bytes.txHash}, tx_hash),
           signed_nonce = ${bytes.nonce},
           signed_expiry = ${bytes.expiry},
           custody_audit_id = ${bytes.custodyAuditId},
           signed_at = now(),
           updated_at = now()
     where id = ${id} and state = 'building'
    returning id
  `
  return rows.length > 0
}

/**
 * Record that the bytes went on the wire.
 *
 * Accepts `broadcast` as well as `signed` so a re-send that discovers a new hash — or a status
 * lookup that finds the transaction on chain when the row still said `signed` — settles the row
 * rather than being refused for being out of order. `broadcast_at` is set once and only once,
 * because it is the clock the stuck deadline runs from and re-stamping it would push the deadline
 * out for ever, which is the exact bug the frozen sweeper's `advanceSweep` carries a paragraph
 * about.
 */
export async function markBroadcast(sql: Db, id: string, txHash: string): Promise<boolean> {
  const rows = await sql<Array<{ id: string }>>`
    update outbound_transactions
       set state = 'broadcast',
           tx_hash = ${txHash},
           broadcast_at = coalesce(broadcast_at, now()),
           updated_at = now()
     where id = ${id} and state in ('signed','broadcast')
    returning id
  `
  return rows.length > 0
}

/**
 * Record depth without changing state.
 *
 * Only when it actually changes something. Touching `updated_at` on every tick is how the frozen
 * sweeper's stuck deadline used to be pushed out by one poll interval for ever, so a broadcast
 * transaction that never confirmed could never be marked stuck — precisely the case the deadline
 * exists to catch.
 */
export async function markConfirmations(
  sql: Db,
  id: string,
  confirmations: number,
  minedHeight: bigint | null,
): Promise<void> {
  await sql`
    update outbound_transactions
       set confirmations = ${confirmations},
           mined_height = coalesce(${minedHeight === null ? null : minedHeight.toString()}, mined_height),
           updated_at = now()
     where id = ${id}
       and (confirmations is distinct from ${confirmations}
            or mined_height is distinct from ${minedHeight === null ? null : minedHeight.toString()})
  `
}

/** Terminal success, with its events in the same transaction. Only from `signed` or `broadcast`. */
export async function markConfirmed(
  sql: Db,
  producer: string,
  id: string,
  confirmations: number,
  events: (row: OutboundTransaction) => readonly DomainEvent[],
): Promise<OutboundTransaction | null> {
  const outcome = await sql.begin(async (tx) => {
    const rows = await tx<OutboundRow[]>`
      update outbound_transactions
         set state = 'confirmed',
             confirmations = ${confirmations},
             confirmed_at = now(),
             updated_at = now()
       where id = ${id} and state in ('signed','broadcast')
      returning ${tx.unsafe(COLUMNS)}
    `
    const row = rows[0]
    if (!row) return { value: null }
    const confirmed = toOutbound(row)
    await emitInto(tx, producer, events(confirmed))
    return { value: confirmed }
  })
  return outcome.value
}

/**
 * Terminal failure, and **the only path that ever declares money refundable.**
 *
 * Guarded on `planned` and `building` in the WHERE clause rather than by a check at the call site,
 * so the guarantee is the database's: a `signed` row cannot reach this function's effect however it
 * is called. Nothing was signed on either state — the signature is made and committed after the
 * build, and a signature made and not committed is discarded unbroadcast — so the money going back
 * is safe.
 */
export async function markFailed(
  sql: Db,
  producer: string,
  id: string,
  reason: string,
  events: (row: OutboundTransaction) => readonly DomainEvent[],
): Promise<OutboundTransaction | null> {
  const outcome = await sql.begin(async (tx) => {
    const rows = await tx<OutboundRow[]>`
      update outbound_transactions
         set state = 'failed', failure_reason = ${reason.slice(0, 2_000)}, updated_at = now()
       where id = ${id} and state in ('planned','building')
      returning ${tx.unsafe(COLUMNS)}
    `
    const row = rows[0]
    if (!row) return { value: null }
    const failed = toOutbound(row)
    await emitInto(tx, producer, events(failed))
    // In the SAME transaction, so a crash cannot leave a dead dependency and a live dependent.
    await failDependents(tx, producer, failed.id, reason, events)
    return { value: failed }
  })
  return outcome.value
}

/**
 * A signed payment that needs a human.
 *
 * Guarded on `signed` and `broadcast`, and a call for a `planned` row is a SILENT NO-OP returning
 * null. That is deliberate and it is load-bearing: `stuck` means "bytes exist and may still land",
 * and if a `planned` row could reach it the state would come to mean "something went wrong", at
 * which point the adjudication path — which refuses to refund a `stuck` row without positive proof
 * — would be refusing to refund transactions that never signed anything.
 *
 * **Nothing here is refundable.** The event carries `refundable: false`, and it is the caller's
 * business to page somebody.
 */
export async function markStuck(
  sql: Db,
  producer: string,
  id: string,
  reason: string,
  events: (row: OutboundTransaction) => readonly DomainEvent[],
): Promise<OutboundTransaction | null> {
  const outcome = await sql.begin(async (tx) => {
    const rows = await tx<OutboundRow[]>`
      update outbound_transactions
         set state = 'stuck', failure_reason = ${reason.slice(0, 2_000)}, updated_at = now()
       where id = ${id} and state in ('signed','broadcast')
      returning ${tx.unsafe(COLUMNS)}
    `
    const row = rows[0]
    if (!row) return { value: null }
    const stuck = toOutbound(row)
    await emitInto(tx, producer, events(stuck))
    return { value: stuck }
  })
  return outcome.value
}

/**
 * **THE ONLY FUNCTION IN THIS SERVICE THAT CAN REFUND A SIGNED TRANSACTION, AND IT TAKES A PROOF.**
 *
 * There is deliberately no other. `markFailed` cannot reach a `signed` row — its WHERE clause
 * excludes it — so every path by which money goes back after a signature exists runs through here,
 * and every one of them has to hand over a sentence saying why the bytes can never apply. The proof
 * is not decoration and it is not a log line: it is written to `outbound_adjudications` in the SAME
 * transaction that moves the state, so the record that a signed payment was refunded is inseparable
 * from the evidence that made it safe.
 *
 * Two callers, and they differ only in where the proof came from:
 *
 *   * `worker.ts`, when the chain itself reports the transaction as applied-and-failed. That is the
 *     one machine-readable proof there is, and it is why a reverted payment does not need an
 *     operator.
 *   * `adjudicate.ts`, when an operator asks and `OutboundChain.proveDead` agrees. Anything the
 *     chain will not positively assert is refused, and the refusal is recorded too.
 *
 * `fromStates` is a parameter rather than a constant because the two callers legitimately act on
 * different states — the automatic one on a live `signed`/`broadcast` row, the operator on a `stuck`
 * one — and collapsing them would let the operator route refund a transaction that had not yet been
 * given its full deadline to land.
 */
export async function resolveWithProof(
  sql: Db,
  producer: string,
  input: {
    readonly id: string
    readonly action: 'refund' | 'confirm'
    readonly proof: string
    readonly actor: string
    readonly correlationId: string | null
    readonly fromStates: readonly OutboundState[]
    readonly events: (row: OutboundTransaction) => readonly DomainEvent[]
  },
): Promise<OutboundTransaction | null> {
  const nextState = input.action === 'refund' ? 'failed' : 'confirmed'
  const outcome = await sql.begin(async (tx) => {
    const rows = await tx<OutboundRow[]>`
      update outbound_transactions
         set state = ${nextState},
             failure_reason = ${input.action === 'refund' ? input.proof.slice(0, 2_000) : null},
             confirmed_at = ${input.action === 'confirm' ? new Date() : null},
             updated_at = now()
       where id = ${input.id}
         and state = any(${tx.array(input.fromStates as string[])}::text[])
      returning ${tx.unsafe(COLUMNS)}
    `
    const row = rows[0]
    if (!row) return { value: null }
    const resolved = toOutbound(row)
    await tx`
      insert into outbound_adjudications (outbound_id, action, proof, actor, correlation_id)
      values (${resolved.id}, ${input.action}, ${input.proof}, ${input.actor}, ${input.correlationId})
    `
    await emitInto(tx, producer, input.events(resolved))
    if (input.action === 'refund') {
      // The other route to `failed`, and it needs the same cascade for the same reason. A refunded
      // gas top-up leaves its token sweep waiting on a dependency that will never confirm, and the
      // adjudication path is the one an OPERATOR drives — so an orphan created here is one somebody
      // is already looking at a screen for.
      await failDependents(tx, producer, resolved.id, input.proof, input.events)
    }
    return { value: resolved }
  })
  return outcome.value
}

/** Record a refusal to adjudicate. The row is untouched; only the attempt is written down. */
export async function recordRefusal(
  sql: Db,
  input: {
    readonly id: string
    readonly code: string
    readonly reason: string
    readonly actor: string
    readonly correlationId: string | null
  },
): Promise<void> {
  await sql`
    insert into outbound_adjudications (outbound_id, action, refusal_code, proof, actor, correlation_id)
    values (${input.id}, 'refused', ${input.code}, ${input.reason}, ${input.actor}, ${input.correlationId})
  `
}

/* ------------------------------------------------------------------ the clock */

/**
 * Has this been unresolved for longer than an operator agreed to wait?
 *
 * Dated from the broadcast where there was one and from creation otherwise, so the clock a queued
 * row is measured against is the one the USER has been waiting on. Takes `now` because it is the
 * deadline every giving-up decision in this service is made against, and a test has to be able to
 * stand on both sides of it.
 */
export function stuckDeadlinePassed(
  row: Pick<OutboundTransaction, 'broadcastAt' | 'createdAt'>,
  stuckMinutes: number,
  now: number = Date.now(),
): boolean {
  const since = (row.broadcastAt ?? row.createdAt).getTime()
  return now - since > Math.max(1, stuckMinutes) * 60_000
}

/* ------------------------------------------------------------------ asking the chain */

export interface OutboundDeps {
  readonly sql: Db
  readonly producer: string
  readonly network: Network
  readonly custody: CustodyClient
  readonly indexer: IndexerClient
  readonly rpc: (chain: ChainId) => JsonRpc
  readonly bounds: FeeBounds
  readonly stuckMinutes: number
  readonly logger: Logger
  readonly now?: () => number
}

export function callFor(deps: OutboundDeps, chain: ChainId): ChainCall {
  return { network: deps.network, rpc: deps.rpc(chain) }
}

/**
 * Where has this transaction got to? **The indexer when it has it, the node when it does not.**
 *
 * The indexer is the estate's declared reader of chain state and it applies the same
 * `contracts-chain` depths this service does, so where it has an answer that answer wins. But it is
 * a FOLLOWER — its worker walks blocks — so a transaction broadcast four seconds ago is not in it
 * yet, and reading that absence as "not on chain" would mark every fresh broadcast unknown,
 * re-send it every tick, and declare a perfectly healthy payment stuck an hour later.
 *
 * An indexer that is DOWN falls through to the node too, and that is the right failure: the node is
 * a weaker source (one view, no reorg history) but it is a source, and the alternative is a service
 * that cannot settle a single payment while the indexer is redeploying.
 */
export async function chainStatusOf(
  deps: OutboundDeps,
  row: Pick<OutboundTransaction, 'chain' | 'network' | 'txHash' | 'rawTx' | 'assetCode'>,
): Promise<OutboundStatus> {
  const adapter = chainFor(row.chain)
  // The DERIVED id first: it is the one that exists when the row's does not, which is exactly the
  // case a crash between broadcasting and recording the hash produces.
  const hash = (row.rawTx ? adapter.txIdOf(row.rawTx) : null) ?? row.txHash
  if (!hash) return { kind: 'unknown' }

  try {
    const indexed = await deps.indexer.transaction(row.chain, row.network, hash)
    if (indexed) return fromIndexer(indexed, row.assetCode)
  } catch (err) {
    deps.logger.warn('the indexer could not be asked about an outbound transaction', {
      chain: row.chain,
      hash,
      err,
    })
  }
  return adapter.status(callFor(deps, row.chain), hash)
}

/**
 * The indexer's normalised vocabulary, mapped onto this service's.
 *
 * `dropped` and `orphaned` both become `unknown` rather than `rejected`, and the difference matters
 * enormously: `rejected` is the one state in which a SIGNED transaction may be refunded without an
 * operator, so it must mean "the chain applied this and it did not deliver" and nothing weaker. A
 * dropped transaction is one no node currently holds — the bytes are untouched and any node can
 * still mine them. An orphaned one was in a block that a reorg removed, so it is very likely back
 * in a mempool. Both mean "re-send the same bytes", which is what `unknown` produces.
 */
function fromIndexer(
  indexed: { readonly status: string; readonly confirmations: number | null; readonly blockHeight: number | null },
  assetCode: string,
): OutboundStatus {
  const height = indexed.blockHeight === null ? 0n : BigInt(indexed.blockHeight)
  switch (indexed.status) {
    case 'failed':
      return {
        kind: 'rejected',
        reason: 'the chain applied this transaction and it failed, so nothing was transferred',
      }
    case 'success': {
      // Null confirmations is NOT zero: it means the indexer knows the transaction and cannot
      // currently say how deep it is, which happens while a tip is being re-read after a reorg.
      // Treating it as zero would reset the depth of a payment that is already final.
      if (indexed.confirmations === null) return { kind: 'pending', confirmations: 0, minedHeight: height }
      const depth = chainSpec(assetCode as never).confirmations
      return indexed.confirmations >= depth
        ? { kind: 'confirmed', confirmations: indexed.confirmations, minedHeight: height }
        : { kind: 'pending', confirmations: indexed.confirmations, minedHeight: height }
    }
    case 'pending':
      return { kind: 'pending', confirmations: indexed.confirmations ?? 0, minedHeight: height }
    default:
      return { kind: 'unknown' }
  }
}

/** The confirmation depth this asset is final at. Read from contracts-chain, never restated. */
export function requiredDepth(chain: ChainId): number {
  return chainSpec(assetOf(chain)).confirmations
}
