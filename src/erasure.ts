/**
 * `identity.user.deleted` — right to erasure, settlement's half.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * WHAT THIS SERVICE HELD, AND WHAT HAPPENS TO EACH OF IT
 *
 * This service is the one place in the estate where erasure meets a ledger nobody controls. Every
 * row below is about coin that has moved, or is moving, on a PUBLIC CHAIN — and a chain cannot be
 * made to forget. Deleting a row here does not un-publish anything; it deletes the platform's own
 * record of an irreversible movement while the movement itself stays in public view. So the shape
 * of the answer is: the record survives, the person's identifier does not, and where even the
 * identifier has to survive the reason is named rather than asserted.
 *
 * | table                  | action              | reasoning + lawful basis if retained            |
 * |------------------------|---------------------|------------------------------------------------|
 * | outbound_transactions  | retain, `user_id`   | THE RECORD THAT A WITHDRAWAL WAS AUTHORISED.    |
 * |                        | nulled + marked     | `raw_tx` holds the exact signed bytes that were |
 * |                        |                     | broadcast; `tx_hash` names them on chain. This  |
 * |                        |                     | is also the evidence in the one dispute that    |
 * |                        |                     | matters — "I never authorised that withdrawal". |
 * |                        |                     | Retention basis for the ROW: **Art 17(3)(b)**   |
 * |                        |                     | (AML/CTF transaction record-keeping on a        |
 * |                        |                     | custodied outbound payment) and **Art 17(3)(e)**|
 * |                        |                     | (establishment, exercise or defence of legal    |
 * |                        |                     | claims). Neither basis reaches `user_id`, so it |
 * |                        |                     | goes: **nothing about the money depends on it.**|
 * |                        |                     | Wallet settles its reservation by               |
 * |                        |                     | `reservation_entry_id` and `source_ref`, and no |
 * |                        |                     | consumer of `settlement.withdrawal.completed`   |
 * |                        |                     | moves money on the strength of the user id —    |
 * |                        |                     | the three that read it (activity, analytics,    |
 * |                        |                     | notify) all use it for attribution and for      |
 * |                        |                     | telling somebody. For a deleted account there   |
 * |                        |                     | is nobody to tell, and `withdrawals.ts:544`     |
 * |                        |                     | already calls a null userId "unreachable", the  |
 * |                        |                     | value those consumers already tolerate.         |
 * |                        |                     | `to_address` is KEPT: it is inside `raw_tx` and |
 * |                        |                     | on the public chain either way, and it is what  |
 * |                        |                     | proves the payment went where it was authorised |
 * |                        |                     | to go. Erasing it from here would remove only   |
 * |                        |                     | the platform's ability to answer for itself.    |
 * |------------------------|---------------------|------------------------------------------------|
 * | sweep_sources          | retain WHOLE,       | The deposit address assigned to the person, and |
 * |                        | marked erased       | `custody_user_id` IS their id — wallet mints it |
 * |                        |                     | with `userId: input.userId`. It is kept, and    |
 * |                        |                     | this is the one place here where an identifier  |
 * |                        |                     | itself survives, for a reason that is not about |
 * |                        |                     | records at all: **custody compares the binding  |
 * |                        |                     | character for character before it will sign**   |
 * |                        |                     | (custody/src/gates.ts:182). A sweep restates    |
 * |                        |                     | `custody_user_id` and `custody_order_id` or it  |
 * |                        |                     | is refused, and the refusal does not say which  |
 * |                        |                     | field disagreed. Null either one and every coin |
 * |                        |                     | at that address is STRANDED FOR EVER, including |
 * |                        |                     | coin that arrives after the deletion — an       |
 * |                        |                     | erasure that permanently confiscates money is   |
 * |                        |                     | not a better outcome for the person than the    |
 * |                        |                     | one it replaces. `swept` compounds it: it is a  |
 * |                        |                     | monotonic high-water mark, so a deleted row     |
 * |                        |                     | restarts it at zero and the next pass pays a    |
 * |                        |                     | fee to re-sweep what has already moved.         |
 * |                        |                     | Basis: **Art 17(3)(b)** — AML/CTF source-of-    |
 * |                        |                     | funds record-keeping on custodied deposits.     |
 * |                        |                     | The row is marked so the retention clock has an |
 * |                        |                     | anchor and so a sweep of these rows, once the   |
 * |                        |                     | statutory period is up, is a `where` clause     |
 * |                        |                     | rather than an archaeology exercise.            |
 * |                        |                     | **This is the residual gap, stated plainly:**   |
 * |                        |                     | there is no job that deletes them at the end of |
 * |                        |                     | that period yet, and until there is, this row   |
 * |                        |                     | is retained indefinitely.                       |
 * |------------------------|---------------------|------------------------------------------------|
 * | treasuries             | NO ACTION —         | **The issue said this table holds an owner      |
 * |                        | not personal data   | reference (migrations.ts:126). It does not.**   |
 * |                        |                     | Its `custody_user_id` is the literal            |
 * |                        |                     | `'cloudsforge:treasury'` (src/treasury.ts:58) — |
 * |                        |                     | the platform's own custody account for the      |
 * |                        |                     | platform's own address. One address per         |
 * |                        |                     | (chain, network), belonging to nobody. Recorded |
 * |                        |                     | here so the correction survives the next survey.|
 * |------------------------|---------------------|------------------------------------------------|
 * | outbound_adjudications | untouched           | `actor` is the OPERATOR who decided a stuck     |
 * |                        |                     | transaction, not the person it belonged to. It  |
 * |                        |                     | is staff data on a staff decision, and deleting |
 * |                        |                     | it on a user's request would erase the audit of |
 * |                        |                     | somebody else's action.                         |
 * |------------------------|---------------------|------------------------------------------------|
 * | inbox, outbox,         | untouched           | Delivery machinery. `outbox.payload` can name a |
 * | outbox_deliveries,     |                     | user in a published event, which is a real      |
 * | event_subscriptions    |                     | residual — see below.                           |
 *
 * ── WHAT REMAINS, HONESTLY ─────────────────────────────────────────────────────────────────────
 *
 * Two things, and neither is hidden by this handler.
 *
 * 1. `outbox.payload` holds the events this service has already published, some of which carry a
 *    `userId`. They are not rewritten here: an outbox row is a record of what WAS SENT, and
 *    editing it would make the local copy disagree with what every subscriber received. The
 *    subscribers erase on their own subscription to this same topic, which is the design; the
 *    local copies need an outbox retention sweep, which this service does not have.
 * 2. `sweep_sources` keeps a real identifier, for the reason in the table above. Marked, not
 *    forgotten.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { Tx } from './outbox.ts'

/** The topic. Registered in `@cloudsforge/contracts-events` as keyed by `user_id`. */
export const IDENTITY_USER_DELETED = 'identity.user.deleted'

/** A uuid, and nothing else. The one shape identity keys this topic by. */
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export interface ErasureCounts {
  readonly outbound: number
  readonly sweepSources: number
  /** Of `outbound`, how many had not reached a terminal state. Reported, never used to skip work. */
  readonly outboundInFlight: number
}

/**
 * The two spellings of one person, and why both are matched.
 *
 * The event payload carries a BARE UUID (`identity/src/deletion.ts:113-125`), and that is also how
 * this service stores it: `outbound_transactions.user_id` comes straight off wallet's withdrawal
 * event, and `sweep_sources.custody_user_id` is the value custody was minted with. So the bare form
 * is the live one here — unlike billing, policy and the other ledger-facing services, which store
 * the LEDGER SPELLING `user:<uuid>` because a grant and the entry that paid for it must name their
 * holder identically.
 *
 * Both forms are matched anyway, and deliberately. This service is one register call away from
 * holding the other spelling — `POST /v1/sweep-sources` takes `custodyUserId` as an opaque string
 * from whatever calls it — and an erasure that silently skips a row because a caller sent the other
 * form would report success while leaving the data in place, which is the exact defect being fixed.
 */
export function userIdForms(userId: string): readonly string[] {
  return [userId, `user:${userId}`]
}

/**
 * When the erasure is anchored.
 *
 * The event carries `tombstoneAt` so a subscriber knows its deadline without having to know
 * identity's configuration (`identity/src/deletion.ts`). It is used as the mark rather than
 * `now()` because the retention clock this starts is the one an auditor will check against the
 * deletion request, not against the moment a relay happened to deliver. An absent or unparseable
 * value falls back to the current time — never to a null, which would make the row indistinguishable
 * from one that was never erased.
 */
export function erasureInstant(tombstoneAt: unknown, now: Date = new Date()): Date {
  if (typeof tombstoneAt !== 'string' || tombstoneAt.length === 0) return now
  const parsed = new Date(tombstoneAt)
  return Number.isNaN(parsed.getTime()) ? now : parsed
}

/**
 * Erase one user, inside the caller's transaction.
 *
 * In-flight transactions are erased too, not deferred. A withdrawal that is still `planned`,
 * `signed` or `broadcast` continues exactly as it was — the signed bytes, the nonce, the
 * reservation and the source reference are all untouched, and none of the settlement path reads
 * `user_id`. Deferring instead would mean holding the person's identifier until a chain confirms,
 * which is an unbounded delay decided by a third party, and it would need a job to finish the work
 * later: a second place for the erasure to be forgotten.
 */
export async function eraseUser(tx: Tx, userId: string, at: Date): Promise<ErasureCounts> {
  const forms = userIdForms(userId)

  // Counted before the update, because afterwards there is nothing left to count it by. Reported
  // so an operator can see that a deletion landed while money was still in flight; it changes
  // nothing about the payment, and it is the sort of thing that should never be a surprise.
  const inFlight = await tx<{ n: number }[]>`
    select count(*)::int as n
      from outbound_transactions
     where user_id = any(${forms})
       and state not in ('confirmed', 'failed')
  `

  const outbound = await tx`
    update outbound_transactions
       set user_id    = null,
           erased_at  = ${at},
           updated_at = now()
     where user_id = any(${forms})
    returning id
  `

  // Marked, not stripped. The custody binding is what makes the address sweepable at all — see the
  // header. `active` is deliberately left alone: a deposit address whose owner has gone must still
  // be swept, or the coin sitting at it is confiscated by inaction.
  const sweepSources = await tx`
    update sweep_sources
       set erased_at  = ${at},
           updated_at = now()
     where custody_user_id = any(${forms})
       and erased_at is null
    returning id
  `

  return {
    outbound: outbound.length,
    sweepSources: sweepSources.length,
    outboundInFlight: inFlight[0]?.n ?? 0,
  }
}
