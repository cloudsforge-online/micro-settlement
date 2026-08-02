/**
 * The network fee, as bookkeeping.
 *
 * Every confirmed outbound transaction burned a fee the platform absorbed, out of an address the
 * platform controls. 04-domain-model §11 — "no 'user balance' column anywhere outside the ledger's
 * projection" — applies to the platform's own money as much as to a user's, and forge-pay records
 * this nowhere at all: the treasury's balance goes down and no entry anywhere says why, so a
 * reconciliation between the chain and the books has nothing to reconcile against.
 *
 * One entry per confirmed transaction, `treasury_spend`, and it balances by construction because it
 * is the same number on both sides: the platform's EXPENSE increases by what was burned, and the
 * custody ASSET decreases by the same.
 *
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 * **BOTH ACCOUNTS MOVED, AND UNTIL THEY DID NOT ONE OF THESE ENTRIES COULD EVER HAVE POSTED.**
 *
 * The ledger keys an account on `(subject, asset_code, purpose)` and NOTHING else.
 *
 *   1. The debit was `(platform, <asset>, fees)` as type `expense`. `micro-billing`,
 *      `micro-market`, `micro-mint`, `micro-trade` and `micro-wallet` all name that SAME key as
 *      type `revenue` (market/src/ledgerclient.ts:123, wallet/src/money.ts:145), and
 *      `micro-foresight` names `(platform, EMBER, fees)` `revenue` too
 *      (foresight/src/ledgerclient.ts:116). `ensureAccount` THROWS `AccountConflictError` when a
 *      caller's stated type disagrees with the row that already exists
 *      (ledger/src/accounts.ts:125) — so whichever service posted second would have had EVERY
 *      entry refused, for as long as the disagreement stood. No suite caught it because each
 *      service tests against its own fake ledger.
 *
 *      `revenue` is the correct reading and this service's `expense` was the wrong one:
 *      `micro-ledger` states the chart for the `platform` subject in its own source — "`platform`
 *      is revenue under `fees`, equity under `treasury` and expense under `payout_due`"
 *      (ledger/src/accounts.ts:16-17) — and `normalBalance` makes `revenue` credit-normal, the
 *      direction six services already credit fee income in.
 *
 *      But merely RETYPING this posting to `revenue` would have swapped one production breakage
 *      for another. A burned gas fee is not negative fee income, and debiting a credit-normal
 *      account drives it below zero: `ledger_assert_no_overdraft` exempts `clearing`, `suspense`
 *      and an explicit `overdraft_allowed`, and NOT `revenue`, so the first BTC fee — an asset
 *      nothing in the estate credits fee revenue in at all — would have been refused by the
 *      trigger instead of by the type check. So the debit moved to the chart's own platform
 *      expense account, `(platform, <asset>, payout_due)`. `expense` is debit-normal, so it grows
 *      with every fee and can never go negative. `payout_due` under a `user:` subject is a
 *      seller's liability in `micro-market` and a different account entirely: the subject is part
 *      of the key.
 *
 *   2. The credit was `(custody, <asset>, treasury)`. Nothing in the estate has ever DEBITED that
 *      account — `micro-wallet` books every deposit and every settled withdrawal against
 *      `(custody, <asset>, available)` (wallet/src/deposits.ts:627, wallet/src/withdrawals.ts:564)
 *      — so its balance is 0, and crediting an `asset` (debit-normal) account with a zero balance
 *      takes it negative and `ledger_assert_no_overdraft` refuses the entry. The fee was burned
 *      out of the coin custody actually holds, so it is that pool which goes down. Same type,
 *      same subject, and reconciliation sums custody `asset` accounts across purposes either way
 *      (ledger/src/reconcile.ts, `totalFor`) — but only one of the two is a pool with a balance in
 *      it.
 * ════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **Its failure is never fatal to the transaction.** The payment is on chain whatever the ledger
 * says, and a service that could not mark a confirmed payment confirmed because a bookkeeping entry
 * failed would re-broadcast it and eventually call it stuck — a bookkeeping outage would become a
 * money outage. So the entry is a backlog job over `ledger_entry_id is null`, and it carries an
 * idempotency key derived from the transaction id, so a retry that lands twice posts once.
 */

import type { Logger } from '@cloudsforge/telemetry'
import type { LedgerAssetCode } from '@cloudsforge/contracts-money'
import type { AccountRef, LedgerClient } from './ledgerclient.ts'
import type { Db } from './outbox.ts'
import type { OutboundTransaction } from './outbound.ts'

/**
 * The platform's own expense line — the chart's `expense` slot for the `platform` subject, named
 * by `micro-ledger` itself (ledger/src/accounts.ts:16-17). Exported so the suite can assert the
 * key rather than re-spell it: a second spelling is a second account, and the whole defect this
 * replaces was two services spelling one key two ways.
 *
 * NOT `(platform, <asset>, fees)`. That key is the platform's fee REVENUE and six other services
 * already own it as such; see the block comment at the head of this file.
 */
export function feeExpenseAccount(assetCode: LedgerAssetCode): AccountRef {
  return { subject: 'platform', assetCode, purpose: 'payout_due', type: 'expense' }
}

/**
 * What custody holds, as `micro-wallet` maintains it — `(custody, <asset>, available)`
 * (wallet/src/deposits.ts:627). The pool a burned network fee actually came out of.
 */
export function custodyAccount(assetCode: LedgerAssetCode): AccountRef {
  return { subject: 'custody', assetCode, purpose: 'available', type: 'asset' }
}

export interface FeeDeps {
  readonly sql: Db
  readonly ledger: LedgerClient
  readonly logger: Logger
  readonly producer: string
}

interface UnbookedRow {
  readonly id: string
  readonly chain: string
  readonly asset_code: string
  readonly fee: string
  readonly tx_hash: string | null
  readonly correlation_id: string | null
}

/** Confirmed transactions whose fee has not been journalled yet. Bounded per pass. */
export async function unbookedFees(sql: Db, limit: number): Promise<readonly UnbookedRow[]> {
  return sql<UnbookedRow[]>`
    select id, chain, asset_code, fee::text as fee, tx_hash, correlation_id
      from outbound_transactions
     where state = 'confirmed' and ledger_entry_id is null and fee > 0
     order by confirmed_at
     limit ${limit}
  `
}

/**
 * Journal one transaction's network fee.
 *
 * Idempotent twice over, and both are needed. The idempotency key means the LEDGER posts once
 * however many times this is called; the conditional update means this service records the entry id
 * once, so a replayed post does not overwrite a different entry's id onto the row.
 */
export async function bookFee(
  deps: FeeDeps,
  row: Pick<UnbookedRow, 'id' | 'asset_code' | 'fee' | 'tx_hash' | 'correlation_id'>,
): Promise<boolean> {
  const fee = BigInt(row.fee)
  if (fee <= 0n) return false
  const assetCode = row.asset_code as LedgerAssetCode
  const entry = await deps.ledger.postEntry({
    kind: 'treasury_spend',
    actor: `service:${deps.producer}`,
    correlationId: row.correlation_id ?? row.id,
    // Derived from the row id, so a retry after a lost response replays rather than double-posts.
    idempotencyKey: `settlement:fee:${row.id}`,
    description: `network fee for outbound transaction ${row.id}${row.tx_hash ? ` (${row.tx_hash})` : ''}`,
    postings: [
      {
        direction: 'debit',
        amount: fee,
        assetCode,
        sequence: 1,
        account: feeExpenseAccount(assetCode),
      },
      {
        direction: 'credit',
        amount: fee,
        assetCode,
        sequence: 2,
        account: custodyAccount(assetCode),
      },
    ],
  })
  const updated = await deps.sql<Array<{ id: string }>>`
    update outbound_transactions
       set ledger_entry_id = ${entry.id}, updated_at = now()
     where id = ${row.id} and ledger_entry_id is null
    returning id
  `
  return updated.length > 0
}

/** What the operator surface reports about a transaction's bookkeeping. */
export function isBooked(row: OutboundTransaction): boolean {
  return row.fee === 0n || row.ledgerEntryId !== null
}
