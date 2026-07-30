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
 * is the same number on both sides: the platform's fee EXPENSE increases by what was burned, and the
 * custody treasury ASSET decreases by the same.
 *
 * **Its failure is never fatal to the transaction.** The payment is on chain whatever the ledger
 * says, and a service that could not mark a confirmed payment confirmed because a bookkeeping entry
 * failed would re-broadcast it and eventually call it stuck — a bookkeeping outage would become a
 * money outage. So the entry is a backlog job over `ledger_entry_id is null`, and it carries an
 * idempotency key derived from the transaction id, so a retry that lands twice posts once.
 */

import type { Logger } from '@cloudsforge/telemetry'
import type { LedgerAssetCode } from '@cloudsforge/contracts-money'
import type { LedgerClient } from './ledgerclient.ts'
import type { Db } from './outbox.ts'
import type { OutboundTransaction } from './outbound.ts'

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
        account: { subject: 'platform', assetCode, purpose: 'fees', type: 'expense' },
      },
      {
        direction: 'credit',
        amount: fee,
        assetCode,
        sequence: 2,
        account: { subject: 'custody', assetCode, purpose: 'treasury', type: 'asset' },
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
