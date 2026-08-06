/**
 * The two accounts a network-fee entry names.
 *
 * Pure, and deliberately separate from the job that writes it: what is worth pinning is the
 * ACCOUNT KEY and its TYPE. The ledger keys an account on `(subject, asset_code, purpose)` and
 * refuses an entry whose stated type disagrees with the row that already exists
 * (ledger/src/accounts.ts, `AccountConflictError`) — and that refusal is not per-entry, it is
 * every entry from whichever service posted second, for as long as the disagreement stands.
 *
 * It is invisible to every suite in the estate because each service tests against its own fake
 * ledger, so nothing in CI ever puts two real services against one real ledger. This file is the
 * closest a single repository can get: it asserts what THIS service claims, in a form a reader can
 * compare against the estate table without running anything.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { custodyAccount, feeExpenseAccount, isBooked } from './fees.ts'
import type { OutboundTransaction } from './outbound.ts'

describe('the fee entry names accounts nobody else claims differently', () => {
  it('debits (platform, <asset>, payout_due) as an expense', () => {
    const account = feeExpenseAccount('EMBER')
    assert.equal(account.subject, 'platform')
    assert.equal(account.assetCode, 'EMBER')
    // The chart's `expense` slot for the `platform` subject — micro-ledger names it in its own
    // source: "`platform` is revenue under `fees`, equity under `treasury` and expense under
    // `payout_due`" (ledger/src/accounts.ts).
    assert.equal(account.purpose, 'payout_due')
    assert.equal(account.type, 'expense')
  })

  it('never touches (platform, <asset>, fees) — six services own that key as revenue', () => {
    // The defect this replaces, exactly: debiting (platform, <asset>, fees) as `expense` while
    // billing, market, mint, trade and wallet name (platform, SHARD, fees) `revenue` and foresight
    // names (platform, EMBER, fees) `revenue`. Reintroducing it turns this red here, before it
    // turns every entry red in production.
    for (const asset of ['EMBER', 'SHARD', 'BTC'] as const) {
      const account = feeExpenseAccount(asset)
      const collides = account.subject === 'platform' && account.purpose === 'fees' && account.type !== 'revenue'
      assert.equal(collides, false, `(platform, ${asset}, fees) is revenue estate-wide; this claims ${account.type}`)
    }
  })

  it('credits the custody pool micro-wallet actually maintains', () => {
    const account = custodyAccount('BTC')
    assert.equal(account.subject, 'custody')
    assert.equal(account.type, 'asset')
    // `available`, not `treasury`. Nothing in the estate has ever DEBITED (custody, <asset>,
    // treasury) — wallet books every deposit and settled withdrawal against
    // (custody, <asset>, available) — so its balance is 0, and crediting a debit-normal `asset`
    // account with a zero balance takes it negative, which `ledger_assert_no_overdraft` refuses.
    assert.equal(account.purpose, 'available')
  })

  it('is debit-normal on the expense side, so a fee can never drive it negative', () => {
    // The property that makes `expense` the right answer rather than merely a free key: an expense
    // account is debit-normal, this entry only ever debits it, and the ledger's overdraft trigger
    // therefore has nothing to refuse. Retyping the old posting to `revenue` would have kept the
    // key and swapped the type check for the trigger — the first BTC fee would still have failed.
    assert.equal(feeExpenseAccount('BTC').type, 'expense')
  })

  it('the two sides are different accounts under the ledger key', () => {
    const key = (a: { subject: string; assetCode: string; purpose: string }): string =>
      [a.subject, a.assetCode, a.purpose].join('|')
    assert.notEqual(key(feeExpenseAccount('EMBER')), key(custodyAccount('EMBER')))
  })

  /**
   * **THE SAME TWO KEYS FOR EVERY ASSET, INCLUDING THE ONES THAT DID NOT EXIST YET.**
   *
   * `ensureAccount` throws `AccountConflictError` when a caller's stated type disagrees with the
   * row that already exists (ledger/src/accounts.ts), and whichever service posts SECOND has
   * EVERY entry refused, not one — for as long as the disagreement stands. No suite in the estate
   * can see it, because each service tests against its own fake ledger.
   *
   * So the property worth pinning is that these two functions are ASSET-AGNOSTIC: adding a chain
   * must not be able to introduce a third key or a different type. SOL is here because it is the
   * chain this repository just added, and BTC because it is the one the reasoning was written for
   * — an asset nothing in the estate credits fee revenue in at all, which is where the old
   * `(platform, <asset>, fees)` posting would have been refused by the overdraft trigger rather
   * than by the type check.
   *
   * Both keys are `micro-conformance`'s CANONICAL_ACCOUNTS entries verbatim
   * (conformance/src/ledgeraccounts.ts): `(platform, *, payout_due)` is `expense` and
   * `(custody, *, available)` is `asset`.
   */
  it('names one key per side for every asset, new chains included', () => {
    for (const asset of ['EMBER', 'ETH', 'BTC', 'SOL', 'XRP', 'SHARD'] as const) {
      assert.deepEqual(feeExpenseAccount(asset), {
        subject: 'platform',
        assetCode: asset,
        purpose: 'payout_due',
        type: 'expense',
      })
      assert.deepEqual(custodyAccount(asset), {
        subject: 'custody',
        assetCode: asset,
        purpose: 'available',
        type: 'asset',
      })
    }
  })
})

describe('isBooked', () => {
  const row = (fee: bigint, ledgerEntryId: string | null): OutboundTransaction =>
    ({ fee, ledgerEntryId }) as unknown as OutboundTransaction

  it('a zero-fee transaction needs no entry', () => {
    assert.equal(isBooked(row(0n, null)), true)
  })

  it('a fee with no entry is unbooked, and with one is booked', () => {
    assert.equal(isBooked(row(21_000n, null)), false)
    assert.equal(isBooked(row(21_000n, 'entry-1')), true)
  })
})
