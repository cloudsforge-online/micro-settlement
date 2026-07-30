/**
 * The treasury: the one address per (chain, network) this platform pays out of and sweeps into.
 *
 * ## This service cannot mint one, and must not be able to
 *
 * custody's mint and pin routes are on its ADMIN surface and take an operator's token. Its read
 * route is on the signing surface and takes a service token. That asymmetry is custody's central
 * defence for the whole sweep shape, and its own comment says why: "there is deliberately NO write
 * route on this surface: a signing credential can read the pin and can never set, rotate or
 * influence it. If that stopped being true the sweep shape would become a total-loss vulnerability
 * rather than a containment — anyone who can mint a `treasury` address would pin their own and
 * sweep every deposit to it."
 *
 * So the frozen `ensureTreasury`'s third branch — "with no row and no pin, MINT one" — is not
 * reproduced. It cannot be: this service's credential is refused at that route. And it should not
 * be. That branch is where the frozen code is most uncomfortable with itself ("minting there is the
 * worst of the three available answers… it manufactures precisely the disagreement the sweeper
 * refuses to act in"), because a self-minted treasury is an address custody does not pin, which
 * means every sweep is refused while every withdrawal is paid out of it. `provisionTreasury` below
 * is the replacement: an operator's two deliberate steps, in custody, with their own credential,
 * driven from here so that the row and the pin are written from one derivation.
 *
 * ## The three-step rotation, and why nothing here does it by itself
 *
 * Mint, move the balance, pin — in that order, and only the first and third are code. `mintTreasury`
 * deliberately does not pin, because pinning at mint time would point every future sweep at an
 * address holding nothing while withdrawals still came out of the old one: deposits consolidate
 * into one pot and payouts starve out of another, with no error anywhere. The middle step is an
 * operator's `treasury_move` and it is the one thing in this file that is a manual procedure.
 */

import { parseAmount, type Network } from '@cloudsforge/contracts-chain'
import { chainKey, custodyChainOf, custodyFamilyOf, type ChainId } from './chains.ts'
import { chainFor } from './registry.ts'
import type { CustodyClient } from './custodyclient.ts'
import type { Db, Tx } from './outbox.ts'

/**
 * The `userId` and `orderId` custody stores against a treasury row.
 *
 * **Reproduces `custody/src/keys.ts treasuryBinding` exactly, and the duplication is deliberate.**
 * The alternative is to remember what custody minted, and a remembered binding is one that drifts
 * with no symptom but a 403 whose message will not say which field is wrong. Derived from the chain
 * and network alone, it is byte-identical to what custody wrote for an address it minted itself,
 * which is also what makes ADOPTING a pinned address safe: the row written for an address custody
 * names is the row a mint would have written.
 *
 * `chain` here is CUSTODY's chain name, not this service's slug. The distinction is real for
 * exactly one chain and it is `eth` versus `ethereum`.
 */
export function treasuryBinding(chain: ChainId, network: Network): {
  readonly userId: string
  readonly orderId: string
} {
  return {
    userId: 'cloudsforge:treasury',
    orderId: `treasury:${custodyChainOf(chain)}:${network}`,
  }
}

export interface Treasury {
  readonly id: string
  readonly chain: ChainId
  readonly network: Network
  /** The display form. What a withdrawal is signed FROM. */
  readonly address: string
  readonly addressKey: string
  /** Everything custody demands be restated at signing time, derived once and stored. */
  readonly custodyChain: string
  readonly custodyFamily: string
  readonly custodyUserId: string
  readonly custodyOrderId: string
  readonly pinnedAt: Date | null
}

interface TreasuryRow {
  readonly id: string
  readonly chain: string
  readonly network: string
  readonly address: string
  readonly address_key: string
  readonly custody_chain: string
  readonly custody_family: string
  readonly custody_user_id: string
  readonly custody_order_id: string
  readonly pinned_at: Date | null
}

function toTreasury(row: TreasuryRow): Treasury {
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
    pinnedAt: row.pinned_at,
  }
}

/** Nobody has pinned a treasury for this chain. An operator's omission, not a fault. */
export class NoTreasuryPinnedError extends Error {
  readonly chain: ChainId
  readonly network: Network
  constructor(chain: ChainId, network: Network) {
    super(
      `custody has no treasury pinned for ${chain} ${network}, so there is nowhere to pay from and ` +
        'nowhere a sweep is allowed to go. An operator provisions one with ' +
        `POST /v1/treasuries/${chain}/${network}/provision; no restart is needed afterwards.`,
    )
    this.name = 'NoTreasuryPinnedError'
    this.chain = chain
    this.network = network
  }
}

/**
 * The pin and the row name two different addresses.
 *
 * A rotation caught mid-way, and the only safe response is to stop. While they differ every sweep
 * moves customer deposits into an address no withdrawal can be paid out of — consolidating money
 * into a place it is stuck — with no failure anywhere to say so. Doing nothing is strictly better.
 */
export class TreasuryDisagreementError extends Error {
  readonly payingFrom: string
  readonly pinned: string
  constructor(chain: ChainId, network: Network, payingFrom: string, pinned: string) {
    super(
      `the ${chain} ${network} treasury this service pays out of (${payingFrom}) is not the one ` +
        `custody pins (${pinned}). Sweeping now would move customer deposits somewhere no ` +
        'withdrawal can be paid from. Finish the rotation — move the balance to the pinned address ' +
        'and re-provision — or restore the pin.',
    )
    this.name = 'TreasuryDisagreementError'
    this.payingFrom = payingFrom
    this.pinned = pinned
  }
}

export interface TreasuryDeps {
  readonly sql: Db
  readonly custody: CustodyClient
  readonly network: Network
}

/** Read-only. Never provisions, so a read path can use it without writing anything. */
export async function findTreasury(
  sql: Db,
  chain: ChainId,
  network: Network,
): Promise<Treasury | null> {
  const rows = await sql<TreasuryRow[]>`
    select id, chain, network, address, address_key, custody_chain, custody_family,
           custody_user_id, custody_order_id, pinned_at
      from treasuries where chain = ${chain} and network = ${network}
  `
  const row = rows[0]
  return row ? toTreasury(row) : null
}

export async function listTreasuries(sql: Db): Promise<readonly Treasury[]> {
  const rows = await sql<TreasuryRow[]>`
    select id, chain, network, address, address_key, custody_chain, custody_family,
           custody_user_id, custody_order_id, pinned_at
      from treasuries order by chain, network
  `
  return rows.map(toTreasury)
}

/**
 * Write the row for an address custody pins, or leave the existing one alone.
 *
 * Race-safe the way every provisioning path in this estate is: resolve, insert-or-ignore, re-read,
 * so two concurrent callers converge on whichever row won rather than on two addresses — one of
 * which would hold funds nothing ever looked at again.
 */
async function upsertTreasury(
  sql: Db | Tx,
  chain: ChainId,
  network: Network,
  address: string,
): Promise<void> {
  const adapter = chainFor(chain)
  const binding = treasuryBinding(chain, network)
  // Canonicalised on arrival, always. custody publishes EIP-55 and compares character for
  // character, so what is stored must be what it published — but what is COMPARED is the lowercase
  // key, because the same account has three valid spellings.
  const display = adapter.canonicalise(address)
  await sql`
    insert into treasuries (
      chain, network, address, address_key,
      custody_chain, custody_family, custody_user_id, custody_order_id, pinned_at
    ) values (
      ${chain}, ${network}, ${display}, ${adapter.addressKey(address)},
      ${custodyChainOf(chain)}, ${custodyFamilyOf(chain)},
      ${binding.userId}, ${binding.orderId}, now()
    )
    on conflict (chain, network) do update
      set address = excluded.address,
          address_key = excluded.address_key,
          pinned_at = now(),
          updated_at = now()
      -- Only when the pin has actually MOVED. Without the predicate every call rewrites the row,
      -- which makes 'updated_at' meaningless and hides a rotation inside ordinary traffic.
      where treasuries.address_key is distinct from excluded.address_key
  `
}

/**
 * The treasury for a chain, adopted from custody's pin if this service has not recorded it yet.
 *
 * **custody is authoritative and this service's row is a cache of it.** The row still matters — it
 * is the binding a WITHDRAWAL is signed against, and custody does not consult the pin for that —
 * but the address itself is custody's answer, so asking is the only way to be right.
 *
 * Throws `NoTreasuryPinnedError` when there is no pin AND no row. It does not fall back to a row
 * whose pin has been removed, because an unpinned address is one no sweep may target, and paying
 * withdrawals out of an address deposits can no longer reach is a treasury that only ever drains.
 */
export async function requireTreasury(
  deps: TreasuryDeps,
  chain: ChainId,
  network: Network,
): Promise<Treasury> {
  const pinned = await deps.custody.treasuryPin(custodyChainOf(chain), network)
  const existing = await findTreasury(deps.sql, chain, network)

  if (!pinned) {
    if (!existing) throw new NoTreasuryPinnedError(chain, network)
    // A row with no pin: an operator has unpinned since this service last looked. Withdrawals can
    // still be paid — custody signs a 'treasury'-purpose transfer without consulting any pin — but
    // sweeps cannot, and `assertSweepable` is where that is refused. Reported by the caller.
    return existing
  }

  const adapter = chainFor(chain)
  const pinnedKey = adapter.addressKey(pinned)
  if (existing && existing.addressKey !== pinnedKey) {
    // A ROTATION IN PROGRESS. Adopting the new address silently would start paying withdrawals out
    // of an address that has not been funded yet, which turns a rotation into an outage that
    // presents as "every withdrawal is refunded for want of a balance". The row is left alone and
    // the disagreement is the caller's to report.
    return existing
  }
  if (!existing) {
    await upsertTreasury(deps.sql, chain, network, pinned)
    const adopted = await findTreasury(deps.sql, chain, network)
    if (!adopted) throw new Error(`the ${chain} ${network} treasury vanished immediately after adoption`)
    return adopted
  }
  return existing
}

/**
 * Refuse to sweep unless the pin and the payout row are the same address.
 *
 * Read fresh from custody every time rather than from the row, and echoed to custody EXACTLY as it
 * published it. custody's `assertSweep` compares `to` against its pin character for character and
 * has a refusal of its own for an address that differs only in case, so the value it just gave us
 * is the only one guaranteed to match.
 *
 * **Nothing sweeps to an unpinned candidate.** That is the whole of this function: a minted
 * treasury candidate is an address custody holds the key to and does not pin, and moving customer
 * deposits into one would put them somewhere no sweep may target and no withdrawal is paid from.
 */
export async function assertSweepable(
  deps: TreasuryDeps,
  chain: ChainId,
  network: Network,
): Promise<{ readonly treasury: Treasury; readonly pin: string }> {
  const pin = await deps.custody.treasuryPin(custodyChainOf(chain), network)
  if (!pin) throw new NoTreasuryPinnedError(chain, network)
  const treasury = await requireTreasury(deps, chain, network)
  const adapter = chainFor(chain)
  if (adapter.addressKey(pin) !== treasury.addressKey) {
    throw new TreasuryDisagreementError(chain, network, treasury.address, pin)
  }
  return { treasury, pin }
}

/**
 * Provision a treasury: mint through custody, pin through custody, record the row.
 *
 * Three calls to custody with the OPERATOR's own token, in an order that is not arbitrary.
 *
 *   1. `mint` — a `treasury`-purpose address custody holds the key to. Idempotent on custody's
 *      side: everything it writes is derived from the path, so a second call a minute later
 *      returns the same outstanding candidate with `reused: true` rather than burning a key.
 *   2. `pin` — the write only an administrator can make, and the only value a sweep may target.
 *   3. the row — written from `treasuryBinding`, the same derivation custody used, so the binding
 *      restated at signing time is byte-identical to the one custody stored.
 *
 * **Refuses to run when a treasury already exists and holds a different address**, because that is
 * a rotation and a rotation's middle step — move the balance — is an operator's decision this
 * function cannot make. Doing it anyway would pin an empty address while withdrawals still needed
 * the old one's balance.
 */
export async function provisionTreasury(
  deps: TreasuryDeps,
  input: {
    readonly chain: ChainId
    readonly network: Network
    readonly operatorToken: string
    /** An operator who has already moved the balance says so here, and only then. */
    readonly allowRotation: boolean
  },
): Promise<{ readonly treasury: Treasury; readonly minted: boolean; readonly rotatedFrom: string | null }> {
  const { chain, network } = input
  const custodyChain = custodyChainOf(chain)
  const adapter = chainFor(chain)

  const existing = await findTreasury(deps.sql, chain, network)
  const currentPin = await deps.custody.treasuryPin(custodyChain, network)

  // Already provisioned and already agreeing. Nothing to do, and saying so is better than minting
  // a key nobody will ever look at.
  if (existing && currentPin && adapter.addressKey(currentPin) === existing.addressKey) {
    return { treasury: existing, minted: false, rotatedFrom: null }
  }
  if (existing && !input.allowRotation) {
    throw new TreasuryDisagreementError(
      chain,
      network,
      existing.address,
      currentPin ?? '(nothing pinned)',
    )
  }

  const candidate = await deps.custody.mintTreasury(custodyChain, network, input.operatorToken)
  const pinResult = await deps.custody.pinTreasury(
    custodyChain,
    network,
    candidate.address,
    input.operatorToken,
  )
  await upsertTreasury(deps.sql, chain, network, pinResult.address)
  const treasury = await findTreasury(deps.sql, chain, network)
  if (!treasury) throw new Error(`the ${chain} ${network} treasury vanished immediately after pinning`)
  return {
    treasury,
    minted: !candidate.reused,
    rotatedFrom: existing && existing.addressKey !== treasury.addressKey ? existing.address : null,
  }
}

/**
 * The float an operator wants sitting in this chain's treasury, in smallest units.
 *
 * **Zero unless somebody said otherwise, and that default is the design.** Every coin in the
 * treasury is inside the blast radius of the signing credential and every coin left in a deposit
 * address is outside it, so moving one from the second to the first is not neutral: a leaked
 * signing token buying the float is a different-sized incident from one buying every deposit ever
 * made. The sweeper is therefore demand-driven — it moves what queued withdrawals actually need —
 * and a standing float is an explicit choice with a number attached.
 *
 * An unparseable target is refused rather than ignored, unlike the frozen version which logged and
 * carried on with zero. Carrying on is defensible when the alternative is stopping the withdrawals
 * people are waiting on; it is not defensible at boot, where the same typo is a float an operator
 * believes they have set and has not.
 */
export function floatTarget(
  targets: Readonly<Record<string, string>>,
  assetCode: string,
  decimals: number,
): bigint {
  const configured = targets[assetCode]
  if (configured === undefined) return 0n
  try {
    const parsed = parseAmount(configured, decimals)
    if (parsed < 0n) throw new RangeError('negative')
    return parsed
  } catch {
    throw new Error(
      `SETTLEMENT_TREASURY_TARGETS.${assetCode} is '${configured}', which is not a non-negative ` +
        `decimal number of whole ${assetCode}`,
    )
  }
}

/** The lease key for this chain's outbound work. Re-exported so callers do not build it by hand. */
export { chainKey }
