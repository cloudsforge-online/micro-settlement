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
import type { Logger } from '@cloudsforge/telemetry'
import { assetOf, chainKey, custodyChainOf, custodyFamilyOf, type ChainId } from './chains.ts'
import { chainFor } from './registry.ts'
import type { CustodyClient } from './custodyclient.ts'
import { custodyAccount, treasuryEquityAccount } from './fees.ts'
import { treasuryLabel, type IndexerClient } from './indexerclient.ts'
import type { LedgerClient } from './ledgerclient.ts'
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
  /**
   * The `addressKey` this service last successfully registered with the indexer's custody set, or
   * `null` if it never has. See migration 7 on why this is a key and not a timestamp.
   */
  readonly indexerWatchedKey: string | null
  /**
   * When this address's on-chain float was given a position in the ledger, or `null` if it never
   * has been.
   *
   * **Registration is not complete until this is set.** Watching an address without booking it
   * raises the indexer's custody aggregate with nothing on the ledger side to match, which is
   * drift, and EMBER reconciles at zero tolerance — one wei freezes every withdrawal in the asset.
   * That is not a hazard, it is the incident of 2026-08-05 (micro-org#247).
   */
  readonly openingBookedAt: Date | null
  /** What was booked, in smallest units. Null on rows back-filled by migration 10 — see it. */
  readonly openingAmount: bigint | null
  /** The ledger entry that booked it. Null likewise, and for the same rows. */
  readonly openingEntryId: string | null
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
  readonly indexer_watched_key: string | null
  readonly opening_booked_at: Date | null
  /** `numeric(78,0)`, selected as text. See `toTreasury` for why it is never a JS number. */
  readonly opening_amount: string | null
  readonly opening_entry_id: string | null
}

/**
 * The columns every read of this table selects, in one place.
 *
 * `opening_amount::text` is not a stylistic choice. `numeric` arrives from the driver as a JS
 * number unless it is cast, and an 18-decimal balance does not survive one — the digits a float
 * drops are exactly the digits a reconciliation drift is made of.
 */
const TREASURY_COLUMNS = `id, chain, network, address, address_key, custody_chain, custody_family,
       custody_user_id, custody_order_id, pinned_at, indexer_watched_key,
       opening_booked_at, opening_amount::text as opening_amount, opening_entry_id`

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
    indexerWatchedKey: row.indexer_watched_key,
    openingBookedAt: row.opening_booked_at,
    openingAmount: row.opening_amount === null ? null : BigInt(row.opening_amount),
    openingEntryId: row.opening_entry_id,
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

/**
 * The treasury is watched by the indexer but its float has no position in the ledger yet.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THIS REFUSES A SWEEP AND NOT A WITHDRAWAL.**
 *
 * A sweep moves customer coin from a deposit address into the treasury. Both addresses are in the
 * indexer's custody set, so the aggregate does not move and the sweep is invariant-neutral — as
 * long as the treasury's own float is already accounted for. In the window between `indexer.watch`
 * and the opening entry it is not, and a sweep landing in that window inflates the treasury's
 * measured balance with coin that IS already booked against the deposit address it came from. The
 * opening entry would then book it a second time, and the estate would believe it holds more coin
 * than exists — which reconciles to drift in the direction that looks like a customer surplus and
 * is really a double count.
 *
 * A WITHDRAWAL is not refused, and must not be. Payouts are the estate's whole purpose, the
 * treasury is the only address they can be paid from, and paying one out of an unbooked treasury
 * is arithmetically harmless: it lowers both the chain balance and the ledger's custody total by
 * the same amount, and the opening entry that lands afterwards measures whatever is left. Refusing
 * withdrawals here would turn a bookkeeping gap into the exact payments outage this whole change
 * exists to prevent.
 *
 * The window is seconds in practice and closes on the next pass of a leased job, so this is a
 * refusal an operator should essentially never see. If they do, it means the indexer is reachable
 * for `watch` and not for the balance read, or the ledger is refusing the entry — both of which
 * are named in the recurring job's log.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export class TreasuryNotBookedError extends Error {
  readonly chain: ChainId
  readonly network: Network
  constructor(chain: ChainId, network: Network, address: string) {
    super(
      `the ${chain} ${network} treasury (${address}) is registered with the indexer but its ` +
        'opening balance has not been booked to the ledger yet, so a sweep landing now would be ' +
        'counted twice when it is. The treasury-watch job books it on its next pass and nothing ' +
        'needs to be done by hand; if this persists, that job is failing and says why.',
    )
    this.name = 'TreasuryNotBookedError'
    this.chain = chain
    this.network = network
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
    select ${sql.unsafe(TREASURY_COLUMNS)}
      from treasuries where chain = ${chain} and network = ${network}
  `
  const row = rows[0]
  return row ? toTreasury(row) : null
}

export async function listTreasuries(sql: Db): Promise<readonly Treasury[]> {
  const rows = await sql<TreasuryRow[]>`
    select ${sql.unsafe(TREASURY_COLUMNS)}
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
  // Watched but not yet booked — see `TreasuryNotBookedError` for why a sweep in that window is
  // the one operation that would be counted twice. Conditioned on `indexerWatchedKey`, not on the
  // booking alone: a treasury nobody has registered yet is not in the aggregate at all, so a sweep
  // into it is invariant-neutral in the old way and there is nothing to double count.
  if (treasury.indexerWatchedKey !== null && treasury.openingBookedAt === null) {
    throw new TreasuryNotBookedError(chain, network, treasury.address)
  }
  return { treasury, pin }
}

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE TREASURY AS THE CHAIN SEES IT
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

export interface TreasuryWatchDeps extends TreasuryDeps {
  readonly indexer: IndexerClient
  readonly ledger: LedgerClient
  /** The `actor` on the entry this posts — `service:<producer>`, as `bookFee` spells it. */
  readonly producer: string
  readonly logger: Logger
}

export type TreasuryWatchOutcome =
  | {
      readonly kind: 'registered'
      readonly address: string
      readonly label: string
      /**
       * What the opening entry booked, in smallest units. `0n` when the address held nothing, and
       * NULL when no opening was owed at all — a rotation onto a row that is already booked. The
       * two are different facts and collapsing them into `0n` would hide the second.
       */
      readonly openingAmount: bigint | null
      /** Null when the balance was zero, or when no opening was owed. */
      readonly openingEntryId: string | null
    }
  /** Watched already, but the opening entry was outstanding and has now been posted. */
  | {
      readonly kind: 'booked'
      readonly address: string
      readonly openingAmount: bigint
      readonly openingEntryId: string | null
    }
  | { readonly kind: 'already_registered'; readonly address: string }
  | { readonly kind: 'no_treasury' }

/**
 * Tell the indexer that this chain's treasury is an address the platform holds.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE DEFECT THIS CLOSES: SWEPT COIN WAS INVISIBLE TO THE PLATFORM'S SOLVENCY CHECK.**
 *
 * `micro-indexer`'s custody aggregate — the number `micro-ledger` reconciles against, and the only
 * thing that can prove the estate's economics are valid from the chain — sums `watched_addresses`
 * whose label carries a platform prefix. `micro-wallet` registers every deposit address under
 * `deposit:`. **Nothing had ever registered a `treasury:` address, in any repository.**
 *
 * And this service SWEEPS: it consolidates deposits out of addresses the aggregate counts and into
 * one it does not. So the aggregate fell by the swept amount while the ledger's custody total was
 * unchanged — a POSITIVE drift, which is the reading that says "the ledger claims coin the chain
 * does not show", which FREEZES WITHDRAWALS. The direction was the safe one and the outcome was a
 * certainty rather than a risk: consolidating deposits is what a treasury is for, so every
 * successful sweep moved the estate closer to a freeze that nothing was wrong.
 *
 * ## Why this belongs to settlement and not to custody
 *
 * `micro-custody` mints and pins, holds the pin row, and is authoritative — it learns of a treasury
 * FIRST. It is still the wrong owner:
 *
 *   * It builds no HTTP client to any peer and holds no `indexer:*` grant. Giving the service that
 *     holds the estate's signing keys an outbound write credential to another service widens the
 *     blast radius of the one process where that matters most.
 *   * Its pin route is on the ADMIN surface, taken with an operator's token, and its own comment
 *     records why the signing surface has no write route at all. Registration is not an operator's
 *     act; it is bookkeeping that must happen whether or not an operator is present.
 *   * This service already builds an indexer client, already carries `INDEXER_URL` and
 *     `SETTLEMENT_SERVICE_TOKEN`, and already re-derives the pin on a leased schedule — so the
 *     repair costs one grant and one job here, against a new outbound surface there.
 *
 * `micro-ledger` is excluded by construction: the aggregate exists precisely so the ledger never
 * learns which addresses are custody's.
 *
 * ## Self-healing, and the two properties that make it so
 *
 * Nothing needs backfilling. `requireTreasury` ADOPTS the pin when this service has no row, so a
 * treasury pinned long before this code existed is picked up on the first pass. And the aggregate
 * reads `eth_getBalance` at a confirmed height rather than summing recorded movements
 * (`indexer/src/custody.ts`), so registering an address that has been accumulating swept coin for
 * months makes its **entire** balance visible on the very next observation — there is no history to
 * replay.
 *
 * **A rotation is handled by storing the KEY that was registered rather than a timestamp.** During
 * a rotation `requireTreasury` deliberately returns the OLD row, and registering the old address is
 * right: it is where the balance still is. When the rotation completes, `upsertTreasury` moves
 * `address_key` and `indexer_watched_key` no longer matches, so the new address registers on the
 * next pass. **The old one is never un-watched**, and that is deliberate too — it is still an
 * address the platform holds, it may still hold dust, and removing it from the set would recreate
 * this very defect for whatever is left on it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * ## Correction, 2026-08-08: registering was only half the operation, and the missing half froze
 * ## the asset for three days
 *
 * Everything above is still true and none of it was the wrong thing to do. What it did not
 * consider is the sentence it advertises as a feature two paragraphs up: *"registering an address
 * that has been accumulating swept coin for months makes its **entire** balance visible on the
 * very next observation — there is no history to replay."*
 *
 * The entire balance includes float the ledger has never booked. `ember/mainnet` was pinned at
 * 2026-08-05 12:39:37 and registered at 12:40:11 holding 25.000021 EMBER of platform float —
 * 24.1 in the treasury itself and 0.900021 stranded in an unswept deposit address, because the
 * withdrawal that day was paid out of the treasury. The aggregate rose by all of it. The ledger's
 * custody total did not move, because nothing had ever booked platform float as anything. EMBER
 * has no tolerance entry, which `ledger/src/env.ts` is explicit means ZERO and not infinity, so
 * reconciliation recorded `drift -25000020999999996000` and froze the asset. **Every EMBER
 * withdrawal in the estate was refused for three days while the platform held MORE coin than it
 * owed.** An invented insolvency. micro-org#247 is the incident and the manual repair; #248 is
 * this.
 *
 * `deploy/scripts/ember-seed.js` had predicted it, in as many words: *"Watching it would add its
 * balance to one side of that comparison and nothing to the other, and every reconciliation from
 * then on would record a non-zero drift and FREEZE EMBER — an invented insolvency."* The seeder
 * honoured its own warning by leaving the faucet float unregistered. That workaround is available
 * to a seed script and NOT to this service, which must register the treasury: sweeps move customer
 * coin into it, and an unwatched treasury on a swept estate hides the very loss reconciliation
 * exists to catch. Both halves of that argument are in migration 7.
 *
 * So the repair is not to watch less. It is to make watching and booking ONE operation:
 *
 *   1. Ask the INDEXER what the address holds, before watching it. Not this service's own adapter
 *      — see `IndexerClient.custodyBalance` for why a read at `latest` books the wrong number.
 *   2. Watch it.
 *   3. Post one entry: debit `(custody, ASSET, available)`, credit `(platform, ASSET, treasury)`.
 *   4. Record the entry on the row. **Registration is not complete until step 4**, and this job
 *      runs again until it is — which is what makes a crash between 2 and 3 heal rather than
 *      reproduce the incident.
 *
 * **The amount is the address's own measured balance and never "the drift".** This is the design's
 * whole safety property and it is worth being blunt about: the drift is an aggregate that a
 * GENUINE shortfall also moves, so a service that books the drift makes the estate paper over the
 * exact loss the check exists to find. A measurement of one named address is a measurement — if
 * the books were already wrong before registration they are still wrong afterwards, and the freeze
 * still fires, for the real reason.
 *
 * **A zero balance is booked as nothing, not as a zero-amount entry.** The ledger refuses a
 * posting of zero and it is right to: an entry that moves nothing is a row that says something
 * happened when it did not. The row is still marked booked, because it was: the correct opening
 * position for an address holding nothing is no position.
 *
 * ## An opening is owed ONCE PER TREASURY ROW, and a rotation is not owed a second one
 *
 * The tempting reading of "book what you start watching" is that it applies per ADDRESS, and it is
 * wrong here in the one case that involves the most money. A rotation's documented middle step is
 * *move the balance* (`provisionTreasury`, `allowRotation`), so the coin at the new address came
 * out of the old one — an address the aggregate already counted and the ledger already booked.
 * Booking the new address's balance too would credit the same coin twice: the aggregate is
 * unchanged by the move (both addresses are watched, the old one is never un-watched) while the
 * ledger's custody total doubles. That is a NEGATIVE drift of the entire float, and it freezes the
 * asset exactly as the original defect did, only from the other side and with a wrong number
 * standing in the books.
 *
 * So the condition on measuring and booking is `opening_booked_at is null`, on the ROW, and a
 * rotation onto a booked row watches the new address and posts nothing. The residual case — an
 * operator who rotates onto an address funded from OUTSIDE the estate rather than from the old
 * treasury — is deliberately not handled here: it is not the documented procedure, the shortfall it
 * produces is the safe direction, and reconciliation will refuse to be clean until an operator
 * posts a `reconciliation_correction` naming what they actually did. Guessing on their behalf is
 * how a bookkeeping service invents money.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export async function registerTreasuryWithIndexer(
  deps: TreasuryWatchDeps,
  chain: ChainId,
  network: Network,
): Promise<TreasuryWatchOutcome> {
  let treasury: Treasury
  try {
    treasury = await requireTreasury(deps, chain, network)
  } catch (err) {
    // An operator has not pinned one yet. That is an omission, not a fault, and it must not
    // dead-letter a recurring job — otherwise registration would be silently off for the life of
    // the deployment rather than starting the moment they pin. Same argument as the sweep handler.
    if (err instanceof NoTreasuryPinnedError) return { kind: 'no_treasury' }
    throw err
  }

  const watched = treasury.indexerWatchedKey === treasury.addressKey
  const owesOpening = treasury.openingBookedAt === null
  if (watched && !owesOpening) {
    return { kind: 'already_registered', address: treasury.address }
  }

  // ── STEP 1: MEASURE FIRST, AND MEASURE BEFORE WATCHING ────────────────────────────────────────
  //
  // The order matters in one direction only, and it is this one. Watching first and measuring
  // second leaves a window in which the aggregate counts this address and the ledger does not, and
  // that window is the incident. Measuring first and failing to watch leaves nothing behind: no
  // row is written, the aggregate is unchanged, and the job tries again.
  //
  // The reading is the INDEXER's, at the indexer's confirmation depth, against a block hash it
  // proved before and after. See `custodyBalance` — a reading of our own at `latest` would count
  // coin the aggregate will not count for another 60 blocks, and book the ledger high by exactly
  // that.
  //
  // Skipped entirely when the row is already booked, which is the rotation case. Not measuring is
  // the point: see the header. It also means a rotation does not fail on an indexer outage, since
  // there is nothing it needs the indexer to tell it.
  const observed = owesOpening
    ? await deps.indexer.custodyBalance(chain, network, treasury.address)
    : null

  const label = treasuryLabel(chain, network)
  if (!watched) {
    // ── STEP 2 ────────────────────────────────────────────────────────────────────────────────
    // The DISPLAY form, exactly as custody published it. The indexer canonicalises for itself, and
    // sending the lowercase comparison key would put a spelling into `watched_addresses` that no
    // operator comparing it against custody's pin would recognise.
    //
    // NO `freshlyDerived` CLAIM, AND THERE NEVER CAN BE ONE HERE. On a UTXO chain the indexer
    // derives custody balances from its own walked record and needs a registrar's statement that
    // the address had no activity below some height before it will call the derivation a balance
    // (micro-org#252). A treasury address is PINNED by an operator, not minted by this service:
    // it may be years old and may have been receiving coin the whole time, so this service knows
    // nothing about its past and must not invent a floor for it. Where the indexer's record does
    // not reach back far enough, the honest outcome is its `history_unknown` refusal and an
    // operator supplying `historyFromHeight` deliberately — which is also why STEP 1 above can
    // refuse on a cold-started UTXO chain, since it measures this address before it is watched.
    await deps.indexer.watch(chain, network, treasury.address, label)

    // Written only AFTER the call returned. `watch` throws on every failure precisely so this line
    // is unreachable unless the indexer really did accept it — a row that recorded the attempt
    // would report an invisible treasury as registered, which is the defect wearing the fix's
    // clothes.
    await deps.sql`
      update treasuries
         set indexer_watched_key = ${treasury.addressKey},
             indexer_watched_at = now(),
             updated_at = now()
       where id = ${treasury.id}
    `
    deps.logger.info('treasury registered with the indexer custody set', {
      chain,
      network,
      address: treasury.address,
      label,
    })
  }

  // A rotation onto a row that is already booked. The new address is now watched, which is the
  // whole of what it needed; the coin at it was booked when the OLD address was registered.
  if (observed === null) {
    return {
      kind: 'registered',
      address: treasury.address,
      label,
      openingAmount: null,
      openingEntryId: null,
    }
  }

  // ── STEP 3: BOOK IT ───────────────────────────────────────────────────────────────────────────
  const assetCode = assetOf(chain)
  let entryId: string | null = null
  if (observed.balance > 0n) {
    const entry = await deps.ledger.postEntry({
      // NOT `deposit_credited` — nobody deposited this and no customer is owed it. NOT
      // `treasury_spend` — nothing was spent. `reconciliation_correction` is the kind the estate
      // already used for exactly this by hand on 2026-08-08, and it is deliberately outside
      // `WITHDRAWAL_KINDS`, so this entry posts even while the asset is FROZEN. That matters more
      // than the naming: if a freeze could block the entry that lifts it, the first deployment of
      // this code into a frozen estate would be unable to repair the estate it was written for.
      kind: 'reconciliation_correction',
      actor: `service:${deps.producer}`,
      correlationId: treasury.id,
      // Derived from the ADDRESS KEY, not the row id, so a retry after a lost response replays
      // rather than double-posting — `bookFee`'s rule, on the address rather than the transaction.
      //
      // It is the address key and not the row id for a second reason that no longer applies, and
      // the difference is worth keeping visible: the first draft let a ROTATION post its own
      // opening entry, and keyed on the row that entry would have replayed the old one instead. It
      // does not post one at all now — see the header on why booking a rotation double-books the
      // float — so both spellings would behave identically today. The address key stays because it
      // is the narrower claim: this entry is the opening of THIS address, and nothing else.
      idempotencyKey: `settlement:treasury-opening:${chain}:${network}:${treasury.addressKey}`,
      description:
        `opening balance of the ${chain} ${network} treasury ${treasury.address}, measured by ` +
        `the indexer at block ${observed.observedAtBlock} (${observed.requiredConfirmations} ` +
        'confirmations deep) as it was registered with the custody set',
      postings: [
        // Debit custody: this is real coin the platform controls, and the custody total is the
        // ledger side of the solvency comparison the indexer's aggregate is the chain side of.
        {
          direction: 'debit',
          amount: observed.balance,
          assetCode,
          sequence: 1,
          account: custodyAccount(assetCode),
        },
        // Credit platform equity: nobody is owed it. Booking this as a liability would say a
        // customer could withdraw the float, which is the mirror-image error and the one that
        // produces a real shortfall rather than an imaginary one.
        {
          direction: 'credit',
          amount: observed.balance,
          assetCode,
          sequence: 2,
          account: treasuryEquityAccount(assetCode),
        },
      ],
    })
    entryId = entry.id
  }

  // ── STEP 4: REGISTRATION IS COMPLETE ─────────────────────────────────────────────────────────
  //
  // `where opening_booked_at is null` so a replayed post cannot overwrite a different entry's id
  // onto a row that is already booked — the same conditional `bookFee` uses, and for the same
  // reason.
  await deps.sql`
    update treasuries
       set opening_amount = ${observed.balance.toString()},
           opening_entry_id = ${entryId},
           opening_observed_block = ${observed.observedAtBlock},
           opening_booked_at = now(),
           updated_at = now()
     where id = ${treasury.id} and opening_booked_at is null
  `
  deps.logger.info('treasury opening balance booked', {
    chain,
    network,
    address: treasury.address,
    amount: observed.balance.toString(),
    observedAtBlock: observed.observedAtBlock,
    entryId,
  })

  return watched
    ? { kind: 'booked', address: treasury.address, openingAmount: observed.balance, openingEntryId: entryId }
    : {
        kind: 'registered',
        address: treasury.address,
        label,
        openingAmount: observed.balance,
        openingEntryId: entryId,
      }
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
