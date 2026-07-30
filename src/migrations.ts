/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 §2: versioned files, run by a one-shot job under an advisory lock,
 * expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the only
 * caller, and the service ASSERTS the version rather than reaching it. That is not tidiness in this
 * repository: below `SCHEMA_VERSION` the partial unique index that makes two in-flight transactions
 * on one chain impossible may not exist, and a service that could create it at boot is a service
 * that could start without it.
 *
 * **Expand/contract is not advice.** A rolling deploy always runs two versions of this service
 * against one schema, so every change is four releases: add a column, deploy code that writes both,
 * backfill, deploy code that reads the new one, then drop the old one.
 *
 * **A released migration is immutable.** `@cloudsforge/db` checksums each one and refuses a run
 * where the text changed after it was applied. The fix for a wrong migration is always a new one.
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'jobs',
    // Taken verbatim from the runtime package so the table the claim query assumes and the table
    // that exists cannot drift. Copying the DDL by hand is how a service ends up with a jobs table
    // missing the (kind, key) unique constraint — which in THIS service would silently turn the
    // chain lease into no lease at all, because two `chain.withdraw / ember:testnet` rows would
    // both be claimable and two workers would sign against one nonce. The unique constraint is the
    // lease.
    up: JOBS_SCHEMA_SQL,
  },
  {
    version: 2,
    name: 'outbox',
    up: `
      create table if not exists outbox (
        id             uuid        primary key default gen_random_uuid(),
        topic          text        not null,
        key            text        not null,
        occurred_at    timestamptz not null default now(),
        producer       text        not null,
        version        integer     not null default 1,
        actor          text,
        correlation_id text,
        payload        jsonb       not null default '{}'::jsonb,
        published_at   timestamptz
      );

      -- The relay's access path. Partial on the unpublished set, so the index stays the size of
      -- the backlog rather than the size of history.
      create index if not exists outbox_unpublished_idx
        on outbox (occurred_at)
        where published_at is null;

      create table if not exists event_subscriptions (
        id         uuid        primary key default gen_random_uuid(),
        topic      text        not null,
        url        text        not null,
        active     boolean     not null default true,
        created_at timestamptz not null default now(),
        constraint event_subscriptions_topic_url_uniq unique (topic, url)
      );

      -- Delivery is tracked per (event, subscription) rather than per event. With one flag on the
      -- outbox row, one failing subscriber either blocks every other subscriber or causes the
      -- event to be redelivered to all of them on each retry.
      create table if not exists outbox_deliveries (
        event_id        uuid        not null references outbox (id) on delete cascade,
        subscription_id uuid        not null references event_subscriptions (id) on delete cascade,
        delivered_at    timestamptz,
        attempts        integer     not null default 0,
        last_error      text,
        primary key (event_id, subscription_id)
      );
    `,
  },
  {
    version: 3,
    name: 'inbox',
    up: `
      -- Delivery is at-least-once, so the consumer is what makes it effectively-once. The primary
      -- key is the dedupe: a redelivered wallet.withdrawal.requested conflicts and the handler is
      -- never re-run, which is half of "the same withdrawal request delivered twice produces one
      -- outbound transaction". The other half is outbound_transactions.idempotency_key, and both
      -- exist because they catch different things: this catches a REDELIVERY, the unique key
      -- catches two DIFFERENT events that name the same withdrawal.
      create table if not exists inbox (
        topic       text        not null,
        event_id    uuid        not null,
        received_at timestamptz not null default now(),
        primary key (topic, event_id)
      );
    `,
  },
  {
    version: 4,
    name: 'treasuries',
    up: `
      -- The one address per (chain, network) this platform pays out of.
      --
      -- WHY A TREASURY AT ALL, rather than paying a withdrawal straight out of the user's own
      -- deposit address: custody signs a 'deposit'-purpose address only into its own PINNED
      -- treasury, never to a caller-chosen destination. That rule is right — a custody-only address
      -- is a much smaller target — and it means outbound money has to come from somewhere else. So
      -- deposits are consolidated into the treasury and withdrawals are paid from it.
      --
      -- EVERY COLUMN EXCEPT address IS DERIVABLE, and they are stored anyway. custody's POST /v1/sign
      -- compares seven fields character for character and its 403 deliberately does not say which
      -- one disagreed, so a binding that is assembled at the call site is a binding that can drift
      -- from the one custody holds with no symptom but a refusal nobody can debug. Written down
      -- once, at adoption, from the same derivation custody itself used.
      create table if not exists treasuries (
        id             uuid        primary key default gen_random_uuid(),
        chain          text        not null,
        network        text        not null,
        address        text        not null,
        -- The comparison form. Lower-cased for EVM, byte-identical elsewhere. Every equality uses
        -- this; forge-pay compared EIP-55 strings and a user pasting their own address in
        -- lowercase walked past two "is this our own address" checks.
        address_key    text        not null,
        -- custody's own vocabulary, not this service's slug. 'ethereum' where the slug is 'eth'.
        custody_chain  text        not null,
        custody_family text        not null,
        custody_user_id  text      not null,
        custody_order_id text      not null,
        -- True once this address has been seen in custody's pin. A treasury this service adopted
        -- from the pin and one an operator pinned afterwards are the same row; what matters is
        -- that nothing sweeps to an address custody does not pin, which is enforced at sweep time
        -- by re-reading the pin rather than by trusting this flag.
        pinned_at      timestamptz,
        adopted_at     timestamptz not null default now(),
        created_at     timestamptz not null default now(),
        updated_at     timestamptz not null default now(),
        constraint treasuries_chain_network_uniq unique (chain, network)
      );

      -- Deposit addresses this service may sweep, registered by wallet when it assigns one.
      --
      -- The binding fields are wallet's assignment facts and there is NOTHING to derive them from
      -- here: custody stores whatever userId and orderId minted the address, and a sweep must
      -- restate both exactly. That is why registration is a route rather than an inference.
      create table if not exists sweep_sources (
        id               uuid        primary key default gen_random_uuid(),
        chain            text        not null,
        network          text        not null,
        address          text        not null,
        address_key      text        not null,
        custody_chain    text        not null,
        custody_family   text        not null,
        custody_user_id  text        not null,
        custody_order_id text        not null,
        -- The high-water mark of everything this service has MATURED out of this address, in
        -- smallest units. numeric(78,0) holds a uint256 exactly; a float loses the least
        -- significant digits, which is where a reconciliation drift shows up.
        --
        -- It advances at MATURITY and never at broadcast, and the delay is the point. In the old
        -- estate that was load-bearing for crediting: the deposit watcher read a BALANCE at
        -- confirmation depth, so money a sweep had moved was still inside the view it credited
        -- from, and advancing early made the watcher credit the depositor a second time and then
        -- freeze the address for ever. The indexer now credits per TRANSACTION with a real hash, so
        -- that particular double-credit is gone. What this still buys is the sweeper's own
        -- decision: between broadcast and maturity the funds have left but the address still looks
        -- funded to any spot read, and without the unmatured subtraction the sweeper would spend a
        -- second fee discovering that.
        swept            numeric(78,0) not null default 0,
        -- The last spendable balance this service READ for this address, and when.
        --
        -- Not a balance anybody is credited from and not a total anything reconciles against: it is
        -- the sweeper's ordering hint, so that "largest first" costs one probe per address per pass
        -- rather than one probe per address per tick. A shortfall covered by the fewest
        -- transactions is a shortfall covered by the fewest fees, and each sweep occupies this
        -- chain's single outbound slot for a full confirmation depth.
        --
        -- Null means never probed, and 'planSweeps' looks at those FIRST — an address nothing has
        -- ever asked about is the one most likely to be holding something unexpected.
        observed         numeric(78,0),
        observed_at      timestamptz,
        active           boolean     not null default true,
        created_at       timestamptz not null default now(),
        updated_at       timestamptz not null default now(),
        constraint sweep_sources_chain_network_address_uniq unique (chain, network, address_key)
      );

      create index if not exists sweep_sources_chain_idx
        on sweep_sources (chain, network)
        where active = true;
    `,
  },
  {
    version: 5,
    name: 'outbound-transactions',
    up: `
      -- 04-domain-model §4.4. ONE table for every outbound movement, whatever its purpose.
      --
      -- A sweep is not a different kind of thing from a withdrawal: both spend from an address this
      -- platform controls, both consume that account's next nonce, and both therefore contend for
      -- exactly the same resource. Two tables would mean two state machines, two stuck deadlines,
      -- two recovery paths and — the part that costs money — two independent notions of "is
      -- anything in flight on this chain". forge-pay has two, and its 'is anything in flight' check
      -- is an unlocked read that both of them pass.
      create table if not exists outbound_transactions (
        id             uuid        primary key default gen_random_uuid(),
        purpose        text        not null,
        chain          text        not null,
        network        text        not null,
        from_address   text        not null,
        from_address_key text      not null,
        to_address     text        not null,
        to_address_key text        not null,
        asset_code     text        not null,
        -- What the destination RECEIVES. The fee is on top of it and comes out of the user's
        -- amount rather than out of the platform's, which is wallet's arithmetic; what leaves the
        -- source address is amount + fee.
        amount         numeric(78,0) not null,
        fee            numeric(78,0) not null,

        state          text        not null default 'planned',

        -- THE BYTES, AND THEY ARE COMMITTED BEFORE ANYTHING IS BROADCAST.
        --
        -- A crash after broadcast but before this write leaves a transaction on chain that the
        -- database does not know about, which is unrecoverable by inspection: there is no id to
        -- poll, no amount to reconcile and no way to tell it from a payment that never happened.
        -- So the order is build → sign → COMMIT → broadcast, and the recovery is to re-send these
        -- exact bytes, which every chain here deduplicates by transaction id.
        raw_tx         text,
        -- The nonce these bytes consume, for an operator to read. The adjudication path prefers
        -- the value it derives from raw_tx, because a column beside the bytes can drift from them
        -- in a way nothing would notice; this is the fallback for a family with no derivation.
        signed_nonce   text,
        -- The height past which the bytes can never apply. Null for EVM, where there is no such
        -- height at all — a legacy transaction is valid for ever and only a consumed nonce retires
        -- it, which is why the EVM death proof is about the nonce and not about time.
        signed_expiry  text,
        -- The id of the audit row custody committed with the signature. The join between a payment
        -- and the record of the key that signed it.
        custody_audit_id text,

        tx_hash        text,
        confirmations  integer     not null default 0,
        mined_height   numeric(78,0),

        signed_at      timestamptz,
        broadcast_at   timestamptz,
        confirmed_at   timestamptz,
        -- Sweeps only: when the movement became deep enough to advance sweep_sources.swept.
        matured_at     timestamptz,
        -- The ledger entry recording the network fee this transaction burned, once it has one.
        -- Null on a confirmed row is a backlog, not a fault: the payment is on chain whatever the
        -- ledger says, so the bookkeeping is retried by its own job rather than being allowed to
        -- stop a confirmation. 'ledger.fee' is the job and this column is its queue.
        ledger_entry_id text,
        failure_reason text,

        -- What caused this. A withdrawal id for a withdrawal, a sweep_sources id for a sweep.
        source_ref     text,
        user_id        text,
        -- wallet's ledger reservation. Quoted back on completion so a settle and a reservation
        -- cannot be matched up wrongly.
        reservation_entry_id text,
        correlation_id text,

        -- WALLET'S KEY, NOT ONE THIS SERVICE MINTS. wallet's boundary contract: "settlement must
        -- use it as the key of its own outbound transaction. A redelivered event must not produce
        -- a second payment, and the only value both services can agree on is this one."
        idempotency_key text       not null,

        created_at     timestamptz not null default now(),
        updated_at     timestamptz not null default now(),

        constraint outbound_transactions_idempotency_uniq unique (idempotency_key),
        constraint outbound_transactions_state_ck check (state in
          ('planned','building','signed','broadcast','confirmed','stuck','failed')),
        constraint outbound_transactions_purpose_ck check (purpose in
          ('withdrawal','sweep','treasury_move','deploy'))
      );

      -- ────────────────────────────────────────────────────────────────────────────────────────
      -- THE INVARIANT, AS A CONSTRAINT RATHER THAN AS A CONVENTION.
      --
      -- One in-flight outbound transaction per (chain, network). The job lease keyed on
      -- 'chain:network' is what normally enforces it and this index is what makes it true anyway.
      -- They are not redundant: a lease is a lease, and everything that can defeat one — a clock
      -- skew past 'locked_until', a handler that outruns its lease without a heartbeat, an
      -- operator running a one-off script beside the workers, a future refactor that keys a new job
      -- on the row id — leaves the database as the last thing standing. Under it, the second
      -- writer gets a 23505 and no signature is requested at all.
      --
      -- 'planned' is deliberately NOT in the set: it is the queue, and a chain may have any number
      -- of payments waiting. In flight begins at 'building', the moment a nonce is about to be read.
      --
      -- STRICTER THAN THE NONCE STRICTLY REQUIRES, and that is a decision. The contended resource
      -- is really (chain, network, from_address) — a sweep out of deposit address A and a payment
      -- out of treasury T draw on two different nonces — and 04-domain-model §4.4 states it that
      -- way. Keyed per chain instead because throughput is not the constraint here and being wrong
      -- is expensive: a coarser index cannot be wrong, and a finer one is only correct while
      -- nothing else on the chain shares an address. Both frozen workers serialise per chain for
      -- the same reason. If a chain ever needs the parallelism, the refinement is to add
      -- from_address_key to this index and to the lease key together, in that order, and never to
      -- one of them alone.
      -- ────────────────────────────────────────────────────────────────────────────────────────
      create unique index if not exists outbound_in_flight_uniq
        on outbound_transactions (chain, network)
        where state in ('building','signed','broadcast');

      -- The worker's queue: what to pick up next on a chain.
      create index if not exists outbound_open_idx
        on outbound_transactions (chain, network, created_at)
        where state in ('planned','building','signed','broadcast');

      -- The fee-posting backlog. Partial, because it is empty in the steady state.
      create index if not exists outbound_unbooked_idx
        on outbound_transactions (confirmed_at)
        where state = 'confirmed' and ledger_entry_id is null;

      create index if not exists outbound_source_idx on outbound_transactions (source_ref);
      create index if not exists outbound_hash_idx on outbound_transactions (chain, network, tx_hash);

      -- The operator's queue. Partial, because the answer is almost always empty and an operator
      -- looking at this list is having a bad day already.
      create index if not exists outbound_stuck_idx
        on outbound_transactions (updated_at)
        where state = 'stuck';
    `,
  },
  {
    version: 6,
    name: 'adjudications',
    up: `
      -- Every operator decision about a stuck transaction, and the evidence it rested on.
      --
      -- A separate table rather than a column, because the decision is the thing that must survive:
      -- the transaction row records WHAT happened, and this records WHO decided it, WHEN, on what
      -- proof, and — for a refusal — why the service said no. forge-pay's equivalent is a curl
      -- command in a runbook and a log line, so the only record that an operator once refunded a
      -- withdrawal by hand is a line in an aggregator with a retention period.
      create table if not exists outbound_adjudications (
        id             uuid        primary key default gen_random_uuid(),
        outbound_id    uuid        not null references outbound_transactions (id) on delete cascade,
        -- 'refund' | 'confirm' | 'refused'
        action         text        not null,
        -- The verdict code when the service refused: on_chain, still_applicable, unprovable.
        refusal_code   text,
        -- The sentence the chain evidence produced. This is the audit: a refund of a SIGNED
        -- transaction is only ever allowed with a positive proof, and this is the proof, stored.
        proof          text,
        actor          text        not null,
        correlation_id text,
        created_at     timestamptz not null default now()
      );

      create index if not exists outbound_adjudications_tx_idx
        on outbound_adjudications (outbound_id, created_at desc);
    `,
  },
]

/**
 * The version this build requires. `index.ts` asserts it at boot and refuses to serve below it,
 * which is what stops a replica of the new code answering requests against the old schema when a
 * deploy runs ahead of its migrator.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce((max, m) => Math.max(max, m.version), 0)

/**
 * How an existing hand-built schema would be adopted.
 *
 * Zero, because settlement is a new service with no predecessor database: forge-pay's withdrawal
 * and sweep rows live in `pay`, which this service does not connect to and will not adopt — the
 * migration of that data is a one-off backfill job, not a baseline, because the state machines
 * differ (forge-pay has no `planned`, and its `sweeps` table is separate).
 */
export const BASELINE_VERSION = 0

/** Every table this service owns. The test harness truncates exactly this list. */
export const TABLES: readonly string[] = Object.freeze([
  'outbound_adjudications',
  'outbound_transactions',
  'sweep_sources',
  'treasuries',
  'inbox',
  'outbox_deliveries',
  'event_subscriptions',
  'outbox',
])
