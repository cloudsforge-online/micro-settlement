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
  {
    version: 7,
    name: 'treasury-indexer-registration',
    up: `
      -- Which address this service has told the indexer to WATCH, and the defect it closes.
      --
      -- micro-indexer serves GET /v1/custody/:chain/:network/total — the number micro-ledger
      -- reconciles the platform's solvency against — as the sum of confirmed native balances over
      -- its "custody set". That set is 'watched_addresses' filtered by label prefix, default
      -- 'deposit:,treasury:' (indexer/src/store.ts custodyAddresses).
      --
      -- micro-wallet registers every deposit address it assigns, with a 'deposit:' label. NOTHING
      -- IN THE ESTATE HAS EVER WRITTEN A 'treasury:' LABEL — grepping the 58 repositories for a
      -- caller of the watch route finds two, both wallet's, both 'deposit:'. And this service
      -- SWEEPS deposits into the treasury: it moves coin out of an address the indexer counts and
      -- into one it does not.
      --
      -- So every sweep made the aggregate smaller while the ledger's custody total stayed the
      -- same. That is a POSITIVE drift — "the ledger claims coin the chain does not show" — which
      -- is the reading that FREEZES WITHDRAWALS. The direction is the safe one and the failure was
      -- certain: consolidating deposits, which is the whole point of a treasury, walked the estate
      -- towards a spurious freeze one sweep at a time.
      --
      -- WHY A KEY AND NOT A TIMESTAMP. 'indexer_watched_at is null' would answer "has this row ever
      -- been registered", and that is the wrong question across a rotation: a treasury rotates by
      -- 'upsertTreasury' overwriting address and address_key in place, so a timestamp set for the
      -- OLD address would report the NEW one as already registered and the new treasury would be
      -- invisible for ever — the same defect, surviving the fix that was meant to end it. Storing
      -- the key that was registered makes the predicate 'indexer_watched_key is distinct from
      -- address_key', which is true again the instant a rotation lands and needs no reset anywhere.
      alter table treasuries add column if not exists indexer_watched_key text;
      alter table treasuries add column if not exists indexer_watched_at timestamptz;

      -- The registration job's access path, and it is deliberately PARTIAL. In a healthy estate
      -- every row is registered, so the index is empty and the job's query touches nothing; the
      -- rows it does hold are exactly the work outstanding.
      create index if not exists treasuries_unregistered_idx
        on treasuries (chain, network)
        where indexer_watched_key is null or indexer_watched_key is distinct from address_key;
    `,
  },
  {
    version: 8,
    name: 'token-sweeps',
    /*
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * THE TWO-PHASE SWEEP: a gas top-up that must land before the token sweep it pays for.
     *
     * An ERC-20 balance sits at a deposit address whose native balance is zero — the sender paid
     * the gas, so the tokens arrived and cannot leave. Moving them is TWO transactions:
     *
     *   A. `gas_topup`    treasury → deposit address, native value, custody's `transfer` shape.
     *   B. `token_sweep`  deposit address → the token contract, calldata `transfer(<pin>, amount)`,
     *                     `value == 0`, custody's `token_sweep` shape.
     *
     * B cannot be built before A has CONFIRMED — not merely broadcast — because until then the
     * address still cannot pay for B, and a B signed against an unfunded address is a signature
     * that exists for ever over bytes no node will accept.
     *
     * ── WHY THE DEPENDENCY IS A COLUMN AND A TRIGGER RATHER THAN A CONVENTION ──────────────────
     *
     * The obvious implementation is "plan A now, plan B when A confirms". It is wrong in the one
     * way that costs money: a crash between A confirming and B being planned leaves a funded
     * deposit address and no record of why it was funded, and the next planning pass — which reads
     * the TOKEN balance, unchanged by the top-up — funds it again. `signing.ts` names this
     * exactly: "a planner that does not treat the top-up as in-flight will fund the same address on
     * every tick until it confirms."
     *
     * So both rows are written in ONE transaction, and B carries `depends_on = A.id`. Either both
     * exist or neither does; there is no window. `nextPlanned` skips a row whose dependency has not
     * confirmed, and the trigger below refuses the transition anyway, for `outbound_in_flight_uniq`'s
     * reason: the query is the design and the constraint is what makes it true when a future
     * refactor, an operator's one-off script or a lost lease gets past the query.
     *
     * ── WHY `to_address` IS THE TREASURY AND NOT THE CONTRACT ─────────────────────────────────
     *
     * A token sweep's transaction `to` is the contract, and its real beneficiary is the first ABI
     * argument of the calldata. Storing the CONTRACT in `to_address` would make every existing
     * query about where money went silently wrong — `sweepCompletedEvents` publishes `to`, the
     * operator surface lists it, and reconciliation reads it. So `to_address` keeps its meaning,
     * WHO IS PAID, and the contract gets its own column. The builder puts `to_address` inside the
     * calldata and `token_contract` in the transaction's `to`, which is also the order custody
     * checks them in.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */
    up: `
      -- The ERC-20 contract a token sweep calls. Null for every other purpose.
      alter table outbound_transactions add column if not exists token_contract text;

      -- The transaction that must have CONFIRMED before this one may be built.
      alter table outbound_transactions
        add column if not exists depends_on uuid references outbound_transactions (id);

      -- The two new purposes. A CHECK is replaced rather than widened in place because the old
      -- text is checksummed; dropping and recreating is the only expand/contract shape a CHECK has.
      alter table outbound_transactions drop constraint if exists outbound_transactions_purpose_ck;
      alter table outbound_transactions add constraint outbound_transactions_purpose_ck check (
        purpose in ('withdrawal','sweep','treasury_move','deploy','gas_topup','token_sweep')
      );

      -- ────────────────────────────────────────────────────────────────────────────────────────
      -- A TOKEN CONTRACT EXISTS IF AND ONLY IF THE PURPOSE IS A TOKEN SWEEP.
      --
      -- Both directions, in one constraint, and both are real. A token_sweep with no contract is
      -- a row the builder would have to invent a destination for. A contract on any OTHER purpose
      -- is a row that reads as a token movement to every query that filters on the column being
      -- non-null, while being built and signed as a plain native transfer — which is the shape of
      -- error that gets found by an auditor rather than by a test.
      --
      -- Lower-cased and shaped, for custody_token_contracts_contract_ck's reason: the allowlist
      -- custody checks this against stores one spelling, so a row carrying another spelling here
      -- is a sweep that will be refused at signing time, after the chain's single outbound slot
      -- has been claimed.
      -- ────────────────────────────────────────────────────────────────────────────────────────
      alter table outbound_transactions add constraint outbound_token_contract_ck check (
        (purpose = 'token_sweep') = (token_contract is not null)
        and (token_contract is null or token_contract ~ '^0x[0-9a-f]{40}$')
      );

      -- ────────────────────────────────────────────────────────────────────────────────────────
      -- A TOKEN SWEEP MOVES NO NATIVE VALUE, AND ITS FEE IS PAID BY SOMEBODY ELSE.
      --
      -- amount on a token sweep is denominated in the TOKEN and fee in native wei, so the two
      -- columns hold different units on this one purpose. value on the transaction itself is
      -- zero — custody refuses a token sweep carrying native value outright, because on most
      -- ERC-20s it reverts and on the rest it is burnt at the contract.
      --
      -- The positive-amount half is the one worth having: a zero-amount token sweep is a signature
      -- over a no-op that costs a real fee, and a signature is permanent.
      -- ────────────────────────────────────────────────────────────────────────────────────────
      alter table outbound_transactions add constraint outbound_token_amount_ck check (
        purpose <> 'token_sweep' or (amount > 0 and fee >= 0)
      );

      -- ────────────────────────────────────────────────────────────────────────────────────────
      -- A DEPENDENT ROW MAY NOT BE BUILT UNTIL ITS DEPENDENCY HAS CONFIRMED.
      --
      -- The last line under nextPlanned's filter, and it is the same relationship
      -- outbound_in_flight_uniq has to the chain lease: the query is what normally enforces this
      -- and the constraint is what makes it true anyway. Everything that can defeat a query — a
      -- future call site that selects a row by id, an operator re-queueing a stuck sweep by hand,
      -- a refactor that adds a second planner — leaves the database as the last thing standing.
      --
      -- A TRIGGER RATHER THAN A CHECK because the fact being asserted lives on ANOTHER ROW, and a
      -- CHECK constraint cannot see one. It fires only on the transition INTO 'building', which is
      -- the moment the nonce is about to be read and therefore the last moment a refusal is free.
      --
      -- IT REFUSES A MISSING DEPENDENCY TOO. depends_on has a foreign key, so the row cannot be
      -- absent, but the found variable is checked rather than assumed: a dependency that is
      -- failed, stuck or still planned all take the same branch as one that is not there, and
      -- the error names which so an operator reads a state rather than a null.
      -- ────────────────────────────────────────────────────────────────────────────────────────
      create or replace function outbound_dependency_confirmed() returns trigger as $$
      declare
        dependency_state text;
      begin
        if new.depends_on is null or new.state <> 'building' then
          return new;
        end if;
        if old.state = 'building' then
          -- Not a transition into 'building'; some other column is being updated on a row that is
          -- already there. Re-checking would refuse a legitimate write after the dependency has
          -- been superseded, and the transition itself was already gated.
          return new;
        end if;
        select state into dependency_state
          from outbound_transactions where id = new.depends_on;
        if dependency_state is distinct from 'confirmed' then
          raise exception
            'outbound transaction % depends on %, which is % rather than confirmed — the gas it '
            'pays for has not landed, so these bytes could not be broadcast',
            new.id, new.depends_on, coalesce(dependency_state, 'missing')
            using errcode = 'integrity_constraint_violation';
        end if;
        return new;
      end;
      $$ language plpgsql;

      drop trigger if exists outbound_dependency_confirmed_trg on outbound_transactions;
      create trigger outbound_dependency_confirmed_trg
        before update on outbound_transactions
        for each row execute function outbound_dependency_confirmed();

      -- The planner's access path: rows blocked on a dependency, and rows that unblock them.
      -- Partial, because in the steady state nothing is waiting.
      create index if not exists outbound_dependent_idx
        on outbound_transactions (depends_on)
        where depends_on is not null and state = 'planned';
    `,
  },
  {
    version: 9,
    name: 'erasure',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- RIGHT TO ERASURE — THE HALF THAT BELONGS IN THE SCHEMA.
      --
      -- 03 §2 rule 6: every service storing a user reference subscribes to 'identity.user.deleted'
      -- and erases. Which rows, and why each one is treated the way it is, is written out in
      -- 'src/erasure.ts'. What is here is only what a handler cannot be trusted with.
      --
      -- ── WHY THIS SERVICE ANONYMISES RATHER THAN DELETES, IN ONE SENTENCE ────────────────────
      --
      -- Every row here is about a movement of coin on a public chain that cannot be un-made, and
      -- 'outbound_transactions.raw_tx' holds the exact signed bytes that made it. Deleting the row
      -- does not delete the transaction; it deletes the platform's own record of it — the record
      -- that answers "was this withdrawal authorised, by whom, against which reservation" — while
      -- leaving the movement itself in public view for ever.
      --
      -- 'erased_at' IS NOT DECORATION. 'user_id' is already nullable and a null already MEANS
      -- something specific in this service: 'withdrawals.ts:544' documents it as "a row that
      -- predates the column being written", for which "unreachable is the correct answer". Without
      -- a second column those two states are indistinguishable, and an erasure would be invisible
      -- to the audit that has to prove it happened. The timestamp is also the anchor for the
      -- retention clock: it is set from the event's own 'tombstoneAt', not from now().
      -- ════════════════════════════════════════════════════════════════════════════════════════

      alter table outbound_transactions add column if not exists erased_at timestamptz;
      alter table sweep_sources        add column if not exists erased_at timestamptz;

      -- An erased outbound transaction names nobody. Stated as a constraint because the handler
      -- writes both columns in one statement today and a future path that writes only one would
      -- otherwise produce a row that claims to be erased and still is not.
      alter table outbound_transactions
        add constraint outbound_erased_names_no_user
        check (erased_at is null or user_id is null);

      -- The access path for an operator asking what has been erased, and for any future retention
      -- sweep. Partial, because in a healthy estate almost nothing is in it.
      create index if not exists outbound_erased_idx
        on outbound_transactions (erased_at)
        where erased_at is not null;

      -- ── THE TRANSITION, WHICH NO CHECK CAN SEE ──────────────────────────────────────────────
      --
      -- Once erased, a row cannot be re-attributed and cannot be un-erased — by anything, a psql
      -- session included. Erasure that a later UPDATE can undo is not erasure.
      create or replace function settlement_outbound_erasure_is_final() returns trigger as $$
      begin
        if old.erased_at is null then return new; end if;
        if new.erased_at is null then
          raise exception 'an erased outbound transaction cannot be un-erased (%)', old.id;
        end if;
        if new.user_id is not null then
          raise exception 'an erased outbound transaction cannot be re-attributed (%)', old.id;
        end if;
        return new;
      end;
      $$ language plpgsql;

      drop trigger if exists outbound_erasure_final on outbound_transactions;
      create trigger outbound_erasure_final
        before update on outbound_transactions
        for each row execute function settlement_outbound_erasure_is_final();

      -- ── SWEEP SOURCES ARE MARKED, NOT STRIPPED, AND THE BINDING IS WHY ──────────────────────
      --
      -- 'custody_user_id' on a sweep source is the end user's id: wallet mints a deposit address
      -- with 'userId: input.userId' (wallet/src/deposits.ts) and settlement must restate that value
      -- CHARACTER FOR CHARACTER or custody refuses to sign (custody/src/gates.ts:182, and the 403
      -- deliberately does not say which field disagreed). Null it and every coin at that address is
      -- stranded for ever, including coin that arrives after the deletion — 'src/server.ts:739'
      -- already says "a guessed binding is a sweep refused every tick for ever".
      --
      -- So the row is marked and kept whole. What the trigger adds is that a marked row cannot be
      -- quietly rebound to a different custody account: registration is an upsert keyed on
      -- (chain, network, address_key), so without this a later register call could re-attribute an
      -- erased person's address.
      create or replace function settlement_sweep_source_erasure_is_final() returns trigger as $$
      begin
        if old.erased_at is null then return new; end if;
        if new.erased_at is null then
          raise exception 'an erased sweep source cannot be un-erased (%)', old.id;
        end if;
        if new.custody_user_id is distinct from old.custody_user_id then
          raise exception 'an erased sweep source cannot be re-attributed (%)', old.id;
        end if;
        return new;
      end;
      $$ language plpgsql;

      drop trigger if exists sweep_source_erasure_final on sweep_sources;
      create trigger sweep_source_erasure_final
        before update on sweep_sources
        for each row execute function settlement_sweep_source_erasure_is_final();
    `,
  },
  {
    version: 10,
    name: 'treasury-opening-balance',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- REGISTERING AN ADDRESS AND BOOKING IT ARE ONE OPERATION, AND MIGRATION 7 ONLY DID THE
      -- FIRST HALF.
      --
      -- Migration 7 closed a real defect — swept coin was invisible to the solvency check — and
      -- closed it correctly. What it did not consider is stated in its own function's header, as a
      -- FEATURE: "registering an address that has been accumulating swept coin for months makes
      -- its ENTIRE balance visible on the very next observation — there is no history to replay."
      --
      -- The entire balance includes float the ledger has never booked. The reconciliation compares
      -- the ledger's custody total against the indexer's aggregate, so an address whose balance
      -- joins one side and not the other is drift, and EMBER has no tolerance entry, which means
      -- ZERO and not infinity (ledger/src/env.ts). One wei freezes every withdrawal in the asset.
      --
      -- On 2026-08-05 the ember/mainnet treasury was pinned at 12:39:37 and registered at 12:40:11
      -- holding 25.000021 EMBER of platform float. Reconciliation went to
      -- drift -25000020999999996000 and froze. Every EMBER withdrawal in the estate was refused
      -- for three days while the platform held MORE coin than it owed. An invented insolvency.
      -- micro-org#247 is the incident; #248 is this.
      --
      -- ── WHAT IS BOOKED, AND WHY IT IS NOT THE DRIFT ─────────────────────────────────────────
      --
      -- The address's OWN measured balance, debited to (custody, ASSET, available) and credited to
      -- (platform, ASSET, treasury) equity — platform float is real coin the platform controls
      -- with no customer behind it, so it belongs on the asset side with an equity counterpart,
      -- exactly as 'engagementAccount' reasons for the platform's earmarked money.
      --
      -- Booking THE DRIFT instead would be one line shorter and catastrophic: the drift is an
      -- aggregate that a genuine shortfall also moves, so a service that books it makes the estate
      -- paper over the exact loss the check exists to find. Booking a specific address's measured
      -- balance is a MEASUREMENT — if the books were already wrong before registration they stay
      -- wrong afterwards, and the freeze still fires for the real reason.
      --
      -- ── WHY THE AMOUNT AND THE ENTRY ID ARE BOTH STORED ─────────────────────────────────────
      --
      -- 'opening_entry_id' is what makes registration complete: the recurring job retries until it
      -- is present, so a crash between watching and booking heals rather than leaving a watched,
      -- unbooked address — which is the incident with extra steps. 'opening_amount' is what an
      -- operator standing in front of a freeze needs in order to answer "was this address booked,
      -- and for how much" without reading the ledger, and 'opening_observed_block' is the height
      -- the indexer measured it at, so the two numbers can be compared against one another rather
      -- than taken on trust.
      alter table treasuries add column if not exists opening_amount          numeric(78,0);
      alter table treasuries add column if not exists opening_entry_id        text;
      alter table treasuries add column if not exists opening_observed_block  bigint;
      alter table treasuries add column if not exists opening_booked_at       timestamptz;

      -- ── THE BACK-FILL, WHICH IS THE DANGEROUS PART OF THIS MIGRATION ────────────────────────
      --
      -- ember/mainnet is ALREADY registered and its float has ALREADY been booked, by hand, as a
      -- 'reconciliation_correction' on 2026-08-08 that took custody from 99979000000004000 to
      -- 25100000000000000000 and lifted the freeze. Without this statement the new code would find
      -- 'opening_booked_at is null' on that row and book the treasury a SECOND time — 25.1 EMBER
      -- of custody that no coin backs, drift in the opposite direction, and the same asset frozen
      -- again by the fix for the freeze.
      --
      -- The predicate is 'indexer_watched_key is not null': a row this service has successfully
      -- registered is one whose balance the aggregate has already been counting, so whatever
      -- reconciliation state exists for it is the state an operator has already settled. Rows that
      -- were never registered are left null and take the new path, which is what should happen.
      --
      -- 'opening_amount' and 'opening_entry_id' stay NULL for these rows on purpose. They are not
      -- known here, and inventing them would put a number in a column an operator reads as
      -- measured. The null says "booked before this column existed, look in the ledger", which is
      -- true, and 'opening_booked_at' carries the timestamp that makes it findable.
      update treasuries
         set opening_booked_at = coalesce(indexer_watched_at, now())
       where indexer_watched_key is not null
         and opening_booked_at is null;

      -- The job's access path for outstanding work, partial for the reason migration 7's is: in a
      -- healthy estate this index is empty and the query touches nothing.
      create index if not exists treasuries_unbooked_idx
        on treasuries (chain, network)
        where opening_booked_at is null;

      -- An amount without a booking is a half-written row, and a booking is never negative. Stated
      -- at the database because the alternative is trusting that every future path writes all four
      -- columns together, and the cost of one that does not is a treasury the estate believes is
      -- booked and is not.
      alter table treasuries
        add constraint treasury_opening_is_whole
        check (
          (opening_amount is null or opening_amount >= 0)
          and (opening_amount is null or opening_booked_at is not null)
          and (opening_entry_id is null or opening_booked_at is not null)
        );
    `,
  },
  {
    version: 11,
    name: 'treasury-derived-here',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- WHICH TREASURY ADDRESSES THIS SERVICE DERIVED ITSELF, WHICH IS THE ONLY CASE WHERE IT MAY
      -- STATE ANYTHING ABOUT THEIR PAST.
      --
      -- 'registerTreasuryWithIndexer' measures the address's balance BEFORE watching it, and that
      -- order is right: watching first leaves a window in which the indexer's custody aggregate
      -- counts the address and the ledger does not, which is drift, which freezes the asset — the
      -- incident migration 10 exists for. But on a UTXO chain the indexer derives a custody
      -- balance from its OWN walked record and refuses an address nobody has claimed a history
      -- floor for, because coin received below the first block it walked would be invisible and
      -- missing from the total (micro-org#252, 'indexer/src/custody.ts' on 'history_unknown').
      -- An unwatched address has made no claim. So on a chain walked from a cold-start height the
      -- measurement refuses, the watch never happens, and the job retries for ever.
      --
      -- Measured on mainnet on 2026-08-09. ltc/mainnet was provisioned at 00:29:39; the indexer's
      -- LTC record starts at block 3154639; every pass of 'treasury.watch' from then until
      -- 00:44 logged 'IndexerUnavailableError: GET /v1/custody/ltc/mainnet/addresses/ltc1qswwly0…
      -- → 503'. The treasury could not be registered or booked at all without an operator watching
      -- it by hand, and an unregistered treasury is exactly the invisible-to-solvency state
      -- migration 7 was written to end.
      --
      -- ── WHY A NEW COLUMN AND NOT A LOOSER CLAIM ─────────────────────────────────────────────
      --
      -- The indexer accepts 'freshlyDerived: true' from a registrar that has JUST DERIVED THE KEY,
      -- because nothing can have paid an address that did not exist. 'treasury.ts' said in as many
      -- words that this service can never make that claim — "a treasury address is PINNED by an
      -- operator, not minted by this service: it may be years old" — and for an ADOPTED pin that
      -- is still exactly true and this migration does not change it.
      --
      -- It is not true of 'provisionTreasury', which mints the address through custody in the same
      -- call that pins it. There this service IS the party that derived the key, and it is the
      -- only party that can say so. The column records WHICH address that was, as an address_key
      -- and not a boolean, for migration 7's reason: a later rotation onto an address an operator
      -- pinned from elsewhere must not inherit a claim that was made about a different key. The
      -- comparison is 'derived_here_key = address_key' and a rotation simply fails it.
      --
      -- Null everywhere on arrival, including on rows this service really did mint before this
      -- column existed. That is deliberate: the fact was not recorded at the time and cannot be
      -- reconstructed from anything in this database, so back-filling it would be a guess wearing
      -- a measurement's clothes. The consequence of the null is the old behaviour — an operator
      -- states 'historyFromHeight' by hand — which is where those rows already are.
      alter table treasuries add column if not exists derived_here_key text;

      -- A claim about a key this row no longer holds is not evidence, but it is also not a fault:
      -- a rotation legitimately leaves the old key behind here. So this is not a foreign key onto
      -- 'address_key' and there is no constraint tying them together; the read compares them and
      -- treats a mismatch as no claim, which is what 'indexer_watched_key' already does.
      -- One string literal and not a concatenation: 'comment on' takes a string CONSTANT, and
      -- Postgres refuses '…' || '…' here with a syntax error at the first pipe.
      comment on column treasuries.derived_here_key is 'The address_key this service derived through custody itself, in the provision call that pinned it. Equal to address_key means this service may tell the indexer freshlyDerived; anything else, including null, means it may not.';
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
