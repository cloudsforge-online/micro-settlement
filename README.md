# settlement

[![ci](https://github.com/cloudsforge-online/micro-settlement/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-settlement/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![tests](https://img.shields.io/badge/tests-real%20Postgres-4169E1?logo=postgresql&logoColor=white)](./.github/workflows/ci.yml) [![licence](https://img.shields.io/badge/licence-MIT-blue)](./LICENSE)

The outbound chain service. Treasuries, sweeps, outbound transaction building, signing requests,
broadcast, confirmation tracking and stuck adjudication.

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

**This is where a bug loses a customer's money permanently.** Its central property is not a feature.

---

## The one property that matters

**One in-flight outbound transaction per `(chain, network)`, by construction.**

The estate this replaces has a withdrawal worker that guards itself with `hasUnsettledOutbound()`,
an **unlocked read**, so two workers both pass it. Its `markWithdrawalSigned` then protects a single
row perfectly — and that is not enough, because **the contended resource is not the row, it is the
chain's nonce**. Two *different* pending withdrawals each pass their own guard, each read
`eth_getTransactionCount`, each get the same answer. At most one can ever be mined. The other is a
payment that has been debited, signed, broadcast and lost.

A per-row lease would not have stopped it. A per-row lease is what it already had.

So there are two defences here, and they fail separately:

| | What it is | What it catches |
|---|---|---|
| **The lease** | `chain.outbound`, keyed **`chain:network`** (`src/jobs.ts`) | Two replicas polling at once. `for update skip locked` hands the job to exactly one. |
| **The index** | `outbound_in_flight_uniq`, partial unique on `(chain, network)` where `state in ('building','signed','broadcast')` (`src/migrations.ts`) | Everything that defeats a lease — clock skew past `locked_until`, a handler that outruns its lease, an operator running a script beside the workers. The second writer gets a 23505 and **no signature is requested at all**. |

`src/concurrency.test.ts` proves both, and the second test removes the lease from the picture
entirely and drives two workers straight at `driveChain` with an interleaving hook, which is the
strictly harder case.

## The order of operations

```
claim the row → read the nonce → ask custody → COMMIT THE BYTES → broadcast
```

**The signed raw transaction is committed before anything is broadcast.** A crash before the commit
has broadcast nothing, so the signature is discarded unbroadcast and the next tick starts again from
a fresh nonce read. A crash *after* it leaves a `signed` row with `raw_tx` on it, and the next tick
**resumes at broadcast** — there is no path anywhere in `src/worker.ts` from `signed` back to
`building`.

The alternative loses money in a way nothing can recover: a crash after broadcast but before the
write leaves a transaction on chain that the database does not know about. No id to poll, nothing to
reconcile, and indistinguishable from a payment that never happened.

## Giving money back

Every giving-up decision is split by **whether a signature exists**, and the split is enforced by
the SQL rather than by discipline at the call sites:

* `markFailed` moves **only** `planned` and `building`. Nothing was signed on either, so a refund is
  unconditionally safe. It is the only path that ever emits `refundable: true` on its own.
* `markStuck` moves **only** `signed` and `broadcast`. A call for a `planned` row updates no row —
  deliberately a silent no-op, so that the meaning of `stuck` ("bytes exist and may still land")
  cannot drift as call sites are added.
* **A `stuck` transaction is never auto-refunded.** It leaves that state only through
  `resolveWithProof`, which takes a sentence saying why the bytes can never apply and stores it in
  `outbound_adjudications` in the same transaction that moves the state.

There are exactly two callers of `resolveWithProof`, and they differ only in where the proof came
from: the worker, when the chain itself reports the transaction as applied-and-failed; and
`src/adjudicate.ts`, when an operator asks and `OutboundChain.proveDead` agrees.

**Absence never refunds.** On an EVM chain "no receipt" means only "this node has no receipt for
that hash" — the nonce is unconsumed, a legacy transaction has no expiry, and any node still holding
the bytes can mine them months later. The proof is that the sending account's nonce has moved past
the one inside them, read at `latest` and never at `pending`. An unreachable node is a refusal too.

## Routes

| | |
|---|---|
| `GET /livez` `GET /readyz` `GET /metrics` | Rule 4. |
| `GET /v1/fees/:chain/:network/:asset` | The live fee, in the shape `wallet/src/settlement.ts` already declares. |
| `POST /v1/events` | `wallet.withdrawal.requested`. Signature verified **before the body is parsed**, under the contract's `cf-signature` scheme or wallet's pre-contract one — see `verifyInbound`. |
| `GET /v1/outbound?state=stuck` | The queue an operator works from. |
| `GET /v1/outbound/:id` | One transaction. The **nonce** is published; the **bytes** never are. |
| `POST /v1/outbound/:id/adjudicate` | **The route that had to exist.** Administrator only. |
| `GET /v1/chains/:chain/:network/in-flight` | What holds this chain's nonce. At most one, by construction. |
| `GET /v1/treasuries` · `POST /v1/treasuries/:chain/:network/provision` | Mint and pin **through custody**, with the operator's own token. |
| `POST /v1/sweep-sources` | wallet registering a deposit address, with its custody binding. |

Adjudication is administrator-only and there is **no force flag**. The genuine break-glass case is an
engineer looking at the row, not a button — a button would be the path of least resistance at
exactly the moment somebody is under pressure to clear an alert.

## Treasuries

One address per `(chain, network)`, **minted and pinned through custody**. This service *cannot*
mint or pin one with its own credential and must not be able to: custody's mint and pin routes are
administrator-only precisely so that a signing credential can never influence the pin. `POST
/v1/treasuries/:chain/:network/provision` forwards the operator's bearer token verbatim.

Nothing sweeps to an unpinned candidate, and nothing sweeps at all while the pin and the payout row
disagree.

### The treasury must be in the indexer's custody set, and until now it never was

`micro-indexer` serves the number `micro-ledger` reconciles the platform's solvency against — Σ
confirmed native balance over `watched_addresses` whose label carries a platform prefix, default
`deposit:,treasury:`. `micro-wallet` writes the first for every deposit address. **Nothing in the
estate had ever written the second**, and this service is the one that moves coin out of an address
counted by that sum and into one that is not.

So every sweep shrank the aggregate while the ledger's custody total stood still — a *positive*
drift, which is the reading that **freezes withdrawals**. The direction was the safe one and the
outcome was a certainty rather than a risk: consolidating deposits is what a treasury is for.

`treasury.watch` is a leased recurring job, one per chain, every five minutes. It adopts the pin,
registers the address under `treasury:<chain>:<network>`, and writes the `address_key` it
registered — not a timestamp, because a rotation overwrites the key in place and a timestamp set
for the old address would report the new treasury as done and leave it invisible for ever. It is
its own kind rather than a step in `chain.sweep`, because a treasury holds coin whether or not
`SWEEP_ENABLED` is set. `registerTreasuryWithIndexer` records the registration only after the
indexer has accepted it; nothing is ever un-watched.

No backfill is needed and none exists: the aggregate reads a live balance at a confirmed height
rather than replaying movements, so a treasury that has been accumulating swept coin for months
becomes fully visible on the next observation after it registers.

This is why `INDEXER_SCOPES` carries `indexer:write`. The grant is derived from that constant by
`deploy/scripts/derive-grants.mjs`; it is not added by hand.

## Sweeps

Deposit address → the pinned treasury, as an `outbound_transaction` with `purpose: 'sweep'` on the
same lease and the same in-flight index. **The float target is zero unless an operator names one**,
so the sweeper is demand-driven: every coin in the treasury is inside the blast radius of the
signing credential and every coin left in a deposit address is outside it. `sweep_sources.swept`
advances at confirmation and never at broadcast.

### ERC-20 sweeps are two transactions, in order

A token balance sits at a deposit address whose native balance is zero — the sender paid the gas —
so moving it needs the address funded first. That is **two** `outbound_transactions`, planned in one
database transaction:

| # | `purpose` | from → to | shape |
| --- | --- | --- | --- |
| A | `gas_topup` | treasury → the deposit address, native value | custody's `transfer` |
| B | `token_sweep` | the deposit address → the token contract, calldata `transfer(<pin>, amount)` | custody's `token_sweep` |

B carries `depends_on = A.id` and **cannot be built until A has `confirmed`** — not merely
broadcast, because a node that has accepted bytes can still drop them. `nextPlanned` skips a blocked
row and the trigger `outbound_dependency_confirmed_trg` refuses the transition anyway, which is the
same relationship `outbound_in_flight_uniq` has to the chain lease: the query is the design, the
constraint is what makes it true when something reaches a row by another route.

Both rows are written at once so there is **no window** in which the top-up exists and its sweep
does not. The naive shape — "plan the sweep when the top-up confirms" — double-funds on a crash in
that gap, because the token balance the planner keys on does not change when gas arrives.

`to_address` is the treasury on both, because it means WHO IS PAID; the contract has a column of its
own. `outbound_token_contract_ck` makes that column present if and only if the purpose is
`token_sweep`.

**`SETTLEMENT_TOKEN_SWEEP_ENABLED` is off by default and must stay off until `micro-wallet` credits
token deposits.** Wallet currently refuses them (`token_deposit_unsupported`) because it has no
decimals registry, and that refusal is correct. Sweeping a balance the ledger has recorded no
liability for moves customer money into the treasury with no record that it is owed and no
withdrawal path to pay it back — leaving the tokens at the deposit address is strictly safer. See
`env.ts` on `tokenSweepEnabled` for the full argument.

## Chains

`ember` and `eth` are one implementation (`src/evm.ts`); `btc` and `ltc` are another
(`src/bitcoin.ts`) and `sol` is `src/solana.ts`. `xrp` is a **real object on the real interface that
throws `NotImplementedError` naming its phase** — not absent from the registry, not a stub returning
zero. `chainFor` is total, so an unsupported chain is a classified, immediately-refunded build
failure rather than a `TypeError` in a job handler.

**Litecoin is `bitcoinChain('ltc')` — the same code, and deliberately not the same constants.** It
speaks the same JSON-RPC and has the same transaction structure, so the follower, the coin selector,
the PSBT encoder and the UTXO death proof are reused unchanged. What the chain argument selects is
everything that is a property of the chain rather than of the software:

| | BTC | LTC | why it is not shared |
|---|---|---|---|
| bech32 HRP | `bc` / `tb` | `ltc` / `tltc` | the HRP is inside the checksum, so this is a binding |
| P2PKH / P2SH version | 0 / 5 | 48 / 50 | Core encodes `SCRIPT_ADDRESS2` 50, not the 5 it also decodes |
| confirmations | 6 | **12** | ~2.5-minute blocks on a fraction of the hashrate |
| dust threshold | 546 | **5,460** | `DUST_RELAY_TX_FEE` is 3,000 against 30,000 |
| supply cap | 21e6 | 84e6 | a sanity bound on a node's JSON answer |

The dust threshold is the one where copying Bitcoin's number is not merely inaccurate: 546 sits
*below* Litecoin's real threshold, so a change output between the two would be built, signed, and
refused by every node as `dust` — a broadcast failure after a signature. The fee ceilings are
deliberately NOT per-chain, because custody's are not; see `assertUnderCustodysCeiling`.

**Taproot destinations are refused on both chains.** `bitcoinjs-lib` routes witness version 1
through `p2tr`, which throws without `initEccLib`, and nothing in this estate calls it — not this
service, which has no secp256k1 package, and not custody, which has one it never initialises. So a
`bc1p…` or `ltc1p…` address cannot be built for or signed, and `wallet` refuses one at request time
rather than reserving a balance against it. Making them payable means a native binding in both
services, for a destination form rather than a chain; it was not done in the change that found it.

A withdrawal and a sweep are built to **different shapes**, because custody applies a different
signing policy to each: a sweep's destination is chosen by the vault and not by this service, and on
Bitcoin that means a PSBT with no change output at all. `BuildInput.shape` is how the adapter is
told which, and `worker.signingPolicy` returns it beside the purpose claimed to custody so the two
cannot disagree.

**XRP is the only chain left, and the gap is on THIS side** — custody signs it today, with a payment
shape and a pinned sweep shape. What is missing here is an XRPL adapter: an XRP blob carries a
`Sequence` and a `LastLedgerSequence` that must be committed beside the bytes to be adjudicable at
all, and a half-implementation that signs without recording them produces payments no operator can
ever settle.

This section previously said BTC and SOL "can currently be neither withdrawn nor swept, and that is
custody's limitation". **Every clause of that was wrong or went stale**, and the way each one failed
is recorded at the head of `src/chains.ts` and `src/registry.ts` rather than deleted — the BTC claim
misread a real gate that was conditioned on `purpose === 'deposit'`, and the SOL claim was true when
written and was never re-checked.

## Running it

```sh
pnpm install
pnpm typecheck
pnpm test          # DB tests skip without SETTLEMENT_TEST_DATABASE_URL
pnpm migrate       # the one-shot migrator; never called by the service
pnpm start
```

**No test broadcasts to a real network.** Every chain call in every test goes through `fakeNode` in
`src/testsupport.ts`, an in-memory EVM node. The local Hearth testnet on `127.0.0.1:8545` may be
read; it is never sent to. `scripts/upstreams.ts` stands up local stubs for identity, custody, the
indexer, the ledger and a fake chain so the real service can be booted and driven by hand.

### Rotating the outbox secret

| Variable | | |
| --- | --- | --- |
| `OUTBOX_SIGNING_SECRET` | required | The key this service **signs** its own outbox deliveries with. One key, always. |
| `OUTBOX_ACCEPT_SECRETS` | optional | Comma-separated, **newest first**. The keys `POST /v1/events` will **accept**, under *both* inbound schemes. Defaults to `[OUTBOX_SIGNING_SECRET]`. |

`OUTBOX_SIGNING_SECRET` is one HMAC key shared across the estate, so replacing it is a rolling
change or it is an outage. `wallet.withdrawal.requested` is this service's **only** inbound topic:
the instant wallet's relay adopts the new key, a receiver that accepts only the old one 401s every
delivery and wallet retries for ever — withdrawals reserved and never built, silently, with a green
`/livez`.

`OUTBOX_ACCEPT_SECRETS` is the overlap window. Set it to `new,old`, redeploy wallet, then drop
`old`. Both arms of `verifyInbound` try every candidate, the contract's and the pre-contract one,
because the pre-contract arm is the one wallet's relay is still on — widening only the first would
be the same partition in disguise. Each entry gets the same checks as the signing secret: no
placeholders, at least 24 characters, and a repeated entry is refused because it makes "which key
verified this" ambiguous. `settlement_event_signatures_total{scheme}` still separates `contract`
from `legacy`. Leaving the variable unset is exactly today's behaviour.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
