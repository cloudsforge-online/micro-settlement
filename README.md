# settlement

The outbound chain service. Treasuries, sweeps, outbound transaction building, signing requests,
broadcast, confirmation tracking and stuck adjudication.

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
| `POST /v1/events` | `wallet.withdrawal.requested`. HMAC verified **before the body is parsed**. |
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

## Sweeps

Deposit address → the pinned treasury, as an `outbound_transaction` with `purpose: 'sweep'` on the
same lease and the same in-flight index. **The float target is zero unless an operator names one**,
so the sweeper is demand-driven: every coin in the treasury is inside the blast radius of the
signing credential and every coin left in a deposit address is outside it. `sweep_sources.swept`
advances at confirmation and never at broadcast.

## Chains

`ember` and `eth` are one implementation (`src/evm.ts`). `btc`, `sol` and `xrp` are **real objects on
the real interface that throw `NotImplementedError` naming their phase** — not absent from the
registry, not stubs returning zero. `chainFor` is total, so an unsupported chain is a classified,
immediately-refunded build failure rather than a `TypeError` in a job handler.

BTC and SOL can currently be neither withdrawn nor swept, and that is **custody's** limitation and a
deliberate one: `signBitcoin`'s sweep output policy is specified and not built, and `signSolana` has
no transfer shape at all, so `gates.SWEEPABLE_FAMILIES` refuses a `deposit`-purpose address in both
families before anything is decrypted. XRP is the opposite case — custody signs it today — and the
gap is this service not yet speaking XRPL.

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
