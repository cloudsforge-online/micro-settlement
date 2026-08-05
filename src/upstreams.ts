/**
 * The three peers, and the credential this service presents to all of them.
 *
 * ── THE TEN-MINUTE CLIFF, IN THE SERVICE THAT BROADCASTS MONEY ─────────────────────────────────
 *
 * This is `micro-wallet`'s `upstreams.ts` defect, still live here months after wallet fixed it:
 *
 *     const token = () => env.serviceToken        // index.ts:83, before this change
 *
 * A function called per request, so that a short-TTL token could rotate without a restart —
 * returning a string read ONCE AT BOOT from a token that expires in 600 seconds
 * (`identity/src/tokens.ts:28`). Ten minutes into every deployment, every call to custody, the
 * indexer and the ledger began answering 401, for ever, until somebody restarted the container
 * with a hand-minted token that would itself die ten minutes later.
 *
 * **It was measured on the mainnet estate, not inferred.** `identity.service_token_issues` held
 * ONE row for `settlement`, dated 2026-08-04 15:12:06 — the bootstrap's own exchange — against 233
 * for wallet and 105 for the ledger, which had both migrated. Every treasury-watch tick since had
 * logged `CustodySignRefusedError: a valid bearer token is required` from `treasuryPin` on all four
 * chains, and that 401 is the whole of what `micro-org#174` observed at the surface: settlement
 * could not read custody's treasury pin, so it could not have paid a withdrawal even once one was
 * pinned.
 *
 * ── WHY THIS IS A MODULE AND NOT TWENTY LINES OF `index.ts` ────────────────────────────────────
 *
 * Because the defect is a WIRING defect, and wiring that lives in the composition root is wiring no
 * test can reach: importing `index.ts` opens a pool, asserts a schema, seeds jobs and calls
 * `listen()`. A suite full of tests that each build their own client proves the CLIENT works; only
 * a test that goes through this function proves the SERVICE uses it. `servicetoken.test.ts` is that
 * test, and it is the reason this file exists as a file.
 *
 * ── WHERE THE CREDENTIAL COMES FROM, AND WHY TWO VARIABLES ARE READ ────────────────────────────
 *
 * `SETTLEMENT_IDENTITY_CREDENTIAL` is the estate's name for it and is preferred whenever it is set.
 * `estate-bootstrap.sh` has been minting it into `compose/estate/tokens.env` all along.
 *
 * But settlement's compose block never referenced it — it passes only `SETTLEMENT_SERVICE_TOKEN` —
 * so on the live estate the minted credential reaches no container. Rather than make the repair
 * depend on a deploy edit landing first, `SETTLEMENT_SERVICE_TOKEN` is ALSO accepted when its value
 * carries the `cfsc_` credential prefix. The prefix is unambiguous: identity issues credentials with
 * it and tokens are JWTs, which begin `eyJ`. So an operator can close the cliff by changing one
 * VALUE in `tokens.env`, and the tidier deploy change — passing `SETTLEMENT_IDENTITY_CREDENTIAL`
 * through, as wallet's and the ledger's blocks already do — remains strictly better and is what the
 * variable above is for.
 *
 * A `SETTLEMENT_SERVICE_TOKEN` that is a genuine JWT is reported at boot and otherwise IGNORED. It
 * cannot be used: it is the ten-minute token, and using it is the defect.
 *
 * ── ONE PROVIDER FOR ALL THREE ─────────────────────────────────────────────────────────────────
 *
 * For the same reason there was one token: it is minted for `service:settlement` with the scopes
 * settlement needs — `custody:sign:deposit`, `custody:sign:treasury`, `custody:treasury:read`,
 * `indexer:read`, `indexer:write`, `ledger:post` — and each peer checks the one it cares about.
 * Three providers would be three exchanges and three refresh schedules against one identity for one
 * process.
 *
 * ── BOTH HOOKS, AND THE SECOND IS NOT DECORATION ───────────────────────────────────────────────
 *
 * `token` keeps the credential fresh on a schedule. `authorizedFetch` catches a 401 from a peer,
 * re-mints and replays once. Without the second, correctness would depend on this process and the
 * peer agreeing about what time it is — and this process signs transactions, so "the clocks
 * disagreed" must not be able to become "the withdrawal was refused".
 */

import {
  ServiceTokenProvider,
  ServiceTokenUnavailableError,
  type ProviderEvent,
} from '@cloudsforge/auth'
import { httpCustodyClient, type CustodyClient } from './custodyclient.ts'
import { httpIndexerClient, type IndexerClient } from './indexerclient.ts'
import { httpLedgerClient, type LedgerClient } from './ledgerclient.ts'
// TYPE-ONLY, and that matters. `./env.ts` validates the process environment at import and calls
// `process.exit(1)` when it is incomplete, so a value import here would make this module — and
// therefore every test of the wiring in it — impossible to load without a full environment. That is
// the same "untestable therefore unchecked" property that let the cliff survive.
import type { Env } from './env.ts'

export interface Upstreams {
  /**
   * `null` when no credential is configured. Handed to `serviceTokenProbe`, which reports that as a
   * hard readiness failure — the image must be able to BOOT without one so CI can smoke-test
   * `/livez`, but a replica in that state must never take traffic.
   */
  readonly identityTokens: ServiceTokenProvider | null
  readonly custody: CustodyClient
  readonly indexer: IndexerClient
  readonly ledger: LedgerClient
}

export interface UpstreamOptions {
  /** This service's name, for the ledger's `originating-service` header. `SERVICE` from `env.ts`. */
  readonly originatingService: string
  /** Test seam. Production uses the global `fetch`. */
  readonly fetch?: typeof globalThis.fetch | undefined
  readonly onEvent?: ((event: ProviderEvent) => void) | undefined
}

/** The subset of `Env` this needs. Named so a test does not have to build a whole environment. */
export type UpstreamEnv = Pick<
  Env,
  | 'identityUrl'
  | 'identityCredential'
  | 'custodyUrl'
  | 'indexerUrl'
  | 'ledgerUrl'
  | 'upstreamDeadlineMs'
>

export function buildUpstreams(env: UpstreamEnv, options: UpstreamOptions): Upstreams {
  const identityTokens = env.identityCredential
    ? new ServiceTokenProvider({
        identityUrl: env.identityUrl,
        credential: env.identityCredential,
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(options.onEvent ? { onEvent: options.onEvent } : {}),
      })
    : null

  /**
   * What every peer client asks for the `Authorization` header.
   *
   * Rejects rather than resolving `undefined` when there is no credential. `HttpClient` omits the
   * header entirely for `undefined`, so the request would go out unauthenticated and come back 401
   * — telling an operator that custody rejected settlement, when the truth is that nobody
   * configured settlement. `ServiceTokenUnavailableError` is 503 under `statusFor`, which is the
   * same answer the estate already gives when a verifier is unreachable and for the same reason.
   */
  const token = (): Promise<string> =>
    identityTokens
      ? identityTokens.token()
      : Promise.reject(new ServiceTokenUnavailableError('no identity credential is configured'))

  // The provider's own `fetch` is the transport it exchanges over. `authorizedFetch` is what the
  // peer clients get, and it is the layer where a 401 is visible and where the header was set — so
  // hooking it needs no change at any call site and cannot be forgotten at one of them.
  const peerFetch = identityTokens?.authorizedFetch ?? options.fetch
  const common = {
    deadlineMs: env.upstreamDeadlineMs,
    token,
    ...(peerFetch ? { fetch: peerFetch } : {}),
  }

  return {
    identityTokens,
    custody: httpCustodyClient({ baseUrl: env.custodyUrl, ...common }),
    indexer: httpIndexerClient({ baseUrl: env.indexerUrl, ...common }),
    ledger: httpLedgerClient({
      baseUrl: env.ledgerUrl,
      originatingService: options.originatingService,
      ...common,
    }),
  }
}
