/**
 * Custody, as this service uses it.
 *
 * **This service holds no keys and asks for none.** It sends an unsigned transaction and receives
 * bytes. There is no method here that could return key material even if custody offered one, and
 * custody has exactly one route that returns any — the export ceremony's redemption — which needs
 * a user token and cannot be reached with the credential below.
 *
 * ## The binding is restated, and that is the awkward part of this interface
 *
 * `POST /v1/sign` takes SEVEN identity fields — `address`, `chain`, `network`, `family`, `purpose`,
 * `userId`, `orderId` — and compares all seven, character for character, against the row it holds
 * (`gates.bindingMatches`). Getting any one of them wrong is a 403 `binding_mismatch` whose message
 * deliberately does NOT say which field disagreed, because naming it would be an oracle a caller
 * could walk one field at a time. That is the right design and it means a caller cannot debug a
 * mismatch from the response; it has to be right by construction instead. So every binding this
 * service sends is DERIVED, never remembered:
 *
 *   * a treasury's is `treasuryBinding(chain, network)` in `treasury.ts`, which reproduces custody's
 *     own `keys.treasuryBinding` — `userId: 'cloudsforge:treasury'`, `orderId: 'treasury:<chain>:<network>'`
 *     — from the chain and network alone;
 *   * a deposit address's is stored on the `sweep_sources` row when wallet registers it, because
 *     the `userId` and `orderId` are wallet's assignment facts and there is nothing to derive them
 *     from here.
 *
 * The one field that is NOT this service's slug is `chain`. Custody's chain names are
 * `ethereum`/`bitcoin`/`solana`/`xrp`/`ember`; this service's are the asset code lowercased. They
 * agree on four of five, and `eth` versus `ethereum` is the fifth — see `custodyChainOf`.
 *
 * ## The pin can be read and never written, and that shapes `treasury.ts`
 *
 * `GET /v1/treasuries/:chain/:network` is on the signing surface. `PUT /v1/admin/treasuries/...`
 * and the mint route are on the ADMIN surface and take an operator's token, not a service token.
 * That asymmetry is custody's central defence for the sweep shape: "if that stopped being true the
 * sweep shape would become a total-loss vulnerability — anyone who can mint a `treasury` address
 * would pin their own and sweep every deposit to it". So this service **cannot mint or pin a
 * treasury with its own credential and must not be able to.** The two admin methods below forward
 * an operator's bearer token verbatim and never fall back to the service token; `server.ts` is
 * where that operator is authenticated.
 */

import { HttpClient, HttpError } from '@cloudsforge/http'
import type { ChainFamily, Network } from '@cloudsforge/contracts-chain'
import type { LiveScope } from '@cloudsforge/contracts-auth'

/**
 * The scopes this service's token must carry. Named here so the deploy can be derived from it.
 *
 * `custody:sign:treasury` pays withdrawals out of the treasury and `custody:sign:deposit` sweeps
 * into it. They are separate because they are different authorities: SDR-05 records that a holder
 * of the first can drain the treasury (a withdrawal must be payable to an address a user names),
 * while the second can only ever move money TOWARDS the pin. A deployment that does not sweep
 * should not be issued the second.
 *
 * ── THE ANNOTATION: AN OUTBOUND DEMAND, TYPED AGAINST THE REGISTRY ───────────────────────────
 *
 * `readonly LiveScope[]`, not `readonly string[]`. `service-ci.yml` proves that every scope a
 * repository's route GATES demand is registered — the INBOUND direction. This constant is the
 * other one: what this service PRESENTS to a peer. Nothing had ever checked it, which is how
 * `micro-market` declared `policy:evaluate` and `micro-wallet` `custody:address` — neither ever
 * a registry key — for the life of both services. `derive-grants.mjs` reads this into
 * `IDENTITY_SERVICE_TOKEN_GRANTS`, and identity validates that list at import and REFUSES TO
 * START on an unknown name (`identity/src/env.ts:141`): a dead identity container, so no tokens
 * for anybody.
 *
 * `LiveScope` rather than `Scope` because `Scope` is `keyof typeof SCOPES` — every registered
 * key, DEPRECATED ones included — and identity will not mint a deprecated scope either.
 * `LiveScope = Exclude<Scope, DeprecatedScope>`, with `DeprecatedScope` computed FROM `SCOPES` by
 * a conditional type over the `deprecated` field rather than hand-listed
 * (`contracts/packages/auth/src/index.ts:507`), so it cannot drift from the registry. `Scope`
 * keeps its wide meaning and this does not narrow it: a token arriving from anywhere may carry a
 * scope that has since died, so reading is wide and demanding is narrow. This is demanding.
 */
export const CUSTODY_SCOPES: readonly LiveScope[] = Object.freeze([
  'custody:sign:treasury',
  'custody:sign:deposit',
  'custody:treasury:read',
])

/** Custody looked at the request and refused it. Never retriable with the same request. */
export class CustodySignRefusedError extends Error {
  /** `purpose_forbidden · binding_mismatch · no_treasury_pinned · shape_refused · not_found`. */
  readonly code: string
  readonly status: number
  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'CustodySignRefusedError'
    this.code = code
    this.status = status
  }
}

/** Custody could not be reached, or answered 5xx. We do not know whether it signed. */
export class CustodyUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CustodyUnavailableError'
  }
}

/**
 * The seven identity fields plus the payload, exactly as `POST /v1/sign` wants them.
 *
 * `purpose` selects the signing POLICY, not a label: `treasury` signs plain value transfers and
 * cannot sign a creation, `deposit` signs a transfer whose destination custody itself chooses. A
 * mislabelled address is a 403 rather than a wider signature, which is what makes this field
 * load-bearing.
 */
export interface SignRequest {
  readonly address: string
  /** Custody's chain NAME, not this service's slug. `custodyChainOf` translates. */
  readonly chain: string
  readonly network: Network
  readonly family: ChainFamily
  readonly purpose: 'treasury' | 'deposit'
  readonly userId: string
  readonly orderId: string
  /**
   * Exactly what custody's signer receives. Extra fields are refused, not ignored.
   *
   * `unknown` because the shape is the family's: an object of allowlisted fields for EVM and XRP,
   * a base64 PSBT string for Bitcoin. See `UnsignedOutbound.payload`.
   */
  readonly payload: unknown
  /** Correlates the signature with the row it was made for, in custody's audit and ours. */
  readonly correlationId: string
}

export interface SignedResult {
  /** The serialised signed transaction. This is what gets committed, then broadcast. */
  readonly signedTx: string
  /** The id of the audit row custody committed with the signature. Stored beside the bytes. */
  readonly auditId: string
}

export interface TreasuryCandidate {
  readonly address: string
  readonly reused: boolean
}

export interface CustodyClient {
  sign(request: SignRequest): Promise<SignedResult>
  /** The address custody will accept as a sweep destination here. Null when nobody has pinned one. */
  treasuryPin(chain: string, network: Network): Promise<string | null>
  /** Mint a rotation candidate. **Does not pin it.** Requires an operator's token. */
  mintTreasury(chain: string, network: Network, operatorToken: string): Promise<TreasuryCandidate>
  /** Pin an address custody already holds the key to. Requires an operator's token. */
  pinTreasury(
    chain: string,
    network: Network,
    address: string,
    operatorToken: string,
  ): Promise<{ readonly address: string; readonly supersededAddress: string | null }>
}

export interface CustodyClientOptions {
  readonly baseUrl: string
  readonly token: () => Promise<string | undefined> | string | undefined
  readonly deadlineMs: number
  readonly fetch?: typeof globalThis.fetch
}

export function httpCustodyClient(options: CustodyClientOptions): CustodyClient {
  const client = new HttpClient({
    baseUrl: options.baseUrl,
    name: 'custody',
    defaultDeadlineMs: options.deadlineMs,
    token: options.token,
    ...(options.fetch ? { fetch: options.fetch } : {}),
  })

  return {
    async sign(request) {
      try {
        // NO IDEMPOTENCY KEY, and its absence is deliberate. `HttpClient` attempts a POST exactly
        // once unless a key is present, which is precisely what is wanted here: a retried signature
        // would consume a second `custody_signatures_total` and, more to the point, this service
        // must never be in a position where two sets of bytes exist for one row. A signature that
        // was made and whose response was lost is discarded UNBROADCAST — nothing was sent, so
        // nothing moved — and the next tick builds again from a fresh nonce read.
        const body = await client.request<SignedResult>('/v1/sign', {
          method: 'POST',
          body: {
            address: request.address,
            chain: request.chain,
            network: request.network,
            family: request.family,
            purpose: request.purpose,
            userId: request.userId,
            orderId: request.orderId,
            payload: request.payload,
          },
          requestId: request.correlationId,
        })
        if (typeof body.signedTx !== 'string' || body.signedTx.length === 0) {
          throw new CustodyUnavailableError('custody answered 200 with no signature')
        }
        return body
      } catch (err) {
        throw translateSign(err)
      }
    },

    async treasuryPin(chain, network) {
      try {
        const body = await client.get<{ address: string }>(`/v1/treasuries/${chain}/${network}`)
        return body.address
      } catch (err) {
        // A 404 is an ANSWER, not a fault: nobody has pinned this chain. Collapsing it into an
        // unavailability would make an unconfigured chain look like an outage and would be retried
        // for ever at error level.
        if (err instanceof HttpError && err.status === 404) return null
        throw translateSign(err)
      }
    },

    async mintTreasury(chain, network, operatorToken) {
      try {
        const body = await client.request<{ key: { address: string }; reused: boolean }>(
          `/v1/admin/treasuries/${chain}/${network}/mint`,
          {
            method: 'POST',
            body: {},
            // The OPERATOR's token, overriding the client's own. This route is admin-only on
            // custody's side and must stay that way: a service credential that could mint a
            // treasury is one step from a service credential that could pin one.
            headers: { authorization: `Bearer ${operatorToken}` },
          },
        )
        // Custody is deliberately idempotent here — everything it writes is derived from the path,
        // so two calls a minute apart are the same request and the second returns the outstanding
        // candidate with `reused: true`. Carried through rather than hidden, because an operator
        // rotating a treasury needs to know whether they just created a key or found one.
        return { address: body.key.address, reused: body.reused === true }
      } catch (err) {
        throw translateSign(err)
      }
    },

    async pinTreasury(chain, network, address, operatorToken) {
      try {
        const body = await client.put<{ address: string; supersededAddress: string | null }>(
          `/v1/admin/treasuries/${chain}/${network}`,
          { address },
          { headers: { authorization: `Bearer ${operatorToken}` } },
        )
        return { address: body.address, supersededAddress: body.supersededAddress ?? null }
      } catch (err) {
        throw translateSign(err)
      }
    },
  }
}

/**
 * Turn an HTTP failure into one of the two things a caller can act on.
 *
 * `HttpError.peerDecided` is the discriminator: a 4xx means custody looked at the request and said
 * no, which is a permanent fact about this request and must not be retried. Anything else — 5xx, a
 * timeout, an open circuit — means we do not know whether it signed, and the only safe response is
 * to leave the row where it is and try again on the next tick. The distinction matters more here
 * than anywhere else in this service: a "refusal" that was really a timeout would refund a
 * withdrawal whose signature may exist.
 */
function translateSign(err: unknown): Error {
  if (err instanceof HttpError && err.peerDecided) {
    const parsed = parseError(err.body)
    return new CustodySignRefusedError(err.status, parsed.code, parsed.message)
  }
  if (err instanceof CustodyUnavailableError || err instanceof CustodySignRefusedError) return err
  return new CustodyUnavailableError(err instanceof Error ? err.message : String(err))
}

function parseError(body: string): { code: string; message: string } {
  try {
    const parsed: unknown = JSON.parse(body)
    const error = (parsed as { error?: { code?: unknown; message?: unknown } }).error
    return {
      code: typeof error?.code === 'string' ? error.code : 'custody_error',
      message: typeof error?.message === 'string' ? error.message : body.slice(0, 500),
    }
  } catch {
    return { code: 'custody_error', message: body.slice(0, 500) }
  }
}
