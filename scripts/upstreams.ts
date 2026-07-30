/**
 * The upstreams settlement needs, as local stubs, so the real service can be booted and driven.
 *
 * This is NOT part of the service and it is NOT a test double the suite uses — `src/testsupport.ts`
 * is that, and it fakes at the JSON-RPC seam so the real adapter is under test. This file exists for
 * one purpose: to let a person start `src/index.ts` unmodified, with its real composition root, its
 * real job runner and its real HTTP surface, and watch a withdrawal go all the way through.
 *
 * **The chain here is a fake and nothing in this file talks to a real network.** The local Hearth
 * testnet on 127.0.0.1:8545 may be read; it is never sent to, and this stub is what stands in its
 * place so that a demonstration cannot become a broadcast.
 *
 * Five servers:
 *
 *   identity  a JWKS and a matching admin token, so the operator routes can be reached.
 *   custody   mint, pin, read-the-pin and sign. The signer assembles REAL legacy RLP, because two
 *             production functions read those bytes back — the transaction id and the nonce.
 *   indexer   404 for every hash, which is the honest state of a transaction broadcast a second
 *             ago and the state that makes settlement fall through to the node.
 *   ledger    accepts entries and remembers their idempotency keys.
 *   chain     an in-memory EVM node over JSON-RPC.
 *
 * Run it, and it prints the environment and the admin token on stdout as JSON.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { generateKeyPair, exportJWK, SignJWT } from 'jose'
import { fakeLegacyTx } from '../src/testsupport.ts'
import { canonicaliseEvm } from '../src/evm.ts'
import { keccak256 } from '../src/keccak.ts'

const PORTS = { identity: 4401, ledger: 4404, custody: 4405, indexer: 4406, chain: 4445 } as const

type Handler = (
  method: string,
  path: string,
  body: string,
) => { status: number; body: unknown } | Promise<{ status: number; body: unknown }>

function serve(port: number, name: string, handle: Handler): Promise<void> {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      void (async () => {
        const raw = Buffer.concat(chunks).toString('utf8')
        try {
          const reply = await handle(req.method ?? 'GET', (req.url ?? '/').split('?')[0]!, raw)
          const payload = `${JSON.stringify(reply.body)}\n`
          res.writeHead(reply.status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) })
          res.end(payload)
        } catch (err) {
          const payload = `${JSON.stringify({ error: { code: 'stub_error', message: String(err) } })}\n`
          res.writeHead(500, { 'content-type': 'application/json' })
          res.end(payload)
        }
      })()
    })
  })
  return new Promise((resolve) => server.listen(port, () => {
    process.stderr.write(`[stub] ${name} listening on ${port}\n`)
    resolve()
  }))
}

/* ------------------------------------------------------------------ identity */

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
const jwk = { ...(await exportJWK(publicKey)), kid: 'demo', alg: 'RS256', use: 'sig' }
const ISSUER = `http://127.0.0.1:${PORTS.identity}`

const adminToken = await new SignJWT({ handle: 'demo-operator', roles: ['admin'] })
  .setProtectedHeader({ alg: 'RS256', kid: 'demo' })
  .setIssuer(ISSUER)
  .setAudience('cloudsforge')
  .setSubject('00000000-0000-4000-8000-00000000000a')
  .setIssuedAt()
  .setExpirationTime('2h')
  .sign(privateKey)

const walletToken = await new SignJWT({ scopes: ['settlement:read', 'settlement:register'] })
  .setProtectedHeader({ alg: 'RS256', kid: 'demo' })
  .setIssuer(ISSUER)
  .setAudience('cloudsforge')
  .setSubject('service:wallet')
  .setIssuedAt()
  .setExpirationTime('2h')
  .sign(privateKey)

await serve(PORTS.identity, 'identity', (_method, path) => {
  if (path === '/livez') return { status: 200, body: { ok: true } }
  return { status: 200, body: { keys: [jwk] } }
})

/* ------------------------------------------------------------------ the chain */

const balances = new Map<string, bigint>()
const nonces = new Map<string, number>()
const receipts = new Map<string, { block: bigint; reverted: boolean }>()
const sent: string[] = []
let head = 1_000n
const CHAIN_ID = 7412

const hexQuantity = (v: bigint) => `0x${v.toString(16)}`
const txHashOf = (rawTx: string) =>
  `0x${Buffer.from(keccak256(Buffer.from(rawTx.replace(/^0x/, ''), 'hex'))).toString('hex')}`

await serve(PORTS.chain, 'chain (fake EVM node)', (method, path, body) => {
  // A control surface, so the demonstration can mine a block or move a nonce without a miner.
  if (method === 'POST' && path === '/control/mine') {
    const { rawTx } = JSON.parse(body) as { rawTx: string }
    receipts.set(txHashOf(rawTx).toLowerCase(), { block: head, reverted: false })
    return { status: 200, body: { mined: txHashOf(rawTx), at: head.toString() } }
  }
  if (method === 'POST' && path === '/control/advance') {
    head += BigInt((JSON.parse(body) as { blocks: number }).blocks)
    return { status: 200, body: { head: head.toString() } }
  }
  if (method === 'POST' && path === '/control/nonce') {
    const { address, value } = JSON.parse(body) as { address: string; value: number }
    nonces.set(address.toLowerCase(), value)
    return { status: 200, body: { address, nonce: value } }
  }
  if (method === 'POST' && path === '/control/fund') {
    const { address, wei } = JSON.parse(body) as { address: string; wei: string }
    balances.set(address.toLowerCase(), BigInt(wei))
    return { status: 200, body: { address, balance: wei } }
  }
  if (path === '/livez') return { status: 200, body: { ok: true } }

  const request = JSON.parse(body) as { id: number; method: string; params: unknown[] }
  const ok = (result: unknown) => ({ status: 200, body: { jsonrpc: '2.0', id: request.id, result } })
  switch (request.method) {
    case 'eth_chainId':
      return ok(hexQuantity(BigInt(CHAIN_ID)))
    case 'eth_gasPrice':
      return ok(hexQuantity(20_000_000_000n))
    case 'eth_blockNumber':
      return ok(hexQuantity(head))
    case 'eth_getBalance':
      return ok(hexQuantity(balances.get(String(request.params[0]).toLowerCase()) ?? 0n))
    case 'eth_getTransactionCount':
      return ok(hexQuantity(BigInt(nonces.get(String(request.params[0]).toLowerCase()) ?? 0)))
    case 'eth_getCode':
      return ok('0x')
    case 'eth_sendRawTransaction': {
      const rawTx = String(request.params[0])
      if (sent.includes(rawTx)) {
        // What a real node says for bytes it already holds. The recovery path depends on it.
        return { status: 200, body: { jsonrpc: '2.0', id: request.id, error: { code: -32000, message: 'already known' } } }
      }
      sent.push(rawTx)
      process.stderr.write(`[stub] chain accepted ${txHashOf(rawTx)}\n`)
      return ok(txHashOf(rawTx))
    }
    case 'eth_getTransactionReceipt': {
      const receipt = receipts.get(String(request.params[0]).toLowerCase())
      return ok(
        receipt ? { blockNumber: hexQuantity(receipt.block), status: receipt.reverted ? '0x0' : '0x1' } : null,
      )
    }
    default:
      return { status: 200, body: { jsonrpc: '2.0', id: request.id, error: { code: -32601, message: request.method } } }
  }
})

/* ------------------------------------------------------------------ custody */

const pins = new Map<string, string>()
const signed: Array<Record<string, unknown>> = []
let minted = 0

await serve(PORTS.custody, 'custody', (method, path, body) => {
  if (path === '/livez') return { status: 200, body: { ok: true } }

  const treasuryMint = /^\/v1\/admin\/treasuries\/([^/]+)\/([^/]+)\/mint$/.exec(path)
  if (method === 'POST' && treasuryMint) {
    minted += 1
    const address = canonicaliseEvm(`0x${minted.toString(16).padStart(40, 'c')}`)
    // Deliberately NOT pinned here, exactly as custody does it: pinning at mint time would point
    // every future sweep at an address holding nothing.
    return { status: 201, body: { key: { address }, pinned: false, reused: false } }
  }

  const treasuryPin = /^\/v1\/admin\/treasuries\/([^/]+)\/([^/]+)$/.exec(path)
  if (method === 'PUT' && treasuryPin) {
    const key = `${treasuryPin[1]}:${treasuryPin[2]}`
    const previous = pins.get(key) ?? null
    const { address } = JSON.parse(body) as { address: string }
    pins.set(key, address)
    return { status: 200, body: { chain: treasuryPin[1], network: treasuryPin[2], address, supersededAddress: previous } }
  }

  const treasuryRead = /^\/v1\/treasuries\/([^/]+)\/([^/]+)$/.exec(path)
  if (method === 'GET' && treasuryRead) {
    const address = pins.get(`${treasuryRead[1]}:${treasuryRead[2]}`)
    if (!address) {
      return {
        status: 404,
        body: { error: { code: 'no_treasury_pinned', message: 'no treasury is pinned for this chain' } },
      }
    }
    return { status: 200, body: { chain: treasuryRead[1], network: treasuryRead[2], address } }
  }

  if (method === 'POST' && path === '/v1/sign') {
    const request = JSON.parse(body) as Record<string, unknown>
    // The seven identity fields custody compares character for character. A demonstration that did
    // not check them would hide the one class of bug this interface is shaped to catch.
    for (const field of ['address', 'chain', 'network', 'family', 'purpose', 'userId', 'orderId']) {
      if (typeof request[field] !== 'string') {
        return { status: 400, body: { error: { code: 'validation', message: `${field} is required` } } }
      }
    }
    const payload = request['payload'] as Record<string, unknown>
    const allowed = new Set(['to', 'data', 'value', 'nonce', 'gasLimit', 'chainId', 'type', 'maxFeePerGas', 'maxPriorityFeePerGas', 'gasPrice'])
    for (const key of Object.keys(payload)) {
      if (!allowed.has(key)) {
        return {
          status: 403,
          body: { error: { code: 'shape_refused', message: `evm payload carries a field this service does not sign: '${key}'` } },
        }
      }
    }
    if (Number(payload['chainId']) !== CHAIN_ID) {
      return { status: 403, body: { error: { code: 'binding_mismatch', message: 'sign request does not match this address' } } }
    }
    signed.push(request)
    process.stderr.write(`[stub] custody signed nonce ${String(payload['nonce'])} for ${String(request['purpose'])}\n`)
    return { status: 200, body: { signedTx: fakeLegacyTx(payload), auditId: `audit-${signed.length}` } }
  }

  return { status: 404, body: { error: { code: 'not_found', message: path } } }
})

/* ------------------------------------------------------------------ indexer and ledger */

await serve(PORTS.indexer, 'indexer', (_method, path) => {
  if (path === '/livez') return { status: 200, body: { ok: true } }
  // 404 for every hash: the honest state of a transaction broadcast a second ago, and the state
  // that makes settlement fall through to the node rather than reading an absence as "not on chain".
  return { status: 404, body: { error: { code: 'transaction_not_found', message: 'not indexed' } } }
})

const entries: Array<Record<string, unknown>> = []
await serve(PORTS.ledger, 'ledger', (method, path, body) => {
  if (path === '/livez') return { status: 200, body: { ok: true } }
  if (method === 'POST' && path === '/entries') {
    const entry = JSON.parse(body) as Record<string, unknown>
    entries.push(entry)
    process.stderr.write(`[stub] ledger posted ${String(entry['kind'])} key=${String(entry['idempotencyKey'])}\n`)
    return { status: 201, body: { entry: { id: `entry-${entries.length}`, kind: entry['kind'], recordedAt: new Date().toISOString() }, replayed: false } }
  }
  return { status: 404, body: { error: { code: 'not_found', message: path } } }
})

/* ------------------------------------------------------------------ the handover */

process.stdout.write(
  `${JSON.stringify(
    {
      adminToken,
      walletToken,
      env: {
        IDENTITY_JWKS_URL: `${ISSUER}/.well-known/jwks.json`,
        IDENTITY_ISSUER: ISSUER,
        CUSTODY_URL: `http://127.0.0.1:${PORTS.custody}`,
        INDEXER_URL: `http://127.0.0.1:${PORTS.indexer}`,
        LEDGER_URL: `http://127.0.0.1:${PORTS.ledger}`,
        SETTLEMENT_RPC_URLS: JSON.stringify({ ember: `http://127.0.0.1:${PORTS.chain}` }),
      },
      control: `http://127.0.0.1:${PORTS.chain}/control`,
    },
    null,
    2,
  )}\n`,
)
process.stderr.write('[stub] all upstreams ready\n')
