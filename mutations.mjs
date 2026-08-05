/**
 * Mutation testing for the two-phase token sweep.
 *
 * A test that cannot fail is not a test, and eight checks that could not fail have been found in
 * this estate. So each entry below WEAKENS one specific guarantee and names the test that must go
 * red because of it. A mutation that leaves the suite green is reported as a SURVIVOR: either the
 * guarantee is untested or the code is dead, and both are findings.
 *
 * Run: SETTLEMENT_TEST_DATABASE_URL=... node mutations.mjs
 *
 * Nothing here is left behind — every mutation is reverted before the next one is applied, and the
 * working tree is restored on exit including on a crash.
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

const MUTATIONS = [
  {
    name: 'nextPlanned offers a sweep whose gas has not confirmed',
    file: 'src/outbound.ts',
    from: `       and (
         o.depends_on is null
         or exists (
           select 1 from outbound_transactions d
            where d.id = o.depends_on and d.state = 'confirmed'
         )
       )`,
    to: `       and (o.depends_on is null or true)`,
    expect: 'will not offer the sweep to the worker until the top-up has confirmed',
  },
  {
    name: 'the dependency trigger permits any transition into building',
    file: 'src/migrations.ts',
    from: `        if dependency_state is distinct from 'confirmed' then`,
    to: `        if false then`,
    expect: 'refuses the transition into building at the database, not only in the query',
  },
  {
    name: 'the in-flight set forgets the address being funded',
    file: 'src/sweeps.ts',
    from: `    keys.add(row.from_address_key)
    keys.add(row.to_address_key)`,
    to: `    keys.add(row.from_address_key)`,
    expect: 'counts the destination of a funding row, not only its source',
  },
  {
    name: 'the in-flight set ignores planned rows, so a pair is planned twice',
    file: 'src/sweeps.ts',
    from: `       and purpose in ('sweep','token_sweep','gas_topup')
       and state in ('planned','building','signed','broadcast')
  \``,
    to: `       and purpose in ('sweep','token_sweep','gas_topup')
       and state in ('building','signed','broadcast')
  \``,
    expect: 'does not fund the same address twice while a pair is outstanding',
  },
  {
    name: 'a failed top-up leaves its sweep queued for ever',
    file: 'src/outbound.ts',
    from: `    await failDependents(tx, producer, failed.id, reason, events)`,
    to: `    void failDependents`,
    expect: 'fails the sweep with its top-up, in the same transaction',
  },
  {
    name: 'the calldata recipient keeps its checksum casing',
    file: 'src/evm.ts',
    from: `  const address = canonicaliseEvm(recipient).toLowerCase().slice(2)
  if (amount <= 0n) {`,
    to: `  const address = canonicaliseEvm(recipient).slice(2)
  if (amount <= 0n) {`,
    expect: 'is exactly 68 bytes, with a zero left-pad and the amount in the second word',
  },
  {
    name: 'a zero-amount token transfer is encoded rather than refused',
    file: 'src/evm.ts',
    from: `  if (amount <= 0n) {
    // Custody refuses this outright`,
    to: `  if (false) {
    // Custody refuses this outright`,
    expect: 'refuses a zero or negative amount, because a signature is permanent',
  },
  {
    name: 'an oversized amount is truncated into the ABI word instead of refused',
    file: 'src/evm.ts',
    from: `  if (value < 0n || value >= 1n << 256n) {
    throw new Error(\`\${value} does not fit in a uint256 ABI word\`)
  }
  return value.toString(16).padStart(64, '0')`,
    to: `  return (value & ((1n << 256n) - 1n)).toString(16).padStart(64, '0')`,
    expect: 'refuses an amount that does not fit a uint256 rather than truncating it',
  },
  {
    name: 'the locked fee is always divided by the native gas limit',
    file: 'src/evm.ts',
    from: `  gas: bigint = TRANSFER_GAS,
): bigint {`,
    to: `  gas: bigint = TRANSFER_GAS,
): bigint {
  gas = TRANSFER_GAS`,
    expect: 'recovers the gas price the fee was actually quoted at, per gas limit',
  },
  {
    name: 'an empty eth_call result is read as a zero balance',
    file: 'src/evm.ts',
    from: `  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(result)) {`,
    to: `  if (typeof result === 'string' && result === '0x') return 0n
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(result)) {`,
    expect: 'refuses an empty eth_call result rather than reading it as a zero balance',
  },
  {
    name: 'a token contract with no code is accepted',
    file: 'src/evm.ts',
    from: `        if (typeof contractCode !== 'string' || contractCode === '0x' || contractCode === '') {
          throw new UnsupportedDestinationError(chain, contract)
        }`,
    to: `        void contractCode`,
    expect: 'refuses a token contract that holds no code, rather than reporting a successful no-op',
  },
  {
    name: 'a token sweep is built at an address that cannot pay for it',
    file: 'src/evm.ts',
    from: `        if (balance < input.fee) throw new InsufficientTreasuryError(chain, balance, input.fee)`,
    to: `        void balance`,
    expect: 'refuses to build a token sweep at an address that cannot pay for it',
  },
  {
    name: 'the token build skips the chain-id binding',
    file: 'src/evm.ts',
    from: `        const chainId = assertChainId(chainIdHex, call.network)
        const nonce = assertNonce(nonceHex)
        return {`,
    to: `        const chainId = Number(quantity(chainIdHex, 'eth_chainId'))
        const nonce = assertNonce(nonceHex)
        return {`,
    expect: 'refuses a node whose chain id is not the one this build is pinned to',
  },
  {
    name: 'token sweeping follows the native sweep flag alone',
    file: 'src/sweeps.ts',
    from: `  if (!deps.enabled || !deps.tokenSweepEnabled) return { kind: 'disabled' }`,
    to: `  if (!deps.enabled) return { kind: 'disabled' }`,
    expect: 'sweeps no tokens when token sweeping is off, even with native sweeping on',
  },
  {
    name: 'the top-up delivers the cost of sending it rather than the sweep fee',
    file: 'src/sweeps.ts',
    from: `          amount: gasFee,
          fee: topUpFee,`,
    to: `          amount: topUpFee,
          fee: topUpFee,`,
    expect: 'plans a top-up and a sweep together, with the sweep depending on the top-up',
  },
  {
    name: 'the token sweep is signed under the native sweep shape',
    file: 'src/worker.ts',
    from: `  if (purpose === 'token_sweep') return { custodyPurpose: 'deposit', shape: 'token_sweep' }`,
    to: `  if (purpose === 'token_sweep') return { custodyPurpose: 'deposit', shape: 'sweep' }`,
    expect: 'claims deposit for a token sweep and treasury for its gas top-up',
  },
  {
    name: 'a gas top-up claims the deposit purpose',
    file: 'src/worker.ts',
    from: `  if (purpose === 'sweep') return { custodyPurpose: 'deposit', shape: 'sweep' }`,
    to: `  if (purpose === 'sweep' || purpose === 'gas_topup') return { custodyPurpose: 'deposit', shape: 'sweep' }`,
    expect: 'never gives a gas top-up a sweep shape',
  },
  {
    name: 'the schema permits a token contract on any purpose',
    file: 'src/migrations.ts',
    from: `        (purpose = 'token_sweep') = (token_contract is not null)`,
    to: `        true`,
    expect: 'refuses a token contract on a purpose that is not a token sweep',
  },
  {
    name: 'the schema permits a zero-amount token sweep',
    file: 'src/migrations.ts',
    from: `        purpose <> 'token_sweep' or (amount > 0 and fee >= 0)`,
    to: `        true`,
    expect: 'refuses a zero-amount token sweep',
  },
  {
    name: 'a contract is stored in whatever case the caller sent',
    file: 'src/outbound.ts',
    from: `      \${input.tokenContract?.toLowerCase() ?? null}, \${input.dependsOn ?? null},`,
    to: `      \${input.tokenContract ?? null}, \${input.dependsOn ?? null},`,
    expect: 'stores one spelling of a contract, the one custody allowlist stores',
  },
  {
    name: 'the registry is filtered by this service slug instead of custody name',
    file: 'src/sweeps.ts',
    from: `    .filter((row) => row.chain === custodyChain && row.network === network)`,
    to: `    .filter((row) => row.chain === chain && row.network === network)`,
    expect: 'matches custody chain name and not this service slug',
  },
]

const originals = new Map()
function snapshot(file) {
  if (!originals.has(file)) originals.set(file, readFileSync(file, 'utf8'))
}
function restoreAll() {
  for (const [file, text] of originals) writeFileSync(file, text)
}
process.on('exit', restoreAll)
process.on('SIGINT', () => process.exit(130))

/**
 * Drop and recreate the schema.
 *
 * **NECESSARY, AND THE REASON IS THE POINT OF THE MECHANISM BEING MUTATED.** `@cloudsforge/db`
 * checksums every migration and refuses to re-run one whose text has changed — which is exactly the
 * property that makes a released migration immutable. So a mutation to `migrations.ts` has NO
 * EFFECT on a database that has already been migrated: the constraint stays as it was, the suite
 * stays green, and the mutation is reported as a survivor when in fact it was never applied.
 *
 * That false negative is worth naming, because it is how a schema guarantee comes to be believed
 * without ever having been tested. Every schema mutation therefore starts from an empty database.
 */
function dropSchema() {
  execFileSync(
    'docker',
    ['exec', CONTAINER, 'psql', '-U', 'test', '-d', 'settlement_test', '-c',
     'drop schema public cascade; create schema public;'],
    { encoding: 'utf8', stdio: 'pipe' },
  )
}

function runSuite(fresh = false) {
  if (fresh) dropSchema()
  try {
    execFileSync(
      'node',
      ['--import', 'tsx', '--test', '--test-concurrency=1', 'src/tokensweeps.test.ts'],
      { encoding: 'utf8', stdio: 'pipe' },
    )
    return { failures: [] }
  } catch (err) {
    const out = `${err.stdout ?? ''}${err.stderr ?? ''}`
    const failures = [...out.matchAll(/^\s+✖ (.+?) \(/gm)].map((m) => m[1])
    return { failures }
  }
}

const CONTAINER = process.env.MUTATION_PG_CONTAINER ?? 'settlement-test-pg'

console.log('baseline …')
const baseline = runSuite(true)
if (baseline.failures.length > 0) {
  console.error('the suite is not green before mutating:', baseline.failures)
  process.exit(1)
}
console.log('baseline is green\n')

let killed = 0
const survivors = []
const misapplied = []

for (const mutation of MUTATIONS) {
  snapshot(mutation.file)
  const original = originals.get(mutation.file)
  if (!original.includes(mutation.from)) {
    misapplied.push(mutation.name)
    console.log(`?  ${mutation.name}\n   — the text to mutate was not found; the mutation is stale`)
    continue
  }
  writeFileSync(mutation.file, original.replace(mutation.from, mutation.to))
  const { failures } = runSuite(mutation.file === 'src/migrations.ts')
  writeFileSync(mutation.file, original)
  // The database now holds the MUTATED schema. Rebuild it from the restored source before the next
  // mutation, or every later one runs against a constraint that is quietly missing.
  if (mutation.file === 'src/migrations.ts') runSuite(true)

  if (failures.includes(mutation.expect)) {
    killed += 1
    console.log(`✓  ${mutation.name}\n   → killed by: "${mutation.expect}"`)
  } else if (failures.length > 0) {
    // Red, but not where it was predicted. Still a kill, and the discrepancy is worth printing:
    // it means the guarantee is tested somewhere other than where this claims.
    killed += 1
    console.log(
      `~  ${mutation.name}\n   → expected "${mutation.expect}"\n   → killed instead by: ${failures.join(', ')}`,
    )
  } else {
    survivors.push(mutation.name)
    console.log(`✖  SURVIVOR: ${mutation.name}\n   → nothing went red. Untested, or dead code.`)
  }
}

console.log(`\n${killed}/${MUTATIONS.length} mutations killed`)
if (misapplied.length > 0) console.log(`stale mutations: ${misapplied.length}`)
if (survivors.length > 0) {
  console.log('survivors:')
  for (const s of survivors) console.log(`  - ${s}`)
  process.exit(1)
}
