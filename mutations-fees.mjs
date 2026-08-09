/**
 * Mutation testing for the fee estimate a node will not give.
 *
 * micro-org#268: `blocksonly=1` on the estate's `litecoind` and `bitcoind` makes `estimatesmartfee`
 * permanently unable to answer, so the relay floor is not a fallback on this deployment — it is the
 * only path. The adapter documented that fallback and had it for ONE of the three spellings a
 * bitcoin-family node actually uses for "I have no estimate"; the other two came out as exceptions.
 *
 * Every mutation here restores one of those states, and each is a defect that produces a THROWN
 * ERROR out of a fee quote or a silent 1 sat/vB during an outage — neither of which a green suite
 * noticed before, because the node fakes answered `{}`, a shape no node in this estate returns.
 *
 * The one that matters most is `the catch swallows every RPC fault`: it leaves the suite passing on
 * the happy path while turning a node outage into transactions built at the relay floor, in
 * silence. That is the mutation whose survival would be worse than the bug it replaces.
 *
 * Run: node mutations-fees.mjs        (no database — this suite needs none)
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

const SUITE = ['src/bitcoin.test.ts']

const GUARD = `    if (typeof quoted !== 'number' || !(quoted > 0)) return floor`
const CATCH = `      if (err instanceof Error && err.message.includes(NO_ESTIMATE_RPC_MESSAGE)) return floor`

const MUTATIONS = [
  {
    name: "the -1 sentinel is read as a fee rate rather than as an absence — dogecoind 1.14.9",
    file: 'src/bitcoin.ts',
    from: GUARD,
    to: `    if (typeof quoted !== 'number') return floor`,
    expect: "takes the floor from dogecoind's `feerate: -1`, which is a number and is not a fee",
  },
  {
    name: 'the absent-feerate guard is narrowed to the sentinel only — litecoind under blocksonly',
    file: 'src/bitcoin.ts',
    from: GUARD,
    to: `    if (typeof quoted === 'number' && quoted < 0) return floor`,
    expect: "takes the floor from litecoind's `errors` answer, which blocksonly makes permanent",
  },
  {
    name: 'the floor is taken unconditionally, so a node that CAN estimate is ignored',
    file: 'src/bitcoin.ts',
    from: GUARD,
    to: `    return floor`,
    expect: 'still prefers a real estimate wherever a node has one, so the floor is a fallback',
  },
  {
    name: "Core's `Fee estimation disabled` is not recognised — bitcoind 27 under blocksonly",
    file: 'src/bitcoin.ts',
    from: CATCH,
    to: `      if (err instanceof Error && err.message.includes('a message no node sends')) return floor`,
    expect: "takes the floor from bitcoind's `Fee estimation disabled`, which arrives as an exception",
  },
  {
    name: 'the catch swallows every RPC fault, so a node outage becomes a silent relay-floor quote',
    file: 'src/bitcoin.ts',
    from: CATCH,
    to: `      if (err instanceof Error) return floor`,
    expect: 'lets every other node fault propagate, so an outage cannot quietly become the floor',
  },
  {
    name: "the floor is resolved from the family rather than the chain, so DOGE gets Bitcoin's 1",
    file: 'src/bitcoin.ts',
    from: `  const floor = MIN_RELAY_PER_VB[chain]`,
    to: `  const floor = MIN_RELAY_PER_VB['btc']`,
    expect: "takes the floor from dogecoind's `feerate: -1`, which is a number and is not a fee",
  },
]

const originals = new Map()
process.on('exit', () => {
  for (const [file, text] of originals) writeFileSync(file, text)
})

function runSuite() {
  try {
    execFileSync('node', ['--import', 'tsx', '--test', '--test-concurrency=1', ...SUITE], {
      encoding: 'utf8',
      stdio: 'pipe',
    })
    return { failures: [] }
  } catch (err) {
    // Stripped of SGR escapes before it is matched. `node:test` colours its output whenever
    // `FORCE_COLOR` is set in the environment — which several terminals and CI runners do — and a
    // coloured `✖` line begins with an escape rather than with whitespace, so `^\s*✖` misses every
    // one of them and EVERY killed mutation is reported as a survivor. It fails loudly rather than
    // quietly, so nothing was ever waved through by it, but a harness whose answer depends on the
    // caller's terminal is a harness nobody trusts twice.
    const out = `${err.stdout ?? ''}${err.stderr ?? ''}`.replace(/\u001b\[[0-9;]*m/g, '')
    // `^\s*` and not `^\s+`: a case nested in a `describe` is indented, a top-level one is not.
    const names = [...out.matchAll(/^\s*✖ (.+?) \(/gm)].map((m) => m[1])
    return { failures: [...new Set(names)] }
  }
}

console.log('baseline …')
const baseline = runSuite()
if (baseline.failures.length > 0) {
  console.error('the suite is not green before mutating:', baseline.failures)
  process.exit(1)
}
console.log('baseline is green\n')

let killed = 0
const survivors = []
for (const mutation of MUTATIONS) {
  if (!originals.has(mutation.file)) originals.set(mutation.file, readFileSync(mutation.file, 'utf8'))
  const original = originals.get(mutation.file)
  if (!original.includes(mutation.from)) {
    console.log(`?  ${mutation.name}\n   — text not found; the mutation is stale`)
    survivors.push(`${mutation.name} (stale)`)
    continue
  }
  writeFileSync(mutation.file, original.replace(mutation.from, mutation.to))
  const { failures } = runSuite()
  writeFileSync(mutation.file, original)

  if (failures.includes(mutation.expect)) {
    killed += 1
    console.log(`✓  ${mutation.name}\n   → killed by: "${mutation.expect}"`)
  } else if (failures.length > 0) {
    killed += 1
    console.log(`~  ${mutation.name}\n   → expected "${mutation.expect}"\n   → killed instead by: ${failures.join(', ')}`)
  } else {
    survivors.push(mutation.name)
    console.log(`✖  SURVIVOR: ${mutation.name}`)
  }
}

console.log(`\n${killed}/${MUTATIONS.length} mutations killed`)
if (survivors.length > 0) {
  for (const s of survivors) console.log(`  survivor: ${s}`)
  process.exit(1)
}
