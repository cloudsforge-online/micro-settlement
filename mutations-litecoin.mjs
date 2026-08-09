/**
 * Mutation testing for the Litecoin outbound adapter.
 *
 * One adapter serves two chains, so almost every Litecoin defect available here is "a parameter was
 * resolved from the family instead of the chain" — and every one of those produces a well-formed
 * transaction rather than an exception. A green suite is therefore not evidence about them, and
 * each mutation below restores one and requires a named test to notice.
 *
 * The three that matter most:
 *
 *   * `the dust threshold is copied from Bitcoin` — the only constant in the file where reuse
 *     produces a transaction no node relays, so its test has to probe the window BETWEEN the two
 *     thresholds rather than at zero.
 *   * `the dust guard is applied to sweeps too` — the mutation that makes an empty treasury look
 *     like a permanent fee refusal, which is a misclassification rather than a wrong number.
 *   * `the confirmation depth comes from BTC` — 6 instead of 12, which spends coins this estate has
 *     not itself accepted as final.
 *
 * Run: SETTLEMENT_TEST_DATABASE_URL=... node mutations-litecoin.mjs
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

const SUITE = ['src/bitcoin.test.ts', 'src/chains.test.ts']

const MUTATIONS = [
  {
    name: 'Litecoin is given Bitcoin network parameters — the whole defect, in one line',
    file: 'src/bitcoin.ts',
    from: `  ltc: Object.freeze({ mainnet: LITECOIN_MAINNET, testnet: LITECOIN_TESTNET }),`,
    to: `  ltc: Object.freeze({ mainnet: bitcoin.networks.bitcoin, testnet: bitcoin.networks.testnet }),`,
    expect: "decodes Core's own published vectors to Core's own published scripts",
  },
  {
    name: "the bech32 HRP becomes Bitcoin's, so an ltc1 address stops decoding and bc1 starts",
    file: 'src/bitcoin.ts',
    from: `  bech32: 'ltc',`,
    to: `  bech32: 'bc',`,
    expect: "decodes Core's own published vectors to Core's own published scripts",
  },
  {
    name: "the P2PKH version byte becomes Bitcoin's 0, so an L… address is refused",
    file: 'src/bitcoin.ts',
    from: `  pubKeyHash: 0x30,`,
    to: `  pubKeyHash: 0x00,`,
    expect: "decodes Core's own published vectors to Core's own published scripts",
  },
  {
    name: "the P2SH byte becomes SCRIPT_ADDRESS 5 rather than SCRIPT_ADDRESS2 50",
    file: 'src/bitcoin.ts',
    from: `  scriptHash: 0x32,`,
    to: `  scriptHash: 0x05,`,
    expect: "decodes Core's own published vectors to Core's own published scripts",
  },
  {
    name: 'the registry constructs the Litecoin adapter as a Bitcoin one',
    file: 'src/registry.ts',
    from: `  ltc: bitcoinChain('ltc'),`,
    to: `  ltc: bitcoinChain('btc'),`,
    expect: 'is an implemented chain, and hands custody the name custody stores',
  },
  {
    name: 'THE DUST THRESHOLD IS COPIED FROM BITCOIN — a change output no node will relay',
    file: 'src/bitcoin.ts',
    from: `  ltc: 5_460n,`,
    to: `  ltc: 546n,`,
    expect: "uses Litecoin's dust threshold of 5,460 — ten times Bitcoin's, and NOT copied from it",
  },
  {
    name: 'the dust guard is removed entirely, so a sub-dust payment is built and signed',
    file: 'src/bitcoin.ts',
    from: `    if (input.shape !== 'sweep' && input.value <= dust) {`,
    to: `    if (false) {`,
    expect: "uses Litecoin's dust threshold of 5,460 — ten times Bitcoin's, and NOT copied from it",
  },
  {
    name: 'the dust guard is applied to sweeps too, misclassifying an empty treasury as permanent',
    file: 'src/bitcoin.ts',
    from: `    if (input.shape !== 'sweep' && input.value <= dust) {`,
    to: `    if (input.value <= dust) {`,
    expect: 'refuses when there is nothing at depth to sweep',
  },
  {
    name: "THE CONFIRMATION DEPTH COMES FROM BTC — Litecoin credited and spent at 6, not 12",
    file: 'src/bitcoin.ts',
    from: `  const spec = chainSpec(assetOf(chain))`,
    to: `  const spec = chainSpec(assetOf('btc'))`,
    expect: "uses Litecoin's own confirmation depth of 12, not Bitcoin's 6",
  },
  {
    name: "the supply cap is Bitcoin's, so a genuine Litecoin amount is refused as malformed",
    file: 'src/bitcoin.ts',
    from: `  ltc: 8_400_000_000_000_000n,`,
    to: `  ltc: 2_100_000_000_000_000n,`,
    expect: "bounds the amount by Litecoin's supply cap and not Bitcoin's",
  },
  {
    name: 'custody is told the slug rather than the chain name it stores — a binding_mismatch',
    file: 'src/chains.ts',
    from: `  ltc: 'litecoin',`,
    to: `  ltc: 'ltc',`,
    expect: 'is an implemented chain, and hands custody the name custody stores',
  },
  {
    name: 'the build validates the destination as Bitcoin whatever the row says',
    file: 'src/bitcoin.ts',
    from: `    validateAddress(chain, input.to, call.network)`,
    to: `    validateAddress('btc', input.to, call.network)`,
    expect: 'refuses a Bitcoin destination at BUILD, not merely at validation',
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
    // Stripped of SGR escapes first: `node:test` colours its output whenever `FORCE_COLOR` is set,
    // and a coloured `✖` line starts with an escape rather than whitespace, so the pattern below
    // misses every one of them and reports every KILLED mutation as a survivor. @see mutations-fees.mjs
    const out = (`${err.stdout ?? ''}${err.stderr ?? ''}`).replace(/\u001b\[[0-9;]*m/g, '')
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
