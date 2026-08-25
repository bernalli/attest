// Run the cross-core witness parity bench against the TYPESCRIPT core.
//
// Reads the JSON document produced by tools/witness_parity_cases.py on stdin
// and writes one verdict per case to stdout, sorted by case id — the same
// shape tools/witness_parity_py.py writes from the Python core. `diff`
// between the two outputs IS the parity check.
//
// Usage (from the repository root):
//   uv run --frozen python tools/witness_parity_cases.py > /tmp/bench.json
//   uv run --frozen python tools/witness_parity_py.py < /tmp/bench.json > /tmp/py.json
//   npm run build --prefix verifiers/ts
//   node verifiers/ts/tools/witness-parity.mjs < /tmp/bench.json > /tmp/ts.json
//   diff /tmp/py.json /tmp/ts.json
//
// Imports the BUILT core (`dist/`), not the sources, so the bench measures
// what the package actually ships. An exception is reported as a verdict
// rather than propagated: whether a core throws is itself part of what has to
// match.
import { readFileSync } from 'node:fs'

import { parseCheckpoint } from '../dist/tlog.js'
import {
  evaluateCorroboration,
  evaluateActivationWitnessQuorum,
  loadPolicy,
} from '../dist/witness.js'

function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, 'base64'))
}

function corroboration(testCase, checkpointText) {
  const checkpoint = parseCheckpoint(checkpointText)
  const signatures = testCase.sigs.map(([name, blobB64]) => [name, b64ToBytes(blobB64)])
  const policy = loadPolicy(
    new TextEncoder().encode(JSON.stringify(testCase.policy)),
  )
  const verdict = evaluateCorroboration(checkpoint, signatures, policy, testCase.epoch_id)
  return { witnessed: verdict.witnessed, warnings: [...verdict.warnings] }
}

function anchorPolicy(raw) {
  const pinnedHeaders = {}
  for (const [key, header] of Object.entries(raw.pinned_headers)) {
    pinnedHeaders[key] = {
      headerHash: header.header_hash,
      merkleRoot: header.merkle_root,
      time: header.time,
    }
  }
  return { pinnedHeaders, crqcHorizon: raw.crqc_horizon }
}

function quorum(testCase) {
  const result = evaluateActivationWitnessQuorum(testCase.checkpoint_text, {
    witnessPolicy: loadPolicy(b64ToBytes(testCase.policy_b64)),
    epochId: testCase.epoch_id,
    expectedOrigin: testCase.expected_origin,
    anchorEvidence: testCase.anchor_evidence,
    anchorPolicy: anchorPolicy(testCase.anchor_policy),
    conflictDomain: testCase.conflict_domain,
  })
  return {
    valid: result.valid,
    witness_time: result.witnessTime,
    counting_control_groups: [...result.countingControlGroups],
  }
}

function sortedStringify(value) {
  // Python's `json.dump(..., sort_keys=True, indent=1)` is the reference
  // rendering; matching it here is what lets a plain `diff` be the check.
  return JSON.stringify(value, (_key, val) => {
    if (val === null || typeof val !== 'object' || Array.isArray(val)) return val
    return Object.fromEntries(Object.keys(val).sort().map((k) => [k, val[k]]))
  }, 1)
}

const bench = JSON.parse(readFileSync(0, 'utf8'))
const out = { corroboration: {}, quorum: {} }

for (const testCase of bench.cases) {
  try {
    out.corroboration[testCase.id] = corroboration(testCase, bench.checkpoint_text)
  } catch (error) {
    out.corroboration[testCase.id] = { raised: error?.constructor?.name ?? 'Error' }
  }
}

for (const testCase of bench.quorum_cases) {
  try {
    out.quorum[testCase.id] = quorum(testCase)
  } catch (error) {
    out.quorum[testCase.id] = { raised: error?.constructor?.name ?? 'Error' }
  }
}

process.stdout.write(sortedStringify(out) + '\n')
