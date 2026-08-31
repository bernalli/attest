// Seeded anchor verification: `verifySeededAnchor` over an arbitrary seed —
// mirrors tests/test_anchor_seeded.py (Python reference) one-for-one.
//
// Where verifyAnchor asks "was THIS checkpoint timestamped?",
// verifySeededAnchor asks "has real time reached date T?": the caller holds
// an OpenTimestamps attestation whose op-chain starts from the canonical
// bytes of some public document and climbs to a Bitcoin header the verifier
// has pinned. No checkpoint is involved, and no anchor profile either — a
// profile only distinguishes WHICH of a checkpoint's two byte-strings an
// accumulator committed to.
//
// Every fixture is pure hash arithmetic over fixed bytes, computed directly
// in TS, exactly as in anchor.test.ts.
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { hexToBytes } from '@noble/curves/utils.js'

// A counting stand-in for sha256, so a ceiling test can assert ORDER and not
// just outcome: a cap enforced after the work it is meant to bound would run
// past the budget and throw instead of returning a verdict. Unlimited by
// default so the fixtures below can hash freely; the three ordering tests set
// a limit for the duration of one call. ESM bindings are immutable, so a
// module mock is the only way to observe this from the outside.
const budget = vi.hoisted(() => ({ limit: Number.POSITIVE_INFINITY, calls: 0 }))
vi.mock('@noble/hashes/sha2', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@noble/hashes/sha2')>()
  return {
    ...actual,
    sha256: (data: Uint8Array): Uint8Array => {
      budget.calls += 1
      if (budget.calls > budget.limit) {
        throw new Error(`digest #${budget.calls} ran past the ${budget.limit}-digest budget`)
      }
      return actual.sha256(data)
    },
  }
})

import { sha256 } from '@noble/hashes/sha2'
import {
  AnchorError,
  AnchorPolicy,
  AnchorVerdict,
  PinnedHeader,
  MAX_PROOFS_PER_EVIDENCE_,
  MAX_OPS_PER_PROOF_,
  MAX_OP_HEX_LEN_,
  MAX_TOTAL_OP_HEX_LEN_,
  verifyAnchor,
  verifySeededAnchor,
  passesHorizon,
} from '../src/anchor.js'
import { pyTypeName } from '../src/messages.js'
import { Checkpoint } from '../src/tlog.js'

const enc = new TextEncoder()
const h = (hex: string) => hexToBytes(hex)

// Stand-in for "the canonical bytes of a public document": arbitrary bytes
// with no checkpoint structure at all — the whole point of the seeded entry
// point is that the seed need not be a note.
const SEED = enc.encode('public document, canonical bytes\n')
const HEADER_TIME = 1700000000
const HEADER_HASH = '3a'.repeat(32) // deliberately contains a hex letter, not just digits

function bytesToHexStr(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Build the op-chain forward and return `(ops, headerMerkleRoot)`. Sequence:
 * append sibling, sha256, prepend prefix, sha256. Computed independently of
 * anchor.ts (plain sha256 calls) so the test pins the real algorithm rather
 * than round-tripping the module's own logic. The chain starts from
 * `sha256(seed)`, exactly as verifyAnchor's note-v1 path starts from
 * `sha256(checkpoint.noteBytes)`. */
function workingChain(seed: Uint8Array = SEED): { ops: unknown[][]; headerMerkleRoot: string } {
  const sibling = h('ab'.repeat(32))
  const prefix = h('cd'.repeat(16))
  let acc = sha256(seed)
  acc = sha256(new Uint8Array([...acc, ...sibling]))
  acc = sha256(new Uint8Array([...prefix, ...acc]))
  const ops = [
    ['append', bytesToHexStr(sibling)],
    ['sha256'],
    ['prepend', bytesToHexStr(prefix)],
    ['sha256'],
  ]
  return { ops, headerMerkleRoot: bytesToHexStr(acc) }
}

function otsProof(
  overrides: {
    ops?: unknown
    headerMerkleRoot?: string
    headerTime?: unknown
    headerHash?: unknown
  } = {},
): Record<string, unknown> {
  const working = workingChain()
  return {
    kind: 'ots',
    ops: 'ops' in overrides ? overrides.ops : working.ops,
    header_merkle_root: overrides.headerMerkleRoot ?? working.headerMerkleRoot,
    header_time: 'headerTime' in overrides ? overrides.headerTime : HEADER_TIME,
    header_hash: 'headerHash' in overrides ? overrides.headerHash : HEADER_HASH,
  }
}

function evidence(proofs: unknown[]): Record<string, unknown> {
  return { proofs: [...proofs] }
}

function policy(
  overrides: {
    headerHash?: string
    merkleRoot?: string
    time?: number
    crqcHorizon?: number | null
  } = {},
): AnchorPolicy {
  const headerHash = overrides.headerHash ?? HEADER_HASH
  const merkleRoot = overrides.merkleRoot ?? workingChain().headerMerkleRoot
  const time = overrides.time ?? HEADER_TIME
  const pinned: PinnedHeader = { headerHash, merkleRoot, time }
  return { pinnedHeaders: { [headerHash]: pinned }, crqcHorizon: overrides.crqcHorizon ?? null }
}

beforeEach(() => {
  budget.limit = Number.POSITIVE_INFINITY
  budget.calls = 0
})

// --------------------------------------------------------------------------
// Positive round trip.
// --------------------------------------------------------------------------

describe('verifySeededAnchor: positive round trip', () => {
  it('a seeded ots proof verifies and anchors before the pinned header time', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.anchoredAfter).toBe(HEADER_TIME)
    expect(verdict.pqSurviving).toBe(true)
    expect(verdict.warnings).toEqual([])
    // There is no profile dimension on this path: noteOnly is not a
    // classification the seeded entry point can make.
    expect(verdict.noteOnly).toBe(false)
  })

  it('agrees with verifyAnchor on the same note-v1 evidence', () => {
    // Pins the seed derivation: sha256(seed) is the accumulator start, so
    // feeding checkpoint.noteBytes replays the identical chain.
    const noteBytes = enc.encode('log.example/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n')
    const checkpointText = new TextDecoder().decode(noteBytes) + '\n' + '— test-key AA==\n'
    const cp: Checkpoint = {
      origin: 'log.example/1',
      treeSize: 1n,
      root: new Uint8Array(32),
      noteBytes,
      signedNoteBytes: enc.encode(checkpointText),
    }
    const { ops, headerMerkleRoot } = workingChain(noteBytes)
    const proof = otsProof({ ops, headerMerkleRoot })
    const p = policy({ merkleRoot: headerMerkleRoot })

    const checkpointBound = verifyAnchor({ checkpoint: checkpointText, proofs: [proof] }, cp, p)
    const seeded = verifySeededAnchor(evidence([proof]), noteBytes, p)

    expect(checkpointBound.anchored).toBe(true)
    expect(seeded.anchored).toBe(true)
    expect(seeded.anchoredBefore).toBe(checkpointBound.anchoredBefore)
    expect(seeded.anchoredAfter).toBe(checkpointBound.anchoredAfter)
    expect(seeded.pqSurviving).toBe(checkpointBound.pqSurviving)
    expect(seeded.warnings).toEqual(checkpointBound.warnings)
  })
})

// --------------------------------------------------------------------------
// No checkpoint, no anchor_profile: neither is read, neither is required.
// --------------------------------------------------------------------------

describe('verifySeededAnchor: checkpoint and anchor_profile are not read', () => {
  it('ignores an incoherent evidence.checkpoint', () => {
    const ev = { ...evidence([otsProof()]), checkpoint: 'not a signed checkpoint at all' }
    const verdict = verifySeededAnchor(ev, SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.warnings).toEqual([])
  })

  it('ignores a well-formed but unrelated evidence.checkpoint', () => {
    const otherNote = 'other.example/1\n7\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n'
    const ev = { ...evidence([otsProof()]), checkpoint: otherNote + '\n' + '— test-key AA==\n' }
    const verdict = verifySeededAnchor(ev, SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.warnings).toEqual([])
  })

  it.each(['note-v1', 'signed-note-v2', 'bogus-profile', null, 42])(
    'ignores evidence.anchor_profile (%s)',
    (profile) => {
      // bogus-profile/42 are values verifyAnchor rejects outright; on the
      // seeded path the field carries no meaning and is never read.
      const ev = { ...evidence([otsProof()]), anchor_profile: profile }
      const verdict = verifySeededAnchor(ev, SEED, policy())
      expect(verdict.anchored).toBe(true)
      expect(verdict.noteOnly).toBe(false)
      expect(verdict.warnings).toEqual([])
    },
  )
})

// --------------------------------------------------------------------------
// Negative: the chain must climb from THIS seed to a PINNED header.
// --------------------------------------------------------------------------

describe('verifySeededAnchor: ots proof negatives', () => {
  it('rejects a seed that differs by one byte', () => {
    const wrongSeed = Uint8Array.from(SEED)
    wrongSeed[0] = (wrongSeed[0] as number) ^ 0x01
    const verdict = verifySeededAnchor(evidence([otsProof()]), wrongSeed, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.pqSurviving).toBe(false)
    // The plain mismatch message: no profile wording can appear on a path
    // that has no profile dimension.
    expect(verdict.warnings).toEqual(['proof[0]: ots op-chain result does not match header_merkle_root'])
  })

  it('rejects a header absent from the pinned store', () => {
    const emptyPolicy: AnchorPolicy = { pinnedHeaders: {}, crqcHorizon: null }
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, emptyPolicy)
    expect(verdict.anchored).toBe(false)
    expect(verdict.pqSurviving).toBe(false)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.warnings).toEqual(['proof[0]: header_hash is not in policy.pinned_headers'])
  })

  it('rejects a header pinned under a different hash', () => {
    const { headerMerkleRoot } = workingChain()
    const otherHash = '77'.repeat(32)
    const p: AnchorPolicy = {
      pinnedHeaders: {
        [otherHash]: { headerHash: otherHash, merkleRoot: headerMerkleRoot, time: HEADER_TIME },
      },
      crqcHorizon: null,
    }
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, p)
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: header_hash is not in policy.pinned_headers'])
  })

  it('rejects a pinned header whose merkle root differs', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy({ merkleRoot: 'ff'.repeat(32) }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: pinned header merkle_root does not match proof'])
  })

  it('rejects a pinned header whose time differs from the proof', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy({ time: HEADER_TIME + 1 }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: pinned header time does not match proof'])
  })

  it('rejects a non-hex64 header_merkle_root', () => {
    const verdict = verifySeededAnchor(evidence([otsProof({ headerMerkleRoot: 'aa'.repeat(31) })]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      "proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars",
    ])
  })

  it('rejects a non-hex operand', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const badOps = [['append', 'zz'.repeat(32)], ...ops.slice(1)]
    const verdict = verifySeededAnchor(
      evidence([otsProof({ ops: badOps, headerMerkleRoot })]),
      SEED,
      policy({ merkleRoot: headerMerkleRoot }),
    )
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex",
    ])
  })

  it('rejects an unknown op', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const badOps = [['ripemd160'], ...ops]
    const verdict = verifySeededAnchor(
      evidence([otsProof({ ops: badOps, headerMerkleRoot })]),
      SEED,
      policy({ merkleRoot: headerMerkleRoot }),
    )
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: unknown ots op 'ripemd160'"])
  })

  it('rejects an empty op-chain', () => {
    const verdict = verifySeededAnchor(evidence([otsProof({ ops: [] })]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: ots proof has empty op-chain'])
  })

  it('rejects an ots proof with no ops field', () => {
    const proof = otsProof()
    delete proof['ops']
    const verdict = verifySeededAnchor(evidence([proof]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots proof 'ops' must be a list"])
  })

  it.each(['not-a-list', 1, null, {}])('rejects ops that is not a list (%s)', (badOps) => {
    const verdict = verifySeededAnchor(evidence([otsProof({ ops: badOps })]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots proof 'ops' must be a list"])
  })
})

// --------------------------------------------------------------------------
// Malformed evidence never throws (untrusted input).
// --------------------------------------------------------------------------

describe('verifySeededAnchor never throws on malformed evidence', () => {
  it.each([null, [], 'not-a-dict', 42, true])('non-object evidence (%s)', (bad) => {
    const verdict = verifySeededAnchor(bad, SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.anchoredAfter).toBeNull() // both reductions absent, not just one
    expect(verdict.pqSurviving).toBe(false)
    expect(verdict.warnings).toEqual([`evidence must be an object, got ${pyTypeName(bad)}`])
  })

  it('never throws when the proofs key is missing', () => {
    const verdict = verifySeededAnchor({}, SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['evidence.proofs must be a list, got NoneType'])
  })

  it.each(['not-a-list', 1, null, {}])('never throws when proofs is not a list (%s)', (badProofs) => {
    const verdict = verifySeededAnchor({ proofs: badProofs }, SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`evidence.proofs must be a list, got ${pyTypeName(badProofs)}`])
  })

  it('an empty proofs list is simply not anchored', () => {
    const verdict = verifySeededAnchor(evidence([]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.warnings).toEqual([])
  })

  it.each([null, 'string', 42, [], true])('ignores a non-object proof entry with a warning (%s)', (badProof) => {
    const verdict = verifySeededAnchor(evidence([badProof]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`proof[0]: must be an object, got ${pyTypeName(badProof)}`])
  })

  it('an unknown kind is ignored, not fatal', () => {
    const ev = evidence([{ kind: 'future-kind', stuff: 1 }, otsProof()])
    const verdict = verifySeededAnchor(ev, SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.warnings).toContain("proof[0]: unknown proof kind 'future-kind', ignored")
  })

  it('an rfc3161 proof anchors without surviving the horizon', () => {
    const verdict = verifySeededAnchor(evidence([{ kind: 'rfc3161', token_b64: 'AAAA' }]), SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.pqSurviving).toBe(false)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.warnings).toEqual([
      'rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight',
    ])
  })
})

// --------------------------------------------------------------------------
// anchoredBefore is the MINIMUM over verified proofs, anchoredAfter the
// MAXIMUM. They answer opposite questions; see the AnchorVerdict docs.
// --------------------------------------------------------------------------

describe('verifySeededAnchor: the two reductions', () => {
  it('is the min over multiple verified pq proofs', () => {
    const { ops, headerMerkleRoot: root } = workingChain()
    const earlierHash = '55'.repeat(32)
    const laterHash = '66'.repeat(32)
    const earlierTime = HEADER_TIME - 100
    const laterTime = HEADER_TIME + 100
    const ev = evidence([
      otsProof({ ops, headerMerkleRoot: root, headerHash: laterHash, headerTime: laterTime }),
      otsProof({ ops, headerMerkleRoot: root, headerHash: earlierHash, headerTime: earlierTime }),
    ])
    const p: AnchorPolicy = {
      pinnedHeaders: {
        [laterHash]: { headerHash: laterHash, merkleRoot: root, time: laterTime },
        [earlierHash]: { headerHash: earlierHash, merkleRoot: root, time: earlierTime },
      },
      crqcHorizon: null,
    }
    const verdict = verifySeededAnchor(ev, SEED, p)
    expect(verdict.anchoredBefore).toBe(earlierTime)
    expect(verdict.pqSurviving).toBe(true)
    // The same evidence, read the other way round: the most recent verified
    // header. The minimum alone would answer "has time reached T?" with a
    // false negative here — the older proof would veto the newer one.
    expect(verdict.anchoredAfter).toBe(laterTime)
  })

  it('before and after coincide on a single proof', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy())
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.anchoredAfter).toBe(HEADER_TIME)
  })

  it('ignores proofs that did not verify, in both reductions', () => {
    // One verified proof, flanked by two proofs whose headers the verifier
    // has NOT pinned: one claiming an earlier time, one a later time.
    // Neither may move the floor down nor the ceiling up.
    const { ops, headerMerkleRoot: root } = workingChain()
    const unpinnedEarly = otsProof({
      ops,
      headerMerkleRoot: root,
      headerHash: '88'.repeat(32),
      headerTime: HEADER_TIME - 1000,
    })
    const unpinnedLate = otsProof({
      ops,
      headerMerkleRoot: root,
      headerHash: '99'.repeat(32),
      headerTime: HEADER_TIME + 1000,
    })
    const verdict = verifySeededAnchor(evidence([unpinnedEarly, otsProof(), unpinnedLate]), SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.anchoredAfter).toBe(HEADER_TIME)
    expect(verdict.warnings).toEqual([
      'proof[0]: header_hash is not in policy.pinned_headers',
      'proof[2]: header_hash is not in policy.pinned_headers',
    ])
  })

  it('leaves both reductions null without a verified pq proof', () => {
    const verdict = verifySeededAnchor(evidence([{ kind: 'rfc3161', token_b64: 'AAAA' }]), SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.anchoredAfter).toBeNull()
  })
})

// --------------------------------------------------------------------------
// `anchoredAfter` is additive: no existing consumer of AnchorVerdict can
// tell that it appeared.
// --------------------------------------------------------------------------

describe('anchoredAfter is additive', () => {
  it('an AnchorVerdict still type-checks and behaves without the new field', () => {
    // Every pre-existing call site builds the literal without it; the
    // optional field keeps those sites compiling untouched.
    const verdict: AnchorVerdict = {
      anchored: true,
      anchoredBefore: HEADER_TIME,
      pqSurviving: true,
      warnings: [],
      noteOnly: false,
    }
    expect(verdict.anchoredAfter).toBeUndefined()
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME + 1 }))).toBe(true)
  })

  it('verifyAnchor populates it without moving any other field', () => {
    // Both entry points share one proof-walking loop, so verifyAnchor gets
    // the maximum for free. Every field its existing consumers read is
    // pinned here to the value it had before the field existed.
    const noteBytes = enc.encode('log.example/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n')
    const checkpointText = new TextDecoder().decode(noteBytes) + '\n' + '— test-key AA==\n'
    const cp: Checkpoint = {
      origin: 'log.example/1',
      treeSize: 1n,
      root: new Uint8Array(32),
      noteBytes,
      signedNoteBytes: enc.encode(checkpointText),
    }
    const { ops, headerMerkleRoot: root } = workingChain(noteBytes)
    const earlierHash = '55'.repeat(32)
    const laterHash = '66'.repeat(32)
    const earlierTime = HEADER_TIME - 100
    const laterTime = HEADER_TIME + 100
    const proofs = [
      otsProof({ ops, headerMerkleRoot: root, headerHash: laterHash, headerTime: laterTime }),
      otsProof({ ops, headerMerkleRoot: root, headerHash: earlierHash, headerTime: earlierTime }),
    ]
    const p: AnchorPolicy = {
      pinnedHeaders: {
        [laterHash]: { headerHash: laterHash, merkleRoot: root, time: laterTime },
        [earlierHash]: { headerHash: earlierHash, merkleRoot: root, time: earlierTime },
      },
      crqcHorizon: null,
    }
    const verdict = verifyAnchor({ checkpoint: checkpointText, proofs }, cp, p)
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(earlierTime) // unchanged: still the minimum
    expect(verdict.pqSurviving).toBe(true)
    expect(verdict.warnings).toEqual([])
    expect(verdict.noteOnly).toBe(true)
    expect(verdict.anchoredAfter).toBe(laterTime) // the only new observable
  })

  it('is invisible to passesHorizon', () => {
    // passesHorizon gates on anchoredBefore; two verdicts differing ONLY in
    // the new field must gate identically, at every horizon.
    const base = { anchored: true, anchoredBefore: HEADER_TIME, pqSurviving: true, warnings: [], noteOnly: false }
    const without: AnchorVerdict = { ...base }
    const withField: AnchorVerdict = { ...base, anchoredAfter: HEADER_TIME + 10_000 }
    for (const crqcHorizon of [null, HEADER_TIME - 1, HEADER_TIME, HEADER_TIME + 1, HEADER_TIME + 20_000]) {
      const p = policy({ crqcHorizon })
      expect(passesHorizon(without, p)).toBe(passesHorizon(withField, p))
    }
  })
})

// --------------------------------------------------------------------------
// Ceilings: same constants as the checkpoint-bound path, applied BEFORE any
// cryptographic work.
// --------------------------------------------------------------------------

describe('verifySeededAnchor: ceilings', () => {
  it('caps the proofs list length', () => {
    // Every entry WOULD verify: one warning and anchored=false is the
    // observable proof that nothing was replayed at all.
    const oversized = Array.from({ length: MAX_PROOFS_PER_EVIDENCE_ + 1 }, () => otsProof())
    const verdict = verifySeededAnchor(evidence(oversized), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`evidence.proofs exceeds max length ${MAX_PROOFS_PER_EVIDENCE_}`])
  })

  it('accepts a proofs list at exactly the cap', () => {
    const atCap = Array.from({ length: MAX_PROOFS_PER_EVIDENCE_ }, () => otsProof())
    const verdict = verifySeededAnchor(evidence(atCap), SEED, policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.warnings).toEqual([])
  })

  it('caps the ops list length', () => {
    const oversizedOps = Array.from({ length: MAX_OPS_PER_PROOF_ + 1 }, () => ['sha256'])
    const verdict = verifySeededAnchor(evidence([otsProof({ ops: oversizedOps })]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`proof[0]: ots proof has more than ${MAX_OPS_PER_PROOF_} ops`])
  })

  // Twin of tests/test_anchor_seeded.py's total-operand guard: the seeded and
  // checkpoint entry points share replayOtsOpChain, and a cap only one door
  // enforces is a cap someone will route around.
  it('caps the total operand length', () => {
    const chunkHex = MAX_OP_HEX_LEN_
    const ops: unknown[] = []
    for (let i = 0; i < MAX_TOTAL_OP_HEX_LEN_ / chunkHex; i++) {
      ops.push(['append', 'ab'.repeat(chunkHex / 2)])
      ops.push(['sha256'])
    }
    ops.push(['append', 'ab'])
    const verdict = verifySeededAnchor(evidence([otsProof({ ops })]), SEED, policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      `proof[0]: ots proof operands exceed ${MAX_TOTAL_OP_HEX_LEN_} total hex chars`,
    ])
  })

  it('accepts an ops list at exactly the cap', () => {
    let acc = sha256(SEED)
    for (let i = 0; i < MAX_OPS_PER_PROOF_; i++) acc = sha256(acc)
    const root = bytesToHexStr(acc)
    const ops = Array.from({ length: MAX_OPS_PER_PROOF_ }, () => ['sha256'])
    const verdict = verifySeededAnchor(
      evidence([otsProof({ ops, headerMerkleRoot: root })]),
      SEED,
      policy({ merkleRoot: root }),
    )
    expect(verdict.anchored).toBe(true)
  })

  it('caps the op operand hex length', () => {
    const { ops, headerMerkleRoot: root } = workingChain()
    const tooLong = 'ab'.repeat(MAX_OP_HEX_LEN_ / 2 + 1)
    const badOps = [['append', tooLong], ...ops.slice(1)]
    const verdict = verifySeededAnchor(
      evidence([otsProof({ ops: badOps, headerMerkleRoot: root })]),
      SEED,
      policy({ merkleRoot: root }),
    )
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex",
    ])
  })

  it('accepts an op operand at exactly the cap', () => {
    const operandHex = 'ab'.repeat(MAX_OP_HEX_LEN_ / 2)
    const operand = h(operandHex)
    const acc = sha256(new Uint8Array([...sha256(SEED), ...operand]))
    const root = bytesToHexStr(acc)
    const ops = [['append', operandHex], ['sha256']]
    const verdict = verifySeededAnchor(
      evidence([otsProof({ ops, headerMerkleRoot: root })]),
      SEED,
      policy({ merkleRoot: root }),
    )
    expect(verdict.anchored).toBe(true)
  })

  it('enforces the proofs ceiling before hashing the seed', () => {
    const oversized = Array.from({ length: MAX_PROOFS_PER_EVIDENCE_ + 1 }, () => otsProof())
    const ev = evidence(oversized)
    const p = policy()
    budget.calls = 0
    budget.limit = 0
    const verdict = verifySeededAnchor(ev, SEED, p)
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`evidence.proofs exceeds max length ${MAX_PROOFS_PER_EVIDENCE_}`])
    expect(budget.calls).toBe(0)
  })

  it('enforces the ops ceiling before replaying any op', () => {
    const oversizedOps = Array.from({ length: MAX_OPS_PER_PROOF_ + 1 }, () => ['sha256'])
    const ev = evidence([otsProof({ ops: oversizedOps })])
    const p = policy()
    budget.calls = 0
    budget.limit = 1 // the seed digest, and not one op beyond it
    const verdict = verifySeededAnchor(ev, SEED, p)
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`proof[0]: ots proof has more than ${MAX_OPS_PER_PROOF_} ops`])
    expect(budget.calls).toBe(1)
  })

  it('enforces the operand ceiling before hashing the operand', () => {
    // The op-chain shape is validated as it is walked (shared with the
    // checkpoint-bound path): the guarantee the cap buys is that an operand
    // is never concatenated or hashed before its own length is checked.
    const { headerMerkleRoot: root } = workingChain()
    const tooLong = 'ab'.repeat(MAX_OP_HEX_LEN_ / 2 + 1)
    const ev = evidence([otsProof({ ops: [['append', tooLong], ['sha256']], headerMerkleRoot: root })])
    const p = policy({ merkleRoot: root })
    budget.calls = 0
    budget.limit = 1 // the seed digest only
    const verdict = verifySeededAnchor(ev, SEED, p)
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex",
    ])
    expect(budget.calls).toBe(1)
  })
})

// --------------------------------------------------------------------------
// Horizon gating: the seeded verdict feeds passesHorizon unchanged.
// --------------------------------------------------------------------------

describe('verifySeededAnchor: horizon gating', () => {
  it('fails a horizon that precedes the seeded anchor time', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME - 1 }))).toBe(false)
  })

  it('passes a horizon that follows the seeded anchor time', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME + 1 }))).toBe(true)
  })

  it('passes when no horizon is configured', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: null }))).toBe(true)
  })

  it('rejects a seeded anchor exactly at the horizon', () => {
    const verdict = verifySeededAnchor(evidence([otsProof()]), SEED, policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME }))).toBe(false)
  })

  it('fails for seeded rfc3161-only evidence', () => {
    const verdict = verifySeededAnchor(evidence([{ kind: 'rfc3161', token_b64: 'AAAA' }]), SEED, policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME + 1 }))).toBe(false)
  })
})

// --------------------------------------------------------------------------
// Caller-bug boundary: `seed` and `policy` are trusted arguments and throw.
// --------------------------------------------------------------------------

describe('verifySeededAnchor: trusted argument boundary', () => {
  it.each(['a string', null, 42, [1, 2, 3], true, new ArrayBuffer(8)])(
    'throws AnchorError on a non-Uint8Array seed (%s)',
    (badSeed) => {
      expect(() =>
        verifySeededAnchor(evidence([otsProof()]), badSeed as unknown as Uint8Array, policy()),
      ).toThrow(AnchorError)
    },
  )

  it('throws AnchorError on an empty seed', () => {
    expect(() => verifySeededAnchor(evidence([otsProof()]), new Uint8Array(0), policy())).toThrow(AnchorError)
  })

  it('throws AnchorError on a non-AnchorPolicy', () => {
    expect(() => verifySeededAnchor(evidence([]), SEED, 'not-a-policy' as unknown as AnchorPolicy)).toThrow(
      AnchorError,
    )
  })

  it('throws AnchorError on malformed policy contents', () => {
    const p: AnchorPolicy = {
      pinnedHeaders: { [HEADER_HASH]: { headerHash: HEADER_HASH, merkleRoot: 'AA'.repeat(32), time: HEADER_TIME } },
      crqcHorizon: null,
    }
    expect(() => verifySeededAnchor(evidence([]), SEED, p)).toThrow(AnchorError)
  })

  it('lets a caller bug take precedence over malformed evidence', () => {
    expect(() =>
      verifySeededAnchor('not-a-dict', 'not-bytes' as unknown as Uint8Array, policy()),
    ).toThrow(AnchorError)
  })
})
