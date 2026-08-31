// OTS op-chain anchor verification, AnchorPolicy, CRQC horizon gating —
// mirrors tests/test_anchor.py (Python reference) one-for-one. Every fixture
// here is pure hash arithmetic (sha256 op-chains over fixed bytes), computed
// directly in TS — no Python precompute needed (unlike tlog.test.ts's
// hybrid-signed checkpoints, `verify_anchor` never checks a cryptographic
// signature itself; it only replays a hash chain and cross-checks a pinned
// header).
import { describe, it, expect } from 'vitest'
import { hexToBytes } from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2'
import {
  AnchorError,
  AnchorPolicy,
  AnchorVerdict,
  PinnedHeader,
  MAX_CHECKPOINT_TEXT_LEN_,
  MAX_OPS_PER_PROOF_,
  MAX_OP_HEX_LEN_,
  MAX_TOTAL_OP_HEX_LEN_,
  replayOtsOpChain,
  verifyAnchor,
  passesHorizon,
} from '../src/anchor.js'
import { Checkpoint } from '../src/tlog.js'

const enc = new TextEncoder()
const h = (hex: string) => hexToBytes(hex)

const NOTE_BYTES = enc.encode('log.example/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n')
const HEADER_TIME = 1700000000
const HEADER_HASH = '3a'.repeat(32) // deliberately contains a hex letter, not just digits
const DUMMY_SIGNATURE_LINE = '— test-key AA==\n'

function checkpoint(noteBytes: Uint8Array = NOTE_BYTES): Checkpoint {
  return {
    origin: 'log.example/1',
    treeSize: 1n,
    root: new Uint8Array(32),
    noteBytes,
    signedNoteBytes: enc.encode(checkpointText(noteBytes)),
  }
}

// `parseCheckpoint` requires a signature line but does not verify it; the
// dummy line lets anchor tests exercise only note binding.
function checkpointText(noteBytes: Uint8Array = NOTE_BYTES): string {
  return new TextDecoder().decode(noteBytes) + '\n' + DUMMY_SIGNATURE_LINE
}

function evidence(proofs: unknown[], noteBytes: Uint8Array = NOTE_BYTES): Record<string, unknown> {
  return { checkpoint: checkpointText(noteBytes), proofs: [...proofs] }
}

/** Build the op-chain forward and return `(ops, headerMerkleRoot)`. Sequence:
 * append sibling, sha256, prepend prefix, sha256. Computed independently of
 * anchor.ts (plain sha256 calls) so the test pins the real algorithm rather
 * than round-tripping the module's own logic. */
function workingChain(noteBytes: Uint8Array = NOTE_BYTES): { ops: unknown[][]; headerMerkleRoot: string } {
  const sibling = h('ab'.repeat(32)) // hex letters, not just digits — needed for uppercase tests
  const prefix = h('cd'.repeat(16))
  let acc = sha256(noteBytes)
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

function bytesToHexStr(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function otsProof(overrides: {
  ops?: unknown[][]
  headerMerkleRoot?: string
  headerTime?: unknown
  headerHash?: unknown
} = {}): Record<string, unknown> {
  const working = workingChain()
  return {
    kind: 'ots',
    ops: overrides.ops ?? working.ops,
    header_merkle_root: overrides.headerMerkleRoot ?? working.headerMerkleRoot,
    header_time: 'headerTime' in overrides ? overrides.headerTime : HEADER_TIME,
    header_hash: 'headerHash' in overrides ? overrides.headerHash : HEADER_HASH,
  }
}

function policy(overrides: {
  headerHash?: string
  merkleRoot?: string
  time?: number
  crqcHorizon?: number | null
} = {}): AnchorPolicy {
  const headerHash = overrides.headerHash ?? HEADER_HASH
  const merkleRoot = overrides.merkleRoot ?? workingChain().headerMerkleRoot
  const time = overrides.time ?? HEADER_TIME
  const pinned: PinnedHeader = { headerHash, merkleRoot, time }
  return { pinnedHeaders: { [headerHash]: pinned }, crqcHorizon: overrides.crqcHorizon ?? null }
}

// --------------------------------------------------------------------------
// Positive round trip.
// --------------------------------------------------------------------------

describe('verifyAnchor: positive round trip', () => {
  it('an ots proof verifies and anchors before the pinned header time', () => {
    const verdict = verifyAnchor(evidence([otsProof()]), checkpoint(), policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.pqSurviving).toBe(true)
    expect(verdict.warnings).toEqual([])
    // No anchor_profile in the evidence -> legacy note-bytes-only
    // commitment (G4): noteOnly flags it for transparency.ts's warning.
    expect(verdict.noteOnly).toBe(true)
  })

  it('requires evidence.checkpoint field', () => {
    const verdict = verifyAnchor({ proofs: [otsProof()] }, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['evidence.checkpoint is required'])
  })

  it('rejects a non-str evidence.checkpoint', () => {
    const verdict = verifyAnchor({ checkpoint: 1, proofs: [otsProof()] }, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['evidence.checkpoint must be a str'])
  })

  it('rejects a malformed evidence.checkpoint', () => {
    const verdict = verifyAnchor(
      { checkpoint: 'not a signed checkpoint', proofs: [otsProof()] },
      checkpoint(),
      policy(),
    )
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['evidence.checkpoint is not a valid signed checkpoint'])
  })

  it('rejects an evidence.checkpoint for a different note', () => {
    const differentNoteBytes = new TextDecoder()
      .decode(NOTE_BYTES)
      .replace('\n1\n', '\n2\n')
    const verdict = verifyAnchor(
      evidence([otsProof()], enc.encode(differentNoteBytes)),
      checkpoint(),
      policy(),
    )
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['evidence.checkpoint does not match checkpoint argument'])
  })
})

// --------------------------------------------------------------------------
// Negatives from the brief's Step 1 list.
// --------------------------------------------------------------------------

describe('verifyAnchor: ots proof negatives', () => {
  it('fails on a wrong header root', () => {
    const { ops } = workingChain()
    const wrongRoot = 'aa'.repeat(32)
    const proof = otsProof({ ops, headerMerkleRoot: wrongRoot })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: wrongRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.pqSurviving).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: ots op-chain result does not match header_merkle_root'])
  })

  it('fails when the header is not pinned', () => {
    const proof = otsProof({ headerHash: '44'.repeat(32) }) // valid shape, not in policy.pinnedHeaders
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: header_hash is not in policy.pinned_headers'])
  })

  it('fails on an unknown op name', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const badOps = [...ops, ['frobnicate']]
    const proof = otsProof({ ops: badOps, headerMerkleRoot })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: unknown ots op 'frobnicate'"])
  })

  it('fails on empty ops', () => {
    const root = bytesToHexStr(sha256(NOTE_BYTES))
    const proof = otsProof({ ops: [], headerMerkleRoot: root })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: root }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: ots proof has empty op-chain'])
  })

  it('fails when the pinned header root differs from the proof root', () => {
    const { headerMerkleRoot } = workingChain()
    const verdict = verifyAnchor(
      evidence([otsProof({ headerMerkleRoot })]),
      checkpoint(),
      policy({ merkleRoot: 'ef'.repeat(32) }),
    )
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: pinned header merkle_root does not match proof'])
  })

  it('fails when the pinned header time differs from the proof time', () => {
    const verdict = verifyAnchor(evidence([otsProof()]), checkpoint(), policy({ time: HEADER_TIME + 1 }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: pinned header time does not match proof'])
  })

  it('rfc3161-only evidence is classical corroboration without PQ or anchor time', () => {
    const ev = evidence([{ kind: 'rfc3161', token_b64: 'cXVpdGVvcGFxdWU=' }])
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.pqSurviving).toBe(false)
    expect(verdict.warnings).toEqual([
      'rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight',
    ])
  })
})

// --------------------------------------------------------------------------
// Anchor profile v2 (G4): commitment over the FULL signed checkpoint, not
// just its unsigned noteBytes header. Mirrors test_anchor.py's own section.
// --------------------------------------------------------------------------

function workingChainV2(
  signedNoteBytes: Uint8Array = enc.encode(checkpointText()),
): { ops: unknown[][]; headerMerkleRoot: string } {
  const sibling = h('ab'.repeat(32))
  const prefix = h('cd'.repeat(16))
  let acc = sha256(signedNoteBytes)
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

describe('verifyAnchor: anchor profile v2 (G4)', () => {
  it('commits over the full signed note', () => {
    const { ops, headerMerkleRoot } = workingChainV2()
    const proof = otsProof({ ops, headerMerkleRoot })
    const ev = { ...evidence([proof]), anchor_profile: 'signed-note-v2' }
    const verdict = verifyAnchor(ev, checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.pqSurviving).toBe(true)
    expect(verdict.noteOnly).toBe(false)
    expect(verdict.warnings).toEqual([])
  })

  it('fails when the op-chain only commits over note_bytes', () => {
    // The op-chain was built from sha256(noteBytes) alone (the v1 seed) —
    // under a declared v2 profile the verifier starts from
    // sha256(signedNoteBytes) instead, so the replayed chain lands on a
    // different root than the one pinned, and the anchor does not verify.
    const { ops, headerMerkleRoot } = workingChain()
    const proof = otsProof({ ops, headerMerkleRoot })
    const ev = { ...evidence([proof]), anchor_profile: 'signed-note-v2' }
    const verdict = verifyAnchor(ev, checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.pqSurviving).toBe(false)
    expect(verdict.warnings).toEqual([
      'proof[0]: ots op-chain result does not match header_merkle_root; anchor_profile ' +
        'signed-note-v2 requires the accumulator to start from ' +
        'SHA256(checkpoint.signed_note_bytes) — this evidence looks like a note-v1 ' +
        'commitment presented as signed-note-v2',
    ])
  })

  it('an explicit note-v1 profile behaves like absent', () => {
    const ev = { ...evidence([otsProof()]), anchor_profile: 'note-v1' }
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.noteOnly).toBe(true)
    expect(verdict.warnings).toEqual([])
  })

  it('an explicit null profile behaves like absent', () => {
    const ev = { ...evidence([otsProof()]), anchor_profile: null }
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.noteOnly).toBe(true)
    expect(verdict.warnings).toEqual([])
  })

  it('rejects an unrecognized anchor_profile', () => {
    const ev = { ...evidence([otsProof()]), anchor_profile: 'signed-note-v3' }
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      "evidence.anchor_profile must be 'note-v1' or 'signed-note-v2', got 'signed-note-v3'",
    ])
  })

  it('rejects a non-string anchor_profile', () => {
    const ev = { ...evidence([otsProof()]), anchor_profile: 2 }
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["evidence.anchor_profile must be 'note-v1' or 'signed-note-v2', got 2"])
  })
})

// --------------------------------------------------------------------------
// passesHorizon.
// --------------------------------------------------------------------------

describe('passesHorizon', () => {
  it('is false when the horizon is before the anchor time', () => {
    const verdict = verifyAnchor(evidence([otsProof()]), checkpoint(), policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: 1600000000 }))).toBe(false)
  })

  it('is true when the horizon is null', () => {
    const verdict = verifyAnchor(evidence([otsProof()]), checkpoint(), policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: null }))).toBe(true)
  })

  it('is true when the horizon is after the anchor time and PQ-surviving', () => {
    const verdict = verifyAnchor(evidence([otsProof()]), checkpoint(), policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME + 1 }))).toBe(true)
  })

  it('is false for rfc3161-only evidence with any horizon set', () => {
    const ev = evidence([{ kind: 'rfc3161', token_b64: 'opaque' }])
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME + 1 }))).toBe(false)
  })

  it('throws AnchorError on a non-AnchorPolicy', () => {
    const verdict: AnchorVerdict = {
      anchored: false,
      anchoredBefore: null,
      pqSurviving: false,
      warnings: [],
      noteOnly: false,
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => passesHorizon(verdict, 'not-a-policy' as any)).toThrow(AnchorError)
  })

  it('never throws on malformed verdict content', () => {
    const p = policy({ crqcHorizon: HEADER_TIME + 1 })
    expect(passesHorizon('not-a-verdict', p)).toBe(false)
    const badVerdict = { anchored: true, anchoredBefore: 'not-an-int', pqSurviving: true, warnings: [] }
    expect(passesHorizon(badVerdict, p)).toBe(false)
  })

  it('is true with a malformed verdict when the horizon is null (short-circuits first)', () => {
    const p = policy({ crqcHorizon: null })
    expect(passesHorizon('not-a-verdict', p)).toBe(true)
  })

  it.each([
    [null, false, null, true],
    [null, false, HEADER_TIME, true],
    [null, true, null, true],
    [null, true, HEADER_TIME, true],
    [HEADER_TIME + 1, false, null, false],
    [HEADER_TIME + 1, false, HEADER_TIME, false],
    [HEADER_TIME + 1, true, null, false],
    [HEADER_TIME + 1, true, HEADER_TIME, true],
  ])('all input combinations: crqcHorizon=%s pqSurviving=%s anchoredBefore=%s -> %s', (crqcHorizon, pqSurviving, anchoredBefore, expected) => {
    const verdict: AnchorVerdict = {
      anchored: false,
      anchoredBefore,
      pqSurviving,
      warnings: [],
      noteOnly: false,
    }
    expect(passesHorizon(verdict, policy({ crqcHorizon }))).toBe(expected)
  })

  it('rejects an anchor exactly at the horizon (strict <)', () => {
    const verdict: AnchorVerdict = {
      anchored: true,
      anchoredBefore: HEADER_TIME,
      pqSurviving: true,
      warnings: [],
      noteOnly: false,
    }
    expect(passesHorizon(verdict, policy({ crqcHorizon: HEADER_TIME }))).toBe(false)
  })
})

// --------------------------------------------------------------------------
// Multiple proofs: anchoredBefore is the min over verified PQ proofs.
// --------------------------------------------------------------------------

describe('multiple proofs', () => {
  it('anchoredBefore is the min over multiple verified PQ proofs', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const earlierHash = '55'.repeat(32)
    const laterHash = '66'.repeat(32)
    const earlierTime = HEADER_TIME - 100
    const laterTime = HEADER_TIME + 100
    const ev = evidence([
      otsProof({ ops, headerMerkleRoot, headerHash: laterHash, headerTime: laterTime }),
      otsProof({ ops, headerMerkleRoot, headerHash: earlierHash, headerTime: earlierTime }),
    ])
    const p: AnchorPolicy = {
      pinnedHeaders: {
        [laterHash]: { headerHash: laterHash, merkleRoot: headerMerkleRoot, time: laterTime },
        [earlierHash]: { headerHash: earlierHash, merkleRoot: headerMerkleRoot, time: earlierTime },
      },
      crqcHorizon: null,
    }
    const verdict = verifyAnchor(ev, checkpoint(), p)
    expect(verdict.anchoredBefore).toBe(earlierTime)
    expect(verdict.pqSurviving).toBe(true)
  })
})

// --------------------------------------------------------------------------
// verifyAnchor never throws on malformed EVIDENCE (untrusted input).
// --------------------------------------------------------------------------

describe('verifyAnchor never throws on malformed evidence', () => {
  it.each([null, [], 'not-a-dict', 42, true])('non-object evidence (%s)', (bad) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const verdict = verifyAnchor(bad as any, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.anchoredBefore).toBeNull()
    expect(verdict.pqSurviving).toBe(false)
    const typeName = bad === null ? 'NoneType' : Array.isArray(bad) ? 'list' : typeof bad === 'boolean' ? 'bool' : typeof bad === 'string' ? 'str' : 'int'
    expect(verdict.warnings).toEqual([`evidence must be an object, got ${typeName}`])
  })

  it('never throws when the proofs key is missing', () => {
    const verdict = verifyAnchor({ checkpoint: checkpointText() }, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['evidence.proofs must be a list, got NoneType'])
  })

  it.each(['not-a-list', 1, null, {}])('never throws when proofs is not a list (%s)', (badProofs) => {
    const verdict = verifyAnchor({ checkpoint: checkpointText(), proofs: badProofs }, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    const typeName = badProofs === null
      ? 'NoneType'
      : Array.isArray(badProofs)
        ? 'list'
        : typeof badProofs === 'boolean'
          ? 'bool'
          : typeof badProofs === 'string'
            ? 'str'
            : typeof badProofs === 'object'
              ? 'dict'
              : 'int'
    expect(verdict.warnings).toEqual([`evidence.proofs must be a list, got ${typeName}`])
  })

  it('caps the proofs list length', () => {
    const oversized = Array.from({ length: 65 }, () => ({ kind: 'bogus' }))
    const verdict = verifyAnchor(evidence(oversized), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['evidence.proofs exceeds max length 64'])
  })

  it.each([null, 'string', 42, [], true])('ignores a non-object proof entry with a warning (%s)', (badProof) => {
    const verdict = verifyAnchor(evidence([badProof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    const typeName = badProof === null ? 'NoneType' : typeof badProof === 'boolean' ? 'bool' : Array.isArray(badProof) ? 'list' : typeof badProof === 'string' ? 'str' : 'int'
    expect(verdict.warnings).toEqual([`proof[0]: must be an object, got ${typeName}`])
  })

  it('an unknown kind is ignored, not fatal', () => {
    const ev = evidence([{ kind: 'future-kind', stuff: 1 }, otsProof()])
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(verdict.anchored).toBe(true)
    expect(verdict.anchoredBefore).toBe(HEADER_TIME)
    expect(verdict.warnings).toEqual(["proof[0]: unknown proof kind 'future-kind', ignored"])
  })

  it.each([
    ["a'b", `"a'b"`],
    ['a"b', "'a\"b'"],
    [`a'"b`, "'a\\'\"b'"],
    ['a\nb', "'a\\nb'"],
    ['a\\b', "'a\\\\b'"],
    ['\u200b', "'\\u200b'"],
    ['🎉', "'\\U0001f389'"],
    ['\u{2ebf0}', "'\\U0002ebf0'"],
    ['\x7f', "'\\x7f'"],
    ['a\x01b', "'a\\x01b'"],
    ['a\x1bb', "'a\\x1bb'"],
  ])('renders Python ascii() exactly in unknown proof-kind and OTS-op warnings (%s)', (value, rendered) => {
    const kindVerdict = verifyAnchor(evidence([{ kind: value }]), checkpoint(), policy())
    expect(kindVerdict.warnings).toEqual([`proof[0]: unknown proof kind ${rendered}, ignored`])

    const opVerdict = verifyAnchor(evidence([otsProof({ ops: [[value]] })]), checkpoint(), policy())
    expect(opVerdict.warnings).toEqual([`proof[0]: unknown ots op ${rendered}`])
  })

  it('slices unknown proof-kind strings by code point before Python ascii()', () => {
    const kind = '🎉'.repeat(60) + 'tail'
    const verdict = verifyAnchor(evidence([{ kind }]), checkpoint(), policy())
    expect(verdict.warnings).toEqual([
      `proof[0]: unknown proof kind '${'\\U0001f389'.repeat(5)}\\U0001..., ignored`,
    ])
  })

  it.each([[10n ** 5000n, 'huge-bigint'], ['x'.repeat(100_000), 'huge-string']])(
    'safely renders a hostile unknown kind (%s)',
    (hostileKind) => {
      const verdict = verifyAnchor(evidence([{ kind: hostileKind }]), checkpoint(), policy())
      expect(verdict.anchored).toBe(false)
      expect(verdict.warnings[0]!.startsWith('proof[0]: unknown proof kind ')).toBe(true)
      expect(verdict.warnings[0]!.length).toBeLessThanOrEqual(100)
    },
  )

  it('ots proof missing the ops field', () => {
    const proof = otsProof()
    delete proof['ops']
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots proof 'ops' must be a list"])
  })

  it('rfc3161 rejects a non-str token', () => {
    const ev = evidence([{ kind: 'rfc3161', token_b64: 12345 }])
    const verdict = verifyAnchor(ev, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: rfc3161 token_b64 must be a str, got int'])
  })

  it('throws AnchorError on a non-Checkpoint argument', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => verifyAnchor({ proofs: [] }, 'not-a-checkpoint' as any, policy())).toThrow(AnchorError)
  })

  it('throws AnchorError on a non-AnchorPolicy argument', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => verifyAnchor({ proofs: [] }, checkpoint(), 'not-a-policy' as any)).toThrow(AnchorError)
  })
})

// --------------------------------------------------------------------------
// Hex validation discipline: lowercase-only, strict length, guard before
// hex decode (which itself accepts uppercase and odd-padded input).
// --------------------------------------------------------------------------

describe('hex validation discipline', () => {
  it('rejects an uppercase header_merkle_root', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const proof = otsProof({ ops, headerMerkleRoot: headerMerkleRoot.toUpperCase() })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars"])
  })

  it.each(['aa'.repeat(31), 'aa'.repeat(33), 'not-hex-at-all-' + 'a'.repeat(49)])(
    'rejects a wrong-length or non-hex header_merkle_root (%s)',
    (badRoot) => {
      const proof = otsProof({ headerMerkleRoot: badRoot })
      const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
      expect(verdict.anchored).toBe(false)
      expect(verdict.warnings).toEqual(["proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars"])
    },
  )

  it('rejects an uppercase header_hash', () => {
    const proof = otsProof({ headerHash: HEADER_HASH.toUpperCase() })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots proof 'header_hash' must be 64 lowercase hex chars"])
  })

  it('rejects an uppercase op operand even though hex-decode would accept it', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const siblingHexUpper = (ops[0]![1] as string).toUpperCase()
    expect(hexToBytes(siblingHexUpper)).toEqual(hexToBytes(ops[0]![1] as string)) // sanity: decode tolerates it
    const badOps = [['append', siblingHexUpper], ...ops.slice(1)]
    const proof = otsProof({ ops: badOps, headerMerkleRoot })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"])
  })

  it('rejects an odd-length op operand', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const badOps = [['append', 'abc'], ...ops.slice(1)] // 3 hex chars: valid charset, odd length
    const proof = otsProof({ ops: badOps, headerMerkleRoot })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"])
  })

  it('rejects an op operand over the max hex length', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const tooLong = 'ab'.repeat(MAX_OP_HEX_LEN_ / 2 + 1)
    const badOps = [['append', tooLong], ...ops.slice(1)]
    const proof = otsProof({ ops: badOps, headerMerkleRoot })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"])
  })

  it('accepts an op operand at exactly the max hex length (boundary)', () => {
    const operandHex = 'ab'.repeat(MAX_OP_HEX_LEN_ / 2)
    const operand = hexToBytes(operandHex)
    let acc = sha256(NOTE_BYTES)
    acc = sha256(new Uint8Array([...acc, ...operand]))
    const root = bytesToHexStr(acc)
    const ops = [['append', operandHex], ['sha256']]
    const proof = otsProof({ ops, headerMerkleRoot: root })
    const verdict = verifyAnchor(evidence([proof], NOTE_BYTES), checkpoint(NOTE_BYTES), policy({ merkleRoot: root }))
    expect(verdict.anchored).toBe(true)
  })

  it("rejects a 'sha256' op carrying an operand", () => {
    const { ops, headerMerkleRoot } = workingChain()
    const badOps = [ops[0]!, ['sha256', 'ff'], ...ops.slice(2)]
    const proof = otsProof({ ops: badOps, headerMerkleRoot })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(["proof[0]: ots 'sha256' op takes no operand"])
  })

  it('rejects an op that is not a list', () => {
    const { ops, headerMerkleRoot } = workingChain()
    const badOps = ['sha256', ...ops] // bare string instead of ["sha256"]
    const proof = otsProof({ ops: badOps as unknown[][], headerMerkleRoot })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy({ merkleRoot: headerMerkleRoot }))
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual(['proof[0]: ots op must be a non-empty list with a string opcode'])
  })

  it('caps the ops list length', () => {
    const oversizedOps = Array.from({ length: MAX_OPS_PER_PROOF_ + 1 }, () => ['sha256'])
    const proof = otsProof({ ops: oversizedOps })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`proof[0]: ots proof has more than ${MAX_OPS_PER_PROOF_} ops`])
  })

  // Twins of tests/test_anchor.py's total-operand boundary pair. The cap that
  // keeps the raised per-op caps inside the normative outer ceiling needs its
  // boundary pinned on BOTH sides, or an off-by-one turns real evidence away.
  it('accepts operands summing to exactly the total cap', () => {
    const chunkHex = MAX_OP_HEX_LEN_
    const chunks = MAX_TOTAL_OP_HEX_LEN_ / chunkHex
    const ops: unknown[] = []
    for (let i = 0; i < chunks; i++) {
      ops.push(['append', 'ab'.repeat(chunkHex / 2)])
      ops.push(['sha256'])
    }
    const { accumulator, warning } = replayOtsOpChain(new Uint8Array(32), ops)
    expect(warning).toBe(null)
    expect(accumulator).not.toBe(null)
  })

  it('rejects operands one hex pair over the total cap', () => {
    const chunkHex = MAX_OP_HEX_LEN_
    const chunks = MAX_TOTAL_OP_HEX_LEN_ / chunkHex
    const ops: unknown[] = []
    for (let i = 0; i < chunks; i++) {
      ops.push(['append', 'ab'.repeat(chunkHex / 2)])
      ops.push(['sha256'])
    }
    ops.push(['append', 'ab'])
    const { accumulator, warning } = replayOtsOpChain(new Uint8Array(32), ops)
    expect(accumulator).toBe(null)
    expect(warning).toBe(`ots proof operands exceed ${MAX_TOTAL_OP_HEX_LEN_} total hex chars`)
  })
})

// --------------------------------------------------------------------------
// bool-is-int traps: TS booleans are never `typeof === 'number'`, so this is
// naturally excluded — these tests still port the SCENARIO (materialized
// evidence carrying a JSON `true` where an int is required).
// --------------------------------------------------------------------------

describe('bool/type traps on numeric fields', () => {
  it('rejects a bool header_time', () => {
    const proof = otsProof({ headerTime: true })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      "proof[0]: ots proof 'header_time' must be a positive int no later than 253402300799",
    ])
  })

  it('rejects a zero or negative header_time', () => {
    const proof = otsProof({ headerTime: 0 })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([
      "proof[0]: ots proof 'header_time' must be a positive int no later than 253402300799",
    ])
  })

  it('rejects a header_time after the renderable Unix bound', () => {
    const proof = otsProof({ headerTime: 253402300799 + 1 })
    const verdict = verifyAnchor(evidence([proof]), checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.pqSurviving).toBe(false)
    expect(verdict.warnings).toEqual([
      "proof[0]: ots proof 'header_time' must be a positive int no later than 253402300799",
    ])
  })

  it('rejects a bool pinned header time', () => {
    const pinned: PinnedHeader = { headerHash: HEADER_HASH, merkleRoot: 'aa'.repeat(32), time: true as unknown as number }
    const p: AnchorPolicy = { pinnedHeaders: { [HEADER_HASH]: pinned }, crqcHorizon: null }
    expect(() => verifyAnchor({ proofs: [] }, checkpoint(), p)).toThrow(AnchorError)
  })

  it('rejects a pinned header time after the renderable Unix bound', () => {
    const pinned: PinnedHeader = { headerHash: HEADER_HASH, merkleRoot: 'aa'.repeat(32), time: 253402300799 + 1 }
    const p: AnchorPolicy = { pinnedHeaders: { [HEADER_HASH]: pinned }, crqcHorizon: null }
    expect(() => verifyAnchor({ proofs: [] }, checkpoint(), p)).toThrow(AnchorError)
  })

  it('rejects a bool crqc_horizon', () => {
    const p: AnchorPolicy = { pinnedHeaders: {}, crqcHorizon: true as unknown as number }
    expect(() => verifyAnchor({ proofs: [] }, checkpoint(), p)).toThrow(AnchorError)
  })
})

// --------------------------------------------------------------------------
// AnchorPolicy structural validation (trusted config side — throws).
// --------------------------------------------------------------------------

describe('AnchorPolicy structural validation', () => {
  it('rejects a mismatched dict key and header_hash field', () => {
    const pinned: PinnedHeader = { headerHash: HEADER_HASH, merkleRoot: 'aa'.repeat(32), time: HEADER_TIME }
    const p: AnchorPolicy = { pinnedHeaders: { ['ff'.repeat(32)]: pinned }, crqcHorizon: null }
    expect(() => verifyAnchor({ proofs: [] }, checkpoint(), p)).toThrow(AnchorError)
  })

  it('rejects a non-PinnedHeader value', () => {
    const p = { pinnedHeaders: { [HEADER_HASH]: 'not-a-pinned-header' }, crqcHorizon: null } as unknown as AnchorPolicy
    expect(() => verifyAnchor({ proofs: [] }, checkpoint(), p)).toThrow(AnchorError)
  })

  it('rejects an uppercase pinned header merkle_root', () => {
    const pinned: PinnedHeader = { headerHash: HEADER_HASH, merkleRoot: 'AA'.repeat(32), time: HEADER_TIME }
    const p: AnchorPolicy = { pinnedHeaders: { [HEADER_HASH]: pinned }, crqcHorizon: null }
    expect(() => verifyAnchor({ proofs: [] }, checkpoint(), p)).toThrow(AnchorError)
  })

  it('rejects an oversized evidence.checkpoint text before it reaches parseCheckpoint', () => {
    const text = 'x'.repeat(MAX_CHECKPOINT_TEXT_LEN_ + 1)
    const verdict = verifyAnchor({ checkpoint: text, proofs: [otsProof()] }, checkpoint(), policy())
    expect(verdict.anchored).toBe(false)
    expect(verdict.warnings).toEqual([`evidence.checkpoint exceeds max length ${MAX_CHECKPOINT_TEXT_LEN_}`])
  })

  it('counts evidence checkpoint caps by Unicode code points, not UTF-16 units', () => {
    const withinCap = '🎉'.repeat(MAX_CHECKPOINT_TEXT_LEN_ / 2 + 1)
    expect(withinCap.length).toBeGreaterThan(MAX_CHECKPOINT_TEXT_LEN_)
    const withinVerdict = verifyAnchor({ checkpoint: withinCap, proofs: [] }, checkpoint(), policy())
    expect(withinVerdict.warnings).toEqual(['evidence.checkpoint is not a valid signed checkpoint'])

    const beyondCap = '🎉'.repeat(MAX_CHECKPOINT_TEXT_LEN_ + 1)
    const beyondVerdict = verifyAnchor({ checkpoint: beyondCap, proofs: [] }, checkpoint(), policy())
    expect(beyondVerdict.warnings).toEqual([`evidence.checkpoint exceeds max length ${MAX_CHECKPOINT_TEXT_LEN_}`])
  })
})
