// OpenTimestamps-style Bitcoin block-header anchoring — mirrors
// src/attest/anchor.py (Python reference). Lets a verifier check that a
// tlog.Checkpoint was timestamped into a Bitcoin block header pinned in its
// own trust store (AnchorPolicy), and gate on whether that anchor lands
// early enough to still count as post-quantum-surviving evidence once a
// future CRQC horizon is reached.
//
// `verifyAnchor` NEVER throws on malformed `evidence` — it arrives from an
// untrusted bundle, so any shape violation degrades to a warning and that
// proof contributes nothing, rather than aborting verification of the rest
// of the bundle. `checkpoint`/`policy` are the trusted, verifier-config side
// (mirrors tlog.verifyCheckpoint's logKey/expectedOrigin split): malformed
// ones throw `AnchorError` instead, since that signals a caller bug.
//
// `verifySeededAnchor` answers the other half of the question. Where
// `verifyAnchor` asks "was THIS checkpoint timestamped?",
// `verifySeededAnchor` asks "has real time reached date T?": the op-chain
// starts from `sha256(seed)` for an arbitrary caller-supplied seed (the
// canonical bytes of some public document), no checkpoint is involved
// anywhere, and the anchor-profile dimension does not exist. Everything else
// is shared, down to the ceilings and the warning strings. Because the two
// ask opposite questions, the verdict carries BOTH reductions over the
// verified proofs — `anchoredBefore` (minimum, "did this exist no later than
// T?") and `anchoredAfter` (maximum, "has real time reached T?") — see
// `AnchorVerdict` for why one cannot stand in for the other.
//
// Anchor profile (G4, attest-v0.2.md §11.1): an `ots` proof's accumulator
// starts from an `evidence.anchor_profile`-selected commitment —
// `sha256(checkpoint.signedNoteBytes)` (the full signed note) for
// "signed-note-v2", or `sha256(checkpoint.noteBytes)` (the unsigned header
// alone — TM-33's residual pre-anchor-then-sign gap) for absent/null/
// "note-v1". `AnchorVerdict.noteOnly` records which profile was used.
import { equalBytes, concatBytes, hexToBytes } from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2'
import { Checkpoint, TlogError, parseCheckpoint } from './tlog.js'
import {
  ANCHOR_WARN,
  RFC3161_WARNING,
  codePointLength,
  pyRepr,
  pyTypeName,
  evidenceNotObject,
  evidenceProofsNotList,
  evidenceCheckpointExceeds,
  evidenceProofsExceeds,
  proofNotObject,
  proofPrefixed,
  otsTooManyOps,
  otsOperandTotalTooLarge,
  otsUnknownOp,
  otsOperandInvalid,
  otsOperandRequired,
  otsHeaderTimeInvalid,
  rfc3161TokenNotStr,
  unknownProofKind,
  evidenceAnchorProfileInvalid,
} from './messages.js'

const HEX64_RE = /^[0-9a-f]{64}$/
const HEX_RE = /^[0-9a-f]*$/

// Caps bounding attacker-controlled work while walking untrusted evidence.
// The op-chain caps below are sized from MEASURED real OpenTimestamps
// attestations (2026-08-31, four upstream example files): largest Bitcoin
// path 100 ops, largest single operand 3432 bytes, largest per-chain operand
// total 7388 hex chars. The pre-2026-08-31 values (64 ops, 2048 hex) turned
// the first of those away outright. Mirrors anchor.py verbatim.
const MAX_PROOFS_PER_EVIDENCE = 64
const MAX_OPS_PER_PROOF = 256
// A legitimate full note is ~400KB worst case — cap the evidence checkpoint
// text BEFORE it reaches tlog.parseCheckpoint, so a hostile multi-megabyte
// string cannot force large parse-time allocations.
const MAX_CHECKPOINT_TEXT_LEN = 500_000
const MAX_OP_HEX_LEN = 16384 // hex chars (8192 bytes) per append/prepend operand
// The per-chain operand TOTAL, and the reason the two caps above could be
// raised at all: verify.ts's outer evidence ceiling is normative (v0.2 §16.1)
// and cannot be raised to meet them. Without this cap,
// MAX_PROOFS_PER_EVIDENCE * MAX_OPS_PER_PROOF * MAX_OP_HEX_LEN would admit
// ~268MB of operands against a 10MB ceiling. It tightens the aggregate rather
// than loosening it: the old regime admitted 131_072 hex chars of
// attacker-chosen bytes per proof, twice what this allows. What does grow is
// the op COUNT per bundle (4x) and the peak single concatenation (8x).
const MAX_TOTAL_OP_HEX_LEN = 65536
// The latest Unix timestamp `Date`/`datetime` can render through
// 9999-12-31T23:59:59Z. Keep pinned and untrusted proof times inside that
// shared bound.
const MAX_RENDERABLE_UNIX_TIME = 253402300799

const KNOWN_OTS_OPS = new Set(['sha256', 'append', 'prepend'])

// Anchor profile (G4, attest-v0.2.md §11.1): which checkpoint bytes an
// `ots` proof's accumulator starts from. Absent or "note-v1" is the legacy
// path (starts from checkpoint.noteBytes, the unsigned header alone —
// eternal verifiability, attest-versioning.md §3: still fully verifiable,
// forever, just classified noteOnly=true). "signed-note-v2" starts from
// checkpoint.signedNoteBytes (the full signed note) and is what
// newly-produced anchors MUST use going forward.
const ANCHOR_PROFILE_NOTE_V1 = 'note-v1'
const ANCHOR_PROFILE_SIGNED_NOTE_V2 = 'signed-note-v2'
const KNOWN_ANCHOR_PROFILES = new Set([ANCHOR_PROFILE_NOTE_V1, ANCHOR_PROFILE_SIGNED_NOTE_V2])

export const MAX_PROOFS_PER_EVIDENCE_ = MAX_PROOFS_PER_EVIDENCE
export const MAX_OPS_PER_PROOF_ = MAX_OPS_PER_PROOF
export const MAX_OP_HEX_LEN_ = MAX_OP_HEX_LEN
export const MAX_TOTAL_OP_HEX_LEN_ = MAX_TOTAL_OP_HEX_LEN
export const MAX_CHECKPOINT_TEXT_LEN_ = MAX_CHECKPOINT_TEXT_LEN
export const MAX_RENDERABLE_UNIX_TIME_ = MAX_RENDERABLE_UNIX_TIME

export class AnchorError extends Error {}

/** A Bitcoin block header pinned out-of-band into the verifier's trust
 * store — never taken from the untrusted evidence bundle itself. */
export interface PinnedHeader {
  headerHash: string
  merkleRoot: string
  time: number
}

/** The verifier's anchor trust store and CRQC cutoff. `pinnedHeaders` is
 * keyed by `headerHash` (each value's own `headerHash` must match its key).
 * `crqcHorizon` is a unix-seconds cutoff; `null` means no cutoff is
 * configured (every PQ-anchored checkpoint passes). */
export interface AnchorPolicy {
  pinnedHeaders: Record<string, PinnedHeader>
  crqcHorizon: number | null
}

/** The outcome of `verifyAnchor` or `verifySeededAnchor` over one evidence
 * bundle.
 *
 * `anchoredBefore` and `anchoredAfter` are the two ends of the same set of
 * verified `ots` (PQ-surviving) proofs — `rfc3161` proofs set neither, and
 * both are `null` when no `ots` proof verified. They exist as a PAIR because
 * a caller can ask two opposite questions of one bundle and only one
 * reduction is sound for each:
 *
 * - `anchoredBefore` is the MINIMUM pinned header time. It answers "did this
 *   exist no later than T?" — the oldest verified anchor is the strongest
 *   claim of prior existence, and the maximum would overclaim.
 * - `anchoredAfter` is the MAXIMUM pinned header time. It answers "has real
 *   time reached T?" — a pinned header's time is a lower bound on real time,
 *   so the most recent verified anchor is the strongest such evidence. The
 *   minimum produces false negatives the moment a bundle carries two valid
 *   proofs: an old one would veto a new one, and a caller handed only the
 *   minimum cannot recover the maximum.
 *
 * Neither is derivable from the other, which is why the verdict carries
 * both. `anchoredAfter` is optional so that every pre-existing construction
 * site keeps compiling untouched; both entry points always populate it.
 *
 * `noteOnly` is `true` iff the evidence's `anchor_profile` is absent,
 * `null`, or `"note-v1"` (G4, attest-v0.2.md §11.1): the accumulator
 * started from `checkpoint.noteBytes` alone, so any resulting anchor proves
 * existence of the unsigned header text only, not of the eventually-
 * attached signature. `false` for `"signed-note-v2"` evidence.
 * `transparency.ts` turns this into the caller-facing `anchor_note_only`
 * warning — `verifyAnchor`'s own `warnings` never mention it. */
export interface AnchorVerdict {
  anchored: boolean
  anchoredBefore: number | null
  pqSurviving: boolean
  warnings: string[]
  noteOnly: boolean
  anchoredAfter?: number | null
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function isPinnedHeaderShape(v: unknown): v is PinnedHeader {
  return isPlainObject(v) && 'headerHash' in v && 'merkleRoot' in v && 'time' in v
}

function isCheckpointShape(v: unknown): v is Checkpoint {
  return (
    isPlainObject(v) &&
    'origin' in v &&
    'treeSize' in v &&
    'root' in v &&
    'noteBytes' in v &&
    'signedNoteBytes' in v
  )
}

function isAnchorVerdictShape(v: unknown): v is AnchorVerdict {
  return isPlainObject(v) && 'anchored' in v && 'anchoredBefore' in v && 'pqSurviving' in v && 'warnings' in v
}

/** Validate every `AnchorPolicy` field before it's trusted. Throws
 * `AnchorError` — `policy` is assembled by the verifier's own config, not
 * adversarial evidence, so a malformed policy is a caller bug to surface
 * loudly, not degrade gracefully. */
export function validatePolicy(policy: unknown): AnchorPolicy {
  if (!isPlainObject(policy) || !('pinnedHeaders' in policy) || !('crqcHorizon' in policy)) {
    throw new AnchorError(`policy must be an AnchorPolicy, got ${pyTypeName(policy)}`)
  }
  const pinnedHeadersRaw = policy['pinnedHeaders']
  if (!isPlainObject(pinnedHeadersRaw)) throw new AnchorError('policy.pinned_headers must be a dict')

  for (const [headerHash, header] of Object.entries(pinnedHeadersRaw)) {
    if (!HEX64_RE.test(headerHash)) {
      throw new AnchorError(`pinned_headers key must be 64 lowercase hex chars: ${pyRepr(headerHash)}`)
    }
    if (!isPinnedHeaderShape(header)) {
      throw new AnchorError(`pinned_headers[${pyRepr(headerHash)}] must be a PinnedHeader`)
    }
    if (typeof header.headerHash !== 'string' || !HEX64_RE.test(header.headerHash)) {
      throw new AnchorError(
        `PinnedHeader.header_hash must be 64 lowercase hex chars: ${pyRepr(header.headerHash)}`,
      )
    }
    if (header.headerHash !== headerHash) {
      throw new AnchorError(
        `pinned_headers key ${pyRepr(headerHash)} != PinnedHeader.header_hash ${pyRepr(header.headerHash)}`,
      )
    }
    if (typeof header.merkleRoot !== 'string' || !HEX64_RE.test(header.merkleRoot)) {
      throw new AnchorError(
        `PinnedHeader.merkle_root must be 64 lowercase hex chars: ${pyRepr(header.merkleRoot)}`,
      )
    }
    if (
      typeof header.time !== 'number' ||
      !Number.isInteger(header.time) ||
      header.time <= 0 ||
      header.time > MAX_RENDERABLE_UNIX_TIME
    ) {
      throw new AnchorError(
        `PinnedHeader.time must be a positive int no later than ${MAX_RENDERABLE_UNIX_TIME}: ${pyRepr(header.time)}`,
      )
    }
  }

  const crqcHorizon = policy['crqcHorizon']
  if (crqcHorizon !== null && (typeof crqcHorizon !== 'number' || !Number.isInteger(crqcHorizon))) {
    throw new AnchorError(`policy.crqc_horizon must be an int or None: ${pyRepr(crqcHorizon)}`)
  }
  return policy as unknown as AnchorPolicy
}

function hex64(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || !HEX64_RE.test(value)) return null
  return hexToBytes(value)
}

/** Decode a bounded, even-length, lowercase-hex op operand, or `null`. */
function opHex(value: unknown): Uint8Array | null {
  if (
    typeof value !== 'string' ||
    codePointLength(value) > MAX_OP_HEX_LEN ||
    codePointLength(value) % 2 !== 0 ||
    !HEX_RE.test(value)
  ) {
    return null
  }
  return hexToBytes(value)
}

interface OtsChainReplay {
  accumulator: Uint8Array | null
  warning: string | null
}

/** Validate and replay an untrusted `ots` proof's `ops` op-chain, starting
 * from `accumulatorStart`. Returns `{accumulator, warning: null}` on
 * success, or `{accumulator: null, warning}` naming the first shape
 * violation. Shared by `verifyOtsProof` (verification) — mirrors
 * `anchor.py`'s `replay_ots_op_chain`; callers must never reimplement this
 * loop. */
export function replayOtsOpChain(accumulatorStart: Uint8Array, ops: unknown): OtsChainReplay {
  if (!Array.isArray(ops)) return { accumulator: null, warning: ANCHOR_WARN.OTS_OPS_NOT_LIST }
  if (ops.length === 0) return { accumulator: null, warning: ANCHOR_WARN.OTS_EMPTY_OPS }
  if (ops.length > MAX_OPS_PER_PROOF) {
    return { accumulator: null, warning: otsTooManyOps(MAX_OPS_PER_PROOF) }
  }

  let accumulator = accumulatorStart
  let totalOperandHex = 0
  for (const op of ops) {
    if (!Array.isArray(op) || op.length === 0 || typeof op[0] !== 'string') {
      return { accumulator: null, warning: ANCHOR_WARN.OTS_OP_SHAPE }
    }
    const opcode = op[0]
    if (!KNOWN_OTS_OPS.has(opcode)) {
      return { accumulator: null, warning: otsUnknownOp(opcode) }
    }
    if (opcode === 'sha256') {
      if (op.length !== 1) {
        return { accumulator: null, warning: ANCHOR_WARN.OTS_SHA256_TAKES_NO_OPERAND }
      }
      accumulator = sha256(accumulator)
    } else {
      if (op.length !== 2) return { accumulator: null, warning: otsOperandRequired(opcode) }
      const operand = opHex(op[1])
      if (operand === null) return { accumulator: null, warning: otsOperandInvalid(opcode) }
      // Bound the operand TOTAL, not just each operand: it is the total that
      // has to stay inside verify.ts's normative outer ceiling. Checked
      // BEFORE the concatenation, so refused material is never materialized.
      totalOperandHex += (op[1] as string).length
      if (totalOperandHex > MAX_TOTAL_OP_HEX_LEN) {
        return { accumulator: null, warning: otsOperandTotalTooLarge(MAX_TOTAL_OP_HEX_LEN) }
      }
      accumulator = opcode === 'append' ? concatBytes(accumulator, operand) : concatBytes(operand, accumulator)
    }
  }
  return { accumulator, warning: null }
}

interface OtsProofOutcome {
  verified: boolean
  headerTime: number
  warning: string | null
}

/** Evaluate one `ots` proof: replay its op-chain from `accumulatorStart`
 * and cross-check the result against a header pinned in `policy`.
 *
 * `legacyAccumulatorStart` (G4/I2, attest-v0.2.md §11.1.1) carries the
 * anchor-profile dimension, and `null` means the call has no such dimension
 * — either a declared note-v1 profile or a seed that is not a checkpoint's
 * bytes at all (`verifySeededAnchor`), both of which get the plain mismatch
 * warning. When it IS supplied (a declared signed-note-v2 profile), an
 * op-chain mismatch also replays the SAME `ops` from the legacy note-v1 seed
 * — purely diagnostic, never changes `verified` — so the warning can name
 * which seed the declared profile actually requires and flag a v1-shaped
 * commitment presented as v2. */
function verifyOtsProof(
  proof: Record<string, unknown>,
  accumulatorStart: Uint8Array,
  policy: AnchorPolicy,
  legacyAccumulatorStart: Uint8Array | null,
): OtsProofOutcome {
  const ops = proof['ops']
  const { accumulator, warning } = replayOtsOpChain(accumulatorStart, ops)
  if (warning !== null) return { verified: false, headerTime: 0, warning }

  const rootBytes = hex64(proof['header_merkle_root'])
  if (rootBytes === null) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_HEADER_MERKLE_ROOT_INVALID }
  }
  const headerHash = proof['header_hash']
  if (typeof headerHash !== 'string' || !HEX64_RE.test(headerHash)) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_HEADER_HASH_INVALID }
  }
  const headerTime = proof['header_time']
  if (
    typeof headerTime !== 'number' ||
    !Number.isInteger(headerTime) ||
    headerTime <= 0 ||
    headerTime > MAX_RENDERABLE_UNIX_TIME
  ) {
    return { verified: false, headerTime: 0, warning: otsHeaderTimeInvalid(MAX_RENDERABLE_UNIX_TIME) }
  }

  // `warning === null` above guarantees `accumulator` is non-null.
  if (!equalBytes(accumulator as Uint8Array, rootBytes)) {
    if (legacyAccumulatorStart === null) {
      return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_CHAIN_MISMATCH }
    }
    const legacyReplay = replayOtsOpChain(legacyAccumulatorStart, ops)
    const looksLikeV1 =
      legacyReplay.warning === null &&
      legacyReplay.accumulator !== null &&
      equalBytes(legacyReplay.accumulator, rootBytes)
    return {
      verified: false,
      headerTime: 0,
      warning: looksLikeV1
        ? ANCHOR_WARN.OTS_CHAIN_MISMATCH_V2_LOOKS_LIKE_V1
        : ANCHOR_WARN.OTS_CHAIN_MISMATCH_V2_REQUIRES,
    }
  }

  const pinned = policy.pinnedHeaders[headerHash]
  if (pinned === undefined) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_HEADER_NOT_PINNED }
  }
  if (pinned.merkleRoot !== proof['header_merkle_root']) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_PINNED_ROOT_MISMATCH }
  }
  if (pinned.time !== headerTime) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_PINNED_TIME_MISMATCH }
  }

  return { verified: true, headerTime: pinned.time, warning: null }
}

interface ProofWalkOutcome {
  anchored: boolean
  pqSurviving: boolean
  anchoredBefore: number | null
  anchoredAfter: number | null
}

/** Evaluate every proof in an already-shape-checked, already-capped `proofs`
 * list, appending any diagnostics to `warnings` in place.
 *
 * `anchoredBefore`/`anchoredAfter` are the minimum and maximum pinned time
 * over the proofs that actually VERIFIED (see `AnchorVerdict` for which
 * question each answers); both are computed here, once, from the same walk,
 * and a proof that failed for any reason contributes to neither. Shared by
 * both entry points so the proof-kind dispatch, the forward-compat "unknown
 * kind is ignored, not fatal" rule and both aggregations exist in exactly
 * one place — the only thing the two callers differ on is which bytes seed
 * the accumulator, and whether the anchor-profile diagnostic
 * (`legacyAccumulatorStart`) applies at all. */
function walkProofs(
  proofs: unknown[],
  accumulatorStart: Uint8Array,
  policy: AnchorPolicy,
  warnings: string[],
  legacyAccumulatorStart: Uint8Array | null,
): ProofWalkOutcome {
  let anchored = false
  let pqSurviving = false
  let anchoredBefore: number | null = null
  let anchoredAfter: number | null = null

  proofs.forEach((proof: unknown, i: number) => {
    if (!isPlainObject(proof)) {
      warnings.push(proofNotObject(i, proof))
      return
    }
    const kind = proof['kind']
    if (kind === 'ots') {
      const outcome = verifyOtsProof(proof, accumulatorStart, policy, legacyAccumulatorStart)
      if (outcome.warning !== null) warnings.push(proofPrefixed(i, outcome.warning))
      if (outcome.verified) {
        anchored = true
        pqSurviving = true
        if (anchoredBefore === null || outcome.headerTime < anchoredBefore) anchoredBefore = outcome.headerTime
        if (anchoredAfter === null || outcome.headerTime > anchoredAfter) anchoredAfter = outcome.headerTime
      }
    } else if (kind === 'rfc3161') {
      const tokenB64 = proof['token_b64']
      if (typeof tokenB64 !== 'string') {
        warnings.push(proofPrefixed(i, rfc3161TokenNotStr(tokenB64)))
        return
      }
      anchored = true
      warnings.push(RFC3161_WARNING)
    } else {
      warnings.push(proofPrefixed(i, unknownProofKind(kind)))
    }
  })

  return { anchored, pqSurviving, anchoredBefore, anchoredAfter }
}

/** Verify an anchor-evidence bundle against `checkpoint` and `policy`.
 *
 * `evidence` is untrusted and this function NEVER throws because of it: any
 * malformation degrades to an `AnchorVerdict` with `anchored: false` and a
 * warning naming the problem, and per-proof malformations drop only that
 * one proof (forward-compat: an unrecognized `kind` must not brick an old
 * verifier reading a bundle produced by a newer one). `checkpoint`/`policy`
 * are the trusted, verifier-config side: malformed ones throw `AnchorError`.
 */
export function verifyAnchor(evidence: unknown, checkpoint: unknown, policy: unknown): AnchorVerdict {
  if (!isCheckpointShape(checkpoint)) {
    throw new AnchorError(`checkpoint must be a tlog.Checkpoint, got ${pyTypeName(checkpoint)}`)
  }
  const validatedPolicy = validatePolicy(policy)

  const warnings: string[] = []
  const fail = (): AnchorVerdict => ({
    anchored: false,
    anchoredBefore: null,
    anchoredAfter: null,
    pqSurviving: false,
    warnings,
    noteOnly: false,
  })

  if (!isPlainObject(evidence)) {
    warnings.push(evidenceNotObject(evidence))
    return fail()
  }
  if (!('checkpoint' in evidence)) {
    warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_REQUIRED)
    return fail()
  }
  const checkpointText = evidence['checkpoint']
  if (typeof checkpointText !== 'string') {
    warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_NOT_STR)
    return fail()
  }
  if (codePointLength(checkpointText) > MAX_CHECKPOINT_TEXT_LEN) {
    warnings.push(evidenceCheckpointExceeds(MAX_CHECKPOINT_TEXT_LEN))
    return fail()
  }
  let evidenceCheckpoint: Checkpoint
  try {
    evidenceCheckpoint = parseCheckpoint(checkpointText)
  } catch (e) {
    if (e instanceof TlogError) {
      warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_INVALID)
      return fail()
    }
    throw e
  }
  if (!equalBytes(evidenceCheckpoint.noteBytes, checkpoint.noteBytes)) {
    warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_MISMATCH)
    return fail()
  }

  const proofs = evidence['proofs']
  if (!Array.isArray(proofs)) {
    warnings.push(evidenceProofsNotList(proofs))
    return fail()
  }
  if (proofs.length > MAX_PROOFS_PER_EVIDENCE) {
    warnings.push(evidenceProofsExceeds(MAX_PROOFS_PER_EVIDENCE))
    return fail()
  }

  let anchorProfile = 'anchor_profile' in evidence ? evidence['anchor_profile'] : ANCHOR_PROFILE_NOTE_V1
  if (anchorProfile === null) anchorProfile = ANCHOR_PROFILE_NOTE_V1 // explicit JSON null: same as absent
  if (typeof anchorProfile !== 'string' || !KNOWN_ANCHOR_PROFILES.has(anchorProfile)) {
    warnings.push(evidenceAnchorProfileInvalid(anchorProfile))
    return fail()
  }
  const noteOnly = anchorProfile !== ANCHOR_PROFILE_SIGNED_NOTE_V2
  // Both seeds are computed unconditionally (cheap): `legacyAccumulatorStart`
  // is only used diagnostically, on a v2 op-chain mismatch, to name the
  // common mistake of presenting a v1-shaped commitment as v2.
  const legacyAccumulatorStart = sha256(checkpoint.noteBytes)
  const v2AccumulatorStart = sha256(checkpoint.signedNoteBytes)
  const accumulatorStart = noteOnly ? legacyAccumulatorStart : v2AccumulatorStart
  const { anchored, pqSurviving, anchoredBefore, anchoredAfter } = walkProofs(
    proofs,
    accumulatorStart,
    validatedPolicy,
    warnings,
    noteOnly ? null : legacyAccumulatorStart,
  )

  return { anchored, anchoredBefore, anchoredAfter, pqSurviving, warnings, noteOnly }
}

/** Verify an anchor-evidence bundle whose op-chains start from `seed`.
 *
 * Answers a different question from `verifyAnchor`. That one asks "was THIS
 * checkpoint timestamped?" and therefore binds every op-chain to a
 * checkpoint's own bytes. This one asks "has real time reached date T?": the
 * caller holds an OpenTimestamps attestation over the canonical bytes of
 * some public document, and the only thing that matters is whether that
 * document's op-chain climbs to a Bitcoin header the verifier has pinned. A
 * pinned header's time is a lower bound on real time, so a verified anchor
 * is evidence that the world has already passed it.
 *
 * `seed` is that document's bytes, and the accumulator starts from
 * `sha256(seed)` — exactly as `verifyAnchor`'s legacy path starts from
 * `sha256(checkpoint.noteBytes)`. Passing a checkpoint's `noteBytes`
 * therefore replays the identical chain, and the two entry points return the
 * same anchor facts for the same `proofs`.
 *
 * There is no checkpoint on this path: `evidence.checkpoint` is neither
 * required nor read, and an incoherent one changes nothing. There is no
 * anchor profile either — profiles say which of a checkpoint's two
 * byte-strings an accumulator committed to, a distinction with no meaning
 * once the seed is an arbitrary document, so `evidence.anchor_profile` is
 * likewise not read and `AnchorVerdict.noteOnly` stays `false`.
 *
 * The verdict carries BOTH reductions over the verified `ots` proofs,
 * because this entry point's caller asks the opposite question from
 * `verifyAnchor`'s and neither reduction answers both:
 *
 * - `anchoredBefore` stays the MINIMUM, byte-for-byte the semantics
 *   `verifyAnchor` has always had. It is kept identical so two twin
 *   functions never answer the same evidence differently — a caller that
 *   moves a bundle between them must not see the floor shift.
 * - `anchoredAfter` is the MAXIMUM, and it is the field a "has time reached
 *   T?" caller wants. The minimum is the wrong reduction for that question
 *   as soon as a bundle carries two valid proofs: an old anchor and a new
 *   one both verify, the minimum reports the old one, and the caller
 *   concludes time has not advanced — a false negative it cannot undo,
 *   since the maximum is not recoverable from a verdict that dropped it.
 *
 * On the single-proof evidence this is usually built for, the two coincide;
 * they diverge exactly when it matters.
 *
 * `evidence` is untrusted and this function NEVER throws because of it. `seed`
 * and `policy` are the trusted, caller-config side: a non-`Uint8Array` or
 * empty `seed`, or a malformed `policy`, throws `AnchorError`. */
export function verifySeededAnchor(evidence: unknown, seed: Uint8Array, policy: unknown): AnchorVerdict {
  if (!(seed instanceof Uint8Array)) {
    throw new AnchorError(`seed must be bytes, got ${pyTypeName(seed)}`)
  }
  if (seed.length === 0) throw new AnchorError('seed must not be empty')
  const validatedPolicy = validatePolicy(policy)

  const warnings: string[] = []
  const fail = (): AnchorVerdict => ({
    anchored: false,
    anchoredBefore: null,
    anchoredAfter: null,
    pqSurviving: false,
    warnings,
    noteOnly: false,
  })

  if (!isPlainObject(evidence)) {
    warnings.push(evidenceNotObject(evidence))
    return fail()
  }

  const proofs = evidence['proofs']
  if (!Array.isArray(proofs)) {
    warnings.push(evidenceProofsNotList(proofs))
    return fail()
  }
  if (proofs.length > MAX_PROOFS_PER_EVIDENCE) {
    warnings.push(evidenceProofsExceeds(MAX_PROOFS_PER_EVIDENCE))
    return fail()
  }

  // Every list-shaped cap is now behind us, so the first digest of the call
  // is bounded work: MAX_OPS_PER_PROOF and MAX_OP_HEX_LEN bound the rest
  // inside replayOtsOpChain, which checks an operand's length before ever
  // concatenating or hashing it.
  const accumulatorStart = sha256(seed)
  const { anchored, pqSurviving, anchoredBefore, anchoredAfter } = walkProofs(
    proofs,
    accumulatorStart,
    validatedPolicy,
    warnings,
    null,
  )

  return { anchored, anchoredBefore, anchoredAfter, pqSurviving, warnings, noteOnly: false }
}

/** True iff `policy.crqcHorizon === null`, or `verdict` is a PQ-surviving
 * anchor whose time is strictly before the horizon. Pure function of
 * `(verdict, policy)`: throws `AnchorError` only on a malformed `policy`
 * (trusted, verifier-config side). Never throws on `verdict` — even a
 * malformed-content verdict degrades to `false` rather than throwing. */
export function passesHorizon(verdict: unknown, policy: unknown): boolean {
  const validatedPolicy = validatePolicy(policy)
  if (validatedPolicy.crqcHorizon === null) return true
  if (!isAnchorVerdictShape(verdict)) return false
  const anchoredBefore = verdict.anchoredBefore
  if (typeof anchoredBefore !== 'number' || !Number.isInteger(anchoredBefore)) return false
  return Boolean(verdict.pqSurviving) && anchoredBefore < validatedPolicy.crqcHorizon
}
