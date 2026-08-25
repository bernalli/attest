// Transparency/corroboration evaluator — mirrors src/attest/transparency.py
// (Python reference). Given one untrusted evidence bundle for a single claim
// (an entry logged into a transparency log, optionally anchored into a
// Bitcoin block header), `evaluateTransparency` walks the Python module's
// documented 7-step decision order and returns a `TransparencyResult` —
// never throwing because of anything in `evidence`.
//
// Untrusted-evidence convention (shared with tlog.ts/anchor.ts): every value
// under `evidence` is a plain "materialized" JSON value — `number` for
// integers, never `bigint` — matching how `verify.ts`'s Stage 2 integration
// produces it (JCS round-trip through `canon.dumps` + native `JSON.parse`,
// which is exactly what strips a hostile object down to inert data AND
// forces every integer through the JCS-safe range, 2**53-1). The one
// exception is `Checkpoint.treeSize` (tlog.ts), which is `bigint` because a
// checkpoint's OWN header can declare a tree size up to 2**64-1 — this
// module converts between the two only at the evidence/checkpoint boundary
// (`BigInt(treeSize) === checkpoint.treeSize`).
//
// Warning strings are fixed, short, snake_case tokens (never carrying
// interpolated untrusted values) precisely because they are a
// cross-language protocol surface — copied byte-for-byte from
// transparency.py (see messages.ts's `TRANSPARENCY_WARN`/`VERIFY_TRANSPARENCY_WARN`).
// `TransparencyError` messages are free-form developer diagnostics with no
// parity requirement.
import { hexToBytes } from '@noble/curves/utils.js'
import {
  AnchorError,
  AnchorPolicy,
  AnchorVerdict,
  verifyAnchor,
  passesHorizon,
  validatePolicy as validateAnchorPolicy,
} from './anchor.js'
import {
  Checkpoint,
  noteSignatures,
  LogKey,
  TlogError,
  encodeEntry,
  leafHash,
  verifyInclusion,
  verifyConsistency,
  verifyCheckpoint,
  validateLogKey,
  validateOrigin as tlogValidateOrigin,
} from './tlog.js'
import { TRANSPARENCY_WARN, pyTypeName } from './messages.js'
import {
  evaluateCorroboration,
  parsePolicy as parseWitnessPolicy,
  type WitnessPolicy,
} from './witness.js'

// RFC 6962 inclusion/consistency proofs for a tree of at most 2**64 leaves
// have at most 64 entries (one per tree level) — caps a hostile proof list
// before any per-item work is done on it.
const MAX_PROOF_LEN = 64
const HEX64_RE = /^[0-9a-f]{64}$/

export const TRANSPARENCY_NOT_CHECKED = 'not_checked'
export const TRANSPARENCY_LOGGED = 'logged'
export const TRANSPARENCY_EQUIVOCATION_DETECTED = 'equivocation_detected'
// "anchored_before:<T>" is rendered dynamically by `iso8601`, not a fixed literal.

export const CORROBORATION_NONE = 'none'
export const CORROBORATION_LOGGED = 'logged'
// Defined for the Stage 3 contract but unreachable in Stage 2: no witness
// input exists yet on the evidence schema above.
export const CORROBORATION_WITNESSED = 'witnessed'

export const MAX_PROOF_LEN_ = MAX_PROOF_LEN

export class TransparencyError extends Error {}

export interface TransparencyResult {
  transparency: string
  corroboration: string
  warnings: string[]
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function notChecked(warning: string): TransparencyResult {
  return { transparency: TRANSPARENCY_NOT_CHECKED, corroboration: CORROBORATION_NONE, warnings: [warning] }
}

/** Render a unix-seconds timestamp as `YYYY-MM-DDTHH:MM:SSZ` (UTC). KAT:
 * `1700000000 -> "2023-11-14T22:13:20Z"`. Returns `null` if the timestamp
 * can't be rendered. Verified anchor times are bounded in
 * `anchor.validatePolicy`, but this remains a defensive containment for
 * future anchor-verdict paths. */
export function iso8601(unixTime: number): string | null {
  if (typeof unixTime !== 'number' || !Number.isInteger(unixTime)) return null
  const ms = unixTime * 1000
  if (!Number.isSafeInteger(ms)) return null
  const d = new Date(ms)
  if (Number.isNaN(d.getTime())) return null
  const year = d.getUTCFullYear()
  if (year < 0 || year > 9999) return null
  const pad = (n: number, len = 2) => String(n).padStart(len, '0')
  return (
    `${pad(year, 4)}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}` +
    `T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`
  )
}

/** Deep-validate the trusted pinned-key list. */
export function validateLogKeys(logKeys: unknown): LogKey[] {
  if (!Array.isArray(logKeys)) {
    throw new TransparencyError(`log_keys must be a list of LogKey, got ${pyTypeName(logKeys)}`)
  }
  try {
    return logKeys.map((key) => validateLogKey(key))
  } catch (e) {
    if (e instanceof TlogError) throw new TransparencyError(e.message)
    throw e
  }
}

export function validateExpectedOrigin(expectedOrigin: unknown): string {
  try {
    return tlogValidateOrigin(expectedOrigin, 'expected_origin')
  } catch (e) {
    if (e instanceof TlogError) throw new TransparencyError(e.message)
    throw e
  }
}

export function validatePolicy(policy: unknown): AnchorPolicy {
  try {
    return validateAnchorPolicy(policy)
  } catch (e) {
    if (e instanceof AnchorError) throw new TransparencyError(e.message)
    throw e
  }
}

export function validateExpectedEntry(expectedEntry: unknown): Record<string, unknown> {
  try {
    encodeEntry(expectedEntry)
  } catch (e) {
    if (e instanceof TlogError) throw new TransparencyError(e.message)
    throw e
  }
  if (!isPlainObject(expectedEntry)) {
    throw new TransparencyError(`expected_entry must be a dict, got ${pyTypeName(expectedEntry)}`)
  }
  return expectedEntry
}

/** Decode an already-length-bounded proof list: each item must be exactly
 * 64 lowercase hex chars (32 bytes once decoded). Returns `null` on any
 * item's shape violation rather than throwing. */
function decodeHexItems(items: unknown[]): Uint8Array[] | null {
  const decoded: Uint8Array[] = []
  for (const item of items) {
    if (typeof item !== 'string' || !HEX64_RE.test(item)) return null
    decoded.push(hexToBytes(item))
  }
  return decoded
}

/** Try each pinned key sharing `expectedOrigin` in order, accepting the
 * first whose `verifyCheckpoint` succeeds (log keys may rotate). `null` on
 * any shape violation or if no candidate verifies — never throws. */
function findVerifiedCheckpoint(text: unknown, candidates: LogKey[], expectedOrigin: string): Checkpoint | null {
  if (typeof text !== 'string') return null
  for (const key of candidates) {
    try {
      return verifyCheckpoint(text, key, expectedOrigin)
    } catch (e) {
      if (e instanceof TlogError) continue
      throw e
    }
  }
  return null
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (typeof a !== typeof b) return false
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false
    return a.every((v, i) => deepEqual(v, b[i]))
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const aKeys = Object.keys(a)
    const bKeys = Object.keys(b)
    if (aKeys.length !== bKeys.length) return false
    return aKeys.every((k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]))
  }
  return false
}

function evaluateUntrustedEvidence(
  evidence: unknown,
  logKeys: LogKey[],
  expectedOrigin: string,
  policy: AnchorPolicy,
  expectedEntry: Record<string, unknown>,
  witnessPolicy: WitnessPolicy | null = null,
): TransparencyResult {
  if (!isPlainObject(evidence)) return notChecked(TRANSPARENCY_WARN.EVIDENCE_INVALID)

  // --- Step 1: entry must encode under the closed schema and match what
  // the caller expects it to say. ---
  const entry = evidence['entry']
  if (!isPlainObject(entry)) return notChecked(TRANSPARENCY_WARN.ENTRY_INVALID)
  let entryBytes: Uint8Array
  try {
    entryBytes = encodeEntry(entry)
  } catch (e) {
    if (e instanceof TlogError) return notChecked(TRANSPARENCY_WARN.ENTRY_INVALID)
    throw e
  }
  if (!deepEqual(entry, expectedEntry)) return notChecked(TRANSPARENCY_WARN.ENTRY_MISMATCH)

  // --- Step 2: checkpoint must verify (hybrid AND) under a pinned key for
  // expectedOrigin; keys may rotate, so try every candidate in order. ---
  const matchingKeys = logKeys.filter((key) => key.origin === expectedOrigin)
  const checkpointText = evidence['checkpoint']
  if (typeof checkpointText !== 'string') return notChecked(TRANSPARENCY_WARN.CHECKPOINT_INVALID)
  const checkpoint = findVerifiedCheckpoint(checkpointText, matchingKeys, expectedOrigin)
  if (checkpoint === null) return notChecked(TRANSPARENCY_WARN.CHECKPOINT_VERIFICATION_FAILED)

  // --- Step 3: inclusion proof, plus the evidence's declared treeSize must
  // agree with what the verified checkpoint actually attests to. ---
  const leafIndex = evidence['leaf_index']
  if (typeof leafIndex !== 'number' || !Number.isSafeInteger(leafIndex)) {
    return notChecked(TRANSPARENCY_WARN.LEAF_INDEX_INVALID)
  }
  const treeSize = evidence['tree_size']
  if (typeof treeSize !== 'number' || !Number.isSafeInteger(treeSize)) {
    return notChecked(TRANSPARENCY_WARN.TREE_SIZE_INVALID)
  }
  if (checkpoint.treeSize !== BigInt(treeSize)) return notChecked(TRANSPARENCY_WARN.TREE_SIZE_MISMATCH)
  const rawInclusionProof = evidence['inclusion_proof']
  if (!Array.isArray(rawInclusionProof)) return notChecked(TRANSPARENCY_WARN.INCLUSION_PROOF_INVALID)
  if (rawInclusionProof.length > MAX_PROOF_LEN) return notChecked(TRANSPARENCY_WARN.INCLUSION_PROOF_TOO_LONG)
  const inclusionProof = decodeHexItems(rawInclusionProof)
  if (inclusionProof === null) return notChecked(TRANSPARENCY_WARN.INCLUSION_PROOF_INVALID)
  if (
    !verifyInclusion(leafHash(entryBytes), BigInt(leafIndex), BigInt(treeSize), inclusionProof, checkpoint.root)
  ) {
    return notChecked(TRANSPARENCY_WARN.INCLUSION_PROOF_INVALID)
  }

  // --- Step 4: an optional prior checkpoint claim. A validly-signed prior
  // whose consistency check fails is proof of equivocation (hard verdict);
  // anything else that prevents evaluating the claim is fail-safe. ---
  if ('prior_checkpoint' in evidence) {
    const priorCheckpointText = evidence['prior_checkpoint']
    const priorCheckpoint = findVerifiedCheckpoint(priorCheckpointText, matchingKeys, expectedOrigin)
    if (priorCheckpoint === null) return notChecked(TRANSPARENCY_WARN.PRIOR_CHECKPOINT_INVALID)
    if (!('consistency_proof' in evidence)) return notChecked(TRANSPARENCY_WARN.CONSISTENCY_PROOF_MISSING)
    const rawConsistencyProof = evidence['consistency_proof']
    if (!Array.isArray(rawConsistencyProof)) return notChecked(TRANSPARENCY_WARN.CONSISTENCY_PROOF_INVALID)
    if (rawConsistencyProof.length > MAX_PROOF_LEN) return notChecked(TRANSPARENCY_WARN.CONSISTENCY_PROOF_TOO_LONG)
    const consistencyProof = decodeHexItems(rawConsistencyProof)
    if (consistencyProof === null) return notChecked(TRANSPARENCY_WARN.CONSISTENCY_PROOF_INVALID)
    if (
      !verifyConsistency(
        priorCheckpoint.treeSize,
        priorCheckpoint.root,
        checkpoint.treeSize,
        checkpoint.root,
        consistencyProof,
      )
    ) {
      return {
        transparency: TRANSPARENCY_EQUIVOCATION_DETECTED,
        corroboration: CORROBORATION_NONE,
        warnings: [TRANSPARENCY_WARN.EQUIVOCATION_DETECTED],
      }
    }
  } else if ('consistency_proof' in evidence) {
    if (!Array.isArray(evidence['consistency_proof'])) {
      return notChecked(TRANSPARENCY_WARN.CONSISTENCY_PROOF_INVALID)
    }
  }

  // --- Step 5: base standing. ---
  let transparencyState: string = TRANSPARENCY_LOGGED
  let corroborationState: string = CORROBORATION_LOGGED
  const warnings: string[] = []

  // --- Step 6: an optional anchor claim upgrades transparencyState if a
  // PQ-surviving proof verifies. ---
  let anchorVerdict: AnchorVerdict | null = null
  if ('anchors' in evidence) {
    const anchorsEvidence = evidence['anchors']
    if (!isPlainObject(anchorsEvidence)) return notChecked(TRANSPARENCY_WARN.ANCHORS_INVALID)
    anchorVerdict = verifyAnchor(anchorsEvidence, checkpoint, policy)
    warnings.push(...anchorVerdict.warnings)
    if (anchorVerdict.pqSurviving && anchorVerdict.anchoredBefore !== null) {
      if (anchorVerdict.noteOnly) warnings.push(TRANSPARENCY_WARN.ANCHOR_NOTE_ONLY)
      const renderedAnchorTime = iso8601(anchorVerdict.anchoredBefore)
      if (renderedAnchorTime === null) {
        warnings.push(TRANSPARENCY_WARN.ANCHOR_TIME_INVALID)
        return { transparency: TRANSPARENCY_NOT_CHECKED, corroboration: CORROBORATION_NONE, warnings }
      }
      transparencyState = `anchored_before:${renderedAnchorTime}`
    }
  }

  // --- Step 7: a declared CRQC horizon caps standing back down unless a
  // PQ-surviving anchor lands strictly before it. ---
  const horizonOk = policy.crqcHorizon === null || (anchorVerdict !== null && passesHorizon(anchorVerdict, policy))
  if (!horizonOk) {
    warnings.push(TRANSPARENCY_WARN.POST_HORIZON_UNANCHORED)
    return { transparency: TRANSPARENCY_NOT_CHECKED, corroboration: CORROBORATION_NONE, warnings }
  }

  // --- Step 8: a pinned witness cosignature upgrades corroboration from
  // `logged` to `witnessed` (§10.1, P1.1b). Reachable only FROM `logged`: a
  // cosignature never rescues a broken inclusion proof. Any failure is
  // SILENT by §11.4 — the independence warning is the only literal this
  // layer may add, and only on success.
  if (witnessPolicy !== null && corroborationState === CORROBORATION_LOGGED) {
    const verdict = evaluateCorroboration(
      checkpoint,
      noteSignatures(new TextDecoder().decode(checkpoint.signedNoteBytes)),
      witnessPolicy,
      evidence['witness_policy_epoch'],
    )
    if (verdict.witnessed) {
      corroborationState = CORROBORATION_WITNESSED
      warnings.push(...verdict.warnings)
    }
  }

  return { transparency: transparencyState, corroboration: corroborationState, warnings }
}

export interface EvaluateTransparencyOptions {
  logKeys: LogKey[]
  expectedOrigin: string
  policy: AnchorPolicy
  expectedEntry: Record<string, unknown>
  /** TRUSTED witness policy, on the same rail as `logKeys`: packaged with the
   * release, never read off evidence. Omitting it preserves the previous
   * result exactly (§10.2). A malformed one throws. */
  witnessPolicy?: unknown
}

/** Evaluate one untrusted transparency/corroboration evidence bundle.
 *
 * Throws `TransparencyError` for a malformed trusted argument
 * (`logKeys`/`expectedOrigin`/`policy`/`expectedEntry`). Once those
 * arguments validate, no behavior supplied by `evidence` may escape this
 * boundary as an exception.
 */
/** Deep-validate the trusted witness policy; `null` means "not configured".
 *
 * Same rail as `logKeys`: a malformed policy is a caller/configuration bug
 * and throws, while omitting it entirely preserves the previous result. */
export function validateWitnessPolicy(witnessPolicy: unknown): WitnessPolicy | null {
  if (witnessPolicy === null || witnessPolicy === undefined) return null
  try {
    return parseWitnessPolicy(witnessPolicy)
  } catch (e) {
    throw new TransparencyError(e instanceof Error ? e.message : String(e))
  }
}

export function evaluateTransparency(evidence: unknown, options: EvaluateTransparencyOptions): TransparencyResult {
  const logKeys = validateLogKeys(options.logKeys)
  const expectedOrigin = validateExpectedOrigin(options.expectedOrigin)
  const policy = validatePolicy(options.policy)
  const expectedEntry = validateExpectedEntry(options.expectedEntry)
  const witnessPolicy = validateWitnessPolicy(options.witnessPolicy)

  try {
    return evaluateUntrustedEvidence(
      evidence,
      logKeys,
      expectedOrigin,
      policy,
      expectedEntry,
      witnessPolicy,
    )
  } catch {
    // Deliberate adversarial-boundary confinement, not lazy error handling:
    // a hostile evidence object's own property getters/toString/valueOf can
    // throw outside the precise shape-error checks above.
    return notChecked(TRANSPARENCY_WARN.EVIDENCE_EVALUATION_FAILED)
  }
}
