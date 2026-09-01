// Verbatim error/warning strings. Conformance vectors substring-match these,
// so DO NOT paraphrase. `pyRepr` is the retained, deliberately limited v0.1
// renderer. Stage 2 warning paths that mirror Python's ascii() use
// `pyStage2StringRepr` below instead.

export function pyRepr(x: unknown): string {
  if (typeof x === 'string') return `'${x}'`
  if (x === null || x === undefined) return 'None'
  if (typeof x === 'boolean') return x ? 'True' : 'False'
  if (Array.isArray(x)) return `[${x.map(pyRepr).join(', ')}]`
  return String(x)
}

/** Count Unicode code points, matching Python's `len(str)`, rather than JS
 * UTF-16 code units. Avoids materializing an array for attacker-sized text. */
export function codePointLength(s: string): number {
  let length = 0
  for (const _ of s) length++
  return length
}

/** Python `s[:limit]` semantics for JS strings. The callers use small,
 * fixed limits for rendered diagnostics, so building the bounded result is
 * safe without splitting an attacker-controlled full string into an array. */
export function sliceCodePoints(s: string, limit: number): string {
  let result = ''
  let length = 0
  for (const ch of s) {
    if (length === limit) break
    result += ch
    length++
  }
  return result
}

/** Faithful Python `ascii(str)` for the bounded Stage-2 warning/error paths.
 * It intentionally does not replace the legacy v0.1 `pyRepr` helper above. */
export function pyStage2StringRepr(value: string): string {
  const quote = value.includes("'") && !value.includes('"') ? '"' : "'"
  let out = quote
  for (const ch of value) {
    const cp = ch.codePointAt(0)!
    if (ch === '\\') out += '\\\\'
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (ch === '\t') out += '\\t'
    else if (ch === quote) out += `\\${quote}`
    else if (cp >= 0x20 && cp < 0x7f) out += ch
    else if (cp < 0x100) out += `\\x${cp.toString(16).padStart(2, '0')}`
    else if (cp <= 0xffff) out += `\\u${cp.toString(16).padStart(4, '0')}`
    else out += `\\U${cp.toString(16).padStart(8, '0')}`
  }
  return out + quote
}

// Python `type(x).__name__` for the closed universe of values that ever cross
// the tlog/anchor/transparency untrusted-evidence boundary (already-JSON.parse'd
// data: null/bool/number/string/array/plain-object — never bigint, never a
// class instance). Stage 1's messages never needed this; Stage 2's fail-closed
// warnings interpolate it verbatim (e.g. anchor.py's `type(evidence).__name__`).
export function pyTypeName(x: unknown): string {
  if (x === null || x === undefined) return 'NoneType'
  if (typeof x === 'boolean') return 'bool'
  if (typeof x === 'number') return Number.isInteger(x) ? 'int' : 'float'
  if (typeof x === 'string') return 'str'
  if (Array.isArray(x)) return 'list'
  if (typeof x === 'object') return 'dict'
  return typeof x
}

export const ERR = {
  ENVELOPE_NOT_OBJECT: 'envelope is not a JSON object',
  MISSING_PAYLOAD: "envelope missing object member 'payload'",
  MISSING_SIGNATURES: "envelope missing array member 'signatures'",
  MALFORMED_SIG_BLOCK: 'malformed signature block',
  MALFORMED_SIG_BLOCK_TYPES: "malformed signature block: 'kid'/'sig' must be strings",
  MISSING_ISSUER_ID: 'malformed payload: missing issuer.id',
  ISSUER_MISMATCH: 'issuer_mismatch: kid domain does not match payload issuer.id',
  SIG_VERIFICATION_FAILED: 'signature verification failed',
  FLOATS_NOT_ALLOWED: 'floats are not allowed in the attest-JCS profile',
  LONE_SURROGATE: 'lone surrogate not allowed in the attest-JCS profile',
  TYPE_NOT_JSON: 'type not representable in JSON',
  MAX_NESTING_DEPTH: 'maximum nesting depth exceeded',
  // v0.2 hybrid envelope (Ed25519 + ML-DSA-65) — byte-identical to verify.py.
  hybridSigCount: 'hybrid envelope requires exactly two signatures',
  hybridAlgs: 'hybrid envelope requires algs Ed25519 and ML-DSA-65 in order',
  hybridKidShared: 'hybrid envelope signatures must share a single kid',
  hybridKidType: "malformed signature block: 'kid' must be a string",
  hybridSigType: "malformed signature block: 'sig' must be a string",
  mldsaSigInvalid: 'ML-DSA-65 signature verification failed',
} as const

export const WARN = {
  DRM_BOUND: 'license.drm is drm-bound (design vector 18)',
  REVOCABILITY_NONE_IGNORED: "revocation record ignored: license.revocability is 'none' (irrevocable)",
  // G6 mixed-keyset prohibition (v0.2 §2.3/§13 amendment) — the wire warning
  // string, exact and cross-language (Python parity: verify.py).
  MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING: 'mixed_keyset_active_ed_only_sibling',
  // G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
  // amendment) — the wire warning string, exact and cross-language.
  ARTIFACT_MANIFEST_UNVERSIONED: 'artifact_manifest_unversioned',
  ARTIFACT_MANIFEST_UNAUTHENTICATED: 'artifact_manifest_unauthenticated',
  ARTIFACT_MANIFEST_ISSUER_MISMATCH: 'artifact_manifest_issuer_mismatch',
  // V-L.8 (design vector "publisher authority") — the wire warning string,
  // exact and cross-language (Python parity: verify.py's
  // `_WARN_PUBLISHER_CLAIM_UNATTESTED`).
  PUBLISHER_CLAIM_UNATTESTED: 'publisher_claim_unattested',
} as const

export const unsupportedAttestVersion = (v: unknown) => `unsupported attest_version: ${pyRepr(v)}`
export const signaturesCount = (n: number) => `signatures must contain exactly one entry, got ${n}`
export const unsupportedSigAlg = (alg: unknown) => `unsupported signature algorithm: ${pyRepr(alg)}`
export const manifestNotSelfConsistent = (issuer: string) =>
  `issuer manifest for ${pyRepr(issuer)} is not self-consistent: its own signature does not verify`

export const noTrustedManifest = (issuer: string) => `no trusted manifest for issuer ${pyRepr(issuer)}`
export const noKeyInManifest = (kid: string) => `no key ${pyRepr(kid)} in issuer manifest`
export const keyCompromised = (kid: string) => `key ${kid} is compromised`
export const keyRetired = (kid: string) => `key ${kid} is retired`
export const issuedAtOutsideWindow = (issuedAt: unknown) => `issued_at ${pyRepr(issuedAt)} outside key validity window`
export const malformedKeyMaterial = (msg: string) => `malformed key material: ${msg}`
export const malformedSigMaterial = (msg: string) => `malformed signature material: ${msg}`
export const keyEntryNotHybrid = (kid: string) => `key entry for kid ${pyRepr(kid)} has no ML-DSA-65 public key`

// canon (CanonError messages)
export const duplicateKey = (k: string) => `duplicate object key: ${pyRepr(k)}`
export const intOutOfRange = (n: bigint) => `integer out of I-JSON safe range: ${n.toString()}`
export const nonStringKey = (k: unknown) => `non-string object key: ${pyRepr(k)}`
export const notUtf8 = (msg: string) => `input is not valid UTF-8: ${msg}`
export const invalidJson = (msg: string) => `invalid JSON: ${msg}`

// content + revocation warnings
export const unknownField = (k: string) => `unknown payload field: ${pyRepr(k)}`
export const unknownEol = (v: unknown) => `unknown survivability.end_of_life value: ${pyRepr(v)}`
export const revocationFailedVerify = (rid: unknown) => `revocation record for ${pyRepr(rid)} failed verification, ignored`
export const outsideRefundWindow = (rid: unknown) => `revocation record for ${pyRepr(rid)} outside refund window, ignored`
export const revocationViewOversize = (n: number, max: number) =>
  `revocation view exceeds ${max} records (${n} supplied), not evaluated`
export const revocationViewOversizeRevocable = (n: number, max: number) =>
  `revocation view exceeds ${max} records (${n} supplied), cannot certify a revocable receipt`

// G1 normative ceilings (attest-versioning.md §5 amendment) — byte-identical
// to validate.py / manifests.py.
export const envelopeExceedsBytes = (max: number) => `envelope exceeds ${max} bytes`
// nestingDepthExceeds() was deleted in the 2026-07-22 fix wave along with
// schema.ts's validateJsonDepth/jsonTreeDepth: the ceiling is now enforced
// entirely by canon.ts's own parse-time cap, which reports "maximum nesting
// depth exceeded" (invalidJson()), never this message.
export const manifestExceedsKeys = (max: number) => `issuer manifest exceeds ${max} keys`
export const manifestDuplicateKids = (kids: string[]) =>
  `issuer manifest lists duplicate kid(s): ${pyRepr(kids)}`

// --------------------------------------------------------------------------
// Stage 2 (tlog/anchor/transparency): AnchorVerdict.warnings and
// TransparencyResult.warnings are a cross-language protocol surface — copied
// byte-for-byte from anchor.py/transparency.py (see those modules' docstrings).
// TlogError/AnchorError/TransparencyError *messages* are free-form developer
// diagnostics with no parity requirement and mostly stay inline in their
// module, except where reused/templated here for DRY.
// --------------------------------------------------------------------------

export const RFC3161_WARNING =
  'rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight'

// Kept byte-identical to tlog.py: free-text entry scalars are bounded before
// regex matching, diagnostic rendering, or JCS canonicalization.
export const entryScalarExceeds = (max: number) => `entry scalar exceeds ${max} chars`

export const ANCHOR_WARN = {
  EVIDENCE_CHECKPOINT_REQUIRED: 'evidence.checkpoint is required',
  EVIDENCE_CHECKPOINT_NOT_STR: 'evidence.checkpoint must be a str',
  EVIDENCE_CHECKPOINT_INVALID: 'evidence.checkpoint is not a valid signed checkpoint',
  EVIDENCE_CHECKPOINT_MISMATCH: 'evidence.checkpoint does not match checkpoint argument',
  OTS_EMPTY_OPS: 'ots proof has empty op-chain',
  OTS_OPS_NOT_LIST: "ots proof 'ops' must be a list",
  OTS_HEADER_MERKLE_ROOT_INVALID: "ots proof 'header_merkle_root' must be 64 lowercase hex chars",
  OTS_HEADER_HASH_INVALID: "ots proof 'header_hash' must be 64 lowercase hex chars",
  OTS_CHAIN_MISMATCH: 'ots op-chain result does not match header_merkle_root',
  // G4/I2 (attest-v0.2.md §11.1.1): the same base mismatch, but under a
  // declared signed-note-v2 profile — profile-aware, so the verifier names
  // which seed the profile requires and, when the legacy note-v1 seed's
  // replay genuinely matches, flags the common mistake explicitly.
  OTS_CHAIN_MISMATCH_V2_REQUIRES:
    'ots op-chain result does not match header_merkle_root; anchor_profile signed-note-v2 requires the accumulator to start from SHA256(checkpoint.signed_note_bytes)',
  OTS_CHAIN_MISMATCH_V2_LOOKS_LIKE_V1:
    'ots op-chain result does not match header_merkle_root; anchor_profile signed-note-v2 requires the accumulator to start from SHA256(checkpoint.signed_note_bytes) — this evidence looks like a note-v1 commitment presented as signed-note-v2',
  OTS_HEADER_NOT_PINNED: 'header_hash is not in policy.pinned_headers',
  OTS_PINNED_ROOT_MISMATCH: 'pinned header merkle_root does not match proof',
  OTS_PINNED_TIME_MISMATCH: 'pinned header time does not match proof',
  OTS_OP_SHAPE: 'ots op must be a non-empty list with a string opcode',
  OTS_SHA256_TAKES_NO_OPERAND: "ots 'sha256' op takes no operand",
} as const

export const evidenceNotObject = (v: unknown) => `evidence must be an object, got ${pyTypeName(v)}`
export const evidenceProofsNotList = (v: unknown) => `evidence.proofs must be a list, got ${pyTypeName(v)}`
export const evidenceCheckpointExceeds = (max: number) => `evidence.checkpoint exceeds max length ${max}`
export const evidenceProofsExceeds = (max: number) => `evidence.proofs exceeds max length ${max}`
export const proofNotObject = (i: number, v: unknown) => `proof[${i}]: must be an object, got ${pyTypeName(v)}`
export const proofPrefixed = (i: number, msg: string) => `proof[${i}]: ${msg}`
export const otsTooManyOps = (max: number) => `ots proof has more than ${max} ops`
export const otsOperandTotalTooLarge = (max: number) => `ots proof operands exceed ${max} total hex chars`
export const otsUnknownOp = (op: string) => `unknown ots op ${pyTruncRepr(op)}`
export const otsOperandInvalid = (op: string) => `ots ${pyTruncRepr(op)} operand must be bounded, even-length lowercase hex`
export const otsOperandRequired = (op: string) => `ots ${pyTruncRepr(op)} op needs exactly one hex operand`
export const otsHeaderTimeInvalid = (max: number) =>
  `ots proof 'header_time' must be a positive int no later than ${max}`
export const rfc3161TokenNotStr = (v: unknown) => `rfc3161 token_b64 must be a str, got ${pyTypeName(v)}`
export const unknownProofKind = (kind: unknown) => `unknown proof kind ${pyTruncRepr(kind)}, ignored`
// G4 (attest-v0.2.md §11.1): evidence declares an anchor_profile outside {absent, null, 'note-v1', 'signed-note-v2'}.
export const evidenceAnchorProfileInvalid = (v: unknown) =>
  `evidence.anchor_profile must be 'note-v1' or 'signed-note-v2', got ${pyTruncRepr(v)}`

// `anchor._trunc`: safely render an untrusted scalar for a bounded warning —
// never invoke a hostile object's own stringification, only these three cases.
export function pyTruncRepr(value: unknown, limit = 60): string {
  if (typeof value === 'string') {
    const text = pyStage2StringRepr(sliceCodePoints(value, limit))
    return codePointLength(text) <= limit ? text : sliceCodePoints(text, limit - 3) + '...'
  }
  if (value === null || value === undefined || typeof value === 'boolean') return pyRepr(value)
  if (typeof value === 'number' && Number.isInteger(value)) return String(value)
  const typeName = pyTypeName(value)
  return `<${typeName.slice(0, limit - 2)}>`
}

// transparency.py: fixed, short, snake_case tokens — a cross-language
// protocol surface (module docstring). Values are the literal wire strings;
// export names are UPPER_SNAKE for readability only.
export const TRANSPARENCY_WARN = {
  EVIDENCE_INVALID: 'evidence_invalid',
  ENTRY_INVALID: 'entry_invalid',
  ENTRY_MISMATCH: 'transparency_entry_mismatch',
  CHECKPOINT_INVALID: 'checkpoint_invalid',
  CHECKPOINT_VERIFICATION_FAILED: 'checkpoint_verification_failed',
  LEAF_INDEX_INVALID: 'leaf_index_invalid',
  TREE_SIZE_INVALID: 'tree_size_invalid',
  TREE_SIZE_MISMATCH: 'tree_size_mismatch',
  INCLUSION_PROOF_INVALID: 'inclusion_proof_invalid',
  INCLUSION_PROOF_TOO_LONG: 'inclusion_proof_too_long',
  PRIOR_CHECKPOINT_INVALID: 'prior_checkpoint_invalid',
  CONSISTENCY_PROOF_MISSING: 'consistency_proof_missing',
  CONSISTENCY_PROOF_INVALID: 'consistency_proof_invalid',
  CONSISTENCY_PROOF_TOO_LONG: 'consistency_proof_too_long',
  EQUIVOCATION_DETECTED: 'log_equivocation_detected',
  ANCHORS_INVALID: 'anchors_invalid',
  ANCHOR_TIME_INVALID: 'anchor_time_invalid',
  // G4 (attest-v0.2.md §11.1): an anchor that established standing via the
  // legacy note-bytes-only commitment (AnchorVerdict.noteOnly) — still
  // fully verifiable (eternal verifiability, attest-versioning.md §3), just
  // classified as the weaker profile.
  ANCHOR_NOTE_ONLY: 'anchor_note_only',
  POST_HORIZON_UNANCHORED: 'post_horizon_unanchored',
  EVIDENCE_EVALUATION_FAILED: 'evidence_evaluation_failed',
} as const

// verify.py Stage 2 integration warnings (also fixed snake_case tokens).
export const VERIFY_TRANSPARENCY_WARN = {
  CONFIG_MISSING: 'transparency_config_missing',
  CLAIM_UNRESOLVABLE: 'transparency_claim_unresolvable',
  ROTATION_CHAIN_REQUIRED: 'corroboration_requires_rotation_chain',
  // G5 (v0.2 §8/§15 amendment, TM-47): a refund_window revocation record
  // that fails the deadline-effectiveness rule (unlogged, or anchored after
  // the receipt's own refund-window deadline) — exact, cross-language wire
  // string (Python parity: verify.py).
  REVOCATION_UNLOGGED_DEADLINE: 'revocation_unlogged_deadline',
} as const

// v0.1 rev 8 / v0.2 §19 anchored compromise cutoff.
// v0.2 §20: the publisher-authority rail. Three literals, byte-identical to the
// Python core's, because a verdict a caller reads must read the same in both.
export const AUTHORITY_WARN = {
  PUBLISHER_NOT_AUTHORIZING_ISSUER: 'publisher_not_authorizing_issuer',
  SIGNER_NOT_PUBLISHER: 'authorization_signer_not_publisher',
  INVALID_IGNORED: 'authorization_invalid_ignored',
} as const

export const COMPROMISE_WARN = {
  RESCUE_APPLIED: 'compromise_rescue_applied',
  CUTOFF_UNANCHORED: 'compromise_cutoff_unanchored',
  RESCUE_REQUIRES_ANCHORED_RECEIPT: 'compromise_rescue_requires_anchored_receipt',
  RESCUE_RECEIPT_AFTER_CUTOFF: 'compromise_rescue_receipt_after_cutoff',
  CUTOFF_CLAIM_IGNORED: 'compromise_cutoff_claim_ignored',
  MARKING_RETRACTED: 'compromise_marking_retracted',
} as const

// v0.2 Stage 3 (§17.2-§17.4, verbatim; TS parity: Python's verify.py) —
// transferred-class backing warnings for classifyRevocation's transferred
// branch (revocation.ts).
export const TRANSFER_WARN = {
  REVOCATION_UNBACKED: 'transferred_revocation_unbacked',
  RECORD_UNLOGGED: 'transfer_record_unlogged',
  NOT_YET_TRANSFERABLE: 'transfer_not_yet_transferable',
  DOUBLE_ASSIGNMENT: 'transfer_double_assignment_conflict',
} as const

// v0.2 Stage 4 (§18.5's ten warning literals, verbatim; TS parity: Python's
// verify.py). All ten are bare wire tokens, not prose: a caller matches them
// exactly, and §18 pins the spelling.
export const GRANT_WARN = {
  NARROWING_IGNORED: 'grant_narrowing_ignored',
  UNANCHORED: 'grant_unanchored',
  SIGNER_NOT_PUBLISHER: 'grant_signer_not_publisher',
  SCOPE_UNCOVERED: 'grant_scope_uncovered',
  COMMITMENT_MISMATCH: 'grant_commitment_mismatch',
  COMMITMENT_DIVERGENCE: 'grant_commitment_divergence',
  DECLARATION_IGNORED: 'grant_declaration_ignored',
  ACTIVATED_BY_SUCCESSOR: 'grant_activated_by_successor',
  PLEDGE_TYPE_UNKNOWN: 'grant_pledge_type_unknown',
  LEGAL_TEXT_CHANGED: 'grant_legal_text_changed',
} as const
