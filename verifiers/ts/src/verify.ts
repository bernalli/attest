import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { JsonObject, JsonValue, canonicalBytes, dumps, CanonError, loadsStrict } from './canon.js'
import {
  TrustStore, findKey, withinValidity, chainContinuous, MAX_MANIFEST_KEYS, hasActiveEdOnlySibling,
  artifactChainContinuous, verifyArtifactManifest,
} from './manifests.js'
import { verifyStrict, Ed25519LengthError } from './ed25519.js'
import { verifyStrict as verifyMldsaStrict, ML_DSA_65_ALG } from './mldsa.js'
import { b64uDecode } from './b64u.js'
import { validatePayload, SCHEMA_TOP_LEVEL_KEYS, validateEnvelopeSize } from './schema.js'
import { classifyRevocation, MAX_REVOCATION_RECORDS } from './revocation.js'
import { evaluateGrant, GRANT_NOT_CHECKED, GRANT_TRUST_NOT_CHECKED } from './grant.js'
import type { GrantVerdict } from './grant.js'
import { computeCommitment, verifyChallenge } from './commitment.js'
import { b64uEncode } from './b64u.js'
import { TlogError, LogKey, receiptCoreHash, encodeEntry } from './tlog.js'
import { AnchorPolicy, validatePolicy as validateAnchorPolicyOnly } from './anchor.js'
import {
  TransparencyError,
  TRANSPARENCY_NOT_CHECKED,
  TRANSPARENCY_EQUIVOCATION_DETECTED,
  CORROBORATION_NONE,
  evaluateTransparency,
  validateLogKeys,
  validateWitnessPolicy,
} from './transparency.js'
import {
  ERR, WARN, unsupportedAttestVersion, signaturesCount, unsupportedSigAlg, noTrustedManifest,
  noKeyInManifest, keyCompromised, keyRetired, issuedAtOutsideWindow, malformedKeyMaterial,
  malformedSigMaterial, unknownField, unknownEol, keyEntryNotHybrid, pyRepr, codePointLength,
  VERIFY_TRANSPARENCY_WARN, manifestExceedsKeys,
} from './messages.js'

// attest_version values this verifier's verify() step 1 accepts (v0.1 single-sig,
// v0.2 hybrid Ed25519+ML-DSA-65). Mirrors verify.py's `_SUPPORTED_ATTEST_VERSIONS`.
const SUPPORTED_ATTEST_VERSIONS = new Set(['0.1', '0.2'])

// Stage 2 (design doc "transparency/corroboration layer"): three new,
// purely informational result components. Defaults are the ZERO-behavior-
// change values existing callers already implicitly get.
const MANIFEST_FRESHNESS_NOT_CHECKED = 'not_checked'
const CLAIM_TYPE_RECEIPT = 'receipt'
const CLAIM_TYPE_KEY_MANIFEST = 'key-manifest'

// This outer cap must COVER everything the downstream evaluators' own inner
// caps accept, or evaluator-valid evidence gets falsely rejected here.
// Worst-case legitimate bundle, derived from those inner caps: checkpoint +
// prior_checkpoint + the anchors bundle's own checkpoint copy at ~500KB each,
// plus anchors proofs at 64 proofs x 64 ops x ~2060 chars per max
// append/prepend op ~ 8.5MB, plus inclusion/consistency proofs (~8KB) —
// ~10MB total. Mirrors verify.py's `_MAX_TRANSPARENCY_EVIDENCE_LEN`.
const MAX_TRANSPARENCY_EVIDENCE_LEN = 10_000_000
export const MAX_TRANSPARENCY_EVIDENCE_LEN_ = MAX_TRANSPARENCY_EVIDENCE_LEN

export type Signature = 'valid' | 'invalid'
export type Schema = 'valid' | 'invalid' | 'not_checked'
export type Binding = 'proven' | 'not_proven' | 'not_checked'
export type Trust = 'verified' | 'unauthenticated_tofu' | 'unverified_rotation'
export interface VerificationResult {
  signature: Signature; schema: Schema; revocation: string; binding: Binding; trust: Trust
  // Stage 2, informational only (never affect signature/schema/revocation/
  // binding/trust/ok): "not_checked" | "logged" | "anchored_before:<T>" |
  // "equivocation_detected"; "none" | "logged" | "witnessed"; "not_checked" |
  // "verified_as_of:<N>". Field names match the Python reference verbatim
  // (design doc + plan explicitly spell `manifest_freshness`, not camelCase).
  transparency: string; corroboration: string; manifest_freshness: string
  warnings: string[]; errors: string[]
  // v0.2 Stage 4 (§18.5), informational only and taking NO exception (D6):
  // neither ever affects `signature`, `schema`, `revocation`, `binding`,
  // `trust` or `ok` — a grant is a permission that becomes exercisable, never
  // a validity property of the receipt. Both default, for every caller that
  // never supplies `grantView`, to the values each already implicitly got.
  // `grant`: "not_checked" | "none" | "dormant" | "activated" |
  // "invalid_grant_ignored". `grant_trust`: "not_checked" | "verified" |
  // "unauthenticated_tofu" | "unverified_rotation" | "signer_mismatch".
  // Spelled snake_case for the same reason `manifest_freshness` is: these are
  // the wire-contract component names §18.5 pins.
  grant: string; grant_trust: string
}
export interface Disclosure {
  identifier?: string | null; identifier_type?: string | null
  salt?: Uint8Array | null; challenge?: [Uint8Array, Uint8Array] | null
}
// Stage 2 addition: verify(..., {transparency, logKeys, anchorPolicy}) — all
// optional, defaulting to the ZERO-behavior-change values. `transparency` is
// one untrusted evidence bundle (a bigint-typed JsonValue, matching this
// verifier's other JCS-serializable inputs); `logKeys`/`anchorPolicy` are
// the verifier's trusted, pinned configuration for evaluating it.
export interface VerifyTransparencyOptions {
  transparency?: JsonValue | null
  logKeys?: LogKey[] | null
  anchorPolicy?: AnchorPolicy | null
  // P1.1b (v0.2 §11.4): the TRUSTED witness policy, on the same rail as
  // `logKeys` — packaged with the verifier, never read off evidence. Omitting
  // it preserves the previous result exactly; supplying it is what makes
  // `corroboration: "witnessed"` reachable through the public verifier at all.
  witnessPolicy?: unknown
  // G5 (v0.2 §8/§15 amendment, TM-47): one untrusted transparency evidence
  // bundle for a SPECIFIC `refund_window` revocation record in
  // `revocationView`, reusing the SAME `logKeys`/`anchorPolicy`
  // configuration — see `classifyRevocation`'s deadline-effectiveness rule.
  revocationEvidence?: JsonValue | null
  // v0.2 Stage 3's (§17) evidence channel — the SECOND sanctioned exception
  // to "Stage 2 is purely informational", after G5's `revocationEvidence`:
  // an untrusted list of claims, each `{record: <a transfer.ts transfer
  // record>, evidence: <§10.2 evidence bundle>}`, reusing the SAME
  // `logKeys`/`anchorPolicy` Stage-2-capability gate (both supplied). A
  // `status: "transferred"` record in `revocationView` is honored —
  // `revocation: "transferred"`, capping `ok` the same way `"revoked"`
  // already does — only when this channel proves a BACKED transfer record
  // for the same receipt_id; see `classifyRevocation`'s transferred branch
  // (revocation.ts). A caller that never supplies `transferView` sees ZERO
  // behavior change, exactly like every other Stage 2/3 addition. Typed as
  // a list (not a single JsonValue) to match its runtime shape and
  // `revocationView`'s own sibling convention above.
  transferView?: JsonValue[] | null
  // v0.2 Stage 4's (§18) evidence channel and its capability gate at once —
  // see grant.ts's `evaluateGrant`, which this delegates to whole. It is NOT a
  // third exception to "Stage 2 is purely informational": per D6, Stage 4
  // takes no exception at all, so `grant`/`grant_trust` never touch
  // `signature`, `schema`, `revocation`, `binding`, `trust` or `ok`. A caller
  // that never supplies it gets `not_checked`/`not_checked` and a byte-for-byte
  // unchanged result, exactly like every Stage 2/3 addition before it. Typed
  // `unknown` rather than a shaped interface because it is UNTRUSTED evidence:
  // every member is validated inside the evaluation, never by the type system.
  grantView?: unknown
}
// attest-versioning.md §6.7 registers `sunset-grant` as `active`: it is the
// label a Stage 4 receipt carries (§18.6 makes it schema-REQUIRED once
// `license.preservation_pledge` is present), so it must stop being reported
// as an unknown value. The vocabulary stays OPEN — registering a value
// assigns it meaning, it does not close the field. Python parity:
// verify.py's `_KNOWN_EOL_VALUES`.
const KNOWN_EOL = new Set(['artifacts-remain-redownloadable', 'escrow', 'none', 'sunset-grant'])

export function isOk(r: VerificationResult): boolean {
  return (
    r.signature === 'valid' && r.schema === 'valid' &&
    r.revocation !== 'revoked' && r.revocation !== 'transferred' &&
    r.errors.length === 0
  )
}

function obj(v: JsonValue | undefined): JsonObject | null {
  return v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

// Loud boundary guard: a loadsStrict-parsed structure never contains a JS `number`
// (integers are `bigint`; floats are rejected at parse time). A JS `number` therefore
// means the consumer built the trust store / revocation view with `JSON.parse` instead
// of loadsStrict. Left unguarded, `manifest_version` as a `number` makes the self-verify
// helpers' `serialize` throw CanonError(TYPE_NOT_JSON) → swallowed by their `catch { return
// false }` → every revocation record is treated as forged → a genuinely REVOKED receipt
// reports not_revoked (silent fail-open). Fail fast at the public boundary instead. Walks
// arrays and plain objects only; non-plain values (e.g. Uint8Array) are not walked.
function assertCanonParsed(value: unknown, label: string): void {
  if (typeof value === 'number')
    throw new TypeError(`${label} must be parsed with loadsStrict (bigint integers), not JSON.parse — found a JS number`)
  if (Array.isArray(value)) {
    for (const item of value) assertCanonParsed(item, label)
    return
  }
  if (value !== null && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value)
    if (proto === Object.prototype || proto === null)
      for (const k of Object.keys(value)) assertCanonParsed((value as Record<string, unknown>)[k], label)
    // non-plain objects (Uint8Array, class instances, etc.) are intentionally not walked
  }
}

function contentWarnings(payload: JsonObject): string[] {
  const w: string[] = []
  for (const k of Object.keys(payload)) if (!SCHEMA_TOP_LEVEL_KEYS.has(k)) w.push(unknownField(k))
  const license = obj(payload['license'])
  if (license && license['drm'] === 'drm-bound') w.push(WARN.DRM_BOUND)
  const surv = obj(payload['survivability'])
  if (surv) { const eol = surv['end_of_life']; if (typeof eol !== 'string' || !KNOWN_EOL.has(eol)) w.push(unknownEol(eol)) }
  return w
}

function classifyBinding(payload: JsonObject, d: Disclosure): Binding {
  const buyer = obj(payload['buyer'])
  if (!buyer) return 'not_proven'
  if (d.salt != null && d.identifier != null && d.identifier_type != null) {
    const expected = buyer['commitment']
    if (typeof expected !== 'string') return 'not_proven'
    try { return b64uEncode(computeCommitment(d.identifier, d.identifier_type, d.salt)) === expected ? 'proven' : 'not_proven' }
    catch { return 'not_proven' }
  }
  if (d.challenge != null) {
    const pub = buyer['pubkey'], rid = payload['receipt_id']
    if (typeof pub !== 'string' || typeof rid !== 'string') return 'not_proven'
    try { return verifyChallenge(rid, d.challenge[0], d.challenge[1], b64uDecode(pub)) ? 'proven' : 'not_proven' }
    catch { return 'not_proven' }
  }
  return 'not_proven'
}

// --------------------------------------------------------------------------
// Stage 2: transparency/corroboration/manifest_freshness integration.
// --------------------------------------------------------------------------

/** True iff `chain` is a validated, gapless rotation history from
 * manifest_version 1 through `manifest` itself, held in the verifier's OWN
 * trust store (design fix 6). Deliberately STRICTER than the plain
 * `chainContinuous` use for `trust`: an ABSENT chain is fine for `trust`
 * (nothing to validate) but NOT fine here — corroborating a rotated
 * key-manifest requires the verifier to already hold every intermediate
 * version itself. `trust` semantics are untouched by this function — it
 * feeds `corroboration` only. */
function rotationChainVerified(chain: JsonObject[] | undefined, manifest: JsonObject | undefined): boolean {
  if (!chain || chain.length === 0 || manifest == null) return false
  if (dumps(chain[chain.length - 1]!) !== dumps(manifest)) return false
  if (chain[0]!['manifest_version'] !== 1n) return false
  return chainContinuous(chain)
}

/** `candidate` iff it passes the log's own closed entry schema, else `null`
 * — never trust a computed entry into `evaluateTransparency` without this
 * (a malformed `expectedEntry` would throw `TransparencyError`, which must
 * never happen just because the RECEIPT's own untrusted payload was
 * malformed, e.g. a bad `issuer.id`). */
function validatedTransparencyEntry(candidate: Record<string, unknown>): Record<string, unknown> | null {
  try {
    encodeEntry(candidate)
  } catch (e) {
    if (e instanceof TlogError) return null
    throw e
  }
  return candidate
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

interface ResolvedTransparencyClaim {
  claimType: string | null
  expectedEntry: Record<string, unknown> | null
  treeSize: number | null
}

/** Read the untrusted evidence's claimed type (`entry.type`) and, only if
 * `verify()` can independently compute a matching entry from its OWN
 * trusted artifacts, that entry — plus the evidence's own declared
 * `tree_size`. The evidence's OWN hash values are never trusted for
 * anything beyond dispatch — `expectedEntry` is always computed locally. */
function resolveTransparencyClaim(
  transparencyEvidence: unknown,
  envelope: JsonObject,
  receiptIssuerId: string | null,
  issuerManifest: JsonObject | null,
): ResolvedTransparencyClaim {
  if (!isPlainRecord(transparencyEvidence)) return { claimType: null, expectedEntry: null, treeSize: null }

  const entry = transparencyEvidence['entry']
  const rawClaimType = isPlainRecord(entry) ? entry['type'] : undefined
  const claimType = typeof rawClaimType === 'string' ? rawClaimType : null

  const rawTreeSize = transparencyEvidence['tree_size']
  const treeSize = typeof rawTreeSize === 'number' && Number.isInteger(rawTreeSize) ? rawTreeSize : null

  let expectedEntry: Record<string, unknown> | null = null
  if (claimType === CLAIM_TYPE_RECEIPT) {
    let coreHash: string | null
    try {
      coreHash = receiptCoreHash(envelope)
    } catch (e) {
      if (e instanceof TlogError) coreHash = null
      else throw e
    }
    if (coreHash !== null) {
      expectedEntry = validatedTransparencyEntry({
        type: CLAIM_TYPE_RECEIPT,
        issuer: receiptIssuerId,
        core_sha256: coreHash,
      })
    }
  } else if (claimType === CLAIM_TYPE_KEY_MANIFEST && issuerManifest !== null) {
    let manifestSha256: string | null
    try {
      manifestSha256 = bytesToHex(sha256(canonicalBytes(issuerManifest)))
    } catch (e) {
      if (e instanceof CanonError) manifestSha256 = null
      else throw e
    }
    if (manifestSha256 !== null) {
      const manifestVersionRaw = issuerManifest['manifest_version']
      expectedEntry = validatedTransparencyEntry({
        type: CLAIM_TYPE_KEY_MANIFEST,
        issuer: issuerManifest['issuer'],
        manifest_version: typeof manifestVersionRaw === 'bigint' ? Number(manifestVersionRaw) : manifestVersionRaw,
        manifest_sha256: manifestSha256,
      })
    }
  }

  return { claimType, expectedEntry, treeSize }
}

/** The single pinned origin shared by every entry in `logKeys` — this is
 * verify()'s own trusted configuration (mirrors `evaluateTransparency`'s
 * `expectedOrigin` argument), never derived from untrusted evidence. Each
 * key is deep-validated via `validateLogKeys` (byte lengths, name/origin
 * grammar), so a malformed pinned key throws here too, eagerly. Disagreeing
 * or empty origins are likewise a caller/config bug. */
function resolveLogOrigin(logKeys: LogKey[]): string {
  const validated = validateLogKeys(logKeys)
  const origins = new Set(validated.map((key) => key.origin))
  if (origins.size !== 1) {
    throw new TransparencyError(
      `log_keys must be a non-empty list sharing a single origin, got ${pyRepr([...origins].sort())}`,
    )
  }
  return [...origins][0]!
}

interface TransparencyClaimOutcome {
  transparency: string
  corroboration: string
  manifestFreshness: string
}

const ZERO_TRANSPARENCY_CLAIM: TransparencyClaimOutcome = {
  transparency: TRANSPARENCY_NOT_CHECKED,
  corroboration: CORROBORATION_NONE,
  manifestFreshness: MANIFEST_FRESHNESS_NOT_CHECKED,
}

/** Resolve `{transparency, corroboration, manifestFreshness}` from one
 * evidence bundle. Computed independently of the receipt's own pass/fail
 * verdict — called once, early, regardless of whether the receipt later
 * turns out invalid (e.g. a compromised key), so that corroboration can
 * never rescue an otherwise-rejected receipt. Absent evidence is the
 * ZERO-behavior-change default. Evidence present but `logKeys`/`anchorPolicy`
 * missing is a configuration gap — degrades with a warning, never throws.
 * A malformed `logKeys`/`anchorPolicy` is trusted-config, validated eagerly
 * regardless of what the evidence looks like, so a config bug always
 * surfaces as `TransparencyError`.
 */
function evaluateTransparencyClaim(
  envelope: JsonObject,
  receiptIssuerId: string | null,
  issuerManifest: JsonObject | null,
  rotationChainOk: boolean,
  transparencyEvidence: JsonValue | null,
  logKeys: LogKey[] | null,
  anchorPolicy: AnchorPolicy | null,
  warnings: string[],
  witnessPolicy: unknown = null,
): TransparencyClaimOutcome {
  if (transparencyEvidence == null) return ZERO_TRANSPARENCY_CLAIM

  if (logKeys == null || anchorPolicy == null) {
    warnings.push(VERIFY_TRANSPARENCY_WARN.CONFIG_MISSING)
    return ZERO_TRANSPARENCY_CLAIM
  }

  // Trusted-config validation: deliberately OUTSIDE the try block below,
  // mirroring verify.py's `_evaluate_transparency_claim` (the origin
  // resolution and policy re-validation run before the untrusted-evidence
  // phase's broad `except Exception`, so a config bug always surfaces as
  // TransparencyError rather than being masked as "claim unresolvable").
  const origin = resolveLogOrigin(logKeys)
  validateAnchorPolicyOnly(anchorPolicy)
  // Same discipline for the witness policy: verifier configuration, so a
  // malformed one throws here rather than being swallowed by the
  // untrusted-evidence boundary below.
  const validatedWitnessPolicy = validateWitnessPolicy(witnessPolicy)

  try {
    // verify()'s untrusted-evidence boundary. Canonicalize and parse once so
    // every following phase sees one ordinary JSON object (plain `number`
    // integers, never bigint) — never a stateful mapping/value supplied by
    // the caller. The size cap prevents decoding an arbitrarily large
    // serialized evidence bundle.
    const serializedEvidence = dumps(transparencyEvidence)
    if (codePointLength(serializedEvidence) > MAX_TRANSPARENCY_EVIDENCE_LEN) {
      throw new Error('transparency evidence exceeds materialization limit')
    }
    const materializedEvidence: unknown = JSON.parse(serializedEvidence)
    if (!isPlainRecord(materializedEvidence)) {
      throw new Error('transparency evidence is not an object')
    }

    const { claimType, expectedEntry, treeSize } = resolveTransparencyClaim(
      materializedEvidence,
      envelope,
      receiptIssuerId,
      issuerManifest,
    )
    if (expectedEntry === null) {
      warnings.push(VERIFY_TRANSPARENCY_WARN.CLAIM_UNRESOLVABLE)
      return ZERO_TRANSPARENCY_CLAIM
    }

    const result = evaluateTransparency(materializedEvidence, {
      logKeys,
      expectedOrigin: origin,
      policy: anchorPolicy,
      expectedEntry,
      witnessPolicy: validatedWitnessPolicy,
    })
    warnings.push(...result.warnings)

    let transparencyState = result.transparency
    let corroborationState = result.corroboration
    let manifestFreshnessState = MANIFEST_FRESHNESS_NOT_CHECKED

    const reachedLoggedOrBetter =
      transparencyState !== TRANSPARENCY_NOT_CHECKED && transparencyState !== TRANSPARENCY_EQUIVOCATION_DETECTED
    if (claimType === CLAIM_TYPE_KEY_MANIFEST && reachedLoggedOrBetter) {
      if (treeSize !== null) manifestFreshnessState = `verified_as_of:${treeSize}`
      const manifestVersion = issuerManifest ? issuerManifest['manifest_version'] : undefined
      if (typeof manifestVersion === 'bigint' && manifestVersion > 1n && !rotationChainOk) {
        corroborationState = CORROBORATION_NONE
        warnings.push(VERIFY_TRANSPARENCY_WARN.ROTATION_CHAIN_REQUIRED)
      }
    }

    return { transparency: transparencyState, corroboration: corroborationState, manifestFreshness: manifestFreshnessState }
  } catch {
    // Deliberately encloses every untrusted claim phase above, including
    // post-evaluation freshness/rotation logic. Confines hostile mapping
    // access and equality implementations.
    warnings.push(VERIFY_TRANSPARENCY_WARN.CLAIM_UNRESOLVABLE)
    return ZERO_TRANSPARENCY_CLAIM
  }
}

export function verify(
  envelopeBytes: Uint8Array, trustStore: TrustStore,
  revocationView: JsonValue[] | null = null, disclosure: Disclosure | null = null,
  maxRevocationRecords: number = MAX_REVOCATION_RECORDS,
  options: VerifyTransparencyOptions = {},
): VerificationResult {
  const transparencyEvidence = options.transparency ?? null
  const logKeys = options.logKeys ?? null
  const anchorPolicy = options.anchorPolicy ?? null
  const revocationEvidence = options.revocationEvidence ?? null
  const transferView = options.transferView ?? null
  const witnessPolicy = options.witnessPolicy ?? null
  const grantView = options.grantView ?? null

  if (revocationView !== null && !Array.isArray(revocationView))
    throw new TypeError('revocation_view must be a list of records or None')
  // Same caller-contract enforcement, extended to the Stage 3 channel: a
  // lone claim OBJECT must fail loud rather than be silently iterated as
  // dict keys by classifyRevocation's transferred-branch resolver.
  if (transferView !== null && !Array.isArray(transferView))
    throw new TypeError('transfer_view must be a list of claims or None')
  // Same caller-contract enforcement for Stage 4's channel: a lone grant
  // DOCUMENT passed where the evidence object belongs would otherwise be read
  // member by member and resolve to `not_checked`, silently reporting "no
  // grant evidence" to a caller who supplied some. Hostile CONTENT inside a
  // well-shaped view never throws — only the wrong container does. Raised here
  // as well as inside evaluateGrant so it fires before any parsing work, the
  // same position its two siblings above occupy.
  if (grantView !== null && (typeof grantView !== 'object' || Array.isArray(grantView)))
    throw new TypeError('grant_view must be an evidence object or None')

  // Fail loud if the trust store / revocation view was JSON.parse'd (JS numbers) rather
  // than loadsStrict-parsed (bigint). Prevents a silent revocation fail-open. Does NOT
  // walk envelopeBytes (parsed internally) or disclosure (holds raw Uint8Array fields).
  assertCanonParsed(trustStore.manifests, 'trustStore.manifests')
  if (trustStore.chains != null) assertCanonParsed(trustStore.chains, 'trustStore.chains')
  // Skip the deep JSON-number guard on an oversized view: it would be an O(N)
  // walk of attacker-controlled data (and would throw TypeError on a JSON.parse-d
  // oversized view instead of failing closed). classifyRevocation handles the
  // oversized case from length alone — matching Python, which never inspects
  // view elements before the len() cap.
  if (revocationView !== null && revocationView.length <= maxRevocationRecords)
    assertCanonParsed(revocationView, 'revocation_view')

  const errors: string[] = []
  const warnings: string[] = []
  let trust: Trust = 'unauthenticated_tofu'
  // Stage 2 defaults — the ZERO-behavior-change values (updated below, once,
  // right after trust is resolved; see `evaluateTransparencyClaim`'s doc
  // comment for why this runs before any pass/fail branching).
  let transparencyState: string = TRANSPARENCY_NOT_CHECKED
  let corroborationState: string = CORROBORATION_NONE
  let manifestFreshnessState: string = MANIFEST_FRESHNESS_NOT_CHECKED
  const invalid = (message: string, schema: Schema = 'not_checked'): VerificationResult => {
    errors.push(message)
    return {
      signature: 'invalid', schema, revocation: 'unknown', binding: 'not_checked', trust,
      transparency: transparencyState, corroboration: corroborationState, manifest_freshness: manifestFreshnessState,
      warnings: [...warnings], errors: [...errors],
      grant: GRANT_NOT_CHECKED, grant_trust: GRANT_TRUST_NOT_CHECKED,
    }
  }

  // --- G1 normative ceiling (attest-versioning.md §5 amendment; v0.1 §11/
  // §15, v0.2 §6/§16): the raw envelope MUST NOT exceed MAX_ENVELOPE_BYTES.
  // Checked on the undecoded bytes, before ANY parsing work. Reported as
  // schema: 'invalid' (not the 'not_checked' default every other
  // precondition failure below uses): this ceiling is conformance-surface,
  // not a parse-shape failure.
  const sizeViolations = validateEnvelopeSize(envelopeBytes)
  if (sizeViolations.length > 0) return invalid(sizeViolations[0]!, 'invalid')

  // Step 0 — strict parse.
  //
  // G1 normative ceiling (attest-versioning.md §5 amendment; v0.1 §11.3):
  // the parsed envelope tree's nesting depth MUST NOT exceed
  // schema.ts's MAX_JSON_DEPTH (== canon.ts's MAX_DEPTH, 256). Enforced
  // entirely by loadsStrict itself during parsing (CanonError, "maximum
  // nesting depth exceeded") — there is deliberately no separate walk of
  // the parsed tree here (2026-07-22 fix wave): the parser's own structural
  // safety cap already IS this ceiling, so a second, redundant check could
  // never fire (see schema.ts's MAX_JSON_DEPTH doc comment). A receipt that
  // trips it never produces a parsed object at all, so it is reported the
  // same way every other malformed-envelope failure is, schema:
  // 'not_checked' — unlike the byte-size/manifest-array ceilings, which run
  // AFTER a successful parse and are conformance-surface checks.
  let parsed: JsonValue
  try { parsed = loadsStrict(envelopeBytes) }
  catch (e) { if (e instanceof CanonError) return invalid(e.message); throw e }
  const envelope = obj(parsed)
  if (!envelope) return invalid(ERR.ENVELOPE_NOT_OBJECT)

  const payload = obj(envelope['payload'])
  if (!payload) return invalid(ERR.MISSING_PAYLOAD)
  const signatures = envelope['signatures']
  if (!Array.isArray(signatures)) return invalid(ERR.MISSING_SIGNATURES)

  // Trust resolution — AFTER payload/signatures checks, BEFORE step 1. Never reset later.
  const issuerBlock = obj(payload['issuer'])
  const issuerId = issuerBlock ? issuerBlock['id'] : undefined
  let issuerManifestForTransparency: JsonObject | undefined
  if (typeof issuerId === 'string') {
    trust = trustStore.provenance[issuerId] === 'tls' ? 'verified' : 'unauthenticated_tofu'
    issuerManifestForTransparency = trustStore.manifests[issuerId]

    // G1 ceiling + G6 detection preflight — moved ABOVE the chain handling
    // (2026-07-22 fix wave 2 round 2, finding I1 residual): the chain
    // tail compare below canonicalizes the resolved manifest via dumps(),
    // which is exactly the unbounded work the ceiling exists to prevent on
    // a hostile keys[] array. See the block comment further down.
    if (issuerManifestForTransparency != null) {
      const preflightKeys = issuerManifestForTransparency['keys']
      if (Array.isArray(preflightKeys) && preflightKeys.length > MAX_MANIFEST_KEYS) {
        return invalid(manifestExceedsKeys(MAX_MANIFEST_KEYS), 'invalid')
      }
      if (payload['attest_version'] === '0.2' && hasActiveEdOnlySibling(issuerManifestForTransparency)) {
        warnings.push(WARN.MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING)
      }
    }

    const chain = trustStore.chains?.[issuerId]
    if (chain && chain.length > 0) {
      // A chain that doesn't end at the manifest being used proves nothing about
      // it — value-compare the tail via its canonical form (2026-07-13 review,
      // finding 8).
      const used = trustStore.manifests[issuerId]
      const tailMatchesUsed = used != null && dumps(chain[chain.length - 1]!) === dumps(used)
      if (!chainContinuous(chain) || !tailMatchesUsed) trust = 'unverified_rotation'
    }
  }

  // --- G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
  // amendment): resolve currency state per (issuer, series), authenticate the
  // pinned manifest and every chain member before touching any currency
  // metadata, then warn legacy manifests or evaluate continuity.
  const workBlock = obj(payload['work'])
  const artifactSeries = workBlock ? workBlock['artifact_series'] : undefined
  if (typeof issuerId === 'string' && typeof artifactSeries === 'string') {
    const candidateArtifactManifest = trustStore.artifact_manifests?.[issuerId]?.[artifactSeries]
    if (candidateArtifactManifest != null) {
      const amChain = trustStore.artifact_manifest_chains?.[issuerId]?.[artifactSeries]
      const members = [candidateArtifactManifest, ...(amChain ?? [])]
      const authenticated = issuerManifestForTransparency != null && members.every(
        member => verifyArtifactManifest(member, issuerManifestForTransparency!),
      )
      if (candidateArtifactManifest['issuer'] !== issuerId) {
        warnings.push(WARN.ARTIFACT_MANIFEST_ISSUER_MISMATCH)
      } else if (!authenticated) {
        warnings.push(WARN.ARTIFACT_MANIFEST_UNAUTHENTICATED)
      } else {
        if (members.some(member => !('manifest_version' in member))) {
          // Any legacy member makes currency non-evaluable: warn and SKIP
          // both continuity and the tail compare — a legacy manifest must
          // never trigger the currency downgrade (v0.1 §7.3, warn-only;
          // round-2 review residual). Mirrors verify.py.
          warnings.push(WARN.ARTIFACT_MANIFEST_UNVERSIONED)
        } else if (amChain && amChain.length > 0) {
          const tailMatchesPinned = dumps(amChain[amChain.length - 1]!) === dumps(candidateArtifactManifest)
          if (!artifactChainContinuous(amChain) || !tailMatchesPinned) trust = 'unverified_rotation'
        }
      }
    }
  }

  // --- G1 normative ceiling, hoisted (attest-versioning.md §5 amendment;
  // v0.1 §11.3): the issuer manifest's keys[] array MUST NOT exceed
  // MAX_MANIFEST_KEYS — checked the moment the manifest is resolved from
  // the trust store, BEFORE any canonicalization/hash/signature/
  // transparency use of it. This MUST run before the transparency block
  // below: evaluateTransparencyClaim canonicalizes and hashes
  // issuerManifestForTransparency whole to check a key-manifest claim,
  // exactly the unbounded work a structural ceiling exists to prevent on a
  // hostile array (2026-07-22 fix wave 2, review finding I1 — this check
  // used to live only after Step 1/2 below, letting transparency/signature
  // work run on an oversized manifest first).
  //
  // G6 mixed-keyset detection is hoisted alongside it (review finding I2):
  // the warning must fire for every v0.2 resolution of a mixed manifest,
  // independent of whether the receipt's signatures go on to verify (v0.2
  // §13/§2.3 amendment) — it used to live only after both signature legs
  // verified, so a tampered/failed receipt never carried it. Detection only
  // depends on the manifest's own keyset and the payload's claimed
  // attest_version, neither of which requires any of the crypto/schema
  // work Step 1-4 below still gate their OWN errors on.
  //
  // Round 2 (finding I1 residual): the check itself now lives INSIDE the
  // trust-resolution block above, before the chain-continuity tail compare —
  // that compare canonicalizes the resolved manifest via dumps(), which is
  // already the unbounded work the ceiling must precede.

  // --- Transparency/corroboration (Stage 2, informational only): resolved
  // here, before any pass/fail branching below, so a receipt that later
  // turns out invalid (e.g. a compromised key) still reports whatever
  // standing the evidence actually earns — see `evaluateTransparencyClaim`.
  {
    const chain = typeof issuerId === 'string' ? trustStore.chains?.[issuerId] : undefined
    const rotationOk = rotationChainVerified(chain, issuerManifestForTransparency)
    const claimOutcome = evaluateTransparencyClaim(
      envelope,
      typeof issuerId === 'string' ? issuerId : null,
      issuerManifestForTransparency ?? null,
      rotationOk,
      transparencyEvidence,
      logKeys,
      anchorPolicy,
      warnings,
      witnessPolicy,
    )
    transparencyState = claimOutcome.transparency
    corroborationState = claimOutcome.corroboration
    manifestFreshnessState = claimOutcome.manifestFreshness
  }

  // Step 1 — envelope shape: attest_version supported; signatures length ==
  // 1 (v0.1) or exactly the hybrid pair (v0.2).
  const attestVersion = payload['attest_version']
  if (typeof attestVersion !== 'string' || !SUPPORTED_ATTEST_VERSIONS.has(attestVersion))
    return invalid(unsupportedAttestVersion(attestVersion))

  let manifest: JsonObject | undefined

  if (attestVersion === '0.2') {
    // --- v0.2 hybrid path: AND semantics — both the Ed25519 leg AND the
    // ML-DSA-65 leg must verify, or the receipt is invalid. Every failure
    // below fails closed via `invalid()`, never throwing.
    if (signatures.length !== 2) return invalid(ERR.hybridSigCount)

    const sig0 = obj(signatures[0]), sig1 = obj(signatures[1])
    if (!sig0 || !sig1) return invalid(ERR.MALFORMED_SIG_BLOCK)

    if (sig0['alg'] !== 'Ed25519' || sig1['alg'] !== ML_DSA_65_ALG) return invalid(ERR.hybridAlgs)

    const kid0 = sig0['kid'], kid1 = sig1['kid']
    if (kid0 !== kid1) return invalid(ERR.hybridKidShared)
    if (typeof kid0 !== 'string') return invalid(ERR.hybridKidType)
    const kid = kid0

    const edSigB64 = sig0['sig'], mldsaSigB64 = sig1['sig']
    if (typeof edSigB64 !== 'string' || typeof mldsaSigB64 !== 'string') return invalid(ERR.hybridSigType)

    // Step 2 (shared with v0.1) — issuer binding
    if (typeof issuerId !== 'string') return invalid(ERR.MISSING_ISSUER_ID)
    manifest = trustStore.manifests[issuerId]
    if (manifest == null) return invalid(noTrustedManifest(issuerId))

    // G1's manifest-keys ceiling and G6's mixed-keyset detection are both
    // handled above, hoisted immediately after issuerManifestForTransparency
    // (== this same manifest) is resolved from the trust store — see the
    // comment there (2026-07-22 fix wave 2, findings I1/I2).

    if (kid.split('/')[0] !== issuerId || manifest['issuer'] !== issuerId) return invalid(ERR.ISSUER_MISMATCH)

    // Step 3 (shared with v0.1) — key resolution + status + validity window
    const entry = findKey(manifest, kid)
    if (entry == null) return invalid(noKeyInManifest(kid))
    const status = entry['status']
    if (status === 'compromised') return invalid(keyCompromised(kid))
    if (status !== 'active' && status !== 'retired') return invalid(`key ${kid} has unusable status`)
    const issuedAt = payload['issued_at']
    if (typeof issuedAt !== 'string' || !withinValidity(issuedAt, entry)) return invalid(issuedAtOutsideWindow(issuedAt))
    if (status === 'retired') warnings.push(keyRetired(kid))

    // Hybrid-only: the resolved key entry must itself carry an ML-DSA-65
    // public key, or there is nothing to verify the second leg against.
    if (!('pub_ml_dsa_65' in entry)) return invalid(keyEntryNotHybrid(kid))

    let edPub: Uint8Array, mldsaPub: Uint8Array, edSig: Uint8Array, mldsaSig: Uint8Array
    try {
      const p = entry['pub'], pm = entry['pub_ml_dsa_65']
      if (typeof p !== 'string' || typeof pm !== 'string') throw new Error('pub not a string')
      edPub = b64uDecode(p); mldsaPub = b64uDecode(pm)
      edSig = b64uDecode(edSigB64); mldsaSig = b64uDecode(mldsaSigB64)
    } catch (e) { return invalid(malformedKeyMaterial(e instanceof Error ? e.message : String(e))) }

    let canonical: Uint8Array, edOk: boolean
    try { canonical = canonicalBytes(payload); edOk = verifyStrict(canonical, edSig, edPub) }
    catch (e) {
      if (e instanceof CanonError || e instanceof Ed25519LengthError) return invalid(malformedSigMaterial(e.message))
      throw e
    }
    if (!edOk) return invalid(ERR.SIG_VERIFICATION_FAILED)

    if (!verifyMldsaStrict(canonical, mldsaSig, mldsaPub)) return invalid(ERR.mldsaSigInvalid)
  } else {
    if (signatures.length !== 1) return invalid(signaturesCount(signatures.length))
    const sigBlock = obj(signatures[0])
    if (!sigBlock) return invalid(ERR.MALFORMED_SIG_BLOCK)
    const kid = sigBlock['kid'], alg = sigBlock['alg'], sigB64 = sigBlock['sig']
    if (typeof kid !== 'string' || typeof sigB64 !== 'string') return invalid(ERR.MALFORMED_SIG_BLOCK_TYPES)
    if (alg !== 'Ed25519') return invalid(unsupportedSigAlg(alg))

    // Step 2 — issuer binding
    if (typeof issuerId !== 'string') return invalid(ERR.MISSING_ISSUER_ID)
    manifest = trustStore.manifests[issuerId]
    if (manifest == null) return invalid(noTrustedManifest(issuerId))

    // G1's manifest-keys ceiling is handled above, hoisted immediately after
    // issuerManifestForTransparency (== this same manifest) is resolved from
    // the trust store — see the comment there (2026-07-22 fix wave 2,
    // finding I1).

    if (kid.split('/')[0] !== issuerId || manifest['issuer'] !== issuerId) return invalid(ERR.ISSUER_MISMATCH)

    // Step 3 — key resolution + status + validity window
    const entry = findKey(manifest, kid)
    if (entry == null) return invalid(noKeyInManifest(kid))
    const status = entry['status']
    if (status === 'compromised') return invalid(keyCompromised(kid))
    // Fail closed on a missing/unknown status instead of validating like an active
    // key (2026-07-13 review, finding 4).
    if (status !== 'active' && status !== 'retired') return invalid(`key ${kid} has unusable status`)
    const issuedAt = payload['issued_at']
    if (typeof issuedAt !== 'string' || !withinValidity(issuedAt, entry)) return invalid(issuedAtOutsideWindow(issuedAt))
    if (status === 'retired') warnings.push(keyRetired(kid))

    // Step 4 — signature
    let pub: Uint8Array, sig: Uint8Array
    try { const p = entry['pub']; if (typeof p !== 'string') throw new Error('pub not a string'); pub = b64uDecode(p); sig = b64uDecode(sigB64) }
    catch (e) { return invalid(malformedKeyMaterial(e instanceof Error ? e.message : String(e))) }
    let signatureOk: boolean
    try { signatureOk = verifyStrict(canonicalBytes(payload), sig, pub) }
    catch (e) {
      if (e instanceof CanonError || e instanceof Ed25519LengthError) return invalid(malformedSigMaterial(e.message))
      throw e
    }
    if (!signatureOk) return invalid(ERR.SIG_VERIFICATION_FAILED)
  }

  // Step 5 — schema + content warnings
  const violations = validatePayload(payload)
  const schema: Schema = violations.length === 0 ? 'valid' : 'invalid'
  errors.push(...violations)
  warnings.push(...contentWarnings(payload))

  // Steps 6-7 — revocation + binding (only when schema valid)
  let revocation = 'unknown'
  let binding: Binding = 'not_checked'
  let grantVerdict: GrantVerdict = { grant: GRANT_NOT_CHECKED, grant_trust: GRANT_TRUST_NOT_CHECKED, warnings: [] }
  if (schema === 'valid') {
    revocation = classifyRevocation(
      payload, revocationView, manifest, warnings, errors, maxRevocationRecords,
      logKeys, anchorPolicy, revocationEvidence, transferView,
    )
    binding = disclosure != null ? classifyBinding(payload, disclosure) : 'not_checked'
    // Stage 4 (§18.4). Gated on a valid schema for the same reason revocation
    // and binding are: §18.6's holder-binding conditional makes a
    // pledge-bearing v0.2 receipt without `buyer.pubkey`, `work.publisher_id`
    // or the `sunset-grant` label a SCHEMA ERROR, and evaluating a grant
    // against a payload that failed that conditional would be reasoning about
    // a receipt the verifier has already rejected.
    grantVerdict = evaluateGrant(payload, trustStore, grantView, anchorPolicy)
  }

  warnings.push(...grantVerdict.warnings)

  return {
    signature: 'valid', schema, revocation, binding, trust,
    transparency: transparencyState, corroboration: corroborationState, manifest_freshness: manifestFreshnessState,
    warnings: [...warnings], errors: [...errors],
    grant: grantVerdict.grant, grant_trust: grantVerdict.grant_trust,
  }
}
