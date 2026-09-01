import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import {
  JsonObject, JsonValue, canonicalBytes, dumps, CanonError, loadsStrict, materializeArray,
} from './canon.js'
import {
  TrustStore, findKey, withinValidity, chainContinuous, MAX_MANIFEST_KEYS, hasActiveEdOnlySibling,
  duplicateKids,
  artifactChainContinuous, verifyArtifactManifest, signableManifestBytes, verifySignatureBlock,
  manifestSignatureIsAuthentic,
} from './manifests.js'
import { verifyStrict, Ed25519LengthError } from './ed25519.js'
import { verifyStrict as verifyMldsaStrict, ML_DSA_65_ALG } from './mldsa.js'
import { b64uDecode } from './b64u.js'
import { validatePayload, SCHEMA_TOP_LEVEL_KEYS, validateEnvelopeSize } from './schema.js'
import { classifyRevocation, MAX_REVOCATION_RECORDS } from './revocation.js'
import { evaluateGrant, GRANT_NOT_CHECKED, GRANT_TRUST_NOT_CHECKED } from './grant.js'
import type { GrantVerdict } from './grant.js'
import { evaluateAuthority, AUTHORITY_NOT_CHECKED, AUTHORITY_UNATTESTED } from './authority.js'
import type { AuthorityVerdict } from './authority.js'
import { computeCommitment, verifyChallenge } from './commitment.js'
import { b64uEncode } from './b64u.js'
import { TlogError, LogKey, receiptCoreHash, encodeEntry } from './tlog.js'
import { AnchorPolicy, validatePolicy as validateAnchorPolicyOnly } from './anchor.js'
import { parseIsoLenient, parseStrictUtc } from './dates.js'
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
  VERIFY_TRANSPARENCY_WARN, COMPROMISE_WARN, manifestExceedsKeys, manifestDuplicateKids,
  manifestNotSelfConsistent,
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
const ANCHORED_BEFORE_PREFIX = 'anchored_before:'
const MAX_COMPROMISE_CLAIMS = 64
const MAX_JCS_INTEGER = 2n ** 53n

// This outer cap must COVER everything the downstream evaluators' own inner
// caps accept, or evaluator-valid evidence gets falsely rejected here.
// Worst-case legitimate bundle, derived from those inner caps: checkpoint +
// prior_checkpoint + the anchors bundle's own checkpoint copy at ~500KB each
// = ~1.5MB, plus anchors operands at 64 proofs x 65_536 total hex chars per
// proof (MAX_PROOFS_PER_EVIDENCE, MAX_TOTAL_OP_HEX_LEN) = ~4.2MB, plus JSON
// overhead for proofs carrying up to 256 ops (~300KB), plus
// inclusion/consistency proofs (~8KB) — ~6MB total, ~4MB inside this ceiling.
//
// The operand term is bounded by the per-chain TOTAL, never by
// MAX_OPS_PER_PROOF * MAX_OP_HEX_LEN: that product is 268_435_456 chars and
// would overshoot this ceiling by ~260MB. This ceiling is normative (v0.1
// §11.3) and cannot be raised to meet the inner caps, so the total-operand
// cap is what makes the raised per-op caps admissible at all — re-derive this
// whenever any of the three moves. Mirrors verify.py's
// `_MAX_TRANSPARENCY_EVIDENCE_LEN`.
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
  // v0.2 §20. `publisher_authority`: "not_checked" | "no_publisher_claim" |
  // "self" | "authorized" | "unauthorized" | "unattested".
  // `publisher_authority_trust`: the §18.5 ladder read for the PUBLISHER's
  // domain, plus "signer_mismatch" when the rail carried a document someone
  // else signed for this publisher.
  publisher_authority: string; publisher_authority_trust: string
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
  // v0.2 §20's caller-supplied channel: an object with `authorizations` and
  // `current_authorization_version`. Informational like the grant rail: it
  // never touches `ok`.
  authorityView?: unknown
  // v0.1 rev 8 / v0.2 §19's evidence channel: untrusted key-manifest
  // compromise declarations. Authenticated declarations only ever strengthen
  // one status, `compromised`; the anchored-cutoff rescue is evaluated later
  // against the receipt's own transparency claim.
  compromiseView?: JsonValue[] | null
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
  // V-L.8's `publisher_claim_unattested` used to be pushed HERE. It is now
  // decided in verify(), after the §20 rail has spoken: the warning says the
  // claim is unattested, and once an authorization attests it the warning
  // would be saying something false. It is emitted only for `not_checked` and
  // `unattested` — the two verdicts that leave the claim exactly as unattested
  // as it was before §20 existed. Python parity: verify.py's gate on
  // `_WARN_PUBLISHER_CLAIM_UNATTESTED`.
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
  claimType: string | null
}

const ZERO_TRANSPARENCY_CLAIM: TransparencyClaimOutcome = {
  transparency: TRANSPARENCY_NOT_CHECKED,
  corroboration: CORROBORATION_NONE,
  manifestFreshness: MANIFEST_FRESHNESS_NOT_CHECKED,
  claimType: null,
}

/** Resolve transparency result components and the evidence claim type from one
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
      return {
        transparency: TRANSPARENCY_NOT_CHECKED,
        corroboration: CORROBORATION_NONE,
        manifestFreshness: MANIFEST_FRESHNESS_NOT_CHECKED,
        claimType,
      }
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

    return {
      transparency: transparencyState,
      corroboration: corroborationState,
      manifestFreshness: manifestFreshnessState,
      claimType,
    }
  } catch {
    // Deliberately encloses every untrusted claim phase above, including
    // post-evaluation freshness/rotation logic. Confines hostile mapping
    // access and equality implementations.
    warnings.push(VERIFY_TRANSPARENCY_WARN.CLAIM_UNRESOLVABLE)
    return ZERO_TRANSPARENCY_CLAIM
  }
}

// A claim that survived the §18.4 admission boundary, in the ONE reconstruction
// every consumer reads. `manifest` is the canonical form the boundary produced
// (integers are `bigint`, the profile's only numeric type) and is what gets
// hashed and signature-checked. `manifestVersion` is that same integer narrowed
// to a JS `number` at the boundary, because the log-entry encoder speaks the
// materialized dialect (`tlog.encodeEntry` refuses anything but `number`) — one
// conversion, done once, rather than a `typeof` test at each consumer that
// would silently never match. `evidence` stays canonical here and is
// materialized where it is consumed, the way `fixedDateReached` and
// `recordLoggedStanding` already do it on their own rails.
interface CompromiseClaim {
  manifest: JsonObject
  manifestVersion: number
  evidence: JsonValue | null
  signerKid: string
  vouchingSigners: JsonObject[]
}

function appendWarningOnce(warnings: string[], warning: string): void {
  if (!warnings.includes(warning)) warnings.push(warning)
}

function normalizeCompromiseValue(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'bigint') {
    if (!(value > -MAX_JCS_INTEGER && value < MAX_JCS_INTEGER)) throw new Error('integer out of JCS range')
    return Number(value)
  }
  if (typeof value === 'number') return value
  if (Array.isArray(value)) return value.map((item) => normalizeCompromiseValue(item))
  if (isPlainRecord(value)) {
    const out: Record<string, unknown> = Object.create(null)
    for (const key of Object.keys(value)) out[key] = normalizeCompromiseValue(value[key])
    return out
  }
  throw new Error('value is not JSON materializable')
}

function materializeCompromiseView(compromiseView: JsonValue[] | null): (JsonValue | null)[] | null {
  if (compromiseView === null) return null
  // This rail accepts a safe-integer `number` as the integer it denotes. It is
  // the one rail whose view a caller routinely writes BY HAND (§19.2's channel
  // is assembled from a manifest the caller already holds), JSON has no bigint
  // literal, and the previous pipeline normalized both representations to one.
  // Refusing the hand-written form here would make the SAME evidence decide
  // differently for having been typed out rather than parsed — and it would
  // decide differently from the Python core, where an integer is an integer and
  // the question does not arise. Its siblings keep the default: what reaches
  // them off the wire is strict-parsed, so a `number` there is a caller's
  // parsing mistake and the unit is set aside.
  const admitted = materializeArray(compromiseView, MAX_COMPROMISE_CLAIMS, {
    acceptSafeIntegerNumbers: true,
  })
  if (admitted === null || admitted.length > MAX_COMPROMISE_CLAIMS) return null
  return admitted
}

// Distinguishes "this value has no materialized form" from a legitimate `null`
// value, which is a perfectly good piece of evidence to hand onward.
const UNMATERIALIZABLE = Symbol('evidence has no materialized form')

/**
 * Re-express an ADMITTED value in the materialized dialect.
 *
 * The admission boundary produces the canonical profile (integers as `bigint`);
 * the transparency and anchor evaluators were written against `JSON.parse`
 * output and test `typeof x === 'number'` throughout. Handing them the
 * canonical form would make every one of those guards fail — silently, and in
 * the permissive direction, since a rescue that never fires cannot be seen.
 *
 * The input here is the reconstruction, never the caller's object, so this
 * cannot reintroduce the verify/consume split: both dialects come from the same
 * admitted value.
 */
function materializedForTransparency(value: JsonValue | null): unknown | typeof UNMATERIALIZABLE {
  if (value === null) return null
  try {
    return JSON.parse(dumps(value))
  } catch {
    return UNMATERIALIZABLE
  }
}

function entriesForKid(manifest: JsonObject, kid: string): JsonObject[] {
  const keys = manifest['keys']
  if (!Array.isArray(keys)) return []
  const entries: JsonObject[] = []
  for (const rawEntry of keys) {
    const entry = obj(rawEntry)
    if (entry !== null && entry['kid'] === kid) entries.push(entry)
  }
  return entries
}

function manifestMarksKidCompromised(manifest: JsonObject, kid: string): boolean {
  return entriesForKid(manifest, kid).some((entry) => entry['status'] === 'compromised')
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) return false
  return true
}

function b64uBytesEqual(left: unknown, right: unknown): boolean {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  try {
    return equalBytes(b64uDecode(left), b64uDecode(right))
  } catch {
    return false
  }
}

function compromiseKeyMaterialMatches(claimEntry: JsonObject, trustedEntry: JsonObject): boolean {
  if (!b64uBytesEqual(claimEntry['pub'], trustedEntry['pub'])) return false
  if (!('pub_ml_dsa_65' in trustedEntry)) return true
  return b64uBytesEqual(claimEntry['pub_ml_dsa_65'], trustedEntry['pub_ml_dsa_65'])
}

function heldIssuerManifests(trustedManifest: JsonObject, chain: JsonObject[] | undefined, issuerId: string): JsonObject[] {
  const held = [trustedManifest, ...(chain ?? [])]
  return held.filter((manifest) => manifest['issuer'] === issuerId)
}

function vouchingSigners(claimManifest: JsonObject, heldManifests: JsonObject[]): [string | null, JsonObject[]] {
  const sigBlock = obj(claimManifest['manifest_signature'])
  if (sigBlock === null || typeof sigBlock['kid'] !== 'string') return [null, []]
  const signerKid = sigBlock['kid']
  let signable: Uint8Array
  try {
    signable = signableManifestBytes(claimManifest)
  } catch {
    return [signerKid, []]
  }

  const issuedAt = claimManifest['issued_at']
  if (typeof issuedAt !== 'string') return [signerKid, []]
  const signers: JsonObject[] = []
  for (const heldManifest of heldManifests) {
    for (const signerEntry of entriesForKid(heldManifest, signerKid)) {
      if (!withinValidity(issuedAt, signerEntry)) continue
      if (verifySignatureBlock(signable, sigBlock, signerEntry)) signers.push(signerEntry)
    }
  }
  return [signerKid, signers]
}

function authenticatedCompromiseClaims(
  compromiseClaims: (JsonValue | null)[] | null,
  trustedManifest: JsonObject,
  trustedEntry: JsonObject,
  chain: JsonObject[] | undefined,
  issuerId: string,
  kid: string,
  warnings: string[],
): CompromiseClaim[] {
  if (compromiseClaims === null || compromiseClaims.length === 0) return []

  const heldManifests = heldIssuerManifests(trustedManifest, chain, issuerId)
  const trustedForKid = entriesForKid(trustedManifest, kid)
  const trustedEntriesForKid = trustedForKid.length > 0 ? trustedForKid : [trustedEntry]
  const authenticated: CompromiseClaim[] = []
  for (const element of compromiseClaims) {
    // A claim the boundary set aside arrives as `null` and is one ignored
    // claim, never a reason to drop the view: its siblings still get their
    // verdict. This is where §18.4's per-unit granularity becomes observable.
    const claim = obj(element ?? undefined)
    if (claim === null) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    const claimManifest = obj(claim['manifest'])
    if (claimManifest === null || claimManifest['issuer'] !== issuerId) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    // The admission boundary yields `bigint` for every integer, so a
    // `typeof === 'number'` test here would silently never match and would
    // discard every claim, genuine ones included — the same trap the comment
    // above markingProvenanceIsARetraction records. The version is read in the
    // profile's representation and narrowed ONCE, for the one consumer that
    // needs the materialized dialect.
    const manifestVersionBig = manifestVersionAsBigInt(claimManifest['manifest_version'])
    if (manifestVersionBig === null) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    // Narrowing is exact by construction, so there is no range guard here and
    // adding one would be unreachable code pretending to be a defence: the
    // admission boundary canonicalizes every unit, and the serializer refuses
    // any integer outside (-2**53, 2**53), so what survives it always fits a
    // JS number without rounding. The claim carrying an out-of-range version
    // is set aside by the boundary itself, alone.
    const manifestVersion = Number(manifestVersionBig)
    const declaresCompromise = entriesForKid(claimManifest, kid).some(
      // v0.1 §7.3 (rev 8): the claimed compromised entry may match ANY trusted
      // entry for the kid, not only the one findKey happened to return first.
      // With duplicates a first-match comparison lets the array's ORDER decide
      // whether a genuine declaration authenticates. Python parity: verify.py.
      (entry) => entry['status'] === 'compromised'
        && trustedEntriesForKid.some((candidate) => compromiseKeyMaterialMatches(entry, candidate)),
    )
    if (!declaresCompromise) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    const [signerKid, signers] = vouchingSigners(claimManifest, heldManifests)
    if (signerKid === null || signers.length === 0) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    authenticated.push({
      manifest: claimManifest,
      manifestVersion,
      evidence: (claim['evidence'] ?? null) as JsonValue | null,
      signerKid,
      vouchingSigners: signers,
    })
  }
  return authenticated
}

function manifestVersionAsBigInt(value: unknown): bigint | null {
  if (typeof value === 'bigint') return value
  if (typeof value === 'number' && Number.isInteger(value)) return BigInt(value)
  return null
}

function heldManifestMarksSignerCompromisedAtOrBefore(
  heldManifests: JsonObject[],
  signerKid: string,
  declarationVersion: number,
): boolean {
  const declarationVersionBigint = BigInt(declarationVersion)
  for (const heldManifest of heldManifests) {
    const version = manifestVersionAsBigInt(heldManifest['manifest_version'])
    if (version === null || version > declarationVersionBigint) continue
    if (manifestMarksKidCompromised(heldManifest, signerKid)) return true
  }
  return false
}

function claimHasCutoffSigner(claim: CompromiseClaim, heldManifests: JsonObject[]): boolean {
  for (const signerEntry of claim.vouchingSigners) {
    if (signerEntry['status'] !== 'active' && signerEntry['status'] !== 'retired') continue
    if (heldManifestMarksSignerCompromisedAtOrBefore(heldManifests, claim.signerKid, claim.manifestVersion)) continue
    return true
  }
  return false
}

function resolveCompromiseCutoff(
  authenticatedClaims: CompromiseClaim[],
  trustedManifest: JsonObject,
  chain: JsonObject[] | undefined,
  issuerId: string,
  logKeys: LogKey[],
  anchorPolicy: AnchorPolicy,
  warnings: string[],
): number | null {
  if (authenticatedClaims.length === 0) return null

  const origin = resolveLogOrigin(logKeys)
  validateAnchorPolicyOnly(anchorPolicy)
  const heldManifests = heldIssuerManifests(trustedManifest, chain, issuerId)
  let best: number | null = null
  for (const claim of authenticatedClaims) {
    if (!claimHasCutoffSigner(claim, heldManifests)) continue
    let manifestSha256: string
    try {
      manifestSha256 = bytesToHex(sha256(canonicalBytes(claim.manifest)))
    } catch {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    const expectedEntry = validatedTransparencyEntry({
      type: CLAIM_TYPE_KEY_MANIFEST,
      issuer: claim.manifest['issuer'],
      manifest_version: claim.manifestVersion,
      manifest_sha256: manifestSha256,
    })
    if (expectedEntry === null) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    // The evidence crossed the admission boundary, so its integers are
    // `bigint`; the transparency evaluator speaks the materialized dialect and
    // its `typeof x !== 'number'` guards would refuse every field in silence,
    // switching off the §19 rescue without an error anywhere. Re-materialize
    // the ADMITTED value — never the caller's object a second time — exactly
    // as fixedDateReached and recordLoggedStanding do on their rails.
    const materializedEvidence = materializedForTransparency(claim.evidence)
    if (materializedEvidence === UNMATERIALIZABLE) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED)
      continue
    }
    const result = evaluateTransparency(materializedEvidence, {
      logKeys,
      expectedOrigin: origin,
      policy: anchorPolicy,
      expectedEntry,
    })
    for (const warning of result.warnings) appendWarningOnce(warnings, warning)
    if (!result.transparency.startsWith(ANCHORED_BEFORE_PREFIX)) continue
    const cutoffTimestamp = result.transparency.slice(ANCHORED_BEFORE_PREFIX.length)
    const cutoff = parseStrictUtc(cutoffTimestamp) ?? (
      typeof cutoffTimestamp === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(cutoffTimestamp)
        ? parseIsoLenient(cutoffTimestamp)
        : null
    )
    if (cutoff === null) continue
    if (best === null || cutoff < best) best = cutoff
  }
  return best
}

/**
 * v0.1 §7.3 (rev 8): did the issuer take its own marking back?
 *
 * True only when the trusted manifest carries an integer version, does NOT mark
 * the kid compromised on ANY of its entries, and some held source that does mark
 * it carries an integer version strictly lower. Provenance, never a verdict: the
 * floor has already decided by the time this runs.
 *
 * Every entry for the kid is consulted in every manifest (via
 * manifestMarksKidCompromised): reading the first matching entry would let the
 * array's ORDER decide whether the issuer rewrote its history. Versions go
 * through manifestVersionAsBigInt because loadsStrict yields bigint, so a
 * `typeof === 'number'` test would silently never match.
 */
function markingProvenanceIsARetraction(
  trustedManifest: JsonObject,
  chain: JsonObject[] | undefined,
  authenticatedClaims: CompromiseClaim[],
  kid: string,
): boolean {
  const trustedVersion = manifestVersionAsBigInt(trustedManifest['manifest_version'])
  if (trustedVersion === null) return false
  if (manifestMarksKidCompromised(trustedManifest, kid)) return false
  const sources: JsonObject[] = [
    ...(chain ?? []),
    ...authenticatedClaims.map((claim) => claim.manifest),
  ]
  for (const source of sources) {
    if (!manifestMarksKidCompromised(source, kid)) continue
    const sourceVersion = manifestVersionAsBigInt(source['manifest_version'])
    if (sourceVersion !== null && sourceVersion < trustedVersion) return true
  }
  return false
}

function resolveKeyStatus(
  trustedEntry: JsonObject,
  trustedManifest: JsonObject,
  chain: JsonObject[] | undefined,
  authenticatedClaims: CompromiseClaim[],
  kid: string,
): unknown {
  if (manifestMarksKidCompromised(trustedManifest, kid)) return 'compromised'
  for (const manifest of chain ?? []) {
    if (manifestMarksKidCompromised(manifest, kid)) return 'compromised'
  }
  if (authenticatedClaims.length > 0) return 'compromised'
  return trustedEntry['status']
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
  const authorityView = options.authorityView ?? null
  const compromiseView = options.compromiseView ?? null

  if (revocationView !== null && !Array.isArray(revocationView))
    throw new TypeError('revocation_view must be a list of records or None')
  // Same caller-contract enforcement, extended to the Stage 3 channel: a
  // lone claim OBJECT must fail loud rather than be silently iterated as
  // dict keys by classifyRevocation's transferred-branch resolver.
  if (transferView !== null && !Array.isArray(transferView))
    throw new TypeError('transfer_view must be a list of claims or None')
  if (compromiseView !== null && !Array.isArray(compromiseView))
    throw new TypeError('compromise_view must be a list of claims or None')
  // Same caller-contract enforcement for Stage 4's channel: a lone grant
  // DOCUMENT passed where the evidence object belongs would otherwise be read
  // member by member and resolve to `not_checked`, silently reporting "no
  // grant evidence" to a caller who supplied some. Hostile CONTENT inside a
  // well-shaped view never throws — only the wrong container does. Raised here
  // as well as inside evaluateGrant so it fires before any parsing work, the
  // same position its two siblings above occupy.
  if (authorityView !== null && (typeof authorityView !== 'object' || Array.isArray(authorityView)))
    throw new TypeError('authority_view must be an evidence object or None')
  if (grantView !== null && (typeof grantView !== 'object' || Array.isArray(grantView)))
    throw new TypeError('grant_view must be an evidence object or None')

  // Fail loud if the TRUST STORE was JSON.parse'd (JS numbers) rather than
  // loadsStrict-parsed (bigint). The trust store is the verifier's own
  // configuration, so a wrong parse there is a programming error and the loud
  // failure is the right one. Does NOT walk envelopeBytes (parsed internally)
  // or disclosure (holds raw Uint8Array fields).
  assertCanonParsed(trustStore.manifests, 'trustStore.manifests')
  if (trustStore.chains != null) assertCanonParsed(trustStore.chains, 'trustStore.chains')
  // The revocation view is NOT checked here any more, and its absence is the
  // point. This guard existed to stop a JSON.parse'd view from failing open in
  // silence, and it did it by THROWING out of a public surface for a property
  // of ONE record -- so one JS number in one record took the whole call down,
  // genuine sibling revocations included, which is the shape §18.4 forbids. The
  // admission boundary in classifyRevocation now serves the same purpose better
  // and per record: a unit carrying a JS number is not representable in the
  // profile, so it is set aside ALONE and, if it claims to be about this
  // receipt, it still surfaces as the §12.2 ignored-record warning. The caller
  // is told, the genuine records survive, and nothing escapes. This also
  // removes the O(N) pre-walk of attacker data the guard had to skip above the
  // record ceiling to stay affordable.

  const errors: string[] = []
  const warnings: string[] = []
  let trust: Trust = 'unauthenticated_tofu'
  // Stage 2 defaults — the ZERO-behavior-change values (updated below, once,
  // right after trust is resolved; see `evaluateTransparencyClaim`'s doc
  // comment for why this runs before any pass/fail branching).
  let transparencyState: string = TRANSPARENCY_NOT_CHECKED
  let corroborationState: string = CORROBORATION_NONE
  let manifestFreshnessState: string = MANIFEST_FRESHNESS_NOT_CHECKED
  let transparencyClaimType: string | null = null
  const materializedCompromiseView = materializeCompromiseView(compromiseView)
  const invalid = (message: string, schema: Schema = 'not_checked'): VerificationResult => {
    errors.push(message)
    return {
      signature: 'invalid', schema, revocation: 'unknown', binding: 'not_checked', trust,
      transparency: transparencyState, corroboration: corroborationState, manifest_freshness: manifestFreshnessState,
      warnings: [...warnings], errors: [...errors],
      grant: GRANT_NOT_CHECKED, grant_trust: GRANT_TRUST_NOT_CHECKED,
      publisher_authority: AUTHORITY_NOT_CHECKED, publisher_authority_trust: AUTHORITY_NOT_CHECKED,
    }
  }

  const compromisedKeyDisposition = (
    kid: string,
    entry: JsonObject,
    trustedManifest: JsonObject,
    chain: JsonObject[] | undefined,
    authenticatedClaims: CompromiseClaim[],
  ): VerificationResult | null => {
    if (logKeys === null || anchorPolicy === null) return invalid(keyCompromised(kid))
    if (transparencyClaimType !== CLAIM_TYPE_RECEIPT || !transparencyState.startsWith(ANCHORED_BEFORE_PREFIX)) {
      if (compromiseView !== null || authenticatedClaims.length > 0) {
        appendWarningOnce(warnings, COMPROMISE_WARN.RESCUE_REQUIRES_ANCHORED_RECEIPT)
      }
      return invalid(keyCompromised(kid))
    }
    const receiptAnchorTimestamp = transparencyState.slice(ANCHORED_BEFORE_PREFIX.length)
    const receiptAnchor = parseStrictUtc(receiptAnchorTimestamp) ?? (
      typeof receiptAnchorTimestamp === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(receiptAnchorTimestamp)
        ? parseIsoLenient(receiptAnchorTimestamp)
        : null
    )
    if (receiptAnchor === null) {
      if (compromiseView !== null || authenticatedClaims.length > 0) {
        appendWarningOnce(warnings, COMPROMISE_WARN.RESCUE_REQUIRES_ANCHORED_RECEIPT)
      }
      return invalid(keyCompromised(kid))
    }

    const cutoff = resolveCompromiseCutoff(
      authenticatedClaims,
      trustedManifest,
      chain,
      typeof issuerId === 'string' ? issuerId : '',
      logKeys,
      anchorPolicy,
      warnings,
    )
    if (cutoff === null) {
      appendWarningOnce(warnings, COMPROMISE_WARN.CUTOFF_UNANCHORED)
      return null
    }
    if (receiptAnchor < cutoff) {
      appendWarningOnce(warnings, COMPROMISE_WARN.RESCUE_APPLIED)
      return null
    }
    appendWarningOnce(warnings, COMPROMISE_WARN.RESCUE_RECEIPT_AFTER_CUTOFF)
    return invalid(keyCompromised(kid))
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
      // V-L.3 (v0.1 §7.1, 2026-08-26 amendment) — an ambiguous trusted manifest
      // is refused whole, before any key is resolved. Without this, a duplicate
      // on a kid the signature does NOT use left the receipt certifiable: step 3
      // resolves the signing key with findKey directly and never passes through
      // verifyKeyManifest.
      const dupKids = duplicateKids(preflightKeys)
      if (dupKids.length > 0) {
        return invalid(manifestDuplicateKids(dupKids), 'invalid')
      }
      if (payload['attest_version'] === '0.2' && hasActiveEdOnlySibling(issuerManifestForTransparency)) {
        warnings.push(WARN.MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING)
      }

      // The trusted manifest must authenticate ITSELF before any key is read
      // out of it. The side-document paths have always asked; the receipt path
      // never did, so a manifest edited after it was trusted certified receipts
      // signed by the edit. Hoisted here, at the ONE place the manifest is
      // resolved, so both receipt paths inherit it, and last in this preflight
      // so the refusals above keep their verdicts and their messages. Python
      // parity: verify.py's same block.
      if (!manifestSignatureIsAuthentic(issuerManifestForTransparency)) {
        return invalid(manifestNotSelfConsistent(issuerId))
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
    transparencyClaimType = claimOutcome.claimType
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
    const chain = trustStore.chains?.[issuerId]
    const authenticatedClaims = authenticatedCompromiseClaims(
      materializedCompromiseView, manifest, entry, chain, issuerId, kid, warnings,
    )
    const status = resolveKeyStatus(entry, manifest, chain, authenticatedClaims, kid)
    let compromisedRescued = false
    if (status === 'compromised') {
      // At the point of RESOLUTION and before the §19 disposition, so it reads
      // identically in the kill branch and the rescue branch and its position
      // in the array is deterministic.
      if (markingProvenanceIsARetraction(manifest, chain, authenticatedClaims, kid)) {
        appendWarningOnce(warnings, COMPROMISE_WARN.MARKING_RETRACTED)
      }
      const disposition = compromisedKeyDisposition(kid, entry, manifest, chain, authenticatedClaims)
      if (disposition !== null) return disposition
      compromisedRescued = true
    }
    if (!compromisedRescued && status !== 'active' && status !== 'retired') return invalid(`key ${kid} has unusable status`)
    const issuedAt = payload['issued_at']
    if (typeof issuedAt !== 'string' || !withinValidity(issuedAt, entry)) return invalid(issuedAtOutsideWindow(issuedAt))
    if (!compromisedRescued && status === 'retired') warnings.push(keyRetired(kid))

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
    const chain = trustStore.chains?.[issuerId]
    const authenticatedClaims = authenticatedCompromiseClaims(
      materializedCompromiseView, manifest, entry, chain, issuerId, kid, warnings,
    )
    const status = resolveKeyStatus(entry, manifest, chain, authenticatedClaims, kid)
    let compromisedRescued = false
    if (status === 'compromised') {
      // At the point of RESOLUTION and before the §19 disposition, so it reads
      // identically in the kill branch and the rescue branch and its position
      // in the array is deterministic.
      if (markingProvenanceIsARetraction(manifest, chain, authenticatedClaims, kid)) {
        appendWarningOnce(warnings, COMPROMISE_WARN.MARKING_RETRACTED)
      }
      const disposition = compromisedKeyDisposition(kid, entry, manifest, chain, authenticatedClaims)
      if (disposition !== null) return disposition
      compromisedRescued = true
    }
    // Fail closed on a missing/unknown status instead of validating like an active
    // key (2026-07-13 review, finding 4).
    if (!compromisedRescued && status !== 'active' && status !== 'retired') return invalid(`key ${kid} has unusable status`)
    const issuedAt = payload['issued_at']
    if (typeof issuedAt !== 'string' || !withinValidity(issuedAt, entry)) return invalid(issuedAtOutsideWindow(issuedAt))
    if (!compromisedRescued && status === 'retired') warnings.push(keyRetired(kid))

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
  let authorityVerdict: AuthorityVerdict = {
    publisher_authority: AUTHORITY_NOT_CHECKED,
    publisher_authority_trust: AUTHORITY_NOT_CHECKED,
    warnings: [],
  }
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
    authorityVerdict = evaluateAuthority(payload, trustStore, authorityView)
  }

  // The order here is load-bearing and mirrors the Python core exactly: the
  // rail's own warnings, then the V-L.8 claim warning it gates, then the grant
  // rail's.
  warnings.push(...authorityVerdict.warnings)
  const authorityWork = obj(payload['work'])
  const claimedPublisherId = authorityWork ? authorityWork['publisher_id'] : undefined
  const claimIssuerBlock = obj(payload['issuer'])
  const claimIssuerId = claimIssuerBlock ? claimIssuerBlock['id'] : undefined
  if (
    typeof claimedPublisherId === 'string'
    && typeof claimIssuerId === 'string'
    && claimedPublisherId !== claimIssuerId
    && (authorityVerdict.publisher_authority === AUTHORITY_NOT_CHECKED
      || authorityVerdict.publisher_authority === AUTHORITY_UNATTESTED)
  ) {
    warnings.push(WARN.PUBLISHER_CLAIM_UNATTESTED)
  }
  warnings.push(...grantVerdict.warnings)

  return {
    signature: 'valid', schema, revocation, binding, trust,
    transparency: transparencyState, corroboration: corroborationState, manifest_freshness: manifestFreshnessState,
    warnings: [...warnings], errors: [...errors],
    grant: grantVerdict.grant, grant_trust: grantVerdict.grant_trust,
    publisher_authority: authorityVerdict.publisher_authority,
    publisher_authority_trust: authorityVerdict.publisher_authority_trust,
  }
}
