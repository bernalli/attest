// Hand-rolled structural validator for the attest v0.1 receipt payload schema
// (docs/spec/schema/attest-receipt.schema.json). No JSON-Schema dependency: this
// ports only the required/type/enum/pattern/conditional rules that schema
// actually pins. `format: "uri"` is annotation-only in draft 2020-12 and is
// deliberately NOT enforced here (Task 5 adjudication) -- we just require
// those fields be strings where the schema requires a string.
import type { JsonObject, JsonValue } from './canon.js'
import { MAX_DEPTH } from './canon.js'
import { envelopeExceedsBytes } from './messages.js'

export const SCHEMA_TOP_LEVEL_KEYS: ReadonlySet<string> = new Set([
  'attest_version',
  'receipt_id',
  'issued_at',
  'supersedes',
  'issuer',
  'buyer',
  'work',
  'license',
  'survivability',
])

const RECEIPT_ID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/
const ISSUED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const ISSUER_ID_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/
const COMMITMENT_RE = /^[A-Za-z0-9_-]{43}$/
const SHA256_RE = /^[0-9a-f]{64}$/

const GRANT_VALUES = new Set(['perpetual', 'subscription'])
const REVOCABILITY_VALUES = new Set(['none', 'refund_window', 'policy'])
const DRM_VALUES = new Set(['drm-free', 'drm-bound'])
const IDENTIFIER_TYPE_VALUES = new Set(['issuer-account', 'email'])

function isObject(v: JsonValue | undefined): v is JsonObject {
  return v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v)
}

function isNonEmptyString(v: JsonValue | undefined): v is string {
  return typeof v === 'string' && v.length >= 1
}

// Pushes `msg` when `cond` is false; returns `cond` so callers can short-circuit
// dependent checks (e.g. don't pattern-match a field that isn't even a string).
function check(errors: string[], cond: boolean, msg: string): boolean {
  if (!cond) errors.push(msg)
  return cond
}

function validateIssuer(v: JsonValue | undefined, errors: string[]): void {
  if (!check(errors, isObject(v), 'issuer: must be an object')) return
  const issuer = v as JsonObject
  if (check(errors, 'id' in issuer, 'issuer.id: required')) {
    check(errors, typeof issuer['id'] === 'string' && ISSUER_ID_RE.test(issuer['id']), 'issuer.id: must be a dotted hostname-like string')
  }
  if (check(errors, 'display_name' in issuer, 'issuer.display_name: required')) {
    check(errors, isNonEmptyString(issuer['display_name']), 'issuer.display_name: must be a non-empty string')
  }
}

function validateBuyer(v: JsonValue | undefined, errors: string[]): void {
  if (!check(errors, isObject(v), 'buyer: must be an object')) return
  const buyer = v as JsonObject
  if (check(errors, 'commitment' in buyer, 'buyer.commitment: required')) {
    check(errors, typeof buyer['commitment'] === 'string' && COMMITMENT_RE.test(buyer['commitment']), 'buyer.commitment: must be a 43-char base64url string')
  }
  if (check(errors, 'identifier_type' in buyer, 'buyer.identifier_type: required')) {
    check(errors, typeof buyer['identifier_type'] === 'string' && IDENTIFIER_TYPE_VALUES.has(buyer['identifier_type']), 'buyer.identifier_type: must be one of issuer-account, email')
  }
  if ('pubkey' in buyer) {
    check(errors, buyer['pubkey'] === null || (typeof buyer['pubkey'] === 'string' && COMMITMENT_RE.test(buyer['pubkey'])), 'buyer.pubkey: must be null or a 43-char base64url string')
  }
}

function validateArtifact(v: JsonValue, index: number, errors: string[]): void {
  if (!check(errors, isObject(v), `work.artifacts[${index}]: must be an object`)) return
  const a = v as JsonObject
  for (const field of ['role', 'platform', 'filename']) {
    if (check(errors, field in a, `work.artifacts[${index}].${field}: required`)) {
      check(errors, isNonEmptyString(a[field]), `work.artifacts[${index}].${field}: must be a non-empty string`)
    }
  }
  if (check(errors, 'size_bytes' in a, `work.artifacts[${index}].size_bytes: required`)) {
    const sizeBytes = a['size_bytes']
    check(errors, typeof sizeBytes === 'bigint' && sizeBytes >= 0n && sizeBytes <= 9007199254740991n, `work.artifacts[${index}].size_bytes: must be an integer in [0, 9007199254740991]`)
  }
  if (check(errors, 'sha256' in a, `work.artifacts[${index}].sha256: required`)) {
    check(errors, typeof a['sha256'] === 'string' && SHA256_RE.test(a['sha256']), `work.artifacts[${index}].sha256: must be a 64-char lowercase hex string`)
  }
}

function validateWork(v: JsonValue | undefined, errors: string[]): void {
  if (!check(errors, isObject(v), 'work: must be an object')) return
  const work = v as JsonObject
  if (check(errors, 'title' in work, 'work.title: required')) {
    check(errors, isNonEmptyString(work['title']), 'work.title: must be a non-empty string')
  }
  if (check(errors, 'publisher' in work, 'work.publisher: required')) {
    check(errors, isNonEmptyString(work['publisher']), 'work.publisher: must be a non-empty string')
  }
  if (check(errors, 'identifiers' in work, 'work.identifiers: required')) {
    const identifiers = work['identifiers']
    if (check(errors, isObject(identifiers), 'work.identifiers: must be an object')) {
      const obj = identifiers as JsonObject
      check(errors, Object.keys(obj).length >= 1, 'work.identifiers: must have at least one member')
      for (const [k, val] of Object.entries(obj)) {
        check(errors, typeof val === 'string', `work.identifiers.${k}: must be a string`)
      }
    }
  }
  // v0.2 §18.1 (Stage 4): the rights holder's own domain, same lowercase-DNS
  // shape as issuer.id. OPTIONAL under v0.1 alone (it carries no meaning
  // there); REQUIRED, schema-conditionally, when license.preservation_pledge
  // is present — see validatePreservationPledgeConditional (§18.6).
  if ('publisher_id' in work) {
    check(errors, typeof work['publisher_id'] === 'string' && ISSUER_ID_RE.test(work['publisher_id']), 'work.publisher_id: must be a dotted hostname-like string')
  }
  if ('artifact_series' in work) {
    check(errors, isNonEmptyString(work['artifact_series']), 'work.artifact_series: must be a non-empty string')
  }
  if ('edition' in work) {
    check(errors, typeof work['edition'] === 'string', 'work.edition: must be a string')
  }
  if ('artifacts' in work) {
    const artifacts = work['artifacts']
    if (check(errors, Array.isArray(artifacts), 'work.artifacts: must be an array')) {
      ;(artifacts as JsonValue[]).forEach((a, i) => validateArtifact(a, i, errors))
    }
  }
}

function validateLicense(v: JsonValue | undefined, errors: string[]): void {
  if (!check(errors, isObject(v), 'license: must be an object')) return
  const license = v as JsonObject
  for (const field of ['grant', 'revocability', 'transferable', 'drm', 'terms_uri', 'legal_text_sha256']) {
    check(errors, field in license, `license.${field}: required`)
  }
  if ('grant' in license) {
    check(errors, typeof license['grant'] === 'string' && GRANT_VALUES.has(license['grant']), 'license.grant: must be one of perpetual, subscription')
  }
  if ('revocability' in license) {
    check(errors, typeof license['revocability'] === 'string' && REVOCABILITY_VALUES.has(license['revocability']), 'license.revocability: must be one of none, refund_window, policy')
  }
  if ('revocation_window_days' in license) {
    const days = license['revocation_window_days']
    check(errors, typeof days === 'bigint' && days >= 1n && days <= 3650n, 'license.revocation_window_days: must be an integer in [1, 3650]')
  }
  if ('transferable' in license) {
    check(errors, typeof license['transferable'] === 'boolean', 'license.transferable: must be a boolean')
  }
  if ('drm' in license) {
    check(errors, typeof license['drm'] === 'string' && DRM_VALUES.has(license['drm']), 'license.drm: must be one of drm-free, drm-bound')
  }
  if ('terms_uri' in license) {
    check(errors, typeof license['terms_uri'] === 'string', 'license.terms_uri: must be a string')
  }
  if ('legal_text_sha256' in license) {
    check(errors, typeof license['legal_text_sha256'] === 'string' && SHA256_RE.test(license['legal_text_sha256']), 'license.legal_text_sha256: must be a 64-char lowercase hex string')
  }
  if ('jurisdiction_flags' in license) {
    const flags = license['jurisdiction_flags']
    if (check(errors, isObject(flags), 'license.jurisdiction_flags: must be an object')) {
      for (const [k, val] of Object.entries(flags as JsonObject)) {
        check(errors, typeof val === 'boolean', `license.jurisdiction_flags.${k}: must be a boolean`)
      }
    }
  }
  // if revocability === "refund_window" then revocation_window_days is required
  if (license['revocability'] === 'refund_window') {
    check(errors, 'revocation_window_days' in license, 'license.revocation_window_days: required when license.revocability is refund_window')
  }
  // v0.2 §17.7 (Stage 3): not_transferable_before, when present, must be an
  // RFC3339 UTC date-time — same shape as issued_at (ISSUED_AT_RE).
  if ('not_transferable_before' in license) {
    check(
      errors,
      typeof license['not_transferable_before'] === 'string' && ISSUED_AT_RE.test(license['not_transferable_before']),
      'license.not_transferable_before: must be an RFC3339 UTC date-time (YYYY-MM-DDTHH:MM:SSZ)',
    )
  }
  // v0.2 §18.2 (Stage 4): the preservation-pledge term. Three REQUIRED
  // members, and deliberately NOT a closed object -- it lives inside the
  // payload, whose posture toward unrecognized members is tolerant (v0.1
  // §11.2), so a future pledge profile needing a fourth member must not be a
  // schema error on a verifier that predates it. That is also why `pledge` is
  // only "non-empty string" here and never an enum: an unrecognized profile
  // is valid-with-warning (`grant_pledge_type_unknown`), never a schema error.
  if ('preservation_pledge' in license) {
    const pledge = license['preservation_pledge']
    if (check(errors, isObject(pledge), 'license.preservation_pledge: must be an object')) {
      const term = pledge as JsonObject
      if (check(errors, 'pledge' in term, 'license.preservation_pledge.pledge: required')) {
        check(errors, isNonEmptyString(term['pledge']), 'license.preservation_pledge.pledge: must be a non-empty string')
      }
      if (check(errors, 'grant_uri' in term, 'license.preservation_pledge.grant_uri: required')) {
        check(errors, typeof term['grant_uri'] === 'string', 'license.preservation_pledge.grant_uri: must be a string')
      }
      if (check(errors, 'grant_sha256' in term, 'license.preservation_pledge.grant_sha256: required')) {
        check(errors, typeof term['grant_sha256'] === 'string' && SHA256_RE.test(term['grant_sha256']), 'license.preservation_pledge.grant_sha256: must be a 64-char lowercase hex string')
      }
    }
  }
}

function validateSurvivability(v: JsonValue | undefined, errors: string[]): void {
  if (!check(errors, isObject(v), 'survivability: must be an object')) return
  const survivability = v as JsonObject
  if (check(errors, 'redownload_right' in survivability, 'survivability.redownload_right: required')) {
    check(errors, typeof survivability['redownload_right'] === 'boolean', 'survivability.redownload_right: must be a boolean')
  }
  if (check(errors, 'end_of_life' in survivability, 'survivability.end_of_life: required')) {
    check(errors, isNonEmptyString(survivability['end_of_life']), 'survivability.end_of_life: must be a non-empty string')
  }
  if ('mirror_policy_uri' in survivability) {
    check(errors, typeof survivability['mirror_policy_uri'] === 'string', 'survivability.mirror_policy_uri: must be a string')
  }
  if ('mirror_policy_sha256' in survivability) {
    check(errors, typeof survivability['mirror_policy_sha256'] === 'string' && SHA256_RE.test(survivability['mirror_policy_sha256']), 'survivability.mirror_policy_sha256: must be a 64-char lowercase hex string')
  }
  if ('eol_commitment_uri' in survivability) {
    const uri = survivability['eol_commitment_uri']
    check(errors, uri === null || typeof uri === 'string', 'survivability.eol_commitment_uri: must be null or a string')
  }
  if ('eol_commitment_sha256' in survivability) {
    const sha = survivability['eol_commitment_sha256']
    check(errors, sha === null || (typeof sha === 'string' && SHA256_RE.test(sha)), 'survivability.eol_commitment_sha256: must be null or a 64-char lowercase hex string')
  }
}

// if license.revocability === "none" then license.drm === "drm-free" AND
// survivability.redownload_right === true AND work has artifact_series OR a
// non-empty artifacts array.
function validateRevocabilityNoneConditional(payload: JsonObject, errors: string[]): void {
  const license = payload['license']
  if (!isObject(license) || license['revocability'] !== 'none') return

  check(errors, license['drm'] === 'drm-free', 'license.drm: must be drm-free when license.revocability is none')

  const survivability = payload['survivability']
  check(errors, isObject(survivability) && survivability['redownload_right'] === true, 'survivability.redownload_right: must be true when license.revocability is none')

  const work = payload['work']
  const hasArtifactSeries = isObject(work) && isNonEmptyString(work['artifact_series'])
  const hasArtifacts = isObject(work) && Array.isArray(work['artifacts']) && (work['artifacts'] as JsonValue[]).length >= 1
  check(errors, hasArtifactSeries || hasArtifacts, 'work: must have artifact_series or a non-empty artifacts array when license.revocability is none')
}

// D1 (v0.2 §17 schema amendment): if attest_version === "0.2" AND
// license.transferable === true then buyer.pubkey must be a non-null 43-char
// base64url string — tighter than validateBuyer's general "null or..." check
// above. Mirrors the JSON-Schema allOf/if/then in
// docs/spec/schema/attest-receipt.schema.json (D1 conditional).
function validateTransferableConditional(payload: JsonObject, errors: string[]): void {
  const license = payload['license']
  if (payload['attest_version'] !== '0.2' || !isObject(license) || license['transferable'] !== true) return

  const buyer = payload['buyer']
  const pubkey = isObject(buyer) ? buyer['pubkey'] : undefined
  check(
    errors,
    typeof pubkey === 'string' && COMMITMENT_RE.test(pubkey),
    'buyer.pubkey: must be a non-null 43-char base64url string when license.transferable is true (attest_version 0.2)',
  )
}

// D5 (v0.2 §18.6 schema amendment): if attest_version === "0.2" AND
// license.preservation_pledge is PRESENT, then all three of buyer.pubkey
// (non-null), work.publisher_id and survivability.end_of_life ===
// "sunset-grant" are required; any of the three absent is a SCHEMA ERROR.
// Mirrors the third allOf/if/then in
// docs/spec/schema/attest-receipt.schema.json, including its `properties`
// semantics: each of the three sub-checks applies only when its own block is
// present (the block's own absence is already reported by the top-level
// required list), exactly as validateTransferableConditional above is only
// reached when `buyer` is present.
//
// The three are not decoration. A grant authorizes delivery to the HOLDER of
// a valid receipt: without a holder key, "holder" degenerates to whoever
// possesses the file and the grant becomes indistinguishable from publishing
// the work outright. work.publisher_id is what §18.1's whole identity check
// hangs on. And the end_of_life label is required so the coarse, evidence-free
// signal and the hash-bound term can never disagree on the same receipt.
function validatePreservationPledgeConditional(payload: JsonObject, errors: string[]): void {
  const license = payload['license']
  if (payload['attest_version'] !== '0.2' || !isObject(license) || !('preservation_pledge' in license)) return

  if ('buyer' in payload) {
    const buyer = payload['buyer']
    const pubkey = isObject(buyer) ? buyer['pubkey'] : undefined
    check(
      errors,
      typeof pubkey === 'string' && COMMITMENT_RE.test(pubkey),
      'buyer.pubkey: must be a non-null 43-char base64url string when license.preservation_pledge is present (attest_version 0.2)',
    )
  }
  if ('work' in payload) {
    const work = payload['work']
    check(
      errors,
      isObject(work) && 'publisher_id' in work,
      'work.publisher_id: required when license.preservation_pledge is present (attest_version 0.2)',
    )
  }
  if ('survivability' in payload) {
    const survivability = payload['survivability']
    check(
      errors,
      isObject(survivability) && survivability['end_of_life'] === 'sunset-grant',
      'survivability.end_of_life: must be sunset-grant when license.preservation_pledge is present (attest_version 0.2)',
    )
  }
}

export function validatePayload(payload: JsonObject): string[] {
  const errors: string[] = []

  if (check(errors, 'attest_version' in payload, 'attest_version: required')) {
    check(errors, payload['attest_version'] === '0.1' || payload['attest_version'] === '0.2', 'attest_version: must be one of 0.1, 0.2')
  }
  if (check(errors, 'receipt_id' in payload, 'receipt_id: required')) {
    check(errors, typeof payload['receipt_id'] === 'string' && RECEIPT_ID_RE.test(payload['receipt_id']), 'receipt_id: must be a 26-char ULID')
  }
  if (check(errors, 'issued_at' in payload, 'issued_at: required')) {
    check(errors, typeof payload['issued_at'] === 'string' && ISSUED_AT_RE.test(payload['issued_at']), 'issued_at: must be an RFC3339 UTC date-time (YYYY-MM-DDTHH:MM:SSZ)')
  }
  if ('supersedes' in payload) {
    const supersedes = payload['supersedes']
    check(errors, supersedes === null || (typeof supersedes === 'string' && RECEIPT_ID_RE.test(supersedes)), 'supersedes: must be null or a 26-char ULID')
  }

  if (check(errors, 'issuer' in payload, 'issuer: required')) validateIssuer(payload['issuer'], errors)
  if (check(errors, 'buyer' in payload, 'buyer: required')) validateBuyer(payload['buyer'], errors)
  if (check(errors, 'work' in payload, 'work: required')) validateWork(payload['work'], errors)
  if (check(errors, 'license' in payload, 'license: required')) validateLicense(payload['license'], errors)
  if (check(errors, 'survivability' in payload, 'survivability: required')) validateSurvivability(payload['survivability'], errors)

  if ('license' in payload && 'survivability' in payload && 'work' in payload) {
    validateRevocabilityNoneConditional(payload, errors)
  }
  if ('license' in payload && 'buyer' in payload) {
    validateTransferableConditional(payload, errors)
  }
  if ('license' in payload) {
    validatePreservationPledgeConditional(payload, errors)
  }

  return errors
}

// --- G1 normative ceilings (attest-versioning.md §5 amendment; v0.1 §11/
// §15, v0.2 §6/§16) — conformance-surface structural bounds a conforming
// verifier MUST enforce, independent of and in addition to validatePayload
// above. Checked by verify.ts before any signature/schema work runs on the
// untrusted bytes they bound. Byte-identical to validate.py.

export const MAX_ENVELOPE_BYTES = 1_048_576 // raw, undecoded envelope size ceiling

/** Nesting-depth ceiling (2026-07-22 fix wave): an alias of canon.ts's
 * MAX_DEPTH, never a second, smaller value. loadsStrict already rejects any
 * input nested deeper than this during parsing (CanonError, "maximum
 * nesting depth exceeded") -- a parsed tree therefore can never exceed it,
 * so this module does NOT define its own jsonTreeDepth/validateJsonDepth
 * walk of the parsed tree: that check was proven byte-for-byte redundant
 * with canon.ts's own enforcement and was deleted rather than kept as dead
 * code. The name is kept as a public alias, at the single source-of-truth
 * value, because the spec (v0.1 §11.3) and tests reference MAX_JSON_DEPTH
 * as the name of the conformance-surface ceiling even though its
 * enforcement lives entirely in canon.ts. */
export const MAX_JSON_DEPTH = MAX_DEPTH

/** The raw envelope MUST NOT exceed MAX_ENVELOPE_BYTES. Checked on the
 * undecoded bytes, before any parsing work. */
export function validateEnvelopeSize(envelopeBytes: Uint8Array): string[] {
  if (envelopeBytes.length > MAX_ENVELOPE_BYTES) return [envelopeExceedsBytes(MAX_ENVELOPE_BYTES)]
  return []
}
