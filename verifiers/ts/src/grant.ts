// Sunset grants and cessation declarations — the preservation pledge (v0.2
// §18). Mirrors src/attest/grant.py (Python reference), VERIFICATION-SIDE
// ONLY (design §9: no build/sign here — a grant, a declaration and a holder's
// redemption response are built/signed only by the reference implementation's
// own CLI tooling, exactly as transfer.ts states for transfer records).
//
// A sunset grant is a CLOSED, hybrid-signed side-document published by the
// RIGHTS HOLDER (not by the receipt's issuer), structurally a sibling of the
// revocation record (revocation.ts) and the transfer record (transfer.ts):
// unknown members are rejected outright, it is JCS-canonicalized (v0.1 §9),
// and its own signature is verified under the §13 hybrid AND-rule through the
// single shared primitive manifests.ts's verifySignatureBlock. A receipt
// hash-binds one such document through the license term
// `license.preservation_pledge` (§18.2); that document is the buyer's FLOOR.
//
// This module holds the PRIMITIVES §18 is built out of, and nothing that
// reaches a verdict:
//
// - authenticating the grant (§18.2) and the cessation declaration (§18.4),
//   both fail-closed on every malformed, wrong-typed, out-of-window or
//   unsigned input, and neither ever throwing;
// - grantHash/declarationHash — `SHA-256(JCS(document))` over the ENTIRE
//   signed document, its own `signature` member included, the identical
//   hashing discipline revocation.ts's/transfer.ts's recordHash already
//   establish;
// - the TWO coverage predicates §18.4 deliberately keeps apart —
//   declarationCoversGrant (two documents of the same shape, series equality
//   a CONJUNCT) and grantCoversReceipt (a grant against a receipt's older
//   `work` block, series equality a SUFFICIENT clause). They are written
//   separately on purpose: sharing an implementation would collapse the very
//   distinction the specification spends a paragraph drawing;
// - the floor-relative non-narrowing ratchet (§18.3) and the prose-divergence
//   test that deliberately sits OUTSIDE it;
// - the structural ceilings (§18.4), which count and never inspect;
// - the audience-bound redemption proof (§18.7).
//
// Grant EVALUATION — §18.4's ordered steps, the `grant`/`grant_trust` result
// components, the resolution of the publisher's key manifest and the anchored
// fixed-date proof — needs the receipt payload, a trust store and an anchor
// policy in hand, so it belongs to the module that has them, exactly as
// revocation-class effectiveness belongs to verify.ts rather than here.
//
// Predicates that already exist are IMPORTED, never restated: the
// lowercase-DNS and 64-hex shapes from tlog.ts, the strict UTC wire-timestamp
// shape and its parse from dates.ts, key lookup and signature-block
// verification from manifests.ts. A second spelling of any of them is a place
// two implementations can drift apart, which is the one thing §18 spends most
// of its prose preventing.
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import type { JsonObject, JsonValue } from './canon.js'
import { canonicalBytes, dumps } from './canon.js'
import type { TrustStore } from './manifests.js'
import { findKey, verifySignatureBlock, verifyKeyManifest, chainContinuous } from './manifests.js'
import { parseStrictUtc, validStage3UtcTimestamp } from './dates.js'
import { ISSUER_RE, HEX64_RE } from './tlog.js'
import { b64uDecode } from './b64u.js'
import { verifyStrict } from './ed25519.js'
import type { AnchorPolicy, AnchorVerdict } from './anchor.js'
import { verifySeededAnchor, passesHorizon } from './anchor.js'
import { GRANT_WARN } from './messages.js'

const ACTIVE = 'active'
export const MAX_JCS_INTEGER = 2n ** 53n - 1n

// The eleven members of a sunset grant (§18.2) and the four of a cessation
// declaration (§18.4). Both documents are CLOSED — the log-entry discipline
// of §8, not the receipt payload's tolerant one — so an unknown member is not
// a warning but a rejection.
const GRANT_MEMBERS: ReadonlySet<string> = new Set([
  'grant_version',
  'publisher',
  'scope',
  'permissions',
  'activation',
  'unprotected_build',
  'legal_text_uri',
  'legal_text_sha256',
  'jurisdiction',
  'issued_at',
  'signature',
])
const DECLARATION_MEMBERS: ReadonlySet<string> = new Set(['publisher', 'scope', 'declared_at', 'signature'])
const SCOPE_MEMBERS: ReadonlySet<string> = new Set(['artifact_series', 'artifacts'])
const ACTIVATION_MEMBERS: ReadonlySet<string> = new Set(['modes', 'fixed_date', 'successor_ids'])

// Registry-governed vocabularies (attest-versioning.md §6.8-§6.10). Named
// constants rather than inline literals so a registration is one edit here.
export const PERMISSION_DELIVER_TO_HOLDER = 'deliver-to-holder'
export const PERMISSION_REDISTRIBUTE_AMONG_HOLDERS = 'redistribute-among-holders'

export const MODE_PUBLISHER_DECLARATION = 'publisher-declaration'
export const MODE_FIXED_DATE = 'fixed-date'
// Registered `reserved` (§6.9) and deliberately unreachable: a mode that reads
// meaning into the ABSENCE of a record cannot be sound until a verifier can
// establish freshness. A grant listing it is NOT thereby invalid — the mode
// simply contributes nothing to activation, which is why this constant exists
// and no code path honors it.
export const MODE_HEARTBEAT_ABSENCE = 'heartbeat-absence'

export const PLEDGE_SUNSET_GRANT_V1 = 'sunset-grant-v1'
export const END_OF_LIFE_SUNSET_GRANT = 'sunset-grant'

export const SIGNER_ROLE_PUBLISHER = 'publisher'
export const SIGNER_ROLE_SUCCESSOR = 'successor'

// Fixed literal (§18.7, verbatim) — the domain-separation label for the
// redemption preimage. A NEW preimage rather than a reuse of v0.1 §8.2's
// binding challenge precisely because that one names no recipient, so a
// response produced for one custodian would be replayable at another.
export const LABEL_REDEMPTION_CHALLENGE = new TextEncoder().encode('Attest-redemption-challenge-v1')
const MIN_REDEMPTION_NONCE_BYTES = 16

// Structural ceilings (§18.4, normative). `later_grants` and supplied
// declarations are attacker-supplied inputs whose elements each cost a hybrid
// signature verification, so a byte cap alone is not a ceiling: the COUNT of
// each is bounded, and the check runs BEFORE any signature work. Byte-identical
// VALUES to grant.py's `_MAX_GRANT_LATER_VERSIONS`/`_MAX_GRANT_DECLARATIONS`.
export const MAX_GRANT_LATER_VERSIONS = 64
export const MAX_GRANT_DECLARATIONS = 64

// --- shared shape predicates -------------------------------------------------

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** The lowercase-DNS shape of `issuer.id`, reused verbatim for `publisher`,
 * `work.publisher_id` and every `successor_ids` entry (§18.1). */
export function isDnsName(value: unknown): value is string {
  return typeof value === 'string' && ISSUER_RE.test(value)
}

function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64_RE.test(value)
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

/** Strict "less than" by UNICODE CODE POINT, which is what Python's `str <`
 * compares — NOT what JavaScript's own `<` does, which orders by UTF-16 code
 * unit. The two disagree exactly on astral characters against U+E000..U+FFFF
 * (a surrogate pair starts at 0xD800, so JS sorts every astral character
 * BEFORE U+E000 while Python sorts it after). `permissions` and
 * `activation.modes` accept any non-empty string, so an attacker can reach
 * that disagreement with a hand-built grant; without this helper the two cores
 * would accept and reject different documents on identical bytes. */
export function codePointLess(a: string, b: string): boolean {
  const left = [...a]
  const right = [...b]
  const shared = Math.min(left.length, right.length)
  for (let i = 0; i < shared; i++) {
    const x = left[i]!.codePointAt(0)!
    const y = right[i]!.codePointAt(0)!
    if (x !== y) return x < y
  }
  return left.length < right.length
}

/** A list whose every item passes `itemOk` and which is STRICTLY ascending —
 * one test for the "sorted, duplicate-free" shape §18.2 requires of
 * `scope.artifacts`, `permissions`, `activation.modes` and
 * `activation.successor_ids`. Set containment later compares these as sets;
 * pinning the wire order here is what keeps two canonicalizations of the same
 * grant byte-identical. Mirrors grant.py's `_sorted_unique`. */
export function sortedUnique(values: unknown, itemOk: (item: unknown) => boolean): values is string[] {
  if (!Array.isArray(values)) return false
  if (!values.every((item) => itemOk(item))) return false
  for (let i = 0; i + 1 < values.length; i++) {
    if (!codePointLess(values[i] as string, values[i + 1] as string)) return false
  }
  return true
}

/** Whether `o`'s own key set is EXACTLY `expected` — the closed-document
 * discipline of §8, spelled once for all four member sets here. */
export function hasExactMembers(o: Record<string, unknown>, expected: ReadonlySet<string>): boolean {
  const keys = Object.keys(o)
  return keys.length === expected.size && keys.every((k) => expected.has(k))
}

/** `scope` itself when it is `{artifact_series: string|null, artifacts:
 * [64-hex, ...]}` with at least one of the two non-empty (§18.2), else `null`.
 * The same shape is required of a cessation declaration's own `scope`.
 *
 * Returning the validated object rather than a bare boolean is what lets every
 * caller index it afterwards without a second, weaker check standing in for
 * the first one. */
export function scopeOrNull(scope: unknown): Record<string, unknown> | null {
  if (!isPlainObject(scope) || !hasExactMembers(scope, SCOPE_MEMBERS)) return null
  const series = scope['artifact_series']
  if (series !== null && !isNonEmptyString(series)) return null
  const artifacts = scope['artifacts']
  if (!sortedUnique(artifacts, isHex64)) return null
  if (series === null && (artifacts as string[]).length === 0) return null
  return scope
}

/** `activation` itself when it is a valid trigger, else `null`.
 *
 * `{modes, fixed_date, successor_ids}` (§18.2). `modes` is non-empty, sorted
 * and duplicate-free; a non-null `fixed_date` REQUIRES `"fixed-date"` among
 * the modes; `successor_ids` may be empty. Mode values are not restricted to
 * the registered three: an unregistered mode contributes nothing to
 * activation, exactly as the reserved `heartbeat-absence` does, and rejecting
 * the document over it would make a later registration retroactively
 * invalidate grants that predate it. */
function activationOrNull(activation: unknown): Record<string, unknown> | null {
  if (!isPlainObject(activation) || !hasExactMembers(activation, ACTIVATION_MEMBERS)) return null
  const modes = activation['modes']
  if (!sortedUnique(modes, isNonEmptyString) || (modes as string[]).length === 0) return null
  const fixedDate = activation['fixed_date']
  if (fixedDate !== null) {
    if (!validStage3UtcTimestamp(fixedDate)) return null
    if (!(modes as string[]).includes(MODE_FIXED_DATE)) return null
  }
  if (!sortedUnique(activation['successor_ids'], isDnsName)) return null
  return activation
}

/** The closed eleven-member shape of §18.2, checked before any cryptographic
 * work. `permissions` values are open for the same reason `activation.modes`
 * values are (see `activationOrNull`), but the array MUST contain
 * `deliver-to-holder`: a grant that does not deliver to the holder is not a
 * sunset grant. */
function validGrantShape(document: unknown): document is Record<string, unknown> {
  if (!isPlainObject(document) || !hasExactMembers(document, GRANT_MEMBERS)) return false
  const version = document['grant_version']
  // The strict/bigint convention canon.ts pins for every SIGNED document: a
  // JSON integer arrives as `bigint`, and canonicalBytes refuses anything else
  // — so a `number` here could never have been a wire grant in the first place.
  if (typeof version !== 'bigint' || version < 1n || version > MAX_JCS_INTEGER) return false
  const permissions = document['permissions']
  return (
    isDnsName(document['publisher']) &&
    scopeOrNull(document['scope']) !== null &&
    sortedUnique(permissions, isNonEmptyString) &&
    (permissions as string[]).includes(PERMISSION_DELIVER_TO_HOLDER) &&
    activationOrNull(document['activation']) !== null &&
    typeof document['unprotected_build'] === 'boolean' &&
    // §18.2 types `legal_text_uri` as "string, non-empty", exactly as it types
    // `jurisdiction` two lines down, so it goes through the same predicate.
    // This is a shape check, and shape is checked BEFORE the signature: a
    // grant naming no prose at all would otherwise authenticate, hash-bind to
    // the receipt, and run the whole evaluation through to `activated` on a
    // valid cessation declaration — a false `activated` authorizes
    // distribution of a work that is still on sale, which is the single
    // direction §18.4 declares normatively forbidden. The prose dependency is
    // load-bearing: `legal_text_uri` and `legal_text_sha256` are REQUIRED
    // members precisely so the commitment a buyer can go read is always
    // reachable, and an empty URI is not a location.
    isNonEmptyString(document['legal_text_uri']) &&
    isHex64(document['legal_text_sha256']) &&
    isNonEmptyString(document['jurisdiction']) &&
    validStage3UtcTimestamp(document['issued_at']) &&
    isPlainObject(document['signature'])
  )
}

/** The closed four-member shape of §18.4. */
function validDeclarationShape(declaration: unknown): declaration is Record<string, unknown> {
  if (!isPlainObject(declaration) || !hasExactMembers(declaration, DECLARATION_MEMBERS)) return false
  return (
    isDnsName(declaration['publisher']) &&
    scopeOrNull(declaration['scope']) !== null &&
    validStage3UtcTimestamp(declaration['declared_at']) &&
    isPlainObject(declaration['signature'])
  )
}

// --- hashing -----------------------------------------------------------------

/** `SHA-256(JCS(grant))`, 64 lowercase hex — the ENTIRE signed grant,
 * INCLUDING its own `signature` member (unlike the body-only bytes the
 * signature itself is computed over).
 *
 * This is what `license.preservation_pledge.grant_sha256` commits to (§18.2):
 * the SAME `canonicalBytes` this module already uses to verify the signature —
 * one canonical form, reused, never a second one invented for the binding.
 * Mirrors revocation.ts's and transfer.ts's recordHash exactly. */
export function grantHash(document: JsonObject): string {
  return bytesToHex(sha256(canonicalBytes(document)))
}

/** `SHA-256(JCS(declaration))`, 64 lowercase hex — the ENTIRE signed
 * declaration, its own `signature` member included.
 *
 * This is what a `cessation-declaration` transparency-log entry commits to
 * (§8, the fifth entry type). Logging a declaration is RECOMMENDED and never
 * load-bearing: an authenticated declaration activates a grant whether or not
 * it was ever logged, the opposite posture from `transfer-record`. */
export function declarationHash(declaration: JsonObject): string {
  return bytesToHex(sha256(canonicalBytes(declaration)))
}

// --- authentication ----------------------------------------------------------

/** The half §18.2's authentication paragraph shares with v0.1 §12.1 and
 * §17.1: the signer key must be **active** in `keyManifest`, its
 * `[valid_from, valid_to]` window must cover the document's OWN signed time
 * (never the verifier's clock), and the signature must verify over
 * `JCS(document)` with `signature` removed, under the §13 AND-rule. */
export function verifySignedDocument(
  document: Record<string, unknown>,
  keyManifest: JsonObject,
  timestampMember: string,
): boolean {
  const sigBlock = document['signature'] as JsonObject
  const kid = sigBlock['kid']
  const entry = findKey(keyManifest, typeof kid === 'string' ? kid : '')
  if (!entry || entry['status'] !== ACTIVE) return false
  const signedAt = parseStrictUtc(document[timestampMember])
  if (signedAt === null) return false
  const from = parseStrictUtc(entry['valid_from'])
  if (from === null || signedAt < from) return false
  const to = entry['valid_to']
  if (to !== null && to !== undefined) {
    const toMs = parseStrictUtc(to)
    if (toMs === null || signedAt > toMs) return false
  }
  const body: JsonObject = Object.create(null)
  for (const k of Object.keys(document)) if (k !== 'signature') body[k] = document[k] as JsonValue
  return verifySignatureBlock(canonicalBytes(body), sigBlock, entry)
}

/** Verify a grant's own signature against an ALREADY self-verified
 * `keyManifest` — exactly `verifyGrant` minus the `verifyKeyManifest`
 * self-consistency check, mirroring revocation.ts's/transfer.ts's
 * verifyRecordSignature.
 *
 * The closed eleven-member shape is checked FIRST: a document whose signature
 * happens to verify over a malformed member (any string canonicalizes fine, so
 * the signature alone cannot catch this) is still rejected. Fails closed on
 * every malformed/wrong-typed/unsigned/out-of-window input — never throws.
 *
 * This is AUTHENTICATION only. The triple domain binding of §18.4 step 5 —
 * `grant.publisher` equal to the resolving manifest's `issuer` equal to the
 * receipt's `work.publisher_id` — is a SEPARATE check, because §18.4 reports
 * its failure differently (`grant_trust: "signer_mismatch"` with
 * `grant_signer_not_publisher`, rather than a plain rejection). Compose it
 * from `signerDomain` and the two documents.
 *
 * PRECONDITION: the caller has already established
 * `verifyKeyManifest(keyManifest)`. Callers checking many documents against
 * ONE manifest hoist that call out of their loop. */
export function verifyGrantSignature(document: unknown, keyManifest: JsonObject): boolean {
  try {
    if (!validGrantShape(document)) return false
    return verifySignedDocument(document, keyManifest, 'issued_at')
  } catch {
    return false
  }
}

/** Verify a grant against `keyManifest`, mirroring revocation.ts's
 * verifyRecord exactly: the signer key must be **active** in a
 * SELF-CONSISTENT `keyManifest`, with its validity window covering the grant's
 * own `issued_at`, and the signature must verify under the §13 AND-rule.
 *
 * Defense-in-depth: `keyManifest` itself must be self-consistent, so a
 * fabricated publisher manifest paired with a matching fabricated grant
 * signature cannot verify. Fails closed on every malformed input, never
 * throws. */
export function verifyGrant(document: unknown, keyManifest: JsonObject): boolean {
  try {
    return verifyKeyManifest(keyManifest) && verifyGrantSignature(document, keyManifest)
  } catch {
    return false
  }
}

/** `verifyGrantSignature` for a cessation declaration: the closed four-member
 * shape, then the same active-key/window/AND-rule checks, with the window
 * checked against the declaration's own `declared_at`.
 *
 * Authentication only — whether this signer was ENTITLED to declare cessation
 * for a given grant is `declarationSignerRole`, and whether the declaration
 * reaches that grant's scope is `declarationCoversGrant`. */
export function verifyDeclarationSignature(declaration: unknown, keyManifest: JsonObject): boolean {
  try {
    if (!validDeclarationShape(declaration)) return false
    return verifySignedDocument(declaration, keyManifest, 'declared_at')
  } catch {
    return false
  }
}

/** `verifyGrant` for a cessation declaration: self-consistent manifest plus
 * `verifyDeclarationSignature`. Fails closed, never throws. */
export function verifyDeclaration(declaration: unknown, keyManifest: JsonObject): boolean {
  try {
    return verifyKeyManifest(keyManifest) && verifyDeclarationSignature(declaration, keyManifest)
  } catch {
    return false
  }
}

// --- who signed, and who was entitled to (§18.1, §18.4) ----------------------

/** The signing domain of a grant or declaration: the text before the first `/`
 * of `signature.kid` (v0.1 §7.1's kid grammar, where that prefix MUST equal
 * the manifest's own `issuer`), or `null` when it is absent, wrong-typed, or
 * not a lowercase DNS name.
 *
 * §18.1's resolution rule and §18.4 step 5's triple binding are both stated
 * over this domain; returning it rather than deciding either keeps the two
 * distinguishable, which is what lets a caller report `signer_mismatch`
 * separately from a plain authentication failure. */
export function signerDomain(document: unknown): string | null {
  if (!isPlainObject(document)) return null
  const sigBlock = document['signature']
  if (!isPlainObject(sigBlock)) return null
  const kid = sigBlock['kid']
  if (typeof kid !== 'string') return null
  const domain = kid.split('/', 1)[0]!
  return isDnsName(domain) ? domain : null
}

/** Who may sign (§18.4): `SIGNER_ROLE_PUBLISHER` when the declaration's `kid`
 * domain equals the EFFECTIVE grant's `publisher`, `SIGNER_ROLE_SUCCESSOR`
 * when it is one of that grant's `activation.successor_ids`, and `null` for
 * anyone else — a declaration from a stranger is never honored.
 *
 * The role is returned rather than a bare boolean because a successor's
 * declaration activates the grant AND is reported as such
 * (`grant_activated_by_successor`): informational, never a downgrade. The
 * successor list is read from the EFFECTIVE grant, so a later version that
 * widened it widens who may declare, and one that narrowed it never became
 * effective (§18.3). */
export function declarationSignerRole(declaration: unknown, document: unknown): string | null {
  try {
    const domain = signerDomain(declaration)
    if (domain === null || !isPlainObject(document)) return null
    const publisher = document['publisher']
    if (isDnsName(publisher) && domain === publisher) return SIGNER_ROLE_PUBLISHER
    const activation = document['activation']
    const successorIds = isPlainObject(activation) ? activation['successor_ids'] : null
    if (Array.isArray(successorIds) && successorIds.some((entry) => domain === entry)) {
      return SIGNER_ROLE_SUCCESSOR
    }
    return null
  } catch {
    return null
  }
}

// --- the two coverage predicates (§18.4) -------------------------------------
//
// Written separately, and deliberately not in terms of one another. A
// declaration and a grant are two documents of the SAME shape written by the
// same party, so series equality is a conjunct there; a grant and a receipt
// are not, and the receipt's `work` block is older and looser, so series
// equality is a SUFFICIENT clause here. Folding them into one helper would
// collapse exactly the distinction §18.4 spends a paragraph drawing.

/** DECLARATION coverage (§18.4): a declaration covers a grant iff `publisher`
 * is equal, `scope.artifact_series` is equal (both `null` counts as equal),
 * and the declaration's `scope.artifacts` is a SUPERSET of the grant's. Set
 * containment over sorted, duplicate-free hex arrays — no ambiguity left for
 * two implementations to drift apart on.
 *
 * Fails closed on every malformed input, never throws: a declaration that does
 * not cover is simply not honored. */
export function declarationCoversGrant(declaration: unknown, document: unknown): boolean {
  try {
    if (!isPlainObject(declaration) || !isPlainObject(document)) return false
    const declarationScope = scopeOrNull(declaration['scope'])
    const grantScope = scopeOrNull(document['scope'])
    if (declarationScope === null || grantScope === null) return false
    const publisher = declaration['publisher']
    if (!isDnsName(publisher) || publisher !== document['publisher']) return false
    if (declarationScope['artifact_series'] !== grantScope['artifact_series']) return false
    const declared = new Set(declarationScope['artifacts'] as string[])
    return (grantScope['artifacts'] as string[]).every((digest) => declared.has(digest))
  } catch {
    return false
  }
}

/** GRANT coverage (§18.4), a DIFFERENT predicate from the one above: a grant
 * covers a receipt iff EITHER holds —
 *
 * - `grant.scope.artifact_series` is non-null and equal to the receipt's
 *   `work.artifact_series`; OR
 * - the receipt's `work.artifacts[]` is PRESENT AND NON-EMPTY, and every
 *   `sha256` in it appears in `grant.scope.artifacts`.
 *
 * Either alone suffices: a grant scoped purely by artifact hash
 * (`artifact_series: null`) covers a receipt that names exactly those
 * artifacts EVEN IF that receipt also carries a series the grant does not
 * name — requiring the series to match here, as declaration coverage does,
 * would deny a buyer a grant that demonstrably names their own files.
 *
 * The non-empty requirement in the second clause is load-bearing, not
 * defensive prose. Both `work.artifact_series` and `work.artifacts` are
 * individually optional (v0.1 §5.4), so a receipt may carry only the series;
 * stated as a bare universal quantifier, the second clause would then range
 * over an empty set and be VACUOUSLY TRUE, making every grant cover every
 * series-only receipt — a false `activated` produced by a quantifier rather
 * than by any bad evidence, which is the exact direction §18.4's failure
 * asymmetry forbids. An empty or absent artifact list is covered by nothing.
 *
 * A receipt carrying only a series the grant does not name is uncovered: a
 * series is NOT resolved into hashes here, because that resolution depends on
 * evidence outside the receipt, and reaching further to say `activated` is
 * exactly what §18.4 forbids. Fails closed, never throws. */
export function grantCoversReceipt(document: unknown, payload: unknown): boolean {
  try {
    if (!isPlainObject(document) || !isPlainObject(payload)) return false
    const scope = scopeOrNull(document['scope'])
    if (scope === null) return false
    const work = payload['work']
    if (!isPlainObject(work)) return false

    const series = scope['artifact_series']
    if (series !== null && series === work['artifact_series']) return true

    const artifacts = work['artifacts']
    if (!Array.isArray(artifacts) || artifacts.length === 0) return false
    const granted = new Set(scope['artifacts'] as string[])
    for (const item of artifacts) {
      if (!isPlainObject(item)) return false
      const digest = item['sha256']
      if (!isHex64(digest) || !granted.has(digest)) return false
    }
    return true
  } catch {
    return false
  }
}

// --- the floor-relative ratchet (§18.3) --------------------------------------

/** `scope.artifact_series` unchanged, or newly set from `null`. A series
 * dropped back to `null`, or swapped for a different one, narrows: the buyer's
 * own catalogue would stop being named. */
function seriesNonNarrowing(floorSeries: unknown, laterSeries: unknown): boolean {
  return floorSeries === null || laterSeries === floorSeries
}

/** `activation.fixed_date` equal or EARLIER, or newly set from `null`.
 *
 * Pushing the backstop date further out makes activation strictly harder to
 * reach for a buyer who has already paid, so it narrows even though nothing
 * about the permissions changed — and removing the date altogether is that
 * same move taken to its limit, so it narrows too. */
function fixedDateNonNarrowing(floorDate: unknown, laterDate: unknown): boolean {
  if (floorDate === null) return true
  if (laterDate === null) return false
  const floorMs = parseStrictUtc(floorDate)
  const laterMs = parseStrictUtc(laterDate)
  // `activationOrNull` already accepted both as strict UTC wire timestamps;
  // the null guard is the fail-closed backstop, never a reachable branch.
  if (floorMs === null || laterMs === null) return false
  return laterMs <= floorMs
}

function isSubset(smaller: readonly string[], larger: readonly string[]): boolean {
  const bigger = new Set(larger)
  return smaller.every((item) => bigger.has(item))
}

/** The non-narrowing half of §18.3's ratchet, evaluated against the FLOOR —
 * never against another later version, and never against whichever version a
 * caller happened to accept first, so the outcome does not depend on the order
 * `later_grants` is presented in.
 *
 * `publisher` equality is checked FIRST, as a precondition of ADMISSIBILITY
 * (§18.3 criterion 1) rather than as one more narrowing test, and it is
 * load-bearing: `publisher` is what declaration coverage compares against
 * (§18.4), so a later version free to change it would move WHO MAY SIGN the
 * cessation that opens the grant. A supplied version naming a different
 * publisher is not a later version of this grant at all — it is a different
 * grant, and it is ignored, however much it widens every member the ratchet
 * does test. The `isDnsName` half is the same idiom `declarationCoversGrant`
 * already uses for the same comparison: a `publisher` that is not a lowercase
 * DNS name is not one this ratchet can reason about.
 *
 * Relative to the floor, ALL of: `permissions` a superset;
 * `scope.artifact_series` unchanged (or newly set from `null`);
 * `scope.artifacts` a superset; `unprotected_build` never going from `true` to
 * `false`; `activation.modes` a superset; `activation.fixed_date` equal or
 * earlier (or newly set from `null`); `activation.successor_ids` a superset.
 *
 * The `activation` half is what keeps the trigger from being narrowed after
 * the sale. `legal_text_uri`, `legal_text_sha256` and `jurisdiction` are
 * deliberately OUTSIDE this test — a verifier cannot read prose and MUST NOT
 * pretend to, so two grants differing only in `legal_text_sha256` are simply
 * different to a machine, and no comparison of hashes tells a clarification
 * from a restriction. That omission leaves the buyer exposed to nothing,
 * because the prose that binds them stays the floor's either way; the
 * divergence is reported instead, by `proseDiffers`.
 *
 * The REST of criterion 1 (currency: a strictly greater `grant_version`, a
 * signer key still active in the publisher's manifest chain, and the
 * rollback-or-equivocation rejection of two authenticated grants sharing one
 * `grant_version`) needs the manifest chain in hand and belongs with the
 * evaluation that resolves it.
 *
 * Fails closed on every malformed input, never throws: a version that cannot
 * be compared is ignored, which leaves the floor effective. */
export function isNonNarrowing(floor: unknown, later: unknown): boolean {
  try {
    if (!isPlainObject(floor) || !isPlainObject(later)) return false

    const floorPublisher = floor['publisher']
    if (!isDnsName(floorPublisher) || floorPublisher !== later['publisher']) return false

    const floorScope = scopeOrNull(floor['scope'])
    const laterScope = scopeOrNull(later['scope'])
    if (floorScope === null || laterScope === null) return false
    const floorActivation = activationOrNull(floor['activation'])
    const laterActivation = activationOrNull(later['activation'])
    if (floorActivation === null || laterActivation === null) return false

    const floorPermissions = floor['permissions']
    const laterPermissions = later['permissions']
    if (!sortedUnique(floorPermissions, isNonEmptyString) || !sortedUnique(laterPermissions, isNonEmptyString)) {
      return false
    }
    if (!isSubset(floorPermissions as string[], laterPermissions as string[])) return false

    const floorUnprotected = floor['unprotected_build']
    const laterUnprotected = later['unprotected_build']
    if (typeof floorUnprotected !== 'boolean' || typeof laterUnprotected !== 'boolean') return false
    if (floorUnprotected && !laterUnprotected) return false

    return (
      seriesNonNarrowing(floorScope['artifact_series'], laterScope['artifact_series']) &&
      isSubset(floorScope['artifacts'] as string[], laterScope['artifacts'] as string[]) &&
      isSubset(floorActivation['modes'] as string[], laterActivation['modes'] as string[]) &&
      fixedDateNonNarrowing(floorActivation['fixed_date'], laterActivation['fixed_date']) &&
      isSubset(floorActivation['successor_ids'] as string[], laterActivation['successor_ids'] as string[])
    )
  } catch {
    return false
  }
}

/** Whether an effective later version's prose-bearing members differ from the
 * FLOOR's — `legal_text_uri`, `legal_text_sha256` or `jurisdiction` (§18.3).
 * ALL THREE count, the URI included: a document served from a new location is
 * a new document to the person who has to go read it, even when the hash is
 * unchanged.
 *
 * The later version governs the machine-checkable members and does NOT replace
 * the prose: the grant text opposable for a receipt remains the one whose hash
 * the receipt itself signed at purchase. This predicate exists so the
 * divergence can be REPORTED (`grant_legal_text_changed`) rather than silently
 * resolved, which is the only reading under which "a publisher can widen what
 * was promised and can never narrow it" is true of the whole document rather
 * than only of its machine-readable half.
 *
 * Two documents that cannot be compared report no divergence; a caller only
 * reaches this with two authenticated grants, in which all three members are
 * strings by shape — so the identity comparison below is the same comparison
 * Python's `!=` performs there. */
export function proseDiffers(floor: unknown, later: unknown): boolean {
  if (!isPlainObject(floor) || !isPlainObject(later)) return false
  return (['legal_text_uri', 'legal_text_sha256', 'jurisdiction'] as const).some(
    (member) => floor[member] !== later[member],
  )
}

// --- structural ceilings (§18.4) ---------------------------------------------

export function withinCeiling(supplied: unknown, ceiling: number): boolean {
  if (supplied === null || supplied === undefined) return true
  if (!Array.isArray(supplied)) return false
  return supplied.length <= ceiling
}

/** Whether both attacker-supplied arrays are within their COUNT ceilings —
 * `MAX_GRANT_LATER_VERSIONS` and `MAX_GRANT_DECLARATIONS`, 64 each (§18.4).
 *
 * Each element of either array costs a hybrid signature verification, so a
 * byte cap alone is not a ceiling, exactly as v0.1 §11.3 and §16.1 already
 * require elsewhere. Exceeding either truncates evaluation fail-closed toward
 * `not_checked`, never toward `activated`.
 *
 * This predicate judges COUNT and nothing else: it never indexes, compares,
 * hashes or otherwise inspects an element. That is what lets a caller run it
 * BEFORE any signature is verified — and the specification is explicit that a
 * check which does not run first is not a ceiling at all. Absent evidence
 * (`null`/`undefined`) is within every ceiling; anything that is not an array
 * fails closed. */
export function withinStructuralCeilings(laterGrants: unknown, declarations: unknown): boolean {
  return withinCeiling(laterGrants, MAX_GRANT_LATER_VERSIONS) && withinCeiling(declarations, MAX_GRANT_DECLARATIONS)
}

// --- redemption (§18.7) ------------------------------------------------------

/** The audience-bound redemption preimage (§18.7, normative, verbatim):
 *
 * `UTF8("Attest-redemption-challenge-v1") || 0x00 || UTF8(receiptId) || 0x00
 * || UTF8(audience) || 0x00 || nonce`
 *
 * `receiptId` is the receipt's own `payload.receipt_id` as UTF-8 text, not
 * decoded and re-encoded (v0.1 §8.2 and §17.1 discipline, unchanged);
 * `audience` is the custodian's lowercase DNS domain, as UTF-8 text; `nonce`
 * is at least 16 RAW bytes, freshly generated by the custodian per challenge.
 *
 * `audience` is why this is a NEW preimage rather than a reuse of v0.1 §8.2's
 * binding challenge: that one names no recipient, so a response produced for
 * one custodian would be replayable at another.
 *
 * Throws on a nonce below the floor — a caller-side mistake, the same posture
 * commitment.ts's `verifyChallenge` takes, with the identical message text.
 * Verification of an untrusted response never throws; see `verifyRedemption`. */
export function redemptionMessage(receiptId: string, audience: string, nonce: Uint8Array): Uint8Array {
  if (nonce.length < MIN_REDEMPTION_NONCE_BYTES) {
    throw new Error(`nonce must be at least ${MIN_REDEMPTION_NONCE_BYTES} bytes`)
  }
  const enc = new TextEncoder()
  const parts = [
    LABEL_REDEMPTION_CHALLENGE,
    Uint8Array.of(0x00),
    enc.encode(receiptId),
    Uint8Array.of(0x00),
    enc.encode(audience),
    Uint8Array.of(0x00),
    nonce,
  ]
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

/** Verify a holder's redemption response for THIS `audience`.
 *
 * `holderPubkeyB64u` is the receipt's own `buyer.pubkey` as its base64url
 * text, read by the caller and never by this function. A response produced for
 * a different custodian, a different receipt, or a different nonce does not
 * verify — that binding is the whole point of the preimage.
 *
 * Fails closed and never throws on every malformed input: a wrong-length
 * signature or key, a non-base64url key, a short nonce, or a genuinely wrong
 * signature all return `false`. A gate that fronts the delivery of content
 * must not have an error path that is distinguishable from a rejection.
 *
 * Salt disclosure is NOT accepted as a redemption proof anywhere in this
 * module, and §18.7 prohibits it normatively: it is a replayable bearer proof
 * that also hands over the identifier (v0.1 §8.1) and burns the receipt's
 * binding secrecy toward that verifier — unfit for a gate queried repeatedly
 * by different custodians. */
export function verifyRedemption(
  receiptId: string,
  audience: string,
  nonce: Uint8Array,
  sig: Uint8Array,
  holderPubkeyB64u: string,
): boolean {
  try {
    const message = redemptionMessage(receiptId, audience, nonce)
    return verifyStrict(message, sig, b64uDecode(holderPubkeyB64u))
  } catch {
    return false
  }
}

// --- Stage 4 evaluation: §18.4's ordered steps 1-11 --------------------------
//
// Python keeps `evaluate_grant` in verify.py rather than grant.py, on the
// stated ground that evaluation needs the payload, a trust store and an anchor
// policy in hand. This port puts it HERE instead, for the same reason
// revocation.ts owns `classifyRevocation` where Python keeps
// `_classify_revocation` in verify.py: one Python module maps to one module
// here, and the evaluation that composes a module's own primitives lives with
// them. verify.ts keeps only the plumbing — the channel, the gate, and the
// merge of the two components into its result.

/** §18.5's two purely informational components plus the warnings §18.4's
 * ordered steps emitted along the way.
 *
 * Kept separate from `VerificationResult` so the evaluation is callable on its
 * own — a custodian checking §18.7's preconditions asks this question without
 * re-verifying a receipt it has already verified — and so the ordered steps
 * stay testable one at a time.
 *
 * The two members are spelled as §18.5 spells the COMPONENTS, `grant` and
 * `grant_trust`, matching `VerificationResult`'s own `manifest_freshness`
 * convention: these are wire-contract names, not internal ones. */
export interface GrantVerdict {
  grant: string
  grant_trust: string
  warnings: string[]
}

// §18.5's two closed value sets. `grant_trust` reuses the three `trust` values
// verbatim (v0.1 §11.1), adding exactly one — `signer_mismatch` — for the case
// v0.1's ladder has no way to express: a well-formed, well-signed document
// from a domain that is not the declared rights holder.
export const GRANT_NOT_CHECKED = 'not_checked'
export const GRANT_NONE = 'none'
export const GRANT_DORMANT = 'dormant'
export const GRANT_ACTIVATED = 'activated'
export const GRANT_INVALID_IGNORED = 'invalid_grant_ignored'

export const GRANT_TRUST_NOT_CHECKED = 'not_checked'
export const GRANT_TRUST_VERIFIED = 'verified'
export const GRANT_TRUST_TOFU = 'unauthenticated_tofu'
export const GRANT_TRUST_UNVERIFIED_ROTATION = 'unverified_rotation'
export const GRANT_TRUST_SIGNER_MISMATCH = 'signer_mismatch'

const PROVENANCE_TLS = 'tls'
const PLEDGE_MEMBERS = ['pledge', 'grant_uri', 'grant_sha256'] as const

/** attest-versioning.md §6.10: the sole preservation-pledge profile §18
 * defines. Open and versioned, following §6.7's discipline — an unrecognized
 * `license.preservation_pledge.pledge` is never a schema error. It is also
 * never evaluated under `sunset-grant-v1`'s rules (§18.4 step 2, warning
 * `grant_pledge_type_unknown`): a later profile may attach different meaning
 * to the same members, and guessing is exactly how two conforming
 * implementations reach different verdicts on identical input. */
export const KNOWN_PLEDGE_TYPES: ReadonlySet<string> = new Set([PLEDGE_SUNSET_GRANT_V1])

/** `license.preservation_pledge` when it is readable as an object carrying the
 * three REQUIRED members of §18.2 with their declared types, else `null`
 * (§18.4 step 1's "absent, or unreadable as an object with the three required
 * members").
 *
 * The object is deliberately NOT closed: it lives inside the payload, whose
 * posture toward unrecognized members is tolerant (v0.1 §11.2), and a future
 * pledge profile that needs a fourth member must not be a schema error on a
 * verifier that predates it. */
function pledgeOrNull(payload: unknown): Record<string, unknown> | null {
  if (!isPlainObject(payload)) return null
  const licenseBlock = payload['license']
  if (!isPlainObject(licenseBlock)) return null
  const pledge = licenseBlock['preservation_pledge']
  if (!isPlainObject(pledge)) return null
  if (!PLEDGE_MEMBERS.every((member) => typeof pledge[member] === 'string')) return null
  if (!isNonEmptyString(pledge['pledge']) || !isNonEmptyString(pledge['grant_uri'])) return null
  if (!isHex64(pledge['grant_sha256'])) return null
  return pledge
}

/** §18.5's ladder for the PUBLISHER's manifest — v0.1 §11.1's discipline for
 * `trust`, applied verbatim to a different domain and reported ONLY in
 * `grant_trust`. The receipt's own `trust` component is untouched: it remains
 * a statement about the issuer, and a publisher the verifier happens to know
 * less well must never downgrade it.
 *
 * The chain's tail is value-compared through its canonical form, not by
 * identity: a chain that does not end at the manifest actually being used
 * proves nothing about it, and two structurally identical manifests are the
 * same document (the same comparison verify.ts already makes for the issuer's
 * own chain). */
function grantTrustLadder(trustStore: TrustStore, domain: string, manifest: unknown): string {
  const level = trustStore.provenance[domain] === PROVENANCE_TLS ? GRANT_TRUST_VERIFIED : GRANT_TRUST_TOFU
  const chain = trustStore.chains?.[domain]
  if (chain && chain.length > 0) {
    let tailMatchesUsed = false
    try {
      tailMatchesUsed = isPlainObject(manifest) && dumps(chain[chain.length - 1]!) === dumps(manifest as JsonValue)
    } catch {
      tailMatchesUsed = false
    }
    if (!chainContinuous(chain) || !tailMatchesUsed) return GRANT_TRUST_UNVERIFIED_ROTATION
  }
  return level
}

/** §18.4's `fixed-date` proof: an anchored attestation over the EFFECTIVE
 * grant's own canonical bytes whose proven chain time `T` satisfies
 * `T >= fixedDate`, verified under §11 with the caller's own `AnchorPolicy`,
 * CRQC horizon check included.
 *
 * The seed is the EFFECTIVE grant, not the floor: §18.3 says a later version
 * that became effective governs the machine-checkable members, and `activation`
 * is one of them — so the document whose backstop is being proven is the one
 * that carries the backstop.
 *
 * `T` is the MAXIMUM over the verified proofs (`AnchorVerdict.anchoredAfter`),
 * deliberately the opposite reduction from §11's `anchoredBefore`: the two
 * answer opposite questions, and taking the minimum here would let one old
 * genuine proof hold a grant closed the moment a second, newer one is
 * presented.
 *
 * A verifier with no `AnchorPolicy` is not anchor-capable at all, so the proof
 * cannot be evaluated and the grant stays closed — the direction §18.4's
 * failure asymmetry requires. Every malformed input degrades to `false`; only
 * a malformed POLICY throws, and that is trusted verifier config, not
 * evidence. */
function fixedDateReached(
  evidence: unknown,
  effective: Record<string, unknown>,
  fixedDate: string,
  anchorPolicy: AnchorPolicy | null,
): boolean {
  if (anchorPolicy == null || !isPlainObject(evidence)) return false
  // The evidence bundle crosses this port's ONE representation boundary here.
  // Everything reaching `evaluateGrant` arrives strict-parsed, because the
  // grant documents in the same view have to canonicalize (`grant_version` is
  // a `bigint`); the §11 evaluators, by contract, read the "materialized"
  // plain-JS-number form (`anchor.ts` requires `typeof header_time ===
  // 'number'`). transfer.ts's `recordLoggedStanding` makes exactly this split
  // over exactly this shape — a strict `record` beside a materialized
  // `evidence` — and this mirrors it, confinement included: a hostile bundle
  // degrades to `dormant`, it never escapes as an exception. Python needs no
  // counterpart because an `int` is an `int` there.
  let materialized: unknown
  try {
    materialized = JSON.parse(dumps(evidence as JsonValue))
  } catch {
    return false
  }
  if (!isPlainObject(materialized)) return false
  const seed = canonicalBytes(effective as JsonObject)
  const verdict: AnchorVerdict = verifySeededAnchor(materialized, seed, anchorPolicy)
  if (!verdict.anchored || verdict.anchoredAfter == null) return false
  if (!passesHorizon(verdict, anchorPolicy)) return false
  const deadlineMs = parseStrictUtc(fixedDate)
  if (deadlineMs === null) return false
  // `anchoredAfter` is a pinned header's own UNIX time, in seconds.
  return verdict.anchoredAfter >= deadlineMs / 1000
}

/** §18.3 step 7: the effective grant is the MAXIMUM `grant_version` over the
 * later versions that independently pass both criteria against the FLOOR — a
 * maximum over a floor-relative filter, never a sequential fold that mutates
 * as candidates are processed, which is what keeps the result independent of
 * `later_grants`' presentation order.
 *
 * Three ways a supplied version is set aside, deliberately distinguished:
 *
 * - It does not AUTHENTICATE against the publisher's manifest: ignored with no
 *   effect at all. Unauthenticated bytes are free for anyone to produce, so
 *   letting them move `grant_trust` would hand an attacker a downgrade for the
 *   price of appending garbage to an array.
 * - Its `publisher` differs from the floor's: INADMISSIBLE — §18.3 says such a
 *   document "is not a later version of this grant at all; it is a different
 *   grant". It says nothing about this grant's currency, so it is ignored with
 *   no effect either. (`isNonNarrowing` enforces the same precondition
 *   independently, so a caller holding only that predicate cannot be widened
 *   into someone else's grant.)
 * - It is authenticated, same-publisher, and its `grant_version` is not
 *   strictly greater than the floor's, or two DISTINCT authenticated documents
 *   share one `grant_version`: rollback-or-equivocation, rejected and reported
 *   `grant_trust: "unverified_rotation"` — the same value and posture v0.1
 *   §7.3 already uses for manifests. Both are genuine publisher-signed
 *   artifacts, so an inconsistency among them is a real currency signal rather
 *   than something an attacker manufactured.
 *
 * A byte-identical duplicate of a document already seen is deduplicated rather
 * than treated as equivocation: "two DISTINCT authenticated grants" is what
 * §18.3 rejects, and a replayed copy is not a second document. */
function resolveEffectiveGrant(
  floor: Record<string, unknown>,
  floorHash: string,
  laterGrants: unknown,
  manifest: JsonObject,
  grantTrust: string,
  warnings: string[],
): { effective: Record<string, unknown>; grantTrust: string } {
  const candidates = new Map<string, Record<string, unknown>>()
  candidates.set(floorHash, floor)
  for (const later of Array.isArray(laterGrants) ? laterGrants : []) {
    if (!isPlainObject(later) || !verifyGrant(later, manifest)) continue
    if (later['publisher'] !== floor['publisher']) continue
    const hash = grantHash(later as JsonObject)
    if (!candidates.has(hash)) candidates.set(hash, later)
  }

  const byVersion = new Map<bigint, number>()
  for (const document of candidates.values()) {
    const version = document['grant_version'] as bigint
    byVersion.set(version, (byVersion.get(version) ?? 0) + 1)
  }
  const equivocating = new Set<bigint>()
  for (const [version, count] of byVersion) if (count > 1) equivocating.add(version)
  if (equivocating.size > 0) grantTrust = GRANT_TRUST_UNVERIFIED_ROTATION

  const floorVersion = floor['grant_version'] as bigint
  const passing: Record<string, unknown>[] = []
  let narrowingSeen = false
  for (const [documentHash, document] of candidates) {
    if (documentHash === floorHash) continue
    const version = document['grant_version'] as bigint
    if (equivocating.has(version)) continue
    if (version <= floorVersion) {
      grantTrust = GRANT_TRUST_UNVERIFIED_ROTATION
      continue
    }
    if (!isNonNarrowing(floor, document)) {
      narrowingSeen = true
      continue
    }
    passing.push(document)
  }

  if (narrowingSeen) warnings.push(GRANT_WARN.NARROWING_IGNORED)
  if (passing.length === 0) return { effective: floor, grantTrust }

  // First maximum wins, over an insertion-ordered map — the same document
  // Python's `max(passing, key=...)` returns for the same input.
  let effective = passing[0]!
  for (const document of passing) {
    if ((document['grant_version'] as bigint) > (effective['grant_version'] as bigint)) effective = document
  }
  if (proseDiffers(floor, effective)) {
    // The structural members of the later version govern; the prose that binds
    // this buyer stays the one their own receipt hash-bound. All three
    // prose-bearing members count, the URI included: a document served from a
    // new location is a new document to the person who has to go read it, even
    // when the hash is unchanged.
    warnings.push(GRANT_WARN.LEGAL_TEXT_CHANGED)
  }
  return { effective, grantTrust }
}

/** §18.4 step 9: EVERY supplied declaration is examined; the step never stops
 * at the first one that succeeds.
 *
 * The full scan is required rather than a short circuit precisely so that the
 * warning set is a function of the evidence and not of its arrangement: with a
 * mixed set, an implementation that stopped at the first valid declaration
 * would report a different result than one that did not, and both would be
 * conforming — which is how two honest implementations end up disagreeing in
 * front of a user. Both warnings are emitted at most once each. */
function honorDeclarations(
  declarations: unknown,
  effective: Record<string, unknown>,
  trustStore: TrustStore,
  warnings: string[],
): boolean {
  let honored = false
  let bySuccessor = false
  let ignored = false
  for (const declaration of Array.isArray(declarations) ? declarations : []) {
    const role = declarationSignerRole(declaration, effective)
    const domain = signerDomain(declaration)
    // A successor's manifest is resolved exactly like the publisher's (§18.1)
    // — same shape, same TOFU/TLS ladder, same `compromised` fail-closed. A
    // declaration signed under a key later marked `compromised` ceases to
    // authenticate, and a grant that had activated on it returns to `dormant`:
    // the safe direction, stated in §18.4 rather than left to be discovered.
    const declarationManifest = typeof domain === 'string' ? trustStore.manifests[domain] : undefined
    if (
      role === null ||
      !isPlainObject(declarationManifest) ||
      declarationManifest['issuer'] !== domain ||
      !verifyDeclaration(declaration, declarationManifest as JsonObject) ||
      !declarationCoversGrant(declaration, effective)
    ) {
      ignored = true
      continue
    }
    honored = true
    bySuccessor = bySuccessor || role === SIGNER_ROLE_SUCCESSOR
  }

  if (ignored) warnings.push(GRANT_WARN.DECLARATION_IGNORED)
  if (honored && bySuccessor) {
    // Informational, never a downgrade: the caller can see that the cessation
    // was declared by a designated third party rather than by the rights
    // holder itself.
    warnings.push(GRANT_WARN.ACTIVATED_BY_SUCCESSOR)
  }
  return honored
}

/** §18.4's deterministic, short-circuiting evaluation order, steps 1-11.
 *
 * `grantView` is Stage 4's evidence channel and its capability gate at once,
 * exactly as `transferView` is Stage 3's: `null`/`undefined` means the caller
 * is not Stage-4-capable and NOTHING is evaluated — `not_checked`/
 * `not_checked`, no warnings, which is byte-for-byte what every pre-Stage-4
 * caller already implicitly gets. Supplying the channel AT ALL — even as `{}` —
 * opts into the ordered evaluation, whose first three steps then read only the
 * signed payload and run BEFORE step 4's "no evidence supplied" short circuit,
 * so a defect visible in the receipt itself is never masked by missing
 * evidence.
 *
 * The view's four members, all optional:
 *
 * - `grant`: the FLOOR grant document the receipt hash-binds (§18.2).
 * - `later_grants`: versions the verifier additionally holds, each evaluated
 *   independently AGAINST THE FLOOR (§18.3).
 * - `declarations`: cessation declarations (§18.4), scanned in full.
 * - `anchor`: ONE §11 evidence bundle for the `fixed-date` proof. One bundle,
 *   not a list: §18.4's maximum reduction is over the PROOFS inside a bundle,
 *   which `verifySeededAnchor` already computes, and a list would be a third
 *   attacker-supplied array with no ceiling of its own.
 *
 * Per D6 the verdict takes no exception: neither component ever affects
 * `signature`, `schema`, `revocation`, `binding`, `trust` or `ok`.
 *
 * Which way this fails is normative (§18.4): a false `activated` authorizes
 * distribution of a work that is still on sale, a false `dormant` only means a
 * buyer cannot yet redeem. Every missing, unverifiable, malformed or ambiguous
 * input therefore resolves to `dormant` or `not_checked`, never to
 * `activated`. Hostile evidence never throws; only malformed TRUSTED config
 * (an `AnchorPolicy`) does, and a `grantView` that is not an evidence object
 * at all, which is a caller-contract violation. */
export function evaluateGrant(
  payload: unknown,
  trustStore: TrustStore,
  grantView: unknown,
  anchorPolicy: AnchorPolicy | null = null,
): GrantVerdict {
  if (grantView != null && !isPlainObject(grantView)) {
    throw new TypeError('grant_view must be an evidence object or None')
  }

  const warnings: string[] = []
  if (grantView == null) {
    return { grant: GRANT_NOT_CHECKED, grant_trust: GRANT_TRUST_NOT_CHECKED, warnings }
  }
  const notChecked = (): GrantVerdict => ({
    grant: GRANT_NOT_CHECKED,
    grant_trust: GRANT_TRUST_NOT_CHECKED,
    warnings,
  })
  const invalidIgnored = (grantTrust: string): GrantVerdict => ({
    grant: GRANT_INVALID_IGNORED,
    grant_trust: grantTrust,
    warnings,
  })

  // --- Step 1: the pledge itself, from the signed payload alone.
  const pledge = pledgeOrNull(payload)
  if (pledge === null) {
    return { grant: GRANT_NONE, grant_trust: GRANT_TRUST_NOT_CHECKED, warnings }
  }

  // --- Step 2: an unrecognized profile is valid-with-warning as SCHEMA, but
  // MUST NOT be evaluated under `sunset-grant-v1`'s rules — a later profile may
  // attach different meaning to the same members, and guessing is exactly how
  // two conforming implementations reach different verdicts.
  if (!KNOWN_PLEDGE_TYPES.has(pledge['pledge'] as string)) {
    warnings.push(GRANT_WARN.PLEDGE_TYPE_UNKNOWN)
    return notChecked()
  }

  // --- Step 3: the issuer's own inconsistency, visible in the signed payload
  // alone, so it is reported whether or not any evidence was supplied. The
  // license term governs and evaluation CONTINUES: the two fields have
  // different authorities, and silently preferring one would hide the
  // inconsistency from the person holding the receipt.
  const survivability = (payload as Record<string, unknown>)['survivability']
  const eolCommitment = isPlainObject(survivability) ? survivability['eol_commitment_sha256'] : null
  if (typeof eolCommitment === 'string' && eolCommitment !== pledge['grant_sha256']) {
    warnings.push(GRANT_WARN.COMMITMENT_DIVERGENCE)
  }

  // --- Step 4: the structural ceilings, then the evidence itself. The
  // ceilings run BEFORE any signature is verified, or they are not ceilings.
  const laterGrants = grantView['later_grants']
  const declarations = grantView['declarations']
  if (!withinStructuralCeilings(laterGrants, declarations)) return notChecked()
  const floor = grantView['grant']
  if (!isPlainObject(floor)) return notChecked()

  // --- Step 5: authenticate the floor, then the triple domain binding.
  // `grant_trust` starts at TOFU the moment evidence exists and is reported at
  // its best-available value from here on, even when the evaluation later
  // rejects the document — it MUST NOT be silently reset on failure (§18.5).
  const work = (payload as Record<string, unknown>)['work']
  const publisherId = isPlainObject(work) ? work['publisher_id'] : null
  const signer = signerDomain(floor)
  const manifest = signer !== null ? trustStore.manifests[signer] : undefined
  // The ladder is scoped to the RECEIPT's declared `work.publisher_id` (§18.5,
  // "the trust store's provenance for the resolved `work.publisher_id`"), and
  // NEVER to whatever domain a supplied document happens to name in its `kid`.
  // The document is attacker-supplied and has not authenticated yet at this
  // point: keying the ladder on its signer would let a blob that authenticates
  // against nothing pick any TLS domain the verifier happens to know and buy
  // `grant_trust: "verified"` for the price of appending bytes to an evidence
  // object. The SIGNER's manifest is still what the signature resolves
  // against, below — the two are the same domain in every case that gets past
  // the binding check, and where they differ the answer is `signer_mismatch`,
  // not a trust value borrowed from a stranger.
  let grantTrust =
    typeof publisherId === 'string'
      ? grantTrustLadder(trustStore, publisherId, trustStore.manifests[publisherId])
      : GRANT_TRUST_TOFU

  if (!isPlainObject(manifest) || !verifyGrant(floor, manifest as JsonObject)) {
    return invalidIgnored(grantTrust)
  }
  // §18.1: the signer's `kid` DNS prefix MUST equal the resolving manifest's
  // own `issuer`. A trust store that maps one domain to another domain's
  // manifest is a misconfiguration, not a rights-holder mismatch, so it is
  // rejected plainly rather than reported as `signer_mismatch`.
  if (manifest['issuer'] !== signer) return invalidIgnored(grantTrust)
  if (typeof publisherId !== 'string' || signer !== publisherId) {
    // The marketplace-signing-a-grant-it-has-no-rights-to-concede case, named.
    // Reachable only for a document that ALREADY authenticated (§18.1): an
    // unsigned blob from a foreign domain is a plain rejection, so hostile
    // evidence cannot force a trust value on its own. A receipt with no
    // `publisher_id` at all has no declared rights holder for the signer to
    // mismatch, so that one is a plain rejection too.
    if (typeof publisherId === 'string') {
      warnings.push(GRANT_WARN.SIGNER_NOT_PUBLISHER)
      return { grant: GRANT_INVALID_IGNORED, grant_trust: GRANT_TRUST_SIGNER_MISMATCH, warnings }
    }
    return invalidIgnored(grantTrust)
  }
  if (floor['publisher'] !== publisherId) return invalidIgnored(grantTrust)

  // --- Step 6: the receipt binding. One canonical form, never a second one.
  const floorHash = grantHash(floor as JsonObject)
  if (floorHash !== pledge['grant_sha256']) {
    warnings.push(GRANT_WARN.COMMITMENT_MISMATCH)
    return invalidIgnored(grantTrust)
  }

  // --- Step 7: the floor-relative ratchet (§18.3).
  const resolved = resolveEffectiveGrant(floor, floorHash, laterGrants, manifest as JsonObject, grantTrust, warnings)
  const effective = resolved.effective
  grantTrust = resolved.grantTrust

  // --- Step 8: scope coverage, and it is a GATE. Reporting `activated` on an
  // uncovered receipt would tell the holder they may redeem something the
  // grant never spoke about, and would contradict §18.7's own custodian
  // precondition — so neither activation path is evaluated.
  if (!grantCoversReceipt(effective, payload)) {
    warnings.push(GRANT_WARN.SCOPE_UNCOVERED)
    return { grant: GRANT_DORMANT, grant_trust: grantTrust, warnings }
  }

  // --- Step 9: the declaration path, scanned in FULL.
  if (honorDeclarations(declarations, effective, trustStore, warnings)) {
    return { grant: GRANT_ACTIVATED, grant_trust: grantTrust, warnings }
  }

  // --- Step 10: the fixed-date path, reached ONLY because step 9 did not
  // activate. A missing backstop proof says nothing about a grant that is
  // already open, so `grant_unanchored` is not emitted there — that is what
  // keeps the warning set from depending on which spare evidence a caller
  // happened to attach.
  const activation = effective['activation']
  const modes = isPlainObject(activation) ? activation['modes'] : null
  const fixedDate = isPlainObject(activation) ? activation['fixed_date'] : null
  if (Array.isArray(modes) && modes.includes(MODE_FIXED_DATE) && fixedDate != null) {
    if (typeof fixedDate === 'string' && fixedDateReached(grantView['anchor'], effective, fixedDate, anchorPolicy)) {
      return { grant: GRANT_ACTIVATED, grant_trust: grantTrust, warnings }
    }
    warnings.push(GRANT_WARN.UNANCHORED)
  }

  // --- Step 11.
  return { grant: GRANT_DORMANT, grant_trust: grantTrust, warnings }
}
