// Publisher authorization manifests -- may this seller sell? (v0.2 section 20).
// Mirrors src/attest/authority.py, verification side only. The Python builder
// has no TypeScript counterpart, matching grant.ts and transfer.ts.
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import type { JsonObject, JsonValue } from './canon.js'
import {
  canonicalBytes, materializeArray, materializeValue, ownViewMember,
  VIEW_MEMBER_ABSENT, VIEW_MEMBER_NESTING,
} from './canon.js'
import { validStage3UtcTimestamp, parseStrictUtc } from './dates.js'
import {
  MAX_JCS_INTEGER,
  GRANT_TRUST_UNVERIFIED_ROTATION,
  grantCoversReceipt,
  grantTrustLadder,
  signerDomain,
  hasExactMembers,
  isDnsName,
  isNonEmptyString,
  isPlainObject,
  scopeOrNull,
  sortedUnique,
  verifySignedDocument,
  withinCeiling,
} from './grant.js'
import type { TrustStore } from './manifests.js'
import { verifyKeyManifest } from './manifests.js'
import { AUTHORITY_WARN } from './messages.js'

export const PERMISSION_ISSUE = 'issue'
// Registered reserved and deliberately unreachable: delegation chains are out
// of this revision. Listing it never invalidates a document, but no code path
// honors it as issue authority.
export const PERMISSION_DELEGATE = 'delegate'

export const MAX_AUTHORIZED_ISSUERS = 4096
export const MAX_AUTHORITY_DOCUMENTS = 64

const AUTHORIZATION_MEMBERS: ReadonlySet<string> = new Set([
  'authorization_version',
  'publisher',
  'authorized_issuers',
  'issued_at',
  'signature',
])
const ENTRY_MEMBERS: ReadonlySet<string> = new Set(['issuer_id', 'valid_from', 'valid_to', 'permissions', 'scope'])

/** Shared predicate for document `authorization_version` and caller-supplied
 * `current_authorization_version`. Strict JSON documents arrive as `bigint`;
 * hand-written JavaScript views may use `number`, so both representations are
 * accepted in the attest-JCS safe-integer range. Booleans stay excluded.
 *
 * Task 7 note: step 10 must normalize before equality. `5n === 5` is false
 * even though this single predicate accepts both encodings of the same value. */
export function isAuthorizationVersion(value: unknown): boolean {
  if (typeof value === 'bigint') return value >= 1n && value <= MAX_JCS_INTEGER
  if (typeof value === 'number') {
    return Number.isInteger(value) && value >= 1 && value <= Number(MAX_JCS_INTEGER)
  }
  return false
}

// Kept local to §20 authority shapes: sparse/non-index arrays are a JavaScript
// representation hazard here, while widening grant.ts would change §18 grant
// and declaration validation outside this task's boundary.
function isDenseAuthorityArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value)) return false
  try {
    const length = value.length
    const keys = Reflect.ownKeys(value)
    if (keys.length !== length + 1) return false
    for (let i = 0; i < length; i++) {
      if (!Object.prototype.hasOwnProperty.call(value, i)) return false
    }
    return keys.every((key) => {
      if (key === 'length') return true
      if (typeof key !== 'string') return false
      const index = Number(key)
      return Number.isInteger(index) && index >= 0 && index < length && String(index) === key
    })
  } catch {
    return false
  }
}

function authorityScopeOrNull(scope: unknown): Record<string, unknown> | null {
  const validScope = scopeOrNull(scope)
  if (validScope === null) return null
  return isDenseAuthorityArray(validScope['artifacts']) ? validScope : null
}

function validEntryShape(entry: unknown): entry is Record<string, unknown> {
  if (!isPlainObject(entry) || !hasExactMembers(entry, ENTRY_MEMBERS)) return false
  const validTo = entry['valid_to']
  const permissions = entry['permissions']
  const scope = entry['scope']
  return (
    isDnsName(entry['issuer_id']) &&
    validStage3UtcTimestamp(entry['valid_from']) &&
    (validTo === null || validStage3UtcTimestamp(validTo)) &&
    Array.isArray(permissions) &&
    permissions.length > 0 &&
    sortedUnique(permissions, isNonEmptyString) &&
    // Density LAST among the array predicates: `permissions` carries no count
    // ceiling, and `isDenseAuthorityArray` allocates one string per index, so
    // a scan that walks the supplied length may never precede the cheap
    // per-item rejection that already refuses hostile arrays in O(1).
    isDenseAuthorityArray(permissions) &&
    (scope === null || authorityScopeOrNull(scope) !== null)
  )
}

function validAuthorizationShape(document: unknown): document is Record<string, unknown> {
  if (!isPlainObject(document) || !hasExactMembers(document, AUTHORIZATION_MEMBERS)) return false
  const version = document['authorization_version']
  // The value predicate remains shared with §20.3's hand-written view member.
  // Signed wire documents have the stricter strict-JCS representation boundary:
  // a JSON integer reaches this port as bigint, never as number.
  if (typeof version !== 'bigint' || !isAuthorizationVersion(version)) return false
  if (!isDnsName(document['publisher'])) return false

  const entries = document['authorized_issuers']
  // COUNT first, SHAPE second. §20.2 refuses an oversized document "on its
  // count first" and §20.3 makes the ceiling precede every cost that scales
  // with the supplied length; `isDenseAuthorityArray` is O(n) in time AND
  // allocation, so running it first would make the ceiling decorative.
  if (!Array.isArray(entries) || entries.length > MAX_AUTHORIZED_ISSUERS) return false
  if (!isDenseAuthorityArray(entries)) return false
  for (const entry of entries) {
    if (!validEntryShape(entry)) return false
  }
  const issuerIds = entries.map((entry) => (entry as Record<string, unknown>)['issuer_id'])
  if (!sortedUnique(issuerIds, isDnsName)) return false

  return validStage3UtcTimestamp(document['issued_at']) && isPlainObject(document['signature'])
}

/** SHA-256(JCS(document)), 64 lowercase hex, over the entire signed document,
 * including its own `signature` member. */
export function authorizationHash(document: JsonObject): string {
  return bytesToHex(sha256(canonicalBytes(document)))
}

/** Verify a publisher authorization's own signature against an already
 * self-verified key manifest. Authentication only; publisher-domain binding
 * belongs to section 20.4 evaluation. Fails closed and never throws. */
export function verifyAuthorizationSignature(document: unknown, keyManifest: JsonObject): boolean {
  try {
    if (!validAuthorizationShape(document)) return false
    return verifySignedDocument(document, keyManifest, 'issued_at')
  } catch {
    return false
  }
}

/** Verify a publisher authorization manifest against a self-consistent key
 * manifest, using the same active-key/window/hybrid AND-rule as its sibling
 * side-documents. Fails closed and never throws. */
export function verifyAuthorization(document: unknown, keyManifest: JsonObject): boolean {
  try {
    if (!validAuthorizationShape(document)) return false
    return verifyKeyManifest(keyManifest) && verifyAuthorizationSignature(document, keyManifest)
  } catch {
    return false
  }
}

/** Return the unique entry for `issuerId`, or null. If duplicates are present
 * in a malformed document, return null rather than letting array order decide. */
export function entryForIssuer(document: unknown, issuerId: unknown): Record<string, unknown> | null {
  try {
    if (!isPlainObject(document) || typeof issuerId !== 'string') return null
    // OWN members only, mirroring authority.py's `dict.get(document, k)`: an
    // inherited `authorized_issuers` is not evidence the caller supplied, and
    // reading one is a place the two implementations answer differently.
    const own = (o: object, k: string): unknown =>
      Object.prototype.hasOwnProperty.call(o, k) ? (o as Record<string, unknown>)[k] : undefined
    const entries = own(document, 'authorized_issuers')
    if (!Array.isArray(entries)) return null
    const matches = entries.filter((entry) => isPlainObject(entry) && own(entry, 'issuer_id') === issuerId)
    return matches.length === 1 ? (matches[0] as Record<string, unknown>) : null
  } catch {
    return null
  }
}

function withinEntryWindow(issuedAt: string, entry: Record<string, unknown>): boolean {
  const issued = parseStrictUtc(issuedAt)
  const validFrom = parseStrictUtc(entry['valid_from'])
  if (issued === null || validFrom === null || issued < validFrom) return false
  const validTo = entry['valid_to']
  if (validTo === null) return true
  const to = parseStrictUtc(validTo)
  return to !== null && issued <= to
}

/** Whether one authorized_issuers entry authorizes this receipt: issuer match,
 * inclusive receipt-time window, `issue` permission, and null-or-covering
 * scope. The entry's closed shape is checked first because this public
 * primitive may be called directly on hostile evidence. */
export function entryAuthorizesReceipt(entry: unknown, payload: unknown): boolean {
  try {
    if (!validEntryShape(entry) || !isPlainObject(payload)) return false
    const issuer = payload['issuer']
    if (!isPlainObject(issuer) || issuer['id'] !== entry['issuer_id']) return false
    const issuedAt = payload['issued_at']
    if (typeof issuedAt !== 'string' || !withinEntryWindow(issuedAt, entry)) return false
    const permissions = entry['permissions']
    if (!Array.isArray(permissions) || !permissions.includes(PERMISSION_ISSUE)) return false
    const scope = entry['scope']
    if (scope === null) return true
    return grantCoversReceipt({ scope }, payload)
  } catch {
    return false
  }
}

/** Count-only ceiling for caller-supplied authority documents. It never
 * indexes, hashes, compares, or otherwise inspects an element. */
export function withinStructuralCeiling(authorizations: unknown): boolean {
  try {
    return withinCeiling(authorizations, MAX_AUTHORITY_DOCUMENTS)
  } catch {
    return false
  }
}


// --- §20.2 window predicates -------------------------------------------------

/** Parse a wire timestamp or THROW, mirroring the Python core's
 * `transfer._parse_date` inside these two predicates. Returning null instead
 * would look gentler and be worse: the caller would have to invent a meaning
 * for "unparseable", and the two cores would then answer differently on the
 * same document. The precondition below is what makes throwing correct. */
function instantOrThrow(value: string): number {
  const parsed = parseStrictUtc(value)
  if (parsed === null) throw new Error('window endpoint is not a wire timestamp')
  return parsed
}

/**
 * Whether two optional window endpoints denote the same instant (§20.2).
 *
 * Two nulls are equal; a null and a timestamp are not. Non-null endpoints are
 * parsed before comparison so carry checks and ordering checks use one
 * spelling of an instant.
 *
 * PRECONDITION, identical to the Python core's: a non-null endpoint that is not
 * a well-formed wire timestamp THROWS. This is deliberately NOT a never-raise
 * surface — §20.4 step 7 may call it only on documents ALREADY ADMITTED, whose
 * endpoints the shape check has proven parseable. Reaching it from anything
 * less breaks "hostile content inside a well-shaped view never raises".
 */
export function sameInstant(left: string | null, right: string | null): boolean {
  if (left === null || right === null) return left === null && right === null
  return instantOrThrow(left) === instantOrThrow(right)
}

/**
 * Classify an entry window relative to `instant` (§20.2): spent when `valid_to`
 * is non-null and strictly earlier, live otherwise.
 *
 * PRECONDITION: as `sameInstant`.
 */
export function windowSpentAt(validTo: string | null, instant: string): boolean {
  if (validTo === null) return false
  return instantOrThrow(validTo) < instantOrThrow(instant)
}

// --- §20.4: the publisher-authority evaluation -------------------------------

export const AUTHORITY_NOT_CHECKED = 'not_checked'
export const AUTHORITY_NO_CLAIM = 'no_publisher_claim'
export const AUTHORITY_SELF = 'self'
export const AUTHORITY_AUTHORIZED = 'authorized'
export const AUTHORITY_UNAUTHORIZED = 'unauthorized'
export const AUTHORITY_UNATTESTED = 'unattested'
export const AUTHORITY_TRUST_SIGNER_MISMATCH = 'signer_mismatch'

export interface AuthorityVerdict {
  publisher_authority: string
  publisher_authority_trust: string
  warnings: string[]
}

/**
 * The two members §20.3 enumerates, reconstructed (§18.4).
 *
 * `authorizations` is admitted PER ELEMENT under its count ceiling;
 * `current_authorization_version` as a single value. A member the rail does not
 * define is never read, and cannot refuse the view or another member.
 */
function admitAuthorityView(authorityView: object): Record<string, unknown> {
  const reconstructed: Record<string, unknown> = {}
  const authorizations = ownViewMember(authorityView, 'authorizations')
  if (authorizations !== VIEW_MEMBER_ABSENT) {
    const admitted = materializeArray(authorizations, MAX_AUTHORITY_DOCUMENTS)
    if (admitted !== null) reconstructed['authorizations'] = admitted
  }
  const assertion = ownViewMember(authorityView, 'current_authorization_version')
  if (assertion !== VIEW_MEMBER_ABSENT) {
    // This member, and ONLY this member, takes a safe-integer `number` as the
    // integer it denotes. It is the caller's own assertion about what it
    // believes is current -- written by hand, in a language whose JSON has no
    // bigint literal -- while `authorizations` carries SIGNED WIRE DOCUMENTS
    // whose shape check requires `bigint` precisely because a number there
    // could never have come off the wire. §18.4 states the rule this
    // implements: "safe-integer number and bigint inputs normalize to one
    // canonical integer value before equality".
    const admitted = materializeValue(assertion, VIEW_MEMBER_NESTING, {
      acceptSafeIntegerNumbers: true,
    })
    if (admitted !== null) reconstructed['current_authorization_version'] = admitted
  }
  return reconstructed
}

/**
 * One canonical integer value for either representation of a version.
 *
 * The predicate above accepts a `bigint` and a safe-integer `number` alike, so
 * an equality that did not normalize first would answer `false` for two
 * spellings of the SAME number — and it would do so exactly at the comparison
 * that decides whether a denial holds (`unauthorized`) or softens to doubt
 * (`unattested`), which is the one place a silent divergence is worth the most
 * to an attacker.
 */
function versionValue(value: unknown): bigint | null {
  if (typeof value === 'bigint') return value
  if (typeof value === 'number' && Number.isInteger(value)) return BigInt(value)
  return null
}

/** `authorizationHash` behind a fail-closed boundary: a document that cannot be
 * canonicalized is one the verifier cannot read, which is the strongest
 * authentication failure there is, and it must not raise out of here. */
function authorizationHashOrNull(candidate: unknown, warnings: string[]): string | null {
  try {
    return authorizationHash(candidate as JsonObject)
  } catch {
    appendWarningOnce(warnings, AUTHORITY_WARN.INVALID_IGNORED)
    return null
  }
}

function appendWarningOnce(warnings: string[], warning: string): void {
  if (!warnings.includes(warning)) warnings.push(warning)
}

function memberEquals(document: unknown, member: string, expected: unknown): boolean {
  try {
    return isPlainObject(document) && document[member] === expected
  } catch {
    return false
  }
}

/** Step 6: authenticate each candidate against the verifier's OWN trust store,
 * deduplicating by document hash BEFORE any shape work, so a view padded with
 * copies of one document costs one verification and not one per copy. */
function admittedAuthorizations(
  authorizations: unknown[],
  trustStore: TrustStore,
  publisherId: string,
  authorityTrust: string,
  warnings: string[],
): [Map<string, Record<string, unknown>>, string] {
  const admitted = new Map<string, Record<string, unknown>>()
  const seenHashes = new Set<string>()
  let trust = authorityTrust
  for (const candidate of authorizations) {
    const documentHash = authorizationHashOrNull(candidate, warnings)
    if (documentHash === null || seenHashes.has(documentHash)) continue
    seenHashes.add(documentHash)

    if (!isPlainObject(candidate)) {
      appendWarningOnce(warnings, AUTHORITY_WARN.INVALID_IGNORED)
      continue
    }
    const signer = signerDomain(candidate)
    const manifest = typeof signer === 'string' ? trustStore.manifests[signer] : undefined
    if (manifest === undefined || !verifyAuthorization(candidate, manifest)) {
      appendWarningOnce(warnings, AUTHORITY_WARN.INVALID_IGNORED)
      continue
    }
    if (!memberEquals(manifest, 'issuer', signer) || !memberEquals(candidate, 'publisher', publisherId)) {
      appendWarningOnce(warnings, AUTHORITY_WARN.INVALID_IGNORED)
      continue
    }
    // A document signed by SOMEONE ELSE for this publisher authenticates but
    // says nothing the publisher said: it is set aside, and the trust component
    // records that the rail carried one.
    if (signer !== publisherId) {
      appendWarningOnce(warnings, AUTHORITY_WARN.SIGNER_NOT_PUBLISHER)
      trust = AUTHORITY_TRUST_SIGNER_MISMATCH
      continue
    }
    admitted.set(documentHash, candidate)
  }
  return [admitted, trust]
}

function entriesByIssuer(document: Record<string, unknown>): Map<unknown, Record<string, unknown>> {
  const entries = document['authorized_issuers'] as Record<string, unknown>[]
  const byIssuer = new Map<unknown, Record<string, unknown>>()
  for (const entry of entries) byIssuer.set(entry['issuer_id'], entry)
  return byIssuer
}

function windowShortens(previousValidTo: unknown, validTo: unknown): boolean {
  if (validTo === null) return false
  if (previousValidTo === null) return true
  const later = parseStrictUtc(validTo as string)
  const earlier = parseStrictUtc(previousValidTo as string)
  if (later === null || earlier === null) return true
  return later < earlier
}

function restrictionOutsideBounds(
  predecessorIssuedAt: string,
  successorIssuedAt: string,
  validTo: string,
): boolean {
  const endpoint = parseStrictUtc(validTo)
  const lower = parseStrictUtc(predecessorIssuedAt)
  const upper = parseStrictUtc(successorIssuedAt)
  if (endpoint === null || lower === null || upper === null) return true
  return endpoint < lower || endpoint > upper
}

/** §20.4 step 7's successor discipline, as a CLOSED enumeration: a successor
 * that drops an issuer the predecessor carried, moves a window's start, lets a
 * spent window reopen, or shortens a live window to an endpoint outside
 * [predecessor issued_at, successor issued_at] is not a conforming successor.
 * Any read that raises is itself a break -- fail closed. */
function breaksSuccessorDiscipline(
  predecessor: Record<string, unknown>,
  successor: Record<string, unknown>,
): boolean {
  try {
    const successorEntries = entriesByIssuer(successor)
    const successorIssuedAt = successor['issued_at'] as string
    const predecessorIssuedAt = predecessor['issued_at'] as string
    for (const predecessorEntry of predecessor['authorized_issuers'] as Record<string, unknown>[]) {
      const issuerId = predecessorEntry['issuer_id']
      const successorEntry = successorEntries.get(issuerId)
      if (successorEntry === undefined) return true
      if (successorEntry['valid_from'] !== predecessorEntry['valid_from']) return true

      const predecessorValidTo = predecessorEntry['valid_to']
      const validTo = successorEntry['valid_to']
      if (windowSpentAt(predecessorValidTo as string | null, successorIssuedAt)) {
        if (!sameInstant(predecessorValidTo as string | null, validTo as string | null)) return true
        continue
      }

      if (
        windowShortens(predecessorValidTo, validTo)
        && validTo !== null
        && restrictionOutsideBounds(predecessorIssuedAt, successorIssuedAt, validTo as string)
      ) {
        return true
      }
    }
  } catch {
    return true
  }
  return false
}

/** Steps 7 and 8: equivocation, then the successor discipline, then the highest
 * surviving version. Two admitted documents at the SAME version are the
 * publisher signing two incompatible statements, which no later step can
 * reconcile -- that whole version is dropped and the trust component records it. */
function effectiveAuthorization(
  admitted: Map<string, Record<string, unknown>>,
  authorityTrust: string,
): [Record<string, unknown> | null, string] {
  let trust = authorityTrust
  const byVersion = new Map<bigint, number>()
  for (const document of admitted.values()) {
    const version = versionValue(document['authorization_version'])
    if (version === null) continue
    byVersion.set(version, (byVersion.get(version) ?? 0) + 1)
  }

  const equivocating = new Set<bigint>()
  for (const [version, count] of byVersion) if (count > 1) equivocating.add(version)
  if (equivocating.size > 0) trust = GRANT_TRUST_UNVERIFIED_ROTATION

  const survivors = new Map<string, Record<string, unknown>>()
  for (const [documentHash, document] of admitted) {
    const version = versionValue(document['authorization_version'])
    if (version === null || equivocating.has(version)) continue
    survivors.set(documentHash, document)
  }

  const excluded = new Set<string>()
  for (const [predecessorHash, predecessor] of survivors) {
    const predecessorVersion = versionValue(predecessor['authorization_version'])
    if (predecessorVersion === null) continue
    for (const [successorHash, successor] of survivors) {
      if (predecessorHash === successorHash) continue
      const successorVersion = versionValue(successor['authorization_version'])
      if (successorVersion === null || predecessorVersion >= successorVersion) continue
      if (breaksSuccessorDiscipline(predecessor, successor)) excluded.add(successorHash)
    }
  }
  if (excluded.size > 0) trust = GRANT_TRUST_UNVERIFIED_ROTATION

  let effective: Record<string, unknown> | null = null
  let effectiveVersion: bigint | null = null
  for (const [documentHash, document] of survivors) {
    if (excluded.has(documentHash)) continue
    const version = versionValue(document['authorization_version'])
    if (version === null) continue
    if (effectiveVersion === null || version > effectiveVersion) {
      effective = document
      effectiveVersion = version
    }
  }
  return [effective, trust]
}

/**
 * §20.4's deterministic, short-circuiting evaluation order.
 *
 * The component is INFORMATIONAL: it never touches `ok`, `signature`, `schema`,
 * `revocation`, `binding` or `trust`. Its failure asymmetry runs the other way
 * from the grant rail's -- a false `authorized` would launder an unauthorized
 * seller, so every missing, unverifiable, malformed or ambiguous input resolves
 * to `unattested`, the verdict that asserts nothing.
 */
export function evaluateAuthority(
  payload: unknown,
  trustStore: TrustStore,
  authorityView: unknown,
): AuthorityVerdict {
  if (authorityView != null && !isPlainObject(authorityView)) {
    throw new TypeError('authority_view must be an evidence object or None')
  }
  const warnings: string[] = []
  const verdict = (authority: string, trust: string): AuthorityVerdict => ({
    publisher_authority: authority,
    publisher_authority_trust: trust,
    warnings,
  })
  if (authorityView == null) return verdict(AUTHORITY_NOT_CHECKED, AUTHORITY_NOT_CHECKED)
  // Admitted ONCE, before any member is read; every step below reads the
  // reconstruction and never the caller's object again.
  const view = admitAuthorityView(authorityView)

  // --- Step 1: no claim to attest.
  const work = isPlainObject(payload) ? payload['work'] : null
  const publisherId = isPlainObject(work) ? work['publisher_id'] : null
  if (typeof publisherId !== 'string') return verdict(AUTHORITY_NO_CLAIM, AUTHORITY_NOT_CHECKED)

  // --- Step 2.
  const issuer = isPlainObject(payload) ? payload['issuer'] : null
  const issuerId = isPlainObject(issuer) ? issuer['id'] : null
  if (typeof issuerId !== 'string') return verdict(AUTHORITY_UNATTESTED, AUTHORITY_NOT_CHECKED)

  // --- Step 3: the seller IS the publisher; no third party is involved.
  if (publisherId === issuerId) return verdict(AUTHORITY_SELF, AUTHORITY_NOT_CHECKED)

  // --- Step 4: the channel is the opt-in, and an empty or oversized one
  // carries nothing. The ceiling runs BEFORE any signature is verified.
  const authorizations = view['authorizations']
  if (!Array.isArray(authorizations)) return verdict(AUTHORITY_UNATTESTED, AUTHORITY_NOT_CHECKED)
  if (!withinStructuralCeiling(authorizations)) return verdict(AUTHORITY_UNATTESTED, AUTHORITY_NOT_CHECKED)
  if (authorizations.length === 0) return verdict(AUTHORITY_UNATTESTED, AUTHORITY_NOT_CHECKED)

  // --- Step 5: the ladder is keyed to the RECEIPT's publisher claim, never to
  // a domain named by a supplied document's kid -- those are still
  // attacker-supplied bytes here, and keying on them would let a blob that
  // authenticates against nothing pick any domain the verifier happens to know.
  let authorityTrust = grantTrustLadder(trustStore, publisherId, trustStore.manifests[publisherId])

  // --- Step 6.
  let admitted: Map<string, Record<string, unknown>>
  ;[admitted, authorityTrust] = admittedAuthorizations(
    authorizations, trustStore, publisherId, authorityTrust, warnings,
  )

  // --- Steps 7 and 8.
  let effective: Record<string, unknown> | null
  ;[effective, authorityTrust] = effectiveAuthorization(admitted, authorityTrust)
  if (effective === null) return verdict(AUTHORITY_UNATTESTED, authorityTrust)

  // --- Step 9: does the effective document authorize THIS issuer for THIS
  // receipt, in the window the receipt was issued in?
  const entry = entryForIssuer(effective, issuerId)
  if (entry !== null && entryAuthorizesReceipt(entry, payload)) {
    return verdict(AUTHORITY_AUTHORIZED, authorityTrust)
  }

  // --- Step 10: a DENIAL only holds if the caller asserts the version it was
  // read from is current. Both representations of that integer normalize first:
  // `5n === 5` is false, and a denial that softened to doubt over a spelling
  // would be the quietest failure this rail has.
  const assertion = view['current_authorization_version']
  const asserted = isAuthorizationVersion(assertion) ? versionValue(assertion) : null
  if (asserted !== null && asserted === versionValue(effective['authorization_version'])) {
    warnings.push(AUTHORITY_WARN.PUBLISHER_NOT_AUTHORIZING_ISSUER)
    return verdict(AUTHORITY_UNAUTHORIZED, authorityTrust)
  }
  return verdict(AUTHORITY_UNATTESTED, authorityTrust)
}
