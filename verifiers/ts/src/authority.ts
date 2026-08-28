// Publisher authorization manifests -- may this seller sell? (v0.2 section 20).
// Mirrors src/attest/authority.py, verification side only. The Python builder
// has no TypeScript counterpart, matching grant.ts and transfer.ts.
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import type { JsonObject } from './canon.js'
import { canonicalBytes } from './canon.js'
import { validStage3UtcTimestamp, parseStrictUtc } from './dates.js'
import {
  MAX_JCS_INTEGER,
  grantCoversReceipt,
  hasExactMembers,
  isDnsName,
  isNonEmptyString,
  isPlainObject,
  scopeOrNull,
  sortedUnique,
  verifySignedDocument,
  withinCeiling,
} from './grant.js'
import { verifyKeyManifest } from './manifests.js'

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
