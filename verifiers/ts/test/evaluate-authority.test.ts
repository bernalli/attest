import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { canonicalBytes } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import {
  evaluateAuthority,
  AUTHORITY_NOT_CHECKED,
  AUTHORITY_NO_CLAIM,
  AUTHORITY_SELF,
  AUTHORITY_AUTHORIZED,
  AUTHORITY_UNAUTHORIZED,
  AUTHORITY_UNATTESTED,
  AUTHORITY_TRUST_SIGNER_MISMATCH,
  MAX_AUTHORITY_DOCUMENTS,
} from '../src/authority.js'
import { AUTHORITY_WARN } from '../src/messages.js'
import type { TrustStore } from '../src/manifests.js'
import { parse, hybridSigner, signBlock, keyEntry, buildKeyManifest } from './helpers/grant-builder.js'
import type { TestSigner } from './helpers/grant-builder.js'

const enc = (s: string) => new TextEncoder().encode(s)
const hex = (s: string) => bytesToHex(sha256(enc(s)))

const ISSUER = 'store.example.com'
const OTHER_ISSUER = 'marketplace.example'
const PUBLISHER = 'pub.example'
const OUTSIDER = 'stranger.example'

const PUB_KID = `${PUBLISHER}/keys/authority#1`
const OUTSIDER_KID = `${OUTSIDER}/keys/authority#1`

const VALID_FROM = '2026-01-01T00:00:00Z'
const RECEIPT_ISSUED_AT = '2026-07-02T14:30:00Z'
const AUTH_ISSUED_AT = '2026-02-01T00:00:00Z'
const LATER_ISSUED_AT = '2026-03-01T00:00:00Z'
const ARTIFACT = hex('attest-authority-test-artifact')

const PUB_KEYS = hybridSigner(51)
const OUTSIDER_KEYS = hybridSigner(52)

function manifestOf(issuer: string, kid: string, signer: TestSigner): JsonObject {
  return buildKeyManifest(issuer, 1, VALID_FROM, [keyEntry(kid, signer, VALID_FROM)], signer, kid)
}

const PUB_MANIFEST = manifestOf(PUBLISHER, PUB_KID, PUB_KEYS)
const OUTSIDER_MANIFEST = manifestOf(OUTSIDER, OUTSIDER_KID, OUTSIDER_KEYS)

function scope(): Record<string, unknown> {
  return { artifact_series: 'series-1', artifacts: [ARTIFACT] }
}

function entry(
  issuerId: string = ISSUER,
  validFrom: string = VALID_FROM,
  validTo: string | null = null,
): Record<string, unknown> {
  return {
    issuer_id: issuerId,
    valid_from: validFrom,
    valid_to: validTo,
    permissions: ['issue'],
    scope: scope(),
  }
}

/** A publisher-signed authorization manifest (§20.2), five members. Like the
 * grant builder, it does NOT validate the body it signs: building a
 * deliberately malformed document is how the verification side gets tested. */
function buildAuthorization(
  version: number,
  entries: Record<string, unknown>[] = [entry()],
  issuedAt: string = AUTH_ISSUED_AT,
  signer: TestSigner = PUB_KEYS,
  kid: string = PUB_KID,
  publisher: string = PUBLISHER,
): JsonObject {
  const body = {
    authorization_version: version,
    publisher,
    authorized_issuers: entries,
    issued_at: issuedAt,
  }
  return parse({ ...body, signature: signBlock(canonicalBytes(parse(body)), signer, kid) })
}

function trustStoreOf(
  manifests: Record<string, JsonObject> = { [PUBLISHER]: PUB_MANIFEST },
  provenance: Record<string, string> = { [PUBLISHER]: 'tls' },
): TrustStore {
  return { manifests, provenance, chains: {} }
}

function receipt(publisherId: string | null = PUBLISHER, issuerId: string = ISSUER): unknown {
  const work: Record<string, unknown> = {
    title: 'Example Work',
    artifact_series: 'series-1',
    identifiers: { issuer_sku: 'SKU-1' },
    artifact_sha256: ARTIFACT,
  }
  if (publisherId !== null) work['publisher_id'] = publisherId
  return { issued_at: RECEIPT_ISSUED_AT, issuer: { id: issuerId }, work }
}

function viewOf(
  authorizations: unknown,
  currentVersion?: unknown,
): Record<string, unknown> {
  const view: Record<string, unknown> = { authorizations }
  if (currentVersion !== undefined) view['current_authorization_version'] = currentVersion
  return view
}

// --- §20.4's ordered steps ---------------------------------------------------

describe('evaluateAuthority — §20.4 evaluation order', () => {
  it('RESTRICTIVE: no channel is no evaluation, not a denial', () => {
    const verdict = evaluateAuthority(receipt(), trustStoreOf(), null)

    expect(verdict.publisher_authority).toBe(AUTHORITY_NOT_CHECKED)
    expect(verdict.publisher_authority_trust).toBe(AUTHORITY_NOT_CHECKED)
    expect(verdict.warnings).toEqual([])
  })

  it('step 1: a receipt claiming no publisher has nothing to attest', () => {
    const verdict = evaluateAuthority(receipt(null), trustStoreOf(), viewOf([buildAuthorization(1)]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_NO_CLAIM)
  })

  it('step 3: a seller who IS the publisher needs no third party', () => {
    const verdict = evaluateAuthority(
      receipt(PUBLISHER, PUBLISHER), trustStoreOf(), viewOf([buildAuthorization(1)]),
    )

    expect(verdict.publisher_authority).toBe(AUTHORITY_SELF)
  })

  it('step 4: an empty channel carries nothing', () => {
    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
  })

  it('step 9: an authorization the publisher signed for this issuer authorizes it', () => {
    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([buildAuthorization(1)]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
    expect(verdict.publisher_authority_trust).toBe('verified')
    expect(verdict.warnings).toEqual([])
  })

  it('PERMISSIVE: an authorization naming a DIFFERENT issuer does not authorize this one', () => {
    const verdict = evaluateAuthority(
      receipt(), trustStoreOf(), viewOf([buildAuthorization(1, [entry(OTHER_ISSUER)])]),
    )

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
  })

  it('step 9 short-circuits step 10: an authorized issuer is never reported unauthorized', () => {
    // The assertion says "version 1 is current" AND version 1 authorizes this
    // issuer. Reaching step 10 would turn an authorization into a denial.
    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([buildAuthorization(1)], 1n))

    expect(verdict.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
    expect(verdict.warnings).toEqual([])
  })
})

// --- step 10: the denial, and what it costs to earn it -----------------------

describe('evaluateAuthority — step 10, the asserted denial', () => {
  it('a denial holds only when the caller asserts the effective version is current', () => {
    const document = buildAuthorization(1, [entry(OTHER_ISSUER)])

    const asserted = evaluateAuthority(receipt(), trustStoreOf(), viewOf([document], 1n))
    const unasserted = evaluateAuthority(receipt(), trustStoreOf(), viewOf([document]))

    expect(asserted.publisher_authority).toBe(AUTHORITY_UNAUTHORIZED)
    expect(asserted.warnings).toContain(AUTHORITY_WARN.PUBLISHER_NOT_AUTHORIZING_ISSUER)
    // Without the assertion the same evidence buys only doubt: a stale
    // document withheld from the view must not read as a denial.
    expect(unasserted.publisher_authority).toBe(AUTHORITY_UNATTESTED)
    expect(unasserted.warnings).toEqual([])
  })

  it('an assertion for a DIFFERENT version softens the denial to doubt', () => {
    const verdict = evaluateAuthority(
      receipt(), trustStoreOf(), viewOf([buildAuthorization(1, [entry(OTHER_ISSUER)])], 2n),
    )

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
  })

  it('a hand-written assertion reaches the same denial as a strict-parsed one', () => {
    // §20's representation trap: `5n === 5` is false, and this is the single
    // comparison that decides whether a denial holds or softens to doubt. A
    // caller writing the view by hand has no bigint literal to write.
    const document = buildAuthorization(1, [entry(OTHER_ISSUER)])

    const parsed = evaluateAuthority(receipt(), trustStoreOf(), viewOf([document], 1n))
    const handWritten = evaluateAuthority(receipt(), trustStoreOf(), viewOf([document], 1))

    expect(typeof document['authorization_version']).toBe('bigint')
    expect(handWritten.publisher_authority).toBe(AUTHORITY_UNAUTHORIZED)
    expect(handWritten).toEqual(parsed)
  })

  it('RESTRICTIVE: a malformed assertion is an absent one, never a denial', () => {
    for (const bad of [true, '1', 1.5, null, -1n, 0n]) {
      const verdict = evaluateAuthority(
        receipt(), trustStoreOf(), viewOf([buildAuthorization(1, [entry(OTHER_ISSUER)])], bad),
      )

      expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
    }
  })
})

// --- step 6: what authenticates, and what merely looks like it ---------------

describe('evaluateAuthority — step 6, admission and authentication', () => {
  it('PERMISSIVE: a document signed by someone else for this publisher never authorizes', () => {
    const forged = buildAuthorization(1, [entry()], AUTH_ISSUED_AT, OUTSIDER_KEYS, OUTSIDER_KID)
    const store = trustStoreOf(
      { [PUBLISHER]: PUB_MANIFEST, [OUTSIDER]: OUTSIDER_MANIFEST },
      { [PUBLISHER]: 'tls', [OUTSIDER]: 'tls' },
    )

    const verdict = evaluateAuthority(receipt(), store, viewOf([forged]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
    expect(verdict.publisher_authority_trust).toBe(AUTHORITY_TRUST_SIGNER_MISMATCH)
    expect(verdict.warnings).toContain(AUTHORITY_WARN.SIGNER_NOT_PUBLISHER)
  })

  it('an unauthenticated document is ignored and its genuine sibling still governs', () => {
    const tampered = buildAuthorization(2) as Record<string, unknown>
    tampered['issued_at'] = LATER_ISSUED_AT // signed bytes no longer match

    const withJunk = evaluateAuthority(
      receipt(), trustStoreOf(), viewOf([tampered, buildAuthorization(1)]),
    )
    const alone = evaluateAuthority(receipt(), trustStoreOf(), viewOf([buildAuthorization(1)]))

    // Bilateral: the junk is set aside AND the genuine document reaches the
    // verdict it would have reached on its own.
    expect(withJunk.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
    expect(withJunk.publisher_authority_trust).toBe(alone.publisher_authority_trust)
    expect(withJunk.warnings).toContain(AUTHORITY_WARN.INVALID_IGNORED)
  })

  it('a view padded with copies of one document costs one verification, not one per copy', () => {
    const document = buildAuthorization(1)

    const verdict = evaluateAuthority(
      receipt(), trustStoreOf(), viewOf(Array.from({ length: 32 }, () => document)),
    )

    expect(verdict.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
  })
})

// --- steps 7 and 8: equivocation and the successor discipline ----------------

describe('evaluateAuthority — steps 7 and 8', () => {
  it('PERMISSIVE: two admitted documents at the same version cancel that version', () => {
    // The publisher signing two incompatible statements at one version is
    // something no later step can reconcile. Both are dropped, and the trust
    // component records that the rail equivocated.
    const first = buildAuthorization(1)
    const second = buildAuthorization(1, [entry(OTHER_ISSUER)])

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([first, second]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
    expect(verdict.publisher_authority_trust).toBe('unverified_rotation')
  })

  it('the highest surviving version governs', () => {
    // The successor PRESERVES the predecessor's entry and adds one: dropping
    // the old one would break the discipline and exclude the successor, which
    // is a different property tested below.
    const older = buildAuthorization(1, [entry(OTHER_ISSUER)])
    const newer = buildAuthorization(2, [entry(OTHER_ISSUER), entry()], LATER_ISSUED_AT)

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([older, newer]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
  })

  it('PERMISSIVE: a successor that DROPS an issuer the predecessor carried is excluded', () => {
    const predecessor = buildAuthorization(1, [entry(OTHER_ISSUER), entry()])
    const successor = buildAuthorization(2, [entry(OTHER_ISSUER)], LATER_ISSUED_AT)

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([predecessor, successor]))

    // The predecessor still governs, so the issuer it authorized stays
    // authorized: a non-conforming successor cannot silently revoke.
    expect(verdict.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
    expect(verdict.publisher_authority_trust).toBe('unverified_rotation')
  })

  it('PERMISSIVE: a successor that MOVES a window start is excluded', () => {
    const predecessor = buildAuthorization(1, [entry()])
    const successor = buildAuthorization(2, [entry(ISSUER, '2026-02-15T00:00:00Z')], LATER_ISSUED_AT)

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([predecessor, successor]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
    expect(verdict.publisher_authority_trust).toBe('unverified_rotation')
  })

  it('a successor closing a live window WITHIN bounds is conforming and governs', () => {
    // Closing at an instant between the predecessor's issued_at and the
    // successor's own is the legitimate way to stop authorizing a seller.
    const predecessor = buildAuthorization(1, [entry()])
    const successor = buildAuthorization(
      2, [entry(ISSUER, VALID_FROM, '2026-02-15T00:00:00Z')], LATER_ISSUED_AT,
    )

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([predecessor, successor]))

    // The receipt was issued after the window closed, so it is no longer
    // covered — and the successor was NOT excluded, which is the point.
    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
    expect(verdict.publisher_authority_trust).toBe('verified')
  })

  it('PERMISSIVE: a successor post-dating a closure past its own issued_at is excluded', () => {
    const predecessor = buildAuthorization(1, [entry()])
    const successor = buildAuthorization(
      2, [entry(ISSUER, VALID_FROM, '2027-01-01T00:00:00Z')], LATER_ISSUED_AT,
    )

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf([predecessor, successor]))

    expect(verdict.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
    expect(verdict.publisher_authority_trust).toBe('unverified_rotation')
  })
})

// --- §18.4's admission boundary, on this rail --------------------------------

describe('evaluateAuthority — the admission boundary (§18.4)', () => {
  it('the container shape is caller contract and raises; content never does', () => {
    expect(() => evaluateAuthority(receipt(), trustStoreOf(), [])).toThrow(TypeError)
  })

  it('an authorizations getter is not own data and attests nothing', () => {
    const view: Record<string, unknown> = {}
    Object.defineProperty(view, 'authorizations', {
      enumerable: true,
      get() { return [buildAuthorization(1)] },
    })

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), view)

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
  })

  it('an authorizations member on the prototype chain is not own data', () => {
    const view = Object.create({ authorizations: [buildAuthorization(1)] }) as Record<string, unknown>

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), view)

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
  })

  it('a member that throws when read is absent data, not an exception out of the surface', () => {
    const view: Record<string, unknown> = {}
    Object.defineProperty(view, 'authorizations', {
      enumerable: true,
      get() { throw new Error('the boundary must never run this') },
    })

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), view)

    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
  })

  it('an inadmissible element is set aside alone and the genuine one still authorizes', () => {
    const hostile: Record<string, unknown> = {}
    Object.defineProperty(hostile, 'authorization_version', {
      enumerable: true,
      get() { throw new Error('the boundary must never run this') },
    })

    const withHostile = evaluateAuthority(
      receipt(), trustStoreOf(), viewOf([hostile, buildAuthorization(1)]),
    )
    const alone = evaluateAuthority(receipt(), trustStoreOf(), viewOf([buildAuthorization(1)]))

    expect(withHostile.publisher_authority).toBe(AUTHORITY_AUTHORIZED)
    expect(withHostile.publisher_authority_trust).toBe(alone.publisher_authority_trust)
  })

  it('an unbounded container returns within a wall-clock bound and spares its sibling', () => {
    const unbounded: unknown[] = []
    Object.defineProperty(unbounded, 'length', { value: 1_000_000_000, writable: true })
    const started = Date.now()

    const verdict = evaluateAuthority(receipt(), trustStoreOf(), viewOf(unbounded))

    expect(Date.now() - started).toBeLessThan(2000)
    expect(verdict.publisher_authority).toBe(AUTHORITY_UNATTESTED)
  })

  it('the count ceiling is exact, and exceeding it truncates evaluation', () => {
    const document = buildAuthorization(1)
    const atCeiling = Array.from({ length: MAX_AUTHORITY_DOCUMENTS }, () => document)
    const pastIt = Array.from({ length: MAX_AUTHORITY_DOCUMENTS + 1 }, () => document)

    expect(evaluateAuthority(receipt(), trustStoreOf(), viewOf(atCeiling)).publisher_authority)
      .toBe(AUTHORITY_AUTHORIZED)
    expect(evaluateAuthority(receipt(), trustStoreOf(), viewOf(pastIt)).publisher_authority)
      .toBe(AUTHORITY_UNATTESTED)
  })
})
