// Tests for src/grant.ts — Stage 4 preservation-pledge primitives (v0.2 §18).
// Mirrors tests/test_grant.py (Python reference) case-for-case: the sunset
// grant document (§18.2), the cessation declaration (§18.4), the two DISTINCT
// coverage predicates (§18.4), the floor-relative non-narrowing ratchet
// (§18.3), the structural ceilings (§18.4), and the audience-bound redemption
// proof (§18.7). Grant EVALUATION (§18.4's ordered steps, the
// `grant`/`grant_trust` result components) is a separate surface and is not
// exercised here.
//
// grant.ts is verification-side only (design §9: no build/sign here), so the
// Python builders `build_grant`/`build_declaration`/`sign_redemption` live in
// test/helpers/grant-builder.ts as fixture material, hand-signed with
// @noble/curves + @noble/post-quantum — the same idiom transfer.test.ts and
// sibling-hybrid.test.ts already established.
import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalBytes, CanonError } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import * as grantModule from '../src/grant.js'
import {
  MAX_GRANT_DECLARATIONS,
  MAX_GRANT_LATER_VERSIONS,
  LABEL_REDEMPTION_CHALLENGE,
  PERMISSION_DELIVER_TO_HOLDER,
  PERMISSION_REDISTRIBUTE_AMONG_HOLDERS,
  PLEDGE_SUNSET_GRANT_V1,
  KNOWN_PLEDGE_TYPES,
  END_OF_LIFE_SUNSET_GRANT,
  SIGNER_ROLE_PUBLISHER,
  SIGNER_ROLE_SUCCESSOR,
  declarationCoversGrant,
  declarationHash,
  declarationSignerRole,
  grantCoversReceipt,
  grantHash,
  isNonNarrowing,
  proseDiffers,
  redemptionMessage,
  signerDomain,
  verifyDeclaration,
  verifyGrant,
  verifyGrantSignature,
  verifyRedemption,
  withinStructuralCeilings,
} from '../src/grant.js'
import {
  buildDeclaration,
  buildGrant,
  buildKeyManifest,
  edSigner,
  hybridSigner,
  keyEntry,
  parse,
  signRedemption,
  type TestSigner,
} from './helpers/grant-builder.js'

const PUBLISHER = 'pub.example'
const SUCCESSOR = 'heritage.example'
const OTHER = 'marketplace.example'
const PUB_KID = `${PUBLISHER}/keys/grants#1`
const SUCCESSOR_KID = `${SUCCESSOR}/keys/grants#1`
const OTHER_KID = `${OTHER}/keys/grants#1`

const VALID_FROM = '2026-01-01T00:00:00Z'
const MANIFEST_ISSUED_AT = '2026-01-01T00:00:00Z'
const GRANT_ISSUED_AT = '2026-02-01T00:00:00Z'
const DECLARED_AT = '2031-03-01T00:00:00Z'
const FIXED_DATE = '2046-01-01T00:00:00Z'

const SERIES = 'pub.example/works/EXG-001'
const hex = (s: string) => bytesToHex(sha256(new TextEncoder().encode(s)))
const ART_A = hex('artifact-a')
const ART_B = hex('artifact-b')
const ART_C = hex('artifact-c')
// The single artifact hash the reference example payload puts in `work.artifacts`.
const RECEIPT_ART = hex('attest-test-artifact-v1')

const LEGAL_TEXT_SHA256 = hex('attest-test-sunset-grant-prose-v1')
const OTHER_LEGAL_TEXT_SHA256 = hex('attest-test-sunset-grant-prose-v2')

const RECEIPT_ID = '01J1V5B4M9Z8QWERTY12345678'
const AUDIENCE = 'custodian.example'
const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i)

// --- fixtures ----------------------------------------------------------------
//
// TEST ONLY — fixed seeds, never use in production. Python generates a fresh
// keypair per fixture call; a pinned seed per ROLE is the equivalent here (and
// keeps ML-DSA-65 keygen, which is not cheap, off the per-test path).
const PUB_ED = edSigner(10)
const PUB_HYBRID = hybridSigner(11)
const SUCCESSOR_ED = edSigner(12)
const OTHER_ED = edSigner(13)
const ANY_ED = edSigner(14)
const HOLDER_ED = edSigner(15)
const OTHER_HOLDER_ED = edSigner(16)
const STRAY_HYBRID = hybridSigner(17)

function manifestFor(issuer: string, kid: string, signer: TestSigner): JsonObject {
  return buildKeyManifest(issuer, 1, MANIFEST_ISSUED_AT, [keyEntry(kid, signer, VALID_FROM)], signer, kid)
}

function scope(
  artifactSeries: string | null = SERIES,
  artifacts: string[] = [ART_A, ART_B],
): Record<string, unknown> {
  return { artifact_series: artifactSeries, artifacts: [...artifacts].sort() }
}

function activation(
  modes: string[] = ['fixed-date', 'publisher-declaration'],
  fixedDate: string | null = FIXED_DATE,
  successorIds: string[] = [SUCCESSOR],
): Record<string, unknown> {
  return { modes: [...modes].sort(), fixed_date: fixedDate, successor_ids: [...successorIds].sort() }
}

function grantBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    grant_version: 1,
    publisher: PUBLISHER,
    scope: scope(),
    permissions: [PERMISSION_DELIVER_TO_HOLDER],
    activation: activation(),
    unprotected_build: true,
    legal_text_uri: 'https://pub.example/sunset-grant-v1',
    legal_text_sha256: LEGAL_TEXT_SHA256,
    jurisdiction: 'IT',
    issued_at: GRANT_ISSUED_AT,
    ...overrides,
  }
}

function makeGrant(
  signer: TestSigner,
  overrides: Record<string, unknown> = {},
  kid: string = PUB_KID,
): JsonObject {
  return buildGrant(grantBody(overrides), signer, kid)
}

/** A grant body plus a real-but-irrelevant `signature` — for the structural
 * predicates (coverage, ratchet) that never touch the signature. Mirrors
 * test_grant.py's `_unsigned_grant`. */
function unsignedGrant(overrides: Record<string, unknown> = {}): JsonObject {
  return makeGrant(ANY_ED, overrides)
}

// The reference example payload (docs/spec/attest-v0.1.md §3.1), mirroring
// tests/helpers.py's `_base_payload`/`make_payload` — including its deep merge
// of nested-dict overrides, which is how the coverage tests below swap one
// `work` member without dropping the rest of the block.
const COMMITMENT = b64uEncode(new Uint8Array(32))
function basePayload(): Record<string, unknown> {
  return {
    attest_version: '0.1',
    receipt_id: RECEIPT_ID,
    issued_at: '2026-07-02T14:30:00Z',
    supersedes: null,
    issuer: { id: 'store.example.com', display_name: 'Example Games Store' },
    buyer: { commitment: COMMITMENT, identifier_type: 'issuer-account', pubkey: null },
    work: {
      title: 'Example Game',
      publisher: 'Example Publisher srl',
      edition: 'Deluxe',
      identifiers: { issuer_sku: 'EXG-001' },
      artifact_series: 'store.example.com/works/EXG-001',
      artifacts: [
        {
          role: 'installer',
          platform: 'windows-x86_64',
          filename: 'example-game-1.0-setup.exe',
          size_bytes: 734003200,
          sha256: RECEIPT_ART,
        },
      ],
    },
    license: {
      grant: 'perpetual',
      revocability: 'none',
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://store.example.com/attest/license-templates/standard-v1',
      legal_text_sha256: hex('attest-test-legal-text-v1'),
      jurisdiction_flags: { eu_usedsoft_asserted: false },
    },
    survivability: {
      redownload_right: true,
      mirror_policy_uri: 'https://store.example.com/attest/mirror-policy-v1',
      mirror_policy_sha256: hex('attest-test-mirror-policy-v1'),
      end_of_life: 'artifacts-remain-redownloadable',
      eol_commitment_uri: null,
      eol_commitment_sha256: null,
    },
  }
}

function isPlainObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}
function deepMerge(base: Record<string, unknown>, overrides: Record<string, unknown>): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...base }
  for (const [key, value] of Object.entries(overrides)) {
    merged[key] = isPlainObj(value) && isPlainObj(merged[key]) ? deepMerge(merged[key], value) : value
  }
  return merged
}
function makePayload(overrides: Record<string, unknown> = {}): JsonObject {
  return parse(deepMerge(basePayload(), overrides))
}
/** The `work` block of a parsed payload, as a mutable bag — the tests below
 * delete/replace members on it exactly as the Python ones do. */
const workOf = (payload: JsonObject) => payload['work'] as unknown as Record<string, unknown>

// --- grant document: build, hash, roundtrip (§18.2) --------------------------

describe('sunset grant document (v0.2 §18.2)', () => {
  it('has exactly the eleven members', () => {
    const document = makeGrant(PUB_ED)

    expect(new Set(Object.keys(document))).toEqual(
      new Set([
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
      ]),
    )
  })

  it('round-trips a classical grant', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED)

    expect('sig_ml_dsa_65' in (document['signature'] as JsonObject)).toBe(false)
    expect(verifyGrant(document, keyManifest)).toBe(true)
  })

  it('round-trips a hybrid grant with both legs', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = makeGrant(PUB_HYBRID)

    expect('sig' in (document['signature'] as JsonObject)).toBe(true)
    expect('sig_ml_dsa_65' in (document['signature'] as JsonObject)).toBe(true)
    expect(verifyGrant(document, keyManifest)).toBe(true)
  })

  it('hashes the ENTIRE signed document, signature included', () => {
    const document = makeGrant(PUB_ED)

    expect(grantHash(document)).toBe(bytesToHex(sha256(canonicalBytes(document))))
    // Explicitly NOT the body-only hash the signature itself is computed over.
    const body: JsonObject = Object.create(null)
    for (const k of Object.keys(document)) if (k !== 'signature') body[k] = document[k]!
    expect(grantHash(document)).not.toBe(bytesToHex(sha256(canonicalBytes(body))))
  })

  it('rejects a tampered grant body', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED)
    document['jurisdiction'] = 'FR'

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('is a closed object: an unknown member is rejected', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = makeGrant(PUB_HYBRID)
    document['extra'] = 'surprise'

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('rejects a grant missing a member', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = makeGrant(PUB_HYBRID)
    delete document['jurisdiction']

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('fails closed on a classical-only grant against a hybrid key (§13 AND-rule)', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = makeGrant(PUB_HYBRID)
    delete (document['signature'] as JsonObject)['sig_ml_dsa_65']

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('fails closed on a stray PQ leg against a classical key (§13 AND-rule)', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED)
    const body: JsonObject = Object.create(null)
    for (const k of Object.keys(document)) if (k !== 'signature') body[k] = document[k]!
    ;(document['signature'] as JsonObject)['sig_ml_dsa_65'] = b64uEncode(
      ml_dsa65.sign(canonicalBytes(body), STRAY_HYBRID.mldsaSecret!),
    )

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('rejects a grant signed by a retired key', () => {
    const signerKid = `${PUBLISHER}/keys/grants#2`
    const keyManifest = buildKeyManifest(
      PUBLISHER,
      1,
      MANIFEST_ISSUED_AT,
      [keyEntry(PUB_KID, PUB_ED, VALID_FROM, { status: 'retired' }), keyEntry(signerKid, PUB_ED, VALID_FROM)],
      PUB_ED,
      signerKid,
    )
    const document = makeGrant(PUB_ED)

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('rejects a grant issued outside the signer key window', () => {
    const keyManifest = buildKeyManifest(
      PUBLISHER,
      1,
      '2026-03-01T00:00:00Z',
      [keyEntry(PUB_KID, PUB_ED, '2026-03-01T00:00:00Z')],
      PUB_ED,
      PUB_KID,
    )
    const document = makeGrant(PUB_ED) // issued_at 2026-02-01, before valid_from

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('rejects a grant against a self-inconsistent manifest, while the signature-only half still accepts it', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED)
    keyManifest['issued_at'] = '2026-06-01T00:00:00Z'

    expect(verifyGrant(document, keyManifest)).toBe(false)
    // ...and the signature-only half, which presumes an already-checked
    // manifest, still accepts it: the two halves are distinct on purpose.
    expect(verifyGrantSignature(document, keyManifest)).toBe(true)
  })

  const malformedOverrides: Array<[string, Record<string, unknown>]> = [
    ['grant_version 0', { grant_version: 0 }],
    ['grant_version true', { grant_version: true }],
    ['publisher not lowercase', { publisher: 'Pub.Example' }],
    ['publisher not a domain', { publisher: 'not-a-domain' }],
    ['scope with neither series nor artifacts', { scope: { artifact_series: null, artifacts: [] } }],
    ['scope with an empty series', { scope: { artifact_series: '', artifacts: [ART_A] } }],
    ['scope missing artifacts', { scope: { artifact_series: SERIES } }],
    ['scope artifacts unsorted', { scope: { artifact_series: SERIES, artifacts: [ART_B, ART_A] } }],
    ['scope artifacts duplicated', { scope: { artifact_series: SERIES, artifacts: [ART_A, ART_A] } }],
    ['scope artifacts uppercase hex', { scope: { artifact_series: SERIES, artifacts: [ART_A.toUpperCase()] } }],
    ['permissions empty', { permissions: [] }],
    ['permissions without deliver-to-holder', { permissions: [PERMISSION_REDISTRIBUTE_AMONG_HOLDERS] }],
    ['permissions unsorted', { permissions: [PERMISSION_REDISTRIBUTE_AMONG_HOLDERS, PERMISSION_DELIVER_TO_HOLDER] }],
    ['permissions duplicated', { permissions: [PERMISSION_DELIVER_TO_HOLDER, PERMISSION_DELIVER_TO_HOLDER] }],
    ['activation with no modes', { activation: { modes: [], fixed_date: null, successor_ids: [] } }],
    [
      'fixed_date set without the fixed-date mode',
      { activation: { modes: ['publisher-declaration'], fixed_date: FIXED_DATE, successor_ids: [] } },
    ],
    [
      'activation modes unsorted',
      { activation: { modes: ['publisher-declaration', 'fixed-date'], fixed_date: null, successor_ids: [] } },
    ],
    [
      'fixed_date not a UTC wire timestamp',
      { activation: { modes: ['fixed-date'], fixed_date: '2046-01-01', successor_ids: [] } },
    ],
    [
      'successor_ids unsorted / not lowercase',
      { activation: { modes: ['fixed-date'], fixed_date: FIXED_DATE, successor_ids: ['B.example', 'a.example'] } },
    ],
    ['unprotected_build a string', { unprotected_build: 'true' }],
    ['legal_text_sha256 not hex', { legal_text_sha256: 'not-hex' }],
    // §18.2 types BOTH prose-bearing members as non-empty, exactly as it
    // types `jurisdiction` below. The shape is checked BEFORE the signature
    // and the evaluation then runs on to activation, so a publisher who
    // signed a grant naming no prose at all could hash-bind it to a receipt,
    // hand over a valid cessation declaration and reach `grant: "activated"`
    // — the single direction §18.4 declares normatively forbidden.
    ['legal_text_uri empty', { legal_text_uri: '' }],
    ['legal_text_sha256 empty', { legal_text_sha256: '' }],
    ['jurisdiction empty', { jurisdiction: '' }],
    ['issued_at not a UTC wire timestamp', { issued_at: '2026-02-01' }],
  ]

  it.each(malformedOverrides)('fails closed on a malformed member: %s', (_label, overrides) => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED, overrides)

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  const garbageDocuments: unknown[] = [null, 42, 'grant', [], {}, { signature: null }]

  it.each(garbageDocuments.map((d, i) => [i, d] as const))(
    'never throws on garbage (#%i)',
    (_i, document) => {
      const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)

      expect(verifyGrant(document, keyManifest)).toBe(false)
    },
  )

  it('cannot represent a grant_version above the JCS integer ceiling', () => {
    // §18.2: `grant_version` is bounded by the attest-JCS safe integer range,
    // so a value above it cannot be canonicalized and never becomes a wire
    // document — and a hand-built one is refused on shape, without throwing.
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)

    // 2**53 on the wire (a JSON number literal, which loadsStrict turns into a
    // bigint) — canonicalBytes refuses it, so the builder never gets to sign.
    expect(() => makeGrant(PUB_ED, { grant_version: Number(2n ** 53n) })).toThrow(CanonError)

    const document = makeGrant(PUB_ED)
    document['grant_version'] = 2n ** 53n

    expect(verifyGrant(document, keyManifest)).toBe(false)
  })

  it('does not invalidate a grant listing the reserved heartbeat-absence mode', () => {
    // §18.4/§6.9: the reserved mode is never honored, but a grant listing it
    // 'is not thereby invalid'.
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED, {
      activation: activation(['fixed-date', 'heartbeat-absence', 'publisher-declaration']),
    })

    expect(verifyGrant(document, keyManifest)).toBe(true)
  })

  // §18.2's "sorted, duplicate-free" is stated over Unicode, and Python's
  // `str <` orders by CODE POINT while JavaScript's `<` orders by UTF-16 CODE
  // UNIT. `modes` and `permissions` accept any non-empty string, so an
  // attacker can hand-build a grant that lands exactly on the disagreement —
  // U+E000 against an astral character, whose surrogate pair begins at
  // 0xD800. These two cases pin the CODE POINT reading in both directions, so
  // the two cores accept and reject the same bytes.
  const ASTRAL = '\u{10000}'
  const PRIVATE_USE = ''

  it('accepts modes sorted by code point even where UTF-16 order would disagree', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED, {
      // Code-point order: 'f' (0x66) < 'p' (0x70) < U+E000 < U+10000.
      activation: {
        modes: ['fixed-date', 'publisher-declaration', PRIVATE_USE, ASTRAL],
        fixed_date: FIXED_DATE,
        successor_ids: [SUCCESSOR],
      },
    })

    expect(PRIVATE_USE < ASTRAL).toBe(false) // JS UTF-16 order says otherwise
    expect(verifyGrant(document, keyManifest)).toBe(true)
  })

  it('rejects modes sorted by UTF-16 code unit but NOT by code point', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = makeGrant(PUB_ED, {
      activation: {
        modes: ['fixed-date', 'publisher-declaration', ASTRAL, PRIVATE_USE],
        fixed_date: FIXED_DATE,
        successor_ids: [SUCCESSOR],
      },
    })

    expect(ASTRAL < PRIVATE_USE).toBe(true) // JS UTF-16 order would accept this
    expect(verifyGrant(document, keyManifest)).toBe(false)
  })
})

// --- cessation declaration (§18.4) -------------------------------------------

describe('cessation declaration (v0.2 §18.4)', () => {
  it('has exactly the four members', () => {
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_ED, PUB_KID)

    expect(new Set(Object.keys(declaration))).toEqual(new Set(['publisher', 'scope', 'declared_at', 'signature']))
  })

  it('round-trips a classical declaration', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_ED, PUB_KID)

    expect(verifyDeclaration(declaration, keyManifest)).toBe(true)
  })

  it('round-trips a hybrid declaration with both legs', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_HYBRID, PUB_KID)

    expect('sig_ml_dsa_65' in (declaration['signature'] as JsonObject)).toBe(true)
    expect(verifyDeclaration(declaration, keyManifest)).toBe(true)
  })

  it('is a closed object: an unknown member is rejected', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_HYBRID, PUB_KID)
    declaration['reason'] = 'bankruptcy'

    expect(verifyDeclaration(declaration, keyManifest)).toBe(false)
  })

  it('fails closed on a classical-only declaration against a hybrid key', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_HYBRID, PUB_KID)
    delete (declaration['signature'] as JsonObject)['sig_ml_dsa_65']

    expect(verifyDeclaration(declaration, keyManifest)).toBe(false)
  })

  it('checks the key window against declared_at, never the verifier clock', () => {
    const keyManifest = buildKeyManifest(
      PUBLISHER,
      1,
      MANIFEST_ISSUED_AT,
      [keyEntry(PUB_KID, PUB_ED, VALID_FROM, { validTo: '2030-01-01T00:00:00Z' })],
      PUB_ED,
      PUB_KID,
    )
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_ED, PUB_KID)

    expect(verifyDeclaration(declaration, keyManifest)).toBe(false)
  })

  it('rejects a tampered declaration scope', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_ED, PUB_KID)
    ;(declaration['scope'] as JsonObject)['artifacts'] = [ART_A, ART_B, ART_C].sort()

    expect(verifyDeclaration(declaration, keyManifest)).toBe(false)
  })

  const garbageDeclarations: unknown[] = [null, 42, 'declaration', [], {}, { publisher: PUBLISHER }]

  it.each(garbageDeclarations.map((d, i) => [i, d] as const))(
    'never throws on garbage (#%i)',
    (_i, declaration) => {
      const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)

      expect(verifyDeclaration(declaration, keyManifest)).toBe(false)
    },
  )

  it('hashes the ENTIRE signed declaration, signature included', () => {
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_ED, PUB_KID)

    expect(declarationHash(declaration)).toBe(bytesToHex(sha256(canonicalBytes(declaration))))
  })
})

// --- who may sign a declaration (§18.4) --------------------------------------

describe('declaration signer role (v0.2 §18.1, §18.4)', () => {
  it('reports the publisher role for a publisher-signed declaration', () => {
    const document = unsignedGrant()
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, PUB_ED, PUB_KID)

    expect(declarationSignerRole(declaration, document)).toBe(SIGNER_ROLE_PUBLISHER)
  })

  it('reports the successor role for a listed successor', () => {
    const document = unsignedGrant()
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, SUCCESSOR_ED, SUCCESSOR_KID)

    expect(declarationSignerRole(declaration, document)).toBe(SIGNER_ROLE_SUCCESSOR)
  })

  it('gives a stranger no role at all', () => {
    const document = unsignedGrant()
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, OTHER_ED, OTHER_KID)

    expect(declarationSignerRole(declaration, document)).toBeNull()
  })

  it("reads the successor list off the EFFECTIVE grant", () => {
    const document = unsignedGrant({ activation: activation(undefined, undefined, []) })
    const declaration = buildDeclaration(PUBLISHER, scope(), DECLARED_AT, SUCCESSOR_ED, SUCCESSOR_KID)

    expect(declarationSignerRole(declaration, document)).toBeNull()
  })

  it('reads the signing domain off the kid prefix', () => {
    const document = makeGrant(PUB_ED)

    expect(signerDomain(document)).toBe(PUBLISHER)
    expect(signerDomain({ signature: { kid: 'nope' } })).toBeNull()
    expect(signerDomain({})).toBeNull()
    expect(signerDomain(null)).toBeNull()
  })
})

// --- declaration coverage of a grant (§18.4) ---------------------------------

describe('declarationCoversGrant (v0.2 §18.4)', () => {
  const declarationWith = (overrides: Record<string, unknown> = {}) =>
    parse({ publisher: PUBLISHER, scope: scope(), declared_at: DECLARED_AT, signature: { kid: PUB_KID }, ...overrides })

  it('covers when publisher, series and artifacts all match', () => {
    expect(declarationCoversGrant(declarationWith(), unsignedGrant())).toBe(true)
  })

  it('covers with a superset of the artifacts', () => {
    expect(declarationCoversGrant(declarationWith({ scope: scope(SERIES, [ART_A, ART_B, ART_C]) }), unsignedGrant())).toBe(true)
  })

  it('does not cover with a subset of the artifacts', () => {
    expect(declarationCoversGrant(declarationWith({ scope: scope(SERIES, [ART_A]) }), unsignedGrant())).toBe(false)
  })

  it('requires an equal artifact_series', () => {
    expect(
      declarationCoversGrant(declarationWith({ scope: scope('pub.example/works/OTHER') }), unsignedGrant()),
    ).toBe(false)
  })

  it('treats both-null series as equal', () => {
    const document = unsignedGrant({ scope: scope(null) })

    expect(declarationCoversGrant(declarationWith({ scope: scope(null) }), document)).toBe(true)
  })

  it('rejects one-null-one-set series', () => {
    const document = unsignedGrant({ scope: scope(null) })

    expect(declarationCoversGrant(declarationWith({ scope: scope(SERIES) }), document)).toBe(false)
  })

  it('requires an equal publisher', () => {
    expect(declarationCoversGrant(declarationWith({ publisher: OTHER }), unsignedGrant())).toBe(false)
  })

  const garbage: unknown[] = [null, 42, {}, { publisher: PUBLISHER }]

  it.each(garbage.map((d, i) => [i, d] as const))('fails closed on garbage (#%i)', (_i, declaration) => {
    expect(declarationCoversGrant(declaration, unsignedGrant())).toBe(false)
  })
})

// --- grant coverage of a receipt (§18.4) -------------------------------------
//
// A DIFFERENT predicate from the one above, and deliberately not implemented
// in terms of it: series equality is a SUFFICIENT clause here, never a
// conjunct.

describe('grantCoversReceipt (v0.2 §18.4)', () => {
  it('covers by series alone', () => {
    const payload = makePayload({ work: { artifact_series: SERIES } })
    const document = unsignedGrant({ scope: scope(SERIES, [ART_A]) })

    expect(grantCoversReceipt(document, payload)).toBe(true)
  })

  it('covers by artifact hashes alone, even when the receipt names a series the grant does not', () => {
    const payload = makePayload() // carries both a series and one artifact
    const document = unsignedGrant({ scope: scope(null, [RECEIPT_ART, ART_A]) })

    expect(grantCoversReceipt(document, payload)).toBe(true)
  })

  it('still covers this receipt when scoped to a broader catalogue', () => {
    const payload = makePayload()
    const document = unsignedGrant({ scope: scope(SERIES, [RECEIPT_ART, ART_A, ART_B]) })

    expect(grantCoversReceipt(document, payload)).toBe(true)
  })

  it('leaves a series-only receipt uncovered when the series differs', () => {
    const payload = makePayload()
    delete workOf(payload)['artifacts']
    const document = unsignedGrant({ scope: scope('pub.example/works/OTHER', [RECEIPT_ART]) })

    expect(grantCoversReceipt(document, payload)).toBe(false)
  })

  it('does not cover a receipt without artifacts under a hash-scoped grant', () => {
    // The second clause is not a bare universal quantifier: over an ABSENT
    // artifact list it would be vacuously true and every grant would cover
    // every series-only receipt (§18.4).
    const payload = makePayload()
    delete workOf(payload)['artifacts']
    const document = unsignedGrant({ scope: scope(null, [ART_A, ART_B]) })

    expect(grantCoversReceipt(document, payload)).toBe(false)
  })

  it('does not cover a receipt with an EMPTY artifact list under a hash-scoped grant', () => {
    const payload = makePayload()
    workOf(payload)['artifacts'] = []
    const document = unsignedGrant({ scope: scope(null, [ART_A, ART_B]) })

    expect(grantCoversReceipt(document, payload)).toBe(false)
  })

  it('still covers a receipt without artifacts through a matching series', () => {
    const payload = makePayload({ work: { artifact_series: SERIES } })
    delete workOf(payload)['artifacts']
    const document = unsignedGrant({ scope: scope(SERIES, [ART_A]) })

    expect(grantCoversReceipt(document, payload)).toBe(true)
  })

  it('still covers a receipt with an empty artifact list through a matching series', () => {
    const payload = makePayload({ work: { artifact_series: SERIES } })
    workOf(payload)['artifacts'] = []
    const document = unsignedGrant({ scope: scope(SERIES, [ART_A]) })

    expect(grantCoversReceipt(document, payload)).toBe(true)
  })

  it('does not match a receipt missing the series with a null-series grant', () => {
    const payload = makePayload()
    delete workOf(payload)['artifact_series']
    delete workOf(payload)['artifacts']
    const document = unsignedGrant({ scope: scope(null, [ART_A]) })

    expect(grantCoversReceipt(document, payload)).toBe(false)
  })

  it('leaves a receipt with one unlisted artifact uncovered', () => {
    const payload = makePayload()
    const first = (workOf(payload)['artifacts'] as Record<string, unknown>[])[0]!
    workOf(payload)['artifacts'] = [
      { ...first, sha256: RECEIPT_ART },
      { ...first, sha256: ART_C, filename: 'extra.bin' },
    ]
    const document = unsignedGrant({ scope: scope(null, [RECEIPT_ART]) })

    expect(grantCoversReceipt(document, payload)).toBe(false)
  })

  const garbagePayloads: unknown[] = [null, 42, {}, { work: null }, { work: { artifacts: 3 } }]

  it.each(garbagePayloads.map((p, i) => [i, p] as const))('fails closed on garbage (#%i)', (_i, payload) => {
    expect(grantCoversReceipt(unsignedGrant(), payload)).toBe(false)
  })

  it('fails closed on a malformed artifact entry', () => {
    const payload = makePayload()
    workOf(payload)['artifacts'] = [{ role: 'installer' }]
    const document = unsignedGrant({ scope: scope(null, [RECEIPT_ART]) })

    expect(grantCoversReceipt(document, payload)).toBe(false)
  })
})

// --- the non-narrowing ratchet (§18.3) ---------------------------------------

describe('isNonNarrowing (v0.2 §18.3)', () => {
  it('rejects a later version naming another publisher, however much else it widens', () => {
    // §18.3 criterion 1: `publisher` equality is a precondition of
    // ADMISSIBILITY, and it is load-bearing — `publisher` is what declaration
    // coverage compares against (§18.4), so a later version free to change it
    // could move WHO MAY SIGN the cessation that opens the grant. This version
    // widens every member the ratchet does test, and is still not a later
    // version of this grant: it is a different grant.
    const floor = unsignedGrant()
    const later = unsignedGrant({
      grant_version: 2,
      publisher: OTHER,
      permissions: [PERMISSION_DELIVER_TO_HOLDER, PERMISSION_REDISTRIBUTE_AMONG_HOLDERS],
    })

    expect(isNonNarrowing(floor, later)).toBe(false)
  })

  const nonDomainPublishers: unknown[] = [null, 42, '', ['pub.example']]

  it.each(nonDomainPublishers.map((p, i) => [i, p] as const))(
    'fails closed on a non-domain publisher, in both directions (#%i)',
    (_i, publisher) => {
      const floor = unsignedGrant()
      const later = unsignedGrant({ grant_version: 2, publisher })

      expect(isNonNarrowing(floor, later)).toBe(false)
      expect(isNonNarrowing(later, floor)).toBe(false)
    },
  )

  it('accepts an identical later version', () => {
    expect(isNonNarrowing(unsignedGrant(), unsignedGrant({ grant_version: 2 }))).toBe(true)
  })

  it('accepts a permissions superset', () => {
    const later = unsignedGrant({
      grant_version: 2,
      permissions: [PERMISSION_DELIVER_TO_HOLDER, PERMISSION_REDISTRIBUTE_AMONG_HOLDERS],
    })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(true)
  })

  it('rejects a permissions subset', () => {
    const floor = unsignedGrant({ permissions: [PERMISSION_DELIVER_TO_HOLDER, PERMISSION_REDISTRIBUTE_AMONG_HOLDERS] })
    const later = unsignedGrant({ grant_version: 2, permissions: [PERMISSION_DELIVER_TO_HOLDER] })

    expect(isNonNarrowing(floor, later)).toBe(false)
  })

  it('accepts a series newly set from null', () => {
    const floor = unsignedGrant({ scope: scope(null) })
    const later = unsignedGrant({ grant_version: 2, scope: scope(SERIES) })

    expect(isNonNarrowing(floor, later)).toBe(true)
  })

  it('rejects a series changed to another value', () => {
    const later = unsignedGrant({ grant_version: 2, scope: scope('pub.example/works/OTHER') })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('rejects a series dropped to null', () => {
    const later = unsignedGrant({ grant_version: 2, scope: scope(null) })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('accepts an artifacts superset', () => {
    const later = unsignedGrant({ grant_version: 2, scope: scope(SERIES, [ART_A, ART_B, ART_C]) })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(true)
  })

  it('rejects an artifacts subset', () => {
    const later = unsignedGrant({ grant_version: 2, scope: scope(SERIES, [ART_A]) })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('accepts unprotected_build false -> true', () => {
    const floor = unsignedGrant({ unprotected_build: false })
    const later = unsignedGrant({ grant_version: 2, unprotected_build: true })

    expect(isNonNarrowing(floor, later)).toBe(true)
  })

  it('rejects unprotected_build true -> false', () => {
    const later = unsignedGrant({ grant_version: 2, unprotected_build: false })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('accepts a modes superset', () => {
    const floor = unsignedGrant({ activation: activation(['publisher-declaration'], null) })
    const later = unsignedGrant({
      grant_version: 2,
      activation: activation(['fixed-date', 'publisher-declaration'], null),
    })

    expect(isNonNarrowing(floor, later)).toBe(true)
  })

  it('rejects a dropped mode', () => {
    const later = unsignedGrant({ grant_version: 2, activation: activation(['fixed-date']) })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('accepts a fixed_date pulled earlier', () => {
    const later = unsignedGrant({ grant_version: 2, activation: activation(undefined, '2040-01-01T00:00:00Z') })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(true)
  })

  it('rejects a fixed_date pushed out', () => {
    const later = unsignedGrant({ grant_version: 2, activation: activation(undefined, '2050-01-01T00:00:00Z') })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('accepts a fixed_date newly set from null', () => {
    const floor = unsignedGrant({ activation: activation(['publisher-declaration'], null) })
    const later = unsignedGrant({
      grant_version: 2,
      activation: activation(['fixed-date', 'publisher-declaration'], FIXED_DATE),
    })

    expect(isNonNarrowing(floor, later)).toBe(true)
  })

  it('rejects a removed fixed_date', () => {
    const later = unsignedGrant({ grant_version: 2, activation: activation(undefined, null) })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('accepts a successor_ids superset', () => {
    const later = unsignedGrant({
      grant_version: 2,
      activation: activation(undefined, undefined, ['archive.example', SUCCESSOR]),
    })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(true)
  })

  it('rejects a removed successor', () => {
    const later = unsignedGrant({ grant_version: 2, activation: activation(undefined, undefined, []) })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })

  it('leaves the prose members outside the ratchet', () => {
    // §18.3: `legal_text_uri`, `legal_text_sha256` and `jurisdiction` are
    // deliberately absent from the structural test — a verifier cannot read
    // prose. The divergence is reported elsewhere, never treated as narrowing.
    const later = unsignedGrant({
      grant_version: 2,
      legal_text_uri: 'https://pub.example/sunset-grant-v2',
      legal_text_sha256: OTHER_LEGAL_TEXT_SHA256,
      jurisdiction: 'FR',
    })

    expect(isNonNarrowing(unsignedGrant(), later)).toBe(true)
  })

  it('detects prose divergence separately, on all three members', () => {
    const floor = unsignedGrant()

    expect(proseDiffers(floor, unsignedGrant({ grant_version: 2 }))).toBe(false)
    expect(
      proseDiffers(floor, unsignedGrant({ grant_version: 2, legal_text_uri: 'https://pub.example/sunset-grant-v2' })),
    ).toBe(true)
    expect(proseDiffers(floor, unsignedGrant({ grant_version: 2, legal_text_sha256: OTHER_LEGAL_TEXT_SHA256 }))).toBe(true)
    expect(proseDiffers(floor, unsignedGrant({ grant_version: 2, jurisdiction: 'FR' }))).toBe(true)
  })

  const ratchetGarbage: unknown[] = [null, 42, {}, { scope: null }]

  it.each(ratchetGarbage.map((g, i) => [i, g] as const))('fails closed on garbage (#%i)', (_i, later) => {
    expect(isNonNarrowing(unsignedGrant(), later)).toBe(false)
  })
})

// --- structural ceilings (§18.4) ---------------------------------------------

describe('withinStructuralCeilings (v0.2 §18.4)', () => {
  it('pins both ceilings at sixty-four', () => {
    expect(MAX_GRANT_LATER_VERSIONS).toBe(64)
    expect(MAX_GRANT_DECLARATIONS).toBe(64)
  })

  it('accepts exactly the maximum', () => {
    expect(
      withinStructuralCeilings(new Array(MAX_GRANT_LATER_VERSIONS).fill({}), new Array(MAX_GRANT_DECLARATIONS).fill({})),
    ).toBe(true)
  })

  it('rejects one later version over the ceiling', () => {
    expect(withinStructuralCeilings(new Array(MAX_GRANT_LATER_VERSIONS + 1).fill({}), [])).toBe(false)
  })

  it('rejects one declaration over the ceiling', () => {
    expect(withinStructuralCeilings([], new Array(MAX_GRANT_DECLARATIONS + 1).fill({}))).toBe(false)
  })

  it('counts and never inspects an element', () => {
    // §18.4: 'the ceiling check MUST run BEFORE any signature is verified, or
    // it is not a ceiling'. The predicate judges COUNT only — elements that
    // would throw on any inspection pass at the ceiling and are refused one
    // past it, without ever being touched.
    const hostile = () =>
      new Proxy(
        {},
        {
          get(_t, name) {
            throw new Error(`ceiling check inspected element property ${String(name)}`)
          },
          has(_t, name) {
            throw new Error(`ceiling check probed element property ${String(name)}`)
          },
          ownKeys() {
            throw new Error('ceiling check enumerated an element')
          },
        },
      )

    expect(withinStructuralCeilings(new Array(64).fill(hostile()), new Array(64).fill(hostile()))).toBe(true)
    expect(withinStructuralCeilings(new Array(65).fill(hostile()), [])).toBe(false)
    expect(withinStructuralCeilings([], new Array(65).fill(hostile()))).toBe(false)
  })

  it('accepts absent evidence', () => {
    expect(withinStructuralCeilings(null, null)).toBe(true)
    expect(withinStructuralCeilings(undefined, undefined)).toBe(true)
  })

  const nonSequences: unknown[] = [42, 'grants', { a: 1 }]

  it.each(nonSequences.map((v, i) => [i, v] as const))('fails closed on a non-sequence (#%i)', (_i, laterGrants) => {
    expect(withinStructuralCeilings(laterGrants, [])).toBe(false)
  })
})

// --- redemption (§18.7) ------------------------------------------------------

describe('redemption (v0.2 §18.7)', () => {
  it('builds a byte-exact preimage', () => {
    const enc = new TextEncoder()
    const parts = [
      enc.encode('Attest-redemption-challenge-v1'),
      Uint8Array.of(0x00),
      enc.encode(RECEIPT_ID),
      Uint8Array.of(0x00),
      enc.encode(AUDIENCE),
      Uint8Array.of(0x00),
      NONCE,
    ]
    const expected = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
    let offset = 0
    for (const p of parts) {
      expected.set(p, offset)
      offset += p.length
    }

    expect(redemptionMessage(RECEIPT_ID, AUDIENCE, NONCE)).toEqual(expected)
    // Pinned against the Python core's own bytes for this exact input
    // (grant.redemption_message, same receipt_id/audience/nonce): the preimage
    // is normative and verbatim (§18.7), so it is worth a literal here rather
    // than only a re-derivation of the same expression.
    expect(bytesToHex(redemptionMessage(RECEIPT_ID, AUDIENCE, NONCE))).toBe(
      '4174746573742d726564656d7074696f6e2d6368616c6c656e67652d7631' + // label
        '00' +
        '30314a31563542344d395a385157455254593132333435363738' + // receipt_id
        '00' +
        '637573746f6469616e2e6578616d706c65' + // audience
        '00' +
        '000102030405060708090a0b0c0d0e0f', // nonce
    )
  })

  it('pins the registered domain label', () => {
    expect(LABEL_REDEMPTION_CHALLENGE).toEqual(new TextEncoder().encode('Attest-redemption-challenge-v1'))
  })

  it('round-trips a holder response', () => {
    const sig = signRedemption(RECEIPT_ID, AUDIENCE, NONCE, HOLDER_ED.edSeed)

    expect(verifyRedemption(RECEIPT_ID, AUDIENCE, NONCE, sig, b64uEncode(HOLDER_ED.edPub))).toBe(true)
  })

  it('is not replayable at another custodian', () => {
    const sig = signRedemption(RECEIPT_ID, AUDIENCE, NONCE, HOLDER_ED.edSeed)

    expect(verifyRedemption(RECEIPT_ID, 'other-custodian.example', NONCE, sig, b64uEncode(HOLDER_ED.edPub))).toBe(false)
  })

  it('is bound to its receipt and nonce', () => {
    const sig = signRedemption(RECEIPT_ID, AUDIENCE, NONCE, HOLDER_ED.edSeed)

    expect(verifyRedemption('01ARZ3NDEKTSV4RRFFQ69G5FAV', AUDIENCE, NONCE, sig, b64uEncode(HOLDER_ED.edPub))).toBe(false)
    expect(
      verifyRedemption(RECEIPT_ID, AUDIENCE, Uint8Array.from({ length: 16 }, (_, i) => i + 1), sig, b64uEncode(HOLDER_ED.edPub)),
    ).toBe(false)
  })

  it("rejects another holder's key", () => {
    const sig = signRedemption(RECEIPT_ID, AUDIENCE, NONCE, HOLDER_ED.edSeed)

    expect(verifyRedemption(RECEIPT_ID, AUDIENCE, NONCE, sig, b64uEncode(OTHER_HOLDER_ED.edPub))).toBe(false)
  })

  it('refuses a nonce below sixteen bytes', () => {
    expect(() => redemptionMessage(RECEIPT_ID, AUDIENCE, new Uint8Array(15))).toThrow('nonce')
    expect(() => signRedemption(RECEIPT_ID, AUDIENCE, new Uint8Array(15), HOLDER_ED.edSeed)).toThrow('nonce')
  })

  const malformedResponses: Array<[string, Uint8Array, Uint8Array, string | null]> = [
    ['short nonce', new Uint8Array(15), new Uint8Array(64), null],
    ['short signature', NONCE, new TextEncoder().encode('short'), null],
    ['non-base64url key', NONCE, new Uint8Array(64), 'not-base64url!!'],
    ['empty key', NONCE, new Uint8Array(64), ''],
  ]

  it.each(malformedResponses)('fails closed and never throws: %s', (_label, nonce, sig, pubkey) => {
    const holderPubkey = pubkey === null ? b64uEncode(HOLDER_ED.edPub) : pubkey

    expect(verifyRedemption(RECEIPT_ID, AUDIENCE, nonce, sig, holderPubkey)).toBe(false)
  })
})

// --- registered vocabulary the verifier recognizes (§6.7, §6.10) -------------

describe('registered Stage 4 vocabulary', () => {
  it('recognizes sunset-grant-v1 as the ONLY pledge profile (§18.2/§6.10)', () => {
    // §18.2/§6.10: `sunset-grant-v1` is the sole profile this revision
    // defines. An unrecognized profile is valid-with-warning and is NEVER
    // evaluated under `sunset-grant-v1`'s rules — a later profile may attach
    // different meaning to the same members, and guessing is how two
    // conforming implementations reach different verdicts on identical input.
    expect(PLEDGE_SUNSET_GRANT_V1).toBe('sunset-grant-v1')
    expect([...KNOWN_PLEDGE_TYPES]).toEqual([PLEDGE_SUNSET_GRANT_V1])
  })

  it('pins the sunset-grant end_of_life label (§6.7)', () => {
    expect(END_OF_LIFE_SUNSET_GRANT).toBe('sunset-grant')
  })

  it('offers no way to spell a salt-disclosure proof (§18.7, normative prohibition)', () => {
    // §18.7 prohibits salt disclosure as a redemption proof, normatively. This
    // module offers no way to spell one: the only proof it verifies is the
    // audience-bound Ed25519 signature.
    expect('verifySaltDisclosure' in grantModule).toBe(false)
    expect(Object.keys(grantModule).some((name) => name.toLowerCase().includes('salt'))).toBe(false)
  })
})
