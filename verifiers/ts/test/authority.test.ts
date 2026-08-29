// Tests for src/authority.ts -- publisher authorization primitives (v0.2
// section 20). Mirrors tests/test_authority.py without the Python-only builder
// successor checks: this port ships verification-side primitives only.
import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalBytes, loadsStrict, CanonError } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import {
  MAX_AUTHORITY_DOCUMENTS,
  MAX_AUTHORIZED_ISSUERS,
  PERMISSION_DELEGATE,
  PERMISSION_ISSUE,
  authorizationHash,
  entryAuthorizesReceipt,
  entryForIssuer,
  isAuthorizationVersion,
  verifyAuthorization,
  verifyAuthorizationSignature,
  withinStructuralCeiling,
} from '../src/authority.js'
import {
  buildKeyManifest,
  edSigner,
  hybridSigner,
  keyEntry,
  parse,
  signBlock,
  type TestSigner,
} from './helpers/grant-builder.js'

const enc = new TextEncoder()

const PUBLISHER = 'pub.example'
const ISSUER = 'store.example.com'
const OTHER_ISSUER = 'marketplace.example'
const PUB_KID = `${PUBLISHER}/keys/authority#1`

const VALID_FROM = '2026-01-01T00:00:00Z'
const MANIFEST_ISSUED_AT = '2026-01-01T00:00:00Z'
const AUTH_ISSUED_AT = '2026-02-01T00:00:00Z'
const ENTRY_FROM = '2026-01-01T00:00:00Z'
const RECEIPT_ISSUED_AT = '2026-07-02T14:30:00Z'
const RECEIPT_SERIES = 'store.example.com/works/EXG-001'

const hex = (s: string) => bytesToHex(sha256(enc.encode(s)))
const RECEIPT_ART = hex('attest-test-artifact-v1')
const OTHER_ART = hex('artifact-elsewhere')

const PUB_ED = edSigner(30)
const PUB_HYBRID = hybridSigner(31)
const OTHER_ED = edSigner(32)
const ANY_ED = edSigner(33)
const STRAY_HYBRID = hybridSigner(34)

function manifestFor(
  issuer: string,
  kid: string,
  signer: TestSigner,
  entries: Record<string, unknown>[] = [keyEntry(kid, signer, VALID_FROM)],
): JsonObject {
  return buildKeyManifest(issuer, 1, MANIFEST_ISSUED_AT, entries, signer, kid)
}

function scope(
  artifactSeries: string | null = RECEIPT_SERIES,
  artifacts: string[] = [RECEIPT_ART],
): Record<string, unknown> {
  return { artifact_series: artifactSeries, artifacts: [...artifacts] }
}

function entry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    issuer_id: ISSUER,
    valid_from: ENTRY_FROM,
    valid_to: null,
    permissions: [PERMISSION_ISSUE],
    scope: null,
    ...overrides,
  }
}

function authorizationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    authorization_version: 1,
    publisher: PUBLISHER,
    authorized_issuers: [entry()],
    issued_at: AUTH_ISSUED_AT,
    ...overrides,
  }
}

function buildAuthorization(
  signer: TestSigner,
  overrides: Record<string, unknown> = {},
  kid: string = PUB_KID,
): JsonObject {
  const body = authorizationBody(overrides)
  const parsedBody = parse(body)
  return parse({ ...body, signature: signBlock(canonicalBytes(parsedBody), signer, kid) })
}

function unsignedAuthorization(overrides: Record<string, unknown> = {}): JsonObject {
  return buildAuthorization(ANY_ED, overrides)
}

const COMMITMENT = b64uEncode(new Uint8Array(32))
function basePayload(): Record<string, unknown> {
  return {
    attest_version: '0.1',
    receipt_id: '01J1V5B4M9Z8QWERTY12345678',
    issued_at: RECEIPT_ISSUED_AT,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: { commitment: COMMITMENT, identifier_type: 'issuer-account', pubkey: null },
    work: {
      title: 'Example Game',
      publisher: 'Example Publisher',
      edition: 'Deluxe',
      identifiers: { issuer_sku: 'EXG-001' },
      artifact_series: RECEIPT_SERIES,
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

const workOf = (payload: JsonObject): Record<string, unknown> => payload['work'] as unknown as Record<string, unknown>

describe('publisher authorization document (v0.2 section 20.2)', () => {
  it('exports the registered literals and ceilings', () => {
    expect(PERMISSION_ISSUE).toBe('issue')
    expect(PERMISSION_DELEGATE).toBe('delegate')
    expect(MAX_AUTHORIZED_ISSUERS).toBe(4096)
    expect(MAX_AUTHORITY_DOCUMENTS).toBe(64)
  })

  it('has exactly the five signed-document members', () => {
    const document = buildAuthorization(PUB_ED)

    expect(new Set(Object.keys(document))).toEqual(
      new Set(['authorization_version', 'publisher', 'authorized_issuers', 'issued_at', 'signature']),
    )
  })

  it('round-trips a classical authorization', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = buildAuthorization(PUB_ED)

    expect('sig_ml_dsa_65' in (document['signature'] as JsonObject)).toBe(false)
    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it('round-trips a hybrid authorization with both legs', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = buildAuthorization(PUB_HYBRID)

    expect('sig' in (document['signature'] as JsonObject)).toBe(true)
    expect('sig_ml_dsa_65' in (document['signature'] as JsonObject)).toBe(true)
    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it('accepts an empty authorized_issuers array on a first document', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = buildAuthorization(PUB_HYBRID, { authorized_issuers: [] })

    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it('accepts several entries sorted by issuer_id', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const entries = [entry({ issuer_id: OTHER_ISSUER }), entry()]
    const document = buildAuthorization(PUB_HYBRID, { authorized_issuers: entries })

    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it('hashes the entire signed document, signature included', () => {
    const document = buildAuthorization(PUB_ED)

    expect(authorizationHash(document)).toBe(bytesToHex(sha256(canonicalBytes(document))))
    const body: JsonObject = Object.create(null)
    for (const k of Object.keys(document)) if (k !== 'signature') body[k] = document[k]!
    expect(authorizationHash(document)).not.toBe(bytesToHex(sha256(canonicalBytes(body))))
    expect(authorizationHash(document)).toBe(authorizationHash(document))
  })

  it('is sensitive to the signature member', () => {
    const one = buildAuthorization(PUB_ED)
    const two = buildAuthorization(OTHER_ED)

    expect(one['signature']).not.toEqual(two['signature'])
    expect(authorizationHash(one)).not.toBe(authorizationHash(two))
  })

  it('rejects a tampered body', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = buildAuthorization(PUB_ED)
    const firstEntry = (document['authorized_issuers'] as JsonObject[])[0]!
    firstEntry['valid_to'] = '2030-01-01T00:00:00Z'

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('rejects a classical-only authorization against a hybrid key', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = buildAuthorization(PUB_HYBRID)
    delete (document['signature'] as JsonObject)['sig_ml_dsa_65']

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('rejects a stray hybrid leg against a classical key', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = buildAuthorization(PUB_ED)
    const body: JsonObject = Object.create(null)
    for (const k of Object.keys(document)) if (k !== 'signature') body[k] = document[k]!
    ;(document['signature'] as JsonObject)['sig_ml_dsa_65'] = b64uEncode(
      ml_dsa65.sign(canonicalBytes(body), STRAY_HYBRID.mldsaSecret!),
    )

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('rejects a document signed by a retired key', () => {
    const signerKid = `${PUBLISHER}/keys/authority#2`
    const keyManifest = buildKeyManifest(
      PUBLISHER,
      1,
      MANIFEST_ISSUED_AT,
      [keyEntry(PUB_KID, PUB_ED, VALID_FROM, { status: 'retired' }), keyEntry(signerKid, PUB_ED, VALID_FROM)],
      PUB_ED,
      signerKid,
    )
    const document = buildAuthorization(PUB_ED)

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('rejects a document issued outside the signer key window', () => {
    const beforeWindow = buildKeyManifest(
      PUBLISHER,
      1,
      '2026-03-01T00:00:00Z',
      [keyEntry(PUB_KID, PUB_ED, '2026-03-01T00:00:00Z')],
      PUB_ED,
      PUB_KID,
    )
    const afterWindow = buildKeyManifest(
      PUBLISHER,
      1,
      MANIFEST_ISSUED_AT,
      [keyEntry(PUB_KID, PUB_ED, VALID_FROM, { validTo: '2026-01-15T00:00:00Z' })],
      PUB_ED,
      PUB_KID,
    )
    const document = buildAuthorization(PUB_ED)

    expect(verifyAuthorization(document, beforeWindow)).toBe(false)
    expect(verifyAuthorization(document, afterWindow)).toBe(false)
  })

  it('rejects a self-inconsistent manifest while the signature-only half still accepts it', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = buildAuthorization(PUB_ED)
    keyManifest['issued_at'] = '2026-06-01T00:00:00Z'

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
    expect(verifyAuthorizationSignature(document, keyManifest)).toBe(true)
  })

  it('rejects an unknown kid', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = buildAuthorization(PUB_ED, {}, `${PUBLISHER}/keys/authority#9`)

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })
})

describe('publisher authorization shape', () => {
  const malformedCases: Array<[string, Record<string, unknown>]> = [
    ['version zero', { authorization_version: 0 }],
    ['version boolean', { authorization_version: true }],
    ['version string', { authorization_version: '1' }],
    ['version null', { authorization_version: null }],
    ['publisher uppercase', { publisher: 'Pub.Example' }],
    ['publisher not a domain', { publisher: 'not-a-domain' }],
    ['publisher empty', { publisher: '' }],
    ['authorized_issuers null', { authorized_issuers: null }],
    ['authorized_issuers object', { authorized_issuers: { [ISSUER]: {} } }],
    ['authorized_issuers contains null', { authorized_issuers: [null] }],
    ['authorized_issuers contains string', { authorized_issuers: [ISSUER] }],
    ['duplicate issuer_id', { authorized_issuers: [entry(), entry()] }],
    ['issuer_id out of order', { authorized_issuers: [entry({ issuer_id: 'z.example' }), entry({ issuer_id: 'a.example' })] }],
    ['entry extra member', { authorized_issuers: [{ ...entry(), extra: 'surprise' }] }],
    ['entry missing scope', { authorized_issuers: [withoutMember(entry(), 'scope')] }],
    ['issuer_id uppercase', { authorized_issuers: [entry({ issuer_id: 'Store.Example.Com' })] }],
    ['issuer_id invalid', { authorized_issuers: [entry({ issuer_id: 'not-a-domain' })] }],
    ['valid_from not strict UTC', { authorized_issuers: [entry({ valid_from: '2026-01-01' })] }],
    ['valid_to not strict UTC', { authorized_issuers: [entry({ valid_to: '2026-05-01' })] }],
    ['valid_to impossible', { authorized_issuers: [entry({ valid_to: '2026-13-01T00:00:00Z' })] }],
    ['valid_to number', { authorized_issuers: [entry({ valid_to: 0 })] }],
    ['permissions empty', { authorized_issuers: [entry({ permissions: [] })] }],
    ['permissions unsorted', { authorized_issuers: [entry({ permissions: ['issue', 'delegate'] })] }],
    ['permissions duplicate', { authorized_issuers: [entry({ permissions: ['issue', 'issue'] })] }],
    ['permissions empty string', { authorized_issuers: [entry({ permissions: [''] })] }],
    ['permissions non-string item', { authorized_issuers: [entry({ permissions: ['issue', 42] })] }],
    ['permissions not array', { authorized_issuers: [entry({ permissions: 'issue' })] }],
    ['scope number', { authorized_issuers: [entry({ scope: 42 })] }],
    ['scope empty object', { authorized_issuers: [entry({ scope: {} })] }],
    ['scope missing artifacts', { authorized_issuers: [entry({ scope: { artifact_series: RECEIPT_SERIES } })] }],
    ['scope empty both halves', { authorized_issuers: [entry({ scope: { artifact_series: null, artifacts: [] } })] }],
    ['scope empty series', { authorized_issuers: [entry({ scope: { artifact_series: '', artifacts: [RECEIPT_ART] } })] }],
    ['scope empty artifact', { authorized_issuers: [entry({ scope: { artifact_series: RECEIPT_SERIES, artifacts: [OTHER_ART, ''] } })] }],
    ['scope duplicate artifact', { authorized_issuers: [entry({ scope: { artifact_series: RECEIPT_SERIES, artifacts: [RECEIPT_ART, RECEIPT_ART] } })] }],
    ['scope uppercase artifact', { authorized_issuers: [entry({ scope: { artifact_series: RECEIPT_SERIES, artifacts: [RECEIPT_ART.toUpperCase()] } })] }],
    ['issued_at not strict UTC', { issued_at: '2026-02-01' }],
    ['issued_at empty', { issued_at: '' }],
    ['issued_at null', { issued_at: null }],
  ]

  it.each(malformedCases)('fails closed on malformed member: %s', (_name, overrides) => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = buildAuthorization(PUB_ED, overrides)

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('rejects an unknown document member and a missing document member', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    expect(verifyAuthorization(buildAuthorization(PUB_HYBRID, { extra: 'surprise' }), keyManifest)).toBe(false)

    const missing = buildAuthorization(PUB_HYBRID)
    delete missing['issued_at']
    expect(verifyAuthorization(missing, keyManifest)).toBe(false)
  })

  it('rejects a non-object signature member', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const document = buildAuthorization(PUB_ED)
    document['signature'] = 'not-an-object'

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('accepts scopes that cover with only one non-empty half', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const seriesOnly = buildAuthorization(PUB_HYBRID, { authorized_issuers: [entry({ scope: scope(RECEIPT_SERIES, []) })] })
    const artifactsOnly = buildAuthorization(PUB_HYBRID, { authorized_issuers: [entry({ scope: scope(null, [RECEIPT_ART]) })] })

    expect(verifyAuthorization(seriesOnly, keyManifest)).toBe(true)
    expect(verifyAuthorization(artifactsOnly, keyManifest)).toBe(true)
  })

  it('carries unregistered permissions without rejecting the document', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_HYBRID)
    const document = buildAuthorization(PUB_HYBRID, {
      authorized_issuers: [entry({ permissions: ['issue', 'resell-in-eu'] })],
    })

    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it('rejects an authorization_version above the JCS integer ceiling without throwing', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)

    expect(() => buildAuthorization(PUB_ED, { authorization_version: Number(2n ** 53n) })).toThrow(CanonError)

    const document = buildAuthorization(PUB_ED)
    document['authorization_version'] = 2n ** 53n
    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('enforces the 4096-entry document ceiling before entry validation', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const entries = Array.from({ length: MAX_AUTHORIZED_ISSUERS + 1 }, (_v, index) =>
      entry({ issuer_id: `i${String(index).padStart(5, '0')}.example` }),
    )

    expect(verifyAuthorization(buildAuthorization(PUB_ED, { authorized_issuers: entries.slice(0, MAX_AUTHORIZED_ISSUERS) }), keyManifest)).toBe(true)
    expect(verifyAuthorization(buildAuthorization(PUB_ED, { authorized_issuers: entries }), keyManifest)).toBe(false)
  })

  it('rejects an oversized document before reading the key manifest', () => {
    let manifestRead = false
    const hostileManifest = new Proxy(
      {},
      {
        get(_target, name) {
          manifestRead = true
          throw new Error(`key manifest was read at ${String(name)}`)
        },
      },
    ) as JsonObject
    const document = {
      authorization_version: 1n,
      publisher: PUBLISHER,
      authorized_issuers: new Array(MAX_AUTHORIZED_ISSUERS + 1).fill(null),
      issued_at: AUTH_ISSUED_AT,
      signature: {},
    }

    expect(verifyAuthorization(document, hostileManifest)).toBe(false)
    expect(manifestRead).toBe(false)
  })

  it('refuses an oversized document on its count before walking the array', () => {
    // §20.2 refuses on the count FIRST and §20.3 makes the ceiling precede
    // every cost that scales with the supplied length. A shape scan that walks
    // the array before the count check turns the ceiling into an amplifier:
    // measured 348ms to reject a document both the parser and the ceiling
    // would refuse in O(1).
    let walked = false
    const oversized = new Array(MAX_AUTHORIZED_ISSUERS + 1).fill(null)
    const watched = new Proxy(oversized, {
      ownKeys(target) {
        walked = true
        return Reflect.ownKeys(target)
      },
    })
    const document = {
      authorization_version: 1n,
      publisher: PUBLISHER,
      authorized_issuers: watched,
      issued_at: AUTH_ISSUED_AT,
      signature: {},
    }

    expect(verifyAuthorizationSignature(document, {} as JsonObject)).toBe(false)
    expect(walked).toBe(false)
  })

  it('refuses a hostile permissions array on its items before walking it', () => {
    // `permissions` carries no count ceiling at all, so this ordering is the
    // only thing bounding the work.
    let walked = false
    const permissions = new Proxy([42], {
      ownKeys(target) {
        walked = true
        return Reflect.ownKeys(target)
      },
    })

    expect(entryAuthorizesReceipt(entry({ permissions }), basePayload())).toBe(false)
    expect(walked).toBe(false)
  })

  it('ignores inherited keys but rejects an own __proto__ key from strict JSON', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const inherited = buildAuthorization(PUB_ED)
    Object.setPrototypeOf(inherited, { extra: 'ignored' })
    expect(verifyAuthorization(inherited, keyManifest)).toBe(true)

    const document = buildAuthorization(PUB_ED)
    const sig = JSON.stringify(document['signature'])
    const withOwnProto = loadsStrict(
      enc.encode(
        `{"__proto__":null,"authorization_version":1,"publisher":"${PUBLISHER}",` +
          `"authorized_issuers":[],"issued_at":"${AUTH_ISSUED_AT}","signature":${sig}}`,
      ),
    ) as JsonObject
    expect(Object.keys(withOwnProto)).toContain('__proto__')
    expect(verifyAuthorization(withOwnProto, keyManifest)).toBe(false)
  })

  it('rejects sparse arrays and non-index own properties in authority shape arrays', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)

    const sparseIssuers = buildAuthorization(PUB_ED, { authorized_issuers: [] })
    const issuerHoles = [] as unknown[]
    issuerHoles.length = 1
    sparseIssuers['authorized_issuers'] = issuerHoles

    const extraIssuers = buildAuthorization(PUB_ED)
    Object.defineProperty(extraIssuers['authorized_issuers'] as unknown[], 'extra', {
      value: 'not-json',
      enumerable: true,
    })

    const sparsePermissions = buildAuthorization(PUB_ED, {
      authorized_issuers: [entry({ permissions: [] })],
    })
    const permissionHoles = [] as unknown[]
    permissionHoles.length = 1
    ;((sparsePermissions['authorized_issuers'] as JsonObject[])[0]! as Record<string, unknown>)['permissions'] =
      permissionHoles

    const extraPermissions = buildAuthorization(PUB_ED)
    Object.defineProperty(((extraPermissions['authorized_issuers'] as JsonObject[])[0]!['permissions'] as unknown[]), 'extra', {
      value: 'not-json',
      enumerable: true,
    })

    const sparseArtifacts = buildAuthorization(PUB_ED, {
      authorized_issuers: [entry({ scope: scope(RECEIPT_SERIES, []) })],
    })
    const artifactHoles = [] as unknown[]
    artifactHoles.length = 1
    ;(
      ((sparseArtifacts['authorized_issuers'] as JsonObject[])[0]!['scope'] as Record<string, unknown>)
    )['artifacts'] = artifactHoles

    const extraArtifacts = buildAuthorization(PUB_ED, {
      authorized_issuers: [entry({ scope: scope(RECEIPT_SERIES, [RECEIPT_ART]) })],
    })
    Object.defineProperty(
      (((extraArtifacts['authorized_issuers'] as JsonObject[])[0]!['scope'] as JsonObject)['artifacts'] as unknown[]),
      'extra',
      { value: 'not-json', enumerable: true },
    )

    for (const document of [
      sparseIssuers,
      extraIssuers,
      sparsePermissions,
      extraPermissions,
      sparseArtifacts,
      extraArtifacts,
    ]) {
      expect(verifyAuthorization(document, keyManifest)).toBe(false)
    }
  })

  it('accepts permissions sorted by code point and rejects UTF-16 code-unit order', () => {
    const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)
    const astral = '\u{10000}'
    const privateUse = '\uE000'
    const codePointSorted = buildAuthorization(PUB_ED, {
      authorized_issuers: [entry({ permissions: [PERMISSION_ISSUE, privateUse, astral] })],
    })
    const codeUnitSorted = buildAuthorization(PUB_ED, {
      authorized_issuers: [entry({ permissions: [PERMISSION_ISSUE, astral, privateUse] })],
    })

    expect(verifyAuthorization(codePointSorted, keyManifest)).toBe(true)
    expect(verifyAuthorization(codeUnitSorted, keyManifest)).toBe(false)
  })

  const garbageDocuments: unknown[] = [null, 42, 'authorization', [], {}, { signature: null }, { authorization_version: 1 }]

  it.each(garbageDocuments.map((document, i) => [i, document] as const))(
    'never throws on garbage document (#%i)',
    (_i, document) => {
      const keyManifest = manifestFor(PUBLISHER, PUB_KID, PUB_ED)

      expect(verifyAuthorization(document, keyManifest)).toBe(false)
      expect(verifyAuthorizationSignature(document, keyManifest)).toBe(false)
    },
  )

  const garbageManifests: unknown[] = [null, 42, 'manifest', [], {}, { keys: null }]

  it.each(garbageManifests.map((keyManifest, i) => [i, keyManifest] as const))(
    'never throws on garbage manifest (#%i)',
    (_i, keyManifest) => {
      const document = buildAuthorization(PUB_ED)

      expect(verifyAuthorization(document, keyManifest as JsonObject)).toBe(false)
      expect(verifyAuthorizationSignature(document, keyManifest as JsonObject)).toBe(false)
    },
  )
})

describe('entryForIssuer (v0.2 section 20.4 step 9)', () => {
  it('returns the only matching entry', () => {
    const document = unsignedAuthorization({
      authorized_issuers: [entry({ issuer_id: OTHER_ISSUER }), entry()],
    })

    expect(entryForIssuer(document, ISSUER)?.['issuer_id']).toBe(ISSUER)
  })

  it('returns null when absent or empty', () => {
    expect(entryForIssuer(unsignedAuthorization({ authorized_issuers: [entry({ issuer_id: OTHER_ISSUER })] }), ISSUER)).toBeNull()
    expect(entryForIssuer(unsignedAuthorization({ authorized_issuers: [] }), ISSUER)).toBeNull()
  })

  it('returns null on duplicates rather than letting array order decide', () => {
    const document = unsignedAuthorization({
      authorized_issuers: [entry(), entry({ permissions: [PERMISSION_DELEGATE] })],
    })

    expect(entryForIssuer(document, ISSUER)).toBeNull()
  })

  it('fails closed on garbage inputs', () => {
    expect(entryForIssuer(null, ISSUER)).toBeNull()
    expect(entryForIssuer({ authorized_issuers: null }, ISSUER)).toBeNull()
    expect(entryForIssuer(unsignedAuthorization(), 42)).toBeNull()
  })

  it('fails closed on hostile document getters', () => {
    const hostile = new Proxy(Object.create(null), {
      get() {
        throw new Error('hostile get')
      },
    }) as Record<string, unknown>
    let result: Record<string, unknown> | null | undefined

    expect(() => {
      result = entryForIssuer(hostile, ISSUER)
    }).not.toThrow()
    expect(result).toBeNull()
  })
})

describe('entryAuthorizesReceipt (v0.2 section 20.4 step 9)', () => {
  it('authorizes an open-ended entry with the issue permission', () => {
    expect(entryAuthorizesReceipt(entry(), makePayload())).toBe(true)
  })

  it('rejects an entry for a different issuer', () => {
    expect(entryAuthorizesReceipt(entry({ issuer_id: OTHER_ISSUER }), makePayload())).toBe(false)
  })

  it('evaluates the inclusive window against the receipt issued_at', () => {
    expect(entryAuthorizesReceipt(entry({ valid_from: RECEIPT_ISSUED_AT }), makePayload())).toBe(true)
    expect(entryAuthorizesReceipt(entry({ valid_to: RECEIPT_ISSUED_AT }), makePayload())).toBe(true)
    expect(entryAuthorizesReceipt(entry({ valid_from: '2026-08-01T00:00:00Z' }), makePayload())).toBe(false)
    expect(entryAuthorizesReceipt(entry({ valid_to: '2026-06-01T00:00:00Z' }), makePayload())).toBe(false)
    expect(
      entryAuthorizesReceipt(
        entry({ valid_from: '2026-01-01T00:00:00Z', valid_to: '2026-02-01T00:00:00Z' }),
        makePayload({ issued_at: '2026-01-15T00:00:00Z' }),
      ),
    ).toBe(true)
    expect(
      entryAuthorizesReceipt(
        entry({ valid_from: '2026-01-01T00:00:00Z', valid_to: '2026-02-01T00:00:00Z' }),
        makePayload({ issued_at: '2026-03-15T00:00:00Z' }),
      ),
    ).toBe(false)
  })

  it('requires the issue permission and never honors delegate alone', () => {
    expect(entryAuthorizesReceipt(entry({ permissions: [PERMISSION_DELEGATE] }), makePayload())).toBe(false)
    expect(entryAuthorizesReceipt(entry({ permissions: [PERMISSION_DELEGATE, PERMISSION_ISSUE] }), makePayload())).toBe(true)
  })

  it('handles null and non-null scopes through grant coverage', () => {
    expect(entryAuthorizesReceipt(entry({ scope: null }), makePayload())).toBe(true)
    expect(entryAuthorizesReceipt(entry({ scope: scope(RECEIPT_SERIES, [OTHER_ART]) }), makePayload())).toBe(true)
    expect(entryAuthorizesReceipt(entry({ scope: scope(null, [RECEIPT_ART]) }), makePayload())).toBe(true)
    expect(entryAuthorizesReceipt(entry({ scope: scope('pub.example/works/OTHER', [OTHER_ART]) }), makePayload())).toBe(false)
  })

  it('does not let an empty artifact list satisfy a non-null scope', () => {
    const payload = makePayload({ work: { artifact_series: 'store.example.com/works/OTHER' } })
    workOf(payload)['artifacts'] = []

    expect(entryAuthorizesReceipt(entry({ scope: scope(null, [RECEIPT_ART]) }), payload)).toBe(false)
  })

  it('does not read an absent scope member as null', () => {
    expect(entryAuthorizesReceipt(withoutMember(entry(), 'scope'), makePayload())).toBe(false)
  })

  it('validates entry shape before believing permissions membership', () => {
    expect(entryAuthorizesReceipt(entry({ permissions: [PERMISSION_ISSUE, {}] }), makePayload())).toBe(false)
  })

  it('rejects unknown entry members before membership evaluation', () => {
    expect(entryAuthorizesReceipt({ ...entry(), note: 'trust me' }, makePayload())).toBe(false)
  })

  it('fails closed on garbage entry and payload inputs', () => {
    expect(entryAuthorizesReceipt(null, makePayload())).toBe(false)
    expect(entryAuthorizesReceipt(entry({ valid_to: 42 }), makePayload())).toBe(false)
    expect(entryAuthorizesReceipt(entry({ permissions: 'issue' }), makePayload())).toBe(false)
    expect(entryAuthorizesReceipt(entry(), null)).toBe(false)
    expect(entryAuthorizesReceipt(entry(), { issued_at: 'nope' })).toBe(false)
  })
})

describe('withinStructuralCeiling (v0.2 section 20.3)', () => {
  it('accepts absent evidence, empty arrays, and exactly the maximum', () => {
    expect(withinStructuralCeiling(null)).toBe(true)
    expect(withinStructuralCeiling(undefined)).toBe(true)
    expect(withinStructuralCeiling([])).toBe(true)
    expect(withinStructuralCeiling(new Array(MAX_AUTHORITY_DOCUMENTS).fill({}))).toBe(true)
  })

  it('rejects one document over the ceiling and non-arrays', () => {
    expect(withinStructuralCeiling(new Array(MAX_AUTHORITY_DOCUMENTS + 1).fill({}))).toBe(false)
    expect(withinStructuralCeiling(42)).toBe(false)
    expect(withinStructuralCeiling('documents')).toBe(false)
    expect(withinStructuralCeiling({ a: 1 })).toBe(false)
  })

  it('counts and never inspects an element', () => {
    const hostile = () =>
      new Proxy(
        {},
        {
          get(_target, name) {
            throw new Error(`ceiling check inspected element property ${String(name)}`)
          },
          has(_target, name) {
            throw new Error(`ceiling check probed element property ${String(name)}`)
          },
          ownKeys() {
            throw new Error('ceiling check enumerated an element')
          },
        },
      )

    expect(withinStructuralCeiling(new Array(MAX_AUTHORITY_DOCUMENTS).fill(hostile()))).toBe(true)
    expect(withinStructuralCeiling(new Array(MAX_AUTHORITY_DOCUMENTS + 1).fill(hostile()))).toBe(false)
  })

  it('fails closed when array length itself is hostile', () => {
    const hostileArray = new Proxy([], {
      get(target, prop, receiver) {
        if (prop === 'length') throw new Error('hostile length')
        return Reflect.get(target, prop, receiver)
      },
    })
    let result: boolean | undefined

    expect(() => {
      result = withinStructuralCeiling(hostileArray)
    }).not.toThrow()
    expect(result).toBe(false)
  })
})

describe('isAuthorizationVersion (v0.2 sections 20.2 and 20.3)', () => {
  it('accepts number and bigint representations at the same valid boundaries', () => {
    expect(isAuthorizationVersion(1)).toBe(true)
    expect(isAuthorizationVersion(1n)).toBe(true)
    expect(isAuthorizationVersion(Number.MAX_SAFE_INTEGER)).toBe(true)
    expect(isAuthorizationVersion((2n ** 53n) - 1n)).toBe(true)
  })

  it('rejects invalid values in both representations', () => {
    for (const value of [2 ** 53, 2n ** 53n, 0, 0n, true, false, '5', null, undefined, NaN, 1.5, -0]) {
      expect(isAuthorizationVersion(value)).toBe(false)
    }
  })

  it('keeps the document and caller-view version predicate unified', () => {
    for (const [numberValue, bigintValue] of [
      [1, 1n],
      [Number.MAX_SAFE_INTEGER, (2n ** 53n) - 1n],
      [0, 0n],
      [2 ** 53, 2n ** 53n],
    ] as const) {
      expect(isAuthorizationVersion(numberValue)).toBe(isAuthorizationVersion(bigintValue))
    }
  })
})

function withoutMember(source: Record<string, unknown>, member: string): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...source }
  delete copy[member]
  return copy
}
