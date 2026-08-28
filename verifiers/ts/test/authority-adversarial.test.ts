// Adversarial tests for the publisher authorization manifest primitives
// described in attest v0.2 section 20. These tests intentionally import the
// authority module interface even in worktrees where the module is not present.
import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { canonicalBytes } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import {
  MAX_AUTHORIZED_ISSUERS,
  MAX_AUTHORITY_DOCUMENTS,
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

const PUBLISHER = 'publisher.example'
const OTHER_PUBLISHER = 'other-publisher.example'
const ISSUER = 'store.example'
const OTHER_ISSUER = 'other-store.example'
const PUB_KID = `${PUBLISHER}/keys/authority#1`
const HYBRID_KID = `${PUBLISHER}/keys/authority#hybrid`
const MANIFEST_ISSUED_AT = '2026-01-01T00:00:00Z'
const KEY_VALID_FROM = '2026-01-01T00:00:00Z'
const KEY_VALID_TO = '2026-12-31T23:59:59Z'
const AUTH_ISSUED_AT = '2026-02-01T00:00:00Z'
const RECEIPT_ISSUED_AT = '2026-03-01T00:00:00Z'
const ENTRY_VALID_FROM = '2026-02-01T00:00:00Z'
const ENTRY_VALID_TO = '2026-04-01T00:00:00Z'
const SERIES = 'publisher.example/works/EXG-001'

const hex = (s: string) => bytesToHex(sha256(new TextEncoder().encode(s)))
const ART_A = hex('authority-artifact-a')
const ART_B = hex('authority-artifact-b')
const ART_C = hex('authority-artifact-c')
const COMMITMENT = b64uEncode(new Uint8Array(32))

const PUB_ED = edSigner(30)
const PUB_HYBRID = hybridSigner(31)
const OTHER_ED = edSigner(32)

function manifestFor(
  signer: TestSigner,
  kid = PUB_KID,
  opts: { issuer?: string; validFrom?: string; validTo?: string | null; status?: string } = {},
): JsonObject {
  return buildKeyManifest(
    opts.issuer ?? PUBLISHER,
    1,
    MANIFEST_ISSUED_AT,
    [keyEntry(kid, signer, opts.validFrom ?? KEY_VALID_FROM, { validTo: opts.validTo ?? null, status: opts.status })],
    signer,
    kid,
  )
}

function scope(artifactSeries: string | null = SERIES, artifacts: string[] = [ART_A]): Record<string, unknown> {
  return { artifact_series: artifactSeries, artifacts: [...artifacts].sort() }
}

function authorizedIssuer(
  issuerId = ISSUER,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    issuer_id: issuerId,
    valid_from: ENTRY_VALID_FROM,
    valid_to: ENTRY_VALID_TO,
    permissions: [PERMISSION_ISSUE],
    scope: null,
    ...overrides,
  }
}

function authorizationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    authorization_version: 1,
    publisher: PUBLISHER,
    authorized_issuers: [authorizedIssuer()],
    issued_at: AUTH_ISSUED_AT,
    ...overrides,
  }
}

function makeAuthorization(
  signer: TestSigner = PUB_ED,
  overrides: Record<string, unknown> = {},
  kid = PUB_KID,
): JsonObject {
  const body = authorizationBody(overrides)
  return parse({ ...body, signature: signBlock(canonicalBytes(parse(body)), signer, kid) })
}

function makeAuthorizationWithEntries(entries: Record<string, unknown>[], signer = PUB_ED, kid = PUB_KID): JsonObject {
  return makeAuthorization(signer, { authorized_issuers: entries }, kid)
}

function manyEntries(count: number): Record<string, unknown>[] {
  return Array.from({ length: count }, (_unused, index) =>
    authorizedIssuer(`issuer${String(index).padStart(4, '0')}.example`),
  )
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function cloneAsObjectLiterals(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => cloneAsObjectLiterals(item))
  if (isRecord(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneAsObjectLiterals(item)]))
  }
  return value
}

function basePayload(): Record<string, unknown> {
  return {
    attest_version: '0.2',
    receipt_id: '01J1V5B4M9Z8QWERTY12345678',
    issued_at: RECEIPT_ISSUED_AT,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: { commitment: COMMITMENT, identifier_type: 'issuer-account', pubkey: null },
    work: {
      title: 'Example Game',
      publisher_id: PUBLISHER,
      artifact_series: SERIES,
      artifacts: [
        {
          role: 'installer',
          platform: 'windows-x86_64',
          filename: 'example-game-setup.exe',
          size_bytes: 734003200,
          sha256: ART_A,
        },
      ],
    },
    license: {
      grant: 'perpetual',
      revocability: 'none',
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://publisher.example/terms',
      legal_text_sha256: hex('authority-license-text'),
      jurisdiction_flags: { eu_usedsoft_asserted: false },
    },
  }
}

function deepMerge(base: Record<string, unknown>, overrides: Record<string, unknown>): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...base }
  for (const [key, value] of Object.entries(overrides)) {
    merged[key] = isRecord(value) && isRecord(merged[key]) ? deepMerge(merged[key], value) : value
  }
  return merged
}

function payload(overrides: Record<string, unknown> = {}): JsonObject {
  return parse(deepMerge(basePayload(), overrides))
}

const workOf = (document: JsonObject) => document['work'] as unknown as Record<string, unknown>

function expectFalseWithoutThrow(fn: () => boolean): void {
  let result: boolean | undefined
  expect(() => {
    result = fn()
  }).not.toThrow()
  expect(result).toBe(false)
}

function expectNullWithoutThrow(fn: () => Record<string, unknown> | null): void {
  let result: Record<string, unknown> | null | undefined
  expect(() => {
    result = fn()
  }).not.toThrow()
  expect(result).toBeNull()
}

function throwingObject(): Record<string, unknown> {
  return new Proxy(Object.create(null), {
    get() {
      throw new Error('hostile get')
    },
    ownKeys() {
      throw new Error('hostile ownKeys')
    },
    getOwnPropertyDescriptor() {
      throw new Error('hostile descriptor')
    },
  }) as Record<string, unknown>
}

describe('authorization_version predicate (v0.2 section 20.2 and 20.3)', () => {
  it('accepts every integer 1 <= n <= 2**53 - 1 as both number and bigint arrivals', () => {
    // Hand-rolled property: the boundaries plus a deterministic spread across
    // the safe-integer range, each asserted in BOTH arrivals. A JSON document
    // parsed strictly yields bigint; a hand-written view yields number.
    const values: number[] = [1, 2, 3, 255, 256, 65535, 2 ** 31 - 1, 2 ** 31, 2 ** 32, Number.MAX_SAFE_INTEGER]
    let seed = 0x2f6e2b1
    for (let i = 0; i < 256; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff
      values.push(1 + (seed % Number.MAX_SAFE_INTEGER))
    }
    for (const n of values) {
      expect(isAuthorizationVersion(n), `number arrival ${n}`).toBe(true)
      expect(isAuthorizationVersion(BigInt(n)), `bigint arrival ${n}`).toBe(true)
    }
  })

  it.each([
    ['zero number', 0],
    ['negative zero', -0],
    ['negative integer', -1],
    ['fraction', 1.5],
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['unsafe integer number', Number.MAX_SAFE_INTEGER + 1],
    ['zero bigint', 0n],
    ['negative bigint', -1n],
    ['2**53 bigint', 2n ** 53n],
    ['boolean', true],
    ['string', '1'],
    ['null', null],
    ['undefined', undefined],
  ])('rejects malformed current_authorization_version values as absent, never fatal: %s', (_label, value) => {
    expect(isAuthorizationVersion(value)).toBe(false)
  })
})

describe('publisher authorization document authentication (v0.2 section 20.2)', () => {
  it('round-trips a classical publisher-signed authorization document', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorization(PUB_ED)

    expect(verifyAuthorizationSignature(document, keyManifest)).toBe(true)
    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it('round-trips a hybrid authorization only when both section 13 signature legs are present', () => {
    const keyManifest = manifestFor(PUB_HYBRID, HYBRID_KID)
    const document = makeAuthorization(PUB_HYBRID, {}, HYBRID_KID)

    expect(verifyAuthorization(document, keyManifest)).toBe(true)
    delete ((document as Record<string, unknown>)['signature'] as Record<string, unknown>)['sig_ml_dsa_65']
    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('hashes SHA-256(JCS(document)) over the entire signed document, signature included', () => {
    const document = makeAuthorization(PUB_ED)
    const body: JsonObject = Object.create(null)
    for (const key of Object.keys(document)) if (key !== 'signature') body[key] = document[key]!

    expect(authorizationHash(document)).toBe(bytesToHex(sha256(canonicalBytes(document))))
    expect(authorizationHash(document)).not.toBe(bytesToHex(sha256(canonicalBytes(body))))
  })

  it('accepts number versions in the view predicate but rejects number versions in signed documents', () => {
    const keyManifest = manifestFor(PUB_ED)
    const bigintDocument = makeAuthorization(PUB_ED)
    const numberDocument = cloneAsObjectLiterals(bigintDocument) as Record<string, unknown>
    numberDocument['authorization_version'] = 1

    // The shared value predicate serves hand-written authority_view values too;
    // signed strict-JCS documents cross the wire as bigint, not as number.
    expect(isAuthorizationVersion(1)).toBe(true)
    expect(isAuthorizationVersion(1n)).toBe(true)
    expect(verifyAuthorization(bigintDocument, keyManifest)).toBe(true)
    expect(verifyAuthorization(numberDocument, keyManifest)).toBe(false)
  })

  it('accepts both null-prototype parsed objects and equivalent object literals', () => {
    const keyManifest = manifestFor(PUB_ED)
    const parsedDocument = makeAuthorization(PUB_ED)
    const literalDocument = cloneAsObjectLiterals(parsedDocument)

    expect(verifyAuthorization(parsedDocument, keyManifest)).toBe(true)
    expect(verifyAuthorization(literalDocument, keyManifest)).toBe(true)
  })

  it.each(['extra', '__proto__', 'constructor', 'toString'])(
    'rejects a non-closed document with unknown member %s',
    (member) => {
      const keyManifest = manifestFor(PUB_ED)
      const document = makeAuthorization(PUB_ED) as Record<string, unknown>
      Object.defineProperty(document, member, { value: 'surprise', enumerable: true, configurable: true })

      expect(verifyAuthorization(document, keyManifest)).toBe(false)
    },
  )

  it('rejects a document missing one of exactly five members', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorization(PUB_ED) as Record<string, unknown>
    delete document['publisher']

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it.each(['Publisher.Example', 'publisher.example.', 'publi\u0441her.example'])(
    'rejects publisher values that are not lowercase DNS names: %s',
    (publisherValue) => {
      const keyManifest = manifestFor(PUB_ED, PUB_KID, { issuer: publisherValue })
      const document = makeAuthorization(PUB_ED, { publisher: publisherValue })

      expect(verifyAuthorization(document, keyManifest)).toBe(false)
    },
  )

  it('keeps document publisher versus signing issuer binding outside authentication', () => {
    const keyManifest = manifestFor(PUB_ED, PUB_KID, { issuer: OTHER_PUBLISHER })
    const document = makeAuthorization(PUB_ED)

    // Section 20.4 step 6 performs the caller-visible triple binding; this
    // primitive only authenticates the document's own signature.
    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it('requires the resolving key manifest to be self-consistent', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorization(PUB_ED)
    keyManifest['issued_at'] = '2026-06-01T00:00:00Z'

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('requires signature.kid to resolve to a key entry', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorization(PUB_ED)
    const signature = (document as Record<string, unknown>)['signature'] as Record<string, unknown>
    signature['kid'] = `${PUBLISHER}/keys/authority#missing`

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it('checks issued_at against the signer key window, not the verifier clock', () => {
    const keyManifest = manifestFor(PUB_ED, PUB_KID, {
      validFrom: '2020-01-01T00:00:00Z',
      validTo: '2020-12-31T23:59:59Z',
    })
    const document = makeAuthorization(PUB_ED, { issued_at: '2020-06-01T00:00:00Z' })

    expect(verifyAuthorization(document, keyManifest)).toBe(true)
  })

  it.each(['2026-01-01T00:00:00Z', '2026-12-31T23:59:59Z'])(
    'treats signer key-window endpoint %s as inclusive',
    (issuedAt) => {
      const keyManifest = manifestFor(PUB_ED, PUB_KID, { validFrom: KEY_VALID_FROM, validTo: KEY_VALID_TO })
      const document = makeAuthorization(PUB_ED, { issued_at: issuedAt })

      expect(verifyAuthorization(document, keyManifest)).toBe(true)
    },
  )

  it('rejects an authorization signed by a retired key', () => {
    const keyManifest = manifestFor(PUB_ED, PUB_KID, { status: 'retired' })
    const document = makeAuthorization(PUB_ED)

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it.each(['2026-02-01T00:00:00+00:00', '2026-02-01T00:00:00.000Z', '2026-02-01T00:00:00'])(
    'rejects issued_at that is not strict ISO-8601 UTC Z: %s',
    (issuedAt) => {
      const keyManifest = manifestFor(PUB_ED)
      const document = makeAuthorization(PUB_ED, { issued_at: issuedAt })

      expect(verifyAuthorization(document, keyManifest)).toBe(false)
    },
  )
})

describe('authorized_issuers shape (v0.2 section 20.2)', () => {
  it('accepts an empty authorized_issuers array as significant on a first document', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorization(PUB_ED, { authorized_issuers: [] })

    expect(verifyAuthorization(document, keyManifest)).toBe(true)
    expect(entryForIssuer(document, ISSUER)).toBeNull()
  })

  it('accepts exactly MAX_AUTHORIZED_ISSUERS entries and rejects one more', () => {
    const keyManifest = manifestFor(PUB_ED)
    const atLimit = makeAuthorizationWithEntries(manyEntries(MAX_AUTHORIZED_ISSUERS))
    const overLimit = makeAuthorizationWithEntries(manyEntries(MAX_AUTHORIZED_ISSUERS + 1))

    expect(verifyAuthorization(atLimit, keyManifest)).toBe(true)
    expect(verifyAuthorization(overLimit, keyManifest)).toBe(false)
  })

  it('rejects an over-limit authorized_issuers array before reading signature bytes', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorizationWithEntries(manyEntries(MAX_AUTHORIZED_ISSUERS + 1)) as Record<string, unknown>
    const signature = Object.create(null) as Record<string, unknown>
    let signatureBytesRead = false
    signature['kid'] = PUB_KID
    Object.defineProperty(signature, 'sig', {
      enumerable: true,
      get() {
        signatureBytesRead = true
        return 'not-used'
      },
    })
    document['signature'] = signature

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
    expect(signatureBytesRead).toBe(false)
  })

  it('requires authorized_issuers to be strictly ascending by issuer_id', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorizationWithEntries([
      authorizedIssuer('z-store.example'),
      authorizedIssuer('a-store.example'),
    ])

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })

  it.each([
    [
      'valid entry first',
      [authorizedIssuer(ISSUER), authorizedIssuer(ISSUER, { permissions: [PERMISSION_DELEGATE] })],
    ],
    [
      'valid entry second',
      [authorizedIssuer(ISSUER, { permissions: [PERMISSION_DELEGATE] }), authorizedIssuer(ISSUER)],
    ],
  ])('rejects duplicate issuer_id as a shape error before signature bytes: %s', (_label, entries) => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorizationWithEntries(entries) as Record<string, unknown>
    const signature = document['signature'] as Record<string, unknown>
    let signatureBytesRead = false
    Object.defineProperty(signature, 'sig', {
      enumerable: true,
      configurable: true,
      get() {
        signatureBytesRead = true
        return 'not-used'
      },
    })

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
    expect(entryForIssuer(document, ISSUER)).toBeNull()
    expect(signatureBytesRead).toBe(false)
  })

  it.each(['Store.Example', 'store.example.', '\u0455tore.example'])(
    'rejects issuer_id values that are not lowercase DNS names: %s',
    (issuerId) => {
      const keyManifest = manifestFor(PUB_ED)
      const document = makeAuthorizationWithEntries([authorizedIssuer(issuerId)])

      expect(verifyAuthorization(document, keyManifest)).toBe(false)
    },
  )

  it.each(['extra', '__proto__', 'constructor', 'toString'])(
    'rejects a non-closed authorized_issuers entry with unknown member %s',
    (member) => {
      const keyManifest = manifestFor(PUB_ED)
      const entry = authorizedIssuer()
      Object.defineProperty(entry, member, { value: 'surprise', enumerable: true, configurable: true })
      const document = makeAuthorizationWithEntries([entry])

      expect(verifyAuthorization(document, keyManifest)).toBe(false)
    },
  )

  it('treats a missing scope member as malformed, not as scope null', () => {
    const keyManifest = manifestFor(PUB_ED)
    const entry = authorizedIssuer()
    delete entry['scope']
    const document = makeAuthorizationWithEntries([entry])

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
    expect(entryAuthorizesReceipt(entry, payload())).toBe(false)
  })

  it('rejects sparse authorized_issuers arrays and arrays with extra own properties', () => {
    const keyManifest = manifestFor(PUB_ED)
    const sparse = [] as unknown[]
    sparse.length = 1
    const sparseDocument = makeAuthorization(PUB_ED) as Record<string, unknown>
    sparseDocument['authorized_issuers'] = sparse

    const withExtra = [authorizedIssuer()]
    Object.defineProperty(withExtra, 'extra', { value: 'not-json', enumerable: true })
    const extraDocument = makeAuthorization(PUB_ED) as Record<string, unknown>
    extraDocument['authorized_issuers'] = withExtra

    expectFalseWithoutThrow(() => verifyAuthorization(sparseDocument, keyManifest))
    expectFalseWithoutThrow(() => verifyAuthorization(extraDocument, keyManifest))
  })

  it('carries unregistered permissions but requires code-point sorted, duplicate-free order', () => {
    const keyManifest = manifestFor(PUB_ED)
    const astral = '\u{10000}'
    const privateUse = '\ue000'
    const codePointSorted = makeAuthorizationWithEntries([
      authorizedIssuer(ISSUER, { permissions: [PERMISSION_ISSUE, privateUse, astral] }),
    ])
    const utf16SortedOnly = makeAuthorizationWithEntries([
      authorizedIssuer(ISSUER, { permissions: [PERMISSION_ISSUE, astral, privateUse] }),
    ])

    expect(privateUse < astral).toBe(false)
    expect(astral < privateUse).toBe(true)
    expect(verifyAuthorization(codePointSorted, keyManifest)).toBe(true)
    expect(verifyAuthorization(utf16SortedOnly, keyManifest)).toBe(false)
  })
})

describe('entryForIssuer (v0.2 section 20.4 membership)', () => {
  it('returns the single entry whose issuer_id equals the receipt issuer.id', () => {
    const document = makeAuthorizationWithEntries([authorizedIssuer('a-store.example'), authorizedIssuer(ISSUER)])

    expect(entryForIssuer(document, ISSUER)).toEqual(authorizedIssuer(ISSUER))
  })

  it('returns null for an absent issuer and for malformed issuerId input', () => {
    const document = makeAuthorizationWithEntries([authorizedIssuer(ISSUER)])

    expect(entryForIssuer(document, OTHER_ISSUER)).toBeNull()
    expect(entryForIssuer(document, 123)).toBeNull()
    expect(entryForIssuer(null, ISSUER)).toBeNull()
  })
})

describe('entryAuthorizesReceipt (v0.2 section 20.4 membership)', () => {
  it('authorizes only when issuer_id equals receipt issuer.id', () => {
    expect(entryAuthorizesReceipt(authorizedIssuer(ISSUER), payload())).toBe(true)
    expect(entryAuthorizesReceipt(authorizedIssuer(OTHER_ISSUER), payload())).toBe(false)
  })

  it.each([ENTRY_VALID_FROM, ENTRY_VALID_TO])(
    'treats receipt issued_at window endpoint %s as inclusive',
    (issuedAt) => {
      const document = payload({ issued_at: issuedAt })

      expect(entryAuthorizesReceipt(authorizedIssuer(), document)).toBe(true)
    },
  )

  it('uses receipt issued_at for prospective de-authorization and never the verifier clock', () => {
    const entry = authorizedIssuer(ISSUER, {
      valid_from: '2020-01-01T00:00:00Z',
      valid_to: '2020-12-31T23:59:59Z',
    })
    const oldReceipt = payload({ issued_at: '2020-06-01T00:00:00Z' })

    expect(entryAuthorizesReceipt(entry, oldReceipt)).toBe(true)
  })

  it('treats valid_to null as an open interval', () => {
    const entry = authorizedIssuer(ISSUER, { valid_to: null })
    const futureReceipt = payload({ issued_at: '2040-01-01T00:00:00Z' })

    expect(entryAuthorizesReceipt(entry, futureReceipt)).toBe(true)
  })

  it.each(['2026-03-01T00:00:00+00:00', '2026-03-01T00:00:00.000Z', '2026-03-01T00:00:00'])(
    'rejects receipt issued_at that is not strict ISO-8601 UTC Z: %s',
    (issuedAt) => {
      expect(entryAuthorizesReceipt(authorizedIssuer(), payload({ issued_at: issuedAt }))).toBe(false)
    },
  )

  it('does not honor delegate unless issue is also present', () => {
    const delegateOnly = authorizedIssuer(ISSUER, { permissions: [PERMISSION_DELEGATE] })
    const issueWithReserved = authorizedIssuer(ISSUER, {
      permissions: [PERMISSION_DELEGATE, PERMISSION_ISSUE, 'zz-unregistered'],
    })

    expect(entryAuthorizesReceipt(delegateOnly, payload())).toBe(false)
    expect(entryAuthorizesReceipt(issueWithReserved, payload())).toBe(true)
  })

  it('treats scope null as the publisher entire catalog', () => {
    const entry = authorizedIssuer(ISSUER, { scope: null })
    const otherWork = payload({
      work: {
        artifact_series: 'publisher.example/works/OTHER',
        artifacts: [{ sha256: ART_C }],
      },
    })

    expect(entryAuthorizesReceipt(entry, otherWork)).toBe(true)
  })

  it('covers a receipt through matching artifact_series even when artifacts are absent or empty', () => {
    const seriesScoped = authorizedIssuer(ISSUER, { scope: scope(SERIES, [ART_B]) })
    const absentArtifacts = payload({ work: { artifact_series: SERIES } })
    delete workOf(absentArtifacts)['artifacts']
    const emptyArtifacts = payload({ work: { artifact_series: SERIES, artifacts: [] } })

    expect(entryAuthorizesReceipt(seriesScoped, absentArtifacts)).toBe(true)
    expect(entryAuthorizesReceipt(seriesScoped, emptyArtifacts)).toBe(true)
  })

  it('does not let a hash-scoped entry cover by vacuous quantification over absent or empty artifacts', () => {
    const hashScoped = authorizedIssuer(ISSUER, { scope: scope(null, [ART_A]) })
    const absentArtifacts = payload()
    delete workOf(absentArtifacts)['artifacts']
    const emptyArtifacts = payload({ work: { artifacts: [] } })

    expect(entryAuthorizesReceipt(hashScoped, absentArtifacts)).toBe(false)
    expect(entryAuthorizesReceipt(hashScoped, emptyArtifacts)).toBe(false)
  })

  it('requires every receipt artifact hash to be covered by non-null scope', () => {
    const scoped = authorizedIssuer(ISSUER, { scope: scope(null, [ART_A]) })
    const twoArtifacts = payload({
      work: {
        artifacts: [
          { sha256: ART_A, filename: 'a.bin' },
          { sha256: ART_B, filename: 'b.bin' },
        ],
      },
    })

    expect(entryAuthorizesReceipt(scoped, twoArtifacts)).toBe(false)
  })

  it('rejects malformed scope objects and malformed valid_to undefined without throwing', () => {
    const entryWithExtraScope = authorizedIssuer(ISSUER, { scope: { ...scope(), extra: true } })
    const entryWithUndefinedValidTo = authorizedIssuer()
    entryWithUndefinedValidTo['valid_to'] = undefined

    expectFalseWithoutThrow(() => entryAuthorizesReceipt(entryWithExtraScope, payload()))
    expectFalseWithoutThrow(() => entryAuthorizesReceipt(entryWithUndefinedValidTo, payload()))
  })
})

describe('authority_view structural ceiling (v0.2 section 20.3)', () => {
  it('counts authorizations and never inspects elements at the 64-document ceiling', () => {
    const hostileElements = Array.from({ length: MAX_AUTHORITY_DOCUMENTS }, () => throwingObject())

    expect(withinStructuralCeiling(hostileElements)).toBe(true)
    expect(withinStructuralCeiling([...hostileElements, throwingObject()])).toBe(false)
  })

  it('counts sparse arrays and ignores extra array properties when checking the document ceiling', () => {
    const sparse = new Array(MAX_AUTHORITY_DOCUMENTS)
    Object.defineProperty(sparse, 'extra', { value: throwingObject(), enumerable: true })

    expect(withinStructuralCeiling(sparse)).toBe(true)
  })

  it('fails closed and does not throw when length itself is hostile', () => {
    const hostileArray = new Proxy([], {
      get(target, prop, receiver) {
        if (prop === 'length') throw new Error('hostile length')
        return Reflect.get(target, prop, receiver)
      },
    })

    expectFalseWithoutThrow(() => withinStructuralCeiling(hostileArray))
  })
})

describe('fail-closed behavior on hostile JS values', () => {
  it('verifyAuthorization and verifyAuthorizationSignature never throw on hostile documents or manifests', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorization(PUB_ED)
    const hostile = throwingObject()

    expectFalseWithoutThrow(() => verifyAuthorization(hostile, keyManifest))
    expectFalseWithoutThrow(() => verifyAuthorizationSignature(hostile, keyManifest))
    expectFalseWithoutThrow(() => verifyAuthorization(document, hostile as JsonObject))
    expectFalseWithoutThrow(() => verifyAuthorizationSignature(document, hostile as JsonObject))
  })

  it('entry selectors and membership predicates never throw on hostile entries or receipts', () => {
    const hostile = throwingObject()

    expectNullWithoutThrow(() => entryForIssuer(hostile, ISSUER))
    expectFalseWithoutThrow(() => entryAuthorizesReceipt(hostile, payload()))
    expectFalseWithoutThrow(() => entryAuthorizesReceipt(authorizedIssuer(), hostile))
  })

  it('fails closed on null, arrays, primitives, getters and proxies nobody expected', () => {
    const keyManifest = manifestFor(PUB_ED)
    const getterDocument = Object.create(null) as Record<string, unknown>
    Object.defineProperty(getterDocument, 'authorization_version', {
      enumerable: true,
      get() {
        throw new Error('hostile authorization_version')
      },
    })

    for (const document of [null, 42, 'authorization', [], {}, getterDocument, throwingObject()]) {
      expectFalseWithoutThrow(() => verifyAuthorization(document, keyManifest))
      expectNullWithoutThrow(() => entryForIssuer(document, ISSUER))
    }
  })

  it('rejects documents signed by an unrelated key even when the body shape is otherwise valid', () => {
    const keyManifest = manifestFor(PUB_ED)
    const document = makeAuthorization(OTHER_ED)

    expect(verifyAuthorization(document, keyManifest)).toBe(false)
  })
})
