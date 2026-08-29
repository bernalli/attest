import { describe, expect, test } from 'vitest'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalBytes, isOk, loadsStrict, verify } from '../src/index.js'

type Jsonish = Record<string, unknown>

const ZERO_HASH = '0'.repeat(64)
const ONE_HASH = '1'.repeat(64)
const TWO_HASH = '2'.repeat(64)
const RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'
const NEW_RECEIPT_ID = '01JZ5PDHT0000G40R40M30E210'
const ISSUER = 'merchant.example'
const KID = `${ISSUER}/keys/2026-q1#ed25519-1`
const SECOND_KID = `${ISSUER}/keys/2026-q1#ed25519-2`

const seed = (label: string) => createHash('sha256').update(label).digest()
const issuerSk = seed('blind-integer-representation issuer')
const issuerPk = ed25519.getPublicKey(issuerSk)
const issuerMl = ml_dsa65.keygen(seed('blind-integer-representation issuer ml-dsa-65'))
const issuer2Sk = seed('blind-integer-representation issuer 2')
const issuer2Pk = ed25519.getPublicKey(issuer2Sk)
const issuer2Ml = ml_dsa65.keygen(seed('blind-integer-representation issuer 2 ml-dsa-65'))
const holderSk = seed('blind-integer-representation holder')
const holderPk = ed25519.getPublicKey(holderSk)
const newHolderPk = ed25519.getPublicKey(seed('blind-integer-representation new holder'))
const logSk = seed('blind-integer-representation log')
const logMl = ml_dsa65.keygen(seed('blind-integer-representation log ml-dsa-65'))

const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex')
const utf8 = (text: string) => new TextEncoder().encode(text)

const sign = (
  document: Jsonish,
  sk: Uint8Array,
  signatureMember: string,
  kid = KID,
  mlSecretKey?: Uint8Array,
): Jsonish => {
  const unsigned = { ...document }
  delete unsigned[signatureMember]
  const signedBytes = canonicalBytes(unsigned as never)
  const signature: Jsonish = { kid, sig: b64u(ed25519.sign(signedBytes, sk)) }
  if (mlSecretKey) signature.sig_ml_dsa_65 = b64u(ml_dsa65.sign(signedBytes, mlSecretKey))
  return { ...document, [signatureMember]: signature }
}

const strict = <T>(value: T): T => loadsStrict(canonicalBytes(value as never)) as T

const numbersForSafeIntegers = (value: unknown): unknown => {
  if (typeof value === 'bigint') return Number(value)
  if (Array.isArray(value)) return value.map(numbersForSafeIntegers)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, numbersForSafeIntegers(v)]),
    )
  }
  return value
}

const jsonTextWithRawValue = (field: string, valueSource: string): string =>
  `{"${field}":${valueSource},"ok":true}`

const trustStore = (manifest: Jsonish): Jsonish => ({
  manifests: { [ISSUER]: manifest },
  provenance: { [ISSUER]: 'tls' },
  chains: {},
})

const stage2Options = (): Jsonish => ({
  logKeys: [
    {
      origin: 'attest-transparency-log.example/2026',
      name: 'attest-log-2026',
      ed25519Pub: ed25519.getPublicKey(logSk),
      mldsaPub: logMl.publicKey,
    },
  ],
  anchorPolicy: { pinnedHeaders: {}, crqcHorizon: null },
})

const keyEntry = (
  kid: string,
  pub: Uint8Array,
  hybrid: boolean,
  mlPublicKey: Uint8Array,
  status = 'active',
): Jsonish => ({
  kid,
  pub: b64u(pub),
  ...(hybrid ? { pub_ml_dsa_65: b64u(mlPublicKey) } : {}),
  valid_from: '2025-01-01T00:00:00Z',
  valid_to: null,
  status,
})

const activeManifest = (hybrid = false): Jsonish =>
  sign(
    {
      issuer: ISSUER,
      manifest_version: 1n,
      issued_at: '2026-01-01T00:00:00Z',
      keys: [
        keyEntry(KID, issuerPk, hybrid, issuerMl.publicKey),
        keyEntry(SECOND_KID, issuer2Pk, hybrid, issuer2Ml.publicKey),
      ],
    },
    issuerSk,
    'manifest_signature',
    KID,
    hybrid ? issuerMl.secretKey : undefined,
  )

const compromisedManifest = (hybrid = false): Jsonish =>
  sign(
    {
      issuer: ISSUER,
      manifest_version: 2n,
      issued_at: '2026-02-01T00:00:00Z',
      keys: [
        keyEntry(KID, issuerPk, hybrid, issuerMl.publicKey, 'compromised'),
        keyEntry(SECOND_KID, issuer2Pk, hybrid, issuer2Ml.publicKey),
      ],
    },
    issuer2Sk,
    'manifest_signature',
    SECOND_KID,
    hybrid ? issuer2Ml.secretKey : undefined,
  )

const basePayload = (overrides: Partial<Jsonish> = {}): Jsonish => ({
  attest_version: '0.1',
  receipt_id: RECEIPT_ID,
  issued_at: '2026-01-15T00:00:00Z',
  supersedes: null,
  issuer: { id: ISSUER, display_name: 'Merchant' },
  buyer: {
    commitment: b64u(new Uint8Array(32)),
    identifier_type: 'issuer-account',
    pubkey: b64u(holderPk),
  },
  work: {
    title: 'Blind Integer Fixture',
    publisher: 'Merchant',
    publisher_id: ISSUER,
    identifiers: { sku: 'blind-integer-fixture' },
    artifact_series: 'series-a',
    artifacts: [
      {
        role: 'game',
        platform: 'pc',
        filename: 'fixture.zip',
        size_bytes: 5n,
        sha256: ONE_HASH,
      },
    ],
  },
  license: {
    grant: 'perpetual',
    revocability: 'policy',
    transferable: false,
    drm: 'drm-free',
    terms_uri: 'https://merchant.example/terms',
    legal_text_sha256: ZERO_HASH,
  },
  survivability: {
    redownload_right: true,
    end_of_life: 'artifacts-remain-redownloadable',
  },
  ...overrides,
})

const envelopeBytes = (payload: Jsonish): Uint8Array => {
  const signedBytes = canonicalBytes(payload as never)
  const signatures =
    payload.attest_version === '0.2'
      ? [
          { kid: KID, alg: 'Ed25519', sig: b64u(ed25519.sign(signedBytes, issuerSk)) },
          { kid: KID, alg: 'ML-DSA-65', sig: b64u(ml_dsa65.sign(signedBytes, issuerMl.secretKey)) },
        ]
      : [{ kid: KID, alg: 'Ed25519', sig: b64u(ed25519.sign(signedBytes, issuerSk)) }]
  return canonicalBytes({
    payload,
    signatures,
  } as never)
}

const revocationRecord = (status = 'revoked', receiptId = RECEIPT_ID, hybrid = false): Jsonish =>
  sign(
    {
      receipt_id: receiptId,
      status,
      revoked_at: '2026-01-20T00:00:00Z',
    },
    issuerSk,
    'signature',
    KID,
    hybrid ? issuerMl.secretKey : undefined,
  )

const transferRecord = (hybrid = false): Jsonish => {
  const transferredAt = '2026-01-20T00:00:00Z'
  const newHolder = b64u(newHolderPk)
  const message = new Uint8Array([
    ...utf8('Attest-transfer-authorization-v1'),
    0,
    ...utf8(RECEIPT_ID),
    0,
    ...utf8(newHolder),
    0,
    ...utf8(transferredAt),
  ])
  return sign(
    {
      receipt_id: RECEIPT_ID,
      new_receipt_id: NEW_RECEIPT_ID,
      new_holder_pubkey: newHolder,
      transferred_at: transferredAt,
      holder_authorization: { sig: b64u(ed25519.sign(message, holderSk)) },
    },
    issuerSk,
    'signature',
    KID,
    hybrid ? issuerMl.secretKey : undefined,
  )
}

const grantDocument = (overrides: Partial<Jsonish> = {}): Jsonish =>
  sign(
    {
      grant_version: 1n,
      publisher: ISSUER,
      scope: { artifact_series: 'series-a', artifacts: [ONE_HASH] },
      permissions: ['deliver-to-holder'],
      activation: {
        modes: ['publisher-declaration'],
        fixed_date: null,
        successor_ids: [],
      },
      unprotected_build: true,
      legal_text_uri: 'https://merchant.example/grant',
      legal_text_sha256: TWO_HASH,
      jurisdiction: 'CH',
      issued_at: '2026-01-10T00:00:00Z',
      ...overrides,
    },
    issuerSk,
    'signature',
    KID,
    issuerMl.secretKey,
  )

const declarationDocument = (scope: Jsonish = { artifact_series: 'series-a', artifacts: [ONE_HASH] }): Jsonish =>
  sign(
    {
      publisher: ISSUER,
      scope,
      declared_at: '2026-02-01T00:00:00Z',
    },
    issuerSk,
    'signature',
    KID,
    issuerMl.secretKey,
  )

const pledgedReceipt = (grant: Jsonish): Uint8Array =>
  envelopeBytes(
    basePayload({
      attest_version: '0.2',
      license: {
        grant: 'perpetual',
        revocability: 'policy',
        transferable: false,
        drm: 'drm-free',
        terms_uri: 'https://merchant.example/terms',
        legal_text_sha256: ZERO_HASH,
        preservation_pledge: {
          pledge: 'sunset-grant-v1',
          grant_uri: 'https://merchant.example/grant',
          grant_sha256: hex(createHash('sha256').update(canonicalBytes(grant as never)).digest()),
        },
      },
      survivability: {
        redownload_right: true,
        end_of_life: 'sunset-grant',
      },
    }),
  )

const callReturns = (
  fn: () => Jsonish,
  expected: Partial<Jsonish> & { ok?: boolean },
  maxMs = 250,
): { result: Jsonish; elapsedMs: number } => {
  const start = performance.now()
  const result = fn()
  const elapsedMs = performance.now() - start
  const { ok, ...components } = expected
  expect(elapsedMs).toBeLessThan(maxMs)
  expect(result).toMatchObject(components)
  if (ok !== undefined) expect(isOk(result as never)).toBe(ok)
  return { result, elapsedMs }
}

const expectNoPublicException = (fn: () => Jsonish, expected: Partial<Jsonish> & { ok?: boolean }): Jsonish => {
  let result: Jsonish | undefined
  expect(() => {
    result = fn()
  }).not.toThrow()
  const { ok, ...components } = expected
  expect(result).toMatchObject(components)
  if (ok !== undefined) expect(isOk(result as never)).toBe(ok)
  return result as Jsonish
}

describe('blind integer representation admission across verify evidence rails', () => {
  test('RESTRITTIVA revocation_view: hostile number-bearing unit is isolated and genuine revocation still invalidates', () => {
    const manifest = activeManifest()
    const payload = basePayload()
    const good = revocationRecord()
    const bad = { ...good, sequence: 5 }
    const result = expectNoPublicException(
      () => verify(envelopeBytes(payload), trustStore(manifest) as never, [bad, good] as never) as never,
      { signature: 'valid', schema: 'valid', revocation: 'revoked', ok: false },
    )
    expect(result.revocation).toBe('revoked')
    expect(isOk(result as never)).toBe(false)
  })

  test('PERMISSIVA revocation_view: live number freshness marker cannot create a false valid over a genuine revoked record', () => {
    const manifest = activeManifest()
    const good = revocationRecord()
    const badFreshness = { ...revocationRecord('unknown-status', '01JZ5PDHT0000G40R40M30E211'), feed_version: 5 }
    const result = expectNoPublicException(
      () => verify(envelopeBytes(basePayload()), trustStore(manifest) as never, [badFreshness, good] as never) as never,
      { signature: 'valid', schema: 'valid', revocation: 'revoked', ok: false },
    )
    expect(result.revocation).toBe('revoked')
    expect(isOk(result as never)).toBe(false)
  })

  test('RESTRITTIVA grant_view: invalid live-number later_grant is isolated and genuine declaration still activates', () => {
    const manifest = activeManifest(true)
    const floor = grantDocument()
    const invalidLater = numbersForSafeIntegers(grantDocument({ grant_version: 2n }))
    const declaration = declarationDocument()
    const result = expectNoPublicException(
      () =>
        verify(
          pledgedReceipt(floor),
          trustStore(manifest) as never,
          null,
          null,
          undefined,
          { grantView: { grant: floor, later_grants: [invalidLater], declarations: [declaration] } } as never,
        ) as never,
      { signature: 'valid', schema: 'valid', grant: 'activated', grant_trust: 'verified', ok: true },
    )
    expect(result.grant).toBe('activated')
    expect(isOk(result as never)).toBe(true)
  })

  test('RESTRITTIVA compromise_view: malformed number claim is isolated and genuine compromise claim invalidates', () => {
    const manifest = activeManifest()
    const goodClaim = { manifest: compromisedManifest(), evidence: { entry: null, tree_size: 1 } }
    const badClaim = {
      manifest: { ...compromisedManifest(), manifest_version: 2 },
      evidence: { entry: null, tree_size: 1 },
    }
    const result = expectNoPublicException(
      () =>
        verify(envelopeBytes(basePayload()), trustStore(manifest) as never, null, null, undefined, {
          compromiseView: [badClaim, goodClaim],
        } as never) as never,
      { signature: 'invalid', schema: 'not_checked', ok: false },
    )
    expect(result.signature).toBe('invalid')
    expect(isOk(result as never)).toBe(false)
  })

  test('RESTRITTIVA compromise_view: live and strict parsed declaration versions produce identical compromised verdicts', () => {
    const manifest = activeManifest()
    const liveClaim = { manifest: numbersForSafeIntegers(compromisedManifest()), evidence: { entry: null, tree_size: 1 } }
    const strictClaim = strict({ manifest: compromisedManifest(), evidence: { entry: null, tree_size: 1n } })
    const live = expectNoPublicException(
      () =>
        verify(envelopeBytes(basePayload()), trustStore(manifest) as never, null, null, undefined, {
          compromiseView: [liveClaim],
        } as never) as never,
      { signature: 'invalid', schema: 'not_checked', ok: false },
    )
    const parsed = expectNoPublicException(
      () =>
        verify(envelopeBytes(basePayload()), trustStore(manifest) as never, null, null, undefined, {
          compromiseView: [strictClaim],
        } as never) as never,
      { signature: 'invalid', schema: 'not_checked', ok: false },
    )
    expect({ signature: live.signature, schema: live.schema, ok: isOk(live as never) }).toEqual({
      signature: parsed.signature,
      schema: parsed.schema,
      ok: isOk(parsed as never),
    })
  })

  test('RESTRITTIVA transfer_view: malformed number evidence is isolated and unbacked transferred revocation stays invalid_revocation_ignored', () => {
    const manifest = activeManifest(true)
    const transferred = revocationRecord('transferred', RECEIPT_ID, true)
    const result = expectNoPublicException(
      () =>
        verify(
          envelopeBytes(basePayload({ attest_version: '0.2', license: { ...(basePayload().license as Jsonish), transferable: true } })),
          trustStore(manifest) as never,
          [transferred] as never,
          null,
          undefined,
          { transferView: [{ record: transferRecord(true), evidence: { entry: null, tree_size: 1 } }] } as never,
        ) as never,
      { signature: 'valid', schema: 'valid', revocation: 'invalid_revocation_ignored', ok: true },
    )
    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(isOk(result as never)).toBe(true)
  })

  test('RESTRITTIVA revocation_evidence: number-typed evidence cannot turn an unlogged deadline record into revoked', () => {
    const manifest = activeManifest()
    const payload = basePayload({
      issued_at: '2026-01-15T00:00:00Z',
      license: {
        ...(basePayload().license as Jsonish),
        revocability: 'refund_window',
        revocation_window_days: 14n,
      },
    })
    const record = revocationRecord()
    const result = expectNoPublicException(
      () =>
        verify(envelopeBytes(payload), trustStore(manifest) as never, [record] as never, null, undefined, {
          ...stage2Options(),
          revocationEvidence: { entry: null, tree_size: 1 },
        } as never) as never,
      { signature: 'valid', schema: 'valid', revocation: 'invalid_revocation_ignored', ok: true },
    )
    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(isOk(result as never)).toBe(true)
  })

  test('RESTRITTIVA transparency evidence: live and strict parsed integer fields produce identical safe no-standing verdicts', () => {
    const manifest = activeManifest()
    const liveEvidence = { entry: { type: 'receipt', issuer: ISSUER, core_sha256: ZERO_HASH }, leaf_index: 0, tree_size: 1 }
    const strictEvidence = loadsStrict(
      utf8(`{"entry":{"type":"receipt","issuer":"${ISSUER}","core_sha256":"${ZERO_HASH}"},"leaf_index":0,"tree_size":1}`),
    )
    const live = expectNoPublicException(
      () =>
        verify(envelopeBytes(basePayload()), trustStore(manifest) as never, null, null, undefined, {
          ...stage2Options(),
          transparency: liveEvidence,
        } as never) as never,
      { signature: 'valid', schema: 'valid', transparency: 'not_checked', corroboration: 'none', ok: true },
    )
    const parsed = expectNoPublicException(
      () =>
        verify(envelopeBytes(basePayload()), trustStore(manifest) as never, null, null, undefined, {
          ...stage2Options(),
          transparency: strictEvidence,
        } as never) as never,
      { signature: 'valid', schema: 'valid', transparency: 'not_checked', corroboration: 'none', ok: true },
    )
    expect({
      transparency: live.transparency,
      corroboration: live.corroboration,
      ok: isOk(live as never),
    }).toEqual({
      transparency: parsed.transparency,
      corroboration: parsed.corroboration,
      ok: isOk(parsed as never),
    })
  })
})

describe('blind integer representation borders on caller-provided JSON values', () => {
  const borderCases: Array<[string, unknown, string | null, boolean]> = [
    ['1', 1, '1', true],
    ['2^53-1', Number.MAX_SAFE_INTEGER, '9007199254740991', true],
    ['2^53', 9007199254740992, '9007199254740992', false],
    ['0', 0, '0', true],
    ['negative', -5, '-5', true],
    ['true', true, 'true', false],
    ['string 5', '5', '"5"', false],
    ['null', null, 'null', false],
    ['undefined', undefined, null, false],
    ['NaN', Number.NaN, 'NaN', false],
    ['1.5', 1.5, '1.5', false],
    ['minus zero', -0, '-0', true],
  ]

  test.each(borderCases)('RESTRITTIVA integer border %s returns an exact verdict', (_name, liveValue, source, admissible) => {
    const liveResult = expectNoPublicException(
      () => {
        const view = { entry: { type: 'receipt', issuer: ISSUER, core_sha256: ZERO_HASH }, leaf_index: liveValue, tree_size: 1 }
        return verify(envelopeBytes(basePayload()), trustStore(activeManifest()) as never, null, null, undefined, {
          ...stage2Options(),
          transparency: view,
        } as never) as never
      },
      { signature: 'valid', schema: 'valid', transparency: 'not_checked', corroboration: 'none', ok: true },
    )
    expect(liveResult.transparency).toBe('not_checked')
    expect(isOk(liveResult as never)).toBe(true)

    if (admissible && source !== null) {
      const parsed = loadsStrict(utf8(jsonTextWithRawValue('n', source)))
      expect(parsed).toMatchObject({ n: BigInt(Object.is(liveValue, -0) ? 0 : Number(liveValue)) })
    }
  })
})

describe('blind grant-view admission is per member and getter-free', () => {
  test('RESTRITTIVA grant_view member getter that throws is absent, returns dormant with verified grant_trust', () => {
    const floor = grantDocument()
    const view = { grant: floor } as Jsonish
    Object.defineProperty(view, 'declarations', {
      enumerable: true,
      get() {
        throw new Error('declarations getter must not escape')
      },
    })
    const result = callReturns(
      () =>
        verify(pledgedReceipt(floor), trustStore(activeManifest(true)) as never, null, null, undefined, {
          grantView: view,
        } as never) as never,
      { signature: 'valid', schema: 'valid', grant: 'dormant', grant_trust: 'verified', ok: true },
    ).result
    expect(result.grant).toBe('dormant')
    expect(result.grant_trust).toBe('verified')
  })

  test('PERMISSIVA inherited grant_view declaration does not activate a grant', () => {
    const floor = grantDocument()
    const proto = { declarations: [declarationDocument()] }
    const view = Object.create(proto) as Jsonish
    view.grant = floor
    const result = callReturns(
      () =>
        verify(pledgedReceipt(floor), trustStore(activeManifest(true)) as never, null, null, undefined, {
          grantView: view,
        } as never) as never,
      { signature: 'valid', schema: 'valid', grant: 'dormant', grant_trust: 'verified', ok: true },
    ).result
    expect(result.grant).toBe('dormant')
    expect(isOk(result as never)).toBe(true)
  })

  test('PERMISSIVA grant_view getter declaration does not synthesize activation', () => {
    const floor = grantDocument()
    const view = { grant: floor } as Jsonish
    Object.defineProperty(view, 'declarations', {
      enumerable: true,
      get() {
        return [declarationDocument()]
      },
    })
    const result = callReturns(
      () =>
        verify(pledgedReceipt(floor), trustStore(activeManifest(true)) as never, null, null, undefined, {
          grantView: view,
        } as never) as never,
      { signature: 'valid', schema: 'valid', grant: 'dormant', grant_trust: 'verified', ok: true },
    ).result
    expect(result.grant).toBe('dormant')
    expect(isOk(result as never)).toBe(true)
  })

  test('PERMISSIVA proxy traps deliver whatever verdict the genuine grant they carry deserves', () => {
    const floor = grantDocument()
    const proxy = new Proxy(
      {},
      {
        get(_target, prop) {
          if (prop === 'grant') return floor
          if (prop === 'declarations') return [declarationDocument()]
          return undefined
        },
        has() {
          return true
        },
        ownKeys() {
          return ['grant', 'declarations']
        },
        getOwnPropertyDescriptor(_target, prop) {
          return { configurable: true, enumerable: true, value: this.get?.(_target, prop, proxy) }
        },
      },
    )
    // The evidence boundary's claim was deliberately narrowed: it guarantees a
    // single, bounded, data-property-only read whose reconstruction is what
    // everything downstream sees — it does not guarantee recognizing a Proxy.
    // A `getOwnPropertyDescriptor` trap answering with a DATA descriptor is not
    // distinguishable from a stored one, so a Proxy that consistently delivers
    // a genuinely-signed grant through its own data gets the same verdict as
    // passing that grant raw, not a synthetic rejection.
    const result = callReturns(
      () =>
        verify(pledgedReceipt(floor), trustStore(activeManifest(true)) as never, null, null, undefined, {
          grantView: proxy,
        } as never) as never,
      { signature: 'valid', schema: 'valid', grant: 'activated', grant_trust: 'verified', ok: true },
    ).result
    expect(result.grant).toBe('activated')
    expect(result.grant_trust).toBe('verified')
    expect(isOk(result as never)).toBe(true)
  })
})

describe('blind wall-clock limits for hostile lazy containers', () => {
  test('RESTRITTIVA lazy grant_view getter returns inside 250ms with exact not_checked verdict', () => {
    const floor = grantDocument()
    const view = {} as Jsonish
    Object.defineProperty(view, 'grant', {
      enumerable: true,
      get() {
        let n = 0
        while (n < 1000) n += 1
        throw new Error('lazy grant getter must be confined')
      },
    })
    callReturns(
      () =>
        verify(pledgedReceipt(floor), trustStore(activeManifest(true)) as never, null, null, undefined, {
          grantView: view,
        } as never) as never,
      { signature: 'valid', schema: 'valid', grant: 'not_checked', grant_trust: 'not_checked', ok: true },
    )
  })

  test('RESTRITTIVA array-like revocation_view with lied length raises within 250ms as a malformed container', () => {
    const arrayLike = { length: 2 ** 31, 0: revocationRecord() }
    // revocation_view's container SHAPE is caller-contract (spec commit
    // 12cd568): a non-Array container raises TypeError, matching the Python
    // core exactly — the lied-length wall-clock guarantee below still holds,
    // it just resolves as a rejection instead of a tolerated 'unknown'.
    const start = performance.now()
    expect(() =>
      verify(envelopeBytes(basePayload()), trustStore(activeManifest()) as never, arrayLike as never),
    ).toThrow(TypeError)
    expect(performance.now() - start).toBeLessThan(250)
  })

  test('RESTRITTIVA iterable transparency evidence returns inside 250ms with exact no-standing verdict', () => {
    const iterable = {
      entry: { type: 'receipt', issuer: ISSUER, core_sha256: ZERO_HASH },
      leaf_index: 0,
      tree_size: 1,
      [Symbol.iterator]: function* () {
        for (let i = 0; i < 1024; i += 1) yield i
        throw new Error('iterator must not be consumed as evidence')
      },
    }
    callReturns(
      () =>
        verify(envelopeBytes(basePayload()), trustStore(activeManifest()) as never, null, null, undefined, {
          ...stage2Options(),
          transparency: iterable,
        } as never) as never,
      { signature: 'valid', schema: 'valid', transparency: 'not_checked', corroboration: 'none', ok: true },
    )
  })
})
