import { describe, expect, it } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { b64uEncode } from '../src/b64u.js'
import { canonicalBytes, loadsStrict } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import {
  checkContinuity,
  duplicateKids,
  findKey,
  verifyArtifactManifest,
  verifyKeyManifest,
} from '../src/manifests.js'
import * as messages from '../src/messages.js'
import { verifyRecord } from '../src/revocation.js'
import { isOk, verify } from '../src/verify.js'

const enc = (value: string) => new TextEncoder().encode(value)
const parse = (value: unknown): JsonObject => loadsStrict(enc(JSON.stringify(value))) as JsonObject

const ISSUER = 'store.example.com'
const SIGNER_KID = `${ISSUER}/keys/signer#ed25519-1`
const OTHER_KID = `${ISSUER}/keys/other#ed25519-1`
const THIRD_KID = `${ISSUER}/keys/third#ed25519-1`
const VALID_FROM = '2026-01-01T00:00:00Z'

const signerSeed = Uint8Array.from({ length: 32 }, () => 11)
const otherSeed = Uint8Array.from({ length: 32 }, () => 12)
const replacementSeed = Uint8Array.from({ length: 32 }, () => 13)
const thirdSeed = Uint8Array.from({ length: 32 }, () => 14)

function keyEntry(
  kid: string,
  seed: Uint8Array,
  status: 'active' | 'retired' | 'compromised' = 'active',
): Record<string, unknown> {
  return {
    kid,
    pub: b64uEncode(ed25519.getPublicKey(seed)),
    valid_from: VALID_FROM,
    valid_to: null,
    status,
  }
}

function sign(body: Record<string, unknown>, signatureField: string, kid: string, seed: Uint8Array): JsonObject {
  const unsigned = parse(body)
  return parse({
    ...body,
    [signatureField]: { kid, sig: b64uEncode(ed25519.sign(canonicalBytes(unsigned), seed)) },
  })
}

function keyManifest(
  keys: unknown[],
  version = 1,
  signerKid = SIGNER_KID,
  signingSeed = signerSeed,
): JsonObject {
  return sign({
    issuer: ISSUER,
    manifest_version: version,
    issued_at: VALID_FROM,
    keys,
  }, 'manifest_signature', signerKid, signingSeed)
}

function receiptBytes(): Uint8Array {
  const payload = parse({
    attest_version: '0.1',
    receipt_id: '01J000000000000000000000AA',
    issued_at: '2026-06-01T00:00:00Z',
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Store' },
    buyer: { commitment: b64uEncode(new Uint8Array(32)), identifier_type: 'issuer-account', pubkey: null },
    work: { title: 'Work', publisher: 'Publisher', identifiers: { sku: 'S-1' } },
    license: {
      grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-free',
      terms_uri: 'https://store.example/terms', legal_text_sha256: 'a'.repeat(64),
    },
    survivability: {
      redownload_right: true, end_of_life: 'artifacts-remain-redownloadable',
      eol_commitment_uri: null, eol_commitment_sha256: null,
    },
  })
  return enc(JSON.stringify({
    payload,
    signatures: [{ kid: SIGNER_KID, alg: 'Ed25519', sig: b64uEncode(ed25519.sign(canonicalBytes(payload), signerSeed)) }],
  }))
}

function revocationRecord(): JsonObject {
  return sign({
    receipt_id: '01J000000000000000000000AA',
    status: 'revoked',
    revoked_at: '2026-06-02T00:00:00Z',
  }, 'signature', SIGNER_KID, signerSeed)
}

function artifactManifest(): JsonObject {
  return sign({
    issuer: ISSUER,
    series: `${ISSUER}/works/S-1`,
    version: 1,
    released_at: '2026-06-02T00:00:00Z',
    artifacts: [{ artifact_id: 'S-1.bin', sha256: '0'.repeat(64) }],
  }, 'manifest_signature', SIGNER_KID, signerSeed)
}

function duplicateKidError(kids: string[]): string {
  const builder = (messages as unknown as Record<string, unknown>)['manifestDuplicateKids']
  expect(typeof builder).toBe('function')
  return (builder as (value: string[]) => string)(kids)
}

function manifestWithUnrelatedDuplicate(order: 'active-first' | 'retired-first' = 'active-first'): JsonObject {
  const duplicate = order === 'active-first'
    ? [keyEntry(OTHER_KID, otherSeed, 'active'), keyEntry(OTHER_KID, otherSeed, 'retired')]
    : [keyEntry(OTHER_KID, otherSeed, 'retired'), keyEntry(OTHER_KID, otherSeed, 'active')]
  return keyManifest([keyEntry(SIGNER_KID, signerSeed), ...duplicate, keyEntry(THIRD_KID, thirdSeed)])
}

// API shape mirrors the Python reference: `duplicateKids` takes the keys[]
// ARRAY (like `duplicate_kids(entries)`) and `findKey` returns null (like
// `find_key` returning None), which is also the convention findKey already
// had in this module.
describe('v0.1 §7.1 duplicate kid manifest self-consistency', () => {
  it('reports sorted distinct duplicates with the Python list repr, not JavaScript join formatting', () => {
    const manifest = keyManifest([
      keyEntry(SIGNER_KID, signerSeed),
      keyEntry('zeta', otherSeed),
      keyEntry('alpha', replacementSeed),
      keyEntry('zeta', otherSeed),
      keyEntry('alpha', replacementSeed),
      keyEntry('alpha', thirdSeed),
    ])

    expect(duplicateKids(manifest['keys'])).toEqual(['alpha', 'zeta'])
    expect(duplicateKidError(['alpha', 'zeta'])).toBe("issuer manifest lists duplicate kid(s): ['alpha', 'zeta']")
  })

  it.each(['active-first', 'retired-first'] as const)(
    'rejects either array order when duplicate entries have different lifecycle states (%s)',
    (order) => {
      const manifest = manifestWithUnrelatedDuplicate(order)
      expect(verifyKeyManifest(manifest)).toBe(false)

      const result = verify(receiptBytes(), {
        manifests: { [ISSUER]: manifest },
        provenance: { [ISSUER]: 'tls' },
      })
      expect(isOk(result)).toBe(false)
      expect(result.signature).toBe('invalid')
      expect(result.schema).toBe('invalid')
      expect(result.errors).toContain(`issuer manifest lists duplicate kid(s): ['${OTHER_KID}']`)
    },
  )

  it.each([
    ['same status', [keyEntry(OTHER_KID, otherSeed), keyEntry(OTHER_KID, otherSeed)]],
    ['different public keys', [keyEntry(OTHER_KID, otherSeed), keyEntry(OTHER_KID, replacementSeed)]],
    ['three entries', [keyEntry(OTHER_KID, otherSeed), keyEntry(OTHER_KID, otherSeed), keyEntry(OTHER_KID, otherSeed)]],
  ] as const)('rejects a duplicate kid regardless of %s', (_caseName, repeated) => {
    const manifest = keyManifest([keyEntry(SIGNER_KID, signerSeed), ...repeated])
    expect(duplicateKids(manifest['keys'])).toEqual([OTHER_KID])
    expect(verifyKeyManifest(manifest)).toBe(false)
  })

  it.each(['active-first', 'retired-first'] as const)(
    'rejects a duplicate of the manifest signing kid in either lifecycle order (%s)',
    (order) => {
      const duplicateSigner = order === 'active-first'
        ? [keyEntry(SIGNER_KID, signerSeed, 'active'), keyEntry(SIGNER_KID, signerSeed, 'retired')]
        : [keyEntry(SIGNER_KID, signerSeed, 'retired'), keyEntry(SIGNER_KID, signerSeed, 'active')]
      const manifest = keyManifest([...duplicateSigner, keyEntry(OTHER_KID, otherSeed)])

      expect(duplicateKids(manifest['keys'])).toEqual([SIGNER_KID])
      expect(findKey(manifest, SIGNER_KID)).toBeNull()
      expect(verifyKeyManifest(manifest)).toBe(false)
    },
  )

  it('fails closed for the ambiguous kid but still resolves an unrelated unambiguous kid', () => {
    const manifest = manifestWithUnrelatedDuplicate()
    expect(findKey(manifest, OTHER_KID)).toBeNull()
    expect(findKey(manifest, SIGNER_KID)).toMatchObject({ kid: SIGNER_KID })
    expect(findKey(manifest, THIRD_KID)).toMatchObject({ kid: THIRD_KID })
  })

  it('does not coerce non-string kid values while finding or grouping duplicates', () => {
    const symbolKid = Symbol('7')
    const raw = {
      keys: [
        null,
        7,
        'not-an-object',
        { kid: 7 },
        { kid: '7' },
        { kid: symbolKid },
        { kid: Symbol('7') },
        { kid: OTHER_KID },
        { kid: OTHER_KID },
      ],
    } as unknown as JsonObject

    expect(duplicateKids(raw['keys'])).toEqual([OTHER_KID])
    expect(findKey(raw, '7')).toMatchObject({ kid: '7' })
    expect(findKey(raw, OTHER_KID)).toBeNull()
    expect(findKey(raw, String(symbolKid))).toBeNull()
  })

  it.each([
    ['empty keys', { keys: [] }],
    ['keys is not an array', { keys: { kid: SIGNER_KID } }],
    ['keys contains no objects', { keys: [null, 7, 'key'] }],
  ])('does not accept a malformed manifest with %s', (_caseName, raw) => {
    const manifest = raw as unknown as JsonObject
    expect(duplicateKids(manifest['keys'])).toEqual([])
    expect(findKey(manifest, SIGNER_KID)).toBeNull()
    expect(verifyKeyManifest(manifest)).toBe(false)
  })

  it.each(['retired', 'compromised'] as const)(
    'keeps a single %s key manifest self-consistent',
    (status) => {
      const manifest = keyManifest([keyEntry(SIGNER_KID, signerSeed, status)])
      expect(duplicateKids(manifest['keys'])).toEqual([])
      expect(verifyKeyManifest(manifest)).toBe(true)
    },
  )
})

describe('v0.1 §7.1 duplicate kid rejection at every manifest consumer', () => {
  it('rejects revocation-record authentication against a signed ambiguous manifest', () => {
    expect(verifyRecord(revocationRecord(), manifestWithUnrelatedDuplicate())).toBe(false)
  })

  it('rejects artifact-manifest authentication against a signed ambiguous manifest', () => {
    expect(verifyArtifactManifest(artifactManifest(), manifestWithUnrelatedDuplicate())).toBe(false)
  })

  it('rejects rotation continuity when the candidate is self-ambiguous', () => {
    const trusted = keyManifest([keyEntry(SIGNER_KID, signerSeed)], 1)
    const candidate = keyManifest([
      keyEntry(SIGNER_KID, signerSeed),
      keyEntry(OTHER_KID, otherSeed),
      keyEntry(OTHER_KID, replacementSeed),
    ], 2)

    expect(verifyKeyManifest(trusted)).toBe(true)
    expect(verifyKeyManifest(candidate)).toBe(false)
    expect(checkContinuity(trusted, candidate)).toBe(false)
  })

  it('rejects rotation continuity when the trusted predecessor is self-ambiguous', () => {
    const trusted = keyManifest([
      keyEntry(SIGNER_KID, signerSeed),
      keyEntry(OTHER_KID, otherSeed),
      keyEntry(OTHER_KID, replacementSeed),
    ], 1)
    const candidate = keyManifest([keyEntry(SIGNER_KID, signerSeed)], 2)

    expect(verifyKeyManifest(trusted)).toBe(false)
    expect(verifyKeyManifest(candidate)).toBe(true)
    expect(checkContinuity(trusted, candidate)).toBe(false)
  })
})
