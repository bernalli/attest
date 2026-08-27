import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { duplicateKids, findKey, verifyKeyManifest } from '../src/manifests.js'
import { manifestDuplicateKids } from '../src/messages.js'
import { verify } from '../src/verify.js'
import type { TrustStore } from '../src/manifests.js'

// V-L.3 parity with src/attest/manifests.py and tests/test_manifests.py
// (v0.1 §7.1, 2026-08-26 amendment).

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject

function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array): JsonObject {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return parse({ ...body, manifest_signature: { kid, sig: b64uEncode(sig) } })
}

const ISSUER = 'store.example.com'
const seed1 = Uint8Array.from({ length: 32 }, () => 7)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/2025-01#ed25519-1`
const seed2 = Uint8Array.from({ length: 32 }, () => 8)
const pub2 = b64uEncode(ed25519.getPublicKey(seed2))
const kid2 = `${ISSUER}/keys/2025-06#ed25519-2`

const entry = (kid: string, pub: string, status = 'active') => ({
  kid,
  pub,
  valid_from: '2025-01-01T00:00:00Z',
  valid_to: null,
  status,
})

const manifestOf = (keys: unknown[]): JsonObject =>
  signManifest(
    { issuer: ISSUER, manifest_version: 1, issued_at: '2025-01-01T00:00:00Z', keys },
    kid1,
    seed1,
  )

describe('duplicate kid entries (v0.1 §7.1 amendment)', () => {
  it('duplicateKids is fail-closed on malformed input and never throws', () => {
    expect(duplicateKids('not-an-array')).toEqual([])
    expect(duplicateKids(7)).toEqual([])
    expect(duplicateKids(null)).toEqual([])
    expect(duplicateKids([null, { kid: 7 }, { kid: 'a' }, { kid: 'a' }, { kid: 'b' }])).toEqual(['a'])
  })

  it('duplicateKids reports every duplicated kid, sorted', () => {
    expect(
      duplicateKids([{ kid: 'b' }, { kid: 'a' }, { kid: 'b' }, { kid: 'a' }, { kid: 'c' }]),
    ).toEqual(['a', 'b'])
  })

  it('findKey fails closed on an ambiguous kid, in both element orders', () => {
    const pair = [entry(kid1, pub1, 'active'), entry(kid1, pub1, 'compromised')]
    for (const keys of [pair, [...pair].reverse()]) {
      expect(findKey(manifestOf(keys), kid1)).toBeNull()
    }
  })

  it('findKey fails closed on three entries for one kid', () => {
    const keys = [entry(kid1, pub1), entry(kid1, pub1), entry(kid1, pub1)]
    expect(findKey(manifestOf(keys), kid1)).toBeNull()
  })

  it('findKey still resolves an unambiguous kid inside an ambiguous manifest', () => {
    const keys = [entry(kid1, pub1), entry(kid2, pub2), entry(kid2, pub2, 'retired')]
    const m = manifestOf(keys)
    expect(findKey(m, kid1)).not.toBeNull()
    expect(findKey(m, kid2)).toBeNull()
  })

  it('verifyKeyManifest rejects duplicates in both element orders', () => {
    const pair = [entry(kid1, pub1, 'active'), entry(kid1, pub1, 'compromised')]
    for (const keys of [pair, [...pair].reverse()]) {
      expect(verifyKeyManifest(manifestOf(keys))).toBe(false)
    }
  })

  it('verifyKeyManifest rejects a duplicate of a kid unrelated to the signer', () => {
    const keys = [entry(kid1, pub1), entry(kid2, pub2), entry(kid2, pub2, 'retired')]
    expect(verifyKeyManifest(manifestOf(keys))).toBe(false)
  })

  it('verifyKeyManifest rejects a duplicate whose two entries carry different material', () => {
    const keys = [entry(kid1, pub1), entry(kid1, pub2)]
    expect(verifyKeyManifest(manifestOf(keys))).toBe(false)
  })

  it('still accepts a degenerate single-key retired or compromised manifest', () => {
    for (const status of ['retired', 'compromised']) {
      expect(verifyKeyManifest(manifestOf([entry(kid1, pub1, status)]))).toBe(true)
    }
  })

  it('the duplicate-kid message is the Python repr form, not a JS array join', () => {
    expect(manifestDuplicateKids(['a', 'b'])).toBe("issuer manifest lists duplicate kid(s): ['a', 'b']")
  })
})

// --- verify() preflight: parity with src/attest/verify.py --------------------

const VALID_FROM = '2025-01-01T00:00:00Z'

function trustStore(manifest: JsonObject): TrustStore {
  return { manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: 'tls' } }
}

function envelope(): { payload: JsonObject; signatures: unknown[] } {
  const payload = parse({
    attest_version: '0.1', issued_at: '2025-06-01T00:00:00Z', receipt_id: '01J000000000000000000000AA',
    issuer: { display_name: 'Store', id: ISSUER },
    work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' } },
    license: { grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-bound', terms_uri: 'https://x/t', legal_text_sha256: 'a'.repeat(64) },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: null },
    survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: false },
    supersedes: null,
  })
  const sig = ed25519.sign(canonicalBytes(payload), seed1)
  return { payload, signatures: [{ kid: kid1, alg: 'Ed25519', sig: b64uEncode(sig) }] }
}

describe('verify(): an ambiguous issuer manifest is refused whole', () => {
  it('rejects a duplicate on a kid unrelated to the signature', () => {
    const manifest = manifestOf([entry(kid1, pub1), entry(kid2, pub2), entry(kid2, pub2, 'retired')])

    const result = verify(enc(JSON.stringify(envelope())), trustStore(manifest), null, null, undefined)

    expect(result.signature).toBe('invalid')
    expect(result.schema).toBe('invalid')
    expect(result.errors).toEqual([`issuer manifest lists duplicate kid(s): ['${kid2}']`])
  })

  it('reaches the same verdict and the same error in both element orders', () => {
    const pair = [entry(kid1, pub1, 'active'), entry(kid1, pub1, 'compromised')]
    const env = enc(JSON.stringify(envelope()))

    const results = [pair, [...pair].reverse()].map((keys) =>
      verify(env, trustStore(manifestOf(keys)), null, null, undefined),
    )

    for (const result of results) {
      expect(result.signature).toBe('invalid')
      expect(result.errors.some((e) => e.includes('duplicate kid'))).toBe(true)
    }
    expect(results[0].errors).toEqual(results[1].errors)
  })

  it('leaves a clean single-key manifest verifying', () => {
    const result = verify(
      enc(JSON.stringify(envelope())),
      trustStore(manifestOf([entry(kid1, pub1)])),
      null,
      null,
      undefined,
    )

    expect(result.signature).toBe('valid')
    expect(result.errors).toEqual([])
  })
})
