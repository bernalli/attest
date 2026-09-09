// Regression tests for the 2026-07-13 security-review must-fix batch (TS side).
// Written test-first; each pins the fixed behaviour.
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { verifyKeyManifest, checkContinuity } from '../src/manifests.js'
import { verify } from '../src/verify.js'
import { validatePayload } from '../src/schema.js'
import { computeCommitment } from '../src/commitment.js'
import { store as trustSnapshot } from './helpers/trust.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject
function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  return { ...body, manifest_signature: { kid, sig: b64uEncode(ed25519.sign(canonicalBytes(b), seed)) } }
}

const ISSUER = 'store.example.com'
const seed1 = Uint8Array.from({ length: 32 }, () => 4)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const seedAttacker = Uint8Array.from({ length: 32 }, () => 11)
const pubAttacker = b64uEncode(ed25519.getPublicKey(seedAttacker))
const kid1 = `${ISSUER}/keys/test#ed25519-1`

function basePayload(): Record<string, unknown> {
  return {
    attest_version: '0.1',
    receipt_id: '01J1V5B4M9Z8QWERTY12345678',
    issued_at: '2026-07-02T14:30:00Z',
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: { commitment: b64uEncode(new Uint8Array(32)), identifier_type: 'issuer-account', pubkey: null },
    work: { title: 'Example Game', publisher: 'Example Pub', identifiers: { sku: 'X' }, artifact_series: `${ISSUER}/works/X` },
    license: { grant: 'perpetual', revocability: 'none', transferable: false, drm: 'drm-free', terms_uri: 'https://x/y', legal_text_sha256: 'a'.repeat(64) },
    survivability: { redownload_right: true, end_of_life: 'artifacts-remain-redownloadable', eol_commitment_uri: null, eol_commitment_sha256: null },
  }
}

// Fix 1: rotation continuity must bind the candidate signature to trusted's pub.
it('checkContinuity rejects a substituted pub under a reused kid', () => {
  const v1 = signManifest(
    { issuer: ISSUER, manifest_version: 1, issued_at: '2026-01-01T00:00:00Z', keys: [{ kid: kid1, pub: pub1, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }] },
    kid1, seed1,
  )
  // Attacker candidate reuses kid1 but lists its own pub, self-signed by it.
  const evil = signManifest(
    { issuer: ISSUER, manifest_version: 2, issued_at: '2026-02-01T00:00:00Z', keys: [{ kid: kid1, pub: pubAttacker, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }] },
    kid1, seedAttacker,
  )
  expect(verifyKeyManifest(parse(evil))).toBe(true) // self-consistent by design
  expect(checkContinuity(parse(v1), parse(evil))).toBe(false)
})

// Fix 4: an unknown/missing key status must fail closed in verify().
it('verify rejects a key with an unknown status even with a valid signature', () => {
  const seedS = Uint8Array.from({ length: 32 }, () => 3)
  const pubS = b64uEncode(ed25519.getPublicKey(seedS))
  const kidS = `${ISSUER}/keys/test#ed25519-s`
  const payload = basePayload()
  const sig = b64uEncode(ed25519.sign(canonicalBytes(parse(payload)), seedS))
  const envelope = { payload, signatures: [{ kid: kidS, alg: 'Ed25519', sig }] }
  const manifest = parse(signManifest(
    { issuer: ISSUER, keys: [{ kid: kidS, pub: pubS, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'frobnicate' }] },
    kidS,
    seedS,
  ))
  const store = trustSnapshot({ manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: 'tls' } })
  const r = verify(enc(JSON.stringify(envelope)), store)
  // The assertion names the REASON, not just the verdict. `signature: 'invalid'`
  // alone did not pin this property: with the store passed as a live object the
  // verifier refused it at the trust-material boundary, and with the manifest
  // unsigned it refused it for self-inconsistency - so swapping the status for
  // 'active' left all five tests green. Measured 2026-09-09.
  expect(r.errors).toContain(`key ${kidS} has unusable status`)
  expect(r.signature).toBe('invalid')
})

// Fix 5: TS schema must reject a non-string work.edition.
it('validatePayload rejects a non-string work.edition', () => {
  const p = basePayload()
  ;(p.work as Record<string, unknown>).edition = 7
  const errors = validatePayload(parse(p))
  expect(errors.some((e) => e.includes('edition'))).toBe(true)
})

// Fix 6: lone surrogates in a buyer identifier must throw, not collapse to U+FFFD.
it('computeCommitment rejects a lone surrogate identifier', () => {
  expect(() => computeCommitment('a\uD800b', 'issuer-account', new Uint8Array(16))).toThrow()
})

// Fix 7: ULID pattern must reject a first character above 7 (>128-bit id).
it('validatePayload rejects a receipt_id whose first character is above 7', () => {
  const p = basePayload()
  p.receipt_id = '8' + '0'.repeat(25)
  const errors = validatePayload(parse(p))
  expect(errors.some((e) => e.includes('receipt_id'))).toBe(true)
})
