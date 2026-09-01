// Regression tests for the 2026-07-13 review SHOULD-FIX batch (TS parity side).
import { it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { checkContinuity } from '../src/manifests.js'
import { verify } from '../src/verify.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject
function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  return { ...body, manifest_signature: { kid, sig: b64uEncode(ed25519.sign(canonicalBytes(b), seed)) } }
}

const ISSUER = 'store.example.com'
const seed1 = Uint8Array.from({ length: 32 }, () => 4)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/test#ed25519-1`

// #12: continuity must honour the signer key's validity window.
it('checkContinuity rejects a candidate issued after the signer key valid_to', () => {
  const v1 = signManifest(
    { issuer: ISSUER, manifest_version: 1, issued_at: '2026-01-01T00:00:00Z', keys: [{ kid: kid1, pub: pub1, valid_from: '2026-01-01T00:00:00Z', valid_to: '2026-06-01T00:00:00Z', status: 'active' }] },
    kid1, seed1,
  )
  const v2 = signManifest(
    { issuer: ISSUER, manifest_version: 2, issued_at: '2026-07-01T00:00:00Z', keys: [{ kid: kid1, pub: pub1, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }] },
    kid1, seed1,
  )
  expect(checkContinuity(parse(v1), parse(v2))).toBe(false)
})

// #8: a chain that doesn't end at the manifest used must downgrade trust.
it('verify downgrades trust when the chain tail is not the used manifest', () => {
  const seedS = Uint8Array.from({ length: 32 }, () => 3)
  const pubS = b64uEncode(ed25519.getPublicKey(seedS))
  const seedX = Uint8Array.from({ length: 32 }, () => 12)
  const pubX = b64uEncode(ed25519.getPublicKey(seedX))
  const kidS = `${ISSUER}/keys/test#ed25519-s`

  const payload = {
    attest_version: '0.1', receipt_id: '01J1V5B4M9Z8QWERTY12345678', issued_at: '2026-07-02T14:30:00Z', supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: { commitment: b64uEncode(new Uint8Array(32)), identifier_type: 'issuer-account', pubkey: null },
    work: { title: 'G', publisher: 'P', identifiers: { sku: 'X' }, artifact_series: `${ISSUER}/works/X` },
    license: { grant: 'perpetual', revocability: 'none', transferable: false, drm: 'drm-free', terms_uri: 'https://x/y', legal_text_sha256: 'a'.repeat(64) },
    survivability: { redownload_right: true, end_of_life: 'artifacts-remain-redownloadable', eol_commitment_uri: null, eol_commitment_sha256: null },
  }
  const sig = b64uEncode(ed25519.sign(canonicalBytes(parse(payload)), seedS))
  const envelope = { payload, signatures: [{ kid: kidS, alg: 'Ed25519', sig }] }

  // `used` must authenticate itself: verify() now checks that before
  // reading any key out of the trusted manifest, so it is self-signed with
  // the same key it lists. `unrelated` never needs a real signature — the
  // chain here has a single member, so `chainContinuous` is trivially true
  // and only the tail-vs-used byte compare (which this test exercises) is
  // reached, never `unrelated`'s own authenticity.
  const used = parse(signManifest(
    { issuer: ISSUER, manifest_version: 1, keys: [{ kid: kidS, pub: pubS, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }] },
    kidS, seedS,
  ))
  const unrelated = parse({ issuer: ISSUER, manifest_version: 5, keys: [{ kid: kidS, pub: pubX, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }] })
  const store = { manifests: { [ISSUER]: used }, provenance: { [ISSUER]: 'tls' }, chains: { [ISSUER]: [unrelated] } }

  const r = verify(enc(JSON.stringify(envelope)), store)
  expect(r.signature).toBe('valid')
  expect(r.trust).toBe('unverified_rotation')
})
