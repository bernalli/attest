// G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
// amendment) — verify()-level tests, mirroring tests/test_verify.py's
// artifact-manifest-currency section one-for-one. Same pattern as
// shouldfix.test.ts's "chain tail is not the used manifest" case, applied to
// TrustStore.artifact_manifests/artifact_manifest_chains instead of
// manifests/chains.
import { it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { verify } from '../src/verify.js'
import { store as parsedStore } from './helpers/trust.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject
function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  return { ...body, manifest_signature: { kid, sig: b64uEncode(ed25519.sign(canonicalBytes(b), seed)) } }
}

const ISSUER = 'store.example.com'
const SERIES = `${ISSUER}/works/EXG-001`
const seed1 = Uint8Array.from({ length: 32 }, () => 9)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/test#ed25519-1`

const keyManifest = parse(signManifest({
  issuer: ISSUER,
  manifest_version: 1,
  issued_at: '2026-01-01T00:00:00Z',
  keys: [{ kid: kid1, pub: pub1, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }],
}, kid1, seed1))

function artifactManifest(version: number, manifestVersion: number | null) {
  const body: Record<string, unknown> = {
    issuer: ISSUER,
    series: SERIES,
    version,
    released_at: '2026-03-01T00:00:00Z',
    artifacts: [],
  }
  if (manifestVersion !== null) body.manifest_version = manifestVersion
  return signManifest(body, kid1, seed1)
}

function envelopeBytes(): Uint8Array {
  const payload = {
    attest_version: '0.1',
    receipt_id: '01J1V5B4M9Z8QWERTY12345678',
    issued_at: '2026-07-02T14:30:00Z',
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: { commitment: b64uEncode(new Uint8Array(32)), identifier_type: 'issuer-account', pubkey: null },
    work: { title: 'G', publisher: 'P', identifiers: { sku: 'X' }, artifact_series: SERIES },
    license: {
      grant: 'perpetual',
      revocability: 'none',
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://x/y',
      legal_text_sha256: 'a'.repeat(64),
    },
    survivability: {
      redownload_right: true,
      end_of_life: 'artifacts-remain-redownloadable',
      eol_commitment_uri: null,
      eol_commitment_sha256: null,
    },
  }
  const sig = b64uEncode(ed25519.sign(canonicalBytes(parse(payload)), seed1))
  return enc(JSON.stringify({ payload, signatures: [{ kid: kid1, alg: 'Ed25519', sig }] }))
}

it('a TrustStore with no artifact_manifests entry is a zero-behavior-change baseline', () => {
  const store = parsedStore({ manifests: { [ISSUER]: keyManifest }, provenance: { [ISSUER]: 'tls' } })
  const r = verify(envelopeBytes(), store)
  expect(r.trust).toBe('verified')
  expect(r.warnings).toEqual([])
})

it('a monotone artifact-manifest chain keeps normal trust', () => {
  const am1 = parse(artifactManifest(1, 1))
  const am2 = parse(artifactManifest(2, 2))
  const store = parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: { [ISSUER]: { [SERIES]: am2 } },
    artifact_manifest_chains: { [ISSUER]: { [SERIES]: [am1, am2] } },
  })
  const r = verify(envelopeBytes(), store)
  expect(r.trust).toBe('verified')
  expect(r.warnings).not.toContain('artifact_manifest_unversioned')
})

it('a rollback (chain tail newer than the pinned manifest) yields unverified_rotation', () => {
  const am1 = parse(artifactManifest(1, 1))
  const am2 = parse(artifactManifest(2, 2))
  const store = parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: { [ISSUER]: { [SERIES]: am1 } },
    artifact_manifest_chains: { [ISSUER]: { [SERIES]: [am1, am2] } },
  })
  const r = verify(envelopeBytes(), store)
  expect(r.signature).toBe('valid')
  expect(r.trust).toBe('unverified_rotation')
})

it('a legacy (unversioned) pinned artifact manifest warns but does not reject', () => {
  const legacy = parse(artifactManifest(1, null))
  const store = parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: { [ISSUER]: { [SERIES]: legacy } },
  })
  const r = verify(envelopeBytes(), store)
  expect(r.warnings).toContain('artifact_manifest_unversioned')
  expect(r.trust).toBe('verified')
})

it('an unauthenticated artifact manifest is ignored before currency evaluation', () => {
  const am1 = parse(artifactManifest(1, 1))
  const unsigned = parse(artifactManifest(2, 2))
  delete unsigned['manifest_signature']
  const r = verify(envelopeBytes(), parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: { [ISSUER]: { [SERIES]: unsigned } },
    artifact_manifest_chains: { [ISSUER]: { [SERIES]: [am1, unsigned] } },
  }))
  expect(r.trust).toBe('verified')
  expect(r.warnings).toEqual(['artifact_manifest_unauthenticated'])
})

it('a legacy-to-versioned artifact transition is warn-only', () => {
  const legacy = parse(artifactManifest(1, null))
  const versioned = parse(artifactManifest(2, 1))
  const r = verify(envelopeBytes(), parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: { [ISSUER]: { [SERIES]: versioned } },
    artifact_manifest_chains: { [ISSUER]: { [SERIES]: [legacy, versioned] } },
  }))
  expect(r.trust).toBe('verified')
  expect(r.warnings).toEqual(['artifact_manifest_unversioned'])
})

it('a legacy pinned manifest after versioned history is warn-only (round-2 residual)', () => {
  // A LEGACY pinned candidate whose chain tail is a versioned manifest used
  // to hit the tail-mismatch branch and get the forbidden currency
  // downgrade. Currency must be skipped entirely on any legacy member.
  const versioned = parse(artifactManifest(1, 1))
  const legacy = parse(artifactManifest(2, null))
  const r = verify(envelopeBytes(), parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: { [ISSUER]: { [SERIES]: legacy } },
    artifact_manifest_chains: { [ISSUER]: { [SERIES]: [versioned] } },
  }))
  expect(r.trust).toBe('verified')
  expect(r.warnings).toEqual(['artifact_manifest_unversioned'])
})

it('artifact currency state is scoped to the receipt issuer and series', () => {
  const am1 = parse(artifactManifest(1, 1))
  const am2 = parse(artifactManifest(2, 2))
  const r = verify(envelopeBytes(), parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: {
      [ISSUER]: { [SERIES]: am2 },
      'other.example.com': { [SERIES]: am1 },
    },
    artifact_manifest_chains: {
      [ISSUER]: { [SERIES]: [am1, am2] },
      'other.example.com': { [SERIES]: [am1, am2] },
    },
  }))
  expect(r.trust).toBe('verified')
  expect(r.warnings).toEqual([])
})

it('an artifact-manifest issuer mismatch has its own warning and no trust effect', () => {
  const mismatched = parse(artifactManifest(1, 1))
  mismatched['issuer'] = 'other.example.com'
  const r = verify(envelopeBytes(), parsedStore({
    manifests: { [ISSUER]: keyManifest },
    provenance: { [ISSUER]: 'tls' },
    artifact_manifests: { [ISSUER]: { [SERIES]: mismatched } },
  }))
  expect(r.trust).toBe('verified')
  expect(r.warnings).toEqual(['artifact_manifest_issuer_mismatch'])
})
