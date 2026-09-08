import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode, b64uDecode } from '../src/b64u.js'
import {
  findKey,
  verifyKeyManifest,
  withinValidity,
  checkContinuity,
  chainContinuous,
  verifyArtifactManifest,
  checkArtifactContinuity,
  MAX_ARTIFACT_ENTRIES,
} from '../src/manifests.js'
import { keyManifest as manifestHandle } from './helpers/trust.js'

const enc = (s: string) => new TextEncoder().encode(s)
function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, manifest_signature: { kid, sig: b64uEncode(sig) } }
}
// Every manifest fed to manifests.ts functions MUST go through loadsStrict so that
// manifest_version parses as bigint (checkContinuity's `typeof tv !== 'bigint'` guard).
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject

const ISSUER = 'store.example.com'

const seed1 = Uint8Array.from({ length: 32 }, () => 7)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/2025-01#ed25519-1`

const seed2 = Uint8Array.from({ length: 32 }, () => 8)
const pub2 = b64uEncode(ed25519.getPublicKey(seed2))
const kid2 = `${ISSUER}/keys/2025-06#ed25519-2`

const seed3 = Uint8Array.from({ length: 32 }, () => 9)
const pub3 = b64uEncode(ed25519.getPublicKey(seed3))
const kid3 = `${ISSUER}/keys/2025-06#ed25519-3`

// v1: single active key (kid1), open-ended validity — the brief's base fixture.
const v1 = signManifest(
  {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2025-01-01T00:00:00Z',
    keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' }],
  },
  kid1,
  seed1,
)

describe('manifests', () => {
  describe('verifyKeyManifest', () => {
    it('self-verifies a pristine key manifest', () => {
      expect(verifyKeyManifest(parse(v1))).toBe(true)
    })

    it('fails self-verify after a signed-field tamper (status flip)', () => {
      const t = JSON.parse(JSON.stringify(v1))
      t.keys[0].status = 'compromised'
      expect(verifyKeyManifest(parse(t))).toBe(false)
    })

    it('a retired or compromised signer still self-verifies — status is enforced elsewhere', () => {
      // verifyKeyManifest checks ONLY that the signature matches the key material
      // listed in the manifest itself; it deliberately never inspects entry.status.
      const retired = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 1,
          issued_at: '2025-01-01T00:00:00Z',
          keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'retired' }],
        },
        kid1,
        seed1,
      )
      expect(verifyKeyManifest(parse(retired))).toBe(true)

      const compromised = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 1,
          issued_at: '2025-01-01T00:00:00Z',
          keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'compromised' }],
        },
        kid1,
        seed1,
      )
      expect(verifyKeyManifest(parse(compromised))).toBe(true)
    })
  })

  describe('findKey', () => {
    it('returns the first matching entry by kid, and null when absent', () => {
      const m = parse(v1)
      const e = findKey(m, kid1)!
      expect(e.status).toBe('active')
      expect(e.pub).toBe(pub1)
      expect(findKey(m, 'nope')).toBeNull()
    })
  })

  describe('withinValidity', () => {
    // Bounded window (valid_to set) so both ends of the inclusive range are testable.
    const bounded = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 1,
        issued_at: '2025-01-01T00:00:00Z',
        keys: [
          {
            kid: kid1,
            pub: pub1,
            valid_from: '2025-01-01T00:00:00Z',
            valid_to: '2025-06-01T00:00:00Z',
            status: 'active',
          },
        ],
      },
      kid1,
      seed1,
    )
    const entry = findKey(parse(bounded), kid1)!

    it('true strictly inside the window', () => {
      expect(withinValidity('2025-03-01T00:00:00Z', entry)).toBe(true)
    })
    it('true at the exact valid_from boundary (inclusive)', () => {
      expect(withinValidity('2025-01-01T00:00:00Z', entry)).toBe(true)
    })
    it('true at the exact valid_to boundary (inclusive)', () => {
      expect(withinValidity('2025-06-01T00:00:00Z', entry)).toBe(true)
    })
    it('false before valid_from', () => {
      expect(withinValidity('2024-12-31T23:59:59Z', entry)).toBe(false)
    })
    it('false after valid_to', () => {
      expect(withinValidity('2025-06-01T00:00:01Z', entry)).toBe(false)
    })
    it('false on a malformed date (fail-closed)', () => {
      expect(withinValidity('garbage', entry)).toBe(false)
    })
    it('true on open-ended validity (valid_to null) well past valid_from', () => {
      const openEntry = findKey(parse(v1), kid1)!
      expect(withinValidity('2025-06-01T00:00:00Z', openEntry)).toBe(true)
    })
  })

  describe('checkContinuity / chainContinuous', () => {
    // v2: kid1 retired (bounded window), kid2 newly active — signed by kid1, which
    // IS active in v1 (the trusted manifest). Rotation-continuity happy path.
    const v2 = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 2,
        issued_at: '2025-06-01T00:00:00Z',
        keys: [
          {
            kid: kid1,
            pub: pub1,
            valid_from: '2025-01-01T00:00:00Z',
            valid_to: '2025-06-01T00:00:00Z',
            status: 'retired',
          },
          { kid: kid2, pub: pub2, valid_from: '2025-06-01T00:00:00Z', valid_to: null, status: 'active' },
        ],
      },
      kid1,
      seed1,
    )

    // v2b (vector-14b discontinuity shape): self-consistent candidate whose signer
    // (kid3) is ABSENT from v1's keys[] — a new key with no chain of trust back.
    const v2b = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 2,
        issued_at: '2025-06-01T00:00:00Z',
        keys: [{ kid: kid3, pub: pub3, valid_from: '2025-06-01T00:00:00Z', valid_to: null, status: 'active' }],
      },
      kid3,
      seed3,
    )

    // v3: version gap (manifest_version = 3, not trusted.manifest_version + 1),
    // otherwise well-formed and self-consistent, signed by kid1 (active in v1) —
    // isolates the version-increment check from every other continuity condition.
    const v3 = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 3,
        issued_at: '2025-06-01T00:00:00Z',
        keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' }],
      },
      kid1,
      seed1,
    )

    it('true for v1 -> v2 signed by a key active in v1', () => {
      expect(checkContinuity(parse(v1), parse(v2))).toBe(true)
      expect(chainContinuous([parse(v1), parse(v2)])).toBe(true)
    })

    it('false when the candidate signer is absent from the trusted manifest (vector 14b shape)', () => {
      expect(checkContinuity(parse(v1), parse(v2b))).toBe(false)
      expect(chainContinuous([parse(v1), parse(v2b)])).toBe(false)
    })

    it('false on a version gap (v1 -> v3, not +1)', () => {
      expect(checkContinuity(parse(v1), parse(v3))).toBe(false)
    })

    it('false when the candidate signer exists in trusted but only as retired (not active)', () => {
      const trustedRetired = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 1,
          issued_at: '2025-01-01T00:00:00Z',
          keys: [
            {
              kid: kid1,
              pub: pub1,
              valid_from: '2025-01-01T00:00:00Z',
              valid_to: '2025-06-01T00:00:00Z',
              status: 'retired',
            },
          ],
        },
        kid1,
        seed1,
      )
      // candidate lists kid1 too (so it self-verifies), signed by kid1; only
      // trusted's view of kid1 (retired) is what checkContinuity must reject on.
      const candidateSignedByRetired = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 2,
          issued_at: '2025-06-01T00:00:00Z',
          keys: [
            {
              kid: kid1,
              pub: pub1,
              valid_from: '2025-01-01T00:00:00Z',
              valid_to: '2025-06-01T00:00:00Z',
              status: 'retired',
            },
            { kid: kid2, pub: pub2, valid_from: '2025-06-01T00:00:00Z', valid_to: null, status: 'active' },
          ],
        },
        kid1,
        seed1,
      )
      expect(checkContinuity(parse(trustedRetired), parse(candidateSignedByRetired))).toBe(false)
    })

    it('a single-manifest chain is trivially continuous', () => {
      expect(chainContinuous([parse(v1)])).toBe(true)
    })
  })

  // v0.2 hybrid (Ed25519 + ML-DSA-65) manifest-signature AND rule — mirrors
  // tests/test_manifests_hybrid.py's four manifest-signature cases one-for-one.
  describe('hybrid manifest signature (AND rule)', () => {
    const HYBRID_KID = `${ISSUER}/keys/test#hybrid-1`
    const hybridEdSeed = Uint8Array.from({ length: 32 }, () => 11)
    const hybridEdPub = ed25519.getPublicKey(hybridEdSeed)
    const { publicKey: hybridMldsaPub, secretKey: hybridMldsaSecret } = ml_dsa65.keygen(
      Uint8Array.from({ length: 32 }, () => 12),
    )

    // Returns a plain (JS-number) manifest object, matching `signManifest`
    // above — callers parse() it (bigint `manifest_version`) at the point of
    // use, so it stays JSON.stringify-able for tamper mutations in between.
    function signHybridManifest(body: Record<string, unknown>, kid: string): Record<string, unknown> {
      const b = parse(body)
      const bytes = canonicalBytes(b)
      const edSig = ed25519.sign(bytes, hybridEdSeed)
      const mldsaSig = ml_dsa65.sign(bytes, hybridMldsaSecret)
      return { ...body, manifest_signature: { kid, sig: b64uEncode(edSig), sig_ml_dsa_65: b64uEncode(mldsaSig) } }
    }

    function hybridManifestBody() {
      return {
        issuer: ISSUER,
        manifest_version: 1,
        issued_at: '2026-01-01T00:00:00Z',
        keys: [
          {
            kid: HYBRID_KID,
            pub: b64uEncode(hybridEdPub),
            valid_from: '2026-01-01T00:00:00Z',
            valid_to: null,
            status: 'active',
            pub_ml_dsa_65: b64uEncode(hybridMldsaPub),
          },
        ],
      }
    }

    it('a hybrid manifest with both legs verifies', () => {
      const manifest = signHybridManifest(hybridManifestBody(), HYBRID_KID)
      expect(verifyKeyManifest(parse(manifest))).toBe(true)
    })

    it('a hybrid manifest missing the ML-DSA-65 leg is invalid', () => {
      const manifest = signHybridManifest(hybridManifestBody(), HYBRID_KID) as any
      delete manifest.manifest_signature.sig_ml_dsa_65
      expect(verifyKeyManifest(parse(manifest))).toBe(false)
    })

    it('a non-hybrid manifest with a stray ML-DSA-65 leg is invalid', () => {
      const body = {
        issuer: ISSUER,
        manifest_version: 1,
        issued_at: '2026-01-01T00:00:00Z',
        keys: [{ kid: HYBRID_KID, pub: b64uEncode(hybridEdPub), valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }],
      }
      const edSig = ed25519.sign(canonicalBytes(parse(body)), hybridEdSeed)
      const nonHybrid = { ...body, manifest_signature: { kid: HYBRID_KID, sig: b64uEncode(edSig) } } as any
      expect(verifyKeyManifest(parse(nonHybrid))).toBe(true)
      nonHybrid.manifest_signature.sig_ml_dsa_65 = b64uEncode(new Uint8Array(3309))
      expect(verifyKeyManifest(parse(nonHybrid))).toBe(false)
    })

    it('a hybrid manifest with a tampered ML-DSA-65 leg is invalid', () => {
      const manifest = signHybridManifest(hybridManifestBody(), HYBRID_KID) as any
      const raw = b64uDecode(manifest.manifest_signature.sig_ml_dsa_65)
      raw[0] = raw[0]! ^ 0xff
      manifest.manifest_signature.sig_ml_dsa_65 = b64uEncode(raw)
      expect(verifyKeyManifest(parse(manifest))).toBe(false)
    })

    // Hybrid rotation continuity — mirrors tests/test_manifests_hybrid.py's
    // test_continuity_hybrid_chain_ok / test_continuity_rejects_candidate_missing_mldsa_leg.
    // If checkContinuity ever regressed to Ed25519-only checking (ignoring the
    // ML-DSA-65 leg), the second case below would wrongly pass.
    it('a hybrid v1 -> v2 rotation signed by the same hybrid kid is continuous', () => {
      const trusted = parse(signHybridManifest(hybridManifestBody(), HYBRID_KID))
      const candidateBody = {
        issuer: ISSUER,
        manifest_version: 2,
        issued_at: '2026-06-01T00:00:00Z',
        keys: [
          {
            kid: HYBRID_KID,
            pub: b64uEncode(hybridEdPub),
            valid_from: '2026-01-01T00:00:00Z',
            valid_to: null,
            status: 'active',
            pub_ml_dsa_65: b64uEncode(hybridMldsaPub),
          },
        ],
      }
      const candidate = parse(signHybridManifest(candidateBody, HYBRID_KID))
      expect(checkContinuity(trusted, candidate)).toBe(true)
    })

    it('a hybrid candidate whose signature is missing the ML-DSA-65 leg breaks continuity', () => {
      const trusted = parse(signHybridManifest(hybridManifestBody(), HYBRID_KID))
      const candidateBody = {
        issuer: ISSUER,
        manifest_version: 2,
        issued_at: '2026-06-01T00:00:00Z',
        keys: [
          {
            kid: HYBRID_KID,
            pub: b64uEncode(hybridEdPub),
            valid_from: '2026-01-01T00:00:00Z',
            valid_to: null,
            status: 'active',
            pub_ml_dsa_65: b64uEncode(hybridMldsaPub),
          },
        ],
      }
      const candidate = signHybridManifest(candidateBody, HYBRID_KID) as any
      delete candidate.manifest_signature.sig_ml_dsa_65
      // candidate.manifest_signature (Ed25519-only) no longer self-verifies against
      // a hybrid key entry (AND rule), so checkContinuity must reject it.
      expect(checkContinuity(trusted, parse(candidate))).toBe(false)
    })

    it('a self-consistent Ed25519-only candidate cannot ride continuity off a hybrid trusted signer', () => {
      // Isolates checkContinuity's OWN AND-rule re-check (it re-verifies the
      // candidate's signature under the TRUSTED manifest's signer entry, not the
      // candidate's own) from verifyKeyManifest's self-consistency check above.
      // The candidate here is independently self-consistent (non-hybrid key
      // entry + Ed25519-only signature), so verifyKeyManifest(candidate) alone
      // would pass; only checkContinuity's re-verification against trusted's
      // hybrid signer entry can catch the missing ML-DSA-65 leg.
      const trusted = parse(signHybridManifest(hybridManifestBody(), HYBRID_KID))
      const nonHybridCandidateBody = {
        issuer: ISSUER,
        manifest_version: 2,
        issued_at: '2026-06-01T00:00:00Z',
        keys: [{ kid: HYBRID_KID, pub: b64uEncode(hybridEdPub), valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }],
      }
      const edOnlySig = ed25519.sign(canonicalBytes(parse(nonHybridCandidateBody)), hybridEdSeed)
      const candidate = { ...nonHybridCandidateBody, manifest_signature: { kid: HYBRID_KID, sig: b64uEncode(edOnlySig) } }
      expect(verifyKeyManifest(parse(candidate))).toBe(true)
      expect(checkContinuity(trusted, parse(candidate))).toBe(false)
    })
  })

  describe('verifyArtifactManifest', () => {
    const am = signManifest(
      {
        issuer: ISSUER,
        series: `${ISSUER}/works/EXG-001`,
        version: 1,
        released_at: '2025-03-01T00:00:00Z',
        artifacts: [
          {
            role: 'installer',
            platform: 'windows-x86_64',
            filename: 'example-game-1.0-setup.exe',
            size_bytes: 734003200,
            sha256: '0'.repeat(64),
          },
        ],
      },
      kid1,
      seed1,
    )

    it('verifies a pristine artifact manifest against its key manifest', () => {
      expect(verifyArtifactManifest(parse(am), manifestHandle(parse(v1)))).toBe(true)
    })

    it('fails after a signed-field tamper', () => {
      const t = JSON.parse(JSON.stringify(am))
      t.version = 2
      expect(verifyArtifactManifest(parse(t), manifestHandle(parse(v1)))).toBe(false)
    })

    // --- I3(b) (2026-07-22 fix wave 2): G1 artifact-entries ceiling boundary —
    // mirrors Python's test_manifests.py test_verify_artifact_manifest_true_at_entries_ceiling
    // / test_verify_artifact_manifest_false_over_entries_ceiling pair.
    const _fillerArtifacts = (count: number) =>
      Array.from({ length: count }, (_, i) => ({
        role: 'installer',
        platform: 'windows-x86_64',
        filename: `example-game-1.0-setup-${i}.exe`,
        size_bytes: 734003200,
        sha256: '0'.repeat(64),
      }))

    it('accepts an artifact manifest at MAX_ARTIFACT_ENTRIES', () => {
      const atCeiling = signManifest(
        {
          issuer: ISSUER,
          series: `${ISSUER}/works/EXG-001`,
          version: 1,
          released_at: '2025-03-01T00:00:00Z',
          artifacts: _fillerArtifacts(MAX_ARTIFACT_ENTRIES),
        },
        kid1,
        seed1,
      )
      expect(verifyArtifactManifest(parse(atCeiling), manifestHandle(parse(v1)))).toBe(true)
    })

    it('rejects an artifact manifest one entry over MAX_ARTIFACT_ENTRIES', () => {
      const overCeiling = signManifest(
        {
          issuer: ISSUER,
          series: `${ISSUER}/works/EXG-001`,
          version: 1,
          released_at: '2025-03-01T00:00:00Z',
          artifacts: _fillerArtifacts(MAX_ARTIFACT_ENTRIES + 1),
        },
        kid1,
        seed1,
      )
      expect(verifyArtifactManifest(parse(overCeiling), manifestHandle(parse(v1)))).toBe(false)
    })

    it('rejects a signed artifact manifest with manifest_version zero', () => {
      const zero = signManifest(
        {
          issuer: ISSUER,
          series: `${ISSUER}/works/EXG-001`,
          version: 1,
          manifest_version: 0,
          released_at: '2025-03-01T00:00:00Z',
          artifacts: [],
        },
        kid1,
        seed1,
      )
      expect(verifyArtifactManifest(parse(zero), manifestHandle(parse(v1)))).toBe(false)
    })
  })

  // G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
  // amendment) — mirrors tests/test_manifests.py's check_artifact_continuity
  // cases one-for-one.
  describe('checkArtifactContinuity', () => {
    const SERIES = `${ISSUER}/works/EXG-001`
    const artifactEntry = () => ({
      role: 'installer',
      platform: 'windows-x86_64',
      filename: 'example-game-1.0-setup.exe',
      size_bytes: 734003200,
      sha256: '0'.repeat(64),
    })
    const am1 = signManifest(
      {
        issuer: ISSUER,
        series: SERIES,
        version: 1,
        manifest_version: 1,
        released_at: '2025-03-01T00:00:00Z',
        artifacts: [artifactEntry()],
      },
      kid1,
      seed1,
    )
    const am2 = signManifest(
      {
        issuer: ISSUER,
        series: SERIES,
        version: 2,
        manifest_version: 2,
        released_at: '2025-04-01T00:00:00Z',
        artifacts: [artifactEntry()],
      },
      kid1,
      seed1,
    )
    const am3 = signManifest(
      {
        issuer: ISSUER,
        series: SERIES,
        version: 3,
        manifest_version: 3,
        released_at: '2025-05-01T00:00:00Z',
        artifacts: [artifactEntry()],
      },
      kid1,
      seed1,
    )
    const amLegacy = signManifest(
      {
        issuer: ISSUER,
        series: SERIES,
        version: 1,
        released_at: '2025-03-01T00:00:00Z',
        artifacts: [artifactEntry()],
      },
      kid1,
      seed1,
    )

    it('true for manifest_version N -> N+1', () => {
      expect(checkArtifactContinuity(parse(am1), parse(am2))).toBe(true)
    })

    it('false on regression (rollback)', () => {
      expect(checkArtifactContinuity(parse(am2), parse(am1))).toBe(false)
    })

    it('false on a version gap', () => {
      expect(checkArtifactContinuity(parse(am1), parse(am3))).toBe(false)
    })

    it('false on issuer mismatch', () => {
      const evil = signManifest(
        {
          issuer: 'evil.example.com',
          series: SERIES,
          version: 2,
          manifest_version: 2,
          released_at: '2025-04-01T00:00:00Z',
          artifacts: [artifactEntry()],
        },
        kid1,
        seed1,
      )
      expect(checkArtifactContinuity(parse(am1), parse(evil))).toBe(false)
    })

    it('false on series mismatch', () => {
      const other = signManifest(
        {
          issuer: ISSUER,
          series: `${ISSUER}/works/OTHER-002`,
          version: 2,
          manifest_version: 2,
          released_at: '2025-04-01T00:00:00Z',
          artifacts: [artifactEntry()],
        },
        kid1,
        seed1,
      )
      expect(checkArtifactContinuity(parse(am1), parse(other))).toBe(false)
    })

    it('true when trusted is legacy (no manifest_version)', () => {
      expect(checkArtifactContinuity(parse(amLegacy), parse(am2))).toBe(true)
    })

    it('true when candidate is legacy (no manifest_version)', () => {
      expect(checkArtifactContinuity(parse(am1), parse(amLegacy))).toBe(true)
    })

    it('true for a same-version re-delivery of the value-identical manifest', () => {
      // Re-fetching the same trusted manifest it already holds must stay continuous.
      expect(checkArtifactContinuity(parse(am1), parse(am1))).toBe(true)
    })

    it('false for two DIFFERENT manifests at the SAME manifest_version (equivocation)', () => {
      const am1Variant = signManifest(
        {
          issuer: ISSUER,
          series: SERIES,
          version: 1,
          manifest_version: 1,
          released_at: '2025-03-02T00:00:00Z',
          artifacts: [artifactEntry()],
        },
        kid1,
        seed1,
      )
      expect(checkArtifactContinuity(parse(am1), parse(am1Variant))).toBe(false)
    })
  })
})
