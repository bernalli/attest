// Review improvement #17: cached manifest self-verify + revocation-view bound.
// Mirrors tests/test_revocation_view_bound.py on the Python side. Fixture
// pattern (sign JCS of body minus the signature member) follows
// revocation.test.ts / manifests.test.ts.
import { describe, it, expect, vi } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { join } from 'node:path'
import { loadsStrict, canonicalBytes, JsonObject, JsonValue } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { VECTORS_ROOT, envelopeBytes, trustStore, revocationView } from './helpers/vectors.js'
import { verify, isOk } from '../src/verify.js'
import { MAX_REVOCATION_RECORDS } from '../src/revocation.js'

// Wrap verifyKeyManifest and manifestSignatureIsAuthentic in call-counting
// spies that delegate to the real implementation, so the once-per-classification
// contract is testable. classifyRevocation's per-classification hoist calls
// manifestSignatureIsAuthentic (the receipt gate's predicate, narrower than
// verifyKeyManifest — see revocation.ts) since the trusted-manifest
// authentication fix; verifyKeyManifest is still spied on because
// verifyRecord (unrelated to that hoist) still calls it.
vi.mock('../src/manifests.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/manifests.js')>()
  return {
    ...actual,
    verifyKeyManifest: vi.fn(actual.verifyKeyManifest),
    manifestSignatureIsAuthentic: vi.fn(actual.manifestSignatureIsAuthentic),
  }
})

import { verifyKeyManifest, manifestSignatureIsAuthentic } from '../src/manifests.js'
import { classifyRevocation, verifyRecord, verifyRecordSignature } from '../src/revocation.js'

const enc = (s: string) => new TextEncoder().encode(s)
// Every fixture MUST go through loadsStrict so integers arrive as bigint.
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject

function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, manifest_signature: { kid, sig: b64uEncode(sig) } }
}

function signRecord(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, signature: { kid, sig: b64uEncode(sig) } }
}

const ISSUER = 'store.example.com'
const seed1 = Uint8Array.from({ length: 32 }, () => 21)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/2026-01#ed25519-1`
const kidGhost = `${ISSUER}/keys/2026-01#ed25519-ghost` // never listed in the manifest
const RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'

const keyManifest = parse(
  signManifest(
    {
      issuer: ISSUER,
      manifest_version: 1,
      issued_at: '2026-01-01T00:00:00Z',
      keys: [
        { kid: kid1, pub: pub1, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' },
      ],
    },
    kid1,
    seed1,
  ),
)

const record = (revokedAt = '2026-07-03T00:00:00Z') =>
  parse(signRecord({ receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: revokedAt }, kid1, seed1))

// classifyRevocation only reads receipt_id and license.* (issued_at only for refund_window).
const policyPayload = parse({
  receipt_id: RECEIPT_ID,
  issued_at: '2026-07-01T00:00:00Z',
  license: { revocability: 'policy' },
})

describe('cached manifest self-verify (improvement #17)', () => {
  it('runs manifestSignatureIsAuthentic exactly once per classification', () => {
    const view = [1, 2, 3, 4, 5].map((d) => record(`2026-07-0${d}T00:00:00Z`))
    const warnings: string[] = []
    const errors: string[] = []
    vi.mocked(manifestSignatureIsAuthentic).mockClear()
    const result = classifyRevocation(policyPayload, view, keyManifest, warnings, errors)
    expect(result).toBe('revoked')
    expect(vi.mocked(manifestSignatureIsAuthentic)).toHaveBeenCalledTimes(1)
  })

  it('verifyRecordSignature accepts a valid record against a pre-verified manifest', () => {
    expect(verifyKeyManifest(keyManifest)).toBe(true) // documented precondition
    expect(verifyRecordSignature(record(), keyManifest)).toBe(true)
  })

  it('verifyRecordSignature rejects an unlisted signer kid', () => {
    const ghost = parse(
      signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2026-07-03T00:00:00Z' },
        kidGhost,
        seed1,
      ),
    )
    expect(verifyRecordSignature(ghost, keyManifest)).toBe(false)
  })

  it('verifyRecordSignature rejects revoked_at before valid_from', () => {
    expect(verifyRecordSignature(record('2025-12-31T23:59:59Z'), keyManifest)).toBe(false)
  })

  it('verifyRecord still requires manifest self-consistency (delegation)', () => {
    expect(verifyRecord(record(), keyManifest)).toBe(true)
    const tampered = { ...keyManifest, issued_at: '2027-01-01T00:00:00Z' } as JsonObject
    expect(verifyRecord(record(), tampered)).toBe(false)
  })
})

describe('revocation view bound (improvement #17, fail-closed)', () => {
  it('exports the default cap', () => {
    expect(MAX_REVOCATION_RECORDS).toBe(10_000)
  })

  it('oversized view on a revocable receipt fails closed (error, not warning)', () => {
    const view = [1, 2, 3, 4].map((d) => record(`2026-07-0${d}T00:00:00Z`))
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(policyPayload, view, keyManifest, warnings, errors, 3)
    expect(result).toBe('unknown')
    expect(errors).toContain('revocation view exceeds 3 records (4 supplied), cannot certify a revocable receipt')
    expect(warnings).toEqual([])
  })

  it('oversized view on the refund_window revocable class also fails closed', () => {
    const refundPayload = parse({ receipt_id: RECEIPT_ID, issued_at: '2026-07-01T00:00:00Z', license: { revocability: 'refund_window', revocation_window_days: 14 } })
    const view = [1, 2, 3, 4].map((d) => record(`2026-07-0${d}T00:00:00Z`))
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(refundPayload, view, keyManifest, warnings, errors, 3)
    expect(result).toBe('unknown')
    expect(errors).toContain('revocation view exceeds 3 records (4 supplied), cannot certify a revocable receipt')
    expect(warnings).toEqual([])
  })

  // Until 2026-09-01 this asserted a warning and no error, on the reasoning the
  // spec itself carried: "a revocation record can never affect ok". v0.2 §17.3
  // ended that — the key-authorization gate covers ALL revocability classes, and a backed
  // `status: "transferred"` record rides this same view, so the old assertion
  // said an oversized feed may hide a transfer from the strongest class.
  it('oversized view on an irrevocable receipt fails closed too', () => {
    const nonePayload = parse({ receipt_id: RECEIPT_ID, issued_at: '2026-07-01T00:00:00Z', license: { revocability: 'none' } })
    const view = [1, 2, 3, 4].map((d) => record(`2026-07-0${d}T00:00:00Z`))
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(nonePayload, view, keyManifest, warnings, errors, 3)
    expect(result).toBe('unknown')
    expect(errors).toContain('revocation view exceeds 3 records (4 supplied), cannot rule out a transfer')
    expect(warnings).toEqual([])
  })

  it('view exactly at cap evaluates normally (boundary is strict >)', () => {
    const view = [1, 2, 3].map((d) => record(`2026-07-0${d}T00:00:00Z`))
    const warnings: string[] = []
    const errors: string[] = []
    expect(classifyRevocation(policyPayload, view, keyManifest, warnings, errors, 3)).toBe('revoked')
    expect(warnings).toEqual([])
    expect(errors).toEqual([])
  })

  it('verify() fails closed on a revocable receipt when a genuine revocation is padded past the cap', () => {
    const dir = join(VECTORS_ROOT, '15-revoked-policy') // policy (revocable) receipt + its genuine revoked record
    const single = revocationView(dir)! // loader returns unknown[]; entries are loadsStrict-parsed
    const big = [0, 1, 2, 3].map(() => single[0]!) as JsonValue[] // 4 copies > cap 3
    const capped = verify(envelopeBytes(dir), trustStore(dir), big, null, 3)
    expect(capped.revocation).toBe('unknown')
    expect(capped.errors).toContain('revocation view exceeds 3 records (4 supplied), cannot certify a revocable receipt')
    expect(isOk(capped)).toBe(false)
    const uncapped = verify(envelopeBytes(dir), trustStore(dir), big)
    expect(uncapped.revocation).toBe('revoked')
  })

  it('does not deep-walk (assertCanonParsed) an oversized JSON.parse-d view — bounds work and matches Python', () => {
    // A JSON.parse-d view has JS-number fields that assertCanonParsed rejects with
    // TypeError. Oversized, it must skip that walk (length-guarded) and fail closed
    // like Python, which never inspects elements before the len() cap.
    const dir = join(VECTORS_ROOT, '15-revoked-policy')
    const jsonParsedJunk = Array.from({ length: 4 }, () => ({ receipt_id: 'x', status: 'revoked', revoked_at: '2026-07-03T00:00:00Z', manifest_version: 2 }))
    const capped = verify(envelopeBytes(dir), trustStore(dir), jsonParsedJunk as unknown as JsonValue[], null, 3)
    expect(capped.revocation).toBe('unknown')
    expect(isOk(capped)).toBe(false)
  })
})
