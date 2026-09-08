// Mirrors the RECEIPT-PATH cases of tests/test_trusted_manifest_gate.py (the
// Python reference). Not yet mirrored from that file, and named here so the
// gap is a decision and not an oversight: the v0.2 hybrid receipt path's
// inheritance of the gate, and the stray-PQ-leg-on-a-non-hybrid-signer refusal
// (both covered indirectly by (e) below and directly by manifests.test.ts).
//
// The receipt path must authenticate the trusted key manifest itself.
// `verify()` resolves the issuer's key manifest from the trust store and then
// verifies the receipt signature against the keys it lists. Until this gate
// existed, nothing ever asked whether that manifest was self-consistent: the
// side-document paths call `manifests.verifyKeyManifest()` (transfer,
// revocation), the receipt path did not. A manifest whose own signature does
// not check out is not evidence of anything, and a verifier that reads keys
// out of it is trusting an attacker's edit of a file it never authenticated.
//
// Each test tampers with a manifest WITHOUT re-signing it, so
// `manifestSignatureIsAuthentic` is false by construction, and asserts the
// receipt is refused. The honest control proves the tampering is what makes
// the difference and that the gate does not reject good manifests.
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { loadsStrict, canonicalBytes } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { verify, isOk } from '../src/verify.js'
import { verifyKeyManifest, manifestSignatureIsAuthentic } from '../src/manifests.js'
import type { TrustStore } from '../src/trustMaterial.js'
import { store as parsedStore } from './helpers/trust.js'
// Assert on the SHIPPED message builders, never on hand-copied substrings: a
// negative substring assertion (`.some(e => e.includes('x'))` is false) passes
// both when the branch did not fire and when someone renamed the message, and
// (d) below turns on telling exactly those two refusals apart.
import { manifestNotSelfConsistent, keyCompromised } from '../src/messages.js'
import { ML_DSA_65_ALG, ML_DSA_65_SIG_LEN } from '../src/mldsa.js'
// Key-manifest construction is NOT reimplemented here: `helpers/grant-builder.ts`
// already carries the single, tested `keyEntry`/`buildKeyManifest` builders
// (mirroring manifests.py's `key_entry`/`build_key_manifest`) shared by
// transfer.test.ts, sibling-hybrid.test.ts, authority*.test.ts and
// grant.test.ts. Reusing it here keeps ownership of that logic in one place
// instead of adding a second copy under a new file name.
import { keyEntry, buildKeyManifest, edSigner, hybridSigner, signBlock } from './helpers/grant-builder.js'
import type { TestSigner } from './helpers/grant-builder.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (v: unknown): JsonObject => loadsStrict(enc(JSON.stringify(v))) as JsonObject

const ISSUER = 'store.example.com'
const VALID_FROM = '2026-01-01T00:00:00Z'
const MANIFEST_ISSUED_AT = '2026-06-01T00:00:00Z'

const KID_A = `${ISSUER}/keys/test#ed25519-a`
const KID_B = `${ISSUER}/keys/test#ed25519-b`
const KID_H = `${ISSUER}/keys/test#hybrid-1`

// TEST ONLY — fixed seeds, never use in production. Mirrors KPA/KPB/KP_ATTACKER.
const SIGNER_A = edSigner(70)
const SIGNER_B = edSigner(71)
const SIGNER_ATTACKER = edSigner(72)
const SIGNER_H = hybridSigner(73)

function honestManifest(): JsonObject {
  return buildKeyManifest(
    ISSUER,
    1,
    MANIFEST_ISSUED_AT,
    [keyEntry(KID_A, SIGNER_A, VALID_FROM), keyEntry(KID_B, SIGNER_B, VALID_FROM)],
    SIGNER_B,
    KID_B,
  )
}

function trustStoreFor(manifest: JsonObject, provenance: 'tls' | 'tofu' = 'tls'): TrustStore {
  return parsedStore({ manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: provenance } })
}

function receiptPayloadV1(): JsonObject {
  return parse({
    attest_version: '0.1',
    issued_at: '2026-01-15T00:00:00Z',
    receipt_id: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    work: {
      title: 'Example Work',
      publisher: 'Example Publisher',
      identifiers: { issuer_sku: 'SKU-1' },
      artifact_series: 'series-1',
    },
    license: {
      grant: 'perpetual',
      revocability: 'none',
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://example.com/terms',
      legal_text_sha256: 'a'.repeat(64),
    },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email' },
    survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: true },
  })
}

function issueV1(signer: TestSigner, kid: string): Uint8Array {
  const payload = receiptPayloadV1()
  const sig = ed25519.sign(canonicalBytes(payload), signer.edSeed)
  return enc(JSON.stringify({ payload, signatures: [{ kid, alg: 'Ed25519', sig: b64uEncode(sig) }] }))
}

function receiptPayloadV02(): JsonObject {
  return parse({ ...(receiptPayloadV1() as unknown as Record<string, unknown>), attest_version: '0.2' })
}

function issueV02(signer: TestSigner, kid: string): Uint8Array {
  const payload = receiptPayloadV02()
  const bytes = canonicalBytes(payload)
  const edSig = ed25519.sign(bytes, signer.edSeed)
  const mldsaSig = ml_dsa65.sign(bytes, signer.mldsaSecret!)
  return enc(
    JSON.stringify({
      payload,
      signatures: [
        { kid, alg: 'Ed25519', sig: b64uEncode(edSig) },
        { kid, alg: ML_DSA_65_ALG, sig: b64uEncode(mldsaSig) },
      ],
    }),
  )
}

function hybridManifest(): JsonObject {
  return buildKeyManifest(ISSUER, 1, MANIFEST_ISSUED_AT, [keyEntry(KID_H, SIGNER_H, VALID_FROM)], SIGNER_H, KID_H)
}

const RECEIPT_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAV' // must equal receiptPayloadV1()'s

function receiptPayloadV02Revocable(): JsonObject {
  const base = receiptPayloadV1() as unknown as Record<string, unknown>
  return parse({
    ...base,
    attest_version: '0.2',
    license: { ...(base['license'] as Record<string, unknown>), revocability: 'policy' },
  })
}

function issueV02Revocable(signer: TestSigner, kid: string): Uint8Array {
  const payload = receiptPayloadV02Revocable()
  const bytes = canonicalBytes(payload)
  return enc(
    JSON.stringify({
      payload,
      signatures: [
        { kid, alg: 'Ed25519', sig: b64uEncode(ed25519.sign(bytes, signer.edSeed)) },
        { kid, alg: ML_DSA_65_ALG, sig: b64uEncode(ml_dsa65.sign(bytes, signer.mldsaSecret!)) },
      ],
    }),
  )
}

/** Mirrors revocation.py's `build_record`: body plus a signature block over its
 * canonical bytes, hybrid iff the signer is. */
function buildRecord(receiptId: string, status: string, revokedAt: string, signer: TestSigner, kid: string): JsonObject {
  const body = { receipt_id: receiptId, status, revoked_at: revokedAt }
  return parse({ ...body, signature: signBlock(canonicalBytes(parse(body)), signer, kid) })
}

function withCorruptedSelfSignature(manifest: JsonObject): JsonObject {
  const block = manifest['manifest_signature'] as JsonObject
  return { ...manifest, manifest_signature: { ...block, sig: b64uEncode(new Uint8Array(64)) } }
}

function withSwappedPub(manifest: JsonObject, kid: string, attackerPub: Uint8Array): JsonObject {
  const keys = (manifest['keys'] as JsonObject[]).map((entry) =>
    entry['kid'] === kid ? { ...entry, pub: b64uEncode(attackerPub) } : entry,
  )
  return { ...manifest, keys }
}

function withStatus(manifest: JsonObject, kid: string, status: string): JsonObject {
  const keys = (manifest['keys'] as JsonObject[]).map((entry) => (entry['kid'] === kid ? { ...entry, status } : entry))
  return { ...manifest, keys }
}

describe('trusted manifest gate (parity: tests/test_trusted_manifest_gate.py)', () => {
  // (a) control — the gate must not cost a good manifest its verdict.
  it('an honest manifest still certifies its own receipt', () => {
    const result = verify(issueV1(SIGNER_A, KID_A), trustStoreFor(honestManifest()))
    expect(isOk(result)).toBe(true)
    expect(result.signature).toBe('valid')
  })

  // (b) a manifest whose own signature fails is not a trust anchor, under
  // EITHER provenance — it reaches `trust: verified` under `tls`, the level
  // claiming the strongest guarantee, so the refusal must not depend on it.
  it.each(['tls', 'tofu'] as const)(
    'a manifest with a broken self-signature is refused (provenance=%s)',
    (provenance) => {
      const manifest = withCorruptedSelfSignature(honestManifest())
      const result = verify(issueV1(SIGNER_A, KID_A), trustStoreFor(manifest, provenance))
      expect(isOk(result)).toBe(false)
      expect(result.signature).toBe('invalid')
      expect(result.errors).toEqual([manifestNotSelfConsistent(ISSUER)])
    },
  )

  // (c) the forgery this gate exists to stop: the attacker never touches the
  // issuer's private key, they replace `pub` on an entry with their own and
  // sign a receipt under the unchanged kid.
  it.each(['tls', 'tofu'] as const)(
    'a swapped public key cannot certify a forged receipt (provenance=%s)',
    (provenance) => {
      const manifest = withSwappedPub(honestManifest(), KID_A, SIGNER_ATTACKER.edPub)
      const result = verify(issueV1(SIGNER_ATTACKER, KID_A), trustStoreFor(manifest, provenance))
      expect(isOk(result)).toBe(false)
      expect(result.signature).toBe('invalid')
      expect(result.errors).toEqual([manifestNotSelfConsistent(ISSUER)])
    },
  )

  // (d) the absorbing key-status floor must not be undone by a text edit.
  // Two DIFFERENT rejections, and the test must tell them apart: the honest
  // "compromised" manifest is refused BY THE COMPROMISE FLOOR (errors say
  // "is compromised"); the resurrected copy — same word flipped back to
  // "active", no re-signature — is refused BY THE GATE ("not self-consistent"),
  // and must NOT say "is compromised" (that would mean the flip worked).
  it('a compromised key cannot be resurrected by editing its status', () => {
    const compromised = buildKeyManifest(
      ISSUER,
      2,
      MANIFEST_ISSUED_AT,
      [keyEntry(KID_A, SIGNER_A, VALID_FROM, { status: 'compromised' }), keyEntry(KID_B, SIGNER_B, VALID_FROM)],
      SIGNER_B,
      KID_B,
    )

    const refused = verify(issueV1(SIGNER_A, KID_A), trustStoreFor(compromised))
    expect(isOk(refused)).toBe(false)
    // Exact array, not `.some(includes(...))`: it carries BOTH halves of the
    // discrimination at once — this refusal IS the compromise floor and is NOT
    // the gate — and cannot silently weaken if a message is renamed.
    expect(refused.errors).toEqual([keyCompromised(KID_A)])

    const resurrected = withStatus(compromised, KID_A, 'active')

    const result = verify(issueV1(SIGNER_A, KID_A), trustStoreFor(resurrected))
    expect(isOk(result)).toBe(false)
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual([manifestNotSelfConsistent(ISSUER)])
  })

  // (e) the hybrid carve-out, pinned in BOTH directions. `manifest_signature`
  // sits outside the signed bytes, so an ABSENT PQ leg is the one downgrade
  // the corpus blesses (26-hybrid/h-manifest-downgraded-continuity); a
  // PRESENT-but-wrong leg is an edit, not a downgrade, and must be refused.
  it('an absent PQ leg on the manifest self-signature is the tolerated downgrade', () => {
    const manifest = hybridManifest()
    const block = manifest['manifest_signature'] as JsonObject
    const { sig_ml_dsa_65: _omit, ...rest } = block as Record<string, unknown>
    // The cast is load-bearing for `tsc`, not decoration: a rest-spread of an
    // index-signature object widens to `Record<string, unknown>`, which is not
    // a `JsonValue`. Without it this file does not type-check — and nothing
    // would say so, since tsconfig's `include` is `["src"]` and vitest strips
    // types without checking them.
    const downgraded = { ...manifest, manifest_signature: rest } as unknown as JsonObject

    const result = verify(issueV02(SIGNER_H, KID_H), trustStoreFor(downgraded))

    expect(isOk(result)).toBe(true)
    expect(result.signature).toBe('valid')
  })

  it('a present but wrong PQ leg on the manifest self-signature is refused, not tolerated', () => {
    const manifest = hybridManifest()
    const block = manifest['manifest_signature'] as JsonObject
    const grafted = { ...manifest, manifest_signature: { ...block, sig_ml_dsa_65: b64uEncode(new Uint8Array(ML_DSA_65_SIG_LEN)) } }

    const result = verify(issueV02(SIGNER_H, KID_H), trustStoreFor(grafted))

    expect(isOk(result)).toBe(false)
    expect(result.errors).toEqual([manifestNotSelfConsistent(ISSUER)])
  })

  // (f) the docstring promise the Python reference pins and this file did not:
  // `manifestSignatureIsAuthentic` NEVER raises on untrusted input, it fails
  // closed. A promise no test drives is one the next refactor breaks silently,
  // and this predicate reads an attacker-supplied document member by member.
  // Mirrors ::test_hostile_manifests_fail_closed_without_raising.
  const hostile: Record<string, (m: JsonObject) => JsonObject> = {
    'keys-not-a-list': (m) => ({ ...m, keys: { not: 'a list' } }) as unknown as JsonObject,
    'keys-member-not-an-object': (m) => ({ ...m, keys: [null] }) as unknown as JsonObject,
    'sig-block-not-an-object': (m) => ({ ...m, manifest_signature: [] }) as unknown as JsonObject,
    'sig-absent': (m) => {
      const block = { ...(m['manifest_signature'] as JsonObject) }
      delete block['sig']
      return { ...m, manifest_signature: block }
    },
    'sig-not-a-string': (m) => ({ ...m, manifest_signature: { ...(m['manifest_signature'] as JsonObject), sig: 7n } }),
    'sig-short': (m) => ({
      ...m,
      manifest_signature: { ...(m['manifest_signature'] as JsonObject), sig: b64uEncode(new Uint8Array(32)) },
    }),
    'pub-absent': (m) => ({
      ...m,
      keys: (m['keys'] as JsonObject[]).map((entry) => {
        const copy = { ...entry }
        delete copy['pub']
        return copy
      }),
    }),
    'pub-not-b64u': (m) => ({ ...m, keys: (m['keys'] as JsonObject[]).map((entry) => ({ ...entry, pub: '@@@@' })) }),
    'duplicate-kid': (m) => ({ ...m, keys: [...(m['keys'] as JsonObject[]), { kid: KID_H }] }),
    // A JS `number` never comes out of loadsStrict; it comes out of a consumer
    // who built the trust store with JSON.parse. Fail closed, do not throw.
    'js-number-outside-the-jcs-profile': (m) => ({ ...m, extra: 1.5 }) as unknown as JsonObject,
  }
  it.each(Object.keys(hostile))('a hostile manifest fails closed without throwing (%s)', (id) => {
    const mutated = hostile[id]!(hybridManifest())
    expect(() => manifestSignatureIsAuthentic(mutated)).not.toThrow()
    expect(manifestSignatureIsAuthentic(mutated)).toBe(false)
  })

  // (g) one manifest, one answer. The tolerance (e) pins has a price, and this
  // is it: a verifier must never hold a manifest authentic enough to certify a
  // receipt and not authentic enough to carry the same issuer's revocation.
  // Every manifest in that gap turns a revocation into silence, and reaching it
  // costs an attacker one deletion and no key at all. Pinning the tolerance
  // without pinning its price leaves the suite green over exactly that gap.
  // Mirrors ::test_a_downgraded_manifest_keeps_its_power_to_revoke and
  // ::test_an_unauthentic_manifest_carries_no_revocation_either.
  it('a PQ-downgraded manifest keeps its power to revoke; an edited one carries nothing', () => {
    const manifest = hybridManifest()
    const envelope = issueV02Revocable(SIGNER_H, KID_H)
    const record = buildRecord(RECEIPT_ID, 'revoked', '2026-07-01T00:00:00Z', SIGNER_H, KID_H)

    const honest = verify(envelope, trustStoreFor(manifest), [record])
    expect(honest.revocation).toBe('revoked')
    expect(isOk(honest)).toBe(false)

    const block = manifest['manifest_signature'] as JsonObject
    const { sig_ml_dsa_65: _omit, ...rest } = block as Record<string, unknown>
    const downgraded = { ...manifest, manifest_signature: rest } as unknown as JsonObject
    // The asymmetry the gate rests on: not a valid manifest, still an authentic
    // signature — `manifest_signature` sits outside the signed bytes.
    expect(verifyKeyManifest(downgraded)).toBe(false)
    expect(manifestSignatureIsAuthentic(downgraded)).toBe(true)

    const kept = verify(envelope, trustStoreFor(downgraded), [record])
    expect(kept.signature).toBe('valid')
    expect(kept.revocation).toBe('revoked')
    expect(isOk(kept)).toBe(false)

    const edited = { ...manifest, manifest_signature: { ...block, sig: b64uEncode(new Uint8Array(64)) } }
    const refused = verify(envelope, trustStoreFor(edited), [record])
    expect(refused.signature).toBe('invalid')
    expect(refused.revocation).toBe('unknown')
    expect(refused.errors).toEqual([manifestNotSelfConsistent(ISSUER)])
  })
})
