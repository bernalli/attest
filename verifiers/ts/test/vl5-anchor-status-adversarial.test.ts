import { describe, expect, it } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { b64uEncode } from '../src/b64u.js'
import { canonicalBytes, loadsStrict, type JsonObject } from '../src/canon.js'
import { verify } from '../src/index.js'
import type { TrustStore } from '../src/manifests.js'
import { classifyRevocation } from '../src/revocation.js'

const enc = (value: string): Uint8Array => new TextEncoder().encode(value)
const parse = (value: unknown): JsonObject => loadsStrict(enc(JSON.stringify(value))) as JsonObject

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/test#ed25519-1`
const RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'
const OTHER_RECEIPT_ID = '01J1V5B4M9Z8QWERTY99999999'
const OLDER = '2026-07-05T00:00:00Z'
const FUTURE = '2099-01-01T00:00:00Z'
const seed = Uint8Array.from({ length: 32 }, () => 7)
const pub = b64uEncode(ed25519.getPublicKey(seed))

function signManifest(): JsonObject {
  const body = {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2026-01-01T00:00:00Z',
    keys: [{ kid: KID, pub, valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }],
  }
  const sig = ed25519.sign(canonicalBytes(parse(body)), seed)
  return parse({ ...body, manifest_signature: { kid: KID, sig: b64uEncode(sig) } })
}

function trustStore(): TrustStore {
  return { manifests: { [ISSUER]: signManifest() }, provenance: { [ISSUER]: 'tls' } }
}

function signRecord(receiptId: string, status: unknown, revokedAt: string): JsonObject {
  const body = { receipt_id: receiptId, status, revoked_at: revokedAt }
  const sig = ed25519.sign(canonicalBytes(parse(body)), seed)
  return parse({ ...body, signature: { kid: KID, sig: b64uEncode(sig) } })
}

function receiptPayload(receiptId = RECEIPT_ID): JsonObject {
  return parse({
    issuer: { id: ISSUER, display_name: 'Example Store' },
    issued_at: '2026-01-02T00:00:00Z',
    receipt_id: receiptId,
    license: { revocability: 'policy' },
  })
}

function envelopeBytes(): Uint8Array {
  const payload = parse({
    attest_version: '0.1',
    issued_at: '2026-01-02T00:00:00Z',
    receipt_id: RECEIPT_ID,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' }, artifact_series: 'series-x' },
    license: {
      grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-free',
      terms_uri: 'https://example.test/terms', legal_text_sha256: 'a'.repeat(64),
    },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: b64uEncode(ed25519.getPublicKey(Uint8Array.from({ length: 32 }, () => 8))) },
    survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: true },
  })
  const sig = ed25519.sign(canonicalBytes(payload), seed)
  return enc(JSON.stringify({ payload, signatures: [{ kid: KID, alg: 'Ed25519', sig: b64uEncode(sig) }] }))
}

function classify(records: JsonObject[], receiptId = RECEIPT_ID): { result: string, warnings: string[] } {
  const warnings: string[] = []
  const errors: string[] = []
  return { result: classifyRevocation(receiptPayload(receiptId), records, signManifest(), warnings, errors), warnings }
}

describe('v0.1 section 12.3 statement-status freshness anchor', () => {
  it.each([
    'Revoked', 'revoked ', 'revoke', 'transferred_pending', 7, true, null, { status: 'revoked' },
  ])('drops authenticated unregistered status %j regardless of its receipt target', (status) => {
    const other = classify([signRecord(OTHER_RECEIPT_ID, status, FUTURE)])
    const matching = classify([signRecord(RECEIPT_ID, status, FUTURE)])

    expect(other.result).toBe('unknown')
    expect(matching.result).toBe('unknown')
    expect(matching.warnings).toEqual([])
  })

  it.each(['revoked', 'transferred'] as const)('uses only genuine %s statements for the order-independent anchor', (statementStatus) => {
    const genuine = signRecord(OTHER_RECEIPT_ID, statementStatus, OLDER)
    const unregistered = signRecord('01J1V5B4M9Z8QWERTY88888888', 'transferred_pending', FUTURE)

    expect(classify([genuine, unregistered]).result).toBe(`not_revoked_as_of:${OLDER}`)
    expect(classify([unregistered, genuine]).result).toBe(`not_revoked_as_of:${OLDER}`)
  })

  it('does not let a broken statement signature anchor T', () => {
    const genuine = signRecord(OTHER_RECEIPT_ID, 'revoked', OLDER)
    const forged = signRecord('01J1V5B4M9Z8QWERTY77777777', 'revoked', FUTURE)
    ;(forged['signature'] as JsonObject)['sig'] = 'A'.repeat(86)

    expect(classify([forged]).result).toBe('unknown')
    expect(classify([genuine, forged]).result).toBe(`not_revoked_as_of:${OLDER}`)
  })

  it('keeps genuine revoked records effective and uses them as anchors', () => {
    const record = signRecord(RECEIPT_ID, 'revoked', OLDER)

    expect(classify([record]).result).toBe('revoked')
    expect(classify([record], OTHER_RECEIPT_ID).result).toBe(`not_revoked_as_of:${OLDER}`)
  })

  it('keeps genuine transferred records as anchors through the public verifier', () => {
    const record = signRecord(OTHER_RECEIPT_ID, 'transferred', OLDER)
    const result = verify(envelopeBytes(), trustStore(), [record], null, undefined)

    expect(result.revocation).toBe(`not_revoked_as_of:${OLDER}`)
  })
})
