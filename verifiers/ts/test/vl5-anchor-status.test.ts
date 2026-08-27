import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { classifyRevocation } from '../src/revocation.js'

// V-L.5 parity with src/attest/verify.py's `_ANCHOR_STATUSES`
// (v0.1 §12.3, 2026-08-26 amendment): only a registered revocation-statement
// status may drive the freshness anchor T.

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (v: unknown): JsonObject => loadsStrict(enc(JSON.stringify(v))) as JsonObject

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/2025-01#ed25519-1`
const RECEIPT_ID = '01J1V5B4M9Z8QWERTY12345678'
const OTHER_ID = '01HZX0000000000000000000AA'
const seed = Uint8Array.from({ length: 32 }, () => 7)
const pub = b64uEncode(ed25519.getPublicKey(seed))

function signed(body: Record<string, unknown>, field: string): JsonObject {
  const unsigned = parse(body)
  return parse({
    ...body,
    [field]: { kid: KID, sig: b64uEncode(ed25519.sign(canonicalBytes(unsigned), seed)) },
  })
}

const manifest = signed(
  {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2025-01-01T00:00:00Z',
    keys: [{ kid: KID, pub, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' }],
  },
  'manifest_signature',
)

function record(receiptId: string, status: unknown, revokedAt: string): JsonObject {
  return signed(
    { receipt_id: receiptId, status, revoked_at: revokedAt, issuer: ISSUER },
    'signature',
  )
}

const payload = parse({ receipt_id: RECEIPT_ID, license: { revocability: 'policy' } })

function classify(view: JsonObject[]): string {
  const warnings: string[] = []
  const errors: string[] = []
  return classifyRevocation(payload, view, manifest, warnings, errors)
}

describe('freshness anchor counts only registered revocation statements', () => {
  it('a registered statement still anchors', () => {
    expect(classify([record(OTHER_ID, 'revoked', '2026-07-05T00:00:00Z')])).toBe(
      'not_revoked_as_of:2026-07-05T00:00:00Z',
    )
  })

  it('a transferred statement still anchors', () => {
    expect(classify([record(OTHER_ID, 'transferred', '2026-07-05T00:00:00Z')])).toBe(
      'not_revoked_as_of:2026-07-05T00:00:00Z',
    )
  })

  it.each([
    ['recalled', 'an unregistered literal'],
    ['Revoked', 'a capitalised near-miss'],
    ['revoked ', 'a trailing-space near-miss'],
    ['revoke', 'a truncated near-miss'],
    ['transferred_pending', 'a prefixed near-miss'],
  ])('%s (%s) does not anchor, on an unrelated receipt', (status) => {
    expect(classify([record(OTHER_ID, status, '2099-01-01T00:00:00Z')])).toBe('unknown')
  })

  it.each([[7], [true], [null], [{}]])(
    'a non-string status (%s) does not anchor',
    (status: unknown) => {
      expect(classify([record(OTHER_ID, status, '2099-01-01T00:00:00Z')])).toBe('unknown')
    },
  )

  it('an unregistered status on the MATCHING receipt neither revokes nor anchors', () => {
    expect(classify([record(RECEIPT_ID, 'recalled', '2099-01-01T00:00:00Z')])).toBe('unknown')
  })

  it('a far-future non-statement cannot inflate a genuine older anchor, in either order', () => {
    const genuine = record(OTHER_ID, 'revoked', '2026-07-05T00:00:00Z')
    const junk = record(OTHER_ID, 'recalled', '2099-01-01T00:00:00Z')

    for (const view of [[genuine, junk], [junk, genuine]]) {
      expect(classify(view)).toBe('not_revoked_as_of:2026-07-05T00:00:00Z')
    }
  })
})
