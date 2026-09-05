// Two Python↔TypeScript parity defects in the revocation path, both measured
// before this file existed. Each `it` states the PYTHON behaviour,
// which is the reference: Python physically cannot represent a refund-window
// deadline past `datetime.max`, so it cannot adopt the TypeScript answer.
//
// Both defects have the same shape: a predicate this module needs was already
// written elsewhere in the tree — the representable-time bound three times, the
// ULID pattern twice — and this call site did not import any of them. A
// restated predicate is owned by nobody, so the tests below pin the SHARED
// definitions, not local copies of the numbers.
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { classifyRevocation, verifyRecordSignature } from '../src/revocation.js'
import { MAX_REPRESENTABLE_UNIX_SECONDS } from '../src/dates.js'
import { RECEIPT_ID_RE } from '../src/ids.js'
import { REFUND_WINDOW_UNREPRESENTABLE } from '../src/messages.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject

function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  return { ...body, manifest_signature: { kid, sig: b64uEncode(ed25519.sign(canonicalBytes(b), seed)) } }
}

function signRecord(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  return { ...body, signature: { kid, sig: b64uEncode(ed25519.sign(canonicalBytes(b), seed)) } }
}

const ISSUER = 'store.example.com'
const seed1 = Uint8Array.from({ length: 32 }, () => 7)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/2025-01#ed25519-1`

const keyManifest = signManifest(
  {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2025-01-01T00:00:00Z',
    keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' }],
  },
  kid1,
  seed1,
)

const RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'
// A well-formed ULID that is NOT the receipt under test: it authenticates, so it
// drives the freshness anchor without ever becoming an effective record.
const OTHER_RECEIPT_ID = '01J1V5B4M9Z8QWERTY1234567A'

function refundPayload(issuedAt: string, windowDays = 14): JsonObject {
  return parse({
    issuer: { id: ISSUER },
    issued_at: issuedAt,
    receipt_id: RECEIPT_ID,
    license: { revocability: 'refund_window', revocation_window_days: windowDays },
  })
}

describe('a refund-window deadline past the representable range', () => {
  // The cliff is exact and both sides of it are pinned. A guard that only
  // checked the far side could over-trigger and reject an ordinary receipt
  // while every test stayed green.
  it('the LAST representable deadline stays an ordinary evaluation', () => {
    const payload = refundPayload('9999-12-17T23:59:59Z')
    const record = signRecord(
      { receipt_id: OTHER_RECEIPT_ID, status: 'revoked', revoked_at: '9999-12-17T23:59:59Z' },
      kid1,
      seed1,
    )
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
    expect(errors).toEqual([])
    expect(result).toBe('not_revoked_as_of:9999-12-17T23:59:59Z')
  })

  it('the FIRST unrepresentable deadline is an error, not a certification', () => {
    const payload = refundPayload('9999-12-18T00:00:00Z')
    const record = signRecord(
      { receipt_id: OTHER_RECEIPT_ID, status: 'revoked', revoked_at: '9999-12-18T00:00:00Z' },
      kid1,
      seed1,
    )
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
    expect(result).toBe('unknown')
    expect(errors).toEqual([REFUND_WINDOW_UNREPRESENTABLE])
  })

  // 3650 days is the schema ceiling for `revocation_window_days`, so it is the
  // window that opens the band earliest — nine years before the 14-day cliff.
  // Both sides of THIS cliff are pinned too, and the two dates are measured,
  // not reasoned: `9990-01-02 + 3650d` lands exactly on 9999-12-31 and is fine;
  // `9990-01-03` is the first that overflows.
  it('the last representable deadline at the schema-maximum window is ordinary', () => {
    const payload = refundPayload('9990-01-02T00:00:00Z', 3650)
    const record = signRecord(
      { receipt_id: OTHER_RECEIPT_ID, status: 'revoked', revoked_at: '9990-01-02T00:00:00Z' },
      kid1,
      seed1,
    )
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
    expect(errors).toEqual([])
    expect(result).toBe('not_revoked_as_of:9990-01-02T00:00:00Z')
  })

  it('the schema-maximum window opens the same band nine years earlier', () => {
    const payload = refundPayload('9990-01-03T00:00:00Z', 3650)
    const record = signRecord(
      { receipt_id: OTHER_RECEIPT_ID, status: 'revoked', revoked_at: '9990-01-03T00:00:00Z' },
      kid1,
      seed1,
    )
    const warnings: string[] = []
    const errors: string[] = []
    expect(classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)).toBe('unknown')
    expect(errors).toEqual([REFUND_WINDOW_UNREPRESENTABLE])
  })

  it('a MATCHING record in the unrepresentable band cannot be certified either', () => {
    // The deadline is a property of the RECEIPT, so the refusal must not wait
    // for the view to contain a record about this receipt.
    const payload = refundPayload('9999-12-20T00:00:00Z')
    const record = signRecord(
      { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '9999-12-20T00:00:00Z' },
      kid1,
      seed1,
    )
    const warnings: string[] = []
    const errors: string[] = []
    expect(classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)).toBe('unknown')
    expect(errors).toEqual([REFUND_WINDOW_UNREPRESENTABLE])
  })

  it('the bound is the one the rest of the tree already declares', () => {
    // 253402300799 = 9999-12-31T23:59:59Z. If this ever needs changing, it must
    // change in ONE place; a test that hardcoded its own copy would be the
    // fourth restatement of the very predicate this fix exists to remove.
    expect(MAX_REPRESENTABLE_UNIX_SECONDS).toBe(253402300799)
    expect(new Date(MAX_REPRESENTABLE_UNIX_SECONDS * 1000).toISOString()).toBe('9999-12-31T23:59:59.000Z')
  })
})

describe('a revocation record whose receipt_id is not a receipt id', () => {
  // Python types and shape-checks `receipt_id` BEFORE anything authenticates
  // (`revocation.py`), because a record the issuer signed but left malformed
  // "must not authenticate, or it feeds the freshness anchor a statement about
  // a receipt it does not name". The TypeScript twin never read the field.
  const malformed: Array<[string, unknown]> = [
    ['not in the ULID alphabet (O)', '01JBQ0000000000000000OTHER'],
    ['lowercase', OTHER_RECEIPT_ID.toLowerCase()],
    ['trailing newline', `${OTHER_RECEIPT_ID}\n`],
    ['too short', '01J1V5B4M9Z8QWERTY123456'],
    ['first character out of range', '81J1V5B4M9Z8QWERTY1234567A'],
    ['a number', 12345],
    ['null', null],
    ['absent', undefined],
  ]

  malformed.forEach(([label, receiptId]) => {
    it(`a genuinely signed record whose receipt_id is ${label} does not authenticate`, () => {
      const body: Record<string, unknown> = { status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' }
      if (receiptId !== undefined) body['receipt_id'] = receiptId
      const record = signRecord(body, kid1, seed1)
      // The signature itself is genuine — this is the issuer's own active key.
      // Only the shape of the field is wrong, and that alone must stop it.
      expect(verifyRecordSignature(parse(record), parse(keyManifest))).toBe(false)
    })
  })

  it('a well-formed receipt_id still authenticates', () => {
    // The negative control. Without it the guard could reject every record and
    // stay green.
    const record = signRecord(
      { receipt_id: OTHER_RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
      kid1,
      seed1,
    )
    expect(verifyRecordSignature(parse(record), parse(keyManifest))).toBe(true)
  })

  it('a malformed receipt_id cannot set the freshness anchor', () => {
    // The consequence that matters to a holder: an unauthenticated record must
    // not be able to answer "not revoked as of <date>" on the receipt's behalf.
    const payload = parse({
      issuer: { id: ISSUER },
      issued_at: '2025-07-01T00:00:00Z',
      receipt_id: RECEIPT_ID,
      license: { revocability: 'policy' },
    })
    const record = signRecord(
      { receipt_id: '01JBQ0000000000000000OTHER', status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
      kid1,
      seed1,
    )
    const warnings: string[] = []
    const errors: string[] = []
    expect(classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)).toBe('unknown')
  })

  it('the ULID pattern is the one the rest of the tree already declares', () => {
    expect(RECEIPT_ID_RE.source).toBe('^[0-7][0-9A-HJKMNP-TV-Z]{25}$')
    expect(RECEIPT_ID_RE.test(RECEIPT_ID)).toBe(true)
    expect(RECEIPT_ID_RE.test('01JBQ0000000000000000OTHER')).toBe(false)
  })
})
