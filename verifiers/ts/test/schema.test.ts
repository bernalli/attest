import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { validatePayload, SCHEMA_TOP_LEVEL_KEYS } from '../src/schema.js'
import { loadsStrict, JsonObject } from '../src/canon.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const enc = (s: string) => new TextEncoder().encode(s)

const MINIMAL = () => loadsStrict(enc(JSON.stringify({
  attest_version: '0.1', issued_at: '2025-06-01T00:00:00Z', receipt_id: '01J000000000000000000000AA',
  issuer: { display_name: 'Store', id: 'store.example.com' },
  work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' } },
  license: { grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-bound', terms_uri: 'https://x/t', legal_text_sha256: 'a'.repeat(64) },
  buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: null },
  survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: false },
  supersedes: null,
}))) as JsonObject

describe('validatePayload', () => {
  it('accepts a well-formed payload', () => { expect(validatePayload(MINIMAL())).toEqual([]) })
  it('rejects a missing required member', () => {
    const p = MINIMAL(); delete (p as any).issuer
    expect(validatePayload(p).length).toBeGreaterThan(0)
  })
  it('rejects an invalid drm enum', () => {
    const p = MINIMAL(); (p['license'] as any).drm = 'nope'
    expect(validatePayload(p).length).toBeGreaterThan(0)
  })
  it('top-level key set matches the schema (for unknown-field warnings)', () => {
    expect(SCHEMA_TOP_LEVEL_KEYS.has('attest_version')).toBe(true)
    expect(SCHEMA_TOP_LEVEL_KEYS.has('promo_code')).toBe(false)
  })
})

// v0.2 Stage 3 (§17): D1 conditional (buyer.pubkey required, non-null, when
// attest_version is 0.2 and license.transferable is true) + the
// not_transferable_before shape check.
const MINIMAL_V02_TRANSFERABLE = () => {
  const p = MINIMAL()
  ;(p as any).attest_version = '0.2'
  ;(p as any).license.transferable = true
  ;(p as any).buyer.pubkey = 'B'.repeat(43)
  return p
}

describe('validatePayload — D1 transferable conditional (v0.2 §17)', () => {
  it('accepts a well-formed v0.2 transferable payload', () => {
    expect(validatePayload(MINIMAL_V02_TRANSFERABLE())).toEqual([])
  })

  it('rejects a null buyer.pubkey when transferable is true (attest_version 0.2)', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).buyer.pubkey = null
    expect(validatePayload(p)).toContain(
      'buyer.pubkey: must be a non-null 43-char base64url string when license.transferable is true (attest_version 0.2)',
    )
  })

  it('rejects a missing buyer.pubkey when transferable is true (attest_version 0.2)', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    delete (p as any).buyer.pubkey
    expect(validatePayload(p)).toContain(
      'buyer.pubkey: must be a non-null 43-char base64url string when license.transferable is true (attest_version 0.2)',
    )
  })

  it('does not apply the conditional under attest_version 0.1, even if transferable is true', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).attest_version = '0.1'
    ;(p as any).buyer.pubkey = null
    expect(validatePayload(p)).toEqual([])
  })

  it('does not apply the conditional when license.transferable is false', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).license.transferable = false
    ;(p as any).buyer.pubkey = null
    expect(validatePayload(p)).toEqual([])
  })
})

describe('validatePayload — license.not_transferable_before (v0.2 §17.7)', () => {
  it('accepts a well-formed not_transferable_before', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).license.not_transferable_before = '2026-08-01T00:00:00Z'
    expect(validatePayload(p)).toEqual([])
  })

  it('rejects a non-canonical not_transferable_before', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).license.not_transferable_before = '2026-8-1T0:0:0Z'
    expect(validatePayload(p)).toContain(
      'license.not_transferable_before: must be an RFC3339 UTC date-time (YYYY-MM-DDTHH:MM:SSZ)',
    )
  })

  it.each(['2026-02-30T00:00:00Z', '2026-13-01T00:00:00Z', '2026-04-31T00:00:00Z'])(
    'keeps calendar-impossible not_transferable_before as schema-valid wire shape (%s)',
    (notTransferableBefore) => {
      const p = MINIMAL_V02_TRANSFERABLE()
      ;(p as any).license.not_transferable_before = notTransferableBefore
      expect(validatePayload(p)).toEqual([])
    },
  )
})

// v0.2 Stage 4 (§18): the license term license.preservation_pledge (§18.2,
// three REQUIRED members, NOT a closed object), work.publisher_id (§18.1), and
// the D5 holder-binding conditional (§18.6) — gated on attest_version 0.2, so
// v0.1 receipts are untouched.
const PLEDGE = () => ({
  pledge: 'sunset-grant-v1',
  grant_uri: 'https://pub.example/sunset-grant-v1.json',
  grant_sha256: 'a'.repeat(64),
})

const MINIMAL_V02_PLEDGE = () => {
  const p = MINIMAL()
  ;(p as any).attest_version = '0.2'
  ;(p as any).license.preservation_pledge = PLEDGE()
  ;(p as any).buyer.pubkey = 'B'.repeat(43)
  ;(p as any).work.publisher_id = 'pub.example'
  ;(p as any).survivability.end_of_life = 'sunset-grant'
  return p
}

describe('validatePayload — license.preservation_pledge shape (v0.2 §18.2)', () => {
  it('accepts a well-formed pledge-bearing v0.2 payload', () => {
    expect(validatePayload(MINIMAL_V02_PLEDGE())).toEqual([])
  })

  it('rejects a non-object preservation_pledge', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).license.preservation_pledge = 'sunset-grant-v1'
    expect(validatePayload(p)).toContain('license.preservation_pledge: must be an object')
  })

  it.each(['pledge', 'grant_uri', 'grant_sha256'])('rejects a preservation_pledge missing %s', (member) => {
    const p = MINIMAL_V02_PLEDGE()
    delete (p as any).license.preservation_pledge[member]
    expect(validatePayload(p)).toContain(`license.preservation_pledge.${member}: required`)
  })

  it('rejects an empty pledge profile string', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).license.preservation_pledge.pledge = ''
    expect(validatePayload(p)).toContain('license.preservation_pledge.pledge: must be a non-empty string')
  })

  it('accepts an UNRECOGNIZED pledge profile: the vocabulary is open, never an enum (§18.2)', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).license.preservation_pledge.pledge = 'sunset-grant-v9'
    expect(validatePayload(p)).toEqual([])
  })

  it('accepts an unrecognized EXTRA member: the term is not a closed object (§18.2)', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).license.preservation_pledge.escrow_uri = 'https://pub.example/escrow'
    expect(validatePayload(p)).toEqual([])
  })

  it('rejects a non-hex grant_sha256', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).license.preservation_pledge.grant_sha256 = 'A'.repeat(64)
    expect(validatePayload(p)).toContain('license.preservation_pledge.grant_sha256: must be a 64-char lowercase hex string')
  })

  it('rejects a non-string grant_uri', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).license.preservation_pledge.grant_uri = 42n
    expect(validatePayload(p)).toContain('license.preservation_pledge.grant_uri: must be a string')
  })
})

describe('validatePayload — work.publisher_id (v0.2 §18.1)', () => {
  it('accepts a lowercase DNS publisher_id', () => {
    const p = MINIMAL()
    ;(p as any).work.publisher_id = 'pub.example'
    expect(validatePayload(p)).toEqual([])
  })

  it('rejects a publisher_id that is not a dotted hostname', () => {
    const p = MINIMAL()
    ;(p as any).work.publisher_id = 'Pub.Example'
    expect(validatePayload(p)).toContain('work.publisher_id: must be a dotted hostname-like string')
  })
})

describe('validatePayload — D5 preservation-pledge conditional (v0.2 §18.6)', () => {
  it('rejects a null buyer.pubkey when the pledge is present (attest_version 0.2)', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).buyer.pubkey = null
    expect(validatePayload(p)).toContain(
      'buyer.pubkey: must be a non-null 43-char base64url string when license.preservation_pledge is present (attest_version 0.2)',
    )
  })

  it('rejects a missing buyer.pubkey when the pledge is present (attest_version 0.2)', () => {
    const p = MINIMAL_V02_PLEDGE()
    delete (p as any).buyer.pubkey
    expect(validatePayload(p)).toContain(
      'buyer.pubkey: must be a non-null 43-char base64url string when license.preservation_pledge is present (attest_version 0.2)',
    )
  })

  it('rejects a missing work.publisher_id when the pledge is present (attest_version 0.2)', () => {
    const p = MINIMAL_V02_PLEDGE()
    delete (p as any).work.publisher_id
    expect(validatePayload(p)).toContain(
      'work.publisher_id: required when license.preservation_pledge is present (attest_version 0.2)',
    )
  })

  it('rejects an end_of_life other than sunset-grant when the pledge is present (attest_version 0.2)', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).survivability.end_of_life = 'artifacts-remain-redownloadable'
    expect(validatePayload(p)).toContain(
      'survivability.end_of_life: must be sunset-grant when license.preservation_pledge is present (attest_version 0.2)',
    )
  })

  it('reports all three when all three are absent or wrong', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).buyer.pubkey = null
    delete (p as any).work.publisher_id
    ;(p as any).survivability.end_of_life = 'none'
    expect(validatePayload(p)).toHaveLength(3)
  })

  it('does not apply the conditional under attest_version 0.1, even with a pledge present', () => {
    const p = MINIMAL_V02_PLEDGE()
    ;(p as any).attest_version = '0.1'
    ;(p as any).buyer.pubkey = null
    delete (p as any).work.publisher_id
    ;(p as any).survivability.end_of_life = 'none'
    expect(validatePayload(p)).toEqual([])
  })

  it('does not apply the conditional when no preservation_pledge is present', () => {
    const p = MINIMAL_V02_PLEDGE()
    delete (p as any).license.preservation_pledge
    ;(p as any).buyer.pubkey = null
    delete (p as any).work.publisher_id
    ;(p as any).survivability.end_of_life = 'none'
    expect(validatePayload(p)).toEqual([])
  })
})

// De-risk the Task 14 conformance gate: every real vector payload must
// validate to []. If any of these fail, the validator is over-strict
// relative to the authoritative schema and must be relaxed (never edit
// the vector to make it pass).
describe('validatePayload against real conformance vectors', () => {
  const repoRoot = join(__dirname, '..', '..', '..')
  const vectors = [
    '01-valid-minimal',
    '02-valid-full',
    '10-unknown-field',
    '15-revoked-policy',
    '16-revocation-against-none-ignored',
    '18-drm-bound',
  ]
  for (const vector of vectors) {
    it(`${vector}/payload.json validates to []`, () => {
      const bytes = readFileSync(join(repoRoot, 'docs/spec/vectors', vector, 'payload.json'))
      const payload = loadsStrict(bytes) as JsonObject
      expect(validatePayload(payload)).toEqual([])
    })
  }
})
