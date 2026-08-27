// Adversarial contract tests for v0.2 §19.  The fixtures are deliberately
// local: a declaration must be authenticated with key material the verifier
// already holds, never with its self-listed replacement key.
import { describe, expect, it, vi } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { b64uEncode } from '../src/b64u.js'
import { canonicalBytes, JsonObject, loadsStrict } from '../src/canon.js'
import type { AnchorPolicy } from '../src/anchor.js'
import type { TrustStore } from '../src/manifests.js'
import type { LogKey } from '../src/tlog.js'

const mockedStanding = vi.hoisted(() => ({ receipt: '', cutoff: '' }))

vi.mock('../src/transparency.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/transparency.js')>()
  return {
    ...actual,
    evaluateTransparency: (...args: unknown[]) => {
      const options = args.find((value): value is { expectedEntry: Record<string, unknown> } => (
        typeof value === 'object'
        && value !== null
        && 'expectedEntry' in value
        && typeof value.expectedEntry === 'object'
        && value.expectedEntry !== null
      ))
      return {
        transparency: options?.expectedEntry.type === 'receipt' ? mockedStanding.receipt : mockedStanding.cutoff,
        corroboration: 'none',
        warnings: [],
      }
    },
  }
})

import { verify } from '../src/verify.js'

const enc = (value: string) => new TextEncoder().encode(value)
const parse = (value: unknown): JsonObject => loadsStrict(enc(JSON.stringify(value))) as JsonObject

const ISSUER = 'store.example.com'
const TARGET_KID = `${ISSUER}/keys/target#ed25519-1`
const DECLARER_KID = `${ISSUER}/keys/declarer#ed25519-1`
const VALID_FROM = '2025-01-01T00:00:00Z'
const ISSUED_AT = '2025-06-01T00:00:00Z'

// TEST ONLY — fixed seeds, never use in production.
const targetSeed = Uint8Array.from({ length: 32 }, () => 17)
const declarerSeed = Uint8Array.from({ length: 32 }, () => 29)
const targetPub = ed25519.getPublicKey(targetSeed)
const declarerPub = ed25519.getPublicKey(declarerSeed)

function keyEntry(
  kid: string,
  pub: Uint8Array,
  status: 'active' | 'retired' | 'compromised',
): Record<string, unknown> {
  return { kid, pub: b64uEncode(pub), valid_from: VALID_FROM, valid_to: null, status }
}

function signManifest(body: Record<string, unknown>): JsonObject {
  const unsigned = parse(body)
  const sig = ed25519.sign(canonicalBytes(unsigned), declarerSeed)
  return parse({ ...body, manifest_signature: { kid: DECLARER_KID, sig: b64uEncode(sig) } })
}

function issuerManifest(
  targetStatus: 'active' | 'retired' | 'compromised' = 'active',
  declarerStatus: 'active' | 'retired' | 'compromised' = 'active',
  version = 1,
): JsonObject {
  return signManifest({
    issuer: ISSUER,
    manifest_version: version,
    issued_at: ISSUED_AT,
    keys: [
      keyEntry(TARGET_KID, targetPub, targetStatus),
      keyEntry(DECLARER_KID, declarerPub, declarerStatus),
    ],
  })
}

function declaration(options: {
  version?: unknown
  issuedAt?: string
  targetPub?: Uint8Array
  keys?: Record<string, unknown>[]
} = {}): JsonObject {
  const target = keyEntry(TARGET_KID, options.targetPub ?? targetPub, 'compromised')
  return signManifest({
    issuer: ISSUER,
    manifest_version: options.version ?? 2,
    issued_at: options.issuedAt ?? ISSUED_AT,
    keys: options.keys ?? [target, keyEntry(DECLARER_KID, declarerPub, 'active')],
  })
}

function receipt(): JsonObject {
  const payload = parse({
    attest_version: '0.1',
    issued_at: ISSUED_AT,
    receipt_id: '01J000000000000000000000AA',
    issuer: { display_name: 'Store', id: ISSUER },
    work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' } },
    license: {
      grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-free',
      terms_uri: 'https://store.example/terms', legal_text_sha256: 'a'.repeat(64),
    },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: null },
    survivability: {
      end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null,
      redownload_right: false,
    },
    supersedes: null,
  })
  const sig = ed25519.sign(canonicalBytes(payload), targetSeed)
  return parse({ payload, signatures: [{ kid: TARGET_KID, alg: 'Ed25519', sig: b64uEncode(sig) }] })
}

function store(
  manifest = issuerManifest(),
  chains: Record<string, JsonObject[]> = {},
): TrustStore {
  return { manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: 'tls' }, chains }
}

function verifyWith(
  trustStore: TrustStore,
  compromiseView: unknown,
  extra: Record<string, unknown> = {},
) {
  // The cast keeps this independent test compiling until compromiseView is
  // added to VerifyOptions; at runtime an unimplemented option is ignored,
  // making these assertions fail as the intended red test signal.
  const options = { compromiseView, ...extra } as Parameters<typeof verify>[5]
  return verify(enc(JSON.stringify(receipt())), trustStore, null, null, undefined, options)
}

const stage2LogKeys: LogKey[] = [{
  origin: 'log.attest.example/2026',
  name: 'test-log',
  ed25519Pub: ed25519.getPublicKey(Uint8Array.from({ length: 32 }, () => 43)),
  mldsaPub: ml_dsa65.keygen(Uint8Array.from({ length: 32 }, () => 47)).publicKey,
}]
const stage2AnchorPolicy: AnchorPolicy = { pinnedHeaders: {}, crqcHorizon: null }

describe('v0.2 §19 compromiseView adversarial boundaries', () => {
  // docs/spec/attest-v0.2.md:1020-1024, item 3a; docs/spec/attest-v0.1.md:224.
  it('makes an authenticated supplied declaration an absorbing floor without a cutoff', () => {
    const result = verifyWith(store(), [{ manifest: declaration(), evidence: null }])

    expect(result.signature).toBe('invalid')
    expect(result.errors).toContain(`key ${TARGET_KID} is compromised`)
  })

  // docs/spec/attest-v0.2.md:1021 — claim key material must be byte-equal to held material.
  it('ignores a declaration that swaps the compromised kid public key', () => {
    const result = verifyWith(store(), [{
      manifest: declaration({ targetPub: ed25519.getPublicKey(Uint8Array.from({ length: 32 }, () => 91)) }),
      evidence: null,
    }])

    expect(result.signature).toBe('valid')
    expect(result.warnings).toContain('compromise_cutoff_claim_ignored')
  })

  // docs/spec/attest-v0.1.md:224; any duplicate marking this kid compromised establishes the floor.
  it('treats a later duplicate compromised entry as an absorbing floor', () => {
    const result = verifyWith(store(), [{
      manifest: declaration({ keys: [
        keyEntry(TARGET_KID, targetPub, 'active'),
        keyEntry(TARGET_KID, targetPub, 'compromised'),
        keyEntry(DECLARER_KID, declarerPub, 'active'),
      ] }),
      evidence: null,
    }])

    expect(result.signature).toBe('invalid')
  })

  // docs/spec/attest-v0.2.md:1021; first-match resolution must not be changed to last-write-wins.
  it('honours a first duplicate compromised entry even when a later duplicate says active', () => {
    const result = verifyWith(store(), [{
      manifest: declaration({ keys: [
        keyEntry(TARGET_KID, targetPub, 'compromised'),
        keyEntry(TARGET_KID, targetPub, 'active'),
        keyEntry(DECLARER_KID, declarerPub, 'active'),
      ] }),
      evidence: null,
    }])

    expect(result.signature).toBe('invalid')
  })

  // docs/spec/attest-v0.1.md:224 — a held history cannot resurrect a compromised kid.
  it('does not resurrect a compromised key merely because the trusted latest manifest says active', () => {
    const historical = issuerManifest('compromised', 'active', 1)
    const latest = issuerManifest('active', 'active', 2)
    const result = verifyWith(store(latest, { [ISSUER]: [historical, latest] }), undefined)

    expect(result.signature).toBe('invalid')
    expect(result.errors).toContain(`key ${TARGET_KID} is compromised`)
  })

  // docs/spec/attest-v0.2.md:1014 — 64 is the acceptance floor, 65 may be rejected wholesale.
  it('evaluates the 64th claim but rejects a 65-claim view wholesale', () => {
    const acceptedBoundary = [...Array.from({ length: 63 }, () => null), {
      manifest: declaration(), evidence: null,
    }]
    const rejectedBoundary = [...Array.from({ length: 64 }, () => null), {
      manifest: declaration(), evidence: null,
    }]

    expect(verifyWith(store(), acceptedBoundary).signature).toBe('invalid')
    expect(verifyWith(store(), rejectedBoundary).signature).toBe('valid')
  })

  // docs/spec/attest-v0.2.md:1014, 1030 — malformed view members are untrusted and cannot abort valid ones.
  it('ignores non-object members while still applying a later authenticated declaration', () => {
    const result = verifyWith(store(), [null, 7, 'not-a-claim', { manifest: declaration(), evidence: null }])

    expect(result.signature).toBe('invalid')
    expect(result.warnings).toContain('compromise_cutoff_claim_ignored')
  })

  // A wrong container is a caller error; hostile content inside a well-shaped view is untrusted evidence.
  it('rejects a non-array compromiseView as a caller-contract error', () => {
    expect(() => verifyWith(store(), { manifest: declaration(), evidence: null }))
      .toThrowError(new TypeError('compromise_view must be a list of claims or None'))
  })

  // docs/spec/attest-v0.2.md:1014 and v0.1 §9 (docs/spec/attest-v0.1.md:275-279).
  it.each([
    ['a float', 2.5],
    ['NaN', Number.NaN],
    ['infinity', Number.POSITIVE_INFINITY],
    ['an over-safe integer', Number.MAX_SAFE_INTEGER + 1],
  ])('does not let %s materialize a floor', (_label, manifestVersion) => {
    const result = verifyWith(store(), [{
      // It need not be signed: a non-canonical claim must be discarded at the
      // untrusted materialization boundary before authentication is attempted.
      manifest: { issuer: ISSUER, manifest_version: manifestVersion }, evidence: null,
    }])

    expect(result.signature).toBe('valid')
  })

  // docs/spec/attest-v0.2.md:1024; Python's JSON behavior treats -0 as integer 0, not as a float.
  it('keeps Python parity for JSON negative zero instead of rejecting it by typeof alone', () => {
    const result = verifyWith(store(), [{ manifest: declaration({ version: -0 }), evidence: null }])

    expect(result.signature).toBe('invalid')
  })

  // docs/spec/attest-v0.2.md:1024 — no string-to-number coercion in manifest_version.
  it('does not coerce a string manifest_version into an authenticated floor', () => {
    const result = verifyWith(store(), [{ manifest: declaration({ version: '2' }), evidence: null }])

    expect(result.signature).toBe('valid')
    expect(result.warnings).toContain('compromise_cutoff_claim_ignored')
  })

  // docs/spec/attest-v0.2.md:1024 — declaring manifest issued_at must be within the held signer's UTC-Z window.
  it.each([
    ['a timezone-less timestamp', '2025-06-01T00:00:00'],
    ['an offset timestamp', '2025-06-01T01:00:00+01:00'],
    ['a fractional-second timestamp', '2025-06-01T00:00:00.000Z'],
  ])('does not authenticate a declaration with %s', (_label, issuedAt) => {
    const result = verifyWith(store(), [{ manifest: declaration({ issuedAt }), evidence: null }])

    expect(result.signature).toBe('valid')
    expect(result.warnings).toContain('compromise_cutoff_claim_ignored')
  })

  // docs/spec/attest-v0.2.md:1026, 1030, 1040 — a floor remains while a compromised declarer cannot set a cutoff.
  it('keeps a floor from a compromised declarer but refuses to turn it into a cutoff', () => {
    mockedStanding.receipt = 'anchored_before:2025-06-01T00:00:00Z'
    mockedStanding.cutoff = 'anchored_before:2025-06-02T00:00:00Z'
    try {
      const result = verifyWith(
        store(issuerManifest('active', 'compromised')),
        [{ manifest: declaration(), evidence: { entry: { type: 'key-manifest' } } }],
        { transparency: { entry: { type: 'receipt' } }, logKeys: stage2LogKeys, anchorPolicy: stage2AnchorPolicy },
      )

      expect(result.signature).toBe('valid')
      expect(result.warnings).toContain('compromise_cutoff_unanchored')
    } finally {
      mockedStanding.receipt = ''
      mockedStanding.cutoff = ''
    }
  })

  // docs/spec/attest-v0.2.md:1018, 1041-1042 — min cutoff and equality both fail closed.
  it('uses the earliest cutoff and rejects receipt anchoring equal to it', () => {
    mockedStanding.receipt = 'anchored_before:2025-06-02T00:00:00Z'
    mockedStanding.cutoff = 'anchored_before:2025-06-02T00:00:00Z'
    try {
      const result = verifyWith(store(), [
        { manifest: declaration({ version: 2 }), evidence: { entry: { type: 'key-manifest' } } },
        { manifest: declaration({ version: 3 }), evidence: { entry: { type: 'key-manifest' } } },
      ], { transparency: { entry: { type: 'receipt' } }, logKeys: stage2LogKeys, anchorPolicy: stage2AnchorPolicy })

      expect(result.signature).toBe('invalid')
      expect(result.warnings).toContain('compromise_rescue_receipt_after_cutoff')
    } finally {
      mockedStanding.receipt = ''
      mockedStanding.cutoff = ''
    }
  })

  // docs/spec/attest-v0.2.md:1008, 1041-1042 — UTC offsets and milliseconds compare as instants; naive time fails closed.
  it.each([
    ['an offset receipt timestamp before cutoff', '2025-06-01T23:00:00+00:00', 'anchored_before:2025-06-02T00:00:00Z', 'valid', 'compromise_rescue_applied'],
    ['a millisecond receipt timestamp before cutoff', '2025-06-01T23:59:59.999Z', 'anchored_before:2025-06-02T00:00:00Z', 'valid', 'compromise_rescue_applied'],
    ['a timezone-less receipt timestamp', '2025-06-01T23:59:59', 'anchored_before:2025-06-02T00:00:00Z', 'invalid', 'compromise_rescue_requires_anchored_receipt'],
  ])('applies the anchored-time comparison to %s', (_label, receiptTime, cutoff, signature, warning) => {
    mockedStanding.receipt = `anchored_before:${receiptTime}`
    mockedStanding.cutoff = cutoff
    try {
      const result = verifyWith(store(), [{ manifest: declaration(), evidence: { entry: { type: 'key-manifest' } } }], {
        transparency: { entry: { type: 'receipt' } }, logKeys: stage2LogKeys, anchorPolicy: stage2AnchorPolicy,
      })

      expect(result.signature).toBe(signature)
      expect(result.warnings).toContain(warning)
    } finally {
      mockedStanding.receipt = ''
      mockedStanding.cutoff = ''
    }
  })
})
