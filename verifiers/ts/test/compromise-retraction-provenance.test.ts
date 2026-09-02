import { describe, expect, it } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalBytes, verify } from '../src/index.js'
import type { AnchorPolicy, JsonObject, JsonValue, LogKey, TrustStore, VerificationResult } from '../src/index.js'

const RETRACTED = 'compromise_marking_retracted'
const ISSUER = 'store.example'
const KID = `${ISSUER}/keys/2025#ed25519`
const ISSUED_AT = '2025-02-01T00:00:00Z'
const VALID_FROM = '2025-01-01T00:00:00Z'
const HERE = dirname(fileURLToPath(import.meta.url))
const VECTORS = resolve(HERE, '../../../docs/spec/vectors/41-compromise-cutoff')
const MISSING = Symbol('missing')

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte)
}

const SIGNER = seed(1)
const SECOND = seed(2)

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

function entry(status: string, options: { kid?: string; signingSeed?: Uint8Array } = {}): JsonObject {
  const signingSeed = options.signingSeed ?? SIGNER
  return {
    kid: options.kid ?? KID,
    pub: b64u(ed25519.getPublicKey(signingSeed)),
    valid_from: VALID_FROM,
    valid_to: null,
    status,
  }
}

function signBlock(payload: JsonValue, signingSeed: Uint8Array, signingKid: string): JsonObject {
  return {
    kid: signingKid,
    sig: b64u(ed25519.sign(canonicalBytes(payload), signingSeed)),
  }
}

function manifest(
  version: unknown,
  entries: JsonObject[],
  options: { signingSeed?: Uint8Array; signingKid?: string } = {},
): JsonObject {
  const signingSeed = options.signingSeed ?? SIGNER
  const signingKid = options.signingKid ?? KID
  const signedVersion = typeof version === 'bigint' ? version : 1n
  const body: JsonObject = {
    issuer: ISSUER,
    manifest_version: signedVersion,
    issued_at: ISSUED_AT,
    keys: entries,
  }
  const built: JsonObject = { ...body, manifest_signature: signBlock(body, signingSeed, signingKid) }
  if (version === MISSING) delete built.manifest_version
  else if (version !== signedVersion) built.manifest_version = version as JsonValue
  return built
}

function payload(): JsonObject {
  return {
    attest_version: '0.1',
    receipt_id: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    issued_at: ISSUED_AT,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Store Example' },
    buyer: {
      commitment: b64u(new Uint8Array(32)),
      identifier_type: 'email',
      pubkey: null,
    },
    work: {
      title: 'Adversarial fixture',
      publisher: 'Example Publisher',
      identifiers: { sku: 'fixture-1' },
      artifact_series: 'series-1',
    },
    license: {
      grant: 'perpetual',
      revocability: 'none',
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://store.example/terms',
      legal_text_sha256: 'a'.repeat(64),
    },
    survivability: {
      redownload_right: true,
      end_of_life: 'artifacts-remain-redownloadable',
      eol_commitment_uri: null,
      eol_commitment_sha256: null,
    },
  }
}

function receiptBytes(signingSeed: Uint8Array = SIGNER, kid = KID): Uint8Array {
  const p = payload()
  const envelope: JsonObject = {
    payload: p,
    signatures: [{ kid, alg: 'Ed25519', sig: b64u(ed25519.sign(canonicalBytes(p), signingSeed)) }],
  }
  return canonicalBytes(envelope)
}

function trustStore(trusted: JsonObject, chain?: JsonObject[]): TrustStore {
  return {
    manifests: { [ISSUER]: trusted },
    provenance: { [ISSUER]: 'tls' },
    chains: chain === undefined ? {} : { [ISSUER]: chain },
  }
}

function claimManifest(version: unknown, entries: JsonObject[] = [entry('compromised')]): JsonObject {
  return manifest(version, entries)
}

function claim(version: unknown = 2n, entries?: JsonObject[]): JsonObject {
  return { manifest: claimManifest(version, entries), evidence: null }
}

function run(
  trusted: JsonObject,
  options: { chain?: JsonObject[]; compromiseView?: JsonValue[]; bytes?: Uint8Array } = {},
): VerificationResult {
  return verify(
    options.bytes ?? receiptBytes(),
    trustStore(trusted, options.chain),
    null,
    null,
    undefined,
    { compromiseView: options.compromiseView ?? null },
  )
}

function expectRetractedOnce(result: VerificationResult): void {
  expect(result.warnings.filter((warning) => warning === RETRACTED)).toHaveLength(1)
}

function expectNotRetracted(result: VerificationResult): void {
  expect(result.warnings).not.toContain(RETRACTED)
}

function stripRetracted(result: VerificationResult): VerificationResult {
  return {
    ...result,
    warnings: result.warnings.filter((warning) => warning !== RETRACTED),
  }
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown
}

function toJcs(value: unknown): JsonValue {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error(`non-integer JSON number: ${value}`)
    return BigInt(value)
  }
  if (Array.isArray(value)) return value.map((item) => toJcs(item))
  if (typeof value === 'object') {
    const out: JsonObject = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) out[key] = toJcs(item)
    return out
  }
  throw new Error(`unsupported JSON value: ${String(value)}`)
}

function vectorTrustStore(caseName: string, trustedVersion: bigint): TrustStore {
  const raw = readJson(resolve(VECTORS, caseName, 'manifests.json')) as {
    manifests: Record<string, unknown>
    provenance: Record<string, string>
    chains: Record<string, unknown>
    artifact_manifests: Record<string, unknown>
    artifact_manifest_chains: Record<string, unknown>
  }
  const manifests = toJcs(raw.manifests) as Record<string, JsonObject>
  const trusted = manifests['store.example.com']!
  trusted.manifest_version = trustedVersion
  // Re-sign: `manifest_version` sits inside the signed body, and verify()
  // now authenticates the trusted manifest before reading any key out of
  // it. Left unsigned, the rewritten manifest would be refused as edited
  // before the retraction-provenance check under test is ever reached.
  // The vector's signer is seed byte 4 -- the same deterministic material
  // gen_vectors.py builds this group from.
  const signingKid = (trusted.manifest_signature as JsonObject)['kid'] as string
  const body: JsonObject = { ...trusted }
  delete body['manifest_signature']
  trusted.manifest_signature = signBlock(body, seed(4), signingKid)
  return {
    manifests,
    provenance: raw.provenance,
    chains: toJcs(raw.chains) as Record<string, JsonObject[]>,
    artifact_manifests: toJcs(raw.artifact_manifests) as Record<string, Record<string, JsonObject>>,
    artifact_manifest_chains: toJcs(raw.artifact_manifest_chains) as Record<string, Record<string, JsonObject[]>>,
  }
}

function vectorLogKeys(caseName: string): LogKey[] {
  const raw = readJson(resolve(VECTORS, caseName, 'log-keys.json')) as Array<{
    origin: string
    name: string
    ed25519_pub_b64u: string
    mldsa_pub_b64u: string
  }>
  return raw.map((item) => ({
    origin: item.origin,
    name: item.name,
    ed25519Pub: Buffer.from(item.ed25519_pub_b64u, 'base64url'),
    mldsaPub: Buffer.from(item.mldsa_pub_b64u, 'base64url'),
  }))
}

function vectorAnchorPolicy(caseName: string): AnchorPolicy {
  const raw = readJson(resolve(VECTORS, caseName, 'anchor-policy.json')) as {
    pinned_headers: Record<string, { header_hash: string; merkle_root: string; time: number }>
    crqc_horizon: number | null
  }
  const pinnedHeaders: AnchorPolicy['pinnedHeaders'] = {}
  for (const [key, value] of Object.entries(raw.pinned_headers)) {
    pinnedHeaders[key] = {
      headerHash: value.header_hash,
      merkleRoot: value.merkle_root,
      time: value.time,
    }
  }
  return { pinnedHeaders, crqcHorizon: raw.crqc_horizon }
}

function vectorResult(caseName: string, trustedVersion: bigint): VerificationResult {
  const envelope = readFileSync(resolve(VECTORS, caseName, 'envelope.json'))
  return verify(
    envelope,
    vectorTrustStore(caseName, trustedVersion),
    null,
    null,
    undefined,
    {
      transparency: toJcs(readJson(resolve(VECTORS, caseName, 'transparency.json'))),
      logKeys: vectorLogKeys(caseName),
      anchorPolicy: vectorAnchorPolicy(caseName),
      compromiseView: [toJcs((readJson(resolve(VECTORS, caseName, 'compromise-view.json')) as unknown[])[0]!)],
    },
  )
}

describe('compromise retraction provenance', () => {
  it('reports retraction from a lower-version held chain manifest', () => {
    const trusted = manifest(3n, [entry('active')])
    const source = manifest(2n, [entry('compromised')])

    const result = run(trusted, { chain: [source, trusted] })

    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual([`key ${KID} is compromised`])
    expectRetractedOnce(result)
  })

  it('reports retraction from a lower-version authenticated declaration', () => {
    const trusted = manifest(3n, [entry('active')])

    const result = run(trusted, { compromiseView: [claim(2n)] })

    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual([`key ${KID} is compromised`])
    expectRetractedOnce(result)
  })

  it.each([MISSING, '3', true, false, null])(
    'does not report retraction when the trusted manifest version is not an integer: %s',
    (trustedVersion) => {
      const trusted = manifest(trustedVersion, [entry('active')])
      const source = manifest(2n, [entry('compromised')])

      const result = run(trusted, { chain: [source, trusted] })

      expect(result.signature).toBe('invalid')
      expectNotRetracted(result)
    },
  )

  it('does not report retraction when the trusted manifest itself marks compromised', () => {
    const trusted = manifest(3n, [entry('active'), entry('compromised')])
    const source = manifest(2n, [entry('compromised')])

    const result = run(trusted, { chain: [source, trusted] })

    expect(result.signature).toBe('invalid')
    expectNotRetracted(result)
  })

  it.each([3n, 4n])(
    'does not report retraction when the marking source version is not lower: %s',
    (sourceVersion) => {
      const trusted = manifest(3n, [entry('active')])
      const source = manifest(sourceVersion, [entry('compromised')])

      const result = run(trusted, { chain: [source, trusted] })

      expect(result.signature).toBe('invalid')
      expectNotRetracted(result)
    },
  )

  it('keeps the floor fatal without retraction for a stale pin with a newer marking source', () => {
    const trusted = manifest(3n, [entry('active')])
    const stalePin = manifest(4n, [entry('compromised')])

    const result = run(trusted, { chain: [stalePin, trusted] })

    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual([`key ${KID} is compromised`])
    expectNotRetracted(result)
  })

  it.each([MISSING, '2', true, false, null])(
    'does not report retraction when the chain marking source version is not an integer: %s',
    (sourceVersion) => {
      const trusted = manifest(3n, [entry('active')])
      const source = manifest(sourceVersion, [entry('compromised')])

      const result = run(trusted, { chain: [source, trusted] })

      expect(result.signature).toBe('invalid')
      expectNotRetracted(result)
    },
  )

  it.each(['2', 2.5, true, false, null])(
    'does not report retraction from an authenticated declaration with non-integer version: %s',
    (sourceVersion) => {
      const trusted = manifest(3n, [entry('active')])
      const c = claim(2n)
      ;(c.manifest as JsonObject).manifest_version = sourceVersion as JsonValue

      const result = run(trusted, { compromiseView: [c] })

      expectNotRetracted(result)
    },
  )

  it.each([
    [entry('active'), entry('compromised')],
    [entry('compromised'), entry('active')],
  ])('trusted duplicate compromised entries suppress retraction in both orders', (trustedEntries) => {
    const trusted = manifest(3n, trustedEntries)
    const source = manifest(2n, [entry('compromised')])

    const result = run(trusted, { chain: [source, trusted] })

    expect(result.signature).toBe('invalid')
    expectNotRetracted(result)
  })

  it.each([
    // vitest spreads each inner array as ARGUMENTS: the pair must be wrapped
    // once more, or the callback receives only the first entry.
    [[entry('active'), entry('compromised')]],
    [[entry('compromised'), entry('active')]],
    // An ambiguous chain member is refused, so no entry of it is consulted.
    // This previously asserted that every duplicated entry WAS consulted, which
    // is the reading that let one duplicated entry marking the declaring signer
    // `compromised` deny the §19 cutoff. The claim twin below still consults
    // every entry — a different site, still undecided. Python parity:
    // tests/test_compromise_retraction_provenance.py's same pair.
  ])('chain duplicate entries are refused instead of consulted in both orders', (sourceEntries) => {
    const trusted = manifest(3n, [entry('active')])
    const source = manifest(2n, sourceEntries)

    const result = run(trusted, { chain: [source, trusted] })

    expect(result.signature).toBe('invalid')
    expect(result.errors.some((e) => e.includes('duplicate kid'))).toBe(true)
    expectNotRetracted(result)
  })

  it.each([
    // vitest spreads each inner array as ARGUMENTS: the pair must be wrapped
    // once more, or the callback receives only the first entry.
    [[entry('active'), entry('compromised')]],
    [[entry('compromised'), entry('active')]],
  ])('authenticated declaration duplicate entries are all consulted in both orders', (claimEntries) => {
    const trusted = manifest(3n, [entry('active')])

    const result = run(trusted, { compromiseView: [claim(2n, claimEntries)] })

    expect(result.signature).toBe('invalid')
    expectRetractedOnce(result)
  })

  // Since the v0.1 §7.1 amendment (2026-08-26) an ambiguous TRUST ANCHOR is
  // refused whole by verify()'s preflight, one layer above the material match.
  // The receipt is still rejected, with the structural error instead of the
  // compromise one.
  //
  // Consequence, stated rather than hidden: on the TRUSTED operand the "match
  // the claimed material against every entry for the kid" property is no
  // longer reachable from here, and the TypeScript resolver is module-private,
  // so this file cannot pin it. That fallback is kept as defence in depth and
  // is pinned on the Python side, in
  // tests/test_compromise_retraction_provenance.py, which asserts the resolver
  // and the material comparison directly. The property on the operands the
  // preflight does NOT cover — the chain member and the claimed manifest —
  // stays pinned by the both-orders cases above.
  it('refuses an ambiguous trust anchor before the claimed material is matched', () => {
    const trusted = manifest(3n, [entry('active', { signingSeed: SIGNER }), entry('active', { signingSeed: SECOND })])
    const claimEntries = [entry('compromised', { signingSeed: SECOND })]

    const result = run(trusted, { compromiseView: [claim(2n, claimEntries)] })

    expect(result.signature).toBe('invalid')
    expect(result.schema).toBe('invalid')
    expect(result.errors.some((e) => e.includes('duplicate kid'))).toBe(true)
  })

  it('emits the retraction warning once for multiple independent sources', () => {
    const trusted = manifest(3n, [entry('active')])
    const sourceA = manifest(2n, [entry('compromised')])
    const sourceB = manifest(1n, [entry('compromised')])

    const result = run(trusted, { chain: [sourceA, sourceB, trusted], compromiseView: [claim(2n)] })

    expect(result.signature).toBe('invalid')
    expectRetractedOnce(result)
  })

  it('does not change rejecting verdict fields except for the retraction warning', () => {
    const trusted = manifest(3n, [entry('active')])
    const lowerSource = manifest(2n, [entry('compromised')])
    const equalSource = manifest(3n, [entry('compromised')])

    const withRetraction = run(trusted, { chain: [lowerSource, trusted] })
    const withoutRetraction = run(trusted, { chain: [equalSource, trusted] })

    expectRetractedOnce(withRetraction)
    expectNotRetracted(withoutRetraction)
    expect(stripRetracted(withRetraction)).toEqual(withoutRetraction)
  })

  it('does not change rescuing verdict fields except for the retraction warning', () => {
    const caseName = 'n-uncompromise-floor-spares-anchored'
    const withRetraction = vectorResult(caseName, 3n)
    const withoutRetraction = vectorResult(caseName, 2n)

    expect(withRetraction.signature).toBe('valid')
    expect(withRetraction.errors).toEqual([])
    expectRetractedOnce(withRetraction)
    expectNotRetracted(withoutRetraction)
    expect(stripRetracted(withRetraction)).toEqual(withoutRetraction)
  })

  it('never reaches the provenance rule when the trusted manifest omits the kid', () => {
    const otherKid = `${ISSUER}/keys/other#ed25519`
    const other = seed(9)
    const trusted = manifest(
      3n,
      [entry('active', { kid: otherKid, signingSeed: other })],
      { signingSeed: other, signingKid: otherKid },
    )
    const source = manifest(2n, [entry('compromised')], { signingSeed: other, signingKid: otherKid })

    const result = run(trusted, { chain: [source, trusted] })

    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual([`no key '${KID}' in issuer manifest`])
    // DIVERGENCE OF READING, raised to review rather than settled here.
    // C1.1 says a kid the trusted manifest omits entirely satisfies the
    // no-entry condition, which reads as if this case should warn. It cannot
    // under decision D1.3, which emits at the point of RESOLUTION: key lookup
    // fails first, so no marking exists whose provenance could be reported.
    // Python parity: tests/test_compromise_retraction_provenance.py.
    expectNotRetracted(result)
  })
})

// --- v0.2 §19.3 item 3b: who may DENY the cutoff -----------------------------
//
// Denying the cutoff WIDENS — a receipt §19.1 would have rejected survives — so
// a held manifest is admitted to that clause only where the TRUSTED manifest
// vouches for the key that signed it. Vector `41z` pins the exploitable case
// end-to-end through the public corpus; the test below pins the SCOPE, which is
// what a future "let us make this stricter" change would break. Python parity:
// tests/test_compromise_retraction_provenance.py's same block.
describe('§19.3 item 3b — an unvouched held manifest is still read everywhere else', () => {
  const OTHER_KID = `${ISSUER}/keys/2026#ed25519`

  it('an unvouched member still feeds the absorbing floor and the retraction warning', () => {
    // The member's signer is `compromised` in the trusted manifest, so it may
    // not deny a cutoff. Everything else must still read it: v0.1 §7.3's floor
    // kills the receipt and the retraction is still reported. A filter leaking
    // into these paths would let an issuer retract a compromise marking by
    // rotating the key that published it.
    const trusted = manifest(3n, [
      entry('active'),
      entry('compromised', { kid: OTHER_KID, signingSeed: SECOND }),
    ])
    const member = manifest(
      2n,
      [entry('compromised'), entry('active', { kid: OTHER_KID, signingSeed: SECOND })],
      { signingSeed: SECOND, signingKid: OTHER_KID },
    )

    const result = run(trusted, { chain: [member, trusted] })

    expect(result.signature).toBe('invalid')
    expect(result.errors.some((e) => e.includes('compromised'))).toBe(true)
    expectRetractedOnce(result)
  })

  it('a member the trusted manifest still stands behind keeps denying the cutoff', () => {
    // The predicate must not become a blanket ban on chain members: with the
    // signer `active` in the trusted manifest the member is admitted, so its
    // `compromised` marking for the signer suppresses the retraction exactly as
    // before. This is the half that proves the fix did not over-tighten.
    const trusted = manifest(3n, [
      entry('active'),
      entry('active', { kid: OTHER_KID, signingSeed: SECOND }),
    ])
    const member = manifest(
      2n,
      [entry('compromised'), entry('active', { kid: OTHER_KID, signingSeed: SECOND })],
      { signingSeed: SECOND, signingKid: OTHER_KID },
    )

    const result = run(trusted, { chain: [member, trusted] })

    expect(result.signature).toBe('invalid')
    expectRetractedOnce(result)
  })
})
