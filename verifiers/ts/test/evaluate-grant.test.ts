// Tests for `evaluateGrant` (src/grant.ts) — Stage 4's ordered evaluation
// (v0.2 §18.4 steps 1-11) and the two result components of §18.5. Mirrors
// tests/test_evaluate_grant.py (Python reference) case-for-case.
//
// test/grant.test.ts covers the PRIMITIVES — the documents, the two coverage
// predicates, the ratchet, the ceilings, the redemption proof — one at a time
// and without a trust store. This file covers the ORDER those primitives are
// applied in, which is where a conforming implementation can still go wrong: a
// short circuit taken one step too early masks a defect visible in the receipt
// itself, a full scan replaced by a first-match makes the warning set depend on
// how evidence was arranged, and a gate skipped makes a verifier tell a holder
// they may redeem something the grant never spoke about.
//
// Every test builds one working fixture and mutates exactly one thing, so a
// single assertion isolates a single failure mode.
import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { canonicalBytes, loadsStrict } from '../src/canon.js'
import type { JsonObject, JsonValue } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import type { TrustStore } from '../src/manifests.js'
import type { AnchorPolicy, PinnedHeader } from '../src/anchor.js'
import { evaluateGrant, grantHash } from '../src/grant.js'
import { verify, isOk } from '../src/verify.js'
import {
  buildDeclaration,
  buildGrant,
  buildKeyManifest,
  hybridSigner,
  keyEntry,
  parse,
  type TestSigner,
} from './helpers/grant-builder.js'

const enc = (s: string) => new TextEncoder().encode(s)
const hex = (s: string) => bytesToHex(sha256(enc(s)))

const ISSUER = 'store.example.com'
const PUBLISHER = 'pub.example'
const SUCCESSOR = 'heritage.example'
const OTHER = 'marketplace.example'

const ISSUER_KID = `${ISSUER}/keys/test#ed25519-1`
const PUB_KID = `${PUBLISHER}/keys/grants#1`
const SUCCESSOR_KID = `${SUCCESSOR}/keys/grants#1`
const OTHER_KID = `${OTHER}/keys/grants#1`

const VALID_FROM = '2026-01-01T00:00:00Z'
const MANIFEST_ISSUED_AT = '2026-01-01T00:00:00Z'
const GRANT_ISSUED_AT = '2026-02-01T00:00:00Z'
const DECLARED_AT = '2031-03-01T00:00:00Z'

// The pinned header the anchor fixture resolves to sits in January 2027, so a
// backstop dated before it has been REACHED and one dated 2046 has not. Both
// dates are after the grant's own `issued_at`: a document cannot be anchored
// before it exists, and a fixture that pretended otherwise would be testing an
// arrangement no publisher can produce.
const HEADER_TIME = 1_800_000_000 // 2027-01-15T08:00:00Z
const HEADER_HASH = '3a'.repeat(32)
const FIXED_DATE_REACHED = '2027-01-01T00:00:00Z'
const FIXED_DATE_FUTURE = '2046-01-01T00:00:00Z'

const RECEIPT_ART = hex('attest-test-artifact-v1')
const ART_OTHER = hex('artifact-elsewhere')

const LEGAL_TEXT_SHA256 = hex('attest-test-sunset-grant-prose-v1')
const OTHER_LEGAL_TEXT_SHA256 = hex('attest-test-sunset-grant-prose-v2')

// --- fixtures ----------------------------------------------------------------
//
// TEST ONLY — fixed seeds, never use in production. Every signer is HYBRID: a
// v0.2 receipt requires the issuer's hybrid keys (§13's AND-rule), and the
// side-documents exercise the same rule.
const ISSUER_KEYS = hybridSigner(31)
const PUB_KEYS = hybridSigner(32)
const SUCCESSOR_KEYS = hybridSigner(33)
const OTHER_KEYS = hybridSigner(34)
// TEST ONLY — the buyer key §18.6 makes mandatory on a pledge-bearing receipt.
const BUYER_SEED = new Uint8Array(32).fill(11)
const BUYER_PUB = ed25519.getPublicKey(BUYER_SEED)

function manifestOf(issuer: string, kid: string, signer: TestSigner, version = 1): JsonObject {
  return buildKeyManifest(issuer, version, MANIFEST_ISSUED_AT, [keyEntry(kid, signer, VALID_FROM)], signer, kid)
}

const ISSUER_MANIFEST = manifestOf(ISSUER, ISSUER_KID, ISSUER_KEYS)
const PUB_MANIFEST = manifestOf(PUBLISHER, PUB_KID, PUB_KEYS)
const SUCCESSOR_MANIFEST = manifestOf(SUCCESSOR, SUCCESSOR_KID, SUCCESSOR_KEYS)
const OTHER_MANIFEST = manifestOf(OTHER, OTHER_KID, OTHER_KEYS)

function scope(artifactSeries: string | null = null, artifacts: string[] = [RECEIPT_ART]): Record<string, unknown> {
  return { artifact_series: artifactSeries, artifacts: [...artifacts].sort() }
}

function activation(
  modes: string[] = ['publisher-declaration'],
  fixedDate: string | null = null,
  successorIds: string[] = [SUCCESSOR],
): Record<string, unknown> {
  return { modes: [...modes].sort(), fixed_date: fixedDate, successor_ids: [...successorIds].sort() }
}

function makeGrant(
  signer: TestSigner = PUB_KEYS,
  kid: string = PUB_KID,
  overrides: Record<string, unknown> = {},
): JsonObject {
  return buildGrant(
    {
      grant_version: 1,
      publisher: PUBLISHER,
      scope: scope(),
      permissions: ['deliver-to-holder'],
      activation: activation(),
      unprotected_build: true,
      legal_text_uri: 'https://pub.example/sunset-grant-v1',
      legal_text_sha256: LEGAL_TEXT_SHA256,
      jurisdiction: 'IT',
      issued_at: GRANT_ISSUED_AT,
      ...overrides,
    },
    signer,
    kid,
  )
}

function makeDeclaration(
  signer: TestSigner = PUB_KEYS,
  kid: string = PUB_KID,
  declarationScope: Record<string, unknown> = scope(),
  publisher: string = PUBLISHER,
  declaredAt: string = DECLARED_AT,
): JsonObject {
  return buildDeclaration(publisher, declarationScope, declaredAt, signer, kid)
}

/** The reference example payload, upgraded to a v0.2 pledge-bearing receipt
 * that satisfies §18.6's conditional: a non-null `buyer.pubkey`, a
 * `work.publisher_id`, and the `sunset-grant` label, all three of which are
 * schema-REQUIRED once the term is present. */
function payloadFor(document: JsonObject | null = null, mutate?: (p: Record<string, unknown>) => void): JsonObject {
  const floor = document ?? makeGrant()
  const raw: Record<string, unknown> = {
    attest_version: '0.2',
    receipt_id: '01J1V5B4M9Z8QWERTY12345678',
    issued_at: '2026-07-02T14:30:00Z',
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Games Store' },
    buyer: { commitment: b64uEncode(new Uint8Array(32)), identifier_type: 'issuer-account', pubkey: b64uEncode(BUYER_PUB) },
    work: {
      title: 'Example Game',
      publisher: 'Example Publisher srl',
      edition: 'Deluxe',
      identifiers: { issuer_sku: 'EXG-001' },
      publisher_id: PUBLISHER,
      artifact_series: 'store.example.com/works/EXG-001',
      artifacts: [
        {
          role: 'installer',
          platform: 'windows-x86_64',
          filename: 'example-game-1.0-setup.exe',
          size_bytes: 734003200,
          sha256: RECEIPT_ART,
        },
      ],
    },
    license: {
      grant: 'perpetual',
      revocability: 'none',
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://store.example.com/attest/license-templates/standard-v1',
      legal_text_sha256: hex('attest-test-legal-text-v1'),
      jurisdiction_flags: { eu_usedsoft_asserted: false },
      preservation_pledge: {
        pledge: 'sunset-grant-v1',
        grant_uri: 'https://pub.example/sunset-grant-v1.json',
        grant_sha256: grantHash(floor),
      },
    },
    survivability: {
      redownload_right: true,
      mirror_policy_uri: 'https://store.example.com/attest/mirror-policy-v1',
      mirror_policy_sha256: hex('attest-test-mirror-policy-v1'),
      end_of_life: 'sunset-grant',
      eol_commitment_uri: null,
      eol_commitment_sha256: null,
    },
  }
  if (mutate) mutate(raw)
  return parse(raw)
}

/** A v0.1 receipt with no pledge at all — the reference example payload. */
function plainPayload(): JsonObject {
  return parse({
    attest_version: '0.1',
    receipt_id: '01J1V5B4M9Z8QWERTY12345678',
    issued_at: '2026-07-02T14:30:00Z',
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Games Store' },
    buyer: { commitment: b64uEncode(new Uint8Array(32)), identifier_type: 'issuer-account', pubkey: null },
    work: {
      title: 'Example Game',
      publisher: 'Example Publisher srl',
      identifiers: { issuer_sku: 'EXG-001' },
      artifact_series: 'store.example.com/works/EXG-001',
      artifacts: [
        { role: 'installer', platform: 'windows-x86_64', filename: 'g.exe', size_bytes: 1, sha256: RECEIPT_ART },
      ],
    },
    license: {
      grant: 'perpetual', revocability: 'none', transferable: false, drm: 'drm-free',
      terms_uri: 'https://store.example.com/t', legal_text_sha256: hex('attest-test-legal-text-v1'),
    },
    survivability: {
      redownload_right: true, end_of_life: 'artifacts-remain-redownloadable',
      eol_commitment_uri: null, eol_commitment_sha256: null,
    },
  })
}

function trustStoreOf(
  extraManifests: Record<string, JsonObject> = {},
  provenance: Record<string, string> = { [PUBLISHER]: 'bundle' },
  chains: Record<string, JsonObject[]> = {},
): TrustStore {
  return {
    manifests: { [PUBLISHER]: PUB_MANIFEST, [SUCCESSOR]: SUCCESSOR_MANIFEST, ...extraManifests },
    provenance,
    chains,
  }
}

function viewOf(document: JsonObject | null = null, members: Record<string, unknown> = {}): Record<string, unknown> {
  return { grant: document ?? makeGrant(), ...members }
}

/** One OTS op-chain over `seed` climbing to one pinned header — the same
 * synthetic shape test/anchor-seeded.test.ts builds, computed with plain
 * sha256 so the fixture pins the real algorithm rather than round-tripping
 * anchor.ts's own logic. `salt` varies the chain so two proofs over the SAME
 * seed resolve to two DIFFERENT headers, which is what a maximum-versus-
 * minimum reduction can be told apart on. */
function otsProof(seed: Uint8Array, salt: string, headerTime: number, headerHash: string): Record<string, unknown> {
  const sibling = Uint8Array.from(Buffer.from(salt.repeat(32), 'hex'))
  const prefix = Uint8Array.from(Buffer.from('cd'.repeat(16), 'hex'))
  let acc = sha256(seed)
  acc = sha256(new Uint8Array([...acc, ...sibling]))
  acc = sha256(new Uint8Array([...prefix, ...acc]))
  return {
    kind: 'ots',
    ops: [
      ['append', bytesToHex(sibling)],
      ['sha256'],
      ['prepend', bytesToHex(prefix)],
      ['sha256'],
    ],
    header_merkle_root: bytesToHex(acc),
    header_time: headerTime,
    header_hash: headerHash,
  }
}

/** The bundle as it arrives OFF THE WIRE — strict-parsed, so `header_time` is
 * a `bigint`, exactly as `grant-view.json` reaches `evaluateGrant` from the
 * conformance loader. Building it from plain JS literals instead would be a
 * fixture no wire document can produce, and would test the one representation
 * the real call never sees. `otsProof` itself stays unparsed: it also feeds
 * `pin()`, and an `AnchorPolicy` is TRUSTED config whose `time` is a plain
 * `number` by its own interface. */
function anchorEvidence(seed: Uint8Array): JsonObject {
  return parse({ proofs: [otsProof(seed, 'ab', HEADER_TIME, HEADER_HASH)] })
}

function pin(proof: Record<string, unknown>): [string, PinnedHeader] {
  const headerHash = String(proof['header_hash'])
  return [
    headerHash,
    { headerHash, merkleRoot: String(proof['header_merkle_root']), time: Number(proof['header_time']) } as PinnedHeader,
  ]
}

function anchorPolicyFor(seed: Uint8Array, crqcHorizon: number | null = null): AnchorPolicy {
  return { pinnedHeaders: Object.fromEntries([pin(otsProof(seed, 'ab', HEADER_TIME, HEADER_HASH))]), crqcHorizon }
}

/** Evaluate with a payload that hash-binds the view's OWN floor unless the
 * caller supplied one — hybrid signatures are randomized in Python, so the
 * reference fixture cannot rebuild the floor; this port keeps the same
 * discipline so the two suites test the same thing. */
function evaluate(
  payload: JsonObject | null = null,
  view: unknown = undefined,
  trustStore: TrustStore | null = null,
  anchorPolicy: AnchorPolicy | null = null,
) {
  let resolvedPayload = payload
  if (resolvedPayload === null) {
    const floor = view !== null && typeof view === 'object' && !Array.isArray(view)
      ? (view as Record<string, unknown>)['grant']
      : null
    resolvedPayload = payloadFor(
      floor !== null && typeof floor === 'object' && !Array.isArray(floor) ? (floor as JsonObject) : null,
    )
  }
  return evaluateGrant(resolvedPayload, trustStore ?? trustStoreOf(), view, anchorPolicy)
}

// --- the capability gate: no channel, no evaluation ---------------------------

describe('evaluateGrant — the capability gate', () => {
  it('evaluates nothing at all without a grant view', () => {
    // `null` means the caller is not Stage-4-capable. Not even step 1 runs:
    // the components stay at the values every pre-Stage-4 caller already
    // implicitly gets, and no warning appears.
    expect(evaluate(null, null)).toEqual({ grant: 'not_checked', grant_trust: 'not_checked', warnings: [] })
  })

  it('opts into the ordered evaluation on an EMPTY view', () => {
    // Supplying the channel AT ALL is the opt-in. An empty view carries no
    // grant document, so it falls through to step 4 — but steps 1-3 ran first.
    const verdict = evaluate(null, {})

    expect(verdict.grant).toBe('not_checked')
    expect(verdict.grant_trust).toBe('not_checked')
  })
})

// --- step 1: the pledge itself, from the signed payload alone -----------------

describe('evaluateGrant — step 1: the pledge', () => {
  it('reports none for a receipt with no pledge', () => {
    const verdict = evaluate(plainPayload(), {})

    expect(verdict.grant).toBe('none')
    expect(verdict.warnings).toEqual([])
  })

  const unreadablePledges: unknown[] = [
    null,
    42,
    {},
    { pledge: 'sunset-grant-v1' },
    { pledge: 'sunset-grant-v1', grant_uri: 'https://pub.example/g.json' },
    { pledge: '', grant_uri: 'https://pub.example/g.json', grant_sha256: 'a'.repeat(64) },
    { pledge: 'sunset-grant-v1', grant_uri: '', grant_sha256: 'a'.repeat(64) },
    { pledge: 'sunset-grant-v1', grant_uri: 'https://pub.example/g.json', grant_sha256: 'AA'.repeat(32) },
    { pledge: 'sunset-grant-v1', grant_uri: 'https://pub.example/g.json', grant_sha256: 'a'.repeat(63) },
  ]

  it.each(unreadablePledges.map((p, i) => [i, p] as const))(
    'reports none for a pledge that is not readable as the three members (#%i)',
    (_i, pledge) => {
      const payload = payloadFor(null, (p) => {
        ;(p['license'] as Record<string, unknown>)['preservation_pledge'] = pledge
      })

      expect(evaluate(payload, viewOf()).grant).toBe('none')
    },
  )
})

// --- step 2: an unrecognized profile is never evaluated under v1's rules ------

describe('evaluateGrant — step 2: the pledge profile', () => {
  const withProfile = (profile: string) =>
    payloadFor(null, (p) => {
      ;((p['license'] as Record<string, unknown>)['preservation_pledge'] as Record<string, unknown>)['pledge'] = profile
    })

  it('reports not_checked with a warning for an unrecognized profile', () => {
    // Valid-with-warning as SCHEMA, but MUST NOT be evaluated under
    // `sunset-grant-v1`'s rules: a later profile may attach different meaning
    // to the same members, and guessing is how two conforming implementations
    // reach different verdicts on identical input.
    const verdict = evaluate(withProfile('sunset-grant-v2'), viewOf())

    expect(verdict.grant).toBe('not_checked')
    expect(verdict.warnings).toEqual(['grant_pledge_type_unknown'])
  })

  it('stops before the grant document is even looked at', () => {
    // Step 2 short-circuits ahead of step 5, so a perfectly good grant
    // document produces no trust value: nothing about it was evaluated.
    expect(evaluate(withProfile('sunset-grant-v2'), viewOf()).grant_trust).toBe('not_checked')
  })
})

// --- step 3: the issuer's own inconsistency, reported from the payload alone --

describe('evaluateGrant — step 3: eol_commitment divergence', () => {
  it('reports the divergence without any evidence at all', () => {
    // Visible in the signed payload alone, so it is reported whether or not
    // grant evidence was supplied — this is the whole reason steps 1-3 run
    // before step 4's short circuit.
    const payload = payloadFor(null, (p) => {
      ;(p['survivability'] as Record<string, unknown>)['eol_commitment_sha256'] = 'b'.repeat(64)
    })
    const verdict = evaluate(payload, {})

    expect(verdict.grant).toBe('not_checked')
    expect(verdict.warnings).toEqual(['grant_commitment_divergence'])
  })

  it('does not stop the evaluation', () => {
    // The license term governs and evaluation CONTINUES: the two fields have
    // different authorities, and silently preferring one would hide the
    // issuer's inconsistency from the person holding the receipt.
    const floor = makeGrant()
    const payload = payloadFor(floor, (p) => {
      ;(p['survivability'] as Record<string, unknown>)['eol_commitment_sha256'] = 'b'.repeat(64)
    })
    const verdict = evaluate(payload, viewOf(floor, { declarations: [makeDeclaration()] }))

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual(['grant_commitment_divergence'])
  })

  it('is silent on an agreeing eol_commitment', () => {
    const floor = makeGrant()
    const payload = payloadFor(floor, (p) => {
      ;(p['survivability'] as Record<string, unknown>)['eol_commitment_sha256'] = grantHash(floor)
    })

    expect(evaluate(payload, viewOf(floor)).warnings).toEqual([])
  })
})

// --- step 4: the structural ceilings, then the evidence ----------------------

describe('evaluateGrant — step 4: ceilings and evidence', () => {
  it.each(['later_grants', 'declarations'])('truncates toward not_checked over the %s ceiling', (member) => {
    const verdict = evaluate(null, viewOf(null, { [member]: new Array(65).fill({}) }))

    expect(verdict.grant).toBe('not_checked')
    expect(verdict.grant_trust).toBe('not_checked')
  })

  it.each(['later_grants', 'declarations'])('accepts exactly the %s ceiling', (member) => {
    expect(evaluate(null, viewOf(null, { [member]: new Array(64).fill({}) })).grant).not.toBe('not_checked')
  })

  it('reports not_checked for a view carrying no grant document', () => {
    const verdict = evaluate(null, { declarations: [makeDeclaration()] })

    expect(verdict.grant).toBe('not_checked')
    expect(verdict.grant_trust).toBe('not_checked')
  })
})

// --- step 5: authentication, the triple domain binding, and the trust ladder --

describe('evaluateGrant — step 5: authentication and the domain binding', () => {
  it('ignores a floor that does not authenticate', () => {
    const document = makeGrant()
    document['jurisdiction'] = 'FR' // signed over "IT"

    expect(evaluate(payloadFor(document), viewOf(document)).grant).toBe('invalid_grant_ignored')
  })

  it('never activates on a grant whose legal_text_uri is empty (§18.2)', () => {
    // The high-severity shape hole, pinned at the level where it does damage.
    // §18.2 types `legal_text_uri` as non-empty. The shape is checked BEFORE
    // the signature, and evaluation then runs on through the ratchet, the
    // scope gate and the declaration scan — so a publisher who signed a grant
    // naming no prose at all, hash-bound it correctly into the receipt and
    // supplied a valid cessation declaration would reach `activated`: the one
    // direction §18.4 declares normatively forbidden, because a false
    // `activated` authorizes distribution of a work that is still on sale.
    // It must be `invalid_grant_ignored` instead, with `grant_trust` still
    // reported at its best available value (§18.5) and no warning: an
    // unauthenticated document is a plain rejection, not a named condition.
    const floor = makeGrant(PUB_KEYS, PUB_KID, { legal_text_uri: '' })
    const verdict = evaluate(
      payloadFor(floor),
      viewOf(floor, { declarations: [makeDeclaration()] }),
      trustStoreOf({}, { [PUBLISHER]: 'tls' }),
    )

    expect(verdict.grant).toBe('invalid_grant_ignored')
    expect(verdict.grant_trust).toBe('verified')
    expect(verdict.warnings).toEqual([])
  })

  it('ignores the grant when the publisher manifest cannot be resolved', () => {
    const trustStore: TrustStore = { manifests: {}, provenance: {} }

    expect(evaluate(null, viewOf(), trustStore).grant).toBe('invalid_grant_ignored')
  })

  it('reports signer_mismatch for a grant signed by a domain that is not the publisher', () => {
    // The marketplace-signing-a-grant-it-has-no-rights-to-concede case, named.
    // The document authenticates perfectly — against the wrong domain.
    const document = makeGrant(OTHER_KEYS, OTHER_KID, { publisher: OTHER })
    const verdict = evaluate(payloadFor(document), viewOf(document), trustStoreOf({ [OTHER]: OTHER_MANIFEST }))

    expect(verdict.grant).toBe('invalid_grant_ignored')
    expect(verdict.grant_trust).toBe('signer_mismatch')
    expect(verdict.warnings).toEqual(['grant_signer_not_publisher'])
  })

  it('cannot be forced into signer_mismatch by an UNSIGNED foreign document', () => {
    // `signer_mismatch` is reachable only for a document that ALREADY
    // authenticated (§18.1). Otherwise appending garbage to an evidence array
    // would buy an attacker a trust value for free.
    const document = makeGrant(OTHER_KEYS, OTHER_KID, { publisher: OTHER })
    document['jurisdiction'] = 'FR' // signed over "IT"
    const verdict = evaluate(payloadFor(document), viewOf(document), trustStoreOf({ [OTHER]: OTHER_MANIFEST }))

    expect(verdict.grant).toBe('invalid_grant_ignored')
    expect(verdict.grant_trust).not.toBe('signer_mismatch')
    expect(verdict.warnings).toEqual([])
  })

  it('ignores a grant whose publisher member disagrees with the receipt', () => {
    const document = makeGrant(PUB_KEYS, PUB_KID, { publisher: OTHER })

    expect(evaluate(payloadFor(document), viewOf(document)).grant).toBe('invalid_grant_ignored')
  })

  it('yields verified grant_trust on TLS provenance for the publisher', () => {
    const verdict = evaluate(
      null,
      viewOf(null, { declarations: [makeDeclaration()] }),
      trustStoreOf({}, { [PUBLISHER]: 'tls' }),
    )

    expect(verdict.grant).toBe('activated')
    expect(verdict.grant_trust).toBe('verified')
  })

  it('forces unverified_rotation on a discontinuous publisher chain', () => {
    const unrelated = manifestOf(PUBLISHER, PUB_KID, PUB_KEYS, 7)
    const trustStore = trustStoreOf({}, { [PUBLISHER]: 'tls' }, { [PUBLISHER]: [unrelated, PUB_MANIFEST] })
    const verdict = evaluate(null, viewOf(null, { declarations: [makeDeclaration()] }), trustStore)

    expect(verdict.grant).toBe('activated')
    expect(verdict.grant_trust).toBe('unverified_rotation')
  })

  it('reports grant_trust at its best value even when the grant is rejected', () => {
    // §18.5: reported at its best-available value even when grant evaluation
    // later rejects the document, and never silently reset on failure.
    const document = makeGrant()
    const payload = payloadFor(document, (p) => {
      ;((p['license'] as Record<string, unknown>)['preservation_pledge'] as Record<string, unknown>)['grant_sha256'] =
        'c'.repeat(64)
    })
    const verdict = evaluate(payload, viewOf(document), trustStoreOf({}, { [PUBLISHER]: 'tls' }))

    expect(verdict.grant).toBe('invalid_grant_ignored')
    expect(verdict.grant_trust).toBe('verified')
  })

  it('never borrows grant_trust from the signer of a document that does not authenticate', () => {
    // §18.5 scopes the ladder to the trust store's provenance for the
    // RECEIPT's resolved `work.publisher_id`, never to the domain a supplied
    // document names in its own `kid`. Keying it on the signer would let a
    // caller attach a blob that authenticates against nothing, point its
    // `kid` at any TLS domain the verifier happens to know, and be handed the
    // top of the scale for the price of appending bytes.
    const forged = { ...makeGrant(OTHER_KEYS, OTHER_KID, { publisher: OTHER }), jurisdiction: 'ZZ' }
    const verdict = evaluate(
      payloadFor(forged),
      viewOf(forged),
      trustStoreOf({ [OTHER]: OTHER_MANIFEST }, { [PUBLISHER]: 'bundle', [OTHER]: 'tls' }),
    )

    expect(verdict.grant).toBe('invalid_grant_ignored')
    expect(verdict.grant_trust).toBe('unauthenticated_tofu')
  })

  it('still reads grant_trust from the publisher when the publisher itself is TLS-known', () => {
    // The other direction of the same rule: the ladder follows the receipt's
    // publisher, so a TLS-known publisher keeps `verified` even though the
    // document that failed to authenticate came from somewhere else.
    const forged = { ...makeGrant(OTHER_KEYS, OTHER_KID, { publisher: OTHER }), jurisdiction: 'ZZ' }
    const verdict = evaluate(
      payloadFor(forged),
      viewOf(forged),
      trustStoreOf({ [OTHER]: OTHER_MANIFEST }, { [PUBLISHER]: 'tls', [OTHER]: 'tls' }),
    )

    expect(verdict.grant).toBe('invalid_grant_ignored')
    expect(verdict.grant_trust).toBe('verified')
  })
})

// --- step 6: the receipt binding ---------------------------------------------

describe('evaluateGrant — step 6: the receipt binding', () => {
  it('ignores a grant whose hash is not the one the receipt signed', () => {
    const payload = payloadFor(null, (p) => {
      ;((p['license'] as Record<string, unknown>)['preservation_pledge'] as Record<string, unknown>)['grant_sha256'] =
        'd'.repeat(64)
    })
    const verdict = evaluate(payload, viewOf())

    expect(verdict.grant).toBe('invalid_grant_ignored')
    expect(verdict.warnings).toEqual(['grant_commitment_mismatch'])
  })
})

// --- step 7: the floor-relative ratchet --------------------------------------

describe('evaluateGrant — step 7: the ratchet', () => {
  it('makes a widening later version effective', () => {
    const floor = makeGrant()
    const later = makeGrant(PUB_KEYS, PUB_KID, {
      grant_version: 2,
      permissions: ['deliver-to-holder', 'redistribute-among-holders'],
      activation: activation(undefined, undefined, [SUCCESSOR, OTHER]),
    })
    // The widened successor list is what proves the LATER version governed: a
    // declaration from `marketplace.example` is honored only under it.
    const declaration = makeDeclaration(OTHER_KEYS, OTHER_KID)
    const verdict = evaluate(
      payloadFor(floor),
      viewOf(floor, { later_grants: [later], declarations: [declaration] }),
      trustStoreOf({ [OTHER]: OTHER_MANIFEST }),
    )

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual(['grant_activated_by_successor'])
  })

  it('ignores a narrowing later version with a warning', () => {
    const floor = makeGrant(PUB_KEYS, PUB_KID, { permissions: ['deliver-to-holder', 'redistribute-among-holders'] })
    const later = makeGrant(PUB_KEYS, PUB_KID, { grant_version: 2, permissions: ['deliver-to-holder'] })
    const verdict = evaluate(payloadFor(floor), viewOf(floor, { later_grants: [later] }))

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_narrowing_ignored'])
  })

  it('forces unverified_rotation on a rollback version', () => {
    const floor = makeGrant(PUB_KEYS, PUB_KID, { grant_version: 5 })
    const older = makeGrant(PUB_KEYS, PUB_KID, { grant_version: 4 })

    expect(evaluate(payloadFor(floor), viewOf(floor, { later_grants: [older] })).grant_trust).toBe(
      'unverified_rotation',
    )
  })

  it('treats two DISTINCT grants sharing a version as rollback-or-equivocation', () => {
    const floor = makeGrant()
    const twin = makeGrant(PUB_KEYS, PUB_KID, { jurisdiction: 'FR' }) // same version, different document

    expect(evaluate(payloadFor(floor), viewOf(floor, { later_grants: [twin] })).grant_trust).toBe(
      'unverified_rotation',
    )
  })

  it('deduplicates a byte-identical duplicate instead of calling it equivocation', () => {
    // "Two DISTINCT authenticated grants" is what §18.3 rejects; a replayed
    // copy of the floor is not a second document.
    const floor = makeGrant()
    const replayed = loadsStrict(enc(JSON.stringify(JSON.parse(JSON.stringify(floor, (_k, v) =>
      typeof v === 'bigint' ? Number(v) : v))))) as JsonObject

    expect(evaluate(payloadFor(floor), viewOf(floor, { later_grants: [replayed] })).grant_trust).toBe(
      'unauthenticated_tofu',
    )
  })

  it('treats a later version from another publisher as inadmissible AND silent', () => {
    // §18.3: such a document "is not a later version of this grant at all; it
    // is a different grant". It says nothing about THIS grant's currency, so
    // it must not move `grant_trust` either — otherwise anyone could downgrade
    // a verdict by appending a stranger's genuine grant to an array.
    const floor = makeGrant()
    const foreign = makeGrant(OTHER_KEYS, OTHER_KID, { grant_version: 2, publisher: OTHER })
    const verdict = evaluate(
      payloadFor(floor),
      viewOf(floor, { later_grants: [foreign] }),
      trustStoreOf({ [OTHER]: OTHER_MANIFEST }),
    )

    expect(verdict.grant_trust).toBe('unauthenticated_tofu')
    expect(verdict.warnings).toEqual([])
  })

  it('ignores an unauthenticated later version without effect', () => {
    const floor = makeGrant()
    const forged = makeGrant(PUB_KEYS, PUB_KID, { grant_version: 2 })
    forged['jurisdiction'] = 'FR' // signed over "IT"
    const verdict = evaluate(payloadFor(floor), viewOf(floor, { later_grants: [forged] }))

    expect(verdict.grant_trust).toBe('unauthenticated_tofu')
    expect(verdict.warnings).toEqual([])
  })

  it('takes the MAXIMUM over the floor-relative filter, independent of presentation order', () => {
    const floor = makeGrant()
    const v2 = makeGrant(PUB_KEYS, PUB_KID, {
      grant_version: 2,
      activation: activation(undefined, undefined, [SUCCESSOR, OTHER]),
    })
    const v3 = makeGrant(PUB_KEYS, PUB_KID, {
      grant_version: 3,
      activation: activation(undefined, undefined, [SUCCESSOR]),
    })
    const declaration = makeDeclaration(OTHER_KEYS, OTHER_KID)
    const trustStore = trustStoreOf({ [OTHER]: OTHER_MANIFEST })

    const forward = evaluate(
      payloadFor(floor),
      viewOf(floor, { later_grants: [v2, v3], declarations: [declaration] }),
      trustStore,
    )
    const backward = evaluate(
      payloadFor(floor),
      viewOf(floor, { later_grants: [v3, v2], declarations: [declaration] }),
      trustStore,
    )

    // v3 dropped `marketplace.example` back off the successor list relative to
    // v2 — but the ratchet compares each candidate against the FLOOR, where it
    // was never present, so v3 passes and, being the greatest version, governs.
    // Under v3 the marketplace's declaration is a stranger's.
    expect(forward.grant).toBe('dormant')
    expect(forward).toEqual(backward)
  })

  it('lets a prose-changing later version govern, and reports the change', () => {
    // The structural members of the later version govern; the prose that binds
    // this buyer stays the one their own receipt hash-bound.
    const floor = makeGrant()
    const later = makeGrant(PUB_KEYS, PUB_KID, {
      grant_version: 2,
      legal_text_uri: 'https://pub.example/sunset-grant-v2',
      legal_text_sha256: OTHER_LEGAL_TEXT_SHA256,
    })
    const verdict = evaluate(
      payloadFor(floor),
      viewOf(floor, { later_grants: [later], declarations: [makeDeclaration()] }),
    )

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual(['grant_legal_text_changed'])
  })

  it('reports the change when only the URI moved', () => {
    // All three prose-bearing members count, the URI included: a document
    // served from a new location is a new document to the person who has to go
    // read it, even when the hash is unchanged.
    const floor = makeGrant()
    const later = makeGrant(PUB_KEYS, PUB_KID, {
      grant_version: 2,
      legal_text_uri: 'https://mirror.example/sunset-grant-v1',
    })

    expect(evaluate(payloadFor(floor), viewOf(floor, { later_grants: [later] })).warnings).toContain(
      'grant_legal_text_changed',
    )
  })
})

// --- step 8: scope coverage is a GATE ----------------------------------------

describe('evaluateGrant — step 8: scope coverage is a gate', () => {
  it('leaves an uncovered receipt dormant with NEITHER path evaluated', () => {
    // Reporting `activated` here would tell the holder they may redeem
    // something the grant never spoke about, and would contradict §18.7's own
    // custodian precondition. `grant_unanchored` is absent even though the
    // fixed-date mode is declared: step 8 returns before step 10.
    const floor = makeGrant(PUB_KEYS, PUB_KID, {
      scope: scope(null, [ART_OTHER]),
      activation: activation(['fixed-date', 'publisher-declaration'], FIXED_DATE_FUTURE),
    })
    const verdict = evaluate(payloadFor(floor), viewOf(floor, { declarations: [makeDeclaration()] }))

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_scope_uncovered'])
  })

  it('still covers the receipt from a wider catalogue', () => {
    const floor = makeGrant(PUB_KEYS, PUB_KID, { scope: scope(null, [ART_OTHER, RECEIPT_ART]) })
    const verdict = evaluate(
      payloadFor(floor),
      viewOf(floor, { declarations: [makeDeclaration(PUB_KEYS, PUB_KID, scope(null, [ART_OTHER, RECEIPT_ART]))] }),
    )

    expect(verdict.grant).toBe('activated')
  })
})

// --- step 9: the declaration path, scanned in FULL ---------------------------

describe('evaluateGrant — step 9: the declaration path', () => {
  it('activates on a publisher declaration', () => {
    const verdict = evaluate(null, viewOf(null, { declarations: [makeDeclaration()] }))

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual([])
  })

  it('activates on a successor declaration and says so', () => {
    const verdict = evaluate(null, viewOf(null, { declarations: [makeDeclaration(SUCCESSOR_KEYS, SUCCESSOR_KID)] }))

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual(['grant_activated_by_successor'])
  })

  it('never honors a declaration from a stranger', () => {
    const verdict = evaluate(
      null,
      viewOf(null, { declarations: [makeDeclaration(OTHER_KEYS, OTHER_KID)] }),
      trustStoreOf({ [OTHER]: OTHER_MANIFEST }),
    )

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_declaration_ignored'])
  })

  it('ignores a declaration that does not cover the grant scope', () => {
    const verdict = evaluate(
      null,
      viewOf(null, { declarations: [makeDeclaration(PUB_KEYS, PUB_KID, scope(null, [ART_OTHER]))] }),
    )

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_declaration_ignored'])
  })

  it('never stops at the first declaration that succeeds', () => {
    // A full scan is required rather than a short circuit precisely so the
    // warning set is a function of the evidence and not of its arrangement: an
    // implementation that stopped early would report a different result than
    // one that did not, and both would be conforming.
    const good = makeDeclaration()
    const bad = makeDeclaration(OTHER_KEYS, OTHER_KID)
    const trustStore = trustStoreOf({ [OTHER]: OTHER_MANIFEST })

    const goodFirst = evaluate(null, viewOf(null, { declarations: [good, bad] }), trustStore)
    const badFirst = evaluate(null, viewOf(null, { declarations: [bad, good] }), trustStore)

    expect(goodFirst.grant).toBe('activated')
    expect(goodFirst.warnings).toEqual(['grant_declaration_ignored'])
    expect(goodFirst).toEqual(badFirst)
  })

  it('emits each declaration warning at most once', () => {
    const stranger = makeDeclaration(OTHER_KEYS, OTHER_KID)
    const successor = makeDeclaration(SUCCESSOR_KEYS, SUCCESSOR_KID)
    const verdict = evaluate(
      null,
      viewOf(null, { declarations: [stranger, successor, stranger, successor, makeDeclaration()] }),
      trustStoreOf({ [OTHER]: OTHER_MANIFEST }),
    )

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual(['grant_declaration_ignored', 'grant_activated_by_successor'])
  })

  it('reads the successor list from the EFFECTIVE grant', () => {
    // A later version that widened `successor_ids` widens who may declare; one
    // that narrowed it never became effective.
    const floor = makeGrant(PUB_KEYS, PUB_KID, { activation: activation(undefined, undefined, []) })
    const later = makeGrant(PUB_KEYS, PUB_KID, {
      grant_version: 2,
      activation: activation(undefined, undefined, [SUCCESSOR]),
    })
    const declaration = makeDeclaration(SUCCESSOR_KEYS, SUCCESSOR_KID)

    const without = evaluate(payloadFor(floor), viewOf(floor, { declarations: [declaration] }))
    const withLater = evaluate(
      payloadFor(floor),
      viewOf(floor, { later_grants: [later], declarations: [declaration] }),
    )

    expect(without.grant).toBe('dormant')
    expect(withLater.grant).toBe('activated')
  })

  const malformedDeclarations: unknown[] = [null, 42, {}, { publisher: PUBLISHER }, []]

  it.each(malformedDeclarations.map((d, i) => [i, d] as const))(
    'ignores a malformed declaration rather than throwing (#%i)',
    (_i, declaration) => {
      const verdict = evaluate(null, viewOf(null, { declarations: [declaration] }))

      expect(verdict.grant).toBe('dormant')
      expect(verdict.warnings).toEqual(['grant_declaration_ignored'])
    },
  )
})

// --- step 10: the fixed-date path --------------------------------------------

describe('evaluateGrant — step 10: the fixed-date path', () => {
  const fixedDateFixture = (fixedDate: string): { document: JsonObject; evidence: Record<string, unknown> } => {
    const document = makeGrant(PUB_KEYS, PUB_KID, {
      activation: activation(['fixed-date', 'publisher-declaration'], fixedDate),
    })
    return { document, evidence: anchorEvidence(canonicalBytes(document)) }
  }

  it('activates on an anchored proof past the fixed date', () => {
    const { document, evidence } = fixedDateFixture(FIXED_DATE_REACHED)
    const verdict = evaluate(
      payloadFor(document),
      viewOf(document, { anchor: evidence }),
      null,
      anchorPolicyFor(canonicalBytes(document)),
    )

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual([])
  })

  it('stays dormant on a proof resolving earlier than the fixed date', () => {
    const { document, evidence } = fixedDateFixture(FIXED_DATE_FUTURE)
    const verdict = evaluate(
      payloadFor(document),
      viewOf(document, { anchor: evidence }),
      null,
      anchorPolicyFor(canonicalBytes(document)),
    )

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_unanchored'])
  })

  it('warns unanchored when the mode is declared with no proof at all', () => {
    const { document } = fixedDateFixture(FIXED_DATE_REACHED)
    const verdict = evaluate(payloadFor(document), viewOf(document))

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_unanchored'])
  })

  it('cannot open a grant on time without an anchor policy', () => {
    // Not anchor-capable at all: the proof cannot be evaluated, so the grant
    // stays closed — the direction §18.4's failure asymmetry requires.
    const { document, evidence } = fixedDateFixture(FIXED_DATE_REACHED)
    const verdict = evaluate(payloadFor(document), viewOf(document, { anchor: evidence }))

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_unanchored'])
  })

  it('does not activate on an anchor over the WRONG document', () => {
    const { document } = fixedDateFixture(FIXED_DATE_REACHED)
    const verdict = evaluate(
      payloadFor(document),
      viewOf(document, { anchor: anchorEvidence(enc('some other document')) }),
      null,
      anchorPolicyFor(canonicalBytes(document)),
    )

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_unanchored'])
  })

  it('suppresses the backstop warning once a declaration activated', () => {
    // A missing backstop proof says nothing about a grant that is already
    // open, and emitting it would make the warning set depend on which spare
    // evidence a caller happened to attach.
    const { document } = fixedDateFixture(FIXED_DATE_FUTURE)
    const verdict = evaluate(payloadFor(document), viewOf(document, { declarations: [makeDeclaration()] }))

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual([])
  })

  it('reduces two genuine proofs to the MAXIMUM, not the minimum', () => {
    // §18.4's reduction, and the one a `verifyAnchor`-shaped habit gets
    // backwards. `anchoredBefore` is the MINIMUM because it answers "no later
    // than when did this exist?"; `fixed-date` asks "has time reached T?",
    // where the LATEST verified header is the conservative answer. Taking the
    // minimum would be sound-looking and wrong the moment a bundle carries two
    // genuine proofs: the old one would hold the grant closed forever, a false
    // negative the buyer cannot recover from.
    const staleTime = 1_760_000_000 // 2025-10-09, before the backstop
    const staleHash = '5c'.repeat(32)
    const document = makeGrant(PUB_KEYS, PUB_KID, {
      activation: activation(['fixed-date', 'publisher-declaration'], FIXED_DATE_REACHED),
    })
    const seed = canonicalBytes(document)
    const stale = otsProof(seed, 'ee', staleTime, staleHash)
    const fresh = otsProof(seed, 'ab', HEADER_TIME, HEADER_HASH)
    const policy: AnchorPolicy = { pinnedHeaders: Object.fromEntries([pin(stale), pin(fresh)]), crqcHorizon: null }

    const verdict = evaluate(
      payloadFor(document),
      viewOf(document, { anchor: parse({ proofs: [stale, fresh] }) }),
      null,
      policy,
    )

    expect(verdict.grant).toBe('activated')
    expect(verdict.warnings).toEqual([])
  })

  it('applies the CRQC horizon check to the fixed-date proof', () => {
    const { document, evidence } = fixedDateFixture(FIXED_DATE_REACHED)
    const verdict = evaluate(
      payloadFor(document),
      viewOf(document, { anchor: evidence }),
      null,
      anchorPolicyFor(canonicalBytes(document), HEADER_TIME - 1),
    )

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual(['grant_unanchored'])
  })

  it('never activates on a fixed_date set without the mode', () => {
    // `heartbeat-absence` and any unregistered mode contribute nothing; so does
    // a `fixed_date` whose mode was never declared.
    const document = makeGrant(PUB_KEYS, PUB_KID, { activation: activation(['publisher-declaration'], null) })
    const verdict = evaluate(payloadFor(document), viewOf(document))

    expect(verdict.grant).toBe('dormant')
    expect(verdict.warnings).toEqual([])
  })
})

// --- step 11 and the failure direction ---------------------------------------

describe('evaluateGrant — step 11 and the failure direction', () => {
  it('leaves a covered, authenticated grant with no trigger evidence dormant', () => {
    const verdict = evaluate(null, viewOf())

    expect(verdict.grant).toBe('dormant')
    expect(verdict.grant_trust).toBe('unauthenticated_tofu')
    expect(verdict.warnings).toEqual([])
  })

  // Routed through the strict parser, exactly as real evidence arrives: a JSON
  // integer is a `bigint` in this port (canon.ts), so a plain JS `number` in a
  // literal would be a fixture that no wire document can produce.
  const hostileViews: unknown[] = [
    { grant: null },
    { grant: 42 },
    { grant: [], later_grants: 'not-a-list', declarations: 7, anchor: 'no' },
    { grant: { signature: { kid: '../../etc/passwd#1' } } },
    { grant: { signature: { kid: 42 } }, later_grants: [null, 42, 'x'] },
    { later_grants: [{ grant_version: 2 }], declarations: [{ publisher: null }] },
  ].map((view) => parse(view))

  it.each(hostileViews.map((v, i) => [i, v] as const))('never throws on hostile evidence (#%i)', (_i, view) => {
    const verdict = evaluate(null, view)

    expect(['not_checked', 'invalid_grant_ignored', 'dormant']).toContain(verdict.grant)
    expect(verdict.grant).not.toBe('activated')
  })

  const badContainers: unknown[] = [[], 'grant', 42, [{}]]

  it.each(badContainers.map((b, i) => [i, b] as const))(
    'fails loud on a grant view that is not an evidence object (#%i)',
    (_i, bad) => {
      // The caller-contract enforcement its Stage 2/3 siblings already have: a
      // lone grant DOCUMENT passed where the evidence object belongs would be
      // read member by member and resolve to `not_checked`, silently reporting
      // "no grant evidence" to a caller who supplied some.
      expect(() => evaluate(null, bad)).toThrow(TypeError)
    },
  )
})

// --- integration with verify(): the D6 no-exception property -----------------

function envelopeBytes(payload: JsonObject): Uint8Array {
  const bytes = canonicalBytes(payload)
  return enc(
    JSON.stringify({
      payload: JSON.parse(new TextDecoder().decode(bytes)),
      signatures: [
        { kid: ISSUER_KID, alg: 'Ed25519', sig: b64uEncode(ed25519.sign(bytes, ISSUER_KEYS.edSeed)) },
        { kid: ISSUER_KID, alg: 'ML-DSA-65', sig: b64uEncode(ml_dsa65.sign(bytes, ISSUER_KEYS.mldsaSecret!)) },
      ],
    }),
  )
}

function verifyStore(publisherChains: Record<string, JsonObject[]> = {}): TrustStore {
  return {
    manifests: { [ISSUER]: ISSUER_MANIFEST, [PUBLISHER]: PUB_MANIFEST, [SUCCESSOR]: SUCCESSOR_MANIFEST },
    provenance: { [ISSUER]: 'tls', [PUBLISHER]: 'bundle' },
    chains: publisherChains,
  }
}

describe('verify() integration — Stage 4 takes NO exception (D6)', () => {
  it('is byte-identical to the pre-Stage-4 result without a grant view', () => {
    const result = verify(envelopeBytes(payloadFor(makeGrant())), verifyStore())

    expect(result.grant).toBe('not_checked')
    expect(result.grant_trust).toBe('not_checked')
    expect(isOk(result)).toBe(true)
    expect(result.warnings).toEqual([])
  })

  it('reports an activated grant without touching ok', () => {
    const floor = makeGrant()
    const result = verify(envelopeBytes(payloadFor(floor)), verifyStore(), null, null, undefined, {
      grantView: viewOf(floor, { declarations: [makeDeclaration()] }),
    })

    expect(result.grant).toBe('activated')
    expect(isOk(result)).toBe(true)
    expect(result.signature).toBe('valid')
    expect(result.schema).toBe('valid')
    expect(result.revocation).toBe('unknown')
    expect(result.binding).toBe('not_checked')
    expect(result.trust).toBe('verified')
  })

  it('never makes a receipt not ok over an invalid grant', () => {
    const floor = makeGrant()
    const payload = payloadFor(floor, (p) => {
      ;((p['license'] as Record<string, unknown>)['preservation_pledge'] as Record<string, unknown>)['grant_sha256'] =
        'e'.repeat(64)
    })
    const result = verify(envelopeBytes(payload), verifyStore(), null, null, undefined, { grantView: viewOf(floor) })

    expect(result.grant).toBe('invalid_grant_ignored')
    expect(isOk(result)).toBe(true)
    expect(result.errors).toEqual([])
    expect(result.warnings).toContain('grant_commitment_mismatch')
  })

  it("never lets the publisher chain move the receipt's own trust", () => {
    // §18.1: the publisher's manifest gets the same ladder as an issuer's,
    // reported ONLY in `grant_trust`. The receipt's `trust` remains a statement
    // about the ISSUER.
    const unrelated = manifestOf(PUBLISHER, PUB_KID, PUB_KEYS, 7)
    const floor = makeGrant()
    const result = verify(
      envelopeBytes(payloadFor(floor)),
      verifyStore({ [PUBLISHER]: [unrelated, PUB_MANIFEST] }),
      null,
      null,
      undefined,
      { grantView: viewOf(floor, { declarations: [makeDeclaration()] }) },
    )

    expect(result.grant_trust).toBe('unverified_rotation')
    expect(result.trust).toBe('verified')
  })

  it('rejects a grant view that is not an evidence object', () => {
    expect(() =>
      verify(envelopeBytes(payloadFor()), verifyStore(), null, null, undefined, { grantView: [] }),
    ).toThrow(TypeError)
  })

  it('stops reporting sunset-grant as an unknown end_of_life value (§6.7)', () => {
    // attest-versioning.md §6.7 registers it `active`: it is the label a
    // Stage 4 receipt carries, and §18.6 makes it schema-REQUIRED once the
    // pledge term is present. The vocabulary stays OPEN — registering a value
    // assigns it meaning, it does not close the field.
    const result = verify(envelopeBytes(payloadFor(makeGrant())), verifyStore())

    expect(result.warnings.some((w) => w.includes('end_of_life'))).toBe(false)
  })

  it('still reports an UNREGISTERED end_of_life value', () => {
    const payload = payloadFor(null, (p) => {
      const survivability = p['survivability'] as Record<string, unknown>
      survivability['end_of_life'] = 'vanished'
      // §18.6 makes `sunset-grant` mandatory alongside the pledge, so the term
      // has to go too — this test is about the open vocabulary, not the
      // conditional.
      delete (p['license'] as Record<string, unknown>)['preservation_pledge']
    })
    const result = verify(envelopeBytes(payload), verifyStore())

    expect(result.warnings.some((w) => w.includes('end_of_life'))).toBe(true)
  })
})
