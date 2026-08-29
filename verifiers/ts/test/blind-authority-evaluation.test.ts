import { describe, expect, it } from 'vitest'
import { evaluateAuthority } from '../src/authority.js'
import {
  buildGrant,
  buildKeyManifest,
  hybridSigner,
  keyEntry,
  parse,
} from './helpers/grant-builder.js'
import { canonicalBytes } from '../src/canon.js'

type Authority = 'not_checked' | 'no_publisher_claim' | 'self' | 'authorized' | 'unauthorized' | 'unattested'
type AuthorityTrust = 'not_checked' | 'verified' | 'unauthenticated_tofu' | 'unverified_rotation' | 'signer_mismatch'
type AuthorityResult = {
  publisher_authority: Authority
  publisher_authority_trust: AuthorityTrust
  warnings: string[]
}

// `publisher_claim_unattested` is NOT an evaluateAuthority warning: section
// 20.1's stratification is a property of the verifier as a whole, and BOTH
// cores emit it in `verify()`, after extending with the verdict's own
// warnings — same reading already ratified for the Python blind bench
// (tests/test_evaluate_authority_blind.py, WARN_CLAIM). Below, every
// expectation that omits it is saying what evaluateAuthority does NOT emit
// itself; where a site still names it, it is left alone as a genuine
// candidate defect (see report), not an instance of this reclassification.
const WARN_CLAIM = 'publisher_claim_unattested'

const PUBLISHER = 'pub.example'
const ISSUER = 'store.example.com'
const OTHER_ISSUER = 'other-store.example'
const THIRD_PARTY = 'marketplace.example'
const PUB_KID = `${PUBLISHER}/keys/2025-01#ed25519-1`
const THIRD_KID = `${THIRD_PARTY}/keys/2025-01#ed25519-1`
const START = '2025-01-01T00:00:00Z'
const RECEIPT_TIME = '2025-06-01T00:00:00Z'
const LATER = '2025-07-01T00:00:00Z'
const ARTIFACT = 'a'.repeat(64)
const MAX_SAFE = 9_007_199_254_740_991
const EVIDENCE_BYTE_CEILING = 10_000_000

const publisherSigner = hybridSigner(11)
const thirdPartySigner = hybridSigner(12)

const publisherManifest = buildKeyManifest(
  PUBLISHER,
  1,
  START,
  [keyEntry(PUB_KID, publisherSigner, START)],
  publisherSigner,
  PUB_KID,
)

const thirdPartyManifest = buildKeyManifest(
  THIRD_PARTY,
  1,
  START,
  [keyEntry(THIRD_KID, thirdPartySigner, START)],
  thirdPartySigner,
  THIRD_KID,
)

function trustStore(provenance: 'tls' | 'tofu' = 'tls') {
  return {
    manifests: {
      [PUBLISHER]: publisherManifest,
      [THIRD_PARTY]: thirdPartyManifest,
    },
    provenance: provenance === 'tls' ? { [PUBLISHER]: 'tls', [THIRD_PARTY]: 'tls' } : {},
    chains: {},
    artifact_manifests: {},
    artifact_manifest_chains: {},
  }
}

function payload(overrides: Record<string, unknown> = {}) {
  return {
    attest_version: '0.2',
    issued_at: RECEIPT_TIME,
    issuer: { id: ISSUER },
    work: {
      publisher_id: PUBLISHER,
      artifact_series: 'series-a',
      artifacts: [{ sha256: ARTIFACT }],
    },
    ...overrides,
  }
}

function entry(overrides: Record<string, unknown> = {}) {
  return {
    issuer_id: ISSUER,
    valid_from: START,
    valid_to: null,
    permissions: ['issue'],
    scope: null,
    ...overrides,
  }
}

function authorization(
  version: number,
  entries = [entry()],
  overrides: Record<string, unknown> = {},
  signer = publisherSigner,
  kid = PUB_KID,
) {
  return buildGrant(
    {
      authorization_version: version,
      publisher: PUBLISHER,
      authorized_issuers: entries,
      issued_at: START,
      ...overrides,
    },
    signer,
    kid,
  )
}

function view(authorizations: unknown, currentAuthorizationVersion?: unknown) {
  const out: Record<string, unknown> = { authorizations }
  if (currentAuthorizationVersion !== undefined) out.current_authorization_version = currentAuthorizationVersion
  return out
}

function jsonClone(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? Number(v) : v)))
}

function strictParsedView(authorizations: unknown[], currentAuthorizationVersion?: number) {
  return parse(jsonClone(view(authorizations, currentAuthorizationVersion)))
}

function manualNumberView(authorizations: unknown[], currentAuthorizationVersion?: number) {
  return jsonClone(view(authorizations, currentAuthorizationVersion))
}

function normalize(result: AuthorityResult): AuthorityResult {
  return { ...result, warnings: [...result.warnings].sort() }
}

function expectAuthority(
  inputPayload: unknown,
  inputTrustStore: unknown,
  authorityView: unknown,
  expected: AuthorityResult,
) {
  let returned = false
  let actual: AuthorityResult | undefined
  expect(() => {
    actual = evaluateAuthority(inputPayload, inputTrustStore, authorityView) as AuthorityResult
    returned = true
  }).not.toThrow()
  expect(returned).toBe(true)
  expect(normalize(actual!)).toEqual(normalize(expected))
}

function expectSameVerdictForStrictAndManualNumbers(
  authorizations: unknown[],
  currentAuthorizationVersion: number | undefined,
  expected: AuthorityResult,
) {
  let strictReturned = false
  let manualReturned = false
  let strict: AuthorityResult | undefined
  let manual: AuthorityResult | undefined
  expect(() => {
    strict = normalize(evaluateAuthority(payload(), trustStore(), strictParsedView(authorizations, currentAuthorizationVersion)) as AuthorityResult)
    strictReturned = true
  }).not.toThrow()
  expect(() => {
    manual = normalize(evaluateAuthority(payload(), trustStore(), manualNumberView(authorizations, currentAuthorizationVersion)) as AuthorityResult)
    manualReturned = true
  }).not.toThrow()
  expect(strictReturned).toBe(true)
  expect(manualReturned).toBe(true)
  expect(strict).toEqual(normalize(expected))
  expect(manual).toEqual(normalize(expected))
  expect(manual).toEqual(strict)
}

function deepArray(depth: number): unknown {
  let value: unknown = null
  for (let i = 0; i < depth; i += 1) value = [value]
  return value
}

function busyWait(ms: number) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    // The loop is the hostile input. A conforming evaluator must not enter it.
  }
}

function authorizationWithCanonicalSize(targetBytes: number) {
  const base = authorization(1, [entry({ permissions: ['issue', 'p'] })])
  const baseSize = canonicalBytes(base).length
  const fillerLength = targetBytes - baseSize + 1
  expect(fillerLength).toBeGreaterThan(0)
  const candidate = authorization(1, [entry({ permissions: ['issue', 'p'.repeat(fillerLength)] })])
  expect(canonicalBytes(candidate).length).toBe(targetBytes)
  return candidate
}

describe('blind publisher authority evaluation', () => {
  it('[RESTRITTIVA] absent authorityView keeps the capability gate closed and emits only the floor warning', () => {
    expectAuthority(payload(), trustStore(), undefined, {
      publisher_authority: 'not_checked',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 1 no publisher claim short-circuits before valid authorizations can authorize', () => {
    expectAuthority(payload({ work: { artifact_series: 'series-a' } }), trustStore(), view([authorization(1)], 1), {
      publisher_authority: 'no_publisher_claim',
      publisher_authority_trust: 'not_checked',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 2 non-string issuer id short-circuits before matching current denial evidence', () => {
    expectAuthority(payload({ issuer: { id: 7 } }), trustStore(), view([authorization(1, [])], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[PERMISSIVA] step 3 self-publishing short-circuits before hostile authorizations are read', () => {
    const hostileView = Object.create(null)
    Object.defineProperty(hostileView, 'authorizations', {
      enumerable: true,
      get() {
        throw new Error('authorizations must not be read after self authority resolves')
      },
    })
    expectAuthority(payload({ work: { publisher_id: ISSUER } }), trustStore(), hostileView, {
      publisher_authority: 'self',
      publisher_authority_trust: 'not_checked',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 4 missing authorizations resolves unattested before trust is resolved', () => {
    expectAuthority(payload(), trustStore(), {}, {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 4 empty authorizations resolves unattested', () => {
    expectAuthority(payload(), trustStore(), view([]), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 4 non-array authorizations resolves unattested and does not raise', () => {
    expectAuthority(payload(), trustStore(), view({ 0: authorization(1) }), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[PERMISSIVA] step 9 authorized needs no current_authorization_version currency assertion', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1)]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 10 unauthorized is reachable only with matching current_authorization_version', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [])], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] missing current_authorization_version makes a denial unattested rather than unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [])]), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] stale current_authorization_version makes a denial unattested rather than unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(2, [])], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] malformed current_authorization_version is absent and cannot buy unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [])], true), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] unverifiable authorization is ignored safely with publisher trust still keyed to the receipt publisher', () => {
    const tampered = { ...authorization(1), publisher: 'other.example' }
    expectAuthority(payload(), trustStore(), view([tampered], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] malformed authorization shape is ignored safely and warning is emitted at most once', () => {
    expectAuthority(payload(), trustStore(), view([{ publisher: PUBLISHER }, { issued_at: START }], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] ambiguous duplicate issuer entries are shape-invalid and cannot ground unauthorized', () => {
    const duplicate = authorization(1, [entry(), entry()])
    expectAuthority(payload(), trustStore(), view([duplicate], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] closed authorization and issuer-entry shapes reject unknown members', () => {
    const topLevelExtra = authorization(1, [entry()], { unexpected: true })
    const entryExtra = authorization(2, [entry({ unexpected: true })])
    expectAuthority(payload(), trustStore(), view([topLevelExtra, entryExtra], 2), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: ['authorization_invalid_ignored'],
    })
  })

  it('[RESTRITTIVA] unsorted authorized_issuers are shape-invalid before membership', () => {
    const unsorted = authorization(1, [entry(), entry({ issuer_id: OTHER_ISSUER })])
    expectAuthority(payload(), trustStore(), view([unsorted], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: ['authorization_invalid_ignored'],
    })
  })

  it('[RESTRITTIVA] unauthenticated foreign kid cannot buy signer_mismatch trust', () => {
    const unsignedForeign = { ...authorization(1), signature: { kid: THIRD_KID, sig: 'bad' } }
    expectAuthority(payload(), trustStore(), view([unsignedForeign], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] authenticated signer mismatch is set aside with signer_mismatch trust', () => {
    const foreignSigned = authorization(1, [], { publisher: PUBLISHER }, thirdPartySigner, THIRD_KID)
    expectAuthority(payload(), trustStore(), view([foreignSigned], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'signer_mismatch',
      warnings: [
        'authorization_signer_not_publisher',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] distinct authenticated documents with the same authorization_version are equivocation', () => {
    const a = authorization(3, [entry({ valid_to: null })])
    const b = authorization(3, [entry({ valid_to: LATER })])
    expectAuthority(payload(), trustStore(), view([a, b], 3), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'unverified_rotation',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[PERMISSIVA] byte-identical duplicate authorizations are deduplicated and do not create equivocation', () => {
    const auth = authorization(3)
    expectAuthority(payload(), trustStore(), view([auth, auth], 3), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 7 unverified_rotation prevails over an appended signer_mismatch document', () => {
    const a = authorization(3, [entry({ valid_to: null })])
    const b = authorization(3, [entry({ valid_to: LATER })])
    const foreignSigned = authorization(4, [], { publisher: PUBLISHER }, thirdPartySigner, THIRD_KID)
    expectAuthority(payload(), trustStore(), view([foreignSigned, a, b], 4), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'unverified_rotation',
      warnings: [
        'authorization_signer_not_publisher',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[PERMISSIVA] step 8 chooses the greatest admitted authorization_version independent of presentation order', () => {
    const oldDeny = authorization(1, [])
    const currentAllow = authorization(2, [entry()])
    expectAuthority(payload(), trustStore(), view([currentAllow, oldDeny]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
    expectAuthority(payload(), trustStore(), view([oldDeny, currentAllow]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] step 9 absent issuer entry falls through to current-gated unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [entry({ issuer_id: OTHER_ISSUER })])], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] step 9 receipt issued outside the window falls through to current-gated unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [entry({ valid_to: '2025-05-31T00:00:00Z' })])], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] step 9 delegate without issue permission falls through to current-gated unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [entry({ permissions: ['delegate'] })])], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] step 9 uncovered scope falls through to current-gated unauthorized', () => {
    const uncoveredScope = { artifact_series: 'other-series', artifacts: [] }
    expectAuthority(payload(), trustStore(), view([authorization(1, [entry({ scope: uncoveredScope })])], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[PERMISSIVA] a scoped authorization covers a receipt by artifact hash even when series differs', () => {
    const hashScope = { artifact_series: null, artifacts: [ARTIFACT] }
    expectAuthority(payload(), trustStore(), view([authorization(1, [entry({ scope: hashScope })])]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] inherited authorityView members are absent and cannot authorize or deny', () => {
    const inherited = Object.create(view([authorization(1, [])], 1))
    expectAuthority(payload(), trustStore(), inherited, {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] getter-defined authorizations are non-admitted and cannot authorize', () => {
    const getterView = Object.create(null)
    Object.defineProperty(getterView, 'authorizations', {
      enumerable: true,
      get: () => [authorization(1)],
    })
    expectAuthority(payload(), trustStore(), getterView, {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] a throwing member read returns unattested instead of raising', () => {
    const throwingView = Object.create(null)
    Object.defineProperty(throwingView, 'authorizations', {
      enumerable: true,
      get() {
        throw new Error('hostile accessor')
      },
    })
    expectAuthority(payload(), trustStore(), throwingView, {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  // A proxy whose getOwnPropertyDescriptor answers with a DATA descriptor is
  // admitted by the boundary, and no JavaScript spelling distinguishes it from a
  // stored descriptor. What the boundary guarantees is that the read happens
  // ONCE, is bounded, sees only DATA properties, and that everything downstream
  // reads the reconstruction — NOT that a proxy is detectable. This one delivers
  // a GENUINE signed authorization with an empty authorized_issuers plus a
  // matching currency assertion, so it synthesizes nothing and earns exactly the
  // verdict that evidence deserves, identical to passing it bare: the denial of
  // leaf 43b-unauthorized-empty-list.
  it('[RESTRITTIVA] a proxy-delivered view earns the verdict its genuine evidence deserves', () => {
    const proxyView = new Proxy(Object.create(null), {
      ownKeys: () => ['authorizations', 'current_authorization_version'],
      getOwnPropertyDescriptor(_target, prop) {
        if (prop === 'authorizations') return { enumerable: true, configurable: true, value: [authorization(1, [])] }
        if (prop === 'current_authorization_version') return { enumerable: true, configurable: true, value: 1 }
        return undefined
      },
      get(_target, prop) {
        if (prop === 'authorizations') return [authorization(1, [])]
        if (prop === 'current_authorization_version') return 1
        return undefined
      },
    })
    expectAuthority(payload(), trustStore(), proxyView, {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] a lazy unbounded authorizations container is not walked and returns within a wall-clock bound', () => {
    const lazyAuthorizations = new Proxy([], {
      get(target, prop, receiver) {
        if (prop === 'length' || prop === Symbol.iterator) busyWait(500)
        return Reflect.get(target, prop, receiver)
      },
      ownKeys() {
        busyWait(500)
        return []
      },
    })
    const started = Date.now()
    expectAuthority(payload(), trustStore(), view(lazyAuthorizations), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
    expect(Date.now() - started).toBeLessThan(250)
  })

  it('[PERMISSIVA] an inadmissible authorization element is set aside without deleting a genuine sibling', () => {
    const badElement = new Proxy(Object.create(null), {
      ownKeys() {
        throw new Error('hostile document')
      },
    })
    expectAuthority(payload(), trustStore(), view([badElement, authorization(1)]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: ['authorization_invalid_ignored'],
    })
  })

  it('[PERMISSIVA] a too-deep authorization element is set aside while its genuine sibling reaches its verdict', () => {
    expectAuthority(payload(), trustStore(), view([deepArray(260), authorization(1)]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: ['authorization_invalid_ignored'],
    })
  })

  it('[PERMISSIVA] exactly 64 authorization documents remain within the count ceiling', () => {
    const auth = authorization(1)
    expectAuthority(payload(), trustStore(), view(Array.from({ length: 64 }, () => auth)), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] 65 authorization documents exceed the count ceiling and fail closed before document work', () => {
    const auth = authorization(1)
    expectAuthority(payload(), trustStore(), view(Array.from({ length: 65 }, () => auth), 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'not_checked',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[PERMISSIVA] exactly 4096 authorized_issuers entries remain within the document ceiling', () => {
    const entries = Array.from({ length: 4095 }, (_v, i) =>
      entry({ issuer_id: `issuer-${String(i).padStart(4, '0')}.example` }),
    )
    entries.push(entry())
    entries.sort((a, b) => String(a.issuer_id).localeCompare(String(b.issuer_id)))
    expectAuthority(payload(), trustStore(), view([authorization(1, entries)]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] 4097 authorized_issuers entries exceed the document ceiling and are ignored safely', () => {
    const entries = Array.from({ length: 4096 }, (_v, i) =>
      entry({ issuer_id: `issuer-${String(i).padStart(4, '0')}.example` }),
    )
    entries.push(entry())
    entries.sort((a, b) => String(a.issuer_id).localeCompare(String(b.issuer_id)))
    expectAuthority(payload(), trustStore(), view([authorization(1, entries)], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] current_authorization_version at the lower bound can ground unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [])], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] current_authorization_version below the lower bound is absent and cannot ground unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [])], 0), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] current_authorization_version at the safe-integer upper bound can ground unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(MAX_SAFE, [])], MAX_SAFE), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] current_authorization_version above the safe-integer upper bound is absent and cannot ground unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1, [])], MAX_SAFE + 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      warnings: [],
    })
  })

  it('[RESTRITTIVA] authorization_version below the lower bound is shape-invalid and cannot ground unauthorized', () => {
    expectAuthority(payload(), trustStore(), view([authorization(0, [])], 0), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] authorization_version above the safe-integer upper bound is shape-invalid and cannot ground unauthorized', () => {
    const tooLargeVersion = { ...authorization(1, []), authorization_version: MAX_SAFE + 1 }
    expectAuthority(payload(), trustStore(), view([tooLargeVersion], MAX_SAFE + 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[PERMISSIVA] an authorization document exactly at the evidence byte ceiling remains admissible', () => {
    const exact = authorizationWithCanonicalSize(EVIDENCE_BYTE_CEILING)
    expectAuthority(payload(), trustStore(), view([exact]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] an authorization document one byte over the evidence byte ceiling is set aside alone', () => {
    const over = authorizationWithCanonicalSize(EVIDENCE_BYTE_CEILING + 1)
    expectAuthority(payload(), trustStore(), view([over], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'verified',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })

  it('[RESTRITTIVA] number and bigint current version representations compare equal for step 10 denial', () => {
    expectSameVerdictForStrictAndManualNumbers([authorization(5, [])], 5, {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[PERMISSIVA] number and bigint authorization versions choose the same step 8 maximum', () => {
    expectSameVerdictForStrictAndManualNumbers([authorization(4, []), authorization(5)], undefined, {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] number and bigint same-version equivocation are classified identically', () => {
    expectSameVerdictForStrictAndManualNumbers(
      [authorization(6, [entry({ valid_to: null })]), authorization(6, [entry({ valid_to: LATER })])],
      6,
      {
        publisher_authority: 'unattested',
        publisher_authority_trust: 'unverified_rotation',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
        warnings: [],
      },
    )
  })

  it('[PERMISSIVA] number and bigint successor ordering exclude the same non-conforming successor', () => {
    expectSameVerdictForStrictAndManualNumbers(
      [authorization(7), authorization(8, [], { issued_at: LATER })],
      undefined,
      {
        publisher_authority: 'authorized',
        publisher_authority_trust: 'unverified_rotation',
        warnings: [],
      },
    )
  })

  it('[RESTRITTIVA] successor deletion of a prior entry excludes the successor', () => {
    expectAuthority(payload(), trustStore(), view([authorization(1), authorization(2, [], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] successor valid_from change excludes the successor', () => {
    const changed = entry({ valid_from: '2025-02-01T00:00:00Z' })
    expectAuthority(payload(), trustStore(), view([authorization(1), authorization(2, [changed], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] spent window moved earlier excludes the successor', () => {
    const spent = entry({ valid_to: '2025-02-01T00:00:00Z' })
    const movedEarlier = entry({ valid_to: '2025-01-15T00:00:00Z' })
    expectAuthority(payload(), trustStore(), view([authorization(1, [spent]), authorization(2, [movedEarlier], { issued_at: LATER })], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] spent window moved later excludes the successor', () => {
    const spent = entry({ valid_to: '2025-02-01T00:00:00Z' })
    const movedLater = entry({ valid_to: '2025-03-01T00:00:00Z' })
    expectAuthority(payload(), trustStore(), view([authorization(1, [spent]), authorization(2, [movedLater], { issued_at: LATER })], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[RESTRITTIVA] spent window moved back to null excludes the successor', () => {
    const spent = entry({ valid_to: '2025-02-01T00:00:00Z' })
    const movedOpen = entry({ valid_to: null })
    expectAuthority(payload(), trustStore(), view([authorization(1, [spent]), authorization(2, [movedOpen], { issued_at: LATER })], 1), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[PERMISSIVA] live window carried forward unchanged conforms', () => {
    const live = entry({ valid_to: '2025-08-01T00:00:00Z' })
    expectAuthority(payload(), trustStore(), view([authorization(1, [live]), authorization(2, [live], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[PERMISSIVA] live window extended later conforms', () => {
    const oldLive = entry({ valid_to: '2025-08-01T00:00:00Z' })
    const extended = entry({ valid_to: '2025-09-01T00:00:00Z' })
    expectAuthority(payload(), trustStore(), view([authorization(1, [oldLive]), authorization(2, [extended], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[PERMISSIVA] live finite window extended to null conforms', () => {
    const oldLive = entry({ valid_to: '2025-08-01T00:00:00Z' })
    const extendedOpen = entry({ valid_to: null })
    expectAuthority(payload(), trustStore(), view([authorization(1, [oldLive]), authorization(2, [extendedOpen], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[PERMISSIVA] live shortening exactly to the earlier issued_at lower bound conforms', () => {
    const oldLive = entry({ valid_to: null })
    const closedAtLowerBound = entry({ valid_to: START })
    expectAuthority(payload(), trustStore(), view([authorization(1, [oldLive]), authorization(2, [closedAtLowerBound], { issued_at: LATER })], 2), {
      publisher_authority: 'unauthorized',
      publisher_authority_trust: 'verified',
      warnings: ['publisher_not_authorizing_issuer'],
    })
  })

  it('[PERMISSIVA] live shortening exactly to the successor issued_at upper bound conforms', () => {
    const oldLive = entry({ valid_to: null })
    const closedAtUpperBound = entry({ valid_to: LATER })
    expectAuthority(payload(), trustStore(), view([authorization(1, [oldLive]), authorization(2, [closedAtUpperBound], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] live shortening below the lower bound excludes the successor', () => {
    const oldLive = entry({ valid_to: null })
    const backDated = entry({ valid_to: '2024-12-31T23:59:59Z' })
    expectAuthority(payload(), trustStore(), view([authorization(1, [oldLive]), authorization(2, [backDated], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] live shortening above the successor issued_at upper bound excludes the successor', () => {
    const oldLive = entry({ valid_to: null })
    const postDated = entry({ valid_to: '2025-07-02T00:00:00Z' })
    expectAuthority(payload(), trustStore(), view([authorization(1, [oldLive]), authorization(2, [postDated], { issued_at: LATER })]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: [],
    })
  })

  it('[PERMISSIVA] adding an entry absent from every earlier version conforms, even when back-dated', () => {
    const old = authorization(1, [entry({ issuer_id: OTHER_ISSUER })])
    const added = authorization(2, [entry({ issuer_id: OTHER_ISSUER }), entry({ valid_from: '2024-01-01T00:00:00Z' })], {
      issued_at: LATER,
    })
    expectAuthority(payload(), trustStore(), view([old, added]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: [],
    })
  })

  it('[RESTRITTIVA] simultaneous successor deletion and valid_from change exclude the successor once', () => {
    // The predecessor's authorized_issuers MUST be sorted strictly ascending by
    // issuer_id at Unicode code point (§20.2), and 'other-store.example' sorts
    // BEFORE 'store.example.com'. Listed the other way round this document is
    // shape-invalid, so it never reaches step 7 and the case asserts nothing:
    // the successor becomes the only admitted document and authorizes on its
    // own. Measured 2026-08-29 — the order is load-bearing for this case.
    const old = authorization(1, [entry({ issuer_id: OTHER_ISSUER }), entry()])
    const changedAndDeleted = authorization(2, [entry({ valid_from: '2025-02-01T00:00:00Z' })], { issued_at: LATER })
    expectAuthority(payload(), trustStore(), view([old, changedAndDeleted]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'unverified_rotation',
      warnings: [],
    })
  })

  it('[PERMISSIVA] unauthenticated successor-looking junk cannot exclude a genuine successor', () => {
    const old = authorization(1)
    const genuineSuccessor = authorization(2, [entry({ valid_to: null })], { issued_at: LATER })
    const junk = { ...authorization(3, [], { issued_at: LATER }), signature: { kid: PUB_KID, sig: 'bad' } }
    expectAuthority(payload(), trustStore(), view([old, junk, genuineSuccessor]), {
      publisher_authority: 'authorized',
      publisher_authority_trust: 'verified',
      warnings: ['authorization_invalid_ignored'],
    })
  })

  it('[RESTRITTIVA] unauthenticated_tofu publisher trust is preserved after every document is rejected', () => {
    const tampered = { ...authorization(1), publisher: 'other.example' }
    expectAuthority(payload(), trustStore('tofu'), view([tampered], 1), {
      publisher_authority: 'unattested',
      publisher_authority_trust: 'unauthenticated_tofu',
      warnings: [
        'authorization_invalid_ignored',
        // publisher_claim_unattested is verify()'s, not evaluateAuthority's (WARN_CLAIM note above).
      ],
    })
  })
})
