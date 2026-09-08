/**
 * The doors take a SNAPSHOT, and nothing that merely looks like one.
 *
 * This file used to test the old boundary, which took the embedder's live
 * store object and copied the data it owned. That defence was sound about what
 * it could see and had one hole nothing inside it could close: a `Proxy` over
 * an EMPTY target forwards `getPrototypeOf`, `getOwnPropertyNames` and
 * `getOwnPropertyDescriptor` to that target, so a facade standing in for
 * `chains` was copied as `{}` and the held rotation history VANISHED. The file
 * pinned that as a KNOWN LIMIT, explicitly "not claimed as fail-closed" — and
 * the limit was not theoretical: measured, it turned a receipt signed by a key
 * the store declares `compromised` into `signature: 'valid'`, `trust:
 * 'verified'`, with no error and no warning.
 *
 * The snapshot does not close that hole. It removes the question it was asked:
 * there is no live container to stand in for, because what a door accepts is
 * not an object carrying the right members but an instance only
 * `trustMaterial.ts` can build, out of bytes it parsed itself. So the tests
 * here no longer sweep truthful-read counts — a count of reads is a property
 * of asking, and nothing asks any more. They check the two halves of INV-4:
 * every door refuses every impostor, in its own DECLARED way, and the honest
 * snapshot still reaches the same verdicts it always did.
 *
 * Python parity: tests/test_trust_store_boundary.py.
 */
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { b64uEncode } from '../src/b64u.js'
import { canonicalBytes, loadsStrict } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import { verify, isOk } from '../src/verify.js'
import { evaluateGrant } from '../src/grant.js'
import { evaluateAuthority } from '../src/authority.js'
import { ERR } from '../src/messages.js'
import { TrustStore, KeyManifest, parseTrustStore, parseKeyManifest } from '../src/trustMaterial.js'

const enc = new TextEncoder()

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/2026-01#ed25519-1`
const DECLARER_KID = `${ISSUER}/keys/2026-02#ed25519-2`
const VALID_FROM = '2026-01-01T00:00:00Z'
const V2_ISSUED = '2026-02-01T00:00:00Z'
const ISSUED_AT = '2026-06-15T00:00:00Z'

const signingSeed = Uint8Array.from({ length: 32 }, () => 41)
const declarerSeed = Uint8Array.from({ length: 32 }, () => 42)
const signingPub = b64uEncode(ed25519.getPublicKey(signingSeed))
const declarerPub = b64uEncode(ed25519.getPublicKey(declarerSeed))

const parseObject = (v: unknown): JsonObject =>
  loadsStrict(enc.encode(JSON.stringify(v))) as JsonObject

const keyEntry = (kid: string, pub: string, status: string) => ({
  kid, pub, valid_from: VALID_FROM, valid_to: null, status,
})

function signManifest(body: Record<string, unknown>, signerKid: string, seed: Uint8Array): JsonObject {
  const parsed = parseObject(body)
  const sig = ed25519.sign(canonicalBytes(parsed), seed)
  return parseObject({ ...body, manifest_signature: { kid: signerKid, sig: b64uEncode(sig) } })
}

const manifestV1 = (): JsonObject =>
  signManifest(
    {
      issuer: ISSUER, manifest_version: 1, issued_at: VALID_FROM,
      keys: [keyEntry(KID, signingPub, 'active'), keyEntry(DECLARER_KID, declarerPub, 'active')],
    },
    KID, signingSeed,
  )

/** The held rotation member that declares the signing key compromised. */
const memberDeclaringCompromise = (): JsonObject =>
  signManifest(
    {
      issuer: ISSUER, manifest_version: 2, issued_at: V2_ISSUED,
      keys: [
        keyEntry(KID, signingPub, 'compromised'),
        keyEntry(DECLARER_KID, declarerPub, 'active'),
      ],
    },
    DECLARER_KID, declarerSeed,
  )

function envelopeBytes(): Uint8Array {
  const payload = parseObject({
    attest_version: '0.1', issued_at: ISSUED_AT,
    receipt_id: '01ARZ3NDEKTSV4RRFFQ69G5FAV', supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    work: {
      title: 'Example Work', publisher: 'Example Publisher',
      identifiers: { issuer_sku: 'SKU-1' }, artifact_series: 'series-1',
    },
    license: {
      grant: 'perpetual', revocability: 'none', transferable: false, drm: 'drm-free',
      terms_uri: 'https://example.com/terms', legal_text_sha256: 'a'.repeat(64),
    },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email' },
    survivability: {
      end_of_life: 'none', eol_commitment_sha256: null,
      eol_commitment_uri: null, redownload_right: true,
    },
  })
  const sig = ed25519.sign(canonicalBytes(payload), signingSeed)
  return enc.encode(
    JSON.stringify({ payload, signatures: [{ kid: KID, alg: 'Ed25519', sig: b64uEncode(sig) }] }),
  )
}

const ENVELOPE = envelopeBytes()

const storeDoc = (chains?: JsonObject[]): JsonObject => {
  const doc: Record<string, unknown> = {
    manifests: { [ISSUER]: manifestV1() },
    provenance: { [ISSUER]: 'tls' },
  }
  if (chains !== undefined) doc.chains = { [ISSUER]: chains }
  return doc as JsonObject
}

const snapshot = (chains?: JsonObject[]): TrustStore =>
  parseTrustStore(canonicalBytes(storeDoc(chains)))

// ---------------------------------------------------------------------------
// The non-vacuity half. If these do not hold, nothing below means anything:
// a door that refused EVERYTHING would pass every impostor test.
// ---------------------------------------------------------------------------

describe('the honest snapshot still reaches the verdicts it always did', () => {
  it('verifies a receipt whose key is good', () => {
    const r = verify(ENVELOPE, snapshot())
    expect(r.signature).toBe('valid')
    expect(isOk(r)).toBe(true)
    expect(r.trust).toBe('verified')
  })

  it('refuses a receipt whose key a HELD rotation member declares compromised', () => {
    const r = verify(ENVELOPE, snapshot([memberDeclaringCompromise()]))
    expect(r.signature).toBe('invalid')
    expect(r.errors.join(' ')).toContain('is compromised')
  })
})

// ---------------------------------------------------------------------------
// INV-4: every door refuses every impostor, in its own declared way.
// ---------------------------------------------------------------------------

/**
 * Everything that can present itself as a trust store without being one.
 *
 * The first entry is the important one and the reason the others exist: it is
 * the shape every embedder used to pass, and the shape the old interface
 * DESCRIBED. An interface is a description of a shape, and a description is
 * exactly what an attacker can satisfy — which is why the door now asks for
 * provenance instead.
 */
function impostors(): Array<[string, unknown]> {
  const real = snapshot([memberDeclaringCompromise()])
  const trapped: string[] = []
  return [
    ['the old interface, complete', storeDoc([memberDeclaringCompromise()])],
    ['a plain object with the five members', {
      manifests: {}, provenance: {}, chains: {},
      artifact_manifests: {}, artifact_manifest_chains: {},
    }],
    ['Object.create(TrustStore.prototype)', Object.create(TrustStore.prototype)],
    ['setPrototypeOf({}, TrustStore.prototype)', Object.setPrototypeOf({}, TrustStore.prototype)],
    // Every trap records. A Proxy of the REAL instance is the sharpest
    // impostor available: it holds a genuine snapshot behind it, so anything
    // that authenticated by asking would be satisfied. `#manifests in x`
    // cannot be forwarded by a Proxy, so no trap ever runs — asserted below.
    ['a Proxy of a real snapshot', new Proxy(real as object, {
      get(t, p, r) { trapped.push(String(p)); return Reflect.get(t, p, r) },
      has(t, p) { trapped.push(`has:${String(p)}`); return Reflect.has(t, p) },
      getOwnPropertyDescriptor(t, p) {
        trapped.push(`gopd:${String(p)}`)
        return Reflect.getOwnPropertyDescriptor(t, p)
      },
      getPrototypeOf(t) { trapped.push('proto'); return Reflect.getPrototypeOf(t) },
    })],
    ['a KeyManifest where a store belongs', parseKeyManifest(canonicalBytes(manifestV1()))],
    ['null', null],
    ['undefined', undefined],
    ['a string', 'manifests'],
    ['an array', []],
    ['a function', () => ({ manifests: {}, provenance: {} })],
  ]
}

describe('INV-4: verify() answers with a verdict, never a crash', () => {
  for (const [label, impostor] of impostors()) {
    it(`refuses ${label}`, () => {
      const r = verify(ENVELOPE, impostor as TrustStore)
      // The DECLARED refusal, not an incidental TypeError: a caller who gets
      // this back is told what to do about it. A crash on a missing property
      // would refuse the same inputs today and stop refusing them the moment
      // the code reads a different member first.
      expect(r.errors).toContain(ERR.TRUST_STORE_NOT_PARSED)
      expect(r.signature).toBe('invalid')
      expect(isOk(r)).toBe(false)
    })
  }
})

describe('INV-4: the two evaluators throw, because a bad store is a bug not a shortfall', () => {
  const grantView = { grant: {} }
  const authorityView = { authorization: {} }

  for (const [label, impostor] of impostors()) {
    it(`evaluateGrant refuses ${label}`, () => {
      expect(() => evaluateGrant({}, impostor as TrustStore, grantView)).toThrow(
        ERR.TRUST_STORE_NOT_PARSED,
      )
    })

    it(`evaluateAuthority refuses ${label}`, () => {
      expect(() => evaluateAuthority({}, impostor as TrustStore, authorityView)).toThrow(
        ERR.TRUST_STORE_NOT_PARSED,
      )
    })
  }

  it('stays silent when the caller supplies no evidence at all', () => {
    // The capability gate comes FIRST: a caller who passes no grant view gets
    // `not_checked` even with a bad store, because it never asked anything of
    // the store. Without this, adding the throw would have made the boundary
    // reach callers that had nothing to do with it.
    expect(evaluateGrant({}, {} as TrustStore, null).grant).toBe('not_checked')
    expect(evaluateAuthority({}, {} as TrustStore, null).publisher_authority).toBe('not_checked')
  })
})

describe('the impostor never gets to run its own code', () => {
  it('a Proxy of a real snapshot is refused with zero traps', () => {
    const real = snapshot()
    const trapped: string[] = []
    const proxy = new Proxy(real as object, {
      get(t, p, r) { trapped.push(String(p)); return Reflect.get(t, p, r) },
      has(t, p) { trapped.push(`has:${String(p)}`); return Reflect.has(t, p) },
      getOwnPropertyDescriptor(t, p) {
        trapped.push(`gopd:${String(p)}`)
        return Reflect.getOwnPropertyDescriptor(t, p)
      },
      getPrototypeOf(t) { trapped.push('proto'); return Reflect.getPrototypeOf(t) },
      ownKeys(t) { trapped.push('ownKeys'); return Reflect.ownKeys(t) },
    })

    const r = verify(ENVELOPE, proxy as TrustStore)

    expect(r.errors).toContain(ERR.TRUST_STORE_NOT_PARSED)
    // The private-field brand is the reason: `#manifests in x` is not a
    // property access, so there is no trap for a Proxy to install on it. An
    // `instanceof` check would have answered TRUE here — and run traps.
    expect(trapped).toEqual([])
    expect(proxy instanceof TrustStore).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// The limit that used to be documented as open.
// ---------------------------------------------------------------------------

describe('the facade that used to empty a member', () => {
  it('no longer reaches a verdict at all', () => {
    // Verbatim the attack the old file pinned as a KNOWN LIMIT: `chains` is a
    // Proxy over an empty target, so the old boundary copied it as `{}`, the
    // held compromise declaration disappeared, and the receipt came back
    // `valid` / `trust: verified`. The document behind this facade is the
    // same one the non-vacuity test above refuses.
    const facade = new Proxy({}, { get: (_t, p) => (p === ISSUER ? [] : undefined) })
    const live = {
      manifests: { [ISSUER]: manifestV1() },
      provenance: { [ISSUER]: 'tls' },
      chains: facade,
    }

    const r = verify(ENVELOPE, live as unknown as TrustStore)

    expect(r.errors).toContain(ERR.TRUST_STORE_NOT_PARSED)
    expect(r.signature).not.toBe('valid')
    expect(r.trust).not.toBe('verified')
  })
})

// ---------------------------------------------------------------------------
// Custody and selectors.
// ---------------------------------------------------------------------------

describe('custody of the handle', () => {
  it('refuses everyone who writes the constructor', () => {
    const notTheToken = Symbol('attest.trustMaterial.admit')
    const fields = {
      manifests: {}, provenance: {}, chains: {},
      artifact_manifests: {}, artifact_manifest_chains: {},
    }
    // Identity and never equality: a symbol with the SAME DESCRIPTION is a
    // different symbol, so a caller cannot forge admission by guessing the
    // name. `Symbol.for` would have made the token a password anyone can look
    // up by description.
    expect(() => new TrustStore(notTheToken, fields, new Uint8Array()))
      .toThrow(TypeError)
    expect(() => new KeyManifest(notTheToken, {}, new Uint8Array()))
      .toThrow(TypeError)
  })

  it('exposes exactly the members the boundary means to expose', () => {
    // Derived from the object, not from prose: a method added tomorrow shows
    // up here and has to be justified, which is the point.
    expect(Reflect.ownKeys(TrustStore.prototype).map(String).sort()).toEqual([
      'chainFor', 'constructor', 'data', 'issuers', 'manifestFor', 'provenanceFor', 'toBytes',
    ])
    expect(Reflect.ownKeys(KeyManifest.prototype).map(String).sort()).toEqual([
      'constructor', 'data', 'toBytes',
    ])
  })

  it('hands back a fresh copy of the bytes every time (INV-5)', () => {
    const s = snapshot()
    const first = s.toBytes()
    first.fill(0)
    expect(s.toBytes()).not.toEqual(first)
  })
})

describe('selectors refuse a hostile key without coercing it (D18)', () => {
  it('never runs the caller\'s conversion hooks', () => {
    const s = snapshot([memberDeclaringCompromise()])
    const called: string[] = []
    const hostile = {
      [Symbol.toPrimitive]: () => { called.push('toPrimitive'); return ISSUER },
      toString: () => { called.push('toString'); return ISSUER },
      valueOf: () => { called.push('valueOf'); return ISSUER },
    }

    expect(s.manifestFor(hostile)).toBeNull()
    expect(s.chainFor(hostile)).toEqual([])
    expect(s.provenanceFor(hostile)).toBeNull()
    // The type check comes BEFORE the indexing, so nothing the caller wrote
    // ever runs. A lookup would have coerced first and then compared.
    expect(called).toEqual([])
  })

  it('does not resolve a prototype member as an issuer', () => {
    const s = snapshot()
    for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(s.manifestFor(name), name).toBeNull()
      expect(s.chainFor(name), name).toEqual([])
      expect(s.provenanceFor(name), name).toBeNull()
    }
  })

  it('resolves the issuer that IS there', () => {
    // The positive control for the three above: without it, a selector that
    // returned null for everything would pass them all.
    const s = snapshot([memberDeclaringCompromise()])
    expect(s.manifestFor(ISSUER)).not.toBeNull()
    expect(s.chainFor(ISSUER)).toHaveLength(1)
    expect(s.provenanceFor(ISSUER)).toBe('tls')
    expect(s.issuers()).toEqual([ISSUER])
  })
})
