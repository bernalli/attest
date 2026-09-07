/**
 * The trust store is caller-supplied data, and until it is materialized it is
 * a caller-supplied OBJECT.
 *
 * `verify()` reads the embedder's key manifests with plain property reads, and
 * in JavaScript a plain property read is a getter or a `Proxy` trap away from
 * answering differently on every call. The trust store never passes through
 * `loadsStrict` — it is not wire data — so an application that builds it from
 * its own objects (an ORM row, a lazy wrapper, a proxy over a database record)
 * could hand the verifier a value whose ANSWERS differ from its own DATA.
 *
 * The window is ONE VALUE WIDE, and that is why nobody finds this by hand: the
 * first reads canonicalize the manifest and satisfy its self-authenticity
 * gate, and the read after that is the one that decides. Measured on the
 * published 0.9.3 core: with 0, 1 or 3+ truthful reads the verdict is correct;
 * with exactly TWO, a receipt issued four months after the key expired and a
 * key the signed manifest marks `compromised` both verified `signature:
 * 'valid'`, `isOk: true`, with no error and no warning.
 *
 * Every test below therefore SWEEPS the truthful-read count instead of picking
 * one, and asserts its own non-vacuity first: the same manifest with plain
 * data in that position must produce the safe verdict.
 *
 * Python parity: tests/test_trust_store_boundary.py.
 */
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { b64uEncode } from '../src/b64u.js'
import { canonicalBytes, dumps, loadsStrict } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import { verify, isOk } from '../src/verify.js'
import { manifestSignatureIsAuthentic } from '../src/manifests.js'
import type { TrustStore } from '../src/manifests.js'
import { materializeKeyManifest, materializeTrustStore } from '../src/trustMaterial.js'

const enc = new TextEncoder()

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/test#ed25519-1`
const COMPROMISED_KID = `${ISSUER}/keys/test#ed25519-compromised`
const RECEIPT_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAV'
const VALID_FROM = '2026-01-01T00:00:00Z'
const EXPIRED_AT = '2026-03-01T00:00:00Z'
const ISSUED_AT = '2026-07-02T14:30:00Z' // four months past EXPIRED_AT

const signingSeed = Uint8Array.from({ length: 32 }, () => 9)
const compromisedSeed = Uint8Array.from({ length: 32 }, () => 15)
const signingPub = b64uEncode(ed25519.getPublicKey(signingSeed))
const compromisedPub = b64uEncode(ed25519.getPublicKey(compromisedSeed))

// How many truthful reads to try before the accessor starts lying. The
// published defect lived at exactly 2; the sweep exists so a future change to
// the read order cannot move the hole somewhere a fixed number would miss.
const TRUTHFUL_READ_COUNTS = [0, 1, 2, 3, 4, 5, 6, 7, 8]

function parseObject(value: unknown): JsonObject {
  return loadsStrict(enc.encode(JSON.stringify(value))) as JsonObject
}

function keyEntry(kid: string, pub: string, status: string, validTo: string | null) {
  return { kid, pub, valid_from: VALID_FROM, valid_to: validTo, status }
}

function signManifest(
  keys: Record<string, unknown>[],
  signerKid: string,
  seed: Uint8Array,
): JsonObject {
  const body = { issuer: ISSUER, manifest_version: 1, issued_at: VALID_FROM, keys }
  const sig = ed25519.sign(canonicalBytes(parseObject(body)), seed)
  return parseObject({ ...body, manifest_signature: { kid: signerKid, sig: b64uEncode(sig) } })
}

/** One key, active, that STOPPED being valid before the receipt was issued. */
function expiringManifest(): JsonObject {
  return signManifest([keyEntry(KID, signingPub, 'active', EXPIRED_AT)], KID, signingSeed)
}

/** Self-signed by an active key; the receipt's signer is marked compromised. */
function compromisedSignerManifest(): JsonObject {
  return signManifest(
    [
      keyEntry(KID, signingPub, 'active', null),
      keyEntry(COMPROMISED_KID, compromisedPub, 'compromised', null),
    ],
    KID,
    signingSeed,
  )
}

function receiptPayload(): JsonObject {
  return parseObject({
    attest_version: '0.1',
    issued_at: ISSUED_AT,
    receipt_id: RECEIPT_ID,
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
    survivability: {
      end_of_life: 'none',
      eol_commitment_sha256: null,
      eol_commitment_uri: null,
      redownload_right: true,
    },
  })
}

function envelopeBytes(kid: string, seed: Uint8Array): Uint8Array {
  const payload = receiptPayload()
  const sig = ed25519.sign(canonicalBytes(payload), seed)
  return enc.encode(
    JSON.stringify({ payload, signatures: [{ kid, alg: 'Ed25519', sig: b64uEncode(sig) }] }),
  )
}

function store(manifest: JsonObject): TrustStore {
  return { manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: 'tls' } }
}

function entryIndex(manifest: JsonObject, kid: string): number {
  return (manifest['keys'] as JsonObject[]).findIndex((e) => e['kid'] === kid)
}

/** Replace `member` with a getter that tells the truth `truthful` times. */
function withCountingGetter(
  manifest: JsonObject,
  kid: string,
  member: string,
  lie: unknown,
  truthful: number,
): JsonObject {
  const entry = (manifest['keys'] as JsonObject[])[entryIndex(manifest, kid)]!
  const real = entry[member]
  delete entry[member]
  let reads = 0
  Object.defineProperty(entry, member, {
    get() {
      reads += 1
      return reads <= truthful ? real : lie
    },
    enumerable: true,
    configurable: true,
  })
  return manifest
}

/** Wrap the entry in a Proxy whose `get` trap tells the truth `truthful` times. */
function withCountingProxy(
  manifest: JsonObject,
  kid: string,
  member: string,
  lie: unknown,
  truthful: number,
): JsonObject {
  const keys = manifest['keys'] as JsonObject[]
  const index = entryIndex(manifest, kid)
  const target = keys[index]!
  let reads = 0
  keys[index] = new Proxy(target, {
    get(t, property, receiver) {
      if (property === member) {
        reads += 1
        return reads <= truthful ? t[member as keyof typeof t] : lie
      }
      return Reflect.get(t, property, receiver)
    },
  }) as JsonObject
  return manifest
}

describe('the trust store is read as data, not asked', () => {
  it('refuses a receipt issued after the key expired, at every truthful-read count', () => {
    const envelope = envelopeBytes(KID, signingSeed)

    // Non-vacuity: with plain data the expiry is what refuses the receipt.
    const baseline = verify(envelope, store(expiringManifest()))
    expect(baseline.signature).toBe('invalid')
    expect(isOk(baseline)).toBe(false)
    expect(baseline.errors.join(' ')).toContain('outside key validity window')

    for (const truthful of TRUTHFUL_READ_COUNTS) {
      const viaGetter = verify(
        envelope,
        store(withCountingGetter(expiringManifest(), KID, 'valid_to', undefined, truthful)),
      )
      expect(viaGetter.signature, `getter, ${truthful} truthful reads`).toBe('invalid')
      expect(isOk(viaGetter)).toBe(false)

      const viaProxy = verify(
        envelope,
        store(withCountingProxy(expiringManifest(), KID, 'valid_to', undefined, truthful)),
      )
      expect(viaProxy.signature, `proxy, ${truthful} truthful reads`).toBe('invalid')
      expect(isOk(viaProxy)).toBe(false)
      // The Proxy only traps `get`, so the reconstruction reads the real data
      // through the own-property descriptor and the verdict names the real
      // reason. That is the property: the boundary does not merely refuse the
      // hostile object, it recovers the truth the object was hiding.
      expect(viaProxy.errors.join(' '), `proxy, ${truthful} truthful reads`).toContain(
        'outside key validity window',
      )
    }
  })

  it('keeps a compromised key dead, at every truthful-read count', () => {
    const envelope = envelopeBytes(COMPROMISED_KID, compromisedSeed)

    const baseline = verify(envelope, store(compromisedSignerManifest()))
    expect(baseline.signature).toBe('invalid')
    expect(isOk(baseline)).toBe(false)
    expect(baseline.errors.join(' ')).toContain('is compromised')

    for (const truthful of TRUTHFUL_READ_COUNTS) {
      const viaProxy = verify(
        envelope,
        store(
          withCountingProxy(compromisedSignerManifest(), COMPROMISED_KID, 'status', 'active', truthful),
        ),
      )
      expect(viaProxy.signature, `proxy, ${truthful} truthful reads`).toBe('invalid')
      expect(isOk(viaProxy)).toBe(false)
      expect(viaProxy.errors.join(' '), `proxy, ${truthful} truthful reads`).toContain(
        'is compromised',
      )

      const viaGetter = verify(
        envelope,
        store(
          withCountingGetter(compromisedSignerManifest(), COMPROMISED_KID, 'status', 'active', truthful),
        ),
      )
      expect(viaGetter.signature, `getter, ${truthful} truthful reads`).toBe('invalid')
      expect(isOk(viaGetter)).toBe(false)
    }
  })

  it('an accessor is not data: the manifest it defines cannot authenticate', () => {
    // The rule `ownDataCopy` already applies to the evidence rails — "an
    // element defined as a getter is not data and is not admitted" — now
    // reaches the trust store. The member disappears from the reconstruction,
    // the canonical form changes, and the manifest's own signature refuses it.
    // Fail-closed, and deliberately: there is no way to tell a lazy accessor
    // from a hostile one.
    const manifest = withCountingGetter(expiringManifest(), KID, 'valid_to', undefined, 99)
    const result = verify(envelopeBytes(KID, signingSeed), store(manifest))
    expect(result.signature).toBe('invalid')
    // After F1 the accessor is REFUSED at the boundary rather than dropped and
    // caught downstream by the broken signature. The named reason moved, and
    // the new one is the honest one: the manifest was not inconsistent, it was
    // unreadable.
    expect(result.errors.join(' ')).toContain('could not be materialized')
  })

  it('a String object cannot pass for the primitive it wraps', () => {
    // `===` between primitives is not overridable in JS, so the Python
    // `__eq__` trick has no twin here: a wrapper object simply fails every
    // comparison. Recorded because "no twin" is a MEASURED result, not an
    // assumption — and because the wrapper still changes the canonical form.
    const manifest = compromisedSignerManifest()
    const entry = (manifest['keys'] as JsonObject[])[entryIndex(manifest, COMPROMISED_KID)]!
    ;(entry as Record<string, unknown>)['status'] = new String('compromised')
    const result = verify(envelopeBytes(COMPROMISED_KID, compromisedSeed), store(manifest))
    expect(result.signature).toBe('invalid')
    expect(isOk(result)).toBe(false)
  })

  it('materializes into values loadsStrict produced, and nothing else', () => {
    const manifest = withCountingProxy(compromisedSignerManifest(), COMPROMISED_KID, 'status', 'active', 0)
    const materialized = materializeTrustStore(store(manifest))
    expect(materialized).not.toBeNull()

    const entries = materialized!.manifests[ISSUER]!['keys'] as JsonObject[]
    const entry = entries[entries.findIndex((e) => e['kid'] === COMPROMISED_KID)]!
    // Own data, not the trap's answer, and a plain object rather than a Proxy.
    expect(entry['status']).toBe('compromised')
    expect(Object.getPrototypeOf(entry)).toBe(null)

    const seen = new Set<string>()
    const walk = (value: unknown): void => {
      if (value === null) { seen.add('null'); return }
      if (Array.isArray(value)) { seen.add('array'); value.forEach(walk); return }
      const t = typeof value
      seen.add(t)
      if (t === 'object') for (const key of Object.keys(value as object)) walk((value as JsonObject)[key])
    }
    walk(materialized!.manifests)
    expect([...seen].sort()).toEqual(['array', 'bigint', 'null', 'object', 'string'])
  })

  it('refuses trust material that is not expressible as data', () => {
    // NOT a float: a JS number is caught one step earlier by
    // `assertCanonParsed`, which throws on purpose because a JSON.parse'd
    // trust store is a programming error and deserves the loud failure. The
    // value that reaches the boundary is the one that guard does not walk —
    // a function is what an accessor-heavy ORM wrapper eventually hands over.
    const unreadable = compromisedSignerManifest()
    ;(unreadable as Record<string, unknown>)['issued_at'] = () => VALID_FROM
    expect(materializeKeyManifest(unreadable)).toBeNull()

    const result = verify(envelopeBytes(KID, signingSeed), store(unreadable))
    expect(result.signature).toBe('invalid')
    expect(isOk(result)).toBe(false)
    expect(result.errors.join(' ')).toContain('could not be materialized')
  })

  it('a store member that refuses to answer yields a verdict, in both cores', () => {
    // The divergence this used to pin is CLOSED (F5). `assertCanonParsed`
    // still runs before the boundary — deliberately, so a JSON.parse'd store
    // stays a loud caller-contract failure — but only that one contract
    // violation throws now; every other failure raised while reading the
    // caller's members becomes the same verdict Python returns.
    const hostile = {
      manifests: { [ISSUER]: expiringManifest() },
      provenance: { [ISSUER]: 'tls' },
      get chains(): never {
        throw new Error('the database is gone')
      },
    } as unknown as TrustStore
    // F5 is closed: this used to propagate out of `verify()` while the Python
    // twin returned a verdict for the same store. Now both cores answer with a
    // verdict, and only the JSON.parse contract violation still throws.
    const thrower = verify(envelopeBytes(KID, signingSeed), hostile)
    expect(thrower.signature).toBe('invalid')
    expect(thrower.errors.join(' ')).toContain('could not be materialized')

    // A member the pre-boundary guard does NOT read reaches the boundary and
    // becomes a verdict, which is the Python shape.
    const lateHostile = {
      manifests: { [ISSUER]: expiringManifest() },
      provenance: { [ISSUER]: 'tls' },
      get artifact_manifests(): never {
        throw new Error('the database is gone')
      },
    } as unknown as TrustStore
    const result = verify(envelopeBytes(KID, signingSeed), lateHostile)
    expect(result.signature).toBe('invalid')
    expect(result.errors.join(' ')).toContain('could not be materialized')
  })

  it('leaves a well-formed store and its verdict untouched', () => {
    const live = signManifest([keyEntry(KID, signingPub, 'active', null)], KID, signingSeed)
    const supplied = store(live)
    const result = verify(envelopeBytes(KID, signingSeed), supplied)
    expect(result.signature).toBe('valid')
    expect(result.trust).toBe('verified')
    expect(isOk(result)).toBe(true)

    const materialized = materializeTrustStore(supplied)
    expect(materialized).not.toBeNull()
    // Compared as CANONICAL FORM, not as JSON.stringify output: the
    // reconstruction comes back with members in canonical order, and the
    // property that matters is that not one byte of the data changed.
    expect(dumps(materialized!.manifests as unknown as JsonObject)).toBe(
      dumps(supplied.manifests as unknown as JsonObject),
    )
    // Optional members stay ABSENT rather than being invented as empty maps.
    expect('chains' in (materialized as object)).toBe(false)
  })
})

describe('F1: an unreadable member is refused, never deleted', () => {
  // The copy reads what a container STORES. A container that stores nothing
  // and answers from somewhere else is not neutralized by that copy, it is
  // EMPTIED — and for an OPTIONAL member emptiness is the direction that SKIPS
  // the check, because `resolveKeyStatus` calls a key compromised only when
  // some held manifest says so. Measured against 98f9d04: a getter-, Proxy- or
  // Map-valued `chains` made the member come back `{}` and a receipt signed by
  // a key a chain member marks `compromised` went from ok=false to ok=true.
  const v1 = () => signManifest([keyEntry(KID, signingPub, 'compromised', null)], KID, signingSeed)
  const v2 = () => signManifest([keyEntry(KID, signingPub, 'active', null)], KID, signingSeed)
  const base = () => ({ manifests: { [ISSUER]: v2() }, provenance: { [ISSUER]: 'tls' } })

  it('refuses a chain it cannot read, rather than deleting it', () => {
    const envelope = envelopeBytes(KID, signingSeed)

    // Non-vacuity: as plain data the chain kills the receipt.
    const plain = verify(envelope, {
      ...base(),
      chains: { [ISSUER]: [v1(), v2()] },
    } as TrustStore)
    expect(isOk(plain)).toBe(false)
    expect(plain.errors.join(' ')).toContain('is compromised')

    const viaGetter: Record<string, unknown> = {}
    Object.defineProperty(viaGetter, ISSUER, {
      get: () => [v1(), v2()],
      enumerable: true,
      configurable: true,
    })
    const byGetter = verify(envelope, { ...base(), chains: viaGetter } as unknown as TrustStore)
    expect(isOk(byGetter), 'accessor-defined chain deleted instead of refused').toBe(false)
    expect(byGetter.errors.join(' ')).toContain('could not be materialized')

    const byMap = verify(envelope, {
      ...base(),
      chains: new Map([[ISSUER, [v1(), v2()]]]),
    } as unknown as TrustStore)
    expect(isOk(byMap), 'Map-valued chain deleted instead of refused').toBe(false)
    expect(byMap.errors.join(' ')).toContain('could not be materialized')
  })

  it('refuses every container that does not store its own content', () => {
    // The families the mandate named, each measured rather than assumed.
    class Row {
      constructor(public readonly issuer: string) {}
    }
    const cases: Array<[string, unknown]> = [
      ['Map', new Map([[ISSUER, {}]])],
      ['Date', new Date(0)],
      ['Set', new Set([ISSUER])],
      ['class instance', new Row(ISSUER)],
      ['accessor member', Object.defineProperty({}, ISSUER, { get: () => ({}), enumerable: true })],
      [
        'non-enumerable member',
        Object.defineProperty({}, ISSUER, { value: {}, enumerable: false }),
      ],
      ['array with an accessor element', Object.defineProperty([], '0', { get: () => ({}) })],
    ]
    for (const [label, chains] of cases) {
      const result = verify(envelopeBytes(KID, signingSeed), {
        ...base(),
        chains,
      } as unknown as TrustStore)
      expect(isOk(result), `${label} was not refused`).toBe(false)
      expect(result.errors.join(' '), label).toContain('could not be materialized')
    }
  })

  it('KNOWN LIMIT: a Proxy that hides its own keys is read as empty, not refused', () => {
    // MEASURED, and recorded as the limit it is rather than asserted away. A
    // Proxy is indistinguishable from its target through every portable
    // reflective operation: `getPrototypeOf`, `getOwnPropertyNames` and
    // `getOwnPropertyDescriptor` all forward to the trap. A trap that reports
    // NO keys therefore looks exactly like a plain empty object, and the guard
    // above cannot tell them apart.
    //
    // The consequence is the F1 direction and it is NOT closed: a `chains`
    // whose keys are hidden is read as empty, and an empty chain is a rotation
    // history the verifier never walks, so the compromised key survives. This
    // test pins the behaviour so nobody can believe the boundary refuses it,
    // and the published contract has to say what it says: the trust store MUST
    // be plain data — a Proxy facade is out of contract.
    const target = { [ISSUER]: [v1(), v2()] }
    const hidesKeys = new Proxy(target, { ownKeys: () => [] })
    const hidden = verify(envelopeBytes(KID, signingSeed), {
      ...base(),
      chains: hidesKeys,
    } as unknown as TrustStore)
    expect(isOk(hidden), 'if this is now false, the limit has been closed — update the docs').toBe(
      true,
    )

    // A descriptor trap that answers with an empty VALUE for every key is the
    // same family with a different landing: the member materializes to a
    // chain that is not an array, and `verify()` THROWS rather than returning
    // a verdict. Recorded, not asserted away — it is the same divergence F5
    // names, reached from a hostile store instead of a throwing accessor.
    const lyingDescriptor = new Proxy(target, {
      getOwnPropertyDescriptor: () => ({ value: {}, enumerable: true, configurable: true }),
    })
    expect(() =>
      verify(envelopeBytes(KID, signingSeed), {
        ...base(),
        chains: lyingDescriptor,
      } as unknown as TrustStore),
    ).toThrow()

    // What IS closed, and the difference that matters: the same hiding aimed
    // at `manifests` cannot buy a green receipt, because emptying the manifest
    // breaks its own signature.
    const hiddenManifests = verify(envelopeBytes(KID, signingSeed), {
      manifests: new Proxy({ [ISSUER]: v2() }, { ownKeys: () => [] }),
      provenance: { [ISSUER]: 'tls' },
    } as unknown as TrustStore)
    expect(isOk(hiddenManifests)).toBe(false)
  })
})
