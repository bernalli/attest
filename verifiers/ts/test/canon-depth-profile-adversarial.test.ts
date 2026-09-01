import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { CanonError, JsonObject, JsonValue, canonicalBytes, loadsStrict } from '../src/canon.js'
import { TrustStore } from '../src/manifests.js'
import { b64uEncode } from '../src/b64u.js'
import { verify } from '../src/verify.js'

const DEPTH_MESSAGE = 'maximum nesting depth exceeded'
const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/depth#ed25519-1`
const ZERO_B64U_32 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

function objectChain(depth: number, leaf: JsonValue = 'leaf'): JsonObject {
  let value: JsonValue = leaf
  for (let index = 0; index < depth; index++) value = { [`k${depth - index}`]: value }
  return value as JsonObject
}

function arrayChain(depth: number, leaf: JsonValue = 'leaf'): JsonValue[] {
  let value: JsonValue = leaf
  for (let index = 0; index < depth; index++) value = [value]
  return value as JsonValue[]
}

function alternatingChain(depth: number, leaf: JsonValue = 'leaf'): JsonValue {
  let value: JsonValue = leaf
  for (let index = 0; index < depth; index++) {
    value = index % 2 === 0 ? { [`k${index}`]: value } : [value]
  }
  return value
}

const builders: Array<[string, (depth: number) => JsonValue]> = [
  ['objects', objectChain],
  ['arrays', arrayChain],
  ['alternating', alternatingChain],
]

// Containment, not equality: the normative conformance contract is
// `errors_contains` (see docs/spec/vectors/21-canon-strict/d-depth-257), and
// the two parsers do not agree on the surrounding text -- Python's raises the
// bare literal, TypeScript's wraps it as `invalid JSON: <literal> at <pos>`.
// That divergence is pre-existing and lives in the parser. The SERIALIZER, the
// surface this amendment introduces, emits the bare literal in both languages;
// `serializerMessageIsExactlyTheProfileLiteral` below pins that exactly.
function expectProfileDepthError(fn: () => unknown): void {
  let caught: unknown
  try { fn() } catch (e) { caught = e }
  expect(caught).toBeInstanceOf(CanonError)
  expect((caught as Error).message).toContain(DEPTH_MESSAGE)
}

function serializerMessageIsExactlyTheProfileLiteral(fn: () => unknown): void {
  let caught: unknown
  try { fn() } catch (e) { caught = e }
  expect(caught).toBeInstanceOf(CanonError)
  expect((caught as Error).message).toBe(DEPTH_MESSAGE)
}

function xorshift32(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return (state >>> 0) / 0x100000000
  }
}

function scalar(rng: () => number): JsonValue {
  const choice = Math.floor(rng() * 5)
  if (choice === 0) return null
  if (choice === 1) return rng() > 0.5
  if (choice === 2) return BigInt(Math.floor(rng() * 2000) - 1000)
  if (choice === 3) return `line\nquote"slash\\${Math.floor(rng() * 100)}`
  return ''
}

function generatedTree(seed: number): JsonValue {
  const rng = xorshift32(seed)
  let value = scalar(rng)
  const depth = Math.floor(rng() * 271)
  for (let index = 0; index < depth; index++) {
    if (rng() > 0.5) value = [value, scalar(rng)]
    else value = { [`hostile\nkey"${index}`]: value, [`side${index}`]: scalar(rng) }
  }
  return value
}

function basePayloadJson(extraMember: string): string {
  return `{
    "attest_version":"0.1",
    "receipt_id":"01J1V5B4M9Z8QWERTY12345678",
    "issued_at":"2026-07-02T14:30:00Z",
    "supersedes":null,
    "issuer":{"id":"${ISSUER}","display_name":"Example Games Store"},
    "buyer":{
      "commitment":"${ZERO_B64U_32}",
      "identifier_type":"issuer-account",
      "pubkey":null
    },
    "work":{
      "title":"Example Game",
      "publisher":"Example Publisher srl",
      "edition":"Deluxe",
      "identifiers":{"issuer_sku":"EXG-001"},
      "artifact_series":"store.example.com/works/EXG-001",
      "artifacts":[{
        "role":"installer",
        "platform":"windows-x86_64",
        "filename":"example-game-1.0-setup.exe",
        "size_bytes":734003200,
        "sha256":"${'0'.repeat(64)}"
      }]
    },
    "license":{
      "grant":"perpetual",
      "revocability":"none",
      "transferable":false,
      "drm":"drm-free",
      "terms_uri":"https://store.example.com/attest/license-templates/standard-v1",
      "legal_text_sha256":"${'1'.repeat(64)}",
      "jurisdiction_flags":{"eu_usedsoft_asserted":false}
    },
    "survivability":{
      "redownload_right":true,
      "mirror_policy_uri":"https://store.example.com/attest/mirror-policy-v1",
      "mirror_policy_sha256":"${'2'.repeat(64)}",
      "end_of_life":"artifacts-remain-redownloadable",
      "eol_commitment_uri":null,
      "eol_commitment_sha256":null
    },
    ${extraMember}
  }`
}

// The manifest below is now genuinely self-signed (2026-09-01: verify()
// authenticates the trusted manifest before reading any key out of it) --
// the property under test here is about the PAYLOAD's canonicalization
// failure, so the manifest itself must be authentic to let the receipt
// path reach that check instead of being turned away at the gate.
const MANIFEST_SEED = Uint8Array.from({ length: 32 }, () => 9)
const MANIFEST_PUB = b64uEncode(ed25519.getPublicKey(MANIFEST_SEED))

function trustStore(): TrustStore {
  const body: JsonObject = {
    issuer: ISSUER,
    manifest_version: 1n,
    issued_at: '2026-01-01T00:00:00Z',
    keys: [{
      kid: KID,
      pub: MANIFEST_PUB,
      valid_from: '2026-01-01T00:00:00Z',
      valid_to: null,
      status: 'active',
    }],
  }
  const sig = ed25519.sign(canonicalBytes(body), MANIFEST_SEED)
  return {
    manifests: {
      [ISSUER]: { ...body, manifest_signature: { kid: KID, sig: b64uEncode(sig) } },
    },
    provenance: {},
  }
}

describe('attest-JCS depth profile adversarial coverage', () => {
  for (const [shape, builder] of builders) {
    for (const depth of [255, 256]) {
      it(`accepts ${shape} at depth ${depth}`, () => {
        const value = builder(depth)
        const encoded = canonicalBytes(value)

        expect(loadsStrict(encoded)).toEqual(value)
      })
    }

    for (const depth of [257, 258]) {
      it(`rejects ${shape} at depth ${depth} with the exact profile literal`, () => {
        const value = builder(depth)
        const text = JSON.stringify(value)

        expectProfileDepthError(() => loadsStrict(enc(text)))
        expectProfileDepthError(() => canonicalBytes(value))
      })
    }
  }

  it('any successful canonical serialization is parseable by the same profile', () => {
    for (let seed = 1; seed <= 200; seed++) {
      const value = generatedTree(seed)
      let encoded: Uint8Array
      try { encoded = canonicalBytes(value) } catch (e) {
        if (e instanceof CanonError) continue
        throw e
      }
      expect(() => loadsStrict(encoded)).not.toThrow()
    }
  })

  it('rejects a direct cycle as profile depth, not RangeError', () => {
    const value: JsonValue[] = []
    value.push(value)

    expectProfileDepthError(() => canonicalBytes(value))
  })

  it('rejects an indirect cycle as profile depth, not RangeError', () => {
    const first: JsonObject = {}
    const second: JsonObject = { next: first }
    first['next'] = second

    expectProfileDepthError(() => canonicalBytes(first))
  })

  it('allows shared but acyclic substructure', () => {
    const shared = alternatingChain(32)
    const value: JsonObject = { left: shared, right: shared }

    expect(loadsStrict(canonicalBytes(value))).toEqual(value)
  })

  for (const [shape, builder] of builders) {
    it(`rejects extreme iterative ${shape} depth as a profile error`, () => {
      expectProfileDepthError(() => canonicalBytes(builder(20_000)))
    })
  }

  it('keeps the out-of-range integer boundary split between parser and serializer', () => {
    const parsed = loadsStrict(enc('{"n":9007199254740992}')) as JsonObject

    expect(parsed['n']).toBe(9007199254740992n)
    expect(() => canonicalBytes(parsed)).toThrow(/integer out of I-JSON safe range/)
  })

  it('verify rejects an uncanonicalizable parsed payload inside its boundary', () => {
    const payload = basePayloadJson('"extra_out_of_range":9007199254740992')
    const envelope = enc(`{"payload":${payload},"signatures":[{"kid":"${KID}","alg":"Ed25519","sig":""}]}`)

    const result = verify(envelope, trustStore())

    expect(result.signature).toBe('invalid')
    expect(result.errors.some((error) => error.includes('integer out of I-JSON safe range'))).toBe(true)
  })

  it('uses the same exact nesting-depth literal for parser and serializer rejections', () => {
    const tooDeep = arrayChain(257)

    for (const action of [() => loadsStrict(enc(JSON.stringify(tooDeep))), () => canonicalBytes(tooDeep)]) {
      expectProfileDepthError(action)
    }
    expect(dec(enc(DEPTH_MESSAGE))).toBe(DEPTH_MESSAGE)
  })
})

describe('serializer message parity', () => {
  it('the serializer raises the bare profile literal, matching the Python side', () => {
    let deep: any = 'leaf'
    for (let i = 0; i < 300; i++) deep = { n: deep }
    serializerMessageIsExactlyTheProfileLiteral(() => canonicalBytes(deep))
    let deepArr: any = 'leaf'
    for (let i = 0; i < 300; i++) deepArr = [deepArr]
    serializerMessageIsExactlyTheProfileLiteral(() => canonicalBytes(deepArr))
  })
})
