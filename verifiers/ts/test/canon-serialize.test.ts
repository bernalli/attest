import { describe, it, expect } from 'vitest'
import { loadsStrict, dumps, canonicalBytes, CanonError, MAX_DEPTH } from '../src/canon.js'
import type { JsonValue } from '../src/canon.js'
const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

describe('canonicalBytes / dumps', () => {
  it('sorts object keys by UTF-16 code units and drops whitespace', () => {
    expect(dumps(loadsStrict(enc('{ "b": 1, "a": 2 }')))).toBe('{"a":2,"b":1}')
  })
  it('accepts 2^53-1 but rejects 2^53', () => {
    expect(dumps(loadsStrict(enc('{"n":9007199254740991}')))).toBe('{"n":9007199254740991}')
    expect(() => canonicalBytes(loadsStrict(enc('{"n":9007199254740992}'))))
      .toThrow(/integer out of I-JSON safe range/)
  })
  it('serializes null/booleans and nested arrays without spaces', () => {
    expect(dumps(loadsStrict(enc('{"a":[true,false,null,1]}')))).toBe('{"a":[true,false,null,1]}')
  })
  it('applies the 7 short escapes and \\u00xx for other controls; leaves / unescaped', () => {
    // \t -> \t short escape;  -> ; '/' literal
    const v = loadsStrict(enc('{"s":"a\\tb\\u000b/"}'))
    expect(dumps(v)).toBe('{"s":"a\\tb\\u000b/"}')
  })
  it('preserves NFD bytes verbatim (no NFC)', () => {
    const bytes = canonicalBytes(loadsStrict(enc('{"t":"Cafe\\u0301"}')))
    expect(dec(bytes)).toBe('{"t":"Café"}')
  })
})

// The nesting-depth ceiling is a property of the attest-JCS profile, enforced at
// BOTH ends: a structure deeper than MAX_DEPTH is not representable, exactly like
// a float or an out-of-range integer. Without it a conforming issuer could sign a
// payload no conforming parser will ever accept, and deep or cyclic input from a
// caller would overflow the native stack with a RangeError that is not a CanonError.

const DEPTH_LITERAL = 'maximum nesting depth exceeded'

const nestArrays = (levels: number): JsonValue => {
  let v: JsonValue = 'leaf'
  for (let i = 0; i < levels; i++) v = [v]
  return v
}
const nestObjects = (levels: number): JsonValue => {
  let v: JsonValue = 'leaf'
  for (let i = 0; i < levels; i++) v = { n: v }
  return v
}
const nestMixed = (levels: number): JsonValue => {
  let v: JsonValue = 'leaf'
  for (let i = 0; i < levels; i++) v = i % 2 ? [v] : { n: v }
  return v
}
const SHAPES: Array<[string, (n: number) => JsonValue]> = [
  ['arrays', nestArrays], ['objects', nestObjects], ['mixed', nestMixed],
]

describe('canonicalBytes nesting-depth ceiling', () => {
  for (const [name, build] of SHAPES) {
    // `build(n)` produces exactly n nested containers around a scalar leaf, so
    // n === MAX_DEPTH sits ON the ceiling and n === MAX_DEPTH + 1 is one past.
    it(`accepts ${name} exactly at the ceiling`, () => {
      expect(canonicalBytes(build(MAX_DEPTH))).toBeTruthy()
    })
    it(`rejects ${name} one level past the ceiling`, () => {
      expect(() => canonicalBytes(build(MAX_DEPTH + 1))).toThrow(CanonError)
      expect(() => canonicalBytes(build(MAX_DEPTH + 1))).toThrow(DEPTH_LITERAL)
    })
  }

  it('rejects extreme depth with the profile error, never a RangeError', () => {
    // Built iteratively so the fixture itself cannot blow the stack: the
    // ceiling must fire at 257, far before any native recursion limit.
    let err: unknown
    try { canonicalBytes(nestObjects(100_000)) } catch (e) { err = e }
    expect(err).toBeInstanceOf(CanonError)
    expect(err).not.toBeInstanceOf(RangeError)
    expect((err as Error).message).toContain(DEPTH_LITERAL)
  })

  it('rejects direct and indirect cycles deterministically', () => {
    const direct: any = {}
    direct.self = direct
    const a: any = {}
    const b: any = { a }
    a.b = b
    for (const cyclic of [direct, a]) {
      expect(() => canonicalBytes(cyclic as JsonValue)).toThrow(CanonError)
      expect(() => canonicalBytes(cyclic as JsonValue)).toThrow(DEPTH_LITERAL)
    }
  })

  it('accepts sharing that is not a cycle', () => {
    const shared: JsonValue = { x: [1n, 2n, 3n] }
    expect(canonicalBytes({ a: shared, b: shared, c: [shared, shared] })).toBeTruthy()
  })

  it('emits only what the strict parser accepts, across the boundary', () => {
    // Direction (1) of the profile boundary contract, false before this change.
    for (const [, build] of SHAPES) {
      for (let levels = MAX_DEPTH - 3; levels <= MAX_DEPTH + 3; levels++) {
        let raw: Uint8Array
        try { raw = canonicalBytes(build(levels)) } catch { continue }
        expect(() => loadsStrict(raw)).not.toThrow()
      }
    }
  })
})
