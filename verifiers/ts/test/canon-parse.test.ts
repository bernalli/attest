import { describe, it, expect } from 'vitest'
import {
  loadsStrict, CanonError, dumps, admitValue,
  MAX_ADMISSION_BYTES, VIEW_MEMBER_NESTING, VIEW_ARRAY_ELEMENT_NESTING,
} from '../src/canon.js'
import type { JsonValue } from '../src/canon.js'
import { codePointLength } from '../src/messages.js'
const enc = (s: string) => new TextEncoder().encode(s)

describe('loadsStrict', () => {
  it('rejects duplicate object members', () => {
    expect(() => loadsStrict(enc('{"a":1,"a":2}'))).toThrow(/duplicate object key/)
  })
  it('preserves integers beyond 2^53 as bigint (no rejection at parse)', () => {
    const v = loadsStrict(enc('{"n":9007199254740992}')) as Record<string, bigint>
    expect(v['n']).toBe(9007199254740992n)
  })
  it('rejects floats and NaN/Infinity', () => {
    expect(() => loadsStrict(enc('{"x":1.5}'))).toThrow(/floats are not allowed/)
    expect(() => loadsStrict(enc('{"x":NaN}'))).toThrow()
    expect(() => loadsStrict(enc('{"x":Infinity}'))).toThrow()
  })
  it('rejects lone surrogate via \\u escape', () => {
    expect(() => loadsStrict(enc('{"s":"\\ud800"}'))).toThrow(/lone surrogate/)
  })
  it('rejects invalid UTF-8 bytes', () => {
    expect(() => loadsStrict(Uint8Array.from([0x22, 0xff, 0x22]))).toThrow(/not valid UTF-8/)
  })
  it('rejects truncated JSON', () => {
    expect(() => loadsStrict(enc('{"a":[1,2'))).toThrow(CanonError)
    expect(() => loadsStrict(enc('{"a":[1,2'))).toThrow(/invalid JSON/)
  })
  it('preserves NFD (no NFC normalization)', () => {
    const v = loadsStrict(enc('{"t":"Cafe\\u0301"}')) as Record<string, string>
    expect(v['t']).toBe('Café') // still decomposed, length 5
    expect(v['t'].length).toBe(5)
  })
  it('parses nested arrays/objects and booleans/null', () => {
    const v = loadsStrict(enc('{"a":[true,false,null,1]}')) as any
    expect(v['a']).toEqual([true, false, null, 1n])
  })
  it('rejects pathological deep nesting as CanonError, not native RangeError', () => {
    const deep = '['.repeat(20000) + ']'.repeat(20000)
    expect(() => loadsStrict(enc(deep))).toThrow(CanonError)
    // Assert the concrete instance so a stack-overflow RangeError would fail here.
    let caught: unknown
    try { loadsStrict(enc(deep)) } catch (e) { caught = e }
    expect(caught instanceof CanonError).toBe(true)
  })
  it('parses legitimately deep nesting just under the cap', () => {
    const nested = '['.repeat(100) + ']'.repeat(100)
    expect(() => loadsStrict(enc(nested))).not.toThrow()
  })
  it('rejects a UTF-8 BOM-prefixed envelope (parity with Python loads_strict)', () => {
    const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...enc('{"a":1}')])
    expect(() => loadsStrict(bom)).toThrow()
  })
})

describe('canon: the admission byte ceiling is measured on the UNIT', () => {
  // The probe wrappers exist to put a unit at its real depth in the view. If
  // the ceiling were measured on the probe instead, a unit sitting exactly AT
  // the ceiling would be refused for the POSITION it occupies rather than for
  // its size — two bytes per level — and the same evidence would be admissible
  // as a top-level value and inadmissible as an array element. That difference
  // is observable, and it is the kind an attacker picks.
  function valueOfCanonicalSize(bytes: number): JsonValue {
    const overhead = codePointLength(dumps({ v: '' }))
    return { v: 'a'.repeat(bytes - overhead) }
  }

  it('a unit exactly at the ceiling is admitted at every nesting depth', () => {
    const exact = valueOfCanonicalSize(MAX_ADMISSION_BYTES)
    expect(codePointLength(dumps(exact))).toBe(MAX_ADMISSION_BYTES)

    for (const nesting of [0, VIEW_MEMBER_NESTING, VIEW_ARRAY_ELEMENT_NESTING]) {
      expect(admitValue(exact, nesting).admitted).toBe(true)
    }
  })

  it('a unit one byte over the ceiling is refused at every nesting depth', () => {
    const over = valueOfCanonicalSize(MAX_ADMISSION_BYTES + 1)

    for (const nesting of [0, VIEW_MEMBER_NESTING, VIEW_ARRAY_ELEMENT_NESTING]) {
      expect(admitValue(over, nesting).admitted).toBe(false)
    }
  })
})
