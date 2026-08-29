import { describe, it, expect } from 'vitest'
import { loadsStrict, CanonError } from '../src/canon.js'
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
