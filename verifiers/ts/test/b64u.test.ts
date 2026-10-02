import { describe, it, expect } from 'vitest'
import { b64uDecode, b64uEncode } from '../src/b64u.js'

describe('b64u', () => {
  it('decodes the vector salt to 0x00..0x0f', () => {
    expect([...b64uDecode('AAECAwQFBgcICQoLDA0ODw')]).toEqual([...Array(16).keys()])
  })
  it('round-trips arbitrary bytes without padding', () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => (i * 7) & 0xff)
    const s = b64uEncode(bytes)
    expect(s).not.toContain('=')
    expect([...b64uDecode(s)]).toEqual([...bytes])
  })
  it('uses URL alphabet (- and _), never + or /', () => {
    const s = b64uEncode(Uint8Array.from([0xfb, 0xff, 0xbf]))
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})

// One decode grammar with Python keys.b64u_decode: vector 22's three lenient
// forms, nothing else. atob alone skipped ASCII whitespace (Python did not)
// while Python dropped characters atob rejects.
describe('b64uDecode shared grammar', () => {
  const raw = Uint8Array.from({ length: 64 }, (_, i) => i)
  const s = b64uEncode(raw)
  it.each([
    ['junk inside', s.slice(0, 10) + '!!!!' + s.slice(10)],
    ['spaces inside', s.slice(0, 10) + '    ' + s.slice(10)],
    ['newlines inside', s.slice(0, 10) + '\n\n' + s.slice(10)],
    ['excess padding', s + '===='],
    ['padding mid-string', s.slice(0, 8) + '==' + s.slice(8)],
    ['non-ASCII', s.slice(0, 10) + 'é' + s.slice(10)],
  ])('rejects %s', (_name, input) => {
    expect(() => b64uDecode(input)).toThrow()
  })
  it('keeps the vector-22 leniency', () => {
    expect([...b64uDecode(s + '==')]).toEqual([...raw])
    expect([...b64uDecode(s.replace(/-/g, '+').replace(/_/g, '/'))]).toEqual([...raw])
    expect([...b64uDecode(s.slice(0, -1) + String.fromCharCode(s.charCodeAt(s.length - 1) + 1))]).toEqual([...raw])
  })
})
