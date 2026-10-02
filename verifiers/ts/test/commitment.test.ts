import { describe, it, expect } from 'vitest'
import { normalizeIdentifier, computeCommitment } from '../src/commitment.js'
import { b64uEncode } from '../src/b64u.js'
const salt = Uint8Array.from({ length: 16 }, (_, i) => i) // 00..0f

describe('commitment', () => {
  it('email: ASCII-only lowercase + NFC + ASCII-ws strip', () => {
    expect(normalizeIdentifier('Buyer@Example.com', 'email')).toBe('buyer@example.com')
    // accented chars already lowercase stay unchanged; only ASCII B,T lowered
    expect(normalizeIdentifier('Büyér+Tag@Example.com', 'email')).toBe('büyér+tag@example.com')
  })
  it('issuer-account: NFC only, case preserved', () => {
    expect(normalizeIdentifier('Zañy_ID-042', 'issuer-account')).toBe('Zañy_ID-042')
  })
  it('does not use String.trim (no wide-unicode strip)', () => {
    expect(normalizeIdentifier(' a@b.com', 'email')).toBe(' a@b.com') // NBSP kept
  })
  it('reproduces the reference commitments (09a/09b/09c)', () => {
    expect(b64uEncode(computeCommitment('Buyer@Example.com', 'email', salt)))
      .toBe('RsKsjOk2kYydyaISKPgHb1tyf8g_k4iGsFCpdMQIL5I')
    expect(b64uEncode(computeCommitment('Büyér+Tag@Example.com', 'email', salt)))
      .toBe('obc4b7CzVQ3d5-Bf7L2umqLdokMQkLMUs62Bdy25Qws')
    expect(b64uEncode(computeCommitment('Zañy_ID-042', 'issuer-account', salt)))
      .toBe('1PfyzQjFrlssflVr4sdbDF7JABB-8DHa0v6JmQBMR4k')
  })
  it('rejects wrong salt length and unknown type', () => {
    expect(() => computeCommitment('a@b.com', 'email', salt.slice(0, 8))).toThrow(/salt/)
    expect(() => computeCommitment('a', 'nope', salt)).toThrow(/identifier_type/)
  })
  it('rejects NUL byte in normalized identifier (Python commitment.py parity)', () => {
    expect(() => normalizeIdentifier('a\x00b@c.com', 'email')).toThrow(/0x00/)
    expect(() => computeCommitment('a\x00b@c.com', 'email', salt)).toThrow(/0x00/)
  })
  it('accepts a plain ASCII space (only NUL is forbidden, matching Python)', () => {
    expect(() => normalizeIdentifier('a b', 'issuer-account')).not.toThrow()
    expect(normalizeIdentifier('a b', 'issuer-account')).toBe('a b')
  })
})

describe('normalizeIdentifier on a long whitespace run', () => {
  it('strips in linear time, not by a backtracking regex', () => {
    const inner = ' '.repeat(200_000)
    const start = performance.now()
    expect(normalizeIdentifier(`a${inner}b`, 'email')).toBe(`a${inner}b`)
    expect(normalizeIdentifier(`${inner}a${inner}`, 'email')).toBe('a')
    expect(performance.now() - start).toBeLessThan(1000)
  })
  it('strips exactly the four ASCII whitespace characters', () => {
    expect(normalizeIdentifier(' \t\r\nA@B.c\n\r\t ', 'email')).toBe('a@b.c')
    expect(normalizeIdentifier(' a@b.c ', 'email')).toBe(' a@b.c ')
  })
})
