import { describe, it, expect } from 'vitest'
import { parseStrictUtc, parseIsoLenient } from '../src/dates.js'

describe('dates', () => {
  it('strict accepts the canonical form only', () => {
    expect(parseStrictUtc('2025-01-01T00:00:00Z')).toBe(Date.UTC(2025, 0, 1, 0, 0, 0))
    expect(parseStrictUtc('2025-01-01T00:00:00.000Z')).toBeNull() // fractional -> fail closed
    expect(parseStrictUtc('2025-01-01T00:00:00+00:00')).toBeNull() // offset -> fail closed
    expect(parseStrictUtc('not-a-date')).toBeNull()
    expect(parseStrictUtc(null)).toBeNull()
  })
  it('strict rejects impossible date/time components (Python strptime parity)', () => {
    expect(parseStrictUtc('2025-13-01T00:00:00Z')).toBeNull() // month 13
    expect(parseStrictUtc('2025-01-32T00:00:00Z')).toBeNull() // day 32
    expect(parseStrictUtc('2025-02-30T00:00:00Z')).toBeNull() // Feb 30
    expect(parseStrictUtc('2025-01-01T24:00:00Z')).toBeNull() // hour 24
    expect(parseStrictUtc('2025-01-01T00:60:00Z')).toBeNull() // minute 60
    expect(parseStrictUtc('2025-01-01T00:00:60Z')).toBeNull() // second 60
    // valid non-midnight time round-trips (exercises H/M/S checks on the happy path)
    expect(parseStrictUtc('2025-06-15T13:45:30Z')).toBe(Date.UTC(2025, 5, 15, 13, 45, 30))
  })
  it('strict handles low four-digit years with Python strptime parity', () => {
    const t = parseStrictUtc('0001-01-01T00:00:00Z')
    expect(t).not.toBeNull()
    expect(new Date(t!).getUTCFullYear()).toBe(1)
    expect(parseStrictUtc('0000-01-01T00:00:00Z')).toBeNull()
  })
  it('lenient parses ISO with offset/fraction', () => {
    expect(parseIsoLenient('2025-08-01T12:00:00Z')).toBe(Date.UTC(2025, 7, 1, 12, 0, 0))
    expect(parseIsoLenient('nope')).toBeNull()
  })
  // The Python owner (`attest.dates.parse_strict_utc`) accepts exactly what
  // these three tests pin. `strptime` alone accepts all of them, so without an
  // explicit guard on that side the two cores disagree on `ok` for the same
  // bytes — which is the split these tests exist to keep closed.
  it('strict rejects every non-ASCII decimal digit in each year position', () => {
    const nd = /^\p{Nd}$/u
    let seen = 0
    for (let cp = 0x80; cp <= 0x10ffff; cp++) {
      const c = String.fromCodePoint(cp)
      if (!nd.test(c)) continue
      seen++
      for (let pos = 0; pos < 4; pos++) {
        const year = '2025'.slice(0, pos) + c + '2025'.slice(pos + 1)
        expect(parseStrictUtc(`${year}-07-02T13:50:00Z`)).toBeNull()
      }
    }
    // Non-vacuity: if the category ever came back empty the loop above would
    // assert nothing at all.
    expect(seen).toBeGreaterThan(600)
  })
  it('strict rejects ASCII spellings Python strptime would accept', () => {
    for (const value of [
      '2025-07-02t13:50:00Z',
      '2025-07-02T13:50:00z',
      '2025-07-02t13:50:00z',
      '2025-7-02T13:50:00Z',
      '2025-07-2T13:50:00Z',
      '2025-07-02T3:50:00Z',
      '2025-07-02T13:5:00Z',
      '2025-07-02T13:50:0Z',
    ]) {
      expect(parseStrictUtc(value)).toBeNull()
    }
  })
  it('strict accepts 0999 like the Python owner', () => {
    const t = parseStrictUtc('0999-01-01T00:00:00Z')
    expect(t).not.toBeNull()
    expect(new Date(t!).getUTCFullYear()).toBe(999)
  })
})
