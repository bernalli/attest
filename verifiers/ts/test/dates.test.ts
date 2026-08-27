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
})
