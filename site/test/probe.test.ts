import { describe, it, expect, vi } from 'vitest'
import { probeIsolation, PROBE_URL } from '../src/probe.js'

// The page claims it cannot talk to any other host. A claim like that is
// exactly what V-I.3 forbids leaving as prose, so the page tries it and shows
// what the browser did. The test that matters most is the LAST one: a probe
// that reports a block it did not observe would be worse than no probe.

const noViolations = () => () => () => {}

describe('the isolation probe reports what the browser did', () => {
  it('aims at a host that is not this one and can never resolve', () => {
    expect(PROBE_URL).toMatch(/^https:\/\//)
    expect(PROBE_URL).toContain('.example/')
  })

  it('reports blocked, in the browser’s own words, when the policy fires', async () => {
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: (cb) => {
        cb({
          blockedURI: PROBE_URL,
          violatedDirective: 'connect-src',
          effectiveDirective: 'connect-src',
        } as SecurityPolicyViolationEvent)
        return () => {}
      },
    })
    expect(outcome.blocked).toBe(true)
    expect(outcome.detail).toContain('connect-src')
    expect(outcome.detail).toContain(PROBE_URL)
  })

  it('waits a beat for a violation the browser dispatches after the rejection', async () => {
    // Chromium rejects the fetch first and reports the violation as its own
    // task. Reading it too early leaves the probe showing a bare TypeError,
    // which is indistinguishable from an ordinary network failure and so
    // demonstrates nothing.
    let fire: (() => void) | null = null
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: (cb) => {
        fire = () =>
          cb({
            blockedURI: PROBE_URL,
            violatedDirective: 'connect-src',
            effectiveDirective: 'connect-src',
          } as SecurityPolicyViolationEvent)
        return () => {}
      },
      settle: async () => {
        fire!()
      },
    })
    expect(outcome.detail).toContain('connect-src')
  })

  it('does not wait at all once a violation has already been seen', async () => {
    const settle = vi.fn(() => Promise.resolve())
    await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: (cb) => {
        cb({ blockedURI: PROBE_URL, violatedDirective: 'connect-src' } as SecurityPolicyViolationEvent)
        return () => {}
      },
      settle,
    })
    expect(settle).not.toHaveBeenCalled()
  })

  it('still reports blocked when only the request fails, with the error verbatim', async () => {
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: noViolations(),
    })
    expect(outcome.blocked).toBe(true)
    expect(outcome.detail).toContain('Failed to fetch')
  })

  it('says the request went through when it went through', async () => {
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.resolve({}),
      onViolation: noViolations(),
    })
    expect(outcome.blocked).toBe(false)
    expect(outcome.detail).toMatch(/reached|went through|not blocked/i)
  })

  it('does not claim the policy blocked what the browser never reported', async () => {
    // The probe URL is under a reserved TLD: a bare rejection is what an
    // unreachable host looks like, with or without a Content-Security-Policy.
    // Reporting that as observed confinement would be the fabricated
    // demonstration this whole module exists to rule out.
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: noViolations(),
    })
    expect(outcome.blocked).toBe(true)
    expect(outcome.observed).toBe(false)
  })

  it('marks the outcome observed only when the browser recorded the violation', async () => {
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: (cb) => {
        cb({ blockedURI: PROBE_URL, violatedDirective: 'connect-src' } as SecurityPolicyViolationEvent)
        return () => {}
      },
    })
    expect(outcome.observed).toBe(true)
  })

  it('ignores a violation that belongs to some other request', async () => {
    // A blocked font, or a resource an extension injected, is not this
    // probe's evidence — and printing it under "the browser refused the
    // request" would attribute someone else's report to this fetch.
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: (cb) => {
        cb({
          blockedURI: 'https://fonts.gstatic.example/x.woff2',
          violatedDirective: 'font-src',
        } as SecurityPolicyViolationEvent)
        return () => {}
      },
    })
    expect(outcome.observed).toBe(false)
    expect(outcome.detail).not.toContain('font-src')
  })

  it('accepts the violation when the browser reports only the origin', async () => {
    const outcome = await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: (cb) => {
        cb({
          blockedURI: new URL(PROBE_URL).origin,
          violatedDirective: 'connect-src',
        } as SecurityPolicyViolationEvent)
        return () => {}
      },
    })
    expect(outcome.observed).toBe(true)
  })

  it('takes the listener down again, whichever way the probe went', async () => {
    const off = vi.fn()
    await probeIsolation(PROBE_URL, {
      fetch: () => Promise.resolve({}),
      onViolation: () => off,
    })
    expect(off).toHaveBeenCalledTimes(1)

    const off2 = vi.fn()
    await probeIsolation(PROBE_URL, {
      fetch: () => Promise.reject(new Error('nope')),
      onViolation: () => off2,
    })
    expect(off2).toHaveBeenCalledTimes(1)
  })
})
