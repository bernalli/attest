import { describe, expect, test } from 'vitest'
import type { VerificationResult } from 'attest-verifier'
import { desktopVerdict } from '../src/verdict.js'

type Trust = VerificationResult['trust']

// The whole point of this mapping is that the app must never look more reassuring than
// the result justifies. So the negative cases come first: they are the ones that would
// hurt a buyer, and they are the ones a green-path test would never catch.
//
// Background the assertions depend on: `ok` is the four-gate boolean of the spec —
// signature, schema, revocation, errors. It does NOT include key trust, and it does not
// include buyer binding. An `ok=true` receipt can still be signed by a key nobody has
// ever vouched for, which is exactly the case this app has to be honest about.

const EVERY_TRUST: Trust[] = ['verified', 'unauthenticated_tofu', 'unverified_rotation']

describe('desktopVerdict — what the app is allowed to claim', () => {
  test('trust-on-first-use never reaches the green verdict', () => {
    // The failure this pins: an app that says "verifies" when it means "signed by a key
    // nobody has checked" does more damage than not existing.
    expect(desktopVerdict(true, 'unauthenticated_tofu')).not.toBe('verified')
  })

  test('a broken key history never reaches the green verdict', () => {
    expect(desktopVerdict(true, 'unverified_rotation')).not.toBe('verified')
  })

  test('a broken key history is NOT the same verdict as trust-on-first-use', () => {
    // These two are both cautionary but they are not the same statement. TOFU is an
    // ABSENCE: nobody vouched for the keys. `unverified_rotation` is an ANOMALY: the
    // issuer's own key history does not join up. One headline cannot honestly describe
    // both, so collapsing them is the defect this test exists to prevent.
    expect(desktopVerdict(true, 'unverified_rotation')).not.toBe(
      desktopVerdict(true, 'unauthenticated_tofu'),
    )
  })

  test('a failed verification is red regardless of how trusted the keys were', () => {
    for (const trust of EVERY_TRUST) {
      expect(desktopVerdict(false, trust), `ok=false with trust=${trust}`).toBe('failed')
    }
  })

  test('green is reachable only from an out-of-band verified key', () => {
    expect(desktopVerdict(true, 'verified')).toBe('verified')
    // …and from nothing else: every other trust value on a passing receipt must land
    // somewhere that is not green.
    for (const trust of EVERY_TRUST.filter((t) => t !== 'verified')) {
      expect(desktopVerdict(true, trust), `ok=true with trust=${trust}`).not.toBe('verified')
    }
  })

  test('every trust value maps to a verdict — no undefined falls through', () => {
    for (const trust of EVERY_TRUST) {
      for (const ok of [true, false]) {
        expect(desktopVerdict(ok, trust), `ok=${ok} trust=${trust}`).toBeTruthy()
      }
    }
  })
})
