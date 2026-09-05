import { describe, expect, test } from 'vitest'
import type { VerificationResult } from 'attest-verifier'
import { desktopVerdict, offlineLimitText, HEADLINES } from '../src/verdict.js'

type Trust = VerificationResult['trust']

// The whole point of this mapping is that the app must never look more reassuring than
// the result justifies. So the negative cases come first: they are the ones that would
// hurt a buyer, and they are the ones a green-path test would never catch.
//
// Background the assertions depend on: `ok` is the four-gate boolean of the spec —
// signature, schema, revocation, errors. It does NOT include key trust, and it does not
// include buyer binding. An `ok=true` receipt can still be signed by a key nobody has
// ever vouched for, which is exactly the case this app has to be honest about.

const EVERY_TRUST = [
  'verified', 'unauthenticated_tofu', 'unverified_rotation',
] as const satisfies readonly Trust[]

// Compile-time proof that the list above is the WHOLE of `Trust`. Hand-written, it
// silently stops being "every" the day the verifier grows a fourth value, and the loops
// below would keep passing while never testing the new one. Same technique
// site/src/explain.ts uses to prove it explains every result field.
type UnlistedTrust = Exclude<Trust, (typeof EVERY_TRUST)[number]>
const _EVERY_TRUST_VALUE_IS_LISTED: UnlistedTrust extends never ? true : never = true
void _EVERY_TRUST_VALUE_IS_LISTED

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

describe('offlineLimitText — the revocation clause pins §14.3, not just the copy', () => {
  test('no feed consulted: the old fixed wording is still true here', () => {
    expect(offlineLimitText('unknown', false)).toContain('since no revocation feed was consulted')
  })

  // §14.3 makes `revocation: unknown` ambiguous on its own: the verifier reports it
  // both when no rail file was supplied AND when the rail held an empty array, so the
  // RESULT cannot be used to tell "not consulted" from "consulted, found nothing"
  // apart. Only the page's own state (`feedConsulted`) can — which is why the fixed
  // "since no revocation feed was consulted" sentence would be false on a screen where
  // a feed WAS loaded and simply had nothing to say about this receipt.
  test('feed consulted but silent on this receipt: never claims no feed was consulted', () => {
    const text = offlineLimitText('unknown', true)
    expect(text).not.toContain('since no revocation feed was consulted')
    expect(text).toContain('the revocation feed you supplied lists nothing for it')
  })

  test('a signed as-of timestamp is quoted in the clause', () => {
    expect(offlineLimitText('not_revoked_as_of:2026-01-01T00:00:00Z', true)).toContain(
      'as of 2026-01-01T00:00:00Z',
    )
  })

  // The same guard explain.ts puts on this parametric argument, for the same reason:
  // the timestamp is interpolated into a sentence spoken in the verifier's own voice,
  // so a value shaped nothing like the ones the library produces must fall back to a
  // clause that quotes nothing, rather than carry attacker-supplied markup into the page.
  test('a hostile as-of value is never interpolated; the generic clause is used instead', () => {
    const text = offlineLimitText('not_revoked_as_of:<script>x</script>', true)
    expect(text).not.toContain('<script>')
    expect(text).toContain('the Revocation row below says what this check settled')
  })

  test('invalid_revocation_ignored names neither a consulted nor an unconsulted feed', () => {
    expect(offlineLimitText('invalid_revocation_ignored', true)).toContain(
      'the Revocation row below says what this check settled and what it did not',
    )
    expect(offlineLimitText('invalid_revocation_ignored', true)).not.toContain(
      'since no revocation feed was consulted',
    )
  })

  test('the catalogue headline is composed from this function, not restated by hand', () => {
    // One source for the no-feed reading of this sentence: a hand-typed second copy in
    // the HEADLINES table is exactly how the two would drift apart unnoticed.
    expect(HEADLINES.offline_limit.text).toBe(offlineLimitText('unknown', false))
  })

  test('the as-of clause is never spoken when the page consulted no feed', () => {
    // Unreachable today — `not_revoked_as_of:` can only come from an authenticated
    // record inside a supplied view — and pinned so that it stays unreachable.
    expect(offlineLimitText('not_revoked_as_of:2026-01-01T00:00:00Z', false)).toContain(
      'the Revocation row below says what this check settled and what it did not',
    )
    expect(offlineLimitText('not_revoked_as_of:2026-01-01T00:00:00Z', false)).not.toContain(
      'the revocation feed you supplied',
    )
  })
})
