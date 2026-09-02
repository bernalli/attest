import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { EXHIBITS, runExhibit, runExhibits, type ExpectedResult } from '../src/exhibits.js'
import { COMPONENTS } from '../src/explain.js'
import { VECTORS_ROOT } from './helpers/vectors.js'

// The §19 exhibits are the project's OWN conformance vectors, compiled into
// the page. Two things have to stay true or the exhibit stops being evidence
// and becomes a picture of evidence:
//
//   1. the bytes the page verifies are the bytes the corpus ships, and
//   2. the verdict the page produces is the verdict the corpus demands.
//
// Both are checked here against the files on disk, not against a copy.

describe('the exhibits carry the corpus, not a retelling of it', () => {
  it('ships at least the two receipts the page contrasts', () => {
    expect(EXHIBITS.length).toBeGreaterThanOrEqual(2)
    expect(new Set(EXHIBITS.map((e) => e.id)).size).toBe(EXHIBITS.length)
  })

  it.each(EXHIBITS.map((e) => [e.id, e] as const))(
    '%s verifies the exact bytes the corpus holds',
    (_id, exhibit) => {
      const onDisk = new Uint8Array(readFileSync(join(VECTORS_ROOT, exhibit.id, 'envelope.json')))
      expect(Array.from(exhibit.envelopeBytes)).toEqual(Array.from(onDisk))
    },
  )

  it.each(EXHIBITS.map((e) => [e.id, e] as const))(
    '%s reproduces the result its expected.json demands',
    (_id, exhibit) => {
      const outcome = runExhibit(exhibit)
      expect(outcome.mismatches).toEqual([])
      expect(outcome.matches).toBe(true)
    },
  )

  it('states the expected verdict from the fixture, never from a literal here', () => {
    for (const exhibit of EXHIBITS) {
      const fixture = JSON.parse(
        readFileSync(join(VECTORS_ROOT, exhibit.id, 'expected.json'), 'utf-8'),
      )
      expect(exhibit.expected).toEqual(fixture)
    }
  })
})

describe('the contrast the page draws is real', () => {
  const byId = (suffix: string) => EXHIBITS.find((e) => e.id.endsWith(suffix))!

  it('contrasts the same receipt with itself', () => {
    const rescued = byId('a-rescued-anchored-before-cutoff')
    const doomed = byId('b-anchored-after-cutoff-fails')
    expect(rescued).toBeDefined()
    expect(doomed).toBeDefined()
    // Byte-for-byte the same receipt, signed by the same key that its issuer
    // later declared compromised. Only the public timeline differs.
    expect(Array.from(rescued.envelopeBytes)).toEqual(Array.from(doomed.envelopeBytes))
  })

  it('reaches opposite verdicts, each with the §19 reason that produced it', () => {
    const rescued = runExhibit(byId('a-rescued-anchored-before-cutoff'))
    const doomed = runExhibit(byId('b-anchored-after-cutoff-fails'))

    expect(rescued.run.ok).toBe(true)
    expect(rescued.run.result.signature).toBe('valid')
    expect(rescued.run.result.warnings).toContain('compromise_rescue_applied')

    expect(doomed.run.ok).toBe(false)
    expect(doomed.run.result.signature).toBe('invalid')
    expect(doomed.run.result.warnings).toContain('compromise_rescue_receipt_after_cutoff')
  })

  it('gives every exhibit a label and a story a stranger could follow', () => {
    for (const e of EXHIBITS) {
      expect(e.label.length).toBeGreaterThan(0)
      expect(e.story.length).toBeGreaterThan(0)
    }
  })
})

describe('runExhibits reports what it ran, and counts nothing by hand', () => {
  it('runs every exhibit and reports the tally from the runs themselves', () => {
    const outcomes = runExhibits()
    expect(outcomes).toHaveLength(EXHIBITS.length)
    expect(outcomes.filter((o) => o.matches)).toHaveLength(EXHIBITS.length)
  })

  it('would report a mismatch rather than hide one', () => {
    // Feed a doctored expectation and demand that the comparison notices: a
    // self-check that cannot fail proves nothing about the runs it blesses.
    const exhibit = { ...EXHIBITS[0], expected: { ...EXHIBITS[0].expected, signature: 'nonsense' } }
    const outcome = runExhibit(exhibit)
    expect(outcome.matches).toBe(false)
    expect(outcome.mismatches.join(' ')).toContain('signature')
  })
})

// The comparison is what turns a replay into evidence, so its COVERAGE is the
// property to pin — not the two fields today's fixtures happen to state. A
// field the comparison silently skips is a field the page shows a verdict for
// and checks nothing about, and the reader cannot tell the difference.
describe('the comparison covers every field a fixture can state', () => {
  it('compares every component the result contract names', () => {
    // COMPONENTS is explain.ts's list of every string-valued field of
    // VerificationResult, held complete at compile time by that module's own
    // exhaustiveness proof. Deriving the sweep from it means a component added
    // to the contract tomorrow arrives here already checked.
    for (const component of COMPONENTS) {
      const exhibit = { ...EXHIBITS[0], expected: { [component]: 'nonsense' } as ExpectedResult }
      const outcome = runExhibit(exhibit)
      expect(outcome.matches, component).toBe(false)
      expect(outcome.mismatches.join(' '), component).toContain(component)
    }
  })

  it('refuses to bless a fixture field it cannot compare', () => {
    // A corpus leaf may grow a key this page knows nothing about. Ignoring it
    // would report "matches the vector field for field" while a field went
    // unread — the one sentence on this page that must never be loose.
    const expected = { ...EXHIBITS[0].expected, unknown_future_field: 'x' } as ExpectedResult
    const outcome = runExhibit({ ...EXHIBITS[0], expected })
    expect(outcome.matches).toBe(false)
    expect(outcome.mismatches.join(' ')).toContain('unknown_future_field')
  })
})
