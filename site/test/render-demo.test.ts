// @vitest-environment jsdom
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { renderTamper, renderExhibit, renderExhibitTally, renderProbe } from '../src/render.js'
import { REPLACEMENT } from '../src/untrusted-text.js'
import type { VerifyRun } from '../src/run.js'
import type { ExhibitRun } from '../src/exhibits.js'
import type { VerificationResult } from 'attest-verifier'

const result = (over: Partial<VerificationResult> = {}): VerificationResult => ({
  signature: 'valid', schema: 'valid', revocation: 'unknown',
  binding: 'not_checked', trust: 'unauthenticated_tofu',
  transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
  grant: 'not_checked', grant_trust: 'not_checked',
  publisher_authority: 'not_checked', publisher_authority_trust: 'not_checked',
  warnings: [], errors: [], ...over,
})
const run = (over: Partial<VerificationResult> = {}, ok = true): VerifyRun => ({ ok, result: result(over) })

describe('renderTamper says exactly what was done to the file', () => {
  const option = { id: 'title' as const, label: 'Change one letter', what: 'Turns a letter.' }

  it('names the byte, the offset and both characters', () => {
    const el = renderTamper({
      option,
      envelopeBytes: new Uint8Array(),
      trustStore: { manifests: {}, provenance: {} },
      edit: {
        path: 'payload.work.title', offset: 417,
        before: 'E', after: 'F', was: 'Example Game', now: 'Fxample Game',
      },
    })
    const text = el.textContent ?? ''
    expect(text).toContain('417')
    expect(text).toContain('payload.work.title')
    expect(text).toContain('Example Game')
    expect(text).toContain('Fxample Game')
    expect(text).toMatch(/one byte/i)
  })

  it('does not claim a byte changed when none did', () => {
    const el = renderTamper({
      option: { id: 'drop-manifest', label: 'Take the keys away', what: 'Hides the manifest.' },
      envelopeBytes: new Uint8Array(),
      trustStore: { manifests: {}, provenance: {} },
      edit: null,
    })
    const text = el.textContent ?? ''
    expect(text).toMatch(/nothing in the file/i)
    expect(text).not.toMatch(/byte \d+/i)
  })
})

// The bench prints the value it turned, before and after — and that value is
// the TITLE OF THE THING SOMEBODY ELSE SOLD, carried out of a dropped file. It
// is untrusted text on the same footing as a diagnostic operand (C-86, C-91),
// and it reaches the page's own sentence about what the bench just did. The
// old bench predated this module and printed it raw.
describe('the bench treats the value it turned as untrusted text', () => {
  const RLO = '‮'
  const tampered = (was: string, now: string) => ({
    option: { id: 'title' as const, label: 'Change one letter', what: 'Turns a letter.' },
    envelopeBytes: new Uint8Array(),
    trustStore: { manifests: {}, provenance: {} },
    edit: { path: 'payload.work.title', offset: 417, before: 'E', after: 'F', was, now },
  })

  it('leaves no format character in either value', () => {
    const text = renderTamper(tampered(`a${RLO}b`, `a${RLO}c`)).textContent ?? ''
    expect(text).not.toContain(RLO)
    expect(text).toContain(REPLACEMENT)
  })

  it('clips a value long enough to bury the sentence around it', () => {
    const long = 'x'.repeat(5000)
    const text = renderTamper(tampered(long, long)).textContent ?? ''
    expect(text).toContain('…')
    expect(text.length).toBeLessThan(1000)
  })

  it('is byte-identical on an ordinary title, so a reader can still search for it', () => {
    const text = renderTamper(tampered('Example Game', 'Fxample Game')).textContent ?? ''
    expect(text).toContain('Example Game')
    expect(text).toContain('Fxample Game')
  })

  it('carries the half of the defence only CSS can hold', () => {
    // Same residual as .diag-operand: RTL letters are not format characters,
    // so neutralization does not touch them and only the stylesheet stops one
    // reordering the page's own words around the value.
    const css = readFileSync(join(__dirname, '..', 'src', 'styles.css'), 'utf8')
    // The exact selector, brace included: `.tamper-values` is declared above it
    // and a prefix match would read that block instead and pass on its rules.
    const block = css.slice(css.indexOf('.tamper-value {'))
    const rules = block.slice(0, block.indexOf('}'))
    expect(rules).toContain('unicode-bidi: isolate')
    expect(rules).toContain('overflow-wrap: anywhere')
  })
})

describe('renderExhibit shows the fixture it is being held to', () => {
  const outcome = (over: Partial<ExhibitRun> = {}): ExhibitRun => ({
    exhibit: {
      id: '41-compromise-cutoff/a-rescued-anchored-before-cutoff',
      label: 'Published before',
      story: 'A story a stranger can follow.',
      envelopeBytes: new Uint8Array(),
      trustStore: { manifests: {}, provenance: {} },
      options: {},
      expected: { signature: 'valid', ok: true },
    },
    run: run(),
    mismatches: [],
    matches: true,
    ...over,
  })

  it('names the corpus leaf, so the reader can go and read it', () => {
    const text = renderExhibit(outcome()).textContent ?? ''
    expect(text).toContain('41-compromise-cutoff/a-rescued-anchored-before-cutoff')
  })

  it('reports the match as a check that ran, not as a promise', () => {
    const text = renderExhibit(outcome()).textContent ?? ''
    expect(text).toMatch(/matches/i)
    expect(text).toContain('expected.json')
  })

  it('shouts when the run and the fixture disagree', () => {
    const el = renderExhibit(outcome({ matches: false, mismatches: ['signature: expected valid, got invalid'] }))
    expect(el.className).toContain('mismatch')
    expect(el.textContent).toContain('signature: expected valid, got invalid')
  })

  it('renders the full verdict breakdown, not a summary of it', () => {
    const el = renderExhibit(outcome())
    expect(el.querySelector('article.result')).not.toBeNull()
    expect(el.querySelectorAll('.group-question')).toHaveLength(3)
  })
})

describe('renderExhibitTally counts the runs it was given', () => {
  const ok = (id: string): ExhibitRun => ({
    exhibit: {
      id, label: id, story: 's', envelopeBytes: new Uint8Array(),
      trustStore: { manifests: {}, provenance: {} }, options: {}, expected: {},
    },
    run: run(), mismatches: [], matches: true,
  })

  it('states both numbers from the array, never from a literal', () => {
    const text = renderExhibitTally([ok('a'), ok('b'), ok('c')]).textContent ?? ''
    expect(text).toContain('3')
    expect(text).not.toContain('2 of 2')
  })

  it('reports a failure as a failure', () => {
    const bad = { ...ok('b'), matches: false, mismatches: ['ok: expected true, got false'] }
    const el = renderExhibitTally([ok('a'), bad])
    expect(el.className).toContain('tone-bad')
    expect(el.textContent).toContain('1')
  })
})

describe('renderProbe reports the browser, not the author', () => {
  it('shows the block and the browser’s own words', () => {
    const el = renderProbe({
      url: 'https://x.example/k',
      blocked: true,
      observed: true,
      detail: 'blocked-uri https://x.example/k',
    })
    expect(el.className).toContain('tone-good')
    expect(el.textContent).toContain('https://x.example/k')
    expect(el.textContent).toContain('blocked-uri')
  })

  // Three states, not two. The probe URL never resolves, so a request that
  // merely failed proves nothing about confinement — and green is a claim.
  it('does not paint an unobserved failure as observed confinement', () => {
    const el = renderProbe({
      url: 'https://x.example/k',
      blocked: true,
      observed: false,
      detail: 'The request failed before it could carry anything anywhere.',
    })
    expect(el.className).toContain('tone-neutral')
    expect(el.className).not.toContain('tone-good')
    expect(el.textContent).toMatch(/cannot say/i)
    expect(el.textContent).not.toMatch(/refused it under this page/i)
  })

  it('shows a failure to block as a failure, in the loudest tone it has', () => {
    const el = renderProbe({
      url: 'https://x.example/k',
      blocked: false,
      observed: false,
      detail: 'It reached the network.',
    })
    expect(el.className).toContain('tone-bad')
    expect(el.textContent).toContain('reached the network')
  })
})
