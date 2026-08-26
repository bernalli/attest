// @vitest-environment jsdom
import { describe, it, expect } from 'vitest'
import type { VerificationResult } from 'attest-verifier'
import { renderResult, renderRejection } from '../src/render.js'
import type { VerifyRun } from '../src/run.js'

// The zero-evidence result: what every caller that supplies nothing already
// gets. Overrides are per-test, so each case says exactly what it is about.
const result = (over: Partial<VerificationResult> = {}): VerificationResult => ({
  signature: 'valid', schema: 'valid', revocation: 'unknown',
  binding: 'not_checked', trust: 'unauthenticated_tofu',
  transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
  grant: 'not_checked', grant_trust: 'not_checked',
  warnings: [], errors: [],
  ...over,
})
const run = (over: Partial<VerificationResult> = {}, ok = true): VerifyRun => ({ ok, result: result(over) })
const texts = (el: HTMLElement, selector: string): string[] =>
  [...el.querySelectorAll(selector)].map((n) => n.textContent ?? '')

describe('renderResult', () => {
  it('renders all ten components, grouped under the three questions', () => {
    const el = renderResult('R1', run())
    expect(texts(el, '.group-question')).toEqual([
      'Is it authentic?',
      'Does it still hold?',
      'Has anyone else seen it?',
    ])
    expect(texts(el, '.component-name')).toEqual([
      'Signature', 'Schema', 'Buyer binding', 'Key trust',
      'Revocation', 'Preservation pledge', 'Pledge signer',
      'Transparency log', 'Independent corroboration', 'Key manifest freshness',
    ])
  })

  // The runtime twin of explain.ts's compile-time check: a component added to
  // VerificationResult that nobody wrote copy for shows up here as a missing
  // row, instead of quietly living on inside the raw JSON as five of them did.
  it('gives every string-valued field of the result a row of its own', () => {
    const r = result()
    const fields = Object.values(r).filter((v) => typeof v === 'string').length
    expect(fields).toBe(10)
    expect(renderResult('R1', { ok: true, result: r }).querySelectorAll('.component')).toHaveLength(fields)
  })

  it('keeps each row’s tone and prints the raw value beside the name', () => {
    const el = renderResult('R1', run({ transparency: 'logged', corroboration: 'logged' }))
    const rows = [...el.querySelectorAll('.component')]
    expect(rows[3].textContent).toContain('unauthenticated_tofu')
    expect(rows[3].classList.contains('tone-warn')).toBe(true)
    expect(rows[7].textContent).toContain('logged')
    expect(rows[7].classList.contains('tone-good')).toBe(true)
    // A pledge nobody offered evidence for is neutral, never a failure.
    expect(rows[5].classList.contains('tone-neutral')).toBe(true)
  })

  it('explains a parametric value with its own argument', () => {
    const el = renderResult('R1', run({ manifest_freshness: 'verified_as_of:41' }))
    const row = [...el.querySelectorAll('.component')].find((r) =>
      r.textContent?.includes('Key manifest freshness'))!
    expect(row.textContent).toContain('41 entries')
    expect(row.textContent).toContain('not seconds')
  })

  it('shows the verdict and the label', () => {
    const el = renderResult('R1', run())
    expect(el.querySelector('.verdict')!.classList.contains('tone-good')).toBe(true)
    expect(el.querySelector('h3')!.textContent).toContain('R1')
    const bad = renderResult('R2', run({ signature: 'invalid', schema: 'not_checked' }, false))
    expect(bad.querySelector('.verdict')!.classList.contains('tone-bad')).toBe(true)
  })

  it('lists errors verbatim', () => {
    const el = renderResult('R2', run({ errors: ['signature: payload does not verify'] }, false))
    expect(el.querySelector('.errors')!.textContent).toContain('signature: payload does not verify')
  })

  it('exposes the raw result JSON behind a details toggle', () => {
    const el = renderResult('R1', run())
    const raw = el.querySelector('details pre')!
    expect(raw.textContent).toContain('"signature"')
    expect(raw.textContent).toContain('"manifest_freshness"')
  })
})

// The half of this page that makes `not_checked` legible. A dozen distinct
// evidence failures collapse into that one value, and until now the token
// that told them apart sat in a flat list with no link to the row it explains.
describe('renderResult — warnings against the row they qualify', () => {
  it('puts an evidence warning inside its own component row, not in a flat list', () => {
    const el = renderResult('R1', run({ warnings: ['transparency_claim_unresolvable'] }))
    const row = [...el.querySelectorAll('.component')].find((r) =>
      r.textContent?.includes('Transparency log'))!
    expect(row.querySelector('.component-warnings')!.textContent).toContain('transparency_claim_unresolvable')
    expect(el.querySelector('.warnings')).toBeNull()
  })

  it('sends a warning that qualifies no single row to the flat list', () => {
    const el = renderResult('R1', run({ warnings: ['license.drm is drm-bound (design vector 18)'] }))
    expect(el.querySelector('.warnings')!.textContent).toContain('drm-bound')
    expect(el.querySelectorAll('.component-warnings')).toHaveLength(0)
    // With nothing attributed, the flat list IS the whole set and must not
    // call itself "other".
    expect(el.querySelector('.warnings h4')!.textContent).toBe('Warnings')
  })

  it('never loses a warning, and never shows one twice', () => {
    const warnings = [
      'transparency_claim_unresolvable',
      'corroboration_requires_rotation_chain',
      'grant_signer_not_publisher',
      'key acme.example/2026a is retired',
      'license.drm is drm-bound (design vector 18)',
    ]
    const el = renderResult('R1', run({ warnings }))
    const shown = [...texts(el, '.component-warnings li'), ...texts(el, '.warnings li')]
    expect(shown.slice().sort()).toEqual(warnings.slice().sort())
    expect(el.querySelector('.warnings h4')!.textContent).toBe('Other warnings')
  })

  it('sends each attributed warning to the right row', () => {
    const el = renderResult('R1', run({
      warnings: [
        'corroboration_requires_rotation_chain',
        'grant_signer_not_publisher',
        'key acme.example/2026a is retired',
        'artifact_manifest_unauthenticated',
      ],
    }))
    const rowFor = (name: string): string =>
      [...el.querySelectorAll('.component')]
        .find((r) => r.querySelector('.component-name')!.textContent === name)!
        .querySelector('.component-warnings')?.textContent ?? ''
    expect(rowFor('Independent corroboration')).toContain('corroboration_requires_rotation_chain')
    expect(rowFor('Pledge signer')).toContain('grant_signer_not_publisher')
    expect(rowFor('Signature')).toContain('is retired')
    expect(rowFor('Key trust')).toContain('artifact_manifest_unauthenticated')
    // and nowhere else
    expect(rowFor('Transparency log')).toBe('')
    expect(rowFor('Preservation pledge')).toBe('')
  })
})

describe('renderRejection', () => {
  it('renders the reason', () => {
    const el = renderRejection('never share a .private.attest')
    expect(el.textContent).toContain('never share')
    expect(el.classList.contains('rejected')).toBe(true)
  })
})
