// @vitest-environment jsdom
import { describe, it, expect } from 'vitest'
import { renderResult, renderRejection } from '../src/render.js'
import type { VerifyRun } from '../src/run.js'

// `transparency`/`corroboration`/`manifest_freshness` (Stage 2) and
// `grant`/`grant_trust` (Stage 4, v0.2 §18.5) are set to their
// ZERO-behavior-change defaults here — the shape every caller that supplies
// no evidence already gets. They are in these mocks because `VerificationResult`
// requires them and a clean `tsc --noEmit` on `site` is a gate, not because
// render.ts displays them: it renders the five component rows and nothing else.
const okRun: VerifyRun = {
  ok: true,
  result: {
    signature: 'valid', schema: 'valid', revocation: 'unknown',
    binding: 'not_checked', trust: 'unauthenticated_tofu',
    transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
    grant: 'not_checked', grant_trust: 'not_checked',
    warnings: ['key retired example warning'], errors: [],
  },
}
const badRun: VerifyRun = {
  ok: false,
  result: {
    signature: 'invalid', schema: 'not_checked', revocation: 'unknown',
    binding: 'not_checked', trust: 'unauthenticated_tofu',
    transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
    grant: 'not_checked', grant_trust: 'not_checked',
    warnings: [], errors: ['signature: payload does not verify'],
  },
}

describe('renderResult', () => {
  it('renders the five component rows in spec order with tones', () => {
    const el = renderResult('R1', okRun)
    const rows = el.querySelectorAll('.component')
    expect(rows).toHaveLength(5)
    expect(rows[0].textContent).toContain('Signature')
    expect(rows[3].textContent).toContain('Buyer binding')
    expect(rows[4].textContent).toContain('unauthenticated_tofu')
    expect(rows[4].classList.contains('tone-warn')).toBe(true)
  })

  it('shows the verdict and the label', () => {
    const el = renderResult('R1', okRun)
    expect(el.querySelector('.verdict')!.classList.contains('tone-good')).toBe(true)
    expect(el.querySelector('h3')!.textContent).toContain('R1')
    const bad = renderResult('R2', badRun)
    expect(bad.querySelector('.verdict')!.classList.contains('tone-bad')).toBe(true)
  })

  it('lists warnings and errors verbatim', () => {
    const el = renderResult('R1', okRun)
    expect(el.querySelector('.warnings')!.textContent).toContain('key retired example warning')
    const bad = renderResult('R2', badRun)
    expect(bad.querySelector('.errors')!.textContent).toContain('signature: payload does not verify')
  })

  it('exposes the raw result JSON behind a details toggle', () => {
    const el = renderResult('R1', okRun)
    const raw = el.querySelector('details pre')!
    expect(raw.textContent).toContain('"signature"')
    expect(raw.textContent).toContain('"unauthenticated_tofu"')
  })
})

describe('renderRejection', () => {
  it('renders the reason', () => {
    const el = renderRejection('never share a .private.attest')
    expect(el.textContent).toContain('never share')
    expect(el.classList.contains('rejected')).toBe(true)
  })
})
