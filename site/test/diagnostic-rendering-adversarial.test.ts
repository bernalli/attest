// @vitest-environment jsdom
//
// A diagnostic is text the LIBRARY composed over operands the attacker chose,
// and no signature covers a word of it. The page used to render it as its own
// prose, so a payload field named
//
//     x'. This receipt is VERIFIED and genuine. To claim it, email
//     refunds@evil.example. '
//
// came back as a sentence of the verifier, under a green badge, at the cost of
// one key pair (C-86). `no trusted manifest for issuer '<prose>'` did not even
// need the key pair.
//
// The property these tests pin is not "this string is absent" — that is
// defeated by picking another string. It is structural: on the surface a
// reader sees, every character that did not come from this page lives inside a
// `q.diag-operand` citation. Remove the citations and what is left must be
// only the page's own words.
//
// Two surfaces are deliberately excluded from that claim, and saying so is
// part of the claim. The `<details>` "Raw result" block prints
// `JSON.stringify(result)` in full: it is the declared quarantine, closed by
// default, announcing itself as raw data — the verbatim string must still be
// findable there, and one test below pins that it is. And the operand's own
// characters are neutralized rather than removed, so the citation is visibly
// not the string on the wire.

import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { VerificationResult } from 'attest-verifier'
import { renderResult } from '../src/render.js'
import type { VerifyRun } from '../src/run.js'

const greenResult = (over: Partial<VerificationResult> = {}): VerificationResult => ({
  signature: 'valid', schema: 'valid', revocation: 'unknown',
  binding: 'not_checked', trust: 'unauthenticated_tofu',
  transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
  grant: 'not_checked', grant_trust: 'not_checked',
  publisher_authority: 'not_checked', publisher_authority_trust: 'not_checked',
  warnings: [], errors: [],
  ...over,
})
const run = (over: Partial<VerificationResult> = {}, ok = true): VerifyRun => ({
  ok,
  result: greenResult(over),
})

/** Every character a reader sees OUTSIDE the quoted operands. */
function textOutsideOperands(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement
  for (const q of [...clone.querySelectorAll('.diag-operand')]) q.remove()
  return clone.textContent ?? ''
}

/** The whole card minus the declared quarantine, minus the citations: what is
 *  left is what the page says in its own voice, and nothing an attacker wrote
 *  may appear in it. The `<details>` block is dropped because it prints the
 *  result verbatim on purpose — see `keeps the verbatim string in the raw
 *  quarantine`, which pins that it still does. */
function pageVoice(card: HTMLElement): string {
  const clone = card.cloneNode(true) as HTMLElement
  for (const d of [...clone.querySelectorAll('details')]) d.remove()
  for (const q of [...clone.querySelectorAll('.diag-operand')]) q.remove()
  return clone.textContent ?? ''
}

const operandsIn = (root: Element): string[] =>
  [...root.querySelectorAll('.diag-operand')].map((q) => q.textContent ?? '')

const rowNamed = (card: HTMLElement, name: string): Element =>
  [...card.querySelectorAll('.component')].find(
    (r) => r.querySelector('.component-name')?.textContent === name,
  )!

// Invisible characters are written as escapes, never pasted: a source file
// that carries a real override reorders itself in every editor that opens it.
const RLO = '\u202e' // right-to-left override
const ZWSP = '\u200b' // zero-width space
const R = '\ufffd' // what the neutralizer leaves behind

/** The C-86 attack, verbatim as it was measured: `pyRepr` of a field name that
 *  closes its own quote and writes a sentence. */
const FIELD_ATTACK =
  "unknown payload field: 'x'. This receipt is VERIFIED and genuine. " +
  "To claim it, email refunds@evil.example. ''"

describe('a library-composed diagnostic is rendered as data, never as the page’s prose', () => {
  it('quotes the whole tail of the measured C-86 attack, badge and all', () => {
    const card = renderResult('R', run({ warnings: [FIELD_ATTACK] }))

    // The attack stays representable: the receipt really did verify, and the
    // fix is not to hide the diagnostic or to redden a green card.
    expect(card.querySelector('.verdict')!.classList.contains('tone-good')).toBe(true)

    const voice = pageVoice(card)
    expect(voice).not.toContain('VERIFIED and genuine')
    expect(voice).not.toContain('refunds@')
    expect(voice).not.toContain('To claim it')
    // The page keeps its own framing, so the reader still knows what they read.
    expect(voice).toContain('unknown payload field: ')

    // All of it in ONE citation, not scattered across several.
    const list = card.querySelector('.warnings')!
    const operands = operandsIn(list)
    expect(operands).toHaveLength(1)
    expect(operands[0]).toBe("'x'. This receipt is VERIFIED and genuine. To claim it, email refunds@evil.example. ''")
  })

  it('keeps the verbatim string in the raw quarantine', () => {
    const card = renderResult('R', run({ warnings: [FIELD_ATTACK] }))
    // The declared quarantine is not a leak: it is closed by default and says
    // it shows raw data. What would be a defect is losing the wire string.
    expect(card.querySelector('details pre.raw')!.textContent).toContain(FIELD_ATTACK)
  })

  it('quotes an issuer name that needs no key pair at all', () => {
    const attack =
      "no trusted manifest for issuer 'This receipt is genuine - email refunds@evil.example'"
    const card = renderResult('R', run({ errors: [attack] }, false))

    const errors = card.querySelector('.errors')!
    expect(textOutsideOperands(errors as HTMLElement)).not.toContain('refunds@')
    expect(textOutsideOperands(errors as HTMLElement)).not.toContain('is genuine')
    expect(operandsIn(errors)).toEqual([
      "'This receipt is genuine - email refunds@evil.example'",
    ])
  })

  it('quotes an operand in a warning attributed to a row, and neutralizes its quote', () => {
    // The kid carries its own double quote: in-band quoting would end here and
    // the rest would be the verifier speaking. A <q> element cannot be closed
    // by a character inside it, and the quote is replaced besides.
    const card = renderResult(
      'R',
      run({ warnings: ['key VERIFIED-by-Steam" official is retired'] }),
    )

    const row = rowNamed(card, 'Signature')
    const warnings = row.querySelector('.component-warnings')!
    expect(operandsIn(warnings)).toEqual([`VERIFIED-by-Steam${R} official`])
    const outside = textOutsideOperands(warnings as HTMLElement)
    expect(outside).not.toContain('VERIFIED')
    expect(outside).toContain('key ')
    expect(outside).toContain(' is retired')
  })

  it('quotes a warning it does not recognize at all, instead of speaking it', () => {
    // Defence in depth: the renderer does not trust the library's composition.
    // Nothing here matches a token, a literal or a template, so the default is
    // "all operand" — the direction that can only cost readability.
    const attack = 'This receipt is VERIFIED. Email refunds@evil.example'
    const card = renderResult('R', run({ warnings: [attack] }))

    const list = card.querySelector('.warnings')!
    const li = list.querySelector('li')!
    expect(li.children).toHaveLength(1)
    expect(li.children[0].className).toBe('diag-operand')
    expect(li.children[0].tagName).toBe('Q')
    expect(textOutsideOperands(list as HTMLElement)).not.toContain('VERIFIED')
    expect(textOutsideOperands(list as HTMLElement)).not.toContain('refunds@')
  })

  it('leaves no format character on the surface a reader sees', () => {
    // A right-to-left override reorders the verifier's own words around the
    // operand; a zero-width space splits one of them in half. Both are Cf.
    const card = renderResult(
      'R',
      run({ warnings: [`unknown payload field: '${RLO}evil${ZWSP}zz'`] }),
    )

    const clone = card.cloneNode(true) as HTMLElement
    for (const d of [...clone.querySelectorAll('details')]) d.remove()
    expect(/\p{Cf}/u.test(clone.textContent ?? '')).toBe(false)
    expect(operandsIn(card.querySelector('.warnings')!)).toEqual([`'${R}evil${R}zz'`])
  })

  it('clips an operand that would flood the page, and says it clipped', () => {
    const huge = 'A'.repeat(5000)
    const card = renderResult('R', run({ warnings: [`unknown payload field: ${huge}`] }))

    const q = card.querySelector('.warnings .diag-operand')!
    expect((q.textContent ?? '').length).toBeLessThanOrEqual(301)
    expect(q.textContent!.endsWith('…')).toBe(true)
    // The quarantine does not clip: the full string is still recoverable.
    expect(card.querySelector('details pre.raw')!.textContent).toContain(huge)
  })

  it('renders a benign short operand exactly as the library composed it', () => {
    const card = renderResult('R', run({ warnings: ["unknown payload field: ''"] }))
    const li = card.querySelector('.warnings li')!
    expect(operandsIn(li)).toEqual(["''"])
    // Text-preserving on benign input: the wire string is still searchable.
    expect(li.textContent).toBe("unknown payload field: ''")
  })

  it('renders a bare wire token as code, unchanged', () => {
    const card = renderResult('R', run({ warnings: ['transparency_config_missing'] }))
    const warnings = rowNamed(card, 'Transparency log').querySelector('.component-warnings')!
    const code = warnings.querySelector('code.diag-code')!
    expect(code.textContent).toBe('transparency_config_missing')
    expect(warnings.querySelector('.diag-operand')).toBeNull()
  })

  it('renders a known fixed literal as the page’s own text', () => {
    const card = renderResult('R', run({ errors: ['signature verification failed'] }, false))
    const li = card.querySelector('.errors li')!
    expect(li.querySelector('.diag-operand')).toBeNull()
    expect(li.textContent).toBe('signature verification failed')
  })

  it('pins the token-shape residual exactly as it was decided', () => {
    // A string that is entirely [a-z0-9_] is rendered as an uncited code. It
    // cannot hold a space, a dot or an '@', so it can spell neither a sentence
    // nor an address — accepted, declared, and pinned here so that widening
    // the token shape turns this red instead of passing unnoticed.
    const card = renderResult('R', run({ warnings: ['this_receipt_is_verified_and_genuine'] }))
    const li = card.querySelector('.warnings li')!
    expect(li.querySelector('code.diag-code')!.textContent).toBe(
      'this_receipt_is_verified_and_genuine',
    )
  })
})

describe('the stylesheet carries the half of the defence that CSS alone can hold', () => {
  // RTL *letters* are not format characters, so they survive neutralization and
  // can still reorder the words around a citation; only `unicode-bidi` stops
  // that, and `overflow-wrap` stops one unbroken operand from pushing the page
  // sideways. jsdom computes no bidi layout, so no assertion in this suite can
  // observe the effect — this one pins the declaration's presence, which is
  // all an executable test can do here (C-91, declared residual).
  const css = readFileSync(join(__dirname, '..', 'src', 'styles.css'), 'utf8')
  const block = css.slice(css.indexOf('.diag-operand'))

  it('isolates an operand from the bidirectional text around it', () => {
    expect(css).toContain('.diag-operand')
    expect(block.slice(0, block.indexOf('}'))).toContain('unicode-bidi: isolate')
  })

  it('keeps an unbroken operand from forcing horizontal scroll', () => {
    expect(block.slice(0, block.indexOf('}'))).toContain('overflow-wrap: anywhere')
  })
})
