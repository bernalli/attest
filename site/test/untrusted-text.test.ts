import { describe, it, expect } from 'vitest'
import { neutralized, HOSTILE_IN_QUOTES, REPLACEMENT } from '../src/untrusted-text.js'

// One character policy, shared by every surface that shows untrusted text
// inside a quoted boundary (C-86). It grew out of `bundle.ts`'s `quoted()`,
// which learned each of these the hard way: a member name carrying its own
// double quote closed the citation and put 48 characters of the attacker's
// prose in the verifier's voice, and an unterminated RIGHT-TO-LEFT OVERRIDE
// reversed the verifier's own trailing words.
//
// Characters are REPLACED, never dropped: a string that carried one has to be
// visibly not the string on the wire. Dropping would let an attacker compose a
// sentence that reads clean once the removal has happened.
//
// Every hostile character below is written as an escape on purpose. A test
// about invisible characters must not contain any: a literal RLO in this file
// would reorder the source on screen for whoever reads it next.

describe('neutralized', () => {
  const attacks: [name: string, input: string][] = [
    ['the straight quote that closes an in-band citation', 'x" is genuine "'],
    ['the curly quotes explain.ts uses for its own quoting', '\u201Cgenuine\u201D'],
    ['RIGHT-TO-LEFT OVERRIDE, which reverses what follows', 'a\u202Eb'],
    ['zero-width space, which splits a word invisibly', 'ev\u200Bil'],
    ['the BOM, which a genuine diagnostic can also carry', 'a\uFEFFb'],
    ['a C0 control', 'a\u0001b'],
    ['a C1 control', 'a\u009Cb'],
  ]

  it.each(attacks)('replaces %s', (_name, input) => {
    const out = neutralized(input, 60)

    // Pinned against the literal U+FFFD, never against the imported constant:
    // `toContain(REPLACEMENT)` measures the module against its own constant,
    // so it follows it wherever it drifts, and it is vacuously true for every
    // string once that constant is ''.
    expect(out).toContain('\uFFFD')
    // The substitution is 1:1, so nothing was removed. Dropping would let an
    // attacker compose a sentence that reads clean once the removal has
    // happened; a space would falsify a true diagnostic the way the BOM did.
    expect(out.length).toBe(input.length)
    // Nothing hostile survives. The exported matcher is deliberately not
    // global, so test() is stateless and needs no lastIndex bookkeeping.
    expect(HOSTILE_IN_QUOTES.test(out)).toBe(false)
    expect(out).not.toBe(input)
  })

  it('marks with U+FFFD and nothing else', () => {
    // The assertion the per-attack cases structurally cannot make.
    expect(REPLACEMENT).toBe('\uFFFD')
  })

  it('exports a stateless matcher, so no caller can be told a hostile string is clean', () => {
    // A global regex answers true, then false, then true for the same input.
    const hostile = 'a\u202Eb'

    expect(HOSTILE_IN_QUOTES.test(hostile)).toBe(true)
    expect(HOSTILE_IN_QUOTES.test(hostile)).toBe(true)
    expect(HOSTILE_IN_QUOTES.test('\u201C')).toBe(true)
    expect(HOSTILE_IN_QUOTES.global).toBe(false)
  })

  it('neutralizes the whole format-character class, not just the three attacks above', () => {
    // One representative per family, across planes: soft hyphen, Arabic letter
    // mark, Mongolian vowel separator, the zero-width family, the bidi
    // isolates, interlinear annotation, the musical controls and the tag plane.
    const family = [
      '\u00AD', '\u061C', '\u180E', '\u200B', '\u200E', '\u2060', '\u2064',
      '\u2066', '\u2069', '\uFEFF', '\uFFF9', '\u{110BD}', '\u{1D173}', '\u{E0001}', '\u{E0041}',
    ]

    for (const ch of family) expect(neutralized(`a${ch}b`, 60)).toBe('a\uFFFDb')
  })

  it('never cuts an astral character in half at the cap', () => {
    const out = neutralized(`${'a'.repeat(59)}\u{1F600}tail`, 60)

    expect(out).toBe(`${'a'.repeat(59)}\u2026`)
    expect(/[\uD800-\uDFFF]/u.test(out)).toBe(false)
  })

  it('keeps an astral character that fits whole under the cap', () => {
    const out = neutralized(`${'a'.repeat(58)}\u{1F600}tail`, 60)

    expect(out).toBe(`${'a'.repeat(58)}\u{1F600}\u2026`)
    expect(/[\uD800-\uDFFF]/u.test(out)).toBe(false)
  })

  it('leaves a benign string byte-identical', () => {
    // The property that keeps wire strings searchable: an honest diagnostic
    // reads exactly as the library composed it.
    const benign = 'store.example.com/keys/2025-01#ed25519-1'

    expect(neutralized(benign, 60)).toBe(benign)
  })

  it('flattens every run of whitespace to a single space', () => {
    expect(neutralized('a \t b\n\nc', 60)).toBe('a b c')
  })

  it('clips past the cap and says so, and leaves the exact length alone', () => {
    // The cap is anti-flooding, not anti-persuasion: a short hostile sentence
    // fits under it either way, and it is the marking that disarms it.
    expect(neutralized('x'.repeat(61), 60)).toBe(`${'x'.repeat(60)}…`)
    expect(neutralized('x'.repeat(60), 60)).toBe('x'.repeat(60))
  })

  it('returns the empty string unchanged', () => {
    expect(neutralized('', 60)).toBe('')
  })
})
