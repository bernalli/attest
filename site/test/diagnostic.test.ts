import { describe, it, expect } from 'vitest'
import { segmentDiagnostic } from '../src/diagnostic.js'

// Where the page decides which part of a library-composed diagnostic is its own
// voice and which part is somebody else's text (C-86).
//
// The rule is default-deny: a string is framed by the page only when the page
// positively recognizes it, and everything unrecognized is operand in full. A
// missing template therefore costs readability, never safety — which is the
// only direction this trade-off may fail in.
//
// The literals emitted for a recognized template come from the page's own
// table, never sliced out of the input. That is what makes it impossible for an
// attacker's text to be promoted into the verifier's voice: the regex that
// matches is built from the same parts that produce the output.

describe('wire tokens are framing, not operands', () => {
  const tokens = [
    'transparency_config_missing',
    'log_equivocation_detected',
    'evidence_invalid',
    'anchor_note_only',
    'post_horizon_unanchored',
    'witness_independence_not_established',
  ]

  it.each(tokens)('recognizes %s as a token', (token) => {
    expect(segmentDiagnostic(token)).toEqual({ kind: 'token', code: token })
  })

  // Default-deny on the shape: a token cannot spell a sentence, an address or a
  // URL. Each near-miss below is a string an attacker would like framed as the
  // verifier's own vocabulary.
  const nearMisses = [
    'this receipt is verified',
    'Verified',
    'refunds@evil.example',
    'a.b',
    'x-y',
  ]

  it.each(nearMisses)('refuses %s the token shape', (input) => {
    expect(segmentDiagnostic(input).kind).not.toBe('token')
  })
})

describe('known fixed literals are page text', () => {
  it.each(['signature verification failed', 'license.drm is drm-bound (design vector 18)'])(
    'recognizes %s',
    (text) => {
      expect(segmentDiagnostic(text)).toEqual({ kind: 'known-literal', text })
    },
  )
})

describe('a composed diagnostic is split at the template, never at the text', () => {
  it('keeps the C-86 attack entirely inside the operand', () => {
    // The measured attack: one unknown field name buys a sentence next to a
    // green badge. Everything after the page's own prefix is the attacker's.
    const attack =
      "unknown payload field: 'x'. This receipt is VERIFIED and genuine. " +
      "To claim it, email refunds@evil.example. ''"
    const seg = segmentDiagnostic(attack)

    expect(seg.kind).toBe('composed')
    if (seg.kind !== 'composed') return
    expect(seg.parts).toEqual([
      { kind: 'literal', text: 'unknown payload field: ' },
      { kind: 'operand', text: attack.slice('unknown payload field: '.length) },
    ])
  })

  it('keeps the unsigned-path attack entirely inside the operand', () => {
    // Cheaper still: this one fires before any signature check.
    const attack = "no trusted manifest for issuer 'Steam Support — refunds at refunds@evil.example'"
    const seg = segmentDiagnostic(attack)

    expect(seg.kind).toBe('composed')
    if (seg.kind !== 'composed') return
    expect(seg.parts).toEqual([
      { kind: 'literal', text: 'no trusted manifest for issuer ' },
      { kind: 'operand', text: attack.slice('no trusted manifest for issuer '.length) },
    ])
  })

  it('absorbs an operand that impersonates the literal around it', () => {
    // A kid chosen to look like the tail of the template. The captures are
    // greedy, so the impersonation is swallowed rather than promoted.
    const seg = segmentDiagnostic('key x is retired is retired')

    expect(seg).toEqual({
      kind: 'composed',
      parts: [
        { kind: 'literal', text: 'key ' },
        { kind: 'operand', text: 'x is retired' },
        { kind: 'literal', text: ' is retired' },
      ],
    })
  })

  it('splits a two-operand template', () => {
    const seg = segmentDiagnostic(
      'revocation view exceeds 128 records (200 supplied), not evaluated',
    )

    expect(seg.kind).toBe('composed')
    if (seg.kind !== 'composed') return
    expect(seg.parts.filter((p) => p.kind === 'operand').map((p) => p.text)).toEqual(['128', '200'])
  })

  it('leaves a genuine BOM in the operand untouched — neutralizing is the renderer’s job', () => {
    // The corpus really does compose this one. Segmentation must not alter the
    // text: if it neutralized here, the renderer could no longer tell what it
    // was given, and the two responsibilities would blur.
    const seg = segmentDiagnostic("invalid JSON: unexpected token '\uFEFF' at 0")

    expect(seg.kind).toBe('composed')
    if (seg.kind !== 'composed') return
    expect(seg.parts).toEqual([
      { kind: 'literal', text: 'invalid JSON: ' },
      { kind: 'operand', text: "unexpected token '\uFEFF' at 0" },
    ])
  })
})

describe('anything unrecognized is operand in full', () => {
  const opaque = [
    'evidence.checkpoint is required',
    'receipt_id: must be a 26-char ULID',
    '',
    'Your receipt is valid. Email refunds@evil.example to claim it.',
  ]

  it.each(opaque)('treats %s as opaque', (input) => {
    expect(segmentDiagnostic(input)).toEqual({ kind: 'opaque', operand: input })
  })
})

describe('the two properties that make the split safe', () => {
  const composed = [
    "unknown payload field: 'x'. Anything at all.",
    'key kid-1 is retired',
    'revocation view exceeds 1 records (2 supplied), not evaluated',
    "invalid JSON: unexpected token '\uFEFF' at 0",
    'no trusted manifest for issuer prose',
  ]

  it.each(composed)('reassembles %s byte-identically', (input) => {
    const seg = segmentDiagnostic(input)

    expect(seg.kind).toBe('composed')
    if (seg.kind !== 'composed') return
    expect(seg.parts.map((p) => p.text).join('')).toBe(input)
  })

  it.each(composed)('emits only literals the page owns, for %s', (input) => {
    // Every literal in the output must be a fragment the page wrote down, not
    // one cut out of the input. This is the property that keeps an attacker's
    // words out of the verifier's voice.
    const owned = new Set([
      'unknown payload field: ',
      'key ',
      ' is retired',
      'revocation view exceeds ',
      ' records (',
      ' supplied), not evaluated',
      'invalid JSON: ',
      'no trusted manifest for issuer ',
    ])
    const seg = segmentDiagnostic(input)

    expect(seg.kind).toBe('composed')
    if (seg.kind !== 'composed') return
    for (const part of seg.parts) {
      if (part.kind === 'literal') expect(owned).toContain(part.text)
    }
  })
})

describe('a diagnostic that is not a string cannot take the page down', () => {
  // `warnings[]` and `errors[]` arrive from parsed JSON. The library types them
  // as string[], but the page is handed whatever the file contained, and a
  // TypeError raised here would abandon the whole render — leaving the buyer
  // with no verdict at all rather than with one qualified warning. Segmentation
  // is the boundary between library data and page rendering, so the guard
  // belongs here, and the value stays quarantined as an operand.
  const notStrings: [name: string, value: unknown][] = [
    ['a number', 7],
    ['null', null],
    ['undefined', undefined],
    ['an object', { toString: () => 'unknown payload field: x' }],
    ['an array', ['unknown payload field: x']],
  ]

  it.each(notStrings)('renders %s as an opaque operand instead of throwing', (_name, value) => {
    const seg = segmentDiagnostic(value)

    expect(seg.kind).toBe('opaque')
  })

  it('never lets a non-string impersonate page framing through toString', () => {
    // The object above stringifies into a known template. Coercing first and
    // matching afterwards would let it borrow the page's voice.
    const seg = segmentDiagnostic({ toString: () => 'unknown payload field: x' })

    expect(seg.kind).toBe('opaque')
    if (seg.kind !== 'opaque') return
    expect(seg.operand).not.toContain('unknown payload field')
  })
})
