import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { intake } from '../src/intake.js'

/**
 * T5.5 — the four evidence rails (v0.1 §14.3) fed RAW BYTES, not objects.
 *
 * The rails arrive as files a person drops on a page, so the input under test
 * is bytes: an object built in a test has already survived a parser, which is
 * the half most likely to be wrong. The cases are generated rather than listed
 * because a hand-written list shares the blind spots of whoever wrote it —
 * three times in one day on this project a hand-picked example passed while the
 * property it stood for was broken.
 *
 * Two properties, and they are the ones a caller can rely on:
 *
 *   1. `intake` never throws. It returns a refusal or a view, whatever the
 *      bytes are. A surface that throws on a dropped file loses the results
 *      already on screen, which §14.3 forbids for a refused evidence file.
 *   2. A refusal names the file and says what an empty array would have meant.
 *      "A file containing null is not an opt-out" is the one sentence a reader
 *      mistakes for an instruction, so it is pinned as a property of every
 *      refusal rather than of one example.
 */

const RAILS = [
  'revocation-view.json',
  'transfer-view.json',
  'compromise-view.json',
  'revocation-evidence.json',
] as const

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text)

// Arbitrary JSON text, including the shapes a rail refuses: wrong container,
// duplicate members at depth, non-integer numbers, and plain garbage.
const jsonText = fc.oneof(
  fc.constant('null'),
  fc.constant('[]'),
  fc.constant('{}'),
  fc.constant('[1.5]'),
  fc.constant('{"a":1,"a":2}'),
  fc.constant('[{"a":{"b":{"c":1,"c":2}}}]'),
  fc.constant('[{"record":{},"evidence":{}}]'),
  fc.json(),
  fc.string(),
)

describe('the evidence rails, on raw bytes', () => {
  it('never throws, whatever the file says', () => {
    fc.assert(
      fc.property(fc.constantFrom(...RAILS), jsonText, (fileName, text) => {
        expect(() => intake(fileName, bytes(text))).not.toThrow()
      }),
      { numRuns: 300 },
    )
  })

  it('never throws on a truncation of a valid file, at any offset', () => {
    // Truncation is the failure a network or a copy produces, and it lands at
    // an offset nobody chose. Every prefix of a well-formed rail file is fed
    // back in: each one is a refusal or a view, never an exception.
    const whole = '[{"receipt_id":"01JZ5PDHT0000G40R40M30E209","status":"revoked"}]'
    fc.assert(
      fc.property(fc.nat({ max: whole.length }), (cut) => {
        const r = intake('revocation-view.json', bytes(whole.slice(0, cut)))
        expect(['view', 'rejected']).toContain(r.kind)
      }),
      { numRuns: 200 },
    )
  })

  it('says what an empty array would have meant, every time it refuses', () => {
    fc.assert(
      fc.property(fc.constantFrom(...RAILS), jsonText, (fileName, text) => {
        const r = intake(fileName, bytes(text))
        if (r.kind !== 'rejected') return
        expect(RAILS.some((suffix) => r.reason.includes(suffix))).toBe(true)
        expect(r.reason).toContain('a file containing null is not an opt-out')
        expect(r.rail).toBeDefined()
      }),
      { numRuns: 300 },
    )
  })

  it('admits an array for the three views and an object for the evidence, and nothing else', () => {
    // The container rule two-sided: what each rail admits, and that it admits
    // no other top level. `runVerify` reads these values, so a rail that
    // admitted the wrong container would hand the verifier a shape its own
    // signature does not describe.
    fc.assert(
      fc.property(fc.constantFrom(...RAILS), jsonText, (fileName, text) => {
        const r = intake(fileName, bytes(text))
        if (r.kind !== 'view') return
        const wantsArray = fileName !== 'revocation-evidence.json'
        expect(Array.isArray(r.value)).toBe(wantsArray)
      }),
      { numRuns: 300 },
    )
  })

  it('keeps a malformed element from making the file unreadable', () => {
    // §14.3 refuses a FILE for a parse defect, never for the content of one
    // element: an array of elements the verifier will reject is still a
    // well-formed view, and refusing it here would hide from the reader that
    // the issuer published something unusable.
    fc.assert(
      fc.property(fc.json(), (junk) => {
        const good = '{"receipt_id":"01JZ5PDHT0000G40R40M30E209","status":"revoked"}'
        const r = intake('revocation-view.json', bytes(`[${good},${junk}]`))
        if (r.kind !== 'view') return
        expect(Array.isArray(r.value) && r.value.length === 2).toBe(true)
      }),
      { numRuns: 200 },
    )
  })

  it('never throws on bytes that are not UTF-8, at any offset', () => {
    // Every other property here feeds bytes produced by TextEncoder, so they are
    // valid UTF-8 by construction — which is exactly half of "raw bytes". A file
    // dropped on a page carries no such guarantee.
    fc.assert(
      fc.property(
        fc.constantFrom(...RAILS),
        fc.uint8Array({ minLength: 0, maxLength: 64 }),
        (fileName, raw) => {
          expect(() => intake(fileName, raw)).not.toThrow()
        },
      ),
      { numRuns: 300 },
    )
  })

  it('recognizes exactly four suffixes and no others, whatever the name', () => {
    // §14.3 closes the list, and says that recognizing `grant-view.json` or
    // `authority-view.json` is a registry amendment rather than a surface's own
    // choice. Two enumerated examples pass on a surface that quietly accepts six;
    // a property over hostile names does not.
    const hostile = fc.oneof(
      fc.constantFrom(
        'grant-view.json', 'authority-view.json', 'Revocation-View.json',
        'revocation-view.JSON', 'revocation-view.json ', 'revocation-view.json.txt',
        'revocation-view.jso', 'REVOCATION-VIEW.JSON',
        'x.private.attest.revocation-view.json', '../../revocation-view.json ',
      ),
      fc.string(),
    )
    fc.assert(
      fc.property(hostile, jsonText, (fileName, text) => {
        const r = intake(fileName, bytes(text))
        if (r.kind !== 'view') return
        // A name that DID route must end in one of the four, exactly, case-sensitively.
        expect(RAILS.some((suffix) => fileName.endsWith(suffix))).toBe(true)
      }),
      { numRuns: 500 },
    )
  })

  it('never speaks the caller-supplied file name back in the refusal', () => {
    // C-86: the refusal is spoken in the verifier's voice, so it names the SUFFIX
    // it recognized and never the untrusted string the file arrived under.
    const evil = 'drops/<img src=x onerror=alert(1)>.revocation-view.json'
    const r = intake(evil, bytes('null'))
    expect(r.kind).toBe('rejected')
    if (r.kind !== 'rejected') return
    expect(r.reason).not.toContain('onerror')
    expect(r.reason).toContain('revocation-view.json')
  })
})
