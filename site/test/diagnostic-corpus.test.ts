// @vitest-environment jsdom
//
// The adversarial suite proves the defence holds against the attacks we
// thought of. This one runs it over every diagnostic the conformance corpus
// actually produces, which is the set we did NOT think of: 150-odd vectors
// through `runVerify`, every warning and every error they emit, each one
// rendered and measured.
//
// It answers two questions the per-case tests cannot. Does the citation
// machinery quietly damage a genuine diagnostic — is the string a reader sees
// still the string the spec writes down? And is there a real diagnostic,
// anywhere in the corpus, that the renderer speaks in its own voice without a
// template covering it?

import { beforeAll, describe, expect, it } from 'vitest'
import type { VerificationResult } from 'attest-verifier'
import { runVerify } from '../src/run.js'
import { renderResult } from '../src/render.js'
import { segmentDiagnostic } from '../src/diagnostic.js'
import { HOSTILE_IN_QUOTES, REPLACEMENT } from '../src/untrusted-text.js'
import * as V from './helpers/vectors.js'

const MAX_DIAG_OPERAND_CHARS = 300

const leaves = V.findLeafDirs().filter(
  (d) => V.chainInput(d) === null && V.quorumInput(d) === null && V.redemptionInput(d) === null,
)

/** Every distinct string the library composes over the whole corpus.
 *  runVerify is wrapped exactly as the page wraps it: a vector whose trusted
 *  config throws must not take the harvest down with it. Harvested in
 *  beforeAll rather than at module scope: 150 verifications belong to the run,
 *  not to collection, where they would be paid before any file starts. */
let diagnostics = new Set<string>()

function harvest(): Set<string> {
  const seen = new Set<string>()
  for (const dir of leaves) {
    try {
      const run = runVerify(
        V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir), V.disclosure(dir),
        {
          transparency: V.transparencyEvidence(dir), logKeys: V.logKeys(dir),
          anchorPolicy: V.anchorPolicy(dir), revocationEvidence: V.revocationEvidence(dir),
          transferView: V.transferView(dir), compromiseView: V.compromiseView(dir),
          witnessPolicy: V.witnessPolicy(dir), grantView: V.grantView(dir),
          authorityView: V.authorityView(dir),
        },
      )
      for (const w of run.result.warnings) seen.add(w)
      for (const e of run.result.errors) seen.add(e)
    } catch {
      // A vector this page cannot run contributes no diagnostic. Counted by
      // the tripwire below, which would catch the harvest collapsing.
    }
  }
  return seen
}

const zeroResult = (over: Partial<VerificationResult>): VerificationResult => ({
  signature: 'valid', schema: 'valid', revocation: 'unknown',
  binding: 'not_checked', trust: 'unauthenticated_tofu',
  transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
  grant: 'not_checked', grant_trust: 'not_checked',
  publisher_authority: 'not_checked', publisher_authority_trust: 'not_checked',
  warnings: [], errors: [],
  ...over,
})

/** The rendered item for one diagnostic, wherever attribution sent it. */
function itemFor(diagnostic: string): HTMLElement {
  const card = renderResult('R', { ok: true, result: zeroResult({ warnings: [diagnostic] }) })
  return card.querySelector('.component-warnings li, .warnings li') as HTMLElement
}

function textOutsideOperands(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement
  for (const q of [...clone.querySelectorAll('.diag-operand')]) q.remove()
  return clone.textContent ?? ''
}

/** An operand the rendering must return unchanged: nothing the character
 * policy replaces, no whitespace the policy collapses, and no clipping. */
const isBenignOperand = (text: string): boolean =>
  !HOSTILE_IN_QUOTES.test(text) &&
  text.length <= MAX_DIAG_OPERAND_CHARS &&
  !/\s\s/.test(text) &&
  !/[^\S ]/.test(text)

const isBenign = (diagnostic: string): boolean => {
  const seg = segmentDiagnostic(diagnostic)
  if (seg.kind === 'token' || seg.kind === 'known-literal') return true
  if (seg.kind === 'opaque') return isBenignOperand(seg.operand)
  return seg.parts.every(
    (part) => part.kind === 'literal' || isBenignOperand(part.text),
  )
}

describe('every diagnostic the corpus really produces', () => {
  beforeAll(() => {
    diagnostics = harvest()
  })

  it('harvests a corpus worth measuring', () => {
    // Without this, a harvest that silently collected nothing would make every
    // property below vacuously true.
    expect(leaves.length).toBeGreaterThanOrEqual(100)
    expect(diagnostics.size).toBeGreaterThanOrEqual(60)
  })

  it('shows a benign diagnostic exactly as the library composed it', () => {
    const damaged = [...diagnostics].filter((d) => isBenign(d) && itemFor(d).textContent !== d)
    expect(damaged).toEqual([])
  })

  it('leaves no format character on the surface a reader sees', () => {
    const leaked = [...diagnostics].filter((d) => /\p{Cf}/u.test(itemFor(d).textContent ?? ''))
    expect(leaked).toEqual([])
  })

  it('marks the diagnostic that genuinely carries one, instead of hiding it', () => {
    // The corpus composes `invalid JSON: unexpected token '<BOM>' at 0`. A
    // format character is replaced, never dropped: a reader must see that the
    // string they are shown is not the string on the wire, and a verifier that
    // silently rewrote the offending character would be lying about what it
    // found.
    const carriers = [...diagnostics].filter((d) => HOSTILE_IN_QUOTES.test(d))
    expect(carriers.length).toBeGreaterThanOrEqual(1)
    for (const d of carriers) expect(itemFor(d).textContent).toContain(REPLACEMENT)
  })

  it('keeps every non-page part inside a structural citation', () => {
    // Measure both sides of C-86 over real inputs. Opaque diagnostics contribute
    // no page-owned text; composed diagnostics contribute exactly their table
    // literals and one q element per operand.
    expect([...diagnostics].some((d) => segmentDiagnostic(d).kind === 'composed')).toBe(true)

    const violations = [...diagnostics].flatMap((diagnostic) => {
      const seg = segmentDiagnostic(diagnostic)
      const item = itemFor(diagnostic)
      const expectedOutside =
        seg.kind === 'token'
          ? seg.code
          : seg.kind === 'known-literal'
            ? seg.text
            : seg.kind === 'composed'
              ? seg.parts.filter((p) => p.kind === 'literal').map((p) => p.text).join('')
              : ''
      const expectedOperandCount =
        seg.kind === 'opaque'
          ? 1
          : seg.kind === 'composed'
            ? seg.parts.filter((p) => p.kind === 'operand').length
            : 0
      const actualOutside = textOutsideOperands(item)
      const actualOperandCount = item.querySelectorAll('q.diag-operand').length

      return actualOutside === expectedOutside &&
        actualOperandCount === expectedOperandCount
        ? []
        : [{
            diagnostic,
            expectedOutside,
            actualOutside,
            expectedOperandCount,
            actualOperandCount,
          }]
    })
    expect(violations).toEqual([])
  })
})
