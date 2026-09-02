import { describe, expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  AUDIT_TOKENS,
  INHERITED_MODULES,
  enumerateCandidates,
  enumerateInheritedCopy,
  readInheritedSources,
} from './helpers/inherited-copy.js'
import { AUDITED_COPY, G1_SENTENCE } from './inherited-copy-audit.js'

/**
 * The executable residue of the inherited-copy audit (plan step 5b).
 *
 * This package writes almost no user-facing copy: it imports the shared catalogue whole
 * and renders every row of it. What it DOES do that the site does not is freeze that
 * copy into a file that is downloaded once and never updated. A sentence the site can
 * correct on its next deploy is, here, permanent — on every copy, to the least
 * technical readership the project has.
 *
 * So the audit is not a paragraph in a document. It is these tests, and they fail the
 * build rather than the reader.
 */

const readme = (): string =>
  readFileSync(fileURLToPath(new URL('../README.md', import.meta.url)), 'utf8')

describe('gate G1 — no inherited sentence promises a fetch no shipped tool performs', () => {
  test('the catalogue this artifact inlines does not contain the sentence', () => {
    const offending = enumerateInheritedCopy().filter((c) => c.text.includes(G1_SENTENCE))
    expect(
      offending.map((c) => `${c.module}.ts: ${c.text}`),
      `Gate G1 is CLOSED: the copy catalogue still tells the reader that "${G1_SENTENCE}". ` +
        'No shipped attest tool performs that fetch, and this row is drawn on EVERY amber ' +
        'verdict — which is the normal verdict of this app. Do not build the artifact: the ' +
        'sentence is corrected at its source in site/, never filtered here.',
    ).toEqual([])
  })

  test('the same check names the sentence when it is present (negative self-test)', () => {
    // The guard above passes today. A guard that has only ever been seen passing is not
    // known to catch anything, so it is pointed at the historical text — the wording
    // that was live in the catalogue before it was corrected upstream — and must name it.
    const historical = [
      {
        module: 'fixture',
        text: `export const X = { text: 'That is trust-on-first-use. The attest CLI ${G1_SENTENCE} for the "verified" level (spec §7.4).' }`,
      },
    ]
    const offending = enumerateCandidates(historical).filter((c) => c.text.includes(G1_SENTENCE))
    expect(offending).toHaveLength(1)
    expect(offending[0]!.text).toContain(G1_SENTENCE)
  })

  test('no audited row reads FALSE', () => {
    // Every FALSE is a blocker of G1's class: it is corrected at its source in site/ by
    // the owner of that surface, never filtered inside this package.
    const bad = AUDITED_COPY.filter((row) => row.verdict === 'FALSE')
    expect(bad.map((r) => `${r.module}.ts: ${r.excerpt}`)).toEqual([])
  })
})

describe('inherited-copy audit — regression guard', () => {
  test('every candidate the catalogue carries today was audited', () => {
    const audited = new Set(AUDITED_COPY.map((r) => r.sha256))
    const unaudited = enumerateInheritedCopy().filter((c) => !audited.has(c.sha256))
    expect(
      unaudited.map((c) => `${c.module}.ts [${c.token}] ${c.sha256}\n    ${c.text}`),
      'A user-facing string that makes a claim of the audited kind was ADDED or REWORDED ' +
        'upstream after this package audited the catalogue. It would be frozen into the ' +
        'artifact unread. Audit it — name the tool it claims about and the command that ' +
        'decides the claim — and record it in desktop/README.md and inherited-copy-audit.ts.',
    ).toEqual([])
  })

  test('no audited row has disappeared from the catalogue', () => {
    const live = new Set(enumerateInheritedCopy().map((c) => c.sha256))
    const stale = AUDITED_COPY.filter((r) => !live.has(r.sha256))
    expect(
      stale.map((r) => `${r.module}.ts ${r.sha256}\n    ${r.excerpt}`),
      'An audited sentence is no longer in the catalogue. The audit table in ' +
        'desktop/README.md is describing copy that no longer exists.',
    ).toEqual([])
  })

  test('the audit covers exactly the modules the artifact inlines', () => {
    expect([...INHERITED_MODULES]).toEqual(
      ['b64u', 'bundle', 'explain', 'intake', 'render', 'run', 'trusted-log'],
    )
    // Every module named in the audit is one of them; a row against a module the
    // artifact does not inline would be auditing something the reader never sees.
    for (const row of AUDITED_COPY) expect(INHERITED_MODULES).toContain(row.module)
  })

  test('the closed token list is the one the plan fixes', () => {
    expect([...AUDIT_TOKENS]).toEqual([
      'can fetch', 'can be', 'can ', 'CLI', 'will ', 'is able', 'supports', 'use the',
      'run ', 'available', 'fetch',
    ])
  })

  test('the enumeration reads the real catalogue, not an empty one', () => {
    // Guards against the whole audit silently becoming vacuous — a path typo, a renamed
    // module, an extractor that stops matching — which would make every assertion above
    // pass over nothing.
    const sources = readInheritedSources()
    expect(sources).toHaveLength(INHERITED_MODULES.length)
    for (const s of sources) expect(s.text.length).toBeGreaterThan(200)
    expect(enumerateInheritedCopy().length).toBeGreaterThan(10)
  })
})

describe('inherited-copy audit — the published table', () => {
  test('README records every audited row with a deciding command', () => {
    const text = readme()
    expect(text).toContain('Inherited copy, audited')
    for (const row of AUDITED_COPY) {
      expect(text, `README is missing the audit row ${row.sha256}`).toContain(row.sha256.slice(0, 12))
      expect(text, `README is missing the verdict for ${row.sha256}`).toContain(row.verdict)
    }
  })

  test('README carries no audit row the audited set does not have', () => {
    const inReadme = [...readme().matchAll(/`([0-9a-f]{12})`/g)].map((m) => m[1]!)
    const audited = new Set(AUDITED_COPY.map((r) => r.sha256.slice(0, 12)))
    expect(inReadme.filter((h) => !audited.has(h))).toEqual([])
  })
})
