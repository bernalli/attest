// @vitest-environment jsdom
// The offline verifier inherits the canonical container reader, or it does not.
//
// `desktop/src/app.ts` imports `intake` from the site, so the desktop artifact
// carries whatever the site's bundle parser does. That inheritance is the
// reason this file exists: the defect the canonical reader closes reached a
// buyer's own single-file verifier, and a claim of inheritance that nobody
// measures is a claim about an import statement, not about the artifact.
//
// The refusing leaves of the shared corpus are fed through `intake` exactly as
// the app feeds it, under a `.attest` name — 58 of the 63 that refuse, and the
// five left out are left out on purpose: they are refused for a cap, which
// depends on the caps the page sets rather than on the reading. Saying "every
// refusing leaf" would be an easier sentence and a false one.
//
// Two more leaves used to be excluded here, and the exclusion was the defect
// rather than a property: `prefix-honest` and `local-header-signature` do not
// open with the archive signature, so a file named `.attest` carrying those
// bytes went to the receipt path and came back with a job while the reference
// importer refused it. The container route is decided by the CONTRACT — the
// extension — so those two are now ordinary members of the list below.

import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { intake } from '../../site/src/intake.js'
import { renderDeclined } from '../../site/src/render.js'

const HERE = fileURLToPath(new NodeURL('.', import.meta.url))
const CORPUS = join(HERE, '..', '..', 'tests', 'container-corpus')

interface Expectation {
  verdict: 'accept' | 'reject'
  code?: string
}

const leaves = readdirSync(CORPUS)
  .filter((name) => statSync(join(CORPUS, name)).isDirectory())
  .sort()

const expectationOf = (leaf: string): Expectation =>
  JSON.parse(readFileSync(join(CORPUS, leaf, 'expected.json'), 'utf8')) as Expectation

const archiveOf = (leaf: string): Uint8Array =>
  new Uint8Array(readFileSync(join(CORPUS, leaf, 'archive.zip')))

// Cap-related refusals depend on the caps the corpus leaf declares, and
// `intake` uses the page's own caps: they are the reader's business, tested
// where the caps are set, not here.
const CAP_CODES = new Set([
  'too-many-entries',
  'declared-member-over-cap',
  'declared-total-over-cap',
  'member-over-cap',
  'total-over-cap',
])

describe('the desktop verifier inherits the container reader', () => {
  const refusing = leaves.filter((leaf) => {
    const expected = expectationOf(leaf)
    return expected.verdict === 'reject' && !CAP_CODES.has(expected.code ?? '')
  })

  it('has refusing leaves to inherit', () => {
    expect(refusing.length).toBeGreaterThan(20)
  })

  it('walks the two leaves that do not open with the archive signature', () => {
    // Named rather than counted: these are the two the routing used to hand to
    // the receipt path, and a filter that quietly dropped them again would
    // leave every other assertion in this file passing.
    expect(refusing).toContain('prefix-honest')
    expect(refusing).toContain('local-header-signature')
  })

  for (const leaf of refusing) {
    it(`refuses ${leaf}`, () => {
      const result = intake('library.attest', archiveOf(leaf))
      expect(result.kind).toBe('rejected')
    })
  }

  it('says why a file with two central directories is refused', () => {
    const result = intake('library.attest', archiveOf('exhibit-D-prefix'))
    expect(result.kind).toBe('rejected')
    if (result.kind === 'rejected') expect(result.reason).toMatch(/canonical form/)
  })

  it('refuses a file that does not open with the archive signature, rather than routing it away', () => {
    // The two leaves the old routing let through. A `.attest` is a container by
    // contract, so a job coming back from one of these is the divergence itself:
    // the reference importer refuses both from their central directory.
    for (const leaf of ['prefix-honest', 'local-header-signature']) {
      const bytes = archiveOf(leaf)
      expect(bytes[0] === 0x50 && bytes[1] === 0x4b).toBe(false)
      const result = intake('library.attest', bytes)
      expect(result.kind).toBe('rejected')
    }
  })

  it('warns rather than parses when a shareable bundle carries the buyer secrets', () => {
    const result = intake('library.attest', archiveOf('exhibit-C-salts-honest'))
    expect(result.kind).toBe('rejected')
    if (result.kind === 'rejected') expect(result.reason).toMatch(/binding salts and keys/)
  })
})

// The trust store is the other half of the inheritance. The app hands whatever
// `intake` built straight to the verifier, so a store that answers for names
// nobody declared answers for them here too — in an artifact that runs from a
// file:// URL, offline, years after the store that issued the receipt is gone.
describe('the desktop verifier inherits the trust store built from own names only', () => {
  const INHERITED = ['toString', 'constructor', 'valueOf', 'hasOwnProperty']

  it('answers nothing for an inherited name when a bundle brought the manifests', () => {
    // The bundle the site ships as its own sample: a real archive, read through
    // the same intake the app uses, so the store under test is the one a person
    // dropping a `.attest` on this artifact actually gets.
    const sample = new Uint8Array(
      readFileSync(join(HERE, '..', '..', 'site', 'public', 'sample', 'demo.attest')),
    )
    const result = intake('library.attest', sample)
    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    expect(Object.keys(result.jobs[0].trustStore.manifests).length).toBeGreaterThan(0)
    for (const name of INHERITED) {
      expect(result.jobs[0].trustStore.manifests[name]).toBeUndefined()
      expect(result.jobs[0].trustStore.provenance[name]).toBeUndefined()
    }
  })

  it('answers nothing for an inherited name when the file brought no manifest', () => {
    const result = intake('receipt.attest.json', new TextEncoder().encode('not json'))
    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    for (const name of INHERITED) {
      expect(result.jobs[0].trustStore.manifests[name]).toBeUndefined()
      expect(result.jobs[0].trustStore.provenance[name]).toBeUndefined()
    }
  })
})

// The register is inherited too, and it is the half of §14.4 that a holder can
// actually see. The offline verifier imports `renderDeclined` from the site by
// the same relative path `desktop/src/app.ts` uses, so this asserts the artifact
// obeys the MUST rather than that an import statement exists: an over-floor
// honest container must not be shown as invalid, corrupt or tampered with,
// because nobody looked at it.
describe('the desktop verifier inherits the register for a container it did not read', () => {
  it('renders the neutral register, never the bad one', () => {
    const article = renderDeclined('bundle declares over 10000 entries — refusing a possible zip bomb')
    const classes = [...article.querySelectorAll('*')].map((node) => node.className)
    expect(classes).toContain('verdict tone-neutral')
    expect(classes).not.toContain('verdict tone-bad')
    expect(article.textContent ?? '').not.toMatch(/invalid|corrupt|tampered/i)
  })
})
