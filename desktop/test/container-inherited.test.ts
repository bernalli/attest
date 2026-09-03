// The offline verifier inherits the canonical container reader, or it does not.
//
// `desktop/src/app.ts` imports `intake` from the site, so the desktop artifact
// carries whatever the site's bundle parser does. That inheritance is the
// reason this file exists: the defect the canonical reader closes reached a
// buyer's own single-file verifier, and a claim of inheritance that nobody
// measures is a claim about an import statement, not about the artifact.
//
// Every refusing leaf of the shared corpus is fed through `intake` exactly as
// the app feeds it, under a `.attest` name.

import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { intake } from '../../site/src/intake.js'

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

// `intake` decides a file is an archive from its first two bytes, so a corpus
// leaf that does not start with the ZIP signature never reaches the container
// reader at all: it is routed to the receipt path and fails there instead. Two
// leaves are in that position by construction — one begins with a stub before
// the archive, the other has its first local header signature altered — and
// they are listed rather than silently filtered, because the routing is a real
// property of the app and not an accident of this test.
const looksLikeAnArchive = (bytes: Uint8Array): boolean =>
  bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b

describe('the desktop verifier inherits the container reader', () => {
  const refusing = leaves.filter((leaf) => {
    const expected = expectationOf(leaf)
    return (
      expected.verdict === 'reject' &&
      !CAP_CODES.has(expected.code ?? '') &&
      looksLikeAnArchive(archiveOf(leaf))
    )
  })

  it('has refusing leaves to inherit', () => {
    expect(refusing.length).toBeGreaterThan(20)
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

  it('routes a file that does not open with the archive signature to the receipt path', () => {
    // Not a refusal by the container reader, and not a receipt either: the file
    // is handed to the verifier, which is where a file that is not an archive
    // belongs. Nothing green comes out of it.
    for (const leaf of ['prefix-honest', 'local-header-signature']) {
      const bytes = archiveOf(leaf)
      expect(looksLikeAnArchive(bytes)).toBe(false)
      const result = intake('library.attest', bytes)
      expect(result.kind).not.toBe('needs-manifest')
      if (result.kind === 'jobs') {
        expect(result.jobs).toHaveLength(1)
        expect(result.jobs[0].trustStore.manifests).toEqual({})
      }
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
