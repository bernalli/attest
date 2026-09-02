import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { EXHIBITS } from '../src/exhibits.js'
import { TAMPERS } from '../src/tamper.js'
import { ANCHOR_POLICY } from '../src/trusted-log.js'

// V-I.3's rule, applied to the page's own prose: a sentence that states a
// quantity or an arrangement is a claim, and a claim nothing checks is a
// claim that goes stale in silence. The repository already lost revisions to
// exactly this — numbers written once and never measured again, defended
// since by tools/check_spec_docs.py. That guard covers corpus counts across
// the tree; these cases are local to the page and to the modules that make
// the demonstration, so they are pinned here, beside them.

const HERE = fileURLToPath(new NodeURL('.', import.meta.url))
const INDEX = readFileSync(join(HERE, '..', 'index.html'), 'utf-8')

const NUMBER_WORDS = ['one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten']

// A non-greedy `</section>` would stop at the first NESTED one — the verifier
// section holds `<section id="results">` — and quietly hand back a fragment
// that happens not to contain the sentence under test. Cut on the next
// top-level section instead, which is the only structure index.html promises:
// two spaces of indentation, which the nested `<section id="results">` (four)
// does not have. Matching only sections that carry a class would run straight
// past the several that carry none, and a fragment four sections long is a
// fragment in which "this sentence is not in that section" cannot fail.
const TOP_LEVEL = /\n {2}<section[ >]/g
const from = (start: number): string => {
  TOP_LEVEL.lastIndex = start + 1
  const next = TOP_LEVEL.exec(INDEX)
  const end = next ? next.index : INDEX.indexOf('</main>', start)
  return INDEX.slice(start, end < 0 ? INDEX.length : end)
}

const section = (className: string): string => {
  const start = INDEX.indexOf(`<section class="${className}">`)
  if (start < 0) throw new Error(`no <section class="${className}"> in index.html`)
  return from(start)
}

/** The top-level section a heading belongs to. Several carry no class, and
 *  giving one a class so a test can find it would put the test in the markup. */
const sectionOf = (heading: string): string => {
  const at = INDEX.indexOf(`<h2>${heading}</h2>`)
  if (at < 0) throw new Error(`no <h2>${heading}</h2> in index.html`)
  const start = INDEX.lastIndexOf('\n  <section', at)
  if (start < 0) throw new Error(`<h2>${heading}</h2> is in no top-level section`)
  return from(start)
}

describe('the page states no number the code does not back', () => {
  it('counts the exhibits the way the module does', () => {
    const prose = section('exhibits')
    const word = NUMBER_WORDS[EXHIBITS.length - 1]
    expect(word, 'add a number word if the exhibit count grows past ten').toBeDefined()
    // The sentence "The two receipts below…" is the claim. If a third exhibit
    // is ever added, this fails here instead of misinforming a reader.
    expect(prose).toContain(`The ${word} receipts below`)
    for (const other of NUMBER_WORDS) {
      if (other === word || other === 'one') continue
      expect(prose, `stale count "${other}" in the exhibits section`).not.toContain(
        `The ${other} receipts below`,
      )
    }
  })

  it('states no corpus total at all, so none of them can go stale', () => {
    // The only numbers the page shows are produced by runs that just happened
    // (the tally, the byte offsets). A written-down corpus size would be the
    // exact drift tools/check_spec_docs.py exists to catch, and the page has
    // no reason to carry one.
    expect(INDEX).not.toMatch(/\b\d+\s+(?:leaf|leaves|vectors|conformance vector)/i)
  })
})

describe('the page describes the bench it actually renders', () => {
  it('puts the file-untouched tamper last, as the prose says', () => {
    expect(section('verifier')).toContain('The last leaves the file untouched')
    expect(TAMPERS[TAMPERS.length - 1].id).toBe('drop-manifest')
    // Everything before it edits bytes, which is the other half of the claim.
    expect(TAMPERS.slice(0, -1).map((t) => t.id)).not.toContain('drop-manifest')
  })
})

describe('the page describes the log this deployment actually pins', () => {
  const anchored = (): boolean => Object.keys(ANCHOR_POLICY.pinnedHeaders).length > 0

  it('keeps the “no anchor yet” sentence exactly while that stays true', () => {
    const claims = section('exhibits').includes('has no anchor attached to any checkpoint yet')
    // The moment an anchor is pinned, this sentence becomes false and the
    // exhibits' reason for existing changes with it. Fail then, not later.
    expect(claims).toBe(!anchored())
  })

  it('says the same thing in the register, where the reader meets it first', () => {
    // The register entry names the reason §19's rescue is out of reach for a
    // receipt someone holds today. It used to say this page "cannot evaluate
    // that evidence", which the exhibits below make false: the verifier does
    // evaluate it, against the vectors' own pinned configuration. What is
    // missing is an anchor on THIS deployment, and that is what it now says —
    // so it has to fall with the same fact the sentence above falls with.
    const register = sectionOf('What attest is not')
    expect(register.includes('this deployment pins no anchor')).toBe(!anchored())
    // And the sentence it replaced must not come back: the page evaluates that
    // evidence two sections further down, in front of the reader.
    expect(register).not.toContain('this page cannot evaluate that evidence')
  })
})
