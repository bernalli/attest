import { describe, expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { JSDOM } from 'jsdom'

import type { RuleId } from '../tools/shell-policy.mjs'
import { RULE_IDS, RULES, decodeShell, tokenizeShell, validateShell } from '../tools/shell-policy.mjs'
import type { Mutant } from './helpers/shell-mutants.js'
import { artifact, mutant, mutants, plant, sourceShell } from './helpers/shell-mutants.js'

/**
 * The shell policy reads TOKENS, not a tree.
 *
 * That is the whole design, and it is not a preference: parse5 — and therefore jsdom —
 * still implements the pre-relaxation "in select" insertion mode and DROPS a `<meta>`,
 * an `<img>` or an `<a>` written inside a `<select>`, while current engines keep them
 * and act on them. A validator that read the tree would have accepted, inside the real
 * `<select id="binding-type">`, the very meta refresh this artifact was already
 * refusing. The tokens see everything a tree builder is later free to discard, so the
 * check no longer depends on which tree builder is asked.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const POLICY_SOURCE = readFileSync(join(ROOT, 'tools', 'shell-policy.mjs'), 'utf8')

const SELECT_FIXTURE =
  '<select><meta http-equiv="refresh" content="9999;url=x"><img src="x">' +
  '<a href="y">t</a><option>o</option></select>'

const names = (html: string): string[] => tokenizeShell(html).tokens.map((t) => t.name)

describe('the token stream sees what a tree builder is free to throw away', () => {
  test('elements inside a select reach the tokens and never reach jsdom', () => {
    expect(names(SELECT_FIXTURE)).toEqual(
      expect.arrayContaining(['select', 'meta', 'img', 'a', 'option']),
    )

    // The divergence pin. A jsdom that one day implements the select relaxation turns
    // this red, which is the signal to re-read the browser oracle — not a silent change
    // of what the validator is protecting against.
    const tree = new JSDOM(SELECT_FIXTURE).window.document
    expect(tree.querySelectorAll('select meta, select img, select a')).toHaveLength(0)
  })

  test('a template inside a template hides nothing from the tokens', () => {
    const found = names('<template><template><img src="x"></template></template>')
    expect(found.filter((n) => n === 'template')).toHaveLength(2)
    expect(found.filter((n) => n === 'img')).toHaveLength(1)
  })

  test('noscript contents are tokenized, because scripting is off for the tokenizer', () => {
    expect(names('<noscript><img src="x"></noscript>')).toEqual(
      expect.arrayContaining(['noscript', 'img']),
    )
  })

  test('text that only LOOKS like markup produces no token', () => {
    // script and title are raw text and character data: a tag written inside them is
    // text to every engine, and a rule that refused it would refuse the bundle itself.
    expect(names('<script>var s="<img src=x>"</script><title><img></title>')).not.toContain('img')
  })
})

describe('the shipped artifact is the allowlist it is measured against', () => {
  test('its token inventory is exactly the one the policy enumerates', () => {
    const { tokens, parseErrors } = tokenizeShell(artifact().html)
    const counts: Record<string, number> = {}
    for (const token of tokens) {
      const key = `${token.name}[${token.attrs.map((a) => a.name).sort().join(',')}]`
      counts[key] = (counts[key] ?? 0) + 1
    }
    expect(counts).toEqual({
      'html[lang]': 1, 'head[]': 1, 'meta[charset]': 1, 'meta[content,http-equiv]': 1,
      'meta[content,name]': 1, 'title[]': 1, 'script[type]': 1, 'style[]': 1, 'body[]': 1,
      'p[class,id,role]': 1, 'header[]': 1, 'h1[]': 1, 'p[]': 5, 'main[]': 1,
      'section[class]': 1, 'div[aria-disabled,id,role,tabindex]': 1, 'strong[]': 3,
      'span[]': 1, 'input[hidden,id,type]': 2, 'div[hidden,id]': 1, 'button[id,type]': 2,
      'details[class]': 1, 'summary[]': 1, 'label[for]': 3, 'input[id,type]': 2,
      'select[id]': 1, 'option[value]': 2, 'div[id]': 1, 'footer[]': 1, 'em[]': 1,
      'a[href]': 1, 'code[]': 3,
    })
    expect(parseErrors).toEqual([])
  })

  test('the anchor carries its source bytes, not a decoded copy of them', () => {
    const { tokens, html } = tokenizeShell(artifact().html)
    const anchor = tokens.find((t) => t.name === 'a')
    expect(anchor).toBeDefined()
    const at = anchor?.location.attrs?.['href']
    expect(at).toBeDefined()
    expect(html.slice(at?.startOffset ?? 0, at?.endOffset ?? 0)).toBe(
      'href="https://attest-receipts.org/"',
    )
  })
})

describe('input the document could not have been decoded from is refused', () => {
  test('a byte order mark is refused, not silently carried into the tokens', () => {
    const row = mutant(102)
    expect(() => decodeShell(row.bytes)).toThrow(/byte order mark/i)
    const refusals = validateShell(row.bytes, { stage: 'artifact', expectedCsp: row.expectedCsp })
    expect(refusals.map((r) => r.rule)).toEqual(['R-INPUT'])
  })

  test('a byte sequence that is not UTF-8 is refused', () => {
    const row = mutant(103)
    expect(() => decodeShell(row.bytes)).toThrow(/utf-8/i)
    const refusals = validateShell(row.bytes, { stage: 'artifact', expectedCsp: row.expectedCsp })
    expect(refusals.map((r) => r.rule)).toEqual(['R-INPUT'])
  })

  test('the mark is not theoretical: it empties the head of the tree parse5 builds', () => {
    // The reason R-INPUT exists rather than "the tokenizer copes": with the mark in
    // front, jsdom parses the document in quirks mode with an EMPTY head — so every
    // rule about what the head may contain would have had nothing to read.
    const marked = `﻿${artifact().html}`
    const dom = new JSDOM(marked).window.document
    expect(dom.compatMode).toBe('BackCompat')
    expect(dom.head.children.length).toBe(0)
  })
})

describe('a document the parser had to complain about is refused', () => {
  test.each([
    [104, /duplicate-attribute/],
    [105, /unexpected-null-character/],
    [106, /comment/],
  ])('row %i is refused by R-PARSE', (n, code) => {
    const row = mutant(n)
    const refusals = validateShell(row.bytes, { stage: 'artifact', expectedCsp: row.expectedCsp })
    const parse = refusals.filter((r) => r.rule === 'R-PARSE')
    expect(parse.length).toBeGreaterThan(0)
    expect(parse.map((r) => r.detail).join(' ')).toMatch(code)
  })

  test('the clean artifact and the clean source shell are accepted', () => {
    expect(validateShell(Buffer.from(artifact().html, 'utf8'), {
      stage: 'artifact',
      expectedCsp: artifact().csp,
    })).toEqual([])
    expect(validateShell(Buffer.from(sourceShell(), 'utf8'), { stage: 'source' })).toEqual([])
  })
})

describe('the module is what it claims to be', () => {
  test('it tokenizes with scripting off and locations on, and builds no tree of its own', () => {
    expect(POLICY_SOURCE).toContain('scriptingEnabled: false')
    expect(POLICY_SOURCE).toContain('sourceCodeLocationInfo: true')
    expect(POLICY_SOURCE).not.toContain('jsdom')
  })
})

/**
 * The mutation obligations. A rule nobody can watch fail is a rule nobody knows is
 * there: for every construct in the corpus the named rule must refuse it, and removing
 * that rule must let it through. The second half is the one that catches a test which
 * passes for a reason other than the one it claims.
 */
describe('every rule is load-bearing, and every mutant names the rule that refuses it', () => {
  const implemented = new Set<RuleId>(RULE_IDS)
  const opts = (m: Mutant) => ({ stage: m.stage, expectedCsp: m.expectedCsp })
  const live = (m: Mutant) => m.rules.filter((r) => implemented.has(r))

  test('the corpus is closed and numbered without repetition', () => {
    const numbers = mutants().map((m) => m.n)
    expect(new Set(numbers).size).toBe(numbers.length)
  })

  test.each(mutants().filter((m) => live(m).length > 0).map((m) => [m.n, m.what, m] as const))(
    'row %i (%s) is refused by the rule it names',
    (_n, _what, m) => {
      const refusals = validateShell(m.bytes, opts(m))
      for (const rule of live(m))
        expect(refusals.filter((r) => r.rule === rule), `${rule} did not fire`).not.toHaveLength(0)
    },
  )

  test.each(
    mutants()
      .filter((m) => live(m).length > 0 && !m.rules.includes('R-INPUT'))
      .map((m) => [m.n, m.what, m] as const),
  )('row %i (%s) passes once its rule is removed', (_n, _what, m) => {
    const without = RULES.filter((r) => !m.rules.includes(r.id))
    const refusals = validateShell(m.bytes, opts(m), without)
    for (const rule of live(m)) expect(refusals.filter((r) => r.rule === rule)).toHaveLength(0)
    // Where the named rules are the only ones that can catch the construct, removing
    // them has to let the whole document through. That is the proof they are what
    // stands between this artifact and the construct — not one belt among several.
    if (m.sole && m.rules.every((r) => implemented.has(r))) expect(refusals).toEqual([])
  })

  test('no rule is dead: every implemented rule id is named by some row', () => {
    const named = new Set(mutants().flatMap((m) => m.rules))
    for (const id of RULE_IDS) expect(named, `${id} has no mutant`).toContain(id)
  })
})

describe('what a tree builder drops, the tokens still see', () => {
  test.each(
    mutants()
      .filter((m) => m.treeDrops !== undefined)
      .map((m) => [m.n, m.treeDrops as string, m.markup as string] as const),
  )('row %i: jsdom loses the %s inside the select and keeps it outside', (_n, dropped, markup) => {
    const walk = (root: { children: HTMLCollection }, out: string[]): string[] => {
      for (const el of Array.from(root.children)) {
        out.push(el.localName)
        if (el.localName === 'template') walk((el as HTMLTemplateElement).content, out)
        walk(el, out)
      }
      return out
    }
    const page = (body: string) =>
      `<!doctype html><html lang="en"><head><title>t</title></head><body>${body}</body></html>`
    const inSelect = page(`<select id="b">${markup}<option value="e">e</option></select>`)
    const elsewhere = page(`<div id="z">${markup}</div>`)

    // The tokens see it wherever it is.
    expect(tokenizeShell(inSelect).tokens.map((t) => t.name)).toContain(dropped)

    // The tree does not — and the carve-out proves the walk can find it at all, so an
    // assertion that stopped working would fail instead of passing for ever.
    expect(walk(new JSDOM(inSelect).window.document.body, [])).not.toContain(dropped)
    expect(walk(new JSDOM(elsewhere).window.document.body, [])).toContain(dropped)
  })
})

describe('the rules do not depend on where a construct sits', () => {
  const ELEMENTS = [
    'html', 'head', 'body', 'title', 'header', 'h1', 'main', 'section', 'div', 'strong',
    'span', 'p', 'details', 'summary', 'footer', 'em', 'code', 'meta', 'script', 'style',
    'input', 'button', 'label', 'select', 'option', 'a',
  ]

  test('an event handler is refused on every element the allowlist names', () => {
    const letters = 'abcdefghijklmnopqrstuvwxyz'
    const names = Array.from({ length: 30 }, (_, i) =>
      `on${letters[i % 26]}${letters[(i * 7) % 26]}${letters[(i * 13) % 26]}`)
    for (const element of ELEMENTS)
      for (const attribute of names) {
        const grown = plant(artifact().html, 'BODY', `<${element} ${attribute}="x()">t</${element}>`)
        const refusals = validateShell(Buffer.from(grown.html, 'utf8'), {
          stage: 'artifact',
          expectedCsp: grown.csp,
        })
        expect(
          refusals.filter((r) => r.rule === 'R-ATTRIBUTE'),
          `${element}[${attribute}]`,
        ).not.toHaveLength(0)
      }
  })

  test('every attribute that names a resource is refused on every allowlisted element', () => {
    const attributes = [
      'src', 'srcset', 'poster', 'background', 'action', 'formaction', 'data', 'ping',
      'href', 'style', 'is', 'slot', 'shadowrootmode', 'xlink:href', 'xml:base',
    ]
    for (const element of ELEMENTS)
      for (const attribute of attributes) {
        if (element === 'a' && attribute === 'href') continue
        const grown = plant(
          artifact().html,
          'BODY',
          `<${element} ${attribute}="https://example.invalid/x">t</${element}>`,
        )
        const refusals = validateShell(Buffer.from(grown.html, 'utf8'), {
          stage: 'artifact',
          expectedCsp: grown.csp,
        })
        expect(
          refusals.filter((r) => r.rule === 'R-ATTRIBUTE'),
          `${element}[${attribute}]`,
        ).not.toHaveLength(0)
      }
  })

  test('a global attribute is accepted whatever its value, including none and a long one', () => {
    for (const value of ['', '   ', 'x'.repeat(10_240)]) {
      const grown = plant(artifact().html, 'BODY', `<p id="pad" class="${value}" role="${value}">t</p>`)
      expect(
        validateShell(Buffer.from(grown.html, 'utf8'), {
          stage: 'artifact',
          expectedCsp: grown.csp,
        }),
      ).toEqual([])
    }
  })

  test('every element the corpus refuses is still refused inside the select', () => {
    const rows = mutants().filter(
      (m) => m.rules.includes('R-ELEMENT') && m.markup !== undefined && m.where !== 'ANCHOR',
    )
    expect(rows.length).toBeGreaterThan(10)
    for (const row of rows) {
      const grown = plant(artifact().html, 'SELECT', row.markup as string)
      const refusals = validateShell(Buffer.from(grown.html, 'utf8'), {
        stage: 'artifact',
        expectedCsp: grown.csp,
      })
      expect(
        refusals.filter((r) => r.rule === 'R-ELEMENT'),
        `row ${row.n} inside the select`,
      ).not.toHaveLength(0)
    }
  })
})
