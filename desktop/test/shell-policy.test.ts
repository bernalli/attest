import { describe, expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { JSDOM } from 'jsdom'

import { decodeShell, tokenizeShell, validateShell } from '../tools/shell-policy.mjs'
import { artifact, mutant, sourceShell } from './helpers/shell-mutants.js'

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
