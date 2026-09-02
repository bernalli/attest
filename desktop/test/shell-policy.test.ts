import { describe, expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { URL as NodeURL, fileURLToPath } from 'node:url'
import { JSDOM } from 'jsdom'

import type { RuleId } from '../tools/shell-policy.mjs'
import {
  RULE_IDS,
  RULES,
  classifyUrl,
  decodeShell,
  tokenizeShell,
  validateShell,
} from '../tools/shell-policy.mjs'
import type { Mutant } from './helpers/shell-mutants.js'
import { artifact, mutant, mutants, plant, sourceShell } from './helpers/shell-mutants.js'
import {
  ACCEPTED_BASES,
  REFUSED_BASES,
  anchorMarkup,
  variants,
} from './helpers/href-vectors.js'

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

const ROOT = fileURLToPath(new NodeURL('..', import.meta.url))
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

  test('every rule has a construct that only IT refuses', () => {
    // The stronger form of the same idea. A rule named by rows that other rules also
    // catch is a rule nobody can watch fail on its own - and a rule nobody can watch
    // fail is one that could already have stopped working.
    for (const id of RULE_IDS) {
      const alone = mutants().filter((m) => m.sole && m.rules.length === 1 && m.rules[0] === id)
      expect(alone.length, `${id} is never the only rule refusing anything`).toBeGreaterThan(0)
    }
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

  // The elements are planted carrying EVERY generated attribute at once, and each has
  // to earn its own refusal naming it. One document per element instead of one per
  // (element, attribute) pair: the coverage is the same and the suite stays inside the
  // budget a test nobody waits for does not have.
  const plantedRefusals = (markup: string) => {
    const grown = plant(artifact().html, 'BODY', markup)
    return validateShell(Buffer.from(grown.html, 'utf8'), {
      stage: 'artifact',
      expectedCsp: grown.csp,
    })
  }

  test('an event handler is refused on every element the allowlist names', () => {
    const letters = 'abcdefghijklmnopqrstuvwxyz'
    const names = Array.from(
      { length: 30 },
      (_, i) => `on${letters[Math.floor(i / 26)]}${letters[i % 26]}`,
    )
    expect(new Set(names).size).toBe(names.length)
    for (const element of ELEMENTS) {
      const attributes = names.map((n) => `${n}="x()"`).join(' ')
      const refusals = plantedRefusals(`<${element} ${attributes}>t</${element}>`)
      const named = refusals.filter((r) => r.rule === 'R-ATTRIBUTE').map((r) => r.detail).join(' ')
      for (const name of names) expect(named, `${element}[${name}]`).toContain(name)
    }
  })

  test('every attribute that names a resource is refused on every allowlisted element', () => {
    const attributes = [
      'src', 'srcset', 'poster', 'background', 'action', 'formaction', 'data', 'ping',
      'href', 'style', 'is', 'slot', 'shadowrootmode', 'xlink:href', 'xml:base',
    ]
    for (const element of ELEMENTS) {
      const wanted = attributes.filter((a) => !(element === 'a' && a === 'href'))
      const spelled = wanted.map((a) => `${a}="https://example.invalid/x"`).join(' ')
      const refusals = plantedRefusals(`<${element} ${spelled}>t</${element}>`)
      const named = refusals.filter((r) => r.rule === 'R-ATTRIBUTE').map((r) => r.detail).join(' ')
      for (const attribute of wanted) expect(named, `${element}[${attribute}]`).toContain(attribute)
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

describe('the one link the document carries, and the fragment branch beside it', () => {
  test('a fragment naming something real is accepted', () => {
    const grown = plant(artifact().html, 'BODY', '<a href="#dropzone">x</a>')
    expect(
      validateShell(Buffer.from(grown.html, 'utf8'), {
        stage: 'artifact',
        expectedCsp: grown.csp,
      }),
    ).toEqual([])
  })

  test('a duplicated href keeps the first, exactly as every engine does', () => {
    // The parser complains, and the document is refused for that. But the value the
    // rules would have judged is the FIRST one - the safe one here - so a reader of the
    // refusal is not told the wrong thing about what the link would have done.
    const row = mutant(107)
    const { tokens, html } = tokenizeShell(row.bytes.toString('utf8'))
    const anchor = tokens.find((t) => t.name === 'a')
    expect(anchor).toBeDefined()
    const span = anchor?.location.attrs?.['href']
    const raw = html.slice(span?.startOffset ?? 0, span?.endOffset ?? 0)
    const value = anchor?.attrs.find((a) => a.name === 'href')?.value ?? ''
    expect(value).toBe('https://attest-receipts.org/')
    const ids = new Set(
      tokens.flatMap((t) => t.attrs.filter((a) => a.name === 'id').map((a) => a.value)),
    )
    expect(classifyUrl(raw, value, ids).accepted).toBe(true)
  })
})

/**
 * The property, over every spelling the generator produces rather than over a list
 * somebody wrote: a refused link stays refused however it is spelled, and the allowed
 * link has exactly ONE accepted spelling. The verdicts are computed per anchor from one
 * document per base, and the whole document is then run through `validateShell` once so
 * the per-anchor verdicts and the rules that carry them cannot drift apart.
 */
describe('a link is what it resolves to, whatever it is spelled like', () => {
  const RULE_FOR: Record<string, RuleId> = {
    unparseable: 'R-URL',
    scheme: 'R-URL',
    userinfo: 'R-URL',
    canonical: 'R-URL-CANONICAL',
    'missing-target': 'R-REF',
  }

  /** One document holding every variant of a base, planted before the footer so the
   *  first N anchors in document order are the variants and the last is the real one. */
  const spread = (base: string) => {
    const vs = variants(base)
    const grown = plant(artifact().html, 'BODY', vs.map(anchorMarkup).join('\n'))
    const { tokens, html } = tokenizeShell(grown.html)
    const ids = new Set(
      tokens.flatMap((t) => t.attrs.filter((a) => a.name === 'id').map((a) => a.value)),
    )
    const verdicts = tokens
      .filter((t) => t.name === 'a')
      .map((token) => {
        const span = token.location.attrs?.['href']
        const raw = span === undefined ? '' : html.slice(span.startOffset, span.endOffset)
        const value = token.attrs.find((a) => a.name === 'href')?.value ?? ''
        return classifyUrl(raw, value, ids)
      })
    return { vs, grown, verdicts: verdicts.slice(0, vs.length), footer: verdicts[vs.length] }
  }

  test.each(REFUSED_BASES.map((b) => [b === '' ? '(empty)' : b, b] as const))(
    'no spelling of %s is ever accepted',
    (_label, base) => {
      const { vs, verdicts } = spread(base)
      expect(verdicts).toHaveLength(vs.length)
      for (const [i, verdict] of verdicts.entries())
        expect(verdict.accepted, `${vs[i].id}: ${JSON.stringify(vs[i].raw)}`).toBe(false)
    },
  )

  test.each(ACCEPTED_BASES.map((b) => [b, b] as const))(
    '%s is accepted spelled one way and no other',
    (_label, base) => {
      const { vs, verdicts, footer } = spread(base)
      // Liveness first: without this the block is satisfied by a policy that refuses
      // everything, which is the failure that looks exactly like success.
      expect(verdicts[0].accepted, 'the identity spelling must be accepted').toBe(true)
      expect(vs[0].id).toBe('identity')
      expect(footer.accepted, "the artifact's own anchor must still be accepted").toBe(true)
      for (const [i, verdict] of verdicts.entries())
        if (i > 0)
          expect(verdict.accepted, `${vs[i].id}: ${JSON.stringify(vs[i].raw)}`).toBe(false)
    },
  )

  test.each([...REFUSED_BASES, ...ACCEPTED_BASES].map((b) => [b === '' ? '(empty)' : b, b] as const))(
    'the rules refuse exactly the anchors the verdict refuses, for %s',
    (_label, base) => {
      const { grown, verdicts, footer } = spread(base)
      const refusals = validateShell(Buffer.from(grown.html, 'utf8'), {
        stage: 'artifact',
        expectedCsp: grown.csp,
      }).filter((r) => r.where.startsWith('a@'))
      const expected = [...verdicts, footer].filter((v) => !v.accepted)
      expect(refusals).toHaveLength(expected.length)
      const wanted = new Set(expected.map((v) => RULE_FOR[v.reason]))
      const fired = new Set(refusals.map((r) => r.rule))
      expect([...fired].sort()).toEqual([...wanted].sort())
    },
  )

  test('the generator produces the spellings this artifact was got around with', () => {
    const js = variants('javascript:alert(1)')
    // Pinned from the transform table: 1 identity + 165 singles + 40 capped pairs. A
    // transform that stops producing anything changes this number instead of quietly
    // shrinking the corpus.
    expect(js).toHaveLength(206)
    const spellings = js.map((v) => v.raw)
    for (const form of [
      'java\tscript:alert(1)',
      '&#106;avascript:alert(1)',
      '&#x6a;avascript:alert(1)',
      'javascript&colon;alert(1)',
      '&Tab;javascript:alert(1)',
      'JaVaScRiPt:alert(1)',
    ])
      expect(spellings, form).toContain(form)

    // The two the previous revision of this design would have accepted: it compared the
    // DECODED value, and the parser decodes both of these into the allowed link.
    const allowed = variants('https://attest-receipts.org/').map((v) => v.raw)
    for (const form of ['&#104;ttps://attest-receipts.org/', 'https&colon;//attest-receipts.org/'])
      expect(allowed, form).toContain(form)
  })
})

describe('a stylesheet that fetches is refused however the token is spelled', () => {
  const refusalsFor = (css: string) => {
    const grown = plant(artifact().html, 'STYLE', css)
    return validateShell(Buffer.from(grown.html, 'utf8'), {
      stage: 'artifact',
      expectedCsp: grown.csp,
    })
  }
  // Where this list comes from is the point: it is the whitespace of the CSS INPUT
  // STREAM after css-syntax-3 3.3 has preprocessed it - CR, CRLF and FF each collapsed
  // to a single LF - and not the list of terminators the module happens to check for.
  // Copying it from the implementation is exactly how a browser-visible `url(` spelled
  // `\\75<CR>rl(` survived a suite that claims every spelling of url( is refused: the
  // generator and the rule shared one blind spot, so the rule was verifying itself.
  const TERMINATORS = ['\n', '\t', ' ', '\f', '\r', '\r\n']

  /** Every way `url(` can be written that a browser still reads as `url(`. */
  const spellings = (): string[] => {
    const token = 'url('
    const out: string[] = [token, token.toUpperCase(), 'Url(', 'uRL(']
    for (let i = 0; i < 3; i += 1) {
      const hex = token.charCodeAt(i).toString(16)
      for (const end of TERMINATORS)
        out.push(`${token.slice(0, i)}\\${hex}${end}${token.slice(i + 1)}`)
      out.push(`${token.slice(0, i)}\\${token[i]}${token.slice(i + 1)}`)
    }
    return out
  }

  test('every spelling of url( in the stylesheet is refused', () => {
    for (const spelling of spellings()) {
      const css = `body{background:${spelling}https://example.invalid/b)}`
      expect(
        refusalsFor(css).filter((r) => r.rule === 'R-CSS'),
        JSON.stringify(css),
      ).not.toHaveLength(0)
    }
  })

  test('a fetch hidden between strings that look like comment markers is refused', () => {
    // Stripping `/* ... */` before searching would join text a browser keeps apart. Each
    // of these is a real fetch in both engines, and each survived the version of this
    // rule that removed comments first.
    const hidden = [
      'body{--x:"/*"} body::before{content:url(https://example.invalid/c)} body{--y:"*/"}',
      'body::before{content:"/*" url(https://example.invalid/c) "*/"}',
      'body{--a:"/*"} body{--b:"*/"} body::after{content:url(https://example.invalid/d)}',
    ]
    for (const css of hidden)
      expect(refusalsFor(css).filter((r) => r.rule === 'R-CSS'), css).not.toHaveLength(0)
  })

  test('a genuine comment naming url( is refused too, and that is the declared price', () => {
    // Pinned so nobody "fixes" this back to stripping comments: the over-approximation
    // is the reason the three rows above are caught at all.
    expect(refusalsFor('/* url( */').filter((r) => r.rule === 'R-CSS')).not.toHaveLength(0)
  })

  test('the artifact carries a stylesheet, so the rule is not passing on an empty one', () => {
    const { tokens, endTags, html } = tokenizeShell(artifact().html)
    const style = tokens.find((t) => t.name === 'style')
    const end = endTags.find((t) => t.name === 'style')
    expect(style).toBeDefined()
    const css = html.slice(style?.location.endOffset ?? 0, end?.location.startOffset ?? 0)
    expect(css.length).toBeGreaterThan(1_000)
  })
})

test('the rule set is closed, and this is the whole of it', () => {
  expect([...RULE_IDS]).toEqual([
    'R-INPUT', 'R-PARSE', 'R-ELEMENT', 'R-ATTRIBUTE', 'R-VALUE', 'R-META', 'R-COUNT',
    'R-URL', 'R-URL-CANONICAL', 'R-REF', 'R-CSS',
  ])
  expect(RULES.map((r) => r.id)).toEqual([...RULE_IDS])
})
