import { test, expect } from '@playwright/test'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { JSDOM } from 'jsdom'

import { ALLOWED_HOSTS, BASE_URL, classifyUrl, tokenizeShell } from '../tools/shell-policy.mjs'
import {
  ACCEPTED_BASES,
  REFUSED_BASES,
  anchorMarkup,
  variants,
} from '../test/helpers/href-vectors.js'

/**
 * The browser is the oracle, and what it is asked is SOUNDNESS, not string equality.
 *
 * The validator resolves a link with Node's WHATWG parser and refuses everything it
 * cannot prove safe. The question a real engine answers is the only one that matters:
 * of the links the validator ACCEPTS, does the engine agree they go where the validator
 * said? Where the two disagree on a link the validator already refused, the
 * disagreement is recorded and attached — it cannot make the artifact less safe, and
 * failing on it would only pin one engine's serialisation quirks into this suite.
 */

const HERE = fileURLToPath(new URL('.', import.meta.url))
const DESKTOP = join(HERE, '..')
const ARTIFACT = join(DESKTOP, 'dist', 'attest-verifier.html')

const pageFile = (name: string, html: string): string => {
  const file = join(mkdtempSync(join(tmpdir(), 'shell-oracle-')), name)
  writeFileSync(file, html)
  return file
}

/** Not named `document`: inside `page.evaluate` that name belongs to the engine, and a
 *  helper called the same thing shadows it silently. */
const htmlPage = (body: string, head = ''): string =>
  `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n` +
  `<meta name="viewport" content="width=device-width, initial-scale=1">\n` +
  `<title>oracle</title>\n${head}</head>\n<body>\n${body}\n</body>\n</html>\n`

interface Seen {
  href: string
  protocol: string
  host: string
}

test.describe('scenario A: what the validator accepts is what the engine resolves', () => {
  // Every base with every generated spelling, in one file:// page. No anchor is clicked
  // and the page carries no policy: what is measured is resolution, not navigation.
  const cases = [...REFUSED_BASES, ...ACCEPTED_BASES].flatMap((base) =>
    variants(base).map((variant) => ({ base, variant })),
  )
  const html = htmlPage(
    `<div id="dropzone">t</div>\n${cases.map(({ variant }) => anchorMarkup(variant)).join('\n')}`,
  )

  test('every accepted spelling resolves where the validator said, in this engine', async ({
    page,
  }, info) => {
    const file = pageFile('anchors.html', html)
    const fileUrl = `file://${file}`

    // The Node-side verdicts come from the tokens of the SAME bytes, in document order.
    const { tokens, html: source } = tokenizeShell(html)
    const anchors = tokens.filter((t) => t.name === 'a')
    const ids = new Set(
      tokens.flatMap((t) => t.attrs.filter((a) => a.name === 'id').map((a) => a.value)),
    )
    const verdicts = anchors.map((token) => {
      const span = token.location.attrs?.['href']
      const raw = span === undefined ? '' : source.slice(span.startOffset, span.endOffset)
      const value = token.attrs.find((a) => a.name === 'href')?.value ?? ''
      return classifyUrl(raw, value, ids)
    })

    await page.goto(fileUrl)
    const seen: Seen[] = await page.$$eval('a', (nodes) =>
      nodes.map((n) => {
        const a = n as HTMLAnchorElement
        return { href: a.href, protocol: a.protocol, host: a.host }
      }),
    )

    expect(seen, 'the engine and the tokenizer disagree on how many anchors there are').toHaveLength(
      cases.length,
    )
    expect(verdicts).toHaveLength(cases.length)

    // Liveness first. Without it the block below is satisfied by a validator that
    // accepts nothing at all, which is the failure that looks exactly like success.
    for (const base of ACCEPTED_BASES) {
      const i = cases.findIndex((c) => c.base === base && c.variant.id === 'identity')
      expect(i, `${base} has no identity variant`).toBeGreaterThanOrEqual(0)
      expect(verdicts[i].accepted, `the identity spelling of ${base} must be accepted`).toBe(true)
    }

    // Not vacuous: of nearly three thousand spellings, exactly two are accepted - one
    // per allowed base, and each is the identity. A validator that had drifted into
    // accepting a family of spellings would fail here before any browser is consulted.
    expect(verdicts.filter((v) => v.accepted)).toHaveLength(ACCEPTED_BASES.length)

    const disagreements: unknown[] = []
    const serialisation: unknown[] = []
    for (const [i, verdict] of verdicts.entries()) {
      const { base, variant } = cases[i]
      const browser = seen[i]
      const where = `${base || '(empty)'} / ${variant.id} / ${JSON.stringify(variant.raw)}`

      if (verdict.accepted) {
        if (verdict.resolved?.startsWith('https:') === true) {
          expect(browser.protocol, where).toBe('https:')
          expect(ALLOWED_HOSTS, where).toContain(browser.host)
          expect(browser.href, where).toBe(verdict.resolved)
        } else {
          // The fragment branch: the validator resolves against a fixed file: base, the
          // engine against the page it is in. Same fragment, different document.
          expect(browser.href.replace(fileUrl, BASE_URL), where).toBe(verdict.resolved)
        }
        continue
      }

      // Refusal direction: an engine that reaches https on the allowed host where the
      // validator refused is worth knowing about, but it is not a soundness failure —
      // the validator refusing MORE than the engine follows is the safe direction. What
      // would be unsafe is the opposite, and that is the branch above.
      if (browser.protocol === 'https:' && ALLOWED_HOSTS.includes(browser.host))
        disagreements.push({ where, browser, validator: verdict })
      if (verdict.resolved !== null && browser.href !== verdict.resolved)
        serialisation.push({ where, browser: browser.href, node: verdict.resolved })
    }

    await info.attach(`url-disagreements-${info.project.name}.json`, {
      body: JSON.stringify(
        {
          total: cases.length,
          reachesTheAllowedLinkAnyway: disagreements,
          serialisationDifferences: serialisation,
        },
        null,
        1,
      ),
      contentType: 'application/json',
    })
    // Recorded, never failed. Both are differences on spellings the validator has
    // already REFUSED, so both can only mean it refuses more than the engine follows.
    // Failing on them would pin one engine's serialisation into this suite and make a
    // browser update look like a defect in the artifact.
    expect(disagreements.length, 'refused spellings the engine still reaches the allowed link with')
      .toBeGreaterThanOrEqual(0)
    expect(serialisation.length, 'refused spellings the engine serialises differently')
      .toBeGreaterThanOrEqual(0)
  })
})

test.describe('scenario B: a stylesheet that fetches, with and without a policy', () => {
  const fixture = (name: string) => `file://${join(HERE, 'fixtures', `${name}.html`)}`

  test('with no policy the stylesheet really does fetch', async ({ page }) => {
    // The negative self-test for the belt below. Without this, "nothing left the file"
    // could be true because the style never applied, and the assertion would be empty.
    const foreign: string[] = []
    page.on('request', (r) => {
      if (!r.url().startsWith('file:')) foreign.push(r.url())
    })
    await page.goto(fixture('css-liveness'))
    await expect
      .poll(() => foreign.length, { message: 'no engine fetched the stylesheet url()' })
      .toBeGreaterThan(0)
    expect(
      await page.evaluate(() => getComputedStyle(document.body, '::before').content),
    ).toContain('css-oracle.invalid')
  })

  test('with the policy in force the same stylesheet reaches nothing', async ({ page }) => {
    const foreign: string[] = []
    const failed = new Map<string, string>()
    page.on('request', (r) => {
      if (!r.url().startsWith('file:')) foreign.push(r.url())
    })
    page.on('requestfailed', (r) => failed.set(r.url(), r.failure()?.errorText ?? ''))
    await page.addInitScript(() => {
      ;(globalThis as unknown as { __violations: string[] }).__violations = []
      window.addEventListener('securitypolicyviolation', (event) => {
        ;(globalThis as unknown as { __violations: string[] }).__violations.push(
          `${event.violatedDirective}|${event.blockedURI}`,
        )
      })
    })
    await page.goto(fixture('css-with-policy'))

    // The style is ALLOWED to apply here - its own hash is in the policy - so what has
    // to stop the fetch is default-src 'none'. Asserting that the rule applied first
    // means the next assertion is about the fetch and not about a stylesheet that was
    // never read.
    expect(
      await page.evaluate(() => getComputedStyle(document.body, '::before').content),
      'the stylesheet did not apply, so this page measures nothing',
    ).toContain('css-oracle.invalid')

    await expect
      .poll(
        async () =>
          (await page.evaluate(() => (globalThis as unknown as { __violations: string[] }).__violations))
            .length,
        { message: 'the policy reported no violation' },
      )
      .toBeGreaterThan(0)

    // Counting `request` events is not the assertion, and this is why: chromium emits
    // one for a request its own policy blocks, firefox emits none at all. What both
    // agree on is that nothing succeeded.
    for (const url of foreign)
      expect(failed.get(url), `${url} was not blocked`).toMatch(/csp|blocked/i)
  })
})

test.describe('scenario C: the tokens are a superset of every tree', () => {
  const artifactBody = (): string => {
    const html = readFileSync(ARTIFACT, 'utf8')
    return html.slice(html.indexOf('<body>') + '<body>'.length, html.lastIndexOf('</body>'))
  }

  /** (localName, sorted attribute names) for every element, through template contents
   *  and through any shadow root the engine attached. */
  const WALK = `(root) => {
    const out = []
    const visit = (node) => {
      for (const el of node.children) {
        out.push(el.localName + '[' + [...el.attributes].map((a) => a.name).sort().join(',') + ']')
        if (el.localName === 'template' && el.content) visit(el.content)
        if (el.shadowRoot) visit(el.shadowRoot)
        visit(el)
      }
    }
    visit(root)
    return out
  }`

  const ROWS: Array<{
    n: number
    what: string
    where: 'BODY' | 'SELECT'
    markup: string
    /** Measured, then pinned. `engineOnly` is what the engines build and jsdom throws
     *  away — the reason the rules read tokens. `treeOnly` is the other direction:
     *  jsdom parses noscript's contents that an engine with scripting on never renders,
     *  and keeps as an element the template an engine consumes into a shadow root.
     *  Either set changing is a signal to re-read this oracle, not to adjust it. */
    engineOnly: string[]
    treeOnly: string[]
  }> = [
    { n: 35, engineOnly: [], treeOnly: [], what: 'a template holding an image', where: 'BODY',
      markup: '<template><img src="https://example.invalid/t"></template>' },
    { n: 36, engineOnly: [], treeOnly: [], what: 'a template inside a template', where: 'BODY',
      markup: '<template><template><img src="https://example.invalid/t"></template></template>' },
    { n: 37, engineOnly: [], treeOnly: ['template'], what: 'a declarative shadow root', where: 'BODY',
      markup: '<div><template shadowrootmode="open"><img src="https://example.invalid/d"></template></div>' },
    { n: 38, engineOnly: [], treeOnly: ['img'], what: 'an image inside noscript', where: 'BODY',
      markup: '<noscript><img src="https://example.invalid/n"></noscript>' },
    { n: 40, engineOnly: ['meta'], treeOnly: [], what: 'a meta refresh inside the select', where: 'SELECT',
      markup: '<meta http-equiv="refresh" content="9999;url=https://example.invalid/">' },
    { n: 41, engineOnly: ['img'], treeOnly: [], what: 'an image inside the select', where: 'SELECT',
      markup: '<img src="https://example.invalid/si">' },
    { n: 42, engineOnly: ['a'], treeOnly: [], what: 'an anchor inside the select', where: 'SELECT',
      markup: '<a href="https://example.invalid/">x</a>' },
    { n: 43, engineOnly: ['image', 'svg'], treeOnly: [], what: 'an svg image inside the select', where: 'SELECT',
      markup: '<svg><image href="https://example.invalid/sv"/></svg>' },
    { n: 44, engineOnly: ['link'], treeOnly: [], what: 'a stylesheet inside the select', where: 'SELECT',
      markup: '<link rel="stylesheet" href="https://example.invalid/s.css">' },
    { n: 45, engineOnly: ['base'], treeOnly: [], what: 'a base inside the select', where: 'SELECT',
      markup: '<base href="https://example.invalid/">' },
    { n: 46, engineOnly: ['div'], treeOnly: ['template'], what: 'a declarative shadow root inside the select', where: 'SELECT',
      markup: '<div><template shadowrootmode="open"><img src="https://example.invalid/sd"></template></div>' },
  ]

  const nameOnly = (entry: string): string => entry.slice(0, entry.indexOf('['))
  const missing = (from: string[], inside: string[]): string[] => {
    const pool = [...inside]
    const out: string[] = []
    for (const entry of from) {
      const i = pool.indexOf(entry)
      if (i === -1) out.push(entry)
      else pool.splice(i, 1)
    }
    return out
  }

  for (const row of ROWS) {
    test(`row ${row.n}: ${row.what}`, async ({ page }, info) => {
      const body =
        row.where === 'SELECT'
          ? artifactBody().replace(
              '<select id="binding-type">',
              () => `<select id="binding-type">${row.markup}`,
            )
          : artifactBody().replace('<main>', () => `${row.markup}\n<main>`)
      const html = htmlPage(body)
      const file = pageFile(`row-${row.n}.html`, html)

      const tokens = tokenizeShell(html).tokens.map(
        (t) => `${t.name}[${t.attrs.map((a) => a.name).sort().join(',')}]`,
      )
      const jsdomTree: string[] = await new Function(
        'root',
        `return (${WALK})(root)`,
      )(new JSDOM(html).window.document.body)

      await page.goto(`file://${file}`)
      const browserTree: string[] = await page.evaluate(
        `(${WALK})(document.body)` as unknown as string,
      )

      // The property the whole design rests on: every element any implementation ends
      // up with was a start-tag token first. A violation here is not a divergence to
      // record, it is the design being wrong.
      expect(missing(browserTree, tokens), 'the engine built an element the tokens never saw')
        .toEqual([])
      expect(missing(jsdomTree, tokens), 'jsdom built an element the tokens never saw').toEqual([])

      const engineOnly = missing(browserTree, jsdomTree).map(nameOnly).sort()
      const treeOnly = missing(jsdomTree, browserTree).map(nameOnly).sort()
      await info.attach(`tree-divergence-row-${row.n}-${info.project.name}.json`, {
        body: JSON.stringify({ engineOnly, treeOnly }, null, 1),
        contentType: 'application/json',
      })

      expect(engineOnly, 'what the engine builds and jsdom drops has changed').toEqual(
        [...row.engineOnly].sort(),
      )
      expect(treeOnly, 'what jsdom builds and the engine does not has changed').toEqual(
        [...row.treeOnly].sort(),
      )
    })
  }
})
