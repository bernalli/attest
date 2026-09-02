import { test, expect, type Page } from '@playwright/test'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { validateShell } from '../tools/shell-policy.mjs'
import { mutantsFrom, plant, policyFor, splitHead } from '../test/helpers/shell-mutants.js'

/**
 * The question none of the other suites asks: a document these rules ACCEPT — does it
 * make a request?
 *
 * Everything else here measures the refusing direction. The corpus proves each named
 * rule fires and that removing it lets the mutant through; scenario C proves the tokens
 * are a superset of every tree; scenario A proves the validator and the engine agree on
 * where an accepted link goes. All of them are questions about constructs the validator
 * already refuses. Nothing opened, in a browser, a document the validator had just
 * waved through.
 *
 * Two defects lived in that gap at once, in different rules, and they were the same
 * defect: the validator's MODEL of the engine drifting from what the engine does, in
 * the direction no in-process test can see. R-CSS read the raw bytes of the stylesheet
 * while css-syntax-3 3.3 preprocesses the input stream, so an escape ended by a
 * carriage return was `url(` to every engine and nothing to the rule. R-META checked
 * four things about where the policy was WRITTEN and nothing about whether the head was
 * still open when the browser got there, so a `<p>` in front of it made the policy a
 * child of the body, where the pragma is not applied at all. Together they produced a
 * file that passed `--check` with exit 0 and fetched over the network in both engines.
 *
 * So this bench GENERATES the documents rather than listing them — a list would share
 * the blind spot of whoever wrote it, which is exactly how the first of those two
 * survived a suite claiming every spelling of `url(` was refused. It walks the boundary
 * of the allowlist, keeps whatever falls on the accepted side, and asks a real engine
 * about each one:
 *
 *   - nothing left the file:// scheme,
 *   - the policy reported no violation, so nothing was even ATTEMPTED that it had to
 *     stop,
 *   - and the policy is in force at all — the meta is still a child of the head.
 *
 * The third is what makes the second mean anything: a dead policy also reports zero
 * violations. The first test below is the self-test for both, and it is the exploit.
 */

const HERE = fileURLToPath(new URL('.', import.meta.url))
const DESKTOP = join(HERE, '..')
const ARTIFACT = join(DESKTOP, 'dist', 'attest-verifier.html')

/** Reserved by RFC 2606: it never resolves anywhere, so nothing can be reached and no
 *  data can leave even when a probe deliberately tries. Each probe gets its own path,
 *  so a violation or a failed request names the exact spelling that produced it. */
const PROBE = 'https://accepted-oracle.invalid'

const artifactHtml = (): string => readFileSync(ARTIFACT, 'utf8')
const artifactCsp = (html: string): string => {
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1]
  if (csp === undefined) throw new Error('the built artifact declares no policy')
  return csp
}

/**
 * A document of the smallest shape these rules accept.
 *
 * Not the artifact, deliberately. The contract under test is "if the validator accepts
 * it, it makes no request", and that is a claim about EVERY document it accepts, not
 * about the one this repository happens to ship. A 600-byte page also loads in a
 * fraction of the time, which is what makes one page per generated document affordable.
 * The shipped artifact is measured too, as the first row of the accepted set.
 */
const MODULE = "document.getElementById('probe').textContent = 'ran'"

/**
 * The stylesheet as the CSS engine will receive it, which is NOT the bytes in the file.
 * The HTML parser turns CR and CRLF into a single LF inside raw text and NUL into
 * U+FFFD, and a browser hashes the element's text content for `style-src`, not the
 * source. Measured 2026-09-02: pinning the raw bytes instead made every document whose
 * stylesheet carried a carriage return report `style-src-elem|inline` and apply no
 * stylesheet at all — so the near-miss spellings this bench exists to put in front of a
 * CSS engine never reached one, and the page measured nothing while looking measured.
 *
 * A shipped artifact could not do this: `tools/inline.mjs` hashes the raw capture, so a
 * carriage return in the real stylesheet fails `--check` on the pin. That is a second
 * and independent belt, and it is not the one under test here — R-CSS is.
 */
const asParsed = (css: string): string => css.replace(/\r\n?/g, '\n').replace(/\0/g, '\uFFFD')

const minimal = (css: string, beforePolicy = ''): { html: string; csp: string } => {
  const csp = policyFor(MODULE, asParsed(css))
  const html =
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    beforePolicy +
    `<meta http-equiv="Content-Security-Policy" content="${csp}">\n` +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<title>accepted</title>\n' +
    `<script type="module">${MODULE}</script>\n` +
    `<style>${css}</style>\n` +
    '</head>\n<body>\n<p id="probe">a document these rules accept</p>\n</body>\n</html>\n'
  return { html, csp }
}

const PLAIN_CSS = 'p{color:#222}'

// ---------------------------------------------------------------------------
// The generators. Neither knows which of the things it produces a browser reads
// as the dangerous construct — that is the question being put to the browser.
// ---------------------------------------------------------------------------

/**
 * The tokens R-CSS refuses, each written into a stylesheet the way an engine would have
 * to act on it — an `@import` before every style rule or it is ignored, an `image-set()`
 * with the resolution its grammar requires, a `src()` inside the only descriptor it is
 * defined for.
 *
 * `fetches` is measured, not assumed, and the liveness test below pins it: with the
 * token spelled plainly, chromium and firefox both fetch for `url(`, `@import` and
 * `image-set(` and both do NOTHING for `image(` and `src(`, which neither implements
 * (2026-09-02). That is a limit of this bench and worth stating plainly: for those two
 * tokens no browser can answer, so a rule that stopped refusing them would be caught by
 * the corpus in Node and not here. When an engine implements one, the pin turns red and
 * says so instead of the coverage quietly staying imaginary.
 */
const SINKS: Record<
  string,
  { css: (spelled: string, url: string) => string; fetches: boolean }
> = {
  'url(': { css: (t, u) => `p{background-image:${t}${u})}\n${PLAIN_CSS}`, fetches: true },
  '@import': { css: (t, u) => `${t} "${u}";\n${PLAIN_CSS}`, fetches: true },
  'image-set(': {
    css: (t, u) => `p{background-image:${t}"${u}" 1x)}\n${PLAIN_CSS}`,
    fetches: true,
  },
  'image(': { css: (t, u) => `p{background-image:${t}"${u}")}\n${PLAIN_CSS}`, fetches: false },
  'src(': {
    css: (t, u) => `@font-face{font-family:probe;src:${t}"${u}")}\np{font-family:probe}`,
    fetches: false,
  },
}

const FETCHING = Object.keys(SINKS)

/**
 * What can stand between a hex escape and the character after it.
 *
 * The list is written from the CSS INPUT STREAM and not from the rule, and that
 * distinction is the whole reason this file exists: css-syntax-3 3.3 collapses CR, CRLF
 * and FF each to a single LF and turns NUL into U+FFFD before the tokenizer reads a
 * byte, so which of these ends an escape is a fact about engines, not about the
 * implementation. Which ones do is deliberately NOT asserted here — that is the shape
 * of the mistake this bench exists to catch. The partition is measured against the
 * rules, and whatever falls on the accepted side is handed to a real engine.
 */
const ENDINGS: ReadonlyArray<readonly [string, string]> = [
  ['lf', '\n'],
  ['cr', '\r'],
  ['crlf', '\r\n'],
  ['ff', '\f'],
  ['tab', '\t'],
  ['space', ' '],
  ['none', ''],
  ['two-spaces', '  '],
  ['lf-lf', '\n\n'],
  ['cr-cr', '\r\r'],
  ['crlf-crlf', '\r\n\r\n'],
  ['nul', '\0'],
  ['nbsp', ' '],
]

interface Spelling {
  id: string
  token: string
  spelled: string
}

/** Every way to write one character of a fetching token: as a hex escape ended each of
 *  the ways above, as a six-digit hex escape that needs no ending at all, as a character
 *  escape, and in capitals. */
const spellings = (): Spelling[] => {
  const out: Spelling[] = []
  for (const token of FETCHING) {
    for (let i = 0; i < token.length; i += 1) {
      const letter = token[i]
      if (!/[a-z]/.test(letter)) continue
      const hex = letter.charCodeAt(0).toString(16)
      const head = token.slice(0, i)
      const tail = token.slice(i + 1)
      const put = (id: string, spelled: string) =>
        out.push({ id: `${token} at ${i} / ${id}`, token, spelled })
      for (const [id, ending] of ENDINGS) put(`hex-${id}`, `${head}\\${hex}${ending}${tail}`)
      put('hex-padded', `${head}\\${hex.padStart(6, '0')}${tail}`)
      put('char-escape', `${head}\\${letter}${tail}`)
      put('capital', `${head}${letter.toUpperCase()}${tail}`)
    }
  }
  return out
}

const cssFor = (spelling: Spelling, n: number): string =>
  SINKS[spelling.token].css(spelling.spelled, `${PROBE}/probe-${n}`)

/**
 * Things written in front of the policy. The "in head" insertion mode pops the head at
 * the first content that is not head content, and a policy that ends up a child of the
 * body is a policy no engine applies — so what matters is not whether these are
 * ALLOWED elements but whether they close the head, which is a different question and
 * the one R-META used not to ask.
 */
const splitters = (id: string): ReadonlyArray<readonly [string, string]> => [
  ['a paragraph', '<p id="split-p">x</p>\n'],
  ['a div', '<div id="split-div">x</div>\n'],
  ['a span', '<span id="split-span">x</span>\n'],
  ['a select', '<select id="split-select"><option value="a">a</option></select>\n'],
  ['an input', '<input id="split-input" type="text">\n'],
  ['a label', `<label for="${id}">x</label>\n`],
  ['an anchor', `<a href="#${id}">x</a>\n`],
  ['a bare character', 'x\n'],
  ['a character reference', '&nbsp;\n'],
  ['a comment', '<!-- nothing at all -->\n'],
  ['whitespace', '  \n\t\n'],
  ['nothing', ''],
]

interface Doc {
  id: string
  family: string
  /** Bytes, never a string. A corpus row whose payload is a byte no UTF-8 decoder
   *  accepts comes back from `Buffer.toString` with that byte silently replaced - a
   *  different document, and one the validator accepts. Measured here: row 103 arrived
   *  in the accepted set that way, which is the bench lying to itself in the direction
   *  it exists to catch. */
  bytes: Buffer
  csp: string
}

/** Every document this bench builds, before the validator has said anything about it. */
const candidates = (): Doc[] => {
  const art = artifactHtml()
  const artCsp = artifactCsp(art)
  const utf8 = (id: string, family: string, html: string, csp: string): Doc => ({
    id,
    family,
    bytes: Buffer.from(html, 'utf8'),
    csp,
  })
  const out: Doc[] = [utf8('the shipped artifact', 'artifact', art, artCsp)]

  spellings().forEach((spelling, n) => {
    const { html, csp } = minimal(cssFor(spelling, n))
    out.push(utf8(`stylesheet: ${spelling.id}`, 'stylesheet', html, csp))
  })

  for (const [what, markup] of splitters('probe')) {
    const { html, csp } = minimal(PLAIN_CSS, markup)
    out.push(utf8(`head: ${what}, in the smallest accepted document`, 'head', html, csp))
  }
  for (const [what, markup] of splitters('dropzone')) {
    const grown = splitHead(art, markup.replace(/\n$/, ''))
    out.push(utf8(`head: ${what}, in the shipped artifact`, 'head', grown, artCsp))
  }

  // The corpus too: every row is supposed to be refused, so this contributes nothing
  // today. It is the net under the corpus - a rule that stops firing turns its rows
  // into accepted documents, and accepted documents get opened in a browser here
  // instead of merely failing an assertion in Node.
  // Built from the bytes already read above rather than through `mutants()`, which
  // shells out to `npm run build`: several browser workers run this file at once and
  // that build is a race between them.
  for (const m of mutantsFrom({ html: art, csp: artCsp }))
    if (m.stage === 'artifact')
      out.push({
        id: `corpus row ${m.n}: ${m.what}`,
        family: 'corpus',
        bytes: m.bytes,
        csp: m.expectedCsp,
      })

  return out
}

const refusalsFor = (doc: Doc): string[] =>
  validateShell(doc.bytes, { stage: 'artifact', expectedCsp: doc.csp }).map((r) => r.rule)

const asDoc = (id: string, family: string, made: { html: string; csp: string }): Doc => ({
  id,
  family,
  bytes: Buffer.from(made.html, 'utf8'),
  csp: made.csp,
})

// ---------------------------------------------------------------------------
// The measurement, one procedure used everywhere so the self-test below proves the
// timing of the real one and not of a gentler variant of it.
// ---------------------------------------------------------------------------

interface Watch {
  foreign: string[]
  failed: Map<string, string>
}

const watch = (page: Page): Watch => {
  const w: Watch = { foreign: [], failed: new Map() }
  page.on('request', (r) => {
    if (!r.url().startsWith('file:')) w.foreign.push(r.url())
  })
  page.on('requestfailed', (r) => w.failed.set(r.url(), r.failure()?.errorText ?? ''))
  return w
}

const collectViolations = async (page: Page): Promise<void> => {
  await page.addInitScript(() => {
    ;(globalThis as unknown as { __violations: string[] }).__violations = []
    window.addEventListener('securitypolicyviolation', (event) => {
      ;(globalThis as unknown as { __violations: string[] }).__violations.push(
        `${event.violatedDirective}|${event.blockedURI}`,
      )
    })
  })
}

interface Reading {
  policyParent: string | null
  violations: string[]
  foreign: string[]
  failed: Record<string, string>
}

const dir = mkdtempSync(join(tmpdir(), 'accepted-documents-'))
let written = 0

const open = async (page: Page, w: Watch, doc: Doc): Promise<Reading> => {
  written += 1
  const file = join(dir, `doc-${written}.html`)
  writeFileSync(file, doc.bytes)

  w.foreign.length = 0
  w.failed.clear()
  await page.goto(`file://${file}`)

  // Style is resolved lazily: a stylesheet that only fetches once something USES it
  // would otherwise be read before the engine had looked at it. Forcing layout forces
  // style for the whole tree, pseudo-elements included.
  await page.evaluate(() => {
    void document.documentElement.offsetHeight
  })

  // A second round trip, so the task that delivers a violation event has had its turn.
  // Not a poll: the self-test below uses this same procedure and expects to SEE a
  // violation and a request, so a procedure that waited too little would fail there
  // rather than quietly passing here.
  const seen = await page.evaluate(() => ({
    policyParent: document.querySelector('meta[http-equiv]')?.parentElement?.localName ?? null,
    violations: (globalThis as unknown as { __violations: string[] }).__violations.slice(),
  }))
  return { ...seen, foreign: [...w.foreign], failed: Object.fromEntries(w.failed) }
}

test.describe('scenario D: what these rules ACCEPT, a real engine is asked about', () => {
  test('both belts this bench rests on can be seen to fail', async ({ page }, info) => {
    const w = watch(page)
    await collectViolations(page)

    // Belt one: with the policy in force, a stylesheet that fetches produces a violation
    // this bench can see. Without this, "no violation" would be satisfied by a collector
    // that never reports anything - the failure that looks exactly like success.
    const fetching = asDoc(
      'liveness: a stylesheet that really fetches',
      'liveness',
      minimal(`p::before{content:url(${PROBE}/liveness.png)}\n${PLAIN_CSS}`),
    )
    const blocked = await open(page, w, fetching)
    expect(blocked.policyParent, 'the liveness page lost its own policy').toBe('head')
    expect(
      blocked.violations.join(' '),
      'the policy reported no violation for a stylesheet that fetches',
    ).toContain('liveness.png')
    // Counting `request` events is deliberately NOT the assertion: measured 2026-09-02,
    // chromium emits one for a request its own policy blocked and firefox emits none,
    // so a bench that counted them would measure the two engines differently. What both
    // agree on is that nothing succeeded, which is what this checks on whatever the
    // engine did report.
    for (const url of blocked.foreign)
      expect(blocked.failed[url], `${url} was not blocked`).toMatch(/csp|blocked/i)
    expect(refusalsFor(fetching), 'R-CSS no longer refuses a plain url(').toContain('R-CSS')

    // And the reach of the bench, pinned rather than assumed: with the token spelled
    // plainly, does this engine act on it at all? A token nothing acts on is one no
    // browser can answer for, and saying which those are is the difference between a
    // limit and a blind spot.
    const reach: Record<string, boolean> = {}
    for (const [token, sink] of Object.entries(SINKS)) {
      const probe = asDoc(
        `reach: ${token}`,
        'liveness',
        // Slugged, not percent-encoded: `encodeURIComponent` leaves `(` alone, and an
        // unescaped parenthesis inside an unquoted url token makes the whole declaration
        // invalid — so the probe fetched nothing and looked like an engine that had
        // stopped implementing `url(`. Measured here, by this pin, which is what it is
        // for.
        minimal(sink.css(token, `${PROBE}/reach-${token.replace(/[^a-z0-9]+/g, '-')}`)),
      )
      const seen = await open(page, w, probe)
      reach[token] = seen.violations.length > 0 || seen.foreign.length > 0
      expect(reach[token], `${token} no longer behaves as this bench recorded`).toBe(sink.fetches)
    }

    // Belt two: the exploit. A `<p>` in front of the policy and an escape ended by a
    // carriage return - each harmless to the rules as they were, together a document
    // that fetched over the network in both engines with zero violations, because the
    // policy was a child of the body and applied to nothing.
    const exploit = asDoc(
      'liveness: the exploit',
      'liveness',
      plant(
        splitHead(artifactHtml(), '<p id="head-split">x</p>'),
        'STYLE',
        `body::before{content:\\75\rrl(${PROBE}/exploit.png)}`,
      ),
    )
    const pwned = await open(page, w, exploit)
    expect(pwned.policyParent, 'the head split no longer moves the policy into the body').toBe(
      'body',
    )
    expect(pwned.violations, 'a policy in the body cannot report a violation').toEqual([])
    expect(
      pwned.foreign.join(' '),
      'the exploit no longer reaches the network, so this page proves nothing',
    ).toContain('exploit.png')

    // And the closing half: what the two belts above just demonstrated is dangerous is
    // what the validator now refuses, naming both rules that let it through.
    const named = refusalsFor(exploit)
    expect(named, 'the exploit is not refused by both rules it defeats').toEqual(
      expect.arrayContaining(['R-META', 'R-CSS']),
    )

    await info.attach(`liveness-${info.project.name}.json`, {
      body: JSON.stringify({ blocked, pwned, reach, exploitRefusedBy: named }, null, 1),
      contentType: 'application/json',
    })
  })

  test('every document these rules accept makes no request and keeps its policy', async ({
    page,
  }, info) => {
    test.setTimeout(240_000)
    const w = watch(page)
    await collectViolations(page)

    const all = candidates()
    const accepted = all.filter((doc) => refusalsFor(doc).length === 0)
    const byFamily = (family: string) => accepted.filter((d) => d.family === family).length

    // The browser runs FIRST, before any assertion made in this process. What this file
    // exists to establish is what an ENGINE says about an accepted document, and a Node
    // -side guard that fired earlier would decide the test on the strength of the very
    // model whose drift is the thing being looked for.
    const failures: Array<Record<string, unknown>> = []
    for (const doc of accepted) {
      const seen = await open(page, w, doc)
      if (seen.policyParent !== 'head' || seen.violations.length > 0 || seen.foreign.length > 0)
        failures.push({ document: doc.id, ...seen })
    }

    await info.attach(`accepted-${info.project.name}.json`, {
      body: JSON.stringify(
        {
          generated: all.length,
          accepted: accepted.length,
          acceptedByFamily: {
            artifact: byFamily('artifact'),
            stylesheet: byFamily('stylesheet'),
            head: byFamily('head'),
            corpus: byFamily('corpus'),
          },
          failures,
        },
        null,
        1,
      ),
      contentType: 'application/json',
    })

    expect(
      failures,
      'a document the validator ACCEPTS either reached the network or lost its policy',
    ).toEqual([])

    // Pinned, so a generator that stops producing changes this number instead of
    // quietly shrinking the set it feeds.
    expect(spellings(), 'the stylesheet generator has changed size').toHaveLength(400)

    // Liveness of the partition. A validator that refused everything would satisfy the
    // loop above with nothing to open, and that is the shape a broken rule set takes.
    expect(byFamily('artifact'), 'the shipped artifact is no longer accepted').toBe(1)
    expect(byFamily('stylesheet'), 'no near-miss spelling survives the css rule').toBeGreaterThan(0)
    expect(
      byFamily('head'),
      'nothing may be written in front of the policy any more',
    ).toBeGreaterThan(0)

    // The corpus is supposed to be refused in full, so this contributes nothing today.
    // A row appearing here means a rule has stopped firing — and by now it will already
    // have been opened in a browser above.
    expect(
      accepted.filter((d) => d.family === 'corpus').map((d) => d.id),
      'a corpus row the validator no longer refuses',
    ).toEqual([])
  })
})
