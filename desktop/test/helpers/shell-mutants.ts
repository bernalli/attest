import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { URL as NodeURL, fileURLToPath } from 'node:url'

/**
 * The mutant corpus: one entry per construct the shell policy must refuse, planted into
 * the REAL artifact (or the real source shell) rather than into a fixture that shares
 * the author's blind spots.
 *
 * Every entry names the rule that must refuse it, so a rule can be removed and the
 * mutant watched to go from refused to accepted — the only evidence that a rule is
 * load-bearing rather than decorative.
 */

const ROOT = fileURLToPath(new NodeURL('../..', import.meta.url))
const ARTIFACT = join(ROOT, 'dist', 'attest-verifier.html')
const SOURCE = join(ROOT, 'index.html')

/** The policy's rule ids, mirrored here so the corpus can be typed without importing
 *  the module it exists to test. */
export type RuleId =
  | 'R-INPUT'
  | 'R-PARSE'
  | 'R-ELEMENT'
  | 'R-ATTRIBUTE'
  | 'R-VALUE'
  | 'R-META'
  | 'R-COUNT'
  | 'R-URL'
  | 'R-URL-CANONICAL'
  | 'R-REF'
  | 'R-CSS'

let built: { html: string; csp: string } | null = null

/** The artifact is built once per test file. Reading a stale `dist/` would silently
 *  measure yesterday's bytes. */
export function artifact(): { html: string; csp: string } {
  if (built === null) {
    const run = spawnSync('npm', ['run', 'build'], { cwd: ROOT, encoding: 'utf8' })
    if (run.status !== 0) throw new Error(`build failed:\n${run.stdout}\n${run.stderr}`)
    const html = readFileSync(ARTIFACT, 'utf8')
    const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1]
    if (csp === undefined) throw new Error('the built artifact declares no policy')
    built = { html, csp }
  }
  return built
}

export const sourceShell = (): string => readFileSync(SOURCE, 'utf8')

export interface Mutant {
  /** Row number in the plan's vector table; the corpus is closed and numbered. */
  n: number
  /** What is planted, in one line, for a failure message that names the construct. */
  what: string
  stage: 'artifact' | 'source'
  /** Every rule that MUST produce a refusal for this mutant. */
  rules: readonly RuleId[]
  /** True when the rules above are the ONLY ones that refuse this mutant, so removing
   *  them makes the document pass entirely. Measured, not assumed. */
  sole: boolean
  bytes: Buffer
  markup?: string
  where: Where
  treeDrops?: string
  /** The policy the document declares; a mutant that edits the inline style has to
   *  recompute it, or the hash pin refuses it first and for the wrong reason. */
  expectedCsp: string
}

/** Where a construct is planted. A token rule must not care, so several rows exist
 *  twice: once in the head or body, once inside the real `<select>` that parse5 empties
 *  and every current engine does not. */
export type Where = 'HEAD' | 'HEAD0' | 'BODY' | 'SELECT' | 'STYLE' | 'ANCHOR' | 'FILE'

/** The last meta of the head: the policy in the artifact, the viewport in the source
 *  shell, which has no policy until the build computes one. */
const HEAD_ANCHOR = (html: string): string => {
  const tag = html.match(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/)?.[0]
  if (tag !== undefined) return tag
  const viewport = html.match(/<meta name="viewport"[^>]*>/)?.[0]
  if (viewport === undefined) throw new Error('no head meta to plant against')
  return viewport
}

const ANCHOR_ATTR = 'href="https://attest-receipts.org/"'

const sha256b64 = (text: string): string =>
  createHash('sha256').update(text, 'utf8').digest('base64')

const CSP = (scriptHash: string, styleHash: string): string =>
  `default-src 'none'; script-src 'sha256-${scriptHash}'; ` +
  `style-src 'sha256-${styleHash}'; connect-src 'none'; ` +
  `base-uri 'none'; form-action 'none'`

/** Plants `what` into `html` and returns the document AND the policy it now declares.
 *  Planting into the stylesheet recomputes the policy on purpose: a mutant whose hash
 *  pin no longer matches is refused before the markup rules ever run, which would make
 *  every stylesheet row measure the pin instead of the rule it names. */
export function plant(html: string, where: Where, what: string): { html: string; csp: string } {
  const declared = (out: string): string => {
    const csp = out.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1]
    return csp ?? ''
  }
  const at = (needle: string, replacement: string): string => {
    if (!html.includes(needle)) throw new Error(`nothing to plant against: ${needle}`)
    return html.replace(needle, () => replacement)
  }
  let out: string
  switch (where) {
    case 'HEAD': {
      const tag = HEAD_ANCHOR(html)
      out = at(tag, `${tag}\n${what}`)
      break
    }
    case 'HEAD0':
      out = at('<head>', `<head>\n${what}`)
      break
    case 'BODY':
      out = at('<main>', `${what}\n<main>`)
      break
    case 'SELECT':
      out = at('<select id="binding-type">', `<select id="binding-type">${what}`)
      break
    case 'ANCHOR':
      out = at(ANCHOR_ATTR, what)
      break
    case 'FILE':
      out = what
      break
    case 'STYLE': {
      const style = html.match(/<style>([\s\S]*?)<\/style>/)
      if (style === null) throw new Error('no inline style to plant against')
      const text = style[1] + what
      out = at(style[0], `<style>${text}</style>`)
      const script = out.match(/<script type="module">([\s\S]*?)<\/script>/)
      if (script === null) throw new Error('no inline module to re-pin')
      const tag = HEAD_ANCHOR(out)
      out = out.replace(
        tag,
        () =>
          `<meta http-equiv="Content-Security-Policy" content="${CSP(sha256b64(script[1]), sha256b64(text))}">`,
      )
      break
    }
  }
  return { html: out, csp: declared(out) }
}

interface Row {
  n: number
  what: string
  where: Where
  rules: readonly RuleId[]
  /** True when the named rules are the ONLY ones that refuse this mutant, so removing
   *  them makes the whole document pass. Measured against the policy, not assumed. */
  sole: boolean
  stage?: 'artifact' | 'source'
  /** The markup planted at `where`. */
  markup?: string
  /** For rows that transform the whole document rather than plant markup. */
  whole?: (html: string) => string
  /** For rows whose payload is bytes no string can carry. */
  raw?: (html: string) => Buffer
  /** For the rows planted inside the select: the element name jsdom's tree loses there
   *  and keeps anywhere else. Measured, and pinned by a test. */
  treeDrops?: string
}

const CSP_RE = /<meta http-equiv="Content-Security-Policy" content="[^"]*">/
const CHARSET = '<meta charset="utf-8">'
const VIEWPORT = '<meta name="viewport" content="width=device-width, initial-scale=1">'
const SOURCE_SCRIPT = '<script type="module" src="/src/main.ts"></script>'

/** Moves the policy meta out of the head and into the body, where a browser ignores it. */
const cspInto = (html: string, at: string): string => {
  const tag = html.match(CSP_RE)?.[0]
  if (tag === undefined) throw new Error('no policy meta to move')
  return html.replace(`${tag}\n`, '').replace(at, () => `${tag}\n${at}`)
}

const ROWS: readonly Row[] = [
  // The head, where a reference the browser resolves by itself would go.
  { n: 1, what: 'a meta refresh', where: 'HEAD', rules: ['R-META'], sole: true,
    markup: '<meta http-equiv="refresh" content="0;url=https://example.invalid/">' },
  { n: 2, what: 'a meta refresh spelled with a capital', where: 'HEAD', rules: ['R-META'], sole: true,
    markup: '<meta http-equiv="Refresh" content="0;url=https://example.invalid/">' },
  { n: 3, what: 'a second policy meta that permits everything', where: 'HEAD', rules: ['R-META'], sole: true,
    markup: '<meta http-equiv="Content-Security-Policy" content="default-src *">' },
  { n: 4, what: 'a duplicated viewport meta', where: 'HEAD', rules: ['R-COUNT'], sole: true,
    markup: VIEWPORT },
  { n: 5, what: 'a base element, which re-points every relative reference', where: 'HEAD',
    rules: ['R-ELEMENT'], sole: true, markup: '<base href="https://example.invalid/">' },
  { n: 6, what: 'a prefetch link', where: 'HEAD', rules: ['R-ELEMENT'], sole: true,
    markup: '<link rel="prefetch" href="https://example.invalid/x">' },
  { n: 7, what: 'an external stylesheet', where: 'HEAD', rules: ['R-ELEMENT'], sole: true,
    markup: '<link rel="stylesheet" href="https://example.invalid/x.css">' },
  { n: 8, what: 'an image in the head', where: 'HEAD', rules: ['R-ELEMENT'], sole: true,
    markup: '<img src="https://example.invalid/p.png">' },

  // The body.
  { n: 9, what: 'the legacy image tag, which every parser turns into img', where: 'BODY',
    rules: ['R-ELEMENT'], sole: true, markup: '<image src="https://example.invalid/p.png">' },
  { n: 10, what: 'an iframe', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<iframe src="https://example.invalid/"></iframe>' },
  { n: 11, what: 'an object', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<object data="https://example.invalid/x"></object>' },
  { n: 12, what: 'an embed', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<embed src="https://example.invalid/x">' },
  { n: 13, what: 'a video poster', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<video poster="https://example.invalid/p.png"></video>' },
  { n: 14, what: 'an audio source', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<audio src="https://example.invalid/a"></audio>' },
  { n: 15, what: 'a picture source set', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<picture><source srcset="https://example.invalid/s 1x"></picture>' },
  { n: 16, what: 'a track', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<track src="https://example.invalid/t">' },
  { n: 17, what: 'a form that posts somewhere', where: 'BODY', rules: ['R-ELEMENT', 'R-VALUE'],
    sole: false,
    markup: '<form action="https://example.invalid/f"><button type="submit">x</button></form>' },
  { n: 18, what: 'a formaction on a button', where: 'BODY', rules: ['R-ATTRIBUTE'], sole: true,
    markup: '<button type="button" formaction="https://example.invalid/b">x</button>' },
  { n: 19, what: 'an image input, which fetches its own picture', where: 'BODY',
    rules: ['R-VALUE', 'R-ATTRIBUTE'], sole: false,
    markup: '<input type="image" src="https://example.invalid/i">' },
  { n: 20, what: 'a submit input', where: 'BODY', rules: ['R-VALUE'], sole: true,
    markup: '<input type="submit">' },
  { n: 21, what: 'the legacy background attribute', where: 'BODY', rules: ['R-ATTRIBUTE'], sole: true,
    markup: '<div background="https://example.invalid/b">x</div>' },
  { n: 22, what: 'a ping on the anchor the carve-out exists for', where: 'BODY',
    rules: ['R-ATTRIBUTE'], sole: true,
    markup: '<a href="https://attest-receipts.org/" ping="https://example.invalid/c">x</a>' },
  { n: 23, what: 'an inline event handler', where: 'BODY', rules: ['R-ATTRIBUTE'], sole: true,
    markup: `<p onclick="fetch('https://example.invalid/')">x</p>` },
  { n: 24, what: 'an event handler in capitals, which the tokenizer lowercases', where: 'BODY',
    rules: ['R-ATTRIBUTE'], sole: true, markup: '<p ONLOAD="x()">x</p>' },
  { n: 25, what: 'a second body carrying an event handler', where: 'BODY',
    rules: ['R-ATTRIBUTE', 'R-COUNT'], sole: false, markup: '<body onload="x()">' },
  { n: 26, what: 'a style attribute fetching a background', where: 'BODY',
    rules: ['R-ATTRIBUTE'], sole: true,
    markup: '<div style="background:url(https://example.invalid/s)">x</div>' },
  { n: 27, what: 'a customised built-in element', where: 'BODY', rules: ['R-ATTRIBUTE'], sole: true,
    markup: '<div is="x-thing">x</div>' },
  { n: 28, what: 'a custom element', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<x-custom href="https://example.invalid/c">x</x-custom>' },

  // Foreign content, where the tree keeps a namespace and the token stream does not.
  { n: 29, what: 'an svg image', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<svg><image href="https://example.invalid/p.png"/></svg>' },
  { n: 30, what: 'an svg image addressed through xlink', where: 'BODY',
    rules: ['R-ELEMENT', 'R-ATTRIBUTE'], sole: false,
    markup: '<svg><image xlink:href="https://example.invalid/p.png"/></svg>' },
  { n: 31, what: 'an svg use, which fetches the document it points at', where: 'BODY',
    rules: ['R-ELEMENT', 'R-ATTRIBUTE'], sole: false,
    markup: '<svg><use xlink:href="https://example.invalid/s.svg#i"/></svg>' },
  { n: 32, what: 'a script inside svg', where: 'BODY', rules: ['R-ELEMENT', 'R-COUNT'], sole: false,
    markup: `<svg><script>fetch('https://example.invalid/')</script></svg>` },
  { n: 33, what: 'an svg anchor with a javascript href', where: 'BODY',
    rules: ['R-ELEMENT', 'R-URL'], sole: false,
    markup: '<svg><a href="javascript:alert(1)">x</a></svg>' },
  { n: 34, what: 'a MathML element carrying an href', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<math><mi href="javascript:alert(1)">m</mi></math>' },

  // Containers whose contents a tree builder parks somewhere else.
  { n: 35, what: 'a template holding an image', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<template><img src="https://example.invalid/t"></template>' },
  { n: 36, what: 'a template inside a template', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<template><template><img src="https://example.invalid/t"></template></template>' },
  { n: 37, what: 'a declarative shadow root holding an image', where: 'BODY',
    rules: ['R-ELEMENT', 'R-ATTRIBUTE'], sole: false,
    markup:
      '<div><template shadowrootmode="open"><img src="https://example.invalid/d"></template></div>' },
  { n: 38, what: 'an image inside noscript', where: 'BODY', rules: ['R-ELEMENT'], sole: true,
    markup: '<noscript><img src="https://example.invalid/n"></noscript>' },
  // Not sole, and measured: an image inside noscript in the HEAD is also a parse error
  // (`disallowed-content-in-noscript-in-head`), so two rules refuse it independently.
  { n: 39, what: 'an image inside noscript, in the head', where: 'HEAD',
    rules: ['R-ELEMENT', 'R-PARSE'], sole: false,
    markup: '<noscript><img src="https://example.invalid/n"></noscript>' },

  // The select. Every row above that a tree builder would have swallowed, planted where
  // it swallows it: parse5 empties the select, current engines do not.
  { n: 40, what: 'a meta refresh inside the select', where: 'SELECT', rules: ['R-META'], sole: true,
    treeDrops: 'meta',
    markup: '<meta http-equiv="refresh" content="9999;url=https://example.invalid/">' },
  { n: 41, what: 'an image inside the select', where: 'SELECT', rules: ['R-ELEMENT'], sole: true,
    treeDrops: 'img',
    markup: '<img src="https://example.invalid/si">' },
  { n: 42, what: 'a foreign anchor inside the select', where: 'SELECT', rules: ['R-URL'], sole: true,
    treeDrops: 'a',
    markup: '<a href="https://example.invalid/">x</a>' },
  // Not sole, and measured: the tree builder ignores <svg> inside a select, so <image/>
  // is never foreign content and its trailing solidus is a parse error too.
  { n: 43, what: 'an svg image inside the select', where: 'SELECT',
    rules: ['R-ELEMENT', 'R-PARSE'], sole: false,
    treeDrops: 'image',
    markup: '<svg><image href="https://example.invalid/sv"/></svg>' },
  { n: 44, what: 'a stylesheet inside the select', where: 'SELECT', rules: ['R-ELEMENT'], sole: true,
    treeDrops: 'link',
    markup: '<link rel="stylesheet" href="https://example.invalid/s.css">' },
  { n: 45, what: 'a base inside the select', where: 'SELECT', rules: ['R-ELEMENT'], sole: true,
    treeDrops: 'base',
    markup: '<base href="https://example.invalid/">' },
  { n: 46, what: 'a declarative shadow root inside the select', where: 'SELECT',
    rules: ['R-ELEMENT', 'R-ATTRIBUTE'], sole: false,
    treeDrops: 'div',
    markup:
      '<div><template shadowrootmode="open"><img src="https://example.invalid/sd"></template></div>' },

  // The anchor the carve-out exists for, given one attribute more than it may have.
  { n: 73, what: 'the anchor opens a new context', where: 'ANCHOR', rules: ['R-ATTRIBUTE'], sole: true,
    markup: 'href="https://attest-receipts.org/" target="_blank"' },
  { n: 74, what: 'the anchor carries a rel', where: 'ANCHOR', rules: ['R-ATTRIBUTE'], sole: true,
    markup: 'href="https://attest-receipts.org/" rel="noopener"' },
  { n: 75, what: 'the anchor downloads instead of navigating', where: 'ANCHOR',
    rules: ['R-ATTRIBUTE'], sole: true, markup: 'href="https://attest-receipts.org/" download' },

  // The two elements the artifact carries exactly once, and their shapes.
  { n: 88, what: 'the inline style gains a media attribute', where: 'FILE', rules: ['R-ATTRIBUTE'],
    sole: true, whole: (html) => html.replace('<style>', '<style media="all">') },
  { n: 89, what: 'a second inline style', where: 'HEAD', rules: ['R-COUNT'], sole: true,
    markup: '<style>x{}</style>' },
  { n: 90, what: 'a second inline module', where: 'HEAD', rules: ['R-COUNT'], sole: true,
    markup: '<script type="module"></script>' },
  { n: 91, what: 'the inline module gains an external source', where: 'FILE',
    rules: ['R-ATTRIBUTE'], sole: true,
    whole: (html) =>
      html.replace('<script type="module">', '<script type="module" src="https://example.invalid/m.js">') },
  { n: 92, what: 'the module is declared a classic script', where: 'FILE', rules: ['R-VALUE'],
    sole: true,
    whole: (html) => html.replace('<script type="module">', '<script type="text/javascript">') },
  { n: 93, what: 'the module declares no type at all', where: 'FILE', rules: ['R-VALUE'], sole: true,
    whole: (html) => html.replace('<script type="module">', '<script>') },

  // The source shell, whose stage allows a different script and neither style nor policy.
  { n: 94, what: 'the source shell inlines its module instead of referencing it', where: 'FILE',
    stage: 'source', rules: ['R-VALUE'], sole: true,
    whole: (html) => html.replace(SOURCE_SCRIPT, '<script type="module"></script>') },
  { n: 95, what: 'the source shell references its module by another path', where: 'FILE',
    stage: 'source', rules: ['R-VALUE'], sole: true,
    whole: (html) =>
      html.replace(SOURCE_SCRIPT, '<script type="module" src="./src/main.ts"></script>') },
  { n: 96, what: 'the source shell declares a policy the build has not computed', where: 'FILE',
    stage: 'source', rules: ['R-META'], sole: true,
    whole: (html) =>
      html.replace(
        CHARSET,
        `${CHARSET}\n<meta http-equiv="Content-Security-Policy" content="default-src 'none'">`,
      ) },
  { n: 97, what: 'the source shell carries an inline style', where: 'FILE', stage: 'source',
    rules: ['R-ELEMENT'], sole: true,
    whole: (html) => html.replace(CHARSET, `${CHARSET}\n<style>body{margin:0}</style>`) },

  // Position: a policy the browser reads too late, and a charset it reads after deciding.
  { n: 98, what: 'the policy meta sits in the body, where it does not apply', where: 'FILE',
    rules: ['R-META'], sole: true, whole: (html) => cspInto(html, '<main>') },
  { n: 99, what: 'the policy meta sits after the module it should govern', where: 'FILE',
    rules: ['R-META'], sole: true, whole: (html) => cspInto(html, '<style>') },
  { n: 100, what: 'the charset is no longer the first thing in the head', where: 'FILE',
    rules: ['R-META'], sole: true,
    whole: (html) => html.replace(`${CHARSET}\n`, '').replace(VIEWPORT, `${VIEWPORT}\n${CHARSET}`) },
  { n: 101, what: 'the charset is pushed past the window the browser prescans', where: 'HEAD0',
    rules: ['R-META'], sole: true, markup: `<!--${'p'.repeat(1_100)}-->` },

  // The one link the document carries, and every other thing an href could be.
  { n: 47, what: 'a javascript href', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="javascript:alert(1)">x</a>' },
  { n: 48, what: 'a data href carrying a document', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="data:text/html,<script>alert(1)</script>">x</a>' },
  { n: 49, what: 'a vbscript href', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="vbscript:MsgBox(1)">x</a>' },
  { n: 50, what: 'a protocol-relative href, which on a file base is a network share',
    where: 'BODY', rules: ['R-URL'], sole: true, markup: '<a href="//example.invalid/x">x</a>' },
  { n: 51, what: 'a file href with a host', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="file://example.invalid/share/x">x</a>' },
  { n: 52, what: 'the right host over the wrong scheme', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="http://attest-receipts.org/">x</a>' },
  { n: 53, what: 'another host', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="https://example.invalid/">x</a>' },
  { n: 54, what: 'a host the allowed one is only a prefix of', where: 'BODY', rules: ['R-URL'],
    sole: true, markup: '<a href="https://attest-receipts.org.example.invalid/">x</a>' },
  { n: 55, what: 'the allowed host spelled as a username', where: 'BODY', rules: ['R-URL'],
    sole: true, markup: '<a href="https://attest-receipts.org@example.invalid/">x</a>' },
  { n: 56, what: 'a mailto href', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="mailto:x@example.invalid">x</a>' },
  { n: 57, what: 'a blob href', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="blob:https://example.invalid/u">x</a>' },
  { n: 58, what: 'an about href', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="about:blank">x</a>' },
  { n: 59, what: 'an empty href, which is the document itself', where: 'BODY', rules: ['R-URL'],
    sole: true, markup: '<a href="">x</a>' },
  { n: 60, what: 'a query-only href', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="?q=1">x</a>' },
  { n: 61, what: 'a relative href, which is a file beside this one', where: 'BODY',
    rules: ['R-URL'], sole: true, markup: '<a href="relative/page.html">x</a>' },
  { n: 62, what: 'an href no URL parser can read', where: 'BODY', rules: ['R-URL'], sole: true,
    markup: '<a href="https://a b/">x</a>' },
  { n: 63, what: 'a fragment naming nothing in the document', where: 'BODY', rules: ['R-REF'],
    sole: true, markup: '<a href="#nope">x</a>' },
  { n: 64, what: 'a bare hash, which names nothing at all', where: 'BODY', rules: ['R-URL'],
    sole: true, markup: '<a href="#">x</a>' },

  // The allowed link, spelled the many ways a browser reads as the same link.
  { n: 65, what: 'the allowed link in capitals', where: 'ANCHOR', rules: ['R-URL-CANONICAL'],
    sole: true, markup: 'href="HTTPS://attest-receipts.org/"' },
  { n: 66, what: 'the allowed link without its slashes', where: 'ANCHOR',
    rules: ['R-URL-CANONICAL'], sole: true, markup: 'href="https:attest-receipts.org"' },
  { n: 67, what: 'the allowed link with its first letter as a character reference',
    where: 'ANCHOR', rules: ['R-URL-CANONICAL'], sole: true,
    markup: 'href="&#104;ttps://attest-receipts.org/"' },
  { n: 68, what: 'the allowed link with a named colon', where: 'ANCHOR',
    rules: ['R-URL-CANONICAL'], sole: true, markup: 'href="https&colon;//attest-receipts.org/"' },
  { n: 69, what: 'the allowed link with named slashes', where: 'ANCHOR',
    rules: ['R-URL-CANONICAL'], sole: true, markup: 'href="https:&sol;&sol;attest-receipts.org/"' },
  { n: 70, what: 'the allowed link without its trailing slash', where: 'ANCHOR',
    rules: ['R-URL-CANONICAL'], sole: true, markup: 'href="https://attest-receipts.org"' },
  { n: 71, what: 'the allowed link in single quotes', where: 'ANCHOR', rules: ['R-URL-CANONICAL'],
    sole: true, markup: `href='https://attest-receipts.org/'` },
  { n: 72, what: 'the allowed link unquoted', where: 'ANCHOR', rules: ['R-URL-CANONICAL'],
    sole: true, markup: 'href=https://attest-receipts.org/' },

  // A label pointing at nothing, and a userinfo the host allowlist would not have seen.
  { n: 76, what: 'a label naming a control that does not exist', where: 'BODY', rules: ['R-REF'],
    sole: true, markup: '<label for="no-such-id">x</label>' },
  { n: 108, what: 'the allowed host reached through a username', where: 'ANCHOR',
    rules: ['R-URL'], sole: true, markup: 'href="https://someone@attest-receipts.org/"' },

  // The stylesheet, which is text the tokenizer never turns into tags and which can
  // still fetch. Every row is planted with the policy hash recomputed, or the pin would
  // refuse it first and the row would be measuring the pin instead of the rule.
  { n: 77, what: 'a background image', where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: 'body{background:url(https://example.invalid/b)}' },
  { n: 78, what: 'an imported stylesheet', where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: '@import url(https://example.invalid/i.css);' },
  { n: 79, what: 'url spelled with a hex escape', where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: 'body{background:\\75 rl(https://example.invalid/b)}' },
  { n: 80, what: 'url spelled with a character escape', where: 'STYLE', rules: ['R-CSS'],
    sole: true, markup: 'body{background:u\\rl(https://example.invalid/b)}' },
  { n: 81, what: 'url in capitals', where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: 'body{background:URL(https://example.invalid/b)}' },
  { n: 82, what: 'import spelled with a hex escape', where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: '@\\69 mport "https://example.invalid/i.css";' },
  { n: 83, what: 'an image set', where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: 'body{background:image-set("https://example.invalid/b" 1x)}' },
  { n: 84, what: 'a fetch hidden between two strings that look like comment markers',
    where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: 'body{--x:"/*"} body::before{content:url(https://example.invalid/c)} body{--y:"*/"}' },
  { n: 85, what: 'a fetch wrapped in strings that look like a comment', where: 'STYLE',
    rules: ['R-CSS'], sole: true,
    markup: 'body::before{content:"/*" url(https://example.invalid/c) "*/"}' },
  { n: 86, what: 'url with a form feed ending the escape', where: 'STYLE', rules: ['R-CSS'],
    sole: true, markup: 'body{background:\\75\fRl(https://example.invalid/b)}' },
  { n: 87, what: 'the image function', where: 'STYLE', rules: ['R-CSS'], sole: true,
    markup: 'body{background:image(https://example.invalid/b)}' },

  // Input the document could not have been decoded from, and parse errors.
  {
    n: 102,
    what: 'a UTF-8 byte order mark prepended to the file',
    where: 'FILE',
    rules: ['R-INPUT'],
    sole: true,
    raw: (html) => Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(html, 'utf8')]),
  },
  {
    n: 103,
    what: 'a lone 0xFF byte in the footer, which is not UTF-8',
    where: 'FILE',
    rules: ['R-INPUT'],
    sole: true,
    raw: (html) => {
      const i = html.indexOf('attest-receipts.org</a>')
      return Buffer.concat([
        Buffer.from(html.slice(0, i), 'utf8'),
        Buffer.from([0xff]),
        Buffer.from(html.slice(i), 'utf8'),
      ])
    },
  },
  {
    n: 104,
    what: 'the anchor carries href twice, the second one javascript:',
    where: 'ANCHOR',
    rules: ['R-PARSE'],
    sole: true,
    markup: 'href="https://attest-receipts.org/" href="javascript:1"',
  },
  {
    n: 105,
    what: 'a NUL byte inside the footer text',
    where: 'FILE',
    rules: ['R-PARSE'],
    sole: true,
    whole: (html) => html.replace('attest-receipts.org</a>', 'attest-receipts.org\u0000</a>'),
  },
  {
    n: 106,
    what: 'a comment opened and never closed',
    where: 'BODY',
    rules: ['R-PARSE'],
    sole: true,
    markup: '<!-- unclosed comment',
  },
  {
    n: 107,
    what: 'the anchor carries HREF and href, and the first one wins',
    where: 'ANCHOR',
    rules: ['R-PARSE'],
    sole: true,
    markup: 'HREF="https://attest-receipts.org/" href="javascript:1"',
  },
]

let corpus: readonly Mutant[] | null = null

export function mutants(): readonly Mutant[] {
  if (corpus === null) {
    const art = artifact()
    corpus = ROWS.map((row) => {
      const stage = row.stage ?? 'artifact'
      const base = stage === 'artifact' ? art.html : sourceShell()
      const baseCsp = stage === 'artifact' ? art.csp : ''
      if (row.raw !== undefined)
        return { ...row, stage, bytes: row.raw(base), expectedCsp: baseCsp } as Mutant
      if (row.whole !== undefined)
        return {
          ...row,
          stage,
          bytes: Buffer.from(row.whole(base), 'utf8'),
          expectedCsp: baseCsp,
        } as Mutant
      if (row.markup === undefined) throw new Error(`row ${row.n} plants nothing`)
      const grown = plant(base, row.where, row.markup)
      return { ...row, stage, bytes: Buffer.from(grown.html, 'utf8'), expectedCsp: grown.csp } as Mutant
    })
  }
  return corpus
}

export const mutant = (n: number): Mutant => {
  const found = mutants().find((m) => m.n === n)
  if (found === undefined) throw new Error(`no mutant numbered ${n}`)
  return found
}

/** The markup a numbered row plants, so another suite can plant the same construct
 *  somewhere else instead of writing a second copy of it. */
export const mutantMarkup = (n: number): string => {
  const row = ROWS.find((r) => r.n === n)
  if (row?.markup === undefined) throw new Error(`row ${n} plants no markup`)
  return row.markup
}
