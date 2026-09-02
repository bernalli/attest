import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * The mutant corpus: one entry per construct the shell policy must refuse, planted into
 * the REAL artifact (or the real source shell) rather than into a fixture that shares
 * the author's blind spots.
 *
 * Every entry names the rule that must refuse it, so a rule can be removed and the
 * mutant watched to go from refused to accepted — the only evidence that a rule is
 * load-bearing rather than decorative.
 */

const ROOT = fileURLToPath(new URL('../..', import.meta.url))
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
  /** The policy the document declares; a mutant that edits the inline style has to
   *  recompute it, or the hash pin refuses it first and for the wrong reason. */
  expectedCsp: string
}

/** Where a construct is planted. A token rule must not care, so several rows exist
 *  twice: once in the head or body, once inside the real `<select>` that parse5 empties
 *  and every current engine does not. */
export type Where = 'HEAD' | 'HEAD0' | 'BODY' | 'SELECT' | 'STYLE' | 'ANCHOR' | 'FILE'

const CSP_TAG = (html: string): string => {
  const tag = html.match(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/)?.[0]
  if (tag === undefined) throw new Error('no policy meta to plant against')
  return tag
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
      const tag = CSP_TAG(html)
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
      const tag = CSP_TAG(out)
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
  sole: boolean
  stage?: 'artifact' | 'source'
  /** For rows that transform the whole file rather than plant markup. */
  whole?: (html: string) => string
  /** For rows whose payload is bytes no string can carry. */
  raw?: (html: string) => Buffer
}

const ROWS: readonly Row[] = [
  // Parse errors and undecodable input.
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
  },
]

/** The markup each planted row carries, kept beside the row it belongs to. */
const PAYLOAD: Record<number, string> = {
  104: 'href="https://attest-receipts.org/" href="javascript:1"',
  106: '<!-- unclosed comment',
}

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
      const grown = plant(base, row.where, PAYLOAD[row.n])
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
