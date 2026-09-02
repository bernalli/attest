#!/usr/bin/env node
// The build's last stage: a folder of files becomes ONE document.
//
// It is written to REFUSE rather than to cope. Every invariant is checked on the
// assembled output, and nothing is written when one of them fails, because the file
// this produces is downloaded once and never re-checked by anyone.
//
// The markup rules live in ./shell-policy.mjs and are an ALLOWLIST over the HTML
// tokenizer's start-tag stream: every element name, every attribute, every value and
// every resolved URL must be one the policy enumerates, wherever the tag occurs. They
// used to be regular expressions over the raw text, and that was wrong three times in a
// row - the browser decodes character references, drops tabs and newlines and
// lowercases the scheme BEFORE it decides what a link is, so a check on the spelling
// could always be spelled around. The rules deliberately run on TOKENS and not on a
// parsed tree: tree builders disagree (parse5 still drops tags inside <select> that
// current engines keep), while a start-tag token becomes an element in every one of
// them. The tokenizer is parse5, which this package already installs for its tests:
// declaring it here installs nothing new, the SBOM is unchanged, and the shipped
// artifact carries no byte of it. What changes is only that the same code which already
// runs in `npm test` now also runs here, one step later in the same job.

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { decodeShell, scriptAndStyleText, tokenizeShell, validateShell } from './shell-policy.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const PKG = resolve(HERE, '..')

/** Request-making APIs and resource references. The list is closed: widening it is a
 *  deliberate edit, never a runtime choice. `https` is NOT on it — the footer carries
 *  anchor hrefs a reader may choose to follow, which are not requests this page makes. */
const FORBIDDEN = [
  'fetch(', 'XMLHttpRequest', 'new WebSocket', 'sendBeacon', 'EventSource',
  'importScripts', 'serviceWorker', 'new Worker', 'import(',
]

const CSP = (scriptHash, styleHash) =>
  `default-src 'none'; script-src 'sha256-${scriptHash}'; ` +
  `style-src 'sha256-${styleHash}'; connect-src 'none'; ` +
  `base-uri 'none'; form-action 'none'`

const sha256b64 = (text) => createHash('sha256').update(text, 'utf8').digest('base64')

class InlineError extends Error {}
const refuse = (message) => {
  throw new InlineError(message)
}

/** Every invariant the finished artifact must satisfy. Used both on what this script
 *  just assembled and, through `--check`, on a file someone hands back — where it is a
 *  CONSISTENCY check and never an identity one. The policy pins the script that is IN
 *  the file, so an attacker who rewrites the script and recomputes the hash passes:
 *  measured 2026-09-01, a copy whose whole module had been replaced with
 *  `document.body.textContent = "Receipt verifies"` exited 0 here and rendered that
 *  sentence in both engines. Identity is the published SHA-256 of the whole file. */
function validate(bytes) {
  let html
  try {
    html = decodeShell(bytes)
  } catch (e) {
    refuse(`R-INPUT at document@0: ${e instanceof Error ? e.message : String(e)}`)
  }

  if (html.includes('import.meta')) refuse('the artifact contains import.meta, which an inline module cannot resolve')

  for (const token of FORBIDDEN) {
    if (html.includes(token)) refuse(`the artifact contains a request-making API: ${token}`)
  }

  const leftover = html.match(/__[A-Z][A-Z0-9_]*__/)
  if (leftover) refuse(`the build left a placeholder unsubstituted: ${leftover[0]}`)

  const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)
  if (!script) refuse('the artifact has no inline module to pin')
  const style = html.match(/<style>([\s\S]*?)<\/style>/)
  if (!style) refuse('the artifact has no inline style to pin')

  const declared = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)
  if (!declared) refuse('the artifact declares no content security policy')
  const expected = CSP(sha256b64(script[1]), sha256b64(style[1]))
  if (declared[1] !== expected) {
    refuse(
      'the content security policy does not pin these bytes — the sha256 hash in the ' +
        `policy does not match the inline content.\n  declared: ${declared[1]}\n  expected: ${expected}`,
    )
  }

  const refusals = validateShell(bytes, { stage: 'artifact', expectedCsp: expected })
  if (refusals.length > 0) {
    refuse(refusals.map((r) => `${r.rule} at ${r.where}: ${r.detail}`).join('\n  '))
  }

  // The hash above pins what the REGEX captured, and the tokenizer can end an element
  // later than the regex does: `<!--<script>` inside the module puts it into its
  // double-escaped state, so the first `</script>` does not close anything and the
  // browser executes past the point the policy covers.
  const text = scriptAndStyleText(tokenizeShell(html))
  if (text.script !== script[1] || text.style !== style[1]) {
    refuse(
      'coherence: the tokenizer and the hash pin disagree on where the inline script or style ends',
    )
  }
  return html
}

function build(inDir, outFile) {
  const indexPath = join(inDir, 'index.html')
  let html = readFileSync(indexPath, 'utf8')

  const scriptTags = [...html.matchAll(/<script\b[^>]*><\/script>/gi)]
  if (scriptTags.length !== 1)
    refuse(`expected exactly one script tag in ${indexPath}, found ${scriptTags.length}`)
  const scriptSrc = scriptTags[0][0].match(/\ssrc="([^"]+)"/i)
  if (!scriptSrc) refuse('the script tag in the build output has no src to inline')

  const linkTags = [...html.matchAll(/<link\b[^>]*>/gi)]
  const styleLinks = linkTags.filter((t) => /rel="stylesheet"/i.test(t[0]))
  if (styleLinks.length !== 1)
    refuse(`expected exactly one stylesheet link in ${indexPath}, found ${styleLinks.length}`)
  const otherLinks = linkTags.filter((t) => !/rel="stylesheet"/i.test(t[0]))
  if (otherLinks.length > 0)
    refuse(`the build output references something this artifact cannot carry: ${otherLinks[0][0]}`)
  const styleHref = styleLinks[0][0].match(/\shref="([^"]+)"/i)
  if (!styleHref) refuse('the stylesheet link in the build output has no href to inline')

  const read = (ref) => readFileSync(join(inDir, ref.replace(/^\.?\//, '')), 'utf8')
  const js = read(scriptSrc[1]).trim()
  const css = read(styleHref[1]).trim()

  // A closing tag inside the content would end the element early and silently change
  // what the browser executes — and what the hash below would then be pinning.
  if (/<\/script/i.test(js)) refuse('the bundle contains a closing script tag and cannot be inlined')
  if (/<\/style/i.test(css)) refuse('the stylesheet contains a closing style tag and cannot be inlined')

  // Replacement FUNCTIONS, never replacement strings: a bundle contains `$` by the
  // hundred, and `String.replace` reads `$&` / `$\`` / `$'` in a string replacement as
  // instructions. Measured here: the first attempt re-inserted the whole `<script src>`
  // tag it was supposed to remove, producing an artifact with two scripts — which the
  // validator caught, and which nothing else would have.
  html = html
    .replace(scriptTags[0][0], () => `<script type="module">${js}</script>`)
    .replace(styleLinks[0][0], () => `<style>${css}</style>`)

  const versions = {
    __DESKTOP_VERSION__: JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8')).version,
    __ATTEST_VERIFIER_VERSION__: JSON.parse(
      readFileSync(join(PKG, '..', 'verifiers', 'ts', 'package.json'), 'utf8'),
    ).version,
  }
  for (const [placeholder, value] of Object.entries(versions)) {
    html = html.split(placeholder).join(value)
  }

  const csp = `<meta http-equiv="Content-Security-Policy" content="${CSP(sha256b64(js), sha256b64(css))}">`
  if (!html.includes('<meta charset="utf-8">'))
    refuse('the shell has no charset meta to anchor the policy to')
  html = html.replace('<meta charset="utf-8">', () => `<meta charset="utf-8">\n${csp}`)

  validate(Buffer.from(html, 'utf8'))
  writeFileSync(outFile, html)
  return html
}

function main(argv) {
  const arg = (name, fallback) => {
    const i = argv.indexOf(name)
    return i === -1 ? fallback : argv[i + 1]
  }
  const checkTarget = arg('--check', null)
  if (checkTarget !== null) {
    validate(readFileSync(checkTarget))
    process.stdout.write(
      `inline: ${checkTarget} is internally consistent — one inline module, one inline style, ` +
        'no external reference, and a policy that pins the bytes PRESENT in this file.\n' +
        'inline: that says NOTHING about whether these are the bytes the project published. ' +
        'A rewritten script with a recomputed hash passes this check. Compare the file\'s ' +
        'SHA-256 with the one published beside the download.\n',
    )
    return
  }
  const inDir = resolve(PKG, arg('--in', 'dist'))
  const outFile = resolve(PKG, arg('--out', join('dist', 'attest-verifier.html')))
  const html = build(inDir, outFile)
  process.stdout.write(`inline: wrote ${outFile} (${html.length} bytes)\n`)
}

try {
  main(process.argv.slice(2))
} catch (e) {
  process.stderr.write(`inline: ${e instanceof Error ? e.message : String(e)}\n`)
  process.exit(1)
}
