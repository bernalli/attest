#!/usr/bin/env node
// The build's last stage: a folder of files becomes ONE document.
//
// It is written to REFUSE rather than to cope. Every invariant is checked on the
// assembled output, and nothing is written when one of them fails, because the file
// this produces is downloaded once and never re-checked by anyone.
//
// No dependency: the shapes it parses are the ones vite emits, and a build step that
// pulled in a parser would widen the supply chain of an artifact whose whole argument
// is that it has almost none.

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

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

/** Every invariant the finished artifact must satisfy. Used both to validate what this
 *  script just assembled and, through `--check`, to validate a file someone hands back. */
function validate(html) {
  const scripts = html.match(/<script\b/gi) ?? []
  if (scripts.length !== 1) refuse(`the artifact must carry exactly one script, found ${scripts.length}`)
  const styles = html.match(/<style\b/gi) ?? []
  if (styles.length !== 1) refuse(`the artifact must carry exactly one inline style, found ${styles.length}`)

  if (/<script\b[^>]*\ssrc=/i.test(html)) refuse('the artifact still references an external script')
  if (/<link\b[^>]*\shref=/i.test(html)) refuse('the artifact still references an external stylesheet or link')
  if (/<img\b[^>]*\ssrc=/i.test(html)) refuse('the artifact references an image; its policy has no img-src')
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

  validate(html)
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
    validate(readFileSync(checkTarget, 'utf8'))
    process.stdout.write(`inline: ${checkTarget} satisfies every artifact invariant\n`)
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
