import { beforeAll, describe, expect, test } from 'vitest'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * The build's last stage turns a folder of files into ONE document.
 *
 * That stage is where the artifact's safety properties are decided, so it is written to
 * refuse rather than to cope: every invariant below is checked on the OUTPUT, after it
 * has been assembled, and nothing is written when one of them does not hold. A build
 * that quietly produced a slightly-wrong file would be the worst outcome available —
 * the file is downloaded once, and nobody re-checks it.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const INLINER = join(ROOT, 'tools', 'inline.mjs')
const ARTIFACT = join(ROOT, 'dist', 'attest-verifier.html')

const sha256b64 = (text: string): string =>
  createHash('sha256').update(text, 'utf8').digest('base64')

function inline(dir: string, out = join(dir, 'attest-verifier.html')) {
  return spawnSync(process.execPath, [INLINER, '--in', dir, '--out', out], { encoding: 'utf8' })
}

function check(file: string) {
  return spawnSync(process.execPath, [INLINER, '--check', file], { encoding: 'utf8' })
}

/** A minimal but STRUCTURALLY REAL vite-style output: the shapes the inliner must
 *  handle are the ones vite emits, so the fixtures imitate them rather than inventing
 *  a simpler markup the real build never produces. */
function fixtureDist(options: { js?: string; css?: string; head?: string; body?: string }): string {
  const dir = mkdtempSync(join(tmpdir(), 'inline-fixture-'))
  mkdirSync(join(dir, 'assets'))
  writeFileSync(join(dir, 'assets', 'app.js'), options.js ?? 'document.title = "ok"\n')
  writeFileSync(join(dir, 'assets', 'app.css'), options.css ?? 'body{margin:0}\n')
  writeFileSync(
    join(dir, 'index.html'),
    `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>t</title>\n` +
      `<script type="module" crossorigin src="./assets/app.js"></script>\n` +
      `<link rel="stylesheet" crossorigin href="./assets/app.css">\n${options.head ?? ''}</head>\n` +
      `<body>\n<p>__DESKTOP_VERSION__ __ATTEST_VERIFIER_VERSION__</p>\n${options.body ?? ''}</body>\n</html>\n`,
  )
  return dir
}

describe('the inliner refuses rather than copes', () => {
  test('a dist with two scripts is refused, and nothing is written', () => {
    const dir = fixtureDist({ head: '<script type="module" crossorigin src="./assets/app.js"></script>\n' })
    const run = inline(dir)

    expect(run.status).not.toBe(0)
    expect(`${run.stderr}`).toMatch(/script/i)
    expect(existsSync(join(dir, 'attest-verifier.html'))).toBe(false)
  })

  test('a dist with no stylesheet is refused', () => {
    const dir = mkdtempSync(join(tmpdir(), 'inline-nocss-'))
    mkdirSync(join(dir, 'assets'))
    writeFileSync(join(dir, 'assets', 'app.js'), 'void 0\n')
    writeFileSync(
      join(dir, 'index.html'),
      '<!doctype html><html><head><script type="module" src="./assets/app.js"></script></head><body>__DESKTOP_VERSION__ __ATTEST_VERIFIER_VERSION__</body></html>',
    )
    const run = inline(dir)

    expect(run.status).not.toBe(0)
    expect(`${run.stderr}`).toMatch(/stylesheet|style/i)
    expect(existsSync(join(dir, 'attest-verifier.html'))).toBe(false)
  })

  test.each([
    ['fetch(', 'const go = () => fetch("https://example.invalid/x")\n'],
    ['XMLHttpRequest', 'const x = new XMLHttpRequest()\n'],
    ['new WebSocket', 'const s = new WebSocket("wss://example.invalid")\n'],
    ['sendBeacon', 'navigator.sendBeacon("/x")\n'],
    ['EventSource', 'const e = new EventSource("/x")\n'],
    ['importScripts', 'importScripts("/x.js")\n'],
    ['serviceWorker', 'navigator.serviceWorker.register("/sw.js")\n'],
    ['new Worker', 'const w = new Worker("/w.js")\n'],
    ['import(', 'const m = import("./x.js")\n'],
  ])('a planted %s is caught by the scanner', (token, js) => {
    // The scanner's own negative self-test: a scanner that has quietly stopped matching
    // would let every one of these through while the suite stayed green.
    const dir = fixtureDist({ js })
    const run = inline(dir)

    expect(run.status, `${token} was not caught`).not.toBe(0)
    expect(`${run.stderr}`).toContain(token)
    expect(existsSync(join(dir, 'attest-verifier.html'))).toBe(false)
  })

  test('a placeholder the build did not substitute is refused', () => {
    const dir = fixtureDist({ body: '<p>__SOMETHING_ELSE__</p>\n' })
    const run = inline(dir)

    expect(run.status).not.toBe(0)
    expect(`${run.stderr}`).toContain('__SOMETHING_ELSE__')
  })

  test('a leftover external reference is refused', () => {
    const dir = fixtureDist({ head: '<link rel="icon" href="./favicon.png">\n' })
    const run = inline(dir)

    expect(run.status).not.toBe(0)
    expect(existsSync(join(dir, 'attest-verifier.html'))).toBe(false)
  })

  test.each([
    ['a meta refresh', '<meta http-equiv="refresh" content="0;url=https://example.invalid/">'],
    ['an iframe', '<iframe src="https://example.invalid/"></iframe>'],
    ['an SVG image addressed with xlink:href', '<svg><image xlink:href="https://example.invalid/p.png"/></svg>'],
    ['an SVG use addressed with xlink:href', '<svg><use xlink:href="https://example.invalid/s.svg#i"/></svg>'],
    ['an anchor carrying ping', '<a href="#" ping="https://example.invalid/c">x</a>'],
    ['a base element', '<base href="https://example.invalid/">'],
    ['an object', '<object data="https://example.invalid/x"></object>'],
    ['a video poster', '<video poster="https://example.invalid/p.png"></video>'],
  ])('%s reaches the shell: refused, and nothing is written', (_what, markup) => {
    // Measured 2026-09-01: with this artifact's own policy in force, every construct
    // here is refused by the CSP EXCEPT the meta refresh, which both engines followed
    // off the file. The policy is the second belt; this is the first.
    const dir = fixtureDist({ body: markup })
    const run = inline(dir)

    expect(run.status, `${_what} was not refused`).not.toBe(0)
    expect(existsSync(join(dir, 'attest-verifier.html'))).toBe(false)
  })

  test('the footer anchor the artifact really carries is NOT refused', () => {
    // Without this the block above is satisfied by a rule that refuses everything.
    const dir = fixtureDist({ body: '<a href="https://attest-receipts.org/">attest-receipts.org</a>\n' })
    expect(inline(dir).status).toBe(0)
  })
})

describe('the artifact the build actually produces', () => {
  let html = ''
  let firstHash = ''
  let secondHash = ''

  beforeAll(() => {
    const build = () => {
      const run = spawnSync('npm', ['run', 'build'], { cwd: ROOT, encoding: 'utf8' })
      if (run.status !== 0) throw new Error(`build failed:\n${run.stdout}\n${run.stderr}`)
      return createHash('sha256').update(readFileSync(ARTIFACT)).digest('hex')
    }
    firstHash = build()
    secondHash = build()
    html = readFileSync(ARTIFACT, 'utf8')
  }, 180_000)

  test('two consecutive builds produce the same bytes', () => {
    // Only self-randomisation is measured here — one machine, one node_modules. The
    // property a published checksum needs is cross-machine reproducibility, and that is
    // measured by comparing this hash with the one CI builds.
    expect(firstHash).toEqual(secondHash)
  })

  test('exactly one inline script and one inline style, and nothing external', () => {
    expect(html.match(/<script/g) ?? []).toHaveLength(1)
    expect(html.match(/<style/g) ?? []).toHaveLength(1)
    expect(html).not.toMatch(/<script[^>]*\ssrc=/i)
    expect(html).not.toMatch(/<link[^>]*\shref=/i)
    expect(html).not.toMatch(/<img[^>]*\ssrc=/i)
    expect(html).not.toContain('import.meta')
  })

  test('the content security policy is exactly the one the plan pins, over these bytes', () => {
    const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1]
    const style = html.match(/<style>([\s\S]*?)<\/style>/)?.[1]
    expect(script, 'no inline module found').toBeTruthy()
    expect(style, 'no inline style found').toBeTruthy()

    const csp = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)?.[1]
    expect(csp).toEqual(
      `default-src 'none'; script-src 'sha256-${sha256b64(script!)}'; ` +
        `style-src 'sha256-${sha256b64(style!)}'; connect-src 'none'; ` +
        `base-uri 'none'; form-action 'none'`,
    )
    expect(csp).not.toContain('unsafe-inline')
  })

  test('no request-making API survives into the shipped bytes', () => {
    for (const token of [
      'fetch(', 'XMLHttpRequest', 'new WebSocket', 'sendBeacon', 'EventSource',
      'importScripts', 'serviceWorker', 'new Worker', 'import(',
    ]) {
      expect(html.includes(token), `the artifact contains ${token}`).toBe(false)
    }
  })

  test('the footer carries both version numbers, and no placeholder survived', () => {
    const desktopVersion = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version
    const verifierVersion = JSON.parse(
      readFileSync(join(ROOT, '..', 'verifiers', 'ts', 'package.json'), 'utf8'),
    ).version

    expect(html).toContain(desktopVersion)
    expect(html).toContain(verifierVersion)
    expect(html).not.toMatch(/__[A-Z][A-Z0-9_]*__/)
  })

  test('the boot failsafe is in the shipped markup, once', () => {
    expect(html.match(/id="boot-failsafe"/g) ?? []).toHaveLength(1)
    expect(html).toContain('did not start')
  })

  test('--check passes on the artifact and fails on a tampered copy', () => {
    expect(check(ARTIFACT).status).toBe(0)

    // One byte inside the inline script, which is what a CSP hash exists to notice.
    const dir = mkdtempSync(join(tmpdir(), 'inline-tamper-'))
    const tampered = join(dir, 'tampered.html')
    writeFileSync(tampered, html.replace('<script type="module">', '<script type="module">;'))
    const run = check(tampered)

    expect(run.status).not.toBe(0)
    expect(`${run.stderr}`).toMatch(/hash|sha256|policy/i)
  })
})
