import { test, expect, type Page } from '@playwright/test'
import { Buffer } from 'node:buffer'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { unzipSync, zipSync } from 'fflate'
import { canonicalBytes, loadsStrict, sha256Hex } from 'attest-verifier'

/**
 * The artifact, opened the way a buyer opens it: a `file://` URL, no server anywhere.
 *
 * Every scenario carries the request collectors. The mandate's requirement is not "we
 * did not notice a request", it is that the app be UNABLE to make one — so the
 * collectors run on all of them, valid and invalid alike, and a single non-`file:`
 * request fails whichever test provoked it.
 */

const HERE = fileURLToPath(new URL('.', import.meta.url))
const DESKTOP = join(HERE, '..')
const REPO = join(DESKTOP, '..')
const ARTIFACT = join(DESKTOP, 'dist', 'attest-verifier.html')
const MULTI_FILE = join(DESKTOP, 'dist', 'index.html')
const SAMPLE = join(REPO, 'site', 'public', 'sample', 'demo.attest')

const url = (path: string) => `file://${path}`
const sampleBytes = () => new Uint8Array(readFileSync(SAMPLE))

interface Traffic {
  foreign: string[]
  sockets: string[]
  files: string[]
}

const seen = new WeakMap<Page, Traffic>()

test.beforeEach(async ({ page }) => {
  const traffic: Traffic = { foreign: [], sockets: [], files: [] }
  page.on('request', (r) => {
    if (r.url().startsWith('file:')) traffic.files.push(r.url())
    else traffic.foreign.push(r.url())
  })
  page.on('websocket', (ws) => traffic.sockets.push(ws.url()))
  seen.set(page, traffic)
})

test.afterEach(async ({ page }) => {
  const traffic = seen.get(page)
  if (!traffic) return
  expect(traffic.foreign, 'the app made a request outside the file:// scheme').toEqual([])
  expect(traffic.sockets, 'the app opened a websocket').toEqual([])
})

test('the collectors every scenario rests on are not blind', async ({ page }) => {
  // Measured 2026-09-01, and it is why this test exists rather than a count in the
  // afterEach: Firefox reports NO `file:` request at all to Playwright — loading the
  // artifact there yields zero request events while the app starts perfectly — whereas
  // Chromium reports exactly one. A liveness check written as "we saw some request"
  // would therefore fail on Firefox for a reason that has nothing to do with the app.
  //
  // What both engines DO report, measured the same way, is a request that leaves the
  // file:// scheme — which is the only thing the mandate asks about. So liveness is
  // proven by provoking one: a page with no policy that reaches for a host under the
  // reserved .invalid domain. If this test ever passes silently, every "zero foreign
  // requests" assertion in this file has stopped meaning anything.
  await page.goto(url(join(HERE, 'fixtures', 'collector-liveness.html')))
  await expect(page.locator('#marker')).toHaveText('tried')

  const traffic = seen.get(page)!
  // Polled, not read once: the websocket event arrives after the fetch on some engines,
  // and a race here would report a live collector as blind.
  await expect
    .poll(() => traffic.foreign.length, { message: 'the request collector saw no foreign request' })
    .toBeGreaterThan(0)
  await expect
    .poll(() => traffic.sockets.length, { message: 'the websocket collector saw no socket' })
    .toBeGreaterThan(0)

  // This one is expected to be dirty; the afterEach must not judge it.
  traffic.foreign.length = 0
  traffic.sockets.length = 0
})

/** Chromium runs with DNS taken away underneath the page (see playwright.config.ts), so
 *  there it can also be asked the stricter question: how many requests IN TOTAL. */
function expectSingleRequest(page: Page): void {
  if (test.info().project.name !== 'chromium') return
  const traffic = seen.get(page)!
  expect(new Set(traffic.files).size, `requests: ${traffic.files.join(', ')}`).toBe(1)
}

async function drop(page: Page, name: string, bytes: Uint8Array): Promise<void> {
  await page.locator('#file-input').setInputFiles({
    name,
    mimeType: 'application/octet-stream',
    buffer: Buffer.from(bytes),
  })
}

const results = (page: Page) => page.locator('#results')

// ---------------------------------------------------------------------------
// Fixtures built in-test. Nothing here writes into the repository.
// ---------------------------------------------------------------------------

function member(prefix: string): { name: string; bytes: Uint8Array } {
  const found = unzipSync(sampleBytes())
  const name = Object.keys(found).find((n) => n.startsWith(prefix))
  if (!name) throw new Error(`the sample bundle has no ${prefix} member`)
  return { name, bytes: found[name]! }
}

const bareEnvelope = () => member('receipts/').bytes
const manifestContainer = () => member('manifests/').bytes

function singleKeyManifest(): Uint8Array {
  const container = JSON.parse(new TextDecoder().decode(manifestContainer()))
  return canonicalBytes(
    loadsStrict(new TextEncoder().encode(JSON.stringify(container.key_manifests[0]))),
  )
}

function saltedBareEnvelope(): Uint8Array {
  // `delivery` sits OUTSIDE the signed payload, so adding it leaves the signature
  // intact — which is the point: a file that still carries its binding salt verifies
  // perfectly well and is still bearer proof.
  const envelope = JSON.parse(new TextDecoder().decode(bareEnvelope()))
  envelope.delivery = { ...(envelope.delivery ?? {}), salt: 'AAAAAAAAAAAAAAAAAAAAAA' }
  return canonicalBytes(loadsStrict(new TextEncoder().encode(JSON.stringify(envelope))))
}

/** The deal every conformance vector's receipt is bound to.
 *
 * `tools/gen_vectors.py` hashes exactly these bytes into each generated payload's
 * `license.legal_text_sha256`, so a bundle assembled around one of those envelopes
 * has to carry the text under its digest: an importer refuses a bundle that names a
 * legal text it does not carry, because a receipt whose terms are gone is a receipt
 * for nothing anyone can read.
 */
const VECTOR_LEGAL_TEXT = new TextEncoder().encode('attest-vectors-legal-text-v1')

const asObject = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null

/** Every hash-bound legal document a payload's terms depend on, read the way both
 *  importers read it: the schema-required licence text, plus the two survivability
 *  hashes when they are present and are strings. */
function referencedLegalHashes(payload: Record<string, unknown>): string[] {
  const hashes: string[] = []
  const license = asObject(payload['license'])
  const legalText = license === null ? undefined : license['legal_text_sha256']
  if (typeof legalText === 'string') hashes.push(legalText)
  const survivability = asObject(payload['survivability'])
  if (survivability !== null)
    for (const field of ['mirror_policy_sha256', 'eol_commitment_sha256']) {
      const hash = survivability[field]
      if (typeof hash === 'string') hashes.push(hash)
    }
  return hashes
}

function vectorBundle(name: string): Uint8Array {
  const dir = join(REPO, 'docs', 'spec', 'vectors', name)
  const envelope = new Uint8Array(readFileSync(join(dir, 'envelope.json')))
  const store = JSON.parse(readFileSync(join(dir, 'manifests.json'), 'utf8'))
  const issuer = Object.keys(store.manifests)[0]!
  const container = canonicalBytes(
    loadsStrict(
      new TextEncoder().encode(
        JSON.stringify({ issuer, key_manifests: [store.manifests[issuer]] }),
      ),
    ),
  )
  // The member NAME is the digest of the bytes put inside it, computed here rather
  // than written down: a name and a content that disagree are the tampering the
  // importer exists to catch, so a fixture that carried one would be exercising the
  // refusal instead of the verdict each of these tests is about.
  const legalDigest = sha256Hex(VECTOR_LEGAL_TEXT)
  const payload = asObject(
    (JSON.parse(new TextDecoder().decode(envelope)) as Record<string, unknown>)['payload'],
  )
  // Every referenced digest, not just the first: a vector that bound its receipt to a
  // second text would otherwise produce a bundle the importers refuse, and the test
  // above would report that refusal as the verdict it was looking for.
  const unavailable = referencedLegalHashes(payload ?? {}).filter((d) => d !== legalDigest)
  if (unavailable.length > 0)
    throw new Error(
      `vector ${name} binds its receipt to legal texts this fixture cannot supply: ` +
        unavailable.join(', '),
    )
  return zipSync({
    'receipts/r.attest.json': envelope,
    'manifests/m.json': container,
    [`legal/${legalDigest}.txt`]: VECTOR_LEGAL_TEXT,
  })
}

/** The sample's members with one `legal/` text filed under a name that is NOT the
 *  digest of its bytes — a structurally perfect archive, honest CRC, valid signature,
 *  and terms nobody can bind to the deal the receipt refers to. */
function bundleWithUnboundLegalText(): Uint8Array {
  const found = unzipSync(sampleBytes())
  return zipSync({ ...found, 'legal/terms.txt': new TextEncoder().encode('You own nothing.') })
}

/** Three bundles carrying the SAME signed receipt bytes and differing only in members
 *  and names the signature does not cover.
 *
 *  Every member here has to be one an importer ACCEPTS, or the test would be
 *  comparing refusals rather than verdicts. A `legal/` member used to stand in this
 *  list, and it stopped qualifying the day both importers began checking a legal text
 *  against the digest in its name: such a member is not uncovered metadata, it is a
 *  malformed one, and it earns a refusal in its own test below. */
function tamperedContainers(): Uint8Array[] {
  const found = unzipSync(sampleBytes())
  const receiptName = Object.keys(found).find((n) => n.startsWith('receipts/'))!
  const enc = (s: string) => new TextEncoder().encode(s)
  const base = { ...found }
  delete base[receiptName]

  const withReceipt = (name: string, extra: Record<string, Uint8Array>) =>
    zipSync({ ...base, ...extra, [name]: found[receiptName]! })

  return [
    withReceipt(receiptName, { 'README.html': enc('<h1>Refund policy: none</h1>') }),
    withReceipt(receiptName, { 'refund-policy.txt': enc('You own nothing.') }),
    withReceipt('receipts/VERIFIED by Steam - Official Purchase - Genuine.attest.json', {}),
  ]
}

// ---------------------------------------------------------------------------

test.describe('the packaging itself', () => {
  test('a page that did not start never looks like one waiting for a file', async ({ page }) => {
    // The multi-file build is the honest reproduction of the failure this packaging
    // exists to avoid, and it is engine-dependent — measured 2026-09-01, opening
    // dist/index.html from file://:
    //
    //   Chromium — the module AND the stylesheet are blocked on the opaque origin
    //              (net::ERR_FAILED, twice), the page renders unstyled, and dropping a
    //              valid bundle produces nothing at all.
    //   Firefox  — both load, the app starts, and a real verdict is rendered.
    //
    // So the plan's premise that "a multi-file build does not work from file://" holds
    // on Chromium and NOT on Firefox, and a test asserting the Chromium outcome
    // everywhere would be asserting a browser bug as a requirement. What must hold on
    // every engine is the invariant underneath it: a script that did not run leaves a
    // page that SAYS so, and never one that looks ready and swallows a dropped receipt
    // in silence. That is the property, and it is what is asserted here.
    await page.goto(url(MULTI_FILE))
    const started = (await page.locator('#boot-failsafe').count()) === 0
    await drop(page, 'demo.attest', sampleBytes())

    if (started) {
      await expect(results(page).locator('.result')).toHaveCount(1)
    } else {
      await expect(page.locator('#boot-failsafe')).toBeVisible()
      await expect(page.locator('#dropzone')).toHaveAttribute('aria-disabled', 'true')
      await expect(results(page).locator('.result')).toHaveCount(0)
    }
  })

  test('on Chromium the multi-file build is blocked outright', async ({ page }) => {
    // The measurement above, pinned where it was taken. If Chromium ever starts running
    // multi-file modules from file://, this goes red and the packaging decision can be
    // revisited on evidence rather than on a memory of how browsers behaved.
    test.skip(test.info().project.name !== 'chromium', 'measured on Chromium')

    await page.goto(url(MULTI_FILE))
    await drop(page, 'demo.attest', sampleBytes())

    await expect(page.locator('#boot-failsafe')).toBeVisible()
    await expect(results(page).locator('.result')).toHaveCount(0)
  })

  test('the artifact starts, and the banner is gone', async ({ page }) => {
    await page.goto(url(ARTIFACT))

    await expect(page.locator('#boot-failsafe')).toHaveCount(0)
    await expect(page.locator('#dropzone')).not.toHaveAttribute('aria-disabled', 'true')
    expectSingleRequest(page)
  })

  test('a policy that no longer pins these bytes leaves a page that says it is dead', async ({ page }) => {
    // One character of the script hash, changed. This is the field failure the CSP can
    // still produce after CI is green — a truncated download, an edited copy — and the
    // test exists so that it can never be silent.
    const html = readFileSync(ARTIFACT, 'utf8')
    const broken = html.replace(/script-src 'sha256-(.)/, (m, c: string) =>
      m.slice(0, -1) + (c === 'A' ? 'B' : 'A'),
    )
    expect(broken).not.toEqual(html)
    const file = join(mkdtempSync(join(tmpdir(), 'attest-broken-')), 'attest-verifier.html')
    writeFileSync(file, broken)

    await page.goto(url(file))
    await drop(page, 'demo.attest', sampleBytes())

    await expect(page.locator('#boot-failsafe')).toBeVisible()
    await expect(page.locator('#dropzone')).toHaveAttribute('aria-disabled', 'true')
    await expect(results(page).locator('.result')).toHaveCount(0)
  })
})

test.describe('verdicts', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(url(ARTIFACT))
  })

  test('the sample bundle gets the amber headline, and never the green one', async ({ page }) => {
    await drop(page, 'demo.attest', sampleBytes())

    await expect(results(page).locator('.result')).toHaveCount(1)
    await expect(results(page).locator('.verdict')).toContainText('as far as an offline check can go')
    await expect(results(page)).not.toContainText('Receipt verifies')
    expectSingleRequest(page)
  })

  for (const vector of ['03-tampered-payload', '04-wrong-key', '11-manifest-tamper']) {
    test(`${vector} is refused, from a file:// page`, async ({ page }) => {
      await drop(page, 'receipt.attest', vectorBundle(vector))

      await expect(results(page).locator('.verdict')).toContainText('does NOT verify')
      await expect(results(page)).not.toContainText('Receipt verifies')
      await expect(results(page)).not.toContainText('as far as an offline check can go')
    })
  }

  test('a bearer file is refused by its name, before anything is parsed', async ({ page }) => {
    await drop(page, 'holiday.private.attest', new Uint8Array([1, 2, 3]))

    // What comes back is the shared REJECTION card (`.result.rejected`), which the site
    // already gets right: a reason, and nothing that looks like a verdict about the
    // receipt — no title read out of a payload nobody parsed, no headline either way.
    await expect(results(page)).toContainText(/never share/i)
    await expect(results(page).locator('.result.rejected')).toHaveCount(1)
    await expect(results(page).locator('h3')).toHaveCount(0)
    await expect(results(page)).not.toContainText('offline check can go')
    await expect(results(page)).not.toContainText('Receipt verifies')
  })

  test('a receipt that still carries its salt is checked, and the risk is named', async ({ page }) => {
    // Dropped under the extension a bare receipt actually has. `.attest` is the
    // CONTAINER extension, so a lone envelope carrying that name is a misnamed file
    // and is read as the archive it claims to be — which is a question about routing,
    // and this test is about the salt.
    await drop(page, 'mine.attest.json', saltedBareEnvelope())

    await expect(results(page)).toContainText(/bearer proof/i)
  })

  test('a bare envelope asks for the key list, then produces a verdict', async ({ page }) => {
    await drop(page, 'receipt.attest.json', bareEnvelope())
    await expect(page.locator('#manifest-zone')).toBeVisible()
    await expect(results(page).locator('.result')).toHaveCount(0)

    await page.locator('#manifest-input').setInputFiles({
      name: 'store.json',
      mimeType: 'application/json',
      buffer: Buffer.from(singleKeyManifest()),
    })

    await expect(results(page).locator('.result')).toHaveCount(1)
    await expect(results(page)).toContainText('receipt.attest.json')
  })
})

test.describe('nothing outside the signature reaches the reader as a claim', () => {
  test('container metadata a signature does not cover changes nothing on screen', async ({ page }) => {
    const rendered: string[] = []
    for (const bundle of tamperedContainers()) {
      await page.goto(url(ARTIFACT))
      await drop(page, 'purchase.attest', bundle)
      await expect(results(page).locator('.result')).toHaveCount(1)
      rendered.push((await results(page).innerText()).trim())
      await expect(results(page).locator('h3')).not.toContainText('Steam')
    }

    expect(rendered[1]).toEqual(rendered[0])
    expect(rendered[2]).toEqual(rendered[0])
  })

  test('a legal text filed under a name that is not its digest is refused', async ({ page }) => {
    // The other side of the test above, and the reason a `legal/` member no longer
    // belongs in it: this family is content-addressed, so the name is a claim about
    // the bytes and the archive is refused when the two disagree. Nothing in the
    // container reader can see it — the zip is well formed, the CRC is honest and the
    // signature still verifies — so if it is not caught here it is not caught at all.
    await page.goto(url(ARTIFACT))
    await drop(page, 'purchase.attest', bundleWithUnboundLegalText())

    await expect(results(page).locator('.result.rejected')).toHaveCount(1)
    await expect(results(page)).toContainText(/integrity check/i)
    await expect(results(page)).not.toContainText('Receipt verifies')
    await expect(results(page)).not.toContainText('offline check can go')
  })

  test('a hostile file name is text, never markup', async ({ page }) => {
    await page.goto(url(ARTIFACT))
    await drop(page, '<img src=x onerror=alert(1)>.attest', sampleBytes())

    await expect(results(page)).toContainText('<img src=x onerror=alert(1)>.attest')
    await expect(results(page).locator('img')).toHaveCount(0)
  })
})

test.describe('the four headlines are told apart by more than their wording', () => {
  test('each state resolves to its own appearance in a real engine', async ({ page }) => {
    // jsdom does not resolve a cascade, so this is asserted where a browser does. The
    // states are injected rather than provoked because two of the four are unreachable
    // from any input attest can produce today: the question here is the STYLESHEET.
    await page.goto(url(ARTIFACT))
    const styles = await page.evaluate(() => {
      const classes = [
        'verdict tone-good',
        'verdict tone-warn',
        'verdict tone-warn verdict-key-gap',
        'verdict tone-bad',
      ]
      const body = getComputedStyle(document.body).color
      const out = classes.map((className) => {
        const p = document.createElement('p')
        p.className = className
        const strong = document.createElement('strong')
        strong.textContent = 'headline'
        p.appendChild(strong)
        document.body.appendChild(p)
        const s = getComputedStyle(strong)
        return `${s.color}|${s.textDecorationLine}`
      })
      return { body, out }
    })

    expect(new Set(styles.out).size, `not four distinct headlines: ${styles.out.join(' / ')}`).toBe(4)
    for (const style of styles.out) expect(style.startsWith(`${styles.body}|none`)).toBe(false)
  })
})
