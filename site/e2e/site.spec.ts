import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { zipSync } from 'fflate'
import { sha256Hex, loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const VECTORS = join(HERE, '..', '..', 'docs', 'spec', 'vectors')

/** The legal text every vector receipt refers to, and the member name it is
 *  filed under. The name is COMPUTED from the bytes and never written by hand:
 *  the family is content-addressed, so a hand-copied digest is a fixture that
 *  claims something about bytes it was not derived from — which is how this
 *  file came to build bundles no importer accepts. */
const VECTOR_LEGAL_TEXT = new TextEncoder().encode('attest-vectors-legal-text-v1')
const legalMember = (): Record<string, Uint8Array> => ({
  [`legal/${sha256Hex(VECTOR_LEGAL_TEXT)}.txt`]: VECTOR_LEGAL_TEXT,
})

const VERDICT = '.verdict strong'

/** Load the sample and wait for its verdict: the state the bench starts from. */
const withSample = async (page: import('@playwright/test').Page): Promise<void> => {
  await page.goto('/')
  await page.click('#load-sample')
  await expect(page.locator(VERDICT).first()).toHaveText(/Receipt verifies/)
}

test('sample bundle verifies at honest TOFU trust', async ({ page }) => {
  await page.goto('/')
  await page.click('#load-sample')
  await expect(page.locator('.verdict strong')).toHaveText(/Receipt verifies/)
  await expect(page.locator('.component-value', { hasText: 'unauthenticated_tofu' })).toBeVisible()
})

test('the bench is not there until there is a receipt to break', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('#bench')).toBeHidden()
  await page.click('#load-sample')
  await expect(page.locator('#bench')).toBeVisible()
})

test('turning one byte flips the verdict, and the page says which byte', async ({ page }) => {
  await withSample(page)
  await page.click('#bench-buttons button[data-tamper="title"]')
  await expect(page.locator(VERDICT).first()).toHaveText(/does NOT verify/i)
  await expect(page.locator('#bench-state')).toContainText(/one byte at offset/i)
  await expect(page.locator('#bench-state')).toContainText('payload.work.title')

  await page.click('#bench-restore')
  await expect(page.locator(VERDICT).first()).toHaveText(/Receipt verifies/)
})

test('taking the seller’s keys away fails for a different reason, and touches no byte', async ({
  page,
}) => {
  await withSample(page)
  await page.click('#bench-buttons button[data-tamper="drop-manifest"]')
  await expect(page.locator(VERDICT).first()).toHaveText(/does NOT verify/i)
  await expect(page.locator('#bench-state')).toContainText(/nothing in the file changed/i)
})

test('the §19 exhibits run in the browser and match the corpus', async ({ page }) => {
  await page.goto('/')
  await page.click('#run-exhibits')
  const tally = page.locator('.exhibit-tally')
  await expect(tally).toHaveClass(/tone-good/)
  await expect(tally).toContainText('2 conformance vectors replayed')
  await expect(tally).toContainText('2 produced exactly the result')
  // The same receipt, two timelines, two verdicts — the contrast the section
  // promises, produced here rather than described.
  await expect(page.locator('.exhibit')).toHaveCount(2)
  await expect(page.locator('.exhibit.mismatch')).toHaveCount(0)
  await expect(page.locator('.exhibit').first().locator(VERDICT)).toHaveText(/Receipt verifies/)
  await expect(page.locator('.exhibit').last().locator(VERDICT)).toHaveText(/does NOT verify/i)
})

test('the page proves it cannot reach another host', async ({ page }) => {
  await page.goto('/')
  await page.click('#run-probe')
  // A real browser enforcing the real Content-Security-Policy: this is the one
  // assertion on the page that no unit test can stand in for.
  await expect(page.locator('#probe .probe')).toHaveClass(/tone-good/)
  await expect(page.locator('#probe')).toContainText('store.nebula.example')
  // And the browser's OWN violation record, not the bare TypeError a plain
  // network failure would also produce — that fallback proves nothing, so a
  // regression back to it has to fail here.
  await expect(page.locator('.probe-detail')).toContainText('violated-directive connect-src')
})

test('salt disclosure proves the sample binding', async ({ page }) => {
  await page.goto('/')
  await page.click('#load-sample')
  await expect(page.locator('.verdict strong')).toHaveText(/Receipt verifies/)
  // The binding form is an expert control, folded under "Advanced checks" so a
  // newcomer meets the dropzone first. It must still be one click away and work
  // from there, with the inputs the sample loader filled in while it was shut.
  await expect(page.locator('#binding-apply')).toBeHidden()
  await page.click('details.advanced > summary')
  await expect(page.locator('#binding-salt')).not.toHaveValue('')
  await page.click('#binding-apply') // inputs were prefilled by the sample loader
  await expect(page.locator('.component-value', { hasText: 'proven' })).toBeVisible()
})

test('a tampered receipt fails loudly', async ({ page }) => {
  const dir = join(VECTORS, '03-tampered-payload')
  const zip = zipSync({
    ['receipts/tampered.attest.json']: new Uint8Array(readFileSync(join(dir, 'envelope.json'))),
    // No manifests entry on purpose: signature must already be invalid; an
    // empty trust store also exercises the no-manifest error path honestly.
    // The legal member IS required, though: this receipt names a legal text by
    // digest, and a bundle that does not carry it is refused on import — so
    // without it the page never reaches a verdict to be loud about, and this
    // test would be asserting on a file the reference importer also rejects.
    ...legalMember(),
  })
  await page.goto('/')
  await page.setInputFiles('#file-input', {
    name: 'tampered.attest',
    mimeType: 'application/zip',
    buffer: Buffer.from(zip),
  })
  await expect(page.locator('.verdict strong')).toHaveText(/does NOT verify/i)
  await expect(page.locator('.component-value', { hasText: 'invalid' }).first()).toBeVisible()
})

test('the page never talks to a non-same-origin host', async ({ page, baseURL }) => {
  const requests: string[] = []
  page.on('request', (req) => requests.push(req.url()))
  await page.goto('/')
  await page.click('#load-sample')
  await expect(page.locator('.verdict strong')).toHaveText(/Receipt verifies/)

  // Counting only FOREIGN requests proved nothing about this claim: the
  // page's own CSP refuses a cross-origin fetch before it becomes a request
  // at all, so Playwright never sees one and the list is empty whatever the
  // page attempts (measured — a fetch to store.nebula.example raises no
  // request event, while a same-origin fetch raises one). What the section
  // actually promises is that the exhibits are compiled into the bundle
  // rather than fetched, and that is a statement about EVERY request.
  const before = requests.length
  await page.click('#run-exhibits')
  await expect(page.locator('.exhibit')).toHaveCount(2)
  expect(requests.slice(before), 'requests issued while replaying the exhibits').toEqual([])
  expect(
    requests.filter((url) => !url.startsWith(baseURL ?? '\u0000')),
    'requests to a host that is not the one serving this page',
  ).toEqual([])
})

test('the hero button loads the sample and brings its verdict into view', async ({ page }) => {
  await page.goto('/')
  await page.click('#try-sample')
  const verdict = page.locator(VERDICT).first()
  await expect(verdict).toHaveText(/Receipt verifies/)
  await expect(page.locator('#bench')).toBeVisible()
  // The reader is taken to the verifier rather than left at the top of the page
  // wondering whether anything happened.
  await expect(page.locator('#check')).toBeInViewport()
})

test('advanced checks stay shut until asked for, and the feeds still clear from there', async ({
  page,
}) => {
  await page.goto('/')
  await expect(page.locator('#clear-feeds')).toBeHidden()
  await page.click('details.advanced > summary')
  await expect(page.locator('#clear-feeds')).toBeVisible()
  await page.click('#load-sample')
  await expect(page.locator(VERDICT).first()).toHaveText(/Receipt verifies/)
  await page.setInputFiles('#file-input', {
    name: 'revocation-view.json',
    mimeType: 'application/json',
    buffer: Buffer.from('[]'),
  })
  await expect(page.locator('#results .rails')).toContainText('Revocation feed: 0 records')
  await page.click('#clear-feeds')
  await expect(page.locator('#results .rails')).toContainText('no revocation feed loaded')
})

test('a receipt with no key manifest reveals the manifest prompt outside the folded controls', async ({
  page,
}) => {
  const dir = join(VECTORS, '01-valid-minimal')
  await page.goto('/')
  await page.setInputFiles('#file-input', {
    name: 'bare.attest.json',
    mimeType: 'application/json',
    buffer: readFileSync(join(dir, 'envelope.json')),
  })
  // Visible with "Advanced checks" still shut: the page asks for a manifest in
  // a box the reader can actually see.
  await expect(page.locator('details.advanced')).not.toHaveAttribute('open', '')
  await expect(page.locator('#manifest-zone')).toBeVisible()
  const all = loadsStrict(new Uint8Array(readFileSync(join(dir, 'manifests.json')))) as JsonObject
  const manifests = all.manifests as JsonObject
  await page.setInputFiles('#manifest-input', {
    name: 'manifest.json',
    mimeType: 'application/json',
    buffer: Buffer.from(canonicalBytes(manifests[Object.keys(manifests)[0]] as JsonObject)),
  })
  await expect(page.locator(VERDICT).first()).toHaveText(/Receipt verifies/)
  await expect(page.locator('#manifest-zone')).toBeHidden()
})

for (const width of [360, 390, 1280]) {
  test(`no page scrolls sideways at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 })
    for (const path of ['/', '/start-here.html', '/faq.html', '/for-sellers.html', '/what-is-this.html']) {
      await page.goto(path)
      const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth)
      expect(scrollWidth, path).toBeLessThanOrEqual(width)
    }
    await page.goto('/')
    await page.click('#load-sample')
    await expect(page.locator(VERDICT).first()).toHaveText(/Receipt verifies/)
    await page.click('details.advanced > summary')
    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth)
    expect(scrollWidth, 'home page with a verdict and the advanced checks open').toBeLessThanOrEqual(width)
  })
}
