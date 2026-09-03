import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { zipSync } from 'fflate'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const VECTORS = join(HERE, '..', '..', 'docs', 'spec', 'vectors')

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
  // The binding form is open on the page: the document shows what it asks for
  // rather than hiding it behind a disclosure triangle.
  await page.click('#binding-apply') // inputs were prefilled by the sample loader
  await expect(page.locator('.component-value', { hasText: 'proven' })).toBeVisible()
})

test('a tampered receipt fails loudly', async ({ page }) => {
  const dir = join(VECTORS, '03-tampered-payload')
  const zip = zipSync({
    ['receipts/tampered.attest.json']: new Uint8Array(readFileSync(join(dir, 'envelope.json'))),
    // No manifests entry on purpose: signature must already be invalid; an
    // empty trust store also exercises the no-manifest error path honestly.
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
