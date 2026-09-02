import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { zipSync } from 'fflate'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const VECTORS = join(HERE, '..', '..', 'docs', 'spec', 'vectors')

test('sample bundle verifies at honest TOFU trust', async ({ page }) => {
  await page.goto('/')
  await page.click('#load-sample')
  await expect(page.locator('.verdict strong')).toHaveText(/Receipt verifies/)
  await expect(page.locator('.component-value', { hasText: 'unauthenticated_tofu' })).toBeVisible()
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

test('the page never talks to a non-same-origin host', async ({ page }) => {
  const foreign: string[] = []
  page.on('request', (req) => {
    if (!req.url().startsWith('http://127.0.0.1:4173')) foreign.push(req.url())
  })
  await page.goto('/')
  await page.click('#load-sample')
  await expect(page.locator('.verdict strong')).toHaveText(/Receipt verifies/)
  expect(foreign).toEqual([])
})
