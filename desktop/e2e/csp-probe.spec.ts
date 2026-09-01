import { test, expect, type Page } from '@playwright/test'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// Step 1 of the plan: the packaging feasibility gate.
//
// The artifact is a single HTML file with an inline ES module, allowed by a CSP that
// pins the SHA-256 of that exact script. Two things have to be true on every engine a
// buyer might use, and a positive result alone cannot tell them apart:
//
//   1. the inline module RUNS from an opaque (file://) origin, and
//   2. the CSP is actually ENFORCED.
//
// An engine that silently ignores a meta-CSP on file:// passes (1) while deleting the
// `connect-src 'none'` belt, and every other test in this suite would still be green.
// So the probe is a pair: a correct-hash fixture that must run, and a wrong-hash fixture
// that must NOT. Passing the first while failing the second is a FAILED gate, not a pass.

const HERE = fileURLToPath(new URL('.', import.meta.url))
const fixture = (name: string) => `file://${HERE}fixtures/${name}`

interface Traffic {
  foreign: string[]
  sockets: string[]
}

// Every scenario carries the same collectors: the mandate's local-only requirement is
// not "we did not notice a request", it is "no request left the file:// scheme".
function watch(page: Page): Traffic {
  const traffic: Traffic = { foreign: [], sockets: [] }
  page.on('request', (r) => {
    if (!r.url().startsWith('file:')) traffic.foreign.push(r.url())
  })
  page.on('websocket', (ws) => traffic.sockets.push(ws.url()))
  return traffic
}

test('the fixtures this gate depends on exist', () => {
  for (const name of ['good.html', 'bad.html', 'connect.html']) {
    expect(existsSync(new URL(`fixtures/${name}`, import.meta.url)), `missing fixture ${name}`).toBe(true)
  }
})

test('an inline module with a matching CSP hash runs from file://', async ({ page }) => {
  const traffic = watch(page)
  await page.goto(fixture('good.html'))
  await expect(page.locator('#marker')).toHaveText('RAN')
  expect(traffic.foreign, 'the probe must not reach the network').toEqual([])
  expect(traffic.sockets).toEqual([])
})

test('an inline module with a WRONG CSP hash does not run — the CSP is enforced', async ({ page }) => {
  const traffic = watch(page)
  await page.goto(fixture('bad.html'))
  // The marker's initial text is the failure state the script would have overwritten.
  // If this reads RAN, the engine ignored the CSP: the artifact would ship there with
  // no policy at all, and `connect-src 'none'` would be decorative.
  await expect(page.locator('#marker')).toHaveText('NOT-RUN')
  expect(traffic.foreign).toEqual([])
  expect(traffic.sockets).toEqual([])
})

test("connect-src 'none' refuses a cross-origin fetch, rather than merely failing to make one", async ({ page }) => {
  const traffic = watch(page)
  await page.goto(fixture('connect.html'))
  // The fixture reports the outcome of its own fetch attempt. BLOCKED means the policy
  // refused it; a resolved fetch (or a request in the collector) means the belt is gone.
  await expect(page.locator('#marker')).toHaveText('BLOCKED')
  expect(traffic.foreign, 'a request escaped despite connect-src none').toEqual([])
  expect(traffic.sockets).toEqual([])
})
