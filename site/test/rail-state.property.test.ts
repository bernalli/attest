// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import fc from 'fast-check'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { initApp } from '../src/main.js'
import { MAX_STORED_BYTES } from '../src/container.js'

/**
 * The desktop shell asserts this same contract over its own wiring, in
 * `desktop/test/rail-state.property.test.ts`. The two files are deliberate twins rather
 * than one file parameterised over both shells, and the reason is the defect that split
 * them: this file used to mount the desktop app too, by importing `desktop/src/app.ts`.
 * The `site` job installs `site/node_modules` and not `desktop/node_modules`, so
 * `attest-verifier` did not resolve through that import and vitest collected NO tests
 * from this file — sixteen assertions that ran on developer machines and nowhere else.
 * A test belongs in the package whose dependencies it needs.
 *
 * These twins drift silently unless someone carries a change across, so change one and
 * change the other.
 */

const rails = ['revocation-view.json', 'transfer-view.json', 'compromise-view.json', 'revocation-evidence.json'] as const
const bytes = (s: string) => new TextEncoder().encode(s)
const sample = new Uint8Array(readFileSync(fileURLToPath(new NodeURL('../public/sample/demo.attest', import.meta.url))))
const results = () => document.getElementById('results')!
function mount() {
  const html = readFileSync(fileURLToPath(new NodeURL('../index.html', import.meta.url)), 'utf8')
  document.body.innerHTML = /<body[^>]*>([\s\S]*)<\/body>/.exec(html)![1]
  return initApp(document)
}
function drop(name: string, size: number, arrayBuffer: () => Promise<ArrayBuffer>) {
  const event = new Event('drop')
  Object.defineProperty(event, 'dataTransfer', { value: { files: [{ name, size, arrayBuffer }] } })
  document.getElementById('dropzone')!.dispatchEvent(event)
}
describe('site: rail transitions', () => {
  it.each([40_000_001, MAX_STORED_BYTES + 1])('refuses an oversized evidence file (%i bytes) without cancelling the current receipt', async size => {
    const app = mount()
    app.handleBytes('sample.attest', sample)
    const card = results().querySelector('article.result')!
    expect(card).not.toBeNull()
    const read = vi.fn(() => Promise.resolve(new ArrayBuffer(0)))
    drop('revocation-evidence.json', size, read)
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(read).not.toHaveBeenCalled()
    expect(results().contains(card)).toBe(true)
    expect(results().textContent).toContain('revocation-evidence.json')
    app.handleBytes('revocation-view.json', bytes('[]'))
    expect(results().querySelectorAll('article.result')).toHaveLength(1)
    expect(results().textContent).toContain('Revocation feed: 0 records')
  })

  // The test above drops the ONE rail whose own ceiling is narrower than the
  // floor. That rail cannot tell a bound composed with the floor from a bound
  // put in its place: both refuse it at 40,000,000. The other three can — their
  // ceilings convert to 2.56 GB and ~372 GB — so each is dropped here at one
  // byte over the limit that actually applies to it, which for those three is
  // the floor itself. Nothing may be read, and the receipt must survive.
  const overLimit: ReadonlyArray<readonly [string, number]> = [
    ['revocation-evidence.json', Math.min(4 * 10_000_000, MAX_STORED_BYTES) + 1],
    ['transfer-view.json', Math.min(4 * 64 * 10_000_000, MAX_STORED_BYTES) + 1],
    ['compromise-view.json', Math.min(4 * 64 * 10_000_000, MAX_STORED_BYTES) + 1],
    ['revocation-view.json', Math.min(4 * 10_000 * 10_000_000, MAX_STORED_BYTES) + 1],
  ]
  it.each(overLimit)('never copies %s at %i bytes, and keeps the receipt', async (name, size) => {
    const app = mount()
    app.handleBytes('sample.attest', sample)
    const card = results().querySelector('article.result')!
    expect(card).not.toBeNull()
    const read = vi.fn(() => Promise.resolve(new ArrayBuffer(0)))
    drop(name, size, read)
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(read).not.toHaveBeenCalled()
    expect(results().contains(card)).toBe(true)
    expect(results().textContent).toContain(name)
    app.handleBytes(name, bytes(name === 'revocation-evidence.json' ? '{}' : '[]'))
    expect(results().querySelectorAll('article.result')).toHaveLength(1)
  })

  it('preserves each receipt across arbitrary rejected rail drops, then accepts a valid replacement', () => {
    fc.assert(fc.property(
      fc.array(fc.tuple(fc.constantFrom(...rails), fc.constantFrom('null', '{', '[1.5]', '{"a":1,"a":2}')), { minLength: 1, maxLength: 8 }),
      drops => {
        const app = mount()
        app.handleBytes('sample.attest', sample)
        const card = results().querySelector('article.result')!
        for (const [name, text] of drops) {
          app.handleBytes(name, bytes(text))
          expect(results().contains(card)).toBe(true)
        }
        app.handleBytes('sample.attest', sample)
        expect(results().querySelectorAll('article.result')).toHaveLength(1)
        expect(results().textContent).not.toContain('was not read')
        expect(results().contains(card)).toBe(false)
      }), { numRuns: 20, seed: 124 })
  })

  it('keeps a container refusal across rail gestures, then replaces it on a valid receipt drop', () => {
    fc.assert(fc.property(fc.array(fc.constantFrom(...rails, 'clear'), { minLength: 1, maxLength: 8 }), gestures => {
      const app = mount()
      app.handleBytes('sample.attest', sample)
      app.handleBytes('private.private.attest', bytes(''))
      const refusal = results().firstElementChild!
      for (const name of gestures) {
        if (name === 'clear') app.clearRails()
        else app.handleBytes(name, bytes(name === 'revocation-evidence.json' ? '{}' : '[]'))
        expect(results().contains(refusal)).toBe(true)
        expect(results().querySelectorAll('.component-value')).toHaveLength(0)
      }
      app.handleBytes('sample.attest', sample)
      expect(results().querySelectorAll('article.result')).toHaveLength(1)
      expect(results().contains(refusal)).toBe(false)
    }), { numRuns: 20, seed: 124 })
  })
})
