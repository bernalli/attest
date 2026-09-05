// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import fc from 'fast-check'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { initApp } from '../src/main.js'
import { initDesktopApp } from '../../desktop/src/app.js'
import { MAX_STORED_BYTES } from '../src/container.js'

const rails = ['revocation-view.json', 'transfer-view.json', 'compromise-view.json', 'revocation-evidence.json'] as const
const bytes = (s: string) => new TextEncoder().encode(s)
const sample = new Uint8Array(readFileSync(fileURLToPath(new NodeURL('../public/sample/demo.attest', import.meta.url))))
const results = () => document.getElementById('results')!
function mount(shell: 'site' | 'desktop') {
  const path = shell === 'site' ? '../index.html' : '../../desktop/index.html'
  const html = readFileSync(fileURLToPath(new NodeURL(path, import.meta.url)), 'utf8')
  document.body.innerHTML = /<body[^>]*>([\s\S]*)<\/body>/.exec(html)![1]
  return shell === 'site' ? initApp(document) : initDesktopApp(document)
}
function drop(name: string, size: number, arrayBuffer: () => Promise<ArrayBuffer>) {
  const event = new Event('drop')
  Object.defineProperty(event, 'dataTransfer', { value: { files: [{ name, size, arrayBuffer }] } })
  document.getElementById('dropzone')!.dispatchEvent(event)
}
for (const shell of ['site', 'desktop'] as const) describe(`${shell}: rail transitions`, () => {
  it.each([40_000_001, MAX_STORED_BYTES + 1])('refuses an oversized evidence file (%i bytes) without cancelling the current receipt', async size => {
    const app = mount(shell)
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

  it('preserves each receipt across arbitrary rejected rail drops, then accepts a valid replacement', () => {
    fc.assert(fc.property(
      fc.array(fc.tuple(fc.constantFrom(...rails), fc.constantFrom('null', '{', '[1.5]', '{"a":1,"a":2}')), { minLength: 1, maxLength: 8 }),
      drops => {
        const app = mount(shell)
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
      const app = mount(shell)
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
