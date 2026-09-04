// @vitest-environment jsdom
//
// The demonstration, driven through the real page markup.
//
// V-I.3's rule is that no claim on the page may go undemonstrated BY the
// page. The wiring is where that rule is kept or lost: a bench that never
// appears, a verdict that does not move when the file does, or a self-check
// that renders nothing, would each turn a demonstration back into a slogan
// while every unit test underneath stayed green.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { initApp, type AppHandle } from '../src/main.js'
import { PROBE_URL } from '../src/probe.js'
import { pageBody } from './helpers/page.js'

const SAMPLE_DIR = join(__dirname, '..', 'public', 'sample')
const sampleBytes = (): Uint8Array => new Uint8Array(readFileSync(join(SAMPLE_DIR, 'demo.attest')))
const sampleBinding = () => JSON.parse(readFileSync(join(SAMPLE_DIR, 'demo-binding.json'), 'utf-8'))

/** Serve the committed sample the way the deployment does, without a server.
 *
 * The response carries `headers` because the loader reads one: v0.1 §14.4's
 * floor is checked against the DECLARED length before the body is asked for,
 * and a stub without headers would model a Response no server sends. This one
 * declares nothing, which is the ordinary case for a file served from disk,
 * and leaves the delivered bytes as the thing actually measured. */
const servingSample = (): void => {
  vi.stubGlobal('fetch', (url: string) =>
    Promise.resolve(
      url.endsWith('demo.attest')
        ? {
            ok: true,
            headers: { get: () => null },
            arrayBuffer: () => Promise.resolve(sampleBytes().buffer),
          }
        : { ok: true, headers: { get: () => null }, json: () => Promise.resolve(sampleBinding()) },
    ),
  )
}

const el = (id: string): HTMLElement => document.getElementById(id)!
const text = (id: string): string => el(id).textContent ?? ''

let app: AppHandle
beforeEach(() => {
  document.body.innerHTML = pageBody()
  app = initApp(document)
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe('the bench opens on a receipt, and never before one', () => {
  it('offers nothing at all until a receipt has been checked', () => {
    // A button that cannot do what it says is worse than no button: with no
    // receipt loaded there is nothing to break, so the bench is not there.
    expect(el('bench').hidden).toBe(true)
    expect(el('bench-buttons').querySelectorAll('button')).toHaveLength(0)
  })

  it('needs no file of the visitor’s own: the sample opens it', async () => {
    servingSample()
    await app.loadSampleBundle()
    expect(text('results')).toContain('Receipt verifies')
    expect(el('bench').hidden).toBe(false)
    expect(el('bench-buttons').querySelectorAll('button').length).toBeGreaterThan(0)
  })

  it('says so plainly when the sample cannot be served, instead of showing an empty box', async () => {
    vi.stubGlobal('fetch', () => Promise.reject(new Error('offline')))
    el('load-sample').click()
    await vi.waitFor(() => expect(text('results')).toMatch(/could not load the sample/i))
    expect(el('bench').hidden).toBe(true)
  })
})

describe('breaking the receipt moves the verdict, and says why', () => {
  beforeEach(async () => {
    servingSample()
    await app.loadSampleBundle()
  })

  it('turns one byte and the verdict flips, with the offset on screen', () => {
    expect(text('results')).toContain('Receipt verifies')
    app.applyTamperById('title')
    expect(text('results')).toMatch(/does NOT verify/i)
    expect(text('bench-state')).toMatch(/one byte at offset/i)
    expect(text('results')).toContain('invalid')
  })

  it('offers a failure that is NOT about the file, and reads differently', () => {
    app.applyTamperById('drop-manifest')
    expect(text('results')).toMatch(/does NOT verify/i)
    expect(text('bench-state')).toMatch(/nothing in the file changed/i)
  })

  it('puts it back', () => {
    app.applyTamperById('signature')
    expect(text('results')).toMatch(/does NOT verify/i)
    expect(el('bench-restore').hidden).toBe(false)

    app.restore()
    expect(text('results')).toContain('Receipt verifies')
    expect(text('bench-state')).toBe('')
    expect(el('bench-restore').hidden).toBe(true)
  })

  it('every button the bench offers actually breaks the receipt', () => {
    const ids = [...el('bench-buttons').querySelectorAll('button')].map(
      (b) => (b as HTMLButtonElement).dataset.tamper!,
    )
    expect(ids.length).toBeGreaterThan(1)
    for (const id of ids) {
      app.restore()
      expect(text('results'), id).toContain('Receipt verifies')
      app.applyTamperById(id as never)
      expect(text('results'), id).toMatch(/does NOT verify/i)
    }
  })

  it('keeps the verdict on screen when a binding proof is rejected', () => {
    // The bench sits above a verdict and its header says so. Wiping the
    // results on a bad salt left the bench narrating an edit whose
    // consequence was nowhere to be seen — a state the design forbids.
    app.applyTamperById('title')
    expect(text('results')).toMatch(/does NOT verify/i)

    const salt = document.getElementById('binding-salt') as HTMLInputElement
    salt.value = 'not base64url!!'
    app.applyDisclosure()

    expect(text('results')).toMatch(/not valid base64url/i)
    expect(text('results'), 'the verdict the bench just moved').toMatch(/does NOT verify/i)
    expect(text('bench-state')).toMatch(/one byte at offset/i)
  })

  it('says nothing was altered only while nothing is', () => {
    // The handle can be driven to a tamper this receipt cannot take. Leaving a
    // PREVIOUS tamper on screen under the words "nothing was altered" is the
    // one reading that sentence must never have.
    app.applyTamperById('title')
    expect(text('results')).toMatch(/does NOT verify/i)
    app.applyTamperById('receipt-id')
    app.restore()
    expect(text('results')).toContain('Receipt verifies')
  })

  it('closes the bench again when the page is handed something it refuses', () => {
    app.handleBytes('lib.private.attest', new Uint8Array([0x50, 0x4b]))
    expect(el('bench').hidden).toBe(true)
    expect(el('bench-buttons').querySelectorAll('button')).toHaveLength(0)
  })
})

describe('the §19 exhibits are run, not described', () => {
  it('renders both verdicts and a tally counted from the runs', () => {
    app.showExhibits()
    const zone = text('exhibits')
    expect(el('exhibits').querySelectorAll('section.exhibit')).toHaveLength(2)
    expect(zone).toContain('2 conformance vectors replayed')
    expect(zone).toContain('2 produced exactly the result the corpus demands')
    // The contrast the section promises, actually on screen.
    expect(zone).toContain('Receipt verifies')
    expect(zone).toMatch(/does NOT verify/i)
    expect(el('exhibits').querySelectorAll('section.exhibit.mismatch')).toHaveLength(0)
  })

  it('names the corpus leaves it replayed, so the claim is checkable', () => {
    app.showExhibits()
    expect(text('exhibits')).toContain('41-compromise-cutoff/a-rescued-anchored-before-cutoff')
    expect(text('exhibits')).toContain('41-compromise-cutoff/b-anchored-after-cutoff-fails')
  })
})

describe('the confinement probe reports the browser', () => {
  it('shows a block the browser witnessed as a block', async () => {
    await app.runProbe({
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: (cb) => {
        cb({
          blockedURI: PROBE_URL,
          violatedDirective: 'connect-src',
        } as SecurityPolicyViolationEvent)
        return () => {}
      },
    })
    expect(text('probe')).toContain('connect-src')
    expect(el('probe').querySelector('.probe')!.className).toContain('tone-good')
  })

  it('stays neutral when the request merely failed', async () => {
    // No violation recorded: this URL never resolves, so a bare failure is
    // what an unreachable host looks like on a page with no policy at all.
    await app.runProbe({
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      onViolation: () => () => {},
    })
    expect(text('probe')).toContain('Failed to fetch')
    expect(el('probe').querySelector('.probe')!.className).toContain('tone-neutral')
  })

  it('shows a request that got through as the failure it would be', async () => {
    await app.runProbe({ fetch: () => Promise.resolve({}), onViolation: () => () => {} })
    expect(el('probe').querySelector('.probe')!.className).toContain('tone-bad')
    expect(text('probe')).toMatch(/not blocked/i)
  })
})
