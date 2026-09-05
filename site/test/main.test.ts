// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { initApp, type AppHandle } from '../src/main.js'
import { VECTORS_ROOT } from './helpers/vectors.js'
import { pageBody } from './helpers/page.js'
import { LEGAL_TEXT, LEGAL_DIGEST } from './helpers/zip.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const envelope = () => new Uint8Array(readFileSync(join(V01, 'envelope.json')))
const manifest = (): JsonObject => {
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  return manifests[Object.keys(manifests)[0]] as JsonObject
}


let app: AppHandle
beforeEach(() => {
  document.body.innerHTML = pageBody()
  app = initApp(document)
})

describe('initApp wiring', () => {
  it('renders a verified result for an envelope with embedded manifest', () => {
    const env = loadsStrict(envelope()) as JsonObject
    const withDelivery: JsonObject = { ...env, delivery: { issuer_manifest: manifest() } }
    app.handleBytes('receipt.attest.json', canonicalBytes(withDelivery))
    const results = document.getElementById('results')!
    expect(results.querySelectorAll('article.result')).toHaveLength(1)
    expect(results.textContent).toContain('unauthenticated_tofu')
  })

  it('asks for a manifest, then verifies once one is supplied', () => {
    app.handleBytes('receipt.attest.json', envelope())
    expect(document.getElementById('manifest-zone')!.hidden).toBe(false)
    app.handleManifestBytes(canonicalBytes(manifest()))
    expect(document.getElementById('manifest-zone')!.hidden).toBe(true)
    expect(document.getElementById('results')!.textContent).toContain('Receipt verifies')
  })

  // The pin on main.ts's call site. With no proofs/ member nothing reaches
  // verify()'s evidence channel and the page stays silent about transparency.
  // With one — here a deliberately unusable stub — the evidence arrives, the
  // pinned configuration judges it, and the verifier reports that it could
  // not resolve the claim. Reaching that verdict at all takes BOTH halves:
  // the evidence from the file and the pinned log from trusted-log.ts. Drop
  // either from the call and this goes quiet.
  const bundleWith = (members: Record<string, Uint8Array>): Uint8Array => {
    const m = manifest()
    const issuer = m.issuer as string
    const blob: JsonObject = { issuer, key_manifests: [m], artifact_manifests: [] }
    return zipSync({
      ['receipts/01JZ5PDHT0000G40R40M30E209.attest.json']: envelope(),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
      ...members,
    })
  }

  it('says nothing about transparency for a bundle carrying no proof', () => {
    app.handleBytes('library.attest', bundleWith({}))
    const text = document.getElementById('results')!.textContent ?? ''
    expect(text).not.toContain('transparency_claim_unresolvable')
    expect(text).toContain('"transparency": "not_checked"')
  })

  it('feeds a bundle’s proofs/ evidence to the pinned log, and reports what came of it', () => {
    const evidence = new TextEncoder().encode('{"leaf_index":0}')
    app.handleBytes('library.attest', bundleWith({ ['proofs/01JZ5PDHT0000G40R40M30E209.json']: evidence }))
    const text = document.getElementById('results')!.textContent ?? ''
    expect(text).toContain('transparency_claim_unresolvable')
    // Never this one again: it meant the page held no pinned log at all.
    expect(text).not.toContain('transparency_config_missing')
  })

  it('shows the private-file refusal', () => {
    app.handleBytes('lib.private.attest', new Uint8Array([0x50, 0x4b]))
    expect(document.getElementById('results')!.textContent).toMatch(/never share/i)
  })

  it('a refusal cancels a receipt still waiting for its key manifest', () => {
    // Otherwise the wait outlives the file it belongs to, and a manifest handed
    // over afterwards answers about the receipt that is no longer on screen —
    // replacing a refusal with a verdict about different bytes.
    app.handleBytes('receipt.attest.json', envelope())
    app.handleBytes('lib.private.attest', new Uint8Array([0x50, 0x4b]))
    const refused = document.getElementById('results')!.textContent

    app.handleManifestBytes(canonicalBytes(manifest()))

    expect(document.getElementById('results')!.textContent).toBe(refused)
    expect(document.getElementById('results')!.textContent).not.toContain('Receipt verifies')
  })

  it('opens the file picker from the dropzone on Enter and Space, but not other keys', () => {
    const fileInput = document.getElementById('file-input') as HTMLInputElement
    const spy = vi.fn()
    fileInput.click = spy
    const dropzone = document.getElementById('dropzone')!

    dropzone.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    expect(spy).toHaveBeenCalledTimes(1)

    dropzone.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true }))
    expect(spy).toHaveBeenCalledTimes(2)

    dropzone.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }))
    expect(spy).toHaveBeenCalledTimes(2)
  })
})

describe('the salted-envelope notice in the page', () => {
  const SALT = 'c2FsdHktbWNzYWx0ZmFjZQ'
  const saltedWithManifest = (): Uint8Array => {
    const env = loadsStrict(envelope()) as JsonObject
    return canonicalBytes({
      ...env,
      delivery: { issuer_manifest: manifest(), salt: SALT },
    } as JsonObject)
  }
  const saltedNoManifest = (): Uint8Array => {
    const env = loadsStrict(envelope()) as JsonObject
    return canonicalBytes({ ...env, delivery: { salt: SALT } } as JsonObject)
  }
  const results = (): HTMLElement => document.getElementById('results')!

  it('renders the notice above the result, not instead of it', () => {
    app.handleBytes('receipt.attest.json', saltedWithManifest())
    const children = Array.from(results().children)
    expect(children[0].className).toContain('notice')
    expect(children[0].textContent).toMatch(/never/i)
    // The receipt is still verified and rendered underneath.
    expect(results().querySelectorAll('article.result')).toHaveLength(1)
  })

  it('keeps the notice after a re-render from applyDisclosure', () => {
    app.handleBytes('receipt.attest.json', saltedWithManifest())
    ;(document.getElementById('binding-salt') as HTMLInputElement).value = SALT
    ;(document.getElementById('binding-identifier') as HTMLInputElement).value = 'a@b.example'
    app.applyDisclosure()
    expect(results().querySelector('.notice')!.textContent).toMatch(/never/i)
    expect(results().querySelectorAll('article.result')).toHaveLength(1)
  })

  it('keeps the notice across the needs-manifest handover', () => {
    app.handleBytes('receipt.attest.json', saltedNoManifest())
    expect(document.getElementById('manifest-zone')!.hidden).toBe(false)
    expect(results().textContent).toMatch(/never/i)

    app.handleManifestBytes(canonicalBytes(manifest()))
    expect(document.getElementById('manifest-zone')!.hidden).toBe(true)
    expect(results().querySelector('.notice')!.textContent).toMatch(/never/i)
    expect(results().textContent).toContain('Receipt verifies')
  })

  it('shows no notice for a salt-free receipt', () => {
    const env = loadsStrict(envelope()) as JsonObject
    app.handleBytes(
      'receipt.attest.json',
      canonicalBytes({ ...env, delivery: { issuer_manifest: manifest() } } as JsonObject),
    )
    expect(results().querySelector('.notice')).toBeNull()
  })
})

// --- T5.4-bis: the four evidence rails as page STATE (v0.1 §14.3) ------------
//
// `intake.test.ts` pins what a rail file parses to; this pins what the PAGE
// does with it, which is a different set of properties: rails outlive the
// receipts on screen, a later file for a rail replaces the earlier one rather
// than merging with it, a refused file changes nothing else, and only an
// explicit gesture puts a rail back to "not consulted".
describe('the evidence rails as page state', () => {
  const bytesOf = (text: string): Uint8Array => new TextEncoder().encode(text)
  const railLine = (): string => document.querySelector('p.rails')?.textContent ?? ''
  const results = (): HTMLElement => document.getElementById('results')!
  const withManifest = (): Uint8Array => {
    const parsed = loadsStrict(envelope()) as JsonObject
    return canonicalBytes({ ...parsed, delivery: { issuer_manifest: manifest() } } as JsonObject)
  }
  const loadReceipt = (): void => {
    app.handleBytes('receipt.attest.json', withManifest())
  }

  it('says a rail was not consulted, which the result cannot say', () => {
    // §14.3: `revocation` reads `unknown` for "no file" and for "an empty
    // feed" alike, so this line is the only place the two are told apart.
    loadReceipt()
    expect(railLine()).toContain('no revocation feed loaded')
  })

  it('says instead that an empty feed WAS consulted and found nothing', () => {
    loadReceipt()
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(railLine()).toContain('Revocation feed: 0 records')
    expect(railLine()).not.toContain('no revocation feed loaded')
  })

  it('carries the same distinction into the verdict copy', () => {
    // The rail line and the Revocation row are two sentences on one screen.
    // Letting them disagree would be the page contradicting itself about its
    // own state, which is the defect this wiring exists to prevent.
    loadReceipt()
    expect(results().textContent).toContain('No revocation feed was consulted')
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(results().textContent).not.toContain('No revocation feed was consulted')
    expect(results().textContent).toContain('A revocation feed was consulted')
  })

  it('keeps a rail dropped before any receipt arrived', () => {
    // The operator of the page supplies the issuer's evidence once and then
    // checks receipt after receipt against it. A rail emptied by the arrival
    // of a receipt would be a rail nobody could keep.
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    loadReceipt()
    expect(railLine()).toContain('Revocation feed: 0 records')
  })

  it('replaces a rail rather than merging into it', () => {
    loadReceipt()
    app.handleBytes('transfer-view.json', bytesOf('[{"a":1}]'))
    expect(railLine()).toContain('Transfer view: 1 claim')
    app.handleBytes('transfer-view.json', bytesOf('[]'))
    expect(railLine()).toContain('Transfer view: 0 claims')
  })

  it('holds the four slots independently', () => {
    loadReceipt()
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    app.handleBytes('transfer-view.json', bytesOf('[{"a":1}]'))
    app.handleBytes('compromise-view.json', bytesOf('[{"b":2}]'))
    app.handleBytes('revocation-evidence.json', bytesOf('{}'))
    expect(railLine()).toContain('Revocation feed: 0 records')
    expect(railLine()).toContain('Transfer view: 1 claim')
    expect(railLine()).toContain('Compromise view: 1 claim')
    expect(railLine()).toContain('Revocation evidence: loaded')
  })

  it('refuses one file without touching the receipts on screen', () => {
    // §14.3 makes a refused evidence file a refusal of THAT file which changes
    // nothing else. Clearing the verdicts would punish the reader for a typo
    // in a file that has nothing to do with the receipt they dropped.
    loadReceipt()
    expect(results().querySelectorAll('article.result:not(.rejected)')).toHaveLength(1)
    app.handleBytes('revocation-view.json', bytesOf('null'))
    // The refusal is ADDED, above the verdicts, and nothing is taken away: the
    // receipt's own card is still the one card on screen that reports a verdict.
    expect(results().querySelectorAll('article.result.rejected')).toHaveLength(1)
    expect(results().textContent).toContain('revocation-view.json')
    expect(results().querySelectorAll('article.result:not(.rejected)')).toHaveLength(1)
    expect(results().textContent).toContain('Receipt verifies')
  })

  it('refuses one file without emptying the rail it names', () => {
    loadReceipt()
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    app.handleBytes('revocation-view.json', bytesOf('null'))
    expect(railLine()).toContain('Revocation feed: 0 records')
  })

  it('puts every rail back to “not consulted”, and only on an explicit gesture', () => {
    loadReceipt()
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    app.handleBytes('transfer-view.json', bytesOf('[{"a":1}]'))
    app.clearRails()
    expect(railLine()).toContain('no revocation feed loaded')
    expect(railLine()).toContain('no transfer view loaded')
  })

  it('wires that gesture to the button the shipped page carries', () => {
    // The fixture is index.html itself, so this fails if the button is wired
    // in main.ts but never rendered — or rendered and never wired.
    loadReceipt()
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    const button = document.getElementById('clear-feeds')
    expect(button).toBeInstanceOf(HTMLButtonElement)
    ;(button as HTMLButtonElement).click()
    expect(railLine()).toContain('no revocation feed loaded')
  })

  it('qualifies verdicts with all four rails, and acknowledges just one without them', () => {
    // This replaces an assertion that the rail line is ABSENT when there are no
    // verdicts. That was true, and it was also why F3 went unseen: "nothing was
    // drawn" and "everything was erased" are indistinguishable to a test that
    // only checks for absence. The real distinction is what the line says.
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(railLine()).toBe('Revocation feed: 0 records')

    loadReceipt()
    expect(railLine()).toContain('Revocation feed: 0 records')
    expect(railLine()).toContain('no transfer view loaded')
    expect(railLine()).toContain('no compromise view loaded')
    expect(railLine()).toContain('no revocation evidence loaded')
  })

  it('does not erase the bearer-file refusal when a rail file arrives after it', () => {
    // Measured before this guard existed: the `.private.attest` refusal — the one
    // sentence on this page that is about the reader's own safety — was wiped by a
    // perfectly valid revocation-view.json dropped next, and the pane went blank.
    app.handleBytes('secrets.private.attest', bytesOf('anything'))
    expect(results().textContent).toContain('Never share')
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(results().textContent).toContain('Never share')
  })

  it('does not erase the manifest handover while the handover is still open', () => {
    app.handleBytes('receipt.attest.json', envelope())
    expect(document.getElementById('manifest-zone')!.hidden).toBe(false)
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(document.getElementById('manifest-zone')!.hidden).toBe(false)
    expect(results().textContent).toContain('issuer manifest')
  })

  it('acknowledges a rail accepted with no receipt on screen', () => {
    // Silence is the one answer a verifier may never give: a rail accepted with
    // nothing to qualify still has to say that it was accepted.
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(results().textContent).toContain('Revocation feed: 0 records')
  })
})
