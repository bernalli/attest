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
