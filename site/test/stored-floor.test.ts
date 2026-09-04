// @vitest-environment jsdom
//
// The container as stored, bounded before it is copied (v0.1 §14.4).
//
// §14.4 asks for the spend to be bounded BEFORE the members are analysed, and
// it fixes a floor for the container as it sits on disk. A surface that reads
// the whole file into memory and only then decides it is too large has already
// spent what the floor exists to protect, and the refusal it eventually shows
// is a statement about bytes it has already paid for.
//
// Two properties are pinned here rather than one. The first is the number: the
// floor is normative, so a change to it is a change to what this project
// promises, not a local tuning decision. The second is the ORDER: the size is
// consulted before `arrayBuffer()`, before `fetch` hands over a body, and
// before the container reader walks a directory — which is why the tests below
// watch for a call that must not happen rather than only for a message.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { MAX_STORED_BYTES } from '../src/container.js'
import { parseBundle, BundleTooLargeError, BundleError, DEFAULT_CAPS } from '../src/bundle.js'
import { declinedForSize } from '../src/intake.js'
import { loadSample } from '../src/sample.js'
import { initApp, type AppHandle } from '../src/main.js'
import { VECTORS_ROOT } from './helpers/vectors.js'
import { pageBody } from './helpers/page.js'
import { LEGAL_TEXT, LEGAL_DIGEST } from './helpers/zip.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')

/** A real `.attest`-shaped archive, small enough to sit far under the floor. */
function bundleBytes(): Uint8Array {
  const envelope = new Uint8Array(readFileSync(join(V01, 'envelope.json')))
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  const blob: JsonObject = { issuer, key_manifests: [manifests[issuer]], artifact_manifests: [] }
  return zipSync({
    ['receipts/01HZX0000000000000000000AA.attest.json']: envelope,
    [`manifests/${issuer}.json`]: canonicalBytes(blob),
    [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
  })
}

describe('the floor for a container as stored', () => {
  it('is the number v0.1 §14.4 fixes, and not a local choice', () => {
    // Written twice on purpose: the left side is what the code computes, the
    // right side is the number the section names. A future edit that changes
    // the arithmetic has to change the normative number too, in the open.
    expect(MAX_STORED_BYTES).toBe(1073741824)
    expect(MAX_STORED_BYTES).toBe(1024 * 1024 * 1024)
  })
})

describe('the admission boundary decides from the size alone', () => {
  it('admits a container of exactly the floor', () => {
    expect(declinedForSize(MAX_STORED_BYTES)).toBeNull()
  })

  it('declines a container one byte over the floor', () => {
    const refusal = declinedForSize(MAX_STORED_BYTES + 1)
    expect(refusal).not.toBeNull()
    expect(refusal?.kind).toBe('rejected')
    // `declined` and never a plain rejection: nobody read these bytes, and
    // §14.4 forbids a surface from showing an unread container as invalid.
    expect(refusal?.declined).toBe(true)
  })

  it('says how large the container was against the limit', () => {
    const reason = declinedForSize(MAX_STORED_BYTES + 1)?.reason ?? ''
    expect(reason).toContain(String(MAX_STORED_BYTES + 1))
    expect(reason).toContain(String(MAX_STORED_BYTES))
    // A refusal about size may not read as a verdict about content.
    expect(reason).not.toMatch(/invalid|corrupt|tampered/i)
  })

  it('reads a size it cannot make sense of as no reason to refuse', () => {
    // A `File` that reports nothing usable is not a container over the floor;
    // it is a file this boundary knows nothing about, and the reader below is
    // where it earns its verdict.
    expect(declinedForSize(Number.NaN)).toBeNull()
    expect(declinedForSize(0)).toBeNull()
  })
})

describe('parseBundle bounds the container as stored before it reads members', () => {
  it('accepts a container of exactly the limit it is given', () => {
    const zip = bundleBytes()
    expect(parseBundle(zip, DEFAULT_CAPS, zip.byteLength).receipts).toHaveLength(1)
  })

  it('refuses a container one byte over the limit it is given', () => {
    const zip = bundleBytes()
    expect(() => parseBundle(zip, DEFAULT_CAPS, zip.byteLength - 1)).toThrow(BundleTooLargeError)
  })

  it('refuses on the size before it decides whether the bytes are an archive', () => {
    // Not an archive at all. Under the floor this earns "not a readable zip";
    // over it, the size is the only thing anyone is entitled to say, because
    // the member list was never walked.
    const notAnArchive = new TextEncoder().encode('not a zip, and over the limit')
    expect(() => parseBundle(notAnArchive, DEFAULT_CAPS, 4)).toThrow(BundleTooLargeError)
    expect(() => parseBundle(notAnArchive, DEFAULT_CAPS, notAnArchive.byteLength)).toThrow(
      BundleError,
    )
    expect(() => parseBundle(notAnArchive, DEFAULT_CAPS, notAnArchive.byteLength)).not.toThrow(
      BundleTooLargeError,
    )
  })

  it('defaults to the normative floor when no limit is given', () => {
    const zip = bundleBytes()
    expect(zip.byteLength).toBeLessThan(MAX_STORED_BYTES)
    expect(parseBundle(zip).receipts).toHaveLength(1)
  })
})

// --- the surfaces, where the copy is actually paid for -----------------------

/** A file the page can be handed without allocating one. Only `name` and
 * `size` are read before the boundary decides, which is the point. */
const fileOfSize = (name: string, size: number, arrayBuffer: () => Promise<ArrayBuffer>): File =>
  ({ name, size, arrayBuffer }) as unknown as File

const drop = (doc: Document, file: File): void => {
  const event = new Event('drop') as Event & { dataTransfer: unknown }
  Object.defineProperty(event, 'dataTransfer', { value: { files: [file] } })
  doc.getElementById('dropzone')!.dispatchEvent(event)
}

describe('the page refuses an oversized file without copying it first', () => {
  let app: AppHandle
  beforeEach(() => {
    document.body.innerHTML = pageBody()
    app = initApp(document)
  })

  it('never asks for the bytes of a file over the floor', async () => {
    const bytes = vi.fn(() => Promise.resolve(new ArrayBuffer(0)))
    drop(document, fileOfSize('huge.attest', MAX_STORED_BYTES + 1, bytes))
    await Promise.resolve()
    expect(bytes).not.toHaveBeenCalled()
  })

  it('shows the neutral register for a file it did not read', async () => {
    drop(
      document,
      fileOfSize('huge.attest', MAX_STORED_BYTES + 1, () => Promise.resolve(new ArrayBuffer(0))),
    )
    await Promise.resolve()
    const results = document.getElementById('results')!
    const classes = [...results.querySelectorAll('*')].map((node) => node.className)
    expect(classes).toContain('verdict tone-neutral')
    expect(classes).not.toContain('verdict tone-bad')
    expect(results.textContent ?? '').not.toMatch(/invalid|corrupt|tampered/i)
  })

  it('does not name the file it refused', async () => {
    // A file name is text whoever sent the file chose, on the same footing as
    // a ZIP member name (`UNIDENTIFIED_LABEL`), and this refusal needs none.
    drop(
      document,
      fileOfSize('Your receipt is valid.attest', MAX_STORED_BYTES + 1, () =>
        Promise.resolve(new ArrayBuffer(0)),
      ),
    )
    await Promise.resolve()
    expect(document.getElementById('results')!.textContent ?? '').not.toContain('Your receipt is valid')
  })

  it('still reads a file at exactly the floor', async () => {
    const zip = bundleBytes()
    const bytes = vi.fn(() => Promise.resolve(zip.buffer as ArrayBuffer))
    drop(document, fileOfSize('library.attest', MAX_STORED_BYTES, bytes))
    await Promise.resolve()
    expect(bytes).toHaveBeenCalledTimes(1)
  })

  it('leaves a verdict on screen for an ordinary bundle', async () => {
    const zip = bundleBytes()
    drop(
      document,
      fileOfSize('library.attest', zip.byteLength, () => Promise.resolve(zip.buffer as ArrayBuffer)),
    )
    await Promise.resolve()
    await Promise.resolve()
    expect(document.getElementById('results')!.querySelectorAll('article.result').length).toBe(1)
    void app
  })
})

describe('the sample is bounded at the network edge too', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const serving = (declaredLength: string | null, body: () => Uint8Array, seen: string[]): void => {
    vi.stubGlobal('fetch', (url: string) =>
      Promise.resolve(
        url.endsWith('demo.attest')
          ? {
              ok: true,
              headers: { get: () => declaredLength },
              arrayBuffer: () => {
                seen.push('body')
                return Promise.resolve(body().buffer)
              },
            }
          : { ok: true, headers: { get: () => null }, json: () => Promise.resolve({}) },
      ),
    )
  }

  it('refuses on the declared length, before the body is materialised', async () => {
    const seen: string[] = []
    serving(String(MAX_STORED_BYTES + 1), () => new Uint8Array(0), seen)
    await expect(loadSample()).rejects.toThrow(BundleTooLargeError)
    expect(seen).toEqual([])
  })

  it('refuses a body over the limit even when the response declared nothing', async () => {
    const seen: string[] = []
    serving(null, () => new Uint8Array(64), seen)
    await expect(loadSample('sample/', 32)).rejects.toThrow(BundleTooLargeError)
    expect(seen).toEqual(['body'])
  })

  it('accepts a body of exactly the limit', async () => {
    const seen: string[] = []
    serving('32', () => new Uint8Array(32), seen)
    await expect(loadSample('sample/', 32)).resolves.toBeTruthy()
  })
})
