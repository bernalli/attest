import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { applyTamper, tamperOptions, TAMPERS } from '../src/tamper.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT, trustStore } from './helpers/vectors.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const envelope = (): Uint8Array => new Uint8Array(readFileSync(join(V01, 'envelope.json')))
const store = () => trustStore(V01)

const differingOffsets = (a: Uint8Array, b: Uint8Array): number[] => {
  const out: number[] = []
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) if (a[i] !== b[i]) out.push(i)
  return out
}

const BYTE_TARGETS = ['title', 'store-name', 'receipt-id', 'signature'] as const

describe('the tamper bench edits exactly what it says it edits', () => {
  it('offers every byte target this receipt actually carries', () => {
    const ids = tamperOptions(envelope()).map((o) => o.id)
    for (const id of BYTE_TARGETS) expect(ids).toContain(id)
    // The trust target needs nothing from the file, so it is always offered.
    expect(ids).toContain('drop-manifest')
  })

  it.each(BYTE_TARGETS)('changes exactly one byte for %s, at the offset it reports', (id) => {
    const before = envelope()
    const t = applyTamper(id, before, store())
    expect(t).not.toBeNull()
    expect(t!.envelopeBytes).toHaveLength(before.length)
    const diff = differingOffsets(before, t!.envelopeBytes)
    expect(diff).toHaveLength(1)
    expect(diff[0]).toBe(t!.edit!.offset)
    expect(String.fromCharCode(before[t!.edit!.offset])).toBe(t!.edit!.before)
    expect(String.fromCharCode(t!.envelopeBytes[t!.edit!.offset])).toBe(t!.edit!.after)
    expect(t!.edit!.after).not.toBe(t!.edit!.before)
  })

  it('keeps the replacement in the same character class, so nothing else breaks', () => {
    // A signature is base64url: swapping in a byte outside that alphabet would
    // fail at decoding and tell a story about parsing, not about signing.
    const t = applyTamper('signature', envelope(), store())!
    expect(t.edit!.after).toMatch(/^[A-Za-z0-9]$/)
    expect(t.edit!.before).toMatch(/^[A-Za-z0-9]$/)
  })

  it('shows the value the reader can read, before and after', () => {
    const t = applyTamper('title', envelope(), store())!
    expect(t.edit!.was).toBe('Example Game')
    expect(t.edit!.now).not.toBe('Example Game')
    expect(t.edit!.now).toHaveLength('Example Game'.length)
  })
})

describe('the tamper bench actually flips the verdict', () => {
  it('verifies before, and does not verify after — for every byte target', () => {
    const clean = runVerify(envelope(), store())
    expect(clean.ok).toBe(true)
    expect(clean.result.signature).toBe('valid')

    for (const id of BYTE_TARGETS) {
      const t = applyTamper(id, envelope(), store())!
      const run = runVerify(t.envelopeBytes, t.trustStore)
      expect(run.ok, id).toBe(false)
      expect(run.result.signature, id).toBe('invalid')
      expect(run.result.errors.length, id).toBeGreaterThan(0)
    }
  })

  it('leaves the file untouched when it takes the issuer’s published material away', () => {
    const before = envelope()
    const t = applyTamper('drop-manifest', before, store())!
    expect(differingOffsets(before, t.envelopeBytes)).toEqual([])
    expect(t.edit).toBeNull()
    expect(Object.keys(t.trustStore.manifests)).toEqual([])

    const run = runVerify(t.envelopeBytes, t.trustStore)
    expect(run.ok).toBe(false)
    expect(run.result.signature).toBe('invalid')
  })

  it('gives a different reason for a broken file than for absent issuer material', () => {
    const broken = runVerify(
      applyTamper('title', envelope(), store())!.envelopeBytes,
      store(),
    ).result.errors.join(' | ')
    const t = applyTamper('drop-manifest', envelope(), store())!
    const stripped = runVerify(t.envelopeBytes, t.trustStore).result.errors.join(' | ')
    expect(broken).not.toBe(stripped)
  })
})

describe('the tamper bench refuses what it cannot do honestly', () => {
  const withTitle = (title: string): Uint8Array => {
    const env = loadsStrict(envelope()) as JsonObject
    const payload = { ...(env.payload as JsonObject) }
    payload.work = { ...(payload.work as JsonObject), title }
    return canonicalBytes({ ...env, payload } as JsonObject)
  }

  it('skips a value with no ASCII letter or digit to turn', () => {
    // A single-byte edit inside a multi-byte character would produce invalid
    // UTF-8 and a story about encoding, not about signatures.
    const ids = tamperOptions(withTitle('日本語')).map((o) => o.id)
    expect(ids).not.toContain('title')
    expect(ids).toContain('signature')
    expect(applyTamper('title', withTitle('日本語'), store())).toBeNull()
  })

  it('skips a target the receipt does not carry at all', () => {
    const env = loadsStrict(envelope()) as JsonObject
    const payload = { ...(env.payload as JsonObject) }
    const work = { ...(payload.work as JsonObject) }
    delete work.title
    payload.work = work
    const bytes = canonicalBytes({ ...env, payload } as JsonObject)
    expect(tamperOptions(bytes).map((o) => o.id)).not.toContain('title')
  })

  it('offers nothing at all for bytes that are not a receipt', () => {
    expect(tamperOptions(new TextEncoder().encode('not json'))).toEqual([])
  })

  it('names every tamper it offers, with a line saying what it does', () => {
    for (const t of TAMPERS) {
      expect(t.label.length).toBeGreaterThan(0)
      expect(t.what.length).toBeGreaterThan(0)
    }
    expect(new Set(TAMPERS.map((t) => t.id)).size).toBe(TAMPERS.length)
  })
})

describe('the tamper bench stays on the page’s own thread', () => {
  // Proving the landing site means trying occurrences, and each try copies and
  // re-parses the whole envelope. Without a cheap filter that is quadratic in
  // the worst case a receipt can actually have: a common single letter as the
  // title matches everywhere. Measured at 29 SECONDS on the shape below, twice
  // over — `tamperOptions` runs on drop, before the reader clicks anything.
  //
  // The budget is deliberately two orders of magnitude above the fixed
  // version (tens of milliseconds) so this fails on a return of the defect,
  // never on a slow machine.
  const BUDGET_MS = 2000

  it('offers and applies within a blink on a receipt full of matches', () => {
    const e = loadsStrict(envelope()) as JsonObject
    const payload = { ...(e.payload as JsonObject) }
    const work = { ...(payload.work as JsonObject) }
    work.title = 'a'
    // A large body of text carrying that letter thousands of times.
    work.publisher = `Studio ${'a b c '.repeat(4000)}`
    payload.work = work
    const bytes = canonicalBytes({ ...e, payload } as JsonObject)
    expect(bytes.length).toBeGreaterThan(20_000)

    const t0 = performance.now()
    const ids = tamperOptions(bytes).map((o) => o.id)
    const offered = performance.now() - t0

    const t1 = performance.now()
    const applied = ids.includes('title') ? applyTamper('title', bytes, store()) : null
    const spent = performance.now() - t1

    expect(offered, 'tamperOptions on a receipt with thousands of matches').toBeLessThan(BUDGET_MS)
    expect(spent, 'applyTamper on the same receipt').toBeLessThan(BUDGET_MS)
    // And it still edits the right field, which is the whole point of the
    // work the filter is making cheaper.
    if (applied) {
      const p = (loadsStrict(applied.envelopeBytes) as JsonObject).payload as JsonObject
      expect((p.work as JsonObject).title).toBe(applied.edit!.now)
    }
  })
})

describe('the tamper bench edits the field it names, not one that looks like it', () => {
  const payloadOf = (b: Uint8Array): JsonObject =>
    (loadsStrict(b) as JsonObject).payload as JsonObject
  const rebuilt = (mutate: (p: JsonObject) => JsonObject): Uint8Array => {
    const e = loadsStrict(envelope()) as JsonObject
    return canonicalBytes({ ...e, payload: mutate({ ...(e.payload as JsonObject) }) } as JsonObject)
  }

  // 01-valid-minimal's own title is a prefix of its own issuer display name,
  // and `issuer` sorts before `work`: searching the envelope for the title's
  // bytes finds the DISPLAY NAME first. Every other test in this file passed
  // while the title button edited the seller's name, because none of them
  // asked what the file said afterwards — only that some byte had moved.
  it('edits the title of the very vector the rest of this file uses', () => {
    const t = applyTamper('title', envelope(), store())!
    const p = payloadOf(t.envelopeBytes)
    expect((p.work as JsonObject).title).toBe(t.edit!.now)
    expect((p.issuer as JsonObject).display_name).toBe('Example Games Store')
  })

  it('edits the title when the title also sits inside the publisher’s name', () => {
    const bytes = rebuilt((p) => ({
      ...p,
      work: { ...(p.work as JsonObject), publisher: 'Starlight Drifter Studios', title: 'Starlight Drifter' },
    }))
    const w = payloadOf(applyTamper('title', bytes, store())!.envelopeBytes).work as JsonObject
    expect(w.publisher).toBe('Starlight Drifter Studios')
    expect(w.title).not.toBe('Starlight Drifter')
  })

  it('edits the title when the seller’s display name is the same string', () => {
    const bytes = rebuilt((p) => ({
      ...p,
      issuer: { ...(p.issuer as JsonObject), display_name: 'Starlight Drifter' },
      work: { ...(p.work as JsonObject), title: 'Starlight Drifter' },
    }))
    const p = payloadOf(applyTamper('title', bytes, store())!.envelopeBytes)
    expect((p.issuer as JsonObject).display_name).toBe('Starlight Drifter')
    expect((p.work as JsonObject).title).not.toBe('Starlight Drifter')
  })

  // `now` used to be built by slicing the string at a BYTE index, which is a
  // UTF-16 index in JavaScript: any character above U+007F before the byte
  // that turned put the replacement in the wrong place, and the page printed
  // a value the file does not contain.
  it('reports the value the file actually holds, not one built by slicing', () => {
    const bytes = rebuilt((p) => ({ ...p, work: { ...(p.work as JsonObject), title: 'é1abc' } }))
    const t = applyTamper('title', bytes, store())!
    expect(t.edit!.now).toBe((payloadOf(t.envelopeBytes).work as JsonObject).title)
  })
})
