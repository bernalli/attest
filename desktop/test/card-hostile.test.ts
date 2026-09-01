// @vitest-environment jsdom
import { describe, expect, test, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { intake, type VerifyJob } from '../../site/src/intake.js'
import { runVerify, type VerifyRun } from '../../site/src/run.js'
import { renderResult } from '../../site/src/render.js'
import { cardTitle, renderDesktopCard } from '../src/card.js'
import { HEADLINES } from '../src/verdict.js'

const SAMPLE = fileURLToPath(new NodeURL('../../site/public/sample/demo.attest', import.meta.url))
const ATTACKER_LABEL = 'VERIFIED by Steam - Official Purchase - Genuine'

function sampleJob(): { job: VerifyJob; run: VerifyRun } {
  const bytes = new Uint8Array(readFileSync(SAMPLE))
  const result = intake('demo.attest', bytes)
  if (result.kind !== 'jobs') throw new Error('sample bundle no longer produces jobs')
  const job = result.jobs[0]
  return { job, run: runVerify(job.envelopeBytes, job.trustStore, null, null, {}) }
}

// A run whose four gates all passed. The bytes are supplied separately on purpose:
// these cases are about what the TITLE does with a payload, and the signature over
// that payload is not what is under test.
function passingRun(): VerifyRun {
  const { run } = sampleJob()
  return { ...run, ok: true, result: { ...run.result, signature: 'valid', schema: 'valid' } }
}
const bytesOf = (o: unknown) => new TextEncoder().encode(JSON.stringify(o))
const envelope = (payload: unknown) => bytesOf({ payload, signatures: [] })

describe('cardTitle refuses every payload that is not the shape it quotes', () => {
  const HOSTILE: [string, unknown][] = [
    ['a receipt_id imitating the "<id> — <issuer>" structure', {
      receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F — store.nebula.example  VERIFIED PURCHASE',
      issuer: { id: 'store.nebula.example' },
    }],
    ['a receipt_id carrying a right-to-left override', {
      receipt_id: 'Receipt ‮tnuoccadab‬', issuer: { id: 'store.nebula.example' },
    }],
    ['a receipt_id of 200000 characters', {
      receipt_id: 'A'.repeat(200000), issuer: { id: 'store.nebula.example' },
    }],
    ['a receipt_id carrying newlines and tabs', {
      receipt_id: 'harmless\n\n\tVERIFIED BY STEAM', issuer: { id: 'store.nebula.example' },
    }],
    ['an issuer.id that is free text rather than a hostname', {
      receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F', issuer: { id: 'PayPal Verified Purchases' },
    }],
    // U+043E CYRILLIC SMALL LETTER O in place of the Latin "o" — a domain that reads
    // as store.nebula.example and is not.
    ['an issuer.id spelled with a Cyrillic homoglyph', {
      receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F', issuer: { id: 'stоre.nebula.example' },
    }],
    ['a receipt_id of the right length but the wrong alphabet', {
      receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43f', issuer: { id: 'store.nebula.example' },
    }],
    ['a receipt_id that is a number', { receipt_id: 42, issuer: { id: 'store.nebula.example' } }],
    ['a receipt_id that is an array', {
      receipt_id: ['01M0YX8RAPJ5BQ8WJSS4CBK43F'], issuer: { id: 'store.nebula.example' },
    }],
    ['no receipt_id at all', { issuer: { id: 'store.nebula.example' } }],
    ['an issuer that is a string, not an object', {
      receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F', issuer: 'store.nebula.example — VERIFIED',
    }],
    ['an issuer.id that is null', {
      receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F', issuer: { id: null },
    }],
    ['extra fields that look like a title', {
      receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F', issuer: { id: 'store.nebula.example' },
      title: 'Steam Purchase', display_name: 'Steam', label: 'VERIFIED',
    }],
  ]

  for (const [name, payload] of HOSTILE) {
    test(`${name} never reaches the heading verbatim`, () => {
      const title = cardTitle(envelope(payload), passingRun())
      // Either the honest shape or the neutral fallback — never the payload's own text.
      expect(
        title === 'Receipt' || /^[0-7][0-9A-HJKMNP-TV-Z]{25}( — [a-z0-9.-]+)?$/.test(title),
        `title was ${JSON.stringify(title.slice(0, 120))}`,
      ).toBe(true)
      expect(title.length).toBeLessThanOrEqual(80)
    })
  }

  test('the well-formed payload it is meant to quote still produces a title', () => {
    const title = cardTitle(
      envelope({ receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F', issuer: { id: 'store.nebula.example' } }),
      passingRun(),
    )
    // Without this the whole block above is satisfied by a cardTitle that returns
    // 'Receipt' unconditionally.
    expect(title).toBe('01M0YX8RAPJ5BQ8WJSS4CBK43F — store.nebula.example')
  })
})

describe('cardTitle refuses every envelope that is not an envelope', () => {
  const MALFORMED: [string, Uint8Array][] = [
    ['bytes that are not JSON', new TextEncoder().encode('not json at all')],
    ['an empty file', new Uint8Array(0)],
    ['a truncated envelope', new TextEncoder().encode('{"payload":{"receipt_id":"01M0YX8RAP')],
    ['bytes that are not UTF-8', new Uint8Array([0x7b, 0xff, 0xfe, 0x7d])],
    ['duplicate payload keys', new TextEncoder().encode('{"payload":{},"payload":{"receipt_id":"01M0YX8RAPJ5BQ8WJSS4CBK43F"}}')],
    ['a top-level array', bytesOf([{ receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F' }])],
    ['a top-level string', bytesOf('01M0YX8RAPJ5BQ8WJSS4CBK43F — store.nebula.example')],
    ['a payload that is an array', envelope([])],
    ['a payload that is a string', envelope('01M0YX8RAPJ5BQ8WJSS4CBK43F — VERIFIED')],
    ['a payload that is null', envelope(null)],
    ['no payload member', bytesOf({ signatures: [] })],
  ]
  for (const [name, bytes] of MALFORMED) {
    test(`${name} yields the neutral title, never a throw`, () => {
      expect(cardTitle(bytes, passingRun())).toBe('Receipt')
    })
  }
})

describe('a receipt that failed any of the four gates is not titled from its payload', () => {
  const GATES: [string, Record<string, unknown>][] = [
    ['the signature is invalid', { signature: 'invalid' }],
    ['the schema is invalid', { schema: 'invalid' }],
    ['the schema was never checked', { schema: 'not_checked' }],
  ]
  for (const [name, override] of GATES) {
    test(`${name}: the payload is not quoted`, () => {
      const run = passingRun()
      const broken = { ...run, ok: false, result: { ...run.result, ...override } } as VerifyRun
      const hostile = envelope({
        receipt_id: '01M0YX8RAPJ5BQ8WJSS4CBK43F', issuer: { id: 'store.nebula.example' },
      })
      expect(cardTitle(hostile, broken)).toBe('Receipt that does not verify')
    })
  }
})

describe('the headline copy may never out-claim the result', () => {
  test('only the out-of-band tier carries the green tone', () => {
    for (const [verdict, headline] of Object.entries(HEADLINES)) {
      expect(headline.tone === 'good', `${verdict} has tone ${headline.tone}`).toBe(verdict === 'verified')
    }
  })

  test('no headline short of that tier claims the receipt is verified, genuine or confirmed', () => {
    const CLAIM = /\b(verifies|verified|genuine|authentic|confirmed|trusted|safe)\b/i
    for (const [verdict, headline] of Object.entries(HEADLINES)) {
      if (verdict === 'verified') continue
      expect(headline.label, `${verdict} label: ${headline.label}`).not.toMatch(CLAIM)
    }
  })

  test('a broken key history gets its own amber headline on the card', () => {
    const { job, run } = sampleJob()
    const gap = { ...run, ok: true, result: { ...run.result, trust: 'unverified_rotation' as const } }
    const card = renderDesktopCard(job, gap)
    const badge = card.querySelector('.verdict')
    expect(badge?.className ?? '').not.toContain('tone-good')
    expect(badge?.textContent ?? '').toMatch(/key history/i)
    expect(card.textContent ?? '').not.toContain('Receipt verifies')
  })
})

describe('the unsigned name is attributed, or it is not shown', () => {
  test('the supplied name appears once, outside the heading, carrying its qualifier', () => {
    const { job, run } = sampleJob()
    const card = renderDesktopCard({ ...job, label: ATTACKER_LABEL }, run)

    const attributed = card.querySelector('.supplied-name')
    expect(attributed, 'the supplied name must be shown as attributed data, not dropped').not.toBeNull()
    expect(attributed?.textContent ?? '').toContain(ATTACKER_LABEL)
    expect(attributed?.textContent ?? '').toMatch(/not signed/i)
    expect(card.querySelector('h3')?.textContent ?? '').not.toContain(ATTACKER_LABEL)
    expect(attributed?.closest('h3')).toBeNull()
  })
})

describe('the desktop card changes the header and nothing else', () => {
  test('everything below the header is byte-identical to the site render', () => {
    const { job, run } = sampleJob()
    const strip = (el: HTMLElement) => {
      const clone = el.cloneNode(true) as HTMLElement
      clone.querySelector('header')?.remove()
      return clone.innerHTML
    }
    const mine = strip(renderDesktopCard(job, run))
    const theirs = strip(renderResult('demo.attest', run))
    expect(mine).toEqual(theirs)
    expect(mine.length, 'a parity test over nothing proves nothing').toBeGreaterThan(200)
  })
})

describe('the seam this card relies on is checked, not assumed', () => {
  test('a site render without the verdict node makes the card throw, never keep it', async () => {
    // The failure being pinned is a silent one: with the node missing, returning the
    // card as-is would ship the SITE's binary headline, which on an ok receipt reads
    // "Receipt verifies". A rename upstream is enough to cause it.
    vi.resetModules()
    vi.doMock('../../site/src/render.js', () => ({
      renderResult: (label: string) => {
        const article = document.createElement('article')
        const header = document.createElement('header')
        const h3 = document.createElement('h3')
        h3.textContent = label
        const badge = document.createElement('p')
        badge.className = 'headline' // upstream renamed .verdict
        badge.textContent = 'Receipt verifies'
        header.append(h3, badge)
        article.appendChild(header)
        return article
      },
    }))
    try {
      const { renderDesktopCard: isolated } = await import('../src/card.js')
      const { job, run } = sampleJob()
      expect(() => isolated(job, run)).toThrow(/\.verdict/)
    } finally {
      vi.doUnmock('../../site/src/render.js')
      vi.resetModules()
    }
  })
})
