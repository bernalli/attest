// @vitest-environment jsdom
import { describe, expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
// node:url's URL explicitly: under `@vitest-environment jsdom` the global URL is
// jsdom's WHATWG implementation, which fileURLToPath does not recognise. The site's
// own test helpers hit this first and solve it the same way.
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { intake } from '../../site/src/intake.js'
import { runVerify } from '../../site/src/run.js'
import { renderResult } from '../../site/src/render.js'
import { renderDesktopCard } from '../src/card.js'

const SAMPLE = fileURLToPath(new NodeURL('../../site/public/sample/demo.attest', import.meta.url))

// The signed payload of the in-repo sample. The card must be titled from these, never
// from a name someone chose outside the signature.
const REAL_RECEIPT_ID = '01M0YX8RAPJ5BQ8WJSS4CBK43F'
const REAL_ISSUER = 'store.nebula.example'
const ATTACKER_LABEL = 'VERIFIED by Steam - Official Purchase - Genuine'

function sampleJob() {
  const bytes = new Uint8Array(readFileSync(SAMPLE))
  const result = intake('demo.attest', bytes)
  if (result.kind !== 'jobs') throw new Error('sample bundle no longer produces jobs')
  const job = result.jobs[0]
  return { job, run: runVerify(job.envelopeBytes, job.trustStore, null, null, {}) }
}

describe('the card is titled by the signature, not by whoever handed over the file', () => {
  test('an attacker-chosen label never becomes the title', () => {
    // This is the defect as it exists in the shipped web verifier: the ZIP member name
    // is unsigned and reaches the heading directly above the verdict badge, so a file
    // can announce "VERIFIED by Steam" over a genuinely valid signature belonging to
    // someone else entirely. Titling from the payload is what closes it.
    const { job, run } = sampleJob()
    const card = renderDesktopCard({ ...job, label: ATTACKER_LABEL }, run, 'demo.attest')
    const title = card.querySelector('h3')?.textContent ?? ''

    expect(title).not.toContain('Steam')
    expect(title).toContain(REAL_RECEIPT_ID)
    expect(title).toContain(REAL_ISSUER)
  })

  test('the supplied name may still be shown, but labelled as unsigned and never as the title', () => {
    const { job, run } = sampleJob()
    const card = renderDesktopCard({ ...job, label: ATTACKER_LABEL }, run, 'demo.attest')
    const title = card.querySelector('h3')?.textContent ?? ''
    const whole = card.textContent ?? ''

    // If the name appears at all it must be outside the heading and marked as not signed,
    // so a reader can tell which of the two strings the signature actually covers.
    if (whole.includes(ATTACKER_LABEL)) {
      expect(title).not.toContain(ATTACKER_LABEL)
      expect(whole).toMatch(/not signed/i)
    }
  })

  test('an unverifiable envelope is not titled as if its payload were authentic', () => {
    // With a broken signature the payload is just bytes someone sent: quoting a receipt
    // id out of it as the card's title would dress unauthenticated content as identity.
    const { job, run } = sampleJob()
    const broken = { ...run, ok: false, result: { ...run.result, signature: 'invalid' as const } }
    const card = renderDesktopCard({ ...job, label: 'whatever.attest' }, broken, 'whatever.attest')
    const title = card.querySelector('h3')?.textContent ?? ''

    expect(title).not.toContain(REAL_RECEIPT_ID)
    expect(title).not.toContain(REAL_ISSUER)
  })
})

describe('the headline says what the result supports', () => {
  test('a trust-on-first-use receipt never shows the binary "Receipt verifies" headline', () => {
    const { job, run } = sampleJob()
    expect(run.result.trust).toBe('unauthenticated_tofu') // guards the premise of this test
    const card = renderDesktopCard(job, run, 'demo.attest')

    expect(card.textContent ?? '').not.toContain('Receipt verifies')
  })

  test('the amber headline names the three things an ok result leaves open', () => {
    const { job, run } = sampleJob()
    const card = renderDesktopCard(job, run, 'demo.attest')
    const headline = card.querySelector('.verdict')?.textContent ?? ''

    expect(headline).toMatch(/belongs to the seller/i) // key trust
    expect(headline).toMatch(/revok/i) // revocation was not consulted
    expect(headline).toMatch(/binding secret/i) // binding was not checked
    expect(headline).not.toMatch(/receipt is yours|belongs to you/i)
  })

  test('exactly one verdict node survives the header replacement', () => {
    const { job, run } = sampleJob()
    const card = renderDesktopCard(job, run, 'demo.attest')
    expect(card.querySelectorAll('.verdict')).toHaveLength(1)
  })

  test('the site still renders exactly one verdict node — the seam this replacement relies on', () => {
    // A structural pin: if an upstream change renames the class or emits two badges,
    // this fails here rather than leaving the desktop card silently showing the binary
    // headline it exists to remove.
    const { job, run } = sampleJob()
    expect(renderResult('demo.attest', run).querySelectorAll('.verdict')).toHaveLength(1)
  })
})

describe('every row the site shows, the desktop shows identically', () => {
  test('component rows match the site render exactly — the header is the only sanctioned difference', () => {
    const { job, run } = sampleJob()
    const mine = renderDesktopCard(job, run, 'demo.attest')
    const theirs = renderResult('demo.attest', run)

    const rows = (el: HTMLElement) =>
      [...el.querySelectorAll('.component-value, .component-note, dt')].map((n) => n.textContent)

    expect(rows(mine)).toEqual(rows(theirs))
    expect(rows(mine).length).toBeGreaterThan(0) // a parity test over nothing proves nothing
  })
})

describe('untrusted strings stay inert', () => {
  test('a hostile file name creates text, never elements', () => {
    const { job, run } = sampleJob()
    const card = renderDesktopCard({ ...job, label: '<img src=x onerror=alert(1)>.attest' }, run, 'plain.attest')
    expect(card.querySelector('img')).toBeNull()
  })
})

describe('the name the OS handed over is shown as such, and it is not the signed one', () => {
  // `intake` labels a job with the SIGNED receipt id (upstream: "every string the
  // verifier shows comes from the signed payload"). So `job.label` is emphatically NOT
  // the name of the file a person dropped, and printing it under "File you dropped …
  // (this name is not signed)" would state the exact opposite of the truth — in a file
  // that is downloaded once and can never be corrected.
  test('the supplied-name line names the dropped file, never the signed receipt id', () => {
    const { job, run } = sampleJob()
    const card = renderDesktopCard(job, run, 'my-purchase.attest')
    const supplied = card.querySelector('.supplied-name')?.textContent ?? ''

    expect(supplied).toContain('my-purchase.attest')
    expect(supplied).toMatch(/not signed/i)
    expect(supplied).not.toContain(REAL_RECEIPT_ID)
  })

  test('the dropped name is text, never markup', () => {
    const { job, run } = sampleJob()
    const hostile = '<img src=x onerror=alert(1)>.attest'
    const card = renderDesktopCard(job, run, hostile)
    const supplied = card.querySelector('.supplied-name')

    expect(supplied?.textContent).toContain(hostile)
    expect(supplied?.querySelector('img')).toBeNull()
  })
})

describe('the two amber headlines are told apart by the stylesheet, not only by wording', () => {
  // A headline whose only distinguishing feature is its wording is not a multi-state
  // headline: a reader who has learned "amber means the ordinary offline limit" will
  // read the anomaly as the limit. So the two carry different classes, and the
  // stylesheet is free to make them look different.
  const headerClasses = (trust: 'unauthenticated_tofu' | 'unverified_rotation'): string => {
    const { job, run } = sampleJob()
    const shaped = { ...run, ok: true, result: { ...run.result, trust } }
    const card = renderDesktopCard(job, shaped, 'demo.attest')
    return card.querySelector('.verdict')?.className ?? ''
  }

  test('a key-history gap is not styled as the ordinary offline limit', () => {
    expect(headerClasses('unverified_rotation')).not.toEqual(headerClasses('unauthenticated_tofu'))
  })

  test('both remain cautionary, and neither is styled as a pass', () => {
    for (const trust of ['unauthenticated_tofu', 'unverified_rotation'] as const) {
      expect(headerClasses(trust)).toContain('tone-warn')
      expect(headerClasses(trust)).not.toContain('tone-good')
    }
  })
})
