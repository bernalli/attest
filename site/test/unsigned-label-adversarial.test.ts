// @vitest-environment jsdom
//
// Everything the verifier shows a buyer must come from the signed payload.
//
// The attack these tests pin costs nothing to mount: take a real bundle, leave
// every byte of the payload and the signature untouched, and rewrite one name
// in the ZIP central directory — metadata no signature covers. The verifier put
// that name in the `<h3>` immediately above the verdict badge, so the page read
//
//     VERIFIED by Steam - Official Purchase - Genuine
//     Receipt verifies — Signature valid, schema valid, not revoked
//
// while the signed payload said `issuer.display_name: "Nebula Games"`. A lie
// with a valid signature underneath it, on the page a buyer meets first.
//
// The property is not "this line is fixed". It is that no attacker-supplied
// string reaches the buyer's eyes at all, so these tests come at it from every
// entry point the page has: a bundle member name, a dropped file name, and the
// notices rendered beside them.

import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { unzipSync, zipSync } from 'fflate'
import { intake, UNIDENTIFIED_LABEL } from '../src/intake.js'
import { renderResult, renderVerifyFailure } from '../src/render.js'
import type { VerifyRun } from '../src/run.js'
import type { VerificationResult } from 'attest-verifier'
import { embeddedManifest, storedZip, validEntries, validEnvelope, VALID_RECEIPT_ID } from './helpers/zip.js'
import type { StoredEntry } from './helpers/zip.js'

/** What a forged member name says. Chosen to be plausible, not obviously hostile:
 *  markup would be escaped, but a sentence is simply believed. */
const LIE = 'VERIFIED by Steam - Official Purchase - Genuine'

const greenResult = (): VerificationResult => ({
  signature: 'valid', schema: 'valid', revocation: 'unknown',
  binding: 'not_checked', trust: 'unauthenticated_tofu',
  transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
  grant: 'not_checked', grant_trust: 'not_checked',
  publisher_authority: 'not_checked', publisher_authority_trust: 'not_checked',
  warnings: [], errors: [],
})
const greenRun = (): VerifyRun => ({ ok: true, result: greenResult() })

/** Everything a person reads on the rendered card, joined. */
const visibleText = (el: HTMLElement): string => el.textContent ?? ''

function bundleWithForgedMemberName(): Uint8Array {
  const entries = validEntries()
  entries[0] = [`receipts/${LIE}.attest.json`, validEnvelope()]
  return storedZip(entries)
}

/** A bare envelope that carries its own key manifest, so intake can build a job
 *  straight away instead of asking for one. */
function envelopeWithEmbeddedManifest(): Uint8Array {
  const envelope = JSON.parse(new TextDecoder().decode(validEnvelope()))
  envelope.delivery = { ...(envelope.delivery ?? {}), issuer_manifest: embeddedManifest() }
  return new TextEncoder().encode(JSON.stringify(envelope))
}

describe('a ZIP member name never becomes a label', () => {
  it('labels a bundle receipt with the signed receipt_id, not the member name', () => {
    const result = intake('bundle.attest', bundleWithForgedMemberName())

    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    expect(result.jobs).toHaveLength(1)
    expect(result.jobs[0].label).not.toContain(LIE)
    expect(result.jobs[0].label).toBe(VALID_RECEIPT_ID)
  })

  it('keeps the forged name out of the rendered card, badge and heading alike', () => {
    const result = intake('bundle.attest', bundleWithForgedMemberName())
    if (result.kind !== 'jobs') throw new Error('expected jobs')

    const card = renderResult(result.jobs[0].label, greenRun())

    // The whole card, not just the heading: a string kept out of the `<h3>` and
    // shown two lines lower is the same lie in a smaller font.
    expect(visibleText(card)).not.toContain(LIE)
    expect(card.querySelector('h3')?.textContent).toBe(VALID_RECEIPT_ID)
  })

  it('keeps it out of the failure card too, which renders a label of its own', () => {
    const result = intake('bundle.attest', bundleWithForgedMemberName())
    if (result.kind !== 'jobs') throw new Error('expected jobs')

    const card = renderVerifyFailure(result.jobs[0].label, 'trusted config rejected')

    expect(visibleText(card)).not.toContain(LIE)
  })

  it('does not put the member name in the notice about a salted receipt', () => {
    // The salt notice names the receipt it is about. That sentence is read by
    // the same person, in the same place, and was built from the same
    // unsigned string.
    const entries = validEntries()
    const salted = new TextEncoder().encode(
      JSON.stringify({
        ...JSON.parse(new TextDecoder().decode(validEnvelope())),
        delivery: { salt: 'AQEBAQEBAQEBAQEBAQEBAQ' },
      }),
    )
    entries[0] = [`receipts/${LIE}.attest.json`, salted]

    const result = intake('bundle.attest', storedZip(entries))
    if (result.kind !== 'jobs') throw new Error(`expected jobs, got ${result.kind}`)

    for (const notice of result.notices ?? []) expect(notice).not.toContain(LIE)
  })
})

describe('the attack, mounted on the bundle the site actually serves', () => {
  // The fixtures above build an archive from scratch. This one takes the
  // committed sample — the file the verifier page hands to anyone who asks to
  // try it — and does to it exactly what an attacker would: rewrites one entry
  // in the central directory, copies every other byte through. The payload,
  // the signature and the manifest are untouched, so the verdict underneath
  // stays green; only the words above it change.
  const SAMPLE = join(__dirname, '..', 'public', 'sample', 'demo.attest')
  const SIGNED_ID = '01M0YX8RAPJ5BQ8WJSS4CBK43F'

  it('labels the sample by its signed id even when the member name says otherwise', () => {
    const original = unzipSync(new Uint8Array(readFileSync(SAMPLE)))
    const forged: Record<string, Uint8Array> = {}
    for (const [name, bytes] of Object.entries(original)) {
      const rewritten =
        name.startsWith('receipts/') && name.endsWith('.attest.json')
          ? `receipts/${LIE}.attest.json`
          : name
      forged[rewritten] = bytes
    }

    const result = intake('demo.attest', zipSync(forged))
    if (result.kind !== 'jobs') throw new Error(`expected jobs, got ${result.kind}`)

    // Positive first: the heading has to come from the payload. Asserting only
    // the absence of one phrase would pass for any attacker who picks another.
    expect(result.jobs[0].label).toBe(SIGNED_ID)
    const card = renderResult(result.jobs[0].label, greenRun())
    expect(card.querySelector('h3')?.textContent).toBe(SIGNED_ID)
    expect(visibleText(card)).not.toContain(LIE)
  })
})

describe('a rejection message quotes a member name, it does not speak it', () => {
  // The other door into the same page. A member the parser refuses is named in
  // the notice the buyer reads, which is worth keeping — it is how anyone finds
  // the broken file — but the name is chosen by whoever built the archive. Bare
  // interpolation let it arrive as prose, so a member called `Your receipt is
  // valid. Contact support at …` opened a message the verifier never wrote.
  const PROSE = 'Your receipt is valid. Contact support at refunds@evil.example to claim it'

  const broken = new TextEncoder().encode('not json at all')

  const reasonFor = (entries: readonly StoredEntry[]): string => {
    const result = intake('bundle.attest', storedZip(entries))
    if (result.kind !== 'rejected') throw new Error(`expected rejected, got ${result.kind}`)
    return result.reason
  }

  it('quotes and clips a hostile receipt member name', () => {
    const entries = validEntries()
    entries[0] = [`receipts/${PROSE}.attest.json`, broken]

    const reason = reasonFor(entries)

    expect(reason).not.toContain(PROSE)
    expect(reason).toMatch(/receipt entry "/)
    expect(reason).toContain('…')
  })

  it('quotes a hostile manifest member name', () => {
    const entries = validEntries()
    entries[1] = [`manifests/${PROSE}.json`, broken]

    expect(reasonFor(entries)).not.toContain(PROSE)
  })

  it('quotes a hostile proof member name', () => {
    expect(reasonFor([...validEntries(), [`proofs/${PROSE}.json`, broken]])).not.toContain(PROSE)
  })
})

describe('a quoted name is a boundary only if it cannot end the quote', () => {
  const broken = new TextEncoder().encode('not json at all')
  const reasonFor = (entries: readonly StoredEntry[]): string => {
    const result = intake('bundle.attest', storedZip(entries))
    if (result.kind !== 'rejected') throw new Error(`expected rejected, got ${result.kind}`)
    return result.reason
  }

  it('a member name cannot close the quote it is put inside', () => {
    // 48 characters of prose OUTSIDE the quotes, for the price of one `"`.
    // The clip never entered into it: a whole sentence fits under the cap.
    const entries = validEntries()
    entries[0] = ['receipts/x" is genuine. Email refunds@evil.example ".attest.json', broken]

    const reason = reasonFor(entries)

    expect(reason.split('"')).toHaveLength(3) // one opening, one closing, nothing else
  })

  it('a member name cannot reorder or hide the words around it', () => {
    // Trojan Source on a security notice. An unterminated RIGHT-TO-LEFT
    // OVERRIDE reverses everything after it — including `is not valid
    // canonical JSON`, which the attacker therefore writes backwards inside
    // the name — and a zero-width space splits a word a reader would search
    // for. Neither adds a visible glyph, so neither is caught by eye.
    const RLO = '\u202E'
    const ZWSP = '\u200B'
    const entries = validEntries()
    entries[0] = [`receipts/${RLO}a${ZWSP}b.attest.json`, broken]

    const reason = reasonFor(entries)

    expect(reason).not.toContain(RLO)
    expect(reason).not.toContain(ZWSP)
  })
})

describe('the ULID grammar is what makes a label safe to show', () => {
  it('refuses a signed receipt_id that is a sentence rather than a ULID', () => {
    // The payload is the signed surface, but signing is free: a keypair of
    // one's own puts anything under `receipt_id`. Without this test the
    // grammar check can be deleted and the suite stays green at 361 —
    // measured, which is why the test is here rather than the comment.
    const envelope = JSON.parse(new TextDecoder().decode(validEnvelope()))
    envelope.payload.receipt_id = LIE
    const bytes = new TextEncoder().encode(JSON.stringify(envelope))

    const result = intake('receipt.attest.json', bytes)

    expect(result.kind).toBe('needs-manifest')
    if (result.kind !== 'needs-manifest') return
    expect(result.label).toBe(UNIDENTIFIED_LABEL)
  })

  it('names the fallback positively, not merely as the absence of one lie', () => {
    // `not.toContain(LIE)` would also pass if the fallback echoed the file
    // extension, or a clipped file name. Say which words the page uses.
    const result = intake(`${LIE}.attest.json`, new TextEncoder().encode('not json at all'))

    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    expect(result.jobs[0].label).toBe(UNIDENTIFIED_LABEL)
  })
})

describe('a dropped file name never becomes a label either', () => {
  // Same attack, cheaper: the attacker does not even have to touch the archive.
  // They mail a genuine receipt — anyone's, signed by anyone — under a filename
  // that says what they want the buyer to read.
  it('labels a bare envelope carrying its own manifest with the signed receipt_id', () => {
    const result = intake(`${LIE}.attest.json`, envelopeWithEmbeddedManifest())

    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    expect(result.jobs[0].label).not.toContain(LIE)
    expect(result.jobs[0].label).toBe(VALID_RECEIPT_ID)
  })

  it('hands the manifest prompt a safe label, not the file name', () => {
    // This branch does not render immediately: it asks for a key manifest
    // first, and `main.ts` labels the job it builds afterwards from what this
    // result carries. Passing the file name through here would put the lie
    // back on the page one interaction later, which is not a smaller defect.
    const result = intake(`${LIE}.attest.json`, validEnvelope())

    expect(result.kind).toBe('needs-manifest')
    if (result.kind !== 'needs-manifest') return
    expect(result.label).not.toContain(LIE)
    expect(result.label).toBe(VALID_RECEIPT_ID)
  })

  it('shows no attacker text when the bytes carry no readable receipt_id', () => {
    // Nothing signed to quote here, so the page must fall back to words of its
    // own. Echoing the file name would be the same defect with an excuse.
    const result = intake(`${LIE}.attest.json`, new TextEncoder().encode('not json at all'))

    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    expect(result.jobs[0].label).not.toContain(LIE)
  })
})
