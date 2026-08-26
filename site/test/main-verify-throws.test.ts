// @vitest-environment jsdom
//
// The page's own failure mode, isolated in its own file because it mocks
// `run.js` wholesale.
//
// verify()'s trusted-configuration checks — `resolveLogOrigin`,
// `validateAnchorPolicyOnly`, `validateWitnessPolicy` — deliberately sit
// OUTSIDE the try that confines untrusted evidence, so a malformed pinned
// configuration THROWS rather than degrading. That is right for a library: a
// configuration bug must not be silently swallowed. It is wrong for a page
// that calls verify() inside an eager `.map()` whose result is spread into
// `replaceChildren`, because one throw abandons the whole call and the page
// simply never updates — no message, stale results left on screen, and on the
// sample path the existing catch relabels it "Could not load the sample
// bundle from this deployment", turning a configuration bug into an apparent
// missing asset.
//
// The receipt is not what failed here, and the page must not let a reader
// think otherwise: a verifier that cannot run says so about ITSELF.
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { VECTORS_ROOT } from './helpers/vectors.js'

const CONFIG_ERROR = 'log keys must all share one origin'

// Throws for exactly the jobs that carry evidence — the shape a malformed
// pinned config produces, since evaluateTransparencyClaim returns before
// touching the configuration when a job has none.
vi.mock('../src/run.js', () => ({
  runVerify: (
    _bytes: Uint8Array,
    _trustStore: unknown,
    _revocationView: unknown,
    _disclosure: unknown,
    options: { transparency?: unknown } = {},
  ) => {
    if (options.transparency != null) throw new Error(CONFIG_ERROR)
    return {
      ok: true,
      result: {
        signature: 'valid', schema: 'valid', revocation: 'unknown',
        binding: 'not_checked', trust: 'unauthenticated_tofu',
        transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
        grant: 'not_checked', grant_trust: 'not_checked',
        warnings: [], errors: [],
      },
    }
  },
}))

const { initApp } = await import('../src/main.js')

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const envelope = () => new Uint8Array(readFileSync(join(V01, 'envelope.json')))
const keyManifest = (): JsonObject => {
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  return manifests[Object.keys(manifests)[0]] as JsonObject
}

const WITH_EVIDENCE = '01JZ5PDHT0000G40R40M30E209'
const WITHOUT_EVIDENCE = '01JZ5PDHT0000G40R40M30E20A'

// The second receipt has to carry its OWN receipt_id in the signed payload,
// not merely a different member name: evidence is paired on the id inside the
// envelope (v0.2 §14), so two members holding the same receipt are one
// receipt, twice, and would both be handed the same proof.
function otherReceipt(): Uint8Array {
  const env = loadsStrict(envelope()) as JsonObject
  const payload = { ...(env.payload as JsonObject), receipt_id: WITHOUT_EVIDENCE }
  return canonicalBytes({ ...env, payload })
}

function twoReceiptBundle(): Uint8Array {
  const m = keyManifest()
  const issuer = m.issuer as string
  const blob: JsonObject = { issuer, key_manifests: [m], artifact_manifests: [] }
  return zipSync({
    [`receipts/${WITH_EVIDENCE}.attest.json`]: envelope(),
    [`receipts/${WITHOUT_EVIDENCE}.attest.json`]: otherReceipt(),
    [`manifests/${issuer}.json`]: canonicalBytes(blob),
    [`proofs/${WITH_EVIDENCE}.json`]: new TextEncoder().encode('{"leaf_index":0}'),
  })
}

const PAGE = `
  <div id="dropzone"></div><input id="file-input" type="file">
  <div id="manifest-zone" hidden></div><input id="manifest-input" type="file">
  <input id="binding-identifier"><select id="binding-type"><option value="email">email</option></select>
  <input id="binding-salt"><button id="binding-apply"></button>
  <button id="load-sample"></button>
  <section id="results"></section>`

beforeEach(() => {
  document.body.innerHTML = PAGE
})

describe('a verifier that cannot run says so about itself', () => {
  it('still renders, and does not leave the previous results on screen', () => {
    const app = initApp(document)
    app.handleBytes('first.attest.json', envelope())
    const results = document.getElementById('results')!
    const before = results.textContent

    app.handleBytes('library.attest', twoReceiptBundle())
    expect(results.textContent).not.toBe(before)
    expect(results.querySelectorAll('article').length).toBe(2)
  })

  it('names the receipt it could not check, and blames the page rather than the file', () => {
    const app = initApp(document)
    app.handleBytes('library.attest', twoReceiptBundle())
    const failed = document.querySelector('article.unverifiable')
    expect(failed).not.toBeNull()
    const text = failed!.textContent ?? ''
    expect(text).toContain(WITH_EVIDENCE)
    expect(text).toMatch(/could not check/i)
    // The reason is shown rather than hidden: a configuration bug that only
    // reaches the console is a bug nobody reports.
    expect(text).toContain(CONFIG_ERROR)
    // And it must not read as a verdict on the receipt: no failure vocabulary
    // that a reader could mistake for the receipt itself being bad.
    expect(text).not.toMatch(/\b(invalid|forged|tampered|failed)\b/i)
  })

  it('verifies the receipts it can, in the same batch', () => {
    const app = initApp(document)
    app.handleBytes('library.attest', twoReceiptBundle())
    const results = document.getElementById('results')!
    expect(results.querySelectorAll('article.result:not(.unverifiable)').length).toBe(1)
    expect(results.textContent).toContain(WITHOUT_EVIDENCE)
  })
})
