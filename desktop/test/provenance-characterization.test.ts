import { describe, expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { unzipSync } from 'fflate'
import { canonicalBytes, loadsStrict } from 'attest-verifier'
import { intake, trustStoreFromManifestBytes } from '../../site/src/intake.js'
import { runVerify } from '../../site/src/run.js'
import { desktopVerdict } from '../src/verdict.js'

// A characterization test, not a specification: it pins what the verifier does TODAY so
// that a change to the meaning of "verified" fails here instead of silently reaching a
// buyer.
//
// The claim being pinned is stronger than "this app cannot reach green". No shipped
// attest tool can: the TypeScript verifier grants `trust: 'verified'` only when the
// trust store's provenance for the issuer is 'tls', and nothing in this repository ever
// writes that value — the browser sets 'bundle', 'embedded' or 'user-supplied', and the
// Python CLI and importer both force 'bundle'. There is no TLS fetch anywhere.
//
// Which is why all THREE reachable provenance paths are exercised. Checking only the
// convenient one would leave the other two free to drift into green unnoticed, and the
// sample bundle takes 'bundle' — not the 'embedded' value one might assume from the
// phrase "the manifest travels with the receipt".

const SAMPLE = fileURLToPath(new URL('../../site/public/sample/demo.attest', import.meta.url))

interface Parts {
  envelope: Uint8Array
  manifest: Uint8Array
  bundle: Uint8Array
}

// A third-party unzip, so this fixture still does not lean on site/src/bundle.ts —
// the code whose behaviour the tests below are characterizing — but it reads the
// central directory instead of scanning for local-header signatures, which mis-reads
// any archive written with data descriptors and can match a false signature inside
// compressed data.
function parts(): Parts {
  const bundle = new Uint8Array(readFileSync(SAMPLE))
  const found = unzipSync(bundle)
  const receiptName = Object.keys(found).find((n) => n.startsWith('receipts/'))
  const manifestName = Object.keys(found).find((n) => n.startsWith('manifests/'))
  if (!receiptName || !manifestName) throw new Error('sample bundle is missing its receipt or manifest')
  return { envelope: found[receiptName], manifest: found[manifestName], bundle }
}

// `delivery` sits OUTSIDE the signed payload — the signature covers the canonical
// payload, not the envelope wrapper — so attaching the issuer manifest here produces the
// 'embedded' path without touching a signed byte.
function withEmbeddedManifest(envelope: Uint8Array, manifest: Uint8Array): Uint8Array {
  const env = JSON.parse(new TextDecoder().decode(envelope))
  // The bundle member is a CONTAINER holding `key_manifests` and `artifact_manifests`;
  // `delivery.issuer_manifest` takes a single KEY MANIFEST, the same distinction the
  // user-supplied test below spells out. Attaching the container instead makes the
  // verifier reject the receipt outright ("its own signature does not verify") — and
  // every assertion in this file was satisfied by a rejected receipt, so the mistake
  // was invisible.
  const container = JSON.parse(new TextDecoder().decode(manifest))
  env.delivery = { issuer_manifest: container.key_manifests[0] }
  return new TextEncoder().encode(JSON.stringify(env))
}

describe('every provenance the app can reach lands short of green', () => {
  const { envelope, manifest, bundle } = parts()

  test("a bundle takes provenance 'bundle' — not 'embedded'", () => {
    const result = intake('demo.attest', bundle)
    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    const [job] = result.jobs
    expect(Object.values(job.trustStore.provenance)).toEqual(['bundle'])

    const run = runVerify(job.envelopeBytes, job.trustStore, null, null, {})
    expect(run.result.trust).toBe('unauthenticated_tofu')
    expect(desktopVerdict(run.ok, run.result.trust)).not.toBe('verified')
  })

  test("a bare envelope carrying its own manifest takes provenance 'embedded'", () => {
    const bytes = withEmbeddedManifest(envelope, manifest)
    const result = intake('receipt.attest.json', bytes)
    expect(result.kind).toBe('jobs')
    if (result.kind !== 'jobs') return
    const [job] = result.jobs
    expect(Object.values(job.trustStore.provenance)).toEqual(['embedded'])

    const run = runVerify(job.envelopeBytes, job.trustStore, null, null, {})
    expect(run.result.trust).toBe('unauthenticated_tofu')
    expect(desktopVerdict(run.ok, run.result.trust)).not.toBe('verified')
    // Anchor: without it this test is satisfied by a receipt that simply broke —
    // `not.toBe('verified')` is true of 'failed' too. Measured: dropping the manifest
    // from this path's trust store left the whole suite green.
    expect(run.ok, 'this path must still pass the four gates').toBe(true)
  })

  test("a bare envelope plus a hand-supplied manifest takes provenance 'user-supplied'", () => {
    const result = intake('receipt.attest.json', envelope)
    // Without an embedded manifest the page has to ask for one: that ask IS this path.
    expect(result.kind).toBe('needs-manifest')
    if (result.kind !== 'needs-manifest') return

    // What this path accepts is a single KEY MANIFEST — `issuer` plus `keys` — not the
    // `manifests/*.json` member of a bundle, which is a container holding
    // `key_manifests` and `artifact_manifests`. Handing over the container returns null,
    // so the fixture has to unwrap it exactly as an issuer publishing one key manifest
    // would. Re-serialised through the project's own canonicaliser because the strict
    // parser on the other side accepts canonical JSON only.
    const container = JSON.parse(new TextDecoder().decode(manifest))
    const keyManifest = canonicalBytes(loadsStrict(new TextEncoder().encode(JSON.stringify(container.key_manifests[0]))))

    const store = trustStoreFromManifestBytes(keyManifest)
    expect(store, 'a single key manifest must be accepted on the user-supplied path').not.toBeNull()
    if (!store) return
    expect(Object.values(store.provenance)).toEqual(['user-supplied'])

    const run = runVerify(result.envelopeBytes, store, null, null, {})
    expect(run.result.trust).toBe('unauthenticated_tofu')
    expect(desktopVerdict(run.ok, run.result.trust)).not.toBe('verified')
    // Anchor: without it this test is satisfied by a receipt that simply broke —
    // `not.toBe('verified')` is true of 'failed' too. Measured: dropping the manifest
    // from this path's trust store left the whole suite green.
    expect(run.ok, 'this path must still pass the four gates').toBe(true)
  })

  test('the sample really does pass the four gates — so the assertions above are about trust, not failure', () => {
    // Without this, all three tests above would still pass if the receipt were simply
    // broken: `not.toBe('verified')` is satisfied by 'failed' too. This pins that the
    // receipt verifies and the headline still refuses to go green.
    const result = intake('demo.attest', bundle)
    if (result.kind !== 'jobs') throw new Error('sample bundle no longer produces jobs')
    const run = runVerify(result.jobs[0].envelopeBytes, result.jobs[0].trustStore, null, null, {})
    expect(run.ok).toBe(true)
    expect(desktopVerdict(run.ok, run.result.trust)).toBe('offline_limit')
  })
})
