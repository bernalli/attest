import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { intake, trustStoreFromManifestBytes } from '../src/intake.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT } from './helpers/vectors.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const envelopeBytes = () => new Uint8Array(readFileSync(join(V01, 'envelope.json')))
const keyManifest = (): { issuer: string; manifest: JsonObject } => {
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  return { issuer, manifest: manifests[issuer] as JsonObject }
}

describe('intake', () => {
  it('rejects *.private.attest by name without reading it', () => {
    const r = intake('library.private.attest', new Uint8Array([0x50, 0x4b, 3, 4]))
    expect(r.kind).toBe('rejected')
  })

  it('routes a zip to parseBundle and yields one job per receipt', () => {
    const { issuer, manifest } = keyManifest()
    const blob: JsonObject = { issuer, key_manifests: [manifest], artifact_manifests: [] }
    const zip = zipSync({
      ['receipts/R1.attest.json']: envelopeBytes(),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
    })
    const r = intake('library.attest', zip)
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    expect(r.jobs).toHaveLength(1)
    expect(r.jobs[0].label).toBe('R1')
    expect(runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore).result.signature).toBe('valid')
  })

  it('hands each receipt its own proofs/ evidence, and nothing to the ones without', () => {
    const { issuer, manifest } = keyManifest()
    const blob: JsonObject = { issuer, key_manifests: [manifest], artifact_manifests: [] }
    const withProof = '01JZ5PDHT0000G40R40M30E209'
    const withoutProof = '01JZ5PDHT0000G40R40M30E20A'
    const zip = zipSync({
      [`receipts/${withProof}.attest.json`]: envelopeBytes(),
      [`receipts/${withoutProof}.attest.json`]: envelopeBytes(),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
      [`proofs/${withProof}.json`]: new TextEncoder().encode('{"leaf_index":0}'),
    })
    const r = intake('library.attest', zip)
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    const byLabel = Object.fromEntries(r.jobs.map((j) => [j.label, j]))
    expect(byLabel[withProof].transparency).not.toBeNull()
    expect(byLabel[withoutProof].transparency).toBeNull()
  })

  it('rejects a private zip with the private message', () => {
    const zip = zipSync({ ['salts.json']: new TextEncoder().encode('{}') })
    const r = intake('oops.attest', zip)
    expect(r.kind).toBe('rejected')
    if (r.kind === 'rejected') expect(r.reason).toMatch(/private/i)
  })

  it('uses delivery.issuer_manifest when embedded in a bare envelope', () => {
    const { issuer, manifest } = keyManifest()
    const env = loadsStrict(envelopeBytes()) as JsonObject
    const withDelivery: JsonObject = { ...env, delivery: { issuer_manifest: manifest } }
    const r = intake('receipt.attest.json', canonicalBytes(withDelivery))
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    const run = runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore)
    expect(run.result.signature).toBe('valid')
    expect(run.result.trust).toBe('unauthenticated_tofu')
    expect(r.jobs[0].trustStore.provenance[issuer]).toBe('embedded')
  })

  it('asks for a manifest when a parseable envelope has none embedded', () => {
    const r = intake('receipt.attest.json', envelopeBytes())
    expect(r.kind).toBe('needs-manifest')
  })

  it('still yields a job (empty trust store) for unparseable JSON so verify() speaks', () => {
    const r = intake('garbage.attest.json', new TextEncoder().encode('{"n": 1.5}'))
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    const run = runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore)
    expect(run.result.signature).toBe('invalid')
    expect(run.ok).toBe(false)
  })
})

describe('trustStoreFromManifestBytes', () => {
  it('builds a user-supplied trust store from a key manifest', () => {
    const { issuer, manifest } = keyManifest()
    const ts = trustStoreFromManifestBytes(canonicalBytes(manifest))
    expect(ts).not.toBeNull()
    expect(ts!.provenance[issuer]).toBe('user-supplied')
    expect(runVerify(envelopeBytes(), ts!).result.signature).toBe('valid')
  })

  it('returns null for JSON that is not a key manifest', () => {
    expect(trustStoreFromManifestBytes(new TextEncoder().encode('{"a": 1}'))).toBeNull()
    expect(trustStoreFromManifestBytes(new TextEncoder().encode('not json'))).toBeNull()
  })
})

// A bare envelope that still carries `delivery.salt` is exactly what `attest
// disclose` produces and what the mail integration point hands over by
// design (§13), so refusing it outright would break both and would take away
// the one place a holder can safely check their own file — verification is
// entirely client-side and the bytes never leave the machine. The measured
// bug was the SILENCE, not the acceptance: the verifier judged the NAME and
// said nothing about the content.
describe('intake: the salted-envelope notice', () => {
  const salted = (withManifest: boolean): Uint8Array => {
    const env = loadsStrict(envelopeBytes()) as JsonObject
    const delivery: JsonObject = withManifest
      ? { issuer_manifest: keyManifest().manifest, salt: 'c2FsdHktbWNzYWx0ZmFjZQ' }
      : { salt: 'c2FsdHktbWNzYWx0ZmFjZQ' }
    return canonicalBytes({ ...env, delivery } as JsonObject)
  }

  it('verifies a salted bare envelope but says it is bearer proof', () => {
    const r = intake('receipt.attest.json', salted(true))
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    expect(r.notices).toBeDefined()
    expect(r.notices!.join(' ')).toMatch(/never/i)
    expect(r.notices!.join(' ')).toMatch(/salt/)
    // Still verified, not refused: the warning is additive.
    expect(runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore).result.signature).toBe('valid')
  })

  it('keeps the notice on the needs-manifest path', () => {
    const r = intake('receipt.attest.json', salted(false))
    if (r.kind !== 'needs-manifest') throw new Error(`expected needs-manifest, got ${r.kind}`)
    expect(r.notices).toBeDefined()
    expect(r.notices!.join(' ')).toMatch(/never/i)
  })

  it('names the salted member of a bundle built by someone else', () => {
    // Our own exporter never writes a salted member into a `.attest`, but the
    // guard is on the CONTENT, so a third party's bundle gets judged too.
    const { issuer, manifest } = keyManifest()
    const blob: JsonObject = { issuer, key_manifests: [manifest], artifact_manifests: [] }
    const zip = zipSync({
      ['receipts/R1.attest.json']: salted(false),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
    })
    const r = intake('library.attest', zip)
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    expect(r.notices).toBeDefined()
    expect(r.notices!.join(' ')).toContain('R1')
    expect(r.notices!.join(' ')).toMatch(/never/i)
  })

  it('says nothing about a salt-free receipt', () => {
    const { manifest } = keyManifest()
    const env = loadsStrict(envelopeBytes()) as JsonObject
    const clean: JsonObject = { ...env, delivery: { issuer_manifest: manifest } }
    const r = intake('receipt.attest.json', canonicalBytes(clean))
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    expect(r.notices ?? []).toHaveLength(0)
  })

  it('leaves both refusals exactly as they were', () => {
    // By name (intake.ts) ...
    expect(intake('x.private.attest', salted(true)).kind).toBe('rejected')
    // ... and by content (bundle.ts): a zip carrying salts.json is refused
    // outright, notice or no notice.
    const priv = zipSync({ ['salts.json']: new TextEncoder().encode('{}') })
    const r = intake('x.attest', priv)
    expect(r.kind).toBe('rejected')
    if (r.kind === 'rejected') expect(r.reason).toMatch(/private/i)
  })
})
