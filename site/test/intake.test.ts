import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { intake, trustStoreFromManifestBytes } from '../src/intake.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT } from './helpers/vectors.js'
import { CORPUS_ROOT } from './helpers/container-corpus.js'
import { LEGAL_TEXT, LEGAL_DIGEST } from './helpers/zip.js'

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
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    })
    const r = intake('library.attest', zip)
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    expect(r.jobs).toHaveLength(1)
    // Labelled by the signed payload, not by the member called `R1`: the
    // central directory is attacker-controlled metadata no signature covers.
    expect(r.jobs[0].label).toBe('01JZ5PDHT0000G40R40M30E209')
    expect(runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore).result.signature).toBe('valid')
  })

  // The receipt whose SIGNED payload names the id gets the evidence, whatever
  // its member happens to be called: v0.1 §14.1 specifies `receipts/*.attest.
  // json` with a wildcard, so a conforming exporter is free to name the file
  // anything, and pairing on the filename dropped the proof on the floor.
  it('pairs proofs/ evidence by the signed receipt id, not by the member name', () => {
    const { issuer, manifest } = keyManifest()
    const blob: JsonObject = { issuer, key_manifests: [manifest], artifact_manifests: [] }
    const proven = '01JZ5PDHT0000G40R40M30E209' // the id inside vector 01's payload
    const other = '01JZ5PDHT0000G40R40M30E20A'
    const envelope = loadsStrict(envelopeBytes()) as JsonObject
    const otherPayload = { ...(envelope.payload as JsonObject), receipt_id: other }
    const otherEnvelope = canonicalBytes({ ...envelope, payload: otherPayload })
    const zip = zipSync({
      // Named by anything at all, and holding the receipt the proof is for.
      ['receipts/order-4711.attest.json']: envelopeBytes(),
      // Named by an id it does not carry, and holding a different receipt.
      [`receipts/${proven}-copy.attest.json`]: otherEnvelope,
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
      [`proofs/${proven}.json`]: new TextEncoder().encode('{"leaf_index":0}'),
    })
    const r = intake('library.attest', zip)
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    // Labels are signed ids now, so this map is keyed by what the payloads
    // say rather than by what their members are called — which is the same
    // property this test was already making about the evidence pairing.
    const byLabel = Object.fromEntries(r.jobs.map((j) => [j.label, j]))
    expect(byLabel[proven].transparency).not.toBeNull()
    expect(byLabel[other].transparency).toBeNull()
  })

  // `proofs` is a plain object and the id comes out of untrusted bytes.
  it('never resolves a prototype member as evidence', () => {
    // Since the 2026-08-26 receipt-id hardening this shape does not reach the
    // evidence lookup at all: `__proto__` is not the uppercase ULID the schema
    // pins, and the importer refuses the whole bundle. Refusing is strictly
    // stronger than resolving to null, so the property is asserted at the
    // point where it now holds.
    const { issuer, manifest } = keyManifest()
    const blob: JsonObject = { issuer, key_manifests: [manifest], artifact_manifests: [] }
    const envelope = loadsStrict(envelopeBytes()) as JsonObject
    const payload = { ...(envelope.payload as JsonObject), receipt_id: '__proto__' }
    const zip = zipSync({
      ['receipts/R1.attest.json']: canonicalBytes({ ...envelope, payload }),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
    })
    const r = intake('library.attest', zip)
    expect(r.kind).toBe('rejected')
    if (r.kind === 'rejected') expect(r.reason).toMatch(/invalid receipt_id/)
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

// A `.attest` is a container by CONTRACT (v0.1 §14.1), and the contract is the
// extension. Deciding from the first two bytes instead let a file opt OUT of the
// canonical container reader by not opening with the archive signature: the
// reference importer refused such a file and this page handed it to the receipt
// path, where it earned a job — the same bytes, two answers, which is exactly
// the divergence the canonical reader exists to remove.
describe('a file named .attest is read as a container, whatever it starts with', () => {
  const corpusArchive = (leaf: string): Uint8Array =>
    new Uint8Array(readFileSync(join(CORPUS_ROOT, leaf, 'archive.zip')))

  // Both leaves refuse in the reference importer and neither opens with `PK`.
  for (const leaf of ['prefix-honest', 'local-header-signature']) {
    it(`refuses ${leaf} instead of routing it to the receipt path`, () => {
      const r = intake('library.attest', corpusArchive(leaf))
      expect(r.kind).toBe('rejected')
    })
  }

  it('refuses a .attest that is not an archive at all, without throwing', () => {
    const r = intake('library.attest', new TextEncoder().encode('this is a note, not an archive'))
    expect(r.kind).toBe('rejected')
    if (r.kind === 'rejected') {
      // The container reader's own complaint, which is the one the reference
      // importer makes about the same bytes.
      expect(r.reason).toMatch(/container|zip/i)
      // It IS a judgement about the bytes — they were read — so it is not the
      // neutral register §14.4 reserves for a container nobody opened.
      expect(r.declined).toBeUndefined()
    }
  })

  it('refuses an empty .attest without throwing', () => {
    const r = intake('library.attest', new Uint8Array(0))
    expect(r.kind).toBe('rejected')
  })

  it('still refuses .private.attest by name, which also ends in .attest', () => {
    // The private-file refusal is about what the file HOLDS, and it must keep
    // winning over the container route now that both branches match the name.
    const r = intake('library.private.attest', new TextEncoder().encode('not an archive'))
    expect(r.kind).toBe('rejected')
    if (r.kind === 'rejected') expect(r.reason).toMatch(/binding salts and keys/)
  })

  it('leaves a receipt that is not named .attest on the receipt path', () => {
    // The extension is what routes; the bare envelope keeps working.
    const r = intake('receipt.attest.json', envelopeBytes())
    expect(r.kind).toBe('needs-manifest')
  })

  it('still reads an archive that is not named .attest', () => {
    // The signature keeps its say: a bundle saved under another name is still
    // read as one, exactly as before.
    const { issuer, manifest } = keyManifest()
    const blob: JsonObject = { issuer, key_manifests: [manifest], artifact_manifests: [] }
    const zip = zipSync({
      ['receipts/R1.attest.json']: envelopeBytes(),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    })
    expect(intake('library.zip', zip).kind).toBe('jobs')
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
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    })
    const r = intake('library.attest', zip)
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    expect(r.notices).toBeDefined()
    // The notice names the receipt by its signed id, never by the member name.
    expect(r.notices!.join(' ')).toContain('01JZ5PDHT0000G40R40M30E209')
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

// A trust store is looked up by a name the file being checked chose, so the
// store must answer for the issuers it was given and for nothing else. An
// ordinary JavaScript object answers for `toString` and every other member of
// `Object.prototype` as well, and hands back a function where a key manifest
// belongs — the reference importer, whose store is a plain dictionary, answers
// nothing. Same file, two trust stores.
describe('the trust stores intake builds answer only for the issuers they were given', () => {
  const INHERITED = ['toString', 'constructor', 'valueOf', 'hasOwnProperty']

  it('answers nothing for an inherited name, for a bare envelope with its own manifest', () => {
    const { manifest } = keyManifest()
    const envelope = loadsStrict(envelopeBytes()) as JsonObject
    const delivery = { ...((envelope['delivery'] as JsonObject) ?? {}), issuer_manifest: manifest }
    const withManifest = canonicalBytes({ ...envelope, delivery } as JsonObject)
    const r = intake('x.attest.json', withManifest)
    expect(r.kind).toBe('jobs')
    if (r.kind !== 'jobs') return
    for (const name of INHERITED) {
      expect(r.jobs[0].trustStore.manifests[name]).toBeUndefined()
      expect(r.jobs[0].trustStore.provenance[name]).toBeUndefined()
    }
  })

  it('answers nothing for an inherited name, for a user-supplied manifest', () => {
    const { manifest } = keyManifest()
    const store = trustStoreFromManifestBytes(canonicalBytes(manifest))
    expect(store).not.toBeNull()
    for (const name of INHERITED) {
      expect(store!.manifests[name]).toBeUndefined()
      expect(store!.provenance[name]).toBeUndefined()
    }
  })

  it('answers nothing for an inherited name, for a file that brought no manifest', () => {
    const r = intake('x.attest.json', new TextEncoder().encode('not json at all'))
    expect(r.kind).toBe('jobs')
    if (r.kind !== 'jobs') return
    for (const name of INHERITED) {
      expect(r.jobs[0].trustStore.manifests[name]).toBeUndefined()
      expect(r.jobs[0].trustStore.provenance[name]).toBeUndefined()
    }
  })

  it('keeps an issuer named after an object member, and gives it to the verifier', () => {
    // The reference importer holds `__proto__` as an ordinary issuer. So does
    // this one — the entry is here because the name was declared, not in spite
    // of it.
    const { manifest } = keyManifest()
    const named = { ...manifest, issuer: '__proto__' } as JsonObject
    const store = trustStoreFromManifestBytes(canonicalBytes(named))
    expect(store).not.toBeNull()
    expect(Object.keys(store!.manifests)).toEqual(['__proto__'])
    expect(store!.manifests['__proto__']).toBeDefined()
  })
})
