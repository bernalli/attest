// The conformance merge gate (36 vector groups / 97 leaves): this suite discovers every leaf under
// `docs/spec/vectors/` and asserts the produced VerificationResult matches
// its `expected.json`, using the exact same match rules as the Python
// reference's `tests/test_vectors.py`. Passing this suite in full IS the
// definition of attest conformance for this implementation, v0.1 and v0.2 (see README).
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { verify, isOk, auditChain } from '../src/index.js'
import { canonicalBytes, loadsStrict } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import * as V from './helpers/vectors.js'

const allLeaves = V.findLeafDirs()
// Group 36 (chain-of-title audit, v0.2 §17.5) leaves are a SEPARATE surface
// (auditChain, never verify()) — excluded here and driven by their own
// describe block below.
const chainLeaves = allLeaves.filter((d) => V.chainInput(d) !== null)
const leaves = allLeaves.filter((d) => V.chainInput(d) === null)
const canonicalLeaves = leaves.filter((d) => existsSync(join(d, 'canonical.json')))

describe('attest conformance vectors', () => {
  it('discovers the full vector suite (>= 97 leaves)', () => {
    expect(allLeaves.length).toBeGreaterThanOrEqual(97)
  })

  it.each(leaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const r = verify(V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir) as any, V.disclosure(dir), undefined, {
      transparency: V.transparencyEvidence(dir),
      logKeys: V.logKeys(dir),
      anchorPolicy: V.anchorPolicy(dir),
      revocationEvidence: V.revocationEvidence(dir),
      transferView: V.transferView(dir),
      witnessPolicy: V.witnessPolicy(dir),
    })

    // always-exact
    expect(r.signature).toBe(exp.signature)
    expect(r.schema).toBe(exp.schema)
    expect(r.trust).toBe(exp.trust)
    // conditional-exact scalars
    if ('revocation' in exp) expect(r.revocation).toBe(exp.revocation)
    if ('binding' in exp) expect(r.binding).toBe(exp.binding)
    if ('transparency' in exp) expect(r.transparency).toBe(exp.transparency)
    if ('corroboration' in exp) expect(r.corroboration).toBe(exp.corroboration)
    if ('manifest_freshness' in exp) expect(r.manifest_freshness).toBe(exp.manifest_freshness)
    if ('ok' in exp) expect(isOk(r)).toBe(exp.ok)
    // exact-list
    if ('errors' in exp) expect([...r.errors]).toEqual(exp.errors)
    if ('warnings' in exp) expect([...r.warnings]).toEqual(exp.warnings)
    // substring-contains
    for (const s of exp.errors_contains ?? []) expect(r.errors.some((e) => e.includes(s)), `error containing ${s}; got ${JSON.stringify(r.errors)}`).toBe(true)
    for (const s of exp.warnings_contains ?? []) expect(r.warnings.some((w) => w.includes(s)), `warning containing ${s}; got ${JSON.stringify(r.warnings)}`).toBe(true)
  })
})

describe('attest conformance vectors: chain-of-title audit (group 36)', () => {
  it.each(chainLeaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const chain = V.chainInput(dir)!
    const logKeys = V.logKeys(dir)
    const anchorPolicy = V.anchorPolicy(dir)
    expect(logKeys).not.toBeNull()
    expect(anchorPolicy).not.toBeNull()

    const result = auditChain(
      chain.payloads,
      chain.transferView,
      chain.revocationView,
      V.soleKeyManifest(dir),
      logKeys!,
      anchorPolicy!,
    )

    expect(result.valid).toBe(exp.chain_valid)
    expect([...result.linkStatus]).toEqual(exp.link_status)
    for (const s of exp.errors_contains ?? []) {
      expect(result.errors.some((e) => e.includes(s)), `chain error containing ${s}; got ${JSON.stringify(result.errors)}`).toBe(true)
    }
    expect([...result.warnings]).toEqual(exp.warnings)
  })
})

// Guarded: vitest errors on a describe block with zero `it`s inside, which
// happens legitimately before any leaf ships a canonical.json (see vector 24
// / 21 f-g).
if (canonicalLeaves.length > 0) {
  describe('canonical re-serialization parity', () => {
    for (const dir of canonicalLeaves) {
      it(`canonical bytes: ${V.vectorId(dir)}`, () => {
        const env = loadsStrict(V.envelopeBytes(dir)) as JsonObject
        const expected = new Uint8Array(readFileSync(join(dir, 'canonical.json')))
        expect(canonicalBytes(env.payload)).toEqual(expected)
      })
    }
  })
}
