import { describe, it, expect } from 'vitest'
import { runVerify, runChainAudit } from '../src/run.js'
import * as V from './helpers/vectors.js'

const allLeaves = V.findLeafDirs()
// Group 36 (chain-of-title audit, v0.2 §17.5) leaves are a SEPARATE surface
// (runChainAudit, never runVerify()) — excluded here and driven by their own
// describe block below.
const chainLeaves = allLeaves.filter((d) => V.chainInput(d) !== null)
const leaves = allLeaves.filter((d) => V.chainInput(d) === null)

describe('conformance corpus through the site adapter', () => {
  it('discovers the full vector suite (>= 97 leaves)', () => {
    expect(allLeaves.length).toBeGreaterThanOrEqual(97)
  })

  it.each(leaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const run = runVerify(V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir), V.disclosure(dir), {
      transparency: V.transparencyEvidence(dir),
      logKeys: V.logKeys(dir),
      anchorPolicy: V.anchorPolicy(dir),
      revocationEvidence: V.revocationEvidence(dir),
      transferView: V.transferView(dir),
      witnessPolicy: V.witnessPolicy(dir),
    })
    const r = run.result
    expect(r.signature).toBe(exp.signature)
    expect(r.schema).toBe(exp.schema)
    expect(r.trust).toBe(exp.trust)
    if ('revocation' in exp) expect(r.revocation).toBe(exp.revocation)
    if ('binding' in exp) expect(r.binding).toBe(exp.binding)
    if ('transparency' in exp) expect(r.transparency).toBe(exp.transparency)
    if ('corroboration' in exp) expect(r.corroboration).toBe(exp.corroboration)
    if ('manifest_freshness' in exp) expect(r.manifest_freshness).toBe(exp.manifest_freshness)
    if ('ok' in exp) expect(run.ok).toBe(exp.ok)
    if ('errors' in exp) expect([...r.errors]).toEqual(exp.errors)
    if ('warnings' in exp) expect([...r.warnings]).toEqual(exp.warnings)
    for (const s of exp.errors_contains ?? []) expect(r.errors.some((e: string) => e.includes(s))).toBe(true)
    for (const s of exp.warnings_contains ?? []) expect(r.warnings.some((w: string) => w.includes(s))).toBe(true)
  })
})

describe('conformance corpus through the site adapter: chain-of-title audit (group 36)', () => {
  it.each(chainLeaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const chain = V.chainInput(dir)!
    const logKeys = V.logKeys(dir)
    const anchorPolicy = V.anchorPolicy(dir)
    expect(logKeys).not.toBeNull()
    expect(anchorPolicy).not.toBeNull()

    const result = runChainAudit(
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
      expect(result.errors.some((e: string) => e.includes(s))).toBe(true)
    }
    expect([...result.warnings]).toEqual(exp.warnings)
  })
})
