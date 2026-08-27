import { describe, it, expect } from 'vitest'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { runVerify, runChainAudit, runWitnessQuorum, runRedemption } from '../src/run.js'
import { parseWitnessPolicy } from 'attest-verifier'
import * as V from './helpers/vectors.js'
import { explain } from '../src/explain.js'
import { b64uDecode } from '../src/b64u.js'

const allLeaves = V.findLeafDirs()
// Group 36 (chain-of-title audit, v0.2 §17.5) leaves are a SEPARATE surface
// (runChainAudit, never runVerify()) — excluded here and driven by their own
// describe block below.
const chainLeaves = allLeaves.filter((d) => V.chainInput(d) !== null)
// Group 40 (activation witness quorum, v0.2 §11.4) leaves are a THIRD surface
// (runWitnessQuorum, never runVerify and never runChainAudit).
const quorumLeaves = allLeaves.filter((d) => V.quorumInput(d) !== null)
// Group 38 (redemption, v0.2 §18.7) leaves are a FOURTH surface
// (runRedemption): no receipt, no trust store, no grant document.
const redemptionLeaves = allLeaves.filter((d) => V.redemptionInput(d) !== null)
const leaves = allLeaves.filter(
  (d) => V.chainInput(d) === null && V.quorumInput(d) === null && V.redemptionInput(d) === null,
)

describe('conformance corpus through the site adapter', () => {
  it('discovers every leaf the corpus holds', () => {
    // Counted by walking the corpus here, independently of the loader under
    // test: comparing the loader's output with itself would protect nothing,
    // and a constant floor stops catching anything once the corpus outgrows
    // it — which is how the number here came to sit at 156 while the corpus
    // reached 158.
    const walk = (dir: string): number =>
      readdirSync(dir, { withFileTypes: true }).reduce(
        (n, e) =>
          e.isDirectory()
            ? n + walk(join(dir, e.name))
            : n + (e.name === 'expected.json' ? 1 : 0),
        0,
      )
    expect(allLeaves.length).toBe(walk(V.VECTORS_ROOT))
  })

  it.each(leaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const run = runVerify(V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir), V.disclosure(dir), {
      transparency: V.transparencyEvidence(dir),
      logKeys: V.logKeys(dir),
      anchorPolicy: V.anchorPolicy(dir),
      revocationEvidence: V.revocationEvidence(dir),
      transferView: V.transferView(dir),
      compromiseView: V.compromiseView(dir),
      witnessPolicy: V.witnessPolicy(dir),
      grantView: V.grantView(dir),
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
    if ('grant' in exp) expect(r.grant).toBe(exp.grant)
    if ('grant_trust' in exp) expect(r.grant_trust).toBe(exp.grant_trust)
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

describe('conformance corpus through the site adapter: activation witness quorum (group 40)', () => {
  it.each(quorumLeaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const q = V.quorumInput(dir)!
    const policyDocument = V.witnessPolicy(dir)
    const anchorPolicy = V.anchorPolicy(dir)
    expect(policyDocument).not.toBeNull()
    expect(anchorPolicy).not.toBeNull()

    const result = runWitnessQuorum(
      q.checkpoint,
      parseWitnessPolicy(policyDocument),
      q.epochId,
      q.expectedOrigin,
      q.anchorEvidence,
      anchorPolicy!,
      q.conflictDomain,
    )

    expect(result.valid).toBe(exp.valid)
    expect(result.witnessTime).toBe(exp.witness_time)
    expect([...result.countingControlGroups]).toEqual(exp.counting_control_groups)
  })
})

describe('conformance corpus through the site adapter: redemption (group 38)', () => {
  it.each(redemptionLeaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const input = V.redemptionInput(dir)!
    const verified = runRedemption(
      input.receipt_id,
      input.audience,
      b64uDecode(input.nonce_b64u),
      b64uDecode(input.sig_b64u),
      input.holder_pubkey_b64u,
    )
    expect(verified).toBe(exp.verified)
  })
})

// The copy each group-41 leaf ACTUALLY produces, driven by the corpus rather
// than by hand-built results: a story that no leaf can reach, or two stories
// that one leaf could reach, shows up here and not in review.
describe('the §19 copy each group-41 leaf produces through the site adapter', () => {
  const SIGNATURE_STORY: Record<string, RegExp> = {
    'a-rescued-anchored-before-cutoff': /strictly before/,
    'b-anchored-after-cutoff-fails': /not anchored strictly before/,
    'c-logged-only-fails': /no anchored proof/,
    'd-cutoff-logged-only-survives': /no anchored compromise cutoff was established/,
    'e-no-cutoff-evidence-survives': /no anchored compromise cutoff was established/,
    'f-stage1-fail-closed': /no anchored proof/,
    'g-boundary-equal-fails': /Equality is not proof of precedence/,
    'h-earliest-cutoff-wins': /not anchored strictly before/,
    'i-unvouched-declaration-ignored': /no anchored compromise cutoff was established/,
    'j-hybrid-rescued': /strictly before/,
    'k-manifest-claim-does-not-rescue': /no anchored proof/,
    'l-uncompromise-chain-floor': /not taken back by a later key list/,
    'm-uncompromise-view-floor': /no anchored proof/,
    'n-uncompromise-floor-spares-anchored': /no anchored compromise cutoff was established/,
    'o-status-regression-breaks-continuity': /Ed25519 signature over the canonical payload/,
    'p-declaring-signer-compromised-still-floors': /no anchored proof/,
    'q-retired-reactivation-untouched': /Ed25519 signature over the canonical payload/,
    'r-compromised-signer-establishes-no-cutoff': /no anchored compromise cutoff was established/,
    // 41s satisfies BOTH the after-cutoff branch and the floor branch: the
    // signature row tells the after-cutoff story, the trust row tells the floor.
    's-chain-dates-the-signer-cutoff-holds': /not anchored strictly before/,
    't-keyset-omission-breaks-continuity': /Ed25519 signature over the canonical payload/,
    // 41u is 41m with an OLDER trusted pin: same signature story, but the
    // verifier holds no evidence of a retraction, so the trust row stays hedged.
    'u-stale-pin-not-a-retraction': /no anchored proof/,
  }

  const g41 = leaves.filter((d) => V.vectorId(d).startsWith('41-compromise-cutoff/'))

  it('covers every leaf of the group', () => {
    expect(g41.length).toBe(Object.keys(SIGNATURE_STORY).length)
  })

  it.each(g41.map((d) => [V.vectorId(d), d] as const))('%s', (id, dir) => {
    const run = runVerify(V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir), V.disclosure(dir), {
      transparency: V.transparencyEvidence(dir),
      logKeys: V.logKeys(dir),
      anchorPolicy: V.anchorPolicy(dir),
      revocationEvidence: V.revocationEvidence(dir),
      transferView: V.transferView(dir),
      compromiseView: V.compromiseView(dir),
      witnessPolicy: V.witnessPolicy(dir),
      grantView: V.grantView(dir),
    })
    const leaf = id.slice('41-compromise-cutoff/'.length)
    const text = explain('signature', run.result.signature, run.result).text
    expect(text, leaf).toMatch(SIGNATURE_STORY[leaf]!)
    expect(text, leaf).not.toContain('does not have dedicated wording')
    if (run.result.trust === 'unverified_rotation') {
      const trustText = explain('trust', 'unverified_rotation', run.result).text
      // v0.1 §7.3 rev 8: with the retraction ESTABLISHED the copy says it as a
      // fact; without the warning the hedged wording stays exactly as it was.
      if (run.result.warnings.includes('compromise_marking_retracted')) {
        expect(trustText, leaf).toMatch(/The issuer rewrote the history of its own keys/)
      } else {
        expect(trustText, leaf)
          .toMatch(/Continuity of the issuer’s key manifest history could not be proven|manifest history has a gap/)
      }
    }
  })
})
