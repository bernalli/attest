// The conformance merge gate (40 vector groups / 158 leaves): this suite discovers every leaf under
// `docs/spec/vectors/` and asserts the produced VerificationResult matches
// its `expected.json`, using the exact same match rules as the Python
// reference's `tests/test_vectors.py`. Passing this suite in full IS the
// definition of attest conformance for this implementation, v0.1 and v0.2 (see README).
//
// FOUR surfaces, partitioned by which file a leaf ships — a leaf belongs to
// exactly one, and the three special ones are EXCLUDED from the verify()
// parametrization rather than being run twice:
//
//  - the default: verify(), for every leaf that ships none of the three files
//    below (130 leaves). Two of its optional leaf files are Stage 4's:
//      * `grant-view.json` (group 37, v0.2 §18.4): the evidence OBJECT
//        `{grant[, later_grants][, declarations][, anchor]}`, fed as
//        `grantView`. Its presence is the §18.4 capability gate, so a leaf
//        without it gets `grant`/`grant_trust` at `not_checked`/`not_checked`
//        — which is what group 37's own negative controls (s/t/u) pin.
//        `expected.json` carries the two new members `grant` and
//        `grant_trust`, asserted with the same conditional-exact discipline
//        `transparency`/`corroboration`/`manifest_freshness` already use.
//      * group 37's `anchor-policy.json` (leaves g/h/i/o), reused verbatim
//        from group 28's shape — the fixed-date proof is verified under §11.
//  - `chain.json` (group 36, §17.5): auditChain, 4 leaves.
//  - `witness-quorum.json` (group 40, §11.4): evaluateActivationWitnessQuorum,
//    20 leaves.
//  - `redemption.json` (group 38, §18.7): verifyRedemption, 4 leaves. There is
//    no receipt in the question these leaves ask — only whether a holder proof
//    is good for THIS custodian — so they ship no payload/envelope/manifests
//    at all, and every negative one must come back `false` rather than throw:
//    a gate that fronts the delivery of content must not have an error path an
//    attacker can distinguish from a refusal.
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { verify, isOk, auditChain, evaluateActivationWitnessQuorum, parseWitnessPolicy, verifyRedemption } from '../src/index.js'
import { canonicalBytes, loadsStrict } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import * as V from './helpers/vectors.js'

const allLeaves = V.findLeafDirs()
// Group 36 (chain-of-title audit, v0.2 §17.5) leaves are a SEPARATE surface
// (auditChain, never verify()) — excluded here and driven by their own
// describe block below.
const chainLeaves = allLeaves.filter((d) => V.chainInput(d) !== null)
// Group 40 (activation witness quorum, v0.2 §11.4) leaves are a THIRD surface
// (evaluateActivationWitnessQuorum, never verify() and never auditChain) —
// excluded here and driven by their own describe block below.
const quorumLeaves = allLeaves.filter((d) => V.quorumInput(d) !== null)
// Group 38 (redemption, v0.2 §18.7) leaves are a FOURTH surface
// (verifyRedemption): the question is whether a holder proof is good for THIS
// custodian, which involves no receipt and no grant document at all —
// excluded from the other three and driven by their own describe block below.
const redemptionLeaves = allLeaves.filter((d) => V.redemptionInput(d) !== null)
const leaves = allLeaves.filter(
  (d) => V.chainInput(d) === null && V.quorumInput(d) === null && V.redemptionInput(d) === null,
)
const canonicalLeaves = leaves.filter((d) => existsSync(join(d, 'canonical.json')))

describe('attest conformance vectors', () => {
  it('discovers every leaf the corpus holds', () => {
    // Counted by walking the corpus here, independently of the loader under
    // test. This was a constant floor (>= 158) until a review pointed out what
    // a floor cannot do: once the corpus outgrows it, a loader that silently
    // skips the new leaves still clears it. The floor it replaced had already
    // sat two stages behind without ever failing.
    const walk = (dir: string): number =>
      readdirSync(dir, { withFileTypes: true }).reduce(
        (n, e) =>
          e.isDirectory() ? n + walk(join(dir, e.name)) : n + (e.name === 'expected.json' ? 1 : 0),
        0,
      )
    expect(allLeaves.length).toBe(walk(V.VECTORS_ROOT))
  })

  it('routes every leaf to exactly one of the four surfaces', () => {
    // Guards the partition itself: a leaf that ships two surface files, or a
    // new surface file nobody excluded, would otherwise be run twice or
    // silently dropped from the gate.
    expect(leaves.length + chainLeaves.length + quorumLeaves.length + redemptionLeaves.length).toBe(allLeaves.length)
    expect(redemptionLeaves.length).toBe(4)
  })

  it.each(leaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const r = verify(V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir) as any, V.disclosure(dir), undefined, {
      transparency: V.transparencyEvidence(dir),
      logKeys: V.logKeys(dir),
      anchorPolicy: V.anchorPolicy(dir),
      revocationEvidence: V.revocationEvidence(dir),
      transferView: V.transferView(dir),
      compromiseView: V.compromiseView(dir),
      witnessPolicy: V.witnessPolicy(dir),
      grantView: V.grantView(dir),
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
    if ('grant' in exp) expect(r.grant).toBe(exp.grant)
    if ('grant_trust' in exp) expect(r.grant_trust).toBe(exp.grant_trust)
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

describe('attest conformance vectors: activation witness quorum (group 40)', () => {
  it.each(quorumLeaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const q = V.quorumInput(dir)!
    const policyDocument = V.witnessPolicy(dir)
    const anchorPolicy = V.anchorPolicy(dir)
    expect(policyDocument).not.toBeNull()
    expect(anchorPolicy).not.toBeNull()

    // Parsed here, not handed over as a document: this entry point takes
    // trusted, already-parsed configuration, unlike verify().
    const result = evaluateActivationWitnessQuorum(q.checkpoint, {
      witnessPolicy: parseWitnessPolicy(policyDocument),
      epochId: q.epochId,
      expectedOrigin: q.expectedOrigin,
      anchorEvidence: q.anchorEvidence,
      anchorPolicy: anchorPolicy!,
      conflictDomain: q.conflictDomain,
    })

    expect(result.valid).toBe(exp.valid)
    expect(result.witnessTime).toBe(exp.witness_time)
    expect([...result.countingControlGroups]).toEqual(exp.counting_control_groups)
  })
})

describe('attest conformance vectors: redemption (group 38)', () => {
  it.each(redemptionLeaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const r = V.redemptionInput(dir)!

    // Every negative leaf must come back `false` rather than throw: a short
    // nonce, a forged signature and a replay at the wrong audience are all
    // refusals, and none of them may be distinguishable from the others.
    expect(verifyRedemption(r.receiptId, r.audience, r.nonce, r.sig, r.holderPubkeyB64u)).toBe(exp.verified)
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
