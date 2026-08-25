// Standalone activation-grade hybrid witness quorum (v0.2 §11.4).
// Mirrors tests/test_witness_quorum.py case for case.
//
// Matching Ed25519 (`0x04`) and ML-DSA-65 (`0xff || "attest-cosignature-ml-dsa-65-v1"`)
// legs over the same `cosignature/v1` payload and the same timestamp; both
// MUST verify (AND); one vote per `control_group`; committee ceiling enforced
// before any signature verification; a full `signed-note-v2` anchor with
// `max(t_i) - min(t_i) <= 600` and `max(t_i) <= A <= T + 86400`, `T = min(t_i)`.
//
// Mirrored tests do not prove PARITY — the cross-core bench in
// tools/witness_parity_cases.py does. They prove each core keeps its own
// contract; the bench proves the two contracts are the same one.
import { describe, it, expect } from 'vitest'

import { WitnessError, evaluateActivationWitnessQuorum, parsePolicy } from '../src/witness.js'
import type { WitnessPolicy } from '../src/witness.js'
import {
  BASE_T,
  ORIGIN,
  anchorFor,
  baseCheckpoint,
  edLeg,
  line,
  noteOf,
  pair,
  pinDoc,
  policyDoc,
  pqLeg,
  w1,
  w1Rotated,
  w2,
  w3,
  makeWitness,
} from './helpers/witness-quorum-fixtures.js'

function policy(
  pins: unknown[],
  threshold: { n: number; m: number },
  epochOverrides: Record<string, unknown> = {},
): WitnessPolicy {
  return parsePolicy(policyDoc(pins, threshold, epochOverrides))
}

interface EvaluateOptions {
  anchorTime: number
  anchorProfile?: string | null
  epochId?: unknown
  expectedOrigin?: string
  conflictDomain?: string
}

function evaluate(text: string, witnessPolicy: WitnessPolicy, options: EvaluateOptions) {
  const { evidence, policy: anchorPolicy } = anchorFor(
    text,
    options.anchorTime,
    options.anchorProfile === undefined ? 'signed-note-v2' : options.anchorProfile,
  )
  return evaluateActivationWitnessQuorum(text, {
    witnessPolicy,
    epochId: options.epochId === undefined ? 'bootstrap-1' : options.epochId,
    expectedOrigin: options.expectedOrigin ?? ORIGIN,
    anchorEvidence: evidence,
    anchorPolicy,
    conflictDomain: options.conflictDomain ?? 'issuer.example',
  })
}

function oneOfOne(timestamp: number): { text: string; witnessPolicy: WitnessPolicy } {
  const base = baseCheckpoint()
  const text = base + pair(w1, noteOf(base), timestamp)
  return { text, witnessPolicy: policy([pinDoc(w1)], { n: 1, m: 1 }) }
}

describe('the valid shapes', () => {
  it('accepts a bootstrap 1-of-1', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    const result = evaluate(text, witnessPolicy, { anchorTime: BASE_T })
    expect(result.valid).toBe(true)
    expect(result.witnessTime).toBe(BASE_T)
    expect(result.countingControlGroups).toEqual([w1.group])
  })

  it('counts two distinct control groups for a 2-of-3', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T + 5)
    const p = policy([pinDoc(w1), pinDoc(w2), pinDoc(w3)], { n: 3, m: 2 })
    const result = evaluate(text, p, { anchorTime: BASE_T + 5 })
    expect(result.valid).toBe(true)
    expect(result.countingControlGroups).toEqual([w1.group, w2.group].sort())
  })

  it('reports the minimum counting timestamp as the witness time', () => {
    // `T = min(t_i)`, the conservative choice: the maximum would let a late
    // signer stretch the anchor window every earlier one is judged by.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T + 300) + pair(w2, note, BASE_T)
    const p = policy([pinDoc(w1), pinDoc(w2), pinDoc(w3)], { n: 3, m: 2 })
    const result = evaluate(text, p, { anchorTime: BASE_T + 300 })
    expect(result.valid).toBe(true)
    expect(result.witnessTime).toBe(BASE_T)
  })
})

describe('the hybrid AND rule', () => {
  it('does not count a pin presenting only its Ed25519 leg', () => {
    const base = baseCheckpoint()
    const text = base + line(w1.name, edLeg(w1, noteOf(base), BASE_T))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('does not count a pin presenting only its PQ leg', () => {
    const base = baseCheckpoint()
    const text = base + line(w1.name, pqLeg(w1, noteOf(base), BASE_T))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('kills the whole pair when the Ed25519 leg is invalid', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const broken = edLeg(w1, note, BASE_T)
    broken[broken.length - 1] ^= 0xff
    const text = base + line(w1.name, broken) + line(w1.name, pqLeg(w1, note, BASE_T))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('kills the whole pair when the PQ leg is invalid', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const broken = pqLeg(w1, note, BASE_T)
    broken[broken.length - 1] ^= 0xff
    const text = base + line(w1.name, edLeg(w1, note, BASE_T)) + line(w1.name, broken)
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('does not pair legs carrying different timestamps', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text =
      base + line(w1.name, edLeg(w1, note, BASE_T)) + line(w1.name, pqLeg(w1, note, BASE_T + 1))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T + 1 }).valid).toBe(false)
  })

  it('does not count a leg transplanted from another checkpoint', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const otherNote = noteOf(baseCheckpoint(9))
    const text =
      base +
      line(w1.name, edLeg(w1, note, BASE_T, { signedNote: otherNote })) +
      line(w1.name, pqLeg(w1, note, BASE_T))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('does not treat a C2SP type-0x06 line as a PQ leg', () => {
    // `0x06` is the registry's ML-DSA-44 `subtree/v1` cosignature — another
    // algorithm over another structure (§9.2).
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text =
      base +
      line(w1.name, edLeg(w1, note, BASE_T)) +
      line(w1.name, pqLeg(w1, note, BASE_T, { sigType: Uint8Array.of(0x06) }))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('does not accept the checkpoint signature type as a cosignature leg', () => {
    const checkpointType = new Uint8Array([0xff, ...new TextEncoder().encode('attest-ml-dsa-65')])
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text =
      base +
      line(w1.name, edLeg(w1, note, BASE_T)) +
      line(w1.name, pqLeg(w1, note, BASE_T, { sigType: checkpointType }))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('does not count a line signed by a stranger', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text =
      base +
      line(w1.name, edLeg(w1, note, BASE_T, { signerSeed: w2.edSeed })) +
      line(w1.name, pqLeg(w1, note, BASE_T))
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('ignores lines naming an unpinned identity', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w2, note, BASE_T) + pair(w1, note, BASE_T)
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    const result = evaluate(text, p, { anchorTime: BASE_T })
    expect(result.valid).toBe(true)
    expect(result.countingControlGroups).toEqual([w1.group])
  })
})

describe('one vote per control group', () => {
  it('refuses two candidate pairs in one control group', () => {
    // A rotated key does not double a group's weight; counting keys instead
    // of groups would make this a satisfied 2-of-2.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w1Rotated, note, BASE_T)
    const p = policy([pinDoc(w1), pinDoc(w1Rotated), pinDoc(w2)], { n: 2, m: 2 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('still counts the group when only the rotated key cosigned', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1Rotated, note, BASE_T) + pair(w2, note, BASE_T)
    const p = policy([pinDoc(w1), pinDoc(w1Rotated), pinDoc(w2)], { n: 2, m: 2 })
    const result = evaluate(text, p, { anchorTime: BASE_T })
    expect(result.valid).toBe(true)
    expect(result.countingControlGroups).toEqual([w1.group, w2.group].sort())
  })

  it('fails the quorum on an ambiguous group instead of dropping it', () => {
    // Ambiguity is a HARD failure, not a silently skipped vote: `w2` alone
    // satisfies `m = 1`, so a reading that merely dropped the ambiguous group
    // would return valid. This is the only shape that tells the two apart.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text =
      base + pair(w1, note, BASE_T) + pair(w1, note, BASE_T + 1) + pair(w2, note, BASE_T)
    const p = policy([pinDoc(w1), pinDoc(w2)], { n: 2, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T + 1 }).valid).toBe(false)
  })

  it('fails the quorum on a duplicated group instead of counting it once', () => {
    // Same distinction for the one-vote-per-group rule: with `w2` also voting,
    // collapsing the duplicated group to a single vote would reach `m = 2`.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text =
      base + pair(w1, note, BASE_T) + pair(w1Rotated, note, BASE_T) + pair(w2, note, BASE_T)
    const p = policy([pinDoc(w1), pinDoc(w1Rotated), pinDoc(w2)], { n: 2, m: 2 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('treats a duplicated line for one pin as ambiguous', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w1, note, BASE_T + 1)
    const p = policy([pinDoc(w1)], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T + 1 }).valid).toBe(false)
  })
})

describe('committee form', () => {
  const fillers = (count: number) =>
    Array.from({ length: count }, (_unused, i) =>
      pinDoc(makeWitness(`filler${i}`, 30 + i)),
    )

  it('refuses a committee of ten', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1), ...fillers(9)], { n: 9, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('still admits a committee of exactly nine', () => {
    // The positive boundary: without it a ceiling refusing every committee
    // would satisfy the case above.
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1), ...fillers(8)], { n: 9, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(true)
  })

  it('requires threshold.n to equal the activation committee size', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1)], { n: 2, m: 2 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('leaves a corroboration-only pin out of the committee', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T)
    const p = policy(
      [pinDoc(w1), pinDoc(w2, { roles: ['corroboration'], mldsa_65_pub_b64u: null })],
      { n: 1, m: 1 },
    )
    const result = evaluate(text, p, { anchorTime: BASE_T })
    expect(result.valid).toBe(true)
    expect(result.countingControlGroups).toEqual([w1.group])
  })

  it('refuses fewer valid votes than m', () => {
    const base = baseCheckpoint()
    const text = base + pair(w1, noteOf(base), BASE_T)
    const p = policy([pinDoc(w1), pinDoc(w2)], { n: 2, m: 2 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })
})

describe('the conflict predicate', () => {
  it('excludes a directly affiliated pin', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T)
    const p = policy(
      [
        pinDoc(w1, { affiliated_domains: [w1.operator, 'issuer.example'].sort() }),
        pinDoc(w2),
      ],
      { n: 2, m: 2 },
    )
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('excludes a transitively affiliated pin', () => {
    // `w1Rotated` names the domain; `w1` does not, but shares its control
    // group, so the whole group is out.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T)
    const p = policy(
      [
        pinDoc(w1),
        pinDoc(w1Rotated, { affiliated_domains: [w1.operator, 'issuer.example'].sort() }),
        pinDoc(w2),
      ],
      { n: 2, m: 2 },
    )
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('takes the conflict domain as a parameter, not a constant', () => {
    // Same policy, same checkpoint, different domain — a different eligible
    // committee. A hardcoded domain passes the two above and fails this.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T)
    const p = policy(
      [pinDoc(w1, { affiliated_domains: [w1.operator, 'issuer.example'].sort() }), pinDoc(w2)],
      { n: 2, m: 2 },
    )
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
    expect(
      evaluate(text, p, { anchorTime: BASE_T, conflictDomain: 'other.example' }).valid,
    ).toBe(true)
  })
})

describe('temporal and lifecycle boundaries', () => {
  it('accepts a skew of exactly 600 seconds', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T + 600)
    const p = policy([pinDoc(w1), pinDoc(w2)], { n: 2, m: 2 })
    expect(evaluate(text, p, { anchorTime: BASE_T + 600 }).valid).toBe(true)
  })

  it('refuses a skew of 601 seconds', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T + 601)
    const p = policy([pinDoc(w1), pinDoc(w2)], { n: 2, m: 2 })
    expect(evaluate(text, p, { anchorTime: BASE_T + 601 }).valid).toBe(false)
  })

  it('accepts an anchor exactly at max(t_i)', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(evaluate(text, witnessPolicy, { anchorTime: BASE_T }).valid).toBe(true)
  })

  it('refuses an anchor predating max(t_i)', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(evaluate(text, witnessPolicy, { anchorTime: BASE_T - 1 }).valid).toBe(false)
  })

  it('accepts an anchor exactly at T + 86400', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(evaluate(text, witnessPolicy, { anchorTime: BASE_T + 86400 }).valid).toBe(true)
  })

  it('refuses an anchor one second past the delay bound', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(evaluate(text, witnessPolicy, { anchorTime: BASE_T + 86401 }).valid).toBe(false)
  })

  it('measures the delay bound from the minimum, not the maximum', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T + 600)
    const p = policy([pinDoc(w1), pinDoc(w2)], { n: 2, m: 2 })
    expect(evaluate(text, p, { anchorTime: BASE_T + 86401 }).valid).toBe(false)
  })

  it('refuses a note-only anchor', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(
      evaluate(text, witnessPolicy, { anchorTime: BASE_T, anchorProfile: 'note-v1' }).valid,
    ).toBe(false)
  })

  it('refuses an absent anchor profile', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(
      evaluate(text, witnessPolicy, { anchorTime: BASE_T, anchorProfile: null }).valid,
    ).toBe(false)
  })

  it('refuses an anchor that does not verify', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    const { evidence, policy: anchorPolicy } = anchorFor(text, BASE_T)
    ;(evidence['proofs'] as Array<Record<string, unknown>>)[0]!['header_merkle_root'] =
      '00'.repeat(32)
    const result = evaluateActivationWitnessQuorum(text, {
      witnessPolicy,
      epochId: 'bootstrap-1',
      expectedOrigin: ORIGIN,
      anchorEvidence: evidence,
      anchorPolicy,
      conflictDomain: 'issuer.example',
    })
    expect(result.valid).toBe(false)
  })

  it('does not revive an epoch that expired before T', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1)], { n: 1, m: 1 }, { not_after: '2021-01-01T00:00:00Z' })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('still covers an epoch ending exactly at T', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1)], { n: 1, m: 1 }, { not_after: '2023-11-14T22:13:20Z' })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(true)
  })

  it('does not count a pin that expired before T', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1, { not_after: '2021-01-01T00:00:00Z' })], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('still counts a pin whose window ends exactly at T', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1, { not_after: '2023-11-14T22:13:20Z' })], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(true)
  })

  it('retains standing for a compromise cutoff exactly at T', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1, { compromised_after: '2023-11-14T22:13:20Z' })], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(true)
  })

  it('excludes a pin whose compromise cutoff is one second before T', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1, { compromised_after: '2023-11-14T22:13:19Z' })], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('gives an unknown compromise onset no standing at all', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1, { compromised_after: null })], { n: 1, m: 1 })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('judges the lifecycle at the quorum time, not per leg', () => {
    // `w2` observed after its own cutoff, but the quorum time is the earlier
    // `T`, and §11.4 judges standing at `T`.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T + 300)
    const p = policy(
      [pinDoc(w1), pinDoc(w2, { compromised_after: '2023-11-14T22:13:20Z' })],
      { n: 2, m: 2 },
    )
    expect(evaluate(text, p, { anchorTime: BASE_T + 300 }).valid).toBe(true)
  })

  it('does not let an excluded vote set T for the counting set', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w2, note, BASE_T + 400)
    const p = policy(
      [
        pinDoc(w1, { compromised_after: '2023-11-14T22:13:19Z' }),
        pinDoc(w2, { compromised_after: '2023-11-14T22:16:40Z' }),
      ],
      { n: 2, m: 1 },
    )
    const result = evaluate(text, p, { anchorTime: BASE_T + 400 })
    expect(result.valid).toBe(false)
    expect(result.witnessTime).toBeNull()
  })
})

describe('scope and untrusted-input discipline', () => {
  it('never substitutes another epoch for an unresolvable one', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(
      evaluate(text, witnessPolicy, { anchorTime: BASE_T, epochId: 'no-such-epoch' }).valid,
    ).toBe(false)
  })

  it('corroborates nothing from an epoch scoped to another origin', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1)], { n: 1, m: 1 }, { log_origins: ['other.example'] })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('corroborates nothing from an epoch with no origins', () => {
    const { text } = oneOfOne(BASE_T)
    const p = policy([pinDoc(w1)], { n: 1, m: 1 }, { log_origins: [] })
    expect(evaluate(text, p, { anchorTime: BASE_T }).valid).toBe(false)
  })

  it('refuses a checkpoint for another origin', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(
      evaluate(text, witnessPolicy, { anchorTime: BASE_T, expectedOrigin: 'other.example' }).valid,
    ).toBe(false)
  })

  it('returns invalid rather than throwing on a malformed checkpoint', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    const { evidence, policy: anchorPolicy } = anchorFor(text, BASE_T)
    const result = evaluateActivationWitnessQuorum('not a checkpoint', {
      witnessPolicy,
      epochId: 'bootstrap-1',
      expectedOrigin: ORIGIN,
      anchorEvidence: evidence,
      anchorPolicy,
      conflictDomain: 'issuer.example',
    })
    expect(result.valid).toBe(false)
    expect(result.witnessTime).toBeNull()
    expect(result.countingControlGroups).toEqual([])
  })

  it('returns invalid rather than throwing on malformed anchor evidence', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    const { policy: anchorPolicy } = anchorFor(text, BASE_T)
    const result = evaluateActivationWitnessQuorum(text, {
      witnessPolicy,
      epochId: 'bootstrap-1',
      expectedOrigin: ORIGIN,
      anchorEvidence: { nonsense: true },
      anchorPolicy,
      conflictDomain: 'issuer.example',
    })
    expect(result.valid).toBe(false)
  })

  it('returns invalid for a non-string epoch id', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    expect(evaluate(text, witnessPolicy, { anchorTime: BASE_T, epochId: null }).valid).toBe(false)
  })
})

describe('trusted-configuration errors', () => {
  it('throws on a raw policy document', () => {
    const { text } = oneOfOne(BASE_T)
    const { evidence, policy: anchorPolicy } = anchorFor(text, BASE_T)
    expect(() =>
      evaluateActivationWitnessQuorum(text, {
        witnessPolicy: { schema: 'attest-witness-policy-v1', epochs: [] } as unknown as WitnessPolicy,
        epochId: 'bootstrap-1',
        expectedOrigin: ORIGIN,
        anchorEvidence: evidence,
        anchorPolicy,
        conflictDomain: 'issuer.example',
      }),
    ).toThrow(WitnessError)
  })

  it('throws on a raw policy document carrying an epoch', () => {
    // The mistake this guards against: handing over the JSON document instead
    // of the parsed policy, which would otherwise resolve no epoch and look
    // like an ordinary negative result rather than the caller bug it is.
    const { text } = oneOfOne(BASE_T)
    const { evidence, policy: anchorPolicy } = anchorFor(text, BASE_T)
    expect(() =>
      evaluateActivationWitnessQuorum(text, {
        witnessPolicy: policyDoc([pinDoc(w1)], { n: 1, m: 1 }) as WitnessPolicy,
        epochId: 'bootstrap-1',
        expectedOrigin: ORIGIN,
        anchorEvidence: evidence,
        anchorPolicy,
        conflictDomain: 'issuer.example',
      }),
    ).toThrow(WitnessError)
  })

  it('throws on a hostile empty-threshold policy shape', () => {
    const { text } = oneOfOne(BASE_T)
    const { evidence, policy: anchorPolicy } = anchorFor(text, BASE_T)
    expect(() =>
      evaluateActivationWitnessQuorum(text, {
        witnessPolicy: {
          epochs: [
            {
              epochId: 'bootstrap-1',
              notBefore: 0,
              threshold: {},
              witnesses: [],
            },
          ],
        } as unknown as WitnessPolicy,
        epochId: 'bootstrap-1',
        expectedOrigin: ORIGIN,
        anchorEvidence: evidence,
        anchorPolicy,
        conflictDomain: 'issuer.example',
      }),
    ).toThrow(WitnessError)
  })

  it('throws on a malformed conflict domain', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    const { evidence, policy: anchorPolicy } = anchorFor(text, BASE_T)
    expect(() =>
      evaluateActivationWitnessQuorum(text, {
        witnessPolicy,
        epochId: 'bootstrap-1',
        expectedOrigin: ORIGIN,
        anchorEvidence: evidence,
        anchorPolicy,
        conflictDomain: 'Not A Domain',
      }),
    ).toThrow(WitnessError)
  })

  it('throws on a malformed expected origin', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    const { evidence, policy: anchorPolicy } = anchorFor(text, BASE_T)
    expect(() =>
      evaluateActivationWitnessQuorum(text, {
        witnessPolicy,
        epochId: 'bootstrap-1',
        expectedOrigin: 'bad\norigin',
        anchorEvidence: evidence,
        anchorPolicy,
        conflictDomain: 'issuer.example',
      }),
    ).toThrow(WitnessError)
  })

  it('throws on a malformed anchor policy', () => {
    const { text, witnessPolicy } = oneOfOne(BASE_T)
    const { evidence } = anchorFor(text, BASE_T)
    expect(() =>
      evaluateActivationWitnessQuorum(text, {
        witnessPolicy,
        epochId: 'bootstrap-1',
        expectedOrigin: ORIGIN,
        anchorEvidence: evidence,
        anchorPolicy: 'not a policy' as unknown as never,
        conflictDomain: 'issuer.example',
      }),
    ).toThrow(WitnessError)
  })
})
