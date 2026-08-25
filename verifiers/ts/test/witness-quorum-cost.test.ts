// The COST half of the activation-grade quorum contract (v0.2 §11.4):
// "the committee ceiling MUST be enforced before any Ed25519 or ML-DSA-65
// signature verification".
//
// Separate file because counting verifications needs `vi.mock`, which is
// file-scoped. The spies delegate to the real implementations, so the
// positive case here proves the same thing the functional suite does and the
// counts describe work that actually happened.
import { describe, it, expect, vi, beforeEach } from 'vitest'

const counts = vi.hoisted(() => ({ ed: 0, pq: 0 }))

vi.mock('../src/ed25519.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/ed25519.js')>()
  return {
    ...actual,
    verifyStrict: (msg: Uint8Array, sig: Uint8Array, pub: Uint8Array) => {
      counts.ed += 1
      return actual.verifyStrict(msg, sig, pub)
    },
  }
})

vi.mock('../src/mldsa.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/mldsa.js')>()
  return {
    ...actual,
    verifyStrict: (msg: Uint8Array, sig: Uint8Array, pub: Uint8Array) => {
      counts.pq += 1
      return actual.verifyStrict(msg, sig, pub)
    },
  }
})

const { evaluateActivationWitnessQuorum, parsePolicy } = await import('../src/witness.js')
const {
  BASE_T,
  ORIGIN,
  anchorFor,
  baseCheckpoint,
  edLeg,
  line,
  makeWitness,
  noteOf,
  pair,
  pinDoc,
  policyDoc,
  pqLeg,
  w1,
  w1Rotated,
  w2,
} = await import('./helpers/witness-quorum-fixtures.js')

function run(text: string, pins: unknown[], threshold: { n: number; m: number }) {
  const { evidence, policy } = anchorFor(text, BASE_T)
  return evaluateActivationWitnessQuorum(text, {
    witnessPolicy: parsePolicy(policyDoc(pins, threshold)),
    epochId: 'bootstrap-1',
    expectedOrigin: ORIGIN,
    anchorEvidence: evidence,
    anchorPolicy: policy,
    conflictDomain: 'issuer.example',
  })
}

beforeEach(() => {
  counts.ed = 0
  counts.pq = 0
})

describe('the cost contract', () => {
  it('refuses a committee of ten before any crypto', () => {
    // The ceiling is a bound on WORK as much as on policy. This does not
    // isolate it from the form check — measured on the parity bench, removing
    // either alone changes no verdict, since `threshold.n > 9` is refused at
    // parse time. What it pins: ten activation groups never reach crypto.
    const base = baseCheckpoint()
    const text = base + pair(w1, noteOf(base), BASE_T)
    const fillers = Array.from({ length: 9 }, (_unused, i) =>
      pinDoc(makeWitness(`filler${i}`, 30 + i)),
    )
    expect(run(text, [pinDoc(w1), ...fillers], { n: 9, m: 1 }).valid).toBe(false)
    expect([counts.ed, counts.pq]).toEqual([0, 0])
  })

  it('refuses two candidate pairs in one control group before any crypto', () => {
    const base = baseCheckpoint()
    const note = noteOf(base)
    const text = base + pair(w1, note, BASE_T) + pair(w1Rotated, note, BASE_T)
    expect(
      run(text, [pinDoc(w1), pinDoc(w1Rotated), pinDoc(w2)], { n: 2, m: 2 }).valid,
    ).toBe(false)
    expect([counts.ed, counts.pq]).toEqual([0, 0])
  })

  it('never verifies the PQ leg once the Ed25519 leg has failed', () => {
    // AND, short-circuited on the cheap leg: an attacker cannot buy ML-DSA
    // work with a garbage classical signature.
    const base = baseCheckpoint()
    const note = noteOf(base)
    const broken = edLeg(w1, note, BASE_T)
    broken[broken.length - 1] ^= 0xff
    const text = base + line(w1.name, broken) + line(w1.name, pqLeg(w1, note, BASE_T))
    expect(run(text, [pinDoc(w1)], { n: 1, m: 1 }).valid).toBe(false)
    expect(counts.ed).toBe(1)
    expect(counts.pq).toBe(0)
  })

  it('does not let extra unknown lines add witness crypto work', () => {
    const base = baseCheckpoint()
    const text =
      base + pair(w1, noteOf(base), BASE_T) + line('stranger/x', new Uint8Array(76))
    expect(run(text, [pinDoc(w1)], { n: 1, m: 1 }).valid).toBe(true)
    expect(counts.ed).toBeLessThanOrEqual(1)
    expect(counts.pq).toBeLessThanOrEqual(1)
  })
})
