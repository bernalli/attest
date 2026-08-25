// Tests for src/witness.ts — WitnessPolicy parsing, epoch validity, compromise
// lifecycle, conflict predicate (v0.2 §11.4, P1.1b amendment). Mirrors
// tests/test_witness.py (Python reference) case-for-case: a policy one core
// accepts is one the other core accepts.
//
// The policy is TRUSTED verifier configuration on the same rail as pinned log
// keys, so malformed input THROWS — it signals a caller bug, never adversarial
// input (§10.2). Nothing here touches evidence.
import { describe, it, expect } from 'vitest'

import { b64uEncode } from '../src/b64u.js'
import { canonicalBytes } from '../src/canon.js'
import { ML_DSA_65_PK_LEN } from '../src/mldsa.js'
import {
  CANONICAL_EMPTY_POLICY_BYTES,
  loadPolicy,
  MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE,
  MAX_WITNESS_ANCHOR_DELAY_SECONDS,
  MAX_WITNESS_SKEW_SECONDS,
  WitnessError,
  type WitnessEpoch,
  epochCovers,
  findEpoch,
  isConflicted,
  parsePolicy,
  pinCovers,
  pinHasStandingAt,
} from '../src/witness.js'

const ED25519_PUB = b64uEncode(new Uint8Array(Array.from({ length: 32 }, (_, i) => i)))
const ED25519_PUB_2 = b64uEncode(new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1)))
const MLDSA_PUB = b64uEncode(new Uint8Array(ML_DSA_65_PK_LEN))

function pin(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    operator_id: 'witness.example',
    control_group: 'witness.example',
    name: 'witness.example/w1',
    ed25519_pub_b64u: ED25519_PUB,
    mldsa_65_pub_b64u: null,
    roles: ['corroboration'],
    not_before: '2026-01-01T00:00:00Z',
    not_after: null,
    affiliated_domains: ['witness.example'],
    ...overrides,
  }
}

function epoch(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    epoch_id: 'bootstrap-1',
    not_before: '2026-01-01T00:00:00Z',
    not_after: null,
    log_origins: [],
    threshold: { n: 1, m: 1 },
    witnesses: [pin()],
    ...overrides,
  }
}

function policy(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { schema: 'attest-witness-policy-v1', epochs: [epoch()], ...overrides }
}

const at = (value: string): number => Date.parse(value)

describe('top-level shape', () => {
  it('parses the packaged empty policy', () => {
    expect(parsePolicy({ schema: 'attest-witness-policy-v1', epochs: [] }).epochs).toEqual([])
  })

  it('pins the canonical empty policy bytes as JCS', () => {
    expect(CANONICAL_EMPTY_POLICY_BYTES).toEqual(
      canonicalBytes({ schema: 'attest-witness-policy-v1', epochs: [] }),
    )
  })

  it('parses a full policy', () => {
    const parsed = parsePolicy(policy())
    expect(parsed.epochs).toHaveLength(1)
    expect(parsed.epochs[0]!.epochId).toBe('bootstrap-1')
    expect(parsed.epochs[0]!.notAfter).toBeNull()
    expect(parsed.epochs[0]!.threshold).toEqual({ n: 1, m: 1 })
  })

  it('rejects an unknown top-level member', () => {
    expect(() => parsePolicy(policy({ extra: 'nope' }))).toThrow(WitnessError)
  })

  it('rejects a wrong schema literal', () => {
    expect(() => parsePolicy(policy({ schema: 'attest-witness-policy-v2' }))).toThrow(WitnessError)
  })

  it('rejects a missing top-level member', () => {
    expect(() => parsePolicy({ schema: 'attest-witness-policy-v1' })).toThrow(WitnessError)
  })

  it('rejects a non-object document', () => {
    expect(() => parsePolicy(['attest-witness-policy-v1'])).toThrow(WitnessError)
  })
})

describe('epoch shape', () => {
  it('rejects an unknown epoch member', () => {
    expect(() => parsePolicy(policy({ epochs: [epoch({ note: 'nope' })] }))).toThrow(WitnessError)
  })

  it('rejects a missing epoch member', () => {
    const incomplete = epoch()
    delete incomplete['threshold']
    expect(() => parsePolicy(policy({ epochs: [incomplete] }))).toThrow(WitnessError)
  })

  it.each(['', '-leading', 'UPPER', 'a'.repeat(129), 'has space', 'dot.ok\n'])(
    'rejects epoch_id %j',
    (epochId) => {
      expect(() => parsePolicy(policy({ epochs: [epoch({ epoch_id: epochId })] }))).toThrow(
        WitnessError,
      )
    },
  )

  it.each(['a', 'bootstrap-1', `x.${'y'.repeat(126)}`])('accepts epoch_id %j', (epochId) => {
    expect(parsePolicy(policy({ epochs: [epoch({ epoch_id: epochId })] })).epochs[0]!.epochId).toBe(
      epochId,
    )
  })

  it('rejects a duplicate epoch_id', () => {
    expect(() => parsePolicy(policy({ epochs: [epoch(), epoch()] }))).toThrow(WitnessError)
  })

  it.each([
    '2026-01-01T00:00:00',
    '2026-01-01 00:00:00Z',
    '2026-01-01T00:00:00.5Z',
    'not-a-date',
  ])('rejects timestamp %j', (timestamp) => {
    expect(() => parsePolicy(policy({ epochs: [epoch({ not_before: timestamp })] }))).toThrow(
      WitnessError,
    )
  })

  it('rejects not_after before not_before', () => {
    expect(() =>
      parsePolicy(
        policy({
          epochs: [epoch({ not_before: '2026-06-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z' })],
        }),
      ),
    ).toThrow(WitnessError)
  })

  it('requires log_origins sorted and duplicate-free', () => {
    expect(() =>
      parsePolicy(policy({ epochs: [epoch({ log_origins: ['b.example', 'a.example'] })] })),
    ).toThrow(WitnessError)
    expect(() =>
      parsePolicy(policy({ epochs: [epoch({ log_origins: ['a.example', 'a.example'] })] })),
    ).toThrow(WitnessError)
  })

  it('accepts sorted log_origins', () => {
    const parsed = parsePolicy(
      policy({ epochs: [epoch({ log_origins: ['a.example', 'b.example'] })] }),
    )
    expect(parsed.epochs[0]!.logOrigins).toEqual(['a.example', 'b.example'])
  })

  it.each([
    { n: 1 },
    { n: 1, m: 1, extra: 0 },
    { n: 0, m: 1 },
    { n: 1, m: 0 },
    { n: 1, m: 2 },
  ])('rejects threshold %j', (threshold) => {
    expect(() => parsePolicy(policy({ epochs: [epoch({ threshold })] }))).toThrow(WitnessError)
  })

  it('rejects a boolean threshold value', () => {
    // Guards the Python core's `bool`-is-`int` hole from becoming a divergence.
    expect(() => parsePolicy(policy({ epochs: [epoch({ threshold: { n: true, m: 1 } })] }))).toThrow(
      WitnessError,
    )
  })
})

describe('cross-core parity guards', () => {
  it('rejects a non-ASCII log origin', () => {
    // Python orders by code point, JS by UTF-16 code unit: ['\u{10000}',
    // '\ufffd'] is unsorted for one core and sorted for the other. The §9.3
    // ASCII grammar is what stops the two from disagreeing.
    expect(() =>
      parsePolicy(policy({ epochs: [epoch({ log_origins: ['\u{10000}'] })] })),
    ).toThrow(WitnessError)
  })

  it('rejects non-integer JSON literals when loading from bytes', () => {
    // `1.0` and `1` are the same value here, so only canon can tell them
    // apart — which is why loading from bytes is the supported entry point.
    const enc = (s: string): Uint8Array => new TextEncoder().encode(s)
    expect(loadPolicy(enc('{"epochs":[],"schema":"attest-witness-policy-v1"}')).epochs).toEqual([])
    expect(() => loadPolicy(enc('{"epochs":[{"threshold":{"n":1.0}}],"schema":"x"}'))).toThrow()
  })

  it('loads a policy carrying a threshold from bytes', () => {
    // canon yields BIGINT for JSON integers, so a policy with a threshold
    // takes a different type path than an in-memory one. An `epochs: []`
    // fixture never reaches that code and hides the difference.
    const parsed = loadPolicy(new TextEncoder().encode(JSON.stringify(policy())))
    expect(parsed.epochs[0]!.threshold).toEqual({ n: 1, m: 1 })
  })

  it('rejects an integer past the JS safe range on both cores', () => {
    const doc = JSON.stringify(policy({ epochs: [epoch({ threshold: { n: 9007199254740993, m: 1 } })] }))
    expect(() => loadPolicy(new TextEncoder().encode(doc))).toThrow(WitnessError)
  })
})

describe('witness pin shape', () => {
  it('rejects an unknown pin member', () => {
    expect(() =>
      parsePolicy(policy({ epochs: [epoch({ witnesses: [pin({ note: 'nope' })] })] })),
    ).toThrow(WitnessError)
  })

  it('rejects a missing pin member', () => {
    const incomplete = pin()
    delete incomplete['roles']
    expect(() => parsePolicy(policy({ epochs: [epoch({ witnesses: [incomplete] })] }))).toThrow(
      WitnessError,
    )
  })

  it('rejects a trailing newline in a DNS name', () => {
    // Python's `$` matches before a trailing newline and JavaScript's does not;
    // both cores must refuse it or they disagree on admissible policies.
    expect(() =>
      parsePolicy(
        policy({
          epochs: [
            epoch({
              witnesses: [
                pin({ operator_id: 'witness.example\n', affiliated_domains: ['witness.example\n'] }),
              ],
            }),
          ],
        }),
      ),
    ).toThrow(WitnessError)
  })

  it.each(['operator_id', 'control_group'])('requires %s to be a lowercase DNS name', (field) => {
    expect(() =>
      parsePolicy(
        policy({
          epochs: [
            epoch({
              witnesses: [pin({ [field]: 'Witness.Example', affiliated_domains: ['witness.example'] })],
            }),
          ],
        }),
      ),
    ).toThrow(WitnessError)
  })

  it('requires the C2SP key-name grammar', () => {
    expect(() =>
      parsePolicy(policy({ epochs: [epoch({ witnesses: [pin({ name: 'witness+w1' })] })] })),
    ).toThrow(WitnessError)
    expect(() =>
      parsePolicy(policy({ epochs: [epoch({ witnesses: [pin({ name: '' })] })] })),
    ).toThrow(WitnessError)
  })

  it('requires affiliated_domains to contain its own operator_id', () => {
    expect(() =>
      parsePolicy(
        policy({ epochs: [epoch({ witnesses: [pin({ affiliated_domains: ['other.example'] })] })] }),
      ),
    ).toThrow(WitnessError)
  })

  it.each([
    ['roles', ['sunset-activation', 'corroboration']],
    ['roles', ['corroboration', 'corroboration']],
    ['affiliated_domains', ['witness.example', 'a.example']],
    ['affiliated_domains', ['witness.example', 'witness.example']],
  ])('requires %s sorted and duplicate-free', (field, value) => {
    expect(() =>
      parsePolicy(
        policy({
          epochs: [
            epoch({ witnesses: [pin({ [field as string]: value, mldsa_65_pub_b64u: MLDSA_PUB })] }),
          ],
        }),
      ),
    ).toThrow(WitnessError)
  })

  it('allows a null activation leg only without the sunset-activation role', () => {
    const parsed = parsePolicy(
      policy({
        epochs: [
          epoch({ witnesses: [pin({ roles: ['corroboration'], mldsa_65_pub_b64u: null })] }),
        ],
      }),
    )
    expect(parsed.epochs[0]!.witnesses[0]!.mldsa65Pub).toBeNull()

    expect(() =>
      parsePolicy(
        policy({
          epochs: [
            epoch({
              witnesses: [
                pin({ roles: ['corroboration', 'sunset-activation'], mldsa_65_pub_b64u: null }),
              ],
            }),
          ],
        }),
      ),
    ).toThrow(WitnessError)
  })

  it('enforces public key lengths', () => {
    expect(() =>
      parsePolicy(
        policy({
          epochs: [epoch({ witnesses: [pin({ ed25519_pub_b64u: b64uEncode(new Uint8Array(5)) })] })],
        }),
      ),
    ).toThrow(WitnessError)
    expect(() =>
      parsePolicy(
        policy({
          epochs: [
            epoch({
              witnesses: [
                pin({
                  roles: ['corroboration', 'sunset-activation'],
                  mldsa_65_pub_b64u: b64uEncode(new Uint8Array(5)),
                }),
              ],
            }),
          ],
        }),
      ),
    ).toThrow(WitnessError)
  })

  it('rejects an unknown role', () => {
    expect(() =>
      parsePolicy(policy({ epochs: [epoch({ witnesses: [pin({ roles: ['auditor'] })] })] })),
    ).toThrow(WitnessError)
  })

  it('does not mutate the caller document', () => {
    const document = policy()
    const before = structuredClone(document)
    parsePolicy(document)
    expect(document).toEqual(before)
  })
})

describe('epoch resolution and validity', () => {
  it('resolves an epoch by id', () => {
    const parsed = parsePolicy(policy())
    expect(findEpoch(parsed, 'bootstrap-1')).toBe(parsed.epochs[0])
    expect(findEpoch(parsed, 'absent')).toBeUndefined()
  })

  it('treats epoch validity as inclusive at both boundaries', () => {
    const parsed = parsePolicy(
      policy({
        epochs: [epoch({ not_before: '2026-01-01T00:00:00Z', not_after: '2026-12-31T23:59:59Z' })],
      }),
    )
    const e = parsed.epochs[0]!
    expect(epochCovers(e, at('2026-01-01T00:00:00Z'))).toBe(true)
    expect(epochCovers(e, at('2026-12-31T23:59:59Z'))).toBe(true)
    expect(epochCovers(e, at('2025-12-31T23:59:59Z'))).toBe(false)
    expect(epochCovers(e, at('2027-01-01T00:00:00Z'))).toBe(false)
  })

  it('never expires an open-ended epoch', () => {
    expect(epochCovers(parsePolicy(policy()).epochs[0]!, at('2999-01-01T00:00:00Z'))).toBe(true)
  })

  it('treats pin validity as inclusive at both boundaries', () => {
    const parsed = parsePolicy(
      policy({
        epochs: [
          epoch({
            witnesses: [pin({ not_before: '2026-01-01T00:00:00Z', not_after: '2026-06-30T23:59:59Z' })],
          }),
        ],
      }),
    )
    const p = parsed.epochs[0]!.witnesses[0]!
    expect(pinCovers(p, at('2026-01-01T00:00:00Z'))).toBe(true)
    expect(pinCovers(p, at('2026-06-30T23:59:59Z'))).toBe(true)
    expect(pinCovers(p, at('2026-07-01T00:00:00Z'))).toBe(false)
  })
})

describe('compromise lifecycle (tri-state)', () => {
  it('treats an absent compromised_after as no compromise declared', () => {
    const p = parsePolicy(policy()).epochs[0]!.witnesses[0]!
    expect(pinHasStandingAt(p, at('2999-01-01T00:00:00Z'))).toBe(true)
  })

  it('treats a compromised_after string as an inclusive cutoff', () => {
    const p = parsePolicy(
      policy({
        epochs: [epoch({ witnesses: [pin({ compromised_after: '2026-06-01T00:00:00Z' })] })],
      }),
    ).epochs[0]!.witnesses[0]!
    expect(pinHasStandingAt(p, at('2026-05-31T23:59:59Z'))).toBe(true)
    expect(pinHasStandingAt(p, at('2026-06-01T00:00:00Z'))).toBe(true)
    expect(pinHasStandingAt(p, at('2026-06-01T00:00:01Z'))).toBe(false)
  })

  it('removes standing at every time for an explicit null compromised_after', () => {
    const p = parsePolicy(
      policy({ epochs: [epoch({ witnesses: [pin({ compromised_after: null })] })] }),
    ).epochs[0]!.witnesses[0]!
    expect(pinHasStandingAt(p, at('2020-01-01T00:00:00Z'))).toBe(false)
    expect(pinHasStandingAt(p, at('2026-01-01T00:00:00Z'))).toBe(false)
    expect(pinHasStandingAt(p, at('2999-01-01T00:00:00Z'))).toBe(false)
  })

  it('distinguishes an absent compromised_after from an explicit null', () => {
    const absent = parsePolicy(policy()).epochs[0]!.witnesses[0]!
    const explicit = parsePolicy(
      policy({ epochs: [epoch({ witnesses: [pin({ compromised_after: null })] })] }),
    ).epochs[0]!.witnesses[0]!
    expect(absent.compromiseDeclared).toBe(false)
    expect(explicit.compromiseDeclared).toBe(true)
    expect(absent.compromisedAfter).toBeNull()
    expect(explicit.compromisedAfter).toBeNull()
  })

  it('also requires the pin validity window for standing', () => {
    const p = parsePolicy(
      policy({ epochs: [epoch({ witnesses: [pin({ not_after: '2026-06-30T23:59:59Z' })] })] }),
    ).epochs[0]!.witnesses[0]!
    expect(pinHasStandingAt(p, at('2026-06-30T23:59:59Z'))).toBe(true)
    expect(pinHasStandingAt(p, at('2026-07-01T00:00:00Z'))).toBe(false)
  })
})

describe('conflict predicate', () => {
  function conflictEpoch(): WitnessEpoch {
    return parsePolicy(
      policy({
        epochs: [
          epoch({
            threshold: { n: 2, m: 1 },
            witnesses: [
              pin({
                operator_id: 'a.example',
                control_group: 'shared.example',
                name: 'a.example/w',
                affiliated_domains: ['a.example', 'vendor.example'],
              }),
              pin({
                operator_id: 'b.example',
                control_group: 'shared.example',
                name: 'b.example/w',
                ed25519_pub_b64u: ED25519_PUB_2,
                affiliated_domains: ['b.example'],
              }),
              pin({
                operator_id: 'c.example',
                control_group: 'c.example',
                name: 'c.example/w',
                ed25519_pub_b64u: ED25519_PUB_2,
                affiliated_domains: ['c.example'],
              }),
            ],
          }),
        ],
      }),
    ).epochs[0]!
  }

  it('detects a direct conflict', () => {
    const e = conflictEpoch()
    expect(isConflicted(e, e.witnesses[0]!, 'vendor.example')).toBe(true)
  })

  it('detects a transitive conflict through a shared control group', () => {
    const e = conflictEpoch()
    expect(isConflicted(e, e.witnesses[1]!, 'vendor.example')).toBe(true)
  })

  it('leaves an unrelated pin unconflicted', () => {
    const e = conflictEpoch()
    expect(isConflicted(e, e.witnesses[2]!, 'vendor.example')).toBe(false)
  })
})

describe('normative constants', () => {
  it('pins the §11.4 values', () => {
    expect(MAX_WITNESS_SKEW_SECONDS).toBe(600)
    expect(MAX_WITNESS_ANCHOR_DELAY_SECONDS).toBe(86400)
    expect(MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE).toBe(9)
  })
})
