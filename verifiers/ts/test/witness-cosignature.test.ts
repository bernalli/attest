// Tests for the cosignature half of src/witness.ts — reachable
// `corroboration: "witnessed"` (v0.2 §9.2, §10.1, P1.1b), plus C2SP
// tlog-cosignature. Mirrors tests/test_witness_cosignature.py case-for-case.
//
// A type-`0x04` blob is `key_id(4) || timestamp(8, big-endian) ||
// signature(64)`; the signed message is `cosignature/v1\n` + `time <POSIX>\n`
// + the checkpoint note body. Fixtures are hand-signed with @noble, the idiom
// transfer.test.ts already established for verification-side modules.
//
// Everything a cosignature can get wrong degrades SILENTLY: §11.4 permits no
// literal from this layer beyond the independence warning.
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { b64uEncode } from '../src/b64u.js'
import { parseCheckpoint, type Checkpoint } from '../src/tlog.js'
// The TS core is verification-only (design §9), so fixtures are signed by the
// shared test builder rather than by the library.
import { signCheckpoint } from './helpers/tlog-builder.js'
import {
  WARN_INDEPENDENCE_NOT_ESTABLISHED,
  cosignatureKeyId,
  cosignatureMessage,
  evaluateCorroboration,
  parsePolicy,
} from '../src/witness.js'

const ORIGIN = 'log.example'
const WITNESS_NAME = 'witness.example/w1'
const TIMESTAMP = 1700000000

const witnessSeed = new Uint8Array(32).fill(7)
const witnessPub = ed25519.getPublicKey(witnessSeed)
const strangerSeed = new Uint8Array(32).fill(9)

function checkpoint(): Checkpoint {
  const edSeed = new Uint8Array(32).fill(1)
  const mldsaSeed = new Uint8Array(32).fill(2)
  const mldsaKeys = ml_dsa65.keygen(mldsaSeed)
  const text = signCheckpoint(
    ORIGIN,
    3,
    new Uint8Array(32),
    {
      edSeed,
      edPub: ed25519.getPublicKey(edSeed),
      mldsaPub: mldsaKeys.publicKey,
      mldsaSecret: mldsaKeys.secretKey,
    },
    ORIGIN,
  )
  return parseCheckpoint(text)
}

function blob(
  cp: Checkpoint,
  seed: Uint8Array = witnessSeed,
  { declared = TIMESTAMP, signed = TIMESTAMP } = {},
): Uint8Array {
  const pub = ed25519.getPublicKey(seed)
  const keyId = cosignatureKeyId(WITNESS_NAME, pub)
  const sig = ed25519.sign(cosignatureMessage(cp.noteBytes, signed), seed)
  const out = new Uint8Array(4 + 8 + 64)
  out.set(keyId, 0)
  new DataView(out.buffer).setBigUint64(4, BigInt(declared), false)
  out.set(sig, 12)
  return out
}

function policyDoc(pubB64u: string, pinOverrides: Record<string, unknown> = {}): unknown {
  return {
    schema: 'attest-witness-policy-v1',
    epochs: [
      {
        epoch_id: 'bootstrap-1',
        not_before: '2020-01-01T00:00:00Z',
        not_after: null,
        log_origins: [ORIGIN],
        threshold: { n: 1, m: 1 },
        witnesses: [
          {
            operator_id: 'witness.example',
            control_group: 'witness.example',
            name: WITNESS_NAME,
            ed25519_pub_b64u: pubB64u,
            mldsa_65_pub_b64u: null,
            roles: ['corroboration'],
            not_before: '2020-01-01T00:00:00Z',
            not_after: null,
            affiliated_domains: ['witness.example'],
            ...pinOverrides,
          },
        ],
      },
    ],
  }
}

const evaluate = (
  cp: Checkpoint,
  sigs: Array<[string, Uint8Array]>,
  doc: unknown,
  epochId = 'bootstrap-1',
) => evaluateCorroboration(cp, sigs, parsePolicy(doc), epochId)

describe('the signed message and the key id', () => {
  it('builds the exact C2SP payload', () => {
    const note = new TextEncoder().encode('log.example\n4\nAAAA\n')
    expect(cosignatureMessage(note, 1679315147)).toEqual(
      new Uint8Array([...new TextEncoder().encode('cosignature/v1\ntime 1679315147\n'), ...note]),
    )
  })

  it('rejects a negative timestamp', () => {
    expect(() => cosignatureMessage(new Uint8Array([1]), -1)).toThrow()
  })
})

describe('reaching witnessed', () => {
  it('accepts one valid pinned cosignature', () => {
    const cp = checkpoint()
    const verdict = evaluate(cp, [[WITNESS_NAME, blob(cp)]], policyDoc(b64uEncode(witnessPub)))
    expect(verdict.witnessed).toBe(true)
    expect(verdict.warnings).toEqual([WARN_INDEPENDENCE_NOT_ESTABLISHED])
  })

  it('skips a line naming someone else without failing', () => {
    const cp = checkpoint()
    const verdict = evaluate(
      cp,
      [['someone.else/x', new Uint8Array(76)], [WITNESS_NAME, blob(cp)]],
      policyDoc(b64uEncode(witnessPub)),
    )
    expect(verdict.witnessed).toBe(true)
  })
})

describe('review regressions (2026-08-25)', () => {
  const withEpoch = (fields: Record<string, unknown>): unknown => {
    const doc = policyDoc(b64uEncode(witnessPub)) as {
      epochs: Array<Record<string, unknown>>
    }
    Object.assign(doc.epochs[0]!, fields)
    return doc
  }

  it('rejects an expired epoch', () => {
    const cp = checkpoint()
    expect(
      evaluate(cp, [[WITNESS_NAME, blob(cp)]], withEpoch({ not_after: '2021-01-01T00:00:00Z' }))
        .witnessed,
    ).toBe(false)
  })

  it('rejects an epoch scoped to another log origin', () => {
    const cp = checkpoint()
    expect(
      evaluate(cp, [[WITNESS_NAME, blob(cp)]], withEpoch({ log_origins: ['other.example'] }))
        .witnessed,
    ).toBe(false)
  })

  it('corroborates nothing under an epoch with no origins', () => {
    // Fail-closed: an empty origin scope is no scope, not every scope.
    const cp = checkpoint()
    expect(evaluate(cp, [[WITNESS_NAME, blob(cp)]], withEpoch({ log_origins: [] })).witnessed).toBe(
      false,
    )
  })

  it('does not let a hostile line veto a later valid one', () => {
    // The attack: prepend garbage under the witness's own name. With one try
    // around the whole scan, that aborted evaluation before the genuine
    // cosignature on the next line was ever examined.
    const cp = checkpoint()
    const hostile = new Uint8Array(76)
    hostile.set(cosignatureKeyId(WITNESS_NAME, witnessPub), 0)
    new DataView(hostile.buffer).setBigUint64(4, 2n ** 64n - 1n, false)
    const verdict = evaluate(
      cp,
      [[WITNESS_NAME, hostile], [WITNESS_NAME, blob(cp)]],
      policyDoc(b64uEncode(witnessPub)),
    )
    expect(verdict.witnessed).toBe(true)
  })

  it.each([253402300800, Number(2n ** 64n - 1n)])(
    'never counts a timestamp past year 9999 (%i)',
    (timestamp) => {
      // Python's datetime stops at 9999, JS Date reaches 275760; without a
      // shared ceiling the same cosignature diverges across the cores.
      const cp = checkpoint()
      const out = new Uint8Array(76)
      out.set(cosignatureKeyId(WITNESS_NAME, witnessPub), 0)
      new DataView(out.buffer).setBigUint64(4, BigInt(timestamp), false)
      const message = new Uint8Array([
        ...new TextEncoder().encode(`cosignature/v1\ntime ${timestamp}\n`),
        ...cp.noteBytes,
      ])
      out.set(ed25519.sign(message, witnessSeed), 12)
      expect(evaluate(cp, [[WITNESS_NAME, out]], policyDoc(b64uEncode(witnessPub))).witnessed).toBe(
        false,
      )
    },
  )
})

describe('everything that must not count', () => {
  it.each([
    ['unpinned key', (cp: Checkpoint) => blob(cp, strangerSeed)],
    ['a timestamp that was not the one signed', (cp: Checkpoint) => blob(cp, witnessSeed, { declared: TIMESTAMP + 1 })],
    ['a short blob', (cp: Checkpoint) => blob(cp).subarray(0, 68)],
    ['a long blob', (cp: Checkpoint) => new Uint8Array([...blob(cp), 0])],
    ['an empty blob', () => new Uint8Array(0)],
  ])('rejects %s', (_label, make) => {
    const cp = checkpoint()
    const verdict = evaluate(cp, [[WITNESS_NAME, make(cp)]], policyDoc(b64uEncode(witnessPub)))
    expect(verdict.witnessed).toBe(false)
    expect(verdict.warnings).toEqual([])
  })

  it('rejects a corrupted signature', () => {
    const cp = checkpoint()
    const bad = blob(cp)
    bad[bad.length - 1] ^= 0xff
    expect(evaluate(cp, [[WITNESS_NAME, bad]], policyDoc(b64uEncode(witnessPub))).witnessed).toBe(
      false,
    )
  })

  it('rejects a checkpoint-domain signature transported into a cosignature', () => {
    // §9.2 domain separation: signing the note body is what the LOG does.
    const cp = checkpoint()
    const out = new Uint8Array(76)
    out.set(cosignatureKeyId(WITNESS_NAME, witnessPub), 0)
    new DataView(out.buffer).setBigUint64(4, BigInt(TIMESTAMP), false)
    out.set(ed25519.sign(cp.noteBytes, witnessSeed), 12)
    expect(evaluate(cp, [[WITNESS_NAME, out]], policyDoc(b64uEncode(witnessPub))).witnessed).toBe(
      false,
    )
  })

  it('rejects a pin without the corroboration role', () => {
    const cp = checkpoint()
    const doc = policyDoc(b64uEncode(witnessPub), {
      roles: ['sunset-activation'],
      mldsa_65_pub_b64u: b64uEncode(new Uint8Array(1952)),
    })
    expect(evaluate(cp, [[WITNESS_NAME, blob(cp)]], doc).witnessed).toBe(false)
  })

  it('rejects an unresolvable epoch', () => {
    const cp = checkpoint()
    expect(
      evaluate(cp, [[WITNESS_NAME, blob(cp)]], policyDoc(b64uEncode(witnessPub)), 'no-such-epoch')
        .witnessed,
    ).toBe(false)
  })

  it('rejects a pin outside its validity window', () => {
    const cp = checkpoint()
    const doc = policyDoc(b64uEncode(witnessPub), { not_after: '2021-01-01T00:00:00Z' })
    expect(evaluate(cp, [[WITNESS_NAME, blob(cp)]], doc).witnessed).toBe(false)
  })

  it('applies the compromise cutoff inclusively', () => {
    const cp = checkpoint()
    const retained = policyDoc(b64uEncode(witnessPub), {
      compromised_after: '2024-01-01T00:00:00Z',
    })
    const excluded = policyDoc(b64uEncode(witnessPub), {
      compromised_after: '2021-01-01T00:00:00Z',
    })
    expect(evaluate(cp, [[WITNESS_NAME, blob(cp)]], retained).witnessed).toBe(true)
    expect(evaluate(cp, [[WITNESS_NAME, blob(cp)]], excluded).witnessed).toBe(false)
  })

  it('never counts a pin whose compromise onset is unknown', () => {
    const cp = checkpoint()
    const doc = policyDoc(b64uEncode(witnessPub), { compromised_after: null })
    expect(evaluate(cp, [[WITNESS_NAME, blob(cp)]], doc).witnessed).toBe(false)
  })

  it('can never reach witnessed under the packaged empty policy', () => {
    const cp = checkpoint()
    const verdict = evaluate(cp, [[WITNESS_NAME, blob(cp)]], {
      schema: 'attest-witness-policy-v1',
      epochs: [],
    })
    expect(verdict.witnessed).toBe(false)
  })

  it('never throws on hostile signature input', () => {
    const cp = checkpoint()
    const doc = policyDoc(b64uEncode(witnessPub))
    for (const sigs of [
      [[WITNESS_NAME, new Uint8Array(0)]],
      [[WITNESS_NAME, new Uint8Array(4096).fill(0xff)]],
      [['', new Uint8Array(76)]],
    ] as Array<Array<[string, Uint8Array]>>) {
      expect(evaluate(cp, sigs, doc).witnessed).toBe(false)
    }
  })
})
