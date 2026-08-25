// Shared fixtures for the activation-grade quorum tests (v0.2 §11.4).
//
// Split out of the test file because the cost contract ("the committee ceiling
// bites before any signature verification") needs a `vi.mock` of the crypto
// modules, and `vi.mock` is file-scoped — the two suites must build identical
// checkpoints, policies and anchors, or the cost claim would be about a
// different artifact than the functional one.
//
// Keys are derived from fixed seeds, never generated: the same fixture has to
// be reproducible when the cross-core parity bench feeds it to both cores.
import { sha256 } from '@noble/hashes/sha2'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { b64uEncode } from '../../src/b64u.js'
import { parseCheckpoint, keyHash } from '../../src/tlog.js'
import type { AnchorPolicy } from '../../src/anchor.js'
import { PQ_COSIGNATURE_SIG_TYPE, cosignatureKeyId } from '../../src/witness.js'
import { signCheckpoint } from './tlog-builder.js'

export const ORIGIN = 'log.example'
// 2023-11-14T22:13:20Z. Every timestamp here is an offset from it, so a reader
// can tell a boundary case from an arbitrary one at a glance.
export const BASE_T = 1700000000
export const HEADER_HASH = '3a'.repeat(32)

export interface TestWitness {
  readonly name: string
  readonly operator: string
  readonly group: string
  readonly edSeed: Uint8Array
  readonly edPub: Uint8Array
  readonly mldsaPub: Uint8Array
  readonly mldsaSecret: Uint8Array
}

export function makeWitness(label: string, seed: number, group?: string): TestWitness {
  const edSeed = new Uint8Array(32).fill(seed)
  const mldsaKeys = ml_dsa65.keygen(new Uint8Array(32).fill(seed + 100))
  const operator = `${label}.example`
  return {
    name: `${operator}/w`,
    operator,
    group: group ?? operator,
    edSeed,
    edPub: ed25519.getPublicKey(edSeed),
    mldsaPub: mldsaKeys.publicKey,
    mldsaSecret: mldsaKeys.secretKey,
  }
}

export const w1 = makeWitness('alpha', 11)
export const w2 = makeWitness('bravo', 12)
export const w3 = makeWitness('charlie', 13)
/** A second key for the SAME control group — a routine key rotation. */
export const w1Rotated: TestWitness = { ...makeWitness('alpha', 14), name: 'alpha.example/w-next' }

const logKeys = (() => {
  const edSeed = new Uint8Array(32).fill(1)
  const mldsaKeys = ml_dsa65.keygen(new Uint8Array(32).fill(2))
  return {
    edSeed,
    edPub: ed25519.getPublicKey(edSeed),
    mldsaPub: mldsaKeys.publicKey,
    mldsaSecret: mldsaKeys.secretKey,
  }
})()

export function baseCheckpoint(treeSize = 4): string {
  return signCheckpoint(ORIGIN, treeSize, new Uint8Array(32), logKeys, ORIGIN)
}

export function noteOf(text: string): Uint8Array {
  return parseCheckpoint(text).noteBytes
}

function toB64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function line(name: string, blob: Uint8Array): string {
  return `— ${name} ${toB64(blob)}\n`
}

/** Built by hand, not through `cosignatureMessage`, so a case can carry a
 * timestamp the helper itself would refuse to sign. */
export function payload(note: Uint8Array, timestamp: number): Uint8Array {
  const head = new TextEncoder().encode(`cosignature/v1\ntime ${timestamp}\n`)
  const out = new Uint8Array(head.length + note.length)
  out.set(head, 0)
  out.set(note, head.length)
  return out
}

interface LegOptions {
  readonly declared?: number
  readonly signedNote?: Uint8Array
  readonly signerSeed?: Uint8Array
  readonly sigType?: Uint8Array
}

export function edLeg(
  w: TestWitness,
  note: Uint8Array,
  timestamp: number,
  options: LegOptions = {},
): Uint8Array {
  const keyId = cosignatureKeyId(w.name, w.edPub)
  const signature = ed25519.sign(
    payload(options.signedNote ?? note, timestamp),
    options.signerSeed ?? w.edSeed,
  )
  const out = new Uint8Array(4 + 8 + 64)
  out.set(keyId, 0)
  new DataView(out.buffer).setBigUint64(4, BigInt(options.declared ?? timestamp), false)
  out.set(signature, 12)
  return out
}

export function pqLeg(
  w: TestWitness,
  note: Uint8Array,
  timestamp: number,
  options: LegOptions = {},
): Uint8Array {
  const keyId = keyHash(w.name, options.sigType ?? PQ_COSIGNATURE_SIG_TYPE, w.mldsaPub)
  const signature = ml_dsa65.sign(payload(options.signedNote ?? note, timestamp), w.mldsaSecret)
  const out = new Uint8Array(4 + 8 + signature.length)
  out.set(keyId, 0)
  new DataView(out.buffer).setBigUint64(4, BigInt(options.declared ?? timestamp), false)
  out.set(signature, 12)
  return out
}

export function pair(
  w: TestWitness,
  note: Uint8Array,
  timestamp: number,
  options: LegOptions = {},
): string {
  return line(w.name, edLeg(w, note, timestamp, options)) + line(w.name, pqLeg(w, note, timestamp, options))
}

export function pinDoc(w: TestWitness, overrides: Record<string, unknown> = {}): unknown {
  return {
    operator_id: w.operator,
    control_group: w.group,
    name: w.name,
    ed25519_pub_b64u: b64uEncode(w.edPub),
    mldsa_65_pub_b64u: b64uEncode(w.mldsaPub),
    roles: ['sunset-activation'],
    not_before: '2020-01-01T00:00:00Z',
    not_after: null,
    affiliated_domains: [w.operator],
    ...overrides,
  }
}

export function policyDoc(
  pins: unknown[],
  threshold: { n: number; m: number },
  epochOverrides: Record<string, unknown> = {},
): unknown {
  return {
    schema: 'attest-witness-policy-v1',
    epochs: [
      {
        epoch_id: 'bootstrap-1',
        not_before: '2020-01-01T00:00:00Z',
        not_after: null,
        log_origins: [ORIGIN],
        threshold,
        witnesses: pins,
        ...epochOverrides,
      },
    ],
  }
}

/** A verifying OTS op-chain over this exact checkpoint, plus its trust store.
 *
 * The v2 seed is `SHA256(signedNoteBytes)` — the WHOLE note, cosignature lines
 * included — which is why the anchor has to be built after the lines are
 * appended, never before. */
export function anchorFor(
  checkpointText: string,
  headerTime: number,
  profile: string | null = 'signed-note-v2',
): { evidence: Record<string, unknown>; policy: AnchorPolicy } {
  const checkpoint = parseCheckpoint(checkpointText)
  const seedSource =
    profile === 'signed-note-v2' ? checkpoint.signedNoteBytes : checkpoint.noteBytes
  const sibling = new Uint8Array(32).fill(0xab)
  const prefix = new Uint8Array(16).fill(0xcd)
  let acc = sha256(seedSource)
  acc = sha256(concat(acc, sibling))
  acc = sha256(concat(prefix, acc))
  const root = hex(acc)
  const evidence: Record<string, unknown> = {
    checkpoint: checkpointText,
    proofs: [
      {
        kind: 'ots',
        ops: [['append', hex(sibling)], ['sha256'], ['prepend', hex(prefix)], ['sha256']],
        header_merkle_root: root,
        header_time: headerTime,
        header_hash: HEADER_HASH,
      },
    ],
  }
  if (profile !== null) evidence['anchor_profile'] = profile
  const policy: AnchorPolicy = {
    pinnedHeaders: {
      [HEADER_HASH]: { headerHash: HEADER_HASH, merkleRoot: root, time: headerTime },
    },
    crqcHorizon: null,
  }
  return { evidence, policy }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}
