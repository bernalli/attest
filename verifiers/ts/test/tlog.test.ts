// RFC 6962 Merkle-tree verification primitives + closed transparency-log
// entry schemas + C2SP hybrid signed-note checkpoints — mirrors
// tests/test_tlog.py (Python reference) one-for-one for every VERIFICATION
// path. Builder-only Python tests (build_tree/inclusion_proof/
// consistency_proof/sign_checkpoint round-trips, the builder's own KATs) are
// intentionally NOT ported: this TS port ships verify-only (see tlog.ts's
// module comment) and has no builder to round-trip against.
//
// Fixtures needing real Merkle-tree construction or hybrid checkpoint
// signing were generated ONCE by a throwaway script pairing the compiled TS
// `leafHash`/`nodeHash`/`encodeEntry` with a Python one-off
// (`tlog.sign_checkpoint`, run via `PYTHONPATH=src .venv/bin/python`) for the
// signature legs — TS ships no signing/building API, so the hybrid
// signatures below are cross-language ground truth, not self-verifying. The
// two hybrid keys used throughout (`HK_A`, `HK_C`) come from fixed Ed25519
// seeds (`21`/`99`, all-bytes-equal) plus a freshly generated ML-DSA-65
// keypair each (pq.generate() has no public deterministic-seed API) —
// non-determinism there doesn't matter since only the resulting PUBLIC keys
// and signatures are ever hardcoded here.
import { describe, it, expect } from 'vitest'
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2'
import { ed25519 } from '@noble/curves/ed25519'
import { canonicalBytes } from '../src/canon.js'
import {
  leafHash,
  nodeHash,
  verifyInclusion,
  verifyConsistency,
  encodeEntry,
  parseCheckpoint,
  verifyCheckpoint,
  receiptCoreHash,
  keyHash,
  TlogError,
  LogKey,
  MAX_ENTRY_SCALAR_LEN_,
  MAX_NOTE_TEXT_LEN_,
} from '../src/tlog.js'

const enc = new TextEncoder()
const h = (hex: string) => hexToBytes(hex)
const hh = (arr: string[]) => arr.map(h)

// --------------------------------------------------------------------------
// Known-answer tests, hand-computed from RFC 6962 §2.1 (copied verbatim from
// test_tlog.py's own comments — these are independent hand derivations, not
// values round-tripped through any build_tree implementation):
//   leaf_hash(d)    = SHA-256(0x00 || d)
//   node_hash(l, r) = SHA-256(0x01 || l || r)
// --------------------------------------------------------------------------

describe('leafHash / nodeHash', () => {
  it('matches the RFC 6962 leaf-hash prefix scheme', () => {
    expect(leafHash(Uint8Array.of(0x00))).toEqual(sha256(Uint8Array.of(0x00, 0x00)))
  })

  it('matches the RFC 6962 node-hash prefix scheme', () => {
    const left = leafHash(Uint8Array.of(0x00))
    const right = leafHash(Uint8Array.of(0x01))
    expect(nodeHash(left, right)).toEqual(sha256(new Uint8Array([0x01, ...left, ...right])))
  })

  it('one-leaf tree root KAT (leaf_hash(0x00))', () => {
    expect(leafHash(Uint8Array.of(0x00))).toEqual(
      h('96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7'),
    )
  })
})

// --------------------------------------------------------------------------
// Inclusion proof: round-trip over the 7-leaf tree LEAVES = 0x00..0x06.
// Root + per-index proofs generated once (see module comment); this table
// pins the same fixture Python's exhaustive round-trip test builds via its
// own build_tree/inclusion_proof.
// --------------------------------------------------------------------------

const ROOT7 = h('3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3')
const LEAVES7 = Array.from({ length: 7 }, (_, i) => Uint8Array.of(i))
const INCLUSION_PROOFS_7: string[][] = [
  ['b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2', '52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb'],
  ['96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', '52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb'],
  ['583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb'],
  ['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb'],
  ['9f1afa4dc124cba73134e82ff50f17c8f7164257c79fed9a13f5943a6acb8e3d', '40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd', '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb'],
  ['4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4', '40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd', '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb'],
  ['4b8c129ed14cce2c08cfc6766db7f8cdb133b5f698b8de3d5890ea7ff7f0a8d1', '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb'],
]

describe('verifyInclusion', () => {
  it.each(LEAVES7.map((_, i) => i))('verifies the real proof for every index of the 7-leaf tree (index %i)', (i) => {
    const proof = hh(INCLUSION_PROOFS_7[i]!)
    const leaf = leafHash(LEAVES7[i]!)
    expect(verifyInclusion(leaf, BigInt(i), 7n, proof, ROOT7)).toBe(true)
  })

  it('single-leaf tree: empty proof verifies against the leaf hash itself', () => {
    const root = leafHash(LEAVES7[0]!)
    expect(verifyInclusion(leafHash(LEAVES7[0]!), 0n, 1n, [], root)).toBe(true)
  })

  it('fails on wrong root', () => {
    const proof = hh(INCLUSION_PROOFS_7[3]!)
    expect(verifyInclusion(leafHash(LEAVES7[3]!), 3n, 7n, proof, new Uint8Array(32))).toBe(false)
  })

  it('fails on wrong index', () => {
    const proof = hh(INCLUSION_PROOFS_7[3]!)
    expect(verifyInclusion(leafHash(LEAVES7[3]!), 2n, 7n, proof, ROOT7)).toBe(false)
  })

  it('fails on a truncated proof', () => {
    const proof = hh(INCLUSION_PROOFS_7[3]!)
    expect(proof.length).toBeGreaterThan(0) // sanity: index 3 of a 7-leaf tree has a non-empty path
    expect(verifyInclusion(leafHash(LEAVES7[3]!), 3n, 7n, proof.slice(0, -1), ROOT7)).toBe(false)
  })

  it('fails on an oversized proof', () => {
    const proof = hh(INCLUSION_PROOFS_7[3]!)
    const bogus = [...proof, new Uint8Array(32)]
    expect(verifyInclusion(leafHash(LEAVES7[3]!), 3n, 7n, bogus, ROOT7)).toBe(false)
  })

  it('fails closed on malformed shapes', () => {
    const leaf = leafHash(LEAVES7[0]!)
    const proof = hh(INCLUSION_PROOFS_7[0]!)
    expect(verifyInclusion(leaf, -1n, 7n, proof, ROOT7)).toBe(false)
    expect(verifyInclusion(leaf, 0n, 0n, proof, ROOT7)).toBe(false)
    expect(verifyInclusion(leaf, 99n, 7n, proof, ROOT7)).toBe(false)
    expect(verifyInclusion(leaf, 0n, 7n, [enc.encode('short')], ROOT7)).toBe(false) // not 32 bytes
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(verifyInclusion(leaf, 0n, 7n, ['not-bytes'] as any, ROOT7)).toBe(false)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(verifyInclusion(leaf, '0' as any, 7n, proof, ROOT7)).toBe(false)
  })

  it.each([enc.encode('x'), new Uint8Array(33).fill(120)])(
    'rejects a short or long leaf/root (both = the same malformed digest)',
    (malformed) => {
      expect(verifyInclusion(malformed, 0n, 1n, [], malformed)).toBe(false)
    },
  )
})

// --------------------------------------------------------------------------
// Consistency proof: round-trip for every (size1, size2 <= 7) pair —
// mirrors test_consistency_round_trip_every_size_pair_up_to_seven_leaves.
// --------------------------------------------------------------------------

const CONSISTENCY_PAIRS: Array<[number, string, number, string, string[]]> = [
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', []],
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', []],
  [1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', []],
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', []],
  [1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', ['b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2']],
  [2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', 2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', []],
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', []],
  [1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', ['b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2', 'fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f']],
  [2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', 3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', ['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f']],
  [3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', 3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', []],
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', []],
  [1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', ['b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2', '52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825']],
  [2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', 4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', ['52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825']],
  [3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', 4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', ['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f', '583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a']],
  [4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', 4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', []],
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', []],
  [1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', ['b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2', '52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4']],
  [2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', 5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', ['52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4']],
  [3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', 5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', ['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f', '583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', '4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4']],
  [4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', 5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', ['4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4']],
  [5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', 5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', []],
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', []],
  [1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', ['b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2', '52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '4b8c129ed14cce2c08cfc6766db7f8cdb133b5f698b8de3d5890ea7ff7f0a8d1']],
  [2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', 6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', ['52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '4b8c129ed14cce2c08cfc6766db7f8cdb133b5f698b8de3d5890ea7ff7f0a8d1']],
  [3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', 6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', ['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f', '583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', '4b8c129ed14cce2c08cfc6766db7f8cdb133b5f698b8de3d5890ea7ff7f0a8d1']],
  [4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', 6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', ['4b8c129ed14cce2c08cfc6766db7f8cdb133b5f698b8de3d5890ea7ff7f0a8d1']],
  [5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', 6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', ['4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4', '9f1afa4dc124cba73134e82ff50f17c8f7164257c79fed9a13f5943a6acb8e3d', '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb']],
  [6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', 6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', []],
  [0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', []],
  [1, '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', ['b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2', '52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb']],
  [2, 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', ['52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb']],
  [3, '3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', ['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f', '583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb']],
  [4, '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', ['89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb']],
  [5, 'b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', ['4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4', '9f1afa4dc124cba73134e82ff50f17c8f7164257c79fed9a13f5943a6acb8e3d', '40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd', '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb']],
  [6, 'bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', ['4b8c129ed14cce2c08cfc6766db7f8cdb133b5f698b8de3d5890ea7ff7f0a8d1', '40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd', '9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb']],
  [7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', 7, '3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3', []],
]

describe('verifyConsistency', () => {
  it.each(CONSISTENCY_PAIRS)('round-trips for every (size1, size2) pair up to 7 leaves: %i -> %i', (size1, root1Hex, size2, root2Hex, proofHex) => {
    expect(verifyConsistency(BigInt(size1), h(root1Hex), BigInt(size2), h(root2Hex), hh(proofHex))).toBe(true)
  })

  it('fails on cross-tree roots', () => {
    const root1 = h('3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688') // size 3
    const root2 = ROOT7 // size 7
    const wrongRoot2 = h('bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8') // size 6
    const proof = hh(['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f', '583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb'])
    expect(verifyConsistency(3n, root1, 7n, root2, proof)).toBe(true)
    expect(verifyConsistency(3n, root1, 7n, wrongRoot2, proof)).toBe(false)
    const wrongRoot1 = h('a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a') // size 2
    expect(verifyConsistency(3n, wrongRoot1, 7n, root2, proof)).toBe(false)
  })

  it('fails closed on malformed shapes', () => {
    const root1 = h('3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688')
    const root2 = ROOT7
    const proof = hh(['fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f', '583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d', 'a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a', '89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb'])
    expect(verifyConsistency(7n, root2, 3n, root1, proof)).toBe(false) // size1 > size2
    expect(verifyConsistency(3n, root1, 7n, root2, proof.slice(0, -1))).toBe(false) // truncated
    expect(verifyConsistency(3n, root1, 7n, root2, [...proof, new Uint8Array(32)])).toBe(false) // oversized
    expect(verifyConsistency(3n, root1, 7n, root2, [enc.encode('short')])).toBe(false) // not 32 bytes
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(verifyConsistency('3' as any, root1, 7n, root2, proof)).toBe(false)
  })

  it.each([enc.encode('x'), new Uint8Array(33).fill(120)])('rejects a short or long root', (malformed) => {
    expect(verifyConsistency(1n, malformed, 1n, malformed, [])).toBe(false)
    expect(verifyConsistency(0n, malformed, 1n, malformed, [])).toBe(false)
  })

  it('empty old tree is vacuously true', () => {
    const root2 = h('b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f') // size 5
    expect(verifyConsistency(0n, new Uint8Array(32), 5n, root2, [])).toBe(true)
  })

  it('equal sizes requires a matching root and empty proof', () => {
    const root = h('9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb') // size 4
    expect(verifyConsistency(4n, root, 4n, root, [])).toBe(true)
    expect(verifyConsistency(4n, root, 4n, root, [new Uint8Array(32)])).toBe(false)
    expect(verifyConsistency(4n, root, 4n, new Uint8Array(32), [])).toBe(false)
  })
})

// --------------------------------------------------------------------------
// encodeEntry: closed schemas.
// --------------------------------------------------------------------------

function validKeyManifestEntry(): Record<string, unknown> {
  return { type: 'key-manifest', issuer: 'shop.example.com', manifest_version: 1, manifest_sha256: 'a'.repeat(64) }
}
function validReceiptEntry(): Record<string, unknown> {
  return { type: 'receipt', issuer: 'shop.example.com', core_sha256: 'b'.repeat(64) }
}
function validRevocationRecordEntry(): Record<string, unknown> {
  return { type: 'revocation-record', issuer: 'shop.example.com', record_sha256: 'c'.repeat(64) }
}
function validTransferRecordEntry(): Record<string, unknown> {
  return { type: 'transfer-record', issuer: 'shop.example.com', record_sha256: 'd'.repeat(64) }
}
function validCessationDeclarationEntry(): Record<string, unknown> {
  return { type: 'cessation-declaration', issuer: 'pub.example', record_sha256: 'e'.repeat(64) }
}
function validPublisherAuthorizationEntry(): Record<string, unknown> {
  return { type: 'publisher-authorization', issuer: 'pub.example', record_sha256: 'f'.repeat(64) }
}

describe('encodeEntry', () => {
  it('accepts a valid key-manifest entry and round-trips through canonicalBytes', () => {
    const entry = validKeyManifestEntry()
    const encoded = encodeEntry(entry)
    expect(encoded).toBeInstanceOf(Uint8Array)
    const expectedJson = '{"issuer":"shop.example.com","manifest_sha256":"' + 'a'.repeat(64) + '","manifest_version":1,"type":"key-manifest"}'
    expect(new TextDecoder().decode(encoded)).toBe(expectedJson)
  })

  it('accepts a valid receipt entry', () => {
    expect(encodeEntry(validReceiptEntry())).toBeInstanceOf(Uint8Array)
  })

  it('accepts a valid revocation-record entry (G5)', () => {
    const entry = validRevocationRecordEntry()
    const encoded = encodeEntry(entry)
    expect(encoded).toBeInstanceOf(Uint8Array)
    const expectedJson = '{"issuer":"shop.example.com","record_sha256":"' + 'c'.repeat(64) + '","type":"revocation-record"}'
    expect(new TextDecoder().decode(encoded)).toBe(expectedJson)
  })

  it('rejects a revocation-record entry missing a member', () => {
    const entry = validRevocationRecordEntry()
    delete entry.record_sha256
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a revocation-record entry with an extra member', () => {
    const entry = { ...validRevocationRecordEntry(), receipt_id: '01J1V5B4M9Z8QWERTY12345678' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a revocation-record entry with uppercase hex', () => {
    const entry = { ...validRevocationRecordEntry(), record_sha256: 'C'.repeat(64) }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('accepts a valid transfer-record entry (v0.2 §17.1, Stage 3)', () => {
    const entry = validTransferRecordEntry()
    const encoded = encodeEntry(entry)
    expect(encoded).toBeInstanceOf(Uint8Array)
    const expectedJson = '{"issuer":"shop.example.com","record_sha256":"' + 'd'.repeat(64) + '","type":"transfer-record"}'
    expect(new TextDecoder().decode(encoded)).toBe(expectedJson)
  })

  it('rejects a transfer-record entry missing a member', () => {
    const entry = validTransferRecordEntry()
    delete entry.record_sha256
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a transfer-record entry with an extra member', () => {
    const entry = { ...validTransferRecordEntry(), receipt_id: '01J1V5B4M9Z8QWERTY12345678' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a transfer-record entry with uppercase hex', () => {
    const entry = { ...validTransferRecordEntry(), record_sha256: 'D'.repeat(64) }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('accepts a valid cessation-declaration entry (v0.2 §8/§18.4, Stage 4)', () => {
    const entry = validCessationDeclarationEntry()
    const encoded = encodeEntry(entry)
    expect(encoded).toBeInstanceOf(Uint8Array)
    const expectedJson = '{"issuer":"pub.example","record_sha256":"' + 'e'.repeat(64) + '","type":"cessation-declaration"}'
    expect(new TextDecoder().decode(encoded)).toBe(expectedJson)
  })

  it('accepts a valid publisher-authorization entry (v0.2 §8/§20.2)', () => {
    const entry = validPublisherAuthorizationEntry()
    const encoded = encodeEntry(entry)
    expect(encoded).toBeInstanceOf(Uint8Array)
    const expectedJson = '{"issuer":"pub.example","record_sha256":"' + 'f'.repeat(64) + '","type":"publisher-authorization"}'
    expect(new TextDecoder().decode(encoded)).toBe(expectedJson)
  })

  // Mirrors the six negatives tests/test_tlog.py already has for this entry
  // type: a closed schema is only as good as the cases that prove it closed.
  it('rejects a publisher-authorization entry missing a member', () => {
    const entry = validPublisherAuthorizationEntry()
    delete entry.record_sha256
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a publisher-authorization entry with an extra member', () => {
    expect(() => encodeEntry({ ...validPublisherAuthorizationEntry(), extra: 1 })).toThrow(TlogError)
  })

  it('rejects a publisher-authorization entry whose digest is not 64 lowercase hex', () => {
    for (const record_sha256 of ['f'.repeat(63), 'F'.repeat(64), 1, null]) {
      expect(() => encodeEntry({ ...validPublisherAuthorizationEntry(), record_sha256 })).toThrow(TlogError)
    }
  })

  it('rejects a publisher-authorization entry whose issuer is not a lowercase DNS name', () => {
    for (const issuer of ['Pub.Example', '', null, 42]) {
      expect(() => encodeEntry({ ...validPublisherAuthorizationEntry(), issuer })).toThrow(TlogError)
    }
  })

  it('rejects a cessation-declaration entry missing a member', () => {
    const entry = validCessationDeclarationEntry()
    delete entry.record_sha256
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a cessation-declaration entry with an extra member', () => {
    const entry = { ...validCessationDeclarationEntry(), declared_at: '2031-03-01T00:00:00Z' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a cessation-declaration entry with uppercase hex', () => {
    const entry = { ...validCessationDeclarationEntry(), record_sha256: 'E'.repeat(64) }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a cessation-declaration entry whose issuer is not a lowercase DNS name', () => {
    const entry = { ...validCessationDeclarationEntry(), issuer: 'Pub.Example' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('accepts an at-bound scalar', () => {
    const entry = { ...validReceiptEntry(), issuer: 'a.'.repeat((MAX_ENTRY_SCALAR_LEN_ - 2) / 2) + 'aa' }
    expect(entry.issuer).toHaveLength(MAX_ENTRY_SCALAR_LEN_)
    expect(encodeEntry(entry)).toBeInstanceOf(Uint8Array)
  })

  it('rejects an over-bound scalar with the Python-parity literal', () => {
    const entry = { ...validReceiptEntry(), issuer: 'a'.repeat(MAX_ENTRY_SCALAR_LEN_ + 1) }
    expect(() => encodeEntry(entry)).toThrow(`entry scalar exceeds ${MAX_ENTRY_SCALAR_LEN_} chars`)
  })

  it('rejects an unknown type', () => {
    const entry = { ...validReceiptEntry(), type: 'bogus' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects an extra member', () => {
    const entry = { ...validReceiptEntry(), extra_field: 'nope' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a missing member', () => {
    const entry = validReceiptEntry()
    delete entry['issuer']
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects uppercase hex', () => {
    const entry = { ...validReceiptEntry(), core_sha256: 'B'.repeat(64) }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a non-int manifest_version', () => {
    const entry = { ...validKeyManifestEntry(), manifest_version: '1' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects manifest_version below 1', () => {
    const entry = { ...validKeyManifestEntry(), manifest_version: 0 }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('accepts the largest JCS-safe manifest_version (2**53 - 1)', () => {
    const entry = { ...validKeyManifestEntry(), manifest_version: 2 ** 53 - 1 }
    expect(encodeEntry(entry)).toBeInstanceOf(Uint8Array)
  })

  it('rejects manifest_version above the JCS limit (2**53)', () => {
    const entry = { ...validKeyManifestEntry(), manifest_version: 2 ** 53 }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a bool manifest_version', () => {
    const entry = { ...validKeyManifestEntry(), manifest_version: true }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects uppercase issuer', () => {
    const entry = { ...validReceiptEntry(), issuer: 'Shop.Example.com' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects issuer with a trailing newline', () => {
    const entry = { ...validReceiptEntry(), issuer: 'shop.example.com\n' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects a non-object entry', () => {
    expect(() => encodeEntry([])).toThrow(TlogError)
  })

  it('rejects short hex', () => {
    const entry = { ...validReceiptEntry(), core_sha256: 'b'.repeat(63) }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects manifest_sha256 with a trailing newline', () => {
    const entry = { ...validKeyManifestEntry(), manifest_sha256: 'a'.repeat(64) + '\n' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })

  it('rejects core_sha256 with a trailing newline', () => {
    const entry = { ...validReceiptEntry(), core_sha256: 'b'.repeat(64) + '\n' }
    expect(() => encodeEntry(entry)).toThrow(TlogError)
  })
})

// --------------------------------------------------------------------------
// Hybrid signed-note checkpoints: parseCheckpoint / verifyCheckpoint.
// --------------------------------------------------------------------------

const ORIGIN = 'log.attest.example/2026'
const LOG_NAME = 'attest-log-1'
const ROOT = sha256(enc.encode('checkpoint-test-root'))

// hkA: fixed ed25519 seed (all bytes = 21) + a freshly-generated ML-DSA-65
// keypair, hybrid-signed a checkpoint (ORIGIN, tree_size=5, ROOT) via the
// Python one-off (see module comment).
const HK_A_ED_PUB = h('d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da')
const HK_A_MLDSA_PUB = h(
  '865561f15c22b0943687f09a751ad91f4f9c37bb311cc2d2bd1edbe66d7e857cbc9beba40a7bba0512f1829e1fb2fd50b75542a5337f828a61d2142c6cca91a24aab6c1adafeccdb4cb69949034f76c34878c84faee9bdf067768ddd60ac9f87e246e1046920a295ac0925f334b689791eb964a044c5a58154ebb1c34c8f877f1853fdeb86e64d6d4d6988ae9ff119c00704a7d16fe996ce22534e28076a61f968f4bf07a78feba64a95eedb02f8be818474ee2742a57a5da5dec6c06e030448bf1eaaf6331a1bac1cd5a92464487d117d7d6750c2907414eeb0a25b877120b1a8782bf8e4739c10fec182a5f7427cca97188ee03b32b621b3c8cee7380dd8ace42edda975d41f996991991b003a9ac99163f0304b46ee033d1b9d3e3edbe93f5db121b95fdd7a11cba473f9993e8ea6c929c15dff7129d7fc911167719512373285ebea283361008bd9c34cbc8dcd3273ebf4c41c0c1211b845c83fa4b69f4bd4529a4ccabb50ea6c5aa661c72d71004aceeb6dd388c52c06deaebd6d6254546270fcf090f3db0956353ad9ddaeb4417593e20f74340815691275795cde85aace7dc2a48a8f6527339398b6e4f118c9da426e7804736887553babc503eacd56dcf115d71a1ec943a835d89ca647c9d994282cab7b5feccd990cf633525bef9f2cd64b7ba18239de09278bb40495a6c66a6bd2e2eba615411a59a4506a4528f5bfe8e7ecd8deda90910996b490330ee531bf84d1997fe6c7747654e8d897af1dad402c5cc2573f3ab79fbd987dba5e733541734e67b241002a36ee047027039a78865e3e11741cc5e30c24d74a785898e9106a7c83b4dcc63f353d8a0990c30fb4be22eb61c0f983a787c10e945ee9ef04fae6082444a0a13b744c10db2ba1dec728648d6f80843bf2b2640b4979fd0d94f79de267e77dfa36b155d90d021848b92cb2089d8c85a0dbc5a29842139bf48907f537e6e3c84dae3f4174f6616c12112a8be84f7e572ba2f42d2cb9f3a0e92650c849fcc32e2704f67850e0841e47218dd424960071955fbad1cf789daadb2d29b2bc1d5da1bc5a6ff49afe4b2d3240cd5011191c43fbbfb917bef75de1c94ab212fab9dea765d1a25a8545f50eaa8be8e854aebe9e00f33757f377c7ef3759efddaafe785095f8839977e1ceed5f7791aa867ef9926b76cd3cab17b2c4d32447e3e3904f970ad5117cc311bfd52fd0275410ab3d65c36e67e60d4dfb3a8845e6d92784461884e5451ed3d6acbdff149c309fcd538dc1259b75dfb34ef2940de1a31e57394f109c1155a3afa2652628b294575239ce8d10d1c7e78d67ed17daaa74edc84c71c6a59de63e8df0beb2018c20cb87f7641c6320d2df4117c5a33a00d825b195760f7a312586f40f3a8d8683ee39e1421b3969f0f880586d323aa4b8c5738f89565b98d79e4f78d6c1301c600951fd032845a222cdd365e3dc6cacc0a9939a17f45480f98c810570b5ce2abe52a8fb10d7737f74d2f05b9bed14b87e793e35349cdda23025211fb2ff6730c73f18283793d93b007da3c94948d90d6a6b1afc58ae421d351eb024f20c918756769f1a61fd0b0696c524aa6024e66508635a58957770bf33992b1fe72f06d78b4ecda540cb9d16105c19d2de36ec87cfd874803589c9966c246baebb60f081981673859d0901891acea5ec0c95df1f6d4028cc91651f809e281fc2f20f0ca70e97f2bff70c3bf973293f535da0f182a6ad777092e9182a93ae3d1209f06073ae780bac773395f2f23e1785e2859f11b8ec95a14f20053e5198724aff072aceb24ea1408fc13c3eda4b4bc16ce881cfe890b09f2e2365ad44624f4770fc1bb8dcad3add264476e260498be9c010079aa6e4d8ee26974b43499eae8d9ca612c19e911612ced05a95d46322384d606ff169ff444ca3fc7c0b5c306ec86f3a58a7e53cffecc85685014fa099a51ff3605408ed7e86a016db8f92e5eb975f7917715298415a6efcf5026c770744966a03b2297bddfed091eeaa92e2e2f08e775f16e34c671bb8cb3a129fc0977619038c77924652625ab7f0be6a740fd8ea482cdf38a01341afa595128351e697a4dea07c03391c15ffcd23e8028f5327650e6eb11c381f94a49e0336314ec28930df314c86aad871aab1a3795a0141f5f91e48908cbcd1a8cbd63d11ecca2c45fc818306636b06db3d677995a8d5f5bb43115be9d1d58f023ac9d6569ef45a304c4acf60ec52250cf085ec36591205c1256a729d9848bded9136c06de0088829abaa308f96343b5b1b51295ddef79ec3ae4435c91eba98026ddf994fdc97895c970835e86ff47a7bdaf36725065899ed084b4a2b90b278f81388d85e431bf16daa6cc0ea808c2752bf16099a9c8cecf03072e17775be0827e3228fb07bb3d694e455067e8194b9c04ceb966d116b5791596c653fe65c42d2ab18d2d0273fa22022e10b2402708a1b88b3f1c55b9baf49c7f9056ada9b133331181202048e53bd0b1399f023f3972161625ea4202acd9b7b26c5b5facf81de4eb83c884a8291e258cc695078e88507ab9133971b11d73729623b2c77bac9ffc6df397b2f5eeb520e26d2962905351850b3cc2b4b1c150a8d3eeee85874960858d53cb35a5da73da532f9ce9f02e0c92d904f6554f293388835cd55c58faa47a670ce83f499cfeb6f4fe2ef5e6b6758ea15a00e7e2a07a479ae7f6d90b6cd85c894a0dd16a739b71aa7ac710112cb55c86ab27d351df087dc3a3a',
)
const CP_FIXTURE_BASE = 'log.attest.example/2026\n5\nemIYuNgZ/Y+hYWxHkK1vxxW0BjjPvBuXMN4fuGt6+Cs=\n\n— attest-log-1 roJk5JF7sicA8VHVGXvVKNs6l+PbseF6tJ182XGnv9i1nfxdZ7ebLJbEFmrn6JpbO25+KmVsYbIe40n6L/bzDg6KfAg=\n— attest-log-1 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\n'

const HK_A: LogKey = { origin: ORIGIN, name: LOG_NAME, ed25519Pub: HK_A_ED_PUB, mldsaPub: HK_A_MLDSA_PUB }

function corruptLine(text: string, index: number, newLine: string): string {
  const lines = text.split('\n')
  lines[index] = newLine
  return lines.join('\n')
}

describe('parseCheckpoint (structural validation only)', () => {
  it('round-trips origin/tree_size/root/note_bytes', () => {
    const checkpoint = parseCheckpoint(CP_FIXTURE_BASE)
    expect(checkpoint.origin).toBe(ORIGIN)
    expect(checkpoint.treeSize).toBe(5n)
    expect(checkpoint.root).toEqual(ROOT)
    const expectedNote = `${ORIGIN}\n5\n${btoa(String.fromCharCode(...ROOT))}\n`
    expect(new TextDecoder().decode(checkpoint.noteBytes)).toBe(expectedNote)
  })

  it('rejects zero signature lines', () => {
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it.each(['', 'bad\x1forigin', 'bad\x7forigin'])('rejects an empty or control-character origin (%s)', (origin) => {
    const text = `${origin}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it.each([
    ['zero-width format', 'bad\u200borigin'],
    ['private-use', 'bad\ue000origin'],
    ['non-breaking space', 'bad\u00a0origin'],
    ['line separator', 'bad\u2028origin'],
  ])('rejects Unicode-category origins under the ASCII grammar (%s)', (_category, origin) => {
    const text = `${origin}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('accepts a printable ASCII origin containing a space', () => {
    const origin = 'plain space'
    const text = `${origin}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(parseCheckpoint(text).origin).toBe(origin)
  })

  it.each(['🎉', '漢', '\u{2ebf0}'])('rejects a non-ASCII origin for version-independent grammar (%s)', (origin) => {
    // Stage-2 note grammar is printable ASCII, not Unicode-category based:
    // cross-core verdicts therefore never depend on a host Unicode database.
    const text = `${origin}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a missing blank line', () => {
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\nnot-blank\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a two-line body (root line missing)', () => {
    const text = `${ORIGIN}\n3\n\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a non-decimal size', () => {
    const text = `${ORIGIN}\nfive\n${btoa(String.fromCharCode(...ROOT))}\n\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a negative size', () => {
    const text = `${ORIGIN}\n-3\n${btoa(String.fromCharCode(...ROOT))}\n\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a leading-zero size', () => {
    const text = `${ORIGIN}\n01\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('accepts the uint64 max size (2**64 - 1)', () => {
    const text = `${ORIGIN}\n${(2n ** 64n - 1n).toString()}\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(parseCheckpoint(text).treeSize).toBe(2n ** 64n - 1n)
  })

  it('rejects a uint64 overflow size (2**64)', () => {
    const text = `${ORIGIN}\n${(2n ** 64n).toString()}\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects an oversized decimal size (5000 digits)', () => {
    const hugeSize = '9'.repeat(5000)
    const text = `${ORIGIN}\n${hugeSize}\n${btoa(String.fromCharCode(...ROOT))}\n\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a root that is not 32 bytes once decoded', () => {
    const shortRootB64 = btoa(String.fromCharCode(...new Uint8Array(31)))
    const text = `${ORIGIN}\n3\n${shortRootB64}\n\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a bad base64 root', () => {
    const text = `${ORIGIN}\n3\nnot-valid-base64!!\n\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects text missing its trailing newline', () => {
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n`
    expect(() => parseCheckpoint(text.slice(0, -1))).toThrow(TlogError)
  })

  it('rejects a malformed signature line', () => {
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\nnot-a-signature-line\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a signature line with a plain hyphen instead of the em dash', () => {
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n- ${LOG_NAME} ${btoa(String.fromCharCode(...new Uint8Array(68)))}\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it.each([
    'bad name',
    'bad+name',
    'bad\tname',
    'bad\x1fname',
    'bad\u200bname',
    'bad\ue000name',
    'bad\u00a0name',
    'bad\u2028name',
    '🎉',
    '漢',
    '\u{2ebf0}',
  ])('rejects an invalid C2SP signature name (%s)', (name) => {
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${name} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a lone surrogate in the origin', () => {
    const text = `bad\ud800origin\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects more than 64 signature lines', () => {
    const signature = `— ${LOG_NAME} ${btoa(String.fromCharCode(...new Uint8Array(68)))}\n`
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n` + signature.repeat(65)
    expect(() => parseCheckpoint(text)).toThrow(TlogError)
  })

  it('rejects a non-string input', () => {
    expect(() => parseCheckpoint(enc.encode('not-a-str'))).toThrow(TlogError)
  })

  it('rejects too many lines before splitting (zero-allocation newline-count guard)', () => {
    const text = '\n'.repeat(69) // MAX_NOTE_LINES (68) + 1
    expect(() => parseCheckpoint(text)).toThrow(/too many lines \(max 68\)/)
  })

  it('rejects an oversized note text before splitting', () => {
    const text = 'x'.repeat(500_001) + '\n' // MAX_NOTE_TEXT_LEN + 1
    let threw = false
    try {
      parseCheckpoint(text)
    } catch (e) {
      threw = true
      expect(e).toBeInstanceOf(TlogError)
      expect((e as Error).message).toContain('500000')
      expect((e as Error).message.length).toBeLessThan(200)
    }
    expect(threw).toBe(true)
  })

  it('counts checkpoint-text caps by Unicode code points, not UTF-16 units', () => {
    const suffix = `\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    const withinCap = '🎉'.repeat(MAX_NOTE_TEXT_LEN_ - suffix.length) + suffix
    expect(withinCap.length).toBeGreaterThan(MAX_NOTE_TEXT_LEN_)
    // It reaches the ASCII-origin grammar, rather than being rejected by the
    // cap: the cap still counts Python-style code points before validation.
    expect(() => parseCheckpoint(withinCap)).toThrow('origin must be a non-empty printable ASCII str')

    const beyondCap = '🎉'.repeat(MAX_NOTE_TEXT_LEN_ - suffix.length + 1) + suffix
    expect(() => parseCheckpoint(beyondCap)).toThrow(`checkpoint text exceeds ${MAX_NOTE_TEXT_LEN_} chars`)
  })

  it('accepts the maximum number of signature lines (64)', () => {
    const signature = `— ${LOG_NAME} AA==\n`
    const header = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n`
    const text = header + signature.repeat(64)
    const checkpoint = parseCheckpoint(text)
    expect(checkpoint.origin).toBe(ORIGIN)
    expect(checkpoint.treeSize).toBe(3n)
    expect(checkpoint.root).toEqual(ROOT)
  })

  it('bounds the error message for a huge malformed size line', () => {
    const rootB64 = btoa(String.fromCharCode(...ROOT))
    const text = `${ORIGIN}\n${'x'.repeat(100_000)}\n${rootB64}\n\n— ${LOG_NAME} AA==\n`
    let threw = false
    try {
      parseCheckpoint(text)
    } catch (e) {
      threw = true
      expect((e as Error).message.length).toBeLessThan(200)
    }
    expect(threw).toBe(true)
  })

  it('uses Python code-point slicing for bounded checkpoint diagnostics', () => {
    const oversizedByOne = '🎉'.repeat(81)
    const text = `${ORIGIN}\n${oversizedByOne}\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} AA==\n`
    expect(() => parseCheckpoint(text)).toThrow(
      `tree size must be ASCII decimal digits: '${'\\U0001f389'.repeat(80)}'…`,
    )
  })

  it('rejects an oversized signature blob before decoding', () => {
    const hugeB64 = 'A'.repeat(8192 + 4) // MAX_SIG_B64_LEN + 4
    const text = `${ORIGIN}\n3\n${btoa(String.fromCharCode(...ROOT))}\n\n— ${LOG_NAME} ${hugeB64}\n`
    let threw = false
    try {
      parseCheckpoint(text)
    } catch (e) {
      threw = true
      expect((e as Error).message).toContain('exceeds')
      expect((e as Error).message.length).toBeLessThan(200)
    }
    expect(threw).toBe(true)
  })

  it('rejects an oversized root before decoding', () => {
    const hugeB64 = 'A'.repeat(100_000)
    const text = `${ORIGIN}\n3\n${hugeB64}\n\n— ${LOG_NAME} AA==\n`
    let threw = false
    try {
      parseCheckpoint(text)
    } catch (e) {
      threw = true
      expect((e as Error).message).toContain('44')
      expect((e as Error).message.length).toBeLessThan(200)
    }
    expect(threw).toBe(true)
  })
})

describe('verifyCheckpoint (hybrid AND + origin binding)', () => {
  it('both legs good passes', () => {
    const checkpoint = verifyCheckpoint(CP_FIXTURE_BASE, HK_A, ORIGIN)
    expect(checkpoint.treeSize).toBe(5n)
    expect(checkpoint.root).toEqual(ROOT)
  })

  it('Ed25519-only fails (ML-DSA leg dropped)', () => {
    const lines = CP_FIXTURE_BASE.split('\n')
    const truncated = lines.slice(0, -2).join('\n') + '\n' // drop mldsa sig line + trailing ""
    expect(() => verifyCheckpoint(truncated, HK_A, ORIGIN)).toThrow(TlogError)
  })

  it('ML-DSA-only fails (Ed25519 leg dropped)', () => {
    const lines = CP_FIXTURE_BASE.split('\n')
    // layout: [origin, size, root, "", ed_sig, mldsa_sig, ""]
    const withoutEd = [...lines.slice(0, 4), ...lines.slice(5)]
    expect(() => verifyCheckpoint(withoutEd.join('\n'), HK_A, ORIGIN)).toThrow(TlogError)
  })

  it('fails on the wrong expected_origin', () => {
    expect(() => verifyCheckpoint(CP_FIXTURE_BASE, HK_A, 'different-origin/2026')).toThrow(TlogError)
  })

  it('fails on the wrong log_key.origin', () => {
    const logKey: LogKey = { ...HK_A, origin: 'different-origin/2026' }
    expect(() => verifyCheckpoint(CP_FIXTURE_BASE, logKey, ORIGIN)).toThrow(TlogError)
  })

  it('a tampered body fails both legs', () => {
    const tampered = corruptLine(CP_FIXTURE_BASE, 1, '6') // signed tree_size 5 -> 6
    expect(() => verifyCheckpoint(tampered, HK_A, ORIGIN)).toThrow(TlogError)
  })

  it('a signature by a different (but well-formed) name is ignored, not counted', () => {
    const logKey: LogKey = { ...HK_A, name: 'attest-log-2' } // signed as attest-log-1
    expect(() => verifyCheckpoint(CP_FIXTURE_BASE, logKey, ORIGIN)).toThrow(TlogError)
  })

  it('a wrong Ed25519 key-hash prefix does not count', () => {
    const lines = CP_FIXTURE_BASE.split('\n')
    const [dash, name, blobB64] = lines[4]!.split(' ', 3)
    const blob = Uint8Array.from(atob(blobB64!), (c) => c.charCodeAt(0))
    blob[0] = blob[0]! ^ 0xff
    lines[4] = `${dash} ${name} ${btoa(String.fromCharCode(...blob))}`
    expect(() => verifyCheckpoint(lines.join('\n'), HK_A, ORIGIN)).toThrow(TlogError)
  })

  it('a corrupted ML-DSA-65 key-hash prefix does not count', () => {
    const lines = CP_FIXTURE_BASE.split('\n')
    const [dash, name, blobB64] = lines[5]!.split(' ', 3)
    const blob = Uint8Array.from(atob(blobB64!), (c) => c.charCodeAt(0))
    blob[0] = blob[0]! ^ 0xff
    lines[5] = `${dash} ${name} ${btoa(String.fromCharCode(...blob))}`
    expect(() => verifyCheckpoint(lines.join('\n'), HK_A, ORIGIN)).toThrow(TlogError)
  })

  it('no signature lines fails', () => {
    const text = `${ORIGIN}\n5\n${btoa(String.fromCharCode(...ROOT))}\n\n`
    expect(() => verifyCheckpoint(text, HK_A, ORIGIN)).toThrow(TlogError)
  })

  it('rejects a short log_key.ed25519Pub', () => {
    const logKey: LogKey = { ...HK_A, ed25519Pub: enc.encode('short') }
    expect(() => verifyCheckpoint(CP_FIXTURE_BASE, logKey, ORIGIN)).toThrow(TlogError)
  })

  it('rejects a short log_key.mldsaPub', () => {
    const logKey: LogKey = { ...HK_A, mldsaPub: enc.encode('short') }
    expect(() => verifyCheckpoint(CP_FIXTURE_BASE, logKey, ORIGIN)).toThrow(TlogError)
  })

  it.each(['origin', 'name', 'ed25519Pub', 'mldsaPub'])('rejects a malformed log_key field (%s = null)', (field) => {
    const logKey = { ...HK_A, [field]: null }
    expect(() => verifyCheckpoint(CP_FIXTURE_BASE, logKey, ORIGIN)).toThrow(TlogError)
  })

  it('rejects a malformed expected_origin type', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => verifyCheckpoint(CP_FIXTURE_BASE, HK_A, null as any)).toThrow(TlogError)
  })
})

// --------------------------------------------------------------------------
// key-hash prefix: hand-pinned KAT (copied verbatim from
// test_key_hash_prefix_matches_hand_computed_sha256's pure hash-math half —
// the ed25519 pubkey is independently re-derived here via noble/curves from
// the same fixed seed Python's keys.from_seed uses, RFC 8032 key derivation
// being deterministic and already cross-verified elsewhere in this suite).
// --------------------------------------------------------------------------

describe('keyHash', () => {
  it('matches the hand-computed SHA-256 KAT for both signature types', () => {
    const seed = new Uint8Array(32).fill(7)
    const edPub = ed25519.getPublicKey(seed)
    // bytes(range(256)) * 7 + bytes(160): the last 160 bytes are zero, NOT a
    // continuation of the 0..255 cycle (Python's bytes(160) is null bytes).
    const mldsaPub = new Uint8Array(1952)
    for (let i = 0; i < 1792; i++) mldsaPub[i] = i % 256
    const expectedEdPrefix = h('fa60fb40')
    const expectedMldsaPrefix = h('5aded660')
    expect(sha256(new Uint8Array([...enc.encode('test-log\n'), 0x01, ...edPub])).slice(0, 4)).toEqual(
      expectedEdPrefix,
    )
    expect(
      sha256(new Uint8Array([...enc.encode('test-log\n'), 0xff, ...enc.encode('attest-ml-dsa-65'), ...mldsaPub])).slice(0, 4),
    ).toEqual(expectedMldsaPrefix)

    expect(keyHash('test-log', Uint8Array.of(0x01), edPub)).toEqual(expectedEdPrefix)
    expect(
      keyHash('test-log', new Uint8Array([0xff, ...enc.encode('attest-ml-dsa-65')]), mldsaPub),
    ).toEqual(expectedMldsaPrefix)
  })
})

// --------------------------------------------------------------------------
// receiptCoreHash: signed-receipt-core hash domain.
// --------------------------------------------------------------------------

describe('receiptCoreHash', () => {
  it('matches a hand-pinned KAT', () => {
    // SHA-256(b"attest-receipt-core-v1\x00" || b'{"a":1}' || 0x00 || b'[]')
    const expected = '1dac7a8f22603b1d77da8c71d84d5dc2e5d258f57654f76e1de0a0c304bc206e'
    const envelope = { payload: { a: 1n }, signatures: [] }
    expect(receiptCoreHash(envelope)).toBe(expected)
  })

  it('matches the domain-separated JCS formula against canonicalBytes independently', () => {
    const payload = { a: 1n, issuer: { id: 'issuer.example' } }
    const signatures = [{ kid: 'issuer.example/keys/x#1', alg: 'Ed25519', sig: 'c2ln' }]
    const envelope = { payload, signatures }
    // Independent re-derivation via the already-tested canon serializer.
    const expected = bytesToHex(
      sha256(
        new Uint8Array([
          ...enc.encode('attest-receipt-core-v1\x00'),
          ...canonicalBytes(payload),
          0x00,
          ...canonicalBytes(signatures),
        ]),
      ),
    )
    expect(receiptCoreHash(envelope)).toBe(expected)
  })

  it('excludes delivery from the hash', () => {
    const base = { payload: { a: 1n }, signatures: [] }
    const withDelivery = { ...base, delivery: { salt: 'irrelevant-to-the-core-hash' } }
    expect(receiptCoreHash(base)).toBe(receiptCoreHash(withDelivery))
  })

  it('changes when signature bytes change (design fix 4)', () => {
    const base = { payload: { a: 1n }, signatures: [{ sig: 'AAAA' }] }
    const resigned = { payload: { a: 1n }, signatures: [{ sig: 'BBBB' }] }
    expect(receiptCoreHash(base)).not.toBe(receiptCoreHash(resigned))
  })

  it('is lowercase 64-char hex', () => {
    const result = receiptCoreHash({ payload: {}, signatures: [] })
    expect(result).toHaveLength(64)
    expect(result).toBe(result.toLowerCase())
    expect(/^[0-9a-f]+$/.test(result)).toBe(true)
  })

  it('throws on a missing payload', () => {
    expect(() => receiptCoreHash({ signatures: [] })).toThrow(TlogError)
  })

  it('throws on a non-object payload', () => {
    expect(() => receiptCoreHash({ payload: 'not-an-object', signatures: [] })).toThrow(TlogError)
  })

  it('throws on missing signatures', () => {
    expect(() => receiptCoreHash({ payload: {} })).toThrow(TlogError)
  })

  it('throws on non-array signatures', () => {
    expect(() => receiptCoreHash({ payload: {}, signatures: 'not-a-list' })).toThrow(TlogError)
  })

  it('throws on a non-object envelope', () => {
    expect(() => receiptCoreHash('not-a-dict')).toThrow(TlogError)
  })
})
