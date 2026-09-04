import { describe, it, expect } from 'vitest'
import * as api from '../src/index.js'

describe('public API', () => {
  it('exports verify, isOk, loadsStrict', () => {
    expect(typeof api.verify).toBe('function')
    expect(typeof api.isOk).toBe('function')
    expect(typeof api.loadsStrict).toBe('function')
  })
})

// `legal/<sha256>.txt` names a member by the digest of its own bytes (v0.1
// §14.1), so an importer that wants to check the name against the content
// needs a hash over RAW BYTES — every other digest on this surface is taken
// over canonical JSON, which is a different question. It is synchronous
// because the importers that ask it are: WebCrypto's digest is a promise, and
// making one parser asynchronous to reach it would turn the whole chain above
// it asynchronous for a hash that is already in this package's dependencies.
describe('sha256Hex', () => {
  const enc = (text: string): Uint8Array => new TextEncoder().encode(text)

  it('hashes the empty input to the published digest', () => {
    expect(api.sha256Hex(new Uint8Array(0))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })

  it('hashes "abc" to the published digest', () => {
    expect(api.sha256Hex(enc('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('returns 64 lowercase hex characters', () => {
    expect(api.sha256Hex(enc('anything at all'))).toMatch(/^[0-9a-f]{64}$/)
  })

  it('hashes bytes, not text: one flipped bit changes the digest', () => {
    const bytes = enc('the deal this receipt preserves')
    const flipped = new Uint8Array(bytes)
    flipped[0] ^= 0x01
    expect(api.sha256Hex(flipped)).not.toBe(api.sha256Hex(bytes))
  })

  it('reads only the view it is given, not the buffer behind it', () => {
    // A member's bytes routinely arrive as a subarray of the whole archive. A
    // hash that reached past the view would answer about the archive instead
    // of about the member, and every digest check built on it would be wrong
    // in a way no example test would show.
    const backing = enc('PREFIXabcSUFFIX')
    const view = backing.subarray(6, 9)
    expect(api.sha256Hex(view)).toBe(api.sha256Hex(enc('abc')))
  })
})
