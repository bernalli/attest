import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha2'
import { concatBytes } from '@noble/curves/utils.js'
import { verifyStrict, Ed25519LengthError } from '../src/ed25519.js'

const L = 2n ** 252n + 27742317777372353535851937790883648493n
const seed = Uint8Array.from({ length: 32 }, () => 1)
const pub = ed25519.getPublicKey(seed)
const msg = new TextEncoder().encode('attest test message')
const sig = ed25519.sign(msg, seed)

function numberToLE(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len)
  for (let i = 0; i < len; i++) { out[i] = Number(n & 0xffn); n >>= 8n }
  return out
}
function leToNumber(b: Uint8Array): bigint {
  let n = 0n
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!)
  return n
}

describe('verifyStrict', () => {
  it('accepts a valid signature', () => { expect(verifyStrict(msg, sig, pub)).toBe(true) })
  it('rejects a tampered message', () => {
    const bad = new TextEncoder().encode('attest test messagE')
    expect(verifyStrict(bad, sig, pub)).toBe(false)
  })
  it('rejects non-canonical S = S + L (malleability, vector 08 shape)', () => {
    const S = leToNumber(sig.slice(32, 64))
    const mal = new Uint8Array(64)
    mal.set(sig.slice(0, 32), 0)
    mal.set(numberToLE(S + L, 32), 32)
    expect(verifyStrict(msg, mal, pub)).toBe(false)
  })
  it('rejects a small-order public key (flag is load-bearing)', () => {
    const smallOrder = Uint8Array.from(Buffer.from(
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'))
    // strict: rejected regardless of signature content — this is the load-bearing assertion.
    expect(verifyStrict(msg, sig, smallOrder)).toBe(false)
    // Documentation probe (reconciled; see task-6-report.md "API-reconciliation" section):
    // a real signature over an unrelated keypair (`sig`) does not verify against
    // `smallOrder` under either mode — the cofactored check depends on k = H(R||A||msg),
    // which differs per keypair, so it never accidentally accepts. To demonstrate that
    // zip215:false is load-bearing, use the textbook degenerate forgery instead:
    // R = identity-point encoding, S = 0. Because `smallOrder` has order dividing 8, the
    // cofactored equation [8]SB == [8]R + [8]kA collapses to 0 == 0 for ANY message when
    // zip215:true (the small-order gate is skipped) — this "signature" forges against
    // smallOrder for every message. Under zip215:false the small-order gate
    // (`!zip215 && A.isSmallOrder()`) rejects it outright, exactly like verifyStrict.
    const forgedSig = new Uint8Array(64)
    forgedSig[0] = 0x01 // R = canonical encoding of the identity point (0, 1)
    // forgedSig[32..64] stays zero => S = 0
    expect(ed25519.verify(forgedSig, msg, smallOrder)).toBe(true)
    expect(verifyStrict(msg, forgedSig, smallOrder)).toBe(false)
  })
  it('throws on wrong lengths', () => {
    expect(() => verifyStrict(msg, sig.slice(0, 63), pub)).toThrow(Ed25519LengthError)
    expect(() => verifyStrict(msg, sig, pub.slice(0, 31))).toThrow(/public key must be 32 bytes/)
  })
})

// Signer-crafted signatures that pass noble's COFACTORED check (even with
// zip215:false) but fail the spec's pinned cofactorless ruleset -- and
// libsodium, i.e. Python keys.verify_strict. Each needs the secret scalar.
describe('verifyStrict is cofactorless (libsodium parity)', () => {
  const P = ed25519.Point
  const a = ed25519.utils.getExtendedPublicKey(seed).scalar
  const T8 = P.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a')
  const kOf = (R: Uint8Array, A: Uint8Array) => leToNumber(sha512(concatBytes(R, A, msg))) % L
  const mod = (n: bigint) => ((n % L) + L) % L
  const sigOf = (R: Uint8Array, S: bigint) => concatBytes(R, numberToLE(mod(S), 32))

  it('rejects a small-order R with S = k*a (cofactored-valid)', () => {
    for (let i = 0; i < 8; i++) {
      const R = (i === 0 ? P.ZERO : T8.multiplyUnsafe(BigInt(i))).toBytes()
      const forged = sigOf(R, kOf(R, pub) * a)
      expect(ed25519.verify(forged, msg, pub, { zip215: false })).toBe(true) // the old call
      expect(verifyStrict(msg, forged, pub)).toBe(false)
    }
  })
  it('rejects a mixed-order R = rB + T8', () => {
    const r = 123456789n
    const R = P.BASE.multiply(r).add(T8).toBytes()
    const forged = sigOf(R, r + kOf(R, pub) * a)
    expect(ed25519.verify(forged, msg, pub, { zip215: false })).toBe(true)
    expect(verifyStrict(msg, forged, pub)).toBe(false)
  })
  it('rejects a mixed-order A = aB + T8 whenever k is not 0 mod 8', () => {
    const A = P.BASE.multiply(a).add(T8).toBytes()
    let r = 1n, R: Uint8Array, k: bigint
    do { r++; R = P.BASE.multiply(r).toBytes(); k = kOf(R, A) } while (k % 8n === 0n)
    const forged = sigOf(R, r + k * a)
    expect(ed25519.verify(forged, msg, A, { zip215: false })).toBe(true)
    expect(verifyStrict(msg, forged, A)).toBe(false)
  })
  it('still accepts honest signatures over arbitrary messages', () => {
    for (let n = 0; n < 16; n++) {
      const m = Uint8Array.from({ length: n * 7 }, (_, i) => (i * 31 + n) & 0xff)
      expect(verifyStrict(m, ed25519.sign(m, seed), pub)).toBe(true)
    }
  })
})
