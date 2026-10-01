// Pinned attest Ed25519 ruleset (spec §10): cofactorless/strict RFC 8032, reject
// non-canonical S (S >= L), reject small-order/non-canonical A and R.
// Mirrors Python keys.verify_strict (PyNaCl/libsodium crypto_sign_verify_detached).
//
// NOT `ed25519.verify(..., { zip215: false })`: in @noble/curves that mode still
// checks the COFACTORED equation [8](R + kA - SB) == 0 and never tests R for
// small order, so it accepts signer-crafted signatures (small-order R, mixed-order
// R or A) that libsodium -- and the spec -- reject. The equation is evaluated here
// exactly the way libsodium does it: recompute R' = SB - kA and compare its
// canonical encoding byte-for-byte with the signature's R.
import { ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha2'
import { concatBytes } from '@noble/curves/utils.js'

export class Ed25519LengthError extends Error {}

const L = 2n ** 252n + 27742317777372353535851937790883648493n
const Point = ed25519.Point

function scalarLE(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!)
  return n
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

export function verifyStrict(msg: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  if (sig.length !== 64) throw new Ed25519LengthError('Ed25519 signature must be 64 bytes')
  if (pub.length !== 32) throw new Ed25519LengthError('Ed25519 public key must be 32 bytes')
  const rBytes = sig.subarray(0, 32)
  const s = scalarLE(sig.subarray(32, 64))
  if (s >= L) return false // non-canonical S (SUF-CMA)
  try {
    // zip215=false: y < p and no "negative zero" x -- canonical encodings only.
    const A = Point.fromHex(pub, false)
    const R = Point.fromHex(rBytes, false)
    if (A.isSmallOrder() || R.isSmallOrder()) return false // SBS
    const k = scalarLE(sha512(concatBytes(rBytes, pub, msg))) % L
    // Cofactorless: R' = [S]B - [k]A, compared on canonical encoding (libsodium).
    const rCheck = Point.BASE.multiplyUnsafe(s).subtract(A.multiplyUnsafe(k))
    return bytesEqual(rCheck.toBytes(), rBytes)
  } catch {
    return false // point/decode errors are a rejected signature, never an exception (like keys.py)
  }
}
