import { scrypt } from '@noble/hashes/scrypt'
import { verifyStrict } from './ed25519.js'

const LABEL_COMMITMENT = 'Attest-buyer-commitment-v1'
const LABEL_CHALLENGE = 'Attest-binding-challenge-v1'
const SCRYPT = { N: 32768, r: 8, p: 1, dkLen: 32 } as const // fixed, never configurable
const IDENTIFIER_TYPES = new Set(['issuer-account', 'email'])

// Index scan, not a regex: /[ \t\n\r]+$/ backtracks quadratically on a long
// whitespace run that is not at the end (100k spaces took 12 s).
function isAsciiWs(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d
}

function stripAsciiWs(s: string): string {
  let start = 0
  let end = s.length
  while (start < end && isAsciiWs(s.charCodeAt(start))) start++
  while (end > start && isAsciiWs(s.charCodeAt(end - 1))) end--
  return s.slice(start, end)
}

export function normalizeIdentifier(identifier: string, identifierType: string): string {
  if (!IDENTIFIER_TYPES.has(identifierType))
    throw new Error(`unknown identifier_type: '${identifierType}'`)
  let norm: string
  if (identifierType === 'email') {
    norm = stripAsciiWs(identifier).normalize('NFC')
      .replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32))
  } else {
    norm = identifier.normalize('NFC') // issuer-account: NFC only, case preserved
  }
  if (hasLoneSurrogate(norm))
    // JS TextEncoder would map a lone surrogate to U+FFFD, so distinct identifiers
    // could derive the same commitment; fail closed for parity with Python
    // (2026-07-13 review, finding 6).
    throw new Error('normalized identifier must not contain lone surrogate code points')
  if (norm.includes('\x00')) throw new Error('normalized identifier must not contain 0x00')
  return norm
}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i)
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const lo = s.charCodeAt(i + 1)
      if (lo >= 0xdc00 && lo <= 0xdfff) { i++; continue }
      return true
    }
    if (cp >= 0xdc00 && cp <= 0xdfff) return true
  }
  return false
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

export function computeCommitment(identifier: string, identifierType: string, salt: Uint8Array): Uint8Array {
  if (salt.length !== 16) throw new Error('salt must be exactly 16 raw bytes')
  const norm = normalizeIdentifier(identifier, identifierType)
  const enc = new TextEncoder()
  const password = concatBytes(
    enc.encode(LABEL_COMMITMENT), Uint8Array.of(0),
    enc.encode(identifierType), Uint8Array.of(0),
    enc.encode(norm),
  )
  return scrypt(password, salt, SCRYPT)
}

export function verifyChallenge(receiptId: string, nonce: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  if (nonce.length < 16) throw new Error('nonce must be at least 16 bytes')
  const enc = new TextEncoder()
  const msg = concatBytes(enc.encode(LABEL_CHALLENGE), Uint8Array.of(0), enc.encode(receiptId), Uint8Array.of(0), nonce)
  return verifyStrict(msg, sig, pub)
}
