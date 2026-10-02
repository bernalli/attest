// Unpadded base64url <-> bytes, matching Python keys.b64u / b64u_decode.
// No deps: @noble/hashes ships no base64 and we refuse libsodium.

function bytesToBinary(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return s
}

export function b64uEncode(bytes: Uint8Array): string {
  const b64 = btoa(bytesToBinary(bytes))
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// The ONE decode grammar both reference decoders share (Python keys.b64u_decode
// carries the twin): optional `=` padding, `+/` or `-_`, non-zero trailing bits
// (vector group 22) -- and nothing else. `atob` alone skips ASCII whitespace,
// which Python never did, while Python silently dropped characters `atob`
// rejects; the explicit grammar is what makes the two answer alike.
const B64U_RE = /^[A-Za-z0-9_+/-]*={0,2}$/

export function b64uDecode(s: string): Uint8Array {
  if (typeof s !== 'string' || !B64U_RE.test(s)) throw new Error('invalid base64url: unexpected character')
  const body = s.replace(/=+$/, '')
  if (body.length % 4 === 1) throw new Error('invalid base64url: impossible length')
  const b64 = body.replace(/-/g, '+').replace(/_/g, '/')
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4) // matches '=' * (-len % 4)
  const binary = atob(padded)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}
