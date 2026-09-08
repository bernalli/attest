import { describe, it, expect } from 'vitest'
import { loadsStrict, verify, isOk, parseTrustStore } from 'attest-verifier'

describe('attest-verifier dependency', () => {
  it('parses integers as bigint (loadsStrict discipline)', () => {
    const v = loadsStrict(new TextEncoder().encode('{"n": 7}')) as { n: unknown }
    expect(typeof v.n).toBe('bigint')
  })
  it('fails closed against an empty trust store', () => {
    // A PARSED store that trusts nobody, and never a `{ manifests: {} }`
    // literal: the literal is refused for not being a snapshot at all, so the
    // test would keep passing while measuring the contract instead of the
    // emptiness it names.
    const empty = parseTrustStore(new TextEncoder().encode('{"manifests":{},"provenance":{}}'))
    const r = verify(new TextEncoder().encode('{}'), empty)
    expect(r.signature).toBe('invalid')
    expect(isOk(r)).toBe(false)
  })
})
