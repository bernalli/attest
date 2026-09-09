import { describe, it, expect } from 'vitest'
import { loadsStrict, verify, isOk, parseTrustStore } from 'attest-verifier'

describe('attest-verifier dependency', () => {
  it('parses integers as bigint (loadsStrict discipline)', () => {
    const v = loadsStrict(new TextEncoder().encode('{"n": 7}')) as { n: unknown }
    expect(typeof v.n).toBe('bigint')
  })
  it('refuses a document that is not an envelope', () => {
    // NOT named after the empty store. Measured: for this input the verdict is
    // byte-identical against a store that trusts an issuer -- both answer
    // `errors: ["envelope missing object member 'payload'"]` -- so the emptiness
    // plays no part here, and naming it would claim a measurement this test does
    // not make. Fail-closed against an empty store is measured in
    // `tamper.test.ts` ('drop-manifest'), where a real receipt makes the store
    // the thing that decides.
    //
    // A PARSED store and never a `{ manifests: {} }` literal: the literal is
    // refused for not being a snapshot at all.
    const empty = parseTrustStore(new TextEncoder().encode('{"manifests":{},"provenance":{}}'))
    expect(empty.issuers()).toEqual([])
    const r = verify(new TextEncoder().encode('{}'), empty)
    expect(r.signature).toBe('invalid')
    expect(isOk(r)).toBe(false)
  })
})
