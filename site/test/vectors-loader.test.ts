import { describe, it, expect } from 'vitest'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as V from './helpers/vectors.js'
import { runVerify } from '../src/run.js'
import { explain } from '../src/explain.js'
import type { VerificationResult } from 'attest-verifier'

const emptyLeaf = (): string => mkdtempSync(join(tmpdir(), 'attest-vectors-'))
const leafWith = (body: string): string => {
  const dir = emptyLeaf()
  writeFileSync(join(dir, 'compromise-view.json'), body)
  return dir
}

// The §19 evidence rail arrives from an UNTRUSTED transport (spec §19.2): the
// loader's job is to refuse what is not well formed, never to half-read it.
describe('compromiseView loader, not-well-formed inputs', () => {
  it('is null when the leaf carries no compromise-view.json', () => {
    expect(V.compromiseView(emptyLeaf())).toBeNull()
  })

  it('refuses a duplicate member instead of letting a twin claim win', () => {
    expect(() => V.compromiseView(leafWith('[{"manifest":{},"manifest":{"issuer":"x"}}]'))).toThrow()
  })

  it('refuses a float where a manifest version belongs', () => {
    expect(() => V.compromiseView(leafWith('[{"manifest":{"manifest_version":1.5}}]'))).toThrow()
  })

  it('lets verify() reject a view that is not an array (caller-contract rail)', () => {
    const view = V.compromiseView(leafWith('{"manifest":{}}'))
    expect(Array.isArray(view)).toBe(false)
    expect(() =>
      runVerify(new Uint8Array(), { manifests: {}, provenance: {} }, null, null, { compromiseView: view }),
    ).toThrow(/compromise_view must be a list/)
  })
})

const result = (over: Partial<VerificationResult> = {}): VerificationResult => ({
  signature: 'valid', schema: 'valid', revocation: 'unknown',
  binding: 'not_checked', trust: 'verified',
  transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
  grant: 'not_checked', grant_trust: 'not_checked',
  warnings: [], errors: [],
  ...over,
})

describe('§19 copy dispatch, states the verifier should never produce', () => {
  it('never tells a §19 story for an invalid signature with no compromised-key error', () => {
    const text = explain('signature', 'invalid', result({
      signature: 'invalid',
      warnings: ['compromise_rescue_receipt_after_cutoff'],
      errors: ['signature verification failed'],
    })).text
    expect(text).toContain('tampered with, corrupted, malformed')
  })

  it('prefers the rescue story when the two mutually exclusive §19 warnings both appear', () => {
    // §19.1 emits one or the other, never both; pin the resolution so a future
    // change to the order is a decision and not an accident.
    const text = explain('signature', 'valid', result({
      warnings: ['compromise_rescue_applied', 'compromise_cutoff_unanchored'],
    })).text
    expect(text).toMatch(/strictly before/)
  })

  it('falls back rather than guessing on an unknown signature value', () => {
    expect(explain('signature', 'quarantined', result()).text)
      .toContain('does not have dedicated wording')
  })
})
