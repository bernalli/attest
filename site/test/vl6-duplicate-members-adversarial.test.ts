import { describe, expect, it } from 'vitest'
import { BundleError, parseBundle } from '../src/bundle.js'
import { concat, storedZip, validEntries } from './helpers/zip.js'
import type { StoredEntry } from './helpers/zip.js'

// The zip writer and the valid-archive fixture live in `./helpers/zip.ts`: this
// file needed them to repeat a member name, and the unsigned-label tests needed
// them to give a member a lying name. Both attacks work the same lever — the
// central directory is metadata no signature covers — so they share the tool.

const encoder = new TextEncoder()

describe('parseBundle duplicate central-directory members', () => {
  it('round-trips a unique STORED archive before using it as duplicate-member evidence', () => {
    /** A valid archive produced by the minimal writer proves duplicate failures are meaningful. */
    const parsed = parseBundle(storedZip(validEntries()))

    expect(parsed.receipts).toHaveLength(1)
  })

  it('rejects two receipt entries with one name and different physical content', () => {
    /** A repeated receipt filename must not resolve to either the first or last physical entry. */
    const entries = validEntries()
    const [receiptName, receiptBytes] = entries[0]
    const modified = concat([receiptBytes, encoder.encode('\n')])

    expect(() => parseBundle(storedZip([...entries, [receiptName, modified]]))).toThrow(BundleError)
  })

  it('rejects a repeated manifest member even when its two physical entries are identical', () => {
    /** Exact duplicate bytes remain ambiguous because the central directory still repeats a name. */
    const entries = validEntries()
    const manifest = entries[1]

    expect(() => parseBundle(storedZip([...entries, manifest]))).toThrow(BundleError)
  })

  it('rejects a repeated proof member instead of collapsing the central-directory pair', () => {
    /** The uniqueness rule applies to proofs as well as receipt and manifest members. */
    const entries = validEntries()
    const proof: StoredEntry = ['proofs/01HZX0000000000000000000AA.json', encoder.encode('{}')]

    expect(() => parseBundle(storedZip([...entries, proof, proof]))).toThrow(BundleError)
  })
})
