// Properties of the container reader, over generated archives.
//
// The corpus is a closed list of hand-picked files and shares the blind spots
// of whoever wrote it. These properties are what the corpus leaves are only
// samples of, and the loop is seeded rather than random so a failure is a
// reproducible failure and not a story about a Tuesday.
//
// No new dependency: a property-testing library would open the supply-chain
// gate on a package this project ships, for a deterministic loop that fits in
// twenty lines.

import { describe, expect, it } from 'vitest'
import { canonicalMembers, readMember, ReadBudget, ContainerError, DEFAULT_CONTAINER_CAPS } from '../src/container.js'
import { storedZip, concat } from './helpers/zip.js'

const encoder = new TextEncoder()

/** xorshift32: a seeded stream, so every run mutates the same bytes. */
function rng(seed: number): () => number {
  let state = seed >>> 0 || 1
  return () => {
    state ^= state << 13
    state >>>= 0
    state ^= state >>> 17
    state ^= state << 5
    state >>>= 0
    return state
  }
}

const honest = () =>
  storedZip([
    ['manifests/h.json', encoder.encode('{"issuer":"h.example","key_manifests":[]}')],
    ['receipts/01JBXYZ0000000000000000000.attest.json', encoder.encode('{"payload":{"receipt_id":"x"}}')],
    ['legal/eula.txt', encoder.encode('the deal this receipt preserves')],
  ])

const readAll = (raw: Uint8Array) => {
  const budget = new ReadBudget(DEFAULT_CONTAINER_CAPS.maxMemberBytes, DEFAULT_CONTAINER_CAPS.maxTotalBytes)
  return canonicalMembers(raw, DEFAULT_CONTAINER_CAPS).map(
    (member) => [member.name, Array.from(readMember(raw, member, budget)).join(',')] as const,
  )
}

const offsetOfDirectory = (raw: Uint8Array): number =>
  new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint32(raw.length - 22 + 16, true)

describe('container properties', () => {
  it('P1 reads an honest archive back as itself', () => {
    expect(readAll(honest()).map(([name]) => name)).toEqual([
      'manifests/h.json',
      'receipts/01JBXYZ0000000000000000000.attest.json',
      'legal/eula.txt',
    ])
  })

  it('P2 never produces a second reading under a single-byte mutation of the directory', () => {
    // A mutated byte either takes the archive outside the canonical form — in
    // which case it is refused — or changes nothing a reader can act on. What
    // must never happen is a DIFFERENT member list from the same file.
    const base = honest()
    const reference = readAll(base)
    const start = offsetOfDirectory(base)
    const next = rng(20260902)
    let refused = 0
    for (let i = 0; i < 3000; i += 1) {
      const mutated = base.slice()
      const position = start + (next() % (mutated.length - start))
      mutated[position] = (mutated[position] + 1 + (next() % 255)) & 0xff
      try {
        expect(readAll(mutated)).toEqual(reference)
      } catch (error) {
        if (!(error instanceof ContainerError)) throw error
        refused += 1
      }
    }
    // If nothing was refused the loop is mutating padding, not structure.
    expect(refused).toBeGreaterThan(1000)
  })

  it('P2 refuses any prefix and any suffix', () => {
    const base = honest()
    const next = rng(7)
    for (let size = 1; size <= 64; size += 1) {
      const filler = new Uint8Array(size).map(() => next() & 0xff)
      expect(() => canonicalMembers(concat([filler, base]), DEFAULT_CONTAINER_CAPS)).toThrowError(ContainerError)
      expect(() => canonicalMembers(concat([base, filler]), DEFAULT_CONTAINER_CAPS)).toThrowError(ContainerError)
    }
  })

  it('P2 refuses every truncation', () => {
    const base = honest()
    for (let cut = 0; cut < base.length; cut += 1) {
      expect(() => canonicalMembers(base.slice(0, cut), DEFAULT_CONTAINER_CAPS)).toThrowError(ContainerError)
    }
  })

  it('P2 refuses a file carrying a second, internally consistent directory', () => {
    // The case no counter check can see: nothing inside either directory is a
    // lie, so only the position of the directory itself can refuse the file.
    const base = honest()
    const doubled = concat([base, base])
    expect(() => canonicalMembers(doubled, DEFAULT_CONTAINER_CAPS)).toThrowError(/does not end where/)
  })

  it('P5 keeps prototype-shaped names as ordinary members', () => {
    const names = ['__proto__', 'constructor', 'hasOwnProperty', 'toString']
    const raw = storedZip(names.map((name) => [name, encoder.encode(name)] as const))
    const read = readAll(raw)
    expect(read.map(([name]) => name)).toEqual(names)
    for (const [name, data] of read) {
      expect(data).toBe(Array.from(encoder.encode(name)).join(','))
    }
  })
})
