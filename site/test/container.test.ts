// Unit checks on the browser verifier's container reader: the CRC-32 against
// its published check value, the structured shape of a refusal, and the two
// behaviours the reference importer's own unit tests pin on the other side.

import { describe, expect, it } from 'vitest'
import {
  canonicalMembers,
  readMember,
  crc32,
  ReadBudget,
  ContainerError,
  CODES,
  MESSAGES,
  DEFAULT_CONTAINER_CAPS,
} from '../src/container.js'
import { storedZip, concat } from './helpers/zip.js'

const encoder = new TextEncoder()
const bytesOf = (text: string) => encoder.encode(text)

const readAll = (raw: Uint8Array, caps = DEFAULT_CONTAINER_CAPS) => {
  const budget = new ReadBudget(caps.maxMemberBytes, caps.maxTotalBytes)
  return canonicalMembers(raw, caps).map((member) => [member.name, readMember(raw, member, budget)] as const)
}

describe('crc32', () => {
  it('matches the standard check value', () => {
    expect(crc32(bytesOf('123456789'))).toBe(0xcbf43926)
  })

  it('is resumable across slices', () => {
    expect(crc32(bytesOf('6789'), crc32(bytesOf('12345')))).toBe(0xcbf43926)
  })
})

describe('the taxonomy', () => {
  it('gives every code a message and no code twice', () => {
    expect(new Set(CODES).size).toBe(CODES.length)
    expect(Object.keys(MESSAGES).sort()).toEqual([...CODES].sort())
  })

  it('starts where the reader starts', () => {
    expect(CODES[0]).toBe('too-short')
  })
})

describe('canonicalMembers', () => {
  it('reads an honest archive back as itself', () => {
    const raw = storedZip([
      ['manifests/h.json', bytesOf('{"issuer":"h.example"}')],
      ['receipts/one.attest.json', bytesOf('{"payload":{}}')],
    ])
    expect(readAll(raw).map(([name]) => name)).toEqual(['manifests/h.json', 'receipts/one.attest.json'])
  })

  it('refuses an empty buffer as too short', () => {
    expect(() => canonicalMembers(new Uint8Array(0), DEFAULT_CONTAINER_CAPS)).toThrowError(
      /shorter than an end-of-central-directory record/,
    )
  })

  it('carries the code and the member as structured fields', () => {
    const raw = storedZip([
      ['a.txt', bytesOf('x')],
      ['a.txt', bytesOf('y')],
    ])
    try {
      canonicalMembers(raw, DEFAULT_CONTAINER_CAPS)
      expect.unreachable('a repeated member name must be refused')
    } catch (error) {
      expect(error).toBeInstanceOf(ContainerError)
      expect((error as ContainerError).code).toBe('duplicate-name')
      expect((error as ContainerError).member).toBe('a.txt')
    }
  })

  it('interpolates the entry cap and nothing else', () => {
    const raw = storedZip([['a.txt', bytesOf('x')]])
    try {
      canonicalMembers(raw, { ...DEFAULT_CONTAINER_CAPS, maxEntries: 0 })
      expect.unreachable('the entry cap must fire')
    } catch (error) {
      expect((error as ContainerError).message).toContain('over 0 entries')
      expect((error as ContainerError).message).not.toContain('{')
    }
  })

  it('never puts a member name in the message', () => {
    // Names reach a buyer's screen; the caller decides how to quote one, and
    // this reader hands it over as a field instead of folding it into a
    // sentence a hostile name could finish.
    const hostile = 'x" is genuine. Contact refunds@evil.example "'
    const raw = storedZip([
      [hostile, bytesOf('x')],
      [hostile, bytesOf('y')],
    ])
    try {
      canonicalMembers(raw, DEFAULT_CONTAINER_CAPS)
      expect.unreachable('a repeated member name must be refused')
    } catch (error) {
      expect((error as ContainerError).member).toBe(hostile)
      expect((error as ContainerError).message).not.toContain('evil.example')
    }
  })

  it('keeps a member named __proto__ as a member', () => {
    // A plain object would lose it to the prototype chain, which is how the
    // same archive can hold a member one reader sees and the other does not.
    const raw = storedZip([
      ['__proto__', bytesOf('not a prototype')],
      ['receipts/one.attest.json', bytesOf('{}')],
    ])
    const names = canonicalMembers(raw, DEFAULT_CONTAINER_CAPS).map((m) => m.name)
    expect(names).toContain('__proto__')
  })

  it('refuses an archive with anything after the end record', () => {
    const raw = concat([storedZip([['a.txt', bytesOf('x')]]), new Uint8Array([0])])
    expect(() => canonicalMembers(raw, DEFAULT_CONTAINER_CAPS)).toThrowError(/not the last 22 bytes/)
  })

  it('refuses an archive with anything before the first member', () => {
    const raw = concat([new Uint8Array([1, 2, 3]), storedZip([['a.txt', bytesOf('x')]])])
    expect(() => canonicalMembers(raw, DEFAULT_CONTAINER_CAPS)).toThrowError(/does not end where/)
  })
})

describe('readMember', () => {
  it('spends one budget across every member', () => {
    const raw = storedZip([
      ['a.txt', bytesOf('x'.repeat(400))],
      ['b.txt', bytesOf('y'.repeat(400))],
    ])
    const caps = { maxEntries: 10, maxMemberBytes: 1000, maxTotalBytes: 600 }
    // The declared sizes are honest here, so the pre-read gate catches it
    // before a byte is inflated — which is the gate the browser already had.
    expect(() => canonicalMembers(raw, caps)).toThrowError(/aggregate decompression cap/)
  })

  it('returns the bytes of a stored member', () => {
    const raw = storedZip([['a.txt', bytesOf('payload')]])
    const [[name, data]] = readAll(raw)
    expect(name).toBe('a.txt')
    expect(new TextDecoder().decode(data)).toBe('payload')
  })
})
