import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { canonicalBytes, loadsStrict } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { BundleError, parseBundle } from '../src/bundle.js'
import { VECTORS_ROOT } from './helpers/vectors.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const encoder = new TextEncoder()

type StoredEntry = readonly [name: string, bytes: Uint8Array]

function crc32(bytes: Uint8Array): number {
  let value = 0xffffffff
  for (const byte of bytes) {
    value ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0)
    }
  }
  return (value ^ 0xffffffff) >>> 0
}

function u16(value: number): Uint8Array {
  const bytes = new Uint8Array(2)
  new DataView(bytes.buffer).setUint16(0, value, true)
  return bytes
}

function u32(value: number): Uint8Array {
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, value >>> 0, true)
  return bytes
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0))
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

function storedZip(entries: readonly StoredEntry[]): Uint8Array {
  const locals: Uint8Array[] = []
  const central: Uint8Array[] = []
  let offset = 0

  for (const [name, bytes] of entries) {
    const filename = encoder.encode(name)
    const checksum = crc32(bytes)
    const local = concat([
      u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0),
      u32(checksum), u32(bytes.length), u32(bytes.length), u16(filename.length), u16(0),
      filename, bytes,
    ])
    locals.push(local)
    central.push(concat([
      u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0),
      u32(checksum), u32(bytes.length), u32(bytes.length), u16(filename.length), u16(0),
      u16(0), u16(0), u16(0), u32(0), u32(offset), filename,
    ]))
    offset += local.length
  }

  const directory = concat(central)
  return concat([
    ...locals,
    directory,
    u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length),
    u32(directory.length), u32(offset), u16(0),
  ])
}

function validEntries(): StoredEntry[] {
  const envelope = new Uint8Array(readFileSync(join(V01, 'envelope.json')))
  const document = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = document.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  const manifest = { issuer, key_manifests: [manifests[issuer]], artifact_manifests: [] } as JsonObject
  return [
    ['receipts/01HZX0000000000000000000AA.attest.json', envelope],
    [`manifests/${issuer}.json`, canonicalBytes(manifest)],
    ['README.html', encoder.encode('<p>bundle readme</p>')],
  ]
}

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
