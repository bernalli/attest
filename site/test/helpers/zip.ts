// A minimal STORED zip writer, so a test can put any name it likes in the
// central directory.
//
// Extracted from `vl6-duplicate-members-adversarial.test.ts`, which needed it
// to repeat a member name. The second caller needed it to give a member a
// *lying* name, and the two attacks share one property: the central directory
// is attacker-controlled metadata that no signature covers, so a test that
// wants to reason about it has to be able to write it by hand.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { canonicalBytes, loadsStrict } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { VECTORS_ROOT } from './vectors.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const encoder = new TextEncoder()

export type StoredEntry = readonly [name: string, bytes: Uint8Array]

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

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0))
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

export function storedZip(entries: readonly StoredEntry[]): Uint8Array {
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

/** The signed receipt every bundle in these tests is built around. */
export function validEnvelope(): Uint8Array {
  return new Uint8Array(readFileSync(join(V01, 'envelope.json')))
}

/** The `receipt_id` inside that signed payload — the only identifier a signature covers.
 *
 * Read from `01-valid-minimal/envelope.json`, never from a member name. Worth
 * saying why the constant exists at all: before this helper, the archive the
 * duplicate-member test built named its receipt `01HZX0000000000000000000AA`
 * while the payload inside it said `01JZ5PDHT0000G40R40M30E209`, and nothing in
 * the suite objected — the bench carried the very divergence these tests are
 * about. `validEntries` below now names the member after the signed id, so a
 * test that wants them to disagree has to say so out loud.
 */
export const VALID_RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'

/** The issuer's key manifest as a bare envelope may embed it (`delivery.issuer_manifest`).
 *
 * Read with `JSON.parse` rather than `loadsStrict`: the strict loader returns
 * BigInt for integers, which is right for canonicalization and unserializable
 * by `JSON.stringify`, and callers here are assembling a fixture rather than
 * canonicalizing one.
 */
export function embeddedManifest(): Record<string, unknown> {
  const document = JSON.parse(readFileSync(join(V01, 'manifests.json'), 'utf8')) as Record<string, Record<string, unknown>>
  const manifests = document.manifests
  const issuer = Object.keys(manifests)[0]
  return manifests[issuer] as Record<string, unknown>
}

export function validEntries(): StoredEntry[] {
  const document = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = document.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  const manifest = { issuer, key_manifests: [manifests[issuer]], artifact_manifests: [] } as JsonObject
  return [
    [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
    [`manifests/${issuer}.json`, canonicalBytes(manifest)],
    ['README.html', encoder.encode('<p>bundle readme</p>')],
  ]
}
