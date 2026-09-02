// The stored-block check, against streams both decoders were measured on.
//
// The walker exists for one measured disagreement and must not invent others:
// a stream any decoder accepts has to walk clean here. The mirror of
// `tests/test_deflate.py`, over the same shapes.

import { describe, expect, it } from 'vitest'
import { deflateSync, Deflate } from 'fflate'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { deflateError } from '../src/deflate.js'
import { canonicalMembers, DEFAULT_CONTAINER_CAPS } from '../src/container.js'

const LIMIT = 1 << 20
const HERE = fileURLToPath(new NodeURL('.', import.meta.url))

function storedStream(payload: Uint8Array, nlen?: number, final = 1): Uint8Array {
  const head = new Uint8Array(5)
  head[0] = final | (0 << 1)
  const length = payload.length
  head[1] = length & 0xff
  head[2] = (length >> 8) & 0xff
  const complement = nlen === undefined ? ~length & 0xffff : nlen
  head[3] = complement & 0xff
  head[4] = (complement >> 8) & 0xff
  const out = new Uint8Array(head.length + payload.length)
  out.set(head)
  out.set(payload, head.length)
  return out
}

const encoder = new TextEncoder()

describe('storedBlockError', () => {
  it('walks an honest stored block clean', () => {
    expect(deflateError(storedStream(encoder.encode('hello world')), LIMIT)).toBeNull()
  })

  it('names a stored block whose complement is wrong', () => {
    // This decoder accepts the stream and the reference importer's refuses it:
    // the verdict moves here so both implementations give the same one.
    expect(deflateError(storedStream(encoder.encode('hello world'), 0x1234), LIMIT)).toBe(
      'stored-block-lengths',
    )
  })

  it('names a bad complement in a later block', () => {
    const first = storedStream(encoder.encode('first'), undefined, 0)
    const second = storedStream(encoder.encode('second'), 0)
    const joined = new Uint8Array(first.length + second.length)
    joined.set(first)
    joined.set(second, first.length)
    expect(deflateError(joined, LIMIT)).toBe('stored-block-lengths')
  })

  it('walks every stream the compressor produces clean', () => {
    // A validator that refused a stream the compressor produces would refuse
    // ordinary bundles: this is the property that keeps it from becoming a bug.
    const payloads = [
      new Uint8Array(0),
      encoder.encode('x'),
      encoder.encode('terms '.repeat(400)),
      new Uint8Array(Array.from({ length: 2048 }, (_, i) => i & 0xff)),
      new Uint8Array(5000),
    ]
    for (const payload of payloads) {
      for (const level of [0, 1, 6, 9] as const) {
        expect(deflateError(deflateSync(payload, { level }), LIMIT)).toBeNull()
      }
    }
  })

  it('walks the shipped sample clean', () => {
    const raw = new Uint8Array(readFileSync(join(HERE, '..', 'public', 'sample', 'demo.attest')))
    const members = canonicalMembers(raw, DEFAULT_CONTAINER_CAPS).filter((m) => m.method === 8)
    expect(members.length).toBeGreaterThan(0)
    for (const member of members) {
      const window = raw.subarray(member.dataStart, member.dataStart + member.compressedSize)
      expect(deflateError(window, LIMIT)).toBeNull()
    }
  })

  it('refuses everything it cannot follow, rather than deferring to the decoder', () => {
    // Fail-closed: the earlier version stayed silent here, on the assumption
    // that the two decoders agreed on whatever it could not follow. They do
    // not — a reserved literal code is accepted by one and refused by the
    // other — so silence is no longer an answer.
    const malformed = [
      new Uint8Array(0),
      new Uint8Array([0xff, 0xff, 0xff, 0xff]),
      deflateSync(encoder.encode('abc')).subarray(0, 2),
      new Uint8Array([0b111]),
    ]
    for (const stream of malformed) expect(deflateError(stream, LIMIT)).not.toBeNull()
  })

  it('refuses the reserved literal code the other decoder accepts', () => {
    // Measured: this stream produces 261 bytes here and is refused by the
    // reference decoder as an invalid literal/length code.
    const reserved = new Uint8Array([0x73, 0x1c, 0x03, 0x00])
    expect(deflateError(reserved, LIMIT)).toBe('reserved-length-symbol')
  })

  it('counts length codes from the normative table', () => {
    // The DEFLATE length table is not linear: code 285 alone means 258 bytes,
    // where counting `3 + index` would report 31. Under-counting does not show
    // up as a wrong answer — it shows up as the walk running PAST the limit it
    // claims to stop at, which is the work an attacker gets to choose.
    //
    // The stream below produces 600 bytes without setting BFINAL, and is
    // followed by a stored block whose complement is wrong. Under the real
    // table the limit of 300 stops the walk before that block is reached;
    // under a linear count the walk believes it produced about a hundred
    // bytes, keeps going, and finds it.
    const deflate = new Deflate({ level: 9 })
    const parts: Uint8Array[] = []
    deflate.ondata = (chunk) => parts.push(chunk)
    deflate.push(new Uint8Array(600).fill(0x41), false)
    deflate.flush()
    const head = parts.reduce((size, part) => size + part.length, 0)
    const bad = storedStream(encoder.encode('second'), 0)
    const stream = new Uint8Array(head + bad.length)
    let offset = 0
    for (const part of parts) {
      stream.set(part, offset)
      offset += part.length
    }
    stream.set(bad, head)
    expect(deflateError(stream, 10_000)).toBe('stored-block-lengths')
    expect(deflateError(stream, 300)).toBeNull()
  })

  it('stops at the limit', () => {
    expect(deflateError(deflateSync(new Uint8Array(100_000)), 10)).toBeNull()
  })
})
