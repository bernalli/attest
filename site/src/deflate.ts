// A member's compressed stream, judged here instead of by two decoders.
//
// The container reader decides which members an archive holds; the
// decompression itself is still done by each language's library. Those
// libraries do not refuse the same streams. Two disagreements were measured
// directly (2026-09-02):
//
//  * a *stored* block whose `NLEN` is not the one's complement of its `LEN` —
//    refused by the reference importer's decoder, accepted by this one, which
//    never reads that field;
//  * a literal/length code of 286, reserved by RFC 1951 and emitted by no
//    encoder — refused there, accepted here, because this decoder gives the
//    reserved codes working bases and produces output from them.
//
// Either one is the defect the canonical container form exists to remove, one
// layer down: same bytes, one verifier accepting and the other refusing. An
// earlier version of this module refused only the first and stayed silent on
// anything it could not follow, on the assumption that the decoders agreed
// everywhere else. The second measurement is what that assumption was worth.
//
// So this module validates the stream against RFC 1951 and is **fail-closed**:
// anything it cannot follow, or that the format does not allow, is refused, and
// only a stream walked to its final block is handed on. `deflateError` returns
// a reason or `null`; the caller turns any reason into the single
// `member-inflate-error` code, because which structure was wrong is not the
// buyer's business.
//
// The one thing it does not do is walk past the caller's output cap: past that
// point both implementations refuse the member for the same reason anyway, and
// walking further would be work an attacker sized.
//
// `src/attest/deflate.py` is the same walk, step for step, with the same
// reasons.

/** Order in which the code-length code lengths are written (RFC 1951 §3.2.7). */
const CLEN_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

/** Extra bits carried by length codes 257-285 and distance codes 0-29. */
const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]

/** Base output length per length code 257-285 (RFC 1951 §3.2.5). The table is
 * not linear — code 285 alone means 258 bytes — so counting `3 + index` would
 * under-report the output by more than eight times at the top of the range,
 * and the cap below would not be a cap. */
const LENGTH_BASE = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258,
]
const DIST_BASE = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
  3073, 4097, 6145, 8193, 12289, 16385, 24577,
]

const MAX_LITERAL_SYMBOLS = 286 // 0-285 are usable; 286 and 287 are reserved
const MAX_DISTANCE_SYMBOLS = 30 // 0-29 are usable; 30 and 31 are reserved

/** The stream is not a well-formed raw DEFLATE stream. */
class Invalid extends Error {
  constructor(readonly reason: string) {
    super(reason)
  }
}

/** The walk reached the caller's output cap; the caps decide from here. */
class PastCap extends Error {}

type Table = { counts: number[]; symbols: number[] }

/** Least-significant-bit-first reader over a byte range.
 *
 * Bit positions are kept in plain arithmetic rather than shifts: a stream may
 * be hundreds of megabytes, and a shift would silently wrap the offset into a
 * negative number past 2^31 bits. */
class Bits {
  position = 0
  constructor(private readonly data: Uint8Array) {}

  take(count: number): number {
    let value = 0
    for (let index = 0; index < count; index += 1) {
      const absolute = this.position + index
      const byteIndex = Math.floor(absolute / 8)
      if (byteIndex >= this.data.length) throw new Invalid('truncated')
      value |= ((this.data[byteIndex] >> absolute % 8) & 1) << index
    }
    this.position += count
    return value
  }

  /** Advance to the next byte boundary and return that byte offset. */
  align(): number {
    this.position = Math.ceil(this.position / 8) * 8
    return this.position / 8
  }

  seekByte(offset: number): void {
    this.position = offset * 8
  }
}

/** Canonical Huffman decoding tables (counts per length, symbols in order).
 *
 * Over-subscribed tables are refused. So are incomplete ones, with the single
 * exception the format allows and the reference decoder accepts: an alphabet
 * carrying at most one code, which is how an encoder says "unused". Refusing
 * that case would refuse ordinary archives; accepting any other incomplete
 * table would accept streams the reference decoder does not. */
function build(lengths: number[], what: string, degenerateOk: boolean): Table {
  const counts = new Array<number>(16).fill(0)
  for (const length of lengths) counts[length] += 1
  let left = 1
  for (let length = 1; length < 16; length += 1) {
    left <<= 1
    left -= counts[length]
    if (left < 0) throw new Invalid(`${what}-oversubscribed`)
  }
  const used = lengths.length - counts[0]
  if (left > 0 && !(degenerateOk && used <= 1)) throw new Invalid(`${what}-incomplete`)
  const offsets = new Array<number>(16).fill(0)
  for (let length = 1; length < 15; length += 1) offsets[length + 1] = offsets[length] + counts[length]
  const symbols = new Array<number>(lengths.length).fill(0)
  for (let symbol = 0; symbol < lengths.length; symbol += 1) {
    const length = lengths[symbol]
    if (length) {
      symbols[offsets[length]] = symbol
      offsets[length] += 1
    }
  }
  return { counts, symbols }
}

function decode(bits: Bits, table: Table): number {
  let code = 0
  let first = 0
  let index = 0
  for (let length = 1; length < 16; length += 1) {
    code |= bits.take(1)
    const count = table.counts[length]
    if (code - first < count) return table.symbols[index + (code - first)]
    index += count
    first = (first + count) << 1
    code <<= 1
  }
  throw new Invalid('code-not-in-table')
}

const FIXED_LITERALS = build(
  [
    ...new Array<number>(144).fill(8),
    ...new Array<number>(112).fill(9),
    ...new Array<number>(24).fill(7),
    ...new Array<number>(8).fill(8),
  ],
  'literal',
  false,
)
// The fixed distance alphabet is 32 five-bit codes, two of them reserved: the
// tree is complete, and codes 30 and 31 are refused where they are USED.
const FIXED_DISTANCES = build(new Array<number>(32).fill(5), 'distance', false)

function dynamicTables(bits: Bits): [Table, Table] {
  const literalCount = bits.take(5) + 257
  const distanceCount = bits.take(5) + 1
  const codeCount = bits.take(4) + 4
  if (literalCount > MAX_LITERAL_SYMBOLS || distanceCount > MAX_DISTANCE_SYMBOLS)
    throw new Invalid('dynamic-counts')
  const codeLengths = new Array<number>(19).fill(0)
  for (let index = 0; index < codeCount; index += 1) codeLengths[CLEN_ORDER[index]] = bits.take(3)
  const codeTable = build(codeLengths, 'code-length', false)

  const total = literalCount + distanceCount
  const lengths: number[] = []
  while (lengths.length < total) {
    const symbol = decode(bits, codeTable)
    if (symbol < 16) {
      lengths.push(symbol)
    } else if (symbol === 16) {
      if (lengths.length === 0) throw new Invalid('repeat-without-previous')
      const repeat = 3 + bits.take(2)
      const previous = lengths[lengths.length - 1]
      for (let index = 0; index < repeat; index += 1) lengths.push(previous)
    } else if (symbol === 17) {
      const repeat = 3 + bits.take(3)
      for (let index = 0; index < repeat; index += 1) lengths.push(0)
    } else {
      const repeat = 11 + bits.take(7)
      for (let index = 0; index < repeat; index += 1) lengths.push(0)
    }
  }
  if (lengths.length > total) throw new Invalid('code-lengths-overrun')
  return [
    build(lengths.slice(0, literalCount), 'literal', true),
    build(lengths.slice(literalCount), 'distance', true),
  ]
}

function walkHuffmanBlock(bits: Bits, tables: [Table, Table], produced: number, limit: number): number {
  const [literals, distances] = tables
  for (;;) {
    const symbol = decode(bits, literals)
    if (symbol < 256) {
      produced += 1
    } else if (symbol === 256) {
      return produced
    } else {
      const index = symbol - 257
      if (index >= LENGTH_EXTRA.length) throw new Invalid('reserved-length-symbol')
      const length = LENGTH_BASE[index] + bits.take(LENGTH_EXTRA[index])
      const distanceSymbol = decode(bits, distances)
      if (distanceSymbol >= DIST_EXTRA.length) throw new Invalid('reserved-distance-symbol')
      const distance = DIST_BASE[distanceSymbol] + bits.take(DIST_EXTRA[distanceSymbol])
      if (distance > produced) throw new Invalid('distance-before-output')
      produced += length
    }
    if (produced > limit) throw new PastCap()
  }
}

/**
 * A reason if `data` is not a well-formed raw DEFLATE stream, else `null`.
 *
 * `null` also means "the walk reached `limit` output bytes and stopped": past
 * the caller's cap both implementations refuse the member for the same reason,
 * so there is nothing left for this check to decide.
 */
export function deflateError(data: Uint8Array, limit: number): string | null {
  const bits = new Bits(data)
  let produced = 0
  try {
    for (;;) {
      const final = bits.take(1)
      const blockType = bits.take(2)
      if (blockType === 0) {
        const start = bits.align()
        if (start + 4 > data.length) throw new Invalid('truncated-stored-header')
        const length = data[start] | (data[start + 1] << 8)
        const nlength = data[start + 2] | (data[start + 3] << 8)
        if (nlength !== (~length & 0xffff)) throw new Invalid('stored-block-lengths')
        if (start + 4 + length > data.length) throw new Invalid('truncated-stored-data')
        bits.seekByte(start + 4 + length)
        produced += length
      } else if (blockType === 1) {
        produced = walkHuffmanBlock(bits, [FIXED_LITERALS, FIXED_DISTANCES], produced, limit)
      } else if (blockType === 2) {
        produced = walkHuffmanBlock(bits, dynamicTables(bits), produced, limit)
      } else {
        throw new Invalid('reserved-block-type')
      }
      if (final) return null
      if (produced > limit) return null
    }
  } catch (error) {
    if (error instanceof Invalid) return error.reason
    if (error instanceof PastCap) return null
    throw error
  }
}
