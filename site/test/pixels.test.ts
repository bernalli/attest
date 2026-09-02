import { describe, it, expect } from 'vitest'
import { deflateSync, crc32 } from 'node:zlib'
import { decodePng, pixelAt, contrast, luminance, parseColour } from '../e2e/helpers/pixels.js'

// The contrast measurement in e2e/contrast.spec.ts believes whatever this
// decoder says a pixel is. It is hand-written - five scanline predictors, two
// colour types - so an unfiltering slip would move every published ratio by a
// plausible-looking amount rather than failing outright. These vectors are
// built here by an independent encoder, so the two have to agree.

const SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]

const chunk = (type: string, body: Buffer): Buffer => {
  const len = Buffer.alloc(4)
  len.writeUInt32BE(body.length)
  const tagged = Buffer.concat([Buffer.from(type, 'ascii'), body])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(tagged) >>> 0)
  return Buffer.concat([len, tagged, crc])
}

const ihdr = (w: number, h: number, colour: number, depth = 8, interlace = 0): Buffer => {
  const b = Buffer.alloc(13)
  b.writeUInt32BE(w, 0)
  b.writeUInt32BE(h, 4)
  b[8] = depth
  b[9] = colour
  b[12] = interlace
  return b
}

const paeth = (a: number, b: number, c: number): number => {
  const p = a + b - c
  const pa = Math.abs(p - a)
  const pb = Math.abs(p - b)
  const pc = Math.abs(p - c)
  if (pa <= pb && pa <= pc) return a
  return pb <= pc ? b : c
}

interface EncodeOptions {
  idatParts?: number
  extra?: [string, Buffer][]
  interlace?: number
  colour?: number
  depth?: number
}

/** Encode rows of flat samples, applying the requested filter to each row. */
const encode = (w: number, h: number, ch: number, rows: number[][], filters: number[], opts: EncodeOptions = {}): Buffer => {
  const colour = opts.colour ?? (ch === 4 ? 6 : 2)
  const parts: Buffer[] = []
  let prev = new Array<number>(w * ch).fill(0)
  for (let y = 0; y < h; y += 1) {
    const line = rows[y]
    const f = filters[y]
    const out = Buffer.alloc(1 + w * ch)
    out[0] = f
    for (let i = 0; i < w * ch; i += 1) {
      const a = i >= ch ? line[i - ch] : 0
      const b = prev[i]
      const c = i >= ch ? prev[i - ch] : 0
      const x = line[i]
      const v = f === 0 ? x : f === 1 ? x - a : f === 2 ? x - b : f === 3 ? x - ((a + b) >> 1) : x - paeth(a, b, c)
      out[1 + i] = v & 0xff
    }
    parts.push(out)
    prev = line
  }
  const comp = deflateSync(Buffer.concat(parts))
  const n = opts.idatParts ?? 1
  const size = Math.ceil(comp.length / n)
  const idats: Buffer[] = []
  for (let i = 0; i < n; i += 1) idats.push(chunk('IDAT', comp.subarray(i * size, (i + 1) * size)))
  return Buffer.concat([
    Buffer.from(SIGNATURE),
    chunk('IHDR', ihdr(w, h, colour, opts.depth ?? 8, opts.interlace ?? 0)),
    ...(opts.extra ?? []).map(([t, b]) => chunk(t, b)),
    ...idats,
    chunk('IEND', Buffer.alloc(0)),
  ])
}

/** Deterministic pseudo-random samples: every predictor gets a different answer. */
const samples = (n: number, seed: number): number[] => {
  const out: number[] = []
  let s = seed
  for (let i = 0; i < n; i += 1) {
    s = (s * 1103515245 + 12345) & 0x7fffffff
    out.push((s >> 16) & 0xff)
  }
  return out
}

const readBack = (bm: { width: number; height: number; data: Uint8Array }, w: number, h: number): number[][] => {
  const rows: number[][] = []
  for (let y = 0; y < h; y += 1) {
    const row: number[] = []
    for (let x = 0; x < w; x += 1) row.push(...pixelAt(bm, x, y))
    rows.push(row)
  }
  return rows
}

const rows3 = (w: number, h: number, seed: number): number[][] =>
  Array.from({ length: h }, (_, y) => samples(w * 3, seed + y))

describe('the PNG decoder the contrast measurement reads pixels through', () => {
  it('round-trips every scanline filter, RGB', () => {
    const rows = rows3(17, 5, 1789)
    const bm = decodePng(encode(17, 5, 3, rows, [0, 1, 2, 3, 4]))
    expect([bm.width, bm.height]).toEqual([17, 5])
    expect(readBack(bm, 17, 5)).toEqual(rows)
  })

  it('round-trips paeth on every row, where the tie-break rule lives', () => {
    const rows = rows3(17, 5, 4001)
    expect(readBack(decodePng(encode(17, 5, 3, rows, [4, 4, 4, 4, 4])), 17, 5)).toEqual(rows)
  })

  it('round-trips RGBA, where the predictor offsets shift by a channel', () => {
    const rows = Array.from({ length: 7 }, (_, y) => samples(13 * 4, 77 + y))
    const bm = decodePng(encode(13, 7, 4, rows, [0, 1, 2, 3, 4, 1, 4]))
    expect(readBack(bm, 13, 7)).toEqual(rows.map((r) => r.filter((_, i) => i % 4 !== 3)))
  })

  it('reads a single pixel, where a, b and c are all off the edge', () => {
    expect(pixelAt(decodePng(encode(1, 1, 3, [[10, 20, 30]], [4])), 0, 0)).toEqual([10, 20, 30])
  })

  it('reassembles pixels split across several IDAT chunks, as a screenshot is', () => {
    const rows = rows3(17, 5, 55)
    expect(readBack(decodePng(encode(17, 5, 3, rows, [0, 1, 2, 3, 4], { idatParts: 4 })), 17, 5)).toEqual(rows)
  })

  it('skips ancillary chunks instead of reading them as pixels', () => {
    const rows = rows3(17, 5, 91)
    const extra: [string, Buffer][] = [
      ['pHYs', Buffer.from([0, 0, 11, 19, 0, 0, 11, 19, 1])],
      ['tEXt', Buffer.from('Comment hi', 'latin1')],
    ]
    expect(readBack(decodePng(encode(17, 5, 3, rows, [0, 1, 2, 3, 4], { extra })), 17, 5)).toEqual(rows)
  })

  // --- not well formed. Each of these must fail loudly: a decoder that
  // guesses returns plausible numbers attached to a wrong verdict.
  const twoRows = (): number[][] => [samples(9, 5), samples(9, 6)]

  it.each([
    ['a corrupted signature', (): Buffer => {
      const b = Buffer.from(encode(3, 2, 3, twoRows(), [0, 1]))
      b[2] = 0x58
      return b
    }],
    ['an undefined scanline filter', (): Buffer => encode(3, 2, 3, twoRows(), [5, 0])],
    ['16-bit samples', (): Buffer => encode(3, 2, 3, twoRows(), [0, 0], { depth: 16 })],
    ['an interlaced image', (): Buffer => encode(3, 2, 3, twoRows(), [0, 0], { interlace: 1 })],
    ['greyscale, which has no colour channels to read', (): Buffer => encode(3, 2, 1, [[1, 2, 3], [4, 5, 6]], [0, 0], { colour: 0 })],
    ['a palette, whose samples are indices and not colours', (): Buffer => encode(3, 2, 1, [[0, 1, 2], [0, 1, 2]], [0, 0], { colour: 3 })],
    ['no IHDR at all', (): Buffer => Buffer.concat([
      Buffer.from(SIGNATURE),
      chunk('IDAT', deflateSync(Buffer.from([0, 1, 2, 3]))),
      chunk('IEND', Buffer.alloc(0)),
    ])],
    ['an IHDR claiming more rows than the pixel data carries', (): Buffer => Buffer.concat([
      Buffer.from(SIGNATURE),
      chunk('IHDR', ihdr(3, 50, 2)),
      chunk('IDAT', deflateSync(Buffer.from([0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9]))),
      chunk('IEND', Buffer.alloc(0)),
    ])],
  ])('refuses %s', (_label, build) => {
    expect(() => decodePng(build())).toThrow()
  })

  it('refuses a pixel stream that stops mid-scanline instead of padding it with black', () => {
    // Every filter byte survives here; only the last three samples are gone.
    // Unguarded they read as undefined, become 0, and turn the darkest pixel
    // of a band pure black - a contrast failure invented by the reader.
    const raw: number[] = []
    for (let y = 0; y < 4; y += 1) raw.push(0, ...new Array<number>(12).fill(200))
    const png = Buffer.concat([
      Buffer.from(SIGNATURE),
      chunk('IHDR', ihdr(4, 4, 2)),
      chunk('IDAT', deflateSync(Buffer.from(raw.slice(0, raw.length - 3)))),
      chunk('IEND', Buffer.alloc(0)),
    ])
    expect(() => decodePng(png)).toThrow(/truncated/i)
  })
})

describe('the WCAG arithmetic the verdict rests on', () => {
  it('matches the published extremes and a known mid ratio', () => {
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5)
    expect(contrast([255, 255, 255], [255, 255, 255])).toBeCloseTo(1, 5)
    expect(contrast([0x77, 0x77, 0x77], [255, 255, 255])).toBeCloseTo(4.48, 2)
  })

  it('is symmetric, so which colour is called the ink cannot change the answer', () => {
    expect(contrast([101, 87, 62], [240, 230, 210])).toBeCloseTo(contrast([240, 230, 210], [101, 87, 62]), 10)
  })

  it('puts luminance on the sRGB curve, not on a linear ramp', () => {
    expect(luminance([255, 255, 255])).toBeCloseTo(1, 10)
    expect(luminance([0, 0, 0])).toBeCloseTo(0, 10)
    expect(luminance([128, 128, 128])).toBeCloseTo(0.2159, 3)
  })
})

describe('reading a colour back out of getComputedStyle', () => {
  it('reads the two forms the browser actually returns', () => {
    expect(parseColour('rgb(101, 87, 62)')).toEqual([101, 87, 62])
    expect(parseColour('rgb(101 87 62)')).toEqual([101, 87, 62])
  })

  it('refuses a colour it cannot read rather than inventing one', () => {
    expect(() => parseColour('transparent')).toThrow()
    expect(() => parseColour('color(srgb 0.4 0.34 0.24)')).toThrow()
  })

  it('refuses a partly transparent ink, which it cannot measure as printed', () => {
    // Dropping alpha reports the ink at full strength against paper the
    // browser actually blends it with, so the ratio comes out too GOOD - the
    // one direction this measurement must never fail in.
    expect(() => parseColour('rgba(101, 87, 62, 0.5)')).toThrow(/transparent/i)
    expect(parseColour('rgba(101, 87, 62, 1)')).toEqual([101, 87, 62])
  })
})

describe('reading a pixel that is not in the bitmap', () => {
  // `pixelAt` is the one function the measurement calls per pixel, and an
  // out-of-range read used to come back as three `undefined`s: `contrast`
  // then returns NaN, and `NaN < floor` is FALSE, so a target sampled outside
  // the screenshot passed the gate in silence. A measurement that fails safe
  // is worth less than no measurement.
  const bitmap = { width: 2, height: 2, data: new Uint8Array(2 * 2 * 4).fill(0x80) }

  it.each([
    ['past the right edge', 2, 0],
    ['past the bottom edge', 0, 2],
    ['left of the origin', -1, 0],
    ['above the origin', 0, -1],
  ])('refuses a pixel %s', (_why, x, y) => {
    expect(() => pixelAt(bitmap, x, y)).toThrow(RangeError)
  })

  it('reads every pixel that IS in the bitmap', () => {
    for (const [x, y] of [[0, 0], [1, 0], [0, 1], [1, 1]]) {
      expect(pixelAt(bitmap, x, y)).toEqual([0x80, 0x80, 0x80])
    }
  })
})
