import { inflateSync } from 'node:zlib'

// A PNG reader for exactly what Playwright's screenshot() produces: 8-bit
// RGB/RGBA, non-interlaced. Written here rather than pulled in, because a new
// dependency on this repo opens the SBOM and licence gates for both published
// packages — a disproportionate price for unfiltering five scanline types.
//
// It exists because this site's contrast cannot be judged from the stylesheet.
// The paper is a fixed texture of five composited layers, so the colour under
// a glyph depends on where that glyph happens to sit in the viewport, and two
// independent measurements of the same variable already disagreed — one
// composited every layer at full alpha, the other argued that point is
// unreachable. Neither looked at a rendered pixel. This does.

export interface Bitmap {
  width: number
  height: number
  /** RGBA, four bytes per pixel, row-major. */
  data: Uint8Array
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]

const paeth = (a: number, b: number, c: number): number => {
  const p = a + b - c
  const pa = Math.abs(p - a)
  const pb = Math.abs(p - b)
  const pc = Math.abs(p - c)
  if (pa <= pb && pa <= pc) return a
  return pb <= pc ? b : c
}

export function decodePng(png: Buffer): Bitmap {
  for (let i = 0; i < PNG_SIGNATURE.length; i += 1) {
    if (png[i] !== PNG_SIGNATURE[i]) throw new Error('not a PNG')
  }
  let width = 0
  let height = 0
  let colourType = -1
  const idat: Buffer[] = []
  let at = 8
  while (at < png.length) {
    const length = png.readUInt32BE(at)
    const type = png.toString('ascii', at + 4, at + 8)
    const body = png.subarray(at + 8, at + 8 + length)
    if (type === 'IHDR') {
      width = body.readUInt32BE(0)
      height = body.readUInt32BE(4)
      if (body[8] !== 8) throw new Error(`unsupported bit depth ${body[8]}`)
      colourType = body[9]
      if (body[12] !== 0) throw new Error('interlaced PNG is not supported')
    } else if (type === 'IDAT') {
      idat.push(body)
    } else if (type === 'IEND') {
      break
    }
    at += 12 + length
  }
  if (colourType !== 2 && colourType !== 6) {
    throw new Error(`unsupported colour type ${colourType}`)
  }
  const channels = colourType === 6 ? 4 : 3
  const stride = width * channels
  const raw = inflateSync(Buffer.concat(idat))
  // A pixel stream shorter than IHDR promises would otherwise read as
  // `undefined`, land as 0 after the mask, and print pure BLACK into the
  // darkest-pixel search — a contrast failure invented by the reader rather
  // than found on the page.
  if (raw.length !== height * (stride + 1)) {
    throw new Error(`truncated pixel data: ${raw.length} bytes for ${height} rows of ${stride}`)
  }
  const out = new Uint8Array(width * height * 4)
  const line = new Uint8Array(stride)
  const prev = new Uint8Array(stride)
  let src = 0
  for (let y = 0; y < height; y += 1) {
    const filter = raw[src]
    src += 1
    for (let i = 0; i < stride; i += 1) {
      const x = raw[src + i]
      const a = i >= channels ? line[i - channels] : 0
      const b = prev[i]
      const c = i >= channels ? prev[i - channels] : 0
      let value: number
      if (filter === 0) value = x
      else if (filter === 1) value = x + a
      else if (filter === 2) value = x + b
      else if (filter === 3) value = x + ((a + b) >> 1)
      else if (filter === 4) value = x + paeth(a, b, c)
      else throw new Error(`unknown PNG filter ${filter}`)
      line[i] = value & 0xff
    }
    src += stride
    for (let x = 0; x < width; x += 1) {
      const o = (y * width + x) * 4
      out[o] = line[x * channels]
      out[o + 1] = line[x * channels + 1]
      out[o + 2] = line[x * channels + 2]
      out[o + 3] = channels === 4 ? line[x * channels + 3] : 255
    }
    prev.set(line)
  }
  return { width, height, data: out }
}

export const pixelAt = (bitmap: Bitmap, x: number, y: number): [number, number, number] => {
  // Out of range must throw, not read past the buffer: the channels would come
  // back `undefined`, `contrast` would return NaN, and `NaN < floor` is FALSE —
  // so a target sampled outside the screenshot would pass the contrast gate in
  // silence. A measurement that fails safe is worth less than none.
  if (x < 0 || y < 0 || x >= bitmap.width || y >= bitmap.height) {
    throw new RangeError(`pixel ${x},${y} is outside a ${bitmap.width}x${bitmap.height} bitmap`)
  }
  const o = (y * bitmap.width + x) * 4
  return [bitmap.data[o], bitmap.data[o + 1], bitmap.data[o + 2]]
}

const channel = (c: number): number => {
  const v = c / 255
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
}

/** WCAG 2.x relative luminance. */
export const luminance = ([r, g, b]: [number, number, number]): number =>
  0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)

export function contrast(a: [number, number, number], b: [number, number, number]): number {
  const la = luminance(a)
  const lb = luminance(b)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}

/** `rgb(r, g, b)` / `rgba(r, g, b, a)` as getComputedStyle returns it. */
export function parseColour(css: string): [number, number, number] {
  const m = /rgba?\(([^)]+)\)/.exec(css)
  if (!m) throw new Error(`cannot read colour ${css}`)
  const parts = m[1].split(/[,/\s]+/).filter(Boolean).map(Number)
  // Ink the browser blends with the paper behind it cannot be measured as if
  // it were opaque: dropping the alpha reports a ratio that is too GOOD, and
  // too good is the one direction this measurement must never fail in.
  if (parts.length > 3 && parts[3] !== 1) {
    throw new Error(`cannot measure a partly transparent ink: ${css}`)
  }
  return [parts[0], parts[1], parts[2]]
}
