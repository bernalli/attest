import { duplicateKey, notUtf8, invalidJson, intOutOfRange, ERR } from './messages.js'

export class CanonError extends Error {}

export type JsonValue = null | boolean | bigint | string | JsonValue[] | JsonObject
export interface JsonObject { [k: string]: JsonValue }

// ---- strict recursive-descent parser (replaces JSON.parse) ----
// Cap nesting so untrusted input cannot overflow the native call stack (which
// would throw a non-CanonError RangeError). 256 is a huge margin over real attest
// receipts (~4-5 deep) yet far below the JS stack limit, keeping the parsed tree
// shallow enough that rejectSurrogates and the Task 5 serializer recurse safely.
// Public (2026-07-22 fix wave): the single normative nesting-depth ceiling
// attest-versioning.md §5's structural-ceilings amendment (v0.1 §11.3)
// refers to -- schema.ts's MAX_JSON_DEPTH aliases this rather than defining
// a second, smaller one.
// Enforced at BOTH ends of the profile, in parity with the Python
// `canon.MAX_DEPTH`: `serialize` refuses one level past it with the parser's
// own literal, so no conforming issuer can sign a document no conforming
// parser will accept, and a deep or cyclic structure from a caller dies as a
// CanonError at the ceiling rather than as a native RangeError at the stack.
export const MAX_DEPTH = 256
class Reader {
  i = 0
  depth = 0
  constructor(readonly s: string) {}
  err(msg: string): never { throw new CanonError(invalidJson(`${msg} at ${this.i}`)) }
  ws() { while (this.i < this.s.length && ' \t\n\r'.includes(this.s[this.i]!)) this.i++ }
  end() { this.ws(); if (this.i !== this.s.length) this.err('trailing content') }
}

function parseValue(r: Reader): JsonValue {
  r.ws()
  const c = r.s[r.i]
  if (c === undefined) r.err('unexpected end')
  if (c === '{') return parseObject(r)
  if (c === '[') return parseArray(r)
  if (c === '"') return parseString(r)
  if (c === '-' || (c >= '0' && c <= '9')) return parseNumber(r)
  if (r.s.startsWith('true', r.i)) { r.i += 4; return true }
  if (r.s.startsWith('false', r.i)) { r.i += 5; return false }
  if (r.s.startsWith('null', r.i)) { r.i += 4; return null }
  // NaN / Infinity / -Infinity and anything else are invalid JSON
  r.err(`unexpected token '${c}'`)
}

function parseObject(r: Reader): JsonObject {
  if (++r.depth > MAX_DEPTH) r.err('maximum nesting depth exceeded')
  r.i++ // {
  const obj: JsonObject = Object.create(null)
  const seen = new Set<string>()
  r.ws()
  if (r.s[r.i] === '}') { r.i++; r.depth--; return obj }
  for (;;) {
    r.ws()
    if (r.s[r.i] !== '"') r.err('expected object key')
    const key = parseString(r)
    if (seen.has(key)) throw new CanonError(duplicateKey(key))
    seen.add(key)
    r.ws()
    if (r.s[r.i] !== ':') r.err("expected ':'")
    r.i++
    obj[key] = parseValue(r)
    r.ws()
    const d = r.s[r.i]
    if (d === ',') { r.i++; continue }
    if (d === '}') { r.i++; r.depth--; return obj }
    r.err("expected ',' or '}'")
  }
}

function parseArray(r: Reader): JsonValue[] {
  if (++r.depth > MAX_DEPTH) r.err('maximum nesting depth exceeded')
  r.i++ // [
  const arr: JsonValue[] = []
  r.ws()
  if (r.s[r.i] === ']') { r.i++; r.depth--; return arr }
  for (;;) {
    arr.push(parseValue(r))
    r.ws()
    const d = r.s[r.i]
    if (d === ',') { r.i++; continue }
    if (d === ']') { r.i++; r.depth--; return arr }
    r.err("expected ',' or ']'")
  }
}

function parseString(r: Reader): string {
  r.i++ // opening quote
  let out = ''
  for (;;) {
    const c = r.s[r.i]
    if (c === undefined) r.err('unterminated string')
    if (c === '"') { r.i++; return out }
    if (c === '\\') {
      const e = r.s[r.i + 1]
      switch (e) {
        case '"': out += '"'; r.i += 2; break
        case '\\': out += '\\'; r.i += 2; break
        case '/': out += '/'; r.i += 2; break
        case 'b': out += '\b'; r.i += 2; break
        case 'f': out += '\f'; r.i += 2; break
        case 'n': out += '\n'; r.i += 2; break
        case 'r': out += '\r'; r.i += 2; break
        case 't': out += '\t'; r.i += 2; break
        case 'u': {
          const hex = r.s.slice(r.i + 2, r.i + 6)
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) r.err('bad \\u escape')
          out += String.fromCharCode(parseInt(hex, 16))
          r.i += 6
          break
        }
        default: r.err('bad escape')
      }
    } else if (c.charCodeAt(0) < 0x20) {
      r.err('unescaped control character')
    } else {
      out += c; r.i++
    }
  }
}

const NUM_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/
function parseNumber(r: Reader): bigint {
  const m = NUM_RE.exec(r.s.slice(r.i))
  if (!m) r.err('bad number')
  const tok = m[0]
  if (tok.includes('.') || tok.includes('e') || tok.includes('E'))
    throw new CanonError(ERR.FLOATS_NOT_ALLOWED)
  r.i += tok.length
  return BigInt(tok) // full precision; range check deferred to canonicalBytes
}

// ---- post-parse lone-surrogate rejection (catches \uXXXX-injected surrogates) ----
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i)
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const lo = s.charCodeAt(i + 1)
      if (lo >= 0xdc00 && lo <= 0xdfff) { i++; continue }
      return true
    }
    if (cp >= 0xdc00 && cp <= 0xdfff) return true
  }
  return false
}
function rejectSurrogates(v: JsonValue): void {
  if (typeof v === 'string') { if (hasLoneSurrogate(v)) throw new CanonError(ERR.LONE_SURROGATE) }
  else if (Array.isArray(v)) v.forEach(rejectSurrogates)
  else if (v !== null && typeof v === 'object') {
    for (const k of Object.keys(v)) {
      if (hasLoneSurrogate(k)) throw new CanonError(ERR.LONE_SURROGATE)
      rejectSurrogates(v[k]!)
    }
  }
}

export function loadsStrict(bytes: Uint8Array): JsonValue {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
  } catch (e) {
    throw new CanonError(notUtf8(e instanceof Error ? e.message : String(e)))
  }
  // Backstop the CanonError-only contract that Task 12's verify() relies on:
  // remap any residual non-CanonError (e.g. RangeError from an oversized BigInt
  // token) into a CanonError. The depth cap already prevents native stack
  // overflow, so this is belt-and-suspenders for anything the parser doesn't
  // surface as a CanonError itself.
  try {
    const r = new Reader(text)
    const value = parseValue(r)
    r.end()
    rejectSurrogates(value)
    return value
  } catch (e) {
    if (e instanceof CanonError) throw e
    throw new CanonError(invalidJson(e instanceof Error ? e.message : String(e)))
  }
}

// ---- JCS canonical serializer (the ONLY byte form that is signed/verified) ----
const INT_MAX = 2n ** 53n
const SHORT_ESCAPES: Record<number, string> = {
  0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\',
}

function serializeString(s: string): string {
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i)
    if (cp >= 0xd800 && cp <= 0xdfff) {
      const lo = s.charCodeAt(i + 1)
      if (cp <= 0xdbff && lo >= 0xdc00 && lo <= 0xdfff) { out += s[i]! + s[i + 1]!; i++; continue }
      throw new CanonError(ERR.LONE_SURROGATE)
    }
    const esc = SHORT_ESCAPES[cp]
    if (esc !== undefined) out += esc
    else if (cp < 0x20) out += '\\u' + cp.toString(16).padStart(4, '0')
    else out += s[i]!
  }
  return out + '"'
}

function serialize(v: JsonValue, depth = 1): string {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'bigint') {
    if (!(-INT_MAX < v && v < INT_MAX)) throw new CanonError(intOutOfRange(v))
    return v.toString()
  }
  if (typeof v === 'string') return serializeString(v)
  if (Array.isArray(v)) {
    if (depth > MAX_DEPTH) throw new CanonError(ERR.MAX_NESTING_DEPTH)
    // Explicit arrow, never `v.map(serialize)`: map would pass the ELEMENT
    // INDEX as the depth argument and the ceiling would move per element.
    return '[' + v.map((x) => serialize(x, depth + 1)).join(',') + ']'
  }
  if (typeof v === 'object') {
    if (depth > MAX_DEPTH) throw new CanonError(ERR.MAX_NESTING_DEPTH)
    // JS Array.prototype.sort default compares by UTF-16 code units == Python utf-16-be byte order.
    const keys = Object.keys(v).sort()
    return '{' + keys.map((k) => serializeString(k) + ':' + serialize(v[k]!, depth + 1)).join(',') + '}'
  }
  throw new CanonError(ERR.TYPE_NOT_JSON)
}

export function dumps(v: JsonValue): string { return serialize(v) }
export function canonicalBytes(v: JsonValue): Uint8Array { return new TextEncoder().encode(dumps(v)) }
