import { duplicateKey, notUtf8, invalidJson, intOutOfRange, codePointLength, ERR } from './messages.js'

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

// ---- v0.2 §18.4: the admission boundary, shared by every rail ----
//
// These primitives live HERE, in the leaf module, because more than one rail
// admits caller-supplied evidence and every one of them must admit it the SAME
// WAY. A second spelling of a boundary is a boundary that will diverge, so the
// boundary has exactly one spelling and every rail imports it. §18.4 states the
// rule; this module is where the rule is executed.
//
// WHY RECONSTRUCTION IS MANDATORY HERE AND NOT MERELY PRUDENT. In Python a
// container's own data can be read through the base class (`dict.items`,
// `list.__getitem__`), so a hostile subclass can be stepped around. In
// JavaScript there is NO such spelling: a Proxy intercepts `Reflect` and
// `Object.*` alike, so nothing this module does can guarantee that the value it
// reads is the value the caller "really" holds. What it CAN guarantee, and what
// §18.4 actually requires, is that the read happens ONCE, is bounded, sees only
// DATA properties, and that everything downstream reads the reconstruction and
// never the live object again.
//
// Stated as the limit rather than left to be discovered: a Proxy whose
// `getOwnPropertyDescriptor` trap answers with a DATA descriptor is admitted,
// and deliberately so. Its value is copied like any other own data, and if what
// it hands over is a genuinely signed document it earns exactly the verdict
// that document earns — the same one the caller would get by passing it
// plainly, which anyone holding it can already do. A proxy is not evidence of
// hostility. What WOULD be is a value that verifies as one thing and is
// consumed as another, and that is what the single read closes, here, for
// every rail. That is what closes the verify/consume split:
// the bytes a signature is checked over and the values consumed afterwards come
// from one reconstruction, whatever the caller's object did during it.

// The ceiling a single admitted unit's canonical form may occupy (v0.2 §6.3).
// Measured in CODE POINTS of that canonical JSON text, not in encoded UTF-8
// bytes. The identifier is historical and does not define the measurement unit.
// One definition for the whole package: the transparency evidence bound, the
// transfer-view bound and the transfer-evidence bound are the same number, and
// a number restated three times is a number that will drift.
export const MAX_ADMISSION_BYTES = 10_000_000

// Node budget for the own-data copy. It can never change an admissible/
// inadmissible answer: every node costs at least one byte of canonical form, so
// a structure over this many nodes cannot fit under the code-point ceiling either. It
// only makes the refusal REACHABLE, before an unbounded container has been
// walked to the end.
export const MAX_ADMISSION_NODES = MAX_ADMISSION_BYTES

// How many of the enclosing VIEW's containers a value sits inside: a member of
// a view object is one deep, an element of a view object's array is two. The
// depth ceiling is measured over the canonicalized view AS A WHOLE (§18.4), so
// a document admitted at its own top level would be allowed 256 levels where
// the view only allows it 254.
export const VIEW_MEMBER_NESTING = 1
export const VIEW_ARRAY_ELEMENT_NESTING = 2

/**
 * What a rail may say about how its own view is written.
 *
 * The boundary is one rule; this is the one place a rail's own DECLARED shape
 * changes what "representable" means for it, and it is deliberately narrow.
 */
export interface AdmissionOptions {
  /**
   * Read a safe-integer JS `number` as the integer it denotes.
   *
   * Off by default: what reaches a rail off the wire has been strict-parsed and
   * carries `bigint`, so a `number` there means the caller parsed with
   * `JSON.parse` and the unit is not in the profile. A rail whose view is
   * routinely HAND-WRITTEN in JavaScript turns it on, because JSON has no
   * bigint literal and the same evidence must not decide differently for having
   * been typed out rather than parsed.
   */
  acceptSafeIntegerNumbers?: boolean
}

export const VIEW_MEMBER_ABSENT = Symbol('view member absent')
export const VIEW_MEMBER_COLLAPSED = Symbol('view member collapsed')

/**
 * The array's own `length` DATA, or null if it has none that makes sense.
 *
 * `value.length` goes through a `get` trap and `for (const x of value)` through
 * the iterator, both of which a caller controls; an unbounded one never returns
 * and no ceiling downstream ever gets to fire. The own descriptor is read once
 * and the elements are then taken by index.
 */
export function ownArrayLength(value: unknown): number | null {
  if (!Array.isArray(value)) return null
  // The descriptor read is itself caller code on a Proxy: a throwing trap must
  // fail CLOSED here, not escape into a caller that only expects a number.
  let descriptor: PropertyDescriptor | undefined
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, 'length')
  } catch {
    return null
  }
  if (descriptor === undefined || !('value' in descriptor)) return null
  const length: unknown = descriptor.value
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) return null
  return length
}

/**
 * Copy a caller-supplied value's OWN DATA into plain types.
 *
 * Only DATA properties are copied: a member defined as a getter is not own
 * data, it is code, and running it is exactly what this boundary exists to
 * avoid. `Object.getOwnPropertyDescriptor` is what tells the two apart;
 * inherited members are never own data and are not copied either.
 *
 * Integers arrive as `bigint` — the profile's only numeric type — and a JS
 * `number` is refused rather than coerced. Coercing would silently admit a
 * float, and the whole point of the integer-only profile is that a float is not
 * representable.
 *
 * The budget refuses on a node count rather than after the work is already
 * done: a lazy or unbounded container would otherwise run to the end (that is,
 * never) before any code-point ceiling could fire.
 */
export function ownDataCopy(
  value: unknown,
  budget: { left: number },
  options: AdmissionOptions = {},
): JsonValue {
  budget.left -= 1
  if (budget.left < 0) throw new CanonError('value exceeds the admission node budget')
  if (value === null) return null
  const t = typeof value
  if (t === 'boolean' || t === 'string' || t === 'bigint') return value as JsonValue
  if (t === 'number') {
    // A JS number is not the profile's integer, and by default a unit carrying
    // one is not representable and is set aside. But a rail whose view is
    // routinely written BY HAND in JavaScript has no way to spell a bigint
    // literal in JSON, and refusing it there would make the same evidence
    // decide differently depending on how the caller happened to parse it —
    // which is the divergence this boundary exists to remove, not one it may
    // introduce. Such a rail says so, and then a SAFE INTEGER is read as the
    // integer it denotes. Anything else stays refused: a float, a NaN and a
    // magnitude past exact representation are values the profile cannot
    // express, whoever supplies them.
    if (!options.acceptSafeIntegerNumbers) throw new CanonError(ERR.TYPE_NOT_JSON)
    if (!Number.isSafeInteger(value as number)) throw new CanonError(ERR.TYPE_NOT_JSON)
    return BigInt(value as number)
  }
  if (Array.isArray(value)) {
    const out: JsonValue[] = []
    // `length` is read once, from the own descriptor, and the elements by
    // index: a lazy iterator never gets to run, and an element defined as a
    // getter is not data and is not admitted.
    const length = ownArrayLength(value)
    if (length === null) throw new CanonError(ERR.TYPE_NOT_JSON)
    for (let i = 0; i < length; i++) {
      const element = Object.getOwnPropertyDescriptor(value, String(i))
      if (element === undefined || !('value' in element)) throw new CanonError(ERR.TYPE_NOT_JSON)
      out.push(ownDataCopy(element.value, budget, options))
    }
    return out
  }
  if (t === 'object') {
    const out: JsonObject = Object.create(null) as JsonObject
    for (const key of Object.getOwnPropertyNames(value as object)) {
      const descriptor = Object.getOwnPropertyDescriptor(value as object, key)
      if (descriptor === undefined || !('value' in descriptor)) continue
      if (!descriptor.enumerable) continue
      out[key] = ownDataCopy(descriptor.value, budget, options)
    }
    return out
  }
  throw new CanonError(ERR.TYPE_NOT_JSON)
}

/**
 * Admit a caller-supplied value by the shared reconstruction boundary.
 *
 * `nesting` is how many of the enclosing VIEW's containers this value sits
 * inside, so the depth ceiling is measured where §18.4 measures it. Admitting
 * an element at its OWN top level and only discovering the excess when the
 * whole view is re-canonicalized would discard the element's SIBLINGS too,
 * where §18.4 requires the one inadmissible unit to be set aside on its own.
 *
 * The returned value is the reconstruction and nothing else.
 */
export function admitValue(
  value: unknown,
  nesting = 0,
  options: AdmissionOptions = {},
): { admitted: boolean; value: JsonValue } {
  let probe: unknown = value
  for (let i = 0; i < nesting; i++) probe = [probe]
  try {
    const serialized = dumps(ownDataCopy(probe, { left: MAX_ADMISSION_NODES }, options))
    // The ceiling is measured on the UNIT, not on the probe. The probe exists
    // to put the unit at its real depth in the view, and each wrapper adds
    // exactly the two code points `[` and `]` — so a unit sitting exactly AT the
    // ceiling would otherwise read as two code points over per nesting level and
    // be refused for the position it occupies rather than for its size.
    const measured = codePointLength(serialized) - 2 * nesting
    if (measured > MAX_ADMISSION_BYTES) return { admitted: false, value: null }
    let materialized = loadsStrict(new TextEncoder().encode(serialized))
    for (let i = 0; i < nesting; i++) materialized = (materialized as JsonValue[])[0]!
    return { admitted: true, value: materialized }
  } catch {
    // Every throw from the walk lands here, a hostile trap's included: §18.4's
    // reconstruction fails CLOSED, it never propagates out of the boundary.
    return { admitted: false, value: null }
  }
}

export function materializeValue(
  value: unknown,
  nesting = 0,
  options: AdmissionOptions = {},
): JsonValue | null {
  const admission = admitValue(value, nesting, options)
  return admission.admitted ? admission.value : null
}

/**
 * Find a rail-defined member by its OWN key data, never by a plain lookup.
 *
 * A plain `view[member]` read goes through the object's `get` trap, so a Proxy
 * can answer with something that is not the member at all. Comparing the OWN
 * property names against the member name removes the steering: the comparison
 * sees stored names only. Two names that collapse onto one member make that
 * member inadmissible rather than letting insertion order pick a winner.
 */
export function ownViewMember(
  view: object,
  member: string,
  budget?: { left: number },
): unknown | typeof VIEW_MEMBER_ABSENT | typeof VIEW_MEMBER_COLLAPSED {
  // `getOwnPropertyNames` and `getOwnPropertyDescriptor` are trap surfaces: on a
  // Proxy they run the caller's code. This function is used on units that have
  // ALREADY been refused, purely to decide a diagnostic, so a throw here must
  // fail closed rather than escape a boundary the unit was already set aside by.
  try {
    let found: unknown = VIEW_MEMBER_ABSENT
    for (const key of Object.getOwnPropertyNames(view)) {
      if (budget !== undefined) {
        // A unit that is ALREADY inadmissible must not be able to buy unbounded
        // work with the diagnostic read that follows it.
        budget.left -= 1
        if (budget.left < 0) return VIEW_MEMBER_COLLAPSED
      }
      if (key !== member) continue
      const descriptor = Object.getOwnPropertyDescriptor(view, key)
      // Non-enumerable members are absent from the canonical form, so the main
      // boundary never admits them; the diagnostic read must agree, or it would
      // speak for a member the boundary itself does not see.
      if (descriptor === undefined || !('value' in descriptor) || !descriptor.enumerable) continue
      if (found !== VIEW_MEMBER_ABSENT) return VIEW_MEMBER_COLLAPSED
      found = descriptor.value
    }
    return found
  } catch {
    return VIEW_MEMBER_COLLAPSED
  }
}

/**
 * Admit an array-valued rail or member PER ELEMENT (§18.4).
 *
 * The member itself is inadmissible only for a property of the MEMBER: its own
 * array data cannot be read, it is not an array, or its element count exceeds
 * the member's ceiling. An element that is not admissible is set aside alone
 * and no element's admissibility decides another's.
 */
export function materializeArray(
  value: unknown,
  ceiling: number,
  options: AdmissionOptions = {},
): (JsonValue | null)[] | null {
  if (!Array.isArray(value)) return null
  try {
    const count = ownArrayLength(value)
    if (count === null) return null
    if (count > ceiling) {
      // A count-ceiling excess is NOT "one bad element": §18.4 makes it
      // truncate evaluation fail-closed, and the predicate that does so judges
      // COUNT alone. Dropping the member here would leave the view with the
      // member ABSENT, which reads as "within every ceiling" and would FORGIVE
      // the excess. Report the excess instead, with placeholders and no
      // per-element work, so the ceiling check still fires before any signature
      // is verified.
      return new Array<JsonValue | null>(ceiling + 1).fill(null)
    }
    const out: (JsonValue | null)[] = []
    for (let i = 0; i < count; i++) {
      const element = Object.getOwnPropertyDescriptor(value, String(i))
      const supplied = element !== undefined && 'value' in element ? element.value : undefined
      out.push(materializeValue(supplied, VIEW_ARRAY_ELEMENT_NESTING, options))
    }
    return out
  } catch {
    return null
  }
}
