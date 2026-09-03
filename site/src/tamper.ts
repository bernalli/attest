import { loadsStrict } from 'attest-verifier'
import type { JsonObject, TrustStore } from 'attest-verifier'
import { EMPTY_TRUST } from './intake.js'

// The bench that lets a visitor break a receipt and watch the verifier notice.
//
// Two rules hold this file together, and both exist so the page demonstrates
// rather than asserts:
//
//  1. A byte tamper changes EXACTLY ONE BYTE of the envelope, at an offset it
//     reports, and says which character was there and which is there now. A
//     re-serialised object would be a different demonstration — "we rewrote
//     the file and it stopped verifying" is a much weaker claim than "we
//     turned one letter and it stopped verifying".
//  2. The replacement stays inside the same character class as the byte it
//     replaces. Dropping a random byte into a base64url signature, or into
//     the middle of a multi-byte character, breaks the file at PARSING — and
//     the reader then watches a story about encoding instead of one about
//     signatures. So a target with no ASCII letter or digit to turn is not
//     offered at all.
//
// Nothing here is a special path: the tampered bytes go back through the same
// `runVerify` the dropzone uses, with the same pinned configuration.

export type TamperId = 'title' | 'store-name' | 'receipt-id' | 'signature' | 'drop-manifest'

export interface TamperOption {
  id: TamperId
  label: string
  /** One line, in the reader's words, saying what the button is about to do. */
  what: string
}

export interface ByteEdit {
  /** Where the edited value lives inside the envelope, for the curious. */
  path: string
  /** Absolute byte offset in the envelope — checkable with any hex editor. */
  offset: number
  before: string
  after: string
  /** The whole string value, before and after the single-character turn. */
  was: string
  now: string
}

export interface Tampered {
  option: TamperOption
  envelopeBytes: Uint8Array
  trustStore: TrustStore
  /** null when nothing in the FILE changed — `drop-manifest` is that case. */
  edit: ByteEdit | null
}

/** Where each byte target lives, and how to say it out loud. */
interface ByteTarget {
  id: TamperId
  label: string
  what: string
  path: string
  /** Reads the target string out of a parsed envelope, or null if absent. */
  read: (envelope: JsonObject) => string | null
}

const asObject = (v: unknown): JsonObject | null =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null)

const payloadField = (envelope: JsonObject, ...path: string[]): string | null => {
  let node = asObject(envelope['payload'])
  for (const key of path.slice(0, -1)) {
    if (!node) return null
    node = asObject(node[key])
  }
  return node ? str(node[path[path.length - 1]]) : null
}

const BYTE_TARGETS: ByteTarget[] = [
  {
    id: 'title',
    label: 'Change one letter of the title',
    what: 'Turns a single letter in the name of the thing that was bought.',
    path: 'payload.work.title',
    read: (e) => payloadField(e, 'work', 'title'),
  },
  {
    id: 'store-name',
    label: 'Change one letter of the seller’s name',
    what: 'Turns a single letter in the display name the seller signed.',
    path: 'payload.issuer.display_name',
    read: (e) => payloadField(e, 'issuer', 'display_name'),
  },
  {
    id: 'receipt-id',
    label: 'Change one character of the receipt id',
    what: 'Turns a single character of the identifier this receipt was issued under.',
    path: 'payload.receipt_id',
    read: (e) => payloadField(e, 'receipt_id'),
  },
  {
    id: 'signature',
    label: 'Corrupt one character of the signature',
    what: 'Leaves every word of the receipt alone and turns one character of the signature instead.',
    path: 'signatures[0].sig',
    read: (e) => {
      const sigs = e['signatures']
      if (!Array.isArray(sigs) || sigs.length === 0) return null
      const first = asObject(sigs[0])
      return first ? str(first['sig']) : null
    },
  },
]

const DROP_MANIFEST: TamperOption = {
  id: 'drop-manifest',
  label: 'Take away the seller’s published keys',
  what:
    'Changes nothing in the file. Hides the key manifest the bundle carries, so the verifier ' +
    'no longer holds the material the signature has to be checked against.',
}

/** Every tamper this bench knows how to perform, in the order it offers them. */
export const TAMPERS: TamperOption[] = [
  ...BYTE_TARGETS.map(({ id, label, what }) => ({ id, label, what })),
  DROP_MANIFEST,
]

const parse = (bytes: Uint8Array): JsonObject | null => {
  try {
    return asObject(loadsStrict(bytes))
  } catch {
    return null
  }
}

/** Every index at which `needle` occurs in `haystack`, in order. */
function indexesOfBytes(haystack: Uint8Array, needle: Uint8Array): number[] {
  const out: number[] = []
  if (needle.length === 0 || needle.length > haystack.length) return out
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (haystack[i + j] !== needle[j]) continue outer
    out.push(i)
  }
  return out
}

const isAsciiAlnum = (byte: number): boolean =>
  (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a)

/** The next character in the same class, wrapping — so the byte always moves. */
function successor(byte: number): number {
  if (byte >= 0x30 && byte <= 0x39) return byte === 0x39 ? 0x30 : byte + 1
  if (byte >= 0x41 && byte <= 0x5a) return byte === 0x5a ? 0x41 : byte + 1
  return byte === 0x7a ? 0x61 : byte + 1
}

interface Turn {
  offset: number
  before: number
  after: number
  /** The target's value read back out of the EDITED document. */
  now: string
}

/** A single-byte turn that provably lands inside this target's own value.
 *
 * The value is still located by its own bytes — the bytes on screen must be
 * the bytes that were verified — but a string can occur more than once in an
 * envelope, and `work.title` is very nearly the LAST member JCS orders: a
 * title that also appears inside `work.publisher`, `work.artifact_series` or
 * an artifact filename would be edited THERE while the page went on naming
 * `payload.work.title`. So every occurrence is tried, and one is accepted
 * only when re-reading the EDITED document through the target's own accessor
 * shows the change.
 *
 * That re-read is also where `now` comes from: deriving it by slicing the
 * string would use a BYTE index as a UTF-16 index, and fabricate a value for
 * any string carrying a non-ASCII character in front of the byte that turned.
 */
function locateTurn(
  envelopeBytes: Uint8Array,
  target: ByteTarget,
  value: string,
): Turn | null {
  const valueBytes = new TextEncoder().encode(value)
  let k = -1
  for (let i = 0; i < valueBytes.length; i += 1) {
    if (isAsciiAlnum(valueBytes[i])) {
      k = i
      break
    }
  }
  // No ASCII letter or digit to turn: the target is not offered at all.
  if (k < 0) return null
  for (const start of indexesOfBytes(envelopeBytes, valueBytes)) {
    // The target's value is a whole JSON string token in the document, so it is
    // delimited by quotes. A run of the same bytes inside a longer string can
    // never be it, and re-parsing the envelope for each one costs the page
    // seconds: measured at 29s on a 91KB receipt whose title is a single common
    // letter. Nothing is lost — a value containing `"` or `\` is escaped on the
    // wire and has no byte-for-byte match at all, so the real occurrence is
    // always the quoted one.
    if (envelopeBytes[start - 1] !== 0x22 || envelopeBytes[start + valueBytes.length] !== 0x22) {
      continue
    }
    const offset = start + k
    const before = envelopeBytes[offset]
    const after = successor(before)
    const edited = new Uint8Array(envelopeBytes)
    edited[offset] = after
    const parsed = parse(edited)
    if (!parsed) continue
    const now = target.read(parsed)
    if (now === null || now === value) continue
    return { offset, before, after, now }
  }
  return null
}

/** The tampers that can be performed on THIS receipt, and only those. */
export function tamperOptions(envelopeBytes: Uint8Array): TamperOption[] {
  const envelope = parse(envelopeBytes)
  if (!envelope) return []
  const available = BYTE_TARGETS.filter((target) => {
    const value = target.read(envelope)
    return value !== null && locateTurn(envelopeBytes, target, value) !== null
  }).map(({ id, label, what }) => ({ id, label, what }))
  return [...available, DROP_MANIFEST]
}

export function applyTamper(
  id: TamperId,
  envelopeBytes: Uint8Array,
  trustStore: TrustStore,
): Tampered | null {
  if (id === 'drop-manifest') {
    return { option: DROP_MANIFEST, envelopeBytes, trustStore: EMPTY_TRUST, edit: null }
  }
  const envelope = parse(envelopeBytes)
  if (!envelope) return null
  const target = BYTE_TARGETS.find((t) => t.id === id)
  if (!target) return null
  const value = target.read(envelope)
  if (value === null) return null
  const spot = locateTurn(envelopeBytes, target, value)
  if (spot === null) return null

  const bytes = new Uint8Array(envelopeBytes)
  bytes[spot.offset] = spot.after

  return {
    option: { id: target.id, label: target.label, what: target.what },
    envelopeBytes: bytes,
    trustStore,
    edit: {
      path: target.path,
      offset: spot.offset,
      before: String.fromCharCode(spot.before),
      after: String.fromCharCode(spot.after),
      was: value,
      now: spot.now,
    },
  }
}
