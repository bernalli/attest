// RFC 6962 Merkle-tree verification primitives and closed transparency-log
// entry schemas, plus C2SP hybrid signed-note checkpoints — mirrors
// src/attest/tlog.py (Python reference), VERIFY-ONLY. There is no
// buildTree/inclusionProof/consistencyProof/signCheckpoint here: those are
// Python-side builder functions with no untrusted-input boundary (used only
// by the reference implementation's own `gen_vectors`/CLI tooling) — this
// port ships only the fail-closed verification half.
//
// Verification here never trusts caller-declared shapes: proof elements are
// type/length-checked before use, and hash comparisons use a constant-time
// byte-equality (`equalBytes`) throughout, mirroring Python's
// `hmac.compare_digest`.
import { equalBytes, concatBytes, bytesToHex, hexToBytes } from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2'
import { JsonValue, canonicalBytes } from './canon.js'
import { verifyStrict as verifyEd25519Strict } from './ed25519.js'
import { verifyStrict as verifyMldsaStrict, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN } from './mldsa.js'
import {
  ERR,
  codePointLength,
  entryScalarExceeds,
  pyRepr,
  pyStage2StringRepr,
  pyTypeName,
  sliceCodePoints,
} from './messages.js'

const HASH_LEN = 32 // SHA-256 digest length in bytes
const MAX_JCS_INTEGER = 2 ** 53 - 1
const LEAF_PREFIX = Uint8Array.of(0x00) // RFC 6962 §2.1: MTH({d(0)}) = SHA-256(0x00 || d(0))
const NODE_PREFIX = Uint8Array.of(0x01) // RFC 6962 §2.1: MTH(D[n]) = SHA-256(0x01 || left || right)

const TYPE_KEY_MANIFEST = 'key-manifest'
const TYPE_RECEIPT = 'receipt'
const TYPE_REVOCATION_RECORD = 'revocation-record'
const TYPE_TRANSFER_RECORD = 'transfer-record'
const KEY_MANIFEST_FIELDS = new Set(['type', 'issuer', 'manifest_version', 'manifest_sha256'])
const RECEIPT_FIELDS = new Set(['type', 'issuer', 'core_sha256'])
const REVOCATION_RECORD_FIELDS = new Set(['type', 'issuer', 'record_sha256'])
const TRANSFER_RECORD_FIELDS = new Set(['type', 'issuer', 'record_sha256'])
// Mirrors tlog.py's `_MAX_ENTRY_SCALAR_LEN`: both cores bound free-text
// entry scalars before regex matching, diagnostic rendering, or JCS work.
const MAX_ENTRY_SCALAR_LEN = 500_000

// Same lowercase-DNS shape as the receipt schema's `issuer.id` pattern
// (src/attest/schema/attest-receipt.schema.json) — kept in sync by hand,
// this module has no schema-file dependency. Mirrors tlog.py's `_ISSUER_RE`.
const ISSUER_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/
const HEX64_RE = /^[0-9a-f]{64}$/

export class TlogError extends Error {}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

export function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF_PREFIX, data))
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(NODE_PREFIX, left, right))
}

// --------------------------------------------------------------------------
// Verification side: untrusted proof input, fail-closed, never throws.
// --------------------------------------------------------------------------

function validProofShape(proof: unknown): proof is Uint8Array[] {
  return Array.isArray(proof) && proof.every((p) => p instanceof Uint8Array && p.length === HASH_LEN)
}

/** RFC 6962 §2.1.1 inclusion proof verification, iterative.
 *
 * Fail-closed: any malformed argument (wrong types, out-of-range index,
 * wrongly-shaped proof elements, too-short/too-long proof) returns `false`
 * rather than throwing — `leaf`/`index`/`proof`/`root` all arrive from an
 * untrusted log server. `index`/`treeSize` are `bigint`, matching
 * `Checkpoint.treeSize`: a RFC 6962 tree can have up to 2**64-1 leaves,
 * which exceeds Number.MAX_SAFE_INTEGER, and this function is called
 * directly against checkpoint-derived sizes (`transparency.ts`'s
 * consistency-proof step), not only evidence-bounded ones. Callers holding
 * a "materialized" (plain-number, JSON-derived) size — the convention this
 * port otherwise uses for untrusted-evidence fields — convert via `BigInt()`
 * before calling.
 */
export function verifyInclusion(
  leaf: Uint8Array,
  index: bigint,
  treeSize: bigint,
  proof: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (!(leaf instanceof Uint8Array) || leaf.length !== HASH_LEN) return false
  if (!(root instanceof Uint8Array) || root.length !== HASH_LEN) return false
  if (typeof index !== 'bigint') return false
  if (typeof treeSize !== 'bigint') return false
  if (index < 0n || treeSize <= 0n || index >= treeSize) return false
  if (!validProofShape(proof)) return false

  let fn = index
  let sn = treeSize - 1n
  let computed = leaf
  for (const sibling of proof) {
    if (sn === 0n) return false // proof has more elements than the path to the root
    if (fn % 2n === 1n || fn === sn) {
      computed = nodeHash(sibling, computed)
      // `fn` was the lone (unpaired) rightmost node at this level: climb
      // without consuming further proof elements until it either becomes a
      // right child (a real sibling exists) or reaches root.
      while (fn % 2n === 0n && fn !== 0n) {
        fn = fn / 2n
        sn = sn / 2n
      }
    } else {
      computed = nodeHash(computed, sibling)
    }
    fn = fn / 2n
    sn = sn / 2n
  }
  return sn === 0n && equalBytes(computed, root)
}

/** RFC 6962 §2.1.2 consistency proof verification, iterative. Fail-closed:
 * any malformed argument returns `false` rather than throwing. `size1`/
 * `size2` are `bigint` — see `verifyInclusion`'s doc comment. */
export function verifyConsistency(
  size1: bigint,
  root1: Uint8Array,
  size2: bigint,
  root2: Uint8Array,
  proof: Uint8Array[],
): boolean {
  if (typeof size1 !== 'bigint') return false
  if (typeof size2 !== 'bigint') return false
  if (!(root1 instanceof Uint8Array) || root1.length !== HASH_LEN) return false
  if (!(root2 instanceof Uint8Array) || root2.length !== HASH_LEN) return false
  if (size1 < 0n || size2 < 0n || size1 > size2) return false
  if (!validProofShape(proof)) return false

  if (size1 === size2) return proof.length === 0 && equalBytes(root1, root2)
  if (size1 === 0n) return proof.length === 0

  let node = size1 - 1n
  let lastNode = size2 - 1n
  let idx = 0
  const nProof = proof.length

  while (node % 2n === 1n) {
    node = node / 2n
    lastNode = lastNode / 2n
  }

  let newHash: Uint8Array
  let oldHash: Uint8Array
  if (node > 0n) {
    if (idx >= nProof) return false
    newHash = proof[idx]!
    oldHash = proof[idx]!
    idx += 1
  } else {
    newHash = root1
    oldHash = root1
  }

  while (node > 0n) {
    if (node % 2n === 1n) {
      if (idx >= nProof) return false
      const sibling = proof[idx]!
      idx += 1
      newHash = nodeHash(sibling, newHash)
      oldHash = nodeHash(sibling, oldHash)
    } else if (node < lastNode) {
      if (idx >= nProof) return false
      const sibling = proof[idx]!
      idx += 1
      newHash = nodeHash(newHash, sibling)
    }
    node = node / 2n
    lastNode = lastNode / 2n
  }

  if (!equalBytes(oldHash, root1)) return false

  while (lastNode > 0n) {
    if (idx >= nProof) return false
    const sibling = proof[idx]!
    idx += 1
    newHash = nodeHash(newHash, sibling)
    lastNode = lastNode / 2n
  }

  if (idx !== nProof) return false // unconsumed proof elements
  return equalBytes(newHash, root2)
}

// --------------------------------------------------------------------------
// Closed log-entry schemas.
// --------------------------------------------------------------------------

function requireFields(entry: Record<string, unknown>, expected: Set<string>): void {
  const actual = Object.keys(entry)
  const actualSet = new Set(actual)
  const missing = [...expected].filter((k) => !actualSet.has(k)).sort()
  const extra = actual.filter((k) => !expected.has(k)).sort()
  if (missing.length > 0 || extra.length > 0) {
    throw new TlogError(`entry field mismatch: missing=${pyRepr(missing)} extra=${pyRepr(extra)}`)
  }
}

function requireEntryScalarBounds(entry: Record<string, unknown>): void {
  for (const field of Object.keys(entry)) {
    const value = entry[field]
    if (
      codePointLength(field) > MAX_ENTRY_SCALAR_LEN ||
      (typeof value === 'string' && codePointLength(value) > MAX_ENTRY_SCALAR_LEN)
    ) {
      throw new TlogError(entryScalarExceeds(MAX_ENTRY_SCALAR_LEN))
    }
  }
}

function requireIssuer(entry: Record<string, unknown>): void {
  const issuer = entry['issuer']
  if (typeof issuer !== 'string' || !ISSUER_RE.test(issuer)) {
    throw new TlogError(`issuer must be a lowercase DNS name: ${pyRepr(issuer)}`)
  }
}

function requireHex64(entry: Record<string, unknown>, field: string): void {
  const value = entry[field]
  if (typeof value !== 'string' || !HEX64_RE.test(value)) {
    throw new TlogError(`${field} must be 64 lowercase hex characters: ${pyRepr(value)}`)
  }
}

function requireManifestVersion(entry: Record<string, unknown>): void {
  const version = entry['manifest_version']
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 1 || version > MAX_JCS_INTEGER) {
    throw new TlogError(`manifest_version must be an int in [1, ${MAX_JCS_INTEGER}]: ${pyRepr(version)}`)
  }
}

/** Validate `entry` against a CLOSED schema and return its canonical
 * (attest-JCS) bytes — the exact bytes that get leaf-hashed into the log.
 *
 * Four entry types, exactly these members each (extras rejected):
 * - `key-manifest`: `{type, issuer, manifest_version, manifest_sha256}`.
 * - `receipt`: `{type, issuer, core_sha256}`.
 * - `revocation-record` (v0.2 §8, G5): `{type, issuer, record_sha256}`,
 *   where `record_sha256 = recordHash(record)` (revocation.ts) —
 *   `SHA-256(JCS(record))` over the entire signed revocation record.
 * - `transfer-record` (v0.2 §8/§17.1, Stage 3): `{type, issuer,
 *   record_sha256}`, where `record_sha256 = recordHash(record)`
 *   (transfer.ts) — `SHA-256(JCS(record))` over the entire signed transfer
 *   record, the same canonical form transfer.ts already builds and verifies
 *   the record's signature over.
 *
 * `entry` is untrusted evidence (the "materialized", plain-JS-number
 * convention this port uses — see `transparency.ts`): `manifest_version`
 * arrives as a `number`, which this function converts to `bigint` only once
 * validated in-range, immediately before the canon.ts JCS serializer (which
 * accepts only `bigint` for JSON integers) — the sole place the materialized
 * convention and the strict/bigint convention meet.
 */
export function encodeEntry(entry: unknown): Uint8Array {
  if (!isPlainObject(entry)) {
    throw new TlogError(`entry must be an object, got ${pyTypeName(entry)}`)
  }

  requireEntryScalarBounds(entry)
  const entryType = entry['type']
  if (entryType === TYPE_KEY_MANIFEST) {
    requireFields(entry, KEY_MANIFEST_FIELDS)
    requireIssuer(entry)
    requireManifestVersion(entry)
    requireHex64(entry, 'manifest_sha256')
  } else if (entryType === TYPE_RECEIPT) {
    requireFields(entry, RECEIPT_FIELDS)
    requireIssuer(entry)
    requireHex64(entry, 'core_sha256')
  } else if (entryType === TYPE_REVOCATION_RECORD) {
    requireFields(entry, REVOCATION_RECORD_FIELDS)
    requireIssuer(entry)
    requireHex64(entry, 'record_sha256')
  } else if (entryType === TYPE_TRANSFER_RECORD) {
    requireFields(entry, TRANSFER_RECORD_FIELDS)
    requireIssuer(entry)
    requireHex64(entry, 'record_sha256')
  } else {
    throw new TlogError(`unknown entry type: ${pyRepr(entryType)}`)
  }

  const canonicalEntry: Record<string, JsonValue> = Object.create(null)
  for (const k of Object.keys(entry)) {
    const v = entry[k]
    canonicalEntry[k] = k === 'manifest_version' ? BigInt(v as number) : (v as JsonValue)
  }
  return canonicalBytes(canonicalEntry)
}

// Domain-separated signed-receipt-core hash prefix (design doc fix 4) — the
// ONLY receipt-entry hash domain; see `receiptCoreHash`.
const RECEIPT_CORE_DOMAIN = new TextEncoder().encode('attest-receipt-core-v1\x00')

/** Domain-separated signed-receipt-core hash (design doc fix 4): `SHA-256(
 * "attest-receipt-core-v1\x00" || JCS(payload) || 0x00 || JCS(signatures))`.
 * `delivery` is deliberately excluded — deleting it never invalidates a
 * receipt's log entry. `envelope` must carry object member `payload` and
 * array member `signatures`, already strictly-parsed (bigint-typed) data —
 * this is trusted-input builder-side surface, like the rest of this
 * module's construction functions, not a fail-closed boundary over
 * untrusted data.
 */
export function receiptCoreHash(envelope: unknown): string {
  if (!isPlainObject(envelope)) {
    throw new TlogError(`envelope must be an object, got ${pyTypeName(envelope)}`)
  }
  const payload = envelope['payload']
  if (!isPlainObject(payload)) throw new TlogError(ERR.MISSING_PAYLOAD)
  const signatures = envelope['signatures']
  if (!Array.isArray(signatures)) throw new TlogError(ERR.MISSING_SIGNATURES)

  const digest = sha256(
    concatBytes(
      RECEIPT_CORE_DOMAIN,
      canonicalBytes(payload as JsonValue),
      Uint8Array.of(0x00),
      canonicalBytes(signatures as JsonValue),
    ),
  )
  return bytesToHex(digest)
}

// --------------------------------------------------------------------------
// Hybrid signed-note checkpoints (C2SP tlog-checkpoint profile, hybrid AND).
// --------------------------------------------------------------------------

// C2SP signed-note signature line: em dash U+2014, one space, name, one
// space, standard base64 (with padding) of the signature blob.
const SIG_LINE_RE = /^— ([^ ]+) ([A-Za-z0-9+/]+={0,2})$/
const DECIMAL_RE = /^[0-9]+$/
const KEY_HASH_LEN = 4 // C2SP signed-note key-hash prefix length, bytes
const ED25519_PUB_LEN = 32
const ED25519_SIG_LEN = 64
// C2SP signed-note type byte 0x01 identifies Ed25519. ML-DSA-65 has no
// assigned identifier byte, so it uses the registry's own extension
// mechanism: 0xff ("signature types without an identifier byte assigned by
// this specification") followed by a longer identifier unlikely to collide.
const ED25519_SIG_TYPE = Uint8Array.of(0x01)
const ML_DSA_65_SIG_TYPE = concatBytes(Uint8Array.of(0xff), new TextEncoder().encode('attest-ml-dsa-65'))
const MAX_TREE_SIZE = 2n ** 64n - 1n
// A uint64 can have at most 20 decimal digits.
const MAX_TREE_SIZE_DIGITS = 20
// C2SP recommends a signature limit while requiring acceptance of at least
// 16. Sixty-four leaves room for witness cosignatures without unbounded work.
const MAX_NOTE_SIGNATURES = 64
// Worst-case legitimate note is ~400KB: 3 header lines plus 64 ML-DSA-65
// signature lines at ~4.4KB base64 each.
const MAX_NOTE_TEXT_LEN = 500_000
const MAX_NOTE_LINES = 4 + MAX_NOTE_SIGNATURES
// Largest legitimate signature blob is 4 (key hash) + 3309 (ML-DSA-65) =
// 3313 bytes -> 4420 base64 chars; 8192 is generous headroom. Checked BEFORE
// base64-decoding so a hostile line cannot force a large allocation.
const MAX_SIG_B64_LEN = 8192
// A 32-byte root encodes to ceil(32 / 3) * 4 = exactly 44 base64 chars.
const MAX_ROOT_B64_LEN = 44

// Test-only visibility for hostile-input-bound tests (mirrors tlog.py's own
// tests reading `tlog._MAX_NOTE_LINES` etc. directly via module attribute
// access — TS has no leading-underscore privacy, so these are exported
// plainly but are NOT part of the package's public index.ts surface).
export const MAX_NOTE_LINES_ = MAX_NOTE_LINES
export const MAX_NOTE_TEXT_LEN_ = MAX_NOTE_TEXT_LEN
export const MAX_NOTE_SIGNATURES_ = MAX_NOTE_SIGNATURES
export const MAX_SIG_B64_LEN_ = MAX_SIG_B64_LEN
export const MAX_ROOT_B64_LEN_ = MAX_ROOT_B64_LEN
export const MAX_ENTRY_SCALAR_LEN_ = MAX_ENTRY_SCALAR_LEN

/** Bound an untrusted string's repr for an error message — slice BEFORE
 * repr so a multi-megabyte hostile field is never fully rendered. */
function truncRepr(value: string, limit = 80): string {
  if (codePointLength(value) <= limit) return pyStage2StringRepr(value)
  return pyStage2StringRepr(sliceCodePoints(value, limit)) + '…'
}

/** A parsed C2SP signed-note transparency-log checkpoint body. `noteBytes`
 * is exactly the bytes a note signature is computed over: the three header
 * lines (origin, tree size, base64 root) through their final newline,
 * excluding the blank line separating them from signatures. `treeSize` is
 * `bigint` (not `number`): the header's decimal size accepts the full uint64
 * range (up to 2**64-1), which exceeds Number.MAX_SAFE_INTEGER — this is the
 * one place in this port that is NOT the "materialized" plain-number
 * convention (see the module comment in transparency.ts).
 *
 * `signedNoteBytes` is the FULL checkpoint text as parsed — header lines,
 * blank line, AND every C2SP signature line, byte-for-byte the original
 * input to `parseCheckpoint`/`verifyCheckpoint` (never re-serialized).
 * `anchor.ts`'s v2 anchor profile (`"signed-note-v2"`, attest-v0.2.md
 * §11.1) commits an OTS op-chain over this instead of `noteBytes` alone,
 * closing the gap where a chosen note could be pre-anchored before it was
 * ever signed (TM-33's residual risk).
 */
export interface Checkpoint {
  origin: string
  treeSize: bigint
  root: Uint8Array
  noteBytes: Uint8Array
  signedNoteBytes: Uint8Array
}

/** A pinned transparency-log signing identity: one `name`, two legs. Ships
 * baked into the verifier's trust store — never taken from an untrusted
 * bundle (design doc "log keys pinned out-of-band"). */
export interface LogKey {
  origin: string
  name: string
  ed25519Pub: Uint8Array
  mldsaPub: Uint8Array
}

/** C2SP key ID: `SHA-256(name || "\n" || type || pub)[:4]`. Exported (not
 * re-exported from index.ts) purely so its exact formula is independently
 * unit-testable, like tlog.py's `_key_hash` KAT. */
export function keyHash(name: string, signatureType: Uint8Array, pub: Uint8Array): Uint8Array {
  return sha256(concatBytes(new TextEncoder().encode(name), Uint8Array.of(0x0a), signatureType, pub)).slice(
    0,
    KEY_HASH_LEN,
  )
}

export function validateOrigin(origin: unknown, field = 'origin'): string {
  if (typeof origin !== 'string' || origin.length === 0 || !hasOnlyAsciiChars(origin, 0x20, 0x7e)) {
    throw new TlogError(`${field} must be a non-empty printable ASCII str`)
  }
  return origin
}

function validateKeyName(name: unknown, field = 'name'): string {
  if (
    typeof name !== 'string' ||
    name.length === 0 ||
    name.includes('+') ||
    !hasOnlyAsciiChars(name, 0x21, 0x7e)
  ) {
    throw new TlogError(`${field} must be non-empty printable ASCII without '+'`)
  }
  return name
}

/** Return true iff every UTF-16 code unit is inside the required ASCII range.
 * This intentionally avoids Unicode properties: Stage-2 note grammar must
 * have the same verdict on every host Unicode database. */
function hasOnlyAsciiChars(value: string, min: number, max: number): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code < min || code > max) return false
  }
  return true
}

function validateBytes(value: unknown, field: string, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new TlogError(`${field} must be ${length} bytes`)
  }
  return value
}

function parseTreeSize(sizeStr: string): bigint {
  if (!DECIMAL_RE.test(sizeStr)) {
    throw new TlogError(`tree size must be ASCII decimal digits: ${truncRepr(sizeStr)}`)
  }
  if (codePointLength(sizeStr) > 1 && sizeStr.startsWith('0')) {
    throw new TlogError(`tree size must not contain leading zeros: ${truncRepr(sizeStr)}`)
  }
  if (codePointLength(sizeStr) > MAX_TREE_SIZE_DIGITS) {
    throw new TlogError(`tree size has too many digits (${codePointLength(sizeStr)}): ${truncRepr(sizeStr)}`)
  }
  const treeSize = BigInt(sizeStr)
  if (treeSize > MAX_TREE_SIZE) {
    throw new TlogError(`tree size must be a uint64: ${truncRepr(sizeStr)}`)
  }
  return treeSize
}

/** Encode C2SP note text: header lines including, not after, final LF. */
function buildNoteBytes(header: string[]): Uint8Array {
  return new TextEncoder().encode(header.join('\n') + '\n')
}

/** Validate every pinned-key field before cryptographic verification. */
export function validateLogKey(logKey: unknown): LogKey {
  if (!isPlainObject(logKey)) throw new TlogError('log_key must be a LogKey')
  const origin = validateOrigin(logKey['origin'], 'log_key.origin')
  const name = validateKeyName(logKey['name'], 'log_key.name')
  const ed25519Pub = validateBytes(logKey['ed25519Pub'], 'log_key.ed25519_pub', ED25519_PUB_LEN)
  const mldsaPub = validateBytes(logKey['mldsaPub'], 'log_key.mldsa_pub', ML_DSA_65_PK_LEN)
  return { origin, name, ed25519Pub, mldsaPub }
}

function decodeStdBase64Strict(s: string): Uint8Array | null {
  // Standard (padded) base64, NOT base64url — b64u.ts's helpers are the wrong
  // alphabet for a C2SP note. Charset + padding shape checked BEFORE atob, so
  // a hostile string can't slip through as "close enough".
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) return null
  try {
    const bin = atob(s)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

function encodeStdBase64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

/** Split raw checkpoint `text` into its 3 header lines and its signature
 * lines, validating the C2SP note shape only (never field contents). */
function splitNote(text: unknown): { header: string[]; sigLines: string[] } {
  if (typeof text !== 'string') {
    throw new TlogError(`checkpoint text must be a str, got ${pyTypeName(text)}`)
  }
  if (!text.endsWith('\n')) throw new TlogError('checkpoint text must end with a newline')
  if (codePointLength(text) > MAX_NOTE_TEXT_LEN) {
    throw new TlogError(`checkpoint text exceeds ${MAX_NOTE_TEXT_LEN} chars`)
  }
  let newlineCount = 0
  for (const ch of text) if (ch === '\n') newlineCount++
  if (newlineCount > MAX_NOTE_LINES) {
    throw new TlogError(`checkpoint text has too many lines (max ${MAX_NOTE_LINES})`)
  }
  const lines = text.split('\n')
  lines.pop() // drop the "" produced by the trailing \n
  if (lines.length < 4) throw new TlogError('checkpoint text is too short for a header plus blank line')
  const header = lines.slice(0, 3)
  const rest = lines.slice(3)
  if (rest[0] !== '') throw new TlogError('checkpoint header must be followed by a blank line')
  return { header, sigLines: rest.slice(1) }
}

/** Parse each `— <name> <base64(blob)>` line into `(name, blob)`. */
function parseSignatureLines(lines: string[]): Array<[string, Uint8Array]> {
  if (lines.length === 0) throw new TlogError('checkpoint must contain at least one signature line')
  if (lines.length > MAX_NOTE_SIGNATURES) {
    throw new TlogError(`checkpoint has too many signature lines (max ${MAX_NOTE_SIGNATURES})`)
  }
  const parsed: Array<[string, Uint8Array]> = []
  for (const line of lines) {
    const m = SIG_LINE_RE.exec(line)
    if (m === null) throw new TlogError(`malformed checkpoint signature line: ${truncRepr(line)}`)
    const name = m[1]!
    const blobB64 = m[2]!
    validateKeyName(name, 'signature key name')
    if (codePointLength(blobB64) > MAX_SIG_B64_LEN) {
      throw new TlogError(`signature blob exceeds ${MAX_SIG_B64_LEN} base64 chars`)
    }
    const blob = decodeStdBase64Strict(blobB64)
    if (blob === null) throw new TlogError(`signature blob is not valid base64: ${truncRepr(blobB64)}`)
    parsed.push([name, blob])
  }
  return parsed
}

/** Shared parse core for `parseCheckpoint`/`verifyCheckpoint`. */
function parseCore(text: unknown): { checkpoint: Checkpoint; signatures: Array<[string, Uint8Array]> } {
  const { header, sigLines } = splitNote(text)
  const [originRaw, sizeStr, rootB64] = header as [string, string, string]
  const origin = validateOrigin(originRaw)
  const treeSize = parseTreeSize(sizeStr)
  if (codePointLength(rootB64) > MAX_ROOT_B64_LEN) {
    throw new TlogError(`root exceeds ${MAX_ROOT_B64_LEN} base64 chars`)
  }
  const root = decodeStdBase64Strict(rootB64)
  if (root === null) throw new TlogError(`root is not valid base64: ${truncRepr(rootB64)}`)
  if (root.length !== HASH_LEN) {
    throw new TlogError(`root must decode to ${HASH_LEN} bytes, got ${root.length}`)
  }
  const signatures = parseSignatureLines(sigLines)
  const noteBytes = buildNoteBytes(header)
  // `text` is guaranteed a string here (splitNote already threw otherwise).
  // It is NOT pure ASCII (each C2SP signature line opens with the em dash
  // U+2014, a 3-byte UTF-8 sequence) but IS valid UTF-8 by construction
  // (origin/tree-size/root/signature-line grammar each already constrain
  // their slice of it to printable ASCII) — this is the original input
  // bytes back, not a re-serialization.
  const signedNoteBytes = new TextEncoder().encode(text as string)
  return { checkpoint: { origin, treeSize, root, noteBytes, signedNoteBytes }, signatures }
}

/** Parse a C2SP signed-note checkpoint body. Structural/shape validation
 * only — no signature is checked here, see `verifyCheckpoint`. */
/** Parse a signed note's `[name, blob]` signature lines.
 *
 * Throws on a malformed note, exactly as `parseCore` does — a caller holding
 * an already-verified checkpoint cannot hit that path, and one that has
 * verified nothing should not be reading signature lines as if they meant
 * something. Mirrors `tlog.note_signatures` in the Python core. */
export function noteSignatures(text: unknown): Array<[string, Uint8Array]> {
  return parseCore(text).signatures
}

export function parseCheckpoint(text: unknown): Checkpoint {
  return parseCore(text).checkpoint
}

/** Verify a checkpoint's hybrid signed-note signature and origin binding.
 *
 * Fail-closed AND (design doc "checkpoint auth is hybrid, mandatory"):
 * standing requires BOTH an Ed25519 AND an ML-DSA-65 signature line by
 * `logKey.name`, each verifying over `checkpoint.noteBytes` against the
 * matching leg's pinned public key, AND `checkpoint.origin` must equal both
 * `expectedOrigin` and `logKey.origin`. Throws `TlogError` (never returns a
 * falsy value) on any parse error, origin mismatch, or missing/invalid
 * signature leg.
 */
export function verifyCheckpoint(text: unknown, logKey: unknown, expectedOrigin: unknown): Checkpoint {
  const validatedLogKey = validateLogKey(logKey)
  const validatedExpectedOrigin = validateOrigin(expectedOrigin, 'expected_origin')

  const { checkpoint, signatures } = parseCore(text)
  if (checkpoint.origin !== validatedExpectedOrigin) {
    throw new TlogError(
      `checkpoint origin ${pyRepr(checkpoint.origin)} != expected_origin ${pyRepr(validatedExpectedOrigin)}`,
    )
  }
  if (checkpoint.origin !== validatedLogKey.origin) {
    throw new TlogError(
      `checkpoint origin ${pyRepr(checkpoint.origin)} != log_key.origin ${pyRepr(validatedLogKey.origin)}`,
    )
  }

  const edPrefix = keyHash(validatedLogKey.name, ED25519_SIG_TYPE, validatedLogKey.ed25519Pub)
  const mldsaPrefix = keyHash(validatedLogKey.name, ML_DSA_65_SIG_TYPE, validatedLogKey.mldsaPub)
  let edOk = false
  let mldsaOk = false
  for (const [name, blob] of signatures) {
    if (name !== validatedLogKey.name) continue // signed-note convention: unknown names are skipped, not fatal
    if (blob.length === KEY_HASH_LEN + ED25519_SIG_LEN && equalBytes(blob.subarray(0, KEY_HASH_LEN), edPrefix)) {
      if (verifyEd25519Strict(checkpoint.noteBytes, blob.subarray(KEY_HASH_LEN), validatedLogKey.ed25519Pub)) {
        edOk = true
      }
    } else if (
      blob.length === KEY_HASH_LEN + ML_DSA_65_SIG_LEN &&
      equalBytes(blob.subarray(0, KEY_HASH_LEN), mldsaPrefix)
    ) {
      if (verifyMldsaStrict(checkpoint.noteBytes, blob.subarray(KEY_HASH_LEN), validatedLogKey.mldsaPub)) {
        mldsaOk = true
      }
    }
    if (edOk && mldsaOk) break
  }

  if (!(edOk && mldsaOk)) {
    throw new TlogError(
      `checkpoint has no valid Ed25519+ML-DSA-65 signature pair for name ${pyRepr(validatedLogKey.name)}`,
    )
  }
  return checkpoint
}

// Re-exported for test fixtures that need to render a hex string identically
// to how Python's tests do (`bytes.hex()`), without importing noble directly.
export { bytesToHex, hexToBytes }
