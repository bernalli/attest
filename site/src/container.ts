// One canonical reading of a `.attest` container (v0.1 §14.1).
//
// A `.attest` file is a ZIP archive, and "which members does this archive hold"
// has more than one answer. Two widely used readers address the central
// directory differently: one takes the end-of-central-directory record's
// declared offset literally and iterates its 16-bit entry counter, the other
// ignores both and places the directory immediately before that record. An
// archive can therefore present one member list to one conforming verifier and
// a different member list to another — same bytes, two receipts — and no guard
// built on top of either reader can see it, because each reader measures the
// archive in its own model.
//
// This module removes the choice of model instead of picking one. It reads the
// container itself, in a fixed order, and refuses every archive in which the
// two addressings could disagree. `src/attest/container.py` is the same
// algorithm, step for step, with the same codes and the same messages: the
// `// S1` … `// S23` comments here and the `# S1` … `# S23` comments there mark
// the correspondence, and the shared corpus in `tests/container-corpus/` is
// what keeps the two honest.
//
// The only thing left to the ZIP library is raw DEFLATE decoding, at offsets
// this module names.

import { Inflate } from 'fflate'
import { deflateError } from './deflate.js'

/** Slice of compressed input fed to the decoder at a time. Identical on both
 * sides so the worst burst before a cap fires is the same in both languages. */
export const INFLATE_SLICE = 65536

const LFH_SIG = 0x04034b50
const CD_SIG = 0x02014b50
const EOCD_SIG = 0x06054b50
const ZIP64_LOCATOR_SIG = 0x07064b50
const EOCD_SIZE = 22
const CD_FIXED = 46
const LFH_FIXED = 30
const ZIP64_LOCATOR_SIZE = 20
const U16_SENTINEL = 0xffff
const U32_SENTINEL = 0xffffffff

/** The closed error taxonomy, in the order the reader checks for it. */
export const CODES = [
  'too-short',
  'eocd-not-last',
  'eocd-comment-length',
  'multi-disk',
  'zip64',
  'entry-counters-disagree',
  'too-many-entries',
  'directory-misplaced',
  'directory-record-signature',
  'directory-record-overrun',
  'directory-trailing-bytes',
  'record-comment',
  'record-multi-disk',
  'record-encrypted',
  'record-method',
  'record-zip64',
  'record-name-empty',
  'record-name-encoding',
  'duplicate-name',
  'record-stored-size',
  'local-header-out-of-range',
  'local-header-signature',
  'local-name-mismatch',
  'member-data-out-of-range',
  'declared-member-over-cap',
  'declared-total-over-cap',
  'member-over-cap',
  'total-over-cap',
  'member-size-mismatch',
  'member-crc-mismatch',
  'member-inflate-error',
] as const

export type ContainerCode = (typeof CODES)[number]

const NOT_CANONICAL = 'container is not in canonical form — '

/** Message per code. A message never carries attacker-supplied text: the member
 * name travels as a structured field, and the caller decides how to render it
 * (these strings reach a buyer's screen verbatim). */
export const MESSAGES: Record<ContainerCode, string> = {
  'too-short': 'not a readable zip archive — shorter than an end-of-central-directory record',
  'eocd-not-last': NOT_CANONICAL + 'the end-of-central-directory record is not the last 22 bytes of the file',
  'eocd-comment-length': NOT_CANONICAL + 'the end-of-central-directory record declares a comment',
  'multi-disk': NOT_CANONICAL + 'multi-disk archive fields are set',
  zip64: NOT_CANONICAL + 'ZIP64 structures are present',
  'entry-counters-disagree': NOT_CANONICAL + 'the two entry counters disagree',
  'too-many-entries': 'bundle declares over {max_entries} entries — refusing a possible zip bomb',
  'directory-misplaced':
    NOT_CANONICAL + 'the central directory does not end where the end-of-central-directory record begins',
  'directory-record-signature': NOT_CANONICAL + 'a central-directory record is missing its signature',
  'directory-record-overrun': NOT_CANONICAL + 'a central-directory record runs past the directory',
  'directory-trailing-bytes': NOT_CANONICAL + 'the central directory holds bytes after its last record',
  'record-comment': NOT_CANONICAL + 'a central-directory record declares a comment',
  'record-multi-disk': NOT_CANONICAL + 'a member is declared on another disk',
  'record-encrypted': NOT_CANONICAL + 'a member is encrypted',
  'record-method': NOT_CANONICAL + 'a member uses a compression method other than stored or deflate',
  'record-zip64': NOT_CANONICAL + 'a member carries ZIP64 sentinel values',
  'record-name-empty': NOT_CANONICAL + 'a member has an empty name',
  'record-name-encoding':
    NOT_CANONICAL + 'a member name is not valid UTF-8, or is non-ASCII without the UTF-8 flag',
  'duplicate-name':
    'bundle central directory repeats member name(s) — refusing to import: duplicated members shadow each other',
  'record-stored-size': NOT_CANONICAL + 'a stored member declares two different sizes',
  'local-header-out-of-range': NOT_CANONICAL + "a member's local header lies outside the member area",
  'local-header-signature': NOT_CANONICAL + "a member's local header is missing its signature",
  'local-name-mismatch':
    NOT_CANONICAL + "a member's local header names a different file than the directory does",
  'member-data-out-of-range': NOT_CANONICAL + "a member's data runs into the central directory",
  'declared-member-over-cap': 'a member is over the per-member decompression cap — refusing a possible zip bomb',
  'declared-total-over-cap': 'bundle is over the aggregate decompression cap — refusing a possible zip bomb',
  'member-over-cap': 'a member inflated past the per-member cap — refusing a possible zip bomb',
  'total-over-cap': 'bundle inflated past the aggregate cap — refusing a possible zip bomb',
  'member-size-mismatch': 'a member inflated to a different size than its directory record declares',
  'member-crc-mismatch': 'a member failed its CRC-32 check',
  'member-inflate-error': 'a member is not a valid deflate stream',
}

export interface ContainerCaps {
  maxEntries: number
  maxMemberBytes: number
  maxTotalBytes: number
}

/** Tighter than the reference importer on purpose: this runs in a browser tab. */
export const DEFAULT_CONTAINER_CAPS: ContainerCaps = {
  maxEntries: 10_000,
  maxMemberBytes: 64 * 1024 * 1024,
  maxTotalBytes: 256 * 1024 * 1024,
}

/** One member, as the central directory declares it. Nothing else from the
 * record is kept; `extra` is skipped by length and never parsed. */
export interface Member {
  name: string
  method: 0 | 8
  crc32: number
  compressedSize: number
  uncompressedSize: number
  dataStart: number
}

export class ContainerError extends Error {
  readonly code: ContainerCode
  readonly member: string | null

  constructor(code: ContainerCode, member: string | null = null, maxEntries?: number) {
    const message =
      maxEntries === undefined
        ? MESSAGES[code]
        : MESSAGES[code].replace('{max_entries}', String(maxEntries))
    super(message)
    this.name = 'ContainerError'
    this.code = code
    this.member = member
  }
}

/** The decompression budget for one import, shared across every member. */
export class ReadBudget {
  spent = 0
  constructor(
    readonly maxMemberBytes: number,
    readonly maxTotalBytes: number,
  ) {}
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let index = 0; index < 256; index += 1) {
    let value = index
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1
    table[index] = value >>> 0
  }
  return table
})()

/** CRC-32 of `data`, resumable through `value`. fflate exports no checksum, and
 * the reference importer checks one, so this reader carries its own. */
export function crc32(data: Uint8Array, value = 0): number {
  let state = (value ^ 0xffffffff) >>> 0
  for (let index = 0; index < data.length; index += 1) {
    state = (CRC_TABLE[(state ^ data[index]) & 0xff] ^ (state >>> 8)) >>> 0
  }
  return (state ^ 0xffffffff) >>> 0
}

const u16 = (view: DataView, offset: number): number => view.getUint16(offset, true)
const u32 = (view: DataView, offset: number): number => view.getUint32(offset, true)

const sameBytes = (bytes: Uint8Array, a: number, b: number, length: number): boolean => {
  for (let index = 0; index < length; index += 1) if (bytes[a + index] !== bytes[b + index]) return false
  return true
}

// ZIP member names are a string of UTF-8 code points, not a text stream to be
// BOM-sniffed: with the default `ignoreBOM: false` a leading U+FEFF is dropped
// here and kept by the reference importer, which is two different member lists
// for one archive — the defect this reader exists to remove.
const NAME_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/**
 * The member list of `bytes`, in central-directory order, or a `ContainerError`.
 *
 * Every step below has a numbered twin in `src/attest/container.py`. The order
 * is part of the contract: two readers that check the same things in a
 * different order can still disagree about WHICH complaint an archive earns,
 * and a corpus that pins codes would then be unshareable between them.
 */
export function canonicalMembers(bytes: Uint8Array, caps: ContainerCaps): Member[] {
  const length = bytes.length
  // S1
  if (length < EOCD_SIZE) throw new ContainerError('too-short')
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const eocd = length - EOCD_SIZE
  // S2
  if (u32(view, eocd) !== EOCD_SIG) throw new ContainerError('eocd-not-last')
  const diskNo = u16(view, eocd + 4)
  const cdDisk = u16(view, eocd + 6)
  const nDisk = u16(view, eocd + 8)
  const nTotal = u16(view, eocd + 10)
  const sizeCd = u32(view, eocd + 12)
  const offCd = u32(view, eocd + 16)
  const commentLen = u16(view, eocd + 20)
  // S3
  if (commentLen !== 0) throw new ContainerError('eocd-comment-length')
  // S4
  if (diskNo !== 0 || cdDisk !== 0) throw new ContainerError('multi-disk')
  // S5 — ZIP64 on presence OR on sentinel: one reader enters it on the locator
  // alone, the other on the sentinel values, so the canonical form refuses both
  // rather than choose which reader is right.
  if (length >= EOCD_SIZE + ZIP64_LOCATOR_SIZE && u32(view, length - EOCD_SIZE - ZIP64_LOCATOR_SIZE) === ZIP64_LOCATOR_SIG)
    throw new ContainerError('zip64')
  if (nDisk === U16_SENTINEL || nTotal === U16_SENTINEL || sizeCd === U32_SENTINEL || offCd === U32_SENTINEL)
    throw new ContainerError('zip64')
  // S6
  if (nDisk !== nTotal) throw new ContainerError('entry-counters-disagree')
  // S7 — before any walking, so the cap bounds the work: this is what makes the
  // entry cap a real pre-read gate on both sides.
  if (nTotal > caps.maxEntries) throw new ContainerError('too-many-entries', null, caps.maxEntries)
  // S8 — the line that refuses a file carrying two valid directories: the
  // directory must END where the end-of-central-directory record begins.
  if (offCd + sizeCd !== eocd) throw new ContainerError('directory-misplaced')

  // S9
  let position = offCd
  const end = eocd
  const seen = new Set<string>()
  let declaredTotal = 0
  const members: Member[] = []
  for (let index = 0; index < nTotal; index += 1) {
    if (end - position < CD_FIXED || u32(view, position) !== CD_SIG)
      throw new ContainerError('directory-record-signature')
    const flags = u16(view, position + 8)
    const method = u16(view, position + 10)
    const crc = u32(view, position + 16)
    const csize = u32(view, position + 20)
    const usize = u32(view, position + 24)
    const nameLen = u16(view, position + 28)
    const extraLen = u16(view, position + 30)
    const recordCommentLen = u16(view, position + 32)
    const diskStart = u16(view, position + 34)
    const lho = u32(view, position + 42)
    const recordEnd = position + CD_FIXED + nameLen + extraLen + recordCommentLen
    if (recordEnd > end) throw new ContainerError('directory-record-overrun')

    // S10
    if (recordCommentLen !== 0) throw new ContainerError('record-comment')
    // S11
    if (diskStart !== 0) throw new ContainerError('record-multi-disk')
    // S12
    if (flags & 0x0001 || flags & 0x0040) throw new ContainerError('record-encrypted')
    // S13
    if (method !== 0 && method !== 8) throw new ContainerError('record-method')
    // S14
    if (csize === U32_SENTINEL || usize === U32_SENTINEL || lho === U32_SENTINEL)
      throw new ContainerError('record-zip64')
    // S15
    if (nameLen === 0) throw new ContainerError('record-name-empty')
    // S16 — no path grammar here: `..`, a leading slash, a NUL and `__proto__`
    // are member names like any other at this level. The member families own
    // their own grammar.
    const nameStart = position + CD_FIXED
    const nameBytes = bytes.subarray(nameStart, nameStart + nameLen)
    let highByte = false
    for (let byteIndex = 0; byteIndex < nameBytes.length; byteIndex += 1)
      if (nameBytes[byteIndex] >= 0x80) highByte = true
    if (highByte && !(flags & 0x0800)) throw new ContainerError('record-name-encoding')
    let name: string
    try {
      name = NAME_DECODER.decode(nameBytes)
    } catch {
      throw new ContainerError('record-name-encoding')
    }
    // S17
    if (seen.has(name)) throw new ContainerError('duplicate-name', name)
    seen.add(name)
    // S18
    if (method === 0 && csize !== usize) throw new ContainerError('record-stored-size', name)
    // S19
    if (lho + LFH_FIXED > offCd) throw new ContainerError('local-header-out-of-range', name)
    // S20
    if (u32(view, lho) !== LFH_SIG) throw new ContainerError('local-header-signature', name)
    // S21
    const localNameLen = u16(view, lho + 26)
    const localExtraLen = u16(view, lho + 28)
    const dataStart = lho + LFH_FIXED + localNameLen + localExtraLen
    if (dataStart > offCd) throw new ContainerError('local-header-out-of-range', name)
    if (localNameLen !== nameLen || !sameBytes(bytes, lho + LFH_FIXED, nameStart, nameLen))
      throw new ContainerError('local-name-mismatch', name)
    // S22
    if (dataStart + csize > offCd) throw new ContainerError('member-data-out-of-range', name)
    // S23 — declared sizes can lie low, and the streamed count in `readMember`
    // is what catches that; these two gates catch the archive that is honestly
    // huge, before a byte is inflated.
    if (usize > caps.maxMemberBytes) throw new ContainerError('declared-member-over-cap', name)
    declaredTotal += usize
    if (declaredTotal > caps.maxTotalBytes) throw new ContainerError('declared-total-over-cap', name)

    members.push({
      name,
      method: method as 0 | 8,
      crc32: crc,
      compressedSize: csize,
      uncompressedSize: usize,
      dataStart,
    })
    position = recordEnd
  }

  if (position !== end) throw new ContainerError('directory-trailing-bytes')
  return members
}

/**
 * The bytes of `member`, under `budget`, verified against its record.
 *
 * The streamed length — not the declared one — is authoritative, which is what
 * catches a header that lies low about a bomb; the CRC-32 is what catches bytes
 * that were replaced after the archive was written.
 */
export function readMember(bytes: Uint8Array, member: Member, budget: ReadBudget): Uint8Array {
  let got = 0
  const count = (produced: number): void => {
    got += produced
    if (got > budget.maxMemberBytes) throw new ContainerError('member-over-cap', member.name)
    if (budget.spent + got > budget.maxTotalBytes) throw new ContainerError('total-over-cap', member.name)
  }

  const start = member.dataStart
  const stop = start + member.compressedSize
  let out: Uint8Array
  if (member.method === 0) {
    out = bytes.slice(start, stop)
    count(out.length)
  } else {
    // An empty payload is the one input on which the two decoders disagree by
    // default: one reports a stream that never reached its final block, the
    // other reports nothing at all. Both readers name it here rather than let
    // each library's silence decide (measured 2026-09-02).
    if (member.compressedSize === 0) throw new ContainerError('member-inflate-error', member.name)
    // The stream is validated here, against the format, rather than by
    // whichever library is doing the decompressing: the two libraries were
    // measured refusing different streams (see `./deflate.js`).
    if (deflateError(bytes.subarray(start, stop), budget.maxMemberBytes) !== null)
      throw new ContainerError('member-inflate-error', member.name)
    // A limit measured and left open (2026-09-02): the two decoders do not hand
    // back the same number of bytes at the same input offset — one returns
    // everything decoded so far, the other only completed blocks — so a stream
    // that is BOTH over the cap and invalid can earn `member-over-cap` on one
    // side and `member-inflate-error` on the other. Both refuse it; the codes
    // differ. Closing that means deciding the cap on the length the validator
    // above computes rather than on what each decoder has produced, which is a
    // change to the shared algorithm and not to this file.
    const chunks: Uint8Array[] = []
    const inflate = new Inflate((chunk) => {
      chunks.push(chunk)
      count(chunk.length)
    })
    for (let position = start; position < stop; position += INFLATE_SLICE) {
      const sliceEnd = Math.min(position + INFLATE_SLICE, stop)
      try {
        inflate.push(bytes.subarray(position, sliceEnd), sliceEnd === stop)
      } catch (error) {
        if (error instanceof ContainerError) throw error
        // Truncated or invalid: fflate refuses a final push it cannot finish.
        // Trailing bytes inside the declared compressed size are ignored by
        // both decoders, so they are not inspected — a check only one side
        // could perform would be a new divergence, not a defence.
        throw new ContainerError('member-inflate-error', member.name)
      }
    }
    out = new Uint8Array(got)
    let offset = 0
    for (const chunk of chunks) {
      out.set(chunk, offset)
      offset += chunk.length
    }
  }

  if (got !== member.uncompressedSize) throw new ContainerError('member-size-mismatch', member.name)
  if (crc32(out) !== member.crc32) throw new ContainerError('member-crc-mismatch', member.name)
  budget.spent += got
  return out
}
