import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createPrivateKey, sign } from 'node:crypto'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes, sha256Hex } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { parseBundle, BundleError, BundleTooLargeError, PrivateBundleError, DEFAULT_CAPS } from '../src/bundle.js'
import { intake } from '../src/intake.js'
import { canonicalMembers, ContainerError } from '../src/container.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT, logKeys, anchorPolicy } from './helpers/vectors.js'
// Aliased: this file already defines a local `storedZip` that does NOT set
// general-purpose bit 11, so a non-ASCII member name written with it is refused
// as `record-name-encoding` before any test can reason about it.
import {
  storedZip as utf8Zip, validEnvelope, VALID_RECEIPT_ID,
  legalEntry, LEGAL_TEXT, LEGAL_DIGEST, type StoredEntry,
} from './helpers/zip.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
// The one conformance leaf that ships a receipt AND the §10.2 evidence that
// stands for it, so a proofs/ member can be tested as evidence rather than as
// bytes: expected.json pins transparency/corroboration to "logged".
const V28 = join(VECTORS_ROOT, '28-transparency', 'a-logged-trust-unchanged')
const V28_RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'

// Build a real .attest-shaped zip from the 01-valid-minimal vector: its
// envelope + its key manifest wrapped in the export format
// manifests/<issuer>.json = {issuer, key_manifests: [...], artifact_manifests: []}.
function sampleZip(): { zip: Uint8Array; issuer: string } {
  const envelope = new Uint8Array(readFileSync(join(V01, 'envelope.json')))
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  const blob: JsonObject = { issuer, key_manifests: [manifests[issuer]], artifact_manifests: [] }
  const zip = zipSync({
    ['receipts/01HZX0000000000000000000AA.attest.json']: envelope,
    [`manifests/${issuer}.json`]: canonicalBytes(blob),
    [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    ['README.html']: new TextEncoder().encode('<p>bundle readme</p>'),
  })
  return { zip, issuer }
}

describe('parseBundle', () => {
  it('extracts receipts and builds a TOFU trust store that verifies', () => {
    const { zip, issuer } = sampleZip()
    const parsed = parseBundle(zip)
    expect(parsed.receipts).toHaveLength(1)
    // The SIGNED id, not the member name. This archive is built with the two
    // deliberately different — the member is called `01HZX…AA` while the
    // payload says `01JZ5PDHT…` — because a bundle from anywhere else may name
    // its members anything at all (v0.1 §14.1 specifies a wildcard), and an
    // attacker will name them something that reads like a verdict.
    expect(parsed.receipts[0].receiptId).toBe('01JZ5PDHT0000G40R40M30E209')
    expect(parsed.trustStore.provenanceFor(issuer)).toBe('bundle')
    const run = runVerify(parsed.receipts[0].bytes, parsed.trustStore)
    expect(run.result.signature).toBe('valid')
    expect(run.result.trust).toBe('unauthenticated_tofu') // never 'verified' from a bundle
  })

  it('keeps the latest key manifest and the full ordered chain', () => {
    const { zip: _zip, issuer } = sampleZip()
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const km = (d.manifests as JsonObject)[issuer] as JsonObject
    const v2: JsonObject = { ...km, manifest_version: 2n }
    const blob: JsonObject = { issuer, key_manifests: [v2, km], artifact_manifests: [] }
    const zip = zipSync({
      ['receipts/X.attest.json']: new Uint8Array(readFileSync(join(V01, 'envelope.json'))),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    })
    const parsed = parseBundle(zip)
    expect(parsed.trustStore.manifestFor(issuer)!.data().manifest_version).toBe(2n)
    expect(parsed.trustStore.chainFor(issuer)).toHaveLength(2)
    expect(parsed.trustStore.chainFor(issuer)[0]!.data().manifest_version).toBe(1n)
  })

  it('rejects a bundle with zero receipts', () => {
    const zip = zipSync({ ['README.html']: new TextEncoder().encode('x') })
    expect(() => parseBundle(zip)).toThrow(BundleError)
  })

  it('rejects garbage bytes as not-a-zip', () => {
    expect(() => parseBundle(new TextEncoder().encode('not a zip'))).toThrow(BundleError)
  })

  it('refuses a private bundle (salts.json) without decompressing secrets', () => {
    const zip = zipSync({ ['salts.json']: new TextEncoder().encode('{"R":"c2FsdA"}') })
    expect(() => parseBundle(zip)).toThrow(PrivateBundleError)
  })

  it('refuses a private bundle (keys/)', () => {
    const zip = zipSync({ ['keys/R.seed']: new Uint8Array(32) })
    expect(() => parseBundle(zip)).toThrow(PrivateBundleError)
  })

  it('enforces the entry-count cap', () => {
    const entries: Record<string, Uint8Array> = {}
    for (let i = 0; i < 4; i++) entries[`receipts/${i}.attest.json`] = new TextEncoder().encode('{}')
    const zip = zipSync(entries)
    expect(() => parseBundle(zip, { ...DEFAULT_CAPS, maxEntries: 3 })).toThrow(/entries/)
  })

  it('enforces the per-member cap', () => {
    const zip = zipSync({ ['receipts/big.attest.json']: new Uint8Array(2048) })
    expect(() => parseBundle(zip, { ...DEFAULT_CAPS, maxMemberBytes: 1024 })).toThrow(/cap/)
  })

  it('enforces the aggregate cap', () => {
    const zip = zipSync({
      ['receipts/a.attest.json']: new Uint8Array(800),
      ['receipts/b.attest.json']: new Uint8Array(800),
    })
    expect(() => parseBundle(zip, { ...DEFAULT_CAPS, maxTotalBytes: 1000 })).toThrow(/cap/)
  })
})

// A bundle shaped the way the reference exporter writes one when a receipt's
// transparency evidence travelled with it: receipts/<ULID>.attest.json +
// manifests/<issuer>.json + proofs/<ULID>.json (v0.2 §14).
function bundleWithMembers(extra: Record<string, Uint8Array>): Uint8Array {
  const d = loadsStrict(new Uint8Array(readFileSync(join(V28, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  const blob: JsonObject = { issuer, key_manifests: [manifests[issuer]], artifact_manifests: [] }
  return zipSync({
    [`receipts/${V28_RECEIPT_ID}.attest.json`]: new Uint8Array(readFileSync(join(V28, 'envelope.json'))),
    [`manifests/${issuer}.json`]: canonicalBytes(blob),
    [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    ...extra,
  })
}
const evidenceBytes = (): Uint8Array => new Uint8Array(readFileSync(join(V28, 'transparency.json')))

describe('parseBundle — proofs/ members (v0.2 §14)', () => {
  it('carries a proof as evidence a verifier can actually stand on', () => {
    const parsed = parseBundle(bundleWithMembers({ [`proofs/${V28_RECEIPT_ID}.json`]: evidenceBytes() }))
    expect(Object.keys(parsed.proofs)).toEqual([V28_RECEIPT_ID])
    // The bundle supplies EVIDENCE only. The standing appears when the
    // verifier's own pinned configuration evaluates it — never because the
    // bundle said so.
    const run = runVerify(parsed.receipts[0].bytes, parsed.trustStore, null, null, {
      transparency: parsed.proofs[V28_RECEIPT_ID],
      logKeys: logKeys(V28),
      anchorPolicy: anchorPolicy(V28),
    })
    expect(run.result.transparency).toBe('logged')
    expect(run.result.corroboration).toBe('logged')
  })

  it('leaves proofs empty for a bundle that carries none', () => {
    expect(parseBundle(bundleWithMembers({})).proofs).toEqual({})
  })

  // v0.2 §14: a conforming importer MUST reject every proofs shape but
  // proofs/<ULID>.json. The page derives no filesystem path, but the grammar
  // is the spec's, not the filesystem's — a member that does not name a
  // receipt id cannot be matched to a receipt at all.
  it.each([
    ['a nested path', `proofs/nested/${V28_RECEIPT_ID}.json`],
    ['a non-.json suffix', `proofs/${V28_RECEIPT_ID}.txt`],
    ['a name that is not a ULID', 'proofs/not-a-ulid.json'],
    ['a lowercase ULID', `proofs/${V28_RECEIPT_ID.toLowerCase()}.json`],
    ['a ULID outside the timestamp-prefix range', 'proofs/8ZZZZZZZZZZZZZZZZZZZZZZZZZ.json'],
  ])('rejects %s under proofs/', (_label, member) => {
    expect(() => parseBundle(bundleWithMembers({ [member]: evidenceBytes() }))).toThrow(BundleError)
  })

  it('rejects a proof member that is not readable JSON', () => {
    const zip = bundleWithMembers({ [`proofs/${V28_RECEIPT_ID}.json`]: new TextEncoder().encode('{oops') })
    expect(() => parseBundle(zip)).toThrow(BundleError)
  })

  it('drops a proof whose evidence is not an object, mirroring the reference importer', () => {
    const zip = bundleWithMembers({ [`proofs/${V28_RECEIPT_ID}.json`]: new TextEncoder().encode('[]') })
    expect(parseBundle(zip).proofs).toEqual({})
  })
})

// --- V-L.6: a central directory repeating a member name (v0.1 §14.1) --------

// Minimal STORED zip writer that, unlike zipSync's Record input, CAN repeat a
// member name — the exact shape a pre-fix export produced.
function crc32(data: Uint8Array): number {
  let c = 0xffffffff
  for (let i = 0; i < data.length; i++) {
    c ^= data[i]
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1))
  }
  return (c ^ 0xffffffff) >>> 0
}

function storedZip(entries: [string, Uint8Array][]): Uint8Array {
  const enc = new TextEncoder()
  const locals: Uint8Array[] = []
  const centrals: Uint8Array[] = []
  let offset = 0
  for (const [name, data] of entries) {
    const n = enc.encode(name)
    const crc = crc32(data)
    const local = new Uint8Array(30 + n.length + data.length)
    const lv = new DataView(local.buffer)
    lv.setUint32(0, 0x04034b50, true)
    lv.setUint16(4, 20, true)
    lv.setUint32(14, crc, true)
    lv.setUint32(18, data.length, true)
    lv.setUint32(22, data.length, true)
    lv.setUint16(26, n.length, true)
    local.set(n, 30)
    local.set(data, 30 + n.length)
    const central = new Uint8Array(46 + n.length)
    const cv = new DataView(central.buffer)
    cv.setUint32(0, 0x02014b50, true)
    cv.setUint16(4, 20, true)
    cv.setUint16(6, 20, true)
    cv.setUint32(16, crc, true)
    cv.setUint32(20, data.length, true)
    cv.setUint32(24, data.length, true)
    cv.setUint16(28, n.length, true)
    cv.setUint32(42, offset, true)
    central.set(n, 46)
    locals.push(local)
    centrals.push(central)
    offset += local.length
  }
  const cdSize = centrals.reduce((s, c) => s + c.length, 0)
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(8, entries.length, true)
  ev.setUint16(10, entries.length, true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, offset, true)
  const out = new Uint8Array(offset + cdSize + 22)
  let p = 0
  for (const b of [...locals, ...centrals, eocd]) {
    out.set(b, p)
    p += b.length
  }
  return out
}

describe('parseBundle: duplicate member names', () => {
  const NAME = 'receipts/01HZX0000000000000000000AA.attest.json'
  const env = () => new Uint8Array(readFileSync(join(V01, 'envelope.json')))
  // The archives that must be ACCEPTED carry the deal their receipt refers to,
  // as an exporter writes them; the ones that must be refused are refused on
  // the directory, long before any family is read.
  const LEGAL: [string, Uint8Array] = [`legal/${LEGAL_DIGEST}.txt`, LEGAL_TEXT]

  // The writer itself is verified first: a throw on the duplicated archive
  // proves nothing unless the non-duplicated one round-trips.
  it('round-trips a hand-built zip without duplicates', () => {
    const parsed = parseBundle(storedZip([[NAME, env()], LEGAL]))
    expect(parsed.receipts).toHaveLength(1)
  })

  it('rejects a central directory that repeats a member name', () => {
    expect(() => parseBundle(storedZip([[NAME, env()], [NAME, env()]]))).toThrow(BundleError)
    expect(() => parseBundle(storedZip([[NAME, env()], [NAME, env()]]))).toThrow(/repeats/)
  })

  it('rejects a repeat whose two entries are byte-identical', () => {
    const bytes = env()
    expect(() => parseBundle(storedZip([[NAME, bytes], [NAME, bytes]]))).toThrow(/repeats/)
  })

  it('rejects three entries under one name', () => {
    // The refusal no longer counts the repeats. Counting them meant comparing
    // two numbers drawn from the same walk of the directory, which is what a
    // hostile archive could make agree; the reader now refuses the first
    // repeated name and stops, exactly as the reference importer does.
    expect(() => parseBundle(storedZip([[NAME, env()], [NAME, env()], [NAME, env()]]))).toThrow(
      /repeats member name/,
    )
  })

  it('rejects a repeat in a non-receipt member family', () => {
    const other = 'manifests/store.example.com.json'
    const blob = new TextEncoder().encode('{}')
    expect(() =>
      parseBundle(storedZip([[NAME, env()], [other, blob], [other, blob]])),
    ).toThrow(/repeats/)
  })

  it('does not false-positive on distinct names', () => {
    // Distinct member names AND distinct payload ids: the same envelope under
    // two names now trips the receipt-id guard instead, which is its own test.
    const second = 'receipts/01HZX0000000000000000000AB.attest.json'
    const envelope = JSON.parse(new TextDecoder().decode(env()))
    envelope.payload.receipt_id = '01HZX0000000000000000000AB'
    const secondBytes = new TextEncoder().encode(JSON.stringify(envelope))
    const parsed = parseBundle(storedZip([[NAME, env()], [second, secondBytes], LEGAL]))
    expect(parsed.receipts).toHaveLength(2)
  })
})

describe('parseBundle: receipt payload ids', () => {
  const NAME = 'receipts/01HZX0000000000000000000AA.attest.json'
  const env = () => new Uint8Array(readFileSync(join(V01, 'envelope.json')))

  function withReceiptId(id: unknown): Uint8Array {
    const envelope = JSON.parse(new TextDecoder().decode(env()))
    envelope.payload.receipt_id = id
    return new TextEncoder().encode(JSON.stringify(envelope))
  }

  it.each([['../../escaped'], ['/tmp/escaped'], ['01hzx0000000000000000000aa'], ['']])(
    'refuses a receipt_id that is not an uppercase ULID (%s)',
    (id) => {
      expect(() => parseBundle(storedZip([[NAME, withReceiptId(id)]]))).toThrow(/invalid receipt_id/)
    },
  )

  it('refuses a non-string receipt_id', () => {
    expect(() => parseBundle(storedZip([[NAME, withReceiptId(7)]]))).toThrow(/invalid receipt_id/)
  })

  it('refuses two distinct member names carrying one receipt_id', () => {
    const other = 'receipts/01HZX0000000000000000000AB.attest.json'
    expect(() => parseBundle(storedZip([[NAME, env()], [other, env()]]))).toThrow(/more than once/)
  })
})

// --- the container is read canonically (v0.1 §14.1) --------------------------
//
// These archives come from the shared corpus, so this page and the reference
// importer are judged on the same bytes rather than on two hand-built fixtures
// that happen to look alike.

describe('parseBundle on the shared container corpus', () => {
  const leaf = (name: string): Uint8Array =>
    new Uint8Array(
      readFileSync(join(VECTORS_ROOT, '..', '..', '..', 'tests', 'container-corpus', name, 'archive.zip')),
    )

  it('refuses a file carrying two central directories', () => {
    // The exhibit that no counter check can see: this page used to read one
    // receipt out of it and the reference importer another, with neither
    // archive telling a lie about itself.
    expect(() => parseBundle(leaf('exhibit-D-prefix'))).toThrow(/canonical form/)
  })

  it('refuses a file whose entry counters disagree', () => {
    // One byte used to decide which members this page saw.
    expect(() => parseBundle(leaf('exhibit-B2-counter'))).toThrow(/counters disagree/)
  })

  it('refuses the archive that used to smuggle the buyer secrets past the filter', () => {
    // The counter hid `salts.json` from this page entirely, so the secrets
    // filter never saw it. The file is now refused before the question of
    // which members it holds can be asked.
    expect(() => parseBundle(leaf('exhibit-C2-salts'))).toThrow(/counters disagree/)
  })

  it('still refuses an honest archive that carries the buyer secrets', () => {
    expect(() => parseBundle(leaf('exhibit-C-salts-honest'))).toThrow(PrivateBundleError)
  })

  it('refuses a repeated member name', () => {
    expect(() => parseBundle(leaf('exhibit-A-honest'))).toThrow(/repeats member name/)
  })

  it('refuses a member whose deflate stream only one decoder would accept', () => {
    // A stored block with a wrong complement field: the reference importer's
    // decoder refuses it, this page's decoder never reads that field, so the
    // verdict is made by shared code instead of by whichever library runs.
    expect(() => parseBundle(leaf('deflate-stored-block-bad-complement'))).toThrow(
      /not a valid deflate stream/,
    )
  })
})

describe('parseBundle reads members on demand', () => {
  it('ignores a member no family claims even when it is corrupt', () => {
    // The twin of the reference importer's own test: an archive can carry
    // something neither importer looks at. Reading every member eagerly made
    // such a file fatal here and invisible there — same bytes, two verdicts,
    // which is the defect this whole change closes.
    const envelope = new Uint8Array(readFileSync(join(V01, 'envelope.json')))
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const manifests = d.manifests as JsonObject
    const issuer = Object.keys(manifests)[0]
    const blob: JsonObject = { issuer, key_manifests: [manifests[issuer]], artifact_manifests: [] }
    const marker = new TextEncoder().encode('CORRUPT-ME-PLEASE-0123456789')
    const raw = zipSync(
      {
        ['receipts/01HZX0000000000000000000AA.attest.json']: envelope,
        [`manifests/${issuer}.json`]: canonicalBytes(blob),
        [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
        ['unknown.bin']: marker,
      },
      { level: 0 },
    )
    // Flip a byte of the unknown member's DATA, leaving its CRC-32 record
    // untouched: the member is now unreadable, and nothing reads it.
    const at = raw.findIndex((_, index) =>
      marker.every((byte, offset) => raw[index + offset] === byte),
    )
    expect(at).toBeGreaterThan(0)
    raw[at] ^= 0xff
    expect(parseBundle(raw).receipts).toHaveLength(1)
  })
})

// --- the trust store is keyed by names the archive chose -----------------------
//
// An issuer is a string a bundle picked, and the trust store this parser hands
// on is looked up by it. Built as an ordinary JavaScript object, a member named
// `__proto__` is not a member at all: assigning it replaces the object's own
// prototype, so the issuer vanishes from the store AND everything the archive
// put in that manifest becomes the answer to every issuer the store was never
// asked about. The reference importer keeps such a name as an ordinary key and
// answers nothing for the others — the same bytes, two trust stores, which is
// the divergence this file exists to keep closed.

describe('parseBundle: the trust store answers only for issuers the bundle named', () => {
  const protoBundle = (extra: JsonObject = {}): Uint8Array => {
    const envelope = new Uint8Array(readFileSync(join(V01, 'envelope.json')))
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const real = (d.manifests as JsonObject)['store.example.com'] as JsonObject
    const blob: JsonObject = {
      issuer: '__proto__',
      key_manifests: [{ ...(real as object), issuer: '__proto__', ...extra } as JsonObject],
      artifact_manifests: [],
    }
    return zipSync({
      ['receipts/01HZX0000000000000000000AA.attest.json']: envelope,
      ['manifests/__proto__.json']: canonicalBytes(blob),
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    })
  }

  it('keeps an issuer named after an object member as an ordinary key', () => {
    const { trustStore } = parseBundle(protoBundle())
    // `issuers()` for the members a door enumerates, `data()` for the two it
    // does not: the snapshot's own tree is the only surface that keeps "this
    // member is absent" apart from "this member is empty", which is the very
    // distinction a store built by hand used to erase.
    expect(trustStore.issuers()).toEqual(['__proto__'])
    expect(Object.keys(trustStore.data().provenance as JsonObject)).toEqual(['__proto__'])
    expect(Object.keys(trustStore.data().chains as JsonObject)).toEqual(['__proto__'])
  })

  it('does not let one manifest stand for an issuer the bundle never named', () => {
    // The archive names one issuer, `__proto__`, and hides inside that
    // manifest a member named after a second one. On an ordinary object the
    // first assignment makes the manifest the store's prototype, and the
    // second name is then answered out of it — a key manifest for an issuer
    // no member of this archive ever declared.
    const victim = 'store.example.com'
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const real = (d.manifests as JsonObject)[victim] as JsonObject
    const { trustStore } = parseBundle(protoBundle({ [victim]: real }))
    // Asked of the DOORS, which is where the answer would have come from: a
    // manifest reachable through a polluted prototype is one `manifestFor`
    // hands to the verifier, whatever the tree underneath looks like.
    expect(trustStore.manifestFor(victim)).toBeNull()
    expect(trustStore.provenanceFor(victim)).toBeNull()
    expect(trustStore.chainFor(victim)).toEqual([])
    // And of the tree, so an empty chain cannot pass for an absent one.
    expect((trustStore.data().chains as JsonObject)[victim]).toBeUndefined()
  })

  it('answers nothing for a name every JavaScript object carries', () => {
    // `toString` is on every ordinary object, so a receipt claiming that
    // issuer used to be handed a function where a manifest belongs.
    const { zip } = sampleZip()
    const { trustStore, proofs } = parseBundle(zip)
    expect(trustStore.manifestFor('toString')).toBeNull()
    expect(trustStore.provenanceFor('toString')).toBeNull()
    expect(trustStore.chainFor('toString')).toEqual([])
    expect(proofs['toString']).toBeUndefined()
  })
})

// --- member order, and the families the reference importer reads -------------

describe('parseBundle orders members the way the reference importer does', () => {
  it('meets a broken member in Unicode code point order, not UTF-16 code unit order', () => {
    // `U+FFFF` sorts BEFORE `U+1F600` by code point and AFTER it by UTF-16 code
    // unit, so the two orders meet a different member first — and complain
    // about a different one. That is the whole reason this file carries its own
    // comparator instead of calling `Array#sort`.
    //
    // Both members are unreadable, so the NAME in the refusal is what the order
    // decides; each carries an ASCII tag so the assertion does not depend on how
    // an exotic character survives being quoted into a message.
    const junk = new TextEncoder().encode('{')
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/\u{1F600}-emoji.json', junk],
      ['manifests/￿-ffff.json', junk],
    ])
    try {
      parseBundle(zip)
      throw new Error('expected parseBundle to refuse an unreadable manifest member')
    } catch (error) {
      expect(error).toBeInstanceOf(BundleError)
      // Code point order meets `U+FFFF` first. A UTF-16 sort names the emoji.
      expect((error as BundleError).message).toContain('-ffff')
      expect((error as BundleError).message).not.toContain('-emoji')
    }
  })
})

// Duplicate member NAMES are already refused by the container reader. Two
// DISTINCT members that declare one issuer are the same attack a level up: the
// archive names an issuer twice and the importer keeps whichever it happened to
// read last, so the key list a receipt is checked against depends on member
// order rather than on anything the bundle states. Exact filename/content
// agreement now refuses the conflicting name before it can claim that issuer.
describe('parseBundle refuses semantic manifest duplicates', () => {
  const manifestFor = (issuer: string, version: bigint): Uint8Array => {
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const real = Object.keys(d.manifests as JsonObject)[0]
    const km = (d.manifests as JsonObject)[real] as JsonObject
    return canonicalBytes({
      issuer,
      key_manifests: [{ ...km, issuer, manifest_version: version }],
      artifact_manifests: [],
    } as JsonObject)
  }

  it('refuses two different manifest members that claim one issuer', () => {
    const issuer = 'store.example.com'
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/a.json', manifestFor(issuer, 1n)],
      ['manifests/b.json', manifestFor(issuer, 2n)],
      legalEntry(),
    ])
    expect(() => parseBundle(zip)).toThrow(/filename issuer .* does not match content issuer/)
  })

  it('still accepts two manifest members that claim different issuers', () => {
    // The refusal above must be a limit and not a ban: a bundle carrying two
    // sellers' key lists is the ordinary shape of a library.
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/store.example.com.json', manifestFor('store.example.com', 1n)],
      ['manifests/other.example.com.json', manifestFor('other.example.com', 1n)],
      legalEntry(),
    ])
    const { trustStore } = parseBundle(zip)
    // `issuers()` is already in the order the signed bytes put them in, so a
    // `sort()` here would be a second ordering rule on top of the library's.
    expect(trustStore.issuers()).toEqual(['other.example.com', 'store.example.com'])
  })

  it('lets one member carry an issuer twice in its own key_manifests', () => {
    // The chain of a single issuer's manifest versions lives INSIDE one member,
    // and that is the shape the trust store is built from. Refusing it would
    // break the rotation the chain exists to record.
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const issuer = Object.keys(d.manifests as JsonObject)[0]
    const km = (d.manifests as JsonObject)[issuer] as JsonObject
    const blob = canonicalBytes({
      issuer,
      key_manifests: [{ ...km, manifest_version: 1n }, { ...km, manifest_version: 2n }],
      artifact_manifests: [],
    } as JsonObject)
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      [`manifests/${issuer}.json`, blob],
      legalEntry(),
    ])
    const { trustStore } = parseBundle(zip)
    expect(trustStore.manifestFor(issuer)!.data()['manifest_version']).toBe(2n)
    expect(trustStore.chainFor(issuer)).toHaveLength(2)
  })

  it('does not count a member it skips as a claim on an issuer', () => {
    // An unshaped blob contributes no issuer at all — the reference importer
    // skips it — so it cannot collide with the member that does.
    const issuer = 'store.example.com'
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/unshaped.json', canonicalBytes([])],
      [`manifests/${issuer}.json`, manifestFor(issuer, 1n)],
      legalEntry(),
    ])
    expect(parseBundle(zip).trustStore.issuers()).toEqual([issuer])
  })
})

describe('parseBundle reads every family the reference importer reads', () => {
  const corruptOneMember = (members: Record<string, Uint8Array>, marker: Uint8Array): Uint8Array => {
    const raw = zipSync(members, { level: 0 })
    const at = raw.findIndex((_, index) => marker.every((byte, offset) => raw[index + offset] === byte))
    expect(at).toBeGreaterThan(0)
    raw[at] ^= 0xff
    return raw
  }
  const base = (): Record<string, Uint8Array> => {
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const issuer = Object.keys(d.manifests as JsonObject)[0]
    const blob: JsonObject = {
      issuer,
      key_manifests: [(d.manifests as JsonObject)[issuer]],
      artifact_manifests: [],
    }
    return {
      [`receipts/${VALID_RECEIPT_ID}.attest.json`]: new Uint8Array(readFileSync(join(V01, 'envelope.json'))),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
      [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    }
  }
  const marker = new TextEncoder().encode('CORRUPT-ME-PLEASE-0123456789')

  it('refuses a corrupt legal/ member, which the reference importer reads', () => {
    const raw = corruptOneMember({ ...base(), ['legal/deadbeef.txt']: marker }, marker)
    expect(() => parseBundle(raw)).toThrow(BundleError)
  })

  it('still ignores a corrupt member no family claims', () => {
    const raw = corruptOneMember({ ...base(), ['unknown.bin']: marker }, marker)
    expect(parseBundle(raw).receipts).toHaveLength(1)
  })
})

// v0.1 §14.1 names a legal text by the digest of its own bytes, and §9 is why:
// the bundle exists to preserve the DEAL, and a text nobody can bind to its
// name preserves nothing. The reference importer hashes every `legal/` member
// and refuses the archive when the two disagree, then refuses again when a
// receipt refers to a text the bundle never carried. Reading those bytes and
// dropping them left this page accepting an archive the reference importer
// refuses — under every cap, on a file both are supposed to judge alike.
describe('parseBundle checks a legal text against the name it travelled under', () => {
  const enc = (text: string): Uint8Array => new TextEncoder().encode(text)

  const withLegal = (entries: StoredEntry[]): Uint8Array => {
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const issuer = Object.keys(d.manifests as JsonObject)[0]
    const blob: JsonObject = {
      issuer,
      key_manifests: [(d.manifests as JsonObject)[issuer]],
      artifact_manifests: [],
    }
    return utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      [`manifests/${issuer}.json`, canonicalBytes(blob)],
      ...entries,
    ])
  }

  it('is the text the conformance vectors actually bind their receipts to', () => {
    // The fixture is only a fixture if the digest, the text and the receipt all
    // agree; otherwise every test below would be about an archive no exporter
    // produces.
    expect(sha256Hex(LEGAL_TEXT)).toBe(LEGAL_DIGEST)
    const payload = (loadsStrict(validEnvelope()) as JsonObject)['payload'] as JsonObject
    expect((payload['license'] as JsonObject)['legal_text_sha256']).toBe(LEGAL_DIGEST)
  })

  it('accepts a legal text that hashes to its own member name', () => {
    const parsed = parseBundle(withLegal([legalEntry()]))
    expect(parsed.receipts).toHaveLength(1)
  })

  it('keeps the text the digest binds, instead of dropping it', () => {
    const parsed = parseBundle(withLegal([legalEntry()]))
    expect(parsed.legalTexts[LEGAL_DIGEST]).toEqual(LEGAL_TEXT)
  })

  it('refuses a legal text that does not hash to its member name', () => {
    // Structurally perfect archive, honest CRC, and one byte of the deal
    // changed: the container reader has nothing to say about it, which is
    // exactly why the digest is checked here.
    const tampered = enc('attest-vectors-legal-text-v2')
    expect(() => parseBundle(withLegal([[`legal/${LEGAL_DIGEST}.txt`, tampered]]))).toThrow(
      /failed its own integrity check on import/,
    )
  })

  it('refuses a legal member whose name is not a digest at all', () => {
    expect(() => parseBundle(withLegal([['legal/eula.txt', LEGAL_TEXT]]))).toThrow(
      /failed its own integrity check on import/,
    )
  })

  it('shows a real digest whole, so the file that was tampered with can be found', () => {
    // 64 hex characters is four more than the quoting cap, so a quoted digest
    // would be a truncated one. A value of that shape can neither end a quote
    // nor write a sentence, which is why it is shown bare.
    try {
      parseBundle(withLegal([[`legal/${LEGAL_DIGEST}.txt`, new TextEncoder().encode('other')]]))
      throw new Error('expected parseBundle to refuse a legal member that fails its digest')
    } catch (error) {
      expect(error).toBeInstanceOf(BundleError)
      expect((error as BundleError).message).toContain(LEGAL_DIGEST)
    }
  })

  it('does not let a member name that is no digest write the sentence', () => {
    // Anything that is not 64 hex characters is a member name like any other:
    // attacker-supplied text that reaches a buyer's screen, so it is quoted and
    // neutralised, and above all it cannot END the quote it sits in.
    const hostile = 'x" is genuine. Email refunds@evil.example "'
    try {
      parseBundle(withLegal([[`legal/${hostile}.txt`, LEGAL_TEXT]]))
      throw new Error('expected parseBundle to refuse a legal member with a false name')
    } catch (error) {
      expect(error).toBeInstanceOf(BundleError)
      const message = (error as BundleError).message
      expect(message).toMatch(/failed its own integrity check on import/)
      // Exactly the two delimiters this file wrote: the name contributes none.
      expect(message.split('"')).toHaveLength(3)
    }
  })

  it('refuses a bundle whose receipt refers to a legal text it does not carry', () => {
    expect(() => parseBundle(withLegal([]))).toThrow(
      /missing legal text for referenced hash/,
    )
  })

  it('refuses when the missing text is one the survivability block refers to', () => {
    // `license.legal_text_sha256` is schema-required and always referenced; the
    // survivability hashes are optional, and an importer that only looked at
    // the required one would carry a bundle missing the terms that say what
    // happens when the seller stops trading.
    const envelope = loadsStrict(validEnvelope()) as JsonObject
    const payload = envelope['payload'] as JsonObject
    const missing = 'b'.repeat(64)
    const altered = canonicalBytes({
      ...envelope,
      payload: {
        ...payload,
        survivability: {
          ...(payload['survivability'] as JsonObject),
          eol_commitment_sha256: missing,
        },
      },
    } as JsonObject)
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, altered],
      legalEntry(),
    ])
    expect(() => parseBundle(zip)).toThrow(new RegExp(missing))
  })

  it('accepts the same bundle once every referenced text is present', () => {
    // The refusals above are limits, not a ban on bundles that carry terms.
    const envelope = loadsStrict(validEnvelope()) as JsonObject
    const payload = envelope['payload'] as JsonObject
    const second = new TextEncoder().encode('the terms that outlive the seller')
    const secondDigest = sha256Hex(second)
    const altered = canonicalBytes({
      ...envelope,
      payload: {
        ...payload,
        survivability: {
          ...(payload['survivability'] as JsonObject),
          eol_commitment_sha256: secondDigest,
        },
      },
    } as JsonObject)
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, altered],
      legalEntry(),
      [`legal/${secondDigest}.txt`, second],
    ])
    const parsed = parseBundle(zip)
    expect(Object.keys(parsed.legalTexts).sort()).toEqual([LEGAL_DIGEST, secondDigest].sort())
  })

  // The examples above are the cases whoever wrote them thought of. The binding
  // is a PROPERTY — no single-byte change to a text still hashes to its name —
  // and the loop below asserts it over a seeded stream of mutations, so a
  // failure is a reproducible failure and not a story about a Tuesday. Seeded
  // rather than random, and hand-rolled rather than pulled in: a property
  // library would open the supply-chain gate on a package this project ships.
  it('P1 refuses every single-byte change to the text the digest binds', () => {
    let state = 20260904
    const next = (): number => {
      state ^= state << 13
      state >>>= 0
      state ^= state >>> 17
      state ^= state << 5
      state >>>= 0
      return state
    }
    let refused = 0
    for (let round = 0; round < 200; round += 1) {
      const mutated = new Uint8Array(LEGAL_TEXT)
      const at = next() % mutated.length
      mutated[at] = (mutated[at] + 1 + (next() % 255)) & 0xff
      expect(() => parseBundle(withLegal([[`legal/${LEGAL_DIGEST}.txt`, mutated]]))).toThrow(
        BundleError,
      )
      refused += 1
    }
    expect(refused).toBe(200)
  })

  it('P2 refuses every single-character change to the name the text is filed under', () => {
    // The mirror of P1: the digest is a two-sided binding, and a member filed
    // under a name one character off is the same tampering seen from the other
    // end — the archive keeps the deal and renames it out of reach.
    const digits = '0123456789abcdef'
    let refused = 0
    for (let at = 0; at < LEGAL_DIGEST.length; at += 1) {
      const replacement = digits[(digits.indexOf(LEGAL_DIGEST[at]) + 1) % digits.length]
      const name = LEGAL_DIGEST.slice(0, at) + replacement + LEGAL_DIGEST.slice(at + 1)
      expect(() => parseBundle(withLegal([[`legal/${name}.txt`, LEGAL_TEXT]]))).toThrow(BundleError)
      refused += 1
    }
    expect(refused).toBe(64)
  })

  it('keeps the legal store free of inherited names', () => {
    // Keyed by a digest the archive chose, so the same rule as every other map
    // in this file: `__proto__` is an ordinary key and `toString` answers
    // nothing.
    const parsed = parseBundle(withLegal([legalEntry()]))
    expect(parsed.legalTexts['toString']).toBeUndefined()
    expect(Object.getPrototypeOf(parsed.legalTexts)).toBeNull()
  })
})

describe('parseBundle: a manifests/ member that is not shaped like one', () => {
  const enc = (text: string): Uint8Array => new TextEncoder().encode(text)
  const withManifestMember = (body: Uint8Array): Uint8Array =>
    utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/a.example.json', body],
      legalEntry(),
    ])

  it('refuses one that is not canonical JSON', () => {
    expect(() => parseBundle(withManifestMember(enc('{oops')))).toThrow(/not valid canonical JSON/)
  })

  it.each([
    ['an object with no issuer', '{"key_manifests":[]}'],
    ['an issuer that is not a string', '{"issuer":7,"key_manifests":[]}'],
    ['an empty issuer', '{"issuer":"","key_manifests":[]}'],
  ])('refuses %s', (_label, body) => {
    expect(() => parseBundle(withManifestMember(enc(body)))).toThrow(
      /content issuer must be a nonempty string/,
    )
  })

  it.each([
    ['an array', '[]'],
    ['a string', '"x"'],
    ['key_manifests that is not an array', '{"issuer":"a.example","key_manifests":{"a":1}}'],
    ['key_manifests holding a non-object', '{"issuer":"a.example","key_manifests":[1]}'],
    ['no key_manifests at all', '{"issuer":"a.example"}'],
  ])('trusts no issuer from %s', (_label, body) => {
    const parsed = parseBundle(withManifestMember(enc(body)))
    expect(parsed.trustStore.issuers()).toEqual([])
    expect(Object.keys(parsed.trustStore.data().provenance as JsonObject)).toEqual([])
  })
})

describe('parseBundle: trust material the library will not admit fails the whole import', () => {
  // Reaching `parseTrustStore`'s refusal at all takes a document the checks
  // BEFORE it admit, and there is exactly one gap: §18.4's depth ceiling is
  // measured over the canonicalized view AS A WHOLE, and `chains` nests a
  // manifest one level deeper than `manifests` does — object, issuer, ARRAY,
  // manifest. An importer always builds `chains`, so a manifest can be admitted
  // as a bundle member, canonicalize on its own, sit inside `manifests`, and
  // still put the store document one level over the ceiling.
  //
  // Measured at these sizes (`nest(n)` is n+1 levels deep):
  //   n=251  member ok, store ok
  //   n=252  member ok, store ok WITHOUT chains, REFUSED with them  <- the gap
  //   n=253  the bundle member itself is already refused
  // A branch no input reaches is correct and does nothing, so the number is
  // pinned here rather than chosen for comfort.
  const GAP_DEPTH = 252
  const nest = (levels: number): JsonObject => {
    let value: JsonObject = {}
    for (let i = 0; i < levels; i++) value = { a: value } as unknown as JsonObject
    return value
  }
  const realManifest = (): { issuer: string; km: JsonObject } => {
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const issuer = Object.keys(d.manifests as JsonObject)[0]!
    return { issuer, km: (d.manifests as JsonObject)[issuer] as JsonObject }
  }
  const deepBundle = (levels: number): Uint8Array => {
    const { issuer, km } = realManifest()
    const body = canonicalBytes({
      issuer,
      key_manifests: [{ ...km, deep: nest(levels) }],
      artifact_manifests: [],
    } as unknown as JsonObject)
    return utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      [`manifests/${issuer}.json`, body],
      legalEntry(),
    ])
  }

  it('names this refusal and not the per-member one, and imports nothing', () => {
    const zip = deepBundle(GAP_DEPTH)
    // The message carries the weight: the per-member check refuses with `is
    // outside the canonical profile`, so a test asserting only `BundleError`
    // would pass on THAT branch and never touch this one.
    expect(() => parseBundle(zip)).toThrow(/bundle trust material is not readable/)
    expect(() => parseBundle(zip)).toThrow(BundleError)
    // Not "imported successfully, minus the part I could not read": there is no
    // store to inspect, because the import did not happen.
  })

  it('is the store document that refuses it — the member and the manifest are admitted', () => {
    // The control that makes the test above measure the gap it claims. If
    // either of these ever throws, the refusal has moved upstream and the test
    // above is passing on a branch it does not name.
    const { issuer, km } = realManifest()
    const deep = { ...km, deep: nest(GAP_DEPTH) } as unknown as JsonObject
    expect(() => canonicalBytes(deep)).not.toThrow()
    expect(() =>
      loadsStrict(
        canonicalBytes({
          issuer,
          key_manifests: [deep],
          artifact_manifests: [],
        } as unknown as JsonObject),
      ),
    ).not.toThrow()
  })

  it('is refused when the store DOCUMENT is over the admission ceiling, though the member is under it', () => {
    // The same gap on the other axis §5.2 measures, and this one is reachable
    // with a WELL-FORMED member. `MAX_ADMISSION_BYTES` is 10_000_000 and it
    // applies to the store DOCUMENT; a bundle member is bounded only by the
    // container's own, far larger, floor. So a manifest that canonicalizes on
    // its own and is admitted as a member still puts the store over the
    // ceiling, because the importer files it under `manifests` AND under
    // `chains`.
    //
    // Measured on both importers at these sizes: a 4.0 MB member makes an 8.0 MB
    // document and both accept it; a 5.1 MB member makes a 10.2 MB document and
    // both refuse it with this same message. The pair is what makes the number a
    // measurement rather than a comfortable choice, as GAP_DEPTH's positive
    // control is above.
    //
    // The message AND the class, from ONE call. The message alone is not
    // enough: it comes from the underlying `TrustMaterialError` and survives the
    // wrapper being removed — measured, with the translation to `BundleError`
    // deleted this test stayed green while the depth one went red. And the class
    // alone is not enough either: the depth gap above throws the same wrapper,
    // so a test asserting only it would pass on THAT branch and never touch this
    // one. The class is what `intake` dispatches on (`intake.ts:373`): anything
    // that is not a `BundleError` is re-thrown and reaches the page as a crash
    // instead of a named refusal.
    //
    // `parseBundle` is called ONCE — each call canonicalizes ten megabytes, and
    // two of them run past the default timeout.
    const { issuer, km } = realManifest()
    const big = { ...km, pad: 'x'.repeat(5_100_000) } as unknown as JsonObject
    expect(() => canonicalBytes(big)).not.toThrow()
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      [
        `manifests/${issuer}.json`,
        canonicalBytes({
          issuer,
          key_manifests: [big],
          artifact_manifests: [],
        } as unknown as JsonObject),
      ],
      legalEntry(),
    ])
    let raised: unknown
    try {
      parseBundle(zip)
    } catch (e) {
      raised = e
    }
    expect(raised).toBeInstanceOf(BundleError)
    expect((raised as Error).message).toMatch(/trust store exceeds the admission ceiling/)
    // Timeout, explicitly: this case builds a document just over the ten
    // megabyte ceiling, so its cost is the ceiling and not the property. It
    // measured 3817ms of the default 5000 on a developer machine and timed out
    // on a shared runner (PR 144), which made a required check report the
    // runner's load instead of the refusal it exists to pin. The assertion is
    // that the document is refused, not that it is refused quickly.
  }, 30_000)
})

// The twin of the reference importer's own outcome-class test
// (`tests/test_bundle.py::test_a_refusal_to_read_is_a_different_outcome_from_a_refusal_of_the_bytes`).
// v0.1 §14.4 forbids a surface from presenting an over-floor honest container
// as invalid, corrupt or tampered with — the parser did not process it, which
// is a fact about the verifier and not about the bytes. This page's caps ARE
// the floor, so every resource refusal it makes is above the floor and falls
// under that sentence: without the distinction an honest archive of one member
// too many was told it looked like a bomb.
describe('parseBundle: declining to read is not a verdict about the bytes', () => {
  const corpusLeaf = (name: string): Uint8Array =>
    new Uint8Array(
      readFileSync(join(VECTORS_ROOT, '..', '..', '..', 'tests', 'container-corpus', name, 'archive.zip')),
    )

  it('refuses a malformed container without calling it a resource refusal', () => {
    // Read, and found to be addressable two ways. No budget makes it readable.
    let caught: unknown
    try {
      parseBundle(corpusLeaf('exhibit-D-prefix'))
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(BundleError)
    expect(caught).not.toBeInstanceOf(BundleTooLargeError)
  })

  it('marks a refusal that is only about the caps', () => {
    const { zip } = sampleZip()
    expect(() => parseBundle(zip, { ...DEFAULT_CAPS, maxEntries: 1 })).toThrow(BundleTooLargeError)
  })

  it('leaves a caller who does not care catching what it always caught', () => {
    expect(BundleTooLargeError.prototype).toBeInstanceOf(BundleError)
  })
})

describe('parseBundle refuses a manifest outside the canonical profile', () => {
  // Spliced into the text rather than built: `canonicalBytes` is precisely what
  // refuses to write this integer, so an oracle that used it to construct the
  // case would be calling the code under test.
  const bundleWithVersion = (version: string): Uint8Array => {
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const issuer = Object.keys(d.manifests as JsonObject)[0]
    const km = (d.manifests as JsonObject)[issuer] as JsonObject
    const canonical = new TextDecoder().decode(
      canonicalBytes({ ...km, manifest_version: 1n } as JsonObject),
    )
    const spliced = canonical.replace(/"manifest_version":1/, `"manifest_version":${version}`)
    const blob = `{"issuer":${JSON.stringify(issuer)},"key_manifests":[${spliced}],"artifact_manifests":[]}`
    return utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      [`manifests/${issuer}.json`, new TextEncoder().encode(blob)],
      legalEntry(),
    ])
  }

  it('refuses a manifest_version past the integer boundary', () => {
    // The reference importer canonicalizes the whole store document before the
    // library parses it, so this bundle fails the ENTIRE import there. One bundle
    // importing on one road and refused on the other is the one thing two
    // importers of one format may not do.
    expect(() => parseBundle(bundleWithVersion('9007199254740992'))).toThrow(
      /outside the canonical profile/,
    )
  })

  it('refuses one past the negative boundary too', () => {
    expect(() => parseBundle(bundleWithVersion('-9007199254740992'))).toThrow(
      /outside the canonical profile/,
    )
  })

  it('keeps the largest integer the profile admits', () => {
    // The positive control. Without it a check that refused every manifest would
    // satisfy both refusals above and say nothing about the boundary.
    expect(() => parseBundle(bundleWithVersion('9007199254740991'))).not.toThrow()
  })

  it('refuses it on the intake road as well', () => {
    // `intake` reaches `parseBundle`, so the refusal covers both roads by
    // structure -- asserted rather than assumed, because "by structure" is a
    // claim about a call that someone may later route around.
    const result = intake('bundle.attest', bundleWithVersion('9007199254740992'))
    expect(result.kind).toBe('rejected')
    expect(JSON.stringify(result)).toMatch(/outside the canonical profile/)
  })
})

// Reserved-root admission, v0.1 §14.1 rev 19. Generate names from the
// normative roots/forms, without importing any member-selection predicate.
const selectionForms = {
  receipts: [VALID_RECEIPT_ID, '.attest.json', 'receipts/*.attest.json'],
  manifests: ['store.example.com', '.json', 'manifests/<issuer>.json'],
  legal: [LEGAL_DIGEST, '.txt', 'legal/<sha256>.txt'],
  proofs: [VALID_RECEIPT_ID, '.json', 'proofs/<ULID>.json'],
} as const
const selectionAxes = ['prefix-case', 'suffix-case', 'absent', 'appended', 'combined'] as const
// v0.1 rev 20: spec-derived path prefixes/root separators, each crossed with
// every ASCII root spelling. No importer predicate supplies the expectations.
const selectionSeparatorForms = [
  ['', '\\'], ['/', '/'], ['./', '/'], ['/', '\\'], ['./', '\\'],
  ['\\', '/'], ['.\\', '/'], ['\\', '\\'], ['.\\', '\\'], ['/./', '/'], ['./\\./.\\', '\\'],
] as const
const selectionSuccessorNames = [
  'MANIFESTS/store.example.com.JSON',
  'manifests\\store.example.com.json',
  'Manifests\\store.example.com.json',
  '/manifests/store.example.com.json',
  './manifests/store.example.com.json',
] as const
type SelectionFamily = keyof typeof selectionForms
type SelectionAxis = typeof selectionAxes[number]
const selectionFamilies = Object.keys(selectionForms) as SelectionFamily[]
const selectionReceipt = `receipts/${VALID_RECEIPT_ID}.attest.json`
const selectionNewId = '01JZ5PDHT0000G40R40M30E20A'
const selectionManifest = 'manifests/store.example.com.json'
const selectionProof = `proofs/${VALID_RECEIPT_ID}.json`
const selectionEncoder = new TextEncoder()

function asciiCases(text: string): string[] {
  let values = ['']
  for (const character of text) {
    const choices = character >= 'a' && character <= 'z' ? [character, character.toUpperCase()] : [character]
    values = values.flatMap(prefix => choices.map(choice => prefix + choice))
  }
  return values
}

function selectionInvalidNames(family: SelectionFamily, axis: SelectionAxis): string[] {
  const [stem, suffix] = selectionForms[family]
  const prefixes = asciiCases(family).slice(1)
  const suffixes = asciiCases(suffix).slice(1)
  if (axis === 'prefix-case') return prefixes.map(root => `${root}/${stem}${suffix}`)
  if (axis === 'suffix-case') return suffixes.map(ending => `${family}/${stem}${ending}`)
  if (axis === 'absent') return [`${family}/${stem}`]
  if (axis === 'appended') return [`${family}/${stem}${suffix}.bak`]
  // Every prefix with absent/appended/uppercase suffix, every suffix with
  // uppercase prefix and .bak. Not the full Cartesian product of both axes.
  return [...new Set([
    ...prefixes.flatMap(root => ['', suffix + '.bak', suffix.toUpperCase()].map(ending => `${root}/${stem}${ending}`)),
    ...suffixes.map(ending => `${family.toUpperCase()}/${stem}${ending}`),
    ...suffixes.map(ending => `${family}/${stem}${ending}.bak`),
  ])].sort()
}

function selectionDocument(leaf: string, name: string): JsonObject {
  return loadsStrict(new Uint8Array(readFileSync(join(VECTORS_ROOT, leaf, name)))) as JsonObject
}

function selectionHistory(): [JsonObject, JsonObject] {
  return ['u-stale-pin-not-a-retraction', 'a-rescued-anchored-before-cutoff'].map(leaf => {
    const doc = selectionDocument(`41-compromise-cutoff/${leaf}`, 'manifests.json')
    return (doc.manifests as JsonObject)['store.example.com'] as JsonObject
  }) as [JsonObject, JsonObject]
}

function selectionWrapper(...versions: JsonObject[]): Uint8Array {
  return canonicalBytes({ issuer: 'store.example.com', key_manifests: versions, artifact_manifests: [] })
}

function selectionSignedReceipt(rid = VALID_RECEIPT_ID, field: readonly [string, string] | null = null, digest = LEGAL_DIGEST): Uint8Array {
  const envelope = selectionDocument('01-valid-minimal', 'envelope.json')
  const payload = envelope.payload as JsonObject
  payload.receipt_id = rid
  if (field !== null) {
    const [section, key] = field
    ;(payload[section] as JsonObject)[key] = digest
    if (key === 'eol_commitment_sha256') (payload[section] as JsonObject).eol_commitment_uri = 'https://store.example.com/eol'
  }
  // Fixed corpus seed, test only. Sign altered payloads so the controls
  // independently prove schema and signature validity before name mutation.
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 1)]),
    format: 'der', type: 'pkcs8',
  })
  const signature = sign(null, canonicalBytes(payload), privateKey).toString('base64url')
  return canonicalBytes({ payload, signatures: [{ ...(envelope.signatures as JsonObject[])[0], sig: signature }] })
}

function selectionMembers(twoReceipts = false): Record<string, Uint8Array> {
  const [old] = selectionHistory()
  const entries: Record<string, Uint8Array> = {
    [selectionReceipt]: selectionSignedReceipt(),
    [selectionManifest]: selectionWrapper(old),
    [`legal/${LEGAL_DIGEST}.txt`]: LEGAL_TEXT,
    'README.html': selectionEncoder.encode('<p>Shareable receipt bundle; keep the private bundle private.</p>'),
  }
  if (twoReceipts) entries[`receipts/${selectionNewId}.attest.json`] = selectionSignedReceipt(selectionNewId)
  return entries
}

function selectionRename(entries: Record<string, Uint8Array>, source: string, target: string): Record<string, Uint8Array> {
  expect(target in entries).toBe(false)
  return Object.fromEntries(Object.entries(entries).map(([name, data]) => [name === source ? target : name, data]))
}

function selectionControl(entries: Record<string, Uint8Array>): ReturnType<typeof parseBundle> {
  const parsed = parseBundle(utf8Zip(Object.entries(entries)))
  for (const receipt of parsed.receipts) {
    const run = runVerify(receipt.bytes, parsed.trustStore)
    expect(run.result.schema, JSON.stringify(run.result.errors)).toBe('valid')
    expect(run.result.signature, JSON.stringify(run.result.errors)).toBe('valid')
    expect(run.ok, JSON.stringify(run.result.errors)).toBe(true)
  }
  return parsed
}

function selectionRefusal(entries: Record<string, Uint8Array>, member: string, family: SelectionFamily): void {
  const bytes = utf8Zip(Object.entries(entries))
  let caught: unknown
  try { parseBundle(bytes) } catch (error) { caught = error }
  expect(caught, `member ${JSON.stringify(member)} was accepted`).toBeInstanceOf(BundleError)
  expect((caught as Error).constructor).toBe(BundleError) // malformed, never resource-limit
  const message = (caught as Error).message
  expect(message).toContain(JSON.stringify(member))
  expect(message).toContain(`expected ${selectionForms[family][2]}`)
  expect(message.toLowerCase()).not.toContain('signature invalid')
  // The caller must receive a malformed refusal, not jobs or a declined read.
  const result = intake('member-selection.attest', bytes)
  expect(result.kind).toBe('rejected')
  if (result.kind === 'rejected') {
    expect(result.declined).toBeUndefined()
    expect(result.reason).toBe(message)
  }
}

describe('member-selection red-first', () => {
  for (const axis of selectionAxes) {
    it.each(selectionFamilies)(`case matrix ${axis} %s`, family => {
      const entries = { ...selectionMembers(true), [selectionProof]: evidenceBytes() }
      expect(selectionControl(entries).receipts).toHaveLength(2)
      const [stem, suffix] = selectionForms[family]
      const source = `${family}/${stem}${suffix}`
      const names = selectionInvalidNames(family, axis)
      const failures: string[] = []
      for (const member of names) {
        try { selectionRefusal(selectionRename(entries, source, member), member, family) }
        catch (error) { failures.push(`${JSON.stringify(member)}: ${(error as Error).message}`) }
      }
      expect(failures.length, `${failures.length}/${names.length} selection contract failures; first: ${failures[0]}; last: ${failures.at(-1)}`).toBe(0)
    })
  }

  it.each([false, true])('excluded receipt beside-valid=%s', besideValid => {
    const entries = selectionMembers(besideValid)
    expect(selectionControl(entries).receipts).toHaveLength(besideValid ? 2 : 1)
    const member = `receipts/${VALID_RECEIPT_ID}.ATTEST.JSON`
    selectionRefusal(selectionRename(entries, selectionReceipt, member), member, 'receipts')
  })

  it.each(selectionSuccessorNames.flatMap(member => [false, true].map(besideOld => ({ member, besideOld }))))('restrictive successor $member beside-old=$besideOld', ({ member, besideOld }) => {
    const entries = selectionMembers()
    const [old, successor] = selectionHistory()
    expect(selectionControl(entries).trustStore.manifestFor('store.example.com')!.data()).toEqual(old)
    const compliant = parseBundle(utf8Zip(Object.entries({ ...entries, [selectionManifest]: selectionWrapper(...(besideOld ? [old, successor] : [successor])) })))
    const run = runVerify(selectionSignedReceipt(), compliant.trustStore)
    expect(run.ok).toBe(false)
    expect(run.result.errors.some(error => error.includes('is compromised'))).toBe(true)
    if (!besideOld) delete entries[selectionManifest]
    selectionRefusal({ ...entries, [member]: selectionWrapper(successor) }, member, 'manifests')
  })

  for (const [leading, separator] of selectionSeparatorForms) {
    it.each(selectionFamilies)(`separator matrix ${JSON.stringify([leading, separator])} %s`, family => {
      const entries = { ...selectionMembers(true), [selectionProof]: evidenceBytes() }
      expect(selectionControl(entries).receipts).toHaveLength(2)
      const [stem, suffix] = selectionForms[family]
      const source = `${family}/${stem}${suffix}`
      for (const root of asciiCases(family)) {
        const member = `${leading}${root}${separator}${stem}${suffix}`
        selectionRefusal(selectionRename(entries, source, member), member, family)
      }
    })
  }

  for (const ending of ['', 'example', 'example.json.bak']) {
    it.each(selectionFamilies)(`separator invalid form ${JSON.stringify(ending)} %s`, family => {
      const member = `./${family}\\${ending}`
      selectionRefusal({ ...selectionMembers(), [member]: selectionEncoder.encode('not JSON') }, member, family)
    })
  }

  it.each([
    ...selectionSuccessorNames.slice(1).map(member => ({ member, family: 'manifests' as const })),
    { member: `legal\\${LEGAL_DIGEST}.txt`, family: 'legal' as const },
  ])('separator inventory refusal $member', ({ member, family }) => {
    const entries = selectionMembers()
    selectionControl(entries)
    entries[member] = selectionEncoder.encode('ignored extension; not JSON')
    selectionRefusal(entries, member, family)
    // Selection still wins when a canonical receipt would fail payload parsing.
    entries[selectionReceipt] = selectionEncoder.encode('not JSON')
    selectionRefusal(entries, member, family)
  })

  const fields = [
    ['license', 'legal_text_sha256'], ['survivability', 'mirror_policy_sha256'],
    ['survivability', 'eol_commitment_sha256'], null,
  ] as const
  for (const corrupt of [false, true]) {
    it.each(fields.map(field => ({ field, label: field?.join('.') ?? 'unreferenced' })))(`legal corrupt=${corrupt} field=$label`, ({ field }) => {
      const text = selectionEncoder.encode('member-selection additional legal document')
      const digest = sha256Hex(text)
      const source = `legal/${digest}.txt`
      const entries = { ...selectionMembers(), [source]: text }
      entries[selectionReceipt] = selectionSignedReceipt(VALID_RECEIPT_ID, field, digest)
      expect(selectionControl(entries).legalTexts[digest]).toEqual(text)
      if (corrupt) {
        entries[source] = selectionEncoder.encode('corrupt legal text, with a correct ZIP CRC')
        expect(() => parseBundle(utf8Zip(Object.entries(entries)))).toThrow(/integrity/)
      }
      const member = `legal/${digest}.TXT`
      selectionRefusal(selectionRename(entries, source, member), member, 'legal')
    })
  }

  it.each(selectionFamilies)('directory marker %s', family => {
    const entries = selectionMembers()
    selectionControl(entries)
    const member = family + '/'
    selectionRefusal({ ...entries, [member]: new Uint8Array() }, member, family)
  })

  it.each([
    'future-evidence/receipt.cbor', 'witness-notes/note.v3', 'receipt/example.attest.json',
    'receıpts/example.ATTEST.JSON', 'receipts-extra/example.JSON', 'README.html',
    'receipt\u017f/example.JSON', '\uff52\uff45\uff43\uff45\uff49\uff50\uff54\uff53/example.JSON', 'proofs',
    '../manifests/example.json', 'other/../manifests/example.json',
    'C:\\manifests\\example.json', '%2fmanifests/example.json',
    './future-evidence\\receipt.cbor', '/witness-notes/note.v3',
    './receipt\\example.attest.json', './receipt\u017f\\example.JSON',
    '/\uff52\uff45\uff43\uff45\uff49\uff50\uff54\uff53/example.JSON', './manifests',
  ])('outside control %s', member => {
    expect(selectionControl({ ...selectionMembers(), [member]: selectionEncoder.encode('ignored extension; not JSON') }).receipts).toHaveLength(1)
  })

  it.each(['MiXeD.name.v2', 'folder/Another.File', 'folder\\Another.File', '', 'note\nreceipt\tname'])('free receipt name control %j', middle => {
    const entries = selectionRename(selectionMembers(), selectionReceipt, `receipts/${middle}.attest.json`)
    expect(selectionControl(entries).receipts[0].receiptId).toBe(VALID_RECEIPT_ID)
  })

  it.each([`proofs/${VALID_RECEIPT_ID}.txt`, `proofs/nested/${VALID_RECEIPT_ID}.json`, 'proofs/not-a-ulid.json'])('existing proof path control %s', member => {
    const entries = { ...selectionMembers(), [selectionProof]: evidenceBytes() }
    selectionControl(entries)
    selectionRefusal(selectionRename(entries, selectionProof, member), member, 'proofs')
  })

  it.each(['RECEIPTS/excluded.JSON', './RECEIPTS\\excluded.JSON'])('duplicate precedence control %s', member => {
    const entries = selectionMembers()
    selectionControl(entries)
    const bytes = utf8Zip([...Object.entries(entries), [member, selectionSignedReceipt()], [member, selectionSignedReceipt()]])
    let caught: unknown
    try { parseBundle(bytes) } catch (error) { caught = error }
    expect((caught as Error).constructor).toBe(BundleError)
    expect((caught as Error).message).toContain('central directory repeats member name')
    // Container diagnostics predate selection admission and do not expose
    // member names. Pin the inventory error's member separately.
    let inventoryError: unknown
    try { canonicalMembers(bytes, DEFAULT_CAPS) } catch (error) { inventoryError = error }
    expect(inventoryError).toBeInstanceOf(ContainerError)
    expect((inventoryError as ContainerError).code).toBe('duplicate-name')
    expect((inventoryError as ContainerError).member).toBe(member)
    expect((caught as Error).message).not.toContain('expected receipts/')
  })

  it.each(['RECEIPTS/excluded.JSON', './RECEIPTS\\excluded.JSON'])('private precedence control %s', member => {
    const entries = selectionMembers()
    selectionControl(entries)
    expect(() => parseBundle(utf8Zip(Object.entries({
      ...entries, [member]: selectionSignedReceipt(), 'salts.json': selectionEncoder.encode('{}'),
    })))).toThrow(PrivateBundleError)
  })

  it('control characters in selection diagnostics', () => {
    const entries = selectionMembers()
    selectionControl(entries)
    const member = 'manifests/store.example.com.json\nSUCCESS\t\u001b[31m.bak'
    selectionRefusal(selectionRename(entries, selectionManifest, member), member, 'manifests')
  })
})


describe('member-selection logged proof', () => {
  it.each([`PROOFS/${VALID_RECEIPT_ID}.json`, `proofs/${VALID_RECEIPT_ID}.txt`])('%s', member => {
    const entries = {
      ...selectionMembers(),
      [selectionReceipt]: new Uint8Array(readFileSync(join(V28, 'envelope.json'))),
      [selectionProof]: evidenceBytes(),
    }
    const parsed = selectionControl(entries)
    const run = runVerify(entries[selectionReceipt], parsed.trustStore, null, null, {
      transparency: parsed.proofs[VALID_RECEIPT_ID], logKeys: logKeys(V28), anchorPolicy: anchorPolicy(V28),
    })
    expect(run.ok).toBe(true)
    expect(run.result.transparency).toBe('logged')
    expect(run.result.corroboration).toBe('logged')
    selectionRefusal(selectionRename(entries, selectionProof, member), member, 'proofs')
  })
})
