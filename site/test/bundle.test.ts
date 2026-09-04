import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { parseBundle, BundleError, BundleTooLargeError, PrivateBundleError, DEFAULT_CAPS } from '../src/bundle.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT, logKeys, anchorPolicy } from './helpers/vectors.js'
// Aliased: this file already defines a local `storedZip` that does NOT set
// general-purpose bit 11, so a non-ASCII member name written with it is refused
// as `record-name-encoding` before any test can reason about it.
import { storedZip as utf8Zip, validEnvelope, VALID_RECEIPT_ID, legalEntry } from './helpers/zip.js'

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
    expect(parsed.trustStore.provenance[issuer]).toBe('bundle')
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
    })
    const parsed = parseBundle(zip)
    expect((parsed.trustStore.manifests[issuer] as JsonObject).manifest_version).toBe(2n)
    expect(parsed.trustStore.chains?.[issuer]).toHaveLength(2)
    expect((parsed.trustStore.chains?.[issuer][0] as JsonObject).manifest_version).toBe(1n)
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

  // The writer itself is verified first: a throw on the duplicated archive
  // proves nothing unless the non-duplicated one round-trips.
  it('round-trips a hand-built zip without duplicates', () => {
    const parsed = parseBundle(storedZip([[NAME, env()]]))
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
    const parsed = parseBundle(storedZip([[NAME, env()], [second, secondBytes]]))
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
      ['manifests/attacker.json']: canonicalBytes(blob),
    })
  }

  it('keeps an issuer named after an object member as an ordinary key', () => {
    const { trustStore } = parseBundle(protoBundle())
    expect(Object.keys(trustStore.manifests)).toEqual(['__proto__'])
    expect(Object.keys(trustStore.provenance)).toEqual(['__proto__'])
    expect(Object.keys(trustStore.chains ?? {})).toEqual(['__proto__'])
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
    expect(trustStore.manifests[victim]).toBeUndefined()
    expect(trustStore.provenance[victim]).toBeUndefined()
    expect(trustStore.chains?.[victim]).toBeUndefined()
  })

  it('answers nothing for a name every JavaScript object carries', () => {
    // `toString` is on every ordinary object, so a receipt claiming that
    // issuer used to be handed a function where a manifest belongs.
    const { zip } = sampleZip()
    const { trustStore, proofs } = parseBundle(zip)
    expect(trustStore.manifests['toString']).toBeUndefined()
    expect(trustStore.provenance['toString']).toBeUndefined()
    expect(trustStore.chains?.['toString']).toBeUndefined()
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
// order rather than on anything the bundle states. The reference importer makes
// the same refusal, in the same words.
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
    expect(() => parseBundle(zip)).toThrow(/one issuer in more than one manifest member/)
  })

  it('still accepts two manifest members that claim different issuers', () => {
    // The refusal above must be a limit and not a ban: a bundle carrying two
    // sellers' key lists is the ordinary shape of a library.
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/a.json', manifestFor('store.example.com', 1n)],
      ['manifests/b.json', manifestFor('other.example.com', 1n)],
      legalEntry(),
    ])
    const { trustStore } = parseBundle(zip)
    expect(Object.keys(trustStore.manifests).sort()).toEqual([
      'other.example.com',
      'store.example.com',
    ])
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
      ['manifests/only.json', blob],
      legalEntry(),
    ])
    const { trustStore } = parseBundle(zip)
    expect((trustStore.manifests[issuer] as JsonObject)['manifest_version']).toBe(2n)
    expect(trustStore.chains?.[issuer]).toHaveLength(2)
  })

  it('does not count a member it skips as a claim on an issuer', () => {
    // An unshaped blob contributes no issuer at all — the reference importer
    // skips it — so it cannot collide with the member that does.
    const issuer = 'store.example.com'
    const zip = utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/unshaped.json', canonicalBytes({ issuer: 1n } as unknown as JsonObject)],
      ['manifests/real.json', manifestFor(issuer, 1n)],
      legalEntry(),
    ])
    expect(Object.keys(parseBundle(zip).trustStore.manifests)).toEqual([issuer])
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

describe('parseBundle: a manifests/ member that is not shaped like one', () => {
  const enc = (text: string): Uint8Array => new TextEncoder().encode(text)
  const withManifestMember = (body: Uint8Array): Uint8Array =>
    utf8Zip([
      [`receipts/${VALID_RECEIPT_ID}.attest.json`, validEnvelope()],
      ['manifests/x.json', body],
    ])

  it('refuses one that is not canonical JSON', () => {
    expect(() => parseBundle(withManifestMember(enc('{oops')))).toThrow(/not valid canonical JSON/)
  })

  it.each([
    ['an array', '[]'],
    ['a string', '"x"'],
    ['an object with no issuer', '{"key_manifests":[]}'],
    ['an issuer that is not a string', '{"issuer":7,"key_manifests":[]}'],
    ['key_manifests that is not an array', '{"issuer":"a.example","key_manifests":{"a":1}}'],
    ['key_manifests holding a non-object', '{"issuer":"a.example","key_manifests":[1]}'],
    ['no key_manifests at all', '{"issuer":"a.example"}'],
  ])('trusts no issuer from %s', (_label, body) => {
    const parsed = parseBundle(withManifestMember(enc(body)))
    expect(Object.keys(parsed.trustStore.manifests)).toEqual([])
    expect(Object.keys(parsed.trustStore.provenance)).toEqual([])
  })
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
