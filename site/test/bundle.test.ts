import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { parseBundle, BundleError, PrivateBundleError, DEFAULT_CAPS } from '../src/bundle.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT, logKeys, anchorPolicy } from './helpers/vectors.js'

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
