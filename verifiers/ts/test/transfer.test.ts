// Tests for src/transfer.ts — issuer-mediated transfer records (v0.2 §17).
// Mirrors tests/test_transfer.py (Python reference) case-for-case. transfer.ts
// is verification-side only (design §9: no build/sign here), so fixtures are
// hand-signed directly with @noble/curves + @noble/post-quantum, the same
// idiom sibling-hybrid.test.ts already established for hybrid-signed
// side-documents (in-memory, per-test keys — no cross-language fixture
// needed since only docs/spec/vectors/ requires byte-for-byte Python
// reproducibility).
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { loadsStrict, canonicalBytes } from '../src/canon.js'
import type { JsonObject } from '../src/canon.js'
import { b64uEncode, b64uDecode } from '../src/b64u.js'
import { ML_DSA_65_SIG_LEN } from '../src/mldsa.js'
import { TransparencyError } from '../src/transparency.js'
import type { LogKey } from '../src/tlog.js'
import { encodeEntry } from '../src/tlog.js'
import type { AnchorPolicy } from '../src/anchor.js'
import {
  authorizationMessage,
  LABEL_TRANSFER_AUTHORIZATION,
  verifyAuthorization,
  recordHash,
  verifyRecordSignature,
  verifyRecord,
  recordLoggedStanding,
  auditChain,
} from '../src/transfer.js'
import { buildTree, inclusionProof, signCheckpoint, type HybridTestKeys } from './helpers/tlog-builder.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (v: unknown): JsonObject => loadsStrict(enc(JSON.stringify(v))) as JsonObject

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/test#ed25519-1`
const OTHER_KID = `${ISSUER}/keys/test#ed25519-2`

// TEST ONLY — fixed seeds, never use in production.
const issuerSeed = Uint8Array.from({ length: 32 }, () => 21)
const otherIssuerSeed = Uint8Array.from({ length: 32 }, () => 22)
const holderSeed = Uint8Array.from({ length: 32 }, () => 23)
const otherHolderSeed = Uint8Array.from({ length: 32 }, () => 24)
const newHolderSeed = Uint8Array.from({ length: 32 }, () => 25)
const secondNewHolderSeed = Uint8Array.from({ length: 32 }, () => 26)

const issuerPub = ed25519.getPublicKey(issuerSeed)
const otherIssuerPub = ed25519.getPublicKey(otherIssuerSeed)
const holderPub = ed25519.getPublicKey(holderSeed)
const otherHolderPub = ed25519.getPublicKey(otherHolderSeed)
const newHolderPub = ed25519.getPublicKey(newHolderSeed)
const secondNewHolderPub = ed25519.getPublicKey(secondNewHolderSeed)

const OLD_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAV'
const NEW_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAW'
const AT = '2026-07-23T00:00:00Z'
const PUB_B64U = b64uEncode(newHolderPub)

function keyManifest(): JsonObject {
  const entry = {
    kid: KID, pub: b64uEncode(issuerPub), valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active',
  }
  const body = { issuer: ISSUER, manifest_version: 1, issued_at: '2026-01-01T00:00:00Z', keys: [entry] }
  const bodyParsed = parse(body)
  const sig = ed25519.sign(canonicalBytes(bodyParsed), issuerSeed)
  return parse({ ...body, manifest_signature: { kid: KID, sig: b64uEncode(sig) } })
}

function keyManifestWithWindow(validFrom: string, validTo: string | null): JsonObject {
  const entry = { kid: KID, pub: b64uEncode(issuerPub), valid_from: validFrom, valid_to: validTo, status: 'active' }
  const body = { issuer: ISSUER, manifest_version: 1, issued_at: '2026-01-01T00:00:00Z', keys: [entry] }
  const bodyParsed = parse(body)
  const sig = ed25519.sign(canonicalBytes(bodyParsed), issuerSeed)
  return parse({ ...body, manifest_signature: { kid: KID, sig: b64uEncode(sig) } })
}

function hybridKeyManifest(): { hk: HybridTestKeys; manifest: JsonObject } {
  const edSeed = Uint8Array.from({ length: 32 }, () => 41)
  const edPub = ed25519.getPublicKey(edSeed)
  const { publicKey: mldsaPub, secretKey: mldsaSecret } = ml_dsa65.keygen(Uint8Array.from({ length: 32 }, () => 42))
  const entry = {
    kid: KID, pub: b64uEncode(edPub), valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active',
    pub_ml_dsa_65: b64uEncode(mldsaPub),
  }
  const body = { issuer: ISSUER, manifest_version: 1, issued_at: '2026-01-01T00:00:00Z', keys: [entry] }
  const bodyParsed = parse(body)
  const edSig = ed25519.sign(canonicalBytes(bodyParsed), edSeed)
  const mldsaSig = ml_dsa65.sign(canonicalBytes(bodyParsed), mldsaSecret)
  const manifest = parse({
    ...body,
    manifest_signature: { kid: KID, sig: b64uEncode(edSig), sig_ml_dsa_65: b64uEncode(mldsaSig) },
  })
  return { hk: { edSeed, edPub, mldsaPub, mldsaSecret }, manifest }
}

interface BuildRecordOptions {
  receiptId?: string
  newReceiptId?: string
  newHolderPubkey?: string
  transferredAt?: string
  holderSeed?: Uint8Array
  issuerSeed?: Uint8Array
  kid?: string
  hybrid?: { edSeed: Uint8Array; mldsaSecret: Uint8Array }
}

function signAuthorization(receiptId: string, newHolderPubkey: string, transferredAt: string, hSeed: Uint8Array): Uint8Array {
  return ed25519.sign(authorizationMessage(receiptId, newHolderPubkey, transferredAt), hSeed)
}

function buildRecord(opts: BuildRecordOptions = {}): JsonObject {
  const receiptId = opts.receiptId ?? OLD_ID
  const newReceiptId = opts.newReceiptId ?? NEW_ID
  const newHolderPubkey = opts.newHolderPubkey ?? PUB_B64U
  const transferredAt = opts.transferredAt ?? AT
  const hSeed = opts.holderSeed ?? holderSeed
  const iSeed = opts.issuerSeed ?? issuerSeed
  const kid = opts.kid ?? KID

  const authSig = signAuthorization(receiptId, newHolderPubkey, transferredAt, hSeed)
  const body = {
    receipt_id: receiptId,
    new_receipt_id: newReceiptId,
    new_holder_pubkey: newHolderPubkey,
    transferred_at: transferredAt,
    holder_authorization: { sig: b64uEncode(authSig) },
  }
  const bodyParsed = parse(body)
  if (opts.hybrid) {
    const edSig = ed25519.sign(canonicalBytes(bodyParsed), opts.hybrid.edSeed)
    const mldsaSig = ml_dsa65.sign(canonicalBytes(bodyParsed), opts.hybrid.mldsaSecret)
    return parse({ ...body, signature: { kid, sig: b64uEncode(edSig), sig_ml_dsa_65: b64uEncode(mldsaSig) } })
  }
  const sig = ed25519.sign(canonicalBytes(bodyParsed), iSeed)
  return parse({ ...body, signature: { kid, sig: b64uEncode(sig) } })
}

function resignRecord(record: JsonObject, iSeed: Uint8Array = issuerSeed, kid: string = KID): JsonObject {
  const body: Record<string, unknown> = {}
  for (const k of Object.keys(record)) if (k !== 'signature') body[k] = record[k]
  const sig = ed25519.sign(canonicalBytes(parse(body)), iSeed)
  return { ...record, signature: { kid, sig: b64uEncode(sig) } }
}

// --- authorizationMessage ----------------------------------------------------

describe('authorizationMessage', () => {
  it('is domain-separated', () => {
    const msg = authorizationMessage(OLD_ID, PUB_B64U, AT)
    const expected = new Uint8Array([
      ...LABEL_TRANSFER_AUTHORIZATION, 0x00, ...enc(OLD_ID), 0x00, ...enc(PUB_B64U), 0x00, ...enc(AT),
    ])
    expect(msg).toEqual(expected)
  })

  it('LABEL_TRANSFER_AUTHORIZATION is the exact literal', () => {
    expect(new TextDecoder().decode(LABEL_TRANSFER_AUTHORIZATION)).toBe('Attest-transfer-authorization-v1')
  })
})

// --- verifyRecord / verifyRecordSignature roundtrip -------------------------

describe('verifyRecord roundtrip', () => {
  it('a well-formed Ed25519 record verifies and its own authorization checks out', () => {
    const record = buildRecord()
    expect(Object.keys(record).sort()).toEqual(
      ['holder_authorization', 'new_holder_pubkey', 'new_receipt_id', 'receipt_id', 'signature', 'transferred_at'].sort(),
    )
    expect(verifyRecord(record, keyManifest())).toBe(true)
    expect(verifyAuthorization(record, b64uEncode(holderPub))).toBe(true)
  })

  it('verifyAuthorization fails against the wrong holder key', () => {
    const record = buildRecord()
    expect(verifyAuthorization(record, b64uEncode(otherHolderPub))).toBe(false)
  })

  it('verifyAuthorization never raises on a malformed record (missing sig)', () => {
    const record = buildRecord()
    const auth = { ...(record['holder_authorization'] as JsonObject) }
    delete auth['sig']
    const mutated = { ...record, holder_authorization: auth }
    expect(verifyAuthorization(mutated, b64uEncode(holderPub))).toBe(false)
  })

  it('verifyAuthorization never raises on wrong-typed fields', () => {
    const record = buildRecord()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mutated = { ...record, receipt_id: 12345 as any }
    expect(verifyAuthorization(mutated, b64uEncode(holderPub))).toBe(false)
  })
})

// --- review round 1: holder authorization strictness ------------------------

describe('holder authorization strictness', () => {
  it('an issuer-signed record with an undecodable holder sig fails (malformed before issuer signing)', () => {
    const body = {
      receipt_id: OLD_ID, new_receipt_id: NEW_ID, new_holder_pubkey: PUB_B64U, transferred_at: AT,
      holder_authorization: { sig: '!'.repeat(86) },
    }
    const sig = ed25519.sign(canonicalBytes(parse(body)), issuerSeed)
    const record = parse({ ...body, signature: { kid: KID, sig: b64uEncode(sig) } })
    expect(verifyRecord(record, keyManifest())).toBe(false)
  })

  it('a post-signing undecodable holder sig also fails', () => {
    const record = buildRecord()
    const auth = { ...(record['holder_authorization'] as JsonObject), sig: '!'.repeat(86) }
    const mutated = { ...record, holder_authorization: auth }
    expect(verifyRecord(mutated, keyManifest())).toBe(false)
  })
})

// --- review round 1: fail-closed verification boundary ----------------------

describe('verifyRecord fails closed at the untrusted boundary', () => {
  it('non-object signature block', () => {
    const record = buildRecord()
    const mutated = { ...record, signature: [] as unknown as JsonObject }
    expect(verifyRecord(mutated, keyManifest())).toBe(false)
  })

  it('non-canonicalizable record field', () => {
    const record = buildRecord()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mutated = { ...record, receipt_id: { bogus: () => {} } as any }
    expect(verifyRecord(mutated, keyManifest())).toBe(false)
  })

  it('malformed key manifest', () => {
    const record = buildRecord()
    expect(verifyRecord(record, [] as unknown as JsonObject)).toBe(false)
  })
})

// --- review round 1: §17.1 closed record profile ----------------------------

describe('closed six-field record profile', () => {
  it('rejects an extra member', () => {
    const record = resignRecord({ ...buildRecord(), extra: 'not permitted' })
    expect(verifyRecord(record, keyManifest())).toBe(false)
  })

  it.each(['receipt_id', 'new_receipt_id'])('rejects a bad ULID in %s', (field) => {
    const record = resignRecord({ ...buildRecord(), [field]: 'not-a-ulid' })
    expect(verifyRecord(record, keyManifest())).toBe(false)
  })

  it('rejects a 31-byte new_holder_pubkey', () => {
    const record = buildRecord({ newHolderPubkey: b64uEncode(new Uint8Array(31)) })
    expect(verifyRecord(record, keyManifest())).toBe(false)
  })

  it('rejects a non-canonical transferred_at', () => {
    const record = buildRecord({ transferredAt: '2026-7-3T0:0:0Z' })
    expect(verifyRecord(record, keyManifest())).toBe(false)
  })

  it.each(['2026-02-30T00:00:00Z', '2026-13-01T00:00:00Z', '2026-04-31T00:00:00Z'])(
    'rejects an impossible calendar transferred_at (%s)',
    (transferredAt) => {
      const record = buildRecord({ transferredAt })
      expect(verifyRecord(record, keyManifest())).toBe(false)
    },
  )
})

// --- review round 1: direct holder-authorization verification ---------------

describe('verifyAuthorization strictness', () => {
  it('rejects an extra holder_authorization member', () => {
    const record = buildRecord()
    const auth = { ...(record['holder_authorization'] as JsonObject), extra: 'not permitted' }
    const mutated = { ...record, holder_authorization: auth }
    expect(verifyAuthorization(mutated, b64uEncode(holderPub))).toBe(false)
  })

  it('rejects a non-canonical holder signature encoding', () => {
    const record = buildRecord()
    const auth = record['holder_authorization'] as JsonObject
    const mutated = { ...record, holder_authorization: { ...auth, sig: `${auth['sig']}=` } }
    expect(verifyAuthorization(mutated, b64uEncode(holderPub))).toBe(false)
  })
})

// --- hybrid AND-rule (mirrors sibling-hybrid.test.ts) -----------------------

describe('hybrid AND-rule', () => {
  it('a classical-only record against a hybrid key fails closed', () => {
    const { hk, manifest } = hybridKeyManifest()
    const record = buildRecord({ issuerSeed: hk.edSeed })
    expect(verifyRecord(record, manifest)).toBe(false)
  })

  it('a hybrid record roundtrips', () => {
    const { hk, manifest } = hybridKeyManifest()
    const record = buildRecord({ hybrid: { edSeed: hk.edSeed, mldsaSecret: hk.mldsaSecret } })
    const sig = record['signature'] as JsonObject
    expect('sig' in sig).toBe(true)
    expect('sig_ml_dsa_65' in sig).toBe(true)
    expect(verifyRecord(record, manifest)).toBe(true)
  })

  it('a hybrid record with a tampered ML-DSA-65 leg fails', () => {
    const { hk, manifest } = hybridKeyManifest()
    const record = buildRecord({ hybrid: { edSeed: hk.edSeed, mldsaSecret: hk.mldsaSecret } })
    const sig = record['signature'] as JsonObject
    const raw = b64uDecode(sig['sig_ml_dsa_65'] as string)
    raw[0] = raw[0]! ^ 0xff
    const mutated = { ...record, signature: { ...sig, sig_ml_dsa_65: b64uEncode(raw) } }
    expect(verifyRecord(mutated, manifest)).toBe(false)
  })

  it('an Ed25519-only record with a stray ML-DSA-65 leg fails', () => {
    const record = buildRecord()
    const sig = record['signature'] as JsonObject
    const mutated = { ...record, signature: { ...sig, sig_ml_dsa_65: b64uEncode(new Uint8Array(ML_DSA_65_SIG_LEN)) } }
    expect(verifyRecord(mutated, keyManifest())).toBe(false)
  })
})

// --- signer key window -------------------------------------------------

describe('signer key window', () => {
  it('rejects a transferred_at outside the key validity window', () => {
    const km = keyManifestWithWindow('2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z')
    const record = buildRecord({ transferredAt: '2026-07-23T00:00:00Z' })
    expect(verifyRecord(record, km)).toBe(false)
  })
})

// --- malformed holder_authorization shapes ----------------------------------

describe('malformed holder_authorization shapes fail closed', () => {
  const cases: Array<[string, (sig: string) => unknown]> = [
    ['missing_member', () => ({})],
    ['extra_member', (sig) => ({ sig, extra: 'x' })],
    ['non_dict', () => 'not-a-dict'],
    ['non_b64u_sig', (sig) => ({ sig: '!'.repeat(sig.length) })],
    ['wrong_length_sig', (sig) => ({ sig: sig.slice(0, -1) })],
  ]

  it.each(cases)('%s', (_name, mutate) => {
    const record = buildRecord()
    const originalSig = (record['holder_authorization'] as JsonObject)['sig'] as string
    const mutated = { ...record, holder_authorization: mutate(originalSig) as JsonObject }
    expect(verifyRecord(mutated, keyManifest())).toBe(false)
  })
})

// --- recordHash (mirrors revocation.recordHash) -----------------------------

describe('recordHash', () => {
  it('is SHA-256 of the canonical bytes', () => {
    const record = buildRecord()
    const expected = bytesToHex(sha256(canonicalBytes(record)))
    expect(recordHash(record)).toBe(expected)
  })

  it('covers the signature member', () => {
    const recordA = buildRecord({ issuerSeed, kid: KID })
    const recordB = buildRecord({ issuerSeed: otherIssuerSeed, kid: OTHER_KID })
    expect(recordHash(recordA)).not.toBe(recordHash(recordB))
  })
})

// --- recordLoggedStanding ----------------------------------------------------

const TRANSFER_LOG_ORIGIN = 'transfer-log.attest.example/2026'
const TRANSFER_LOG_NAME = 'attest-transfer-log-1'

function transferLogKey(hk: HybridTestKeys): LogKey {
  return { origin: TRANSFER_LOG_ORIGIN, name: TRANSFER_LOG_NAME, ed25519Pub: hk.edPub, mldsaPub: hk.mldsaPub }
}

function noHorizonPolicy(): AnchorPolicy {
  return { pinnedHeaders: {}, crqcHorizon: null }
}

function generateHybridLogKeys(): HybridTestKeys {
  const edSeed = ed25519.utils.randomSecretKey()
  const edPub = ed25519.getPublicKey(edSeed)
  const { publicKey: mldsaPub, secretKey: mldsaSecret } = ml_dsa65.keygen()
  return { edSeed, edPub, mldsaPub, mldsaSecret }
}

function transferLogEvidence(record: JsonObject, hk: HybridTestKeys, issuerId: string = ISSUER): Record<string, unknown> {
  const entry = { type: 'transfer-record', issuer: issuerId, record_sha256: recordHash(record) }
  const entryBytes = encodeEntry(entry)
  const root = buildTree([entryBytes])
  const checkpointText = signCheckpoint(TRANSFER_LOG_ORIGIN, 1, root, hk, TRANSFER_LOG_NAME)
  return { entry, leaf_index: 0, tree_size: 1, inclusion_proof: [], checkpoint: checkpointText }
}

describe('recordLoggedStanding', () => {
  it('returns the leaf index when logged', () => {
    const hk = generateHybridLogKeys()
    const record = buildRecord()
    const evidence = parse(transferLogEvidence(record, hk))

    const leafIndex = recordLoggedStanding(record, evidence, ISSUER, [transferLogKey(hk)], noHorizonPolicy())

    expect(leafIndex).toBe(0)
  })

  it('returns null without evidence', () => {
    const hk = generateHybridLogKeys()
    const record = buildRecord()

    expect(recordLoggedStanding(record, null, ISSUER, [transferLogKey(hk)], noHorizonPolicy())).toBeNull()
  })

  it('returns null on unresolvable evidence', () => {
    const hk = generateHybridLogKeys()
    const record = buildRecord()
    const evidence = parse(transferLogEvidence(record, hk))
    const mutated = { ...evidence, checkpoint: 'not a real checkpoint\n' }

    const warnings: string[] = []
    const leafIndex = recordLoggedStanding(record, mutated, ISSUER, [transferLogKey(hk)], noHorizonPolicy(), warnings)

    expect(leafIndex).toBeNull()
    expect(warnings.length).toBeGreaterThan(0)
  })

  it('raises on malformed log keys (trusted verifier config)', () => {
    const record = buildRecord()
    expect(() => recordLoggedStanding(record, parse({ entry: {} }), ISSUER, [], noHorizonPolicy())).toThrow(TransparencyError)
  })
})

// --- auditChain (v0.2 §17.5) -------------------------------------------------

const ID0 = OLD_ID
const ID1 = NEW_ID
const ID2 = '01ARZ3NDEKTSV4RRFFQ69G5FAY'
const LOSING_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAZ'
const AT2 = '2026-07-24T00:00:00Z'

function chainPayload(receiptId: string, buyerPub: Uint8Array): JsonObject {
  return parse({ receipt_id: receiptId, buyer: { pubkey: b64uEncode(buyerPub) } })
}

function chainTransferRecord(
  receiptId: string, newReceiptId: string, newHolderKeyPub: Uint8Array, holderKeySeed: Uint8Array, transferredAt: string = AT,
): JsonObject {
  return buildRecord({
    receiptId, newReceiptId, newHolderPubkey: b64uEncode(newHolderKeyPub), transferredAt, holderSeed: holderKeySeed,
  })
}

function chainTransferredRevocation(receiptId: string, at: string = AT): JsonObject {
  const body = { receipt_id: receiptId, status: 'transferred', revoked_at: at }
  const sig = ed25519.sign(canonicalBytes(parse(body)), issuerSeed)
  return parse({ ...body, signature: { kid: KID, sig: b64uEncode(sig) } })
}

function chainLogBundle(recordsInOrder: JsonObject[], hk: HybridTestKeys): Record<string, unknown>[] {
  const entries = recordsInOrder.map((r) => ({ type: 'transfer-record', issuer: ISSUER, record_sha256: recordHash(r) }))
  const leaves = entries.map((e) => encodeEntry(e))
  const root = buildTree(leaves)
  const treeSize = leaves.length
  const checkpointText = signCheckpoint(TRANSFER_LOG_ORIGIN, treeSize, root, hk, TRANSFER_LOG_NAME)
  return entries.map((entry, i) => ({
    entry, leaf_index: i, tree_size: treeSize,
    inclusion_proof: inclusionProof(leaves, i).map((p) => Buffer.from(p).toString('hex')),
    checkpoint: checkpointText,
  }))
}

describe('auditChain', () => {
  it('validates a two-link chain', () => {
    const hk = generateHybridLogKeys()
    const p0 = chainPayload(ID0, holderPub)
    const p1 = chainPayload(ID1, newHolderPub)
    const p2 = chainPayload(ID2, secondNewHolderPub)

    const record1 = chainTransferRecord(ID0, ID1, newHolderPub, holderSeed, AT)
    const record2 = chainTransferRecord(ID1, ID2, secondNewHolderPub, newHolderSeed, AT2)
    const [bundle1, bundle2] = chainLogBundle([record1, record2], hk)
    const view = parse([
      { record: record1, evidence: bundle1 },
      { record: record2, evidence: bundle2 },
    ])
    const revView = parse([chainTransferredRevocation(ID0, AT), chainTransferredRevocation(ID1, AT2)])

    const res = auditChain([p0, p1, p2], view, revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.valid).toBe(true)
    expect(res.linkStatus).toEqual(['valid', 'valid'])
    expect(res.errors).toEqual([])
  })

  it('rejects a pubkey loop-closure failure', () => {
    const hk = generateHybridLogKeys()
    const p0 = chainPayload(ID0, holderPub)
    // p1's own buyer.pubkey does NOT match the transfer record's new_holder_pubkey.
    const p1 = chainPayload(ID1, secondNewHolderPub)

    const record1 = chainTransferRecord(ID0, ID1, newHolderPub, holderSeed, AT)
    const bundle1 = chainLogBundle([record1], hk)[0]
    const view = parse([{ record: record1, evidence: bundle1 }])
    const revView = parse([chainTransferredRevocation(ID0, AT)])

    const res = auditChain([p0, p1], view, revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain('chain link 1: new receipt buyer.pubkey != new_holder_pubkey')
  })

  it('rejects the losing branch of a double assignment', () => {
    const hk = generateHybridLogKeys()
    const p0 = chainPayload(ID0, holderPub)
    // The chain is built on the LATER-logged record (new_receipt_id=LOSING_ID).
    const p1 = chainPayload(LOSING_ID, secondNewHolderPub)

    const earlyRecord = chainTransferRecord(ID0, ID1, newHolderPub, holderSeed, AT)
    const lateRecord = chainTransferRecord(ID0, LOSING_ID, secondNewHolderPub, holderSeed, AT)
    // Log order: earlyRecord first (leaf_index 0), lateRecord second (1).
    const [earlyBundle, lateBundle] = chainLogBundle([earlyRecord, lateRecord], hk)
    const view = parse([
      { record: earlyRecord, evidence: earlyBundle },
      { record: lateRecord, evidence: lateBundle },
    ])
    const revView = parse([chainTransferredRevocation(ID0, AT)])

    const res = auditChain([p0, p1], view, revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain('chain link 1: losing branch of a double assignment')
  })

  it('ignores a pre-floor competing claim', () => {
    const hk = generateHybridLogKeys()
    const p0 = parse({ receipt_id: ID0, buyer: { pubkey: b64uEncode(holderPub) }, license: { not_transferable_before: '2026-07-24T00:00:00Z' } })
    const p1 = chainPayload(ID1, newHolderPub)

    const preFloorRecord = chainTransferRecord(ID0, LOSING_ID, secondNewHolderPub, holderSeed, AT)
    const validRecord = chainTransferRecord(ID0, ID1, newHolderPub, holderSeed, AT2)
    const [preFloorBundle, validBundle] = chainLogBundle([preFloorRecord, validRecord], hk)
    const view = parse([
      { record: preFloorRecord, evidence: preFloorBundle },
      { record: validRecord, evidence: validBundle },
    ])
    const revView = parse([chainTransferredRevocation(ID0, AT2)])

    const res = auditChain([p0, p1], view, revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.valid).toBe(true)
    expect(res.linkStatus).toEqual(['valid'])
    expect(res.errors).toEqual([])
  })

  it('rejects a transfer before the previous receipt floor', () => {
    const hk = generateHybridLogKeys()
    const p0 = parse({ receipt_id: ID0, buyer: { pubkey: b64uEncode(holderPub) }, license: { not_transferable_before: '2026-07-24T00:00:00Z' } })
    const p1 = chainPayload(ID1, newHolderPub)
    const record1 = chainTransferRecord(ID0, ID1, newHolderPub, holderSeed, AT)
    const bundle1 = chainLogBundle([record1], hk)[0]
    const view = parse([{ record: record1, evidence: bundle1 }])
    const revView = parse([chainTransferredRevocation(ID0, AT)])

    const res = auditChain([p0, p1], view, revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain('chain link 1: transferred before not_transferable_before')
  })

  it('flags a missing backed transferred-class revocation', () => {
    const hk = generateHybridLogKeys()
    const p0 = chainPayload(ID0, holderPub)
    const p1 = chainPayload(ID1, newHolderPub)

    const record1 = chainTransferRecord(ID0, ID1, newHolderPub, holderSeed, AT)
    const bundle1 = chainLogBundle([record1], hk)[0]
    const view = parse([{ record: record1, evidence: bundle1 }])

    const res = auditChain([p0, p1], view, [], keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain('chain link 1: previous receipt lacks a backed transferred-class revocation')
  })

  it('flags an unlogged record', () => {
    const p0 = chainPayload(ID0, holderPub)
    const p1 = chainPayload(ID1, newHolderPub)

    const record1 = chainTransferRecord(ID0, ID1, newHolderPub, holderSeed, AT)
    const view = parse([{ record: record1, evidence: null }])
    const revView = parse([chainTransferredRevocation(ID0, AT)])
    const hk = generateHybridLogKeys()

    const res = auditChain([p0, p1], view, revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain('chain link 1: transfer record not logged')
  })

  it('flags an invalid holder authorization', () => {
    const hk = generateHybridLogKeys()
    const p0 = chainPayload(ID0, holderPub)
    const p1 = chainPayload(ID1, newHolderPub)
    const unrelatedHolderSeed = new Uint8Array(32).fill(27)
    const record1 = chainTransferRecord(ID0, ID1, newHolderPub, unrelatedHolderSeed, AT)
    const bundle1 = chainLogBundle([record1], hk)[0]
    const view = parse([{ record: record1, evidence: bundle1 }])
    const revView = parse([chainTransferredRevocation(ID0, AT)])

    const res = auditChain([p0, p1], view, revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain('chain link 1: holder authorization invalid')
  })

  it('reports no transfer record for the link', () => {
    const p0 = chainPayload(ID0, holderPub)
    const p1 = chainPayload(ID1, newHolderPub)
    const hk = generateHybridLogKeys()
    const revView = parse([chainTransferredRevocation(ID0, AT)])

    const res = auditChain([p0, p1], [], revView, keyManifest(), [transferLogKey(hk)], noHorizonPolicy())

    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toEqual(['chain link 1: no transfer record'])
  })

  it('marks every link invalid when the manifest is self-inconsistent', () => {
    const hk = generateHybridLogKeys()
    const p0 = chainPayload(ID0, holderPub)
    const p1 = chainPayload(ID1, newHolderPub)
    const p2 = chainPayload(ID2, secondNewHolderPub)
    const brokenManifest = { ...keyManifest(), manifest_signature: { kid: KID, sig: '!'.repeat(86) } }

    const res = auditChain([p0, p1, p2], [], [], brokenManifest, [transferLogKey(hk)], noHorizonPolicy())

    expect(res.valid).toBe(false)
    expect(res.linkStatus).toEqual(['invalid', 'invalid'])
    expect(res.errors).toEqual(['chain link 1: issuer signature invalid', 'chain link 2: issuer signature invalid'])
  })
})

// --- auditChain: §18.4 admission of the caller's rails -----------------------
//
// auditChain is a SECOND public entry point for the two untrusted rails
// verify() admits, so the same boundary applies. Every case pins a PROPERTY and
// asserts the call RETURNS a ChainAuditResult. Python parity:
// tests/test_transfer.py's own admission block.

describe('auditChain admission boundary', () => {
  function backedLink(): {
    hk: HybridTestKeys
    p0: JsonObject
    p1: JsonObject
    view: JsonValue[]
    revView: JsonValue[]
  } {
    const hk = generateHybridLogKeys()
    const p0 = chainPayload(OLD_ID, holderPub)
    const p1 = chainPayload(NEW_ID, newHolderPub)
    const record = chainTransferRecord(OLD_ID, NEW_ID, newHolderPub, holderSeed)
    const bundle = chainLogBundle([record], hk)[0]!
    return {
      hk, p0, p1,
      view: [parse({ record, evidence: bundle })],
      revView: [chainTransferredRevocation(OLD_ID)],
    }
  }

  const audit = (
    payloads: JsonObject[], view: unknown, revView: unknown, hk: HybridTestKeys,
  ) => auditChain(
    payloads, view as JsonValue[], revView as JsonValue[],
    keyManifest(), [transferLogKey(hk)], noHorizonPolicy(),
  )

  it.each([
    ['null', null],
    ['a mapping', { record: null }],
    ['a string', 'not-an-array'],
    ['a number', 7],
  ])('returns a verdict for a transfer view that is not an array (%s)', (_name, notAnArray) => {
    // §18.4 leaves the declared container shape to the rail: this rail is an
    // array, so anything else carries no claim. The audit degrades and RETURNS
    // -- a public surface must not answer a malformed view with an exception.
    const { p0, p1, revView, hk } = backedLink()

    const res = audit([p0, p1], notAnArray, revView, hk)

    expect(res.valid).toBe(false)
    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain('chain link 1: no transfer record')
  })

  it.each([
    ['null', null],
    ['a mapping', { receipt_id: OLD_ID }],
    ['a string', 'not-an-array'],
  ])('returns a verdict for a revocation view that is not an array (%s)', (_name, notAnArray) => {
    // The same rule on the other rail, failing in the same direction: with no
    // record the predecessor has no backed extinguishment. Silence on either
    // rail can never make a link VALID.
    const { p0, p1, view, hk } = backedLink()

    const res = audit([p0, p1], view, notAnArray, hk)

    expect(res.valid).toBe(false)
    expect(res.linkStatus).toEqual(['invalid'])
    expect(res.errors).toContain(
      'chain link 1: previous receipt lacks a backed transferred-class revocation',
    )
  })

  it('never invokes a caller getter on a claim, and sets that claim aside', () => {
    // A getter is code, not own data. The boundary reconstructs from data
    // property descriptors, so the getter is never invoked -- ZERO reads, not
    // one -- and the claim it defines carries nothing. Bilateral: the same
    // claim supplied as DATA is still honoured, so this refuses code-as-
    // evidence and not the rail.
    const { p0, p1, view, revView, hk } = backedLink()
    let reads = 0
    const plain = view[0] as JsonObject
    const getterClaim = {
      get record() { reads += 1; return plain['record'] },
      get evidence() { reads += 1; return plain['evidence'] },
    }

    const setAside = audit([p0, p1], [getterClaim], revView, hk)
    const honoured = audit([p0, p1], view, revView, hk)

    expect(reads).toBe(0)
    expect(setAside.valid).toBe(false)
    expect(setAside.errors).toContain('chain link 1: no transfer record')
    expect(honoured.valid).toBe(true)
    expect(honoured.linkStatus).toEqual(['valid'])
  })

  it('sets an unrepresentable claim aside alone and keeps its genuine sibling', () => {
    // Bilateral, per claim, with a CONTROL so the test proves what it claims.
    // The decoy names the same link and would therefore be selected first and
    // fail its signature, making the link invalid -- the control run shows
    // exactly that. The only difference in the second run is one value the
    // profile cannot represent, so the link staying valid can only mean the
    // claim was refused by ADMISSION and not skipped for some ordinary reason
    // of shape or selection.
    const { p0, p1, view, revView, hk } = backedLink()
    const decoy = { record: { receipt_id: OLD_ID, new_receipt_id: NEW_ID } }
    const unrepresentable = { ...decoy, annotation: 1.5 }

    const control = audit([p0, p1], [decoy, ...view], revView, hk)
    const res = audit([p0, p1], [unrepresentable, ...view], revView, hk)

    expect(control.valid).toBe(false)
    expect(control.errors).toContain('chain link 1: issuer signature invalid')
    expect(res.valid).toBe(true)
    expect(res.linkStatus).toEqual(['valid'])
  })

  it('returns within a wall-clock bound for a rail claiming an enormous length', () => {
    // The count comes from the array's own length data and the ceiling is
    // judged on it alone, so an enormous claimed length costs no per-element
    // work. Asserted on WALL TIME, because "it returned something" is not the
    // property at risk.
    const { p0, p1, revView, hk } = backedLink()
    const enormous: unknown[] = []
    Object.defineProperty(enormous, 'length', { value: 1e9, writable: true })

    const started = Date.now()
    const res = audit([p0, p1], enormous, revView, hk)
    const elapsed = Date.now() - started

    expect(elapsed).toBeLessThan(2000)
    expect(res.valid).toBe(false)
    expect(res.errors).toContain('chain link 1: no transfer record')
  })
})
