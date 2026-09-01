import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { verify, isOk } from '../src/verify.js'
import { canonicalBytes, loadsStrict } from '../src/canon.js'
import type { JsonObject, JsonValue } from '../src/canon.js'
import type { TrustStore } from '../src/manifests.js'
import { authorizationMessage, recordHash } from '../src/transfer.js'
import { encodeEntry, receiptCoreHash } from '../src/tlog.js'
import { b64uEncode } from '../src/b64u.js'
import { parsePolicy as parseWitnessPolicy } from '../src/witness.js'
import { MAX_ENVELOPE_BYTES } from '../src/schema.js'
import { buildTree, inclusionProof, signCheckpoint, type HybridTestKeys } from './helpers/tlog-builder.js'

const enc = (s: string) => new TextEncoder().encode(s)
const emptyStore = { manifests: {}, provenance: {} }

describe('verify unit', () => {
  it('throws TypeError on non-array revocationView', () => {
    expect(() => verify(enc('{}'), emptyStore, {} as any)).toThrow(TypeError)
  })
  it('non-object envelope -> invalid/not_checked/tofu', () => {
    const r = verify(enc('123'), emptyStore)
    expect(r.signature).toBe('invalid')
    expect(r.schema).toBe('not_checked')
    expect(r.trust).toBe('unauthenticated_tofu')
    expect(isOk(r)).toBe(false)
  })
  // v0.1 §11.3's raw-envelope acceptance floor: 2^20 bytes, judged on the
  // undecoded bytes at step 0, reported as `schema: "invalid"`. Python pins it
  // in test_envelope_over_byte_ceiling_rejected; this side pinned nothing, so
  // deleting the check here would have left both suites green — the ceiling is
  // normative, and a normative rule enforced in one core only is a parity claim
  // nothing defends.
  it('raw envelope over the byte ceiling -> schema invalid (v0.1 §11.3)', () => {
    const oversized = enc(`{"payload":{"padding":"${'x'.repeat(MAX_ENVELOPE_BYTES)}"}}`)
    expect(oversized.length).toBeGreaterThan(MAX_ENVELOPE_BYTES)

    const r = verify(oversized, emptyStore)

    expect(r.schema).toBe('invalid')
    expect(r.errors.some((e) => e.includes('envelope exceeds'))).toBe(true)
    expect(isOk(r)).toBe(false)
  })
  it('isOk is the 4-gate rule', () => {
    expect(isOk({ signature: 'valid', schema: 'valid', revocation: 'revoked', binding: 'not_checked', trust: 'verified', warnings: [], errors: [] })).toBe(false)
    expect(isOk({ signature: 'valid', schema: 'valid', revocation: 'unknown', binding: 'not_checked', trust: 'unverified_rotation', warnings: [], errors: [] })).toBe(true)
  })
  it('isOk is false for revocation: "transferred" (v0.2 Stage 3)', () => {
    expect(isOk({ signature: 'valid', schema: 'valid', revocation: 'transferred', binding: 'not_checked', trust: 'verified', warnings: [], errors: [] })).toBe(false)
  })

  it('throws TypeError on a JSON.parse-d (number-typed) trust store', () => {
    // Simulate the JSON.parse mistake: manifest_version is a JS number, not bigint.
    const store = { manifests: { 'ex.com': { issuer: 'ex.com', manifest_version: 3 } }, provenance: {} }
    expect(() => verify(enc('{}'), store as any)).toThrow(TypeError)
    expect(() => verify(enc('{}'), store as any)).toThrow(/loadsStrict|bigint/)
  })
  // The revocation view no longer throws for a JS number, and the property this
  // test protects is stronger than the one it used to pin. A JSON.parse'd record
  // carries values the integer-only profile cannot represent, so the ADMISSION
  // BOUNDARY sets that record aside on its own (§18.4) instead of taking the
  // whole call down for a property of one record. The caller still learns —
  // §12.2's ignored-record warning fires when the inadmissible record claims to
  // be about this receipt — and a genuine sibling revocation still reaches its
  // verdict, which the throwing guard made impossible.
  it('sets a JSON.parse-d (number-typed) revocation record aside and still honours its sibling', () => {
    // Bilateral, and this is the point: the record carrying a JS number is not
    // representable in the integer-only profile, so it is set aside ALONE and
    // still surfaces as §12.2's ignored-record warning because it claims to be
    // about this receipt — while the genuine, signed sibling beside it still
    // revokes. The guard this replaced threw for the bad record and took the
    // good one down with it.
    const bad = { receipt_id: T_OLD_ID, status: 'revoked', revoked_at: T_AT, manifest_version: 2 }
    const body = { receipt_id: T_OLD_ID, status: 'revoked', revoked_at: T_AT }
    const sig = ed25519.sign(canonicalBytes(parse(body)), tIssuerSeed)
    const good = parse({ ...body, signature: { kid: T_KID, sig: b64uEncode(sig) } })

    const result = verify(tEnvelopeBytes('policy'), tTrustStore(), [bad as unknown as JsonValue, good])

    expect(result.revocation).toBe('revoked')
    expect(result.warnings).toContain(`revocation record for '${T_OLD_ID}' failed verification, ignored`)
  })
  it('does not throw the guard for a loadsStrict-parsed (bigint) trust store', () => {
    const store = { manifests: { 'ex.com': { issuer: 'ex.com', manifest_version: 3n } }, provenance: {} }
    expect(() => verify(enc('{}'), store as any)).not.toThrow()
  })
})

// --------------------------------------------------------------------------
// v0.2 Stage 3 (§17): verify()'s transferView option, transferred-class
// backing, not_transferable_before, and the ok extension. Mirrors
// tests/test_verify_transfer.py (Python reference). Fixtures build a real
// transfer record (hand-signed with noble, transfer.ts is verify-only) and a
// real transparency log (mirrors transfer.test.ts's own fixtures and
// test/helpers/tlog-builder.ts, the same idiom sibling-hybrid.test.ts
// established for hybrid-signed side-documents).
const parse = (v: unknown): JsonObject => loadsStrict(enc(JSON.stringify(v))) as JsonObject

const T_ISSUER = 'store.example.com'
const T_KID = `${T_ISSUER}/keys/test#ed25519-1`

// TEST ONLY — fixed seeds, never use in production.
const tIssuerSeed = Uint8Array.from({ length: 32 }, () => 31)
const tHolderSeed = Uint8Array.from({ length: 32 }, () => 32)
const tOtherHolderSeed = Uint8Array.from({ length: 32 }, () => 33)
const tNewHolderSeed = Uint8Array.from({ length: 32 }, () => 34)

const tIssuerPub = ed25519.getPublicKey(tIssuerSeed)
const tHolderPub = ed25519.getPublicKey(tHolderSeed)
const tOtherHolderPub = ed25519.getPublicKey(tOtherHolderSeed)
const tNewHolderPub = ed25519.getPublicKey(tNewHolderSeed)

const T_OLD_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAV'
const T_NEW_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAW'
const T_LATE_NEW_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAX'
const T_AT = '2026-07-23T00:00:00Z'
const T_NEW_HOLDER_PUBKEY = b64uEncode(tNewHolderPub)

const T_LOG_ORIGIN = 'transfer-log.attest.example/2026'
const T_LOG_NAME = 'attest-transfer-log-1'

function tKeyManifest(): JsonObject {
  const entry = { kid: T_KID, pub: b64uEncode(tIssuerPub), valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }
  const body = { issuer: T_ISSUER, manifest_version: 1, issued_at: '2026-01-01T00:00:00Z', keys: [entry] }
  const bodyParsed = parse(body)
  const sig = ed25519.sign(canonicalBytes(bodyParsed), tIssuerSeed)
  return parse({ ...body, manifest_signature: { kid: T_KID, sig: b64uEncode(sig) } })
}

function tTrustStore(): TrustStore {
  return { manifests: { [T_ISSUER]: tKeyManifest() }, provenance: { [T_ISSUER]: 'tls' } }
}

function tPayload(revocability: string, notTransferableBefore?: string): Record<string, unknown> {
  const license: Record<string, unknown> = {
    grant: 'perpetual', revocability, transferable: false, drm: 'drm-free',
    terms_uri: 'https://x/t', legal_text_sha256: 'a'.repeat(64),
  }
  if (notTransferableBefore !== undefined) license['not_transferable_before'] = notTransferableBefore
  return {
    attest_version: '0.1', issued_at: '2026-01-02T00:00:00Z', receipt_id: T_OLD_ID, supersedes: null,
    issuer: { id: T_ISSUER, display_name: 'Example Store' },
    work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' }, artifact_series: 'series-x' },
    license,
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: b64uEncode(tHolderPub) },
    survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: true },
  }
}

function tEnvelopeBytes(revocability: string, notTransferableBefore?: string): Uint8Array {
  const payload = parse(tPayload(revocability, notTransferableBefore))
  const sig = ed25519.sign(canonicalBytes(payload), tIssuerSeed)
  const envelope = { payload, signatures: [{ kid: T_KID, alg: 'Ed25519', sig: b64uEncode(sig) }] }
  return enc(JSON.stringify(envelope))
}

function tTransferredRevocationRecord(receiptId: string = T_OLD_ID, at: string = T_AT): JsonObject {
  const body = { receipt_id: receiptId, status: 'transferred', revoked_at: at }
  const sig = ed25519.sign(canonicalBytes(parse(body)), tIssuerSeed)
  return parse({ ...body, signature: { kid: T_KID, sig: b64uEncode(sig) } })
}

function tTransferRecord(newReceiptId: string = T_NEW_ID, newHolderPubkey: string = T_NEW_HOLDER_PUBKEY, transferredAt: string = T_AT, hSeed: Uint8Array = tHolderSeed): JsonObject {
  const authSig = ed25519.sign(authorizationMessage(T_OLD_ID, newHolderPubkey, transferredAt), hSeed)
  const body = {
    receipt_id: T_OLD_ID, new_receipt_id: newReceiptId, new_holder_pubkey: newHolderPubkey,
    transferred_at: transferredAt, holder_authorization: { sig: b64uEncode(authSig) },
  }
  const bodyParsed = parse(body)
  const sig = ed25519.sign(canonicalBytes(bodyParsed), tIssuerSeed)
  return parse({ ...body, signature: { kid: T_KID, sig: b64uEncode(sig) } })
}

function resignTransferRecord(record: JsonObject): JsonObject {
  const body: Record<string, unknown> = {}
  for (const k of Object.keys(record)) if (k !== 'signature') body[k] = record[k]
  const sig = ed25519.sign(canonicalBytes(parse(body)), tIssuerSeed)
  return { ...record, signature: { kid: T_KID, sig: b64uEncode(sig) } }
}

function noHorizonPolicy() {
  return { pinnedHeaders: {}, crqcHorizon: null }
}

function generateHybridLogKeys(): HybridTestKeys {
  const edSeed = ed25519.utils.randomSecretKey()
  const edPub = ed25519.getPublicKey(edSeed)
  const { publicKey: mldsaPub, secretKey: mldsaSecret } = ml_dsa65.keygen()
  return { edSeed, edPub, mldsaPub, mldsaSecret }
}

function tLogKey(hk: HybridTestKeys) {
  return { origin: T_LOG_ORIGIN, name: T_LOG_NAME, ed25519Pub: hk.edPub, mldsaPub: hk.mldsaPub }
}

/** One genuine transfer-record log containing every record in
 * `recordsInOrder`, in that log order (index 0 = earliest/first-logged).
 * Mirrors test_transfer.py's identically-named helper. */
function tLogBundle(recordsInOrder: JsonObject[], hk: HybridTestKeys): Record<string, unknown>[] {
  const entries = recordsInOrder.map((r) => ({ type: 'transfer-record', issuer: T_ISSUER, record_sha256: recordHash(r) }))
  const leaves = entries.map((e) => encodeEntry(e))
  const root = buildTree(leaves)
  const treeSize = leaves.length
  const checkpointText = signCheckpoint(T_LOG_ORIGIN, treeSize, root, hk, T_LOG_NAME)
  return entries.map((entry, i) => ({
    entry, leaf_index: i, tree_size: treeSize,
    inclusion_proof: inclusionProof(leaves, i).map((p) => Buffer.from(p).toString('hex')),
    checkpoint: checkpointText,
  }))
}

interface VerifyWithOpts {
  revocationView?: JsonValue[] | null
  transferView?: JsonValue[] | null
  logKeys?: ReturnType<typeof tLogKey>[] | null
  anchorPolicy?: ReturnType<typeof noHorizonPolicy> | null
  revocability?: string
  notTransferableBefore?: string
  supplyTransferView?: boolean
}

function verifyWith(opts: VerifyWithOpts = {}) {
  const {
    revocationView = null, transferView = null, logKeys = null, anchorPolicy = null,
    revocability = 'none', notTransferableBefore, supplyTransferView = true,
  } = opts
  const envelopeBytes = tEnvelopeBytes(revocability, notTransferableBefore)
  const options: Record<string, unknown> = { logKeys, anchorPolicy }
  if (supplyTransferView) options['transferView'] = transferView
  return verify(envelopeBytes, tTrustStore(), revocationView, null, undefined, options as any)
}

describe('verify(): Stage 3 transferred-class backing (§17.3)', () => {
  it('reports transferred (not ok) with full backing', () => {
    const hk = generateHybridLogKeys()
    const record = tTransferRecord()
    const bundle = tLogBundle([record], hk)[0]
    const validClaim = parse({ record, evidence: bundle })

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [validClaim],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    })

    expect(result.revocation).toBe('transferred')
    expect(isOk(result)).toBe(false)
  })

  it('honors the consent gate even for the irrevocable "none" class', () => {
    const hk = generateHybridLogKeys()
    const record = tTransferRecord()
    const bundle = tLogBundle([record], hk)[0]
    const validClaim = parse({ record, evidence: bundle })

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [validClaim],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'none',
    })

    expect(result.revocation).toBe('transferred')
    expect(isOk(result)).toBe(false)
  })

  it('ignores an unbacked transfer without a transferView at all', () => {
    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: null,
      revocability: 'policy',
    })

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transferred_revocation_unbacked')
    expect(isOk(result)).toBe(true)
  })

  it.each([
    ['empty', [] as JsonValue[]],
    ['only-mismatched', [{ record: { receipt_id: T_NEW_ID }, evidence: null }] as unknown as JsonValue[]],
    ['oversized', [{ padding: 'x'.repeat(10_000_000) }] as unknown as JsonValue[]],
    ['unserializable', (() => { const cyclic: unknown[] = []; cyclic.push(cyclic); return cyclic })() as unknown as JsonValue[]],
  ])('warns unbacked when the resolver never engages (%s)', (_name, transferView) => {
    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView,
      revocability: 'policy',
    })

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transferred_revocation_unbacked')
    expect(isOk(result)).toBe(true)
  })

  // The property here is that the caller's live claim is not read a second time
  // after the boundary. It used to be pinned by letting the getter run ONCE and
  // capturing what it returned; the admission boundary makes it stronger, and
  // this test now pins the stronger form: a member defined as a GETTER is not
  // own data at all (§18.4 reconstructs from data property descriptors), so the
  // getter is never invoked — zero reads, not one — and the claim it defines is
  // set aside on its own. Running a caller's code inside the boundary is what
  // the boundary exists to avoid; "read it exactly once" still runs it.
  //
  // The claim is set aside rather than honoured, so the receipt reads as never
  // transferred: RESTRICTIVE, and the same evidence-withholding residue that is
  // already declared (§20.6 item 6) — whoever carries the evidence can always
  // omit it, so supplying it as code buys no power that omitting it did not.
  it('never invokes a caller getter on the transfer view, and sets that claim aside', () => {
    const hk = generateHybridLogKeys()
    const record = tTransferRecord()
    const bundle = tLogBundle([record], hk)[0]
    const plainClaim = parse({ record, evidence: bundle })
    let reads = 0
    const options = {
      revocationView: parse([tTransferredRevocationRecord()]),
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    }

    const honoured = verifyWith({ ...options, transferView: [plainClaim] })
    const statefulClaim = {
      get record() { reads += 1; return plainClaim['record'] },
      get evidence() { reads += 1; return plainClaim['evidence'] },
    }
    const actual = verifyWith({ ...options, transferView: [statefulClaim] as unknown as JsonValue[] })

    expect(reads).toBe(0)
    expect(actual.revocation).toBe('invalid_revocation_ignored')
    expect(actual.warnings).toContain('transferred_revocation_unbacked')
    expect(isOk(actual)).toBe(true)
    // Bilateral: the same claim supplied as DATA is still honoured, so this is
    // a refusal of code-as-evidence and not of the rail.
    expect(honoured.revocation).toBe('transferred')
  })

  it('treats a forged holder authorization as unbacked', () => {
    const hk = generateHybridLogKeys()
    const record = tTransferRecord()
    // Forge the holder leg with a DIFFERENT keypair, then re-sign the whole
    // record so the issuer signature itself still verifies structurally.
    const forgedSig = ed25519.sign(authorizationMessage(T_OLD_ID, T_NEW_HOLDER_PUBKEY, T_AT), tOtherHolderSeed)
    const forged = resignTransferRecord({ ...record, holder_authorization: { sig: b64uEncode(forgedSig) } })
    const bundle = tLogBundle([forged], hk)[0]
    const forgedClaim = parse({ record: forged, evidence: bundle })

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [forgedClaim],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    })

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transferred_revocation_unbacked')
    expect(isOk(result)).toBe(true)
  })

  it('ignores an authenticated but unlogged transfer record', () => {
    const record = tTransferRecord()
    const unloggedClaim = parse({ record, evidence: null })
    const hk = generateHybridLogKeys()

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [unloggedClaim],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    })

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transfer_record_unlogged')
    expect(isOk(result)).toBe(true)
  })

  it('cannot honor a transfer when the verifier is not Stage-2 capable', () => {
    const hk = generateHybridLogKeys()
    const record = tTransferRecord()
    const bundle = tLogBundle([record], hk)[0]
    const claim = parse({ record, evidence: bundle })

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [claim],
      logKeys: null,
      anchorPolicy: null,
      revocability: 'policy',
    })

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transfer_record_unlogged')
    expect(isOk(result)).toBe(true)
  })

  it('resolves a double assignment to the earliest-logged leaf index', () => {
    const hk = generateHybridLogKeys()
    const earlyRecord = tTransferRecord(T_NEW_ID)
    const lateRecord = tTransferRecord(T_LATE_NEW_ID)
    // Log order: earlyRecord first (leaf_index 0), lateRecord second (1).
    const [earlyBundle, lateBundle] = tLogBundle([earlyRecord, lateRecord], hk)
    const earlyClaim = parse({ record: earlyRecord, evidence: earlyBundle })
    const lateClaim = parse({ record: lateRecord, evidence: lateBundle })

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [lateClaim, earlyClaim], // list order deliberately reversed
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    })

    expect(result.revocation).toBe('transferred')
    expect(result.warnings).toContain('transfer_double_assignment_conflict')
  })

  it('treats duplicate valid transfer claims as one survivor', () => {
    const hk = generateHybridLogKeys()
    const record = tTransferRecord()
    const bundle = tLogBundle([record], hk)[0]
    const claim = parse({ record, evidence: bundle })

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [claim, claim],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    })

    expect(result.revocation).toBe('transferred')
    expect(result.warnings).not.toContain('transfer_double_assignment_conflict')
  })

  it('keeps distinct valid transfer claims as a double assignment', () => {
    const hk = generateHybridLogKeys()
    const earlyRecord = tTransferRecord(T_NEW_ID)
    const lateRecord = tTransferRecord(T_LATE_NEW_ID)
    const [earlyBundle, lateBundle] = tLogBundle([earlyRecord, lateRecord], hk)

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [parse({ record: earlyRecord, evidence: earlyBundle }), parse({ record: lateRecord, evidence: lateBundle })],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    })

    expect(result.warnings).toContain('transfer_double_assignment_conflict')
  })

  it('ignores a transfer_at earlier than not_transferable_before', () => {
    const hk = generateHybridLogKeys()
    const record = tTransferRecord(T_NEW_ID, T_NEW_HOLDER_PUBKEY, T_AT)
    const bundle = tLogBundle([record], hk)[0]
    const claim = parse({ record, evidence: bundle })

    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      transferView: [claim],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
      notTransferableBefore: '2026-08-01T00:00:00Z',
    })

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transfer_not_yet_transferable')
    expect(result.warnings).not.toContain('transferred_revocation_unbacked')
    expect(isOk(result)).toBe(true)
  })

  it.each(['2026-02-30T00:00:00Z', '2026-13-01T00:00:00Z', '2026-04-31T00:00:00Z'])(
    'does not honor a transfer with an impossible not_transferable_before (%s)',
    (notTransferableBefore) => {
      const hk = generateHybridLogKeys()
      const record = tTransferRecord()
      const bundle = tLogBundle([record], hk)[0]
      const claim = parse({ record, evidence: bundle })

      const result = verifyWith({
        revocationView: parse([tTransferredRevocationRecord()]),
        transferView: [claim],
        logKeys: [tLogKey(hk)],
        anchorPolicy: noHorizonPolicy(),
        revocability: 'policy',
        notTransferableBefore,
      })

      expect(result.revocation).toBe('invalid_revocation_ignored')
      expect(result.warnings).toContain('transfer_not_yet_transferable')
      expect(result.warnings).not.toContain('transferred_revocation_unbacked')
      expect(isOk(result)).toBe(true)
    },
  )

  it('leaves a plain "revoked" record unaffected by an also-present transferView', () => {
    const hk = generateHybridLogKeys()
    const revokedBody = { receipt_id: T_OLD_ID, status: 'revoked', revoked_at: T_AT }
    const revokedSig = ed25519.sign(canonicalBytes(parse(revokedBody)), tIssuerSeed)
    const revokedRecord = parse({ ...revokedBody, signature: { kid: T_KID, sig: b64uEncode(revokedSig) } })
    const unrelatedTransferRecord = tTransferRecord()
    const bundle = tLogBundle([unrelatedTransferRecord], hk)[0]
    const claim = parse({ record: unrelatedTransferRecord, evidence: bundle })

    const result = verifyWith({
      revocationView: [revokedRecord],
      transferView: [claim],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      revocability: 'policy',
    })

    expect(result.revocation).toBe('revoked')
    expect(isOk(result)).toBe(false)
  })

  it('sees zero behavior change when transferView is never supplied at all', () => {
    const result = verifyWith({
      revocationView: parse([tTransferredRevocationRecord()]),
      revocability: 'policy',
      supplyTransferView: false,
    })

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transferred_revocation_unbacked')
    expect(isOk(result)).toBe(true)
  })

  it('throws TypeError on a non-list transferView (caller-contract enforcement)', () => {
    const envelopeBytes = tEnvelopeBytes('none')
    expect(() =>
      verify(envelopeBytes, tTrustStore(), null, null, undefined, { transferView: { record: {}, evidence: null } as any }),
    ).toThrow(TypeError)
  })
})

// --- P1.1b: the witness policy reaches the transparency layer through verify() --
// Mirrors tests/test_verify.py's wiring tests. The POSITIVE end-to-end path
// (a pinned cosignature reaching `witnessed` through the public verifier) is
// pinned by conformance group 39, which is language-neutral; what belongs here
// is the trusted-rail discipline: a malformed policy must be loud, and an
// omitted one must change nothing.
describe('verify(): witness policy on the trusted rail (§11.4)', () => {
  const witnessPolicyDoc = {
    schema: 'attest-witness-policy-v1',
    epochs: [
      {
        epoch_id: 'bootstrap-1',
        not_before: '2020-01-01T00:00:00Z',
        not_after: null,
        log_origins: ['log.example'],
        threshold: { n: 1, m: 1 },
        witnesses: [
          {
            operator_id: 'witness.example',
            control_group: 'witness.example',
            name: 'witness.example/w1',
            ed25519_pub_b64u: b64uEncode(ed25519.getPublicKey(new Uint8Array(32).fill(21))),
            mldsa_65_pub_b64u: null,
            roles: ['corroboration'],
            not_before: '2020-01-01T00:00:00Z',
            not_after: null,
            affiliated_domains: ['witness.example'],
          },
        ],
      },
    ],
  }

  it('throws on a malformed witness policy, like a malformed logKeys', () => {
    const hk = generateHybridLogKeys()
    expect(() =>
      verify(tEnvelopeBytes('none'), tTrustStore(), null, null, undefined, {
        transparency: tLogBundle([tTransferRecord()], hk)[0],
        logKeys: [tLogKey(hk)],
        anchorPolicy: noHorizonPolicy(),
        witnessPolicy: { schema: 'wrong', epochs: [] },
      } as any),
    ).toThrow()
  })

  it('accepts a well-formed witness policy without changing an uncorroborated result', () => {
    const hk = generateHybridLogKeys()
    const withPolicy = verify(tEnvelopeBytes('none'), tTrustStore(), null, null, undefined, {
      transparency: tLogBundle([tTransferRecord()], hk)[0],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
      witnessPolicy: witnessPolicyDoc,
    } as any)
    const withoutPolicy = verify(tEnvelopeBytes('none'), tTrustStore(), null, null, undefined, {
      transparency: tLogBundle([tTransferRecord()], hk)[0],
      logKeys: [tLogKey(hk)],
      anchorPolicy: noHorizonPolicy(),
    } as any)
    expect(withPolicy.corroboration).toBe(withoutPolicy.corroboration)
    expect(withPolicy.warnings).not.toContain('witness_independence_not_established')
  })

  // Regression, found by conformance group 39 and not by any test above:
  // comparing `withPolicy` to `withoutPolicy` field by field passes happily
  // while BOTH collapse, so the claim state has to be pinned absolutely.
  //
  // `verify()` validates the policy eagerly and then passes the PARSED result
  // to `evaluateTransparency`, which validates it again. `WitnessPolicy` is an
  // interface — erased at runtime — so that second pass used to reject the
  // parser's own output for a missing `schema`, and the throw landed outside
  // the untrusted-evidence guard: the entire transparency claim degraded to
  // `transparency_claim_unresolvable`, on byte-identical input the Python
  // core evaluated normally. Both accepted shapes are pinned here, the
  // document AND the parsed policy `loadWitnessPolicy()` hands back, because
  // the exported loader makes the second one a supported caller input.
  it('does not degrade the transparency claim, for either accepted policy shape', () => {
    const hk = generateHybridLogKeys()
    // A bundle whose claim actually RESOLVES: the receipt itself is the
    // logged entry. The sibling tests above log a transfer record instead, so
    // their claim is unresolvable whatever the policy says — which is exactly
    // why a field-by-field comparison between `withPolicy` and `withoutPolicy`
    // could not see this defect. The baseline here reaches `logged`, so a
    // policy that collapses the claim is visible as a difference.
    const envelopeBytes = tEnvelopeBytes('none')
    const entry = {
      type: 'receipt',
      issuer: T_ISSUER,
      core_sha256: receiptCoreHash(loadsStrict(envelopeBytes) as JsonObject),
    }
    const leaves = [encodeEntry(entry)]
    const root = buildTree(leaves)
    // Through `parse`, not a plain object literal: verify() re-serializes the
    // evidence with the canonical serializer, which accepts only `bigint` for
    // JSON integers — a bundle carrying plain `number` leaf_index/tree_size
    // throws there and lands in the same catch-all, which would make this
    // fixture unresolvable for a reason that has nothing to do with witnesses.
    const bundle = parse({
      entry,
      leaf_index: 0,
      tree_size: 1,
      inclusion_proof: inclusionProof(leaves, 0).map((p) => Buffer.from(p).toString('hex')),
      checkpoint: signCheckpoint(T_LOG_ORIGIN, 1, root, hk, T_LOG_NAME),
    })
    const call = (witnessPolicy?: unknown) =>
      verify(envelopeBytes, tTrustStore(), null, null, undefined, {
        transparency: bundle,
        logKeys: [tLogKey(hk)],
        anchorPolicy: noHorizonPolicy(),
        ...(witnessPolicy === undefined ? {} : { witnessPolicy }),
      } as any)

    const baseline = call()
    expect(baseline.transparency).toBe('logged')
    expect(baseline.warnings).not.toContain('transparency_claim_unresolvable')
    for (const shape of [witnessPolicyDoc, parseWitnessPolicy(witnessPolicyDoc)]) {
      const result = call(shape)
      expect(result.transparency).toBe(baseline.transparency)
      expect(result.corroboration).toBe(baseline.corroboration)
      expect([...result.warnings]).toEqual([...baseline.warnings])
    }
  })
})

// --------------------------------------------------------------------------
// V-L.8 (design vector "publisher authority"): work.publisher_id differing
// from issuer.id is an unattested rights-holder claim under v0.1 alone.
// Mirrors tests/test_verify.py's Python-side trio (Python reference).
// --------------------------------------------------------------------------
describe('verify(): V-L.8 publisher_claim_unattested (design vector "publisher authority")', () => {
  function pPayload(publisherId?: unknown): Record<string, unknown> {
    const work: Record<string, unknown> = { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' }, artifact_series: 'series-x' }
    if (publisherId !== undefined) work['publisher_id'] = publisherId
    return {
      attest_version: '0.1', issued_at: '2026-01-02T00:00:00Z', receipt_id: T_OLD_ID, supersedes: null,
      issuer: { id: T_ISSUER, display_name: 'Example Store' },
      work,
      license: {
        grant: 'perpetual', revocability: 'none', transferable: false, drm: 'drm-free',
        terms_uri: 'https://x/t', legal_text_sha256: 'a'.repeat(64),
      },
      buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: b64uEncode(tHolderPub) },
      survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: true },
    }
  }

  function pEnvelopeBytesFromPayload(body: Record<string, unknown>): Uint8Array {
    const payload = parse(body)
    const sig = ed25519.sign(canonicalBytes(payload), tIssuerSeed)
    const envelope = { payload, signatures: [{ kid: T_KID, alg: 'Ed25519', sig: b64uEncode(sig) }] }
    // `parse` round-trips numbers through loadsStrict, which returns them as
    // BigInt (canon.ts's parseNumber) -- JSON.stringify can't serialize BigInt
    // natively, so put it back on the wire as a JSON number (same idiom as
    // evaluate-grant.test.ts:663).
    return enc(JSON.stringify(envelope, (_k, v) => (typeof v === 'bigint' ? Number(v) : v)))
  }

  function pEnvelopeBytes(publisherId?: unknown): Uint8Array {
    return pEnvelopeBytesFromPayload(pPayload(publisherId))
  }

  it('warns when work.publisher_id differs from issuer.id', () => {
    const result = verify(pEnvelopeBytes('pub.example'), tTrustStore())
    expect(isOk(result)).toBe(true)
    expect(result.warnings).toContain('publisher_claim_unattested')
  })

  it('is silent when work.publisher_id equals issuer.id', () => {
    const result = verify(pEnvelopeBytes(T_ISSUER), tTrustStore())
    expect(isOk(result)).toBe(true)
    expect(result.warnings).not.toContain('publisher_claim_unattested')
  })

  it('is silent when work.publisher_id is absent', () => {
    const result = verify(pEnvelopeBytes(), tTrustStore())
    expect(isOk(result)).toBe(true)
    expect(result.warnings).not.toContain('publisher_claim_unattested')
  })

  it.each([
    ['publisher_id object', pPayload({})],
    ['publisher_id array', pPayload([])],
    ['publisher_id null', pPayload(null)],
    ['publisher_id non-string', pPayload(7)],
    ['work array', { ...pPayload(), work: [] }],
    ['work null', { ...pPayload(), work: null }],
    ['work string', { ...pPayload(), work: 'not-an-object' }],
  ])('does not throw or warn on hostile %s', (_label, body) => {
    const result = verify(pEnvelopeBytesFromPayload(body), tTrustStore())
    expect(result.signature).toBe('valid')
    expect(result.schema).toBe('invalid')
    expect(result.warnings).not.toContain('publisher_claim_unattested')
  })

  it('warns for an empty string publisher_id because it is still a string claim', () => {
    const result = verify(pEnvelopeBytes(''), tTrustStore())
    expect(result.signature).toBe('valid')
    expect(result.schema).toBe('invalid')
    expect(result.warnings).toContain('publisher_claim_unattested')
  })
})
