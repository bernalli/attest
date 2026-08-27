import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { b64uEncode } from '../src/b64u.js'
import { canonicalBytes, loadsStrict } from '../src/canon.js'
import type { JsonObject, JsonValue } from '../src/canon.js'
import { verify, isOk } from '../src/verify.js'
import { checkContinuity, chainContinuous } from '../src/manifests.js'
import type { TrustStore } from '../src/manifests.js'
import { encodeEntry, parseCheckpoint, receiptCoreHash } from '../src/tlog.js'
import type { LogKey } from '../src/tlog.js'
import type { AnchorPolicy, PinnedHeader } from '../src/anchor.js'
import { COMPROMISE_WARN } from '../src/messages.js'
import { buildTree, signCheckpoint } from './helpers/tlog-builder.js'
import type { HybridTestKeys } from './helpers/tlog-builder.js'

const enc = new TextEncoder()
const dec = new TextDecoder()

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/2026-01#ed25519-1`
const DECLARER_KID = `${ISSUER}/keys/2026-02#ed25519-2`
const VALID_FROM = '2026-01-01T00:00:00Z'
const DECLARED_AT = '2026-02-01T00:00:00Z'
const RECEIPT_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAV'

const signingSeed = Uint8Array.from({ length: 32 }, () => 41)
const declarerSeed = Uint8Array.from({ length: 32 }, () => 42)
const signingPub = b64uEncode(ed25519.getPublicKey(signingSeed))
const declarerPub = b64uEncode(ed25519.getPublicKey(declarerSeed))

const LOG_ORIGIN = 'compromise-log.attest.example/2026'
const LOG_NAME = 'attest-compromise-log-1'
const H1 = 1_700_000_000
const H2 = 1_700_003_600

function parseObject(value: unknown): JsonObject {
  return loadsStrict(enc.encode(JSON.stringify(value))) as JsonObject
}

function bytesHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function keyEntry(kid: string, pub: string, status: string): Record<string, unknown> {
  return { kid, pub, valid_from: VALID_FROM, valid_to: null, status }
}

function manifestBody(version: number, keys: Record<string, unknown>[]): Record<string, unknown> {
  return { issuer: ISSUER, manifest_version: version, issued_at: version === 1 ? VALID_FROM : DECLARED_AT, keys }
}

function signManifestPlain(body: Record<string, unknown>, signerKid: string, seed: Uint8Array): Record<string, unknown> {
  const parsed = parseObject(body)
  const sig = ed25519.sign(canonicalBytes(parsed), seed)
  return { ...body, manifest_signature: { kid: signerKid, sig: b64uEncode(sig) } }
}

function signManifest(body: Record<string, unknown>, signerKid: string, seed: Uint8Array): JsonObject {
  return parseObject(signManifestPlain(body, signerKid, seed))
}

function manifestV1(): JsonObject {
  return signManifest(
    manifestBody(1, [keyEntry(KID, signingPub, 'active'), keyEntry(DECLARER_KID, declarerPub, 'active')]),
    KID,
    signingSeed,
  )
}

function manifestV2Compromised(): JsonObject {
  return signManifest(
    manifestBody(2, [keyEntry(KID, signingPub, 'compromised'), keyEntry(DECLARER_KID, declarerPub, 'active')]),
    DECLARER_KID,
    declarerSeed,
  )
}

function manifestV2DuplicateDeclaration(): JsonObject {
  return signManifest(
    manifestBody(2, [
      keyEntry(KID, signingPub, 'active'),
      keyEntry(KID, signingPub, 'compromised'),
      keyEntry(DECLARER_KID, declarerPub, 'active'),
    ]),
    DECLARER_KID,
    declarerSeed,
  )
}

function manifestV3Resurrected(): JsonObject {
  return signManifest(
    manifestBody(3, [keyEntry(KID, signingPub, 'active'), keyEntry(DECLARER_KID, declarerPub, 'active')]),
    DECLARER_KID,
    declarerSeed,
  )
}

function manifestV3DuplicateResurrection(): JsonObject {
  return signManifest(
    manifestBody(3, [
      keyEntry(KID, signingPub, 'compromised'),
      keyEntry(KID, signingPub, 'active'),
      keyEntry(DECLARER_KID, declarerPub, 'active'),
    ]),
    DECLARER_KID,
    declarerSeed,
  )
}

function manifestV3OmittingCompromisedKid(): JsonObject {
  return signManifest(
    manifestBody(3, [keyEntry(DECLARER_KID, declarerPub, 'active')]),
    DECLARER_KID,
    declarerSeed,
  )
}

function trustStore(manifest: JsonObject, chain?: JsonObject[]): TrustStore {
  const store: TrustStore = { manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: 'tls' } }
  if (chain !== undefined) store.chains = { [ISSUER]: chain }
  return store
}

function receiptPayload(): JsonObject {
  return parseObject({
    attest_version: '0.1',
    issued_at: '2026-01-15T00:00:00Z',
    receipt_id: RECEIPT_ID,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    work: {
      title: 'Example Work',
      publisher: 'Example Publisher',
      identifiers: { issuer_sku: 'SKU-1' },
      artifact_series: 'series-1',
    },
    license: {
      grant: 'perpetual',
      revocability: 'none',
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://example.com/terms',
      legal_text_sha256: 'a'.repeat(64),
    },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email' },
    survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: true },
  })
}

function envelopeBytes(): Uint8Array {
  const payload = receiptPayload()
  const sig = ed25519.sign(canonicalBytes(payload), signingSeed)
  return enc.encode(JSON.stringify({ payload, signatures: [{ kid: KID, alg: 'Ed25519', sig: b64uEncode(sig) }] }))
}

function generateLogKeys(): HybridTestKeys {
  const edSeed = Uint8Array.from({ length: 32 }, () => 43)
  const edPub = ed25519.getPublicKey(edSeed)
  const { publicKey: mldsaPub, secretKey: mldsaSecret } = ml_dsa65.keygen(Uint8Array.from({ length: 32 }, () => 44))
  return { edSeed, edPub, mldsaPub, mldsaSecret }
}

const LOG_KEYS = generateLogKeys()
const LOG_KEY: LogKey = { origin: LOG_ORIGIN, name: LOG_NAME, ed25519Pub: LOG_KEYS.edPub, mldsaPub: LOG_KEYS.mldsaPub }

function publicEntry(entry: Record<string, unknown>): Record<string, unknown> {
  if (typeof entry['manifest_version'] === 'number') return { ...entry, manifest_version: BigInt(entry['manifest_version']) }
  return { ...entry }
}

function logEvidence(entry: Record<string, unknown>): Record<string, JsonValue> {
  const leaf = encodeEntry(entry)
  const root = buildTree([leaf])
  const checkpoint = signCheckpoint(LOG_ORIGIN, 1, root, LOG_KEYS, LOG_NAME)
  return { entry: publicEntry(entry) as JsonObject, leaf_index: 0n, tree_size: 1n, inclusion_proof: [], checkpoint }
}

function anchorForCheckpoint(checkpointText: string, headerTime: number): {
  anchors: JsonObject
  policy: AnchorPolicy
} {
  const checkpoint = parseCheckpoint(checkpointText)
  const headerHash = bytesHex(sha256(enc.encode(`header-${headerTime}`)))
  const merkleRoot = bytesHex(sha256(sha256(checkpoint.noteBytes)))
  const proof = {
    kind: 'ots',
    ops: [['sha256']],
    header_merkle_root: merkleRoot,
    header_time: BigInt(headerTime),
    header_hash: headerHash,
  }
  const anchors = {
    checkpoint: `${dec.decode(checkpoint.noteBytes)}\n— test-key AA==\n`,
    proofs: [proof as unknown as JsonObject],
  } as JsonObject
  const pinnedHeaders: Record<string, PinnedHeader> = {
    [headerHash]: { headerHash, merkleRoot, time: headerTime },
  }
  return { anchors, policy: { pinnedHeaders, crqcHorizon: null } }
}

function anchoredEvidence(entry: Record<string, unknown>, headerTime: number): {
  evidence: JsonObject
  policy: AnchorPolicy
} {
  const evidence = logEvidence(entry)
  const { anchors, policy } = anchorForCheckpoint(evidence.checkpoint as string, headerTime)
  return { evidence: { ...evidence, anchors }, policy }
}

function mergedPolicy(...policies: AnchorPolicy[]): AnchorPolicy {
  return {
    pinnedHeaders: Object.assign(Object.create(null), ...policies.map((policy) => policy.pinnedHeaders)),
    crqcHorizon: null,
  }
}

function receiptEntry(envelope: Uint8Array): Record<string, unknown> {
  return { type: 'receipt', issuer: ISSUER, core_sha256: receiptCoreHash(loadsStrict(envelope)) }
}

function manifestEntry(manifest: JsonObject): Record<string, unknown> {
  const version = manifest['manifest_version']
  return {
    type: 'key-manifest',
    issuer: ISSUER,
    manifest_version: typeof version === 'bigint' ? Number(version) : version,
    manifest_sha256: bytesHex(sha256(canonicalBytes(manifest))),
  }
}

function compromiseClaim(manifest: JsonObject | Record<string, unknown>, evidence: JsonValue | null): JsonObject {
  return { manifest: manifest as JsonValue, evidence } as JsonObject
}

function noHorizonPolicy(): AnchorPolicy {
  return { pinnedHeaders: {}, crqcHorizon: null }
}

describe('verify(): anchored compromise cutoff (§19)', () => {
  it('rescues a compromised-key receipt anchored before the declaration cutoff', () => {
    const envelope = envelopeBytes()
    const declaration = manifestV2Compromised()
    const receipt = anchoredEvidence(receiptEntry(envelope), H1)
    const cutoff = anchoredEvidence(manifestEntry(declaration), H2)

    const result = verify(envelope, trustStore(declaration), null, null, undefined, {
      transparency: receipt.evidence,
      logKeys: [LOG_KEY],
      anchorPolicy: mergedPolicy(receipt.policy, cutoff.policy),
      compromiseView: [compromiseClaim(declaration, cutoff.evidence)],
    })

    expect(result.signature).toBe('valid')
    expect(isOk(result)).toBe(true)
    expect(result.warnings).toEqual(['anchor_note_only', COMPROMISE_WARN.RESCUE_APPLIED])
    expect(result.errors).toEqual([])
  })

  it('uses an authenticated unanchored declaration as a floor but not as a cutoff', () => {
    const envelope = envelopeBytes()
    const declaration = manifestV2Compromised()
    const trusted = manifestV3Resurrected()
    const receipt = anchoredEvidence(receiptEntry(envelope), H1)

    const result = verify(envelope, trustStore(trusted), null, null, undefined, {
      transparency: receipt.evidence,
      logKeys: [LOG_KEY],
      anchorPolicy: receipt.policy,
      compromiseView: [compromiseClaim(declaration, logEvidence(manifestEntry(declaration)) as JsonObject)],
    })

    expect(result.signature).toBe('valid')
    expect(isOk(result)).toBe(true)
    expect(result.warnings).toEqual(['anchor_note_only', COMPROMISE_WARN.CUTOFF_UNANCHORED])
    expect(result.errors).toEqual([])
  })

  it('reads every duplicate key entry in a compromise declaration before deciding the floor', () => {
    const result = verify(envelopeBytes(), trustStore(manifestV3Resurrected()), null, null, undefined, {
      logKeys: [LOG_KEY],
      anchorPolicy: noHorizonPolicy(),
      compromiseView: [compromiseClaim(manifestV2DuplicateDeclaration(), null)],
    })

    expect(result.signature).toBe('invalid')
    expect(result.warnings).toEqual([COMPROMISE_WARN.RESCUE_REQUIRES_ANCHORED_RECEIPT])
    expect(result.errors).toEqual([`key ${KID} is compromised`])
  })

  it('ignores a declaration with a non-integer manifest_version before applying the floor', () => {
    const badDeclaration = {
      ...signManifestPlain(
        manifestBody(2, [keyEntry(KID, signingPub, 'compromised'), keyEntry(DECLARER_KID, declarerPub, 'active')]),
        DECLARER_KID,
        declarerSeed,
      ),
      manifest_version: 2.5,
    }

    const result = verify(envelopeBytes(), trustStore(manifestV3Resurrected()), null, null, undefined, {
      logKeys: [LOG_KEY],
      anchorPolicy: noHorizonPolicy(),
      compromiseView: [compromiseClaim(badDeclaration, null)],
    })

    expect(result.signature).toBe('valid')
    expect(result.warnings).toEqual([COMPROMISE_WARN.CUTOFF_CLAIM_IGNORED])
    expect(result.errors).toEqual([])
  })
})

describe('key-manifest continuity compromise floor', () => {
  it('rejects uncompromise and omission by reading every current entry for the kid', () => {
    const v1 = manifestV1()
    const v2 = manifestV2Compromised()
    const duplicateResurrection = manifestV3DuplicateResurrection()
    const omitted = manifestV3OmittingCompromisedKid()

    expect(checkContinuity(v1, v2)).toBe(true)
    expect(checkContinuity(v2, duplicateResurrection)).toBe(false)
    expect(checkContinuity(v2, omitted)).toBe(false)
    expect(chainContinuous([v1, v2, duplicateResurrection])).toBe(false)
  })

  it('rejects a duplicate signer kid when any predecessor entry says compromised', () => {
    const v1 = signManifest(
      manifestBody(1, [
        keyEntry(KID, signingPub, 'active'),
        keyEntry(DECLARER_KID, declarerPub, 'active'),
        keyEntry(DECLARER_KID, declarerPub, 'compromised'),
      ]),
      DECLARER_KID,
      declarerSeed,
    )
    const v2 = signManifest(
      manifestBody(2, [
        keyEntry(KID, signingPub, 'active'),
        keyEntry(DECLARER_KID, declarerPub, 'compromised'),
      ]),
      DECLARER_KID,
      declarerSeed,
    )

    expect(checkContinuity(v1, v2)).toBe(false)
  })

  it('makes a held chain compromise binding even when the trusted manifest reactivates the key', () => {
    const v1 = manifestV1()
    const v2 = manifestV2Compromised()
    const v3 = manifestV3Resurrected()

    const result = verify(envelopeBytes(), trustStore(v3, [v1, v2, v3]))

    expect(result.signature).toBe('invalid')
    expect(result.trust).toBe('unverified_rotation')
    expect(result.errors).toEqual([`key ${KID} is compromised`])
  })
})
