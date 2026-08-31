import { describe, expect, it } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import {
  authorizationMessage,
  canonicalBytes,
  encodeEntry,
  grantHash,
  isOk,
  loadsStrict,
  receiptCoreHash,
  transferRecordHash,
  verify,
} from '../src/index.js'
import type { AnchorPolicy, JsonObject, JsonValue, LogKey, TrustStore } from '../src/index.js'
import {
  buildDeclaration,
  buildGrant,
  buildKeyManifest,
  hybridSigner,
  keyEntry,
  parse,
  signBlock,
  type TestSigner,
} from './helpers/grant-builder.js'
import { buildTree, inclusionProof, signCheckpoint, type HybridTestKeys } from './helpers/tlog-builder.js'

const enc = new TextEncoder()
const dec = new TextDecoder()

const ISSUER = 'store.example.com'
const PUBLISHER = 'pub.example'
const SUCCESSOR = 'heritage.example'
const OTHER = 'marketplace.example'

const ISSUER_KID = `${ISSUER}/keys/2026-01#ed25519-1`
const PUB_KID = `${PUBLISHER}/keys/grants#1`
const SUCCESSOR_KID = `${SUCCESSOR}/keys/grants#1`
const OTHER_KID = `${OTHER}/keys/grants#1`

const VALID_FROM = '2026-01-01T00:00:00Z'
const MANIFEST_ISSUED_AT = '2026-01-01T00:00:00Z'
const GRANT_ISSUED_AT = '2026-02-01T00:00:00Z'
const RECEIPT_ISSUED_AT = '2026-07-02T14:30:00Z'
const DECLARED_AT = '2031-03-01T00:00:00Z'
const REVOKED_AT = '2026-07-03T00:00:00Z'
const TRANSFERRED_AT = '2026-07-23T00:00:00Z'

const RECEIPT_ID = '01J1V5B4M9Z8QWERTY12345678'
const OTHER_RECEIPT_ID = '01J1V5B4M9Z8QWERTY12345679'
const NEW_RECEIPT_ID = '01J1V5B4M9Z8QWERTY1234567A'

const RECEIPT_ART = bytesToHex(sha256(enc.encode('blind-rail-artifact-v1')))
const OTHER_ART = bytesToHex(sha256(enc.encode('blind-rail-artifact-v2')))
const LEGAL_TEXT_SHA256 = bytesToHex(sha256(enc.encode('blind-rail-legal-text-v1')))

const ISSUER_KEYS = hybridSigner(81)
const PUB_KEYS = hybridSigner(82)
const SUCCESSOR_KEYS = hybridSigner(83)
const OTHER_KEYS = hybridSigner(84)
const HOLDER_SEED = new Uint8Array(32).fill(85)
const HOLDER_PUB = ed25519.getPublicKey(HOLDER_SEED)
const NEW_HOLDER_SEED = new Uint8Array(32).fill(86)
const NEW_HOLDER_PUB = ed25519.getPublicKey(NEW_HOLDER_SEED)

const LOG_ORIGIN = 'transfer-log.attest.example/2026'
const LOG_NAME = 'attest-transfer-log-1'
const MAX_SAFE_JCS_INTEGER_PLUS_ONE = 2n ** 53n

function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

function manifestOf(issuer: string, kid: string, signer: TestSigner, version = 1): JsonObject {
  return buildKeyManifest(issuer, version, MANIFEST_ISSUED_AT, [keyEntry(kid, signer, VALID_FROM)], signer, kid)
}

const ISSUER_MANIFEST = manifestOf(ISSUER, ISSUER_KID, ISSUER_KEYS)
const PUB_MANIFEST = manifestOf(PUBLISHER, PUB_KID, PUB_KEYS)
const SUCCESSOR_MANIFEST = manifestOf(SUCCESSOR, SUCCESSOR_KID, SUCCESSOR_KEYS)
const OTHER_MANIFEST = manifestOf(OTHER, OTHER_KID, OTHER_KEYS)

function scope(artifactSeries: string | null = null, artifacts: string[] = [RECEIPT_ART]): Record<string, unknown> {
  return { artifact_series: artifactSeries, artifacts: [...artifacts].sort() }
}

function activation(
  modes: string[] = ['publisher-declaration'],
  fixedDate: string | null = null,
  successorIds: string[] = [SUCCESSOR],
): Record<string, unknown> {
  return { modes: [...modes].sort(), fixed_date: fixedDate, successor_ids: [...successorIds].sort() }
}

function makeGrant(
  signer: TestSigner = PUB_KEYS,
  kid: string = PUB_KID,
  overrides: Record<string, unknown> = {},
): JsonObject {
  return buildGrant(
    {
      grant_version: 1,
      publisher: PUBLISHER,
      scope: scope(),
      permissions: ['deliver-to-holder'],
      activation: activation(),
      unprotected_build: true,
      legal_text_uri: 'https://pub.example/sunset-grant-v1',
      legal_text_sha256: LEGAL_TEXT_SHA256,
      jurisdiction: 'IT',
      issued_at: GRANT_ISSUED_AT,
      ...overrides,
    },
    signer,
    kid,
  )
}

function makeDeclaration(
  signer: TestSigner = PUB_KEYS,
  kid: string = PUB_KID,
  declarationScope: Record<string, unknown> = scope(),
  publisher = PUBLISHER,
): JsonObject {
  return buildDeclaration(publisher, declarationScope, DECLARED_AT, signer, kid)
}

function payloadForGrant(document: JsonObject, revocability = 'none'): JsonObject {
  return parse({
    attest_version: '0.2',
    receipt_id: RECEIPT_ID,
    issued_at: RECEIPT_ISSUED_AT,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: {
      commitment: b64uEncode(new Uint8Array(32)),
      identifier_type: 'issuer-account',
      pubkey: b64uEncode(HOLDER_PUB),
    },
    work: {
      title: 'Example Game',
      publisher: 'Example Publisher',
      identifiers: { issuer_sku: 'EXG-001' },
      publisher_id: PUBLISHER,
      artifact_series: 'store.example.com/works/EXG-001',
      artifacts: [
        {
          role: 'installer',
          platform: 'windows-x86_64',
          filename: 'example-game.exe',
          size_bytes: 734003200,
          sha256: RECEIPT_ART,
        },
      ],
    },
    license: {
      grant: 'perpetual',
      revocability,
      revocation_window_days: 30,
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://store.example.com/license',
      legal_text_sha256: 'a'.repeat(64),
      preservation_pledge: {
        pledge: 'sunset-grant-v1',
        grant_uri: 'https://pub.example/sunset-grant-v1.json',
        grant_sha256: grantHash(document),
      },
    },
    survivability: {
      redownload_right: true,
      end_of_life: 'sunset-grant',
      eol_commitment_uri: null,
      eol_commitment_sha256: null,
    },
  })
}

function payloadForReceipt(revocability = 'policy'): JsonObject {
  return parse({
    attest_version: '0.2',
    receipt_id: RECEIPT_ID,
    issued_at: RECEIPT_ISSUED_AT,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: {
      commitment: b64uEncode(new Uint8Array(32)),
      identifier_type: 'issuer-account',
      pubkey: b64uEncode(HOLDER_PUB),
    },
    work: {
      title: 'Example Game',
      publisher: 'Example Publisher',
      identifiers: { issuer_sku: 'EXG-001' },
      artifact_series: 'store.example.com/works/EXG-001',
    },
    license: {
      grant: 'perpetual',
      revocability,
      revocation_window_days: 30,
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://store.example.com/license',
      legal_text_sha256: 'a'.repeat(64),
    },
    survivability: {
      redownload_right: true,
      end_of_life: 'none',
      eol_commitment_uri: null,
      eol_commitment_sha256: null,
    },
  })
}

function envelopeBytes(payload: JsonObject): Uint8Array {
  const bytes = canonicalBytes(payload)
  const wirePayload = JSON.parse(dec.decode(bytes))
  return enc.encode(JSON.stringify({
    payload: wirePayload,
    signatures: [
      { kid: ISSUER_KID, alg: 'Ed25519', sig: b64uEncode(ed25519.sign(bytes, ISSUER_KEYS.edSeed)) },
      { kid: ISSUER_KID, alg: 'ML-DSA-65', sig: b64uEncode(ml_dsa65.sign(bytes, ISSUER_KEYS.mldsaSecret!)) },
    ],
  }))
}

function trustStore(extraManifests: Record<string, JsonObject> = {}): TrustStore {
  return {
    manifests: {
      [ISSUER]: ISSUER_MANIFEST,
      [PUBLISHER]: PUB_MANIFEST,
      [SUCCESSOR]: SUCCESSOR_MANIFEST,
      [OTHER]: OTHER_MANIFEST,
      ...extraManifests,
    },
    provenance: { [ISSUER]: 'tls', [PUBLISHER]: 'bundle', [SUCCESSOR]: 'bundle', [OTHER]: 'bundle' },
  }
}

function signRecord(body: Record<string, unknown>, signer: TestSigner = ISSUER_KEYS, kid = ISSUER_KID): JsonObject {
  const parsedBody = parse(body)
  return parse({ ...body, signature: signBlock(canonicalBytes(parsedBody), signer, kid) })
}

function revokedRecord(receiptId = RECEIPT_ID): JsonObject {
  return signRecord({ receipt_id: receiptId, status: 'revoked', revoked_at: REVOKED_AT })
}

function transferredRevocationRecord(receiptId = RECEIPT_ID): JsonObject {
  return signRecord({ receipt_id: receiptId, status: 'transferred', revoked_at: TRANSFERRED_AT })
}

function transferRecord(receiptId = RECEIPT_ID, newReceiptId = NEW_RECEIPT_ID): JsonObject {
  const newHolderPubkey = b64uEncode(NEW_HOLDER_PUB)
  const holderSig = ed25519.sign(authorizationMessage(receiptId, newHolderPubkey, TRANSFERRED_AT), HOLDER_SEED)
  return signRecord({
    receipt_id: receiptId,
    new_receipt_id: newReceiptId,
    new_holder_pubkey: newHolderPubkey,
    transferred_at: TRANSFERRED_AT,
    holder_authorization: { sig: b64uEncode(holderSig) },
  })
}

function deterministicLogKeys(): HybridTestKeys {
  const edSeed = new Uint8Array(32).fill(87)
  const edPub = ed25519.getPublicKey(edSeed)
  const { publicKey: mldsaPub, secretKey: mldsaSecret } = ml_dsa65.keygen(new Uint8Array(32).fill(88))
  return { edSeed, edPub, mldsaPub, mldsaSecret }
}

function logKey(keys: HybridTestKeys): LogKey {
  return { origin: LOG_ORIGIN, name: LOG_NAME, ed25519Pub: keys.edPub, mldsaPub: keys.mldsaPub }
}

function transferClaim(record: JsonObject, keys: HybridTestKeys): JsonObject {
  const entry = { type: 'transfer-record', issuer: ISSUER, record_sha256: transferRecordHash(record) }
  const leaf = encodeEntry(entry)
  const root = buildTree([leaf])
  const checkpoint = signCheckpoint(LOG_ORIGIN, 1, root, keys, LOG_NAME)
  const evidence = {
    entry,
    leaf_index: 0,
    tree_size: 1,
    inclusion_proof: inclusionProof([leaf], 0).map((part) => Buffer.from(part).toString('hex')),
    checkpoint,
  }
  return parse({ record, evidence })
}

function noHorizonPolicy(): AnchorPolicy {
  return { pinnedHeaders: {}, crqcHorizon: null }
}

function receiptEntry(envelope: Uint8Array): Record<string, unknown> {
  return { type: 'receipt', issuer: ISSUER, core_sha256: receiptCoreHash(loadsStrict(envelope)) }
}

function logEvidence(entry: Record<string, unknown>, keys: HybridTestKeys): JsonObject {
  const leaf = encodeEntry(entry)
  const root = buildTree([leaf])
  const checkpoint = signCheckpoint(LOG_ORIGIN, 1, root, keys, LOG_NAME)
  return parse({ entry, leaf_index: 0, tree_size: 1, inclusion_proof: [], checkpoint })
}

function compromiseManifest(): JsonObject {
  return buildKeyManifest(
    ISSUER,
    2,
    '2026-08-01T00:00:00Z',
    [
      keyEntry(ISSUER_KID, ISSUER_KEYS, VALID_FROM, { status: 'compromised' }),
      keyEntry(`${ISSUER}/keys/2026-02#ed25519-2`, hybridSigner(89), VALID_FROM, { status: 'active' }),
    ],
    ISSUER_KEYS,
    ISSUER_KID,
  )
}

function parseWireObject(value: unknown): JsonObject {
  return loadsStrict(enc.encode(JSON.stringify(value, (_key, item) => (
    typeof item === 'bigint' ? Number(item) : item
  )))) as JsonObject
}

function compromiseClaim(manifest: JsonObject): JsonObject {
  return parseWireObject({ manifest, evidence: null })
}

type Captured = { returned: true; result: ReturnType<typeof verify>; elapsedMs: number } | {
  returned: false
  error: unknown
  elapsedMs: number
}

function captureVerify(fn: () => ReturnType<typeof verify>): Captured {
  const started = performance.now()
  try {
    return { returned: true, result: fn(), elapsedMs: performance.now() - started }
  } catch (error) {
    return { returned: false, error, elapsedMs: performance.now() - started }
  }
}

function unwrapReturned(observed: Captured): ReturnType<typeof verify> {
  expect(observed.returned, observed.returned ? 'verify returned' : `verify threw: ${String(observed.error)}`).toBe(true)
  if (!observed.returned) throw observed.error
  return observed.result
}

function verifyReceipt(
  revocationView: unknown = null,
  options: Record<string, unknown> = {},
  revocability = 'policy',
): Captured {
  return captureVerify(() =>
    verify(
      envelopeBytes(payloadForReceipt(revocability)),
      trustStore(),
      revocationView as JsonValue[] | null,
      null,
      undefined,
      options as never,
    ),
  )
}

function verifyGrantReceipt(grantView: unknown, document: JsonObject = makeGrant()): Captured {
  return captureVerify(() =>
    verify(envelopeBytes(payloadForGrant(document)), trustStore(), null, null, undefined, { grantView } as never),
  )
}

function viewOf(document: JsonObject, members: Record<string, unknown> = {}): Record<string, unknown> {
  return { grant: document, ...members }
}

function throwingProxy(label: string): Record<string, unknown> {
  return new Proxy(Object.create(null), {
    get() { throw new Error(`${label}: get trap`) },
    has() { throw new Error(`${label}: has trap`) },
    ownKeys() { throw new Error(`${label}: ownKeys trap`) },
    getOwnPropertyDescriptor() { throw new Error(`${label}: descriptor trap`) },
  })
}

function revocationRecordWithLyingReceiptId(record: JsonObject): JsonObject {
  let receiptIdReads = 0
  return new Proxy(record, {
    get(target, prop, receiver) {
      if (prop === 'receipt_id') {
        receiptIdReads += 1
        return receiptIdReads <= 2 ? Reflect.get(target, prop, receiver) : OTHER_RECEIPT_ID
      }
      return Reflect.get(target, prop, receiver)
    },
    has() { return false },
    ownKeys(target) { return Reflect.ownKeys(target) },
  }) as JsonObject
}

function declarationWithLyingScope(declaration: JsonObject, visibleScope: Record<string, unknown>): JsonObject {
  let scopeReads = 0
  return new Proxy(declaration, {
    get(target, prop, receiver) {
      if (prop === 'scope') {
        scopeReads += 1
        return scopeReads <= 2 ? Reflect.get(target, prop, receiver) : visibleScope
      }
      return Reflect.get(target, prop, receiver)
    },
    has() { return true },
    ownKeys(target) { return Reflect.ownKeys(target) },
  }) as JsonObject
}

function transferRecordWithLyingFirstReceiptId(record: JsonObject): JsonObject {
  let receiptIdReads = 0
  return new Proxy(record, {
    get(target, prop, receiver) {
      if (prop === 'receipt_id') {
        receiptIdReads += 1
        return receiptIdReads === 1 ? RECEIPT_ID : Reflect.get(target, prop, receiver)
      }
      return Reflect.get(target, prop, receiver)
    },
    has() { return true },
    ownKeys(target) { return Reflect.ownKeys(target) },
  }) as JsonObject
}

function arrayProxyFakingContents(realItem: JsonValue, fakeItem: JsonValue): JsonValue[] {
  return new Proxy([realItem], {
    get(target, prop, receiver) {
      if (prop === '0') return fakeItem
      return Reflect.get(target, prop, receiver)
    },
    has(target, prop) {
      if (prop === '0') return true
      return Reflect.has(target, prop)
    },
    ownKeys(target) { return Reflect.ownKeys(target) },
  }) as JsonValue[]
}

function badNumberRecord(): JsonObject {
  return { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: REVOKED_AT, manifest_version: 1 } as unknown as JsonObject
}

function badOutOfRangeClaim(): JsonObject {
  return { record: { receipt_id: RECEIPT_ID, too_large: MAX_SAFE_JCS_INTEGER_PLUS_ONE }, evidence: null } as unknown as JsonObject
}

function nestedArray(depth: number): JsonValue {
  let value: JsonValue = null
  for (let i = 0; i < depth; i += 1) value = [value]
  return value
}

function lazyThrowingClaim(delayMs: number): JsonObject {
  const claim = Object.create(null) as Record<string, unknown>
  Object.defineProperty(claim, 'manifest', {
    enumerable: true,
    get() {
      const until = performance.now() + delayMs
      while (performance.now() < until) {
        // Deliberately burn a bounded slice of wall-clock time.
      }
      throw new Error('lazy getter did not produce a finite evidence unit')
    },
  })
  return claim as JsonObject
}

function grantViewWithGetter(document: JsonObject, member: string, value: unknown, throwing = false): Record<string, unknown> {
  const view: Record<string, unknown> = { grant: document }
  Object.defineProperty(view, member, {
    enumerable: true,
    get() {
      if (throwing) throw new Error(`${member} getter`)
      return value
    },
  })
  return view
}

function grantViewWithPrototypeMember(document: JsonObject, member: string, value: unknown): Record<string, unknown> {
  const proto = { [member]: value }
  const view = Object.create(proto) as Record<string, unknown>
  view['grant'] = document
  return view
}

function grantViewProxyWithLyingGet(document: JsonObject, hostileDeclarations: unknown): Record<string, unknown> {
  return new Proxy({ grant: document, declarations: [] }, {
    get(target, prop, receiver) {
      if (prop === 'declarations') return hostileDeclarations
      return Reflect.get(target, prop, receiver)
    },
    has() { return true },
    ownKeys() { return ['grant'] },
  })
}

function expectRevoked(result: ReturnType<typeof verify>): void {
  expect(result.signature).toBe('valid')
  expect(result.schema).toBe('valid')
  expect(result.revocation).toBe('revoked')
  expect(isOk(result)).toBe(false)
}

function expectTransferred(result: ReturnType<typeof verify>): void {
  expect(result.signature).toBe('valid')
  expect(result.schema).toBe('valid')
  expect(result.revocation).toBe('transferred')
  expect(isOk(result)).toBe(false)
}

describe('blind caller-rail admission boundary', () => {
  it('A/H permissive: a revocation record proxy may not hide the signed receipt_id after authentication', () => {
    const observed = verifyReceipt([revocationRecordWithLyingReceiptId(revokedRecord())])
    const result = unwrapReturned(observed)

    expectRevoked(result)
  })

  it('A permissive: a declaration proxy may not activate a grant on a scope the signature did not cover', () => {
    const floor = makeGrant()
    const nonCovering = makeDeclaration(PUB_KEYS, PUB_KID, scope(null, [OTHER_ART]))
    const chameleon = declarationWithLyingScope(nonCovering, scope())
    const observed = verifyGrantReceipt(viewOf(floor, { declarations: [chameleon] }), floor)
    const result = unwrapReturned(observed)

    expect(result.signature).toBe('valid')
    expect(result.schema).toBe('valid')
    expect(result.grant).toBe('dormant')
    expect(result.warnings).toContain('grant_declaration_ignored')
  })

  it('A permissive: a transfer claim proxy may not be honored for a receipt_id the signature did not cover', () => {
    const keys = deterministicLogKeys()
    const signedForOtherReceipt = transferRecord(OTHER_RECEIPT_ID, NEW_RECEIPT_ID)
    const hostileRecord = transferRecordWithLyingFirstReceiptId(signedForOtherReceipt)
    const hostileClaim = transferClaim(hostileRecord, keys)
    const observed = verifyReceipt([transferredRevocationRecord()], {
      transferView: [hostileClaim],
      logKeys: [logKey(keys)],
      anchorPolicy: noHorizonPolicy(),
    })
    const result = unwrapReturned(observed)

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transferred_revocation_unbacked')
    expect(isOk(result)).toBe(true)
  })

  it('A restrictive: a throwing grant-view member is absent data, not a whole-view exception', () => {
    const floor = makeGrant()
    const observed = verifyGrantReceipt(grantViewWithGetter(floor, 'declarations', [], true), floor)
    const result = unwrapReturned(observed)

    expect(result.signature).toBe('valid')
    expect(result.schema).toBe('valid')
    expect(result.grant).toBe('dormant')
    expect(result.grant_trust).toBe('unauthenticated_tofu')
  })

  it('B restrictive: a declarations getter is not own data and must not activate the grant', () => {
    const floor = makeGrant()
    const observed = verifyGrantReceipt(grantViewWithGetter(floor, 'declarations', [makeDeclaration()]), floor)
    const result = unwrapReturned(observed)

    expect(result.grant).toBe('dormant')
    expect(result.warnings).not.toContain('grant_declaration_ignored')
  })

  it('B restrictive: a prototype declarations member is not own data and must not activate the grant', () => {
    const floor = makeGrant()
    const observed = verifyGrantReceipt(grantViewWithPrototypeMember(floor, 'declarations', [makeDeclaration()]), floor)
    const result = unwrapReturned(observed)

    expect(result.grant).toBe('dormant')
    expect(result.grant_trust).toBe('unauthenticated_tofu')
  })

  it('C permissive: an Array.isArray-true proxy cannot fake a valid transfer claim over non-data contents', () => {
    const keys = deterministicLogKeys()
    const validRecord = transferRecord()
    const validClaim = transferClaim(validRecord, keys)
    const fakeTransferView = arrayProxyFakingContents({ record: null, evidence: null } as unknown as JsonObject, validClaim)
    const observed = verifyReceipt([transferredRevocationRecord()], {
      transferView: fakeTransferView,
      logKeys: [logKey(keys)],
      anchorPolicy: noHorizonPolicy(),
    })
    const result = unwrapReturned(observed)

    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(result.warnings).toContain('transferred_revocation_unbacked')
    expect(isOk(result)).toBe(true)
  })

  it('C restrictive: an array-shaped transferView object is a malformed container and raises', () => {
    const keys = deterministicLogKeys()
    const validClaim = transferClaim(transferRecord(), keys)
    const arrayShaped = { 0: validClaim, length: 1 }
    const observed = verifyReceipt([transferredRevocationRecord()], {
      transferView: arrayShaped,
      logKeys: [logKey(keys)],
      anchorPolicy: noHorizonPolicy(),
    })

    // transfer_view's container SHAPE is caller-contract (spec commit 12cd568):
    // a non-Array container raises TypeError, exactly like the Python core —
    // the hostile-CONTENT tolerance this suite tests elsewhere only applies
    // inside an admitted array, never to the array member itself.
    expect(observed.returned).toBe(false)
    expect(observed.elapsedMs).toBeLessThan(250)
    if (observed.returned) return
    expect(observed.error).toBeInstanceOf(TypeError)
    expect(String((observed.error as Error).message)).toMatch(/transfer_view must be a list of claims or None/)
  })

  it('D permissive: a number where bigint belongs in one revocation unit degrades without neutralizing a genuine revocation', () => {
    const observed = verifyReceipt([badNumberRecord(), revokedRecord()])
    const result = unwrapReturned(observed)

    expectRevoked(result)
  })

  it('D permissive: an out-of-range bigint transfer claim is set aside alone beside a genuine backed claim', () => {
    const keys = deterministicLogKeys()
    const validClaim = transferClaim(transferRecord(), keys)
    const observed = verifyReceipt([transferredRevocationRecord()], {
      transferView: [badOutOfRangeClaim(), validClaim],
      logKeys: [logKey(keys)],
      anchorPolicy: noHorizonPolicy(),
    })
    const result = unwrapReturned(observed)

    expectTransferred(result)
  })

  it('E permissive: depth 256 is admitted but depth 257 is not; the bad sibling alone is lost', () => {
    const keys = deterministicLogKeys()
    const validClaim = transferClaim(transferRecord(), keys)
    const depth256 = { record: null, evidence: nestedArray(256) } as unknown as JsonObject
    const depth257 = { record: null, evidence: nestedArray(257) } as unknown as JsonObject
    const observed = verifyReceipt([transferredRevocationRecord()], {
      transferView: [depth256, depth257, validClaim],
      logKeys: [logKey(keys)],
      anchorPolicy: noHorizonPolicy(),
    })
    const result = unwrapReturned(observed)

    expectTransferred(result)
  })

  it('F permissive: a lazy compromise getter returns within a wall-clock bound and cannot erase a genuine compromise claim', () => {
    const declaration = compromiseManifest()
    const observed = verifyReceipt(null, {
      compromiseView: [lazyThrowingClaim(25), compromiseClaim(declaration)],
    })
    const result = unwrapReturned(observed)

    expect(observed.elapsedMs).toBeLessThan(500)
    expect(result.signature).toBe('invalid')
    expect(result.errors).toContain(`key ${ISSUER_KID} is compromised`)
  })

  it('G permissive: revocation sibling survival sets aside only a throwing bad record', () => {
    const observed = verifyReceipt([throwingProxy('revocation'), revokedRecord()])
    const result = unwrapReturned(observed)

    expectRevoked(result)
  })

  it('G permissive: transfer sibling survival sets aside only an inadmissible claim', () => {
    const keys = deterministicLogKeys()
    const validClaim = transferClaim(transferRecord(), keys)
    const observed = verifyReceipt([transferredRevocationRecord()], {
      transferView: [throwingProxy('transfer') as unknown as JsonObject, validClaim],
      logKeys: [logKey(keys)],
      anchorPolicy: noHorizonPolicy(),
    })
    const result = unwrapReturned(observed)

    expectTransferred(result)
  })

  it('G permissive: compromise sibling survival sets aside only an inadmissible claim', () => {
    const declaration = compromiseManifest()
    const observed = verifyReceipt(null, {
      compromiseView: [() => declaration, compromiseClaim(declaration)],
    })
    const result = unwrapReturned(observed)

    expect(result.signature).toBe('invalid')
    expect(result.errors).toContain(`key ${ISSUER_KID} is compromised`)
  })

  it('G restrictive: declaration sibling survival reports the bad declaration and honors the genuine one', () => {
    const floor = makeGrant()
    const observed = verifyGrantReceipt(viewOf(floor, {
      declarations: [throwingProxy('declaration'), makeDeclaration()],
    }), floor)
    const result = unwrapReturned(observed)

    expect(result.grant).toBe('activated')
    expect(result.warnings).toContain('grant_declaration_ignored')
  })

  it('G restrictive: later_grants sibling survival keeps a genuine widening version and does not downgrade trust for the bad one', () => {
    const floor = makeGrant(PUB_KEYS, PUB_KID, { activation: activation(['publisher-declaration'], null, []) })
    const later = makeGrant(PUB_KEYS, PUB_KID, {
      grant_version: 2,
      activation: activation(['publisher-declaration'], null, [SUCCESSOR]),
    })
    const observed = verifyGrantReceipt(viewOf(floor, {
      later_grants: [throwingProxy('later-grant'), later],
      declarations: [makeDeclaration(SUCCESSOR_KEYS, SUCCESSOR_KID)],
    }), floor)
    const result = unwrapReturned(observed)

    expect(result.grant).toBe('activated')
    expect(result.grant_trust).toBe('unauthenticated_tofu')
    expect(result.warnings).toContain('grant_activated_by_successor')
  })

  it('A restrictive: a grantView proxy with lying get/has/ownKeys traps cannot synthesize declaration evidence', () => {
    const floor = makeGrant()
    const observed = verifyGrantReceipt(grantViewProxyWithLyingGet(floor, [makeDeclaration()]), floor)
    const result = unwrapReturned(observed)

    expect(result.grant).toBe('dormant')
    expect(result.grant_trust).toBe('unauthenticated_tofu')
  })

  it('H restrictive: a refused floor grant does not invalidate the receipt and is named invalid_grant_ignored', () => {
    const goodFloor = makeGrant()
    const numericVersionFloor = { ...goodFloor, grant_version: 1 } as unknown as JsonObject
    const observed = verifyGrantReceipt(viewOf(numericVersionFloor, { declarations: [makeDeclaration()] }), goodFloor)
    const result = unwrapReturned(observed)

    expect(result.signature).toBe('valid')
    expect(result.schema).toBe('valid')
    expect(result.grant).toBe('invalid_grant_ignored')
    expect(isOk(result)).toBe(true)
  })

  it('H permissive: a refused revocation evidence unit must not report ok when a genuine sibling revokes', () => {
    const seedCases = [101, 202, 303, 404]
    for (const seed of seedCases) {
      const badUnit = seed % 2 === 0 ? badNumberRecord() : throwingProxy(`revocation-${seed}`)
      const observed = verifyReceipt([badUnit as JsonObject, revokedRecord()])
      const result = unwrapReturned(observed)

      expectRevoked(result)
    }
  })

  it('H permissive: a refused transfer evidence unit must not neutralize genuine backed transfer evidence', () => {
    const keys = deterministicLogKeys()
    const validClaim = transferClaim(transferRecord(), keys)
    const seedCases = [17, 29, 43, 59]
    for (const seed of seedCases) {
      const badUnit = seed % 2 === 0 ? badOutOfRangeClaim() : throwingProxy(`transfer-${seed}`)
      const observed = verifyReceipt([transferredRevocationRecord()], {
        transferView: [badUnit as JsonObject, validClaim],
        logKeys: [logKey(keys)],
        anchorPolicy: noHorizonPolicy(),
      })
      const result = unwrapReturned(observed)

      expectTransferred(result)
    }
  })

  it('F restrictive: an array-shaped grant declarations value with a finite lazy length carries nothing within the bound', () => {
    const floor = makeGrant()
    const declarations = {
      length: 1,
      get 0() {
        const until = performance.now() + 25
        while (performance.now() < until) {
          // Bounded delay: a real array would be traversed, this shape is not one.
        }
        return makeDeclaration()
      },
    }
    const observed = verifyGrantReceipt(viewOf(floor, { declarations }), floor)
    const result = unwrapReturned(observed)

    expect(observed.elapsedMs).toBeLessThan(500)
    // The wall-clock bound is the property this case pins: an array-SHAPED
    // member with a lazy accessor is not traversed. What the two verdicts
    // below record is a CONFORMANCE GAP, not a ratified reading — see the
    // strict expected-failure immediately after.
    expect(result.grant).toBe('not_checked')
    expect(result.grant_trust).toBe('not_checked')
  })

  // §18.4, "The unit of admission is the MEMBER": a member is inadmissible only
  // for a property of the MEMBER, and it is "never a reason to refuse the view
  // or any other member" — a malformed `declarations` must not erase the
  // sibling `grant` member nor the trust its genuine evidence already bought.
  // MEASURED 2026-08-29, and the two cores DISAGREE: Python drops a member
  // that does not reconstruct to an array, so the sibling grant survives and
  // the verdict is dormant/verified — conforming. TypeScript keeps it, the
  // ceiling guard refuses, and the genuine grant is erased. A restrictive
  // parity divergence on a rail already published, and precisely the
  // defame-by-junk primitive §18.4 exists to deny. The fix belongs to
  // the grant rail's own round, not to a test commit. Marked failing on purpose:
  // when the cores are fixed this test starts failing and forces its own
  // removal, exactly as a strict xfail does on the Python side.
  it.fails('F restrictive: a malformed declarations member must not erase the sibling grant', () => {
    const floor = makeGrant()
    const declarations = {
      length: 1,
      get 0() {
        return makeDeclaration()
      },
    }
    const result = unwrapReturned(verifyGrantReceipt(viewOf(floor, { declarations }), floor))

    expect(result.grant).toBe('dormant')
    expect(result.grant_trust).toBe('unauthenticated_tofu')
  })

  it('F permissive: compromise sibling survival still holds when the genuine claim is needed after receipt anchoring', () => {
    const keys = deterministicLogKeys()
    const envelope = envelopeBytes(payloadForReceipt('none'))
    const receiptEvidence = logEvidence(receiptEntry(envelope), keys)
    const declaration = compromiseManifest()
    const observed = captureVerify(() =>
      verify(envelope, trustStore(), null, null, undefined, {
        transparency: receiptEvidence,
        logKeys: [logKey(keys)],
        anchorPolicy: noHorizonPolicy(),
        compromiseView: [lazyThrowingClaim(25), compromiseClaim(declaration)],
      } as never),
    )
    const result = unwrapReturned(observed)

    expect(observed.elapsedMs).toBeLessThan(500)
    expect(result.signature).toBe('invalid')
    expect(result.errors).toContain(`key ${ISSUER_KID} is compromised`)
  })
})
