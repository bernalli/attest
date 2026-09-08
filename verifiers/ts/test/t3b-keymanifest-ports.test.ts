/**
 * The manifest ports take a HANDLE, and the reconstruction boundary refuses an
 * accessor instead of dropping it. Two properties, two sections, because they
 * fail for different reasons and a single suite would hide which one broke.
 *
 * WHAT THIS REPLACES, AND WHY IT IS NOT THE SAME FILE
 * --------------------------------------------------
 * Its ancestor was a measurement probe: it DOCUMENTED a defect, asserting the
 * verdicts an attacker could reach on 0.9.3's core. `materializeKeyManifest`
 * read each field's descriptor exactly twice — once to validate, once to copy —
 * and an entry answering truthfully to the first read and with an accessor to
 * the second was validated with its true `valid_to` and copied WITHOUT it,
 * because the object branch of `ownDataCopy` skipped a non-data descriptor
 * where the array branch threw on it. Downstream an absent `valid_to` is not an
 * error, it is "no upper bound", so an expired key verified. Measured on this
 * branch: `verifyGrantSignature` -> true against `verifyGrant` -> false, on the
 * four doors whose contract makes the manifest's self-verify the caller's job.
 *
 * Both halves of that are now closed, and the sections below are separate
 * because the halves are:
 *
 *   1. the ports do not take a live object AT ALL — there is no second read to
 *      disagree with the first, because there is nothing of the caller's left
 *      to read (`KeyManifest`, built from bytes this library parsed);
 *   2. the reconstruction boundary the EVIDENCE rails still walk refuses a unit
 *      carrying an accessor rather than admitting it with the member gone.
 *
 * Section 1 alone would be a weaker suite than it looks: once every live object
 * is refused, "returns false" stops telling a defence from a contract refusal.
 * Every case here is therefore paired with a POSITIVE control on the same
 * material through the handle — a `false` next to a `true` is a measurement, a
 * `false` on its own is not.
 */
import { describe, it, expect } from 'vitest'
import { canonicalBytes, materializeValue } from '../src/canon.js'
import { ERR } from '../src/messages.js'
import type { JsonObject } from '../src/canon.js'
import type { KeyManifest as KeyManifestHandle } from '../src/trustMaterial.js'
import { keyManifest as manifestHandle } from './helpers/trust.js'
import {
  verifyGrant,
  verifyGrantSignature,
  verifyDeclaration,
  verifyDeclarationSignature,
} from '../src/grant.js'
import {
  verifyAuthorization as verifyPublisherAuthorization,
  verifyAuthorizationSignature as verifyPublisherAuthorizationSignature,
} from '../src/authority.js'
import {
  verifyRecord as verifyTransferRecord,
  verifyRecordSignature as verifyTransferRecordSignature,
  auditChain,
  authorizationMessage,
} from '../src/transfer.js'
import { ed25519 } from '@noble/curves/ed25519'
import { b64uEncode } from '../src/b64u.js'
import {
  buildKeyManifest,
  buildGrant,
  buildDeclaration,
  edSigner,
  keyEntry,
  signBlock,
  parse,
  type TestSigner,
} from './helpers/grant-builder.js'

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/probe#ed25519-1`
const SIGNER: TestSigner = edSigner(70)
const MANIFEST_ISSUED_AT = '2020-01-01T00:00:00Z'
const VALID_FROM = '2020-01-01T00:00:00Z'
const PAST_VALID_TO = '2020-06-01T00:00:00Z' // the key's real expiry
const AFTER_EXPIRY = '2026-01-01T00:00:00Z' // every document below is signed at this instant

const activeEntry = () => keyEntry(KID, SIGNER, VALID_FROM, { validTo: null, status: 'active' })
const expiredEntry = () => keyEntry(KID, SIGNER, VALID_FROM, { validTo: PAST_VALID_TO, status: 'active' })
const manifestWith = (entries: Record<string, unknown>[]): JsonObject =>
  buildKeyManifest(ISSUER, 1, MANIFEST_ISSUED_AT, entries, SIGNER, KID)

const ACTIVE = manifestWith([activeEntry()])
const EXPIRED = manifestWith([expiredEntry()])

/**
 * A Proxy over a real entry that answers `getOwnPropertyDescriptor(prop)` with
 * a truthful DATA descriptor for the first `truthfulReads` calls and with an
 * ACCESSOR for every call after that.
 *
 * This is the exact shape that made the old two-walk materializer drop a
 * member: truthful for the validating walk, an accessor for the copying one.
 */
function lyingEntry(honest: Record<string, unknown>, prop: string, truthfulReads: number): unknown {
  let reads = 0
  return new Proxy(honest, {
    getOwnPropertyDescriptor(target, p) {
      if (p === prop) {
        reads += 1
        if (reads > truthfulReads) {
          return { get: () => (target as Record<string, unknown>)[prop], enumerable: true, configurable: true }
        }
      }
      return Reflect.getOwnPropertyDescriptor(target, p)
    },
  })
}

const hostileManifest = (truthfulReads: number): unknown => ({
  ...(EXPIRED as unknown as Record<string, unknown>),
  keys: [lyingEntry((EXPIRED['keys'] as JsonObject[])[0] as unknown as Record<string, unknown>, 'valid_to', truthfulReads)],
})

// --- the documents, one per rail, all signed AFTER the key expired ----------

const GRANT = buildGrant(
  {
    grant_version: 1,
    publisher: ISSUER,
    scope: { artifact_series: `${ISSUER}/works/EXG-001`, artifacts: [] },
    permissions: ['deliver-to-holder'],
    activation: { modes: ['fixed-date'], fixed_date: '2046-01-01T00:00:00Z', successor_ids: [] },
    unprotected_build: true,
    legal_text_uri: 'https://store.example.com/sunset-grant-v1',
    legal_text_sha256: 'a'.repeat(64),
    jurisdiction: 'IT',
    issued_at: AFTER_EXPIRY,
  },
  SIGNER,
  KID,
)

const DECLARATION = buildDeclaration(
  ISSUER,
  { artifact_series: `${ISSUER}/works/EXG-001`, artifacts: [] },
  AFTER_EXPIRY,
  SIGNER,
  KID,
)

const AUTHORIZATION = (() => {
  const body = {
    authorization_version: 1,
    publisher: ISSUER,
    authorized_issuers: [
      { issuer_id: ISSUER, valid_from: VALID_FROM, valid_to: null, permissions: ['issue'], scope: null },
    ],
    issued_at: AFTER_EXPIRY,
  }
  return parse({ ...body, signature: signBlock(canonicalBytes(parse(body)), SIGNER, KID) })
})()

const OLD_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAV'
const NEW_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAW'
const holderSeed = Uint8Array.from({ length: 32 }, () => 90)
const holderPub = ed25519.getPublicKey(holderSeed)

const TRANSFER = (() => {
  const newHolderPubkey = b64uEncode(holderPub)
  const authSig = ed25519.sign(authorizationMessage(OLD_ID, newHolderPubkey, AFTER_EXPIRY), holderSeed)
  const body = {
    receipt_id: OLD_ID,
    new_receipt_id: NEW_ID,
    new_holder_pubkey: newHolderPubkey,
    transferred_at: AFTER_EXPIRY,
    holder_authorization: { sig: b64uEncode(authSig) },
  }
  return parse({ ...body, signature: signBlock(canonicalBytes(parse(body)), SIGNER, KID) })
})()

/**
 * The eight boolean ports, each as a function of the manifest alone.
 *
 * Enumerated from the module exports rather than described in prose: a port
 * added to one of these files and not to this list is a port this suite does
 * not measure, and a list is the only form in which that omission is visible.
 * `auditChain` is not here — it returns a report, not a boolean — and has its
 * own section below.
 */
const BOOLEAN_PORTS: ReadonlyArray<readonly [string, (m: KeyManifestHandle) => boolean]> = [
  ['verifyGrant', (m) => verifyGrant(GRANT, m)],
  ['verifyGrantSignature', (m) => verifyGrantSignature(GRANT, m)],
  ['verifyDeclaration', (m) => verifyDeclaration(DECLARATION, m)],
  ['verifyDeclarationSignature', (m) => verifyDeclarationSignature(DECLARATION, m)],
  ['verifyPublisherAuthorization', (m) => verifyPublisherAuthorization(AUTHORIZATION, m)],
  ['verifyPublisherAuthorizationSignature', (m) => verifyPublisherAuthorizationSignature(AUTHORIZATION, m)],
  ['verifyTransferRecord', (m) => verifyTransferRecord(TRANSFER, m)],
  ['verifyTransferRecordSignature', (m) => verifyTransferRecordSignature(TRANSFER, m)],
]

// ===========================================================================
// SECTION 1 — the ports take a handle, and a live object is not one.
// ===========================================================================

describe('the manifest ports accept a parsed handle and nothing else', () => {
  it.each(BOOLEAN_PORTS)('%s: honest manifest accepted as a handle (positive control)', (_name, port) => {
    expect(port(manifestHandle(ACTIVE))).toBe(true)
  })

  it.each(BOOLEAN_PORTS)('%s: the SAME honest manifest as a live object is refused', (_name, port) => {
    // Not a hostile object: the very manifest that returns `true` above, passed
    // as the plain object callers used to hand over. The pair is the point —
    // one `false` next to one `true` on identical material says the refusal is
    // the contract and not the document.
    expect(port(ACTIVE as unknown as KeyManifestHandle)).toBe(false)
  })

  it.each(BOOLEAN_PORTS)('%s: an expired key is refused THROUGH the handle', (_name, port) => {
    // The substantive property, on the path callers actually take. Without this
    // the suite would only be pinning the contract, and a core that refused
    // everything would pass it.
    expect(port(manifestHandle(EXPIRED))).toBe(false)
  })

  it.each([0, 1, 2, 3])(
    'the two-read window that flipped four verdicts on 0.9.3 is unreachable (truthful reads = %i)',
    (truthful) => {
      const hostile = hostileManifest(truthful) as KeyManifestHandle
      for (const [, port] of BOOLEAN_PORTS) expect(port(hostile)).toBe(false)
    },
  )
})

// ===========================================================================
// SECTION 2 — the reconstruction boundary, which the EVIDENCE rails still walk.
//
// Section 1 removed the live object from the trust path; it did not remove it
// from the evidence path, where §18.4 admits caller-supplied views by
// reconstruction. `ownDataCopy` is shared by both, and the asymmetry that made
// the flip possible lived there: the object branch skipped a non-data
// descriptor, the array branch threw on one. These cases are what tell a
// boundary that REFUSES a mutilated unit from one that ADMITS it.
// ===========================================================================

describe('the reconstruction boundary refuses a unit whose member reads as an accessor', () => {
  const honest = (): Record<string, unknown> => ({ kept: 'a', dropped: 'b' })

  it('positive control: a plain unit is reconstructed whole', () => {
    expect(materializeValue(honest())).toEqual({ kept: 'a', dropped: 'b' })
  })

  it('a member whose descriptor reads as an accessor sets the WHOLE unit aside', () => {
    // Before the fix this returned `{ kept: 'a' }`: admitted, and silently one
    // member short. An absent member is not an absent meaning downstream, which
    // is precisely how a dropped `valid_to` became "no upper bound".
    const unit: Record<string, unknown> = { kept: 'a' }
    Object.defineProperty(unit, 'dropped', { get: () => 'b', enumerable: true, configurable: true })
    expect(materializeValue(unit)).toBeNull()
  })

  it('the array branch behaves the same way, which is the symmetry that was missing', () => {
    const arr: unknown[] = ['a']
    Object.defineProperty(arr, '1', { get: () => 'b', enumerable: true, configurable: true })
    expect(materializeValue(arr)).toBeNull()
  })

  it('a NON-ENUMERABLE data member is still skipped, and that is a different case', () => {
    // Deliberately NOT symmetric with the accessor, and the reason is that a
    // non-enumerable property is not in the object's JSON form at all —
    // `JSON.stringify` does not serialize it and no parser produces one — so
    // there is no member to lose. Making this refuse too costs a genuine
    // document its activation, which `blind-integer-representation.test.ts`
    // pins ("a non-enumerable extra member is not own data and the genuine
    // declaration still activates").
    const unit: Record<string, unknown> = { kept: 'a' }
    Object.defineProperty(unit, 'hidden', { value: 'b', enumerable: false, configurable: true })
    expect(materializeValue(unit)).toEqual({ kept: 'a' })
  })

  it('one truthful read is now enough to be admitted WHOLE: there is no second walk to lie to', () => {
    // The old boundary read every descriptor twice, so `truthfulReads: 1` meant
    // "honest to the validator, an accessor to the copier" — the exploit. There
    // is one walk now, so a unit that answers honestly to it is admitted with
    // its member intact, and one that does not is set aside entire. The window
    // is not narrower, it is gone.
    const base = honest()
    expect(materializeValue(lyingEntry(base, 'dropped', 1))).toEqual({ kept: 'a', dropped: 'b' })
    expect(materializeValue(lyingEntry(base, 'dropped', 0))).toBeNull()
  })
})

// ===========================================================================
// SECTION 3 — auditChain, whose two refusals are not the same refusal.
// ===========================================================================

describe('auditChain separates a contract refusal from a finding about real material', () => {
  const payloads = [
    parse({ receipt_id: OLD_ID, buyer: { pubkey: b64uEncode(holderPub) } }),
    parse({ receipt_id: NEW_ID, buyer: { pubkey: b64uEncode(holderPub) } }),
  ]
  const view = parse([{ record: TRANSFER, evidence: null }])
  const NO_ANCHOR = { horizon: null } as unknown as import('../src/anchor.js').AnchorPolicy
  const audit = (m: unknown, ps = payloads) =>
    auditChain(ps, view, [], m as KeyManifestHandle, [], NO_ANCHOR)

  it('positive control: an honest handle audits the chain without an issuer-signature error', () => {
    const res = audit(manifestHandle(ACTIVE))
    expect(res.errors.some((e) => e.toLowerCase().includes('issuer'))).toBe(false)
  })

  it('the contract refusal NAMES itself, and at zero links it is the only thing said', () => {
    // `valid: false` with an empty `errors` would be a rejection a caller
    // cannot act on: nothing in the report would say the manifest was never
    // parsed. The message is the one `verify()` uses for the trust store, with
    // "key manifest" in it, and the Python twin puts the SAME string in the
    // SAME position — measured, both cores print
    // "key manifest must be a parsed snapshot produced by this library; a live
    // object is not accepted".
    const zeroLinks = audit(ACTIVE, [payloads[0]!])
    expect(zeroLinks.valid).toBe(false)
    expect(zeroLinks.errors).toEqual([ERR.KEY_MANIFEST_NOT_PARSED])

    // With links, the naming error comes FIRST and the per-link errors follow.
    const withLinks = audit(ACTIVE)
    expect(withLinks.errors[0]).toBe(ERR.KEY_MANIFEST_NOT_PARSED)
    expect(withLinks.errors).toHaveLength(2)

    // And a handle that merely fails its own self-verify does NOT carry it:
    // that refusal is a verdict on real material, not a contract violation.
    const selfInconsistent = manifestHandle({
      ...(ACTIVE as unknown as Record<string, unknown>),
      issued_at: '2021-01-01T00:00:00Z',
    } as JsonObject)
    expect(audit(selfInconsistent).errors).not.toContain(ERR.KEY_MANIFEST_NOT_PARSED)
  })

  it('a live object is refused, and an EMPTY chain of it is invalid too', () => {
    // D6: with no handle there is no audited material, so there is nothing for
    // an empty chain to be vacuously valid ABOUT. This is the case a plain
    // `valid: linkCount === 0` would have reported as valid.
    expect(audit(ACTIVE).valid).toBe(false)
    expect(audit(ACTIVE, [payloads[0]!]).valid).toBe(false)
  })

  it('a handle whose manifest fails its OWN self-verify keeps the empty chain vacuously valid', () => {
    // Unchanged on purpose, and the contrast with the case above is the whole
    // point of writing the two refusals apart: this one is a finding about real
    // parsed material, not a caller who never parsed any.
    const selfInconsistent = manifestHandle({
      ...(ACTIVE as unknown as Record<string, unknown>),
      issued_at: '2021-01-01T00:00:00Z', // signed over the other value
    } as JsonObject)
    expect(audit(selfInconsistent).valid).toBe(false)
    expect(audit(selfInconsistent, [payloads[0]!]).valid).toBe(true)
  })
})
