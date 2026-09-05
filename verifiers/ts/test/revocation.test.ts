import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { hexToBytes } from '@noble/curves/utils.js'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { verifyRecord, classifyRevocation, recordHash } from '../src/revocation.js'
import { parseCheckpoint, type LogKey } from '../src/tlog.js'
import type { AnchorPolicy } from '../src/anchor.js'

const h = (hex: string) => hexToBytes(hex)

const enc = (s: string) => new TextEncoder().encode(s)

// Reuses Task 10's self-signed-manifest pattern (see manifests.test.ts): sign JCS of
// the body (everything except the signature member itself), then attach the block.
function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, manifest_signature: { kid, sig: b64uEncode(sig) } }
}

// Same pattern, but for a revocation record: sign JCS of the record minus 'signature'.
function signRecord(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, signature: { kid, sig: b64uEncode(sig) } }
}

// Every fixture fed to revocation.ts functions MUST go through loadsStrict so that
// integers (manifest_version, revocation_window_days, ...) parse as bigint.
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject

const ISSUER = 'store.example.com'

const seed1 = Uint8Array.from({ length: 32 }, () => 7)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/2025-01#ed25519-1`

// Wrong/absent key: never listed in the key manifest at all — signs a record that
// looks otherwise identical to one signed by kid1, but cannot authenticate.
const seedWrong = Uint8Array.from({ length: 32 }, () => 99)
const kidWrong = `${ISSUER}/keys/2025-01#ed25519-wrong`

const seedCompromised = Uint8Array.from({ length: 32 }, () => 11)
const pubCompromised = b64uEncode(ed25519.getPublicKey(seedCompromised))
const kidCompromised = `${ISSUER}/keys/2025-01#ed25519-compromised`

const seedRetired = Uint8Array.from({ length: 32 }, () => 12)
const pubRetired = b64uEncode(ed25519.getPublicKey(seedRetired))
const kidRetired = `${ISSUER}/keys/2025-01#ed25519-retired`

// Key manifest self-signed by the active key (kid1); also lists a compromised and a
// retired key so a "record signed by a non-active key" can be tested without needing
// a second manifest.
const keyManifest = signManifest(
  {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2025-01-01T00:00:00Z',
    keys: [
      { kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' },
      {
        kid: kidCompromised,
        pub: pubCompromised,
        valid_from: '2025-01-01T00:00:00Z',
        valid_to: null,
        status: 'compromised',
      },
      {
        kid: kidRetired,
        pub: pubRetired,
        valid_from: '2025-01-01T00:00:00Z',
        valid_to: null,
        status: 'retired',
      },
    ],
  },
  kid1,
  seed1,
)

const RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'

// Minimal payload shape: classifyRevocation only reads receipt_id and license.*.
function receiptPayload(license: Record<string, unknown>): JsonObject {
  return parse({
    issuer: { id: ISSUER, display_name: 'Example Games Store' },
    issued_at: '2025-07-02T13:50:00Z',
    receipt_id: RECEIPT_ID,
    license,
  })
}

// vector 15/16 shape: a single valid revoked record for RECEIPT_ID, signed by kid1.
const revokedRecord = signRecord(
  { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
  kid1,
  seed1,
)

describe('revocation', () => {
  describe('verifyRecord', () => {
    it('verifies a record signed by the active key', () => {
      expect(verifyRecord(parse(revokedRecord), parse(keyManifest))).toBe(true)
    })

    it('rejects a record signed by a compromised key (a compromised key must not forge revocations)', () => {
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidCompromised,
        seedCompromised,
      )
      expect(verifyRecord(parse(record), parse(keyManifest))).toBe(false)
    })

    it('rejects a record signed by a retired key', () => {
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidRetired,
        seedRetired,
      )
      expect(verifyRecord(parse(record), parse(keyManifest))).toBe(false)
    })

    it('rejects a record signed by a key absent from the manifest entirely', () => {
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidWrong,
        seedWrong,
      )
      expect(verifyRecord(parse(record), parse(keyManifest))).toBe(false)
    })

    it('rejects a record whose revoked_at falls outside the signer key\'s validity window', () => {
      const boundedManifest = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 1,
          issued_at: '2025-01-01T00:00:00Z',
          keys: [
            {
              kid: kid1,
              pub: pub1,
              valid_from: '2025-01-01T00:00:00Z',
              valid_to: '2025-06-01T00:00:00Z',
              status: 'active',
            },
          ],
        },
        kid1,
        seed1,
      )
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kid1,
        seed1,
      )
      expect(verifyRecord(parse(record), parse(boundedManifest))).toBe(false)
    })
  })

  describe('classifyRevocation', () => {
    it('policy receipt + authenticated matching revoked record -> revoked, no warnings (vector 15 shape)', () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        [parse(revokedRecord)],
        parse(keyManifest),
        warnings,
        errors,
      )
      expect(result).toBe('revoked')
      expect(warnings).toEqual([])
    })

    it("none receipt + same record -> invalid_revocation_ignored + a warning containing \"revocability is 'none'\" (vector 16 shape)", () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'none' }),
        [parse(revokedRecord)],
        parse(keyManifest),
        warnings,
        errors,
      )
      expect(result).toBe('invalid_revocation_ignored')
      expect(warnings.some((w) => w.includes("revocability is 'none'"))).toBe(true)
    })

    it('an unauthenticated record (wrong/absent key) matching receipt_id is dropped with a "failed verification, ignored" warning', () => {
      const badRecord = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidWrong,
        seedWrong,
      )
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        [parse(badRecord)],
        parse(keyManifest),
        warnings,
        errors,
      )
      // Dropped -> no valid record, and no authenticated record to anchor T -> unknown.
      expect(result).toBe('unknown')
      expect(warnings.some((w) => w.includes('failed verification, ignored'))).toBe(true)
    })

    it('returns unknown for an empty view', () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(receiptPayload({ revocability: 'policy' }), [], parse(keyManifest), warnings, errors)
      expect(result).toBe('unknown')
      expect(warnings).toEqual([])
    })

    it('returns unknown for a null view', () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        null,
        parse(keyManifest),
        warnings,
        errors,
      )
      expect(result).toBe('unknown')
      expect(warnings).toEqual([])
    })

    it('the freshness anchor uses ONLY authenticated records; an unauthenticated record must not move T', () => {
      // Neither record's receipt_id matches the payload's, so neither can become a
      // "valid" (effective) record for this receipt — this isolates the anchor
      // computation, which runs over ALL authenticated records regardless of
      // receipt_id, from the per-receipt matching logic.
      //
      // Both ids are WELL-FORMED ULIDs that simply name other receipts. They
      // have to be: a malformed receipt_id now fails authentication outright
      // (see revocation-parity.test.ts), which would make this test pass for
      // the wrong reason — no record would authenticate and the anchor would be
      // absent rather than correctly chosen.
      const authRecordEarlier = signRecord(
        { receipt_id: '01J000000000000000000000AA', status: 'revoked', revoked_at: '2025-01-01T00:00:00Z' },
        kid1,
        seed1,
      )
      const unauthRecordLater = signRecord(
        { receipt_id: '01J000000000000000000000AB', status: 'revoked', revoked_at: '2099-01-01T00:00:00Z' },
        kidWrong,
        seedWrong,
      )
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        [parse(authRecordEarlier), parse(unauthRecordLater)],
        parse(keyManifest),
        warnings,
        errors,
      )
      // If the unauthenticated 2099 record had moved T, this would read
      // 'not_revoked_as_of:2099-01-01T00:00:00Z' instead.
      expect(result).toBe('not_revoked_as_of:2025-01-01T00:00:00Z')
      // Neither record's receipt_id matches -> no "failed verification" warning either.
      expect(warnings).toEqual([])
    })

    describe('refund_window class', () => {
      function refundPayload(windowDays: number, issuedAt: string, receiptId = RECEIPT_ID): JsonObject {
        return parse({
          issuer: { id: ISSUER },
          issued_at: issuedAt,
          receipt_id: receiptId,
          license: { revocability: 'refund_window', revocation_window_days: windowDays },
        })
      }

      it('an effective (in-window) record -> revoked', () => {
        const payload = refundPayload(30, '2025-07-01T00:00:00Z')
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        expect(classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)).toBe('revoked')
        expect(warnings).toEqual([])
      })

      it('a valid but out-of-window record -> invalid_revocation_ignored + outside-refund-window warning', () => {
        const payload = refundPayload(30, '2025-07-01T00:00:00Z')
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-09-01T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
        expect(result).toBe('invalid_revocation_ignored')
        expect(warnings.some((w) => w.includes('outside refund window, ignored'))).toBe(true)
      })

      it('no matching valid record -> not_revoked_as_of anchor from the authenticated record', () => {
        // revokedRecord authenticates (kid1, active) so it drives the freshness anchor,
        // but its receipt_id doesn't match this payload's, so it can never become
        // "valid" here -> falls through to the anchor-based not_revoked_as_of result.
        const noMatchPayload = refundPayload(30, '2025-07-01T00:00:00Z', 'no-such-receipt')
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(noMatchPayload, [parse(revokedRecord)], parse(keyManifest), warnings, errors)
        expect(result).toBe('not_revoked_as_of:2025-08-01T00:00:00Z')
        expect(warnings).toEqual([])
      })

      it('a non-integer revocation_window_days (bool) is treated as no window -> not_revoked/unknown, never revoked', () => {
        const payload = parse({
          issuer: { id: ISSUER },
          issued_at: '2025-07-01T00:00:00Z',
          receipt_id: RECEIPT_ID,
          license: { revocability: 'refund_window', revocation_window_days: true },
        })
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
        // window_end is null -> record can never be "effective" -> falls through to the
        // "valid but no effective window" branch -> invalid_revocation_ignored.
        expect(result).toBe('invalid_revocation_ignored')
        expect(warnings.some((w) => w.includes('outside refund window, ignored'))).toBe(true)
      })
    })

    // G5 (v0.2 §8/§15 amendment, TM-47): a refund_window record is effective
    // only if Stage-2 evidence proves it was logged/anchored no later than
    // the refund-window deadline, once the verifier is Stage-2 capable
    // (logKeys/anchorPolicy supplied). The full genuine-crypto round trip
    // (checkpoint + OTS anchor) is exercised end-to-end by conformance
    // vectors 33a/33c (both runners); these unit tests isolate the
    // engagement gate itself.
    describe('G5: deadline effectiveness (TM-47)', () => {
      const fakeLogKey: LogKey = {
        origin: 'revocation-log.example/2026',
        name: 'log-1',
        ed25519Pub: ed25519.getPublicKey(new Uint8Array(32).fill(3)),
        mldsaPub: new Uint8Array(1952),
      }
      const noHorizonPolicy: AnchorPolicy = { pinnedHeaders: {}, crqcHorizon: null }

      function refundPayload(windowDays: number, issuedAt: string): JsonObject {
        return parse({
          issuer: { id: ISSUER },
          issued_at: issuedAt,
          receipt_id: RECEIPT_ID,
          license: { revocability: 'refund_window', revocation_window_days: windowDays },
        })
      }

      it('Stage-2-capable verifier, no revocationEvidence -> ignored with revocation_unlogged_deadline', () => {
        const payload = refundPayload(30, '2025-07-01T00:00:00Z')
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(
          payload, [parse(record)], parse(keyManifest), warnings, errors,
          undefined, [fakeLogKey], noHorizonPolicy, null,
        )
        expect(result).toBe('invalid_revocation_ignored')
        expect(warnings).toContain('revocation_unlogged_deadline')
      })

      it('verifier without logKeys/anchorPolicy at all -> v0.1 semantics unchanged (still revoked)', () => {
        const payload = refundPayload(30, '2025-07-01T00:00:00Z')
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
        expect(result).toBe('revoked')
        expect(warnings).toEqual([])
      })

      it('policy class unaffected: Stage-2-capable verifier, no revocationEvidence -> still revoked', () => {
        const payload = parse({
          issuer: { id: ISSUER },
          issued_at: '2025-07-01T00:00:00Z',
          receipt_id: RECEIPT_ID,
          license: { revocability: 'policy' },
        })
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-03T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(
          payload, [parse(record)], parse(keyManifest), warnings, errors,
          undefined, [fakeLogKey], noHorizonPolicy, null,
        )
        expect(result).toBe('revoked')
        expect(warnings).not.toContain('revocation_unlogged_deadline')
      })
    })
  })
})

describe('recordHash (G5)', () => {
  it('is SHA-256 of the record\'s canonical bytes, including the signature member', () => {
    const record = signRecord({ receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' }, kid1, seed1)
    const parsed = parse(record)
    // Independent SHA-256 via Node's crypto, not this module's own machinery.
    const digest = createHash('sha256').update(Buffer.from(canonicalBytes(parsed))).digest('hex')
    expect(recordHash(parsed)).toBe(digest)
    expect(recordHash(parsed)).toHaveLength(64)
  })

  it('changes when the signature member changes (commits to the WHOLE record)', () => {
    const recordA = signRecord({ receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' }, kid1, seed1)
    const recordB = signRecord({ receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' }, kidWrong, seedWrong)
    expect(recordHash(parse(recordA))).not.toBe(recordHash(parse(recordB)))
  })
})

// --------------------------------------------------------------------------
// I1/M1 (T5 fix wave, review round-1 findings): the revocation-evidence path
// (`classifyRevocation`'s `refund_window` deadline rule) dispatches through
// the SAME shared transparency evaluator the direct transparency path uses,
// with a GENUINE logged + OTS-anchored `revocation-record` entry (not just
// the engagement-gate unit tests above, which never supply evidence that
// resolves). The checkpoint below was generated ONCE by a companion Python
// one-off (`tlog.sign_checkpoint`, same provenance discipline as
// tlog.test.ts/transparency.test.ts's HK_A fixtures — TS ships no
// signing/building API) over a single-leaf tree whose one leaf is a
// `revocation-record` entry for RECEIPT_ID/kid1/seed1's `revokedRecord`
// shape (`{receipt_id: RECEIPT_ID, status: 'revoked', revoked_at:
// '2026-07-10T00:00:00Z'}`, signed by kid1/seed1 — reused here so the
// record itself is rebuilt with THIS file's own `signRecord`/`recordHash`,
// never hardcoded, and independently re-derives the exact root the
// checkpoint below was signed over).
describe('G5: revocation-evidence path dispatches through the shared evaluator (I1/M1)', () => {
  const REVOCATION_LOG_ORIGIN = 'revocation-log.attest.example/2026'
  const REVOCATION_LOG_NAME = 'attest-revocation-log-1'

  const REVOCATION_LOG_KEY: LogKey = {
    origin: REVOCATION_LOG_ORIGIN,
    name: REVOCATION_LOG_NAME,
    ed25519Pub: h('fcb48dec8c105c0091d8e001d443f6b974a5fd694390a233ca1590219790f46d'),
    mldsaPub: h(
      'eedd20b2f84f0a4a786f684c76e17ac0f9e7343b07d227547a216f00cfc8ca92861c5f7572785d0abf6129c192e838cd7112cefce8f15597920950b7a08dd67c2fbb5f9c8a9c0429eed49c4aa9b1842ef788aece8e49a40fb55faecbf17876d6013405a26341239fa10bc109951717666850018306b6a057f7a80973f9b873745cd658b2446e9e0fd806430c9722952a0aae17298ab4239b0d0b5f8e82215b9aaf8dc8ea308dc43415484ef94fc015760bb5536bf006c6e6fb0db32508c58722dcb3b2856e3b38ab6d122770fd84baae88323e97df1bfa0842f9cceeeb79b06941171df211295e9320f6c97c037c5517be7f38cc4bc11772b5791d8f281a1e272d709ab7d9fe36473e1accbc7486a905d0473de98fb0935e4400a2194cfa0f3d49f01c18ff1dc9f01d5fc24e8a2ba86fd8d175d0dc69a2fee59d045f189a87d59219181f2aa2edac7f292ec36cf7a3a30a50a17cc81bf4589d4063ae7b4e992f7703aed60160e58a1b8849e815fc876d2fef0393573c15f371cc67f31e5406f19e800afd90fb2ec2f6defdcac74d9dc726c85da6ca2a3564d321472add8521c39e130949ee90f9c8e7200639c2aa204c3d822d858bc7480cba4fa2640c8ad44f3398f02fb98843379cd51c00fb92e7541fb7777af5a36f1c5dc4493e77a7e14746d4578f9d31b1dd369ceac71fca043b7dd017b3e44439c619dfe7c995fe03333cc5b6b8fd9c0296caae30da37c95b1e1c0d35fcfdbf83293af00f8349a73adae1410ae559cada43b40770059d651c53f5661e709a0c5cf5efbe395564a4d731d9dfbb80114cf2127a57f0d8a1c6022ad14d4525de2d0d5c2b62c08704c27d908acb6a3238316f3df5ddddf7a5fe21c886f21be7b7329f76b3b186ed76c145fa4c0faff88742d09d4dc1b1c8ceb684a92b5098bf646c83e18bf603efdd381feb67b2ccb49be2b695131abc3a02c1f5155b1b9446861e6529a1173087b5f93185b135f9dc3c310fc6f28cbd5e1e49763c2eaf721aa0d540d42c749d720498ef6edeef5348389a5fd038fafc11e8d82cd0b14eb9ae8d0f4e5ba5e2906b02ac75f60bac0459c7bcd31ffd893f221e436fa9312ba4c6b881040f2b971a8158c7013d1bac3428059099dc3a79b8230e65da9f689041a3c526dc952a00d8b0587f29df1719c21c10cce5ec1b086b82d287ef505de9a0eb7c877cdaf6b1672fb7a0500d37520b552f16f1ca0cca7ea3c7ebfb7d6f788c12053ddab626a09680adb43ba44b933d000fbbb8b5feb5a83bbe9c9ac91b368adda31cf11e593cb367733c37a81fb6440e50212b95dce0dee6822a1b79bfee07012b41580ff1abafae9f79048f68c85ccdbafc45f4c9a1201f088dd4eabecee4d68d32ee6ef1a289c94c713922910ee1df05c7a1b0bb1ed5c141ee8cb8b0edcc80072307257c883f8e234e6d26355c1dc3ad146038fa06420442aa9a1ef1e46a60a817edafbac7881100ee48b73d9a20e167723f9d25ebb511c32bb1d0ec1029e9983f6a815bf4ec815fac761e4b5d922d6c1b1bac0669cb5e6257f9da348a8c5bc783d7955dbe165bb8c0fb4b10a008daecd0338daf5f989de3b7f71e44d7db5cf37ed08e470c6882533c0b857c0c282de6a4368dbb073e0b625d24a3e90b581dbe7254925e503fd578daadaf506e18bcfa36a3f5c124564c9b7b7379bf65789baac325c9184189594809282df5b77549828fe268cfe946e67632edf0a1ab35e5918251a003a694eaf5a3a1ebd6c9277ddec5133f2bd23afa46f1755d4c6842ab9ddaedca9f65b04af73d7240f07262ae957a4daf3099b9a778dfb0de93f121f59047a7230cf8bf1a98857a7ba9d7651178fd5ccfe582f40d59e6c81f20694e94c426cb1d6e16daf859c2a7f281bf039efb6a61931ca5472ec8921ec04a9a2d2da04776a25deba0f654449d084c69d499f71147dd07119f8dbb75dac797eff501fa31270ca7c6b45460f62b2e10bb47ce89e5c2e59cf9de0d930fd76bd500215fadc0c5cc16fd543f83a76d820e922f3842c3aadd9f21fc7fd9dc427e508650d1ddffaeb46635e2f1b0bc11df3dea856fa19998a7ae93e597d6fa38d46676b1eb0c1342d8eee57deb83d6621c6b4a9f2edcb6efb44b6bd5ace99cb3b024ecb7c1838478656a7ad6df8ddfb5bbc7e7206a94c86ddcfd651c5eb42400a6316affc4c5fc81e4163605d2afc0debd544c985fc89f9df9cfe480b758e957c979cdd83697fb0ab01e3e126ddcd8306414129b1af8c61b5f6c491fa699141d4f80e77bb0d740f0b45d67d58b014c3bfcc7346b0166920c79c5f8d95ba29f3558065acb406f5553e62c86edee61ca9b5a0a35ab0ecf0a234bdcdb71658a6002da3ecdb7c8e207124b91fab8f1044667971389078a1cb3dc2d00a5342a491e9244a492bb565bc623141a4453231163e93a8c11c319dec365cc3008ccfdd7226f791b21a301ae485251e5e3926af6f5f21dd897f04cd8d7af9faa9208ee6ed5e7842a2681797d98ede97fc1bf6869009551f96a4cd798abf6a82dfab760e50f9a0b8683e4dd810e6dde1af9d510f7803b4d1337eb7369f8278b6b408daf57cee963fff76872deed48e44980eb991be28b71068b261400bc475fb6d72d1df5a676a93e922403738386877adccc839e6d0166be6b5756195570eff7d4e460f40ef4d2f83aec7723a7bf6094290db40d5428b839e41dd8bbb436acf2e8825cd93f3f3e1141f5f984e4ca6ca5bd54aaef360410',
    ),
  }

  // Generated once by the companion Python one-off; committed here as
  // cross-language ground truth (see the module comment above).
  const CHECKPOINT_TEXT =
    'revocation-log.attest.example/2026\n' +
    '1\n' +
    'knpJ/bbI6gw2XgCLrGcamJpDmx+FEm2pCi5huzWKkQE=\n' +
    '\n' +
    '— attest-revocation-log-1 h3fC9HbZJHOzC70Lh2KDtfL+gjebcj/4QZ8JAgMqlOnRAceOAtilqwV8/1s/pto3VSNQpkEzRa9Wo0m6HVAZmX7Q/Qw=\n' +
    '— attest-revocation-log-1 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\n'

  const RECORD = signRecord(
    { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2026-07-10T00:00:00Z' },
    kid1,
    seed1,
  )

  function refundPayload(windowDays: number, issuedAt: string): JsonObject {
    return parse({
      issuer: { id: ISSUER },
      issued_at: issuedAt,
      receipt_id: RECEIPT_ID,
      license: { revocability: 'refund_window', revocation_window_days: windowDays },
    })
  }

  // Single-`["sha256"]`-op OTS anchor, mirroring `tools/gen_vectors.py`'s
  // `_single_hash_ots_proof`/group 33's own `_revocation_evidence`.
  function otsEvidence(
    headerTimeSec: number,
    anchorProfile?: 'signed-note-v2',
  ): { evidence: JsonObject; policy: AnchorPolicy } {
    const checkpoint = parseCheckpoint(CHECKPOINT_TEXT)
    const commitment = anchorProfile === 'signed-note-v2' ? checkpoint.signedNoteBytes : checkpoint.noteBytes
    const headerHash = bytesHex(sha256(new TextEncoder().encode(`ts-revocation-header-${headerTimeSec}`)))
    const accumulatorStart = sha256(commitment)
    const headerMerkleRoot = bytesHex(sha256(accumulatorStart))
    const anchors: Record<string, unknown> = {
      checkpoint: CHECKPOINT_TEXT,
      proofs: [
        {
          kind: 'ots',
          ops: [['sha256']],
          header_merkle_root: headerMerkleRoot,
          header_hash: headerHash,
          header_time: headerTimeSec,
        },
      ],
    }
    if (anchorProfile !== undefined) anchors['anchor_profile'] = anchorProfile
    const record = parse(RECORD)
    const entry = {
      type: 'revocation-record',
      issuer: ISSUER,
      record_sha256: recordHash(record),
    }
    const evidence = {
      entry,
      leaf_index: 0,
      tree_size: 1,
      inclusion_proof: [],
      checkpoint: CHECKPOINT_TEXT,
      anchors,
    }
    const policy: AnchorPolicy = {
      pinnedHeaders: { [headerHash]: { headerHash, merkleRoot: headerMerkleRoot, time: headerTimeSec } },
      crqcHorizon: null,
    }
    // `revocationDeadlineSatisfied` re-canonicalizes the evidence via
    // `dumps`/`canon.ts`, which only accepts `bigint` for numbers (never a
    // plain JS `number`, mirroring Python's own int/JSON discipline) — MUST
    // go through `parse()` (`loadsStrict`) exactly like every other fixture
    // in this file, or the untrusted-evidence boundary throws and the
    // deadline rule fails closed silently (no warning at all).
    return { evidence: parse(evidence), policy }
  }

  function bytesHex(bytes: Uint8Array): string {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  }

  it('I1(a)/(c): legacy-profiled revocation evidence is honored but yields anchor_note_only (RED-then-fixed: verify()/classifyRevocation must not discard the evaluator warnings)', () => {
    const payload = refundPayload(14, '2026-06-26T00:00:00Z') // deadline 2026-07-10T00:00:00Z
    const { evidence, policy } = otsEvidence(1783641600) // == deadline, legacy (note-v1) profile
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(
      payload, [parse(RECORD)], parse(keyManifest), warnings, errors,
      undefined, [REVOCATION_LOG_KEY], policy, evidence,
    )
    expect(result).toBe('revoked')
    expect(warnings).toContain('anchor_note_only')
  })

  it('I1(c): v2-profiled revocation evidence verifies under the v2 seed without the note-only warning', () => {
    const payload = refundPayload(14, '2026-06-26T00:00:00Z') // deadline 2026-07-10T00:00:00Z
    const { evidence, policy } = otsEvidence(1783641600, 'signed-note-v2') // == deadline
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(
      payload, [parse(RECORD)], parse(keyManifest), warnings, errors,
      undefined, [REVOCATION_LOG_KEY], policy, evidence,
    )
    expect(result).toBe('revoked')
    expect(warnings).not.toContain('anchor_note_only')
  })

  it('M1: anchored_before == deadline EXACTLY is timely (honored)', () => {
    const payload = refundPayload(14, '2026-06-26T00:00:00Z') // deadline 2026-07-10T00:00:00Z
    const { evidence, policy } = otsEvidence(1783641600, 'signed-note-v2') // == deadline, to the second
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(
      payload, [parse(RECORD)], parse(keyManifest), warnings, errors,
      undefined, [REVOCATION_LOG_KEY], policy, evidence,
    )
    expect(result).toBe('revoked')
    expect(warnings).not.toContain('revocation_unlogged_deadline')
  })

  it('M1: deadline + 1s is late (ignored+warning) — a regression from <= to < must turn this red', () => {
    const payload = refundPayload(14, '2026-06-26T00:00:00Z') // deadline 2026-07-10T00:00:00Z
    const { evidence, policy } = otsEvidence(1783641601, 'signed-note-v2') // one second late
    const warnings: string[] = []
    const errors: string[] = []
    const result = classifyRevocation(
      payload, [parse(RECORD)], parse(keyManifest), warnings, errors,
      undefined, [REVOCATION_LOG_KEY], policy, evidence,
    )
    expect(result).toBe('invalid_revocation_ignored')
    expect(warnings).toContain('revocation_unlogged_deadline')
  })
})
