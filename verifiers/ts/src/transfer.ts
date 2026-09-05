// Transfer records — issuer-mediated transfer, holder-authorized (v0.2 §17).
// Mirrors src/attest/transfer.py (Python reference), VERIFICATION-SIDE ONLY
// (design §9: no build/sign here — a transfer record is built/signed only by
// the reference implementation's own CLI tooling).
//
// A transfer record is an issuer-signed side-document, structurally
// analogous to a revocation record (revocation.ts): it carries a closed set
// of fields, including an OUTGOING holder's Ed25519 authorization (over a
// domain-separated preimage, authorizationMessage) and the ISSUER's own
// signature over canonicalBytes(record) with `signature` removed — signed
// exactly like every other v0.2 side-document (hybrid AND-rule via
// manifests.ts's verifySignatureBlock, §13).
//
// This module checks a holder's authorization signature in isolation, checks
// a record's own issuer-signature self-consistency against an issuer's key
// manifest, and evaluates whether a record has proven `logged` (or better)
// standing in the issuer's transparency log. Old-receipt extinguishment,
// double-assignment, and not_transferable_before need the receipt PAYLOAD in
// hand (its buyer/license blocks) and belong to revocation.ts's
// classifyRevocation (§17.3/§17.7), which already owns the single-receipt
// revocation-by-class dispatch (mirrors verify.py's structural note that
// this belongs to the one module with the full single-receipt pipeline —
// classifyRevocation is that module here, not verify.ts). Chain-of-title
// auditing (§17.5, auditChain below) lives here instead: it is a separate
// audit surface over a whole SEQUENCE of receipts, needs none of that
// single-receipt pipeline, and composes only this module's own primitives
// plus revocation.ts's verifyRecordSignature.
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import type { JsonObject, JsonValue } from './canon.js'
import { canonicalBytes, dumps, CanonError, MAX_ADMISSION_BYTES, materializeArray } from './canon.js'
import { verifyKeyManifest, findKey, verifySignatureBlock } from './manifests.js'
import {
  verifyRecordSignature as verifyRevocationRecordSignature,
  MAX_REVOCATION_RECORDS,
} from './revocation.js'
import { parseStrictUtc, parseIsoLenient, validStage3UtcTimestamp } from './dates.js'
import { b64uDecode, b64uEncode } from './b64u.js'
import { verifyStrict } from './ed25519.js'
import type { LogKey } from './tlog.js'
import { encodeEntry, TlogError } from './tlog.js'
import type { AnchorPolicy } from './anchor.js'
import { evaluateTransparency, validateLogKeys, validatePolicy, TransparencyError, TRANSPARENCY_LOGGED } from './transparency.js'
import { pyRepr, codePointLength } from './messages.js'

function isObject(v: JsonValue | undefined): v is JsonObject {
  return v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v)
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

// Fixed literal (v0.2 §17.1, verbatim) — the domain-separation label for the
// holder-authorization preimage. Never changes without a protocol version bump.
export const LABEL_TRANSFER_AUTHORIZATION = new TextEncoder().encode('Attest-transfer-authorization-v1')

// Fixed literal (v0.2 §8/§17.1) — the fourth transparency-log entry type.
const LOG_ENTRY_TYPE = 'transfer-record'

const RECEIPT_ID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/

const TRANSFER_RECORD_MEMBERS = new Set([
  'receipt_id', 'new_receipt_id', 'new_holder_pubkey', 'transferred_at', 'holder_authorization', 'signature',
])

// Ed25519 signature: 64 raw bytes, base64url-no-pad encodes to exactly 86
// characters (ceil(64/3)*4 - 2 stripped padding chars). holder_authorization
// carries exactly one member, `sig`, at exactly this length — anything else
// is a malformed shape, checked before any cryptographic work.
const HOLDER_AUTH_SIG_B64U_LEN = 86

// Bounds the untrusted evidence bundle's canonicalized size before it is ever
// parsed. Bound to the leaf module's own ceiling rather than restated: this
// module cannot import verify.ts without an import cycle, and a size ceiling
// written in three places is a ceiling that will drift. Python parity:
// transfer.py's _MAX_TRANSFER_EVIDENCE_LEN.
const MAX_TRANSFER_EVIDENCE_LEN = MAX_ADMISSION_BYTES

// A transfer view is a list of claims, and admitting it PER CLAIM needs a count
// bound of its own -- the whole-view byte cap it used to rely on is gone with
// the whole-view materialization. Exported because the module that ADMITS the
// rail (revocation.ts) is not the module that owns it, and the two must not be
// able to drift apart on the number. Python parity: transfer.MAX_TRANSFER_CLAIMS.
export const MAX_TRANSFER_CLAIMS = 64

// Same literal VALUE as transparency.ts renders dynamically for
// "anchored_before:<T>" standing (never a fixed enum member there).
const ANCHORED_BEFORE_PREFIX = 'anchored_before:'

/** Return `value` decoded iff it canonical-base64url-decodes to exactly
 * `expectedLength` bytes AND its own canonical re-encoding round-trips back
 * to `value` — never throws. Mirrors transfer.py's `_strict_b64u_decode`. */
function strictB64uDecode(value: unknown, expectedLength: number): Uint8Array | null {
  if (typeof value !== 'string') return null
  let decoded: Uint8Array
  try {
    decoded = b64uDecode(value)
  } catch {
    return null
  }
  if (decoded.length !== expectedLength) return null
  if (b64uEncode(decoded) !== value) return null
  return decoded
}

/** The domain-separated holder-authorization preimage (v0.2 §17.1, normative,
 * verbatim):
 *
 * `UTF8("Attest-transfer-authorization-v1") || 0x00 || UTF8(receiptId) ||
 * 0x00 || UTF8(newHolderPubkey) || 0x00 || UTF8(transferredAt)`
 *
 * Each component is its wire TEXT form encoded as UTF-8 (not decoded/
 * re-encoded) — `receiptId`/`transferredAt` as the literal strings carried
 * in the record, `newHolderPubkey` as its base64url text — mirroring v0.1
 * §8.2's receipt_id-encoding discipline exactly. Binding all three together
 * makes the authorization non-replayable against a different old receipt, a
 * different incoming key, or a different signed time.
 */
export function authorizationMessage(receiptId: string, newHolderPubkey: string, transferredAt: string): Uint8Array {
  const enc = new TextEncoder()
  const parts = [
    LABEL_TRANSFER_AUTHORIZATION,
    Uint8Array.of(0x00),
    enc.encode(receiptId),
    Uint8Array.of(0x00),
    enc.encode(newHolderPubkey),
    Uint8Array.of(0x00),
    enc.encode(transferredAt),
  ]
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

/** `holder_authorization` must be a dict with exactly one member, `sig`,
 * whose value is a well-formed base64url string decoding to exactly a
 * 64-byte Ed25519 signature. Fails closed on every other shape — never
 * throws. Mirrors transfer.py's `_valid_holder_authorization_shape`. */
function validHolderAuthorizationShape(value: JsonValue | undefined): boolean {
  if (!isObject(value)) return false
  const keys = Object.keys(value)
  if (keys.length !== 1 || keys[0] !== 'sig') return false
  const sig = value['sig']
  return typeof sig === 'string' && sig.length === HOLDER_AUTH_SIG_B64U_LEN && strictB64uDecode(sig, 64) !== null
}

/** `SHA-256(JCS(record))`, rendered as 64 lowercase hex characters — the
 * ENTIRE signed record dict, INCLUDING its `signature` member. This is what
 * a transfer-record transparency-log entry commits to (v0.2 §8/§17.1).
 * Mirrors revocation.ts's recordHash exactly. */
export function recordHash(record: JsonObject): string {
  return bytesToHex(sha256(canonicalBytes(record)))
}

/** Verify `record`'s own signature against an ALREADY self-verified
 * `keyManifest`. Exactly `verifyRecord` minus the `verifyKeyManifest`
 * self-consistency check: the signer key must be **active** in
 * `keyManifest`, with its `[valid_from, valid_to]` window covering the
 * record's own signed `transferred_at`, and the signature must verify
 * against that key's `pub` — mirrors revocation.ts's verifyRecordSignature
 * line-for-line. PLUS a shape-check unique to transfer records:
 * `holder_authorization` must be `validHolderAuthorizationShape` (v0.2
 * §17.1's closed six-field object). Fails closed on every malformed/
 * wrong-typed/unsigned/out-of-window input — never throws.
 *
 * AND rule (v0.2 §13, mirrors manifests.ts's verifySignatureBlock): if the
 * signer's keyManifest entry is hybrid (carries pub_ml_dsa_65), `signature`
 * MUST also carry a valid sig_ml_dsa_65 leg over the same signed bytes, or
 * verification fails closed; an Ed25519-only entry with a stray
 * sig_ml_dsa_65 leg likewise fails closed. Ed25519-only signers keep v0.1
 * behavior byte-for-byte.
 *
 * PRECONDITION: the caller has already established `verifyKeyManifest
 * (keyManifest)` is true. Callers checking many records against ONE
 * manifest hoist that call out of their loop. To verify a single record,
 * use `verifyRecord`, which composes both halves.
 */
export function verifyRecordSignature(record: JsonObject, keyManifest: JsonObject): boolean {
  try {
    const keys = Object.keys(record)
    if (keys.length !== TRANSFER_RECORD_MEMBERS.size || !keys.every((k) => TRANSFER_RECORD_MEMBERS.has(k))) return false
    const receiptId = record['receipt_id']
    const newReceiptId = record['new_receipt_id']
    const newHolderPubkey = record['new_holder_pubkey']
    const transferredAtValue = record['transferred_at']
    if (
      typeof receiptId !== 'string' || !RECEIPT_ID_RE.test(receiptId) ||
      typeof newReceiptId !== 'string' || !RECEIPT_ID_RE.test(newReceiptId) ||
      strictB64uDecode(newHolderPubkey, 32) === null ||
      !validStage3UtcTimestamp(transferredAtValue) ||
      !validHolderAuthorizationShape(record['holder_authorization'])
    ) {
      return false
    }
    const sigBlock = record['signature']
    if (!isObject(sigBlock)) return false
    const kid = sigBlock['kid']
    const entry = findKey(keyManifest, typeof kid === 'string' ? kid : '')
    if (!entry || entry['status'] !== 'active') return false
    const body: JsonObject = Object.create(null)
    for (const k of Object.keys(record)) if (k !== 'signature') body[k] = record[k]!
    const transferredAtMs = parseStrictUtc(transferredAtValue)!
    const fromMs = parseStrictUtc(entry['valid_from'])
    if (fromMs === null || transferredAtMs < fromMs) return false
    const to = entry['valid_to']
    if (to !== null && to !== undefined) {
      const toMs = parseStrictUtc(to)
      if (toMs === null || transferredAtMs > toMs) return false
    }
    return verifySignatureBlock(canonicalBytes(body), sigBlock, entry)
  } catch {
    return false
  }
}

/** Verify against `keyManifest`, mirroring revocation.ts's verifyRecord
 * exactly: the signer key must be **active** in a self-consistent
 * `keyManifest`, with its `[valid_from, valid_to]` window covering the
 * record's own signed `transferred_at`, and the signature must verify.
 * Fails closed on every malformed/wrong-typed/unsigned/out-of-window input
 * — never throws. Composes `verifyKeyManifest` + `verifyRecordSignature`;
 * loop-over-records callers hoist the former.
 */
export function verifyRecord(record: JsonObject, keyManifest: JsonObject): boolean {
  try {
    return verifyKeyManifest(keyManifest) && verifyRecordSignature(record, keyManifest)
  } catch {
    return false
  }
}

/** Verify the OUTGOING holder's own authorization signature in isolation
 * from the issuer's signature: does `record.holder_authorization.sig`
 * verify over `authorizationMessage(...)` (rebuilt from the record's own
 * receipt_id/new_holder_pubkey/transferred_at) against `holderPubkeyB64u` —
 * the OLD receipt's own buyer.pubkey, read by the caller, never by this
 * function.
 *
 * Fails closed (never throws) on every malformed input: a missing or
 * wrong-typed field, a non-b64u pubkey/signature, or a genuinely wrong
 * signature all return false.
 */
export function verifyAuthorization(record: JsonObject, holderPubkeyB64u: string): boolean {
  try {
    const receiptId = record['receipt_id']
    const newHolderPubkey = record['new_holder_pubkey']
    const transferredAt = record['transferred_at']
    if (typeof receiptId !== 'string' || typeof newHolderPubkey !== 'string' || typeof transferredAt !== 'string') {
      return false
    }
    const sigBlock = record['holder_authorization']
    if (!validHolderAuthorizationShape(sigBlock)) return false
    const sig = strictB64uDecode((sigBlock as JsonObject)['sig'], 64)
    if (sig === null) return false
    let holderPub: Uint8Array
    try {
      holderPub = b64uDecode(holderPubkeyB64u)
    } catch {
      return false
    }
    const message = authorizationMessage(receiptId, newHolderPubkey, transferredAt)
    return verifyStrict(message, sig, holderPub)
  } catch {
    return false
  }
}

/** The single pinned origin shared by every entry in `logKeys` — TRUSTED
 * verifier configuration, never derived from untrusted evidence. Duplicated
 * locally (mirrors revocation.ts's own private `resolveLogOrigin`) to avoid
 * an import cycle. Malformed or disagreeing/empty origins are a
 * caller/config bug and throw TransparencyError. */
function resolveLogOrigin(logKeys: LogKey[]): string {
  const validated = validateLogKeys(logKeys)
  const origins = new Set(validated.map((key) => key.origin))
  if (origins.size !== 1) {
    throw new TransparencyError(`log_keys must be a non-empty list sharing a single origin, got ${pyRepr([...origins].sort())}`)
  }
  return [...origins][0]!
}

/** The record's own proven `leaf_index` iff `evidence` proves its
 * transfer-record log entry reached `logged` standing or better (`"logged"`
 * or `"anchored_before:..."`), else `null` — mirrors verify.ts's untrusted-
 * evidence confinement exactly (§17.2's log-required honoring, D2).
 *
 * `evidence` is untrusted: canonicalized and re-parsed once via `dumps`/
 * `JSON.parse` (bounded by MAX_TRANSFER_EVIDENCE_LEN) so every later phase
 * sees one ordinary JSON object, never a stateful/hostile mapping.
 * `record`/`issuerId` feed the EXPECTED entry `{type: "transfer-record",
 * issuer: issuerId, record_sha256: recordHash(record)}`, computed locally
 * and never read off `evidence` — a malformed `record`/`issuerId` degrades
 * to `null`.
 *
 * `logKeys`/`anchorPolicy` ARE the trusted, verifier-config side of the
 * call: malformed ones throw TransparencyError (a config bug). Every
 * warning the shared evaluator returns is appended to `warnings` (dedup
 * against identical strings already present) when `warnings` is provided,
 * regardless of whether standing is ultimately reached.
 */
export function recordLoggedStanding(
  record: JsonObject,
  evidence: JsonValue | null,
  issuerId: string,
  logKeys: LogKey[],
  anchorPolicy: AnchorPolicy,
  warnings?: string[],
): number | null {
  if (evidence == null) return null

  const origin = resolveLogOrigin(logKeys)
  validatePolicy(anchorPolicy)

  let materialized: unknown
  try {
    const serialized = dumps(evidence)
    if (codePointLength(serialized) > MAX_TRANSFER_EVIDENCE_LEN) return null
    materialized = JSON.parse(serialized)
    if (!isPlainRecord(materialized)) return null
  } catch {
    // Adversarial-boundary confinement (never rethrow): a hostile evidence
    // mapping's own property getters must not escape as a bare exception.
    return null
  }

  let recordSha256: string
  try {
    recordSha256 = recordHash(record)
  } catch (e) {
    if (e instanceof CanonError) return null
    throw e
  }

  const candidateEntry = { type: LOG_ENTRY_TYPE, issuer: issuerId, record_sha256: recordSha256 }
  try {
    encodeEntry(candidateEntry)
  } catch (e) {
    if (e instanceof TlogError) return null
    throw e
  }

  const result = evaluateTransparency(materialized, {
    logKeys, expectedOrigin: origin, policy: anchorPolicy, expectedEntry: candidateEntry,
  })
  if (warnings) {
    for (const warning of result.warnings) if (!warnings.includes(warning)) warnings.push(warning)
  }

  const reachedStanding = result.transparency === TRANSPARENCY_LOGGED || result.transparency.startsWith(ANCHORED_BEFORE_PREFIX)
  if (!reachedStanding) return null

  const leafIndex = (materialized as JsonObject)['leaf_index']
  if (typeof leafIndex !== 'number' || !Number.isInteger(leafIndex) || leafIndex < 0) return null
  return leafIndex
}

// --- auditChain (v0.2 §17.5): chain-of-title, a separate audit surface -----

// Fixed literal (mirrors verify.ts's REVOCATION_TRANSFERRED — the record's
// own `status` field value a backing revocation record must carry).
const RECORD_STATUS_TRANSFERRED = 'transferred'

// Chain-audit error literals (v0.2 §17.5, verbatim; `i` = 1-based link
// ordinal; identical strings in Python — verify.py/transfer.py).
const errNoTransferRecord = (i: number) => `chain link ${i}: no transfer record`
const errIssuerSignatureInvalid = (i: number) => `chain link ${i}: issuer signature invalid`
const errHolderAuthorizationInvalid = (i: number) => `chain link ${i}: holder authorization invalid`
const errTransferRecordNotLogged = (i: number) => `chain link ${i}: transfer record not logged`
const errNotTransferableBefore = (i: number) => `chain link ${i}: transferred before not_transferable_before`
const errLosingBranch = (i: number) => `chain link ${i}: losing branch of a double assignment`
const errLoopClosure = (i: number) => `chain link ${i}: new receipt buyer.pubkey != new_holder_pubkey`
const errMissingBackedRevocation = (i: number) =>
  `chain link ${i}: previous receipt lacks a backed transferred-class revocation`

/** v0.2 §17.5: chain-of-title audit — a SEPARATE surface from standard
 * single-receipt verify() (a receipt verifies standalone; §17.1's
 * loop-closure paragraph). `linkStatus`/errors are ordered link-by-link,
 * 1-based in the error text, `linkStatus[k]` describing the transfer from
 * `payloads[k]` to `payloads[k + 1]`. */
export interface ChainAuditResult {
  valid: boolean
  linkStatus: readonly string[]
  errors: readonly string[]
  warnings: readonly string[]
}

function asObject(v: JsonValue | undefined): JsonObject | null {
  return v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

/** Walk `payloads` (each receipt's own PAYLOAD dict — `receipt_id` and
 * `buyer.pubkey` are all this reads) as a chain of title, validating each
 * consecutive link `payloads[i - 1] -> payloads[i]` (1-based `i` in the
 * error text) against `transferView` (`{record, evidence}` claims, the same
 * untrusted shape verify()'s `transferView` option takes) and
 * `revocationView` (ordinary revocation records).
 *
 * `verifyKeyManifest(keyManifest)` is hoisted once: if the manifest is not
 * self-consistent, NOTHING it would sign can be trusted, so every link is
 * immediately "invalid" with only the issuer-signature literal, and no
 * other check runs.
 *
 * Otherwise, per link, in this exact order (deterministic multi-error
 * output — later checks for the SAME link still run after an earlier one
 * fails):
 *
 * 1. select the transfer-view claim whose `record.receipt_id ==
 *    payloads[i - 1].receipt_id` and `record.new_receipt_id ==
 *    payloads[i].receipt_id` — none found -> errNoTransferRecord, and
 *    checks 2-7 below are skipped entirely; check 8 still runs
 *    independently.
 * 2. `verifyRecordSignature(record, keyManifest)` -> issuer signature.
 * 3. `verifyAuthorization(record, payloads[i - 1].buyer.pubkey)` -> holder
 *    authorization, against the PREVIOUS receipt's own key.
 * 4. `recordLoggedStanding(...)` -> log inclusion.
 * 5. When the previous receipt has `license.not_transferable_before`: both
 *    it and `record.transferred_at` must be strict Stage-3 UTC timestamps,
 *    and the transfer time must not be earlier than the floor.
 * 6. Only once 2-5 all succeeded: among every OTHER transfer-view claim
 *    that is ALSO established (issuer sig + holder auth + logged + floor)
 *    for the SAME previous receipt_id, the selected record must hold the
 *    smallest log index -> losing branch of a double assignment.
 * 7. `record.new_holder_pubkey == payloads[i].buyer.pubkey` -> pubkey loop
 *    closure on the NEXT receipt.
 * 8. (independent of the transfer record) an authenticated `status ==
 *    "transferred"` revocation record for `payloads[i - 1]`'s receipt_id
 *    exists in `revocationView` -> the previous receipt's own backed
 *    extinguishment.
 *
 * A link is "valid" iff every applicable check above passed; `valid` is
 * true iff every link is.
 */
/**
 * Admit one caller-supplied array rail PER ELEMENT (§18.4), never raising.
 *
 * §18.4 leaves the declared CONTAINER shape to the rail, and both rails this
 * audit surface takes are arrays: a value that is not one carries no claim and
 * no record, so the audit degrades to "nothing here" rather than answering a
 * malformed view with an exception. Over the ceiling is not "one bad element":
 * it truncates evaluation, and a truncated view cannot be told apart from an
 * empty one, so both rails fail CLOSED in the same direction -- with no claim a
 * link has no transfer record, with no record the predecessor has no backed
 * extinguishment. Neither silence can make a link VALID.
 */
function admitCallerRail(view: unknown, ceiling: number): (JsonValue | null)[] {
  const admitted = materializeArray(view, ceiling)
  if (admitted === null || admitted.length > ceiling) return []
  return admitted
}

export function auditChain(
  payloads: JsonObject[],
  transferView: JsonValue[],
  revocationView: JsonValue[],
  keyManifest: JsonObject,
  logKeys: LogKey[],
  anchorPolicy: AnchorPolicy,
): ChainAuditResult {
  const linkCount = Math.max(payloads.length - 1, 0)

  if (!verifyKeyManifest(keyManifest)) {
    return {
      valid: linkCount === 0,
      linkStatus: Array.from({ length: linkCount }, () => 'invalid'),
      errors: Array.from({ length: linkCount }, (_, idx) => errIssuerSignatureInvalid(idx + 1)),
      warnings: [],
    }
  }

  // §18.4: this is a SECOND public entry point for the same two caller rails
  // verify() admits, so it admits them the same way and at the same moment --
  // once, per unit, before anything reads them -- and from here on ONLY the
  // reconstruction is read. Without it the successor id a signature COVERS and
  // the successor id a link is MATCHED against could differ, and a chain of
  // title nobody authorized would be reported valid. Python parity:
  // transfer._admit_caller_rail.
  //
  // AFTER the manifest self-verify, never before: that check is cheap and
  // refuses everything the manifest would sign, while admitting the rails
  // canonicalizes and re-parses up to 64 claims and 10000 records. Nothing
  // between the two reads a view, so the order is free.
  const admittedTransferView = admitCallerRail(transferView, MAX_TRANSFER_CLAIMS)
  const admittedRevocationView = admitCallerRail(revocationView, MAX_REVOCATION_RECORDS)

  const manifestIssuer = keyManifest['issuer']
  const issuerIdForLog = typeof manifestIssuer === 'string' ? manifestIssuer : ''

  const errors: string[] = []
  const warnings: string[] = []
  const linkStatus: string[] = []

  for (let i = 1; i <= linkCount; i++) {
    const prevPayload = payloads[i - 1]!
    const nextPayload = payloads[i]!
    const prevReceiptId = prevPayload['receipt_id']
    const nextReceiptId = nextPayload['receipt_id']
    const prevBuyer = asObject(prevPayload['buyer'])
    const prevPubkey = prevBuyer ? prevBuyer['pubkey'] : undefined
    let linkOk = true

    let selectedClaim: JsonObject | null = null
    for (const claim of admittedTransferView) {
      const c = asObject(claim)
      if (!c) continue
      const candidateRecord = asObject(c['record'])
      if (candidateRecord && candidateRecord['receipt_id'] === prevReceiptId && candidateRecord['new_receipt_id'] === nextReceiptId) {
        selectedClaim = c
        break
      }
    }

    const record = selectedClaim ? asObject(selectedClaim['record']) : null
    if (!record) {
      errors.push(errNoTransferRecord(i))
      linkOk = false
    } else {
      const sigOk = verifyRecordSignature(record, keyManifest)
      if (!sigOk) {
        errors.push(errIssuerSignatureInvalid(i))
        linkOk = false
      }

      const authOk = typeof prevPubkey === 'string' && verifyAuthorization(record, prevPubkey)
      if (!authOk) {
        errors.push(errHolderAuthorizationInvalid(i))
        linkOk = false
      }

      const evidence = (selectedClaim!['evidence'] ?? null) as JsonValue | null
      const leafIndex = recordLoggedStanding(record, evidence, issuerIdForLog, logKeys, anchorPolicy, warnings)
      if (leafIndex === null) {
        errors.push(errTransferRecordNotLogged(i))
        linkOk = false
      }

      const prevLicense = asObject(prevPayload['license'])
      const notTransferableBefore = prevLicense ? prevLicense['not_transferable_before'] : undefined
      const honorsFloor = (candidate: JsonObject): boolean => {
        if (notTransferableBefore === undefined || notTransferableBefore === null) return true
        const transferredAt = validStage3UtcTimestamp(candidate['transferred_at']) ? parseStrictUtc(candidate['transferred_at']) : null
        const floor = validStage3UtcTimestamp(notTransferableBefore) ? parseStrictUtc(notTransferableBefore) : null
        return transferredAt !== null && floor !== null && transferredAt >= floor
      }
      const floorOk = honorsFloor(record)
      if (!floorOk) {
        errors.push(errNotTransferableBefore(i))
        linkOk = false
      }

      if (sigOk && authOk && leafIndex !== null && floorOk) {
        const establishedLeafIndices = [leafIndex]
        for (const claim of admittedTransferView) {
          const c = asObject(claim)
          if (!c) continue
          const candidate = asObject(c['record'])
          if (!candidate || candidate === record || candidate['receipt_id'] !== prevReceiptId) continue
          if (!verifyRecordSignature(candidate, keyManifest)) continue
          if (!(typeof prevPubkey === 'string' && verifyAuthorization(candidate, prevPubkey))) continue
          const candidateEvidence = (c['evidence'] ?? null) as JsonValue | null
          const candidateLeafIndex = recordLoggedStanding(candidate, candidateEvidence, issuerIdForLog, logKeys, anchorPolicy, warnings)
          if (candidateLeafIndex !== null && honorsFloor(candidate)) establishedLeafIndices.push(candidateLeafIndex)
        }
        if (leafIndex !== Math.min(...establishedLeafIndices)) {
          errors.push(errLosingBranch(i))
          linkOk = false
        }
      }

      const nextBuyer = asObject(nextPayload['buyer'])
      const nextPubkey = nextBuyer ? nextBuyer['pubkey'] : undefined
      if (record['new_holder_pubkey'] !== nextPubkey) {
        errors.push(errLoopClosure(i))
        linkOk = false
      }
    }

    let backed = false
    for (const revRecord of admittedRevocationView) {
      const r = asObject(revRecord)
      if (
        r &&
        r['receipt_id'] === prevReceiptId &&
        r['status'] === RECORD_STATUS_TRANSFERRED &&
        verifyRevocationRecordSignature(r, keyManifest)
      ) {
        backed = true
        break
      }
    }
    if (!backed) {
      errors.push(errMissingBackedRevocation(i))
      linkOk = false
    }

    linkStatus.push(linkOk ? 'valid' : 'invalid')
  }

  return {
    valid: linkStatus.every((s) => s === 'valid'),
    linkStatus,
    errors,
    warnings,
  }
}
