import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import {
  JsonObject, JsonValue, canonicalBytes, dumps, loadsStrict, CanonError,
  materializeArray, materializeValue, ownArrayLength, ownViewMember,
  MAX_ADMISSION_NODES, VIEW_ARRAY_ELEMENT_NESTING, VIEW_MEMBER_ABSENT, VIEW_MEMBER_COLLAPSED,
} from './canon.js'
import { verifyKeyManifest, manifestSignatureIsAuthentic, findKey, verifySignatureBlock } from './manifests.js'
import { parseStrictUtc, parseIsoLenient, validStage3UtcTimestamp } from './dates.js'
import { LogKey, encodeEntry, TlogError } from './tlog.js'
import { AnchorPolicy, validatePolicy } from './anchor.js'
import { evaluateTransparency, validateLogKeys, TransparencyError } from './transparency.js'
import {
  verifyRecordSignature as verifyTransferRecordSignature,
  verifyAuthorization as verifyTransferAuthorization,
  recordLoggedStanding as transferRecordLoggedStanding,
  MAX_TRANSFER_CLAIMS,
} from './transfer.js'
import {
  revocationFailedVerify, outsideRefundWindow, revocationViewOversize, revocationViewOversizeRevocable,
  WARN, VERIFY_TRANSPARENCY_WARN, TRANSFER_WARN, pyRepr, codePointLength,
} from './messages.js'

function asObject(v: JsonValue | undefined): JsonObject | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

function signableRecordBytes(record: JsonObject): Uint8Array {
  const body: JsonObject = Object.create(null)
  for (const k of Object.keys(record)) if (k !== 'signature') body[k] = record[k]!
  return canonicalBytes(body)
}

// G5 (v0.2 §8, TM-47): `SHA-256(JCS(record))` over the ENTIRE signed record
// (including its `signature` member, unlike `signableRecordBytes` above,
// which excludes it to check the signature itself) — what a
// `revocation-record` transparency-log entry commits to. Python parity:
// `revocation.record_hash`.
export function recordHash(record: JsonObject): string {
  return bytesToHex(sha256(canonicalBytes(record)))
}

// PRECONDITION: caller already established verifyKeyManifest(keyManifest) is
// true. Loop-over-records callers hoist that call — one manifest self-verify
// per classification, not per record (review improvement #17). To verify a
// single record, use verifyRecord, which composes both halves.
//
// AND rule (v0.2, mirrors manifests.py's verify_record_signature): if the
// signer's keyManifest entry is hybrid (carries pub_ml_dsa_65), `signature`
// MUST also carry a valid sig_ml_dsa_65 leg over the same signed bytes, or
// verification fails closed; an Ed25519-only entry with a stray
// sig_ml_dsa_65 leg likewise fails closed (see verifySignatureBlock).
// Ed25519-only signers keep v0.1 behavior byte-for-byte (Stage 2 Task 6/8
// sibling-patch parity).
export function verifyRecordSignature(record: JsonObject, keyManifest: JsonObject): boolean {
  try {
    const sig = asObject(record['signature'])
    if (!sig || typeof sig['kid'] !== 'string') return false
    const entry = findKey(keyManifest, sig['kid'])
    if (!entry || entry['status'] !== 'active') return false // active only: retired/compromised reject
    const at = parseStrictUtc(record['revoked_at'])
    const from = parseStrictUtc(entry['valid_from'])
    if (at === null || from === null || at < from) return false
    const to = entry['valid_to']
    if (to !== null && to !== undefined) { const toMs = parseStrictUtc(to); if (toMs === null || at > toMs) return false }
    return verifySignatureBlock(signableRecordBytes(record), sig, entry)
  } catch { return false }
}

export function verifyRecord(record: JsonObject, keyManifest: JsonObject): boolean {
  try { return verifyKeyManifest(keyManifest) && verifyRecordSignature(record, keyManifest) } catch { return false }
}

function refundWindowEnd(payload: JsonObject): number | null {
  const license = asObject(payload['license'])
  if (!license) return null
  const days = license['revocation_window_days']
  if (typeof days !== 'bigint') return null // integer only; bool/float/string -> null
  const issued = parseStrictUtc(payload['issued_at'])
  if (issued === null) return null
  return issued + Number(days) * 86_400_000
}

// Preflight bound on the untrusted revocation view (review improvement #17):
// a legitimate view for one verify() call is an issuer's records for one
// receipt — realistically single digits; 10k is far above any legitimate case
// and keeps hostile worst-case work bounded. Mirrors Python's
// _MAX_REVOCATION_RECORDS.
export const MAX_REVOCATION_RECORDS = 10_000

const CLAIM_TYPE_REVOCATION_RECORD = 'revocation-record'
// Mirrors verify.py's `_MAX_TRANSPARENCY_EVIDENCE_LEN` — this is the SAME
// class of untrusted per-claim evidence bundle, just for a revocation
// record's claim instead of a receipt/key-manifest claim.
const MAX_REVOCATION_EVIDENCE_LEN = 10_000_000

/** The single pinned origin shared by every entry in `logKeys` — trusted
 * verifier config, never derived from untrusted evidence (mirrors
 * verify.ts's own private `resolveLogOrigin`, duplicated here rather than
 * imported to avoid a revocation.ts <-> verify.ts import cycle). */
function resolveLogOrigin(logKeys: LogKey[]): string {
  const validated = validateLogKeys(logKeys)
  const origins = new Set(validated.map((key) => key.origin))
  if (origins.size !== 1) {
    throw new TransparencyError(
      `log_keys must be a non-empty list sharing a single origin, got ${pyRepr([...origins].sort())}`,
    )
  }
  return [...origins][0]!
}

function validatedRevocationEntry(candidate: Record<string, unknown>): Record<string, unknown> | null {
  try { encodeEntry(candidate); return candidate } catch (e) { if (e instanceof TlogError) return null; throw e }
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** G5 (v0.2 §8/§15, TM-47): True iff at least one of `effective`'s
 * refund_window revocation records has Stage 2 evidence proving it was
 * logged AND anchored no later than `windowEndMs` (the SAME refund-window
 * deadline `refundWindowEnd`/the caller's own `within-window` filter already
 * compute). Only called once the caller has established the verifier is
 * Stage-2 capable (`logKeys`/`anchorPolicy` both supplied) and `effective`
 * is non-empty; `revocationEvidence` may still be absent or fail to
 * resolve, in which case this returns `false`. Every warning the shared
 * evaluator returns for a candidate record (e.g. `anchor_note_only`,
 * malformed-evidence reasons, `log_equivocation_detected`) is appended to
 * `warnings` (dedup against identical strings already present) regardless
 * of whether that record ends up timely — mirrors the direct transparency
 * path's own `warnings.push(...result.warnings)`. Python parity:
 * `verify._revocation_deadline_satisfied`. */
function revocationDeadlineSatisfied(
  effective: JsonObject[], revocationEvidence: JsonValue | null, issuerId: string | null,
  logKeys: LogKey[], anchorPolicy: AnchorPolicy, windowEndMs: number | null, warnings: string[],
): boolean {
  if (revocationEvidence == null || windowEndMs === null) return false

  const origin = resolveLogOrigin(logKeys)
  validatePolicy(anchorPolicy)

  let materialized: unknown
  try {
    const serialized = dumps(revocationEvidence)
    if (codePointLength(serialized) > MAX_REVOCATION_EVIDENCE_LEN) return false
    materialized = JSON.parse(serialized)
    if (!isPlainRecord(materialized)) return false
  } catch { return false }

  for (const record of effective) {
    let hash: string
    try { hash = recordHash(record) } catch (e) { if (e instanceof CanonError) continue; throw e }
    const expectedEntry = validatedRevocationEntry({
      type: CLAIM_TYPE_REVOCATION_RECORD, issuer: issuerId, record_sha256: hash,
    })
    if (expectedEntry === null) continue
    const result = evaluateTransparency(materialized as JsonObject, {
      logKeys, expectedOrigin: origin, policy: anchorPolicy, expectedEntry,
    })
    for (const warning of result.warnings) {
      if (!warnings.includes(warning)) warnings.push(warning)
    }
    if (!result.transparency.startsWith('anchored_before:')) continue
    const anchoredMs = parseIsoLenient(result.transparency.slice('anchored_before:'.length))
    if (anchoredMs === null) continue
    if (anchoredMs <= windowEndMs) return true
  }
  return false
}

// v0.2 Stage 3 (§17, issuer-mediated transfer): old-receipt extinguishment
// via a `status: "transferred"` revocation record, honored only when BACKED
// by an authenticated, log-included transfer record (§17.3's consent gate).
// The literal is deliberately reused for both the record's own `status`
// field and the reachable `revocation` result value — mirrors 'revoked''s
// existing dual use above. Python parity: verify.py's
// `_REVOCATION_TRANSFERRED`.
const REVOCATION_TRANSFERRED = 'transferred'

/** v0.2 §17.2-§17.4 (Stage 3): the winning, BACKED transfer record for
 * `payload`'s own `receipt_id` among `transferView`'s untrusted claims
 * (`{record: <transfer record>, evidence: <§10.2 evidence bundle>}`), or
 * `null` if no claim survives every gate below.
 *
 * `transferView`'s aggregate serialized size is bound and materialized up
 * front, so no caller-owned getter or proxy is consulted after the boundary.
 * `loadsStrict` preserves the verifier's bigint JSON representation while
 * materializing the canonical serialized form.
 *
 * Per claim, in this exact order (§17.3's consent gate plus §17.7/§17.2):
 *
 * 1. `record` is an object whose `receipt_id` equals `payload`'s own — else
 *    the claim is irrelevant to this receipt and is skipped silently.
 * 2. `transfer.verifyRecordSignature(record, issuerManifest)` — the
 *    issuer's own signature (hoisting `verifyKeyManifest` once here,
 *    mirroring `classifyRevocation`'s own hoisting of the same check). On
 *    failure: TRANSFER_WARN.REVOCATION_UNBACKED (deduplicated), skip.
 * 3. `payload.buyer.pubkey` is a non-null string AND
 *    `transfer.verifyAuthorization(record, pubkey)` — the OLD receipt's own
 *    holder consented. Same unbacked warning on failure, skip.
 * 4. If `payload.license.not_transferable_before` is present: both
 *    timestamps parse (fail-closed) and `record.transferred_at` is not
 *    earlier than it — else TRANSFER_WARN.NOT_YET_TRANSFERABLE, skip.
 * 5. Stage-2 capability (`logKeys` AND `anchorPolicy` both supplied) and
 *    `transfer.recordLoggedStanding(...)` proves this record's own
 *    transfer-record log entry reached at least `logged` standing — else
 *    TRANSFER_WARN.RECORD_UNLOGGED, skip.
 *
 * Survivors are `(leafIndex, record)` pairs; two or more is a double
 * assignment (§17.4) — TRANSFER_WARN.DOUBLE_ASSIGNMENT — and the EARLIEST
 * log index (first-logged) wins. Python parity:
 * `verify._resolve_transfer_backing`.
 */
function resolveTransferBacking(
  payload: JsonObject, transferView: JsonValue[], issuerManifest: JsonObject,
  issuerId: string | null, logKeys: LogKey[] | null, anchorPolicy: AnchorPolicy | null,
  warnings: string[],
): JsonObject | null {
  // Admitted PER CLAIM, not as one indivisible view: a claim that cannot be
  // represented is set aside ALONE, and a genuine claim with full backing still
  // reaches its verdict beside it. Admitting the view as a whole would let one
  // malformed sibling delete a real transfer -- a FALSE VALID, since the receipt
  // would read as never transferred. Python parity:
  // verify._resolve_transfer_backing.
  //
  // Admitting per claim gives up the aggregate byte cap the whole-view
  // materialization relied on, so the COUNT ceiling replaces it. Over the
  // ceiling is not "one bad claim": it truncates evaluation, and a truncated
  // transfer view cannot be told apart from a view with no transfer in it, so
  // it fails closed by resolving no backing at all.
  let materialized: (JsonValue | null)[]
  try {
    const admitted = materializeArray(transferView, MAX_TRANSFER_CLAIMS)
    if (admitted === null || admitted.length > MAX_TRANSFER_CLAIMS) return null
    materialized = admitted
  } catch {
    // Adversarial-boundary confinement (never rethrow), mirroring
    // revocationDeadlineSatisfied: a hostile transferView list/object's own
    // property getters must not escape as a bare exception.
    return null
  }

  const receiptId = payload['receipt_id']
  // The receipt gate's predicate, deliberately, not verifyKeyManifest: a
  // manifest downgraded by deleting its PQ leg loses its TRUST LEVEL,
  // never its power to revoke (v0.2 §4). The two must not disagree about
  // whether the same manifest is authentic — the gap turns a revocation
  // into silence, and reaching it costs one keyless deletion, since
  // manifest_signature sits outside the signed bytes. Python parity:
  // verify.py's _resolve_transfer_backing and _classify_revocation.
  const manifestOk = manifestSignatureIsAuthentic(issuerManifest)

  const appendOnce = (warning: string) => { if (!warnings.includes(warning)) warnings.push(warning) }

  const survivors = new Map<string, [number, JsonObject]>()
  for (const claim of materialized) {
    const c = asObject(claim)
    if (!c) continue
    const record = asObject(c['record'])
    if (!record || record['receipt_id'] !== receiptId) continue

    if (!manifestOk || !verifyTransferRecordSignature(record, issuerManifest)) {
      appendOnce(TRANSFER_WARN.REVOCATION_UNBACKED)
      continue
    }

    const buyer = asObject(payload['buyer'])
    const holderPubkey = buyer ? buyer['pubkey'] : undefined
    if (typeof holderPubkey !== 'string' || !verifyTransferAuthorization(record, holderPubkey)) {
      appendOnce(TRANSFER_WARN.REVOCATION_UNBACKED)
      continue
    }

    const license = asObject(payload['license'])
    const notTransferableBefore = license ? license['not_transferable_before'] : undefined
    if (notTransferableBefore !== undefined && notTransferableBefore !== null) {
      const transferredAt = validStage3UtcTimestamp(record['transferred_at']) ? parseStrictUtc(record['transferred_at']) : null
      const floor = validStage3UtcTimestamp(notTransferableBefore) ? parseStrictUtc(notTransferableBefore) : null
      const honored = transferredAt !== null && floor !== null && transferredAt >= floor
      if (!honored) {
        appendOnce(TRANSFER_WARN.NOT_YET_TRANSFERABLE)
        continue
      }
    }

    let leafIndex: number | null = null
    if (logKeys != null && anchorPolicy != null) {
      leafIndex = transferRecordLoggedStanding(
        record, (c['evidence'] ?? null) as JsonValue | null, issuerId ?? '', logKeys, anchorPolicy, warnings,
      )
    }
    if (leafIndex === null) {
      appendOnce(TRANSFER_WARN.RECORD_UNLOGGED)
      continue
    }

    const hash = recordHash(record)
    const previous = survivors.get(hash)
    if (previous === undefined || leafIndex < previous[0]) survivors.set(hash, [leafIndex, record])
  }

  if (survivors.size === 0) return null
  if (survivors.size > 1) appendOnce(TRANSFER_WARN.DOUBLE_ASSIGNMENT)
  return [...survivors.values()].reduce((best, cur) => (cur[0] < best[0] ? cur : best))[1]
}

export function classifyRevocation(
  payload: JsonObject, view: JsonValue[] | null, issuerManifest: JsonObject, warnings: string[],
  errors: string[], maxRecords: number = MAX_REVOCATION_RECORDS,
  logKeys: LogKey[] | null = null, anchorPolicy: AnchorPolicy | null = null,
  revocationEvidence: JsonValue | null = null, transferView: JsonValue[] | null = null,
): string {
  if (!view) return 'unknown'

  // The element COUNT comes from the array's own length data, never from
  // iterating: a lazy or unbounded container would otherwise run forever before
  // any ceiling could fire, and no catch is ever reached by a value that does
  // not return.
  const suppliedCount = ownArrayLength(view)
  if (suppliedCount === null) return 'unknown'
  if (suppliedCount === 0) return 'unknown'

  const license = asObject(payload['license'])
  const revocability = license ? license['revocability'] : undefined

  // Oversized view: not evaluated — never truncate, never throw. Fail CLOSED
  // for revocable receipts (error → ok=false): an untrusted view too large to
  // evaluate cannot rule out a revocation, and "unknown"+ok would let an
  // append-only feed-poisoning attacker suppress a genuine revocation by
  // padding past the cap. Irrevocable ("none") receipts fail closed too: the
  // branch was a non-fatal warning while "a revocation can never affect ok"
  // held, and v0.2 §17.3 ended that by extending the consent gate to ALL
  // revocability classes — a backed `status: "transferred"` record caps `ok`
  // for `none` as well, and rides this same view, so returning early on size
  // discarded it and let whoever appends to the view pick the transfer the
  // verifier never sees. Python parity: verify.py's same branch.
  if (suppliedCount > maxRecords) {
    if (revocability === 'policy' || revocability === 'refund_window') {
      errors.push(revocationViewOversizeRevocable(suppliedCount, maxRecords))
    } else {
      errors.push(revocationViewOversize(suppliedCount, maxRecords))
    }
    return 'unknown'
  }

  // §18.4: the caller's view is ADMITTED ONCE, per record, before anything
  // reads it -- and from here on ONLY the reconstruction is read. Two
  // properties depend on that being the first thing this function does, and
  // both are the reason the Python twin does it too:
  //
  //   * the three passes below correlate authentication with matching BY INDEX,
  //     which assumes every pass sees the SAME objects. A Proxy whose `get`
  //     trap answers with fresh objects satisfies every shape check and
  //     desynchronizes them, so a genuinely signed, matching record can be
  //     reported not_revoked. Reconstructed records are plain and stable, which
  //     closes it by construction rather than by a defensive read.
  //   * the bytes a signature is verified over and the values consumed
  //     afterwards must come from ONE reconstruction. Reading the live object a
  //     second time is what lets a caller authenticate one value and be judged
  //     on another, with the issuer's genuine signature.
  //
  // A record that cannot be represented lands as `null` and is set aside ALONE;
  // its admissibility decides no sibling's.
  const admittedView: (JsonValue | null)[] = materializeArray(view, maxRecords) ?? []

  const receiptIdForDiagnostics = payload['receipt_id']
  // A record that was NOT ADMITTED still has to be VISIBLE if it claims to be
  // about this receipt: §12.2 makes an unauthenticated matching record an
  // ignore WITH A WARNING, which is what stops a forged record from silently
  // disappearing, and an inadmissible record is less than unauthenticated. The
  // claim is read the only way the boundary allows -- the diagnostic member
  // alone, through the same own-data primitives, never the value that made the
  // record inadmissible -- and it decides NOTHING but the warning. It carries
  // its own budget so a record already set aside cannot buy unbounded work.
  const diagnosticBudget = { left: MAX_ADMISSION_NODES }
  for (let i = 0; i < admittedView.length; i++) {
    if (admittedView[i] !== null) continue
    let original: PropertyDescriptor | undefined
    try {
      original = Object.getOwnPropertyDescriptor(view, String(i))
    } catch {
      // Same rule as the diagnostic read below: a record already set aside must
      // not be able to throw out of the pass that only decides its warning.
      continue
    }
    if (original === undefined || !('value' in original)) continue
    const candidate: unknown = original.value
    if (candidate === null || typeof candidate !== 'object') continue
    const claimed = ownViewMember(candidate as object, 'receipt_id', diagnosticBudget)
    if (claimed === VIEW_MEMBER_ABSENT || claimed === VIEW_MEMBER_COLLAPSED) continue
    if (typeof claimed !== 'string') continue
    const admittedClaim = materializeValue(claimed, VIEW_ARRAY_ELEMENT_NESTING)
    if (admittedClaim === receiptIdForDiagnostics) {
      warnings.push(revocationFailedVerify(receiptIdForDiagnostics))
    }
  }

  // One manifest self-verify per classification, not per record (improvement #17).
  // The receipt gate's predicate, deliberately, not verifyKeyManifest: a
  // manifest downgraded by deleting its PQ leg loses its TRUST LEVEL,
  // never its power to revoke (v0.2 §4). The two must not disagree about
  // whether the same manifest is authentic — the gap turns a revocation
  // into silence, and reaching it costs one keyless deletion, since
  // manifest_signature sits outside the signed bytes. Python parity:
  // verify.py's _resolve_transfer_backing and _classify_revocation.
  const manifestOk = manifestSignatureIsAuthentic(issuerManifest)
  const auth: boolean[] = admittedView.map((r) => { const o = asObject(r); return manifestOk && o !== null && verifyRecordSignature(o, issuerManifest) })

  // freshness anchor T = max revoked_at over AUTHENTICATED STATEMENT-STATUS
  // records (status revoked/transferred, v0.1 §12.3 2026-08-26 amendment) of
  // ANY receipt_id. §12 already rules any other status is not a revocation
  // statement, so it must not speak for the feed's freshness either.
  let anchorMs = -Infinity, anchorRaw: string | null = null
  admittedView.forEach((r, i) => {
    if (!auth[i]) return
    const o = asObject(r)!
    const status = o['status']
    if (status !== 'revoked' && status !== REVOCATION_TRANSFERRED) return
    const raw = o['revoked_at']
    const ms = parseIsoLenient(raw)
    if (ms !== null && ms > anchorMs) { anchorMs = ms; anchorRaw = typeof raw === 'string' ? raw : null }
  })
  const notRevoked = anchorRaw === null ? 'unknown' : `not_revoked_as_of:${anchorRaw}`

  const receiptId = payload['receipt_id']
  const valid: JsonObject[] = []
  // A matching, authenticated `status: "transferred"` record (Stage 3,
  // §17.3) is collected separately — it is not a "revoked"-status
  // statement, so it plays no part in the "revoked"-status dispatch below.
  const transferredMatches: JsonObject[] = []
  admittedView.forEach((r, i) => {
    const o = asObject(r)
    if (!o || o['receipt_id'] !== receiptId) return
    if (!auth[i]) { warnings.push(revocationFailedVerify(receiptId)); return }
    if (o['status'] === 'revoked') valid.push(o)
    else if (o['status'] === REVOCATION_TRANSFERRED) transferredMatches.push(o)
  })

  // The pre-Stage-3 "revoked"-status dispatch, unchanged — captured so its
  // result can be checked before the Stage 3 transferred-class check runs.
  const revokedClassResult = (): string => {
    if (revocability === 'none') {
      if (valid.length > 0) { warnings.push(WARN.REVOCABILITY_NONE_IGNORED); return 'invalid_revocation_ignored' }
      return notRevoked
    }
    if (revocability === 'policy') return valid.length > 0 ? 'revoked' : notRevoked
    if (revocability === 'refund_window') {
      const end = refundWindowEnd(payload)
      const effective = valid.filter((r) => { const ms = parseIsoLenient(r['revoked_at']); return end !== null && ms !== null && ms <= end })
      if (effective.length > 0) {
        // G5 (TM-47): a Stage-2-capable verifier (logKeys AND anchorPolicy
        // both supplied — the same gate `evaluateTransparencyClaim` uses)
        // MUST additionally apply the deadline-effectiveness rule. A verifier
        // that never supplies them is not Stage-2 capable, so the rule does
        // not engage and v0.1 semantics stand.
        if (logKeys != null && anchorPolicy != null) {
          const issuerId = typeof issuerManifest['issuer'] === 'string' ? (issuerManifest['issuer'] as string) : null
          const timely = revocationDeadlineSatisfied(effective, revocationEvidence, issuerId, logKeys, anchorPolicy, end, warnings)
          if (!timely) { warnings.push(VERIFY_TRANSPARENCY_WARN.REVOCATION_UNLOGGED_DEADLINE); return 'invalid_revocation_ignored' }
        }
        return 'revoked'
      }
      if (valid.length > 0) { warnings.push(outsideRefundWindow(receiptId)); return 'invalid_revocation_ignored' }
      return notRevoked
    }
    return notRevoked
  }

  const revokedResult = revokedClassResult()
  if (revokedResult === 'revoked') return revokedResult

  // --- Stage 3 (§17.3): transferred-class backing, considered only once the
  // "revoked"-status logic above did NOT itself yield "revoked" — and for
  // ALL revocability classes, `none` included (the consent-gate principle).
  if (transferredMatches.length > 0) {
    if (transferView == null) {
      // The resolver is never reached at all — this is the only place left
      // to report the unbacked outcome.
      if (!warnings.includes(TRANSFER_WARN.REVOCATION_UNBACKED)) warnings.push(TRANSFER_WARN.REVOCATION_UNBACKED)
      return 'invalid_revocation_ignored'
    }

    const manifestIssuerId = typeof issuerManifest['issuer'] === 'string' ? (issuerManifest['issuer'] as string) : null
    const winner = resolveTransferBacking(payload, transferView, issuerManifest, manifestIssuerId, logKeys, anchorPolicy, warnings)
    if (winner !== null) return REVOCATION_TRANSFERRED
    const alreadyWarned = [
      TRANSFER_WARN.REVOCATION_UNBACKED, TRANSFER_WARN.RECORD_UNLOGGED,
      TRANSFER_WARN.NOT_YET_TRANSFERABLE, TRANSFER_WARN.DOUBLE_ASSIGNMENT,
    ].some((w) => warnings.includes(w))
    if (!alreadyWarned) warnings.push(TRANSFER_WARN.REVOCATION_UNBACKED)
    return 'invalid_revocation_ignored'
  }

  return revokedResult
}
