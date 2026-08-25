// WitnessPolicy: closed policy documents, epoch validity, conflict predicate.
// Contract: v0.2 §11.4 (P1.1b amendment). Mirrors src/attest/witness.py
// case for case — a policy this core accepts is one the Python core accepts,
// and vice versa.
//
// A WitnessPolicy is TRUSTED verifier configuration on the same rail as pinned
// log keys: packaged with the release, never read off an evidence bundle. Every
// function here THROWS on a malformed document, because that is a caller bug,
// not adversarial input (§10.2). Nothing here parses evidence or verifies a
// signature.

import { AnchorPolicy, validatePolicy, verifyAnchor } from './anchor.js'
import { b64uDecode } from './b64u.js'
import { canonicalBytes, loadsStrict } from './canon.js'
import { parseStrictUtc } from './dates.js'
import {
  ML_DSA_65_PK_LEN,
  ML_DSA_65_SIG_LEN,
  verifyStrict as verifyMlDsaStrict,
} from './mldsa.js'
import { verifyStrict as verifyEd25519Strict } from './ed25519.js'
import { TlogError, keyHash, noteSignatures, parseCheckpoint, type Checkpoint } from './tlog.js'

export const SCHEMA_ID = 'attest-witness-policy-v1'

// §11.4 normative constants.
export const MAX_WITNESS_SKEW_SECONDS = 600
export const MAX_WITNESS_ANCHOR_DELAY_SECONDS = 86400
export const MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE = 9

export const ROLE_CORROBORATION = 'corroboration'
export const ROLE_SUNSET_ACTIVATION = 'sunset-activation'
const KNOWN_ROLES: ReadonlySet<string> = new Set([ROLE_CORROBORATION, ROLE_SUNSET_ACTIVATION])

// Anchored with an explicit end-of-input, matching the Python core's `\Z`.
// JavaScript's `$` already refuses a trailing newline without the `m` flag;
// the two cores must agree on that, so neither is allowed to drift.
const EPOCH_ID_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/
const DNS_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/

const POLICY_MEMBERS = ['schema', 'epochs']
const EPOCH_MEMBERS = [
  'epoch_id',
  'not_before',
  'not_after',
  'log_origins',
  'threshold',
  'witnesses',
]
const THRESHOLD_MEMBERS = ['n', 'm']
const PIN_REQUIRED_MEMBERS = [
  'operator_id',
  'control_group',
  'name',
  'ed25519_pub_b64u',
  'mldsa_65_pub_b64u',
  'roles',
  'not_before',
  'not_after',
  'affiliated_domains',
]
const PIN_OPTIONAL_MEMBERS = ['compromised_after']

export class WitnessError extends Error {}

export const CANONICAL_EMPTY_POLICY_BYTES = canonicalBytes({ schema: SCHEMA_ID, epochs: [] })

export interface Threshold {
  readonly n: number
  readonly m: number
}

export interface WitnessPin {
  readonly operatorId: string
  readonly controlGroup: string
  readonly name: string
  readonly ed25519Pub: Uint8Array
  readonly mldsa65Pub: Uint8Array | null
  readonly roles: readonly string[]
  readonly notBefore: number
  readonly notAfter: number | null
  readonly affiliatedDomains: readonly string[]
  /** Whether the policy declares anything at all about compromise. Absent is
   * NOT the same as an explicit `null` (§11.4's tri-state). */
  readonly compromiseDeclared: boolean
  readonly compromisedAfter: number | null
}

export interface WitnessEpoch {
  readonly epochId: string
  readonly notBefore: number
  readonly notAfter: number | null
  readonly logOrigins: readonly string[]
  readonly threshold: Threshold
  readonly witnesses: readonly WitnessPin[]
}

export interface WitnessPolicy {
  readonly epochs: readonly WitnessEpoch[]
}

function requireObject(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new WitnessError(`${field} must be a JSON object`)
  return value as Record<string, unknown>
}

function requireExactMembers(
  obj: Record<string, unknown>,
  required: readonly string[],
  field: string,
  optional: readonly string[] = [],
): void {
  const missing = required.filter((k) => !Object.hasOwn(obj, k))
  if (missing.length > 0)
    throw new WitnessError(`${field} missing member(s): ${missing.sort().join(', ')}`)
  const allowed = new Set([...required, ...optional])
  const unknown = Object.keys(obj).filter((k) => !allowed.has(k))
  if (unknown.length > 0)
    throw new WitnessError(`${field} has unknown member(s): ${unknown.sort().join(', ')}`)
}

function requireTimestamp(value: unknown, field: string): number {
  // Years 0000-0099 are refused explicitly: `Date.UTC` remaps them to
  // 1900-1999, so `parseStrictUtc` rejects them while Python's `strptime`
  // accepts them — the same document would be admissible in one core only.
  if (typeof value === 'string' && /^00\d\d-/.test(value))
    throw new WitnessError(`${field} must be a UTC ISO-8601 second timestamp`)
  const parsed = parseStrictUtc(value)
  if (parsed === null) throw new WitnessError(`${field} must be a UTC ISO-8601 second timestamp`)
  return parsed
}

function requireOptionalTimestamp(value: unknown, field: string): number | null {
  return value === null ? null : requireTimestamp(value, field)
}

function requireDnsName(value: unknown, field: string): string {
  if (typeof value !== 'string' || !DNS_RE.test(value))
    throw new WitnessError(`${field} must be a lowercase DNS name`)
  return value
}

/** The C2SP signed-note key-name grammar of §9.3, restated for policy input. */
function requireKeyName(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('+'))
    throw new WitnessError(`${field} must be non-empty printable ASCII without '+'`)
  for (const ch of value) {
    const code = ch.codePointAt(0)!
    if (code < 0x21 || code > 0x7e)
      throw new WitnessError(`${field} must be non-empty printable ASCII without '+'`)
  }
  return value
}

/** Non-empty printable ASCII, the §9.3 checkpoint-origin grammar.
 *
 * Enforced here and not only at use: without it a non-ASCII origin would sort
 * by code point in Python and by UTF-16 code unit here, so the two cores would
 * disagree on whether the same `log_origins` array is sorted. */
function requireOrigin(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0)
    throw new WitnessError(`${field} must be a non-empty printable ASCII origin`)
  for (const ch of value) {
    const code = ch.codePointAt(0)!
    if (code < 0x20 || code > 0x7e)
      throw new WitnessError(`${field} must be a non-empty printable ASCII origin`)
  }
  return value
}

function requireSortedUnique(value: unknown, field: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string'))
    throw new WitnessError(`${field} must be an array of strings`)
  const items = value as string[]
  // Python sorts by code point; JS `<` on strings compares UTF-16 code units.
  // Callers restrict every list this touches to ASCII (DNS names, roles,
  // origins), where the two orders coincide — that restriction is what keeps
  // the cores in agreement, not this comparison.
  for (let i = 1; i < items.length; i += 1)
    if (items[i - 1]! > items[i]!) throw new WitnessError(`${field} must be sorted`)
  if (new Set(items).size !== items.length)
    throw new WitnessError(`${field} must be duplicate-free`)
  return [...items]
}

function requirePositiveInt(value: unknown, field: string): number {
  // `canon.loadsStrict` yields BIGINT for JSON integers, so the byte path and
  // the in-memory path arrive here with different types for the same value.
  // Both are accepted; `boolean` is not (`typeof true` is neither).
  let n: number
  if (typeof value === 'bigint') {
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new WitnessError(`${field} must be a positive integer`)
    n = Number(value)
  } else if (typeof value === 'number') {
    n = value
  } else {
    throw new WitnessError(`${field} must be a positive integer`)
  }
  // `isSafeInteger`, not `isInteger`: 2^53 is an "integer" here but Python
  // rejects it, and an unsafe integer cannot round-trip identically anyway.
  if (!Number.isSafeInteger(n) || n < 1)
    throw new WitnessError(`${field} must be a positive integer`)
  return n
}

function requirePub(value: unknown, field: string, length: number): Uint8Array {
  if (typeof value !== 'string') throw new WitnessError(`${field} must be a base64url string`)
  let decoded: Uint8Array
  try {
    decoded = b64uDecode(value)
  } catch {
    throw new WitnessError(`${field} must be canonical base64url`)
  }
  if (decoded.length !== length)
    throw new WitnessError(`${field} must decode to ${length} bytes`)
  return decoded
}

function parsePin(raw: unknown, index: number): WitnessPin {
  const field = `witnesses[${index}]`
  const pin = requireObject(raw, field)
  requireExactMembers(pin, PIN_REQUIRED_MEMBERS, field, PIN_OPTIONAL_MEMBERS)

  const operatorId = requireDnsName(pin['operator_id'], `${field}.operator_id`)
  const controlGroup = requireDnsName(pin['control_group'], `${field}.control_group`)
  const name = requireKeyName(pin['name'], `${field}.name`)

  const roles = requireSortedUnique(pin['roles'], `${field}.roles`)
  const unknownRoles = roles.filter((role) => !KNOWN_ROLES.has(role))
  if (unknownRoles.length > 0)
    throw new WitnessError(`${field}.roles has unknown role(s): ${unknownRoles.sort().join(', ')}`)

  const affiliatedDomains = requireSortedUnique(
    pin['affiliated_domains'],
    `${field}.affiliated_domains`,
  )
  for (const domain of affiliatedDomains)
    requireDnsName(domain, `${field}.affiliated_domains member`)
  if (!affiliatedDomains.includes(operatorId))
    throw new WitnessError(`${field}.affiliated_domains must contain its own operator_id`)

  const ed25519Pub = requirePub(pin['ed25519_pub_b64u'], `${field}.ed25519_pub_b64u`, 32)
  const mldsaRaw = pin['mldsa_65_pub_b64u']
  let mldsa65Pub: Uint8Array | null
  if (mldsaRaw === null) {
    // The activation leg may be absent ONLY for a pin that cannot activate.
    if (roles.includes(ROLE_SUNSET_ACTIVATION))
      throw new WitnessError(
        `${field}.mldsa_65_pub_b64u may be null only without the ${ROLE_SUNSET_ACTIVATION} role`,
      )
    mldsa65Pub = null
  } else {
    mldsa65Pub = requirePub(mldsaRaw, `${field}.mldsa_65_pub_b64u`, ML_DSA_65_PK_LEN)
  }

  const notBefore = requireTimestamp(pin['not_before'], `${field}.not_before`)
  const notAfter = requireOptionalTimestamp(pin['not_after'], `${field}.not_after`)
  if (notAfter !== null && notAfter < notBefore)
    throw new WitnessError(`${field}.not_after precedes not_before`)

  const compromiseDeclared = Object.hasOwn(pin, 'compromised_after')
  const compromisedAfter = compromiseDeclared
    ? requireOptionalTimestamp(pin['compromised_after'], `${field}.compromised_after`)
    : null

  // `readonly` is erased at runtime: without freezing, a consumer can mutate
  // validated trusted configuration in place. Typed arrays cannot be frozen
  // (`Cannot freeze array buffer views with elements`), so the key material
  // is copied on the way in and its immutability stays a convention.
  return Object.freeze({
    operatorId,
    controlGroup,
    name,
    ed25519Pub,
    mldsa65Pub,
    roles: Object.freeze([...roles]),
    notBefore,
    notAfter,
    affiliatedDomains: Object.freeze([...affiliatedDomains]),
    compromiseDeclared,
    compromisedAfter,
  })
}

function parseThreshold(raw: unknown, field: string): Threshold {
  const threshold = requireObject(raw, field)
  requireExactMembers(threshold, THRESHOLD_MEMBERS, field)
  const n = requirePositiveInt(threshold['n'], `${field}.n`)
  const m = requirePositiveInt(threshold['m'], `${field}.m`)
  if (m > n) throw new WitnessError(`${field}.m must not exceed ${field}.n`)
  // §11.4's committee ceiling. Declaring a committee larger than the ceiling
  // is a policy that could never be satisfied, so it is refused at parse
  // time. Whether `n` MATCHES the epoch's activation control groups is
  // checked where those groups are actually counted, not here.
  if (n > MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE)
    throw new WitnessError(
      `${field}.n must not exceed ${MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE}`,
    )
  return Object.freeze({ n, m })
}

function parseEpoch(raw: unknown, index: number): WitnessEpoch {
  const field = `epochs[${index}]`
  const epoch = requireObject(raw, field)
  requireExactMembers(epoch, EPOCH_MEMBERS, field)

  const epochId = epoch['epoch_id']
  if (typeof epochId !== 'string' || !EPOCH_ID_RE.test(epochId))
    throw new WitnessError(`${field}.epoch_id must match ^[a-z0-9][a-z0-9._-]{0,127}$`)

  const notBefore = requireTimestamp(epoch['not_before'], `${field}.not_before`)
  const notAfter = requireOptionalTimestamp(epoch['not_after'], `${field}.not_after`)
  if (notAfter !== null && notAfter < notBefore)
    throw new WitnessError(`${field}.not_after precedes not_before`)

  const logOrigins = requireSortedUnique(epoch['log_origins'], `${field}.log_origins`)
  for (const origin of logOrigins) requireOrigin(origin, `${field}.log_origins member`)
  const threshold = parseThreshold(epoch['threshold'], `${field}.threshold`)

  const rawWitnesses = epoch['witnesses']
  if (!Array.isArray(rawWitnesses)) throw new WitnessError(`${field}.witnesses must be an array`)
  const witnesses = rawWitnesses.map((item, position) => parsePin(item, position))

  return Object.freeze({
    epochId,
    notBefore,
    notAfter,
    logOrigins: Object.freeze([...logOrigins]),
    threshold,
    witnesses: Object.freeze(witnesses),
  })
}

/** Parse a TRUSTED `attest-witness-policy-v1` document. Throws on anything
 * malformed: this is verifier configuration, so a defect must be loud rather
 * than a silent downgrade (§10.2's trusted-side discipline). */
export function parsePolicy(document: unknown): WitnessPolicy {
  const policy = requireObject(document, 'witness policy')
  requireExactMembers(policy, POLICY_MEMBERS, 'witness policy')
  if (policy['schema'] !== SCHEMA_ID)
    throw new WitnessError(`witness policy schema must be '${SCHEMA_ID}'`)

  const rawEpochs = policy['epochs']
  if (!Array.isArray(rawEpochs)) throw new WitnessError('witness policy epochs must be an array')
  const epochs = rawEpochs.map((item, index) => parseEpoch(item, index))

  const seen = new Set<string>()
  for (const epoch of epochs) {
    if (seen.has(epoch.epochId)) throw new WitnessError(`duplicate epoch_id: '${epoch.epochId}'`)
    seen.add(epoch.epochId)
  }

  return Object.freeze({ epochs: Object.freeze(epochs) })
}

/** Parse a policy from its canonical JCS bytes — the supported entry point.
 *
 * Going through `loadsStrict` is what makes the two cores agree on NUMBERS:
 * JSON `1.0` is rejected there as a non-integer literal, while an in-memory
 * `{n: 1.0}` handed to `parsePolicy` is indistinguishable from `{n: 1}` here
 * (they are the same value). Loading from bytes removes that asymmetry
 * instead of papering over it. */
export function loadPolicy(data: Uint8Array): WitnessPolicy {
  return parsePolicy(loadsStrict(data))
}

/** Resolve an epoch by identifier, or `undefined` when unknown. Evidence names
 * an epoch explicitly (§10.2); the current epoch is never substituted. */
export function findEpoch(policy: WitnessPolicy, epochId: string): WitnessEpoch | undefined {
  return policy.epochs.find((epoch) => epoch.epochId === epochId)
}

/** Validity window, inclusive at both declared boundaries. */
export function epochCovers(epoch: WitnessEpoch, at: number): boolean {
  if (at < epoch.notBefore) return false
  return epoch.notAfter === null || at <= epoch.notAfter
}

export function pinCovers(pin: WitnessPin, at: number): boolean {
  if (at < pin.notBefore) return false
  return pin.notAfter === null || at <= pin.notAfter
}

/** Whether this pin may contribute standing for an observation at `at`. */
export function pinHasStandingAt(pin: WitnessPin, at: number): boolean {
  if (!pinCovers(pin, at)) return false
  if (!pin.compromiseDeclared) return true
  // Onset unknown: fail closed at every time, forever.
  if (pin.compromisedAfter === null) return false
  return at <= pin.compromisedAfter
}

/** §11.4's two-limb conflict predicate, parameterized by `conflictDomain`.
 *
 * Direct: the pin itself names the domain. Transitive: some pin in this epoch
 * names the domain and shares this pin's control group.
 *
 * There is deliberately no inverse: domain inequality MUST NOT establish
 * independence, and policy v1 defines no positive independence certificate. */
export function isConflicted(
  epoch: WitnessEpoch,
  pin: WitnessPin,
  conflictDomain: string,
): boolean {
  if (pin.affiliatedDomains.includes(conflictDomain)) return true
  return epoch.witnesses.some(
    (other) =>
      other.affiliatedDomains.includes(conflictDomain) && other.controlGroup === pin.controlGroup,
  )
}

// --- C2SP tlog-cosignature (v0.2 §9.2) -------------------------------------

// Type `0x04` is the interoperable Ed25519 cosignature real witnesses already
// emit. Type `0x06` is an ML-DSA-44 signature over the DIFFERENT `subtree/v1`
// structure and MUST NOT count as either leg (§9.2).
export const COSIGNATURE_SIG_TYPE = Uint8Array.of(0x04)
const COSIGNATURE_HEADER = new TextEncoder().encode('cosignature/v1\n')
const KEY_ID_LEN = 4
const TIMESTAMP_LEN = 8
const ED25519_SIG_LEN = 64
const COSIGNATURE_BLOB_LEN = KEY_ID_LEN + TIMESTAMP_LEN + ED25519_SIG_LEN

// Both cores must agree on which timestamps are representable at all:
// Python's `datetime` stops at year 9999 while JavaScript's `Date` reaches
// year 275760, so a cosignature past this bound would be rejected by one core
// and accepted by the other. 253402300799 is 9999-12-31T23:59:59Z.
export const MAX_COSIGNATURE_TIMESTAMP = 253402300799

export const WARN_INDEPENDENCE_NOT_ESTABLISHED = 'witness_independence_not_established'

/** The exact bytes a witness signs: header, time line, then the note body.
 *
 * `cosignature/v1\n` is the domain separation that stops a signature made
 * over a checkpoint body from being transported into a witness assertion,
 * or the reverse (§9.2). */
export function cosignatureMessage(noteBytes: Uint8Array, timestamp: number): Uint8Array {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0)
    throw new WitnessError('timestamp must be a non-negative POSIX integer')
  const timeLine = new TextEncoder().encode(`time ${timestamp}\n`)
  const out = new Uint8Array(COSIGNATURE_HEADER.length + timeLine.length + noteBytes.length)
  out.set(COSIGNATURE_HEADER, 0)
  out.set(timeLine, COSIGNATURE_HEADER.length)
  out.set(noteBytes, COSIGNATURE_HEADER.length + timeLine.length)
  return out
}

/** `SHA-256(name || "\n" || 0x04 || pub)[:4]` — the C2SP type-`0x04` key ID.
 * Distinct from the same witness's checkpoint-type key ID by construction. */
export function cosignatureKeyId(name: string, ed25519Pub: Uint8Array): Uint8Array {
  return keyHash(name, COSIGNATURE_SIG_TYPE, ed25519Pub)
}

export interface CorroborationVerdict {
  readonly witnessed: boolean
  readonly warnings: readonly string[]
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

/** Whether one signature-line blob is a valid cosignature by `pin`.
 * Never throws: these bytes come from an untrusted note. */
function countsAsCorroboration(
  blob: unknown,
  pin: WitnessPin,
  noteBytes: Uint8Array,
  epoch: WitnessEpoch,
): boolean {
  if (!(blob instanceof Uint8Array) || blob.length !== COSIGNATURE_BLOB_LEN) return false
  if (!equalBytes(blob.subarray(0, KEY_ID_LEN), cosignatureKeyId(pin.name, pin.ed25519Pub)))
    return false
  const view = new DataView(blob.buffer, blob.byteOffset + KEY_ID_LEN, TIMESTAMP_LEN)
  const seconds = view.getBigUint64(0, false)
  if (seconds > BigInt(MAX_COSIGNATURE_TIMESTAMP)) return false
  const timestamp = Number(seconds)
  // Standing is judged at the moment the witness CLAIMS to have observed, not
  // at the verifier's local clock — an old but valid observation must keep
  // verifying forever.
  // §10.1 requires an epoch-VALID witness: the epoch's own inclusive window
  // bounds the observation just as the pin's does.
  if (!epochCovers(epoch, timestamp * 1000)) return false
  if (!pinHasStandingAt(pin, timestamp * 1000)) return false
  const message = cosignatureMessage(noteBytes, timestamp)
  return verifyEd25519Strict(message, blob.subarray(KEY_ID_LEN + TIMESTAMP_LEN), pin.ed25519Pub)
}

/** Decide whether one pinned witness cosignature reaches `witnessed`.
 *
 * §10.1's one-`0x04` rule: a single valid Ed25519 cosignature by a pinned,
 * epoch-resolved witness holding the `corroboration` role is sufficient.
 *
 * Every failure returns `witnessed: false` with NO warning, leaving the
 * caller's existing standing untouched. That silence is normative (§11.4). */
export function evaluateCorroboration(
  checkpoint: Checkpoint,
  signatures: ReadonlyArray<readonly [string, Uint8Array]>,
  policy: WitnessPolicy,
  epochId: unknown,
): CorroborationVerdict {
  if (typeof epochId !== 'string') return { witnessed: false, warnings: [] }
  const epoch = findEpoch(policy, epochId)
  if (epoch === undefined) return { witnessed: false, warnings: [] }

  // The epoch's scope is part of what makes a witness pinned FOR THIS LOG: an
  // epoch listing other origins says nothing about this checkpoint.
  // Fail-closed, so an epoch with no origins corroborates nothing.
  if (!epoch.logOrigins.includes(checkpoint.origin)) return { witnessed: false, warnings: [] }

  for (const [name, blob] of signatures) {
    for (const pin of epoch.witnesses) {
      // A line naming someone else is a signed-note convention, never a
      // fatal condition (§9.2).
      if (pin.name !== name || !pin.roles.includes(ROLE_CORROBORATION)) continue
      // Per-line confinement, NOT one try around the whole scan: an untrusted
      // line that throws must not veto a later valid one, which would let an
      // attacker suppress genuine corroboration by prepending garbage under
      // the same name.
      let counted = false
      try {
        counted = countsAsCorroboration(blob, pin, checkpoint.noteBytes, epoch)
      } catch {
        continue
      }
      if (counted) return { witnessed: true, warnings: [WARN_INDEPENDENCE_NOT_ESTABLISHED] }
    }
  }
  return { witnessed: false, warnings: [] }
}

// --- Standalone activation-grade hybrid quorum (v0.2 §11.4) ----------------
//
// A STANDALONE primitive: §11.4 defines no grant consumer, and nothing below
// knows about receipts, result vocabularies, or grant state. It answers one
// question — did a quorum of pinned witnesses observe THIS checkpoint, and by
// when — and returns the conservative time at which that became true.
// Mirrors src/attest/witness.py step for step.

// The activation leg's own C2SP type: `0xff` (the registry's extension
// mechanism) followed by an identifier distinct from the checkpoint's own
// `attest-ml-dsa-65`. Sharing the checkpoint identifier would let a checkpoint
// signature be presented as a witness assertion.
export const PQ_COSIGNATURE_SIG_TYPE = new Uint8Array([
  0xff,
  ...new TextEncoder().encode('attest-cosignature-ml-dsa-65-v1'),
])
const PQ_COSIGNATURE_BLOB_LEN = KEY_ID_LEN + TIMESTAMP_LEN + ML_DSA_65_SIG_LEN

/** Quorum standing and conservative witness time — nothing else.
 *
 * `witnessTime` is `T = min(t_i)` over the counting votes, and is `null`
 * whenever `valid` is `false`: an invalid quorum has no time to report. */
export interface ActivationWitnessQuorumResult {
  readonly valid: boolean
  readonly witnessTime: number | null
  readonly countingControlGroups: readonly string[]
}

export interface ActivationWitnessQuorumOptions {
  readonly witnessPolicy: WitnessPolicy
  readonly epochId: unknown
  readonly expectedOrigin: string
  readonly anchorEvidence: unknown
  readonly anchorPolicy: AnchorPolicy
  readonly conflictDomain: string
}

const INVALID_QUORUM: ActivationWitnessQuorumResult = Object.freeze({
  valid: false,
  witnessTime: null,
  countingControlGroups: Object.freeze([]),
})

/** One pin's unambiguous `0x04`+`0xff` candidate, before any verification. */
interface CandidatePair {
  readonly pin: WitnessPin
  readonly timestamp: number
  readonly ed25519Signature: Uint8Array
  readonly mldsaSignature: Uint8Array
}

/** Structural match of one signature-line blob against one expected key ID.
 *
 * Pure byte work — no signature is verified here, which is what lets the
 * committee ceiling and the ambiguity rule bite before any crypto. */
function leg(
  blob: unknown,
  keyId: Uint8Array,
  blobLen: number,
): { timestamp: number; signature: Uint8Array } | null {
  if (!(blob instanceof Uint8Array) || blob.length !== blobLen) return null
  if (!equalBytes(blob.subarray(0, KEY_ID_LEN), keyId)) return null
  const view = new DataView(blob.buffer, blob.byteOffset + KEY_ID_LEN, TIMESTAMP_LEN)
  const seconds = view.getBigUint64(0, false)
  if (seconds > BigInt(MAX_COSIGNATURE_TIMESTAMP)) return null
  return { timestamp: Number(seconds), signature: blob.subarray(KEY_ID_LEN + TIMESTAMP_LEN) }
}

/** This pin's candidate pair, `null` if it presented none, `'ambiguous'` if it
 * presented more than one of either leg.
 *
 * Ambiguity is a hard failure rather than a choice, because choosing between
 * two candidate legs would mean verifying both — exactly the work §11.4
 * requires to be bounded before crypto begins. */
function candidateFor(
  pin: WitnessPin,
  signatures: ReadonlyArray<readonly [string, Uint8Array]>,
): CandidatePair | null | 'ambiguous' {
  if (pin.mldsa65Pub === null) return null
  const edKeyId = cosignatureKeyId(pin.name, pin.ed25519Pub)
  const pqKeyId = keyHash(pin.name, PQ_COSIGNATURE_SIG_TYPE, pin.mldsa65Pub)

  const edLegs: Array<{ timestamp: number; signature: Uint8Array }> = []
  const pqLegs: Array<{ timestamp: number; signature: Uint8Array }> = []
  for (const [name, blob] of signatures) {
    // A line naming someone else is a signed-note convention (§9.2).
    if (name !== pin.name) continue
    const ed = leg(blob, edKeyId, COSIGNATURE_BLOB_LEN)
    if (ed !== null) {
      edLegs.push(ed)
      continue
    }
    const pq = leg(blob, pqKeyId, PQ_COSIGNATURE_BLOB_LEN)
    if (pq !== null) pqLegs.push(pq)
  }

  if (edLegs.length > 1 || pqLegs.length > 1) return 'ambiguous'
  if (edLegs.length === 0 || pqLegs.length === 0) return null
  const ed = edLegs[0]!
  const pq = pqLegs[0]!
  // Both legs sign the byte-identical payload, timestamp included: legs
  // carrying different times are not a pair at all.
  if (ed.timestamp !== pq.timestamp) return null
  return {
    pin,
    timestamp: ed.timestamp,
    ed25519Signature: ed.signature,
    mldsaSignature: pq.signature,
  }
}

/** Fail-closed AND over both legs of one candidate pair.
 *
 * Ed25519 first, and the ML-DSA leg is never reached when it fails: an
 * attacker who can put arbitrary lines in a note must not be able to buy
 * post-quantum verification work with a garbage classical signature. */
function verifiesBothLegs(candidate: CandidatePair, noteBytes: Uint8Array): boolean {
  const message = cosignatureMessage(noteBytes, candidate.timestamp)
  if (!verifyEd25519Strict(message, candidate.ed25519Signature, candidate.pin.ed25519Pub))
    return false
  // `mldsa65Pub` is non-null for every candidate — `candidateFor` returns
  // `null` otherwise.
  return verifyMlDsaStrict(message, candidate.mldsaSignature, candidate.pin.mldsa65Pub!)
}

/** Refuse anything that is not a policy this module itself parsed.
 *
 * The Python core gets this from `isinstance(WitnessPolicy)`. TypeScript
 * interfaces are erased at runtime, so the check here is one of SHAPE: a
 * parsed policy carries exactly `epochs`, and each of its epochs carries the
 * camelCase fields `parseEpoch` produces. That is what catches the mistake
 * this guard exists for — handing the raw JSON document (with its `schema`
 * member and `epoch_id`/`not_before` keys) straight to the evaluator, which
 * would otherwise resolve no epoch and look like an ordinary negative result
 * instead of the configuration bug it is.
 *
 * Declared limit: an empty hand-built `{ epochs: [] }` is indistinguishable
 * from a parsed empty policy here, while the Python core would reject it.
 * Both cores return the same verdict for it (no epoch resolves), so no
 * verification outcome diverges — only the diagnostic does. */
function requireParsedPolicy(policy: unknown): asserts policy is WitnessPolicy {
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy))
    throw new WitnessError('witnessPolicy must be a parsed WitnessPolicy')
  const members = Object.keys(policy)
  if (members.length !== 1 || members[0] !== 'epochs')
    throw new WitnessError('witnessPolicy must be a parsed WitnessPolicy')
  const epochs = (policy as { epochs: unknown }).epochs
  if (!Array.isArray(epochs))
    throw new WitnessError('witnessPolicy must be a parsed WitnessPolicy')
  for (const epoch of epochs) {
    if (
      typeof epoch !== 'object' ||
      epoch === null ||
      typeof (epoch as WitnessEpoch).epochId !== 'string' ||
      typeof (epoch as WitnessEpoch).notBefore !== 'number' ||
      typeof (epoch as WitnessEpoch).threshold !== 'object' ||
      !Array.isArray((epoch as WitnessEpoch).witnesses)
    )
      throw new WitnessError('witnessPolicy must be a parsed WitnessPolicy')
  }
}

/** Evaluate the reusable activation-grade hybrid quorum of §11.4.
 *
 * Trusted configuration — the witness policy, the anchor policy, the expected
 * origin, the conflict domain — THROWS when malformed, on the same rail as
 * pinned log keys. Everything untrusted — the checkpoint text, its signature
 * lines, the anchor evidence — degrades to `valid: false`, never an exception.
 *
 * The evaluation order is normative, not incidental: the committee ceiling and
 * the one-candidate-per-control-group rule are enforced BEFORE any signature
 * verification, so a hostile policy or note cannot turn this primitive into a
 * work amplifier.
 *
 * No local clock is consulted anywhere: an observation that was valid when it
 * was made stays verifiable forever. */
export function evaluateActivationWitnessQuorum(
  checkpointText: unknown,
  options: ActivationWitnessQuorumOptions,
): ActivationWitnessQuorumResult {
  const { witnessPolicy, epochId, anchorEvidence, anchorPolicy } = options

  // 1. Trusted configuration.
  requireParsedPolicy(witnessPolicy)
  if (typeof anchorPolicy !== 'object' || anchorPolicy === null)
    throw new WitnessError('anchorPolicy must be an AnchorPolicy')
  validatePolicy(anchorPolicy)
  const expectedOrigin = requireOrigin(options.expectedOrigin, 'expectedOrigin')
  const conflictDomain = requireDnsName(options.conflictDomain, 'conflictDomain')

  // 2. The named epoch, never a substitute for one that fails to resolve.
  if (typeof epochId !== 'string') return INVALID_QUORUM
  const epoch = findEpoch(witnessPolicy, epochId)
  if (epoch === undefined) return INVALID_QUORUM

  // 3-4. Committee form. `threshold.n` counts distinct activation-role control
  // groups, so the ceiling is a property of the epoch's MEMBERSHIP, not of the
  // number the policy declares — and it is checked first, before the declared
  // form, because it is the bound on work.
  //
  // Measured, not assumed: the ceiling is REDUNDANT today. `n > 9` is already
  // refused at parse time, so an epoch that trips the ceiling also trips the
  // form check, and no case can distinguish the two — deleting either one
  // alone leaves every parity case green, deleting both turns
  // `committee-of-ten` red. It stays because §11.4 states it normatively and
  // because a future policy revision that relaxes the parser must not silently
  // relax this.
  const committee = new Set(
    epoch.witnesses
      .filter((pin) => pin.roles.includes(ROLE_SUNSET_ACTIVATION))
      .map((pin) => pin.controlGroup),
  )
  if (committee.size > MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE) return INVALID_QUORUM
  if (committee.size !== epoch.threshold.n) return INVALID_QUORUM

  // 5. Origin scope: an epoch listing other origins says nothing about this
  // log. Fail-closed, so an epoch with no origins carries no quorum.
  if (!epoch.logOrigins.includes(expectedOrigin)) return INVALID_QUORUM

  // 6-7. The checkpoint is untrusted; parse it once, and only structurally
  // (this primitive never authenticates the checkpoint — that is the caller's
  // log key, not a witness's business).
  if (typeof checkpointText !== 'string') return INVALID_QUORUM
  let checkpoint: Checkpoint
  let signatures: Array<[string, Uint8Array]>
  try {
    checkpoint = parseCheckpoint(checkpointText)
    signatures = noteSignatures(checkpointText)
  } catch (error) {
    if (error instanceof TlogError) return INVALID_QUORUM
    throw error
  }
  if (checkpoint.origin !== expectedOrigin) return INVALID_QUORUM

  // 8. Conflict exclusion, before crypto and before pairing.
  const eligible = epoch.witnesses.filter(
    (pin) => pin.roles.includes(ROLE_SUNSET_ACTIVATION) && !isConflicted(epoch, pin, conflictDomain),
  )

  // 9. At most one unambiguous candidate pair per control group.
  const candidates = new Map<string, CandidatePair>()
  for (const pin of eligible) {
    const candidate = candidateFor(pin, signatures)
    if (candidate === null) continue
    if (candidate === 'ambiguous') return INVALID_QUORUM
    if (candidates.has(candidate.pin.controlGroup)) return INVALID_QUORUM
    candidates.set(candidate.pin.controlGroup, candidate)
  }

  // 10-11. Fail-closed AND over both legs, one pair per group at most.
  const verified = [...candidates.values()].filter((candidate) =>
    verifiesBothLegs(candidate, checkpoint.noteBytes),
  )
  if (verified.length === 0) return INVALID_QUORUM

  // 12-14. `T = min(t_i)`: the conservative quorum time. Taking the maximum
  // would let the latest signer stretch the anchor window every earlier
  // observation is judged by.
  const quorumTime = Math.min(...verified.map((candidate) => candidate.timestamp))

  // 15-16. Epoch validity, pin validity and compromise state are all judged AT
  // `T`, not at each leg's own timestamp.
  if (!epochCovers(epoch, quorumTime * 1000)) return INVALID_QUORUM
  const counting = verified.filter((candidate) =>
    pinHasStandingAt(candidate.pin, quorumTime * 1000),
  )
  if (counting.length < epoch.threshold.m) return INVALID_QUORUM

  // 17-18. Every counting vote already refers to this checkpoint: its note
  // body is inside the payload each leg signed. What remains is the skew.
  const times = counting.map((candidate) => candidate.timestamp)
  const latest = Math.max(...times)
  if (latest - Math.min(...times) > MAX_WITNESS_SKEW_SECONDS) return INVALID_QUORUM

  // 19-21. A full `signed-note-v2` anchor over the complete signed note —
  // cosignature lines included — is what ties these observations to a
  // PQ-surviving time. A `note-v1` anchor commits to the unsigned header alone
  // and so says nothing about the lines being counted here.
  const verdict = verifyAnchor(anchorEvidence, checkpoint, anchorPolicy)
  if (!verdict.pqSurviving || verdict.noteOnly || verdict.anchoredBefore === null)
    return INVALID_QUORUM
  const anchoredAt = verdict.anchoredBefore
  if (!(latest <= anchoredAt && anchoredAt <= quorumTime + MAX_WITNESS_ANCHOR_DELAY_SECONDS))
    return INVALID_QUORUM

  // 22.
  return Object.freeze({
    valid: true,
    witnessTime: quorumTime,
    countingControlGroups: Object.freeze(
      [...new Set(counting.map((candidate) => candidate.pin.controlGroup))].sort(),
    ),
  })
}
