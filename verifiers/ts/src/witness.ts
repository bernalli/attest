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

import { b64uDecode } from './b64u.js'
import { canonicalBytes, loadsStrict } from './canon.js'
import { parseStrictUtc } from './dates.js'
import { ML_DSA_65_PK_LEN } from './mldsa.js'

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
  if (!Number.isInteger(n) || n < 1) throw new WitnessError(`${field} must be a positive integer`)
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

  return {
    operatorId,
    controlGroup,
    name,
    ed25519Pub,
    mldsa65Pub,
    roles,
    notBefore,
    notAfter,
    affiliatedDomains,
    compromiseDeclared,
    compromisedAfter,
  }
}

function parseThreshold(raw: unknown, field: string): Threshold {
  const threshold = requireObject(raw, field)
  requireExactMembers(threshold, THRESHOLD_MEMBERS, field)
  const n = requirePositiveInt(threshold['n'], `${field}.n`)
  const m = requirePositiveInt(threshold['m'], `${field}.m`)
  if (m > n) throw new WitnessError(`${field}.m must not exceed ${field}.n`)
  return { n, m }
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

  return { epochId, notBefore, notAfter, logOrigins, threshold, witnesses }
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

  return { epochs }
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
