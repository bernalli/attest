/**
 * The one place the verifier's local trust material stops being the embedder's
 * OBJECT and becomes the verifier's DATA. Python parity: `trust_material.py`.
 *
 * WHY A BOUNDARY AND NOT A SPELLING RULE
 * --------------------------------------
 * `verify.ts` and `manifests.ts` reach conclusions about a key by asking the
 * entry: `entry['valid_to']`, `entry['status'] === 'compromised'`,
 * `status !== 'active' && status !== 'retired'`. The trust store is not wire
 * data — `loadsStrict` never touches it — it is whatever the embedding
 * application put there, and in JavaScript a plain property read is a GETTER
 * or a `Proxy` trap away from answering differently on every call.
 *
 * The class is not Python-specific, and JavaScript is not immune to it.
 * `===` between
 * primitives cannot be overridden, so the Python `__eq__` trick has no twin
 * here and `new String('compromised')` fails closed. What DOES have a twin is
 * the read itself. Measured on the published 0.9.3 core, not reasoned about: a
 * getter (or a Proxy `get` trap) that returns the true value for the first
 * TWO reads and lies afterwards makes a receipt issued four months after the
 * key expired verify `signature: 'valid'`, and makes a key the signed manifest
 * marks `compromised` verify `signature: 'valid'` — both with no error and no
 * warning. Two, because the first reads canonicalize the manifest and satisfy
 * its self-authenticity gate, and the read after that is the one that decides.
 *
 * That number is the reason a hand-written test does not find this: the window
 * is one value wide. With 0, 1 or 3+ truthful reads the verdict is correct.
 *
 * WHAT "MATERIALIZED" MEANS HERE
 * ------------------------------
 * Everything reachable from the returned structure is a value `loadsStrict`
 * produced: plain objects, arrays, strings, `bigint`, booleans, `null`. The
 * caller's instance does not survive, and neither does any getter or Proxy on
 * it. The guarantee comes from `canon.admitValue`, the reconstruction boundary
 * §18.4 already ratified for the evidence rails — this module contributes the
 * POLICY (what is admitted, and what a refusal means), never a second copy of
 * the HOW. `ownDataCopy` reads own property DESCRIPTORS, so an accessor is not
 * data and is not copied; a value whose own data cannot be expressed is
 * refused whole.
 *
 * Fail-closed: `null` is the only failure, never a partial read.
 */
import { admitValue, MAX_ADMISSION_NODES, type JsonObject } from './canon.js'
import type { TrustStore } from './manifests.js'

/**
 * The `TrustStore` members this boundary owns, in the order the interface
 * declares them. Enumerated rather than discovered: a store that grows a sixth
 * member has to be added here, and until it is, that member never reaches the
 * verifier.
 */
export const TRUST_STORE_FIELDS = [
  'manifests',
  'provenance',
  'chains',
  'artifact_manifests',
  'artifact_manifest_chains',
] as const

/**
 * True iff every CONTAINER reachable from `value` is a plain object or a real
 * array whose members are own, enumerable DATA properties.
 *
 * `ownDataCopy` copies what a container STORES. A container that stores
 * nothing and answers from somewhere else — a `Map`, a `Date`, a class
 * instance, a member defined as a getter — is not NEUTRALIZED by that copy, it
 * is EMPTIED, and for an OPTIONAL trust-store member emptiness is not the safe
 * direction: it is the direction that SKIPS the check. Measured against
 * 98f9d04: with `chains` supplied as a getter or as a `Map`, the member came
 * back `{}`, the held rotation history vanished, and a receipt signed by a key
 * a chain member marks `compromised` went from `ok=false` to `ok=true`.
 *
 * Refusing is therefore the only sound answer for a container. Scalars are
 * unaffected: a primitive carries its own data.
 *
 * KNOWN LIMIT, and it is a contract rather than a bug that can be closed here:
 * a Proxy over an EMPTY target is indistinguishable from `{}` through every
 * portable reflective operation — `getPrototypeOf`, `getOwnPropertyNames` and
 * `getOwnPropertyDescriptor` all forward to the target. The trust store MUST be
 * plain data; a Proxy facade is out of contract and its members are read as
 * empty. That is said in the docs, and it is NOT claimed as fail-closed.
 */
function readsAsOwnData(value: unknown, budget: { left: number }): boolean {
  budget.left -= 1
  if (budget.left < 0) return false
  if (value === null) return true
  const t = typeof value
  if (t !== 'object') return t === 'string' || t === 'bigint' || t === 'boolean'
  if (Array.isArray(value)) {
    let descriptor: PropertyDescriptor | undefined
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, 'length')
    } catch {
      return false
    }
    if (descriptor === undefined || !('value' in descriptor)) return false
    const length: unknown = descriptor.value
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) return false
    for (let i = 0; i < length; i++) {
      const element = Object.getOwnPropertyDescriptor(value, String(i))
      if (element === undefined || !('value' in element)) return false
      if (!readsAsOwnData(element.value, budget)) return false
    }
    return true
  }
  let proto: unknown
  try {
    proto = Object.getPrototypeOf(value as object)
  } catch {
    return false
  }
  // A Map, a Date, a String wrapper, a class instance: none of them store
  // their content as own enumerable data properties.
  if (proto !== Object.prototype && proto !== null) return false
  for (const key of Object.getOwnPropertyNames(value as object)) {
    const descriptor = Object.getOwnPropertyDescriptor(value as object, key)
    // An accessor is code, not data, and `ownDataCopy` SKIPS it — which is a
    // silent deletion. A non-enumerable data property is skipped for the same
    // reason and deleted just as silently. Both are refused here instead.
    if (descriptor === undefined || !('value' in descriptor) || !descriptor.enumerable) return false
    if (!readsAsOwnData(descriptor.value, budget)) return false
  }
  return true
}

/** One key manifest as DATA, or `null` if it cannot be read as data. */
export function materializeKeyManifest(keyManifest: unknown): JsonObject | null {
  // Budget mirrors `canon.admitValue`'s own node budget, so a lazy or
  // unbounded container is refused here rather than followed to the end.
  if (!readsAsOwnData(keyManifest, { left: MAX_ADMISSION_NODES })) return null
  const admission = admitValue(keyManifest)
  if (!admission.admitted) return null
  const value = admission.value
  // A plain object and nothing else. `loadsStrict` cannot return anything but
  // its own output, so this states the postcondition callers rely on.
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  return value as JsonObject
}

/**
 * The caller's trust store as DATA, or `null` if any member of it cannot be.
 *
 * Members that are absent stay absent — `chains`, `artifact_manifests` and
 * `artifact_manifest_chains` are optional and every consumer already reads
 * them with `?.`, so materializing an absent member into an empty object
 * would be the one thing this function must not do: invent state. A member
 * that IS supplied and cannot be read as data refuses the whole store, the
 * same fail-closed posture as the Python twin: the trust store is the
 * verifier's own configuration, not adversarial evidence, and one it cannot
 * fully read is one it should not reason from at all.
 */
export function materializeTrustStore(store: TrustStore): TrustStore | null {
  return materializeTrustStoreDetailed(store).store
}

/**
 * The same boundary, plus the NAME of the member that failed.
 *
 * A refusal that accuses the wrong member sends whoever receives it to debug
 * the wrong half of their configuration — the message used to say "its
 * manifests" whatever had actually failed. `materializeTrustStore` stays as it
 * is for the callers that only need the yes/no; `verify()` uses this one so it
 * can name the member in the error it reports. Python parity:
 * `trust_material.TrustMaterialError.member`.
 */
export function materializeTrustStoreDetailed(store: TrustStore): {
  store: TrustStore | null
  member: string | null
} {
  const out: Record<string, JsonObject> = {}
  for (const field of TRUST_STORE_FIELDS) {
    let supplied: unknown
    try {
      // A plain read, so a legitimate accessor-backed store still works; it
      // runs exactly ONCE, and what it returns is the only thing materialized.
      supplied = (store as unknown as Record<string, unknown>)[field]
    } catch {
      return { store: null, member: field }
    }
    if (supplied === undefined || supplied === null) continue
    const materialized = materializeKeyManifest(supplied)
    if (materialized === null) return { store: null, member: field }
    out[field] = materialized
  }
  return { store: out as unknown as TrustStore, member: null }
}
