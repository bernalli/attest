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
import {
  CanonError,
  MAX_ADMISSION_BYTES,
  MAX_ADMISSION_NODES,
  admitValue,
  canonicalBytes,
  canonicalKeyOrder,
  loadsStrict,
  type JsonObject,
  type JsonValue,
} from './canon.js'
import {
  detachedBuffer,
  memberShape,
  notByteView,
  notBytes,
  notCanonical,
  notObject,
  sharedMemory,
  tooLarge,
  unknownMember,
  unparsable,
} from './messages.js'
// The alias `TrustStoreShape` and the `TRUST_STORE_FIELDS` list stood here.
// Both belonged to the old boundary: the first named the live interface
// `manifests.ts` used to declare, the second enumerated the members that
// boundary walked. `TrustStore` in this file now means the CLASS below with no
// alias to keep apart from it, and the members are enumerated once, where the
// document's grammar is checked (`MEMBER_SHAPES`) — one list instead of two
// that could disagree about what a store has.

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

// `materializeTrustStore` and `materializeTrustStoreDetailed` stood here, and
// T3 removed them with their last caller. They took the embedder's live store
// object and copied the data it OWNED, member by member — a good defence with
// one hole nothing inside it could close: a `Proxy` over an EMPTY target
// forwards every reflective operation to that target, so a facade standing in
// for `chains` was copied as `{}` and the held rotation history vanished. That
// was measured, not feared: with it, a receipt signed by a key the store
// declares `compromised` verified `signature: 'valid'`, `trust: 'verified'` —
// a verdict indistinguishable from an honest store that declares nothing.
//
// The snapshot below does not close that hole, it removes the question. There
// is no live container to stand in for, because what a door accepts is not an
// object with the right members but an instance only this file can build, out
// of bytes it parsed itself.

// ===========================================================================
// The serialized entry (plan section 5.2). Everything below takes BYTES and
// hands back a snapshot.
// ===========================================================================

// Intrinsics captured at module load: own-SLOT reads, never property reads on
// the candidate. A getter taken off the prototype and invoked with `.call(x)`
// reads `x`'s internal slot and runs none of `x`'s code, which is what makes
// the refusals below observable-free.
const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype) as object
// `[[TypedArrayName]]`, or `undefined` for anything that is not a typed array
// — a DataView, a plain object, a Proxy over a real view. A Proxy answers
// `undefined` with ZERO traps, because the getter reads a slot the Proxy does
// not have rather than a property it could forward.
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, Symbol.toStringTag)!
  .get as (this: unknown) => string | undefined
// 0 on a detached or out-of-bounds view.
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteLength')!
  .get as (this: unknown) => number
const TYPED_ARRAY_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'buffer')!.get as (
  this: unknown,
) => ArrayBufferLike
const ARRAY_BUFFER_BYTE_LENGTH = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  'byteLength',
)!.get as (this: unknown) => number

/** The three views whose elements ARE bytes. */
const BYTE_VIEWS: ReadonlySet<string> = new Set(['Uint8Array', 'Int8Array', 'Uint8ClampedArray'])

/**
 * True only for an ORDINARY `ArrayBuffer`, proved positively.
 *
 * The question is deliberately not "is it shared?". Asking it that way needs a
 * `SharedArrayBuffer` binding to compare against, and in a realm where that
 * global is absent the honest answer is "I cannot tell" — which a boolean
 * turns into "no", admitting a shared view that arrived from another realm.
 * A fallback that admits when it does not know is fail-OPEN.
 *
 * `ArrayBuffer.prototype.byteLength` reads an internal slot and THROWS on
 * every `SharedArrayBuffer`, local or cross-realm, so it answers the question
 * that actually matters — "is this the kind of buffer whose bytes only this
 * agent can change?" — without needing either constructor to be in scope.
 */
function isOrdinaryArrayBuffer(buffer: ArrayBufferLike): boolean {
  try {
    ARRAY_BUFFER_BYTE_LENGTH.call(buffer)
    return true
  } catch {
    return false
  }
}

/**
 * `data` as a PRIVATE copy of its bytes, or a refusal.
 *
 * Order (section 5.2.1): M1, M9, M10, M2, M11, M2 again on the copy.
 *
 * The ceiling before the copy is the one that does the work: it refuses an
 * oversized input WITHOUT copying it.
 *
 * The ceiling after the copy is a BACKSTOP and is currently UNREACHABLE, which
 * is stated here because the comment used to claim otherwise. The claim was
 * that the two reads are "two different observations of a buffer that can
 * resize"; they are not, given the three checks above them. A buffer that
 * another agent can resize is a SharedArrayBuffer, and M10 has already refused
 * every one of them -- fixed or growable -- three checks earlier. Between the
 * remaining read and `new Uint8Array(data)` no caller code runs at all:
 * `InitializeTypedArrayFromTypedArray` reads the source's internal slots and
 * consults neither `Symbol.species`, nor `constructor`, nor a `length` or
 * `byteLength` accessor, nor an index getter (measured 2026-09-08 across a
 * Uint8Array subclass carrying all of those, a length-tracking view on a
 * resizable buffer, and an instrumented `ArrayBuffer[Symbol.species]`: zero
 * hooks fired, and the copy's length equalled the first read in every case).
 *
 * It is kept rather than deleted because it costs one comparison and it is the
 * check that would still hold if the M10/M2 order were ever changed. What it
 * must not be is REASONED FROM: the first read is not redundant, and removing
 * it would let a 10 GB view be copied before being refused.
 *
 * The copy is what makes INV-5 true: after this returns, the caller can
 * overwrite the bytes, detach the buffer or resize it to nothing, and the
 * snapshot built from the copy does not notice.
 */
function documentBytes(data: unknown, what: string): Uint8Array {
  if (data === null || typeof data !== 'object') throw new TrustMaterialError(notBytes(what))
  const tag = TYPED_ARRAY_TAG.call(data)
  if (tag === undefined) throw new TrustMaterialError(notBytes(what))
  if (!BYTE_VIEWS.has(tag)) throw new TrustMaterialError(notByteView(what))
  if (!isOrdinaryArrayBuffer(TYPED_ARRAY_BUFFER.call(data))) {
    throw new TrustMaterialError(sharedMemory(what))
  }
  if (TYPED_ARRAY_BYTE_LENGTH.call(data) > MAX_ADMISSION_BYTES) {
    throw new TrustMaterialError(tooLarge(what))
  }
  let copy: Uint8Array
  try {
    // Slot copy: reads the source's internal slots and runs no caller code —
    // not `Symbol.species`, not `constructor`, not an index getter.
    copy = new Uint8Array(data as Uint8Array)
  } catch {
    throw new TrustMaterialError(detachedBuffer(what))
  }
  if (copy.byteLength > MAX_ADMISSION_BYTES) throw new TrustMaterialError(tooLarge(what))
  return copy
}

/** Bytes in, parsed tree out. M7 for anything the profile's parser refuses. */
function parseDocument(data: unknown, what: string): JsonValue {
  const copy = documentBytes(data, what)
  try {
    return loadsStrict(copy)
  } catch (e) {
    if (e instanceof CanonError) throw new TrustMaterialError(unparsable(what, e.message))
    throw e
  }
}

/** The admitted domain is what the snapshot can export without loss (D16). */
function canonicalOf(parsed: JsonValue, what: string): Uint8Array {
  try {
    return canonicalBytes(parsed)
  } catch (e) {
    if (e instanceof CanonError) throw new TrustMaterialError(notCanonical(what, e.message))
    throw e
  }
}

function isPlainObject(value: JsonValue): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * The container grammar of section 5.3: the nesting path of each member, and
 * the phrase its refusal uses.
 *
 * Derived from one place so the check and the message cannot drift apart. Two
 * copies of the same rule are two rules that will disagree eventually, and the
 * message is what a caller uses to fix their document.
 */
const MEMBER_SHAPES: ReadonlyArray<readonly [string, readonly string[], string]> = [
  ['manifests', ['object', 'object'], 'an object of objects'],
  ['provenance', ['object', 'string'], 'an object of strings'],
  ['chains', ['object', 'array', 'object'], 'an object of arrays of objects'],
  ['artifact_manifests', ['object', 'object', 'object'], 'an object of objects of objects'],
  [
    'artifact_manifest_chains',
    ['object', 'object', 'array', 'object'],
    'an object of objects of arrays of objects',
  ],
]
const REQUIRED_MEMBERS: ReadonlySet<string> = new Set(['manifests', 'provenance'])
const KNOWN_MEMBERS: ReadonlySet<string> = new Set(MEMBER_SHAPES.map(([name]) => name))

/** Whether `value` has the nesting the grammar names for a member. */
function matchesShape(value: JsonValue, kinds: readonly string[]): boolean {
  const kind = kinds[0]
  const rest = kinds.slice(1)
  if (kind === 'object') {
    if (!isPlainObject(value)) return false
    if (rest.length === 0) return true
    return Object.values(value).every((item) => matchesShape(item, rest))
  }
  if (kind === 'array') {
    if (!Array.isArray(value)) return false
    if (rest.length === 0) return true
    return value.every((item) => matchesShape(item, rest))
  }
  return typeof value === 'string'
}

/**
 * The grammar of section 5.3, in its stated order: M4, M5, M6, and nothing else.
 *
 * The order is part of the contract, not an implementation detail: a document
 * with two defects must be refused for the FIRST one, so that a caller fixing
 * what the message names makes progress instead of meeting a different
 * complaint about the same document.
 *
 * What this does NOT validate is as deliberate as what it does: manifest
 * contents, the agreement between `manifests[i]` and `chains[i]`'s last entry,
 * the values of `provenance`, empty issuer ids. The boundary guarantees the
 * shape of the containers and canonical representability — that the readers
 * downstream find what they read, and that `data()`/`toBytes()` are total.
 * Everything else belongs to whoever knows what it means.
 */
function validatedStoreDocument(parsed: JsonValue): StoreData {
  if (!isPlainObject(parsed)) throw new TrustMaterialError(notObject('trust store'))
  // M5 before M6. WHICH unknown member gets named is the minimum in CANONICAL
  // key order, never the first in document order -- and in this language that
  // is not a refinement, it is the only implementable rule. `JSON.parse` (and
  // `loadsStrict`, which builds ordinary objects) enumerates integer-like keys
  // first whatever the document said, so document order is already gone here
  // (measured 2026-09-08: this core named '0' where Python named 'zz' on the
  // same bytes). Canonical order is what the protocol already signs on, and
  // `Array.prototype.sort`'s default comparator IS that order -- UTF-16 code
  // units -- which is why `canonicalKeyOrder` is a call and not a comparator.
  const unknown = canonicalKeyOrder(Object.keys(parsed).filter((n) => !KNOWN_MEMBERS.has(n)))
  if (unknown.length > 0) throw new TrustMaterialError(unknownMember(unknown[0]!))
  const fields: Record<string, unknown> = {}
  for (const [name, kinds, phrase] of MEMBER_SHAPES) {
    if (!Object.hasOwn(parsed, name)) {
      if (REQUIRED_MEMBERS.has(name)) throw new TrustMaterialError(memberShape(name, phrase), name)
      // Absent: read as empty, exported as absent. `Object.create(null)` and
      // never `{}` — a `{}` would answer `chains['toString']` with a function
      // inherited from `Object.prototype`, so an issuer id that happens to be
      // an object-system name would select something the document never
      // carried. A member present with value `null` is NOT this case and falls
      // to the shape check below.
      fields[name] = Object.create(null) as object
      continue
    }
    const value = parsed[name]!
    if (!matchesShape(value, kinds)) throw new TrustMaterialError(memberShape(name, phrase), name)
    fields[name] = value
  }
  return fields as unknown as StoreData
}

/** The five member trees of an admitted store document. */
export interface StoreData {
  manifests: Record<string, JsonObject>
  provenance: Record<string, string>
  chains: Record<string, JsonObject[]>
  artifact_manifests: Record<string, Record<string, JsonObject>>
  artifact_manifest_chains: Record<string, Record<string, JsonObject[]>>
}

/**
 * Trust material that cannot be admitted as data.
 *
 * `member` names the trust-store member that failed, when the failure happened
 * inside one. A refusal that accuses the wrong member sends whoever receives
 * it to debug the wrong half of their configuration, so the name travels with
 * the error instead of being guessed by the caller. Python parity:
 * `trust_material.TrustMaterialError.member`.
 */
export class TrustMaterialError extends Error {
  readonly member: string | null
  constructor(message: string, member: string | null = null) {
    super(message)
    this.name = 'TrustMaterialError'
    this.member = member
  }
}

// Module sentinel. NOT `Symbol.for`: a registered symbol is reachable by
// description from any code in the realm, which would make the token a
// password anyone can look up. This one is never exported and never stored on
// an object a caller can reach, so the only way to hold it is to be this file.
const ADMIT: unique symbol = Symbol('attest.trustMaterial.admit')

// Declared BEFORE the classes: the static blocks below assign them during
// class evaluation, and a `let` declared after the class would still be in its
// temporal dead zone when that block runs.
//
// These two are the doors' way in. They are exported from this MODULE for the
// rest of the package and never from `index.ts` — a snapshot's internal tree
// leaving the package is exactly the shape C-216 was about.
export let manifestData!: (m: unknown) => JsonObject | null
export let storeData!: (s: unknown) => StoreData | null

/**
 * A key manifest that was parsed from bytes by this library, and nothing else.
 *
 * The constructor exists in the type system — a caller can write it — and
 * refuses everyone who is not this file. Holding one of these is therefore the
 * proof that the bytes went through `parseKeyManifest`, which is what every
 * door downstream needs to know and what it could not learn from a live object.
 */
export class KeyManifest {
  #data: JsonObject
  #canonical: Uint8Array

  constructor(token: symbol, data: JsonObject, canonical: Uint8Array) {
    // Identity, and never equality: `!==` on symbols runs no user code, so a
    // caller cannot forge admission with something that compares equal.
    if (token !== ADMIT) throw new TypeError('KeyManifest is built by parseKeyManifest(bytes)')
    this.#data = data
    this.#canonical = canonical
  }

  /**
   * The brand: a private field is present only on an instance this class built.
   *
   * `instanceof` would answer for `Object.create(KeyManifest.prototype)` and
   * for a Proxy over one; a private-field check answers false for both, and a
   * Proxy cannot forward it, so no trap of a hostile wrapper ever runs.
   */
  static is(x: unknown): x is KeyManifest {
    try {
      return #data in (x as object)
    } catch {
      return false
    }
  }

  /** The canonical bytes computed at import. A fresh copy every call (INV-5). */
  toBytes(): Uint8Array {
    return new Uint8Array(this.#canonical)
  }

  /**
   * A fresh tree of parser types, every call.
   *
   * Re-parsed rather than returned: handing back the internal tree would let a
   * caller mutate what a later reader sees, and two readers of the same
   * snapshot disagreeing is the whole class of defect this boundary ends.
   */
  data(): JsonObject {
    return loadsStrict(this.#canonical) as JsonObject
  }

  static {
    manifestData = (m: unknown): JsonObject | null => (KeyManifest.is(m) ? m.#data : null)
  }
}

/** A trust store parsed from bytes: five member trees plus the bytes they came from. */
export class TrustStore {
  #manifests: Record<string, JsonObject>
  #provenance: Record<string, string>
  #chains: Record<string, JsonObject[]>
  #artifactManifests: Record<string, Record<string, JsonObject>>
  #artifactManifestChains: Record<string, Record<string, JsonObject[]>>
  #canonical: Uint8Array

  constructor(token: symbol, fields: StoreData, canonical: Uint8Array) {
    if (token !== ADMIT) throw new TypeError('TrustStore is built by parseTrustStore(bytes)')
    this.#manifests = fields.manifests
    this.#provenance = fields.provenance
    this.#chains = fields.chains
    this.#artifactManifests = fields.artifact_manifests
    this.#artifactManifestChains = fields.artifact_manifest_chains
    this.#canonical = canonical
  }

  static is(x: unknown): x is TrustStore {
    try {
      return #manifests in (x as object)
    } catch {
      return false
    }
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.#canonical)
  }

  data(): JsonObject {
    return loadsStrict(this.#canonical) as JsonObject
  }

  /**
   * The issuer ids, in the order the SIGNED BYTES put them in.
   *
   * `canonicalKeyOrder` and not a bare `.sort()`, even though in this language
   * the two are the same call: the bare form is what let the Python twin drift
   * to CODE POINT order without either suite being able to see it, because each
   * suite used its own language's default sort as the oracle and so agreed with
   * itself. Naming the rule is what makes it checkable that both cores use one.
   */
  issuers(): string[] {
    return canonicalKeyOrder(Object.keys(this.#manifests))
  }

  // D18 on all three selectors: the type check comes BEFORE any indexing, so a
  // hostile object's `Symbol.toPrimitive`/`toString`/`valueOf` never runs. A
  // `String` wrapper is refused too — it is an object, and the thing that gets
  // past a lookup is precisely a value that coerces to a real key.
  manifestFor(issuer: unknown): KeyManifest | null {
    if (typeof issuer !== 'string') return null
    const found = this.#manifests[issuer]
    return found === undefined ? null : new KeyManifest(ADMIT, found, canonicalBytes(found))
  }

  chainFor(issuer: unknown): KeyManifest[] {
    if (typeof issuer !== 'string') return []
    const found = this.#chains[issuer]
    if (found === undefined) return []
    return found.map((m) => new KeyManifest(ADMIT, m, canonicalBytes(m)))
  }

  provenanceFor(issuer: unknown): string | null {
    if (typeof issuer !== 'string') return null
    const found = this.#provenance[issuer]
    return found === undefined ? null : found
  }

  static {
    storeData = (s: unknown): StoreData | null =>
      TrustStore.is(s)
        ? {
            manifests: s.#manifests,
            provenance: s.#provenance,
            chains: s.#chains,
            artifact_manifests: s.#artifactManifests,
            artifact_manifest_chains: s.#artifactManifestChains,
          }
        : null
  }
}

/** One key manifest, from its serialized bytes. Throws `TrustMaterialError`. */
export function parseKeyManifest(data: unknown): KeyManifest {
  const parsed = parseDocument(data, 'key manifest')
  if (!isPlainObject(parsed)) throw new TrustMaterialError(notObject('key manifest'))
  return new KeyManifest(ADMIT, parsed, canonicalOf(parsed, 'key manifest'))
}

/** A trust store, from its serialized bytes. Throws `TrustMaterialError`. */
export function parseTrustStore(data: unknown): TrustStore {
  const parsed = parseDocument(data, 'trust store')
  const fields = validatedStoreDocument(parsed)
  // On the document AS RECEIVED (D17): an absent member stays absent in what
  // `toBytes()` gives back, which is not the same document as one carrying an
  // empty member. `canonicalOf` runs after the grammar so a shape complaint
  // reaches the caller before a representability one.
  return new TrustStore(ADMIT, fields, canonicalOf(parsed, 'trust store'))
}
