/// <reference lib="es2024.arraybuffer" />
/// <reference lib="es2024.sharedmemory" />
// The two directives above are the file's own declaration of what it needs,
// and they belong here rather than in a compiler flag: this suite is the only
// place in the repo that constructs a RESIZABLE ArrayBuffer and a GROWABLE
// SharedArrayBuffer, because those are two of the shapes the boundary has to
// refuse or survive (M10, M11, INV-5). The package targets ES2022 and G-TS-TC-F6
// typechecks with that target pinned (P-27); widening the target for everyone
// to typecheck one test file would move a decision about the shipped library
// into a test's convenience. A `reference lib` is scoped to this file and is
// erased at runtime, so it changes nothing that ships.
//
// They sit above the module docstring because a triple-slash directive is only
// honoured in a file's leading trivia. The FIRST IMPORT is still
// `../src/manifests.js`, which is the property section 5.6(b) measures.
/**
 * The serialized entry to the verifier's local trust material — TypeScript twin
 * of `tests/test_trust_material_parse.py` (front F6, T1).
 *
 * THE FIRST IMPORT IS DELIBERATE AND IS PART OF WHAT THIS FILE MEASURES
 * ---------------------------------------------------------------------
 * Section 5.6(b): `manifests.ts` imports `trustMaterial.ts` and `trustMaterial.ts`
 * must not import it back at runtime. The two initialization orders are
 * exercised by two test files with different FIRST imports — the index-surface
 * suite starts from `../src/index.js`, this one starts from `../src/manifests.js`
 * — and vitest isolates files, so both orders really run. Moving the `vitest`
 * import above it would leave only one order tested, and the one that breaks is
 * always the other one.
 *
 * WHAT THIS FILE MEASURES
 * -----------------------
 * INV-1   conservation: a well-formed document goes in and comes back out of
 *         the snapshot unchanged, INCLUDING which optional members were
 *         present. Absent is not empty, all the way to `toBytes()`.
 * INV-1b  admissibility: an oracle written from the FORMAT — `JSON.parse`, a
 *         token scanner written here, this file's own transcription of the
 *         container grammar — decides for every mutant whether the boundary
 *         must accept or refuse. The oracle never calls `canon.ts` and never
 *         calls the code under test, so it is able to contradict them.
 * INV-3   refusal of the whole unit: a defective document yields ONE error, of
 *         the class the evaluation order prescribes, naming the member at
 *         fault, and no half-built snapshot.
 * INV-4   contract refusal before any hook: a value presented in place of the
 *         bytes is refused with a constant message and WITHOUT a single trap,
 *         getter or coercion of that value running. The empty registry is the
 *         evidence; the exception alone would not be.
 * INV-5   no aliasing: `data()` and `toBytes()` hand back fresh values every
 *         call, and the bytes the caller supplied can be overwritten — or the
 *         buffer resized away — without the snapshot noticing.
 * D15     custody: the snapshot classes are built by their factories or not at
 *         all, and their surface is exactly the declared one.
 * D18     selectors: a lookup key that is not exactly a primitive string is
 *         answered before any coercion of it happens.
 *
 * WHAT IT DOES NOT MEASURE
 * ------------------------
 * The ports. At T1 no public signature takes a snapshot yet, so an impostor
 * offered to `verify()` still travels the old path; that is INV-4 of section
 * 6.4 and it belongs to T3. What is measured here is the boundary itself.
 *
 * The `// @ts-expect-error` directive on the old `TrustStore` shape is NOT
 * written here either, and that is a measurement rather than an omission: at
 * T1 `verify` still accepts the old interface, so the directive would be
 * unused and `tsc` reports an unused directive as an error. It is born in T3,
 * with the old shape spelled COMPLETE — `{ manifests: {}, provenance: {} }` —
 * because the incomplete spelling is already an error for the missing member
 * and would certify nothing.
 */
import { findKey, verifyArtifactManifest } from '../src/manifests.js'
import vm from 'node:vm'
import { describe, expect, it } from 'vitest'
import {
  CanonError,
  MAX_ADMISSION_BYTES,
  MAX_DEPTH as CANON_MAX_DEPTH,
  canonicalBytes,
  type JsonObject,
  type JsonValue,
} from '../src/canon.js'
import * as MSG from '../src/messages.js'
import {
  KeyManifest,
  TrustMaterialError,
  TrustStore,
  manifestData,
  parseKeyManifest,
  parseTrustStore,
  storeData,
  type StoreData,
} from '../src/trustMaterial.js'
import { readFileSync } from 'node:fs'
import { manifestDoc, storeBytes } from './helpers/trust.js'

/**
 * The cross-language fixture, read here for the ONE thing this suite needs from
 * it: which unknown member each core names. The rendering half of the same file
 * is measured by `messages.test.ts`, which does not have a parser and does not
 * need one.
 */
const MESSAGE_FIXTURE = JSON.parse(
  readFileSync(
    new URL('../../../tests/fixtures/trust-material-messages.json', import.meta.url),
    'utf8',
  ),
) as { unknown_member_choice: Array<{ document: string; expected: string }> }

// ---------------------------------------------------------------------------
// The format's own numbers, transcribed rather than imported: this file has to
// be able to disagree with the library about them. One test asserts the
// transcription still matches, so a drift is loud instead of silent.
// ---------------------------------------------------------------------------

const CEILING_BYTES = 10_000_000
const MAX_DEPTH = 256
const INT_LIMIT = 2n ** 53n // exclusive on both sides: |n| < 2**53

const WHAT_STORE = 'trust store'
const WHAT_MANIFEST = 'key manifest'

// The container grammar of section 5.3, transcribed: the nesting path from each
// member down to its leaves, in the order the boundary evaluates them.
const MEMBER_KINDS: Record<string, readonly string[]> = {
  manifests: ['object', 'object'],
  provenance: ['object', 'string'],
  chains: ['object', 'array', 'object'],
  artifact_manifests: ['object', 'object', 'object'],
  artifact_manifest_chains: ['object', 'object', 'array', 'object'],
}
const MEMBER_ORDER = Object.keys(MEMBER_KINDS)
const REQUIRED_MEMBERS = ['manifests', 'provenance']
const OPTIONAL_MEMBERS = ['chains', 'artifact_manifests', 'artifact_manifest_chains']

/**
 * The wording the grammar fixes for a member, DERIVED from its nesting path.
 *
 * Retyping the five phrases would pin the retyping: the phrase and the check
 * have to come from one place or they will eventually describe different
 * grammars, and the message is what a caller uses to fix their document.
 */
function expectedPhrase(member: string): string {
  const kinds = MEMBER_KINDS[member]!
  const plural: Record<string, string> = { object: 'objects', array: 'arrays', string: 'strings' }
  return 'an object' + kinds.slice(1).map((kind) => ` of ${plural[kind]!}`).join('')
}

// ---------------------------------------------------------------------------
// Reading a refusal. Messages are read from `messages.ts`, never retyped: a
// test carrying its own copy of a message pins the copy.
// ---------------------------------------------------------------------------

const PROBE = 'PROBE-c0ffee'

/** The part of `full` that comes before `tail`, which must be in it. */
function headBefore(full: string, tail: string): string {
  const at = full.indexOf(tail)
  if (at < 0) throw new Error(`expected ${JSON.stringify(tail)} inside ${JSON.stringify(full)}`)
  return full.slice(0, at)
}

/** The constant head of message `id`, derived from the builder itself. */
function messagePrefix(id: string, what: string): string {
  switch (id) {
    case 'M1':
      return MSG.notBytes(what)
    case 'M2':
      return MSG.tooLarge(what)
    case 'M4':
      return MSG.notObject(what)
    case 'M9':
      return MSG.notByteView(what)
    case 'M10':
      return MSG.sharedMemory(what)
    case 'M11':
      return MSG.detachedBuffer(what)
    case 'M5':
      return headBefore(MSG.unknownMember(PROBE), MSG.pyStage2StringRepr(PROBE))
    case 'M6':
      return headBefore(MSG.memberShape(PROBE, 'x'), MSG.pyStage2StringRepr(PROBE))
    case 'M7':
      return headBefore(MSG.unparsable(what, PROBE), PROBE)
    case 'M8':
      return headBefore(MSG.notCanonical(what, PROBE), PROBE)
    default:
      throw new Error(`unknown message id ${id}`)
  }
}

const MESSAGE_IDS = ['M1', 'M2', 'M4', 'M5', 'M6', 'M7', 'M8', 'M9', 'M10', 'M11'] as const

/**
 * Which message template produced `error`.
 *
 * The LONGEST matching head wins. Two heads can both match — M4's
 * "<what> document must be a JSON object" and M5's "<what> document has an
 * unknown member" share an opening — and taking the first match would classify
 * by declaration order, which is not a property of the message at all.
 */
function classify(error: TrustMaterialError, what: string): string {
  const matches = MESSAGE_IDS.filter((id) => error.message.startsWith(messagePrefix(id, what)))
  if (matches.length === 0) throw new Error(`refusal matches no message template: ${error.message}`)
  let best = matches[0]!
  for (const id of matches) {
    if (messagePrefix(id, what).length > messagePrefix(best, what).length) best = id
  }
  return best
}

/** Run `call`, require a `TrustMaterialError`, hand it back for inspection. */
function refusal(call: () => unknown): TrustMaterialError {
  let thrown: unknown
  let threw = false
  try {
    call()
  } catch (e) {
    threw = true
    thrown = e
  }
  expect(threw, 'the call was expected to be refused and returned instead').toBe(true)
  expect(thrown, `expected a TrustMaterialError, got ${String(thrown)}`).toBeInstanceOf(TrustMaterialError)
  return thrown as TrustMaterialError
}

function refusedAs(
  call: () => unknown,
  id: string,
  options: { what?: string; member?: string | null } = {},
): TrustMaterialError {
  const what = options.what ?? WHAT_STORE
  const member = options.member ?? null
  const error = refusal(call)
  expect(classify(error, what), `expected ${id}, got ${JSON.stringify(error.message)}`).toBe(id)
  expect(error.member, `expected member ${String(member)}, got ${String(error.member)}`).toBe(member)
  return error
}

const parseStore = (payload: unknown): TrustStore => parseTrustStore(payload)
const parseManifest = (payload: unknown): KeyManifest => parseKeyManifest(payload)

// ---------------------------------------------------------------------------
// Ground truth documents. Built as trees FIRST and serialized second: the tree
// is the truth the snapshot is compared against, and it exists before the
// library has seen anything.
// ---------------------------------------------------------------------------

const PUBLIC_MATERIAL = '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29'
const PLAIN_ISSUERS = ['store.example.com', 'shop.example.org', 'market.example.net']
// Names that mean something to an object system and nothing to a JSON document.
const SPECIAL_ISSUERS = ['__proto__', '', 'toString', 'constructor', 'hasOwnProperty']
const SERIES = 'works/EXG-001'

function keyManifestTree(issuer: string, version: number): JsonObject {
  return {
    manifest_version: BigInt(version),
    issuer,
    keys: [
      {
        kid: `${issuer}/keys/manifest#ed25519-${version}`,
        alg: 'ed25519',
        public_key: PUBLIC_MATERIAL,
        status: 'active',
        valid_from: '2026-01-01T00:00:00Z',
        valid_to: null,
      },
    ],
  }
}

function artifactManifestTree(issuer: string, version: number): JsonObject {
  return {
    manifest_version: BigInt(version),
    series: `${issuer}/works/EXG-001`,
    artifacts: [{ role: 'installer', sha256: PUBLIC_MATERIAL }],
  }
}

interface DocumentOptions {
  chainLength?: number
  artifacts?: boolean
  absent?: readonly string[]
  empty?: readonly string[]
}

function mapOf(issuers: readonly string[], value: (issuer: string) => JsonValue): JsonObject {
  const out: JsonObject = {}
  // Assigned one by one rather than through `Object.fromEntries` so the
  // construction is visibly a data property even for `__proto__`, which is one
  // of the issuer ids this suite deliberately carries.
  for (const issuer of issuers) Object.defineProperty(out, issuer, { value: value(issuer), enumerable: true, writable: true, configurable: true })
  return out
}

function document(issuers: readonly string[], options: DocumentOptions = {}): JsonObject {
  const chainLength = options.chainLength ?? 1
  const artifacts = options.artifacts ?? true
  const tree: JsonObject = {}
  tree.manifests = mapOf(issuers, (i) => keyManifestTree(i, 1))
  tree.provenance = mapOf(issuers, () => 'tls')
  tree.chains = mapOf(issuers, (i) =>
    Array.from({ length: chainLength }, (_unused, k) => keyManifestTree(i, k + 1)),
  )
  if (artifacts) {
    tree.artifact_manifests = mapOf(issuers, (i) => mapOf([SERIES], () => artifactManifestTree(i, 1)))
    tree.artifact_manifest_chains = mapOf(issuers, (i) =>
      mapOf([SERIES], () => [artifactManifestTree(i, 1)]),
    )
  }
  for (const name of options.absent ?? []) delete tree[name]
  for (const name of options.empty ?? []) tree[name] = {}
  return tree
}

const SMALL_DOCUMENT = document(PLAIN_ISSUERS.slice(0, 1), { chainLength: 1, artifacts: false })
const RICH_DOCUMENT = document(PLAIN_ISSUERS.slice(0, 1), { chainLength: 1, artifacts: true })

/** A deep copy, so a mutating test cannot corrupt a shared fixture. */
function clone<T>(value: T): T {
  return structuredClone(value)
}

/**
 * `doc` plus one member called `name`, as a DATA property.
 *
 * `doc[name] = value` is not the same thing and the difference is silent: on
 * any object that inherits from `Object.prototype`, assigning to `__proto__`
 * runs the inherited SETTER and changes the prototype instead of adding a
 * member. The mutant then serializes without the member and the document under
 * test is a valid one — a green test measuring nothing. Found by this suite
 * failing on exactly that case, which is why the corpus carries the name.
 */
function withMember(doc: JsonObject, name: string, value: JsonValue): JsonObject {
  const out: JsonObject = { ...doc }
  Object.defineProperty(out, name, { value, enumerable: true, writable: true, configurable: true })
  return out
}

// ---------------------------------------------------------------------------
// Serialization and comparison. Neither touches the library.
// ---------------------------------------------------------------------------

function jsonText(node: unknown): string {
  if (typeof node === 'bigint') return node.toString()
  if (node === null) return 'null'
  if (typeof node === 'boolean' || typeof node === 'number') return String(node)
  if (typeof node === 'string') return JSON.stringify(node)
  if (Array.isArray(node)) return '[' + node.map(jsonText).join(',') + ']'
  if (typeof node === 'object') {
    return (
      '{' +
      Object.entries(node as Record<string, unknown>)
        .map(([k, v]) => JSON.stringify(k) + ':' + jsonText(v))
        .join(',') +
      '}'
    )
  }
  throw new Error(`cannot serialize ${typeof node}`)
}

/** JSON text for a tree that may carry `bigint`, written without `canon`. */
function serialize(tree: unknown): Uint8Array {
  return new TextEncoder().encode(jsonText(tree))
}

/**
 * A canonical-enough rendering for comparison — and the comparator the plan
 * asks for: `bigint` on one side is only ever equal to `bigint` on the other.
 *
 * A `number` renders with a marker no `bigint` can produce, so a snapshot that
 * quietly turned `1n` into `1` is a mismatch rather than a match. That is the
 * whole reason the profile carries `bigint` at all: an integer that survived a
 * round trip through `number` is not the integer the issuer signed.
 */
function ordered(node: unknown): string {
  if (typeof node === 'bigint') return `#${node.toString()}`
  if (node === null) return 'null'
  if (typeof node === 'boolean') return String(node)
  if (typeof node === 'number') return `?number:${String(node)}`
  if (typeof node === 'string') return JSON.stringify(node)
  if (Array.isArray(node)) return '[' + node.map(ordered).join(',') + ']'
  if (node !== undefined && typeof node === 'object') {
    const keys = Object.keys(node as object).sort()
    return (
      '{' +
      keys
        .map((k) => JSON.stringify(k) + ':' + ordered((node as Record<string, unknown>)[k]))
        .join(',') +
      '}'
    )
  }
  return `?${typeof node}`
}

function sameTree(a: unknown, b: unknown): boolean {
  return ordered(a) === ordered(b)
}

/** Container nesting depth of a tree, walked by this file. */
function depthOf(node: unknown): number {
  let deepest = 0
  const stack: Array<[unknown, number]> = [[node, 1]]
  while (stack.length > 0) {
    const [current, depth] = stack.pop()!
    if (Array.isArray(current)) {
      deepest = Math.max(deepest, depth)
      for (const item of current) stack.push([item, depth + 1])
    } else if (current !== null && typeof current === 'object') {
      deepest = Math.max(deepest, depth)
      for (const value of Object.values(current as Record<string, unknown>)) {
        stack.push([value, depth + 1])
      }
    }
  }
  return deepest
}

function deepDocument(totalDepth: number): JsonObject {
  const chainLength = totalDepth - 3
  if (chainLength < 1) throw new Error('depth fixture too shallow')
  let node: JsonValue = {}
  for (let i = 0; i < chainLength - 1; i++) node = { n: node }
  const tree: JsonObject = { manifests: { i: { deep: node } }, provenance: { i: 'tls' } }
  // A depth fixture that is off by one turns a boundary test into a test of
  // the interior, silently. The builder verifies its own construction.
  if (depthOf(tree) !== totalDepth) {
    throw new Error('the depth fixture does not have the depth it claims')
  }
  return tree
}

/**
 * A valid document whose one manifest carries `literal` verbatim as a value.
 *
 * Written as TEXT because the cases that matter — `-0`, a float spelling, a
 * 4301-digit token — do not survive a JavaScript tree.
 */
function documentWithLiteral(literal: string): Uint8Array {
  return new TextEncoder().encode(
    '{"manifests":{"i":{"issuer":"i","probe":' + literal + '}},"provenance":{"i":"tls"}}',
  )
}

/** A well-formed document padded with legal whitespace to exactly `total` bytes. */
function paddedDocument(total: number): Uint8Array {
  const body = serialize(SMALL_DOCUMENT)
  if (body.byteLength > total) throw new Error('padding target smaller than the document')
  const out = new Uint8Array(total)
  out.fill(0x20)
  out.set(body, 0)
  return out
}

// ---------------------------------------------------------------------------
// INV-1b: the admissibility oracle. `JSON.parse`, a token scanner written
// here, and this file's grammar — never `canon.ts`. It must be able to say
// "the format admits this" about a document the importer refuses.
// ---------------------------------------------------------------------------

interface TokenScan {
  duplicate: string | null
  fractionalToken: string | null
  integerTokens: string[]
}

/**
 * Object keys and number tokens, scanned independently of `JSON.parse`.
 *
 * `JSON.parse` is a genuinely separate parser and is used as the structural
 * oracle, but it HIDES exactly two things the profile refuses: a duplicate
 * member (it keeps the last one) and the difference between an integer and a
 * float (both arrive as `number`, and an integer past 2^53 arrives rounded).
 * This scanner recovers those two from the raw text, and nothing else.
 *
 * It is only ever run on text `JSON.parse` has already accepted, so it does not
 * have to diagnose malformed input — which is what keeps it short enough to be
 * read and trusted.
 */
function scanTokens(text: string): TokenScan {
  type Level = { kind: 'object' | 'array'; seen: Set<string> }
  const stack: Level[] = []
  let duplicate: string | null = null
  let fractionalToken: string | null = null
  const integerTokens: string[] = []
  let expectKey = false
  let i = 0
  while (i < text.length) {
    const c = text[i]!
    if (c === '{') {
      stack.push({ kind: 'object', seen: new Set() })
      expectKey = true
      i++
    } else if (c === '[') {
      stack.push({ kind: 'array', seen: new Set() })
      expectKey = false
      i++
    } else if (c === '}' || c === ']') {
      stack.pop()
      expectKey = false
      i++
    } else if (c === ',') {
      expectKey = stack[stack.length - 1]?.kind === 'object'
      i++
    } else if (c === ':') {
      expectKey = false
      i++
    } else if (c === '"') {
      const start = i
      i++
      while (i < text.length) {
        if (text[i] === '\\') {
          i += 2
          continue
        }
        if (text[i] === '"') {
          i++
          break
        }
        i++
      }
      if (expectKey) {
        const key = JSON.parse(text.slice(start, i)) as string
        const level = stack[stack.length - 1]
        if (level !== undefined) {
          if (level.seen.has(key)) duplicate = key
          level.seen.add(key)
        }
        expectKey = false
      }
    } else if (c === '-' || (c >= '0' && c <= '9')) {
      const token = /^-?[0-9]*\.?[0-9]*(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i))![0]
      if (/[.eE]/.test(token)) fractionalToken = token
      else integerTokens.push(token)
      i += token.length
    } else {
      i++
    }
  }
  return { duplicate, fractionalToken, integerTokens }
}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i)
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const lo = s.charCodeAt(i + 1)
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        i++
        continue
      }
      return true
    }
    if (cp >= 0xdc00 && cp <= 0xdfff) return true
  }
  return false
}

function anyLoneSurrogate(node: unknown): boolean {
  if (typeof node === 'string') return hasLoneSurrogate(node)
  if (Array.isArray(node)) return node.some(anyLoneSurrogate)
  if (node !== null && typeof node === 'object') {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (hasLoneSurrogate(k) || anyLoneSurrogate(v)) return true
    }
  }
  return false
}

/** `JSON.parse`'s `number`s widened to the `bigint` the profile carries. */
function widenIntegers(node: unknown): unknown {
  if (typeof node === 'number') {
    if (!Number.isSafeInteger(node)) throw new Error(`the oracle cannot widen ${String(node)}`)
    return BigInt(node)
  }
  if (Array.isArray(node)) return node.map(widenIntegers)
  if (node !== null && typeof node === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) out[k] = widenIntegers(v)
    return out
  }
  return node
}

/** This file's transcription of section 5.3, used as the oracle's grammar. */
function matchesShape(value: unknown, kinds: readonly string[]): boolean {
  const kind = kinds[0]
  const rest = kinds.slice(1)
  if (kind === 'object') {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
    if (rest.length === 0) return true
    return Object.values(value as Record<string, unknown>).every((v) => matchesShape(v, rest))
  }
  if (kind === 'array') {
    if (!Array.isArray(value)) return false
    if (rest.length === 0) return true
    return value.every((v) => matchesShape(v, rest))
  }
  return typeof value === 'string'
}

/** `[refusal id, member]` for the grammar, or `null` when the document passes it. */
function grammarRefusal(parsed: unknown): [string, string | null] | null {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return ['M4', null]
  const doc = parsed as Record<string, unknown>
  for (const name of Object.keys(doc)) {
    if (!Object.hasOwn(MEMBER_KINDS, name)) return ['M5', null]
  }
  for (const name of MEMBER_ORDER) {
    if (!Object.hasOwn(doc, name)) {
      if (REQUIRED_MEMBERS.includes(name)) return ['M6', name]
      continue
    }
    if (!matchesShape(doc[name], MEMBER_KINDS[name]!)) return ['M6', name]
  }
  return null
}

interface OracleVerdict {
  refusal: string | null
  member: string | null
  parsed: unknown
}

/**
 * `(refusal id, member, parsed tree)` for `payload`, decided from the FORMAT.
 *
 * The order mirrors section 5.1.1 — ceiling, parse, container grammar,
 * canonical representability — because a document with two defects must be
 * predicted by the same order the importer applies.
 */
function oracle(payload: Uint8Array): OracleVerdict {
  const refuse = (id: string, member: string | null = null): OracleVerdict => ({
    refusal: id,
    member,
    parsed: null,
  })
  if (payload.byteLength > CEILING_BYTES) return refuse('M2')
  let text: string
  try {
    // `ignoreBOM: true` keeps a leading U+FEFF in the decoded text instead of
    // silently eating it, which is what makes the BOM case visible at all: the
    // profile has no rule that removes it, so it reaches the parser as a
    // character no document may start with.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload)
  } catch {
    return refuse('M7')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text) as unknown
  } catch {
    return refuse('M7')
  }
  const tokens = scanTokens(text)
  if (tokens.fractionalToken !== null) return refuse('M7')
  if (tokens.duplicate !== null) return refuse('M7')
  if (depthOf(parsed) > MAX_DEPTH || anyLoneSurrogate(parsed)) return refuse('M7')
  const violation = grammarRefusal(parsed)
  if (violation !== null) return { refusal: violation[0]!, member: violation[1], parsed }
  for (const token of tokens.integerTokens) {
    const value = BigInt(token)
    if (!(-INT_LIMIT < value && value < INT_LIMIT)) return { refusal: 'M8', member: null, parsed }
  }
  return { refusal: null, member: null, parsed: widenIntegers(parsed) }
}

// ---------------------------------------------------------------------------
// The hostile corpus of section 6.2: mutations of a valid document's BYTES.
// ---------------------------------------------------------------------------

const DUPLICATE_KEY_DOCUMENTS: Array<[string, string]> = [
  ['duplicate top-level member', '{"manifests":{},"provenance":{},"chains":{},"chains":{}}'],
  [
    'duplicate top-level member spelled with an escape',
    '{"manifests":{},"provenance":{},"chains":{},"\\u0063hains":{}}',
  ],
  ['duplicate issuer inside manifests', '{"manifests":{"i":{},"i":{}},"provenance":{"i":"tls"}}'],
  [
    'duplicate field inside a manifest',
    '{"manifests":{"i":{"issuer":"a","issuer":"b"}},"provenance":{"i":"tls"}}',
  ],
  [
    'duplicate field inside a keys entry',
    '{"manifests":{"i":{"keys":[{"status":"active","status":"compromised"}]}},"provenance":{"i":"tls"}}',
  ],
]

const UNKNOWN_MEMBER_NAMES = [
  'Manifests',
  'manifests ',
  '__proto__',
  'constructor',
  'toString',
  'hasOwnProperty',
  '',
  "it's",
]

function withBom(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(payload.byteLength + 3)
  out.set([0xef, 0xbb, 0xbf], 0)
  out.set(payload, 3)
  return out
}

const LEXICAL_MUTANTS: Array<[string, Uint8Array, string]> = [
  ['byte order mark', withBom(serialize(SMALL_DOCUMENT)), 'M7'],
  [
    'lone surrogate in an issuer id',
    new TextEncoder().encode('{"manifests":{"\\ud800":{}},"provenance":{}}'),
    'M7',
  ],
  ['float 1.5', documentWithLiteral('1.5'), 'M7'],
  ['float 1e3', documentWithLiteral('1e3'), 'M7'],
  ['float -0.0', documentWithLiteral('-0.0'), 'M7'],
  ['float 1e400', documentWithLiteral('1e400'), 'M7'],
  ['NaN', documentWithLiteral('NaN'), 'M7'],
  ['Infinity', documentWithLiteral('Infinity'), 'M7'],
  ['integer just inside the safe range', documentWithLiteral('9007199254740991'), 'accepted'],
  [
    'negative integer just inside the safe range',
    documentWithLiteral('-9007199254740991'),
    'accepted',
  ],
  ['integer one past the safe range', documentWithLiteral('9007199254740992'), 'M8'],
  ['negative integer one past the safe range', documentWithLiteral('-9007199254740992'), 'M8'],
  ['minus zero', documentWithLiteral('-0'), 'accepted'],
  ['a 4300-digit integer', documentWithLiteral('9'.repeat(4300)), 'M8'],
  // Declared divergence (D16): Python's int-to-str conversion refuses past
  // 4300 digits and surfaces it as a PARSE failure, so the same token is M7
  // there and M8 here. Neither core produces an object, which is the property
  // that matters; the class differs and the plan says so rather than hiding it.
  ['a 4301-digit integer', documentWithLiteral('9'.repeat(4301)), 'M8'],
]

interface TypeMatrixCase {
  label: string
  tree: JsonObject
  member: string
  shouldPass: boolean
}

const PROBE_VALUES: Array<[string, JsonValue]> = [
  ['null', null],
  ['true', true],
  ['1', 1n],
  ['"s"', 's'],
  ['[]', []],
  ['{}', {}],
  ['[1]', [1n]],
  ['[{}]', [{}]],
  ['{"k":1}', { k: 1n }],
]

/** Replace every node `depth` levels under `node` along `kinds` with `value`. */
function substituteAt(
  node: unknown,
  kinds: readonly string[],
  depth: number,
  value: JsonValue,
): JsonValue {
  if (depth === 0) return value
  const kind = kinds[0]
  const rest = kinds.slice(1)
  if (kind === 'object' && node !== null && typeof node === 'object' && !Array.isArray(node)) {
    const out: JsonObject = {}
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      out[k] = substituteAt(v, rest, depth - 1, value)
    }
    return out
  }
  if (kind === 'array' && Array.isArray(node)) {
    return node.map((v) => substituteAt(v, rest, depth - 1, value))
  }
  return node as JsonValue
}

function typeMatrixCases(): TypeMatrixCase[] {
  const cases: TypeMatrixCase[] = []
  for (const member of MEMBER_ORDER) {
    const kinds = MEMBER_KINDS[member]!
    for (let depth = 0; depth < kinds.length; depth++) {
      for (const [label, probe] of PROBE_VALUES) {
        const mutated = substituteAt(RICH_DOCUMENT[member], kinds, depth, probe)
        const tree: JsonObject = { ...RICH_DOCUMENT }
        tree[member] = mutated
        cases.push({
          label: `${member}@${depth}:=${label}`,
          tree,
          member,
          shouldPass: matchesShape(mutated, kinds),
        })
      }
    }
  }
  return cases
}

const TYPE_MATRIX_CASES = typeMatrixCases()

function byteMutantCorpus(): Array<[string, Uint8Array]> {
  const valid = serialize(SMALL_DOCUMENT)
  const corpus: Array<[string, Uint8Array]> = [['the unmutated document', valid]]
  for (let offset = 0; offset < valid.byteLength; offset++) {
    corpus.push([`truncated at ${offset}`, valid.slice(0, offset)])
  }
  for (let offset = 0; offset < valid.byteLength; offset++) {
    for (const mask of [0x01, 0x20, 0x80]) {
      const mutant = valid.slice()
      mutant[offset] = valid[offset]! ^ mask
      corpus.push([`byte ${offset} flipped with 0x${mask.toString(16).padStart(2, '0')}`, mutant])
    }
  }
  for (const [name, text] of DUPLICATE_KEY_DOCUMENTS) {
    corpus.push([name, new TextEncoder().encode(text)])
  }
  for (const [name, payload] of LEXICAL_MUTANTS) corpus.push([name, payload])
  for (const name of UNKNOWN_MEMBER_NAMES) {
    corpus.push([`unknown member ${JSON.stringify(name)}`, serialize(withMember(SMALL_DOCUMENT, name, {}))])
  }
  for (const item of TYPE_MATRIX_CASES) {
    corpus.push([`type matrix ${item.label}`, serialize(item.tree)])
  }
  for (const member of REQUIRED_MEMBERS) {
    corpus.push([
      `missing required member ${member}`,
      serialize(document(PLAIN_ISSUERS.slice(0, 1), { absent: [member] })),
    ])
  }
  corpus.push(['the empty document', new TextEncoder().encode('{}')])
  for (const [label, text] of [
    ['array', '[]'],
    ['string', '"a document"'],
    ['number', '1'],
    ['null', 'null'],
    ['boolean', 'true'],
    ['array wrapping the document', '[{"manifests":{},"provenance":{}}]'],
  ] as Array<[string, string]>) {
    corpus.push([`top level ${label}`, new TextEncoder().encode(text)])
  }
  for (const member of MEMBER_ORDER) {
    const nulled: JsonObject = { ...RICH_DOCUMENT }
    nulled[member] = null
    corpus.push([`member ${member} present as null`, serialize(nulled)])
  }
  for (const totalDepth of [255, 256, 257]) {
    corpus.push([`document of depth ${totalDepth}`, serialize(deepDocument(totalDepth))])
  }
  return corpus
}

const BYTE_MUTANT_CORPUS = byteMutantCorpus()

// ---------------------------------------------------------------------------
// The hostile corpus of section 6.1: values that present themselves AS bytes,
// AS a snapshot, or AS a selector. Every one carries a registry, and the empty
// registry is the property under test.
// ---------------------------------------------------------------------------

const PROXY_TRAPS = [
  'getPrototypeOf',
  'setPrototypeOf',
  'isExtensible',
  'preventExtensions',
  'getOwnPropertyDescriptor',
  'defineProperty',
  'has',
  'get',
  'set',
  'deleteProperty',
  'ownKeys',
  'apply',
  'construct',
] as const

/** A Proxy over `target` whose thirteen traps all record before forwarding. */
function recordingProxy<T extends object>(target: T, hits: string[]): T {
  const handler: Record<string, unknown> = {}
  for (const trap of PROXY_TRAPS) {
    handler[trap] = (...args: unknown[]): unknown => {
      hits.push(trap)
      const forward = (Reflect as unknown as Record<string, (...a: unknown[]) => unknown>)[trap]!
      return forward(...args)
    }
  }
  return new Proxy(target, handler as ProxyHandler<T>)
}

/** A value that answers every coercion protocol, and records being asked. */
function coercionImpostor(hits: string[], text: string): object {
  return {
    get [Symbol.toStringTag]() {
      hits.push('toStringTag')
      return 'Uint8Array'
    },
    [Symbol.toPrimitive](): string {
      hits.push('toPrimitive')
      return text
    },
    toString(): string {
      hits.push('toString')
      return text
    },
    valueOf(): string {
      hits.push('valueOf')
      return text
    },
  }
}

/** The document as bytes, in a view that owns its whole buffer. */
function validBytes(): Uint8Array {
  return Uint8Array.from(serialize(SMALL_DOCUMENT))
}

function detachedView(): Uint8Array {
  const buffer = new ArrayBuffer(64)
  const view = new Uint8Array(buffer)
  structuredClone(buffer, { transfer: [buffer] })
  return view
}

function outOfBoundsView(): Uint8Array {
  const buffer = new ArrayBuffer(64, { maxByteLength: 64 })
  const view = new Uint8Array(buffer, 32, 8)
  buffer.resize(8)
  return view
}

interface Impostor {
  name: string
  build: (hits: string[]) => unknown
  expect: string
}

const BYTE_IMPOSTORS: Impostor[] = [
  {
    name: 'a Proxy over a real Uint8Array',
    build: (hits) => recordingProxy(validBytes(), hits),
    expect: 'M1',
  },
  {
    name: 'an object whose prototype is Uint8Array.prototype',
    build: () => Object.create(Uint8Array.prototype) as object,
    expect: 'M1',
  },
  {
    name: 'a duck-typed byte view',
    build: () => {
      const real = validBytes()
      return { buffer: real.buffer, byteLength: real.byteLength, length: real.length, 0: real[0] }
    },
    expect: 'M1',
  },
  { name: 'a bare ArrayBuffer', build: () => validBytes().buffer, expect: 'M1' },
  { name: 'the document as a string', build: () => jsonText(SMALL_DOCUMENT), expect: 'M1' },
  { name: 'an Array of byte values', build: () => Array.from(validBytes()), expect: 'M1' },
  {
    name: 'an object that answers every coercion protocol',
    build: (hits) => coercionImpostor(hits, jsonText(SMALL_DOCUMENT)),
    expect: 'M1',
  },
  { name: 'null', build: () => null, expect: 'M1' },
  { name: 'undefined', build: () => undefined, expect: 'M1' },
  { name: 'a function returning the bytes', build: () => () => validBytes(), expect: 'M1' },
  {
    name: 'an object literal of the OLD trust-store shape',
    build: () => ({ manifests: {}, provenance: {} }),
    expect: 'M1',
  },
  {
    name: 'a DataView over a valid document',
    build: () => new DataView(validBytes().buffer),
    expect: 'M1',
  },
  { name: 'an Int16Array', build: () => new Int16Array(validBytes().buffer, 0, 8), expect: 'M9' },
  { name: 'an Int32Array', build: () => new Int32Array(validBytes().buffer, 0, 4), expect: 'M9' },
  { name: 'a Uint32Array', build: () => new Uint32Array(validBytes().buffer, 0, 4), expect: 'M9' },
  {
    name: 'a Float32Array',
    build: () => new Float32Array(validBytes().buffer, 0, 4),
    expect: 'M9',
  },
  {
    name: 'a Float64Array',
    build: () => new Float64Array(validBytes().buffer, 0, 2),
    expect: 'M9',
  },
  {
    name: 'a BigInt64Array',
    build: () => new BigInt64Array(validBytes().buffer, 0, 2),
    expect: 'M9',
  },
  {
    name: 'a BigUint64Array',
    build: () => new BigUint64Array(validBytes().buffer, 0, 2),
    expect: 'M9',
  },
  {
    name: 'a view on a fixed SharedArrayBuffer',
    build: () => new Uint8Array(new SharedArrayBuffer(64)),
    expect: 'M10',
  },
  {
    name: 'a view on a growable SharedArrayBuffer',
    build: () => new Uint8Array(new SharedArrayBuffer(64, { maxByteLength: 128 })),
    expect: 'M10',
  },
  { name: 'a view on a detached buffer', build: () => detachedView(), expect: 'M11' },
  { name: 'a view that has gone out of bounds', build: () => outOfBoundsView(), expect: 'M11' },
]

// ---------------------------------------------------------------------------
// Section 0: what this file assumes about the library it measures.
// ---------------------------------------------------------------------------

describe('the assumptions this file is built on', () => {
  it('the transcribed limits are the numbers the library uses', () => {
    expect(MAX_ADMISSION_BYTES).toBe(CEILING_BYTES)
    expect(CANON_MAX_DEPTH).toBe(MAX_DEPTH)
  })

  it('the derived shape phrases are the wording the grammar fixes', () => {
    expect(expectedPhrase('manifests')).toBe('an object of objects')
    expect(expectedPhrase('provenance')).toBe('an object of strings')
    expect(expectedPhrase('chains')).toBe('an object of arrays of objects')
    expect(expectedPhrase('artifact_manifests')).toBe('an object of objects of objects')
    expect(expectedPhrase('artifact_manifest_chains')).toBe(
      'an object of objects of arrays of objects',
    )
  })

  it('the oracle decides on its own, and can therefore contradict the library', () => {
    expect(oracle(serialize(SMALL_DOCUMENT)).refusal).toBeNull()
    expect(oracle(new TextEncoder().encode('{')).refusal).toBe('M7')
    expect(oracle(new TextEncoder().encode('[]')).refusal).toBe('M4')
    expect(oracle(new TextEncoder().encode('{"manifests":{},"provenance":{},"x":{}}')).refusal).toBe(
      'M5',
    )
    expect(oracle(new TextEncoder().encode('{"provenance":{}}')).refusal).toBe('M6')
    expect(oracle(documentWithLiteral('9007199254740992')).refusal).toBe('M8')
    expect(
      oracle(new TextEncoder().encode('{"manifests":{"i":{},"i":{}},"provenance":{}}')).refusal,
    ).toBe('M7')
  })

  it('the flip corpus carries no integer the oracle would have to round', () => {
    // The oracle reads integers from its own token scan, then widens
    // `JSON.parse`'s `number`s to compare trees. That widening is only faithful
    // while every integer in the corpus is exactly representable, and this is
    // the assertion that keeps it so.
    for (const token of scanTokens(jsonText(SMALL_DOCUMENT)).integerTokens) {
      expect(Number.isSafeInteger(Number(token)), token).toBe(true)
    }
  })
})

// ---------------------------------------------------------------------------
// Section 5.6(b): the module cycle, at runtime, from this file's import order.
// ---------------------------------------------------------------------------

describe('the module graph initializes from either end', () => {
  it('a manifest-first import order still builds and reads a snapshot', () => {
    const handle = parseKeyManifest(canonicalBytes(manifestDoc('store.example.com')))
    // At T1 `verifyArtifactManifest` still takes the DATA, not the handle: the
    // ports flip in T3. What is exercised here is the initialization order,
    // which is exercised whichever of the two shapes is passed.
    expect(typeof verifyArtifactManifest({ series: 'x' }, handle.data())).toBe('boolean')
    expect(findKey(handle.data(), 'nothing')).toBeNull()
    const snapshot = parseTrustStore(storeBytes(SMALL_DOCUMENT))
    expect(snapshot.manifestFor(PLAIN_ISSUERS[0]!)).toBeInstanceOf(KeyManifest)
  })
})

// ---------------------------------------------------------------------------
// INV-1: conservation.
// ---------------------------------------------------------------------------

function conservationCorpus(): Array<[string, JsonObject]> {
  const corpus: Array<[string, JsonObject]> = []
  for (const [family, pool] of [
    ['plain', PLAIN_ISSUERS],
    ['special', SPECIAL_ISSUERS],
  ] as Array<[string, string[]]>) {
    for (const count of [1, 3]) {
      for (const chainLength of [0, 1, 2, 3]) {
        for (const artifacts of [false, true]) {
          corpus.push([
            `${family}-${count}issuer-chain${chainLength}-artifacts${artifacts ? 1 : 0}`,
            document(pool.slice(0, count), { chainLength, artifacts }),
          ])
        }
      }
    }
  }
  for (let mask = 0; mask < 1 << OPTIONAL_MEMBERS.length; mask++) {
    const absent = OPTIONAL_MEMBERS.filter((_unused, bit) => (mask >> bit) & 1)
    const empty = OPTIONAL_MEMBERS.filter((name) => !absent.includes(name))
    corpus.push([
      'absent:' + (absent.join('+') || 'none'),
      document(PLAIN_ISSUERS, { absent, empty }),
    ])
  }
  return corpus
}

const CONSERVATION_CORPUS = conservationCorpus()

describe('INV-1 conservation', () => {
  for (const [name, tree] of CONSERVATION_CORPUS) {
    it(`a well-formed document survives the snapshot unchanged: ${name}`, () => {
      const snapshot = parseStore(serialize(tree))
      expect(sameTree(snapshot.data(), tree), `data() differs for ${name}`).toBe(true)
      expect(snapshot.toBytes()).toEqual(canonicalBytes(tree))
    })

    it(`an absent member stays absent and an empty member stays empty: ${name}`, () => {
      const snapshot = parseStore(serialize(tree))
      const back = snapshot.data()
      for (const member of MEMBER_ORDER) {
        expect(Object.hasOwn(back, member), `${member} presence changed in ${name}`).toBe(
          Object.hasOwn(tree, member),
        )
      }
      const text = new TextDecoder().decode(snapshot.toBytes())
      for (const member of OPTIONAL_MEMBERS) {
        if (!Object.hasOwn(tree, member)) {
          expect(text.includes(`"${member}"`), `${member} reappeared in ${name}`).toBe(false)
        }
      }
    })
  }

  it('the issuer list comes from the manifests member, sorted', () => {
    const snapshot = parseStore(serialize(document(SPECIAL_ISSUERS)))
    expect(snapshot.issuers()).toEqual([...SPECIAL_ISSUERS].sort())
  })

  it('every selector hands back what the document carried', () => {
    const tree = document([...PLAIN_ISSUERS, ...SPECIAL_ISSUERS], { chainLength: 2 })
    const snapshot = parseStore(serialize(tree))
    const manifests = tree.manifests as Record<string, JsonValue>
    const chains = tree.chains as Record<string, JsonValue[]>
    for (const issuer of Object.keys(manifests)) {
      const held = snapshot.manifestFor(issuer)
      expect(held, issuer).toBeInstanceOf(KeyManifest)
      expect(sameTree(held!.data(), manifests[issuer]), issuer).toBe(true)
      expect(snapshot.provenanceFor(issuer)).toBe('tls')
      const chain = snapshot.chainFor(issuer)
      expect(chain).toHaveLength(chains[issuer]!.length)
      expect(
        sameTree(
          chain.map((m) => m.data()),
          chains[issuer],
        ),
        issuer,
      ).toBe(true)
    }
    expect(snapshot.manifestFor('absent.example.com')).toBeNull()
    expect(snapshot.chainFor('absent.example.com')).toEqual([])
    expect(snapshot.provenanceFor('absent.example.com')).toBeNull()
  })

  it('a store without chains answers the empty chain like one with empty chains', () => {
    const without = parseStore(serialize(document(PLAIN_ISSUERS, { absent: ['chains'] })))
    const withEmpty = parseStore(serialize(document(PLAIN_ISSUERS, { empty: ['chains'] })))
    for (const issuer of PLAIN_ISSUERS) {
      expect(without.chainFor(issuer)).toEqual([])
      expect(withEmpty.chainFor(issuer)).toEqual([])
    }
    // They answer alike and are still DIFFERENT documents: absence survives.
    expect(without.toBytes()).not.toEqual(withEmpty.toBytes())
  })

  it('the snapshot does not depend on the order the members arrived in', () => {
    const names = Object.keys(RICH_DOCUMENT)
    const reversed: JsonObject = {}
    for (const name of [...names].reverse()) reversed[name] = RICH_DOCUMENT[name]!
    expect(parseStore(serialize(reversed)).toBytes()).toEqual(
      parseStore(serialize(RICH_DOCUMENT)).toBytes(),
    )
  })
})

// ---------------------------------------------------------------------------
// INV-1b: the oracle rules, the importer must agree.
// ---------------------------------------------------------------------------

describe('INV-1b admissibility', () => {
  it('the boundary admits exactly what the format admits', () => {
    const disagreements: string[] = []
    let admitted = 0
    for (const [name, payload] of BYTE_MUTANT_CORPUS) {
      const verdict = oracle(payload)
      if (verdict.refusal === null) {
        admitted++
        let snapshot: TrustStore
        try {
          snapshot = parseStore(payload)
        } catch (e) {
          disagreements.push(`${name}: admissible but refused as ${String((e as Error).message)}`)
          continue
        }
        if (!sameTree(snapshot.data(), verdict.parsed)) {
          disagreements.push(`${name}: admitted but not conserved`)
        }
      } else {
        try {
          parseStore(payload)
          disagreements.push(`${name}: inadmissible (${verdict.refusal}) but accepted`)
        } catch (e) {
          if (!(e instanceof TrustMaterialError)) {
            disagreements.push(`${name}: refused with ${String(e)} rather than a TrustMaterialError`)
          }
        }
      }
    }
    expect(disagreements).toEqual([])
    // Non-vacuity: a corpus the oracle refused wholesale would make the loop
    // above pass without ever admitting anything.
    expect(admitted, 'the corpus admits nothing: the comparison is vacuous').toBeGreaterThan(10)
  })

  it('the refusal CLASS the oracle predicts is the class the boundary reports', () => {
    // Separate from the test above on purpose. That one measures the
    // ACCEPT/REFUSE decision, which is the security property; this one measures
    // the message class, which is a diagnostic. Merging them would let a
    // mismatched message hide behind a correct decision.
    const disagreements: string[] = []
    for (const [name, payload] of BYTE_MUTANT_CORPUS) {
      const verdict = oracle(payload)
      if (verdict.refusal === null) continue
      try {
        parseStore(payload)
      } catch (e) {
        if (!(e instanceof TrustMaterialError)) continue
        const seen = classify(e, WHAT_STORE)
        if (seen !== verdict.refusal) {
          disagreements.push(`${name}: oracle says ${verdict.refusal}, boundary says ${seen}`)
        } else if (verdict.member !== null && e.member !== verdict.member) {
          disagreements.push(`${name}: oracle blames ${verdict.member}, boundary blames ${String(e.member)}`)
        }
      }
    }
    expect(disagreements).toEqual([])
  })

  for (const [name, payload, expected] of LEXICAL_MUTANTS) {
    it(`the lexical boundary case lands in the class the format predicts: ${name}`, () => {
      if (expected === 'accepted') {
        expect(oracle(payload).refusal).toBeNull()
        expect(parseStore(payload)).toBeInstanceOf(TrustStore)
        return
      }
      expect(oracle(payload).refusal, `the oracle disagrees about ${name}`).toBe(expected)
      refusedAs(() => parseStore(payload), expected)
    })
  }

  it('the integer ceiling is refused with the wording both cores share', () => {
    const error = refusedAs(() => parseStore(documentWithLiteral('9007199254740992')), 'M8')
    expect(error.message).toBe(MSG.notCanonical(WHAT_STORE, MSG.intOutOfRange(9007199254740992n)))
  })

  for (const totalDepth of [255, 256]) {
    it(`a document at or under the nesting ceiling is admitted: depth ${totalDepth}`, () => {
      expect(parseStore(serialize(deepDocument(totalDepth)))).toBeInstanceOf(TrustStore)
    })
  }

  it('a document one level over the nesting ceiling is refused', () => {
    refusedAs(() => parseStore(serialize(deepDocument(257))), 'M7')
  })

  it('a document of exactly the admission ceiling is admitted', () => {
    const payload = paddedDocument(CEILING_BYTES)
    expect(payload.byteLength).toBe(CEILING_BYTES)
    expect(parseStore(payload)).toBeInstanceOf(TrustStore)
  })

  it('a document one byte over the admission ceiling is refused by size', () => {
    const payload = paddedDocument(CEILING_BYTES + 1)
    expect(payload.byteLength).toBe(CEILING_BYTES + 1)
    // M2 and not M7: the refusal has to be the CHEAP one, before the bytes are
    // decoded. The document inside the padding is well formed, so a boundary
    // that parsed first would answer with a different class.
    refusedAs(() => parseStore(payload), 'M2')
  })

  it('the oversized document is refused without being copied', () => {
    // The claim is not "the refusal is fast", which is a threshold somebody has
    // to guess and a shared machine will eventually break. The claim is "the
    // refusal does not COPY", and the test calibrates itself against the cost
    // of exactly one copy of the same buffer, measured here and now.
    //
    // A ceiling checked after the copy passes a wall-clock threshold on a quiet
    // machine and fails this one: it spends a whole copy to say no, which is
    // what a caller sending 100MB of padding is asking it to do.
    const ten = paddedDocument(CEILING_BYTES + 1)
    const hundred = new Uint8Array(100_000_001)
    hundred.fill(0x20)

    const c0 = performance.now()
    const oneCopy = new Uint8Array(hundred)
    const copyCost = performance.now() - c0
    expect(oneCopy.byteLength, 'the calibration copy did not happen').toBe(hundred.byteLength)

    const t0 = performance.now()
    refusedAs(() => parseStore(ten), 'M2')
    const small = performance.now() - t0
    const t1 = performance.now()
    refusedAs(() => parseStore(hundred), 'M2')
    const large = performance.now() - t1

    expect(
      large,
      `refusing 100MB took ${large}ms; one copy of it costs ${copyCost}ms (10MB refusal: ${small}ms)`,
    ).toBeLessThan(copyCost / 2)
  })

  it('every truncation of a valid document is refused as unparsable', () => {
    const valid = serialize(SMALL_DOCUMENT)
    for (let offset = 0; offset < valid.byteLength; offset++) {
      refusedAs(() => parseStore(valid.slice(0, offset)), 'M7')
    }
  })
})

// ---------------------------------------------------------------------------
// INV-3: the grammar refuses the whole unit, in a stated order.
// ---------------------------------------------------------------------------

describe('INV-3 refusal of the whole unit', () => {
  for (const [name, text] of DUPLICATE_KEY_DOCUMENTS) {
    it(`a duplicated member is refused, never resolved: ${name}`, () => {
      refusedAs(() => parseStore(new TextEncoder().encode(text)), 'M7')
    })
  }

  for (const unknown of UNKNOWN_MEMBER_NAMES) {
    it(`an unknown member is refused and named as the caller spelled it: ${JSON.stringify(unknown)}`, () => {
      const mutant = withMember(SMALL_DOCUMENT, unknown, {})
      // Non-vacuity: the member really is in the bytes the boundary receives.
      expect(new TextDecoder().decode(serialize(mutant))).toContain(JSON.stringify(unknown) + ':')
      const error = refusedAs(() => parseStore(serialize(mutant)), 'M5')
      expect(error.message).toBe(MSG.unknownMember(unknown))
    })
  }

  it('WHICH unknown member is named is the same in both cores, and for the same reason', () => {
    // Section 5.3 used to say "the first unknown member in DOCUMENT order".
    // Measured 2026-09-08, that rule is not implementable here at all: the
    // parser builds ordinary objects and JavaScript enumerates integer-like
    // keys first whatever the document said, so on
    // `{"manifests":{},"provenance":{},"zz":{},"0":{}}` this core named '0'
    // where Python named 'zz'. A normative sentence a conforming core cannot
    // satisfy is the family this whole front exists to close, so the TEXT was
    // corrected rather than the cores: the member named is the minimum in
    // CANONICAL key order, which the protocol already defines and already
    // signs on.
    //
    // The answers come from the shared fixture, produced by RUNNING the Python
    // boundary. This suite cannot agree with itself here: it did not choose
    // these strings.
    const choices = MESSAGE_FIXTURE.unknown_member_choice
    expect(choices.length, 'the fixture pins no choice at all').toBeGreaterThan(3)
    for (const c of choices) {
      const error = refusedAs(() => parseStore(new TextEncoder().encode(c.document)), 'M5')
      expect(error.message, c.document).toBe(c.expected)
      expect(error.member).toBeNull()
    }
  })

  it('the pinned documents can tell the new rule from the old one', () => {
    // Non-vacuity, and it is the whole value of the case list: on a document
    // where the first member in document order IS the canonical minimum, both
    // rules give the same answer and the fixture would prove nothing. Every
    // pinned document must disagree with document order — and at least one
    // must disagree with CODE POINT order too, which is what makes it a test
    // of JCS rather than of "sorted".
    let codePointDiscriminates = 0
    for (const c of MESSAGE_FIXTURE.unknown_member_choice) {
      const unknown = Object.keys(JSON.parse(c.document) as Record<string, unknown>).filter(
        (n) => !Object.hasOwn(MEMBER_KINDS, n),
      )
      if (unknown.length < 2) continue
      const byCodeUnit = [...unknown].sort()[0]!
      const byCodePoint = [...unknown].sort((a, b) => {
        const ca = Array.from(a)
        const cb = Array.from(b)
        for (let i = 0; i < Math.min(ca.length, cb.length); i++) {
          const d = ca[i]!.codePointAt(0)! - cb[i]!.codePointAt(0)!
          if (d !== 0) return d
        }
        return ca.length - cb.length
      })[0]!
      // The document's own order must not already agree with the rule, or the
      // case cannot separate them. `JSON.parse` loses that order for
      // integer-like names, so it is read off the raw text instead.
      const documentOrder = [...c.document.matchAll(/"((?:[^"\\]|\\.)*)"\s*:/g)]
        .map((m) => JSON.parse(`"${m[1]!}"`) as string)
        .filter((n) => unknown.includes(n))[0]!
      expect(documentOrder, `${c.document} agrees with document order`).not.toBe(byCodeUnit)
      if (byCodePoint !== byCodeUnit) codePointDiscriminates++
    }
    expect(
      codePointDiscriminates,
      'no pinned document separates UTF-16 code-unit order from code-point order',
    ).toBeGreaterThan(0)
  })

  it('the container grammar decides every type substitution', () => {
    const disagreements: string[] = []
    let passing = 0
    for (const item of TYPE_MATRIX_CASES) {
      const payload = serialize(item.tree)
      if (item.shouldPass) {
        passing++
        try {
          const snapshot = parseStore(payload)
          if (!sameTree(snapshot.data(), item.tree)) {
            disagreements.push(`${item.label}: admitted but not conserved`)
          }
        } catch (e) {
          disagreements.push(
            `${item.label}: the grammar admits it, the boundary refused ${String((e as Error).message)}`,
          )
        }
        continue
      }
      try {
        parseStore(payload)
        disagreements.push(`${item.label}: the grammar refuses it, the boundary accepted`)
      } catch (e) {
        if (!(e instanceof TrustMaterialError)) {
          disagreements.push(`${item.label}: ${String(e)}`)
        } else if (classify(e, WHAT_STORE) !== 'M6') {
          disagreements.push(`${item.label}: expected M6, got ${JSON.stringify(e.message)}`)
        } else if (e.member !== item.member) {
          disagreements.push(`${item.label}: blamed ${String(e.member)}`)
        }
      }
    }
    expect(disagreements).toEqual([])
    expect(passing, 'no substitution passes: the matrix is vacuous').toBeGreaterThan(0)
  })

  for (const member of MEMBER_ORDER) {
    it(`a member present as null is not treated as an absent member: ${member}`, () => {
      const mutant: JsonObject = { ...RICH_DOCUMENT }
      mutant[member] = null
      refusedAs(() => parseStore(serialize(mutant)), 'M6', { member })
    })
  }

  for (const member of REQUIRED_MEMBERS) {
    it(`a missing required member is refused and named: ${member}`, () => {
      const mutant = document(PLAIN_ISSUERS.slice(0, 1), { absent: [member] })
      refusedAs(() => parseStore(serialize(mutant)), 'M6', { member })
    })
  }

  it('the empty document is refused naming the first member of the order', () => {
    const error = refusedAs(() => parseStore(new TextEncoder().encode('{}')), 'M6', {
      member: 'manifests',
    })
    expect(error.message).toBe(MSG.memberShape('manifests', expectedPhrase('manifests')))
  })

  for (const text of ['[]', '"a document"', '1', 'null', 'true']) {
    it(`a document that is not an object is refused before the grammar: ${text}`, () => {
      refusedAs(() => parseStore(new TextEncoder().encode(text)), 'M4')
    })
  }

  it('a document with several defects is refused by the first gate only', () => {
    // `chains` malformed AND an integer past the safe range: the grammar runs
    // before canonical representability, so M6 must win.
    const both = clone(RICH_DOCUMENT)
    both.chains = 1n
    ;(both.manifests as Record<string, JsonObject>)[PLAIN_ISSUERS[0]!]!.probe = 9007199254740992n
    // Non-vacuity: without the malformed member, the same document is M8.
    const onlyInteger = clone(both)
    delete onlyInteger.chains
    refusedAs(() => parseStore(serialize(onlyInteger)), 'M8')
    refusedAs(() => parseStore(serialize(both)), 'M6', { member: 'chains' })

    // An unknown member AND a malformed `manifests`: M5 is checked first.
    const unknownFirst = withMember(clone(RICH_DOCUMENT), 'surprise', {})
    unknownFirst.manifests = 1n
    refusedAs(() => parseStore(serialize(clone(unknownFirst))), 'M5')
    const onlyShape = clone(unknownFirst)
    delete onlyShape.surprise
    refusedAs(() => parseStore(serialize(onlyShape)), 'M6', { member: 'manifests' })
  })

  it('the member blamed for a shape failure is the member at fault', () => {
    for (const member of MEMBER_ORDER) {
      const mutant: JsonObject = { ...RICH_DOCUMENT }
      mutant[member] = 1n
      const error = refusedAs(() => parseStore(serialize(mutant)), 'M6', { member })
      expect(error.message).toBe(MSG.memberShape(member, expectedPhrase(member)))
    }
  })

  it('a refused document leaves nothing behind and is not quoted back', () => {
    const mutant: JsonObject = { ...RICH_DOCUMENT, chains: 1n }
    const error = refusal(() => parseStore(serialize(mutant)))
    expect(TrustStore.is(error)).toBe(false)
    // Nothing about the rejected document is formatted into the text: a hostile
    // document must not get to choose what the verifier prints.
    expect(error.message.includes(PLAIN_ISSUERS[0]!)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// INV-4: contract refusal before a single hook of the value runs.
// ---------------------------------------------------------------------------

describe('INV-4 contract refusal', () => {
  for (const impostor of BYTE_IMPOSTORS) {
    it(`a value offered in place of the bytes is refused untouched: ${impostor.name}`, () => {
      const hits: string[] = []
      const value = impostor.build(hits)
      const storeError = refusedAs(() => parseStore(value), impostor.expect)
      const manifestError = refusedAs(() => parseManifest(value), impostor.expect, {
        what: WHAT_MANIFEST,
      })
      expect(hits, `${impostor.name} was touched: ${hits.join(', ')}`).toEqual([])
      expect(storeError.message).toBe(messagePrefix(impostor.expect, WHAT_STORE))
      expect(manifestError.message).toBe(messagePrefix(impostor.expect, WHAT_MANIFEST))
    })
  }

  it('the backing buffer is judged by what it IS, not by which realm made it', () => {
    // The premise this measures did not exist before T1 (plan section 5.2.1
    // records it as a MISSING MEASUREMENT, to be produced rather than
    // transcribed). It is what separates the two ways of asking the question:
    //
    //   "is it a SharedArrayBuffer?"  -- `instanceof`, realm-local, answers NO
    //                                    for a shared buffer from another realm
    //                                    and for every buffer in a realm where
    //                                    the global is not defined: fail-OPEN.
    //   "is it an ordinary one?"      -- reads the internal slot, so it answers
    //                                    for any realm: fail-CLOSED.
    //
    // Measured here, all four corners.
    const build = vm.runInNewContext(`
      (bytes, shared) => {
        const buffer = shared ? new SharedArrayBuffer(bytes.length) : new ArrayBuffer(bytes.length)
        const view = new Uint8Array(buffer)
        for (let i = 0; i < bytes.length; i++) view[i] = bytes[i]
        return view
      }
    `) as (bytes: number[], shared: boolean) => Uint8Array
    const body = Array.from(serialize(SMALL_DOCUMENT))

    const foreignPlain = build(body, false)
    const foreignShared = build(body, true)
    // Non-vacuity, and the reason `instanceof` is not the tool: neither of
    // these is an instance of OUR Uint8Array, and the shared one is not an
    // instance of our SharedArrayBuffer either.
    expect(foreignPlain instanceof Uint8Array, 'the vm context reused our intrinsics').toBe(false)
    expect(foreignShared.buffer instanceof SharedArrayBuffer).toBe(false)

    expect(parseStore(validBytes()), 'ordinary buffer, our realm').toBeInstanceOf(TrustStore)
    refusedAs(() => parseStore(new Uint8Array(new SharedArrayBuffer(64))), 'M10')
    expect(parseStore(foreignPlain), 'ordinary buffer, another realm').toBeInstanceOf(TrustStore)
    refusedAs(() => parseStore(foreignShared), 'M10')
  })

  it('an oversized live object is refused as a live object, not as a size', () => {
    // Order matters: M1 is decided before the ceiling, so an impostor cannot
    // learn where the ceiling is by watching which refusal it gets.
    refusedAs(() => parseStore({ length: CEILING_BYTES * 10 }), 'M1')
  })

  const ACCEPTED: Array<[string, (hits: string[]) => unknown]> = [
    ['a plain Uint8Array', () => validBytes()],
    ['a Node Buffer', () => Buffer.from(validBytes())],
    ['an Int8Array over the same bytes', () => new Int8Array(validBytes().buffer)],
    ['a Uint8ClampedArray over the same bytes', () => new Uint8ClampedArray(validBytes())],
    [
      'a subclass with a recording species and constructor',
      (hits) => {
        class Sneaky extends Uint8Array {
          static get [Symbol.species](): Uint8ArrayConstructor {
            hits.push('species')
            return Uint8Array
          }
        }
        Object.defineProperty(Sneaky.prototype, 'constructor', {
          configurable: true,
          get() {
            hits.push('constructor')
            return Uint8Array
          },
        })
        return new Sneaky(validBytes())
      },
    ],
    [
      'a real view whose prototype is a recording Proxy',
      (hits) => {
        const view = validBytes()
        Object.setPrototypeOf(view, recordingProxy(Uint8Array.prototype, hits))
        return view
      },
    ],
    [
      'a view at an offset inside a larger buffer',
      () => {
        const body = validBytes()
        const buffer = new ArrayBuffer(body.byteLength + 16)
        const view = new Uint8Array(buffer, 8, body.byteLength)
        view.set(body)
        return view
      },
    ],
    [
      'a view on a resizable, non-shared buffer',
      () => {
        const body = validBytes()
        const buffer = new ArrayBuffer(body.byteLength, { maxByteLength: body.byteLength * 2 })
        const view = new Uint8Array(buffer)
        view.set(body)
        return view
      },
    ],
  ]

  for (const [name, build] of ACCEPTED) {
    it(`exact byte views are admitted however they were built: ${name}`, () => {
      const hits: string[] = []
      const snapshot = parseStore(build(hits))
      expect(sameTree(snapshot.data(), SMALL_DOCUMENT), name).toBe(true)
      expect(hits, `${name} was consulted: ${hits.join(', ')}`).toEqual([])
    })
  }
})

// ---------------------------------------------------------------------------
// D15: custody. Seven forgeries, and the declared surface.
// ---------------------------------------------------------------------------

describe('D15 custody of the snapshot classes', () => {
  const bytes = (): Uint8Array => serialize(SMALL_DOCUMENT)
  const fields = (): StoreData => ({}) as unknown as StoreData

  const FORGERIES: Array<[string, () => unknown]> = [
    ['a fresh symbol as the token', () => new TrustStore(Symbol('admit'), fields(), bytes())],
    [
      'a registered symbol with the same description',
      () => new TrustStore(Symbol.for('attest.trustMaterial.admit'), fields(), bytes()),
    ],
    [
      'the description read off the real token, re-registered',
      () => new TrustStore(Symbol.for(String(Symbol('attest.trustMaterial.admit').description)), fields(), bytes()),
    ],
    [
      'Reflect.construct with a forged token',
      () => Reflect.construct(TrustStore, [Symbol('admit'), fields(), bytes()]),
    ],
    [
      'a subclass that calls super with its own token',
      () => {
        class Sub extends TrustStore {
          constructor() {
            super(Symbol('admit'), fields(), bytes())
          }
        }
        return new Sub()
      },
    ],
    [
      'a fresh symbol as the key-manifest token',
      () => new KeyManifest(Symbol('admit'), {}, bytes()),
    ],
    [
      'Reflect.construct on the key manifest',
      () => Reflect.construct(KeyManifest, [Symbol('admit'), {}, bytes()]),
    ],
  ]

  for (const [name, build] of FORGERIES) {
    it(`a snapshot cannot be built by calling its class: ${name}`, () => {
      expect(build).toThrow(TypeError)
    })
  }

  it('the seven forgeries are all still there', () => {
    // A count next to a list is the copy that ages first, so the LIST is the
    // pin. This states only that none of the seven was quietly dropped.
    expect(FORGERIES).toHaveLength(7)
  })

  it('a snapshot smuggled past the factory has nothing to export', () => {
    const fake = Object.create(TrustStore.prototype) as TrustStore
    expect(TrustStore.is(fake)).toBe(false)
    expect(storeData(fake)).toBeNull()
    expect(() => fake.toBytes()).toThrow(TypeError)
    const fakeManifest = Object.create(KeyManifest.prototype) as KeyManifest
    expect(KeyManifest.is(fakeManifest)).toBe(false)
    expect(manifestData(fakeManifest)).toBeNull()
    expect(() => fakeManifest.toBytes()).toThrow(TypeError)
  })

  it('the brand answers false for every shape that is not a snapshot', () => {
    for (const value of [
      null,
      undefined,
      1,
      'x',
      {},
      { manifests: {}, provenance: {} },
      Object.setPrototypeOf({}, TrustStore.prototype) as object,
      parseKeyManifest(canonicalBytes(manifestDoc('i'))),
    ]) {
      expect(TrustStore.is(value), String(value)).toBe(false)
      expect(storeData(value)).toBeNull()
    }
    const real = parseStore(bytes())
    expect(KeyManifest.is(real)).toBe(false)
    expect(manifestData(real)).toBeNull()
    // Non-vacuity: the brand is not simply always false.
    expect(TrustStore.is(real)).toBe(true)
    expect(storeData(real)).not.toBeNull()
  })

  it('a Proxy over a real snapshot is not a snapshot, and is not consulted', () => {
    const hits: string[] = []
    const proxied = recordingProxy(parseStore(bytes()), hits)
    expect(TrustStore.is(proxied)).toBe(false)
    expect(storeData(proxied)).toBeNull()
    // The brand reads a private field, which a Proxy cannot forward: no trap
    // runs, and the answer is false rather than the target's.
    expect(hits).toEqual([])
  })

  it('the declared surface is the whole surface', () => {
    expect(new Set(Reflect.ownKeys(TrustStore))).toEqual(
      new Set(['length', 'name', 'prototype', 'is']),
    )
    expect(new Set(Reflect.ownKeys(TrustStore.prototype))).toEqual(
      new Set(['constructor', 'toBytes', 'data', 'issuers', 'manifestFor', 'chainFor', 'provenanceFor']),
    )
    expect(new Set(Reflect.ownKeys(KeyManifest))).toEqual(
      new Set(['length', 'name', 'prototype', 'is']),
    )
    expect(new Set(Reflect.ownKeys(KeyManifest.prototype))).toEqual(
      new Set(['constructor', 'toBytes', 'data']),
    )
    for (const target of [TrustStore, TrustStore.prototype, KeyManifest, KeyManifest.prototype]) {
      expect(Object.getOwnPropertySymbols(target)).toEqual([])
    }
  })
})

// ---------------------------------------------------------------------------
// INV-5: no shared reference between the caller, the snapshot and its exports.
// ---------------------------------------------------------------------------

describe('INV-5 no aliasing', () => {
  it('the snapshot hands back a fresh tree every time', () => {
    const snapshot = parseStore(serialize(RICH_DOCUMENT))
    expect(snapshot.data()).not.toBe(snapshot.data())
    expect(sameTree(snapshot.data(), snapshot.data())).toBe(true)
  })

  it('mutating what the snapshot handed back changes nothing', () => {
    const snapshot = parseStore(serialize(RICH_DOCUMENT))
    const before = snapshot.toBytes()
    const tree = snapshot.data() as Record<string, unknown>
    delete tree.manifests
    tree.provenance = { invented: 'yes' }
    expect(sameTree(snapshot.data(), RICH_DOCUMENT)).toBe(true)
    expect(snapshot.toBytes()).toEqual(before)
  })

  it('mutating a held manifest changes neither it nor the store', () => {
    const snapshot = parseStore(serialize(RICH_DOCUMENT))
    const issuer = PLAIN_ISSUERS[0]!
    const held = snapshot.manifestFor(issuer)!
    const before = held.toBytes()
    const tree = held.data() as Record<string, unknown>
    tree.issuer = 'somebody-else.example.com'
    expect(held.toBytes()).toEqual(before)
    expect(
      sameTree(snapshot.manifestFor(issuer)!.data(), (RICH_DOCUMENT.manifests as JsonObject)[issuer]),
    ).toBe(true)
  })

  it('the exported bytes are a copy the caller cannot reach back through', () => {
    const snapshot = parseStore(serialize(RICH_DOCUMENT))
    const first = snapshot.toBytes()
    expect(first).not.toBe(snapshot.toBytes())
    first.fill(0x41)
    expect(snapshot.toBytes()).toEqual(canonicalBytes(RICH_DOCUMENT))
  })

  it('a held manifest exports a copy too, not its own buffer', () => {
    // The store and the manifest are two classes with the same promise, and a
    // test that only exercises one of them leaves the other free to hand out
    // its internals. Measured: with the manifest's `toBytes` returning the
    // field itself, every other test in this file stayed green.
    const held = parseStore(serialize(RICH_DOCUMENT)).manifestFor(PLAIN_ISSUERS[0]!)!
    const expected = canonicalBytes((RICH_DOCUMENT.manifests as JsonObject)[PLAIN_ISSUERS[0]!]!)
    const first = held.toBytes()
    expect(first).not.toBe(held.toBytes())
    first.fill(0x41)
    expect(held.toBytes()).toEqual(expected)
    const standalone = parseManifest(serialize(keyManifestTree('i', 1)))
    const mine = standalone.toBytes()
    expect(mine).not.toBe(standalone.toBytes())
    mine.fill(0x41)
    expect(standalone.toBytes()).toEqual(canonicalBytes(keyManifestTree('i', 1)))
  })

  it('overwriting the input bytes after the import changes nothing', () => {
    const input = serialize(RICH_DOCUMENT)
    const snapshot = parseStore(input)
    const before = snapshot.toBytes()
    input.fill(0x41)
    expect(snapshot.toBytes()).toEqual(before)
    expect(sameTree(snapshot.data(), RICH_DOCUMENT)).toBe(true)
  })

  it('resizing the input buffer away after the import changes nothing', () => {
    const body = serialize(RICH_DOCUMENT)
    const buffer = new ArrayBuffer(body.byteLength, { maxByteLength: body.byteLength })
    const view = new Uint8Array(buffer)
    view.set(body)
    const snapshot = parseStore(view)
    const before = snapshot.toBytes()
    buffer.resize(0)
    expect(snapshot.toBytes()).toEqual(before)
    expect(sameTree(snapshot.data(), RICH_DOCUMENT)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// D18: a selector that is not exactly a primitive string is answered first.
// ---------------------------------------------------------------------------

describe('D18 selectors', () => {
  const snapshot = (): TrustStore =>
    parseStore(serialize(document([...PLAIN_ISSUERS, ...SPECIAL_ISSUERS])))

  const HOSTILE_SELECTORS: Array<[string, (hits: string[]) => unknown]> = [
    [
      'an object answering every coercion protocol',
      (hits) => coercionImpostor(hits, PLAIN_ISSUERS[0]!),
    ],
    ['a String wrapper', () => new String(PLAIN_ISSUERS[0]!)],
    ['a number', () => 1],
    ['a bigint', () => 1n],
    ['a symbol', () => Symbol('store.example.com')],
    ['null', () => null],
    ['undefined', () => undefined],
    ['an array holding the issuer id', () => [PLAIN_ISSUERS[0]!]],
  ]

  for (const [name, build] of HOSTILE_SELECTORS) {
    it(`a selector that is not exactly a string is answered before it is touched: ${name}`, () => {
      const hits: string[] = []
      const selector = build(hits)
      const store = snapshot()
      expect(store.manifestFor(selector)).toBeNull()
      expect(store.chainFor(selector)).toEqual([])
      expect(store.provenanceFor(selector)).toBeNull()
      expect(hits, `${name} was coerced: ${hits.join(', ')}`).toEqual([])
    })
  }

  it('an object-shaped name selects only when the document carried it', () => {
    const carried = snapshot()
    for (const name of SPECIAL_ISSUERS) {
      expect(carried.manifestFor(name), name).toBeInstanceOf(KeyManifest)
      expect(carried.provenanceFor(name), name).toBe('tls')
      expect(carried.chainFor(name), name).toHaveLength(1)
    }
    const plain = parseStore(serialize(document(PLAIN_ISSUERS)))
    for (const name of [...SPECIAL_ISSUERS, 'valueOf', 'prototype']) {
      expect(plain.manifestFor(name), name).toBeNull()
      expect(plain.chainFor(name), name).toEqual([])
      expect(plain.provenanceFor(name), name).toBeNull()
    }
  })

  it('a synthesized member answers object-shaped names as absent too', () => {
    // `chains` and the artifact members are ABSENT here, so the maps the
    // snapshot reads were made by the boundary, not by the parser. A `{}`
    // literal would answer `chainFor('toString')` with a function.
    const bare = parseStore(serialize(document(PLAIN_ISSUERS, { absent: OPTIONAL_MEMBERS })))
    for (const name of [...SPECIAL_ISSUERS, 'valueOf', 'prototype']) {
      expect(bare.chainFor(name), name).toEqual([])
    }
  })

  it('findKey answers a non-string kid without comparing it', () => {
    const hits: string[] = []
    const data = parseManifest(canonicalBytes(manifestDoc('i'))).data()
    expect(findKey(data, coercionImpostor(hits, 'x') as unknown as string)).toBeNull()
    expect(hits).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// The key manifest boundary: the same lexical rules, and no container grammar.
// ---------------------------------------------------------------------------

describe('the key manifest boundary', () => {
  it('a key manifest document survives the snapshot unchanged', () => {
    const tree = keyManifestTree('store.example.com', 3)
    const handle = parseManifest(serialize(tree))
    expect(sameTree(handle.data(), tree)).toBe(true)
    expect(handle.toBytes()).toEqual(canonicalBytes(tree))
  })

  for (const text of ['[]', '"a manifest"', '1', 'null', 'true']) {
    it(`a key manifest that is not an object is refused: ${text}`, () => {
      refusedAs(() => parseManifest(new TextEncoder().encode(text)), 'M4', { what: WHAT_MANIFEST })
    })
  }

  it('a key manifest is refused for the same lexical reasons as a store', () => {
    refusedAs(() => parseManifest(new TextEncoder().encode('{')), 'M7', { what: WHAT_MANIFEST })
    refusedAs(() => parseManifest(new TextEncoder().encode('{"probe":9007199254740992}')), 'M8', {
      what: WHAT_MANIFEST,
    })
    refusedAs(() => parseManifest(new TextEncoder().encode('{"a":1,"a":2}')), 'M7', {
      what: WHAT_MANIFEST,
    })
  })

  it('the key manifest boundary applies no container grammar', () => {
    // Any object at all: what a key manifest's members MEAN is `manifests.ts`'s
    // business, and section 5.3 gives the grammar to the store only. This test
    // is what that decision costs, stated out loud.
    const odd = parseManifest(new TextEncoder().encode('{"anything":[1,2,3],"chains":null}'))
    expect(sameTree(odd.data(), { anything: [1n, 2n, 3n], chains: null })).toBe(true)
    for (const member of MEMBER_ORDER) {
      const shaped: JsonObject = {}
      shaped[member] = 1n
      expect(parseManifest(serialize(shaped))).toBeInstanceOf(KeyManifest)
    }
  })

  it('only M1, M2, M4, M7 and M8 are reachable from the manifest side', () => {
    // M5 and M6 name the trust store in their own text, so a manifest can never
    // produce them. Stated as a test because it is the reason the `{what}` slot
    // and the grammar messages are shaped differently.
    expect(MSG.unknownMember('x').includes(WHAT_STORE)).toBe(true)
    expect(MSG.memberShape('x', 'y').includes(WHAT_STORE)).toBe(true)
    expect(MSG.unknownMember('x').includes(WHAT_MANIFEST)).toBe(false)
    expect(MSG.memberShape('x', 'y').includes(WHAT_MANIFEST)).toBe(false)
  })

  it('a CanonError from the parser never escapes as itself', () => {
    // The doors catch `TrustMaterialError`; a `CanonError` crossing this
    // boundary would travel past every handler written for this module.
    for (const text of ['{', '{"a":9007199254740992}', '{"a":1.5}']) {
      let caught: unknown
      try {
        parseManifest(new TextEncoder().encode(text))
      } catch (e) {
        caught = e
      }
      expect(caught, text).toBeInstanceOf(TrustMaterialError)
      expect(caught, text).not.toBeInstanceOf(CanonError)
    }
  })
})

// ---------------------------------------------------------------------------
// The internal accessors: what the doors will use in T3, and nothing else.
// ---------------------------------------------------------------------------

describe('the internal accessors', () => {
  it('storeData hands the doors the five member trees', () => {
    const data = storeData(parseStore(serialize(RICH_DOCUMENT)))!
    expect(data).not.toBeNull()
    for (const member of MEMBER_ORDER) expect(Object.hasOwn(data, member), member).toBe(true)
    expect(sameTree(data.manifests, RICH_DOCUMENT.manifests)).toBe(true)
    expect(sameTree(data.provenance, RICH_DOCUMENT.provenance)).toBe(true)
    expect(sameTree(data.chains, RICH_DOCUMENT.chains)).toBe(true)
  })

  it('an absent optional member reads as an empty map with no prototype', () => {
    const snapshot = parseStore(serialize(document(PLAIN_ISSUERS, { absent: OPTIONAL_MEMBERS })))
    const data = storeData(snapshot)! as unknown as Record<string, object>
    for (const member of OPTIONAL_MEMBERS) {
      const value = data[member]!
      expect(Object.keys(value), member).toEqual([])
      // `Object.create(null)` and not `{}` (D17): a `{}` would answer
      // `chains['toString']` with a function inherited from Object.prototype.
      expect(Object.getPrototypeOf(value), member).toBeNull()
    }
  })

  it('the empty maps are per-instance, never shared', () => {
    const doc = serialize(document(PLAIN_ISSUERS, { absent: OPTIONAL_MEMBERS }))
    const first = storeData(parseStore(doc))!
    const second = storeData(parseStore(doc))!
    expect(first.chains).not.toBe(second.chains)
  })

  it('manifestData hands the doors the manifest tree', () => {
    const tree = keyManifestTree('store.example.com', 1)
    expect(sameTree(manifestData(parseManifest(serialize(tree))), tree)).toBe(true)
  })
})
