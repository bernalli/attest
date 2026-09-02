import { loadsStrict } from 'attest-verifier'
import type {
  AnchorPolicy, JsonObject, JsonValue, LogKey, PinnedHeader, TrustStore,
  VerificationResult, VerifyTransparencyOptions,
} from 'attest-verifier'
import { b64uDecode } from './b64u.js'
import { COMPONENTS, type Component } from './explain.js'
import { runVerify, type VerifyRun } from './run.js'

// The §19 exhibits: the project's own conformance vectors, compiled into the
// page and replayed in the visitor's browser.
//
// Why the corpus and not a receipt made for the occasion. §19's rescue needs
// an ANCHORED compromise cutoff and an ANCHORED receipt, and this site's own
// log has no anchor attached to any checkpoint yet (see trusted-log.ts) — so
// the rail cannot be reached with the material this deployment holds. The
// corpus can reach it, because each of its leaves ships the pinned log keys
// and pinned block headers that its own evidence is judged against. That is
// the ONE thing to be plain about on the page: these two exhibits are judged
// against the VECTOR's pinned configuration, not against this site's.
//
// Everything is imported with `?raw` and parsed here, never imported as a
// parsed JSON module: `loadsStrict` is the project's JSON model — integers
// arrive as bigint and duplicate members are refused — and a document that
// went through `JSON.parse` first would fail to re-canonicalise, which would
// make every exhibit report `not_checked` for a reason that has nothing to do
// with §19. The envelope, likewise, is carried as BYTES: a signature is over
// bytes, and a re-serialised object is a different file.
//
// The expected result is read from the leaf's own `expected.json` and shown
// beside what the run produced. That is the point of the exhibit: the page
// does not ask to be believed, it shows the fixture it is being held to.

import envelopeA from '../../docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/envelope.json?raw'
import manifestsA from '../../docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/manifests.json?raw'
import transparencyA from '../../docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/transparency.json?raw'
import compromiseA from '../../docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/compromise-view.json?raw'
import anchorPolicyA from '../../docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/anchor-policy.json?raw'
import logKeysA from '../../docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/log-keys.json?raw'
import expectedA from '../../docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/expected.json?raw'

import envelopeB from '../../docs/spec/vectors/41-compromise-cutoff/b-anchored-after-cutoff-fails/envelope.json?raw'
import manifestsB from '../../docs/spec/vectors/41-compromise-cutoff/b-anchored-after-cutoff-fails/manifests.json?raw'
import transparencyB from '../../docs/spec/vectors/41-compromise-cutoff/b-anchored-after-cutoff-fails/transparency.json?raw'
import compromiseB from '../../docs/spec/vectors/41-compromise-cutoff/b-anchored-after-cutoff-fails/compromise-view.json?raw'
import anchorPolicyB from '../../docs/spec/vectors/41-compromise-cutoff/b-anchored-after-cutoff-fails/anchor-policy.json?raw'
import logKeysB from '../../docs/spec/vectors/41-compromise-cutoff/b-anchored-after-cutoff-fails/log-keys.json?raw'
import expectedB from '../../docs/spec/vectors/41-compromise-cutoff/b-anchored-after-cutoff-fails/expected.json?raw'

/** The subset of a leaf's `expected.json` the page compares against.
 *
 * The component half is derived from `Component` rather than listed, so the
 * comparison below can sweep the whole result contract: a field this page
 * cannot compare is a field the page shows a verdict for and checks nothing
 * about, which is the one thing an exhibit may never do quietly.
 */
export type ExpectedResult = Partial<Record<Component, string>> & {
  ok?: boolean
  errors?: string[]
  warnings?: string[]
  errors_contains?: string[]
  warnings_contains?: string[]
}

export interface Exhibit {
  /** The corpus leaf this exhibit IS, relative to docs/spec/vectors. */
  id: string
  label: string
  story: string
  envelopeBytes: Uint8Array
  trustStore: TrustStore
  options: VerifyTransparencyOptions
  expected: ExpectedResult
}

export interface ExhibitRun {
  exhibit: Exhibit
  run: VerifyRun
  /** Every field the run disagreed with the fixture about. Empty is the point. */
  mismatches: string[]
  matches: boolean
}

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text)
const strict = (text: string): JsonValue => loadsStrict(bytes(text)) as JsonValue

function trustStoreOf(text: string): TrustStore {
  const d = strict(text) as unknown as JsonObject
  return {
    manifests: d.manifests as unknown as Record<string, JsonObject>,
    provenance: d.provenance as unknown as Record<string, string>,
    chains: (d.chains ?? {}) as unknown as Record<string, JsonObject[]>,
  }
}

// Configuration, not evidence: shaped by hand from the leaf's own trusted
// files, exactly as the conformance harness does it (test/helpers/vectors.ts).
function anchorPolicyOf(text: string): AnchorPolicy {
  const data = JSON.parse(text) as {
    pinned_headers: Record<string, { header_hash: string; merkle_root: string; time: number }>
    crqc_horizon: number | null
  }
  const pinnedHeaders: Record<string, PinnedHeader> = {}
  for (const [headerHash, header] of Object.entries(data.pinned_headers)) {
    pinnedHeaders[headerHash] = {
      headerHash: header.header_hash, merkleRoot: header.merkle_root, time: header.time,
    }
  }
  return { pinnedHeaders, crqcHorizon: data.crqc_horizon }
}

function logKeysOf(text: string): LogKey[] {
  const entries = JSON.parse(text) as Array<{
    origin: string; name: string; ed25519_pub_b64u: string; mldsa_pub_b64u: string
  }>
  return entries.map((e) => ({
    origin: e.origin,
    name: e.name,
    ed25519Pub: b64uDecode(e.ed25519_pub_b64u),
    mldsaPub: b64uDecode(e.mldsa_pub_b64u),
  }))
}

interface RawLeaf {
  id: string
  label: string
  story: string
  envelope: string
  manifests: string
  transparency: string
  compromiseView: string
  anchorPolicy: string
  logKeys: string
  expected: string
}

const LEAVES: RawLeaf[] = [
  {
    id: '41-compromise-cutoff/a-rescued-anchored-before-cutoff',
    label: 'Published before the seller cried theft',
    story:
      'The seller’s signing key was stolen, and the seller said so — in public, in the same ' +
      'append-only log, at a moment a Bitcoin block header fixes. This receipt was already in ' +
      'that log, under an earlier block. The order of the two is not the seller’s to choose.',
    envelope: envelopeA,
    manifests: manifestsA,
    transparency: transparencyA,
    compromiseView: compromiseA,
    anchorPolicy: anchorPolicyA,
    logKeys: logKeysA,
    expected: expectedA,
  },
  {
    id: '41-compromise-cutoff/b-anchored-after-cutoff-fails',
    label: 'Published after',
    story:
      'The same receipt, the same signature, the same stolen key, the same declaration — and ' +
      'this time the receipt reaches the log under a later block than the declaration. Nothing ' +
      'proves it was written before the key was in someone else’s hands, so it is refused.',
    envelope: envelopeB,
    manifests: manifestsB,
    transparency: transparencyB,
    compromiseView: compromiseB,
    anchorPolicy: anchorPolicyB,
    logKeys: logKeysB,
    expected: expectedB,
  },
]

export const EXHIBITS: Exhibit[] = LEAVES.map((leaf) => ({
  id: leaf.id,
  label: leaf.label,
  story: leaf.story,
  envelopeBytes: bytes(leaf.envelope),
  trustStore: trustStoreOf(leaf.manifests),
  options: {
    transparency: strict(leaf.transparency),
    compromiseView: strict(leaf.compromiseView) as unknown as JsonValue[],
    anchorPolicy: anchorPolicyOf(leaf.anchorPolicy),
    logKeys: logKeysOf(leaf.logKeys),
  },
  expected: JSON.parse(leaf.expected) as ExpectedResult,
}))

const LIST_FIELDS = ['errors', 'warnings', 'errors_contains', 'warnings_contains'] as const

/** Every key of `expected.json` this comparison knows how to read. */
const COMPARABLE: ReadonlySet<string> = new Set<string>([...COMPONENTS, 'ok', ...LIST_FIELDS])

/** Compare a run with its fixture the way the conformance harness does. */
function compare(result: VerificationResult, ok: boolean, expected: ExpectedResult): string[] {
  const out: string[] = []
  // A key nobody compares is worse than a failing one: the exhibit would go on
  // saying it matched the vector field for field while a field went unread.
  for (const key of Object.keys(expected)) {
    if (!COMPARABLE.has(key)) out.push(`${key}: this page cannot compare that field`)
  }
  for (const field of COMPONENTS) {
    const want = expected[field]
    if (want === undefined) continue
    const got = result[field]
    if (got !== want) out.push(`${field}: expected ${want}, got ${got}`)
  }
  if (expected.ok !== undefined && ok !== expected.ok) {
    out.push(`ok: expected ${expected.ok}, got ${ok}`)
  }
  const exact = (name: string, want: string[] | undefined, got: readonly string[]): void => {
    if (want === undefined) return
    if (want.length !== got.length || want.some((v, i) => v !== got[i])) {
      out.push(`${name}: expected [${want.join(', ')}], got [${got.join(', ')}]`)
    }
  }
  exact('errors', expected.errors, result.errors)
  exact('warnings', expected.warnings, result.warnings)
  for (const needle of expected.errors_contains ?? []) {
    if (!result.errors.some((e) => e.includes(needle))) out.push(`errors: nothing contains ${needle}`)
  }
  for (const needle of expected.warnings_contains ?? []) {
    if (!result.warnings.some((w) => w.includes(needle))) {
      out.push(`warnings: nothing contains ${needle}`)
    }
  }
  return out
}

export function runExhibit(exhibit: Exhibit): ExhibitRun {
  const run = runVerify(exhibit.envelopeBytes, exhibit.trustStore, null, null, exhibit.options)
  const mismatches = compare(run.result, run.ok, exhibit.expected)
  return { exhibit, run, mismatches, matches: mismatches.length === 0 }
}

export const runExhibits = (): ExhibitRun[] => EXHIBITS.map(runExhibit)
