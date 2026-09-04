#!/usr/bin/env node
// The browser importer, behind a line protocol, at its own shipped defaults.
//
// Reads one JSON request per line on stdin — {"path": …, "fileName": …, "op":
// "parse" | "intake"} — and prints one JSON projection per line, in the shape
// `tools/importer_differential.py` computes from the reference Python importer.
//
// Two entry points, because a page has two: `parseBundle` is the parser a
// caller reaches with bytes in hand, and `intake` is the door a FILE arrives
// at, where a name decides which road the bytes take. A differential that
// asks only the first cannot see a container that never reached it.
//
// No caps are passed. The point of the measurement is what each side admits
// when nobody tells it — the defaults are themselves one of the things that
// can disagree — so this adapter calls both entry points with their own.
//
// The bundle to import is built by the runner (esbuild, into a temp dir) and
// passed as argv[2]; run standalone with a path to a prebuilt bundle.

import { createInterface } from 'node:readline'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const bundlePath = process.argv[2]
if (!bundlePath) {
  process.stderr.write('usage: importer_adapter_ts.mjs <bundle.mjs>\n')
  process.exit(2)
}

const {
  intake,
  declinedForSize,
  parseBundle,
  BundleError,
  BundleTooLargeError,
  canonicalBytes,
  loadsStrict,
} = await import(pathToFileURL(bundlePath).href)

// The outcome vocabulary of the specification's §14.4, not this importer's own
// error catalogue: `resource-limit` is the refusal that says the container was
// not read, and it is the one refusal a surface may not present as invalidity.
const ACCEPT = 'accept'
const RESOURCE_LIMIT = 'resource-limit'
const MALFORMED = 'malformed'
// A class only a file-name door can produce: the bytes were treated as one
// receipt rather than as a container. The reference importer has no way to say
// it, which is the point of recording it rather than folding it into another.
const BARE_ENVELOPE = 'bare-envelope'
const CRASH = 'crash'

/** The digest of a JSON value in its canonical form, or a marker naming the
 *  value as one the canonicalizer refuses. Both sides run their own
 *  canonicalizer over the value they parsed, so the marker is as comparable as
 *  the digest is. */
function canonicalDigest(value) {
  try {
    return createHash('sha256').update(canonicalBytes(value)).digest('hex')
  } catch {
    return 'uncanonicalizable'
  }
}

/** The digest of an envelope as its importer parsed it, addressed the same way
 *  on both sides: parse, then canonicalize, then hash. Hashing the member bytes
 *  instead would compare something the reference importer never keeps. */
function envelopeDigest(bytes) {
  try {
    return canonicalDigest(loadsStrict(bytes))
  } catch {
    return 'unparseable'
  }
}

/** Issuers as a caller of the trust store observes them: a sorted list, because
 *  a store is looked up by name and the order of its members is not a fact
 *  about the bundle. */
function issuerProjection(store) {
  if (!store) return []
  const manifests = store.manifests || {}
  const provenance = store.provenance || {}
  const chains = store.chains || {}
  return Object.keys(manifests)
    .sort()
    .map((issuer) => ({
      issuer,
      provenance: Object.prototype.hasOwnProperty.call(provenance, issuer)
        ? provenance[issuer]
        : null,
      selected: canonicalDigest(manifests[issuer]),
      chain: Object.prototype.hasOwnProperty.call(chains, issuer)
        ? chains[issuer].map(canonicalDigest)
        : [canonicalDigest(manifests[issuer])],
    }))
}

function proofProjection(proofs) {
  return Object.keys(proofs || {})
    .sort()
    .map((id) => ({ id, sha256: canonicalDigest(proofs[id]) }))
}

function classOf(error) {
  if (error instanceof BundleTooLargeError) return RESOURCE_LIMIT
  if (error instanceof BundleError) return MALFORMED
  return null
}

function parseProjection(bytes) {
  let parsed
  try {
    parsed = parseBundle(bytes)
  } catch (error) {
    const outcome = classOf(error)
    if (outcome === null) return { outcome: CRASH, error: String((error && error.message) || error) }
    return { outcome }
  }
  return {
    outcome: ACCEPT,
    receipts: parsed.receipts.map((r) => ({ id: r.receiptId, sha256: envelopeDigest(r.bytes) })),
    issuers: issuerProjection(parsed.trustStore),
    proofs: proofProjection(parsed.proofs),
    // This importer reads the `legal/` family and keeps none of it, so it has
    // nothing to answer here. Recorded as absent rather than as an empty list:
    // "kept nothing" and "cannot say" are different answers and the runner
    // must not be able to read one as the other.
    legal: null,
  }
}

function intakeProjection(fileName, bytes) {
  let result
  try {
    // The size-only admission the surface makes before it materialises the
    // bytes, in the order its own contract puts it: a container refused here
    // was never analysed. Guarded, because a revision that does not export it
    // has not got that boundary and must not look as though it had.
    const declined =
      typeof declinedForSize === 'function' ? declinedForSize(bytes.length) : null
    if (declined !== null && declined !== undefined)
      return { outcome: declined.declined === true ? RESOURCE_LIMIT : MALFORMED }
    result = intake(fileName, bytes)
  } catch (error) {
    return { outcome: CRASH, error: String((error && error.message) || error) }
  }
  if (result.kind === 'rejected')
    return { outcome: result.declined === true ? RESOURCE_LIMIT : MALFORMED }
  if (result.kind === 'needs-manifest')
    return {
      outcome: BARE_ENVELOPE,
      receipts: [{ id: result.label, sha256: envelopeDigest(result.envelopeBytes) }],
      issuers: [],
      proofs: [],
      legal: null,
    }
  // `jobs`. One store per job on the bare road, one shared store on the
  // container road; the union is what a caller can act on either way.
  const issuers = []
  const seen = new Set()
  for (const job of result.jobs)
    for (const entry of issuerProjection(job.trustStore))
      if (!seen.has(entry.issuer)) {
        seen.add(entry.issuer)
        issuers.push(entry)
      }
  issuers.sort((a, b) => (a.issuer < b.issuer ? -1 : a.issuer > b.issuer ? 1 : 0))
  const proofs = result.jobs
    .filter((job) => job.transparency !== null && job.transparency !== undefined)
    .map((job) => ({ id: job.label, sha256: canonicalDigest(job.transparency) }))
  proofs.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  return {
    outcome: ACCEPT,
    receipts: result.jobs.map((job) => ({
      id: job.label,
      sha256: envelopeDigest(job.envelopeBytes),
    })),
    issuers,
    proofs,
    legal: null,
  }
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of lines) {
  if (!line.trim()) continue
  const request = JSON.parse(line)
  let projection
  try {
    const bytes = new Uint8Array(readFileSync(request.path))
    projection =
      request.op === 'intake'
        ? intakeProjection(request.fileName, bytes)
        : parseProjection(bytes)
  } catch (error) {
    // A failure to even read the file is this harness misbehaving, not a
    // verdict about the archive, and it must not be able to look like one.
    projection = { outcome: CRASH, error: String((error && error.message) || error) }
  }
  process.stdout.write(JSON.stringify(projection) + '\n')
}
