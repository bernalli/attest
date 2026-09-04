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
// Both are reached the way the shipped surfaces reach them: through the
// admission boundary they put in FRONT of every road. `site/src/main.ts` and
// `desktop/src/app.ts` each hand a dropped `File` to a reader that consults
// `declinedForSize(file.size)` and only then calls `arrayBuffer()`, so a
// container over v0.1 §14.4's stored floor is refused on the size it declares,
// before a copy of it is paid for. This adapter does the same with the size
// the filesystem declares, and it materialises through one function that
// counts: a refusal issued after the bytes were fetched is reported as a
// crash rather than as a limit, because it is the defect the boundary exists
// to prevent wearing the answer that boundary was supposed to give.
//
// No caps are passed. The point of the measurement is what each side admits
// when nobody tells it — the defaults are themselves one of the things that
// can disagree — so this adapter calls both entry points with their own.
//
// The bundle to import is built by the runner (esbuild, into a temp dir) and
// passed as argv[2]; run standalone with a path to a prebuilt bundle.

import { createInterface } from 'node:readline'
import { readFileSync, statSync } from 'node:fs'
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

// A build that does not export the admission boundary is a surface that has
// lost it, and measuring it as though it still had one is how a green run
// certifies the regression. Guarding the call site instead — "use it if it is
// there" — is exactly that: silent, and green.
if (typeof declinedForSize !== 'function') {
  process.stderr.write(
    'the browser build exports no declinedForSize: the surfaces admit a file on its ' +
      'declared size before materialising it, and a build without that boundary cannot ' +
      'be measured against one that has it\n',
  )
  process.exit(2)
}

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

/** The hash-bound legal members an importer kept, each beside the digest of
 *  the bytes it kept under that name.
 *
 *  The name alone would compare a member LIST; the pair compares the binding
 *  §14.1 states — a `legal/<sha256>.txt` is its own digest — so a side that
 *  admitted the right name over the wrong bytes is visible here and not only
 *  in the outcome class. Keys are digests, so ordering them by code unit and
 *  by code point is the same ordering. */
function legalProjection(texts) {
  return Object.keys(texts || {})
    .sort()
    .map((digest) => ({
      digest,
      sha256: createHash('sha256').update(texts[digest]).digest('hex'),
    }))
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
    // The parser keeps the `legal/` family, digest-checked, exactly as the
    // reference importer does, so there is a value here to hold against the
    // other side's.
    legal: legalProjection(parsed.legalTexts),
  }
}

function intakeProjection(fileName, bytes) {
  let result
  try {
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
      // See the note at the foot of this function: what the door hands back is
      // work to do on a receipt, and legal members are not part of it. Absent,
      // never empty — "kept nothing" and "cannot say" are different answers and
      // the runner must not be able to read one as the other.
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
    // What this door hands a caller is one verify job per receipt — an
    // envelope, a trust store, the evidence keyed to that receipt — and the
    // bundle's legal members are not in that contract. `parseBundle` did read
    // and digest-check them on the way here; they simply do not travel through
    // the job. Absent rather than empty, and the runner narrows the same field
    // out of BOTH sides on this road, so the shape of the interface is never
    // reported as a disagreement about the archive.
    legal: null,
  }
}

/** A file as a surface meets one: a name it was given, the size it DECLARES,
 *  and bytes that exist only once somebody asks for them.
 *
 *  The size of a regular file is metadata — `statSync` reads no byte of it —
 *  which is what makes it the same quantity `File.size` gives the two shipped
 *  surfaces, and what lets the boundary below refuse a container without
 *  paying for it. `reads` is how the refusal is held to that: it counts the
 *  materialisations, and nothing else in this file can fetch the bytes. */
function fileHandle(path) {
  let reads = 0
  return {
    size: statSync(path).size,
    get reads() {
      return reads
    },
    bytes() {
      reads += 1
      return new Uint8Array(readFileSync(path))
    },
  }
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of lines) {
  if (!line.trim()) continue
  const request = JSON.parse(line)
  let projection
  try {
    const file = fileHandle(request.path)
    // The admission boundary the shipped surfaces put in front of EVERY road:
    // there is no way through either page to `parseBundle` that does not pass
    // the dropped file's declared size through here first. `parseBundle` keeps
    // its own front door for the bytes that do arrive, which is a different
    // question — that one bounds a caller who already holds a copy.
    const declined = declinedForSize(file.size)
    if (declined !== null && declined !== undefined) {
      projection =
        file.reads === 0
          ? { outcome: declined.declined === true ? RESOURCE_LIMIT : MALFORMED }
          : {
              outcome: CRASH,
              error:
                'the container was materialised before the boundary refused it, which is ' +
                'the spend §14.4 bounds — the refusal is not the answer to report',
            }
    } else {
      const bytes = file.bytes()
      projection =
        request.op === 'intake'
          ? intakeProjection(request.fileName, bytes)
          : parseProjection(bytes)
    }
  } catch (error) {
    // A failure to even read the file is this harness misbehaving, not a
    // verdict about the archive, and it must not be able to look like one.
    projection = { outcome: CRASH, error: String((error && error.message) || error) }
  }
  process.stdout.write(JSON.stringify(projection) + '\n')
}
