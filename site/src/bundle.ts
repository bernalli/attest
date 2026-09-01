import { unzipSync } from 'fflate'
import { loadsStrict } from 'attest-verifier'
import type { JsonObject, JsonValue, TrustStore } from 'attest-verifier'

export class BundleError extends Error {}
export class PrivateBundleError extends BundleError {}

export interface Caps {
  maxEntries: number
  maxMemberBytes: number
  maxTotalBytes: number
}

// Tighter than the Python reference importer on purpose: this runs in a
// browser tab. Same three-gate model (entry count, per-member, aggregate).
export const DEFAULT_CAPS: Caps = {
  maxEntries: 10_000,
  maxMemberBytes: 64 * 1024 * 1024,
  maxTotalBytes: 256 * 1024 * 1024,
}

export interface ParsedBundle {
  // Keyed by the `receipt_id` inside the SIGNED payload, never by the member
  // name. A ZIP central directory is attacker-controlled metadata that no
  // signature covers: a member renamed to `VERIFIED by Steam - Official
  // Purchase` used to travel from here into the heading above the verdict
  // badge, with the real signature checking out underneath it. The member name
  // finds the bytes; it never describes them.
  receipts: { receiptId: string; bytes: Uint8Array }[]
  trustStore: TrustStore
  // v0.2 §14: one untrusted §10.2 evidence bundle per receipt, keyed by the
  // receipt id its member name pins. This is EVIDENCE and nothing else — the
  // pinned log keys, anchor policy and witness policy that decide what the
  // evidence is worth are the verifier's own configuration and never travel
  // in a bundle, which is the whole point of keeping the two apart.
  proofs: Record<string, JsonValue>
}

const PRIVATE_MSG =
  'This looks like a .private.attest — it holds your binding salts and keys. ' +
  'Never share or upload it anywhere. Drop the shareable .attest instead.'

const asObject = (v: unknown): JsonObject | null =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null

/** A member name as it may appear in a message a person reads.
 *
 * Naming the offending member is worth keeping — it is how someone finds the
 * broken file — but the name is attacker-supplied, and these messages are
 * rendered to the buyer verbatim. Interpolated bare, a member called
 * `Your receipt is valid. Contact support at …` produced a rejection notice
 * that opened with a sentence the verifier never wrote. Quoting it makes the
 * boundary visible and the length cap keeps a paragraph from arriving where a
 * filename was expected; both matter more than the tail of a long name.
 */
const MAX_QUOTED_MEMBER_CHARS = 60
const quoted = (name: string): string => {
  const flat = name.replace(/\s+/g, ' ')
  const clipped =
    flat.length > MAX_QUOTED_MEMBER_CHARS ? `${flat.slice(0, MAX_QUOTED_MEMBER_CHARS)}…` : flat
  return `"${clipped}"`
}

// The receipt schema's own ULID grammar (Crockford base32, 26 chars, leading
// character 0-7). Mirrors the reference importer's `_RECEIPT_ID_RE`.
const RECEIPT_ID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/

// v0.2 §14: a conforming bundle carries proofs members ONLY as
// `proofs/<ULID>.json`, and an importer must reject every other shape. This
// page joins no filesystem path, so the traversal hazard the grammar closes
// is not ours; the grammar is kept because a member name that is not a
// receipt id cannot name the receipt its evidence is supposed to stand for,
// and accepting one would mean guessing.
// The receipt id inside an imported envelope, strictly shaped — mirrors the
// reference importer's `_receipt_payload_id`. A bundle is attacker-supplied and
// the id is used as an identity, so accept only the ULID shape, never a
// traversal component or a case/normalization variant of a sibling.
function receiptPayloadId(name: string, bytes: Uint8Array): string {
  let envelope: JsonObject | null
  try {
    envelope = asObject(loadsStrict(bytes))
  } catch {
    throw new BundleError(`receipt entry ${quoted(name)} is not valid canonical JSON`)
  }
  const payload = asObject(envelope?.['payload'])
  const receiptId = payload?.['receipt_id']
  if (typeof receiptId !== 'string' || !RECEIPT_ID_RE.test(receiptId))
    throw new BundleError(`receipt entry ${quoted(name)} has invalid receipt_id; expected uppercase ULID`)
  return receiptId
}

function proofMemberReceiptId(name: string): string {
  const relative = name.slice('proofs/'.length)
  const receiptId = relative.endsWith('.json') ? relative.slice(0, -'.json'.length) : ''
  if (relative !== `${receiptId}.json` || !RECEIPT_ID_RE.test(receiptId))
    throw new BundleError(`invalid proof member path ${quoted(name)} — expected proofs/<ULID>.json`)
  return receiptId
}

export function parseBundle(bytes: Uint8Array, caps: Caps = DEFAULT_CAPS): ParsedBundle {
  let entryCount = 0
  let declaredTotal = 0
  let entries: Record<string, Uint8Array>
  try {
    entries = unzipSync(bytes, {
      filter(file) {
        // Secrets are rejected BEFORE anything is decompressed.
        if (file.name === 'salts.json' || file.name.startsWith('keys/'))
          throw new PrivateBundleError(PRIVATE_MSG)
        entryCount += 1
        if (entryCount > caps.maxEntries)
          throw new BundleError(`bundle declares over ${caps.maxEntries} entries — refusing a possible zip bomb`)
        if (file.originalSize > caps.maxMemberBytes)
          throw new BundleError(`member ${quoted(file.name)} is over the per-member decompression cap — refusing a possible zip bomb`)
        declaredTotal += file.originalSize
        if (declaredTotal > caps.maxTotalBytes)
          throw new BundleError('bundle is over the aggregate decompression cap — refusing a possible zip bomb')
        return true
      },
    })
  } catch (e) {
    if (e instanceof BundleError) throw e
    throw new BundleError('not a readable zip archive — expected a .attest bundle or a .attest.json receipt')
  }

  // V-L.6 (v0.1 §14.1, 2026-08-26 amendment): entryCount is incremented per
  // raw central-directory entry inside `filter`, BEFORE Record keys collapse —
  // a mismatch against the surviving key count means duplicate member names,
  // which silently shadow each other (and diverge from the reference importer,
  // which resolves every duplicate to the LAST entry instead of the first).
  const uniqueNames = Object.keys(entries).length
  if (entryCount !== uniqueNames)
    throw new BundleError(
      `bundle central directory repeats ${entryCount - uniqueNames} member name(s) — refusing to import: duplicated members shadow each other`,
    )

  // Declared sizes are header data and can lie low; the inflated lengths are
  // authoritative (mirrors the reference importer's streamed-size rule).
  let actualTotal = 0
  for (const data of Object.values(entries)) {
    if (data.length > caps.maxMemberBytes)
      throw new BundleError('a member inflated past the per-member cap — refusing a possible zip bomb')
    actualTotal += data.length
    if (actualTotal > caps.maxTotalBytes)
      throw new BundleError('bundle inflated past the aggregate cap — refusing a possible zip bomb')
  }

  const receipts: { receiptId: string; bytes: Uint8Array }[] = []
  const keyManifestsByIssuer = new Map<string, JsonObject[]>()
  const proofs: Record<string, JsonValue> = {}

  const receiptIds = new Set<string>()

  for (const name of Object.keys(entries).sort()) {
    if (name.startsWith('receipts/') && name.endsWith('.attest.json')) {
      const receiptId = receiptPayloadId(name, entries[name])
      if (receiptIds.has(receiptId))
        throw new BundleError(`bundle lists receipt_id ${receiptId} more than once`)
      receiptIds.add(receiptId)
      receipts.push({ receiptId, bytes: entries[name] })
    } else if (name.startsWith('manifests/') && name.endsWith('.json')) {
      let blob: JsonObject | null
      try {
        blob = asObject(loadsStrict(entries[name]))
      } catch {
        throw new BundleError(`manifest entry ${quoted(name)} is not valid canonical JSON`)
      }
      const issuer = blob?.['issuer']
      if (blob === null || typeof issuer !== 'string') continue // mirror the reference importer: skip unshaped blobs
      const raw = blob['key_manifests']
      const kms = Array.isArray(raw) ? raw.map(asObject).filter((m): m is JsonObject => m !== null) : []
      keyManifestsByIssuer.set(issuer, kms)
    } else if (name.startsWith('proofs/')) {
      const receiptId = proofMemberReceiptId(name)
      let evidence: JsonValue
      try {
        evidence = loadsStrict(entries[name])
      } catch {
        throw new BundleError(`proof entry ${quoted(name)} is not valid JSON`)
      }
      // Mirror the reference importer: a non-object proof is dropped, not
      // fatal. Its contents are untrusted §10.2 evidence either way — the
      // verifier judges them, this parser only carries them.
      if (asObject(evidence) !== null) proofs[receiptId] = evidence
    }
  }

  if (receipts.length === 0)
    throw new BundleError('no receipts found inside this archive — is it really a .attest bundle?')

  const mv = (m: JsonObject): bigint =>
    typeof m['manifest_version'] === 'bigint' ? (m['manifest_version'] as bigint) : 0n
  const manifests: Record<string, JsonObject> = {}
  const provenance: Record<string, string> = {}
  const chains: Record<string, JsonObject[]> = {}
  for (const [issuer, versions] of keyManifestsByIssuer) {
    if (versions.length === 0) continue
    const ordered = [...versions].sort((a, b) => (mv(a) < mv(b) ? -1 : mv(a) > mv(b) ? 1 : 0))
    manifests[issuer] = ordered[ordered.length - 1]
    provenance[issuer] = 'bundle' // offline-imported = TOFU by construction, never 'tls'
    chains[issuer] = ordered
  }

  return { receipts, trustStore: { manifests, provenance, chains }, proofs }
}
