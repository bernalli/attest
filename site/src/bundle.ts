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
  receipts: { name: string; bytes: Uint8Array }[]
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

// The receipt schema's own ULID grammar (Crockford base32, 26 chars, leading
// character 0-7). Mirrors the reference importer's `_RECEIPT_ID_RE`.
const RECEIPT_ID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/

// v0.2 §14: a conforming bundle carries proofs members ONLY as
// `proofs/<ULID>.json`, and an importer must reject every other shape. This
// page joins no filesystem path, so the traversal hazard the grammar closes
// is not ours; the grammar is kept because a member name that is not a
// receipt id cannot name the receipt its evidence is supposed to stand for,
// and accepting one would mean guessing.
function proofMemberReceiptId(name: string): string {
  const relative = name.slice('proofs/'.length)
  const receiptId = relative.endsWith('.json') ? relative.slice(0, -'.json'.length) : ''
  if (relative !== `${receiptId}.json` || !RECEIPT_ID_RE.test(receiptId))
    throw new BundleError(`invalid proof member path ${name} — expected proofs/<ULID>.json`)
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
          throw new BundleError(`member ${file.name} is over the per-member decompression cap — refusing a possible zip bomb`)
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

  const receipts: { name: string; bytes: Uint8Array }[] = []
  const keyManifestsByIssuer = new Map<string, JsonObject[]>()
  const proofs: Record<string, JsonValue> = {}

  for (const name of Object.keys(entries).sort()) {
    if (name.startsWith('receipts/') && name.endsWith('.attest.json')) {
      receipts.push({ name: name.slice('receipts/'.length, -'.attest.json'.length), bytes: entries[name] })
    } else if (name.startsWith('manifests/') && name.endsWith('.json')) {
      let blob: JsonObject | null
      try {
        blob = asObject(loadsStrict(entries[name]))
      } catch {
        throw new BundleError(`manifest entry ${name} is not valid canonical JSON`)
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
        throw new BundleError(`proof entry ${name} is not valid JSON`)
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
