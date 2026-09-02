import { loadsStrict } from 'attest-verifier'
import { canonicalMembers, readMember, ReadBudget, ContainerError } from './container.js'
import type { Member } from './container.js'
import { neutralized } from './untrusted-text.js'
import type { JsonObject, JsonValue, TrustStore } from 'attest-verifier'

export class BundleError extends Error {}
export class PrivateBundleError extends BundleError {}

export type { ContainerCaps as Caps } from './container.js'
import type { ContainerCaps as Caps } from './container.js'
export { DEFAULT_CONTAINER_CAPS as DEFAULT_CAPS } from './container.js'
import { DEFAULT_CONTAINER_CAPS as DEFAULT_CAPS } from './container.js'

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
 * that opened with a sentence the verifier never wrote.
 *
 * Quoting is only a boundary if the name cannot END the quote, and a length
 * cap is no defence at all against a sentence that fits inside it: a member
 * called `x" is genuine. Email refunds@evil.example "` put its claim OUTSIDE
 * the quotes in 48 characters. Two more classes of character rewrite the
 * sentence without adding one visible glyph — an unterminated RIGHT-TO-LEFT
 * OVERRIDE reverses every word that follows it, the verifier's own included,
 * and zero-width characters split a word a reader would otherwise recognise.
 * All three are replaced rather than dropped, so a name that carried one is
 * visibly not the name on disk.
 */
const MAX_QUOTED_MEMBER_CHARS = 60
// The character policy lives in `untrusted-text.ts` and is shared with the
// diagnostic renderer: one rule, so the two cannot drift apart at the first
// correction. This caller's only job is the in-band quoting and the cap.
const quoted = (name: string): string => `"${neutralized(name, MAX_QUOTED_MEMBER_CHARS)}"`

/** Order member names the way the reference importer does: by Unicode code
 * point. JavaScript's default string comparison orders by UTF-16 code unit, so
 * a name outside the basic plane sorts before one whose BMP character is above
 * the surrogate range — and the two importers would meet a broken member in a
 * different order, and complain about a different one. */
const byCodePoint = (left: string, right: string): number => {
  const a = [...left]
  const b = [...right]
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = a[index].codePointAt(0)! - b[index].codePointAt(0)!
    if (difference !== 0) return difference
  }
  return a.length - b.length
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
  // The member list comes from the canonical container reader, not from a ZIP
  // library's own reading of the archive: two readers address the central
  // directory differently, and an archive that exploits that used to show this
  // page one set of members and the reference importer another. The reader
  // refuses any archive where the two addressings could disagree, so the list
  // below is the only list that file has.
  let members
  try {
    members = canonicalMembers(bytes, caps)
  } catch (e) {
    if (e instanceof ContainerError) throw new BundleError(e.message)
    throw new BundleError('not a readable zip archive — expected a .attest bundle or a .attest.json receipt')
  }

  // Secrets are refused from the member LIST, before anything is decompressed —
  // which is what the old comment here claimed while the check sat inside the
  // library's own walk, where a member the archive hid never reached it.
  for (const member of members)
    if (member.name === 'salts.json' || member.name.startsWith('keys/'))
      throw new PrivateBundleError(PRIVATE_MSG)

  // Members are read ON DEMAND, and only the ones a family below claims. The
  // reference importer does the same, and reading every member here instead
  // meant a corrupt member no importer looks at — `unknown.bin` with a broken
  // CRC — was fatal on this page and invisible to the reference one. Same
  // bytes, two verdicts, which is the whole defect being closed.
  const budget = new ReadBudget(caps.maxMemberBytes, caps.maxTotalBytes)
  const read = (member: Member): Uint8Array => {
    try {
      return readMember(bytes, member, budget)
    } catch (e) {
      if (e instanceof ContainerError) throw new BundleError(e.message)
      throw e
    }
  }

  const receipts: { receiptId: string; bytes: Uint8Array }[] = []
  const keyManifestsByIssuer = new Map<string, JsonObject[]>()
  const proofs: Record<string, JsonValue> = {}

  const receiptIds = new Set<string>()

  for (const member of [...members].sort((a, b) => byCodePoint(a.name, b.name))) {
    const name = member.name
    if (name.startsWith('receipts/') && name.endsWith('.attest.json')) {
      const memberBytes = read(member)
      const receiptId = receiptPayloadId(name, memberBytes)
      if (receiptIds.has(receiptId))
        throw new BundleError(`bundle lists receipt_id ${receiptId} more than once`)
      receiptIds.add(receiptId)
      receipts.push({ receiptId, bytes: memberBytes })
    } else if (name.startsWith('manifests/') && name.endsWith('.json')) {
      let blob: JsonObject | null
      try {
        blob = asObject(loadsStrict(read(member)))
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
        evidence = loadsStrict(read(member))
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
