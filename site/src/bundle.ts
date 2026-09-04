import { loadsStrict, sha256Hex } from 'attest-verifier'
import { canonicalMembers, readMember, ReadBudget, ContainerError, MAX_STORED_BYTES } from './container.js'
import type { Member, ContainerCode } from './container.js'
import { neutralized } from './untrusted-text.js'
import type { JsonObject, JsonValue, TrustStore } from 'attest-verifier'

export class BundleError extends Error {}
export class PrivateBundleError extends BundleError {}

/** The importer declined to read the container, and found nothing wrong with it.
 *
 * v0.1 §14.4 asks for this as an outcome of its own, apart from every refusal
 * that says the container is malformed, and the reason is what a holder does
 * next: a refusal of this kind may succeed on a surface that reads more, while
 * a malformed container never will however much budget it is given. Reporting
 * an unread container as corrupt states something about bytes nobody looked at.
 *
 * Mirrors the reference importer's `BundleTooLargeError`, and derives from
 * `BundleError` so a caller who does not care catches what it always caught.
 */
export class BundleTooLargeError extends BundleError {}

/** The container codes that say the importer DECLINED TO READ rather than that
 * it read and found something wrong. v0.1 §14.4 names exactly these five, and
 * the reference importer holds the same set in `_RESOURCE_CODES`. */
const RESOURCE_CODES: ReadonlySet<ContainerCode> = new Set<ContainerCode>([
  'too-many-entries',
  'declared-member-over-cap',
  'declared-total-over-cap',
  'member-over-cap',
  'total-over-cap',
])

/** Carry a container refusal across the boundary in this module's own voice,
 * keeping the outcome class the code already decided. */
const asBundleError = (e: ContainerError): BundleError =>
  RESOURCE_CODES.has(e.code) ? new BundleTooLargeError(e.message) : new BundleError(e.message)

/** What a surface says about a container it did NOT read because of its size
 * as stored (v0.1 §14.4).
 *
 * One sentence, in one place, because three surfaces refuse on this axis — the
 * drop target, the sample fetch and the parser's own front door — and three
 * sentences for one limit would let a holder think they had met three limits.
 * It mirrors the reference importer's `_over_snapshot_bound`: what this bound
 * measures is the size of the FILE and never of anything inside it, so it
 * borrows no wording from the decompression caps, which would send its holder
 * to look at the wrong thing.
 *
 * It names both numbers — how large the container is, and how large this
 * verifier reads — because that difference is the only thing a holder can act
 * on. It never names the file: a file name is text whoever sent the file
 * chose, on the same footing as a ZIP member name (see `quoted` below), and
 * this refusal needs none.
 */
export const storedLimitMessage = (storedBytes: number, limit: number = MAX_STORED_BYTES): string =>
  `container is ${storedBytes} bytes, over the ${limit}-byte limit this verifier reads ` +
  'in order to open it — refusing to read an archive that large'

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
  // The hash-bound legal texts the bundle carries, keyed by the digest each one
  // hashes to (v0.1 §14.1's `legal/<sha256>.txt`). Kept rather than dropped for
  // the reason the family exists: §9's promise is that the bundle preserves the
  // DEAL, and a parser that verified the texts and then threw them away would
  // leave every caller unable to show the terms it just proved intact. Keyed by
  // a name the archive chose, so the store has no prototype (`bareStore`).
  legalTexts: Record<string, Uint8Array>
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

/** A content-address as it may appear in a message a person reads.
 *
 * A sha256 in hex is 64 characters of `[0-9a-f]`, which is four more than the
 * cap above: quoting one would truncate the very string a holder needs whole to
 * find the file that was tampered with. A value of that shape can neither end a
 * quote nor write a sentence, so it is shown bare — the same reasoning that
 * lets `receipt_id` be interpolated bare after it has been matched against its
 * own grammar. Anything else claiming to be a digest is a member name like any
 * other, and is quoted and neutralised as one.
 */
const HEX64_RE = /^[0-9a-f]{64}$/
const digestLabel = (value: string): string => (HEX64_RE.test(value) ? value : quoted(value))

/** A lookup table with no prototype, for every map this file keys by a name the
 * archive chose — issuers, receipt ids.
 *
 * An ordinary JavaScript object is not a dictionary: it inherits members from
 * `Object.prototype`, and one of them, `__proto__`, is an accessor. Writing
 * `store[name] = value` with `name` of `"__proto__"` therefore stores nothing
 * and replaces the object's own prototype instead, so that issuer disappears
 * from the store while every manifest inside it becomes the answer to issuers
 * the archive never named. Reading is the same hazard from the other side: an
 * issuer of `"toString"` resolves to a function where a key manifest belongs.
 *
 * The reference importer holds these in a plain dictionary, where both names
 * are ordinary keys and nothing is inherited. This is how the two are made to
 * agree — the same reason the container reader keeps its members in a list and
 * its seen names in a `Set` rather than in a map built from the file's own
 * strings.
 */
export const bareStore = <T>(): Record<string, T> => Object.create(null) as Record<string, T>

/** Order member names the way the reference importer does: by Unicode code
 * point. JavaScript's default string comparison orders by UTF-16 code unit, so
 * a name outside the basic plane sorts before one whose BMP character is above
 * the surrogate range — and the two importers would meet a broken member in a
 * different order, and complain about a different one. */
const byCodePoint = (left: string, right: string): number => {
  const shared = Math.min(left.length, right.length)
  for (let index = 0; index < shared; index += 1) {
    const l = left.codePointAt(index)!
    const r = right.codePointAt(index)!
    if (l !== r) return l - r
    // One code point above the basic plane occupies two UTF-16 units, and its
    // low surrogate is not a position of its own. Spreading the strings into
    // arrays said the same thing by allocating one string per code point, on
    // every comparison — ten seconds of sorting on a 60 MB archive whose
    // members carry long names, against 44 ms for the UTF-16 sort it replaced.
    if (l > 0xffff) index += 1
  }
  // Only reached when one name is a proper prefix of the other, where the count
  // of UTF-16 units and the count of code points have the same sign.
  return left.length - right.length
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
function receiptPayload(name: string, bytes: Uint8Array): { receiptId: string; payload: JsonObject | null } {
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
  // The payload travels with the id because the completeness pass below needs
  // it, and parsing the envelope a second time to ask a second question would
  // be two readings of one attacker-supplied document.
  return { receiptId, payload }
}

/** Every hash-bound legal document this payload's terms depend on.
 *
 * Mirrors the reference importer's `_referenced_legal_hashes`, field for field:
 * `license.legal_text_sha256`, which the schema requires, plus
 * `survivability.mirror_policy_sha256` and `survivability.eol_commitment_sha256`
 * when they are present and are strings. A malformed or missing block
 * contributes no hashes rather than raising — deciding whether a payload is
 * well-formed is the verifier's job, and this function only says which texts a
 * well-formed one requires.
 */
function referencedLegalHashes(payload: JsonObject | null): string[] {
  const hashes: string[] = []
  if (payload === null) return hashes

  const license = asObject(payload['license'])
  const legalText = license?.['legal_text_sha256']
  if (typeof legalText === 'string') hashes.push(legalText)

  const survivability = asObject(payload['survivability'])
  if (survivability !== null)
    for (const field of ['mirror_policy_sha256', 'eol_commitment_sha256'] as const) {
      const hash = survivability[field]
      if (typeof hash === 'string') hashes.push(hash)
    }

  return hashes
}

function proofMemberReceiptId(name: string): string {
  const relative = name.slice('proofs/'.length)
  const receiptId = relative.endsWith('.json') ? relative.slice(0, -'.json'.length) : ''
  if (relative !== `${receiptId}.json` || !RECEIPT_ID_RE.test(receiptId))
    throw new BundleError(`invalid proof member path ${quoted(name)} — expected proofs/<ULID>.json`)
  return receiptId
}

export function parseBundle(
  bytes: Uint8Array,
  caps: Caps = DEFAULT_CAPS,
  maxStoredBytes: number = MAX_STORED_BYTES,
): ParsedBundle {
  // v0.1 §14.4 bounds the spend BEFORE the members are analysed, and the
  // container as stored is the first quantity a caller can be over. The
  // surfaces admit a file on its size before they ever materialise it, which
  // is where the copy is actually spared; this is the same bound at the
  // parser's own front door, for the callers that arrive with bytes already in
  // hand — `parseBundle` is public, and not every caller passed a `File`.
  //
  // The limit is an argument for the same reason the reference importer's is:
  // an embedder who reads less should be able to say so, and a bound nobody
  // can move is a bound nobody can test at its edge either.
  if (bytes.byteLength > maxStoredBytes)
    throw new BundleTooLargeError(storedLimitMessage(bytes.byteLength, maxStoredBytes))

  // The member list comes from the canonical container reader, not from a ZIP
  // library's own reading of the archive: two readers address the central
  // directory differently, and an archive that exploits that used to show this
  // page one set of members and the reference importer another. The reader
  // refuses any archive where the two addressings could disagree, so the list
  // below is the only list that file has.
  let members: Member[]
  try {
    members = canonicalMembers(bytes, caps)
  } catch (e) {
    if (e instanceof ContainerError) throw asBundleError(e)
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
      if (e instanceof ContainerError) throw asBundleError(e)
      throw e
    }
  }

  const receipts: { receiptId: string; bytes: Uint8Array }[] = []
  const payloads: (JsonObject | null)[] = []
  const keyManifestsByIssuer = new Map<string, JsonObject[]>()
  const proofs: Record<string, JsonValue> = bareStore()
  const legalTexts: Record<string, Uint8Array> = bareStore()

  const receiptIds = new Set<string>()

  for (const member of [...members].sort((a, b) => byCodePoint(a.name, b.name))) {
    const name = member.name
    if (name.startsWith('receipts/') && name.endsWith('.attest.json')) {
      const memberBytes = read(member)
      const { receiptId, payload } = receiptPayload(name, memberBytes)
      if (receiptIds.has(receiptId))
        throw new BundleError(`bundle lists receipt_id ${receiptId} more than once`)
      receiptIds.add(receiptId)
      receipts.push({ receiptId, bytes: memberBytes })
      payloads.push(payload)
    } else if (name.startsWith('manifests/') && name.endsWith('.json')) {
      let blob: JsonObject | null
      try {
        blob = asObject(loadsStrict(read(member)))
      } catch {
        throw new BundleError(`manifest entry ${quoted(name)} is not valid canonical JSON`)
      }
      const issuer = blob?.['issuer']
      if (blob === null || typeof issuer !== 'string') continue // mirror the reference importer: skip unshaped blobs
      // Duplicate member NAMES are refused by the container reader. Two DISTINCT
      // members declaring ONE issuer are the same attack a level up, and keeping
      // the last of them made the key list a receipt is checked against depend on
      // member order rather than on anything the bundle states. A chain of
      // versions for one issuer belongs INSIDE a member, under `key_manifests`,
      // which is the shape the store below is built from.
      if (keyManifestsByIssuer.has(issuer))
        throw new BundleError('bundle lists one issuer in more than one manifest member')
      const raw = blob['key_manifests']
      const kms = Array.isArray(raw) ? raw.map(asObject).filter((m): m is JsonObject => m !== null) : []
      keyManifestsByIssuer.set(issuer, kms)
    } else if (name.startsWith('legal/') && name.endsWith('.txt')) {
      // A legal text is named by the digest of its own bytes (v0.1 §14.1), and
      // §9 is why: the bundle's promise is that it preserves the DEAL, so a
      // text nobody can bind to its name preserves nothing. The reference
      // importer hashes the member and refuses the archive when the two
      // disagree — a structurally perfect zip with an honest CRC and one word
      // of the terms changed is invisible to the container reader and caught
      // here, which is the only place it can be caught.
      //
      // Reading also spends the shared budget on this family, as the reference
      // importer does, so the two agree on the aggregate decompression axis
      // about which archives are too large as well.
      const digest = name.slice('legal/'.length, -'.txt'.length)
      const content = read(member)
      if (sha256Hex(content) !== digest)
        throw new BundleError(
          `legal text ${digestLabel(digest)} failed its own integrity check on import ` +
            '— bundle is corrupt or tampered',
        )
      legalTexts[digest] = content
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

  // Every legal hash referenced by any imported receipt must be present. The
  // reference importer mirrors its own exporter's completeness pass here, so a
  // stripped bundle cannot import as though it still preserved the deal — an
  // archive can be shorn of its terms without touching a signature, and a
  // receipt whose terms are gone is a receipt for nothing anyone can read.
  for (const payload of payloads)
    for (const digest of referencedLegalHashes(payload))
      if (!Object.prototype.hasOwnProperty.call(legalTexts, digest))
        throw new BundleError(
          `bundle is missing legal text for referenced hash ${digestLabel(digest)} ` +
            '— it cannot preserve the deal this receipt refers to',
        )

  const mv = (m: JsonObject): bigint =>
    typeof m['manifest_version'] === 'bigint' ? (m['manifest_version'] as bigint) : 0n
  const manifests: Record<string, JsonObject> = bareStore()
  const provenance: Record<string, string> = bareStore()
  const chains: Record<string, JsonObject[]> = bareStore()
  for (const [issuer, versions] of keyManifestsByIssuer) {
    if (versions.length === 0) continue
    const ordered = [...versions].sort((a, b) => (mv(a) < mv(b) ? -1 : mv(a) > mv(b) ? 1 : 0))
    manifests[issuer] = ordered[ordered.length - 1]
    provenance[issuer] = 'bundle' // offline-imported = TOFU by construction, never 'tls'
    chains[issuer] = ordered
  }

  return { receipts, trustStore: { manifests, provenance, chains }, proofs, legalTexts }
}
