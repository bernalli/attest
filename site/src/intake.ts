import { loadsStrict } from 'attest-verifier'
import type { JsonObject, JsonValue, TrustStore } from 'attest-verifier'
import { parseBundle, BundleError, BundleTooLargeError, bareStore, storedLimitMessage } from './bundle.js'
import { MAX_STORED_BYTES } from './container.js'

export interface VerifyJob {
  label: string
  envelopeBytes: Uint8Array
  trustStore: TrustStore
  // v0.2 §14 evidence that travelled inside the same bundle as this receipt,
  // or null when none did. Untrusted input on the same footing as the
  // envelope itself: it is handed to the verifier, never believed here.
  transparency: JsonValue | null
}

export type IntakeResult =
  | { kind: 'jobs'; jobs: VerifyJob[]; notices?: string[] }
  | { kind: 'needs-manifest'; envelopeBytes: Uint8Array; label: string; notices?: string[] }
  // `declined` marks the one refusal that says nothing about the bytes: the
  // container was not read because it is larger than this surface admits
  // (v0.1 §14.4). A surface MUST NOT show it as invalidity, so it cannot be
  // rendered like every other rejection.
  | { kind: 'rejected'; reason: string; declined?: true }

/** The refusal arm of `IntakeResult`, named so a surface can be handed one
 * without narrowing a union it never built. */
export type Refusal = Extract<IntakeResult, { kind: 'rejected' }>

// Every trust store this module hands on is looked up by an issuer name the
// file being checked chose, so each one is built without a prototype
// (`bareStore`, and the paragraph above it): an ordinary object answers for
// `toString` and the rest of `Object.prototype` as well, and hands back a
// function where a key manifest belongs. The reference importer's store is a
// plain dictionary that answers nothing for those names.
const storeFor = (issuer: string, manifest: JsonObject, provenance: string): TrustStore => {
  const manifests = bareStore<JsonObject>()
  const where = bareStore<string>()
  manifests[issuer] = manifest
  where[issuer] = provenance
  return { manifests, provenance: where }
}

// Frozen because it is a module singleton handed to the verifier and to the
// tamper exhibit: a store whose whole purpose is to answer nothing should not
// be able to start answering because someone downstream wrote to it.
export const EMPTY_TRUST: TrustStore = {
  manifests: Object.freeze(bareStore<JsonObject>()),
  provenance: Object.freeze(bareStore<string>()),
}

const PRIVATE_NAME_MSG =
  'That file is named .private.attest — it holds your binding salts and keys. ' +
  'Never share or upload it anywhere. Drop the shareable .attest instead.'

// A receipt that still carries `delivery.salt` is judged by CONTENT, not by
// name: the name-based refusal above only catches files someone bothered to
// name honestly. It is a warning rather than a refusal on purpose — `attest
// disclose` and the mail integration point both hand over salted envelopes by
// design (§13), and this page is the one place a holder can check their own
// file safely, since verification is entirely client-side and nothing is
// uploaded. What was broken was the silence, not the acceptance.
const saltNotice = (subject: string): string =>
  `${subject} still carries its private binding salt (delivery.salt). ` +
  'Checking it here is safe — everything runs in your browser and the file never leaves ' +
  'your machine — but the file itself is bearer proof: anyone who holds it can claim this ' +
  'purchase is theirs. Keep it with your own files and never email, post, or upload it to ' +
  'anyone — not a store, not support. To share the receipt, share the salt-free .attest ' +
  'file instead; if you only have this one, re-download the pair from your receipt link.'

const carriesSalt = (delivery: JsonObject | null): boolean =>
  delivery !== null && 'salt' in delivery

const deliveryOf = (bytes: Uint8Array): JsonObject | null => {
  try {
    const env = asObject(loadsStrict(bytes))
    return env ? asObject(env['delivery']) : null
  } catch {
    return null
  }
}

const asObject = (v: unknown): JsonObject | null =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null

// A proof member is keyed by the receipt id (v0.2 §14), so the pairing has to
// read that id out of the SIGNED payload — never out of the receipt's own
// member name. v0.1 §14.1 specifies `receipts/*.attest.json` with a wildcard:
// this project's exporter happens to name the file after the id, but a
// conforming bundle from anywhere else need not, and matching on the name
// silently dropped valid evidence for those — `not_checked` reported with the
// proof sitting right there in the same archive. Untrusted like everything
// else here: a wrong id only fails to find evidence, it never transfers
// standing, because the verifier derives the entry it expects from the
// envelope itself.
const receiptIdOf = (bytes: Uint8Array): string | null => {
  try {
    const envelope = asObject(loadsStrict(bytes))
    const payload = envelope ? asObject(envelope['payload']) : null
    const id = payload ? payload['receipt_id'] : undefined
    return typeof id === 'string' ? id : null
  } catch {
    return null
  }
}

// The receipt schema's own ULID grammar, mirrored from `bundle.ts`. A label is
// shown to a person, so its shape is checked before it is shown: a payload can
// carry any string under `receipt_id` — self-signing one costs an attacker a
// keypair — and only the ULID shape is a receipt id rather than a sentence.
const RECEIPT_ID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/

/** What the page may call a file whose signed payload names no usable id.
 *
 * Deliberately not the file name. A file name and a ZIP member name are the
 * same kind of thing — a string the person who sent the file chose — and the
 * defect this constant exists for was exactly that string appearing above a
 * verdict badge as though the verifier had concluded it.
 */
export const UNIDENTIFIED_LABEL = 'Unidentified receipt'

/** The only identifier this page will show for a receipt: the one inside the
 *  signed payload, shaped as the schema requires, or nothing at all. */
export const labelFor = (bytes: Uint8Array): string => {
  const id = receiptIdOf(bytes)
  return id !== null && RECEIPT_ID_RE.test(id) ? id : UNIDENTIFIED_LABEL
}

// The id is attacker-supplied text, so the lookup is on own members only. The
// map `parseBundle` builds has no prototype and its keys are ULID-shaped, which
// closes this twice over; the guard stays because it is this caller's own
// promise about the id it was handed, and not a bet on where the map came from.
const proofFor = (proofs: Record<string, JsonValue>, id: string | null): JsonValue | null =>
  id !== null && Object.prototype.hasOwnProperty.call(proofs, id) ? proofs[id] : null

/**
 * What a surface answers for a file it has NOT read, decided from the size
 * alone — or `null` when the file is within the floor and its bytes may be
 * materialised.
 *
 * This is the admission boundary v0.1 §14.4 asks for: the spend is bounded
 * BEFORE the container is analysed, and a size is metadata, so consulting it
 * reads no byte of the file. Every surface that turns a file into bytes calls
 * this first — the drop targets on both apps, and the sample fetch through its
 * own declared length — because a refusal issued after the copy has already
 * paid for exactly what the floor exists to protect.
 *
 * The outcome is `declined` and never an ordinary rejection. Nobody looked at
 * these bytes, and §14.4 forbids showing an unread container as invalid.
 *
 * A size this boundary cannot make sense of — a `File` that reports none — is
 * not a container over the floor: it is a file this boundary knows nothing
 * about, and it is admitted so the reader downstream can give it a verdict.
 * The parser's own front door bounds the bytes that actually arrive.
 */
export function declinedForSize(storedBytes: number): Refusal | null {
  if (!(storedBytes > MAX_STORED_BYTES)) return null
  return { kind: 'rejected', reason: storedLimitMessage(storedBytes), declined: true }
}

export function intake(fileName: string, bytes: Uint8Array): IntakeResult {
  if (fileName.endsWith('.private.attest')) return { kind: 'rejected', reason: PRIVATE_NAME_MSG }

  // A `.attest` is a container by CONTRACT (v0.1 §14.1), so the extension routes
  // it — and the archive signature keeps its say for a bundle saved under some
  // other name. Deciding on the first two bytes ALONE let a file opt out of the
  // canonical container reader by simply not opening with them: the reference
  // importer refused such a file from its central directory, while this page sent
  // it to the receipt path, where it earned a job. Same bytes, two answers, which
  // is the divergence the canonical reader exists to remove — and the one shape
  // where it mattered most, since a file that reaches a buyer is named `.attest`.
  //
  // A `.attest` that is not an archive is refused BY the container reader now,
  // which is where a file claiming to be a container belongs; the private-file
  // branch above still wins, because `.private.attest` ends in `.attest` too.
  const isZip =
    fileName.endsWith('.attest') ||
    (bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b)
  if (isZip) {
    try {
      const parsed = parseBundle(bytes)
      // Our own exporter strips the salt before it writes a `.attest`, but a
      // bundle from anywhere else gets the same content check as a bare file.
      const notices = parsed.receipts
        .filter((r) => carriesSalt(deliveryOf(r.bytes)))
        .map((r) => saltNotice(`The receipt ${r.receiptId} in this bundle`))
      return {
        kind: 'jobs',
        jobs: parsed.receipts.map((r) => ({
          // The signed id, which `parseBundle` read out of the payload. The
          // member name is how the bytes were found, never what they are.
          label: r.receiptId,
          envelopeBytes: r.bytes,
          trustStore: parsed.trustStore,
          // Matched on the receipt id inside the signed payload (v0.2 §14),
          // which is the only thing the proof member's name is keyed to.
          transparency: proofFor(parsed.proofs, r.receiptId),
        })),
        ...(notices.length > 0 ? { notices } : {}),
      }
    } catch (e) {
      // includes PrivateBundleError; BundleTooLargeError is separated because
      // v0.1 §14.4 forbids showing an unread container as invalid.
      if (e instanceof BundleTooLargeError)
        return { kind: 'rejected', reason: e.message, declined: true }
      if (e instanceof BundleError) return { kind: 'rejected', reason: e.message }
      throw e
    }
  }

  // Bare envelope. Peek for delivery.issuer_manifest; if the bytes don't even
  // strict-parse, hand them to verify() anyway — its error catalog speaks
  // better than we could, and a failing receipt rendering is demo gold.
  let parsed = false
  let embedded: JsonObject | null = null
  let salted = false
  try {
    const env = asObject(loadsStrict(bytes))
    parsed = env !== null
    const delivery = env ? asObject(env['delivery']) : null
    embedded = delivery ? asObject(delivery['issuer_manifest']) : null
    salted = carriesSalt(delivery)
  } catch {
    parsed = false
  }
  // The notice has to survive BOTH bare-envelope exits: a file that needs a
  // manifest is no less a bearer proof than one that carries its own.
  const notices = salted ? { notices: [saltNotice('This file')] } : {}

  if (embedded && typeof embedded['issuer'] === 'string') {
    const issuer = embedded['issuer']
    return {
      kind: 'jobs',
      jobs: [{
        label: labelFor(bytes),
        envelopeBytes: bytes,
        trustStore: storeFor(issuer, embedded, 'embedded'),
        transparency: null, // a bare envelope brings no proofs/ member with it
      }],
      ...notices,
    }
  }
  if (parsed) return { kind: 'needs-manifest', envelopeBytes: bytes, label: labelFor(bytes), ...notices }
  return { kind: 'jobs', jobs: [{ label: labelFor(bytes), envelopeBytes: bytes, trustStore: EMPTY_TRUST, transparency: null }] }
}

export function trustStoreFromManifestBytes(bytes: Uint8Array): TrustStore | null {
  try {
    const m = asObject(loadsStrict(bytes))
    if (m && typeof m['issuer'] === 'string' && Array.isArray(m['keys'])) {
      const issuer = m['issuer']
      return storeFor(issuer, m, 'user-supplied')
    }
  } catch {
    /* not canonical JSON → not a manifest */
  }
  return null
}
