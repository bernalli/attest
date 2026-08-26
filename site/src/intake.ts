import { loadsStrict } from 'attest-verifier'
import type { JsonObject, JsonValue, TrustStore } from 'attest-verifier'
import { parseBundle, BundleError } from './bundle.js'

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
  | { kind: 'needs-manifest'; envelopeBytes: Uint8Array; fileName: string; notices?: string[] }
  | { kind: 'rejected'; reason: string }

export const EMPTY_TRUST: TrustStore = { manifests: {}, provenance: {} }

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

// The id is attacker-supplied text and `proofs` is a plain object, so an id of
// "__proto__" would otherwise resolve to Object.prototype and be handed on as
// if it were evidence.
const proofFor = (proofs: Record<string, JsonValue>, id: string | null): JsonValue | null =>
  id !== null && Object.prototype.hasOwnProperty.call(proofs, id) ? proofs[id] : null

export function intake(fileName: string, bytes: Uint8Array): IntakeResult {
  if (fileName.endsWith('.private.attest')) return { kind: 'rejected', reason: PRIVATE_NAME_MSG }

  const isZip = bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b
  if (isZip) {
    try {
      const parsed = parseBundle(bytes)
      // Our own exporter strips the salt before it writes a `.attest`, but a
      // bundle from anywhere else gets the same content check as a bare file.
      const notices = parsed.receipts
        .filter((r) => carriesSalt(deliveryOf(r.bytes)))
        .map((r) => saltNotice(`The receipt ${r.name} in this bundle`))
      return {
        kind: 'jobs',
        jobs: parsed.receipts.map((r) => ({
          label: r.name,
          envelopeBytes: r.bytes,
          trustStore: parsed.trustStore,
          // Matched on the receipt id inside the signed payload (v0.2 §14),
          // which is the only thing the proof member's name is keyed to.
          transparency: proofFor(parsed.proofs, receiptIdOf(r.bytes)),
        })),
        ...(notices.length > 0 ? { notices } : {}),
      }
    } catch (e) {
      if (e instanceof BundleError) return { kind: 'rejected', reason: e.message } // includes PrivateBundleError
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
        label: fileName,
        envelopeBytes: bytes,
        trustStore: { manifests: { [issuer]: embedded }, provenance: { [issuer]: 'embedded' } },
        transparency: null, // a bare envelope brings no proofs/ member with it
      }],
      ...notices,
    }
  }
  if (parsed) return { kind: 'needs-manifest', envelopeBytes: bytes, fileName, ...notices }
  return { kind: 'jobs', jobs: [{ label: fileName, envelopeBytes: bytes, trustStore: EMPTY_TRUST, transparency: null }] }
}

export function trustStoreFromManifestBytes(bytes: Uint8Array): TrustStore | null {
  try {
    const m = asObject(loadsStrict(bytes))
    if (m && typeof m['issuer'] === 'string' && Array.isArray(m['keys'])) {
      const issuer = m['issuer']
      return { manifests: { [issuer]: m }, provenance: { [issuer]: 'user-supplied' } }
    }
  } catch {
    /* not canonical JSON → not a manifest */
  }
  return null
}
