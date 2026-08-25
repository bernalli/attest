// Stage 4 fixture BUILDERS (v0.2 §18) — sunset grants, cessation
// declarations, publisher key manifests and the holder's redemption response.
//
// src/grant.ts ships verify-only (design §9: no build/sign — see that
// module's header comment, and transfer.ts's before it), so grant.py's
// `build_grant`/`build_declaration`/`sign_redemption` have no src-side
// counterpart here: they are Python-side builder functions with no
// untrusted-input boundary, used only by the reference implementation's own
// CLI tooling. This module mirrors their algorithms for TEST fixtures only,
// hand-signing with @noble/curves + @noble/post-quantum exactly as
// transfer.test.ts and sibling-hybrid.test.ts already do. Keys are derived
// from fixed seeds, never generated: in-memory, per-test fixture material,
// never a committed vector (only docs/spec/vectors/ needs byte-for-byte
// cross-language reproducibility).
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { loadsStrict, canonicalBytes } from '../../src/canon.js'
import type { JsonObject } from '../../src/canon.js'
import { b64uEncode } from '../../src/b64u.js'
import { redemptionMessage } from '../../src/grant.js'

const enc = (s: string) => new TextEncoder().encode(s)

/** Round-trip through the strict parser so JSON integers arrive as `bigint`,
 * the only representation canon.ts's JCS serializer accepts — the same
 * convention every other side-document fixture in this suite uses. */
export const parse = (v: unknown): JsonObject => loadsStrict(enc(JSON.stringify(v))) as JsonObject

/** A signing keypair: Ed25519 always, ML-DSA-65 only for a hybrid signer.
 * Mirrors the `keys.SigningKeyPair | pq.HybridSigningKeys` union grant.py's
 * builders take. */
export interface TestSigner {
  readonly edSeed: Uint8Array
  readonly edPub: Uint8Array
  readonly mldsaPub?: Uint8Array
  readonly mldsaSecret?: Uint8Array
}

/** TEST ONLY — fixed seeds, never use in production. */
export function edSigner(seed: number): TestSigner {
  const edSeed = new Uint8Array(32).fill(seed)
  return { edSeed, edPub: ed25519.getPublicKey(edSeed) }
}

/** TEST ONLY — fixed seeds, never use in production. */
export function hybridSigner(seed: number): TestSigner {
  const edSeed = new Uint8Array(32).fill(seed)
  const mldsa = ml_dsa65.keygen(new Uint8Array(32).fill((seed + 100) % 256))
  return {
    edSeed,
    edPub: ed25519.getPublicKey(edSeed),
    mldsaPub: mldsa.publicKey,
    mldsaSecret: mldsa.secretKey,
  }
}

/** A `signature`/`manifest_signature` block over `bytes`, carrying the
 * ML-DSA-65 leg iff `signer` is hybrid — mirrors manifests.py's
 * `sign_signature_block`, the single primitive grant.py's two builders share
 * with every other v0.2 side-document. */
export function signBlock(bytes: Uint8Array, signer: TestSigner, kid: string): Record<string, unknown> {
  const block: Record<string, unknown> = { kid, sig: b64uEncode(ed25519.sign(bytes, signer.edSeed)) }
  if (signer.mldsaSecret) block['sig_ml_dsa_65'] = b64uEncode(ml_dsa65.sign(bytes, signer.mldsaSecret))
  return block
}

/** A key-manifest entry (v0.1 §7.1), hybrid iff `signer` is. Mirrors
 * manifests.py's `key_entry`. */
export function keyEntry(
  kid: string,
  signer: TestSigner,
  validFrom: string,
  opts: { validTo?: string | null; status?: string } = {},
): Record<string, unknown> {
  const entry: Record<string, unknown> = {
    kid,
    pub: b64uEncode(signer.edPub),
    valid_from: validFrom,
    valid_to: opts.validTo ?? null,
    status: opts.status ?? 'active',
  }
  if (signer.mldsaPub) entry['pub_ml_dsa_65'] = b64uEncode(signer.mldsaPub)
  return entry
}

/** A self-signed key manifest (v0.1 §7.1). Mirrors manifests.py's
 * `build_key_manifest`. */
export function buildKeyManifest(
  issuer: string,
  manifestVersion: number,
  issuedAt: string,
  entries: Record<string, unknown>[],
  signer: TestSigner,
  kid: string,
): JsonObject {
  const body = { issuer, manifest_version: manifestVersion, issued_at: issuedAt, keys: entries }
  const bytes = canonicalBytes(parse(body))
  return parse({ ...body, manifest_signature: signBlock(bytes, signer, kid) })
}

/** Build a publisher-signed sunset grant (§18.2), eleven members. Like
 * grant.py's `build_grant`, this does NOT validate the body it signs:
 * building a deliberately malformed document is how the verification side
 * gets tested, and a document that does not conform simply never
 * authenticates. */
export function buildGrant(body: Record<string, unknown>, signer: TestSigner, kid: string): JsonObject {
  const parsedBody = parse(body)
  return parse({ ...body, signature: signBlock(canonicalBytes(parsedBody), signer, kid) })
}

/** Build a signed cessation declaration (§18.4), four members. The signer is
 * the publisher OR a domain listed in the effective grant's
 * `activation.successor_ids` — a distinction this builder cannot make (it has
 * no grant in hand) and `declarationSignerRole` does. */
export function buildDeclaration(
  publisher: string,
  scope: Record<string, unknown>,
  declaredAt: string,
  signer: TestSigner,
  kid: string,
): JsonObject {
  const body = { publisher, scope, declared_at: declaredAt }
  const bytes = canonicalBytes(parse(body))
  return parse({ ...body, signature: signBlock(bytes, signer, kid) })
}

/** The HOLDER's raw 64-byte Ed25519 signature over `redemptionMessage(...)`.
 *
 * The holder is not a manifest signer, so there is no `kid` here, unlike every
 * publisher-signed side-document. The classical leg is an
 * authorization-liveness mechanism, not the grant's long-term evidentiary
 * wrapper: a post-CRQC forger of THIS leg still cannot forge the publisher's
 * hybrid signature over the grant (§18.2), so the holder leg's classical
 * weakness is bounded by what surrounds it and is never load-bearing alone.
 * Mirrors grant.py's `sign_redemption`. */
export function signRedemption(
  receiptId: string,
  audience: string,
  nonce: Uint8Array,
  holderEdSeed: Uint8Array,
): Uint8Array {
  return ed25519.sign(redemptionMessage(receiptId, audience, nonce), holderEdSeed)
}
