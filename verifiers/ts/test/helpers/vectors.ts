// Vector loader for the attest conformance suite (v0.1 + v0.2). Reads (never mutates)
// `docs/spec/vectors/` — the language-neutral vector set replayed identically
// by the Python reference's `tests/test_vectors.py`. See that file's module
// docstring for the vector-directory conventions this loader implements.
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { b64uDecode } from '../../src/b64u.js'
import { loadsStrict } from '../../src/canon.js'
import type { JsonObject, JsonValue } from '../../src/canon.js'
import type { Disclosure } from '../../src/index.js'
import type { LogKey } from '../../src/tlog.js'
import type { AnchorPolicy, PinnedHeader } from '../../src/anchor.js'

const HERE = fileURLToPath(new URL('.', import.meta.url))
export const VECTORS_ROOT = join(HERE, '..', '..', '..', '..', 'docs', 'spec', 'vectors')

export function findLeafDirs(root = VECTORS_ROOT): string[] {
  const out: string[] = []
  const walk = (d: string) => {
    if (existsSync(join(d, 'expected.json'))) out.push(d)
    for (const name of readdirSync(d)) { const p = join(d, name); if (statSync(p).isDirectory()) walk(p) }
  }
  walk(root)
  return out.sort()
}
export const vectorId = (dir: string) => relative(VECTORS_ROOT, dir).split(sep).join('/')
const loadJson = (p: string) => JSON.parse(readFileSync(p, 'utf-8'))
// manifests.json / revocation.json feed straight into verify()'s canon-typed
// JsonObject (TrustStore.manifests, revocation records) — anywhere that data
// gets self-verified (manifest signature, revocation record signature) it is
// re-canonicalized via canonicalBytes(), which only accepts `bigint` for JSON
// integers (see canon.ts JsonValue). Plain JSON.parse yields `number` for
// fields like manifest_version, so canonicalBytes() throws TYPE_NOT_JSON and
// the self-verify is silently swallowed as `false`. Route these two files
// through the same strict parser loadsStrict() uses for envelope bytes so
// integers arrive as bigint, matching the runtime type the verifier expects.
const loadJsonValueStrict = (p: string): JsonValue => loadsStrict(new Uint8Array(readFileSync(p)))
const loadJsonStrict = (p: string): JsonObject => loadJsonValueStrict(p) as JsonObject

export function envelopeBytes(dir: string): Uint8Array {
  const raw = join(dir, 'envelope.raw.json')
  if (existsSync(raw)) return new Uint8Array(readFileSync(raw)) // exact bytes; strict parser must reject dups
  return new Uint8Array(readFileSync(join(dir, 'envelope.json')))
}
export function trustStore(dir: string) {
  const d = loadJsonStrict(join(dir, 'manifests.json'))
  return {
    manifests: d.manifests as Record<string, JsonObject>,
    provenance: d.provenance as Record<string, string>,
    chains: (d.chains ?? {}) as Record<string, JsonObject[]>,
    // G2/G3 (attest-versioning.md rev 4, group 31 only) — keyed by issuer
    // and then work.artifact_series; every other leaf keeps these at the
    // empty-object default, same convention as chains.
    artifact_manifests: (d.artifact_manifests ?? {}) as Record<string, Record<string, JsonObject>>,
    artifact_manifest_chains: (d.artifact_manifest_chains ?? {}) as Record<string, Record<string, JsonObject[]>>,
  }
}
export function revocationView(dir: string): unknown[] | null {
  const p = join(dir, 'revocation.json')
  return existsSync(p) ? [loadJsonStrict(p)] : null
}
export function disclosure(dir: string): Disclosure | null {
  const p = join(dir, 'disclosure.json')
  if (!existsSync(p)) return null
  const d = loadJson(p)
  if ('salt_b64u' in d) return { identifier: d.identifier, identifier_type: d.identifier_type, salt: b64uDecode(d.salt_b64u) }
  return { challenge: [b64uDecode(d.nonce_b64u), b64uDecode(d.sig_b64u)] }
}
export const expected = (dir: string) => loadJson(join(dir, 'expected.json'))

// group 28 (transparency/corroboration conformance corpus) only — see
// tools/gen_vectors.py's gen_28_transparency docstring for the on-disk shape.
export function transparencyEvidence(dir: string): JsonValue | null {
  const p = join(dir, 'transparency.json')
  // Routed through loadJsonStrict (not plain JSON.parse), same reasoning as
  // manifests.json/revocation.json above: verify()'s transparency claim
  // resolution re-canonicalizes this evidence via canonicalBytes(), which
  // only accepts bigint for JSON integers (leaf_index/tree_size).
  return existsSync(p) ? loadJsonStrict(p) : null
}
export function logKeys(dir: string): LogKey[] | null {
  const p = join(dir, 'log-keys.json')
  if (!existsSync(p)) return null
  const entries = loadJson(p) as Array<{
    origin: string; name: string; ed25519_pub_b64u: string; mldsa_pub_b64u: string
  }>
  return entries.map((entry) => ({
    origin: entry.origin,
    name: entry.name,
    ed25519Pub: b64uDecode(entry.ed25519_pub_b64u),
    mldsaPub: b64uDecode(entry.mldsa_pub_b64u),
  }))
}
// group 33 (logged-revocation conformance corpus, G5/TM-47) only — see
// tools/gen_vectors.py's gen_33_logged_revocation docstring for the on-disk
// shape. A DIFFERENT evidence channel from transparency.json: fed to
// verify() as revocationEvidence, reusing the SAME logKeys/anchorPolicy.
export function revocationEvidence(dir: string): JsonValue | null {
  const p = join(dir, 'revocation-evidence.json')
  return existsSync(p) ? loadJsonStrict(p) : null
}
// group 35 (transfer conformance corpus, v0.2 §17 Stage 3) only — mirrors
// revocationEvidence(dir)'s file-presence convention. A DIFFERENT evidence
// channel from transparency.json: fed to verify() as transferView, reusing
// group 35's own logKeys/anchorPolicy. Absent for every leaf outside group
// 35, so verify() sees `transferView: null` and existing leaves see zero
// behavior change.
export function transferView(dir: string): JsonValue[] | null {
  const p = join(dir, 'transfer-view.json')
  return existsSync(p) ? (loadJsonValueStrict(p) as JsonValue[]) : null
}
// group 39 (witness-corroboration conformance corpus, v0.2 §11.4, P1.1b)
// only: the TRUSTED `attest-witness-policy-v1` DOCUMENT, fed to verify() as
// `witnessPolicy`. Same rail as logKeys/anchorPolicy — verifier
// configuration, never evidence — so it is its own file and never appears
// nested inside transparency.json. Handed over as the DOCUMENT, not as a
// parsed WitnessPolicy: verify()'s own validateWitnessPolicy() runs
// parsePolicy() over it, which is half of what shipping the document is for
// (the corpus exercises both cores' PARSERS, not just their evaluators).
export function witnessPolicy(dir: string): JsonValue | null {
  const p = join(dir, 'witness-policy.json')
  return existsSync(p) ? (loadJson(p) as JsonValue) : null
}
// group 40 (activation witness quorum, v0.2 §11.4, P1.1b) only: a leaf
// containing `witness-quorum.json` is a THIRD surface, routed to
// `evaluateActivationWitnessQuorum` instead of `verify()` or `auditChain`.
// `expected_origin`/`conflict_domain` are TRUSTED call configuration;
// `epoch_id`/`checkpoint`/`anchor_evidence` are untrusted. The two trusted
// POLICIES stay in their own files beside this one. Plain JSON.parse: nothing
// on this surface is re-canonicalized, so nothing here needs bigint.
export interface QuorumInput {
  expectedOrigin: string
  conflictDomain: string
  epochId: unknown
  checkpoint: unknown
  anchorEvidence: unknown
}
export function quorumInput(dir: string): QuorumInput | null {
  const p = join(dir, 'witness-quorum.json')
  if (!existsSync(p)) return null
  const d = loadJson(p)
  return {
    expectedOrigin: d.expected_origin,
    conflictDomain: d.conflict_domain,
    epochId: d.epoch_id,
    checkpoint: d.checkpoint,
    anchorEvidence: d.anchor_evidence,
  }
}
// group 37 (preservation-pledge conformance corpus, v0.2 §18 Stage 4) only:
// the §18.4 evidence OBJECT `{grant[, later_grants][, declarations][, anchor]}`,
// fed to verify() as `grantView`. Mirrors transferView(dir)'s file-presence
// convention, and like it goes through the STRICT parser: the grant documents
// inside are re-canonicalized (grantHash, verifyGrant's signature check), and
// canonicalBytes only accepts bigint for JSON integers — `grant_version` read
// as a plain `number` would make every grant fail to authenticate. Absent for
// every leaf outside group 37, so verify() sees `grantView: null`, the
// capability gate stays shut, and existing leaves see zero behavior change.
export function grantView(dir: string): JsonValue | null {
  const p = join(dir, 'grant-view.json')
  return existsSync(p) ? loadJsonValueStrict(p) : null
}
// group 38 (redemption, v0.2 §18.7) only: a leaf containing `redemption.json`
// is a FOURTH surface, routed to `verifyRedemption` — never verify(), never
// auditChain, never the quorum evaluator. The question these leaves ask
// involves no receipt and no grant document at all, only whether a holder
// proof is good for THIS custodian, which is why the leaf ships no
// payload/envelope/manifests. Plain JSON.parse: nothing here is
// re-canonicalized, so nothing here needs bigint (same reasoning as
// quorumInput above).
export interface RedemptionInput {
  receiptId: string
  audience: string
  nonce: Uint8Array
  sig: Uint8Array
  holderPubkeyB64u: string
}
export function redemptionInput(dir: string): RedemptionInput | null {
  const p = join(dir, 'redemption.json')
  if (!existsSync(p)) return null
  const d = loadJson(p)
  return {
    receiptId: d.receipt_id,
    audience: d.audience,
    nonce: b64uDecode(d.nonce_b64u),
    sig: b64uDecode(d.sig_b64u),
    holderPubkeyB64u: d.holder_pubkey_b64u,
  }
}
// group 36 (transfer-chain conformance corpus, v0.2 §17.5) only: a leaf
// containing `chain.json` is routed to `auditChain` instead of `verify()` —
// see tools/gen_vectors.py's gen_36_transfer_chain docstring for the shape.
export interface ChainInput {
  payloads: JsonObject[]
  transferView: JsonValue[]
  revocationView: JsonValue[]
}
export function chainInput(dir: string): ChainInput | null {
  const p = join(dir, 'chain.json')
  if (!existsSync(p)) return null
  const parsed = loadJsonValueStrict(p) as JsonObject
  return {
    payloads: parsed.payloads as JsonObject[],
    transferView: parsed.transfer_view as JsonValue[],
    revocationView: parsed.revocation_view as JsonValue[],
  }
}
// group 36 only: auditChain takes ONE trusted keyManifest, not a full
// TrustStore — every group 36 leaf's manifests.json trusts exactly one
// issuer, so its sole `manifests` value is that manifest.
export function soleKeyManifest(dir: string): JsonObject {
  const store = trustStore(dir)
  return Object.values(store.manifests)[0]!
}
export function anchorPolicy(dir: string): AnchorPolicy | null {
  const p = join(dir, 'anchor-policy.json')
  if (!existsSync(p)) return null
  const data = loadJson(p) as {
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
