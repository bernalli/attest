import { JsonObject, JsonValue, canonicalBytes, dumps } from './canon.js'
import { verifyStrict } from './ed25519.js'
import { verifyStrict as verifyMldsaStrict } from './mldsa.js'
import { b64uDecode } from './b64u.js'
import { parseStrictUtc } from './dates.js'

export type KeyStatus = 'active' | 'retired' | 'compromised'
export interface KeyEntry {
  kid: string; pub: string; valid_from: string; valid_to: string | null; status: KeyStatus
  pub_ml_dsa_65?: string
}
export interface KeyManifest {
  issuer: string; manifest_version: number; issued_at: string
  keys: KeyEntry[]; manifest_signature: { kid: string; sig: string }
}
export interface TrustStore {
  manifests: Record<string, JsonObject>
  provenance: Record<string, string>
  chains?: Record<string, JsonObject[]>
  // G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
  // amendment) — the artifact-manifest analog of manifests/chains above,
  // scoped as issuer -> work.artifact_series -> manifest/history. Both
  // optional and backward-compatible (mirrors chains?): absent means zero
  // behavior change.
  artifact_manifests?: Record<string, Record<string, JsonObject>>
  artifact_manifest_chains?: Record<string, Record<string, JsonObject[]>>
}

function asObject(v: JsonValue | undefined): JsonObject | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

// G1 normative ceilings (attest-versioning.md §5 amendment; v0.1 §11/§15,
// v0.2 §6/§16) — conformance-surface structural bounds a conforming
// verifier MUST enforce on the untrusted keys[]/artifacts[] arrays before
// doing any signature work over them. Byte-identical to manifests.py.
export const MAX_MANIFEST_KEYS = 256
export const MAX_ARTIFACT_ENTRIES = 4096

// Sorted list of `kid` values appearing on 2+ keys[] entries. Fail-closed on
// malformed input and never throws: a non-array `entries`, a non-object member
// and a non-string `kid` are ignored — none of them can ever resolve anyway.
// Byte-identical semantics to manifests.py's `duplicate_kids` (V-L.3, v0.1
// §7.1 amendment 2026-08-26).
export function duplicateKids(entries: unknown): string[] {
  if (!Array.isArray(entries)) return []
  const seen = new Set<string>()
  const dups = new Set<string>()
  for (const e of entries) {
    const o = asObject(e)
    const kid = o ? o['kid'] : undefined
    if (typeof kid !== 'string') continue
    if (seen.has(kid)) dups.add(kid)
    seen.add(kid)
  }
  return [...dups].sort()
}

/** The entry carrying `kid` — or null if absent, AMBIGUOUS, or `kid` is not
 * a string.
 *
 * With duplicates, element order would decide which lifecycle status wins, so
 * resolution fails closed instead of picking by position (V-L.3, v0.1 §7.1
 * amendment 2026-08-26). This selects the entry carrying the cryptographic
 * material; a lifecycle STATUS is never decided here — that reads every entry
 * for the kid.
 *
 * The type guard is here, at the root, so every caller inherits it —
 * present and future, instead of each one carrying its own copy of the
 * check. A list of callers is only ever shown to be incomplete when somebody
 * finds the missing one, which is how this very property slipped past the
 * duplicate-kid guard: `duplicateKids` compares strings only, so an entry
 * keyed by a non-string is invisible to it, and the kid inside a signature
 * block carries no signature of its own because `signableManifestBytes`
 * drops `manifest_signature`.
 *
 * Python parity: `manifests.find_key` holds the same guard at the same
 * place, so the two cores refuse the same input for the same reason. That
 * sentence was written twice — first claiming a parity that had not landed
 * yet, then corrected to promise it, and now stating it — because a comment
 * about parity goes stale from the OTHER side of the fence without anyone
 * touching this file. If the reference ever moves this check, this line is
 * wrong again and nothing here will fail.
 *
 * A warning for whoever tests this next, paid for once already. A test that
 * passes the pre-parse JavaScript literal into a parsed manifest can miss
 * for the wrong reason — integers become `bigint` at the admission boundary,
 * and objects and arrays acquire a different identity — so three of five
 * negative cases went green with no guard in place at all. Those are
 * accidents of the TEST, not defences in this function: looked up by the
 * value the parsed entry actually carries, every one of the five resolves
 * unless the guard below refuses it.
 */
export function findKey(manifest: JsonObject, kid: string): JsonObject | null {
  if (typeof kid !== 'string') return null
  const keys = manifest['keys']
  if (!Array.isArray(keys)) return null
  let found: JsonObject | null = null
  for (const e of keys) {
    const o = asObject(e)
    if (o && o['kid'] === kid) {
      if (found !== null) return null
      found = o
    }
  }
  return found
}

// The repo does not guarantee `kid` uniqueness inside keys[]. Status decisions
// MUST read every entry: with duplicates of differing status, a first-match
// read lets the array's ORDER decide the verdict. Mirrors manifests.py.
function entriesForKidLocal(manifest: JsonObject, kid: string): JsonObject[] {
  const keys = manifest['keys']
  if (!Array.isArray(keys)) return []
  const matches: JsonObject[] = []
  for (const e of keys) {
    const o = asObject(e)
    if (o !== null && o['kid'] === kid) matches.push(o)
  }
  return matches
}

function kidIsActiveForContinuity(manifest: JsonObject, kid: string): boolean {
  const entries = entriesForKidLocal(manifest, kid)
  return entries.length > 0 && entries.every((entry) => entry['status'] === 'active')
}

export function signableManifestBytes(manifest: JsonObject): Uint8Array {
  const body: JsonObject = Object.create(null)
  for (const k of Object.keys(manifest)) if (k !== 'manifest_signature') body[k] = manifest[k]!
  return canonicalBytes(body)
}

// AND rule: `entry` hybrid (carries `pub_ml_dsa_65`) requires BOTH legs present
// and valid; non-hybrid requires the Ed25519 leg valid and `sig_ml_dsa_65`
// ABSENT. Any other combination fails closed. Never throws — decode/type
// errors on untrusted input are treated as verification failure. Mirrors
// manifests.py's `verify_signature_block` — exported (not module-private, unlike
// the Python function's leading-underscore convention) because it is the
// single shared hybrid-verification primitive behind every v0.2 signed
// side-document: `revocation.ts`'s `verifyRecordSignature` calls this too.
export function verifySignatureBlock(payload: Uint8Array, sigBlock: JsonObject, entry: JsonObject): boolean {
  const isHybridEntry = 'pub_ml_dsa_65' in entry
  const hasMldsaLeg = 'sig_ml_dsa_65' in sigBlock
  if (isHybridEntry !== hasMldsaLeg) return false
  try {
    const sig = sigBlock['sig'], pub = entry['pub']
    if (typeof sig !== 'string' || typeof pub !== 'string') return false
    const edOk = verifyStrict(payload, b64uDecode(sig), b64uDecode(pub))
    if (!isHybridEntry) return edOk
    const mldsaSig = sigBlock['sig_ml_dsa_65'], mldsaPub = entry['pub_ml_dsa_65']
    if (typeof mldsaSig !== 'string' || typeof mldsaPub !== 'string') return false
    return edOk && verifyMldsaStrict(payload, b64uDecode(mldsaSig), b64uDecode(mldsaPub))
  } catch { return false }
}

export function verifyKeyManifest(manifest: JsonObject): boolean {
  try {
    // Fail closed (never throw) if keys[] exceeds MAX_MANIFEST_KEYS — the
    // G1 ceiling: an oversized array is not evaluated at all.
    const entriesForCeiling = manifest['keys']
    if (Array.isArray(entriesForCeiling) && entriesForCeiling.length > MAX_MANIFEST_KEYS) return false
    // v0.1 §7.1 (2026-08-26 amendment): a keys[] array listing any kid twice
    // is rejected in BOTH element orders and wherever a key manifest is
    // consumed, never resolved by position. The duplicated kid need not be
    // the signer's.
    if (duplicateKids(entriesForCeiling).length > 0) return false
    const sigBlock = asObject(manifest['manifest_signature'])
    if (!sigBlock) return false
    const kid = sigBlock['kid']
    if (typeof kid !== 'string') return false
    const entry = findKey(manifest, kid)
    if (!entry) return false
    return verifySignatureBlock(signableManifestBytes(manifest), sigBlock, entry)
    // NOTE: deliberately does NOT check entry.status — a retired/compromised signer still self-verifies.
  } catch { return false }
}

/** Did the issuer actually sign THIS manifest, byte for byte?
 *
 * Narrower than `verifyKeyManifest` on purpose — the Python twin is
 * `manifests.manifest_signature_is_authentic`, and the two must agree. That
 * function answers "is this manifest conformant", which also fails a hybrid
 * signer whose block carries only the Ed25519 leg. The carve-out here is
 * exactly one case and no wider: a hybrid signer whose `manifest_signature`
 * OMITS `sig_ml_dsa_65`, which `26-hybrid/h-manifest-downgraded-continuity`
 * pins as `ok: true`.
 *
 * A PQ leg that is PRESENT is not that case. `manifest_signature` sits
 * OUTSIDE the bytes `signableManifestBytes` covers, so none of its members
 * carry a signature and anyone can graft one on with no key at all; §2.3 is
 * fail-closed in both directions, a stray leg on an Ed25519-only signer
 * included. Never throws.
 */
export function manifestSignatureIsAuthentic(manifest: JsonObject): boolean {
  try {
    const entriesForCeiling = manifest['keys']
    if (Array.isArray(entriesForCeiling) && entriesForCeiling.length > MAX_MANIFEST_KEYS) return false
    if (duplicateKids(entriesForCeiling).length > 0) return false
    const sigBlock = asObject(manifest['manifest_signature'])
    if (!sigBlock) return false
    const kid = sigBlock['kid']
    if (typeof kid !== 'string') return false
    const entry = findKey(manifest, kid)
    if (!entry) return false
    const signable = signableManifestBytes(manifest)
    const sig = sigBlock['sig'], pub = entry['pub']
    if (typeof sig !== 'string' || typeof pub !== 'string') return false
    if (!verifyStrict(signable, b64uDecode(sig), b64uDecode(pub))) return false
    // Absent: the one downgrade the corpus pins. Present: signed material
    // that must verify, or the manifest has been edited.
    const mldsaSig = sigBlock['sig_ml_dsa_65']
    if (mldsaSig === undefined) return true
    const mldsaPub = entry['pub_ml_dsa_65']
    if (typeof mldsaSig !== 'string' || typeof mldsaPub !== 'string') return false
    return verifyMldsaStrict(signable, b64uDecode(mldsaSig), b64uDecode(mldsaPub))
  } catch { return false }
}

export function withinValidity(issuedAt: unknown, entry: JsonObject): boolean {
  const issued = parseStrictUtc(issuedAt)
  const from = parseStrictUtc(entry['valid_from'])
  if (issued === null || from === null) return false
  if (issued < from) return false
  const to = entry['valid_to']
  if (to === null || to === undefined) return true
  const toMs = parseStrictUtc(to)
  if (toMs === null) return false
  return issued <= toMs
}

function preservesAbsorbingCompromises(trusted: JsonObject, candidate: JsonObject): boolean {
  const trustedEntries = trusted['keys']
  const candidateEntries = candidate['keys']
  if (!Array.isArray(trustedEntries) || !Array.isArray(candidateEntries)) return false

  const candidateByKid = new Map<string, JsonObject[]>()
  for (const rawEntry of candidateEntries) {
    const entry = asObject(rawEntry)
    if (entry === null) return false
    const kid = entry['kid']
    if (typeof kid === 'string') {
      const entries = candidateByKid.get(kid)
      if (entries === undefined) candidateByKid.set(kid, [entry])
      else entries.push(entry)
    }
  }

  for (const rawEntry of trustedEntries) {
    const entry = asObject(rawEntry)
    if (entry === null) return false
    const kid = entry['kid']
    if (typeof kid !== 'string') return false
    const currentEntries = candidateByKid.get(kid)
    if (currentEntries === undefined) return false
    if (entry['status'] === 'compromised' && currentEntries.some((current) => current['status'] !== 'compromised')) {
      return false
    }
  }
  return true
}

function withinReleaseWindow(at: unknown, entry: JsonObject): boolean {
  const t = parseStrictUtc(at)
  const from = parseStrictUtc(entry['valid_from'])
  if (t === null || from === null) return false
  if (t < from) return false
  const to = entry['valid_to']
  if (to === null || to === undefined) return true
  const toMs = parseStrictUtc(to)
  return toMs !== null && t <= toMs
}

export function checkContinuity(trusted: JsonObject, candidate: JsonObject): boolean {
  try {
    if (!verifyKeyManifest(trusted) || !verifyKeyManifest(candidate)) return false
    if (trusted['issuer'] !== candidate['issuer']) return false
    const tv = trusted['manifest_version'], cv = candidate['manifest_version']
    if (typeof tv !== 'bigint' || typeof cv !== 'bigint' || cv !== tv + 1n) return false
    const sigBlock = asObject(candidate['manifest_signature'])
    if (!sigBlock) return false
    const signerKid = sigBlock['kid']
    if (typeof signerKid !== 'string') return false
    const signer = findKey(trusted, signerKid)
    if (signer === null || !kidIsActiveForContinuity(trusted, signerKid)) return false
    // The signer key must also cover the candidate's issuance window, consistent
    // with verifyArtifactManifest (2026-07-13 review, finding 12).
    if (!withinValidity(candidate['issued_at'], signer)) return false
    if (!preservesAbsorbingCompromises(trusted, candidate)) return false
    // Bind continuity to the key TRUSTED vouches for: verify the candidate's
    // signature under trusted's pub for signer_kid, NOT the candidate's own
    // (attacker-substitutable) entry (2026-07-13 review, finding 1).
    return verifySignatureBlock(signableManifestBytes(candidate), sigBlock, signer)
  } catch { return false }
}

export function chainContinuous(chain: JsonObject[]): boolean {
  if (chain.length < 2) return true
  for (let i = 0; i < chain.length - 1; i++) if (!checkContinuity(chain[i]!, chain[i + 1]!)) return false
  return true
}

// G3 currency rule (attest-versioning.md rev 4; v0.1 §7.2/§7.3 amendment):
// true iff `candidate` is currency-conformant for `trusted` on the same
// issuer/series. Currency is evaluable only when both manifest_version values
// are bigint >= 1: a regression or an advancing gap is discontinuous. Legacy
// manifests are warn-only and return true. Mirrors manifests.py.
//
// Does NOT verify self-consistency or signer-trust of either manifest
// (unlike checkContinuity, which can call verifyKeyManifest on both sides
// with no external input) — verifyArtifactManifest needs a resolving key
// manifest this function's (trusted, candidate) contract has no room for, so
// that stays the caller's job. Callers MUST authenticate both sides with
// verifyArtifactManifest before calling this metadata-only predicate. Fails
// closed on issuer/series mismatch; a legacy or invalid version is not
// currency-evaluable and returns true.
export function checkArtifactContinuity(trusted: JsonObject, candidate: JsonObject): boolean {
  if (trusted['issuer'] !== candidate['issuer']) return false
  if (trusted['series'] !== candidate['series']) return false
  const tv = trusted['manifest_version'], cv = candidate['manifest_version']
  if (typeof tv !== 'bigint' || tv < 1n || typeof cv !== 'bigint' || cv < 1n) return true
  // Strict N -> N+1 between two DISTINCT versioned manifests. A same-version
  // re-delivery is continuous only if the two manifests are value-identical
  // (canonical-form compare, as the chain tail compare in verify.ts does);
  // two DIFFERENT manifests at the SAME version is the equivocation shape and
  // must not be treated as continuous.
  if (cv === tv) return dumps(trusted) === dumps(candidate)
  return cv === tv + 1n
}

export function artifactChainContinuous(chain: JsonObject[]): boolean {
  if (chain.length < 2) return true
  for (let i = 0; i < chain.length - 1; i++) {
    if (!checkArtifactContinuity(chain[i]!, chain[i + 1]!)) return false
  }
  return true
}

// AND rule (v0.2, mirrors verifyKeyManifest/manifests.py's
// verify_artifact_manifest): if the signer's keyManifest entry is hybrid
// (carries pub_ml_dsa_65), manifest_signature MUST also carry a valid
// sig_ml_dsa_65 leg over the same signed bytes, or verification fails closed;
// an Ed25519-only entry with a stray sig_ml_dsa_65 leg likewise fails closed
// (see verifySignatureBlock). Ed25519-only signers keep v0.1 behavior
// byte-for-byte (Stage 2 Task 6/8 sibling-patch parity).
export function verifyArtifactManifest(manifest: JsonObject, keyManifest: JsonObject): boolean {
  try {
    const manifestVersion = manifest['manifest_version']
    if ('manifest_version' in manifest && (typeof manifestVersion !== 'bigint' || manifestVersion < 1n)) {
      return false
    }
    // G1 ceiling: fail closed if artifacts[] exceeds MAX_ARTIFACT_ENTRIES,
    // mirroring verifyKeyManifest's MAX_MANIFEST_KEYS check.
    const artifactsForCeiling = manifest['artifacts']
    if (Array.isArray(artifactsForCeiling) && artifactsForCeiling.length > MAX_ARTIFACT_ENTRIES) {
      return false
    }
    if (!verifyKeyManifest(keyManifest)) return false
    const sigBlock = asObject(manifest['manifest_signature'])
    if (!sigBlock || typeof sigBlock['kid'] !== 'string') return false
    if (manifest['issuer'] !== keyManifest['issuer']) return false
    const entry = findKey(keyManifest, sigBlock['kid'])
    if (!entry || entry['status'] !== 'active') return false
    if (!withinReleaseWindow(manifest['released_at'], entry)) return false
    return verifySignatureBlock(signableManifestBytes(manifest), sigBlock, entry)
  } catch { return false }
}

// G6 mixed-keyset detection (v0.2 §2.3/§13 amendment): True iff `manifest`
// declares the hybrid profile (at least one keys[] entry carries
// pub_ml_dsa_65) AND ALSO holds at least one Ed25519-only key (no
// pub_ml_dsa_65) whose status is "active". See manifests.py's
// has_active_ed_only_sibling for the full rationale (attack_mixed_keyset_
// hijack) — never throws, malformed keys[] entries are ignored.
export function hasActiveEdOnlySibling(manifest: JsonObject): boolean {
  const entries = manifest['keys']
  if (!Array.isArray(entries)) return false
  const hasHybridKey = entries.some((e) => {
    const o = asObject(e)
    return o !== null && 'pub_ml_dsa_65' in o
  })
  if (!hasHybridKey) return false
  return entries.some((e) => {
    const o = asObject(e)
    return o !== null && !('pub_ml_dsa_65' in o) && o['status'] === 'active'
  })
}
