# attest v0.2 — Normative Specification Delta: Hybrid Signature Profile, Transparency, and Anchoring

- **Status**: Normative, v0.2 (Stage 1, Stage 2, AND Stage 3 — see §1 Scope; Stage 2b witness federation: wire format and verification rules shipped in rev 7, §9.2/§10.1/§11.4, independent operators still outstanding, §15 item 1)
- **Date**: 2026-07-18
- **Grounding**: this document is grounded in the reference implementation in `src/attest/` (`verify.py`, `pq.py`, `manifests.py`, `tlog.py`, `anchor.py`, `transparency.py`, `bundle.py`, `cli.py`, `revocation.py`) and the conformance vectors in [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/) and [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/). It introduces no design decision not already present in the shipped implementation and its conformance corpus (repo rule: spec-follows-implementation).
- **Companion artifacts**: [`docs/spec/attest-v0.1.md`](attest-v0.1.md) (the base specification this document extends — read together, never in isolation); conformance vectors — [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/), [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/), and [`docs/spec/vectors/README.md`](vectors/README.md) (per-group vector index).

This document uses the same conformance language as v0.1 §1 (RFC 2119/RFC 8174 key words, non-normative notes carry no conformance weight).

## 1. Status and scope

attest v0.2 is **additive**: every v0.1 receipt, key manifest, and revocation record remains valid and verifiable forever, under the v0.1 rules, with no expiry. This document does not revise, deprecate, or restrict anything in v0.1 — it defines a second, parallel signature profile selected by the payload's own `attest_version` field.

**No downgrade path.** `attest_version` is INSIDE the signed payload (v0.1 §5.1), so a receipt's version is itself signed and cannot be stripped or rewritten without invalidating the signature. A v0.1 verifier supports only `attest_version: "0.1"` (v0.1 §11 step 1) and MUST reject any `"0.2"` envelope outright, exactly as it would reject any other unsupported version string — there is no compatibility shim and none is planned. Conversely, a v0.2 verifier supports both `"0.1"` and `"0.2"` and dispatches on that field alone, never on `signatures[].alg` (v0.1 §4.1's dispatch prohibition extends unchanged to v0.2).

**This document specifies Stage 1 (§2–§6, the hybrid Ed25519+ML-DSA-65 signature profile), Stage 2 (§7–§16, transparency logging, hybrid checkpoints, anchoring, and the `transparency`/`corroboration`/`manifest_freshness` result components), and Stage 3 (§17, issuer-mediated transfer).** Stage 2 is additive over Stage 1 exactly as Stage 1 is additive over v0.1: it introduces new, purely informational result components (§10) and never changes `signature`, `schema`, `revocation`, `binding`, or the `ok` predicate for any receipt. A verifier that implements only Stage 1 remains fully conforming for everything Stage 1 specifies; it simply never populates the Stage 2 fields (they default to their zero-behavior-change stub values, §10). Stage 3 is additive over Stage 1 and Stage 2 in the same sense, with two stated exceptions: it adds exactly one genuinely new reachable value, `revocation: "transferred"`, to the EXISTING v0.1 §11.1 `revocation` component — §17.3 states precisely when it is reachable and how it affects `ok` — and §17.8's holder-binding conditional makes `license.transferable: true` with a null or absent `buyer.pubkey` a schema error on `attest_version: "0.2"` receipts, a sanctioned newly-recognized-hazard instance under attest-versioning.md §2.

Stage 2 does **not** deliver full anti-equivocation. §15 states this as a normative limitation: detecting two inconsistent signed checkpoints for the same log (`equivocation_detected`, §10.3) is a hard verdict this stage does implement, but *ruling out* equivocation in the general case requires witnesses operated independently of the log, which no revision of this document can supply — that is Stage 2b, a federation/ops effort, not a format change. Its format, however, is no longer outstanding: as of rev 7, §9.2 registers the cosignature identifiers, §11.4 defines the pinned `WitnessPolicy` epochs and the reusable quorum primitives, and §10.1 makes `corroboration: "witnessed"` reachable — one valid type-`0x04` cosignature by a pinned, epoch-valid witness holding the `corroboration` role is sufficient to emit it. A witnessed result asserts timestamped observation and nothing further: every one carries `witness_independence_not_established`, and none of them may be described as proof of organizational independence or as split-view prevention (§10.1, §15 item 1). Revisions before rev 7 forbade emitting `corroboration: "witnessed"` at all; that prohibition is lifted by rev 7 and does not survive it.

Issuer-mediated transfer records (a new record type giving real meaning to the reserved `license.transferable` field) are specified in §17 (Stage 3) as of this revision (rev 6) — built ON the Stage 2 machinery, not beside it: honoring one requires §8's `transfer-record` log entries, §10.2's evidence evaluation, and §13's hybrid AND-rule (§17.2). Stage 2 itself is unaffected by anything Stage 3 adds. Stage 2b witness federation (above) remains a federation-and-operations effort, independent of Stage 3: rev 7 ships its format and its verification rules, while the independent operators — and a non-empty pinned policy for a verifier to check them against — are what is still outstanding.

## 2. The hybrid signature profile (`ed25519+ml-dsa-65`)

### 2.1 Rationale

**Non-normative note:** the classical leg (Ed25519, mature, constant-time reference implementations) covers today's relative immaturity of production PQ signature implementations; the post-quantum leg (ML-DSA-65, FIPS 204) covers a future cryptographically-relevant quantum computer (CRQC). Forging a v0.2 receipt requires breaking **both** primitives — an attacker who breaks only Ed25519 (e.g. via a CRQC) or only ML-DSA-65 (e.g. via a classical cryptanalytic advance) still cannot forge a signature. ML-DSA-65 is NIST security category 3, chosen because it matches the pairing used by `draft-ietf-lamps-pq-composite-sigs` (MLDSA65-Ed25519), maximizing future interoperability with that emerging composite-signature standard.

### 2.2 Envelope structure

A v0.2 hybrid envelope has the same three-member shape as a v0.1 envelope (`payload`, `signatures`, optional `delivery`; v0.1 §4). The only differences are inside `payload.attest_version` and `signatures`:

- `payload.attest_version` MUST equal the literal string `"0.2"`.
- `signatures` MUST be a JSON array containing **exactly two** entries, in this **fixed order**:

```json
{
  "payload": { "attest_version": "0.2", "...": "..." },
  "signatures": [
    { "kid": "store.example.com/keys/2025-01#ed25519-1", "alg": "Ed25519", "sig": "<base64url, 64 bytes decoded>" },
    { "kid": "store.example.com/keys/2025-01#ed25519-1", "alg": "ML-DSA-65", "sig": "<base64url, 3309 bytes decoded>" }
  ]
}
```

- Entry 0 MUST have `alg == "Ed25519"`; entry 1 MUST have `alg == "ML-DSA-65"`. A verifier MUST reject any other order, count, or `alg` value.
- Both entries MUST carry the **same `kid`** — the hybrid pair is one signer, not two independently-resolved keys. The `kid` format is unchanged from v0.1 (`<issuer-domain>/keys/<label>#<name>`, v0.1 §7.1): `kid` is an operator-chosen string, never a hash, and it does not itself encode which algorithms are bound to it.
- Both signatures MUST be computed over the **same** `JCS(payload)` canonical bytes (v0.1 §9) — there is one signature input, signed twice with two different keys.

### 2.3 Composite key binding lives in the manifest, not the kid

Because `kid` carries no algorithm information, the binding between a hybrid signer's Ed25519 and ML-DSA-65 public keys is established entirely by the **key manifest** (v0.1 §7.1): a single key-entry object carries both public keys.

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `pub` | string, base64url, 32 decoded bytes | REQUIRED (unchanged from v0.1) | Ed25519 public key. |
| `pub_ml_dsa_65` | string, base64url, 1952 decoded bytes | REQUIRED for a hybrid signer's key entry; absent for an Ed25519-only entry | ML-DSA-65 public key. Its presence is what makes a key entry "hybrid": a verifier MUST NOT accept a v0.2 hybrid signature against an entry lacking `pub_ml_dsa_65` (§3, step 6). |

Mix-and-match across signers is structurally prevented: both legs of a hybrid signature resolve through the identical signed manifest key-entry (same `kid`, same lookup), so there is no way to pair one signer's Ed25519 key with a different signer's ML-DSA-65 key without also forging the manifest itself.

**Manifest signature must itself be hybrid for a hybrid signer.** A manifest's own `manifest_signature` (v0.1 §7.1) is extended with an optional second member:

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `manifest_signature.sig_ml_dsa_65` | string, base64url, 3309 decoded bytes | REQUIRED iff the manifest was signed by a key whose own entry carries `pub_ml_dsa_65` (i.e. the signer is hybrid); MUST be absent otherwise | ML-DSA-65 signature over the same `JCS(manifest)` (with `manifest_signature` removed) that the Ed25519 leg signs. |

This is **AND-verified, fail-closed in both directions**: a hybrid signer's manifest signature that is missing its `sig_ml_dsa_65` leg MUST be treated as invalid (a downgrade attempt — stripping the PQ leg to fall back to a break-one-primitive forgery), and an Ed25519-only signer's manifest signature that carries a stray `sig_ml_dsa_65` MUST likewise be treated as invalid (a manifest cannot claim hybrid protection for a key that never had a PQ public key). **Rationale:** without this rule, a future CRQC could forge a manifest *rotation* using only the broken classical primitive and thereby bypass the hybrid protection on every receipt the rotation vouches for — the manifest chain is exactly as strong as its weakest verified leg, so the manifest signature's strength MUST match the strength implied by the keys it lists.

**Mixed-keyset prohibition (normative, 2026-07-22 amendment).** An issuer that declares the hybrid profile MUST NOT hold an Ed25519-only key in state `active`. §13 states the migration ceremony and the verifier-side warning this obligation is paired with; conformance vector group [`30-mixed-keyset`](vectors/30-mixed-keyset/) exercises both the violating case and the cleanly-migrated case.

### 2.4 Sizes and measured cost

**Measured 2026-07-17** (ML-DSA-65 / FIPS 204, NIST category 3), base64url-unpadded on the wire:

| Quantity | Raw bytes | b64u (no padding) |
| --- | --- | --- |
| Public key (`pub_ml_dsa_65`) | 1952 | 2603 |
| Secret key (not on the wire) | 4032 | — |
| Signature (`sig`, `sig_ml_dsa_65`) | 3309 | 4412 |

A hybrid receipt and its manifest total roughly 13–14 KB (about 6 KB for the envelope plus 8 KB for the manifest, b64u overhead included) — larger than a v0.1 receipt (a few hundred bytes) but still an acceptable size for a signed receipt document, not a constrained protocol frame.

## 3. Verification algorithm — v0.2 hybrid path

A v0.2-capable verifier executes v0.1 §11's algorithm with the hybrid path substituted for §11 steps 1 and 4 whenever `payload.attest_version == "0.2"`; steps 0 (preconditions), 2 (issuer binding), 3 (key checks), 5 (schema), 6 (revocation), and 7 (binding) are unchanged from v0.1 and are not restated here. Every step below fails closed: any rejection sets `signature: "invalid"` and short-circuits (v0.1 §11's short-circuit rule applies unchanged — `revocation` and `binding` take their stub values `"unknown"`/`"not_checked"`, and `schema` takes `"not_checked"`, whenever a step upstream of schema validation rejects). This is **AND semantics**: both legs must independently verify, or the receipt is invalid.

The reference implementation (`src/attest/verify.py`) executes these checks in exactly this order:

1. **Signature count.** `signatures` MUST have length exactly 2. Otherwise: `hybrid envelope requires exactly two signatures`.
2. **Signature-block structure.** Both entries MUST be objects. Otherwise: `malformed signature block`.
3. **Alg and order.** Entry 0's `alg` MUST equal `"Ed25519"` and entry 1's `alg` MUST equal `"ML-DSA-65"`. Otherwise: `hybrid envelope requires algs Ed25519 and ML-DSA-65 in order`.
4. **Shared kid.** Both entries' `kid` values MUST be identical. Otherwise: `hybrid envelope signatures must share a single kid`.
5. **Kid type.** The shared `kid` MUST be a string. Otherwise: `malformed signature block: 'kid' must be a string`.
6. **Signature type.** Both entries' `sig` values MUST be strings. Otherwise: `malformed signature block: 'sig' must be a string`.
7. **Issuer binding** (shared with v0.1 §11 step 2, unchanged): resolve the manifest for `payload.issuer.id`; the shared `kid`'s DNS-domain prefix and the manifest's own `issuer` field MUST both equal `payload.issuer.id`.
8. **Key checks** (shared with v0.1 §11 step 3, unchanged): the key entry MUST be present in the resolved manifest, MUST NOT be `status == "compromised"` (unconditional, v0.1 §7.3), and `payload.issued_at` MUST fall within the key's `[valid_from, valid_to]` window; a `"retired"` key still verifies, with a warning.
9. **Hybrid key-entry requirement.** The resolved key entry MUST carry `pub_ml_dsa_65`. Otherwise: `key entry for kid {kid!r} has no ML-DSA-65 public key`.
10. **Ed25519 leg.** `Ed25519.verify(JCS(payload), sig_0, pub)` under the v0.1 §10 pinned ruleset, over the same canonical bytes computed once for both legs. Otherwise: `signature verification failed`.
11. **ML-DSA-65 leg.** `ML-DSA-65.verify(JCS(payload), sig_1, pub_ml_dsa_65)`. Otherwise: `ML-DSA-65 signature verification failed`.

Only if both legs (steps 10 and 11) verify does the algorithm continue to v0.1 §11 steps 5–7 (schema, revocation, binding) unchanged.

### 3.1 Error-literal table (verbatim)

A conforming implementation SHOULD surface these exact strings (or a superset containing them, e.g. via `errors_contains` in the conformance harness) so that cross-implementation conformance testing can match on literal text:

| Literal (verbatim) | Emitted when |
| --- | --- |
| `hybrid envelope requires exactly two signatures` | `signatures` length ≠ 2. |
| `malformed signature block` | either signature entry is not an object. |
| `hybrid envelope requires algs Ed25519 and ML-DSA-65 in order` | entry 0/1 `alg` is not exactly `["Ed25519", "ML-DSA-65"]` in that order (includes a duplicated `alg`). |
| `hybrid envelope signatures must share a single kid` | the two entries' `kid` values differ. |
| `malformed signature block: 'kid' must be a string` | the shared `kid` is not a string. |
| `malformed signature block: 'sig' must be a string` | either signature entry's `sig` is not a string. |
| `key entry for kid {kid!r} has no ML-DSA-65 public key` | the resolved manifest key entry lacks `pub_ml_dsa_65`. |
| `signature verification failed` | the Ed25519 leg fails to verify (unchanged literal from v0.1). |
| `ML-DSA-65 signature verification failed` | the ML-DSA-65 leg fails to verify. |

Result vocabulary (`signature`, `schema`, `revocation`, `binding`, `trust`) and the `ok` predicate are unchanged from v0.1 §11.1 — v0.2 introduces no new result values, only new ways to arrive at `signature: "invalid"`.

## 4. Manifest continuity and trust

Rotation continuity (v0.1 §7.3) is unchanged in mechanism — a manifest at `manifest_version` N+1 is auto-trusted only if signed by a key `active` in the version-N manifest already trusted — but for a **hybrid signer**, that continuity check is enforced through the hybrid manifest signature (§2.3): a candidate rotation manifest whose signer key is hybrid but whose `manifest_signature` has been **downgraded** to an Ed25519-only signature (missing `sig_ml_dsa_65`) fails the AND-verified manifest-signature check and is therefore treated as **not validly signed by that key** for continuity purposes — the chain is discontinuous at that point, and the verifier MUST report `trust: "unverified_rotation"` (v0.1 §11.1) exactly as it would for any other discontinuous rotation, even though the receipt's own hybrid signature (§3) may independently verify cleanly against the manifest in use.

The **single-manifest, un-rotated receipt path** — a bare envelope plus a directly-trusted manifest, with no rotation chain in play — is unaffected by this: it continues to follow the existing v0.1 TOFU model (v0.1 §7.4) unchanged. `trust` is `verified` if the manifest was obtained over TLS from the issuer's own domain, `unauthenticated_tofu` otherwise; the hybrid manifest-signature requirement (§2.3) governs whether the manifest itself is accepted as self-consistent, not whether the verifier's *provenance* for that manifest is upgraded.

## 5. Worked example (vector `26-hybrid/a-valid-hybrid`)

Trimmed payload (`attest_version: "0.2"`, otherwise an ordinary `revocability: "none"` receipt):

```json
{
  "attest_version": "0.2",
  "issuer": { "id": "store.example.com", "display_name": "Example Games Store" },
  "issued_at": "2025-07-02T13:50:00Z",
  "receipt_id": "01JZ5PDHT0000G40R40M30E209",
  "license": { "grant": "perpetual", "revocability": "none", "drm": "drm-free", "...": "..." },
  "work": { "title": "Example Game", "publisher": "Example Publisher srl", "...": "..." }
}
```

Envelope — the two-entry hybrid `signatures` array, both entries sharing one `kid` (sizes are illustrative — see §2.4 for the exact byte counts; a full ML-DSA-65 signature is thousands of base64url characters):

```json
{
  "payload": { "attest_version": "0.2", "...": "..." },
  "signatures": [
    { "alg": "Ed25519",   "kid": "store.example.com/keys/2025-01#ed25519-1", "sig": "_srp5DTeCSCG...LsifBQ" },
    { "alg": "ML-DSA-65", "kid": "store.example.com/keys/2025-01#ed25519-1", "sig": "JIuyB18NYaoD...GAh0i" }
  ]
}
```

Key manifest — one key entry carrying both public keys, and a manifest signature carrying both legs:

```json
{
  "issuer": "store.example.com",
  "manifest_version": 1,
  "keys": [
    {
      "kid": "store.example.com/keys/2025-01#ed25519-1",
      "pub": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
      "pub_ml_dsa_65": "LQ5NxHed2F9hW-FOSlutPO5NE3XAARBF5HkSLNPmaHbOL_QrOQ...5nwRmal-cfm5TeRwhXxlyrQtEsFBwGiAdsDsRZKKjNF",
      "status": "active",
      "valid_from": "2025-01-01T00:00:00Z",
      "valid_to": null
    }
  ],
  "manifest_signature": {
    "kid": "store.example.com/keys/2025-01#ed25519-1",
    "sig": "frfQdQJAQbNuZC7bB24_pI_OJvkEIa--F4f5-QLeEYLsFSG5TP8XcQosgSUxebwNf3ZKgh73TDoRGrsKByhcAg",
    "sig_ml_dsa_65": "OGGEM4MjqPb1FeUrVH1AG0lQi_ewMS_Jijhs8gyDz01U4EjeKSTZgrc2Ufcd5JNKa5ktNdGHMTSy8Xg5d7WWNm93yV...jqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAggSFh0i"
  }
}
```

Against this manifest, both signature legs of the envelope above verify (§3 steps 10–11), yielding `signature: "valid"`, `schema: "valid"`, `trust: "verified"`, `ok: true` — the same layered `VerificationResult` shape v0.1 §11.1 defines, unchanged.

## 6. Conformance

The conformance leaf group [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/) adds 8 leaves (a–h) to the existing 45 v0.1/cross-implementation leaves (43 plus [`29-limits`](vectors/29-limits/)'s 2 leaves, v0.1 §15), for 53 total. Each leaf is checked against all three conformance runners (Python reference, TypeScript verifier, and the web verifier where applicable) from the same shared golden files, exactly as the v0.1 corpus is (v0.1 §15).

| Leaf | Checks |
| --- | --- |
| `a-valid-hybrid` | The happy path worked in §5: both legs verify, `ok: true`. |
| `b-ed25519-leg-tampered` | Entry 0's signature bytes flipped post-signing → `signature verification failed`, `signature: "invalid"`. |
| `c-mldsa-leg-tampered` | Entry 1's signature bytes flipped post-signing → `ML-DSA-65 signature verification failed`, `signature: "invalid"`. |
| `d-mldsa-leg-missing` | The ML-DSA-65 entry stripped, leaving only the Ed25519 leg → `hybrid envelope requires exactly two signatures`, `signature: "invalid"` (a stripped PQ leg is not a valid v0.1-shaped fallback; it is rejected outright). |
| `e-duplicate-ed25519-alg` | Both entries carry `alg: "Ed25519"` → `hybrid envelope requires algs Ed25519 and ML-DSA-65 in order`, `signature: "invalid"`. |
| `f-kid-mismatch-between-legs` | The two entries carry different `kid` values → `hybrid envelope signatures must share a single kid`, `signature: "invalid"`. |
| `g-key-entry-not-hybrid` | The resolved manifest key entry has no `pub_ml_dsa_65` → `key entry for kid {kid!r} has no ML-DSA-65 public key`, `signature: "invalid"`. |
| `h-manifest-downgraded-continuity` | A rotation candidate manifest signed by a hybrid key but with its `manifest_signature` downgraded to Ed25519-only (§4) → the receipt's own hybrid signature still verifies (`signature: "valid"`, `ok: true`), but `trust: "unverified_rotation"`, because the manifest signature itself failed the hybrid AND-check and the rotation chain is therefore discontinuous. |

### 6.1 Vector determinism and cross-implementation parity

**Non-normative note:** the 26-hybrid vectors are generated deterministically by [`tools/gen_vectors.py`](../../tools/gen_vectors.py), the same generator and the same determinism gate as the v0.1 corpus (v0.1 §15 / [`docs/spec/vectors/README.md`](vectors/README.md) "Regeneration"). ML-DSA-65 keys and signatures are produced with the dev-only oracle `dilithium-py` (`ML_DSA_65.key_derive(seed)` from a committed fixed seed, `sign(sk, m, deterministic=True)` per the FIPS 204 deterministic variant) — reproducible byte-for-byte, never used at verification runtime in either production package. At runtime, `pqcrypto` (Python, PQClean-derived) and `@noble/post-quantum` (TypeScript) independently verify the same vectors, so cross-implementation parity is exercised by the corpus itself rather than by a separate parity harness.

### 6.2 Normative ceilings apply to v0.2 too (2026-07-22 amendment)

v0.1 §11.3's structural ceilings (raw envelope size, parsed-tree nesting depth, issuer key manifest `keys[]` length, artifact manifest `artifacts[]` length) are wire/envelope-level requirements, not v0.1-payload-shape-specific ones — they bind every `attest_version` this specification family defines, including v0.2's hybrid envelopes and hybrid key manifests. No v0.2-specific ceiling value differs from v0.1's; this section exists only to state the binding explicitly, since a reader of the additive v0.2 delta might otherwise assume §11.3 stayed v0.1-scoped.

## 7. Stage 2 architecture and substrate

### 7.1 The corroboration thesis

**Non-normative note:** a transparency log proves *existence* and, with a witness quorum, *append-only history* — never *domain control*. attest key manifests are self-signed (v0.1 §7.1) and a log is an open-ingestion host, so "this manifest is in the log" says nothing by itself about who controls issuer X's domain. Stage 2 therefore introduces the log as a **corroboration layer**, orthogonal to `trust`, never a replacement for it (§10). `trust: "verified"` continues to require an independent domain-control root (a TLS fetch from the issuer's own domain, v0.1 §7.4, unchanged); a log-corroborated manifest with no such root stays `unauthenticated_tofu`.

### 7.2 Log substrate: a documented C2SP tlog-tiles subset

A conforming Stage 2 log is a static, mirrorable file set following the shape of [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) (RFC 6962 Merkle tree, SHA-256 leaf/interior hashing, §7.1's tiles carry leaf hashes, a signed-note checkpoint attests to the tree root) — with one documented, honest subset of the full C2SP profile, matching the reference layout (`src/attest/cli.py`, module-level `attest log` on-disk layout comment):

- **`entries.jsonl` is the SOLE source of truth.** One JSON entry object per line, append-only. Every other on-disk artifact is derived from it: tiles, the RFC 6962 tree root, and the unsigned checkpoint candidate are recomputable from `entries.jsonl` alone by re-running RFC 6962 `MTH` (v0.1's Merkle build, `tlog.build_tree`) over the re-encoded entries. The signed checkpoint's note body is likewise recomputable, but producing its signatures requires the ceremony-side private keys.
- **Level-0 (leaf-hash) tiles only.** A full C2SP tlog-tiles deployment materializes interior-level cache tiles as a read-amplification optimization for very large logs. A conforming Stage 2 log MAY materialize only level-0 tiles (leaf hashes, `_TILE_FULL_WIDTH = 256` leaves per full tile) and MUST always recompute the tree root from the entries list directly rather than trusting a cached interior tile — this is a documented, intentional subset, not full C2SP tlog-tiles.
- **Partial-tile naming is flattened.** A not-yet-full tile at the growing right edge of the log is named `<index>.p.<width>` — a flattened stand-in for C2SP's nested `<index>.p/<width>` directory form. The nested form exists in the C2SP spec purely to keep tile URLs short at huge scale; this document's flattened form is equivalent content addressed differently, and is what a conforming implementation MUST produce and accept.

A conforming implementation MUST fully rebuild its tile cache from `entries.jsonl` on every append (never patch a tile incrementally). The tile cache carries no authority: signing and proof generation MUST recompute from `entries.jsonl` and MUST NOT consult tiles.

### 7.3 Log key custody: the offline-signer split

Log signing keys are held offline (HSM/ceremony), never by the CI or serving process that appends entries (design doc "Log key custody: offline/HSM ceremony, never CI"). A conforming Stage 2 log implementation MUST split the append and sign responsibilities into two separately-administered steps:

1. **`log append` (CI-side).** Validates and appends one new entry to `entries.jsonl`, rebuilds the level-0 tile cache, recomputes the tree root, and writes an **UNSIGNED** checkpoint candidate (origin, decimal tree size, base64 root — the same three header lines a signed checkpoint's note body carries, §9.1 — with no signature lines at all; this is genuinely unsigned, not a signed note with an empty signature list, which the checkpoint grammar rejects outright, §9.1). This step holds no signing key material of any kind.
2. **`log sign-checkpoint` (ceremony-side).** The ONLY step that may hold the log's Ed25519/ML-DSA-65 secret keys. It MUST independently recompute the tree root from `entries.jsonl` (never trust the candidate's claimed root) and refuse to sign unless that recomputation matches the candidate exactly; if a checkpoint was previously signed for this log, it MUST additionally verify the new tree is a valid RFC 6962 consistency-proof extension of the prior signed tree (v0.1's `tlog.verify_consistency`) before signing a successor. Both checks are against the log's own authoritative on-disk state, never against which flags were passed on the command line.

This split is what makes the log's signing key operationally independent of the (comparatively higher-exposure) ingestion path — an attacker who compromises the CI-side append step obtains no signing capability at all, only the ability to propose entries a separately-administered signer may refuse.

Pinned log keys (§9.2 `LogKey`) ship baked into the verifier's own trust store, distributed and rotated out-of-band from any bundle. A conforming verifier MUST NOT take log keys from a bundle: bundle-embedded key material is untrusted and is never a trust root.

## 8. Log entry schemas

Every entry admitted to the log is a CLOSED, versioned, JCS-canonicalized object (`tlog.encode_entry`): unknown members are rejected outright (no silent extension of a schema in production use — schema extension is a registry-governed change, out of this document's scope), and the canonical bytes produced are exactly what gets RFC 6962 leaf-hashed: `tlog.leaf_hash(entry_bytes) = SHA-256(0x00 || entry_bytes)`. Exactly four entry types are defined:

| Type | Members (exactly these, no more, no fewer) | Semantics |
| --- | --- | --- |
| `key-manifest` | `type` (`"key-manifest"`), `issuer` (lowercase DNS name, same shape as the receipt schema's `issuer.id`), `manifest_version` (int, `1 <= manifest_version <= 2**53 - 1`), `manifest_sha256` (64 lowercase-hex chars) | `manifest_sha256 = SHA-256(JCS(manifest))` — the hash of the manifest as it re-canonicalizes, not of any particular served byte stream (v0.2 §5's `manifest_sha256` domain, unchanged for Stage 2). |
| `receipt` | `type` (`"receipt"`), `issuer` (lowercase DNS name), `core_sha256` (64 lowercase-hex chars) | `core_sha256` is the **signed-receipt-core hash** defined in §12 — never a hash of `payload` alone. `issuer` here is a NON-AUTHENTICATED hint only, a convenience for log browsing/filtering; a conforming verifier MUST NOT read it as attribution — the receipt's own signature is what binds it to an issuer. |
| `revocation-record` (G5, TM-47, rev 5) | `type` (`"revocation-record"`), `issuer` (lowercase DNS name), `record_sha256` (64 lowercase-hex chars) | `record_sha256 = SHA-256(JCS(record))`, where `record` is the ENTIRE issuer-signed revocation record (design §3.1/§6, v0.1 §12.2) — including its own `signature` member, the same canonicalization `revocation.py`/`revocation.ts` already build and verify the record's signature over (`revocation.record_hash` / `recordHash`; one canonical form, never a second one). `issuer` here is the same NON-AUTHENTICATED browsing hint as `receipt`'s — the record's own signature (verified against the issuer's key manifest, §13) is what binds it to an issuer, never this entry. §15 item 5 defines the one behavioral consequence of a record's presence (or absence) in the log: the `refund_window` deadline-effectiveness rule. |
| `transfer-record` (Stage 3, rev 6) | `type` (`"transfer-record"`), `issuer` (lowercase DNS name), `record_sha256` (64 lowercase-hex chars) | `record_sha256 = SHA-256(JCS(record))` over the ENTIRE signed transfer record (§17.1) — including its own `signature` member, the identical hashing discipline `revocation-record` above already establishes, applied to the new record shape. `issuer` here is the same NON-AUTHENTICATED browsing hint as `receipt`'s and `revocation-record`'s — the record's own signature (verified against the issuer's key manifest, §13) is what binds it to an issuer, never this entry. §17.2 defines the one behavioral consequence of a transfer record's presence (or absence) in the log: the log-required honoring rule (D2). |

An entry whose `type` is not one of these four, or whose member set is not exactly the required set, MUST be rejected by the log (never admitted) and, if encountered as evidence during verification, MUST resolve to `transparency: "not_checked"` (§10.2) rather than being partially trusted.

## 9. Checkpoints: the hybrid C2SP signed-note profile

### 9.1 An explicit carve-out: signed bytes are C2SP signed-note TEXT, not JCS

Every other signed artifact in this protocol (v0.1 payloads, v0.2 §2 envelopes, key manifests, artifact manifests, revocation records) is signed over `JCS(...)` canonical bytes. **Checkpoints are the one explicit exception**, by design, for Stage 2b witness compatibility: a checkpoint's signed bytes are the [C2SP signed-note](https://c2sp.org/signed-note) TEXT format — three ASCII header lines (`origin`, decimal `tree_size`, standard-base64 32-byte `root`), each newline-terminated, WITHOUT the blank line that separates the header from the signature lines that follow it (`tlog.Checkpoint.note_bytes` — "the three header lines... through their final newline, excluding the blank line"). This carve-out exists so a Stage 2 checkpoint is byte-for-byte a C2SP tlog-checkpoint note, interoperable with the wider C2SP witness ecosystem — the property rev 7's cosignature path already relies on (§9.2, §11.4), and the one that will let independently operated witnesses cosign without any format change (§15) — a JCS-wrapped checkpoint would not be.

A checkpoint's full serialized text is: the three header lines, a blank line, then one or more C2SP signature lines of the form `— <name> <base64(key-hash || signature)>` (an em dash U+2014, one space, key name, one space, standard base64 with padding). The whole text MUST end with a trailing newline. A conforming implementation MUST reject a checkpoint text that has any other shape (missing header line, missing blank-line separator, non-decimal tree size, a root that does not decode to exactly 32 bytes, zero signature lines, a malformed signature line) — see the literal-error table in §9.4.

### 9.2 Hybrid signature, mandatory

A checkpoint carries a **key-id** — a 4-byte prefix `SHA-256(name || "\n" || signature-type || pub)[:4]` (C2SP's key-hash convention) — and BOTH of the following signature legs, keyed by the same log key `name`:

- An **Ed25519** signature over `note_bytes`, using C2SP's assigned signature-type byte `0x01`.
- An **ML-DSA-65** signature over the same `note_bytes`, using signature-type `0xff` (C2SP's own extension mechanism — "signature types without an identifier byte assigned by this specification") followed by the identifier string `attest-ml-dsa-65`. This document REGISTERS INTENT for this type but it is NOT YET IN THE C2SP REGISTRY — a future single-byte assignment cannot collide with it, since it is namespaced under `0xff`. (Byte `0x06` was considered and rejected: the C2SP registry assigns `0x06` to a *timestamped ML-DSA-44 cosignature*, a different algorithm and a different note-signature shape than the plain ML-DSA-65 leg this document defines.)

Standing requires **BOTH** legs to independently verify against a pinned `LogKey`'s matching public key (fail-closed AND — mirrors `manifests.py`'s hybrid `manifest_signature` discipline, v0.2 §2.3). An Ed25519-only checkpoint — even one whose Ed25519 signature is genuinely valid — MUST NOT confer any `transparency`/`corroboration` standing (conformance vector 28c). A conforming verifier scans every signature line whose `name` matches the pinned key's `name`; a line whose key-hash prefix doesn't match either expected leg's prefix simply does not count toward that leg and scanning continues — a signed-note convention, not a fatal condition, since multiple parties — Stage 2b witnesses included, whose cosignature lines §9.2 and §11.4 define — may sign lines with different names in the same note.

**Witness cosignature registration (P1.1b amendment).** A witness's interoperable Ed25519 leg is C2SP type `0x04`.  The hybrid activation-grade ML-DSA-65 leg is type `0xff || UTF8("attest-cosignature-ml-dsa-65-v1")`; its identifier is exactly `attest-cosignature-ml-dsa-65-v1`, and it is distinct from the checkpoint identifier `attest-ml-dsa-65`.  Both legs sign the byte-identical payload `UTF8("cosignature/v1\n") || UTF8("time " + decimal_timestamp + "\n") || checkpoint.note_bytes`. C2SP type `0x06` MUST NOT count as either leg: it is not this ML-DSA-65 cosignature type or payload.

### 9.3 Origin and key-name grammar: printable ASCII on both cores

Checkpoint `origin` and `LogKey.name` are each constrained to **non-empty printable ASCII**: `origin` to the range `0x20`–`0x7e` inclusive; `name` to `0x21`–`0x7e` inclusive and additionally forbidden from containing `+` (avoids ambiguity with C2SP's `+`-delimited note-signer conventions). This is a deliberate protocol decision, not an oversight: a `\p{}`-class Unicode grammar would drift between the Python and TypeScript runtimes' bundled Unicode Character Database versions, making acceptance version-dependent across the two conformance cores. Restricting to ASCII makes the grammar identical, forever, regardless of either runtime's Unicode table.

For the same reason, diagnostic rendering of untrusted origin/name/tree-size/signature-line values follows **Python `ascii()` per-character escape semantics on both cores**: printable ASCII passes through unchanged, and every other code point renders as `\xNN` (one byte, `< 0x100`), `\uNNNN` (BMP), or `\UNNNNNNNN` (astral). The reference implementations are `tlog.py`'s `_trunc_repr` (Python, calling `ascii()` directly) and `verifiers/ts/src/messages.ts`'s `pyStage2StringRepr` (TypeScript). The TypeScript `pyRepr` used by some checkpoint diagnostics has a known, non-normative quote-style deviation from Python `repr` for apostrophes and backslashes; it affects diagnostic text only, never parsing, acceptance, or verdicts.

### 9.4 Checkpoint error literals (verbatim)

| Literal (verbatim, `{...}` interpolated) | Emitted when |
| --- | --- |
| `checkpoint text must end with a newline` | checkpoint text is missing its trailing `\n`. |
| `checkpoint header must be followed by a blank line` | the line immediately after the 3 header lines is not empty. |
| `tree size must be ASCII decimal digits: {trunc}` | the tree-size header line is not pure ASCII decimal. |
| `tree size must not contain leading zeros: {trunc}` | the tree-size header line has a leading `0` with more than one digit. |
| `root must decode to 32 bytes, got {n}` | the base64-decoded root header is not exactly 32 bytes. |
| `malformed checkpoint signature line: {trunc}` | a signature line does not match `— <name> <base64>`. |
| `checkpoint origin {origin!r} != expected_origin {expected!r}` | the checkpoint's own origin disagrees with the caller's pinned expectation. |
| `checkpoint origin {origin!r} != log_key.origin {origin!r}` | the checkpoint's own origin disagrees with the pinned `LogKey`'s origin. |
| `checkpoint has no valid Ed25519+ML-DSA-65 signature pair for name {name!r}` | after scanning every signature line, at least one hybrid leg never verified. |

`{trunc}` denotes the `ascii()`-rendered, length-bounded value described in §9.3 (never the raw untrusted text). These literals are Python-side (`tlog.py`); `verifiers/ts/src/tlog.ts` renders the equivalent message with `pyRepr`/`truncRepr` for parity, matching the same substrings a conformance harness checks against.

## 10. Result contract: `transparency`, `corroboration`, `manifest_freshness`

Stage 2 adds three new, purely informational `VerificationResult` components (v0.1 §11.1's table gains three rows; none of the five original rows, nor `ok`, gain a new possible value). **The log NEVER upgrades `trust`, and these three components never affect `signature`, `schema`, `revocation`, `binding`, or `ok`** — this is Stage 2's central correctness property, not an incidental one (design doc: the log is a corroboration layer, not an authenticity layer), **with exactly two scoped exceptions: (G5, TM-47, rev 5) a `refund_window` revocation record's effectiveness, once a verifier is Stage-2 capable and evaluates `revocation-record` transparency evidence for it — §15 item 5 states the rule precisely; and (Stage 3, rev 6) an authenticated `transferred`-class record is honored ONLY when its transfer record's `holder_authorization` verifies AND its log inclusion proof checks out (§17.3).** Their defaults (`not_checked` / `none` / `not_checked`) are the exact values every pre-Stage-2 caller already implicitly gets, so Stage 1 behavior is unchanged for any caller that never supplies transparency evidence (and, per §15 item 5 and §17.3, for any caller that never engages either exception).

### 10.1 Vocabulary

| Component | Allowed values |
| --- | --- |
| `transparency` | `not_checked` \| `logged` \| `anchored_before:<T>` \| `equivocation_detected` |
| `corroboration` | `none` \| `logged` \| `witnessed` |
| `manifest_freshness` | `not_checked` \| `verified_as_of:<N>` |

`anchored_before:<T>` concatenates the fixed prefix with `T`, an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) rendered from the anchor's pinned Bitcoin block-header time (§11). `verified_as_of:<N>` concatenates the fixed prefix with `N`, the checkpoint's own `tree_size` at the moment the claim was evaluated — a size, not a wall-clock time, since a manifest's freshness is bounded by log inclusion order, not by anchor time.

`corroboration: "witnessed"` asserts timestamped witness observation only. It MUST NOT be described as proof of organizational independence or split-view prevention. One valid Ed25519 C2SP type-`0x04` cosignature by a pinned, epoch-valid witness with the `corroboration` role is sufficient to emit it. Every P1.1b-produced witnessed result carries `witness_independence_not_established`: domain inequality MUST NOT establish independence, and v1 defines no positive independence certificate or inference rule.

### 10.2 Evidence input and decision order

A verifier evaluates at most one untrusted **evidence bundle** per claim (`attest.transparency.evaluate_transparency`), shaped:

```json
{
  "entry": { "...": "the log entry the caller claims corroborates this artifact" },
  "leaf_index": 0,
  "tree_size": 1,
  "inclusion_proof": ["<64-hex-char>", "..."],
  "checkpoint": "<C2SP signed-note text, §9>",
  "prior_checkpoint": "<optional, C2SP signed-note text>",
  "consistency_proof": ["<64-hex-char>", "..."],
  "anchors": { "...": "optional anchor evidence, §11" },
  "witness_policy_epoch": "optional epoch identifier for witness evaluation"
}
```

`evidence` is entirely untrusted (it arrives from wherever the bundle was fetched — a log mirror, an anchor service, or an adversary) and evaluation NEVER raises because of anything in it; every failure degrades to `(transparency: "not_checked", corroboration: "none")` plus a warning naming the condition, except equivocation, which is its own hard verdict (§10.3). `log_keys`, `expected_origin`, `policy`, `witness_policy`, and `expected_entry` are the TRUSTED, verifier-config side of the call — computed by the caller from its OWN trusted artifacts (never read off the evidence itself, §12) — and a malformed one of these raises, since that signals a caller/configuration bug, not adversarial input. Evidence MUST identify `witness_policy_epoch` explicitly; the current epoch is never substituted. Evidence MUST NOT carry epoch contents: it carries only that identifier, cosignature lines already in the signed note, and ordinary anchor evidence. This adds no checkpoint-body member or checkpoint-format change. Omitting trusted `witness_policy` preserves the previous result.

A conforming implementation MUST evaluate the claim in this order:

1. **Entry validity and match.** `entry` MUST re-encode under the closed schema (§8) and MUST deep-equal the `expected_entry` the caller independently computed from the artifact actually being corroborated (never trust the evidence's own hash claims).
2. **Checkpoint verification.** Try every pinned `LogKey` sharing `expected_origin` (log keys may rotate) until one verifies the checkpoint per §9.2's hybrid AND rule; a checkpoint that verifies under none of them yields no standing.
3. **Inclusion.** The evidence's declared `tree_size` MUST equal the verified checkpoint's own `tree_size`, and the entry's leaf hash MUST verify (RFC 6962 §2.1.1) against the checkpoint's root at the declared `leaf_index`.
4. **Optional prior-checkpoint consistency.** If `prior_checkpoint` is present, it MUST itself verify under a pinned key, and its tree MUST be RFC 6962-consistent (§2.1.2) with the current checkpoint's tree. A validly-signed prior whose consistency check FAILS is proof the log signed two incompatible histories for the same origin — `transparency: "equivocation_detected"` (§10.3), a hard verdict that short-circuits every later step. A prior that does not itself verify, or that verifies with no consistency proof supplied, is fail-safe (not equivocation) and degrades to `not_checked`.
5. **Base standing.** `(transparency: "logged", corroboration: "logged")`.
6. **Optional anchor upgrade.** If `anchors` evidence is present, verify it (§11) against the same checkpoint; a PQ-surviving proof upgrades `transparency` to `anchored_before:<T>`.
7. **CRQC horizon gate.** If the verifier's policy declares a `crqc_horizon` and the anchor verdict (or its absence) does not pass it (§11.3), the WHOLE result caps back down to `(transparency: "not_checked", corroboration: "none")` — a checkpoint signature alone does not survive a declared post-quantum cutoff; only a PQ-surviving anchor dated strictly before the horizon does.

### 10.3 Equivocation

`transparency: "equivocation_detected"` is a HARD verdict (step 4 above): two validly hybrid-signed checkpoints for the same pinned origin that are not RFC 6962-consistent is conclusive proof the log signed two incompatible histories. This is the one Stage 2 verdict that is not "fail-safe degrade to not_checked" — it is a positive, actionable signal that MUST be surfaced, never silently absorbed into `not_checked`.

Detecting equivocation this way requires the verifier to already be in possession of BOTH checkpoints (typically because it, or a source it trusts, saw the log branch at two different points). Stage 2 provides no independent mechanism for DISCOVERING that a log has equivocated when the verifier has only ever seen one branch — that is exactly what an independent witness quorum (`corroboration: "witnessed"`, Stage 2b) is for (§15), and rev 7 supplies that quorum's format and makes a witnessed result reachable as observation, never as discovery: anchors bound *time*, not *branching*, so a keyed log with no witnesses can in principle maintain parallel self-consistent branches forever without ever producing the two-checkpoint evidence this section relies on.

### 10.4 Freshness and the rotation-chain rule

A `key-manifest` claim that reaches `logged` or better additionally sets `manifest_freshness: verified_as_of:<tree_size>` — this proves the manifest existed, unmodified, as of that point in the log's history, and MUST NOT by itself be read as a claim about the key's CURRENT status: a later manifest version may have since marked the same key compromised.

If the claimed manifest's own `manifest_version` is greater than 1, `corroboration` is only honored (left at `logged`) when the verifier's OWN trust store independently holds a validated, gapless rotation chain from version 1 through that manifest (`_rotation_chain_verified` — deliberately STRICTER than the `trust: "unverified_rotation"` continuity check of v0.1 §7.3/v0.2 §4, which tolerates an absent chain as "nothing to validate"). Absent that chain, `corroboration` is forced back down to `none` with the warning `corroboration_requires_rotation_chain` (conformance vector 28h) — the log merely saying "this manifest existed" is not proof of a legitimate rotation history, only of publication; a verifier that has not independently validated every intermediate version cannot corroborate that the presented manifest is the legitimate head of its issuer's key history.

The transparency/corroboration verdict for a receipt is resolved BEFORE that receipt's own pass/fail verdict is known, and independently of it (`verify.py`'s `_evaluate_transparency_claim` runs unconditionally, early). This is deliberate: it is what lets conformance vector 28i demonstrate that a receipt rejected outright for a compromised signing key (`signature: "invalid"`, `ok: false`) still honestly reports `transparency: "logged"`/`corroboration: "logged"` for its own genuinely-logged evidence — corroboration can never rescue an otherwise-invalid receipt, because it was never given the chance to.

## 11. Anchoring: `AnchorPolicy`, OTS, RFC 3161, and the CRQC horizon

### 11.1 OpenTimestamps is the required post-quantum leg

An anchor proves a checkpoint existed no later than a fixed point in time, external to the log operator's own signing key. Two anchor kinds are defined:

- **`ots` (OpenTimestamps, REQUIRED for any post-horizon standing).** A hash-only Bitcoin block-header commitment: starting from a profile-selected commitment (below), an op-chain of `sha256`/`append`/`prepend` operations is replayed and MUST land on the `header_merkle_root` of a Bitcoin block header **pinned, by header hash, in the verifier's own `AnchorPolicy.pinned_headers`** — never fetched live, never trusted from the untrusted evidence's own claimed header time. This is hash-based, not signature-based, and therefore PQ-surviving: no future cryptanalytic or quantum advance against a classical signature scheme un-anchors it.
- **`rfc3161` (OPTIONAL, classical convenience only).** An RFC 3161 timestamp token (a CMS/X.509 RSA/ECDSA signature) is accepted as OPAQUE classical corroboration — parsed only far enough to note its presence, never validated as a certificate chain — and carries the fixed warning `rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight`. An `rfc3161` proof alone sets `anchored: true` but NEVER sets `pq_surviving` and NEVER sets `anchored_before`: its own signature is exactly the kind of classical primitive a CRQC breaks, so it carries zero post-horizon evidentiary weight (conformance vector 28k).

`AnchorVerdict.anchored_before` is the MINIMUM pinned header time across every verified `ots` proof in the bundle (never a single timestamping authority's self-asserted `genTime`). `anchored_before:<T>` states that the checkpoint existed, in the form the profile below commits to, at or before time `T`: it is an upper bound on the earliest provable existence time, not a lower bound. It appears only when at least one `ots` proof verifies. `AnchorPolicy` evaluates every verified, PQ-surviving `ots` proof with these min-over-proofs semantics; its two fields (`pinned_headers` and optional `crqc_horizon`) express no quorum requirement.

#### 11.1.1 Anchor profile v2: commitment over the full signed checkpoint (G4, 2026-07-22 amendment)

Evidence's `anchors` member carries an OPTIONAL `anchor_profile` string field selecting what bytes the `ots` op-chain's accumulator starts from:

- **`"signed-note-v2"`** — the accumulator starts from `SHA-256(checkpoint.signed_note_bytes)`, where `signed_note_bytes` is the checkpoint's FULL serialized text: the three header lines, the blank line, AND every C2SP signature line (§9.1), byte-for-byte the text a verified `verify_checkpoint` call actually read — never re-serialized. **Newly-produced anchors MUST use this profile.**
- **`"note-v1"`, or the field absent (equivalently `null`)** — the LEGACY profile: the accumulator starts from `SHA-256(checkpoint.note_bytes)` alone, the unsigned header text (§9.1's carve-out) with none of the signature lines. A conforming implementation MUST reject any other `anchor_profile` value (a shape violation, degrading like any other malformed evidence field, §10.2) but MUST NOT reject `"note-v1"` or an absent field — this is the pre-G4 shape every anchor produced before this amendment already carries, and it stays first-class, forever (eternal verifiability, attest-versioning.md §3).

**Single-profile rule.** An anchors evidence bundle carries exactly one `anchor_profile`, and every proof in the bundle MUST commit under that profile. Implementations MUST NOT append a proof of a different profile to an existing bundle; re-anchoring under `signed-note-v2` requires a fresh bundle (or re-anchoring every proof). `attest log anchor` (the reference CLI's attachment command) enforces this by refusing to append when the target evidence already carries proofs under a different profile, rather than silently relabeling those retained proofs.

**Why this closes a real gap (TM-33).** `note_bytes` is unsigned-header-only text (§9.1) that exists identically before and after a checkpoint is ever actually signed: nothing about a v1 (`note_bytes`-only) OTS anchor proves anyone had signed the note yet, only that SOME note with that header existed by the pinned time. An attacker holding (or having briefly compromised) the log's checkpoint-signing keys can therefore pre-anchor a chosen, still-unsigned note and sign it only later, past the anchor time — TM-33's documented residual risk. `signed_note_bytes` contains the actual signature-line bytes, so a v2 anchor's commitment cannot exist before the note was genuinely signed: the signature has to already be there to be hashed.

**Verification consequence, not a separate check.** A verifier does not need a dedicated cross-check to reject a v1-shaped proof presented against a declared v2 profile: replaying the SAME op-chain from the WRONG seed (`note_bytes` instead of `signed_note_bytes`, or vice versa) lands on a different final hash than the one actually pinned for that seed, so the op-chain simply fails to match `header_merkle_root` — the existing `ots op-chain result does not match header_merkle_root` failure mode, reused, not a new one. This mismatch is profile-aware: under a declared `signed-note-v2` profile, the warning also names the seed the profile requires (`SHA256(checkpoint.signed_note_bytes)`) and, when the SAME op-chain genuinely replays to the pinned root from the legacy `note_bytes` seed instead, states plainly that the evidence looks like a `note-v1` commitment presented as `signed-note-v2` (conformance vector `32-anchor-v2/b-v2-commit-mismatch`).

**Attachment-time seed validation.** `attest log anchor` (the reference CLI's attachment command) does not merely stamp a declarative `anchor_profile` label: before accepting an externally-obtained `--ots-proof`, it replays the proof's own op-chain against `SHA-256(checkpoint.signed_note_bytes)` and checks the result matches the proof's own `header_merkle_root`. A proof whose op-chain instead replays correctly from `SHA-256(checkpoint.note_bytes)` (the legacy pre-G4 seed) is refused with a diagnostic naming that exact cause; any other non-matching op-chain is refused with a generic, actionable error naming the required v2 seed. This catches the common mistake — attaching a proof produced by pre-G4 tooling — before it ever reaches a verifier's fail-closed op-chain replay.

`AnchorVerdict.note_only` (Python) / `AnchorVerdict.noteOnly` (TypeScript) records which profile a verified anchor used. It is never itself a member of `AnchorVerdict.warnings` — `attest.transparency.evaluate_transparency` (§10.2 step 6) is the one boundary that turns a `note_only`/`noteOnly` anchor that established standing into the caller-facing warning `anchor_note_only`, exactly the "still fully verifiable, just classified" pattern §12's signed-receipt-core commitment already establishes for a structurally analogous gap (unsigned-content-only commitments letting a claim predate its own signature).

### 11.2 `AnchorPolicy`

```
AnchorPolicy {
  pinned_headers: { <64-hex header_hash>: PinnedHeader { header_hash, merkle_root, time } },
  crqc_horizon: <unix-seconds int> | null
}
```

`pinned_headers` is the verifier's own trust store of Bitcoin block headers — shipped with the verifier (or its trust-store update mechanism), never taken from a bundle; a proof naming a `header_hash` absent from this map contributes nothing. `crqc_horizon` is `null` by default ("no cutoff yet configured" — every PQ-anchored checkpoint passes unconditionally); once a verifier operator sets it, §10.2 step 7 gates every standing that would otherwise rest on it.

### 11.3 `passes_horizon`

A verdict passes the horizon iff `policy.crqc_horizon is None`, OR the verdict is PQ-surviving (`pq_surviving == true`) AND its `anchored_before` is strictly less than `crqc_horizon`. An `rfc3161`-only verdict (`pq_surviving == false`) never passes a configured horizon, regardless of how early its claimed time is — consistent with §11.1: a classical timestamp is exactly the kind of evidence a CRQC horizon exists to stop trusting.

### 11.4 WitnessPolicy and reusable quorum primitives (P1.1b amendment)

`WitnessPolicy` is a closed JSON object. Any comparison, digest, packaged-byte assertion, or revision check uses attest JCS. Its top-level shape is exactly `{"schema": "attest-witness-policy-v1", "epochs": []}`: no other top-level member is permitted. `epochs` is an ordered array of immutable epochs. Each epoch has exactly `epoch_id`, `not_before`, `not_after`, `log_origins`, `threshold`, and `witnesses`; `epoch_id` is a unique, non-empty ASCII token matching `^[a-z0-9][a-z0-9._-]{0,127}$`. `not_before` and non-null `not_after` are exact UTC ISO-8601 second timestamps, and validity is inclusive at both declared boundaries.

Each epoch has the closed shape `{"epoch_id":"bootstrap-1","not_before":"2026-01-01T00:00:00Z","not_after":null,"log_origins":[],"threshold":{"n":1,"m":1},"witnesses":[]}`. `log_origins` is sorted and duplicate-free. `threshold.n` counts distinct activation-role `control_group` values, not keys; `threshold.m` is the required number of valid distinct control-group votes.

Each witness pin has exactly `operator_id`, `control_group`, `name`, `ed25519_pub_b64u`, `mldsa_65_pub_b64u`, `roles`, `not_before`, `not_after`, and `affiliated_domains`, plus optional `compromised_after`. `roles`, `log_origins`, and `affiliated_domains` are sorted and duplicate-free. `operator_id`, `control_group`, and every `affiliated_domains` member are lowercase DNS names; `name` follows the C2SP signed-note printable-ASCII grammar; and `affiliated_domains` contains its own `operator_id`. `mldsa_65_pub_b64u` may be null only when the pin lacks `sunset-activation`.

Trusted policy uses the same verifier-owned configuration rail as existing pinned log keys: Python core keyword `witness_policy=`, Python CLI file `--witness-policy`, and TypeScript verifier option `witnessPolicy`. The bootstrap policy is release-controlled data in both published verifier packages. Installing a release authorizes that packaged policy revision; evidence cannot authorize an update. Packaged copies are generated or checked from one canonical JCS document and MUST be byte-identical.

For an offline deterministic conflict predicate parameterized as `conflict_domain`, a pin is conflicted with domain `X` under either limb: Direct conflict: `X` appears in the pin's `affiliated_domains`. Transitive conflict: the pin's `control_group` equals the `control_group` of any pin in the epoch whose `affiliated_domains` contains `X`. Domain inequality MUST NOT establish independence. No positive independence certificate or inference rule exists in policy v1.

`compromised_after` has a tri-state policy lifecycle. Absent `compromised_after` means no compromise is declared by the installed policy. A string is an inclusive trusted cutoff: `T <= compromised_after` retains its standing and `T > compromised_after` excludes it. An explicit `"compromised_after": null` means compromise onset is unknown and the pin contributes no standing at any `T`. The release publisher that ships the policy is authoritative for this field. An update may add or tighten compromise information but cannot rewrite or delete prior epoch contents. A corroboration dependent on an excluded pin remains at its prior non-witness standing; a standalone hybrid quorum dependent on one is invalid.

The reusable ordinary quorum is the one-`0x04` rule of §10.1. The reusable activation-grade quorum requires matching Ed25519 and ML-DSA-65 legs for each counted pin, over the same payload and timestamp: both legs MUST verify (AND), and it counts one vote per `control_group`. An epoch permits at most one activation candidate pair per active `control_group`; ambiguous duplicate candidates fail before crypto. It is a standalone primitive: this section defines no grant consumer. The constants are `MAX_WITNESS_SKEW_SECONDS = 600`, `MAX_WITNESS_ANCHOR_DELAY_SECONDS = 86400`, and `MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE = 9`. The committee ceiling MUST be enforced before any Ed25519 or ML-DSA-65 signature verification. A full `signed-note-v2` anchor over the complete signed note, including cosignature lines, is required; legacy note-only anchoring is not sufficient for this primitive. With counting times `t_i`, conservative quorum time `T = min(t_i)`, and full-note anchor time `A`, validity requires `max(t_i) - min(t_i) <= MAX_WITNESS_SKEW_SECONDS` and `max(t_i) <= A <= T + MAX_WITNESS_ANCHOR_DELAY_SECONDS`.

The reference witness receives a configured allowlist of log origins and their pinned hybrid log keys. No origin or log key is hardcoded in source. Its parsing, state, monitoring, and signing support any configured allowlist size, including a single origin. Unknown origins are rejected before checkpoint or consistency work can advance state. Landing order is spec, policy, both-core verification, vectors, reference witness, ceremony, review/PR/tag. The reference implementation is top-level `witness/`, follows the `bridge/` workspace precedent, is unpublished, receives no independent tag, and is excluded from both public package artifacts. The formal model remains explicitly out of scope and unchanged. No warning literal is introduced by this section other than `witness_independence_not_established`.

## 12. The signed-receipt-core commitment

A `receipt` log entry (§8) commits to the **signed-receipt-core**, not to `payload` alone:

```
receipt_core_hash = SHA-256("attest-receipt-core-v1" || 0x00 || JCS(payload) || 0x00 || JCS(signatures))
```

rendered as 64 lowercase hex characters (`tlog.receipt_core_hash`). `signatures` is the envelope's `signatures` array, canonicalized as a JSON array exactly as the rest of this document canonicalizes any array-valued member; `delivery` is deliberately excluded from this hash entirely — deleting a receipt's `delivery` member (v0.1 §4.2, already unsigned) never invalidates its log entry. This is the ONLY receipt-entry hash domain; a conforming implementation MUST NOT define or accept any other.

**Committing to the signature bytes, not just the payload, is deliberate and load-bearing, not redundant.** Post-CRQC, an attacker who has derived an issuer's Ed25519 private key from its public key (the exact scenario Stage 1's hybrid profile defends against for FUTURE receipts) can sign an arbitrary backdated payload at will. A hash over `payload` alone would let a precommitted log entry describe a payload that was never actually signed until long after it was logged: the attacker signs it only after the fact, past the horizon, and the old entry still "matches" the forged receipt byte-for-byte. Domain-separating and hashing the signature bytes too means a log entry can only ever describe a signature that ALREADY EXISTED at logging time — this is what makes `anchored_before:<T>` a genuine existence-of-signature proof rather than a mere existence-of-payload proof, and it is what conformance vector 28l pins: an unsigned payload-only precommit (a hash computed over `payload` alone, without domain separation or the signature bytes) is NOT accepted as receipt existence proof — it fails entry matching exactly like any other mismatched claim (`transparency_entry_mismatch`).

**The same shape of gap exists one level up, for the checkpoint's own signature, and §11.1.1's anchor profile v2 closes it the identical way.** This section's guarantee is about the RECEIPT entry committing to its signature bytes; it says nothing about whether the CHECKPOINT that included that entry was itself signed yet at anchor time. A `"note-v1"` OTS anchor commits only to the checkpoint's unsigned header (`note_bytes`), so it proves a tree with that root existed by time `T`, not that the log had actually signed a checkpoint over it — precisely TM-33's residual risk (a chosen unsigned note pre-anchored, signed later). Anchor profile `"signed-note-v2"` (§11.1.1) domain-separates the OUTER (checkpoint) signature exactly as this section domain-separates the entry's own: it commits over `signed_note_bytes`, which cannot exist before the checkpoint was genuinely signed.

This is also the honest boundary of what Stage 2 protects for pre-existing receipt stock (§15): the guarantee holds only for a receipt whose signed-receipt-core was ACTUALLY logged and PQ-anchored before the horizon — never for "the stock" unqualified.

## 13. Sibling hardening: hybrid AND-rule extended to revocation and artifact manifests

**Normative note on scope:** this section documents a hardening fix folded into the Stage 2 wave, not new Stage 2 machinery — it closes a gap in code that shipped with v0.2 Stage 1.

v0.2 Stage 1, as originally shipped, left revocation records' own authentication Ed25519-only even for a hybrid-keyed issuer. Post-CRQC, an attacker who has broken only Ed25519 could forge a `policy`/`refund_window` revocation record against an otherwise-hybrid-protected manifest key, driving `revocation: "revoked"` (`ok: false`) purely through the classical leg — defeating the "breaking only Ed25519 is insufficient" guarantee (v0.2 §2.1) specifically for revocation, even though it held everywhere else.

**Fix, normative for every Stage-2-and-later implementation.** The Stage 2 sibling patch extends artifact manifests and revocation records to the hybrid AND-rule: if the signing key's own manifest entry carries `pub_ml_dsa_65` (i.e. the signer is hybrid), the side-document's signature block MUST also carry a valid `sig_ml_dsa_65` leg over the same signed bytes, or the document is treated as invalid and ignored — a downgraded, Ed25519-only signature against a hybrid key's authority is never honored, regardless of how early or late it is presented. An Ed25519-only signer's side-document carrying a stray `sig_ml_dsa_65` leg likewise fails closed (a document cannot claim hybrid protection for a key that never had a PQ public key). This is symmetric, fail-closed AND-verification in both directions, exactly mirroring §2.3's manifest-signature rule.

Conformance vector 28m pins the mechanism this closes: an Ed25519-only-signed revocation record against a HYBRID issuer key is unconditionally rejected and ignored (`revocation: "unknown"`, `ok: true`) — the record simply never counts, regardless of any transparency/anchor evidence presented alongside it. **This "transparency evidence cannot rescue OR condemn a revocation verdict" property is otherwise general (§10) but carries the two scoped exceptions §10 now names: (G5, TM-47, rev 5) `revocation-record` evidence for a `refund_window` record's OWN log entry can condemn (never rescue) that record's effectiveness under §15 item 5's deadline rule; and (Stage 3, rev 6) an authenticated `transferred`-class record is honored ONLY when its transfer record's `holder_authorization` verifies AND its log inclusion proof checks out (§17.2/§17.3) — both are entirely separate evidence channels from the receipt/key-manifest evidence this vector's AND-rule scenario concerns, and orthogonal to it.**

### 13.1 Mixed-keyset prohibition and migration ceremony (normative, 2026-07-22 amendment)

**An issuer that declares the hybrid profile MUST NOT hold an Ed25519-only key in state `active`** (§2.3). Leaving one active after adopting hybrid signing silently downgrades the issuer's claimed hybrid protection back to classical-only: an attacker who has broken only Ed25519 can still forge under the still-active Ed25519-only sibling, with no visible signal that hybrid protection never actually applied to receipts a buyer might reasonably assume it covered. This is `attack_mixed_keyset_hijack` in the formal threat-model exhibits — the motivating attack for this rule.

**Migration is a single manifest step.** The same `manifest_version` increment that introduces the hybrid key MUST retire (or otherwise move out of `active`) every Ed25519-only key the issuer holds — there is no intermediate, spec-sanctioned state where a hybrid key and an active Ed25519-only key coexist as a deliberate migration phase.

**Verifier behavior.** A conforming verifier that resolves an issuer manifest exhibiting the mixed-keyset condition (at least one hybrid key-entry AND at least one Ed25519-only key-entry in state `active`) for a v0.2 receipt it is verifying MUST emit the warning `mixed_keyset_active_ed_only_sibling`. This warning is the entire verifier-side contract: no result-vocabulary field (§10.1, v0.1 §11.1) caps a "hybrid strength" classification, because none exists — the layered result reports `signature`/`schema`/`trust`/`revocation`/`binding` exactly as it would for any other v0.2 receipt, with this warning as the caller's signal to investigate the issuer's key hygiene. A manifest whose Ed25519-only keys are all `retired` or `compromised` — the completed migration ceremony above — carries no such warning.

## 14. Bundle transparency evidence: the `proofs/` member

An offline `.attest` bundle (v0.1 §14.1) MAY carry transparency/corroboration evidence for its receipts, one JSON evidence bundle (§10.2's shape) per receipt, as a `proofs/` member.

**A conforming bundle contains `proofs/` members only in the shape `proofs/<ULID>.json`**, where `<ULID>` is exactly the 26-character Crockford base32 ULID the receipt schema already pins `receipt_id` to (first character in `0`–`7`, matching the schema's own timestamp-prefix constraint). A conforming importer MUST reject any other shape under `proofs/` — a nested path, a nested member, a nonexistent-`.json` suffix, or a filename that is not itself a syntactically valid ULID — BEFORE deriving any filesystem path from it: the member name is attacker-supplied bundle content, and letting an unvalidated shape reach a filesystem join is exactly the traversal hazard the ULID-only grammar exists to close.

`proofs/<ULID>.json`'s contents are exactly the untrusted §10.2 evidence shape and MUST be treated with the same untrusted-evidence discipline as evidence obtained any other way — importing it into a bundle confers no additional trust. A bundle's `README.html` (v0.1 §14.1) MUST document, in plain language, that a `proofs/` entry is corroboration, not authenticity: the receipt's own signature is what makes it authentic; a proof only shows the receipt (or manifest) was independently observable in the log at a point in time and, absent independent witnesses, does not by itself rule out the log operator equivocating.

## 15. Limitations (normative)

This section states Stage 2's bound, honestly and normatively — not as a caveat to be read past, but as part of the conformance surface. A conforming implementation and its documentation MUST NOT claim more than this section allows. Each limitation below is carried as an entry or forward-looking requirement in the maintained threat model, [`attest-threat-model.md`](attest-threat-model.md).

1. **Witness observation is not independent anti-equivocation.** Stage 2 can DETECT equivocation when a verifier already holds two inconsistent, validly-signed checkpoints for the same origin (§10.3), while P1.1b makes `corroboration: "witnessed"` reachable as timestamped observation (§10.1). Neither a witnessed result nor domain inequality proves organizational independence or prevents split views: a keyed log and its witnesses can still maintain parallel self-consistent branches, and a partitioned or colluding witness may not have observed a larger head. `witness_independence_not_established` is therefore required on every P1.1b witnessed result.
2. **Un-logged stock is unprotected.** Every guarantee in §10–§13 applies only to an artifact that was ACTUALLY logged (and, for post-horizon standing, ALSO PQ-anchored, §10.2 step 7). A receipt or key manifest that was never submitted to a log gets no existence-before-T guarantee from this document at all, no matter how old it is or how strong its original signature was. "Protect the existing stock" is true ONLY for the subset of stock that has been logged and anchored — a **bulk-logging path** for pre-existing receipts is therefore RECOMMENDED for any issuer that wants this guarantee to cover its historical stock, and a conforming implementation MUST NOT claim to protect "the stock" unqualified; the claim MUST always be scoped to "logged-and-anchored receipts."
3. **`corroboration` is not `authenticity`.** `corroboration: "logged"` (or `"witnessed"`, reachable since rev 7) says an artifact was independently observable at a point in the log's history. It says nothing about who is entitled to have written that artifact — that is exactly what the receipt's own signature (`signature`) and the issuer's domain-control root (`trust`) already establish, unchanged by anything in this document. A consumer MUST NOT treat `corroboration` as a substitute for either.
4. **The log never upgrades `trust`.** Stated already in §7.1 and §10, restated here because it is the single most important non-goal: no value of `transparency` or `corroboration`, however strong, changes `trust` from `unauthenticated_tofu` to `verified`. `verified` requires the v0.1 §7.4 domain-control root; nothing else suffices, ever.
5. **Revocation records are loggable (G5, TM-47, rev 5); a deadline-sensitive `refund_window` effectiveness rule follows from that; signer intent and compulsion remain out of scope.** `revocation-record` is a THIRD loggable entry type (§8): `record_sha256 = SHA-256(JCS(record))` over the entire signed record, committed and RFC 6962 leaf-hashed exactly like a `key-manifest`/`receipt` entry, and eligible for the same generic log machinery every entry gets — inclusion proofs, consistency-proof-driven equivocation detection (§10.3), and OTS anchoring (§11) all apply to a `revocation-record` entry with no special casing. **Deadline-effectiveness rule (normative).** A `refund_window` revocation record's own signed `revoked_at` falling within `issued_at + revocation_window_days` (v0.1 §12.2) makes it *window-effective*; a conforming verifier that is Stage-2 capable (§10.2: it evaluates `revocation-record` transparency evidence for that specific record) MUST additionally require that entry's log standing to reach `anchored_before:<T>` with `T` no later than that SAME deadline before honoring the record — MUST apply the rule, not MAY. A window-effective record that fails this bound (no evidence at all, evidence that never reaches an anchored standing, or an anchor dated after the deadline) resolves to `revocation: "invalid_revocation_ignored"` (the existing v0.1 result value — no vocabulary growth) plus the warning `revocation_unlogged_deadline`. **Eternal verifiability carve-out:** the rule engages ONLY where a verifier actually asks for it — a verifier that is not Stage-2 capable at all (no `log_keys`/`anchor_policy` configured for revocation evidence) performs exactly v0.1's window-only check, unchanged. This is NOT "every pre-G5 caller's behavior byte-for-byte identical": a caller supplying neither `log_keys` nor `anchor_policy` IS byte-for-byte unchanged, but a Stage-2-capable caller (both supplied) now requires timeliness evidence for a `refund_window` record regardless of whether it separately opted into `revocation_evidence` — gating on that presence instead would let an adversary evade the deadline rule by omission. This outcome change on unchanged inputs is a sanctioned security-strengthening amendment, not a breaking one (attest-versioning.md §2). `policy`/`none` revocability classes are UNAFFECTED by this rule in every case — logging remains optional corroboration for them, exactly as §13 already establishes, never a gate on their effectiveness. **What this does NOT close:** TM-47's residual scope. A log entry proves a record existed by a given time; it does not establish why the record was signed. Signer intent and compulsion remain explicit out-of-scope boundaries (§7 of the threat model) — no signature scheme, and no transparency log, distinguishes a compelled revocation from a voluntary one, and this amendment makes no claim otherwise. Artifact manifests are UNCHANGED by this amendment: they remain non-loggable, and §13's hybrid-signature AND-rule patch for their own authentication is the full extent of Stage 2's treatment of them.

## 16. Conformance: transparency and corroboration (groups 28, 30–33, 35, 36, 39, 40)

The conformance leaf group [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/) adds 14 leaves (28a–28n) to the 54 pre-Stage-2 leaves (the 45 v0.1 leaves, v0.1 §15 — 43 plus [`29-limits`](vectors/29-limits/)'s 2 leaves — the 8 `26-hybrid` leaves, and the single `27-valid-to-absent` leaf), for 68. Together with [`30-mixed-keyset`](vectors/30-mixed-keyset/)'s 2 leaves (§13.1), [`31-manifest-currency`](vectors/31-manifest-currency/)'s 5 leaves (v0.1 §7.2/§7.3 amendment, rev 4 — not gated by `attest_version`, so it binds v0.2 implementations too; corrected from an earlier miscount of 3, rev 5), and [`32-anchor-v2`](vectors/32-anchor-v2/)'s 3 leaves (§11.1.1, this document's own rev 4), the corpus stood at **78 total** before this document's rev 5. [`33-logged-revocation`](vectors/33-logged-revocation/)'s 4 leaves (§8/§15 item 5, this document's own rev 5, G5/TM-47 — see §16.4) brought the full corpus to **82 total**. [`35-transfer`](vectors/35-transfer/)'s 11 leaves (§17, this document's own rev 6 — see §16.5) and [`36-transfer-chain`](vectors/36-transfer-chain/)'s 4 leaves (§17.5, rev 6 — see §16.6) bring the corpus to **97 total**. [`39-witness-corroboration`](vectors/39-witness-corroboration/)'s 13 leaves (§10.1/§11.4, this document's own rev 7 — see §16.7) and [`40-witness-quorum`](vectors/40-witness-quorum/)'s 20 leaves (§11.4, rev 7 — see §16.8) bring the full corpus this document and its implementations MUST meet to **130 total**. Every group-28 and group-32 leaf's `expected.json` additionally carries `transparency`, `corroboration`, and `manifest_freshness` — the only groups where these three fields appear (group 33 uses a DIFFERENT evidence channel, `revocation_evidence`, and carries none of the three; group 35 likewise uses its own `transfer_view` channel and carries none of the three either); every other leaf's absence of them means the verifier saw no transparency evidence at all (zero-behavior-change default, §10). Group 36's leaves are a separate result shape entirely — `ChainAuditResult` (§17.5), never a `VerificationResult` — routed to `audit_chain`/`auditChain`/`runChainAudit` instead of `verify()`. Group 40's leaves are a third result shape — `{valid, witness_time, counting_control_groups}` (§11.4), routed to the activation-quorum entry point — and, having no receipt in them at all, they ship neither an envelope nor a trust store. Group 39's leaves DO carry `transparency` and `corroboration` in `expected.json`, on the same grounds as group 28's: they are the only leaves where `corroboration: "witnessed"` is reachable. Each leaf runs against every conformance runner (Python reference, TypeScript verifier, and the site adapter) from the same shared golden files, per the discipline of v0.1 §15 and [`docs/spec/vectors/README.md`](vectors/README.md).

### 16.1 Structural ceilings normed (2026-07-22 amendment)

The Stage 2 evidence-parsing modules already enforced fixed structural bounds on untrusted transparency/anchor evidence before this amendment; this section formalizes those pre-existing, unchanged bounds as conformance-surface requirements (attest-versioning.md §5) rather than introducing new limits:

| Ceiling | Value | Module |
| --- | --- | --- |
| Inclusion/consistency proof length | 64 hashes | `transparency.py` (`_MAX_PROOF_LEN`) |
| Checkpoint note text length | 500,000 chars | `tlog.py` (`_MAX_NOTE_TEXT_LEN`) |
| Checkpoint signature-line count | 64 | `tlog.py` (`_MAX_NOTE_SIGNATURES`) |

None of these values changed and no vector distinguishes pre/post behavior for this specific norming — the reference implementation and TypeScript verifier already enforced them byte-for-byte identically before this revision.

| Leaf | Checks |
| --- | --- |
| `28a` | Genuinely logged receipt (hybrid checkpoint, valid inclusion proof), TOFU/bundle provenance → `transparency: "logged"`, `corroboration: "logged"`, `trust: "unauthenticated_tofu"` UNCHANGED — logging never upgrades trust (§7.1, §15 item 4). |
| `28b` | Valid hybrid checkpoint, but for a root that does not actually contain the entry → inclusion proof fails, `transparency: "not_checked"`. |
| `28c` | Checkpoint with only the Ed25519 leg, no ML-DSA-65 line → NO standing at all, even though the Ed25519 signature is genuinely valid (§9.2). |
| `28d` | Genuinely hybrid-signed checkpoint by the pinned key material, but a different `origin` than pinned → no candidate `LogKey` verifies (§10.2 step 2). |
| `28e` | A verifying prior (smaller) checkpoint plus a genuine RFC 6962 consistency proof against the current checkpoint → still just `"logged"` — consistency rules out equivocation only between those two supplied checkpoints; it does not itself upgrade standing. |
| `28f` | A validly hybrid-signed prior checkpoint claiming the SAME tree size as the current checkpoint but a DIFFERENT root → `transparency: "equivocation_detected"` (§10.3, hard verdict). |
| `28g` | The evidence's `entry` disagrees with the entry `verify()` independently computes from the actual receipt → `transparency_entry_mismatch`, regardless of an otherwise-valid checkpoint/proof. |
| `28h` | A self-consistent `manifest_version: 2` key-manifest claim, but the verifier's trust store holds no rotation chain for the issuer → `corroboration_requires_rotation_chain`, `corroboration` downgraded to `"none"`, while `transparency: "logged"` and `manifest_freshness: "verified_as_of:1"` are unaffected (§10.4). |
| `28i` | A receipt rejected outright for a compromised signing key (`signature: "invalid"`, `ok: false`) still honestly reports `transparency: "logged"`/`corroboration: "logged"` for its own genuinely-logged evidence — corroboration never rescues an otherwise-invalid receipt (§10.4). |
| `28j` | A PQ-surviving `ots` proof replaying to a pinned Bitcoin block header → `transparency` upgrades to `anchored_before:2023-11-14T22:13:20Z` (header time `1700000000`). No `anchor_profile` declared → legacy `"note-v1"` commitment (§11.1.1), so `warnings` now also carries `anchor_note_only` (2026-07-22 amendment, rev 4) — still fully verifiable, just classified. |
| `28k` | An `rfc3161`-only anchor proof → opaque classical corroboration only, `transparency` stays `"logged"`, never `anchored_before:<T>`; the verbatim RFC 3161 warning literal is asserted (§11.1). **Documented adaptation**: this vector's committed policy has `crqc_horizon=None`, so it does not consult `anchor.passes_horizon` here. With a configured horizon, the evaluator does call `anchor.passes_horizon`; an `rfc3161`-only verdict never becomes `pq_surviving` and is capped. |
| `28l` | The evidence entry's `core_sha256` is hashed over `payload` alone — no domain separation, no signature commitment — exactly the "pre-sign, log now, sign later" attack §12's domain separation defeats; same observable outcome as 28g (`transparency_entry_mismatch`), different attacker narrative. |
| `28m` | **Documented adaptation** from "post-horizon Ed-only revocation": `verify()`'s revocation classification has no `crqc_horizon`-shaped input at all — the horizon cap and revocation classification are separate subsystems, so a literal "post-horizon revocation" cannot be expressed through any `verify()` call. Adapted to the mechanism that would have to exist for that framing to hold: an Ed25519-only-signed revocation record against a HYBRID issuer key is unconditionally rejected/ignored (§13's AND rule, fail-closed) — `revocation: "unknown"`, `ok: true`. |
| `28n` | An evidence `entry` whose `type` the log's closed schema (§8) doesn't recognize → the claim is unresolvable before any checkpoint/proof is even consulted (`transparency_claim_unresolvable`); the receipt itself verifies untouched. |

### 16.2 Vector determinism

**Non-normative note:** group-28 vectors are generated deterministically by [`tools/gen_vectors.py`](../../tools/gen_vectors.py)'s `gen_28_transparency`, the same generator and determinism gate as every other group. Checkpoint/log fixtures use fixed keys and seeds; the `ots`/`rfc3161` anchor fixtures are frozen and committed (a committed OTS proof plus a pinned test Bitcoin header; synthetic opaque bytes for the `rfc3161` token) — no network access occurs in any conformance test, ever.

### 16.3 Anchor profile v2 (G4, 2026-07-22 amendment)

The conformance leaf group [`docs/spec/vectors/32-anchor-v2/`](vectors/32-anchor-v2/) (generated by `gen_32_anchor_v2`, same determinism discipline as §16.2) pins §11.1.1's profile dispatch with one receipt/checkpoint fixture and three anchor-evidence variants:

| Leaf | Checks |
| --- | --- |
| `32a-v2-valid` | `anchor_profile: "signed-note-v2"`, `ots` op-chain genuinely committing over `signed_note_bytes` → `transparency` upgrades to `anchored_before:<T>`, no `anchor_note_only` warning. |
| `32b-v2-commit-mismatch` | Same declared `"signed-note-v2"` profile, but the op-chain was built from `SHA-256(note_bytes)` alone (the legacy v1 seed) → the replayed chain lands on a different root than pinned, so the proof FAILS with the profile-aware, legacy-shape diagnostic (`ots op-chain result does not match header_merkle_root; anchor_profile signed-note-v2 requires the accumulator to start from SHA256(checkpoint.signed_note_bytes) — this evidence looks like a note-v1 commitment presented as signed-note-v2`) — the direct negative demonstration that a v1-shaped commitment cannot pass as v2 proof of the signed note's existence. |
| `32c-v1-note-only-warn` | No `anchor_profile` declared (legacy), genuinely v1-shaped op-chain → verifies and upgrades standing exactly as every pre-G4 anchor always has (eternal verifiability), now carrying `anchor_note_only`. |

### 16.4 Logged revocation and deadline effectiveness (G5, TM-47, 2026-07-23 amendment)

The conformance leaf group [`docs/spec/vectors/33-logged-revocation/`](vectors/33-logged-revocation/) (generated by `gen_33_logged_revocation`, same determinism discipline as §16.2) pins §15 item 5's deadline-effectiveness rule with one `refund_window` receipt/record fixture (`revocation_window_days: 14`, deadline `issued_at + 14d`) and one independent `policy`-class fixture:

| Leaf | Checks |
| --- | --- |
| `33a-timely-logged-honored` | The record's `revocation-record` log entry is genuinely logged and OTS-anchored to a pinned header dated BEFORE the deadline → the deadline rule is satisfied, `revocation: "revoked"` exactly as v0.1 already required for a window-effective record. |
| `33b-unlogged-ignored-warn` | A Stage-2-capable verifier (`log_keys`/`anchor_policy` both configured), but NO `revocation_evidence` supplied for this record at all → the record was never proven logged, so the deadline rule cannot honor it → `revocation: "invalid_revocation_ignored"` plus `revocation_unlogged_deadline`. |
| `33c-late-anchor-ignored` | `revocation_evidence` present and genuinely verifies as logged, but the OTS anchor's pinned header time is AFTER the deadline → `anchored_before:<T>` fails the `T <= deadline` bound → same ignored-with-warning outcome as 33b, different cause. |
| `33d-policy-class-unchanged` | A `policy`-class record (not `refund_window`) under a Stage-2-capable verifier with no `revocation_evidence` → `revocation: "revoked"`, UNCHANGED — the deadline rule never engages outside `refund_window`; logging remains optional corroboration for this class (§13). |

### 16.5 Transfer records and the consent gate (§17, this document's own rev 6)

The conformance leaf group [`docs/spec/vectors/35-transfer/`](vectors/35-transfer/) (generated by `gen_35_transfer`, same determinism discipline as §16.2) pins §17.1–§17.4 and §17.7–§17.8 with one shared `attest_version: "0.2"`, `license.transferable: true` old-receipt fixture (varied per leaf as noted) and one shared, genuinely issuer-signed + holder-authorized + logged transfer record (`record_valid`/`evidence_valid`, reused across a/b/g/k). Every leaf's `expected.json` carries none of `transparency`/`corroboration`/`manifest_freshness` — a DIFFERENT evidence channel from `transparency.json` (`transfer_view`), same discipline as group 33's `revocation_evidence`.

| Leaf | Checks |
| --- | --- |
| `35a-transferred-with-backing` | A `policy`-class old receipt plus an authenticated `status: "transferred"` revocation record plus one fully valid transfer-view claim (issuer sig + holder auth + logged evidence) → the consent gate is satisfied: `revocation: "transferred"`, `ok: false`. |
| `35b-transferred-on-none-with-backing` | The identical claim, but `license.revocability: "none"` → STILL honored — §17.3's consent gate applies to every revocability class, `none` included. |
| `35c-transferred-on-none-unbacked` | The SAME `none`-class receipt/revocation as 35b, but NO `transfer-view.json` at all → the resolver is never reached, unbacked directly: `revocation: "invalid_revocation_ignored"`, `ok: true`, `transferred_revocation_unbacked`. |
| `35d-forged-holder-auth` | The transfer record's issuer signature genuinely verifies, but `holder_authorization.sig` was made by an unrelated key, not the old receipt's own `buyer.pubkey` → the consent gate itself fails: same unbacked outcome as 35c. |
| `35e-unlogged-transfer` | The SAME fully-authenticating record as 35a, but its claim carries no `evidence` at all → never proven logged: `invalid_revocation_ignored`, `ok: true`, `transfer_record_unlogged`. |
| `35f-double-assignment-earliest-wins` | TWO fully valid claims for the same `receipt_id`, distinct `new_receipt_id`/`new_holder_pubkey`, logged at indices 0 (earliest) and 1 (later) in a shared 2-entry tree, the later-logged one listed FIRST in the array → the earliest-logged one still wins (§17.4): `revocation: "transferred"`, `ok: false`, `transfer_double_assignment_conflict`. |
| `35g-not-transferable-before-violation` | The old receipt's own `license.not_transferable_before` falls AFTER the (otherwise fully valid) claim's `transferred_at` (§17.7) → not yet transferable: `invalid_revocation_ignored`, `ok: true`, `transfer_not_yet_transferable`. |
| `35h-classical-only-record-hybrid-key` | The transfer record's holder-authorization is genuine, but the ISSUER side is signed Ed25519-ONLY against a HYBRID manifest → the §13 AND-rule fails closed, same unbacked outcome as 35c/35d. |
| `35i-v01-transferable-null-pubkey-ok` | D1's (§17.8) negative control: `attest_version: "0.1"` is untouched by the schema conditional (it only gates v0.2), so `license.transferable: true` with a null `buyer.pubkey` stays schema-valid — `schema: "valid"`, `ok: true`. |
| `35j-v02-transferable-requires-pubkey` | The SAME shape under `attest_version: "0.2"` IS a schema error (§17.8's positive gate) — signed like 25-schema-parity (the signature genuinely covers the invalid payload): `schema: "invalid"`, `ok: false`, an error mentioning `pubkey`. |
| `35k-not-transferable-before-boundary` | The old receipt's `license.not_transferable_before` is EXACTLY the otherwise fully valid claim's `transferred_at` (§17.7) → honored: `revocation: "transferred"`, `ok: false`, no warnings. |

### 16.6 Chain of title (§17.5, this document's own rev 6)

The conformance leaf group [`docs/spec/vectors/36-transfer-chain/`](vectors/36-transfer-chain/) (generated by `gen_36_transfer_chain`, same determinism discipline as §16.2) pins §17.5's chain-of-title audit — a SEPARATE surface from single-receipt `verify()`, over a whole sequence of receipt payloads. Since `audit_chain` never touches an envelope's own signature/schema/hybrid-ness, these four leaves use a PLAIN (non-hybrid) issuer manifest. Each leaf's `expected.json` is `{"chain_valid": bool, "link_status": [...], "errors_contains": [...], "warnings": [...]}`, matched as: `chain_valid` exact against `result.valid`, `link_status` exact list, `errors_contains` substring, `warnings` exact list.

| Leaf | Checks |
| --- | --- |
| `36a-valid-chain` | Three receipts R0→R1→R2, two fully valid links (issuer sig + holder auth + logged, each backed by a `transferred`-class revocation on the previous receipt) → `chain_valid: true`, `link_status: ["valid", "valid"]`. |
| `36b-pubkey-mismatch-no-link` | One link whose transfer record otherwise fully authenticates, but the NEXT receipt's own `buyer.pubkey` does not equal the record's `new_holder_pubkey` (§17.1 loop closure) → `chain_valid: false`, `link_status: ["invalid"]`, an error naming the pubkey/new_holder_pubkey mismatch. |
| `36c-losing-branch-no-link` | The previous receipt has TWO fully-authenticating, logged transfer records (a phantom continuation logged FIRST, at index 0, and the record actually continued by `payloads`, logged SECOND, at index 1) → the later-logged, presented branch loses to the earlier one (§17.4): `chain_valid: false`, `link_status: ["invalid"]`, an error naming the losing branch of a double assignment. |
| `36d-floor-violation-no-link` | A two-receipt chain whose otherwise valid link's `transferred_at` predates the previous receipt's own `not_transferable_before` (§17.7) → `chain_valid: false`, `link_status: ["invalid"]`, `chain link 1: transferred before not_transferable_before`. |

### 16.7 Witness corroboration (§10.1/§11.4, this document's own rev 7)

The conformance leaf group [`docs/spec/vectors/39-witness-corroboration/`](vectors/39-witness-corroboration/) (generated by `gen_39_witness_corroboration`, same determinism discipline as §16.2) pins §10.1's one-`0x04` rule end to end through `verify()`. Every leaf shares one receipt and one checkpoint; they differ only in the cosignature lines appended to the checkpoint note and in the TRUSTED `witness-policy.json` supplied alongside `log-keys.json`. That file is an `attest-witness-policy-v1` DOCUMENT, not a parsed object: a conformant implementation exercises its own policy parser on it, and it is never nested inside the untrusted evidence bundle — the evidence names an epoch (`witness_policy_epoch`), the policy says whom that epoch pins.

Failure in this layer is SILENT (§11.4): the only literal it may add is `witness_independence_not_established`, which accompanies EVERY witnessed verdict and nothing else. Ten of these thirteen leaves are therefore distinguished from one another by nothing but `corroboration` remaining `"logged"`. That is normative, not an under-specified expectation — a verifier that explained why a cosignature failed would leak the policy's shape to whoever supplied the note.

| Leaf | Checks |
| --- | --- |
| `39a-ed25519-witnessed-bootstrap` | One valid `0x04` cosignature by a pinned, epoch-resolved witness holding the `corroboration` role → `corroboration: "witnessed"`, warning `witness_independence_not_established`. |
| `39b-unpinned-witness-does-not-count` | A genuine cosignature by a witness no epoch pins → `"logged"`. Standing comes from the policy, never from the note. |
| `39c-invalid-ed25519-does-not-count` | Correct name and key ID, corrupted signature → `"logged"`. |
| `39d-c2sp-type-06-does-not-count` | Same witness, same timestamp, same 76-byte blob shape, genuine Ed25519 signature over the correct cosignature message — the ONLY defect is the C2SP signature type `0x06` baked into the key ID (§9.2) → `"logged"`. |
| `39e-checkpoint-domain-not-cosignature` | A genuine signature made over the checkpoint BODY, transported into a cosignature blob: without the `cosignature/v1` prefix the message is a different one → `"logged"`. |
| `39f-cosignature-domain-not-checkpoint` | The log's own ML-DSA-65 checkpoint line is missing and a genuine witness `0xff` activation leg stands in its place. Checkpoint authentication is hybrid and mandatory (§9.3), so the claim never reaches `logged` at all → `transparency: "not_checked"`, `corroboration: "none"`, warning `checkpoint_verification_failed`. |
| `39g-missing-policy-epoch` | 39a's cosignature verbatim, but the evidence names an epoch the policy does not contain → `"logged"`. An unresolvable epoch is never a reason to substitute another (§10.2). |
| `39h-wrong-role` | A current, uncompromised pin that holds only `sunset-activation` → `"logged"`. Roles are capabilities. |
| `39i-historical-epoch-valid` | A CLOSED epoch still corroborates: the observation falls inside its window, and a timely `signed-note-v2` anchor over the full note — cosignature line included — ties it to a PQ-surviving time → `transparency: "anchored_before:<T>"` and `corroboration: "witnessed"`. |
| `39j-current-epoch-not-substituted` | The same checkpoint and epoch name as 39i, but the historical epoch pins a different operator and the witness who signed is pinned only in the CURRENT epoch → `"logged"`. That pin's own window deliberately reaches back into the historical epoch: the operator existed all along and only entered the committee later, which is what leaves the MEMBERSHIP difference as the only thing deciding the verdict. |
| `39k-old-valid-no-local-clock-cap` | The pin retired after the observation was made. Standing is judged at the instant claimed, never at the verifier's local clock, so this verdict must still read `"witnessed"` decades from now. |
| `39l-evidence-policy-substitution-ignored` | The evidence carries its OWN, perfectly valid policy document pinning the witness who signed. It is ignored in full → `"logged"`. |
| `39m-compromise-onset-unknown` | `compromised_after: null` — a compromise IS declared and its onset is unknown, so the pin fails closed at every instant, forever. Distinct from the member being absent → `"logged"`. |

### 16.8 Activation witness quorum (§11.4, this document's own rev 7)

The conformance leaf group [`docs/spec/vectors/40-witness-quorum/`](vectors/40-witness-quorum/) (generated by `gen_40_witness_quorum`) pins §11.4's activation-grade hybrid quorum. It is a THIRD conformance surface: routed by the presence of `witness-quorum.json`, evaluated by the activation-quorum entry point rather than `verify()` or `audit_chain`, and carrying a result shape of its own — `{"valid": bool, "witness_time": int | null, "counting_control_groups": [...]}`, all three matched exactly. There is no receipt in the group at all, so these leaves ship no envelope and no trust store; `witness-quorum.json` holds the call's own inputs, of which `expected_origin` and `conflict_domain` are TRUSTED (malformed values raise) while `epoch_id`, `checkpoint`, and `anchor_evidence` are untrusted and may only degrade the verdict.

Every temporal limit ships as a PAIR one second apart, because that is where a rule either holds or silently does not: skew 600/601 (40l/40m) and anchor delay 86400/86401 (40o/40p). Two declared limits, measured rather than assumed. The committee ceiling of 40j is REDUNDANT with the declared-form check, since `threshold.n > 9` is already refused when the policy is parsed — no leaf can separate the two, so 40j pins their conjunction. And the one-timestamp-per-pair rule of 40e is redundant with signature verification: both legs sign a message built from a SINGLE timestamp, so a verifier that dropped the equality check would build the pair and then fail the signatures anyway, leaving every leaf green. 40e pins the outcome, not the rule that produces it. The corpus also cannot pin that NO cryptographic work happened before the ordering checks bind; a vector observes a verdict, not a call count, so the spies that prove it live in each implementation's unit tests.

| Leaf | Checks |
| --- | --- |
| `40a-one-of-one-valid` | One pinned witness, a complete `0x04`+`0xff` hybrid vote, an anchor inside the window → `valid: true`, `witness_time` = the vote's timestamp. |
| `40b-two-of-three-conservative-t` | 2-of-3 with the votes 300s apart → `T = min(t_i)`, not the maximum: taking the latest would let the last signer stretch the anchor window every earlier observation is judged by. |
| `40c-ed25519-leg-only-invalid` | The classical leg alone is not a weakened vote; it is no vote → `valid: false`. |
| `40d-mldsa-leg-only-invalid` | The post-quantum leg alone, likewise → `valid: false`. |
| `40e-legs-with-divergent-timestamps` | Both legs sign the byte-identical payload, timestamp included; legs one second apart are not a pair → `valid: false`. |
| `40f-transplanted-leg` | A genuine, correctly typed, correctly timed `0xff` leg signed over a DIFFERENT note: it pairs structurally and then fails the fail-closed AND → `valid: false`. |
| `40g-one-vote-per-control-group` | An operator who rotated keys has two pinned identities in ONE control group and presents a valid vote from each → rejected outright, not de-duplicated: a single organization must not reach the threshold on its own say-so. |
| `40h-direct-domain-conflict` | The pin itself names the domain whose sunset the quorum would activate → excluded before pairing, and the remaining vote cannot reach 2-of-3. |
| `40i-transitive-domain-conflict` | The voting pin names nothing, but a sibling in its own control group names the domain. Shared control is shared conflict — and there is deliberately no inverse: domain inequality never establishes independence. |
| `40j-committee-of-ten-invalid` | Ten activation control groups against a ceiling of nine, carrying votes that would otherwise satisfy the declared threshold → `valid: false`. |
| `40k-declared-form-incoherent-with-membership` | `threshold.n` counts distinct activation control groups; this epoch declares two while pinning three. The votes present would satisfy 2-of-2 exactly; the policy is refused rather than reconciled to them. |
| `40l-skew-600-valid` / `40m-skew-601-invalid` | Exactly 600s of spread between counting votes is inside the limit; 601 is not. |
| `40n-anchor-before-latest-vote` | An anchor that predates a counting vote cannot be evidence that the vote existed → `valid: false`. |
| `40o-anchor-delay-86400-valid` / `40p-anchor-delay-86401-invalid` | The anchor-delay boundary, measured from `T` and NOT from the latest vote. Both leaves carry two votes 300s apart, which is what makes the difference observable: with a single vote the two readings coincide, and a verifier measuring the window from the latest vote would pass the pair while reporting the same `witness_time`. |
| `40q-note-v1-anchor-insufficient` | A `note-v1` anchor commits to the unsigned header alone, so it proves nothing about the cosignature lines being counted (§11.1.1). Nothing else differs from 40a. |
| `40r-new-evidence-does-not-revive-expired-epoch` | The pins are open-ended and would have standing today; it is the EPOCH's window that closed, and `T` falls outside it → `valid: false`. |
| `40s-quorum-time-exactly-at-compromise-cutoff` | `T` exactly at the declared compromise onset still counts: the boundary is inclusive. The leaf runs inside the CLOSED 2020 epoch, which pins a second property — a VALID quorum whose `T` falls inside a window that has since expired. A verifier judging the epoch against its own clock rather than against `T` rejects this; 40r alone cannot catch that substitution, since both readings reject 40r. The two leaves pin the rule together. |
| `40t-compromise-cutoff-null-zero-votes` | The same member set with an explicit `null` onset: a compromise is declared and nobody knows when it began, so the pin fails closed at every instant and the quorum has zero counting votes. |

## 17. Stage 3: issuer-mediated transfer

This section specifies the transfer profile named as forthcoming by §1: an issuer-mediated protocol that moves a receipt from one holder to another with a verifiable chain of title, giving `license.transferable` (v0.1 §5.5) its first real meaning. Like Stage 1 and Stage 2 before it, Stage 3 is additive: no `signature`, `schema`, `binding`, or `trust` component gains a new value, and verification behavior is unchanged for any evaluation in which no `transferred`-class record is presented with Stage 3 backing evidence — with one schema-level carve-out: §17.8's holder-binding conditional (D1) makes a v0.2 receipt claiming `license.transferable: true` with a null or absent `buyer.pubkey` a schema error. That combination never had assigned meaning (v0.1 §2), and the changed outcome is sanctioned as a newly-recognized-hazard instance under attest-versioning.md §2 — a transferable receipt without a holder key would otherwise claim a capability this profile could never let it exercise. Stage 3 does add one genuinely new reachable value to an EXISTING v0.1 §11.1 component — `revocation: "transferred"` — under the conditions §17.3 states; this is the one exception to "no new result values" §1 and §10 claim for Stage 1 and Stage 2, and it is stated here explicitly rather than left implicit.

Transfer is issuer-mediated by design, never buyer-to-buyer: the issuer signs both the extinguishment of the old receipt and the issuance of the new one, consistent with the legal frame this profile targets (a resale mechanism exists only where the rights holder cooperates). A conforming Stage 3 implementation additionally requires the issuer to be Stage-2-capable (§17.2): transfer is layered on top of the transparency log, never a parallel mechanism of its own.

### 17.1 Transfer record profile

A transfer record is an issuer-signed side-document, structurally analogous to a revocation record (v0.1 §12), carrying exactly these six fields:

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `receipt_id` | string, ULID | REQUIRED | The receipt being transferred away — the OUTGOING holder's. |
| `new_receipt_id` | string, ULID | REQUIRED | The `receipt_id` of the receipt the issuer issues to the INCOMING holder. |
| `new_holder_pubkey` | string, base64url, 32 decoded bytes | REQUIRED | The incoming holder's Ed25519 public key. MUST equal the new receipt's `buyer.pubkey` (loop closure, below). |
| `transferred_at` | string, ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`) | REQUIRED | The record's own signed time — window and currency checks read this, never the verifier's local clock (mirrors v0.1 §12's `revoked_at` discipline). |
| `holder_authorization` | object, exactly one member `sig` | REQUIRED | An Ed25519 signature by the OUTGOING holder's `buyer.pubkey` (read from the OLD receipt — no `kid`, since the holder is not an issuer-manifest signer) over the domain-separated preimage below. |
| `signature` | object | REQUIRED | The ISSUER's signature over `JCS(record)` with `signature` removed; hybrid AND-rule per §13 (a classical-only record against a hybrid key entry MUST fail closed, exactly as revocation records do, §13). |

**Holder-authorization preimage (normative, verbatim):**

```
UTF8("Attest-transfer-authorization-v1") || 0x00 || UTF8(receipt_id) || 0x00 || UTF8(new_holder_pubkey) || 0x00 || UTF8(transferred_at)
```

The domain label is the ASCII string `Attest-transfer-authorization-v1`. Each component is its wire TEXT form — `receipt_id` and `transferred_at` as the literal strings carried in the record, `new_holder_pubkey` as its base64url text — encoded as UTF-8 (not decoded/re-encoded), mirroring v0.1 §8.2's `receipt_id`-encoding discipline exactly ("encoded as UTF-8 text (not decoded/re-encoded)"). Binding `receipt_id`, `new_holder_pubkey`, and `transferred_at` together in one signed preimage makes the authorization non-replayable against a different old receipt, a different incoming key, or a different signed time.

**Record authentication** mirrors v0.1 §12.1 in full: the resolving manifest MUST be self-consistent (v0.1 §7.1); `signature.kid` MUST resolve to a key-entry with `status == "active"`; `transferred_at` MUST fall within that key's `[valid_from, valid_to]` window; the issuer signature MUST verify over `JCS(record)` with `signature` removed; and every check fails closed (treated as unauthenticated) on any malformed, wrong-typed, or missing input, never by raising. The hybrid AND-rule of §13 layers on top exactly as it does for revocation records: a hybrid-keyed issuer's transfer record carrying only an Ed25519 `signature` MUST be treated as invalid.

**Loop closure.** A verifier checking a transfer record's effect on the OLD receipt does not itself re-verify the NEW receipt — the new receipt is a first-class receipt in its own right, verified standalone under the ordinary v0.1 §11 / v0.2 §3 algorithm, with its own `issued_at` and its own `license` block as set by the issuer at re-issuance. What the record's authentication DOES establish, and what a verifier tracing a chain of title (§17.5) MUST check, is: `holder_authorization` binds `new_holder_pubkey`; the record binds `new_receipt_id`; and the new receipt's `buyer.pubkey` MUST equal `new_holder_pubkey` — closing the loop between the record and the receipt it names. A mismatch here is a broken chain link (§17.5), not a rejection of either receipt standing alone.

The transfer type this profile registers is `issuer-mediated-v1` (attest-versioning.md §6.5), state `active`.

### 17.2 Log-required honoring (D2)

A transfer record remains the closed six-field object of §17.1; its inclusion proof is ACCOMPANYING evidence in the §10.2 evidence-bundle shape, proving the corresponding `transfer-record` entry (§8). It is honored ONLY when that inclusion proof in the issuer's Stage 2 log (§7–§10) reaches `logged` standing or better under §10.2's evaluation machinery. First-logged wins (§17.4). A transfer record that authenticates (§17.1) but has no such accompanying inclusion proof, or whose inclusion proof does not reach `logged` standing, MUST be ignored with warning `transfer_record_unlogged` — fail-closed, exactly as an unauthenticated revocation record is ignored (v0.1 §12.1). Transfer capability therefore exists only for Stage-2-capable issuers: an issuer with no transparency log cannot mediate a transfer under this profile, consistent with the issuer-mediated frame this profile targets (a resale mechanism exists only where the rights holder cooperates and keeps the evidence the mechanism needs).

### 17.3 Old-receipt extinguishment and the consent gate

The old receipt dies via an ORDINARY revocation record (v0.1 §12) carrying `status: "transferred"` — the class attest-versioning.md §6.3 registered `reserved` and this revision moves to `active`. A verifier reports this outcome as `revocation: "transferred"`, distinguishing "sold" from "revoked" on the existing revocation feed without a new feed or a new record shape.

**Reachability and `ok` (normative addition to v0.1 §11.1, v0.2 Stage 3 only).** `revocation` gains the reachable value `"transferred"`. It is reachable only under v0.2 Stage-3-capable verification — a verifier that evaluates transfer-record backing (below) for the matching revocation record. The `ok` predicate (v0.1 §11.1) is extended accordingly for such a verifier: `ok` additionally requires `revocation != "transferred"`, mirroring exactly how `revocation == "revoked"` already caps `ok`. A verifier that is not Stage-3 capable never produces this value at all and keeps v0.1's `ok` formula unchanged (eternal verifiability, attest-versioning.md §3).

**The consent gate.** The `transferred` class is honored for ALL revocability classes — `none` included — but ONLY when BACKED: an authenticated transfer record (§17.1) whose `holder_authorization` verifies AND whose log inclusion proof checks out (§17.2), matching this same `receipt_id`. Buyer consent is what permits extinguishing an otherwise-irrevocable receipt — the same principle v0.1 §5.1's `supersedes` field already rests on. Without valid backing, a `status: "transferred"` revocation record is ignored for EVERY class: `revocation: "invalid_revocation_ignored"` (the existing v0.1 value — no vocabulary growth for the unbacked case) plus warning `transferred_revocation_unbacked` — the `revocability: "none"` irrevocability guarantee (v0.1 §6.2) holds exactly as before, because nothing about this profile lets an unbacked record through.

Plain `status: "revoked"` records are entirely unaffected by this section and keep v0.1 §12.2's `refund_window`/`policy` semantics unchanged.

### 17.4 Double assignment

Two authenticated, log-included transfer records naming the same `receipt_id` are a double assignment: the EARLIEST log index wins. The later-indexed record is reported as conflicting evidence — warning `transfer_double_assignment_conflict` — echoing §10.3's two-checkpoints-in-hand discipline for equivocation: a verifier holding both records has conclusive evidence something is wrong, even though (unlike §10.3) neither record is itself invalid on its own terms. A receipt descending from the losing record's `new_receipt_id` does not obtain a valid chain link (§17.5) — the chain-of-title audit treats the earliest-wins record as the sole valid continuation.

### 17.5 Chain of title (separate audit surface)

Chain-of-title evaluation is NOT part of standard single-receipt verification (v0.1 §11 / v0.2 §3) — a receipt verifies standalone, exactly as §17.1's loop-closure paragraph states. It is a separate audit surface a verifier MAY additionally run. A chain walk MUST evaluate each link in this deterministic order: select the transfer record for the previous/next receipt pair; issuer signature (hybrid rule, §13); `holder_authorization` against the PREVIOUS receipt's own `buyer.pubkey` (never a later receipt's); log inclusion (§17.2); when `license.not_transferable_before` is present on the PREVIOUS receipt, strict Stage-3 UTC validation of both timestamps and the transfer floor; earliest-wins double-assignment selection (§17.4); pubkey loop closure on the NEXT receipt (§17.1); then the independent BACKED `transferred`-class revocation record on the previous receipt (§17.3). A competing claim is established for earliest-wins selection only when its issuer signature, holder authorization, log inclusion, and that same previous receipt's transfer floor all pass. A missing selected record skips the record-dependent checks but not the final backed-revocation check.

The following diagnostics are normative, byte-identical cross-language literals (`{i}` is the 1-based link ordinal), in the same per-link check order:

| Order | Literal |
| --- | --- |
| 1 | `chain link {i}: no transfer record` |
| 2 | `chain link {i}: issuer signature invalid` |
| 3 | `chain link {i}: holder authorization invalid` |
| 4 | `chain link {i}: transfer record not logged` |
| 5 | `chain link {i}: transferred before not_transferable_before` |
| 6 | `chain link {i}: losing branch of a double assignment` |
| 7 | `chain link {i}: new receipt buyer.pubkey != new_holder_pubkey` |
| 8 | `chain link {i}: previous receipt lacks a backed transferred-class revocation` |

v0.1 §8.2's prohibition on reading `buyer.pubkey` equality across two receipts as proof of buyer identity is untouched by this profile: the chain lives in these explicit, signed records, never in key equality alone.

### 17.6 Revocation interplay post-transfer

Revocation records continue to match by `receipt_id` alone (unchanged, v0.1 §12). The old receipt is already dead via its `transferred`-class record; any further record matching the OLD `receipt_id` is moot. A record matching the NEW `receipt_id` operates entirely under the NEW receipt's OWN `license.revocability` class, with the NEW receipt's OWN `issued_at` as the `refund_window` anchor (v0.1 §12.2) — the issuer sets the license terms afresh at re-issuance, and nothing about the old receipt's history constrains them.

### 17.7 `not_transferable_before` enforcement

`license.not_transferable_before` (OPTIONAL, string, ISO-8601 UTC; registered attest-versioning.md §6.2, v0.1 §5.5 amendment note) lets an issuer pin a floor on when a receipt becomes eligible for transfer. A transfer record whose `transferred_at` is earlier than the OLD receipt's own `not_transferable_before` (when that field is present) is NOT honored: it is ignored with warning `transfer_not_yet_transferable`, and the old receipt stays alive exactly as if no transfer record existed. This is fail-closed for the TRANSFER, never for the receipt itself — an unhonored transfer record has no effect on the old receipt's own `signature`/`schema`/`revocation`/`binding`/`ok` beyond the absence of the transfer.

### 17.8 Holder binding (D1)

A v0.2 receipt (gated on `attest_version`; v0.1 receipts are untouched) with `license.transferable: true` and `buyer.pubkey` null or absent is a SCHEMA ERROR — the chain of title is cryptographic from the first link, so a transferable receipt MUST name the key that would have to authorize any future transfer. Guest and client-less flows remain entirely valid, simply non-transferable, until re-issued with a `buyer.pubkey` via the existing `supersedes` path (the v0.1 §8.1 disclosure re-issue precedent, reused here for the same shape of problem). The operative gate for HONORING a transfer is the non-null `buyer.pubkey`, not the `transferable` flag's own value — this preserves the v0.1 §5.5 `eu_usedsoft_asserted` posture unchanged: `transferable: false` never overrides statutory exhaustion where the issuer cooperates and a pubkey is present.

Challenge-response (v0.1 §8.2) stays Ed25519 for the holder leg. This is an authorization-liveness mechanism, not the transfer's long-term evidentiary wrapper — that role belongs to the issuer's hybrid signature (§13) plus log inclusion (§17.2) plus anchoring (§11), exactly as for revocation records. Stated honestly: a post-CRQC forger of the Ed25519 holder leg still cannot forge the issuer's hybrid signature or rewrite the log — the holder leg's classical weakness is bounded by what surrounds it, never load-bearing alone.

### 17.9 Coerced transfer (normative limitation)

A signature establishes what was signed, never why. This profile claims authorization, not volition — a `holder_authorization` proves the outgoing holder's key produced that signature over that preimage, and nothing about compulsion, fraud, or duress in obtaining it. This is the TM-47 scoping (v0.1's revocation-record limitation) inherited unchanged: no signature scheme, and no transparency log, distinguishes a coerced consent from a voluntary one.

### 17.10 Business knobs out of protocol

Exactly one in-protocol field governs transfer economics: `license.not_transferable_before` (§17.7). Royalty schedules, resale windows, pricing floors, and revenue splits are issuer/marketplace policy, entirely out of this specification's scope — see the non-normative annex [`attest-transfer-economics.md`](attest-transfer-economics.md) for the business frame this profile intentionally leaves unregulated.

## Revision log

- **2026-07-28 (rev 7)**: P1.1b witness federation primitives added without Stage 4: §9.2 registers C2SP type `0xff` identifier `attest-cosignature-ml-dsa-65-v1`, its exact `cosignature/v1` payload, domain separation from `attest-ml-dsa-65`, and excludes `0x06`; §10 makes one pinned type-`0x04` cosignature reach `corroboration: "witnessed"` as timestamped observation with `witness_independence_not_established`, and adds explicit `witness_policy_epoch`; §11.4 defines closed JCS WitnessPolicy epochs, distribution, conflicts, compromise lifecycle, configured witness origin scope, and reusable quorum primitives; §15 item 1 preserves the residual anti-equivocation limitation; §1 amended in the same revision so its Stage 2b paragraph no longer forbids emitting `corroboration: "witnessed"` — that prohibition predates this revision and §10.1 supersedes it — and no longer calls the format forthcoming, and §10.3 annotated so the discovery half stays distinct from the observation this revision makes reachable. No §18 material is introduced. — vectors: 39-witness-corroboration, 40-witness-quorum
- **2026-07-23 (rev 6)**: §17 added — Stage 3, issuer-mediated transfer: the transfer record profile (§17.1, six fields, holder-authorization domain `Attest-transfer-authorization-v1`, issuer signature under the §13 hybrid AND-rule); log-required honoring (§17.2, D2 — unlogged records ignored with `transfer_record_unlogged`); old-receipt extinguishment via `status: "transferred"` revocation records reported as `revocation: "transferred"` (new reachable value on v0.1 §11.1's `revocation` component, capping `ok` the same way `"revoked"` already does) for all revocability classes when backed by §17.1/§17.2, `invalid_revocation_ignored` plus warning `transferred_revocation_unbacked` otherwise (§17.3); double assignment — earliest log index wins, loser reported with warning `transfer_double_assignment_conflict` (§17.4); chain-of-title audit surface, separate from single-receipt verify (§17.5); post-transfer revocation interplay, matched by `receipt_id`, new receipt's own class and `issued_at` anchor (§17.6); `license.not_transferable_before` enforcement, warning `transfer_not_yet_transferable` (§17.7); holder binding at issuance (§17.8, D1 — `transferable: true` requires non-null `buyer.pubkey`, schema-conditional, v0.1 untouched); coerced-transfer limitation, TM-47 scoping inherited (§17.9); business knobs out of protocol (§17.10). §8 amended — fourth loggable entry type `transfer-record` (`{type, issuer, record_sha256}`). §10 amended — the "these three components never affect revocation/ok" property gains a second scoped exception for `transferred`-class backing. attest-versioning.md §6.3's `transferred` row moves `reserved` -> `active`; §6.4 gains `transfer-record`; §6.5 receives its first entry, `issuer-mediated-v1`. — vectors: 35-transfer, 36-transfer-chain
- **2026-07-23 (rev 5)**: §8 amended — `revocation-record` is a THIRD loggable entry type (`{type, issuer, record_sha256}`, `record_sha256 = SHA-256(JCS(record))` over the entire signed revocation record); §10 amended — the "these three components never affect revocation/ok" property gains one scoped exception; §13 amended — the AND-rule paragraph's "transparency evidence cannot rescue OR condemn a revocation verdict" claim scoped against this exception; §15 item 5 rewritten — a `refund_window` revocation record is effective ONLY when a Stage-2-capable verifier's `revocation-record` transparency evidence proves the record's log entry was anchored no later than the receipt's own refund-window deadline (`issued_at + revocation_window_days`); failing that bound (unlogged, or anchored after the deadline) resolves to `revocation: "invalid_revocation_ignored"` (no vocabulary growth) plus warning `revocation_unlogged_deadline`; a verifier that is not Stage-2 capable at all keeps v0.1 semantics unchanged (eternal verifiability); `policy`/`none` classes unaffected; closes TM-47's deadline-unenforceable-effectiveness gap (signer intent/compulsion remain out of scope, §7 of the threat model). §16/§16.4 leaf counts added/corrected (`31-manifest-currency`'s stated leaf count corrected from 3 to 5, matching its actual 5 leaves since rev 2; corpus 78 -> 82). attest-versioning.md §6.4's `revocation-record` registry row moves `reserved` -> `active`. — vectors: 33-logged-revocation
- **2026-07-22 (rev 4)**: §11.1.1 added — anchor profile v2 (`anchor_profile: "signed-note-v2"`): the `ots` OTS commitment covers the checkpoint's FULL signed note (header AND signature lines, `signed_note_bytes`) instead of the unsigned header alone (`note_bytes`), closing TM-33's residual chosen-unsigned-note pre-anchoring risk; newly-produced anchors MUST use it, while absent/`"note-v1"` legacy anchors remain fully verifiable forever, classified with warning `anchor_note_only` (eternal verifiability, attest-versioning.md §3); §12 cross-references the symmetric checkpoint-level gap; §16/§16.3 leaf counts and the `28j` warning updated. **Amended same-day, still rev 4 (unpublished):** §11.1.1's single-profile rule made explicit (a bundle carries exactly one `anchor_profile`; `attest log anchor` refuses to append a mismatched-profile proof instead of relabeling retained ones); `attest log anchor` now validates an `--ots-proof`'s op-chain against the `signed-note-v2` seed at attachment time, with a dedicated diagnostic for a pre-G4 `note_bytes`-seeded proof; the op-chain mismatch warning is now profile-aware (names the required seed under `signed-note-v2`, and flags a v1-shaped commitment presented as v2) — `32b-v2-commit-mismatch`'s pinned `warnings` string updated accordingly. — vectors: 32-anchor-v2
- **2026-07-22 (rev 3)**: §2.3 + §13.1 added — mixed-keyset prohibition: an issuer declaring the hybrid profile MUST NOT hold an active Ed25519-only key; migration is a single manifest-version step; a conforming verifier emits `mixed_keyset_active_ed_only_sibling` when the condition is present. — vectors: 30-mixed-keyset
- **2026-07-22 (rev 2)**: §6.2 added — v0.1 §11.3's normative structural ceilings bind v0.2 too; §16.1 added — Stage 2's pre-existing evidence-parsing bounds (`_MAX_PROOF_LEN`, `_MAX_NOTE_TEXT_LEN`, `_MAX_NOTE_SIGNATURES`) formalized as conformance-surface requirements, unchanged in value; §6/§16 leaf counts updated for `29-limits`. — vectors: 29-limits
- **2026-07-22 (rev 1)**: revision log introduced by attest-versioning.md §5; no normative change. — vectors: none

## References

- [`docs/spec/attest-v0.1.md`](attest-v0.1.md) — the base specification; every section referenced above (§1, §4, §7.1, §7.2, §7.3, §7.4, §9, §10, §11, §11.1, §14.1, §15) is unchanged by this document except where explicitly stated.
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA).
- `draft-ietf-lamps-pq-composite-sigs` — the composite-signature parameter pairing (MLDSA65-Ed25519) this profile's parameter choice tracks for future interoperability.
- RFC 6962 — Certificate Transparency (the Merkle Tree Hash / inclusion / consistency proof construction §7–§10 build on).
- [C2SP tlog-tiles](https://c2sp.org/tlog-tiles), [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint), [C2SP signed-note](https://c2sp.org/signed-note) — the substrate profiles §7.2 and §9 specify a documented subset of / hybrid extension to.
- [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/) — normative conformance vectors for §2–§6 of this document.
- [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/) — normative conformance vectors for §7–§16 of this document.
