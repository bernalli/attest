# attest v0.1 — Normative Specification

- **Status**: Normative, v0.1
- **Date**: 2026-07-02
- **Grounding**: this document is grounded in the reference implementation in `src/attest/` and the conformance vectors in [`docs/spec/vectors/`](vectors/). It introduces no design decision not already present in one of those two sources.
- **Companion artifacts**: JSON Schema — [`docs/spec/schema/attest-receipt.schema.json`](schema/attest-receipt.schema.json); conformance vectors — [`docs/spec/vectors/`](vectors/).

## 1. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119, as clarified by RFC 8174, when, and only when, they appear in all capitals.

Passages introduced with **Non-normative note:** are explanatory or historical context. They carry no conformance weight; the surrounding normative text alone determines conformance. Everything else in this document is normative.

## 2. Scope

**Non-normative note:** attest is a standard for universal digital purchase receipts — games, music, film, TV, and books. DRM-free PC gaming is the adoption wedge for the reference implementation and initial conformance vectors, not a boundary on the scope defined below; nothing in this specification restricts a receipt to any single medium.

attest v0.1 defines: a signed receipt envelope and payload format; a restricted JSON canonicalization profile; a pinned Ed25519 signing/verification ruleset; a buyer-binding commitment scheme; issuer key and artifact manifest formats with rotation and compromise rules; a layered verification algorithm; revocation-record semantics; and two export bundle formats.

The following are explicitly **out of scope** for v0.1 and MUST NOT be assumed by a conforming implementation:

- **DRM.** attest MUST NOT be used, marketed, or implemented as a means of circumventing DRM or stripping protection from an artifact. attest defines no DRM-stripping functionality.
- **Content hosting/indexing.** A conforming attest implementation or registry node MUST NOT host or index the copyrighted works a receipt refers to; attest is content-free by design.
- **Resale/transfer.** v0.1 defines no resale or transfer protocol. `license.transferable` (§5.5) is a reserved field: implementations MUST NOT treat `transferable: true` as authorization to resell or transfer a license in v0.1 — that requires a future, rights-holder-authorized transfer profile. **Amendment note (2026-07-23):** that profile now exists — [`attest-v0.2.md`](attest-v0.2.md) §17 (Stage 3) defines the issuer-mediated transfer profile referenced above. Under v0.1 alone (an implementation that does not also implement v0.2 §17), the MUST NOT above stands unchanged: `transferable` carries no authorization meaning absent the v0.2 Stage 3 profile actively evaluating it.
- **Blockchain.** On-chain anchoring is an optional future transparency layer (Appendix B, non-normative). A conforming v0.1 implementation MUST NOT require blockchain infrastructure to issue or verify a receipt.
- **Payment processing.** A receipt records the outcome of a purchase, not the purchase transaction itself; it MUST NOT be construed as a payment instrument or as processing payment.

**What a receipt is.** A signed attest receipt is evidence of a license grant and its terms, signed by the issuer identified in the receipt. A receipt is not a claim of "ownership"; it does not promise access "forever" — it promises that the *evidence* verifies indefinitely and that the referenced *terms* remain producible (§7.4, §14). A receipt does not itself determine any seller's regulatory compliance (§5.4).

## 3. Terminology and actors

- **Issuer**: the entity that signs receipts, identified by a DNS domain it controls (§7). A marketplace or merchant-of-record MAY act as issuer on behalf of a named `work.publisher` (delegated-issuer path).
- **Buyer**: the holder of exported receipts.
- **Verifier**: any software that runs the algorithm in §11 against a receipt envelope.
- **Registry node**: an independent replicator of verification material (key/artifact manifests, revocation records, license/policy texts). Registry nodes are out of scope for v0.1 conformance (Appendix B, non-normative).

## 4. Envelope structure

A receipt is transmitted as a JSON envelope with exactly three top-level members: `payload` (§5, the only signed bytes), `signatures`, and an OPTIONAL `delivery` (§13).

```json
{
  "payload": { "...": "..." },
  "signatures": [
    { "kid": "store.example.com/keys/2026-01#ed25519-1", "alg": "Ed25519", "sig": "<base64url, 64 bytes decoded>" }
  ],
  "delivery": { "salt": "<base64url, 16 bytes decoded>", "issuer_manifest": { "...": "..." } }
}
```

### 4.1 `signatures`

- `signatures` MUST be a JSON array. A conforming verifier MUST reject an envelope whose `signatures` array does not contain **exactly one** entry (§11 step 1).
- Each entry MUST have `kid` (string) and `sig` (string, base64url, 64 decoded bytes) members.
- `alg` MUST equal the literal string `"Ed25519"`. A verifier MUST reject any other value. `alg` MUST NOT be used to select a verification primitive: the algorithm for `attest_version: "0.1"` is fixed at Ed25519 by this specification; a future version that adds algorithms MUST do so via a new `attest_version`, never via `alg` dispatch.

**Non-normative note:** the array shape of `signatures` is reserved for future counter-signatures (e.g. publisher counter-signing a delegated issuer's receipt); v0.1 defines no semantics for more than one entry beyond rejecting it.

### 4.2 `delivery`

- `delivery` is UNSIGNED (it is not part of `payload` and is not covered by the signature) and OPTIONAL.
- `delivery.salt`, if present, MUST be the base64url (no padding) encoding of the 16 raw bytes used as the buyer-commitment salt (§8).
- `delivery.issuer_manifest`, if present, MUST be a key-manifest object (§7.1) usable as a trust-store entry.
- An envelope carrying `delivery.salt` is a **private artifact**. Implementations MUST strip `delivery.salt` before treating an envelope as shareable (§14, `.attest`).
- Tampering with `delivery` cannot forge or invalidate a receipt: the salt is meaningful only insofar as it reproduces the signed `buyer.commitment` (§8), and any embedded manifest snapshot is independently signature-checked against its own `manifest_signature` (§7.1).

## 5. Payload field registry

`payload` is the sole signed object. Its JSON Schema is normative and lives at [`docs/spec/schema/attest-receipt.schema.json`](schema/attest-receipt.schema.json); this section is the field-by-field prose companion. Every property in every object below is permitted to carry additional, unlisted properties (the schema sets no `additionalProperties: false` anywhere) — see §11.2 on unknown-field handling.

### 5.1 Top level

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `attest_version` | string, const `"0.1"` | REQUIRED | Fixes the payload shape and the crypto suite (§8–§10) for this receipt. |
| `receipt_id` | string, ULID (`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`) | REQUIRED | ULID: sortable and coordination-free; its randomness provides practical collision-resistance. The leading character is bounded to `[0-7]` — a 26-char Crockford base32 ULID otherwise overflows the 128-bit value space (the same constraint [`attest-receipt.schema.json`](schema/attest-receipt.schema.json)'s `receipt_id` pattern already enforced; this row previously omitted it, a prose-only drift fixed 2026-07-22, no behavior change). |
| `issued_at` | string, `YYYY-MM-DDTHH:MM:SSZ` (UTC) | REQUIRED | Issuance timestamp; anchors key-validity checks (§11 step 3) and `refund_window` revocation (§12). |
| `supersedes` | string (ULID) or `null` | Schema-optional; the reference issuer always emits it (defaulting to `null`) | Informational lineage pointer to a prior `receipt_id` this one replaces. A superseding re-issue does **not** invalidate the superseded receipt absent buyer consent; a verifier MUST treat it as lineage metadata only, never as an implicit revocation. |
| `issuer` | object | REQUIRED | See §5.2. |
| `buyer` | object | REQUIRED | See §5.3. |
| `work` | object | REQUIRED | See §5.4. |
| `license` | object | REQUIRED | See §5.5. |
| `survivability` | object | REQUIRED | See §5.6. |

### 5.2 `issuer`

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `issuer.id` | string, lowercase DNS domain (≥2 labels) | REQUIRED | The issuer's identity. Roots key discovery (§7) and issuer-binding (§11 step 2). |
| `issuer.display_name` | string, non-empty | REQUIRED | Human-readable name; carries no cryptographic weight. |

### 5.3 `buyer`

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `buyer.commitment` | string, base64url, 32 decoded bytes | REQUIRED | `scrypt` commitment over a normalized identifier (§8.1). Binds the receipt to an identifier without exposing it. |
| `buyer.identifier_type` | enum `issuer-account` \| `email` | REQUIRED | `issuer-account` (a store-scoped account/customer id) is RECOMMENDED: disclosing it links nothing globally. `email` is for guest checkouts. |
| `buyer.pubkey` | string, base64url, 32 decoded bytes, or `null` | OPTIONAL, RECOMMENDED where a client app exists | Ed25519 public key for the challenge-response binding path (§8.2). `null` is the default for client-less flows. |

### 5.4 `work`

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `work.title` | string, non-empty | REQUIRED | |
| `work.publisher` | string, non-empty | REQUIRED | Names the publisher of record — the delegated-issuer path's anchor when `issuer` is a marketplace/MoR. |
| `work.edition` | string | OPTIONAL | |
| `work.identifiers` | object, ≥1 property, string-valued | REQUIRED | Issuer-scoped identifiers (e.g. `{"issuer_sku": "EXG-001"}`). |
| `work.artifact_series` | string, non-empty | OPTIONAL (conditionally required, §6.1) | Issuer-scoped series identifier; verifiers resolve the current artifact set for a series from issuer-signed artifact manifests (§7.2), not from the immutable receipt. |
| `work.artifacts` | array of artifact objects | OPTIONAL (conditionally required, §6.1) | At-purchase snapshot — evidence of what existed when the license was granted, not a live index. |
| `work.publisher_id` | string, lowercase DNS domain | OPTIONAL | The rights holder's domain, machine-readable alongside `work.publisher`'s human-readable name. REQUIRED, schema-conditionally, on a v0.2 receipt carrying `license.preservation_pledge` ([`attest-v0.2.md`](attest-v0.2.md) §18.6). Absent under v0.1 alone, it carries no meaning. |

Each `work.artifacts[]` item:

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `role` | string, non-empty | REQUIRED | e.g. `installer`. |
| `platform` | string, non-empty | REQUIRED | e.g. `windows-x86_64`. |
| `filename` | string, non-empty | REQUIRED | |
| `size_bytes` | integer, `0 ≤ n ≤ 2^53 − 1` | REQUIRED | See §9, correction on where over-range values are actually rejected. |
| `sha256` | string, `^[0-9a-f]{64}$` | REQUIRED | Lowercase hex (§9.1). |

Artifact hashes here and in artifact manifests (§7.2) identify content **authorized** under the issuer's mirror policy (§5.6); they MUST NOT be construed as a license or invitation to source matching-hash files from arbitrary or unauthorized hosts.

### 5.5 `license`

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `grant` | enum `perpetual` \| `subscription` | REQUIRED | |
| `revocability` | enum `none` \| `refund_window` \| `policy` | REQUIRED | Governs revocation-record effectiveness; see §12.2. |
| `revocation_window_days` | integer, `1 ≤ n ≤ 3650` | REQUIRED iff `revocability == "refund_window"` | The window is anchored to `issued_at` and evaluated against a revocation record's own signed time, never the verifier's clock (§12.2). |
| `transferable` | boolean | REQUIRED | Reserved; see §2. Assigned meaning by v0.2 §17 (Stage 3, 2026-07-23 amendment note). |
| `not_transferable_before` | string, ISO-8601 UTC | OPTIONAL | Reserved for the v0.2 Stage 3 transfer profile; enforced at transfer evaluation, never at issuance (v0.2 §17.7, 2026-07-23 amendment note). Absent under v0.1 alone, this field carries no meaning. |
| `drm` | enum `drm-free` \| `drm-bound` | REQUIRED | v0.1 issuers SHOULD only issue `drm-free` receipts. `drm-bound` is permitted (a receipt is still better than nothing), but a verifier MUST NOT present a `drm-bound` receipt as a platform-independent entitlement, and MUST emit a warning on `drm-bound` (§11.2). A receipt never removes DRM and this specification never claims it does. |
| `terms_uri` | string, `format: "uri"` | REQUIRED | See §9 on the annotation-only status of `format: "uri"`. |
| `legal_text_sha256` | string, `^[0-9a-f]{64}$` | REQUIRED | SHA-256 of the license text at `terms_uri`, hash-binding it into the signed payload. |
| `jurisdiction_flags` | object, boolean-valued, open vocabulary | OPTIONAL | See `eu_usedsoft_asserted` below. |
| `preservation_pledge` | object | OPTIONAL | The rights holder's signed end-of-life redistribution rider, declared as a license term and hash-bound the way `terms_uri`/`legal_text_sha256` bind the licence text. Specified by v0.2 §18 (Stage 4, 2026-08-25 amendment note); its three members are `pledge`, `grant_uri` and `grant_sha256` ([`attest-v0.2.md`](attest-v0.2.md) §18.2). Absent under v0.1 alone, this field carries no meaning. |

`jurisdiction_flags.eu_usedsoft_asserted` means precisely: the issuer asserts this sale met the *UsedSoft* C‑128/11 conditions (perpetual software license, fee corresponding to economic value, no license splitting). It is **informational, not a transfer authorization**: transfer-time conditions (e.g. disabling the seller's own copy) are out of receipt scope. Where the assertion is true and EU law applies, statutory exhaustion cannot be contracted away, and `transferable: false` MUST NOT be read as overriding it.

### 5.6 `survivability`

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `redownload_right` | boolean | REQUIRED | |
| `mirror_policy_uri` | string, `format: "uri"` | OPTIONAL | See §9. |
| `mirror_policy_sha256` | string, `^[0-9a-f]{64}$` | OPTIONAL | Hash-binds the mirror policy text into the signed payload so the issuer cannot silently rewrite obligations post-issuance; the policy text itself travels in the export bundle (§14). |
| `end_of_life` | string, non-empty, open versioned vocabulary | REQUIRED | v0.1 seed values: `artifacts-remain-redownloadable`, `escrow`, `none`. Unknown values are valid-with-warning (§11.2), never a schema error — this keeps the field extensible toward a future EU end-of-life industry code of conduct without a new `attest_version`. v0.2 §18 registers one further value, `sunset-grant` (2026-08-25 amendment note): it is the label a Stage 4 receipt carries, while the commitment itself is hash-bound by `license.preservation_pledge`. A v0.1-only verifier treats it exactly as it treats any other unrecognized value. |
| `eol_commitment_uri` | string or `null`, `format: "uri"` | OPTIONAL | See §9. |
| `eol_commitment_sha256` | string or `null`, `^[0-9a-f]{64}$` | OPTIONAL | Hash-binds a future end-of-life commitment document once referenced. |

## 6. Legal-weight field semantics

### 6.1 `revocability: "none"` conditional

When `license.revocability == "none"`, the schema imposes an `allOf`/`if`/`then` conditional (see [`attest-receipt.schema.json`](schema/attest-receipt.schema.json)) that a conforming issuer implementation MUST satisfy at issuance time and a conforming verifier MUST enforce at schema-validation time (§11 step 5):

- `license.drm` MUST equal `"drm-free"`;
- `survivability.redownload_right` MUST equal `true`;
- at least one of `work.artifact_series` (non-empty) or `work.artifacts` (non-empty array) MUST be present.

A receipt meeting this conditional supports an argument that the sale falls under exemptions such as CA AB 2426 or MD HB 208 (keyed to goods the seller cannot revoke — in practice, a permanent offline download). This specification states that support precisely: **a receipt meeting the `revocability: "none"` conditional is evidence, not a compliance determination** — the seller's storefront language and funnel remain the seller's own duty.

### 6.2 Revocation semantics follow the class

Revocation records against a `revocability: "none"` receipt are **invalid and MUST be ignored** by a conforming verifier — flagged as a warning, never as an invalidation — because the only thing that MAY invalidate such a receipt is key compromise (§7.3) (itself bounded, for a Stage-2-capable verifier, by the anchored-cutoff rule of [`attest-v0.2.md`](attest-v0.2.md) §19 — so the narrowest honest statement of the guarantee is: a `revocability: "none"` receipt whose signed-receipt-core is anchored strictly before any anchored compromise declaration of its key cannot be invalidated by anyone, including its issuer). `refund_window` and `policy` records are honored per §12.2's revocation-by-class table. Without this rule, the protocol's own revocation machinery would falsify every irrevocability assertion made under §6.1.

### 6.3 Immutability

A receipt is immutable once signed. Dynamic state — revocation events, current artifacts, key rotations, commercial availability — MUST live in signed side-documents (§7, §12) and MUST NOT be represented as living inside the receipt payload itself.

## 7. Issuer identity, keys, and manifests

### 7.1 Key manifests

An issuer's identity is its DNS domain (`issuer.id` / manifest `issuer`). An issuer SHOULD publish its key manifest at `https://<issuer.id>/.well-known/attest.json`.

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `issuer` | string, DNS domain | REQUIRED | MUST equal the domain prefix of every listed `kid`. |
| `manifest_version` | integer, monotonically increasing per issuer | REQUIRED | Rotation continuity (§7.3) keys off `N → N+1`. |
| `issued_at` | string, UTC `Z` timestamp | REQUIRED | |
| `keys` | array of key-entry objects | REQUIRED | See below. |
| `manifest_signature` | object `{kid, sig}` | REQUIRED | Ed25519 signature over `JCS(manifest)` with this member removed. Every listed key's `kid`, `pub`, `valid_from`, `valid_to`, `status` is inside the signed body — nothing about a key's lifecycle is tamperable without breaking the signature. |

Key-entry object (`keys[]`):

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `kid` | string, `<issuer-domain>/keys/<label>#<name>` | REQUIRED | Domain prefix (text before the first `/`) MUST equal `issuer`. |
| `pub` | string, base64url, 32 decoded bytes | REQUIRED | Ed25519 public key. |
| `valid_from` | string, UTC `Z` timestamp | REQUIRED | |
| `valid_to` | string, UTC `Z` timestamp, or `null` | OPTIONAL | Absent or `null` = open-ended (no upper bound). |
| `status` | enum `active` \| `retired` \| `compromised` | REQUIRED | See §7.3. |

**Non-normative note:** the design's illustrative manifest JSON (design §5) also shows a per-key `alg` member; the reference implementation and every shipped vector omit it, because v0.1 fixes exactly one algorithm (Ed25519, §10) for the whole manifest scope — a per-key `alg` would be redundant. This specification follows the implementation: `keys[]` entries carry no `alg` member.

> **Amendment note (2026-08-25, v0.2 §18.1).** v0.2 Stage 4 resolves a key manifest of this IDENTICAL shape, at this identical well-known path, for a second role: the rights holder named by `work.publisher_id`, who need not be the receipt's issuer. No new manifest type and no new key format are introduced — domain-control provenance, rotation continuity, `compromised` fail-closed handling and the trust ladder of §7.4 are reused verbatim. What is new is only which domain a verifier resolves, and the resulting standing is reported in a separate component, never folded into the receipt's own `trust`.

### 7.2 Artifact manifests

Artifact manifests are separate signed documents, same signing discipline as key manifests, that let fast-changing artifact state live outside the immutable receipt. `work.artifact_series` names the series; acceptance is NOT unconditional on being issuer-signed for that series — a verifier MUST authenticate an artifact manifest (its `manifest_signature`, §7.2) AND MUST additionally satisfy the currency rule of §7.3 below before accepting it as the newest-seen state: rollback and equivocation (two distinct manifests at the same `manifest_version`) are rejected, not silently accepted. An unauthenticated manifest contributes nothing to currency and MUST be ignored with a warning.

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `issuer` | string, DNS domain | REQUIRED | MUST equal the resolving key manifest's `issuer`. |
| `series` | string | REQUIRED | Matches `work.artifact_series`. |
| `version` | integer | REQUIRED | The series' own release number — unrelated to currency/rollback protection, see `manifest_version` below. |
| `manifest_version` | integer ≥ 1, monotonically increasing per issuer/series (2026-07-22 amendment) | REQUIRED on manifests produced after this revision | Currency/newest-seen ordering (§7.3) — distinct from `version` above, and from key manifests' own `manifest_version` (§7.1), which this field parallels but does not share a namespace with. Absent on a manifest produced before this revision (a legacy manifest): still VALID, never rejected (attest-versioning.md §3, eternal verifiability) — a conforming verifier MUST report warning `artifact_manifest_unversioned` (§11.2) instead. |
| `released_at` | string, UTC `Z` timestamp | REQUIRED | Checked against the signer key's `[valid_from, valid_to]` window. |
| `artifacts` | array of artifact objects (§5.4 shape) | REQUIRED | Current artifact set for the series. |
| `manifest_signature` | object `{kid, sig}` | REQUIRED | Ed25519 over `JCS(manifest)` with this member removed. |

An artifact manifest is valid only if: its resolving key manifest is self-consistent (§7.1); the signer's `kid` resolves to a key-entry with `status == "active"` in that key manifest; `released_at` falls within that key's `[valid_from, valid_to]`; `issuer` matches between the two manifests; and the Ed25519 signature verifies. `manifest_version`'s presence or absence never affects this self-consistency verdict — it is signed-and-carried like any other member, checked only by the currency rule below.

### 7.3 Rotation continuity and key compromise

**Rotation continuity is normative, not best-effort.** A manifest with `manifest_version` N+1 is auto-trusted by a verifier only if it was signed by a key that was `active` in the version-N manifest the verifier already trusts. Version gaps are bridgeable only by validating every intermediate manifest in sequence; if intermediates are unavailable, the manifest MUST be treated as reached via a **discontinuous** rotation. On a discontinuous manifest, or on conflicting manifests for the same issuer, a verifier MUST report `trust: "unverified_rotation"` (§11.1) and MUST NOT auto-accept the manifest. Receipts signed while a key was `active` remain valid after that key is later `retired`.

**Artifact manifest currency is normative too (2026-07-22 amendment).** Currency state is scoped per (issuer, `artifact_series`) pair. A verifier holding persistent trust state MUST NOT accept, for that pair, a manifest with `manifest_version` lower than the newest it has already accepted; on regression it MUST report `trust: "unverified_rotation"` (§11.1) — the same value, and the same rollback-detection posture, §7.3's key-manifest rotation-continuity rule above already uses; no new `trust` value is introduced. Currency comparison applies only between manifests that both carry `manifest_version`: a manifest missing the field (§7.2, a legacy manifest predating this amendment) has no currency ordering to violate, so it is never rejected on these grounds, only warned (§11.2, `artifact_manifest_unversioned`) — eternal verifiability (attest-versioning.md §3) applies here exactly as it does everywhere else this specification is amended. The Stage 2 `manifest_freshness` result component (v0.2 §10) is the recency evidence a verifier MAY additionally consult when transparency-log corroboration is configured; it is informational only and does not itself drive this currency check.

**Key compromise fails closed; a Stage-2-capable verifier bounds it at the anchored cutoff.** A key whose status resolves to `compromised` under the absorbing-status rule below invalidates every receipt signature ever made with it — with exactly one carve-out, the anchored-cutoff rescue of [`attest-v0.2.md`](attest-v0.2.md) §19, available only to a verifier that is Stage-2 capable (v0.2 §10.2: pinned `log_keys` AND `anchor_policy` both configured) and only for a receipt whose signed-receipt-core (v0.2 §12) provably existed, logged and externally anchored (v0.2 §11.1), **strictly before** the anchored time of a qualifying key manifest that declared the compromise. A verifier that is NOT Stage-2 capable — including every v0.1-only verifier — MUST reject any receipt signature whose signing key resolves to `compromised` (§11 step 3) unconditionally, regardless of `issued_at`: `issued_at` lives inside the signed payload and is controlled by whoever holds the key, so a back-dated forgery is undetectable without an external existence proof, and a verifier that cannot evaluate such a proof has no sound alternative to failing closed. This is byte-for-byte unchanged only for a v0.1-only verifier that holds neither an issuer manifest-version chain nor authenticated compromise-declaration evidence; a verifier that holds either MUST apply the absorbing-status rule before this check. The same fail-closed rule governs revocation records: a revocation record signed by a key that is not `status == "active"` in its resolving key manifest — including `compromised` and `retired` keys — MUST be treated as failing authentication and MUST be ignored (with a warning), never treated as effective (§12.2); the §19 rescue applies to receipt signatures ONLY and does not extend to any side-document (v0.2 §19.5). Issuers SHOULD use one signing key per period (e.g. quarterly `kid`s) to bound the **forgery** exposure of a compromise — per-period keys do NOT bound the invalidation reach of a compromise marking itself, since any still-active key may publish a manifest marking any other key `compromised` — and SHOULD re-issue affected receipts after one. An issuer declaring a compromise SHOULD submit the declaring key manifest to a transparency log and anchor it (v0.2 §11) promptly: under v0.2 §19 a compromise declaration that has no anchored time cannot invalidate any receipt that holds anchored standing.

**A `compromised` marking is absorbing.** For each issuer, a verifier resolves only one key-status value monotonically: `compromised`. A verifier MUST resolve a `kid` as `compromised` if the verifier holds any evidence for that issuer that marks the `kid` `status: "compromised"`: the entry in its trusted key manifest; the entry for that `kid` in any manifest of that issuer's version history held in the §7.4 `TrustStore` chain; or the entry for that `kid` in any compromise declaration authenticated under [`attest-v0.2.md`](attest-v0.2.md) §19.3 items 1, 2, and 3a. Otherwise the `kid`'s status is the status in the trusted key manifest. This rule governs `compromised` and nothing else: it does not order `active` below `retired`, it does not make `retired` absorbing, and a `kid` moving from `retired` back to `active` is outside this revision's scope. A verifier holding persistent trust state MUST NOT stop resolving a `kid` as `compromised` after resolving it so once, exactly as it MUST NOT accept a regressed `manifest_version` above. From this revision forward, key-manifest continuity also fails if a successor manifest lists a `kid` as anything other than `compromised` when the immediately preceding manifest listed that `kid` as `compromised`, or if a successor manifest drops any `kid` the immediately preceding manifest listed at all. In either case the verifier MUST report `trust: "unverified_rotation"`, and an issuer MUST NOT publish the successor manifest. Keyset preservation is part of the rule: omitting a `kid` entirely is otherwise a silent way to unmake a compromise marking and to strand declarations signed by that `kid`. There is no un-compromise ceremony, and none is planned: reversing a compromise marking asserts that an incident never happened, and the pen for that assertion would belong to the very party the rule constrains. The remedy for a marking made in error, under coercion, or by an attacker holding some other still-active key is a NEW `kid` and re-issuance, never the resurrection of the marked key. A verifier that holds only the issuer's latest key manifest, with no version history and no authenticated compromise declaration, resolves status from that manifest alone and cannot detect a regression: like every other Stage-1 limit in this specification, the floor is only as strong as the evidence the verifier holds (v0.2 §19.6 item 5).

### 7.4 Offline verification and trust bootstrapping

Offline verification MUST work from a local trust store of key manifests (a `TrustStore`: per-issuer manifest, per-issuer provenance, optional per-issuer manifest-version chain). A manifest obtained from the issuer's own domain over TLS is the v0.1 root of trust; a verifier that resolved a manifest this way MUST report `trust: "verified"` (absent a discontinuous rotation, §7.3). A manifest that arrived by any other path — e.g. embedded in an export bundle, never independently fetched over TLS — is **unauthenticated TOFU** and MUST be reported as `trust: "unauthenticated_tofu"`, never silently upgraded to `"verified"`.

## 8. Buyer commitment and binding

Two mechanisms, layered.

### 8.1 Commitment (always present)

```
P = UTF8("Attest-buyer-commitment-v1") || 0x00 || UTF8(identifier_type) || 0x00 || UTF8(normalize(identifier))
commitment = scrypt(P, salt, N=32768, r=8, p=1, dkLen=32)
```

- The domain label is the ASCII string `Attest-buyer-commitment-v1`.
- `salt` MUST be exactly 16 raw bytes, generated per receipt by the issuer, hashed as **raw bytes** (never as base64url text), and delivered to the buyer (`delivery.salt` and/or export bundle, §14).
- scrypt parameters are fixed by this specification version: `N=32768, r=8, p=1, dkLen=32`. Implementations MUST use these exact parameters; they MUST NOT be configurable per-issuer.
- `identifier_type` MUST be one of `issuer-account` or `email` (§5.3).

**`normalize()` is normative.** For a given `(identifier, identifier_type)`:

1. If `identifier_type == "email"`: strip ASCII whitespace (`0x20`, `0x09`, `0x0A`, `0x0D`) from both ends of `identifier`; apply Unicode NFC normalization; then lowercase **ASCII `A`–`Z` only** (byte-deterministic — no locale case-folding, since locale-dependent folding such as Turkish dotless‑ı behavior is a worse failure mode than imperfect casing of non-ASCII text).
2. If `identifier_type == "issuer-account"`: apply Unicode NFC normalization only; the string is otherwise used exactly as given (no whitespace stripping, no case folding).
3. In both cases, the resulting normalized string MUST NOT contain the byte `0x00`; an implementation MUST reject an identifier that does.

**Non-normative note:** scrypt, not plain SHA-256, is used because identifiers are low-entropy (emails); a leaked salt must not enable cheap dictionary recovery. SHA-256 remains the hash for high-entropy inputs (artifacts, legal texts, §10).

**Disclosure semantics.** Revealing `(identifier, salt)` to a verifier is a replayable bearer proof that also hands over the identifier: it permanently burns that receipt's binding secrecy toward that verifier and, for `email`, links the buyer across issuers. Per-receipt salts confine this damage to one receipt. A verifier MUST treat a disclosed identifier as personal data not to be retained beyond the verification. Issuers SHOULD offer re-issue (via `supersedes`) after a disclosure.

### 8.2 Key binding (`buyer.pubkey`, optional)

The strong path: an Ed25519 public key bound into the signed payload, proven via non-replayable challenge-response.

```
verifier sends nonce (≥16 random bytes)
buyer signs: UTF8("Attest-binding-challenge-v1") || 0x00 || receipt_id || 0x00 || nonce
```

- The domain label is the ASCII string `Attest-binding-challenge-v1`.
- `nonce` MUST be at least 16 bytes, freshly generated per challenge.
- `receipt_id` is the receipt's own `payload.receipt_id`, encoded as UTF-8 text (not decoded/re-encoded).
- Keys SHOULD be per-receipt (a fresh keypair per purchase, stored alongside the salt in the private bundle, §14; deterministic derivation from a buyer master key is acceptable — only the public key is ever signed into the payload). A verifier MUST NOT treat `buyer.pubkey` equality across two receipts as proof of buyer identity.
- `pubkey: null` is the default for client-less flows; mandatory key custody is out of scope for v0.1.

## 9. attest-JCS canonicalization profile

Canonicalization follows RFC 8785 (JSON Canonicalization Scheme, JCS) over `payload`, with one deliberate, explicit **deviation by restriction**:

> **Deviation from RFC 8785 (I-JSON integer-only profile).** Full JCS permits any I-JSON number, canonicalized via the ECMAScript `Number::toString` algorithm, which must reproduce IEEE-754 double rounding behavior identically across implementations to stay interoperable. attest v0.1 removes that entire cross-language interop risk by restricting numbers to **integers only**, with `|n| < 2^53`. A conforming attest-JCS canonicalizer:
>
> - MUST accept a JSON number if and only if it is an integer with `-(2^53 − 1) ≤ n ≤ 2^53 − 1`;
> - MUST reject (fail canonicalization) any float, any `NaN`/`Infinity`/`-Infinity` construct, and any integer with `|n| ≥ 2^53`.
>
> This is a restriction of, not an incompatible extension to, RFC 8785: every attest-JCS output is also a valid JCS output.

The signature input for a receipt is exactly `JCS(payload)` — as produced by the attest-JCS profile above — encoded as UTF-8 bytes. Additional canonicalization-time requirements, applied at parse time before any signature or schema step runs (§11 step 0):

- The input MUST be valid UTF-8.
- A JSON object containing a **duplicate member name** MUST be rejected outright (parse failure) — RFC 8785 requires rejection, never silent last-value-wins deduplication.
- Object keys MUST be serialized in the order produced by sorting their UTF-16BE code-unit sequences.
- Lone UTF-16 surrogates (whether arriving as literal bytes or via `\uXXXX` escapes) MUST be rejected.

**Correction (over-range integers, normative).** An integer with `|n| ≥ 2^53` inside `payload` is rejected **at canonicalization**, not at schema validation: the value fails the attest-JCS precondition in §9 before `JCS(payload)` can even be computed, so the signature-verification step (§11 step 4, which requires `JCS(payload)` as its input) reports `signature: "invalid"` and `schema: "not_checked"` — schema validation never runs, because it operates on the same already-parsed object and the pipeline only proceeds past a canonicalization failure by rejecting outright. The JSON Schema's own `maximum: 9007199254740991` constraint on integer fields such as `size_bytes` (§5.4) is a defense-in-depth backstop for callers that invoke `validate_payload` directly and unsigned (bypassing canonicalization entirely) — it MUST NOT be relied upon as the primary enforcement point when verifying a signed envelope.

**`format: "uri"` is annotation-only in v0.1.** `license.terms_uri`, `survivability.mirror_policy_uri`, and `survivability.eol_commitment_uri` are declared `format: "uri"` in the JSON Schema, but a conforming v0.1 validator is **not required to, and the reference implementation does not,** assert URI well-formedness as a validation failure — wiring a format-checker is an additional dependency the attest-JCS/schema profile does not require, and JSON Schema draft 2020-12 treats unassserted `format` as annotation-only by default. Integrity of the document a URI field points to is guaranteed by its accompanying SHA-256 hash binding (`legal_text_sha256`, `mirror_policy_sha256`, `eol_commitment_sha256`), never by URI syntax validation.

### 9.1 Encodings

- **Signatures, commitments, salts, and public keys** MUST be encoded as base64url **without padding** (RFC 4648 §5, `=` stripped).
- **SHA-256 hashes** (artifact hashes, legal-text hashes, mirror-policy hashes, EOL-commitment hashes) MUST be encoded as **lowercase hexadecimal** (matching common `shasum -a 256` output).
- `receipt_id` and `supersedes` are ULIDs (Crockford base32, 26 characters, excluding `I`, `L`, `O`, `U`).

## 10. Cryptography

- **Signature algorithm**: Ed25519 (RFC 8032). v0.1 defines exactly one algorithm; a future algorithm requires a new `attest_version` (§4.1).
- **Pinned verification ruleset.** A conforming verifier MUST perform cofactorless (strict) RFC 8032 verification and MUST additionally:
  - reject a signature whose scalar `S` is non-canonical, i.e. `S ≥ L`, where the Ed25519 group order is `L = 2^252 + 27742317777372353535851937790883648493` (SUF-CMA property);
  - reject small-order or non-canonical encodings of the public key `A` and the signature's `R` component (SBS property).
- **Receipt hash** (for bundles and dedup): `SHA-256(JCS(payload))`. It MUST NOT be computed over the envelope, which contains unsigned, malleable members (`delivery`).
  > **Superseded for transparency use (v0.2 Stage 2).** This payload-only hash is NOT the transparency-log commitment. A `receipt` log entry commits to the signed-receipt core — `SHA-256("attest-receipt-core-v1" || 0x00 || JCS(payload) || 0x00 || JCS(signatures))` — so that the commitment binds the signature bytes and not the payload alone; see [`attest-v0.2.md`](attest-v0.2.md) §12. Conformance vector `28-transparency` rejects the payload-only construction. Building log entries from the hash above would produce evidence no conforming verifier accepts.
- **Hashes**: SHA-256 for artifacts, legal texts, and policies (§9.1); scrypt (§8.1) exclusively for the buyer commitment.

**Non-normative note:** the pinned ruleset exists so that implementations built on different backends (libsodium, OpenSSL, `ed25519-dalek`, …) disagree loudly at conformance-test time (§15) rather than silently accepting a malleable signature in the field.

## 11. Verification algorithm

```
verify(envelope, trust_store, revocation_view=None, disclosure=None) → VerificationResult
```

A conforming verifier MUST execute the following steps in order. A step that rejects the input MUST short-circuit the remaining steps; the result's `revocation` and `binding` components take their safe stub values (`"unknown"` and `"not_checked"` respectively) whenever they are not reached.

0. **Preconditions.** Parse the input once per §9 (UTF-8, attest-JCS-conformant, no duplicate keys). Every later step, and every downstream consumer, MUST operate on this single parsed object — never on the raw transmitted bytes and never on a re-serialization of it.
1. **Envelope well-formedness.** `attest_version` MUST be a version this verifier supports (v0.1 verifiers support only `"0.1"`); `signatures` MUST have length exactly 1; the signature block's `alg` MUST equal `"Ed25519"` (§4.1).
2. **Issuer binding.** Resolve the signing key **only** from the trust store's manifest for `payload.issuer.id`. The `kid`'s DNS-domain prefix MUST equal `payload.issuer.id`, and the resolved manifest's own `issuer` field MUST also equal it; otherwise reject with an issuer-mismatch error. This is what makes cross-issuer impersonation impossible: a valid manifest for one domain can never validate a receipt claiming a different `issuer.id`.
3. **Key checks.** The key MUST be present in the trust store's manifest for `payload.issuer.id`; its resolved status under §7.3 MUST NOT be `"compromised"` (§7.3 — unconditional for a verifier that is not Stage-2 capable; a Stage-2-capable verifier MUST apply the anchored-cutoff rule of [`attest-v0.2.md`](attest-v0.2.md) §19 before rejecting); `payload.issued_at` MUST fall within the key's `[valid_from, valid_to]` window. If the resolved status is `"retired"`, verification continues but a warning MUST be emitted (§11.2).
4. **Signature verification.** `Ed25519.verify(JCS(payload), sig, pub)` under the pinned ruleset (§10). `JCS(payload)` — as computed here — is the only signature input; a canonicalization failure at this stage (including the over-range-integer case, §9) yields `signature: "invalid"`.
5. **Schema validation** of the parsed payload from step 0, against [`attest-receipt.schema.json`](schema/attest-receipt.schema.json) (JSON Schema draft 2020-12).
6. **Revocation** (only performed if `revocation_view` is supplied, and only reached if steps 4 and 5 both succeeded): classify revocation records against `payload.license.revocability` per §12.
7. **Binding** (only performed if `disclosure` is supplied, and only reached if steps 4 and 5 both succeeded): recompute the commitment from `(identifier_type, identifier, salt)` per §8.1, or verify a `buyer.pubkey` challenge-response transcript per §8.2.

### 11.1 Result vocabulary

The result MUST be layered — never a single boolean — with exactly these components and exactly these literal values:

| Component | Allowed values |
| --- | --- |
| `signature` | `valid` \| `invalid` |
| `schema` | `valid` \| `invalid` \| `not_checked` |
| `revocation` | `unknown` \| `not_revoked_as_of:<T>` \| `revoked` \| `invalid_revocation_ignored` |
| `binding` | `proven` \| `not_proven` \| `not_checked` |
| `trust` | `verified` \| `unauthenticated_tofu` \| `unverified_rotation` |

`not_revoked_as_of:<T>` is a single literal string formed by concatenating the fixed prefix `not_revoked_as_of:` with `T`, the ISO-8601 UTC timestamp of the freshest **authenticated** revocation record the verifier consulted (§12.3) — with no separator between the colon and `T`. When no authenticated record was available, the result MUST be the bare literal `unknown` instead.

**`trust` is resolved as early as possible** — as soon as `payload.issuer.id` can be read — and is reported at its best-available value even when a later step (steps 1–5) rejects the receipt: a verifier MUST NOT silently reset `trust` to a default on later failure. `trust` starts at `unauthenticated_tofu`; it becomes `verified` if the trust store's provenance for the resolved issuer is `"tls"`; it is forced to `unverified_rotation`, overriding provenance, if the trust store holds a manifest-version chain for that issuer and that chain is discontinuous (§7.3) at any point.

`ok` is defined as: `signature == "valid"` **and** `schema == "valid"` **and** `revocation != "revoked"` **and** the result carries no errors. `invalid_revocation_ignored`, `unknown`, and any `not_revoked_as_of:<T>` value do **not** affect `ok` — an ignored-by-class or merely-unverified revocation state must never degrade a receipt's validity, or it would defeat the `revocability: "none"` irrevocability guarantee (§6.2).

> **Amendment note (2026-07-23, v0.2 §17.3).** v0.2 Stage 3 adds one new reachable value to the `revocation` row above: `"transferred"`. It is reachable only under v0.2 Stage-3-capable verification and, where reachable, extends the `ok` predicate above to additionally require `revocation != "transferred"` — mirroring exactly how `"revoked"` already caps `ok`. Under v0.1 alone this value is never produced and the `ok` formula above is unchanged.

> **Amendment note (2026-08-25, v0.2 §18.5).** v0.2 Stage 4 adds two entirely NEW result components, `grant` and `grant_trust`, alongside the rows above. Neither adds a value to any existing row, and neither enters the `ok` predicate: the formula above is unchanged, in both directions. A grant is a permission that becomes exercisable, never a validity property of the receipt — an `activated` grant does not make a receipt more valid, and a rejected grant does not make it less. Under v0.1 alone both components are absent.

### 11.2 Unknown fields and warnings

Unknown top-level payload fields (any key of `payload` not present in the top-level `properties` of the schema) are **allowed and signed** — they are inside the `JCS(payload)` signature input — but MUST be reported as warnings, never as errors: this is the forward-compatibility mechanism, distinguishing "unrecognized" from "invalid."

A conforming verifier MUST emit a warning for each of the following conditions when it applies, independent of and in addition to the layered result above:

- a signing key resolved with `status == "retired"` (§11 step 3);
- `license.drm == "drm-bound"` (§5.5);
- `survivability.end_of_life` is not one of the v0.1 seed vocabulary values (§5.6);
- an unrecognized top-level payload field, as above;
- a revocation record matching this receipt's `receipt_id` that failed authentication (§12.2) — ignored, not honored;
- a revocation record ignored specifically because `license.revocability == "none"` (§6.2, §12);
- a revocation record that matched, authenticated, but fell outside a `refund_window` (§12).

Offline verifiers with no `revocation_view` report `revocation: "unknown"` honestly rather than failing closed on the whole receipt — a receipt's evidentiary value degrades gracefully, the way a paper receipt's does.

### 11.3 Structural ceilings (normative, 2026-07-22 amendment)

A conforming verifier MUST bound the resource a hostile envelope, key manifest, or artifact manifest can force it to spend before any cryptographic or schema work runs, per the amendment procedure (attest-versioning.md §5). Two distinct classes of ceiling are named below, and they are worded differently on purpose:

- **Newly-introduced ceilings** (raw envelope size; issuer key manifest `keys[]` length; artifact manifest `artifacts[]` length) did not exist as a conformance requirement before this amendment. For these, a conforming verifier MUST accept inputs within the ceiling and MAY reject inputs beyond it as a resource-exhaustion guard. The reference implementations reject inputs beyond the ceiling; the conformance leaves in vector group [`29-limits`](vectors/29-limits/) pin that reference-profile behavior, not a universal MUST-reject.
- **Pre-existing, already-enforced bounds** (parsed-tree nesting depth; the revocation-view record count, §12.4) were already unconditionally enforced before this amendment. This section only formalizes them as conformance-surface requirements; it changes no behavior, and they keep their unconditional MUST-reject wording.

| Ceiling | Value | Checked | Rejects with | Class |
| --- | --- | --- | --- | --- |
| Raw envelope size | 1,048,576 bytes (2²⁰) | Step 0, on the undecoded bytes, before any parsing | `schema: "invalid"` | New — acceptance floor |
| Parsed envelope tree nesting depth | 256 | During strict parsing (§10, `canon.loads_strict`) — this is `canon.py`'s own pre-existing parser structural safety cap, not a second, smaller conformance ceiling layered on top of it | `schema: "not_checked"` — a parse failure, reported the same way any other malformed input is (no parsed object is ever produced) | Pre-existing — unconditional |
| Issuer key manifest `keys[]` length | 256 entries | Step 2, once the manifest is resolved from the trust store, before any key lookup | `schema: "invalid"` | New — acceptance floor |
| Artifact manifest `artifacts[]` length | 4,096 entries | Wherever an artifact manifest's own self-consistency is checked (§7.2) | Manifest treated as self-inconsistent | New — acceptance floor |

The nesting-depth ceiling is `canon.py`'s own long-standing parser structural safety cap (256), which has never rejected a receipt nesting a handful of levels deep, exercised at its exact boundary by [`docs/spec/vectors/21-canon-strict`](vectors/21-canon-strict/) leaves `b`/`c`/`d`: this amendment states that pre-existing bound normatively and introduces nothing smaller on top of it, so leaves `b-depth-255` and `c-depth-256` keep their original accepted expectations, per attest-versioning.md §2's additive-pattern rule. Vector group [`29-limits`](vectors/29-limits/) exercises the two newly-introduced ceilings that sit on `verify()`'s own wire surface (envelope size, key-manifest array length); the artifact-manifest ceiling is exercised directly against `verify_artifact_manifest`/`verifyArtifactManifest`, outside `verify()`'s own wire surface, so it carries no dedicated vector leaf — see §15.

A byte-length, key-manifest-array, or artifact-manifest-array ceiling failure is reported as `schema: "invalid"` (not the `"not_checked"` value most other step-0 failures use, §11.1): these are conformance-surface structural requirements on the envelope's/manifest's own shape, not parse-format failures in the RFC 8785 sense. The nesting-depth ceiling is the one exception to this: because it is enforced by the parser itself, an over-ceiling receipt never produces a parsed object at all, so it is reported the same way any other malformed input is, `schema: "not_checked"` — unchanged, pre-existing behavior.

## 12. Revocation records

A revocation record is a minimal, issuer-signed side-document:

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `receipt_id` | string, ULID | REQUIRED | The receipt this record refers to. |
| `status` | string | REQUIRED | Only the literal value `"revoked"` carries revocation meaning in v0.1; any other value is not a revocation statement. |
| `revoked_at` | string, ISO-8601 UTC timestamp | REQUIRED | The record's own signed time — this, never the verifier's local clock, is what window checks (§12.1) are evaluated against. |
| `signature` | object `{kid, sig}` | REQUIRED | Ed25519 over `JCS(record)` with this member removed. |

### 12.1 Record authentication

A verifier MUST treat a revocation record as **authenticated** only if all of the following hold, and MUST fail closed (treat as unauthenticated) on any malformed, wrong-typed, or missing input rather than raising:

1. its resolving key manifest is itself self-consistent (§7.1);
2. its `signature.kid` resolves to a key-entry in that manifest with `status == "active"` — a `compromised` or `retired` key's signature on a revocation record MUST be rejected, fail-closed (§7.3) — note the asymmetry introduced by the 2026-08-26 amendment: receipts have the v0.2 §19 anchored rescue, side-documents deliberately do not (v0.2 §19.5);
3. `revoked_at` falls within that key's `[valid_from, valid_to]` window;
4. the Ed25519 signature verifies over `JCS(record)` with `signature` removed, under the pinned ruleset (§10).

An unauthenticated record that nonetheless matches this receipt's `receipt_id` MUST be ignored with a warning (§11.2), never honored — this is what prevents a forged or replayed record from silently revoking a receipt (a fail-closed hardening of §7.3's key-compromise rule, extended to side-documents).

### 12.2 Revocation-by-class

What an authenticated, matching record (`status == "revoked"`) then *means* depends on `license.revocability`:

| `license.revocability` | Effect of an authenticated, matching record | Effect of none matching |
| --- | --- | --- |
| `none` | **Ignored.** The record is itself treated as invalid; `revocation: "invalid_revocation_ignored"`; a warning is emitted; the receipt's `ok` is unaffected. This is the irrevocability guarantee (§6.2) — without it, the revocation mechanism would falsify every `revocability: "none"` receipt's own claim. | `revocation` is `not_revoked_as_of:<T>` or `unknown` (§11.1). |
| `refund_window` | Honored **only if** the record's own `revoked_at` falls at or before `issued_at + revocation_window_days`: `revocation: "revoked"` (`ok` becomes `false`). A record that matches and authenticates but falls outside the window is ignored with a warning: `revocation: "invalid_revocation_ignored"`. | `revocation` is `not_revoked_as_of:<T>` or `unknown`. |
| `policy` | Honored as-is: `revocation: "revoked"` (`ok` becomes `false`). The verifier cannot itself evaluate the referenced policy terms, so a correctly signed record is trusted. | `revocation` is `not_revoked_as_of:<T>` or `unknown`. |

> **Amendment note (2026-07-23, v0.2 §17.3).** `status` (§12 above) gains a second literal value with revocation meaning: `"transferred"`. It carries meaning only under v0.2 §17.3 (Stage 3, backed by an authenticated, logged transfer record) — under v0.1 alone, `status: "transferred"` remains a non-statement exactly as any value other than `"revoked"` already is (§12 above).

### 12.3 Freshness anchor `T`

`T`, used in `not_revoked_as_of:<T>` (§11.1), MUST be computed as the maximum `revoked_at` across **all authenticated records** the verifier consulted in the supplied revocation view — regardless of which `receipt_id` they target. It describes how current the verifier's authenticated revocation feed is, not this one receipt's own history. Restricting the computation to authenticated records is a required security property: an unauthenticated record with a forged far-future `revoked_at` MUST NOT be able to inflate the reported freshness of the verifier's data. With zero authenticated records available, `T` has no trustworthy value and the result MUST be the bare literal `unknown`.

### 12.4 Revocation-view record ceiling (normed, 2026-07-22 amendment)

A conforming verifier MUST bound the number of records it will evaluate from an untrusted `revocation_view`: 10,000 records (the reference implementations' pre-existing `verify._MAX_REVOCATION_RECORDS` default, a 2026-07-13 hardening that predates this amendment; unchanged in value here). This is a pre-existing, already-enforced bound in the §11.3 sense — this amendment only states it normatively, it does not introduce a new ceiling or change behavior.

An oversized view (more than 10,000 records) is not evaluated — never truncated (a truncated subset could misreport a genuine revocation as absent), never raised as an exception. It fails closed for revocable receipts (`license.revocability` of `refund_window` or `policy`): an untrusted view too large to evaluate cannot rule out a revocation, so it MUST NOT certify the receipt, and the failure is recorded as an error (`ok` becomes `false`). For `license.revocability: "none"` (irrevocable), a revocation record can never affect `ok` regardless of the view's size, so an oversized view is a non-fatal warning instead. In both cases `revocation` is reported as `unknown`. This bound exists independent of §11.3's structural ceilings — it is a per-call record-count cap on trusted-input-shaped-as-untrusted data (§6's `revocation_view` parameter), not a wire-format or manifest-shape structural bound.

## 13. Delivery member and single-receipt sharing

A bare `.attest.json` envelope — payload, signatures, and an optional `delivery` block (§4.2) — is self-contained: when `delivery.salt` and/or `delivery.issuer_manifest` are populated, the envelope carries everything a verifier needs without any account page or bundle machinery, which is what makes an ordinary order-confirmation email a valid integration point.

The per-receipt sharing primitive is `attest disclose <receipt_id>`, which MUST emit exactly one receipt plus its manifests plus its salt — never an entire library at once, since forwarding a whole `.private.attest` (§14) would leak every purchase's binding secret simultaneously.

## 14. Export bundle formats

Export produces two files:

### 14.1 `<name>.attest` (shareable-safe)

MUST contain:

- `receipts/*.attest.json` — with `delivery.salt` stripped from every envelope (§4.2);
- `manifests/<issuer>.json` — key and artifact manifests;
- `legal/<sha256>.txt` — the license texts, mirror policies, and end-of-life commitment documents referenced by every included receipt, each verified against its hash binding (§5.5, §5.6) at export time. A receipt whose referenced terms can no longer be produced is a signature without a deal; the bundle MUST preserve the deal, not just the signature.
- `proofs/` — OPTIONAL (reserved for future receipt-existence proofs);
- a generated, human-readable `README.html` explaining what the bundle is, how to verify it even if the issuing store no longer exists, and which file MUST NOT be shared.

### 14.2 `<name>.private.attest` (secrets)

MUST contain `salts.json` (`receipt_id → salt`) and, if used, `keys/` (per-receipt buyer keypairs, §8.2). This file MUST be named and documented as private, and a conforming CLI implementation MUST warn whenever it is accessed.

## 15. Test vectors and conformance

The conformance vectors under [`docs/spec/vectors/`](vectors/) are the attest conformance suite. Since v0.2 it is no longer a v0.1-only corpus: groups `01`–`25`, `29-limits`, and `31-manifest-currency` (50 leaves), plus leaves `35i`, `37s`, and `41f` (each an `attest_version: "0.1"` negative control, added by the transfer amendment, v0.2 §17.8, the preservation-pledge amendment, v0.2 §18.6, and the anchored-cutoff amendment, v0.2 §19), define **v0.1** conformance, while `26-hybrid`, `27-valid-to-absent`, `28-transparency`, `30-mixed-keyset`, `32-anchor-v2`, `33-logged-revocation`, the rest of `35-transfer`, `36-transfer-chain`, `37-preservation-pledge` (every leaf but `s`), `38-redemption`, `39-witness-corroboration`, `40-witness-quorum`, and `41-compromise-cutoff` (every leaf but `f`) exercise v0.2 behaviour. `29-limits` (§11.3's structural ceilings) binds v0.1 as well as v0.2 — the two newly-introduced acceptance-floor ceilings it exercises (raw envelope size, issuer key manifest `keys[]` length) added by the amendment that introduced it (2026-07-22, attest-versioning.md §5); the pre-existing `21-canon-strict` leaves `b-depth-255`/`c-depth-256` are unaffected by it and keep their original `ok: true` expectations, since the nesting-depth ceiling §11.3 documents is `canon.py`'s own pre-existing 256 parser cap, not a new, smaller one. `31-manifest-currency` (§7.2/§7.3's manifest-currency amendment, rev 4) likewise binds v0.1 as well as v0.2 — artifact-manifest `manifest_version` and the newest-seen rule are not gated by `attest_version`. A v0.1-only verifier is REQUIRED to reject v0.2 envelopes, so it cannot reproduce the v0.2-only expectations and is measured against the 52-leaf v0.1 subset (the 50 above plus `35i`, `37s`, and `41f`); an implementation claiming v0.2 must reproduce all 158. **An implementation is attest-conformant if and only if it produces the expected `VerificationResult` — every component listed in a vector's `expected.json`, matched exactly — for every vector present under `docs/spec/vectors/`.**

| Vector | Directory | Exercises |
| --- | --- | --- |
| 1 | `01-valid-minimal` | Smallest schema-valid receipt verifies green (`ok: true`). |
| 2 | `02-valid-full` | Every optional field populated, still verifies green. |
| 3 | `03-tampered-payload` | One byte changed post-signature → `signature: "invalid"`. |
| 4 | `04-wrong-key` | Signed by a key absent from the issuer's manifest → key-not-found rejection. |
| 5 | `05-issuer-mismatch` | Valid signature from one domain's key over a payload claiming a different `issuer.id` → rejected at §11 step 2. |
| 6 | `06-duplicate-key-reject` | A payload with a genuinely duplicated JSON member (fed as raw bytes, since `json.load` cannot round-trip a true duplicate) → rejected at §11 step 0. |
| 7 | `07-unicode-canon` (`a-...`, `b-...`) | NFC/NFD string handling and the integer boundary of the attest-JCS profile: `|n| = 2^53 − 1` is accepted (`a-nfd-and-int-boundary-accepted`); `|n| ≥ 2^53` is rejected (`b-int-boundary-rejected`) — with `signature: "invalid"` and `schema: "not_checked"`, confirming the §9 canonicalization-time rejection, not a schema-validation rejection. |
| 8 | `08-sig-malleability` | A non-canonical `S` (`S ≥ L`) signature → `signature: "invalid"` under the pinned ruleset (§10). |
| 9 | `09-commitment` (`a-...`, `b-...`, `c-...`) | Buyer-binding normalization and scrypt commitment vectors: an ASCII email, a non-ASCII (Unicode) email, and an `issuer-account` identifier. |
| 10 | `10-unknown-field` | An extra signed top-level field → verifies green with a warning (§11.2). |
| 11 | `11-manifest-tamper` | A key manifest whose `status` was flipped after signing no longer self-verifies (§7.1); the receipt signed against the tampered manifest is rejected as if the key were compromised. |
| 12 | `12-retired-key-ok` | A receipt genuinely signed while its key was `active`, verified against a manifest where that key is now `retired` → still verifies green, with a mandatory warning (§7.3, §11.2). |
| 13 | `13-compromised-key` | A receipt genuinely signed by a key now marked `compromised` in the trust store, verified WITHOUT Stage-2 evidence → `signature: "invalid"` (§7.3): absent an anchored existence proof the kill is unconditional and independent of `issued_at`. The anchored-cutoff carve-out is exercised by group `41-compromise-cutoff` (v0.2 §16.11). |
| 14 | `14-rotation-continuity` | A manifest-version chain where v2 is signed by a key `active` in v1 (the trusted root) → the chain is continuous; `trust` stays at its provenance-derived value (§7.3, §11.1). |
| 14b | `14b-rotation-discontinuous` | A manifest-version chain where v2 is signed by a key never listed in v1 → discontinuous rotation; `trust: "unverified_rotation"`, overriding provenance, while `signature`/`schema`/`ok` are unaffected (`trust` is not one of `ok`'s components, §11.1). |
| 15 | `15-revoked-policy` | A `revocability: "policy"` receipt plus an authenticated, matching revocation record → honored as-is: `revocation: "revoked"`, `ok: false` (§12.2). |
| 16 | `16-revocation-against-none-ignored` | A `revocability: "none"` receipt plus an authenticated, matching revocation record → the record itself is invalid: `revocation: "invalid_revocation_ignored"`, a warning is emitted, `ok` is unaffected (§6.2, §12.2). |
| 17 | `17-binding-proven` (`a-...`, `b-...`) | Both buyer-binding proof paths (§8, §11 step 7): `a-salt-disclosure` recomputes the commitment from a disclosed `(identifier, identifier_type, salt)`; `b-pubkey-challenge` verifies an Ed25519 challenge-response transcript against `buyer.pubkey`. Both → `binding: "proven"`. |
| 18 | `18-drm-bound` | `license.drm == "drm-bound"` → verifies green with a mandatory warning (§5.5, §11.2). |

**Signature-malleability vector scope.** Vector 8 exercises non-canonical `S` specifically. Small-order and non-canonical `A`/`R` rejection (the other half of the pinned ruleset, §10) is enforced by the underlying libsodium verification primitive at verification time and is not separately vectorized in v0.1 — a conforming implementation MUST still reject such inputs (§10 is normative regardless of vector coverage), but conformance testing for that specific property currently relies on the pinned-library guarantee rather than a dedicated fixture.

## Appendix A — Threat model summary (non-normative)

> **Superseded (2026-07-18).** This summary is retained for historical continuity.
> The normative, maintained threat model is [`attest-threat-model.md`](attest-threat-model.md);
> privacy analysis lives in [`attest-privacy.md`](attest-privacy.md).

| Threat | Answer |
| --- | --- |
| Receipt forgery | Pinned-ruleset Ed25519 (§10) + issuer key manifests (§7.1). |
| Receipt tampering | Any byte change breaks the signature; attest-JCS duplicate-key rejection (§9) removes canonicalization ambiguity as an attack surface. |
| Cross-issuer impersonation | §11 step 2: the signing key is resolved only from `issuer.id`'s own manifest. |
| Issuer dies | Verification material is user-held (export bundle, §14) and, in a future registry layer, independently replicated. |
| Issuer key compromise | Fail-closed: `compromised` invalidates every past signature by that key (§7.3); per-period keys bound the blast radius. |
| Stolen bundle (bearer risk) | Per-receipt salts confine damage; `.private.attest` is separated from the shareable bundle (§14); the optional `buyer.pubkey` path is theft-resistant. |
| Bundle leaked via casual sharing | The shareable `.attest` contains no salts or keys; `attest disclose` is the per-receipt sharing unit (§13). |
| Buyer privacy | No plaintext PII is signed; the scrypt commitment (§8.1) is over a store-scoped identifier by default; disclosure is selective and per-receipt. |
| Malicious issuer | attest proves what an issuer signed, not that the issuer is honest — reputation is a client concern, out of this specification's scope. |
| Replay across works/stores | A receipt binds issuer, work, and series together; binding proofs (§8) are nonce-bound or per-receipt. |

## Appendix B — Registry layer and future work (non-normative, out of v0.1 conformance scope)

This appendix outlines, but v0.1 does not build, a registry layer: independent nodes replicating key/artifact manifests, license/policy texts, and revocation records, plus optional receipt-existence proofs anchored via Merkle roots. Nothing in this specification's conformance requirement (§15) depends on a registry node existing. A future revision of this specification will normatize the registry-node wire format if and when it ships.

## Revision log

- **2026-08-26 (rev 8)**: §7.3 rewritten — key compromise remains fail-closed but is bounded, for Stage-2-capable verification, by the anchored-cutoff rescue of attest-v0.2.md §19; a `compromised` marking is now absorbing for any verifier that holds the marking in its trusted manifest, manifest-version chain, or authenticated compromise-declaration evidence, while `retired` is not made absorbing; status regressions from `compromised` and keyset omissions break rotation continuity; §11 step 3, §6.2, §12.1 and the §15 vector-13 row scoped accordingly; the §7.3 blast-radius claim honestly restricted to forgery exposure. v0.1-only verifier behavior remains byte-for-byte unchanged only when the verifier holds neither a manifest-version chain nor authenticated compromise-declaration evidence; a verifier holding either now rejects a receipt whose signing key resolves to `compromised` under §7.3. — vectors: 41-compromise-cutoff

- **2026-08-26 (rev 7)**: Stale counts in §15 corrected, no normative change — the v0.1 subset is 52 leaves, not 51 (`37s` joined `35i` as a second `attest_version: "0.1"` negative control at rev 6 and was never added to this sentence), a v0.2 implementation reproduces all 158, not 130, and the v0.2 group list gains `37-preservation-pledge` and `38-redemption`, which shipped without being named here. The conformance definition itself — every component of every vector present under `docs/spec/vectors/` — is unchanged and was already count-independent. — vectors: none

- **2026-08-25 (rev 6)**: Amendment notes only, no rewrite of existing normative text — §5.4 gains a new row `work.publisher_id` (string, lowercase DNS domain, OPTIONAL under v0.1, schema-conditionally REQUIRED on a v0.2 receipt carrying a preservation pledge, [`attest-v0.2.md`](attest-v0.2.md) §18.6). §5.5 gains a new row `preservation_pledge` (object, OPTIONAL, specified by v0.2 §18.2), which under v0.1 alone carries no meaning. §5.6's `end_of_life` row gains a note that v0.2 §18 registers one further value, `sunset-grant`, treated by a v0.1-only verifier exactly like any other unrecognized value. §7.1 gains a note that v0.2 §18.1 resolves a manifest of the identical shape for the rights-holder role, reusing the existing provenance and rotation machinery verbatim. §11.1 gains a note: v0.2 §18.5 adds two entirely new result components, `grant` and `grant_trust`, which add no value to any existing row and leave the `ok` formula unchanged in both directions. — vectors: 37-preservation-pledge
- **2026-07-23 (rev 5)**: Amendment notes only, no rewrite of existing normative text — §2 gains a note that the future transfer profile named in the Resale/transfer exclusion is now specified ([`attest-v0.2.md`](attest-v0.2.md) §17, Stage 3); the MUST NOT above it stands unchanged under v0.1 alone. §5.5 gains a new row `not_transferable_before` (string, ISO-8601 UTC, OPTIONAL, enforced at transfer evaluation, v0.2 §17.7); the `transferable` row's "Reserved; see §2" note gains "assigned meaning by v0.2 §17". §11.1 gains a note: v0.2 §17.3 adds `"transferred"` as a reachable `revocation` value, capping `ok` the same way `"revoked"` does, only under Stage-3-capable verification. §12.2 gains a note: `status: "transferred"` carries meaning only under v0.2 §17.3, remaining a non-statement under v0.1 alone. — vectors: 35-transfer
- **2026-07-22 (rev 4)**: §7.2 amended — artifact manifests gain `manifest_version` (integer ≥ 1, monotonically increasing per issuer/series), REQUIRED on manifests produced after this revision; absent on a legacy manifest, which stays valid with warning `artifact_manifest_unversioned` (eternal verifiability, attest-versioning.md §3); manifests MUST authenticate before currency evaluation, otherwise they are ignored with `artifact_manifest_unauthenticated`; issuer mismatches are ignored with `artifact_manifest_issuer_mismatch`. §7.3 amended — currency state is scoped per (issuer, `artifact_series`) pair; currency comparison applies only where both manifests carry `manifest_version`, and regression reports `trust: "unverified_rotation"` (no new `trust` value). §15 leaf counts updated for the five-leaf `31-manifest-currency` vector group. — vectors: 31-manifest-currency
- **2026-07-22 (rev 3)**: §11.3 added — normative structural ceilings: three newly-introduced acceptance floors (raw envelope size, issuer manifest `keys[]` length, artifact manifest `artifacts[]` length; the last of these carries no dedicated vector) that a verifier MUST accept within and MAY reject beyond, and the pre-existing parsed-tree nesting-depth cap (256, `canon.py`'s own parser bound — not a new, smaller ceiling) and revocation-view record cap (10,000, §12.4) formalized with their unconditional wording unchanged; §15 leaf counts updated for the new `29-limits` vector group (envelope size, key-manifest length). — vectors: 29-limits
- **2026-07-22 (rev 2)**: §5.1 `receipt_id` prose regex corrected to `^[0-7][0-9A-HJKMNP-TV-Z]{25}$`, matching the schema's pre-existing pattern (editorial drift fix, no behavior change). — vectors: none
- **2026-07-22 (rev 1)**: revision log introduced by attest-versioning.md §5; no normative change. — vectors: none

## References

- RFC 2119 / RFC 8174 — normative key words.
- RFC 8785 — JSON Canonicalization Scheme (JCS); §9 states this specification's deviation-by-restriction from it.
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA); §10 states the pinned verification ruleset.
- RFC 4648 §5 — base64url encoding.
- ULID specification — `receipt_id` / `supersedes` format.
- [`docs/spec/schema/attest-receipt.schema.json`](schema/attest-receipt.schema.json) — normative JSON Schema for `payload`.
- [`docs/spec/vectors/`](vectors/) — normative conformance vectors (§15).
