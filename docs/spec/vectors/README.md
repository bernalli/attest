# attest conformance vectors

This directory holds the attest conformance suite: fixed, language-neutral test cases against which any implementation can be checked. Groups `01`–`25`, `29-limits`, `31-manifest-currency`, `42-publisher-claim`, `44-manifest-duplicate-kid`, `45-revocation-anchor-status`, and `46-manifest-unauthenticated` (60 leaves — corrected 2026-07-23, rev 5: `31-manifest-currency` carries 5 leaves, not the 3 an earlier count stated; groups 44 and 45 added 2026-08-26 by the V-L guards, v0.1 rev 10; group 42 added 2026-08-26 by the publisher-claim floor, v0.1 rev 11), plus leaves `35i` (2026-07-23, rev 6 — see below) and `37s` (2026-08-26, rev 8), are **v0.1** conformance, against [`docs/spec/attest-v0.1.md`](../attest-v0.1.md) — `29-limits` was added by the G1 normative-ceilings amendment (v0.1 rev 3 / v0.2 rev 2, 2026-07-22, attest-versioning.md §5), and `31-manifest-currency` by the G2/G3 manifest-currency amendment (v0.1 rev 4, 2026-07-22, v0.1 §7.2/§7.3), both of which bind v0.1 as well as v0.2 — `42-publisher-claim` binds both the same way, since v0.1 §11.2's warning is payload-deterministic and independent of `attest_version`. `26-hybrid`, `27-valid-to-absent`, `28-transparency`, `30-mixed-keyset`, `32-anchor-v2`, `33-logged-revocation`, `35-transfer` (leaves `a`–`h`, `j`, `k`), `36-transfer-chain`, `37-preservation-pledge` (every leaf but `s`), `38-redemption`, `39-witness-corroboration`, `40-witness-quorum`, `41-compromise-cutoff` (every leaf but `f`), and `43-publisher-authority` cover **v0.2**, against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md). Leaves `35i`, `37s` and `41f` are the exceptions inside their own groups: `35i` and `37s` are `attest_version: "0.1"` by construction — the negative control for a v0.2-only schema conditional (§17.8's holder binding, §18.6's pledge conditional), which a v0.1 receipt is untouched by — while `41f` ships no Stage-2 material at all, so the anchored-cutoff rescue (§19) is out of reach and the unconditional v0.1 §7.3 rejection is what a conformant verifier must produce; all three belong to the v0.1 subset even though their sibling leaves are v0.2. A v0.1-only verifier must reject v0.2 envelopes and is therefore measured against the v0.1 subset (63 leaves — the 60 above plus `35i`, `37s` and `41f`), not all 217. Each vector is a leaf directory (identified by containing `expected.json`) holding the raw inputs to feed the verification algorithm and the exact `VerificationResult` a conformant verifier must produce (group 36 leaves instead hold the inputs to `audit_chain` and the exact `ChainAuditResult` it must produce, group 40 leaves the inputs to the activation witness quorum and its `{valid, witness_time, counting_control_groups}` result, and group 38 leaves the inputs to the redemption check and its `{verified}` result — see below).

**Normative conformance requirement**: an implementation is attest-conformant iff it produces every vector's expected result. There is no partial conformance — any single mismatch is a conformance failure.

To run this corpus against YOUR implementation (any language) see [`docs/conformance.md`](../../conformance.md) — `tools/conformance_runner.py` replays every leaf through an adapter command you supply and produces the pass/fail conformance report; the v0.1/v0.2 subset rules above are exactly what it implements.

## Vector format

Each leaf directory contains:

- `payload.json` — the receipt payload, for readability (not itself fed to `verify()`; it is embedded inside `envelope.json`).
- `envelope.json` — the full envelope (`payload` + `signatures` + optional `delivery`), or `envelope.raw.json` (vector 06 only) for a case whose raw bytes intentionally cannot round-trip through a parsed object.
- `manifests.json` — the trust material: `{"manifests": {...}, "provenance": {...}, "chains": {...}, "artifact_manifests": {...}, "artifact_manifest_chains": {...}}`, fed straight into the verifier's trust store. The last two (group 31 only) are nested by issuer, then `work.artifact_series`.
- `expected.json` — the spec-intended `VerificationResult`: `signature`, `schema`, `trust`, `revocation`, `binding`, `ok`, plus `errors`/`errors_contains` and `warnings`/`warnings_contains`.
- optional `disclosure.json` — a buyer-binding disclosure, salt path (`identifier`, `identifier_type`, `salt_b64u`) or challenge path (`nonce_b64u`, `sig_b64u`), for vectors that check §6 step 7.
- optional `revocation.json` — a single issuer-signed revocation record, fed to the verifier as its revocation view, for vectors that check §6 step 6.
- optional `manifest_pristine.json` — only for vector 11: the untampered, self-consistent manifest, alongside the tampered one actually used for verification.
- optional `canonical.json` — the exact canonical serialization bytes of the leaf's payload. A conforming implementation MUST reproduce these bytes exactly when canonicalizing the parsed payload. Present on vectors 21f/21g (supplementary-plane encodings) and 24.
- optional `transparency.json` / `log-keys.json` / `anchor-policy.json` — groups 28, 32, 39, and 41: the untrusted transparency/corroboration evidence bundle, the verifier's pinned transparency-log signing identities, and its pinned Bitcoin block headers + CRQC horizon, fed to the verifier as `transparency`/`log_keys`/`anchor_policy`. Only those groups' `expected.json` carry the corresponding `transparency`/`corroboration`/`manifest_freshness` result fields — groups 28 and 32 throughout, group 39 for `transparency`/`corroboration`, and group 41 on the Stage-2 leaves that ship receipt-side evidence of their own.
- optional `revocation-evidence.json` — group 33 only (G5, TM-47, v0.2 §8/§15 amendment): the untrusted transparency evidence bundle for the SPECIFIC `refund_window` revocation record in `revocation.json`, fed to the verifier as `revocation_evidence` and reusing group 33's own `log-keys.json`/`anchor-policy.json`. A DIFFERENT evidence channel from `transparency.json` — group 33's `expected.json` does NOT carry `transparency`/`corroboration`/`manifest_freshness`.
- optional `transfer-view.json` — group 35 only (v0.2 §17 Stage 3): a JSON ARRAY of untrusted claims `[{"record": <a transfer record>, "evidence": <the same §10.2 evidence-bundle shape>}]`, fed to the verifier as `transfer_view` and reusing group 35's own `log-keys.json`/`anchor-policy.json`. A DIFFERENT evidence channel from `transparency.json`/`revocation-evidence.json` — group 35's `expected.json` likewise does NOT carry `transparency`/`corroboration`/`manifest_freshness`.
- optional `witness-policy.json` — group 39 only (P1.1b, v0.2 §11.4): the TRUSTED `attest-witness-policy-v1` DOCUMENT, fed to the verifier as `witness_policy`/`witnessPolicy`. It rides the same rail as `log-keys.json`/`anchor-policy.json` — verifier configuration, never evidence — which is why it is its own file and never appears nested inside `transparency.json`. The untrusted `transparency.json` names the epoch it claims (`witness_policy_epoch`); this document says whom that epoch pins. Shipped as the document, not as a parsed object, so a conforming implementation exercises its OWN policy parser. Group 39's `expected.json` carries `transparency`/`corroboration`, like group 28's.
- `witness-quorum.json` — group 40 only (P1.1b, v0.2 §11.4): present INSTEAD of `payload.json`/`envelope.json`/`manifests.json` — this group has no receipt in it at all. `{"expected_origin", "conflict_domain", "epoch_id", "checkpoint", "anchor_evidence"}`, of which the first two are TRUSTED call configuration (malformed values raise) and the last three are untrusted and may only degrade the verdict. A leaf containing this file is routed to `evaluate_activation_witness_quorum`/`evaluateActivationWitnessQuorum`/`runWitnessQuorum` instead of `verify()` or `audit_chain`; the two trusted POLICIES sit beside it in `witness-policy.json` and `anchor-policy.json`. Its `expected.json` shape is `{"valid": bool, "witness_time": int | null, "counting_control_groups": [...]}`, all three matched exactly — this surface has no `errors`/`warnings`, so there is nothing here to match loosely.
- optional `grant-view.json` — group 37 only (v0.2 §18, Stage 4): the untrusted evidence object `{grant[, later_grants][, declarations][, anchor]}`, fed to the verifier as `grant_view`/`grantView`. Its PRESENCE is the capability gate — a leaf shipping none evaluates nothing at all and the two new result members stay `not_checked`, which is what leaf `37s` relies on. `anchor` is ONE §11 evidence bundle, never a list: §18.4's maximum reduction is over the proofs inside it, and a list would be a third attacker-supplied array with no ceiling. Group 37's `expected.json` carries `grant` and `grant_trust` — the only group where either appears — and carries none of Stage 2's three.
- optional `authority-view.json` — group 43 only (v0.2 §20, 2026-08-26 amendment): the untrusted evidence object `{authorizations[, current_authorization_version]}`, fed to the verifier as `authority_view`/`authorityView`. Its PRESENCE is the capability gate for publisher-authorization evaluation. Group 43's `expected.json` carries `publisher_authority` and `publisher_authority_trust` — the only group where either appears — and carries none of Stage 2's three.
- `redemption.json` — group 38 only (v0.2 §18.7, the audience-bound redemption proof): present INSTEAD of `payload.json`/`envelope.json`/`manifests.json` — like group 40, this group has no receipt in it at all. `{"receipt_id", "audience", "nonce_b64u", "sig_b64u", "holder_pubkey_b64u"}`. A leaf containing this file is routed to the redemption check instead of `verify()`; its `expected.json` shape is `{"verified": bool}`, matched exactly. There is deliberately no `errors`/`warnings` here: a gate that fronts the delivery of content must not have an error path an attacker can tell apart from a refusal.
- optional `compromise-view.json` — group 41 only (v0.1 rev 8 §7.3 / v0.2 rev 9 §19, the anchored-cutoff rescue and the monotone `compromised` floor): a JSON ARRAY of untrusted compromise-declaration claims `[{"manifest": <a v0.1 §7.1 key manifest>, "evidence": <the same §10.2 evidence-bundle shape, for that manifest's own `key-manifest` log entry>}]`, fed to the verifier as `compromise_view`/`compromiseView` and reusing group 41's own `log-keys.json`/`anchor-policy.json`. It rides the caller's configuration rail, never the receipt presenter's, and nothing in it is trusted by arrival: every claim re-authenticates against the leaf's own `manifests.json` and pinned material (§19.3). Group 41's Stage-2 leaves DO carry `transparency`/`corroboration`/`manifest_freshness` wherever they ship receipt-side evidence — §19 decides from the receipt's own anchored standing, so that standing belongs in the expected result.
- `chain.json` — group 36 only (v0.2 §17.5, chain-of-title audit): present INSTEAD of `payload.json`/`envelope.json`, `{"payloads": [...], "transfer_view": [...], "revocation_view": [...]}` (`payloads` are receipt PAYLOAD dicts, not envelopes). A leaf containing this file is routed to `audit_chain`/`auditChain`/`runChainAudit` instead of `verify()`; its `expected.json` shape is `{"chain_valid": bool, "link_status": [...], "errors_contains": [...], "warnings": [...]}`, matched as: `chain_valid` exact against the result's `valid`, `link_status` exact list, `errors_contains` substring, `warnings` exact list.

## Vector index

### 1–11: format and crypto

| # | Name | Checks |
| --- | --- | --- |
| 01 | `valid-minimal` | The happy path: a minimal, schema-valid, correctly-signed receipt verifies clean. |
| 02 | `valid-full` | Every optional payload field populated at once (edition, artifacts, refund-window revocability, DRM-bound, jurisdiction flags, escrow end-of-life, supersedes, buyer pubkey) still verifies clean. |
| 03 | `tampered-payload` | A single byte flipped in a signed field, post-signing — signature must fail. |
| 04 | `wrong-key` | Signed by a key whose `kid` domain matches the issuer but is absent from the trusted manifest — rejected at the key-resolution step, not the domain-match step. |
| 05 | `issuer-mismatch` | A genuinely valid signature by a different domain's key over a payload claiming a different `issuer.id` — must never validate (kills cross-issuer impersonation). |
| 06 | `duplicate-key-reject` | A raw envelope with a genuinely duplicated JSON object member — rejected at strict parsing (RFC 8785 forbids duplicate members), before any issuer/key resolution. |
| 07 | `unicode-canon` | (a) NFD-decomposed Unicode in a payload string, plus an integer at the exact I-JSON safe-range boundary, both accepted and signed/verified byte-exact (no silent NFC normalization outside the buyer-commitment path). (b) The same integer field bumped one past the safe boundary — rejected, because canonicalization (required before any signature check) fails first. |
| 08 | `sig-malleability` | A signature's `S` component re-encoded as `S + L` (same scalar mod the curve order) — the pinned Ed25519 ruleset must reject the non-canonical encoding (SUF-CMA). |
| 09 | `commitment` | Buyer-binding commitment recomputation across three identifier shapes: (a) plain ASCII email, (b) non-ASCII/Unicode email, (c) issuer-account identifier with NFD input — normalization must be applied identically at issuance and at verification. |
| 10 | `unknown-field` | An unrecognized top-level payload field is signed and carried through verification successfully, with a non-fatal warning (forward-compatibility). |
| 11 | `manifest-tamper` | A key manifest's `status` flipped from `active` to `compromised` after the manifest itself was signed — the manifest no longer self-verifies, and a receipt genuinely signed while the key was active is now rejected because the trust store's copy says `compromised`. |

### 12–18: lifecycle and policy

| # | Name | Checks |
| --- | --- | --- |
| 12 | `retired-key-ok` | A receipt signed while a key was active still verifies once that key is later marked `retired` in the trust-store manifest — with a warning, not a rejection. |
| 13 | `compromised-key` | A receipt signed by a key now marked `compromised` in an otherwise self-consistent manifest is rejected unconditionally, regardless of `issued_at`. |
| 14 | `rotation-continuity` | A two-manifest chain (v1 → v2) where v2 is signed by v1's own active key, introducing a new active key and retiring the old one — the standard rotation handoff. A receipt signed by the new key resolves against the current manifest and keeps full (TLS-derived) trust. |
| 14b | `rotation-discontinuous` | Same v1 root, but the candidate v2 is signed by a key never listed in v1 at all — the chain is discontinuous, so trust is forced down to `unverified_rotation` even though the receipt's own signature verifies cleanly against the current manifest. |
| 15 | `revoked-policy` | A `revocability: "policy"` receipt plus an authenticated, matching revocation record is honored as-is: `revocation: "revoked"`, `ok: false`. |
| 16 | `revocation-against-none-ignored` | The irrevocability guarantee: a `revocability: "none"` receipt plus an authenticated, matching revocation record ignores the record (`invalid_revocation_ignored`) and stays `ok: true` — a revocation feed can never override an irrevocable license. |
| 17 | `binding-proven` | Both buyer-binding proof paths: (a) salt disclosure recomputing the commitment, (b) pubkey challenge-response — a signed transcript proving key possession without revealing an identifier. |
| 18 | `drm-bound` | `license.drm == "drm-bound"` verifies green but always carries a mandatory warning — a receipt never claims to remove DRM. |

### 19–25: cross-implementation review parity

| # | Name | Checks |
| --- | --- | --- |
| 19a | `rotation-substituted-key/a-substituted-candidate-key` | A candidate v2 manifest that is itself self-consistent (signed by a substituted key never present in the trusted v1 root) — the discontinuous chain is unmasked against the root, forcing `trust: "unverified_rotation"` even though the receipt's own signature verifies. |
| 19b | `rotation-substituted-key/b-chain-tail-not-manifest-used` | A genuinely continuous v1→v2 chain exists, but the receipt is verified against v1 (the manifest actually in trust), not the chain's tail — trust downgrades the same way, pinning that continuity is judged against the manifest in use, not any reachable chain. |
| 20a | `sig-canonicity/a-s-equals-l` | Signature `S` set to exactly `L` (the curve order) — the smallest non-canonical scalar boundary case beyond vector 08's `S + L` — rejected. |
| 20b | `sig-canonicity/b-small-order-pubkey` | Signer pubkey (`A`) is a small-order point — rejected (zip215:false / libsodium-equivalent ruleset). |
| 20c | `sig-canonicity/c-small-order-r` | Signature's `R` component is a small-order point, `S` otherwise genuine — rejected. |
| 21a | `canon-strict/a-bom` | A UTF-8 byte-order mark prepended to the raw envelope bytes — rejected at strict parsing. |
| 21b | `canon-strict/b-depth-255` | Whole-text nesting depth exactly 255 — accepted (unknown-field tolerance, vector 10) against canon.py's structural cap (`canon.MAX_DEPTH`, 256), one short of the boundary. |
| 21c | `canon-strict/c-depth-256` | Whole-text nesting depth exactly 256, canon.py's own structural boundary — still accepted; the boundary is strict `>`. |
| 21d | `canon-strict/d-depth-257` | Whole-text nesting depth 257, one past canon.py's boundary — rejected at strict parsing (maximum nesting depth exceeded). |
| 21e | `canon-strict/e-lone-surrogate` | A lone UTF-16 surrogate injected via `\uXXXX` escape — rejected at strict parsing (a payload carrying one can never be signed in the first place). |
| 21f | `canon-strict/f-supplementary-raw` | A supplementary-plane character (outside the BMP) encoded as raw UTF-8 bytes — verifies clean; carries `canonical.json` for the payload's exact canonical bytes. |
| 21g | `canon-strict/g-supplementary-escaped` | The same payload and signature as 21f, but the envelope bytes use `𝄞`-style surrogate-pair escaping instead of raw UTF-8 — verifies clean with the identical result, proving canonicalization is transport-escaping-independent; carries the same `canonical.json`. |
| 22a | `b64u-decoder-parity/a-padding-accepted` | A signature's base64url encoding with explicit `=` padding added — accepted (both reference decoders are deliberately permissive). |
| 22b | `b64u-decoder-parity/b-standard-alphabet-accepted` | The same signature re-encoded with the standard `+/` alphabet instead of urlsafe `-_` — accepted. |
| 22c | `b64u-decoder-parity/c-trailing-bits-accepted` | The same signature with non-zero discarded trailing bits in its final base64 character — accepted. |
| 23a | `revocation-refund-window/a-inside-window` | A `revocability: "refund_window"` receipt with an authenticated revocation record whose `revoked_at` falls inside the window — effective: `revocation: "revoked"`, `ok: false`. |
| 23b | `revocation-refund-window/b-after-window` | The same receipt with an authenticated revocation record whose `revoked_at` falls after the window closes — ignored: `revocation: "invalid_revocation_ignored"`, a warning is emitted, `ok` stays `true`. |
| 24 | `canonical-roundtrip` | A plain valid receipt that additionally commits its payload's exact canonical bytes via `canonical.json` — a Python→TS→Python round-trip must reproduce them byte-for-byte. |
| 25a | `schema-parity/a-edition-nonstring` | `work.edition` set to a non-string (an int) before signing, so the signature genuinely covers the invalid payload — signature valid, `schema: "invalid"` (pins schema drift where an implementation's runtime type accepts non-strings). |
| 25b | `schema-parity/b-ulid-first-char` | `receipt_id`'s first character set to `'8'`, past the ULID timestamp-prefix range the pinned regex allows (`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`) — signature valid, `schema: "invalid"`. |

### 26: hybrid Ed25519+ML-DSA-65 signatures (attest v0.2)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md), the additive delta specification for the `attest_version: "0.2"` hybrid signature profile.

| Leaf | Name | Checks |
| --- | --- | --- |
| 26a | `a-valid-hybrid` | The happy path: both the Ed25519 and ML-DSA-65 legs verify against a single hybrid key-manifest entry — `ok: true`. |
| 26b | `b-ed25519-leg-tampered` | The Ed25519 leg's signature bytes flipped post-signing — `signature: "invalid"`. |
| 26c | `c-mldsa-leg-tampered` | The ML-DSA-65 leg's signature bytes flipped post-signing — `signature: "invalid"`. |
| 26d | `d-mldsa-leg-missing` | The ML-DSA-65 signature entry stripped, leaving one signature — rejected outright (`signatures` must have length exactly 2), never treated as a v0.1-shaped fallback. |
| 26e | `e-duplicate-ed25519-alg` | Both signature entries carry `alg: "Ed25519"` instead of the fixed `[Ed25519, ML-DSA-65]` order — rejected. |
| 26f | `f-kid-mismatch-between-legs` | The two signature entries carry different `kid` values — rejected (the hybrid pair must be one signer). |
| 26g | `g-key-entry-not-hybrid` | The resolved manifest key entry has no `pub_ml_dsa_65` — rejected, nothing to verify the PQ leg against. |
| 26h | `h-manifest-downgraded-continuity` | A rotation candidate manifest signed by a hybrid key but whose `manifest_signature` was downgraded to Ed25519-only — the receipt's own signature still verifies, but the manifest fails its own hybrid AND-check, so the rotation chain is discontinuous: `trust: "unverified_rotation"`. |

### 27: `valid_to` omitted (attest v0.2)

| Leaf | Name | Checks |
| --- | --- | --- |
| 27 | `valid-to-absent` | A key manifest entry with the `valid_to` field omitted entirely (not `null`) still self-verifies and resolves an open-ended key — the JSON-shape divergence (absent vs. explicit `null`) must not affect verification. |

### 28: transparency/corroboration layer (attest v0.2, design doc "transparency/corroboration layer")

The cross-core corpus for `verify()`'s Stage 2 `transparency`/`corroboration`/`manifest_freshness` result components, exercising `tlog`/`anchor`/`transparency` end to end. Every leaf's `expected.json` additionally carries `transparency`, `corroboration`, and `manifest_freshness` — the ONLY group where these three appear; every other leaf's absence of these files/fields means `verify()` saw `transparency=None`/`log_keys=None`/`anchor_policy=None` (zero behavior change, Task-8-and-earlier defaults). New per-leaf input files (loaded when present, absent everywhere else): `transparency.json` (the untrusted evidence bundle), `log-keys.json` (the verifier's pinned transparency-log signing identities), `anchor-policy.json` (pinned Bitcoin block headers + optional CRQC horizon).

| Leaf | Name | Checks |
| --- | --- | --- |
| 28a | `a-logged-trust-unchanged` | A genuinely logged receipt (hybrid-signed checkpoint, valid inclusion proof) with TOFU/bundle provenance — `transparency: "logged"` and `corroboration: "logged"` MUST leave `trust: "unauthenticated_tofu"` unchanged; log evidence never upgrades trust. |
| 28b | `b-wrong-root` | A validly hybrid-signed checkpoint, but for a Merkle root that does not actually contain this entry — inclusion proof fails, `transparency: "not_checked"`. |
| 28c | `c-ed-only-checkpoint` | A checkpoint carrying only the Ed25519 signature line, no ML-DSA-65 leg — checkpoint auth is hybrid, MANDATORY (design doc), so a genuine Ed25519-only signature grants no standing at all. |
| 28d | `d-origin-mismatch-log-key` | A genuinely hybrid-signed checkpoint by the pinned log key material, but claiming a different `origin` than the one pinned in `log-keys.json` — no candidate verifies. |
| 28e | `e-consistency-ok` | A two-leaf tree with a verifying prior checkpoint (smaller tree) and a genuine consistency proof against the current checkpoint — still just `"logged"` (consistency rules out equivocation, it does not upgrade standing on its own). |
| 28f | `f-equivocation-detected` | A validly hybrid-signed prior checkpoint claiming the SAME tree size as the current checkpoint but a DIFFERENT root — proof the log signed two incompatible histories: `transparency: "equivocation_detected"` (a hard verdict, not fail-safe degradation). |
| 28g | `g-entry-hash-mismatch` | The evidence's `entry` disagrees with the hash `verify()` independently computes from the actual receipt — `transparency_entry_mismatch`, regardless of an otherwise-valid checkpoint/proof. |
| 28h | `h-rotation-chain-omitted` | A self-consistent `manifest_version: 2` issuer manifest, logged as a key-manifest claim, but the trust store holds no rotation chain for the issuer at all — `corroboration` is downgraded to `"none"` with `corroboration_requires_rotation_chain`, even though `transparency` (`"logged"`) and `manifest_freshness` (`"verified_as_of:1"`) are unaffected. |
| 28i | `i-compromised-key-fail-closed` | A receipt rejected outright for a compromised signing key (`signature: "invalid"`, `ok: false`) still reports `transparency: "logged"`/`corroboration: "logged"` for its own genuinely-logged evidence — proving corroboration can never rescue an otherwise-invalid receipt (design fix 6; transparency is resolved before the pass/fail verdict). |
| 28j | `j-ots-anchor` | A PQ-surviving `ots` proof replaying from `SHA-256(checkpoint.note_bytes)` to a pinned Bitcoin block header — `transparency` upgrades to `anchored_before:2023-11-14T22:13:20Z` (header time `1700000000`, `transparency.py`'s own documented KAT). No `anchor_profile` declared → legacy `"note-v1"` commitment (§11.1.1, G4, 2026-07-22), so `warnings` now also carries `anchor_note_only`. |
| 28k | `k-rfc3161-only` | An `rfc3161`-only anchor proof — opaque classical corroboration only, never sets `pq_surviving`, so `transparency` stays `"logged"` (no PQ/post-horizon standing); the verbatim RFC 3161 warning is asserted. **Adapted**: no leaf here sets `anchor-policy.json`'s `crqc_horizon` — an rfc3161-only proof never reaches `anchor.passes_horizon` regardless of horizon configuration, so a horizon value would add configuration, not test coverage. |
| 28l | `l-payload-only-precommit` | The evidence entry's `core_sha256` is hashed over the payload ALONE (no domain separation, no signature commitment) — exactly the "pre-sign, log now, sign later" attack `receipt_core_hash`'s domain separation defeats. Same observable outcome as 28g (`transparency_entry_mismatch`), different attacker narrative: this is specifically the hash an attacker could compute before the receipt was ever signed. |
| 28m | `m-hybrid-revocation-and-rule` | **Adapted** from the original "post-horizon ed-only revocation" framing: `verify.py`'s revocation classification has no `crqc_horizon`-shaped parameter at all (revocation and the transparency/anchor horizon cap are separate subsystems), so that framing cannot be expressed through any `verify()` input. Pins the mechanism that would have to exist for it to hold instead: an Ed25519-only-signed revocation record against a HYBRID (`pub_ml_dsa_65`-carrying) issuer key is unconditionally rejected/ignored (the Task 6/8 sibling-hybrid AND rule, fail-closed) — `revocation: "unknown"`, the record ignored with a warning, `ok: true`. |
| 28n | `n-unknown-entry-type` | An evidence `entry` whose `type` the log's closed schema doesn't recognize — the claim is unresolvable before any checkpoint/proof is even consulted (`transparency_claim_unresolvable`); the receipt itself verifies untouched (`ok: true`). |

### 29: normative ceilings (G1, v0.1 rev 3 / v0.2 rev 2 amendment, attest-versioning.md §5)

Checked against v0.1 §11.3/§15 and v0.2 §6.2/§16 (the same amendment binds both — a v0.1-only verifier must enforce these ceilings too). Both leaves are a genuinely, cleanly signed envelope, rejected purely for crossing one of the newly-introduced acceptance-floor ceilings — never for a schema-shape or signature problem otherwise. Three ceilings are genuinely new under this amendment (a verifier MUST accept within them, MAY reject beyond, v0.1 §11.3): raw envelope size, issuer key manifest `keys[]` length, and artifact manifest `artifacts[]` length. Only the first two sit on `verify()`'s own wire surface, so only those two carry dedicated `29-limits` vector leaves; the artifact-manifest ceiling is exercised directly against `verify_artifact_manifest`/`verifyArtifactManifest` instead (v0.1 §11.3/§15) and carries no vector leaf of its own. The amendment's other ceilings (nesting depth, revocation-view record count, and v0.2's Stage 2 evidence bounds, §16.1) norm pre-existing, already-enforced behavior and are likewise not exercised by dedicated `29-limits` leaves — the nesting-depth boundary is exercised instead by `21-canon-strict` leaves `b`/`c`/`d`, unaffected by this amendment (see above).

| Leaf | Name | Checks |
| --- | --- | --- |
| 29a | `limits/a-envelope-oversize` | The raw, undecoded envelope exceeds `MAX_ENVELOPE_BYTES` (1,048,576) — rejected at the parse boundary, before any parsing work: `schema: "invalid"`. |
| 29c | `limits/c-manifest-array-overflow` | The issuer's key manifest `keys[]` array exceeds `MAX_MANIFEST_KEYS` (256) — rejected right after the manifest is resolved from the trust store, before any specific key lookup: `schema: "invalid"`. |

### 30: mixed-keyset prohibition (G6, v0.2 rev 3 amendment, v0.2 §2.3/§13)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §2.3/§13 — an issuer that declares the hybrid profile MUST NOT hold an Ed25519-only key in state `active`; the migration ceremony is a single manifest step (the same `manifest_version` bump that introduces the hybrid key retires every Ed25519-only key). Motivated by `attack_mixed_keyset_hijack` (the formal threat-model exhibit).

| Leaf | Name | Checks |
| --- | --- | --- |
| 30a | `mixed-keyset/a-active-ed-sibling-warn` | The resolved issuer manifest declares the hybrid suite AND still holds an Ed25519-only key in state `active` — the receipt verifies clean otherwise, but carries the `mixed_keyset_active_ed_only_sibling` warning. The warning is the entire verifier-side contract: no result field caps a "hybrid strength" classification, since none exists. |
| 30b | `mixed-keyset/b-migrated-clean` | Same manifest shape, but the Ed25519-only sibling is `retired` (the completed migration ceremony) — no mixed-keyset condition, no warning. |

### 31: manifest currency (G2/G3, v0.1 rev 4 amendment, v0.1 §7.2/§7.3)

Checked against [`docs/spec/attest-v0.1.md`](../attest-v0.1.md) §7.2/§7.3 — artifact manifests gain `manifest_version` (REQUIRED on manifests produced after this revision; absent on a legacy manifest, which stays valid with a warning, eternal verifiability per attest-versioning.md §3); every artifact manifest is authenticated before currency comparison; and a verifier holding persistent trust state MUST NOT accept, for the same (issuer, `artifact_series`) pair, an artifact manifest with `manifest_version` lower than the newest already accepted. Not gated by `attest_version`, so it binds v0.2 implementations too. All five leaves share one receipt and one issuer key manifest; only the artifact-manifest trust material (`manifests.json`'s `artifact_manifests`/`artifact_manifest_chains`, nested by issuer then `work.artifact_series`) differs per leaf.

| Leaf | Name | Checks |
| --- | --- | --- |
| 31a | `manifest-currency/a-rollback-rejected` | The trust store's own artifact-manifest chain history already holds `manifest_version: 2`, but the manifest currently PINNED for the series is the OLDER `manifest_version: 1` (a rollback attempt, or a stale re-import) — mirrors vector 14b's key-manifest discontinuity shape: `trust: "unverified_rotation"`, the receipt's own signature otherwise verifies clean. |
| 31b | `manifest-currency/b-monotone-ok` | Same chain, but the pinned manifest IS the chain tail (`manifest_version: 2`) — no currency violation, `trust` stays at its provenance-derived value. |
| 31c | `manifest-currency/c-legacy-unversioned-warn` | The pinned artifact manifest predates this amendment (no `manifest_version` at all) — warned (`artifact_manifest_unversioned`), never rejected: `trust` stays at its provenance-derived value, `ok: true`. |
| 31d | `manifest-currency/d-unauthenticated-ignored` | A signed v1 is followed by an unsigned v2 candidate. The artifact-manifest machinery is skipped: `artifact_manifest_unauthenticated` is the only warning, no currency conclusion is made, and the provenance-derived trust remains unchanged. |
| 31e | `manifest-currency/e-legacy-transition-warn-only` | A legacy trusted manifest is followed by the first versioned candidate. Currency is not evaluable across the transition: the candidate is accepted, only `artifact_manifest_unversioned` is emitted for the legacy side, and trust is not `unverified_rotation`. |

### 32: anchor profile v2 (G4, v0.2 rev 4 amendment, v0.2 §11.1.1)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §11.1.1 — the `ots` OTS commitment covers the checkpoint's FULL signed note (header AND signature lines, `signed_note_bytes`) instead of the unsigned header alone (`note_bytes`), closing TM-33's residual chosen-unsigned-note pre-anchoring risk; newly-produced anchors MUST declare `anchor_profile: "signed-note-v2"`, while absent/`"note-v1"` legacy anchors remain fully verifiable forever, classified with warning `anchor_note_only` (eternal verifiability, attest-versioning.md §3). One receipt/checkpoint fixture, four anchor-evidence variants.

| Leaf | Name | Checks |
| --- | --- | --- |
| 32a | `a-v2-valid` | `anchor_profile: "signed-note-v2"`, `ots` op-chain genuinely committing over `signed_note_bytes` — `transparency` upgrades to `anchored_before:<T>`, no `anchor_note_only` warning. |
| 32b | `b-v2-commit-mismatch` | Same declared `"signed-note-v2"` profile, but the op-chain was built from `SHA-256(note_bytes)` alone (the legacy v1 seed) — the replayed chain lands on a different root than pinned, so the anchor FAILS (`ots op-chain result does not match header_merkle_root`): a v1-shaped commitment cannot pass as v2 proof of the signed note's existence. |
| 32c | `c-v1-note-only-warn` | No `anchor_profile` declared (legacy), genuinely v1-shaped op-chain — verifies and upgrades standing exactly as every pre-G4 anchor always has, now carrying `anchor_note_only`. |
| 32d | `d-converted-from-ots` | The same clean `signed-note-v2` case as 32a, except the proof and its pinned header were emitted by the reference implementation's own detached-`.ots` converter (`attest log ots-convert`) instead of assembled by hand — the one leaf that holds a producer, and not only the two verifiers, to the shared corpus. Its op-chain opens with the operand-carrying step a real calendar aggregation leaves behind, so the replay is exercised on the shape a real attestation yields. |

### 33: logged revocation and deadline effectiveness (G5, TM-47, v0.2 rev 5 amendment, v0.2 §8/§15)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §8/§15 item 5 — `revocation-record` is a third loggable entry type, and a `refund_window` revocation record is effective only when a Stage-2-capable verifier's `revocation_evidence` proves the record's log entry was logged and OTS-anchored no later than the receipt's own refund-window deadline (`issued_at + revocation_window_days`). One `refund_window` receipt/record fixture (14-day window) drives (a)-(c); (d) is an independent `policy`-class fixture pinning that class as unaffected.

| Leaf | Name | Checks |
| --- | --- | --- |
| 33a | `a-timely-logged-honored` | The record's `revocation-record` log entry is genuinely logged and OTS-anchored to a pinned header BEFORE the deadline — the deadline rule is satisfied, `revocation: "revoked"`. |
| 33b | `b-unlogged-ignored-warn` | A Stage-2-capable verifier (`log_keys`/`anchor_policy` configured), but NO `revocation_evidence` for this record at all — never proven logged, ignored: `revocation: "invalid_revocation_ignored"` plus `revocation_unlogged_deadline`. |
| 33c | `c-late-anchor-ignored` | `revocation_evidence` present and genuinely verifies as logged, but the OTS anchor's pinned header time is AFTER the deadline — same ignored-with-warning outcome as 33b, different cause. |
| 33d | `d-policy-class-unchanged` | A `policy`-class record (not `refund_window`) under a Stage-2-capable verifier with no `revocation_evidence` — `revocation: "revoked"`, UNCHANGED; the deadline rule never engages outside `refund_window`. |

### 35: transfer — issuer-mediated transfer and the consent gate (v0.2 rev 6 amendment, v0.2 §17, revision provenance: v0.2 rev 6, 2026-07-23)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §17.1–§17.4 and §17.7–§17.8 — see that document's own §16.5 for the full leaf table (identical content, kept in one place to avoid drift). One shared `attest_version: "0.2"`, `license.transferable: true` old-receipt fixture (varied per leaf) and one shared, genuinely issuer-signed + holder-authorized + logged transfer record drive leaves a/b/g/k; leaves i/j are D1's (§17.8) schema-conditional negative/positive control pair — `35i` is `attest_version: "0.1"` and therefore counts toward the v0.1 subset above, `35j` is `attest_version: "0.2"` and does not.

| Leaf | Name | Checks |
| --- | --- | --- |
| 35a | `a-transferred-with-backing` | A `policy`-class old receipt plus an authenticated `status: "transferred"` revocation record plus one fully valid transfer-view claim (issuer sig + holder auth + logged evidence) — the consent gate is satisfied: `revocation: "transferred"`, `ok: false`. |
| 35b | `b-transferred-on-none-with-backing` | The identical claim, but `license.revocability: "none"` — STILL honored; the consent gate applies to every revocability class, `none` included. |
| 35c | `c-transferred-on-none-unbacked` | The SAME `none`-class receipt/revocation as 35b, but NO `transfer-view.json` at all — the resolver is never reached, unbacked directly: `invalid_revocation_ignored`, `ok: true`, `transferred_revocation_unbacked`. |
| 35d | `d-forged-holder-auth` | The transfer record's issuer signature genuinely verifies, but `holder_authorization.sig` was made by an unrelated key, not the old receipt's own `buyer.pubkey` — the consent gate itself fails: same unbacked outcome as 35c. |
| 35e | `e-unlogged-transfer` | The SAME fully-authenticating record as 35a, but its claim carries no `evidence` at all — never proven logged: `invalid_revocation_ignored`, `ok: true`, `transfer_record_unlogged`. |
| 35f | `f-double-assignment-earliest-wins` | TWO fully valid claims for the same `receipt_id`, distinct `new_receipt_id`/`new_holder_pubkey`, logged at indices 0 (earliest) and 1 (later), the later-logged one listed FIRST in the array — the earliest-logged one still wins: `revocation: "transferred"`, `ok: false`, `transfer_double_assignment_conflict`. |
| 35g | `g-not-transferable-before-violation` | The old receipt's own `license.not_transferable_before` falls AFTER the (otherwise fully valid) claim's `transferred_at` — not yet transferable: `invalid_revocation_ignored`, `ok: true`, `transfer_not_yet_transferable`. |
| 35h | `h-classical-only-record-hybrid-key` | The transfer record's holder-authorization is genuine, but the ISSUER side is signed Ed25519-ONLY against a HYBRID manifest — the §13 AND-rule fails closed, same unbacked outcome as 35c/35d. |
| 35i | `i-v01-transferable-null-pubkey-ok` | D1's negative control: `attest_version: "0.1"` is untouched by the schema conditional, so `transferable: true` with a null `buyer.pubkey` stays schema-valid — `schema: "valid"`, `ok: true`. |
| 35j | `j-v02-transferable-requires-pubkey` | The SAME shape under `attest_version: "0.2"` IS a schema error — `schema: "invalid"`, `ok: false`, an error mentioning `pubkey`. |
| 35k | `k-not-transferable-before-boundary` | The old receipt's `not_transferable_before` EXACTLY equals the fully valid claim's `transferred_at` → honored: `revocation: "transferred"`, `ok: false`, no warnings. |

### 36: transfer-chain — chain of title (v0.2 rev 6 amendment, v0.2 §17.5, revision provenance: v0.2 rev 6, 2026-07-23)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §17.5 — see that document's own §16.6 for the full leaf table. A SEPARATE audit surface from single-receipt `verify()`; every leaf carries `chain.json` instead of `payload.json`/`envelope.json` and is routed to `audit_chain`/`auditChain`/`runChainAudit`. A PLAIN (non-hybrid) issuer manifest — `audit_chain` never touches an envelope's own signature/schema/hybrid-ness. Vector coverage exercises 3 of the 8 normative literals: 36b (pubkey mismatch), 36c (losing branch), and 36d (transfer floor); the remaining five are pinned by unit tests in both implementations.

| Leaf | Name | Checks |
| --- | --- | --- |
| 36a | `a-valid-chain` | Three receipts R0→R1→R2, two fully valid links (each backed by a `transferred`-class revocation on the previous receipt) — `chain_valid: true`, `link_status: ["valid", "valid"]`. |
| 36b | `b-pubkey-mismatch-no-link` | One link whose transfer record otherwise fully authenticates, but the NEXT receipt's own `buyer.pubkey` does not equal the record's `new_holder_pubkey` — `chain_valid: false`, `link_status: ["invalid"]`. |
| 36c | `c-losing-branch-no-link` | The previous receipt has TWO fully-authenticating, logged transfer records — a phantom continuation logged FIRST, the record actually continued by `payloads` logged SECOND — the later-logged, presented branch loses: `chain_valid: false`, `link_status: ["invalid"]`. |
| 36d | `d-floor-violation-no-link` | A two-receipt chain whose link transfer predates the previous receipt's `not_transferable_before` → `chain_valid: false`, `link_status: ["invalid"]`, error `chain link 1: transferred before not_transferable_before`. |

### 37: preservation pledge — Stage 4 (v0.2 rev 8 amendment, v0.2 §18, revision provenance: v0.2 rev 8, 2026-08-25)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §18 — see that document's own §16.9 for the full leaf table. Every leaf is a normal `verify()` call carrying a `grant-view.json`, and the file's presence is the capability gate. Three domains appear and the separation is the point: the receipt's `issuer.id` is the store, the grant's `publisher` is the rights holder, and a third exists only so `signer_mismatch` has something to mismatch against — each with its own manifest and its own ML-DSA-65 key, because a corpus in which unrelated domains shared one post-quantum key would teach exactly the reuse v0.1 §7.1 exists to prevent. Seventeen of the twenty-four leaves end somewhere other than `activated`: §18.4's failure asymmetry is normative, and a false `activated` is the single failure that would discredit the instrument. Leaf `37s` is `attest_version: "0.1"` by construction and belongs to the v0.1 subset, exactly as `35i` does.

### 38: redemption — the audience-bound holder proof (v0.2 rev 8 amendment, v0.2 §18.7)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §18.7 — see that document's own §16.10 for the full leaf table. A FOURTH conformance surface, routed by the presence of `redemption.json`: there is no receipt and no grant document in the question these leaves ask, only whether a holder proof is good for THIS custodian, so they ship no envelope and no trust store. Leaf `38b` is the reason the group exists — a genuine response produced for a different custodian and replayed here, which is precisely what v0.1 §8.2's recipient-less binding challenge could not refuse.

### 39: witness corroboration — `corroboration: "witnessed"` (P1.1b, v0.2 §10.1/§11.4)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §11.4 — see that document's own §16.7 for the full leaf table. One receipt/checkpoint fixture; the leaves differ only in the cosignature lines appended to the checkpoint note and in the trusted `witness-policy.json` supplied alongside `log-keys.json`. Every failure in this layer is SILENT by §11.4 — the only literal it may emit is the independence warning that accompanies a successful upgrade — so ten of the thirteen leaves are distinguished from one another by nothing but `corroboration` remaining `"logged"`.

| Leaf | Name | Checks |
| --- | --- | --- |
| 39a | `a-ed25519-witnessed-bootstrap` | One valid `0x04` cosignature by a pinned, epoch-resolved witness holding the `corroboration` role → `witnessed`, with `witness_independence_not_established` (unconditional on every witnessed verdict). |
| 39b | `b-unpinned-witness-does-not-count` | A genuine cosignature by a witness no epoch pins → stays `logged`. Trust comes from the policy, never from the note. |
| 39c | `c-invalid-ed25519-does-not-count` | Right name, right key ID, corrupted signature → stays `logged`. |
| 39d | `d-c2sp-type-06-does-not-count` | Same witness, same timestamp, same 76-byte shape, genuine signature over the correct message — but the key ID is derived with C2SP type `0x06` → stays `logged`. |
| 39e | `e-checkpoint-domain-not-cosignature` | A genuine signature made over the checkpoint BODY, transported into a cosignature blob: without the `cosignature/v1` prefix the message is a different one → stays `logged`. |
| 39f | `f-cosignature-domain-not-checkpoint` | The log's own ML-DSA-65 checkpoint line is missing and a genuine witness `0xff` activation leg stands in its place. Checkpoint auth is hybrid and mandatory → `transparency: not_checked`, `corroboration: none`, `checkpoint_verification_failed`. |
| 39g | `g-missing-policy-epoch` | 39a's cosignature verbatim, but the evidence names an epoch the policy does not contain → stays `logged`. An unresolvable epoch is never a reason to substitute another. |
| 39h | `h-wrong-role` | The pin is real and current but holds only `sunset-activation` → stays `logged`. |
| 39i | `i-historical-epoch-valid` | A CLOSED epoch still corroborates: the observation falls inside its window, and a timely `signed-note-v2` anchor over the full note (cosignature line included) ties it to a PQ-surviving time → `anchored_before:<T>` and `witnessed`. |
| 39j | `j-current-epoch-not-substituted` | Same checkpoint and epoch name as 39i, but the historical epoch pins a different operator and the witness who signed is pinned only in the current epoch → stays `logged`. That pin's window reaches back into the historical epoch on purpose, so the membership difference is the only thing deciding. |
| 39k | `k-old-valid-no-local-clock-cap` | The pin retired after the observation was made; standing is judged at the instant claimed, never at the verifier's clock → `witnessed`, and it must still read `witnessed` decades from now. |
| 39l | `l-evidence-policy-substitution-ignored` | The evidence carries its own, perfectly valid policy document pinning the witness who signed. It is ignored in full → stays `logged`. |
| 39m | `m-compromise-onset-unknown` | `compromised_after: null` — a compromise IS declared and its onset is unknown, so the pin fails closed at every instant, forever. Distinct from the member being absent → stays `logged`. |

### 40: activation witness quorum (P1.1b, v0.2 §11.4)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §11.4 — see that document's own §16.8 for the full leaf table. A THIRD conformance surface, routed by the presence of `witness-quorum.json`. Every temporal limit ships as a PAIR one second apart, because that is where a rule either holds or silently does not.

| Leaf | Name | Checks |
| --- | --- | --- |
| 40a | `a-one-of-one-valid` | One pinned witness, a complete `0x04`+`0xff` hybrid vote, an anchor inside the window → valid, `witness_time` = the vote's timestamp. |
| 40b | `b-two-of-three-conservative-t` | 2-of-3 with votes 300s apart → `T = min(t_i)`, never the maximum. |
| 40c | `c-ed25519-leg-only-invalid` | The classical leg alone is no vote. |
| 40d | `d-mldsa-leg-only-invalid` | The post-quantum leg alone is no vote. |
| 40e | `e-legs-with-divergent-timestamps` | Legs one second apart are not a pair. Declared limit: redundant with signature verification, since both legs sign a message built from one timestamp — the leaf pins the outcome, not the rule. |
| 40f | `f-transplanted-leg` | A genuine `0xff` leg signed over a DIFFERENT note pairs structurally, then fails the fail-closed AND. |
| 40g | `g-one-vote-per-control-group` | Two pinned keys of one operator in one control group, each voting → rejected outright, not de-duplicated. |
| 40h | `h-direct-domain-conflict` | The pin names the domain whose sunset the quorum would activate → excluded before pairing. |
| 40i | `i-transitive-domain-conflict` | A sibling in the voting pin's own control group names the domain → shared control is shared conflict. |
| 40j | `j-committee-of-ten-invalid` | Ten activation control groups against a ceiling of nine, carrying otherwise sufficient votes. |
| 40k | `k-declared-form-incoherent-with-membership` | `threshold.n` declares two while the epoch pins three activation control groups. |
| 40l/40m | `l-skew-600-valid` / `m-skew-601-invalid` | 600s of spread between counting votes is inside the limit; 601 is not. |
| 40n | `n-anchor-before-latest-vote` | An anchor predating a counting vote cannot evidence it. |
| 40o/40p | `o-anchor-delay-86400-valid` / `p-anchor-delay-86401-invalid` | The anchor-delay boundary, measured from `T` and not from the latest vote — both leaves carry two votes 300s apart, which is what makes the two readings disagree. |
| 40q | `q-note-v1-anchor-insufficient` | A `note-v1` anchor commits to the unsigned header alone; nothing else differs from 40a. |
| 40r | `r-new-evidence-does-not-revive-expired-epoch` | Open-ended pins, but the EPOCH's window has closed. |
| 40s | `s-quorum-time-exactly-at-compromise-cutoff` | `T` exactly at the declared onset still counts: the boundary is inclusive. Inside the CLOSED 2020 epoch, so it also pins that the epoch window is judged at `T` and not at the verifier's clock — which 40r cannot pin alone. |
| 40t | `t-compromise-cutoff-null-zero-votes` | An explicit `null` onset fails closed at every instant, forever. |

### 41: compromise cutoff — the absorbing marking and its anchored bound (v0.1 rev 8 §7.3 / v0.2 rev 9 §19)

Checked against [`docs/spec/attest-v0.1.md`](../attest-v0.1.md) §7.3 and [`docs/spec/attest-v0.2.md`](../attest-v0.2.md) §19 — see the latter's own §16.11 for the full leaf table. Two rules over one fixture: manifest v1 (both issuer keys `active`) → v2, which marks the receipt's signing key `compromised` and is signed by the second key; a `revocability: "none"` receipt; three pinned Bitcoin headers H1 < H2 < H3. Leaves `a`–`k` exercise the RESCUE, which is Stage-2 only: a receipt whose signed-receipt-core is anchored strictly before the declaring manifest's own anchored time survives. Leaves `l`–`t` exercise the FLOOR, which is v0.1's and needs no Stage-2 configuration at all: a `compromised` marking the verifier holds anywhere — trusted manifest, version chain, or an authenticated declaration — cannot be undone by a later manifest that re-lists the key `active` or drops it. Leaf `f` is the group's v0.1 subset member; leaf `q` is its negative control, and a red `q` means a general status ordering was implemented where only `compromised` was asked for.

| Leaf | Name | Checks |
| --- | --- | --- |
| 41a | `a-rescued-anchored-before-cutoff` | Receipt anchored at H1, declaration at H2 → rescued, `compromise_rescue_applied`. |
| 41b | `b-anchored-after-cutoff-fails` | Receipt at H2, declaration at H1 → not provably older, `compromise_rescue_receipt_after_cutoff`. |
| 41c | `c-logged-only-fails` | A `logged`-only receipt holds the log operator's word, not an external timestamp → `compromise_rescue_requires_anchored_receipt`. |
| 41d | `d-cutoff-logged-only-survives` | A declaration with no anchor cannot destroy stock that has one → `compromise_cutoff_unanchored`. |
| 41e | `e-no-cutoff-evidence-survives` | The same, with no `compromise-view.json` at all. |
| 41f | `f-stage1-fail-closed` | The (a) fixture with every Stage-2 file removed → unconditional rejection, byte-identical to vector 13. The v0.1 subset leaf. |
| 41g | `g-boundary-equal-fails` | Receipt and declaration in the SAME pinned header → equality fails closed; same-block ambiguity is not precedence. |
| 41h | `h-earliest-cutoff-wins` | Two declarations at H1 and H3 with the receipt at H2 → the cutoff is the minimum, so a later declaration cannot launder an earlier one. |
| 41i | `i-unvouched-declaration-ignored` | A self-consistent declaration signed by a `kid` no held manifest lists, anchored in the receipt's own header → ignored, and the receipt an accepted claim would have killed survives. |
| 41j | `j-hybrid-rescued` | (a) again over a v0.2 hybrid envelope and manifest. |
| 41k | `k-manifest-claim-does-not-rescue` | The receipt's transparency claim is a key-manifest claim: it proves the manifest existed, never that the receipt's signature did. |
| 41l | `l-uncompromise-chain-floor` | Trusted v3 re-lists the key `active`, the chain [v1, v2, v3] is held, and NO Stage-2 configuration exists → the floor still kills, and the regression breaks continuity. |
| 41m | `m-uncompromise-view-floor` | The same regression seen through a declaration claim instead of a chain, evidence only `logged` → the status is established; the anchor is what is missing. |
| 41n | `n-uncompromise-floor-spares-anchored` | (m) with an anchored receipt → the floor settles THAT, the missing anchor leaves WHEN open, and anchored stock survives. |
| 41o | `o-status-regression-breaks-continuity` | The (l) chain with a receipt signed by the never-compromised second key → nothing to kill, `trust: "unverified_rotation"` all the same. |
| 41p | `p-declaring-signer-compromised-still-floors` | The declaring signer is itself `compromised` in the trusted manifest → the floor stands, so marking the signer cannot cancel an honest declaration. |
| 41q | `q-retired-reactivation-untouched` | NEGATIVE CONTROL: `retired` → `active` again is untouched. The rule is about `compromised` and nothing else. |
| 41r | `r-compromised-signer-establishes-no-cutoff` | (p) with both sides anchored → the claim that floors establishes no cutoff, because without a chain the signer's own compromise cannot be dated. |
| 41s | `s-chain-dates-the-signer-cutoff-holds` | (r) plus the chain that dates the signer's compromise AFTER the declaration → the cutoff holds and the later receipt dies; the unrelated discontinuity does not cancel it. |
| 41t | `t-keyset-omission-breaks-continuity` | Trusted v3 OMITS the key instead of re-listing it → keyset preservation makes that a discontinuity too; the twin of (o). |
| 41u | `u-stale-pin-not-a-retraction` | Trusted v1 is older than the v2 declaration carried in `compromise-view.json` → the floor still kills the unanchored receipt, but no `compromise_marking_retracted` warning is emitted, because this is a stale pin rather than an issuer rewriting its history. |
| 41w | `w-oversized-view-does-not-certify` (v0.1 rev 13) | (m)'s exact fixture, but `compromise-view.json` pads the genuine declaration with 64 junk entries past `verify._MAX_COMPROMISE_CLAIMS` → the oversized view is never evaluated at all, so `signature: "invalid"`, `errors_contains: ["compromise view exceeds 64 claims"]`, `warnings: []` — no rescue and no retraction warning, because the ceiling returns before either is reached. `v` is reserved for other work. |

## Regeneration

The vectors are generated deterministically by [`tools/gen_vectors.py`](../../../tools/gen_vectors.py): every keypair, salt, timestamp, and ULID randomness source is a fixed constant (no wall-clock reads, no CSPRNG). Running

```sh
.venv/bin/python tools/gen_vectors.py
```

twice must produce byte-identical output — `git diff --exit-code docs/spec/vectors` after a second run is the determinism gate. `tests/test_vectors.py` replays every vector against the reference implementation and asserts the produced `VerificationResult` matches `expected.json` exactly.

## 42 — `42-publisher-claim`

v0.1 §11.2 (2026-08-26 amendment, rev 11): `work.publisher_id` present and
differing from `issuer.id` is warned `publisher_claim_unattested`,
payload-deterministically and independent of `attest_version` and of
trust-store contents. All three leaves are `attest_version: "0.1"` receipts,
signed against a trust store that holds only the issuer's own manifest — leaf
`a`'s trust store has never heard of the claimed publisher domain at all,
which is the point: the warning cannot be switched off by what the verifier
happens to trust.

| Leaf | Name | `work.publisher_id` | Expected |
| --- | --- | --- | --- |
| 42a | `a-claim-differs-warn` | `"pub.example"`, differs from `issuer.id` | `ok: true`, `trust: "verified"`, `warnings: ["publisher_claim_unattested"]` |
| 42b | `b-self-publisher-silent` | equal to `issuer.id` | `ok: true`, `trust: "verified"`, `warnings: []` — self-publishing needs no claim to attest |
| 42c | `c-no-claim-silent` | absent | `ok: true`, `trust: "verified"`, `warnings: []` — no claim, nothing to warn about |

## 43 — `43-publisher-authority`

v0.2 §20 (2026-08-26 amendment): publisher authorization is evaluated from the caller-supplied `authority-view.json` channel. All 25 leaves are v0.2 hybrid receipts whose `work.publisher_id` is `pub.example` and whose issuer is `store.example.com`, except the self/no-claim controls. Each leaf's receipt remains `ok: true` and `trust: "verified"`; only `publisher_authority`, `publisher_authority_trust`, and the publisher-claim warnings move.

| Leaf | Name | Expected authority result |
| --- | --- | --- |
| 43a | `a-authorized` | Current publisher authorization covers the issuer at the receipt time → `authorized` / `verified`, no warnings. |
| 43b | `b-unauthorized-empty-list` | Current authenticated authorization has no issuers and asserts version 1 current → `unauthorized` / `verified`, `publisher_not_authorizing_issuer`. |
| 43c | `c-no-view-not-checked` | No `authority-view.json` → `not_checked` / `not_checked`, `publisher_claim_unattested`. |
| 43d | `d-empty-view-unattested` | Empty view object → `unattested` / `not_checked`, `publisher_claim_unattested`. |
| 43e | `e-forged-ignored` | Authorization signed by a key outside the publisher manifest → `unattested` / `verified`, `authorization_invalid_ignored` then `publisher_claim_unattested`. |
| 43f | `f-signer-mismatch` | Document authenticates under another domain's manifest while claiming `pub.example` → `unattested` / `signer_mismatch`, `authorization_signer_not_publisher` then `publisher_claim_unattested`. |
| 43g | `g-window-expired-unauthorized` | Entry window closed before the receipt and the view asserts that version current → `unauthorized` / `verified`, `publisher_not_authorizing_issuer`. |
| 43h | `h-prospective-not-retroactive` | Entry has since expired, but the receipt was issued inside the window → `authorized` / `verified`. |
| 43i | `i-equivocation` | Two authenticated documents share one `authorization_version` with different contents → `unattested` / `unverified_rotation`, `publisher_claim_unattested`. |
| 43j | `j-rollback-max-wins` | Version 2 conformingly closes version 1 before the receipt and is asserted current → `unauthorized` / `verified`, `publisher_not_authorizing_issuer`. |
| 43k | `k-scope-uncovered` | Entry scope covers a different artifact/series and is asserted current → `unauthorized` / `verified`, `publisher_not_authorizing_issuer`. |
| 43l | `l-permission-missing` | Entry carries only reserved `delegate`, not honored `issue`, and is asserted current → `unauthorized` / `verified`, `publisher_not_authorizing_issuer`. |
| 43m | `m-self-publisher` | `publisher_id == issuer.id`, even with a view supplied → `self` / `not_checked`, no warnings. |
| 43n | `n-no-claim` | No `publisher_id`, even with a view supplied → `no_publisher_claim` / `not_checked`, no warnings. |
| 43o | `o-tofu-authorized` | Same as 43a, but publisher manifest provenance is `bundle` → `authorized` / `unauthenticated_tofu`. |
| 43p | `p-view-ceiling` | View supplies 65 authorization documents, above the §20.3 ceiling → `unattested` / `not_checked`, `publisher_claim_unattested`. |
| 43q | `q-classical-only-rejected` | Ed25519-only authorization against a hybrid publisher manifest → `unattested` / `verified`, `authorization_invalid_ignored` then `publisher_claim_unattested`. |
| 43r | `r-denial-without-currency` | Empty-list authorization is genuine but lacks `current_authorization_version` → `unattested` / `verified`, `publisher_claim_unattested`. |
| 43s | `s-stale-behind-assertion` | Empty-list authorization v1 is supplied with assertion that v2 is current → `unattested` / `verified`, `publisher_claim_unattested`. |
| 43t | `t-deauth-window-closed-past-receipt` | Version 2 closes the window, but the receipt was issued before closure → `authorized` / `verified`. |
| 43u | `u-entry-removal-nonconforming` | Version 2 deletes the entry rather than preserving it; version 1 remains effective → `authorized` / `unverified_rotation`. |
| 43v | `v-backdated-closure-nonconforming` | Version 2 backdates the closure before version 1's issue time; version 1 remains effective → `authorized` / `unverified_rotation`. |
| 43w | `w-postdated-closure-nonconforming` | Version 2 postdates the closure after its own issue time; version 1 remains effective → `authorized` / `unverified_rotation`. |
| 43x | `x-early-revocation-live-term-window` | Version 2 conformingly shortens a still-live term window before the receipt and is asserted current → `unauthorized` / `verified`, `publisher_not_authorizing_issuer`. |
| 43y | `y-extension-live-window-conforming` | Version 2 conformingly extends a still-live term window to cover the receipt → `authorized` / `verified`. |

## 44 — `44-manifest-duplicate-kid`

v0.1 §7.1 (2026-08-26 amendment): a `keys[]` array listing one `kid` twice has no
well-defined key resolution, so the manifest is refused whole — in both element orders,
and whether or not the duplicated `kid` is the one that signed the receipt.

| Leaf | Name | Manifest `keys[]` | Expected |
| --- | --- | --- | --- |
| 44a | `a-active-first` | `[{ISSUER_KID, active}, {ISSUER_KID, compromised}]`, same `pub` | `signature: "invalid"`, `schema: "invalid"`, `revocation: "unknown"`, `binding: "not_checked"`, `trust: "verified"`, `ok: false`, `errors_contains: ["duplicate kid"]`, `warnings: []` |
| 44b | `b-compromised-first` | the same two entries, order inverted | identical to 44a — the pair proves element order does not decide |
| 44c | `c-unrelated-duplicate` | `[{ISSUER_KID, active}, {ROTATED_KID, active}, {ROTATED_KID, retired}]`, receipt signed by `ISSUER_KID` | identical to 44a — a duplicate on a `kid` the signature does not use is refused too, which is the case the §7.3 status floor cannot see |

## 45 — `45-revocation-anchor-status`

v0.1 §12.3 (2026-08-26 amendment): only a record whose `status` is a registered
revocation-statement literal may drive the freshness anchor `T`. Both leaves carry a
single issuer-signed record with `revoked_at: "2099-01-01T00:00:00Z"`, covered by the
signer's open-ended validity window, and an unregistered `status`.

| Leaf | Name | Record | Expected |
| --- | --- | --- | --- |
| 45a | `a-unrelated-unknown-status` | `receipt_id` of another receipt, `status: "recalled"` | `signature: "valid"`, `schema: "valid"`, `revocation: "unknown"`, `binding: "not_checked"`, `trust: "verified"`, `ok: true`, `errors: []`, `warnings: []` |
| 45b | `b-matching-unknown-status` | the receipt's own `receipt_id`, `status: "recalled"` | identical to 45a — a matching record with an unregistered status neither revokes nor anchors |

## 47 — `47-oversized-view-transfer` (v0.1 rev 13)

`_classify_revocation`'s oversized-view ceiling (§18.4) fails CLOSED for the `revocability: "none"` class exactly as it already does for `policy`/`refund_window`: a genuine, backed `status: "transferred"` record — the same fixture as `35-transfer/b-transferred-on-none-with-backing` — padded past `revocation.MAX_REVOCATION_RECORDS` with junk entries must not verify green with no warning at all, per v0.2 §17.3's consent gate applying to every revocability class.

| Leaf | Name | Checks |
| --- | --- | --- |
| 47a | `a-oversized-view-hides-transfer` | `revocation-view.json` carries the genuine backing record plus 10,000 `null` entries, one past the ceiling → `signature: "valid"`, `schema: "valid"`, `revocation: "unknown"`, `binding: "not_checked"`, `trust: "verified"`, `ok: false`, `errors_contains: ["cannot rule out a transfer"]`, `warnings: []` — the transfer the record would have honored is invisible, and no warning rides along because the ceiling returns before the resolver ever runs. |
