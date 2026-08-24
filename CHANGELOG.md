# Changelog

All notable changes to `attest-receipts` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] — 2026-08-24

### Added

- `attest-bridge` email delivery now sends the spec §14.1/§14.2 bundle pair for
  every sale, instead of a single receipt file: `<issuer-slug>-<receipt_id>.attest`
  (shareable — salt-stripped receipt plus the issuer's key manifest and the
  licence text, verifiable even after the store is gone) and
  `<issuer-slug>-<receipt_id>.private.attest` (the buyer's secret, carrying the
  buyer-binding salt; the web verifier refuses this file by name).

- `[delivery] info_url` in `bridge.toml` is now optional. Left unset, every
  receipt email links to attest's canonical "what is this file?" page
  (`https://bernalli.github.io/attest/what-is-this.html`) instead of requiring
  every merchant to write their own explainer.

### Changed

- `[products.<key>] legal_text_path` is now a **required** `bridge.toml` field:
  the bridge reads that file and cross-checks its SHA-256 against the
  already-declared `legal_text_sha256` at startup, refusing to start (naming
  the offending product key) on a mismatch, a missing file, or an unreadable
  one. `legal_text_sha256` alone was never enough — it enters every signed
  receipt's payload, so the terms text backing it must be verified once, loudly,
  at startup, not trusted to stay in sync. This is a breaking change to
  `bridge.toml`, accepted because no merchant is running this bridge in
  production yet.

- `attest export`'s generated `README.html` (and therefore the bundle every
  `attest-bridge` delivery now ships) was rewritten for a reader who has never
  seen an attest receipt before, not just a merchant debugging one.

## [0.4.0] — 2026-07-23

### Added

- **v0.2 Stage 3 — issuer-mediated transfer** (`docs/spec/attest-v0.2.md` §17), giving
  the reserved `license.transferable` field its first real meaning. A transfer record
  is an issuer-signed side-document — `receipt_id`, `new_receipt_id`, `new_holder_pubkey`,
  `transferred_at`, an outgoing-holder `holder_authorization` signature over a
  domain-separated preimage, and the issuer's own hybrid-AND-ruled `signature` — that
  moves a receipt from one holder to another. Old-receipt extinguishment reuses the
  existing revocation feed (`status: "transferred"`, reported as the new reachable
  value `revocation: "transferred"`, capping `ok` the same way `"revoked"` already
  does) and is honored for every `license.revocability` class, including `none`, but
  only when backed by an authenticated `holder_authorization` and a logged inclusion
  proof (the consent gate). A transfer record that authenticates but is not logged is
  ignored (`transfer_record_unlogged`); two records for the same receipt resolve
  earliest-log-index-wins (`transfer_double_assignment_conflict`); `license.not_transferable_before`
  gates transfer eligibility (`transfer_not_yet_transferable`); post-transfer revocation
  matches by `receipt_id`, under the new receipt's own class and `issued_at` anchor. A
  v0.2 receipt with `license.transferable: true` and a null/absent `buyer.pubkey` is now
  a schema error — the chain of title is cryptographic from the first link — while v0.1
  receipts are untouched. A separate `audit_chain`/`auditChain` surface walks a whole
  chain of transfers and reports per-link validity, independent of single-receipt
  `verify()`. New conformance leaf groups `35-transfer` (11 leaves) and
  `36-transfer-chain` (4 leaves), bringing the corpus to 97 leaves across 36 groups,
  reproduced by the Python reference, the TypeScript verifier, and the site adapter.
- Python: `src/attest/transfer.py` (record build/sign/verify, holder authorization,
  chain-of-title audit), `verify.py` integration (transferred-class backing,
  `not_transferable_before` enforcement), and `attest transfer` CLI
  subcommands.
- TypeScript: `verifiers/ts/src/transfer.ts` and `revocation.ts`/`verify.ts` parity for
  the full transfer profile, including Stage 3's stricter date validation (a
  Python/TypeScript divergence closed during review).
- Threat model (`docs/spec/attest-threat-model.md`): §6.1's five forthcoming-revision
  requirements resolved into cross-references; new Group K adds TM-61 through TM-67
  (transfer-record forgery, chain-of-title hijack, double assignment, post-transfer
  revocation confusion, coerced transfer, post-CRQC holder-authorization forgery,
  transfer-feed trade-graph observability); a declared, tracked gap records that the
  Tamarin formal-verification model does not cover the transfer profile in this
  revision (`formal/` and `tools/check_formal.py` are untouched by design).
- Privacy considerations (`docs/spec/attest-privacy.md`): `not_transferable_before`
  classified (§2.5); the `revocation-record` and `transfer-record` log-entry types
  documented for the first time (§2.11, closing a pre-existing gap left open since
  rev 5); new §2.17 analyzing transfer-record observability and its pseudonymity
  bound; a §5 note that a `transfer-record` log entry is a content-free hash with a
  non-authenticated issuer hint and does not by itself establish that a transfer happened.
- Non-normative annex `docs/spec/attest-transfer-economics.md`: the resale-velocity
  problem, the issuer-royalty incentive (the Robot Cache precedent), the legal frame
  (*UsedSoft* C-128/11, *Tom Kabinet* C-263/18, and the `eu_usedsoft_asserted`
  relationship), and an explicit out-of-scope list (marketplaces, payments, escrow,
  royalty mechanics).

## [0.3.0] — 2026-07-23

### Added

- Normative amendment `attest-versioning.md`: the upgrade-policy document governing every future revision of the attest specification family. States the additive pattern (a change that would make a previously-conforming verifier reject a previously-conforming artifact requires a new `attest_version`), the eternal-verifiability constraint (no amendment ever makes an already-issued artifact unverifiable — only its result classification may degrade), the three-state algorithm lifecycle (`active` / `deprecated` / `unsafe`, defined for `ed25519` and `ed25519+ml-dsa-65`), the amendment procedure (one dated, numbered entry per document's own `## Revision log`), and the extension-point registries (signature suites, payload fields, revocation classes, log entry types, transfer types).

- Normative resource ceilings (v0.1 §11.3, extended to v0.2 by §6.2), binding both `attest_version`s: raw envelope size capped at 1,048,576 bytes, checked before any parsing; issuer key manifest `keys[]` capped at 256 entries; artifact manifest `artifacts[]` capped at 4,096 entries. The pre-existing parsed-tree nesting-depth cap (256) and the 10,000-record revocation-view ceiling are formalized as conformance-surface requirements at the same time, unchanged in value and behavior. New conformance leaf group `29-limits`.

- Mixed-keyset prohibition (v0.2 §2.3/§13.1): an issuer that declares the hybrid signature profile MUST NOT hold an Ed25519-only key in state `active` — leaving one active would silently downgrade an attacker able to break only Ed25519 back to forging under the still-active classical sibling, with no visible signal that hybrid protection never actually covered those receipts. Migration retires (or otherwise deactivates) every Ed25519-only key in the same `manifest_version` bump that introduces the hybrid key; a verifier that resolves the mixed condition for a v0.2 receipt emits the warning `mixed_keyset_active_ed_only_sibling`. New conformance leaf group `30-mixed-keyset`.

- Artifact manifest currency (v0.1 §7.2/§7.3): artifact manifests gain a `manifest_version` field, REQUIRED going forward and monotonically increasing per (issuer, `artifact_series`) pair. A verifier holding persistent trust state MUST NOT accept a version regression for that pair, and reports `trust: "unverified_rotation"` on one — the same value key-manifest rotation already uses, no new vocabulary. A manifest predating this revision has no `manifest_version` and stays fully valid, warned instead of rejected (`artifact_manifest_unversioned`, eternal verifiability); an unauthenticated or issuer-mismatched manifest is ignored with `artifact_manifest_unauthenticated` / `artifact_manifest_issuer_mismatch`. New conformance leaf group `31-manifest-currency`.

- Anchor profile v2 (v0.2 §11.1.1): an anchoring evidence bundle may declare `anchor_profile: "signed-note-v2"`, committing the OpenTimestamps op-chain over the checkpoint's full signed bytes (header **and** signature lines) instead of the legacy unsigned-header-only commitment. This closes a residual risk in the pre-v2 anchor: an unsigned checkpoint note could be pre-anchored and signed only later, so a v1 anchor never actually proved the note had been signed by the anchored time. Legacy (absent or `"note-v1"`) anchors remain fully verifiable forever and are now classified with the warning `anchor_note_only`. New conformance leaf group `32-anchor-v2`.

- `revocation-record` log entries and refund-window deadline effectiveness (v0.2 §8/§15): revocation records are now a third loggable entry type (`record_sha256` over the entire signed record), reachable by the same inclusion proofs, equivocation detection, and OTS anchoring as `key-manifest`/`receipt` entries. A `refund_window` revocation record is honored by a Stage-2-capable verifier only when its own log entry is proven logged and anchored no later than the receipt's `issued_at + revocation_window_days` deadline; failing that bound resolves to the existing `revocation: "invalid_revocation_ignored"` plus the new warning `revocation_unlogged_deadline`. A verifier that is not Stage-2-capable keeps v0.1's window-only semantics unchanged, and `policy`/`compromised`/`none` revocability classes are unaffected. New conformance leaf group `33-logged-revocation`.

- Conformance corpus grown to **82 leaf vectors across 34 groups**, from 66 at 0.2.0.

## [0.2.0] — 2026-07-22

### Fixed

- The TypeScript verifier treats an absent key-entry `valid_to` as open-ended, matching the Python reference; spec §7.1 now clarifies `valid_to` is optional.

### Added

- v0.2 hybrid Ed25519+ML-DSA-65 signature profile (`attest_version: "0.2"`):
  envelopes carry exactly two signatures, in fixed order `[Ed25519, ML-DSA-65]`,
  both over the same `JCS(payload)` canonical bytes and sharing one `kid`.
  Composite key binding lives in the key manifest (`pub` + new
  `pub_ml_dsa_65`), never in `kid`; a hybrid signer's `manifest_signature`
  itself must carry both a `sig` and a new `sig_ml_dsa_65`, AND-verified,
  fail-closed both ways. Verification is AND semantics: both legs must verify
  or the receipt is rejected. v0.1 receipts remain valid and verifiable
  forever; a v0.1 verifier MUST reject a v0.2 envelope outright (no downgrade
  path). New public spec: [`docs/spec/attest-v0.2.md`](docs/spec/attest-v0.2.md).
  New conformance leaf group `26-hybrid` (8 leaves).

- v0.2 Stage 2 — issuer key transparency and timestamp anchoring, as a
  **corroboration** layer. What it proves is inclusion in a log-signed Merkle
  root: a verifier checks a hybrid-signed checkpoint plus an inclusion proof, and
  anchoring can additionally bound when that checkpoint existed. It can never
  make an unsigned or untrusted artifact look authentic — the `verified` trust
  result stays what it always was, domain control, and inclusion evidence
  surfaces separately as `transparency` / `corroboration` so the two claims
  cannot be confused.

  What it does **not** provide, stated in the spec itself (§10.4, §13) and worth
  repeating here: without witness cosignatures there is no anti-equivocation. An
  unwitnessed log operator can maintain split views indefinitely, and a verifier
  detects equivocation only when it already holds two inconsistent validly-signed
  checkpoints. `corroboration: "witnessed"` — the verdict that closes this — needs
  a witness federation that does not exist yet.

  Substrate is a static C2SP tlog-tiles log; checkpoints carry hybrid Ed25519 +
  ML-DSA-65 signatures on both cores. Two anchor kinds: OpenTimestamps, required
  for any **post-horizon** standing, and RFC 3161, accepted as a classical
  convenience that carries no weight past a configured CRQC horizon. The receipt
  commitment covers the signed-receipt core — `JCS(payload)` and `JCS(signatures)`
  under a domain separator — so it binds the signature bytes, not the payload
  alone. Log keys are pinned in the verifier's own trust store and rotated
  out-of-band; the mandatory gapless rotation chain is a rule about **issuer key
  manifests** above version 1, not about log keys. Sibling patch shipped with it:
  revocation records and artifact manifests carry hybrid signatures too, closing
  the window where they were Ed25519-only and forgeable once a cryptographically
  relevant quantum computer exists. New conformance leaf groups
  `27-valid-to-absent` and `28-transparency`.

- Conformance corpus grown to **66 leaf vectors across 29 groups**, from 43 at
  0.1.2. Both implementations reproduce every one, with none skipped. Note the
  corpus is no longer a v0.1 corpus: the 43 leaves at 0.1.2 are v0.1 conformance,
  and the 23 added since exercise v0.2 behaviour a v0.1-only verifier is required
  to reject.

## [0.1.2] — 2026-07-13

First PyPI release built and published from the hardened OIDC pipeline
(Trusted Publishing + PEP 740 attestations). It rolls up every correctness and
security fix landed after 0.1.0.

### Security / correctness

- Continuity check rejects key-substitution: a candidate signature is verified
  against the candidate's own public key, not the trusted key.
- Strict canonical parser gained a recursion depth cap (DoS guard) and rejects
  lone surrogates; unknown key-status is treated fail-closed.
- Revocation view is bounded (default 10,000 records, injectable) and the
  issuer manifest is verified once per classification instead of per record;
  oversized revocation feeds fail closed for revocable receipts.
- Hardened key/artifact manifest handling, bundle import validation, ULID and
  edition schema strictness, and CLI path-escape defenses.

### Added

- Cross-language regression corpus (conformance vectors 19–25) pinning
  Python↔TypeScript parity.

## [0.1.0] — 2026-07-10

### Added

- Initial release: attest v0.1 reference implementation (signer + verifier,
  JCS canonicalization, Ed25519 via PyNaCl, offline verification, CLI).

[0.1.2]: https://github.com/bernalli/attest/releases/tag/v0.1.2
[0.1.0]: https://github.com/bernalli/attest/releases/tag/attest-verifier-v0.1.0
