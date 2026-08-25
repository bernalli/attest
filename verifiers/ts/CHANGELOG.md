# Changelog

All notable changes to `attest-verifier` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] — 2026-08-25

### Added

- **v0.2 revision 7 — witness federation primitives**, at parity with the
  Python reference. `verify()`'s `options` argument gains `witnessPolicy`:
  supply an `attest-witness-policy-v1` document, and one valid C2SP
  type-`0x04` cosignature from a witness that policy pins — inside a live
  epoch, holding the `corroboration` role — raises `corroboration` from
  `"logged"` to `"witnessed"`, always alongside the warning
  `witness_independence_not_established`. A witnessed result asserts that a
  second party observed a given tree head at a given time: not that the party
  is independent of the log, and not that the log has not branched. Omit the
  policy — the default — and every result is what it was.

  - New module `src/witness.ts`: the closed policy document parsed from bytes
    and canonicalized with attest-JCS; immutable epochs with their validity
    windows; pinned operators whose standing is judged at the instant claimed
    rather than at the verifier's clock; the conflict predicate that retires a
    compromised pin; and the reusable activation-grade quorum primitive
    (`evaluateActivationWitnessQuorum`), which no verification path consumes:
    its callers are the conformance harness and the tests that exercise group
    40, never `verify()`.
  - `src/tlog.ts` parses checkpoint cosignature lines: type `0x04` (Ed25519)
    and the type `0xff` identifier `attest-cosignature-ml-dsa-65-v1` that spec
    §9.2 registers, domain-separated from `attest-ml-dsa-65`.
  - Conformance corpus 97 → **130 leaves across 38 groups**, adding
    `39-witness-corroboration` (13 leaves) and `40-witness-quorum` (20).
  - Failure inside the witness layer is silent by specification: a cosignature
    that does not verify leaves `corroboration` at `"logged"` and adds no
    literal explaining why, so nothing leaks the policy's shape to whoever
    supplied the note.

### Fixed

- `corroboration: "witnessed"` was unreachable through this package's public
  API even once the core could compute it. `verify()` validated a witness
  policy eagerly and then passed the already-parsed object to
  `evaluateTransparency`, which re-validated it with `parsePolicy` — a
  function that accepts raw documents only. The throw landed outside the guard
  for untrusted evidence, so the entire transparency claim collapsed to
  `transparency_claim_unresolvable`: on byte-identical input the Python
  reference reported `logged` where this package reported `not_checked`. Found
  by the shared conformance corpus, which failed all thirteen group-39 leaves
  here while passing them in Python.

### Changed

- This file's history has been reconstructed from git. Each change is now
  attributed to the version whose published artifact contained it, rather than
  to the commit that happened to document it: the section that stood as
  `[Unreleased]` describes what 0.2.0 shipped and now carries that heading,
  even though part of its text was written after that release went out. 0.3.0,
  0.5.0 and 0.6.0 had no section at all and now do. Two counts in the released
  0.4.0 entry had been amended in place after publication and are restored to
  what 0.4.0 actually shipped, with the later leaves credited to 0.5.0.

## [0.6.0] — 2026-08-24

### Changed

- Version bump only, in lockstep with `attest-receipts` 0.6.0. Nothing under
  `src/` changed between 0.5.0 and this release, so no verifier behaviour
  differs.

## [0.5.0] — 2026-08-24

### Fixed

- `auditChain()` enforces `license.not_transferable_before`: a chain link whose
  `transferred_at` predates that floor is rejected (`chain link N: transferred
  before not_transferable_before`), and a record that fails the floor no longer
  competes in the earliest-log-index-wins comparison that resolves a double
  assignment.
- `resolveTransferBacking()` — the path `classifyRevocation()` takes to reach
  `revocation: "transferred"` — deduplicates candidate records by `recordHash()`
  before flagging `transfer_double_assignment_conflict`, keeping the lowest
  index per distinct record. One logged record observed at two indices used to
  read as two competing assignments.

### Added

- The two conformance leaves that accompanied those fixes — a boundary vector
  in `35-transfer` and the count-sweep completion in `36-transfer-chain` —
  taking the corpus this package runs to 97 leaves across the same 36 groups.
  The `[0.4.0]` entry below claimed these counts for a while: it was amended in
  place when these leaves landed, months after 0.4.0 went out. It has been
  restored to the 95 leaves 0.4.0 actually published.

### Changed

- Package `homepage`, `repository` and `bugs` URLs follow the account rename to
  `bernalli/attest`. No behavioural change.

## [0.4.0] — 2026-07-23

### Added

- **v0.2 Stage 3 — issuer-mediated transfer** (`docs/spec/attest-v0.2.md` §17) verify-only
  parity: `src/transfer.ts` builds the same transfer-record verification, holder-authorization
  check, and log-required honoring (consent gate) as the Python reference, over the
  identical closed six-field record profile and `Attest-transfer-authorization-v1`
  domain-separated preimage. `verify()` reports the new reachable `revocation:
  "transferred"` value, capping `ok` the same way `"revoked"` already does, honored for
  every `license.revocability` class once backed by an authenticated
  `holder_authorization` and a logged inclusion proof; unlogged, double-assigned
  (earliest-index-wins), and not-yet-transferable claims resolve to the same warning
  literals as the Python reference (`transfer_record_unlogged`,
  `transfer_double_assignment_conflict`, `transfer_not_yet_transferable`). A separate
  `auditChain` surface walks a whole chain of transfers independent of single-receipt
  `verify()`. A v0.2 receipt with `license.transferable: true` and a null/absent
  `buyer.pubkey` is now a schema error (v0.1 receipts untouched). Closed a
  Python/TypeScript parity divergence in Stage 3 date validation during review. New
  conformance leaf groups `35-transfer` (10 leaves) and `36-transfer-chain` (3 leaves),
  bringing the corpus this package runs to 95 leaves across 36 groups.

## [0.3.0] — 2026-07-23

### Added

- **Normative structural ceilings (G1):** `MAX_ENVELOPE_BYTES` (1,048,576,
  checked before parsing), `MAX_MANIFEST_KEYS` (256) and
  `MAX_ARTIFACT_ENTRIES` (4,096). Input above a ceiling now fails closed with
  its own literal (`envelope exceeds N bytes`, `issuer manifest exceeds N
  keys`) instead of being parsed first.
- **Mixed-keyset prohibition (G6):** `hasActiveEdOnlySibling()` warns
  `mixed_keyset_active_ed_only_sibling` when a v0.2 manifest keeps an active
  Ed25519-only key beside a hybrid one.
- **Artifact-manifest currency (G2/G3):** `TrustStore` gains
  `artifact_manifests` and `artifact_manifest_chains`, with
  `checkArtifactContinuity()` and `artifactChainContinuous()`. A stale,
  discontinuous or unauthenticated artifact manifest reports
  `trust: "unverified_rotation"` or one of `artifact_manifest_issuer_mismatch`,
  `artifact_manifest_unauthenticated`, `artifact_manifest_unversioned`.
- **Anchor profile v2 (G4):** `AnchorVerdict` gains `noteOnly`, and
  `evidence.anchor_profile` selects whether an OpenTimestamps accumulator
  starts from the checkpoint's full signed note (`signed-note-v2`) or from the
  legacy unsigned header alone (`note-v1`, or absent) — warning
  `anchor_note_only`, with a diagnostic replay against the legacy seed on
  mismatch. `Checkpoint` now carries `signedNoteBytes`.
- **Refund-window deadline effectiveness (G5):** `classifyRevocation()` takes
  `logKeys`, `anchorPolicy` and `revocationEvidence`; a Stage-2-capable
  verifier honours a `refund_window` revocation only when that record's own log
  entry is anchored no later than the deadline, and otherwise reports
  `invalid_revocation_ignored` with `revocation_unlogged_deadline`. New
  `recordHash()` export.

### Changed

- Package description names both the v0.1 and the v0.2 profile.

## [0.2.0] — 2026-07-22

### Fixed

- The TypeScript verifier treats an absent key-entry `valid_to` as open-ended, matching the Python reference; spec §7.1 now clarifies `valid_to` is optional.

### Added

- v0.2 hybrid Ed25519+ML-DSA-65 signature profile (`attest_version: "0.2"`):
  `verify()` accepts a two-signature hybrid envelope (`[Ed25519, ML-DSA-65]`,
  fixed order, shared `kid`), verifying both legs over the same
  `JCS(payload)` bytes with AND semantics — either leg failing invalidates
  the receipt. Composite key binding lives in the key manifest (`pub` +
  new `pub_ml_dsa_65`); a hybrid signer's `manifest_signature` gains
  `sig_ml_dsa_65`, AND-verified, fail-closed both ways. ML-DSA-65
  verification uses `@noble/post-quantum` (verify-only leg, no secret keys
  in this package). v0.1 receipts remain valid and verifiable forever; a
  v0.1-only build MUST reject a v0.2 envelope outright. New public spec:
  [`docs/spec/attest-v0.2.md`](../../docs/spec/attest-v0.2.md). New
  conformance leaf group `26-hybrid` (8 leaves).

- v0.2 Stage 2 verification — transparency and anchoring evidence, verify-only
  as everything in this package is. `verify()` gains a sixth `options` argument
  (`transparency`, `logKeys`, `anchorPolicy`); omit it and behaviour is
  unchanged, offline and log-free. Inclusion evidence is checked against a
  hybrid-signed checkpoint and reported as `transparency` / `corroboration`,
  which never upgrade the `trust` verdict — corroboration is not authenticity.
  Log keys come from the caller's pinned trust store, never from the bundle.
  Anchors: OpenTimestamps (required for post-horizon standing) and RFC 3161
  (classical convenience, no weight past a configured CRQC horizon). New
  modules `src/transparency.ts`, `src/tlog.ts`, `src/anchor.ts`. New conformance
  leaf groups `27-valid-to-absent` and `28-transparency`, bringing the corpus
  this package runs to 66 leaves across 29 groups.

## [0.1.2] — 2026-07-13

First npm release from the hardened OIDC pipeline (Trusted Publishing +
provenance). Rolls up the 0.1.1 BOM-rejection fix (never published to npm) and
the revocation-view bound.

### Security / correctness

- Bound the revocation view (`MAX_REVOCATION_RECORDS`, default 10,000, 5th
  `verify` parameter); verify the issuer manifest once per classification;
  fail closed on an oversized revocation view for revocable receipts.
- (from 0.1.1, first time on npm) Reject a leading UTF-8 BOM in the strict
  envelope parser, matching the Python reference.

## [0.1.1] — 2026-07-13

### Fixed

- **Reject a leading UTF-8 BOM in the strict envelope parser** (security /
  cross-implementation parity). The decoder previously used `TextDecoder`
  with the default `ignoreBOM: false`, which silently strips a leading byte
  order mark (`U+FEFF`) before parsing. As a result this verifier **accepted**
  a BOM-prefixed receipt envelope that the Python reference implementation
  (`attest`) **rejects** — two conforming verifiers disagreeing on whether the
  same bytes are valid. The parser now decodes with `ignoreBOM: true`, so the
  BOM survives as `U+FEFF` and is rejected as an unexpected character, matching
  the Python reference and the spec's strict-parser intent.

  This narrows the set of inputs the verifier accepts. Receipts carrying a
  leading BOM were never conformant (the Python reference always rejected
  them), so no legitimate issuer output is affected; the canonical signed bytes
  are unchanged, so this is not a wire-format or protocol change. Surfaced by
  the cross-language regression corpus (conformance vector `21-canon-strict/
  a-bom`).

## [0.1.0] — 2026-07-10

### Added

- Initial release: an independent, from-scratch TypeScript implementation of
  the attest v0.1 verifier — strict JSON parser, JCS-style canonical
  serializer, Ed25519 verification (via `@noble/curves`), key/artifact manifest
  logic, revocation classification, and buyer-binding checks. Verifier-only:
  it reads and validates receipts, never issues, signs, or mutates them.

[0.1.2]: https://github.com/bernalli/attest/releases/tag/v0.1.2
[0.1.1]: https://github.com/bernalli/attest/releases/tag/attest-verifier-v0.1.1
[0.1.0]: https://github.com/bernalli/attest/releases/tag/attest-verifier-v0.1.0
