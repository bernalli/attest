# Changelog

All notable changes to `attest-verifier` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1] — 2026-09-01

### Changed

- **No code change.** This release exists to publish the README already
  corrected in `main` to npm, which freezes the README at whatever it read at
  publish time. The per-surface leaf counts the README used to cite there —
  150/4/20/4 summing to 178 — have already been removed from `main`'s README:
  they move every time the corpus grows, and a number no test defends goes
  stale without anyone noticing. Behavior is unchanged from 0.9.0.

## [0.9.0] — 2026-08-31

### Added

- **`authorityView`, the publisher-authority rail of attest-v0.2 section 20.**
  An array of publisher authorization manifests supplied by the caller, judged
  by `evaluateAuthority` in the same evaluation order the Python
  implementation follows, and surfaced as two new components of the result,
  `publisher_authority` and `publisher_authority_trust`. Neither touches `ok` or
  `trust`: whether a seller was entitled to sell is a fact about the seller,
  not a validity property of the receipt. Absent, malformed, stale or
  ambiguous evidence gives `unattested` — never `authorized`, and never
  `unauthorized` unless the caller supplies its own proof of currency.

- **`compromiseView`, the anchored-cutoff rescue for compromised signing keys.**
  A Stage-2-capable verifier may now keep a receipt valid when its own
  signed-receipt-core reached anchored standing and either no anchored cutoff is
  established or that standing predates the cutoff; receipts without anchored
  standing, or at or after the cutoff, still fail closed. Compromise markings
  are absorbing across every manifest the verifier holds: once a kid has been
  seen compromised, a later manifest cannot silently relist it as active or drop
  it to undo that floor.

- **A publisher-claim floor on v0.1 receipts**, warning when a receipt names a
  publisher it cannot substantiate, independent of the protocol version.

### Fixed

- **Two evidence rails read the caller's live object a second time, after the
  bytes had already been signed and checked.** A value can answer differently
  on the second read, so the bytes that verified and the values that decided
  were not necessarily the same — which lets an attacker with no key at all
  take a document an honest third party genuinely signed and make the verifier
  act on something else. Both rails are now admitted once, at entry, per
  element, through the single shared boundary, and only the reconstruction is
  read afterwards. **Upgrade from 0.8.1 or earlier.**

- **Ambiguous key manifests no longer verify by array order.** `keys[]` may not
  list one `kid` twice; the verifier rejects the manifest before resolving any
  signing key, including when the duplicate is unrelated to the receipt's own
  signature. Key-manifest continuity also preserves the compromised-status floor
  instead of letting a later manifest undo it.

- **`not_revoked_as_of:` now counts only authenticated revocation statements.**
  Signed records carrying an unregistered `status` no longer inflate the
  freshness timestamp reported for every receipt in the revocation view.

- **A parity divergence in the shared canonicalization sink.** One
  implementation measured the admission ceiling including the depth probe and
  the other subtracted it, so the same evidence was admitted by one core and
  refused by the other — a unit refused for the position it occupied rather
  than for any property of its own. The property is now pinned in both
  languages.

### Changed

- **The OTS op-chain caps, raised in step with `attest-receipts`.** Real
  OpenTimestamps attestations exceed the bounds this verifier shipped with —
  measured on upstream example files, a genuine Bitcoin path carries 100
  operations against a cap of 64, and a genuine operand is 3432 bytes against a
  cap of 1024. The per-proof operation cap is now 256, the per-operand cap
  16384 hex characters, and a per-chain operand TOTAL of 65536 hex characters
  bounds them together so the raised inner caps stay inside the normative outer
  admission ceiling. Values and refusal points are identical to the Python
  implementation, which is the property that matters here: a proof either
  language admits, the other admits.

- **The harmonization guard now derives every bound it claims to harmonize.**
  It previously hardcoded the operand size, the operation count, the proof
  count and the outer ceiling, so it stayed green straight through a cap change
  while its Python twin — which derives them — failed immediately. A test that
  does not read the constants it harmonizes is not enforcing the invariant its
  name claims. It also sits at the worst case on both binding axes now, rather
  than filling one and asserting an upper bound on the other.

- **`canonicalBytes` enforces the 256-level nesting-depth ceiling**, in parity
  with the Python implementation and with the profile's own parser: one level
  past it throws `CanonError` with the same literal the parser uses, so a
  conforming issuer cannot produce bytes no conforming parser accepts. Deep or
  cyclic input from a caller now fails as a `CanonError` at the ceiling instead
  of overflowing the native stack with a `RangeError`.

## [0.8.1] — 2026-08-26

Version bump only, to keep the two implementations in lockstep. No change to
the verifier: this release accompanies a demonstration of the Stage 4
preservation pledge — an archive gate that hands a work back to a receipt
holder once a sunset grant has been activated — which lives in the Python
package's `demo/` directory and is not part of any published API.

## [0.8.0] — 2026-08-25

### Added

- **v0.2 revision 8 — Stage 4, the preservation pledge**, at parity with the
  Python reference. A rights holder can sign a commitment that, once a
  verifiable trigger fires, converts into a machine-checkable permission for a
  receipt's holder to obtain an unprotected copy of the work. `verify()`'s
  `options` argument gains `grantView`; supply the evidence object and the
  result carries two new components, `grant` and `grant_trust`. Omit it — the
  default — and every result is byte-for-byte what it was.

  Neither component ever touches `signature`, `schema`, `revocation`,
  `binding`, `trust`, or `ok`. `isOk` is unchanged, deliberately and
  normatively: a grant is a permission that becomes exercisable, never a
  validity property of the receipt. An invalid grant on a good receipt leaves
  that receipt good.

  - New module `src/grant.ts`. The §18 primitives first: the closed,
    hybrid-signed sunset grant and cessation declaration, authenticated under
    the same §13 AND-rule every other v0.2 side-document uses; the two
    coverage predicates §18.4 keeps deliberately apart, one comparing two
    documents of the same shape and one comparing a grant against a receipt's
    older `work` block; the floor-relative non-narrowing ratchet, which a
    later version can widen and can never narrow; and the structural ceilings,
    which count and never inspect, so they can run before any signature does.
  - `evaluateGrant` implements §18.4's eleven ordered steps, short-circuiting
    in one direction only. Its first three steps read the signed payload alone
    and run *before* the "no evidence supplied" exit, so a defect visible in
    the receipt itself is never masked by evidence a caller happened not to
    attach. Scope coverage at step 8 is a gate rather than a note: an
    uncovered receipt resolves `dormant` without either activation path
    running, because telling a holder they may redeem something the grant
    never spoke about would contradict §18.7's own custodian precondition. The
    declaration scan at step 9 is exhaustive rather than first-match, so the
    warning set is a function of the evidence and not of its arrangement. The
    `fixed-date` proof at step 10 reduces to the **maximum** over verified
    anchors, the opposite of §11's `anchored_before` and for the opposite
    question: "has time reached T?" is answered conservatively by the latest
    verified header, and the minimum would let one stale genuine proof hold a
    grant closed forever.
  - `verifyRedemption` (§18.7): the audience-bound holder proof, over a
    preimage that names the custodian precisely so a response produced for one
    is not replayable at another. Salt disclosure is not accepted as a
    redemption proof and this module offers no way to spell one — §18.7
    prohibits it normatively, being a replayable bearer proof that also hands
    over the identifier.
  - `src/tlog.ts` gains the fifth transparency-log entry type,
    `cessation-declaration`. Unlike `transfer-record` it is never
    load-bearing: logging a declaration is recommended for discoverability and
    for a date opposable to third parties, but an authenticated declaration
    activates a grant whether or not it was ever logged. Nobody gains by
    hiding one.
  - `src/schema.ts` gains the `license.preservation_pledge` term — three
    required members, and deliberately *not* a closed object, so a future
    pledge profile needing a fourth is not a schema error on a verifier that
    predates it — plus `work.publisher_id` and §18.6's holder-binding
    conditional: a v0.2 receipt carrying the pledge must also carry a non-null
    `buyer.pubkey`, a `work.publisher_id`, and
    `survivability.end_of_life == "sunset-grant"`. The holder key is the
    load-bearing one. Without it "holder" degenerates to whoever possesses the
    file, and the grant becomes indistinguishable from publishing the work
    outright. v0.1 receipts are untouched.
  - Conformance corpus 130 → **158 leaves across 40 groups**, adding
    `37-preservation-pledge` (24 leaves) and `38-redemption` (4). The
    redemption group is a fourth surface, alongside `verify()`, `auditChain`
    and the quorum evaluator: no receipt, no trust store, no grant document,
    only whether a holder's proof is good for one named custodian.

### Fixed

- Four defects that a single implementation cannot see, found by carrying §18
  into this package and comparing against the Python reference on
  byte-identical input, and by independent review of the pair. None is
  reachable from either core alone, which is the whole argument for writing
  the second one.

  - **Sorted-array checks ordered by UTF-16 code unit, not by code point.**
    §18.2 requires `permissions`, `activation.modes`, `scope.artifacts` and
    `activation.successor_ids` to arrive sorted and duplicate-free, and states
    that over Unicode. JavaScript's `<` compares strings by UTF-16 code unit;
    Python's compares by code point. The two disagree exactly on an astral
    character against U+E000–U+FFFF, because a surrogate pair begins at
    0xD800 — so this package would have *accepted* grants the reference
    rejects and *rejected* grants it accepts, on the same bytes. `modes` and
    `permissions` admit any non-empty string, so the disagreement is
    attacker-reachable with a hand-built document rather than theoretical.
    `src/grant.ts` now compares by code point explicitly, and two tests pin
    both directions, each asserting that raw `<` says the opposite.
  - **A grant naming no prose at all could reach `activated`.** §18.2 types
    `legal_text_uri` as "string, non-empty"; the shape check accepted any
    string, `""` included. Shape is checked *before* the signature and the
    evaluation then runs on through the ratchet, the scope gate and the
    declaration scan, so a publisher could sign such a grant, hash-bind it
    into a receipt, supply a valid cessation declaration and open it — a false
    `activated`, which authorizes distribution of a work that is still on
    sale and is the single direction §18.4 declares normatively forbidden.
    Both prose-bearing members now go through the same non-empty predicate as
    their neighbour `jurisdiction`. Found by review on the Python reference
    and present here identically, this package having mirrored it; corpus leaf
    `37-preservation-pledge/w-empty-legal-text-uri` now pins it for any third
    implementation.
  - **The `bigint`/`number` boundary between a signed document and the
    evidence beside it.** This package parses signed documents strictly, with
    JSON integers as `bigint`, because they have to re-canonicalize; it hands
    untrusted evidence to the §11 anchor evaluator in the materialized,
    plain-`number` form that evaluator requires. Stage 4's evidence object is
    the first place both meet inside one file: the grant documents need the
    first representation, the anchor bundle nested beside them needs the
    second. The `fixed-date` proof was handed across without conversion, so
    every proof arriving as real wire JSON was rejected on `header_time` being
    a `bigint`, and the grant stayed `dormant` forever — while the negative
    cases still passed, for the wrong reason. It survived unit testing because
    the fixtures were hand-built JavaScript literals, a shape no document on
    the wire can produce; the shared corpus caught it on the first run, which
    is what the corpus is for.
  - **`grant_trust` read from the supplied document's signer, not from the
    receipt's publisher.** §18.5 scopes the ladder to the trust store's
    provenance for the resolved `work.publisher_id`; this package keyed it on
    the `kid` of the grant in the evidence object, before that grant
    authenticates against anything. A caller could therefore name any domain
    the verifier happens to know over domain control, attach a document that
    authenticates against nothing, and be handed `grant_trust: "verified"` for
    the price of appending bytes — the upward direction on the trust scale
    that §18.4/§18.5 forbid to unauthenticated evidence. The Python reference
    was corrected in the same review round and this package mirrored the
    earlier shape, so the two disagreed on identical input; neither the
    signer-mismatch leaf (its foreign grant *does* authenticate, so it reaches
    the later override) nor the TOFU leaf (signer and publisher are the same
    domain there) could see it. Corpus leaf
    `37-preservation-pledge/x-trust-not-borrowed-from-signer` now pins it for
    any third implementation.

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
