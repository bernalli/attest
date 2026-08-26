# Changelog

All notable changes to `attest-receipts` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The stale conformance numbers the 0.8.1 fix did not reach.** That fix
  corrected the README and the certification table; a census of every artefact a
  human reads found six more, in five files, all saying the corpus is smaller
  than it is: `CONTRIBUTING.md` (130 leaves / 38 groups, plus two suite counts
  frozen at 2048 and 876), the README's own v0.1 subset (51 where the paragraph
  above says 52), `docs/spec/vectors/README.md` (157), the standards annex and
  the threat model (130-leaf corpus, twice each), and two more in
  `docs/conformance.md`. Measured rather than edited: the corpus holds **158
  leaves across 40 groups**, the v0.1 subset **52**, and the suites run **2484**
  Python and **1231** TypeScript tests. The `130` in `verifiers/ts/README.md` is
  left alone — there it is the share of leaves routed to `verify()`, one term of
  a partition that sums to 158. (The TypeScript guard test pins the sum and the
  redemption surface, not each individual share; the README said otherwise and
  now says this.)

### Added

- **A guard against the corpus counts going stale, and an honest account of
  what it does not cover.** `tools/check_spec_docs.py` measures the corpus on
  disk — reusing `conformance_runner`'s own discovery and v0.1 subset rule
  rather than restating them — and fails on any Markdown file whose stated leaf
  count, group count or subset size disagrees. It scans every `.md` rather than
  a fixed list, because the numbers that went stale were in files nobody would
  have listed, and it matches with newlines folded to spaces, since one version
  of it was blind to a claim wrapped across two lines.

  It recognises the claim shapes it has been taught, so a count phrased a new
  way still passes: this narrows the gap, it does not close it. Judging every
  figure near the corpus vocabulary was tried and abandoned — technical prose
  is dense with numbers beside the word "leaves" that are byte sizes, RFC
  numbers and section numbers, and that version reported 36 of them. Removing
  the hand-written numbers from the documents is the design that closes this,
  and it is its own task. The shapes are pinned by unit tests, so the next
  edit to the patterns fails here rather than in a release.
- Two more stale counts a hand review caught after the guard's first draft, in
  places the draft could not see: v0.1 §15 still measured a v0.1-only verifier
  against a 51-leaf subset and told a v0.2 implementation to reproduce all 130,
  and the conformance document still called the v0.2 subset "currently 156".
  Both are corrected, v0.1 §15's group list gains the two v0.2 groups that
  shipped without being named there, and the guard learned the two shapes it
  had missed — it now reports exactly those three claims when they are wrong.
- The two suite counts are gone from `CONTRIBUTING.md` instead of being
  guarded: a number that changes with every merged test teaches nothing and
  would fail CI on every green PR.

## [0.8.1] — 2026-08-26

### Added

- **A second demo, `demo/pledge_dies.py`, and the archive gate it runs
  against.** Stage 4 shipped the mechanism in 0.8.0; this is the mechanism
  actually running, end to end, from a shell. A rights holder signs a sunset
  grant at the time of sale, the store dies, the trigger fires, and an archive
  that kept its own copy hands it over — but only against a valid receipt, an
  activated grant, and an audience-bound proof of possession. Both triggers are
  demonstrated: `publisher-declaration`, and `fixed-date` for when nobody is
  left to declare, including the negative half where the backstop has not yet
  been reached and the grant stays shut.

- `demo/custodian.py`, a **non-normative reference** for the §18.7 gate. It is
  deliberately outside the installed package, outside the conformance surface,
  and has no CLI verb: attest defines a receipt format and a verifier, and does
  not distribute content. Every check that verifies, authenticates or signs is
  delegated to the real CLI. What the module adds is what the CLI cannot: the
  gate mints its own redemption challenges, remembers them, and spends each on
  the single request that uses it, so a captured transcript is worth exactly
  one attempt. Both files the requester owns are frozen for the length of a
  call, because a path read more than once is a path that can change between
  reads.

- `demo/_driver.py`, the CLI helpers both demos share, and the canonical way to
  run either: `python -m demo.<name>` from the repository root.

### Changed

- CI now executes both demos as scripts, not only through their pytest
  wrappers. Running from a shell is the claim being made, and a claim nothing
  executes decays quietly.

### Fixed

- **The public conformance claim was stale, and said two different things.**
  The README claimed 130/130 in one place and 158 leaves in two others, and
  `docs/conformance.md` — whose table is explicitly a CURRENT claim, not a
  changelog — still carried 0.6.0 rows measured against a corpus revision two
  growth steps behind. All four rows are re-measured, not edited: Python and
  TypeScript both pass 158/158 on the v0.2 subset and 52/52 on v0.1, against
  corpus revision `a74f7f3c…`, through the documented command.

## [0.8.0] — 2026-08-25

### Added

- **v0.2 revision 8 — Stage 4, the preservation pledge.** The standard way for
  a rights holder to say "if I disappear, the file becomes redistributable and
  the receipt stays the proof". A new licence term, `license.preservation_pledge`,
  hash-binds a signed *sunset grant* — an eleven-member document the RIGHTS
  HOLDER signs, not the store — and once a verifiable trigger fires, that grant
  converts into a machine-checkable permission for the receipt's holder to
  obtain an unprotected copy.

  - New module `attest.grant`: the grant document and the cessation
    declaration, both hybrid-signed under the §13 AND-rule; the two coverage
    predicates, written separately and deliberately not in terms of one
    another; the floor-relative non-narrowing ratchet; the structural ceilings;
    and the audience-bound redemption proof.
  - `verify()` accepts `grant_view=` and reports two new components, `grant`
    and `grant_trust`. Both are purely informational and take NO exception:
    neither ever affects `signature`, `schema`, `revocation`, `binding`,
    `trust` or `ok` — a grant is a permission that becomes exercisable, never
    a validity property of the receipt. A caller that never supplies the
    channel gets a byte-for-byte unchanged result.
  - `attest.verify.evaluate_grant` implements §18.4's ordered, short-circuiting
    evaluation on its own, so a custodian checking §18.7's preconditions can
    ask the question without re-verifying a receipt it has already verified.
  - New CLI group `attest grant`, five verbs across three parties:
    `issue`/`declare` for the rights holder, `challenge`/`verify` for the
    custodian, `respond` for the holder. `attest verify --grant-view <file>` is
    where grant evaluation lives, next to every other verdict. The redemption
    nonce is generated inside `challenge` and never read from a flag — one a
    caller can choose is one a caller can replay.
  - Conformance corpus 130 → **158 leaves across 40 groups**, adding
    `37-preservation-pledge` (24 leaves) and `38-redemption` (4), each executed
    by all three runners from the same golden files. The v0.1 subset grows
    51 → 52: leaf `37s` is an `attest_version: "0.1"` receipt by construction,
    the negative control proving §18.6's conditional never touches v0.1.

  **Activation is established by POSITIVE evidence, never by an absence.** An
  earlier design opened a grant when no recent proof-of-distribution appeared
  in a transparency log; that design is unsound and the flaw sits at the level
  of the idea rather than of the wording, because anchoring bounds a
  checkpoint's age only from above. It is abandoned and registered `reserved`.
  The two modes that ship are a signed cessation declaration and an anchored
  fixed date, and the residual they leave — a publisher who simply vanishes,
  signing nothing and setting no date — is stated in the threat model rather
  than hidden.

  **Which way this fails is normative.** A false `activated` would authorize
  distribution of a work that is still on sale; a false `dormant` only means a
  buyer cannot yet redeem. Every missing, unverifiable, malformed or ambiguous
  input therefore resolves to `dormant` or `not_checked`.

### Fixed

- Two ways the two implementations could have disagreed on identical bytes,
  both found by porting §18 to TypeScript and neither visible from one side
  alone: "sorted" now means by Unicode **code point**, which UTF-16 code-unit
  order contradicts for astral characters — reachable through `permissions`
  and `modes`, which carry unregistered values rather than rejecting them —
  and the boundary between a strictly-parsed signed document and materialized
  untrusted evidence, which the fixed-date anchor path crossed in the wrong
  direction.
- `attest-bridge itch-dry-run` could report "no receipt issued" about a race
  inside itself. The command read the clock twice — once for the synthetic
  purchase and the poller, once inside `enqueue_claim` — and built the Ledger
  between the two reads, so a loaded machine could land the second one in the
  next whole second. The claim's `next_attempt_at` then sat one second ahead
  of the `now` the poller queried with, `due_claims` returned nothing, and the
  claim was never drained: no receipt, and no dead letter either, because
  nothing entered the loop that records one — leaving the merchant with a
  failure message about their own setup and nothing to act on. One clock read
  now serves the whole command, which is what `attest_bridge.ledger`'s own
  contract ("timestamps are always caller-supplied; this module never reads a
  clock") assumes of its callers.
- A third divergence, found by independent review of the pair and present only
  in the TypeScript verifier, which had mirrored this package's earlier shape:
  `grant_trust` keyed on the `kid` of the supplied grant instead of on the
  receipt's `work.publisher_id` (§18.5), which would hand unauthenticated
  evidence the top of the trust scale. Corrected there; corpus leaf
  `37-preservation-pledge/x-trust-not-borrowed-from-signer` pins it here too,
  so no third implementation can reintroduce it.

## [0.7.0] — 2026-08-25

### Added

- **v0.2 revision 7 — witness federation primitives.**
  `corroboration: "witnessed"` is reachable for the first time. Supply a witness
  policy, and one valid C2SP type-`0x04` cosignature from a witness that policy
  pins — inside a live epoch, holding the `corroboration` role — raises
  `corroboration` from `"logged"` to `"witnessed"`. It is always reported
  together with the warning `witness_independence_not_established`, because a
  witnessed result asserts that a second party observed a given tree head at a
  given time and nothing else: not that the party is independent of the log, and
  not that the log has not branched (spec §10.1, §15 item 1). Supply no policy —
  the default — and every result is byte-for-byte what it was before.

  - New module `attest.witness`: the closed `attest-witness-policy-v1` document,
    parsed from bytes and canonicalized with attest-JCS; immutable epochs with
    their validity windows; pinned operators with roles and per-pin standing
    judged at the instant claimed rather than at the verifier's clock; the
    conflict predicate that retires a compromised pin; and the reusable
    activation-grade quorum primitive.
  - `verify()` and `evaluate_transparency()` accept `witness_policy=`, and the
    CLI accepts `attest verify --witness-policy <file>`. The document is read as
    bytes under the existing Stage 2 input ceiling and refused as trusted-config
    on any malformation, never silently degraded — by the CLI when it loads the
    file, and by `evaluate_transparency()` unconditionally. `verify()` reaches
    that validation only when it actually evaluates a transparency claim: given
    no evidence, or incomplete Stage 2 configuration, it returns the unchanged
    result without inspecting the policy.
  - `attest.tlog` parses checkpoint cosignature lines: C2SP type `0x04`
    (Ed25519) and the type `0xff` identifier `attest-cosignature-ml-dsa-65-v1`
    that §9.2 registers, domain-separated from `attest-ml-dsa-65`.
  - An activation-grade hybrid quorum primitive (§11.4): both legs must verify
    over the same note, one vote per `control_group`, the committee ceiling
    applied before any signature verification, and explicit temporal boundaries.
    No verification path consumes it: nothing in `verify()`, in revocation, in
    transfer or in the bridge calls it. Its callers are the conformance
    harness — the vector generator, both language adapters and the site
    runner — and the tests that exercise group 40.
  - Conformance corpus 97 → **130 leaves across 38 groups**, adding
    `39-witness-corroboration` (13 leaves) and `40-witness-quorum` (20), each
    executed by all three runners — Python reference, TypeScript verifier, site
    adapter — from the same golden files.

  Failure inside the witness layer is deliberately SILENT (§11.4): a cosignature
  that does not verify leaves `corroboration` at `"logged"` and adds no literal
  saying why, because a verifier that explained itself would leak the policy's
  shape to whoever supplied the note.

- A reference witness under `witness/`, runnable for tests and demonstration:
  the C2SP `add-checkpoint` protocol over WSGI, a configured origin allowlist,
  an append-only store, and a CLI. **It is not published and belongs to neither
  package** — §11.4 keeps an operator's component out of the public artifacts,
  and `tools/assert_artifacts.py` now fails a build that ships it.

### Changed

- The published sdist no longer carries `bridge/`'s neighbour `witness/`:
  hatchling's sdist default is everything not gitignored, so the exclusion is
  stated (`[tool.hatch.build.targets.sdist] exclude = ["/witness"]`) and pinned
  by an artifact assertion instead of left to a default.
- Threat model: §6.2 rewritten — revision 7 closes the format half of witness
  federation, and the section's own prohibition on emitting
  `corroboration: "witnessed"` is superseded by spec §10.1. What keeps the
  section open is now stated as operational rather than editorial: no
  independently run witness exists, and the policy packaged with the verifiers
  is empty. TM-49 stays **Out of scope** and open, reformulated around
  observation not being prevention; TM-34, TM-60 and the §6.3 rows follow.
- Spec §1 corrected: it still carried the pre-revision-7 sentence forbidding
  `corroboration: "witnessed"` outright — a contradiction with §10.1 in the same
  document — still called Stage 2b's format forthcoming, and still named only
  Stage 1 and Stage 2, omitting Stage 3 (rev 6).
- `docs/faq.md` no longer tells readers the witnessed verdict "requires a
  witness federation that does not exist yet", and states the real residual
  instead.

## [0.6.0] — 2026-08-24

### Changed

- **Breaking (CLI):** outputs whose loss is irrecoverable — key seeds
  (`keygen --seed-out`/`--mldsa-out`), issuer key manifests
  (`manifest init`/`rotate --out`), issued envelopes and salts
  (`issue --out`/`--salt-out`), transfer and revocation records
  (`transfer record --out`/`--revocation-out`), exported `.private.attest`,
  and imported trust-store files and `salts.json` — now refuse to overwrite an
  existing file whose content differs from what would be written (exit 2,
  naming the path and the reason), under a single write-if-absent-or-identical
  rule. Byte-identical rewrites still succeed, so re-running `attest import`
  on the same bundle stays idempotent. Every affected command gains `--force`,
  which authorizes replacing *different content* — it does not lift the
  structural refusals: a target that is a directory, a symlink (a dangling one
  included), or a regular file carrying more than one hard link is refused
  unconditionally, `--force` and all, because in each of those cases the bytes
  would land somewhere other than the path the caller named. A target swapped
  for another file between the check and the write is refused as well, instead
  of being truncated. Derivable outputs
  (`--pub-out`, artifact manifests, the shareable `.attest`, imported
  receipts/proofs/legal texts, `log prove`/`log anchor` evidence, and the
  bridge's `itch-dry-run` receipt) are deliberately not gated.
- **Breaking (CLI):** `attest import` now rejects two bundles it used to
  accept: one whose issuers sanitize to the same trust-store filename (the
  second anchor would destroy the first within a single run), and one carrying
  a key manifest whose `manifest_version` is not an integer `>= 1` — that value
  names the trust-store file, so it is validated before any path is built.
- **Breaking (CLI):** `attest disclose --out` refuses a symlink named as the
  output path, including a dangling one and one pointing at a directory. The
  disclosed file carries `delivery.salt`, so writing it through a link someone
  else planted is a disclosure. The refusal covers the path you name, not its
  parent directories: if a *parent* component is a symlink someone else
  controls, the disclosure still lands under their target — write disclosures
  only into directories whose whole path you control. There is deliberately no
  `--force` counterpart here: the disclosure is recomputable from the receipt,
  the manifest and the salt, so the answer to a refusal is to name another
  path. A hard-linked target is still written — every alias of that inode
  already holds the same secret, so refusing would break callers for no gain.

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
