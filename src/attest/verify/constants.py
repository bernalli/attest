"""The verifier's fixed vocabulary: result values, wire warning literals and
ceilings.

Every literal here is a cross-language wire string (TS parity: messages.ts) or
a ceiling defined by the module that owns its rail. Nothing in this module
decides anything; it only names what the deciding modules report.
"""

from __future__ import annotations

from attest import canon, revocation, transfer

_ALG = "Ed25519"  # hard-coded — never selected from any field, mirrors issue.py
_SUPPORTED_ATTEST_VERSIONS = frozenset({"0.1", "0.2"})
# attest-versioning.md §6.7: v0.1's three seed values plus `sunset-grant`,
# registered `active` by v0.2 §18 — the label a Stage 4 receipt carries, while
# the commitment itself is hash-bound by `license.preservation_pledge` (§18.2).
# The vocabulary stays OPEN (v0.1 §5.6): registering a value assigns it meaning
# to a Stage-4-capable verifier and stops it being reported as unknown; it does
# not close the field, and an unrecognized value remains valid-with-warning.
_KNOWN_EOL_VALUES = frozenset({"artifacts-remain-redownloadable", "escrow", "none", "sunset-grant"})

# attest-versioning.md §6.10: the sole preservation-pledge profile v0.2 §18
# defines. Open and versioned, following §6.7's discipline — an unrecognized
# `license.preservation_pledge.pledge` is never a schema error. It is also
# never evaluated under `sunset-grant-v1`'s rules (§18.4 step 2, warning
# `grant_pledge_type_unknown`): a later profile may attach different meaning to
# the same members, and guessing is exactly how two conforming implementations
# reach different verdicts on identical input.
_KNOWN_PLEDGE_TYPES = frozenset({"sunset-grant-v1"})

_STATUS_ACTIVE = "active"
_STATUS_COMPROMISED = "compromised"
_STATUS_RETIRED = "retired"

_PROVENANCE_TLS = "tls"

_TRUST_VERIFIED = "verified"
_TRUST_TOFU = "unauthenticated_tofu"
_TRUST_UNVERIFIED_ROTATION = "unverified_rotation"

_SIG_VALID = "valid"
_SIG_INVALID = "invalid"
_SCHEMA_VALID = "valid"
_SCHEMA_INVALID = "invalid"
_SCHEMA_NOT_CHECKED = "not_checked"

_REVOCATION_UNKNOWN = "unknown"
_REVOCATION_REVOKED = "revoked"
_REVOCATION_INVALID_IGNORED = "invalid_revocation_ignored"
_REVOCATION_NOT_REVOKED_PREFIX = "not_revoked_as_of:"

# Preflight bound on the untrusted revocation view (review improvement #17),
# defined by the module that owns the rail and injectable per call via
# `verify(..., max_revocation_records=...)`.
_MAX_REVOCATION_RECORDS = revocation.MAX_REVOCATION_RECORDS

_REVOCABILITY_NONE = "none"
_REVOCABILITY_REFUND_WINDOW = "refund_window"
_REVOCABILITY_POLICY = "policy"

_RECORD_STATUS_REVOKED = "revoked"

# v0.2 Stage 3 (§17, issuer-mediated transfer): old-receipt extinguishment via
# a `status: "transferred"` revocation record, honored only when BACKED by an
# authenticated, log-included transfer record (§17.3's key-authorization gate). The
# literal is deliberately reused for both the record's own `status` field and
# the reachable `revocation` result value — mirrors `_RECORD_STATUS_REVOKED`/
# `_REVOCATION_REVOKED`'s existing dual use above.
_REVOCATION_TRANSFERRED = "transferred"

# v0.1 §12.3 (2026-08-26 amendment): only records whose status is a REGISTERED
# revocation-statement literal may drive the freshness anchor T. Any other
# status "is not a revocation statement" (§12) — and a non-statement must not
# inflate the feed's reported freshness either (V-L.5).
_ANCHOR_STATUSES = frozenset({_RECORD_STATUS_REVOKED, _REVOCATION_TRANSFERRED})

# V-L.8 (design vector "publisher authority"): `work.publisher_id` is an
# unattested claim under v0.1 alone — no manifest resolution or grant
# evaluation backs it — so a receipt asserting a rights holder distinct from
# its own issuer gets a warning, never an exception (TS parity: messages.ts).
_WARN_PUBLISHER_CLAIM_UNATTESTED = "publisher_claim_unattested"

# Fixed literals (v0.2 §17.2-§17.4, verbatim; TS parity: messages.ts).
_WARN_TRANSFERRED_REVOCATION_UNBACKED = "transferred_revocation_unbacked"
_WARN_TRANSFER_RECORD_UNLOGGED = "transfer_record_unlogged"
_WARN_TRANSFER_NOT_YET_TRANSFERABLE = "transfer_not_yet_transferable"
_WARN_TRANSFER_DOUBLE_ASSIGNMENT = "transfer_double_assignment_conflict"

_BINDING_PROVEN = "proven"
_BINDING_NOT_PROVEN = "not_proven"
_BINDING_NOT_CHECKED = "not_checked"

# Stage 2 (design doc "transparency/corroboration layer"): three new,
# purely informational result components. Defaults are the ZERO-behavior-
# change values existing callers already implicitly get (Task 5's one
# non-negotiable constraint) — see `VerificationResult` and `verify()`.
_TRANSPARENCY_NOT_CHECKED = "not_checked"
_CORROBORATION_NONE = "none"
_MANIFEST_FRESHNESS_NOT_CHECKED = "not_checked"

_CLAIM_TYPE_RECEIPT = "receipt"
_CLAIM_TYPE_KEY_MANIFEST = "key-manifest"
_CLAIM_TYPE_REVOCATION_RECORD = "revocation-record"

_WARN_TRANSPARENCY_CONFIG_MISSING = "transparency_config_missing"
_WARN_TRANSPARENCY_CLAIM_UNRESOLVABLE = "transparency_claim_unresolvable"
_WARN_ROTATION_CHAIN_REQUIRED = "corroboration_requires_rotation_chain"

# G5 (v0.2 §8/§15 amendment, TM-47): a refund_window revocation record that
# fails the deadline-effectiveness rule (unlogged, or logged/anchored after
# the receipt's own refund-window deadline) — exact, cross-language wire
# string (TS parity: messages.ts).
_WARN_REVOCATION_UNLOGGED_DEADLINE = "revocation_unlogged_deadline"
_ANCHORED_BEFORE_PREFIX = "anchored_before:"

# v0.1 rev 8 / v0.2 §19 anchored compromise cutoff.
_WARN_COMPROMISE_RESCUE_APPLIED = "compromise_rescue_applied"
_WARN_COMPROMISE_CUTOFF_UNANCHORED = "compromise_cutoff_unanchored"
_WARN_COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT = "compromise_rescue_requires_anchored_receipt"
_WARN_COMPROMISE_RESCUE_RECEIPT_AFTER_CUTOFF = "compromise_rescue_receipt_after_cutoff"
_WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED = "compromise_cutoff_claim_ignored"
_WARN_COMPROMISE_MARKING_RETRACTED = "compromise_marking_retracted"
_MAX_COMPROMISE_CLAIMS = 64
# Same ceiling shape as the compromise rail, defined by the module that owns
# the rail: `transfer.audit_chain()` admits the same view against the same
# number, and a ceiling restated in two places is a ceiling that will drift.
_MAX_TRANSFER_CLAIMS = transfer.MAX_TRANSFER_CLAIMS

# G6 mixed-keyset prohibition (v0.2 §2.3/§13 amendment) — the wire warning
# string, exact and cross-language (TS parity: messages.ts).
_WARN_MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING = "mixed_keyset_active_ed_only_sibling"

# G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
# amendment) — the wire warning string for a legacy (no `manifest_version`)
# artifact manifest resolved for the receipt's `work.artifact_series`, exact
# and cross-language (TS parity: messages.ts).
_WARN_ARTIFACT_MANIFEST_UNVERSIONED = "artifact_manifest_unversioned"
_WARN_ARTIFACT_MANIFEST_UNAUTHENTICATED = "artifact_manifest_unauthenticated"
_WARN_ARTIFACT_MANIFEST_ISSUER_MISMATCH = "artifact_manifest_issuer_mismatch"

# v0.2 Stage 4 (§18, the preservation pledge): two new, PURELY informational
# result components. Per D6 they take no exception at all — neither ever
# affects `signature`, `schema`, `revocation`, `binding`, `trust` or `ok`,
# because a grant is a permission that becomes exercisable, never a validity
# property of the receipt. Defaults are the ZERO-behavior-change values every
# pre-Stage-4 caller already implicitly gets.
_GRANT_NOT_CHECKED = "not_checked"
_GRANT_NONE = "none"
_GRANT_DORMANT = "dormant"
_GRANT_ACTIVATED = "activated"
_GRANT_INVALID_IGNORED = "invalid_grant_ignored"

# §18.5: `grant_trust` reuses the three `trust` values verbatim (v0.1 §11.1)
# and adds exactly one — the case v0.1's ladder has no way to express: a
# well-formed, well-signed document from a domain that is not the declared
# rights holder.
_GRANT_TRUST_NOT_CHECKED = "not_checked"
_GRANT_TRUST_SIGNER_MISMATCH = "signer_mismatch"

# The ten warning literals of §18.5, verbatim and cross-language (TS parity:
# messages.ts).
_WARN_GRANT_NARROWING_IGNORED = "grant_narrowing_ignored"
_WARN_GRANT_UNANCHORED = "grant_unanchored"
_WARN_GRANT_SIGNER_NOT_PUBLISHER = "grant_signer_not_publisher"
_WARN_GRANT_SCOPE_UNCOVERED = "grant_scope_uncovered"
_WARN_GRANT_COMMITMENT_MISMATCH = "grant_commitment_mismatch"
_WARN_GRANT_COMMITMENT_DIVERGENCE = "grant_commitment_divergence"
_WARN_GRANT_DECLARATION_IGNORED = "grant_declaration_ignored"
_WARN_GRANT_ACTIVATED_BY_SUCCESSOR = "grant_activated_by_successor"
_WARN_GRANT_PLEDGE_TYPE_UNKNOWN = "grant_pledge_type_unknown"
_WARN_GRANT_LEGAL_TEXT_CHANGED = "grant_legal_text_changed"

_AUTHORITY_NOT_CHECKED = "not_checked"
_AUTHORITY_NO_CLAIM = "no_publisher_claim"
_AUTHORITY_SELF = "self"
_AUTHORITY_AUTHORIZED = "authorized"
_AUTHORITY_UNAUTHORIZED = "unauthorized"
_AUTHORITY_UNATTESTED = "unattested"
_AUTHORITY_TRUST_SIGNER_MISMATCH = "signer_mismatch"

_WARN_PUBLISHER_NOT_AUTHORIZING_ISSUER = "publisher_not_authorizing_issuer"
_WARN_AUTHORIZATION_SIGNER_NOT_PUBLISHER = "authorization_signer_not_publisher"
_WARN_AUTHORIZATION_INVALID_IGNORED = "authorization_invalid_ignored"

_PLEDGE_MEMBERS = ("pledge", "grant_uri", "grant_sha256")
_HEX_LOWER = frozenset("0123456789abcdef")

# This outer cap must COVER everything the downstream evaluators' own inner
# caps accept, or evaluator-valid evidence gets falsely rejected here.
# Worst-case legitimate bundle, derived from those inner caps: checkpoint +
# prior_checkpoint + the anchors bundle's own checkpoint copy at 500,000
# characters each (tlog._MAX_NOTE_TEXT_LEN) = 1,500,000 characters, plus
# anchors operands at 64 proofs x 65_536 total hex chars per proof
# (anchor._MAX_PROOFS_PER_EVIDENCE, _MAX_TOTAL_OP_HEX_LEN) = 4,194,304
# characters, plus JSON overhead for proofs carrying up to 256 ops (~4,000-
# 5,000 characters per proof, ~300,000), plus inclusion/consistency proofs
# (~8,000) — ~6,000,000 characters total, ~4,000,000 characters inside this
# 10,000,000-character ceiling. The cap still bounds hostile materialization
# before the JSON decoder performs a second full traversal.
#
# The operand term is bounded by the per-chain TOTAL, never by
# `_MAX_OPS_PER_PROOF * _MAX_OP_HEX_LEN`: that product is 268,435,456 operand
# characters and would overshoot this 10,000,000-character ceiling by
# ~258,000,000 characters. This ceiling is normative
# (canon.MAX_ADMISSION_BYTES, v0.2 §6.3) and cannot be raised to meet the
# inner caps, so the total-operand cap is what makes the raised per-op caps
# admissible at all — re-derive this arithmetic whenever any of the three
# moves, and see tests/test_anchor.py for it as an executable assertion.
_MAX_TRANSPARENCY_EVIDENCE_LEN = canon.MAX_ADMISSION_BYTES
