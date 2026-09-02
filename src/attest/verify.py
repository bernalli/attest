"""Receipt verification core — §6 steps 0-7 (the security heart of attest).

Decides whether a receipt's signature is valid, from which issuer, whether
it is schema-conformant, whether it has been effectively revoked, and
whether a buyer-binding disclosure proves the receipt belongs to a given
identifier/keyholder.

Pipeline invariant: `canon.loads_strict` parses the raw envelope bytes
exactly once (step 0); every later step operates on that single parsed
object, never on the raw bytes or on any re-serialization of it. `alg` is
read from the signature block only to reject anything that is not the
literal string "Ed25519" — it is never used to select a verification
algorithm.

Steps 6 (revocation) and 7 (binding) only run once the receipt already has
a valid signature AND a valid schema (§6: "on the parsed object from step
0" pipeline continues only on success) — an already-invalid receipt never
gets a revocation/binding verdict computed against it; both dimensions stay
at their safe stub values (`revocation: "unknown"`, `binding:
"not_checked"`) exactly like the rest of an invalid result.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from attest import (
    anchor,
    canon,
    commitment,
    keys,
    manifests,
    pq,
    revocation,
    tlog,
    transfer,
    validate,
)
from attest import (
    authority as authority_module,
)
from attest import grant as grant_module
from attest import transparency as transparency_module

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
_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"

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
# authenticated, log-included transfer record (§17.3's consent gate). The
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


@dataclass(frozen=True)
class TrustStore:
    """The verifier's local trust material (design §5: offline verification
    works from a local trust store of key manifests).

    `chains` is optional and backward-compatible (default empty): when
    present, `chains[issuer_id]` is the ordered manifest-version history the
    verifier holds for that issuer, oldest first, ending with the same
    manifest as `manifests[issuer_id]` — the one actually used to resolve
    signing keys in steps 2-4. `verify()` walks consecutive pairs with
    `manifests.check_continuity`; any break marks the issuer's active
    manifest as reached via a discontinuous rotation (design §5: "version
    gaps are bridgeable only by validating every intermediate manifest in
    sequence... if intermediates are unavailable, the manifest counts as
    discontinuous"), which forces `trust: "unverified_rotation"` regardless
    of provenance. An issuer absent from `chains`, or a chain with fewer
    than 2 entries, has nothing to validate and behaves exactly like a
    Task-8 `TrustStore` (no `chains` kwarg at all).
    """

    manifests: dict[str, dict[str, Any]]  # issuer_id -> key manifest
    provenance: dict[str, str]  # issuer_id -> "tls" | "bundle"
    chains: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # G2/G3 (attest-versioning.md rev 4; v0.1 §7.2/§7.3 amendment) — the
    # artifact-manifest analog of `manifests`/`chains` above, scoped by the
    # receipt issuer and `work.artifact_series`: issuer_id -> series ->
    # manifest/history. This prevents one issuer's series name from affecting
    # another issuer's currency state.
    artifact_manifests: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    artifact_manifest_chains: dict[str, dict[str, list[dict[str, Any]]]] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class Disclosure:
    """§3.2 buyer-binding disclosure — exactly one path is meant to be populated.

    Salt path: `identifier` + `identifier_type` + `salt` recompute the
    commitment and compare it against `payload.buyer.commitment`. Challenge
    path: `challenge = (nonce, sig)` verifies an Ed25519 challenge-response
    transcript against `payload.buyer.pubkey`.

    The salt path takes precedence: if all three salt fields are populated,
    `verify()` evaluates it (returning `proven`/`not_proven`) even when a
    `challenge` is also supplied — a fully-specified salt disclosure is a
    legitimate proof, so a stray extra field never downgrades it. A partial
    path (e.g. `salt` without `identifier`, or neither path complete) is a
    malformed disclosure and fails closed to `binding: "not_proven"` rather
    than raising — never trust an under-specified proof.
    """

    identifier: str | None = None
    identifier_type: str | None = None
    salt: bytes | None = None
    challenge: tuple[bytes, bytes] | None = None  # (nonce, sig)


@dataclass(frozen=True)
class VerificationResult:
    """Layered, never boolean (design §6): each dimension of trust is reported
    independently so a caller can degrade gracefully instead of getting a
    single opaque true/false."""

    signature: str  # "valid" | "invalid" (with v0.2 §19's anchored rescue carve-out)
    schema: str  # "valid" | "invalid" | "not_checked"
    revocation: (
        str  # "unknown" | "not_revoked_as_of:<T>" | "revoked" | "invalid_revocation_ignored"
        # | "transferred" (v0.2 §17.3, Stage 3: a BACKED status:"transferred"
        # revocation record extinguishes the old receipt — reachable only
        # under Stage-3-capable verification, i.e. a caller that evaluates
        # `transfer_view`)
    )
    binding: str  # "proven" | "not_proven" | "not_checked"
    trust: str  # "verified" | "unauthenticated_tofu" | "unverified_rotation"
    # Stage 2, informational only (never affect `ok`/`trust`/key-status — see
    # `verify()`'s module-level constants and `_evaluate_transparency_claim`):
    transparency: str = _TRANSPARENCY_NOT_CHECKED
    # "not_checked" | "logged" | "anchored_before:<T>" | "equivocation_detected"
    corroboration: str = _CORROBORATION_NONE  # "none" | "logged" | "witnessed"
    manifest_freshness: str = (
        _MANIFEST_FRESHNESS_NOT_CHECKED  # "not_checked" | "verified_as_of:<N>"
    )
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    # v0.2 Stage 4 (§18.5), informational only and taking NO exception (D6):
    # neither ever affects `signature`, `schema`, `revocation`, `binding`,
    # `trust` or `ok` — a grant is a permission that becomes exercisable, never
    # a validity property of the receipt. Declared LAST so every existing
    # positional construction keeps working, and defaulted to the values every
    # pre-Stage-4 caller already implicitly gets.
    grant: str = _GRANT_NOT_CHECKED
    # "not_checked" | "none" | "dormant" | "activated" | "invalid_grant_ignored"
    grant_trust: str = _GRANT_TRUST_NOT_CHECKED
    # "not_checked" | "verified" | "unauthenticated_tofu" | "unverified_rotation"
    # | "signer_mismatch"
    # v0.2 section 20.5, informational only. Declared after Stage 4 for the
    # same additive-construction reason as `grant`/`grant_trust`.
    publisher_authority: str = _AUTHORITY_NOT_CHECKED
    # "not_checked" | "no_publisher_claim" | "self" | "authorized"
    # | "unauthorized" | "unattested"
    publisher_authority_trust: str = _AUTHORITY_NOT_CHECKED
    # "not_checked" | "verified" | "unauthenticated_tofu" | "unverified_rotation"
    # | "signer_mismatch"

    @property
    def ok(self) -> bool:
        """Design §3.1/§6: an effective revocation record makes a receipt not
        `ok` ("Effective record ⇒ revocation='revoked' (receipt not ok)").
        `invalid_revocation_ignored` and `unknown`/`not_revoked_as_of:<T>` do
        NOT affect `ok` — an ignored-by-class or unverified revocation record
        must never degrade a receipt's validity (that would defeat the
        revocability:none irrevocability guarantee, design vector 16).

        v0.2 Stage 3 (design doc §4): `revocation == "transferred"` caps `ok`
        the same way `"revoked"` already does — a BACKED transfer record
        extinguishes the old receipt exactly as effectively as a plain
        revocation, it is simply reported on a distinct value so a caller can
        tell "sold" from "revoked" on the same feed. Reachable only under
        Stage-3-capable verification (a caller that evaluates
        `transfer_view`); a verifier that never does keeps v0.1's `ok`
        formula unchanged."""
        return (
            self.signature == _SIG_VALID
            and self.schema == _SCHEMA_VALID
            and self.revocation not in (_REVOCATION_REVOKED, _REVOCATION_TRANSFERRED)
            and not self.errors
        )


@dataclass(frozen=True)
class _CompromiseClaim:
    manifest: dict[str, Any]
    evidence: object
    signer_kid: str
    vouching_signers: tuple[dict[str, Any], ...]


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def _within_validity(issued_at: str, entry: dict[str, Any]) -> bool:
    """Fail closed on any malformed/missing date — an unparseable window
    never resurrects a receipt into validity."""
    try:
        issued = _parse_date(issued_at)
        valid_from = _parse_date(entry["valid_from"])
    except (KeyError, TypeError, ValueError):
        return False
    if issued < valid_from:
        return False
    valid_to = entry.get("valid_to")
    if valid_to is None:
        return True
    try:
        return issued <= _parse_date(valid_to)
    except (TypeError, ValueError):
        return False


def _content_warnings(payload: dict[str, Any]) -> list[str]:
    """Non-fatal, payload-content warnings — independent of the crypto pipeline.

    Unknown top-level fields are compared against the schema's top-level
    `properties` keys only (top level is enough for v0.1, per brief).
    """
    found: list[str] = []

    known_top_level = set(validate.SCHEMA.get("properties", {}))
    for key in payload:
        if key not in known_top_level:
            found.append(f"unknown payload field: {key!r}")

    license_block = payload.get("license")
    if isinstance(license_block, dict) and license_block.get("drm") == "drm-bound":
        found.append("license.drm is drm-bound (design vector 18)")

    survivability = payload.get("survivability")
    if isinstance(survivability, dict):
        eol = survivability.get("end_of_life")
        # `x not in <frozenset>` RAISES on an unhashable x, and the payload is
        # untrusted wire data: a signed receipt carrying
        # `survivability.end_of_life: {}` crashed verify() with a TypeError.
        # Only a string can ever be a registered value, so the type check is
        # also the guard — and it restores parity with verify.ts, which has
        # always written this as `typeof eol !== 'string' || !KNOWN_EOL.has(eol)`.
        if not isinstance(eol, str) or eol not in _KNOWN_EOL_VALUES:
            found.append(f"unknown survivability.end_of_life value: {eol!r}")

    return found


def _chain_continuous(chain: list[dict[str, Any]]) -> bool:
    """True iff every consecutive pair in `chain` passes `manifests.check_continuity`.

    A chain of fewer than 2 entries has nothing to validate (no recorded
    history, or a single trusted root with no successor yet) and is treated
    as continuous — this is what keeps a `TrustStore` with no `chains` entry
    for an issuer behaving exactly like Task 8.
    """
    if len(chain) < 2:
        return True
    return all(manifests.check_continuity(chain[i], chain[i + 1]) for i in range(len(chain) - 1))


def _artifact_chain_continuous(chain: list[dict[str, Any]]) -> bool:
    """True iff every consecutive pair in `chain` passes
    `manifests.check_artifact_continuity` — the artifact-manifest analog of
    `_chain_continuous` (G2/G3, attest-versioning.md rev 4)."""
    if len(chain) < 2:
        return True
    return all(
        manifests.check_artifact_continuity(chain[i], chain[i + 1]) for i in range(len(chain) - 1)
    )


def _rotation_chain_verified(
    chain: list[dict[str, Any]] | None, manifest: dict[str, Any] | None
) -> bool:
    """True iff `chain` is a validated, gapless rotation history from
    manifest_version 1 through `manifest` itself, held in the verifier's OWN
    trust store (design fix 6).

    Deliberately STRICTER than `_chain_continuous`'s use for `trust`: an
    ABSENT chain is fine for `trust` (Task-8 behavior — nothing to validate)
    but is NOT fine here. Corroborating a rotated key-manifest requires the
    verifier to already hold every intermediate version itself; the log
    merely saying "this manifest existed" is not proof of a legitimate
    rotation history, only of publication. `trust` semantics are untouched
    by this function — it feeds `corroboration` only.
    """
    if not chain or manifest is None:
        return False
    if chain[-1] != manifest:
        return False
    if chain[0].get("manifest_version") != 1:
        return False
    return _chain_continuous(chain)


def _validated_transparency_entry(candidate: dict[str, Any]) -> dict[str, Any] | None:
    """`candidate` iff it passes the log's own closed entry schema, else `None`
    — never trust a computed entry into `evaluate_transparency` without this
    (a malformed `expected_entry` would raise `TransparencyError`, which must
    never happen just because the RECEIPT's own untrusted payload was
    malformed, e.g. a bad `issuer.id`)."""
    try:
        tlog.encode_entry(candidate)
    except tlog.TlogError:
        return None
    return candidate


def _resolve_transparency_claim(
    transparency_evidence: object,
    envelope: dict[str, Any],
    receipt_issuer_id: str | None,
    issuer_manifest: dict[str, Any] | None,
) -> tuple[str | None, dict[str, Any] | None, int | None]:
    """Read the untrusted evidence's claimed type (`entry.type`) and, only if
    verify() can independently compute a matching entry from its OWN trusted
    artifacts, that entry — plus the evidence's own declared `tree_size`.

    `claim_type` selects WHICH artifact verify() computes an `expected_entry`
    for: `"receipt"` from `envelope` itself (the signed-receipt-core hash),
    `"key-manifest"` from the trusted `issuer_manifest` the caller's trust
    store already resolved. The evidence's OWN hash values are never trusted
    for anything beyond this dispatch — `expected_entry` is always computed
    locally, never read off `transparency_evidence`.

    Returns `(claim_type, expected_entry, tree_size)`. `expected_entry` is
    `None` when the claim type is unrecognized, no matching trusted artifact
    exists, or the computed entry fails the log's own closed schema — the
    caller degrades to `not_checked` in every case, uniformly.
    """
    if not isinstance(transparency_evidence, dict):
        return None, None, None

    entry = transparency_evidence.get("entry")
    claim_type = entry.get("type") if isinstance(entry, dict) else None
    if not isinstance(claim_type, str):
        claim_type = None

    tree_size = transparency_evidence.get("tree_size")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        tree_size = None

    expected_entry: dict[str, Any] | None = None
    if claim_type == _CLAIM_TYPE_RECEIPT:
        try:
            core_hash: str | None = tlog.receipt_core_hash(envelope)
        except tlog.TlogError:
            core_hash = None
        if core_hash is not None:
            expected_entry = _validated_transparency_entry(
                {
                    "type": _CLAIM_TYPE_RECEIPT,
                    "issuer": receipt_issuer_id,
                    "core_sha256": core_hash,
                }
            )
    elif claim_type == _CLAIM_TYPE_KEY_MANIFEST and issuer_manifest is not None:
        try:
            manifest_sha256: str | None = hashlib.sha256(
                canon.canonical_bytes(issuer_manifest)
            ).hexdigest()
        except canon.CanonError:
            manifest_sha256 = None
        if manifest_sha256 is not None:
            expected_entry = _validated_transparency_entry(
                {
                    "type": _CLAIM_TYPE_KEY_MANIFEST,
                    "issuer": issuer_manifest.get("issuer"),
                    "manifest_version": issuer_manifest.get("manifest_version"),
                    "manifest_sha256": manifest_sha256,
                }
            )

    return claim_type, expected_entry, tree_size


def _resolve_log_origin(log_keys: list[tlog.LogKey]) -> str:
    """The single pinned origin shared by every entry in `log_keys` — this is
    verify()'s own trusted configuration (mirrors `evaluate_transparency`'s
    `expected_origin` argument), never derived from untrusted evidence. Each
    key is deep-validated via `evaluate_transparency`'s own `log_keys`
    validation (byte lengths, name/origin grammar) — not just shallow
    `isinstance` — so a malformed pinned key raises here too, eagerly,
    exactly like it would once `evaluate_transparency` itself validates
    `log_keys` again. Disagreeing or empty origins are likewise a
    caller/config bug and raise `TransparencyError`.
    """
    validated = transparency_module._validate_log_keys(log_keys)
    origins = {key.origin for key in validated}
    if len(origins) != 1:
        raise transparency_module.TransparencyError(
            f"log_keys must be a non-empty list sharing a single origin, got {sorted(origins)!r}"
        )
    return next(iter(origins))


def _evaluate_transparency_claim(
    envelope: dict[str, Any],
    receipt_issuer_id: str | None,
    issuer_manifest: dict[str, Any] | None,
    rotation_chain_ok: bool,
    transparency_evidence: dict[str, Any] | None,
    log_keys: list[tlog.LogKey] | None,
    anchor_policy: anchor.AnchorPolicy | None,
    warnings: list[str],
    witness_policy: object = None,
) -> tuple[str, str, str, str | None]:
    """Resolve transparency result components plus the evidence claim type
    from one evidence bundle (design doc "transparency/corroboration layer").

    Computed independently of the receipt's own pass/fail verdict — called
    once, early, regardless of whether the receipt later turns out invalid
    (e.g. a compromised key), so that corroboration can never rescue an
    otherwise-rejected receipt: demonstrating that requires the evidence
    actually being evaluated, not merely defaulting to `not_checked` because
    the receipt failed first (design fix 6 / vector 28i's property).

    Absent evidence is the ZERO-behavior-change default. Evidence present but
    `log_keys`/`anchor_policy` missing is a configuration gap (the verifier
    wasn't set up for transparency checking) — degrades with a warning,
    never raises: the evidence side must never brick a receipt verification.
    A malformed `log_keys`/`anchor_policy`/`witness_policy` is trusted-config,
    validated eagerly once this function reaches the point of evaluating a
    transparency claim — before the untrusted-evidence boundary, never after —
    so a config bug surfaces as `TransparencyError` instead of being masked by
    coincidentally-also-unresolvable evidence. It is NOT validated on the two
    paths that return before evaluating anything: no `transparency_evidence`
    at all, and Stage 2 config incomplete. A caller that passes a malformed
    policy alongside no evidence gets the same zero-behaviour-change result as
    one that passes no policy, by design — `evaluate_transparency` is the
    surface that raises unconditionally (§10.2), and the CLI validates
    `--witness-policy` when it loads the file, before `verify()` is called.
    """
    if transparency_evidence is None:
        return (
            _TRANSPARENCY_NOT_CHECKED,
            _CORROBORATION_NONE,
            _MANIFEST_FRESHNESS_NOT_CHECKED,
            None,
        )

    if log_keys is None or anchor_policy is None:
        warnings.append(_WARN_TRANSPARENCY_CONFIG_MISSING)
        return (
            _TRANSPARENCY_NOT_CHECKED,
            _CORROBORATION_NONE,
            _MANIFEST_FRESHNESS_NOT_CHECKED,
            None,
        )

    origin = _resolve_log_origin(log_keys)
    transparency_module._validate_policy(anchor_policy)
    # The witness policy (v0.2 §11.4) rides the same trusted rail, so it gets
    # the same eager validation: a malformed one is a configuration bug and
    # must surface as an error, never be swallowed by the untrusted-evidence
    # boundary below. Parsed here rather than inside `evaluate_transparency`
    # for exactly that reason — inside, it would be past the boundary.
    validated_witness_policy = transparency_module._validate_witness_policy(witness_policy)

    try:
        # This is verify()'s untrusted-evidence boundary. Canonicalize and
        # parse once so every following phase sees one ordinary JSON object,
        # never a stateful mapping/value supplied by the caller. The size cap
        # prevents decoding an arbitrarily large serialized evidence bundle.
        # The copy of the value's OWN data runs FIRST and refuses on a node
        # budget: the code-point cap below is compared against a serialization that
        # has ALREADY been produced, so a caller value whose iteration never
        # ends would hang here before any cap could fire -- and a hang reaches
        # no `except` clause, which is why the enclosing one is not a defence
        # against it.
        serialized_evidence = canon.dumps(
            _own_data_copy(transparency_evidence, [_MAX_EVIDENCE_NODES])
        )
        if len(serialized_evidence) > _MAX_TRANSPARENCY_EVIDENCE_LEN:
            raise ValueError("transparency evidence exceeds materialization limit")
        materialized_evidence = json.loads(serialized_evidence)
        if not isinstance(materialized_evidence, dict):
            raise ValueError("transparency evidence is not an object")

        claim_type, expected_entry, tree_size = _resolve_transparency_claim(
            materialized_evidence, envelope, receipt_issuer_id, issuer_manifest
        )
        if expected_entry is None:
            warnings.append(_WARN_TRANSPARENCY_CLAIM_UNRESOLVABLE)
            return (
                _TRANSPARENCY_NOT_CHECKED,
                _CORROBORATION_NONE,
                _MANIFEST_FRESHNESS_NOT_CHECKED,
                claim_type,
            )

        result = transparency_module.evaluate_transparency(
            materialized_evidence,
            log_keys=log_keys,
            expected_origin=origin,
            policy=anchor_policy,
            expected_entry=expected_entry,
            witness_policy=validated_witness_policy,
        )
        warnings.extend(result.warnings)

        transparency_state = result.transparency
        corroboration_state = result.corroboration
        manifest_freshness_state = _MANIFEST_FRESHNESS_NOT_CHECKED

        reached_logged_or_better = transparency_state not in (
            transparency_module.TRANSPARENCY_NOT_CHECKED,
            transparency_module.TRANSPARENCY_EQUIVOCATION_DETECTED,
        )
        if claim_type == _CLAIM_TYPE_KEY_MANIFEST and reached_logged_or_better:
            if tree_size is not None:
                manifest_freshness_state = f"verified_as_of:{tree_size}"
            manifest_version = issuer_manifest.get("manifest_version") if issuer_manifest else None
            if (
                isinstance(manifest_version, int)
                and not isinstance(manifest_version, bool)
                and manifest_version > 1
                and not rotation_chain_ok
            ):
                corroboration_state = _CORROBORATION_NONE
                warnings.append(_WARN_ROTATION_CHAIN_REQUIRED)

        return transparency_state, corroboration_state, manifest_freshness_state, claim_type
    # This intentionally encloses every untrusted claim phase above, including
    # post-evaluation freshness/rotation logic. It confines hostile mapping
    # access and equality implementations; never catch BaseException so
    # interrupts and process-control exceptions still propagate.
    except Exception:
        warnings.append(_WARN_TRANSPARENCY_CLAIM_UNRESOLVABLE)
        return (
            _TRANSPARENCY_NOT_CHECKED,
            _CORROBORATION_NONE,
            _MANIFEST_FRESHNESS_NOT_CHECKED,
            None,
        )


def _append_warning_once(warnings: list[str], warning: str) -> None:
    if warning not in warnings:
        warnings.append(warning)


# §18.4's admission boundary has exactly ONE spelling, in `canon` — the leaf
# module both public entry points that admit caller rails can import
# (`verify()` here, `transfer.audit_chain()` there, which cannot import this
# module without closing the cycle `verify -> transfer`). These names are the
# vocabulary the rest of this module reads; they bind to that one boundary
# rather than restating it, because a boundary with two spellings is a boundary
# that will diverge.
_MAX_EVIDENCE_NODES = canon.MAX_ADMISSION_NODES
_own_data_copy = canon.own_data_copy
_admit_evidence_value = canon.admit_value
_materialize_evidence_value = canon.materialize_value
_own_view_member = canon.own_view_member
_materialize_evidence_array = canon.materialize_array
_VIEW_MEMBER_NESTING = canon.VIEW_MEMBER_NESTING
_VIEW_ARRAY_ELEMENT_NESTING = canon.VIEW_ARRAY_ELEMENT_NESTING
_VIEW_MEMBER_ABSENT = canon.VIEW_MEMBER_ABSENT
_VIEW_MEMBER_COLLAPSED = canon.VIEW_MEMBER_COLLAPSED


def _admit_single_view_member(
    view: dict[str, Any], reconstructed: dict[str, Any], member: str
) -> None:
    supplied = _own_view_member(view, member)
    if supplied is _VIEW_MEMBER_ABSENT or supplied is _VIEW_MEMBER_COLLAPSED:
        return
    admitted, materialized = _admit_evidence_value(supplied, _VIEW_MEMBER_NESTING)
    if admitted:
        reconstructed[member] = materialized


def _materialize_grant_view(grant_view: dict[str, Any]) -> dict[str, Any] | None:
    """Admit `grant_view` MEMBER BY MEMBER, over the members §18.4 enumerates.

    The view is never reconstructed as one indivisible value: a single
    unencodable value would then discard the publisher's whole signed evidence
    where §18.4 requires it to be set aside on its own, and anyone able to
    append one member — a relay, a mirror, an aggregating cache — would buy
    `not_checked` for a few hundred bytes of nesting.

    The members are the ones the RAIL defines, never the ones the value
    supplies: `grant` and `anchor` are admitted as single values (one that is
    not admissible is ABSENT), `later_grants` and `declarations` per element. A
    member the rail does not define is not admitted at all — never
    reconstructed, never read, and never a reason to refuse the view or any
    other member. Every read of the caller's object goes through an
    unshadowable `dict` accessor, so a subclass is not refused for BEING a
    subclass either.
    """
    try:
        reconstructed: dict[str, Any] = {}
        later_grants = _own_view_member(grant_view, "later_grants")
        if later_grants is not _VIEW_MEMBER_ABSENT and later_grants is not _VIEW_MEMBER_COLLAPSED:
            materialized_later = _materialize_evidence_array(
                later_grants, grant_module._MAX_GRANT_LATER_VERSIONS
            )
            if materialized_later is not None:
                reconstructed["later_grants"] = materialized_later
        declarations = _own_view_member(grant_view, "declarations")
        if declarations is not _VIEW_MEMBER_ABSENT and declarations is not _VIEW_MEMBER_COLLAPSED:
            materialized_declarations = _materialize_evidence_array(
                declarations, grant_module._MAX_GRANT_DECLARATIONS
            )
            if materialized_declarations is not None:
                reconstructed["declarations"] = materialized_declarations
        _admit_single_view_member(grant_view, reconstructed, "grant")
        _admit_single_view_member(grant_view, reconstructed, "anchor")
    except Exception:
        return None
    return reconstructed


def _materialize_authority_view(authority_view: dict[str, Any]) -> dict[str, Any] | None:
    """Admit `authority_view` MEMBER BY MEMBER, over the members §20.3 enumerates.

    Same rule as `_materialize_grant_view`: `authorizations` is admitted per
    element, `current_authorization_version` as a single value, and a member
    the rail does not define is never read.
    """
    try:
        reconstructed: dict[str, Any] = {}
        authorizations = _own_view_member(authority_view, "authorizations")
        if (
            authorizations is not _VIEW_MEMBER_ABSENT
            and authorizations is not _VIEW_MEMBER_COLLAPSED
        ):
            materialized_authorizations = _materialize_evidence_array(
                authorizations, authority_module.MAX_AUTHORITY_DOCUMENTS
            )
            if materialized_authorizations is not None:
                reconstructed["authorizations"] = materialized_authorizations
        _admit_single_view_member(authority_view, reconstructed, "current_authorization_version")
    except Exception:
        return None
    return reconstructed


def _materialize_compromise_view(
    compromise_view: list[dict[str, Any]] | None,
) -> list[Any] | None:
    if compromise_view is None:
        return None
    try:
        count = list.__len__(compromise_view)
        if count > _MAX_COMPROMISE_CLAIMS:
            return None
        return [
            _materialize_evidence_value(
                list.__getitem__(compromise_view, index),
                _VIEW_MEMBER_NESTING,
            )
            for index in range(count)
        ]
    except Exception:
        return None


def _held_issuer_manifests(
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
) -> list[dict[str, Any]]:
    held = [trusted_manifest]
    if chain is not None:
        held.extend(member for member in chain if isinstance(member, dict))
    return [member for member in held if member.get("issuer") == issuer_id]


def _b64u_bytes_equal(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return keys.b64u_decode(left) == keys.b64u_decode(right)
    except (TypeError, ValueError):
        return False


def _compromise_key_material_matches(
    claim_entry: dict[str, Any], trusted_entry: dict[str, Any]
) -> bool:
    if not _b64u_bytes_equal(claim_entry.get("pub"), trusted_entry.get("pub")):
        return False
    if "pub_ml_dsa_65" not in trusted_entry:
        return True
    return _b64u_bytes_equal(claim_entry.get("pub_ml_dsa_65"), trusted_entry.get("pub_ml_dsa_65"))


def _entries_for_kid(manifest: dict[str, Any], kid: str) -> tuple[dict[str, Any], ...]:
    entries = manifest.get("keys", [])
    if not isinstance(entries, list):
        return ()
    return tuple(entry for entry in entries if isinstance(entry, dict) and entry.get("kid") == kid)


def _manifest_marks_kid_compromised(manifest: dict[str, Any], kid: str) -> bool:
    return any(
        entry.get("status") == _STATUS_COMPROMISED for entry in _entries_for_kid(manifest, kid)
    )


def _vouching_signers(
    claim_manifest: dict[str, Any],
    held_manifests: list[dict[str, Any]],
) -> tuple[str | None, tuple[dict[str, Any], ...]]:
    sig_block = claim_manifest.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return None, ()
    signer_kid = sig_block.get("kid")
    if not isinstance(signer_kid, str):
        return None, ()
    try:
        signable = manifests._signable(claim_manifest)
    except (TypeError, canon.CanonError):
        return signer_kid, ()

    issued_at = claim_manifest.get("issued_at")
    if not isinstance(issued_at, str):
        return signer_kid, ()
    signers: list[dict[str, Any]] = []
    for held_manifest in held_manifests:
        for signer_entry in _entries_for_kid(held_manifest, signer_kid):
            if not _within_validity(issued_at, signer_entry):
                continue
            if manifests.verify_signature_block(signable, sig_block, signer_entry):
                signers.append(signer_entry)
    return signer_kid, tuple(signers)


def _authenticated_compromise_claims(
    compromise_claims: list[Any] | None,
    trusted_manifest: dict[str, Any],
    trusted_entry: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
    kid: str,
    warnings: list[str],
) -> tuple[_CompromiseClaim, ...]:
    if not compromise_claims:
        return ()

    held_manifests = _held_issuer_manifests(trusted_manifest, chain, issuer_id)
    authenticated: list[_CompromiseClaim] = []
    for claim in compromise_claims:
        if not isinstance(claim, dict):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        claim_manifest = claim.get("manifest")
        if not isinstance(claim_manifest, dict) or claim_manifest.get("issuer") != issuer_id:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        manifest_version = claim_manifest.get("manifest_version")
        if not isinstance(manifest_version, int) or isinstance(manifest_version, bool):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        # v0.1 §7.3 (rev 8): the claimed compromised entry may match ANY trusted
        # entry for the kid, not only the one `find_key` happened to return
        # first. With duplicate entries a first-match comparison lets the
        # array's ORDER decide whether a genuine declaration authenticates.
        trusted_entries_for_kid = _entries_for_kid(trusted_manifest, kid) or (trusted_entry,)
        if not any(
            claim_entry.get("status") == _STATUS_COMPROMISED
            and any(
                _compromise_key_material_matches(claim_entry, candidate)
                for candidate in trusted_entries_for_kid
            )
            for claim_entry in _entries_for_kid(claim_manifest, kid)
        ):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        signer_kid, signers = _vouching_signers(claim_manifest, held_manifests)
        if signer_kid is None or not signers:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        authenticated.append(
            _CompromiseClaim(
                manifest=claim_manifest,
                evidence=claim.get("evidence"),
                signer_kid=signer_kid,
                vouching_signers=signers,
            )
        )
    return tuple(authenticated)


def _held_manifest_marks_signer_compromised_at_or_before(
    held_manifests: list[dict[str, Any]], signer_kid: str, declaration_version: int
) -> bool:
    for held_manifest in held_manifests:
        version = held_manifest.get("manifest_version")
        if not isinstance(version, int) or isinstance(version, bool):
            continue
        if version > declaration_version:
            continue
        if _manifest_marks_kid_compromised(held_manifest, signer_kid):
            return True
    return False


def _trusted_manifest_vouches_for_member(
    member: dict[str, Any], trusted_manifest: dict[str, Any]
) -> bool:
    """Does the TRUSTED manifest itself stand behind this held chain member?

    v0.2 §19.3 item 3b lets a held manifest DENY the cutoff, and denial is the
    direction that WIDENS: a receipt §19.1 would have rejected survives. §19's
    own principle — evidence that can only narrow is admitted under weaker
    conditions than evidence that can widen it — therefore asks more of a
    member used this way than the letter of item 3b spells out. This predicate
    is deliberately STRICTER than that letter; the spec is not amended here,
    the code is knowingly the tighter of the two.

    What it requires: the member's `manifest_signature` kid resolves IN THE
    TRUSTED MANIFEST to an entry that is `active` or `retired`, the member's
    `issued_at` falls inside that entry's validity window, and the signature
    verifies under THAT entry's material, hybrid AND rule included.

    Why the trusted manifest and not the member's own `keys[]`: a thief
    holding the stolen key satisfies a self-check by construction — he signs
    the doctored member with the stolen key and it verifies against the copy
    of that key he placed inside it. Only the manifest the verifier already
    trusts can say whether the signing key was still the issuer's to sign
    with. A predicate checking a member against itself closes the
    broken-signature case and leaves this one wide open.

    Never raises; every malformed shape fails closed, and the `keys[]` ceiling
    is checked BEFORE canonicalizing, so a hostile array cannot buy unbounded
    work here (same order as `verify_key_manifest`).
    """
    entries_for_ceiling = member.get("keys")
    if (
        isinstance(entries_for_ceiling, list)
        and len(entries_for_ceiling) > manifests.MAX_MANIFEST_KEYS
    ):
        return False
    sig_block = member.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return False
    signer_kid = sig_block.get("kid")
    if not isinstance(signer_kid, str):
        return False
    issued_at = member.get("issued_at")
    if not isinstance(issued_at, str):
        return False
    signer_entry = manifests.find_key(trusted_manifest, signer_kid)
    if signer_entry is None:
        return False
    if signer_entry.get("status") not in (_STATUS_ACTIVE, _STATUS_RETIRED):
        return False
    if not _within_validity(issued_at, signer_entry):
        return False
    try:
        signable = manifests._signable(member)
    except (TypeError, canon.CanonError):
        return False
    return manifests.verify_signature_block(signable, sig_block, signer_entry)


def _cutoff_denying_manifests(
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
) -> list[dict[str, Any]]:
    """The held manifests allowed to DENY a §19.3 cutoff.

    The trusted manifest is always in: it is the trust anchor, admitted by the
    store's own provenance (v0.1 §7.4) and already self-authenticated by
    `verify()`'s preflight, never by a signature check against itself — `41p`
    and `41r` are the leaves where it legitimately denies the cutoff. Every
    CHAIN MEMBER has to be vouched for by that anchor instead.

    The scope is deliberately this one clause, and the boundary was measured
    rather than chosen. The absorbing status floor (v0.1 §7.3), item 3a's
    vouching set, the retraction warning and the `trust` label all keep
    reading the UNFILTERED held set: extending this predicate to item 3a
    flips `41s` from `ok: false` to `ok: true`, because there every member is
    signed by a key the head marks `compromised`, and without their entries
    to date the signer the cutoff falls and the forgeries survive. `41l` gets
    its floor from a discontinuous chain for the same reason. On this
    perimeter a filter that looks stricter widens who survives.
    """
    held = [trusted_manifest]
    if chain is not None:
        held.extend(
            member
            for member in chain
            if isinstance(member, dict)
            and _trusted_manifest_vouches_for_member(member, trusted_manifest)
        )
    return [member for member in held if member.get("issuer") == issuer_id]


def _claim_has_cutoff_signer(claim: _CompromiseClaim, held_manifests: list[dict[str, Any]]) -> bool:
    declaration_version = claim.manifest.get("manifest_version")
    if not isinstance(declaration_version, int) or isinstance(declaration_version, bool):
        return False
    for signer_entry in claim.vouching_signers:
        if signer_entry.get("status") not in (_STATUS_ACTIVE, _STATUS_RETIRED):
            continue
        if _held_manifest_marks_signer_compromised_at_or_before(
            held_manifests, claim.signer_kid, declaration_version
        ):
            continue
        return True
    return False


def _resolve_compromise_cutoff(
    authenticated_claims: tuple[_CompromiseClaim, ...],
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
    log_keys: list[tlog.LogKey],
    anchor_policy: anchor.AnchorPolicy,
    warnings: list[str],
) -> datetime | None:
    """v0.2 §19.3: minimum anchored declaration time for a kid, or None."""
    if not authenticated_claims:
        return None

    origin = _resolve_log_origin(log_keys)
    transparency_module._validate_policy(anchor_policy)
    # Only manifests the TRUSTED manifest vouches for may deny the cutoff
    # (§19.3 item 3b). Every other consumer of the held set is unchanged.
    held_manifests = _cutoff_denying_manifests(trusted_manifest, chain, issuer_id)
    best: datetime | None = None
    for claim in authenticated_claims:
        if not _claim_has_cutoff_signer(claim, held_manifests):
            continue
        try:
            manifest_sha256 = hashlib.sha256(canon.canonical_bytes(claim.manifest)).hexdigest()
        except (TypeError, canon.CanonError):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        expected_entry = _validated_transparency_entry(
            {
                "type": _CLAIM_TYPE_KEY_MANIFEST,
                "issuer": claim.manifest.get("issuer"),
                "manifest_version": claim.manifest.get("manifest_version"),
                "manifest_sha256": manifest_sha256,
            }
        )
        if expected_entry is None:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        result = transparency_module.evaluate_transparency(
            cast(dict[str, Any], claim.evidence),
            log_keys=log_keys,
            expected_origin=origin,
            policy=anchor_policy,
            expected_entry=expected_entry,
        )
        for warning in result.warnings:
            _append_warning_once(warnings, warning)
        if not result.transparency.startswith(_ANCHORED_BEFORE_PREFIX):
            continue
        cutoff = _parse_iso(result.transparency[len(_ANCHORED_BEFORE_PREFIX) :])
        if cutoff is None:
            continue
        if best is None:
            best = cutoff
            continue
        try:
            if cutoff < best:
                best = cutoff
        except TypeError:
            continue
    return best


def _integer_manifest_version(manifest: dict[str, Any]) -> int | None:
    """`manifest_version` only when it is a genuine integer.

    `bool` is excluded explicitly: it subclasses `int`, and a `true` on the
    wire must not be allowed to order versions.
    """
    version = manifest.get("manifest_version")
    if isinstance(version, bool) or not isinstance(version, int):
        return None
    return version


def _marking_provenance_is_a_retraction(
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    authenticated_claims: tuple[_CompromiseClaim, ...],
    kid: str,
) -> bool:
    """v0.1 §7.3 (rev 8): did the issuer take its own marking back?

    True only when the trusted manifest carries an integer version, does NOT
    mark the kid compromised on ANY of its entries, and some held source that
    does mark it carries an integer version strictly lower. Provenance, never a
    verdict: the floor has already decided by the time this runs.

    Every entry for the kid is consulted in every manifest (via
    `_manifest_marks_kid_compromised`): reading the first matching entry would
    let the array's ORDER decide whether the issuer rewrote its history.
    """
    trusted_version = _integer_manifest_version(trusted_manifest)
    if trusted_version is None:
        return False
    if _manifest_marks_kid_compromised(trusted_manifest, kid):
        return False
    sources: list[dict[str, Any]] = []
    if chain is not None:
        sources.extend(manifest for manifest in chain if isinstance(manifest, dict))
    sources.extend(claim.manifest for claim in authenticated_claims)
    for source in sources:
        if not _manifest_marks_kid_compromised(source, kid):
            continue
        source_version = _integer_manifest_version(source)
        if source_version is not None and source_version < trusted_version:
            return True
    return False


def _resolve_key_status(
    trusted_entry: dict[str, Any],
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    authenticated_claims: tuple[_CompromiseClaim, ...],
    kid: str,
) -> object:
    if _manifest_marks_kid_compromised(trusted_manifest, kid):
        return _STATUS_COMPROMISED
    if chain is not None:
        for manifest in chain:
            if not isinstance(manifest, dict):
                continue
            if _manifest_marks_kid_compromised(manifest, kid):
                return _STATUS_COMPROMISED
    if authenticated_claims:
        return _STATUS_COMPROMISED
    return trusted_entry.get("status")


def _parse_iso(value: object) -> datetime | None:
    """Fail-closed ISO-8601 parse for revocation timestamps — `None` on any
    non-str or unparseable input, never raises. `datetime.fromisoformat`
    handles the `Z` suffix directly on Python 3.12."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _max_revoked_at(view: list[dict[str, Any]]) -> str | None:
    """Freshness anchor for `not_revoked_as_of:<T>`: the maximum `revoked_at`
    across the records passed in — which callers MUST have already filtered to
    signature-authenticated records only (`revocation.verify_record` True).
    Restricting to authenticated records is a security fix: otherwise an
    attacker could inject an unsigned record with a far-future `revoked_at`
    and inflate the reported freshness of the verifier's revocation feed. T
    describes how current the verifier's *authenticated* revocation data is,
    not this one receipt's history (design decision: §6 does not define T
    itself). Malformed entries (non-dict, missing/unparseable `revoked_at`)
    are skipped, never crash; naive/aware datetime mixes that can't be
    compared are likewise skipped rather than raising.

    Restricted further to records whose `status` is a registered
    revocation-statement literal (`_ANCHOR_STATUSES`): an issuer-signed record
    with an unregistered status and a far-future `revoked_at` must not inflate
    T (v0.1 §12.3, 2026-08-26 amendment). §12 already rules such a record is
    not a revocation statement, so it cannot speak for the feed's freshness
    either.
    """
    best_dt: datetime | None = None
    best_raw: str | None = None
    for record in view:
        if not isinstance(record, dict):
            continue
        status = record.get("status")
        # `x not in frozenset` RAISES on an unhashable x, and the revocation
        # view is untrusted wire data: a record carrying `status: {}` would
        # crash a function documented never to raise. Only a string can ever
        # be a registered literal, so the type check is also the guard.
        if not isinstance(status, str) or status not in _ANCHOR_STATUSES:
            continue
        parsed = _parse_iso(record.get("revoked_at"))
        if parsed is None:
            continue
        raw = record["revoked_at"]
        if best_dt is None:
            best_dt, best_raw = parsed, raw
            continue
        try:
            newer = parsed > best_dt
        except TypeError:
            continue  # incomparable naive/aware mix — skip, never crash
        if newer:
            best_dt, best_raw = parsed, raw
    return best_raw


def _not_revoked_or_unknown(view: list[dict[str, Any]]) -> str:
    anchor = _max_revoked_at(view)
    return _REVOCATION_UNKNOWN if anchor is None else f"{_REVOCATION_NOT_REVOKED_PREFIX}{anchor}"


def _refund_window_end(payload: dict[str, Any]) -> datetime | None:
    license_block = payload.get("license")
    window_days = (
        license_block.get("revocation_window_days") if isinstance(license_block, dict) else None
    )
    if not isinstance(window_days, int) or isinstance(window_days, bool):
        return None
    issued = _parse_iso(payload.get("issued_at"))
    if issued is None:
        return None
    return issued + timedelta(days=window_days)


def _within_refund_window(record: dict[str, Any], window_end: datetime | None) -> bool:
    if window_end is None:
        return False
    revoked_at = _parse_iso(record.get("revoked_at"))
    if revoked_at is None:
        return False
    try:
        return revoked_at <= window_end
    except TypeError:
        return False  # incomparable naive/aware mix — fail closed, never effective


def _revocation_deadline_satisfied(
    effective: list[dict[str, Any]],
    revocation_evidence: dict[str, Any] | None,
    issuer_id: str | None,
    log_keys: list[tlog.LogKey],
    anchor_policy: anchor.AnchorPolicy,
    window_end: datetime | None,
    warnings: list[str],
) -> bool:
    """G5 (v0.2 §8/§15, TM-47): True iff at least one of `effective`'s
    refund_window revocation records has Stage 2 evidence proving it was
    logged AND anchored no later than `window_end` — the SAME refund-window
    deadline `_refund_window_end`/`_within_refund_window` already compute,
    never a second definition of "deadline".

    Only called once the caller has ALREADY established the verifier is
    Stage-2 capable (`log_keys`/`anchor_policy` both supplied) and `effective`
    is non-empty; `revocation_evidence` itself may still be absent or fail to
    resolve — either way this returns `False`, so a Stage-2-capable verifier
    with no (or unresolvable) evidence for this specific record never honors
    it. `log_keys`/`anchor_policy` are the same trusted, verifier-config
    values `_evaluate_transparency_claim` validates for receipt/key-manifest
    claims; malformed ones raise `TransparencyError` here too (a config bug),
    exactly the same discipline.

    Every warning the shared evaluator returns for a candidate record (e.g.
    `anchor_note_only`, malformed-evidence reasons, `log_equivocation_detected`)
    is appended to `warnings` (dedup against identical strings already
    present) regardless of whether that record ends up timely — mirrors
    `_evaluate_transparency_claim`'s own `warnings.extend(result.warnings)`.
    """
    if revocation_evidence is None or window_end is None:
        return False

    origin = _resolve_log_origin(log_keys)
    transparency_module._validate_policy(anchor_policy)

    try:
        # verify()'s untrusted-evidence boundary, mirroring
        # `_evaluate_transparency_claim`: canonicalize and parse once so
        # every following phase sees one ordinary JSON object, never a
        # stateful mapping/value supplied by the caller.
        # Own-data copy first, for the same reason as the transparency sink:
        # the code-point cap cannot fire on a serialization that never returns.
        serialized_evidence = canon.dumps(
            _own_data_copy(revocation_evidence, [_MAX_EVIDENCE_NODES])
        )
        if len(serialized_evidence) > _MAX_TRANSPARENCY_EVIDENCE_LEN:
            return False
        materialized_evidence = json.loads(serialized_evidence)
        if not isinstance(materialized_evidence, dict):
            return False
    # Adversarial-boundary confinement (never BaseException): a hostile
    # `revocation_evidence` mapping's `__eq__`/`__getitem__` must not escape
    # as a bare exception, mirroring `_evaluate_transparency_claim`.
    except Exception:
        return False

    for record in effective:
        try:
            record_hash = revocation.record_hash(record)
        except (TypeError, canon.CanonError):
            continue
        expected_entry = _validated_transparency_entry(
            {
                "type": _CLAIM_TYPE_REVOCATION_RECORD,
                "issuer": issuer_id,
                "record_sha256": record_hash,
            }
        )
        if expected_entry is None:
            continue
        result = transparency_module.evaluate_transparency(
            materialized_evidence,
            log_keys=log_keys,
            expected_origin=origin,
            policy=anchor_policy,
            expected_entry=expected_entry,
        )
        for warning in result.warnings:
            if warning not in warnings:
                warnings.append(warning)
        if not result.transparency.startswith(_ANCHORED_BEFORE_PREFIX):
            continue
        anchored_time = _parse_iso(result.transparency[len(_ANCHORED_BEFORE_PREFIX) :])
        if anchored_time is None:
            continue
        try:
            if anchored_time <= window_end:
                return True
        except TypeError:
            continue  # incomparable naive/aware mix — fail closed, never timely
    return False


def _resolve_transfer_backing(
    payload: dict[str, Any],
    transfer_view: list[dict[str, Any]],
    issuer_manifest: dict[str, Any],
    issuer_id: str | None,
    log_keys: list[tlog.LogKey] | None,
    anchor_policy: anchor.AnchorPolicy | None,
    warnings: list[str],
) -> dict[str, Any] | None:
    """v0.2 §17.2-§17.4 (Stage 3): the winning, BACKED transfer record for
    `payload`'s own `receipt_id` among `transfer_view`'s untrusted claims
    (`{"record": <transfer record>, "evidence": <§10.2 evidence bundle>}`),
    or `None` if no claim survives every gate below.

    `transfer_view` is materialized once at the untrusted boundary — the
    SAME `canon.dumps`/size-bound/`except Exception` confinement
    `_revocation_deadline_satisfied` already applies to `revocation_evidence`
    — so every later phase sees ordinary JSON values, never a stateful/
    hostile mapping or list a caller constructed.

    Per claim, in this exact order (§17.3's consent gate plus §17.7/§17.2):

    1. `record` is a dict whose `receipt_id` equals `payload`'s own — else
       the claim is irrelevant to this receipt and is skipped silently.
    2. `transfer.verify_record_signature(record, issuer_manifest)` — the
       issuer's own signature (hoisting `manifests.verify_key_manifest` once
       here, mirroring `_classify_revocation`'s own hoisting of the same
       check — this function is called at most once per classification).
       On failure: `_WARN_TRANSFERRED_REVOCATION_UNBACKED` (deduplicated),
       skip.
    3. `payload["buyer"]["pubkey"]` is a non-null string AND
       `transfer.verify_authorization(record, pubkey)` — the OLD receipt's
       own holder consented. Same unbacked warning on failure, skip.
    4. If `payload["license"]["not_transferable_before"]` is present: both
       timestamps parse (fail-closed) and `record["transferred_at"]` is not
       earlier than it — else `_WARN_TRANSFER_NOT_YET_TRANSFERABLE`, skip.
    5. Stage-2 capability (`log_keys` AND `anchor_policy` both supplied) and
       `transfer.record_logged_standing(...)` proves this record's own
       `transfer-record` log entry reached at least `logged` standing — else
       `_WARN_TRANSFER_RECORD_UNLOGGED`, skip.

    Survivors are `(leaf_index, record)` pairs; two or more is a double
    assignment (§17.4) — `_WARN_TRANSFER_DOUBLE_ASSIGNMENT` — and the
    EARLIEST log index (first-logged) wins.
    """
    # Admitted PER CLAIM, not as one indivisible view: a claim that cannot be
    # represented is set aside ALONE, and a genuine claim with full backing
    # still reaches its verdict beside it. Admitting the view as a whole would
    # let one malformed sibling delete a real transfer -- a FALSE VALID, since
    # the receipt would read as never transferred.
    try:
        if not isinstance(transfer_view, list):
            return None
        materialized_claims = _materialize_evidence_array(transfer_view, _MAX_TRANSFER_CLAIMS)
    # Adversarial-boundary confinement (never BaseException), mirroring
    # `_revocation_deadline_satisfied`: a hostile `transfer_view` list/dict's
    # `__eq__`/`__getitem__` must not escape as a bare exception.
    except Exception:
        return None
    if materialized_claims is None:
        return None
    if len(materialized_claims) > _MAX_TRANSFER_CLAIMS:
        # The count ceiling is not "one bad claim": it truncates evaluation,
        # and a truncated transfer view cannot be told apart from a view with
        # no transfer in it. Fail closed by declining to resolve any backing.
        return None
    materialized = materialized_claims

    receipt_id = payload.get("receipt_id")
    # The receipt gate's predicate, deliberately, not `verify_key_manifest`:
    # a manifest downgraded by deleting its PQ leg loses its TRUST LEVEL,
    # never its power to revoke. The two must not disagree about whether
    # the same manifest is authentic — a manifest good enough to certify a
    # receipt and not good enough to carry the same issuer's revocation
    # turns a revocation into silence, and reaching that gap costs an
    # attacker one deletion and no key: `manifest_signature` sits outside
    # the signed bytes. Severe where evidence can SAVE, permissive where it
    # can only KILL.
    manifest_ok = manifests.manifest_signature_is_authentic(issuer_manifest)

    def _append_once(warning: str) -> None:
        if warning not in warnings:
            warnings.append(warning)

    survivors: dict[str, tuple[int, dict[str, Any]]] = {}
    for claim in materialized:
        if not isinstance(claim, dict):
            continue
        record = claim.get("record")
        if not isinstance(record, dict) or record.get("receipt_id") != receipt_id:
            continue

        if not manifest_ok or not transfer.verify_record_signature(record, issuer_manifest):
            _append_once(_WARN_TRANSFERRED_REVOCATION_UNBACKED)
            continue

        buyer = payload.get("buyer")
        holder_pubkey = buyer.get("pubkey") if isinstance(buyer, dict) else None
        if not isinstance(holder_pubkey, str) or not transfer.verify_authorization(
            record, holder_pubkey
        ):
            _append_once(_WARN_TRANSFERRED_REVOCATION_UNBACKED)
            continue

        license_block = payload.get("license")
        not_transferable_before = (
            license_block.get("not_transferable_before")
            if isinstance(license_block, dict)
            else None
        )
        if not_transferable_before is not None:
            transferred_at = _parse_iso(record.get("transferred_at"))
            floor = _parse_iso(not_transferable_before)
            honored = False
            if transferred_at is not None and floor is not None:
                try:
                    honored = transferred_at >= floor
                except TypeError:
                    honored = False  # incomparable naive/aware mix — fail closed
            if not honored:
                _append_once(_WARN_TRANSFER_NOT_YET_TRANSFERABLE)
                continue

        leaf_index = None
        if log_keys is not None and anchor_policy is not None:
            leaf_index = transfer.record_logged_standing(
                record,
                claim.get("evidence"),
                issuer_id if issuer_id is not None else "",
                log_keys,
                anchor_policy,
                warnings,
            )
        if leaf_index is None:
            _append_once(_WARN_TRANSFER_RECORD_UNLOGGED)
            continue

        record_hash = transfer.record_hash(record)
        previous = survivors.get(record_hash)
        if previous is None or leaf_index < previous[0]:
            survivors[record_hash] = (leaf_index, record)

    if not survivors:
        return None
    if len(survivors) > 1:
        _append_once(_WARN_TRANSFER_DOUBLE_ASSIGNMENT)
    return min(survivors.values(), key=lambda item: item[0])[1]


def _classify_revocation(
    payload: dict[str, Any],
    revocation_view: list[dict[str, Any]] | None,
    issuer_manifest: dict[str, Any],
    warnings: list[str],
    errors: list[str],
    max_records: int = _MAX_REVOCATION_RECORDS,
    log_keys: list[tlog.LogKey] | None = None,
    anchor_policy: anchor.AnchorPolicy | None = None,
    revocation_evidence: dict[str, Any] | None = None,
    transfer_view: list[dict[str, Any]] | None = None,
) -> str:
    """§6 step 6 / §3.1: revocation-by-class.

    A record is a candidate revocation for THIS receipt only if it (a)
    matches the payload's `receipt_id`, (b) authenticates against
    `issuer_manifest` (`revocation.verify_record`: active, in-window,
    correctly signed — the §5 hardening), and (c) carries
    `status == "revoked"` (any other status is not a revocation statement).
    A matching record that fails authentication is ignored with a warning
    (turning a would-be silent DoS into a visible ignore). What an effective
    record then *means* depends on `license.revocability`:

    - "none": ANY effective record is itself invalid — this is the
      irrevocability guarantee (design vector 16). The receipt stays `ok`.
    - "policy": any effective record is honored as-is (terms govern; the
      verifier cannot evaluate them, so a signed record is trusted).
    - "refund_window": an effective record is honored only if its own signed
      `revoked_at` falls within `issued_at + revocation_window_days` —
      evaluated against the record's own signed time, never local clock.
      G5 (TM-47) adds a deadline-EFFECTIVENESS rule on top, gated on the
      verifier being Stage-2 capable (`log_keys`/`anchor_policy` both
      supplied, exactly `_evaluate_transparency_claim`'s existing gate): a
      window-effective record is honored only if `revocation_evidence`
      proves it was logged (`revocation-record` entry, §8) AND anchored no
      later than the SAME refund-window deadline — see
      `_revocation_deadline_satisfied`. A verifier that is not Stage-2
      capable at all keeps v0.1 semantics unchanged (eternal verifiability:
      the rule only engages where a verifier actually asks for it).
      `policy`/`compromised`/`none` classes are UNAFFECTED by this rule —
      logging remains optional corroboration for them, never a gate.

    The `not_revoked_as_of:<T>` freshness anchor is computed over ALL
    authenticated STATEMENT-STATUS records in the view (any receipt_id;
    `status` `revoked`/`transferred` only, §12.3 as amended 2026-08-26), not
    the raw view — so neither unsigned junk nor a signed non-statement can
    revoke or inflate T. With no authenticated statement-status records at
    all, T has no trustworthy value and the result is `unknown`.

    An oversized view (more than `max_records` entries) is not evaluated —
    never truncated (a subset could misreport), never raised. It fails CLOSED
    for every revocability class: for `policy`/`refund_window` an untrusted
    view too large to evaluate cannot rule out a revocation, and for `none`
    (irrevocable) it cannot rule out a *transfer* either — v0.2 §17.3's
    consent gate applies to ALL revocability classes, and a BACKED
    `status: "transferred"` record rides this same view. Both are recorded
    as an error (`ok` becomes `false`); otherwise an append-only
    feed-poisoning attacker could suppress genuine evidence by padding past
    the cap. In both cases revocation is `"unknown"`.

    v0.2 Stage 3 (§17.3, design doc §4): once the `"revoked"`-status logic
    above has run to completion WITHOUT itself yielding `_REVOCATION_REVOKED`
    — byte-identical to pre-Stage-3 behavior; this ordering is what keeps
    every existing conformance leaf unchanged — an authenticated, matching
    `status == "transferred"` record is additionally considered, for ALL
    revocability classes, `none` included (the consent-gate principle,
    §17.3): a BACKED winner (see `_resolve_transfer_backing`) yields
    `_REVOCATION_TRANSFERRED`; otherwise the outcome reverts to whatever the
    `"revoked"`-status logic already computed, and
    `_WARN_TRANSFERRED_REVOCATION_UNBACKED` is appended UNLESS the resolver
    itself already appended a more specific warning
    (`transfer_record_unlogged`/`transfer_not_yet_transferable`) or
    `transfer_view` was never supplied at all — in which case the resolver is
    never reached, and this function appends the unbacked warning directly.
    """
    if revocation_view is None:  # no data, no freshness anchor either way
        return _REVOCATION_UNKNOWN

    # 18.4: the caller's view is ADMITTED ONCE, per record, before anything
    # reads it -- and from here on ONLY the reconstruction is read. Two
    # properties depend on that being the first thing this function does:
    #
    #   * the two passes below correlate authentication with matching by
    #     `id()`, which assumes both passes see the SAME objects. A `list`
    #     subclass whose `__iter__` returns FRESH objects on the second pass
    #     satisfies `isinstance(..., list)` and desynchronizes them, so a
    #     genuinely signed, matching record can be reported `not_revoked`.
    #     Plain reconstructed records have stable identity, which closes it by
    #     construction rather than by a defensive read.
    #   * the bytes a signature is verified over and the values consumed
    #     afterwards must come from ONE reconstruction. Reading the live
    #     object a second time is what lets a caller authenticate one value
    #     and be judged on another, with the issuer's genuine signature.
    #
    # The element count comes from `list.__len__` and never from iteration:
    # an unbounded `__iter__` would hang the verifier before any ceiling could
    # fire, and no `except` clause is ever reached by a value that does not
    # return. A view that is not a list keeps the caller-contract behaviour it
    # has always had -- 18.4 leaves the declared container shape to the rail.
    supplied: int
    admitted_view: Any
    if isinstance(revocation_view, list):
        supplied = list.__len__(revocation_view)
        if supplied == 0:
            return _REVOCATION_UNKNOWN
    else:
        if not revocation_view:
            return _REVOCATION_UNKNOWN
        supplied = len(revocation_view)

    license_block = payload.get("license")
    revocability = license_block.get("revocability") if isinstance(license_block, dict) else None

    if supplied > max_records:
        if revocability in (_REVOCABILITY_POLICY, _REVOCABILITY_REFUND_WINDOW):
            # Revocable receipt + an untrusted view too large to evaluate: fail
            # closed. "unknown" here would keep ok=true, letting an append-only
            # feed-poisoning attacker suppress a genuine revocation by padding
            # past the cap. We cannot rule out a revocation, so we cannot certify.
            errors.append(
                f"revocation view exceeds {max_records} records "
                f"({supplied} supplied), cannot certify a revocable receipt"
            )
        else:
            # Irrevocable ("none") or unknown-class (rejected at schema). This
            # branch used to be a non-fatal warning, on the grounds that "a
            # revocation can never affect ok" — true when it was written, and
            # false since v0.2 §17.3 made the consent gate apply to ALL
            # revocability classes, `none` included: a BACKED
            # `status: "transferred"` record caps `ok` for this class too, and
            # those records ride this very view (see `_classify_revocation`'s
            # docstring). Returning early on size therefore discarded them as
            # well, so whoever could append to the view chose which transfer the
            # verifier never saw. We cannot rule out a transfer, so we cannot
            # certify.
            errors.append(
                f"revocation view exceeds {max_records} records "
                f"({supplied} supplied), cannot rule out a transfer"
            )
        return _REVOCATION_UNKNOWN

    if isinstance(revocation_view, list):
        # Per RECORD: an inadmissible record is set aside ALONE (it lands as
        # `None` and no pass treats it as a record), and its admissibility
        # decides no sibling's. The ceiling is already known to hold here, so
        # this never walks more than `max_records` elements.
        admitted_view = _materialize_evidence_array(revocation_view, max_records) or []
    else:
        admitted_view = revocation_view

    receipt_id = payload.get("receipt_id")

    # Authenticated records (any receipt_id) drive the freshness anchor; only
    # signature-verified records may set T (§5 hardening). The manifest's own
    # self-verify is hoisted out of the loop — one check per classification,
    # not per record, so a hostile many-record feed cannot multiply
    # manifest-verification work (review improvement #17).
    # The receipt gate's predicate, deliberately, not `verify_key_manifest`:
    # a manifest downgraded by deleting its PQ leg loses its TRUST LEVEL,
    # never its power to revoke. The two must not disagree about whether
    # the same manifest is authentic — a manifest good enough to certify a
    # receipt and not good enough to carry the same issuer's revocation
    # turns a revocation into silence, and reaching that gap costs an
    # attacker one deletion and no key: `manifest_signature` sits outside
    # the signed bytes. Severe where evidence can SAVE, permissive where it
    # can only KILL.
    manifest_ok = manifests.manifest_signature_is_authentic(issuer_manifest)
    authenticated_ids: set[int] = set()
    authenticated: list[dict[str, Any]] = []
    if manifest_ok:
        for record in admitted_view:
            if isinstance(record, dict) and revocation.verify_record_signature(
                record, issuer_manifest
            ):
                authenticated.append(record)
                authenticated_ids.add(id(record))
    not_revoked = _not_revoked_or_unknown(authenticated)

    # Effective revocations for THIS receipt: matching receipt_id, authenticated,
    # and status == "revoked". Matching-but-unauthenticated records are warned.
    # A matching, authenticated `status == "transferred"` record (Stage 3,
    # §17.3) is collected separately — it is not a "revoked"-status statement,
    # so it plays no part in the "revoked"-status dispatch below.
    # A record that was NOT ADMITTED still has to be VISIBLE if it claims to be
    # about this receipt: 12.2 makes an unauthenticated matching record an
    # ignore WITH A WARNING, which is what stops a forged record from silently
    # disappearing, and an inadmissible record is less than unauthenticated.
    # The claim is read the only way the boundary allows -- the diagnostic
    # member alone, through the same own-data primitives, never the value that
    # made the record inadmissible -- and it decides NOTHING but the warning.
    if isinstance(revocation_view, list):
        diagnostic_budget = [_MAX_EVIDENCE_NODES]
        for index, admitted_record in enumerate(admitted_view):
            if admitted_record is not None:
                continue
            original = list.__getitem__(revocation_view, index)
            if not isinstance(original, dict):
                continue
            claimed = _own_view_member(original, "receipt_id", diagnostic_budget)
            if claimed is _VIEW_MEMBER_ABSENT or claimed is _VIEW_MEMBER_COLLAPSED:
                continue
            if not isinstance(claimed, str):
                continue
            claimed_admitted, claimed_id = _admit_evidence_value(
                claimed, _VIEW_ARRAY_ELEMENT_NESTING
            )
            if claimed_admitted and claimed_id == receipt_id:
                warnings.append(
                    f"revocation record for {receipt_id!r} failed verification, ignored"
                )

    valid: list[dict[str, Any]] = []
    transferred_matches: list[dict[str, Any]] = []
    for record in admitted_view:
        if not isinstance(record, dict) or record.get("receipt_id") != receipt_id:
            continue
        if id(record) not in authenticated_ids:
            warnings.append(f"revocation record for {receipt_id!r} failed verification, ignored")
            continue
        if record.get("status") == _RECORD_STATUS_REVOKED:
            valid.append(record)
        elif record.get("status") == _REVOCATION_TRANSFERRED:
            transferred_matches.append(record)

    def _revoked_class_result() -> str:
        """The pre-Stage-3 `"revoked"`-status dispatch, unchanged — kept as a
        nested function purely so its result can be captured before the
        Stage 3 transferred-class check runs (see the enclosing docstring)."""
        if revocability == _REVOCABILITY_NONE:
            if valid:
                warnings.append(
                    "revocation record ignored: license.revocability is 'none' (irrevocable)"
                )
                return _REVOCATION_INVALID_IGNORED
            return not_revoked

        if revocability == _REVOCABILITY_POLICY:
            if valid:
                return _REVOCATION_REVOKED
            return not_revoked

        if revocability == _REVOCABILITY_REFUND_WINDOW:
            window_end = _refund_window_end(payload)
            effective = [r for r in valid if _within_refund_window(r, window_end)]
            if effective:
                # G5 (TM-47): a Stage-2-capable verifier MUST additionally
                # apply the deadline-effectiveness rule — a window-effective
                # record is honored only with evidence proving it was logged
                # and anchored no later than `window_end`. A verifier that
                # never supplies log_keys/anchor_policy at all is not
                # Stage-2 capable, so the rule does not engage and v0.1
                # semantics stand.
                if log_keys is not None and anchor_policy is not None:
                    deadline_issuer_id = (
                        issuer_manifest.get("issuer") if isinstance(issuer_manifest, dict) else None
                    )
                    if not _revocation_deadline_satisfied(
                        effective,
                        revocation_evidence,
                        deadline_issuer_id if isinstance(deadline_issuer_id, str) else None,
                        log_keys,
                        anchor_policy,
                        window_end,
                        warnings,
                    ):
                        warnings.append(_WARN_REVOCATION_UNLOGGED_DEADLINE)
                        return _REVOCATION_INVALID_IGNORED
                return _REVOCATION_REVOKED
            if valid:  # matched and verified, but every one fell outside the window
                warnings.append(
                    f"revocation record for {receipt_id!r} outside refund window, ignored"
                )
                return _REVOCATION_INVALID_IGNORED
            return not_revoked

        # Unknown/malformed revocability: schema validation (step 5, already
        # run before this is ever called) should reject this payload outright
        # — fail closed by never honoring a match under an unrecognized class.
        return not_revoked

    revoked_result = _revoked_class_result()
    if revoked_result == _REVOCATION_REVOKED:
        return revoked_result

    # --- Stage 3 (§17.3): transferred-class backing, considered only once
    # the "revoked"-status logic above did NOT itself yield "revoked" — and
    # for ALL revocability classes, `none` included (the consent-gate
    # principle).
    if transferred_matches:
        if transfer_view is None:
            # The resolver is never reached at all — this function is the
            # only place left to report the unbacked outcome.
            if _WARN_TRANSFERRED_REVOCATION_UNBACKED not in warnings:
                warnings.append(_WARN_TRANSFERRED_REVOCATION_UNBACKED)
            return _REVOCATION_INVALID_IGNORED

        manifest_issuer_id = (
            issuer_manifest.get("issuer") if isinstance(issuer_manifest, dict) else None
        )
        winner = _resolve_transfer_backing(
            payload,
            transfer_view,
            issuer_manifest,
            manifest_issuer_id if isinstance(manifest_issuer_id, str) else None,
            log_keys,
            anchor_policy,
            warnings,
        )
        if winner is not None:
            return _REVOCATION_TRANSFERRED
        if not any(
            warning in warnings
            for warning in (
                _WARN_TRANSFERRED_REVOCATION_UNBACKED,
                _WARN_TRANSFER_RECORD_UNLOGGED,
                _WARN_TRANSFER_NOT_YET_TRANSFERABLE,
                _WARN_TRANSFER_DOUBLE_ASSIGNMENT,
            )
        ):
            warnings.append(_WARN_TRANSFERRED_REVOCATION_UNBACKED)
        return _REVOCATION_INVALID_IGNORED

    return revoked_result


def _check_binding_salt(
    buyer: dict[str, Any], identifier: str, identifier_type: str, salt: bytes
) -> str:
    expected = buyer.get("commitment")
    if not isinstance(expected, str):
        return _BINDING_NOT_PROVEN
    try:
        computed = commitment.compute(identifier, identifier_type, salt)
    except ValueError:
        return _BINDING_NOT_PROVEN
    return _BINDING_PROVEN if keys.b64u(computed) == expected else _BINDING_NOT_PROVEN


def _check_binding_challenge(
    payload: dict[str, Any], buyer: dict[str, Any], nonce: bytes, sig: bytes
) -> str:
    pubkey_b64 = buyer.get("pubkey")
    receipt_id = payload.get("receipt_id")
    if not isinstance(pubkey_b64, str) or not isinstance(receipt_id, str):
        return _BINDING_NOT_PROVEN
    try:
        pub = keys.b64u_decode(pubkey_b64)
        proven = commitment.verify_challenge(receipt_id, nonce, sig, pub)
    except (ValueError, TypeError):
        return _BINDING_NOT_PROVEN
    return _BINDING_PROVEN if proven else _BINDING_NOT_PROVEN


def _classify_binding(payload: dict[str, Any], disclosure: Disclosure) -> str:
    """§6 step 7 / §3.2: recompute the commitment (salt path) or verify a
    challenge-response transcript (pubkey path). A malformed/partial
    disclosure (neither path fully populated) fails closed to "not_proven"."""
    buyer = payload.get("buyer")
    if not isinstance(buyer, dict):
        return _BINDING_NOT_PROVEN

    if (
        disclosure.salt is not None
        and disclosure.identifier is not None
        and disclosure.identifier_type is not None
    ):
        return _check_binding_salt(
            buyer, disclosure.identifier, disclosure.identifier_type, disclosure.salt
        )
    if disclosure.challenge is not None:
        nonce, sig = disclosure.challenge
        return _check_binding_challenge(payload, buyer, nonce, sig)
    return _BINDING_NOT_PROVEN


# --- Stage 4: grant evaluation (v0.2 §18.4) ----------------------------------


@dataclass(frozen=True)
class GrantVerdict:
    """The outcome of `evaluate_grant` over one receipt and one evidence view:
    §18.5's two purely informational components plus the warnings §18.4's
    ordered steps emitted along the way.

    Kept separate from `VerificationResult` so the evaluation is callable on
    its own — a custodian checking §18.7's preconditions asks this question
    without re-verifying a receipt it has already verified — and so the
    ordered steps stay testable one at a time."""

    grant: str
    grant_trust: str
    warnings: tuple[str, ...] = ()


def _pledge_or_none(payload: object) -> dict[str, Any] | None:
    """`license.preservation_pledge` when it is readable as an object carrying
    the three REQUIRED members of §18.2 with their declared types, else `None`
    (§18.4 step 1's "absent, or unreadable as an object with the three required
    members").

    The object is deliberately NOT closed: it lives inside the payload, whose
    posture toward unrecognized members is tolerant (v0.1 §11.2), and a future
    pledge profile that needs a fourth member must not be a schema error on a
    verifier that predates it.
    """
    if not isinstance(payload, dict):
        return None
    license_block = payload.get("license")
    if not isinstance(license_block, dict):
        return None
    pledge = license_block.get("preservation_pledge")
    if not isinstance(pledge, dict):
        return None
    if not all(isinstance(pledge.get(member), str) for member in _PLEDGE_MEMBERS):
        return None
    if not pledge["pledge"] or not pledge["grant_uri"]:
        return None
    grant_sha256 = pledge["grant_sha256"]
    if len(grant_sha256) != 64 or not set(grant_sha256) <= _HEX_LOWER:
        return None
    return pledge


def _grant_trust_ladder(trust_store: TrustStore, domain: str, manifest: object) -> str:
    """§18.5's ladder for the PUBLISHER's manifest — v0.1 §11.1's discipline
    for `trust`, applied verbatim to a different domain and reported ONLY in
    `grant_trust`. The receipt's own `trust` component is untouched: it remains
    a statement about the issuer, and a publisher the verifier happens to know
    less well must never downgrade it."""
    level = (
        _TRUST_VERIFIED if trust_store.provenance.get(domain) == _PROVENANCE_TLS else _TRUST_TOFU
    )
    chain = trust_store.chains.get(domain)
    if chain and (not _chain_continuous(chain) or chain[-1] != manifest):
        return _TRUST_UNVERIFIED_ROTATION
    return level


def _fixed_date_reached(
    evidence: object,
    effective: dict[str, Any],
    fixed_date: str,
    anchor_policy: anchor.AnchorPolicy | None,
) -> bool:
    """§18.4's `fixed-date` proof: an anchored attestation over the EFFECTIVE
    grant's own canonical bytes whose proven chain time `T` satisfies
    `T >= fixed_date`, verified under §11 with the caller's own `AnchorPolicy`
    including the CRQC horizon check.

    `T` is the MAXIMUM over the verified proofs (`AnchorVerdict.anchored_after`),
    deliberately the opposite reduction from §11's `anchored_before`: the two
    answer opposite questions, and taking the minimum here would let one old
    genuine proof hold a grant closed the moment a second, newer one is
    presented.

    A verifier with no `AnchorPolicy` is not anchor-capable at all, so the
    proof cannot be evaluated and the grant stays closed — the direction
    §18.4's failure asymmetry requires. Every malformed input degrades to
    `False`; only a malformed POLICY raises, and that is trusted verifier
    config, not evidence.
    """
    if anchor_policy is None or not isinstance(evidence, dict):
        return False
    seed = canon.canonical_bytes(effective)
    verdict = anchor.verify_seeded_anchor(evidence, seed, anchor_policy)
    if not verdict.anchored or verdict.anchored_after is None:
        return False
    if not anchor.passes_horizon(verdict, anchor_policy):
        return False
    try:
        deadline = int(_parse_date(fixed_date).replace(tzinfo=UTC).timestamp())
    except (TypeError, ValueError):
        return False
    return verdict.anchored_after >= deadline


def evaluate_grant(
    payload: dict[str, Any],
    trust_store: TrustStore,
    grant_view: dict[str, Any] | None,
    *,
    anchor_policy: anchor.AnchorPolicy | None = None,
) -> GrantVerdict:
    """§18.4's deterministic, short-circuiting evaluation order, steps 1-11.

    `grant_view` is Stage 4's evidence channel and its capability gate at once,
    exactly as `transfer_view` is Stage 3's: `None` means the caller is not
    Stage-4-capable and NOTHING is evaluated — `not_checked`/`not_checked`, no
    warnings, which is byte-for-byte what every pre-Stage-4 caller already
    implicitly gets. Supplying the channel AT ALL — even as `{}` — opts into
    the ordered evaluation, whose first three steps then read only the signed
    payload and run BEFORE step 4's "no evidence supplied" short circuit, so a
    defect visible in the receipt itself is never masked by missing evidence.

    The view's four members, all optional:

    - `grant`: the FLOOR grant document the receipt hash-binds (§18.2).
    - `later_grants`: versions the verifier additionally holds, each evaluated
      independently AGAINST THE FLOOR (§18.3).
    - `declarations`: cessation declarations (§18.4), scanned in full.
    - `anchor`: ONE §11 evidence bundle for the `fixed-date` proof. One bundle,
      not a list: §18.4's maximum reduction is over the PROOFS inside a bundle,
      which `anchor.verify_seeded_anchor` already computes, and a list would be
      a third attacker-supplied array with no ceiling of its own.

    Per D6 the verdict takes no exception: neither component ever affects
    `signature`, `schema`, `revocation`, `binding`, `trust` or `ok`.

    Which way this fails is normative (§18.4): a false `activated` authorizes
    distribution of a work that is still on sale, a false `dormant` only means
    a buyer cannot yet redeem. Every missing, unverifiable, malformed or
    ambiguous input therefore resolves to `dormant` or `not_checked`, never to
    `activated`. Hostile evidence never raises; only malformed TRUSTED config
    (an `AnchorPolicy`) does.
    """
    if grant_view is not None and not isinstance(grant_view, dict):
        raise TypeError("grant_view must be an evidence object or None")

    warnings: list[str] = []
    if grant_view is None:
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED)
    materialized_grant_view = _materialize_grant_view(grant_view)

    # --- Step 1: the pledge itself, from the signed payload alone.
    pledge = _pledge_or_none(payload)
    if pledge is None:
        return GrantVerdict(_GRANT_NONE, _GRANT_TRUST_NOT_CHECKED)

    # --- Step 2: an unrecognized profile is valid-with-warning as SCHEMA, but
    # MUST NOT be evaluated under `sunset-grant-v1`'s rules — a later profile
    # may attach different meaning to the same members, and guessing is exactly
    # how two conforming implementations reach different verdicts.
    if pledge["pledge"] not in _KNOWN_PLEDGE_TYPES:
        warnings.append(_WARN_GRANT_PLEDGE_TYPE_UNKNOWN)
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))

    # --- Step 3: the issuer's own inconsistency, visible in the signed payload
    # alone, so it is reported whether or not any evidence was supplied. The
    # license term governs and evaluation CONTINUES: the two fields have
    # different authorities, and silently preferring one would hide the
    # inconsistency from the person holding the receipt.
    survivability = payload.get("survivability")
    eol_commitment = (
        survivability.get("eol_commitment_sha256") if isinstance(survivability, dict) else None
    )
    if isinstance(eol_commitment, str) and eol_commitment != pledge["grant_sha256"]:
        warnings.append(_WARN_GRANT_COMMITMENT_DIVERGENCE)

    # --- Step 4: the structural ceilings, then the evidence itself. The
    # ceilings run BEFORE any signature is verified, or they are not ceilings.
    if not isinstance(materialized_grant_view, dict):
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))
    later_grants = cast("list[Any] | None", _own_member(materialized_grant_view, "later_grants"))
    declarations = cast("list[Any] | None", _own_member(materialized_grant_view, "declarations"))
    if not grant_module.within_structural_ceilings(later_grants, declarations):
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))
    floor = _own_member(materialized_grant_view, "grant")
    if not isinstance(floor, dict):
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))

    # --- Step 5: authenticate the floor, then the triple domain binding.
    # `grant_trust` starts at TOFU the moment evidence exists and is reported
    # at its best-available value from here on, even when the evaluation later
    # rejects the document — it MUST NOT be silently reset on failure (§18.5).
    work = payload.get("work")
    publisher_id = work.get("publisher_id") if isinstance(work, dict) else None
    signer = grant_module.signer_domain(floor)
    manifest = trust_store.manifests.get(signer) if isinstance(signer, str) else None
    # The ladder is scoped to the RECEIPT's declared `work.publisher_id` (§18.5,
    # "the trust store's provenance for the resolved `work.publisher_id`"), and
    # NEVER to whatever domain a supplied document happens to name in its `kid`.
    # The document is attacker-supplied and has not authenticated yet at this
    # point: keying the ladder on its signer would let a blob that authenticates
    # against nothing pick any TLS domain the verifier happens to know and buy
    # `grant_trust: "verified"` for the price of appending bytes to an evidence
    # object. The SIGNER's manifest is still what the signature resolves
    # against, below — the two are the same domain in every case that gets past
    # the binding check, and where they differ the answer is `signer_mismatch`,
    # not a trust value borrowed from a stranger.
    grant_trust = (
        _grant_trust_ladder(trust_store, publisher_id, trust_store.manifests.get(publisher_id))
        if isinstance(publisher_id, str)
        else _TRUST_TOFU
    )

    if not isinstance(manifest, dict) or not grant_module.verify_grant(floor, manifest):
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))
    # §18.1: the signer's `kid` DNS prefix MUST equal the resolving manifest's
    # own `issuer`. A trust store that maps one domain to another domain's
    # manifest is a misconfiguration, not a rights-holder mismatch, so it is
    # rejected plainly rather than reported as `signer_mismatch`.
    if manifest.get("issuer") != signer:
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))
    if not isinstance(publisher_id, str) or signer != publisher_id:
        # The marketplace-signing-a-grant-it-has-no-rights-to-concede case,
        # named. Reachable only for a document that ALREADY authenticated
        # (§18.1): an unsigned blob from a foreign domain is a plain rejection,
        # so hostile evidence cannot force a trust value on its own. A receipt
        # with no `publisher_id` at all has no declared rights holder for the
        # signer to mismatch, so that one is a plain rejection too.
        if isinstance(publisher_id, str):
            warnings.append(_WARN_GRANT_SIGNER_NOT_PUBLISHER)
            return GrantVerdict(
                _GRANT_INVALID_IGNORED, _GRANT_TRUST_SIGNER_MISMATCH, tuple(warnings)
            )
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))
    if not _member_equals(floor, "publisher", publisher_id):
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))

    # --- Step 6: the receipt binding. One canonical form, never a second one.
    floor_hash = _grant_hash_or_none(floor)
    if floor_hash is None or floor_hash != pledge["grant_sha256"]:
        warnings.append(_WARN_GRANT_COMMITMENT_MISMATCH)
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))

    # --- Step 7: the floor-relative ratchet (§18.3).
    effective, grant_trust = _resolve_effective_grant(
        floor, floor_hash, later_grants, manifest, grant_trust, warnings
    )

    # --- Step 8: scope coverage, and it is a GATE. Reporting `activated` on an
    # uncovered receipt would tell the holder they may redeem something the
    # grant never spoke about, and would contradict §18.7's own custodian
    # precondition — so neither activation path is evaluated.
    if not grant_module.grant_covers_receipt(effective, payload):
        warnings.append(_WARN_GRANT_SCOPE_UNCOVERED)
        return GrantVerdict(_GRANT_DORMANT, grant_trust, tuple(warnings))

    # --- Step 9: the declaration path, scanned in FULL.
    if _honor_declarations(declarations, effective, trust_store, warnings):
        return GrantVerdict(_GRANT_ACTIVATED, grant_trust, tuple(warnings))

    # --- Step 10: the fixed-date path, reached ONLY because step 9 did not
    # activate. A missing backstop proof says nothing about a grant that is
    # already open, so `grant_unanchored` is not emitted there — that is what
    # keeps the warning set from depending on which spare evidence a caller
    # happened to attach.
    activation = dict.get(effective, "activation")
    modes = dict.get(activation, "modes") if isinstance(activation, dict) else None
    fixed_date = dict.get(activation, "fixed_date") if isinstance(activation, dict) else None
    if isinstance(modes, list) and grant_module.MODE_FIXED_DATE in modes and fixed_date is not None:
        if isinstance(fixed_date, str) and _fixed_date_reached(
            _own_member(materialized_grant_view, "anchor"), effective, fixed_date, anchor_policy
        ):
            return GrantVerdict(_GRANT_ACTIVATED, grant_trust, tuple(warnings))
        warnings.append(_WARN_GRANT_UNANCHORED)

    # --- Step 11.
    return GrantVerdict(_GRANT_DORMANT, grant_trust, tuple(warnings))


def _resolve_effective_grant(
    floor: dict[str, Any],
    floor_hash: str,
    later_grants: object,
    manifest: dict[str, Any],
    grant_trust: str,
    warnings: list[str],
) -> tuple[dict[str, Any], str]:
    """§18.3 step 7: the effective grant is the MAXIMUM `grant_version` over
    the later versions that independently pass both criteria against the FLOOR
    — a maximum over a floor-relative filter, never a sequential fold that
    mutates as candidates are processed, which is what keeps the result
    independent of `later_grants`' presentation order.

    Three ways a supplied version is set aside, deliberately distinguished:

    - It does not AUTHENTICATE against the publisher's manifest: ignored with
      no effect at all. Unauthenticated bytes are free for anyone to produce,
      so letting them move `grant_trust` would hand an attacker a downgrade for
      the price of appending garbage to an array.
    - Its `publisher` differs from the floor's: INADMISSIBLE — §18.3 says such
      a document "is not a later version of this grant at all; it is a
      different grant". It says nothing about this grant's currency, so it is
      ignored with no effect either. (`grant_module.is_non_narrowing` enforces
      the same precondition independently, so a caller holding only that
      predicate cannot be widened into someone else's grant.)
    - It is authenticated, same-publisher, and its `grant_version` is not
      strictly greater than the floor's, or two DISTINCT authenticated
      documents share one `grant_version`: rollback-or-equivocation, rejected
      and reported `grant_trust: "unverified_rotation"` — the same value and
      posture v0.1 §7.3 already uses for manifests. Both are genuine
      publisher-signed artifacts, so an inconsistency among them is a real
      currency signal rather than something an attacker manufactured.

    A byte-identical duplicate of a document already seen is deduplicated
    rather than treated as equivocation: "two DISTINCT authenticated grants" is
    what §18.3 rejects, and a replayed copy is not a second document.
    """
    candidates: dict[str, dict[str, Any]] = {floor_hash: floor}
    for later in later_grants if isinstance(later_grants, list) else []:
        if not isinstance(later, dict) or not grant_module.verify_grant(later, manifest):
            continue
        if not _member_equals(later, "publisher", _own_member(floor, "publisher")):
            continue
        later_hash = _grant_hash_or_none(later)
        if later_hash is None:
            continue
        candidates.setdefault(later_hash, later)

    by_version: dict[int, int] = {}
    for document in candidates.values():
        version = document["grant_version"]
        by_version[version] = by_version.get(version, 0) + 1
    equivocating = {version for version, count in by_version.items() if count > 1}
    if equivocating:
        grant_trust = _TRUST_UNVERIFIED_ROTATION

    floor_version = floor["grant_version"]
    passing: list[dict[str, Any]] = []
    narrowing_seen = False
    for document_hash, document in candidates.items():
        if document_hash == floor_hash:
            continue
        version = document["grant_version"]
        if version in equivocating:
            continue
        if version <= floor_version:
            grant_trust = _TRUST_UNVERIFIED_ROTATION
            continue
        if not grant_module.is_non_narrowing(floor, document):
            narrowing_seen = True
            continue
        passing.append(document)

    if narrowing_seen:
        warnings.append(_WARN_GRANT_NARROWING_IGNORED)
    if not passing:
        return floor, grant_trust

    effective = max(passing, key=lambda document: int(document["grant_version"]))
    if grant_module.prose_differs(floor, effective):
        # The structural members of the later version govern; the prose that
        # binds this buyer stays the one their own receipt hash-bound. All
        # three prose-bearing members count, the URI included: a document
        # served from a new location is a new document to the person who has
        # to go read it, even when the hash is unchanged.
        warnings.append(_WARN_GRANT_LEGAL_TEXT_CHANGED)
    return effective, grant_trust


def _honor_declarations(
    declarations: object,
    effective: dict[str, Any],
    trust_store: TrustStore,
    warnings: list[str],
) -> bool:
    """§18.4 step 9: EVERY supplied declaration is examined; the step never
    stops at the first one that succeeds.

    The full scan is required rather than a short circuit precisely so that the
    warning set is a function of the evidence and not of its arrangement: with
    a mixed set, an implementation that stopped at the first valid declaration
    would report a different result than one that did not, and both would be
    conforming — which is how two honest implementations end up disagreeing in
    front of a user. Both warnings are emitted at most once each.
    """
    honored = False
    by_successor = False
    ignored = False
    for declaration in declarations if isinstance(declarations, list) else []:
        role = grant_module.declaration_signer_role(declaration, effective)
        domain = grant_module.signer_domain(declaration)
        # A successor's manifest is resolved exactly like the publisher's
        # (§18.1) — same shape, same TOFU/TLS ladder, same `compromised`
        # fail-closed. A declaration signed under a key later marked
        # `compromised` ceases to authenticate, and a grant that had activated
        # on it returns to `dormant`: the safe direction, stated in §18.4
        # rather than left to be discovered.
        declaration_manifest = (
            trust_store.manifests.get(domain) if isinstance(domain, str) else None
        )
        if (
            role is None
            or not isinstance(declaration_manifest, dict)
            or declaration_manifest.get("issuer") != domain
            or not grant_module.verify_declaration(declaration, declaration_manifest)
            or not grant_module.declaration_covers_grant(declaration, effective)
        ):
            ignored = True
            continue
        honored = True
        by_successor = by_successor or role == grant_module.SIGNER_ROLE_SUCCESSOR

    if ignored:
        warnings.append(_WARN_GRANT_DECLARATION_IGNORED)
    if honored and by_successor:
        # Informational, never a downgrade: the caller can see that the
        # cessation was declared by a designated third party rather than by
        # the rights holder itself.
        warnings.append(_WARN_GRANT_ACTIVATED_BY_SUCCESSOR)
    return honored


# --- Stage 5: publisher authority evaluation (v0.2 section 20.4) ------------


@dataclass(frozen=True)
class AuthorityVerdict:
    """Section 20.5's authority components plus warnings produced by section
    20.4's ordered evaluation."""

    publisher_authority: str
    publisher_authority_trust: str
    warnings: tuple[str, ...] = ()


def _own_member(document: object, member: str) -> object:
    return dict.get(document, member) if isinstance(document, dict) else None


def _member_equals(document: object, member: str, expected: object) -> bool:
    """`_own_member` plus the comparison, fail-closed.

    An own-item read defeats an overridden `get`, but it hands back whatever
    the member holds — and a `str` subclass that refuses to be compared
    canonicalizes, signs and authenticates exactly like the string it shadows,
    so it survives to the binding checks that run AFTER authentication. This
    is the `__eq__` trigger `authority.entry_for_issuer` names as the reason
    an own-item read still needs an enclosing guard. A value that will not
    compare is not equal to anything: every binding this decides fails closed.
    """
    try:
        return isinstance(document, dict) and bool(dict.get(document, member) == expected)
    except Exception:
        return False


def _authorization_hash_or_none(candidate: object, warnings: list[str]) -> str | None:
    try:
        return authority_module.authorization_hash(cast(dict[str, Any], candidate))
    except Exception:
        _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
        return None


def _grant_hash_or_none(candidate: object) -> str | None:
    """`grant_hash` behind the same fail-closed boundary
    `_authorization_hash_or_none` puts around `authorization_hash`.

    Canonicalization walks a mapping with `__iter__` and `__getitem__`, both of
    which caller-supplied content can override, so hashing a document that
    arrived on an evidence rail is one of the few places §18.4's never-raise
    promise can still be broken after every member read has been made an
    own-item read. The builder-side helpers stay loud on purpose; the boundary
    belongs at the verifier's call site, exactly as §20.4's does.
    """
    try:
        return grant_module.grant_hash(cast(dict[str, Any], candidate))
    except Exception:
        return None


def _admitted_authorizations(
    authorizations: list[Any],
    trust_store: TrustStore,
    publisher_id: str,
    authority_trust: str,
    warnings: list[str],
) -> tuple[dict[str, dict[str, Any]], str]:
    admitted: dict[str, dict[str, Any]] = {}
    seen_hashes: set[str] = set()
    for candidate in authorizations:
        document_hash = _authorization_hash_or_none(candidate, warnings)
        if document_hash is None or document_hash in seen_hashes:
            continue
        seen_hashes.add(document_hash)

        if not isinstance(candidate, dict):
            _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
            continue
        document = candidate
        signer = grant_module.signer_domain(document)
        manifest = trust_store.manifests.get(signer) if isinstance(signer, str) else None
        if not isinstance(manifest, dict) or not authority_module.verify_authorization(
            document, manifest
        ):
            _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
            continue
        if not _member_equals(manifest, "issuer", signer) or not _member_equals(
            document, "publisher", publisher_id
        ):
            _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
            continue
        if signer != publisher_id:
            _append_warning_once(warnings, _WARN_AUTHORIZATION_SIGNER_NOT_PUBLISHER)
            authority_trust = _AUTHORITY_TRUST_SIGNER_MISMATCH
            continue
        admitted[document_hash] = document
    return admitted, authority_trust


def _entries_by_issuer(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = cast(list[dict[str, Any]], document["authorized_issuers"])
    return {entry["issuer_id"]: entry for entry in entries}


def _window_shortens(previous_valid_to: str | None, valid_to: str | None) -> bool:
    if valid_to is None:
        return False
    if previous_valid_to is None:
        return True
    return transfer._parse_date(valid_to) < transfer._parse_date(previous_valid_to)


def _restriction_outside_bounds(
    predecessor_issued_at: str, successor_issued_at: str, valid_to: str
) -> bool:
    endpoint = transfer._parse_date(valid_to)
    return endpoint < transfer._parse_date(
        predecessor_issued_at
    ) or endpoint > transfer._parse_date(successor_issued_at)


def _breaks_successor_discipline(predecessor: dict[str, Any], successor: dict[str, Any]) -> bool:
    try:
        successor_entries = _entries_by_issuer(successor)
        successor_issued_at = cast(str, successor["issued_at"])
        predecessor_issued_at = cast(str, predecessor["issued_at"])
        for predecessor_entry in cast(list[dict[str, Any]], predecessor["authorized_issuers"]):
            issuer_id = predecessor_entry["issuer_id"]
            successor_entry = successor_entries.get(issuer_id)
            if successor_entry is None:
                return True
            if successor_entry["valid_from"] != predecessor_entry["valid_from"]:
                return True

            predecessor_valid_to = cast(str | None, predecessor_entry["valid_to"])
            valid_to = cast(str | None, successor_entry["valid_to"])
            if authority_module.window_spent_at(predecessor_valid_to, successor_issued_at):
                if not authority_module.same_instant(predecessor_valid_to, valid_to):
                    return True
                continue

            if (
                _window_shortens(predecessor_valid_to, valid_to)
                and valid_to is not None
                and _restriction_outside_bounds(
                    predecessor_issued_at, successor_issued_at, valid_to
                )
            ):
                return True
    except Exception:
        return True
    return False


def _effective_authorization(
    admitted: dict[str, dict[str, Any]], authority_trust: str
) -> tuple[dict[str, Any] | None, str]:
    by_version: dict[int, int] = {}
    for document in admitted.values():
        version = int(cast(int, dict.get(document, "authorization_version")))
        by_version[version] = by_version.get(version, 0) + 1

    equivocating = {version for version, count in by_version.items() if count > 1}
    if equivocating:
        authority_trust = _TRUST_UNVERIFIED_ROTATION

    survivors = {
        document_hash: document
        for document_hash, document in admitted.items()
        if int(cast(int, dict.get(document, "authorization_version"))) not in equivocating
    }
    excluded: set[str] = set()
    for predecessor_hash, predecessor in survivors.items():
        predecessor_version = int(cast(int, dict.get(predecessor, "authorization_version")))
        for successor_hash, successor in survivors.items():
            if predecessor_hash == successor_hash:
                continue
            if predecessor_version >= int(cast(int, dict.get(successor, "authorization_version"))):
                continue
            if _breaks_successor_discipline(predecessor, successor):
                excluded.add(successor_hash)

    if excluded:
        authority_trust = _TRUST_UNVERIFIED_ROTATION

    effective_candidates = [
        document for document_hash, document in survivors.items() if document_hash not in excluded
    ]
    if not effective_candidates:
        return None, authority_trust
    return (
        max(
            effective_candidates,
            key=lambda document: int(cast(int, dict.get(document, "authorization_version"))),
        ),
        authority_trust,
    )


def evaluate_publisher_authority(
    payload: dict[str, Any],
    trust_store: TrustStore,
    authority_view: dict[str, Any] | None,
) -> AuthorityVerdict:
    """Section 20.4's deterministic, short-circuiting evaluation order."""
    if authority_view is not None and not isinstance(authority_view, dict):
        raise TypeError("authority_view must be an evidence object or None")

    warnings: list[str] = []
    if authority_view is None:
        return AuthorityVerdict(_AUTHORITY_NOT_CHECKED, _AUTHORITY_NOT_CHECKED)
    materialized_authority_view = _materialize_authority_view(authority_view)

    # --- Step 1.
    work = _own_member(payload, "work")
    publisher_id = _own_member(work, "publisher_id")
    if not isinstance(publisher_id, str):
        return AuthorityVerdict(_AUTHORITY_NO_CLAIM, _AUTHORITY_NOT_CHECKED)

    # --- Step 2.
    issuer = _own_member(payload, "issuer")
    issuer_id = _own_member(issuer, "id")
    if not isinstance(issuer_id, str):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)

    # --- Step 3.
    if publisher_id == issuer_id:
        return AuthorityVerdict(_AUTHORITY_SELF, _AUTHORITY_NOT_CHECKED)

    # --- Step 4.
    if not isinstance(materialized_authority_view, dict):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)
    authorizations = _own_member(materialized_authority_view, "authorizations")
    if not isinstance(authorizations, list):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)
    if not authority_module.within_structural_ceiling(authorizations):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)
    if len(authorizations) == 0:
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)

    # --- Step 5. The ladder is keyed to the RECEIPT's publisher claim, never
    # to any domain named by a supplied document's kid; the document is still
    # attacker-supplied bytes at this point.
    authority_trust = _grant_trust_ladder(
        trust_store, publisher_id, trust_store.manifests.get(publisher_id)
    )

    # --- Step 6.
    admitted, authority_trust = _admitted_authorizations(
        authorizations, trust_store, publisher_id, authority_trust, warnings
    )

    # --- Step 7.
    effective, authority_trust = _effective_authorization(admitted, authority_trust)
    if effective is None:
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, authority_trust, tuple(warnings))

    # --- Step 8 is the `effective` selection above.

    # --- Step 9.
    entry = authority_module.entry_for_issuer(effective, issuer_id)
    if entry is not None and authority_module.entry_authorizes_receipt(entry, payload):
        return AuthorityVerdict(_AUTHORITY_AUTHORIZED, authority_trust, tuple(warnings))

    # --- Step 10.
    assertion = _own_member(materialized_authority_view, "current_authorization_version")
    if authority_module.is_authorization_version(assertion) and assertion == dict.get(
        effective, "authorization_version"
    ):
        warnings.append(_WARN_PUBLISHER_NOT_AUTHORIZING_ISSUER)
        return AuthorityVerdict(_AUTHORITY_UNAUTHORIZED, authority_trust, tuple(warnings))
    return AuthorityVerdict(_AUTHORITY_UNATTESTED, authority_trust, tuple(warnings))


def verify(
    envelope_bytes: bytes,
    trust_store: TrustStore,
    revocation_view: list[dict[str, Any]] | None = None,
    disclosure: Disclosure | None = None,
    max_revocation_records: int = _MAX_REVOCATION_RECORDS,
    *,
    transparency: dict[str, Any] | None = None,
    log_keys: list[tlog.LogKey] | None = None,
    anchor_policy: anchor.AnchorPolicy | None = None,
    revocation_evidence: dict[str, Any] | None = None,
    transfer_view: list[dict[str, Any]] | None = None,
    compromise_view: list[dict[str, Any]] | None = None,
    witness_policy: object = None,
    grant_view: dict[str, Any] | None = None,
    authority_view: dict[str, Any] | None = None,
) -> VerificationResult:
    """§6 steps 0-7. `max_revocation_records` bounds the untrusted revocation
    view: a larger view is not evaluated (revocation `"unknown"`). It fails
    closed for revocable receipts (`policy`/`refund_window`: an error, so
    `ok` is false) and warns for irrevocable `none` receipts.

    `transparency`/`log_keys`/`anchor_policy` are Stage 2 additions (design
    doc "transparency/corroboration layer"), all keyword-only and defaulting
    to `None` — an existing caller who never passes them sees ZERO behavior
    change: `signature`/`schema`/`revocation`/`binding`/`trust`/`ok` are
    entirely unaffected by these three, which only ever populate the new
    `transparency`/`corroboration`/`manifest_freshness` result components.
    `transparency` carries one untrusted evidence bundle (see
    `attest.transparency.evaluate_transparency`); `log_keys`/`anchor_policy`
    are the verifier's trusted, pinned configuration for evaluating it. A
    malformed `log_keys`/`anchor_policy` raises `attest.transparency.
    TransparencyError` (a config bug); malformed/absent `transparency`
    evidence never raises, only degrades the three new components.

    `revocation_evidence` is G5's (v0.2 §8/§15, TM-47) one exception to the
    "Stage 2 is purely informational" rule: it carries one untrusted
    transparency evidence bundle for a SPECIFIC `refund_window` revocation
    record in `revocation_view`, reusing the SAME `log_keys`/`anchor_policy`
    configuration. Once a verifier is Stage-2 capable (`log_keys` AND
    `anchor_policy` both supplied — the same gate that already governs
    `transparency`), a `refund_window` record is honored only if this
    evidence proves it was logged and anchored no later than the receipt's
    own refund-window deadline; see `_revocation_deadline_satisfied` and
    `_classify_revocation`. A verifier that supplies neither `log_keys` nor
    `anchor_policy` is not Stage-2 capable at all, so this rule never
    engages and v0.1 semantics are unchanged — this is what keeps every
    pre-G5 caller's behavior byte-for-byte identical. `policy`/`compromised`/
    `none` revocability classes are entirely unaffected by this parameter.

    `transfer_view` is v0.2 Stage 3's (§17) evidence channel — the SECOND
    sanctioned exception to "Stage 2 is purely informational", after G5's
    `revocation_evidence`: an untrusted list of claims, each `{"record": <a
    transfer.py transfer record>, "evidence": <§10.2 evidence bundle>}`,
    reusing the SAME `log_keys`/`anchor_policy` Stage-2-capability gate
    (both supplied). A `status: "transferred"` record in `revocation_view`
    is honored — `revocation: "transferred"`, capping `ok` the same way
    `"revoked"` already does — only when this channel proves a BACKED
    transfer record for the same `receipt_id`; see
    `_resolve_transfer_backing` and `_classify_revocation`. A caller that
    never supplies `transfer_view` sees ZERO behavior change, exactly like
    every other Stage 2/3 addition.

    `grant_view` is v0.2 Stage 4's (§18) evidence channel and its capability
    gate at once — see `evaluate_grant`, which this delegates to whole. It is
    NOT a third exception to "Stage 2 is purely informational": per D6, Stage 4
    takes no exception at all, so `grant`/`grant_trust` never touch
    `signature`, `schema`, `revocation`, `binding`, `trust` or `ok`. A caller
    that never supplies it gets `not_checked`/`not_checked` and a byte-for-byte
    unchanged result, exactly like every Stage 2/3 addition before it.

    `authority_view` is v0.2 section 20's caller-supplied evidence channel for
    publisher authorization. It is informational only: `publisher_authority`
    and `publisher_authority_trust` never affect receipt validity or issuer
    trust. A caller that never supplies it gets `not_checked`/`not_checked`;
    the existing publisher-claim warning is then stratified from that verdict.

    `compromise_view` is v0.1 rev 8 / v0.2 §19's fourth sanctioned exception
    to the Stage 2 informational rule: a caller-supplied list of key-manifest
    compromise declarations. Authenticated declarations only ever strengthen
    one status, `compromised`; a Stage-2-capable verifier may then spare a
    receipt whose own receipt claim was anchored strictly before the earliest
    anchored compromise declaration for the signing key.
    """
    # Caller-contract enforcement (security): a non-list `revocation_view`
    # must fail loud. If a lone record OBJECT slipped through here,
    # `_classify_revocation` would iterate its string keys, authenticate
    # nothing, and report `revocation: "unknown"` / `ok: true` for a receipt
    # genuinely revoked under `policy`/`refund_window` — a silent pass on a
    # security check. `None` (no view) stays valid.
    if revocation_view is not None and not isinstance(revocation_view, list):
        raise TypeError("revocation_view must be a list of records or None")
    # Same caller-contract enforcement, extended to the Stage 3 channel: a
    # lone claim OBJECT must fail loud rather than be silently iterated as
    # dict keys by `_resolve_transfer_backing`.
    if transfer_view is not None and not isinstance(transfer_view, list):
        raise TypeError("transfer_view must be a list of claims or None")
    if compromise_view is not None and not isinstance(compromise_view, list):
        raise TypeError("compromise_view must be a list of claims or None")
    # Same caller-contract enforcement for Stage 4's channel: a lone grant
    # DOCUMENT passed where the evidence object belongs would otherwise be
    # read member by member and resolve to `not_checked`, silently reporting
    # "no grant evidence" to a caller who supplied some. Hostile CONTENT
    # inside a well-shaped view never raises — only the wrong container does.
    if grant_view is not None and not isinstance(grant_view, dict):
        raise TypeError("grant_view must be an evidence object or None")
    if authority_view is not None and not isinstance(authority_view, dict):
        raise TypeError("authority_view must be an evidence object or None")

    errors: list[str] = []
    warnings: list[str] = []
    # Conservative default: never claim "verified" trust until we've resolved
    # a manifest whose provenance is actually "tls".
    trust = _TRUST_TOFU
    # Stage 2 defaults — the ZERO-behavior-change values (updated below, once,
    # right after trust is resolved; see the module docstring on
    # `_evaluate_transparency_claim` for why this runs before any pass/fail
    # branching).
    transparency_state = _TRANSPARENCY_NOT_CHECKED
    corroboration_state = _CORROBORATION_NONE
    manifest_freshness_state = _MANIFEST_FRESHNESS_NOT_CHECKED
    transparency_claim_type: str | None = None
    materialized_compromise_view = _materialize_compromise_view(compromise_view)
    # v0.2 §19.2's 64-claim acceptance floor, given the fail-closed effect §6.3
    # requires the owning section to define. Discarding an over-ceiling view in
    # silence is the compromise rail's version of the revocation-view padding
    # attack `_revocation_state` already refuses below: an attacker who can feed
    # this channel — one §19.2 itself blesses for untrusted transport — appends
    # junk claims until a genuine declaration falls off the end, and the receipt
    # that declaration would have killed verifies green with no warning at all.
    # We cannot rule out a declaration, so we cannot certify the signing key.
    compromise_view_supplied = 0
    compromise_view_oversized = False
    if compromise_view is not None:
        try:
            compromise_view_supplied = list.__len__(compromise_view)
        except Exception:
            compromise_view_supplied = _MAX_COMPROMISE_CLAIMS + 1
        compromise_view_oversized = compromise_view_supplied > _MAX_COMPROMISE_CLAIMS

    def _invalid(message: str, *, schema: str = _SCHEMA_NOT_CHECKED) -> VerificationResult:
        errors.append(message)
        return VerificationResult(
            signature=_SIG_INVALID,
            schema=schema,
            revocation=_REVOCATION_UNKNOWN,
            binding=_BINDING_NOT_CHECKED,
            trust=trust,
            transparency=transparency_state,
            corroboration=corroboration_state,
            manifest_freshness=manifest_freshness_state,
            warnings=tuple(warnings),
            errors=tuple(errors),
        )

    def _compromised_key_disposition(
        kid: str,
        entry: dict[str, Any],
        trusted_manifest: dict[str, Any],
        chain: list[dict[str, Any]] | None,
        authenticated_claims: tuple[_CompromiseClaim, ...],
    ) -> VerificationResult | None:
        if log_keys is None or anchor_policy is None:
            return _invalid(f"key {kid} is compromised")
        if transparency_claim_type != _CLAIM_TYPE_RECEIPT or not transparency_state.startswith(
            _ANCHORED_BEFORE_PREFIX
        ):
            _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT)
            return _invalid(f"key {kid} is compromised")
        receipt_anchor = _parse_iso(transparency_state[len(_ANCHORED_BEFORE_PREFIX) :])
        if receipt_anchor is None:
            _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT)
            return _invalid(f"key {kid} is compromised")

        cutoff = _resolve_compromise_cutoff(
            authenticated_claims,
            trusted_manifest,
            chain,
            issuer_id if isinstance(issuer_id, str) else "",
            log_keys,
            anchor_policy,
            warnings,
        )
        if cutoff is None:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_UNANCHORED)
            return None
        try:
            if receipt_anchor < cutoff:
                _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_APPLIED)
                return None
        except TypeError:
            pass
        _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_RECEIPT_AFTER_CUTOFF)
        return _invalid(f"key {kid} is compromised")

    # --- G1 normative ceiling (attest-versioning.md §5 amendment; v0.1 §11/
    # §15, v0.2 §6/§16): the raw envelope MUST NOT exceed MAX_ENVELOPE_BYTES.
    # Checked on the undecoded bytes, before ANY parsing work — the cheapest
    # possible check on input a hostile sender fully controls the size of.
    # Reported as `schema: "invalid"` (not the "not_checked" default every
    # other precondition failure below uses): this ceiling is conformance-
    # surface, not a parse-shape failure.
    size_violations = validate.validate_envelope_size(envelope_bytes)
    if size_violations:
        return _invalid(size_violations[0], schema=_SCHEMA_INVALID)

    # --- Step 0: preconditions — parse once, strictly. All later steps and
    # all downstream consumers operate on this single parsed object, never
    # on the raw bytes (kills sign-vs-parse splits).
    #
    # G1 normative ceiling (attest-versioning.md §5 amendment; v0.1 §11.3):
    # the parsed envelope tree's nesting depth MUST NOT exceed
    # `validate.MAX_JSON_DEPTH` (== `canon.MAX_DEPTH`, 256). Enforced entirely
    # by `canon.loads_strict` itself during parsing (`CanonError`, "maximum
    # nesting depth exceeded") — there is deliberately no separate walk of
    # the parsed tree here (2026-07-22 fix wave): the parser's own structural
    # safety cap already IS this ceiling, so a second, redundant check could
    # never fire (see `validate.py`'s `MAX_JSON_DEPTH` docstring). A receipt
    # that trips it never produces a parsed object at all, so it is reported
    # the same way every other malformed-envelope failure is, `schema:
    # "not_checked"` — unlike the byte-size/manifest-array ceilings below,
    # which run AFTER a successful parse and are conformance-surface checks.
    try:
        parsed = canon.loads_strict(envelope_bytes)
    except canon.CanonError as exc:
        return _invalid(str(exc))

    if not isinstance(parsed, dict):
        return _invalid("envelope is not a JSON object")
    envelope: dict[str, Any] = parsed

    payload_obj = envelope.get("payload")
    if not isinstance(payload_obj, dict):
        return _invalid("envelope missing object member 'payload'")
    payload: dict[str, Any] = payload_obj

    signatures_obj = envelope.get("signatures")
    if not isinstance(signatures_obj, list):
        return _invalid("envelope missing array member 'signatures'")

    # Resolve trust as soon as we can identify the claimed issuer, even if a
    # later step rejects the receipt — a failed verification still reports
    # the trust level of the manifest that was consulted (or the safe
    # default if none could be identified/resolved). A discontinuous
    # manifest chain (design §5) overrides provenance-based trust entirely:
    # verifiers MUST NOT auto-accept a rotation they can't chain to a root.
    issuer_block = payload.get("issuer")
    issuer_id = issuer_block.get("id") if isinstance(issuer_block, dict) else None
    issuer_manifest: dict[str, Any] | None = None
    if isinstance(issuer_id, str):
        provenance = trust_store.provenance.get(issuer_id)
        trust = _TRUST_VERIFIED if provenance == _PROVENANCE_TLS else _TRUST_TOFU
        issuer_manifest = trust_store.manifests.get(issuer_id)

        # G1 ceiling + G6 detection preflight — ABOVE the chain handling, for
        # structural parity with verify.ts (2026-07-22 fix wave 2 round 2,
        # finding I1 residual: the TS chain tail compare canonicalizes the
        # manifest, so its preflight had to precede the chain block; Python's
        # chain compare is plain equality, but the two verifiers keep the
        # same order so trust in an early-rejection result matches). See the
        # block comment below.
        if isinstance(issuer_manifest, dict):
            issuer_manifest_keys = issuer_manifest.get("keys")
            if (
                isinstance(issuer_manifest_keys, list)
                and len(issuer_manifest_keys) > manifests.MAX_MANIFEST_KEYS
            ):
                return _invalid(
                    f"issuer manifest exceeds {manifests.MAX_MANIFEST_KEYS} keys",
                    schema=_SCHEMA_INVALID,
                )

            # V-L.3 (v0.1 §7.1, 2026-08-26 amendment) — an ambiguous trusted
            # manifest is refused whole, before any key is resolved. Without
            # this, a duplicate on a kid the signature does NOT use left the
            # receipt certifiable: step 3 resolves the signing key with
            # `find_key` directly and never passes through
            # `verify_key_manifest`.
            dup_kids = manifests.duplicate_kids(issuer_manifest_keys)
            if dup_kids:
                return _invalid(
                    f"issuer manifest lists duplicate kid(s): {dup_kids}",
                    schema=_SCHEMA_INVALID,
                )

            if payload.get("attest_version") == "0.2" and manifests.has_active_ed_only_sibling(
                issuer_manifest
            ):
                warnings.append(_WARN_MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING)

            # V-J.7 — the trusted manifest must authenticate ITSELF before any
            # key is read out of it. The side-document paths have always asked
            # (`transfer`/`revocation` hoist the same call); the receipt path
            # never did, so a manifest edited after it was trusted certified
            # receipts signed by the edit: a swapped `pub` forges a receipt
            # without the issuer's private key, and a `compromised` status
            # flipped back to `active` resurrects signatures §7.3 declares
            # dead. Hoisted here, at the ONE place the manifest is resolved,
            # so both receipt paths (v0.2 hybrid and v0.1) inherit it.
            # Deliberately last in this preflight: the keys ceiling above
            # bounds the work this check does, and running it after the
            # existing refusals leaves their verdicts and messages unchanged.
            if not manifests.manifest_signature_is_authentic(issuer_manifest):
                return _invalid(
                    f"issuer manifest for {issuer_id!r} is not self-consistent: "
                    "its own signature does not verify"
                )

        chain = trust_store.chains.get(issuer_id)
        # v0.1 §7.1 (2026-08-26 amendment): an ambiguous key manifest fails its
        # self-consistency check WHEREVER it is consumed. A held chain member is
        # consumed — by rotation continuity (§7.3) and by v0.2 §19.3's floor and
        # cutoff authentication — so it is refused here on the same terms as the
        # trusted manifest above, before any status or signer is read out of it.
        if chain:
            for member in chain:
                if not isinstance(member, dict):
                    continue
                member_dups = manifests.duplicate_kids(member.get("keys"))
                if member_dups:
                    return _invalid(
                        f"issuer manifest chain lists duplicate kid(s): {member_dups}",
                        schema=_SCHEMA_INVALID,
                    )
        if chain and (not _chain_continuous(chain) or chain[-1] != issuer_manifest):
            # A chain that does not actually end at the manifest being used proves
            # nothing about it — treat it as a discontinuous rotation (2026-07-13
            # review, finding 8).
            trust = _TRUST_UNVERIFIED_ROTATION

    # --- G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
    # amendment): resolve currency state per (issuer, series), authenticate
    # the pinned manifest and every chain member before touching any currency
    # metadata, then warn legacy manifests or evaluate continuity.
    work_block = payload.get("work")
    artifact_series = work_block.get("artifact_series") if isinstance(work_block, dict) else None
    if isinstance(issuer_id, str) and isinstance(artifact_series, str):
        issuer_artifact_manifests = trust_store.artifact_manifests.get(issuer_id, {})
        candidate_artifact_manifest = issuer_artifact_manifests.get(artifact_series)
        if isinstance(candidate_artifact_manifest, dict):
            am_chain = trust_store.artifact_manifest_chains.get(issuer_id, {}).get(artifact_series)
            members = [candidate_artifact_manifest]
            if am_chain:
                members.extend(am_chain)
            authenticated = (
                isinstance(issuer_manifest, dict)
                and all(
                    manifests.verify_artifact_manifest(member, issuer_manifest)
                    for member in members
                    if isinstance(member, dict)
                )
                and not any(not isinstance(member, dict) for member in members)
            )
            if candidate_artifact_manifest.get("issuer") != issuer_id:
                warnings.append(_WARN_ARTIFACT_MANIFEST_ISSUER_MISMATCH)
            elif not authenticated:
                warnings.append(_WARN_ARTIFACT_MANIFEST_UNAUTHENTICATED)
            else:
                if any("manifest_version" not in member for member in members):
                    # Any legacy member makes currency non-evaluable: warn and
                    # SKIP both continuity and the tail compare — a legacy
                    # manifest must never trigger the currency downgrade
                    # (v0.1 §7.3, warn-only; round-2 review residual).
                    warnings.append(_WARN_ARTIFACT_MANIFEST_UNVERSIONED)
                elif am_chain and (
                    not _artifact_chain_continuous(am_chain)
                    or am_chain[-1] != candidate_artifact_manifest
                ):
                    trust = _TRUST_UNVERIFIED_ROTATION

    # --- G1 normative ceiling, hoisted (attest-versioning.md §5 amendment;
    # v0.1 §11.3): the issuer manifest's `keys[]` array MUST NOT exceed
    # manifests.MAX_MANIFEST_KEYS — checked the moment the manifest is
    # resolved from the trust store, BEFORE any canonicalization/hash/
    # signature/transparency use of it. This MUST run before the transparency
    # block below: `_evaluate_transparency_claim` canonicalizes and SHA-256s
    # `issuer_manifest` whole (via `_resolve_transparency_claim`) to check a
    # key-manifest claim, which is exactly the unbounded work a structural
    # ceiling exists to prevent on a hostile array (2026-07-22 fix wave 2,
    # review finding I1 — this check used to live only after Step 1/2 below,
    # letting transparency/signature work run on an oversized manifest first).
    #
    # G6 mixed-keyset detection is hoisted alongside it (review finding I2):
    # the warning must fire for every v0.2 resolution of a mixed manifest,
    # independent of whether the receipt's signatures go on to verify (v0.2
    # §13/§2.3 amendment) — it used to live only after both signature legs
    # verified, so a tampered/failed receipt never carried it. Detection only
    # depends on the manifest's own keyset and the payload's claimed
    # `attest_version`, neither of which requires any of the crypto/schema
    # work Step 1-4 below still gate their OWN errors on.
    #
    # Round 2 (finding I1 residual): the check itself now lives INSIDE the
    # trust-resolution block above, before the chain handling — mirroring
    # verify.ts, whose chain tail compare canonicalizes the manifest.

    # --- Transparency/corroboration (Stage 2, informational only): resolved
    # here, before any pass/fail branching below, so a receipt that later
    # turns out invalid (e.g. a compromised key) still reports whatever
    # standing the evidence actually earns. Corroboration must never be able
    # to rescue an otherwise-rejected receipt, and demonstrating that
    # requires computing it regardless of the eventual verdict (design fix 6
    # / vector 28i's property) — see `_evaluate_transparency_claim`.
    (
        transparency_state,
        corroboration_state,
        manifest_freshness_state,
        transparency_claim_type,
    ) = _evaluate_transparency_claim(
        envelope,
        issuer_id if isinstance(issuer_id, str) else None,
        issuer_manifest,
        _rotation_chain_verified(
            trust_store.chains.get(issuer_id) if isinstance(issuer_id, str) else None,
            issuer_manifest,
        ),
        transparency,
        log_keys,
        anchor_policy,
        warnings,
        witness_policy,
    )

    # --- Step 1: envelope well-formed; attest_version supported; signatures
    # length == 1 (v0.1) or exactly the hybrid pair (v0.2); alg checked against
    # the literal expected string(s) (read only to reject, never to select).
    attest_version = payload.get("attest_version")
    if not isinstance(attest_version, str) or attest_version not in _SUPPORTED_ATTEST_VERSIONS:
        return _invalid(f"unsupported attest_version: {attest_version!r}")

    if attest_version == "0.2":
        # --- v0.2 hybrid path: AND semantics — both the Ed25519 leg AND the
        # ML-DSA-65 leg must verify, or the receipt is invalid. Every failure
        # below fails closed via `_invalid`, never raising.
        if len(signatures_obj) != 2:
            return _invalid("hybrid envelope requires exactly two signatures")

        sig0, sig1 = signatures_obj
        if not isinstance(sig0, dict) or not isinstance(sig1, dict):
            return _invalid("malformed signature block")

        if sig0.get("alg") != _ALG or sig1.get("alg") != pq.ML_DSA_65_ALG:
            return _invalid("hybrid envelope requires algs Ed25519 and ML-DSA-65 in order")

        kid0 = sig0.get("kid")
        kid1 = sig1.get("kid")
        if kid0 != kid1:
            return _invalid("hybrid envelope signatures must share a single kid")
        if not isinstance(kid0, str):
            return _invalid("malformed signature block: 'kid' must be a string")
        kid = kid0

        ed_sig_b64 = sig0.get("sig")
        mldsa_sig_b64 = sig1.get("sig")
        if not isinstance(ed_sig_b64, str) or not isinstance(mldsa_sig_b64, str):
            return _invalid("malformed signature block: 'sig' must be a string")

        # --- Step 2 (shared with v0.1): issuer binding — resolve the key
        # ONLY from the manifest of payload.issuer.id; the shared kid's
        # DNS-domain prefix and the manifest's own `issuer` field must both
        # equal it, or reject (issuer_mismatch).
        if not isinstance(issuer_id, str):
            return _invalid("malformed payload: missing issuer.id")

        # The SAME object the manifest gate authenticated above. Re-resolving
        # would authenticate one read and verify against another. The
        # isinstance also closes a crash: a trust store mapping an issuer to
        # a non-dict used to raise AttributeError out of the library, while
        # the TypeScript verifier failed closed on the same input.
        manifest = issuer_manifest
        if not isinstance(manifest, dict):
            return _invalid(f"no trusted manifest for issuer {issuer_id!r}")

        # G1's manifest-keys ceiling and G6's mixed-keyset detection are both
        # handled above, hoisted immediately after `issuer_manifest` (== this
        # same `manifest`) is resolved from the trust store — see the comment
        # there (2026-07-22 fix wave 2, findings I1/I2).

        if kid.split("/")[0] != issuer_id or manifest.get("issuer") != issuer_id:
            return _invalid("issuer_mismatch: kid domain does not match payload issuer.id")

        # --- Step 3 (shared with v0.1): key checks — present, not
        # compromised (fail-closed regardless of issued_at), issued_at within
        # the key's validity window.
        entry = manifests.find_key(manifest, kid)
        if entry is None:
            return _invalid(f"no key {kid!r} in issuer manifest")

        chain = trust_store.chains.get(issuer_id)
        authenticated_claims = _authenticated_compromise_claims(
            materialized_compromise_view,
            manifest,
            entry,
            chain,
            issuer_id,
            kid,
            warnings,
        )
        status = _resolve_key_status(entry, manifest, chain, authenticated_claims, kid)
        if compromise_view_oversized and status != _STATUS_COMPROMISED:
            return _invalid(
                f"compromise view exceeds {_MAX_COMPROMISE_CLAIMS} claims "
                f"({compromise_view_supplied} supplied), cannot certify the signing key"
            )
        compromised_rescued = False
        if status == _STATUS_COMPROMISED:
            # Emitted at the point of RESOLUTION and before the §19 disposition,
            # so it reads identically in the kill branch and the rescue branch
            # and its position in the array is deterministic.
            if _marking_provenance_is_a_retraction(manifest, chain, authenticated_claims, kid):
                _append_warning_once(warnings, _WARN_COMPROMISE_MARKING_RETRACTED)
            disposition = _compromised_key_disposition(
                kid, entry, manifest, chain, authenticated_claims
            )
            if disposition is not None:
                return disposition
            compromised_rescued = True
        if not compromised_rescued and status not in (_STATUS_ACTIVE, _STATUS_RETIRED):
            return _invalid(f"key {kid} has unusable status {status!r}")

        issued_at = payload.get("issued_at")
        if not isinstance(issued_at, str) or not _within_validity(issued_at, entry):
            return _invalid(f"issued_at {issued_at!r} outside key validity window")

        if status == _STATUS_RETIRED:
            warnings.append(f"key {kid} is retired")

        # --- Hybrid-only: the resolved key entry must itself carry an
        # ML-DSA-65 public key, or there is nothing to verify the second leg
        # against.
        if "pub_ml_dsa_65" not in entry:
            return _invalid(f"key entry for kid {kid!r} has no ML-DSA-65 public key")

        try:
            ed_pub = keys.b64u_decode(entry["pub"])
            mldsa_pub = keys.b64u_decode(entry["pub_ml_dsa_65"])
            ed_sig = keys.b64u_decode(ed_sig_b64)
            mldsa_sig = keys.b64u_decode(mldsa_sig_b64)
        except (KeyError, TypeError, ValueError) as exc:
            return _invalid(f"malformed key material: {exc}")

        try:
            canonical = canon.canonical_bytes(payload)
            ed_ok = keys.verify_strict(canonical, ed_sig, ed_pub)
        except ValueError as exc:
            return _invalid(f"malformed signature material: {exc}")
        if not ed_ok:
            return _invalid("signature verification failed")

        if not pq.verify_strict(canonical, mldsa_sig, mldsa_pub):
            return _invalid("ML-DSA-65 signature verification failed")
    else:
        if len(signatures_obj) != 1:
            return _invalid(f"signatures must contain exactly one entry, got {len(signatures_obj)}")

        sig_block = signatures_obj[0]
        if not isinstance(sig_block, dict):
            return _invalid("malformed signature block")

        raw_kid = sig_block.get("kid")
        alg = sig_block.get("alg")
        sig_b64 = sig_block.get("sig")
        if not isinstance(raw_kid, str) or not isinstance(sig_b64, str):
            return _invalid("malformed signature block: 'kid'/'sig' must be strings")
        kid = raw_kid

        if alg != _ALG:
            return _invalid(f"unsupported signature algorithm: {alg!r}")

        # --- Step 2: issuer binding — resolve the key ONLY from the manifest
        # of payload.issuer.id; kid's DNS-domain prefix and the manifest's
        # own `issuer` field must both equal it, or reject (issuer_mismatch).
        # This kills cross-issuer impersonation: a valid manifest for
        # evil.example.com can never validate a receipt claiming issuer.id
        # "store.example.com".
        if not isinstance(issuer_id, str):
            return _invalid("malformed payload: missing issuer.id")

        # The SAME object the manifest gate authenticated above. Re-resolving
        # would authenticate one read and verify against another. The
        # isinstance also closes a crash: a trust store mapping an issuer to
        # a non-dict used to raise AttributeError out of the library, while
        # the TypeScript verifier failed closed on the same input.
        manifest = issuer_manifest
        if not isinstance(manifest, dict):
            return _invalid(f"no trusted manifest for issuer {issuer_id!r}")

        # G1's manifest-keys ceiling is handled above, hoisted immediately
        # after `issuer_manifest` (== this same `manifest`) is resolved from
        # the trust store — see the comment there (2026-07-22 fix wave 2,
        # finding I1).

        if kid.split("/")[0] != issuer_id or manifest.get("issuer") != issuer_id:
            return _invalid("issuer_mismatch: kid domain does not match payload issuer.id")

        # --- Step 3: key checks — present, not compromised (fail-closed
        # regardless of issued_at), issued_at within the key's validity window.
        entry = manifests.find_key(manifest, kid)
        if entry is None:
            return _invalid(f"no key {kid!r} in issuer manifest")

        chain = trust_store.chains.get(issuer_id)
        authenticated_claims = _authenticated_compromise_claims(
            materialized_compromise_view,
            manifest,
            entry,
            chain,
            issuer_id,
            kid,
            warnings,
        )
        status = _resolve_key_status(entry, manifest, chain, authenticated_claims, kid)
        if compromise_view_oversized and status != _STATUS_COMPROMISED:
            return _invalid(
                f"compromise view exceeds {_MAX_COMPROMISE_CLAIMS} claims "
                f"({compromise_view_supplied} supplied), cannot certify the signing key"
            )
        compromised_rescued = False
        if status == _STATUS_COMPROMISED:
            # Emitted at the point of RESOLUTION and before the §19 disposition,
            # so it reads identically in the kill branch and the rescue branch
            # and its position in the array is deterministic.
            if _marking_provenance_is_a_retraction(manifest, chain, authenticated_claims, kid):
                _append_warning_once(warnings, _WARN_COMPROMISE_MARKING_RETRACTED)
            disposition = _compromised_key_disposition(
                kid, entry, manifest, chain, authenticated_claims
            )
            if disposition is not None:
                return disposition
            compromised_rescued = True
        if not compromised_rescued and status not in (_STATUS_ACTIVE, _STATUS_RETIRED):
            # Fail closed on missing/unknown status instead of validating
            # like an active key (2026-07-13 review, finding 4).
            return _invalid(f"key {kid} has unusable status {status!r}")

        issued_at = payload.get("issued_at")
        if not isinstance(issued_at, str) or not _within_validity(issued_at, entry):
            return _invalid(f"issued_at {issued_at!r} outside key validity window")

        if status == _STATUS_RETIRED:
            warnings.append(f"key {kid} is retired")

        # --- Step 4: Ed25519.verify(JCS(payload), sig, pub) under the pinned
        # ruleset. canon.canonical_bytes(payload) is the only signature input.
        try:
            pub = keys.b64u_decode(entry["pub"])
            sig = keys.b64u_decode(sig_b64)
        except (KeyError, TypeError, ValueError) as exc:
            return _invalid(f"malformed key material: {exc}")

        try:
            signature_ok = keys.verify_strict(canon.canonical_bytes(payload), sig, pub)
        except ValueError as exc:
            return _invalid(f"malformed signature material: {exc}")

        if not signature_ok:
            return _invalid("signature verification failed")

    # --- Step 5: schema validation of the parsed payload from step 0.
    violations = validate.validate_payload(payload)
    schema_result = _SCHEMA_VALID if not violations else _SCHEMA_INVALID
    errors.extend(violations)

    warnings.extend(_content_warnings(payload))

    # --- Steps 6-7: revocation-by-class and buyer binding. Only evaluated
    # once signature (guaranteed above) AND schema are both valid — see
    # module docstring.
    if schema_result == _SCHEMA_VALID:
        revocation_result = _classify_revocation(
            payload,
            revocation_view,
            manifest,
            warnings,
            errors,
            max_records=max_revocation_records,
            log_keys=log_keys,
            anchor_policy=anchor_policy,
            revocation_evidence=revocation_evidence,
            transfer_view=transfer_view,
        )
        binding_result = (
            _classify_binding(payload, disclosure)
            if disclosure is not None
            else _BINDING_NOT_CHECKED
        )
        # Stage 4 (§18.4). Gated on a valid schema for the same reason
        # revocation and binding are: §18.6's holder-binding conditional makes
        # a pledge-bearing v0.2 receipt without `buyer.pubkey`,
        # `work.publisher_id` or the `sunset-grant` label a SCHEMA ERROR, and
        # evaluating a grant against a payload that failed that conditional
        # would be reasoning about a receipt the verifier has already rejected.
        grant_verdict = evaluate_grant(
            payload, trust_store, grant_view, anchor_policy=anchor_policy
        )
        authority_verdict = evaluate_publisher_authority(payload, trust_store, authority_view)
    else:
        revocation_result = _REVOCATION_UNKNOWN
        binding_result = _BINDING_NOT_CHECKED
        grant_verdict = GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED)
        authority_verdict = AuthorityVerdict(_AUTHORITY_NOT_CHECKED, _AUTHORITY_NOT_CHECKED)

    warnings.extend(authority_verdict.warnings)

    work_block = payload.get("work")
    publisher_id = work_block.get("publisher_id") if isinstance(work_block, dict) else None
    if (
        isinstance(publisher_id, str)
        and isinstance(issuer_id, str)
        and publisher_id != issuer_id
        and authority_verdict.publisher_authority in (_AUTHORITY_NOT_CHECKED, _AUTHORITY_UNATTESTED)
    ):
        warnings.append(_WARN_PUBLISHER_CLAIM_UNATTESTED)
    warnings.extend(grant_verdict.warnings)

    return VerificationResult(
        signature=_SIG_VALID,
        schema=schema_result,
        revocation=revocation_result,
        binding=binding_result,
        trust=trust,
        transparency=transparency_state,
        corroboration=corroboration_state,
        manifest_freshness=manifest_freshness_state,
        warnings=tuple(warnings),
        errors=tuple(errors),
        grant=grant_verdict.grant,
        grant_trust=grant_verdict.grant_trust,
        publisher_authority=authority_verdict.publisher_authority,
        publisher_authority_trust=authority_verdict.publisher_authority_trust,
    )
