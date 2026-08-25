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
from datetime import datetime, timedelta
from typing import Any

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

# Preflight bound on the untrusted revocation view (review improvement #17):
# a legitimate view for one verify() call is an issuer's records for one
# receipt — realistically single digits; 10k is far above any legitimate
# case and keeps hostile worst-case work bounded. Injectable per call via
# `verify(..., max_revocation_records=...)`. Mirrored by the TS verifier's
# MAX_REVOCATION_RECORDS.
_MAX_REVOCATION_RECORDS = 10_000

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

# This outer cap must COVER everything the downstream evaluators' own inner
# caps accept, or evaluator-valid evidence gets falsely rejected here.
# Worst-case legitimate bundle, derived from those inner caps: checkpoint +
# prior_checkpoint + the anchors bundle's own checkpoint copy at ~500KB each
# (tlog._MAX_NOTE_TEXT_LEN), plus anchors proofs at 64 proofs x 64 ops x
# ~2060 chars per max append/prepend op (anchor._MAX_PROOFS_PER_EVIDENCE,
# _MAX_OPS_PER_PROOF, _MAX_OP_HEX_LEN) ~ 8.5MB, plus inclusion/consistency
# proofs (~8KB) — ~10MB total. The cap still bounds hostile materialization
# before the JSON decoder performs a second full traversal.
_MAX_TRANSPARENCY_EVIDENCE_LEN = 10_000_000


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

    signature: str  # "valid" | "invalid"
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
        if eol not in _KNOWN_EOL_VALUES:
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
) -> tuple[str, str, str]:
    """Resolve `(transparency, corroboration, manifest_freshness)` from one
    evidence bundle (design doc "transparency/corroboration layer").

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
        return _TRANSPARENCY_NOT_CHECKED, _CORROBORATION_NONE, _MANIFEST_FRESHNESS_NOT_CHECKED

    if log_keys is None or anchor_policy is None:
        warnings.append(_WARN_TRANSPARENCY_CONFIG_MISSING)
        return _TRANSPARENCY_NOT_CHECKED, _CORROBORATION_NONE, _MANIFEST_FRESHNESS_NOT_CHECKED

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
        serialized_evidence = canon.dumps(transparency_evidence)
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
            return _TRANSPARENCY_NOT_CHECKED, _CORROBORATION_NONE, _MANIFEST_FRESHNESS_NOT_CHECKED

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

        return transparency_state, corroboration_state, manifest_freshness_state
    # This intentionally encloses every untrusted claim phase above, including
    # post-evaluation freshness/rotation logic. It confines hostile mapping
    # access and equality implementations; never catch BaseException so
    # interrupts and process-control exceptions still propagate.
    except Exception:
        warnings.append(_WARN_TRANSPARENCY_CLAIM_UNRESOLVABLE)
        return _TRANSPARENCY_NOT_CHECKED, _CORROBORATION_NONE, _MANIFEST_FRESHNESS_NOT_CHECKED


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
    """
    best_dt: datetime | None = None
    best_raw: str | None = None
    for record in view:
        if not isinstance(record, dict):
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
        serialized_evidence = canon.dumps(revocation_evidence)
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
    try:
        serialized = canon.dumps(transfer_view)
        if len(serialized) > _MAX_TRANSPARENCY_EVIDENCE_LEN:
            return None
        materialized = json.loads(serialized)
    # Adversarial-boundary confinement (never BaseException), mirroring
    # `_revocation_deadline_satisfied`: a hostile `transfer_view` list/dict's
    # `__eq__`/`__getitem__` must not escape as a bare exception.
    except Exception:
        return None
    if not isinstance(materialized, list):
        return None

    receipt_id = payload.get("receipt_id")
    manifest_ok = manifests.verify_key_manifest(issuer_manifest)

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
    authenticated records in the view (any receipt_id), not the raw view —
    so unsigned junk can neither revoke nor inflate T. With no authenticated
    records at all, T has no trustworthy value and the result is `unknown`.

    An oversized view (more than `max_records` entries) is not evaluated —
    never truncated (a subset could misreport), never raised. It fails CLOSED
    for revocable receipts: for `policy`/`refund_window` an error is recorded
    (so `ok` is false), because an untrusted view too large to evaluate cannot
    rule out a revocation and must not certify the receipt — otherwise an
    append-only feed-poisoning attacker could suppress a genuine revocation by
    padding past the cap. For `none` (irrevocable) a revocation can never
    affect `ok`, so it is a non-fatal warning. In both cases revocation is
    `"unknown"`.

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
    if not revocation_view:  # None or empty: no data, no freshness anchor either way
        return _REVOCATION_UNKNOWN

    license_block = payload.get("license")
    revocability = license_block.get("revocability") if isinstance(license_block, dict) else None

    if len(revocation_view) > max_records:
        supplied = len(revocation_view)
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
            # Irrevocable ("none") or unknown-class (rejected at schema): a
            # revocation can never affect ok, so an oversized view is non-fatal.
            warnings.append(
                f"revocation view exceeds {max_records} records "
                f"({supplied} supplied), not evaluated"
            )
        return _REVOCATION_UNKNOWN

    receipt_id = payload.get("receipt_id")

    # Authenticated records (any receipt_id) drive the freshness anchor; only
    # signature-verified records may set T (§5 hardening). The manifest's own
    # self-verify is hoisted out of the loop — one `verify_key_manifest` per
    # classification, not per record, so a hostile many-record feed cannot
    # multiply manifest-verification work (review improvement #17).
    manifest_ok = manifests.verify_key_manifest(issuer_manifest)
    authenticated_ids: set[int] = set()
    authenticated: list[dict[str, Any]] = []
    if manifest_ok:
        for record in revocation_view:
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
    valid: list[dict[str, Any]] = []
    transferred_matches: list[dict[str, Any]] = []
    for record in revocation_view:
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
    witness_policy: object = None,
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

            if payload.get("attest_version") == "0.2" and manifests.has_active_ed_only_sibling(
                issuer_manifest
            ):
                warnings.append(_WARN_MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING)

        chain = trust_store.chains.get(issuer_id)
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
    transparency_state, corroboration_state, manifest_freshness_state = (
        _evaluate_transparency_claim(
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

        manifest = trust_store.manifests.get(issuer_id)
        if manifest is None:
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

        status = entry.get("status")
        if status == _STATUS_COMPROMISED:
            return _invalid(f"key {kid} is compromised")
        if status not in (_STATUS_ACTIVE, _STATUS_RETIRED):
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

        manifest = trust_store.manifests.get(issuer_id)
        if manifest is None:
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

        status = entry.get("status")
        if status == _STATUS_COMPROMISED:
            return _invalid(f"key {kid} is compromised")
        if status not in (_STATUS_ACTIVE, _STATUS_RETIRED):
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
    else:
        revocation_result = _REVOCATION_UNKNOWN
        binding_result = _BINDING_NOT_CHECKED

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
    )
