"""Transparency/corroboration evaluator — Stage 2 (design doc "transparency/
corroboration layer").

Scope: this module is the glue between Tasks 1-3. Given one untrusted
evidence bundle for a single claim (an entry logged into a transparency
log, optionally anchored into a Bitcoin block header), `evaluate_transparency`
walks the decision order below and returns a `TransparencyResult` — never
raising because of anything in `evidence`, which arrives from wherever the
bundle was fetched (log server, anchor service, or an adversary).

Evidence input schema (one per claim, all JCS-friendly dicts)::

    {
        "entry": <entry dict>,
        "leaf_index": int,
        "tree_size": int,
        "inclusion_proof": [<64-hex-char str>, ...],
        "checkpoint": <note text>,
        "prior_checkpoint": <note text>,       # optional
        "consistency_proof": [<64-hex-char str>, ...],  # optional
        "anchors": <anchor evidence dict>,     # optional
    }

Decision order (fail-safe: any failure degrades to `(TRANSPARENCY_NOT_CHECKED,
CORROBORATION_NONE)` plus a warning naming the condition, EXCEPT equivocation,
which is its own hard verdict):

1. `tlog.encode_entry(evidence["entry"])`, then compare the entry dict
   deep-equal against the caller-supplied `expected_entry` (what the entry
   MUST say, computed by the caller from the artifact being corroborated).
2. Find the pinned `LogKey` whose `origin == expected_origin` and whose
   `tlog.verify_checkpoint` succeeds (log keys may rotate — see below).
3. `tlog.verify_inclusion` of the entry's leaf hash, and
   `checkpoint.tree_size` must equal the evidence's declared `tree_size`.
4. If `prior_checkpoint` is present: verify it under the same pinned key
   set, then `tlog.verify_consistency` against the current checkpoint. A
   validly-signed prior whose consistency check FAILS is proof the log
   equivocated — `TRANSPARENCY_EQUIVOCATION_DETECTED` (hard verdict). A
   prior that does NOT verify is not proof of anything (fail-safe, not
   equivocation). A verifying prior with no consistency proof to check
   cannot be evaluated (fail-safe, not silently ignored).
5. Base standing: `(TRANSPARENCY_LOGGED, CORROBORATION_LOGGED)`.
6. If `anchors` is present: `anchor.verify_anchor` against the same
   checkpoint and the trusted `policy`. A PQ-surviving proof upgrades
   `transparency` to `anchored_before:<ISO-8601 UTC timestamp>`; if that
   proof used the legacy note-bytes-only commitment
   (`AnchorVerdict.note_only`, G4, attest-v0.2.md §11.1) the warning
   `anchor_note_only` is added — the anchor still stands (eternal
   verifiability, attest-versioning.md §3), just classified as the weaker
   pre-G4 profile.
7. Horizon: if `policy.crqc_horizon` is set and the anchor verdict (or its
   absence) does not `anchor.passes_horizon`, the whole result caps back to
   `(TRANSPARENCY_NOT_CHECKED, CORROBORATION_NONE)` — a checkpoint signature
   alone does not survive a declared CRQC horizon.

`log_keys`, `expected_origin`, `policy`, and `expected_entry` are the
TRUSTED, verifier-config side of the call (mirrors `anchor.verify_anchor`'s
`checkpoint`/`policy` split): a malformed one raises `TransparencyError`
rather than degrading, since that signals a caller bug, not adversarial
input.

Warning strings are fixed, short, snake_case tokens (never carrying
interpolated untrusted values or language-specific type names) precisely
because they are a cross-language protocol surface: the TypeScript parity
port copies them byte-for-byte. Contrast `TransparencyError` messages, which
are free-form developer diagnostics with no parity requirement.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from typing import Any, cast

from attest import anchor, tlog, witness

# RFC 6962 inclusion/consistency proofs for a tree of at most 2**64 leaves
# have at most 64 entries (one per tree level) — caps a hostile proof list
# before any per-item work is done on it.
_MAX_PROOF_LEN = 64
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

TRANSPARENCY_NOT_CHECKED = "not_checked"
TRANSPARENCY_LOGGED = "logged"
TRANSPARENCY_EQUIVOCATION_DETECTED = "equivocation_detected"
# "anchored_before:<T>" is rendered dynamically by `_iso8601`, not a fixed
# literal — it carries the anchor's own timestamp.

CORROBORATION_NONE = "none"
CORROBORATION_LOGGED = "logged"
# Defined for the Stage 3 contract but unreachable in Stage 2: no witness
# input exists yet on the evidence schema above. Tests assert it is never
# returned by `evaluate_transparency`.
CORROBORATION_WITNESSED = "witnessed"

_WARN_EVIDENCE_INVALID = "evidence_invalid"
_WARN_ENTRY_INVALID = "entry_invalid"
_WARN_ENTRY_MISMATCH = "transparency_entry_mismatch"
_WARN_CHECKPOINT_INVALID = "checkpoint_invalid"
_WARN_CHECKPOINT_VERIFICATION_FAILED = "checkpoint_verification_failed"
_WARN_LEAF_INDEX_INVALID = "leaf_index_invalid"
_WARN_TREE_SIZE_INVALID = "tree_size_invalid"
_WARN_TREE_SIZE_MISMATCH = "tree_size_mismatch"
_WARN_INCLUSION_PROOF_INVALID = "inclusion_proof_invalid"
_WARN_INCLUSION_PROOF_TOO_LONG = "inclusion_proof_too_long"
_WARN_PRIOR_CHECKPOINT_INVALID = "prior_checkpoint_invalid"
_WARN_CONSISTENCY_PROOF_MISSING = "consistency_proof_missing"
_WARN_CONSISTENCY_PROOF_INVALID = "consistency_proof_invalid"
_WARN_CONSISTENCY_PROOF_TOO_LONG = "consistency_proof_too_long"
_WARN_EQUIVOCATION_DETECTED = "log_equivocation_detected"
_WARN_ANCHORS_INVALID = "anchors_invalid"
_WARN_ANCHOR_TIME_INVALID = "anchor_time_invalid"
# G4 (attest-v0.2.md §11.1): an anchor that established standing via the
# legacy note-bytes-only commitment (`AnchorVerdict.note_only`) — still
# fully verifiable (eternal verifiability, attest-versioning.md §3), just
# classified as the weaker profile.
_WARN_ANCHOR_NOTE_ONLY = "anchor_note_only"
_WARN_POST_HORIZON_UNANCHORED = "post_horizon_unanchored"
_WARN_EVIDENCE_EVALUATION_FAILED = "evidence_evaluation_failed"


class TransparencyError(ValueError):
    """A TRUSTED `evaluate_transparency` argument (`log_keys`, `expected_origin`,
    `policy`, `expected_entry`) is malformed.

    Never raised for malformed `evidence` — that boundary reports through
    `TransparencyResult.warnings` instead, see `evaluate_transparency`.
    """


@dataclass(frozen=True)
class TransparencyResult:
    """The outcome of `evaluate_transparency` over one evidence bundle.

    `transparency` is one of `TRANSPARENCY_NOT_CHECKED`, `TRANSPARENCY_LOGGED`,
    `f"anchored_before:{iso8601}"`, or `TRANSPARENCY_EQUIVOCATION_DETECTED`.
    `corroboration` is one of `CORROBORATION_NONE`, `CORROBORATION_LOGGED`, or
    `CORROBORATION_WITNESSED` (the last unreachable in Stage 2).
    """

    transparency: str
    corroboration: str
    warnings: list[str]


def _not_checked(warning: str) -> TransparencyResult:
    return TransparencyResult(
        transparency=TRANSPARENCY_NOT_CHECKED, corroboration=CORROBORATION_NONE, warnings=[warning]
    )


def _iso8601(unix_time: int) -> str | None:
    """Render a unix-seconds timestamp as `YYYY-MM-DDTHH:MM:SSZ` (UTC).

    KAT: `1700000000 -> "2023-11-14T22:13:20Z"`.

    Returns `None` if the platform cannot render the supplied timestamp.
    Verified anchor times are bounded in `anchor._validate_policy`, but this
    remains a defensive containment for future anchor-verdict paths.
    """
    try:
        return datetime.datetime.fromtimestamp(unix_time, tz=datetime.UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (ValueError, OverflowError, OSError):
        return None


def _validate_log_keys(log_keys: object) -> list[tlog.LogKey]:
    """Deep-validate the trusted pinned-key list."""
    if not isinstance(log_keys, list):
        raise TransparencyError(f"log_keys must be a list of LogKey, got {type(log_keys).__name__}")
    try:
        return [tlog._validate_log_key(log_key) for log_key in log_keys]
    except tlog.TlogError as exc:
        raise TransparencyError(str(exc)) from exc


def _validate_witness_policy(witness_policy: object) -> witness.WitnessPolicy | None:
    """Deep-validate the trusted witness policy; `None` means "not configured".

    Same rail as `log_keys`: a malformed policy is a caller/configuration bug
    and raises, while omitting it entirely preserves the previous result
    exactly (§10.2, zero behavior change for existing callers).
    """
    if witness_policy is None:
        return None
    if isinstance(witness_policy, witness.WitnessPolicy):
        return witness_policy
    try:
        return witness.parse_policy(witness_policy)
    except witness.WitnessError as exc:
        raise TransparencyError(str(exc)) from exc


def _validate_expected_origin(expected_origin: object) -> str:
    try:
        return tlog._validate_origin(expected_origin, "expected_origin")
    except tlog.TlogError as exc:
        raise TransparencyError(str(exc)) from exc


def _validate_policy(policy: object) -> anchor.AnchorPolicy:
    try:
        return anchor._validate_policy(policy)
    except anchor.AnchorError as exc:
        raise TransparencyError(str(exc)) from exc


def _validate_expected_entry(expected_entry: object) -> dict[str, Any]:
    try:
        tlog.encode_entry(cast(dict[str, Any], expected_entry))
    except tlog.TlogError as exc:
        raise TransparencyError(str(exc)) from exc
    if not isinstance(expected_entry, dict):  # defensive: encode_entry has already rejected this.
        raise TransparencyError(
            f"expected_entry must be a dict, got {type(expected_entry).__name__}"
        )
    return expected_entry


def _decode_hex_items(items: list[object]) -> list[bytes] | None:
    """Decode an already-length-bounded proof list: each item must be
    exactly 64 lowercase hex chars (32 bytes once decoded).

    Charset/length are checked BEFORE `bytes.fromhex`, which itself accepts
    uppercase and would silently normalize an out-of-schema encoding (same
    discipline as `anchor.py`'s `_hex64`). Returns `None` on any item's
    shape violation rather than raising — `evaluate_transparency`'s caller
    maps that to a fixed warning. The list-vs-not-a-list and length-cap
    checks live at the call site so each has its own distinct, testable
    warning (a hostile oversized list must never even reach the per-item
    hex/`bytes.fromhex` work below).
    """
    decoded = []
    for item in items:
        if not isinstance(item, str) or not _HEX64_RE.fullmatch(item):
            return None
        decoded.append(bytes.fromhex(item))
    return decoded


def _find_verified_checkpoint(
    text: object, candidates: list[tlog.LogKey], expected_origin: str
) -> tlog.Checkpoint | None:
    """Try each pinned key sharing `expected_origin` in order, accepting the
    first whose `tlog.verify_checkpoint` succeeds (log keys may rotate).
    `None` on any shape violation or if no candidate verifies — never
    raises, `text` and its signatures are untrusted.
    """
    if not isinstance(text, str):
        return None
    for key in candidates:
        try:
            return tlog.verify_checkpoint(text, key, expected_origin)
        except tlog.TlogError:
            continue
    return None


def _evaluate_untrusted_evidence(
    evidence: object,
    *,
    log_keys: list[tlog.LogKey],
    expected_origin: str,
    policy: anchor.AnchorPolicy,
    expected_entry: dict[str, Any],
    witness_policy: witness.WitnessPolicy | None = None,
) -> TransparencyResult:
    if not isinstance(evidence, dict):
        return _not_checked(_WARN_EVIDENCE_INVALID)

    # --- Step 1: entry must encode under the closed schema and match what
    # the caller expects it to say. ---
    entry = evidence.get("entry")
    if not isinstance(entry, dict):
        return _not_checked(_WARN_ENTRY_INVALID)
    try:
        entry_bytes = tlog.encode_entry(entry)
    except tlog.TlogError:
        return _not_checked(_WARN_ENTRY_INVALID)
    if entry != expected_entry:
        return _not_checked(_WARN_ENTRY_MISMATCH)

    # --- Step 2: checkpoint must verify (hybrid AND) under a pinned key for
    # expected_origin; keys may rotate, so try every candidate in order. ---
    matching_keys = [key for key in log_keys if key.origin == expected_origin]
    checkpoint_text = evidence.get("checkpoint")
    if not isinstance(checkpoint_text, str):
        return _not_checked(_WARN_CHECKPOINT_INVALID)
    checkpoint = _find_verified_checkpoint(checkpoint_text, matching_keys, expected_origin)
    if checkpoint is None:
        return _not_checked(_WARN_CHECKPOINT_VERIFICATION_FAILED)

    # --- Step 3: inclusion proof, plus the evidence's declared tree_size
    # must agree with what the verified checkpoint actually attests to. ---
    leaf_index = evidence.get("leaf_index")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        return _not_checked(_WARN_LEAF_INDEX_INVALID)
    tree_size = evidence.get("tree_size")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        return _not_checked(_WARN_TREE_SIZE_INVALID)
    if checkpoint.tree_size != tree_size:
        return _not_checked(_WARN_TREE_SIZE_MISMATCH)
    raw_inclusion_proof = evidence.get("inclusion_proof")
    if not isinstance(raw_inclusion_proof, list):
        return _not_checked(_WARN_INCLUSION_PROOF_INVALID)
    if len(raw_inclusion_proof) > _MAX_PROOF_LEN:
        return _not_checked(_WARN_INCLUSION_PROOF_TOO_LONG)
    inclusion_proof = _decode_hex_items(raw_inclusion_proof)
    if inclusion_proof is None:
        return _not_checked(_WARN_INCLUSION_PROOF_INVALID)
    if not tlog.verify_inclusion(
        tlog.leaf_hash(entry_bytes), leaf_index, tree_size, inclusion_proof, checkpoint.root
    ):
        return _not_checked(_WARN_INCLUSION_PROOF_INVALID)

    # --- Step 4: an optional prior checkpoint claim. A validly-signed prior
    # whose consistency check fails is proof of equivocation (hard verdict);
    # anything else that prevents evaluating the claim is fail-safe. ---
    if "prior_checkpoint" in evidence:
        prior_checkpoint_text = evidence.get("prior_checkpoint")
        prior_checkpoint = _find_verified_checkpoint(
            prior_checkpoint_text, matching_keys, expected_origin
        )
        if prior_checkpoint is None:
            return _not_checked(_WARN_PRIOR_CHECKPOINT_INVALID)
        if "consistency_proof" not in evidence:
            return _not_checked(_WARN_CONSISTENCY_PROOF_MISSING)
        raw_consistency_proof = evidence.get("consistency_proof")
        if not isinstance(raw_consistency_proof, list):
            return _not_checked(_WARN_CONSISTENCY_PROOF_INVALID)
        if len(raw_consistency_proof) > _MAX_PROOF_LEN:
            return _not_checked(_WARN_CONSISTENCY_PROOF_TOO_LONG)
        consistency_proof = _decode_hex_items(raw_consistency_proof)
        if consistency_proof is None:
            return _not_checked(_WARN_CONSISTENCY_PROOF_INVALID)
        if not tlog.verify_consistency(
            prior_checkpoint.tree_size,
            prior_checkpoint.root,
            checkpoint.tree_size,
            checkpoint.root,
            consistency_proof,
        ):
            return TransparencyResult(
                transparency=TRANSPARENCY_EQUIVOCATION_DETECTED,
                corroboration=CORROBORATION_NONE,
                warnings=[_WARN_EQUIVOCATION_DETECTED],
            )
    elif "consistency_proof" in evidence:
        if not isinstance(evidence.get("consistency_proof"), list):
            return _not_checked(_WARN_CONSISTENCY_PROOF_INVALID)

    # --- Step 5: base standing. ---
    transparency_state = TRANSPARENCY_LOGGED
    corroboration_state = CORROBORATION_LOGGED
    warnings: list[str] = []

    # --- Step 6: an optional anchor claim upgrades transparency_state if a
    # PQ-surviving proof verifies. ---
    anchor_verdict: anchor.AnchorVerdict | None = None
    if "anchors" in evidence:
        anchors_evidence = evidence.get("anchors")
        if not isinstance(anchors_evidence, dict):
            return _not_checked(_WARN_ANCHORS_INVALID)
        anchor_verdict = anchor.verify_anchor(anchors_evidence, checkpoint, policy)
        warnings.extend(anchor_verdict.warnings)
        if anchor_verdict.pq_surviving and anchor_verdict.anchored_before is not None:
            if anchor_verdict.note_only:
                warnings.append(_WARN_ANCHOR_NOTE_ONLY)
            rendered_anchor_time = _iso8601(anchor_verdict.anchored_before)
            if rendered_anchor_time is None:
                warnings.append(_WARN_ANCHOR_TIME_INVALID)
                return TransparencyResult(
                    transparency=TRANSPARENCY_NOT_CHECKED,
                    corroboration=CORROBORATION_NONE,
                    warnings=warnings,
                )
            transparency_state = f"anchored_before:{rendered_anchor_time}"

    # --- Step 7: a declared CRQC horizon caps standing back down unless a
    # PQ-surviving anchor lands strictly before it. `anchor.passes_horizon`
    # is typed to require an `AnchorVerdict` (unlike its runtime behavior,
    # which tolerates malformed content); no anchors evidence at all means
    # no verdict was ever produced, so the `policy.crqc_horizon is None`
    # short-circuit is inlined here rather than passing `None` through.
    horizon_ok = policy.crqc_horizon is None or (
        anchor_verdict is not None and anchor.passes_horizon(anchor_verdict, policy)
    )
    if not horizon_ok:
        warnings.append(_WARN_POST_HORIZON_UNANCHORED)
        return TransparencyResult(
            transparency=TRANSPARENCY_NOT_CHECKED,
            corroboration=CORROBORATION_NONE,
            warnings=warnings,
        )

    # --- Step 8: a pinned witness cosignature upgrades corroboration from
    # `logged` to `witnessed` (§10.1, P1.1b). Only reachable from `logged`:
    # a cosignature never rescues a broken inclusion proof. Any failure is
    # SILENT by §11.4 — the only literal this layer may add is the
    # independence warning that accompanies a successful upgrade.
    if witness_policy is not None and corroboration_state == CORROBORATION_LOGGED:
        verdict = witness.evaluate_corroboration(
            checkpoint=checkpoint,
            signatures=tlog.note_signatures(checkpoint.signed_note_bytes.decode()),
            policy=witness_policy,
            epoch_id=evidence.get("witness_policy_epoch"),
        )
        if verdict.witnessed:
            corroboration_state = CORROBORATION_WITNESSED
            warnings.extend(verdict.warnings)

    return TransparencyResult(
        transparency=transparency_state, corroboration=corroboration_state, warnings=warnings
    )


def evaluate_transparency(
    evidence: dict[str, Any],
    *,
    log_keys: list[tlog.LogKey],
    expected_origin: str,
    policy: anchor.AnchorPolicy,
    expected_entry: dict[str, Any],
    witness_policy: object = None,
) -> TransparencyResult:
    """Evaluate one untrusted transparency/corroboration evidence bundle.

    Raises `TransparencyError` for a malformed trusted argument. Once those
    arguments validate, no behavior supplied by `evidence` may escape this
    boundary as an exception.
    """
    log_keys = _validate_log_keys(log_keys)
    expected_origin = _validate_expected_origin(expected_origin)
    policy = _validate_policy(policy)
    expected_entry = _validate_expected_entry(expected_entry)
    validated_witness_policy = _validate_witness_policy(witness_policy)

    try:
        return _evaluate_untrusted_evidence(
            evidence,
            log_keys=log_keys,
            expected_origin=expected_origin,
            policy=policy,
            expected_entry=expected_entry,
            witness_policy=validated_witness_policy,
        )
    # This is deliberate adversarial-boundary confinement, not lazy error
    # handling: hostile dict `get`/`__getitem__`/`__eq__` implementations can
    # raise outside the precise shape-error catches above. Never catch
    # BaseException, so interrupts and process-control exceptions still work.
    except Exception:
        return _not_checked(_WARN_EVIDENCE_EVALUATION_FAILED)
