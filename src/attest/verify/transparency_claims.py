"""Stage 2 transparency/corroboration: resolving a receipt or key-manifest
log claim against the verifier's own trusted artifacts and pinned log
configuration (design doc "transparency/corroboration layer")."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from attest import anchor, canon, tlog
from attest import transparency as transparency_module
from attest.verify.constants import (
    _CLAIM_TYPE_KEY_MANIFEST,
    _CLAIM_TYPE_RECEIPT,
    _CORROBORATION_NONE,
    _MANIFEST_FRESHNESS_NOT_CHECKED,
    _MAX_TRANSPARENCY_EVIDENCE_LEN,
    _TRANSPARENCY_NOT_CHECKED,
    _WARN_ROTATION_CHAIN_REQUIRED,
    _WARN_TRANSPARENCY_CLAIM_UNRESOLVABLE,
    _WARN_TRANSPARENCY_CONFIG_MISSING,
)
from attest.verify.evidence import _MAX_EVIDENCE_NODES, _own_data_copy


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
