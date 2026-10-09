"""Step 6, revocation-by-class (section 6 / section 3.1): the freshness
anchor, the refund window, the G5 deadline-effectiveness rule and the
classification itself."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from attest import anchor, canon, manifests, revocation, tlog
from attest import transparency as transparency_module
from attest.verify.constants import (
    _ANCHOR_STATUSES,
    _ANCHORED_BEFORE_PREFIX,
    _CLAIM_TYPE_REVOCATION_RECORD,
    _MAX_REVOCATION_RECORDS,
    _MAX_TRANSPARENCY_EVIDENCE_LEN,
    _RECORD_STATUS_REVOKED,
    _REVOCABILITY_NONE,
    _REVOCABILITY_POLICY,
    _REVOCABILITY_REFUND_WINDOW,
    _REVOCATION_INVALID_IGNORED,
    _REVOCATION_NOT_REVOKED_PREFIX,
    _REVOCATION_REVOKED,
    _REVOCATION_TRANSFERRED,
    _REVOCATION_UNKNOWN,
    _WARN_REVOCATION_UNLOGGED_DEADLINE,
    _WARN_TRANSFER_DOUBLE_ASSIGNMENT,
    _WARN_TRANSFER_NOT_YET_TRANSFERABLE,
    _WARN_TRANSFER_RECORD_UNLOGGED,
    _WARN_TRANSFERRED_REVOCATION_UNBACKED,
)
from attest.verify.evidence import (
    _MAX_EVIDENCE_NODES,
    _VIEW_ARRAY_ELEMENT_NESTING,
    _VIEW_MEMBER_ABSENT,
    _VIEW_MEMBER_COLLAPSED,
    _admit_evidence_value,
    _materialize_evidence_array,
    _own_data_copy,
    _own_view_member,
)
from attest.verify.helpers import _parse_iso
from attest.verify.transfer_backing import _resolve_transfer_backing
from attest.verify.transparency_claims import _resolve_log_origin, _validated_transparency_entry


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

    PRECONDITION: `issuer_manifest` is ALREADY MATERIALIZED, exactly as in
    `_resolve_transfer_backing` above and for the same reason — the per-record
    loop below uses `revocation._verify_record_signature`, the variant that
    does not re-apply the boundary.

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
    key-authorization gate applies to ALL revocability classes, and a BACKED
    `status: "transferred"` record rides this same view. Both are recorded
    as an error (`ok` becomes `false`); otherwise an append-only
    feed-poisoning attacker could suppress genuine evidence by padding past
    the cap. In both cases revocation is `"unknown"`.

    v0.2 Stage 3 (§17.3, design doc §4): once the `"revoked"`-status logic
    above has run to completion WITHOUT itself yielding `_REVOCATION_REVOKED`
    — byte-identical to pre-Stage-3 behavior; this ordering is what keeps
    every existing conformance leaf unchanged — an authenticated, matching
    `status == "transferred"` record is additionally considered, for ALL
    revocability classes, `none` included (the key-authorization-gate
    principle,
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
            # false since v0.2 §17.3 made the key-authorization gate apply to ALL
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
    manifest_ok = manifests._manifest_signature_is_authentic(issuer_manifest)
    authenticated_ids: set[int] = set()
    authenticated: list[dict[str, Any]] = []
    if manifest_ok:
        for record in admitted_view:
            # Materialized variant, hoisted for the same reason as the
            # transfer rail above: this loop runs up to
            # `MAX_REVOCATION_RECORDS` times against ONE manifest.
            if isinstance(record, dict) and revocation._verify_record_signature(
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
            # `issued_at + timedelta(days=window_days)` walks off the end of the
            # representable range for a receipt issued near year 9999, and the
            # schema's 3650-day cap does not prevent it. `OverflowError` is not
            # part of this function's contract: it would escape `verify()`
            # itself. Answering "unknown" with an explicit error is the
            # fail-closed reading — returning None instead would silently make
            # the revocation record ineffective (`_within_refund_window` treats
            # a `None` window as "no record is ever effective", so the receipt
            # would verify green with a genuine revocation in hand).
            # The "unknown" here is THIS dispatch's answer, not necessarily the
            # reported one: a matching `status: "transferred"` record still
            # sends the outcome through the Stage 3 fallthrough below, which may
            # rename it `invalid_revocation_ignored` or `transferred`. What holds
            # on every one of those paths is the error, and `VerificationResult.ok`
            # is `False` as soon as `errors` is non-empty — that, not the literal
            # returned here, is what makes this fail closed.
            try:
                window_end = _refund_window_end(payload)
            except OverflowError:
                errors.append("refund window is outside the representable timestamp range")
                return _REVOCATION_UNKNOWN
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
    # for ALL revocability classes, `none` included (the
    # key-authorization-gate principle).
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
