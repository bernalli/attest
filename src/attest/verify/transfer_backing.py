"""Stage 3 transfer backing (v0.2 sections 17.2-17.4): the winning, backed
transfer record for a receipt among untrusted transfer claims."""

from __future__ import annotations

from typing import Any

from attest import anchor, manifests, tlog, transfer
from attest.verify.constants import (
    _MAX_TRANSFER_CLAIMS,
    _WARN_TRANSFER_DOUBLE_ASSIGNMENT,
    _WARN_TRANSFER_NOT_YET_TRANSFERABLE,
    _WARN_TRANSFER_RECORD_UNLOGGED,
    _WARN_TRANSFERRED_REVOCATION_UNBACKED,
)
from attest.verify.evidence import _materialize_evidence_array
from attest.verify.helpers import _parse_iso


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

    PRECONDITION: `issuer_manifest` is ALREADY MATERIALIZED — it came out of
    `_materialized_trust_store`. This function reaches the hoisted
    `transfer._verify_record_signature`, which does not re-apply the boundary,
    so a raw caller object handed in here would reopen the class that boundary
    closes. Private for exactly that reason.

    `transfer_view` is materialized once at the untrusted boundary — the
    SAME `canon.dumps`/size-bound/`except Exception` confinement
    `_revocation_deadline_satisfied` already applies to `revocation_evidence`
    — so every later phase sees ordinary JSON values, never a stateful/
    hostile mapping or list a caller constructed.

    Per claim, in this exact order (§17.3's key-authorization gate plus §17.7/§17.2):

    1. `record` is a dict whose `receipt_id` equals `payload`'s own — else
       the claim is irrelevant to this receipt and is skipped silently.
    2. `transfer._verify_record_signature(record, issuer_manifest)` — the
       issuer's own signature (hoisting `manifests.verify_key_manifest` once
       here, mirroring `_classify_revocation`'s own hoisting of the same
       check — this function is called at most once per classification).
       On failure: `_WARN_TRANSFERRED_REVOCATION_UNBACKED` (deduplicated),
       skip.
    3. `payload["buyer"]["pubkey"]` is a non-null string AND
       `transfer.verify_authorization(record, pubkey)` — the signer controls
       the key the issuer recorded in the OLD receipt, which is not consent
       by the buyer or outgoing holder. Same unbacked warning on failure, skip.
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
    manifest_ok = manifests._manifest_signature_is_authentic(issuer_manifest)

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

        # The MATERIALIZED variant, deliberately: `issuer_manifest` came out of
        # `_materialized_trust_store` before this function was reached, and the
        # public entry point would re-materialize it once PER RECORD instead of
        # once per call. The boundary is not skipped here, it is hoisted.
        if not manifest_ok or not transfer._verify_record_signature(record, issuer_manifest):
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
