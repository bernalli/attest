"""Tests for verify.py's Stage 3 (v0.2 §17) integration: `transfer_view`,
transferred-class backing, `not_transferable_before`, and the `ok`
extension.

Fixtures build a real transfer record (`transfer.build_record` +
`transfer.sign_authorization`) and a real single/two-leaf transparency log
(mirrors `tests/test_transparency.py`'s hand-built-tree style and
`tests/test_transfer.py`'s own `record_logged_standing` fixtures — both read
first, per the task brief).
"""

from __future__ import annotations

from typing import Any

import pytest

from attest import anchor, canon, issue, keys, manifests, pq, revocation, tlog, transfer, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"

# TEST ONLY — fixed seeds, never use in production.
ISSUER_KP = keys.from_seed(bytes([31]) * 32)
HOLDER_KP = keys.from_seed(bytes([32]) * 32)
OTHER_HOLDER_KP = keys.from_seed(bytes([33]) * 32)
NEW_HOLDER_KP = keys.from_seed(bytes([34]) * 32)

OLD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
NEW_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
LATE_NEW_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
AT = "2026-07-23T00:00:00Z"
NEW_HOLDER_PUBKEY = keys.b64u(NEW_HOLDER_KP.pub)

_TRANSFER_LOG_ORIGIN = "transfer-log.attest.example/2026"
_TRANSFER_LOG_NAME = "attest-transfer-log-1"


# --- shared fixtures ---------------------------------------------------------


def _key_manifest() -> dict[str, Any]:
    entries = [manifests.key_entry(KID, ISSUER_KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, ISSUER_KP, KID)


def _trust_store() -> verify.TrustStore:
    return verify.TrustStore(manifests={ISSUER: _key_manifest()}, provenance={ISSUER: "tls"})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    import json

    return json.dumps(envelope).encode("utf-8")


def _payload(
    revocability: str = "none", not_transferable_before: str | None = None
) -> dict[str, Any]:
    license_block: dict[str, Any] = {"revocability": revocability}
    if not_transferable_before is not None:
        license_block["not_transferable_before"] = not_transferable_before
    return make_payload(
        receipt_id=OLD_ID,
        issuer={"id": ISSUER, "display_name": "Example Store"},
        buyer={"pubkey": keys.b64u(HOLDER_KP.pub)},
        license=license_block,
    )


def _envelope(
    revocability: str = "none", not_transferable_before: str | None = None
) -> dict[str, Any]:
    return issue.issue(_payload(revocability, not_transferable_before), ISSUER_KP, KID)


def _transferred_revocation_record(receipt_id: str = OLD_ID, at: str = AT) -> dict[str, Any]:
    return revocation.build_record(receipt_id, "transferred", at, ISSUER_KP, KID)


def _transfer_record(
    new_receipt_id: str = NEW_ID,
    new_holder_pubkey: str = NEW_HOLDER_PUBKEY,
    transferred_at: str = AT,
    holder_kp: keys.SigningKeyPair = HOLDER_KP,
) -> dict[str, Any]:
    sig = transfer.sign_authorization(OLD_ID, new_holder_pubkey, transferred_at, holder_kp)
    return transfer.build_record(
        OLD_ID, new_receipt_id, new_holder_pubkey, transferred_at, sig, ISSUER_KP, KID
    )


def _resign_transfer_record(record: dict[str, Any]) -> None:
    """Re-sign `record`'s issuer signature after an out-of-band mutation
    (mirrors `tests/test_transfer.py`'s `_resign_record`)."""
    body = {key: value for key, value in record.items() if key != "signature"}
    record["signature"] = manifests.sign_signature_block(
        canon.canonical_bytes(body), ISSUER_KP, KID
    )


def _no_horizon_policy() -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


def _transfer_log_key(hk: pq.HybridSigningKeys) -> tlog.LogKey:
    return tlog.LogKey(
        origin=_TRANSFER_LOG_ORIGIN,
        name=_TRANSFER_LOG_NAME,
        ed25519_pub=hk.ed.pub,
        mldsa_pub=hk.mldsa.pub,
    )


def _transfer_log_bundle(
    records_in_order: list[dict[str, Any]], hk: pq.HybridSigningKeys
) -> list[dict[str, Any]]:
    """One genuine transfer-record log containing every record in
    `records_in_order`, in that log order (index 0 = earliest/first-logged).
    Returns one evidence bundle per record, each proving its own real
    `leaf_index`/`inclusion_proof` against the SAME final checkpoint."""
    entries = [
        {"type": "transfer-record", "issuer": ISSUER, "record_sha256": transfer.record_hash(r)}
        for r in records_in_order
    ]
    leaves = [tlog.encode_entry(e) for e in entries]
    root = tlog.build_tree(leaves)
    tree_size = len(leaves)
    checkpoint_text = tlog.sign_checkpoint(
        _TRANSFER_LOG_ORIGIN, tree_size, root, hk, _TRANSFER_LOG_NAME
    )
    return [
        {
            "entry": entry,
            "leaf_index": i,
            "tree_size": tree_size,
            "inclusion_proof": [p.hex() for p in tlog.inclusion_proof(leaves, i)],
            "checkpoint": checkpoint_text,
        }
        for i, entry in enumerate(entries)
    ]


def verify_with(
    *,
    revocation_view: list[dict[str, Any]] | None = None,
    transfer_view: list[dict[str, Any]] | None = None,
    log_keys: list[tlog.LogKey] | None = None,
    anchor_policy: anchor.AnchorPolicy | None = None,
    revocability: str = "none",
    not_transferable_before: str | None = None,
    supply_transfer_view: bool = True,
) -> verify.VerificationResult:
    envelope = _envelope(revocability, not_transferable_before)
    kwargs: dict[str, Any] = {
        "revocation_view": revocation_view,
        "log_keys": log_keys,
        "anchor_policy": anchor_policy,
    }
    if supply_transfer_view:
        kwargs["transfer_view"] = transfer_view
    return verify.verify(_to_bytes(envelope), _trust_store(), **kwargs)


# --- transferred-class backing (§17.3) ---------------------------------------


def test_transferred_with_full_backing_reports_transferred_not_ok() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _transfer_record()
    bundle = _transfer_log_bundle([record], hk)[0]
    valid_claim = {"record": record, "evidence": bundle}

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[valid_claim],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
    )

    assert result.revocation == "transferred"
    assert result.ok is False


def test_transferred_on_none_with_backing_honored() -> None:
    """Key-authorization gate (§17.3): honored even for the irrevocable `none` class."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _transfer_record()
    bundle = _transfer_log_bundle([record], hk)[0]
    valid_claim = {"record": record, "evidence": bundle}

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[valid_claim],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="none",
    )

    assert result.revocation == "transferred"
    assert result.ok is False


def test_transferred_without_transfer_view_ignored_with_warning() -> None:
    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=None,
        revocability="policy",
    )

    assert result.revocation == "invalid_revocation_ignored"
    assert "transferred_revocation_unbacked" in result.warnings
    assert result.ok is True


@pytest.mark.parametrize(
    "transfer_view",
    [
        [],
        [{"record": {"receipt_id": NEW_ID}, "evidence": None}],
        [{"padding": "x" * verify._MAX_TRANSPARENCY_EVIDENCE_LEN}],
        [{"record": _transfer_record(), "evidence": object()}],
    ],
    ids=("empty", "only-mismatched", "oversized", "unserializable"),
)
def test_transferred_resolver_never_engages_warns_unbacked(
    transfer_view: list[dict[str, Any]],
) -> None:
    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=transfer_view,
        revocability="policy",
    )

    assert result.revocation == "invalid_revocation_ignored"
    assert "transferred_revocation_unbacked" in result.warnings
    assert result.ok is True


def test_forged_holder_authorization_unbacked() -> None:
    """Same outcome as an unbacked record: a genuinely issuer-signed transfer
    record whose `holder_authorization` was never produced by the real
    holder must not back the transfer."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _transfer_record()
    # Forge the holder leg with a DIFFERENT keypair, then re-sign the whole
    # record so the issuer signature itself still verifies structurally.
    forged_sig = transfer.sign_authorization(OLD_ID, NEW_HOLDER_PUBKEY, AT, OTHER_HOLDER_KP)
    record["holder_authorization"]["sig"] = keys.b64u(forged_sig)
    _resign_transfer_record(record)
    bundle = _transfer_log_bundle([record], hk)[0]
    forged_claim = {"record": record, "evidence": bundle}

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[forged_claim],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
    )

    assert result.revocation == "invalid_revocation_ignored"
    assert "transferred_revocation_unbacked" in result.warnings
    assert result.ok is True


def test_unlogged_transfer_record_ignored() -> None:
    """Authenticated record (issuer sig + holder auth both verify), but no
    log evidence at all -> never proven logged, so it cannot back the
    transfer."""
    record = _transfer_record()
    unlogged_claim = {"record": record, "evidence": None}
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[unlogged_claim],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
    )

    assert result.revocation == "invalid_revocation_ignored"
    assert "transfer_record_unlogged" in result.warnings
    assert result.ok is True


def test_not_stage2_capable_cannot_honor_transfer() -> None:
    """No `log_keys`/`anchor_policy` at all (not Stage-2 capable) -> the
    capability gate itself fails, even though genuine log evidence IS
    present in the claim."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _transfer_record()
    bundle = _transfer_log_bundle([record], hk)[0]
    claim = {"record": record, "evidence": bundle}

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[claim],
        log_keys=None,
        anchor_policy=None,
        revocability="policy",
    )

    assert result.revocation == "invalid_revocation_ignored"
    assert "transfer_record_unlogged" in result.warnings
    assert result.ok is True


def test_double_assignment_earliest_leaf_index_wins() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    early_record = _transfer_record(new_receipt_id=NEW_ID)
    late_record = _transfer_record(new_receipt_id=LATE_NEW_ID)
    # Log order: early_record first (leaf_index 0), late_record second (1).
    early_bundle, late_bundle = _transfer_log_bundle([early_record, late_record], hk)
    early_claim = {"record": early_record, "evidence": early_bundle}
    late_claim = {"record": late_record, "evidence": late_bundle}

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[late_claim, early_claim],  # list order deliberately reversed
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
    )

    assert result.revocation == "transferred"
    assert "transfer_double_assignment_conflict" in result.warnings


def test_duplicate_transfer_claim_is_one_survivor_not_double_assignment() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _transfer_record()
    bundle = _transfer_log_bundle([record], hk)[0]
    claim = {"record": record, "evidence": bundle}

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[claim, claim],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
    )

    assert result.revocation == "transferred"
    assert "transfer_double_assignment_conflict" not in result.warnings


def test_distinct_transfer_claims_remain_double_assignment() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    early_record = _transfer_record(new_receipt_id=NEW_ID)
    late_record = _transfer_record(new_receipt_id=LATE_NEW_ID)
    early_bundle, late_bundle = _transfer_log_bundle([early_record, late_record], hk)

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[
            {"record": early_record, "evidence": early_bundle},
            {"record": late_record, "evidence": late_bundle},
        ],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
    )

    assert "transfer_double_assignment_conflict" in result.warnings


def test_not_transferable_before_violation_ignored() -> None:
    """`transferred_at` (AT, 2026-07-23) earlier than the receipt's own
    `not_transferable_before` -> not honored, distinct warning."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _transfer_record(transferred_at=AT)
    bundle = _transfer_log_bundle([record], hk)[0]
    claim = {"record": record, "evidence": bundle}

    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        transfer_view=[claim],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
        not_transferable_before="2026-08-01T00:00:00Z",
    )

    assert result.revocation == "invalid_revocation_ignored"
    assert "transfer_not_yet_transferable" in result.warnings
    assert "transferred_revocation_unbacked" not in result.warnings
    assert result.ok is True


def test_plain_revoked_semantics_unchanged_with_transfer_view_present() -> None:
    """A plain `status: "revoked"` record's outcome must be entirely
    unaffected by an ALSO-present `transfer_view` — the existing-`revoked`-
    logic-first rule."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    revoked_record = revocation.build_record(OLD_ID, "revoked", AT, ISSUER_KP, KID)
    unrelated_transfer_record = _transfer_record()
    bundle = _transfer_log_bundle([unrelated_transfer_record], hk)[0]
    claim = {"record": unrelated_transfer_record, "evidence": bundle}

    result = verify_with(
        revocation_view=[revoked_record],
        transfer_view=[claim],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        revocability="policy",
    )

    assert result.revocation == "revoked"
    assert result.ok is False


def test_existing_callers_unchanged() -> None:
    """A caller that never supplies `transfer_view` at all (relying on the
    keyword-only default) sees the exact same outcome as explicitly passing
    `None` — zero behavior change for every pre-Stage-3 caller."""
    result = verify_with(
        revocation_view=[_transferred_revocation_record()],
        revocability="policy",
        supply_transfer_view=False,
    )

    assert result.revocation == "invalid_revocation_ignored"
    assert "transferred_revocation_unbacked" in result.warnings
    assert result.ok is True


def test_non_list_transfer_view_raises_type_error() -> None:
    """Caller-contract enforcement (security), mirroring `revocation_view`'s
    own equivalent check: a lone claim OBJECT passed where a list is
    required must fail loud, never be silently iterated as dict keys."""
    envelope = _envelope()
    with pytest.raises(TypeError):
        verify.verify(
            _to_bytes(envelope),
            _trust_store(),
            transfer_view={"record": {}, "evidence": None},  # type: ignore[arg-type]
        )


def test_oversized_revocation_view_still_honours_a_transfer_on_none() -> None:
    """An over-ceiling view must not hide a transfer from an irrevocable receipt.

    The over-ceiling branch treats `none` as non-fatal because "a revocation can
    never affect ok" — true before Stage 3, and no longer true since §17.3 made
    the key-authorization gate apply to ALL revocability classes, `none` included: a backed
    `status: "transferred"` record caps `ok` for this class too. Those records
    ride the same `revocation_view`, so returning early on size discards them as
    well, and whoever can append to that view decides which transfer the verifier
    never sees.
    """
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _transfer_record()
    bundle = _transfer_log_bundle([record], hk)[0]
    envelope = _envelope("none")

    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(),
        revocation_view=[_transferred_revocation_record(), None, None],  # type: ignore[list-item]
        transfer_view=[{"record": record, "evidence": bundle}],
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_no_horizon_policy(),
        max_revocation_records=2,
    )

    # The property under test is that the receipt is NOT certified, not which of
    # the two ways of getting there is used. Honouring the transfer over the
    # ceiling would mean reading a view too large to evaluate; refusing to
    # certify keeps the ceiling and still denies the caller a green verdict it
    # cannot support. `revocation` stays `unknown` — nothing was evaluated — and
    # that is exactly why `ok` may not be true.
    assert result.ok is False
    assert any("cannot rule out a transfer" in error for error in result.errors)
