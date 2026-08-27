"""Statement-status freshness-anchor properties from v0.1 section 12.3."""

from __future__ import annotations

import json
from typing import Any

import pytest

from attest import issue, keys, manifests, revocation, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
KP = keys.from_seed(bytes([9]) * 32)
OTHER_RECEIPT_ID = "01J1V5B4M9Z8QWERTY99999999"
OLDER = "2026-07-05T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"


def _trust_store() -> verify.TrustStore:
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    manifest = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)
    return verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})


def _verify(records: list[dict[str, Any]], *, receipt_id: str | None = None) -> verify.Result:
    payload = make_payload(license={"revocability": "policy"})
    if receipt_id is not None:
        payload["receipt_id"] = receipt_id
    envelope = issue.issue(payload, KP, KID)
    return verify.verify(
        json.dumps(envelope).encode("utf-8"), _trust_store(), revocation_view=records
    )


def _record(receipt_id: str, status: Any, revoked_at: str) -> dict[str, Any]:
    return revocation.build_record(receipt_id, status, revoked_at, KP, KID)


@pytest.mark.parametrize(
    "status",
    [
        "Revoked",
        "revoked ",
        "revoke",
        "transferred_pending",
        7,
        True,
        None,
        {"status": "revoked"},
    ],
)
def test_authenticated_unregistered_status_never_provides_a_freshness_anchor(status: Any) -> None:
    """Every non-statement vocabulary value leaves a one-record view at bare ``unknown``."""
    result = _verify([_record(OTHER_RECEIPT_ID, status, FUTURE)])

    assert result.revocation == "unknown"
    assert not result.warnings


@pytest.mark.parametrize(
    "status", ["Revoked", "revoked ", "revoke", "transferred_pending", 7, True, None, {}]
)
def test_matching_unregistered_status_is_silent_and_cannot_revoke(status: Any) -> None:
    """A matching authenticated non-statement is ignored without a special anchor-only warning."""
    result = _verify([_record(make_payload()["receipt_id"], status, FUTURE)])

    assert result.revocation == "unknown"
    assert not result.warnings


@pytest.mark.parametrize("statement_status", ["revoked", "transferred"])
@pytest.mark.parametrize("records_in_reverse", [False, True])
def test_only_authenticated_registered_statement_statuses_determine_t(
    statement_status: str, records_in_reverse: bool
) -> None:
    """T is the order-independent maximum over genuine statements, never a future lookalike."""
    genuine = _record(OTHER_RECEIPT_ID, statement_status, OLDER)
    unregistered = _record("01J1V5B4M9Z8QWERTY88888888", "transferred_pending", FUTURE)
    records = [unregistered, genuine] if records_in_reverse else [genuine, unregistered]

    result = _verify(records)

    assert result.revocation == f"not_revoked_as_of:{OLDER}"


def test_broken_signature_cannot_supply_a_freshness_anchor() -> None:
    """A forged signature is neither a trustworthy statement nor a fallback source for T."""
    genuine = _record(OTHER_RECEIPT_ID, "revoked", OLDER)
    forged = _record("01J1V5B4M9Z8QWERTY77777777", "revoked", FUTURE)
    forged["signature"]["sig"] = "A" * 86

    only_forged = _verify([forged])
    mixed = _verify([genuine, forged])

    assert only_forged.revocation == "unknown"
    assert mixed.revocation == f"not_revoked_as_of:{OLDER}"


def test_genuine_revoked_record_still_revokes_and_anchors() -> None:
    """The status filter preserves matching revocation and a non-matching feed anchor."""
    matching_id = make_payload()["receipt_id"]
    record = _record(matching_id, "revoked", OLDER)

    matching = _verify([record])
    non_matching = _verify([record], receipt_id=OTHER_RECEIPT_ID)

    assert matching.revocation == "revoked"
    assert non_matching.revocation == f"not_revoked_as_of:{OLDER}"


def test_genuine_transferred_record_still_anchors() -> None:
    """The registered ``transferred`` literal remains a valid source for feed freshness."""
    record = _record(OTHER_RECEIPT_ID, "transferred", OLDER)

    result = _verify([record])

    assert result.revocation == f"not_revoked_as_of:{OLDER}"
