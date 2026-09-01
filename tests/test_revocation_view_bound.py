"""Tests for the revocation-view bound + cached manifest self-verify.

Review improvement #17 (security review, 2026-07-13): `_classify_revocation`
used to re-run the issuer manifest's self-verify once PER RECORD in the
untrusted revocation view (O(N * manifest-verify) wasted-work DoS), and
the view had no size bound. This file pins the two hardenings:

- the manifest self-verify runs exactly once per classification
  (`verify_record_signature` + hoisted `verify_key_manifest`);
- an oversized view is not evaluated (`revocation: "unknown"`), and it fails
  CLOSED for revocable receipts (`policy`/`refund_window` → an error, so
  `ok` is false) while only warning for irrevocable `none` receipts — never
  truncation, never a raise. Fail-closed is the fix for the append-only
  feed-poisoning suppression attack flagged in the final review round.

Mirrored on the TS side by `verifiers/ts/test/revocation-bound.test.ts`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from attest import issue, keys, manifests, revocation, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
RETIRED_KID = f"{ISSUER}/keys/test#ed25519-retired"
GHOST_KID = f"{ISSUER}/keys/test#ed25519-ghost"  # never listed in the manifest

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([21]) * 32)
RETIRED_KP = keys.from_seed(bytes([22]) * 32)
GHOST_KP = keys.from_seed(bytes([23]) * 32)

RECEIPT_ID = "01J1V5B4M9Z8QWERTY12345678"  # tests.helpers base payload receipt_id


def _key_manifest() -> dict[str, Any]:
    entries = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(RETIRED_KID, RETIRED_KP.pub, "2026-01-01T00:00:00Z", None, "retired"),
    ]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def _record(revoked_at: str = "2026-07-03T00:00:00Z") -> dict[str, Any]:
    return revocation.build_record(RECEIPT_ID, "revoked", revoked_at, KP, KID)


# --- cached manifest self-verify (Task 1) -------------------------------------


def test_manifest_self_verify_runs_once_per_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Improvement #17 core: one manifest self-verify per classification, not
    one per record — a hostile many-record feed can no longer multiply
    manifest-verification work.

    The hoisted call is `manifest_signature_is_authentic`, not
    `verify_key_manifest`: a manifest downgraded by deleting its PQ leg loses
    its trust level, never its power to revoke (v0.2 §4). What this test
    pins is the COUNT, so it follows the function the hoist actually calls."""
    manifest = _key_manifest()
    payload = make_payload(license={"revocability": "policy"})
    view = [_record(f"2026-07-0{i}T00:00:00Z") for i in range(1, 6)]

    calls = {"count": 0}
    real = manifests.manifest_signature_is_authentic

    def counting(m: dict[str, Any]) -> bool:
        calls["count"] += 1
        return real(m)

    monkeypatch.setattr(manifests, "manifest_signature_is_authentic", counting)
    warnings: list[str] = []
    errors: list[str] = []
    result = verify._classify_revocation(payload, view, manifest, warnings, errors)
    assert result == "revoked"
    assert calls["count"] == 1


def test_verify_record_signature_accepts_valid_record() -> None:
    manifest = _key_manifest()
    assert manifests.verify_key_manifest(manifest) is True  # documented precondition
    assert revocation.verify_record_signature(_record(), manifest) is True


def test_verify_record_signature_rejects_unlisted_signer() -> None:
    record = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", GHOST_KP, GHOST_KID
    )
    assert revocation.verify_record_signature(record, _key_manifest()) is False


def test_verify_record_signature_rejects_non_active_signer() -> None:
    record = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", RETIRED_KP, RETIRED_KID
    )
    assert revocation.verify_record_signature(record, _key_manifest()) is False


def test_verify_record_signature_rejects_revoked_at_before_valid_from() -> None:
    record = _record(revoked_at="2025-12-31T23:59:59Z")
    assert revocation.verify_record_signature(record, _key_manifest()) is False


def test_verify_record_delegates_and_still_requires_manifest_self_consistency() -> None:
    manifest = _key_manifest()
    assert revocation.verify_record(_record(), manifest) is True
    tampered = dict(manifest)
    tampered["issued_at"] = "2027-01-01T00:00:00Z"  # breaks the manifest's own signature
    assert revocation.verify_record(_record(), tampered) is False


# --- revocation-view size cap (Task 2) -----------------------------------------


def _trust_store(manifest: dict[str, Any]) -> verify.TrustStore:
    return verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    """Simulate bytes received over the wire — need not be canonical, only valid JSON."""
    return json.dumps(envelope).encode("utf-8")


def test_default_cap_is_10_000() -> None:
    assert verify._MAX_REVOCATION_RECORDS == 10_000


def test_oversized_view_on_revocable_receipt_fails_closed() -> None:
    """Overflow on a REVOCABLE receipt fails closed: an untrusted view too
    large to evaluate must not certify the receipt as ok. Returning "unknown"
    with ok=true would let an append-only feed-poisoning attacker suppress a
    genuine revocation by padding past the cap (adversarial review finding)."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    view = [_record(f"2026-07-0{i}T00:00:00Z") for i in range(1, 5)]  # 4 records
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=view,
        max_revocation_records=3,
    )
    assert result.revocation == "unknown"
    assert (
        "revocation view exceeds 3 records (4 supplied), cannot certify a revocable receipt"
        in result.errors
    )
    assert result.ok is False


def test_oversized_view_on_irrevocable_receipt_warns_and_stays_ok() -> None:
    """Overflow on an irrevocable ("none") receipt is a non-fatal warning:
    revocation can never affect ok, so an oversized feed cannot force not-ok."""
    payload = make_payload()  # revocability: none (base payload default)
    envelope = issue.issue(payload, KP, KID)
    view = [_record(f"2026-07-0{i}T00:00:00Z") for i in range(1, 5)]  # 4 records
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=view,
        max_revocation_records=3,
    )
    assert result.revocation == "unknown"
    assert "revocation view exceeds 3 records (4 supplied), not evaluated" in result.warnings
    assert result.errors == ()
    assert result.ok is True


def test_padding_a_genuine_revocation_past_the_cap_cannot_suppress_it() -> None:
    """The suppression scenario from the review: a genuine issuer-signed
    revocation for a policy receipt, padded with junk past the cap, must NOT
    flip the receipt to ok. Fail-closed: revocation "unknown" but ok=false."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    genuine = _record("2026-07-03T00:00:00Z")
    junk = [
        {"receipt_id": "x", "status": "revoked", "revoked_at": "2026-07-03T00:00:00Z"}
        for _ in range(3)
    ]
    view = [genuine, *junk]  # 4 entries > cap 3
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=view,
        max_revocation_records=3,
    )
    assert result.revocation == "unknown"
    assert result.ok is False


def test_oversized_view_on_refund_window_receipt_fails_closed() -> None:
    """The second revocable class (`refund_window`) fails closed on overflow
    exactly like `policy` — pins that both revocable classes are covered."""
    payload = make_payload(license={"revocability": "refund_window", "revocation_window_days": 14})
    envelope = issue.issue(payload, KP, KID)
    view = [_record(f"2026-07-0{i}T00:00:00Z") for i in range(1, 5)]  # 4 records
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=view,
        max_revocation_records=3,
    )
    assert result.revocation == "unknown"
    assert (
        "revocation view exceeds 3 records (4 supplied), cannot certify a revocable receipt"
        in result.errors
    )
    assert result.ok is False


def test_same_view_under_default_cap_is_still_revoked() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    view = [_record(f"2026-07-0{i}T00:00:00Z") for i in range(1, 5)]  # 4 records
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=view)
    assert result.revocation == "revoked"
    assert result.ok is False


def test_view_exactly_at_cap_evaluates_normally() -> None:
    """The boundary is strict `>`: n == cap is evaluated, n == cap + 1 is not."""
    payload = make_payload(license={"revocability": "policy"})
    view = [_record(f"2026-07-0{i}T00:00:00Z") for i in range(1, 4)]  # 3 records
    warnings: list[str] = []
    errors: list[str] = []
    result = verify._classify_revocation(
        payload, view, _key_manifest(), warnings, errors, max_records=3
    )
    assert result == "revoked"
    assert warnings == []
    assert errors == []
