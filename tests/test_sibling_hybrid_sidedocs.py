"""Tests for hybrid (Ed25519 + ML-DSA-65) revocation records and artifact
manifests (v0.2 profile) — the "sibling patch" mirroring
`test_manifests_hybrid.py`'s coverage of key manifests onto the two
remaining Ed25519-only side-documents (design §12.1 / Stage 2 Task 6).
"""

from __future__ import annotations

from typing import Any

from attest import keys, manifests, pq, revocation, verify
from tests.helpers import key_manifest as km
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#hybrid-1"
VALID_FROM = "2026-01-01T00:00:00Z"
ISSUED_AT = "2026-01-01T00:00:00Z"
RELEASED_AT = "2026-02-01T00:00:00Z"
REVOKED_AT = "2026-02-01T00:00:00Z"
RECEIPT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _hybrid_key_manifest() -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(KID, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    key_manifest = manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, [entry], hk, KID)
    return hk, key_manifest


def _ed_only_key_manifest() -> tuple[keys.SigningKeyPair, dict[str, Any]]:
    ed_kp = keys.generate()
    entry = manifests.key_entry(KID, ed_kp.pub, VALID_FROM)
    key_manifest = manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, [entry], ed_kp, KID)
    return ed_kp, key_manifest


# --- revocation records ------------------------------------------------------


def test_hybrid_revocation_record_has_both_legs() -> None:
    hk, _ = _hybrid_key_manifest()
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, hk, KID)
    assert "sig" in record["signature"]
    assert "sig_ml_dsa_65" in record["signature"]


def test_hybrid_revocation_record_verifies() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, hk, KID)
    assert revocation.verify_record(record, km(key_manifest))


def test_hybrid_revocation_record_missing_mldsa_leg_invalid() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, hk, KID)
    assert revocation.verify_record(record, km(key_manifest))
    del record["signature"]["sig_ml_dsa_65"]
    assert not revocation.verify_record(record, km(key_manifest))


def test_hybrid_revocation_record_tampered_mldsa_leg_invalid() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, hk, KID)
    raw = bytearray(keys.b64u_decode(record["signature"]["sig_ml_dsa_65"]))
    raw[0] ^= 0xFF
    record["signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(raw))
    assert not revocation.verify_record(record, km(key_manifest))


def test_edonly_revocation_record_unchanged() -> None:
    ed_kp, key_manifest = _ed_only_key_manifest()
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, ed_kp, KID)
    assert "sig_ml_dsa_65" not in record["signature"]
    assert revocation.verify_record(record, km(key_manifest))


def test_edonly_revocation_record_with_stray_mldsa_leg_invalid() -> None:
    ed_kp, key_manifest = _ed_only_key_manifest()
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, ed_kp, KID)
    record["signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(pq.ML_DSA_65_SIG_LEN))
    assert not revocation.verify_record(record, km(key_manifest))


# --- artifact manifests -------------------------------------------------------


def _artifacts() -> list[dict[str, Any]]:
    return [{"artifact_id": "widget-1.0.0", "sha256": "0" * 64}]


def test_hybrid_artifact_manifest_has_both_legs() -> None:
    hk, _ = _hybrid_key_manifest()
    manifest = manifests.build_artifact_manifest(
        ISSUER, "widget", 1, RELEASED_AT, _artifacts(), hk, KID
    )
    assert "sig" in manifest["manifest_signature"]
    assert "sig_ml_dsa_65" in manifest["manifest_signature"]


def test_hybrid_artifact_manifest_verifies() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    manifest = manifests.build_artifact_manifest(
        ISSUER, "widget", 1, RELEASED_AT, _artifacts(), hk, KID
    )
    assert manifests.verify_artifact_manifest(manifest, km(key_manifest))


def test_hybrid_artifact_manifest_missing_mldsa_leg_invalid() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    manifest = manifests.build_artifact_manifest(
        ISSUER, "widget", 1, RELEASED_AT, _artifacts(), hk, KID
    )
    assert manifests.verify_artifact_manifest(manifest, km(key_manifest))
    del manifest["manifest_signature"]["sig_ml_dsa_65"]
    assert not manifests.verify_artifact_manifest(manifest, km(key_manifest))


def test_hybrid_artifact_manifest_tampered_mldsa_leg_invalid() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    manifest = manifests.build_artifact_manifest(
        ISSUER, "widget", 1, RELEASED_AT, _artifacts(), hk, KID
    )
    raw = bytearray(keys.b64u_decode(manifest["manifest_signature"]["sig_ml_dsa_65"]))
    raw[0] ^= 0xFF
    manifest["manifest_signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(raw))
    assert not manifests.verify_artifact_manifest(manifest, km(key_manifest))


def test_edonly_artifact_manifest_unchanged() -> None:
    ed_kp, key_manifest = _ed_only_key_manifest()
    manifest = manifests.build_artifact_manifest(
        ISSUER, "widget", 1, RELEASED_AT, _artifacts(), ed_kp, KID
    )
    assert "sig_ml_dsa_65" not in manifest["manifest_signature"]
    assert manifests.verify_artifact_manifest(manifest, km(key_manifest))


def test_edonly_artifact_manifest_with_stray_mldsa_leg_invalid() -> None:
    ed_kp, key_manifest = _ed_only_key_manifest()
    manifest = manifests.build_artifact_manifest(
        ISSUER, "widget", 1, RELEASED_AT, _artifacts(), ed_kp, KID
    )
    manifest["manifest_signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(pq.ML_DSA_65_SIG_LEN))
    assert not manifests.verify_artifact_manifest(manifest, km(key_manifest))


# --- §12.1 semantics through verify._classify_revocation ---------------------
#
# The library-level AND rule above is what `verify.py`'s `_classify_revocation`
# consumes via `revocation.verify_record_signature` — this pins that an
# unauthenticated hybrid record (missing PQ leg) degrades exactly like today's
# unauthenticated Ed25519 record: ignored with the existing warning literal,
# never silently dropped and never promoted to an error (mirrors the pattern
# in `tests/test_revocation_view_bound.py`).


def test_hybrid_revocation_record_missing_mldsa_leg_ignored_with_warning_in_verify() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, hk, KID)
    del record["signature"]["sig_ml_dsa_65"]
    payload = make_payload(receipt_id=RECEIPT_ID, license={"revocability": "policy"})

    warnings: list[str] = []
    errors: list[str] = []
    result = verify._classify_revocation(payload, [record], key_manifest, warnings, errors)

    assert result == "unknown"
    assert warnings == [f"revocation record for {RECEIPT_ID!r} failed verification, ignored"]
    assert errors == []
