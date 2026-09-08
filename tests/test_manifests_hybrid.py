"""Tests for hybrid (Ed25519 + ML-DSA-65) key manifests (v0.2 profile)."""

from __future__ import annotations

from typing import Any

from attest import keys, manifests, pq
from tests.helpers import key_manifest as km

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#hybrid-1"
VALID_FROM = "2026-01-01T00:00:00Z"
ISSUED_AT = "2026-01-01T00:00:00Z"


def _hybrid_manifest() -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(KID, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    manifest = manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, [entry], hk, KID)
    return hk, manifest


def test_hybrid_key_entry_carries_mldsa_pub() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(KID, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    assert entry["pub_ml_dsa_65"] == keys.b64u(hk.mldsa.pub)


def test_hybrid_manifest_signature_has_both_legs() -> None:
    _, manifest = _hybrid_manifest()
    sig_block = manifest["manifest_signature"]
    assert "sig" in sig_block
    assert "sig_ml_dsa_65" in sig_block


def test_hybrid_manifest_verifies() -> None:
    _, manifest = _hybrid_manifest()
    assert manifests.verify_key_manifest(km(manifest))


def test_hybrid_manifest_missing_mldsa_leg_invalid() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(KID, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    manifest = manifests.build_key_manifest("shop.example", 1, ISSUED_AT, [entry], hk, KID)
    assert manifests.verify_key_manifest(km(manifest))
    del manifest["manifest_signature"]["sig_ml_dsa_65"]
    assert not manifests.verify_key_manifest(km(manifest))


def test_nonhybrid_manifest_with_stray_mldsa_leg_invalid() -> None:
    ed_kp = keys.generate()
    entry = manifests.key_entry(KID, ed_kp.pub, VALID_FROM)
    manifest = manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, [entry], ed_kp, KID)
    assert manifests.verify_key_manifest(km(manifest))
    manifest["manifest_signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(pq.ML_DSA_65_SIG_LEN))
    assert not manifests.verify_key_manifest(km(manifest))


def test_hybrid_manifest_tampered_mldsa_leg_invalid() -> None:
    _, manifest = _hybrid_manifest()
    raw = bytearray(keys.b64u_decode(manifest["manifest_signature"]["sig_ml_dsa_65"]))
    raw[0] ^= 0xFF
    manifest["manifest_signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(raw))
    assert not manifests.verify_key_manifest(km(manifest))


def test_continuity_hybrid_chain_ok() -> None:
    hk, trusted = _hybrid_manifest()
    entries_v2 = [
        manifests.key_entry(KID, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub, status="active")
    ]
    candidate = manifests.build_key_manifest(ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, hk, KID)
    assert manifests.check_continuity(km(trusted), km(candidate))


def test_continuity_rejects_candidate_missing_mldsa_leg() -> None:
    hk, trusted = _hybrid_manifest()
    entries_v2 = [
        manifests.key_entry(KID, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub, status="active")
    ]
    candidate = manifests.build_key_manifest(ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, hk, KID)
    del candidate["manifest_signature"]["sig_ml_dsa_65"]
    assert not manifests.check_continuity(km(trusted), km(candidate))
