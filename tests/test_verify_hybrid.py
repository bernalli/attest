"""Tests for the v0.2 hybrid (Ed25519 + ML-DSA-65) verification path.

AND semantics, fail-closed: a v0.2 receipt is accepted only if BOTH its
Ed25519 and ML-DSA-65 signatures verify. Every canonical error literal here
is mirrored byte-for-byte by the TypeScript verifier (Task 7) — copy them
verbatim, never paraphrase.
"""

from __future__ import annotations

import json
from typing import Any

from attest import canon, issue, keys, manifests, pq, verify
from tests.helpers import make_payload, store

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#hybrid-1"
VALID_FROM = "2026-01-01T00:00:00Z"

# TEST ONLY — fixed seeds, never use in production.
_HK = pq.HybridSigningKeys(ed=keys.from_seed(bytes([21]) * 32), mldsa=pq.generate())


def _hybrid_manifest() -> dict[str, Any]:
    entry = manifests.key_entry(KID, _HK.ed.pub, VALID_FROM, pub_ml_dsa_65=_HK.mldsa.pub)
    return manifests.build_key_manifest(ISSUER, 1, VALID_FROM, [entry], _HK, KID)


def _non_hybrid_manifest() -> dict[str, Any]:
    """A manifest whose key entry has no `pub_ml_dsa_65` — self-signed with an
    Ed25519-only key so it stays independently valid, letting the hybrid
    envelope's own Ed25519 leg be re-signed with the same `_HK.ed` key."""
    entry = manifests.key_entry(KID, _HK.ed.pub, VALID_FROM)
    return manifests.build_key_manifest(ISSUER, 1, VALID_FROM, [entry], _HK.ed, KID)


def _trust_store(manifest: dict[str, Any]) -> verify.TrustStore:
    return store({ISSUER: manifest}, {ISSUER: "tls"})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _hybrid_envelope() -> dict[str, Any]:
    payload = make_payload(attest_version="0.2")
    return issue.issue(payload, _HK, KID)


def test_valid_hybrid_receipt_ok() -> None:
    envelope = _hybrid_envelope()
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.signature == "valid"
    assert result.errors == ()
    assert result.ok is True


def test_single_signature_v02_invalid() -> None:
    envelope = _hybrid_envelope()
    envelope["signatures"] = envelope["signatures"][:1]
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.signature == "invalid"
    assert result.errors == ("hybrid envelope requires exactly two signatures",)


def test_wrong_alg_order_invalid() -> None:
    envelope = _hybrid_envelope()
    envelope["signatures"] = list(reversed(envelope["signatures"]))
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.signature == "invalid"
    assert result.errors == ("hybrid envelope requires algs Ed25519 and ML-DSA-65 in order",)


def test_duplicate_ed25519_alg_invalid() -> None:
    envelope = _hybrid_envelope()
    ed_entry = envelope["signatures"][0]
    envelope["signatures"] = [ed_entry, dict(ed_entry)]
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.signature == "invalid"
    assert result.errors == ("hybrid envelope requires algs Ed25519 and ML-DSA-65 in order",)


def test_kid_mismatch_between_legs_invalid() -> None:
    envelope = _hybrid_envelope()
    envelope["signatures"][1]["kid"] = f"{ISSUER}/keys/test#hybrid-other"
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.signature == "invalid"
    assert result.errors == ("hybrid envelope signatures must share a single kid",)


def test_key_entry_without_mldsa_pub_invalid() -> None:
    # The envelope's Ed25519 leg is re-signed with the same `_HK.ed` key that
    # the non-hybrid manifest lists, so the only thing that can fail is the
    # missing `pub_ml_dsa_65` check itself.
    payload = make_payload(attest_version="0.2")
    payload_bytes = canon.canonical_bytes(payload)
    envelope = {
        "payload": payload,
        "signatures": [
            {"kid": KID, "alg": "Ed25519", "sig": keys.b64u(keys.sign(payload_bytes, _HK.ed))},
            {
                "kid": KID,
                "alg": "ML-DSA-65",
                "sig": keys.b64u(pq.sign(payload_bytes, _HK.mldsa)),
            },
        ],
    }
    result = verify.verify(_to_bytes(envelope), _trust_store(_non_hybrid_manifest()))
    assert result.signature == "invalid"
    assert result.errors == (f"key entry for kid {KID!r} has no ML-DSA-65 public key",)


def test_tampered_mldsa_leg_invalid() -> None:
    envelope = _hybrid_envelope()
    raw = bytearray(keys.b64u_decode(envelope["signatures"][1]["sig"]))
    raw[0] ^= 0xFF
    envelope["signatures"][1]["sig"] = keys.b64u(bytes(raw))
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.signature == "invalid"
    assert result.errors == ("ML-DSA-65 signature verification failed",)


def test_tampered_ed_leg_invalid() -> None:
    envelope = _hybrid_envelope()
    raw = bytearray(keys.b64u_decode(envelope["signatures"][0]["sig"]))
    raw[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = keys.b64u(bytes(raw))
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.signature == "invalid"
    assert result.errors == ("signature verification failed",)


def test_v01_receipt_still_verifies() -> None:
    ed_kp = keys.from_seed(bytes([22]) * 32)  # TEST ONLY
    kid = f"{ISSUER}/keys/test#ed25519-1"
    entry = manifests.key_entry(kid, ed_kp.pub, VALID_FROM)
    manifest = manifests.build_key_manifest(ISSUER, 1, VALID_FROM, [entry], ed_kp, kid)

    envelope = issue.issue(make_payload(), ed_kp, kid)
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "valid"
    assert result.errors == ()


def test_v02_uncanonicalizable_payload_is_invalid_not_raised() -> None:
    """A payload that reaches canonicalization at verify time but that
    `canon.canonical_bytes` rejects (integer outside the I-JSON safe range)
    must return an invalid `VerificationResult`, never raise `CanonError`
    out of `verify.verify` (adversarial review finding #1)."""
    envelope = _hybrid_envelope()
    envelope["payload"]["out_of_range_int"] = 2**53
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.ok is False
    assert result.signature == "invalid"
    assert len(result.errors) == 1
    assert result.errors[0].startswith("malformed signature material: ")


def test_non_string_attest_version_is_invalid_not_raised() -> None:
    """`attest_version` must fail closed when it is an unhashable value (e.g.
    a JSON list), not raise `TypeError` from the `in` membership check
    against `_SUPPORTED_ATTEST_VERSIONS` (adversarial review finding #3)."""
    envelope = _hybrid_envelope()
    envelope["payload"]["attest_version"] = ["0.2"]
    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))
    assert result.ok is False
    assert result.signature == "invalid"
    assert result.errors == ("unsupported attest_version: ['0.2']",)


# --- G6 mixed-keyset prohibition (v0.2 §2.3/§13 amendment) ------------------

_LEGACY_KID = f"{ISSUER}/keys/test#ed25519-legacy-1"
_LEGACY_KP = keys.from_seed(bytes([22]) * 32)


def _mixed_keyset_manifest(legacy_status: str) -> dict[str, Any]:
    entries = [
        manifests.key_entry(
            KID, _HK.ed.pub, VALID_FROM, None, "active", pub_ml_dsa_65=_HK.mldsa.pub
        ),
        manifests.key_entry(_LEGACY_KID, _LEGACY_KP.pub, VALID_FROM, None, legacy_status),
    ]
    return manifests.build_key_manifest(ISSUER, 1, VALID_FROM, entries, _HK, KID)


def test_mixed_keyset_active_ed_only_sibling_warns() -> None:
    manifest = _mixed_keyset_manifest("active")
    envelope = _hybrid_envelope()

    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))

    assert result.signature == "valid"
    assert "mixed_keyset_active_ed_only_sibling" in result.warnings
    assert result.ok is True  # the warning is the whole contract — no field caps this


def test_mixed_keyset_no_warning_when_sibling_retired() -> None:
    """v0.2 §13's migration ceremony: the same `manifest_version` that
    introduces the hybrid key retires every Ed25519-only key — a cleanly
    completed migration carries no mixed-keyset warning."""
    manifest = _mixed_keyset_manifest("retired")
    envelope = _hybrid_envelope()

    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))

    assert result.signature == "valid"
    assert "mixed_keyset_active_ed_only_sibling" not in result.warnings


def test_no_mixed_keyset_warning_without_ed_only_sibling() -> None:
    envelope = _hybrid_envelope()

    result = verify.verify(_to_bytes(envelope), _trust_store(_hybrid_manifest()))

    assert result.signature == "valid"
    assert "mixed_keyset_active_ed_only_sibling" not in result.warnings


def test_mixed_keyset_warning_present_on_tampered_ed_leg() -> None:
    """I2 (2026-07-22 fix wave 2, review round-1): the G6 warning must fire
    for every v0.2 resolution of a mixed manifest, independent of whether the
    receipt's own signatures then verify — a tampered/failed receipt must
    still carry it, not just the happy path."""
    manifest = _mixed_keyset_manifest("active")
    envelope = _hybrid_envelope()
    raw = bytearray(keys.b64u_decode(envelope["signatures"][0]["sig"]))
    raw[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = keys.b64u(bytes(raw))

    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))

    assert result.signature == "invalid"
    assert result.errors == ("signature verification failed",)
    assert "mixed_keyset_active_ed_only_sibling" in result.warnings


def test_mixed_keyset_warning_present_on_tampered_mldsa_leg() -> None:
    """I2 companion: the same must hold when the failing leg is the
    ML-DSA-65 signature instead of the Ed25519 one."""
    manifest = _mixed_keyset_manifest("active")
    envelope = _hybrid_envelope()
    raw = bytearray(keys.b64u_decode(envelope["signatures"][1]["sig"]))
    raw[0] ^= 0xFF
    envelope["signatures"][1]["sig"] = keys.b64u(bytes(raw))

    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))

    assert result.signature == "invalid"
    assert result.errors == ("ML-DSA-65 signature verification failed",)
    assert "mixed_keyset_active_ed_only_sibling" in result.warnings
