"""Regression tests for the 2026-07-13 security-review must-fix batch.

Each test pins the *fixed* behaviour; written test-first (they fail against the
pre-fix code).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from attest import bundle, canon, commitment, issue, keys, manifests, validate, verify
from tests.helpers import key_manifest, make_payload, store

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([9]) * 32)
KP_ATTACKER = keys.from_seed(bytes([11]) * 32)


def _key_manifest(status: str = "active") -> dict[str, Any]:
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, status)]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def _trust_store(manifest: dict[str, Any]) -> verify.TrustStore:
    return store({ISSUER: manifest}, {ISSUER: "tls"})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


# --- Fix 1: rotation continuity must bind the candidate signature to trusted's pub ---


def test_continuity_rejects_substituted_pub_under_reused_kid() -> None:
    """A candidate that reuses an active kid but swaps in an attacker pub and
    self-signs must NOT pass continuity: continuity means 'signed by the key
    TRUSTED vouches for', which requires trusted's pub, not the candidate's own."""
    trusted = manifests.build_key_manifest(
        ISSUER,
        1,
        "2026-01-01T00:00:00Z",
        [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")],
        KP,
        KID,
    )
    # Attacker candidate: reuses KID but lists the attacker's pub, self-signed by it.
    candidate = manifests.build_key_manifest(
        ISSUER,
        2,
        "2026-02-01T00:00:00Z",
        [manifests.key_entry(KID, KP_ATTACKER.pub, "2026-01-01T00:00:00Z", None, "active")],
        KP_ATTACKER,
        KID,
    )
    assert manifests.verify_key_manifest(key_manifest(candidate))  # self-consistent by design
    assert manifests.check_continuity(key_manifest(trusted), key_manifest(candidate)) is False


# --- Fix 2: .private.attest carries bearer salts and must be created 0600 ---


def test_export_private_bundle_is_owner_only(tmp_path: Any) -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    km = _key_manifest()
    legal_texts = {
        hashlib.sha256(b"attest-test-legal-text-v1").hexdigest(): b"attest-test-legal-text-v1",
        hashlib.sha256(
            b"attest-test-mirror-policy-v1"
        ).hexdigest(): b"attest-test-mirror-policy-v1",
    }
    _, private_path = bundle.export([envelope], [km], [], legal_texts, tmp_path, "b")
    assert private_path.stat().st_mode & 0o777 == 0o600


# --- Fix 3: canon parser must cap nesting and stay CanonError-only (no crash) ---


def test_loads_strict_rejects_excessive_nesting() -> None:
    deep = b"[" * 2000 + b"]" * 2000
    with pytest.raises(canon.CanonError):
        canon.loads_strict(deep)


def test_verify_rejects_deeply_nested_envelope_without_crashing() -> None:
    deep = b'{"payload":' + b"[" * 2000 + b"]" * 2000 + b',"signatures":[]}'
    result = verify.verify(deep, _trust_store(_key_manifest()))
    assert result.signature == "invalid"


# --- Fix 4: an unknown/missing key status must fail closed, not validate ---


def test_verify_rejects_unknown_key_status() -> None:
    manifest = _key_manifest(status="frobnicate")
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


# --- Fix 6: lone surrogates in a buyer identifier must be rejected explicitly ---


def test_normalize_rejects_lone_surrogate() -> None:
    with pytest.raises(ValueError):
        commitment.normalize("a\ud800b", "issuer-account")


# --- Fix 7: ULID pattern must reject a first character above 7 (>128-bit id) ---


def test_ulid_pattern_rejects_first_char_above_7() -> None:
    bad_id = "8" + "0" * 25  # 26 valid Crockford chars, but a 130-bit id
    errors = validate.validate_payload(make_payload(receipt_id=bad_id))
    assert any("receipt_id" in e for e in errors)
