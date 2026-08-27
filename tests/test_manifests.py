"""Tests for attest.manifests — key manifests, artifact manifests, rotation
continuity (design §5)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from attest import issue, keys, manifests, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
SERIES = "store.example.com/works/EXG-001"

# TEST ONLY — fixed seeds, never use in production.
KP1 = keys.from_seed(bytes([4]) * 32)
KP2 = keys.from_seed(bytes([5]) * 32)
KP3 = keys.from_seed(bytes([6]) * 32)

KID1 = f"{ISSUER}/keys/test#ed25519-1"
KID2 = f"{ISSUER}/keys/test#ed25519-2"
KID3 = f"{ISSUER}/keys/test#ed25519-3"

_ARTIFACT_SHA256 = hashlib.sha256(b"attest-test-artifact-manifest-v1").hexdigest()


def _artifact() -> dict[str, Any]:
    return {
        "role": "installer",
        "platform": "windows-x86_64",
        "filename": "example-game-1.0-setup.exe",
        "size_bytes": 734003200,
        "sha256": _ARTIFACT_SHA256,
    }


def _v1_manifest(status: str = "active") -> dict[str, Any]:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, status)]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1)


# --- key_entry -------------------------------------------------------------


def test_key_entry_shape_and_defaults() -> None:
    e = manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z")
    assert e == {
        "kid": KID1,
        "pub": keys.b64u(KP1.pub),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_to": None,
        "status": "active",
    }


# --- find_key ----------------------------------------------------------------


def test_find_key_present_and_missing() -> None:
    m = _v1_manifest()
    assert manifests.find_key(m, KID1) is not None
    assert manifests.find_key(m, "nope") is None


# --- build_key_manifest / verify_key_manifest -------------------------------


def test_build_verify_key_manifest_roundtrip() -> None:
    m = _v1_manifest()
    assert manifests.verify_key_manifest(m)


def test_tampered_key_status_breaks_verification() -> None:
    """Design vector 11: key status flipped after manifest signing -> manifest invalid."""
    m = _v1_manifest()
    m["keys"][0]["status"] = "compromised"
    assert not manifests.verify_key_manifest(m)


def test_tampered_signature_breaks_verification() -> None:
    m = _v1_manifest()
    m["manifest_signature"]["sig"] = keys.b64u(bytes(64))
    assert not manifests.verify_key_manifest(m)


def test_verify_key_manifest_missing_signature_block_false() -> None:
    m = _v1_manifest()
    del m["manifest_signature"]
    assert not manifests.verify_key_manifest(m)


def test_verify_key_manifest_unknown_signer_kid_false() -> None:
    m = _v1_manifest()
    m["manifest_signature"]["kid"] = "someone/else#ed25519-9"
    assert not manifests.verify_key_manifest(m)


def test_verify_key_manifest_nonstr_sig_false_no_raise() -> None:
    m = _v1_manifest()
    m["manifest_signature"]["sig"] = 12345  # wrong-typed, arrives from untrusted source
    assert not manifests.verify_key_manifest(m)


def test_verify_key_manifest_nonstr_pub_false_no_raise() -> None:
    m = _v1_manifest()
    m["keys"][0]["pub"] = 12345  # wrong-typed pub encoding
    assert not manifests.verify_key_manifest(m)


# --- check_continuity --------------------------------------------------------


def test_continuity_active_signer_true() -> None:
    trusted = _v1_manifest()
    entries_v2 = [
        manifests.key_entry(
            KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "retired"
        ),
        manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active"),
    ]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP1, KID1
    )
    assert manifests.check_continuity(trusted, candidate)


def test_continuity_version_gap_false() -> None:
    trusted = _v1_manifest()
    entries_v3 = [manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        ISSUER, 3, "2026-06-01T00:00:00Z", entries_v3, KP1, KID1
    )
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_signer_absent_from_trusted_false() -> None:
    trusted = _v1_manifest()
    entries_v2 = [manifests.key_entry(KID3, KP3.pub, "2026-06-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP3, KID3
    )
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_signer_retired_in_trusted_false() -> None:
    entries_v1 = [
        manifests.key_entry(
            KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "retired"
        )
    ]
    trusted = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries_v1, KP1, KID1)
    entries_v2 = [manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP1, KID1
    )
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_candidate_self_tampered_false() -> None:
    trusted = _v1_manifest()
    entries_v2 = [
        manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active"),
    ]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP1, KID1
    )
    candidate["keys"][1]["status"] = "compromised"  # breaks candidate's own signature
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_issuer_mismatch_false() -> None:
    trusted = _v1_manifest()
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        "evil.example.com", 2, "2026-06-01T00:00:00Z", entries, KP1, KID1
    )
    assert not manifests.check_continuity(trusted, candidate)


# --- build_artifact_manifest / verify_artifact_manifest ---------------------


def test_build_verify_artifact_manifest_roundtrip() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_wrong_issuer_false() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        "other.example.com", SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_tampered_false() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    am["version"] = 2
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_signer_not_active_false() -> None:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "retired")]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_released_before_valid_from_false() -> None:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-06-01T00:00:00Z", None, "active")]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-06-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-01-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_released_after_valid_to_false() -> None:
    entries = [
        manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "active")
    ]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_nonstr_released_at_false_no_raise() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    am["released_at"] = 12345  # wrong-typed date
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_none_released_at_false_no_raise() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    am["released_at"] = None  # missing/null date
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_self_inconsistent_key_manifest_false() -> None:
    # key_manifest no longer self-verifies (status tampered after signing), yet the
    # artifact manifest is well-formed and signed by a kid still listed in it.
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert manifests.verify_artifact_manifest(am, key_manifest)  # sanity: valid before tamper
    key_manifest["keys"][0]["valid_from"] = "1999-01-01T00:00:00Z"  # breaks self-signature
    assert not manifests.verify_key_manifest(key_manifest)
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_released_within_window_true() -> None:
    entries = [
        manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z", "active")
    ]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-06-15T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert manifests.verify_artifact_manifest(am, key_manifest)


# --- G1 normative ceilings (attest-versioning.md §5 amendment) --------------


def _filler_key_entries(count: int, prefix: str) -> list[dict[str, Any]]:
    """`count` distinct, deterministic Ed25519 key entries — no wall-clock or
    CSPRNG randomness, matching `tools/gen_vectors.py`'s determinism
    discipline (this file has no such existing rule, but generated
    filler at ceiling scale should still be reproducible on inspection)."""
    entries = []
    for i in range(count):
        seed = hashlib.sha256(f"{prefix}-{i}".encode()).digest()
        kp = keys.from_seed(seed)
        entries.append(
            manifests.key_entry(
                f"{ISSUER}/keys/test#filler-{i}", kp.pub, "2026-01-01T00:00:00Z", None, "active"
            )
        )
    return entries


def test_verify_key_manifest_true_at_key_ceiling() -> None:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active")]
    entries += _filler_key_entries(manifests.MAX_MANIFEST_KEYS - 1, "test-manifest-ceiling-at")
    assert len(entries) == manifests.MAX_MANIFEST_KEYS
    manifest = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1)
    assert manifests.verify_key_manifest(manifest) is True


def test_verify_key_manifest_false_over_key_ceiling() -> None:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active")]
    entries += _filler_key_entries(manifests.MAX_MANIFEST_KEYS, "test-manifest-ceiling-over")
    assert len(entries) == manifests.MAX_MANIFEST_KEYS + 1
    manifest = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1)
    assert manifests.verify_key_manifest(manifest) is False


def test_verify_artifact_manifest_true_at_entries_ceiling() -> None:
    key_manifest = _v1_manifest()
    artifacts = [_artifact() for _ in range(manifests.MAX_ARTIFACT_ENTRIES)]
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", artifacts, KP1, KID1
    )
    assert manifests.verify_artifact_manifest(am, key_manifest) is True


def test_build_artifact_manifest_manifest_version_included_when_given() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1, manifest_version=1
    )
    assert am["manifest_version"] == 1
    assert manifests.verify_artifact_manifest(am, key_manifest)


@pytest.mark.parametrize("manifest_version", [0, -1, True, "1"])
def test_build_artifact_manifest_rejects_invalid_manifest_version(manifest_version: object) -> None:
    with pytest.raises(ValueError, match="manifest_version must be an integer >= 1"):
        manifests.build_artifact_manifest(
            ISSUER,
            SERIES,
            1,
            "2026-03-01T00:00:00Z",
            [_artifact()],
            KP1,
            KID1,
            manifest_version=manifest_version,  # type: ignore[arg-type]
        )


def test_verify_artifact_manifest_rejects_signed_zero_manifest_version() -> None:
    key_manifest = _v1_manifest()
    manifest = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    manifest["manifest_version"] = 0
    manifest["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(manifest),
        KP1,
        KID1,  # type: ignore[attr-defined]
    )
    assert manifests.verify_artifact_manifest(manifest, key_manifest) is False


def test_build_artifact_manifest_manifest_version_omitted_by_default() -> None:
    """Backward compatibility: an artifact manifest built without `manifest_version`
    (the pre-Task-3 shape) never gains the field — eternal verifiability requires
    every previously-conforming caller of `build_artifact_manifest` to keep working
    byte-for-byte."""
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert "manifest_version" not in am


# --- check_artifact_continuity (G3 currency, attest-versioning.md rev 4) ----


def _artifact_manifest(version: int, manifest_version: int | None) -> dict[str, Any]:
    return manifests.build_artifact_manifest(
        ISSUER,
        SERIES,
        version,
        "2026-03-01T00:00:00Z",
        [_artifact()],
        KP1,
        KID1,
        manifest_version=manifest_version,
    )


def test_artifact_manifest_monotone_accepts() -> None:
    m1 = _artifact_manifest(1, 1)
    m2 = _artifact_manifest(2, 2)
    assert manifests.check_artifact_continuity(trusted=m1, candidate=m2) is True


def test_artifact_manifest_regression_not_silently_accepted() -> None:
    m1 = _artifact_manifest(1, 1)
    m2 = _artifact_manifest(2, 2)
    assert manifests.check_artifact_continuity(trusted=m2, candidate=m1) is False


def test_artifact_manifest_continuity_gap_false() -> None:
    m1 = _artifact_manifest(1, 1)
    m3 = _artifact_manifest(3, 3)
    assert manifests.check_artifact_continuity(trusted=m1, candidate=m3) is False


def test_artifact_manifest_continuity_issuer_mismatch_false() -> None:
    trusted = _artifact_manifest(1, 1)
    candidate = manifests.build_artifact_manifest(
        "evil.example.com",
        SERIES,
        2,
        "2026-03-01T00:00:00Z",
        [_artifact()],
        KP1,
        KID1,
        manifest_version=2,
    )
    assert manifests.check_artifact_continuity(trusted=trusted, candidate=candidate) is False


def test_artifact_manifest_continuity_series_mismatch_false() -> None:
    trusted = _artifact_manifest(1, 1)
    candidate = manifests.build_artifact_manifest(
        ISSUER,
        "store.example.com/works/OTHER-002",
        2,
        "2026-03-01T00:00:00Z",
        [_artifact()],
        KP1,
        KID1,
        manifest_version=2,
    )
    assert manifests.check_artifact_continuity(trusted=trusted, candidate=candidate) is False


def test_artifact_manifest_continuity_legacy_trusted_warn_only() -> None:
    trusted = _artifact_manifest(1, None)
    candidate = _artifact_manifest(2, 1)
    assert manifests.check_artifact_continuity(trusted=trusted, candidate=candidate) is True


def test_artifact_manifest_continuity_legacy_candidate_warn_only() -> None:
    trusted = _artifact_manifest(1, 1)
    candidate = _artifact_manifest(2, None)
    assert manifests.check_artifact_continuity(trusted=trusted, candidate=candidate) is True


def test_artifact_manifest_same_version_value_identical_accepted() -> None:
    """A same-version RE-DELIVERY of the byte-identical manifest is continuous
    (e.g. a caller re-fetching the same trusted manifest it already holds)."""
    m1 = _artifact_manifest(1, 1)
    m1_again = dict(m1)
    assert manifests.check_artifact_continuity(trusted=m1, candidate=m1_again) is True


def test_artifact_manifest_same_version_distinct_content_rejected() -> None:
    """Equivocation shape: two DIFFERENT manifests at the SAME manifest_version
    must NOT be treated as continuous — the caller routes this to
    `unverified_rotation` instead of silently accepting either."""
    m1 = _artifact_manifest(1, 1)
    m1_variant = manifests.build_artifact_manifest(
        ISSUER,
        SERIES,
        1,
        "2026-03-02T00:00:00Z",
        [_artifact()],
        KP1,
        KID1,
        manifest_version=1,
    )
    assert m1 != m1_variant
    assert manifests.check_artifact_continuity(trusted=m1, candidate=m1_variant) is False


def test_verify_artifact_manifest_false_over_entries_ceiling() -> None:
    key_manifest = _v1_manifest()
    artifacts = [_artifact() for _ in range(manifests.MAX_ARTIFACT_ENTRIES + 1)]
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", artifacts, KP1, KID1
    )
    assert manifests.verify_artifact_manifest(am, key_manifest) is False


# --- G6 mixed-keyset prohibition (v0.2 §2.3/§13 amendment) ------------------


def _hybrid_entry(kid: str, kp: Any, status: str = "active") -> dict[str, Any]:
    return manifests.key_entry(
        kid, kp.pub, "2026-01-01T00:00:00Z", None, status, pub_ml_dsa_65=bytes(1952)
    )


def test_has_active_ed_only_sibling_true_when_ed_only_key_active() -> None:
    manifest = {
        "keys": [
            _hybrid_entry(KID1, KP1, status="active"),
            manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z", None, "active"),
        ]
    }
    assert manifests.has_active_ed_only_sibling(manifest) is True


def test_has_active_ed_only_sibling_false_when_sibling_retired() -> None:
    manifest = {
        "keys": [
            _hybrid_entry(KID1, KP1, status="active"),
            manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z", None, "retired"),
        ]
    }
    assert manifests.has_active_ed_only_sibling(manifest) is False


def test_has_active_ed_only_sibling_false_when_no_hybrid_key_at_all() -> None:
    manifest = {
        "keys": [
            manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active"),
            manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z", None, "active"),
        ]
    }
    assert manifests.has_active_ed_only_sibling(manifest) is False


def test_has_active_ed_only_sibling_false_when_all_keys_hybrid() -> None:
    manifest = {
        "keys": [
            _hybrid_entry(KID1, KP1, status="active"),
            _hybrid_entry(KID2, KP2, status="active"),
        ]
    }
    assert manifests.has_active_ed_only_sibling(manifest) is False


def test_has_active_ed_only_sibling_malformed_keys_fails_closed_no_raise() -> None:
    assert manifests.has_active_ed_only_sibling({"keys": "not-a-list"}) is False
    assert manifests.has_active_ed_only_sibling({"keys": [None, 42, "x"]}) is False
    assert manifests.has_active_ed_only_sibling({}) is False


# --- rotate_key_manifest: retirement / compromise ----------------------------


def _two_active_v1() -> dict[str, Any]:
    """A v1 manifest with two active keys, so a rotation can compromise one and
    still be signed by the other (the recovery-key requirement)."""
    entries = [
        manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z"),
        manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z"),
    ]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1)


def test_rotate_compromise_flips_status_and_chains() -> None:
    v1 = _two_active_v1()
    rotated = manifests.rotate_key_manifest(
        v1,
        KP2,
        KID2,
        "2026-06-01T00:00:00Z",
        compromise_kids=[KID1],
        new_entry=manifests.key_entry(KID3, KP3.pub, "2026-06-01T00:00:00Z"),
    )
    assert rotated["manifest_version"] == 2
    assert manifests.find_key(rotated, KID1)["status"] == "compromised"
    assert manifests.find_key(rotated, KID3)["status"] == "active"
    assert manifests.verify_key_manifest(rotated)
    assert manifests.check_continuity(v1, rotated)  # signed by KID2, active in v1


def test_rotate_retire_flips_status() -> None:
    v1 = _two_active_v1()
    rotated = manifests.rotate_key_manifest(
        v1, KP2, KID2, "2026-06-01T00:00:00Z", retire_kids=[KID1]
    )
    assert manifests.find_key(rotated, KID1)["status"] == "retired"
    assert manifests.verify_key_manifest(rotated)


def test_rotate_does_not_mutate_the_input_manifest() -> None:
    v1 = _two_active_v1()
    manifests.rotate_key_manifest(v1, KP2, KID2, "2026-06-01T00:00:00Z", compromise_kids=[KID1])
    assert manifests.find_key(v1, KID1)["status"] == "active"  # caller's copy untouched


def test_compromised_key_past_receipt_fails_verification() -> None:
    """The load-bearing security assertion: once a key is compromised, a
    receipt it previously signed no longer verifies (fail-closed, §5)."""
    v1 = _two_active_v1()
    envelope_bytes = json.dumps(issue.issue(make_payload(), KP1, KID1)).encode("utf-8")

    ts_before = verify.TrustStore(manifests={ISSUER: v1}, provenance={ISSUER: "bundle"})
    assert verify.verify(envelope_bytes, ts_before).signature == "valid"

    v2 = manifests.rotate_key_manifest(
        v1, KP2, KID2, "2026-06-01T00:00:00Z", compromise_kids=[KID1]
    )
    ts_after = verify.TrustStore(manifests={ISSUER: v2}, provenance={ISSUER: "bundle"})
    result = verify.verify(envelope_bytes, ts_after)
    assert result.signature == "invalid"
    assert any("compromised" in e for e in result.errors)


def test_retired_key_past_receipt_still_verifies_with_warning() -> None:
    """Contrast: a retired key's past receipt stays valid, only warned."""
    v1 = _two_active_v1()
    envelope_bytes = json.dumps(issue.issue(make_payload(), KP1, KID1)).encode("utf-8")

    v2 = manifests.rotate_key_manifest(v1, KP2, KID2, "2026-06-01T00:00:00Z", retire_kids=[KID1])
    ts = verify.TrustStore(manifests={ISSUER: v2}, provenance={ISSUER: "bundle"})
    result = verify.verify(envelope_bytes, ts)
    assert result.signature == "valid"
    assert any("retired" in w for w in result.warnings)


def test_rotate_rejects_unknown_kid() -> None:
    v1 = _two_active_v1()
    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(v1, KP1, KID1, "2026-06-01T00:00:00Z", retire_kids=["nope"])


def test_rotate_rejects_kid_in_both_sets() -> None:
    v1 = _two_active_v1()
    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(
            v1, KP2, KID2, "2026-06-01T00:00:00Z", retire_kids=[KID1], compromise_kids=[KID1]
        )


def test_rotate_rejects_signing_key_in_compromised_set() -> None:
    v1 = _two_active_v1()
    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(v1, KP1, KID1, "2026-06-01T00:00:00Z", compromise_kids=[KID1])


def test_rotate_rejects_no_change() -> None:
    v1 = _two_active_v1()
    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(v1, KP1, KID1, "2026-06-01T00:00:00Z")


def test_rotate_rejects_new_kid_already_present() -> None:
    v1 = _two_active_v1()
    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(
            v1,
            KP1,
            KID1,
            "2026-06-01T00:00:00Z",
            new_entry=manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z"),
        )


def test_continuity_rejects_compromised_status_regression() -> None:
    v1 = _two_active_v1()
    v2 = manifests.rotate_key_manifest(
        v1, KP2, KID2, "2026-06-01T00:00:00Z", compromise_kids=[KID1]
    )
    entries_v3 = [
        manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z", None, "active"),
    ]
    v3 = manifests.build_key_manifest(ISSUER, 3, "2026-07-01T00:00:00Z", entries_v3, KP2, KID2)

    assert not manifests.check_continuity(v2, v3)


def test_continuity_rejects_omitted_prior_kid() -> None:
    v1 = _two_active_v1()
    entries_v2 = [manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z", None, "active")]
    v2 = manifests.build_key_manifest(ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP2, KID2)

    assert not manifests.check_continuity(v1, v2)


def test_build_key_manifest_previous_rejects_compromised_status_regression() -> None:
    v1 = _two_active_v1()
    v2 = manifests.rotate_key_manifest(
        v1, KP2, KID2, "2026-06-01T00:00:00Z", compromise_kids=[KID1]
    )
    regressed_entries = [
        manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z", None, "active"),
    ]

    with pytest.raises(ValueError):
        manifests.build_key_manifest(
            ISSUER,
            3,
            "2026-07-01T00:00:00Z",
            regressed_entries,
            KP2,
            KID2,
            previous=v2,
        )


def test_build_key_manifest_previous_rejects_previous_kid_omission() -> None:
    v1 = _two_active_v1()
    entries_v2 = [manifests.key_entry(KID2, KP2.pub, "2026-01-01T00:00:00Z", None, "active")]

    with pytest.raises(ValueError):
        manifests.build_key_manifest(
            ISSUER,
            2,
            "2026-06-01T00:00:00Z",
            entries_v2,
            KP2,
            KID2,
            previous=v1,
        )


def test_rotate_rejects_status_change_for_already_compromised_kid() -> None:
    v1 = _two_active_v1()
    v2 = manifests.rotate_key_manifest(
        v1, KP2, KID2, "2026-06-01T00:00:00Z", compromise_kids=[KID1]
    )

    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(v2, KP2, KID2, "2026-07-01T00:00:00Z", retire_kids=[KID1])
