"""Tests for attest.revocation — issuer-signed revocation records (design §3.1/§6/§8)."""

from __future__ import annotations

import hashlib
from typing import Any

from attest import canon, keys, manifests, revocation

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
OTHER_KID = f"{ISSUER}/keys/test#ed25519-2"
COMPROMISED_KID = f"{ISSUER}/keys/test#ed25519-compromised"
RETIRED_KID = f"{ISSUER}/keys/test#ed25519-retired"

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([13]) * 32)
OTHER_KP = keys.from_seed(bytes([14]) * 32)
COMPROMISED_KP = keys.from_seed(bytes([15]) * 32)
RETIRED_KP = keys.from_seed(bytes([16]) * 32)

RECEIPT_ID = "01J1V5B4M9Z8QWERTY12345678"


def _key_manifest() -> dict[str, Any]:
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def _manifest_with(*extra: dict[str, Any]) -> dict[str, Any]:
    """Manifest self-signed by the active KID, plus any extra key entries."""
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"), *extra]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


# --- build_record ---------------------------------------------------------------


def test_build_record_shape() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    assert record["receipt_id"] == RECEIPT_ID
    assert record["status"] == "revoked"
    assert record["revoked_at"] == "2026-07-03T00:00:00Z"
    assert record["signature"]["kid"] == KID
    assert isinstance(record["signature"]["sig"], str)


# --- verify_record ----------------------------------------------------------------


def test_build_verify_record_roundtrip() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    assert revocation.verify_record(record, _key_manifest())


def test_tampered_status_breaks_verification() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    record["status"] = "not-revoked-anymore"
    assert not revocation.verify_record(record, _key_manifest())


def test_tampered_revoked_at_breaks_verification() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    record["revoked_at"] = "2099-01-01T00:00:00Z"
    assert not revocation.verify_record(record, _key_manifest())


# --- record_hash (G5: revocation-record log entries) -----------------------------


def test_record_hash_is_sha256_of_canonical_bytes() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    expected = hashlib.sha256(canon.canonical_bytes(record)).hexdigest()
    assert revocation.record_hash(record) == expected
    assert len(revocation.record_hash(record)) == 64


def test_record_hash_covers_signature_member() -> None:
    """Two records differing ONLY in their signature (e.g. re-signed by a
    different key) must hash differently — `record_hash` commits to the
    WHOLE record, not just the unsigned body (§8, G5)."""
    record_a = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    record_b = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", OTHER_KP, OTHER_KID
    )
    assert revocation.record_hash(record_a) != revocation.record_hash(record_b)


def test_record_hash_changes_with_tampered_status() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    original = revocation.record_hash(record)
    record["status"] = "not-revoked-anymore"
    assert revocation.record_hash(record) != original


def test_signer_kid_not_in_manifest_false() -> None:
    record = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", OTHER_KP, OTHER_KID
    )
    assert not revocation.verify_record(record, _key_manifest())


def test_missing_signature_block_false() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    del record["signature"]
    assert not revocation.verify_record(record, _key_manifest())


def test_nonstr_sig_false_no_raise() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    record["signature"]["sig"] = 12345  # wrong-typed, arrives from untrusted source
    assert not revocation.verify_record(record, _key_manifest())


def test_garbage_signature_block_type_false_no_raise() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    record["signature"] = "not-a-dict"
    assert not revocation.verify_record(record, _key_manifest())


def test_self_inconsistent_key_manifest_false() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    km = _key_manifest()
    km["keys"][0]["status"] = "compromised"  # breaks key_manifest's own signature
    assert not manifests.verify_key_manifest(km)
    assert not revocation.verify_record(record, km)


# --- fail-closed on non-active / out-of-window signing keys (§5, hardening) -------
#
# A revocation record is a NEW side-document issued at revoke-time; §5 says a
# `compromised` key's signatures are ALL invalid, and a revocation must be
# signed with a currently-active key whose validity window covers the record's
# own `revoked_at`. Mirrors `manifests.verify_artifact_manifest`.


def test_record_signed_by_compromised_key_is_rejected() -> None:
    """§5: a compromised key's signatures are all invalid — even over a record
    whose signature would otherwise verify against the listed key."""
    km = _manifest_with(
        manifests.key_entry(
            COMPROMISED_KID, COMPROMISED_KP.pub, "2026-01-01T00:00:00Z", None, "compromised"
        )
    )
    record = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", COMPROMISED_KP, COMPROMISED_KID
    )
    assert not revocation.verify_record(record, km)


def test_record_signed_by_retired_key_is_rejected() -> None:
    """A revocation must be signed by a currently-active key; retired is rejected."""
    km = _manifest_with(
        manifests.key_entry(RETIRED_KID, RETIRED_KP.pub, "2026-01-01T00:00:00Z", None, "retired")
    )
    record = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", RETIRED_KP, RETIRED_KID
    )
    assert not revocation.verify_record(record, km)


def test_record_revoked_at_before_key_valid_from_is_rejected() -> None:
    entries = [manifests.key_entry(KID, KP.pub, "2026-06-01T00:00:00Z", None, "active")]
    km = manifests.build_key_manifest(ISSUER, 1, "2026-06-01T00:00:00Z", entries, KP, KID)
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-01-01T00:00:00Z", KP, KID)
    assert not revocation.verify_record(record, km)


def test_record_revoked_at_after_key_valid_to_is_rejected() -> None:
    entries = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "active")
    ]
    km = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    assert not revocation.verify_record(record, km)


def test_record_revoked_at_within_key_window_is_accepted() -> None:
    entries = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z", "active")
    ]
    km = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-06-15T00:00:00Z", KP, KID)
    assert revocation.verify_record(record, km)


def test_record_nonstr_revoked_at_false_no_raise() -> None:
    record = revocation.build_record(RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", KP, KID)
    record["revoked_at"] = 12345  # wrong-typed date; must fail closed, never raise
    assert not revocation.verify_record(record, _key_manifest())


# -- receipt_id shape is a PRECONDITION for authentication ---------------------
#
# `verify_record_signature` types and shape-checks `receipt_id` before anything
# authenticates. The guard has been there since `bbde704`; nothing made it red
# if removed, and its TypeScript twin — edited in that same commit — never got
# it. These pin the property in the language that has it, so the two cores
# cannot drift apart again silently.


def _signed_record_with_receipt_id(receipt_id: Any) -> dict[str, Any]:
    """A record genuinely signed by the issuer's active key, malformed in one field.

    Built by signing the canonical body directly rather than through
    `build_record`, which would reject the malformed id before signing: the
    point is that only the ISSUER can produce this, and that a real signature
    over a malformed id must still not authenticate.
    """
    body: dict[str, Any] = {"status": "revoked", "revoked_at": "2026-07-03T00:00:00Z"}
    if receipt_id is not _ABSENT:
        body["receipt_id"] = receipt_id
    record = dict(body)
    record["signature"] = manifests.sign_signature_block(canon.canonical_bytes(body), KP, KID)
    return record


_ABSENT = object()


def test_a_genuinely_signed_record_with_a_malformed_receipt_id_does_not_authenticate() -> None:
    malformed: list[Any] = [
        "01JBQ0000000000000000OTHER",  # `O` is not in the Crockford alphabet
        RECEIPT_ID.lower(),
        RECEIPT_ID + "\n",
        RECEIPT_ID[:-1],  # 25 characters
        "8" + RECEIPT_ID[1:],  # first character above 7 overflows 128 bits
        12345,
        None,
        _ABSENT,
    ]
    km = _key_manifest()
    for receipt_id in malformed:
        record = _signed_record_with_receipt_id(receipt_id)
        assert not revocation.verify_record_signature(record, km), receipt_id


def test_a_well_formed_receipt_id_still_authenticates() -> None:
    """The negative control: without it the guard could reject everything and stay green."""
    record = _signed_record_with_receipt_id(RECEIPT_ID)
    assert revocation.verify_record_signature(record, _key_manifest())
