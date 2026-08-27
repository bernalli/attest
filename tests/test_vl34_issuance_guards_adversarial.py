"""Adversarial coverage for key-manifest issuance and resolution guards."""

from __future__ import annotations

import json
from typing import Any

import pytest

from attest import canon, issue, keys, manifests, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID1 = f"{ISSUER}/keys/vl34#one"
KID2 = f"{ISSUER}/keys/vl34#two"
KID3 = f"{ISSUER}/keys/vl34#three"
KP1 = keys.from_seed(bytes([31]) * 32)
KP2 = keys.from_seed(bytes([32]) * 32)
KP3 = keys.from_seed(bytes([33]) * 32)
ISSUED_AT = "2026-08-26T00:00:00Z"


def _entry(
    kid: str,
    key_pair: keys.SigningKeyPair,
    status: str = "active",
) -> dict[str, Any]:
    """Create a valid key entry whose status can be varied by a test."""
    return manifests.key_entry(kid, key_pair.pub, "2026-01-01T00:00:00Z", None, status)


def _receipt_bytes() -> bytes:
    """A genuinely signed receipt from KID1 — the manifest, not the receipt, is
    what these tests make hostile."""
    return json.dumps(issue.issue(make_payload(issuer_id=ISSUER), KP1, KID1)).encode("utf-8")


def _trust(manifest: dict[str, Any]) -> verify.TrustStore:
    return verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})


def _self_signed_manifest(entries: list[Any], version: int = 1) -> dict[str, Any]:
    """Sign hostile entries directly so verification reaches self-consistency."""
    body: dict[str, Any] = {
        "issuer": ISSUER,
        "manifest_version": version,
        "issued_at": ISSUED_AT,
        "keys": entries,
    }
    return {
        **body,
        "manifest_signature": manifests.sign_signature_block(
            canon.canonical_bytes(body), KP1, KID1
        ),
    }


def _active_manifest() -> dict[str, Any]:
    """Build a one-key manifest suitable as a rotation predecessor."""
    return manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, [_entry(KID1, KP1)], KP1, KID1)


@pytest.mark.parametrize(
    ("first_status", "second_status"),
    [
        ("active", "retired"),
        ("retired", "active"),
        ("active", "active"),
    ],
)
def test_duplicate_kid_is_rejected_independently_of_order_or_status(
    first_status: str, second_status: str
) -> None:
    """A duplicated kid is invalid even when order or lifecycle status changes."""
    entries = [_entry(KID1, KP1, first_status), _entry(KID1, KP1, second_status)]

    with pytest.raises(ValueError):
        manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, entries, KP1, KID1)

    ambiguous = _self_signed_manifest(entries)
    assert manifests.verify_key_manifest(ambiguous) is False
    assert manifests.find_key(ambiguous, KID1) is None


def test_three_duplicate_kids_fail_closed_without_position_selection() -> None:
    """Three entries sharing a kid must not let a resolver select any position."""
    entries = [
        _entry(KID1, KP1),
        _entry(KID2, KP2, "active"),
        _entry(KID2, KP2, "retired"),
        _entry(KID2, KP2, "compromised"),
    ]

    with pytest.raises(ValueError):
        manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, entries, KP1, KID1)

    ambiguous = _self_signed_manifest(entries)
    assert manifests.verify_key_manifest(ambiguous) is False
    assert manifests.find_key(ambiguous, KID2) is None


def test_duplicate_unrelated_to_signer_invalidates_the_whole_manifest() -> None:
    """A duplicate unrelated to the signing kid still fails manifest self-consistency."""
    entries = [
        _entry(KID1, KP1),
        _entry(KID2, KP2, "retired"),
        _entry(KID2, KP2, "retired"),
    ]

    with pytest.raises(ValueError):
        manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, entries, KP1, KID1)

    ambiguous = _self_signed_manifest(entries)
    assert manifests.verify_key_manifest(ambiguous) is False
    # `find_key` fails closed per KID, not per manifest: KID1 is unambiguous
    # here and still resolves. The whole-manifest refusal is delivered by
    # `verify_key_manifest` above and by `verify()`'s preflight below — every
    # consumer of a manifest passes through one of the two.
    assert manifests.find_key(ambiguous, KID1) is not None
    assert manifests.find_key(ambiguous, KID2) is None
    result = verify.verify(_receipt_bytes(), _trust(ambiguous))
    assert result.ok is False
    assert any("duplicate kid" in error for error in result.errors)


@pytest.mark.parametrize("invalid_entry", [None, [], "not-a-key-entry"])
def test_non_dict_entries_fail_every_manifest_consumer(invalid_entry: object) -> None:
    """A non-dict entry is ignored by resolution and never raises.

    The 2026-08-26 amendment is about duplicated kids, not about entry shape,
    and the library deliberately tolerates a malformed member (`keys: [null]`)
    rather than crashing the caller (2026-07-13 review, finding 11). What must
    hold is that such an entry can never RESOLVE and never escapes as an
    exception.
    """
    entries: list[Any] = [_entry(KID1, KP1), invalid_entry]

    built = manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, entries, KP1, KID1)
    assert manifests.verify_key_manifest(built) is True

    malformed = _self_signed_manifest(entries)
    assert manifests.find_key(malformed, KID1) is not None
    assert manifests.duplicate_kids(entries) == []


def test_non_string_kids_do_not_collide_through_python_equality() -> None:
    """True, 1 and '1' never collide with one another.

    The amendment does not make a non-string kid an issuance error; what it
    forbids is two entries sharing ONE kid. Python's `True == 1` could have
    made a bool and an int look like a duplicate pair, and `1 == "1"` is
    False, so this pins that only genuine strings are ever compared: three
    distinct non-colliding kids, no duplicate reported, and none of them
    resolvable by the string form.
    """
    true_kid = _entry(KID2, KP2)
    integer_kid = _entry(KID3, KP3)
    string_kid = _entry(KID2, KP2)
    true_kid["kid"] = True
    integer_kid["kid"] = 1
    string_kid["kid"] = "1"
    entries: list[Any] = [_entry(KID1, KP1), true_kid, integer_kid, string_kid]

    assert manifests.duplicate_kids(entries) == []

    built = manifests.build_key_manifest(ISSUER, 1, ISSUED_AT, entries, KP1, KID1)
    assert manifests.verify_key_manifest(built) is True
    assert manifests.find_key(built, "1") == string_kid
    # Neither the bool nor the int entry answers to the string form, and the
    # only kid still carrying a real string besides "1" is KID1.
    assert manifests.find_key(built, KID1) is not None
    assert manifests.find_key(built, KID2) is None


def test_continuity_rejects_duplicates_in_either_manifest() -> None:
    """Continuity consumes both manifests and rejects either ambiguous keyset."""
    valid_predecessor = _active_manifest()
    valid_successor = manifests.build_key_manifest(
        ISSUER,
        2,
        "2026-08-27T00:00:00Z",
        [_entry(KID1, KP1), _entry(KID2, KP2)],
        KP1,
        KID1,
    )
    duplicate_entries = [_entry(KID1, KP1), _entry(KID2, KP2), _entry(KID2, KP2)]
    ambiguous_predecessor = _self_signed_manifest(duplicate_entries)
    ambiguous_successor = _self_signed_manifest(duplicate_entries, version=2)

    assert manifests.check_continuity(ambiguous_predecessor, valid_successor) is False
    assert manifests.check_continuity(valid_predecessor, ambiguous_successor) is False


@pytest.mark.parametrize("operation", ["retire", "compromise"])
def test_rotation_cannot_remove_the_last_active_key_without_replacement(
    operation: str,
) -> None:
    """Retiring or compromising the sole active key must refuse the rotation."""
    kwargs: dict[str, Any] = {f"{operation}_kids": [KID1]}

    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(_active_manifest(), KP1, KID1, ISSUED_AT, **kwargs)


def test_rotation_can_retire_the_last_active_key_when_an_active_replacement_exists() -> None:
    """Retirement succeeds when the successor retains an active replacement key."""
    rotated = manifests.rotate_key_manifest(
        _active_manifest(),
        KP1,
        KID1,
        ISSUED_AT,
        new_entry=_entry(KID2, KP2, "active"),
        retire_kids=[KID1],
    )

    replacement = manifests.find_key(rotated, KID2)
    assert manifests.verify_key_manifest(rotated) is True
    assert replacement is not None
    assert replacement["status"] == "active"


@pytest.mark.parametrize("replacement_status", ["retired", "compromised"])
def test_rotation_rejects_a_non_active_replacement_for_the_last_active_key(
    replacement_status: str,
) -> None:
    """A replacement marked retired or compromised cannot satisfy the active-key rule."""
    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(
            _active_manifest(),
            KP1,
            KID1,
            ISSUED_AT,
            new_entry=_entry(KID2, KP2, replacement_status),
            retire_kids=[KID1],
        )


def test_rotation_rejects_a_zero_active_predecessor_that_stays_zero_active() -> None:
    """Rotation may not publish a successor that leaves an already-degenerate keyset active-less."""
    zero_active = manifests.build_key_manifest(
        ISSUER, 1, ISSUED_AT, [_entry(KID1, KP1, "retired")], KP1, KID1
    )

    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(
            zero_active,
            KP1,
            KID1,
            ISSUED_AT,
            new_entry=_entry(KID2, KP2, "retired"),
        )


def test_rotation_applies_duplicate_and_zero_active_guards_together() -> None:
    """A rotation must not turn an ambiguous manifest into a zero-active successor."""
    ambiguous = _self_signed_manifest(
        [
            _entry(KID1, KP1),
            _entry(KID2, KP2, "retired"),
            _entry(KID2, KP2, "retired"),
        ]
    )

    with pytest.raises(ValueError):
        manifests.rotate_key_manifest(ambiguous, KP1, KID1, ISSUED_AT, retire_kids=[KID1])


@pytest.mark.parametrize("status", ["retired", "compromised"])
def test_existing_single_key_zero_active_manifests_remain_verifiable(status: str) -> None:
    """Verification keeps accepting signed retired or compromised fixture manifests."""
    degenerate = manifests.build_key_manifest(
        ISSUER, 1, ISSUED_AT, [_entry(KID1, KP1, status)], KP1, KID1
    )

    resolved = manifests.find_key(degenerate, KID1)
    assert manifests.verify_key_manifest(degenerate) is True
    assert resolved is not None
    assert resolved["status"] == status
