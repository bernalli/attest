"""Tests for attest.validate — JSON Schema (draft 2020-12) validation of attest payloads."""

from __future__ import annotations

import importlib.resources
import json
from pathlib import Path

import pytest

from attest import canon, validate
from attest.keys import b64u

from .helpers import make_payload

_PUBKEY = b64u(bytes(32))


def test_valid_example_payload_passes() -> None:
    assert validate.validate_payload(make_payload()) == []


def test_revocability_none_with_drm_bound_fails() -> None:
    payload = make_payload(license={"drm": "drm-bound"})

    errors = validate.validate_payload(payload)

    assert errors


def test_revocability_none_without_artifacts_or_series_fails() -> None:
    payload = make_payload()
    del payload["work"]["artifact_series"]
    payload["work"]["artifacts"] = []

    errors = validate.validate_payload(payload)

    assert errors


def test_refund_window_without_revocation_window_days_fails() -> None:
    payload = make_payload(license={"revocability": "refund_window"})

    errors = validate.validate_payload(payload)

    assert errors
    assert any("revocation_window_days" in e for e in errors)


def test_size_bytes_at_2_pow_53_fails() -> None:
    payload = make_payload()
    payload["work"]["artifacts"][0]["size_bytes"] = 2**53

    errors = validate.validate_payload(payload)

    assert errors
    assert any("size_bytes" in e for e in errors)


def test_packaged_schema_is_byte_identical_to_normative_copy() -> None:
    repo_root = Path(__file__).parent.parent
    normative = repo_root / "docs" / "spec" / "schema" / "attest-receipt.schema.json"
    packaged = importlib.resources.files("attest.schema").joinpath("attest-receipt.schema.json")

    assert packaged.read_bytes() == normative.read_bytes()


def test_attest_version_02_accepted() -> None:
    payload = make_payload(attest_version="0.2")

    assert validate.validate_payload(payload) == []


def test_attest_version_unknown_rejected() -> None:
    payload = make_payload(attest_version="0.3")

    errors = validate.validate_payload(payload)

    assert errors


# --- D1 holder binding (v0.2 §17.8) ------------------------------------------


def test_v02_transferable_true_requires_pubkey() -> None:
    payload = make_payload(attest_version="0.2")
    payload["license"]["transferable"] = True
    payload["buyer"]["pubkey"] = None

    errors = validate.validate_payload(payload)

    assert any("pubkey" in e for e in errors)


def test_v01_transferable_true_null_pubkey_still_valid() -> None:
    payload = make_payload(attest_version="0.1")
    payload["license"]["transferable"] = True
    payload["buyer"]["pubkey"] = None

    assert validate.validate_payload(payload) == []


def test_v02_transferable_true_with_pubkey_present_is_valid() -> None:
    payload = make_payload(attest_version="0.2")
    payload["license"]["transferable"] = True
    payload["buyer"]["pubkey"] = _PUBKEY

    assert validate.validate_payload(payload) == []


def test_v02_transferable_false_null_pubkey_still_valid() -> None:
    payload = make_payload(attest_version="0.2")
    payload["license"]["transferable"] = False
    payload["buyer"]["pubkey"] = None

    assert validate.validate_payload(payload) == []


# --- not_transferable_before (v0.2 §17.7) ------------------------------------


def test_not_transferable_before_accepts_iso_and_rejects_garbage() -> None:
    payload = make_payload()
    payload["license"]["not_transferable_before"] = "2026-07-23T00:00:00Z"

    assert validate.validate_payload(payload) == []

    payload["license"]["not_transferable_before"] = "not-a-date"

    errors = validate.validate_payload(payload)

    assert any("not_transferable_before" in e for e in errors)


# --- D5 preservation pledge (v0.2 §18.2, §18.6) ------------------------------

_GRANT_SHA256 = "9f2b4a1c0d3e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4"
_PLEDGE = {
    "pledge": "sunset-grant-v1",
    "grant_uri": "https://pub.example/sunset-grant-v1.json",
    "grant_sha256": _GRANT_SHA256,
}


def _pledge_payload(**overrides: object) -> dict[str, object]:
    """A v0.2 receipt satisfying §18.6's holder-binding conditional."""
    payload = make_payload(
        attest_version="0.2",
        buyer={"pubkey": _PUBKEY},
        work={"publisher_id": "pub.example"},
        license={"preservation_pledge": dict(_PLEDGE)},
        survivability={"end_of_life": "sunset-grant"},
    )
    payload.update(overrides)
    return payload


def test_pledge_bearing_v02_receipt_is_valid() -> None:
    assert validate.validate_payload(_pledge_payload()) == []


def test_pledge_requires_all_three_members() -> None:
    for member in ("pledge", "grant_uri", "grant_sha256"):
        payload = _pledge_payload()
        del payload["license"]["preservation_pledge"][member]  # type: ignore[index]

        errors = validate.validate_payload(payload)

        assert errors, f"missing {member!r} must be a schema error"


def test_pledge_grant_sha256_must_be_lowercase_hex64() -> None:
    payload = _pledge_payload()
    payload["license"]["preservation_pledge"]["grant_sha256"] = _GRANT_SHA256.upper()  # type: ignore[index]

    assert validate.validate_payload(payload)


def test_unrecognized_pledge_profile_is_never_a_schema_error() -> None:
    """§18.2: the pledge vocabulary is open and versioned — an unrecognized
    value is valid-with-warning, following v0.1 §5.6's `end_of_life`
    discipline, never a schema error."""
    payload = _pledge_payload()
    payload["license"]["preservation_pledge"]["pledge"] = "sunset-grant-v9"  # type: ignore[index]

    assert validate.validate_payload(payload) == []


def test_v02_pledge_requires_non_null_buyer_pubkey() -> None:
    payload = _pledge_payload()
    payload["buyer"]["pubkey"] = None  # type: ignore[index]

    assert any("pubkey" in e for e in validate.validate_payload(payload))


def test_v02_pledge_requires_work_publisher_id() -> None:
    payload = _pledge_payload()
    del payload["work"]["publisher_id"]  # type: ignore[index]

    assert any("publisher_id" in e for e in validate.validate_payload(payload))


def test_v02_pledge_requires_the_sunset_grant_eol_label() -> None:
    payload = _pledge_payload()
    payload["survivability"]["end_of_life"] = "escrow"  # type: ignore[index]

    assert any("sunset-grant" in e for e in validate.validate_payload(payload))


def test_v01_receipt_with_a_pledge_is_untouched() -> None:
    """§18.6 is gated on `attest_version`: a v0.1 receipt carrying the same
    three fields — no pubkey, no publisher_id, another end_of_life — stays
    exactly as valid as it was before Stage 4 existed."""
    payload = make_payload(
        attest_version="0.1",
        license={"preservation_pledge": dict(_PLEDGE)},
    )
    payload["buyer"]["pubkey"] = None

    assert validate.validate_payload(payload) == []


def test_v02_receipt_without_a_pledge_is_untouched() -> None:
    payload = make_payload(attest_version="0.2")
    payload["buyer"]["pubkey"] = None

    assert validate.validate_payload(payload) == []


def test_v01_receipt_corpus_is_byte_identical_after_stage_4() -> None:
    """No v0.1 receipt changes meaning: the pledge conditional is
    `attest_version`-gated, and the two new OPTIONAL properties constrain only
    names v0.1 never assigned. Pinned over the reference payload rather than
    asserted in prose."""
    before = canon.canonical_bytes(make_payload())

    assert validate.validate_payload(make_payload()) == []
    assert canon.canonical_bytes(make_payload()) == before


def test_work_publisher_id_must_be_a_lowercase_dns_name() -> None:
    payload = _pledge_payload()
    payload["work"]["publisher_id"] = "Pub.Example"  # type: ignore[index]

    assert any("publisher_id" in e for e in validate.validate_payload(payload))


def test_work_publisher_id_pattern_equals_issuer_id_pattern() -> None:
    """§18.1: the rights holder's domain has the same shape as `issuer.id` —
    one grammar, not a second one that could drift."""
    properties = validate.SCHEMA["properties"]
    issuer_pattern = properties["issuer"]["properties"]["id"]["pattern"]
    publisher_pattern = properties["work"]["properties"]["publisher_id"]["pattern"]

    assert publisher_pattern == issuer_pattern


# --- G1 normative ceilings (attest-versioning.md §5 amendment) --------------


def test_validate_envelope_size_accepts_at_ceiling() -> None:
    assert validate.validate_envelope_size(b"x" * validate.MAX_ENVELOPE_BYTES) == []


def test_validate_envelope_size_rejects_over_ceiling() -> None:
    violations = validate.validate_envelope_size(b"x" * (validate.MAX_ENVELOPE_BYTES + 1))

    assert any(
        "envelope exceeds" in v and str(validate.MAX_ENVELOPE_BYTES) in v for v in violations
    )


# `validate.validate_json_depth` was deleted in the 2026-07-22 fix wave: it
# duplicated `canon.py`'s own parse-time nesting-depth cap byte-for-byte (a
# parsed tree handed to it could never exceed the cap, since `canon.
# loads_strict` already rejects deeper input before a parsed tree exists) —
# see `validate.py`'s `MAX_JSON_DEPTH` docstring for the redundant-check
# deletion rationale. These tests cover the single source of truth directly.


def test_max_json_depth_aliases_canon_max_depth() -> None:
    """`validate.MAX_JSON_DEPTH` is a single-source-of-truth alias of
    `canon.MAX_DEPTH` (256), not a second, independently-defined ceiling —
    the previous `MAX_JSON_DEPTH = 32` duplicated and shrank canon.py's own
    parse-time cap, rejecting two previously-conforming vectors
    (`21-canon-strict/b-depth-255`, `c-depth-256`) in violation of
    attest-versioning.md §2's additive-pattern rule."""
    assert validate.MAX_JSON_DEPTH == canon.MAX_DEPTH == 256


def test_json_nesting_accepted_exactly_at_ceiling() -> None:
    nested: object = "leaf"
    for _ in range(validate.MAX_JSON_DEPTH):
        nested = {"n": nested}

    assert canon.loads_strict(json.dumps(nested).encode("utf-8")) is not None


def test_json_nesting_rejected_one_past_ceiling() -> None:
    nested: object = "leaf"
    for _ in range(validate.MAX_JSON_DEPTH + 1):
        nested = {"n": nested}

    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.loads_strict(json.dumps(nested).encode("utf-8"))
