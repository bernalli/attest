"""Tests for attest.issue (receipt issuance envelope) and attest.ulid (receipt_id)."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest

from attest import canon, commitment, issue, keys, ulid, validate
from tests.helpers import make_payload

_CROCKFORD_EXCLUDED = set("ILOU")
_KID = "store.example.com/keys/2026-01#ed25519-1"


def _kp() -> keys.SigningKeyPair:
    return keys.from_seed(bytes([7]) * 32)  # TEST ONLY


class TestUlidGenerate:
    def test_length_is_26(self) -> None:
        assert len(ulid.generate()) == 26

    def test_alphabet_is_crockford_no_ambiguous_chars(self) -> None:
        value = ulid.generate()
        assert not (_CROCKFORD_EXCLUDED & set(value))
        assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", value)

    def test_sortable_by_timestamp(self) -> None:
        rnd = bytes(range(10))
        earlier = ulid.generate(timestamp_ms=1_000, randomness=rnd)
        later = ulid.generate(timestamp_ms=2_000, randomness=rnd)
        assert earlier < later

    def test_deterministic_with_injected_inputs(self) -> None:
        rnd = bytes(range(10))
        first = ulid.generate(timestamp_ms=1_700_000_000_000, randomness=rnd)
        second = ulid.generate(timestamp_ms=1_700_000_000_000, randomness=rnd)
        assert first == second

    def test_rejects_invalid_inputs(self) -> None:
        with pytest.raises(ValueError):
            ulid.generate(timestamp_ms=-1, randomness=bytes(10))
        with pytest.raises(ValueError):
            ulid.generate(timestamp_ms=2**48, randomness=bytes(10))
        with pytest.raises(ValueError):
            ulid.generate(timestamp_ms=0, randomness=bytes(9))


class TestIssue:
    def test_envelope_has_exactly_one_signature(self) -> None:
        envelope = issue.issue(make_payload(), _kp(), _KID)
        assert len(envelope["signatures"]) == 1

    def test_signature_verifies_against_canonical_payload_bytes(self) -> None:
        kp = _kp()
        payload = make_payload()
        envelope = issue.issue(payload, kp, _KID)
        sig_entry = envelope["signatures"][0]
        assert sig_entry["kid"] == _KID
        assert sig_entry["alg"] == "Ed25519"
        sig = keys.b64u_decode(sig_entry["sig"])
        assert keys.verify_strict(canon.canonical_bytes(payload), sig, kp.pub)

    def test_schema_invalid_payload_raises_issue_error(self) -> None:
        payload = make_payload()
        del payload["attest_version"]
        with pytest.raises(issue.IssueError):
            issue.issue(payload, _kp(), _KID)

    def test_kid_domain_mismatch_raises_issue_error(self) -> None:
        with pytest.raises(issue.IssueError):
            issue.issue(make_payload(), _kp(), "evil.com/keys/x#1")

    def test_delivery_salt_is_b64u_of_raw_salt(self) -> None:
        salt = bytes(range(16))
        envelope = issue.issue(make_payload(), _kp(), _KID, salt=salt)
        assert envelope["delivery"]["salt"] == keys.b64u(salt)

    def test_delivery_includes_manifest_snapshot_when_given(self) -> None:
        manifest = {"issuer": "store.example.com", "manifest_version": 3}
        envelope = issue.issue(make_payload(), _kp(), _KID, manifest_snapshot=manifest)
        assert envelope["delivery"]["issuer_manifest"] == manifest
        assert "salt" not in envelope["delivery"]

    def test_no_delivery_key_when_neither_salt_nor_manifest_given(self) -> None:
        envelope = issue.issue(make_payload(), _kp(), _KID)
        assert "delivery" not in envelope


class TestBuildPayload:
    def _kwargs(self) -> dict[str, object]:
        return {
            "issuer_id": "store.example.com",
            "display_name": "Example Games Store",
            "buyer_identifier": "user@example.com",
            "buyer_identifier_type": "email",
            "buyer_salt": bytes(range(16)),
            "title": "Example Game",
            "publisher": "Example Publisher srl",
            "identifiers": {"issuer_sku": "EXG-001"},
            "artifact_series": "store.example.com/works/EXG-001",
            "terms_uri": "https://store.example.com/attest/license-templates/standard-v1",
            "legal_text_sha256": hashlib.sha256(b"legal-text").hexdigest(),
        }

    def test_produces_schema_valid_payload(self) -> None:
        payload = issue.build_payload(**self._kwargs())  # type: ignore[arg-type]
        assert validate.validate_payload(payload) == []

    def test_receipt_id_is_a_valid_ulid(self) -> None:
        payload = issue.build_payload(**self._kwargs())  # type: ignore[arg-type]
        assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", payload["receipt_id"])

    def test_commitment_is_recomputable_from_identifier_type_and_salt(self) -> None:
        payload = issue.build_payload(**self._kwargs())  # type: ignore[arg-type]
        expected = keys.b64u(commitment.compute("user@example.com", "email", bytes(range(16))))
        assert payload["buyer"]["commitment"] == expected

    def test_build_then_issue_roundtrips(self) -> None:
        payload = issue.build_payload(**self._kwargs())  # type: ignore[arg-type]
        envelope = issue.issue(payload, _kp(), _KID)
        sig = keys.b64u_decode(envelope["signatures"][0]["sig"])
        assert keys.verify_strict(canon.canonical_bytes(payload), sig, _kp().pub)


class TestReceiptHash:
    def test_matches_sha256_of_canonical_bytes(self) -> None:
        payload = make_payload()
        expected = hashlib.sha256(canon.canonical_bytes(payload)).hexdigest()
        assert issue.receipt_hash(payload) == expected

    def test_is_stable_across_key_ordering(self) -> None:
        payload = make_payload()
        reordered = {k: payload[k] for k in reversed(list(payload))}
        assert issue.receipt_hash(payload) == issue.receipt_hash(reordered)


def _chain(levels: int) -> Any:
    """A dict chain of exactly `levels` nesting levels, ending in a scalar."""
    nested: Any = "leaf"
    for _ in range(levels):
        nested = {"n": nested}
    return nested


# An envelope wraps the payload in one more level, so a payload that sits
# exactly ON the ceiling assembles to an envelope one level PAST it. That gap
# is the whole reason the ceiling in the serializer is not enough on its own:
# `issue.issue` canonicalizes the PAYLOAD, never the envelope it returns.


def test_issue_accepts_a_payload_whose_envelope_lands_on_the_ceiling() -> None:
    payload = make_payload()
    payload["_depth_probe"] = _chain(canon.MAX_DEPTH - 2)
    envelope = issue.issue(payload, _kp(), _KID)
    # emittible implies parsable -- the negation of the asymmetry
    assert canon.loads_strict(json.dumps(envelope).encode())


def test_issue_refuses_a_payload_whose_envelope_passes_the_ceiling() -> None:
    payload = make_payload()
    payload["_depth_probe"] = _chain(canon.MAX_DEPTH - 1)
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        issue.issue(payload, _kp(), _KID)


def test_issue_counts_the_manifest_snapshot_towards_the_ceiling() -> None:
    # The payload alone is shallow here: only `delivery.issuer_manifest` pushes
    # the assembled envelope past the ceiling. A guard that looked at the
    # payload would pass this and emit an unparsable receipt.
    deep_manifest = _chain(canon.MAX_DEPTH - 1)
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        issue.issue(make_payload(), _kp(), _KID, manifest_snapshot=deep_manifest)


@pytest.mark.parametrize(
    "levels",
    [
        canon.MAX_DEPTH - 4,
        canon.MAX_DEPTH - 3,
        canon.MAX_DEPTH - 2,
        canon.MAX_DEPTH - 1,
        canon.MAX_DEPTH,
    ],
)
def test_whatever_issue_emits_is_parsable(levels: int) -> None:
    # The asymmetry this closes, walked across the exact boundary: for every
    # payload `issue.issue` accepts, the emitted envelope parses.
    payload = make_payload()
    payload["_depth_probe"] = _chain(levels)
    try:
        envelope = issue.issue(payload, _kp(), _KID)
    except canon.CanonError:
        return
    assert canon.loads_strict(json.dumps(envelope).encode())
