"""Adversarial tests for the v0.2 §19 compromise floor and cutoff inputs.

These cases deliberately use valid signatures around malformed-but-JSON-shaped
manifest data. A signature authenticates its bytes; it must not turn an
ambiguous key lifecycle into a way to resurrect a compromised kid.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from attest import issue, keys, manifests, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/adversarial#ed25519-1"
DECLARER_KID = f"{ISSUER}/keys/adversarial#ed25519-2"

# Fixed test-only seeds.
KP = keys.from_seed(bytes([71]) * 32)
DECLARER_KP = keys.from_seed(bytes([72]) * 32)

VALID_FROM = "2026-01-01T00:00:00Z"


def _wire(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _entry(kid: str, kp: keys.SigningKeyPair, status: str = "active") -> dict[str, Any]:
    return manifests.key_entry(kid, kp.pub, VALID_FROM, None, status)


def _manifest(entries: list[dict[str, Any]], version: object = 1) -> dict[str, Any]:
    return manifests.build_key_manifest(
        ISSUER,
        version,  # type: ignore[arg-type]  # hostile view may not meet the manifest schema
        VALID_FROM,
        entries,
        DECLARER_KP,
        DECLARER_KID,
    )


def _trust(
    manifest: dict[str, Any], *, chain: list[dict[str, Any]] | None = None
) -> verify.TrustStore:
    return verify.TrustStore(
        manifests={ISSUER: manifest},
        provenance={ISSUER: "tls"},
        chains={} if chain is None else {ISSUER: chain},
    )


def _receipt() -> dict[str, Any]:
    return issue.issue(make_payload(), KP, KID)


def test_duplicate_trusted_kid_cannot_hide_compromise_from_status_floor() -> None:
    """v0.1 §7.3: *any* held entry that marks K compromised must win.

    The manifest is self-signed and the first duplicate is active, so an
    implementation that only calls ``find_key`` observes the wrong entry.
    The second, signed entry is still evidence the verifier possesses.
    """
    trusted = _manifest(
        [
            _entry(KID, KP, "active"),
            _entry(KID, KP, "compromised"),
            _entry(DECLARER_KID, DECLARER_KP, "active"),
        ]
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted))

    assert result.signature == "invalid"
    assert any("compromised" in error for error in result.errors)


def test_duplicate_claim_kid_cannot_hide_compromise_from_status_floor() -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    claim = _manifest(
        [
            _entry(KID, KP, "active"),
            _entry(KID, KP, "compromised"),
            _entry(DECLARER_KID, DECLARER_KP),
        ]
    )

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": claim}]
    )

    assert result.signature == "invalid"
    assert any("compromised" in error for error in result.errors)


def test_build_successor_rejects_conflicting_duplicate_for_compromised_kid() -> None:
    """An issuer must not publish a successor that lists a compromised kid
    as anything other than compromised (v0.1 §7.3).

    The final duplicate is compromised, but the first is an active
    resurrection. A last-value map must not make the builder accept it.
    """
    previous = _manifest([_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)])
    successor_entries = [
        _entry(KID, KP, "active"),
        _entry(KID, KP, "compromised"),
        _entry(DECLARER_KID, DECLARER_KP),
    ]

    with pytest.raises(ValueError):
        manifests.build_key_manifest(
            ISSUER,
            2,
            "2026-08-01T00:00:00Z",
            successor_entries,
            DECLARER_KP,
            DECLARER_KID,
            previous=previous,
        )


def test_continuity_rejects_conflicting_duplicate_for_compromised_kid() -> None:
    """Continuity itself must reject the same published ambiguity, even when
    a caller did not use ``build_key_manifest(previous=...)``.
    """
    trusted = _manifest([_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)])
    candidate = _manifest(
        [
            _entry(KID, KP, "active"),
            _entry(KID, KP, "compromised"),
            _entry(DECLARER_KID, DECLARER_KP),
        ],
        version=2,
    )
    candidate["issued_at"] = "2026-08-01T00:00:00Z"
    candidate["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(candidate),
        DECLARER_KP,
        DECLARER_KID,  # type: ignore[attr-defined]
    )

    assert manifests.check_continuity(trusted, candidate) is False


@pytest.mark.parametrize("bad_version", [True, "2", None])
def test_noninteger_claim_manifest_version_cannot_create_compromise_floor(
    bad_version: object,
) -> None:
    """§19.2 requires a v0.1 §7.1 manifest object, whose version is an
    integer. A signed object outside that shape cannot establish item 3a's
    irreversible floor merely because a held key can verify its signature.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    malformed_claim = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)],
        version=bad_version,
    )

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": malformed_claim}]
    )

    assert result.signature == "valid"
    assert "compromise_cutoff_claim_ignored" in result.warnings


@pytest.mark.parametrize(
    "bad_issued_at",
    ["2026-08-01T00:00:00", "2026-08-01T02:00:00+02:00", "2026-08-01T00:00:00.000001Z"],
)
def test_non_utc_z_claim_timestamp_cannot_create_compromise_floor(bad_issued_at: str) -> None:
    """v0.1 §7.1 defines manifest ``issued_at`` as a UTC-Z timestamp.
    A timezone-less, offset, or microsecond spelling cannot become a valid
    §19.3 declaration by being signed.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    malformed_claim = _manifest([_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)])
    malformed_claim["issued_at"] = bad_issued_at
    malformed_claim["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(malformed_claim),
        DECLARER_KP,
        DECLARER_KID,  # type: ignore[attr-defined]
    )

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": malformed_claim}]
    )

    assert result.signature == "valid"
    assert "compromise_cutoff_claim_ignored" in result.warnings


def test_compromise_view_processes_64_nonobject_claims_without_crashing() -> None:
    """§19.2's mandatory 64-claim acceptance floor includes hostile JSON
    members; they must be ignored rather than crash or become declarations.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    hostile_view: list[object] = [None, True, 17, "claim", []] * 12 + [None, {}, [], 0]
    assert len(hostile_view) == 64

    result = verify.verify(
        _wire(_receipt()),
        _trust(trusted),
        compromise_view=hostile_view,  # type: ignore[arg-type]
    )

    assert result.signature == "valid"
    assert "compromise_cutoff_claim_ignored" in result.warnings


def test_oversize_compromise_view_fails_safe_without_changing_valid_receipt() -> None:
    """The §19.2 materialization guard must not let a giant untrusted view
    crash verification or manufacture a compromise declaration.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    oversized = [{"padding": "x" * 10_000_000}]

    result = verify.verify(_wire(_receipt()), _trust(trusted), compromise_view=oversized)

    assert result.signature == "valid"
