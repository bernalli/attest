from __future__ import annotations

import copy
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from attest import anchor, canon, issue, keys, manifests, tlog, verify

RETRACTED = "compromise_marking_retracted"
ISSUER = "store.example"
KID = f"{ISSUER}/keys/2025#ed25519"
ISSUED_AT = "2025-02-01T00:00:00Z"
VALID_FROM = "2025-01-01T00:00:00Z"
VECTORS = Path(__file__).resolve().parents[1] / "docs/spec/vectors/41-compromise-cutoff"
MISSING = object()


def _kp(seed_byte: int) -> keys.SigningKeyPair:
    return keys.from_seed(bytes([seed_byte]) * 32)


SIGNER = _kp(1)
SECOND = _kp(2)


def _entry(
    status: str,
    *,
    kid: str = KID,
    kp: keys.SigningKeyPair = SIGNER,
) -> dict[str, Any]:
    return manifests.key_entry(kid, kp.pub, VALID_FROM, None, status)


def _manifest(
    version: Any,
    entries: list[dict[str, Any]],
    *,
    signing_kp: keys.SigningKeyPair = SIGNER,
    signing_kid: str = KID,
) -> dict[str, Any]:
    signed_version = version if isinstance(version, int) and not isinstance(version, bool) else 1
    # Signed WITHOUT the public builder: since the v0.1 §7.1 amendment
    # (2026-08-26) `build_key_manifest` refuses a duplicated `kid`, and these
    # fixtures are hostile or already-published manifests, not issuance. The
    # body and signature are byte-identical to the builder's output for every
    # manifest the builder still accepts.
    built: dict[str, Any] = {
        "issuer": ISSUER,
        "manifest_version": signed_version,
        "issued_at": ISSUED_AT,
        "keys": entries,
    }
    built["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(built),  # type: ignore[attr-defined]
        signing_kp,
        signing_kid,
    )
    if version is MISSING:
        built.pop("manifest_version", None)
    elif not isinstance(version, int) or isinstance(version, bool) or version != signed_version:
        # `version != signed_version` alone is not enough: in Python `True == 1`,
        # so a bool fixture silently kept the genuine integer the manifest was
        # signed with and stopped testing what it meant to test.
        built["manifest_version"] = version
    return built


def _receipt_bytes(kid: str = KID, kp: keys.SigningKeyPair = SIGNER) -> bytes:
    payload = issue.build_payload(
        issuer_id=ISSUER,
        display_name="Store Example",
        buyer_identifier="buyer@example.net",
        buyer_identifier_type="email",
        buyer_salt=b"\x00" * 16,
        title="Adversarial fixture",
        publisher="Example Publisher",
        identifiers={"sku": "fixture-1"},
        artifact_series="series-1",
        terms_uri="https://store.example/terms",
        legal_text_sha256="a" * 64,
        issued_at=ISSUED_AT,
        receipt_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
    )
    return canon.canonical_bytes(issue.issue(payload, kp, kid))


def _trust_store(
    trusted: dict[str, Any],
    *,
    chain: list[dict[str, Any]] | None = None,
) -> verify.TrustStore:
    return verify.TrustStore(
        manifests={ISSUER: trusted},
        provenance={ISSUER: "tls"},
        chains={ISSUER: chain} if chain is not None else {},
    )


def _run(
    trusted: dict[str, Any],
    *,
    chain: list[dict[str, Any]] | None = None,
    compromise_view: list[dict[str, Any]] | None = None,
    receipt_bytes: bytes | None = None,
) -> verify.VerificationResult:
    return verify.verify(
        receipt_bytes or _receipt_bytes(),
        _trust_store(trusted, chain=chain),
        compromise_view=compromise_view,
    )


def _claim_manifest(
    version: Any,
    entries: list[dict[str, Any]] | None = None,
    *,
    signing_kp: keys.SigningKeyPair = SIGNER,
    signing_kid: str = KID,
) -> dict[str, Any]:
    return _manifest(
        version,
        entries if entries is not None else [_entry("compromised")],
        signing_kp=signing_kp,
        signing_kid=signing_kid,
    )


def _claim(version: Any = 2, entries: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"manifest": _claim_manifest(version, entries), "evidence": None}


def _strip_retracted(result: verify.VerificationResult) -> dict[str, Any]:
    data = asdict(result)
    data["warnings"] = tuple(w for w in data["warnings"] if w != RETRACTED)
    return data


def _assert_retracted_once(result: verify.VerificationResult) -> None:
    assert result.warnings.count(RETRACTED) == 1


def _assert_not_retracted(result: verify.VerificationResult) -> None:
    assert RETRACTED not in result.warnings


def test_chain_source_lower_than_trusted_active_manifest_reports_retraction() -> None:
    trusted = _manifest(3, [_entry("active")])
    source = _manifest(2, [_entry("compromised")])

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    assert result.errors == (f"key {KID} is compromised",)
    _assert_retracted_once(result)


def test_authenticated_declaration_lower_than_trusted_active_manifest_reports_retraction() -> None:
    trusted = _manifest(3, [_entry("active")])

    result = _run(trusted, compromise_view=[_claim(2)])

    assert result.signature == "invalid"
    assert result.errors == (f"key {KID} is compromised",)
    _assert_retracted_once(result)


@pytest.mark.parametrize("trusted_version", [MISSING, "3", 3.0, 3.5, True, False, None])
def test_no_retraction_when_trusted_manifest_version_is_not_an_integer(
    trusted_version: Any,
) -> None:
    trusted = _manifest(trusted_version, [_entry("active")])
    source = _manifest(2, [_entry("compromised")])

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    _assert_not_retracted(result)


def test_no_retraction_when_trusted_manifest_itself_marks_compromised() -> None:
    trusted = _manifest(3, [_entry("active"), _entry("compromised")])
    source = _manifest(2, [_entry("compromised")])

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    _assert_not_retracted(result)


@pytest.mark.parametrize("source_version", [3, 4])
def test_no_retraction_when_marking_source_version_is_equal_or_newer(source_version: int) -> None:
    trusted = _manifest(3, [_entry("active")])
    source = _manifest(source_version, [_entry("compromised")])

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    _assert_not_retracted(result)


def test_pin_stale_newer_source_still_kills_without_retraction_warning() -> None:
    trusted = _manifest(3, [_entry("active")])
    stale_pin = _manifest(4, [_entry("compromised")])

    result = _run(trusted, chain=[stale_pin, trusted])

    assert result.signature == "invalid"
    assert result.errors == (f"key {KID} is compromised",)
    _assert_not_retracted(result)


@given(st.sampled_from([MISSING, "2", 2.0, 2.5, True, False, None]))
def test_no_retraction_when_marking_source_version_is_not_an_integer(source_version: Any) -> None:
    trusted = _manifest(3, [_entry("active")])
    source = _manifest(source_version, [_entry("compromised")])

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    _assert_not_retracted(result)


@pytest.mark.parametrize(
    "trusted_entries",
    [
        [_entry("active"), _entry("compromised")],
        [_entry("compromised"), _entry("active")],
    ],
)
def test_trusted_duplicate_compromised_entry_suppresses_retraction_in_both_orders(
    trusted_entries: list[dict[str, Any]],
) -> None:
    trusted = _manifest(3, trusted_entries)
    source = _manifest(2, [_entry("compromised")])

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    _assert_not_retracted(result)


@pytest.mark.parametrize(
    "source_entries",
    [
        [_entry("active"), _entry("compromised")],
        [_entry("compromised"), _entry("active")],
    ],
)
def test_chain_duplicate_entries_are_all_consulted_in_both_orders(
    source_entries: list[dict[str, Any]],
) -> None:
    trusted = _manifest(3, [_entry("active")])
    source = _manifest(2, source_entries)

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    _assert_retracted_once(result)


@pytest.mark.parametrize(
    "claim_entries",
    [
        [_entry("active"), _entry("compromised")],
        [_entry("compromised"), _entry("active")],
    ],
)
def test_authenticated_declaration_duplicate_entries_are_all_consulted_in_both_orders(
    claim_entries: list[dict[str, Any]],
) -> None:
    trusted = _manifest(3, [_entry("active")])

    result = _run(trusted, compromise_view=[_claim(2, claim_entries)])

    assert result.signature == "invalid"
    _assert_retracted_once(result)


def test_claimed_compromised_material_may_match_second_trusted_entry_for_same_kid() -> None:
    trusted = _manifest(3, [_entry("active", kp=SIGNER), _entry("active", kp=SECOND)])
    claim_entries = [_entry("compromised", kp=SECOND)]

    result = _run(trusted, compromise_view=[_claim(2, claim_entries)])

    assert result.signature == "invalid"
    assert result.errors == (f"key {KID} is compromised",)
    _assert_retracted_once(result)


def test_retraction_warning_is_emitted_once_for_multiple_independent_sources() -> None:
    trusted = _manifest(3, [_entry("active")])
    source_a = _manifest(2, [_entry("compromised")])
    source_b = _manifest(1, [_entry("compromised")])

    result = _run(trusted, chain=[source_a, source_b, trusted], compromise_view=[_claim(2)])

    assert result.signature == "invalid"
    _assert_retracted_once(result)


def test_retraction_warning_does_not_change_rejecting_verdict_fields() -> None:
    trusted = _manifest(3, [_entry("active")])
    lower_source = _manifest(2, [_entry("compromised")])
    equal_source = _manifest(3, [_entry("compromised")])

    with_retraction = _run(trusted, chain=[lower_source, trusted])
    without_retraction = _run(trusted, chain=[equal_source, trusted])

    _assert_retracted_once(with_retraction)
    _assert_not_retracted(without_retraction)
    assert _strip_retracted(with_retraction) == asdict(without_retraction)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_vector_trust_store(case: str, *, trusted_version: int | None = None) -> verify.TrustStore:
    raw = _load_json(VECTORS / case / "manifests.json")
    if trusted_version is not None:
        raw["manifests"]["store.example.com"]["manifest_version"] = trusted_version
    return verify.TrustStore(
        manifests=raw["manifests"],
        provenance=raw["provenance"],
        chains=raw["chains"],
        artifact_manifests=raw.get("artifact_manifests", {}),
        artifact_manifest_chains=raw.get("artifact_manifest_chains", {}),
    )


def _load_log_keys(case: str) -> list[tlog.LogKey]:
    raw = _load_json(VECTORS / case / "log-keys.json")
    return [
        tlog.LogKey(
            origin=item["origin"],
            name=item["name"],
            ed25519_pub=keys.b64u_decode(item["ed25519_pub_b64u"]),
            mldsa_pub=keys.b64u_decode(item["mldsa_pub_b64u"]),
        )
        for item in raw
    ]


def _load_anchor_policy(case: str) -> anchor.AnchorPolicy:
    raw = _load_json(VECTORS / case / "anchor-policy.json")
    return anchor.AnchorPolicy(
        pinned_headers={
            key: anchor.PinnedHeader(
                header_hash=value["header_hash"],
                merkle_root=value["merkle_root"],
                time=value["time"],
            )
            for key, value in raw["pinned_headers"].items()
        },
        crqc_horizon=raw["crqc_horizon"],
    )


def _run_rescue_vector(case: str, *, trusted_version: int) -> verify.VerificationResult:
    return verify.verify(
        (VECTORS / case / "envelope.json").read_bytes(),
        _load_vector_trust_store(case, trusted_version=trusted_version),
        transparency=_load_json(VECTORS / case / "transparency.json"),
        log_keys=_load_log_keys(case),
        anchor_policy=_load_anchor_policy(case),
        compromise_view=copy.deepcopy(_load_json(VECTORS / case / "compromise-view.json")),
    )


def test_retraction_warning_does_not_change_rescuing_verdict_fields() -> None:
    with_retraction = _run_rescue_vector("n-uncompromise-floor-spares-anchored", trusted_version=3)
    without_retraction = _run_rescue_vector(
        "n-uncompromise-floor-spares-anchored", trusted_version=2
    )

    assert with_retraction.signature == "valid"
    assert with_retraction.ok
    _assert_retracted_once(with_retraction)
    _assert_not_retracted(without_retraction)
    assert _strip_retracted(with_retraction) == asdict(without_retraction)


def test_omitted_trusted_kid_never_reaches_the_provenance_rule() -> None:
    other_kid = f"{ISSUER}/keys/other#ed25519"
    other = _kp(9)
    trusted = _manifest(
        3,
        [_entry("active", kid=other_kid, kp=other)],
        signing_kp=other,
        signing_kid=other_kid,
    )
    source = _manifest(2, [_entry("compromised")], signing_kp=other, signing_kid=other_kid)

    result = _run(trusted, chain=[source, trusted])

    assert result.signature == "invalid"
    assert result.errors == (f"no key {KID!r} in issuer manifest",)
    # DIVERGENCE OF READING, raised to review rather than settled here.
    # C1.1 says "a kid the trusted manifest omits entirely satisfies the
    # no-entry condition", which reads as if this case should warn. It cannot
    # under decision D1.3 of the approved plan, which emits the warning "at the
    # point of RESOLUTION": key lookup fails before any status is resolved, so
    # no marking exists whose provenance could be reported. Under that reading
    # the clause is strictly VACUOUS — reaching the predicate at all requires
    # find_key to have returned a trusted entry for the kid, i.e. requires the
    # trusted manifest NOT to omit it. Pinned here as the behavior that follows
    # from D1.3; if review prefers the other reading, the spec sentence and the
    # emission point both move together.
    _assert_not_retracted(result)
