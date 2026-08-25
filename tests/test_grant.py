"""Tests for attest.grant — Stage 4 preservation-pledge primitives (v0.2 §18).

Covers the sunset grant document (§18.2), the cessation declaration (§18.4),
the two DISTINCT coverage predicates (§18.4), the floor-relative non-narrowing
ratchet (§18.3), the structural ceilings (§18.4), and the audience-bound
redemption proof (§18.7). Grant EVALUATION (§18.4's ordered steps, the
`grant`/`grant_trust` result components) is a separate surface and is not
exercised here.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from attest import canon, grant, keys, manifests, pq, verify
from tests.helpers import make_payload

PUBLISHER = "pub.example"
SUCCESSOR = "heritage.example"
OTHER = "marketplace.example"
PUB_KID = f"{PUBLISHER}/keys/grants#1"
SUCCESSOR_KID = f"{SUCCESSOR}/keys/grants#1"
OTHER_KID = f"{OTHER}/keys/grants#1"

VALID_FROM = "2026-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2026-01-01T00:00:00Z"
GRANT_ISSUED_AT = "2026-02-01T00:00:00Z"
DECLARED_AT = "2031-03-01T00:00:00Z"
FIXED_DATE = "2046-01-01T00:00:00Z"

SERIES = "pub.example/works/EXG-001"
ART_A = hashlib.sha256(b"artifact-a").hexdigest()
ART_B = hashlib.sha256(b"artifact-b").hexdigest()
ART_C = hashlib.sha256(b"artifact-c").hexdigest()
# The single artifact hash `tests.helpers.make_payload` puts in `work.artifacts`.
RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()

LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-sunset-grant-prose-v1").hexdigest()
OTHER_LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-sunset-grant-prose-v2").hexdigest()

RECEIPT_ID = "01J1V5B4M9Z8QWERTY12345678"
AUDIENCE = "custodian.example"
NONCE = bytes(range(16))


# --- fixtures ----------------------------------------------------------------


def _hybrid_manifest(issuer: str, kid: str) -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(kid, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    return hk, manifests.build_key_manifest(issuer, 1, MANIFEST_ISSUED_AT, [entry], hk, kid)


def _ed_manifest(issuer: str, kid: str) -> tuple[keys.SigningKeyPair, dict[str, Any]]:
    kp = keys.generate()
    entry = manifests.key_entry(kid, kp.pub, VALID_FROM)
    return kp, manifests.build_key_manifest(issuer, 1, MANIFEST_ISSUED_AT, [entry], kp, kid)


def _scope(
    artifact_series: str | None = SERIES, artifacts: list[str] | None = None
) -> dict[str, Any]:
    return {
        "artifact_series": artifact_series,
        "artifacts": sorted(artifacts if artifacts is not None else [ART_A, ART_B]),
    }


def _activation(
    modes: list[str] | None = None,
    fixed_date: str | None = FIXED_DATE,
    successor_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "modes": sorted(modes if modes is not None else ["fixed-date", "publisher-declaration"]),
        "fixed_date": fixed_date,
        "successor_ids": sorted(successor_ids if successor_ids is not None else [SUCCESSOR]),
    }


def _grant(
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str = PUB_KID,
    **overrides: Any,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "grant_version": 1,
        "publisher": PUBLISHER,
        "scope": _scope(),
        "permissions": ["deliver-to-holder"],
        "activation": _activation(),
        "unprotected_build": True,
        "legal_text_uri": "https://pub.example/sunset-grant-v1",
        "legal_text_sha256": LEGAL_TEXT_SHA256,
        "jurisdiction": "IT",
        "issued_at": GRANT_ISSUED_AT,
    }
    body.update(overrides)
    return grant.build_grant(signing_kp=signing_kp, kid=kid, **body)


def _unsigned_grant(**overrides: Any) -> dict[str, Any]:
    """A grant body plus a placeholder `signature` — for the structural
    predicates (coverage, ratchet) that never touch the signature."""
    kp = keys.generate()
    return _grant(kp, **overrides)


# --- grant document: build, hash, roundtrip (§18.2) --------------------------


def test_grant_has_exactly_the_eleven_members() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp)

    assert set(document) == {
        "grant_version",
        "publisher",
        "scope",
        "permissions",
        "activation",
        "unprotected_build",
        "legal_text_uri",
        "legal_text_sha256",
        "jurisdiction",
        "issued_at",
        "signature",
    }


def test_classical_grant_roundtrips() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp)

    assert "sig_ml_dsa_65" not in document["signature"]
    assert grant.verify_grant(document, key_manifest)


def test_hybrid_grant_roundtrips_with_both_legs() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _grant(hk)

    assert "sig" in document["signature"]
    assert "sig_ml_dsa_65" in document["signature"]
    assert grant.verify_grant(document, key_manifest)


def test_grant_hash_is_over_the_entire_signed_document() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp)

    assert grant.grant_hash(document) == hashlib.sha256(canon.canonical_bytes(document)).hexdigest()
    # Explicitly NOT the body-only hash the signature itself is computed over.
    body = {k: v for k, v in document.items() if k != "signature"}
    assert grant.grant_hash(document) != hashlib.sha256(canon.canonical_bytes(body)).hexdigest()


def test_tampered_grant_body_fails_verification() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp)
    document["jurisdiction"] = "FR"

    assert not grant.verify_grant(document, key_manifest)


def test_grant_is_a_closed_object_unknown_member_rejected() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _grant(hk)
    document["extra"] = "surprise"

    assert not grant.verify_grant(document, key_manifest)


def test_grant_missing_member_rejected() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _grant(hk)
    del document["jurisdiction"]

    assert not grant.verify_grant(document, key_manifest)


def test_classical_only_grant_against_hybrid_key_fails_closed() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _grant(hk)
    del document["signature"]["sig_ml_dsa_65"]

    assert not grant.verify_grant(document, key_manifest)


def test_stray_pq_leg_against_classical_key_fails_closed() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    hk, _ = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp)
    body = {k: v for k, v in document.items() if k != "signature"}
    document["signature"]["sig_ml_dsa_65"] = keys.b64u(
        pq.sign(canon.canonical_bytes(body), hk.mldsa)
    )

    assert not grant.verify_grant(document, key_manifest)


def test_grant_signed_by_retired_key_rejected() -> None:
    kp = keys.generate()
    entry = manifests.key_entry(PUB_KID, kp.pub, VALID_FROM, status="retired")
    signer_entry = manifests.key_entry(f"{PUBLISHER}/keys/grants#2", kp.pub, VALID_FROM)
    key_manifest = manifests.build_key_manifest(
        PUBLISHER,
        1,
        MANIFEST_ISSUED_AT,
        [entry, signer_entry],
        kp,
        f"{PUBLISHER}/keys/grants#2",
    )
    document = _grant(kp)

    assert not grant.verify_grant(document, key_manifest)


def test_grant_issued_outside_key_window_rejected() -> None:
    kp = keys.generate()
    entry = manifests.key_entry(PUB_KID, kp.pub, "2026-03-01T00:00:00Z")
    key_manifest = manifests.build_key_manifest(
        PUBLISHER, 1, "2026-03-01T00:00:00Z", [entry], kp, PUB_KID
    )
    document = _grant(kp)  # issued_at 2026-02-01, before valid_from

    assert not grant.verify_grant(document, key_manifest)


def test_grant_against_self_inconsistent_manifest_rejected() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp)
    key_manifest["issued_at"] = "2026-06-01T00:00:00Z"

    assert not grant.verify_grant(document, key_manifest)
    # ...and the signature-only half, which presumes an already-checked
    # manifest, still accepts it: the two halves are distinct on purpose.
    assert grant.verify_grant_signature(document, key_manifest)


@pytest.mark.parametrize(
    "overrides",
    [
        {"grant_version": 0},
        {"grant_version": True},
        {"publisher": "Pub.Example"},
        {"publisher": "not-a-domain"},
        {"scope": {"artifact_series": None, "artifacts": []}},
        {"scope": {"artifact_series": "", "artifacts": [ART_A]}},
        {"scope": {"artifact_series": SERIES}},
        {"scope": {"artifact_series": SERIES, "artifacts": [ART_B, ART_A]}},
        {"scope": {"artifact_series": SERIES, "artifacts": [ART_A, ART_A]}},
        {"scope": {"artifact_series": SERIES, "artifacts": [ART_A.upper()]}},
        {"permissions": []},
        {"permissions": ["redistribute-among-holders"]},
        {"permissions": ["redistribute-among-holders", "deliver-to-holder"]},
        {"permissions": ["deliver-to-holder", "deliver-to-holder"]},
        {"activation": {"modes": [], "fixed_date": None, "successor_ids": []}},
        {
            "activation": {
                "modes": ["publisher-declaration"],
                "fixed_date": FIXED_DATE,
                "successor_ids": [],
            }
        },
        {
            "activation": {
                "modes": ["publisher-declaration", "fixed-date"],
                "fixed_date": None,
                "successor_ids": [],
            }
        },
        {"activation": {"modes": ["fixed-date"], "fixed_date": "2046-01-01", "successor_ids": []}},
        {
            "activation": {
                "modes": ["fixed-date"],
                "fixed_date": FIXED_DATE,
                "successor_ids": ["B.example", "a.example"],
            }
        },
        {"unprotected_build": "true"},
        {"legal_text_sha256": "not-hex"},
        {"jurisdiction": ""},
        {"issued_at": "2026-02-01"},
    ],
)
def test_malformed_grant_members_fail_closed(overrides: dict[str, Any]) -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp, **overrides)

    assert not grant.verify_grant(document, key_manifest)


@pytest.mark.parametrize(
    "document",
    [None, 42, "grant", [], {}, {"signature": None}],
)
def test_verify_grant_never_raises_on_garbage(document: Any) -> None:
    _, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)

    assert not grant.verify_grant(document, key_manifest)


def test_grant_version_above_the_jcs_integer_ceiling_is_unrepresentable() -> None:
    """`grant_version` is bounded by the attest-JCS safe integer range (§18.2):
    a value above it cannot be canonicalized, so it never becomes a wire
    document — and a hand-built one is refused on shape, without raising."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)

    with pytest.raises(canon.CanonError):
        _grant(kp, grant_version=2**53)

    document = _grant(kp)
    document["grant_version"] = 2**53

    assert not grant.verify_grant(document, key_manifest)


def test_heartbeat_absence_mode_does_not_invalidate_a_grant() -> None:
    """§18.4/§6.9: the reserved mode is never honored, but a grant listing it
    'is not thereby invalid'."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(
        kp,
        activation=_activation(modes=["fixed-date", "heartbeat-absence", "publisher-declaration"]),
    )

    assert grant.verify_grant(document, key_manifest)


# --- cessation declaration (§18.4) -------------------------------------------


def test_declaration_has_exactly_the_four_members() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, PUB_KID)

    assert set(declaration) == {"publisher", "scope", "declared_at", "signature"}


def test_classical_declaration_roundtrips() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, PUB_KID)

    assert grant.verify_declaration(declaration, key_manifest)


def test_hybrid_declaration_roundtrips_with_both_legs() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, hk, PUB_KID)

    assert "sig_ml_dsa_65" in declaration["signature"]
    assert grant.verify_declaration(declaration, key_manifest)


def test_declaration_is_a_closed_object_unknown_member_rejected() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, hk, PUB_KID)
    declaration["reason"] = "bankruptcy"

    assert not grant.verify_declaration(declaration, key_manifest)


def test_classical_only_declaration_against_hybrid_key_fails_closed() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, hk, PUB_KID)
    del declaration["signature"]["sig_ml_dsa_65"]

    assert not grant.verify_declaration(declaration, key_manifest)


def test_declaration_key_window_is_checked_against_declared_at() -> None:
    kp = keys.generate()
    entry = manifests.key_entry(PUB_KID, kp.pub, VALID_FROM, valid_to="2030-01-01T00:00:00Z")
    key_manifest = manifests.build_key_manifest(
        PUBLISHER, 1, MANIFEST_ISSUED_AT, [entry], kp, PUB_KID
    )
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, PUB_KID)

    assert not grant.verify_declaration(declaration, key_manifest)


def test_tampered_declaration_scope_fails_verification() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, PUB_KID)
    declaration["scope"]["artifacts"] = sorted([ART_A, ART_B, ART_C])

    assert not grant.verify_declaration(declaration, key_manifest)


@pytest.mark.parametrize(
    "declaration",
    [None, 42, "declaration", [], {}, {"publisher": PUBLISHER}],
)
def test_verify_declaration_never_raises_on_garbage(declaration: Any) -> None:
    _, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)

    assert not grant.verify_declaration(declaration, key_manifest)


def test_declaration_hash_is_over_the_entire_signed_document() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, PUB_KID)

    assert (
        grant.declaration_hash(declaration)
        == hashlib.sha256(canon.canonical_bytes(declaration)).hexdigest()
    )


# --- who may sign a declaration (§18.4) --------------------------------------


def test_declaration_signed_by_publisher_reports_publisher_role() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _unsigned_grant()
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, PUB_KID)

    assert grant.declaration_signer_role(declaration, document) == grant.SIGNER_ROLE_PUBLISHER


def test_declaration_signed_by_listed_successor_reports_successor_role() -> None:
    kp, _ = _ed_manifest(SUCCESSOR, SUCCESSOR_KID)
    document = _unsigned_grant()
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, SUCCESSOR_KID)

    assert grant.declaration_signer_role(declaration, document) == grant.SIGNER_ROLE_SUCCESSOR


def test_declaration_signed_by_stranger_has_no_role() -> None:
    kp, _ = _ed_manifest(OTHER, OTHER_KID)
    document = _unsigned_grant()
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, OTHER_KID)

    assert grant.declaration_signer_role(declaration, document) is None


def test_declaration_signer_role_uses_the_effective_grants_successor_list() -> None:
    kp, _ = _ed_manifest(SUCCESSOR, SUCCESSOR_KID)
    document = _unsigned_grant(activation=_activation(successor_ids=[]))
    declaration = grant.build_declaration(PUBLISHER, _scope(), DECLARED_AT, kp, SUCCESSOR_KID)

    assert grant.declaration_signer_role(declaration, document) is None


def test_signer_domain_is_the_kid_prefix() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _grant(kp)

    assert grant.signer_domain(document) == PUBLISHER
    assert grant.signer_domain({"signature": {"kid": "nope"}}) is None
    assert grant.signer_domain({}) is None
    assert grant.signer_domain(None) is None


# --- declaration coverage of a grant (§18.4) ---------------------------------


def test_declaration_covers_grant_when_publisher_series_and_artifacts_match() -> None:
    document = _unsigned_grant()
    declaration = {
        "publisher": PUBLISHER,
        "scope": _scope(),
        "declared_at": DECLARED_AT,
        "signature": {"kid": PUB_KID},
    }

    assert grant.declaration_covers_grant(declaration, document)


def test_declaration_with_superset_artifacts_covers_grant() -> None:
    document = _unsigned_grant()
    declaration = {
        "publisher": PUBLISHER,
        "scope": _scope(artifacts=[ART_A, ART_B, ART_C]),
        "declared_at": DECLARED_AT,
        "signature": {"kid": PUB_KID},
    }

    assert grant.declaration_covers_grant(declaration, document)


def test_declaration_with_subset_artifacts_does_not_cover_grant() -> None:
    document = _unsigned_grant()
    declaration = {
        "publisher": PUBLISHER,
        "scope": _scope(artifacts=[ART_A]),
        "declared_at": DECLARED_AT,
        "signature": {"kid": PUB_KID},
    }

    assert not grant.declaration_covers_grant(declaration, document)


def test_declaration_coverage_requires_equal_series() -> None:
    document = _unsigned_grant()
    declaration = {
        "publisher": PUBLISHER,
        "scope": _scope(artifact_series="pub.example/works/OTHER"),
        "declared_at": DECLARED_AT,
        "signature": {"kid": PUB_KID},
    }

    assert not grant.declaration_covers_grant(declaration, document)


def test_declaration_coverage_treats_both_null_series_as_equal() -> None:
    document = _unsigned_grant(scope=_scope(artifact_series=None))
    declaration = {
        "publisher": PUBLISHER,
        "scope": _scope(artifact_series=None),
        "declared_at": DECLARED_AT,
        "signature": {"kid": PUB_KID},
    }

    assert grant.declaration_covers_grant(declaration, document)


def test_declaration_coverage_rejects_one_null_one_set_series() -> None:
    document = _unsigned_grant(scope=_scope(artifact_series=None))
    declaration = {
        "publisher": PUBLISHER,
        "scope": _scope(artifact_series=SERIES),
        "declared_at": DECLARED_AT,
        "signature": {"kid": PUB_KID},
    }

    assert not grant.declaration_covers_grant(declaration, document)


def test_declaration_coverage_requires_equal_publisher() -> None:
    document = _unsigned_grant()
    declaration = {
        "publisher": OTHER,
        "scope": _scope(),
        "declared_at": DECLARED_AT,
        "signature": {"kid": PUB_KID},
    }

    assert not grant.declaration_covers_grant(declaration, document)


@pytest.mark.parametrize("declaration", [None, 42, {}, {"publisher": PUBLISHER}])
def test_declaration_coverage_fails_closed_on_garbage(declaration: Any) -> None:
    assert not grant.declaration_covers_grant(declaration, _unsigned_grant())


# --- grant coverage of a receipt (§18.4) -------------------------------------
#
# A DIFFERENT predicate from the one above, and deliberately not implemented in
# terms of it: series equality is a SUFFICIENT clause here, never a conjunct.


def test_grant_covers_receipt_by_series_alone() -> None:
    payload = make_payload(work={"artifact_series": SERIES})
    document = _unsigned_grant(scope=_scope(artifact_series=SERIES, artifacts=[ART_A]))

    assert grant.grant_covers_receipt(document, payload)


def test_grant_covers_receipt_by_artifact_hashes_alone() -> None:
    """§18.4: a hash-scoped grant (`artifact_series: null`) covers a receipt
    that names exactly those artifacts EVEN IF the receipt also carries a
    series the grant does not name."""
    payload = make_payload()  # carries both a series and one artifact
    document = _unsigned_grant(scope=_scope(artifact_series=None, artifacts=[RECEIPT_ART, ART_A]))

    assert grant.grant_covers_receipt(document, payload)


def test_grant_covering_a_broader_catalogue_still_covers_this_receipt() -> None:
    payload = make_payload()
    document = _unsigned_grant(
        scope=_scope(artifact_series=SERIES, artifacts=[RECEIPT_ART, ART_A, ART_B])
    )

    assert grant.grant_covers_receipt(document, payload)


def test_series_only_receipt_is_uncovered_when_the_series_differs() -> None:
    payload = make_payload()
    del payload["work"]["artifacts"]
    document = _unsigned_grant(
        scope=_scope(artifact_series="pub.example/works/OTHER", artifacts=[RECEIPT_ART])
    )

    assert not grant.grant_covers_receipt(document, payload)


def test_receipt_without_artifacts_is_not_covered_by_a_hash_scoped_grant() -> None:
    """The second clause is not a bare universal quantifier: over an ABSENT
    artifact list it would be vacuously true and every grant would cover every
    series-only receipt (§18.4)."""
    payload = make_payload()
    del payload["work"]["artifacts"]
    document = _unsigned_grant(scope=_scope(artifact_series=None, artifacts=[ART_A, ART_B]))

    assert not grant.grant_covers_receipt(document, payload)


def test_receipt_with_empty_artifact_list_is_not_covered_by_a_hash_scoped_grant() -> None:
    payload = make_payload()
    payload["work"]["artifacts"] = []
    document = _unsigned_grant(scope=_scope(artifact_series=None, artifacts=[ART_A, ART_B]))

    assert not grant.grant_covers_receipt(document, payload)


def test_receipt_without_artifacts_is_still_covered_by_a_matching_series() -> None:
    payload = make_payload(work={"artifact_series": SERIES})
    del payload["work"]["artifacts"]
    document = _unsigned_grant(scope=_scope(artifact_series=SERIES, artifacts=[ART_A]))

    assert grant.grant_covers_receipt(document, payload)


def test_receipt_with_empty_artifact_list_is_still_covered_by_a_matching_series() -> None:
    payload = make_payload(work={"artifact_series": SERIES})
    payload["work"]["artifacts"] = []
    document = _unsigned_grant(scope=_scope(artifact_series=SERIES, artifacts=[ART_A]))

    assert grant.grant_covers_receipt(document, payload)


def test_grant_with_null_series_does_not_match_a_receipt_missing_the_series() -> None:
    payload = make_payload()
    del payload["work"]["artifact_series"]
    del payload["work"]["artifacts"]
    document = _unsigned_grant(scope=_scope(artifact_series=None, artifacts=[ART_A]))

    assert not grant.grant_covers_receipt(document, payload)


def test_receipt_with_one_unlisted_artifact_is_uncovered() -> None:
    payload = make_payload()
    payload["work"]["artifacts"] = [
        dict(payload["work"]["artifacts"][0], sha256=RECEIPT_ART),
        dict(payload["work"]["artifacts"][0], sha256=ART_C, filename="extra.bin"),
    ]
    document = _unsigned_grant(scope=_scope(artifact_series=None, artifacts=[RECEIPT_ART]))

    assert not grant.grant_covers_receipt(document, payload)


@pytest.mark.parametrize("payload", [None, 42, {}, {"work": None}, {"work": {"artifacts": 3}}])
def test_grant_coverage_of_receipt_fails_closed_on_garbage(payload: Any) -> None:
    assert not grant.grant_covers_receipt(_unsigned_grant(), payload)


def test_grant_coverage_fails_closed_on_a_malformed_artifact_entry() -> None:
    payload = make_payload()
    payload["work"]["artifacts"] = [{"role": "installer"}]
    document = _unsigned_grant(scope=_scope(artifact_series=None, artifacts=[RECEIPT_ART]))

    assert not grant.grant_covers_receipt(document, payload)


# --- the non-narrowing ratchet (§18.3) ---------------------------------------


def test_identical_later_version_is_non_narrowing() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2)

    assert grant.is_non_narrowing(floor, later)


def test_permissions_superset_is_non_narrowing() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(
        grant_version=2, permissions=["deliver-to-holder", "redistribute-among-holders"]
    )

    assert grant.is_non_narrowing(floor, later)


def test_permissions_subset_narrows() -> None:
    floor = _unsigned_grant(permissions=["deliver-to-holder", "redistribute-among-holders"])
    later = _unsigned_grant(grant_version=2, permissions=["deliver-to-holder"])

    assert not grant.is_non_narrowing(floor, later)


def test_series_newly_set_from_null_is_non_narrowing() -> None:
    floor = _unsigned_grant(scope=_scope(artifact_series=None))
    later = _unsigned_grant(grant_version=2, scope=_scope(artifact_series=SERIES))

    assert grant.is_non_narrowing(floor, later)


def test_series_changed_to_another_value_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(
        grant_version=2, scope=_scope(artifact_series="pub.example/works/OTHER")
    )

    assert not grant.is_non_narrowing(floor, later)


def test_series_dropped_to_null_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2, scope=_scope(artifact_series=None))

    assert not grant.is_non_narrowing(floor, later)


def test_artifacts_superset_is_non_narrowing() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2, scope=_scope(artifacts=[ART_A, ART_B, ART_C]))

    assert grant.is_non_narrowing(floor, later)


def test_artifacts_subset_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2, scope=_scope(artifacts=[ART_A]))

    assert not grant.is_non_narrowing(floor, later)


def test_unprotected_build_false_to_true_is_non_narrowing() -> None:
    floor = _unsigned_grant(unprotected_build=False)
    later = _unsigned_grant(grant_version=2, unprotected_build=True)

    assert grant.is_non_narrowing(floor, later)


def test_unprotected_build_true_to_false_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2, unprotected_build=False)

    assert not grant.is_non_narrowing(floor, later)


def test_modes_superset_is_non_narrowing() -> None:
    floor = _unsigned_grant(
        activation=_activation(modes=["publisher-declaration"], fixed_date=None)
    )
    later = _unsigned_grant(
        grant_version=2,
        activation=_activation(modes=["fixed-date", "publisher-declaration"], fixed_date=None),
    )

    assert grant.is_non_narrowing(floor, later)


def test_dropping_a_mode_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2, activation=_activation(modes=["fixed-date"]))

    assert not grant.is_non_narrowing(floor, later)


def test_fixed_date_pulled_earlier_is_non_narrowing() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(
        grant_version=2, activation=_activation(fixed_date="2040-01-01T00:00:00Z")
    )

    assert grant.is_non_narrowing(floor, later)


def test_fixed_date_pushed_out_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(
        grant_version=2, activation=_activation(fixed_date="2050-01-01T00:00:00Z")
    )

    assert not grant.is_non_narrowing(floor, later)


def test_fixed_date_newly_set_from_null_is_non_narrowing() -> None:
    floor = _unsigned_grant(
        activation=_activation(modes=["publisher-declaration"], fixed_date=None)
    )
    later = _unsigned_grant(
        grant_version=2,
        activation=_activation(
            modes=["fixed-date", "publisher-declaration"], fixed_date=FIXED_DATE
        ),
    )

    assert grant.is_non_narrowing(floor, later)


def test_fixed_date_removed_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2, activation=_activation(fixed_date=None))

    assert not grant.is_non_narrowing(floor, later)


def test_successor_ids_superset_is_non_narrowing() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(
        grant_version=2, activation=_activation(successor_ids=["archive.example", SUCCESSOR])
    )

    assert grant.is_non_narrowing(floor, later)


def test_removing_a_successor_narrows() -> None:
    floor = _unsigned_grant()
    later = _unsigned_grant(grant_version=2, activation=_activation(successor_ids=[]))

    assert not grant.is_non_narrowing(floor, later)


def test_prose_members_are_outside_the_ratchet() -> None:
    """§18.3: `legal_text_uri`, `legal_text_sha256` and `jurisdiction` are
    deliberately absent from the structural test — a verifier cannot read
    prose. The divergence is reported elsewhere, never treated as narrowing."""
    floor = _unsigned_grant()
    later = _unsigned_grant(
        grant_version=2,
        legal_text_uri="https://pub.example/sunset-grant-v2",
        legal_text_sha256=OTHER_LEGAL_TEXT_SHA256,
        jurisdiction="FR",
    )

    assert grant.is_non_narrowing(floor, later)


def test_prose_divergence_is_detected_separately() -> None:
    floor = _unsigned_grant()
    same = _unsigned_grant(grant_version=2)
    changed_uri = _unsigned_grant(
        grant_version=2, legal_text_uri="https://pub.example/sunset-grant-v2"
    )
    changed_hash = _unsigned_grant(grant_version=2, legal_text_sha256=OTHER_LEGAL_TEXT_SHA256)
    changed_jurisdiction = _unsigned_grant(grant_version=2, jurisdiction="FR")

    assert not grant.prose_differs(floor, same)
    assert grant.prose_differs(floor, changed_uri)
    assert grant.prose_differs(floor, changed_hash)
    assert grant.prose_differs(floor, changed_jurisdiction)


@pytest.mark.parametrize("later", [None, 42, {}, {"scope": None}])
def test_ratchet_fails_closed_on_garbage(later: Any) -> None:
    assert not grant.is_non_narrowing(_unsigned_grant(), later)


# --- structural ceilings (§18.4) ---------------------------------------------


def test_ceilings_are_sixty_four_each() -> None:
    assert grant._MAX_GRANT_LATER_VERSIONS == 64
    assert grant._MAX_GRANT_DECLARATIONS == 64


def test_ceilings_accept_exactly_the_maximum() -> None:
    assert grant.within_structural_ceilings(
        [object()] * grant._MAX_GRANT_LATER_VERSIONS,
        [object()] * grant._MAX_GRANT_DECLARATIONS,
    )


def test_one_later_version_over_the_ceiling_is_rejected() -> None:
    assert not grant.within_structural_ceilings(
        [object()] * (grant._MAX_GRANT_LATER_VERSIONS + 1), []
    )


def test_one_declaration_over_the_ceiling_is_rejected() -> None:
    assert not grant.within_structural_ceilings(
        [], [object()] * (grant._MAX_GRANT_DECLARATIONS + 1)
    )


def test_ceiling_check_counts_and_never_inspects_an_element() -> None:
    """§18.4: 'the ceiling check MUST run BEFORE any signature is verified, or
    it is not a ceiling'. The predicate judges COUNT only — elements that would
    raise on any inspection pass at the ceiling and are refused one past it,
    without ever being touched."""

    class Hostile:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"ceiling check inspected element attribute {name!r}")

        def __eq__(self, other: object) -> bool:
            raise AssertionError("ceiling check compared an element")

        def __hash__(self) -> int:
            raise AssertionError("ceiling check hashed an element")

    assert grant.within_structural_ceilings([Hostile()] * 64, [Hostile()] * 64)
    assert not grant.within_structural_ceilings([Hostile()] * 65, [])
    assert not grant.within_structural_ceilings([], [Hostile()] * 65)


def test_ceilings_accept_absent_evidence() -> None:
    assert grant.within_structural_ceilings(None, None)


@pytest.mark.parametrize("later_grants", [42, "grants", {"a": 1}])
def test_ceilings_fail_closed_on_a_non_sequence(later_grants: Any) -> None:
    assert not grant.within_structural_ceilings(later_grants, [])


# --- redemption (§18.7) ------------------------------------------------------


def test_redemption_preimage_is_byte_exact() -> None:
    expected = (
        b"Attest-redemption-challenge-v1"
        + b"\x00"
        + RECEIPT_ID.encode()
        + b"\x00"
        + AUDIENCE.encode()
        + b"\x00"
        + NONCE
    )

    assert grant.redemption_message(RECEIPT_ID, AUDIENCE, NONCE) == expected


def test_redemption_label_is_the_registered_literal() -> None:
    assert grant.LABEL_REDEMPTION_CHALLENGE == b"Attest-redemption-challenge-v1"


def test_redemption_roundtrips() -> None:
    kp = keys.generate()
    sig = grant.sign_redemption(RECEIPT_ID, AUDIENCE, NONCE, kp)

    assert grant.verify_redemption(RECEIPT_ID, AUDIENCE, NONCE, sig, keys.b64u(kp.pub))


def test_redemption_response_is_not_replayable_at_another_custodian() -> None:
    kp = keys.generate()
    sig = grant.sign_redemption(RECEIPT_ID, AUDIENCE, NONCE, kp)

    assert not grant.verify_redemption(
        RECEIPT_ID, "other-custodian.example", NONCE, sig, keys.b64u(kp.pub)
    )


def test_redemption_response_is_bound_to_its_receipt_and_nonce() -> None:
    kp = keys.generate()
    sig = grant.sign_redemption(RECEIPT_ID, AUDIENCE, NONCE, kp)

    assert not grant.verify_redemption(
        "01ARZ3NDEKTSV4RRFFQ69G5FAV", AUDIENCE, NONCE, sig, keys.b64u(kp.pub)
    )
    assert not grant.verify_redemption(
        RECEIPT_ID, AUDIENCE, bytes(range(1, 17)), sig, keys.b64u(kp.pub)
    )


def test_redemption_rejects_another_holders_key() -> None:
    kp = keys.generate()
    other = keys.generate()
    sig = grant.sign_redemption(RECEIPT_ID, AUDIENCE, NONCE, kp)

    assert not grant.verify_redemption(RECEIPT_ID, AUDIENCE, NONCE, sig, keys.b64u(other.pub))


def test_redemption_nonce_below_sixteen_bytes_is_refused() -> None:
    kp = keys.generate()

    with pytest.raises(ValueError, match="nonce"):
        grant.redemption_message(RECEIPT_ID, AUDIENCE, bytes(15))
    with pytest.raises(ValueError, match="nonce"):
        grant.sign_redemption(RECEIPT_ID, AUDIENCE, bytes(15), kp)


@pytest.mark.parametrize(
    ("nonce", "sig", "pubkey"),
    [
        (bytes(15), bytes(64), None),
        (NONCE, b"short", None),
        (NONCE, bytes(64), "not-base64url!!"),
        (NONCE, bytes(64), ""),
    ],
)
def test_verify_redemption_fails_closed_and_never_raises(
    nonce: bytes, sig: bytes, pubkey: str | None
) -> None:
    kp = keys.generate()
    holder_pubkey = keys.b64u(kp.pub) if pubkey is None else pubkey

    assert not grant.verify_redemption(RECEIPT_ID, AUDIENCE, nonce, sig, holder_pubkey)


# --- registered vocabulary the verifier recognizes (§6.7, §6.10) -------------


def test_sunset_grant_is_a_recognized_end_of_life_value() -> None:
    """attest-versioning.md §6.7 registers `sunset-grant` as `active`: it is
    the label a Stage 4 receipt carries, so it must stop being reported as an
    unknown value. The vocabulary stays OPEN — registering a value assigns it
    meaning, it does not close the field."""
    assert grant.END_OF_LIFE_SUNSET_GRANT in verify._KNOWN_EOL_VALUES

    payload = make_payload(survivability={"end_of_life": grant.END_OF_LIFE_SUNSET_GRANT})

    assert not any("end_of_life" in w for w in verify._content_warnings(payload))


def test_an_unregistered_end_of_life_value_is_still_reported() -> None:
    payload = make_payload(survivability={"end_of_life": "vanished"})

    assert any("end_of_life" in w for w in verify._content_warnings(payload))


def test_sunset_grant_v1_is_the_only_recognized_pledge_profile() -> None:
    """§18.2/§6.10: `sunset-grant-v1` is the sole profile this revision
    defines. An unrecognized profile is valid-with-warning and is NEVER
    evaluated under `sunset-grant-v1`'s rules — a later profile may attach
    different meaning to the same members, and guessing is how two conforming
    implementations reach different verdicts on identical input."""
    assert verify._KNOWN_PLEDGE_TYPES == frozenset({grant.PLEDGE_SUNSET_GRANT_V1})
    assert grant.PLEDGE_SUNSET_GRANT_V1 == "sunset-grant-v1"


def test_salt_disclosure_is_not_a_redemption_primitive() -> None:
    """§18.7 prohibits salt disclosure as a redemption proof, normatively. This
    module offers no way to spell one: the only proof it verifies is the
    audience-bound Ed25519 signature."""
    assert not hasattr(grant, "verify_salt_disclosure")
    assert not any("salt" in name for name in dir(grant))
