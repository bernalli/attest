"""Tests for `attest.verify.evaluate_publisher_authority`.

The primitive tests in `tests/test_authority.py` cover document shape,
authentication and membership one at a time. This file covers the ordered
evaluation of section 20.4: which evidence is admitted, which document becomes
effective, and which informational result is reported.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from attest import authority, keys, manifests, pq, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
PUBLISHER = "pub.example"
OTHER = "marketplace.example"

ISSUER_KID = f"{ISSUER}/keys/authority#1"
PUB_KID = f"{PUBLISHER}/keys/authority#1"
OTHER_KID = f"{OTHER}/keys/authority#1"

VALID_FROM = "2026-01-01T00:00:00Z"
AUTH_ISSUED_AT = "2026-02-01T00:00:00Z"
LATER_ISSUED_AT = "2026-09-01T00:00:00Z"
THIRD_ISSUED_AT = "2026-10-01T00:00:00Z"
ENTRY_FROM = "2026-01-01T00:00:00Z"
RECEIPT_ISSUED_AT = "2026-07-02T14:30:00Z"
RECEIPT_SERIES = "store.example.com/works/EXG-001"
RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
OTHER_ART = hashlib.sha256(b"artifact-elsewhere").hexdigest()


def _hybrid_manifest(
    issuer: str, kid: str, version: int = 1
) -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(kid, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    return hk, manifests.build_key_manifest(issuer, version, VALID_FROM, [entry], hk, kid)


PUBLISHER_KEYS, PUBLISHER_MANIFEST = _hybrid_manifest(PUBLISHER, PUB_KID)
ISSUER_KEYS, ISSUER_MANIFEST = _hybrid_manifest(ISSUER, ISSUER_KID)
OTHER_KEYS, OTHER_MANIFEST = _hybrid_manifest(OTHER, OTHER_KID)

_ABSENT = object()
_DEFAULT = object()


def _scope(
    artifact_series: str | None = RECEIPT_SERIES, artifacts: list[str] | None = None
) -> dict[str, Any]:
    return {
        "artifact_series": artifact_series,
        "artifacts": sorted(artifacts if artifacts is not None else [RECEIPT_ART]),
    }


def _entry(
    issuer_id: Any = ISSUER,
    valid_from: Any = ENTRY_FROM,
    valid_to: Any = None,
    permissions: Any = _DEFAULT,
    scope: Any = None,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "permissions": [authority.PERMISSION_ISSUE] if permissions is _DEFAULT else permissions,
        "scope": scope,
    }


def _authorization(
    signing_keys: keys.SigningKeyPair | pq.HybridSigningKeys = PUBLISHER_KEYS,
    kid: str = PUB_KID,
    *,
    version: int = 1,
    publisher: str = PUBLISHER,
    entries: list[dict[str, Any]] | None = None,
    issued_at: str = AUTH_ISSUED_AT,
) -> dict[str, Any]:
    return authority.build_authorization(
        authorization_version=version,
        publisher=publisher,
        authorized_issuers=[_entry()] if entries is None else entries,
        issued_at=issued_at,
        signing_kp=signing_keys,
        kid=kid,
    )


def _payload(
    *,
    publisher_id: Any = PUBLISHER,
    issuer_id: Any = ISSUER,
    issued_at: str = RECEIPT_ISSUED_AT,
) -> dict[str, Any]:
    overrides: dict[str, Any] = {"attest_version": "0.2", "issued_at": issued_at}
    if publisher_id is not _ABSENT:
        overrides["work"] = {"publisher_id": publisher_id}
    if issuer_id is not _ABSENT:
        overrides["issuer"] = {"id": issuer_id}
    return make_payload(**overrides)


def _store(
    *,
    publisher_manifest: dict[str, Any] = PUBLISHER_MANIFEST,
    publisher_provenance: str = "tls",
    extra_manifests: dict[str, dict[str, Any]] | None = None,
    chains: dict[str, list[dict[str, Any]]] | None = None,
) -> verify.TrustStore:
    resolved = {
        PUBLISHER: publisher_manifest,
        ISSUER: ISSUER_MANIFEST,
        OTHER: OTHER_MANIFEST,
    }
    resolved.update(extra_manifests or {})
    provenance = {PUBLISHER: publisher_provenance, ISSUER: "tls", OTHER: "tls"}
    return verify.TrustStore(manifests=resolved, provenance=provenance, chains=chains or {})


def _view(*documents: dict[str, Any], current: Any = _ABSENT) -> dict[str, Any]:
    view: dict[str, Any] = {"authorizations": list(documents)}
    if current is not _ABSENT:
        view["current_authorization_version"] = current
    return view


def _evaluate(
    *,
    payload: dict[str, Any] | None = None,
    view: dict[str, Any] | None | object = _ABSENT,
    trust_store: verify.TrustStore | None = None,
) -> Any:
    return verify.evaluate_publisher_authority(
        _payload() if payload is None else payload,
        _store() if trust_store is None else trust_store,
        _view(_authorization()) if view is _ABSENT else view,  # type: ignore[arg-type]
    )


def _assert_verdict(
    verdict: Any, authority_value: str, trust_value: str, warnings: tuple[str, ...] = ()
) -> None:
    assert verdict.publisher_authority == authority_value
    assert verdict.publisher_authority_trust == trust_value
    assert verdict.warnings == warnings


# --- group 43 table ----------------------------------------------------------


def test_43a_authorized() -> None:
    verdict = _evaluate()

    _assert_verdict(verdict, "authorized", "verified")


def test_43b_unauthorized_empty_list() -> None:
    document = _authorization(entries=[])

    verdict = _evaluate(view=_view(document, current=1))

    _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


def test_43c_no_view_not_checked() -> None:
    verdict = _evaluate(view=None)

    _assert_verdict(verdict, "not_checked", "not_checked")


def test_43d_empty_view_unattested() -> None:
    verdict = _evaluate(view={})

    _assert_verdict(verdict, "unattested", "not_checked")


def test_43e_forged_ignored() -> None:
    document = _authorization(ISSUER_KEYS, kid=PUB_KID)

    verdict = _evaluate(view=_view(document))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


def test_43f_signer_mismatch() -> None:
    document = _authorization(ISSUER_KEYS, kid=ISSUER_KID, publisher=PUBLISHER)

    verdict = _evaluate(view=_view(document))

    _assert_verdict(
        verdict,
        "unattested",
        "signer_mismatch",
        ("authorization_signer_not_publisher",),
    )


def test_43g_window_expired_unauthorized() -> None:
    document = _authorization(entries=[_entry(valid_to="2026-06-01T00:00:00Z")])

    verdict = _evaluate(view=_view(document, current=1))

    _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


def test_43h_prospective_not_retroactive() -> None:
    document = _authorization(entries=[_entry(valid_to="2026-06-01T00:00:00Z")])
    payload = _payload(issued_at="2026-05-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(document, current=1))

    _assert_verdict(verdict, "authorized", "verified")


def test_43i_equivocation() -> None:
    first = _authorization(entries=[_entry()])
    second = _authorization(entries=[])

    verdict = _evaluate(view=_view(first, second, current=1))

    _assert_verdict(verdict, "unattested", "unverified_rotation")


def test_43j_rollback_max_wins() -> None:
    first = _authorization()
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-06-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )

    verdict = _evaluate(view=_view(first, second, current=2))

    _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


def test_43k_scope_uncovered() -> None:
    document = _authorization(
        entries=[_entry(scope=_scope(artifact_series=None, artifacts=[OTHER_ART]))]
    )

    verdict = _evaluate(view=_view(document, current=1))

    _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


def test_43l_permission_missing() -> None:
    document = _authorization(entries=[_entry(permissions=[authority.PERMISSION_DELEGATE])])

    verdict = _evaluate(view=_view(document, current=1))

    _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


def test_43m_self_publisher() -> None:
    payload = _payload(publisher_id=ISSUER, issuer_id=ISSUER)

    verdict = _evaluate(payload=payload)

    _assert_verdict(verdict, "self", "not_checked")


def test_43n_no_claim() -> None:
    payload = _payload(publisher_id=_ABSENT)

    verdict = _evaluate(payload=payload)

    _assert_verdict(verdict, "no_publisher_claim", "not_checked")


def test_43o_tofu_authorized() -> None:
    verdict = _evaluate(trust_store=_store(publisher_provenance="bundle"))

    _assert_verdict(verdict, "authorized", "unauthenticated_tofu")


def test_43p_view_ceiling() -> None:
    documents = [_authorization() for _ in range(authority.MAX_AUTHORITY_DOCUMENTS + 1)]

    verdict = _evaluate(view=_view(*documents))

    _assert_verdict(verdict, "unattested", "not_checked")


def test_43q_classical_only_rejected() -> None:
    ed_keys = keys.generate()
    hybrid = pq.HybridSigningKeys(ed=ed_keys, mldsa=pq.generate())
    entry = manifests.key_entry(PUB_KID, ed_keys.pub, VALID_FROM, pub_ml_dsa_65=hybrid.mldsa.pub)
    hybrid_manifest = manifests.build_key_manifest(
        PUBLISHER, 1, VALID_FROM, [entry], hybrid, PUB_KID
    )
    document = _authorization(ed_keys, kid=PUB_KID)

    verdict = _evaluate(
        view=_view(document), trust_store=_store(publisher_manifest=hybrid_manifest)
    )

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


def test_43r_denial_without_currency() -> None:
    document = _authorization(entries=[])

    verdict = _evaluate(view=_view(document))

    _assert_verdict(verdict, "unattested", "verified")


def test_43s_stale_behind_assertion() -> None:
    document = _authorization(entries=[])

    verdict = _evaluate(view=_view(document, current=2))

    _assert_verdict(verdict, "unattested", "verified")


def test_43t_deauth_window_past_receipt() -> None:
    first = _authorization()
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-06-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )
    payload = _payload(issued_at="2026-05-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "verified")


def test_43u_entry_removal_nonconforming() -> None:
    first = _authorization()
    second = _authorization(version=2, entries=[], issued_at=LATER_ISSUED_AT)

    verdict = _evaluate(view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "unverified_rotation")


def test_43v_backdated_closure_nonconforming() -> None:
    first = _authorization()
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-01-15T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )

    verdict = _evaluate(view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "unverified_rotation")


def test_43w_postdated_closure_nonconforming() -> None:
    first = _authorization()
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-09-01T00:00:01Z")],
        issued_at=LATER_ISSUED_AT,
    )

    verdict = _evaluate(view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "unverified_rotation")


def test_43x_early_revocation_live_term_window() -> None:
    first = _authorization(entries=[_entry(valid_to="2026-12-01T00:00:00Z")])
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-06-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )

    verdict = _evaluate(view=_view(first, second, current=2))

    _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


def test_43y_extension_live_window_conforming() -> None:
    first = _authorization(entries=[_entry(valid_to="2026-09-15T00:00:00Z")])
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-12-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )
    payload = _payload(issued_at="2026-10-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "verified")


# --- caller contract and evidence failures -----------------------------------


@pytest.mark.parametrize("bad", [[], "authority", 42, ({},)])
def test_authority_view_that_is_not_an_evidence_object_fails_loud(bad: Any) -> None:
    with pytest.raises(TypeError):
        _evaluate(view=bad)  # type: ignore[arg-type]


def test_authorizations_member_that_is_not_an_array_is_unattested() -> None:
    verdict = _evaluate(view={"authorizations": "x"})

    _assert_verdict(verdict, "unattested", "not_checked")


def test_verified_publisher_trust_is_not_reset_when_every_document_fails() -> None:
    document = _authorization(ISSUER_KEYS, kid=PUB_KID)

    verdict = _evaluate(view=_view(document))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


def test_byte_identical_duplicate_is_not_equivocation() -> None:
    document = _authorization()

    verdict = _evaluate(view=_view(document, document))

    _assert_verdict(verdict, "authorized", "verified")


def test_authorization_invalid_ignored_is_emitted_once() -> None:
    bad_one = _authorization(ISSUER_KEYS, kid=PUB_KID)
    bad_two = _authorization(OTHER_KEYS, kid=PUB_KID)

    verdict = _evaluate(view=_view(bad_one, bad_two))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


def test_issuer_id_that_is_not_a_string_is_unattested() -> None:
    verdict = _evaluate(payload=_payload(issuer_id=42))

    _assert_verdict(verdict, "unattested", "not_checked")


@pytest.mark.parametrize("assertion", [True, False, 0, 2**53, "1"])
def test_malformed_current_authorization_version_is_absent(assertion: Any) -> None:
    document = _authorization(entries=[])

    verdict = _evaluate(view=_view(document, current=assertion))

    _assert_verdict(verdict, "unattested", "verified")


@pytest.mark.parametrize("assertion", [2, 4096, 2**53 - 1])
def test_currency_assertion_does_not_gate_the_positive(assertion: int) -> None:
    document = _authorization()

    verdict = _evaluate(view=_view(document, current=assertion))

    _assert_verdict(verdict, "authorized", "verified")


def test_noncanonicalizable_document_hash_failure_is_inside_the_evaluator_boundary() -> None:
    document = _authorization()
    document["authorization_version"] = 2**53

    verdict = _evaluate(view=_view(document))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


def test_malformed_temporal_content_never_reaches_shared_window_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(_valid_to: str | None, _instant: str) -> bool:
        raise AssertionError("window helper reached a non-admitted document")

    monkeypatch.setattr(authority, "window_spent_at", fail_if_called)
    document = _authorization(entries=[_entry(valid_to="not-a-timestamp")])

    verdict = _evaluate(view=_view(document))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


# --- the triple binding: document publisher, manifest issuer, receipt claim ---


def test_document_publisher_member_must_match_the_receipt_publisher_claim() -> None:
    document = _authorization(publisher=OTHER)

    verdict = _evaluate(view=_view(document))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


def test_resolving_manifest_issuer_must_match_the_kid_domain() -> None:
    keys_for_wrong_manifest = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(
        PUB_KID,
        keys_for_wrong_manifest.ed.pub,
        VALID_FROM,
        pub_ml_dsa_65=keys_for_wrong_manifest.mldsa.pub,
    )
    manifest = manifests.build_key_manifest(
        OTHER, 1, VALID_FROM, [entry], keys_for_wrong_manifest, PUB_KID
    )
    document = _authorization(keys_for_wrong_manifest, kid=PUB_KID)

    verdict = _evaluate(view=_view(document), trust_store=_store(publisher_manifest=manifest))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


def test_signer_domain_must_match_the_receipt_publisher_claim_after_authentication() -> None:
    document = _authorization(ISSUER_KEYS, kid=ISSUER_KID, publisher=PUBLISHER)

    verdict = _evaluate(view=_view(document))

    _assert_verdict(
        verdict,
        "unattested",
        "signer_mismatch",
        ("authorization_signer_not_publisher",),
    )


def test_publisher_member_mismatch_takes_the_invalid_branch_before_signer_mismatch() -> None:
    document = _authorization(ISSUER_KEYS, kid=ISSUER_KID, publisher=OTHER)

    verdict = _evaluate(view=_view(document))

    _assert_verdict(verdict, "unattested", "verified", ("authorization_invalid_ignored",))


# --- successor discipline extras --------------------------------------------


def test_positive_stability_is_bounded_over_the_interregnum() -> None:
    first = _authorization()
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-06-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )
    payload = _payload(issued_at=RECEIPT_ISSUED_AT)

    before = _evaluate(payload=payload, view=_view(first))
    after = _evaluate(payload=payload, view=_view(first, second, current=2))

    _assert_verdict(before, "authorized", "verified")
    _assert_verdict(after, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


def test_live_term_window_may_extend_to_null() -> None:
    first = _authorization(entries=[_entry(valid_to="2026-09-15T00:00:00Z")])
    second = _authorization(version=2, entries=[_entry(valid_to=None)], issued_at=LATER_ISSUED_AT)
    payload = _payload(issued_at="2026-10-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(first, second))

    _assert_verdict(verdict, "authorized", "verified")


def test_postdated_restriction_of_a_live_term_window_is_nonconforming() -> None:
    first = _authorization(entries=[_entry(valid_to="2026-12-01T00:00:00Z")])
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-09-01T00:00:01Z")],
        issued_at=LATER_ISSUED_AT,
    )
    payload = _payload(issued_at="2026-10-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "unverified_rotation")


@pytest.mark.parametrize("valid_to", [AUTH_ISSUED_AT, LATER_ISSUED_AT])
def test_live_window_restriction_may_land_exactly_on_either_bound(valid_to: str) -> None:
    first = _authorization()
    second = _authorization(
        version=2, entries=[_entry(valid_to=valid_to)], issued_at=LATER_ISSUED_AT
    )

    verdict = _evaluate(view=_view(first, second, current=2))

    if valid_to == AUTH_ISSUED_AT:
        _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))
    else:
        _assert_verdict(verdict, "authorized", "verified")


def test_valid_to_equal_to_successor_issued_at_is_live_for_classification() -> None:
    first = _authorization(entries=[_entry(valid_to=LATER_ISSUED_AT)])
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-06-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )

    verdict = _evaluate(view=_view(first, second, current=2))

    _assert_verdict(verdict, "unauthorized", "verified", ("publisher_not_authorizing_issuer",))


@pytest.mark.parametrize(
    "moved_to",
    ["2026-04-01T00:00:00Z", "2026-06-01T00:00:00Z", None],
)
def test_spent_window_moved_in_any_direction_is_nonconforming(moved_to: str | None) -> None:
    first = _authorization(entries=[_entry(valid_to="2026-05-01T00:00:00Z")])
    second = _authorization(
        version=2, entries=[_entry(valid_to=moved_to)], issued_at=LATER_ISSUED_AT
    )
    payload = _payload(issued_at="2026-04-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "unverified_rotation")


def test_spent_window_carried_forward_identically_is_conforming() -> None:
    first = _authorization(entries=[_entry(valid_to="2026-05-01T00:00:00Z")])
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-05-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )
    payload = _payload(issued_at="2026-04-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "verified")


def test_valid_from_changed_on_a_shared_entry_is_nonconforming() -> None:
    first = _authorization()
    second = _authorization(
        version=2,
        entries=[_entry(valid_from="2026-01-02T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )

    verdict = _evaluate(view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "unverified_rotation")


def test_non_admitted_documents_are_not_successor_witnesses() -> None:
    bad = _authorization(entries=[_entry(valid_from="2026-01-01T00:00:00Z")])
    bad["issued_at"] = "2026-02-02T00:00:00Z"
    good = _authorization(
        version=2,
        entries=[_entry(valid_from="2026-01-02T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )
    payload = _payload(issued_at="2026-07-02T14:30:00Z")

    verdict = _evaluate(payload=payload, view=_view(bad, good))

    _assert_verdict(verdict, "authorized", "verified", ("authorization_invalid_ignored",))


def test_successor_exclusions_are_simultaneous_not_cascading() -> None:
    first = _authorization()
    violating = _authorization(version=2, entries=[], issued_at=LATER_ISSUED_AT)
    third = _authorization(
        version=3,
        entries=[_entry(valid_to="2026-06-01T00:00:00Z")],
        issued_at=THIRD_ISSUED_AT,
    )

    verdict = _evaluate(view=_view(first, violating, third, current=3))

    _assert_verdict(
        verdict, "unauthorized", "unverified_rotation", ("publisher_not_authorizing_issuer",)
    )


def test_successor_discipline_uses_shared_window_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str | None, str | None]] = []
    original_same = authority.same_instant
    original_spent = authority.window_spent_at

    def same_instant(left: str | None, right: str | None) -> bool:
        calls.append(("same", left, right))
        return original_same(left, right)

    def window_spent_at(valid_to: str | None, instant: str) -> bool:
        calls.append(("spent", valid_to, instant))
        return original_spent(valid_to, instant)

    monkeypatch.setattr(authority, "same_instant", same_instant)
    monkeypatch.setattr(authority, "window_spent_at", window_spent_at)
    first = _authorization(entries=[_entry(valid_to="2026-05-01T00:00:00Z")])
    second = _authorization(
        version=2,
        entries=[_entry(valid_to="2026-06-01T00:00:00Z")],
        issued_at=LATER_ISSUED_AT,
    )
    payload = _payload(issued_at="2026-04-01T00:00:00Z")

    verdict = _evaluate(payload=payload, view=_view(first, second, current=2))

    _assert_verdict(verdict, "authorized", "unverified_rotation")
    assert ("same", "2026-05-01T00:00:00Z", "2026-06-01T00:00:00Z") in calls
    assert ("spent", "2026-05-01T00:00:00Z", LATER_ISSUED_AT) in calls
