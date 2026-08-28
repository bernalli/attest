"""Black-box adversarial tests for publisher authorization primitives.

These tests intentionally use only the public authority interface and reviewed
neighbouring helpers to build signed wire objects. Malformed bodies are signed
when JCS can represent them, so rejection must come from the authority shape
rules rather than from an incidental signature mismatch.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from attest import authority, canon, keys, manifests, pq
from tests.helpers import make_payload

PUBLISHER = "publisher.example"
PUB_KID = f"{PUBLISHER}/keys/authority#1"
ISSUER = "store.example.com"
ISSUER_A = "alpha.example"
ISSUER_B = "beta.example"
ISSUER_Z = "zeta.example"

VALID_FROM = "2026-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2026-01-01T00:00:00Z"
AUTH_ISSUED_AT = "2026-02-01T00:00:00Z"
SUCCESSOR_ISSUED_AT = "2026-03-01T00:00:00Z"
RECEIPT_ISSUED_AT = "2026-02-15T00:00:00Z"
SERIES = "store.example.com/works/EXG-001"
RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
ART_A = hashlib.sha256(b"authority-artifact-a").hexdigest()
ART_B = hashlib.sha256(b"authority-artifact-b").hexdigest()
MAX_JCS_INTEGER = 2**53 - 1

_NO_PREVIOUS = object()
_DEFAULT_SCOPE = object()


def _ed_manifest(
    issuer: str = PUBLISHER,
    kid: str = PUB_KID,
    *,
    valid_from: str = VALID_FROM,
    valid_to: str | None = None,
    status: str = "active",
) -> tuple[keys.SigningKeyPair, dict[str, Any]]:
    kp = keys.generate()
    entry = manifests.key_entry(kid, kp.pub, valid_from, valid_to=valid_to, status=status)
    return kp, manifests.build_key_manifest(issuer, 1, MANIFEST_ISSUED_AT, [entry], kp, kid)


def _hybrid_manifest(
    issuer: str = PUBLISHER, kid: str = PUB_KID
) -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(kid, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    return hk, manifests.build_key_manifest(issuer, 1, MANIFEST_ISSUED_AT, [entry], hk, kid)


def _scope(
    artifact_series: str | None = SERIES, artifacts: list[str] | None = None
) -> dict[str, Any]:
    return {
        "artifact_series": artifact_series,
        "artifacts": sorted([RECEIPT_ART] if artifacts is None else artifacts),
    }


def _entry(
    issuer_id: str = ISSUER,
    *,
    valid_from: str = VALID_FROM,
    valid_to: str | None = None,
    permissions: list[Any] | None = None,
    scope: Any = _DEFAULT_SCOPE,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "permissions": ["issue"] if permissions is None else permissions,
        "scope": None if scope is _DEFAULT_SCOPE else scope,
    }


def _many_entries(count: int) -> list[dict[str, Any]]:
    return [_entry(f"issuer{i:04d}.example") for i in range(count)]


def _authorization_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "authorization_version": 1,
        "publisher": PUBLISHER,
        "authorized_issuers": [_entry()],
        "issued_at": AUTH_ISSUED_AT,
    }
    body.update(overrides)
    return copy.deepcopy(body)


def _signed_body(
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str = PUB_KID,
    **overrides: Any,
) -> dict[str, Any]:
    body = _authorization_body(**overrides)
    body["signature"] = manifests.sign_signature_block(canon.canonical_bytes(body), signing_kp, kid)
    return body


def _authorization(
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str = PUB_KID,
    *,
    previous: object = _NO_PREVIOUS,
    **overrides: Any,
) -> dict[str, Any]:
    body = _authorization_body(**overrides)
    kwargs = {
        "authorization_version": body["authorization_version"],
        "publisher": body["publisher"],
        "authorized_issuers": body["authorized_issuers"],
        "issued_at": body["issued_at"],
        "signing_kp": signing_kp,
        "kid": kid,
    }
    if previous is _NO_PREVIOUS:
        return authority.build_authorization(**kwargs)
    return authority.build_authorization(**kwargs, previous=previous)


def _payload(**overrides: Any) -> dict[str, Any]:
    base_overrides: dict[str, Any] = {
        "issued_at": RECEIPT_ISSUED_AT,
        "issuer": {"id": ISSUER},
        "work": {"publisher_id": PUBLISHER, "artifact_series": SERIES},
    }
    base_overrides.update(overrides)
    return make_payload(**base_overrides)


def _set_path(document: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    cursor: Any = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value


def _document_with_mutation(
    signing_kp: keys.SigningKeyPair,
    path: tuple[Any, ...],
    value: Any,
) -> dict[str, Any]:
    scoped_entry = _entry(scope=_scope())
    if path[0] == "signature":
        document = _signed_body(signing_kp, authorized_issuers=[scoped_entry])
        _set_path(document, path, value)
        return document

    body = _authorization_body(authorized_issuers=[scoped_entry])
    _set_path(body, path, value)
    body["signature"] = manifests.sign_signature_block(
        canon.canonical_bytes(body), signing_kp, PUB_KID
    )
    return body


# --- build, hash, and authentication ----------------------------------------


def test_classical_authorization_roundtrips_and_empty_first_list_is_admitted() -> None:
    kp, key_manifest = _ed_manifest()

    document = _authorization(kp)
    empty_document = _authorization(kp, authorized_issuers=[])

    assert "sig_ml_dsa_65" not in document["signature"]
    assert authority.verify_authorization_signature(document, key_manifest) is True
    assert authority.verify_authorization(document, key_manifest) is True
    assert authority.verify_authorization(empty_document, key_manifest) is True


def test_hybrid_authorization_requires_both_signature_legs() -> None:
    hk, key_manifest = _hybrid_manifest()
    document = _authorization(hk)

    assert "sig" in document["signature"]
    assert "sig_ml_dsa_65" in document["signature"]
    assert authority.verify_authorization(document, key_manifest) is True

    del document["signature"]["sig_ml_dsa_65"]

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


def test_stray_pq_signature_leg_against_classical_key_fails_closed() -> None:
    kp, key_manifest = _ed_manifest()
    hk, _ = _hybrid_manifest()
    document = _authorization(kp)
    body = {key: value for key, value in document.items() if key != "signature"}
    document["signature"]["sig_ml_dsa_65"] = keys.b64u(
        pq.sign(canon.canonical_bytes(body), hk.mldsa)
    )

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


def test_authorization_hash_is_jcs_over_the_entire_signed_document() -> None:
    kp, _ = _ed_manifest()
    document = _authorization(kp)
    expected = hashlib.sha256(canon.canonical_bytes(document)).hexdigest()

    assert authority.authorization_hash(document) == expected

    body = {key: value for key, value in document.items() if key != "signature"}
    assert (
        authority.authorization_hash(document)
        != hashlib.sha256(canon.canonical_bytes(body)).hexdigest()
    )

    reordered = {key: document[key] for key in reversed(tuple(document))}
    assert authority.authorization_hash(reordered) == expected


def test_authorization_hash_uses_jcs_code_point_key_order() -> None:
    hostile_order = {"z": 1, "A": 2, "\U00010000": 3, "a": 4}
    same_document_different_insertion = {"\U00010000": 3, "a": 4, "A": 2, "z": 1}
    expected = hashlib.sha256(canon.canonical_bytes(hostile_order)).hexdigest()

    assert authority.authorization_hash(hostile_order) == expected
    assert authority.authorization_hash(same_document_different_insertion) == expected


def test_verify_authorization_composes_key_manifest_self_consistency() -> None:
    kp, key_manifest = _ed_manifest()
    document = _authorization(kp)
    key_manifest["issued_at"] = "2026-06-01T00:00:00Z"

    assert authority.verify_authorization_signature(document, key_manifest) is True
    assert authority.verify_authorization(document, key_manifest) is False


def test_authorization_signed_by_retired_key_is_rejected() -> None:
    kp = keys.generate()
    retired_entry = manifests.key_entry(PUB_KID, kp.pub, VALID_FROM, status="retired")
    signer_kid = f"{PUBLISHER}/keys/authority#2"
    signer_entry = manifests.key_entry(signer_kid, kp.pub, VALID_FROM)
    key_manifest = manifests.build_key_manifest(
        PUBLISHER,
        1,
        MANIFEST_ISSUED_AT,
        [retired_entry, signer_entry],
        kp,
        signer_kid,
    )
    document = _authorization(kp)

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


@pytest.mark.parametrize(
    ("valid_from", "valid_to"),
    [
        ("2026-03-01T00:00:00Z", None),
        ("2026-01-01T00:00:00Z", "2026-01-31T23:59:59Z"),
    ],
)
def test_authorization_issued_outside_signer_key_window_is_rejected(
    valid_from: str, valid_to: str | None
) -> None:
    kp, key_manifest = _ed_manifest(valid_from=valid_from, valid_to=valid_to)
    document = _authorization(kp)

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


@pytest.mark.parametrize(
    "key_manifest",
    [
        None,
        42,
        "manifest",
        [],
        {},
        {"issuer": PUBLISHER, "keys": [{"kid": []}]},
    ],
)
def test_verify_authorization_fails_closed_on_malformed_key_manifest(
    key_manifest: Any,
) -> None:
    kp, _ = _ed_manifest()
    document = _authorization(kp)

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


# --- shape: closed members, type confusion, ordering, and ceilings -----------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda body: body.update({"extra": "surprise"}),
        lambda body: body.pop("publisher"),
        lambda body: body["authorized_issuers"][0].update({"extra": "surprise"}),
        lambda body: body["authorized_issuers"][0].pop("scope"),
    ],
)
def test_authorization_and_entry_members_are_closed_even_with_matching_signature(
    mutate: Any,
) -> None:
    kp, key_manifest = _ed_manifest()
    body = _authorization_body()
    mutate(body)
    body["signature"] = manifests.sign_signature_block(canon.canonical_bytes(body), kp, PUB_KID)

    assert authority.verify_authorization_signature(body, key_manifest) is False
    assert authority.verify_authorization(body, key_manifest) is False


_JSON_LEAF = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10, max_value=10),
    st.text(max_size=5),
)
_JSON_LIST = st.lists(_JSON_LEAF, max_size=2)
_JSON_DICT = st.dictionaries(st.text(min_size=1, max_size=5), _JSON_LEAF, max_size=2)

_NON_STRING = st.one_of(st.none(), st.booleans(), st.integers(-10, 10), _JSON_LIST, _JSON_DICT)
_NON_NULLABLE_STRING = st.one_of(st.booleans(), st.integers(-10, 10), _JSON_LIST, _JSON_DICT)
_NON_INT = st.one_of(st.none(), st.booleans(), st.text(max_size=5), _JSON_LIST, _JSON_DICT)
_NON_LIST = st.one_of(
    st.none(), st.booleans(), st.integers(-10, 10), st.text(max_size=5), _JSON_DICT
)
_NON_DICT = st.one_of(
    st.none(), st.booleans(), st.integers(-10, 10), st.text(max_size=5), _JSON_LIST
)
_NON_SCOPE = st.one_of(st.booleans(), st.integers(-10, 10), st.text(max_size=5), _JSON_LIST)

_STRING_PATHS = (
    ("publisher",),
    ("issued_at",),
    ("authorized_issuers", 0, "issuer_id"),
    ("authorized_issuers", 0, "valid_from"),
    ("authorized_issuers", 0, "permissions", 0),
    ("authorized_issuers", 0, "scope", "artifacts", 0),
    ("signature", "kid"),
    ("signature", "sig"),
)
_NULLABLE_STRING_PATHS = (
    ("authorized_issuers", 0, "valid_to"),
    ("authorized_issuers", 0, "scope", "artifact_series"),
)
_INT_PATHS = (("authorization_version",),)
_LIST_PATHS = (
    ("authorized_issuers",),
    ("authorized_issuers", 0, "permissions"),
    ("authorized_issuers", 0, "scope", "artifacts"),
)
_DICT_PATHS = (("authorized_issuers", 0), ("signature",))
_SCOPE_PATHS = (("authorized_issuers", 0, "scope"),)

_TYPE_CONFUSION_MUTATION = st.one_of(
    st.tuples(st.sampled_from(_STRING_PATHS), _NON_STRING),
    st.tuples(st.sampled_from(_NULLABLE_STRING_PATHS), _NON_NULLABLE_STRING),
    st.tuples(st.sampled_from(_INT_PATHS), _NON_INT),
    st.tuples(st.sampled_from(_LIST_PATHS), _NON_LIST),
    st.tuples(st.sampled_from(_DICT_PATHS), _NON_DICT),
    st.tuples(st.sampled_from(_SCOPE_PATHS), _NON_SCOPE),
)


@settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(mutation=_TYPE_CONFUSION_MUTATION)
def test_verify_authorization_never_raises_on_type_confusion_in_wire_fields(
    mutation: tuple[tuple[Any, ...], Any],
) -> None:
    path, value = mutation
    kp, key_manifest = _ed_manifest()
    document = _document_with_mutation(kp, path, value)

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("publisher",), ""),
        (("publisher",), "Publisher.Example"),
        (("publisher",), "not a dns"),
        (("issued_at",), ""),
        (("issued_at",), "2026-02-30T00:00:00Z"),
        (("issued_at",), "2026-01-01T00:00:00+00:00"),
        (("authorized_issuers", 0, "issuer_id"), ""),
        (("authorized_issuers", 0, "issuer_id"), "Store.Example.Com"),
        (("authorized_issuers", 0, "valid_from"), ""),
        (("authorized_issuers", 0, "valid_from"), "2026-02-30T00:00:00Z"),
        (("authorized_issuers", 0, "valid_to"), ""),
        (("authorized_issuers", 0, "valid_to"), "2026-02-30T00:00:00Z"),
        (("authorized_issuers", 0, "permissions", 0), ""),
        (("authorized_issuers", 0, "scope", "artifact_series"), ""),
        (("authorized_issuers", 0, "scope", "artifacts", 0), ART_A.upper()),
    ],
)
def test_empty_case_and_semantically_invalid_strings_are_shape_errors(
    path: tuple[Any, ...], value: Any
) -> None:
    kp, key_manifest = _ed_manifest()
    document = _document_with_mutation(kp, path, value)

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        (1, True),
        (MAX_JCS_INTEGER, True),
        (0, False),
        (-1, False),
        (True, False),
        (False, False),
        (2**53, False),
    ],
)
def test_authorization_version_boundaries_are_enforced_on_signed_documents(
    version: Any, expected: bool
) -> None:
    kp, key_manifest = _ed_manifest()
    if version == 2**53:
        document = _authorization(kp)
        document["authorization_version"] = version
    else:
        document = _signed_body(kp, authorization_version=version)

    assert authority.verify_authorization_signature(document, key_manifest) is expected
    assert authority.verify_authorization(document, key_manifest) is expected


@pytest.mark.parametrize(
    "value",
    [None, [], {}, True, False, -1, 0, 1, MAX_JCS_INTEGER, 2**53, "1", 1.0],
)
def test_is_authorization_version_is_the_exact_safe_integer_predicate(value: Any) -> None:
    expected = (
        isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_JCS_INTEGER
    )

    assert authority.is_authorization_version(value) is expected


@pytest.mark.parametrize(
    "issuers",
    [
        [ISSUER_A, ISSUER_A],
        [ISSUER_A, ISSUER_B, ISSUER_B],
        [ISSUER_B, ISSUER_A],
        [ISSUER_A, ISSUER_Z, ISSUER_B],
        ["issuer2.example", "issuer10.example"],
    ],
)
def test_authorized_issuers_must_be_strictly_ascending_by_code_point(
    issuers: list[str],
) -> None:
    kp, key_manifest = _ed_manifest()
    entries = [_entry(issuer_id) for issuer_id in issuers]
    document = _signed_body(kp, authorized_issuers=entries)

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


def test_code_point_sorted_numeric_looking_issuer_ids_are_accepted() -> None:
    kp, key_manifest = _ed_manifest()
    entries = [_entry("issuer10.example"), _entry("issuer2.example")]
    document = _signed_body(kp, authorized_issuers=entries)

    assert authority.verify_authorization_signature(document, key_manifest) is True
    assert authority.verify_authorization(document, key_manifest) is True


@pytest.mark.parametrize(
    "permissions",
    [
        [],
        ["issue", "issue"],
        ["issue", "delegate"],
        [""],
        ["issue", {}],
    ],
)
def test_permissions_must_be_non_empty_sorted_duplicate_free_strings(
    permissions: list[Any],
) -> None:
    kp, key_manifest = _ed_manifest()
    document = _signed_body(kp, authorized_issuers=[_entry(permissions=permissions)])

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


def test_permission_vocabulary_is_open_but_still_code_point_sorted() -> None:
    kp, key_manifest = _ed_manifest()
    sorted_permissions = ["a", "delegate", "issue", "\U00010000"]
    unsorted_permissions = ["a", "\U00010000", "delegate", "issue"]
    sorted_document = _signed_body(kp, authorized_issuers=[_entry(permissions=sorted_permissions)])
    unsorted_document = _signed_body(
        kp, authorized_issuers=[_entry(permissions=unsorted_permissions)]
    )

    assert authority.verify_authorization(sorted_document, key_manifest) is True
    assert authority.verify_authorization(unsorted_document, key_manifest) is False


def test_semantically_absurd_entry_window_does_not_authenticate() -> None:
    """§20.2's `valid_to` shape is a plain ISO-8601 UTC timestamp; a calendar
    date that does not exist (30 February) fails that shape outright, which is
    a different failure from an inverted-but-well-formed window (see
    `test_inverted_entry_window_authenticates_but_never_authorizes_any_receipt`
    below) — this test isolates the shape failure alone.
    """
    kp, key_manifest = _ed_manifest()
    document = _signed_body(
        kp,
        authorized_issuers=[
            _entry(valid_from="2026-01-01T00:00:00Z", valid_to="2026-02-30T00:00:00Z")
        ],
    )

    assert authority.verify_authorization_signature(document, key_manifest) is False
    assert authority.verify_authorization(document, key_manifest) is False


@pytest.mark.parametrize(
    "issued_at",
    [
        "2026-04-15T00:00:00Z",  # before both bounds of the inverted gap
        "2026-04-30T23:59:59Z",  # equals valid_to, still short of valid_from
        "2026-05-01T00:00:00Z",  # equals valid_from, past valid_to
        "2026-06-01T00:00:00Z",  # after both bounds
    ],
)
def test_inverted_entry_window_authenticates_but_never_authorizes_any_receipt(
    issued_at: str,
) -> None:
    """§20.2's shape does not forbid `valid_from > valid_to` — each bound is
    independently a well-formed timestamp, so a document carrying such an
    entry authenticates exactly like any other. But the window it describes
    covers no instant: for `_within_entry_window`, `issued < valid_from`
    rejects everything before the (later) `valid_from`, and `issued <=
    valid_to` rejects everything from `valid_from` onward, since `valid_to`
    is earlier still. No `issued_at` threads both, at any of the four
    representative points around the inverted gap.
    """
    kp, key_manifest = _ed_manifest()
    entry = _entry(valid_from="2026-05-01T00:00:00Z", valid_to="2026-04-30T23:59:59Z")
    document = _signed_body(kp, authorized_issuers=[entry])

    assert authority.verify_authorization_signature(document, key_manifest) is True
    assert authority.verify_authorization(document, key_manifest) is True
    assert authority.entry_authorizes_receipt(entry, _payload(issued_at=issued_at)) is False


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (4096, True),
        (4097, False),
    ],
)
def test_authorized_issuers_ceiling_is_exact_on_signed_documents(
    count: int, expected: bool
) -> None:
    kp, key_manifest = _ed_manifest()
    document = _signed_body(kp, authorized_issuers=_many_entries(count))

    assert authority.verify_authorization_signature(document, key_manifest) is expected
    assert authority.verify_authorization(document, key_manifest) is expected


def test_within_structural_ceiling_counts_only_and_never_inspects_documents() -> None:
    hostile = object()

    assert authority.within_structural_ceiling(None) is True
    assert authority.within_structural_ceiling([hostile] * 64) is True
    assert authority.within_structural_ceiling([hostile] * 65) is False
    assert authority.within_structural_ceiling("not an array") is False
    assert authority.within_structural_ceiling({"authorizations": []}) is False


# --- entry lookup and receipt authorization ---------------------------------


def test_entry_for_issuer_returns_the_unique_matching_entry_only() -> None:
    target = _entry(ISSUER_B, scope=_scope(artifacts=[ART_A, ART_B]))
    document = _signed_body(
        keys.generate(),
        authorized_issuers=[_entry(ISSUER_A), target, _entry(ISSUER_Z)],
    )

    assert authority.entry_for_issuer(document, ISSUER_B) == target
    assert authority.entry_for_issuer(document, "missing.example") is None


def test_entry_for_issuer_refuses_duplicate_entries_instead_of_using_array_order() -> None:
    first = _entry(ISSUER_A, scope=None)
    second = _entry(ISSUER_A, scope=_scope(artifacts=[ART_A]))
    document = _signed_body(keys.generate(), authorized_issuers=[first, second])

    assert authority.entry_for_issuer(document, ISSUER_A) is None


@pytest.mark.parametrize("issuer_id", [None, [], {}, True, 0, ""])
def test_entry_for_issuer_fails_closed_on_non_string_lookup_keys(issuer_id: Any) -> None:
    document = _signed_body(keys.generate())

    assert authority.entry_for_issuer(document, issuer_id) is None


@pytest.mark.parametrize(
    ("issued_at", "expected"),
    [
        ("2026-01-01T00:00:00Z", True),
        ("2026-02-15T00:00:00Z", True),
        ("2026-05-01T00:00:00Z", True),
        ("2025-12-31T23:59:59Z", False),
        ("2026-05-01T00:00:01Z", False),
    ],
)
def test_entry_authorizes_receipt_uses_inclusive_receipt_time_window(
    issued_at: str, expected: bool
) -> None:
    entry = _entry(valid_to="2026-05-01T00:00:00Z")

    assert authority.entry_authorizes_receipt(entry, _payload(issued_at=issued_at)) is expected


def test_entry_authorizes_receipt_allows_open_ended_window_after_valid_from() -> None:
    assert authority.entry_authorizes_receipt(_entry(valid_to=None), _payload()) is True


@pytest.mark.parametrize(
    ("permissions", "expected"),
    [
        (["issue"], True),
        (["delegate"], False),
        (["delegate", "issue"], True),
        (["future-permission"], False),
    ],
)
def test_entry_authorizes_receipt_requires_issue_and_never_honors_delegate_alone(
    permissions: list[str], expected: bool
) -> None:
    entry = _entry(permissions=permissions)

    assert authority.entry_authorizes_receipt(entry, _payload()) is expected


@pytest.mark.parametrize(
    ("scope", "payload_overrides", "expected"),
    [
        (None, {}, True),
        (_scope(artifact_series=SERIES, artifacts=[ART_A]), {}, True),
        (_scope(artifact_series=None, artifacts=[RECEIPT_ART, ART_A]), {}, True),
        (_scope(artifact_series="other.example/works/OTHER", artifacts=[ART_A]), {}, False),
        (_scope(artifact_series=None, artifacts=[RECEIPT_ART]), {"work": {"artifacts": []}}, False),
        # A non-null, artifact-only scope must fail closed on a hostile
        # `work.artifacts[]` shape rather than raise or default to coverage:
        # `grant_covers_receipt` rejects the malformed `sha256` element
        # ([] is not a 64-hex digest) before it can match anything.
        (
            _scope(artifact_series=None, artifacts=[ART_A]),
            {"work": {"artifacts": [{"sha256": []}]}},
            False,
        ),
    ],
)
def test_entry_authorizes_receipt_applies_scope_and_vacuous_artifact_guard(
    scope: Any, payload_overrides: dict[str, Any], expected: bool
) -> None:
    entry = _entry(scope=scope)

    assert authority.entry_authorizes_receipt(entry, _payload(**payload_overrides)) is expected


@pytest.mark.parametrize(
    ("entry_overrides", "payload_overrides"),
    [
        ({"valid_from": []}, {}),
        ({"valid_to": {}}, {}),
        ({"valid_from": "2026-02-30T00:00:00Z"}, {}),
        ({"valid_from": "2026-05-01T00:00:00Z", "valid_to": "2026-04-01T00:00:00Z"}, {}),
        ({"permissions": ["issue", {}]}, {}),
        ({"permissions": {}}, {}),
        ({"scope": {"artifact_series": None, "artifacts": []}}, {}),
        ({}, {"issued_at": []}),
        ({}, {"issued_at": {}}),
        ({}, {"issued_at": "2026-02-30T00:00:00Z"}),
    ],
)
def test_entry_authorizes_receipt_fails_closed_on_hostile_entry_or_payload_types(
    entry_overrides: dict[str, Any], payload_overrides: dict[str, Any]
) -> None:
    entry = _entry(**entry_overrides)

    assert authority.entry_authorizes_receipt(entry, _payload(**payload_overrides)) is False


@pytest.mark.parametrize("entry", [None, 42, "entry", [], {}, {"permissions": ["issue"]}])
def test_entry_authorizes_receipt_never_raises_on_non_entry_inputs(entry: Any) -> None:
    assert authority.entry_authorizes_receipt(entry, _payload()) is False


# --- build_authorization successor discipline -------------------------------


def test_build_authorization_previous_none_is_byte_identical_to_omitted() -> None:
    kp, _ = _ed_manifest()

    assert _authorization(kp) == _authorization(kp, previous=None)


@pytest.mark.parametrize("version", [1, 2])
def test_build_authorization_rejects_non_increasing_successor_version(version: int) -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorization_version=2)

    with pytest.raises(ValueError):
        _authorization(kp, authorization_version=version, previous=previous)


def test_previous_violation_is_detected_before_signature_attempt() -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorization_version=2)

    with pytest.raises(ValueError):
        authority.build_authorization(
            authorization_version=2,
            publisher=PUBLISHER,
            authorized_issuers=[_entry()],
            issued_at=SUCCESSOR_ISSUED_AT,
            signing_kp=object(),
            kid=PUB_KID,
            previous=previous,
        )


@pytest.mark.parametrize(
    "successor_entries",
    [
        [_entry(ISSUER_B)],
        [_entry(ISSUER_A)],
        [],
    ],
)
def test_build_authorization_rejects_entry_deletion(
    successor_entries: list[dict[str, Any]],
) -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorized_issuers=[_entry(ISSUER_A), _entry(ISSUER_B)])

    with pytest.raises(ValueError):
        _authorization(
            kp,
            authorization_version=2,
            authorized_issuers=successor_entries,
            issued_at=SUCCESSOR_ISSUED_AT,
            previous=previous,
        )


def test_build_authorization_allows_new_entry_without_moving_existing_entry() -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorized_issuers=[_entry(ISSUER_B)])
    successor = _authorization(
        kp,
        authorization_version=2,
        authorized_issuers=[_entry(ISSUER_A), _entry(ISSUER_B)],
        issued_at=SUCCESSOR_ISSUED_AT,
        previous=previous,
    )

    assert successor["authorization_version"] == 2


def test_build_authorization_rejects_valid_from_mutation_for_existing_entry() -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorized_issuers=[_entry(ISSUER_A)])

    with pytest.raises(ValueError):
        _authorization(
            kp,
            authorization_version=2,
            authorized_issuers=[_entry(ISSUER_A, valid_from="2026-01-02T00:00:00Z")],
            issued_at=SUCCESSOR_ISSUED_AT,
            previous=previous,
        )


def test_build_authorization_allows_identical_already_closed_window() -> None:
    kp, _ = _ed_manifest()
    closed = _entry(ISSUER_A, valid_to="2026-01-15T00:00:00Z")
    previous = _authorization(kp, authorized_issuers=[closed], issued_at=AUTH_ISSUED_AT)
    successor = _authorization(
        kp,
        authorization_version=2,
        authorized_issuers=[copy.deepcopy(closed)],
        issued_at=SUCCESSOR_ISSUED_AT,
        previous=previous,
    )

    assert successor["authorized_issuers"][0]["valid_to"] == "2026-01-15T00:00:00Z"


@pytest.mark.parametrize(
    "moved_valid_to",
    ["2026-01-14T23:59:59Z", "2026-01-15T00:00:01Z", None],
)
def test_build_authorization_rejects_moving_already_closed_window(
    moved_valid_to: str | None,
) -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(
        kp,
        authorized_issuers=[_entry(ISSUER_A, valid_to="2026-01-15T00:00:00Z")],
        issued_at=AUTH_ISSUED_AT,
    )

    with pytest.raises(ValueError):
        _authorization(
            kp,
            authorization_version=2,
            authorized_issuers=[_entry(ISSUER_A, valid_to=moved_valid_to)],
            issued_at=SUCCESSOR_ISSUED_AT,
            previous=previous,
        )


def test_build_authorization_rejects_retrodated_new_closure_for_open_entry() -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorized_issuers=[_entry(ISSUER_A, valid_to=None)])

    with pytest.raises(ValueError):
        _authorization(
            kp,
            authorization_version=2,
            authorized_issuers=[_entry(ISSUER_A, valid_to="2026-01-31T23:59:59Z")],
            issued_at=SUCCESSOR_ISSUED_AT,
            previous=previous,
        )


@pytest.mark.parametrize(
    "valid_to",
    ["2026-02-01T00:00:00Z", "2026-02-15T00:00:00Z"],
)
def test_build_authorization_allows_prospective_closure_for_open_entry(
    valid_to: str,
) -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorized_issuers=[_entry(ISSUER_A, valid_to=None)])
    successor = _authorization(
        kp,
        authorization_version=2,
        authorized_issuers=[_entry(ISSUER_A, valid_to=valid_to)],
        issued_at=SUCCESSOR_ISSUED_AT,
        previous=previous,
    )

    assert successor["authorized_issuers"][0]["valid_to"] == valid_to


def test_build_authorization_rejects_postdated_new_closure_after_successor_issued_at() -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(kp, authorized_issuers=[_entry(ISSUER_A, valid_to=None)])

    with pytest.raises(ValueError):
        _authorization(
            kp,
            authorization_version=2,
            authorized_issuers=[_entry(ISSUER_A, valid_to="2026-03-01T00:00:01Z")],
            issued_at=SUCCESSOR_ISSUED_AT,
            previous=previous,
        )


def test_build_authorization_rejects_shortened_closure_before_previous_issued_at() -> None:
    kp, _ = _ed_manifest()
    previous = _authorization(
        kp,
        authorized_issuers=[_entry(ISSUER_A, valid_to="2026-04-01T00:00:00Z")],
        issued_at=AUTH_ISSUED_AT,
    )

    with pytest.raises(ValueError):
        _authorization(
            kp,
            authorization_version=2,
            authorized_issuers=[_entry(ISSUER_A, valid_to="2026-01-31T23:59:59Z")],
            issued_at=SUCCESSOR_ISSUED_AT,
            previous=previous,
        )


def test_build_authorization_allows_closure_of_open_entry_exactly_at_previous_issued_at() -> None:
    """A predecessor's OPEN entry (`valid_to: null`) may be closed by its
    successor at exactly the predecessor's own `issued_at` — the earliest
    legal bound §20.2 sets on a newly introduced closure ("no earlier than
    the `issued_at` of the latest version that showed the window open").
    This is distinct from moving an ALREADY-closed window (which §20.2
    forbids in either direction, see
    `test_build_authorization_rejects_shortened_closure_before_previous_issued_at`
    and `test_build_authorization_rejects_moving_already_closed_window`): here
    the predecessor's window was still open, so the successor is introducing
    the closure, not moving one.
    """
    kp, _ = _ed_manifest()
    previous = _authorization(
        kp,
        authorized_issuers=[_entry(ISSUER_A, valid_to=None)],
        issued_at=AUTH_ISSUED_AT,
    )
    successor = _authorization(
        kp,
        authorization_version=2,
        authorized_issuers=[_entry(ISSUER_A, valid_to=AUTH_ISSUED_AT)],
        issued_at=SUCCESSOR_ISSUED_AT,
        previous=previous,
    )

    assert successor["authorized_issuers"][0]["valid_to"] == AUTH_ISSUED_AT
