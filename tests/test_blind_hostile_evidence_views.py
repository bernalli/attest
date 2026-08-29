"""Adversarial caller-owned evidence views for the public Python evaluators.

The fixtures start with records accepted by the corresponding public
authentication primitive.  Each case then replaces only caller-owned evidence
with a live hostile value.  A hostile value is not a wire document: the
evaluator must return, and it may not manufacture the positive verdict.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from attest import authority, grant, keys, manifests, pq, verify
from tests.helpers import make_payload

ISSUER = "store.example"
PUBLISHER = "pub.example"
ROGUE = "rogue.example"
ISSUER_KID = f"{ISSUER}/keys/blind#1"
PUBLISHER_KID = f"{PUBLISHER}/keys/blind#1"
KEY_VALID_FROM = "2026-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2026-01-01T00:00:00Z"
AUTHORIZATION_ISSUED_AT = "2026-01-10T00:00:00Z"
RECEIPT_ISSUED_AT = "2026-01-20T00:00:00Z"
GRANT_ISSUED_AT = "2026-02-01T00:00:00Z"
DECLARED_AT = "2031-03-01T00:00:00Z"
ARTIFACT = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
OTHER_ARTIFACT = hashlib.sha256(b"blind-hostile-other-artifact").hexdigest()
LEGAL_TEXT_SHA256 = hashlib.sha256(b"blind-hostile-grant-prose").hexdigest()


def _hybrid_manifest(issuer: str, kid: str) -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    signing_keys = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(
        kid,
        signing_keys.ed.pub,
        KEY_VALID_FROM,
        pub_ml_dsa_65=signing_keys.mldsa.pub,
    )
    return signing_keys, manifests.build_key_manifest(
        issuer, 1, MANIFEST_ISSUED_AT, [entry], signing_keys, kid
    )


ISSUER_KEYS, ISSUER_MANIFEST = _hybrid_manifest(ISSUER, ISSUER_KID)
PUBLISHER_KEYS, PUBLISHER_MANIFEST = _hybrid_manifest(PUBLISHER, PUBLISHER_KID)
BUYER_KEY = keys.from_seed(bytes([19]) * 32)


def _authority_entry(issuer_id: str = ISSUER) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "valid_from": KEY_VALID_FROM,
        "valid_to": None,
        "permissions": [authority.PERMISSION_ISSUE],
        "scope": None,
    }


def _authorization(issuer_id: str = ISSUER) -> dict[str, Any]:
    return authority.build_authorization(
        authorization_version=1,
        publisher=PUBLISHER,
        authorized_issuers=[_authority_entry(issuer_id)],
        issued_at=AUTHORIZATION_ISSUED_AT,
        signing_kp=PUBLISHER_KEYS,
        kid=PUBLISHER_KID,
    )


def _grant(
    scope_artifacts: list[str] | None = None, artifact_series: str | None = None
) -> dict[str, Any]:
    return grant.build_grant(
        grant_version=1,
        publisher=PUBLISHER,
        scope={
            "artifact_series": artifact_series,
            "artifacts": scope_artifacts or [ARTIFACT],
        },
        permissions=["deliver-to-holder"],
        activation={
            "modes": ["publisher-declaration"],
            "fixed_date": None,
            "successor_ids": [],
        },
        unprotected_build=True,
        legal_text_uri="https://pub.example/sunset-grant-v1",
        legal_text_sha256=LEGAL_TEXT_SHA256,
        jurisdiction="IT",
        issued_at=GRANT_ISSUED_AT,
        signing_kp=PUBLISHER_KEYS,
        kid=PUBLISHER_KID,
    )


def _declaration(
    scope_artifacts: list[str] | None = None, artifact_series: str | None = None
) -> dict[str, Any]:
    return grant.build_declaration(
        publisher=PUBLISHER,
        scope={
            "artifact_series": artifact_series,
            "artifacts": scope_artifacts or [ARTIFACT],
        },
        declared_at=DECLARED_AT,
        signing_kp=PUBLISHER_KEYS,
        kid=PUBLISHER_KID,
    )


def _authority_payload() -> dict[str, Any]:
    return make_payload(
        attest_version="0.2",
        issued_at=RECEIPT_ISSUED_AT,
        issuer={"id": ISSUER},
        work={"publisher_id": PUBLISHER},
    )


def _grant_payload(document: dict[str, Any]) -> dict[str, Any]:
    return make_payload(
        attest_version="0.2",
        buyer={"pubkey": keys.b64u(BUYER_KEY.pub)},
        work={"publisher_id": PUBLISHER},
        license={
            "preservation_pledge": {
                "pledge": "sunset-grant-v1",
                "grant_uri": "https://pub.example/sunset-grant-v1.json",
                "grant_sha256": grant.grant_hash(document),
            }
        },
        survivability={"end_of_life": "sunset-grant"},
    )


def _store() -> verify.TrustStore:
    return verify.TrustStore(
        manifests={ISSUER: ISSUER_MANIFEST, PUBLISHER: PUBLISHER_MANIFEST},
        provenance={ISSUER: "tls", PUBLISHER: "tls"},
        chains={},
    )


def _evaluate_authority(view: object) -> Any:
    return verify.evaluate_publisher_authority(_authority_payload(), _store(), view)


def _evaluate_grant(document: dict[str, Any], view: object) -> Any:
    return verify.evaluate_grant(_grant_payload(document), _store(), view)


def _assert_authority_fixture(document: dict[str, Any]) -> None:
    assert authority.verify_authorization(document, PUBLISHER_MANIFEST) is True


def _assert_grant_fixture(document: dict[str, Any], declaration: dict[str, Any]) -> None:
    assert grant.verify_grant(document, PUBLISHER_MANIFEST) is True
    assert grant.verify_declaration(declaration, PUBLISHER_MANIFEST) is True


class _LyingGet(dict[str, Any]):
    def get(self, key: object, default: object = None) -> object:
        return default


class _RaisingGet(dict[str, Any]):
    def get(self, key: object, default: object = None) -> object:
        raise RuntimeError("hostile get")


class _LyingKeys(dict[str, Any]):
    def keys(self) -> Any:
        return ()


class _RaisingKeys(dict[str, Any]):
    def keys(self) -> Any:
        raise RuntimeError("hostile keys")


class _LyingItems(dict[str, Any]):
    def items(self) -> Any:
        return (("not-evidence", None),)


class _RaisingItems(dict[str, Any]):
    def items(self) -> Any:
        raise RuntimeError("hostile items")


class _LyingGetItem(dict[str, Any]):
    def __getitem__(self, key: str) -> Any:
        return None


class _RaisingGetItem(dict[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise RuntimeError("hostile getitem")


class _LyingContains(dict[str, Any]):
    def __contains__(self, key: object) -> bool:
        return False


class _RaisingContains(dict[str, Any]):
    def __contains__(self, key: object) -> bool:
        raise RuntimeError("hostile contains")


MAPPING_MUTATIONS: tuple[Callable[[dict[str, Any]], dict[str, Any]], ...] = (
    _LyingGet,
    _RaisingGet,
    _LyingKeys,
    _RaisingKeys,
    _LyingItems,
    _RaisingItems,
    _LyingGetItem,
    _RaisingGetItem,
    _LyingContains,
    _RaisingContains,
)


class _LyingLen(list[Any]):
    def __len__(self) -> int:
        return 0

    def __iter__(self) -> Any:
        return (list.__getitem__(self, index) for index in range(len(self)))


class _RaisingLen(list[Any]):
    def __len__(self) -> int:
        raise RuntimeError("hostile len")

    def __iter__(self) -> Any:
        return (list.__getitem__(self, index) for index in range(len(self)))


class _LyingIter(list[Any]):
    def __iter__(self) -> Any:
        return iter(())


class _RaisingIter(list[Any]):
    def __iter__(self) -> Any:
        raise RuntimeError("hostile iter")


class _LyingGetItemList(list[Any]):
    def __iter__(self) -> Any:
        return (self[index] for index in range(list.__len__(self)))

    def __getitem__(self, index: object) -> Any:
        return None


class _RaisingGetItemList(list[Any]):
    def __iter__(self) -> Any:
        return (self[index] for index in range(list.__len__(self)))

    def __getitem__(self, index: object) -> Any:
        raise RuntimeError("hostile list getitem")


LIST_MUTATIONS: tuple[Callable[[list[Any]], list[Any]], ...] = (
    _LyingLen,
    _RaisingLen,
    _LyingIter,
    _RaisingIter,
    _LyingGetItemList,
    _RaisingGetItemList,
)


class _HostileIdentifier(str):
    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return hash(ISSUER)


def _deep_value(depth: int = 257) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("mutation", MAPPING_MUTATIONS, ids=lambda item: item.__name__)
def test_hostile_mapping_content_in_authority_view_returns(
    mutation: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    document = _authorization()
    _assert_authority_fixture(document)

    verdict = _evaluate_authority({"authorizations": [mutation(document)]})

    assert verdict is not None


@pytest.mark.parametrize("mutation", MAPPING_MUTATIONS, ids=lambda item: item.__name__)
def test_hostile_mapping_content_in_grant_view_returns(
    mutation: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    document = _grant()
    declaration = _declaration()
    _assert_grant_fixture(document, declaration)

    verdict = _evaluate_grant(
        document, {"grant": mutation(document), "declarations": [declaration]}
    )

    assert verdict is not None


@pytest.mark.parametrize("mutation", LIST_MUTATIONS, ids=lambda item: item.__name__)
@pytest.mark.parametrize("member", ("later_grants", "declarations"))
def test_hostile_grant_arrays_return(
    mutation: Callable[[list[Any]], list[Any]], member: str
) -> None:
    document = _grant()
    declaration = _declaration()
    _assert_grant_fixture(document, declaration)
    member_value: list[Any] = [_grant() if member == "later_grants" else declaration]

    verdict = _evaluate_grant(document, {"grant": document, member: mutation(member_value)})

    assert verdict is not None


@pytest.mark.parametrize("mutation", LIST_MUTATIONS, ids=lambda item: item.__name__)
def test_hostile_authorizations_array_returns(
    mutation: Callable[[list[Any]], list[Any]],
) -> None:
    document = _authorization()
    _assert_authority_fixture(document)

    verdict = _evaluate_authority({"authorizations": mutation([document])})

    assert verdict is not None


@pytest.mark.parametrize("value", (1.5, 2**53, "\ud800", _deep_value()))
def test_uncanonicalizable_grant_content_returns(value: object) -> None:
    document = _grant()
    declaration = _declaration()
    _assert_grant_fixture(document, declaration)

    verdict = _evaluate_grant(document, {"grant": value, "declarations": [declaration]})

    assert verdict is not None


@pytest.mark.parametrize("value", (1.5, 2**53, "\ud800", _deep_value()))
def test_uncanonicalizable_authority_content_returns(value: object) -> None:
    document = _authorization()
    _assert_authority_fixture(document)

    verdict = _evaluate_authority({"authorizations": [value]})

    assert verdict is not None


def test_over_byte_ceiling_grant_view_returns() -> None:
    document = _grant()
    declaration = _declaration()
    _assert_grant_fixture(document, declaration)

    verdict = _evaluate_grant(document, {"grant": document, "anchor": "x" * 10_000_001})

    assert verdict is not None


def test_over_byte_ceiling_authority_view_returns() -> None:
    document = _authorization()
    _assert_authority_fixture(document)

    verdict = _evaluate_authority({"authorizations": [document], "padding": "x" * 10_000_001})

    assert verdict is not None


def test_hostile_identifier_cannot_false_activate() -> None:
    document = _grant([OTHER_ARTIFACT], ROGUE)
    declaration = _declaration([OTHER_ARTIFACT], ROGUE)
    _assert_grant_fixture(document, declaration)
    normal = _evaluate_grant(document, {"grant": document, "declarations": [declaration]})
    assert normal.grant != "activated"

    hostile = copy.deepcopy(document)
    scope = hostile["scope"]
    assert isinstance(scope, dict)
    scope["artifact_series"] = _HostileIdentifier(ROGUE)
    hostile_declaration = copy.deepcopy(declaration)
    declaration_scope = hostile_declaration["scope"]
    assert isinstance(declaration_scope, dict)
    declaration_scope["artifact_series"] = _HostileIdentifier(ROGUE)
    assert grant.verify_grant(hostile, PUBLISHER_MANIFEST) is True
    assert grant.verify_declaration(hostile_declaration, PUBLISHER_MANIFEST) is True

    verdict = _evaluate_grant(hostile, {"grant": hostile, "declarations": [hostile_declaration]})

    assert verdict is not None
    assert verdict.grant != "activated"


def test_hostile_identifier_cannot_false_authorize() -> None:
    document = _authorization(ROGUE)
    _assert_authority_fixture(document)
    normal = _evaluate_authority({"authorizations": [document]})
    assert normal.publisher_authority != "authorized"

    hostile = copy.deepcopy(document)
    entries = hostile["authorized_issuers"]
    assert isinstance(entries, list)
    entry = entries[0]
    assert isinstance(entry, dict)
    entry["issuer_id"] = _HostileIdentifier(ROGUE)
    _assert_authority_fixture(hostile)

    verdict = _evaluate_authority({"authorizations": [hostile]})

    assert verdict is not None
    assert verdict.publisher_authority != "authorized"


@pytest.mark.parametrize("bad_view", ([], "evidence", 1, ({},)))
def test_only_a_non_object_top_level_view_raises(bad_view: object) -> None:
    with pytest.raises(TypeError):
        _evaluate_grant(_grant(), bad_view)
    with pytest.raises(TypeError):
        _evaluate_authority(bad_view)
