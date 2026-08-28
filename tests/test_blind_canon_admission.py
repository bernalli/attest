"""Adversarial admission tests for caller-owned canonicalization inputs."""

from __future__ import annotations

import copy
import json
import signal
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from attest import authority, canon, issue, keys, manifests, pq, revocation, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
PUBLISHER = "pub.example"
ISSUER_KID = f"{ISSUER}/keys/blind-canon#1"
PUBLISHER_KID = f"{PUBLISHER}/keys/blind-canon#1"
VALID_FROM = "2026-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2026-01-01T00:00:00Z"
AUTHORIZATION_ISSUED_AT = "2026-02-01T00:00:00Z"
REVOCATION_AT = "2026-07-03T00:00:00Z"

ISSUER_KEYS = keys.from_seed(bytes([41]) * 32)
PUBLISHER_KEYS = pq.HybridSigningKeys(ed=keys.from_seed(bytes([42]) * 32), mldsa=pq.generate())


def _issuer_manifest() -> dict[str, Any]:
    entry = manifests.key_entry(ISSUER_KID, ISSUER_KEYS.pub, VALID_FROM, None, "active")
    return manifests.build_key_manifest(
        ISSUER,
        1,
        MANIFEST_ISSUED_AT,
        [entry],
        ISSUER_KEYS,
        ISSUER_KID,
    )


def _publisher_manifest() -> dict[str, Any]:
    entry = manifests.key_entry(
        PUBLISHER_KID,
        PUBLISHER_KEYS.ed.pub,
        VALID_FROM,
        pub_ml_dsa_65=PUBLISHER_KEYS.mldsa.pub,
    )
    return manifests.build_key_manifest(
        PUBLISHER,
        1,
        MANIFEST_ISSUED_AT,
        [entry],
        PUBLISHER_KEYS,
        PUBLISHER_KID,
    )


ISSUER_MANIFEST = _issuer_manifest()
PUBLISHER_MANIFEST = _publisher_manifest()


def _trust_store() -> verify.TrustStore:
    return verify.TrustStore(
        manifests={ISSUER: ISSUER_MANIFEST, PUBLISHER: PUBLISHER_MANIFEST},
        provenance={ISSUER: "tls", PUBLISHER: "tls"},
    )


def _payload(*, revocability: str = "none") -> dict[str, Any]:
    return make_payload(
        issuer={"id": ISSUER},
        work={"publisher_id": PUBLISHER},
        license={"revocability": revocability},
    )


def _envelope_bytes(payload: dict[str, Any]) -> bytes:
    envelope = issue.issue(payload, ISSUER_KEYS, ISSUER_KID)
    return json.dumps(envelope).encode("utf-8")


def _authorization_entry(issuer_id: object = ISSUER) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "valid_from": VALID_FROM,
        "valid_to": None,
        "permissions": [authority.PERMISSION_ISSUE],
        "scope": None,
    }


def _authorization(*, entries: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return authority.build_authorization(
        authorization_version=1,
        publisher=PUBLISHER,
        authorized_issuers=[_authorization_entry()] if entries is None else entries,
        issued_at=AUTHORIZATION_ISSUED_AT,
        signing_kp=PUBLISHER_KEYS,
        kid=PUBLISHER_KID,
    )


def _verify_authority_view(authority_view: dict[str, Any]) -> verify.VerificationResult:
    return verify.verify(
        _envelope_bytes(_payload()),
        _trust_store(),
        authority_view=authority_view,
    )


def _revocation_record() -> dict[str, Any]:
    return revocation.build_record(
        make_payload()["receipt_id"],
        "revoked",
        REVOCATION_AT,
        ISSUER_KEYS,
        ISSUER_KID,
    )


def _verify_revocation_view(revocation_view: list[dict[str, Any]]) -> verify.VerificationResult:
    return verify.verify(
        _envelope_bytes(_payload(revocability="policy")),
        _trust_store(),
        revocation_view=revocation_view,
    )


def _assert_receipt_layer_still_valid(result: verify.VerificationResult) -> None:
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.trust == "verified"


class _CollapsingKey(str):
    def __new__(cls, value: str, salt: int = 0) -> _CollapsingKey:
        item = str.__new__(cls, value)
        item._salt = salt
        return item

    def __hash__(self) -> int:
        return hash(("_collapsing_key", str.__str__(self), self._salt))

    def __eq__(self, other: object) -> bool:
        return self is other


def _object_with_collapsing_key(name: str, first: object, second: object) -> dict[object, object]:
    shadow = _CollapsingKey(name, 1)
    return {shadow: first, name: second}


def _wrap_at_path(value: object, path: tuple[str, ...]) -> object:
    wrapped = value
    for depth, step in enumerate(reversed(path)):
        if step == "object":
            wrapped = {f"level_{depth}": wrapped, f"sibling_{depth}": "kept"}
        else:
            wrapped = [f"sibling_{depth}", wrapped]
    return wrapped


KEY_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=1,
    max_size=16,
)
NESTING_PATH = st.lists(st.sampled_from(("object", "array")), max_size=10).map(tuple)


@given(key=KEY_TEXT, path=NESTING_PATH)
@settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_dumps_rejects_key_collapse_at_any_nested_position(key: str, path: tuple[str, ...]) -> None:
    value = _wrap_at_path(
        _object_with_collapsing_key(
            key,
            {"chosen_by_insertion_order": "shadow"},
            {"chosen_by_insertion_order": "plain"},
        ),
        path,
    )

    with pytest.raises(canon.CanonError):
        canon.dumps(value)


class _InjectingInt(int):
    def __str__(self) -> str:
        return '0,"injected_member":true'


class _RaisingInt(int):
    def __str__(self) -> str:
        raise RuntimeError("host integer conversion")


class _AlteringIterStr(str):
    def __iter__(self) -> Iterator[str]:
        return iter("altered")


class _RaisingIterStr(str):
    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("host string iteration")


@pytest.mark.parametrize(
    ("value", "own_data"),
    [
        ({"scalar": _InjectingInt(0)}, {"scalar": 0}),
        ({"scalar": _RaisingInt(7)}, {"scalar": 7}),
        ({"scalar": _AlteringIterStr("plain")}, {"scalar": "plain"}),
        ({"scalar": _RaisingIterStr("plain")}, {"scalar": "plain"}),
    ],
    ids=("int-injects-member", "int-raises", "str-alters-by-iter", "str-raises-by-iter"),
)
def test_scalar_subclasses_cannot_change_member_structure_or_escape_contract(
    value: object, own_data: object
) -> None:
    try:
        encoded = canon.canonical_bytes(value)
    except canon.CanonError:
        return

    assert canon.loads_strict(encoded) == own_data


class _LyingAuthorizationArray(list[Any]):
    def __len__(self) -> int:
        return 0

    def __iter__(self) -> Iterator[Any]:
        return iter(())

    def __getitem__(self, index: int) -> Any:
        raise RuntimeError("host list indexing")


def test_verify_authority_admits_plain_data_from_hostile_array_subclass() -> None:
    document = _authorization()

    result = _verify_authority_view({"authorizations": _LyingAuthorizationArray([document])})

    _assert_receipt_layer_still_valid(result)
    assert result.ok is True
    assert result.publisher_authority == "authorized"
    assert result.publisher_authority_trust == "verified"
    assert result.warnings == ()


class _DenyingEqStr(str):
    def __eq__(self, other: object) -> bool:
        return False

    def __hash__(self) -> int:
        return hash(str.__str__(self))


def test_verify_authority_consumes_reconstructed_scalar_not_hostile_equality() -> None:
    document = _authorization(entries=[_authorization_entry(_DenyingEqStr(ISSUER))])

    result = _verify_authority_view({"authorizations": [document]})

    _assert_receipt_layer_still_valid(result)
    assert result.ok is True
    assert result.publisher_authority == "authorized"
    assert result.publisher_authority_trust == "verified"
    assert result.warnings == ()


def test_verify_authority_collapsed_document_key_is_set_aside_alone() -> None:
    genuine = _authorization()
    ambiguous: dict[object, Any] = {_CollapsingKey("publisher", 1): "attacker.example"}
    for key, value in copy.deepcopy(genuine).items():
        ambiguous[key] = value

    result = _verify_authority_view({"authorizations": [ambiguous, genuine]})  # type: ignore[list-item]

    _assert_receipt_layer_still_valid(result)
    assert result.ok is True
    assert result.publisher_authority == "authorized"
    assert result.publisher_authority_trust == "verified"
    assert result.warnings == ("authorization_invalid_ignored",)


def test_verify_authority_collapsed_current_version_cannot_create_denial() -> None:
    denial_document = _authorization(entries=[])
    view: dict[object, Any] = {
        "authorizations": [denial_document],
        _CollapsingKey("current_authorization_version", 1): 2,
        "current_authorization_version": 1,
    }

    result = _verify_authority_view(view)  # type: ignore[arg-type]

    _assert_receipt_layer_still_valid(result)
    assert result.ok is True
    assert result.publisher_authority == "unattested"
    assert result.publisher_authority_trust == "verified"
    assert result.warnings == ("publisher_claim_unattested",)


class _RaisingGetRecord(dict[str, Any]):
    def get(self, key: object, default: object = None) -> object:
        raise RuntimeError("host mapping get")


def test_verify_revocation_record_accessor_exception_is_non_admission_not_escape() -> None:
    result = _verify_revocation_view([_RaisingGetRecord(_revocation_record())])

    _assert_receipt_layer_still_valid(result)
    assert result.revocation == "unknown"
    assert result.ok is True


class _FreshIterRevocationView(list[Any]):
    def __iter__(self) -> Iterator[Any]:
        return (copy.deepcopy(list.__getitem__(self, index)) for index in range(list.__len__(self)))


def test_verify_revocation_view_uses_one_reconstruction_for_authentication_and_match() -> None:
    result = _verify_revocation_view(_FreshIterRevocationView([_revocation_record()]))  # type: ignore[arg-type]

    _assert_receipt_layer_still_valid(result)
    assert result.revocation == "revoked"
    assert result.ok is False


class _InfiniteItemsRecord(dict[str, Any]):
    def items(self) -> Iterator[tuple[str, Any]]:
        while True:
            yield ("receipt_id", dict.__getitem__(self, "receipt_id"))


@contextmanager
def _wall_time_limit(seconds: float) -> Iterator[None]:
    def _raise_timeout(signum: int, frame: object) -> None:
        del signum, frame
        raise AssertionError(f"call did not return within {seconds:.1f}s")

    old_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, old_handler)


def test_verify_revocation_record_infinite_items_returns_within_wall_time() -> None:
    with _wall_time_limit(2.0):
        result = _verify_revocation_view([_InfiniteItemsRecord(_revocation_record())])

    _assert_receipt_layer_still_valid(result)
    assert result.revocation == "revoked"
    assert result.ok is False
