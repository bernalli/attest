"""Hostile CONTENT on a caller evidence rail must never make a verifier raise.

Sections 20.3 and 18.4 draw the same line: a wrongly-TYPED view (not an object)
is a caller-contract violation and RAISES, but hostile CONTENT inside a
well-shaped view never does. `authority.entry_for_issuer` states the mechanism
this file tests for: an own-item read (`dict.get(d, k)`) cannot be hijacked by
an overridden `get`, and an enclosing `except Exception` covers the triggers an
own-item read does not reach (`__getitem__`, `__iter__`, `__eq__`).

The property under test is THE NOT RAISING. These tests therefore assert that
the call RETURNS, never that it returns something falsy: a hostile input that
happens to make one trigger fire early would pin an accident of that trigger
rather than the promise. Where the spec does determine an outcome — section
20.4's failure asymmetry, "never `authorized` and never `unauthorized`" — that
is asserted separately, in its own test.

The hostile wrappers below sit over genuine, correctly signed document bytes:
the attack is the read spelling, not the content, so a surface that
authenticates the document still has to survive being read.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from attest import authority, canon, grant, issue, keys, manifests, pq, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
PUBLISHER = "pub.example"
SUCCESSOR = "heritage.example"

ISSUER_KID = f"{ISSUER}/keys/hostile#1"
PUB_KID = f"{PUBLISHER}/keys/hostile#1"
SUCCESSOR_KID = f"{SUCCESSOR}/keys/hostile#1"

VALID_FROM = "2026-01-01T00:00:00Z"
AUTH_ISSUED_AT = "2026-02-01T00:00:00Z"
GRANT_ISSUED_AT = "2026-02-01T00:00:00Z"
DECLARED_AT = "2031-03-01T00:00:00Z"
RECEIPT_ISSUED_AT = "2026-07-02T14:30:00Z"

RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
OTHER_RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v2").hexdigest()
LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-sunset-grant-prose-v1").hexdigest()
BUYER_KP = keys.from_seed(bytes([11]) * 32)


def _hybrid_manifest(issuer: str, kid: str) -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(kid, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    return hk, manifests.build_key_manifest(issuer, 1, VALID_FROM, [entry], hk, kid)


ISSUER_KEYS, ISSUER_MANIFEST = _hybrid_manifest(ISSUER, ISSUER_KID)
PUB_KEYS, PUB_MANIFEST = _hybrid_manifest(PUBLISHER, PUB_KID)
SUCCESSOR_KEYS, SUCCESSOR_MANIFEST = _hybrid_manifest(SUCCESSOR, SUCCESSOR_KID)

AUTHORITY_ENTRY: dict[str, Any] = {
    "issuer_id": ISSUER,
    "valid_from": VALID_FROM,
    "valid_to": None,
    "permissions": [authority.PERMISSION_ISSUE],
    "scope": None,
}
AUTHORIZATION = authority.build_authorization(
    authorization_version=1,
    publisher=PUBLISHER,
    authorized_issuers=[AUTHORITY_ENTRY],
    issued_at=AUTH_ISSUED_AT,
    signing_kp=PUB_KEYS,
    kid=PUB_KID,
)
GRANT = grant.build_grant(
    signing_kp=PUB_KEYS,
    kid=PUB_KID,
    grant_version=1,
    publisher=PUBLISHER,
    scope={"artifact_series": None, "artifacts": [RECEIPT_ART]},
    permissions=["deliver-to-holder"],
    activation={
        "modes": ["publisher-declaration"],
        "fixed_date": None,
        "successor_ids": [SUCCESSOR],
    },
    unprotected_build=True,
    legal_text_uri="https://pub.example/sunset-grant-v1",
    legal_text_sha256=LEGAL_TEXT_SHA256,
    jurisdiction="IT",
    issued_at=GRANT_ISSUED_AT,
)
DECLARATION = grant.build_declaration(
    signing_kp=PUB_KEYS,
    kid=PUB_KID,
    publisher=PUBLISHER,
    scope={"artifact_series": None, "artifacts": [RECEIPT_ART]},
    declared_at=DECLARED_AT,
)

AUTHORITY_PAYLOAD = make_payload(
    attest_version="0.2",
    work={"publisher_id": PUBLISHER},
    issuer={"id": ISSUER},
    issued_at=RECEIPT_ISSUED_AT,
)
GRANT_PAYLOAD = make_payload(
    attest_version="0.2",
    buyer={"pubkey": keys.b64u(BUYER_KP.pub)},
    work={"publisher_id": PUBLISHER},
    license={
        "preservation_pledge": {
            "pledge": "sunset-grant-v1",
            "grant_uri": "https://pub.example/sunset-grant-v1.json",
            "grant_sha256": grant.grant_hash(GRANT),
        }
    },
    survivability={"end_of_life": "sunset-grant"},
)
TRUST_STORE = verify.TrustStore(
    manifests={PUBLISHER: PUB_MANIFEST, ISSUER: ISSUER_MANIFEST, SUCCESSOR: SUCCESSOR_MANIFEST},
    provenance={PUBLISHER: "tls", ISSUER: "tls", SUCCESSOR: "tls"},
)

_BOOM = RuntimeError("hijacked read")


class _GetRaises(dict):  # type: ignore[type-arg]
    def get(self, *args: Any, **kwargs: Any) -> Any:
        raise _BOOM


class _GetItemRaises(dict):  # type: ignore[type-arg]
    """Raises on every member read but `signature`, so the document still
    reaches the surfaces that resolve a signer before reading anything else."""

    def __getitem__(self, key: Any) -> Any:
        if key != "signature":
            raise _BOOM
        return super().__getitem__(key)


class _ContainsRaises(dict):  # type: ignore[type-arg]
    def __contains__(self, key: Any) -> bool:
        raise _BOOM


class _KeysRaises(dict):  # type: ignore[type-arg]
    def keys(self) -> Any:
        raise _BOOM


class _IterRaises(dict):  # type: ignore[type-arg]
    def __iter__(self) -> Any:
        raise _BOOM


class _LenRaises(dict):  # type: ignore[type-arg]
    def __len__(self) -> int:
        raise _BOOM


_SPELLINGS = {
    "get": _GetRaises,
    "getitem": _GetItemRaises,
    "contains": _ContainsRaises,
    "keys": _KeysRaises,
    "iter": _IterRaises,
    "len": _LenRaises,
}
_SPELLING_IDS = sorted(_SPELLINGS)


class _IterRaisesView(dict):  # type: ignore[type-arg]
    def __iter__(self) -> Any:
        raise _BOOM


class _PlainDict(dict):  # type: ignore[type-arg]
    pass


class _LenRaisesList(list):  # type: ignore[type-arg]
    def __len__(self) -> int:
        raise _BOOM


class _IterRaisesList(list):  # type: ignore[type-arg]
    def __iter__(self) -> Any:
        raise _BOOM


def _hostile(spelling: str, base: dict[str, Any]) -> dict[str, Any]:
    return _SPELLINGS[spelling](base)  # type: ignore[no-any-return]


def _receipt_for(payload: dict[str, Any]) -> bytes:
    return json.dumps(issue.issue(payload, ISSUER_KEYS, ISSUER_KID)).encode("utf-8")


def _work_for_artifact(artifact: str) -> dict[str, Any]:
    return {
        "publisher_id": PUBLISHER,
        "artifacts": [
            {
                "role": "installer",
                "platform": "windows-x86_64",
                "filename": "artifact.bin",
                "size_bytes": 1,
                "sha256": artifact,
            }
        ],
    }


def _grant_for_artifacts(
    artifacts: list[str],
    *,
    permissions: list[str] | None = None,
) -> dict[str, Any]:
    return grant.build_grant(
        signing_kp=PUB_KEYS,
        kid=PUB_KID,
        grant_version=1,
        publisher=PUBLISHER,
        scope={"artifact_series": None, "artifacts": sorted(artifacts)},
        permissions=permissions
        if permissions is not None
        else [grant.PERMISSION_DELIVER_TO_HOLDER],
        activation={
            "modes": [grant.MODE_PUBLISHER_DECLARATION],
            "fixed_date": None,
            "successor_ids": [],
        },
        unprotected_build=True,
        legal_text_uri="https://pub.example/sunset-grant-v1",
        legal_text_sha256=LEGAL_TEXT_SHA256,
        jurisdiction="IT",
        issued_at=GRANT_ISSUED_AT,
    )


def _grant_payload_for(document: dict[str, Any], artifact: str) -> dict[str, Any]:
    return make_payload(
        attest_version="0.2",
        buyer={"pubkey": keys.b64u(BUYER_KP.pub)},
        work=_work_for_artifact(artifact),
        license={
            "preservation_pledge": {
                "pledge": grant.PLEDGE_SUNSET_GRANT_V1,
                "grant_uri": "https://pub.example/sunset-grant-v1.json",
                "grant_sha256": grant.grant_hash(document),
            }
        },
        survivability={"end_of_life": grant.END_OF_LIFE_SUNSET_GRANT},
    )


def _declaration_for_artifacts(artifacts: list[str]) -> dict[str, Any]:
    return grant.build_declaration(
        signing_kp=PUB_KEYS,
        kid=PUB_KID,
        publisher=PUBLISHER,
        scope={"artifact_series": None, "artifacts": sorted(artifacts)},
        declared_at=DECLARED_AT,
    )


def _nested_list(depth: int) -> object:
    value: object = []
    for _ in range(depth):
        value = [value]
    return value


def _float_member() -> object:
    return 1.5


def _unsafe_integer_member() -> object:
    return 2**53


def _over_depth_member() -> object:
    return _nested_list(canon.MAX_DEPTH + 1)


def _over_byte_member() -> object:
    return "x" * (verify._MAX_TRANSPARENCY_EVIDENCE_LEN + 1)


_PROFILE_MEMBER_FACTORIES = [
    pytest.param(_float_member, id="float"),
    pytest.param(_unsafe_integer_member, id="unsafe-int"),
    pytest.param(_over_depth_member, id="over-depth"),
    pytest.param(_over_byte_member, id="over-byte"),
]


class _TwoFacedScope(dict):  # type: ignore[type-arg]
    def __init__(self, base: dict[str, Any], free_reads: int, widened_artifacts: list[str]) -> None:
        super().__init__(base)
        self._free_reads = free_reads
        self._widened_artifacts = sorted(widened_artifacts)

    def __getitem__(self, key: Any) -> Any:
        if self._free_reads > 0:
            self._free_reads -= 1
            return super().__getitem__(key)
        if key == "artifacts":
            return self._widened_artifacts
        return super().__getitem__(key)


# --- the authority rail (section 20.3) ---------------------------------------


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
def test_authority_evaluator_returns_on_every_hijacked_read(spelling: str) -> None:
    verify.evaluate_publisher_authority(
        AUTHORITY_PAYLOAD,
        TRUST_STORE,
        {"authorizations": [_hostile(spelling, AUTHORIZATION)]},
    )


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
def test_authority_primitives_return_on_every_hijacked_read(spelling: str) -> None:
    document = _hostile(spelling, AUTHORIZATION)
    authority.verify_authorization(document, PUB_MANIFEST)
    authority.entry_for_issuer(document, ISSUER)
    authority.within_structural_ceiling([document])
    grant.signer_domain(document)


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
def test_authority_entry_predicate_returns_on_every_hijacked_read(spelling: str) -> None:
    authority.entry_authorizes_receipt(_hostile(spelling, AUTHORITY_ENTRY), AUTHORITY_PAYLOAD)


def test_verify_reconstructs_authority_before_post_auth_consumes_entry_scope() -> None:
    """The public verifier must pin the entry scope before any post-auth consumer
    can read the same signed object through a different spelling."""

    entry = {
        "issuer_id": ISSUER,
        "valid_from": VALID_FROM,
        "valid_to": None,
        "permissions": [authority.PERMISSION_ISSUE],
        "scope": {"artifact_series": None, "artifacts": [RECEIPT_ART]},
    }
    document = authority.build_authorization(
        authorization_version=1,
        publisher=PUBLISHER,
        authorized_issuers=[entry],
        issued_at=AUTH_ISSUED_AT,
        signing_kp=PUB_KEYS,
        kid=PUB_KID,
    )
    hostile = copy.deepcopy(document)
    hostile["authorized_issuers"][0]["scope"] = _TwoFacedScope(
        entry["scope"],
        4,
        [RECEIPT_ART, OTHER_RECEIPT_ART],
    )
    payload = make_payload(
        attest_version="0.2",
        work=_work_for_artifact(OTHER_RECEIPT_ART),
        issuer={"id": ISSUER},
        issued_at=RECEIPT_ISSUED_AT,
    )

    result = verify.verify(
        _receipt_for(payload),
        TRUST_STORE,
        authority_view={"authorizations": [hostile]},
    )

    assert result.publisher_authority != "authorized"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_authority_string_subclass_data_as_plain_string() -> None:
    entry = dict(AUTHORITY_ENTRY)
    entry["issuer_id"] = _EvilStr(ISSUER)
    entry["permissions"] = [_EvilStr(authority.PERMISSION_ISSUE)]
    document = authority.build_authorization(
        authorization_version=1,
        publisher=PUBLISHER,
        authorized_issuers=[entry],
        issued_at=AUTH_ISSUED_AT,
        signing_kp=PUB_KEYS,
        kid=PUB_KID,
    )

    result = verify.verify(
        _receipt_for(AUTHORITY_PAYLOAD),
        TRUST_STORE,
        authority_view={"authorizations": [document]},
    )

    assert result.publisher_authority == "authorized"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_authority_dict_subclass_data_as_plain_object() -> None:
    result = verify.verify(
        _receipt_for(AUTHORITY_PAYLOAD),
        TRUST_STORE,
        authority_view=_PlainDict({"authorizations": [_PlainDict(AUTHORIZATION)]}),
    )

    assert result.publisher_authority == "authorized"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_authority_list_subclass_data_when_len_raises() -> None:
    result = verify.verify(
        _receipt_for(AUTHORITY_PAYLOAD),
        TRUST_STORE,
        authority_view={"authorizations": _LenRaisesList([AUTHORIZATION])},
    )

    assert result.publisher_authority == "authorized"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_authority_list_subclass_data_when_iteration_raises() -> None:
    # 18.4: a subtype carrying ordinary data "survives as its plain base type,
    # with any behaviour it defined discarded -- the identity of the object is
    # lost, never the data". An overridden `__iter__` is behaviour; the list's
    # own storage reads without raising through `list.__getitem__`, so refusal
    # here would be refusing a value FOR BEING A SUBTYPE, which 18.4 forbids.
    result = verify.verify(
        _receipt_for(AUTHORITY_PAYLOAD),
        TRUST_STORE,
        authority_view={"authorizations": _IterRaisesList([AUTHORIZATION])},
    )

    assert result.publisher_authority == "authorized"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_authority_view_subclass_data_when_iteration_raises() -> None:
    result = verify.verify(
        _receipt_for(AUTHORITY_PAYLOAD),
        TRUST_STORE,
        authority_view=_IterRaisesView({"authorizations": [AUTHORIZATION]}),
    )

    assert result.publisher_authority == "authorized"
    assert result.ok is True
    assert result.trust == "verified"


@pytest.mark.parametrize("bad_member_factory", _PROFILE_MEMBER_FACTORIES)
def test_verify_degrades_authority_view_values_outside_the_profile(
    bad_member_factory: Any,
) -> None:
    result = verify.verify(
        _receipt_for(AUTHORITY_PAYLOAD),
        TRUST_STORE,
        authority_view={
            "authorizations": [AUTHORIZATION],
            "profile_boundary_probe": bad_member_factory(),
        },
    )

    assert result.publisher_authority != "authorized"
    assert result.ok is True
    assert result.trust == "verified"


# --- the grant rail (section 18.4) -------------------------------------------


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
@pytest.mark.parametrize("member", ["grant", "later_grants", "declarations"])
def test_grant_evaluator_returns_on_every_hijacked_read(spelling: str, member: str) -> None:
    if member == "grant":
        view: dict[str, Any] = {"grant": _hostile(spelling, GRANT)}
    elif member == "later_grants":
        view = {"grant": GRANT, "later_grants": [_hostile(spelling, GRANT)]}
    else:
        view = {"grant": GRANT, "declarations": [_hostile(spelling, DECLARATION)]}
    verify.evaluate_grant(GRANT_PAYLOAD, TRUST_STORE, view)


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
def test_grant_primitives_return_on_every_hijacked_read(spelling: str) -> None:
    document = _hostile(spelling, GRANT)
    declaration = _hostile(spelling, DECLARATION)
    grant.verify_grant(document, PUB_MANIFEST)
    grant.signer_domain(document)
    grant.grant_covers_receipt(document, GRANT_PAYLOAD)
    grant.is_non_narrowing(GRANT, document)
    grant.is_non_narrowing(document, GRANT)
    grant.prose_differs(GRANT, document)
    grant.verify_declaration(declaration, PUB_MANIFEST)
    grant.declaration_signer_role(declaration, GRANT)
    grant.declaration_covers_grant(declaration, GRANT)


def test_verify_reconstructs_grant_before_declaration_consumes_scope() -> None:
    wide_grant = _grant_for_artifacts([RECEIPT_ART, OTHER_RECEIPT_ART])
    narrow_declaration = _declaration_for_artifacts([RECEIPT_ART])
    hostile_declaration = dict(narrow_declaration)
    hostile_declaration["scope"] = _TwoFacedScope(
        narrow_declaration["scope"],
        2,
        [RECEIPT_ART, OTHER_RECEIPT_ART],
    )
    payload = _grant_payload_for(wide_grant, OTHER_RECEIPT_ART)

    result = verify.verify(
        _receipt_for(payload),
        TRUST_STORE,
        grant_view={"grant": wide_grant, "declarations": [hostile_declaration]},
    )

    assert result.grant != "activated"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_grant_string_subclass_data_as_plain_string() -> None:
    document = _grant_for_artifacts(
        [RECEIPT_ART],
        permissions=[_EvilStr(grant.PERMISSION_DELIVER_TO_HOLDER)],
    )
    payload = _grant_payload_for(document, RECEIPT_ART)

    result = verify.verify(
        _receipt_for(payload),
        TRUST_STORE,
        grant_view={"grant": document, "declarations": [DECLARATION]},
    )

    assert result.grant == "activated"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_grant_dict_subclass_data_as_plain_object() -> None:
    result = verify.verify(
        _receipt_for(GRANT_PAYLOAD),
        TRUST_STORE,
        grant_view=_PlainDict(
            {"grant": _PlainDict(GRANT), "declarations": [_PlainDict(DECLARATION)]}
        ),
    )

    assert result.grant == "activated"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_grant_list_subclass_data_when_len_raises() -> None:
    result = verify.verify(
        _receipt_for(GRANT_PAYLOAD),
        TRUST_STORE,
        grant_view={"grant": GRANT, "declarations": _LenRaisesList([DECLARATION])},
    )

    assert result.grant == "activated"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_grant_list_subclass_data_when_iteration_raises() -> None:
    result = verify.verify(
        _receipt_for(GRANT_PAYLOAD),
        TRUST_STORE,
        grant_view={"grant": GRANT, "declarations": _IterRaisesList([DECLARATION])},
    )

    assert result.grant == "activated"
    assert result.ok is True
    assert result.trust == "verified"


def test_verify_preserves_grant_view_subclass_data_when_iteration_raises() -> None:
    result = verify.verify(
        _receipt_for(GRANT_PAYLOAD),
        TRUST_STORE,
        grant_view=_IterRaisesView({"grant": GRANT, "declarations": [DECLARATION]}),
    )

    assert result.grant == "activated"
    assert result.ok is True
    assert result.trust == "verified"


@pytest.mark.parametrize("bad_member_factory", _PROFILE_MEMBER_FACTORIES)
def test_verify_degrades_grant_view_values_outside_the_profile(
    bad_member_factory: Any,
) -> None:
    result = verify.verify(
        _receipt_for(GRANT_PAYLOAD),
        TRUST_STORE,
        grant_view={
            "grant": GRANT,
            "declarations": [DECLARATION],
            "profile_boundary_probe": bad_member_factory(),
        },
    )

    assert result.grant != "activated"
    assert result.ok is True
    assert result.trust == "verified"


# --- the whole verifier, both rails at once ----------------------------------


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
def test_verify_returns_on_every_hijacked_read_in_either_view(spelling: str) -> None:
    envelope = issue.issue(GRANT_PAYLOAD, ISSUER_KEYS, ISSUER_KID)

    verify.verify(
        json.dumps(envelope).encode(),
        TRUST_STORE,
        grant_view={"grant": _hostile(spelling, GRANT)},
        authority_view={"authorizations": [_hostile(spelling, AUTHORIZATION)]},
    )


# --- the outcome the spec DOES determine, asserted on its own ----------------


NON_AUTHORIZING = authority.build_authorization(
    authorization_version=1,
    publisher=PUBLISHER,
    authorized_issuers=[],
    issued_at=AUTH_ISSUED_AT,
    signing_kp=PUB_KEYS,
    kid=PUB_KID,
)


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
def test_hijacked_read_can_never_buy_authorized(spelling: str) -> None:
    """Section 20.4's failure asymmetry, in the only direction a hijacked read
    could profit from: a document that does NOT authorize this issuer must not
    become `authorized` because of how its members were read.

    Deliberately NOT asserted here: which of `unattested`/`unauthorized` a
    hijacked read lands on. That varies with whether the hijack happens to make
    the document unreadable, which is an accident of the wrapper rather than a
    property of the spec — pinning it would test the trigger, not the promise.
    """
    verdict = verify.evaluate_publisher_authority(
        AUTHORITY_PAYLOAD,
        TRUST_STORE,
        {
            "authorizations": [_hostile(spelling, NON_AUTHORIZING)],
            "current_authorization_version": 1,
        },
    )
    assert verdict.publisher_authority != "authorized"


# --- hostile VALUES, not just hostile containers ------------------------------
#
# An own-item read defeats an overridden `get`, but it hands back whatever the
# member holds, and what a verifier then DOES with that value is compare it.
# `authority.entry_for_issuer` names this explicitly: the enclosing guard is
# what covers "the triggers an own-item read does not cover (`__eq__`,
# `__getitem__`)". A `str` subclass canonicalizes — and therefore signs and
# authenticates — exactly like the `str` it shadows, so this reaches the
# comparisons that run AFTER a document has authenticated.


class _EvilStr(str):
    """A string that refuses to be compared. Canonicalizes as its own text, so
    a document carrying it authenticates under a signature made over the plain
    spelling."""

    __hash__ = str.__hash__

    def __eq__(self, other: object) -> bool:
        raise _BOOM

    def __ne__(self, other: object) -> bool:
        raise _BOOM


def _with_evil_value(document: dict[str, Any], member: str) -> dict[str, Any]:
    poisoned = dict(document)
    poisoned[member] = _EvilStr(document[member])
    return poisoned


@pytest.mark.parametrize("member", ["publisher", "issued_at"])
def test_authority_evaluator_returns_on_uncomparable_member_value(member: str) -> None:
    verify.evaluate_publisher_authority(
        AUTHORITY_PAYLOAD,
        TRUST_STORE,
        {"authorizations": [_with_evil_value(AUTHORIZATION, member)]},
    )


@pytest.mark.parametrize("member", ["publisher", "issued_at", "legal_text_uri"])
def test_grant_evaluator_returns_on_uncomparable_member_value(member: str) -> None:
    verify.evaluate_grant(GRANT_PAYLOAD, TRUST_STORE, {"grant": _with_evil_value(GRANT, member)})


@pytest.mark.parametrize("member", ["publisher", "issued_at"])
def test_grant_primitives_return_on_uncomparable_member_value(member: str) -> None:
    document = _with_evil_value(GRANT, member)
    grant.verify_grant(document, PUB_MANIFEST)
    grant.signer_domain(document)
    grant.is_non_narrowing(GRANT, document)
    grant.prose_differs(GRANT, document)
    grant.grant_covers_receipt(document, GRANT_PAYLOAD)
