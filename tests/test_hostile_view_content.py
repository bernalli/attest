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

Every hostile wrapper below is a `dict` SUBCLASS over genuine, correctly signed
document bytes: the attack is the read spelling, not the content, so a surface
that authenticates the document still has to survive being read.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from attest import authority, grant, keys, manifests, pq, verify
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


def _hostile(spelling: str, base: dict[str, Any]) -> dict[str, Any]:
    return _SPELLINGS[spelling](base)  # type: ignore[no-any-return]


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


# --- the whole verifier, both rails at once ----------------------------------


@pytest.mark.parametrize("spelling", _SPELLING_IDS)
def test_verify_returns_on_every_hijacked_read_in_either_view(spelling: str) -> None:
    from attest import issue

    envelope = issue.issue(GRANT_PAYLOAD, ISSUER_KEYS, ISSUER_KID)
    import json

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
