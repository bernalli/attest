"""Tests for attest.authority — publisher authorization primitives (v0.2 §20).

Covers the publisher authorization manifest document (§20.2), its hash and its
authentication, the membership predicate §20.4 step 9 is built out of, the
structural ceiling of the evidence channel (§20.3), the shared
`authorization_version` predicate (§20.2/§20.3) and the successor discipline
the builder refuses to sign against (§20.2, entry preservation). Authority
EVALUATION — §20.4's ordered steps, the `publisher_authority`/
`publisher_authority_trust` result components — is a separate surface and is
not exercised here.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from attest import authority, canon, keys, manifests, pq
from tests.helpers import make_payload

PUBLISHER = "pub.example"
# The `issuer.id` of `tests.helpers.make_payload`, so an entry naming it is the
# entry §20.4 step 9 looks up for that receipt.
ISSUER = "store.example.com"
OTHER_ISSUER = "marketplace.example"
PUB_KID = f"{PUBLISHER}/keys/authority#1"

VALID_FROM = "2026-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2026-01-01T00:00:00Z"
AUTH_ISSUED_AT = "2026-02-01T00:00:00Z"
LATER_ISSUED_AT = "2026-09-01T00:00:00Z"
ENTRY_FROM = "2026-01-01T00:00:00Z"

# `tests.helpers.make_payload`'s own `issued_at`, and the series and artifact
# hash it puts in `work`.
RECEIPT_ISSUED_AT = "2026-07-02T14:30:00Z"
RECEIPT_SERIES = "store.example.com/works/EXG-001"
RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
OTHER_ART = hashlib.sha256(b"artifact-elsewhere").hexdigest()


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
    artifact_series: str | None = RECEIPT_SERIES, artifacts: list[str] | None = None
) -> dict[str, Any]:
    return {
        "artifact_series": artifact_series,
        "artifacts": sorted(artifacts if artifacts is not None else [RECEIPT_ART]),
    }


# A sentinel distinct from `None`, so `permissions=None` builds an entry whose
# `permissions` member IS null rather than falling back to the default.
_DEFAULT = object()


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
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str = PUB_KID,
    **overrides: Any,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "authorization_version": 1,
        "publisher": PUBLISHER,
        "authorized_issuers": [_entry()],
        "issued_at": AUTH_ISSUED_AT,
    }
    body.update(overrides)
    return authority.build_authorization(signing_kp=signing_kp, kid=kid, **body)


def _unsigned_authorization(**overrides: Any) -> dict[str, Any]:
    """A document plus a placeholder signature — for the structural predicates
    that never touch the signature."""
    return _authorization(keys.generate(), **overrides)


# --- registered vocabulary and ceilings (§20.2, §20.3) -----------------------


def test_registered_permission_literals_are_verbatim() -> None:
    assert authority.PERMISSION_ISSUE == "issue"
    assert authority.PERMISSION_DELEGATE == "delegate"


def test_ceiling_constants_are_the_specified_values() -> None:
    assert authority.MAX_AUTHORIZED_ISSUERS == 4096
    assert authority.MAX_AUTHORITY_DOCUMENTS == 64


# --- the document: build, hash, roundtrip (§20.2) ----------------------------


def test_authorization_has_exactly_the_five_members() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)

    assert set(document) == {
        "authorization_version",
        "publisher",
        "authorized_issuers",
        "issued_at",
        "signature",
    }


def test_classical_authorization_roundtrips() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)

    assert "sig_ml_dsa_65" not in document["signature"]
    assert authority.verify_authorization(document, key_manifest)


def test_hybrid_authorization_roundtrips_with_both_legs() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _authorization(hk)

    assert "sig" in document["signature"]
    assert "sig_ml_dsa_65" in document["signature"]
    assert authority.verify_authorization(document, key_manifest)


def test_an_empty_authorized_issuers_array_is_a_valid_first_document() -> None:
    """§20.2: an EMPTY array is meaningful on a first document — 'no one has
    ever been authorized', a publisher that sells only direct."""
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _authorization(hk, authorized_issuers=[])

    assert authority.verify_authorization(document, key_manifest)


def test_several_entries_sorted_by_issuer_id_roundtrip() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    entries = sorted(
        [_entry(issuer_id=OTHER_ISSUER), _entry()], key=lambda entry: str(entry["issuer_id"])
    )
    document = _authorization(hk, authorized_issuers=entries)

    assert authority.verify_authorization(document, key_manifest)


def test_authorization_hash_is_over_the_entire_signed_document() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)

    assert (
        authority.authorization_hash(document)
        == hashlib.sha256(canon.canonical_bytes(document)).hexdigest()
    )
    # Explicitly NOT the body-only hash the signature itself is computed over.
    body = {key: value for key, value in document.items() if key != "signature"}
    assert (
        authority.authorization_hash(document)
        != hashlib.sha256(canon.canonical_bytes(body)).hexdigest()
    )


def test_authorization_hash_is_stable_across_calls() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)

    assert authority.authorization_hash(document) == authority.authorization_hash(document)


def test_authorization_hash_is_sensitive_to_the_signature() -> None:
    """§20.2's hashing discipline covers the document's OWN `signature`
    member: two documents identical but for their signature bytes are two
    different log entries, never one deduplicated document."""
    first, _ = _ed_manifest(PUBLISHER, PUB_KID)
    second, _ = _ed_manifest(PUBLISHER, PUB_KID)
    one = _authorization(first)
    two = _authorization(second)

    assert one["signature"] != two["signature"]
    assert authority.authorization_hash(one) != authority.authorization_hash(two)


def test_tampered_authorization_body_fails_verification() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)
    document["authorized_issuers"][0]["valid_to"] = "2030-01-01T00:00:00Z"

    assert not authority.verify_authorization(document, key_manifest)


def test_authorization_is_a_closed_object_unknown_member_rejected() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _authorization(hk)
    document["extra"] = "surprise"

    assert not authority.verify_authorization(document, key_manifest)


def test_authorization_missing_member_rejected() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _authorization(hk)
    del document["issued_at"]

    assert not authority.verify_authorization(document, key_manifest)


def test_classical_only_authorization_against_hybrid_key_fails_closed() -> None:
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _authorization(hk)
    del document["signature"]["sig_ml_dsa_65"]

    assert not authority.verify_authorization(document, key_manifest)


def test_stray_pq_leg_against_classical_key_fails_closed() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    hk, _ = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)
    body = {key: value for key, value in document.items() if key != "signature"}
    document["signature"]["sig_ml_dsa_65"] = keys.b64u(
        pq.sign(canon.canonical_bytes(body), hk.mldsa)
    )

    assert not authority.verify_authorization(document, key_manifest)


def test_authorization_signed_by_retired_key_rejected() -> None:
    kp = keys.generate()
    entry = manifests.key_entry(PUB_KID, kp.pub, VALID_FROM, status="retired")
    signer_entry = manifests.key_entry(f"{PUBLISHER}/keys/authority#2", kp.pub, VALID_FROM)
    key_manifest = manifests.build_key_manifest(
        PUBLISHER,
        1,
        MANIFEST_ISSUED_AT,
        [entry, signer_entry],
        kp,
        f"{PUBLISHER}/keys/authority#2",
    )
    document = _authorization(kp)

    assert not authority.verify_authorization(document, key_manifest)


def test_authorization_issued_outside_key_window_rejected() -> None:
    kp = keys.generate()
    entry = manifests.key_entry(PUB_KID, kp.pub, "2026-03-01T00:00:00Z")
    key_manifest = manifests.build_key_manifest(
        PUBLISHER, 1, "2026-03-01T00:00:00Z", [entry], kp, PUB_KID
    )
    document = _authorization(kp)  # issued_at 2026-02-01, before valid_from

    assert not authority.verify_authorization(document, key_manifest)


def test_authorization_issued_after_the_key_window_closed_rejected() -> None:
    kp = keys.generate()
    entry = manifests.key_entry(PUB_KID, kp.pub, VALID_FROM, valid_to="2026-01-15T00:00:00Z")
    key_manifest = manifests.build_key_manifest(
        PUBLISHER, 1, MANIFEST_ISSUED_AT, [entry], kp, PUB_KID
    )
    document = _authorization(kp)

    assert not authority.verify_authorization(document, key_manifest)


def test_authorization_against_self_inconsistent_manifest_rejected() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)
    key_manifest["issued_at"] = "2026-06-01T00:00:00Z"

    assert not authority.verify_authorization(document, key_manifest)
    # ...and the signature-only half, which presumes an already-checked
    # manifest, still accepts it: the two halves are distinct on purpose.
    assert authority.verify_authorization_signature(document, key_manifest)


def test_authorization_signed_by_an_unknown_kid_rejected() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp, kid=f"{PUBLISHER}/keys/authority#9")

    assert not authority.verify_authorization(document, key_manifest)


# --- shape (§20.2) ------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        # authorization_version (§20.2, the `manifest_version` discipline)
        {"authorization_version": 0},
        {"authorization_version": -1},
        {"authorization_version": True},
        {"authorization_version": "1"},
        {"authorization_version": None},
        # publisher
        {"publisher": "Pub.Example"},
        {"publisher": "not-a-domain"},
        {"publisher": ""},
        {"publisher": None},
        # authorized_issuers, the array itself
        {"authorized_issuers": None},
        {"authorized_issuers": {"store.example.com": {}}},
        {"authorized_issuers": [None]},
        {"authorized_issuers": ["store.example.com"]},
        # sortedness IS the duplicate rejection (§20.2): both a repeat and a
        # descending pair break strict ascent by `issuer_id`.
        {"authorized_issuers": [_entry(), _entry()]},
        {"authorized_issuers": [_entry(issuer_id="z.example"), _entry(issuer_id="a.example")]},
        {
            "authorized_issuers": [
                _entry(issuer_id="a.example"),
                _entry(issuer_id="z.example"),
                _entry(issuer_id="m.example"),
            ]
        },
        # entry members, closed exactly
        {"authorized_issuers": [{**_entry(), "extra": "surprise"}]},
        {"authorized_issuers": [{key: value for key, value in _entry().items() if key != "scope"}]},
        {"authorized_issuers": [_entry(issuer_id="Store.Example.Com")]},
        {"authorized_issuers": [_entry(issuer_id="not-a-domain")]},
        {"authorized_issuers": [_entry(issuer_id=None)]},
        {"authorized_issuers": [_entry(valid_from="2026-01-01")]},
        {"authorized_issuers": [_entry(valid_from=None)]},
        {"authorized_issuers": [_entry(valid_from=1767225600)]},
        # `valid_to` is null OR a timestamp — anything else is refused
        {"authorized_issuers": [_entry(valid_to="2026-05-01")]},
        {"authorized_issuers": [_entry(valid_to="2026-13-01T00:00:00Z")]},
        {"authorized_issuers": [_entry(valid_to="")]},
        {"authorized_issuers": [_entry(valid_to=0)]},
        {"authorized_issuers": [_entry(valid_to=False)]},
        # permissions: non-empty, sorted, duplicate-free, strings
        {"authorized_issuers": [_entry(permissions=[])]},
        {"authorized_issuers": [_entry(permissions=["issue", "delegate"])]},
        {"authorized_issuers": [_entry(permissions=["issue", "issue"])]},
        {"authorized_issuers": [_entry(permissions=[""])]},
        {"authorized_issuers": [_entry(permissions=["issue", 42])]},
        {"authorized_issuers": [_entry(permissions="issue")]},
        {"authorized_issuers": [_entry(permissions=None)]},
        # scope: null, or §18.2's scope shape
        {"authorized_issuers": [_entry(scope=42)]},
        {"authorized_issuers": [_entry(scope={})]},
        {"authorized_issuers": [_entry(scope={"artifact_series": RECEIPT_SERIES})]},
        {"authorized_issuers": [_entry(scope={"artifact_series": None, "artifacts": []})]},
        {"authorized_issuers": [_entry(scope={"artifact_series": "", "artifacts": [RECEIPT_ART]})]},
        {
            "authorized_issuers": [
                _entry(scope={"artifact_series": RECEIPT_SERIES, "artifacts": [OTHER_ART, ""]})
            ]
        },
        {
            "authorized_issuers": [
                _entry(
                    scope={
                        "artifact_series": RECEIPT_SERIES,
                        "artifacts": [RECEIPT_ART, RECEIPT_ART],
                    }
                )
            ]
        },
        {
            "authorized_issuers": [
                _entry(
                    scope={"artifact_series": RECEIPT_SERIES, "artifacts": [RECEIPT_ART.upper()]}
                )
            ]
        },
        # issued_at
        {"issued_at": "2026-02-01"},
        {"issued_at": ""},
        {"issued_at": None},
    ],
)
def test_malformed_authorization_members_fail_closed(overrides: dict[str, Any]) -> None:
    """The body is SIGNED as given: only the shape check can reject it, so a
    passing assertion here is evidence of the shape check and not of a broken
    signature."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp, **overrides)

    assert not authority.verify_authorization(document, key_manifest)


def test_a_non_object_signature_member_is_refused() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)
    document["signature"] = "not-an-object"

    assert not authority.verify_authorization(document, key_manifest)


def test_scope_covering_only_one_of_the_two_scope_members_is_accepted() -> None:
    """§18.2's scope shape, reused verbatim: at least one of the two halves
    must be non-empty, and either alone is a valid scope."""
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    series_only = _authorization(hk, authorized_issuers=[_entry(scope=_scope(artifacts=[]))])
    artifacts_only = _authorization(
        hk, authorized_issuers=[_entry(scope=_scope(artifact_series=None))]
    )

    assert authority.verify_authorization(series_only, key_manifest)
    assert authority.verify_authorization(artifacts_only, key_manifest)


def test_an_unregistered_permission_is_carried_never_fatal() -> None:
    """§18.2's directional rule, restated by §20.2: unregistered values are
    carried, never fatal — a later registration must not retroactively
    invalidate documents that predate it."""
    hk, key_manifest = _hybrid_manifest(PUBLISHER, PUB_KID)
    document = _authorization(
        hk, authorized_issuers=[_entry(permissions=sorted(["issue", "resell-in-eu"]))]
    )

    assert authority.verify_authorization(document, key_manifest)


@pytest.mark.parametrize("version", [2**53, 1.0])
def test_an_unrepresentable_authorization_version_never_becomes_a_wire_document(
    version: Any,
) -> None:
    """`authorization_version` is bounded by the attest-JCS safe integer range
    and floats are outside the profile altogether (§20.2): neither can be
    canonicalized, so neither becomes a wire document — and a hand-built one is
    refused on shape, without raising."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)

    with pytest.raises(canon.CanonError):
        _authorization(kp, authorization_version=version)

    document = _authorization(kp)
    document["authorization_version"] = version

    assert not authority.verify_authorization(document, key_manifest)


def test_the_four_thousand_ninety_six_entry_ceiling_is_enforced_on_shape() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    entries = [_entry(issuer_id=f"i{index:05d}.example") for index in range(4097)]

    at_the_ceiling = _authorization(kp, authorized_issuers=entries[:4096])
    over_the_ceiling = _authorization(kp, authorized_issuers=entries)

    assert authority.verify_authorization(at_the_ceiling, key_manifest)
    assert not authority.verify_authorization(over_the_ceiling, key_manifest)


def test_verify_authorization_rejects_oversized_document_before_manifest_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(_key_manifest: object) -> bool:
        raise AssertionError("key manifest verification ran before authorization shape")

    monkeypatch.setattr(manifests, "verify_key_manifest", fail_if_called)
    document = {
        "authorization_version": 1,
        "publisher": PUBLISHER,
        "authorized_issuers": [None] * (authority.MAX_AUTHORIZED_ISSUERS + 1),
        "issued_at": AUTH_ISSUED_AT,
        "signature": {},
    }

    assert authority.verify_authorization(document, {"keys": []}) is False


@pytest.mark.parametrize(
    "document",
    [None, 42, "authorization", [], {}, {"signature": None}, {"authorization_version": 1}],
)
def test_verify_authorization_never_raises_on_garbage(document: Any) -> None:
    _, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)

    assert not authority.verify_authorization(document, key_manifest)
    assert not authority.verify_authorization_signature(document, key_manifest)


@pytest.mark.parametrize("key_manifest", [None, 42, "manifest", [], {}, {"keys": None}])
def test_verify_authorization_never_raises_on_a_garbage_manifest(key_manifest: Any) -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)

    assert not authority.verify_authorization(document, key_manifest)
    assert not authority.verify_authorization_signature(document, key_manifest)


def test_a_hostile_signature_block_never_raises() -> None:
    """`status` arriving as an object instead of a string is the shape that has
    already crashed a fail-closed predicate in this repository twice: every
    member of a supplied document is assumed hostile."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp)
    document["signature"] = {"kid": {"nested": "object"}, "alg": None, "sig": 42}

    assert not authority.verify_authorization(document, key_manifest)
    assert not authority.verify_authorization_signature(document, key_manifest)


# --- entry lookup (§20.4 step 9) ---------------------------------------------


def test_entry_for_issuer_returns_the_matching_entry() -> None:
    document = _unsigned_authorization(
        authorized_issuers=sorted(
            [_entry(), _entry(issuer_id=OTHER_ISSUER)], key=lambda entry: str(entry["issuer_id"])
        )
    )

    entry = authority.entry_for_issuer(document, ISSUER)

    assert entry is not None
    assert entry["issuer_id"] == ISSUER


def test_entry_for_issuer_returns_none_when_absent() -> None:
    document = _unsigned_authorization(authorized_issuers=[_entry(issuer_id=OTHER_ISSUER)])

    assert authority.entry_for_issuer(document, ISSUER) is None


def test_entry_for_issuer_returns_none_on_an_empty_array() -> None:
    document = _unsigned_authorization(authorized_issuers=[])

    assert authority.entry_for_issuer(document, ISSUER) is None


def test_entry_for_issuer_refuses_to_let_array_order_decide() -> None:
    """§20.2: 'the order of this array must never be able to decide an
    outcome'. A duplicated `issuer_id` is a shape error caught upstream, so
    this function never sees one from an admitted document — and on a document
    that was never admitted it resolves to NO entry rather than to whichever
    duplicate the presenter put first."""
    document = _unsigned_authorization(
        authorized_issuers=[_entry(), _entry(permissions=[authority.PERMISSION_DELEGATE])]
    )

    assert authority.entry_for_issuer(document, ISSUER) is None


@pytest.mark.parametrize(
    "document",
    [None, 42, "document", [], {}, {"authorized_issuers": None}, {"authorized_issuers": [None]}],
)
def test_entry_for_issuer_never_raises_on_garbage(document: Any) -> None:
    assert authority.entry_for_issuer(document, ISSUER) is None


@pytest.mark.parametrize("issuer_id", [None, 42, True, ["store.example.com"]])
def test_entry_for_issuer_never_raises_on_a_garbage_issuer_id(issuer_id: Any) -> None:
    document = _unsigned_authorization()

    assert authority.entry_for_issuer(document, issuer_id) is None


# --- membership (§20.4 step 9) -----------------------------------------------


def test_an_open_ended_entry_with_issue_authorizes_the_receipt() -> None:
    assert authority.entry_authorizes_receipt(_entry(), make_payload())


def test_an_entry_for_a_different_issuer_never_authorizes_the_receipt() -> None:
    assert not authority.entry_authorizes_receipt(_entry(issuer_id=OTHER_ISSUER), make_payload())


def test_an_entry_whose_window_opens_after_the_receipt_does_not_authorize() -> None:
    entry = _entry(valid_from="2026-08-01T00:00:00Z")

    assert not authority.entry_authorizes_receipt(entry, make_payload())


def test_an_entry_whose_window_closed_before_the_receipt_does_not_authorize() -> None:
    entry = _entry(valid_to="2026-06-01T00:00:00Z")

    assert not authority.entry_authorizes_receipt(entry, make_payload())


def test_the_window_is_inclusive_at_both_bounds() -> None:
    opens_exactly = _entry(valid_from=RECEIPT_ISSUED_AT)
    closes_exactly = _entry(valid_to=RECEIPT_ISSUED_AT)

    assert authority.entry_authorizes_receipt(opens_exactly, make_payload())
    assert authority.entry_authorizes_receipt(closes_exactly, make_payload())


def test_a_window_closed_after_the_receipt_still_authorizes_it() -> None:
    """§20.2: de-authorization is PROSPECTIVE — a receipt issued while its
    issuer was inside an authorized window resolves authorized forever."""
    entry = _entry(valid_to="2026-08-01T00:00:00Z")

    assert authority.entry_authorizes_receipt(entry, make_payload())


def test_the_window_is_evaluated_against_the_receipts_own_issued_at() -> None:
    entry = _entry(valid_from="2026-01-01T00:00:00Z", valid_to="2026-02-01T00:00:00Z")

    assert authority.entry_authorizes_receipt(entry, make_payload(issued_at="2026-01-15T00:00:00Z"))
    assert not authority.entry_authorizes_receipt(
        entry, make_payload(issued_at="2026-03-15T00:00:00Z")
    )


def test_an_entry_without_the_issue_permission_does_not_authorize() -> None:
    """§20.2/§6.11: `delegate` is registered `reserved` and MUST NOT be
    honored — no code path reads it as authority to issue."""
    entry = _entry(permissions=[authority.PERMISSION_DELEGATE])

    assert not authority.entry_authorizes_receipt(entry, make_payload())


def test_issue_alongside_other_permissions_authorizes() -> None:
    entry = _entry(permissions=sorted([authority.PERMISSION_ISSUE, authority.PERMISSION_DELEGATE]))

    assert authority.entry_authorizes_receipt(entry, make_payload())


def test_a_null_scope_covers_the_whole_catalogue() -> None:
    assert authority.entry_authorizes_receipt(_entry(scope=None), make_payload())


def test_a_non_null_scope_covering_by_series_authorizes() -> None:
    entry = _entry(scope=_scope(artifact_series=RECEIPT_SERIES, artifacts=[OTHER_ART]))

    assert authority.entry_authorizes_receipt(entry, make_payload())


def test_a_non_null_scope_covering_by_artifact_hash_authorizes() -> None:
    entry = _entry(scope=_scope(artifact_series=None, artifacts=[RECEIPT_ART]))

    assert authority.entry_authorizes_receipt(entry, make_payload())


def test_a_non_null_scope_naming_neither_does_not_authorize() -> None:
    entry = _entry(scope=_scope(artifact_series="pub.example/works/OTHER", artifacts=[OTHER_ART]))

    assert not authority.entry_authorizes_receipt(entry, make_payload())


def test_an_empty_artifact_list_is_covered_by_no_non_null_scope() -> None:
    """§18.4's vacuous-quantifier guard, inherited verbatim: stated as a bare
    universal quantifier the artifact clause would range over an empty set and
    be VACUOUSLY TRUE, making every scope cover every artifact-less receipt."""
    entry = _entry(scope=_scope(artifact_series=None, artifacts=[RECEIPT_ART]))
    payload = make_payload(work={"artifact_series": "store.example.com/works/OTHER"})
    payload["work"]["artifacts"] = []

    assert not authority.entry_authorizes_receipt(entry, payload)


def test_a_missing_artifact_list_is_covered_by_no_non_null_scope() -> None:
    entry = _entry(scope=_scope(artifact_series=None, artifacts=[RECEIPT_ART]))
    payload = make_payload(work={"artifact_series": "store.example.com/works/OTHER"})
    del payload["work"]["artifacts"]

    assert not authority.entry_authorizes_receipt(entry, payload)


def test_a_missing_scope_member_never_authorizes() -> None:
    """An absent member is not `null`: a malformed entry must not be read as
    'the publisher's entire catalogue'."""
    entry = {key: value for key, value in _entry().items() if key != "scope"}

    assert not authority.entry_authorizes_receipt(entry, make_payload())


def test_a_non_string_permission_never_authorizes() -> None:
    """Bare membership is blind to the type of what surrounds the value it
    finds: `["issue", {}]` contains `issue` and is still not a `permissions`
    array. An entry arrives on the caller's evidence rail, so every member it
    carries is held to §20.2's shape before any of it is believed."""
    entry = _entry(permissions=[authority.PERMISSION_ISSUE, {}])

    assert not authority.entry_authorizes_receipt(entry, make_payload())


def test_an_entry_with_an_unknown_member_never_authorizes() -> None:
    """The entry shape is CLOSED (§20.2): an entry that would be refused inside
    a document is refused here too, rather than authorizing on the strength of
    the members that happen to be well-formed."""
    entry = {**_entry(), "note": "trust me"}

    assert not authority.entry_authorizes_receipt(entry, make_payload())


@pytest.mark.parametrize(
    "entry",
    [
        None,
        42,
        "entry",
        [],
        {},
        {"permissions": ["issue"]},
        _entry(valid_from=None),
        _entry(valid_from="2026-01-01"),
        _entry(valid_to=42),
        _entry(permissions="issue"),
        _entry(permissions=None),
        _entry(scope=42),
    ],
)
def test_entry_authorizes_receipt_fails_closed_on_a_garbage_entry(entry: Any) -> None:
    assert not authority.entry_authorizes_receipt(entry, make_payload())


@pytest.mark.parametrize(
    "payload",
    [None, 42, "payload", [], {}, {"issued_at": None}, {"issued_at": 42}, {"issued_at": "nope"}],
)
def test_entry_authorizes_receipt_fails_closed_on_a_garbage_payload(payload: Any) -> None:
    assert not authority.entry_authorizes_receipt(_entry(), payload)


def test_entry_authorizes_receipt_fails_closed_on_a_malformed_artifact_entry() -> None:
    entry = _entry(scope=_scope(artifact_series=None, artifacts=[RECEIPT_ART]))
    payload = make_payload(work={"artifact_series": "store.example.com/works/OTHER"})
    payload["work"]["artifacts"] = [{"role": "installer"}]

    assert not authority.entry_authorizes_receipt(entry, payload)


# --- the evidence-channel ceiling (§20.3) ------------------------------------


def test_the_document_ceiling_accepts_exactly_the_maximum() -> None:
    assert authority.within_structural_ceiling([object()] * authority.MAX_AUTHORITY_DOCUMENTS)


def test_one_document_over_the_ceiling_is_rejected() -> None:
    assert not authority.within_structural_ceiling(
        [object()] * (authority.MAX_AUTHORITY_DOCUMENTS + 1)
    )


def test_the_ceiling_accepts_absent_evidence_and_an_empty_array() -> None:
    assert authority.within_structural_ceiling(None)
    assert authority.within_structural_ceiling([])


@pytest.mark.parametrize("authorizations", [42, "documents", {"a": 1}, True, ({},)])
def test_the_ceiling_fails_closed_on_a_non_array(authorizations: Any) -> None:
    assert not authority.within_structural_ceiling(authorizations)


def test_the_ceiling_counts_and_never_inspects_an_element() -> None:
    """§20.3: the count ceiling is checked BEFORE any signature is verified —
    'each element costs a hybrid signature verification, so a byte cap alone is
    not a ceiling'. Elements that raise on any inspection pass at the ceiling
    and are refused one past it, without ever being touched."""

    class Hostile:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"ceiling check inspected element attribute {name!r}")

        def __eq__(self, other: object) -> bool:
            raise AssertionError("ceiling check compared an element")

        def __hash__(self) -> int:
            raise AssertionError("ceiling check hashed an element")

    assert authority.within_structural_ceiling([Hostile()] * 64)
    assert not authority.within_structural_ceiling([Hostile()] * 65)


# --- the shared version predicate (§20.2 shape AND §20.3 view member) --------


@pytest.mark.parametrize("value", [1, 2, 4096, 2**53 - 1])
def test_is_authorization_version_accepts_the_range(value: Any) -> None:
    assert authority.is_authorization_version(value)


@pytest.mark.parametrize(
    "value",
    [0, -1, 2**53, 2**64, True, False, 1.0, "1", None, [1], {"v": 1}],
)
def test_is_authorization_version_rejects_everything_else(value: Any) -> None:
    assert not authority.is_authorization_version(value)


def test_the_document_shape_and_the_view_member_share_one_predicate() -> None:
    """§20.3/D16: `authorization_version` in the document and
    `current_authorization_version` in the view are the SAME range, and step 10
    compares them for equality — two spellings of the predicate would diverge
    exactly on the boundary that decides whether a denial holds or degrades to
    `unattested`."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)

    for value in (0, True, 2**53 - 1):
        document = _authorization(kp, authorization_version=value)
        assert authority.verify_authorization(document, key_manifest) is (
            authority.is_authorization_version(value)
        )


# --- the successor discipline the builder refuses to sign against (§20.2) ----


def _previous(**overrides: Any) -> dict[str, Any]:
    """A predecessor document. Only `authorization_version`,
    `authorized_issuers` and `issued_at` are read by the check."""
    return _unsigned_authorization(**overrides)


def test_a_successor_that_preserves_every_entry_is_signed() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()
    document = authority.build_authorization(
        2,
        PUBLISHER,
        [_entry()],
        LATER_ISSUED_AT,
        kp,
        PUB_KID,
        previous=previous,
    )

    assert authority.verify_authorization(document, key_manifest)


def test_a_successor_may_add_a_new_entry() -> None:
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()
    entries = sorted(
        [_entry(), _entry(issuer_id=OTHER_ISSUER)], key=lambda entry: str(entry["issuer_id"])
    )
    document = authority.build_authorization(
        2, PUBLISHER, entries, LATER_ISSUED_AT, kp, PUB_KID, previous=previous
    )

    assert authority.verify_authorization(document, key_manifest)


def test_a_successor_may_close_a_window_at_or_after_the_predecessors_issued_at() -> None:
    """§20.2: a closure is set no earlier than the `issued_at` of the latest
    version that showed the window open — closing it exactly there is the
    tightest conforming closure."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()

    tightest = authority.build_authorization(
        2,
        PUBLISHER,
        [_entry(valid_to=AUTH_ISSUED_AT)],
        LATER_ISSUED_AT,
        kp,
        PUB_KID,
        previous=previous,
    )
    later = authority.build_authorization(
        3,
        PUBLISHER,
        [_entry(valid_to="2026-08-01T00:00:00Z")],
        LATER_ISSUED_AT,
        kp,
        PUB_KID,
        previous=previous,
    )

    assert authority.verify_authorization(tightest, key_manifest)
    assert authority.verify_authorization(later, key_manifest)


def test_a_version_not_above_the_predecessors_is_refused() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous(authorization_version=2)

    for version in (1, 2):
        with pytest.raises(ValueError):
            authority.build_authorization(
                version, PUBLISHER, [_entry()], LATER_ISSUED_AT, kp, PUB_KID, previous=previous
            )


def test_deleting_a_published_entry_is_refused() -> None:
    """§20.2: an entry, once published, MUST appear in every later version —
    de-authorization CLOSES the window, and emptying a list that carried
    entries is entry deletion, not total revocation."""
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()

    with pytest.raises(ValueError):
        authority.build_authorization(
            2, PUBLISHER, [], LATER_ISSUED_AT, kp, PUB_KID, previous=previous
        )

    with pytest.raises(ValueError):
        authority.build_authorization(
            2,
            PUBLISHER,
            [_entry(issuer_id=OTHER_ISSUER)],
            LATER_ISSUED_AT,
            kp,
            PUB_KID,
            previous=previous,
        )


def test_changing_valid_from_on_a_shared_entry_is_refused() -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()

    for moved in ("2025-01-01T00:00:00Z", "2026-03-01T00:00:00Z"):
        with pytest.raises(ValueError):
            authority.build_authorization(
                2,
                PUBLISHER,
                [_entry(valid_from=moved)],
                LATER_ISSUED_AT,
                kp,
                PUB_KID,
                previous=previous,
            )


def test_an_already_closed_window_carried_forward_unchanged_is_signed() -> None:
    """§20.2: 'carrying forward an already-closed window unchanged is
    conforming' — a closed window is a historical fact and it stays listed."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    closed = _entry(valid_to="2026-05-01T00:00:00Z")
    previous = _previous(authorized_issuers=[closed])

    document = authority.build_authorization(
        2,
        PUBLISHER,
        [_entry(valid_to="2026-05-01T00:00:00Z")],
        LATER_ISSUED_AT,
        kp,
        PUB_KID,
        previous=previous,
    )

    assert authority.verify_authorization(document, key_manifest)


@pytest.mark.parametrize(
    "moved_to",
    [
        "2026-04-01T00:00:00Z",  # earlier: uncovers receipts already issued inside it
        "2026-06-01T00:00:00Z",  # later: re-covers a window the publisher had closed
        None,  # reopened: the closure unmade altogether
    ],
)
def test_a_closed_window_moved_in_any_direction_is_refused(moved_to: Any) -> None:
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous(authorized_issuers=[_entry(valid_to="2026-05-01T00:00:00Z")])

    with pytest.raises(ValueError):
        authority.build_authorization(
            2,
            PUBLISHER,
            [_entry(valid_to=moved_to)],
            LATER_ISSUED_AT,
            kp,
            PUB_KID,
            previous=previous,
        )


def test_a_back_dated_new_closure_is_refused() -> None:
    """§20.2: a closure is set no earlier than the `issued_at` of the latest
    version that showed the window open — a back-dated closure would uncover
    receipts already issued inside it."""
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()  # entry open, document issued_at 2026-02-01

    with pytest.raises(ValueError):
        authority.build_authorization(
            2,
            PUBLISHER,
            [_entry(valid_to="2026-01-15T00:00:00Z")],
            LATER_ISSUED_AT,
            kp,
            PUB_KID,
            previous=previous,
        )


def test_a_post_dated_new_closure_is_refused() -> None:
    """§20.2 bounds a closure from ABOVE as well: `valid_to` no later than the
    closing document's own `issued_at` — 'a closure may not be post-dated into
    the future'. A publisher announcing a closure it has not yet lived through
    keeps the freedom to move it again while presenting it as settled."""
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()

    with pytest.raises(ValueError):
        authority.build_authorization(
            2,
            PUBLISHER,
            [_entry(valid_to="2026-09-01T00:00:01Z")],  # one second past issued_at
            LATER_ISSUED_AT,
            kp,
            PUB_KID,
            previous=previous,
        )


def test_a_closure_exactly_at_this_documents_issued_at_is_signed() -> None:
    """The upper bound is INCLUSIVE: closing at the closing document's own
    `issued_at` is the latest conforming closure."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous()

    document = authority.build_authorization(
        2,
        PUBLISHER,
        [_entry(valid_to=LATER_ISSUED_AT)],
        LATER_ISSUED_AT,
        kp,
        PUB_KID,
        previous=previous,
    )

    assert authority.verify_authorization(document, key_manifest)


def test_a_closure_shortened_below_the_predecessors_issued_at_is_refused() -> None:
    """The predecessor's entry was still open at that document's own
    `issued_at` (its window ran past it); shortening the closure to a moment
    before it is the same back-dating, one step removed."""
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)
    previous = _previous(authorized_issuers=[_entry(valid_to="2026-12-01T00:00:00Z")])

    with pytest.raises(ValueError):
        authority.build_authorization(
            2,
            PUBLISHER,
            [_entry(valid_to="2026-01-15T00:00:00Z")],
            LATER_ISSUED_AT,
            kp,
            PUB_KID,
            previous=previous,
        )


def test_the_successor_check_runs_before_any_signature() -> None:
    """§20.2/D18: the refusal happens BEFORE the document is signed. A signing
    key that cannot sign anything proves it: reaching the signature would raise
    something other than `ValueError`."""
    previous = _previous()

    with pytest.raises(ValueError):
        authority.build_authorization(
            1,
            PUBLISHER,
            [],
            LATER_ISSUED_AT,
            object(),  # type: ignore[arg-type]
            PUB_KID,
            previous=previous,
        )


def test_a_previous_that_cannot_be_read_is_refused_rather_than_skipped() -> None:
    """A predecessor supplied but unusable cannot show the successor
    conforming, so the builder refuses to sign instead of silently dropping the
    check."""
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)

    for previous in (42, "previous", [], {}, {"authorization_version": 1}):
        with pytest.raises(ValueError):
            authority.build_authorization(
                2, PUBLISHER, [_entry()], LATER_ISSUED_AT, kp, PUB_KID, previous=previous
            )


def test_previous_none_runs_no_check_and_is_byte_identical() -> None:
    """`previous=None` is the pre-existing builder, byte for byte: it does not
    validate what it signs, exactly like `build_grant`."""
    kp, _ = _ed_manifest(PUBLISHER, PUB_KID)

    implicit = authority.build_authorization(1, PUBLISHER, [], AUTH_ISSUED_AT, kp, PUB_KID)
    explicit = authority.build_authorization(
        1, PUBLISHER, [], AUTH_ISSUED_AT, kp, PUB_KID, previous=None
    )

    assert canon.canonical_bytes(implicit) == canon.canonical_bytes(explicit)
    # ...and the very same body IS refused when the predecessor is supplied.
    with pytest.raises(ValueError):
        authority.build_authorization(
            1, PUBLISHER, [], AUTH_ISSUED_AT, kp, PUB_KID, previous=_previous()
        )


def test_the_builder_does_not_validate_what_it_signs_without_a_predecessor() -> None:
    """Building a deliberately malformed document is how the verification side
    gets tested (the `build_grant` posture): the builder never raises on a body
    it will not vouch for."""
    kp, key_manifest = _ed_manifest(PUBLISHER, PUB_KID)
    document = _authorization(kp, publisher="NOT-A-DOMAIN", authorized_issuers=[_entry(), _entry()])

    assert document["publisher"] == "NOT-A-DOMAIN"
    assert not authority.verify_authorization(document, key_manifest)
