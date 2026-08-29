"""Tests for publisher authority evaluation over one payload and one evidence view."""

from __future__ import annotations

import copy
import hashlib
import itertools
from collections.abc import Callable
from typing import Any

import pytest

from attest import authority, keys, manifests, pq, verify
from tests.helpers import make_payload

ISSUER = "store.example"
PUBLISHER = "pub.example"
MARKET = "market.example"
CATALOG = "catalog.example"

ISSUER_KID = f"{ISSUER}/keys/authority#1"
PUBLISHER_KID = f"{PUBLISHER}/keys/authority#1"
MARKET_KID = f"{MARKET}/keys/authority#1"
CATALOG_KID = f"{CATALOG}/keys/authority#1"

KEY_VALID_FROM = "2026-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2026-01-01T00:00:00Z"
AUTH_V1_ISSUED_AT = "2026-01-10T00:00:00Z"
AUTH_V2_ISSUED_AT = "2026-02-01T00:00:00Z"
AUTH_V3_ISSUED_AT = "2026-03-01T00:00:00Z"

RECEIPT_ISSUED_AT = "2026-01-20T00:00:00Z"
AFTER_V2_ISSUED_AT = "2026-02-10T00:00:00Z"
VALID_FROM = "2026-01-01T00:00:00Z"
LOWER_BOUND = AUTH_V1_ISSUED_AT
MID_CLOSURE = "2026-01-20T00:00:00Z"
TERM_END = "2026-03-01T00:00:00Z"
EXTENDED_TERM_END = "2026-04-01T00:00:00Z"

# The receipt's own artifact digest. `tests.helpers.make_payload` builds
# `work.artifacts` as section 5.4 objects carrying `sha256`, not as bare
# digests, and section 18.4's grant-coverage predicate reads that member — so
# the digest the scope fixtures name has to be the one the base payload
# already carries, or "scope covers this receipt" could never be true.
ARTIFACT = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
OTHER_ARTIFACT = hashlib.sha256(b"other-artifact").hexdigest()

AUTH_NOT_CHECKED = "not_checked"
AUTH_NO_CLAIM = "no_publisher_claim"
AUTH_SELF = "self"
AUTH_AUTHORIZED = "authorized"
AUTH_UNAUTHORIZED = "unauthorized"
AUTH_UNATTESTED = "unattested"

TRUST_NOT_CHECKED = "not_checked"
TRUST_VERIFIED = "verified"
TRUST_TOFU = "unauthenticated_tofu"
TRUST_UNVERIFIED_ROTATION = "unverified_rotation"
TRUST_SIGNER_MISMATCH = "signer_mismatch"

# `publisher_claim_unattested` is NOT an evaluator warning: section 20.1's
# stratification is a property of the verifier as a whole, and this branch
# emits it in `verify()` after extending with the verdict's own warnings.
# Kept as a name so the assertions below can say what they do NOT expect.
WARN_CLAIM = "publisher_claim_unattested"
WARN_NOT_AUTHORIZING = "publisher_not_authorizing_issuer"
WARN_SIGNER = "authorization_signer_not_publisher"
WARN_INVALID = "authorization_invalid_ignored"

_MISSING = object()


def _hybrid_manifest(
    issuer: str, kid: str, version: int = 1
) -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    signing_keys = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    key_entry = manifests.key_entry(
        kid,
        signing_keys.ed.pub,
        KEY_VALID_FROM,
        pub_ml_dsa_65=signing_keys.mldsa.pub,
    )
    manifest = manifests.build_key_manifest(
        issuer,
        version,
        MANIFEST_ISSUED_AT,
        [key_entry],
        signing_keys,
        kid,
    )
    return signing_keys, manifest


ISSUER_KEYS, ISSUER_MANIFEST = _hybrid_manifest(ISSUER, ISSUER_KID)
PUBLISHER_KEYS, PUBLISHER_MANIFEST = _hybrid_manifest(PUBLISHER, PUBLISHER_KID)
MARKET_KEYS, MARKET_MANIFEST = _hybrid_manifest(MARKET, MARKET_KID)
CATALOG_KEYS, CATALOG_MANIFEST = _hybrid_manifest(CATALOG, CATALOG_KID)

MISMATCH_KEYS, MISMATCH_MANIFEST = _hybrid_manifest(MARKET, PUBLISHER_KID)

KEYS_BY_DOMAIN: dict[str, pq.HybridSigningKeys] = {
    ISSUER: ISSUER_KEYS,
    PUBLISHER: PUBLISHER_KEYS,
    MARKET: MARKET_KEYS,
    CATALOG: CATALOG_KEYS,
}
KID_BY_DOMAIN = {
    ISSUER: ISSUER_KID,
    PUBLISHER: PUBLISHER_KID,
    MARKET: MARKET_KID,
    CATALOG: CATALOG_KID,
}
MANIFEST_BY_DOMAIN = {
    ISSUER: ISSUER_MANIFEST,
    PUBLISHER: PUBLISHER_MANIFEST,
    MARKET: MARKET_MANIFEST,
    CATALOG: CATALOG_MANIFEST,
}


def _entry(
    issuer: str = ISSUER,
    *,
    valid_from: str = VALID_FROM,
    valid_to: str | None = None,
    permissions: list[str] | None = None,
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "permissions": sorted(
            permissions if permissions is not None else [authority.PERMISSION_ISSUE]
        ),
        "scope": scope,
    }


def _scope(
    artifacts: list[str] | None = None,
    artifact_series: str | None = None,
) -> dict[str, Any]:
    return {
        "artifact_series": artifact_series,
        "artifacts": sorted(artifacts if artifacts is not None else [ARTIFACT]),
    }


def _authorization(
    *,
    version: int = 1,
    publisher: str = PUBLISHER,
    entries: list[dict[str, Any]] | None = None,
    issued_at: str = AUTH_V1_ISSUED_AT,
    signing_domain: str = PUBLISHER,
    signing_keys: pq.HybridSigningKeys | keys.SigningKeyPair | None = None,
    kid: str | None = None,
) -> dict[str, Any]:
    chosen_keys = signing_keys if signing_keys is not None else KEYS_BY_DOMAIN[signing_domain]
    chosen_kid = kid if kid is not None else KID_BY_DOMAIN[signing_domain]
    chosen_entries = [_entry()] if entries is None else entries
    return authority.build_authorization(
        authorization_version=version,
        publisher=publisher,
        authorized_issuers=sorted(chosen_entries, key=lambda item: item["issuer_id"]),
        issued_at=issued_at,
        signing_kp=chosen_keys,
        kid=chosen_kid,
    )


def _payload(
    *,
    publisher_id: object = PUBLISHER,
    issuer_id: object = ISSUER,
    issued_at: str = RECEIPT_ISSUED_AT,
) -> dict[str, Any]:
    payload = make_payload(attest_version="0.2")
    payload["issued_at"] = issued_at
    issuer = payload.setdefault("issuer", {})
    if isinstance(issuer, dict):
        issuer["id"] = issuer_id
    work = payload.setdefault("work", {})
    if isinstance(work, dict):
        if publisher_id is _MISSING:
            work.pop("publisher_id", None)
        else:
            work["publisher_id"] = publisher_id
    return payload


def _trust_store(
    *,
    manifests_by_domain: dict[str, dict[str, Any]] | None = None,
    provenance: dict[str, str] | None = None,
    chains: dict[str, list[dict[str, Any]]] | None = None,
) -> verify.TrustStore:
    resolved = dict(MANIFEST_BY_DOMAIN)
    resolved.update(manifests_by_domain or {})
    resolved_provenance = {domain: "tls" for domain in resolved}
    resolved_provenance.update(provenance or {})
    return verify.TrustStore(
        manifests=resolved,
        provenance=resolved_provenance,
        chains=chains or {},
    )


def _view(
    *documents: Any,
    current: object = _MISSING,
    include_authorizations: bool = True,
) -> dict[str, Any]:
    view: dict[str, Any] = {}
    if include_authorizations:
        view["authorizations"] = list(documents)
    if current is not _MISSING:
        view["current_authorization_version"] = current
    return view


def _evaluate(
    *,
    payload: dict[str, Any] | None = None,
    trust_store: verify.TrustStore | None = None,
    view: dict[str, Any] | None = None,
) -> Any:
    return verify.evaluate_publisher_authority(
        _payload() if payload is None else payload,
        _trust_store() if trust_store is None else trust_store,
        view,
    )


def _assert_verdict(
    verdict: Any,
    publisher_authority: str,
    publisher_authority_trust: str,
    warnings: tuple[str, ...],
) -> None:
    assert verdict.publisher_authority == publisher_authority
    assert verdict.publisher_authority_trust == publisher_authority_trust
    assert verdict.warnings == warnings


def _expect(
    *,
    publisher_authority: str,
    publisher_authority_trust: str,
    warnings: tuple[str, ...],
    payload: dict[str, Any] | None = None,
    trust_store: verify.TrustStore | None = None,
    view: dict[str, Any] | None = None,
) -> None:
    verdict = _evaluate(payload=payload, trust_store=trust_store, view=view)
    _assert_verdict(verdict, publisher_authority, publisher_authority_trust, warnings)


def _tamper(document: dict[str, Any], **changes: Any) -> dict[str, Any]:
    mutated = copy.deepcopy(document)
    mutated.update(changes)
    return mutated


def _deep_list(depth: int = 512) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth):
        value = [value]
    return value


def _version_pair(
    *,
    previous_valid_to: str | None = None,
    successor_valid_to: str | None = MID_CLOSURE,
    previous_issued_at: str = AUTH_V1_ISSUED_AT,
    successor_issued_at: str = AUTH_V2_ISSUED_AT,
    successor_valid_from: str = VALID_FROM,
) -> tuple[dict[str, Any], dict[str, Any]]:
    previous = _authorization(
        version=1,
        issued_at=previous_issued_at,
        entries=[_entry(valid_to=previous_valid_to)],
    )
    successor = _authorization(
        version=2,
        issued_at=successor_issued_at,
        entries=[_entry(valid_from=successor_valid_from, valid_to=successor_valid_to)],
    )
    return previous, successor


def _assert_authorized_fixture(document: dict[str, Any], manifest: dict[str, Any]) -> None:
    assert authority.verify_authorization(document, manifest) is True


def _valid_authorization_documents() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    _, v2_closed = _version_pair(successor_valid_to=MID_CLOSURE)
    _, v2_lower_bound = _version_pair(successor_valid_to=LOWER_BOUND)
    _, v2_upper_bound = _version_pair(successor_valid_to=AUTH_V2_ISSUED_AT)
    _, v2_extended = _version_pair(
        previous_valid_to=TERM_END,
        successor_valid_to=EXTENDED_TERM_END,
    )
    _, v2_reopened = _version_pair(previous_valid_to=TERM_END, successor_valid_to=None)
    v2_entry_removed = _authorization(version=2, issued_at=AUTH_V2_ISSUED_AT, entries=[])
    return [
        ("baseline", _authorization(), PUBLISHER_MANIFEST),
        ("empty-first-version", _authorization(entries=[]), PUBLISHER_MANIFEST),
        ("conforming-closure", v2_closed, PUBLISHER_MANIFEST),
        ("closure-at-lower-bound", v2_lower_bound, PUBLISHER_MANIFEST),
        ("closure-at-upper-bound", v2_upper_bound, PUBLISHER_MANIFEST),
        ("live-extension-to-later-bound", v2_extended, PUBLISHER_MANIFEST),
        ("live-extension-to-null", v2_reopened, PUBLISHER_MANIFEST),
        ("nonconforming-entry-removal-still-authenticates", v2_entry_removed, PUBLISHER_MANIFEST),
        (
            "document-publisher-mutated-before-signing",
            _authorization(publisher=MARKET),
            PUBLISHER_MANIFEST,
        ),
        (
            "foreign-signed-before-binding",
            _authorization(signing_domain=MARKET),
            MARKET_MANIFEST,
        ),
    ]


@pytest.mark.parametrize(
    ("case", "document", "manifest"),
    _valid_authorization_documents(),
    ids=[case for case, _, _ in _valid_authorization_documents()],
)
def test_authorization_fixtures_authenticate_with_existing_primitives(
    case: str, document: dict[str, Any], manifest: dict[str, Any]
) -> None:
    assert case
    _assert_authorized_fixture(document, manifest)
    assert len(authority.authorization_hash(document)) == 64


def test_baseline_entry_authorizes_the_baseline_payload() -> None:
    document = _authorization()
    entry = authority.entry_for_issuer(document, ISSUER)

    assert entry is not None
    assert authority.entry_authorizes_receipt(entry, _payload()) is True


def test_no_authority_view_keeps_the_components_not_checked() -> None:
    _expect(
        view=None,
        publisher_authority=AUTH_NOT_CHECKED,
        publisher_authority_trust=TRUST_NOT_CHECKED,
        warnings=(),
    )


def test_empty_authority_view_opts_into_unattested() -> None:
    _expect(
        view=_view(include_authorizations=False),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_NOT_CHECKED,
        warnings=(),
    )


@pytest.mark.parametrize(
    "publisher_id",
    [_MISSING, 17, True, None, {"id": PUBLISHER}],
    ids=["absent", "integer", "boolean", "null", "object"],
)
def test_unreadable_publisher_claim_reports_no_claim(publisher_id: object) -> None:
    _expect(
        payload=_payload(publisher_id=publisher_id),
        view=_view(_authorization()),
        publisher_authority=AUTH_NO_CLAIM,
        publisher_authority_trust=TRUST_NOT_CHECKED,
        warnings=(),
    )


def test_self_publisher_short_circuits_before_evidence() -> None:
    invalid_document = _tamper(_authorization(), publisher=MARKET)

    _expect(
        payload=_payload(publisher_id=ISSUER),
        view=_view(invalid_document),
        publisher_authority=AUTH_SELF,
        publisher_authority_trust=TRUST_NOT_CHECKED,
        warnings=(),
    )


def test_non_string_issuer_id_degrades_to_unattested_not_unauthorized() -> None:
    _expect(
        payload=_payload(issuer_id=7),
        view=_view(_authorization(), current=1),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_NOT_CHECKED,
        warnings=(),
    )


def test_authority_view_must_be_an_object_when_present() -> None:
    with pytest.raises(TypeError):
        _evaluate(view=[])  # type: ignore[arg-type]


def test_authorizations_member_with_wrong_type_degrades_to_unattested() -> None:
    _expect(
        view={"authorizations": "not-an-array", "current_authorization_version": 1},
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_NOT_CHECKED,
        warnings=(),
    )


def test_authorizations_ceiling_is_checked_before_evidence_content() -> None:
    class ExplodingDocument:
        def __getattribute__(self, name: str) -> Any:
            raise AssertionError(f"content inspected before ceiling: {name}")

    _expect(
        view={"authorizations": [ExplodingDocument() for _ in range(65)]},
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_NOT_CHECKED,
        warnings=(),
    )


@pytest.mark.parametrize(
    ("case", "document", "payload", "trust_store", "expected_trust", "expected_warnings"),
    [
        (
            "document-publisher-differs-from-receipt-and-manifest",
            _authorization(publisher=MARKET, signing_domain=PUBLISHER),
            _payload(publisher_id=PUBLISHER),
            _trust_store(),
            TRUST_VERIFIED,
            (WARN_INVALID,),
        ),
        (
            "resolved-manifest-issuer-differs-from-kid-domain",
            _authorization(signing_keys=MISMATCH_KEYS, kid=PUBLISHER_KID),
            _payload(publisher_id=PUBLISHER),
            _trust_store(manifests_by_domain={PUBLISHER: MISMATCH_MANIFEST}),
            TRUST_VERIFIED,
            (WARN_INVALID,),
        ),
        (
            "signer-domain-differs-from-receipt-publisher",
            _authorization(publisher=PUBLISHER, signing_domain=MARKET),
            _payload(publisher_id=PUBLISHER),
            _trust_store(),
            TRUST_SIGNER_MISMATCH,
            (WARN_SIGNER,),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_authorized_requires_each_single_link_of_the_triple_binding(
    case: str,
    document: dict[str, Any],
    payload: dict[str, Any],
    trust_store: verify.TrustStore,
    expected_trust: str,
    expected_warnings: tuple[str, ...],
) -> None:
    assert case
    _expect(
        payload=payload,
        trust_store=trust_store,
        view=_view(document),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=expected_trust,
        warnings=expected_warnings,
    )


@pytest.mark.parametrize(
    ("case", "document", "payload"),
    [
        (
            "document-and-signer-match-each-other-but-not-receipt-publisher",
            _authorization(publisher=MARKET, signing_domain=MARKET),
            _payload(publisher_id=PUBLISHER),
        ),
        (
            "document-publisher-signer-and-receipt-publisher-all-differ",
            _authorization(publisher=CATALOG, signing_domain=MARKET),
            _payload(publisher_id=PUBLISHER),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_overlapping_triple_binding_failures_never_authorize_or_deny(
    case: str, document: dict[str, Any], payload: dict[str, Any]
) -> None:
    assert case
    verdict = _evaluate(payload=payload, view=_view(document, current=1))

    assert verdict.publisher_authority == AUTH_UNATTESTED
    assert verdict.publisher_authority != AUTH_AUTHORIZED
    assert verdict.publisher_authority != AUTH_UNAUTHORIZED
    assert WARN_NOT_AUTHORIZING not in verdict.warnings


def test_byte_identical_duplicate_authorization_is_not_equivocation() -> None:
    document = _authorization()

    _expect(
        view=_view(document, copy.deepcopy(document)),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )


def test_distinct_authorizations_at_the_same_version_are_equivocation() -> None:
    covering = _authorization(version=1)
    empty = _authorization(version=1, entries=[])

    _expect(
        view=_view(covering, empty, current=1),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_UNVERIFIED_ROTATION,
        warnings=(),
    )


@pytest.mark.parametrize(
    ("case", "mutator"),
    [
        (
            "integer-outside-jcs-range",
            lambda document: _tamper(document, authorization_version=2**53),
        ),
        (
            "depth-outside-jcs-range",
            lambda document: _tamper(document, unexpected=_deep_list()),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_uncanonicalizable_documents_inside_well_typed_view_do_not_raise(
    case: str, mutator: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    assert case
    hostile_document = mutator(_authorization())

    try:
        verdict = _evaluate(view=_view(hostile_document))
    except AttributeError:
        raise
    except Exception as exc:  # pragma: no cover - this is the property under test
        pytest.fail(f"authority evaluation raised on hostile content: {exc!r}")

    _assert_verdict(
        verdict,
        AUTH_UNATTESTED,
        TRUST_VERIFIED,
        (WARN_INVALID,),
    )


def test_authorization_invalid_ignored_is_emitted_once_for_many_invalid_documents() -> None:
    forged = _tamper(_authorization(), issued_at=AUTH_V2_ISSUED_AT)
    malformed = _tamper(_authorization(), authorized_issuers="not-an-array")

    _expect(
        view=_view(forged, malformed),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_INVALID,),
    )


def test_rejecting_all_documents_does_not_reset_resolved_publisher_trust() -> None:
    forged = _tamper(_authorization(), issued_at=AUTH_V2_ISSUED_AT)

    _expect(
        view=_view(forged),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_INVALID,),
    )


def test_unauthenticated_foreign_blob_cannot_force_signer_mismatch() -> None:
    document = _authorization(publisher=PUBLISHER, signing_domain=MARKET)
    document["issued_at"] = AUTH_V2_ISSUED_AT

    _expect(
        view=_view(document),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_INVALID,),
    )


def test_matching_current_authorization_version_reaches_unauthorized() -> None:
    document = _authorization(entries=[])

    _expect(
        view=_view(document, current=1),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_NOT_AUTHORIZING,),
    )


@pytest.mark.parametrize(
    ("case", "current"),
    [
        ("absent", _MISSING),
        # The effective document below is version 2, so the assertion that is
        # strictly HIGHER than it is 3, not 2 — 2 is the EQUAL assertion, and
        # section 20.4 step 10 makes equality the one thing that does reach a
        # denial. 3 is also the scenario the case is for: a caller who knows a
        # newer version exists is holding a STALE document, which must buy
        # doubt and never denial (section 20.6 item 6).
        ("higher-than-effective", 3),
        ("lower-than-effective", 1),
    ],
)
def test_denial_requires_a_matching_current_authorization_version(
    case: str, current: object
) -> None:
    document = _authorization(version=2, entries=[])

    _expect(
        view=_view(document, current=current),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )
    assert case


@pytest.mark.parametrize(
    "current",
    [True, 0, 2**53, "1"],
    ids=["bool", "zero", "too-large", "string"],
)
def test_malformed_current_authorization_version_is_absent_not_fatal(current: object) -> None:
    document = _authorization(entries=[])

    _expect(
        view=_view(document, current=current),
        publisher_authority=AUTH_UNATTESTED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )


@pytest.mark.parametrize(
    "current",
    [_MISSING, True, 0, 2, "1"],
    ids=["absent", "bool", "zero", "higher", "string"],
)
def test_positive_authorization_does_not_depend_on_currency(current: object) -> None:
    document = _authorization()

    _expect(
        view=_view(document, current=current),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )


@pytest.mark.parametrize(
    ("case", "entry"),
    [
        ("permission-missing", _entry(permissions=[authority.PERMISSION_DELEGATE])),
        ("scope-uncovered", _entry(scope=_scope([OTHER_ARTIFACT]))),
    ],
)
def test_membership_failures_are_denials_only_with_matching_currency(
    case: str, entry: dict[str, Any]
) -> None:
    document = _authorization(entries=[entry])

    _expect(
        view=_view(document, current=1),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_NOT_AUTHORIZING,),
    )
    assert case


def test_tls_publisher_manifest_yields_verified_authority_trust() -> None:
    document = _authorization()

    _expect(
        view=_view(document),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )


def test_bundle_publisher_manifest_yields_tofu_authority_trust() -> None:
    document = _authorization()

    _expect(
        trust_store=_trust_store(provenance={PUBLISHER: "bundle"}),
        view=_view(document),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_TOFU,
        warnings=(),
    )


def test_discontinuous_publisher_manifest_chain_forces_unverified_rotation() -> None:
    _, unrelated = _hybrid_manifest(PUBLISHER, PUBLISHER_KID, version=7)

    _expect(
        trust_store=_trust_store(chains={PUBLISHER: [unrelated, PUBLISHER_MANIFEST]}),
        view=_view(_authorization()),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_UNVERIFIED_ROTATION,
        warnings=(),
    )


def test_conforming_closure_can_uncover_interregnum_receipt() -> None:
    first, second = _version_pair(successor_valid_to=LOWER_BOUND)

    _expect(
        payload=_payload(issued_at="2026-01-20T00:00:00Z"),
        view=_view(first, second, current=2),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_NOT_AUTHORIZING,),
    )


def test_conforming_closure_preserves_receipts_inside_the_closed_window() -> None:
    first, second = _version_pair(successor_valid_to=MID_CLOSURE)

    _expect(
        payload=_payload(issued_at=MID_CLOSURE),
        view=_view(first, second, current=2),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )


@pytest.mark.parametrize(
    ("case", "pair"),
    [
        (
            "entry-removal",
            lambda: (
                _authorization(version=1, entries=[_entry()]),
                _authorization(version=2, entries=[], issued_at=AUTH_V2_ISSUED_AT),
            ),
        ),
        (
            "valid-from-change",
            lambda: _version_pair(successor_valid_from="2026-01-02T00:00:00Z"),
        ),
        (
            "backdated-closure",
            lambda: _version_pair(successor_valid_to="2026-01-05T00:00:00Z"),
        ),
        (
            "postdated-closure-from-open-window",
            lambda: _version_pair(successor_valid_to="2026-02-15T00:00:00Z"),
        ),
        (
            "postdated-closure-from-live-term-window",
            lambda: _version_pair(
                previous_valid_to=TERM_END,
                successor_valid_to="2026-02-15T00:00:00Z",
            ),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_nonconforming_successors_are_excluded_and_cannot_buy_a_denial(
    case: str, pair: Callable[[], tuple[dict[str, Any], dict[str, Any]]]
) -> None:
    first, second = pair()

    _expect(
        payload=_payload(issued_at=RECEIPT_ISSUED_AT),
        view=_view(first, second, current=2),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_UNVERIFIED_ROTATION,
        warnings=(),
    )
    assert case


@pytest.mark.parametrize(
    ("case", "closure"),
    [
        ("lower-bound-inclusive", AUTH_V1_ISSUED_AT),
        ("upper-bound-inclusive", AUTH_V2_ISSUED_AT),
    ],
)
def test_live_window_closure_landing_on_either_bound_is_conforming(case: str, closure: str) -> None:
    first, second = _version_pair(successor_valid_to=closure)

    _expect(
        payload=_payload(issued_at=AFTER_V2_ISSUED_AT),
        view=_view(first, second, current=2),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_NOT_AUTHORIZING,),
    )
    assert case


def test_live_term_window_can_be_shortened_inside_bounds() -> None:
    first, second = _version_pair(
        previous_valid_to=TERM_END,
        successor_valid_to=MID_CLOSURE,
    )

    _expect(
        payload=_payload(issued_at=AFTER_V2_ISSUED_AT),
        view=_view(first, second, current=2),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_NOT_AUTHORIZING,),
    )


@pytest.mark.parametrize(
    ("case", "previous_valid_to", "successor_valid_to", "receipt_issued_at"),
    [
        (
            "extend-to-later-bound",
            TERM_END,
            EXTENDED_TERM_END,
            "2026-03-15T00:00:00Z",
        ),
        ("extend-to-null", TERM_END, None, "2026-03-15T00:00:00Z"),
        (
            "classification-equality-is-live",
            AUTH_V2_ISSUED_AT,
            EXTENDED_TERM_END,
            "2026-02-15T00:00:00Z",
        ),
    ],
)
def test_live_window_extension_is_conforming(
    case: str,
    previous_valid_to: str,
    successor_valid_to: str | None,
    receipt_issued_at: str,
) -> None:
    first, second = _version_pair(
        previous_valid_to=previous_valid_to,
        successor_valid_to=successor_valid_to,
    )

    _expect(
        payload=_payload(issued_at=receipt_issued_at),
        view=_view(first, second),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )
    assert case


def test_classification_equality_can_also_be_shortened_inside_bounds() -> None:
    first, second = _version_pair(
        previous_valid_to=AUTH_V2_ISSUED_AT,
        successor_valid_to=MID_CLOSURE,
    )

    _expect(
        payload=_payload(issued_at=AFTER_V2_ISSUED_AT),
        view=_view(first, second, current=2),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_NOT_AUTHORIZING,),
    )


@pytest.mark.parametrize(
    ("case", "successor_valid_to"),
    [
        ("moved-earlier", "2026-01-10T00:00:00Z"),
        ("moved-later", "2026-01-25T00:00:00Z"),
        ("reopened", None),
    ],
)
def test_spent_window_moved_in_any_direction_is_excluded(
    case: str, successor_valid_to: str | None
) -> None:
    first, second = _version_pair(
        previous_valid_to="2026-01-15T00:00:00Z",
        successor_valid_to=successor_valid_to,
    )

    _expect(
        payload=_payload(issued_at="2026-01-12T00:00:00Z"),
        view=_view(first, second, current=2),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_UNVERIFIED_ROTATION,
        warnings=(),
    )
    assert case


def test_spent_window_carried_forward_unchanged_is_conforming() -> None:
    first, second = _version_pair(
        previous_valid_to="2026-01-15T00:00:00Z",
        successor_valid_to="2026-01-15T00:00:00Z",
    )

    _expect(
        payload=_payload(issued_at="2026-01-12T00:00:00Z"),
        view=_view(first, second),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(),
    )


@pytest.mark.parametrize("order", tuple(itertools.permutations(("a", "b", "c"))))
def test_fixed_witnesses_make_successor_discipline_order_independent(
    order: tuple[str, str, str],
) -> None:
    a = _authorization(version=1, issued_at=AUTH_V1_ISSUED_AT, entries=[_entry()])
    b = _authorization(
        version=2,
        issued_at=AUTH_V2_ISSUED_AT,
        entries=[_entry(valid_from="2026-01-02T00:00:00Z")],
    )
    c = _authorization(
        version=3,
        issued_at=AUTH_V3_ISSUED_AT,
        entries=[_entry(valid_to=MID_CLOSURE)],
    )
    documents = {"a": a, "b": b, "c": c}

    _expect(
        payload=_payload(issued_at=AFTER_V2_ISSUED_AT),
        view=_view(*(documents[name] for name in order), current=3),
        publisher_authority=AUTH_AUTHORIZED,
        publisher_authority_trust=TRUST_UNVERIFIED_ROTATION,
        warnings=(),
    )


def test_non_admitted_document_cannot_get_a_successor_excluded() -> None:
    first = _authorization(version=1, issued_at=AUTH_V1_ISSUED_AT, entries=[_entry()])
    forged_witness = _authorization(
        version=2,
        issued_at=AUTH_V2_ISSUED_AT,
        entries=[_entry(valid_from="2026-01-02T00:00:00Z")],
    )
    forged_witness["issued_at"] = AUTH_V3_ISSUED_AT
    successor = _authorization(
        version=3,
        issued_at=AUTH_V3_ISSUED_AT,
        entries=[_entry(valid_to=MID_CLOSURE)],
    )

    _expect(
        payload=_payload(issued_at=AFTER_V2_ISSUED_AT),
        view=_view(first, forged_witness, successor, current=3),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_INVALID, WARN_NOT_AUTHORIZING),
    )


@pytest.mark.parametrize("order", tuple(itertools.permutations(("old", "new"))))
def test_maximum_admitted_version_decides_the_effective_authorization(
    order: tuple[str, str],
) -> None:
    old = _authorization(version=1, entries=[_entry()])
    new = _authorization(
        version=2,
        issued_at=AUTH_V2_ISSUED_AT,
        entries=[_entry(valid_to=MID_CLOSURE)],
    )
    documents = {"old": old, "new": new}

    _expect(
        payload=_payload(issued_at=AFTER_V2_ISSUED_AT),
        view=_view(*(documents[name] for name in order), current=2),
        publisher_authority=AUTH_UNAUTHORIZED,
        publisher_authority_trust=TRUST_VERIFIED,
        warnings=(WARN_NOT_AUTHORIZING,),
    )
