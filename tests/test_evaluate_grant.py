"""Tests for `attest.verify.evaluate_grant` — Stage 4's ordered evaluation
(v0.2 §18.4 steps 1-11) and the two result components of §18.5.

`tests/test_grant.py` covers the PRIMITIVES — the documents, the two coverage
predicates, the ratchet, the ceilings, the redemption proof — one at a time and
without a trust store. This file covers the ORDER those primitives are applied
in, which is where a conforming implementation can still go wrong: a short
circuit taken one step too early masks a defect visible in the receipt itself, a
full scan replaced by a first-match makes the warning set depend on how evidence
was arranged, and a gate skipped makes a verifier tell a holder they may redeem
something the grant never spoke about.

Every test builds one working fixture and mutates exactly one thing, so a single
assertion isolates a single failure mode. Mirrored one-for-one by the TypeScript
core (§18 parity).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from attest import anchor, canon, grant, issue, keys, manifests, pq, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
PUBLISHER = "pub.example"
SUCCESSOR = "heritage.example"
OTHER = "marketplace.example"

ISSUER_KID = f"{ISSUER}/keys/test#ed25519-1"
PUB_KID = f"{PUBLISHER}/keys/grants#1"
SUCCESSOR_KID = f"{SUCCESSOR}/keys/grants#1"
OTHER_KID = f"{OTHER}/keys/grants#1"

VALID_FROM = "2026-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2026-01-01T00:00:00Z"
GRANT_ISSUED_AT = "2026-02-01T00:00:00Z"
DECLARED_AT = "2031-03-01T00:00:00Z"

# The pinned header the anchor fixture resolves to sits in January 2027, so a
# backstop dated before it has been REACHED and one dated 2046 has not. Both
# dates are after the grant's own `issued_at`: a document cannot be anchored
# before it exists, and a fixture that pretended otherwise would be testing an
# arrangement no publisher can produce.
HEADER_TIME = 1_800_000_000  # 2027-01-15T08:00:00Z
HEADER_HASH = "3a" * 32
FIXED_DATE_REACHED = "2027-01-01T00:00:00Z"
FIXED_DATE_FUTURE = "2046-01-01T00:00:00Z"

# TEST ONLY — fixed seed for the buyer key; the issuer signs v0.2 receipts,
# which require hybrid keys (§13's AND-rule).
BUYER_KP = keys.from_seed(bytes([11]) * 32)

RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
ART_OTHER = hashlib.sha256(b"artifact-elsewhere").hexdigest()

LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-sunset-grant-prose-v1").hexdigest()
OTHER_LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-sunset-grant-prose-v2").hexdigest()


# --- fixtures ----------------------------------------------------------------


def _hybrid_manifest(
    issuer: str, kid: str, version: int = 1
) -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(kid, hk.ed.pub, VALID_FROM, pub_ml_dsa_65=hk.mldsa.pub)
    return hk, manifests.build_key_manifest(issuer, version, MANIFEST_ISSUED_AT, [entry], hk, kid)


ISSUER_KEYS, ISSUER_MANIFEST = _hybrid_manifest(ISSUER, ISSUER_KID)
PUB_KEYS, PUB_MANIFEST = _hybrid_manifest(PUBLISHER, PUB_KID)
SUCCESSOR_KEYS, SUCCESSOR_MANIFEST = _hybrid_manifest(SUCCESSOR, SUCCESSOR_KID)
OTHER_KEYS, OTHER_MANIFEST = _hybrid_manifest(OTHER, OTHER_KID)


def _scope(
    artifact_series: str | None = None, artifacts: list[str] | None = None
) -> dict[str, Any]:
    return {
        "artifact_series": artifact_series,
        "artifacts": sorted(artifacts if artifacts is not None else [RECEIPT_ART]),
    }


def _activation(
    modes: list[str] | None = None,
    fixed_date: str | None = None,
    successor_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "modes": sorted(modes if modes is not None else ["publisher-declaration"]),
        "fixed_date": fixed_date,
        "successor_ids": sorted(successor_ids if successor_ids is not None else [SUCCESSOR]),
    }


def _grant(signing_keys: Any = None, kid: str = PUB_KID, **overrides: Any) -> dict[str, Any]:
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
    return grant.build_grant(
        signing_kp=PUB_KEYS if signing_keys is None else signing_keys, kid=kid, **body
    )


def _declaration(
    signing_keys: Any = None,
    kid: str = PUB_KID,
    scope: dict[str, Any] | None = None,
    publisher: str = PUBLISHER,
    declared_at: str = DECLARED_AT,
) -> dict[str, Any]:
    return grant.build_declaration(
        signing_kp=PUB_KEYS if signing_keys is None else signing_keys,
        kid=kid,
        publisher=publisher,
        scope=_scope() if scope is None else scope,
        declared_at=declared_at,
    )


def _payload(document: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
    """A v0.2 pledge-bearing payload that satisfies §18.6's conditional: a
    non-null `buyer.pubkey`, a `work.publisher_id`, and the `sunset-grant`
    label, all three of which are schema-REQUIRED once the term is present."""
    floor = _grant() if document is None else document
    base = make_payload(
        attest_version="0.2",
        buyer={"pubkey": keys.b64u(BUYER_KP.pub)},
        work={"publisher_id": PUBLISHER},
        license={
            "preservation_pledge": {
                "pledge": "sunset-grant-v1",
                "grant_uri": "https://pub.example/sunset-grant-v1.json",
                "grant_sha256": grant.grant_hash(floor),
            }
        },
        survivability={"end_of_life": "sunset-grant"},
    )
    return make_payload(**{**base, **overrides}) if overrides else base


def _trust_store(
    extra_manifests: dict[str, dict[str, Any]] | None = None,
    provenance: dict[str, str] | None = None,
    chains: dict[str, list[dict[str, Any]]] | None = None,
) -> verify.TrustStore:
    resolved = {PUBLISHER: PUB_MANIFEST, SUCCESSOR: SUCCESSOR_MANIFEST}
    resolved.update(extra_manifests or {})
    return verify.TrustStore(
        manifests=resolved,
        provenance=provenance if provenance is not None else {PUBLISHER: "bundle"},
        chains=chains or {},
    )


def _view(document: dict[str, Any] | None = None, **members: Any) -> dict[str, Any]:
    view: dict[str, Any] = {"grant": _grant() if document is None else document}
    view.update(members)
    return view


def _ots_proof(seed: bytes, salt: str, header_time: int, header_hash: str) -> dict[str, Any]:
    """One OTS op-chain over `seed` climbing to one pinned header — the same
    synthetic shape `tests/test_anchor_seeded.py` builds, computed with plain
    `hashlib` so the fixture pins the real algorithm rather than round-tripping
    `anchor.py`'s own logic. `salt` varies the chain so two proofs over the SAME
    seed resolve to two DIFFERENT headers, which is what a maximum-versus-
    minimum reduction can be told apart on."""
    sibling = bytes.fromhex(salt * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(seed).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    return {
        "kind": "ots",
        "ops": [
            ["append", sibling.hex()],
            ["sha256"],
            ["prepend", prefix.hex()],
            ["sha256"],
        ],
        "header_merkle_root": acc.hex(),
        "header_time": header_time,
        "header_hash": header_hash,
    }


def _anchor_evidence(seed: bytes) -> dict[str, Any]:
    return {"proofs": [_ots_proof(seed, "ab", HEADER_TIME, HEADER_HASH)]}


def _pin(proof: dict[str, Any]) -> tuple[str, anchor.PinnedHeader]:
    header_hash = str(proof["header_hash"])
    return header_hash, anchor.PinnedHeader(
        header_hash=header_hash,
        merkle_root=str(proof["header_merkle_root"]),
        time=int(proof["header_time"]),
    )


def _anchor_policy(seed: bytes, crqc_horizon: int | None = None) -> anchor.AnchorPolicy:
    evidence = _anchor_evidence(seed)
    return anchor.AnchorPolicy(
        pinned_headers=dict([_pin(evidence["proofs"][0])]), crqc_horizon=crqc_horizon
    )


def _evaluate(
    payload: dict[str, Any] | None = None,
    view: dict[str, Any] | None = None,
    trust_store: verify.TrustStore | None = None,
    anchor_policy: anchor.AnchorPolicy | None = None,
) -> verify.GrantVerdict:
    """Evaluate with a payload that hash-binds the view's OWN floor unless the
    caller supplied one — hybrid signatures are randomized, so two calls to the
    grant builder produce two different documents and a fixture that rebuilt
    the floor would test nothing but step 6."""
    if payload is None:
        floor = view.get("grant") if isinstance(view, dict) else None
        payload = _payload(floor if isinstance(floor, dict) else None)
    return verify.evaluate_grant(
        payload,
        _trust_store() if trust_store is None else trust_store,
        view,
        anchor_policy=anchor_policy,
    )


# --- the capability gate: no channel, no evaluation ---------------------------


def test_no_grant_view_evaluates_nothing_at_all() -> None:
    """`None` means the caller is not Stage-4-capable. Not even step 1 runs:
    the components stay at the values every pre-Stage-4 caller already
    implicitly gets, and no warning appears."""
    verdict = _evaluate(view=None)

    assert verdict == verify.GrantVerdict("not_checked", "not_checked", ())


def test_an_empty_view_still_opts_into_the_ordered_evaluation() -> None:
    """Supplying the channel AT ALL is the opt-in. An empty view carries no
    grant document, so it falls through to step 4 — but steps 1-3 ran first,
    which is exactly what the next two tests pin."""
    verdict = _evaluate(view={})

    assert verdict.grant == "not_checked"
    assert verdict.grant_trust == "not_checked"


# --- step 1: the pledge itself, from the signed payload alone -----------------


def test_a_receipt_with_no_pledge_reports_none() -> None:
    verdict = _evaluate(payload=make_payload(), view={})

    assert verdict.grant == "none"
    assert verdict.warnings == ()


@pytest.mark.parametrize(
    "pledge",
    [
        None,
        42,
        {},
        {"pledge": "sunset-grant-v1"},
        {"pledge": "sunset-grant-v1", "grant_uri": "https://pub.example/g.json"},
        {"pledge": "", "grant_uri": "https://pub.example/g.json", "grant_sha256": "a" * 64},
        {"pledge": "sunset-grant-v1", "grant_uri": "", "grant_sha256": "a" * 64},
        {
            "pledge": "sunset-grant-v1",
            "grant_uri": "https://pub.example/g.json",
            "grant_sha256": "AA" * 32,
        },
        {
            "pledge": "sunset-grant-v1",
            "grant_uri": "https://pub.example/g.json",
            "grant_sha256": "a" * 63,
        },
    ],
)
def test_a_pledge_that_is_not_readable_as_the_three_members_reports_none(pledge: Any) -> None:
    payload = _payload()
    payload["license"]["preservation_pledge"] = pledge

    verdict = _evaluate(payload=payload, view=_view())

    assert verdict.grant == "none"


# --- step 2: an unrecognized profile is never evaluated under v1's rules ------


def test_an_unrecognized_pledge_profile_is_not_checked_and_warns() -> None:
    """Valid-with-warning as SCHEMA, but MUST NOT be evaluated under
    `sunset-grant-v1`'s rules: a later profile may attach different meaning to
    the same members, and guessing is how two conforming implementations reach
    different verdicts on identical input."""
    payload = _payload()
    payload["license"]["preservation_pledge"]["pledge"] = "sunset-grant-v2"

    verdict = _evaluate(payload=payload, view=_view())

    assert verdict.grant == "not_checked"
    assert verdict.warnings == ("grant_pledge_type_unknown",)


def test_an_unrecognized_profile_stops_before_the_grant_is_even_looked_at() -> None:
    """Step 2 short-circuits ahead of step 5, so a perfectly good grant
    document produces no trust value: nothing about it was evaluated."""
    payload = _payload()
    payload["license"]["preservation_pledge"]["pledge"] = "sunset-grant-v2"

    verdict = _evaluate(payload=payload, view=_view())

    assert verdict.grant_trust == "not_checked"


# --- step 3: the issuer's own inconsistency, reported from the payload alone --


def test_eol_commitment_divergence_is_reported_without_any_evidence() -> None:
    """Visible in the signed payload alone, so it is reported whether or not
    grant evidence was supplied — this is the whole reason steps 1-3 run before
    step 4's short circuit."""
    payload = _payload()
    payload["survivability"]["eol_commitment_sha256"] = "b" * 64

    verdict = _evaluate(payload=payload, view={})

    assert verdict.grant == "not_checked"
    assert verdict.warnings == ("grant_commitment_divergence",)


def test_eol_commitment_divergence_does_not_stop_the_evaluation() -> None:
    """The license term governs and evaluation CONTINUES: the two fields have
    different authorities, and silently preferring one would hide the issuer's
    inconsistency from the person holding the receipt."""
    floor = _grant()
    payload = _payload(floor)
    payload["survivability"]["eol_commitment_sha256"] = "b" * 64

    verdict = _evaluate(payload=payload, view=_view(floor, declarations=[_declaration()]))

    assert verdict.grant == "activated"
    assert verdict.warnings == ("grant_commitment_divergence",)


def test_an_agreeing_eol_commitment_is_silent() -> None:
    floor = _grant()
    payload = _payload(floor)
    payload["survivability"]["eol_commitment_sha256"] = payload["license"]["preservation_pledge"][
        "grant_sha256"
    ]

    verdict = _evaluate(payload=payload, view=_view(floor))

    assert verdict.warnings == ()


# --- step 4: the structural ceilings, then the evidence ----------------------


@pytest.mark.parametrize("member", ["later_grants", "declarations"])
def test_exceeding_a_structural_ceiling_truncates_toward_not_checked(member: str) -> None:
    view = _view()
    view[member] = [{} for _ in range(65)]

    verdict = _evaluate(view=view)

    assert verdict.grant == "not_checked"
    assert verdict.grant_trust == "not_checked"


@pytest.mark.parametrize("member", ["later_grants", "declarations"])
def test_exactly_the_ceiling_is_within_it(member: str) -> None:
    view = _view()
    view[member] = [{} for _ in range(64)]

    verdict = _evaluate(view=view)

    assert verdict.grant != "not_checked"


def test_a_view_carrying_no_grant_document_is_not_checked() -> None:
    verdict = _evaluate(view={"declarations": [_declaration()]})

    assert verdict.grant == "not_checked"
    assert verdict.grant_trust == "not_checked"


# --- step 5: authentication, the triple domain binding, and the trust ladder --


def test_a_floor_that_does_not_authenticate_is_ignored() -> None:
    document = _grant()
    document["jurisdiction"] = "FR"  # signed over "IT"

    verdict = _evaluate(payload=_payload(document), view=_view(document))

    assert verdict.grant == "invalid_grant_ignored"


def test_an_unresolvable_publisher_manifest_leaves_the_grant_ignored() -> None:
    trust_store = verify.TrustStore(manifests={}, provenance={})

    verdict = _evaluate(view=_view(), trust_store=trust_store)

    assert verdict.grant == "invalid_grant_ignored"


def test_a_grant_signed_by_a_domain_that_is_not_the_publisher_is_a_signer_mismatch() -> None:
    """The marketplace-signing-a-grant-it-has-no-rights-to-concede case, named.
    The document authenticates perfectly — against the wrong domain."""
    document = _grant(OTHER_KEYS, kid=OTHER_KID, publisher=OTHER)
    payload = _payload(document)

    verdict = _evaluate(
        payload=payload,
        view=_view(document),
        trust_store=_trust_store({OTHER: OTHER_MANIFEST}),
    )

    assert verdict.grant == "invalid_grant_ignored"
    assert verdict.grant_trust == "signer_mismatch"
    assert verdict.warnings == ("grant_signer_not_publisher",)


def test_an_unsigned_document_from_a_foreign_domain_cannot_force_signer_mismatch() -> None:
    """`signer_mismatch` is reachable only for a document that ALREADY
    authenticated (§18.1). Otherwise appending garbage to an evidence array
    would buy an attacker a trust value for free."""
    document = _grant(OTHER_KEYS, kid=OTHER_KID, publisher=OTHER)
    document["jurisdiction"] = "FR"  # signed over "IT"
    payload = _payload(document)

    verdict = _evaluate(
        payload=payload,
        view=_view(document),
        trust_store=_trust_store({OTHER: OTHER_MANIFEST}),
    )

    assert verdict.grant == "invalid_grant_ignored"
    assert verdict.grant_trust != "signer_mismatch"
    assert verdict.warnings == ()


def test_a_grant_whose_publisher_member_disagrees_with_the_receipt_is_ignored() -> None:
    document = _grant(publisher=OTHER)
    payload = _payload(document)

    verdict = _evaluate(payload=payload, view=_view(document))

    assert verdict.grant == "invalid_grant_ignored"


def test_tls_provenance_for_the_publisher_yields_verified_grant_trust() -> None:
    verdict = _evaluate(
        view=_view(declarations=[_declaration()]),
        trust_store=_trust_store(provenance={PUBLISHER: "tls"}),
    )

    assert verdict.grant == "activated"
    assert verdict.grant_trust == "verified"


def test_a_discontinuous_publisher_chain_forces_unverified_rotation() -> None:
    _, unrelated = _hybrid_manifest(PUBLISHER, PUB_KID, version=7)
    trust_store = _trust_store(
        provenance={PUBLISHER: "tls"}, chains={PUBLISHER: [unrelated, PUB_MANIFEST]}
    )

    verdict = _evaluate(view=_view(declarations=[_declaration()]), trust_store=trust_store)

    assert verdict.grant == "activated"
    assert verdict.grant_trust == "unverified_rotation"


def test_grant_trust_is_reported_at_its_best_value_even_when_the_grant_is_rejected() -> None:
    """§18.5: reported at its best-available value even when grant evaluation
    later rejects the document, and never silently reset on failure."""
    document = _grant()
    payload = _payload(document)
    payload["license"]["preservation_pledge"]["grant_sha256"] = "c" * 64

    verdict = _evaluate(
        payload=payload,
        view=_view(document),
        trust_store=_trust_store(provenance={PUBLISHER: "tls"}),
    )

    assert verdict.grant == "invalid_grant_ignored"
    assert verdict.grant_trust == "verified"


# --- step 6: the receipt binding ---------------------------------------------


def test_a_grant_whose_hash_is_not_the_one_the_receipt_signed_is_ignored() -> None:
    payload = _payload()
    payload["license"]["preservation_pledge"]["grant_sha256"] = "d" * 64

    verdict = _evaluate(payload=payload, view=_view())

    assert verdict.grant == "invalid_grant_ignored"
    assert verdict.warnings == ("grant_commitment_mismatch",)


# --- step 7: the floor-relative ratchet --------------------------------------


def test_a_widening_later_version_becomes_effective() -> None:
    floor = _grant()
    later = _grant(
        grant_version=2,
        permissions=["deliver-to-holder", "redistribute-among-holders"],
        activation=_activation(successor_ids=[SUCCESSOR, OTHER]),
    )
    # The widened successor list is what proves the LATER version governed:
    # a declaration from `marketplace.example` is honored only under it.
    declaration = _declaration(OTHER_KEYS, kid=OTHER_KID)

    verdict = _evaluate(
        payload=_payload(floor),
        view=_view(floor, later_grants=[later], declarations=[declaration]),
        trust_store=_trust_store({OTHER: OTHER_MANIFEST}),
    )

    assert verdict.grant == "activated"
    assert verdict.warnings == ("grant_activated_by_successor",)


def test_a_narrowing_later_version_is_ignored_with_a_warning() -> None:
    floor = _grant(permissions=["deliver-to-holder", "redistribute-among-holders"])
    later = _grant(grant_version=2, permissions=["deliver-to-holder"])

    verdict = _evaluate(payload=_payload(floor), view=_view(floor, later_grants=[later]))

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_narrowing_ignored",)


def test_a_rollback_version_forces_unverified_rotation() -> None:
    floor = _grant(grant_version=5)
    older = _grant(grant_version=4)

    verdict = _evaluate(payload=_payload(floor), view=_view(floor, later_grants=[older]))

    assert verdict.grant_trust == "unverified_rotation"


def test_two_distinct_grants_sharing_a_version_are_rollback_or_equivocation() -> None:
    floor = _grant()
    twin = _grant(jurisdiction="FR")  # same grant_version, different document

    verdict = _evaluate(payload=_payload(floor), view=_view(floor, later_grants=[twin]))

    assert verdict.grant_trust == "unverified_rotation"


def test_a_byte_identical_duplicate_is_deduplicated_not_treated_as_equivocation() -> None:
    """ "Two DISTINCT authenticated grants" is what §18.3 rejects; a replayed
    copy of the floor is not a second document."""
    floor = _grant()

    verdict = _evaluate(
        payload=_payload(floor),
        view=_view(floor, later_grants=[json.loads(json.dumps(floor))]),
    )

    assert verdict.grant_trust == "unauthenticated_tofu"


def test_a_later_version_from_another_publisher_is_inadmissible_and_silent() -> None:
    """§18.3: such a document "is not a later version of this grant at all; it
    is a different grant". It says nothing about THIS grant's currency, so it
    must not move `grant_trust` either — otherwise anyone could downgrade a
    verdict by appending a stranger's genuine grant to an array."""
    floor = _grant()
    foreign = _grant(OTHER_KEYS, kid=OTHER_KID, grant_version=2, publisher=OTHER)

    verdict = _evaluate(
        payload=_payload(floor),
        view=_view(floor, later_grants=[foreign]),
        trust_store=_trust_store({OTHER: OTHER_MANIFEST}),
    )

    assert verdict.grant_trust == "unauthenticated_tofu"
    assert verdict.warnings == ()


def test_an_unauthenticated_later_version_is_ignored_without_effect() -> None:
    floor = _grant()
    forged = _grant(grant_version=2)
    forged["jurisdiction"] = "FR"  # signed over "IT"

    verdict = _evaluate(payload=_payload(floor), view=_view(floor, later_grants=[forged]))

    assert verdict.grant_trust == "unauthenticated_tofu"
    assert verdict.warnings == ()


def test_the_effective_version_is_the_maximum_over_the_floor_relative_filter() -> None:
    """A maximum over a filter, never a sequential fold — so the result does
    not depend on the order `later_grants` is presented in."""
    floor = _grant()
    v2 = _grant(grant_version=2, activation=_activation(successor_ids=[SUCCESSOR, OTHER]))
    v3 = _grant(grant_version=3, activation=_activation(successor_ids=[SUCCESSOR]))
    declaration = _declaration(OTHER_KEYS, kid=OTHER_KID)
    trust_store = _trust_store({OTHER: OTHER_MANIFEST})

    forward = _evaluate(
        payload=_payload(floor),
        view=_view(floor, later_grants=[v2, v3], declarations=[declaration]),
        trust_store=trust_store,
    )
    backward = _evaluate(
        payload=_payload(floor),
        view=_view(floor, later_grants=[v3, v2], declarations=[declaration]),
        trust_store=trust_store,
    )

    # v3 dropped `marketplace.example` back off the successor list relative to
    # v2 — but the ratchet compares each candidate against the FLOOR, where it
    # was never present, so v3 passes and, being the greatest version, governs.
    # Under v3 the marketplace's declaration is a stranger's.
    assert forward.grant == "dormant"
    assert forward == backward


def test_a_later_version_changing_the_prose_still_governs_and_reports_it() -> None:
    """The structural members of the later version govern; the prose that binds
    this buyer stays the one their own receipt hash-bound."""
    floor = _grant()
    later = _grant(
        grant_version=2,
        legal_text_uri="https://pub.example/sunset-grant-v2",
        legal_text_sha256=OTHER_LEGAL_TEXT_SHA256,
    )

    verdict = _evaluate(
        payload=_payload(floor),
        view=_view(floor, later_grants=[later], declarations=[_declaration()]),
    )

    assert verdict.grant == "activated"
    assert verdict.warnings == ("grant_legal_text_changed",)


def test_a_later_version_moving_only_the_uri_still_reports_the_change() -> None:
    """All three prose-bearing members count, the URI included: a document
    served from a new location is a new document to the person who has to go
    read it, even when the hash is unchanged."""
    floor = _grant()
    later = _grant(grant_version=2, legal_text_uri="https://mirror.example/sunset-grant-v1")

    verdict = _evaluate(payload=_payload(floor), view=_view(floor, later_grants=[later]))

    assert "grant_legal_text_changed" in verdict.warnings


# --- step 8: scope coverage is a GATE ----------------------------------------


def test_an_uncovered_receipt_is_dormant_and_neither_path_is_evaluated() -> None:
    """Reporting `activated` here would tell the holder they may redeem
    something the grant never spoke about, and would contradict §18.7's own
    custodian precondition. `grant_unanchored` is absent even though the
    fixed-date mode is declared: step 8 returns before step 10."""
    floor = _grant(
        scope=_scope(artifacts=[ART_OTHER]),
        activation=_activation(
            modes=["fixed-date", "publisher-declaration"], fixed_date=FIXED_DATE_FUTURE
        ),
    )

    verdict = _evaluate(payload=_payload(floor), view=_view(floor, declarations=[_declaration()]))

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_scope_uncovered",)


def test_a_grant_scoped_to_a_wider_catalogue_still_covers_the_receipt() -> None:
    floor = _grant(scope=_scope(artifacts=[ART_OTHER, RECEIPT_ART]))

    verdict = _evaluate(
        payload=_payload(floor),
        view=_view(
            floor, declarations=[_declaration(scope=_scope(artifacts=[ART_OTHER, RECEIPT_ART]))]
        ),
    )

    assert verdict.grant == "activated"


# --- step 9: the declaration path, scanned in FULL ---------------------------


def test_a_publisher_declaration_activates_the_grant() -> None:
    verdict = _evaluate(view=_view(declarations=[_declaration()]))

    assert verdict.grant == "activated"
    assert verdict.warnings == ()


def test_a_successor_declaration_activates_and_says_so() -> None:
    declaration = _declaration(SUCCESSOR_KEYS, kid=SUCCESSOR_KID)

    verdict = _evaluate(view=_view(declarations=[declaration]))

    assert verdict.grant == "activated"
    assert verdict.warnings == ("grant_activated_by_successor",)


def test_a_declaration_from_a_stranger_is_never_honored() -> None:
    declaration = _declaration(OTHER_KEYS, kid=OTHER_KID)

    verdict = _evaluate(
        view=_view(declarations=[declaration]), trust_store=_trust_store({OTHER: OTHER_MANIFEST})
    )

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_declaration_ignored",)


def test_a_declaration_that_does_not_cover_the_grant_scope_is_ignored() -> None:
    declaration = _declaration(scope=_scope(artifacts=[ART_OTHER]))

    verdict = _evaluate(view=_view(declarations=[declaration]))

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_declaration_ignored",)


def test_the_scan_never_stops_at_the_first_declaration_that_succeeds() -> None:
    """A full scan is required rather than a short circuit precisely so the
    warning set is a function of the evidence and not of its arrangement: an
    implementation that stopped early would report a different result than one
    that did not, and both would be conforming."""
    good = _declaration()
    bad = _declaration(OTHER_KEYS, kid=OTHER_KID)
    trust_store = _trust_store({OTHER: OTHER_MANIFEST})

    good_first = _evaluate(view=_view(declarations=[good, bad]), trust_store=trust_store)
    bad_first = _evaluate(view=_view(declarations=[bad, good]), trust_store=trust_store)

    assert good_first.grant == "activated"
    assert good_first.warnings == ("grant_declaration_ignored",)
    assert good_first == bad_first


def test_each_declaration_warning_is_emitted_at_most_once() -> None:
    stranger = _declaration(OTHER_KEYS, kid=OTHER_KID)
    successor = _declaration(SUCCESSOR_KEYS, kid=SUCCESSOR_KID)
    trust_store = _trust_store({OTHER: OTHER_MANIFEST})

    verdict = _evaluate(
        view=_view(declarations=[stranger, successor, stranger, successor, _declaration()]),
        trust_store=trust_store,
    )

    assert verdict.grant == "activated"
    assert verdict.warnings == ("grant_declaration_ignored", "grant_activated_by_successor")


def test_the_successor_list_is_read_from_the_effective_grant() -> None:
    """A later version that widened `successor_ids` widens who may declare; one
    that narrowed it never became effective."""
    floor = _grant(activation=_activation(successor_ids=[]))
    later = _grant(grant_version=2, activation=_activation(successor_ids=[SUCCESSOR]))
    declaration = _declaration(SUCCESSOR_KEYS, kid=SUCCESSOR_KID)

    without = _evaluate(payload=_payload(floor), view=_view(floor, declarations=[declaration]))
    with_later = _evaluate(
        payload=_payload(floor),
        view=_view(floor, later_grants=[later], declarations=[declaration]),
    )

    assert without.grant == "dormant"
    assert with_later.grant == "activated"


@pytest.mark.parametrize("declaration", [None, 42, {}, {"publisher": PUBLISHER}, []])
def test_a_malformed_declaration_is_ignored_not_raised(declaration: Any) -> None:
    verdict = _evaluate(view=_view(declarations=[declaration]))

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_declaration_ignored",)


# --- step 10: the fixed-date path --------------------------------------------


def _fixed_date_fixture(fixed_date: str) -> tuple[dict[str, Any], dict[str, Any]]:
    document = _grant(
        activation=_activation(modes=["fixed-date", "publisher-declaration"], fixed_date=fixed_date)
    )
    return document, _anchor_evidence(canon.canonical_bytes(document))


def test_an_anchored_proof_past_the_fixed_date_activates_the_grant() -> None:
    document, evidence = _fixed_date_fixture(FIXED_DATE_REACHED)
    policy = _anchor_policy(canon.canonical_bytes(document))

    verdict = _evaluate(
        payload=_payload(document),
        view=_view(document, anchor=evidence),
        anchor_policy=policy,
    )

    assert verdict.grant == "activated"
    assert verdict.warnings == ()


def test_a_proof_resolving_earlier_than_the_fixed_date_leaves_the_grant_dormant() -> None:
    document, evidence = _fixed_date_fixture(FIXED_DATE_FUTURE)
    policy = _anchor_policy(canon.canonical_bytes(document))

    verdict = _evaluate(
        payload=_payload(document),
        view=_view(document, anchor=evidence),
        anchor_policy=policy,
    )

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_unanchored",)


def test_the_mode_declared_with_no_proof_at_all_warns_unanchored() -> None:
    document, _ = _fixed_date_fixture(FIXED_DATE_REACHED)

    verdict = _evaluate(payload=_payload(document), view=_view(document))

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_unanchored",)


def test_a_verifier_with_no_anchor_policy_cannot_open_a_grant_on_time() -> None:
    """Not anchor-capable at all: the proof cannot be evaluated, so the grant
    stays closed — the direction §18.4's failure asymmetry requires."""
    document, evidence = _fixed_date_fixture(FIXED_DATE_REACHED)

    verdict = _evaluate(payload=_payload(document), view=_view(document, anchor=evidence))

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_unanchored",)


def test_an_anchor_over_the_wrong_document_does_not_activate() -> None:
    document, _ = _fixed_date_fixture(FIXED_DATE_REACHED)
    policy = _anchor_policy(canon.canonical_bytes(document))

    verdict = _evaluate(
        payload=_payload(document),
        view=_view(document, anchor=_anchor_evidence(b"some other document")),
        anchor_policy=policy,
    )

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_unanchored",)


def test_a_declaration_that_activated_suppresses_the_backstop_warning() -> None:
    """A missing backstop proof says nothing about a grant that is already
    open, and emitting it would make the warning set depend on which spare
    evidence a caller happened to attach."""
    document, _ = _fixed_date_fixture(FIXED_DATE_FUTURE)

    verdict = _evaluate(
        payload=_payload(document), view=_view(document, declarations=[_declaration()])
    )

    assert verdict.grant == "activated"
    assert verdict.warnings == ()


def test_two_genuine_proofs_reduce_to_the_MAXIMUM_not_the_minimum() -> None:
    """§18.4's reduction, and the one a `verify_anchor`-shaped habit gets
    backwards. `anchored_before` is the MINIMUM because it answers "no later
    than when did this exist?"; `fixed-date` asks "has time reached T?", where
    the LATEST verified header is the conservative answer. Taking the minimum
    would be sound-looking and wrong the moment a bundle carries two genuine
    proofs: the old one would hold the grant closed forever, a false negative
    the buyer cannot recover from."""
    stale_time = 1_760_000_000  # 2025-10-09, before the backstop
    stale_hash = "5c" * 32
    document = _grant(
        activation=_activation(
            modes=["fixed-date", "publisher-declaration"], fixed_date=FIXED_DATE_REACHED
        )
    )
    seed = canon.canonical_bytes(document)
    stale = _ots_proof(seed, "ee", stale_time, stale_hash)
    fresh = _ots_proof(seed, "ab", HEADER_TIME, HEADER_HASH)
    policy = anchor.AnchorPolicy(pinned_headers=dict([_pin(stale), _pin(fresh)]), crqc_horizon=None)

    verdict = _evaluate(
        payload=_payload(document),
        view=_view(document, anchor={"proofs": [stale, fresh]}),
        anchor_policy=policy,
    )

    assert verdict.grant == "activated"
    assert verdict.warnings == ()


def test_the_crqc_horizon_check_applies_to_the_fixed_date_proof() -> None:
    document, evidence = _fixed_date_fixture(FIXED_DATE_REACHED)
    policy = _anchor_policy(canon.canonical_bytes(document), crqc_horizon=HEADER_TIME - 1)

    verdict = _evaluate(
        payload=_payload(document),
        view=_view(document, anchor=evidence),
        anchor_policy=policy,
    )

    assert verdict.grant == "dormant"
    assert verdict.warnings == ("grant_unanchored",)


def test_a_fixed_date_set_without_the_mode_never_activates() -> None:
    """`heartbeat-absence` and any unregistered mode contribute nothing; so
    does a `fixed_date` whose mode was never declared."""
    document = _grant(activation=_activation(modes=["publisher-declaration"], fixed_date=None))

    verdict = _evaluate(payload=_payload(document), view=_view(document))

    assert verdict.grant == "dormant"
    assert verdict.warnings == ()


# --- step 11 and the failure direction ---------------------------------------


def test_a_covered_authenticated_grant_with_no_trigger_evidence_is_dormant() -> None:
    verdict = _evaluate(view=_view())

    assert verdict.grant == "dormant"
    assert verdict.grant_trust == "unauthenticated_tofu"
    assert verdict.warnings == ()


@pytest.mark.parametrize(
    "view",
    [
        {"grant": None},
        {"grant": 42},
        {"grant": [], "later_grants": "not-a-list", "declarations": 7, "anchor": "no"},
        {"grant": {"signature": {"kid": "../../etc/passwd#1"}}},
        {"grant": {"signature": {"kid": 42}}, "later_grants": [None, 42, "x"]},
        {"later_grants": [{"grant_version": 2}], "declarations": [{"publisher": None}]},
    ],
)
def test_hostile_evidence_never_raises(view: dict[str, Any]) -> None:
    verdict = _evaluate(view=view)

    assert verdict.grant in {"not_checked", "invalid_grant_ignored", "dormant"}
    assert verdict.grant != "activated"


@pytest.mark.parametrize("bad", [[], "grant", 42, ({},)])
def test_a_grant_view_that_is_not_an_evidence_object_fails_loud(bad: Any) -> None:
    """The caller-contract enforcement its Stage 2/3 siblings already have: a
    lone grant DOCUMENT passed where the evidence object belongs would be read
    member by member and resolve to `not_checked`, silently reporting "no grant
    evidence" to a caller who supplied some."""
    with pytest.raises(TypeError):
        _evaluate(view=bad)


# --- integration with verify(): the D6 no-exception property -----------------


def _envelope(payload: dict[str, Any]) -> bytes:
    return json.dumps(issue.issue(payload, ISSUER_KEYS, ISSUER_KID)).encode("utf-8")


def _verify_store(
    publisher_chains: dict[str, list[dict[str, Any]]] | None = None,
) -> verify.TrustStore:
    return verify.TrustStore(
        manifests={
            ISSUER: ISSUER_MANIFEST,
            PUBLISHER: PUB_MANIFEST,
            SUCCESSOR: SUCCESSOR_MANIFEST,
        },
        provenance={ISSUER: "tls", PUBLISHER: "bundle"},
        chains=publisher_chains or {},
    )


def test_verify_without_grant_view_is_byte_identical_to_the_pre_stage_4_result() -> None:
    floor = _grant()
    envelope = _envelope(_payload(floor))

    result = verify.verify(envelope, _verify_store())

    assert result.grant == "not_checked"
    assert result.grant_trust == "not_checked"
    assert result.ok is True
    assert result.warnings == ()


def test_verify_reports_an_activated_grant_without_touching_ok() -> None:
    floor = _grant()
    envelope = _envelope(_payload(floor))

    result = verify.verify(
        envelope, _verify_store(), grant_view=_view(floor, declarations=[_declaration()])
    )

    assert result.grant == "activated"
    assert result.ok is True
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"
    assert result.trust == "verified"


def test_an_invalid_grant_never_makes_a_receipt_not_ok() -> None:
    floor = _grant()
    payload = _payload(floor)
    payload["license"]["preservation_pledge"]["grant_sha256"] = "e" * 64
    envelope = _envelope(payload)

    result = verify.verify(envelope, _verify_store(), grant_view=_view(floor))

    assert result.grant == "invalid_grant_ignored"
    assert result.ok is True
    assert result.errors == ()
    assert "grant_commitment_mismatch" in result.warnings


def test_the_publisher_chain_never_moves_the_receipts_own_trust() -> None:
    """§18.1: the publisher's manifest gets the same ladder as an issuer's,
    reported ONLY in `grant_trust`. The receipt's `trust` remains a statement
    about the ISSUER."""
    _, unrelated = _hybrid_manifest(PUBLISHER, PUB_KID, version=7)
    floor = _grant()
    envelope = _envelope(_payload(floor))

    result = verify.verify(
        envelope,
        _verify_store({PUBLISHER: [unrelated, PUB_MANIFEST]}),
        grant_view=_view(floor, declarations=[_declaration()]),
    )

    assert result.grant_trust == "unverified_rotation"
    assert result.trust == "verified"


def test_verify_rejects_a_grant_view_that_is_not_an_evidence_object() -> None:
    envelope = _envelope(_payload())

    with pytest.raises(TypeError):
        verify.verify(envelope, _verify_store(), grant_view=[])  # type: ignore[arg-type]
