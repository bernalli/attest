"""WitnessPolicy parsing, epoch validity, compromise lifecycle, conflict predicate.

Contract: v0.2 §11.4 (P1.1b amendment). The policy is TRUSTED verifier
configuration on the same rail as pinned log keys, so a malformed document
RAISES — it signals a caller/configuration bug, never adversarial input
(§10.2). Nothing here touches evidence.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import pytest

from attest import canon, keys, pq, witness

_ED25519_PUB = keys.b64u(bytes(range(32)))
_ED25519_PUB_2 = keys.b64u(bytes(range(1, 33)))
_MLDSA_PUB = keys.b64u(bytes(pq.ML_DSA_65_PK_LEN))


def _pin(**overrides: Any) -> dict[str, Any]:
    """A minimal valid corroboration-only pin (no ML-DSA leg required)."""
    pin: dict[str, Any] = {
        "operator_id": "witness.example",
        "control_group": "witness.example",
        "name": "witness.example/w1",
        "ed25519_pub_b64u": _ED25519_PUB,
        "mldsa_65_pub_b64u": None,
        "roles": ["corroboration"],
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": None,
        "affiliated_domains": ["witness.example"],
    }
    pin.update(overrides)
    return pin


def _epoch(**overrides: Any) -> dict[str, Any]:
    epoch: dict[str, Any] = {
        "epoch_id": "bootstrap-1",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": None,
        "log_origins": [],
        "threshold": {"n": 1, "m": 1},
        "witnesses": [_pin()],
    }
    epoch.update(overrides)
    return epoch


def _policy(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": "attest-witness-policy-v1",
        "epochs": [_epoch()],
    }
    document.update(overrides)
    return document


def _at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


# --- top-level shape -------------------------------------------------------


def test_empty_canonical_policy_parses() -> None:
    """The packaged default: no epochs, so `witnessed` is unreachable."""
    policy = witness.parse_policy({"schema": "attest-witness-policy-v1", "epochs": []})
    assert policy.epochs == ()


def test_canonical_empty_policy_bytes_are_jcs() -> None:
    """§11.4: comparisons and packaged-byte assertions use attest JCS."""
    assert witness.CANONICAL_EMPTY_POLICY_BYTES == canon.canonical_bytes(
        {"schema": "attest-witness-policy-v1", "epochs": []}
    )
    reparsed = witness.parse_policy(canon.loads_strict(witness.CANONICAL_EMPTY_POLICY_BYTES))
    assert reparsed.epochs == ()


def test_full_policy_parses() -> None:
    policy = witness.parse_policy(_policy())
    assert len(policy.epochs) == 1
    epoch = policy.epochs[0]
    assert epoch.epoch_id == "bootstrap-1"
    assert epoch.not_after is None
    assert epoch.threshold == witness.Threshold(n=1, m=1)
    assert len(epoch.witnesses) == 1


def test_unknown_top_level_member_rejected() -> None:
    """`WitnessPolicy` is a CLOSED object: no other top-level member."""
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(extra="nope"))


def test_wrong_schema_literal_rejected() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(schema="attest-witness-policy-v2"))


def test_missing_top_level_member_rejected() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy({"schema": "attest-witness-policy-v1"})


def test_non_object_document_rejected() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(["attest-witness-policy-v1"])


# --- epoch shape -----------------------------------------------------------


def test_epoch_unknown_member_rejected() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(note="nope")]))


def test_epoch_missing_member_rejected() -> None:
    epoch = _epoch()
    del epoch["threshold"]
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[epoch]))


@pytest.mark.parametrize(
    "epoch_id",
    ["", "-leading", "UPPER", "a" * 129, "has space", "dot.ok\n"],
)
def test_epoch_id_grammar_rejected(epoch_id: str) -> None:
    """`^[a-z0-9][a-z0-9._-]{0,127}$`, pinned by the spec literal."""
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(epoch_id=epoch_id)]))


@pytest.mark.parametrize("epoch_id", ["a", "bootstrap-1", "x." + "y" * 126])
def test_epoch_id_grammar_accepted(epoch_id: str) -> None:
    policy = witness.parse_policy(_policy(epochs=[_epoch(epoch_id=epoch_id)]))
    assert policy.epochs[0].epoch_id == epoch_id


def test_duplicate_epoch_id_rejected() -> None:
    """`epoch_id` is unique across the policy."""
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(), _epoch()]))


@pytest.mark.parametrize(
    "timestamp",
    ["2026-01-01T00:00:00", "2026-01-01 00:00:00Z", "2026-01-01T00:00:00.5Z", "not-a-date"],
)
def test_epoch_timestamp_must_be_exact_utc_second(timestamp: str) -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(not_before=timestamp)]))


def test_epoch_not_after_before_not_before_rejected() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(
            _policy(
                epochs=[
                    _epoch(
                        not_before="2026-06-01T00:00:00Z",
                        not_after="2026-01-01T00:00:00Z",
                    )
                ]
            )
        )


def test_log_origins_must_be_sorted_and_duplicate_free() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(log_origins=["b.example", "a.example"])]))
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(log_origins=["a.example", "a.example"])]))


def test_log_origins_sorted_accepted() -> None:
    policy = witness.parse_policy(_policy(epochs=[_epoch(log_origins=["a.example", "b.example"])]))
    assert policy.epochs[0].log_origins == ("a.example", "b.example")


@pytest.mark.parametrize(
    "threshold",
    [{"n": 1}, {"n": 1, "m": 1, "extra": 0}, {"n": 0, "m": 1}, {"n": 1, "m": 0}, {"n": 1, "m": 2}],
)
def test_threshold_shape_rejected(threshold: dict[str, Any]) -> None:
    """Closed `{n, m}`, both positive, and `m <= n` (m votes out of n groups)."""
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(threshold=threshold)]))


def test_threshold_rejects_bool() -> None:
    """`True` is an `int` in Python; the TS core would never accept it."""
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(threshold={"n": True, "m": 1})]))


def test_log_origins_must_be_printable_ascii() -> None:
    """Cross-core sort parity: Python orders by code point, JS by UTF-16 unit.

    `["\U00010000", "\ufffd"]` is unsorted for Python and sorted for
    JavaScript — the ASCII grammar of §9.3 is what keeps the two cores from
    disagreeing about the same array.
    """
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(log_origins=["\U00010000"])]))


def test_load_policy_rejects_non_integer_json_literals() -> None:
    """`1.0` is a float literal: canon rejects it before the policy is shaped.

    Loading from bytes is what makes the cores agree on numbers — an in-memory
    `{"n": 1.0}` is indistinguishable from `{"n": 1}` in TypeScript.
    """
    document = b'{"epochs":[],"schema":"attest-witness-policy-v1"}'
    assert witness.load_policy(document).epochs == ()
    with pytest.raises(canon.CanonError):
        witness.load_policy(b'{"epochs":[{"threshold":{"n":1.0}}],"schema":"x"}')


def test_integer_past_the_js_safe_range_rejected() -> None:
    """TypeScript cannot represent 2^53+1 exactly, so neither core accepts it."""
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(threshold={"n": 2**53 + 1, "m": 1})]))


# --- witness pin shape -----------------------------------------------------


def test_pin_unknown_member_rejected() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(witnesses=[_pin(note="nope")])]))


def test_pin_missing_member_rejected() -> None:
    pin = _pin()
    del pin["roles"]
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(witnesses=[pin])]))


def test_dns_grammar_rejects_trailing_newline() -> None:
    """Python's `$` matches before a trailing newline; JavaScript's does not.

    Accepting it here would make the two cores disagree on which policies are
    admissible — the exact class of divergence this project cannot carry.
    """
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(
            _policy(
                epochs=[
                    _epoch(
                        witnesses=[
                            _pin(
                                operator_id="witness.example\n",
                                affiliated_domains=["witness.example\n"],
                            )
                        ]
                    )
                ]
            )
        )


@pytest.mark.parametrize("field", ["operator_id", "control_group"])
def test_pin_identifiers_must_be_lowercase_dns(field: str) -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(
            _policy(
                epochs=[
                    _epoch(
                        witnesses=[
                            _pin(
                                **{field: "Witness.Example"}, affiliated_domains=["witness.example"]
                            )
                        ]
                    )
                ]
            )
        )


def test_pin_name_follows_c2sp_grammar() -> None:
    """Printable ASCII without `+` — the signed-note key-name grammar (§9.3)."""
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(witnesses=[_pin(name="witness+w1")])]))
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(witnesses=[_pin(name="")])]))


def test_affiliated_domains_must_contain_operator_id() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(
            _policy(epochs=[_epoch(witnesses=[_pin(affiliated_domains=["other.example"])])])
        )


@pytest.mark.parametrize("field", ["roles", "affiliated_domains"])
def test_pin_lists_must_be_sorted_and_duplicate_free(field: str) -> None:
    unsorted = {
        "roles": ["sunset-activation", "corroboration"],
        "affiliated_domains": ["witness.example", "a.example"],
    }[field]
    duplicated = {
        "roles": ["corroboration", "corroboration"],
        "affiliated_domains": ["witness.example", "witness.example"],
    }[field]
    for value in (unsorted, duplicated):
        with pytest.raises(witness.WitnessError):
            witness.parse_policy(
                _policy(
                    epochs=[
                        _epoch(witnesses=[_pin(**{field: value}, mldsa_65_pub_b64u=_MLDSA_PUB)])
                    ]
                )
            )


def test_mldsa_may_be_null_only_without_sunset_activation() -> None:
    """§11.4: the activation leg is required exactly when the role is held."""
    policy = witness.parse_policy(
        _policy(epochs=[_epoch(witnesses=[_pin(roles=["corroboration"], mldsa_65_pub_b64u=None)])])
    )
    assert policy.epochs[0].witnesses[0].mldsa_65_pub is None

    with pytest.raises(witness.WitnessError):
        witness.parse_policy(
            _policy(
                epochs=[
                    _epoch(
                        witnesses=[
                            _pin(
                                roles=["corroboration", "sunset-activation"],
                                mldsa_65_pub_b64u=None,
                            )
                        ]
                    )
                ]
            )
        )


def test_public_key_lengths_enforced() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(
            _policy(epochs=[_epoch(witnesses=[_pin(ed25519_pub_b64u=keys.b64u(b"short"))])])
        )
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(
            _policy(
                epochs=[
                    _epoch(
                        witnesses=[
                            _pin(
                                roles=["corroboration", "sunset-activation"],
                                mldsa_65_pub_b64u=keys.b64u(b"short"),
                            )
                        ]
                    )
                ]
            )
        )


def test_unknown_role_rejected() -> None:
    with pytest.raises(witness.WitnessError):
        witness.parse_policy(_policy(epochs=[_epoch(witnesses=[_pin(roles=["auditor"])])]))


def test_parse_does_not_mutate_the_caller_document() -> None:
    document = _policy()
    before = copy.deepcopy(document)
    witness.parse_policy(document)
    assert document == before


# --- epoch resolution and validity -----------------------------------------


def test_epoch_lookup_by_id() -> None:
    policy = witness.parse_policy(_policy())
    assert policy.epoch("bootstrap-1") is policy.epochs[0]
    assert policy.epoch("absent") is None


def test_epoch_validity_is_inclusive_at_both_boundaries() -> None:
    policy = witness.parse_policy(
        _policy(
            epochs=[_epoch(not_before="2026-01-01T00:00:00Z", not_after="2026-12-31T23:59:59Z")]
        )
    )
    epoch = policy.epochs[0]
    assert epoch.covers(_at("2026-01-01T00:00:00Z"))
    assert epoch.covers(_at("2026-12-31T23:59:59Z"))
    assert not epoch.covers(_at("2025-12-31T23:59:59Z"))
    assert not epoch.covers(_at("2027-01-01T00:00:00Z"))


def test_open_ended_epoch_never_expires() -> None:
    epoch = witness.parse_policy(_policy()).epochs[0]
    assert epoch.covers(_at("2999-01-01T00:00:00Z"))


def test_pin_validity_is_inclusive_at_both_boundaries() -> None:
    policy = witness.parse_policy(
        _policy(
            epochs=[
                _epoch(
                    witnesses=[
                        _pin(
                            not_before="2026-01-01T00:00:00Z",
                            not_after="2026-06-30T23:59:59Z",
                        )
                    ]
                )
            ]
        )
    )
    pin = policy.epochs[0].witnesses[0]
    assert pin.covers(_at("2026-01-01T00:00:00Z"))
    assert pin.covers(_at("2026-06-30T23:59:59Z"))
    assert not pin.covers(_at("2026-07-01T00:00:00Z"))


# --- compromise lifecycle (tri-state) --------------------------------------


def test_absent_compromised_after_means_no_compromise_declared() -> None:
    pin = witness.parse_policy(_policy()).epochs[0].witnesses[0]
    assert pin.has_standing_at(_at("2999-01-01T00:00:00Z"))


def test_compromised_after_string_is_an_inclusive_cutoff() -> None:
    policy = witness.parse_policy(
        _policy(epochs=[_epoch(witnesses=[_pin(compromised_after="2026-06-01T00:00:00Z")])])
    )
    pin = policy.epochs[0].witnesses[0]
    assert pin.has_standing_at(_at("2026-05-31T23:59:59Z"))
    assert pin.has_standing_at(_at("2026-06-01T00:00:00Z"))
    assert not pin.has_standing_at(_at("2026-06-01T00:00:01Z"))


def test_explicit_null_compromised_after_removes_standing_at_every_time() -> None:
    """Unknown onset is fail-closed: no standing at ANY `T`, ever."""
    policy = witness.parse_policy(
        _policy(epochs=[_epoch(witnesses=[_pin(compromised_after=None)])])
    )
    pin = policy.epochs[0].witnesses[0]
    assert not pin.has_standing_at(_at("2020-01-01T00:00:00Z"))
    assert not pin.has_standing_at(_at("2026-01-01T00:00:00Z"))
    assert not pin.has_standing_at(_at("2999-01-01T00:00:00Z"))


def test_absent_and_explicit_null_compromised_after_are_distinguished() -> None:
    """The tri-state would collapse if parsing normalized absent to None."""
    absent = witness.parse_policy(_policy()).epochs[0].witnesses[0]
    explicit = (
        witness.parse_policy(_policy(epochs=[_epoch(witnesses=[_pin(compromised_after=None)])]))
        .epochs[0]
        .witnesses[0]
    )
    assert absent.compromise_declared is False
    assert explicit.compromise_declared is True
    assert absent.compromised_after is None
    assert explicit.compromised_after is None


def test_standing_also_requires_pin_validity_window() -> None:
    policy = witness.parse_policy(
        _policy(epochs=[_epoch(witnesses=[_pin(not_after="2026-06-30T23:59:59Z")])])
    )
    pin = policy.epochs[0].witnesses[0]
    assert pin.has_standing_at(_at("2026-06-30T23:59:59Z"))
    assert not pin.has_standing_at(_at("2026-07-01T00:00:00Z"))


# --- conflict predicate ----------------------------------------------------


def _conflict_epoch() -> witness.WitnessEpoch:
    """Two operators, one shared control group, one independent."""
    policy = witness.parse_policy(
        _policy(
            epochs=[
                _epoch(
                    threshold={"n": 2, "m": 1},
                    witnesses=[
                        _pin(
                            operator_id="a.example",
                            control_group="shared.example",
                            name="a.example/w",
                            affiliated_domains=["a.example", "vendor.example"],
                        ),
                        _pin(
                            operator_id="b.example",
                            control_group="shared.example",
                            name="b.example/w",
                            ed25519_pub_b64u=_ED25519_PUB_2,
                            affiliated_domains=["b.example"],
                        ),
                        _pin(
                            operator_id="c.example",
                            control_group="c.example",
                            name="c.example/w",
                            ed25519_pub_b64u=_ED25519_PUB_2,
                            affiliated_domains=["c.example"],
                        ),
                    ],
                )
            ]
        )
    )
    return policy.epochs[0]


def test_direct_conflict() -> None:
    epoch = _conflict_epoch()
    assert epoch.is_conflicted(epoch.witnesses[0], "vendor.example")


def test_transitive_conflict_through_shared_control_group() -> None:
    """`b` never names `vendor.example`, but shares `a`'s control group."""
    epoch = _conflict_epoch()
    assert epoch.is_conflicted(epoch.witnesses[1], "vendor.example")


def test_unrelated_pin_is_not_conflicted() -> None:
    epoch = _conflict_epoch()
    assert not epoch.is_conflicted(epoch.witnesses[2], "vendor.example")


def test_domain_inequality_does_not_establish_independence() -> None:
    """§11.4 forbids reading non-conflict as a positive independence claim."""
    epoch = _conflict_epoch()
    assert not hasattr(epoch, "is_independent")
    assert not hasattr(witness, "establish_independence")


# --- constants -------------------------------------------------------------


def test_normative_constants() -> None:
    assert witness.MAX_WITNESS_SKEW_SECONDS == 600
    assert witness.MAX_WITNESS_ANCHOR_DELAY_SECONDS == 86400
    assert witness.MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE == 9
