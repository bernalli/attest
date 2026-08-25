"""Standalone activation-grade hybrid witness quorum (v0.2 §11.4).

Contract: the reusable activation-grade quorum requires MATCHING Ed25519
(C2SP type `0x04`) and ML-DSA-65 (type `0xff || "attest-cosignature-ml-dsa-65-v1"`)
legs for each counted pin, over the same `cosignature/v1` payload and the same
timestamp; both legs MUST verify (AND); it counts one vote per `control_group`;
the committee ceiling is enforced BEFORE any signature verification; and a full
`signed-note-v2` anchor over the complete signed note is required, with
`max(t_i) - min(t_i) <= 600` and `max(t_i) <= A <= T + 86400` for `T = min(t_i)`.

It is a STANDALONE primitive: §11.4 defines no grant consumer, so nothing here
touches a receipt, a result vocabulary, or a warning literal. Untrusted input
(the checkpoint text, its signature lines, the anchor evidence) never raises —
it returns `valid=False`. Trusted configuration (policy, anchor policy, origin,
conflict domain) raises, exactly as `log_keys` does elsewhere.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass
from typing import Any

import pytest

from attest import anchor, keys, pq, tlog, witness

_ORIGIN = "log.example"
# 2023-11-14T22:13:20Z. Every timestamp in this file is an offset from it, so a
# reader can tell a boundary case from an arbitrary one at a glance.
_BASE_T = 1700000000
_HEADER_HASH = "3a" * 32


@dataclass(frozen=True)
class _Witness:
    """One test witness identity: a name, a control group, and both key legs."""

    name: str
    operator: str
    group: str
    ed: Any
    mldsa: Any


# --- fixtures --------------------------------------------------------------


@pytest.fixture(scope="module")
def log_signing() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _make_witness(label: str, group: str | None = None) -> _Witness:
    operator = f"{label}.example"
    return _Witness(
        name=f"{operator}/w",
        operator=operator,
        group=group if group is not None else operator,
        ed=keys.generate(),
        mldsa=pq.generate(),
    )


@pytest.fixture(scope="module")
def w1() -> _Witness:
    return _make_witness("alpha")


@pytest.fixture(scope="module")
def w2() -> _Witness:
    return _make_witness("bravo")


@pytest.fixture(scope="module")
def w3() -> _Witness:
    return _make_witness("charlie")


@pytest.fixture(scope="module")
def w1_rotated(w1: _Witness) -> _Witness:
    """A second key for the SAME control group — a routine key rotation."""
    return _Witness(
        name=f"{w1.operator}/w-next",
        operator=w1.operator,
        group=w1.group,
        ed=keys.generate(),
        mldsa=pq.generate(),
    )


# --- policy construction ---------------------------------------------------


def _pin(w: _Witness, **overrides: Any) -> dict[str, Any]:
    pin: dict[str, Any] = {
        "operator_id": w.operator,
        "control_group": w.group,
        "name": w.name,
        "ed25519_pub_b64u": keys.b64u(w.ed.pub),
        "mldsa_65_pub_b64u": keys.b64u(w.mldsa.pub),
        "roles": ["sunset-activation"],
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": None,
        "affiliated_domains": [w.operator],
    }
    pin.update(overrides)
    return pin


def _policy_doc(pins: list[dict[str, Any]], *, n: int, m: int, **epoch: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "epoch_id": "bootstrap-1",
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": None,
        "log_origins": [_ORIGIN],
        "threshold": {"n": n, "m": m},
        "witnesses": pins,
    }
    fields.update(epoch)
    return {"schema": "attest-witness-policy-v1", "epochs": [fields]}


def _policy(pins: list[dict[str, Any]], *, n: int, m: int, **epoch: Any) -> witness.WitnessPolicy:
    return witness.parse_policy(_policy_doc(pins, n=n, m=m, **epoch))


# --- checkpoint and cosignature construction -------------------------------


def _base_checkpoint(log_signing: pq.HybridSigningKeys) -> str:
    return tlog.sign_checkpoint(_ORIGIN, 4, bytes(32), log_signing, _ORIGIN)


def _line(name: str, blob: bytes) -> str:
    return f"— {name} {base64.b64encode(blob).decode('ascii')}\n"


def _payload(note: bytes, timestamp: int) -> bytes:
    """Built by hand, not through `cosignature_message`, so a case can carry a
    timestamp the helper itself would refuse to sign."""
    return b"cosignature/v1\n" + f"time {timestamp}\n".encode() + note


def _ed_leg(
    w: _Witness,
    note: bytes,
    timestamp: int,
    *,
    declared: int | None = None,
    signed_note: bytes | None = None,
    signer: Any | None = None,
) -> bytes:
    key_id = witness.cosignature_key_id(w.name, w.ed.pub)
    message = _payload(note if signed_note is None else signed_note, timestamp)
    signature = keys.sign(message, w.ed if signer is None else signer)
    return key_id + struct.pack(">Q", timestamp if declared is None else declared) + signature


def _pq_leg(
    w: _Witness,
    note: bytes,
    timestamp: int,
    *,
    declared: int | None = None,
    signed_note: bytes | None = None,
    sig_type: bytes | None = None,
) -> bytes:
    key_id = tlog.key_hash(
        w.name,
        witness.PQ_COSIGNATURE_SIG_TYPE if sig_type is None else sig_type,
        w.mldsa.pub,
    )
    message = _payload(note if signed_note is None else signed_note, timestamp)
    signature = pq.sign(message, w.mldsa)
    return key_id + struct.pack(">Q", timestamp if declared is None else declared) + signature


def _pair(w: _Witness, note: bytes, timestamp: int, **kwargs: Any) -> list[str]:
    return [
        _line(w.name, _ed_leg(w, note, timestamp, **kwargs)),
        _line(w.name, _pq_leg(w, note, timestamp, **kwargs)),
    ]


# --- anchor construction ---------------------------------------------------


def _anchor(
    checkpoint_text: str,
    header_time: int,
    *,
    profile: str | None = "signed-note-v2",
) -> tuple[dict[str, Any], anchor.AnchorPolicy]:
    """A verifying OTS op-chain over this exact checkpoint, plus its trust store.

    The v2 seed is `SHA256(signed_note_bytes)` — the WHOLE note, cosignature
    lines included — which is why the anchor has to be built after the lines
    are appended, never before.
    """
    checkpoint = tlog.parse_checkpoint(checkpoint_text)
    seed_source = (
        checkpoint.signed_note_bytes if profile == "signed-note-v2" else checkpoint.note_bytes
    )
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(seed_source).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    root = acc.hex()
    evidence: dict[str, Any] = {
        "checkpoint": checkpoint_text,
        "proofs": [
            {
                "kind": "ots",
                "ops": [
                    ["append", sibling.hex()],
                    ["sha256"],
                    ["prepend", prefix.hex()],
                    ["sha256"],
                ],
                "header_merkle_root": root,
                "header_time": header_time,
                "header_hash": _HEADER_HASH,
            }
        ],
    }
    if profile is not None:
        evidence["anchor_profile"] = profile
    policy = anchor.AnchorPolicy(
        pinned_headers={
            _HEADER_HASH: anchor.PinnedHeader(
                header_hash=_HEADER_HASH, merkle_root=root, time=header_time
            )
        },
        crqc_horizon=None,
    )
    return evidence, policy


def _evaluate(
    checkpoint_text: str,
    policy: witness.WitnessPolicy,
    *,
    anchor_time: int,
    anchor_profile: str | None = "signed-note-v2",
    epoch_id: str = "bootstrap-1",
    expected_origin: str = _ORIGIN,
    conflict_domain: str = "issuer.example",
) -> witness.ActivationWitnessQuorumResult:
    evidence, anchor_policy = _anchor(checkpoint_text, anchor_time, profile=anchor_profile)
    return witness.evaluate_activation_witness_quorum(
        checkpoint_text,
        witness_policy=policy,
        epoch_id=epoch_id,
        expected_origin=expected_origin,
        anchor_evidence=evidence,
        anchor_policy=anchor_policy,
        conflict_domain=conflict_domain,
    )


def _one_of_one(
    log_signing: pq.HybridSigningKeys, w: _Witness, timestamp: int
) -> tuple[str, witness.WitnessPolicy]:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w, note, timestamp))
    return text, _policy([_pin(w)], n=1, m=1)


# --- crypto spies ----------------------------------------------------------


class _Spy:
    """Counts calls while still doing the real work — a mocked-out verifier
    would make the positive cases prove nothing."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.calls = 0

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        return self._real(*args, **kwargs)


@pytest.fixture
def crypto_spies(monkeypatch: pytest.MonkeyPatch) -> tuple[_Spy, _Spy]:
    ed_spy = _Spy(keys.verify_strict)
    pq_spy = _Spy(pq.verify_strict)
    monkeypatch.setattr(keys, "verify_strict", ed_spy)
    monkeypatch.setattr(pq, "verify_strict", pq_spy)
    return ed_spy, pq_spy


# --- the valid shapes ------------------------------------------------------


def test_bootstrap_one_of_one_is_valid(log_signing: pq.HybridSigningKeys, w1: _Witness) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    result = _evaluate(text, policy, anchor_time=_BASE_T)
    assert result.valid is True
    assert result.witness_time == _BASE_T
    assert result.counting_control_groups == (w1.group,)


def test_two_of_three_counts_two_distinct_control_groups(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness, w3: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T + 5))
    policy = _policy([_pin(w1), _pin(w2), _pin(w3)], n=3, m=2)
    result = _evaluate(text, policy, anchor_time=_BASE_T + 5)
    assert result.valid is True
    assert result.counting_control_groups == tuple(sorted((w1.group, w2.group)))


def test_witness_time_is_the_minimum_counting_timestamp(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness, w3: _Witness
) -> None:
    """`T = min(t_i)`, the conservative choice: using the maximum would let a
    late signer stretch the anchor-delay window every earlier one is judged by."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T + 300) + _pair(w2, note, _BASE_T))
    policy = _policy([_pin(w1), _pin(w2), _pin(w3)], n=3, m=2)
    result = _evaluate(text, policy, anchor_time=_BASE_T + 300)
    assert result.valid is True
    assert result.witness_time == _BASE_T


# --- the hybrid AND rule ---------------------------------------------------


def test_a_pin_with_only_its_ed25519_leg_does_not_count(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + _line(w1.name, _ed_leg(w1, note, _BASE_T))
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_pin_with_only_its_pq_leg_does_not_count(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + _line(w1.name, _pq_leg(w1, note, _BASE_T))
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_an_invalid_ed25519_leg_kills_the_whole_pair(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    broken = bytearray(_ed_leg(w1, note, _BASE_T))
    broken[-1] ^= 0xFF
    text = base + _line(w1.name, bytes(broken)) + _line(w1.name, _pq_leg(w1, note, _BASE_T))
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_an_invalid_pq_leg_kills_the_whole_pair(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    broken = bytearray(_pq_leg(w1, note, _BASE_T))
    broken[-1] ^= 0xFF
    text = base + _line(w1.name, _ed_leg(w1, note, _BASE_T)) + _line(w1.name, bytes(broken))
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_legs_carrying_different_timestamps_do_not_pair(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = (
        base
        + _line(w1.name, _ed_leg(w1, note, _BASE_T))
        + _line(w1.name, _pq_leg(w1, note, _BASE_T + 1))
    )
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 1).valid is False


def test_a_leg_transplanted_from_another_checkpoint_does_not_count(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """The payload commits to this checkpoint's note body, so a genuine
    signature made over a different one cannot be carried across."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    other_note = tlog.parse_checkpoint(
        tlog.sign_checkpoint(_ORIGIN, 9, bytes(32), log_signing, _ORIGIN)
    ).note_bytes
    text = (
        base
        + _line(w1.name, _ed_leg(w1, note, _BASE_T, signed_note=other_note))
        + _line(w1.name, _pq_leg(w1, note, _BASE_T))
    )
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_c2sp_type_06_line_is_not_a_pq_leg(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """`0x06` is the registry's ML-DSA-44 `subtree/v1` cosignature — a
    different algorithm over a different structure (§9.2)."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = (
        base
        + _line(w1.name, _ed_leg(w1, note, _BASE_T))
        + _line(w1.name, _pq_leg(w1, note, _BASE_T, sig_type=b"\x06"))
    )
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_the_checkpoint_signature_type_is_not_a_cosignature_leg(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """`0xff || "attest-ml-dsa-65"` authenticates the checkpoint itself; it is
    a distinct identifier from the cosignature type and must not substitute."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = (
        base
        + _line(w1.name, _ed_leg(w1, note, _BASE_T))
        + _line(w1.name, _pq_leg(w1, note, _BASE_T, sig_type=b"\xff" + b"attest-ml-dsa-65"))
    )
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_line_signed_by_a_stranger_does_not_count(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = (
        base
        + _line(w1.name, _ed_leg(w1, note, _BASE_T, signer=w2.ed))
        + _line(w1.name, _pq_leg(w1, note, _BASE_T))
    )
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_lines_naming_an_unpinned_identity_are_ignored(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w2, note, _BASE_T) + _pair(w1, note, _BASE_T))
    policy = _policy([_pin(w1)], n=1, m=1)
    result = _evaluate(text, policy, anchor_time=_BASE_T)
    assert result.valid is True
    assert result.counting_control_groups == (w1.group,)


# --- one vote per control group -------------------------------------------


def test_two_candidate_pairs_in_one_control_group_fail_before_crypto(
    log_signing: pq.HybridSigningKeys,
    w1: _Witness,
    w1_rotated: _Witness,
    w2: _Witness,
    crypto_spies: tuple[_Spy, _Spy],
) -> None:
    """A rotated key does not double a control group's weight. Counting keys
    instead of groups would make this a satisfied 2-of-2."""
    ed_spy, pq_spy = crypto_spies
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w1_rotated, note, _BASE_T))
    policy = _policy([_pin(w1), _pin(w1_rotated), _pin(w2)], n=2, m=2)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False
    assert (ed_spy.calls, pq_spy.calls) == (0, 0)


def test_a_rotated_key_still_carries_its_group_when_it_is_the_only_candidate(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w1_rotated: _Witness, w2: _Witness
) -> None:
    """The positive half of the rule above: the group votes once, through
    whichever of its keys actually cosigned."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1_rotated, note, _BASE_T) + _pair(w2, note, _BASE_T))
    policy = _policy([_pin(w1), _pin(w1_rotated), _pin(w2)], n=2, m=2)
    result = _evaluate(text, policy, anchor_time=_BASE_T)
    assert result.valid is True
    assert result.counting_control_groups == tuple(sorted((w1.group, w2.group)))


def test_an_ambiguous_group_fails_the_quorum_instead_of_dropping_out(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    """Ambiguity is a HARD failure, not a silently skipped vote.

    `w2` alone satisfies `m = 1`, so a reading that merely dropped the
    ambiguous group would return valid. §11.4 says ambiguous duplicate
    candidates fail — and this is the only shape that tells the two apart.
    """
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(
        _pair(w1, note, _BASE_T) + _pair(w1, note, _BASE_T + 1) + _pair(w2, note, _BASE_T)
    )
    policy = _policy([_pin(w1), _pin(w2)], n=2, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 1).valid is False


def test_a_duplicate_control_group_fails_the_quorum_instead_of_counting_once(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w1_rotated: _Witness, w2: _Witness
) -> None:
    """The same distinction for the one-vote-per-group rule: with `w2` also
    voting, collapsing the duplicated group to a single vote would reach
    `m = 2`. Refusing outright is what §11.4 requires."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(
        _pair(w1, note, _BASE_T) + _pair(w1_rotated, note, _BASE_T) + _pair(w2, note, _BASE_T)
    )
    policy = _policy([_pin(w1), _pin(w1_rotated), _pin(w2)], n=2, m=2)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_duplicated_line_for_one_pin_is_ambiguous(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w1, note, _BASE_T + 1))
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 1).valid is False


# --- committee form and the ceiling ---------------------------------------


def test_a_committee_of_ten_is_refused_before_any_crypto(
    log_signing: pq.HybridSigningKeys, w1: _Witness, crypto_spies: tuple[_Spy, _Spy]
) -> None:
    """`MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE` is a COST bound as much as a
    policy one: an oversized committee must cost nothing.

    It does NOT isolate the ceiling from the form check below — measured on
    the parity bench, removing either one alone changes no verdict, because
    `threshold.n > 9` is already refused at parse time. What this pins is the
    observable property: ten activation groups never reach crypto."""
    ed_spy, pq_spy = crypto_spies
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    extras = [
        _pin(
            _Witness(
                name=f"filler{i}.example/w",
                operator=f"filler{i}.example",
                group=f"filler{i}.example",
                ed=w1.ed,
                mldsa=w1.mldsa,
            )
        )
        for i in range(9)
    ]
    policy = _policy([_pin(w1), *extras], n=9, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False
    assert (ed_spy.calls, pq_spy.calls) == (0, 0)


def test_a_committee_of_exactly_nine_is_still_admissible(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """The positive boundary: without it, a ceiling that refused every
    committee would satisfy the case above."""
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    extras = [
        _pin(
            _Witness(
                name=f"filler{i}.example/w",
                operator=f"filler{i}.example",
                group=f"filler{i}.example",
                ed=w1.ed,
                mldsa=w1.mldsa,
            )
        )
        for i in range(8)
    ]
    policy = _policy([_pin(w1), *extras], n=9, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is True


def test_threshold_n_must_equal_the_activation_committee_size(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """`threshold.n` counts distinct activation-role control groups (§11.4).
    An epoch whose declared form does not match its own membership is not a
    quorum anybody can reason about."""
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1)], n=2, m=2)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_corroboration_only_pin_is_not_part_of_the_committee(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T))
    policy = _policy(
        [_pin(w1), _pin(w2, roles=["corroboration"], mldsa_65_pub_b64u=None)], n=1, m=1
    )
    result = _evaluate(text, policy, anchor_time=_BASE_T)
    assert result.valid is True
    assert result.counting_control_groups == (w1.group,)


def test_fewer_valid_votes_than_m_is_invalid(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T))
    policy = _policy([_pin(w1), _pin(w2)], n=2, m=2)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


# --- the conflict predicate ------------------------------------------------


def test_a_directly_affiliated_pin_is_excluded(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T))
    policy = _policy(
        [
            _pin(w1, affiliated_domains=sorted([w1.operator, "issuer.example"])),
            _pin(w2),
        ],
        n=2,
        m=2,
    )
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_transitively_affiliated_pin_is_excluded(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w1_rotated: _Witness, w2: _Witness
) -> None:
    """`w1_rotated` names the domain; `w1` does not, but shares its control
    group, so the whole group is out."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T))
    policy = _policy(
        [
            _pin(w1),
            _pin(w1_rotated, affiliated_domains=sorted([w1.operator, "issuer.example"])),
            _pin(w2),
        ],
        n=2,
        m=2,
    )
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_the_conflict_domain_is_a_parameter_not_a_constant(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    """Same policy, same checkpoint, different domain — a different eligible
    committee. A hardcoded domain passes the two tests above and fails this."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T))
    policy = _policy(
        [_pin(w1, affiliated_domains=sorted([w1.operator, "issuer.example"])), _pin(w2)],
        n=2,
        m=2,
    )
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False
    assert (
        _evaluate(text, policy, anchor_time=_BASE_T, conflict_domain="other.example").valid is True
    )


# --- temporal and lifecycle boundaries -------------------------------------


def test_skew_of_exactly_600_seconds_is_valid(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T + 600))
    policy = _policy([_pin(w1), _pin(w2)], n=2, m=2)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 600).valid is True


def test_skew_of_601_seconds_is_invalid(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T + 601))
    policy = _policy([_pin(w1), _pin(w2)], n=2, m=2)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 601).valid is False


def test_an_anchor_exactly_at_max_t_is_valid(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is True


def test_an_anchor_before_max_t_is_invalid(log_signing: pq.HybridSigningKeys, w1: _Witness) -> None:
    """An anchor that predates the observation cannot be evidence for it."""
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    assert _evaluate(text, policy, anchor_time=_BASE_T - 1).valid is False


def test_an_anchor_at_exactly_t_plus_86400_is_valid(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 86400).valid is True


def test_an_anchor_one_second_past_the_delay_bound_is_invalid(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 86401).valid is False


def test_the_delay_bound_is_measured_from_the_minimum_not_the_maximum(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    """With `T = min(t_i)` this anchor is one second too late; with `max(t_i)`
    it would sit comfortably inside the window."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T + 600))
    policy = _policy([_pin(w1), _pin(w2)], n=2, m=2)
    assert _evaluate(text, policy, anchor_time=_BASE_T + 86401).valid is False


def test_a_note_only_anchor_is_not_sufficient(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """`note-v1` commits to the unsigned header alone, so it proves nothing
    about the cosignature lines this primitive is counting."""
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    assert _evaluate(text, policy, anchor_time=_BASE_T, anchor_profile="note-v1").valid is False


def test_an_absent_anchor_profile_is_not_sufficient(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    assert _evaluate(text, policy, anchor_time=_BASE_T, anchor_profile=None).valid is False


def test_an_anchor_that_does_not_verify_is_not_sufficient(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    evidence["proofs"][0]["header_merkle_root"] = "00" * 32
    result = witness.evaluate_activation_witness_quorum(
        text,
        witness_policy=policy,
        epoch_id="bootstrap-1",
        expected_origin=_ORIGIN,
        anchor_evidence=evidence,
        anchor_policy=anchor_policy,
        conflict_domain="issuer.example",
    )
    assert result.valid is False


def test_an_epoch_that_expired_before_t_does_not_revive(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """Fresh evidence does not reopen a closed epoch."""
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1)], n=1, m=1, not_after="2021-01-01T00:00:00Z")
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_an_epoch_ending_exactly_at_t_still_covers_it(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1)], n=1, m=1, not_after="2023-11-14T22:13:20Z")
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is True


def test_a_pin_that_expired_before_t_does_not_count(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1, not_after="2021-01-01T00:00:00Z")], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_pin_whose_window_ends_exactly_at_t_still_counts(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1, not_after="2023-11-14T22:13:20Z")], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is True


def test_a_compromise_cutoff_exactly_at_t_retains_standing(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """`T <= compromised_after` keeps the pin — the cutoff is inclusive."""
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1, compromised_after="2023-11-14T22:13:20Z")], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is True


def test_a_compromise_cutoff_one_second_before_t_excludes_the_pin(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1, compromised_after="2023-11-14T22:13:19Z")], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_an_unknown_compromise_onset_contributes_no_standing(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """An explicit `null` means the onset is unknown: fail closed at every
    time, forever."""
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1, compromised_after=None)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_the_lifecycle_is_judged_at_the_quorum_time_not_per_leg(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    """`w2` observed after its own cutoff, but the quorum time is the earlier
    `T`, and §11.4 judges standing at `T`."""
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T + 300))
    policy = _policy(
        [_pin(w1), _pin(w2, compromised_after="2023-11-14T22:13:20Z")],
        n=2,
        m=2,
    )
    assert _evaluate(text, policy, anchor_time=_BASE_T + 300).valid is True


def test_an_excluded_vote_does_not_set_t_for_the_counting_set(
    log_signing: pq.HybridSigningKeys, w1: _Witness, w2: _Witness
) -> None:
    """The fixed point makes `T` belong to the votes that still count.

    `w1` is already out at its own timestamp. If that excluded vote were allowed
    to set T, `w2` would still have standing and a 1-of-2 would pass. Recomputing
    T over the surviving vote moves T past `w2`'s cutoff, so no vote counts.
    """
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T) + _pair(w2, note, _BASE_T + 400))
    policy = _policy(
        [
            _pin(w1, compromised_after="2023-11-14T22:13:19Z"),
            _pin(w2, compromised_after="2023-11-14T22:16:40Z"),
        ],
        n=2,
        m=1,
    )
    result = _evaluate(text, policy, anchor_time=_BASE_T + 400)
    assert result.valid is False
    assert result.witness_time is None


# --- scope and untrusted-input discipline ----------------------------------


def test_an_unresolvable_epoch_is_invalid_and_never_substituted(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    assert _evaluate(text, policy, anchor_time=_BASE_T, epoch_id="no-such-epoch").valid is False


def test_an_epoch_scoped_to_another_origin_corroborates_nothing(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1)], n=1, m=1, log_origins=["other.example"])
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_an_epoch_with_no_origins_corroborates_nothing(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    policy = _policy([_pin(w1)], n=1, m=1, log_origins=[])
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False


def test_a_checkpoint_for_another_origin_is_invalid(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    result = _evaluate(text, policy, anchor_time=_BASE_T, expected_origin="other.example")
    assert result.valid is False


def test_a_malformed_checkpoint_returns_invalid_rather_than_raising(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    result = witness.evaluate_activation_witness_quorum(
        "not a checkpoint",
        witness_policy=policy,
        epoch_id="bootstrap-1",
        expected_origin=_ORIGIN,
        anchor_evidence=evidence,
        anchor_policy=anchor_policy,
        conflict_domain="issuer.example",
    )
    assert result.valid is False
    assert result.witness_time is None
    assert result.counting_control_groups == ()


def test_malformed_anchor_evidence_returns_invalid_rather_than_raising(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    _, anchor_policy = _anchor(text, _BASE_T)
    result = witness.evaluate_activation_witness_quorum(
        text,
        witness_policy=policy,
        epoch_id="bootstrap-1",
        expected_origin=_ORIGIN,
        anchor_evidence={"nonsense": True},
        anchor_policy=anchor_policy,
        conflict_domain="issuer.example",
    )
    assert result.valid is False


def test_a_non_string_epoch_id_is_invalid(log_signing: pq.HybridSigningKeys, w1: _Witness) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    result = witness.evaluate_activation_witness_quorum(
        text,
        witness_policy=policy,
        epoch_id=None,
        expected_origin=_ORIGIN,
        anchor_evidence=evidence,
        anchor_policy=anchor_policy,
        conflict_domain="issuer.example",
    )
    assert result.valid is False


# --- trusted-configuration errors ------------------------------------------


def test_a_non_policy_argument_raises(log_signing: pq.HybridSigningKeys, w1: _Witness) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    with pytest.raises(witness.WitnessError):
        witness.evaluate_activation_witness_quorum(
            text,
            witness_policy={"schema": witness.SCHEMA_ID, "epochs": []},  # type: ignore[arg-type]
            epoch_id="bootstrap-1",
            expected_origin=_ORIGIN,
            anchor_evidence=evidence,
            anchor_policy=anchor_policy,
            conflict_domain="issuer.example",
        )


def test_a_raw_policy_document_carrying_an_epoch_also_raises(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    """The mistake this guards against is handing over the JSON document
    instead of the parsed policy — which would otherwise resolve no epoch and
    look like an ordinary negative result rather than the caller bug it is."""
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    with pytest.raises(witness.WitnessError):
        witness.evaluate_activation_witness_quorum(
            text,
            witness_policy=_policy_doc([_pin(w1)], n=1, m=1),  # type: ignore[arg-type]
            epoch_id="bootstrap-1",
            expected_origin=_ORIGIN,
            anchor_evidence=evidence,
            anchor_policy=anchor_policy,
            conflict_domain="issuer.example",
        )


def test_a_hostile_empty_threshold_policy_shape_raises(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, _ = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    hostile = {
        "epochs": [
            {
                "epochId": "bootstrap-1",
                "notBefore": 0,
                "threshold": {},
                "witnesses": [],
            }
        ]
    }
    with pytest.raises(witness.WitnessError):
        witness.evaluate_activation_witness_quorum(
            text,
            witness_policy=hostile,  # type: ignore[arg-type]
            epoch_id="bootstrap-1",
            expected_origin=_ORIGIN,
            anchor_evidence=evidence,
            anchor_policy=anchor_policy,
            conflict_domain="issuer.example",
        )


def test_a_malformed_conflict_domain_raises(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    with pytest.raises(witness.WitnessError):
        witness.evaluate_activation_witness_quorum(
            text,
            witness_policy=policy,
            epoch_id="bootstrap-1",
            expected_origin=_ORIGIN,
            anchor_evidence=evidence,
            anchor_policy=anchor_policy,
            conflict_domain="Not A Domain",
        )


def test_a_malformed_expected_origin_raises(
    log_signing: pq.HybridSigningKeys, w1: _Witness
) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    evidence, anchor_policy = _anchor(text, _BASE_T)
    with pytest.raises(witness.WitnessError):
        witness.evaluate_activation_witness_quorum(
            text,
            witness_policy=policy,
            epoch_id="bootstrap-1",
            expected_origin="bad\norigin",
            anchor_evidence=evidence,
            anchor_policy=anchor_policy,
            conflict_domain="issuer.example",
        )


def test_a_malformed_anchor_policy_raises(log_signing: pq.HybridSigningKeys, w1: _Witness) -> None:
    text, policy = _one_of_one(log_signing, w1, _BASE_T)
    evidence, _ = _anchor(text, _BASE_T)
    with pytest.raises(witness.WitnessError):
        witness.evaluate_activation_witness_quorum(
            text,
            witness_policy=policy,
            epoch_id="bootstrap-1",
            expected_origin=_ORIGIN,
            anchor_evidence=evidence,
            anchor_policy="not a policy",  # type: ignore[arg-type]
            conflict_domain="issuer.example",
        )


# --- cost contract ---------------------------------------------------------


def test_a_valid_nine_group_committee_verifies_at_most_nine_pairs(
    log_signing: pq.HybridSigningKeys, w1: _Witness, crypto_spies: tuple[_Spy, _Spy]
) -> None:
    """Extra unknown signed-note lines must not increase witness crypto work."""
    ed_spy, pq_spy = crypto_spies
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    text = base + "".join(_pair(w1, note, _BASE_T)) + _line("stranger/x", b"\x00" * 76)
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is True
    assert ed_spy.calls <= 1
    assert pq_spy.calls <= 1


def test_the_pq_leg_is_never_verified_when_the_ed25519_leg_fails(
    log_signing: pq.HybridSigningKeys, w1: _Witness, crypto_spies: tuple[_Spy, _Spy]
) -> None:
    """AND semantics, short-circuited on the cheap leg first: an attacker
    cannot force ML-DSA work with a garbage Ed25519 signature."""
    ed_spy, pq_spy = crypto_spies
    base = _base_checkpoint(log_signing)
    note = tlog.parse_checkpoint(base).note_bytes
    broken = bytearray(_ed_leg(w1, note, _BASE_T))
    broken[-1] ^= 0xFF
    text = base + _line(w1.name, bytes(broken)) + _line(w1.name, _pq_leg(w1, note, _BASE_T))
    policy = _policy([_pin(w1)], n=1, m=1)
    assert _evaluate(text, policy, anchor_time=_BASE_T).valid is False
    assert ed_spy.calls == 1
    assert pq_spy.calls == 0
