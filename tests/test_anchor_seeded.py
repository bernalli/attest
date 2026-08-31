"""Seeded anchor verification: `verify_seeded_anchor` over an arbitrary seed.

Where `verify_anchor` asks "was THIS checkpoint timestamped?",
`verify_seeded_anchor` asks "has real time reached date T?": the caller holds
an OpenTimestamps attestation whose op-chain starts from the canonical bytes
of some public document and climbs to a Bitcoin header the verifier has
pinned. There is no checkpoint anywhere in that question, and no anchor
profile either — the profile dimension only means something when the seed is
one of a checkpoint's two byte-strings.

The positive fixture builds the same synthetic op-chain the checkpoint-bound
suite builds — start from `SHA256(seed)`, append a sibling, hash, prepend a
prefix, hash again — then pins the resulting root as a `PinnedHeader`. Every
other test is a controlled mutation of that one working fixture, so a single
assertion isolates exactly one failure mode. Mirrored one-for-one by
`verifiers/ts/test/anchor-seeded.test.ts`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

import pytest

from attest import anchor, tlog

# Stand-in for "the canonical bytes of a public document": arbitrary bytes
# with no checkpoint structure at all — the whole point of the seeded entry
# point is that the seed need not be a note.
SEED = b"public document, canonical bytes\n"
HEADER_TIME = 1700000000
HEADER_HASH = "3a" * 32  # deliberately contains a hex letter, not just digits


def _working_chain(seed: bytes = SEED) -> tuple[list[list[str]], str]:
    """Build the op-chain forward and return `(ops, header_merkle_root)`.

    Sequence: append sibling, sha256, prepend prefix, sha256. Computed
    independently of `anchor.py` (plain `hashlib` calls) so the test pins the
    real algorithm rather than round-tripping the module's own logic. The
    chain starts from `SHA256(seed)`, exactly as `verify_anchor`'s note-v1
    path starts from `SHA256(checkpoint.note_bytes)`.
    """
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(seed).digest()
    acc = acc + sibling
    acc = hashlib.sha256(acc).digest()
    acc = prefix + acc
    acc = hashlib.sha256(acc).digest()
    ops: list[list[str]] = [
        ["append", sibling.hex()],
        ["sha256"],
        ["prepend", prefix.hex()],
        ["sha256"],
    ]
    return ops, acc.hex()


def _ots_proof(
    ops: object | None = None,
    header_merkle_root: str | None = None,
    header_time: object = HEADER_TIME,
    header_hash: object = HEADER_HASH,
) -> dict[str, object]:
    working_ops, working_root = _working_chain()
    if ops is None:
        ops = working_ops
    if header_merkle_root is None:
        header_merkle_root = working_root
    return {
        "kind": "ots",
        "ops": ops,
        "header_merkle_root": header_merkle_root,
        "header_time": header_time,
        "header_hash": header_hash,
    }


def _evidence(proofs: Sequence[object]) -> dict[str, object]:
    return {"proofs": list(proofs)}


def _policy(
    header_hash: str = HEADER_HASH,
    merkle_root: str | None = None,
    time: int = HEADER_TIME,
    crqc_horizon: int | None = None,
) -> anchor.AnchorPolicy:
    if merkle_root is None:
        _, merkle_root = _working_chain()
    pinned = anchor.PinnedHeader(header_hash=header_hash, merkle_root=merkle_root, time=time)
    return anchor.AnchorPolicy(pinned_headers={header_hash: pinned}, crqc_horizon=crqc_horizon)


# --------------------------------------------------------------------------
# Positive round trip.
# --------------------------------------------------------------------------


def test_seeded_ots_proof_verifies_and_anchors_before_pinned_header_time() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.anchored_after == HEADER_TIME
    assert verdict.pq_surviving is True
    assert verdict.warnings == []
    # There is no profile dimension on this path: `note_only` is not a
    # classification the seeded entry point can make, so it stays at its
    # dataclass default rather than claiming a profile it never determined.
    assert verdict.note_only is False


def test_seeded_anchor_agrees_with_verify_anchor_on_the_same_note_v1_evidence() -> None:
    """Pins the seed derivation: `SHA256(seed)` is the accumulator start.

    Feeding `checkpoint.note_bytes` as the seed must replay the identical
    chain `verify_anchor` replays for legacy note-v1 evidence — the two
    entry points are twins over the same op-chain, and a divergence here
    would mean one of them derives its accumulator differently.
    """
    note_bytes = b"log.example/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    checkpoint_text = note_bytes.decode() + "\n" + "— test-key AA==\n"
    checkpoint = tlog.Checkpoint(
        origin="log.example/1",
        tree_size=1,
        root=b"\x00" * 32,
        note_bytes=note_bytes,
        signed_note_bytes=checkpoint_text.encode(),
    )
    ops, root = _working_chain(note_bytes)
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    policy = _policy(merkle_root=root)

    checkpoint_bound = anchor.verify_anchor(
        {"checkpoint": checkpoint_text, "proofs": [proof]}, checkpoint, policy
    )
    seeded = anchor.verify_seeded_anchor(_evidence([proof]), note_bytes, policy)

    assert checkpoint_bound.anchored is True
    assert seeded.anchored is True
    assert seeded.anchored_before == checkpoint_bound.anchored_before
    assert seeded.anchored_after == checkpoint_bound.anchored_after
    assert seeded.pq_surviving == checkpoint_bound.pq_surviving
    assert seeded.warnings == checkpoint_bound.warnings


# --------------------------------------------------------------------------
# No checkpoint, no anchor_profile: neither is read, neither is required.
# --------------------------------------------------------------------------


def test_seeded_anchor_ignores_an_incoherent_evidence_checkpoint() -> None:
    evidence = _evidence([_ots_proof()])
    evidence["checkpoint"] = "not a signed checkpoint at all"
    verdict = anchor.verify_seeded_anchor(evidence, SEED, _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.warnings == []


def test_seeded_anchor_ignores_a_well_formed_but_unrelated_evidence_checkpoint() -> None:
    other_note = b"other.example/1\n7\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
    evidence = _evidence([_ots_proof()])
    evidence["checkpoint"] = other_note.decode() + "\n" + "— test-key AA==\n"
    verdict = anchor.verify_seeded_anchor(evidence, SEED, _policy())
    assert verdict.anchored is True
    assert verdict.warnings == []


@pytest.mark.parametrize(
    "profile",
    ["note-v1", "signed-note-v2", "bogus-profile", None, 42],
)
def test_seeded_anchor_ignores_evidence_anchor_profile(profile: object) -> None:
    # `bogus-profile`/`42` are values `verify_anchor` rejects outright; on the
    # seeded path the field carries no meaning and is never read.
    evidence = _evidence([_ots_proof()])
    evidence["anchor_profile"] = profile
    verdict = anchor.verify_seeded_anchor(evidence, SEED, _policy())
    assert verdict.anchored is True
    assert verdict.note_only is False
    assert verdict.warnings == []


# --------------------------------------------------------------------------
# Negative: the chain must actually climb from THIS seed to a PINNED header.
# --------------------------------------------------------------------------


def test_seeded_anchor_rejects_a_seed_that_differs_by_one_byte() -> None:
    wrong_seed = bytearray(SEED)
    wrong_seed[0] ^= 0x01
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), bytes(wrong_seed), _policy())
    assert verdict.anchored is False
    assert verdict.anchored_before is None
    assert verdict.pq_surviving is False
    # The plain mismatch message: no profile wording can appear on a path
    # that has no profile dimension.
    assert verdict.warnings == ["proof[0]: ots op-chain result does not match header_merkle_root"]


def test_seeded_anchor_rejects_a_header_absent_from_the_pinned_store() -> None:
    # The op-chain itself replays perfectly to the proof's own claimed root:
    # the ONLY thing missing is the verifier's pin. A seeded anchor must
    # never be "verified" against a header the verifier has not pinned.
    empty_policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, empty_policy)
    assert verdict.anchored is False
    assert verdict.pq_surviving is False
    assert verdict.anchored_before is None
    assert verdict.warnings == ["proof[0]: header_hash is not in policy.pinned_headers"]


def test_seeded_anchor_rejects_a_header_pinned_under_a_different_hash() -> None:
    _, root = _working_chain()
    other_hash = "77" * 32
    policy = anchor.AnchorPolicy(
        pinned_headers={
            other_hash: anchor.PinnedHeader(
                header_hash=other_hash, merkle_root=root, time=HEADER_TIME
            )
        },
        crqc_horizon=None,
    )
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, policy)
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: header_hash is not in policy.pinned_headers"]


def test_seeded_anchor_rejects_a_pinned_header_whose_merkle_root_differs() -> None:
    verdict = anchor.verify_seeded_anchor(
        _evidence([_ots_proof()]), SEED, _policy(merkle_root="ff" * 32)
    )
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: pinned header merkle_root does not match proof"]


def test_seeded_anchor_rejects_a_pinned_header_whose_time_differs_from_the_proof() -> None:
    verdict = anchor.verify_seeded_anchor(
        _evidence([_ots_proof()]), SEED, _policy(time=HEADER_TIME + 1)
    )
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: pinned header time does not match proof"]


# --------------------------------------------------------------------------
# Malformed evidence never raises (untrusted input).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_evidence", [None, [], "not-a-dict", 42, True])
def test_seeded_anchor_never_raises_on_non_dict_evidence(bad_evidence: object) -> None:
    verdict = anchor.verify_seeded_anchor(bad_evidence, SEED, _policy())  # type: ignore[arg-type]
    assert verdict.anchored is False
    assert verdict.anchored_before is None
    assert verdict.anchored_after is None  # both reductions absent, not just one
    assert verdict.pq_surviving is False
    assert len(verdict.warnings) == 1
    assert "evidence must be an object" in verdict.warnings[0]


def test_seeded_anchor_never_raises_when_proofs_key_missing() -> None:
    verdict = anchor.verify_seeded_anchor({}, SEED, _policy())
    assert verdict.anchored is False
    assert "evidence.proofs must be a list" in verdict.warnings[0]


@pytest.mark.parametrize("bad_proofs", ["not-a-list", 1, None, {}])
def test_seeded_anchor_never_raises_when_proofs_not_a_list(bad_proofs: object) -> None:
    verdict = anchor.verify_seeded_anchor({"proofs": bad_proofs}, SEED, _policy())
    assert verdict.anchored is False
    assert "evidence.proofs must be a list" in verdict.warnings[0]


def test_seeded_anchor_empty_proofs_list_is_simply_not_anchored() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.anchored_before is None
    assert verdict.warnings == []


@pytest.mark.parametrize("bad_proof", [None, "string", 42, [], True])
def test_seeded_anchor_ignores_non_dict_proof_entry_with_warning(bad_proof: object) -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([bad_proof]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [f"proof[0]: must be an object, got {type(bad_proof).__name__}"]


def test_seeded_anchor_ots_proof_missing_ops_field() -> None:
    proof = _ots_proof()
    del proof["ops"]
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'ops' must be a list"]


@pytest.mark.parametrize("bad_ops", ["not-a-list", 1, None, {}])
def test_seeded_anchor_ots_proof_ops_not_a_list(bad_ops: object) -> None:
    proof = _ots_proof()
    proof["ops"] = bad_ops  # set directly: `ops=None` is the helper's "use default" sentinel
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'ops' must be a list"]


def test_seeded_anchor_ots_proof_empty_op_chain() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof(ops=[])]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof has empty op-chain"]


def test_seeded_anchor_ots_proof_rejects_non_hex_operand() -> None:
    ops, root = _working_chain()
    bad_ops = [["append", "zz" * 32], *ops[1:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_seeded_anchor_ots_proof_rejects_unknown_op() -> None:
    ops, root = _working_chain()
    bad_ops = [["ripemd160"], *ops]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: unknown ots op 'ripemd160'"]


def test_seeded_anchor_rejects_non_hex64_header_merkle_root() -> None:
    proof = _ots_proof(header_merkle_root="aa" * 31)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars"
    ]


def test_seeded_anchor_unknown_proof_kind_is_ignored_not_fatal() -> None:
    evidence = _evidence([{"kind": "future-kind", "stuff": 1}, _ots_proof()])
    verdict = anchor.verify_seeded_anchor(evidence, SEED, _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert "proof[0]: unknown proof kind 'future-kind', ignored" in verdict.warnings


def test_seeded_anchor_rfc3161_proof_anchors_without_surviving_the_horizon() -> None:
    evidence = _evidence([{"kind": "rfc3161", "token_b64": "AAAA"}])
    verdict = anchor.verify_seeded_anchor(evidence, SEED, _policy())
    assert verdict.anchored is True
    assert verdict.pq_surviving is False
    assert verdict.anchored_before is None
    assert verdict.warnings == [
        "rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight"
    ]


# --------------------------------------------------------------------------
# The two reductions: `anchored_before` is the MINIMUM over verified proofs
# (as on the checkpoint-bound entry point), `anchored_after` is the MAXIMUM.
# They answer opposite questions; see the function's docstring.
# --------------------------------------------------------------------------


def test_seeded_anchored_before_is_min_over_multiple_verified_pq_proofs() -> None:
    ops, root = _working_chain()
    earlier_hash = "55" * 32
    later_hash = "66" * 32
    earlier_time = HEADER_TIME - 100
    later_time = HEADER_TIME + 100
    evidence = _evidence(
        [
            _ots_proof(
                ops=ops, header_merkle_root=root, header_hash=later_hash, header_time=later_time
            ),
            _ots_proof(
                ops=ops, header_merkle_root=root, header_hash=earlier_hash, header_time=earlier_time
            ),
        ]
    )
    policy = anchor.AnchorPolicy(
        pinned_headers={
            later_hash: anchor.PinnedHeader(
                header_hash=later_hash, merkle_root=root, time=later_time
            ),
            earlier_hash: anchor.PinnedHeader(
                header_hash=earlier_hash, merkle_root=root, time=earlier_time
            ),
        },
        crqc_horizon=None,
    )
    verdict = anchor.verify_seeded_anchor(evidence, SEED, policy)
    assert verdict.anchored_before == earlier_time
    assert verdict.pq_surviving is True
    # The same evidence, read the other way round: the most recent verified
    # header. The minimum alone would answer "has time reached T?" with a
    # false negative here — the older proof would veto the newer one.
    assert verdict.anchored_after == later_time


def test_seeded_anchored_before_and_after_coincide_on_a_single_proof() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, _policy())
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.anchored_after == HEADER_TIME


def test_seeded_reductions_ignore_proofs_that_did_not_verify() -> None:
    # One verified proof, flanked by two proofs whose headers the verifier
    # has NOT pinned: one claiming an earlier time, one a later time. Neither
    # may enter either reduction — an unpinned header cannot move the floor
    # down nor the ceiling up.
    ops, root = _working_chain()
    unpinned_early = _ots_proof(
        ops=ops, header_merkle_root=root, header_hash="88" * 32, header_time=HEADER_TIME - 1000
    )
    unpinned_late = _ots_proof(
        ops=ops, header_merkle_root=root, header_hash="99" * 32, header_time=HEADER_TIME + 1000
    )
    evidence = _evidence([unpinned_early, _ots_proof(), unpinned_late])
    verdict = anchor.verify_seeded_anchor(evidence, SEED, _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.anchored_after == HEADER_TIME
    assert verdict.warnings == [
        "proof[0]: header_hash is not in policy.pinned_headers",
        "proof[2]: header_hash is not in policy.pinned_headers",
    ]


def test_seeded_reductions_are_both_none_without_a_verified_pq_proof() -> None:
    verdict = anchor.verify_seeded_anchor(
        _evidence([{"kind": "rfc3161", "token_b64": "AAAA"}]), SEED, _policy()
    )
    assert verdict.anchored is True
    assert verdict.anchored_before is None
    assert verdict.anchored_after is None


# --------------------------------------------------------------------------
# `anchored_after` is additive: no existing consumer of `AnchorVerdict` can
# tell that it appeared.
# --------------------------------------------------------------------------


def test_anchor_verdict_still_constructs_without_the_new_field() -> None:
    # Every pre-existing caller builds the verdict by keyword and never
    # mentions `anchored_after`; the default keeps those call sites valid.
    verdict = anchor.AnchorVerdict(
        anchored=False, anchored_before=None, pq_surviving=False, warnings=[]
    )
    assert verdict.anchored_after is None


def test_verify_anchor_populates_anchored_after_without_moving_any_other_field() -> None:
    """The checkpoint-bound entry point gains the field and nothing else.

    Both entry points share one proof-walking loop, so `verify_anchor` gets
    the maximum for free. Every field its existing consumers read is pinned
    here to the exact value it had before the field existed.
    """
    note_bytes = b"log.example/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    checkpoint_text = note_bytes.decode() + "\n" + "— test-key AA==\n"
    checkpoint = tlog.Checkpoint(
        origin="log.example/1",
        tree_size=1,
        root=b"\x00" * 32,
        note_bytes=note_bytes,
        signed_note_bytes=checkpoint_text.encode(),
    )
    ops, root = _working_chain(note_bytes)
    earlier_hash, later_hash = "55" * 32, "66" * 32
    earlier_time, later_time = HEADER_TIME - 100, HEADER_TIME + 100
    proofs = [
        _ots_proof(
            ops=ops, header_merkle_root=root, header_hash=later_hash, header_time=later_time
        ),
        _ots_proof(
            ops=ops, header_merkle_root=root, header_hash=earlier_hash, header_time=earlier_time
        ),
    ]
    policy = anchor.AnchorPolicy(
        pinned_headers={
            later_hash: anchor.PinnedHeader(
                header_hash=later_hash, merkle_root=root, time=later_time
            ),
            earlier_hash: anchor.PinnedHeader(
                header_hash=earlier_hash, merkle_root=root, time=earlier_time
            ),
        },
        crqc_horizon=None,
    )
    verdict = anchor.verify_anchor(
        {"checkpoint": checkpoint_text, "proofs": proofs}, checkpoint, policy
    )
    assert verdict.anchored is True
    assert verdict.anchored_before == earlier_time  # unchanged: still the minimum
    assert verdict.pq_surviving is True
    assert verdict.warnings == []
    assert verdict.note_only is True
    assert verdict.anchored_after == later_time  # the only new observable


def test_anchored_after_is_invisible_to_passes_horizon() -> None:
    # `passes_horizon` gates on `anchored_before`; two verdicts that differ
    # ONLY in the new field must gate identically, at every horizon.
    common = {
        "anchored": True,
        "anchored_before": HEADER_TIME,
        "pq_surviving": True,
        "warnings": [],
    }
    without = anchor.AnchorVerdict(**common)  # type: ignore[arg-type]
    with_field = anchor.AnchorVerdict(**common, anchored_after=HEADER_TIME + 10_000)  # type: ignore[arg-type]
    for horizon in (None, HEADER_TIME - 1, HEADER_TIME, HEADER_TIME + 1, HEADER_TIME + 20_000):
        policy = _policy(crqc_horizon=horizon)
        assert anchor.passes_horizon(without, policy) == anchor.passes_horizon(with_field, policy)


# --------------------------------------------------------------------------
# Ceilings: same constants as the checkpoint-bound path, applied BEFORE any
# cryptographic work.
# --------------------------------------------------------------------------


def test_seeded_anchor_caps_proofs_list_length() -> None:
    # Every entry is a proof that WOULD verify: if the cap were applied after
    # the per-proof work, the verdict would be anchored and carry per-proof
    # warnings. One warning and `anchored is False` is the observable proof
    # that nothing was replayed at all.
    oversized = [_ots_proof()] * (anchor._MAX_PROOFS_PER_EVIDENCE + 1)
    verdict = anchor.verify_seeded_anchor(_evidence(oversized), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"evidence.proofs exceeds max length {anchor._MAX_PROOFS_PER_EVIDENCE}"
    ]


def test_seeded_anchor_accepts_a_proofs_list_at_exactly_the_cap() -> None:
    at_cap = [_ots_proof()] * anchor._MAX_PROOFS_PER_EVIDENCE
    verdict = anchor.verify_seeded_anchor(_evidence(at_cap), SEED, _policy())
    assert verdict.anchored is True
    assert verdict.warnings == []


def test_seeded_anchor_caps_ops_list_length() -> None:
    oversized_ops = [["sha256"]] * (anchor._MAX_OPS_PER_PROOF + 1)
    proof = _ots_proof(ops=oversized_ops)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"proof[0]: ots proof has more than {anchor._MAX_OPS_PER_PROOF} ops"
    ]


def test_seeded_anchor_accepts_an_ops_list_at_exactly_the_cap() -> None:
    acc = hashlib.sha256(SEED).digest()
    for _ in range(anchor._MAX_OPS_PER_PROOF):
        acc = hashlib.sha256(acc).digest()
    root = acc.hex()
    ops = [["sha256"]] * anchor._MAX_OPS_PER_PROOF
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy(merkle_root=root))
    assert verdict.anchored is True


def test_seeded_anchor_caps_op_operand_hex_length() -> None:
    ops, root = _working_chain()
    too_long = "ab" * (anchor._MAX_OP_HEX_LEN // 2 + 1)
    bad_ops = [["append", too_long], *ops[1:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_seeded_anchor_accepts_an_op_operand_at_exactly_the_cap() -> None:
    operand_hex = "ab" * (anchor._MAX_OP_HEX_LEN // 2)
    operand = bytes.fromhex(operand_hex)
    acc = hashlib.sha256(SEED).digest()
    acc = hashlib.sha256(acc + operand).digest()
    root = acc.hex()
    proof = _ots_proof(ops=[["append", operand_hex], ["sha256"]], header_merkle_root=root)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy(merkle_root=root))
    assert verdict.anchored is True


class _HashBudget:
    """Stand-in for `hashlib` allowing exactly `limit` digests, then failing.

    Lets a ceiling test assert ORDER, not just outcome: a cap enforced after
    the work it is supposed to bound would blow the budget and raise instead
    of returning a verdict. The one digest a seeded call cannot avoid is the
    seed's own — tests that need the op loop reached give a budget of 1.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.calls = 0

    def sha256(self, data: bytes = b"") -> Any:
        self.calls += 1
        if self.calls > self.limit:
            raise AssertionError(f"digest #{self.calls} ran past the {self.limit}-digest budget")
        return hashlib.sha256(data)


def test_seeded_anchor_enforces_proofs_ceiling_before_hashing_the_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    budget = _HashBudget(0)
    monkeypatch.setattr(anchor, "hashlib", budget)
    oversized = [_ots_proof()] * (anchor._MAX_PROOFS_PER_EVIDENCE + 1)
    verdict = anchor.verify_seeded_anchor(_evidence(oversized), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"evidence.proofs exceeds max length {anchor._MAX_PROOFS_PER_EVIDENCE}"
    ]
    assert budget.calls == 0


def test_seeded_anchor_enforces_ops_ceiling_before_replaying_any_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = _ots_proof(ops=[["sha256"]] * (anchor._MAX_OPS_PER_PROOF + 1))
    budget = _HashBudget(1)  # the seed digest, and not one op beyond it
    monkeypatch.setattr(anchor, "hashlib", budget)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"proof[0]: ots proof has more than {anchor._MAX_OPS_PER_PROOF} ops"
    ]
    assert budget.calls == 1


def test_seeded_anchor_enforces_operand_ceiling_before_hashing_the_operand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The op-chain shape is validated as it is walked (shared with the
    # checkpoint-bound path): the guarantee the cap buys is that an operand
    # is never concatenated or hashed before its own length is checked.
    _, root = _working_chain()
    too_long = "ab" * (anchor._MAX_OP_HEX_LEN // 2 + 1)
    proof = _ots_proof(ops=[["append", too_long], ["sha256"]], header_merkle_root=root)
    budget = _HashBudget(1)  # the seed digest only
    monkeypatch.setattr(anchor, "hashlib", budget)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]
    assert budget.calls == 1


# --------------------------------------------------------------------------
# Horizon gating: the seeded verdict feeds `passes_horizon` unchanged.
# --------------------------------------------------------------------------


def test_passes_horizon_false_when_horizon_before_seeded_anchor_time() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, _policy())
    assert anchor.passes_horizon(verdict, _policy(crqc_horizon=HEADER_TIME - 1)) is False


def test_passes_horizon_true_when_horizon_after_seeded_anchor_time() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, _policy())
    assert anchor.passes_horizon(verdict, _policy(crqc_horizon=HEADER_TIME + 1)) is True


def test_passes_horizon_true_for_seeded_verdict_when_horizon_none() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, _policy())
    assert anchor.passes_horizon(verdict, _policy(crqc_horizon=None)) is True


def test_passes_horizon_rejects_a_seeded_anchor_exactly_at_the_horizon() -> None:
    verdict = anchor.verify_seeded_anchor(_evidence([_ots_proof()]), SEED, _policy())
    assert anchor.passes_horizon(verdict, _policy(crqc_horizon=HEADER_TIME)) is False


def test_passes_horizon_false_for_seeded_rfc3161_only_evidence() -> None:
    evidence = _evidence([{"kind": "rfc3161", "token_b64": "AAAA"}])
    verdict = anchor.verify_seeded_anchor(evidence, SEED, _policy())
    assert anchor.passes_horizon(verdict, _policy(crqc_horizon=HEADER_TIME + 1)) is False


# --------------------------------------------------------------------------
# Caller-bug boundary: `seed` and `policy` are trusted arguments and raise.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_seed", ["a string", None, 42, [1, 2, 3], bytearray(b"abc"), memoryview(b"abc"), True]
)
def test_seeded_anchor_raises_anchor_error_on_non_bytes_seed(bad_seed: object) -> None:
    with pytest.raises(anchor.AnchorError):
        anchor.verify_seeded_anchor(_evidence([_ots_proof()]), bad_seed, _policy())  # type: ignore[arg-type]


def test_seeded_anchor_raises_anchor_error_on_empty_seed() -> None:
    with pytest.raises(anchor.AnchorError):
        anchor.verify_seeded_anchor(_evidence([_ots_proof()]), b"", _policy())


def test_seeded_anchor_raises_anchor_error_on_non_anchor_policy() -> None:
    with pytest.raises(anchor.AnchorError):
        anchor.verify_seeded_anchor(_evidence([]), SEED, "not-a-policy")  # type: ignore[arg-type]


def test_seeded_anchor_raises_anchor_error_on_malformed_policy_contents() -> None:
    policy = anchor.AnchorPolicy(
        pinned_headers={HEADER_HASH: anchor.PinnedHeader(HEADER_HASH, "AA" * 32, HEADER_TIME)},
        crqc_horizon=None,
    )
    with pytest.raises(anchor.AnchorError):
        anchor.verify_seeded_anchor(_evidence([]), SEED, policy)


def test_seeded_anchor_caller_bug_takes_precedence_over_malformed_evidence() -> None:
    # A bad seed raises even when the evidence is itself garbage: the trusted
    # argument boundary is checked first.
    with pytest.raises(anchor.AnchorError):
        anchor.verify_seeded_anchor("not-a-dict", "not-bytes", _policy())  # type: ignore[arg-type]


def test_seeded_anchor_caps_total_operand_length() -> None:
    """The total-operand cap reaches the seeded entry point too.

    `verify_seeded_anchor` and `verify_anchor` share `replay_ots_op_chain`, so
    this is the same guard seen from the other door — pinned here because the
    repo's convention is that both entry points carry their own coverage, and
    a cap that only one door enforces is a cap someone will route around.
    """
    chunk_hex = anchor._MAX_OP_HEX_LEN
    ops: list[list[str]] = []
    for _ in range(anchor._MAX_TOTAL_OP_HEX_LEN // chunk_hex):
        ops.append(["append", "ab" * (chunk_hex // 2)])
        ops.append(["sha256"])
    ops.append(["append", "ab"])
    proof = _ots_proof(ops=ops)
    verdict = anchor.verify_seeded_anchor(_evidence([proof]), SEED, _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"proof[0]: ots proof operands exceed {anchor._MAX_TOTAL_OP_HEX_LEN} total hex chars"
    ]
