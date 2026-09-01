"""OTS op-chain anchor verification, `AnchorPolicy`, CRQC horizon gating.

The positive fixture builds a synthetic OTS op-chain forward by hand: start
from `SHA256(note_bytes)`, append a sibling, hash, prepend a prefix, hash
again — the exact op sequence the task brief specifies — then pins the
resulting root as a `PinnedHeader` and asserts `verify_anchor` recognizes it.
Every other test is a controlled mutation of that one working fixture, so a
single assertion isolates exactly one failure mode.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import cast

import pytest

from attest import anchor, canon, tlog

NOTE_BYTES = b"log.example/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
HEADER_TIME = 1700000000
HEADER_HASH = "3a" * 32  # deliberately contains a hex letter, not just digits
_DUMMY_SIGNATURE_LINE = "— test-key AA==\n"


def _checkpoint(note_bytes: bytes = NOTE_BYTES) -> tlog.Checkpoint:
    return tlog.Checkpoint(
        origin="log.example/1",
        tree_size=1,
        root=b"\x00" * 32,
        note_bytes=note_bytes,
        signed_note_bytes=_checkpoint_text(note_bytes).encode(),
    )


def _checkpoint_text(note_bytes: bytes = NOTE_BYTES) -> str:
    """Return a syntactically valid full C2SP note for ``note_bytes``.

    ``parse_checkpoint`` requires a signature line but does not verify it;
    the dummy line therefore lets anchor tests exercise only note binding.
    """
    return note_bytes.decode() + "\n" + _DUMMY_SIGNATURE_LINE


def _evidence(proofs: Sequence[object], note_bytes: bytes = NOTE_BYTES) -> dict[str, object]:
    return {"checkpoint": _checkpoint_text(note_bytes), "proofs": list(proofs)}


def _working_chain(note_bytes: bytes = NOTE_BYTES) -> tuple[list[list[str]], str]:
    """Build the op-chain forward and return `(ops, header_merkle_root)`.

    Sequence per the brief: append sibling, sha256, prepend prefix, sha256.
    Computed independently of `anchor.py` (plain `hashlib` calls) so the test
    pins the real algorithm rather than round-tripping the module's own logic.
    """
    sibling = bytes.fromhex("ab" * 32)  # hex letters, not just digits — needed for uppercase tests
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(note_bytes).digest()
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


def test_ots_proof_verifies_and_anchors_before_pinned_header_time() -> None:
    verdict = anchor.verify_anchor(_evidence([_ots_proof()]), _checkpoint(), _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.pq_surviving is True
    assert verdict.warnings == []
    # No `anchor_profile` in the evidence -> legacy note-bytes-only
    # commitment (G4): `note_only` flags it for `transparency.py`'s warning.
    assert verdict.note_only is True


def test_verify_anchor_requires_evidence_checkpoint_field() -> None:
    verdict = anchor.verify_anchor({"proofs": [_ots_proof()]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["evidence.checkpoint is required"]


def test_verify_anchor_rejects_non_str_evidence_checkpoint() -> None:
    verdict = anchor.verify_anchor(
        {"checkpoint": 1, "proofs": [_ots_proof()]}, _checkpoint(), _policy()
    )
    assert verdict.anchored is False
    assert verdict.warnings == ["evidence.checkpoint must be a str"]


def test_verify_anchor_rejects_malformed_evidence_checkpoint() -> None:
    verdict = anchor.verify_anchor(
        {"checkpoint": "not a signed checkpoint", "proofs": [_ots_proof()]},
        _checkpoint(),
        _policy(),
    )
    assert verdict.anchored is False
    assert verdict.warnings == ["evidence.checkpoint is not a valid signed checkpoint"]


def test_verify_anchor_rejects_evidence_checkpoint_for_different_note() -> None:
    different_note_bytes = NOTE_BYTES.replace(b"\n1\n", b"\n2\n")
    verdict = anchor.verify_anchor(
        _evidence([_ots_proof()], note_bytes=different_note_bytes), _checkpoint(), _policy()
    )
    assert verdict.anchored is False
    assert verdict.warnings == ["evidence.checkpoint does not match checkpoint argument"]


# --------------------------------------------------------------------------
# Negatives from the brief's Step 1 list.
# --------------------------------------------------------------------------


def test_ots_proof_fails_on_wrong_header_root() -> None:
    ops, _real_root = _working_chain()
    wrong_root = "aa" * 32
    proof = _ots_proof(ops=ops, header_merkle_root=wrong_root)
    verdict = anchor.verify_anchor(
        _evidence([proof]), _checkpoint(), _policy(merkle_root=wrong_root)
    )
    assert verdict.anchored is False
    assert verdict.anchored_before is None
    assert verdict.pq_surviving is False
    assert verdict.warnings == ["proof[0]: ots op-chain result does not match header_merkle_root"]


def test_ots_proof_fails_when_header_not_pinned() -> None:
    proof = _ots_proof(header_hash="44" * 32)  # valid shape, not in policy.pinned_headers
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: header_hash is not in policy.pinned_headers"]


def test_ots_proof_fails_on_unknown_op_name() -> None:
    ops, root = _working_chain()
    ops = [*ops, ["frobnicate"]]
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: unknown ots op 'frobnicate'"]


def test_ots_proof_fails_on_empty_ops() -> None:
    root = hashlib.sha256(NOTE_BYTES).hexdigest()
    proof = _ots_proof(ops=[], header_merkle_root=root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof has empty op-chain"]


def test_ots_proof_fails_when_pinned_header_root_differs_from_proof_root() -> None:
    _, proof_root = _working_chain()
    verdict = anchor.verify_anchor(
        _evidence([_ots_proof(header_merkle_root=proof_root)]),
        _checkpoint(),
        _policy(merkle_root="ef" * 32),
    )
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: pinned header merkle_root does not match proof"]


def test_ots_proof_fails_when_pinned_header_time_differs_from_proof_time() -> None:
    verdict = anchor.verify_anchor(
        _evidence([_ots_proof()]), _checkpoint(), _policy(time=HEADER_TIME + 1)
    )
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: pinned header time does not match proof"]


def test_rfc3161_only_evidence_is_classical_corroboration_without_pq_or_anchor_time() -> None:
    evidence = _evidence([{"kind": "rfc3161", "token_b64": "cXVpdGVvcGFxdWU="}])
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before is None
    assert verdict.pq_surviving is False
    assert verdict.warnings == [
        "rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight"
    ]


# --------------------------------------------------------------------------
# Anchor profile v2 (G4): commitment over the FULL signed checkpoint, not
# just its unsigned `note_bytes` header.
# --------------------------------------------------------------------------


def _working_chain_v2(
    signed_note_bytes: bytes = _checkpoint_text().encode(),
) -> tuple[list[list[str]], str]:
    """Same op sequence as `_working_chain`, but starting from
    `SHA256(signed_note_bytes)` — the v2 accumulator seed."""
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(signed_note_bytes).digest()
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


def test_v2_anchor_commits_over_the_full_signed_note() -> None:
    ops, root = _working_chain_v2()
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    evidence = {**_evidence([proof]), "anchor_profile": "signed-note-v2"}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.pq_surviving is True
    assert verdict.note_only is False
    assert verdict.warnings == []


def test_v2_anchor_over_note_bytes_only_fails() -> None:
    # The op-chain was built from SHA256(note_bytes) alone (the v1 seed) —
    # under a declared v2 profile the verifier starts from
    # SHA256(signed_note_bytes) instead, so the replayed chain lands on a
    # different root than the one pinned for the v1-seeded chain, and the
    # anchor does not verify. This is exactly the TM-33 property: a v1-style
    # commitment cannot pass as v2 proof of the signed note's existence.
    ops, root = _working_chain()
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    evidence = {**_evidence([proof]), "anchor_profile": "signed-note-v2"}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.pq_surviving is False
    assert verdict.warnings == [
        "proof[0]: ots op-chain result does not match header_merkle_root; anchor_profile "
        "signed-note-v2 requires the accumulator to start from "
        "SHA256(checkpoint.signed_note_bytes) — this evidence looks like a note-v1 "
        "commitment presented as signed-note-v2"
    ]


def test_v2_anchor_mismatch_not_matching_legacy_seed_stays_generic() -> None:
    """A v2-declared op-chain that matches NEITHER seed gets the profile-aware
    "requires" clause but not the "looks like note-v1" diagnosis — that extra
    clause is only added when the legacy seed's replay genuinely matches."""
    ops, root = _working_chain(note_bytes=b"neither-seed-produces-this-root\n")
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    evidence = {**_evidence([proof]), "anchor_profile": "signed-note-v2"}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots op-chain result does not match header_merkle_root; anchor_profile "
        "signed-note-v2 requires the accumulator to start from SHA256(checkpoint.signed_note_bytes)"
    ]


def test_v1_anchor_explicit_note_v1_profile_behaves_like_absent() -> None:
    evidence = {**_evidence([_ots_proof()]), "anchor_profile": "note-v1"}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.note_only is True
    assert verdict.warnings == []


def test_v1_anchor_explicit_null_profile_behaves_like_absent() -> None:
    evidence = {**_evidence([_ots_proof()]), "anchor_profile": None}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is True
    assert verdict.note_only is True
    assert verdict.warnings == []


def test_verify_anchor_rejects_unrecognized_anchor_profile() -> None:
    evidence = {**_evidence([_ots_proof()]), "anchor_profile": "signed-note-v3"}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        "evidence.anchor_profile must be 'note-v1' or 'signed-note-v2', got 'signed-note-v3'"
    ]


def test_verify_anchor_rejects_non_string_anchor_profile() -> None:
    evidence = {**_evidence([_ots_proof()]), "anchor_profile": 2}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        "evidence.anchor_profile must be 'note-v1' or 'signed-note-v2', got 2"
    ]


# --------------------------------------------------------------------------
# passes_horizon.
# --------------------------------------------------------------------------


def test_passes_horizon_false_when_horizon_before_anchor_time() -> None:
    verdict = anchor.verify_anchor(_evidence([_ots_proof()]), _checkpoint(), _policy())
    policy = _policy(crqc_horizon=1600000000)  # before HEADER_TIME
    assert anchor.passes_horizon(verdict, policy) is False


def test_passes_horizon_true_when_horizon_none() -> None:
    verdict = anchor.verify_anchor(_evidence([_ots_proof()]), _checkpoint(), _policy())
    policy = _policy(crqc_horizon=None)
    assert anchor.passes_horizon(verdict, policy) is True


def test_passes_horizon_true_when_horizon_after_anchor_time_and_pq_surviving() -> None:
    verdict = anchor.verify_anchor(_evidence([_ots_proof()]), _checkpoint(), _policy())
    policy = _policy(crqc_horizon=HEADER_TIME + 1)
    assert anchor.passes_horizon(verdict, policy) is True


def test_passes_horizon_false_for_rfc3161_only_with_any_horizon_set() -> None:
    evidence = _evidence([{"kind": "rfc3161", "token_b64": "opaque"}])
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    policy = _policy(crqc_horizon=HEADER_TIME + 1)
    assert anchor.passes_horizon(verdict, policy) is False


def test_passes_horizon_raises_anchor_error_on_non_anchor_policy() -> None:
    verdict = anchor.AnchorVerdict(
        anchored=False, anchored_before=None, pq_surviving=False, warnings=[]
    )
    with pytest.raises(anchor.AnchorError):
        anchor.passes_horizon(verdict, "not-a-policy")  # type: ignore[arg-type]


def test_passes_horizon_never_raises_on_malformed_verdict_content() -> None:
    policy = _policy(crqc_horizon=HEADER_TIME + 1)
    assert anchor.passes_horizon("not-a-verdict", policy) is False  # type: ignore[arg-type]
    bad_verdict = anchor.AnchorVerdict(
        anchored=True,
        anchored_before=cast(int | None, "not-an-int"),
        pq_surviving=True,
        warnings=[],
    )
    assert anchor.passes_horizon(bad_verdict, policy) is False


def test_passes_horizon_true_with_malformed_verdict_when_horizon_none() -> None:
    # policy.crqc_horizon is None short-circuits True before verdict is even inspected.
    policy = _policy(crqc_horizon=None)
    assert anchor.passes_horizon("not-a-verdict", policy) is True  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("crqc_horizon", "pq_surviving", "anchored_before", "expected"),
    [
        (None, False, None, True),
        (None, False, HEADER_TIME, True),
        (None, True, None, True),
        (None, True, HEADER_TIME, True),
        (HEADER_TIME + 1, False, None, False),
        (HEADER_TIME + 1, False, HEADER_TIME, False),
        (HEADER_TIME + 1, True, None, False),
        (HEADER_TIME + 1, True, HEADER_TIME, True),
    ],
)
def test_passes_horizon_all_input_combinations(
    crqc_horizon: int | None,
    pq_surviving: bool,
    anchored_before: int | None,
    expected: bool,
) -> None:
    verdict = anchor.AnchorVerdict(
        anchored=False,
        anchored_before=anchored_before,
        pq_surviving=pq_surviving,
        warnings=[],
    )
    assert anchor.passes_horizon(verdict, _policy(crqc_horizon=crqc_horizon)) is expected


def test_passes_horizon_rejects_anchor_exactly_at_horizon() -> None:
    verdict = anchor.AnchorVerdict(
        anchored=True, anchored_before=HEADER_TIME, pq_surviving=True, warnings=[]
    )
    assert anchor.passes_horizon(verdict, _policy(crqc_horizon=HEADER_TIME)) is False


# --------------------------------------------------------------------------
# Multiple proofs: anchored_before is the min over verified PQ proofs.
# --------------------------------------------------------------------------


def test_anchored_before_is_min_over_multiple_verified_pq_proofs() -> None:
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
    verdict = anchor.verify_anchor(evidence, _checkpoint(), policy)
    assert verdict.anchored_before == earlier_time
    assert verdict.pq_surviving is True


# --------------------------------------------------------------------------
# verify_anchor never raises on malformed EVIDENCE (untrusted input).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_evidence", [None, [], "not-a-dict", 42, True])
def test_verify_anchor_never_raises_on_non_dict_evidence(bad_evidence: object) -> None:
    verdict = anchor.verify_anchor(bad_evidence, _checkpoint(), _policy())  # type: ignore[arg-type]
    assert verdict.anchored is False
    assert verdict.anchored_before is None
    assert verdict.pq_surviving is False
    assert len(verdict.warnings) == 1
    assert "evidence must be an object" in verdict.warnings[0]


def test_verify_anchor_never_raises_when_proofs_key_missing() -> None:
    verdict = anchor.verify_anchor({"checkpoint": _checkpoint_text()}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert "evidence.proofs must be a list" in verdict.warnings[0]


@pytest.mark.parametrize("bad_proofs", ["not-a-list", 1, None, {}])
def test_verify_anchor_never_raises_when_proofs_not_a_list(bad_proofs: object) -> None:
    verdict = anchor.verify_anchor(
        {"checkpoint": _checkpoint_text(), "proofs": bad_proofs}, _checkpoint(), _policy()
    )
    assert verdict.anchored is False
    assert "evidence.proofs must be a list" in verdict.warnings[0]


def test_verify_anchor_caps_proofs_list_length() -> None:
    oversized = [{"kind": "bogus"}] * (anchor._MAX_PROOFS_PER_EVIDENCE + 1)
    verdict = anchor.verify_anchor(_evidence(oversized), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert f"exceeds max length {anchor._MAX_PROOFS_PER_EVIDENCE}" in verdict.warnings[0]


@pytest.mark.parametrize("bad_proof", [None, "string", 42, [], True])
def test_verify_anchor_ignores_non_dict_proof_entry_with_warning(bad_proof: object) -> None:
    verdict = anchor.verify_anchor(_evidence([bad_proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [f"proof[0]: must be an object, got {type(bad_proof).__name__}"]


def test_verify_anchor_unknown_kind_is_ignored_not_fatal() -> None:
    evidence = _evidence([{"kind": "future-kind", "stuff": 1}, _ots_proof()])
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    # The unrecognized proof doesn't crash the whole evidence, and the valid
    # ots proof alongside it still verifies.
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert "proof[0]: unknown proof kind 'future-kind', ignored" in verdict.warnings


@pytest.mark.parametrize(
    ("value", "rendered"),
    [
        ("a'b", '"a\'b"'),
        ('a"b', "'a\"b'"),
        ("a'\"b", "'a\\'\"b'"),
        ("a\nb", r"'a\nb'"),
        ("a\\b", r"'a\\b'"),
        ("\u200b", r"'\u200b'"),
        ("🎉", r"'\U0001f389'"),
        ("\U0002ebf0", r"'\U0002ebf0'"),
        ("\x7f", r"'\x7f'"),
    ],
)
def test_verify_anchor_warning_renderer_matches_python_ascii(value: str, rendered: str) -> None:
    kind_verdict = anchor.verify_anchor(_evidence([{"kind": value}]), _checkpoint(), _policy())
    assert kind_verdict.warnings == [f"proof[0]: unknown proof kind {rendered}, ignored"]

    op_verdict = anchor.verify_anchor(
        _evidence([_ots_proof(ops=[[value]])]), _checkpoint(), _policy()
    )
    assert op_verdict.warnings == [f"proof[0]: unknown ots op {rendered}"]


@pytest.mark.parametrize("hostile_kind", [10**5000, "x" * 100_000], ids=["huge-int", "huge-string"])
def test_verify_anchor_safely_renders_hostile_unknown_kind(hostile_kind: object) -> None:
    verdict = anchor.verify_anchor(_evidence([{"kind": hostile_kind}]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings[0].startswith("proof[0]: unknown proof kind ")
    assert len(verdict.warnings[0]) <= 100


def test_verify_anchor_ots_proof_missing_ops_field() -> None:
    proof = _ots_proof()
    del proof["ops"]
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'ops' must be a list"]


def test_verify_anchor_rfc3161_rejects_non_str_token() -> None:
    evidence = _evidence([{"kind": "rfc3161", "token_b64": 12345}])
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: rfc3161 token_b64 must be a str, got int"]


def test_verify_anchor_raises_anchor_error_on_non_checkpoint_argument() -> None:
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, "not-a-checkpoint", _policy())  # type: ignore[arg-type]


def test_verify_anchor_raises_anchor_error_on_non_anchor_policy() -> None:
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), "not-a-policy")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Hex validation discipline: lowercase-only, strict length, guard before
# bytes.fromhex (which itself accepts uppercase and odd-padded input).
# --------------------------------------------------------------------------


def test_ots_proof_rejects_uppercase_header_merkle_root() -> None:
    ops, root = _working_chain()
    proof = _ots_proof(ops=ops, header_merkle_root=root.upper())
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars"
    ]


@pytest.mark.parametrize("bad_root", ["aa" * 31, "aa" * 33, "not-hex-at-all-" + "a" * 49])
def test_ots_proof_rejects_wrong_length_or_non_hex_header_merkle_root(bad_root: str) -> None:
    proof = _ots_proof(header_merkle_root=bad_root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars"
    ]


def test_ots_proof_rejects_uppercase_header_hash() -> None:
    proof = _ots_proof(header_hash=HEADER_HASH.upper())
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'header_hash' must be 64 lowercase hex chars"]


def test_ots_proof_rejects_uppercase_op_operand_even_though_bytes_fromhex_would_accept_it() -> None:
    ops, root = _working_chain()
    sibling_hex_upper = ops[0][1].upper()
    assert bytes.fromhex(sibling_hex_upper) == bytes.fromhex(
        ops[0][1]
    )  # sanity: fromhex tolerates it
    bad_ops = [["append", sibling_hex_upper], *ops[1:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_ots_proof_rejects_odd_length_op_operand() -> None:
    ops, root = _working_chain()
    bad_ops = [["append", "abc"], *ops[1:]]  # 3 hex chars: valid charset, odd length
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_ots_proof_rejects_op_operand_over_max_hex_length() -> None:
    ops, root = _working_chain()
    too_long = "ab" * (anchor._MAX_OP_HEX_LEN // 2 + 1)
    bad_ops = [["append", too_long], *ops[1:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_ots_proof_accepts_op_operand_at_exactly_max_hex_length() -> None:
    # Boundary check the cap itself doesn't off-by-one reject a legitimate max-size operand.
    note_bytes = NOTE_BYTES
    operand_hex = "ab" * (anchor._MAX_OP_HEX_LEN // 2)
    operand = bytes.fromhex(operand_hex)
    acc = hashlib.sha256(note_bytes).digest()
    acc = acc + operand
    acc = hashlib.sha256(acc).digest()
    root = acc.hex()
    ops = [["append", operand_hex], ["sha256"]]
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(
        _evidence([proof], note_bytes), _checkpoint(note_bytes), _policy(merkle_root=root)
    )
    assert verdict.anchored is True


def test_ots_proof_rejects_sha256_op_with_operand() -> None:
    ops, root = _working_chain()
    bad_ops = [*ops[:1], ["sha256", "ff"], *ops[2:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots 'sha256' op takes no operand"]


def test_ots_proof_rejects_op_that_is_not_a_list() -> None:
    ops, root = _working_chain()
    bad_ops = ["sha256", *ops]  # bare string instead of ["sha256"]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots op must be a non-empty list with a string opcode"]


def test_ots_proof_caps_ops_list_length() -> None:
    oversized_ops = [["sha256"]] * (anchor._MAX_OPS_PER_PROOF + 1)
    proof = _ots_proof(ops=oversized_ops)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"proof[0]: ots proof has more than {anchor._MAX_OPS_PER_PROOF} ops"
    ]


# --------------------------------------------------------------------------
# bool-is-int traps: `isinstance(True, int)` is True in Python — must be
# excluded everywhere an int is required.
# --------------------------------------------------------------------------


def test_ots_proof_rejects_bool_header_time() -> None:
    proof = _ots_proof(header_time=True)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_time' must be a positive int no later than "
        f"{anchor._MAX_RENDERABLE_UNIX_TIME}"
    ]


def test_ots_proof_rejects_zero_or_negative_header_time() -> None:
    proof = _ots_proof(header_time=0)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_time' must be a positive int no later than "
        f"{anchor._MAX_RENDERABLE_UNIX_TIME}"
    ]


def test_ots_proof_rejects_header_time_after_renderable_unix_bound() -> None:
    proof = _ots_proof(header_time=anchor._MAX_RENDERABLE_UNIX_TIME + 1)
    verdict = anchor.verify_anchor(_evidence([proof]), _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.pq_surviving is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_time' must be a positive int no later than "
        f"{anchor._MAX_RENDERABLE_UNIX_TIME}"
    ]


def test_anchor_policy_rejects_bool_pinned_header_time() -> None:
    pinned = anchor.PinnedHeader(header_hash=HEADER_HASH, merkle_root="aa" * 32, time=True)
    policy = anchor.AnchorPolicy(pinned_headers={HEADER_HASH: pinned}, crqc_horizon=None)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_anchor_policy_rejects_pinned_header_time_after_renderable_unix_bound() -> None:
    pinned = anchor.PinnedHeader(
        header_hash=HEADER_HASH,
        merkle_root="aa" * 32,
        time=anchor._MAX_RENDERABLE_UNIX_TIME + 1,
    )
    policy = anchor.AnchorPolicy(pinned_headers={HEADER_HASH: pinned}, crqc_horizon=None)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_anchor_policy_rejects_bool_crqc_horizon() -> None:
    policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=True)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


# --------------------------------------------------------------------------
# AnchorPolicy structural validation (trusted config side — raises).
# --------------------------------------------------------------------------


def test_anchor_policy_rejects_mismatched_dict_key_and_header_hash_field() -> None:
    pinned = anchor.PinnedHeader(header_hash=HEADER_HASH, merkle_root="aa" * 32, time=HEADER_TIME)
    policy = anchor.AnchorPolicy(pinned_headers={"ff" * 32: pinned}, crqc_horizon=None)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_anchor_policy_rejects_non_pinned_header_value() -> None:
    policy = anchor.AnchorPolicy(
        pinned_headers=cast(dict[str, anchor.PinnedHeader], {HEADER_HASH: "not-a-pinned-header"}),
        crqc_horizon=None,
    )
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_anchor_policy_rejects_uppercase_pinned_header_merkle_root() -> None:
    pinned = anchor.PinnedHeader(header_hash=HEADER_HASH, merkle_root="AA" * 32, time=HEADER_TIME)
    policy = anchor.AnchorPolicy(pinned_headers={HEADER_HASH: pinned}, crqc_horizon=None)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_verify_anchor_rejects_oversized_evidence_checkpoint_text() -> None:
    # A multi-megabyte hostile checkpoint string must be rejected BEFORE it
    # reaches tlog.parse_checkpoint (allocation-DoS guard), with a bounded
    # warning and no exception.
    text = "x" * (anchor._MAX_CHECKPOINT_TEXT_LEN + 1)
    verdict = anchor.verify_anchor(
        {"checkpoint": text, "proofs": [_ots_proof()]}, _checkpoint(), _policy()
    )
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"evidence.checkpoint exceeds max length {anchor._MAX_CHECKPOINT_TEXT_LEN}"
    ]


def test_caps_admit_a_real_ots_bitcoin_attestation() -> None:
    """The three op-chain caps are sized from MEASURED real attestations, not guessed.

    Measured 2026-08-31 over four upstream OpenTimestamps example files: the
    largest Bitcoin path carries 100 ops (`bitcoin.pdf.ots`), the largest single
    operand is 3432 bytes (`empty.ots`, the Bitcoin transaction prefix ahead of
    the commitment output), and the largest per-chain operand total is 7388 hex
    chars. The pre-2026-08-31 values (64 ops, 2048 hex) rejected the first of
    those outright, so no real attestation could ever have been attached.

    `_MAX_TOTAL_OP_HEX_LEN` is not decoration: it is what keeps the raised
    per-op caps inside `verify`'s outer evidence ceiling, which is normative
    (`canon.MAX_ADMISSION_BYTES`, v0.2 §6.3) and therefore cannot be raised to
    meet them. Without it, `_MAX_PROOFS_PER_EVIDENCE * _MAX_OPS_PER_PROOF *
    _MAX_OP_HEX_LEN` admits 268,435,456 operand characters against a 10,000,000-character ceiling.
    """
    assert anchor._MAX_OPS_PER_PROOF == 256
    assert anchor._MAX_OP_HEX_LEN == 16384
    assert anchor._MAX_TOTAL_OP_HEX_LEN == 65536


def test_total_operand_cap_keeps_evidence_inside_the_normative_outer_ceiling() -> None:
    """The three caps must compose to something the outer ceiling still covers.

    This is the invariant `verify.py`'s `_MAX_TRANSPARENCY_EVIDENCE_LEN` comment
    states in prose; asserting it here makes it a test rather than an arithmetic
    claim nobody re-derives when a cap moves.
    """
    operand_budget = anchor._MAX_PROOFS_PER_EVIDENCE * anchor._MAX_TOTAL_OP_HEX_LEN
    checkpoints = 3 * anchor._MAX_CHECKPOINT_TEXT_LEN
    assert operand_budget + checkpoints < canon.MAX_ADMISSION_BYTES


def _chain_totalling(total_hex: int, *, chunk_hex: int = 8192) -> list[list[str]]:
    """Build an op-chain whose append operands sum to exactly `total_hex` hex chars."""
    ops: list[list[str]] = []
    remaining = total_hex
    while remaining > 0:
        take = min(chunk_hex, remaining)
        ops.append(["append", "ab" * (take // 2)])
        ops.append(["sha256"])
        remaining -= take
    return ops


def test_replay_accepts_operands_at_exactly_the_total_cap() -> None:
    """The boundary is inclusive: a chain summing to exactly the cap still replays.

    A real Bitcoin path's operands totalled 7388 hex chars at the largest
    measured, so the cap is not a limit real material sits against — but the
    boundary still has to be pinned, or an off-by-one turns legitimate evidence
    away.
    """
    ops = _chain_totalling(anchor._MAX_TOTAL_OP_HEX_LEN)
    accumulator, warning = anchor.replay_ots_op_chain(b"\x00" * 32, ops)
    assert warning is None
    assert accumulator is not None


def test_replay_rejects_operands_one_hex_pair_over_the_total_cap() -> None:
    """One byte past the total is refused, and the message names the cap."""
    ops = [*_chain_totalling(anchor._MAX_TOTAL_OP_HEX_LEN), ["append", "ab"]]
    accumulator, warning = anchor.replay_ots_op_chain(b"\x00" * 32, ops)
    assert accumulator is None
    assert warning == (f"ots proof operands exceed {anchor._MAX_TOTAL_OP_HEX_LEN} total hex chars")


def test_replay_rejects_total_cap_overflow_from_many_small_operands() -> None:
    """The total is an accumulator, so it must refuse a sum reached in crumbs.

    The boundary pair above overflows with one maximal operand; an attacker
    who never touches the per-op cap gets there with many small ones instead,
    and only the running total sees it.
    """
    chunk_hex = 1024
    ops = _chain_totalling(anchor._MAX_TOTAL_OP_HEX_LEN + 2, chunk_hex=chunk_hex)
    operand_ops = [op for op in ops if len(op) == 2]
    assert len(ops) <= anchor._MAX_OPS_PER_PROOF
    assert len(operand_ops) > anchor._MAX_TOTAL_OP_HEX_LEN // anchor._MAX_OP_HEX_LEN
    assert all(len(op[1]) <= chunk_hex <= anchor._MAX_OP_HEX_LEN for op in operand_ops)
    assert sum(len(op[1]) for op in operand_ops) == anchor._MAX_TOTAL_OP_HEX_LEN + 2

    accumulator, warning = anchor.replay_ots_op_chain(b"\x00" * 32, ops)

    assert accumulator is None
    assert warning == (f"ots proof operands exceed {anchor._MAX_TOTAL_OP_HEX_LEN} total hex chars")


def test_total_operand_cap_counts_only_append_and_prepend_operands() -> None:
    """`sha256` carries no operand and must not consume the budget.

    Stated because a total-byte cap implemented over "every op" would silently
    shrink the real budget, and the shrink would only show on chains long
    enough that nobody writes them by hand.
    """
    ops = _chain_totalling(anchor._MAX_TOTAL_OP_HEX_LEN, chunk_hex=1024)
    sha_ops = sum(1 for op in ops if op[0] == "sha256")
    assert sha_ops > 1
    _, warning = anchor.replay_ots_op_chain(b"\x00" * 32, ops)
    assert warning is None
