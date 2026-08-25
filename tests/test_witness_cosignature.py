"""Witness cosignature verification and reachable `corroboration: "witnessed"`.

Contract: v0.2 §9.2 and §10.1 (P1.1b amendment), plus C2SP tlog-cosignature.
A type-`0x04` line's blob is `key_id(4) || timestamp(8, big-endian) ||
signature(64)`, and the signed message is `cosignature/v1\\n` + `time <POSIX>\\n`
+ the checkpoint note body.

Everything a cosignature can get wrong degrades SILENTLY to the standing the
evidence already had: §11.4 forbids any warning literal here beyond
`witness_independence_not_established`, and the cosignature is untrusted input,
so nothing in this file may raise.
"""

from __future__ import annotations

import base64
import struct
from typing import Any

import pytest

from attest import anchor, canon, keys, pq, tlog, transparency, witness

_ORIGIN = "log.example"
_WITNESS_NAME = "witness.example/w1"


@pytest.fixture(scope="module")
def log_keys() -> tuple[Any, Any]:
    return keys.generate(), pq.generate()


@pytest.fixture(scope="module")
def witness_keys() -> Any:
    return keys.generate()


def _checkpoint_text(log_ed: Any, log_mldsa: Any, *, tree_size: int = 4) -> str:
    """A minimally valid hybrid-signed checkpoint for this origin."""
    return tlog.sign_checkpoint(
        _ORIGIN,
        tree_size,
        bytes(32),
        pq.HybridSigningKeys(ed=log_ed, mldsa=log_mldsa),
        _ORIGIN,
    )


def _policy_doc(witness_pub_b64u: str, **pin_overrides: Any) -> dict[str, Any]:
    pin: dict[str, Any] = {
        "operator_id": "witness.example",
        "control_group": "witness.example",
        "name": _WITNESS_NAME,
        "ed25519_pub_b64u": witness_pub_b64u,
        "mldsa_65_pub_b64u": None,
        "roles": ["corroboration"],
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": None,
        "affiliated_domains": ["witness.example"],
    }
    pin.update(pin_overrides)
    return {
        "schema": "attest-witness-policy-v1",
        "epochs": [
            {
                "epoch_id": "bootstrap-1",
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": None,
                "log_origins": [_ORIGIN],
                "threshold": {"n": 1, "m": 1},
                "witnesses": [pin],
            }
        ],
    }


# --- the signed message and the key id -------------------------------------


def test_cosignature_message_is_the_c2sp_payload() -> None:
    """`cosignature/v1\\n` + `time <POSIX>\\n` + note body, byte for byte."""
    note = b"log.example\n4\nAAAA\n"
    assert witness.cosignature_message(note, 1679315147) == (
        b"cosignature/v1\ntime 1679315147\n" + note
    )


def test_cosignature_message_rejects_a_negative_timestamp() -> None:
    with pytest.raises(witness.WitnessError):
        witness.cosignature_message(b"x\n", -1)


def test_cosignature_key_id_uses_type_04(witness_keys: Any) -> None:
    """`SHA-256(name || "\\n" || 0x04 || pub)[:4]` — distinct from the log's."""
    key_id = witness.cosignature_key_id(_WITNESS_NAME, witness_keys.pub)
    assert len(key_id) == 4
    # Type 0x01 is the checkpoint's own Ed25519 type: a different key id.
    assert key_id != tlog.key_hash(_WITNESS_NAME, tlog.ED25519_SIG_TYPE, witness_keys.pub)


# --- reaching `witnessed` --------------------------------------------------


def _cosign(checkpoint: tlog.Checkpoint, signer: Any, timestamp: int) -> bytes:
    """A well-formed type-`0x04` blob over this checkpoint."""
    key_id = witness.cosignature_key_id(_WITNESS_NAME, signer.pub)
    message = witness.cosignature_message(checkpoint.note_bytes, timestamp)
    return key_id + struct.pack(">Q", timestamp) + keys.sign(message, signer)


def test_one_valid_pinned_cosignature_reaches_witnessed(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """§10.1: one valid `0x04` by a pinned, epoch-valid corroboration witness."""
    log_ed, log_mldsa = log_keys
    text = _checkpoint_text(log_ed, log_mldsa)
    checkpoint = tlog.parse_checkpoint(text)
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    policy = witness.parse_policy(_policy_doc(keys.b64u(witness_keys.pub)))

    verdict = witness.evaluate_corroboration(
        checkpoint=checkpoint,
        signatures=[(_WITNESS_NAME, blob)],
        policy=policy,
        epoch_id="bootstrap-1",
    )
    assert verdict.witnessed is True
    assert verdict.warnings == [witness.WARN_INDEPENDENCE_NOT_ESTABLISHED]


def test_the_independence_warning_is_unconditional(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """§11.4: no witnessed result may ever be emitted without it."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    policy = witness.parse_policy(
        _policy_doc(keys.b64u(witness_keys.pub), affiliated_domains=["witness.example"])
    )
    verdict = witness.evaluate_corroboration(
        checkpoint=checkpoint,
        signatures=[(_WITNESS_NAME, blob)],
        policy=policy,
        epoch_id="bootstrap-1",
    )
    assert witness.WARN_INDEPENDENCE_NOT_ESTABLISHED in verdict.warnings


# --- everything that must NOT count ----------------------------------------


def _reject_case(
    checkpoint: tlog.Checkpoint,
    signatures: list[tuple[str, bytes]],
    policy_doc: dict[str, Any],
    epoch_id: str = "bootstrap-1",
) -> witness.CorroborationVerdict:
    return witness.evaluate_corroboration(
        checkpoint=checkpoint,
        signatures=signatures,
        policy=witness.parse_policy(policy_doc),
        epoch_id=epoch_id,
    )


def test_unpinned_witness_does_not_count(log_keys: tuple[Any, Any]) -> None:
    """A genuine cosignature by a key the policy never pinned."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    stranger = keys.generate()
    pinned = keys.generate()
    blob = _cosign(checkpoint, stranger, 1700000000)
    verdict = _reject_case(checkpoint, [(_WITNESS_NAME, blob)], _policy_doc(keys.b64u(pinned.pub)))
    assert verdict.witnessed is False
    assert verdict.warnings == []


def test_invalid_signature_does_not_count(log_keys: tuple[Any, Any], witness_keys: Any) -> None:
    """Right name, right key id, corrupted signature bytes."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = bytearray(_cosign(checkpoint, witness_keys, 1700000000))
    blob[-1] ^= 0xFF
    verdict = _reject_case(
        checkpoint, [(_WITNESS_NAME, bytes(blob))], _policy_doc(keys.b64u(witness_keys.pub))
    )
    assert verdict.witnessed is False
    assert verdict.warnings == []


def test_signature_over_a_different_timestamp_does_not_count(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """The blob's declared time must be the time that was signed."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    key_id = witness.cosignature_key_id(_WITNESS_NAME, witness_keys.pub)
    signed = keys.sign(witness.cosignature_message(checkpoint.note_bytes, 1700000000), witness_keys)
    # Declare a different timestamp than the one inside the signed message.
    blob = key_id + struct.pack(">Q", 1700000001) + signed
    verdict = _reject_case(
        checkpoint, [(_WITNESS_NAME, blob)], _policy_doc(keys.b64u(witness_keys.pub))
    )
    assert verdict.witnessed is False


def test_checkpoint_domain_signature_is_not_a_cosignature(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """§9.2 domain separation: a note-body signature is not a `cosignature/v1`."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    key_id = witness.cosignature_key_id(_WITNESS_NAME, witness_keys.pub)
    # Signs the checkpoint body directly, the way the LOG signs it.
    blob = key_id + struct.pack(">Q", 1700000000) + keys.sign(checkpoint.note_bytes, witness_keys)
    verdict = _reject_case(
        checkpoint, [(_WITNESS_NAME, blob)], _policy_doc(keys.b64u(witness_keys.pub))
    )
    assert verdict.witnessed is False


def test_wrong_blob_length_does_not_count(log_keys: tuple[Any, Any], witness_keys: Any) -> None:
    """A `0x01` checkpoint blob is 68 bytes; a `0x04` cosignature is 76."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    short = _cosign(checkpoint, witness_keys, 1700000000)[:-8]
    verdict = _reject_case(
        checkpoint, [(_WITNESS_NAME, short)], _policy_doc(keys.b64u(witness_keys.pub))
    )
    assert verdict.witnessed is False


def test_wrong_role_does_not_count(log_keys: tuple[Any, Any], witness_keys: Any) -> None:
    """A pin without the `corroboration` role contributes nothing."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    doc = _policy_doc(
        keys.b64u(witness_keys.pub),
        roles=["sunset-activation"],
        mldsa_65_pub_b64u=keys.b64u(bytes(pq.ML_DSA_65_PK_LEN)),
    )
    verdict = _reject_case(checkpoint, [(_WITNESS_NAME, blob)], doc)
    assert verdict.witnessed is False


def test_unresolvable_epoch_does_not_count(log_keys: tuple[Any, Any], witness_keys: Any) -> None:
    """Evidence names the epoch explicitly; the current one is never substituted."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    verdict = _reject_case(
        checkpoint,
        [(_WITNESS_NAME, blob)],
        _policy_doc(keys.b64u(witness_keys.pub)),
        epoch_id="no-such-epoch",
    )
    assert verdict.witnessed is False


def test_pin_outside_its_validity_window_does_not_count(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)  # 2023-11-14
    doc = _policy_doc(keys.b64u(witness_keys.pub), not_after="2021-01-01T00:00:00Z")
    verdict = _reject_case(checkpoint, [(_WITNESS_NAME, blob)], doc)
    assert verdict.witnessed is False


def test_compromise_cutoff_excludes_a_later_observation(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """`T > compromised_after` excludes; `T <= compromised_after` retains."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    retained = _reject_case(
        checkpoint,
        [(_WITNESS_NAME, blob)],
        _policy_doc(keys.b64u(witness_keys.pub), compromised_after="2024-01-01T00:00:00Z"),
    )
    assert retained.witnessed is True
    excluded = _reject_case(
        checkpoint,
        [(_WITNESS_NAME, blob)],
        _policy_doc(keys.b64u(witness_keys.pub), compromised_after="2021-01-01T00:00:00Z"),
    )
    assert excluded.witnessed is False


def test_unknown_compromise_onset_never_counts(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """Explicit `null` is fail-closed at every time (§11.4)."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    verdict = _reject_case(
        checkpoint,
        [(_WITNESS_NAME, blob)],
        _policy_doc(keys.b64u(witness_keys.pub), compromised_after=None),
    )
    assert verdict.witnessed is False


def test_a_wrong_name_line_is_skipped_not_fatal(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """Signed-note convention: other parties' lines coexist in the same note."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    good = _cosign(checkpoint, witness_keys, 1700000000)
    verdict = _reject_case(
        checkpoint,
        [("someone.else/x", b"\x00" * 76), (_WITNESS_NAME, good)],
        _policy_doc(keys.b64u(witness_keys.pub)),
    )
    assert verdict.witnessed is True


def test_no_signatures_at_all_is_silent(log_keys: tuple[Any, Any], witness_keys: Any) -> None:
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    verdict = _reject_case(checkpoint, [], _policy_doc(keys.b64u(witness_keys.pub)))
    assert verdict.witnessed is False
    assert verdict.warnings == []


def test_evaluation_never_raises_on_hostile_input(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """Cosignature lines are untrusted: every defect degrades, none raises."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    policy = witness.parse_policy(_policy_doc(keys.b64u(witness_keys.pub)))
    hostile: list[list[tuple[str, bytes]]] = [
        [(_WITNESS_NAME, b"")],
        [(_WITNESS_NAME, b"\xff" * 4096)],
        [("", b"\x00" * 76)],
    ]
    for signatures in hostile:
        verdict = witness.evaluate_corroboration(
            checkpoint=checkpoint, signatures=signatures, policy=policy, epoch_id="bootstrap-1"
        )
        assert verdict.witnessed is False


def test_canonical_empty_policy_can_never_reach_witnessed(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """What ships in the published packages: no epochs, so no witness at all."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    empty = witness.parse_policy(canon.loads_strict(witness.CANONICAL_EMPTY_POLICY_BYTES))
    verdict = witness.evaluate_corroboration(
        checkpoint=checkpoint,
        signatures=[(_WITNESS_NAME, blob)],
        policy=empty,
        epoch_id="bootstrap-1",
    )
    assert verdict.witnessed is False


# --- review regressions (2026-08-25) --------------------


def test_expired_epoch_does_not_count(log_keys: tuple[Any, Any], witness_keys: Any) -> None:
    """§10.1 wants an epoch-VALID witness, not merely a resolvable epoch."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    doc = _policy_doc(keys.b64u(witness_keys.pub))
    doc["epochs"][0]["not_after"] = "2021-01-01T00:00:00Z"
    assert _reject_case(checkpoint, [(_WITNESS_NAME, blob)], doc).witnessed is False


def test_epoch_scoped_to_another_origin_does_not_count(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """An epoch listing other logs says nothing about THIS checkpoint."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    doc = _policy_doc(keys.b64u(witness_keys.pub))
    doc["epochs"][0]["log_origins"] = ["other.example"]
    assert _reject_case(checkpoint, [(_WITNESS_NAME, blob)], doc).witnessed is False


def test_epoch_with_no_origins_corroborates_nothing(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """Fail-closed: an empty origin scope is no scope, not every scope."""
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    blob = _cosign(checkpoint, witness_keys, 1700000000)
    doc = _policy_doc(keys.b64u(witness_keys.pub))
    doc["epochs"][0]["log_origins"] = []
    assert _reject_case(checkpoint, [(_WITNESS_NAME, blob)], doc).witnessed is False


def test_a_hostile_line_cannot_veto_a_later_valid_one(
    log_keys: tuple[Any, Any], witness_keys: Any
) -> None:
    """The attack this closes: prepend garbage under the witness's own name.

    With one `try` around the whole scan, a well-shaped blob carrying an
    unrepresentable timestamp aborted evaluation before the genuine
    cosignature on the next line was ever examined — suppressing real
    corroboration for free.
    """
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    good = _cosign(checkpoint, witness_keys, 1700000000)
    hostile = (
        witness.cosignature_key_id(_WITNESS_NAME, witness_keys.pub)
        + struct.pack(">Q", 2**64 - 1)
        + bytes(64)
    )
    verdict = _reject_case(
        checkpoint,
        [(_WITNESS_NAME, hostile), (_WITNESS_NAME, good)],
        _policy_doc(keys.b64u(witness_keys.pub)),
    )
    assert verdict.witnessed is True


@pytest.mark.parametrize("timestamp", [253402300800, 2**64 - 1])
def test_timestamps_past_year_9999_never_count(
    log_keys: tuple[Any, Any], witness_keys: Any, timestamp: int
) -> None:
    """Python's `datetime` stops at 9999, JS `Date` reaches 275760.

    Without a shared ceiling the same cosignature would be refused by one
    core and accepted by the other.
    """
    log_ed, log_mldsa = log_keys
    checkpoint = tlog.parse_checkpoint(_checkpoint_text(log_ed, log_mldsa))
    key_id = witness.cosignature_key_id(_WITNESS_NAME, witness_keys.pub)
    message = b"cosignature/v1\n" + f"time {timestamp}\n".encode() + checkpoint.note_bytes
    blob = key_id + struct.pack(">Q", timestamp) + keys.sign(message, witness_keys)
    verdict = _reject_case(
        checkpoint, [(_WITNESS_NAME, blob)], _policy_doc(keys.b64u(witness_keys.pub))
    )
    assert verdict.witnessed is False


# --- end-to-end through evaluate_transparency ------------------------------


def _with_cosignature(checkpoint_text: str, name: str, blob: bytes) -> str:
    """Append a C2SP signature line to an existing signed note."""
    return checkpoint_text + f"\u2014 {name} {base64.b64encode(blob).decode()}\n"


class _Bundle:
    """A 3-leaf log with the entry under test at index 1 — the minimum
    `evaluate_transparency` needs to reach `logged` standing."""

    def __init__(self) -> None:
        self.hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
        self.log_key = tlog.LogKey(
            origin=_ORIGIN, name=_ORIGIN, ed25519_pub=self.hk.ed.pub, mldsa_pub=self.hk.mldsa.pub
        )
        self.entries: list[dict[str, Any]] = [
            {"type": "receipt", "issuer": f"issuer{i}.example", "core_sha256": f"{i:064x}"}
            for i in range(3)
        ]
        self.leaves = [tlog.encode_entry(e) for e in self.entries]
        self.root = tlog.build_tree(self.leaves)
        self.proof = tlog.inclusion_proof(self.leaves, 1)
        self.text = tlog.sign_checkpoint(_ORIGIN, 3, self.root, self.hk, _ORIGIN)
        self.checkpoint = tlog.parse_checkpoint(self.text)

    def evidence(self, checkpoint_text: str | None = None, **extra: Any) -> dict[str, Any]:
        bundle: dict[str, Any] = {
            "entry": dict(self.entries[1]),
            "leaf_index": 1,
            "tree_size": 3,
            "inclusion_proof": [p.hex() for p in self.proof],
            "checkpoint": checkpoint_text if checkpoint_text is not None else self.text,
        }
        bundle.update(extra)
        return bundle

    def evaluate(self, evidence: dict[str, Any], **overrides: Any) -> Any:
        kwargs: dict[str, Any] = {
            "log_keys": [self.log_key],
            "expected_origin": _ORIGIN,
            "policy": anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
            "expected_entry": dict(self.entries[1]),
        }
        kwargs.update(overrides)
        return transparency.evaluate_transparency(evidence, **kwargs)


def test_omitting_the_policy_preserves_the_previous_result(witness_keys: Any) -> None:
    """Zero behavior change for every existing caller (§10.2)."""
    bundle = _Bundle()
    blob = _cosign(bundle.checkpoint, witness_keys, 1700000000)
    text = _with_cosignature(bundle.text, _WITNESS_NAME, blob)
    result = bundle.evaluate(bundle.evidence(text, witness_policy_epoch="bootstrap-1"))
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert witness.WARN_INDEPENDENCE_NOT_ESTABLISHED not in result.warnings


def test_policy_plus_pinned_cosignature_reaches_witnessed(witness_keys: Any) -> None:
    bundle = _Bundle()
    blob = _cosign(bundle.checkpoint, witness_keys, 1700000000)
    text = _with_cosignature(bundle.text, _WITNESS_NAME, blob)
    result = bundle.evaluate(
        bundle.evidence(text, witness_policy_epoch="bootstrap-1"),
        witness_policy=_policy_doc(keys.b64u(witness_keys.pub)),
    )
    assert result.corroboration == transparency.CORROBORATION_WITNESSED
    assert witness.WARN_INDEPENDENCE_NOT_ESTABLISHED in result.warnings


def test_missing_epoch_in_evidence_stays_logged(witness_keys: Any) -> None:
    """Evidence MUST name the epoch; the current one is never substituted."""
    bundle = _Bundle()
    blob = _cosign(bundle.checkpoint, witness_keys, 1700000000)
    text = _with_cosignature(bundle.text, _WITNESS_NAME, blob)
    result = bundle.evaluate(
        bundle.evidence(text), witness_policy=_policy_doc(keys.b64u(witness_keys.pub))
    )
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.warnings == []


def test_evidence_cannot_supply_epoch_contents(witness_keys: Any) -> None:
    """A policy-shaped object in the EVIDENCE creates no trust whatsoever."""
    bundle = _Bundle()
    blob = _cosign(bundle.checkpoint, witness_keys, 1700000000)
    text = _with_cosignature(bundle.text, _WITNESS_NAME, blob)
    result = bundle.evaluate(
        bundle.evidence(
            text,
            witness_policy_epoch="bootstrap-1",
            witness_policy=_policy_doc(keys.b64u(witness_keys.pub)),
        )
    )
    assert result.corroboration == transparency.CORROBORATION_LOGGED


def test_a_malformed_trusted_policy_raises(witness_keys: Any) -> None:
    """Trusted-side discipline: a configuration bug is loud, never a downgrade."""
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        bundle.evaluate(bundle.evidence(), witness_policy={"schema": "wrong", "epochs": []})


def test_a_cosignature_never_rescues_a_broken_inclusion_proof(witness_keys: Any) -> None:
    """`witnessed` is reachable only from `logged` standing."""
    bundle = _Bundle()
    blob = _cosign(bundle.checkpoint, witness_keys, 1700000000)
    text = _with_cosignature(bundle.text, _WITNESS_NAME, blob)
    evidence = bundle.evidence(text, witness_policy_epoch="bootstrap-1")
    evidence["inclusion_proof"] = ["00" * 32]
    result = bundle.evaluate(evidence, witness_policy=_policy_doc(keys.b64u(witness_keys.pub)))
    assert result.corroboration != transparency.CORROBORATION_WITNESSED
