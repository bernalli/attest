"""What this witness signs, and whether anybody can check it.

The oracle in this file is always a CORE function, never a constant written
here. A cosignature is not "the bytes attest_witness produces" — it is what
`attest.witness` accepts, and pinning our own output against our own
expectation would prove only that we are self-consistent. So: the Ed25519 leg
is judged by `evaluate_corroboration`, the hybrid pair by
`evaluate_activation_witness_quorum`, and the resulting note by
`verify_checkpoint`. Every one of those can fail; a tautology cannot.
"""

from __future__ import annotations

import base64
import struct

import pytest
from attest_witness.cosign import CosignError, cosign
from witness_support import (
    BOOTSTRAP_EPOCH,
    WITNESS_NAME,
    anchor_for,
    log_keys,  # noqa: F401
    signed_checkpoint,
    witness_keys,  # noqa: F401
    witness_pin,
    witness_policy_document,
)

from attest import keys, pq, tlog
from attest import witness as witness_policy

ORIGIN = "log.example"
TIMESTAMP = 1_700_000_000


def _checkpoint_text(log_signing_keys: pq.HybridSigningKeys, size: int = 4) -> str:
    return signed_checkpoint(ORIGIN, size, bytes(32), log_signing_keys, ORIGIN)


def _corroboration(
    text: str, policy_document: dict[str, object], epoch_id: str = BOOTSTRAP_EPOCH
) -> witness_policy.CorroborationVerdict:
    checkpoint = tlog.parse_checkpoint(text)
    signatures = tlog.note_signatures(text)
    policy = witness_policy.load_policy(witness_policy.policy_bytes(policy_document))
    return witness_policy.evaluate_corroboration(
        checkpoint=checkpoint, signatures=signatures, policy=policy, epoch_id=epoch_id
    )


def test_the_signed_message_is_the_cosignature_v1_payload(
    witness_keys: pq.HybridSigningKeys,
) -> None:
    """Known-answer test on the payload itself (v0.2 §9.2): the header, the
    decimal timestamp line, then the note bytes — nothing else, in that order."""
    note = b"log.example\n4\nAAAA\n"
    assert (
        witness_policy.cosignature_message(note, TIMESTAMP)
        == b"cosignature/v1\ntime 1700000000\n" + note
    )


def test_the_ed25519_leg_makes_a_checkpoint_witnessed(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """The whole point of the service, judged by the core: one valid `0x04`
    cosignature from a pinned, epoch-valid witness reaches
    `corroboration: "witnessed"` (v0.2 §10.1)."""
    text = _checkpoint_text(log_keys)
    note = tlog.parse_checkpoint(text).note_bytes
    signature = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)

    verdict = _corroboration(
        text + signature.lines, witness_policy_document([witness_pin(witness_keys)])
    )
    assert verdict.witnessed is True
    assert witness_policy.WARN_INDEPENDENCE_NOT_ESTABLISHED in verdict.warnings


def test_an_unpinned_witness_does_not_reach_witnessed(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """Control for the test above: standing comes from the policy, never from
    the note. Same genuine signature, a policy pinning somebody else."""
    text = _checkpoint_text(log_keys)
    note = tlog.parse_checkpoint(text).note_bytes
    signature = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)

    stranger = pq.HybridSigningKeys(ed=keys.generate(), mldsa=witness_keys.mldsa)
    verdict = _corroboration(
        text + signature.lines, witness_policy_document([witness_pin(stranger)])
    )
    assert verdict.witnessed is False


def test_the_hybrid_pair_counts_as_an_activation_vote(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """Both legs, one timestamp, judged by §11.4's activation quorum — the
    only oracle that checks the ML-DSA-65 leg's own key id, identifier string
    and payload rather than just its presence."""
    text = _checkpoint_text(log_keys)
    note = tlog.parse_checkpoint(text).note_bytes
    signature = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)
    cosigned = text + signature.lines
    anchor = anchor_for(cosigned, TIMESTAMP + 60)

    document = witness_policy_document(
        [witness_pin(witness_keys, roles=["corroboration", "sunset-activation"], with_pq=True)]
    )
    result = witness_policy.evaluate_activation_witness_quorum(
        cosigned,
        witness_policy=witness_policy.load_policy(witness_policy.policy_bytes(document)),
        epoch_id=BOOTSTRAP_EPOCH,
        expected_origin=ORIGIN,
        anchor_evidence=anchor["evidence"],
        anchor_policy=anchor["policy"],
        conflict_domain="issuer.example",
    )
    assert result.valid is True
    assert result.witness_time == TIMESTAMP
    assert result.counting_control_groups == ("witness.example",)


def test_legs_signed_at_different_times_are_not_a_hybrid_vote(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """The invariant the code states and cannot show: §11.4 counts a pin only
    when both legs cover the same payload AND timestamp. Two legs a second
    apart are two unrelated signatures, and the quorum declines them."""
    text = _checkpoint_text(log_keys)
    note = tlog.parse_checkpoint(text).note_bytes
    early = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)
    late = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP + 1)
    mismatched = text + early.ed25519_line + late.mldsa_65_line
    anchor = anchor_for(mismatched, TIMESTAMP + 60)

    document = witness_policy_document(
        [witness_pin(witness_keys, roles=["corroboration", "sunset-activation"], with_pq=True)]
    )
    result = witness_policy.evaluate_activation_witness_quorum(
        mismatched,
        witness_policy=witness_policy.load_policy(witness_policy.policy_bytes(document)),
        epoch_id=BOOTSTRAP_EPOCH,
        expected_origin=ORIGIN,
        anchor_evidence=anchor["evidence"],
        anchor_policy=anchor["policy"],
        conflict_domain="issuer.example",
    )
    assert result.valid is False


def test_cosigning_leaves_the_log_signatures_verifiable(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """Appending lines must not disturb the note: the log's own hybrid pair
    still authenticates the checkpoint afterwards, byte for byte."""
    text = _checkpoint_text(log_keys, size=9)
    note = tlog.parse_checkpoint(text).note_bytes
    signature = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)
    cosigned = text + signature.lines

    log_key = tlog.LogKey(
        origin=ORIGIN, name=ORIGIN, ed25519_pub=log_keys.ed.pub, mldsa_pub=log_keys.mldsa.pub
    )
    checkpoint = tlog.verify_checkpoint(cosigned, log_key, ORIGIN)
    assert checkpoint.tree_size == 9
    assert checkpoint.note_bytes == note
    assert checkpoint.signed_note_bytes == cosigned.encode("utf-8")


def test_both_lines_parse_as_c2sp_signature_lines(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    text = _checkpoint_text(log_keys)
    note = tlog.parse_checkpoint(text).note_bytes
    signature = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)

    names = [name for name, _ in tlog.note_signatures(text + signature.lines)]
    assert names.count(WITNESS_NAME) == 2
    for line in (signature.ed25519_line, signature.mldsa_65_line):
        assert line.startswith("— "), "C2SP requires an em dash, not a hyphen"
        assert line.endswith("\n")


def test_blob_layout_is_key_id_then_big_endian_timestamp_then_signature(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """The one thing this module owns outright. Checked field by field because
    a wrong-endian or wrong-width timestamp still verifies as SOME signature —
    just not at the time anybody thinks."""
    text = _checkpoint_text(log_keys)
    note = tlog.parse_checkpoint(text).note_bytes
    signature = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)
    blobs = {name: blob for name, blob in tlog.note_signatures(text + signature.lines)}
    ed_blob = base64.b64decode(signature.ed25519_line.split(" ", 2)[2])
    pq_blob = base64.b64decode(signature.mldsa_65_line.split(" ", 2)[2])
    assert WITNESS_NAME in blobs

    assert len(ed_blob) == 4 + 8 + 64
    assert ed_blob[:4] == witness_policy.cosignature_key_id(WITNESS_NAME, witness_keys.ed.pub)
    assert struct.unpack(">Q", ed_blob[4:12])[0] == TIMESTAMP
    message = witness_policy.cosignature_message(note, TIMESTAMP)
    assert keys.verify_strict(message, ed_blob[12:], witness_keys.ed.pub)

    assert len(pq_blob) == 4 + 8 + pq.ML_DSA_65_SIG_LEN
    assert pq_blob[:4] == tlog.key_hash(
        WITNESS_NAME, witness_policy.PQ_COSIGNATURE_SIG_TYPE, witness_keys.mldsa.pub
    )
    assert struct.unpack(">Q", pq_blob[4:12])[0] == TIMESTAMP
    assert pq.verify_strict(message, pq_blob[12:], witness_keys.mldsa.pub)


def test_the_two_legs_are_domain_separated_from_the_checkpoint_legs(
    witness_keys: pq.HybridSigningKeys,
) -> None:
    """A witness cosignature and a log checkpoint signature must never be
    interchangeable (v0.2 §9.2): distinct signature types, hence distinct key
    ids for the very same public key."""
    cosignature_id = witness_policy.cosignature_key_id(WITNESS_NAME, witness_keys.ed.pub)
    checkpoint_id = tlog.key_hash(WITNESS_NAME, tlog.ED25519_SIG_TYPE, witness_keys.ed.pub)
    assert cosignature_id != checkpoint_id

    pq_cosignature_id = tlog.key_hash(
        WITNESS_NAME, witness_policy.PQ_COSIGNATURE_SIG_TYPE, witness_keys.mldsa.pub
    )
    pq_checkpoint_id = tlog.key_hash(
        WITNESS_NAME, b"\xff" + b"attest-ml-dsa-65", witness_keys.mldsa.pub
    )
    assert pq_cosignature_id != pq_checkpoint_id


def test_an_out_of_range_timestamp_is_refused_not_signed(
    witness_keys: pq.HybridSigningKeys,
) -> None:
    note = b"log.example\n4\nAAAA\n"
    with pytest.raises(CosignError):
        cosign(
            note,
            name=WITNESS_NAME,
            signing_keys=witness_keys,
            timestamp=witness_policy.MAX_COSIGNATURE_TIMESTAMP + 1,
        )


def test_cosigning_the_whole_signed_note_produces_nothing_a_verifier_counts(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """`cosign` takes the three HEADER lines, not the full signed note, and the
    difference is not cosmetic: a cosignature commits to the checkpoint, not to
    who else has signed it. Passing the whole text produces a well-formed line
    over the wrong message, which the core silently declines to count —
    exactly the kind of defect that would ship looking correct."""
    text = _checkpoint_text(log_keys)
    wrong = cosign(
        text.encode("utf-8"), name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP
    )
    verdict = _corroboration(
        text + wrong.lines, witness_policy_document([witness_pin(witness_keys)])
    )
    assert verdict.witnessed is False


@pytest.mark.parametrize("timestamp", [0, -1])
def test_a_non_positive_timestamp_is_refused_not_signed(
    witness_keys: pq.HybridSigningKeys, timestamp: int
) -> None:
    """C2SP add-checkpoint: "The cosignature MUST NOT omit the timestamp, i.e.
    the timestamp MUST NOT be zero." Zero is how the wire format spells "no
    timestamp", so a cosignature carrying it asserts something other than what
    this witness means — and the core's verifier would still accept it, which
    is what makes signing one worse than failing."""
    note = b"log.example\n4\nAAAA\n"
    with pytest.raises(CosignError):
        cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=timestamp)
