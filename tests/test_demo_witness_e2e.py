"""The log -> submission -> witness -> cosignature chain, end to end.

Covers `demo/witness_client.py` (the non-normative C2SP `add-checkpoint`
client this repository did not have) and `demo/witness_cosigns.py` (the
narrated scenario that drives it).

The cosignature oracle here is written from v0.2 s9.2 and NOT from the code
that produces a cosignature: the key id, the signed payload, the blob layout
and the line framing are re-derived from the specification's own words, and
the signatures are checked with the underlying primitives rather than through
`attest.witness`. An oracle that called `attest_witness.cosign` would agree
with a wrong implementation as readily as with a right one.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import socket
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any
from wsgiref.simple_server import make_server

import nacl.exceptions
import nacl.signing
import pytest
from attest_witness.cli import _QuietRequestHandler, _ThreadingWSGIServer
from attest_witness.config import load_config
from attest_witness.http import make_app
from attest_witness.service import WitnessService, origin_hash
from attest_witness.store import WitnessStore
from pqcrypto.sign import ml_dsa_65

from attest import keys, pq, tlog, witness
from demo import witness_client, witness_cosigns
from tools.ci_required import ci_prerequisites_required

# v0.2 s9.2, quoted: a checkpoint carries a key-id, "a 4-byte prefix
# SHA-256(name || "\n" || signature-type || pub)[:4] (C2SP's key-hash
# convention)". The Ed25519 cosignature's signature type is C2SP's `0x04`;
# the hybrid leg's is `0xff || UTF8("attest-cosignature-ml-dsa-65-v1")`.
ED25519_COSIGNATURE_TYPE = b"\x04"
MLDSA_COSIGNATURE_TYPE = b"\xff" + b"attest-cosignature-ml-dsa-65-v1"

# A note body shaped like a real one, used where only the framing matters.
SAMPLE_NOTE = (
    "log.example\n"
    "1\n"
    + base64.b64encode(bytes(range(32))).decode("ascii")
    + "\n"
    + "\n"
    + "— log.example "
    + base64.b64encode(b"x" * 76).decode("ascii")
    + "\n"
)


def test_a_submission_body_is_the_old_size_then_a_blank_line_then_the_note() -> None:
    """C2SP `add-checkpoint`: `old <decimal size>`, then zero or more base64
    consistency-proof lines, then a blank line, then the checkpoint note.
    With no proof the body is the two-line head and the note."""
    body = witness_client.build_submission(0, SAMPLE_NOTE)

    assert body == b"old 0\n\n" + SAMPLE_NOTE.encode("utf-8")


def test_a_submission_body_carries_one_padded_base64_line_per_proof_node() -> None:
    """Each consistency-proof node is its own line, standard base64 WITH
    padding (the witness bounds a proof line at 44 characters, which is a
    padded base64 SHA-256 hash and nothing else)."""
    first = bytes(range(32))
    second = bytes(range(32, 64))

    body = witness_client.build_submission(4, SAMPLE_NOTE, proof=[first, second])

    expected_head = (
        "old 4\n"
        + base64.b64encode(first).decode("ascii")
        + "\n"
        + base64.b64encode(second).decode("ascii")
        + "\n"
        + "\n"
    )
    assert body == expected_head.encode("ascii") + SAMPLE_NOTE.encode("utf-8")
    assert len(base64.b64encode(first)) == 44


def test_a_submission_refuses_a_negative_old_size() -> None:
    """A tree size has no negative decimal spelling, so a client that could
    render one would only ever be building a 400. (C2SP also forbids a
    leading zero; a Python `int` has no such spelling, so there is nothing
    here to refuse and nothing is claimed about it.)"""
    with pytest.raises(ValueError, match="old size"):
        witness_client.build_submission(-1, SAMPLE_NOTE)


def test_a_submission_refuses_a_proof_node_that_is_not_a_sha256_hash() -> None:
    """A proof line is a base64 SHA-256 hash; anything else is a 400 the
    client can see coming without a round trip."""
    with pytest.raises(ValueError, match="32 bytes"):
        witness_client.build_submission(4, SAMPLE_NOTE, proof=[b"short"])


def test_a_submission_refuses_a_boolean_as_a_tree_size() -> None:
    """`True` is an `int` in Python, so without the type guard it renders as
    `old 1`: a size nobody chose, spelled correctly enough that the witness
    would compare against it. A witness compares sizes for a living."""
    with pytest.raises(ValueError, match="old size"):
        witness_client.build_submission(True, SAMPLE_NOTE)


def test_a_submission_refuses_a_proof_node_that_is_not_bytes() -> None:
    """A 32-character `str` has the right length and is not a hash. Without
    the type half of the guard the length check admits it, and the failure
    lands inside `base64.b64encode` as a `TypeError` the caller cannot act
    on — a bound this client exists to check before the round trip."""
    with pytest.raises(ValueError, match="32 bytes"):
        witness_client.build_submission(4, SAMPLE_NOTE, proof=["x" * 32])


def test_evidence_refuses_an_epoch_that_names_nothing() -> None:
    """The trap this module's own docstring names, closed on the writing side.

    v0.2 s10.2 step 8 is normatively SILENT (s11.4): an epoch the verifier
    cannot resolve leaves `corroboration: "logged"` with no warning and no
    condition named. Measured through the real CLI: an empty string, a
    `None` and a typo all produce exit 0, `ok: true` and `"logged"` — a
    cosigned note reported as if nobody had cosigned it. Every other
    precondition of this join already refuses loudly; this one has to as
    well, because the verifier by design will not.
    """
    evidence = {"entry": {"type": "receipt"}, "checkpoint": SAMPLE_NOTE}
    merged = witness_client.cosigned_note(SAMPLE_NOTE, COSIGNATURE_LINES)

    for epoch in ("", None, 1):
        with pytest.raises(ValueError, match="witness_policy_epoch"):
            witness_client.evidence_with_cosignature(
                evidence,
                merged,
                witness_policy_epoch=epoch,
                witness_policy_bytes=WITNESS_POLICY_BYTES,
            )


# --- the note join: a cosignature is APPENDED, never substituted -------------

# A real Ed25519 keypair, used ONLY by the two tests below that must reach a
# genuine `witnessed` verdict. Closing COMP-5's R1 residual means
# `evidence_with_cosignature` now calls `witness.evaluate_corroboration` for
# real (see `_require_resolvable_epoch`): a synthetic 76-byte blob no longer
# reaches the updated evidence, it correctly raises `CosignatureNotWitnessed`
# instead — so the two tests that assert on the updated evidence need a
# cosignature the verifier's own check would actually count.
_UNIT_WITNESS_KEYS = keys.generate()
# Inside the fixed policy epoch's open window (`not_before` 2020-01-01,
# `not_after` None) and comfortably below `MAX_COSIGNATURE_TIMESTAMP`.
_UNIT_COSIGNATURE_TIMESTAMP = 1_700_000_000


def _real_cosignature_line(name: str, note_bytes: bytes, signing: keys.SigningKeyPair) -> str:
    """One genuine C2SP type-`0x04` cosignature line over `note_bytes`,
    built the way `witness.evaluate_corroboration` will check it — key ID
    via `witness.cosignature_key_id`, payload via `witness.cosignature_message`
    — never through `attest_witness.cosign`, which would agree with a wrong
    implementation as readily as a right one."""
    key_id = witness.cosignature_key_id(name, signing.pub)
    message = witness.cosignature_message(note_bytes, _UNIT_COSIGNATURE_TIMESTAMP)
    signature = keys.sign(message, signing)
    blob = key_id + _UNIT_COSIGNATURE_TIMESTAMP.to_bytes(8, "big") + signature
    return f"— {name} {base64.b64encode(blob).decode('ascii')}\n"


COSIGNATURE_LINES = _real_cosignature_line(
    witness_cosigns.WITNESS_NAME, tlog.parse_checkpoint(SAMPLE_NOTE).note_bytes, _UNIT_WITNESS_KEYS
) + ("— witness.example/w1 " + base64.b64encode(b"b" * 76).decode("ascii") + "\n")


def test_splitting_a_note_keeps_the_body_the_signatures_commit_to() -> None:
    """The body is everything up to and including the blank line — which is
    what a signature covers — and each signature is one line after it."""
    note = witness_client.split_note(SAMPLE_NOTE)

    root_line = base64.b64encode(bytes(range(32))).decode("ascii")
    assert note.body == f"log.example\n1\n{root_line}\n\n"
    assert len(note.signature_lines) == 1
    assert note.signature_lines[0].startswith("— log.example ")
    assert note.body + "".join(note.signature_lines) == SAMPLE_NOTE


def test_splitting_refuses_text_with_no_blank_line_at_all() -> None:
    with pytest.raises(ValueError, match="no blank line"):
        witness_client.split_note("log.example\n1\nroot\n")


def test_splitting_refuses_a_signature_block_that_is_not_newline_terminated() -> None:
    """Refused HERE rather than after an append: appending to a note whose
    last line has no newline runs the witness's first line into the log's
    last one, and the corruption is then inside a signature nobody re-reads."""
    with pytest.raises(ValueError, match="newline-terminated"):
        witness_client.split_note(SAMPLE_NOTE.rstrip("\n"))


def test_a_cosigned_note_is_the_original_note_plus_the_new_lines() -> None:
    """Appended, not substituted: the body the log signed is byte-identical,
    its own signature lines still come first and still say what they said,
    and the note grew by exactly the lines the witness returned."""
    merged = witness_client.cosigned_note(SAMPLE_NOTE, COSIGNATURE_LINES)

    before = witness_client.split_note(SAMPLE_NOTE)
    after = witness_client.split_note(merged)
    assert after.body == before.body
    assert after.signature_lines[: len(before.signature_lines)] == before.signature_lines
    assert len(after.signature_lines) == len(before.signature_lines) + 2
    assert after.signature_lines[1:] == tuple(COSIGNATURE_LINES.splitlines(keepends=True))


def test_a_cosigned_note_refuses_an_empty_set_of_cosignature_lines() -> None:
    """ "Cosigned" has to mean something was added. A witness that answered
    200 with an empty body would otherwise produce a note indistinguishable
    from the one nobody witnessed."""
    with pytest.raises(ValueError, match="no cosignature lines"):
        witness_client.cosigned_note(SAMPLE_NOTE, "")


def test_a_cosigned_note_refuses_cosignature_lines_that_are_not_terminated() -> None:
    with pytest.raises(ValueError, match="newline-terminated"):
        witness_client.cosigned_note(SAMPLE_NOTE, COSIGNATURE_LINES.rstrip("\n"))


# --- the evidence join: what `attest log prove` cannot write -----------------

OTHER_NOTE = SAMPLE_NOTE.replace("\n1\n", "\n2\n", 1)

# The verifier's own trusted configuration, built by the demo's own builder so
# these tests resolve epochs against the document shape the demo really writes
# — not a second copy of it. `log_origin` is SAMPLE_NOTE's, because an epoch
# that does not list a checkpoint's origin resolves to nothing for it. Pins
# `_UNIT_WITNESS_KEYS`, the SAME keypair `COSIGNATURE_LINES` signs with above
# — the pin and the cosignature have to name the same key for
# `witness.evaluate_corroboration` to ever say `witnessed`.
WITNESS_POLICY_BYTES = witness.policy_bytes(
    witness_cosigns._witness_policy_document(
        keys.b64u(_UNIT_WITNESS_KEYS.pub),
        log_origin="log.example",
    )
)


def test_evidence_is_repointed_at_the_cosigned_note_and_names_the_epoch() -> None:
    """`attest log prove` writes the note in LOG/checkpoint, which the
    witness's lines never reach, and emits no `witness_policy_epoch` — the
    member v0.2 s10.2 step 8 reads to decide which epoch pins whom. Both are
    supplied here, because a verifier missing either reports `logged` and,
    by s11.4, says nothing about why."""
    evidence = {"entry": {"type": "receipt"}, "leaf_index": 0, "checkpoint": SAMPLE_NOTE}
    merged = witness_client.cosigned_note(SAMPLE_NOTE, COSIGNATURE_LINES)

    updated = witness_client.evidence_with_cosignature(
        evidence,
        merged,
        witness_policy_epoch="bootstrap-1",
        witness_policy_bytes=WITNESS_POLICY_BYTES,
    )

    assert updated["checkpoint"] == merged
    assert updated["witness_policy_epoch"] == "bootstrap-1"
    assert updated["entry"] == {"type": "receipt"}
    assert updated["leaf_index"] == 0


def test_evidence_is_not_mutated_in_place() -> None:
    """The caller keeps the un-witnessed evidence: the demo verifies against
    both, and a verdict that differs only in the cosignature is the whole
    control. An in-place update would make the two runs the same run."""
    evidence = {"entry": {"type": "receipt"}, "checkpoint": SAMPLE_NOTE}
    merged = witness_client.cosigned_note(SAMPLE_NOTE, COSIGNATURE_LINES)

    witness_client.evidence_with_cosignature(
        evidence,
        merged,
        witness_policy_epoch="bootstrap-1",
        witness_policy_bytes=WITNESS_POLICY_BYTES,
    )

    assert evidence == {"entry": {"type": "receipt"}, "checkpoint": SAMPLE_NOTE}


def test_evidence_refuses_a_cosigned_note_for_a_different_checkpoint() -> None:
    """The one thing "add a cosignature" must never be able to mean. A note
    for another tree — or another log — carries genuine witness signatures
    over a head this evidence's inclusion proof says nothing about."""
    evidence = {"entry": {"type": "receipt"}, "checkpoint": SAMPLE_NOTE}
    foreign = witness_client.cosigned_note(OTHER_NOTE, COSIGNATURE_LINES)

    with pytest.raises(ValueError, match="different checkpoint"):
        witness_client.evidence_with_cosignature(
            evidence,
            foreign,
            witness_policy_epoch="bootstrap-1",
            witness_policy_bytes=WITNESS_POLICY_BYTES,
        )


def test_evidence_refuses_an_epoch_the_verifiers_policy_does_not_define() -> None:
    """A typo in an epoch name is well-formed, so no check of FORM can catch
    it — and v0.2 s10.2 step 8 resolves an unknown epoch to nothing in
    SILENCE (s11.4). Measured before this guard existed: `bootstrap-l` for
    `bootstrap-1` produced exit 0, `ok: true`, `corroboration: "logged"` and
    `warnings: []` — the same output as a run where no witness cosigned at
    all. The only thing that can tell the two apart is the document the
    verifier will resolve the name against, so this client resolves it there
    first and names what it found."""
    evidence = {"entry": {"type": "receipt"}, "checkpoint": SAMPLE_NOTE}
    merged = witness_client.cosigned_note(SAMPLE_NOTE, COSIGNATURE_LINES)

    with pytest.raises(witness_client.UnknownPolicyEpoch) as raised:
        witness_client.evidence_with_cosignature(
            evidence,
            merged,
            witness_policy_epoch="bootstrap-l",
            witness_policy_bytes=WITNESS_POLICY_BYTES,
        )

    message = str(raised.value)
    assert "witness_policy_epoch" in message
    assert "bootstrap-l" in message
    assert "bootstrap-1" in message


def test_evidence_refuses_an_epoch_that_does_not_cover_this_logs_origin() -> None:
    """The second condition the verifier resolves in silence: an epoch that
    resolves by name still corroborates nothing for a checkpoint whose origin
    it does not list (`witness.evaluate_corroboration`, fail-closed on
    `log_origins`). Named apart from the unknown-epoch case because the
    operator's repair is a different one — the epoch is right, its scope is
    not."""
    foreign = SAMPLE_NOTE.replace("log.example", "log.other.example")
    evidence = {"entry": {"type": "receipt"}, "checkpoint": foreign}
    merged = witness_client.cosigned_note(foreign, COSIGNATURE_LINES)

    with pytest.raises(witness_client.EpochDoesNotCoverLog) as raised:
        witness_client.evidence_with_cosignature(
            evidence,
            merged,
            witness_policy_epoch="bootstrap-1",
            witness_policy_bytes=WITNESS_POLICY_BYTES,
        )

    message = str(raised.value)
    assert "log.other.example" in message
    assert "log.example" in message


def test_evidence_refuses_a_policy_document_it_cannot_read() -> None:
    """Constraint on the redesign itself: the case where the authority cannot
    be consulted must be LOUD, not a branch that degrades to the comfortable
    outcome. A policy this client cannot parse is not a policy that resolves
    nothing — it is a different condition with a different repair, so it
    carries its own type.

    The parsed document is the third input on purpose: handing over the dict
    instead of the bytes the verifier loads is the mistake an operator
    actually makes, and left alone it surfaces as `AttributeError: \'dict\'
    object has no attribute \'decode\'` — loud, but naming nothing a caller
    can act on."""
    evidence = {"entry": {"type": "receipt"}, "checkpoint": SAMPLE_NOTE}
    merged = witness_client.cosigned_note(SAMPLE_NOTE, COSIGNATURE_LINES)

    for unreadable in (b"{}", b"not json at all", {"schema": "attest-witness-policy-v1"}, None):
        with pytest.raises(witness_client.UnreadableWitnessPolicy) as raised:
            witness_client.evidence_with_cosignature(
                evidence,
                merged,
                witness_policy_epoch="bootstrap-1",
                witness_policy_bytes=unreadable,
            )
        assert "witness_policy_bytes" in str(raised.value)


def test_the_policy_mismatches_are_one_family_and_the_unreadable_one_is_not() -> None:
    """`UnknownPolicyEpoch` and `EpochDoesNotCoverLog` are both "the authority
    does not agree with the name you gave"; an unreadable document is "the
    authority could not be consulted". A caller that cannot tell those two
    kinds apart is back to treating a configuration typo like malformed data,
    which is the confusion this redesign exists to remove."""
    assert issubclass(witness_client.UnknownPolicyEpoch, witness_client.WitnessPolicyMismatch)
    assert issubclass(witness_client.EpochDoesNotCoverLog, witness_client.WitnessPolicyMismatch)
    assert not issubclass(
        witness_client.UnreadableWitnessPolicy, witness_client.WitnessPolicyMismatch
    )
    assert issubclass(witness_client.WitnessPolicyMismatch, ValueError)
    assert issubclass(witness_client.UnreadableWitnessPolicy, ValueError)


def test_evidence_refuses_a_bundle_with_no_checkpoint_of_its_own() -> None:
    with pytest.raises(ValueError, match="no `checkpoint`"):
        witness_client.evidence_with_cosignature(
            {"entry": {}},
            SAMPLE_NOTE,
            witness_policy_epoch="bootstrap-1",
            witness_policy_bytes=WITNESS_POLICY_BYTES,
        )


# --- the client against a real socket ---------------------------------------
#
# A served witness, not the WSGI app called in-process: this module's subject
# is the join between attest and the witness, and a client that never opened a
# connection would leave the Content-Length handling, the routing and the
# status codes untested — the three things a real submission actually meets.
#
# The world here is built from scratch rather than taken from the demo, the
# same reasoning `test_demo_pledge_e2e.py` states for the custodian: if the
# demo's construction drifts, these still pin the client against a world it
# did not build.
#
# One log origin per test, and the served witness is module-scoped. A witness
# keeps state by design — the head it last cosigned — so tests sharing an
# origin would be an ordering dependency wearing a fixture's clothes: the
# refusal below is a 409 only because something was cosigned first, and that
# "first" has to belong to the test that relies on it.

WITNESS_NAME = "witness.comp5.example/w1"
SUBMISSION_PATH = "/witness/v0/add-checkpoint"
ACCEPTED_ORIGIN = "log.accepted.example"
RESYNC_ORIGIN = "log.resync.example"
MONITORED_ORIGIN = "log.monitored.example"
UNPINNED_ORIGIN = "log.nobody-configured.example"
PINNED_ORIGINS = (ACCEPTED_ORIGIN, RESYNC_ORIGIN, MONITORED_ORIGIN)


class ServedWitness:
    """A witness on a real loopback port, and the log it is pinned to.

    `checkpoint()` CACHES: ML-DSA-65 signing is randomised, so signing the
    same tree twice produces two different notes. A test that re-derived the
    note it had submitted would be comparing the witness's answer against
    bytes nobody ever sent. (Measured — that is exactly how this class came
    to memoise.)
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        log_signing_keys: pq.HybridSigningKeys,
        witness_signing_keys: pq.HybridSigningKeys,
    ) -> None:
        self.host = host
        self.port = port
        self.log_signing_keys = log_signing_keys
        self.witness_signing_keys = witness_signing_keys
        self._leaves = [f"leaf-{index}".encode() for index in range(8)]
        self._notes: dict[tuple[str, int], str] = {}

    def checkpoint(self, origin: str, size: int) -> str:
        key = (origin, size)
        if key not in self._notes:
            self._notes[key] = tlog.sign_checkpoint(
                origin,
                size,
                tlog.build_tree(self._leaves[:size]),
                self.log_signing_keys,
                origin,
            )
        return self._notes[key]


def _write_witness_config(
    directory: Path,
    *,
    witness_signing_keys: pq.HybridSigningKeys,
    log_signing_keys: pq.HybridSigningKeys,
    origins: Sequence[str],
) -> Path:
    seed_path = directory / "witness.seed"
    seed_path.write_text(keys.b64u(witness_signing_keys.ed.seed), encoding="utf-8")
    mldsa_path = directory / "witness-mldsa65.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(witness_signing_keys.mldsa.sk),
                "pub": keys.b64u(witness_signing_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    lines = [
        "[witness]",
        f'name = "{WITNESS_NAME}"',
        f'seed_path = "{seed_path}"',
        f'mldsa_key_path = "{mldsa_path}"',
        "",
        "[storage]",
        f'database_path = "{directory / "state.sqlite3"}"',
        "",
        "[server]",
        'submission_prefix = "/witness/v0"',
        'monitoring_prefix = "/witness/v0/monitoring"',
        "",
    ]
    for origin in origins:
        lines += [
            "[[log]]",
            f'origin = "{origin}"',
            f'name = "{origin}"',
            f'ed25519_pub_b64u = "{keys.b64u(log_signing_keys.ed.pub)}"',
            f'mldsa_65_pub_b64u = "{keys.b64u(log_signing_keys.mldsa.pub)}"',
            "",
        ]
    config_path = directory / "witness.toml"
    config_path.write_text("\n".join(lines), encoding="utf-8")
    return config_path


@pytest.fixture(scope="module")
def served(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ServedWitness]:
    """One witness on a real loopback port for this module.

    Module-scoped because ML-DSA-65 key generation is the slowest thing here
    by an order of magnitude, and every test below wants the same witness.
    """
    directory = tmp_path_factory.mktemp("served-witness")
    log_signing = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    witness_signing = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    config = load_config(
        _write_witness_config(
            directory,
            witness_signing_keys=witness_signing,
            log_signing_keys=log_signing,
            origins=PINNED_ORIGINS,
        )
    )
    store = WitnessStore(config.database_path)
    app = make_app(WitnessService(config, store), config)
    try:
        httpd = make_server(
            "127.0.0.1",
            0,
            app,
            server_class=_ThreadingWSGIServer,
            handler_class=_QuietRequestHandler,
        )
    except PermissionError:  # pragma: no cover - depends on the runner
        store.close()
        reason = "binding a loopback socket is not permitted for this process"
        # Same contract the witness suite states for its own socket test: where
        # a job promised the environment, an absent prerequisite is that job's
        # defect, not a reason to step aside.
        if ci_prerequisites_required():
            pytest.fail(f"{reason}; the required CI gate cannot run")
        pytest.skip(reason)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield ServedWitness(
            host="127.0.0.1",
            port=int(httpd.server_address[1]),
            log_signing_keys=log_signing,
            witness_signing_keys=witness_signing,
        )
    finally:
        httpd.shutdown()
        thread.join(timeout=10)
        httpd.server_close()
        store.close()


def test_submitting_a_checkpoint_returns_the_cosignature_lines(served: ServedWitness) -> None:
    """The 200 body is the witness's signature lines and nothing else: two of
    them, both naming this witness, both newline-terminated so the client can
    append them to the note without repairing anything."""
    note = served.checkpoint(ACCEPTED_ORIGIN, 4)

    lines = witness_client.submit(
        served.host, served.port, SUBMISSION_PATH, witness_client.build_submission(0, note)
    )

    parsed = lines.splitlines(keepends=True)
    assert len(parsed) == 2
    assert all(line.startswith(f"— {WITNESS_NAME} ") for line in parsed)
    assert all(line.endswith("\n") for line in parsed)
    # And the join this client exists for accepts them without complaint.
    assert witness_client.cosigned_note(note, lines) == note + lines


def test_a_submission_for_an_unknown_log_is_refused_with_404(served: ServedWitness) -> None:
    """The allowlist is the whole of what a witness trusts. An origin absent
    from it is refused before any key is used or any state is read."""
    stranger = served.checkpoint(UNPINNED_ORIGIN, 4)

    with pytest.raises(witness_client.WitnessRefused) as raised:
        witness_client.submit(
            served.host, served.port, SUBMISSION_PATH, witness_client.build_submission(0, stranger)
        )

    assert raised.value.status == 404


def test_a_stale_old_size_is_refused_with_409_carrying_the_size_held(
    served: ServedWitness,
) -> None:
    """C2SP's resynchronisation answer. The head is cosigned here, in this
    test, so the refusal that follows is this test's own doing: `old 0` no
    longer describes the witness's state, and the body of the 409 is the size
    it does hold — enough to retry correctly without a second round trip."""
    witness_client.submit(
        served.host,
        served.port,
        SUBMISSION_PATH,
        witness_client.build_submission(0, served.checkpoint(RESYNC_ORIGIN, 4)),
    )

    with pytest.raises(witness_client.WitnessRefused) as raised:
        witness_client.submit(
            served.host,
            served.port,
            SUBMISSION_PATH,
            witness_client.build_submission(0, served.checkpoint(RESYNC_ORIGIN, 6)),
        )

    assert raised.value.status == 409
    assert raised.value.body.strip() == "4"


def test_the_monitoring_endpoint_serves_the_note_with_the_lines_appended(
    served: ServedWitness,
) -> None:
    """What anybody can fetch afterwards is the cosigned note itself — the
    head this witness observed, byte-identical, with its own lines on it."""
    note = served.checkpoint(MONITORED_ORIGIN, 4)
    lines = witness_client.submit(
        served.host, served.port, SUBMISSION_PATH, witness_client.build_submission(0, note)
    )
    path = f"/witness/v0/monitoring/{origin_hash(MONITORED_ORIGIN)}/checkpoint"

    served_note = witness_client.fetch_monitored(served.host, served.port, path)

    assert served_note == note + lines


# --- the scenario, end to end -----------------------------------------------


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict[str, Any], str]:
    """One run of the whole scenario, and its narration.

    Module-scoped: the run generates two ML-DSA-65 key pairs, signs a
    checkpoint with one and cosigns it with the other, and every assertion
    below is about the same run. Stdout is captured here rather than with
    `capsys`, which is function-scoped and cannot see a module fixture's run.
    """
    output = io.StringIO()
    # Both streams into one buffer: the narration is on stdout, and anything
    # the served witness writes about its own requests would come out on
    # stderr — which is exactly what the last test below asserts is absent.
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        outcomes = witness_cosigns.run_demo(tmp_path_factory.mktemp("witness-demo"))
    return outcomes, output.getvalue()


def _parse_signature_line(line: str) -> tuple[str, bytes]:
    """One C2SP signed-note signature line, per v0.2 s9.1's grammar: em dash
    U+2014, a space, the key name, a space, standard base64 WITH padding.

    Written out here rather than taken from `attest.tlog`: this module's
    oracle has to be able to disagree with the implementation it is judging.
    """
    prefix = "— "
    assert line.startswith(prefix), line
    name, space, encoded = line[len(prefix) :].partition(" ")
    assert space, line
    return name, base64.b64decode(encoded, validate=True)


def _spec_key_id(name: str, signature_type: bytes, pub: bytes) -> bytes:
    """v0.2 s9.2: `SHA-256(name || "\\n" || signature-type || pub)[:4]`."""
    return hashlib.sha256(name.encode("utf-8") + b"\n" + signature_type + pub).digest()[:4]


def _spec_cosignature_payload(note_bytes: bytes, timestamp: int) -> bytes:
    """v0.2 s9.2, quoted: both legs sign the byte-identical payload
    `UTF8("cosignature/v1\\n") || UTF8("time " + decimal_timestamp + "\\n")
    || checkpoint.note_bytes`."""
    return b"cosignature/v1\n" + f"time {timestamp}\n".encode() + note_bytes


def _spec_note_bytes(checkpoint_text: str) -> bytes:
    """The bytes a note signature covers: the header lines up to the blank
    line, INCLUDING the newline that ends the last of them. Derived from
    C2SP's note grammar — the blank line is the separator, not part of what
    is signed."""
    header, separator, _ = checkpoint_text.partition("\n\n")
    assert separator, checkpoint_text
    return header.encode("utf-8") + b"\n"


def test_the_witness_lines_are_a_cosignature_by_the_specifications_own_words(
    demo: tuple[dict[str, Any], str],
) -> None:
    """The oracle here re-derives the key id, the payload and the blob layout
    from v0.2 s9.2 and checks the signatures with the raw primitives. It
    never calls `attest.witness` or `attest_witness.cosign`: an oracle built
    from the producer agrees with a wrong producer as readily as a right one.
    """
    outcomes, _ = demo
    note_bytes = _spec_note_bytes(outcomes["checkpoint"])
    ed_pub = keys.b64u_decode(outcomes["witness"]["ed25519_pub_b64u"])
    mldsa_pub = keys.b64u_decode(outcomes["witness"]["mldsa_65_pub_b64u"])
    lines = outcomes["cosignature_lines"].splitlines()
    assert len(lines) == 2

    ed_name, ed_blob = _parse_signature_line(lines[0])
    pq_name, pq_blob = _parse_signature_line(lines[1])
    assert ed_name == pq_name == outcomes["witness"]["name"]

    # Blob layout: 4-byte key id, 8-byte big-endian POSIX time, signature.
    ed_timestamp = int.from_bytes(ed_blob[4:12], "big")
    ed_signature = ed_blob[12:]
    pq_timestamp = int.from_bytes(pq_blob[4:12], "big")
    pq_signature = pq_blob[12:]

    assert ed_blob[:4] == _spec_key_id(ed_name, ED25519_COSIGNATURE_TYPE, ed_pub)
    assert pq_blob[:4] == _spec_key_id(pq_name, MLDSA_COSIGNATURE_TYPE, mldsa_pub)
    assert len(ed_signature) == 64
    assert len(pq_signature) == 3309
    # C2SP: "the timestamp MUST NOT be zero" — zero is how the format spells
    # "no timestamp at all".
    assert ed_timestamp > 0
    # s11.4 counts a hybrid vote only when both legs cover the same payload
    # AND the same timestamp; two legs a second apart are two unrelated
    # signatures that a quorum silently declines to count.
    assert ed_timestamp == pq_timestamp

    payload = _spec_cosignature_payload(note_bytes, ed_timestamp)
    nacl.signing.VerifyKey(ed_pub).verify(payload, ed_signature)
    assert ml_dsa_65.verify(mldsa_pub, payload, pq_signature)


def test_the_oracle_above_rejects_the_payload_it_is_supposed_to_reject(
    demo: tuple[dict[str, Any], str],
) -> None:
    """The other half of judging an oracle: feed it what must NOT satisfy it.

    Same lines, same keys, one different timestamp in the payload. If this
    still verified, the test above would be pinning nothing — it would pass
    for any 76-byte blob carrying a signature over anything at all.
    """
    outcomes, _ = demo
    note_bytes = _spec_note_bytes(outcomes["checkpoint"])
    ed_pub = keys.b64u_decode(outcomes["witness"]["ed25519_pub_b64u"])
    _, ed_blob = _parse_signature_line(outcomes["cosignature_lines"].splitlines()[0])
    timestamp = int.from_bytes(ed_blob[4:12], "big")

    wrong_time = _spec_cosignature_payload(note_bytes, timestamp + 1)
    with pytest.raises(nacl.exceptions.BadSignatureError):
        nacl.signing.VerifyKey(ed_pub).verify(wrong_time, ed_blob[12:])

    # And a payload without the domain separator: a signature made over the
    # checkpoint body alone must not pass as a cosignature (v0.2 s9.2).
    with pytest.raises(nacl.exceptions.BadSignatureError):
        nacl.signing.VerifyKey(ed_pub).verify(note_bytes, ed_blob[12:])


def test_the_cosignature_raises_corroboration_to_witnessed(
    demo: tuple[dict[str, Any], str],
) -> None:
    """The verdict the whole chain exists to produce, through the real CLI."""
    outcomes, _ = demo
    result = outcomes["verify_witnessed"]

    assert outcomes["verify_witnessed_exit_code"] == 0
    assert result["ok"] is True
    assert result["transparency"] == "logged"
    assert result["corroboration"] == "witnessed"
    # s10.1: EVERY witnessed verdict carries this. One witness is one
    # observer, and nothing here establishes that it is independent of the
    # log — the demo runs both.
    assert "witness_independence_not_established" in result["warnings"]


def test_the_same_evidence_without_the_lines_is_only_logged(
    demo: tuple[dict[str, Any], str],
) -> None:
    """The control that makes the verdict above mean something.

    Same receipt, same log keys, same witness policy, same inclusion proof —
    the two evidence bundles differ in the cosignature lines and in the epoch
    member, and nowhere else. The note BODY is byte-identical, so `witnessed`
    cannot have come from a different checkpoint being verified.
    """
    outcomes, _ = demo
    result = outcomes["verify_unwitnessed"]

    assert outcomes["verify_unwitnessed_exit_code"] == 0
    assert result["ok"] is True
    assert result["transparency"] == "logged"
    assert result["corroboration"] == "logged"
    assert "witness_independence_not_established" not in result["warnings"]

    assert outcomes["cosigned_checkpoint"].startswith(outcomes["checkpoint"])
    assert _spec_note_bytes(outcomes["cosigned_checkpoint"]) == _spec_note_bytes(
        outcomes["checkpoint"]
    )


def test_the_witness_refuses_a_fork_of_the_head_it_already_cosigned(
    demo: tuple[dict[str, Any], str],
) -> None:
    """Why a cosignature is worth anything at all.

    The fork is signed with the log's OWN keys over a different tree of the
    same size — a genuine signature over dishonest contents, which is exactly
    the adversary a witness faces, because the log holds its own keys. C2SP
    assigns 422: well formed, not processable, the consistency proof (here
    the degenerate n-to-n one) does not verify.
    """
    outcomes, _ = demo

    assert outcomes["fork_refusal_status"] == 422
    # WHICH 422: C2SP gives that status to three conditions, and only one of
    # them is the consistency check this fork is meant to trip. Asserting the
    # status alone would accept a refusal for a malformed size-0 root just as
    # readily. (Pinned, not mutation-proved: from the state this demo reaches
    # — a size-1 head already cosigned — the other two are unreachable.)
    assert "consistency proof does not verify" in outcomes["fork_refusal_body"]
    # And the refusal left no trace on what the witness will vouch for.
    assert outcomes["monitored_checkpoint"] == outcomes["cosigned_checkpoint"]
    assert outcomes["monitored_after_fork"] == outcomes["cosigned_checkpoint"]


def test_the_narration_names_every_step_it_claims_to_run(
    demo: tuple[dict[str, Any], str],
) -> None:
    _, narration = demo

    for step in range(1, 10):
        assert f"Step {step}" in narration


def test_the_demo_leaves_no_witness_listening(demo: tuple[dict[str, Any], str]) -> None:
    """What it turned on, it turned off. The witness was a real server on a
    real port; after `run_demo` returns, nothing is answering there."""
    outcomes, _ = demo

    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", outcomes["witness"]["port"]), timeout=2):
            pass


def test_run_demo_touches_nothing_outside_its_own_workspace(tmp_path: Path) -> None:
    """A second, independent run: a sibling canary directory proves the demo
    writes only inside the workspace it was handed."""
    canary_dir = tmp_path.parent / f"{tmp_path.name}-canary"
    canary_dir.mkdir()
    canary_file = canary_dir / "must-survive.txt"
    canary_file.write_text("untouched", encoding="utf-8")
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            outcomes = witness_cosigns.run_demo(tmp_path)
        assert canary_file.read_text(encoding="utf-8") == "untouched"
        assert outcomes["verify_witnessed"]["corroboration"] == "witnessed"
    finally:
        canary_file.unlink()
        canary_dir.rmdir()


def test_the_narration_is_not_buried_under_the_servers_access_log(
    demo: tuple[dict[str, Any], str],
) -> None:
    """A demo is read, so what it prints is part of what it delivers.

    `attest-witness serve` uses a request handler that logs no access lines —
    it resolves no client address and echoes no client-controlled request
    line. A demo server that skipped that handler would not be the server the
    command runs, and would spray HTTP logs through its own narration from a
    second thread, mid-sentence.
    """
    _, output = demo

    assert "POST /witness/v0/add-checkpoint HTTP/1.1" not in output
    assert "GET /witness/v0/monitoring" not in output


def test_the_two_steps_with_no_cli_output_still_report_their_outcome(
    demo: tuple[dict[str, Any], str],
) -> None:
    """Steps 6 and 9 are the ones this demo exists for, and they are the two
    that drive no `attest` verb — so without a line of their own a reader
    watching it run sees a heading and then nothing. The facts are pinned
    here, not the prose: who cosigned, and what the fork was refused with.
    """
    outcomes, output = demo

    assert outcomes["witness"]["name"] in output
    assert str(outcomes["fork_refusal_status"]) in output


def test_the_two_evidence_bundles_differ_in_the_cosignature_and_nowhere_else(
    demo: tuple[dict[str, Any], str],
) -> None:
    """What makes the control above a control.

    Both bundles name the epoch; both carry the same entry, leaf index, tree
    size and inclusion proof. If the un-witnessed one were also missing
    `witness_policy_epoch`, its `"logged"` verdict would have two possible
    causes and would prove neither — v0.2 §10.2 step 8 is normatively silent,
    so a missing member and a witness that did not count look identical.
    """
    outcomes, _ = demo
    without = outcomes["evidence_unwitnessed"]
    with_lines = outcomes["evidence_witnessed"]

    differing = {
        key for key in set(without) | set(with_lines) if without.get(key) != with_lines.get(key)
    }
    assert differing == {"checkpoint"}
    assert without["witness_policy_epoch"] == with_lines["witness_policy_epoch"]


def _doctored(outcomes: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """A copy of a REAL run's outcomes with one recorded verdict changed.

    Built from a real run rather than written by hand: a fabricated outcomes
    dict would drift from the one `main` actually reads, and would then pin
    the fabrication instead of the conjunction. Copied, never mutated in
    place — the run is a module-scoped fixture every test below shares.
    """
    doctored: dict[str, Any] = {
        key: dict(value) if isinstance(value, dict) else value for key, value in outcomes.items()
    }
    doctored.update(changes)
    return doctored


def test_the_entry_point_returns_zero_for_the_run_it_just_made(
    demo: tuple[dict[str, Any], str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`main` is what `ci.yml` and the G-CI-PY gate read: their entire verdict
    on this demo is its exit code."""
    outcomes, _ = demo
    monkeypatch.setattr(witness_cosigns, "run_demo", lambda _workspace: _doctored(outcomes))

    assert witness_cosigns.main() == 0
    capsys.readouterr()


def test_the_entry_point_returns_one_when_the_cosignature_did_not_count(
    demo: tuple[dict[str, Any], str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The clause carrying the demo's whole claim, checked by making it false.

    A zero-exit assertion alone cannot see this: `main`'s conjunction gutted
    to `ok = True` still returns 0. Measured on this tree — with the whole
    conjunction replaced by a constant, the suite stayed 29/29 green, so the
    exit code CI trusts rested on something no test exercised.
    """
    outcomes, _ = demo
    degraded = _doctored(
        outcomes,
        verify_witnessed=dict(outcomes["verify_witnessed"], corroboration="logged"),
    )
    monkeypatch.setattr(witness_cosigns, "run_demo", lambda _workspace: degraded)

    assert witness_cosigns.main() == 1
    capsys.readouterr()


def test_the_entry_point_returns_one_when_the_witness_cosigned_a_fork(
    demo: tuple[dict[str, Any], str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Step 9's clause. A witness that cosigned the fork is the one failure
    this demo exists to rule out, so the entry point must not report success
    for a run in which it happened."""
    outcomes, _ = demo
    monkeypatch.setattr(
        witness_cosigns, "run_demo", lambda _workspace: _doctored(outcomes, fork_refusal_status=200)
    )

    assert witness_cosigns.main() == 1
    capsys.readouterr()
