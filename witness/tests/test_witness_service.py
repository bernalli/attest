"""The C2SP tlog-witness protocol, exercised against a real log.

The log in these tests is real in every way that matters: genuine hybrid keys,
genuine RFC 6962 trees, genuine consistency proofs from the core. Nothing is
mocked, because everything worth testing here is whether the CORE accepts what
the service did — and a mock would answer that question with our own opinion.

Two properties get more attention than the rest, because they are the ones a
witness exists to provide:

- An invalid submission never signs and never advances state. Every refusal
  path asserts the state afterwards, not just the status.
- The witness will not cosign two different checkpoints at one tree size, and
  will not go backwards.
"""

from __future__ import annotations

import base64
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from attest_witness.config import ServerConfig, WitnessConfig, WitnessIdentity
from attest_witness.service import (
    BadRequest,
    Conflict,
    InconsistentProof,
    UnknownOrigin,
    UntrustedCheckpoint,
    WitnessService,
    origin_hash,
    parse_submission,
)
from attest_witness.store import WitnessStore
from witness_support import (
    BOOTSTRAP_EPOCH,
    WITNESS_NAME,
    FakeLog,
    log_keys,  # noqa: F401
    other_log_keys,  # noqa: F401
    witness_keys,  # noqa: F401
    witness_pin,
    witness_policy_document,
)

from attest import pq, tlog
from attest import witness as witness_policy

ORIGIN = "log.example"
TIMESTAMP = 1_700_000_000


def _config(
    tmp_path: Path,
    witness_signing_keys: pq.HybridSigningKeys,
    logs: dict[str, tlog.LogKey],
) -> WitnessConfig:
    return WitnessConfig(
        identity=WitnessIdentity(name=WITNESS_NAME, signing_keys=witness_signing_keys),
        server=ServerConfig(
            submission_prefix="/witness/v0",
            monitoring_prefix="/witness/v0/monitoring",
            max_request_bytes=262_144,
            max_proof_lines=63,
        ),
        database_path=tmp_path / "state.sqlite3",
        logs=logs,
    )


@pytest.fixture
def log(log_keys: pq.HybridSigningKeys) -> FakeLog:
    return FakeLog(ORIGIN, log_keys)


@pytest.fixture
def service(tmp_path: Path, witness_keys: pq.HybridSigningKeys, log: FakeLog) -> WitnessService:
    config = _config(tmp_path, witness_keys, {ORIGIN: log.log_key})
    return WitnessService(
        config, WitnessStore(config.database_path), clock=lambda: float(TIMESTAMP)
    )


def _body(old_size: int, proof: list[bytes], checkpoint_text: str) -> bytes:
    lines = [f"old {old_size}"]
    lines.extend(base64.b64encode(node).decode("ascii") for node in proof)
    return ("\n".join(lines) + "\n\n" + checkpoint_text).encode("utf-8")


# --- parsing ----------------------------------------------------------------


def test_a_body_without_a_blank_separator_is_refused() -> None:
    with pytest.raises(BadRequest, match="blank line"):
        parse_submission(b"old 0\nsome-checkpoint\n", max_proof_lines=63)


def test_a_body_without_an_old_line_is_refused() -> None:
    with pytest.raises(BadRequest, match="old <size>"):
        parse_submission(b"7\n\ncheckpoint\n", max_proof_lines=63)


@pytest.mark.parametrize("digits", ["+1", " 1", "1 ", "0x4", "١٢", "1_0", "-1", ""])
def test_a_non_decimal_old_size_is_refused(digits: str) -> None:
    """`int()` would accept most of these. The protocol says decimal, and a
    witness that accepts a size a client did not write is comparing against
    something nobody agreed to."""
    with pytest.raises(BadRequest):
        parse_submission(f"old {digits}\n\ncheckpoint\n".encode(), max_proof_lines=63)


def test_more_proof_lines_than_the_bound_are_refused() -> None:
    proof = "\n".join(base64.b64encode(bytes(32)).decode("ascii") for _ in range(64))
    with pytest.raises(BadRequest, match="proof lines"):
        parse_submission(f"old 1\n{proof}\n\ncheckpoint\n".encode(), max_proof_lines=63)


def test_the_bound_on_proof_lines_is_configurable_downwards() -> None:
    proof = "\n".join(base64.b64encode(bytes(32)).decode("ascii") for _ in range(4))
    with pytest.raises(BadRequest, match="proof lines"):
        parse_submission(f"old 1\n{proof}\n\ncheckpoint\n".encode(), max_proof_lines=3)


def test_a_proof_line_that_is_not_a_sha256_hash_is_refused() -> None:
    short = base64.b64encode(bytes(16)).decode("ascii")
    with pytest.raises(BadRequest, match="base64"):
        parse_submission(f"old 1\n{short}\n\ncheckpoint\n".encode(), max_proof_lines=63)


def test_an_overlong_proof_line_is_refused_before_decoding() -> None:
    with pytest.raises(BadRequest, match="too long"):
        parse_submission(b"old 1\n" + b"A" * 5000 + b"\n\ncheckpoint\n", max_proof_lines=63)


def test_a_non_utf8_body_is_refused() -> None:
    with pytest.raises(BadRequest, match="UTF-8"):
        parse_submission(b"old 0\n\n\xff\xfe", max_proof_lines=63)


def test_a_body_with_no_checkpoint_is_refused() -> None:
    with pytest.raises(BadRequest, match="no checkpoint"):
        parse_submission(b"old 0\n\n", max_proof_lines=63)


def test_a_well_formed_body_parses(log: FakeLog) -> None:
    log.append(4)
    # Signed once and reused: ML-DSA-65 signing is randomised, so two calls to
    # `checkpoint_text()` produce two different texts for the same checkpoint.
    text = log.checkpoint_text()
    submission = parse_submission(_body(0, [], text), max_proof_lines=63)
    assert submission.old_size == 0
    assert submission.proof == ()
    assert submission.checkpoint_text == text


# --- the happy paths --------------------------------------------------------


def test_a_first_submission_is_cosigned(service: WitnessService, log: FakeLog) -> None:
    log.append(4)
    lines = service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    assert lines.count("\n") == 2, "one Ed25519 line and one ML-DSA-65 line"


def test_the_returned_lines_make_the_checkpoint_witnessed(
    service: WitnessService, log: FakeLog, witness_keys: pq.HybridSigningKeys
) -> None:
    """End to end, judged by the core: this is the entire point of the
    service, and nothing short of the core's own verdict proves it."""
    log.append(4)
    text = log.checkpoint_text()
    lines = service.add_checkpoint(_body(0, [], text))

    document = witness_policy_document([witness_pin(witness_keys)], log_origins=[ORIGIN])
    verdict = witness_policy.evaluate_corroboration(
        checkpoint=tlog.parse_checkpoint(text + lines),
        signatures=tlog.note_signatures(text + lines),
        policy=witness_policy.load_policy(witness_policy.policy_bytes(document)),
        epoch_id=BOOTSTRAP_EPOCH,
    )
    assert verdict.witnessed is True


def test_genuine_growth_with_a_real_consistency_proof_advances_state(
    service: WitnessService, log: FakeLog
) -> None:
    log.append(4)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    log.append(3)
    service.add_checkpoint(_body(4, log.consistency_proof_from(4), log.checkpoint_text()))

    stored = service._store.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 7


def test_an_empty_tree_checkpoint_is_accepted_with_the_empty_tree_root(
    service: WitnessService, log: FakeLog
) -> None:
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    stored = service._store.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 0


def test_an_empty_tree_with_a_fabricated_root_is_refused(
    service: WitnessService, log: FakeLog
) -> None:
    """Size 0 fixes the root: RFC 6962 says it is SHA-256 of nothing. A
    witness that cosigned any other root at size 0 would let a log start its
    history from a value of its choosing."""
    text = log.checkpoint_text(root=b"\x11" * 32, tree_size=0)
    with pytest.raises(BadRequest, match="empty-tree root"):
        service.add_checkpoint(_body(0, [], text))
    assert service._store.latest(ORIGIN) is None


def test_resubmitting_the_same_checkpoint_re_cosigns_without_advancing(
    service: WitnessService, log: FakeLog
) -> None:
    """The client lost our response and asked again — a normal event, not an
    attack. It gets a fresh cosignature over the same head."""
    log.append(4)
    first = service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    # A DIFFERENT text for the same checkpoint: ML-DSA-65 signing is
    # randomised, so the log re-signing its own head produces different bytes
    # for identical contents. Identity is the note's three header lines, which
    # is why the witness compares those and not the text.
    second = service.add_checkpoint(_body(4, [], log.checkpoint_text()))
    assert first != second, "each cosignature is freshly signed"
    stored = service._store.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 4


# --- the refusals -----------------------------------------------------------


def test_an_unknown_origin_is_refused_before_state_is_touched(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, other_log_keys: pq.HybridSigningKeys
) -> None:
    """v0.2 §11.4 in one test: an origin nobody pinned gets no work done for
    it at all."""
    stranger = FakeLog("stranger.example", other_log_keys)
    stranger.append(4)
    config = _config(tmp_path, witness_keys, {ORIGIN: stranger.log_key})
    service = WitnessService(
        config, WitnessStore(config.database_path), clock=lambda: float(TIMESTAMP)
    )
    with pytest.raises(UnknownOrigin):
        service.add_checkpoint(_body(0, [], stranger.checkpoint_text()))
    assert service._store.latest("stranger.example") is None
    assert service._store.latest(ORIGIN) is None


def test_a_checkpoint_signed_by_the_wrong_key_is_refused(
    service: WitnessService, other_log_keys: pq.HybridSigningKeys
) -> None:
    impostor = FakeLog(ORIGIN, other_log_keys)
    impostor.append(4)
    with pytest.raises(UntrustedCheckpoint):
        service.add_checkpoint(_body(0, [], impostor.checkpoint_text()))
    assert service._store.latest(ORIGIN) is None


def test_an_ed25519_only_checkpoint_is_refused(service: WitnessService, log: FakeLog) -> None:
    """Checkpoint authentication is the hybrid AND of v0.2 §9.3. A note whose
    ML-DSA-65 line has been stripped is not half-authentic; it is
    unauthenticated."""
    log.append(4)
    text = log.checkpoint_text()
    lines = [line for line in text.splitlines(keepends=True)]
    stripped = "".join(lines[:-1])
    with pytest.raises(UntrustedCheckpoint):
        service.add_checkpoint(_body(0, [], stripped))
    assert service._store.latest(ORIGIN) is None


def test_an_old_size_larger_than_the_checkpoint_is_refused(
    service: WitnessService, log: FakeLog
) -> None:
    log.append(4)
    with pytest.raises(BadRequest, match="old size exceeds"):
        service.add_checkpoint(_body(9, [], log.checkpoint_text()))


def test_an_old_size_that_disagrees_with_stored_state_conflicts(
    service: WitnessService, log: FakeLog
) -> None:
    log.append(4)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    log.append(3)
    with pytest.raises(Conflict) as excinfo:
        service.add_checkpoint(_body(2, log.consistency_proof_from(4), log.checkpoint_text()))
    assert excinfo.value.stored_size == 4, "a client must be able to resynchronise from this"


def test_a_rollback_is_refused_and_changes_nothing(service: WitnessService, log: FakeLog) -> None:
    log.append(7)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    older = log.checkpoint_text(tree_size=4, root=log.root_at(4))
    with pytest.raises(Conflict) as excinfo:
        service.add_checkpoint(_body(0, [], older))
    assert excinfo.value.stored_size == 7
    stored = service._store.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 7


def test_two_different_checkpoints_at_one_size_conflict(
    service: WitnessService, log: FakeLog
) -> None:
    """Equivocation, seen from the witness's side: same size, different root.
    It has already spoken for one of them."""
    log.append(4)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    forked = log.checkpoint_text(tree_size=4, root=b"\x42" * 32)
    with pytest.raises(Conflict):
        service.add_checkpoint(_body(4, [], forked))
    stored = service._store.latest(ORIGIN)
    assert stored is not None and stored.root == log.root_at(4)


def test_an_invalid_consistency_proof_is_refused(service: WitnessService, log: FakeLog) -> None:
    log.append(4)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    log.append(3)
    with pytest.raises(InconsistentProof):
        service.add_checkpoint(_body(4, [bytes(32)], log.checkpoint_text()))
    stored = service._store.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 4, "a bad proof advanced nothing"


def test_a_missing_consistency_proof_is_refused(service: WitnessService, log: FakeLog) -> None:
    log.append(4)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))
    log.append(3)
    with pytest.raises(InconsistentProof):
        service.add_checkpoint(_body(4, [], log.checkpoint_text()))


def test_a_proof_on_a_first_submission_is_refused(service: WitnessService, log: FakeLog) -> None:
    """There is nothing to be consistent with yet, so a proof is not a proof
    of anything."""
    log.append(4)
    with pytest.raises(BadRequest, match="no prior state"):
        service.add_checkpoint(_body(0, [bytes(32)], log.checkpoint_text()))


# --- monitoring -------------------------------------------------------------


def test_monitoring_returns_the_cosigned_note(service: WitnessService, log: FakeLog) -> None:
    log.append(4)
    text = log.checkpoint_text()
    lines = service.add_checkpoint(_body(0, [], text))
    served = service.monitoring(origin_hash(ORIGIN))
    assert served == text + lines, "monitoring serves the note as submitted, plus our lines"


def test_monitoring_is_404_for_an_unknown_origin(service: WitnessService) -> None:
    with pytest.raises(UnknownOrigin):
        service.monitoring(origin_hash("nobody.example"))


def test_monitoring_is_404_before_anything_is_cosigned(service: WitnessService) -> None:
    with pytest.raises(UnknownOrigin):
        service.monitoring(origin_hash(ORIGIN))


def test_monitoring_does_not_leak_the_origin_of_an_unknown_hash(
    service: WitnessService,
) -> None:
    """The path segment is a hash, and the refusal says nothing more than
    'unknown' — the same words for a hash of nothing and a hash of a log this
    witness was never told about."""
    with pytest.raises(UnknownOrigin) as unknown:
        service.monitoring("00" * 32)
    with pytest.raises(UnknownOrigin) as never_pinned:
        service.monitoring(origin_hash("secret-log.example"))
    assert str(unknown.value) == str(never_pinned.value)


# --- concurrency and durability --------------------------------------------


def test_concurrent_submissions_cosign_exactly_one_head(
    service: WitnessService, log: FakeLog
) -> None:
    """Two clients race with two genuinely different next heads. Exactly one
    is cosigned; the other is told what we hold."""
    log.append(4)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))

    forks = []
    for marker in (b"\x01", b"\x02"):
        branch = log.fork(4)
        branch.append(1, filler=marker)
        forks.append(branch)

    outcomes: list[str] = []
    barrier = threading.Barrier(2, timeout=10)

    def submit(branch: FakeLog) -> None:
        body = _body(4, branch.consistency_proof_from(4), branch.checkpoint_text())
        barrier.wait()
        try:
            service.add_checkpoint(body)
            outcomes.append("cosigned")
        except Conflict:
            outcomes.append("conflict")
        except Exception as exc:  # a third outcome would be the bug
            outcomes.append(type(exc).__name__)

    threads = [threading.Thread(target=submit, args=(branch,)) for branch in forks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert sorted(outcomes) == ["conflict", "cosigned"], outcomes
    stored = service._store.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 5


def test_state_is_committed_before_the_cosignature_is_returned(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log: FakeLog
) -> None:
    """Instrumented at the only moment that can distinguish the two orders:
    the clock is read while the transaction is open, so reading the database
    from an INDEPENDENT connection at that instant shows whether the write has
    landed. It must not have — and it must have by the time the call returns.

    Signing before committing would pass every other test in this file and
    still leave a cosignature in the world for a head the witness could forget
    on the next power cut.
    """
    config = _config(tmp_path, witness_keys, {ORIGIN: log.log_key})
    store = WitnessStore(config.database_path)
    log.append(4)

    seen_during_signing: list[int | None] = []

    def clock_that_peeks() -> float:
        outside = WitnessStore(config.database_path)
        stored = outside.latest(ORIGIN)
        outside.close()
        seen_during_signing.append(None if stored is None else stored.tree_size)
        return float(TIMESTAMP)

    service = WitnessService(config, store, clock=clock_that_peeks)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))

    assert seen_during_signing == [None], "the write was visible before the commit returned"
    after = store.latest(ORIGIN)
    assert after is not None and after.tree_size == 4


def test_a_restarted_witness_still_refuses_a_fork(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log: FakeLog
) -> None:
    config = _config(tmp_path, witness_keys, {ORIGIN: log.log_key})
    log.append(4)
    first = WitnessService(
        config, WitnessStore(config.database_path), clock=lambda: float(TIMESTAMP)
    )
    first.add_checkpoint(_body(0, [], log.checkpoint_text()))
    first._store.close()

    revived = WitnessService(
        config, WitnessStore(config.database_path), clock=lambda: float(TIMESTAMP)
    )
    forked = log.checkpoint_text(tree_size=4, root=b"\x42" * 32)
    with pytest.raises(Conflict):
        revived.add_checkpoint(_body(4, [], forked))


def test_the_read_and_the_write_happen_inside_one_transaction(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log: FakeLog
) -> None:
    """C2SP: "checking the old size against the latest checkpoint and
    persisting the new checkpoint must be performed atomically."

    Asserted structurally rather than by racing two threads, and deliberately
    so: a timing test for this passes or fails on scheduling luck. Splitting
    the compare and the write into two transactions leaves a window between
    them that a concurrent submitter can walk through — a window measured in
    microseconds, which is exactly why no reliable race can be written around
    it. Recording which transaction each operation belongs to can.
    """
    events: list[tuple[str, int]] = []

    class RecordingTransaction:
        def __init__(self, inner: object, index: int) -> None:
            self._inner = inner
            self._index = index

        def latest(self, origin: str) -> object:
            events.append(("read", self._index))
            return self._inner.latest(origin)  # type: ignore[attr-defined]

        def store(self, origin: str, **kwargs: object) -> None:
            events.append(("write", self._index))
            self._inner.store(origin, **kwargs)  # type: ignore[attr-defined]

    class RecordingStore(WitnessStore):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self._transactions = 0

        @contextmanager
        def transaction(self):  # type: ignore[no-untyped-def,override]
            self._transactions += 1
            index = self._transactions
            events.append(("begin", index))
            with super().transaction() as inner:
                yield RecordingTransaction(inner, index)
            events.append(("commit", index))

    config = _config(tmp_path, witness_keys, {ORIGIN: log.log_key})
    service = WitnessService(
        config, RecordingStore(config.database_path), clock=lambda: float(TIMESTAMP)
    )
    log.append(4)
    service.add_checkpoint(_body(0, [], log.checkpoint_text()))

    assert [name for name, _ in events] == ["begin", "read", "write", "commit"]
    assert len({index for _, index in events}) == 1, "the read and the write must share one"
