"""What happens when two processes touch one Ledger at the same time.

The deployment the guides describe is already concurrent: `retry-failed` and
`itch-import` open the same sqlite file as a second process while `serve` is
running. Every test here is about a window between a read and the write that
depends on it — the kind of defect that never shows up in a single-threaded
suite, and reaches a buyer as a double email or a 500 on a paid order.

The interleavings are made deterministic, never approximated with sleeps: an
interposing Ledger fires the rival write at the exact point the race needs it.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import queue
import sqlite3
import stat
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from attest_bridge import delivery as delivery_mod
from attest_bridge import ledger as ledger_mod
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import DeliveryResult
from attest_bridge.ledger import Ledger, StoredReceipt
from attest_bridge.model import NormalizedPurchase

NOW = "2026-07-24T10:00:00Z"

# Download handles, named without the word "token" so the security linter does
# not read a test fixture as a hardcoded credential.
WINNER_HANDLE = "handle-from-the-winner"
COLLIDING_HANDLE = "the-one-and-only-handle"


def _purchase(**overrides: Any) -> NormalizedPurchase:
    base: dict[str, Any] = dict(
        platform="stripe",
        platform_purchase_id="cs_test_race",
        buyer_identifier="buyer@example.com",
        identifier_type="email",
        buyer_pubkey=None,
        product_key="price_TEST",
        purchased_at=NOW,
    )
    base.update(overrides)
    return NormalizedPurchase(**base)


class _RivalWinsTheRace:
    """A Ledger that lets a rival process commit between a lookup and its write.

    Wraps a real `Ledger`. The FIRST `get_receipt` for the contested key does
    the real read (which finds nothing), then lets the rival insert its own
    receipt, and finally returns the pre-insertion answer — exactly what the
    losing side of the race sees. Every other call, including the re-read the
    loser is expected to perform after its INSERT fails, goes straight
    through, so the rival's row is what it finds.

    The opposite interleaving — the rival committing BEFORE the first lookup —
    is the plain idempotent path already covered in `test_bridge_core_oracle`.
    """

    def __init__(self, real: Ledger, rival: Ledger, rival_row: dict[str, Any]) -> None:
        self._real = real
        self._rival = rival
        self._rival_row = rival_row
        self.rival_committed = False

    def get_receipt(self, platform: str, purchase_id: str) -> StoredReceipt | None:
        row = self._real.get_receipt(platform, purchase_id)
        if not self.rival_committed and (platform, purchase_id) == (
            self._rival_row["platform"],
            self._rival_row["purchase_id"],
        ):
            self.rival_committed = True
            self._rival.record_receipt(**self._rival_row)
        return row

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def _rival_row(envelope: dict[str, Any]) -> dict[str, Any]:
    return dict(
        platform="stripe",
        purchase_id="cs_test_race",
        receipt_id="rcpt-from-the-winner",
        envelope=envelope,
        buyer_email="buyer@example.com",
        download_token=WINNER_HANDLE,
        issued_at=NOW,
    )


# -- the losing side of an issuance race ---------------------------------------


def test_the_loser_of_an_issuance_race_returns_the_winners_stored_receipt(
    tmp_path: Path,
    catalog: Any,
    issuer_identity: Any,
) -> None:
    """Two processes issue the same purchase: one wins, neither 500s.

    Today the loser's INSERT hits the `(platform, purchase_id)` primary key
    and `sqlite3.IntegrityError` escapes `issue_for` — a paid order answered
    with a 500 that the platform will retry into the same race.
    """
    db = tmp_path / "ledger.sqlite3"
    winner_envelope = {"attest_version": "0.2", "payload": {"marker": "winner"}}
    racing = _RivalWinsTheRace(Ledger(db), Ledger(db), _rival_row(winner_envelope))
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=racing,  # type: ignore[arg-type]
        public_base_url="https://receipts.example.com",
    )

    outcome = core.issue_for(_purchase())

    assert racing.rival_committed, "the interposition did not fire — the test proves nothing"
    assert outcome.duplicate is True
    assert outcome.receipt_id == "rcpt-from-the-winner"
    assert outcome.envelope == winner_envelope
    stored = Ledger(db).get_receipt("stripe", "cs_test_race")
    assert stored is not None
    assert stored.receipt_id == "rcpt-from-the-winner"
    assert stored.download_token == WINNER_HANDLE


def test_an_integrity_error_that_is_not_a_duplicate_purchase_is_never_reported_as_one(
    tmp_path: Path,
    catalog: Any,
    issuer_identity: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A download-token collision must not be laundered into a duplicate.

    `receipts.download_token` is UNIQUE too. Deciding "duplicate" from the
    fact that an INSERT failed — rather than from a re-read that finds the
    row — would answer a purchase that was never recorded with someone
    else's receipt id.
    """
    db = tmp_path / "ledger.sqlite3"
    ledger = Ledger(db)
    ledger.record_receipt(
        platform="stripe",
        purchase_id="cs_test_other",
        receipt_id="rcpt-other",
        envelope={"attest_version": "0.2"},
        buyer_email="other@example.com",
        download_token=COLLIDING_HANDLE,
        issued_at=NOW,
    )
    monkeypatch.setattr("attest_bridge.core.secrets.token_urlsafe", lambda _n: COLLIDING_HANDLE)
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
    )

    with pytest.raises(ledger_mod.DownloadTokenAlreadyRecorded):
        core.issue_for(_purchase(platform_purchase_id="cs_test_fresh"))

    assert ledger.get_receipt("stripe", "cs_test_fresh") is None


def test_the_winners_row_is_left_exactly_as_the_winner_wrote_it(
    tmp_path: Path,
    catalog: Any,
    issuer_identity: Any,
) -> None:
    """First writer wins: the loser's envelope and salt die with the loser.

    Two receipts for one purchase would mean two salts binding one buyer, and
    the buyer would hold one of them while the merchant's Ledger remembered
    the other.
    """
    db = tmp_path / "ledger.sqlite3"
    winner_envelope = {"attest_version": "0.2", "delivery": {"salt": "d2lubmVyLXNhbHQ="}}
    racing = _RivalWinsTheRace(Ledger(db), Ledger(db), _rival_row(winner_envelope))
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=racing,  # type: ignore[arg-type]
        public_base_url="https://receipts.example.com",
    )

    core.issue_for(_purchase())

    stored = Ledger(db).get_receipt("stripe", "cs_test_race")
    assert stored is not None
    assert json.loads(stored.envelope_json) == winner_envelope


# -- the delivery sweep, across processes --------------------------------------

_WORKER = Path(__file__).with_name("_sweep_worker.py")
_RECEIPT_ID = "01HZX0000000000000000SWEEP"
# How long a second sweep must stay blocked for the bench to believe it is
# waiting on the lock rather than merely slow. Nothing is slept before this
# window opens: it starts only once the second process has said it is about to
# sweep, so process start-up never eats into it.
_BLOCKED_WINDOW_SECONDS = 2.0
_GENEROUS = 60.0
_WORKER_EXITED = "<worker exited>"


class _RecordingMailer:
    """Stands in for `Delivery`: the sweep only asks it to send and reads the
    status back. Optionally parks inside the send so a second sweep can be
    observed meeting the lock."""

    def __init__(
        self,
        entered: threading.Event | None = None,
        hold: threading.Event | None = None,
    ) -> None:
        self.sent: list[str] = []
        self._entered = entered
        self._hold = hold

    def send(self, **kwargs: Any) -> DeliveryResult:
        self.sent.append(kwargs["receipt_id"])
        if self._entered is not None:
            self._entered.set()
        if self._hold is not None:
            self._hold.wait(_GENEROUS)
        return DeliveryResult(status="sent", detail=None)


def _record_undelivered(ledger: Ledger, purchase_id: str) -> None:
    ledger.record_receipt(
        "stripe",
        purchase_id,
        _RECEIPT_ID,
        {"payload": {"work": {"title": "Stardrift Chronicles"}}},
        "buyer@example.com",
        f"handle_{purchase_id}",
        NOW,
    )


class _Worker:
    """A worker subprocess, with a reader thread draining its stdout.

    The reader thread is not a nicety. `select` on a buffered pipe reports
    "nothing to read" while a line already sits in the reader's own buffer, so
    a bench built on it passes or stalls depending on how the child's writes
    happened to be split — a false red, and a slow one. A blocking `readline`
    in a thread feeding a queue has no such window.

    EOF arrives as a marker, never as silence: a worker that DIED must not be
    mistaken for a worker that is patiently waiting on the lock, which is the
    exact conclusion this bench draws from a quiet worker.
    """

    def __init__(self, *args: str) -> None:
        self._proc = subprocess.Popen(  # noqa: S603
            [sys.executable, str(_WORKER), *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            self._lines.put(line.strip())
        self._lines.put(_WORKER_EXITED)

    def next_line(self, timeout: float) -> str | None:
        """The next progress marker, or None if the worker stayed silent."""
        try:
            return self._lines.get(timeout=timeout)
        except queue.Empty:
            return None

    def release(self) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write("go\n")
        self._proc.stdin.flush()

    @property
    def running(self) -> bool:
        return self._proc.poll() is None

    def kill(self) -> None:
        self._proc.kill()
        self._proc.wait(timeout=_GENEROUS)

    def stop(self) -> None:
        if self.running:
            self._proc.kill()
        self._proc.wait(timeout=_GENEROUS)


def test_two_processes_sweeping_one_ledger_deliver_the_receipt_once(tmp_path: Path) -> None:
    """The bench this whole file exists for: one buyer, one email.

    `retry-failed` sweeping while `serve`'s own sweeper runs is the documented
    workflow, and until the lock existed both would send. The overlap here is
    not hoped for, it is forced: B is started and observed entering its sweep
    while A is provably parked inside the send, holding the lock.

    This bench is also the probe for the half of the claim a laptop cannot
    settle. That `flock` does what it says was measured on a local filesystem;
    that the volume a deploy target mounts behaves the same way can only be
    established by running there. Point `tmp_path` inside that mounted volume
    (`pytest --basetemp=<volume>/tmp`) on the first real Fly or Render deploy:
    a green here is the answer, and until then the target half is open.
    """
    db = tmp_path / "ledger.sqlite3"
    _record_undelivered(Ledger(db), "cs_sweep")
    log = tmp_path / "sends.log"
    log.touch()

    first = _Worker("sweep", str(db), "A", str(log), "block")
    second: _Worker | None = None
    try:
        assert first.next_line(_GENEROUS) == "A:BEFORE-SWEEP"
        assert first.next_line(_GENEROUS) == "A:IN-SEND"

        second = _Worker("sweep", str(db), "B", str(log), "run")
        assert second.next_line(_GENEROUS) == "B:BEFORE-SWEEP"
        assert second.next_line(_BLOCKED_WINDOW_SECONDS) is None, (
            "the second process swept while the first was still inside the lock"
        )
        assert second.running, "the second process died instead of waiting for the lock"

        first.release()
        assert first.next_line(_GENEROUS) == "A:AFTER-SWEEP delivered=1 failed=0"
        assert second.next_line(_GENEROUS) == "B:AFTER-SWEEP delivered=0 failed=0"
    finally:
        for worker in (first, second):
            if worker is not None:
                worker.stop()

    # The log is read as the SEQUENCE it is: collapsing it would throw away
    # precisely the duplicate this test exists to detect.
    events = log.read_text().splitlines()
    assert [line for line in events if "SEND-START" in line] == [f"A:SEND-START {_RECEIPT_ID}"]
    stored = Ledger(db).get_receipt("stripe", "cs_sweep")
    assert stored is not None
    assert stored.delivered_at is not None


def test_the_sweep_lock_is_held_for_as_long_as_the_sweep_takes(tmp_path: Path) -> None:
    """Waiting, not timing out — and the wait is observable from outside."""
    db = tmp_path / "ledger.sqlite3"
    _record_undelivered(Ledger(db), "cs_probe")
    log = tmp_path / "sends.log"
    log.touch()
    lock_path = Path(str(db) + delivery_mod.SWEEP_LOCK_SUFFIX)

    worker = _Worker("sweep", str(db), "A", str(log), "block")
    try:
        assert worker.next_line(_GENEROUS) == "A:BEFORE-SWEEP"
        assert worker.next_line(_GENEROUS) == "A:IN-SEND"

        probe = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            worker.release()
            assert worker.next_line(_GENEROUS) == "A:AFTER-SWEEP delivered=1 failed=0"
            assert worker.next_line(_GENEROUS) == _WORKER_EXITED
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)  # free once the sweep is over
        finally:
            os.close(probe)
    finally:
        worker.stop()


def test_a_lock_left_behind_by_a_killed_process_does_not_block_the_next_sweep(
    tmp_path: Path,
) -> None:
    """The classic file-lock footgun, checked rather than assumed.

    The lock file is never unlinked — deleting one another process still holds
    open lets two holders coexist on the recreated file — so the next sweep
    always meets a file that already exists, sometimes left by a process that
    died mid-sweep.
    """
    db = tmp_path / "ledger.sqlite3"
    _record_undelivered(Ledger(db), "cs_after_crash")
    lock_path = Path(str(db) + delivery_mod.SWEEP_LOCK_SUFFIX)

    holder = _Worker("hold-lock", str(lock_path))
    assert holder.next_line(_GENEROUS) == "HELD"
    holder.kill()

    mailer = _RecordingMailer()
    assert delivery_mod.sweep_undelivered(
        ledger=Ledger(db),
        delivery=mailer,  # type: ignore[arg-type]
        public_base_url="https://receipts.example.com",
    ) == (1, 0)
    assert lock_path.exists(), "the lock file must survive its sweep, never be unlinked"
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_a_sweep_that_cannot_take_the_lock_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail loud. A filesystem without locking must stop the sweep.

    Falling back to an unlocked sweep would be the worst outcome available:
    the deployments that cannot lock are exactly the ones running more than
    one writer, which is when duplicate delivery actually happens.
    """
    db = tmp_path / "ledger.sqlite3"
    _record_undelivered(Ledger(db), "cs_nolock")

    def _no_locking(_fd: int, _op: int) -> None:
        raise OSError(errno.ENOTSUP, "locking is not supported by this filesystem")

    monkeypatch.setattr(delivery_mod.fcntl, "flock", _no_locking)
    mailer = _RecordingMailer()

    with pytest.raises(OSError, match="locking is not supported"):
        delivery_mod.sweep_undelivered(
            ledger=Ledger(db),
            delivery=mailer,  # type: ignore[arg-type]
            public_base_url="https://receipts.example.com",
        )

    assert mailer.sent == []


def test_two_threads_of_one_process_still_deliver_the_receipt_once(tmp_path: Path) -> None:
    """The in-process guarantee the module lock used to give, kept.

    A file lock is held per open file description, so a fresh descriptor per
    acquisition is what makes two threads of one process serialize on it. A
    descriptor shared at module level would be re-entrant between threads and
    would silently give this back.
    """
    db = tmp_path / "ledger.sqlite3"
    _record_undelivered(Ledger(db), "cs_threads")
    inside = threading.Event()
    release = threading.Event()
    blocking = _RecordingMailer(entered=inside, hold=release)
    second = _RecordingMailer()

    def _sweep(mailer: _RecordingMailer) -> None:
        delivery_mod.sweep_undelivered(
            ledger=Ledger(db),
            delivery=mailer,  # type: ignore[arg-type]
            public_base_url="https://receipts.example.com",
        )

    first_thread = threading.Thread(target=_sweep, args=(blocking,))
    first_thread.start()
    try:
        assert inside.wait(_GENEROUS), "the first sweep never reached its send"
        second_thread = threading.Thread(target=_sweep, args=(second,))
        second_thread.start()
        second_thread.join(_BLOCKED_WINDOW_SECONDS)
        assert second_thread.is_alive(), (
            "the second thread swept while the first was inside the lock"
        )
    finally:
        release.set()
        first_thread.join(timeout=_GENEROUS)
    second_thread.join(timeout=_GENEROUS)

    assert blocking.sent == [_RECEIPT_ID]
    assert second.sent == []


# -- what the journal mode buys, and what it does not --------------------------


def test_an_open_reader_does_not_block_a_write(tmp_path: Path) -> None:
    """The reason WAL is the right journal for this service.

    The bridge reads on the request thread while the itch poller and the
    delivery sweep write. Under the rollback journal a reader that is still
    inside its transaction holds a shared lock and the write dies `database
    is locked` — a paid webhook answered with a 500 because someone was
    downloading a receipt.
    """
    db = tmp_path / "ledger.sqlite3"
    Ledger(db)
    reader = sqlite3.connect(db)
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM receipts").fetchone()

        Ledger(db).record_receipt(
            "stripe",
            "cs_while_reading",
            "receipt-1",
            {"payload": {"work": {"title": "Stardrift Chronicles"}}},
            "buyer@example.com",
            "handle-while-reading",
            NOW,
        )
    finally:
        reader.close()

    stored = Ledger(db).get_receipt("stripe", "cs_while_reading")
    assert stored is not None


def test_a_second_writer_fails_loudly_and_leaves_the_ledger_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """WAL admits one writer at a time — and that is a clean error, not damage.

    The failure mode `deploy.md` used to describe generally was a corrupted
    file. On a filesystem with working locks it is this: the second writer is
    told it cannot have the database, and everything the first one wrote is
    there afterwards. Worth pinning, because it is the claim the deploy guide
    now makes to a merchant choosing where to run.
    """
    db = tmp_path / "ledger.sqlite3"
    Ledger(db)
    monkeypatch.setattr(ledger_mod, "_BUSY_TIMEOUT_MS", 100)
    rival = sqlite3.connect(db)
    try:
        rival.execute("BEGIN IMMEDIATE")
        rival.execute(
            "INSERT INTO receipts (platform, purchase_id, receipt_id, envelope_json, "
            "download_token, buyer_email, issued_at) VALUES (?,?,?,?,?,?,?)",
            ("stripe", "cs_rival", "receipt-rival", "{}", "handle-rival", "r@example.com", NOW),
        )

        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            Ledger(db).record_receipt(
                "stripe", "cs_mine", "receipt-mine", {}, "m@example.com", "handle-mine", NOW
            )

        rival.commit()
    finally:
        rival.close()

    after = Ledger(db)
    assert after.get_receipt("stripe", "cs_rival") is not None
    assert after.get_receipt("stripe", "cs_mine") is None


def test_two_spellings_of_one_ledger_meet_on_the_same_lock(tmp_path: Path) -> None:
    """A lock keyed on the path as typed is two locks, and two locks are none.

    Nothing stops a second process from reaching the same Ledger by another
    route — most plainly a symlink to the database file. Derived from the
    spelling, each process would take a lock of its own and both would send.
    """
    real = tmp_path / "ledger.sqlite3"
    _record_undelivered(Ledger(real), "cs_spelling")
    alias = tmp_path / "alias.sqlite3"
    alias.symlink_to(real)

    delivery_mod.sweep_undelivered(
        ledger=Ledger(alias),
        delivery=_RecordingMailer(),  # type: ignore[arg-type]
        public_base_url="https://receipts.example.com",
    )

    assert Path(str(real) + delivery_mod.SWEEP_LOCK_SUFFIX).exists()
    assert not Path(str(alias) + delivery_mod.SWEEP_LOCK_SUFFIX).exists(), (
        "the sweep locked a file of its own instead of the one every writer shares"
    )


def _assert_second_lock_waits(first: Any, second: Any) -> None:
    entered = threading.Event()

    def take_second() -> None:
        with delivery_mod._sweep_lock(second):
            entered.set()

    with delivery_mod._sweep_lock(first):
        thread = threading.Thread(target=take_second)
        thread.start()
        assert not entered.wait(_BLOCKED_WINDOW_SECONDS)
    thread.join(_GENEROUS)
    assert not thread.is_alive()
    assert entered.is_set()


def test_hardlink_spellings_lock_the_same_ledger_inode(tmp_path: Path) -> None:
    """A second name for one inode is one Ledger, and must take one lock.

    A path-derived lock cannot see that: each spelling gets a lock file of its
    own and both sweeps send. The Ledger's own inode is the identity every
    spelling shares.
    """
    real = tmp_path / "ledger.sqlite3"
    ledger = Ledger(real)
    alias = tmp_path / "hardlink.sqlite3"
    os.link(real, alias)

    _assert_second_lock_waits(ledger, SimpleNamespace(db_path=alias))


def test_deleting_the_side_lock_cannot_split_a_live_lock(tmp_path: Path) -> None:
    """Unlinking the lock file mid-sweep must not let a second sweeper in.

    Anything with write access to the Ledger's directory can remove the lock
    file — a stale-file cleanup, an operator, a container restart script. On a
    lock keyed only on that file the next sweeper recreates the name and walks
    straight in, next to a sweep that is still sending.
    """
    db = tmp_path / "ledger.sqlite3"
    first, second = Ledger(db), Ledger(db)
    entered = threading.Event()

    def take_second() -> None:
        with delivery_mod._sweep_lock(second):
            entered.set()

    with delivery_mod._sweep_lock(first):
        Path(str(db) + delivery_mod.SWEEP_LOCK_SUFFIX).unlink()
        thread = threading.Thread(target=take_second)
        thread.start()
        assert not entered.wait(_BLOCKED_WINDOW_SECONDS)
    thread.join(_GENEROUS)
    assert entered.is_set()
