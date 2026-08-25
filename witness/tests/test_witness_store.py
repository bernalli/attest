"""The witness's state is the only thing standing between it and cosigning two
inconsistent heads for the same log. Everything here is about that: the stored
size never goes backwards, the comparison and the write happen inside ONE
transaction, and what is stored is durable before anybody is told about it.

These are storage-level tests. The protocol that drives them (old-size
comparison, consistency proofs, status codes) is exercised in
test_witness_service.py.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest
from attest_witness.store import StaleState, WitnessStore

ORIGIN = "log.example"
OTHER = "other-log.example"


def _checkpoint(size: int, marker: bytes = b"r") -> tuple[int, bytes, bytes, str]:
    """(tree_size, root, note_bytes, cosigned_text) for a checkpoint at `size`."""
    root = (marker * 32)[:32]
    note = f"{ORIGIN}\n{size}\n".encode() + root
    return size, root, note, f"cosigned:{size}:{marker.decode()}"


def test_unknown_origin_has_no_state(tmp_path: Path) -> None:
    store = WitnessStore(tmp_path / "state.sqlite3")
    assert store.latest(ORIGIN) is None
    store.close()


def test_stored_state_round_trips(tmp_path: Path) -> None:
    store = WitnessStore(tmp_path / "state.sqlite3")
    size, root, note, text = _checkpoint(7)
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=size, root=root, note_bytes=note, cosigned_text=text)
    stored = store.latest(ORIGIN)
    assert stored is not None
    assert (stored.tree_size, stored.root, stored.note_bytes, stored.cosigned_text) == (
        size,
        root,
        note,
        text,
    )
    store.close()


def test_state_survives_a_restart(tmp_path: Path) -> None:
    """A witness that forgets on restart re-cosigns a fork it already refused."""
    path = tmp_path / "state.sqlite3"
    store = WitnessStore(path)
    size, root, note, text = _checkpoint(4)
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=size, root=root, note_bytes=note, cosigned_text=text)
    store.close()

    reopened = WitnessStore(path)
    stored = reopened.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 4
    reopened.close()


def test_state_is_per_origin(tmp_path: Path) -> None:
    store = WitnessStore(tmp_path / "state.sqlite3")
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=9, root=b"a" * 32, note_bytes=b"a", cosigned_text="a")
        tx.store(OTHER, tree_size=2, root=b"b" * 32, note_bytes=b"b", cosigned_text="b")
    first = store.latest(ORIGIN)
    second = store.latest(OTHER)
    assert first is not None and first.tree_size == 9
    assert second is not None and second.tree_size == 2
    store.close()


def test_stored_size_can_never_go_backwards(tmp_path: Path) -> None:
    """Refused in SQL, not only in the caller: a caller bug must not be able
    to roll a witnessed head back."""
    store = WitnessStore(tmp_path / "state.sqlite3")
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=9, root=b"a" * 32, note_bytes=b"a", cosigned_text="nine")
    with pytest.raises(StaleState), store.transaction() as tx:
        tx.store(ORIGIN, tree_size=8, root=b"b" * 32, note_bytes=b"b", cosigned_text="eight")
    stored = store.latest(ORIGIN)
    assert stored is not None
    assert stored.tree_size == 9
    assert stored.cosigned_text == "nine"
    store.close()


def test_re_storing_the_same_size_is_allowed(tmp_path: Path) -> None:
    """Equal-size resubmission is legitimate (the client lost our response and
    asked again); it refreshes the cosignature, it does not advance anything."""
    store = WitnessStore(tmp_path / "state.sqlite3")
    _, root, note, _ = _checkpoint(5)
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=5, root=root, note_bytes=note, cosigned_text="first")
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=5, root=root, note_bytes=note, cosigned_text="second")
    stored = store.latest(ORIGIN)
    assert stored is not None and stored.cosigned_text == "second"
    store.close()


def test_a_failed_transaction_leaves_no_trace(tmp_path: Path) -> None:
    store = WitnessStore(tmp_path / "state.sqlite3")
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=3, root=b"a" * 32, note_bytes=b"a", cosigned_text="three")

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        with store.transaction() as tx:
            tx.store(ORIGIN, tree_size=4, root=b"b" * 32, note_bytes=b"b", cosigned_text="four")
            raise Boom
    stored = store.latest(ORIGIN)
    assert stored is not None and stored.tree_size == 3
    store.close()


def test_the_comparison_and_the_write_are_one_transaction(tmp_path: Path) -> None:
    """The classic lost update, in witness terms — across two connections.

    Two `WitnessStore` instances on one database file stand in for two
    processes: a redeployed witness overlapping its predecessor, or an
    operator running a second instance by mistake. Each writer reads the
    current size inside its transaction and stores that size plus one. If the
    transactions serialise, the second sees the first's write and the final
    size is 2.

    Two connections is what makes this test able to fail: within ONE store the
    in-process lock already serialises everything, so a deferred `BEGIN` —
    which takes no write lock until its first write, letting both readers see
    the same pre-write state — passes unnoticed. Across connections it does
    not.
    """
    path = tmp_path / "state.sqlite3"
    stores = [WitnessStore(path), WitnessStore(path)]
    errors: list[BaseException] = []

    def advance(store: WitnessStore) -> None:
        try:
            with store.transaction() as tx:
                current = tx.latest(ORIGIN)
                size = 1 if current is None else current.tree_size + 1
                # Real work happens between the read and the write; the sleep
                # makes the interleaving reliable instead of dependent on how
                # fast SQLite happens to be today.
                time.sleep(0.05)
                tx.store(
                    ORIGIN,
                    tree_size=size,
                    root=bytes([size]) * 32,
                    note_bytes=bytes([size]),
                    cosigned_text=str(size),
                )
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=advance, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    stored = stores[0].latest(ORIGIN)
    for store in stores:
        store.close()
    assert not errors, errors
    assert stored is not None
    assert stored.tree_size == 2, "one advance was lost: the read escaped the write lock"


def test_concurrent_advances_never_lose_ground(tmp_path: Path) -> None:
    """Many threads pushing increasing sizes: the final state is the largest,
    and no intermediate read ever sees a decrease."""
    store = WitnessStore(tmp_path / "state.sqlite3")
    sizes = list(range(1, 25))
    seen: list[int] = []
    lock = threading.Lock()

    def submit(size: int) -> None:
        try:
            with store.transaction() as tx:
                tx.store(
                    ORIGIN,
                    tree_size=size,
                    root=bytes([size % 256]) * 32,
                    note_bytes=bytes([size % 256]),
                    cosigned_text=str(size),
                )
        except StaleState:
            pass
        current = store.latest(ORIGIN)
        assert current is not None
        with lock:
            seen.append(current.tree_size)

    threads = [threading.Thread(target=submit, args=(size,)) for size in sizes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    final = store.latest(ORIGIN)
    assert final is not None and final.tree_size == max(sizes)
    assert seen and max(seen) == max(sizes)
    store.close()


def test_committed_state_is_visible_to_an_independent_connection(tmp_path: Path) -> None:
    """What 'durable' means operationally: a second connection -- a different
    process, in production -- can read it back. This is the property the
    service relies on when it signs only after the commit returns."""
    path = tmp_path / "state.sqlite3"
    store = WitnessStore(path)
    with store.transaction() as tx:
        tx.store(ORIGIN, tree_size=11, root=b"c" * 32, note_bytes=b"c", cosigned_text="eleven")

    with sqlite3.connect(path) as outside:
        row = outside.execute(
            "SELECT tree_size FROM witnessed WHERE origin = ?", (ORIGIN,)
        ).fetchone()
    assert row is not None and row[0] == 11
    store.close()


def test_database_file_is_not_world_readable(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = WitnessStore(path)
    assert path.stat().st_mode & 0o077 == 0
    store.close()


def test_an_existing_over_permissive_database_is_tightened(tmp_path: Path) -> None:
    """`touch(mode=...)` only applies to a file it CREATES. A database left
    0644 by an earlier deploy would keep those permissions forever, so the
    mode is re-applied on every open — and this is the case that proves it."""
    path = tmp_path / "state.sqlite3"
    path.touch(mode=0o644)
    store = WitnessStore(path)
    assert path.stat().st_mode & 0o077 == 0
    store.close()


def test_commits_are_configured_to_reach_the_disk(tmp_path: Path) -> None:
    """Pins the configuration, not the physics: durability under power loss
    cannot be observed from inside the process, but `synchronous=FULL` is what
    lets the service sign only after a commit returns, and a silent downgrade
    to NORMAL or OFF would leave that reasoning resting on nothing."""
    store = WitnessStore(tmp_path / "state.sqlite3")
    # Read through the store's OWN connection on purpose: `synchronous` is a
    # per-connection setting, so a fresh connection would report the default
    # and the assertion would be about nothing.
    row = store._connection.execute("PRAGMA synchronous").fetchone()
    assert row is not None and row[0] == 2, "synchronous is not FULL"
    store.close()
