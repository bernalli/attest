"""Durable per-origin witness state.

Contract: for each pinned log origin this holds the LATEST checkpoint this
witness authenticated and cosigned — its tree size, its root, its note bytes,
and the exact text served back to monitors. That row is the whole of the
witness's memory, and three properties of it are what make a witness worth
anything at all:

- **The comparison and the write are one transaction.** C2SP tlog-witness
  requires that "checking the old size against the latest checkpoint and
  persisting the new checkpoint must be performed atomically". Two submissions
  racing on one origin must not both read the same pre-write state and both
  commit: that is how a witness ends up cosigning two inconsistent heads. The
  window is closed by `BEGIN IMMEDIATE` (the write lock is taken before the
  first read, so a concurrent writer waits rather than reads) plus one
  in-process lock over the shared connection.
- **Stored size never goes backwards.** Enforced in SQL, not only in the
  caller: the upsert's `WHERE excluded.tree_size >= witnessed.tree_size`
  refuses a rollback even if a caller asks for one, and the caller is told
  (`StaleState`) rather than left believing it succeeded.
- **State is durable before anybody is told about it.** `synchronous=FULL`
  means a returned commit has reached the disk, which is what lets the service
  sign only AFTER committing. A witness that signed first and crashed would
  wake with a cosignature in the world for a checkpoint it has no record of —
  and would happily cosign a fork of it.

The database file is state, not secret material (checkpoints are public), but
it is created 0600 anyway: it is the operational record of what this witness
has attested to, and nothing else on the host needs to read it.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS witnessed (
    origin        TEXT PRIMARY KEY,
    tree_size     INTEGER NOT NULL,
    root          BLOB NOT NULL,
    note_bytes    BLOB NOT NULL,
    cosigned_text TEXT NOT NULL
)
"""

# The rollback refusal lives here, in the statement itself: `excluded` is the
# proposed row, `witnessed` the stored one. A smaller proposed size updates
# nothing at all, and rowcount reports that.
_UPSERT: Final = """
INSERT INTO witnessed (origin, tree_size, root, note_bytes, cosigned_text)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(origin) DO UPDATE SET
    tree_size = excluded.tree_size,
    root = excluded.root,
    note_bytes = excluded.note_bytes,
    cosigned_text = excluded.cosigned_text
WHERE excluded.tree_size >= witnessed.tree_size
"""

_SELECT: Final = (
    "SELECT origin, tree_size, root, note_bytes, cosigned_text FROM witnessed WHERE origin = ?"
)


class StaleState(Exception):
    """A write would have moved a log's witnessed head backwards."""


@dataclass(frozen=True, slots=True)
class WitnessedCheckpoint:
    origin: str
    tree_size: int
    root: bytes
    # The three header lines through their final newline (v0.2 §9.1): the
    # IDENTITY of a checkpoint. Signature lines are deliberately not part of
    # it — other witnesses cosigning the same head produce different full
    # texts for the same checkpoint.
    note_bytes: bytes
    # The full note text plus this witness's own cosignature lines: what
    # monitoring serves, and what an equal-size resubmission returns.
    cosigned_text: str


class Transaction:
    """The inside of one atomic compare-and-advance."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def latest(self, origin: str) -> WitnessedCheckpoint | None:
        row = self._connection.execute(_SELECT, (origin,)).fetchone()
        return None if row is None else _row_to_checkpoint(row)

    def store(
        self,
        origin: str,
        *,
        tree_size: int,
        root: bytes,
        note_bytes: bytes,
        cosigned_text: str,
    ) -> None:
        cursor = self._connection.execute(
            _UPSERT, (origin, tree_size, root, note_bytes, cosigned_text)
        )
        if cursor.rowcount == 0:
            raise StaleState(f"refused to move {origin!r} back to tree size {tree_size}")


def _row_to_checkpoint(row: tuple[str, int, bytes, bytes, str]) -> WitnessedCheckpoint:
    return WitnessedCheckpoint(
        origin=row[0],
        tree_size=row[1],
        root=bytes(row[2]),
        note_bytes=bytes(row[3]),
        cosigned_text=row[4],
    )


class WitnessStore:
    """One SQLite database, one connection, one lock.

    The single shared connection is the bridge's ledger precedent: a
    connection is not safe to use from two threads at once, so every access —
    read or write — is taken under `self._lock` for its whole duration.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(mode=0o600, exist_ok=True)
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        path.chmod(0o600)
        with self._lock:
            # WAL keeps a monitoring read from blocking a submission; FULL is
            # the point of the whole module: a commit that has returned has
            # reached the disk, so signing after it cannot outlive the state
            # it attests to.
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute(_SCHEMA)

    def latest(self, origin: str) -> WitnessedCheckpoint | None:
        with self._lock:
            row = self._connection.execute(_SELECT, (origin,)).fetchone()
        return None if row is None else _row_to_checkpoint(row)

    @contextmanager
    def transaction(self) -> Iterator[Transaction]:
        """Run a compare-and-advance atomically.

        `BEGIN IMMEDIATE`, not a bare `BEGIN`: a deferred transaction takes no
        lock until its first write, so two writers would both complete their
        reads before either was blocked — precisely the lost update this
        module exists to prevent.
        """
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield Transaction(self._connection)
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
            self._connection.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._connection.close()
