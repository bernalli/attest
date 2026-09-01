"""Ledger: sqlite3-backed OPERATIONAL state — webhook-event idempotency,
issued-receipt store, itch claim queue, dead letters.

Contract: this is NOT part of the trust model — nothing
`attest.verify` does depends on any of it — but the `receipts` table stores
issued envelopes verbatim, including `delivery.salt`, so the database file
itself is a SECRET. `__init__` creates the file at 0600 before the first
byte is ever written to it (`Path.touch(mode=0o600)`), then re-chmods it
after connecting as a belt-and-braces guard for a file that predates this
contract (documented in T10).

The journal is WAL, declared at connection time and verified (`_enable_wal`),
because this process reads on the request thread while the itch poller and
the delivery sweep write: under the rollback journal an open reader blocks
every writer. That makes the Ledger THREE files on disk — `.db`, `-wal`,
`-shm` — and the first two hold committed rows, so all three inherit the
secrecy contract above and a copy taken while the bridge is running must
include them (or be taken with the process stopped). The busy timeout is
declared alongside it, at the same value the driver would have used
implicitly, so it can be read and changed here rather than inherited.

Timestamps are always CALLER-SUPPLIED RFC3339 strings — this module never
reads a clock — which keeps tests deterministic and hands retry/backoff
policy entirely to the caller. RFC3339's lexicographic-equals-chronological
ordering is exactly what makes `due_claims`'s plain string comparison
correct without parsing a single string into a datetime.

One `sqlite3.Connection` per `Ledger`, shared by the WSGI request thread and
the itch poller thread (T8/T9): `check_same_thread=False` disables sqlite3's
default single-thread guard, and EVERY access — reads and writes alike — takes
`_lock` for the full duration of its statement (plus commit, for writes). A
shared connection yields undefined results if a write steps a cursor a read is
mid-iteration on (SQLite same-connection isolation), so the lock serializes
whole read+fetch operations, not just writes. Every statement is parametrized —
never string-formatted — SQL.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attest_bridge.model import ClaimQueueFull, purchase_id_for_log

MAX_PENDING_CLAIMS = 1000

# Declared rather than inherited. It is the same number CPython's driver uses
# by default, which is the point: a deployment property nobody can read in the
# source is one nobody can review or change.
_BUSY_TIMEOUT_MS = 5000


def _enable_wal(conn: sqlite3.Connection, db_path: Path) -> None:
    """Put this database in WAL, or refuse to use it at all.

    sqlite answers `PRAGMA journal_mode=WAL` with the mode it ENDED UP in
    rather than with an error, so a filesystem that cannot support WAL leaves
    the connection quietly on the rollback journal — under which an open
    reader blocks every writer, which is precisely what this call exists to
    remove. Read the answer back and fail closed on anything else.
    """
    row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
    mode = None if row is None else str(row[0]).lower()
    if mode != "wal":
        raise sqlite3.OperationalError(
            f"the ledger at {str(db_path)!r} could not be put in WAL journal mode "
            f"(sqlite reports {mode!r}). It needs a filesystem with working file "
            "locking: a local disk or a mounted block device, never a network share. "
            "See bridge/docs/deploy.md."
        )


class ReceiptAlreadyRecorded(Exception):
    """`record_receipt` lost a race: its INSERT hit a uniqueness constraint.

    Two constraints can produce it — the `(platform, purchase_id)` PRIMARY KEY
    of a purchase another writer recorded first, and the UNIQUE
    `download_token`. WHICH of the two is deliberately not decided here: the
    text of a sqlite error is not a contract to parse. The caller settles it
    by re-reading the row (`core.IssuingCore.issue_for`), which is the only
    answer that cannot be wrong.
    """


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  platform TEXT NOT NULL, event_id TEXT NOT NULL, received_at TEXT NOT NULL,
  PRIMARY KEY (platform, event_id));
CREATE TABLE IF NOT EXISTS receipts (
  platform TEXT NOT NULL, purchase_id TEXT NOT NULL, receipt_id TEXT NOT NULL,
  envelope_json TEXT NOT NULL, download_token TEXT NOT NULL UNIQUE,
  buyer_email TEXT NOT NULL, issued_at TEXT NOT NULL,
  delivered_at TEXT, delivery_attempts INTEGER NOT NULL DEFAULT 0,
  last_delivery_error TEXT,
  PRIMARY KEY (platform, purchase_id));
CREATE TABLE IF NOT EXISTS claims (
  token TEXT PRIMARY KEY, email TEXT NOT NULL, game_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL, created_at TEXT NOT NULL,
  receipts_issued INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS claims_pending_email_game_unique
  ON claims (email, game_id) WHERE status = 'pending';
CREATE TABLE IF NOT EXISTS dead_letters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform TEXT NOT NULL, purchase_id TEXT, reason TEXT NOT NULL,
  raw_json TEXT NOT NULL, created_at TEXT NOT NULL, resolved_at TEXT);
"""


@dataclass(frozen=True, slots=True)
class StoredReceipt:
    platform: str
    purchase_id: str
    receipt_id: str
    envelope_json: str
    download_token: str
    buyer_email: str
    issued_at: str
    delivered_at: str | None
    delivery_attempts: int
    last_delivery_error: str | None


@dataclass(frozen=True, slots=True)
class Claim:
    token: str
    email: str
    game_id: str
    status: str  # "pending" | "confirmed" | "exhausted"
    attempts: int
    next_attempt_at: str
    created_at: str
    # Operator-only count of receipts issued while resolving this claim. It is
    # intentionally never an HTTP response field: claim state must not reveal
    # whether an address owns a particular game.
    receipts_issued: int


@dataclass(frozen=True, slots=True)
class DeadLetter:
    id: int
    platform: str
    purchase_id: str | None
    reason: str
    raw_json: str
    created_at: str
    resolved_at: str | None


def _receipt_from_row(row: sqlite3.Row) -> StoredReceipt:
    return StoredReceipt(
        platform=row["platform"],
        purchase_id=row["purchase_id"],
        receipt_id=row["receipt_id"],
        envelope_json=row["envelope_json"],
        download_token=row["download_token"],
        buyer_email=row["buyer_email"],
        issued_at=row["issued_at"],
        delivered_at=row["delivered_at"],
        delivery_attempts=row["delivery_attempts"],
        last_delivery_error=row["last_delivery_error"],
    )


def _claim_from_row(row: sqlite3.Row) -> Claim:
    return Claim(
        token=row["token"],
        email=row["email"],
        game_id=row["game_id"],
        status=row["status"],
        attempts=row["attempts"],
        next_attempt_at=row["next_attempt_at"],
        created_at=row["created_at"],
        receipts_issued=row["receipts_issued"],
    )


def _dead_letter_from_row(row: sqlite3.Row) -> DeadLetter:
    return DeadLetter(
        id=row["id"],
        platform=row["platform"],
        purchase_id=row["purchase_id"],
        reason=row["reason"],
        raw_json=row["raw_json"],
        created_at=row["created_at"],
        resolved_at=row["resolved_at"],
    )


class Ledger:
    """Operational state store — idempotency, receipts, claims, dead letters.

    NOT part of the trust model. See module docstring for the secrecy (0600)
    and threading (shared connection + write lock) contracts.
    """

    def __init__(self, db_path: Path) -> None:
        # Kept so that anything needing to coordinate ACROSS processes on this
        # Ledger — the delivery sweep's file lock — can derive its own path
        # from the one file every writer already agrees on, instead of being
        # told a second path that could disagree with this one.
        self.db_path = db_path
        # Secrecy contract: the file must never exist world/group readable,
        # not even for the instant between creation and a later chmod — set
        # the mode at creation time, then re-assert it once connected.
        db_path.touch(mode=0o600, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        os.chmod(db_path, 0o600)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            # Before the schema, and before any caller can reach this object:
            # both are properties of the connection, not of a statement.
            _enable_wal(self._conn, db_path)
            self._conn.execute(f"PRAGMA busy_timeout = {int(_BUSY_TIMEOUT_MS)}")
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    # -- webhook-event idempotency ----------------------------------------

    def seen_event(self, platform: str, event_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM events WHERE platform = ? AND event_id = ?", (platform, event_id)
            ).fetchone()
        return row is not None

    def mark_event(self, platform: str, event_id: str, *, now: str) -> None:
        # `now` mirrors the other state-recording methods (enqueue_claim,
        # add_dead_letter, resolve_dead_letter): the caller supplies the RFC3339
        # timestamp so events.received_at holds a real value (the Ledger never
        # reads a clock) rather than an empty sentinel.
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO events (platform, event_id, received_at) VALUES (?, ?, ?)",
                (platform, event_id, now),
            )

    # -- receipts -----------------------------------------------------------

    def get_receipt(self, platform: str, purchase_id: str) -> StoredReceipt | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM receipts WHERE platform = ? AND purchase_id = ?",
                (platform, purchase_id),
            ).fetchone()
        return None if row is None else _receipt_from_row(row)

    def record_receipt(
        self,
        platform: str,
        purchase_id: str,
        receipt_id: str,
        envelope: dict[str, Any],
        buyer_email: str,
        download_token: str,
        issued_at: str,
    ) -> None:
        # The (platform, purchase_id) PRIMARY KEY stays the last line of
        # defense against a race, not the primary dedup mechanism — the caller
        # (core, T5) checks `get_receipt` first. What changed is what a lost
        # race produces: sqlite3 never leaves this module, so the caller can
        # catch it by a name it owns, re-read the winner's row, and answer the
        # purchase with a duplicate outcome instead of a 500 the platform will
        # retry straight back into the same race.
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    """
                    INSERT INTO receipts
                        (platform, purchase_id, receipt_id, envelope_json, download_token,
                         buyer_email, issued_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        platform,
                        purchase_id,
                        receipt_id,
                        json.dumps(envelope),
                        download_token,
                        buyer_email,
                        issued_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            # The purchase id is hashed here for the same reason it is hashed
            # in the logs: this message ends up in operator-visible output.
            raise ReceiptAlreadyRecorded(
                f"a uniqueness constraint rejected the receipt for platform={platform!r} "
                f"purchase_id={purchase_id_for_log(purchase_id)}"
            ) from exc

    def ping(self) -> None:
        """Raise if this Ledger cannot currently be read.

        Readiness needs a question the database has to actually answer — a
        connection object survives a file that has since been deleted,
        truncated or corrupted, so probing the handle proves nothing. Reads
        one row of the schema this module owns, takes the same lock as every
        other access, writes nothing.
        """
        with self._lock:
            self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()

    def by_download_token(self, token: str) -> StoredReceipt | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM receipts WHERE download_token = ?", (token,)
            ).fetchone()
        return None if row is None else _receipt_from_row(row)

    def mark_delivered(self, platform: str, purchase_id: str, at: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE receipts SET delivered_at = ? WHERE platform = ? AND purchase_id = ?",
                (at, platform, purchase_id),
            )

    def record_delivery_failure(self, platform: str, purchase_id: str, error: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE receipts
                SET delivery_attempts = delivery_attempts + 1, last_delivery_error = ?
                WHERE platform = ? AND purchase_id = ?
                """,
                (error, platform, purchase_id),
            )

    def undelivered(self) -> list[StoredReceipt]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM receipts WHERE delivered_at IS NULL"
            ).fetchall()
        return [_receipt_from_row(row) for row in rows]

    # -- itch claims queue (the poller "cursor") -----------------------------

    def enqueue_claim(self, email: str, game_id: str, *, now: str) -> str:
        with self._lock, self._conn:
            # This lookup and potential insert deliberately share one lock and
            # transaction. The partial unique index below extends the dedup
            # half across Ledger instances/processes. The count cap remains
            # best-effort across processes: an extra admission is not a
            # security boundary and does not justify distributed counting.
            existing = self._conn.execute(
                "SELECT token FROM claims WHERE email = ? AND game_id = ? "
                "AND status = 'pending' ORDER BY created_at LIMIT 1",
                (email, game_id),
            ).fetchone()
            if existing is not None:
                return str(existing["token"])
            pending = self._conn.execute(
                "SELECT COUNT(*) AS count FROM claims WHERE status = 'pending'"
            ).fetchone()
            assert pending is not None
            if int(pending["count"]) >= MAX_PENDING_CLAIMS:
                raise ClaimQueueFull("claim queue is full")
            token = secrets.token_urlsafe(32)
            try:
                self._conn.execute(
                    """
                    INSERT INTO claims (token, email, game_id, status, attempts,
                                         next_attempt_at, created_at)
                    VALUES (?, ?, ?, 'pending', 0, ?, ?)
                    """,
                    (token, email, game_id, now, now),
                )
            except sqlite3.IntegrityError:
                existing = self._conn.execute(
                    "SELECT token FROM claims WHERE email = ? AND game_id = ? "
                    "AND status = 'pending' ORDER BY created_at LIMIT 1",
                    (email, game_id),
                ).fetchone()
                if existing is None:
                    raise
                return str(existing["token"])
        return token

    def get_claim(self, token: str) -> Claim | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM claims WHERE token = ?", (token,)).fetchone()
        return None if row is None else _claim_from_row(row)

    def due_claims(self, now: str) -> list[Claim]:
        # RFC3339 strings sort lexicographically, so this is a plain string
        # comparison — a future `next_attempt_at` is correctly not due. Only
        # 'pending' claims are ever due: 'confirmed'/'exhausted' are terminal.
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM claims WHERE status = 'pending' AND next_attempt_at <= ? "
                "ORDER BY next_attempt_at",
                (now,),
            ).fetchall()
        return [_claim_from_row(row) for row in rows]

    def add_claim_receipts(self, token: str, n: int) -> None:
        """Increment the operator-visible issued count for a claim."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE claims SET receipts_issued = receipts_issued + ? WHERE token = ?",
                (n, token),
            )

    def complete_claim(self, token: str) -> None:
        """Mark a claim terminal while retaining its cumulative receipt count.

        No receipt identifier or download capability is associated with the
        claim row: claims are delivered to the submitted mailbox only.
        """
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE claims SET status = 'confirmed' WHERE token = ?",
                (token,),
            )

    def defer_claim(self, token: str, *, next_attempt_at: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE claims SET attempts = attempts + 1, next_attempt_at = ? WHERE token = ?",
                (next_attempt_at, token),
            )

    def exhaust_claim_with_dead_letter(
        self,
        token: str,
        *,
        platform: str,
        purchase_id: str | None,
        reason: str,
        raw_json: str,
        now: str,
    ) -> None:
        """Atomically abandon a claim and retain its recovery record.

        An exhausted claim is terminal and therefore invisible to the poller.
        Its dead letter is the sole recovery path for ``retry-failed``, so the
        two writes must commit together or neither may persist.
        """
        with self._lock, self._conn:
            self._conn.execute("UPDATE claims SET status = 'exhausted' WHERE token = ?", (token,))
            self._conn.execute(
                """
                INSERT INTO dead_letters (platform, purchase_id, reason, raw_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (platform, purchase_id, reason, raw_json, now),
            )

    # -- dead letters (operator-visible failed purchases) --------------------

    def add_dead_letter(
        self, platform: str, purchase_id: str | None, reason: str, raw_json: str, *, now: str
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO dead_letters (platform, purchase_id, reason, raw_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (platform, purchase_id, reason, raw_json, now),
            )

    def unresolved_dead_letters(self) -> list[DeadLetter]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM dead_letters WHERE resolved_at IS NULL ORDER BY id"
            ).fetchall()
        return [_dead_letter_from_row(row) for row in rows]

    def resolve_dead_letter(self, dead_letter_id: int, *, now: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE dead_letters SET resolved_at = ? WHERE id = ?",
                (now, dead_letter_id),
            )
