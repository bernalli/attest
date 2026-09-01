"""Ledger: sqlite3 operational-state store — idempotency, receipts, claims, dead letters.

Contract: the Ledger is NOT part of the trust model, but the
`receipts` table stores issued envelopes verbatim (carrying `delivery.salt`), so
the database file is a SECRET — must be 0600 on disk. Timestamps are always
caller-supplied RFC3339 strings; the Ledger never reads a clock. Each behavior
below gets its own test per the brief's Step 1 enumeration.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest
from attest_bridge import ledger as ledger_mod
from attest_bridge.ledger import Claim, DeadLetter, Ledger, StoredReceipt
from attest_bridge.model import ClaimQueueFull

NOW = "2026-07-24T10:00:00Z"
FUTURE = "2026-07-25T10:00:00Z"
PAST = "2026-07-23T10:00:00Z"


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger(tmp_path / "ledger.sqlite3")


def _envelope() -> dict[str, object]:
    return {
        "attest_version": "0.2",
        "issuer": {"id": "merchant.example.com"},
        "delivery": {"salt": "c29tZS1zYWx0LWJ5dGVz"},
    }


# -- 0600 secrecy contract ----------------------------------------------------


def test_db_file_is_created_with_mode_0600(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.sqlite3"
    Ledger(db_path)

    mode = oct(stat.S_IMODE(os.stat(db_path).st_mode))

    assert mode == "0o600"


# -- webhook-event idempotency -------------------------------------------------


def test_seen_event_is_false_when_unmarked(ledger: Ledger) -> None:
    assert ledger.seen_event("stripe", "evt_1") is False


def test_seen_event_is_true_after_mark_event(ledger: Ledger) -> None:
    ledger.mark_event("stripe", "evt_1", now=NOW)

    assert ledger.seen_event("stripe", "evt_1") is True


# -- receipts -------------------------------------------------------------------


def test_record_receipt_then_get_receipt_round_trips_every_field(ledger: Ledger) -> None:
    envelope = _envelope()

    ledger.record_receipt(
        "stripe",
        "cs_123",
        "receipt-abc",
        envelope,
        "buyer@example.com",
        "download-token-xyz",
        NOW,
    )

    stored = ledger.get_receipt("stripe", "cs_123")

    assert stored is not None
    assert stored.platform == "stripe"
    assert stored.purchase_id == "cs_123"
    assert stored.receipt_id == "receipt-abc"
    assert json.loads(stored.envelope_json) == envelope
    assert stored.download_token == "download-token-xyz"  # noqa: S105 - test fixture value
    assert stored.buyer_email == "buyer@example.com"
    assert stored.issued_at == NOW
    assert stored.delivered_at is None
    assert stored.delivery_attempts == 0
    assert stored.last_delivery_error is None


def test_get_receipt_returns_none_when_absent(ledger: Ledger) -> None:
    assert ledger.get_receipt("stripe", "cs_missing") is None


def test_double_record_receipt_same_purchase_raises_receipt_already_recorded(
    ledger: Ledger,
) -> None:
    """The PRIMARY KEY still refuses, but through this module's own exception.

    It used to raise `sqlite3.IntegrityError` verbatim, which made the driver
    part of every caller's contract. The underlying error is kept as the
    cause, so an operator still gets the constraint that fired.
    """
    ledger.record_receipt(
        "stripe", "cs_dup", "receipt-1", _envelope(), "buyer@example.com", "token-1", NOW
    )

    with pytest.raises(ledger_mod.ReceiptAlreadyRecorded) as caught:
        ledger.record_receipt(
            "stripe", "cs_dup", "receipt-2", _envelope(), "buyer@example.com", "token-2", NOW
        )

    assert isinstance(caught.value.__cause__, sqlite3.IntegrityError)


def test_a_download_token_collision_raises_the_same_exception_as_a_duplicate_purchase(
    ledger: Ledger,
) -> None:
    """Two different constraints, one exception type — deliberately.

    This is why `core.issue_for` re-reads the row instead of treating the
    exception as proof of a duplicate: here the purchase is brand new and
    nothing about it was recorded, and calling it a duplicate would answer
    the buyer with a receipt issued to somebody else.
    """
    ledger.record_receipt(
        "stripe", "cs_first", "receipt-1", _envelope(), "buyer@example.com", "shared-token", NOW
    )

    with pytest.raises(ledger_mod.ReceiptAlreadyRecorded):
        ledger.record_receipt(
            "stripe",
            "cs_second",
            "receipt-2",
            _envelope(),
            "other@example.com",
            "shared-token",
            NOW,
        )

    assert ledger.get_receipt("stripe", "cs_second") is None


def test_by_download_token_hit(ledger: Ledger) -> None:
    ledger.record_receipt(
        "stripe", "cs_tok", "receipt-1", _envelope(), "buyer@example.com", "token-hit", NOW
    )

    stored = ledger.by_download_token("token-hit")

    assert stored is not None
    assert stored.purchase_id == "cs_tok"


def test_by_download_token_miss(ledger: Ledger) -> None:
    assert ledger.by_download_token("no-such-token") is None


def test_mark_delivered_updates_delivered_at(ledger: Ledger) -> None:
    ledger.record_receipt(
        "stripe", "cs_del", "receipt-1", _envelope(), "buyer@example.com", "token-del", NOW
    )

    ledger.mark_delivered("stripe", "cs_del", NOW)

    stored = ledger.get_receipt("stripe", "cs_del")
    assert stored is not None
    assert stored.delivered_at == NOW


def test_record_delivery_failure_updates_attempts_and_error(ledger: Ledger) -> None:
    ledger.record_receipt(
        "stripe", "cs_fail", "receipt-1", _envelope(), "buyer@example.com", "token-fail", NOW
    )

    ledger.record_delivery_failure("stripe", "cs_fail", "SMTP connection refused")
    ledger.record_delivery_failure("stripe", "cs_fail", "SMTP timeout")

    stored = ledger.get_receipt("stripe", "cs_fail")
    assert stored is not None
    assert stored.delivery_attempts == 2
    assert stored.last_delivery_error == "SMTP timeout"
    assert stored.delivered_at is None


def test_undelivered_returns_only_never_delivered(ledger: Ledger) -> None:
    ledger.record_receipt(
        "stripe", "cs_a", "receipt-a", _envelope(), "a@example.com", "token-a", NOW
    )
    ledger.record_receipt(
        "stripe", "cs_b", "receipt-b", _envelope(), "b@example.com", "token-b", NOW
    )
    ledger.mark_delivered("stripe", "cs_a", NOW)

    pending = ledger.undelivered()

    assert [r.purchase_id for r in pending] == ["cs_b"]


# -- itch claims queue ----------------------------------------------------------


def test_enqueue_claim_returns_a_token_and_get_claim_finds_it(ledger: Ledger) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=NOW)

    claim = ledger.get_claim(token)

    assert claim is not None
    assert claim.token == token
    assert claim.email == "buyer@example.com"
    assert claim.game_id == "game_1"
    assert claim.status == "pending"
    assert claim.attempts == 0
    assert claim.next_attempt_at == NOW
    assert claim.created_at == NOW


def test_get_claim_returns_none_for_unknown_token(ledger: Ledger) -> None:
    assert ledger.get_claim("no-such-token") is None


def test_due_claims_includes_claim_whose_next_attempt_at_has_passed(ledger: Ledger) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=PAST)

    due = ledger.due_claims(NOW)

    assert [c.token for c in due] == [token]


def test_due_claims_excludes_a_future_claim(ledger: Ledger) -> None:
    ledger.enqueue_claim("buyer@example.com", "game_1", now=FUTURE)

    due = ledger.due_claims(NOW)

    assert due == []


def test_enqueue_claim_deduplicates_a_pending_email_and_game(ledger: Ledger) -> None:
    first = ledger.enqueue_claim("buyer@example.com", "game_1", now=NOW)
    second = ledger.enqueue_claim("buyer@example.com", "game_1", now=FUTURE)

    assert second == first
    assert len(ledger.due_claims(FUTURE)) == 1


def test_enqueue_claim_rejects_at_pending_cap(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ledger_mod, "MAX_PENDING_CLAIMS", 1)
    ledger.enqueue_claim("one@example.com", "game_1", now=NOW)

    with pytest.raises(ClaimQueueFull):
        ledger.enqueue_claim("two@example.com", "game_1", now=NOW)


def test_defer_claim_increments_attempts_and_updates_next_attempt_at(ledger: Ledger) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=NOW)

    ledger.defer_claim(token, next_attempt_at=FUTURE)

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.attempts == 1
    assert claim.next_attempt_at == FUTURE
    assert claim.status == "pending"


def test_complete_claim_drops_it_from_due_claims(ledger: Ledger) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=PAST)

    ledger.complete_claim(token)

    assert ledger.due_claims(NOW) == []
    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "confirmed"


def test_complete_claim_retains_zero_receipts(ledger: Ledger) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=PAST)

    ledger.complete_claim(token)

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.receipts_issued == 0


def test_add_claim_receipts_is_cumulative_across_completion(ledger: Ledger) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=PAST)

    ledger.add_claim_receipts(token, 1)
    ledger.add_claim_receipts(token, 1)
    ledger.complete_claim(token)

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "confirmed"
    assert claim.receipts_issued == 2


def test_two_ledger_connections_deduplicate_the_same_pending_claim(tmp_path: Path) -> None:
    db_path = tmp_path / "shared.sqlite3"
    first = Ledger(db_path)
    second = Ledger(db_path)

    token = first.enqueue_claim("buyer@example.com", "game_1", now=NOW)

    assert second.enqueue_claim("buyer@example.com", "game_1", now=NOW) == token


def test_exhaust_claim_with_dead_letter_drops_it_from_due_claims(ledger: Ledger) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=PAST)

    ledger.exhaust_claim_with_dead_letter(
        token,
        platform="itch",
        purchase_id=None,
        reason="claim abandoned after 1 failed API attempts",
        raw_json='{"email": "buyer@example.com", "game_id": "game_1"}',
        now=NOW,
    )

    assert ledger.due_claims(NOW) == []
    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "exhausted"
    dead_letters = ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0].reason == "claim abandoned after 1 failed API attempts"


def test_exhaust_claim_with_dead_letter_rolls_back_when_dead_letter_insert_fails(
    ledger: Ledger,
) -> None:
    token = ledger.enqueue_claim("buyer@example.com", "game_1", now=PAST)
    ledger._conn.execute(
        """
        CREATE TRIGGER fail_dead_letter_insert
        BEFORE INSERT ON dead_letters
        BEGIN
          SELECT RAISE(ABORT, 'dead letter insert failed');
        END;
        """
    )

    with pytest.raises(sqlite3.IntegrityError, match="dead letter insert failed"):
        ledger.exhaust_claim_with_dead_letter(
            token,
            platform="itch",
            purchase_id=None,
            reason="claim abandoned after 1 failed API attempts",
            raw_json='{"email": "buyer@example.com", "game_id": "game_1"}',
            now=NOW,
        )

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "pending"
    assert ledger.due_claims(NOW) == [claim]
    assert ledger.unresolved_dead_letters() == []


# -- dead letters -----------------------------------------------------------------


def test_add_dead_letter_appears_in_unresolved(ledger: Ledger) -> None:
    ledger.add_dead_letter(
        "stripe", "cs_bad", "unmapped product", json.dumps({"raw": True}), now=NOW
    )

    unresolved = ledger.unresolved_dead_letters()

    assert len(unresolved) == 1
    entry = unresolved[0]
    assert entry.platform == "stripe"
    assert entry.purchase_id == "cs_bad"
    assert entry.reason == "unmapped product"
    assert json.loads(entry.raw_json) == {"raw": True}
    assert entry.created_at == NOW
    assert entry.resolved_at is None


def test_add_dead_letter_allows_none_purchase_id(ledger: Ledger) -> None:
    ledger.add_dead_letter("itch", None, "malformed webhook", "{}", now=NOW)

    unresolved = ledger.unresolved_dead_letters()

    assert unresolved[0].purchase_id is None


def test_resolve_dead_letter_removes_it_from_unresolved(ledger: Ledger) -> None:
    ledger.add_dead_letter("stripe", "cs_bad", "unmapped product", "{}", now=NOW)
    dead_letter_id = ledger.unresolved_dead_letters()[0].id

    ledger.resolve_dead_letter(dead_letter_id, now=FUTURE)

    assert ledger.unresolved_dead_letters() == []


def test_stored_receipt_claim_dead_letter_are_frozen_dataclasses() -> None:
    # Sanity check on the pinned shapes — mutation must
    # raise, since later tasks treat these as immutable value objects.
    receipt = StoredReceipt(
        platform="stripe",
        purchase_id="cs_1",
        receipt_id="r_1",
        envelope_json="{}",
        download_token="tok",  # noqa: S106 - test fixture value
        buyer_email="a@example.com",
        issued_at=NOW,
        delivered_at=None,
        delivery_attempts=0,
        last_delivery_error=None,
    )
    claim = Claim(
        token="tok",  # noqa: S106 - test fixture value
        email="a@example.com",
        game_id="game_1",
        status="pending",
        attempts=0,
        next_attempt_at=NOW,
        created_at=NOW,
        receipts_issued=0,
    )
    dead_letter = DeadLetter(
        id=1,
        platform="stripe",
        purchase_id=None,
        reason="x",
        raw_json="{}",
        created_at=NOW,
        resolved_at=None,
    )

    with pytest.raises(AttributeError):
        receipt.platform = "itch"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        claim.status = "confirmed"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        dead_letter.reason = "y"  # type: ignore[misc]


# -- concurrent writers on one file (the PK as last line of defense) -----------


def test_a_second_ledger_recording_the_same_purchase_raises_receipt_already_recorded(
    tmp_path: Path,
) -> None:
    """Two Ledger objects, one file: the second INSERT must not leak sqlite3.

    `retry-failed` and `itch-import` open the same file as a second process
    while `serve` runs, so this is the ordinary shape of a lost race, not a
    hypothetical one. The caller has to be able to catch it by a name that
    belongs to this module.
    """
    db_path = tmp_path / "ledger.sqlite3"
    first, second = Ledger(db_path), Ledger(db_path)
    first.record_receipt("stripe", "cs_1", "rcpt-first", _envelope(), "a@example.com", "tok-1", NOW)

    with pytest.raises(ledger_mod.ReceiptAlreadyRecorded):
        second.record_receipt(
            "stripe", "cs_1", "rcpt-second", _envelope(), "b@example.com", "tok-2", NOW
        )


def test_the_first_writer_of_a_purchase_keeps_the_row(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.sqlite3"
    first, second = Ledger(db_path), Ledger(db_path)
    first.record_receipt("stripe", "cs_1", "rcpt-first", _envelope(), "a@example.com", "tok-1", NOW)

    with pytest.raises(ledger_mod.ReceiptAlreadyRecorded):
        second.record_receipt(
            "stripe", "cs_1", "rcpt-second", _envelope(), "b@example.com", "tok-2", NOW
        )

    stored = second.get_receipt("stripe", "cs_1")
    assert stored is not None
    assert (stored.receipt_id, stored.download_token, stored.buyer_email) == (
        "rcpt-first",
        "tok-1",
        "a@example.com",
    )


def test_ledger_exposes_the_file_every_writer_shares(tmp_path: Path) -> None:
    """Cross-process coordination needs the path, not a second copy of it.

    The delivery sweep's file lock derives its own path from this one, so a
    Ledger that did not remember where it lives would force callers to pass a
    path alongside it — two sources of truth for one file.
    """
    db_path = tmp_path / "ledger.sqlite3"

    assert Ledger(db_path).db_path == db_path


# -- journal mode and busy timeout: declared, not inherited --------------------


def _record_one(ledger: Ledger, purchase_id: str = "cs_wal") -> None:
    ledger.record_receipt(
        "stripe", purchase_id, "receipt-1", _envelope(), "buyer@example.com", "handle-1", NOW
    )


def test_the_ledger_journal_is_wal_when_another_connection_asks(tmp_path: Path) -> None:
    """The journal mode is a deployment property, so it is set here, not hoped for.

    Left implicit it was the rollback journal, under which any open reader
    blocks the writer — and the bridge reads on the request thread while the
    poller and the sweep write.
    """
    db_path = tmp_path / "ledger.sqlite3"
    _record_one(Ledger(db_path))

    other = sqlite3.connect(db_path)
    try:
        assert other.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    finally:
        other.close()


def test_the_wal_sidecars_are_as_secret_as_the_database_itself(tmp_path: Path) -> None:
    """In WAL the Ledger is THREE files, and committed rows live in two of them.

    `-wal` holds rows not yet checkpointed into the database — envelopes,
    with their `delivery.salt`. The 0600 contract covers the secret, not the
    filename it happens to sit in.
    """
    db_path = tmp_path / "ledger.sqlite3"
    _record_one(Ledger(db_path))

    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(db_path) + suffix)
        assert sidecar.exists(), f"expected {suffix} beside a WAL Ledger"
        assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600


def test_the_busy_timeout_is_declared_rather_than_left_to_the_driver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same number as the implicit default — but ours, and visible in the file.

    A default that lives in the driver is a deployment property nobody can
    read, review or change; asserting the value the module declares is what
    makes it one.
    """
    monkeypatch.setattr(ledger_mod, "_BUSY_TIMEOUT_MS", 1234)

    ledger = Ledger(tmp_path / "ledger.sqlite3")

    # The connection is private on purpose; there is no other way to ask a
    # sqlite handle what timeout it is carrying.
    assert ledger._conn.execute("PRAGMA busy_timeout").fetchone()[0] == 1234


def test_a_database_that_cannot_use_wal_refuses_to_open(tmp_path: Path) -> None:
    """Fail closed: never degrade silently to the journal this task removed.

    An in-memory database is a real database that genuinely cannot go WAL, so
    this exercises the refusal rather than a stub of it. The message has to
    carry the path and the mode actually obtained: the operator's next move
    is about the filesystem the Ledger sits on.
    """
    db_path = tmp_path / "ledger.sqlite3"
    conn = sqlite3.connect(":memory:")
    try:
        with pytest.raises(sqlite3.OperationalError) as caught:
            ledger_mod._enable_wal(conn, db_path)
    finally:
        conn.close()

    message = str(caught.value)
    assert str(db_path) in message
    assert "memory" in message
