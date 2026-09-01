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

import json
from pathlib import Path
from typing import Any

import pytest
from attest_bridge import ledger as ledger_mod
from attest_bridge.core import IssuingCore
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

    with pytest.raises(ledger_mod.ReceiptAlreadyRecorded):
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
