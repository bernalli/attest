"""itch.io claim-queue poller tests (OI-4, source-verified
2026-07-24): itch.io has no purchase webhook and no purchase-enumeration
endpoint, so issuance is a claim-queue poller whose SOLE issuance authority is
the live `GET /games/{game_id}/purchases?email=...` API response -- a claim
or a CSV row never causes issuance on its own. Every test below either pins
that invariant directly (the E2E oracle, the dead-letter-but-claim-completes
case) or pins the backoff/exhaustion arithmetic and HTTP/CLI surface around
it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import urllib.error
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from attest_bridge import cli
from attest_bridge.catalog import ProductCatalog, ProductTemplate
from attest_bridge.config import BridgeConfig, DeliveryConfig, IssuerConfig, ItchConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery, DeliveryResult
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.itch_adapter import ItchAdapter, ItchApiError, ItchPoller, _default_http_get
from attest_bridge.ledger import Ledger
from attest_bridge.model import NormalizedPurchase, PurchaseRejected
from attest_bridge.signing import IssuerIdentity
from conftest import DISPLAY_NAME, ISSUER, KID
from test_bridge_http import call_app

from attest import keys, pq
from attest import verify as verify_mod

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
# Same convention as conftest.py's own _LEGAL_TEXT_SHA256 -- a realistic
# 64-lowercase-hex digest, never a hand-typed placeholder.
_LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-bridge-itch-test-license-terms-v1").hexdigest()


# -- shared fixtures/helpers -------------------------------------------------


def _purchase_json(
    *,
    id: int = 1001,  # mirrors the itch API's own field name
    email: str = "buyer@example.com",
    created_at: str = "2016-11-18 21:07:03",
    source: str = "download_page",
    currency: str = "USD",
    price: str = "5.00",
    quantity: int = 1,
    status: str = "settled",
    purchase_type: str = "default",
    game_id: int = 123456,
) -> dict[str, Any]:
    return {
        "id": id,
        "email": email,
        "created_at": created_at,
        "source": source,
        "currency": currency,
        "price": price,
        "quantity": quantity,
        "status": status,
        "purchase_type": purchase_type,
        "game_id": game_id,
    }


def _fake_http_get(
    purchases: list[dict[str, Any]],
) -> tuple[Any, list[tuple[str, dict[str, str]]]]:
    calls: list[tuple[str, dict[str, str]]] = []

    def fake(url: str, headers: dict[str, str]) -> bytes:
        calls.append((url, headers))
        return json.dumps({"purchases": purchases}).encode("utf-8")

    return fake, calls


def _failing_http_get(status: int = 500) -> Any:
    def fake(url: str, headers: dict[str, str]) -> bytes:
        raise urllib.error.HTTPError(url, status, "itch API error", {}, None)  # type: ignore[arg-type]

    return fake


# -- fetch_purchases: URL/auth/parse -----------------------------------------


def test_fetch_purchases_builds_url_with_bearer_auth_and_returns_purchases_list() -> None:
    purchases = [_purchase_json(id=1001), _purchase_json(id=1002)]
    fake, calls = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="itch_secret_key", http_get=fake)

    result = adapter.fetch_purchases("123456", "buyer@example.com")

    assert result == purchases
    assert len(calls) == 1
    url, headers = calls[0]
    assert url == "https://api.itch.io/games/123456/purchases?email=buyer%40example.com"
    assert headers == {"Authorization": "Bearer itch_secret_key"}


def test_fetch_purchases_uses_configured_api_base() -> None:
    fake, calls = _fake_http_get([])
    adapter = ItchAdapter(api_key="key", api_base="https://itch.example.test", http_get=fake)

    adapter.fetch_purchases("999", "a@b.com")

    url, _ = calls[0]
    assert url == "https://itch.example.test/games/999/purchases?email=a%40b.com"


def test_fetch_purchases_non_200_raises_itch_api_error() -> None:
    adapter = ItchAdapter(api_key="key", http_get=_failing_http_get(404))
    with pytest.raises(ItchApiError):
        adapter.fetch_purchases("123456", "buyer@example.com")


def test_fetch_purchases_error_message_carries_neither_the_email_nor_the_api_key() -> None:
    """The message is built from an exception this module does not control, and
    the request URL carries the buyer's address while the key travels in a
    header. Anything that echoes either must be scrubbed where the message is
    built — every consumer downstream logs or stores it verbatim."""

    def echoing_http_get(url: str, headers: dict[str, str]) -> bytes:
        raise RuntimeError(f"connection reset for {url} with {headers['Authorization']}")

    adapter = ItchAdapter(api_key="sk_itch_secret_value", http_get=echoing_http_get)

    with pytest.raises(ItchApiError) as exc_info:
        adapter.fetch_purchases("123456", "buyer@example.com")

    message = str(exc_info.value)
    assert "buyer@example.com" not in message
    assert "buyer%40example.com" not in message
    assert "sk_itch_secret_value" not in message
    assert "<redacted-email>" in message
    assert "<redacted-api-key>" in message


def test_fetch_purchases_bad_json_raises_itch_api_error() -> None:
    def fake(url: str, headers: dict[str, str]) -> bytes:
        return b"not json at all"

    adapter = ItchAdapter(api_key="key", http_get=fake)
    with pytest.raises(ItchApiError):
        adapter.fetch_purchases("123456", "buyer@example.com")


def test_fetch_purchases_missing_purchases_key_raises_itch_api_error() -> None:
    def fake(url: str, headers: dict[str, str]) -> bytes:
        return json.dumps({"unexpected": "shape"}).encode("utf-8")

    adapter = ItchAdapter(api_key="key", http_get=fake)
    with pytest.raises(ItchApiError):
        adapter.fetch_purchases("123456", "buyer@example.com")


def test_default_http_get_refuses_a_non_https_url_before_opening() -> None:
    with pytest.raises(ValueError, match="non-https"):
        _default_http_get("http://api.itch.io/games/1/purchases", {})


# -- normalize ----------------------------------------------------------------


def test_normalize_maps_space_separated_timestamp_and_all_fields() -> None:
    raw = _purchase_json(
        id=1001, created_at="2016-11-18 21:07:03", price="5.00", currency="USD", game_id=123456
    )
    purchase = ItchAdapter(api_key="key").normalize(raw, email="buyer@example.com")
    assert purchase == NormalizedPurchase(
        platform="itch",
        platform_purchase_id="1001",
        buyer_identifier="buyer@example.com",
        identifier_type="email",
        buyer_pubkey=None,
        product_key="itch_123456",
        purchased_at="2016-11-18T21:07:03Z",
        amount="5.00",
        currency="USD",
    )


def test_normalize_accepts_iso_form_with_z_suffix() -> None:
    raw = _purchase_json(created_at="2016-11-18T21:07:03Z")
    purchase = ItchAdapter(api_key="key").normalize(raw, email="buyer@example.com")
    assert purchase.purchased_at == "2016-11-18T21:07:03Z"


def test_normalize_iso_form_with_offset_converts_to_utc() -> None:
    raw = _purchase_json(created_at="2016-11-18T23:07:03+02:00")
    purchase = ItchAdapter(api_key="key").normalize(raw, email="buyer@example.com")
    assert purchase.purchased_at == "2016-11-18T21:07:03Z"


def test_normalize_garbage_timestamp_raises_purchase_rejected() -> None:
    raw = _purchase_json(created_at="not-a-timestamp-at-all")
    with pytest.raises(PurchaseRejected):
        ItchAdapter(api_key="key").normalize(raw, email="buyer@example.com")


def test_normalize_missing_price_and_currency_are_none() -> None:
    raw = _purchase_json()
    del raw["price"]
    del raw["currency"]
    purchase = ItchAdapter(api_key="key").normalize(raw, email="buyer@example.com")
    assert purchase.amount is None
    assert purchase.currency is None


def test_normalize_buyer_pubkey_is_always_none() -> None:
    raw = _purchase_json()
    purchase = ItchAdapter(api_key="key").normalize(raw, email="buyer@example.com")
    assert purchase.buyer_pubkey is None


def test_normalize_uses_email_argument_not_raw_email_field() -> None:
    # The poller always supplies the claim's own email -- normalize must never
    # trust raw["email"] instead (they should agree, but the contract is
    # pinned on the explicit kwarg).
    raw = _purchase_json(email="someone-else@example.com")
    purchase = ItchAdapter(api_key="key").normalize(raw, email="claimant@example.com")
    assert purchase.buyer_identifier == "claimant@example.com"


# -- ItchPoller.tick: the E2E oracle (OI-4) -----------------------------------


def test_e2e_claim_tick_issues_api_confirmed_receipt_that_verifies_offline(
    ledger: Ledger, core: IssuingCore, trust_store: verify_mod.TrustStore
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    purchases = [
        _purchase_json(id=5001, email="buyer@example.com", game_id=123456, status="settled")
    ]
    fake_http_get, calls = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="itch_key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)

    poller.tick(now=now)

    assert len(calls) == 1
    stored = ledger.get_receipt("itch", "5001")
    assert stored is not None
    result = verify_mod.verify(stored.envelope_json.encode(), trust_store)
    assert result.ok is True

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "confirmed"
    assert claim.receipts_issued == 1


def test_claim_with_two_purchases_issues_and_delivers_both(
    ledger: Ledger, core: IssuingCore
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    sent: list[str] = []

    class RecordingDelivery:
        def send(self, **kwargs: Any) -> DeliveryResult:
            sent.append(kwargs["receipt_id"])
            return DeliveryResult("sent", None)

    core._delivery = RecordingDelivery()  # type: ignore[assignment]
    adapter = ItchAdapter(
        api_key="itch_key",
        http_get=_fake_http_get([_purchase_json(id=5011), _purchase_json(id=5012)])[0],
    )
    ItchPoller(adapter=adapter, ledger=ledger, core=core).tick(now=now)

    assert ledger.get_receipt("itch", "5011") is not None
    assert ledger.get_receipt("itch", "5012") is not None
    assert len(sent) == 2
    claim = ledger.get_claim(token)
    assert claim is not None and claim.receipts_issued == 2


def test_generic_purchase_failure_in_a_claim_does_not_abort_a_later_purchase(
    ledger: Ledger, core: IssuingCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    bad = _purchase_json(id=5013)
    good = _purchase_json(id=5014)
    adapter = ItchAdapter(api_key="itch_key", http_get=_fake_http_get([bad, good])[0])

    original_process = core.process

    def fail_one_purchase(purchase: NormalizedPurchase) -> Any:
        if purchase.platform_purchase_id == "5013":
            raise RuntimeError("transient signing failure")
        return original_process(purchase)

    monkeypatch.setattr(core, "process", fail_one_purchase)

    ItchPoller(adapter=adapter, ledger=ledger, core=core).tick(now=now)

    assert ledger.get_receipt("itch", "5014") is not None
    claim = ledger.get_claim(token)
    assert claim is not None and claim.receipts_issued == 1
    assert claim.status == "pending"


def test_claim_receipt_count_survives_a_deferred_tick(
    ledger: Ledger, core: IssuingCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    adapter = ItchAdapter(
        api_key="itch_key",
        http_get=_fake_http_get([_purchase_json(id=5021), _purchase_json(id=5022)])[0],
    )
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core, backoff_base_seconds=60)
    original_process = core.process
    failures = 0

    def fail_b_once(purchase: NormalizedPurchase) -> Any:
        nonlocal failures
        if purchase.platform_purchase_id == "5022" and failures == 0:
            failures += 1
            raise RuntimeError("transient signing failure")
        return original_process(purchase)

    monkeypatch.setattr(core, "process", fail_b_once)
    poller.tick(now=now)
    poller.tick(now=now + timedelta(seconds=60))

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "confirmed"
    assert claim.receipts_issued == 2


def test_e2e_repoll_after_reenqueue_does_not_reissue_dedups_on_purchase_id(
    ledger: Ledger, core: IssuingCore
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    purchases = [
        _purchase_json(id=5002, email="buyer@example.com", game_id=123456, status="settled")
    ]
    fake_http_get, _ = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="itch_key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)

    poller.tick(now=now)
    first = ledger.get_receipt("itch", "5002")
    assert first is not None

    # Buyer re-submits the claim form (or the merchant re-imports the same
    # email/game) -- the SAME purchase must never be issued twice.
    token2 = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    poller.tick(now=now)

    second = ledger.get_receipt("itch", "5002")
    assert second == first  # unchanged -- never re-issued
    claim2 = ledger.get_claim(token2)
    assert claim2 is not None
    assert claim2.status == "confirmed"
    assert claim2.receipts_issued == 0


def test_purchase_rejected_dead_letters_but_claim_still_completes(
    ledger: Ledger, core: IssuingCore
) -> None:
    # The purchase provably existed on the API (OI-4 is satisfied) even
    # though its shape can't be normalized -- it must be dead-lettered for
    # operator triage, and the claim must still complete (never left
    # pending forever for something the API confirmed happened).
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    purchases = [
        _purchase_json(id=5003, game_id=123456, status="settled", created_at="garbage-timestamp")
    ]
    fake_http_get, _ = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="itch_key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)

    poller.tick(now=now)

    assert ledger.get_receipt("itch", "5003") is None
    dead_letters = ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0].platform == "itch"
    # T9 review fix (FIX 2b): a `normalize()` failure is now caught BEFORE the
    # purchase id is extracted (extraction only happens via
    # `normalized.platform_purchase_id`, which never exists on this path), so
    # the dead letter's purchase_id is None here -- a deliberate, spec-exact
    # consequence of the crash-proofing restructure, not a regression. The
    # raw purchase JSON (including "id": 5003) is still fully preserved in
    # raw_json for operator triage.
    assert dead_letters[0].purchase_id is None
    assert '"id": 5003' in dead_letters[0].raw_json
    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "confirmed"
    assert claim.receipts_issued == 0


# -- ItchPoller.tick: purchase-row validation + crash-proofing (FIX 2) --------


def test_purchase_with_null_id_is_dead_lettered_not_signed_as_None(
    ledger: Ledger, core: IssuingCore
) -> None:
    # A `null`/missing "id" must never be coerced to the literal string
    # "None" and signed -- `ItchAdapter.normalize` now rejects it before any
    # field mapping, and `_drain_claim` dead-letters it like any other
    # unnormalizable-but-API-confirmed purchase.
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    purchases = [_purchase_json(id=None, game_id=123456, status="settled")]
    fake_http_get, _ = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="itch_key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)

    poller.tick(now=now)

    assert ledger.get_receipt("itch", "None") is None
    dead_letters = ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0].platform == "itch"
    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "confirmed"


def test_non_dict_purchase_row_is_skipped_without_crashing(
    ledger: Ledger, core: IssuingCore
) -> None:
    # A malformed (non-object) row in the `purchases` list must be skipped,
    # not crash the tick -- and a later valid row in the same response must
    # still be issued.
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    valid = _purchase_json(id=7001, game_id=123456, status="settled")
    fake_http_get, _ = _fake_http_get(["garbage", valid])
    adapter = ItchAdapter(api_key="itch_key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)

    poller.tick(now=now)  # must not raise

    stored = ledger.get_receipt("itch", "7001")
    assert stored is not None
    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "confirmed"


def test_unexpected_core_error_defers_claim_and_poller_survives(
    ledger: Ledger, core: IssuingCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An unanticipated exception from `core.process` (e.g. a signing
    # IssueError) must neither propagate out of `tick` nor abandon the claim
    # -- it gets deferred on the normal backoff, exactly like an API miss.
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    purchases = [_purchase_json(id=8001, game_id=123456, status="settled")]
    fake_http_get, _ = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="itch_key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core, backoff_base_seconds=60)

    def boom(purchase: object) -> None:
        raise RuntimeError("unexpected signing failure")

    monkeypatch.setattr(core, "process", boom)

    poller.tick(now=now)  # must not raise

    assert ledger.get_receipt("itch", "8001") is None
    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "pending"
    assert claim.attempts == 1
    assert claim.next_attempt_at == (now + timedelta(seconds=60)).strftime(_RFC3339)


def test_exhausted_claim_after_core_failure_has_recovery_dead_letter(
    ledger: Ledger,
    core: IssuingCore,
    itch_bridge_config: BridgeConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An API-confirmed purchase must remain operator-recoverable on exhaustion."""
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    fake_http_get, _ = _fake_http_get([_purchase_json(id=8001, game_id=123456, status="settled")])
    adapter = ItchAdapter(api_key="itch_key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core, max_attempts=1)

    def boom(purchase: object) -> None:
        raise RuntimeError("unexpected signing failure")

    monkeypatch.setattr(core, "process", boom)

    poller.tick(now=now)

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "exhausted"
    dead_letters = ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0].platform == "itch"
    assert dead_letters[0].purchase_id is None
    # The generic prefix alone would leave the operator with "something failed":
    # the reason that actually caused the abandonment must survive to the
    # dead letter, or the dry run (and production triage) reports nothing usable.
    assert dead_letters[0].reason.startswith("claim abandoned after 1 issuance/storage failures")
    assert "unexpected signing failure" in dead_letters[0].reason

    deps = BridgeDeps(
        config=replace(itch_bridge_config, itch=None),
        core=core,
        ledger=ledger,
        stripe=None,
        log=logging.getLogger("test-exhausted-claim-retry-failed"),
    )
    monkeypatch.setattr(cli, "_build_deps", lambda config_path, *, log: deps)
    monkeypatch.setattr(cli, "_sweep_deliveries", lambda deps: (0, 0))
    assert cli.main(["retry-failed", "--config", "unused.toml"]) == 1


def test_run_forever_survives_a_tick_exception(ledger: Ledger, core: IssuingCore) -> None:
    # Last-resort guard: even if `tick` itself somehow raises (bypassing its
    # own per-claim isolation), `run_forever` must not let that kill the
    # sole daemon thread -- it logs and keeps looping.
    import threading

    fake_http_get, _ = _fake_http_get([])
    adapter = ItchAdapter(api_key="key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)
    stop = threading.Event()

    tick_count = 0

    def failing_then_stopping_tick(*, now: datetime) -> None:
        nonlocal tick_count
        tick_count += 1
        if tick_count == 1:
            raise RuntimeError("due_claims() blew up")
        stop.set()

    poller.tick = failing_then_stopping_tick  # type: ignore[method-assign]

    poller.run_forever(stop, interval_seconds=0)  # must return, not raise

    assert tick_count == 2


# -- ItchPoller.tick: backoff/exhaustion arithmetic ---------------------------


def test_api_error_defers_claim_with_exponential_backoff(ledger: Ledger, core: IssuingCore) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    adapter = ItchAdapter(api_key="key", http_get=_failing_http_get())
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core, backoff_base_seconds=60)

    poller.tick(now=now)

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "pending"
    assert claim.attempts == 1
    assert claim.next_attempt_at == (now + timedelta(seconds=60)).strftime(_RFC3339)

    # second consecutive failure: backoff doubles (base * 2**attempts)
    poller.tick(now=now + timedelta(seconds=60))
    claim2 = ledger.get_claim(token)
    assert claim2 is not None
    assert claim2.attempts == 2
    assert claim2.next_attempt_at == (
        now + timedelta(seconds=60) + timedelta(seconds=120)
    ).strftime(_RFC3339)


def test_claim_is_exhausted_after_reaching_max_attempts(
    ledger: Ledger, core: IssuingCore, caplog: pytest.LogCaptureFixture
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    adapter = ItchAdapter(api_key="key", http_get=_failing_http_get())
    poller = ItchPoller(
        adapter=adapter, ledger=ledger, core=core, max_attempts=1, backoff_base_seconds=1
    )

    poller.tick(now=now)

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "exhausted"
    assert ledger.due_claims((now + timedelta(seconds=1000)).strftime(_RFC3339)) == []
    assert "game 123456 (attempt 1)" in caplog.text
    assert "abandoning claim" in caplog.text
    assert "key" not in caplog.text
    assert token not in caplog.text
    dead_letters = ledger.unresolved_dead_letters()
    # The reason names WHY, not only how many times: an operator triaging a
    # dead letter needs to tell a bad API key from itch being down.
    assert dead_letters[-1].reason.startswith("claim abandoned after 1 failed API attempts")
    assert "HTTP Error 500" in dead_letters[-1].reason


def test_claim_gets_exactly_max_attempts_api_calls(ledger: Ledger, core: IssuingCore) -> None:
    # Off-by-one fix (FIX 1): a claim capped at `max_attempts` must get
    # EXACTLY that many live API fetches before exhausting -- not
    # max_attempts + 1. The old `claim.attempts >= self._max_attempts` check
    # exhausted one tick too late, because the failing fetch that just
    # happened isn't reflected in `claim.attempts` until AFTER
    # `_defer_or_exhaust` increments it via `defer_claim` -- so the fetch
    # that pushes `attempts` up to `max_attempts` was still allowed to
    # happen, for `max_attempts + 1` fetches total.
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    call_count = 0

    def always_failing(url: str, headers: dict[str, str]) -> bytes:
        nonlocal call_count
        call_count += 1
        raise urllib.error.HTTPError(url, 500, "itch API error", {}, None)  # type: ignore[arg-type]

    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    adapter = ItchAdapter(api_key="key", http_get=always_failing)
    poller = ItchPoller(
        adapter=adapter, ledger=ledger, core=core, max_attempts=2, backoff_base_seconds=1
    )

    # Tick repeatedly, each time advancing `now` to (at least) the claim's own
    # `next_attempt_at`, until it exhausts -- a generous ceiling (10 ticks) so
    # this fails loudly (not by looping forever) if the cap ever slips.
    current = now
    for _ in range(10):
        claim = ledger.get_claim(token)
        assert claim is not None
        if claim.status == "exhausted":
            break
        next_attempt_at = datetime.strptime(claim.next_attempt_at, _RFC3339).replace(tzinfo=UTC)
        current = max(current, next_attempt_at)
        poller.tick(now=current)
    else:
        pytest.fail("claim never reached 'exhausted' within 10 ticks")

    final = ledger.get_claim(token)
    assert final is not None
    assert final.status == "exhausted"
    assert call_count == 2  # exactly max_attempts -- never max_attempts + 1


def test_api_success_with_zero_purchases_is_treated_like_a_miss(
    ledger: Ledger, core: IssuingCore
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    fake_http_get, _ = _fake_http_get([])
    adapter = ItchAdapter(api_key="key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core, backoff_base_seconds=60)

    poller.tick(now=now)

    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "pending"
    assert claim.attempts == 1
    assert claim.next_attempt_at == (now + timedelta(seconds=60)).strftime(_RFC3339)


def test_refunded_purchase_is_skipped_and_claim_is_not_confirmed(
    ledger: Ledger, core: IssuingCore
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    token = ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    purchases = [_purchase_json(id=6001, game_id=123456, status="refunded")]
    fake_http_get, _ = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core, backoff_base_seconds=60)

    poller.tick(now=now)

    assert ledger.get_receipt("itch", "6001") is None
    claim = ledger.get_claim(token)
    assert claim is not None
    assert claim.status == "pending"  # not confirmed -- nothing settled yet
    assert claim.attempts == 1


def test_canceled_purchase_is_skipped_same_as_refunded(ledger: Ledger, core: IssuingCore) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    ledger.enqueue_claim("buyer@example.com", "123456", now=now.strftime(_RFC3339))
    purchases = [_purchase_json(id=6002, game_id=123456, status="canceled")]
    fake_http_get, _ = _fake_http_get(purchases)
    adapter = ItchAdapter(api_key="key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)

    poller.tick(now=now)

    assert ledger.get_receipt("itch", "6002") is None


def test_only_pending_due_claims_are_processed_confirmed_ones_are_untouched(
    ledger: Ledger, core: IssuingCore
) -> None:
    now = datetime(2026, 7, 24, 10, 0, 0, tzinfo=UTC)
    past = (now - timedelta(hours=1)).strftime(_RFC3339)
    already_confirmed_token = ledger.enqueue_claim("done@example.com", "123456", now=past)
    ledger.add_claim_receipts(already_confirmed_token, 1)
    ledger.complete_claim(already_confirmed_token)

    fake_http_get, calls = _fake_http_get([])
    adapter = ItchAdapter(api_key="key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)

    poller.tick(now=now)

    assert calls == []  # never even called the API for an already-confirmed claim
    claim = ledger.get_claim(already_confirmed_token)
    assert claim is not None
    assert claim.status == "confirmed"
    assert claim.receipts_issued == 1


# -- run_forever --------------------------------------------------------------


def test_run_forever_ticks_until_stop_is_set(ledger: Ledger, core: IssuingCore) -> None:
    import threading

    fake_http_get, _calls = _fake_http_get([])
    adapter = ItchAdapter(api_key="key", http_get=fake_http_get)
    poller = ItchPoller(adapter=adapter, ledger=ledger, core=core)
    stop = threading.Event()

    tick_count = 0
    original_tick = poller.tick

    def counting_tick(*, now: datetime) -> None:
        nonlocal tick_count
        tick_count += 1
        original_tick(now=now)
        if tick_count >= 2:
            stop.set()

    poller.tick = counting_tick  # type: ignore[method-assign]
    poller.run_forever(stop, interval_seconds=0)

    assert tick_count == 2


# -- HTTP claim routes ---------------------------------------------------------


def _product_template(**overrides: Any) -> ProductTemplate:
    base: dict[str, Any] = dict(
        title="Nebula Drifters",
        publisher="Example Games Store",
        identifiers={"itch_game_id": "123456"},
        artifact_series=f"{ISSUER}/works/nebula-drifters",
        terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
        legal_text_sha256=_LEGAL_TEXT_SHA256,
    )
    base.update(overrides)
    return ProductTemplate(**base)


@pytest.fixture
def itch_bridge_config(tmp_path: Path) -> BridgeConfig:
    return BridgeConfig(
        public_base_url="https://receipts.example.com",
        ledger_path=tmp_path / "unused-ledger-path.sqlite3",
        issuer=IssuerConfig(
            id=ISSUER,
            display_name=DISPLAY_NAME,
            kid=KID,
            seed_path=tmp_path / "issuer.seed",
            mldsa_key_path=tmp_path / "issuer.mldsa.json",
            manifest_path=tmp_path / "key-manifest.json",
        ),
        products={"itch_123456": _product_template()},
        stripe=None,
        itch=ItchConfig(api_key="itch_key"),
        delivery=DeliveryConfig(
            smtp_host="smtp.example.com",
            smtp_port=465,
            smtp_username="receipts@example.com",
            smtp_password="smtp-test-password",  # noqa: S106 - test fixture
            from_address="receipts@example.com",
            info_url="https://receipts.example.com/info",
        ),
    )


@pytest.fixture
def itch_deps(
    itch_bridge_config: BridgeConfig,
    catalog: ProductCatalog,
    issuer_identity: IssuerIdentity,
    ledger: Ledger,
) -> BridgeDeps:
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(None),
    )
    adapter = ItchAdapter(api_key="itch_key")
    return BridgeDeps(
        config=itch_bridge_config,
        core=core,
        ledger=ledger,
        stripe=None,
        log=logging.getLogger("test-bridge-itch"),
        itch=adapter,
    )


@pytest.fixture
def bridge_deps_no_itch(
    itch_bridge_config: BridgeConfig,
    catalog: ProductCatalog,
    issuer_identity: IssuerIdentity,
    ledger: Ledger,
) -> BridgeDeps:
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(None),
    )
    config = BridgeConfig(
        public_base_url=itch_bridge_config.public_base_url,
        ledger_path=itch_bridge_config.ledger_path,
        issuer=itch_bridge_config.issuer,
        products=itch_bridge_config.products,
        stripe=None,
        itch=None,
        delivery=None,
    )
    return BridgeDeps(
        config=config,
        core=core,
        ledger=ledger,
        stripe=None,
        log=logging.getLogger("test-bridge-itch-no-itch"),
        itch=None,
    )


def test_get_itch_claim_form_lists_configured_itch_games(itch_deps: BridgeDeps) -> None:
    app = make_app(itch_deps)
    status, headers, body = call_app(app, "GET", "/itch/claim")
    assert status.startswith("200")
    assert headers["Content-Type"].startswith("text/html")
    assert b"123456" in body


def test_itch_claim_form_shows_the_buyer_a_title_not_a_game_id(itch_deps: BridgeDeps) -> None:
    """The buyer picks from this dropdown. A merchant selling more than one
    title cannot expect them to recognise itch's numeric game id, and the
    catalog already carries the title."""
    app = make_app(itch_deps)
    _, _, body = call_app(app, "GET", "/itch/claim")

    assert b'<option value="123456">Nebula Drifters</option>' in body


def test_itch_claim_form_escapes_a_title_containing_markup(itch_deps: BridgeDeps) -> None:
    """A title is merchant-supplied text now rendered into a page served to
    that merchant's customers. It must arrive escaped however it was written —
    the label is new, the escaping must not be assumed."""
    product = itch_deps.config.products["itch_123456"]
    itch_deps.config.products["itch_123456"] = replace(
        product, title='</option><script>alert("xss")</script>'
    )
    app = make_app(itch_deps)

    _, _, body = call_app(app, "GET", "/itch/claim")

    assert b"<script>" not in body
    assert b"&lt;script&gt;" in body


def test_post_itch_claim_acknowledgement_is_identical_for_fresh_dedup_and_no_purchase(
    itch_deps: BridgeDeps,
) -> None:
    app = make_app(itch_deps)
    body = urlencode({"email": "buyer@example.com", "game_id": "123456"}).encode()
    status, _, fresh = call_app(
        app,
        "POST",
        "/itch/claim",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status.startswith("202")
    second_status, _, dedup = call_app(
        app,
        "POST",
        "/itch/claim",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    no_purchase_body = urlencode({"email": "nobody@example.com", "game_id": "123456"}).encode()
    third_status, _, no_purchase = call_app(
        app,
        "POST",
        "/itch/claim",
        body=no_purchase_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert second_status.startswith("202") and third_status.startswith("202")
    assert fresh == dedup == no_purchase
    assert json.loads(fresh) == {
        "status": "received",
        "detail": "If a matching itch.io purchase exists, its receipt will be emailed to the "
        "address you submitted.",
    }
    assert len(itch_deps.ledger.due_claims("2099-01-01T00:00:00Z")) == 2


def test_post_itch_claim_unknown_game_returns_400(itch_deps: BridgeDeps) -> None:
    app = make_app(itch_deps)
    body = urlencode({"email": "buyer@example.com", "game_id": "999999"}).encode()
    status, _, _ = call_app(
        app,
        "POST",
        "/itch/claim",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status.startswith("400")


def test_post_itch_claim_missing_fields_returns_400(itch_deps: BridgeDeps) -> None:
    app = make_app(itch_deps)
    status, _, _ = call_app(
        app,
        "POST",
        "/itch/claim",
        body=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status.startswith("400")


def test_post_itch_claim_rejects_cheaply_malformed_email(itch_deps: BridgeDeps) -> None:
    app = make_app(itch_deps)
    status, _, _ = call_app(
        app,
        "POST",
        "/itch/claim",
        body=urlencode({"email": "not-an-email", "game_id": "123456"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status.startswith("400")


def test_itch_claim_routes_refuse_to_enqueue_without_delivery(itch_deps: BridgeDeps) -> None:
    unavailable = replace(itch_deps.config, delivery=None)
    deps = replace(itch_deps, config=unavailable)
    status, _, body = call_app(
        make_app(deps),
        "POST",
        "/itch/claim",
        body=urlencode({"email": "buyer@example.com", "game_id": "123456"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status.startswith("503")
    assert json.loads(body) == {"error": "receipt delivery is not configured"}
    assert deps.ledger.due_claims("2099-01-01T00:00:00Z") == []


def test_post_itch_claim_returns_503_when_queue_is_full(
    itch_deps: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    from attest_bridge import ledger as ledger_mod

    monkeypatch.setattr(ledger_mod, "MAX_PENDING_CLAIMS", 1)
    itch_deps.ledger.enqueue_claim("other@example.com", "123456", now="2026-07-24T10:00:00Z")
    status, _, body = call_app(
        make_app(itch_deps),
        "POST",
        "/itch/claim",
        body=urlencode({"email": "buyer@example.com", "game_id": "123456"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status.startswith("503")
    assert json.loads(body) == {"error": "claim queue is full, retry later"}


def test_get_itch_claim_token_route_is_not_registered(itch_deps: BridgeDeps) -> None:
    app = make_app(itch_deps)
    status, _, body = call_app(app, "GET", "/itch/claim/does-not-exist-token")
    assert status.startswith("404")
    assert b"does-not-exist-token" not in body


def test_itch_claim_form_and_post_404_when_itch_not_configured(
    bridge_deps_no_itch: BridgeDeps,
) -> None:
    app = make_app(bridge_deps_no_itch)
    status, _, _ = call_app(app, "GET", "/itch/claim")
    assert status.startswith("404")
    status2, _, _ = call_app(
        app,
        "POST",
        "/itch/claim",
        body=urlencode({"email": "a@b.com", "game_id": "123456"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status2.startswith("404")


def test_salt_bearing_download_docs_set_umask_before_curl_output() -> None:
    docs_root = Path(__file__).parents[1] / "docs"
    for path in docs_root.glob("*.md"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"curl\b[^\n]*\s-o\s", text):
            preceding_lines = text[: match.start()].rstrip().splitlines()
            assert preceding_lines[-1] == "umask 077"


# -- itch-import CLI ------------------------------------------------------------


def _write_minimal_config(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: Any
) -> Path:
    seed_path = tmp_path / "issuer.seed"
    seed_path.write_text(keys.b64u(hybrid_keys.ed.seed) + "\n", encoding="utf-8")

    mldsa_path = tmp_path / "issuer.mldsa.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "key-manifest.json"
    manifest_path.write_text(json.dumps(key_manifest), encoding="utf-8")
    ledger_path = tmp_path / "ledger.sqlite3"

    config_text = f"""
public_base_url = "https://receipts.example.com"
ledger_path = "{ledger_path}"

[issuer]
id = "{ISSUER}"
display_name = "{DISPLAY_NAME}"
kid = "{KID}"
seed_path = "{seed_path}"
mldsa_key_path = "{mldsa_path}"
manifest_path = "{manifest_path}"
"""
    config_path = tmp_path / "bridge.toml"
    config_path.write_text(config_text, encoding="utf-8")
    return config_path


def test_itch_import_happy_path_enqueues_one_claim_per_unique_email(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = Ledger(ledger_path)  # held open across the CLI run, per T8 convention
    config_path = _write_minimal_config(tmp_path, hybrid_keys, key_manifest)
    csv_path = tmp_path / "purchases.csv"
    csv_path.write_text(
        "Email,Name\nbuyer1@example.com,A\nbuyer2@example.com,B\nbuyer1@example.com,A2\n",
        encoding="utf-8",
    )

    rc = cli.main(
        ["itch-import", "--config", str(config_path), "--game-id", "123456", str(csv_path)]
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "2" in out

    due = ledger.due_claims("2099-01-01T00:00:00Z")
    emails = sorted(c.email for c in due)
    assert emails == ["buyer1@example.com", "buyer2@example.com"]
    assert all(c.game_id == "123456" for c in due)
    assert all(c.status == "pending" for c in due)


def test_itch_import_is_case_insensitive_on_email_column_name(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = Ledger(ledger_path)
    config_path = _write_minimal_config(tmp_path, hybrid_keys, key_manifest)
    csv_path = tmp_path / "purchases.csv"
    csv_path.write_text("EMAIL,Name\nbuyer@example.com,A\n", encoding="utf-8")

    rc = cli.main(
        ["itch-import", "--config", str(config_path), "--game-id", "123456", str(csv_path)]
    )

    assert rc == 0
    due = ledger.due_claims("2099-01-01T00:00:00Z")
    assert [c.email for c in due] == ["buyer@example.com"]


def test_itch_import_missing_email_column_returns_rc_2(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_minimal_config(tmp_path, hybrid_keys, key_manifest)
    csv_path = tmp_path / "purchases.csv"
    csv_path.write_text("Name,Foo\nA,1\n", encoding="utf-8")

    rc = cli.main(
        ["itch-import", "--config", str(config_path), "--game-id", "123456", str(csv_path)]
    )

    assert rc == 2
    assert "email" in capsys.readouterr().err.lower()


def test_itch_import_csv_alone_never_issues_a_receipt(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
) -> None:
    # OI-4: intake is never issuance -- the CSV import must not touch
    # IssuingCore/receipts at all, only enqueue claims.
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = Ledger(ledger_path)
    config_path = _write_minimal_config(tmp_path, hybrid_keys, key_manifest)
    csv_path = tmp_path / "purchases.csv"
    csv_path.write_text("email\nbuyer@example.com\n", encoding="utf-8")

    rc = cli.main(
        ["itch-import", "--config", str(config_path), "--game-id", "123456", str(csv_path)]
    )

    assert rc == 0
    assert ledger.get_receipt("itch", "anything") is None
    due = ledger.due_claims("2099-01-01T00:00:00Z")
    assert len(due) == 1
    assert due[0].status == "pending"


def test_itch_import_reports_partial_progress_when_the_queue_fills(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from attest_bridge import ledger as ledger_mod

    monkeypatch.setattr(ledger_mod, "MAX_PENDING_CLAIMS", 2)
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    ledger.enqueue_claim("existing@example.com", "123456", now="2026-07-24T10:00:00Z")
    config_path = _write_minimal_config(tmp_path, hybrid_keys, key_manifest)
    csv_path = tmp_path / "purchases.csv"
    csv_path.write_text("email\nfirst@example.com\nsecond@example.com\n", encoding="utf-8")

    rc = cli.main(
        ["itch-import", "--config", str(config_path), "--game-id", "123456", str(csv_path)]
    )

    assert rc != 0
    assert "imported: 1; queue is full" in capsys.readouterr().err


def test_serve_does_not_start_a_delivery_sweeper_without_delivery(
    bridge_deps_no_itch: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Server:
        def __enter__(self) -> Server:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def serve_forever(self) -> None:
            return None

    monkeypatch.setattr(cli, "_build_deps", lambda _path, log: bridge_deps_no_itch)
    monkeypatch.setattr(cli, "make_server", lambda *args, **kwargs: Server())

    def unexpected_thread(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("delivery sweeper must not start without delivery")

    monkeypatch.setattr(cli.threading, "Thread", unexpected_thread)

    args = type("Args", (), {"config": "unused", "host": "127.0.0.1", "port": 0})()
    assert cli._cmd_serve(args) == 0


def test_itch_import_rc_2_on_config_error(tmp_path: Path) -> None:
    missing_config = tmp_path / "does-not-exist.toml"
    csv_path = tmp_path / "purchases.csv"
    csv_path.write_text("email\na@b.com\n", encoding="utf-8")
    rc = cli.main(
        ["itch-import", "--config", str(missing_config), "--game-id", "123456", str(csv_path)]
    )
    assert rc == 2
