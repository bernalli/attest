"""WSGI app tests: the pinned webhook error-handling
policy table, one test per row, plus the phase-defining E2E oracle —
signed webhook in, offline-`attest.verify`-passing envelope out, no mocks
anywhere on that path.
"""

from __future__ import annotations

import io
import json
import logging
import threading
from typing import Any

import pytest
from attest_bridge import http as http_mod
from attest_bridge.config import BridgeConfig, IssuerConfig, StripeConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.ledger import Ledger
from attest_bridge.signing import IssuerIdentity
from attest_bridge.stripe_adapter import StripeAdapter
from conftest import DISPLAY_NAME, ISSUER, KID
from test_bridge_stripe_adapter import make_session_completed_event, sign_stripe

from attest import verify as verify_mod

_WEBHOOK_SECRET = "whsec_test"  # noqa: S105 - test fixture, not a real secret
_FROZEN_NOW = 1_784_000_000


def call_app(
    app: Any,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    query: str = "",
) -> tuple[str, dict[str, str], bytes]:
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": io.StringIO(),
        "wsgi.url_scheme": "https",
        "SERVER_NAME": "test",
        "SERVER_PORT": "443",
        "SERVER_PROTOCOL": "HTTP/1.1",
    }
    for k, v in (headers or {}).items():
        key = k.upper().replace("-", "_")
        environ[key if key in ("CONTENT_TYPE", "CONTENT_LENGTH") else "HTTP_" + key] = v
    captured: dict[str, Any] = {}

    def start_response(status: str, response_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(response_headers)

    chunks = app(environ, start_response)
    return captured["status"], captured["headers"], b"".join(chunks)


# -- fixtures -----------------------------------------------------------


@pytest.fixture
def frozen_now(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr("attest_bridge.stripe_adapter.time.time", lambda: _FROZEN_NOW)
    return _FROZEN_NOW


@pytest.fixture
def bridge_config(tmp_path: Any) -> BridgeConfig:
    # Never dereferenced by http.py at request time (only IssuingCore/
    # StripeAdapter, already built, are) — placeholder paths are fine.
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
        products={},
        stripe=StripeConfig(webhook_secret=_WEBHOOK_SECRET, api_key=None),
        itch=None,
        delivery=None,
    )


@pytest.fixture
def deps(
    bridge_config: BridgeConfig,
    catalog: Any,
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
    stripe = StripeAdapter(webhook_secret=_WEBHOOK_SECRET, api_key=None)
    return BridgeDeps(
        config=bridge_config,
        core=core,
        ledger=ledger,
        stripe=stripe,
        log=logging.getLogger("test-bridge-http"),
    )


def _signed_webhook(deps: BridgeDeps, event: dict[str, Any]) -> tuple[str, dict[str, str], bytes]:
    body = json.dumps(event).encode()
    header = sign_stripe(body, _WEBHOOK_SECRET, _FROZEN_NOW)
    app = make_app(deps)
    return call_app(
        app,
        "POST",
        "/stripe/webhook",
        body=body,
        headers={"Stripe-Signature": header, "Content-Type": "application/json"},
    )


# -- the phase-defining E2E oracle ---------------------------------------


def test_e2e_signed_webhook_to_offline_verified_receipt(
    deps: BridgeDeps, trust_store: verify_mod.TrustStore, frozen_now: int
) -> None:
    event = make_session_completed_event(
        session_id="cs_e2e_1",
        email="buyer@example.com",
        metadata={"attest_product_key": "price_TEST"},
        created=1_784_000_000,
    )
    body = json.dumps(event).encode()
    header = sign_stripe(body, "whsec_test", ts=1_784_000_000)
    app = make_app(deps)
    status, _, _ = call_app(
        app,
        "POST",
        "/stripe/webhook",
        body=body,
        headers={"Stripe-Signature": header, "Content-Type": "application/json"},
    )
    assert status.startswith("200")
    stored = deps.ledger.get_receipt("stripe", "cs_e2e_1")
    assert stored is not None
    result = verify_mod.verify(stored.envelope_json.encode(), trust_store)
    assert result.ok is True  # webhook -> envelope -> offline verify, no mocks

    # replay: same event again -- no second receipt (idempotent, no reprocessing)
    status2, _, _ = call_app(
        app,
        "POST",
        "/stripe/webhook",
        body=body,
        headers={"Stripe-Signature": header, "Content-Type": "application/json"},
    )
    assert status2.startswith("200")
    replay_stored = deps.ledger.get_receipt("stripe", "cs_e2e_1")
    assert replay_stored == stored

    # download fallback works and round-trips the same envelope
    s, h, dl = call_app(app, "GET", "/r/" + stored.download_token)
    assert s.startswith("200")
    # /r/ returns the stored envelope bytes VERBATIM — a reserialization
    # regression (re-dumping with different key order/whitespace) must fail here,
    # not merely require the reparsed JSON to match.
    assert dl == stored.envelope_json.encode()
    assert json.loads(dl) == json.loads(stored.envelope_json)
    assert h["Content-Type"] == "application/json"
    assert h["Cache-Control"] == "no-store"
    assert h["Content-Disposition"] == f'attachment; filename="receipt-{stored.receipt_id}.attest"'

    s2, _, dl2 = call_app(app, "GET", "/stripe/receipt", query="session_id=cs_e2e_1")
    assert s2.startswith("200")
    assert dl2 == dl


# -- policy row: missing/invalid Stripe-Signature -> 400, no mark_event --


def test_missing_signature_header_returns_400_and_ledger_stays_empty(
    deps: BridgeDeps, frozen_now: int
) -> None:
    event = make_session_completed_event(metadata={"attest_product_key": "price_TEST"})
    app = make_app(deps)
    status, _, _ = call_app(app, "POST", "/stripe/webhook", body=json.dumps(event).encode())
    assert status.startswith("400")
    assert deps.ledger.seen_event("stripe", event["id"]) is False
    assert deps.ledger.get_receipt("stripe", event["data"]["object"]["id"]) is None


def test_forged_signature_returns_400_and_ledger_empty(deps: BridgeDeps, frozen_now: int) -> None:
    # Adversarial: a signature computed with the WRONG secret must never pass.
    event = make_session_completed_event(
        metadata={"attest_product_key": "price_TEST"}, created=_FROZEN_NOW
    )
    body = json.dumps(event).encode()
    forged_header = sign_stripe(body, "whsec_attacker_secret", _FROZEN_NOW)
    app = make_app(deps)
    status, _, _ = call_app(
        app, "POST", "/stripe/webhook", body=body, headers={"Stripe-Signature": forged_header}
    )
    assert status.startswith("400")
    assert deps.ledger.seen_event("stripe", event["id"]) is False
    assert deps.ledger.get_receipt("stripe", event["data"]["object"]["id"]) is None
    assert deps.ledger.unresolved_dead_letters() == []


# -- policy row: valid sig, unparseable JSON -> 400, no mark_event -------


def test_valid_signature_unparseable_json_returns_400(deps: BridgeDeps, frozen_now: int) -> None:
    body = b"{not valid json"
    header = sign_stripe(body, _WEBHOOK_SECRET, _FROZEN_NOW)
    app = make_app(deps)
    status, _, _ = call_app(
        app, "POST", "/stripe/webhook", body=body, headers={"Stripe-Signature": header}
    )
    assert status.startswith("400")


def test_valid_signature_non_utf8_body_returns_400(deps: BridgeDeps, frozen_now: int) -> None:
    # A correctly-signed but non-UTF-8 body: `json.loads` raises UnicodeDecodeError
    # (not JSONDecodeError). The "unparseable body -> 400" row must cover it too —
    # it must never escape the handler as a server-level 500.
    body = b"\xff\xfe not utf-8 at all"
    header = sign_stripe(body, _WEBHOOK_SECRET, _FROZEN_NOW)
    app = make_app(deps)
    status, _, _ = call_app(
        app, "POST", "/stripe/webhook", body=body, headers={"Stripe-Signature": header}
    )
    assert status.startswith("400")
    assert deps.ledger.unresolved_dead_letters() == []


# -- policy row: event type not handled / not paid -> 200, mark_event ---


def test_unhandled_event_type_returns_200_and_marks_event(
    deps: BridgeDeps, frozen_now: int
) -> None:
    event = make_session_completed_event(
        event_type="payment_intent.succeeded",
        metadata={"attest_product_key": "price_TEST"},
        created=_FROZEN_NOW,
    )
    status, _, _ = _signed_webhook(deps, event)
    assert status.startswith("200")
    assert deps.ledger.seen_event("stripe", event["id"]) is True
    assert deps.ledger.get_receipt("stripe", event["data"]["object"]["id"]) is None


def test_payment_status_not_paid_returns_200_and_marks_event(
    deps: BridgeDeps, frozen_now: int
) -> None:
    event = make_session_completed_event(
        payment_status="unpaid",
        metadata={"attest_product_key": "price_TEST"},
        created=_FROZEN_NOW,
    )
    status, _, _ = _signed_webhook(deps, event)
    assert status.startswith("200")
    assert deps.ledger.seen_event("stripe", event["id"]) is True
    assert deps.ledger.get_receipt("stripe", event["data"]["object"]["id"]) is None


# -- policy row: ledger.seen_event (replay) -> 200, no reprocessing ------


def test_replayed_event_id_returns_200_without_reprocessing(
    deps: BridgeDeps, frozen_now: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = make_session_completed_event(
        session_id="cs_replay", metadata={"attest_product_key": "price_TEST"}, created=_FROZEN_NOW
    )
    calls: list[int] = []
    original_process = deps.core.process

    def spy_process(purchase: Any) -> Any:
        calls.append(1)
        return original_process(purchase)

    monkeypatch.setattr(deps.core, "process", spy_process)

    body = json.dumps(event).encode()
    header = sign_stripe(body, _WEBHOOK_SECRET, _FROZEN_NOW)
    app = make_app(deps)
    headers = {"Stripe-Signature": header}
    status1, _, _ = call_app(app, "POST", "/stripe/webhook", body=body, headers=headers)
    status2, _, _ = call_app(app, "POST", "/stripe/webhook", body=body, headers=headers)

    assert status1.startswith("200")
    assert status2.startswith("200")
    assert len(calls) == 1


def test_concurrent_identical_webhooks_issue_exactly_one_receipt(
    deps: BridgeDeps, frozen_now: int
) -> None:
    # Two worker threads deliver the SAME signed event at once (Stripe retries
    # aggressively and the server is threaded). The webhook critical section is
    # serialized, so exactly one receipt is issued and BOTH requests return 200.
    # Without the lock the loser races past `seen_event` and dies with an
    # IntegrityError -> 500 on the duplicate insert.
    event = make_session_completed_event(
        session_id="cs_concurrent",
        metadata={"attest_product_key": "price_TEST"},
        created=_FROZEN_NOW,
    )
    body = json.dumps(event).encode()
    header = sign_stripe(body, _WEBHOOK_SECRET, _FROZEN_NOW)
    app = make_app(deps)

    barrier = threading.Barrier(2)
    results_lock = threading.Lock()
    statuses: list[str] = []

    def hit() -> None:
        barrier.wait()  # both threads enter the handler together -> real contention
        status, _, _ = call_app(
            app, "POST", "/stripe/webhook", body=body, headers={"Stripe-Signature": header}
        )
        with results_lock:
            statuses.append(status)

    threads = [threading.Thread(target=hit) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(statuses) == 2
    assert all(s.startswith("200") for s in statuses)  # no lost-race 500
    assert deps.ledger.get_receipt("stripe", "cs_concurrent") is not None


# -- policy row: PurchaseRejected/UnmappedProduct -> 200 + dead letter ---


def test_unmapped_product_dead_letters_and_returns_200(deps: BridgeDeps, frozen_now: int) -> None:
    event = make_session_completed_event(
        session_id="cs_unmapped",
        metadata={"attest_product_key": "price_UNKNOWN"},
        created=_FROZEN_NOW,
    )
    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("200")
    assert deps.ledger.get_receipt("stripe", "cs_unmapped") is None
    dead_letters = deps.ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0].platform == "stripe"
    assert json.loads(dead_letters[0].raw_json) == event
    assert deps.ledger.seen_event("stripe", event["id"]) is True


def test_missing_buyer_email_dead_letters_and_returns_200(
    deps: BridgeDeps, frozen_now: int
) -> None:
    event = make_session_completed_event(
        session_id="cs_no_email",
        email=None,
        metadata={"attest_product_key": "price_TEST"},
        created=_FROZEN_NOW,
    )
    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("200")
    assert deps.ledger.get_receipt("stripe", "cs_no_email") is None
    assert len(deps.ledger.unresolved_dead_letters()) == 1


def test_paid_event_missing_id_is_dead_lettered_and_acknowledged(
    deps: BridgeDeps, frozen_now: int
) -> None:
    event = make_session_completed_event(metadata={"attest_product_key": "price_TEST"})
    del event["id"]

    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("200")
    assert deps.ledger.unresolved_dead_letters()[0].reason == (
        "stripe event id is missing or not a non-empty string"
    )


def test_paid_event_with_non_object_customer_details_is_dead_lettered(
    deps: BridgeDeps, frozen_now: int, caplog: pytest.LogCaptureFixture
) -> None:
    event = make_session_completed_event(metadata={"attest_product_key": "price_TEST"})
    event["data"]["object"]["customer_details"] = "x"

    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("200")
    assert deps.ledger.seen_event("stripe", event["id"]) is True
    assert len(deps.ledger.unresolved_dead_letters()) == 1
    assert "cs_test_123" not in caplog.text
    assert "stripe event evt_test_1: dead-lettered" in caplog.text


@pytest.mark.parametrize("has_event_id", [False, True])
def test_paid_event_with_non_object_data_is_dead_lettered_and_acknowledged(
    deps: BridgeDeps, frozen_now: int, has_event_id: bool
) -> None:
    event = make_session_completed_event(metadata={"attest_product_key": "price_TEST"})
    event["data"] = "x"
    if not has_event_id:
        del event["id"]

    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("200")
    assert len(deps.ledger.unresolved_dead_letters()) == 1
    if has_event_id:
        assert deps.ledger.seen_event("stripe", "evt_test_1") is True


def test_multiple_stripe_line_items_dead_letter_without_issuing(
    deps: BridgeDeps, frozen_now: int
) -> None:
    def line_items(url: str, headers: dict[str, str]) -> bytes:
        return json.dumps(
            {"data": [{"price": {"id": "price_TEST"}}, {"price": {"id": "x"}}]}
        ).encode()

    deps.stripe = StripeAdapter(
        webhook_secret=_WEBHOOK_SECRET, api_key="sk_test", http_get=line_items
    )
    event = make_session_completed_event(
        session_id="cs_two_items", metadata={"attest_product_key": "price_TEST"}
    )
    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("200")
    assert deps.ledger.get_receipt("stripe", "cs_two_items") is None
    assert deps.ledger.unresolved_dead_letters()[0].reason == (
        "checkout session contains multiple line items; the bridge issues one receipt per purchase"
    )


def test_line_items_fetch_happens_before_the_webhook_lock(
    deps: BridgeDeps, frozen_now: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    class InspectableLock:
        def __init__(self) -> None:
            self.locked = False

        def __enter__(self) -> None:
            assert not self.locked
            self.locked = True

        def __exit__(self, *args: object) -> None:
            self.locked = False

    lock = InspectableLock()

    def line_items(url: str, headers: dict[str, str]) -> bytes:
        assert lock.locked is False
        return json.dumps({"data": [{"price": {"id": "price_TEST"}}]}).encode()

    monkeypatch.setattr(http_mod.threading, "Lock", lambda: lock)
    deps.stripe = StripeAdapter(
        webhook_secret=_WEBHOOK_SECRET, api_key="sk_test", http_get=line_items
    )
    event = make_session_completed_event(session_id="cs_fetch_outside_lock", metadata={})

    assert _signed_webhook(deps, event)[0].startswith("200")
    assert deps.ledger.get_receipt("stripe", "cs_fetch_outside_lock") is not None


# -- policy row: duplicate purchase (receipt exists) -> 200, mark_event --


def test_duplicate_purchase_across_two_events_reuses_receipt(
    deps: BridgeDeps, frozen_now: int
) -> None:
    session_id = "cs_dup_events"
    event1 = make_session_completed_event(
        session_id=session_id,
        metadata={"attest_product_key": "price_TEST"},
        created=_FROZEN_NOW,
        event_id="evt_a",
        event_type="checkout.session.completed",
    )
    event2 = make_session_completed_event(
        session_id=session_id,
        metadata={"attest_product_key": "price_TEST"},
        created=_FROZEN_NOW,
        event_id="evt_b",
        event_type="checkout.session.async_payment_succeeded",
    )
    status1, _, _ = _signed_webhook(deps, event1)
    status2, _, _ = _signed_webhook(deps, event2)

    assert status1.startswith("200")
    assert status2.startswith("200")
    stored = deps.ledger.get_receipt("stripe", session_id)
    assert stored is not None
    assert deps.ledger.seen_event("stripe", "evt_a") is True
    assert deps.ledger.seen_event("stripe", "evt_b") is True


# -- policy row: success -> 200, mark_event ------------------------------


def test_success_issues_receipt_marks_event_and_returns_200(
    deps: BridgeDeps, frozen_now: int
) -> None:
    event = make_session_completed_event(
        session_id="cs_success", metadata={"attest_product_key": "price_TEST"}, created=_FROZEN_NOW
    )
    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("200")
    assert deps.ledger.get_receipt("stripe", "cs_success") is not None
    assert deps.ledger.seen_event("stripe", event["id"]) is True


# -- policy row: IssueError/ConfigError/unexpected Exception -> 500 -----


def _stripe_adapter_whose_line_items_raise(status: int) -> StripeAdapter:
    def line_items(url: str, headers: dict[str, str]) -> bytes:
        import urllib.error

        raise urllib.error.HTTPError(url, status, "err", {}, None)  # type: ignore[arg-type]

    return StripeAdapter(webhook_secret=_WEBHOOK_SECRET, api_key="sk_test", http_get=line_items)


@pytest.mark.parametrize("status", [429, 500, 503])
def test_transient_stripe_api_failure_returns_500_without_dead_lettering(
    deps: BridgeDeps, frozen_now: int, status: int
) -> None:
    """The asymmetry that protects a receipt, asserted at the WSGI boundary and
    not only in the adapter: a transient Stripe API failure must surface as a
    500 so Stripe redelivers. Dead-lettering it would acknowledge the event,
    stop redelivery, and lose the receipt until someone noticed."""
    deps.stripe = _stripe_adapter_whose_line_items_raise(status)
    event = make_session_completed_event(session_id="cs_transient", metadata={})

    http_status, _, _ = _signed_webhook(deps, event)

    assert http_status.startswith("500")
    assert deps.ledger.seen_event("stripe", event["id"]) is False
    assert deps.ledger.unresolved_dead_letters() == []
    assert deps.ledger.get_receipt("stripe", "cs_transient") is None


@pytest.mark.parametrize("status", [401, 403])
def test_permanent_stripe_api_failure_dead_letters_and_returns_200(
    deps: BridgeDeps, frozen_now: int, status: int
) -> None:
    """The other half of the same invariant: a misconfigured or revoked API key
    never fixes itself by redelivery, so it is acknowledged once with a readable
    reason and replayed later with `retry-failed`."""
    deps.stripe = _stripe_adapter_whose_line_items_raise(status)
    event = make_session_completed_event(session_id="cs_permanent", metadata={})

    http_status, _, _ = _signed_webhook(deps, event)

    assert http_status.startswith("200")
    assert deps.ledger.seen_event("stripe", event["id"]) is True
    dead_letters = deps.ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert str(status) in dead_letters[0].reason
    assert deps.ledger.get_receipt("stripe", "cs_permanent") is None


def test_unexpected_core_exception_returns_500_and_does_not_mark_event(
    deps: BridgeDeps, frozen_now: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(purchase: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(deps.core, "issue_for", boom)
    event = make_session_completed_event(
        session_id="cs_boom", metadata={"attest_product_key": "price_TEST"}, created=_FROZEN_NOW
    )
    status, _, _ = _signed_webhook(deps, event)

    assert status.startswith("500")
    assert deps.ledger.seen_event("stripe", event["id"]) is False
    assert deps.ledger.get_receipt("stripe", "cs_boom") is None


# -- other routes ---------------------------------------------------------


def test_healthz_returns_200_ok(deps: BridgeDeps) -> None:
    app = make_app(deps)
    status, _, body = call_app(app, "GET", "/healthz")
    assert status.startswith("200")
    assert json.loads(body) == {"ok": True}


def test_unknown_download_token_returns_uniform_404(deps: BridgeDeps) -> None:
    app = make_app(deps)
    status, _, body = call_app(app, "GET", "/r/does-not-exist-token")
    assert status.startswith("404")
    assert b"does-not-exist-token" not in body


def test_unknown_stripe_receipt_session_id_returns_uniform_404(deps: BridgeDeps) -> None:
    app = make_app(deps)
    status, _, body = call_app(app, "GET", "/stripe/receipt", query="session_id=cs_missing")
    assert status.startswith("404")
    assert b"cs_missing" not in body


def test_stripe_receipt_without_session_id_returns_404(deps: BridgeDeps) -> None:
    app = make_app(deps)
    status, _, _ = call_app(app, "GET", "/stripe/receipt")
    assert status.startswith("404")


def test_unknown_route_returns_404(deps: BridgeDeps) -> None:
    app = make_app(deps)
    status, _, _ = call_app(app, "GET", "/nonexistent")
    assert status.startswith("404")


def test_stripe_webhook_returns_404_when_stripe_not_configured(
    catalog: Any, issuer_identity: IssuerIdentity, ledger: Ledger, bridge_config: BridgeConfig
) -> None:
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(None),
    )
    deps_no_stripe = BridgeDeps(
        config=bridge_config,
        core=core,
        ledger=ledger,
        stripe=None,
        log=logging.getLogger("test-bridge-http-no-stripe"),
    )
    app = make_app(deps_no_stripe)
    status, _, _ = call_app(app, "POST", "/stripe/webhook", body=b"{}")
    assert status.startswith("404")
