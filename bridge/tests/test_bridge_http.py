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
import zipfile
from pathlib import Path
from typing import Any

import pytest
from attest_bridge import http as http_mod
from attest_bridge.config import BridgeConfig, IssuerConfig, StripeConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.ledger import Ledger, StoredReceipt
from attest_bridge.signing import IssuerIdentity
from attest_bridge.stripe_adapter import StripeAdapter
from conftest import DISPLAY_NAME, ISSUER, KID, LEGAL_TEXT_SHA256
from test_bridge_stripe_adapter import make_session_completed_event, sign_stripe

from attest import bundle, keys
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


_EXTERNAL_MARKERS = (
    # tags that fetch by themselves; <style> is allowed, what it CONTAINS is not
    "<link",
    "<script",
    "<img",
    "<iframe",
    "<object",
    "<embed",
    "<video",
    "<audio",
    "<source",
    # attributes and css constructs that fetch
    "srcset=",
    "@font-face",
    "@import",
    "url(",
    # absolute and protocol-relative urls (protocol-relative carries no scheme,
    # so the http:// / https:// markers never see it)
    "http://",
    "https://",
    '="//',
    "='//",
)


def assert_offline_self_contained(page: bytes) -> None:
    """Fail if a served bridge page reaches outside itself for anything.

    Case-insensitive on purpose: a browser accepts <SCRIPT SRC=...> and
    src="//cdn/..." just as happily as the lowercase, schemeful spellings,
    so a guard that only knows those proves its own assumptions, not the
    page. The core suite proves this property for `render_page` around a
    FAKE body (tests/test_buyer_surface.py); these are the REAL bodies the
    bridge injects, which that test never sees.
    """
    text = page.decode("utf-8").lower()
    for marker in _EXTERNAL_MARKERS:
        assert marker not in text, f"served page depends on the outside: {marker!r}"


@pytest.mark.parametrize(
    "poison",
    [
        # the polite forms
        '<link rel="stylesheet" href="style.css">',
        '<script src="app.js"></script>',
        '<img src="logo.png">',
        '<a href="http://example.com">x</a>',
        '<a href="https://example.com">x</a>',
        "<style>@font-face{font-family:x;src:local(x)}</style>",
        "<style>body{background:url(x.png)}</style>",
        # the hostile spellings a case-sensitive guard would wave through
        '<SCRIPT SRC="app.js"></SCRIPT>',
        '<IMG SRC="logo.png">',
        "<STYLE>BODY{BACKGROUND:URL(X.PNG)}</STYLE>",
        # protocol-relative: no http://, no https://, fetches all the same
        '<a href="//cdn.example.com/x">x</a>',
        "<a href='//cdn.example.com/x'>x</a>",
        # fetching tags and attributes the naive marker list ignores
        '<iframe src="frame.html"></iframe>',
        '<object data="movie.swf"></object>',
        '<video src="clip.mp4"></video>',
        '<source srcset="hero.png 1x, hero-2x.png 2x">',
        "<style>@import 'other.css';</style>",
    ],
)
def test_the_self_containment_guard_actually_fires(poison: str) -> None:
    page = f"<!doctype html><html><body>{poison}</body></html>".encode()
    with pytest.raises(AssertionError):
        assert_offline_self_contained(page)


# -- fixtures -----------------------------------------------------------


@pytest.fixture
def frozen_now(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr("attest_bridge.stripe_adapter.time.time", lambda: _FROZEN_NOW)
    return _FROZEN_NOW


@pytest.fixture
def bridge_config(tmp_path: Any, legal_texts: dict[str, bytes]) -> BridgeConfig:
    # The PATHS are never dereferenced by http.py at request time (only
    # IssuingCore/StripeAdapter, already built, are), so placeholders are fine
    # — but `legal_texts` IS read on every download: the shareable half of the
    # pair ships the licence text the receipt hashes (§14.1).
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
        legal_texts=dict(legal_texts),
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
    deps: BridgeDeps, trust_store: verify_mod.TrustStore, frozen_now: int, tmp_path: Path
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

    # Download fallback: the buyer gets the §14.1/§14.2 pair, and the oracle
    # is what they can DO with it — import both halves and verify the receipt
    # offline, binding proven from the salt that travelled in the private one.
    # (Before V-A.3 this section pinned the stored envelope byte-for-byte,
    # which is exactly the salt-bearing file a shareable name must not carry.)
    s, h, share = call_app(app, "GET", "/r/" + stored.download_token, query="part=receipt")
    assert s.startswith("200")
    assert h["Content-Type"] == "application/zip"
    assert h["Cache-Control"] == "no-store"
    assert h["Content-Disposition"].endswith('.attest"')
    assert not h["Content-Disposition"].endswith('.private.attest"')

    s2, h2, private = call_app(app, "GET", "/r/" + stored.download_token, query="part=private")
    assert s2.startswith("200")
    assert h2["Content-Disposition"].endswith('.private.attest"')

    share_path = tmp_path / "buyer.attest"
    private_path = tmp_path / "buyer.private.attest"
    share_path.write_bytes(share)
    private_path.write_bytes(private)
    imported = bundle.import_bundle(share_path, private_path)
    assert len(imported.receipts) == 1
    receipt = imported.receipts[0]
    assert receipt["payload"]["receipt_id"] == stored.receipt_id
    offline = verify_mod.verify(json.dumps(receipt).encode("utf-8"), imported.trust_store)
    assert offline.ok is True
    bound = verify_mod.verify(
        json.dumps(receipt).encode("utf-8"),
        imported.trust_store,
        disclosure=verify_mod.Disclosure(
            identifier="buyer@example.com",
            identifier_type="email",
            salt=imported.salts[stored.receipt_id],
        ),
    )
    assert bound.binding == "proven"

    # The same pair, semantically, from the session-id surface.
    s3, h3, share2 = call_app(
        app, "GET", "/stripe/receipt", query="session_id=cs_e2e_1&part=receipt"
    )
    assert s3.startswith("200")
    assert h3["Content-Disposition"] == h["Content-Disposition"]
    share2_path = tmp_path / "buyer-2.attest"
    share2_path.write_bytes(share2)
    assert bundle.import_bundle(share2_path).receipts == imported.receipts


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


# -- the receipt pair on every download surface (V-A.3) --------------------
#
# `IssuingCore` records ONE envelope and it is always salt-bearing: it has to
# be, the buyer needs their own salt to prove the receipt is theirs (§8). What
# the download routes may hand out is a different question, and until V-A.3
# they handed out that envelope verbatim under `receipt-<id>.attest` — a name
# §14.1 reserves for the salt-FREE half. A buyer forwarding "their receipt"
# forwarded their own bearer proof. These tests pin the pair on every surface.

_DOWNLOAD_SESSION = "cs_dl_1"


@pytest.fixture
def issued(deps: BridgeDeps, frozen_now: int) -> StoredReceipt:
    event = make_session_completed_event(
        session_id=_DOWNLOAD_SESSION,
        email="buyer@example.com",
        metadata={"attest_product_key": "price_TEST"},
        created=_FROZEN_NOW,
    )
    status, _, _ = _signed_webhook(deps, event)
    assert status.startswith("200")
    stored = deps.ledger.get_receipt("stripe", _DOWNLOAD_SESSION)
    assert stored is not None
    return stored


def _salt_b64u(stored: StoredReceipt) -> str:
    salt = json.loads(stored.envelope_json)["delivery"]["salt"]
    assert isinstance(salt, str) and salt
    return salt


def _pair_name(stored: StoredReceipt) -> str:
    # `merchant.example.com` slugged, per pair.build_pair's naming rule.
    return f"merchant-example-com-{stored.receipt_id}"


def _token_url(stored: StoredReceipt) -> str:
    return "/r/" + stored.download_token


def test_download_landing_names_both_halves_and_marks_the_private_one(
    deps: BridgeDeps, issued: StoredReceipt
) -> None:
    app = make_app(deps)
    status, headers, body = call_app(app, "GET", _token_url(issued))

    assert status.startswith("200")
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"

    page = body.decode("utf-8")
    name = _pair_name(issued)
    shareable_at = page.index(f"{name}.attest")
    private_at = page.index(f"{name}.private.attest")
    # Shareable first, exactly as the email body orders the two attachments:
    # the buyer meets the safe file before the secret one.
    assert shareable_at < private_at
    # And the warning sits AFTER the private filename — a caveat above the
    # thing it warns about is one the reader never connects to it.
    assert "never" in page[private_at:].lower()

    assert 'href="?part=receipt"' in page
    assert 'href="?part=private"' in page
    # The page never echoes the capability that reached it: the token is
    # already in the address bar, and page source gets copied around.
    assert issued.download_token not in page
    assert _salt_b64u(issued) not in page


def test_download_part_receipt_is_a_salt_free_bundle(
    deps: BridgeDeps, issued: StoredReceipt
) -> None:
    app = make_app(deps)
    status, headers, body = call_app(app, "GET", _token_url(issued), query="part=receipt")

    assert status.startswith("200")
    assert headers["Content-Type"] == "application/zip"
    assert headers["Cache-Control"] == "no-store"
    name = _pair_name(issued)
    assert headers["Content-Disposition"] == f'attachment; filename="{name}.attest"'

    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        assert set(zf.namelist()) == {
            f"receipts/{issued.receipt_id}.attest.json",
            f"manifests/{ISSUER}.json",
            f"legal/{LEGAL_TEXT_SHA256}.txt",
            "README.html",
        }
        receipt = json.loads(zf.read(f"receipts/{issued.receipt_id}.attest.json"))
        assert "salt" not in receipt.get("delivery", {})
        # The embedded manifest survives the strip: that is what keeps the
        # extracted receipt verifiable on its own.
        assert isinstance(receipt["delivery"]["issuer_manifest"], dict)


def test_download_part_private_carries_the_salt_under_the_private_name(
    deps: BridgeDeps, issued: StoredReceipt
) -> None:
    app = make_app(deps)
    status, headers, body = call_app(app, "GET", _token_url(issued), query="part=private")

    assert status.startswith("200")
    assert headers["Content-Type"] == "application/zip"
    assert headers["Cache-Control"] == "no-store"
    name = _pair_name(issued)
    assert headers["Content-Disposition"] == f'attachment; filename="{name}.private.attest"'
    assert headers["Content-Disposition"].endswith('.private.attest"')

    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        assert zf.namelist() == ["salts.json"]
        assert json.loads(zf.read("salts.json")) == {issued.receipt_id: _salt_b64u(issued)}


@pytest.mark.parametrize("part", ["", "receipts", "PRIVATE", "salts.json", "../private"])
def test_download_unknown_part_is_a_uniform_404(
    deps: BridgeDeps, issued: StoredReceipt, part: str
) -> None:
    app = make_app(deps)
    status, _, body = call_app(app, "GET", _token_url(issued), query=f"part={part}")
    assert status.startswith("404")
    assert body == b'{"error":"not found"}'


@pytest.mark.parametrize("query", ["", "part=receipt", "part=private"])
def test_unknown_download_token_stays_a_uniform_404_on_every_part(
    deps: BridgeDeps, query: str
) -> None:
    app = make_app(deps)
    status, _, body = call_app(app, "GET", "/r/does-not-exist-token", query=query)
    assert status.startswith("404")
    assert b"does-not-exist-token" not in body
    assert body == b'{"error":"not found"}'


def test_stripe_receipt_landing_links_via_session_id_not_download_token(
    deps: BridgeDeps, issued: StoredReceipt
) -> None:
    """`/stripe/receipt` is reached with a Stripe session id, not a download
    token. Its landing must keep using the capability the caller already
    holds — translating one capability into another hands the visitor a
    credential they did not arrive with."""
    app = make_app(deps)
    status, headers, body = call_app(
        app, "GET", "/stripe/receipt", query=f"session_id={_DOWNLOAD_SESSION}"
    )

    assert status.startswith("200")
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    page = body.decode("utf-8")
    assert f'href="?session_id={_DOWNLOAD_SESSION}&amp;part=receipt"' in page
    assert f'href="?session_id={_DOWNLOAD_SESSION}&amp;part=private"' in page
    assert issued.download_token not in page
    assert _salt_b64u(issued) not in page


def test_stripe_receipt_parts_serve_the_same_pair(deps: BridgeDeps, issued: StoredReceipt) -> None:
    app = make_app(deps)
    name = _pair_name(issued)

    _, share_headers, share_body = call_app(
        app, "GET", "/stripe/receipt", query=f"session_id={_DOWNLOAD_SESSION}&part=receipt"
    )
    assert share_headers["Content-Disposition"] == f'attachment; filename="{name}.attest"'

    _, priv_headers, priv_body = call_app(
        app, "GET", "/stripe/receipt", query=f"session_id={_DOWNLOAD_SESSION}&part=private"
    )
    assert priv_headers["Content-Disposition"] == f'attachment; filename="{name}.private.attest"'

    # Semantic equivalence with the token surface, not byte equality: zip
    # containers carry timestamps and ordering details worth nothing here.
    with zipfile.ZipFile(io.BytesIO(share_body)) as zf:
        assert f"receipts/{issued.receipt_id}.attest.json" in zf.namelist()
    with zipfile.ZipFile(io.BytesIO(priv_body)) as zf:
        assert json.loads(zf.read("salts.json")) == {issued.receipt_id: _salt_b64u(issued)}


@pytest.mark.parametrize("query", ["", "part=receipt", "part=private"])
def test_download_pair_build_failure_is_a_500_never_the_salted_envelope(
    deps: BridgeDeps, issued: StoredReceipt, query: str
) -> None:
    """Fail closed. The shareable half cannot be built without the licence
    text the receipt hashes, and the only other thing this route could serve
    is the salted envelope — which is precisely the defect. So: 500."""
    deps.config.legal_texts.clear()
    app = make_app(deps)

    status, _, body = call_app(app, "GET", _token_url(issued), query=query)

    assert status.startswith("500")
    assert _salt_b64u(issued).encode() not in body
    assert issued.envelope_json.encode() not in body
    assert b"issuer_manifest" not in body


def test_no_route_serves_salt_bytes_under_a_shareable_name(
    deps: BridgeDeps, issued: StoredReceipt
) -> None:
    """The structural regression this whole task exists to close.

    A byte-scan of a zip container proves nothing — members are DEFLATE
    compressed, so a salt sitting inside one would not show up in the
    container's bytes. Every zip response is therefore opened and each member
    decompressed. The salt may leave ONLY under a `.private.attest` filename.
    """
    app = make_app(deps)
    salt_b64u = _salt_b64u(issued)
    needles = [salt_b64u.encode(), keys.b64u_decode(salt_b64u)]

    requests = [
        (_token_url(issued), ""),
        (_token_url(issued), "part=receipt"),
        (_token_url(issued), "part=private"),
        ("/stripe/receipt", f"session_id={_DOWNLOAD_SESSION}"),
        ("/stripe/receipt", f"session_id={_DOWNLOAD_SESSION}&part=receipt"),
        ("/stripe/receipt", f"session_id={_DOWNLOAD_SESSION}&part=private"),
    ]

    private_responses = 0
    shareable_responses = 0
    for path, query in requests:
        status, headers, body = call_app(app, "GET", path, query=query)
        assert status.startswith("200"), (path, query, status)
        disposition = headers.get("Content-Disposition", "")
        if disposition.endswith('.private.attest"'):
            private_responses += 1
            continue
        shareable_responses += 1
        for needle in needles:
            assert needle not in body, (path, query)
        if body[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(body)) as zf:
                members = zf.namelist()
                assert members
                for member in members:
                    content = zf.read(member)
                    for needle in needles:
                        assert needle not in content, (path, query, member)
                    if member.endswith(".json"):
                        decoded = json.loads(content)
                        block = decoded.get("delivery") if isinstance(decoded, dict) else None
                        assert not (isinstance(block, dict) and "salt" in block)

    assert private_responses == 2
    assert shareable_responses == 4
