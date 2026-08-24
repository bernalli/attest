"""Stdlib WSGI app: Stripe webhook endpoint + receipt-download routes + the
itch claim-queue endpoints.

Contract: this module is the integration point between the
platform adapters (T7's `StripeAdapter`) and `IssuingCore` (T5) — it owns the
webhook error-handling policy (the design's "what happens on every kind of
failure" section, made executable) and never invents behavior the policy
table doesn't pin.

The `/itch/claim` routes (T9, OI-4) are a different shape entirely: itch has
no webhook, so these routes only ever enqueue Ledger claim rows — never
call `IssuingCore.process`. See `itch_adapter.py`'s module docstring for the
full claim-queue design and why the API response (fetched later, by
`ItchPoller.tick`) is the sole issuance authority.

Webhook handler policy (PINNED — `mark_event` only on the rows marked with a
side effect other than "already"/none):

| Condition                                   | HTTP | mark_event |
|----------------------------------------------|------|------------|
| Missing/invalid `Stripe-Signature`            | 400  | no         |
| Valid sig, unparseable JSON                   | 400  | no         |
| Event type not handled / not `payment_status  | 200  | yes        |
|   == "paid"`                                  |      |            |
| `ledger.seen_event` (replay)                  | 200  | already    |
| `PurchaseRejected` / `UnmappedProduct`        | 200  | yes (+ dead letter) |
| Duplicate purchase (receipt exists)          | 200  | yes        |
| Success                                       | 200  | yes        |
| `StripeApiError` (transient upstream failure) | 500  | NO — fail closed, Stripe retries |
| `IssueError`/`ConfigError`/unexpected `Exception` | 500 | NO — fail closed, Stripe retries |

The 500 row is the one that matters most: a signing/config/unexpected
failure must never be acknowledged, or Stripe will never retry it and the
purchase is silently lost. Every other terminal state — including a
permanently-bad purchase (dead-lettered) — gets a 200 so Stripe stops
retrying something that will never succeed.

Never logged, anywhere in this module: a download token, a Stripe session id,
a salt, a secret, or a full envelope. A Stripe session id is a receipt
capability: it is retained in the dead-letter row for operator recovery and
never emitted to a log.
"""

from __future__ import annotations

import html
import json
import logging
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import parse_qs

from attest_bridge.config import BridgeConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.itch_adapter import ItchAdapter
from attest_bridge.ledger import Ledger, StoredReceipt
from attest_bridge.model import (
    ClaimQueueFull,
    NormalizedPurchase,
    PurchaseRejected,
    UnmappedProduct,
)
from attest_bridge.shopify_adapter import ShopifyAdapter, ShopifySignatureError
from attest_bridge.stripe_adapter import StripeAdapter, StripeSignatureError

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
_NOT_FOUND_BODY = b'{"error":"not found"}'
_ITCH_PRODUCT_PREFIX = "itch_"
_ITCH_CLAIM_ACCEPTED = {
    "status": "received",
    "detail": "If a matching itch.io purchase exists, its receipt will be emailed to the "
    "address you submitted.",
}

WSGIApp = Callable[[dict[str, Any], Any], Iterable[bytes]]


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime(_RFC3339)


@dataclass
class BridgeDeps:
    config: BridgeConfig
    core: IssuingCore
    ledger: Ledger
    stripe: StripeAdapter | None
    log: logging.Logger
    # Default None so existing (pre-T9) `BridgeDeps(...)` construction sites
    # keep working unchanged — purely additive, mirrors `stripe`'s optionality.
    itch: ItchAdapter | None = None
    delivery: Delivery | None = None
    shopify: ShopifyAdapter | None = None


# -- WSGI response helpers ---------------------------------------------------


def _json_response(start_response: Any, status: str, payload: dict[str, Any]) -> Iterable[bytes]:
    body = json.dumps(payload).encode("utf-8")
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    start_response(status, headers)
    return [body]


def _plain_response(start_response: Any, status: str, body: bytes) -> Iterable[bytes]:
    headers = [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))]
    start_response(status, headers)
    return [body]


def _not_found(start_response: Any) -> Iterable[bytes]:
    # Uniform body for every 404 in this module — a download token or Stripe
    # session_id must never be echoed back, valid or not.
    headers = [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(_NOT_FOUND_BODY))),
    ]
    start_response("404 Not Found", headers)
    return [_NOT_FOUND_BODY]


def _receipt_response(start_response: Any, stored: StoredReceipt) -> Iterable[bytes]:
    body = stored.envelope_json.encode("utf-8")
    headers = [
        ("Content-Type", "application/json"),
        ("Content-Disposition", f'attachment; filename="receipt-{stored.receipt_id}.attest"'),
        ("Cache-Control", "no-store"),
        ("Content-Length", str(len(body))),
    ]
    start_response("200 OK", headers)
    return [body]


def _read_body(environ: dict[str, Any]) -> bytes:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length <= 0:
        return b""
    stream: Any = environ.get("wsgi.input")
    data: bytes = stream.read(length)
    return data


def _parse_query(query_string: str) -> dict[str, str]:
    parsed = parse_qs(query_string, keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items() if values}


def _best_effort_purchase_id(event: object) -> str | None:
    """Extract a session/purchase id from a raw event for dead-letter operator
    visibility only — never load-bearing (the dead letter's `raw_json` is the
    authoritative record `retry-failed` re-drives from)."""
    if not isinstance(event, dict):
        return None
    data = event.get("data")
    if not isinstance(data, dict):
        return None
    session = data.get("object")
    if not isinstance(session, dict):
        return None
    session_id = session.get("id")
    return session_id if isinstance(session_id, str) else None


# -- stripe webhook -----------------------------------------------------------


def _handle_stripe_webhook(
    deps: BridgeDeps, environ: dict[str, Any], start_response: Any, lock: threading.Lock
) -> Iterable[bytes]:
    stripe = deps.stripe
    if stripe is None:
        # No [stripe] section configured: this route simply doesn't exist.
        return _not_found(start_response)

    body = _read_body(environ)
    sig_header = environ.get("HTTP_STRIPE_SIGNATURE") or ""
    if not sig_header:
        deps.log.warning("stripe webhook: missing Stripe-Signature header")
        return _plain_response(start_response, "400 Bad Request", b"missing signature")

    try:
        event = stripe.parse_event(body, sig_header, now=None)
    except StripeSignatureError:
        deps.log.warning("stripe webhook: signature verification failed")
        return _plain_response(start_response, "400 Bad Request", b"invalid signature")
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Signature valid but the body is not parseable JSON — including a body
        # that is not even valid UTF-8 (`json.loads(b"\xff")` raises
        # UnicodeDecodeError, not JSONDecodeError). Both are the pinned
        # "unparseable body -> 400" row; neither must escape as a 500.
        deps.log.error("stripe webhook: signature valid but body is not parseable JSON")
        return _plain_response(start_response, "400 Bad Request", b"malformed body")

    if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not event["id"]:
        # There is no usable event id to persist in `events`, but this validly
        # signed malformed input can never succeed. Dead-letter it and return
        # 200 so Stripe does not retry it forever.
        raw_event = event if isinstance(event, dict) else {"event": event}
        deps.ledger.add_dead_letter(
            "stripe",
            _best_effort_purchase_id(raw_event),
            "stripe event id is missing or not a non-empty string",
            json.dumps(event),
            now=_now_rfc3339(),
        )
        return _json_response(start_response, "200 OK", {"ok": True})
    event_id = event["id"]
    # Serialize the check-then-act critical section (seen_event -> issue/record
    # -> mark_event, and the delivery inside `core.process`) across the server's
    # worker threads. The Ledger's own lock makes each statement atomic, NOT
    # this whole workflow — so without this, two concurrent deliveries of the
    # same event (Stripe retries aggressively) could both pass `seen_event` and
    # then double-issue / double-deliver. One lock per app process is sufficient:
    # a self-hosted merchant bridge is single-process and low-volume; the sig
    # verify + JSON parse above stay outside the lock (read-only, no shared
    # state). Cross-process concurrency is out of scope (see `cli.py`).
    # Advisory pre-check only. It avoids needless API fetches on ordinary
    # replays but may race; the lock below remains authoritative.
    if deps.ledger.seen_event("stripe", event_id):
        return _json_response(start_response, "200 OK", {"ok": True})

    purchase: NormalizedPurchase | None = None
    try:
        actionable = stripe.wants(event)
        if actionable:
            # This may fetch Stripe line items. It must stay outside the
            # webhook lock so a slow upstream cannot stall every webhook.
            purchase = stripe.normalize(event)
    except (PurchaseRejected, UnmappedProduct, KeyError, TypeError, AttributeError) as exc:
        with lock:
            if deps.ledger.seen_event("stripe", event_id):
                return _json_response(start_response, "200 OK", {"ok": True})
            # Permanently-bad input: dead-letter for operator triage and mark the
            # event seen — Stripe must not retry something that will never
            # succeed. `raw_json` is the whole event, so `retry-failed` can
            # re-normalize it once the merchant fixes the catalog/config.
            purchase_id = (
                purchase.platform_purchase_id
                if purchase is not None
                else _best_effort_purchase_id(event)
            )
            deps.ledger.add_dead_letter(
                "stripe", purchase_id, str(exc), json.dumps(event), now=_now_rfc3339()
            )
            deps.ledger.mark_event("stripe", event_id, now=_now_rfc3339())
            deps.log.error("stripe event %s: dead-lettered", event_id)
            return _json_response(start_response, "200 OK", {"ok": True})
    except Exception:
        # Transient upstream failure (a Stripe API error, a network fault) or an
        # unexpected one: fail closed exactly as the post-lock row does. NEVER
        # mark_event and never dead-letter — Stripe must redeliver, or the
        # receipt is lost. Without this row the exception escaped the app and
        # only the WSGI server turned it into a 500, so the guarantee lived
        # outside the bridge.
        deps.log.exception("stripe event %s: unexpected error, not acknowledged", event_id)
        return _plain_response(start_response, "500 Internal Server Error", b"internal error")

    with lock:
        if deps.ledger.seen_event("stripe", event_id):
            return _json_response(start_response, "200 OK", {"ok": True})
        if not actionable:
            deps.log.info("stripe event %s: not actionable (type/payment_status)", event_id)
            deps.ledger.mark_event("stripe", event_id, now=_now_rfc3339())
            return _json_response(start_response, "200 OK", {"ok": True})
        assert purchase is not None
        try:
            outcome = deps.core.process(purchase)
        except (PurchaseRejected, UnmappedProduct) as exc:
            deps.ledger.add_dead_letter(
                "stripe",
                purchase.platform_purchase_id,
                str(exc),
                json.dumps(event),
                now=_now_rfc3339(),
            )
            deps.ledger.mark_event("stripe", event_id, now=_now_rfc3339())
            deps.log.error("stripe event %s: dead-lettered", event_id)
            return _json_response(start_response, "200 OK", {"ok": True})
        except Exception:
            # Signing/config/unexpected failure: fail closed. NEVER mark_event —
            # Stripe must retry, or a transient failure would silently drop a
            # purchase forever.
            deps.log.exception("stripe event %s: unexpected error, not acknowledged", event_id)
            return _plain_response(start_response, "500 Internal Server Error", b"internal error")

        deps.ledger.mark_event("stripe", event_id, now=_now_rfc3339())
        deps.log.info(
            "stripe event %s: processed (receipt=%s duplicate=%s)",
            event_id,
            outcome.receipt_id,
            outcome.duplicate,
        )
        return _json_response(start_response, "200 OK", {"ok": True})


# -- receipt download ---------------------------------------------------------


# -- shopify webhook ----------------------------------------------------------


def _handle_shopify_webhook(
    deps: BridgeDeps, environ: dict[str, Any], start_response: Any, lock: threading.Lock
) -> Iterable[bytes]:
    """Same pinned policy table as the Stripe webhook — every row identical,
    including which ones may `mark_event`. Two differences, both narrowing:
    the delivery id comes from an unsigned header rather than the body, and
    there is no API call inside `normalize`, so the transient-failure row can
    only ever be reached by an unexpected error."""
    shopify = deps.shopify
    if shopify is None:
        # No [shopify] section configured: this route simply doesn't exist.
        return _not_found(start_response)

    body = _read_body(environ)
    sig_header = environ.get("HTTP_X_SHOPIFY_HMAC_SHA256") or ""
    if not sig_header:
        deps.log.warning("shopify webhook: missing X-Shopify-Hmac-Sha256 header")
        return _plain_response(start_response, "400 Bad Request", b"missing signature")

    try:
        order = shopify.parse_event(body, sig_header)
    except ShopifySignatureError:
        deps.log.warning("shopify webhook: signature verification failed")
        return _plain_response(start_response, "400 Bad Request", b"invalid signature")
    except (json.JSONDecodeError, UnicodeDecodeError):
        deps.log.warning("shopify webhook: signature valid but body is not parseable JSON")
        return _plain_response(start_response, "400 Bad Request", b"malformed body")

    topic = environ.get("HTTP_X_SHOPIFY_TOPIC") or ""
    # The delivery id is Shopify's own per-delivery identifier. It is NOT
    # covered by the HMAC, so it is a dedup key and never an authorization
    # input: the worst a tampered value can do is make this bridge treat one
    # delivery as two, which the Ledger's `(platform, purchase_id)` receipt
    # dedup then collapses back into a single receipt.
    event_id = environ.get("HTTP_X_SHOPIFY_WEBHOOK_ID") or ""
    if not event_id:
        deps.log.warning("shopify webhook: missing X-Shopify-Webhook-Id header")
        return _plain_response(start_response, "400 Bad Request", b"missing delivery id")

    purchase: NormalizedPurchase | None = None
    try:
        actionable = shopify.wants(order, topic=topic)
        if actionable:
            purchase = shopify.normalize(order)
    except (PurchaseRejected, UnmappedProduct, KeyError, TypeError, AttributeError) as exc:
        with lock:
            if deps.ledger.seen_event("shopify", event_id):
                return _json_response(start_response, "200 OK", {"ok": True})
            purchase_id = (
                purchase.platform_purchase_id
                if purchase is not None
                else _best_effort_shopify_purchase_id(order)
            )
            deps.ledger.add_dead_letter(
                "shopify", purchase_id, str(exc), json.dumps(order), now=_now_rfc3339()
            )
            deps.ledger.mark_event("shopify", event_id, now=_now_rfc3339())
            deps.log.error("shopify delivery %s: dead-lettered", event_id)
            return _json_response(start_response, "200 OK", {"ok": True})
    except Exception:
        deps.log.exception("shopify delivery %s: unexpected error, not acknowledged", event_id)
        return _plain_response(start_response, "500 Internal Server Error", b"internal error")

    with lock:
        if deps.ledger.seen_event("shopify", event_id):
            return _json_response(start_response, "200 OK", {"ok": True})
        if not actionable:
            deps.log.info("shopify delivery %s: not actionable (topic/financial_status)", event_id)
            deps.ledger.mark_event("shopify", event_id, now=_now_rfc3339())
            return _json_response(start_response, "200 OK", {"ok": True})
        assert purchase is not None
        try:
            outcome = deps.core.process(purchase)
        except (PurchaseRejected, UnmappedProduct) as exc:
            deps.ledger.add_dead_letter(
                "shopify",
                purchase.platform_purchase_id,
                str(exc),
                json.dumps(order),
                now=_now_rfc3339(),
            )
            deps.ledger.mark_event("shopify", event_id, now=_now_rfc3339())
            deps.log.error("shopify delivery %s: dead-lettered", event_id)
            return _json_response(start_response, "200 OK", {"ok": True})
        except Exception:
            # Signing/config/unexpected failure: fail closed. NEVER mark_event —
            # Shopify must retry, or a transient failure would silently drop a
            # purchase forever.
            deps.log.exception("shopify delivery %s: unexpected error, not acknowledged", event_id)
            return _plain_response(start_response, "500 Internal Server Error", b"internal error")

        deps.ledger.mark_event("shopify", event_id, now=_now_rfc3339())
        deps.log.info(
            "shopify delivery %s: processed (receipt=%s duplicate=%s)",
            event_id,
            outcome.receipt_id,
            outcome.duplicate,
        )
        return _json_response(start_response, "200 OK", {"ok": True})


def _best_effort_shopify_purchase_id(order: object) -> str | None:
    """Order id for dead-letter operator visibility only — never load-bearing
    (the dead letter's `raw_json` is the authoritative record)."""
    if not isinstance(order, dict):
        return None
    raw_id = order.get("id")
    if isinstance(raw_id, bool):
        return None
    return str(raw_id) if isinstance(raw_id, (int, str)) and raw_id != "" else None


def _handle_download(deps: BridgeDeps, start_response: Any, *, token: str) -> Iterable[bytes]:
    stored = deps.ledger.by_download_token(token)
    if stored is None:
        return _not_found(start_response)
    return _receipt_response(start_response, stored)


def _handle_stripe_receipt(
    deps: BridgeDeps, start_response: Any, *, session_id: str | None
) -> Iterable[bytes]:
    if not session_id:
        return _not_found(start_response)
    stored = deps.ledger.get_receipt("stripe", session_id)
    if stored is None:
        return _not_found(start_response)
    return _receipt_response(start_response, stored)


# -- itch claim queue (OI-4) --------------------------------
#
# There is no itch webhook (see `itch_adapter.py`'s module docstring) — these
# routes only ever touch the Ledger's claim queue. Enqueuing a claim NEVER
# calls `IssuingCore.process`; only `ItchPoller.tick` (running on its own
# daemon thread, wired up in `cli.py`'s `serve`) does that, gated on a live
# `GET /games/{game_id}/purchases` response. Nothing here is issuance-capable.


def _parse_claim_fields(environ: dict[str, Any]) -> dict[str, str]:
    """Accept both form-encoded and JSON claim submissions.

    A body this function can't make sense of (wrong content type, malformed
    JSON, non-UTF-8 bytes) degrades to an empty mapping — the caller's own
    required-field check turns that into a uniform 400, never a 500.
    """
    body = _read_body(environ)
    content_type = (environ.get("CONTENT_TYPE") or "").split(";")[0].strip().lower()
    if content_type == "application/json":
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            key: str(value) for key, value in data.items() if isinstance(value, str | int | float)
        }
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    return _parse_query(text)


def _itch_game_choices(deps: BridgeDeps) -> list[tuple[str, str]]:
    """Configured itch games as `(game_id, title)`, derived from catalog keys
    `itch_<game_id>`. The id is what the form submits; the title is what the
    buyer reads — a dropdown of bare numeric ids is unusable for anyone
    holding more than one title."""
    return sorted(
        (key[len(_ITCH_PRODUCT_PREFIX) :], product.title)
        for key, product in deps.config.products.items()
        if key.startswith(_ITCH_PRODUCT_PREFIX)
    )


def _handle_itch_claim_form(deps: BridgeDeps, start_response: Any) -> Iterable[bytes]:
    if deps.itch is None:
        # No [itch] section configured: this route simply doesn't exist —
        # mirrors `/stripe/webhook`'s 404 when `deps.stripe is None`.
        return _not_found(start_response)
    if deps.config.delivery is None:
        return _json_response(
            start_response,
            "503 Service Unavailable",
            {"error": "receipt delivery is not configured"},
        )
    options = "".join(
        f'<option value="{html.escape(gid)}">{html.escape(title)}</option>'
        for gid, title in _itch_game_choices(deps)
    )
    body = (
        "<!doctype html><html><body>"
        '<form method="post" action="/itch/claim">'
        '<label>Email <input type="email" name="email" required></label>'
        f'<label>Game <select name="game_id">{options}</select></label>'
        '<button type="submit">Email my receipt</button>'
        "</form></body></html>"
    ).encode()
    headers = [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))]
    start_response("200 OK", headers)
    return [body]


def _handle_itch_claim_post(
    deps: BridgeDeps, environ: dict[str, Any], start_response: Any
) -> Iterable[bytes]:
    if deps.itch is None:
        return _not_found(start_response)
    if deps.config.delivery is None:
        return _json_response(
            start_response,
            "503 Service Unavailable",
            {"error": "receipt delivery is not configured"},
        )
    fields = _parse_claim_fields(environ)
    email = fields.get("email", "").strip()
    game_id = fields.get("game_id", "").strip()
    local, separator, domain = email.partition("@")
    if (
        not email
        or len(email) > 254
        or separator != "@"
        or not local
        or not domain
        or "@" in domain
        or not game_id
        or f"{_ITCH_PRODUCT_PREFIX}{game_id}" not in deps.config.products
    ):
        return _json_response(
            start_response, "400 Bad Request", {"error": "invalid email or game_id"}
        )
    try:
        deps.ledger.enqueue_claim(email, game_id, now=_now_rfc3339())
    except ClaimQueueFull:
        return _json_response(
            start_response, "503 Service Unavailable", {"error": "claim queue is full, retry later"}
        )
    # The token remains an internal queue handle only. Every accepted claim
    # gets this byte-identical acknowledgement, including dedup and API-miss
    # cases, so the public route cannot become a purchase-ownership oracle.
    return _json_response(start_response, "202 Accepted", _ITCH_CLAIM_ACCEPTED)


# -- app ------------------------------------------------------------------


def make_app(deps: BridgeDeps) -> WSGIApp:
    # One lock per app process serializes the webhook check-then-act critical
    # section across worker threads (see `_handle_stripe_webhook`). Downloads
    # are read-only and never take it.
    webhook_lock = threading.Lock()

    def app(environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO") or "/"

        if method == "GET" and path == "/healthz":
            return _json_response(start_response, "200 OK", {"ok": True})
        if method == "POST" and path == "/stripe/webhook":
            return _handle_stripe_webhook(deps, environ, start_response, webhook_lock)
        if method == "POST" and path == "/shopify/webhook":
            return _handle_shopify_webhook(deps, environ, start_response, webhook_lock)
        if method == "GET" and path.startswith("/r/"):
            token = path[len("/r/") :]
            return _handle_download(deps, start_response, token=token)
        if method == "GET" and path == "/stripe/receipt":
            params = _parse_query(environ.get("QUERY_STRING", ""))
            return _handle_stripe_receipt(deps, start_response, session_id=params.get("session_id"))
        if method == "GET" and path == "/itch/claim":
            return _handle_itch_claim_form(deps, start_response)
        if method == "POST" and path == "/itch/claim":
            return _handle_itch_claim_post(deps, environ, start_response)
        return _not_found(start_response)

    return cast(WSGIApp, app)
