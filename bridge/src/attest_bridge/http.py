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

The receipt-download routes (`/r/<token>` and `/stripe/receipt`) serve the
spec §14.1/§14.2 PAIR, never the stored envelope: a landing page naming both
halves plus one `?part=receipt|private` link each, all built through
`pair.build_pair`. The stored envelope is salt-bearing by necessity, and
`.attest` is the name §14.1 reserves for the salt-free half — there is no code
path here that hands it out under that name, and a pair that cannot be built
is a 500, not a fallback.

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
from urllib.parse import parse_qs, quote

from attest import buyer_surface
from attest_bridge.config import DEFAULT_INFO_URL, BridgeConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.itch_adapter import ItchAdapter
from attest_bridge.ledger import Ledger, StoredReceipt
from attest_bridge.model import (
    ClaimQueueFull,
    NormalizedPurchase,
    PurchaseRejected,
    UnmappedProduct,
    loads_utf8_strict,
    purchase_id_for_log,
)
from attest_bridge.pair import BundlePair, build_pair
from attest_bridge.shopify_adapter import ShopifyAdapter, ShopifySignatureError
from attest_bridge.stripe_adapter import StripeAdapter, StripeSignatureError

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
_NOT_FOUND_BODY = b'{"error":"not found"}'
_INTERNAL_ERROR_BODY = b'{"error":"internal error"}'
# The two halves of the §14.1/§14.2 pair, as `?part=` values. Anything else —
# including the empty string — is a 404, never a guess at what was meant.
_PART_SHAREABLE = "receipt"
_PART_PRIVATE = "private"
_ITCH_PRODUCT_PREFIX = "itch_"

# What these served pages may reach: nothing. Both policies deliberately
# DIVERGE from the static explainer's (tools/gen_buyer_pages.py): no img-src,
# because bridge pages carry no icons, and the policy travels as a RESPONSE
# HEADER rather than a <meta> twin — the bridge has a server to speak through,
# a header applies before parsing and can pin frame-ancestors (which a meta
# CSP ignores by spec), and one channel means no second copy to drift from.
# Do not "align" them with the static page: the difference is the decision.
#
# A deploy must hand these headers to the client UNCHANGED and must not inject
# a second policy. Multiple CSPs combine restrictively, so one added downstream
# without style-src 'unsafe-inline' would strip both pages of their styling —
# and no in-process test can see that happen.
_CSP_LANDING = (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
# Same policy but for form submissions: 'self' RESTRICTS them to this origin.
# It does not enable the POST — without form-action the POST would work anyway.
# Nor does it pin the path: a CSP source expression can carry a path only when
# it names an origin, and 'self' names none, so every path on this origin is
# an allowed target. action="/itch/claim" and its tests are what pin the path.
_CSP_CLAIM_FORM = (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)

# Presentation only the claim form needs. It rides `render_page`'s extra_css
# hook instead of CORE_CSS: core bytes are paid inside every exported receipt
# (a HELD cost), while this page is SERVED — a form selector in the core would
# charge every buyer's disk for a page they may never load.
_CLAIM_FORM_CSS = (
    "label{display:block;margin:1rem 0}\n"
    "input,select{font:inherit;padding:.4rem .6rem;max-width:100%}\n"
    "button{font:inherit;font-weight:600;margin-top:1.25rem;padding:.55rem 1.1rem;"
    "border:1px solid var(--accent);border-radius:8px;background:none;color:var(--accent)}\n"
)
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


def _internal_error(start_response: Any) -> Iterable[bytes]:
    # Uniform body, like every 404 here: a failure to build the pair must not
    # describe the envelope it failed on.
    headers = [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(_INTERNAL_ERROR_BODY))),
    ]
    start_response("500 Internal Server Error", headers)
    return [_INTERNAL_ERROR_BODY]


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
    except (ValueError, RecursionError):
        # Signature valid but the body is not parseable JSON — including a body
        # that is not even valid UTF-8 (`json.loads(b"\xff")` raises
        # UnicodeDecodeError, not JSONDecodeError). Both are the pinned
        # "unparseable body -> 400" row; integer limits and excessive
        # nesting belong here too (ValueError and RecursionError), and none
        # of them must escape as a 500.
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
    including which ones may `mark_event`.

    One structural difference from the Stripe rail, and it is a security
    property rather than a detail: Shopify's HMAC covers the body only, so this
    handler reads NOTHING from the unsigned headers except the signature
    itself. The event key is the order id out of the signed body. Using
    `X-Shopify-Webhook-Id` for it would let an attacker replay a genuine
    delivery with an already-seen id and have the receipt acknowledged and
    dropped."""
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
    except (ValueError, RecursionError):
        deps.log.warning("shopify webhook: signature valid but body is not parseable JSON")
        return _plain_response(start_response, "400 Bad Request", b"malformed body")

    # The event key comes from the signed body, never from a header. An order
    # with no usable id cannot be deduplicated, and issuing something that
    # cannot be recognised again on redelivery would risk a second receipt for
    # the same purchase — so it is refused outright, before the Ledger is
    # touched at all.
    event_id = _best_effort_shopify_purchase_id(order)
    if not event_id:
        deps.log.warning("shopify webhook: signed body has no usable order id")
        return _plain_response(start_response, "400 Bad Request", b"missing order id")

    purchase: NormalizedPurchase | None = None
    try:
        actionable = shopify.wants(order)
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
            deps.log.error("shopify order %s: dead-lettered", purchase_id_for_log(event_id))
            return _json_response(start_response, "200 OK", {"ok": True})
    except Exception:
        deps.log.exception(
            "shopify order %s: unexpected error, not acknowledged",
            purchase_id_for_log(event_id),
        )
        return _plain_response(start_response, "500 Internal Server Error", b"internal error")

    with lock:
        if deps.ledger.seen_event("shopify", event_id):
            return _json_response(start_response, "200 OK", {"ok": True})
        if not actionable:
            # Acknowledged so Shopify stops redelivering THIS body, but
            # deliberately NOT marked seen. The event key here is the order id,
            # and an order is not an event: the same id arrives again as it
            # moves through its lifecycle, and "not paid yet" is not a terminal
            # state. Marking it would make an `orders/create` seen first close
            # the door on the `orders/paid` that follows, and the receipt would
            # be lost to a perfectly ordinary sequence rather than an attack.
            # Re-parsing a repeated non-actionable body costs nothing and
            # issues nothing.
            deps.log.info(
                "shopify order %s: not actionable (unpaid or cancelled)",
                purchase_id_for_log(event_id),
            )
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
            deps.log.error("shopify order %s: dead-lettered", purchase_id_for_log(event_id))
            return _json_response(start_response, "200 OK", {"ok": True})
        except Exception:
            # Signing/config/unexpected failure: fail closed. NEVER mark_event —
            # Shopify must retry, or a transient failure would silently drop a
            # purchase forever.
            deps.log.exception(
                "shopify order %s: unexpected error, not acknowledged",
                purchase_id_for_log(event_id),
            )
            return _plain_response(start_response, "500 Internal Server Error", b"internal error")

        deps.ledger.mark_event("shopify", event_id, now=_now_rfc3339())
        deps.log.info(
            "shopify order %s: processed (receipt=%s duplicate=%s)",
            purchase_id_for_log(event_id),
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


# -- receipt downloads: the §14.1/§14.2 pair, never the salted envelope -----
#
# The Ledger stores ONE envelope per receipt and it is always salt-bearing: it
# has to be, the buyer needs their own salt to prove the receipt is theirs
# (§8). What these routes may hand out is a different question. §14.1 reserves
# the `.attest` name for the salt-FREE half, so serving that envelope verbatim
# under `receipt-<id>.attest` — as this module did until V-A.3 — handed every
# buyer a bearer proof wearing the name of the file they are told to share.
#
# So a download surface is now a landing page naming both halves, plus one
# `?part=` link per half. `build_pair` is the single mechanism behind all of
# them, and there is no code path that falls back to the stored envelope: if
# the pair cannot be built, the answer is 500.


def _render_pair_landing(
    start_response: Any, pair: BundlePair, hrefs: tuple[str, str], info_url: str
) -> Iterable[bytes]:
    """The page a receipt link lands on: two named downloads, in the order the
    email body uses (shareable first, so the buyer meets the safe file before
    the secret one) and with the warning AFTER the private filename, where a
    reader connects it to the thing it warns about.

    `hrefs` are relative and carry only the capability the visitor already
    arrived with — never a translation of one capability into another.
    """
    shareable_href, private_href = (html.escape(href, quote=True) for href in hrefs)
    name = html.escape(pair.name)
    # This page is where the delivery email sends a buyer whose attachments did
    # not arrive, so it is a buyer-facing surface like the bundle README and the
    # explainer page — it renders the same warning from the same source rather
    # than keeping a shorter fourth wording of its own.
    body = buyer_surface.render_page(
        "Your receipt",
        "<h1>Your receipt</h1>\n"
        "<p>Your receipt is two files. Download both.</p>\n"
        f'<p><a href="{shareable_href}" download>{name}.attest</a> is your receipt. '
        "It is safe to share, and it can be checked by anyone, offline, even if this "
        "store is gone.</p>\n"
        f'<p><a href="{private_href}" download>{name}.private.attest</a> is the one to '
        "keep to yourself.</p>\n"
        f"{buyer_surface.private_file_warning_html(pair.name)}\n"
        # In zero-config mode this page IS the delivery — no email is sent, so
        # this is the only place the explainer can be offered.
        #
        # Written as text rather than as an <a href>, deliberately: every page
        # this module serves is held to carrying no reference to the outside,
        # and that rule is not about rendering offline — it is what stops a
        # link the merchant's own data could inject from leading a buyer
        # somewhere hostile. The address goes on its own line, the way the
        # delivery email writes it, so a reader can copy it.
        f"<p>What are these files? {html.escape(info_url)}</p>",
    ).encode()
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Security-Policy", _CSP_LANDING),
        ("Cache-Control", "no-store"),
        ("Content-Length", str(len(body))),
    ]
    start_response("200 OK", headers)
    return [body]


def _pair_file_response(start_response: Any, pair: BundlePair, part: str) -> Iterable[bytes]:
    """One half of the pair, under the filename §14 gives it.

    The filename is safe to interpolate unquoted: `pair.name` is a slug plus a
    receipt id, both already forced through pinned character classes in
    `pair.build_pair`, so it can carry neither a quote nor a newline into the
    header.
    """
    private = part == _PART_PRIVATE
    body = pair.private if private else pair.shareable
    suffix = ".private.attest" if private else ".attest"
    headers = [
        ("Content-Type", "application/zip"),
        ("Content-Disposition", f'attachment; filename="{pair.name}{suffix}"'),
        ("Cache-Control", "no-store"),
        ("Content-Length", str(len(body))),
    ]
    start_response("200 OK", headers)
    return [body]


def _serve_receipt_pair(
    deps: BridgeDeps,
    start_response: Any,
    stored: StoredReceipt,
    *,
    part: str | None,
    hrefs: tuple[str, str],
) -> Iterable[bytes]:
    if part is not None and part not in (_PART_SHAREABLE, _PART_PRIVATE):
        # Uniform with an unknown token: the route never says which of the two
        # it did not recognise.
        return _not_found(start_response)
    try:
        pair = build_pair(
            json.loads(stored.envelope_json), stored.receipt_id, deps.config.legal_texts
        )
    except Exception:
        # Fail closed, deliberately broad. Whatever went wrong — a missing
        # embedded manifest, a licence text this process cannot serve, an
        # unwritable temp dir — the ONLY other thing this route could hand
        # over is the salted envelope, which is the defect itself. The log
        # line carries the receipt id and nothing else: never the token, the
        # session id, the salt, or the envelope.
        deps.log.exception(
            "receipt download: cannot build the pair for receipt %s", stored.receipt_id
        )
        return _internal_error(start_response)
    if part is None:
        info_url = (
            deps.config.delivery.info_url if deps.config.delivery is not None else DEFAULT_INFO_URL
        )
        return _render_pair_landing(start_response, pair, hrefs, info_url)
    return _pair_file_response(start_response, pair, part)


def _handle_download(
    deps: BridgeDeps, start_response: Any, *, token: str, part: str | None
) -> Iterable[bytes]:
    stored = deps.ledger.by_download_token(token)
    if stored is None:
        return _not_found(start_response)
    # Relative hrefs: the token is already in the address bar, and page source
    # travels further than an address bar does.
    return _serve_receipt_pair(
        deps,
        start_response,
        stored,
        part=part,
        hrefs=(f"?part={_PART_SHAREABLE}", f"?part={_PART_PRIVATE}"),
    )


def _handle_stripe_receipt(
    deps: BridgeDeps, start_response: Any, *, session_id: str | None, part: str | None
) -> Iterable[bytes]:
    if not session_id:
        return _not_found(start_response)
    stored = deps.ledger.get_receipt("stripe", session_id)
    if stored is None:
        return _not_found(start_response)
    # This surface is reached with a Stripe session id, so its links keep
    # using one: handing the visitor the download token instead would give
    # them a credential they did not arrive with.
    held = quote(session_id, safe="")
    return _serve_receipt_pair(
        deps,
        start_response,
        stored,
        part=part,
        hrefs=(
            f"?session_id={held}&part={_PART_SHAREABLE}",
            f"?session_id={held}&part={_PART_PRIVATE}",
        ),
    )


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
            data = loads_utf8_strict(body)
        except (ValueError, RecursionError):
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
    page = buyer_surface.render_page(
        "Claim your receipt",
        "<h1>Claim your receipt</h1>\n"
        "<p>Enter the email address you used on itch.io and pick the game: "
        "the receipt will be emailed to that address.</p>\n"
        '<form method="post" action="/itch/claim">'
        '<label>Email <input type="email" name="email" required></label>'
        f'<label>Game <select name="game_id">{options}</select></label>'
        '<button type="submit">Email my receipt</button>'
        "</form>\n"
        # The seller is told to link this page from their game page, so it is
        # met BEFORE any email: the warning about the private half belongs
        # here, not only in the message that arrives afterwards. And because
        # nothing has been sent yet, this is the one surface whose reader
        # holds no file at all: the pre-delivery form says what will arrive
        # instead of naming a file as if it were already on their disk.
        f"{buyer_surface.private_file_warning_html(delivered=False)}",
        extra_css=_CLAIM_FORM_CSS,
    )
    body = page.encode()
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Security-Policy", _CSP_CLAIM_FORM),
        ("Content-Length", str(len(body))),
    ]
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


# -- readiness ------------------------------------------------------------
#
# `/healthz` says the process is alive. `/readyz` says something a merchant
# actually needs to know and cannot see from the outside: whether a purchase
# arriving now could become a receipt. The two can disagree for days — a
# daemon outliving its signing key keeps answering 200 on /healthz while
# rejecting every purchase.
#
# What is checked is exactly what issuance requires, all of it local:
# a readable Ledger, a signing key inside its validity window, and at least
# one product to resolve a purchase against.
#
# What is deliberately NOT checked: SMTP, the itch API, the Stripe API.
# Neither is on the issuing path — `IssuingCore.process` records the receipt
# durably BEFORE any delivery is attempted, and a failed delivery leaves it
# downloadable and retried by the sweep — so a dead mail relay does not make
# this bridge unable to do its job, and reporting otherwise would invite an
# operator to restart a service that is working. A probe that opened an SMTP
# session on every platform health check (every 15s on Fly) would also be a
# fine way for a merchant to get rate-limited by their own relay.


def _readiness_failure(deps: BridgeDeps) -> str | None:
    """The first reason this bridge could not issue right now, or None.

    Never raises: a readiness probe that 500s tells an operator nothing
    about the dependency it was asked about.
    """
    try:
        deps.ledger.ping()
    except Exception:
        return "ledger is not readable"
    try:
        if not deps.core.signing_key_within_validity(at=_now_rfc3339()):
            return "signing key is outside its validity window"
    except Exception:
        return "signing key could not be checked against the key manifest"
    if not deps.core.has_configured_products:
        return "no product is configured"
    return None


def _handle_readyz(deps: BridgeDeps, start_response: Any) -> Iterable[bytes]:
    failure = _readiness_failure(deps)
    if failure is None:
        return _json_response(start_response, "200 OK", {"ready": True})
    # The reason goes to the operator, never into the response: this route is
    # unauthenticated and reachable by anyone who can reach the webhook
    # endpoints, and which dependency of a merchant's bridge is broken is not
    # theirs to learn.
    deps.log.warning("readiness check failed: %s", failure)
    return _json_response(start_response, "503 Service Unavailable", {"ready": False})


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
        if method == "GET" and path == "/readyz":
            return _handle_readyz(deps, start_response)
        if method == "POST" and path == "/stripe/webhook":
            return _handle_stripe_webhook(deps, environ, start_response, webhook_lock)
        if method == "POST" and path == "/shopify/webhook":
            return _handle_shopify_webhook(deps, environ, start_response, webhook_lock)
        if method == "GET" and path.startswith("/r/"):
            token = path[len("/r/") :]
            params = _parse_query(environ.get("QUERY_STRING", ""))
            return _handle_download(deps, start_response, token=token, part=params.get("part"))
        if method == "GET" and path == "/stripe/receipt":
            params = _parse_query(environ.get("QUERY_STRING", ""))
            return _handle_stripe_receipt(
                deps,
                start_response,
                session_id=params.get("session_id"),
                part=params.get("part"),
            )
        if method == "GET" and path == "/itch/claim":
            return _handle_itch_claim_form(deps, start_response)
        if method == "POST" and path == "/itch/claim":
            return _handle_itch_claim_post(deps, environ, start_response)
        return _not_found(start_response)

    return cast(WSGIApp, app)
