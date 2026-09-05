"""Shopify adapter: verify the inbound webhook signature (the trust boundary
between a merchant's Shopify store and this bridge), then normalize an
`orders/paid` order into a platform-agnostic `NormalizedPurchase` — the same
contract `StripeAdapter` and `ItchAdapter` implement.

Signature scheme (Shopify docs, verified 2026-08-24): the
`X-Shopify-Hmac-Sha256` header carries `base64(HMAC-SHA256(raw_body, secret))`,
keyed by the app's client secret / webhook signing secret. Unlike Stripe there
is no timestamp in the header, so there is no clock tolerance to apply and no
timestamp to reject on. The body is parsed with `json.loads` only AFTER the
signature verifies; there is no code path here that returns order data without
a verified signature first. The comparison is constant-time
(`hmac.compare_digest`, never `==`), on the raw header bytes, so neither a
length difference nor a prefix match leaks through timing.

**What the signature does and does not cover — and what follows from it.** The
HMAC is computed over the request body alone. `X-Shopify-Topic`,
`X-Shopify-Shop-Domain` and `X-Shopify-Webhook-Id` are NOT signed. The
consequence is stronger than "treat them with care": **no decision this module
or its handler makes may read them at all.** An unsigned value that can
suppress issuance loses a receipt just as surely as one that can cause a false
issuance — relabelling a genuine `orders/paid` delivery to another topic would
otherwise get it acknowledged as unhandled and dropped. So the topic is not an
input here, and every gate reads the signed body: `financial_status == "paid"`,
`cancelled_at` absent, and the line items that name the product.

Replay is explicitly NOT this module's job, exactly as in `stripe_adapter`: the
same valid `(body, header)` pair verifies every time it is presented, and
Shopify itself redelivers on a non-2xx response. Rejecting an actual replay is
the Ledger's job, keyed on the **order id from the signed body** — never on the
delivery id header, which an attacker could set to a value already seen to have
a genuine delivery acknowledged and discarded.

**No API call, by construction.** A Shopify order webhook already carries its
`line_items`, so unlike the Stripe path there is no follow-up request to make,
no API key to configure, and none of the failure modes that come with one — a
rotated key cannot break issuance here because there is no key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from attest_bridge.model import (
    BridgeError,
    ConfigError,
    NormalizedPurchase,
    PurchaseRejected,
    decode_buyer_pubkey,
    purchase_id_for_log,
)

_PRODUCT_KEY_PREFIX = "shopify_"
# Only `orders/paid` is handled. `orders/create` fires before payment is
# settled and `orders/updated` fires for edits, refunds and fulfilment changes
# — neither means "this purchase was paid for", which is the only event that
# may lead to a signed receipt.
_HANDLED_TOPICS = frozenset({"orders/paid"})


class ShopifySignatureError(BridgeError):
    """The inbound webhook signature failed verification — reject before parsing."""


def verify_shopify_signature(payload: bytes, sig_header: str, secret: str) -> None:
    """Raise `ShopifySignatureError` unless `sig_header` is the correct
    base64 HMAC-SHA256 of `payload` under `secret`.

    The header is compared as given, without base64-decoding it first: a
    decode step would accept non-canonical encodings of the same digest and
    would have to fail closed on malformed input anyway.
    """
    if not sig_header:
        raise ShopifySignatureError("missing X-Shopify-Hmac-Sha256 header")
    expected = base64.b64encode(
        hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    ).decode("ascii")
    # `hmac.compare_digest` raises TypeError when either str argument is not
    # ASCII, and the header is latin-1-decoded remote input (PEP 3333): one byte
    # >= 0x80 would escape this function's "only ShopifySignatureError" contract
    # and surface as an unhandled 500 instead of the pinned "invalid signature
    # -> 400" row. A non-ASCII header can never equal a base64 digest, so
    # scoring it a non-match is exact, not lenient; `isascii()` inspects only
    # the caller's own input, never secret-derived data, so it adds no timing
    # signal.
    candidate = sig_header.strip()
    if not candidate.isascii() or not hmac.compare_digest(candidate, expected):
        raise ShopifySignatureError("shopify webhook signature verification failed")


def _parse_shopify_created_at(raw: Any, purchase_id: str) -> str:
    """Shopify sends ISO-8601 with an explicit offset (`2021-12-31T19:00:00-05:00`).
    Return RFC3339 `...Z`. Anything unparseable is malformed purchase input —
    `PurchaseRejected`, never signed."""
    if not isinstance(raw, str) or not raw.strip():
        raise PurchaseRejected(
            f"shopify order {purchase_id_for_log(purchase_id)} created_at is not a non-empty string"
        )
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise PurchaseRejected(
            f"shopify order {purchase_id_for_log(purchase_id)} created_at is not a recognized "
            "timestamp"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    # `astimezone(UTC)` raises OverflowError at either end of the representable
    # range (a year-1 value with a positive offset, a year-9999 value with a
    # negative one), and `strftime("%Y")` does not zero-pad below year 1000 on
    # glibc. Neither belongs in a signed-body path: the first escapes this
    # function's PurchaseRejected contract, the second emits a string that is
    # not RFC 3339.
    try:
        moment = parsed.astimezone(UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise PurchaseRejected(
            f"shopify order {purchase_id_for_log(purchase_id)} created_at is outside the "
            "representable range"
        ) from exc
    return moment.replace(microsecond=0, tzinfo=None).isoformat() + "Z"


def _note_attributes(order: dict[str, Any], purchase_id: str) -> dict[str, str]:
    """Shopify's carrier for checkout-time custom fields is `note_attributes`,
    a list of `{"name": ..., "value": ...}` — the structural equivalent of
    Stripe's `metadata` object. Entries that are not string/string pairs are
    ignored rather than rejected: this list is shared with every other app the
    merchant has installed, so a neighbour's malformed entry must not stop a
    receipt from being issued."""
    raw = order.get("note_attributes")
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise PurchaseRejected(
            f"shopify order {purchase_id_for_log(purchase_id)} note_attributes is not a list"
        )
    attributes: dict[str, str] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        value = entry.get("value")
        if isinstance(name, str) and isinstance(value, str):
            attributes[name] = value
    return attributes


class ShopifyAdapter:
    platform = "shopify"
    HANDLED_TOPICS = _HANDLED_TOPICS

    def __init__(self, *, webhook_secret: str) -> None:
        # Fail fast, before serving: an empty (or whitespace-only) secret makes
        # every inbound signature forgeable. The config layer permits an empty
        # env-var value, so this trust boundary must not rely on it.
        if not webhook_secret.strip():
            raise ConfigError("shopify webhook secret is empty")
        self._webhook_secret = webhook_secret

    def parse_event(self, payload: bytes, sig_header: str) -> dict[str, Any]:
        """Verify the signature, then parse — in that order, always."""
        verify_shopify_signature(payload, sig_header, self._webhook_secret)
        order: dict[str, Any] = json.loads(payload)
        return order

    def wants(self, order: dict[str, Any]) -> bool:
        """True iff the signed body describes a paid, live order.

        Deliberately takes NO topic argument. `X-Shopify-Topic` is not covered
        by the HMAC, so letting it gate this decision would mean an attacker
        who relabels a genuine `orders/paid` delivery could make the bridge
        acknowledge it as unhandled and drop the receipt. Every input here
        comes from the signed body instead, which cannot be edited without
        breaking the signature. A redelivery under a different topic is
        therefore still issuable, and costs nothing: the Ledger's
        `(platform, purchase_id)` dedup collapses it onto the same receipt.

        `cancelled_at` is checked because an order cancelled after payment can
        still carry `financial_status: "paid"` until it is refunded — a
        cancelled order is not a purchase to attest to.
        """
        if not isinstance(order, dict):
            raise PurchaseRejected("shopify order payload is not an object")
        if order.get("financial_status") != "paid":
            return False
        cancelled_at = order.get("cancelled_at")
        return not (isinstance(cancelled_at, str) and cancelled_at.strip())

    def normalize(self, order: dict[str, Any]) -> NormalizedPurchase:
        """Turn an `orders/paid` order into a `NormalizedPurchase`.

        Raises `PurchaseRejected` for any malformed *purchase* input: a missing
        order id or buyer email, an order that is not exactly one line item, a
        line item with no variant id, or a malformed buyer pubkey (decoded
        through `decode_buyer_pubkey`, fail-before-signing).
        """
        if not isinstance(order, dict):
            raise PurchaseRejected("shopify order payload is not an object")

        raw_id = order.get("id")
        # Shopify order ids are JSON numbers; `bool` is an `int` subclass and
        # would otherwise pass as an id of "True".
        if isinstance(raw_id, bool) or not isinstance(raw_id, (int, str)) or raw_id == "":
            raise PurchaseRejected("shopify order id is missing or not a number or string")
        platform_purchase_id = str(raw_id)

        email = self._buyer_email(order, platform_purchase_id)
        purchased_at = _parse_shopify_created_at(order.get("created_at"), platform_purchase_id)
        attributes = _note_attributes(order, platform_purchase_id)
        product_key = self._product_key(order, platform_purchase_id)

        amount = order.get("total_price")
        if amount is not None and not isinstance(amount, str):
            amount = str(amount)
        currency = order.get("currency")
        if currency is not None and not isinstance(currency, str):
            raise PurchaseRejected(
                f"shopify order {purchase_id_for_log(platform_purchase_id)} "
                "currency is not a string"
            )

        buyer_pubkey = decode_buyer_pubkey(attributes.get("attest_buyer_pubkey"))

        return NormalizedPurchase(
            platform=self.platform,
            platform_purchase_id=platform_purchase_id,
            buyer_identifier=email,
            identifier_type="email",
            buyer_pubkey=buyer_pubkey,
            product_key=product_key,
            purchased_at=purchased_at,
            amount=amount,
            currency=currency,
        )

    def _buyer_email(self, order: dict[str, Any], purchase_id: str) -> str:
        """`email` is the order's own address; `contact_email` and
        `customer.email` are the documented fallbacks for orders created
        through channels that populate one but not the other. All three can be
        null on an order placed without an address, and a receipt with no
        holder is not issuable."""
        for candidate in (order.get("email"), order.get("contact_email")):
            if isinstance(candidate, str) and candidate.strip():
                return candidate
        customer = order.get("customer")
        if isinstance(customer, dict):
            candidate = customer.get("email")
            if isinstance(candidate, str) and candidate.strip():
                return candidate
        raise PurchaseRejected(
            f"shopify order {purchase_id_for_log(purchase_id)} has no buyer email "
            "(email, contact_email and customer.email are all absent)"
        )

    def _product_key(self, order: dict[str, Any], purchase_id: str) -> str:
        """`shopify_<variant_id>` — the variant is Shopify's unit of sale and
        the closest analogue of a Stripe price id.

        There is deliberately NO `note_attributes` override here, unlike the
        Stripe adapter's `metadata.attest_product_key`. The two carriers are not
        equivalent: Stripe's metadata is set by the merchant's own server when
        it creates the Checkout Session, whereas Shopify's `note_attributes` is
        populated from cart attributes that a theme, an installed app, or the
        buyer's own browser session can set. An override there would let
        whoever controls the cart name the catalog entry, which both detaches
        the receipt from the variant that was actually sold and skips the
        single-line-item check below. A merchant who needs a different mapping
        writes it in the catalog, where only the merchant can.

        The single-line-item invariant is the same one the Stripe adapter
        enforces, and here it costs nothing: the line items are already in the
        signed payload, so this is a length check rather than an API call.
        """
        line_items = order.get("line_items")
        if not isinstance(line_items, list):
            raise PurchaseRejected(
                f"shopify order {purchase_id_for_log(purchase_id)} line_items is not a list"
            )
        if len(line_items) != 1:
            raise PurchaseRejected(
                "shopify order contains "
                f"{len(line_items)} line items; the bridge issues one receipt per purchase"
            )
        item = line_items[0]
        if not isinstance(item, dict):
            raise PurchaseRejected(
                f"shopify order {purchase_id_for_log(purchase_id)} line item is not an object"
            )
        variant_id = item.get("variant_id")
        if (
            isinstance(variant_id, bool)
            or not isinstance(variant_id, (int, str))
            or variant_id == ""
        ):
            raise PurchaseRejected(
                f"shopify order {purchase_id_for_log(purchase_id)} line item has no variant_id"
            )
        return f"{_PRODUCT_KEY_PREFIX}{variant_id}"
