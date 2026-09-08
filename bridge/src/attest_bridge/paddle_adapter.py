"""Paddle Billing webhook verification and purchase normalization.

The Paddle Billing signature scheme was verified against Paddle's developer
documentation on 2026-09-05. ``Paddle-Signature`` carries a Unix timestamp
(``ts``) and one or more HMAC-SHA256 candidates (``h1``); each candidate signs
``b"<timestamp>:" + raw_body`` with the notification destination secret. This
adapter does not support Paddle Classic, which instead sends a form-encoded
body containing ``p_signature`` and uses an RSA signature.

Only ``transaction.completed`` is actionable: ``transaction.paid`` arrives
before Paddle has finished processing, while completed is the terminal paid
event. Transactions with a non-null ``subscription_id`` are skipped because a
subscription renewal is not the one-time perpetual purchase modeled by the
bridge. Billing transaction payloads carry a ``customer_id`` but no email, so
normalization must fetch the customer through Paddle's API before issuance.

The timestamp tolerance is 300 seconds rather than Paddle SDKs' five-second
default. Five seconds turns ordinary delivery latency into rejection and
retries; the Ledger, not this time window, supplies replay protection. It is
not verified whether Paddle re-signs a retried delivery with a fresh timestamp
(premise P8), so the wider window also avoids depending on that behavior.

Replay is deliberately the Ledger's job: the same genuine body and signature
verify every time. The webhook handler deduplicates the signed ``event_id`` and
the transaction ``data.id`` in its event and purchase namespaces respectively.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import urllib.error
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from attest_bridge._http import https_get as _default_http_get
from attest_bridge.model import (
    BridgeError,
    ConfigError,
    NormalizedPurchase,
    PurchaseRejected,
    decode_buyer_pubkey,
    loads_utf8_strict,
    purchase_id_for_log,
)

_DEFAULT_TOLERANCE_SECONDS = 300
_MAX_TIMESTAMP_DIGITS = 20
_PRODUCT_KEY_PREFIX = "paddle_"
_HANDLED_EVENT_TYPES = frozenset({"transaction.completed"})
_CUSTOMER_ID_RE = re.compile(r"^ctm_[a-z0-9]{26}$")
_API_BASES = {
    "live": "https://api.paddle.com",
    "sandbox": "https://sandbox-api.paddle.com",
}
_PERMANENT_API_STATUSES = frozenset({400, 401, 403, 404})


class PaddleSignatureError(BridgeError):
    """The inbound Paddle Billing webhook signature failed verification."""


class PaddleApiError(BridgeError):
    """A transient Paddle API or network failure that should cause redelivery."""


def verify_paddle_signature(
    payload: bytes,
    sig_header: str,
    secret: str,
    *,
    tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> None:
    """Verify ``sig_header`` against the raw Paddle Billing ``payload``.

    Header keys may appear in any order and unknown keys are ignored, but
    exactly one canonical ASCII ``ts`` and at least one ``h1`` candidate are
    required. Every candidate comparison uses ``hmac.compare_digest``.
    """
    # Whitespace-only is empty here too: the constructor already refuses such a
    # secret with `not webhook_secret.strip()`, and a public verifier that is
    # laxer than the object owning it would silently HMAC under a secret the
    # rest of the bridge treats as unconfigured.
    if not secret.strip():
        raise PaddleSignatureError("refusing to verify against an empty webhook secret")

    timestamp_values: list[str] = []
    signature_values: list[str] = []
    for part in sig_header.split(";"):
        key, _, value = part.partition("=")
        if key == "ts":
            timestamp_values.append(value)
        elif key == "h1":
            signature_values.append(value)

    if len(timestamp_values) != 1:
        raise PaddleSignatureError(
            "Paddle-Signature header must carry exactly one timestamp ('ts')"
        )
    timestamp_raw = timestamp_values[0]
    if not (
        timestamp_raw.isascii()
        and timestamp_raw.isdigit()
        and len(timestamp_raw) <= _MAX_TIMESTAMP_DIGITS
    ):
        raise PaddleSignatureError("malformed timestamp ('ts')")
    timestamp = int(timestamp_raw)

    if not signature_values:
        raise PaddleSignatureError("no h1 signature present in Paddle-Signature header")

    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance_seconds:
        raise PaddleSignatureError("stale webhook timestamp")

    expected = hmac.new(
        secret.encode(), f"{timestamp}:".encode() + payload, hashlib.sha256
    ).hexdigest()
    # `hmac.compare_digest` raises TypeError when either str argument is not
    # ASCII, and a WSGI header value is latin-1-decoded remote input (PEP 3333):
    # one byte >= 0x80 in `h1` would escape this function's
    # "only PaddleSignatureError" contract and surface as an unhandled 500
    # instead of the pinned "invalid signature -> 400" row. A non-ASCII
    # candidate can never equal a lower-case hex digest, so scoring it a
    # non-match is exact, not lenient; `isascii()` inspects only the caller's
    # own input, never secret-derived data, so it adds no timing signal.
    if not any(
        candidate.isascii() and hmac.compare_digest(expected, candidate)
        for candidate in signature_values
    ):
        raise PaddleSignatureError("signature mismatch")


def _parse_billed_at(raw: Any, purchase_id: str) -> str:
    """Parse Paddle's ISO-8601 billed time into an RFC 3339 UTC timestamp."""
    # Intentionally mirrors `_parse_shopify_created_at`: both providers send
    # ISO-8601 strings, and an absent offset is interpreted as UTC.
    if not isinstance(raw, str) or not raw.strip():
        raise PurchaseRejected(
            "paddle transaction "
            f"{purchase_id_for_log(purchase_id)} billed_at is not a non-empty string"
        )
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise PurchaseRejected(
            "paddle transaction "
            f"{purchase_id_for_log(purchase_id)} billed_at is not a recognized timestamp"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    # `strftime("%Y")` does not zero-pad below year 1000 on glibc, so a year-1
    # timestamp would leave here as "1-01-01T00:00:00Z", which is not RFC 3339.
    # `isoformat()` always pads to four digits. The Shopify, itch and
    # `model.rfc3339_from_unix` twins already carry the same fix.
    return parsed.astimezone(UTC).replace(microsecond=0, tzinfo=None).isoformat() + "Z"


class PaddleAdapter:
    """Paddle Billing ``PurchaseSource`` with mandatory customer lookup."""

    platform = "paddle"
    HANDLED_EVENT_TYPES = _HANDLED_EVENT_TYPES

    def __init__(
        self,
        *,
        webhook_secret: str,
        api_key: str,
        environment: str = "live",
        http_get: Callable[[str, dict[str, str]], bytes] | None = None,
    ) -> None:
        if not webhook_secret.strip():
            raise ConfigError("paddle webhook secret is empty")
        if not api_key.strip():
            raise ConfigError("paddle api key is empty")
        if environment not in _API_BASES:
            raise ConfigError("paddle environment must be one of live, sandbox")
        self._webhook_secret = webhook_secret
        self._api_key = api_key
        self._api_base = _API_BASES[environment]
        self._http_get = http_get if http_get is not None else _default_http_get

    def parse_event(
        self, payload: bytes, sig_header: str, *, now: int | None = None
    ) -> dict[str, Any]:
        """Verify the signature over raw bytes, then parse the JSON event.

        Every malformed-input failure is normalised to
        ``json.JSONDecodeError`` so that one handler clause covers them all.
        A body that nests too deeply raises ``RecursionError``, which is
        neither a ``BridgeError`` nor a ``json.JSONDecodeError``: the handler
        would answer 500 and Paddle would redeliver a body that can never
        parse, 60 times over three days. Mirrors
        ``paypal_adapter._loads_authenticated_body``.
        """
        verify_paddle_signature(payload, sig_header, self._webhook_secret, now=now)
        try:
            event: dict[str, Any] = loads_utf8_strict(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise
        except RecursionError as exc:
            raise json.JSONDecodeError("paddle webhook body nests too deeply", "", 0) from exc
        except ValueError as exc:
            # A >4300-digit integer literal leaves `json.loads` as a bare
            # `ValueError`, and `loads_utf8_strict` signals a lone surrogate as
            # `UnicodeEncodeError`; neither is a `JSONDecodeError`, so without
            # this both would answer 500 and Paddle would redeliver a body that
            # can never parse. Mirrors `paypal_adapter._loads_authenticated_body`.
            raise json.JSONDecodeError(str(exc), "", 0) from exc
        return event

    def wants(self, event: dict[str, Any]) -> bool:
        """Return whether a signed event is a completed one-time transaction."""
        if event.get("event_type") not in self.HANDLED_EVENT_TYPES:
            return False
        data = event.get("data")
        if not isinstance(data, dict):
            raise PurchaseRejected("paddle event data is not an object")
        if data.get("status") != "completed":
            return False
        if data.get("subscription_id") is not None:
            return False
        return True

    def normalize(self, event: dict[str, Any]) -> NormalizedPurchase:
        """Normalize one Paddle transaction after all local checks pass.

        Every structural validation and buyer-pubkey decode precedes the first
        API call. Malformed signed input therefore costs no Paddle request.
        """
        data = event.get("data")
        if not isinstance(data, dict):
            raise PurchaseRejected("paddle event data is not an object")

        platform_purchase_id = data.get("id")
        if not isinstance(platform_purchase_id, str) or not platform_purchase_id:
            raise PurchaseRejected("paddle transaction id is missing or not a non-empty string")
        purchase_log_id = purchase_id_for_log(platform_purchase_id)

        customer_id = data.get("customer_id")
        if not isinstance(customer_id, str) or _CUSTOMER_ID_RE.fullmatch(customer_id) is None:
            raise PurchaseRejected(
                f"paddle transaction {purchase_log_id} customer id is not a valid Paddle id"
            )

        items = data.get("items")
        if not isinstance(items, list):
            raise PurchaseRejected(f"paddle transaction {purchase_log_id} items is not a list")
        if len(items) != 1:
            raise PurchaseRejected(
                f"paddle transaction contains {len(items)} items; "
                "the bridge issues one receipt per purchase"
            )
        item = items[0]
        if not isinstance(item, dict):
            raise PurchaseRejected(f"paddle transaction {purchase_log_id} item is not an object")
        price = item.get("price")
        if not isinstance(price, dict):
            raise PurchaseRejected(
                f"paddle transaction {purchase_log_id} item price is not an object"
            )
        price_id = price.get("id")
        if not isinstance(price_id, str) or not price_id:
            raise PurchaseRejected(f"paddle transaction {purchase_log_id} item has no price.id")
        product_key = f"{_PRODUCT_KEY_PREFIX}{price_id}"

        purchased_at = _parse_billed_at(data.get("billed_at"), platform_purchase_id)

        details = data.get("details")
        if details is None:
            totals: dict[str, Any] | None = None
        elif not isinstance(details, dict):
            raise PurchaseRejected(f"paddle transaction {purchase_log_id} details is not an object")
        else:
            raw_totals = details.get("totals")
            if raw_totals is None:
                totals = None
            elif not isinstance(raw_totals, dict):
                raise PurchaseRejected(
                    f"paddle transaction {purchase_log_id} details.totals is not an object"
                )
            else:
                totals = raw_totals
        amount_value = totals.get("grand_total") if totals is not None else None
        currency_value = totals.get("currency_code") if totals is not None else None
        amount = amount_value if isinstance(amount_value, str) else None
        currency = currency_value if isinstance(currency_value, str) else None

        attributes = self._checkout_attributes(data, platform_purchase_id)
        buyer_pubkey = decode_buyer_pubkey(attributes.get("attest_buyer_pubkey"))

        email = self._customer_email(customer_id, platform_purchase_id)
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

    def _checkout_attributes(
        self, data: dict[str, Any], platform_purchase_id: str
    ) -> dict[str, str]:
        """Return string attributes from Paddle's ``custom_data`` carrier.

        ``normalize`` currently reads only ``attest_buyer_pubkey``. Transported
        keys grow through protocol decisions, never platform-specific guesses;
        in particular, ``attest_product_key`` cannot override ``price.id``.
        Neighbouring non-string keys or values are ignored because merchants
        share this object with unrelated checkout data.
        """
        custom_data = data.get("custom_data")
        if custom_data is None:
            return {}
        if not isinstance(custom_data, dict):
            raise PurchaseRejected(
                "paddle transaction "
                f"{purchase_id_for_log(platform_purchase_id)} custom_data is not an object"
            )
        return {
            key: value
            for key, value in custom_data.items()
            if isinstance(key, str) and isinstance(value, str)
        }

    def _customer_email(self, customer_id: str, platform_purchase_id: str) -> str:
        """Fetch the transaction customer's required email from Paddle."""
        purchase_log_id = purchase_id_for_log(platform_purchase_id)
        url = f"{self._api_base}/customers/{customer_id}"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            body = self._http_get(url, headers)
        except urllib.error.HTTPError as exc:
            if exc.code in _PERMANENT_API_STATUSES:
                raise PurchaseRejected(
                    f"paddle api returned {exc.code} fetching customer for transaction "
                    f"{purchase_log_id}: check paddle.api_key_env (a sandbox key against the "
                    "live API, or a key without customer.read, is the usual cause)"
                ) from exc
            raise PaddleApiError(
                f"paddle api returned {exc.code} fetching customer for transaction "
                f"{purchase_log_id}"
            ) from exc
        except urllib.error.URLError as exc:
            raise PaddleApiError(
                f"paddle api unreachable fetching customer for transaction {purchase_log_id}"
            ) from exc

        try:
            response = json.loads(body)
        except (ValueError, RecursionError):
            response = None
        customer = response.get("data") if isinstance(response, dict) else None
        if not isinstance(customer, dict):
            raise PurchaseRejected(
                f"paddle customer for transaction {purchase_log_id} has no email"
            )

        returned_id = customer.get("id")
        if isinstance(returned_id, str) and returned_id != customer_id:
            raise PurchaseRejected(
                f"paddle customer response for transaction {purchase_log_id} names a "
                "different customer than the signed transaction"
            )

        email = customer.get("email")
        if not isinstance(email, str) or not email:
            raise PurchaseRejected(
                f"paddle customer for transaction {purchase_log_id} has no email"
            )
        return email
