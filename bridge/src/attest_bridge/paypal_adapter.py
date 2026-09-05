"""PayPal webhook adapter using postback verification over the raw body.

PayPal documents both local RSA verification and its verification postback.
This project deliberately uses the postback: self-verification would require
an RSA/X.509 dependency that the bridge does not otherwise need, certificate
retrieval, and certificate-chain validation. The five PayPal transmission
headers are validated locally before any request, then the original webhook
body bytes are spliced verbatim into ``webhook_event``. Re-serialising the
event is forbidden by PayPal and can make an authentic delivery fail.

Only ``PAYMENT.CAPTURE.COMPLETED`` can be actionable. ``CHECKOUT.ORDER.*``
does not establish an ordinary completed capture, while legacy
``PAYMENT.SALE.*`` belongs to the deprecated Payments v1 flow. The related
order id is the purchase id because one order is one purchase; partial
captures therefore do not issue. The order must be fetched to obtain its
buyer email and sole line-item SKU, and the fetched id is cross-checked against
the authenticated capture. Merchants must create orders server-side: order
fields such as SKU and ``custom_id`` are only as trustworthy as order creation.

Replay rejection is the Ledger's job. A genuine delivery verifies again when
PayPal retries it; Ledger deduplication on the signed envelope id and related
order id prevents duplicate processing and duplicate receipts.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import quote

from attest_bridge._http import https_get, https_post
from attest_bridge.model import (
    BridgeError,
    ConfigError,
    NormalizedPurchase,
    PurchaseRejected,
    purchase_id_for_log,
)

_PRODUCT_KEY_PREFIX = "paypal_"
_HANDLED_EVENT_TYPES = frozenset({"PAYMENT.CAPTURE.COMPLETED"})
_API_BASES = {
    "live": "https://api-m.paypal.com",
    "sandbox": "https://api-m.sandbox.paypal.com",
}
_TOKEN_PATH = "/v1/oauth2/token"  # noqa: S105 - OAuth endpoint path, not a secret
_VERIFY_PATH = "/v1/notifications/verify-webhook-signature"
_ORDER_PATH = "/v2/checkout/orders/{order_id}"
_AUTH_ALGO = "SHA256withRSA"
# Y6: the official OpenAPI schema bounds every postback request field. Enforcing
# the bounds locally keeps a junk delivery from being relayed to PayPal verbatim.
_MAX_HEADER_LENGTHS = (
    ("transmission_id", 50),
    ("transmission_time", 64),
    ("transmission_sig", 500),
    ("cert_url", 500),
    ("auth_algo", 100),
)
_CERT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]*\.paypal\.com(/|$)")
# Matched with `fullmatch`, not `match`: `$` also matches just before a final
# newline, so `re.match` would accept "5O190127TN364715T\n" for a value that
# ends up in an outbound URL path.
_ORDER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PERMANENT_API_STATUSES = frozenset({400, 403, 404})
_TOKEN_REFRESH_MARGIN_SECONDS = 60
_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"


class PayPalSignatureError(BridgeError):
    """The PayPal webhook trust boundary could not authenticate the body."""


class PayPalApiError(BridgeError):
    """A transient or credential failure while calling the PayPal API."""


@dataclass(frozen=True, slots=True)
class PayPalTransmission:
    """The five PayPal headers required for postback signature verification."""

    transmission_id: str
    transmission_time: str
    transmission_sig: str
    cert_url: str
    auth_algo: str


def _json_string(value: str) -> bytes:
    return json.dumps(value, ensure_ascii=True).encode("ascii")


def build_verification_request(
    payload: bytes, transmission: PayPalTransmission, webhook_id: str
) -> bytes:
    """Build PayPal's postback request with ``payload`` inserted byte-for-byte.

    Only the surrounding header and webhook-id strings are JSON encoded. The
    event itself is never parsed or re-serialized before PayPal authenticates
    it, preserving whitespace, member order, escapes, and UTF-8 bytes.
    """
    return b"".join(
        (
            b'{"auth_algo":',
            _json_string(transmission.auth_algo),
            b',"cert_url":',
            _json_string(transmission.cert_url),
            b',"transmission_id":',
            _json_string(transmission.transmission_id),
            b',"transmission_sig":',
            _json_string(transmission.transmission_sig),
            b',"transmission_time":',
            _json_string(transmission.transmission_time),
            b',"webhook_id":',
            _json_string(webhook_id),
            b',"webhook_event":',
            payload,
            b"}",
        )
    )


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def _loads_strict(body: bytes) -> Any:
    return json.loads(body, object_pairs_hook=_reject_duplicate_members)


def _loads_authenticated_body(body: bytes) -> Any:
    """Parse a body PayPal has already authenticated.

    Every malformed-input failure is normalised to ``json.JSONDecodeError`` so
    that one handler clause covers them all. Without this, a duplicate member
    raises a bare ``ValueError`` and a deeply nested body raises
    ``RecursionError``; neither is a ``BridgeError`` nor a
    ``json.JSONDecodeError``, so the handler would answer 500 and PayPal would
    redeliver a body that can never parse for three days (Y5).
    """
    try:
        return _loads_strict(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise
    except RecursionError as exc:
        raise json.JSONDecodeError("paypal webhook body nests too deeply", "", 0) from exc
    except ValueError as exc:
        raise json.JSONDecodeError(str(exc), "", 0) from exc


def _parse_create_time(raw: Any, order_id: str) -> str:
    log_id = purchase_id_for_log(order_id)
    if not isinstance(raw, str) or not raw.strip():
        raise PurchaseRejected(
            f"paypal capture for order {log_id} create_time is not a non-empty string"
        )
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise PurchaseRejected(
            f"paypal capture for order {log_id} create_time is not a recognized timestamp"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime(_RFC3339)


class PayPalAdapter:
    """Verify PayPal capture webhooks and normalize their fetched orders."""

    platform = "paypal"
    HANDLED_EVENT_TYPES = _HANDLED_EVENT_TYPES

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        webhook_id: str,
        environment: str = "live",
        http_get: Callable[[str, dict[str, str]], bytes] | None = None,
        http_post: Callable[[str, dict[str, str], bytes], bytes] | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        for field, value in (
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("webhook_id", webhook_id),
        ):
            if not value.strip():
                raise ConfigError(f"paypal {field} is empty")
        if environment not in _API_BASES:
            raise ConfigError("paypal environment must be one of live, sandbox")

        self._client_id = client_id
        self._client_secret = client_secret
        self._webhook_id = webhook_id
        self._base = _API_BASES[environment]
        self._http_get = http_get if http_get is not None else https_get
        self._http_post = http_post if http_post is not None else https_post
        self._now = now if now is not None else time.time
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._token_lock = threading.Lock()

    def parse_event(self, payload: bytes, transmission: PayPalTransmission) -> dict[str, Any]:
        """Authenticate ``payload`` through PayPal, then parse its JSON.

        All local header checks happen before OAuth or verification calls. A
        response is accepted only when ``verification_status`` is exactly the
        string ``SUCCESS``.
        """
        values = (
            transmission.transmission_id,
            transmission.transmission_time,
            transmission.transmission_sig,
            transmission.cert_url,
            transmission.auth_algo,
        )
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise PayPalSignatureError("missing PayPal transmission headers")
        for field_name, limit in _MAX_HEADER_LENGTHS:
            field_value: str = getattr(transmission, field_name)
            # A WSGI header value is latin-1-decoded remote input (PEP 3333),
            # so a byte >= 0x80 arrives here as a non-ASCII character. All five
            # PayPal transmission values are ASCII by construction (a UUID, an
            # RFC 3339 instant, base64, an https URL, an algorithm name), so
            # refusing a non-ASCII one is exact, not lenient — and it keeps
            # arbitrary remote bytes out of the outbound postback body.
            if (
                len(field_value) > limit
                or not field_value.isascii()
                or any(c.isspace() for c in field_value)
            ):
                raise PayPalSignatureError("malformed PayPal transmission headers")
        if transmission.auth_algo != _AUTH_ALGO:
            raise PayPalSignatureError("unsupported auth algorithm")
        if _CERT_URL_RE.match(transmission.cert_url) is None:
            raise PayPalSignatureError("certificate url is not a paypal.com https url")
        if not payload:
            raise PayPalSignatureError("empty body")

        request_body = build_verification_request(payload, transmission, self._webhook_id)
        response = self._post_verification(request_body)
        try:
            result = _loads_strict(response)
        except (ValueError, RecursionError):
            raise PayPalSignatureError("paypal webhook signature verification failed") from None
        if not isinstance(result, dict) or result.get("verification_status") != "SUCCESS":
            raise PayPalSignatureError("paypal webhook signature verification failed")

        event = _loads_authenticated_body(payload)
        return cast(dict[str, Any], event)

    def wants(self, event: dict[str, Any]) -> bool:
        """Return whether a signed event is a completed final capture."""
        if event.get("event_type") not in self.HANDLED_EVENT_TYPES:
            return False
        resource = event.get("resource")
        if not isinstance(resource, dict):
            raise PurchaseRejected("paypal event resource is not an object")
        if resource.get("status") != "COMPLETED":
            return False
        final_capture = resource.get("final_capture")
        if final_capture is None or final_capture is True:
            return True
        if final_capture is False:
            return False
        raise PurchaseRejected("paypal capture final_capture is not a boolean")

    def normalize(self, event: dict[str, Any]) -> NormalizedPurchase:
        """Normalize a completed capture after fetching its matching order.

        Every structural check available from the authenticated event runs
        before OAuth or order lookup. The order then supplies the mandatory
        payer email and sole item SKU; malformed or mismatched orders are
        rejected rather than used to mint a receipt.
        """
        resource = event.get("resource")
        if not isinstance(resource, dict):
            raise PurchaseRejected("paypal event resource is not an object")

        order_id = self._related_order_id(resource)
        purchased_at = _parse_create_time(resource.get("create_time"), order_id)
        amount, currency = self._amount(resource)

        order = self._fetch_order(order_id)
        fetched_id = order.get("id")
        if fetched_id != order_id:
            raise PurchaseRejected(
                "paypal fetched order id does not match capture order "
                f"{purchase_id_for_log(order_id)}"
            )

        payer = order.get("payer")
        email = payer.get("email_address") if isinstance(payer, dict) else None
        if not isinstance(email, str) or not email.strip():
            raise PurchaseRejected(
                f"paypal order {purchase_id_for_log(order_id)} has no payer.email_address"
            )

        product_key = self._product_key(order, order_id)
        self._checkout_attributes(order)
        buyer_pubkey = None

        return NormalizedPurchase(
            platform=self.platform,
            platform_purchase_id=order_id,
            buyer_identifier=email,
            identifier_type="email",
            buyer_pubkey=buyer_pubkey,
            product_key=product_key,
            purchased_at=purchased_at,
            amount=amount,
            currency=currency,
        )

    @staticmethod
    def _related_order_id(resource: dict[str, Any]) -> str:
        supplementary_data = resource.get("supplementary_data")
        if not isinstance(supplementary_data, dict):
            raise PurchaseRejected("paypal capture has no usable related order id")
        related_ids = supplementary_data.get("related_ids")
        if not isinstance(related_ids, dict):
            raise PurchaseRejected("paypal capture has no usable related order id")
        order_id = related_ids.get("order_id")
        if not isinstance(order_id, str) or _ORDER_ID_RE.fullmatch(order_id) is None:
            raise PurchaseRejected("paypal capture has no usable related order id")
        return order_id

    @staticmethod
    def _amount(resource: dict[str, Any]) -> tuple[str | None, str | None]:
        raw = resource.get("amount")
        if raw is None:
            return None, None
        if not isinstance(raw, dict):
            raise PurchaseRejected("paypal capture amount is not an object")
        value = raw.get("value")
        currency_code = raw.get("currency_code")
        return (
            value if isinstance(value, str) else None,
            currency_code if isinstance(currency_code, str) else None,
        )

    @staticmethod
    def _checkout_attributes(order: dict[str, Any]) -> dict[str, str]:
        """Return checkout-carried attributes; currently always empty.

        PayPal's reserved carrier is ``purchase_units[0].custom_id``, a single
        free-text value of up to 255 characters echoed on orders and captures.
        Encoding several named keys into that one value belongs to the
        binding-consent design when ratified, so this adapter intentionally
        assigns it no semantics today.
        """
        del order
        return {}

    def _product_key(self, order: dict[str, Any], order_id: str) -> str:
        purchase_units = order.get("purchase_units")
        if not isinstance(purchase_units, list) or len(purchase_units) != 1:
            count = len(purchase_units) if isinstance(purchase_units, list) else "non-list"
            raise PurchaseRejected(
                f"paypal order contains {count} purchase units; "
                "the bridge issues one receipt per purchase"
            )
        unit = purchase_units[0]
        if not isinstance(unit, dict):
            raise PurchaseRejected(
                "paypal order contains a non-object purchase unit; "
                "the bridge issues one receipt per purchase"
            )
        items = unit.get("items")
        if not isinstance(items, list) or len(items) != 1:
            count = len(items) if isinstance(items, list) else "non-list"
            raise PurchaseRejected(
                f"paypal order contains {count} items; the bridge issues one receipt per purchase"
            )
        item = items[0]
        if not isinstance(item, dict):
            raise PurchaseRejected(
                "paypal order contains a non-object item; "
                "the bridge issues one receipt per purchase"
            )
        sku = item.get("sku")
        if not isinstance(sku, str) or not sku.strip():
            raise PurchaseRejected(
                f"paypal order {purchase_id_for_log(order_id)} line item has no sku"
            )
        return f"{_PRODUCT_KEY_PREFIX}{sku}"

    def _fetch_order(self, order_id: str) -> dict[str, Any]:
        encoded_order_id = quote(order_id, safe="")
        url = f"{self._base}{_ORDER_PATH.format(order_id=encoded_order_id)}"
        token = self._access_token()
        for attempt in range(2):
            try:
                body = self._http_get(url, self._bearer_headers(token))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    if attempt == 0:
                        token = self._access_token(force_refresh=True)
                        continue
                    raise PayPalApiError(self._credentials_error()) from exc
                if exc.code in _PERMANENT_API_STATUSES:
                    raise PurchaseRejected(
                        f"paypal api returned {exc.code} fetching order "
                        f"{purchase_id_for_log(order_id)}: check paypal.client_id_env / "
                        "client_secret_env and that the app can read orders"
                    ) from exc
                raise PayPalApiError(
                    f"paypal api returned {exc.code} fetching order {purchase_id_for_log(order_id)}"
                ) from exc
            except urllib.error.URLError as exc:
                raise PayPalApiError(
                    f"paypal api unreachable fetching order {purchase_id_for_log(order_id)}"
                ) from exc
        else:  # pragma: no cover - the loop always returns or raises
            raise AssertionError("unreachable")

        try:
            order = _loads_strict(body)
        except (ValueError, RecursionError):
            raise PurchaseRejected(
                f"paypal order response for {purchase_id_for_log(order_id)} is not valid JSON"
            ) from None
        if not isinstance(order, dict):
            raise PurchaseRejected(
                f"paypal order response for {purchase_id_for_log(order_id)} is not an object"
            )
        return order

    def _post_verification(self, body: bytes) -> bytes:
        url = f"{self._base}{_VERIFY_PATH}"
        token = self._access_token()
        for attempt in range(2):
            try:
                return self._http_post(url, self._bearer_headers(token), body)
            except urllib.error.HTTPError as exc:
                if exc.code == 400:
                    raise PayPalSignatureError("verification request rejected") from exc
                if exc.code == 401:
                    if attempt == 0:
                        token = self._access_token(force_refresh=True)
                        continue
                    raise PayPalApiError(self._credentials_error()) from exc
                raise PayPalApiError(f"paypal verification api returned {exc.code}") from exc
            except urllib.error.URLError as exc:
                raise PayPalApiError("paypal verification api is unreachable") from exc
        raise AssertionError("unreachable")  # pragma: no cover

    def _access_token(self, *, force_refresh: bool = False) -> str:
        with self._token_lock:
            if (
                not force_refresh
                and self._token is not None
                and self._now() < self._token_expires_at
            ):
                return self._token
            return self._request_token()

    def _request_token(self) -> str:
        credentials = f"{self._client_id}:{self._client_secret}".encode()
        basic = base64.b64encode(credentials).decode("ascii")
        headers = {
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        try:
            body = self._http_post(
                f"{self._base}{_TOKEN_PATH}", headers, b"grant_type=client_credentials"
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise PayPalApiError(self._credentials_error()) from exc
            raise PayPalApiError(f"paypal token api returned {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise PayPalApiError("paypal token api is unreachable") from exc

        try:
            response = _loads_strict(body)
        except (ValueError, RecursionError):
            raise PayPalApiError("paypal token response is malformed") from None
        if not isinstance(response, dict):
            raise PayPalApiError("paypal token response is malformed")
        token = response.get("access_token")
        expires_in = response.get("expires_in")
        if (
            not isinstance(token, str)
            or not token.strip()
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
        ):
            raise PayPalApiError("paypal token response is malformed")
        self._token = token
        self._token_expires_at = self._now() + expires_in - _TOKEN_REFRESH_MARGIN_SECONDS
        return token

    @staticmethod
    def _bearer_headers(token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @staticmethod
    def _credentials_error() -> str:
        return "paypal rejected the api credentials: check paypal.client_id_env / client_secret_env"
