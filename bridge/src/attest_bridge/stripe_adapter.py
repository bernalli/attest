"""Stripe adapter: verify the inbound webhook signature (the trust boundary
between a merchant's Stripe account and this bridge), then normalize a
`checkout.session.completed` / `checkout.session.async_payment_succeeded`
event into a platform-agnostic `NormalizedPurchase` (Global
Constraint 15 / OI-1 — the bridge plan).

Signature scheme (Stripe docs, verified 2026-07-24): the `Stripe-Signature`
header is `t=<unix>,v1=<hex>[,v1=...][,v0=...]`. The signed message is
`"{t}." + <raw request body bytes>`, HMAC-SHA256 keyed by the `whsec_`
endpoint secret. Multiple `v1` values are legal during a secret rotation
(Stripe signs with both the old and new secret for a window) — ANY matching
candidate is accepted, compared constant-time (`hmac.compare_digest`, never
`==`). `v0` is Stripe's older signing scheme and is NEVER accepted. The body
is parsed with `json.loads` only AFTER the signature has verified — there is
no code path in this module that returns event data without a verified
signature first.

Replay is explicitly NOT this module's job: the same valid `(body, header)`
pair verifies successfully every time it is presented (Stripe's own webhook
sender retries delivery on non-2xx responses, resending the identical signed
body). Rejecting an actual replay is the Ledger's `(platform, purchase_id)`
event-dedup job (T8), not the signature's — a valid signature only proves
"this body was really signed with the merchant's Stripe secret", never
"this is the first time we've seen it".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
from collections.abc import Callable
from typing import Any

from attest_bridge._http import https_get as _default_http_get
from attest_bridge.model import (
    BridgeError,
    ConfigError,
    NormalizedPurchase,
    PurchaseRejected,
    decode_buyer_pubkey,
    purchase_id_for_log,
    rfc3339_from_unix,
)

_DEFAULT_TOLERANCE_SECONDS = 300
# A real unix-seconds timestamp is ~10 digits; this generous ceiling keeps the
# value far below CPython's 4300-digit integer-string-conversion limit, so
# `int()` on a validated timestamp can never raise (see `verify_stripe_signature`).
_MAX_TIMESTAMP_DIGITS = 20
_LINE_ITEMS_URL = "https://api.stripe.com/v1/checkout/sessions/{session_id}/line_items"


class StripeSignatureError(BridgeError):
    """The inbound webhook signature failed verification — reject before parsing."""


class StripeApiError(BridgeError):
    """A TRANSIENT failure calling Stripe's API (rate limit, Stripe-side error,
    network). Deliberately not a `PurchaseRejected`: the webhook layer
    dead-letters that class and answers 200, which is right for permanently-bad
    input and wrong here — a transient failure must surface as a 500 so Stripe
    redelivers the event and the receipt still gets issued (`_http.py`'s
    "each adapter maps to its own *ApiError", as `ItchApiError` already does)."""


def verify_stripe_signature(
    payload: bytes,
    sig_header: str,
    secret: str,
    *,
    tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> None:
    """Verify a Stripe `Stripe-Signature` header against the raw `payload` bytes.

    Raises `StripeSignatureError` on any failure: missing/unparseable
    timestamp, no `v1` candidate present at all, a stale timestamp (outside
    `tolerance_seconds`), or no `v1` candidate whose HMAC matches `secret`.
    Does NOT raise on a replayed-but-genuinely-valid signature — see the
    module docstring for why that split is deliberate.
    """
    # An empty secret makes the HMAC forgeable by anyone: the empty-key MAC of
    # any chosen body is trivially computable, so an empty secret can never
    # authenticate a webhook. Refuse to verify against one — defence in depth,
    # since `StripeAdapter.__init__` already rejects an empty secret at
    # construction, but this primitive is a public entry point called directly
    # too (T8, tests).
    if not secret:
        raise StripeSignatureError("refusing to verify against an empty webhook secret")

    t_values: list[str] = []
    v1_candidates: list[str] = []
    for part in sig_header.split(","):
        key, _, value = part.partition("=")
        if key == "t":
            t_values.append(value)
        elif key == "v1":
            v1_candidates.append(value)
        # "v0" (Stripe's older signing scheme) is parsed like any other
        # unrecognized key and intentionally never added to the accepted
        # candidates — it must never be sufficient to pass verification.

    # Fail closed on a malformed timestamp: require EXACTLY ONE `t` (a duplicate
    # `t=abc` appended to a valid header must not be silently skipped while the
    # earlier valid timestamp survives) whose value is a canonical run of ASCII
    # decimal digits. `int()` on its own is too lenient — it also accepts
    # surrounding whitespace, a leading sign, digit-group underscores, and
    # Unicode digits, so `t= 1784000000 ` would otherwise reconstruct the
    # canonical integer and slip past the staleness check.
    if len(t_values) != 1:
        raise StripeSignatureError("Stripe-Signature header must carry exactly one timestamp ('t')")
    ts_raw = t_values[0]
    # ASCII decimal digits only (above), and short enough to be a real unix
    # timestamp: an over-long digit run is malformed remote input, not a
    # timestamp, and letting it reach `int()` would raise a raw ValueError once
    # it crosses CPython's 4300-digit integer-parse limit — escaping this
    # verifier's "only StripeSignatureError" contract (a 500 in the T8 handler
    # instead of a clean rejection).
    if not (ts_raw.isascii() and ts_raw.isdigit()) or len(ts_raw) > _MAX_TIMESTAMP_DIGITS:
        raise StripeSignatureError("malformed timestamp ('t') in Stripe-Signature header")
    t = int(ts_raw)

    if not v1_candidates:
        raise StripeSignatureError("no v1 signature present in Stripe-Signature header")

    current = int(time.time()) if now is None else now
    if abs(current - t) > tolerance_seconds:
        raise StripeSignatureError("stale webhook timestamp")

    expected = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    # Constant-time compare against every v1 candidate — never short-circuit
    # on the first mismatch's content, and never use `==` on secret-derived data.
    if not any(hmac.compare_digest(expected, candidate) for candidate in v1_candidates):
        raise StripeSignatureError("signature mismatch")


class StripeAdapter:
    """Stripe `PurchaseSource`: webhook verification + normalize."""

    platform = "stripe"
    HANDLED_EVENT_TYPES = frozenset(
        {"checkout.session.completed", "checkout.session.async_payment_succeeded"}
    )

    def __init__(
        self,
        *,
        webhook_secret: str,
        api_key: str | None,
        http_get: Callable[[str, dict[str, str]], bytes] | None = None,
    ) -> None:
        # Fail fast, before serving: an empty (or whitespace-only) webhook
        # secret makes every inbound signature forgeable (see
        # `verify_stripe_signature`). The config layer permits an empty
        # env-var value, so this trust boundary must not rely on it.
        if not webhook_secret.strip():
            raise ConfigError("stripe webhook secret is empty")
        self._webhook_secret = webhook_secret
        self._api_key = api_key
        self._http_get = http_get if http_get is not None else _default_http_get

    def parse_event(
        self, payload: bytes, sig_header: str, *, now: int | None = None
    ) -> dict[str, Any]:
        """Verify the signature, then parse — in that order, always."""
        verify_stripe_signature(payload, sig_header, self._webhook_secret, now=now)
        event: dict[str, Any] = json.loads(payload)
        return event

    def wants(self, event: dict[str, Any]) -> bool:
        """True iff `event` is a handled type for a completed (paid) checkout."""
        if event.get("type") not in self.HANDLED_EVENT_TYPES:
            return False
        data = event.get("data")
        if not isinstance(data, dict):
            raise PurchaseRejected("stripe event data is not an object")
        session = data.get("object")
        if not isinstance(session, dict):
            raise PurchaseRejected("stripe event data.object is not an object")
        return bool(session.get("payment_status") == "paid")

    def normalize(self, event: dict[str, Any]) -> NormalizedPurchase:
        """Turn a `checkout.session.completed`-shaped event into a `NormalizedPurchase`.

        Raises `PurchaseRejected` for any malformed *purchase* input: missing
        buyer email, no resolvable product key, or a malformed buyer pubkey
        (decoded through `decode_buyer_pubkey`, fail-before-signing).
        """
        data = event.get("data")
        if not isinstance(data, dict):
            raise PurchaseRejected("stripe event data is not an object")
        session = data.get("object")
        if not isinstance(session, dict):
            raise PurchaseRejected("stripe event data.object is not an object")
        platform_purchase_id = session.get("id")
        if not isinstance(platform_purchase_id, str) or not platform_purchase_id:
            raise PurchaseRejected("stripe session id is missing or not a non-empty string")

        customer_details = session.get("customer_details") if "customer_details" in session else {}
        if not isinstance(customer_details, dict):
            raise PurchaseRejected(
                "stripe session "
                f"{purchase_id_for_log(platform_purchase_id)} customer_details is not an object"
            )
        email = customer_details.get("email")
        if not isinstance(email, str) or not email:
            raise PurchaseRejected(
                "stripe session "
                f"{purchase_id_for_log(platform_purchase_id)} has no customer_details.email"
            )

        created = event.get("created")
        if not isinstance(created, int) or isinstance(created, bool):
            raise PurchaseRejected("stripe event created is missing or not an integer")
        purchased_at = rfc3339_from_unix(created)

        amount_total = session.get("amount_total")
        amount = str(amount_total) if amount_total is not None else None
        currency = session.get("currency")

        metadata = session.get("metadata") if "metadata" in session else {}
        if not isinstance(metadata, dict):
            raise PurchaseRejected(
                "stripe session "
                f"{purchase_id_for_log(platform_purchase_id)} metadata is not an object"
            )
        if not all(
            isinstance(key, str) and isinstance(value, str) for key, value in metadata.items()
        ):
            raise PurchaseRejected(
                "stripe session "
                f"{purchase_id_for_log(platform_purchase_id)} metadata must contain string keys "
                "and values"
            )
        metadata_product_key = metadata.get("attest_product_key")
        # With an API key, line items are always fetched to enforce the
        # single-item invariant. Metadata still decides the catalog mapping.
        # Without an API key that count is unknowable, so metadata-only is the
        # explicitly documented merchant assertion of a single-item session.
        line_items_product_key = (
            self._line_items_product_key(platform_purchase_id) if self._api_key else None
        )
        product_key = metadata_product_key or line_items_product_key
        if not product_key:
            raise PurchaseRejected(
                "no product key: set metadata.attest_product_key or configure stripe.api_key_env"
            )

        # OI-1 precedence: metadata carrier wins over the buyer-typed custom field.
        pubkey_str = metadata.get("attest_buyer_pubkey") or self._custom_field_pubkey(session)
        buyer_pubkey = decode_buyer_pubkey(pubkey_str)

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

    def _line_items_product_key(self, session_id: str) -> str:
        """Fallback when `metadata.attest_product_key` is absent (Global Constraint 15).

        Requires `api_key` (the merchant's Stripe secret key) — with neither
        a metadata key nor an api_key configured there is no way to
        determine what was purchased, and issuing on a guess would violate
        the catalog-resolution contract (`UnmappedProduct` exists precisely
        so nothing is ever issued without a known product).
        """
        if not self._api_key:
            raise PurchaseRejected(
                "no product key: set metadata.attest_product_key or configure stripe.api_key_env"
            )
        url = _LINE_ITEMS_URL.format(session_id=session_id)
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            body = self._http_get(url, headers)
        except urllib.error.HTTPError as exc:
            # 4xx (bad or rotated key, revoked permissions, unknown session) is a
            # configuration fault, not a transient one: retrying re-sends the same
            # request to the same rejection. Dead-letter it with a readable reason
            # so `retry-failed` can replay the event once the merchant fixes the
            # config — never let it escape as a bare HTTPError (a 500 plus a
            # traceback, which Stripe then retries on a schedule nobody wants).
            # 429 is the exception: rate limiting IS transient.
            if 400 <= exc.code < 500 and exc.code != 429:
                raise PurchaseRejected(
                    f"stripe api returned {exc.code} fetching line items for session "
                    f"{purchase_id_for_log(session_id)}: check stripe.api_key_env "
                    "(a test-mode or rotated key is the usual cause)"
                ) from exc
            raise StripeApiError(
                f"stripe api returned {exc.code} fetching line items for session "
                f"{purchase_id_for_log(session_id)}"
            ) from exc
        except urllib.error.URLError as exc:
            raise StripeApiError(
                f"stripe api unreachable fetching line items for session "
                f"{purchase_id_for_log(session_id)}: {exc.reason}"
            ) from exc
        data = json.loads(body)
        if not isinstance(data, dict):
            raise PurchaseRejected(
                f"stripe line items for session {purchase_id_for_log(session_id)} are not an object"
            )
        items = data.get("data")
        if not isinstance(items, list) or not items:
            raise PurchaseRejected(
                f"stripe line items for session {purchase_id_for_log(session_id)} are empty"
            )
        if len(items) > 1:
            raise PurchaseRejected(
                "checkout session contains multiple line items; the bridge issues one receipt "
                "per purchase"
            )
        item = items[0]
        if not isinstance(item, dict):
            raise PurchaseRejected(
                f"stripe line item for session {purchase_id_for_log(session_id)} is not an object"
            )
        price = item.get("price") or {}
        if not isinstance(price, dict):
            raise PurchaseRejected(
                "stripe line item for session "
                f"{purchase_id_for_log(session_id)} price is not an object"
            )
        price_id = price.get("id")
        if not isinstance(price_id, str) or not price_id:
            raise PurchaseRejected(
                f"stripe line item for session {purchase_id_for_log(session_id)} has no price.id"
            )
        return str(price_id)

    @staticmethod
    def _custom_field_pubkey(session: dict[str, Any]) -> str | None:
        """OI-1 carrier #2: Checkout custom field `key="attest_pubkey"`, `type="text"`."""
        fields = session.get("custom_fields") or []
        if not isinstance(fields, list):
            raise PurchaseRejected("stripe session custom_fields is not a list")
        for field in fields:
            if not isinstance(field, dict):
                raise PurchaseRejected("stripe session custom field is not an object")
            if field.get("key") == "attest_pubkey" and field.get("type") == "text":
                text = field.get("text") or {}
                if not isinstance(text, dict):
                    raise PurchaseRejected("stripe session custom field text is not an object")
                value = text.get("value")
                return value if isinstance(value, str) else None
        return None
