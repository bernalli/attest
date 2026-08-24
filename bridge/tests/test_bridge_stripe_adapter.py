"""StripeAdapter: webhook signature verification (trust boundary) + normalize
to `NormalizedPurchase` (Global Constraint 15 / OI-1 —
the bridge plan).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest
from attest_bridge.model import (
    ConfigError,
    NormalizedPurchase,
    PurchaseRejected,
    purchase_id_for_log,
    rfc3339_from_unix,
)
from attest_bridge.stripe_adapter import (
    StripeAdapter,
    StripeSignatureError,
    _default_http_get,
    verify_stripe_signature,
)

from attest import keys

_SECRET = "whsec_test_secret"  # noqa: S105 - test fixture, not a real secret
_T = 1_784_000_000
_BODY = b'{"id":"evt_test_1","type":"checkout.session.completed"}'
_PUBKEY_BYTES = bytes(range(32))
_PUBKEY_B64 = keys.b64u(_PUBKEY_BYTES)


def sign_stripe(payload: bytes, secret: str, ts: int) -> str:
    """Build a `Stripe-Signature` header value the way Stripe's own webhook
    sender does. Shared with T8 (imported there, not duplicated)."""
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def _adapter(
    *,
    webhook_secret: str = _SECRET,
    api_key: str | None = None,
    http_get: Any = None,
) -> StripeAdapter:
    return StripeAdapter(webhook_secret=webhook_secret, api_key=api_key, http_get=http_get)


def _session(
    *,
    session_id: str = "cs_test_123",
    email: str | None = "buyer@example.com",
    metadata: dict[str, str] | None = None,
    custom_fields: list[dict[str, Any]] | None = None,
    payment_status: str = "paid",
    amount_total: int | None = 1999,
    currency: str | None = "usd",
) -> dict[str, Any]:
    return {
        "id": session_id,
        "object": "checkout.session",
        "payment_status": payment_status,
        "amount_total": amount_total,
        "currency": currency,
        "customer_details": {"email": email} if email is not None else None,
        "metadata": metadata if metadata is not None else {},
        "custom_fields": custom_fields if custom_fields is not None else [],
    }


def _event(
    session: dict[str, Any],
    *,
    event_type: str = "checkout.session.completed",
    created: int = _T,
    event_id: str = "evt_test_1",
) -> dict[str, Any]:
    return {
        "id": event_id,
        "type": event_type,
        "created": created,
        "data": {"object": session},
    }


def test_malformed_session_rejection_digests_its_capability() -> None:
    adapter = _adapter()
    session_id = "cs_live_capability"
    session = _session(session_id=session_id, metadata={"attest_product_key": "price_TEST"})
    session["customer_details"] = "not-an-object"

    with pytest.raises(PurchaseRejected) as raised:
        adapter.normalize(_event(session))

    assert session_id not in str(raised.value)
    assert purchase_id_for_log(session_id) in str(raised.value)


def make_session_completed_event(
    *,
    session_id: str = "cs_test_123",
    email: str | None = "buyer@example.com",
    metadata: dict[str, str] | None = None,
    custom_fields: list[dict[str, Any]] | None = None,
    payment_status: str = "paid",
    amount_total: int | None = 1999,
    currency: str | None = "usd",
    event_type: str = "checkout.session.completed",
    created: int = _T,
    event_id: str = "evt_test_1",
) -> dict[str, Any]:
    """Public event-builder — one source of truth for the `checkout.session.
    completed`-shaped event fixture, shared with T8 (imported by
    `test_bridge_http.py`, not duplicated). Delegates to `_session`/`_event`
    above so this module's existing tests are untouched (purely additive)."""
    session = _session(
        session_id=session_id,
        email=email,
        metadata=metadata,
        custom_fields=custom_fields,
        payment_status=payment_status,
        amount_total=amount_total,
        currency=currency,
    )
    return _event(session, event_type=event_type, created=created, event_id=event_id)


# -- signature verification (the trust boundary) ----------------------------


def test_verify_stripe_signature_accepts_a_correctly_signed_payload() -> None:
    header = sign_stripe(_BODY, _SECRET, _T)
    assert verify_stripe_signature(_BODY, header, _SECRET, now=_T) is None


def test_parse_event_with_valid_signature_returns_the_parsed_dict() -> None:
    header = sign_stripe(_BODY, _SECRET, _T)
    event = _adapter().parse_event(_BODY, header, now=_T)
    assert event == json.loads(_BODY)


def test_tampered_body_after_signing_is_rejected() -> None:
    header = sign_stripe(_BODY, _SECRET, _T)
    tampered = bytearray(_BODY)
    tampered[0] ^= 0xFF  # flip one byte after the signature was computed
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(bytes(tampered), header, now=_T)


def test_stale_timestamp_one_second_over_tolerance_is_rejected() -> None:
    header = sign_stripe(_BODY, _SECRET, _T)
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(_BODY, header, now=_T + 301)


def test_stale_timestamp_exactly_at_tolerance_boundary_is_accepted() -> None:
    header = sign_stripe(_BODY, _SECRET, _T)
    event = _adapter().parse_event(_BODY, header, now=_T + 300)
    assert event == json.loads(_BODY)


def test_wrong_secret_is_rejected() -> None:
    header = sign_stripe(_BODY, "whsec_a_different_secret", _T)
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(_BODY, header, now=_T)


def test_v0_only_header_is_never_accepted() -> None:
    # v0 is Stripe's older (weaker) signing scheme; even a correctly computed
    # v0 MAC must never be accepted — only v1 candidates are ever checked.
    mac_v0 = hmac.new(_SECRET.encode(), f"{_T}.".encode() + _BODY, hashlib.sha1).hexdigest()
    header = f"t={_T},v0={mac_v0}"
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(_BODY, header, now=_T)


def test_multiple_v1_candidates_accept_if_any_one_matches_the_current_secret() -> None:
    # Secret rotation: Stripe signs with both the old and new secret for a
    # window, sending multiple v1 values in one header.
    good_mac = hmac.new(_SECRET.encode(), f"{_T}.".encode() + _BODY, hashlib.sha256).hexdigest()
    bad_mac = "0" * 64
    header = f"t={_T},v1={bad_mac},v1={good_mac}"
    event = _adapter().parse_event(_BODY, header, now=_T)
    assert event == json.loads(_BODY)


def test_replayed_valid_signature_parses_successfully_every_time() -> None:
    # Signature verification alone does NOT reject replay: Stripe retries
    # webhook delivery on non-2xx responses, resending the identical signed
    # body, and that must keep verifying. Rejecting an actual replay is the
    # Ledger's (platform, purchase_id) event-dedup job (T8), never the
    # signature's — a valid signature only proves who signed the body, not
    # that this is the first time it has been seen.
    header = sign_stripe(_BODY, _SECRET, _T)
    adapter = _adapter()
    first = adapter.parse_event(_BODY, header, now=_T)
    second = adapter.parse_event(_BODY, header, now=_T)
    assert first == second == json.loads(_BODY)


@pytest.mark.parametrize(
    "header",
    ["", "t=abc,v1=00", f"t={_T}"],
    ids=["empty", "non_numeric_timestamp", "missing_v1"],
)
def test_malformed_signature_header_is_rejected(header: str) -> None:
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(_BODY, header, now=_T)


@pytest.mark.parametrize("secret", ["", "   "], ids=["empty", "whitespace_only"])
def test_empty_webhook_secret_rejected_at_construction(secret: str) -> None:
    # config.py permits an empty env-var value; this trust boundary must not
    # rely on it — an empty HMAC key makes every inbound signature forgeable.
    with pytest.raises(ConfigError):
        StripeAdapter(webhook_secret=secret, api_key=None)


def test_verify_stripe_signature_refuses_an_empty_secret() -> None:
    # Even bypassing the constructor, the primitive must never authenticate
    # against an empty key: an attacker can compute the empty-key MAC of any
    # body, so accepting it would forge an issuance-adjacent event.
    forged_header = sign_stripe(_BODY, "", _T)
    with pytest.raises(StripeSignatureError):
        verify_stripe_signature(_BODY, forged_header, "", now=_T)


def test_duplicate_timestamp_key_is_rejected() -> None:
    # A malformed duplicate `t` appended to an otherwise-valid header must fail
    # closed — it must not be silently skipped while the earlier valid `t`
    # survives, which would let a crafted header pass verification.
    header = sign_stripe(_BODY, _SECRET, _T) + ",t=abc"
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(_BODY, header, now=_T)


@pytest.mark.parametrize(
    "ts_field",
    [
        f" {_T} ",
        f"+{_T}",
        "1_784_000_000",
        "١٧٨٤٠٠٠٠٠٠",
    ],
    ids=["whitespace", "leading_sign", "digit_underscores", "unicode_digits"],
)
def test_non_canonical_timestamp_is_rejected(ts_field: str) -> None:
    # `int()` would accept all of these and reconstruct the canonical integer
    # 1_784_000_000, sliding past the staleness gate. The MAC below is computed
    # over the canonical `f"{_T}."`, so if the parser normalized `ts_field` to
    # _T the signature would match — the header must be rejected on the
    # timestamp form itself, before any MAC is computed.
    mac = hmac.new(_SECRET.encode(), f"{_T}.".encode() + _BODY, hashlib.sha256).hexdigest()
    header = f"t={ts_field},v1={mac}"
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(_BODY, header, now=_T)


def test_overlong_timestamp_is_rejected_as_signature_error_not_valueerror() -> None:
    # A 5000-digit `t` passes the ASCII-digit gate but exceeds CPython's
    # 4300-digit integer-parse limit; it must be rejected as a
    # StripeSignatureError (the verifier's only-error contract), never escape as
    # a raw ValueError that the T8 webhook handler would surface as a 500.
    mac = hmac.new(_SECRET.encode(), f"{_T}.".encode() + _BODY, hashlib.sha256).hexdigest()
    header = f"t={'9' * 5000},v1={mac}"
    with pytest.raises(StripeSignatureError):
        _adapter().parse_event(_BODY, header, now=_T)


def test_default_http_get_refuses_a_non_https_url_before_opening() -> None:
    # The injectable `http_get` is replaced in every other test; this pins the
    # real default's https guard directly (no network — it raises before open).
    with pytest.raises(ValueError, match="non-https"):
        _default_http_get("http://api.stripe.com/v1/checkout/sessions/cs/line_items", {})


# -- normalize ---------------------------------------------------------------


def test_normalize_happy_path_with_metadata_product_key() -> None:
    session = _session(metadata={"attest_product_key": "price_TEST"})
    event = _event(session)
    purchase = _adapter().normalize(event)
    assert purchase == NormalizedPurchase(
        platform="stripe",
        platform_purchase_id="cs_test_123",
        buyer_identifier="buyer@example.com",
        identifier_type="email",
        buyer_pubkey=None,
        product_key="price_TEST",
        purchased_at=rfc3339_from_unix(_T),
        amount="1999",
        currency="usd",
    )


def test_normalize_pubkey_via_metadata() -> None:
    session = _session(
        metadata={"attest_product_key": "price_TEST", "attest_buyer_pubkey": _PUBKEY_B64}
    )
    event = _event(session)
    purchase = _adapter().normalize(event)
    assert purchase.buyer_pubkey == _PUBKEY_BYTES


def test_normalize_pubkey_via_custom_field_attest_pubkey_text_value() -> None:
    session = _session(
        metadata={"attest_product_key": "price_TEST"},
        custom_fields=[
            {
                "key": "attest_pubkey",
                "label": {"type": "custom", "custom": "attest receipt key (optional)"},
                "optional": True,
                "type": "text",
                "text": {"value": _PUBKEY_B64},
            }
        ],
    )
    event = _event(session)
    purchase = _adapter().normalize(event)
    assert purchase.buyer_pubkey == _PUBKEY_BYTES


def test_normalize_metadata_pubkey_wins_over_custom_field() -> None:
    other_pubkey_b64 = keys.b64u(bytes([1] * 32))
    session = _session(
        metadata={"attest_product_key": "price_TEST", "attest_buyer_pubkey": _PUBKEY_B64},
        custom_fields=[
            {"key": "attest_pubkey", "type": "text", "text": {"value": other_pubkey_b64}}
        ],
    )
    event = _event(session)
    purchase = _adapter().normalize(event)
    assert purchase.buyer_pubkey == _PUBKEY_BYTES


def test_normalize_malformed_pubkey_raises_purchase_rejected_before_signing() -> None:
    session = _session(
        metadata={"attest_product_key": "price_TEST", "attest_buyer_pubkey": "not-valid-b64u!!"}
    )
    event = _event(session)
    with pytest.raises(PurchaseRejected):
        _adapter().normalize(event)


def test_normalize_missing_email_raises_purchase_rejected() -> None:
    session = _session(email=None, metadata={"attest_product_key": "price_TEST"})
    event = _event(session)
    with pytest.raises(PurchaseRejected):
        _adapter().normalize(event)


@pytest.mark.parametrize("field", ["customer_details", "metadata"])
def test_normalize_rejects_falsy_non_object_present_fields(field: str) -> None:
    session = _session(metadata={"attest_product_key": "price_TEST"})
    session[field] = []

    with pytest.raises(PurchaseRejected):
        _adapter().normalize(_event(session))


def test_normalize_no_metadata_key_with_api_key_uses_line_items_fallback() -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    def fake_http_get(url: str, headers: dict[str, str]) -> bytes:
        calls.append((url, headers))
        return json.dumps({"data": [{"price": {"id": "price_TEST"}}]}).encode("utf-8")

    session = _session(metadata={})  # no attest_product_key
    event = _event(session)
    adapter = _adapter(api_key="sk_test_merchant_key", http_get=fake_http_get)
    purchase = adapter.normalize(event)

    assert purchase.product_key == "price_TEST"
    assert len(calls) == 1
    url, headers = calls[0]
    assert url == "https://api.stripe.com/v1/checkout/sessions/cs_test_123/line_items"
    assert headers == {"Authorization": "Bearer sk_test_merchant_key"}


def test_normalize_metadata_product_key_with_api_key_still_validates_line_item_count() -> None:
    session = _session(metadata={"attest_product_key": "price_TEST"})

    with pytest.raises(PurchaseRejected, match="multiple line items"):
        _adapter(
            api_key="sk_test_merchant_key",
            http_get=lambda _url, _headers: json.dumps(
                {"data": [{"price": {"id": "price_TEST"}}, {"price": {"id": "price_other"}}]}
            ).encode(),
        ).normalize(_event(session))


def test_normalize_no_metadata_and_no_api_key_raises_purchase_rejected_with_exact_message() -> None:
    session = _session(metadata={})
    event = _event(session)
    with pytest.raises(PurchaseRejected) as exc_info:
        _adapter(api_key=None).normalize(event)
    assert str(exc_info.value) == (
        "no product key: set metadata.attest_product_key or configure stripe.api_key_env"
    )


def test_normalize_amount_and_currency_are_none_when_absent() -> None:
    session = _session(
        metadata={"attest_product_key": "price_TEST"}, amount_total=None, currency=None
    )
    event = _event(session)
    purchase = _adapter().normalize(event)
    assert purchase.amount is None
    assert purchase.currency is None


# -- wants ---------------------------------------------------------------


def test_wants_true_for_checkout_session_completed_paid() -> None:
    event = _event(_session(payment_status="paid"))
    assert _adapter().wants(event) is True


def test_wants_true_for_checkout_session_async_payment_succeeded_paid() -> None:
    event = _event(
        _session(payment_status="paid"), event_type="checkout.session.async_payment_succeeded"
    )
    assert _adapter().wants(event) is True


def test_wants_false_for_other_event_types() -> None:
    event = _event(_session(payment_status="paid"), event_type="payment_intent.succeeded")
    assert _adapter().wants(event) is False


def test_wants_false_when_payment_status_is_not_paid() -> None:
    event = _event(_session(payment_status="unpaid"))
    assert _adapter().wants(event) is False


# --- Stripe API transport failures (asymmetry with ItchApiError, found by running
# the documented local-test path in docs/setup-stripe.md end to end) ---


def _http_error(status: int) -> Any:
    """An `HTTPError` shaped like the one `urlopen` raises on a non-2xx."""
    import urllib.error

    return urllib.error.HTTPError(
        "https://api.stripe.com/v1/checkout/sessions/cs_test_123/line_items",
        status,
        "err",
        {},  # type: ignore[arg-type]
        None,
    )


def _raising_http_get(exc: BaseException) -> Any:
    def _get(_url: str, _headers: dict[str, str]) -> bytes:
        raise exc

    return _get


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_line_items_client_error_is_purchase_rejected_not_a_bare_httperror(status: int) -> None:
    """A bad/rotated API key must dead-letter with a readable reason, never
    escape as an unhandled `HTTPError` (which the WSGI layer turns into a 500
    plus a traceback, and Stripe then retries forever)."""
    session = _session(metadata={"attest_product_key": "price_TEST"})

    with pytest.raises(PurchaseRejected) as exc_info:
        _adapter(
            api_key="sk_test_merchant_key",
            http_get=_raising_http_get(_http_error(status)),
        ).normalize(_event(session))

    assert "stripe api" in str(exc_info.value).lower()
    assert str(status) in str(exc_info.value)


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_line_items_transient_error_is_stripe_api_error(status: int) -> None:
    """Rate limiting and Stripe-side failures are transient: they must NOT be
    dead-lettered as permanently-bad input. They surface as `StripeApiError`,
    which the webhook layer lets become a 500 so Stripe redelivers."""
    from attest_bridge.stripe_adapter import StripeApiError

    session = _session(metadata={"attest_product_key": "price_TEST"})

    with pytest.raises(StripeApiError):
        _adapter(
            api_key="sk_test_merchant_key",
            http_get=_raising_http_get(_http_error(status)),
        ).normalize(_event(session))


def test_line_items_network_failure_is_stripe_api_error() -> None:
    """Same for a transport failure with no HTTP status at all."""
    import urllib.error

    from attest_bridge.stripe_adapter import StripeApiError

    session = _session(metadata={"attest_product_key": "price_TEST"})

    with pytest.raises(StripeApiError):
        _adapter(
            api_key="sk_test_merchant_key",
            http_get=_raising_http_get(urllib.error.URLError("connection refused")),
        ).normalize(_event(session))
