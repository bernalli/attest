"""Paddle Billing adapter signature, actionability, and normalization tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import string
import threading
import urllib.error
from collections.abc import Callable
from typing import Any

import pytest
from attest_bridge import http as http_module
from attest_bridge import paddle_adapter as paddle_module
from attest_bridge.config import BridgeConfig, IssuerConfig, PaddleConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.ledger import Ledger
from attest_bridge.model import ConfigError, PurchaseRejected
from attest_bridge.paddle_adapter import (
    PaddleAdapter,
    PaddleApiError,
    PaddleSignatureError,
    verify_paddle_signature,
)
from attest_bridge.signing import IssuerIdentity
from conftest import DISPLAY_NAME, ISSUER, KID
from hypothesis import given, settings
from hypothesis import strategies as st
from test_bridge_http import call_app

from attest import keys
from attest import verify as verify_mod

_WEBHOOK_SECRET = "pdl_ntfset_test_fixture"  # noqa: S105 - env var PADDLE_WEBHOOK_SECRET, not a secret
_API_KEY = "pdl_sdbx_apikey_test_fixture"
_OTHER_SECRET = "pdl_ntfset_other_fixture"  # noqa: S105 - env var PADDLE_WEBHOOK_SECRET, not a secret
_T = 1_784_000_000
_CUSTOMER_ID = "ctm_" + "a" * 26
_TRANSACTION_ID = "txn_01h123456789abcdefghijklm"
_PRICE_ID = "pri_01h123456789abcdefghijklm"
_CATALOG_PRICE_ID = "pri_01h8xce4qz2m3n4p5q6r7s8t9v"
_PUBKEY_BYTES = bytes(range(32))
_PUBKEY_B64 = keys.b64u(_PUBKEY_BYTES)

HttpGet = Callable[[str, dict[str, str]], bytes]


class RecordingHttpGet:
    """Injected Paddle API fake that records requests and serves staged outcomes."""

    def __init__(self, *outcomes: bytes | Exception) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []
        self._outcomes = list(outcomes)
        self._default = (
            None
            if outcomes
            else json.dumps(
                {"data": {"email": "buyer@example.com"}, "meta": {"request_id": "x"}}
            ).encode()
        )

    def __call__(self, url: str, headers: dict[str, str]) -> bytes:
        self.calls.append((url, headers))
        outcome = self._outcomes.pop(0) if self._outcomes else self._default
        if outcome is None:
            raise AssertionError("unexpected extra Paddle API call")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def sign_paddle(body: bytes, secret: str, ts: int) -> str:
    """Return the Paddle-Signature value for raw Billing webhook bytes."""
    signature = hmac.new(secret.encode(), f"{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return f"ts={ts};h1={signature}"


def make_transaction_completed(
    *, event_type: str = "transaction.completed", **overrides: Any
) -> dict[str, Any]:
    """Build the minimal documented Paddle Billing transaction event fixture."""
    data: dict[str, Any] = {
        "id": _TRANSACTION_ID,
        "status": "completed",
        "customer_id": _CUSTOMER_ID,
        "subscription_id": None,
        "items": [{"price": {"id": _PRICE_ID}}],
        "billed_at": "2026-09-05T10:00:00Z",
        "details": {"totals": {"grand_total": "1999", "currency_code": "EUR"}},
        "custom_data": None,
    }
    data.update(overrides)
    return {
        "event_id": "evt_01h123456789abcdefghijklm",
        "event_type": event_type,
        "occurred_at": "2026-09-05T10:00:01Z",
        "notification_id": "ntf_01h123456789abcdefghijklm",
        "data": data,
    }


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    http_get: HttpGet | None = None,
    *,
    webhook_secret: str = _WEBHOOK_SECRET,
    api_key: str = _API_KEY,
    environment: str = "live",
) -> tuple[PaddleAdapter, RecordingHttpGet | HttpGet]:
    fake = http_get if http_get is not None else RecordingHttpGet()
    monkeypatch.setattr(paddle_module, "_default_http_get", fake)
    return (
        PaddleAdapter(
            webhook_secret=webhook_secret,
            api_key=api_key,
            environment=environment,
        ),
        fake,
    )


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://api.paddle.com/customers/redacted",
        code=status,
        msg="fixture",
        hdrs={},  # type: ignore[arg-type]
        fp=None,
    )


# -- signature verification -------------------------------------------------


def test_valid_signature_verifies() -> None:
    body = b'{"event_id":"evt_test"}'
    verify_paddle_signature(body, sign_paddle(body, _WEBHOOK_SECRET, _T), _WEBHOOK_SECRET, now=_T)


def test_wrong_secret_is_rejected() -> None:
    body = b'{"event_id":"evt_test"}'
    header = sign_paddle(body, _OTHER_SECRET, _T)
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(body, header, _WEBHOOK_SECRET, now=_T)


def test_tampered_body_after_signing_is_rejected() -> None:
    body = b'{"event_id":"evt_test"}'
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(
            body + b" ", sign_paddle(body, _WEBHOOK_SECRET, _T), _WEBHOOK_SECRET, now=_T
        )


def test_v1_or_unknown_keys_are_never_accepted() -> None:
    body = b"{}"
    correct = sign_paddle(body, _WEBHOOK_SECRET, _T).partition("h1=")[2]
    with pytest.raises(PaddleSignatureError, match="no h1"):
        verify_paddle_signature(
            body, f"ts={_T};v1={correct};future={correct}", _WEBHOOK_SECRET, now=_T
        )


def test_multiple_h1_candidates_accept_if_any_matches() -> None:
    body = b"{}"
    correct = sign_paddle(body, _WEBHOOK_SECRET, _T).partition("h1=")[2]
    header = f"ts={_T};h1={'0' * 64};h1={correct};h1={'f' * 64}"
    verify_paddle_signature(body, header, _WEBHOOK_SECRET, now=_T)


def test_no_h1_is_rejected() -> None:
    with pytest.raises(PaddleSignatureError, match="no h1"):
        verify_paddle_signature(b"{}", f"ts={_T}", _WEBHOOK_SECRET, now=_T)


def test_duplicate_ts_is_rejected() -> None:
    body = b"{}"
    header = f"{sign_paddle(body, _WEBHOOK_SECRET, _T)};ts={_T}"
    with pytest.raises(PaddleSignatureError, match="exactly one timestamp"):
        verify_paddle_signature(body, header, _WEBHOOK_SECRET, now=_T)


@pytest.mark.parametrize(
    "timestamp",
    [" 1784000000", "+1784000000", "1_784_000_000", "١٧٨٤٠٠٠٠٠٠"],
)
def test_non_canonical_ts_is_rejected(timestamp: str) -> None:
    with pytest.raises(PaddleSignatureError, match="malformed timestamp"):
        verify_paddle_signature(b"{}", f"ts={timestamp};h1={'0' * 64}", _WEBHOOK_SECRET, now=_T)


def test_overlong_ts_is_a_signature_error_not_valueerror() -> None:
    with pytest.raises(PaddleSignatureError, match="malformed timestamp"):
        verify_paddle_signature(b"{}", f"ts={'1' * 5000};h1={'0' * 64}", _WEBHOOK_SECRET, now=_T)


def test_stale_one_second_over_tolerance_is_rejected() -> None:
    body = b"{}"
    with pytest.raises(PaddleSignatureError, match="stale webhook timestamp"):
        verify_paddle_signature(
            body, sign_paddle(body, _WEBHOOK_SECRET, _T - 301), _WEBHOOK_SECRET, now=_T
        )


def test_stale_exactly_at_tolerance_is_accepted() -> None:
    body = b"{}"
    verify_paddle_signature(
        body, sign_paddle(body, _WEBHOOK_SECRET, _T - 300), _WEBHOOK_SECRET, now=_T
    )


def test_future_one_second_over_tolerance_is_rejected() -> None:
    body = b"{}"
    with pytest.raises(PaddleSignatureError, match="stale webhook timestamp"):
        verify_paddle_signature(
            body, sign_paddle(body, _WEBHOOK_SECRET, _T + 301), _WEBHOOK_SECRET, now=_T
        )


def test_future_exactly_at_tolerance_is_accepted() -> None:
    body = b"{}"
    verify_paddle_signature(
        body, sign_paddle(body, _WEBHOOK_SECRET, _T + 300), _WEBHOOK_SECRET, now=_T
    )


def test_empty_secret_is_refused_by_the_verifier_and_by_the_constructor() -> None:
    for secret in ("", "   "):
        with pytest.raises(PaddleSignatureError, match="empty webhook secret"):
            verify_paddle_signature(b"{}", "", secret, now=_T)
    with pytest.raises(ConfigError, match="paddle webhook secret is empty"):
        PaddleAdapter(
            webhook_secret="   ",  # noqa: S106 - empty env var PADDLE_WEBHOOK_SECRET, not a secret
            api_key=_API_KEY,
        )


def test_empty_api_key_and_unknown_environment_are_refused_by_the_constructor() -> None:
    with pytest.raises(ConfigError, match="paddle api key is empty"):
        PaddleAdapter(webhook_secret=_WEBHOOK_SECRET, api_key="   ")
    with pytest.raises(ConfigError, match="environment"):
        PaddleAdapter(webhook_secret=_WEBHOOK_SECRET, api_key=_API_KEY, environment="prod")


def test_replayed_valid_signature_verifies_every_time() -> None:
    body = b"{}"
    header = sign_paddle(body, _WEBHOOK_SECRET, _T)
    verify_paddle_signature(body, header, _WEBHOOK_SECRET, now=_T)
    verify_paddle_signature(body, header, _WEBHOOK_SECRET, now=_T)


def test_parse_event_verifies_before_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _ = _adapter(monkeypatch)
    with pytest.raises(PaddleSignatureError):
        adapter.parse_event(b'{"truncated":', "not-a-signature", now=_T)


def test_empty_signature_header_is_rejected() -> None:
    with pytest.raises(PaddleSignatureError, match="exactly one timestamp"):
        verify_paddle_signature(b"{}", "", _WEBHOOK_SECRET, now=_T)


def test_signature_header_missing_timestamp_is_rejected() -> None:
    with pytest.raises(PaddleSignatureError, match="exactly one timestamp"):
        verify_paddle_signature(b"{}", f"h1={'0' * 64}", _WEBHOOK_SECRET, now=_T)


def test_reversed_signature_header_order_is_accepted() -> None:
    body = b"{}"
    signature = sign_paddle(body, _WEBHOOK_SECRET, _T).partition("h1=")[2]
    verify_paddle_signature(body, f"h1={signature};ts={_T}", _WEBHOOK_SECRET, now=_T)


def test_non_hex_signature_is_rejected() -> None:
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(b"{}", f"ts={_T};h1=not-hex", _WEBHOOK_SECRET, now=_T)


def test_empty_h1_signature_is_rejected() -> None:
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(b"{}", f"ts={_T};h1=", _WEBHOOK_SECRET, now=_T)


def test_a_non_ascii_h1_candidate_is_rejected_and_never_escapes_as_a_typeerror() -> None:
    body = b"{}"
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(body, f"ts={_T};h1=" + "ÿ" * 64, _WEBHOOK_SECRET, now=_T)


def test_a_non_ascii_segment_after_a_valid_h1_still_verifies() -> None:
    body = b"{}"
    correct = sign_paddle(body, _WEBHOOK_SECRET, _T).partition("h1=")[2]
    verify_paddle_signature(body, f"ts={_T};h1={correct};h1=é", _WEBHOOK_SECRET, now=_T)


def test_candidates_are_compared_with_compare_digest_not_equality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, Any]] = []
    real = hmac.compare_digest

    def recording(left: Any, right: Any) -> bool:
        calls.append((left, right))
        return bool(real(left, right))

    monkeypatch.setattr(paddle_module.hmac, "compare_digest", recording)
    body = b"{}"
    verify_paddle_signature(body, sign_paddle(body, _WEBHOOK_SECRET, _T), _WEBHOOK_SECRET, now=_T)
    assert len(calls) == 1

    calls.clear()
    correct = sign_paddle(body, _WEBHOOK_SECRET, _T).partition("h1=")[2]
    header = f"ts={_T};h1={'0' * 64};h1={'f' * 64};h1={correct}"
    verify_paddle_signature(body, header, _WEBHOOK_SECRET, now=_T)
    assert len(calls) == 3

    calls.clear()
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(body, sign_paddle(body, _OTHER_SECRET, _T), _WEBHOOK_SECRET, now=_T)
    assert len(calls) == 1


def test_a_leading_zero_ts_is_normalised_through_int_before_the_hmac() -> None:
    body = b"{}"
    padded = f"0{_T}"
    over_the_raw_string = hmac.new(
        _WEBHOOK_SECRET.encode(), f"{padded}:".encode() + body, hashlib.sha256
    ).hexdigest()
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(
            body, f"ts={padded};h1={over_the_raw_string}", _WEBHOOK_SECRET, now=_T
        )
    over_the_normalised_int = sign_paddle(body, _WEBHOOK_SECRET, _T).partition("h1=")[2]
    verify_paddle_signature(
        body, f"ts={padded};h1={over_the_normalised_int}", _WEBHOOK_SECRET, now=_T
    )


def test_an_uppercase_hex_h1_is_rejected() -> None:
    body = b"{}"
    upper = sign_paddle(body, _WEBHOOK_SECRET, _T).partition("h1=")[2].upper()
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(body, f"ts={_T};h1={upper}", _WEBHOOK_SECRET, now=_T)


def test_truncated_json_body_is_rejected_after_signature_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"data":'
    adapter, _ = _adapter(monkeypatch)
    with pytest.raises(json.JSONDecodeError):
        adapter.parse_event(body, sign_paddle(body, _WEBHOOK_SECRET, _T), now=_T)


def test_non_utf8_body_is_rejected_after_signature_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'\xff{"data":{}}'
    adapter, _ = _adapter(monkeypatch)
    with pytest.raises(UnicodeDecodeError):
        adapter.parse_event(body, sign_paddle(body, _WEBHOOK_SECRET, _T), now=_T)


def test_duplicated_json_fields_use_the_last_signed_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"event_type":"transaction.paid","event_type":"transaction.completed"}'
    adapter, _ = _adapter(monkeypatch)
    event = adapter.parse_event(body, sign_paddle(body, _WEBHOOK_SECRET, _T), now=_T)
    assert event["event_type"] == "transaction.completed"


@settings(max_examples=50)
@given(payload=st.binary(min_size=1, max_size=256), index=st.integers(min_value=0))
def test_any_single_byte_flip_in_the_body_breaks_verification(payload: bytes, index: int) -> None:
    header = sign_paddle(payload, _WEBHOOK_SECRET, _T)
    tampered = bytearray(payload)
    tampered[index % len(tampered)] ^= 1
    with pytest.raises(PaddleSignatureError, match="signature mismatch"):
        verify_paddle_signature(bytes(tampered), header, _WEBHOOK_SECRET, now=_T)


@settings(max_examples=50)
@given(
    key=st.text(alphabet=string.ascii_letters + string.digits, min_size=1).filter(
        lambda value: value not in {"ts", "h1"}
    ),
    value=st.text(alphabet=string.ascii_letters + string.digits, min_size=1),
    valid=st.booleans(),
)
def test_unknown_header_segments_never_change_the_verdict(
    key: str, value: str, valid: bool
) -> None:
    body = b"{}"
    header = sign_paddle(body, _WEBHOOK_SECRET if valid else _OTHER_SECRET, _T)
    extended = f"{header};{key}={value}"
    if valid:
        verify_paddle_signature(body, extended, _WEBHOOK_SECRET, now=_T)
    else:
        with pytest.raises(PaddleSignatureError, match="signature mismatch"):
            verify_paddle_signature(body, extended, _WEBHOOK_SECRET, now=_T)


@settings(max_examples=50)
@given(timestamp=st.text().filter(lambda value: not (value.isascii() and value.isdigit())))
def test_ts_that_is_not_an_ascii_digit_run_is_always_rejected(timestamp: str) -> None:
    with pytest.raises(PaddleSignatureError, match="malformed timestamp"):
        verify_paddle_signature(b"{}", f"ts={timestamp};h1={'0' * 64}", _WEBHOOK_SECRET, now=_T)


# -- actionability ----------------------------------------------------------


def test_wants_true_for_a_completed_one_time_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, _ = _adapter(monkeypatch)
    assert adapter.wants(make_transaction_completed()) is True


@pytest.mark.parametrize(
    "event_type", ["transaction.paid", "transaction.updated", "adjustment.created"]
)
def test_wants_false_for_other_event_types(
    monkeypatch: pytest.MonkeyPatch, event_type: str
) -> None:
    adapter, _ = _adapter(monkeypatch)
    assert adapter.wants(make_transaction_completed(event_type=event_type)) is False


@pytest.mark.parametrize("status", ["draft", "ready", "billed", "paid", "canceled", "past_due"])
def test_wants_false_when_status_is_not_completed(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    adapter, _ = _adapter(monkeypatch)
    assert adapter.wants(make_transaction_completed(status=status)) is False


def test_wants_false_for_a_subscription_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _ = _adapter(monkeypatch)
    assert adapter.wants(make_transaction_completed(subscription_id="sub_test")) is False


@pytest.mark.parametrize("bad_data", [None, [], "transaction", 7, True])
def test_wants_rejects_a_non_object_data(monkeypatch: pytest.MonkeyPatch, bad_data: Any) -> None:
    adapter, _ = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="event data is not an object"):
        adapter.wants({"event_type": "transaction.completed", "data": bad_data})


# -- normalization ----------------------------------------------------------


@pytest.mark.parametrize("bad_data", [None, [], "transaction", 7, True])
def test_normalize_rejects_non_object_data_before_api_call(
    monkeypatch: pytest.MonkeyPatch, bad_data: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="event data is not an object"):
        adapter.normalize({"data": bad_data})
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


def test_normalize_maps_price_id_to_the_product_key_and_fetches_the_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, fake = _adapter(monkeypatch)
    purchase = adapter.normalize(make_transaction_completed())
    assert purchase.platform == "paddle"
    assert purchase.platform_purchase_id == _TRANSACTION_ID
    assert purchase.buyer_identifier == "buyer@example.com"
    assert purchase.identifier_type == "email"
    assert purchase.product_key == f"paddle_{_PRICE_ID}"
    assert purchase.purchased_at == "2026-09-05T10:00:00Z"
    assert purchase.amount == "1999"
    assert purchase.currency == "EUR"
    assert purchase.buyer_pubkey is None
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == [
        (
            f"https://api.paddle.com/customers/{_CUSTOMER_ID}",
            {"Authorization": f"Bearer {_API_KEY}"},
        )
    ]


def test_sandbox_environment_uses_the_sandbox_base(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, fake = _adapter(monkeypatch, environment="sandbox")
    adapter.normalize(make_transaction_completed())
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls[0][0] == f"https://sandbox-api.paddle.com/customers/{_CUSTOMER_ID}"


@pytest.mark.parametrize("items", [None, {}, "item", 7, True])
def test_normalize_rejects_items_that_are_not_a_list(
    monkeypatch: pytest.MonkeyPatch, items: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="items is not a list"):
        adapter.normalize(make_transaction_completed(items=items))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


def test_normalize_rejects_a_transaction_with_more_than_one_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="one receipt per purchase"):
        adapter.normalize(
            make_transaction_completed(items=[{"price": {"id": "a"}}, {"price": {"id": "b"}}])
        )
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


def test_normalize_rejects_a_transaction_with_zero_items(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="one receipt per purchase"):
        adapter.normalize(make_transaction_completed(items=[]))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


@pytest.mark.parametrize("item", [None, [], "item", 7, True])
def test_normalize_rejects_an_item_that_is_not_an_object(
    monkeypatch: pytest.MonkeyPatch, item: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="item is not an object"):
        adapter.normalize(make_transaction_completed(items=[item]))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


@pytest.mark.parametrize("price", [None, [], "price", 7, True])
def test_normalize_rejects_a_price_that_is_not_an_object(
    monkeypatch: pytest.MonkeyPatch, price: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="price is not an object"):
        adapter.normalize(make_transaction_completed(items=[{"price": price}]))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


@pytest.mark.parametrize("price_id", [None, "", True, 7])
def test_normalize_rejects_a_missing_or_wrong_type_price_id(
    monkeypatch: pytest.MonkeyPatch, price_id: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match=r"price\.id"):
        adapter.normalize(make_transaction_completed(items=[{"price": {"id": price_id}}]))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


@pytest.mark.parametrize("transaction_id", [None, "", True, 7])
def test_normalize_rejects_a_missing_or_boolean_or_empty_id(
    monkeypatch: pytest.MonkeyPatch, transaction_id: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="transaction id"):
        adapter.normalize(make_transaction_completed(id=transaction_id))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


@pytest.mark.parametrize("customer_id", ["ctm_", "../customers", "ctm_" + "A" * 26, 123])
def test_normalize_rejects_a_customer_id_that_is_not_a_paddle_id(
    monkeypatch: pytest.MonkeyPatch, customer_id: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="customer id"):
        adapter.normalize(make_transaction_completed(customer_id=customer_id))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


@pytest.mark.parametrize("billed_at", [None, "", "yesterday", 17])
def test_normalize_rejects_an_unparseable_billed_at(
    monkeypatch: pytest.MonkeyPatch, billed_at: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="billed_at"):
        adapter.normalize(make_transaction_completed(billed_at=billed_at))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


def test_custom_data_cannot_name_the_product(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _ = _adapter(monkeypatch)
    purchase = adapter.normalize(
        make_transaction_completed(custom_data={"attest_product_key": "paddle_attacker"})
    )
    assert purchase.product_key == f"paddle_{_PRICE_ID}"


def test_custom_data_pubkey_is_honoured_and_a_malformed_one_fails_before_signing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, fake = _adapter(monkeypatch)
    purchase = adapter.normalize(
        make_transaction_completed(custom_data={"attest_buyer_pubkey": _PUBKEY_B64})
    )
    assert purchase.buyer_pubkey == _PUBKEY_BYTES
    assert isinstance(fake, RecordingHttpGet)
    fake.calls.clear()
    with pytest.raises(PurchaseRejected, match="buyer pubkey"):
        adapter.normalize(
            make_transaction_completed(custom_data={"attest_buyer_pubkey": "not-base64!!"})
        )
    assert fake.calls == []


@pytest.mark.parametrize("custom_data", [[], "x", 1])
def test_custom_data_that_is_not_an_object_is_rejected(
    monkeypatch: pytest.MonkeyPatch, custom_data: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    with pytest.raises(PurchaseRejected, match="custom_data is not an object"):
        adapter.normalize(make_transaction_completed(custom_data=custom_data))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


def test_a_neighbours_non_string_custom_data_entry_does_not_block_issuance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, _ = _adapter(monkeypatch)
    purchase = adapter.normalize(
        make_transaction_completed(
            custom_data={"attest_buyer_pubkey": _PUBKEY_B64, "cart": {"n": 2}, 7: "x"}
        )
    )
    assert purchase.buyer_pubkey == _PUBKEY_BYTES


def test_checkout_attributes_is_the_single_reader_of_custom_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, _ = _adapter(monkeypatch)
    unknown_value = "x" * 132
    event = make_transaction_completed(custom_data={"future_protocol_key": unknown_value})
    attributes = adapter._checkout_attributes(event["data"], _TRANSACTION_ID)
    assert attributes == {"future_protocol_key": unknown_value}
    assert adapter.normalize(event).buyer_pubkey is None


def test_amount_and_currency_are_none_when_totals_are_absent_and_rejected_when_details_is_not_an_object(  # noqa: E501
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, _ = _adapter(monkeypatch)
    for details in (None, {}, {"totals": None}):
        purchase = adapter.normalize(make_transaction_completed(details=details))
        assert purchase.amount is None
        assert purchase.currency is None
    with pytest.raises(PurchaseRejected, match="details is not an object"):
        adapter.normalize(make_transaction_completed(details=[]))


@pytest.mark.parametrize("field,value", [("details", []), ("totals", [])])
def test_details_and_totals_wrong_types_are_rejected_before_api_call(
    monkeypatch: pytest.MonkeyPatch, field: str, value: Any
) -> None:
    adapter, fake = _adapter(monkeypatch)
    details = value if field == "details" else {"totals": value}
    with pytest.raises(PurchaseRejected, match=field):
        adapter.normalize(make_transaction_completed(details=details))
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


def test_non_string_total_members_become_none(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _ = _adapter(monkeypatch)
    purchase = adapter.normalize(
        make_transaction_completed(details={"totals": {"grand_total": 1999, "currency_code": 7}})
    )
    assert purchase.amount is None
    assert purchase.currency is None


def test_extra_members_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _ = _adapter(monkeypatch)
    event = make_transaction_completed(unrelated={"nested": [1, 2, 3]})
    event["extra_envelope_member"] = True
    assert adapter.normalize(event).platform_purchase_id == _TRANSACTION_ID


@pytest.mark.parametrize("missing", ["id", "customer_id", "items", "billed_at"])
def test_missing_required_members_are_rejected_before_api_call(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    adapter, fake = _adapter(monkeypatch)
    event = make_transaction_completed()
    del event["data"][missing]
    with pytest.raises(PurchaseRejected):
        adapter.normalize(event)
    assert isinstance(fake, RecordingHttpGet)
    assert fake.calls == []


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_permanent_api_status_is_purchase_rejected(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    fake = RecordingHttpGet(_http_error(status))
    adapter, _ = _adapter(monkeypatch, fake)
    with pytest.raises(PurchaseRejected, match=r"paddle\.api_key_env"):
        adapter.normalize(make_transaction_completed())


@pytest.mark.parametrize("status", [408, 409, 429, 500, 503])
def test_transient_api_status_is_paddle_api_error(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(_http_error(status)))
    with pytest.raises(PaddleApiError, match=f"returned {status}"):
        adapter.normalize(make_transaction_completed())


def test_network_failure_is_paddle_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = urllib.error.URLError("network unavailable")
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(failure))
    with pytest.raises(PaddleApiError, match="unreachable"):
        adapter.normalize(make_transaction_completed())


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"data": {}},
        {"data": {"email": ""}},
        [],
        {"data": []},
        b"not-json",
    ],
)
def test_customer_response_without_email_is_purchase_rejected(
    monkeypatch: pytest.MonkeyPatch, response: Any
) -> None:
    body = response if isinstance(response, bytes) else json.dumps(response).encode()
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(body))
    with pytest.raises(PurchaseRejected, match="has no email"):
        adapter.normalize(make_transaction_completed())


def test_api_response_wrong_transaction_id_cannot_override_the_signed_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = json.dumps(
        {"data": {"email": "buyer@example.com", "transaction_id": "txn_wrong"}}
    ).encode()
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(response))
    purchase = adapter.normalize(make_transaction_completed())
    assert purchase.platform_purchase_id == _TRANSACTION_ID


def test_a_customer_response_for_a_different_customer_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = json.dumps(
        {"data": {"id": "ctm_" + "b" * 26, "email": "someone.else@example.com"}}
    ).encode()
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(response))
    with pytest.raises(PurchaseRejected, match="different customer"):
        adapter.normalize(make_transaction_completed())


def test_a_customer_response_echoing_the_requested_id_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = json.dumps({"data": {"id": _CUSTOMER_ID, "email": "buyer@example.com"}}).encode()
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(response))
    assert adapter.normalize(make_transaction_completed()).buyer_identifier == "buyer@example.com"


def test_401_then_200_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    success = json.dumps({"data": {"email": "buyer@example.com"}}).encode()
    fake = RecordingHttpGet(_http_error(401), success)
    adapter, _ = _adapter(monkeypatch, fake)
    with pytest.raises(PurchaseRejected, match=r"paddle\.api_key_env"):
        adapter.normalize(make_transaction_completed())
    assert len(fake.calls) == 1


@pytest.mark.parametrize("status", [401, 500])
def test_api_error_messages_never_contain_the_api_key(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(_http_error(status)))
    with pytest.raises((PurchaseRejected, PaddleApiError)) as raised:
        adapter.normalize(make_transaction_completed())
    assert _API_KEY not in str(raised.value)


def test_a_year_below_1000_is_still_zero_padded_to_rfc_3339(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = json.dumps({"data": {"email": "buyer@example.com"}}).encode()
    adapter, _ = _adapter(monkeypatch, RecordingHttpGet(response))
    purchase = adapter.normalize(make_transaction_completed(billed_at="0001-01-01T00:00:00Z"))
    assert purchase.purchased_at == "0001-01-01T00:00:00Z"


@pytest.mark.parametrize("body", [b"[]", b"123", b'"x"', b"null", b"true"])
def test_a_signed_body_that_is_json_but_not_an_object_reaches_the_handler_as_is(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    adapter, _ = _adapter(monkeypatch)
    event = adapter.parse_event(body, sign_paddle(body, _WEBHOOK_SECRET, _T), now=_T)
    assert not isinstance(event, dict)
    with pytest.raises(AttributeError):
        adapter.wants(event)  # type: ignore[arg-type]


# -- the WSGI route ----------------------------------------------------------


@pytest.fixture
def paddle_http() -> RecordingHttpGet:
    """Return the per-test Paddle customer API fake used by the route."""
    return RecordingHttpGet()


@pytest.fixture
def paddle_deps(
    catalog: Any,
    issuer_identity: IssuerIdentity,
    ledger: Ledger,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    paddle_http: RecordingHttpGet,
) -> BridgeDeps:
    """Build route dependencies with a deterministic Paddle clock and API."""
    monkeypatch.setattr(paddle_module.time, "time", lambda: float(_T))
    config = BridgeConfig(
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
        stripe=None,
        itch=None,
        delivery=None,
        paddle=PaddleConfig(webhook_secret=_WEBHOOK_SECRET, api_key=_API_KEY),
    )
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(None),
    )
    return BridgeDeps(
        config=config,
        core=core,
        ledger=ledger,
        stripe=None,
        log=logging.getLogger("test-bridge-paddle"),
        paddle=PaddleAdapter(
            webhook_secret=_WEBHOOK_SECRET,
            api_key=_API_KEY,
            http_get=paddle_http,
        ),
    )


def _route_transaction(
    *,
    event_id: str = "evt_paddle_route_1",
    transaction_id: str = "txn_paddle_route_1",
    **data_overrides: Any,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": transaction_id,
        "items": [{"price": {"id": _CATALOG_PRICE_ID}}],
    }
    data.update(data_overrides)
    event = make_transaction_completed(**data)
    event["event_id"] = event_id
    return event


def _post_paddle_webhook(
    deps: BridgeDeps,
    event: object,
    *,
    signature: str | None = None,
    app: Any | None = None,
) -> tuple[str, dict[str, str], bytes]:
    body = json.dumps(event).encode()
    header = sign_paddle(body, _WEBHOOK_SECRET, _T) if signature is None else signature
    return call_app(
        make_app(deps) if app is None else app,
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": header, "Content-Type": "application/json"},
    )


def test_e2e_signed_paddle_webhook_to_offline_verified_receipt(
    paddle_deps: BridgeDeps,
    trust_store: verify_mod.TrustStore,
    catalog: Any,
) -> None:
    event = _route_transaction(transaction_id="txn_paddle_e2e")

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    stored = paddle_deps.ledger.get_receipt("paddle", "txn_paddle_e2e")
    assert stored is not None
    assert verify_mod.verify(stored.envelope_json.encode(), trust_store).ok is True
    template = catalog.resolve(f"paddle_{_CATALOG_PRICE_ID}")
    assert json.loads(stored.envelope_json)["payload"]["work"]["title"] == template.title


def test_forged_paddle_signature_returns_400_and_ledger_stays_empty(
    paddle_deps: BridgeDeps,
) -> None:
    event = _route_transaction()
    body = json.dumps(event).encode()

    status, _, _ = _post_paddle_webhook(
        paddle_deps,
        event,
        signature=sign_paddle(body, _OTHER_SECRET, _T),
    )

    assert status.startswith("400")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_missing_paddle_signature_returns_400(paddle_deps: BridgeDeps) -> None:
    event = _route_transaction()
    status, _, _ = call_app(
        make_app(paddle_deps),
        "POST",
        "/paddle/webhook",
        body=json.dumps(event).encode(),
    )

    assert status.startswith("400")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False


def test_valid_paddle_signature_unparseable_json_returns_400(
    paddle_deps: BridgeDeps,
) -> None:
    body = b"{not json"
    status, _, _ = call_app(
        make_app(paddle_deps),
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": sign_paddle(body, _WEBHOOK_SECRET, _T)},
    )

    assert status.startswith("400")
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_valid_paddle_signature_non_utf8_body_returns_400(
    paddle_deps: BridgeDeps,
) -> None:
    body = b"\xffnot utf-8"
    status, _, _ = call_app(
        make_app(paddle_deps),
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": sign_paddle(body, _WEBHOOK_SECRET, _T)},
    )

    assert status.startswith("400")
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_non_ascii_paddle_signature_returns_400_with_an_empty_ledger(
    paddle_deps: BridgeDeps,
) -> None:
    event = _route_transaction()
    status, _, _ = _post_paddle_webhook(paddle_deps, event, signature=f"ts={_T};h1=\xff")

    assert status.startswith("400")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_paddle_event_without_an_id_is_dead_lettered_and_acknowledged(
    paddle_deps: BridgeDeps,
) -> None:
    event = _route_transaction()
    del event["event_id"]

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    dead_letters = paddle_deps.ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0].platform == "paddle"
    assert paddle_deps.ledger.get_receipt("paddle", event["data"]["id"]) is None


@pytest.mark.parametrize("event", [[], 7, "event", None, True])
def test_signed_non_object_paddle_event_is_dead_lettered_and_acknowledged(
    paddle_deps: BridgeDeps, event: object
) -> None:
    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    assert len(paddle_deps.ledger.unresolved_dead_letters()) == 1


def test_unhandled_paddle_event_type_returns_200_and_marks_event(
    paddle_deps: BridgeDeps,
) -> None:
    event = _route_transaction()
    event["event_type"] = "transaction.updated"

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is True
    assert paddle_deps.ledger.get_receipt("paddle", event["data"]["id"]) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "paid"},
        {"subscription_id": "sub_01h123456789abcdefghijklm"},
    ],
)
def test_not_actionable_paddle_event_returns_200_and_marks_event(
    paddle_deps: BridgeDeps, overrides: dict[str, Any]
) -> None:
    event = _route_transaction(**overrides)

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is True
    assert paddle_deps.ledger.get_receipt("paddle", event["data"]["id"]) is None


def test_replayed_paddle_event_id_returns_200_without_reprocessing(
    paddle_deps: BridgeDeps,
    paddle_http: RecordingHttpGet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _route_transaction(transaction_id="txn_paddle_replay")
    outcomes: list[Any] = []
    process = paddle_deps.core.process

    def record_process(purchase: Any) -> Any:
        outcome = process(purchase)
        outcomes.append(outcome)
        return outcome

    monkeypatch.setattr(paddle_deps.core, "process", record_process)

    first = _post_paddle_webhook(paddle_deps, event)
    second = _post_paddle_webhook(paddle_deps, event)

    assert first[0].startswith("200")
    assert second[0].startswith("200")
    assert len(outcomes) == 1
    assert len(paddle_http.calls) == 1


def test_concurrent_identical_paddle_webhooks_issue_exactly_one_receipt(
    paddle_deps: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = _route_transaction(transaction_id="txn_paddle_concurrent")
    app = make_app(paddle_deps)
    barrier = threading.Barrier(2)
    statuses: list[str] = []
    process_calls: list[int] = []
    results_lock = threading.Lock()
    process = paddle_deps.core.process

    def record_process(purchase: Any) -> Any:
        process_calls.append(1)
        return process(purchase)

    def hit() -> None:
        barrier.wait()
        status, _, _ = _post_paddle_webhook(paddle_deps, event, app=app)
        with results_lock:
            statuses.append(status)

    monkeypatch.setattr(paddle_deps.core, "process", record_process)
    threads = [threading.Thread(target=hit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(statuses) == 2
    assert all(status.startswith("200") for status in statuses)
    assert len(process_calls) == 1
    assert paddle_deps.ledger.get_receipt("paddle", "txn_paddle_concurrent") is not None


def test_unmapped_paddle_product_dead_letters_and_returns_200(
    paddle_deps: BridgeDeps,
) -> None:
    event = _route_transaction(items=[{"price": {"id": "pri_unmapped"}}])

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    assert len(paddle_deps.ledger.unresolved_dead_letters()) == 1
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is True


def test_missing_paddle_buyer_email_dead_letters_and_returns_200(
    paddle_deps: BridgeDeps,
) -> None:
    paddle_deps.paddle = PaddleAdapter(
        webhook_secret=_WEBHOOK_SECRET,
        api_key=_API_KEY,
        http_get=RecordingHttpGet(b'{"data":{}}'),
    )
    event = _route_transaction(transaction_id="txn_paddle_no_email")

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    assert len(paddle_deps.ledger.unresolved_dead_letters()) == 1
    assert paddle_deps.ledger.get_receipt("paddle", "txn_paddle_no_email") is None


def test_multiple_paddle_items_dead_letter_without_issuing(
    paddle_deps: BridgeDeps, paddle_http: RecordingHttpGet
) -> None:
    event = _route_transaction(
        transaction_id="txn_paddle_two_items",
        items=[{"price": {"id": _CATALOG_PRICE_ID}}, {"price": {"id": "pri_other"}}],
    )

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    assert paddle_deps.ledger.get_receipt("paddle", "txn_paddle_two_items") is None
    assert "one receipt per purchase" in paddle_deps.ledger.unresolved_dead_letters()[0].reason
    assert paddle_http.calls == []


def test_duplicate_paddle_purchase_across_two_events_reuses_receipt(
    paddle_deps: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes: list[Any] = []
    process = paddle_deps.core.process

    def record_process(purchase: Any) -> Any:
        outcome = process(purchase)
        outcomes.append(outcome)
        return outcome

    monkeypatch.setattr(paddle_deps.core, "process", record_process)
    first = _route_transaction(event_id="evt_paddle_a", transaction_id="txn_paddle_duplicate")
    second = _route_transaction(event_id="evt_paddle_b", transaction_id="txn_paddle_duplicate")

    assert _post_paddle_webhook(paddle_deps, first)[0].startswith("200")
    assert _post_paddle_webhook(paddle_deps, second)[0].startswith("200")
    assert [outcome.duplicate for outcome in outcomes] == [False, True]
    assert paddle_deps.ledger.seen_event("paddle", "evt_paddle_a") is True
    assert paddle_deps.ledger.seen_event("paddle", "evt_paddle_b") is True


def test_transient_paddle_api_failure_returns_500_without_dead_lettering_or_marking(
    paddle_deps: BridgeDeps,
) -> None:
    paddle_deps.paddle = PaddleAdapter(
        webhook_secret=_WEBHOOK_SECRET,
        api_key=_API_KEY,
        http_get=RecordingHttpGet(_http_error(503)),
    )
    event = _route_transaction(transaction_id="txn_paddle_transient")

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("500")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_permanent_paddle_api_failure_dead_letters_and_returns_200(
    paddle_deps: BridgeDeps,
) -> None:
    paddle_deps.paddle = PaddleAdapter(
        webhook_secret=_WEBHOOK_SECRET,
        api_key=_API_KEY,
        http_get=RecordingHttpGet(_http_error(401)),
    )
    event = _route_transaction(transaction_id="txn_paddle_permanent")

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("200")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is True
    assert len(paddle_deps.ledger.unresolved_dead_letters()) == 1


def test_paddle_api_calls_happen_before_the_webhook_lock(
    paddle_deps: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    class InspectableLock:
        def __init__(self) -> None:
            self.locked = False

        def __enter__(self) -> None:
            assert self.locked is False
            self.locked = True

        def __exit__(self, *args: object) -> None:
            self.locked = False

    lock = InspectableLock()

    def customer_get(url: str, headers: dict[str, str]) -> bytes:
        assert lock.locked is False
        return b'{"data":{"email":"buyer@example.com"}}'

    monkeypatch.setattr(http_module.threading, "Lock", lambda: lock)
    paddle_deps.paddle = PaddleAdapter(
        webhook_secret=_WEBHOOK_SECRET,
        api_key=_API_KEY,
        http_get=customer_get,
    )

    assert _post_paddle_webhook(paddle_deps, _route_transaction())[0].startswith("200")


def test_unexpected_paddle_core_exception_returns_500_and_does_not_mark_event(
    paddle_deps: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(purchase: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(paddle_deps.core, "issue_for", boom)
    event = _route_transaction(transaction_id="txn_paddle_boom")

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("500")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_unexpected_paddle_adapter_exception_returns_500_and_does_not_mark_event(
    paddle_deps: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = _route_transaction()

    def boom(payload: bytes, sig_header: str, *, now: int | None = None) -> dict[str, Any]:
        raise RuntimeError("adapter bug")

    assert paddle_deps.paddle is not None
    monkeypatch.setattr(paddle_deps.paddle, "parse_event", boom)

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("500")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False


def test_paddle_timestamp_underflow_returns_500_and_does_not_mark_event(
    paddle_deps: BridgeDeps,
) -> None:
    event = _route_transaction(billed_at="0001-01-01T00:00:00+05:00")

    status, _, _ = _post_paddle_webhook(paddle_deps, event)

    assert status.startswith("500")
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_paddle_route_is_404_when_paddle_is_not_configured(paddle_deps: BridgeDeps) -> None:
    paddle_deps.paddle = None

    status, _, _ = _post_paddle_webhook(paddle_deps, _route_transaction())

    assert status.startswith("404")


def test_oversized_paddle_body_returns_413_without_calling_the_adapter(
    paddle_deps: BridgeDeps, paddle_http: RecordingHttpGet
) -> None:
    app = make_app(paddle_deps, webhook_body_limit_bytes=32)
    event = _route_transaction()
    body = json.dumps(event).encode()
    status, _, _ = call_app(
        app,
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": sign_paddle(body, _WEBHOOK_SECRET, _T)},
    )

    assert status.startswith("413")
    assert paddle_http.calls == []
    assert paddle_deps.ledger.seen_event("paddle", event["event_id"]) is False
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_no_paddle_log_line_carries_the_raw_purchase_id_or_a_secret(
    paddle_deps: BridgeDeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    purchase_id = "txn_paddle_log_secret_guard"
    event = _route_transaction(transaction_id=purchase_id)
    caplog.set_level(logging.INFO)

    assert _post_paddle_webhook(paddle_deps, event)[0].startswith("200")

    for record in caplog.records:
        message = record.getMessage()
        assert purchase_id not in message
        assert _WEBHOOK_SECRET not in message
        assert _API_KEY not in message


def test_a_non_completed_transaction_marked_seen_does_not_close_the_door_on_its_completion(
    paddle_deps: BridgeDeps,
) -> None:
    """Ordering hostility (plan section 6): the two events carry different event ids.

    Marking the non-actionable one seen is only safe because of that. Keying on
    the transaction id instead — the Shopify shape — would acknowledge and
    discard the `transaction.completed` that follows.
    """
    ready = _route_transaction(
        event_id="evt_paddle_ready", transaction_id="txn_paddle_lifecycle", status="ready"
    )
    completed = _route_transaction(
        event_id="evt_paddle_completed", transaction_id="txn_paddle_lifecycle"
    )

    assert _post_paddle_webhook(paddle_deps, ready)[0].startswith("200")
    assert paddle_deps.ledger.seen_event("paddle", "evt_paddle_ready") is True
    assert _post_paddle_webhook(paddle_deps, completed)[0].startswith("200")

    assert paddle_deps.ledger.get_receipt("paddle", "txn_paddle_lifecycle") is not None
    assert paddle_deps.ledger.seen_event("paddle", "evt_paddle_completed") is True


def test_a_signed_body_that_can_never_parse_is_400_not_a_three_day_retry_loop(
    paddle_deps: BridgeDeps,
) -> None:
    """Y5 on this rail too: `json.loads` raises `RecursionError`, not a decode
    error, on a deeply nested body, and the handler's 500 row would make Paddle
    redeliver a body that can never parse 60 times over three days. Well under
    the route's body cap, so the cap does not cover this."""
    body = b"[" * 20_000 + b"]" * 20_000

    status, _, _ = call_app(
        make_app(paddle_deps),
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": sign_paddle(body, _WEBHOOK_SECRET, _T)},
    )

    assert status.startswith("400")
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_a_signed_body_with_a_lone_surrogate_is_400_not_an_escaping_encode_error(
    paddle_deps: BridgeDeps,
) -> None:
    """A `\\udXXX` escape is legal JSON syntax and `json.loads` answers it with
    a `str` Python can hold but cannot encode. It survives every `isinstance`
    the adapter writes and fails at the first sink that encodes it — here
    `Ledger.seen_event`, which the handler calls OUTSIDE every `try`. So the
    failure did not land on the policy table's 500 row: it escaped
    `_handle_paddle_webhook`, escaped `app()`, and reached the WSGI server.
    Stripe and Shopify never had this hole because they parse through
    `loads_utf8_strict`; this rail has to use the same door."""
    body = json.dumps(make_transaction_completed()).encode()
    body = body.replace(b'"event_id": "evt', b'"event_id": "\\ud800evt')

    status, _, _ = call_app(
        make_app(paddle_deps),
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": sign_paddle(body, _WEBHOOK_SECRET, _T)},
    )

    assert status.startswith("400")
    assert paddle_deps.ledger.unresolved_dead_letters() == []


def test_a_signed_body_whose_integer_literal_is_too_long_is_400_not_a_retry_loop(
    paddle_deps: BridgeDeps,
) -> None:
    """CPython refuses to build an int from a literal of more than 4300 digits
    and says so with a BARE `ValueError`, not a `JSONDecodeError`. Unnormalised
    it reaches the handler's 500 row, and Paddle redelivers a body that can
    never parse 60 times over three days. The boundary is exact: 4300 digits
    parse, 4301 do not — and it sits far under the route's body cap, so the cap
    does not cover it. The PayPal twin already answers 400 on the same input."""
    body = b'{"event_id": "evt_1", "data": {"amount": ' + b"1" * 4301 + b"}}"

    status, _, _ = call_app(
        make_app(paddle_deps),
        "POST",
        "/paddle/webhook",
        body=body,
        headers={"Paddle-Signature": sign_paddle(body, _WEBHOOK_SECRET, _T)},
    )

    assert status.startswith("400")
    assert paddle_deps.ledger.unresolved_dead_letters() == []
