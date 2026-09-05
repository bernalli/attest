"""Paddle Billing adapter signature, actionability, and normalization tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import string
import urllib.error
from collections.abc import Callable
from typing import Any

import pytest
from attest_bridge import paddle_adapter as paddle_module
from attest_bridge.model import ConfigError, PurchaseRejected
from attest_bridge.paddle_adapter import (
    PaddleAdapter,
    PaddleApiError,
    PaddleSignatureError,
    verify_paddle_signature,
)
from hypothesis import given, settings
from hypothesis import strategies as st

from attest import keys

_WEBHOOK_SECRET = "pdl_ntfset_test_fixture"  # noqa: S105 - env var PADDLE_WEBHOOK_SECRET, not a secret
_API_KEY = "pdl_sdbx_apikey_test_fixture"
_OTHER_SECRET = "pdl_ntfset_other_fixture"  # noqa: S105 - env var PADDLE_WEBHOOK_SECRET, not a secret
_T = 1_784_000_000
_CUSTOMER_ID = "ctm_" + "a" * 26
_TRANSACTION_ID = "txn_01h123456789abcdefghijklm"
_PRICE_ID = "pri_01h123456789abcdefghijklm"
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
