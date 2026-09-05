"""PayPal adapter tests: postback verification and order normalization."""

from __future__ import annotations

import base64
import json
import logging
import threading
import urllib.error
from collections.abc import Callable
from typing import Any

import attest_bridge.http as http_module
import attest_bridge.paypal_adapter as paypal_module
import pytest
from attest_bridge.config import BridgeConfig, IssuerConfig, PayPalConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.ledger import Ledger
from attest_bridge.model import BridgeError, ConfigError, PurchaseRejected
from attest_bridge.paypal_adapter import (
    PayPalAdapter,
    PayPalApiError,
    PayPalSignatureError,
    PayPalTransmission,
    build_verification_request,
)
from attest_bridge.signing import IssuerIdentity
from conftest import DISPLAY_NAME, ISSUER, KID
from hypothesis import given
from hypothesis import strategies as st
from pytest import MonkeyPatch
from test_bridge_http import call_app

from attest import verify as verify_mod

_CLIENT_ID = "paypal-test-client-id"
_CLIENT_SECRET = "paypal-test-client-secret"  # noqa: S105 - env var PAYPAL_TEST_SECRET, not a secret
_WEBHOOK_ID = "8PT597110X687430LKGECATA"
_ACCESS_TOKEN = "paypal-test-access-token"  # noqa: S105 - env var PAYPAL_TEST_TOKEN, not a secret
_ORDER_ID = "5O190127TN364715T"


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api-m.paypal.com", code, "failure", {}, None)


def make_transmission(**overrides: Any) -> PayPalTransmission:
    """Return valid PayPal transmission metadata with optional overrides."""
    values: dict[str, Any] = {
        "transmission_id": "69cd13f0-d67a-11e5-baa3-778b53f4ae55",
        "transmission_time": "2026-09-05T10:00:00Z",
        "transmission_sig": "base64-signature",
        "cert_url": "https://api.paypal.com/v1/notifications/certs/CERT-1",
        "auth_algo": "SHA256withRSA",
    }
    values.update(overrides)
    return PayPalTransmission(**values)


def make_capture_completed(**overrides: Any) -> dict[str, Any]:
    """Return a Payments v2 final-capture event shaped like PayPal's envelope."""
    resource: dict[str, Any] = {
        "id": "2GG279541U471931P",
        "status": "COMPLETED",
        "amount": {"currency_code": "USD", "value": "100.00"},
        "final_capture": True,
        "supplementary_data": {"related_ids": {"order_id": _ORDER_ID}},
        "create_time": "2026-09-05T09:58:00Z",
    }
    resource_override = overrides.pop("resource", {})
    if isinstance(resource_override, dict):
        resource.update(resource_override)
        event_resource: Any = resource
    else:
        event_resource = resource_override
    event: dict[str, Any] = {
        "id": "WH-7W0787462A916330F-7MF68566VF385353G",
        "event_version": "1.0",
        "create_time": "2026-09-05T09:58:01Z",
        "resource_type": "capture",
        "resource_version": "2.0",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "summary": "Payment completed",
        "resource": event_resource,
        "links": [],
    }
    event.update(overrides)
    return event


def make_order(**overrides: Any) -> dict[str, Any]:
    """Return a one-unit, one-item Orders v2 response."""
    order: dict[str, Any] = {
        "id": _ORDER_ID,
        "status": "COMPLETED",
        "intent": "CAPTURE",
        "payer": {"email_address": "buyer@example.com"},
        "purchase_units": [
            {
                "reference_id": "default",
                "items": [{"name": "Stardrift Chronicles", "sku": "SDC-STD-001"}],
            }
        ],
    }
    order.update(overrides)
    return order


class FakePayPalApi:
    """In-memory replacement for the two shared outbound HTTP primitives."""

    def __init__(self) -> None:
        self.post_calls: list[tuple[str, dict[str, str], bytes]] = []
        self.get_calls: list[tuple[str, dict[str, str]]] = []
        self.verification_responses: list[bytes | BaseException] = []
        self.token_responses: list[bytes | BaseException] = []
        self.order_responses: list[bytes | BaseException] = []
        self.order = make_order()
        self.token_number = 0

    def post(self, url: str, headers: dict[str, str], body: bytes) -> bytes:
        self.post_calls.append((url, dict(headers), body))
        if url.endswith("/v1/oauth2/token"):
            if self.token_responses:
                return self._resolve(self.token_responses.pop(0))
            self.token_number += 1
            return json.dumps(
                {"access_token": f"{_ACCESS_TOKEN}-{self.token_number}", "expires_in": 120}
            ).encode()
        if url.endswith("/v1/notifications/verify-webhook-signature"):
            if self.verification_responses:
                return self._resolve(self.verification_responses.pop(0))
            return b'{"verification_status":"SUCCESS"}'
        raise AssertionError(f"unexpected POST url: {url}")

    def get(self, url: str, headers: dict[str, str]) -> bytes:
        self.get_calls.append((url, dict(headers)))
        if self.order_responses:
            return self._resolve(self.order_responses.pop(0))
        return json.dumps(self.order).encode()

    @staticmethod
    def _resolve(value: bytes | BaseException) -> bytes:
        if isinstance(value, BaseException):
            raise value
        return value

    def token_calls(self) -> list[tuple[str, dict[str, str], bytes]]:
        return [call for call in self.post_calls if call[0].endswith("/v1/oauth2/token")]

    def verification_calls(self) -> list[tuple[str, dict[str, str], bytes]]:
        return [
            call
            for call in self.post_calls
            if call[0].endswith("/v1/notifications/verify-webhook-signature")
        ]


def make_adapter(
    monkeypatch: MonkeyPatch,
    api: FakePayPalApi,
    *,
    environment: str = "live",
    now: Callable[[], float] | None = None,
    client_secret: str = _CLIENT_SECRET,
) -> PayPalAdapter:
    """Patch the shared HTTP primitives and construct an adapter."""
    monkeypatch.setattr(paypal_module, "https_post", api.post)
    monkeypatch.setattr(paypal_module, "https_get", api.get)
    return PayPalAdapter(
        client_id=_CLIENT_ID,
        client_secret=client_secret,
        webhook_id=_WEBHOOK_ID,
        environment=environment,
        now=now,
    )


def _payload(event: dict[str, Any] | None = None) -> bytes:
    return json.dumps(event if event is not None else make_capture_completed()).encode()


def test_build_verification_request_embeds_the_raw_body_verbatim() -> None:
    payload = b'{\n  "id" : "evt-1", "summary": "spaces stay"\n}'
    request = build_verification_request(payload, make_transmission(), _WEBHOOK_ID)

    assert request.find(payload) != -1
    assert request.endswith(b'"webhook_event":' + payload + b"}")


_JSON_SCALARS = (
    st.none() | st.booleans() | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1) | st.text()
)
_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(), children, max_size=5)
    ),
    max_leaves=20,
)


@given(
    value=_JSON_VALUES,
    indent=st.one_of(st.none(), st.integers(min_value=0, max_value=4)),
    ensure_ascii=st.booleans(),
)
def test_verification_request_parses_to_the_original_event_for_any_json_body(
    value: Any, indent: int | None, ensure_ascii: bool
) -> None:
    payload = json.dumps(
        value,
        ensure_ascii=ensure_ascii,
        indent=indent,
        separators=None if indent is not None else (",", ":"),
    ).encode()

    request = build_verification_request(payload, make_transmission(), _WEBHOOK_ID)

    assert json.loads(request)["webhook_event"] == value
    assert request.find(payload) != -1


def test_verification_request_keeps_non_ascii_bytes_untouched() -> None:
    payload = '{"summary":"caffè ☃"}'.encode()
    request = build_verification_request(payload, make_transmission(), _WEBHOOK_ID)

    assert payload in request
    assert json.loads(request)["webhook_event"] == {"summary": "caffè ☃"}


def test_parse_event_calls_the_postback_before_parsing_and_only_parses_on_success(
    monkeypatch: MonkeyPatch,
) -> None:
    api = FakePayPalApi()
    api.verification_responses = [b'{"verification_status":"FAILURE"}']
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(PayPalSignatureError):
        transmission = make_transmission()
        adapter.parse_event(b"not json", transmission)

    assert len(api.verification_calls()) == 1
    assert api.verification_calls()[0][2] == build_verification_request(
        b"not json", transmission, _WEBHOOK_ID
    )


def test_oauth_and_postback_requests_have_exact_headers_and_bodies(
    monkeypatch: MonkeyPatch,
) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)
    payload = _payload()
    transmission = make_transmission()

    adapter.parse_event(payload, transmission)

    oauth_url, oauth_headers, oauth_body = api.token_calls()[0]
    basic = base64.b64encode(f"{_CLIENT_ID}:{_CLIENT_SECRET}".encode()).decode()
    assert oauth_url == "https://api-m.paypal.com/v1/oauth2/token"
    assert oauth_headers == {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    assert oauth_body == b"grant_type=client_credentials"

    verify_url, verify_headers, verify_body = api.verification_calls()[0]
    assert verify_url == ("https://api-m.paypal.com/v1/notifications/verify-webhook-signature")
    assert verify_headers == {
        "Authorization": f"Bearer {_ACCESS_TOKEN}-1",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    assert verify_body == build_verification_request(payload, transmission, _WEBHOOK_ID)


@pytest.mark.parametrize(
    "response",
    [
        b'{"verification_status":"FAILURE"}',
        b'{"verification_status":"success"}',
        b'{"verification_status":"SUCCESS "}',
        b'{"verification_status":" SUCCESS"}',
        b'{"verification_status":["SUCCESS"]}',
        b'{"VERIFICATION_STATUS":"SUCCESS"}',
        b'{"verification_status":"SUCCESS","verification_status":"FAILURE"}',
        b'{"verification_status":""}',
        b'{"verification_status":null}',
        b'{"verification_status":1}',
        b'{"verification_status":{"x":1}}',
        b"[]",
        b"null",
        b"true",
        b"123",
        b'"SUCCESS"',
        b"",
        b"not json",
    ],
)
def test_anything_but_the_exact_success_string_is_a_failure(
    monkeypatch: MonkeyPatch, response: bytes
) -> None:
    api = FakePayPalApi()
    api.verification_responses = [response]
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(PayPalSignatureError, match="signature verification failed"):
        adapter.parse_event(_payload(), make_transmission())


@pytest.mark.parametrize(
    "field",
    ["transmission_id", "transmission_time", "transmission_sig", "cert_url", "auth_algo"],
)
@pytest.mark.parametrize("bad", ["", "   ", None])
def test_missing_or_blank_transmission_header_is_a_signature_error(
    monkeypatch: MonkeyPatch, field: str, bad: Any
) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(PayPalSignatureError, match="missing PayPal transmission headers"):
        adapter.parse_event(_payload(), make_transmission(**{field: bad}))

    assert api.post_calls == []


def test_unsupported_auth_algo_is_rejected_before_any_call(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(PayPalSignatureError, match="unsupported auth algorithm"):
        adapter.parse_event(_payload(), make_transmission(auth_algo="SHA1withRSA"))

    assert api.post_calls == []


@pytest.mark.parametrize(
    ("cert_url", "accepted"),
    [
        ("http://api.paypal.com/x", False),
        ("https://paypal.com.evil.example/x", False),
        ("https://evil-paypal.com/x", False),
        ("https://evilpaypal.com/x", False),
        ("https://api.paypal.com", True),
        ("https://api.sandbox.paypal.com/v1/notifications/certs/CERT", True),
    ],
)
def test_cert_url_must_be_https_on_paypal_com(
    monkeypatch: MonkeyPatch, cert_url: str, accepted: bool
) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)

    if accepted:
        assert adapter.parse_event(_payload(), make_transmission(cert_url=cert_url))
        assert len(api.verification_calls()) == 1
    else:
        with pytest.raises(PayPalSignatureError, match=r"paypal[.]com https url"):
            adapter.parse_event(_payload(), make_transmission(cert_url=cert_url))
        assert api.post_calls == []


def test_empty_payload_is_rejected_before_any_call(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(PayPalSignatureError, match="empty body"):
        adapter.parse_event(b"", make_transmission())

    assert api.post_calls == []


@pytest.mark.parametrize(("code", "error"), [(400, PayPalSignatureError), (500, PayPalApiError)])
def test_verification_400_is_a_signature_error_and_5xx_is_transient(
    monkeypatch: MonkeyPatch, code: int, error: type[Exception]
) -> None:
    api = FakePayPalApi()
    api.verification_responses = [_http_error(code)]
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(error):
        adapter.parse_event(_payload(), make_transmission())


@pytest.mark.parametrize("fails_twice", [False, True], ids=["retry_success", "retry_failure"])
def test_a_401_refreshes_the_token_once_then_fails_closed(
    monkeypatch: MonkeyPatch, fails_twice: bool
) -> None:
    api = FakePayPalApi()
    api.verification_responses = [_http_error(401)]
    if fails_twice:
        api.verification_responses.append(_http_error(401))
    adapter = make_adapter(monkeypatch, api)

    if fails_twice:
        with pytest.raises(PayPalApiError, match="client_id_env / client_secret_env"):
            adapter.parse_event(_payload(), make_transmission())
    else:
        assert adapter.parse_event(_payload(), make_transmission()) == make_capture_completed()

    assert len(api.token_calls()) == 2
    assert len(api.verification_calls()) == 2


def test_token_is_cached_until_its_margin(monkeypatch: MonkeyPatch) -> None:
    clock = [1_000.0]
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api, now=lambda: clock[0])

    adapter.parse_event(_payload(), make_transmission())
    clock[0] = 1_059.0
    adapter.parse_event(_payload(), make_transmission())
    assert len(api.token_calls()) == 1

    clock[0] = 1_060.0
    adapter.parse_event(_payload(), make_transmission())
    assert len(api.token_calls()) == 2


@pytest.mark.parametrize(
    "token_response",
    [
        b"not json",
        b"[]",
        b"{}",
        b'{"access_token":"","expires_in":120}',
        b'{"access_token":"x","expires_in":true}',
    ],
)
def test_malformed_token_responses_are_api_errors(
    monkeypatch: MonkeyPatch, token_response: bytes
) -> None:
    api = FakePayPalApi()
    api.token_responses = [token_response]
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(PayPalApiError):
        adapter.parse_event(_payload(), make_transmission())


@pytest.mark.parametrize(
    ("failure_path", "failure"),
    [
        ("token", _http_error(401)),
        ("token", _http_error(500)),
        ("token", urllib.error.URLError("offline")),
        ("token", b'{"access_token":"x","expires_in":"soon"}'),
        ("verification", _http_error(401)),
        ("verification", _http_error(500)),
        ("verification", urllib.error.URLError("offline")),
        ("order", _http_error(401)),
        ("order", _http_error(403)),
        ("order", _http_error(500)),
        ("order", urllib.error.URLError("offline")),
    ],
)
def test_no_message_ever_contains_the_client_secret_or_the_token(
    monkeypatch: MonkeyPatch, failure_path: str, failure: Any
) -> None:
    """Every branch that builds a message must be forced, not just one per path.

    A 401 is queued twice so the refresh-once path also terminates in an error.
    """
    api = FakePayPalApi()
    queue = [failure, failure]
    if failure_path == "token":
        api.token_responses = queue
    elif failure_path == "verification":
        api.verification_responses = queue
    else:
        api.order_responses = queue
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(BridgeError) as raised:
        if failure_path == "order":
            adapter.normalize(make_capture_completed())
        else:
            adapter.parse_event(_payload(), make_transmission())

    message = str(raised.value)
    basic = base64.b64encode(f"{_CLIENT_ID}:{_CLIENT_SECRET}".encode()).decode()
    assert _CLIENT_SECRET not in message
    assert _ACCESS_TOKEN not in message
    assert "Basic " not in message
    assert basic not in message


@pytest.mark.parametrize(
    "kwargs",
    [
        {"client_id": ""},
        {"client_id": "   "},
        {"client_secret": ""},
        {"client_secret": "   "},
        {"webhook_id": ""},
        {"webhook_id": "   "},
        {"environment": "production"},
    ],
)
def test_empty_credentials_or_webhook_id_are_config_errors(kwargs: dict[str, str]) -> None:
    values = {
        "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
        "webhook_id": _WEBHOOK_ID,
        "environment": "live",
    }
    values.update(kwargs)
    with pytest.raises(ConfigError):
        PayPalAdapter(**values)


def test_wants_true_for_a_completed_final_capture(monkeypatch: MonkeyPatch) -> None:
    assert make_adapter(monkeypatch, FakePayPalApi()).wants(make_capture_completed()) is True


@pytest.mark.parametrize(
    "event_type",
    [
        "CHECKOUT.ORDER.APPROVED",
        "CHECKOUT.ORDER.COMPLETED",
        "PAYMENT.CAPTURE.REFUNDED",
        "PAYMENT.SALE.COMPLETED",
    ],
)
def test_wants_false_for_other_event_types(monkeypatch: MonkeyPatch, event_type: str) -> None:
    event = make_capture_completed(event_type=event_type, resource="not-an-object")
    assert make_adapter(monkeypatch, FakePayPalApi()).wants(event) is False


@pytest.mark.parametrize("status", ["PENDING", "DECLINED", "REFUNDED", ""])
def test_wants_false_when_status_is_not_completed(monkeypatch: MonkeyPatch, status: str) -> None:
    event = make_capture_completed(resource={"status": status, "final_capture": "wrong"})
    assert make_adapter(monkeypatch, FakePayPalApi()).wants(event) is False


def test_wants_false_for_a_partial_capture(monkeypatch: MonkeyPatch) -> None:
    event = make_capture_completed(resource={"final_capture": False})
    assert make_adapter(monkeypatch, FakePayPalApi()).wants(event) is False


def test_wants_treats_an_absent_final_capture_as_final(monkeypatch: MonkeyPatch) -> None:
    event = make_capture_completed()
    del event["resource"]["final_capture"]
    assert make_adapter(monkeypatch, FakePayPalApi()).wants(event) is True


@pytest.mark.parametrize("value", ["false", 0])
def test_wants_rejects_a_non_bool_final_capture(monkeypatch: MonkeyPatch, value: Any) -> None:
    event = make_capture_completed(resource={"final_capture": value})
    with pytest.raises(PurchaseRejected):
        make_adapter(monkeypatch, FakePayPalApi()).wants(event)


def test_wants_rejects_a_non_object_resource(monkeypatch: MonkeyPatch) -> None:
    with pytest.raises(PurchaseRejected, match="resource is not an object"):
        make_adapter(monkeypatch, FakePayPalApi()).wants(
            make_capture_completed(resource="not-an-object")
        )


def test_normalize_uses_the_order_id_as_the_purchase_id_and_fetches_the_order(
    monkeypatch: MonkeyPatch,
) -> None:
    api = FakePayPalApi()
    purchase = make_adapter(monkeypatch, api).normalize(make_capture_completed())

    assert purchase.platform == "paypal"
    assert purchase.platform_purchase_id == _ORDER_ID
    assert purchase.buyer_identifier == "buyer@example.com"
    assert purchase.identifier_type == "email"
    assert purchase.buyer_pubkey is None
    assert purchase.product_key == "paypal_SDC-STD-001"
    assert purchase.purchased_at == "2026-09-05T09:58:00Z"
    assert purchase.amount == "100.00"
    assert purchase.currency == "USD"
    assert api.get_calls[0][0] == f"https://api-m.paypal.com/v2/checkout/orders/{_ORDER_ID}"


def test_sandbox_base(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api, environment="sandbox")
    adapter.parse_event(_payload(), make_transmission())
    adapter.normalize(make_capture_completed())

    assert all(url.startswith("https://api-m.sandbox.paypal.com/") for url, _, _ in api.post_calls)
    assert api.get_calls[0][0].startswith("https://api-m.sandbox.paypal.com/")


@pytest.mark.parametrize("bad", [None, "", "../x", "a b", True, "x" * 65])
def test_normalize_rejects_a_missing_or_malformed_related_order_id(
    monkeypatch: MonkeyPatch, bad: Any
) -> None:
    api = FakePayPalApi()
    event = make_capture_completed(
        resource={"supplementary_data": {"related_ids": {"order_id": bad}}}
    )

    with pytest.raises(PurchaseRejected, match="no usable related order id"):
        make_adapter(monkeypatch, api).normalize(event)

    assert api.post_calls == []
    assert api.get_calls == []


@pytest.mark.parametrize(
    "chain",
    [
        None,
        "bad",
        {},
        {"related_ids": None},
        {"related_ids": "bad"},
        {"related_ids": {}},
    ],
)
def test_wrong_types_in_the_related_order_chain_are_rejected_before_network(
    monkeypatch: MonkeyPatch, chain: Any
) -> None:
    api = FakePayPalApi()
    event = make_capture_completed(resource={"supplementary_data": chain})

    with pytest.raises(PurchaseRejected, match="no usable related order id"):
        make_adapter(monkeypatch, api).normalize(event)

    assert api.post_calls == []
    assert api.get_calls == []


@pytest.mark.parametrize("bad", [None, "", "   ", "yesterday", 17])
def test_normalize_rejects_an_unparseable_create_time(monkeypatch: MonkeyPatch, bad: Any) -> None:
    api = FakePayPalApi()
    with pytest.raises(PurchaseRejected, match="create_time"):
        make_adapter(monkeypatch, api).normalize(
            make_capture_completed(resource={"create_time": bad})
        )
    assert api.get_calls == []


@pytest.mark.parametrize(
    ("amount_data", "expected"),
    [
        (None, (None, None)),
        ({}, (None, None)),
        ({"value": 100, "currency_code": ["USD"]}, (None, None)),
        ({"value": "12.30", "currency_code": "EUR"}, ("12.30", "EUR")),
    ],
)
def test_amount_rules(
    monkeypatch: MonkeyPatch, amount_data: Any, expected: tuple[str | None, str | None]
) -> None:
    api = FakePayPalApi()
    event = make_capture_completed(resource={"amount": amount_data})
    purchase = make_adapter(monkeypatch, api).normalize(event)
    assert (purchase.amount, purchase.currency) == expected


def test_amount_wrong_type_is_rejected_before_network(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    with pytest.raises(PurchaseRejected, match="amount is not an object"):
        make_adapter(monkeypatch, api).normalize(
            make_capture_completed(resource={"amount": "100.00"})
        )
    assert api.get_calls == []


@pytest.mark.parametrize("payer", [None, {}, {"email_address": ""}, {"email_address": 7}])
def test_normalize_rejects_an_order_without_a_payer_email(
    monkeypatch: MonkeyPatch, payer: Any
) -> None:
    api = FakePayPalApi()
    api.order = make_order(payer=payer)
    with pytest.raises(PurchaseRejected, match=r"payer[.]email_address"):
        make_adapter(monkeypatch, api).normalize(make_capture_completed())


@pytest.mark.parametrize(
    "purchase_units",
    [
        [],
        [{"items": [{"sku": "one"}]}, {"items": [{"sku": "two"}]}],
        [{"items": []}],
        [{"items": [{"sku": "one"}, {"sku": "two"}]}],
        [{}],
        "not-a-list",
        ["not-an-object"],
    ],
)
def test_normalize_rejects_more_than_one_purchase_unit_or_item(
    monkeypatch: MonkeyPatch, purchase_units: Any
) -> None:
    api = FakePayPalApi()
    api.order = make_order(purchase_units=purchase_units)
    with pytest.raises(PurchaseRejected) as raised:
        make_adapter(monkeypatch, api).normalize(make_capture_completed())
    assert "one receipt per purchase" in str(raised.value)


@pytest.mark.parametrize("item", [{}, {"sku": ""}, {"sku": 7}])
def test_normalize_rejects_a_line_item_without_a_sku(
    monkeypatch: MonkeyPatch, item: dict[str, Any]
) -> None:
    api = FakePayPalApi()
    api.order = make_order(purchase_units=[{"items": [item]}])
    with pytest.raises(PurchaseRejected, match="no sku"):
        make_adapter(monkeypatch, api).normalize(make_capture_completed())


def test_custom_id_never_names_the_product(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    api.order = make_order(
        purchase_units=[{"custom_id": "someone-elses-product", "items": [{"sku": "SDC-STD-001"}]}]
    )
    purchase = make_adapter(monkeypatch, api).normalize(make_capture_completed())
    assert purchase.product_key == "paypal_SDC-STD-001"


def test_custom_id_is_not_interpreted_today_and_the_seam_returns_an_empty_map(
    monkeypatch: MonkeyPatch,
) -> None:
    api = FakePayPalApi()
    api.order = make_order(
        purchase_units=[{"custom_id": "x" * 255, "items": [{"sku": "SDC-STD-001"}]}]
    )
    adapter = make_adapter(monkeypatch, api)
    purchase = adapter.normalize(make_capture_completed())
    assert adapter._checkout_attributes(api.order) == {}
    assert purchase.buyer_pubkey is None


@pytest.mark.parametrize("code", [400, 403, 404])
def test_permanent_order_fetch_status_is_purchase_rejected(
    monkeypatch: MonkeyPatch, code: int
) -> None:
    api = FakePayPalApi()
    api.order_responses = [_http_error(code)]
    with pytest.raises(PurchaseRejected, match=f"api returned {code}"):
        make_adapter(monkeypatch, api).normalize(make_capture_completed())


@pytest.mark.parametrize(
    "failure",
    [
        _http_error(408),
        _http_error(429),
        _http_error(500),
        _http_error(503),
        urllib.error.URLError("offline"),
    ],
)
def test_transient_order_fetch_status_is_paypal_api_error(
    monkeypatch: MonkeyPatch, failure: BaseException
) -> None:
    api = FakePayPalApi()
    api.order_responses = [failure]
    with pytest.raises(PayPalApiError):
        make_adapter(monkeypatch, api).normalize(make_capture_completed())


@pytest.mark.parametrize("fails_twice", [False, True], ids=["retry_success", "retry_failure"])
def test_order_fetch_401_refreshes_once(monkeypatch: MonkeyPatch, fails_twice: bool) -> None:
    api = FakePayPalApi()
    api.order_responses = [_http_error(401)]
    if fails_twice:
        api.order_responses.append(_http_error(401))
    adapter = make_adapter(monkeypatch, api)

    if fails_twice:
        with pytest.raises(PayPalApiError, match="client_id_env / client_secret_env"):
            adapter.normalize(make_capture_completed())
    else:
        assert adapter.normalize(make_capture_completed()).platform_purchase_id == _ORDER_ID

    assert len(api.token_calls()) == 2
    assert len(api.get_calls) == 2


def test_order_response_with_the_wrong_id_is_rejected(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    api.order = make_order(id="DIFFERENTORDER123")
    with pytest.raises(PurchaseRejected, match="does not match capture order"):
        make_adapter(monkeypatch, api).normalize(make_capture_completed())


@pytest.mark.parametrize("response", [b"not json", b"[]", b"null"])
def test_order_response_must_be_a_json_object(monkeypatch: MonkeyPatch, response: bytes) -> None:
    api = FakePayPalApi()
    api.order_responses = [response]
    with pytest.raises(PurchaseRejected, match="order response"):
        make_adapter(monkeypatch, api).normalize(make_capture_completed())


def test_duplicated_json_members_are_rejected_after_success(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)
    body = b'{"id":"first","id":"second","event_type":"PAYMENT.CAPTURE.COMPLETED","resource":{}}'

    with pytest.raises(ValueError, match="duplicate JSON member"):
        adapter.parse_event(body, make_transmission())

    assert body in api.verification_calls()[0][2]


def test_wrong_json_member_types_are_rejected(monkeypatch: MonkeyPatch) -> None:
    adapter = make_adapter(monkeypatch, FakePayPalApi())
    with pytest.raises(PurchaseRejected, match="resource is not an object"):
        adapter.wants({"event_type": "PAYMENT.CAPTURE.COMPLETED", "resource": []})


def test_extra_json_members_are_ignored(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    api.order = make_order(unrecognized={"future": True})
    event = make_capture_completed(unrecognized={"future": True})
    purchase = make_adapter(monkeypatch, api).normalize(event)
    assert purchase.platform_purchase_id == _ORDER_ID


def test_missing_json_members_are_rejected_without_api_calls(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    event = make_capture_completed(resource={"supplementary_data": {}})
    with pytest.raises(PurchaseRejected, match="no usable related order id"):
        make_adapter(monkeypatch, api).normalize(event)
    assert api.post_calls == []
    assert api.get_calls == []


def test_truncated_body_is_rejected_only_after_postback_success(monkeypatch: MonkeyPatch) -> None:
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)
    body = b'{"id":"evt-1","event_type":'

    with pytest.raises(json.JSONDecodeError):
        adapter.parse_event(body, make_transmission())

    assert body in api.verification_calls()[0][2]


def test_verification_response_with_extra_members_accepts_exact_success(
    monkeypatch: MonkeyPatch,
) -> None:
    api = FakePayPalApi()
    api.verification_responses = [b'{"verification_status":"SUCCESS","future":true}']
    adapter = make_adapter(monkeypatch, api)
    assert adapter.parse_event(_payload(), make_transmission()) == make_capture_completed()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("transmission_id", "i" * 51),
        ("transmission_sig", "s" * 501),
        ("cert_url", "https://api.paypal.com/" + "c" * 500),
        ("auth_algo", "SHA256withRSA" + "x" * 100),
        ("transmission_time", "2026-09-05T10:00:00Z" * 10),
        ("cert_url", "https://api.paypal.com\n"),
        ("transmission_sig", "sig with space"),
    ],
)
def test_oversized_or_whitespace_headers_are_rejected_before_any_call(
    monkeypatch: MonkeyPatch, field: str, value: str
) -> None:
    """Y6 bounds every postback field; a junk header is never relayed to PayPal."""
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(PayPalSignatureError):
        adapter.parse_event(_payload(), make_transmission(**{field: value}))

    assert api.post_calls == []


@pytest.mark.parametrize(
    "body",
    [
        b'{"id":"a","id":"b"}',
        b"[" * 200000,
    ],
)
def test_an_authenticated_body_that_cannot_parse_is_always_a_json_decode_error(
    monkeypatch: MonkeyPatch, body: bytes
) -> None:
    """A duplicate member and a too-deep body must reach the handler as one type.

    Otherwise the bare ``ValueError``/``RecursionError`` answers 500 and PayPal
    redelivers a body that can never parse for three days (Y5).
    """
    api = FakePayPalApi()
    adapter = make_adapter(monkeypatch, api)

    with pytest.raises(json.JSONDecodeError):
        adapter.parse_event(body, make_transmission())


# -- the WSGI route ----------------------------------------------------------


@pytest.fixture
def paypal_api() -> FakePayPalApi:
    """Return the per-test PayPal OAuth, verification, and order API fake."""
    return FakePayPalApi()


@pytest.fixture
def paypal_deps(
    catalog: Any,
    issuer_identity: IssuerIdentity,
    ledger: Ledger,
    tmp_path: Any,
    paypal_api: FakePayPalApi,
) -> BridgeDeps:
    """Build route dependencies with every PayPal network call injected."""
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
        paypal=PayPalConfig(
            client_id=_CLIENT_ID,
            client_secret=_CLIENT_SECRET,
            webhook_id=_WEBHOOK_ID,
        ),
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
        log=logging.getLogger("test-bridge-paypal"),
        paypal=PayPalAdapter(
            client_id=_CLIENT_ID,
            client_secret=_CLIENT_SECRET,
            webhook_id=_WEBHOOK_ID,
            http_get=paypal_api.get,
            http_post=paypal_api.post,
        ),
    )


def _route_capture(
    *,
    event_id: str = "WH-PAYPAL-ROUTE-1",
    order_id: str = _ORDER_ID,
    **resource_overrides: Any,
) -> dict[str, Any]:
    resource: dict[str, Any] = {
        "supplementary_data": {"related_ids": {"order_id": order_id}},
    }
    resource.update(resource_overrides)
    event = make_capture_completed(resource=resource)
    event["id"] = event_id
    return event


def _post_paypal_webhook(
    deps: BridgeDeps,
    event: object,
    *,
    transmission: PayPalTransmission | None = None,
    omit_header: str | None = None,
    body: bytes | None = None,
    app: Any | None = None,
) -> tuple[str, dict[str, str], bytes]:
    payload = json.dumps(event).encode() if body is None else body
    sent = make_transmission() if transmission is None else transmission
    headers = {
        "PayPal-Transmission-Id": sent.transmission_id,
        "PayPal-Transmission-Time": sent.transmission_time,
        "PayPal-Transmission-Sig": sent.transmission_sig,
        "PayPal-Cert-Url": sent.cert_url,
        "PayPal-Auth-Algo": sent.auth_algo,
        "Content-Type": "application/json",
    }
    if omit_header is not None:
        del headers[omit_header]
    return call_app(
        make_app(deps) if app is None else app,
        "POST",
        "/paypal/webhook",
        body=payload,
        headers=headers,
    )


def test_e2e_signed_paypal_webhook_to_offline_verified_receipt(
    paypal_deps: BridgeDeps,
    trust_store: verify_mod.TrustStore,
    catalog: Any,
) -> None:
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    stored = paypal_deps.ledger.get_receipt("paypal", _ORDER_ID)
    assert stored is not None
    assert verify_mod.verify(stored.envelope_json.encode(), trust_store).ok is True
    template = catalog.resolve("paypal_SDC-STD-001")
    assert json.loads(stored.envelope_json)["payload"]["work"]["title"] == template.title


def test_forged_paypal_signature_returns_400_and_ledger_stays_empty(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    paypal_api.verification_responses.append(b'{"verification_status":"FAILURE"}')
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("400")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False
    assert paypal_deps.ledger.unresolved_dead_letters() == []


@pytest.mark.parametrize(
    "missing",
    [
        "PayPal-Transmission-Id",
        "PayPal-Transmission-Time",
        "PayPal-Transmission-Sig",
        "PayPal-Cert-Url",
        "PayPal-Auth-Algo",
    ],
)
def test_missing_paypal_signature_header_returns_400_without_an_api_call(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi, missing: str
) -> None:
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event, omit_header=missing)

    assert status.startswith("400")
    assert paypal_api.post_calls == []
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False


def test_valid_paypal_signature_unparseable_json_returns_400(
    paypal_deps: BridgeDeps,
) -> None:
    body = b"{not json"
    status, _, _ = _post_paypal_webhook(paypal_deps, {}, body=body)

    assert status.startswith("400")
    assert paypal_deps.ledger.unresolved_dead_letters() == []


def test_valid_paypal_signature_non_utf8_body_returns_400(
    paypal_deps: BridgeDeps,
) -> None:
    body = b"\xffnot utf-8"
    status, _, _ = _post_paypal_webhook(paypal_deps, {}, body=body)

    assert status.startswith("400")
    assert paypal_deps.ledger.unresolved_dead_letters() == []


def test_non_ascii_paypal_header_returns_400_with_an_empty_ledger(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    event = _route_capture()
    transmission = make_transmission(auth_algo="SHA256withRSA\xff")

    status, _, _ = _post_paypal_webhook(paypal_deps, event, transmission=transmission)

    assert status.startswith("400")
    assert paypal_api.post_calls == []
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False
    assert paypal_deps.ledger.unresolved_dead_letters() == []


def test_paypal_event_without_an_id_is_dead_lettered_and_acknowledged(
    paypal_deps: BridgeDeps,
) -> None:
    event = _route_capture()
    del event["id"]

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    dead_letters = paypal_deps.ledger.unresolved_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0].platform == "paypal"
    assert paypal_deps.ledger.get_receipt("paypal", _ORDER_ID) is None


@pytest.mark.parametrize("event", [[], 7, "event", None, True])
def test_signed_non_object_paypal_event_is_dead_lettered_and_acknowledged(
    paypal_deps: BridgeDeps, event: object
) -> None:
    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    assert len(paypal_deps.ledger.unresolved_dead_letters()) == 1


def test_unhandled_paypal_event_type_returns_200_and_marks_event(
    paypal_deps: BridgeDeps,
) -> None:
    event = _route_capture()
    event["event_type"] = "CHECKOUT.ORDER.APPROVED"

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is True
    assert paypal_deps.ledger.get_receipt("paypal", _ORDER_ID) is None


@pytest.mark.parametrize(
    "resource_overrides",
    [
        {"status": "PENDING"},
        {"final_capture": False},
    ],
)
def test_not_actionable_paypal_event_returns_200_and_marks_event(
    paypal_deps: BridgeDeps, resource_overrides: dict[str, Any]
) -> None:
    event = _route_capture(**resource_overrides)

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is True
    assert paypal_deps.ledger.get_receipt("paypal", _ORDER_ID) is None


def test_replayed_paypal_event_id_returns_200_without_renormalizing(
    paypal_deps: BridgeDeps,
    paypal_api: FakePayPalApi,
    monkeypatch: MonkeyPatch,
) -> None:
    event = _route_capture()
    outcomes: list[Any] = []
    process = paypal_deps.core.process

    def record_process(purchase: Any) -> Any:
        outcome = process(purchase)
        outcomes.append(outcome)
        return outcome

    monkeypatch.setattr(paypal_deps.core, "process", record_process)

    first = _post_paypal_webhook(paypal_deps, event)
    second = _post_paypal_webhook(paypal_deps, event)

    assert first[0].startswith("200")
    assert second[0].startswith("200")
    assert len(outcomes) == 1
    assert len(paypal_api.verification_calls()) == 2
    assert len(paypal_api.get_calls) == 1


def test_concurrent_identical_paypal_webhooks_issue_exactly_one_receipt(
    paypal_deps: BridgeDeps, monkeypatch: MonkeyPatch
) -> None:
    event = _route_capture()
    app = make_app(paypal_deps)
    barrier = threading.Barrier(2)
    statuses: list[str] = []
    process_calls: list[int] = []
    results_lock = threading.Lock()
    process = paypal_deps.core.process

    def record_process(purchase: Any) -> Any:
        process_calls.append(1)
        return process(purchase)

    def hit() -> None:
        barrier.wait()
        status, _, _ = _post_paypal_webhook(paypal_deps, event, app=app)
        with results_lock:
            statuses.append(status)

    monkeypatch.setattr(paypal_deps.core, "process", record_process)
    threads = [threading.Thread(target=hit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(statuses) == 2
    assert all(status.startswith("200") for status in statuses)
    assert len(process_calls) == 1
    assert paypal_deps.ledger.get_receipt("paypal", _ORDER_ID) is not None


def test_unmapped_paypal_product_dead_letters_and_returns_200(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    paypal_api.order = make_order(
        purchase_units=[{"items": [{"name": "Unknown", "sku": "UNKNOWN-SKU"}]}]
    )
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    assert len(paypal_deps.ledger.unresolved_dead_letters()) == 1
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is True


def test_missing_paypal_buyer_email_dead_letters_and_returns_200(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    paypal_api.order = make_order(payer={})
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    assert len(paypal_deps.ledger.unresolved_dead_letters()) == 1
    assert paypal_deps.ledger.get_receipt("paypal", _ORDER_ID) is None


def test_multiple_paypal_items_dead_letter_without_issuing(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    paypal_api.order = make_order(
        purchase_units=[
            {
                "items": [
                    {"name": "One", "sku": "SDC-STD-001"},
                    {"name": "Two", "sku": "SECOND-SKU"},
                ]
            }
        ]
    )
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    assert paypal_deps.ledger.get_receipt("paypal", _ORDER_ID) is None
    assert "one receipt per purchase" in paypal_deps.ledger.unresolved_dead_letters()[0].reason


def test_duplicate_paypal_purchase_across_two_events_reuses_receipt(
    paypal_deps: BridgeDeps, monkeypatch: MonkeyPatch
) -> None:
    outcomes: list[Any] = []
    process = paypal_deps.core.process

    def record_process(purchase: Any) -> Any:
        outcome = process(purchase)
        outcomes.append(outcome)
        return outcome

    monkeypatch.setattr(paypal_deps.core, "process", record_process)
    first = _route_capture(event_id="WH-PAYPAL-A")
    second = _route_capture(event_id="WH-PAYPAL-B")

    assert _post_paypal_webhook(paypal_deps, first)[0].startswith("200")
    assert _post_paypal_webhook(paypal_deps, second)[0].startswith("200")
    assert [outcome.duplicate for outcome in outcomes] == [False, True]
    assert paypal_deps.ledger.seen_event("paypal", "WH-PAYPAL-A") is True
    assert paypal_deps.ledger.seen_event("paypal", "WH-PAYPAL-B") is True


def test_transient_paypal_verification_failure_returns_500_without_marking(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    paypal_api.verification_responses.append(_http_error(503))
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("500")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False
    assert paypal_deps.ledger.unresolved_dead_letters() == []


def test_transient_paypal_order_failure_returns_500_without_marking(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    paypal_api.order_responses.append(_http_error(503))
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("500")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False
    assert paypal_deps.ledger.unresolved_dead_letters() == []


def test_permanent_paypal_api_failure_dead_letters_and_returns_200(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    paypal_api.order_responses.append(_http_error(404))
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("200")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is True
    assert len(paypal_deps.ledger.unresolved_dead_letters()) == 1


def test_paypal_api_calls_happen_before_the_webhook_lock(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi, monkeypatch: MonkeyPatch
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

    def post(url: str, headers: dict[str, str], body: bytes) -> bytes:
        assert lock.locked is False
        return paypal_api.post(url, headers, body)

    def get(url: str, headers: dict[str, str]) -> bytes:
        assert lock.locked is False
        return paypal_api.get(url, headers)

    adapter = PayPalAdapter(
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
        webhook_id=_WEBHOOK_ID,
        http_get=get,
        http_post=post,
    )
    # Construct the adapter first so its legitimate OAuth token lock remains a
    # real lock; only the app's webhook/rate locks are made inspectable here.
    monkeypatch.setattr(http_module.threading, "Lock", lambda: lock)
    paypal_deps.paypal = adapter

    assert _post_paypal_webhook(paypal_deps, _route_capture())[0].startswith("200")


def test_unexpected_paypal_core_exception_returns_500_and_does_not_mark_event(
    paypal_deps: BridgeDeps, monkeypatch: MonkeyPatch
) -> None:
    def boom(purchase: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(paypal_deps.core, "issue_for", boom)
    event = _route_capture()

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("500")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False
    assert paypal_deps.ledger.unresolved_dead_letters() == []


def test_unexpected_paypal_adapter_exception_returns_500_and_does_not_mark_event(
    paypal_deps: BridgeDeps, monkeypatch: MonkeyPatch
) -> None:
    event = _route_capture()

    def boom(payload: bytes, transmission: PayPalTransmission) -> dict[str, Any]:
        raise RuntimeError("adapter bug")

    assert paypal_deps.paypal is not None
    monkeypatch.setattr(paypal_deps.paypal, "parse_event", boom)

    status, _, _ = _post_paypal_webhook(paypal_deps, event)

    assert status.startswith("500")
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False


def test_paypal_route_is_404_when_paypal_is_not_configured(paypal_deps: BridgeDeps) -> None:
    paypal_deps.paypal = None

    status, _, _ = _post_paypal_webhook(paypal_deps, _route_capture())

    assert status.startswith("404")


def test_oversized_paypal_body_returns_413_without_any_outbound_call(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    app = make_app(paypal_deps, webhook_body_limit_bytes=32)
    event = _route_capture()
    body = json.dumps(event).encode()

    status, _, _ = _post_paypal_webhook(paypal_deps, {}, body=body, app=app)

    assert status.startswith("413")
    assert paypal_api.post_calls == []
    assert paypal_api.get_calls == []
    assert paypal_deps.ledger.seen_event("paypal", event["id"]) is False
    assert paypal_deps.ledger.unresolved_dead_letters() == []


def test_paypal_rate_limit_accepts_up_to_the_configured_bound_then_rejects(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    app = make_app(paypal_deps, paypal_rate_limit=1)
    accepted = _route_capture(event_id="WH-PAYPAL-RATE-ACCEPTED")
    rejected = _route_capture(event_id="WH-PAYPAL-RATE-REJECTED")

    first = _post_paypal_webhook(paypal_deps, accepted, app=app)
    calls_after_first = len(paypal_api.post_calls) + len(paypal_api.get_calls)
    second = _post_paypal_webhook(paypal_deps, rejected, app=app)

    assert first[0].startswith("200")
    assert second[0].startswith("429")
    assert len(paypal_api.post_calls) + len(paypal_api.get_calls) == calls_after_first
    assert paypal_deps.ledger.seen_event("paypal", rejected["id"]) is False


def test_paypal_dedup_key_comes_from_the_verified_body_not_transmission_id(
    paypal_deps: BridgeDeps, paypal_api: FakePayPalApi
) -> None:
    second_order_id = "7A12345678901234B"
    paypal_api.order_responses.extend(
        [
            json.dumps(make_order(id=_ORDER_ID)).encode(),
            json.dumps(make_order(id=second_order_id)).encode(),
        ]
    )
    repeated_transmission = make_transmission(transmission_id="repeated-transmission-id")
    first = _route_capture(event_id="WH-PAYPAL-BODY-A", order_id=_ORDER_ID)
    second = _route_capture(event_id="WH-PAYPAL-BODY-B", order_id=second_order_id)

    assert _post_paypal_webhook(paypal_deps, first, transmission=repeated_transmission)[
        0
    ].startswith("200")
    assert _post_paypal_webhook(paypal_deps, second, transmission=repeated_transmission)[
        0
    ].startswith("200")

    assert paypal_deps.ledger.get_receipt("paypal", second_order_id) is not None
    assert paypal_deps.ledger.seen_event("paypal", "WH-PAYPAL-BODY-B") is True
    assert len(paypal_api.get_calls) == 2


def test_paypal_auth_algorithm_and_signature_failures_have_distinct_log_lines(
    paypal_deps: BridgeDeps,
    paypal_api: FakePayPalApi,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    event = _route_capture()
    unsupported = make_transmission(auth_algo="SHA512withRSA")
    paypal_api.verification_responses.append(b'{"verification_status":"FAILURE"}')

    assert _post_paypal_webhook(paypal_deps, event, transmission=unsupported)[0].startswith("400")
    assert _post_paypal_webhook(paypal_deps, event)[0].startswith("400")

    messages = [record.getMessage() for record in caplog.records]
    assert messages.count("paypal webhook: unsupported auth algorithm") == 1
    assert messages.count("paypal webhook: signature verification failed") == 1
    for message in messages:
        assert _ORDER_ID not in message
        assert _CLIENT_SECRET not in message
        assert _ACCESS_TOKEN not in message


def test_no_paypal_log_line_carries_the_raw_purchase_id_or_a_secret(
    paypal_deps: BridgeDeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)

    assert _post_paypal_webhook(paypal_deps, _route_capture())[0].startswith("200")

    for record in caplog.records:
        message = record.getMessage()
        assert _ORDER_ID not in message
        assert _CLIENT_SECRET not in message
        assert _ACCESS_TOKEN not in message
