"""Shopify adapter + webhook route tests.

The adversarial cases are the point of this file: the HMAC covers the body and
nothing else, so every header this bridge reads has to be treated as untrusted,
and the tests below say what happens when each one lies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any

import pytest
from attest_bridge import shopify_adapter as shopify_module
from attest_bridge.config import BridgeConfig, IssuerConfig, ShopifyConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.ledger import Ledger
from attest_bridge.model import ConfigError, PurchaseRejected
from attest_bridge.shopify_adapter import (
    ShopifyAdapter,
    ShopifySignatureError,
    verify_shopify_signature,
)
from attest_bridge.signing import IssuerIdentity
from conftest import DISPLAY_NAME, ISSUER, KID
from test_bridge_http import call_app

from attest import verify as verify_mod

_WEBHOOK_SECRET = "shpss_test_secret"  # noqa: S105 - test fixture, not a real secret
_VARIANT_ID = 49148385
_ORDER_ID = 820982911946154508


def sign_shopify(body: bytes, secret: str = _WEBHOOK_SECRET) -> str:
    return base64.b64encode(hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()).decode(
        "ascii"
    )


def make_order(
    *,
    order_id: int | str = _ORDER_ID,
    email: str | None = "buyer@example.com",
    financial_status: str = "paid",
    line_items: list[dict[str, Any]] | None = None,
    created_at: str = "2026-08-24T11:15:00-05:00",
    note_attributes: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    order: dict[str, Any] = {
        "id": order_id,
        "financial_status": financial_status,
        "created_at": created_at,
        "currency": "EUR",
        "total_price": "12.00",
        "line_items": (
            line_items
            if line_items is not None
            else [{"variant_id": _VARIANT_ID, "title": "The Long Dusk", "quantity": 1}]
        ),
    }
    if email is not None:
        order["email"] = email
    if note_attributes is not None:
        order["note_attributes"] = note_attributes
    order.update(extra)
    return order


# -- signature ---------------------------------------------------------------


def test_valid_signature_verifies() -> None:
    body = b'{"id":1}'
    verify_shopify_signature(body, sign_shopify(body), _WEBHOOK_SECRET)


def test_signature_from_the_wrong_secret_is_rejected() -> None:
    body = b'{"id":1}'
    with pytest.raises(ShopifySignatureError):
        verify_shopify_signature(body, sign_shopify(body, "attacker_secret"), _WEBHOOK_SECRET)


def test_signature_over_a_different_body_is_rejected() -> None:
    """The tampered-body case: a signature harvested from one delivery must not
    validate another."""
    with pytest.raises(ShopifySignatureError):
        verify_shopify_signature(b'{"id":2}', sign_shopify(b'{"id":1}'), _WEBHOOK_SECRET)


@pytest.mark.parametrize("header", ["", "   ", "not-base64", "AAAA"])
def test_missing_or_malformed_signature_header_is_rejected(header: str) -> None:
    with pytest.raises(ShopifySignatureError):
        verify_shopify_signature(b'{"id":1}', header, _WEBHOOK_SECRET)


def test_empty_webhook_secret_is_a_config_error_not_a_forgeable_adapter() -> None:
    """An empty secret makes every inbound signature forgeable, and the config
    layer permits an empty env-var value — so the trust boundary refuses here."""
    with pytest.raises(ConfigError):
        ShopifyAdapter(webhook_secret="   ")  # noqa: S106 - the point of the test


def test_parse_event_verifies_before_parsing() -> None:
    """A body that is not even JSON must fail on the signature, not on the
    parser: there is no path that reaches `json.loads` unverified."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    with pytest.raises(ShopifySignatureError):
        adapter.parse_event(b"not json at all", "AAAA")


# -- wants: the topic header is a filter, the body is the authority ----------


def test_wants_true_for_orders_paid_and_paid_status() -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    assert adapter.wants(make_order()) is True


@pytest.mark.parametrize(
    "status",
    ["pending", "authorized", "refunded", "partially_refunded", "voided", "partially_paid"],
)
def test_wants_false_for_any_status_that_is_not_paid(status: str) -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    assert adapter.wants(make_order(financial_status=status)) is False


def test_wants_false_for_a_cancelled_order_that_is_still_marked_paid() -> None:
    """An order cancelled after payment keeps `financial_status: "paid"` until
    it is refunded. It is not a purchase to attest to."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    order = make_order(cancelled_at="2026-08-24T12:00:00-05:00", cancel_reason="customer")

    assert adapter.wants(order) is False


# -- normalize ---------------------------------------------------------------


def test_normalize_maps_the_variant_id_to_the_product_key() -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    purchase = adapter.normalize(make_order())

    assert purchase.platform == "shopify"
    assert purchase.platform_purchase_id == str(_ORDER_ID)
    assert purchase.product_key == f"shopify_{_VARIANT_ID}"
    assert purchase.buyer_identifier == "buyer@example.com"
    assert purchase.identifier_type == "email"
    assert purchase.amount == "12.00"
    assert purchase.currency == "EUR"


def test_normalize_converts_created_at_offset_to_utc() -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    purchase = adapter.normalize(make_order(created_at="2026-08-24T11:15:00-05:00"))

    assert purchase.purchased_at == "2026-08-24T16:15:00Z"


@pytest.mark.parametrize("bad", ["", "   ", "yesterday", "2026-13-45T99:99:99Z", 17])
def test_normalize_rejects_an_unparseable_created_at(bad: Any) -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    with pytest.raises(PurchaseRejected):
        adapter.normalize(make_order(created_at=bad))


def test_normalize_rejects_an_order_with_more_than_one_line_item() -> None:
    """Same invariant the Stripe adapter enforces — one receipt per purchase —
    and here it is a length check on the signed payload rather than an API
    call."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    order = make_order(
        line_items=[{"variant_id": _VARIANT_ID}, {"variant_id": 99}],
    )

    with pytest.raises(PurchaseRejected) as exc_info:
        adapter.normalize(order)

    assert "one receipt per purchase" in str(exc_info.value)


def test_normalize_rejects_a_line_item_without_a_variant_id() -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    with pytest.raises(PurchaseRejected) as exc_info:
        adapter.normalize(make_order(line_items=[{"title": "no variant"}]))

    assert "variant_id" in str(exc_info.value)


def test_note_attributes_cannot_name_the_product() -> None:
    """The security difference from Stripe, asserted rather than assumed.
    Stripe's `metadata` is written by the merchant's own server when it creates
    the Checkout Session; Shopify's `note_attributes` comes from cart
    attributes a theme, an app, or the buyer's browser can set. Honouring an
    `attest_product_key` there would let whoever controls the cart pick which
    catalog entry gets attested — and, worse, skip the single-line-item check.
    The variant that was actually sold decides, always."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    order = make_order(
        line_items=[{"variant_id": _VARIANT_ID}],
        note_attributes=[{"name": "attest_product_key", "value": "shopify_someone_elses_product"}],
    )

    assert adapter.normalize(order).product_key == f"shopify_{_VARIANT_ID}"


def test_note_attributes_cannot_smuggle_a_multi_item_cart_past_the_invariant() -> None:
    """The same override used to be read before the line items were counted, so
    a five-item cart could issue a single receipt for whatever it named."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    order = make_order(
        line_items=[{"variant_id": _VARIANT_ID}, {"variant_id": 2}, {"variant_id": 3}],
        note_attributes=[{"name": "attest_product_key", "value": f"shopify_{_VARIANT_ID}"}],
    )

    with pytest.raises(PurchaseRejected) as exc_info:
        adapter.normalize(order)

    assert "one receipt per purchase" in str(exc_info.value)


def test_a_neighbours_malformed_note_attribute_does_not_block_issuance() -> None:
    """`note_attributes` is shared with every other app the merchant installed,
    so a non-string entry from one of them must not cost the buyer a receipt —
    the buyer pubkey carrier still has to be readable past it."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    order = make_order(
        note_attributes=[
            {"name": "other_app_field", "value": {"nested": "object"}},
            "not even a dict",
        ]
    )

    assert adapter.normalize(order).product_key == f"shopify_{_VARIANT_ID}"


@pytest.mark.parametrize(
    "order_kwargs",
    [
        {"email": None, "contact_email": "contact@example.com"},
        {"email": None, "customer": {"email": "customer@example.com"}},
        {"email": "  ", "contact_email": "contact@example.com"},
    ],
)
def test_normalize_falls_back_through_the_documented_email_fields(
    order_kwargs: dict[str, Any],
) -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    purchase = adapter.normalize(make_order(**order_kwargs))

    assert purchase.buyer_identifier in {"contact@example.com", "customer@example.com"}


def test_normalize_rejects_an_order_with_no_buyer_email_anywhere() -> None:
    """A receipt with no holder is not issuable — dead-letter, never a guess."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    with pytest.raises(PurchaseRejected) as exc_info:
        adapter.normalize(make_order(email=None))

    assert "buyer email" in str(exc_info.value)


@pytest.mark.parametrize("bad_id", [None, "", True])
def test_normalize_rejects_a_missing_or_boolean_order_id(bad_id: Any) -> None:
    """`bool` is an `int` subclass; without the explicit guard `True` would
    become an order id of "True"."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    with pytest.raises(PurchaseRejected):
        adapter.normalize(make_order(order_id=bad_id))


def test_normalize_rejects_a_malformed_buyer_pubkey_before_signing() -> None:
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    order = make_order(
        note_attributes=[{"name": "attest_buyer_pubkey", "value": "!!! not base64url !!!"}]
    )

    with pytest.raises(PurchaseRejected):
        adapter.normalize(order)


# -- the WSGI route ----------------------------------------------------------


@pytest.fixture
def shopify_deps(
    catalog: Any,
    issuer_identity: IssuerIdentity,
    ledger: Ledger,
    tmp_path: Any,
) -> BridgeDeps:
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
        shopify=ShopifyConfig(webhook_secret=_WEBHOOK_SECRET),
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
        log=logging.getLogger("test-bridge-shopify"),
        shopify=ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET),
    )


def _post_webhook(
    deps: BridgeDeps,
    order: dict[str, Any],
    *,
    topic: str = "orders/paid",
    delivery_id: str = "delivery-1",
    signature: str | None = None,
) -> tuple[str, dict[str, str], bytes]:
    body = json.dumps(order).encode()
    headers = {
        "X-Shopify-Hmac-Sha256": signature if signature is not None else sign_shopify(body),
        "Content-Type": "application/json",
    }
    if topic:
        headers["X-Shopify-Topic"] = topic
    if delivery_id:
        headers["X-Shopify-Webhook-Id"] = delivery_id
    return call_app(make_app(deps), "POST", "/shopify/webhook", body=body, headers=headers)


def test_e2e_signed_shopify_webhook_to_offline_verified_receipt(
    shopify_deps: BridgeDeps, trust_store: verify_mod.TrustStore
) -> None:
    """The phase-defining oracle for this rail: signed webhook in, envelope out,
    verified offline with nothing but the published key."""
    status, _, _ = _post_webhook(shopify_deps, make_order())

    assert status.startswith("200")
    stored = shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID))
    assert stored is not None
    assert verify_mod.verify(stored.envelope_json.encode(), trust_store).ok is True


def test_forged_signature_returns_400_and_ledger_stays_empty(shopify_deps: BridgeDeps) -> None:
    body = json.dumps(make_order()).encode()
    status, _, _ = _post_webhook(
        shopify_deps, make_order(), signature=sign_shopify(body, "attacker_secret")
    )

    assert status.startswith("400")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is None
    assert shopify_deps.ledger.unresolved_dead_letters() == []


def test_missing_signature_header_returns_400(shopify_deps: BridgeDeps) -> None:
    status, _, _ = _post_webhook(shopify_deps, make_order(), signature="")

    assert status.startswith("400")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is None


def test_missing_order_id_in_the_signed_body_returns_400_without_issuing(
    shopify_deps: BridgeDeps,
) -> None:
    """The dedup key comes from the signed body. An order with no usable id
    could not be recognised on redelivery, so it is refused before the Ledger
    is touched rather than issued once and then again."""
    body = json.dumps({k: v for k, v in make_order().items() if k != "id"}).encode()
    status, _, _ = call_app(
        make_app(shopify_deps),
        "POST",
        "/shopify/webhook",
        body=body,
        headers={
            "X-Shopify-Hmac-Sha256": sign_shopify(body),
            "X-Shopify-Topic": "orders/paid",
            "X-Shopify-Webhook-Id": "delivery-1",
            "Content-Type": "application/json",
        },
    )

    assert status.startswith("400")
    assert shopify_deps.ledger.unresolved_dead_letters() == []


def test_redelivery_issues_exactly_one_receipt(shopify_deps: BridgeDeps) -> None:
    first = _post_webhook(shopify_deps, make_order())
    second = _post_webhook(shopify_deps, make_order())

    assert first[0].startswith("200")
    assert second[0].startswith("200")
    stored = shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID))
    assert stored is not None
    assert shopify_deps.ledger.seen_event("shopify", str(_ORDER_ID)) is True


def test_a_tampered_delivery_id_cannot_get_a_genuine_order_discarded(
    shopify_deps: BridgeDeps,
) -> None:
    """The delivery id header is unsigned. If it were the dedup key, replaying
    a genuine delivery with an already-seen id would have it acknowledged and
    dropped — a lost receipt. The key is the order id inside the signed body,
    so the header can say anything and the receipt is still issued."""
    seeded = make_order(order_id=111111)
    assert _post_webhook(shopify_deps, seeded, delivery_id="delivery-seen")[0].startswith("200")

    status, _, _ = _post_webhook(shopify_deps, make_order(), delivery_id="delivery-seen")

    assert status.startswith("200")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is not None


@pytest.mark.parametrize("topic", ["orders/updated", "orders/cancelled", "", "anything"])
def test_a_relabelled_topic_cannot_get_a_paid_order_discarded(
    shopify_deps: BridgeDeps, topic: str
) -> None:
    """Same class of attack through the other unsigned header: if the topic
    gated issuance, relabelling a genuine paid delivery would lose its receipt.
    Nothing in the decision path reads it."""
    status, _, _ = _post_webhook(shopify_deps, make_order(), topic=topic)

    assert status.startswith("200")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is not None


def test_a_cancelled_paid_order_is_acknowledged_without_issuing(
    shopify_deps: BridgeDeps,
) -> None:
    status, _, _ = _post_webhook(shopify_deps, make_order(cancelled_at="2026-08-24T12:00:00-05:00"))

    assert status.startswith("200")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is None
    assert shopify_deps.ledger.unresolved_dead_letters() == []


def test_unmapped_product_dead_letters_and_returns_200(shopify_deps: BridgeDeps) -> None:
    """A variant with no catalog entry is permanently bad input: acknowledged
    once with a readable reason, never issued with guessed terms."""
    status, _, _ = _post_webhook(shopify_deps, make_order(line_items=[{"variant_id": 404404}]))

    assert status.startswith("200")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is None
    assert len(shopify_deps.ledger.unresolved_dead_letters()) == 1
    assert shopify_deps.ledger.seen_event("shopify", str(_ORDER_ID)) is True


def test_unpaid_order_is_acknowledged_without_issuing(shopify_deps: BridgeDeps) -> None:
    status, _, _ = _post_webhook(shopify_deps, make_order(financial_status="pending"))

    assert status.startswith("200")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is None
    assert shopify_deps.ledger.unresolved_dead_letters() == []
    # NOT marked seen: the event key is the order id, and "not paid yet" is not
    # a terminal state for an order — see the lifecycle test below.
    assert shopify_deps.ledger.seen_event("shopify", str(_ORDER_ID)) is False


def test_an_unpaid_delivery_does_not_suppress_the_paid_one_that_follows(
    shopify_deps: BridgeDeps,
) -> None:
    """The ordinary Shopify lifecycle, not an attack: the same order id arrives
    first unpaid and then paid. Marking the unpaid one terminal would close the
    door on the receipt."""
    first = _post_webhook(shopify_deps, make_order(financial_status="pending"))
    second = _post_webhook(shopify_deps, make_order(financial_status="paid"))

    assert first[0].startswith("200")
    assert second[0].startswith("200")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is not None


def test_a_cancelled_delivery_does_not_suppress_a_later_paid_one(
    shopify_deps: BridgeDeps,
) -> None:
    """Same shape through the cancellation guard."""
    _post_webhook(shopify_deps, make_order(cancelled_at="2026-08-24T12:00:00-05:00"))
    status, _, _ = _post_webhook(shopify_deps, make_order())

    assert status.startswith("200")
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is not None


def test_unexpected_core_failure_returns_500_and_does_not_acknowledge(
    shopify_deps: BridgeDeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: Shopify must redeliver, or a transient failure would drop a
    purchase forever."""

    def boom(purchase: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(shopify_deps.core, "issue_for", boom)

    status, _, _ = _post_webhook(shopify_deps, make_order())

    assert status.startswith("500")
    assert shopify_deps.ledger.seen_event("shopify", str(_ORDER_ID)) is False
    assert shopify_deps.ledger.get_receipt("shopify", str(_ORDER_ID)) is None
    assert shopify_deps.ledger.unresolved_dead_letters() == []


def test_route_is_404_when_shopify_is_not_configured(shopify_deps: BridgeDeps) -> None:
    shopify_deps.shopify = None

    status, _, _ = _post_webhook(shopify_deps, make_order())

    assert status.startswith("404")


def test_a_non_ascii_hmac_header_is_rejected_and_never_escapes_as_a_typeerror() -> None:
    """`hmac.compare_digest` raises TypeError on a non-ASCII str.

    The header is latin-1-decoded remote input (PEP 3333), so one byte >= 0x80
    would escape this function's "only ShopifySignatureError" contract and
    reach the route layer as an unhandled 500 instead of the pinned 400.
    """
    with pytest.raises(ShopifySignatureError):
        verify_shopify_signature(b"{}", "\u00ff" * 44, _WEBHOOK_SECRET)


def test_the_header_is_compared_with_compare_digest_not_equality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing else in this file distinguishes `compare_digest` from `==`."""
    calls: list[tuple[Any, Any]] = []
    real = hmac.compare_digest

    def recording(left: Any, right: Any) -> bool:
        calls.append((left, right))
        return bool(real(left, right))

    monkeypatch.setattr(shopify_module.hmac, "compare_digest", recording)
    body = b"{}"
    verify_shopify_signature(body, sign_shopify(body), _WEBHOOK_SECRET)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "created_at",
    ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"],
)
def test_an_extreme_created_at_is_a_purchase_rejection_not_an_overflowerror(
    created_at: str,
) -> None:
    """`astimezone(UTC)` walks off the end of the representable range.

    `OverflowError` is not named by this adapter's contract, and the body that
    carries the value is signed, so the route would answer 500 instead of
    dead-lettering a malformed purchase.
    """
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    with pytest.raises(PurchaseRejected):
        adapter.normalize(make_order(created_at=created_at))


def test_a_year_below_1000_created_at_is_zero_padded_to_rfc_3339() -> None:
    """`strftime("%Y")` does not zero-pad on glibc; `1-01-01T...` is not RFC 3339."""
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    purchase = adapter.normalize(make_order(created_at="0001-01-01T00:00:00Z"))
    assert purchase.purchased_at == "0001-01-01T00:00:00Z"


@pytest.mark.parametrize("verdict", [False, True])
def test_digest_result_controls_verification(
    verdict: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counting the calls is not enough: a spy that always agrees also counts."""
    body = b"{}"
    expected = sign_shopify(body)
    candidate = "A" * 44 if verdict else expected

    def comparison(left: str, right: str) -> bool:
        assert (left, right) == (candidate, expected)
        return verdict

    monkeypatch.setattr(shopify_module.hmac, "compare_digest", comparison)
    if verdict:
        verify_shopify_signature(body, candidate, _WEBHOOK_SECRET)
    else:
        with pytest.raises(ShopifySignatureError):
            verify_shopify_signature(body, candidate, _WEBHOOK_SECRET)


@pytest.mark.parametrize(
    "bad",
    [
        None,
        True,
        17,
        [],
        {},
        "",
        " ",
        "2026-02-30T12:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01T",
        "2026-01-01T00:00:00+",
        "2026-01-01T00:00:00Zjunk",
    ],
)
def test_created_at_negative_family(bad: Any) -> None:
    """Coverage by property, not by the handful of examples the author imagined."""
    raw = make_order()
    raw["created_at"] = bad
    with pytest.raises(PurchaseRejected):
        ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET).normalize(raw)


@pytest.mark.parametrize(
    "body",
    [
        b'{"created":' + b"1" * 4301 + b"}",
        b"[" * 20000 + b"0" + b"]" * 20000,
    ],
)
def test_json_limits_return_400(shopify_deps: BridgeDeps, body: bytes) -> None:
    """Same family as the Stripe rail: a bare ValueError and a RecursionError."""
    status, _, reply = call_app(
        make_app(shopify_deps),
        "POST",
        "/shopify/webhook",
        body=body,
        headers={"X-Shopify-Hmac-Sha256": sign_shopify(body)},
    )
    assert status == "400 Bad Request"
    assert reply == b"malformed body"
    assert shopify_deps.ledger.unresolved_dead_letters() == []


def test_a_lone_surrogate_order_id_is_a_400_not_a_500(shopify_deps: BridgeDeps) -> None:
    """Same family on the signed rail: the parse succeeds and the encode fails
    later, in `Ledger.seen_event`, outside every `except` this handler names."""
    body = b'{"id": "\\ud800", "created_at": "2026-07-14T03:33:20Z"}'
    status, _, reply = call_app(
        make_app(shopify_deps),
        "POST",
        "/shopify/webhook",
        body=body,
        headers={"X-Shopify-Hmac-Sha256": sign_shopify(body)},
    )
    assert status == "400 Bad Request"
    assert reply == b"malformed body"


@pytest.mark.parametrize(
    "created_at",
    [
        "2026-07-14T03:33:20.123456Z",
        "2026-07-14T03:33:20.5+02:00",
        "2026-07-14T03:33:20.999999-05:00",
    ],
)
def test_a_fractional_second_created_at_is_truncated_not_carried_through(created_at: str) -> None:
    """Same property as the itch rail: `microsecond=0` is load-bearing.

    The schema pins `^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$`, and
    `isoformat()` — unlike the `strftime` it replaced — carries sub-second
    precision through unless it is zeroed first.
    """
    adapter = ShopifyAdapter(webhook_secret=_WEBHOOK_SECRET)
    purchase = adapter.normalize(make_order(created_at=created_at))
    assert purchase.purchased_at.endswith(":20Z")
    assert "." not in purchase.purchased_at
