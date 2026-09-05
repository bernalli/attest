"""NormalizedPurchase DTO + buyer-pubkey decoding (fail-before-signing gate #1)."""

from __future__ import annotations

import dataclasses

import pytest
from attest_bridge.model import (
    NormalizedPurchase,
    PurchaseRejected,
    decode_buyer_pubkey,
    rfc3339_from_unix,
)

from attest import keys


def _purchase(**overrides: object) -> NormalizedPurchase:
    base: dict[str, object] = dict(
        platform="stripe",
        platform_purchase_id="cs_test_1",
        buyer_identifier="buyer@example.com",
        identifier_type="email",
        buyer_pubkey=None,
        product_key="price_TEST",
        purchased_at="2026-07-24T10:00:00Z",
    )
    base.update(overrides)
    return NormalizedPurchase(**base)  # type: ignore[arg-type]


def test_normalized_purchase_is_frozen() -> None:
    p = _purchase()
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.platform = "itch"  # type: ignore[misc]


def test_decode_buyer_pubkey_none_and_empty_and_whitespace_are_absent() -> None:
    assert decode_buyer_pubkey(None) is None
    assert decode_buyer_pubkey("") is None
    assert decode_buyer_pubkey("   ") is None


def test_decode_buyer_pubkey_valid_roundtrip() -> None:
    raw = bytes(range(32))
    assert decode_buyer_pubkey(keys.b64u(raw)) == raw
    assert decode_buyer_pubkey("  " + keys.b64u(raw) + "\n") == raw  # tolerant of pasted whitespace


@pytest.mark.parametrize("bad", ["not!!b64u", keys.b64u(bytes(31)), keys.b64u(bytes(33)), "AAAA"])
def test_decode_buyer_pubkey_malformed_rejects(bad: str) -> None:
    with pytest.raises(PurchaseRejected):
        decode_buyer_pubkey(bad)


def test_decode_buyer_pubkey_rejects_non_canonical_alphabet_decoding_to_32_bytes() -> None:
    # `keys.b64u_decode` silently drops out-of-alphabet chars, so a valid 32-byte
    # key with injected "!" still decodes to 32 bytes and would pass a length-only
    # gate. gate #1 must reject it via the canonical round-trip check (security review).
    valid = keys.b64u(bytes(range(32)))
    injected = valid[:4] + "!!!!" + valid[4:]
    assert (
        len(keys.b64u_decode(injected)) == 32
    )  # sanity: permissive decoder accepts it back to 32B
    with pytest.raises(PurchaseRejected):
        decode_buyer_pubkey(injected)


def test_rfc3339_from_unix_matches_attest_format() -> None:
    # Epoch literal independently recomputed (the design doc's literal
    # "2026-07-13T16:53:20Z" did not match `datetime.fromtimestamp(1_784_000_000,
    # UTC)`; the literal is fixed here, not the function under test).
    assert rfc3339_from_unix(1_784_000_000) == "2026-07-14T03:33:20Z"


def test_rfc3339_from_unix_zero_pads_years_below_1000() -> None:
    """`strftime("%Y")` does not zero-pad on glibc, and `1-01-01T...` is not RFC 3339."""
    assert rfc3339_from_unix(-62_135_596_800) == "0001-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "ts",
    [
        10**18,
        -(10**18),
        253_402_300_800 * 1000,
        10**100,
        -(10**100),
        -62_135_596_801,
        253_402_300_800,
    ],
)
def test_rfc3339_from_unix_rejects_a_timestamp_outside_the_representable_range(
    ts: int,
) -> None:
    """An out-of-range integer is malformed purchase input, not a crash.

    `datetime.fromtimestamp` raises `OSError` (or `OverflowError`, or
    `ValueError`) for these, none of which any caller's contract names: the
    Stripe adapter only checks that `event["created"]` is an `int`, so a signed
    body carrying an absurd value would escape `normalize` as an unhandled
    error instead of the pinned rejection.
    """
    with pytest.raises(PurchaseRejected):
        rfc3339_from_unix(ts)
