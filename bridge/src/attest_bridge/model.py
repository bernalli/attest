"""Platform-agnostic purchase model — the single boundary between adapters and issuance."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from attest import keys

_ED25519_PUBKEY_LEN = 32


class BridgeError(Exception):
    """Base class for every bridge-originated failure."""


class PurchaseRejected(BridgeError):
    """The purchase input is malformed — nothing may be signed for it."""


class UnmappedProduct(BridgeError):
    """No catalog entry for this product_key — never issue with guessed terms."""


class ConfigError(BridgeError):
    """Bad or missing configuration/secret — fail at startup, before serving."""


class ClaimQueueFull(BridgeError):
    """The bounded itch claim queue cannot accept another pending claim."""


def purchase_id_for_log(purchase_id: str) -> str:
    """Return a stable, non-reversible representation safe for application logs."""
    digest = hashlib.sha256(purchase_id.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"


@dataclass(frozen=True, slots=True)
class NormalizedPurchase:
    platform: str
    platform_purchase_id: str
    buyer_identifier: str
    identifier_type: str
    buyer_pubkey: bytes | None
    product_key: str
    purchased_at: str
    amount: str | None = None
    currency: str | None = None


class PurchaseSource(Protocol):
    platform: str

    def normalize(self, raw: dict[str, Any]) -> NormalizedPurchase: ...


def decode_buyer_pubkey(value: str | None) -> bytes | None:
    """Absent/empty -> None (email-bound receipt). Malformed -> PurchaseRejected.

    Fail-before-signing gate: a bad pubkey must never survive to build_payload,
    where transferable=(pubkey is not None) would otherwise turn a buyer typo
    into a schema error or a mis-bound receipt (§17.8/D1).
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        raw = keys.b64u_decode(text)
    except ValueError as exc:
        raise PurchaseRejected(f"buyer pubkey is not valid base64url: {exc}") from exc
    if len(raw) != _ED25519_PUBKEY_LEN:
        raise PurchaseRejected(f"buyer pubkey must be {_ED25519_PUBKEY_LEN} bytes, got {len(raw)}")
    # `keys.b64u_decode` (base64.urlsafe_b64decode, validate=False) silently drops
    # out-of-alphabet characters, so a canonical 32-byte key with injected junk
    # (e.g. "!") decodes back to 32 bytes and would pass the length gate. Require a
    # strict canonical round-trip so gate #1 fails closed on any non-canonical input.
    if keys.b64u(raw) != text:
        raise PurchaseRejected("buyer pubkey is not canonical base64url")
    return raw


def rfc3339_from_unix(ts: int) -> str:
    """Render a unix timestamp as RFC 3339 `...Z`, or reject it.

    Two things this cannot do naively. `datetime.fromtimestamp` answers an
    out-of-range integer with `OSError`, `OverflowError` or `ValueError`,
    none of which any caller's contract names — and callers only check that
    the value is an `int` before passing it here, so a signed body carrying an
    absurd number would escape `normalize` as an unhandled error instead of
    the pinned rejection. And `strftime("%Y")` does not zero-pad below year
    1000 on glibc, which would emit `1-01-01T00:00:00Z`: not RFC 3339.
    `isoformat` always pads to four digits.
    """
    try:
        moment = datetime.fromtimestamp(ts, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise PurchaseRejected("purchase timestamp is outside the representable range") from exc
    return moment.replace(microsecond=0, tzinfo=None).isoformat() + "Z"
