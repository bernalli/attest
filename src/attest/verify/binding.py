"""Step 7, buyer binding (section 6 / section 3.2): the salt path and the
challenge-response path."""

from __future__ import annotations

from typing import Any

from attest import commitment, keys
from attest.verify.constants import _BINDING_NOT_PROVEN, _BINDING_PROVEN
from attest.verify.results import Disclosure


def _check_binding_salt(
    buyer: dict[str, Any], identifier: str, identifier_type: str, salt: bytes
) -> str:
    expected = buyer.get("commitment")
    if not isinstance(expected, str):
        return _BINDING_NOT_PROVEN
    try:
        computed = commitment.compute(identifier, identifier_type, salt)
    except ValueError:
        return _BINDING_NOT_PROVEN
    return _BINDING_PROVEN if keys.b64u(computed) == expected else _BINDING_NOT_PROVEN


def _check_binding_challenge(
    payload: dict[str, Any], buyer: dict[str, Any], nonce: bytes, sig: bytes
) -> str:
    pubkey_b64 = buyer.get("pubkey")
    receipt_id = payload.get("receipt_id")
    if not isinstance(pubkey_b64, str) or not isinstance(receipt_id, str):
        return _BINDING_NOT_PROVEN
    try:
        pub = keys.b64u_decode(pubkey_b64)
        proven = commitment.verify_challenge(receipt_id, nonce, sig, pub)
    except (ValueError, TypeError):
        return _BINDING_NOT_PROVEN
    return _BINDING_PROVEN if proven else _BINDING_NOT_PROVEN


def _classify_binding(payload: dict[str, Any], disclosure: Disclosure) -> str:
    """§6 step 7 / §3.2: recompute the commitment (salt path) or verify a
    challenge-response transcript (pubkey path). A malformed/partial
    disclosure (neither path fully populated) fails closed to "not_proven"."""
    buyer = payload.get("buyer")
    if not isinstance(buyer, dict):
        return _BINDING_NOT_PROVEN

    if (
        disclosure.salt is not None
        and disclosure.identifier is not None
        and disclosure.identifier_type is not None
    ):
        return _check_binding_salt(
            buyer, disclosure.identifier, disclosure.identifier_type, disclosure.salt
        )
    if disclosure.challenge is not None:
        nonce, sig = disclosure.challenge
        return _check_binding_challenge(payload, buyer, nonce, sig)
    return _BINDING_NOT_PROVEN
