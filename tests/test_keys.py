from typing import Any

import pytest

from attest import keys

SEED = bytes([1]) * 32  # TEST ONLY — NEVER USE IN PRODUCTION
MSG = b"attest test message"


def test_sign_verify_roundtrip() -> None:
    kp = keys.from_seed(SEED)
    sig = keys.sign(MSG, kp)
    assert len(sig) == 64
    assert keys.verify_strict(MSG, sig, kp.pub)


def test_tampered_message_fails() -> None:
    kp = keys.from_seed(SEED)
    sig = keys.sign(MSG, kp)
    assert not keys.verify_strict(MSG + b"x", sig, kp.pub)


def test_wrong_key_fails() -> None:
    kp = keys.from_seed(SEED)
    other = keys.from_seed(bytes([2]) * 32)
    sig = keys.sign(MSG, kp)
    assert not keys.verify_strict(MSG, sig, other.pub)


def test_noncanonical_s_rejected() -> None:
    kp = keys.from_seed(SEED)
    sig = keys.sign(MSG, kp)
    s_int = int.from_bytes(sig[32:], "little")
    malleated = sig[:32] + (s_int + keys.L).to_bytes(32, "little")
    assert not keys.verify_strict(MSG, malleated, kp.pub)


def test_small_order_pubkey_rejected() -> None:
    identity = bytes([1]) + bytes(31)  # small-order point encoding
    sig = bytes(64)
    assert not keys.verify_strict(MSG, sig, identity)


def test_wrong_lengths_raise() -> None:
    with pytest.raises(ValueError):
        keys.verify_strict(MSG, bytes(63), bytes(32))
    with pytest.raises(ValueError):
        keys.verify_strict(MSG, bytes(64), bytes(31))


def test_b64u_roundtrip_no_padding() -> None:
    data = bytes(range(16))
    s = keys.b64u(data)
    assert "=" not in s
    assert keys.b64u_decode(s) == data


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s[:10] + "!!!!" + s[10:],  # used to be DROPPED by urlsafe_b64decode
        lambda s: s[:10] + "    " + s[10:],
        lambda s: s[:10] + "\n\n" + s[10:],
        lambda s: s + "====",
        lambda s: s[:8] + "==" + s[8:],
        lambda s: s[:10] + "é" + s[10:],
    ],
)
def test_b64u_decode_rejects_outside_shared_grammar(mutate: Any) -> None:
    s = keys.b64u(bytes(range(64)))
    with pytest.raises(ValueError):
        keys.b64u_decode(mutate(s))


def test_b64u_decode_keeps_vector_22_leniency() -> None:
    raw = bytes(range(64))
    s = keys.b64u(raw)
    assert keys.b64u_decode(s + "==") == raw
    assert keys.b64u_decode(s.replace("-", "+").replace("_", "/")) == raw
    assert keys.b64u_decode(s[:-1] + chr(ord(s[-1]) + 1)) == raw
    with pytest.raises(TypeError):
        keys.b64u_decode(b"AAAA")  # type: ignore[arg-type]
