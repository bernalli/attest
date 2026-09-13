"""The three derivations of a raw Bitcoin block header, with the byte order named.

`merkle_root_internal` returns bytes 36-68 of the raw header as they are — the header's own
byte order, which is what an OpenTimestamps op-chain replays onto; `bitcoin-cli getblockheader`
and block explorers print that field byte-reversed, and copying it from there is the mistake
this module exists to make visible. The two orders are the same 32 bytes read in opposite
directions, so a root supplied in the wrong one looks exactly as plausible as the right one and
nothing short of a comparison against a real header can tell them apart.

`header_hash_display` goes the other way on purpose, and that asymmetry is not a slip: a block
hash is quoted in reversed order everywhere it is quoted at all, so that is the form this
function returns and the form the rest of the toolchain stores and pins.

Pure standard library, and nothing from `attest`, so the tools that build an anchoring policy
and the tests that pin its byte order derive these values from the same code instead of from two
copies that can drift apart.
"""

from __future__ import annotations

import hashlib
import re

RAW_HEADER_BYTES = 80
"""A Bitcoin block header is a fixed 80-byte structure."""

RAW_HEADER_HEX_CHARS = RAW_HEADER_BYTES * 2
"""The header as hex: two characters per byte."""

_RAW_HEADER_HEX_RE = re.compile(rf"[0-9a-f]{{{RAW_HEADER_HEX_CHARS}}}")


def require_raw_header(raw_hex: str) -> bytes:
    """Decode the hex of a raw 80-byte block header into bytes.

    Accepts exactly 160 lowercase hex characters and nothing else: truncation, uppercase and
    stray whitespace are all mistakes worth refusing before they reach a derivation, where they
    would turn into a wrong root rather than an error. A value of the right length in the wrong
    alphabet is called out separately, because the count an operator would recheck first is the
    one thing that is not wrong.
    """

    if not isinstance(raw_hex, str):
        raise ValueError(
            f"raw header must be 160 lowercase hex chars (80 bytes), got {type(raw_hex).__name__}"
        )
    if _RAW_HEADER_HEX_RE.fullmatch(raw_hex) is None:
        if len(raw_hex) != RAW_HEADER_HEX_CHARS:
            raise ValueError(
                f"raw header must be 160 lowercase hex chars (80 bytes), got {len(raw_hex)}"
            )
        raise ValueError(
            "raw header must be 160 lowercase hex chars (80 bytes): the length is right, "
            "but it is not all lowercase hex - uppercase digits, an 0x prefix or stray "
            "whitespace land here"
        )
    return bytes.fromhex(raw_hex)


def _require_header_bytes(raw: bytes) -> None:
    if len(raw) != RAW_HEADER_BYTES:
        raise ValueError("raw header must be 80 bytes")


def header_hash_display(raw: bytes) -> str:
    """Return the block hash in display order: the double SHA-256 of the header, reversed.

    This is the form `getblockheader` prints and the form used as a key everywhere a block is
    named, so reversing here is correct and deliberate.
    """

    _require_header_bytes(raw)
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def merkle_root_internal(raw: bytes) -> str:
    """Return bytes 36-68 of the header unchanged — the header's own byte order.

    No reversal: this is the order an OpenTimestamps replay ends on, so it is the order an
    anchoring policy must carry. The value a block explorer shows for `merkleroot` is this one
    reversed, and supplying that instead is the error this function exists to avoid.
    """

    _require_header_bytes(raw)
    return raw[36:68].hex()


def header_time(raw: bytes) -> int:
    """Return the header timestamp: the little-endian uint32 at bytes 68-72, in Unix seconds."""

    _require_header_bytes(raw)
    return int.from_bytes(raw[68:72], "little")
