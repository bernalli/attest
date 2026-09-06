"""ULID generation for `receipt_id` (§4): sortable, no coordination.

Crockford base32 (excludes I/L/O/U to avoid visual ambiguity), 48-bit
millisecond timestamp + 80 bits of randomness = 128 bits, encoded as 26
characters (130 bits of output; the 2 highest-order bits are always zero).
"""

from __future__ import annotations

import os
import re
import time

# The receipt schema uses the 128-bit ULID range, including the leading digit.
RECEIPT_ID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_TIMESTAMP_BITS = 48
_RANDOMNESS_BYTES = 10


def generate(timestamp_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Return a 26-char Crockford-base32 ULID.

    `timestamp_ms` and `randomness` are injectable for deterministic tests;
    by default the wall clock and the OS CSPRNG are used.
    """
    ts = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    rnd = os.urandom(_RANDOMNESS_BYTES) if randomness is None else randomness
    if ts < 0 or ts >= 2**_TIMESTAMP_BITS or len(rnd) != _RANDOMNESS_BYTES:
        raise ValueError("invalid ULID inputs")
    value = (ts << 80) | int.from_bytes(rnd, "big")
    return "".join(_ALPHABET[(value >> shift) & 0x1F] for shift in range(125, -1, -5))
