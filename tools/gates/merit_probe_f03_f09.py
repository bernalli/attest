"""Probe for the two merit decisions that live outside the gate layer: F-03 and F-09.

Neither outcome is transcribed from an earlier report. Both are produced here, by
running the normative block the plan tells the executor to transcribe.
"""

from __future__ import annotations

import json
import re
from typing import Any

print("=== F-03: is `-0` admitted? ===")

# The lexical rule the plan prescribes for the test's tokenizer (line 262).
GRAMMAR = re.compile(r"^-?(0|[1-9][0-9]*)$")
for token in ("-0", "0", "-1", "1e3", "1.0", "-0.0", "9007199254740990.1"):
    print(f"grammar {token!r:24} match={bool(GRAMMAR.match(token))}")

# What the current Python core actually does with the token.
for token in ("-0", "0"):
    value = json.loads(token)
    print(
        f"json.loads({token!r}) -> {value!r} type={type(value).__name__} "
        f"is_integer_zero={value == 0}"
    )

print()
print("=== F-09: what does the OLD Python constructor call actually raise? ===")

# The normative block of section 5.1.2, transcribed as the executor would.
_ADMIT = object()


class TrustStore:
    __slots__ = (
        "_artifact_manifest_chains",
        "_artifact_manifests",
        "_canonical",
        "_chains",
        "_manifests",
        "_provenance",
    )

    def __init__(self, token: object, fields: Any, canonical: bytes) -> None:
        if token is not _ADMIT:
            raise TypeError("TrustStore is built by TrustStore.from_bytes(data)")
        (
            self._manifests,
            self._provenance,
            self._chains,
            self._artifact_manifests,
            self._artifact_manifest_chains,
        ) = fields
        self._canonical = canonical


# (a) The OLD call shape the plan says must produce the migration message.
try:
    TrustStore(manifests={})  # type: ignore[call-arg]
except TypeError as exc:
    print(f"OLD SHAPE   TrustStore(manifests=...) -> TypeError: {exc}")
except Exception as exc:  # pragma: no cover - documents anything unexpected
    print(f"OLD SHAPE   unexpected {type(exc).__name__}: {exc}")

# (b) The three-argument call with a forged token: does the body run?
try:
    TrustStore(object(), (None, None, None, None, None), b"")
except TypeError as exc:
    print(f"FORGED TOKEN TrustStore(object(), fields, b'') -> TypeError: {exc}")

# (c) The positional call with the real token: custody admits it.
store = TrustStore(_ADMIT, ({}, {}, {}, {}, {}), b"{}")
print(f"REAL TOKEN  admitted, canonical={store._canonical!r}")
