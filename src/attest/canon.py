"""RFC 8785 (JCS) canonicalization — attest integer-only profile.

Deviation-by-restriction from full JCS: numbers MUST be integers with
|n| < 2**53. Floats are rejected at both serialization and parse time,
which removes the ECMAScript Number::toString implementation burden and
its cross-language interop risk. Normative for attest v0.1 payloads.
"""

from __future__ import annotations

import json
from typing import Any

_INT_MAX = 2**53  # exclusive
MAX_DEPTH = 256  # matches the TS parser cap; bounds parse/reject-surrogate recursion.
# Public (2026-07-22 fix wave): this is the single normative nesting-depth
# ceiling attest-versioning.md §5's structural-ceilings amendment (v0.1 §11.3)
# refers to — `validate.MAX_JSON_DEPTH` aliases this constant rather than
# defining a second, smaller one.
_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class CanonError(ValueError):
    """Input not representable in the attest-JCS profile."""


class DuplicateKeyError(CanonError):
    """JSON object contains a duplicated member name (RFC 8785 requires rejection)."""


def _serialize_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise CanonError("lone surrogate not allowed in the attest-JCS profile")
        if cp in _ESCAPES:
            out.append(_ESCAPES[cp])
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize(obj: Any, out: list[str]) -> None:
    if obj is None:
        out.append("null")
    elif isinstance(obj, bool):  # MUST precede int (bool subclasses int)
        out.append("true" if obj else "false")
    elif isinstance(obj, int):
        if not -_INT_MAX < obj < _INT_MAX:
            raise CanonError(f"integer out of I-JSON safe range: {obj}")
        out.append(str(obj))
    elif isinstance(obj, float):
        raise CanonError("floats are not allowed in the attest-JCS profile")
    elif isinstance(obj, str):
        out.append(_serialize_string(obj))
    elif isinstance(obj, list):
        out.append("[")
        for i, item in enumerate(obj):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise CanonError(f"non-string object key: {k!r}")
        out.append("{")
        for i, k in enumerate(sorted(obj, key=lambda k: k.encode("utf-16-be", "surrogatepass"))):
            if i:
                out.append(",")
            out.append(_serialize_string(k))
            out.append(":")
            _serialize(obj[k], out)
        out.append("}")
    else:
        raise CanonError(f"type not representable in JSON: {type(obj).__name__}")


def dumps(obj: object) -> str:
    out: list[str] = []
    try:
        _serialize(obj, out)
    except RecursionError as exc:
        # A body too deep (or self-referential) to serialize is not
        # representable in the profile, exactly like a float or an
        # out-of-range integer -- and it MUST leave this module in the
        # CanonError family, or it escapes every fail-closed boundary that
        # catches CanonError/ValueError (manifests, revocation, transfer,
        # verify). Mirrors `loads_strict`'s own RecursionError belt.
        raise CanonError("maximum nesting depth exceeded") from exc
    return "".join(out)


def canonical_bytes(obj: object) -> bytes:
    """The only byte form ever signed or hashed in attest."""
    return dumps(obj).encode("utf-8")


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKeyError(f"duplicate object key: {k!r}")
        d[k] = v
    return d


def _reject_float(_s: str) -> Any:
    raise CanonError("floats are not allowed in the attest-JCS profile")


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def _reject_surrogates(obj: Any) -> None:
    """Reject lone surrogates that entered via \\uXXXX escapes (keys or values)."""
    if isinstance(obj, str):
        if _has_surrogate(obj):
            raise CanonError("lone surrogate not allowed in the attest-JCS profile")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if _has_surrogate(k):
                raise CanonError("lone surrogate not allowed in the attest-JCS profile")
            _reject_surrogates(v)
    elif isinstance(obj, list):
        for item in obj:
            _reject_surrogates(item)


def _check_depth(text: str) -> None:
    """Reject nesting beyond ``MAX_DEPTH`` before ``json.loads`` runs, so a
    pathologically nested payload can never drive JSON parsing or surrogate
    rejection into an uncaught ``RecursionError`` (2026-07-13 review, finding 3).
    Mirrors the TS recursive-descent depth cap. Brackets inside strings are
    ignored so string content never inflates the count."""
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise CanonError("maximum nesting depth exceeded")
        elif ch in "]}":
            depth -= 1


def loads_strict(data: bytes) -> object:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CanonError(f"input is not valid UTF-8: {exc}") from exc
    _check_depth(text)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except json.JSONDecodeError as exc:
        raise CanonError(f"invalid JSON: {exc}") from exc
    except RecursionError as exc:  # belt-and-suspenders: the depth cap should prevent this
        raise CanonError("maximum nesting depth exceeded") from exc
    _reject_surrogates(parsed)
    return parsed
