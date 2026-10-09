"""Small fail-closed predicates shared by several verification stages: the
strict date parse, key-entry validity windows, the lenient ISO parse used for
revocation/anchor times, warning de-duplication and own-item member reads."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from attest.dates import parse_strict_utc

# The strict wire shape is owned by `attest.dates`, for the whole package.
# TEMPORARY name: the call sites in this package still say `_parse_date`.
_parse_date = parse_strict_utc


def _within_validity(issued_at: str, entry: dict[str, Any]) -> bool:
    """Fail closed on any malformed or missing date. `parse_strict_utc` refuses
    both what `strptime` cannot parse and what it would parse WRONGLY (non-ASCII
    digits, unpadded fields, lowercase `t`/`z`): a bound that is not the
    canonical spelling of an instant never resurrects a receipt into validity,
    and never lets one core accept a window the other rejects."""
    try:
        issued = _parse_date(issued_at)
        valid_from = _parse_date(entry["valid_from"])
    except (KeyError, TypeError, ValueError):
        return False
    if issued < valid_from:
        return False
    valid_to = entry.get("valid_to")
    if valid_to is None:
        return True
    try:
        return issued <= _parse_date(valid_to)
    except (TypeError, ValueError):
        return False


def _append_warning_once(warnings: list[str], warning: str) -> None:
    if warning not in warnings:
        warnings.append(warning)


def _parse_iso(value: object) -> datetime | None:
    """Fail-closed ISO-8601 parse for revocation timestamps — `None` on any
    non-str or unparseable input, never raises. `datetime.fromisoformat`
    handles the `Z` suffix directly on Python 3.12."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _own_member(document: object, member: str) -> object:
    return dict.get(document, member) if isinstance(document, dict) else None


def _member_equals(document: object, member: str, expected: object) -> bool:
    """`_own_member` plus the comparison, fail-closed.

    An own-item read defeats an overridden `get`, but it hands back whatever
    the member holds — and a `str` subclass that refuses to be compared
    canonicalizes, signs and authenticates exactly like the string it shadows,
    so it survives to the binding checks that run AFTER authentication. This
    is the `__eq__` trigger `authority.entry_for_issuer` names as the reason
    an own-item read still needs an enclosing guard. A value that will not
    compare is not equal to anything: every binding this decides fails closed.
    """
    try:
        return isinstance(document, dict) and bool(dict.get(document, member) == expected)
    except Exception:
        return False
