"""Timestamp predicates shared by receipt evidence producers and verifiers.

This module owns, for the whole package, what `verifiers/ts/src/dates.ts`
owns for the TypeScript core:

* `MAX_REPRESENTABLE_UNIX_SECONDS` — the last instant BOTH cores can represent;
* `parse_strict_utc` / `is_strict_utc` — the ONE strict parser of the signed
  UTC wire shape `YYYY-MM-DDTHH:MM:SSZ`.

A restated predicate is owned by nobody: import these, never re-declare them.
`_parse_date` lived in four identical copies (`verify`, `manifests`,
`revocation`, `transfer`) plus three inline `strptime` calls, and the copy
that guarded the refund-window check did not know the other three existed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

# 9999-12-31T23:59:59Z: the last whole Unix second Python's datetime can render.
# JavaScript Date reaches further; both cores use this common upper bound.
MAX_REPRESENTABLE_UNIX_SECONDS: Final = 253402300799

# The signed UTC wire shape. `strptime` with this format is the ONLY strptime
# call in `src/attest/` — pinned by tests/test_shared_predicate_ownership.py.
STRICT_UTC_FMT: Final = "%Y-%m-%dT%H:%M:%SZ"


class NonCanonicalTimestamp(ValueError):
    """`strptime` accepted `value`, but `value` is not the canonical spelling of
    the instant it names. Carries that spelling for callers that want to say
    "write it exactly as ...". It IS a `ValueError`: every existing
    `except ValueError` keeps its meaning."""

    def __init__(self, value: str, canonical: str) -> None:
        super().__init__(f"timestamp {value!r} is not the canonical spelling {canonical!r}")
        self.canonical = canonical


def _render_strict_utc(parsed: datetime) -> str:
    # NOT `strftime(STRICT_UTC_FMT)`: glibc renders `%Y` for years below 1000
    # without zero padding ("999"), so a strftime round trip would refuse
    # `0999-...` on Linux and accept it on a libc that pads — a verdict that
    # depends on the platform, and a split with `parseStrictUtc`, which
    # accepts 0001-9999. This rendering is what the format promises.
    return (
        f"{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}"
        f"T{parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}Z"
    )


def parse_strict_utc(value: str) -> datetime:
    """The signed UTC wire shape `YYYY-MM-DDTHH:MM:SSZ`, checked by ROUND TRIP.

    `strptime` alone accepts what no conforming producer emits and what the
    TypeScript core refuses: Unicode decimal digits in the year (`%Y` is a
    `\\d\\d\\d\\d` regex and `\\d` matches every Nd character), unpadded fields
    (`2025-8-1T0:0:0Z`), lowercase `t`/`z` (the match is case-insensitive).
    Re-rendering the parsed instant and comparing it with the input refuses
    all of them at once, whatever the next member of the family turns out to be.

    Returns a naive `datetime` (UTC by convention, as every caller assumed).
    Raises `ValueError` — `NonCanonicalTimestamp` when `strptime` accepted but
    the spelling differs — on anything else; a non-`str` raises `TypeError`,
    as `strptime` always did. Mirror of `parseStrictUtc` in
    `verifiers/ts/src/dates.ts`: the two accept the same set of strings.
    """
    parsed = datetime.strptime(value, STRICT_UTC_FMT)
    canonical = _render_strict_utc(parsed)
    if canonical != value:
        raise NonCanonicalTimestamp(value, canonical)
    return parsed


def is_strict_utc(value: object) -> bool:
    """Whether `value` is a `str` in the strict UTC wire shape naming a real
    instant. Mirror of `validStage3UtcTimestamp` in `dates.ts`."""
    if not isinstance(value, str):
        return False
    try:
        parse_strict_utc(value)
    except ValueError:
        return False
    return True
