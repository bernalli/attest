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


def render_strict_utc(parsed: datetime) -> str:
    """The canonical wire text of an instant, for the whole package.

    Public because three modules render wire text of their own, and a module
    that has to guess how reaches for `strftime` — which is the defect this
    function exists to avoid. A renderer nobody can call is a renderer
    everybody rewrites.

    PRECONDITION: `parsed` carries UTC wall-clock fields. This reads
    `.year`…`.second` and appends `Z`; it does NOT convert. An aware datetime
    in another zone is rendered with ITS OWN fields and labelled `Z`, which
    names a different instant — `2026-07-03T00:00:00+09:00` comes back as
    `2026-07-03T00:00:00Z`, nine hours away. Callers holding an aware value
    convert first (`resolved.astimezone(UTC)`), as `views._cutoff_axis` does.
    Sub-second precision is dropped: the wire shape has no place for it.

    The precondition was harmless while this was private — its one caller
    passed `strptime` output, which is always naive. It stops being harmless
    the moment the whole package is invited to call it, which is the point of
    making it public.
    """
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

    The verdict is read from the CHARACTERS, never from the object carrying
    them. `str.__str__` is this package's own-data spelling for a string
    (`canon.own_data_copy`): a `str` subclass reaching an embedding
    application's trust store would otherwise decide this guard from three
    different seats — `__ne__` (the round-trip comparison prefers the
    subclass's reflected operator), `__getitem__`/`__len__` (`strptime` reads
    the input through them) and `__repr__` (the message below formats it). All
    three are answered once, here, by taking the own data first; the plain
    `str` is what the rest of the function ever sees. `str.__str__` on a
    non-`str` raises `TypeError` on its own, so the contract above needs no
    branch of its own.
    """
    own = str.__str__(value)
    parsed = datetime.strptime(own, STRICT_UTC_FMT)
    canonical = render_strict_utc(parsed)
    if canonical != own:
        raise NonCanonicalTimestamp(own, canonical)
    return parsed


def is_strict_utc(value: object) -> bool:
    """Whether `value` is a `str` in the strict UTC wire shape naming a real
    instant. Mirror of `validStage3UtcTimestamp` in `dates.ts`.

    TOTAL, exactly like that mirror, and the asymmetry is why this catches
    `TypeError` too. `typeof s !== 'string'` cannot be forged in JavaScript, so
    the TypeScript side answers `false` for anything that is not a string;
    `isinstance(value, str)` CAN be forged — `isinstance` consults `__class__`
    when the exact type check fails, so a plain object whose `__class__`
    property answers `str` walks past the gate below and makes `str.__str__`
    raise `TypeError` inside `parse_strict_utc`. Letting that out would leave
    the two cores answering the same question in different KINDS — a verdict
    there, an exception here — which is the divergence this module exists to
    remove, not one it may introduce.

    `parse_strict_utc` keeps raising `TypeError` on a non-`str`: that is its
    documented contract and callers who want the distinction still get it.
    This predicate is the one that promises a bool.
    """
    if not isinstance(value, str):
        return False
    try:
        parse_strict_utc(value)
    except (TypeError, ValueError):
        return False
    return True
