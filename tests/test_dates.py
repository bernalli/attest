"""The strict UTC timestamp predicate, owned by `attest.dates`.

`strptime` alone accepts spellings no conforming producer emits and the
TypeScript core refuses: Unicode decimal digits in year/time fields, unpadded fields,
lowercase `t`/`z`. Guard regressions establish acceptance by raw `strptime`
per case or by an aggregate non-vacuity check. Contract tests also cover
malformed inputs that `strptime` already rejects.
"""

from __future__ import annotations

import sys
import unicodedata
from datetime import datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from attest.dates import (
    MAX_REPRESENTABLE_UNIX_SECONDS,
    STRICT_UTC_FMT,
    NonCanonicalTimestamp,
    is_strict_utc,
    parse_strict_utc,
)

_CANONICAL = "2025-07-02T13:50:00Z"

# Every non-ASCII decimal digit. Built once: the year-position loops below reuse it.
_NON_ASCII_DECIMAL_DIGITS = tuple(
    c
    for c in (chr(cp) for cp in range(0x80, sys.maxunicode + 1))
    if unicodedata.category(c) == "Nd"
)


def _year_with(char: str, position: int) -> str:
    """`_CANONICAL` with one character of the year replaced — the rest canonical.

    The mutation is confined to the year to exercise the original exploit
    in every year position. `strptime` also accepts non-ASCII digits in some
    time-field positions; those have dedicated regression cases below.
    """
    year = "2025"
    return year[:position] + char + year[position + 1 :] + _CANONICAL[4:]


def test_parse_strict_utc_accepts_canonical_instants() -> None:
    for value, expected in (
        (_CANONICAL, (2025, 7, 2, 13, 50, 0)),
        ("9999-12-31T23:59:59Z", (9999, 12, 31, 23, 59, 59)),
        ("1000-01-01T00:00:00Z", (1000, 1, 1, 0, 0, 0)),
        ("0999-12-31T23:59:59Z", (999, 12, 31, 23, 59, 59)),
        ("0001-01-01T00:00:00Z", (1, 1, 1, 0, 0, 0)),
    ):
        parsed = parse_strict_utc(value)
        assert isinstance(parsed, datetime)
        assert parsed.tzinfo is None, "callers assume a naive UTC datetime"
        assert (
            parsed.year,
            parsed.month,
            parsed.day,
            parsed.hour,
            parsed.minute,
            parsed.second,
        ) == expected


def test_parse_strict_utc_rejects_every_non_ascii_decimal_digit_in_each_year_position() -> None:
    accepted_raw = 0
    for char in _NON_ASCII_DECIMAL_DIGITS:
        for position in range(4):
            value = _year_with(char, position)
            try:
                datetime.strptime(value, STRICT_UTC_FMT)
            except ValueError:
                pass
            else:
                accepted_raw += 1
            with pytest.raises(ValueError):
                parse_strict_utc(value)
            assert is_strict_utc(value) is False

    # Non-vacuity: the guard is doing the rejecting, not `strptime`. If this
    # count ever drops to zero the test above would pass while proving nothing.
    assert accepted_raw >= 600, f"only {accepted_raw} spellings reached the guard"


def test_raw_strptime_accepts_the_fullwidth_year_the_guard_refuses() -> None:
    """The exploit primitive, pinned: this is the one spelling that got through."""
    hostile = "２０２５-07-02T13:50:00Z"  # noqa: RUF001 - the fullwidth year IS the exploit
    assert datetime.strptime(hostile, STRICT_UTC_FMT).year == 2025
    assert hostile.isascii() is False
    with pytest.raises(NonCanonicalTimestamp):
        parse_strict_utc(hostile)


@pytest.mark.parametrize(
    "value",
    [
        "2025-07-02T1\uff13:50:00Z",
        "2025-07-02T13:5\uff10:00Z",
        "2025-07-02T13:50:0\uff10Z",
    ],
)
def test_parse_strict_utc_rejects_unicode_time_digits_strptime_accepts(value: str) -> None:
    assert datetime.strptime(value, STRICT_UTC_FMT) == datetime(2025, 7, 2, 13, 50, 0)
    assert value.isascii() is False
    with pytest.raises(NonCanonicalTimestamp) as excinfo:
        parse_strict_utc(value)
    assert excinfo.value.canonical == _CANONICAL
    assert is_strict_utc(value) is False


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("2025-07-02t13:50:00Z", _CANONICAL),
        ("2025-07-02T13:50:00z", _CANONICAL),
        ("2025-07-02t13:50:00z", _CANONICAL),
        ("2025-7-02T13:50:00Z", _CANONICAL),
        ("2025-07-2T13:50:00Z", _CANONICAL),
        ("2025-07-02T13:5:00Z", "2025-07-02T13:05:00Z"),
        ("2025-07-02T13:50:0Z", _CANONICAL),
        ("2025-07-02T3:50:00Z", "2025-07-02T03:50:00Z"),
    ],
)
def test_parse_strict_utc_rejects_ascii_spellings_strptime_accepts(
    value: str, canonical: str
) -> None:
    # Precondition: without the guard these reach every caller unchanged, and
    # `isascii()` — the narrower guard — does not see them at all.
    assert datetime.strptime(value, STRICT_UTC_FMT) is not None
    assert value.isascii() is True

    with pytest.raises(NonCanonicalTimestamp) as excinfo:
        parse_strict_utc(value)
    assert excinfo.value.canonical == canonical
    assert is_strict_utc(value) is False


@given(
    digit=st.characters(categories=("Nd",), min_codepoint=128),
    position=st.integers(min_value=0, max_value=3),
)
@settings(max_examples=200, deadline=None, derandomize=True)
def test_parse_strict_utc_property_one_non_ascii_digit_anywhere_in_the_year(
    digit: str, position: int
) -> None:
    with pytest.raises(ValueError):
        parse_strict_utc(_year_with(digit, position))


def test_parse_strict_utc_low_years_match_the_typescript_core() -> None:
    """Mirrors `verifiers/ts/test/dates.test.ts`: 0001-0999 are representable in
    both cores, 0000 in neither. This is why the round trip renders the year
    explicitly instead of calling `strftime`, which drops the padding below
    1000 on this libc and would refuse these in Python alone."""
    for value, expected_year in (
        ("0001-01-01T00:00:00Z", 1),
        ("0099-01-01T00:00:00Z", 99),
        ("0999-01-01T00:00:00Z", 999),
    ):
        assert parse_strict_utc(value).year == expected_year
        assert is_strict_utc(value) is True

    with pytest.raises(ValueError):
        parse_strict_utc("0000-01-01T00:00:00Z")


def test_parse_strict_utc_contract() -> None:
    for not_a_string in (None, 20250702, b"2025-07-02T13:50:00Z", object()):
        with pytest.raises(TypeError):
            parse_strict_utc(not_a_string)  # type: ignore[arg-type]
        assert is_strict_utc(not_a_string) is False

    for malformed in (
        "",
        "not-a-date",
        "2025-07-02T13:50:00.000Z",
        "2025-07-02T13:50:00+00:00",
        "2025-07-02T13:50:00",
        " 2025-07-02T13:50:00Z",
        "2025-07-02T13:50:00Z ",
        "2025-02-30T00:00:00Z",
        "2025-13-01T00:00:00Z",
    ):
        with pytest.raises(ValueError):
            parse_strict_utc(malformed)
        assert is_strict_utc(malformed) is False

    assert issubclass(NonCanonicalTimestamp, ValueError)
    assert is_strict_utc(_CANONICAL) is True


def test_strict_utc_fmt_is_the_wire_shape() -> None:
    assert STRICT_UTC_FMT == "%Y-%m-%dT%H:%M:%SZ"
    assert MAX_REPRESENTABLE_UNIX_SECONDS == 253402300799
