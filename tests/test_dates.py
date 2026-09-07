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
from tests.helpers import non_canonical_spellings

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


# --- the verdict comes from the characters, not from the object ---------------

# A `str` subclass reaching this predicate is not a threat from the wire —
# `json.loads` only ever builds exact `str`. It is the surface of the embedding
# application, which builds its trust store from objects of its own, and which
# §18.4 already puts in perimeter for `canon.own_data_copy`. Three seats let
# such an object steer this guard, and each has a case below: `__ne__` (the
# round-trip comparison prefers a subclass's reflected operator), `__len__`/
# `__getitem__` (`strptime` reads the input through them) and `__repr__` (the
# `NonCanonicalTimestamp` message formats it). Taking `str.__str__` once, at
# the top, answers all three; these tests fail if that line is removed.

_NON_CANONICAL = "\uff12\uff10\uff12\uff15-07-02T13:50:00Z"  # fullwidth year, same instant


class _LyingStr(str):
    """Claims to equal anything: `canonical != value` consults it first."""

    def __ne__(self, other: object) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return str.__hash__(self)


class _RaisingStr(str):
    """Turns the round-trip comparison into an exception of the caller's choice."""

    def __ne__(self, other: object) -> bool:
        raise RuntimeError("comparison invoked")

    def __hash__(self) -> int:
        return str.__hash__(self)


class _BadReprStr(str):
    """Raises from the very hook that renders the refusal message."""

    def __repr__(self) -> str:
        raise RuntimeError("repr invoked")


class _ShadowedReadStr(str):
    """Lies about its own characters to `strptime`, which reads them itself."""

    def __len__(self) -> int:
        return 0

    def __getitem__(self, index: object) -> str:
        raise RuntimeError("getitem invoked")

    def __iter__(self) -> object:
        raise RuntimeError("iter invoked")


def test_parse_strict_utc_reads_a_subclass_by_its_own_data() -> None:
    """§18.4's rule, restated for this predicate: a subtype is never refused for
    BEING a subtype — its own characters decide, and they decide alone."""
    honest = parse_strict_utc(_LyingStr(_CANONICAL))
    assert honest == datetime(2025, 7, 2, 13, 50, 0)
    assert is_strict_utc(_LyingStr(_CANONICAL)) is True
    # `strptime` reads the input through `__len__`/`__getitem__`; a subclass
    # that shadows them cannot reach it, because it never gets there.
    assert parse_strict_utc(_ShadowedReadStr(_CANONICAL)) == datetime(2025, 7, 2, 13, 50, 0)
    assert is_strict_utc(_ShadowedReadStr(_CANONICAL)) is True


@pytest.mark.parametrize(
    "hostile",
    [_LyingStr, _RaisingStr, _BadReprStr, _ShadowedReadStr],
    ids=lambda cls: cls.__name__,
)
def test_parse_strict_utc_refuses_a_non_canonical_subclass(hostile: type[str]) -> None:
    """Non-vacuity first: raw `strptime` accepts this spelling, so only the
    round trip can refuse it. Then the refusal must be a `ValueError` — an
    exception of the OBJECT's choosing escaping here is what breaks the
    `verify()`-never-raises contract two layers up."""
    assert datetime.strptime(_NON_CANONICAL, STRICT_UTC_FMT) == datetime(2025, 7, 2, 13, 50, 0)
    with pytest.raises(NonCanonicalTimestamp) as excinfo:
        parse_strict_utc(hostile(_NON_CANONICAL))
    assert excinfo.value.canonical == _CANONICAL
    assert is_strict_utc(hostile(_NON_CANONICAL)) is False


def test_strict_utc_fmt_is_the_wire_shape() -> None:
    assert STRICT_UTC_FMT == "%Y-%m-%dT%H:%M:%SZ"
    assert MAX_REPRESENTABLE_UNIX_SECONDS == 253402300799


# --- the shared corpus is complete, and stays complete ------------------------

# `tests.helpers.non_canonical_spellings` is the hostile corpus four test
# modules parametrize over. Its predecessor was a hand-written list of ten
# forms, and it missed two whole families — a day written with a LEADING SPACE
# (`%d` is `3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9]`; the last branch exists so
# `asctime` output parses) and a non-ASCII digit anywhere outside the year. A
# guard weak enough to admit those passed the whole suite, because no case
# named them.
#
# So the corpus is not asserted against a list here. The family is RE-DERIVED
# from the bare parser by brute force, and the corpus must cover everything the
# derivation finds. A future CPython that widens a field pattern fails this
# test instead of silently opening a hole.

_ND_SAMPLE_SCRIPTS = (
    0xFF10,
    0x0966,
    0x0660,
    0x1C50,
)  # fullwidth, devanagari, arabic-indic, ol chiki
_WHITESPACE = (" ", "\t", "\n", "\r", "\v", "\f", "\u00a0", "\u2007", "\u202f")
_CORPUS_PROBES = (
    "2026-06-05T04:07:09Z",  # every two-digit field zero-padded
    "2026-06-15T14:37:59Z",  # day 10-29, hour 10-19
    "2026-12-31T23:59:59Z",  # upper edges, where most `\d` branches vanish
    "2026-10-25T20:50:50Z",  # month 10-12, hour 20-23
    "0001-01-01T00:00:00Z",  # lower edge
)
_NUMERIC_FIELDS = (
    ("year", 0, 4),
    ("month", 5, 2),
    ("day", 8, 2),
    ("hour", 11, 2),
    ("minute", 14, 2),
    ("second", 17, 2),
)
_SEPARATOR_OFFSETS = (4, 7, 10, 13, 16, 19)


def _skeleton(value: str) -> str:
    """A spelling reduced to its SHAPE: every non-ASCII decimal digit becomes
    one sentinel. Which `Nd` script fills a slot is not a separate risk — the
    corpus carries two scripts at the year to keep that evidence — so coverage
    is judged per shape, not per byte."""
    return "".join("#" if not c.isascii() and unicodedata.category(c) == "Nd" else c for c in value)


def _every_accepted_mutation(canonical: str) -> set[str]:
    """Every single mutation of `canonical` that raw `strptime` accepts as the
    same instant. This is the ground truth the corpus is measured against."""
    expected = datetime.strptime(canonical, STRICT_UTC_FMT)

    def accepted(value: str) -> bool:
        if value == canonical:
            return False
        try:
            return datetime.strptime(value, STRICT_UTC_FMT) == expected
        except ValueError:
            return False

    found: set[str] = set()
    for _, start, width in _NUMERIC_FIELDS:
        raw = canonical[start : start + width]
        bare = str(int(raw))
        replacements: list[str] = [bare, "+" + bare, "-" + bare, "0" + bare, "00" + bare, "0" + raw]
        for ws in _WHITESPACE:
            replacements += [
                ws + bare,
                ws + ws + bare,
                bare + ws,
                ws + bare + ws,
                ws + raw,
                raw + ws,
            ]
        for base in _ND_SAMPLE_SCRIPTS:
            table = str.maketrans("0123456789", "".join(chr(base + d) for d in range(10)))
            replacements.append(raw.translate(table))
            replacements += [raw[:i] + raw[i].translate(table) + raw[i + 1 :] for i in range(width)]
        found |= {
            canonical[:start] + r + canonical[start + width :]
            for r in replacements
            if accepted(canonical[:start] + r + canonical[start + width :])
        }
    for offset in _SEPARATOR_OFFSETS:
        literal = canonical[offset]
        for repl in (literal.lower(), literal.upper(), "", *_WHITESPACE):
            candidate = canonical[:offset] + repl + canonical[offset + 1 :]
            if accepted(candidate):
                found.add(candidate)
    for position in range(len(canonical) + 1):
        for ws in _WHITESPACE:
            candidate = canonical[:position] + ws + canonical[position:]
            if accepted(candidate):
                found.add(candidate)
    return found


@pytest.mark.parametrize("canonical", _CORPUS_PROBES)
def test_the_shared_corpus_covers_every_shape_strptime_accepts(canonical: str) -> None:
    derived = _every_accepted_mutation(canonical)
    assert derived, "the derivation itself found nothing — it would prove nothing"
    covered = {_skeleton(value) for _, value in non_canonical_spellings(canonical)}
    missing = {_skeleton(value) for value in derived} - covered
    assert not missing, (
        f"raw strptime accepts shapes the shared corpus never offers: {sorted(missing)}"
    )


@pytest.mark.parametrize("canonical", _CORPUS_PROBES)
def test_every_corpus_case_is_hostile_and_refused(canonical: str) -> None:
    """Both halves, per case: raw `strptime` ACCEPTS it as the same instant (so
    the case is not vacuous) and the owner REFUSES it (so the guard holds).
    A corpus entry the parser already rejects would make its consumers green
    for the wrong reason — which is the failure this whole section is about."""
    expected = datetime.strptime(canonical, STRICT_UTC_FMT)
    spellings = non_canonical_spellings(canonical)
    assert len(spellings) >= 10, f"corpus shrank to {len(spellings)} cases for {canonical!r}"
    assert len({name for name, _ in spellings}) == len(spellings), "duplicate case names"
    for name, value in spellings:
        assert value != canonical, name
        assert datetime.strptime(value, STRICT_UTC_FMT) == expected, name
        with pytest.raises(NonCanonicalTimestamp):
            parse_strict_utc(value)
        assert is_strict_utc(value) is False, name


def test_the_corpus_names_the_two_families_the_hand_written_list_missed() -> None:
    """Pinned by name, because a regression here is invisible: both families
    are ordinary-looking strings that `strptime` takes and the wire shape does
    not define."""
    by_name = dict(non_canonical_spellings("2026-06-05T04:07:09Z"))
    assert by_name["space_padded_day"] == "2026-06- 5T04:07:09Z"
    assert by_name["non_ascii_digit_hour_1"] == "2026-06-05T0\uff14:07:09Z"
    assert by_name["non_ascii_digit_minute_1"] == "2026-06-05T04:0\uff17:09Z"
    assert by_name["non_ascii_digit_second_1"] == "2026-06-05T04:07:0\uff19Z"
    assert dict(non_canonical_spellings("2026-06-15T14:37:59Z"))["non_ascii_digit_day_1"] == (
        "2026-06-1\uff15T14:37:59Z"
    )
