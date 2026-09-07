"""The strict UTC timestamp predicate, owned by `attest.dates`.

`strptime` alone accepts spellings no conforming producer emits and the
TypeScript core refuses: Unicode decimal digits in year/time fields, unpadded fields,
lowercase `t`/`z`. Guard regressions establish acceptance by raw `strptime`
per case or by an aggregate non-vacuity check. Contract tests also cover
malformed inputs that `strptime` already rejects.
"""

from __future__ import annotations

import _strptime
import functools
import itertools
import re
import sys
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from attest import dates
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

# `tests.helpers.non_canonical_spellings` is the hostile corpus five test
# modules parametrize over. Three successive attempts to establish that it was
# complete failed the same way, and the third was itself a brute-force
# derivation written to audit the second: each applied a non-ASCII digit only
# to the zero-padded spelling of a field, so none of them ever produced
# `2026-06-05T\uff14:07:09Z` — an hour written without its leading zero, in one
# non-ASCII character. `%H`, `%M` and `%S` end their alternation with a bare
# `\d`, so `strptime` takes it, it names the same instant, and no case named it.
#
# What that costs is not three missing entries. It is that a derivation written
# from the corpus inherits the corpus's blind spots, and then reports green.
#
# So the check below does not derive anything and shares nothing with the
# generator. It reads `_strptime.TimeRE()` for itself, by a deliberately
# different route — the generator hands each alternative to the `re` module's
# own parser and compiler, while this file splits the alternation as TEXT and
# then treats each branch as a BLACK BOX, probing it character by character to
# learn what it accepts where. Neither imports the other's machinery, and the
# duplicated eight lines that read the authority are the price of that.
#
# What it demands is COVERAGE, not a count:
#
#   * every branch the parser declares for every field of the format, unless
#     the branch is witnessed unusable (`%S` accepts `60` and `61`, and
#     `datetime` then refuses the leap second — so that branch can appear in no
#     timestamp at all, and the witness is exhaustive, not an opinion);
#   * for every position of every usable branch, both script classes the
#     position admits — an ASCII decimal digit, and a non-ASCII one. This is
#     the cell the old corpus left empty three times: `%H` branch `\d`,
#     position 0, non-ASCII;
#   * for every literal separator, the opposite case, because `TimeRE` compiles
#     the format with `IGNORECASE`;
#   * for every position of every usable branch, each NON-DIGIT character of
#     `_PROBE_ALPHABET` it accepts in a spelling that really parses. Today that
#     is one cell — the space `%d` pads a short day with — and it exists so that
#     a position widened to a second whitespace character cannot pass unseen:
#     the generator builds field spellings out of a hand-written alphabet
#     (`helpers._INT_ALPHABET`), so a widening it does not know about would
#     shrink the corpus in silence. Measured: without this cell, teaching
#     `%d` to accept U+00A0 leaves every test in this section green while
#     `strptime` starts taking a spelling the corpus does not carry.
#
# A future CPython that adds a branch, or widens an existing position to accept
# any character of `_PROBE_ALPHABET` it did not accept before, turns this test
# red instead of silently opening a hole — the alarm is only as wide as that
# alphabet, which is why it is broad. A future CPython that changes a field
# into something that is not a flat run of single-character items fails the
# shape assertion in `_branches`, which is the same alarm one level up.

_CORPUS_PROBES = (
    # Chosen so that between them they realise every branch the parser declares:
    # months 01/06/10/12, days 01/05/15/25/31, hours 00/04/14/20/23, and the
    # minutes and seconds that reach both `[0-5]\d` and the bare `\d`. A branch
    # no probe realises makes the coverage test red, naming it — the list is
    # held to that, it is not trusted.
    "2026-06-05T04:07:09Z",  # every two-digit field zero-padded
    "2026-06-15T14:37:59Z",  # day 10-29, hour 10-19
    "2026-12-31T23:59:59Z",  # upper edges, where most `\d` branches vanish
    "2026-10-25T20:50:50Z",  # month 10-12, hour 20-23
    "0001-01-01T00:00:00Z",  # lower edge
)

# Any timestamp whose fields can be replaced one at a time without hitting a
# calendar edge: January has 31 days, so every day branch is testable on it.
_REALISABILITY_BASE = "0001-01-01T00:00:00Z"

_WHITESPACE = (" ", "\t", "\n", "\r", "\v", "\f", "\u00a0", "\u2007", "\u202f")

# The characters this file offers a branch to find out what it accepts. Broad on
# purpose: every printable ASCII character, decimal digits from five scripts,
# and a couple of non-digit non-ASCII characters. A branch that accepted a
# letter or a sign would show up here.
_PROBE_ALPHABET = tuple(
    dict.fromkeys(
        [chr(c) for c in range(0x20, 0x7F)]
        + [chr(base + d) for base in (0xFF10, 0x0966, 0x0660, 0x1C50, 0x0E50) for d in range(10)]
        + ["\u00e9", "\u00a0", "\t"]
    )
)
_ASCII_DIGITS = frozenset("0123456789")
# Every printable ASCII character, so that a branch built out of something that
# is not a digit still gets its usability decided by enumeration instead of
# being waved through as unreachable.
_ASCII_CHARS = frozenset(chr(code) for code in range(0x20, 0x7F))
# Small enough to enumerate at four positions, wide enough to contain a member
# of every branch the format declares: ASCII digits, the space `%d` pads a short
# day with, and the sign and underscore `int()` would tolerate around a numeral.
# A branch built from anything else finds no member here — which is not silence,
# it is the first assertion in `_probe_branch`, and it says so.
_SEED_ALPHABET = "0123456789 +-_"

_OWN_TIME_RE = _strptime.TimeRE()
_OWN_FORMAT_RE = _OWN_TIME_RE.compile(STRICT_UTC_FMT)


def _is_non_ascii_digit(char: str) -> bool:
    return not char.isascii() and unicodedata.category(char) == "Nd"


def _split_alternation(pattern: str) -> tuple[str, ...]:
    """The top-level `|` alternatives of the body of a `(?P<x>...)` group.

    Text-level on purpose: the generator asks `re._parser` for the same split,
    and two readings of one authority that share a mechanism share its failures.
    Depth-aware, so a future `(?:a|b)|c` splits into two branches and not three.
    """
    outer = re.fullmatch(r"\(\?P<\w+>(.*)\)", pattern, re.DOTALL)
    assert outer is not None, f"unexpected directive shape: {pattern!r}"
    body = outer.group(1)
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            current.append(body[index : index + 2])
            index += 2
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        if char == "|" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    return tuple(parts)


@dataclass(frozen=True)
class _Branch:
    """One alternative of one field, learned by probing rather than by parsing."""

    directive: str
    index: int
    text: str
    matcher: re.Pattern[str]
    accepted: tuple[frozenset[str], ...]  # per position, from the probe alphabet
    usable: bool  # some spelling of it survives into a real timestamp

    @property
    def label(self) -> str:
        return f"%{self.directive} branch {self.index} {self.text!r}"


def _probe_branch(directive: str, index: int, text: str) -> _Branch:
    matcher = re.compile(text, re.IGNORECASE)
    widths = {
        width
        for width in range(1, 5)
        if any(
            matcher.fullmatch("".join(combo))
            for combo in itertools.product(_SEED_ALPHABET, repeat=width)
        )
    }
    assert widths, (
        f"%{directive} branch {text!r} matches nothing built from {_SEED_ALPHABET!r} at "
        "widths 1-4: this probe cannot see it, so its coverage cannot be judged — widen "
        "_SEED_ALPHABET, and read what the field now accepts before trusting anything below"
    )
    assert len(widths) == 1, f"%{directive} branch {text!r} is not fixed-width: {widths}"
    width = widths.pop()
    seed = next(
        "".join(combo)
        for combo in itertools.product(_SEED_ALPHABET, repeat=width)
        if matcher.fullmatch("".join(combo))
    )
    accepted = tuple(
        frozenset(c for c in _PROBE_ALPHABET if matcher.fullmatch(seed[:i] + c + seed[i + 1 :]))
        for i in range(width)
    )
    # Usable = some ASCII member of this branch survives into a timestamp the
    # parser accepts. ASCII is enough to decide it: on every class the format
    # declares today, a position that takes a non-ASCII decimal digit takes an
    # ASCII one too, so replacing them keeps both the match and the value — a
    # branch with a live member therefore has a live ASCII member. A future
    # class that accepted non-ASCII digits and no ASCII one would break that,
    # and would be reported unusable; the pin in
    # `test_every_branch_is_either_usable_or_witnessed_unusable` turns that into
    # a red rather than a silent skip.
    start, end = _OWN_FORMAT_RE.match(_REALISABILITY_BASE).span(directive)  # type: ignore[union-attr]
    ascii_positions = [sorted(a & _ASCII_CHARS) for a in accepted]
    space = 1
    for position in ascii_positions:
        space *= len(position)
    assert space <= 250_000, (
        f"%{directive} branch {text!r} spans {space} ASCII members: too many to decide "
        "usability by enumeration — read what the field now accepts"
    )
    ascii_members = itertools.product(*ascii_positions)
    usable = False
    for member in ascii_members:
        candidate = _REALISABILITY_BASE[:start] + "".join(member) + _REALISABILITY_BASE[end:]
        try:
            datetime.strptime(candidate, STRICT_UTC_FMT)
        except ValueError:
            continue
        usable = True
        break
    return _Branch(directive, index, text, matcher, accepted, usable)


@functools.cache
def _branches() -> dict[str, tuple[_Branch, ...]]:
    found: dict[str, tuple[_Branch, ...]] = {}
    for directive in _OWN_FORMAT_RE.groupindex:
        texts = _split_alternation(_OWN_TIME_RE[directive])
        found[directive] = tuple(
            _probe_branch(directive, index, text) for index, text in enumerate(texts)
        )
    return found


def _realisable_with(branch: _Branch, position: int, char: str) -> bool:
    """Whether some member of `branch` carrying `char` at `position` parses.

    A branch may accept a character that no whole timestamp can carry — `%S`
    takes `60`, `datetime` does not — and requiring the corpus to cover such a
    cell would be a red nobody can clear. So the requirement is gated on a
    spelling that the real parser takes."""
    start, end = _OWN_FORMAT_RE.match(_REALISABILITY_BASE).span(branch.directive)  # type: ignore[union-attr]
    positions = [sorted(a & _ASCII_CHARS) for a in branch.accepted]
    positions[position] = [char]
    for member in itertools.product(*positions):
        candidate = _REALISABILITY_BASE[:start] + "".join(member) + _REALISABILITY_BASE[end:]
        try:
            datetime.strptime(candidate, STRICT_UTC_FMT)
        except ValueError:
            continue
        return True
    return False


def _required_cells() -> set[str]:
    required: set[str] = set()
    for branches in _branches().values():
        for branch in branches:
            if not branch.usable:
                continue
            required.add(branch.label)
            for position, allowed in enumerate(branch.accepted):
                if allowed & _ASCII_DIGITS:
                    required.add(f"{branch.label} position {position} ASCII digit")
                if any(_is_non_ascii_digit(c) for c in allowed):
                    required.add(f"{branch.label} position {position} non-ASCII digit")
                for char in sorted(c for c in allowed if not c.isdigit()):
                    if _realisable_with(branch, position, char):
                        required.add(f"{branch.label} position {position} {char!r}")
    return required


def _covered_cells(values: Iterable[str]) -> set[str]:
    covered: set[str] = set()
    for value in values:
        match = _OWN_FORMAT_RE.match(value)
        if match is None or match.end() != len(value):
            continue
        for directive, branches in _branches().items():
            field = match.group(directive)
            # The engine picks the first alternative that matches the field: a
            # later one could only match the same characters and continue the
            # same way, so first-fullmatch is the branch that actually ran.
            branch = next((b for b in branches if b.matcher.fullmatch(field)), None)
            if branch is None:
                continue
            covered.add(branch.label)
            for position, char in enumerate(field):
                if char in _ASCII_DIGITS:
                    covered.add(f"{branch.label} position {position} ASCII digit")
                elif _is_non_ascii_digit(char):
                    covered.add(f"{branch.label} position {position} non-ASCII digit")
                else:
                    covered.add(f"{branch.label} position {position} {char!r}")
    return covered


def _corpus_values() -> tuple[str, ...]:
    return tuple(_CORPUS_PROBES) + tuple(
        value for probe in _CORPUS_PROBES for _, value in non_canonical_spellings(probe)
    )


def test_the_branch_split_agrees_with_the_parser_it_came_from() -> None:
    """This file splits the alternation by text; the field regex is the whole
    truth. If the two ever disagree on a string, the split is wrong and every
    verdict below it is worthless — so it is checked against the parser's own
    compiled field, not assumed."""
    samples = (
        *("0", "5", "05", "09", "31", " 5", "60", "23", "2026", "0000"),
        *("\uff14", "0\uff14", "202\uff16", "\uff10\uff10\uff10\uff10", " 0", "x", ""),
    )
    for directive, branches in _branches().items():
        whole = re.compile(_OWN_TIME_RE[directive], re.IGNORECASE)
        for sample in samples:
            assert bool(whole.fullmatch(sample)) == any(
                b.matcher.fullmatch(sample) for b in branches
            ), (directive, sample)


def test_the_corpus_covers_every_branch_the_parser_declares() -> None:
    """The corpus is held to the STRUCTURE `strptime` publishes, not to a list
    and not to a count: every usable branch of every field, both script classes
    at every position that admits them."""
    required = _required_cells()
    assert required, "the probe found no branch at all — it would prove nothing"
    missing = required - _covered_cells(_corpus_values())
    assert not missing, (
        "the parser declares spellings the shared corpus never offers "
        f"(add a probe to _CORPUS_PROBES, or the generator misses a dimension): {sorted(missing)}"
    )


def test_every_branch_is_either_usable_or_witnessed_unusable() -> None:
    """A branch nothing can reach is skipped above, and this test is the record
    of which and why — so that "skipped" never becomes a place to hide a branch
    the corpus simply does not cover. `%S` accepting `60`/`61` is the one case
    on CPython 3.12: the regex takes the leap second, `datetime` refuses it."""
    unusable = {b.label for bs in _branches().values() for b in bs if not b.usable}
    for label in unusable:
        directive = label[1]
        branch = next(b for b in _branches()[directive] if b.label == label)
        start, end = _OWN_FORMAT_RE.match(_REALISABILITY_BASE).span(directive)  # type: ignore[union-attr]
        members = itertools.product(*[sorted(a & _ASCII_CHARS) for a in branch.accepted])
        for member in members:
            candidate = _REALISABILITY_BASE[:start] + "".join(member) + _REALISABILITY_BASE[end:]
            with pytest.raises(ValueError):
                datetime.strptime(candidate, STRICT_UTC_FMT)
    assert unusable == {"%S branch 0 '6[0-1]'"}, (
        "the set of unreachable branches moved; read the new one before trusting "
        f"the coverage test above: {sorted(unusable)}"
    )


def test_the_corpus_covers_the_case_of_every_literal_separator() -> None:
    """`TimeRE` compiles the format with `IGNORECASE`, so each literal has a
    second spelling. Derived from the compiled pattern's flags, not asserted:
    a CPython that dropped `IGNORECASE` would drop the requirement with it."""
    match = _OWN_FORMAT_RE.match(_CORPUS_PROBES[0])
    assert match is not None
    numeric = {i for d in _OWN_FORMAT_RE.groupindex for i in range(*match.span(d))}
    literals = [i for i in range(len(_CORPUS_PROBES[0])) if i not in numeric]
    assert literals, "the format has no literal separators — the probe is wrong"
    required = set()
    if _OWN_FORMAT_RE.flags & re.IGNORECASE:
        for probe in _CORPUS_PROBES:
            for index in literals:
                if probe[index].swapcase() != probe[index]:
                    required.add((index, probe[index].swapcase()))
    covered = {
        (index, value[index])
        for value in _corpus_values()
        if len(value) == len(_CORPUS_PROBES[0])
        for index in literals
    }
    assert not required - covered, sorted(required - covered)


def test_no_whitespace_can_be_smuggled_into_the_wire_shape() -> None:
    """The branch model above covers what each FIELD accepts; this covers the
    format around them. A directive separated by whitespace, or a literal
    compiled as `\\s*`, would let a spelling in through a dimension no branch
    describes — so the property is measured directly, on every probe.

    What the corpus would need is the weaker "no insertion names the same
    instant"; what holds today, and what is asserted, is the stronger "no
    insertion parses at all". If a future parser ever accepts one, this fails
    and the weaker property has to be looked at on its own."""
    for canonical in _CORPUS_PROBES:
        for position in range(len(canonical) + 1):
            for space in _WHITESPACE:
                candidate = canonical[:position] + space + canonical[position:]
                with pytest.raises(ValueError):
                    datetime.strptime(candidate, STRICT_UTC_FMT)


@pytest.mark.parametrize("canonical", _CORPUS_PROBES)
def test_every_corpus_case_is_hostile_and_refused(canonical: str) -> None:
    """Both halves, per case: raw `strptime` ACCEPTS it as the same instant (so
    the case is not vacuous) and the owner REFUSES it (so the guard holds).
    A corpus entry the parser already rejects would make its consumers green
    for the wrong reason — which is the failure this whole section is about.

    No floor on the count: how many spellings a value has is measured, and the
    coverage test above is what keeps the corpus from shrinking."""
    expected = datetime.strptime(canonical, STRICT_UTC_FMT)
    spellings = non_canonical_spellings(canonical)
    assert spellings, f"empty corpus for {canonical!r}"
    assert len({name for name, _ in spellings}) == len(spellings), "duplicate case names"
    assert len({value for _, value in spellings}) == len(spellings), "duplicate spellings"
    for name, value in spellings:
        assert value != canonical, name
        assert datetime.strptime(value, STRICT_UTC_FMT) == expected, name
        with pytest.raises(NonCanonicalTimestamp):
            parse_strict_utc(value)
        assert is_strict_utc(value) is False, name


def test_the_corpus_carries_the_family_three_constructions_missed() -> None:
    """Pinned by VALUE, not by case name: an unpadded time field written with
    one non-ASCII digit is the spelling that a hand-written list, a generative
    rewrite of it, and a brute-force audit of that all failed to produce. It is
    an ordinary-looking string `strptime` takes and the wire shape does not
    define, so a regression here is invisible without a pin.

    Its neighbours are pinned with it: the padded form of the same family, the
    space-padded day, and the second-position digit of a two-digit day — the
    forms whose absence made earlier corpora green for the wrong reason."""
    padded = {value for _, value in non_canonical_spellings("2026-06-05T04:07:09Z")}
    assert {
        "2026-06-05T\uff14:07:09Z",  # hour, no leading zero, one fullwidth digit
        "2026-06-05T04:\uff17:09Z",  # minute, same family
        "2026-06-05T04:07:\uff19Z",  # second, same family
        "2026-06-05T0\uff14:07:09Z",  # the padded form the earlier corpora had
        "2026-06- 5T04:07:09Z",  # `%d` pads a short day with a SPACE
    } <= padded
    teens = {value for _, value in non_canonical_spellings("2026-06-15T14:37:59Z")}
    assert "2026-06-1\uff15T14:37:59Z" in teens


def test_the_corpus_size_moves_with_the_value_and_is_never_asserted() -> None:
    """The corpus is not a fixed set of N forms, and writing N down anywhere is
    how the last three versions of this file went stale. What IS true, and what
    this pins, is the shape of the dependency: a value whose fields have
    droppable leading zeros carries strictly more spellings than one whose
    fields are all two significant digits."""
    sizes = {probe: len(non_canonical_spellings(probe)) for probe in _CORPUS_PROBES}
    assert sizes["2026-06-05T04:07:09Z"] > sizes["2026-12-31T23:59:59Z"]
    assert sizes["0001-01-01T00:00:00Z"] > sizes["2026-12-31T23:59:59Z"]


# --- the rendering half: the owner must EXPOSE what it renders with ---------


@pytest.mark.parametrize("year", [1, 99, 100, 999, 1000, 2026, 9999])
def test_render_strict_utc_pads_every_year_the_format_admits(year: int) -> None:
    """`strftime` is not the renderer of this format. glibc writes `%Y` below
    the year 1000 without padding, so a module that renders wire text with it
    emits `999-…` for the instant `0999-…` — a string its own parser refuses.

    The owner rendered correctly all along, privately. Three modules still
    render wire text on their own; the first of them can only stop guessing if
    the owner offers the rendering it already performs.
    """
    rendered = dates.render_strict_utc(datetime(year, 6, 15, 12, 30, 45))
    assert rendered == f"{year:04d}-06-15T12:30:45Z"
    assert dates.is_strict_utc(rendered)
    assert parse_strict_utc(rendered) == datetime(year, 6, 15, 12, 30, 45)


def test_render_strict_utc_is_the_inverse_of_the_parser() -> None:
    """Whatever the parser admits, the renderer reproduces byte for byte."""
    for probe in ("0001-01-01T00:00:00Z", "0999-12-31T23:59:59Z", "9999-12-31T23:59:59Z"):
        assert dates.render_strict_utc(parse_strict_utc(probe)) == probe


def test_render_strict_utc_states_its_timezone_precondition() -> None:
    """The renderer reads wall-clock fields and appends `Z`; it does not
    convert. Pinned because the function is newly public and the precondition
    is invisible at the call site: an aware value in another zone renders to a
    `Z` string naming a different instant, and the docstring is the only thing
    standing between a caller and a mislabelled signed timestamp."""
    from datetime import UTC, timedelta, timezone

    tokyo = datetime(2026, 7, 3, 0, 0, 0, tzinfo=timezone(timedelta(hours=9)))
    assert dates.render_strict_utc(tokyo) == "2026-07-03T00:00:00Z"
    assert dates.render_strict_utc(tokyo.astimezone(UTC)) == "2026-07-02T15:00:00Z"
    assert dates.render_strict_utc(tokyo) != dates.render_strict_utc(tokyo.astimezone(UTC))


def test_render_strict_utc_drops_sub_second_precision() -> None:
    """The wire shape has no place for microseconds, so they are dropped rather
    than rounded or refused. Pinned so the choice is a decision, not a
    coincidence of the format string."""
    assert dates.render_strict_utc(datetime(2026, 7, 3, 0, 0, 0, 999999)) == "2026-07-03T00:00:00Z"


@pytest.mark.parametrize("hostile", [None, 0, "2026-07-03T00:00:00Z", object()])
def test_render_strict_utc_refuses_what_is_not_a_datetime(hostile: object) -> None:
    """A non-datetime raises rather than rendering something plausible: every
    field read below is an attribute access, and a duck-typed object with the
    right attribute names would otherwise mint wire text."""
    with pytest.raises((AttributeError, TypeError)):
        dates.render_strict_utc(hostile)  # type: ignore[arg-type]
