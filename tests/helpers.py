"""Shared test payload builder for attest receipt payload tests."""

from __future__ import annotations

import _strptime
import hashlib
import re
import unicodedata
from datetime import datetime
from functools import cache
from itertools import product
from re import _compiler as _re_compiler
from re import _parser as _re_parser
from typing import Any

from attest.keys import b64u

# Fixed 32 zero-bytes commitment/pubkey material — deterministic, test-only.
_COMMITMENT = b64u(bytes(32))

_LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-legal-text-v1").hexdigest()
_MIRROR_POLICY_SHA256 = hashlib.sha256(b"attest-test-mirror-policy-v1").hexdigest()
_ARTIFACT_SHA256 = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()


def _base_payload() -> dict[str, Any]:
    """The reference example payload (see docs/spec/attest-v0.1.md)."""
    return {
        "attest_version": "0.1",
        "receipt_id": "01J1V5B4M9Z8QWERTY12345678",
        "issued_at": "2026-07-02T14:30:00Z",
        "supersedes": None,
        "issuer": {
            "id": "store.example.com",
            "display_name": "Example Games Store",
        },
        "buyer": {
            "commitment": _COMMITMENT,
            "identifier_type": "issuer-account",
            "pubkey": None,
        },
        "work": {
            "title": "Example Game",
            "publisher": "Example Publisher srl",
            "edition": "Deluxe",
            "identifiers": {"issuer_sku": "EXG-001"},
            "artifact_series": "store.example.com/works/EXG-001",
            "artifacts": [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "example-game-1.0-setup.exe",
                    "size_bytes": 734003200,
                    "sha256": _ARTIFACT_SHA256,
                }
            ],
        },
        "license": {
            "grant": "perpetual",
            "revocability": "none",
            "transferable": False,
            "drm": "drm-free",
            "terms_uri": "https://store.example.com/attest/license-templates/standard-v1",
            "legal_text_sha256": _LEGAL_TEXT_SHA256,
            "jurisdiction_flags": {"eu_usedsoft_asserted": False},
        },
        "survivability": {
            "redownload_right": True,
            "mirror_policy_uri": "https://store.example.com/attest/mirror-policy-v1",
            "mirror_policy_sha256": _MIRROR_POLICY_SHA256,
            "end_of_life": "artifacts-remain-redownloadable",
            "eol_commitment_uri": None,
            "eol_commitment_sha256": None,
        },
    }


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def make_payload(**overrides: Any) -> dict[str, Any]:
    """Return the §3.1 example payload as a dict, deep-merged with `overrides`.

    Nested dict overrides (e.g. `license={"revocability": "policy"}`) merge into
    the corresponding base dict instead of replacing it wholesale; non-dict
    values (including lists) replace the base value outright.
    """
    return _deep_merge(_base_payload(), overrides)


# --- non-canonical spellings of a strict UTC timestamp -----------------------

# `%Y-%m-%dT%H:%M:%SZ` is not the shape `strptime` enforces, and the difference
# is not a list of curiosities anybody could be asked to remember. It is a
# STRUCTURE the parser publishes about itself: `_strptime.TimeRE()` carries, per
# directive, the alternation of spellings that directive accepts, and it
# compiles the whole format case-insensitively. On CPython 3.12 it reads
#
#     %Y -> (?P<Y>\d\d\d\d)
#     %m -> (?P<m>1[0-2]|0[1-9]|[1-9])
#     %d -> (?P<d>3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9])
#     %H -> (?P<H>2[0-3]|[0-1]\d|\d)
#     %M -> (?P<M>[0-5]\d|\d)
#     %S -> (?P<S>6[0-1]|[0-5]\d|\d)
#
# — and that block is a comment, not the corpus. Everything below reads
# `TimeRE()` at import time, so a CPython that widens, narrows or reorders a
# field changes what this module produces without anyone editing a list.
#
# WHY IT IS BUILT THIS WAY. Three hand-made constructions in a row missed the
# same family, the third being a brute-force derivation written specifically to
# prove that nothing was missing. Each of them applied a non-ASCII digit only to
# the ZERO-PADDED spelling of a field. But `%H`, `%M` and `%S` end their
# alternation with a bare `\d` — one character, Unicode-aware — so
# `2026-06-05T\uff14:07:09Z` parses, names the same instant, and appeared in no
# corpus. The remedy is not three more entries: a corpus whose forms are
# enumerated by a person shares that person's blind spots, and the derivation
# meant to audit it shared them too because it was written from the corpus.
#
# So nobody writes the forms here. Per field, the declared branches are asked
# which ASCII spellings of that field's VALUE they accept; every accepted
# spelling — padded, unpadded, space-padded alike, with no case singled out —
# is then crossed with the script dimension, one position at a time and whole,
# and with the case dimension on each literal separator. The oracle at the
# bottom of `non_canonical_spellings` throws away whatever the parser refuses,
# so the generator never has to know in advance which field admits what.
#
# The number of spellings is therefore a MEASURED OUTPUT, not a constant: it
# depends on the value (a day of 5 has a space-padded form, a day of 15 has a
# second digit that may go non-ASCII, a second of 59 has neither), and it moves
# when CPython moves. No test asserts it, and none should.
#
# The corpus lives here, once, because five test modules need the same hostile
# inputs. A list restated per module drifts, and the family belongs to
# `strptime`, not to any one caller.

_STRICT_UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"

# The authority, read once.
_TIME_RE = _strptime.TimeRE()
_FORMAT_RE = _TIME_RE.compile(_STRICT_UTC_FMT)

# Cosmetic only — the readable half of a case name. A directive missing from
# this map still gets its cases, named by its group letter.
_FIELD_NAMES = {"Y": "year", "m": "month", "d": "day", "H": "hour", "M": "minute", "S": "second"}

# `_strptime` turns a matched field into a number with `int()`, so the
# characters worth offering around a numeral are the ones `int()` itself
# tolerates: decimal digits, a sign, the digit-group underscore, whitespace.
# Which of them a given field accepts is the branch's business, not ours.
_INT_ALPHABET = "0123456789+-_ \t\n\r\v\f"

# Two decimal scripts, so the evidence stays that this is about the `Nd`
# CATEGORY and not about one alphabet. The exhaustive sweep over all Unicode
# decimal digits belongs to the owner's own tests in `tests/test_dates.py`;
# here the script is a dimension to cross, not a set to enumerate.
_SCRIPT_ZEROS = (("fullwidth", "\uff10"), ("devanagari", "\u0966"))


@cache
def _branch_matchers(directive: str) -> tuple[tuple[re.Pattern[str], int], ...]:
    """The alternatives `strptime` declares for one directive, each compiled.

    `TimeRE()[directive]` is a named group whose body is an alternation; the
    `re` module's own parser splits it and its own compiler turns each
    alternative back into a matcher, so a CPython that adds, drops or reorders
    a branch changes this tuple with nobody editing anything. The width comes
    from the same parse: every alternative here is a flat run of
    single-character items, and the assertion says so out loud, so a future
    pattern built out of anything else — a repeat, a group, a backreference —
    fails here instead of quietly generating half a family.
    """
    parsed = _re_parser.parse(_TIME_RE[directive])
    assert len(parsed.data) == 1 and parsed.data[0][0] is _re_parser.SUBPATTERN, parsed.data
    body = parsed.data[0][1][3]
    if len(body.data) == 1 and body.data[0][0] is _re_parser.BRANCH:
        alternatives = tuple(body.data[0][1][1])
    else:
        alternatives = (body,)
    single_char = {_re_parser.LITERAL, _re_parser.NOT_LITERAL, _re_parser.IN, _re_parser.ANY}
    for alternative in alternatives:
        for opcode, _ in alternative.data:
            assert opcode in single_char, (directive, opcode)
    return tuple(
        (_re_compiler.compile(alternative, re.IGNORECASE), len(alternative.data))
        for alternative in alternatives
    )


@cache
def _numerals(width: int, value: int) -> tuple[str, ...]:
    """Every ASCII string of `width` characters that `int()` reads as `value`.

    Brute force over the alphabet `int()` accepts, not a construction: asking
    for "the padded one and the unpadded one" is exactly the step that has
    produced three corpora with the same hole. `05`, `5`, ` 5`, `+5` and `5\\n`
    all arrive here on the same footing, and the branch decides.
    """
    found = []
    for combination in product(_INT_ALPHABET, repeat=width):
        text = "".join(combination)
        try:
            if int(text) == value:
                found.append(text)
        except ValueError:
            continue
    return tuple(found)


@cache
def _field_shapes(directive: str, value: int) -> tuple[str, ...]:
    """Every ASCII spelling of `value` that some declared branch of `directive`
    accepts — the canonical one included, since the script dimension is applied
    to it as well."""
    shapes = {
        text
        for matcher, width in _branch_matchers(directive)
        for text in _numerals(width, value)
        if matcher.fullmatch(text)
    }
    return tuple(sorted(shapes))


def _script_variants(shape: str) -> tuple[tuple[str, str], ...]:
    """`(script, text)` for `shape` rewritten with non-ASCII decimal digits:
    one position at a time, and the whole field.

    Applied to EVERY shape a branch accepts, with no case singled out. That
    uniformity is the point: the family this corpus kept missing lives on the
    composition of a dropped leading zero with a non-ASCII digit, and a
    dimension applied to only some shapes cannot reach a composition.
    """
    variants: list[tuple[str, str]] = []
    for script, zero in _SCRIPT_ZEROS:
        table = str.maketrans("0123456789", "".join(chr(ord(zero) + d) for d in range(10)))
        for index in range(len(shape)):
            variants.append(
                (script, shape[:index] + shape[index].translate(table) + shape[index + 1 :])
            )
        variants.append((script, shape.translate(table)))
    return tuple((script, text) for script, text in variants if text != shape)


def _shape_of(text: str) -> str:
    """`text` with every non-ASCII decimal digit reduced to one sentinel — the
    readable half of a case name, and stable across scripts."""
    return "".join("#" if not c.isascii() and unicodedata.category(c) == "Nd" else c for c in text)


@cache
def non_canonical_spellings(canonical: str) -> tuple[tuple[str, str], ...]:
    """`(name, spelling)` pairs naming the SAME instant as `canonical`.

    Every spelling is accepted by a bare `datetime.strptime(value,
    "%Y-%m-%dT%H:%M:%SZ")` and renders back to `canonical`, yet differs from it
    byte for byte. Callers assert that precondition per case instead of
    trusting it: a case `strptime` already refuses would prove nothing about
    the guard under test.

    The family is DERIVED from the structure `strptime` publishes about itself
    (see the comment above this section), never listed. Two dimensions are
    crossed over every shape the parser's own branches accept for the value —
    the decimal script, per position and whole-field, and the case of each
    literal separator, which `TimeRE` compiles with `IGNORECASE`. The oracle
    below is the only filter: `strptime` accepts it, it names the same instant,
    and it differs from `canonical`. Whatever fails that is dropped in silence,
    which is what frees the generator from having to know that `%m` has no
    `\\d` branch while `%H` does.

    How many spellings come back is a property of the value and of the
    installed CPython, not a number this repository owns.
    `tests/test_dates.py` holds the corpus to the parser's declared branches;
    it does not hold it to a count.
    """
    expected = datetime.strptime(canonical, _STRICT_UTC_FMT)
    match = _FORMAT_RE.match(canonical)
    if match is None or match.end() != len(canonical):
        raise ValueError(f"{canonical!r} is not a strict UTC timestamp")

    spellings: dict[str, str] = {}

    def offer(name: str, candidate: str) -> None:
        if candidate == canonical:
            return
        try:
            if datetime.strptime(candidate, _STRICT_UTC_FMT) != expected:
                return
        except ValueError:
            return
        previous = spellings.setdefault(name, candidate)
        assert previous == candidate, (name, previous, candidate)

    numeric_positions: set[int] = set()
    for directive in _FORMAT_RE.groupindex:
        start, end = match.span(directive)
        numeric_positions |= set(range(start, end))
        field = _FIELD_NAMES.get(directive, directive)
        for shape in _field_shapes(directive, int(canonical[start:end])):
            offer(f"{field}:{_shape_of(shape)}", canonical[:start] + shape + canonical[end:])
            for script, text in _script_variants(shape):
                offer(
                    f"{field}:{_shape_of(text)}:{script}",
                    canonical[:start] + text + canonical[end:],
                )

    for index, char in enumerate(canonical):
        if index in numeric_positions:
            continue
        for variant in (char.lower(), char.upper()):
            offer(
                f"separator:{index}:{variant}",
                canonical[:index] + variant + canonical[index + 1 :],
            )

    assert len(set(spellings.values())) == len(spellings), "two names for one spelling"
    return tuple(sorted(spellings.items()))


# --- an input the `isinstance` gate cannot refuse -----------------------------


class ForgedStr:
    """Not a `str`, and `isinstance(x, str)` answers True anyway.

    Every other hostile timestamp class in this suite is a `str` SUBCLASS —
    `_RaisingEqStr`, `_DenyingEqStr`, `_LyingStr`, `_RaisingStr`, `_BadReprStr`,
    `_ShadowedReadStr`, `_RaisingEq`, `_LyingEq`, `_DenyingEq`,
    `_AlwaysEqualId` — because the family they were written for is "a string
    that misbehaves": a hostile `__eq__`, a lying `__str__`, a shadowed read.
    A corpus grown around one attack inherits that attack's perimeter, and the
    question that leaves it is not "which other misbehaving string is missing"
    but "what if it were not a string at all".

    This is that input, and it lives here rather than in one test module
    because it is a property of every `isinstance(value, str)` gate in the
    package, not of any one caller. `isinstance` consults `__class__` when the
    exact type check fails, so this passes every such gate while `str.__str__`
    — the own-data spelling those gates reach for immediately afterwards —
    raises `TypeError` on it. A predicate that takes its own data OUTSIDE its
    `try` therefore answers with an exception instead of a verdict.
    """

    __slots__ = ()

    @property
    def __class__(self) -> type:  # type: ignore[override]
        return str
