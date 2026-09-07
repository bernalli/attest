"""Shared test payload builder for attest receipt payload tests."""

from __future__ import annotations

import hashlib
from datetime import datetime
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

# `%Y-%m-%dT%H:%M:%SZ` is not the shape `strptime` enforces. Its numeric fields
# are `\d`-class regexes, so every Unicode decimal digit spells the same
# number; its literal separators match case-insensitively, so `t` and `z` pass;
# and each field accepts one OR two digits, so a dropped leading zero passes.
# The TypeScript core refuses all of them, which is what makes this family a
# cross-core question rather than a tidiness one.
#
# The corpus lives here, once, because four test modules need the same hostile
# inputs. A list restated per module drifts, and the family belongs to
# `strptime`, not to any one caller.

_FULLWIDTH_DIGITS = str.maketrans(
    "0123456789", "\uff10\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18\uff19"
)
_DEVANAGARI_DIGITS = str.maketrans(
    "0123456789", "\u0966\u0967\u0968\u0969\u096a\u096b\u096c\u096d\u096e\u096f"
)

_STRICT_UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"

# (name, offset, width) of every numeric field of the wire shape, in order.
_FIELDS: tuple[tuple[str, int, int], ...] = (
    ("year", 0, 4),
    ("month", 5, 2),
    ("day", 8, 2),
    ("hour", 11, 2),
    ("minute", 14, 2),
    ("second", 17, 2),
)


def _candidate_spellings(canonical: str) -> tuple[tuple[str, str], ...]:
    """Every mutation worth ASKING the parser about \u2014 the superset, unfiltered.

    Which of these `strptime` actually accepts depends on the VALUE, because
    its field patterns are alternations and only some branches carry a `\\d`
    class or a padding alternative (CPython 3.12: `%d` is
    `3[0-1]|[1-2]\\d|0[1-9]|[1-9]| [1-9]`, so a day of 1-9 may be written with a
    LEADING SPACE and a day of 10-29 may carry a non-ASCII digit in its second
    position, while `%m` has no `\\d` branch at all and accepts neither).
    Enumerating that by hand is what produced a corpus with a hole in it; the
    filter in `non_canonical_spellings` decides instead.
    """
    candidates: list[tuple[str, str]] = []

    def mutate(name: str, start: int, width: int, replacement: str) -> None:
        candidates.append((name, canonical[:start] + replacement + canonical[start + width :]))

    for field, start, width in _FIELDS:
        raw = canonical[start : start + width]
        # A dropped leading zero, and the space that `%d` pads a short day with.
        mutate(f"unpadded_{field}", start, width, str(int(raw)))
        mutate(f"space_padded_{field}", start, width, " " + str(int(raw)))
        # A single non-ASCII decimal digit, at each position in turn: `\d`
        # matches every Unicode Nd character, and which positions reach a `\d`
        # branch is the parser's business, not ours.
        for index in range(width):
            mutate(
                f"non_ascii_digit_{field}_{index}",
                start,
                width,
                raw[:index] + raw[index].translate(_FULLWIDTH_DIGITS) + raw[index + 1 :],
            )
        # The whole field in one non-ASCII script, twice, to keep the evidence
        # that this is about the `Nd` category and not about one alphabet.
        for script, table in (("fullwidth", _FULLWIDTH_DIGITS), ("devanagari", _DEVANAGARI_DIGITS)):
            mutate(f"{script}_{field}", start, width, raw.translate(table))

    # The two literals whose match is case-insensitive.
    candidates.append(("lowercase_t", canonical[:10] + "t" + canonical[11:]))
    candidates.append(("lowercase_z", canonical[:-1] + "z"))
    return tuple(candidates)


def non_canonical_spellings(canonical: str) -> tuple[tuple[str, str], ...]:
    """`(name, spelling)` pairs naming the SAME instant as `canonical`.

    Every spelling is accepted by a bare `datetime.strptime(value,
    "%Y-%m-%dT%H:%M:%SZ")` and renders back to `canonical`, yet differs from it
    byte for byte. Callers assert that precondition per case instead of
    trusting it: a case `strptime` already refuses would prove nothing about
    the guard under test.

    The family is decided by ASKING the parser, not by listing what its
    documentation suggests. The previous hand-written list named ten forms and
    missed two whole families \u2014 a space-padded day and a non-ASCII digit
    anywhere outside the year \u2014 which is the failure mode a hand-written list
    has: it shares the blind spots of whoever wrote it, and a guard weak enough
    to let those through still passed every test. `tests/test_dates.py`
    re-derives the family by brute force and fails if this function misses
    anything, so the corpus cannot silently shrink back.
    """
    expected = datetime.strptime(canonical, _STRICT_UTC_FMT)
    spellings: list[tuple[str, str]] = []
    for name, candidate in _candidate_spellings(canonical):
        if candidate == canonical:
            continue
        try:
            if datetime.strptime(candidate, _STRICT_UTC_FMT) != expected:
                continue
        except ValueError:
            continue
        spellings.append((name, candidate))
    return tuple(spellings)
