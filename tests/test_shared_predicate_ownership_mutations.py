"""Independent mutations of the source ownership guard."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests import test_shared_predicate_ownership as guard


@pytest.mark.parametrize(
    ("language", "predicate", "suffix", "source"),
    [
        ("python", "timestamp", ".py", "CAP = 253402300799"),
        ("python", "timestamp", ".py", "CAP = 253402300799.0"),
        ("python", "timestamp", ".py", "CAP = 0x3afff4417f"),
        ("python", "timestamp", ".py", "CAP = 253402300800 - 1"),
        (
            "python",
            "receipt_id",
            ".py",
            'import re\nID = re.compile(r"^[0-7]" + r"[0-9A-HJKMNP-TV-Z]{25}$")',
        ),
        (
            "typescript",
            "timestamp",
            ".ts",
            'const note = "0x_"; export const cap = 253402300799n',
        ),
        ("typescript", "timestamp", ".ts", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".mjs", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".js", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".cjs", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".mts", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".cts", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".tsx", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".jsx", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".ts", "export const cap = 0x3afff4417fn"),
        ("typescript", "timestamp", ".ts", "export const cap = 253402300799.0"),
        ("typescript", "timestamp", ".ts", "export const cap = 2.53402300799e11"),
        (
            "typescript",
            "timestamp",
            ".ts",
            'const url = "https://example.org"; export const cap = 253402300799n',
        ),
        (
            "typescript",
            "receipt_id",
            ".mjs",
            "export const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        ),
    ],
)
def test_guard_turns_red_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
    predicate: str,
    suffix: str,
    source: str,
) -> None:
    # Seed the permitted production locations; test inputs do not come from
    # the scanner's token definitions or from the implementation under test.
    owners = {
        "src/attest/ulid.py": 'ID = "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"',
        "src/attest/dates.py": "CAP = 253402300799",
        "tools/witness_parity_cases.py": "A = 253402300799\nB = 253402300799",
        "verifiers/ts/src/ids.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        "verifiers/ts/src/dates.ts": "const cap = 253402300799",
        "site/src/bundle.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        "site/src/intake.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        "desktop/src/card.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
    }
    for name, content in owners.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(guard, "REPO_ROOT", tmp_path)
    check = guard.test_shared_predicate_definitions_do_not_multiply
    check(language, predicate)
    probe = tmp_path / f"tools/new_adapter{suffix}"
    probe.write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="import the shared predicate"):
        check(language, predicate)
    probe.unlink()
    check(language, predicate)


@pytest.mark.parametrize("prefix", ["0x", "0X", "0b", "0B", "0o", "0O"])
@settings(max_examples=40, derandomize=True)
@given(
    separators=st.integers(min_value=1, max_value=12),
    tail=st.sampled_from(["", "n", "1", "1n"]),
    quote=st.sampled_from(['"', "'", "`"]),
    before=st.booleans(),
)
def test_malformed_radix_text_does_not_abort_or_hide_other_numbers(
    prefix: str, separators: int, tail: str, quote: str, before: bool
) -> None:
    # Mutate a radix spelling at the prefix/digit boundary. Quoted text is
    # valid source even when its contents are not a numeric literal.
    malformed = prefix + "_" * separators + tail
    note = f"const note = {quote}{malformed}{quote};"
    cap = "const cap = 253402300799n;"
    source = note + cap if before else cap + note
    assert guard._script_numbers(guard._script_source(source)) == [253402300799]


@pytest.mark.parametrize(("prefix", "format_code"), [("0x", "x"), ("0b", "b"), ("0o", "o")])
@settings(max_examples=40, derandomize=True)
@given(
    uppercase=st.booleans(),
    bigint=st.booleans(),
    cut=st.integers(min_value=1, max_value=9),
)
def test_valid_radix_spellings_still_expose_the_bound(
    prefix: str, format_code: str, uppercase: bool, bigint: bool, cut: int
) -> None:
    digits = format(253402300799, format_code)
    token = prefix + digits[:cut] + "_" + digits[cut:]
    if uppercase:
        token = token.upper()
    if bigint:
        token += "n"
    assert guard._script_numbers(f"const cap = {token};") == [253402300799]


# --- the three guards added for C-217 join the harness above ----------------
#
# Every guard in the ownership file is expected to prove it turns red and
# recovers. The three below arrived without that proof, and the round that
# added them was rejected twice on exactly this question: a guard that cannot
# be shown to fail is indistinguishable from one that measures nothing.

_OWNERS_FOR_DATES = {
    "src/attest/dates.py": "import datetime\nd = datetime.datetime.strptime(s, F)\n",
    "tools/gen_vectors.py": "import datetime\nd = datetime.datetime.strptime(s, F)\n",
    "bridge/src/attest_bridge/itch_adapter.py": (
        "import datetime\nd = datetime.datetime.strptime(s, F)\n"
    ),
    "src/attest/issue.py": "r = now().strftime(F)\n",
    "src/attest/transparency.py": "r = ts().strftime(F)\n",
}


def _seed_dates_owners(tmp_path: Path) -> None:
    for name, content in _OWNERS_FOR_DATES.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


@pytest.mark.parametrize(
    ("probe_path", "source"),
    [
        # A fourth parser, in each spelling a later hand might reach for.
        ("src/attest/newmod.py", "import datetime\nd = datetime.datetime.strptime(s, F)\n"),
        # The deferred binding: an attribute that is never a callee.
        ("src/attest/newmod.py", "import datetime\np = datetime.datetime.strptime\n"),
        ("tools/new_tool.py", "import datetime\nd = datetime.datetime.strptime(s, F)\n"),
    ],
)
def test_the_parser_guard_turns_red_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe_path: str, source: str
) -> None:
    _seed_dates_owners(tmp_path)
    monkeypatch.setattr(guard, "REPO_ROOT", tmp_path)
    check = guard.test_the_wire_timestamp_is_parsed_in_exactly_one_place
    check()
    probe = tmp_path / probe_path
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match=r"parsed in one place|import it instead"):
        check()
    probe.unlink()
    check()


@pytest.mark.parametrize(
    "source",
    [
        # The plain call.
        "r = parsed.strftime(F)\n",
        # The three spellings a call-only criterion walks straight past. Each
        # was measured green against the earlier version of the guard, with the
        # low-year defect live.
        "render = parsed.strftime\nr = render(F)\n",
        'r = f"{parsed:%Y-%m-%dT%H:%M:%SZ}"\n',
        'r = getattr(parsed, "strftime")(F)\n',
    ],
)
def test_the_renderer_guard_turns_red_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    _seed_dates_owners(tmp_path)
    monkeypatch.setattr(guard, "REPO_ROOT", tmp_path)
    check = guard.test_canonical_wire_text_is_rendered_only_where_it_is_pinned
    check()
    probe = tmp_path / "src/attest/newmod.py"
    probe.write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="canonicality is decided by"):
        check()
    probe.unlink()
    check()


def test_the_renderer_guard_ignores_prose_and_percentage_formats(tmp_path: Path) -> None:
    """The criterion reads the AST, never the word: this file and the package
    both DISCUSS `strftime` at length, and a guard that could not tell an
    explanation from a call would be impossible to keep green."""
    assert guard._strftime_calls('"""never call strftime here"""\n') == 0
    assert guard._strftime_calls('r = f"{share:.1%}"\n') == 0
    assert guard._strftime_calls('r = f"{d:%Y}"\n') == 1


def test_the_semantic_guard_turns_red_on_a_predicate_it_was_never_told_about() -> None:
    """The point of the semantic guard is that it is not a list.

    A predicate added tomorrow must be caught without anyone remembering to
    register it, so the mutation here does not touch the guard's own source: it
    puts a divergent predicate into a package module and asks the guard to find
    it. Measured against the hand-listed version of the guard, this mutant was
    green.
    """
    from datetime import datetime as _datetime

    from attest import views

    def _valid_signed_at(value: object) -> bool:
        if not isinstance(value, str):
            return False
        own = str.__str__(value)
        try:
            parsed = _datetime.strptime(own, "%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            return False
        return f"{parsed:%Y-%m-%dT%H:%M:%SZ}" == own

    _valid_signed_at.__module__ = views.__name__
    check = guard.test_every_canonicality_predicate_agrees_with_the_owner
    check()
    views._valid_signed_at = _valid_signed_at  # type: ignore[attr-defined]
    try:
        assert ("views._valid_signed_at", _valid_signed_at) in guard._canonicality_predicates(), (
            "discovery did not reach the injected predicate; the mutation proves nothing"
        )
        with pytest.raises(AssertionError, match="decides canonicality differently"):
            check()
    finally:
        del views._valid_signed_at  # type: ignore[attr-defined]
    check()


def test_the_semantic_guard_turns_red_on_a_predicate_written_as_a_method() -> None:
    """The same defect, spelled so that NEITHER guard's usual handle applies.

    The mutant above is a module-level function whose rendering goes through a
    format spec, so the syntactic guard catches it too. This one removes both
    handles at once: the predicate is a `@staticmethod`, which `vars(module)`
    never yields, and the rendering is built by hand out of `zfill`, so there is
    no `strftime` and no format spec for the syntactic guard to count.

    Measured before discovery was taught to follow classes: 45 passed, exit 0,
    with the predicate disagreeing with the owner on `0099-12-31T23:59:59Z` and
    living in the tree. Both guards green, the defect they exist to stop alive.

    The spelling is not exotic — writing the zero-padding out by hand is exactly
    how this repository's own replacement oracle is built, so it is the shape a
    reader of these tests is most likely to copy into production code.
    """
    from attest import dates, views

    class _TimestampPolicy:
        @staticmethod
        def spells_canonically(value: str) -> bool:
            try:
                parsed = dates.parse_strict_utc(value)
            except Exception:
                return False
            rendered = (
                str(parsed.year).zfill(2)
                + f"-{parsed.month:02d}-{parsed.day:02d}"
                + f"T{parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}Z"
            )
            return rendered == value

    # Both the class and the function it holds must claim the module they are
    # injected into: discovery keeps only callables the module actually owns, and
    # a predicate written there for real would carry that module on both.
    _TimestampPolicy.__module__ = views.__name__
    _TimestampPolicy.spells_canonically.__module__ = views.__name__
    check = guard.test_every_canonicality_predicate_agrees_with_the_owner
    check()
    views._TimestampPolicy = _TimestampPolicy  # type: ignore[attr-defined]
    try:
        reached = [name for name, _ in guard._canonicality_predicates()]
        assert "views._TimestampPolicy.spells_canonically" in reached, (
            "discovery did not reach a predicate written as a method; "
            f"the mutation proves nothing. Found {sorted(reached)}"
        )
        with pytest.raises(AssertionError, match="decides canonicality differently"):
            check()
    finally:
        del views._TimestampPolicy  # type: ignore[attr-defined]
    check()
