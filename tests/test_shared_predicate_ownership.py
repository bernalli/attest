"""Shared core predicates must not acquire new source definitions.

Scan recursively, including new and untracked modules and tools. Test oracles
retain independent expectations; dependencies and generated builds are excluded.
Counting occurrences also rejects a second declaration inside the owner itself.
"""

from __future__ import annotations

import ast
import os
import re
from collections import Counter
from decimal import Decimal
from pathlib import Path

import pytest

from tests.helpers import non_canonical_spellings
from tests.test_shared_predicate_parity import EXPECTED_BOUND, EXPECTED_ULID_PATTERN

REPO_ROOT = Path(__file__).resolve().parents[1]
_EXCLUDED_DIRS = {"node_modules", "dist", "__pycache__", "tests", "test", "e2e"}


def _sources(suffixes: tuple[str, ...]) -> list[Path]:
    paths = []
    for directory, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in _EXCLUDED_DIRS)
        for name in sorted(files):
            if name.endswith(suffixes) and not name.endswith(
                tuple(
                    f".{kind}{suffix}" for kind in ("test", "spec") for suffix in _SCRIPT_SUFFIXES
                )
            ):
                paths.append(Path(directory) / name)
    return paths


def _python_literals(source: str) -> list[str | int | float]:
    tree = ast.parse(source)
    prose = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }

    def literal(node: ast.AST) -> str | int | float | None:
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                return value
        if isinstance(node, ast.BinOp):
            left, right = literal(node.left), literal(node.right)
            if isinstance(node.op, ast.Add):
                if isinstance(left, str) and isinstance(right, str):
                    return left + right
                if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    return left + right
            if isinstance(node.op, ast.Sub):
                if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    return left - right
        return None

    values = []
    for node in ast.walk(tree):
        if id(node) not in prose and (value := literal(node)) is not None:
            values.append(value)
    return values


_SCRIPT_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
# Quoted text must win over comment delimiters: an URL is not a line comment.
_SCRIPT_COMMENTS = re.compile(
    r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)"
    r"|/\*.*?\*/|//[^\n]*",
    re.DOTALL,
)
# Every radix prefix needs a real digit before any separator: `0x_` is not a
# number in any of these languages, and `int("0x", 0)` would abort the scan.
_SCRIPT_NUMBERS = re.compile(
    r"(?<![\w.])(?:0[xX][0-9a-fA-F][0-9a-fA-F_]*n?|0[bB][01][01_]*n?|"
    r"0[oO][0-7][0-7_]*n?|"
    r"[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]+)?n?)(?![\w.])"
)


def _script_source(source: str) -> str:
    return _SCRIPT_COMMENTS.sub(lambda match: match.group(1) or " ", source)


def _script_numbers(source: str) -> list[int | Decimal]:
    values: list[int | Decimal] = []
    for token in _SCRIPT_NUMBERS.findall(source):
        token = token.replace("_", "").removesuffix("n")
        values.append(
            int(token, 0) if token.lower().startswith(("0x", "0b", "0o")) else Decimal(token)
        )
    return values


@pytest.mark.parametrize("language", ["python", "typescript"])
@pytest.mark.parametrize("predicate", ["receipt_id", "timestamp"])
def test_shared_predicate_definitions_do_not_multiply(language: str, predicate: str) -> None:
    owners = {
        ("python", "receipt_id"): {"src/attest/ulid.py": 1},
        ("python", "timestamp"): {
            "src/attest/dates.py": 1,
            # Independent boundary inputs, not validator declarations.
            "tools/witness_parity_cases.py": 2,
        },
        ("typescript", "receipt_id"): {
            "verifiers/ts/src/ids.ts": 1,
            # Existing application guards: the package does not export its
            # internal predicate. Pin their locations and counts as well.
            "site/src/bundle.ts": 1,
            "site/src/intake.ts": 1,
            "desktop/src/card.ts": 1,
        },
        ("typescript", "timestamp"): {"verifiers/ts/src/dates.ts": 1},
    }
    found: Counter[str] = Counter()
    needle = EXPECTED_ULID_PATTERN.removeprefix("^").removesuffix("$")
    for path in _sources((".py",) if language == "python" else _SCRIPT_SUFFIXES):
        source = path.read_text(encoding="utf-8")
        if language == "python":
            literals = _python_literals(source)
            count = sum(
                isinstance(value, str) and needle in value
                if predicate == "receipt_id"
                else value == EXPECTED_BOUND
                for value in literals
            )
        else:
            source = _script_source(source)
            if predicate == "receipt_id":
                count = source.count(needle)
            else:
                count = sum(number == EXPECTED_BOUND for number in _script_numbers(source))
        if count:
            found[path.relative_to(REPO_ROOT).as_posix()] = count
    assert dict(found) == owners[language, predicate], (
        f"{language} {predicate}: import the shared predicate instead of restating it; "
        f"found {dict(found)}"
    )


def _strptime_references(source: str) -> int:
    """References to `.strptime`, counted from the AST — the call AND the
    binding that defers one.

    Counting the WORD would count prose: this package's docstrings name
    `strptime` a dozen times to explain what the owner refuses, and a guard
    that cannot tell an explanation from a call is a guard nobody can keep
    green.

    Counting only `ast.Call` would miss this repository's own idiom for
    deferring a parser. `_parse_date = parse_strict_utc` is how three modules
    name the owner today, so `_parse_date = datetime.datetime.strptime` is the
    shape a fourth copy would arrive in — an attribute that is never the
    callee of a call node, and therefore invisible to a call-only guard.
    Measured: a probe module written that way kept this test green.
    Every file below references `.strptime` exactly as often as it calls it,
    so the wider criterion costs nothing and closes the alias.
    """
    return sum(
        1
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Attribute) and node.attr == "strptime"
    )


def test_the_wire_timestamp_is_parsed_in_exactly_one_place() -> None:
    """One parser for the signed UTC wire shape, in the module that owns it.

    Four modules declared their own, plus three inline calls, and the copy that
    guarded the refund window did not know the other six existed — which is how
    the two cores came to disagree about which bytes name an instant. The count
    is the criterion: it does not depend on how many tests are green.

    The two files outside `src/attest/` are not verdict paths and are pinned by
    name and count rather than excluded by pattern: a corpus generator doing
    clock arithmetic, and a merchant adapter reading a DIFFERENT wire format.
    A third one appearing anywhere turns this red.
    """
    owners = {
        "src/attest/dates.py": 1,
        "tools/gen_vectors.py": 1,
        "bridge/src/attest_bridge/itch_adapter.py": 1,
    }
    found = {
        path.relative_to(REPO_ROOT).as_posix(): references
        for path in _sources((".py",))
        if (references := _strptime_references(path.read_text(encoding="utf-8")))
    }
    assert found == owners, (
        "the strict UTC wire shape is parsed in one place, `attest.dates`; "
        f"import it instead of restating it. Found {found}"
    )


def _strftime_calls(source: str) -> int:
    """Calls to `.strftime(...)`, counted from the AST."""
    return sum(
        1
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "strftime"
    )


def test_canonical_wire_text_is_rendered_only_where_it_is_pinned() -> None:
    """`strftime` never decides whether a timestamp is canonical, anywhere.

    Four modules used to decide it by re-serializing the parsed instant and
    comparing: glibc renders `%Y` below the year 1000 without padding, so all
    four refused 999 canonical years the TypeScript core accepts, and the
    command that signs a record disagreed with the command that reads it.

    This counts CALLS, not the shape of the expression around them. An earlier
    version of this guard matched `<call> == <value>` and was green on the very
    same defect written across two statements — which is how it was written in
    `cli.py` until the commit that removed it. A criterion that misses the most
    recent spelling of the bug it exists to prevent is not a criterion.

    The two survivors RENDER text and never read it back; they are pinned by
    path and count, not excluded by pattern, so a third call — or a second one
    in a pinned file — is red. Both render `now()`, whose year has four digits,
    so they are correct BY ACCIDENT rather than by construction: that is the
    emission half of C-217 and it is still open. `views.py` was the third and
    is gone — it renders through `dates.render_strict_utc`, which is why that
    function is public.
    """
    renderers = {
        "src/attest/issue.py": 1,
        "src/attest/transparency.py": 1,
    }
    found = {
        path.relative_to(REPO_ROOT).as_posix(): calls
        for path in _sources((".py",))
        if path.is_relative_to(REPO_ROOT / "src" / "attest")
        and (calls := _strftime_calls(path.read_text(encoding="utf-8")))
    }
    assert found == renderers, (
        "canonicality is decided by `attest.dates`, which renders the year "
        f"explicitly; `strftime` does not pad `%Y` below 1000. Found {found}"
    )


def test_every_canonicality_predicate_agrees_with_the_owner() -> None:
    """The structural guard above says nobody WRITES the defect; this says
    nobody HAS it, whatever they wrote.

    A shape can always be rewritten — one statement into two, a helper, a
    loop — so a guard that reads syntax can be evaded by accident. This one
    reads behaviour: every predicate in the package that answers "is this the
    canonical spelling" must answer exactly what the owner answers, on a corpus
    that includes the years where the two used to differ.
    """
    from attest import dates, transfer, views

    probes = [f"{year:04d}-06-15T12:30:45Z" for year in (1, 99, 100, 999, 1000, 2026, 9999)]
    probes += [
        spelling for probe in probes[:] for _name, spelling in non_canonical_spellings(probe)
    ]
    probes += ["", "not-a-date", "2026-13-01T00:00:00Z", "2026-06-15T12:30:45"]

    disagreements = [
        (probe, name, predicate(probe))
        for probe in probes
        for name, predicate in (
            ("views._round_trips", views._round_trips),
            ("transfer._valid_utc_timestamp", transfer._valid_utc_timestamp),
        )
        if predicate(probe) != dates.is_strict_utc(probe)
    ]
    assert not disagreements, (
        f"a predicate decides canonicality differently from `attest.dates`: {disagreements[:5]}"
    )
