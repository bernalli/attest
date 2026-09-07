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
    return sum(1 for node in ast.walk(ast.parse(source)) if _names_attribute(node, "strptime"))


def _names_attribute(node: ast.AST, attribute: str) -> bool:
    """Whether `node` reaches `attribute` by name — as an attribute access, or
    as a `getattr` naming it as a constant. Shared by both counters below so
    the two cannot drift apart: the parser guard closed the deferred-binding
    hole and the renderer guard did not, and a defect written in the spelling
    one of them misses is a defect neither reports."""
    if isinstance(node, ast.Attribute) and node.attr == attribute:
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == attribute
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
    """Every way this source can reach `strftime`, counted from the AST.

    Symmetric with `_strptime_references` above, and for the same reason. An
    earlier version counted only `ast.Call` nodes whose callee was the
    attribute, which three ordinary spellings walk straight past — measured,
    each with the low-year defect live in `views._round_trips`:

    * `render = parsed.strftime` then `render(fmt)` — the attribute is never a
      callee, exactly the deferred binding `_strptime_references` exists to
      catch;
    * `f"{parsed:%Y-%m-%dT%H:%M:%SZ}"` — `datetime.__format__` IS `strftime`,
      and this is the spelling a reader reaches for by ACCIDENT, which is the
      whole reason a second, semantic guard was written;
    * `getattr(parsed, "strftime")(fmt)`.

    So: any attribute named `strftime`, any `getattr` naming it as a constant,
    and any format spec carrying a `%` directive applied to an interpolated
    value. Prose is unaffected — this reads the AST, never the word.
    """
    tree = ast.parse(source)
    count = 0
    for node in ast.walk(tree):
        if _names_attribute(node, "strftime"):
            count += 1
        elif isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            spec = "".join(
                part.value
                for part in ast.walk(node.format_spec)
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            # `%` followed by a letter is a strftime directive; a bare
            # trailing `%` is the percentage presentation type (`f"{x:.1%}"`)
            # and has nothing to do with dates.
            if re.search(r"%[a-zA-Z]", spec):
                count += 1
    return count


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


def _canonicality_predicates() -> list[tuple[str, object]]:
    """Every canonicality predicate in the package, DISCOVERED, never listed.

    A hand-written list is the one thing this guard must not be: a predicate
    added tomorrow would be born exempt, which is exactly the state that let
    four copies of the same round trip drift apart. Measured before this was
    written: a fourth predicate carrying the low-year defect, added to
    `authority.py`, left the whole file green.

    A callable qualifies by BEHAVIOUR, not by name or module: it takes one
    argument, is ANNOTATED to return a bool, says yes to plainly canonical
    modern instants and no to plainly non-instants. Anything answering that way
    is deciding this question, whatever it is called; anything else (shape
    checks, unrelated string predicates) fails the probe and is not collected.

    The annotation filter is not cosmetic and is not an optimisation: without
    it this sweep CALLS every one-argument function in the package, and one of
    them is `cli.main`, which parses the probe as `sys.argv` and raises
    `SystemExit` — measured, it took the whole test run down. Restricting to
    `-> bool` keeps the sweep to predicates; the `BaseException` guard below
    keeps a future non-pure one from doing the same thing again.
    """
    import importlib
    import inspect
    import pkgutil
    import typing
    from types import ModuleType

    import attest

    yes = ("2026-06-15T12:30:45Z", "1970-01-01T00:00:00Z")
    no = ("", "not-a-date", "2026-13-01T00:00:00Z")
    found: list[tuple[str, object]] = []

    def candidates(module: ModuleType) -> list[tuple[str, object]]:
        """Module-level functions AND functions reached through a class.

        Iterating `vars(module)` alone finds only module-level functions, so a
        predicate written as a method is invisible to discovery. Not a
        hypothetical: measured against this guard as first written, a
        `@staticmethod` carrying the low-year defect — with the rendering
        spelled by hand, so the syntactic guard had nothing to count — left the
        file GREEN: 45 passed, the defect live in the tree, both guards
        satisfied.

        The two guards are complementary by design: one says nobody WRITES the
        defect, the other that nobody HAS it whatever they wrote. The second is
        the half that must hold regardless of spelling, and it cannot if
        discovery never reaches the callable. So discovery follows classes too,
        and the behaviour probe below decides exactly as it does for a plain
        function.
        """
        out: list[tuple[str, object]] = []
        for name, obj in vars(module).items():
            if inspect.isfunction(obj):
                out.append((name, obj))
                continue
            if inspect.isclass(obj) and obj.__module__ == module.__name__:
                for attribute, value in vars(obj).items():
                    if isinstance(value, staticmethod | classmethod):
                        value = value.__func__
                    if inspect.isfunction(value):
                        out.append((f"{name}.{attribute}", value))
        return out

    for info in pkgutil.iter_modules(attest.__path__):
        module = importlib.import_module(f"attest.{info.name}")
        for name, obj in candidates(module):
            if not inspect.isfunction(obj) or obj.__module__ != module.__name__:
                continue
            try:
                signature = inspect.signature(obj)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                continue
            if len(signature.parameters) != 1:
                continue
            annotation = signature.return_annotation
            if (
                annotation is not bool
                and str(annotation)
                not in {
                    "bool",
                    "<class 'bool'>",
                }
                and typing.get_origin(annotation) is not typing.TypeGuard
            ):
                continue
            try:
                verdicts = [obj(probe) for probe in yes + no]
            except BaseException:  # noqa: S112 - a probe must never abort the sweep
                continue
            if all(v is True for v in verdicts[: len(yes)]) and all(
                v is False for v in verdicts[len(yes) :]
            ):
                found.append((f"{info.name}.{name}", obj))
    return found


def test_every_canonicality_predicate_agrees_with_the_owner() -> None:
    """The structural guard above says nobody WRITES the defect; this says
    nobody HAS it, whatever they wrote.

    A shape can always be rewritten — one statement into two, a helper, a
    loop — so a guard that reads syntax can be evaded by accident. This one
    reads behaviour: every predicate in the package that answers "is this the
    canonical spelling" must answer exactly what the owner answers, on a corpus
    that includes the years where the two used to differ.
    """
    from attest import dates

    probes = [f"{year:04d}-06-15T12:30:45Z" for year in (1, 99, 100, 999, 1000, 2026, 9999)]
    probes += [
        spelling for probe in probes[:] for _name, spelling in non_canonical_spellings(probe)
    ]
    probes += ["", "not-a-date", "2026-13-01T00:00:00Z", "2026-06-15T12:30:45"]

    found = dict(_canonicality_predicates())
    assert set(found) >= {"views._round_trips", "transfer._valid_utc_timestamp"}, (
        "discovery stopped finding the predicates this guard was written for: "
        f"found {sorted(found)}"
    )

    disagreements = [
        (probe, name, predicate(probe))
        for probe in probes
        for name, predicate in sorted(found.items())
        if predicate(probe) != dates.is_strict_utc(probe)
    ]
    assert not disagreements, (
        f"a predicate decides canonicality differently from `attest.dates`: {disagreements[:5]}"
    )


def test_the_one_predicate_allowed_to_differ_differs_only_where_it_says() -> None:
    """`witness._require_timestamp` is the package's third canonicality
    predicate and the ONLY one exempt from the guard above.

    It is exempt for a stated reason, not by oversight: it additionally refuses
    years 0000-0099 because JavaScript's `Date.UTC` remaps them, so admitting
    them would make a document admissible in this core alone. Discovery above
    does not reach it (it raises instead of returning a bool), which is an
    accident of its signature — so the exemption is pinned HERE, with its
    boundary, rather than left to that accident. Below 100 it may differ; at
    100 and above it may not.
    """
    from attest import dates, witness

    def admits(value: str) -> bool:
        try:
            witness._require_timestamp(value, "field")
        except Exception:
            return False
        return True

    probes = [f"{year:04d}-06-15T12:30:45Z" for year in (1, 99, 100, 999, 1000, 2026, 9999)]
    probes += [
        spelling for probe in probes[:] for _name, spelling in non_canonical_spellings(probe)
    ]

    assert not admits("0099-06-15T12:30:45Z") and dates.is_strict_utc("0099-06-15T12:30:45Z")
    above = [
        (probe, admits(probe))
        for probe in probes
        if not probe.startswith(("0000", "0001", "0002", "0099", "\uff10"))
        and probe[:4].isascii()
        and probe[:4].isdigit()
        and int(probe[:4]) >= 100
        and admits(probe) != dates.is_strict_utc(probe)
    ]
    assert not above, f"the witness gate differs from the owner ABOVE year 100: {above[:5]}"
