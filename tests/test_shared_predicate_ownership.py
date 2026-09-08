"""Shared core predicates must not acquire new source definitions.

Scan recursively, including new and untracked modules and tools. Test oracles
retain independent expectations; dependencies and generated builds are excluded.
Counting occurrences also rejects a second declaration inside the owner itself.
"""

from __future__ import annotations

import ast
import os
import re
import string
from collections import Counter
from decimal import Decimal
from pathlib import Path

import pytest

from tests.helpers import ForgedStr, non_canonical_spellings
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

    What this guard does NOT see, named here for the same reason the renderer
    guard names its own blind spot: `datetime.fromisoformat` parses the strict
    wire shape too, and this counter never looks for it. Three sites use it
    today — `verify._parse_iso` (deliberately lenient: revocation freshness,
    the separate ISO parse `dates.ts` documents as the sibling of this one),
    `itch_adapter.py:158` and `shopify_adapter.py:105` (both on a DIFFERENT
    merchant wire format). None decides the signed shape, so none is pinned;
    but a fourth copy of THIS predicate written with `fromisoformat` plus a
    hand-built round trip would be invisible to both syntactic guards, and
    inside `attest.*` only the semantic guard below would catch it. A guard
    that recognizes one spelling reads as "every spelling is watched" unless
    it says otherwise.
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


def _spec_renders_a_date(spec: str) -> bool:
    """`%` followed by a letter is a `strftime` directive; a bare trailing `%`
    is the percentage presentation type (`f"{x:.1%}"`, `"{:.1%}".format(x)`)
    and has nothing to do with dates."""
    return bool(re.search(r"%[a-zA-Z]", spec))


def _format_call_spec_renders_a_date(node: ast.Call) -> bool:
    """Whether `node` is `"...{:%X...}...".format(...)` or `format(v, "%X...")`.

    Both reach `datetime.__format__`, which is `strftime`. The `.format` arm
    reads the template through `string.Formatter().parse`, so a `%` sitting in
    the LITERAL text of the template rather than in a field's spec does not
    count — `"100%  done {}".format(x)` is not a date rendering.
    """
    func = node.func
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "format"
        and isinstance(func.value, ast.Constant)
        and isinstance(func.value.value, str)
    ):
        try:
            fields = list(string.Formatter().parse(func.value.value))
        except ValueError:  # pragma: no cover - a template `str.format` itself rejects
            return False
        return any(spec is not None and _spec_renders_a_date(spec) for _, _, spec, _ in fields)
    return (
        isinstance(func, ast.Name)
        and func.id == "format"
        and len(node.args) == 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
        and _spec_renders_a_date(node.args[1].value)
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

    `datetime.__format__` IS `strftime`, so every route to it counts, not only
    the f-string one: `"{:%Y-%m-%d}".format(parsed)`, `format(parsed, fmt)` and
    an explicit `parsed.__format__(fmt)` all render through it and all reproduce
    the low-year defect verbatim (measured: each returns `'999-06-15...'` for
    `datetime(999, ...)` on this libc, exactly as `strftime` does). A guard that
    counted only the f-string spelling was the same criterion-misses-the-newest-
    spelling defect this docstring already records one paragraph up, and it
    mattered more here than there: outside `src/attest/` this syntactic guard is
    the ONLY one — the semantic guard below walks `attest.*` and never reaches
    `bridge/` or `tools/`, which is where D-C7 grew this perimeter to look.

    So: any attribute named `strftime` or `__format__`, any `getattr` naming
    either as a constant, and any `%`-directive format spec — whether written as
    an f-string spec, inside a literal `.format()` template, or as the second
    argument of the `format` builtin. Prose is unaffected — this reads the AST,
    never the word.
    """
    tree = ast.parse(source)
    count = 0
    for node in ast.walk(tree):
        if _names_attribute(node, "strftime") or _names_attribute(node, "__format__"):
            count += 1
        elif isinstance(node, ast.Call) and _format_call_spec_renders_a_date(node):
            count += 1
        elif isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            spec = "".join(
                part.value
                for part in ast.walk(node.format_spec)
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if _spec_renders_a_date(spec):
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

    This guard used to stop at `src/attest/`, on the theory that a workspace
    member could not reach a signed receipt. That theory was never checked: it
    excluded `bridge/` and `tools/` by PATH, not by argument, and the exclusion
    itself was the untested claim (C-7). Removed: this walks every source in
    the repository, exactly like the parser guard above, and pins what it
    finds by name and count, never by pattern — a pattern exempts whatever is
    written after it, which is how the first four copies of this defect were
    born unwatched.

    Nine files render `strftime`-shaped text today. They fall into four
    groups, and the two reasons below are NOT interchangeable — writing the
    fail-closed reason for a site whose product a verifier never re-reads is
    the same mistake C-6 made the other way round, just with the roles
    reversed:

    * `src/attest/issue.py` (`_now_iso`) and `src/attest/transparency.py`
      (`_iso8601`) — the core's own two survivors, unchanged from before this
      guard's perimeter grew. See their per-function reasons further down.

    * `bridge/src/attest_bridge/core.py:41`, `http.py:137`, and
      `signing.py:174` — the only three sites whose product actually reaches
      the core's fail-closed boundary. `core.py`'s `_now_rfc3339()` supplies
      `issue_for`'s `issued_at`, which both signs into the payload
      (`issue.build_payload`) AND gates `signing_key_within_validity` before
      that happens; `http.py`'s copy of the same helper is called the same
      way at the webhook readiness/issuance gate (`http.py:823`); `signing.py`
      calls `verifier._within_validity` directly, at issuer load, before a key
      may sign at all. For these three: *(i)* they render `datetime.now(UTC)`,
      so the year is always four digits and the padding defect is
      unreachable today, AND *(ii)* even if a future caller fed them a low
      year, `verify._within_validity` re-derives the instant with
      `parse_strict_utc` (fail-closed) before trusting it — so the failure
      mode of a divergent renderer here is a REJECTED window, never an
      admitted one. Both halves are load-bearing; the first without the
      second is the exact claim this docstring used to make about the whole
      file and C-7 found false for `bridge/` as a class. Reason *(ii)*
      protects THAT CALL, not every call these two helpers serve:
      `core.py`'s copy is also read at `:264` (`_ledger.mark_delivered`)
      and `http.py`'s copy roughly a dozen more times in the same file
      (`mark_event`, `enqueue_claim`) — those calls share the ledger-only
      failure mode of the group below, not this one.

    * `bridge/src/attest_bridge/cli.py:76` (the `_now_rfc3339()` helper) and
      `:880` (a SEPARATE, inline `now.strftime(_RFC3339)` on the one clock
      read `_cmd_itch_dry_run` takes for its whole run — not a call
      through that helper; see the comment above `:880`), `delivery.py:388`,
      and `itch_adapter.py:319`, `:484`, `:495` — all six feed only
      `Ledger.*` bookkeeping (`enqueue_claim`, `resolve_dead_letter`,
      `mark_delivered`, `mark_event`, `due_claims`,
      `exhaust_claim_with_dead_letter`, `defer_claim`): grepped for every
      call site of each helper, none reaches `signing_key_within_validity`,
      `_within_validity`, or `build_payload`. Reason *(ii)* above is FALSE
      for these six and is not claimed: the ledger stores the string and
      compares it lexically, it does not reparse it through the core's
      strict parser. Only *(i)* holds, and only because their production
      caller happens to pass `datetime.now(UTC)` today (`itch_adapter.py`'s
      `now` is a parameter of `ItchPoller.tick`, supplied in production by
      `run_forever` and by `cli.py`'s own dry-run command at `:901` —
      neither is a clock read inside the pinned function itself). A
      divergent renderer here produces a malformed ledger row — a retry
      scheduled wrong, a dead letter that never resolves — never an admitted
      receipt: it is C-6 on a different site, not a signing-path defect.

    * `bridge/src/attest_bridge/cli.py:209` — a THIRD call in `cli.py`,
      inside `_itch_dry_run_purchase`, and it is not attempting the canonical
      wire shape at all: it renders `%Y-%m-%d %H:%M:%S` (a space, no `Z`) to
      imitate itch.io's own `created_at` field in a synthetic dry-run
      fixture. Safe because it is a DIFFERENT format on purpose, the same pin
      shape the parser guard above already uses for this file's `strptime`
      side ("a merchant adapter reading a DIFFERENT wire format").

    * `tools/conformance_runner.py:423` (`_utc_now_iso`) — renders
      `Report.generated_at` for a conformance run's own report. A generator
      doing clock arithmetic for tooling output, the same category as
      `tools/gen_vectors.py`, already pinned in the parser guard above; not a
      verdict path.

    A second, UNRELATED grafia reaches the same canonical shape without ever
    calling `strftime`, and this guard cannot see it:
    `moment.replace(microsecond=0, tzinfo=None).isoformat() + "Z"`, written
    identically in `itch_adapter.py:177`, `shopify_adapter.py:126`, and
    `model.py:123`. It is safe for a DIFFERENT reason than either group
    above — `datetime.isoformat()` always pads the year to four digits, so
    the glibc `%Y` defect this guard exists to catch cannot occur there
    regardless of which year is rendered — and it feeds
    `NormalizedPurchase.purchased_at`, which the adapters construct but
    nothing in this repository re-reads. Naming it here is C-222's own
    lesson applied to this guard: a guard that recognizes one spelling reads
    as "every spelling is watched" unless it says otherwise.

    `witness/` carries zero `strftime`/`strptime`/`isoformat` occurrences
    today (its timestamp is a POSIX integer, the C2SP cosign shape) and is
    walked anyway — not because it renders anything now, but so a predicate
    born there tomorrow does not inherit the exemption C-7 just closed.

    The pinned two from before this guard's perimeter grew:

    * `issue._now_iso()` does render the clock, but it takes no argument, so a
      low year can never reach it. It is a DEFAULT of `build_payload`, not a
      gate: the CLI's `issue` verb never calls it, and signs whatever
      `issued_at` the caller wrote into `--payload` (deliberately — see the
      header of `demo/store_dies.py`). The callers that do reach it —
      `demo/store_dies.py`, `demo/pledge_dies.py`, `tools/gen_site_sample.py` —
      never override it.
    * `transparency._iso8601()` does NOT render `now()` at all. Its argument is
      `anchor_verdict.anchored_before`, a block-header time carried by the
      `--transparency` evidence a verifier is handed. It is contained because
      `anchor._validate_policy` bounds verified anchor times, not because it
      reads the clock.

    So the emission half of C-217 is still open, but not where that claim put
    it: a receipt's `issued_at` reaches a verifier as a string the issuer wrote,
    which passed through no renderer this guard counts. `views.py` was the third
    and is gone — it renders through `dates.render_strict_utc`, which is why
    that function is public.
    """
    renderers = {
        "src/attest/issue.py": 1,
        "src/attest/transparency.py": 1,
        "bridge/src/attest_bridge/cli.py": 3,
        "bridge/src/attest_bridge/core.py": 1,
        "bridge/src/attest_bridge/delivery.py": 1,
        "bridge/src/attest_bridge/http.py": 1,
        "bridge/src/attest_bridge/itch_adapter.py": 3,
        "bridge/src/attest_bridge/signing.py": 1,
        "tools/conformance_runner.py": 1,
    }
    found = {
        path.relative_to(REPO_ROOT).as_posix(): calls
        for path in _sources((".py",))
        if (calls := _strftime_calls(path.read_text(encoding="utf-8")))
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


def test_every_canonicality_predicate_fails_closed_on_an_object_that_forges_its_type() -> None:
    """`isinstance(value, str)` is not a check an object cannot forge, and every
    predicate discovered above opens with one.

    DISCOVERED, never listed — the same sweep as the test above and for the same
    reason: a predicate written tomorrow inherits this without anyone
    remembering to register it. It found three, the OWNER included, which is the
    point: `dates.is_strict_utc` had this defect too, so fixing only the two
    callers would have left the module the whole branch exists to make
    authoritative answering with an exception.

    The observable is the KIND of answer, not merely that something happened: a
    predicate that returns `False` has DECIDED, one that raises has ESCAPED into
    its callers. Nothing else distinguishes them —
    `transfer._valid_utc_timestamp` alone is read at sixteen call sites across
    `transfer`, `authority`, `grant` and `cli`, and not one of them catches
    `TypeError`. `views._round_trips` was fail-closed on this input before the
    round that introduced `attest.dates` and stopped being so; the assertion
    below is what would have said so.
    """
    forged = ForgedStr()
    assert isinstance(forged, str), "premise failed: this input must pass the gate it forges"
    assert type(forged) is not str, "premise failed: this input must not actually be a str"

    found = dict(_canonicality_predicates())
    assert set(found) >= {
        "dates.is_strict_utc",
        "transfer._valid_utc_timestamp",
        "views._round_trips",
    }, f"discovery stopped finding the predicates this guard was written for: {sorted(found)}"

    escaped = []
    for name, predicate in sorted(found.items()):
        try:
            verdict = predicate(forged)
        # Broad on purpose: the escape IS the finding, whatever its class.
        except BaseException as exc:
            escaped.append((name, f"raised {type(exc).__name__}"))
            continue
        if verdict is not False:
            escaped.append((name, f"answered {verdict!r}"))
    assert not escaped, (
        "a canonicality predicate does not fail closed on an object that forges "
        f"`isinstance(x, str)`; it must answer False, not raise: {escaped}"
    )


def test_the_witness_gate_refuses_a_forged_type_with_its_own_error() -> None:
    """`_require_timestamp` promises `WitnessError`, and every caller catches
    that and nothing else.

    Pinned apart from the sweep above because discovery cannot reach it (it
    raises instead of returning a bool, the same accident that already puts its
    low-year exemption in a test of its own). On a forged type it raised
    `TypeError` out of `str.__str__`, straight through `parse_policy` and out of
    the core: a malformed field taking down the whole policy parse instead of
    being refused.
    """
    from attest import witness

    with pytest.raises(witness.WitnessError):
        witness._require_timestamp(ForgedStr(), "field")


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
