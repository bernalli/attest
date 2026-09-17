#!/usr/bin/env python3
"""Ablation bench: put a defect back into a file, run the suite that claims to catch it, classify.

The number this bench produces is a count of survivors, so the bench has to prove
that it measured before any count is believed. Every mutation that reaches the
tree leaves three traces, each produced by something other than the code that
applied it and other than the classification:

* the ledger: the journal record written before the target was touched, and the
  re-read of the target that confirmed the mutated bytes are on disk;
* git: `git status --porcelain --untracked-files=normal`, taken after that re-read
  and before the suite, must name exactly the mutated file (and nothing, for a
  mutant that loads a pytest plugin instead of changing a file);
* the nonce: every suite run gets a fresh random nonce in its environment, and the
  outcome record it is classified from must carry that same nonce back. A vitest
  run that `tsc` stops before vitest runs echoes no nonce; for that row, and only
  for it, the third trace is `typecheck` -- `tsc`'s exit status, the codes of the
  `: error TS<digits>:` diagnostics in the output captured from it, and that
  output's SHA-256 -- and it holds only with a non-zero exit and at least one code.

`applications_confirmed` counts the rows for which all three hold and whose outcome
records are coherent. It is computed from the traces, never from the classification,
and it is compared with the number of mutations that had to land: a mismatch exits
10, because the hypothesis to falsify first is then the bench itself.

Usage:
    ablate.py <spec.json> [--tree PATH] [--only ID[,ID...]] [--out results.json]
                          [--no-typecheck] [--preflight] [--skip-preflight]
    ablate.py --restore [--tree PATH]

`ablate.py <spec.json>` checks, in this order and with nothing in between: the
arguments (exit 3); a journal directory already under the tree (exit 8 when it holds
`owner.json`, 5 when it does not; it is never touched); the spec against its schema
and against the tree ("item 0", exit 3); a `--only` that names an id not in the spec,
or selects nothing (exit 4); a tree that is dirty before the run (exit 5); and the
acquisition of the journal (exit 8 when another process wins it). Only then is
anything mutated. `--preflight` takes the same checks up to item 0 and stops there.

Exit status, and no other: 0 everything verified; 3 invalid arguments or spec; 4
nothing selected; 5 dirty before the run; 6 dirty after it; 7 a declared
`expect_verdict` not met; 8 the journal is held; 9 a journal record is in a state
nobody wrote; 10 a mutation ran without its three traces; 11 more than one mutant
and every one of them survived; 12 a filesystem of the tree cannot exchange two
files atomically. An exit decided by the journal (8, 9, 12) wins over 6, 7, 10 and
11, and 9 wins over 12 wherever either appears in the chain of errors. After the
run the checks are evaluated in the order 6, 7, 10, 11.

`results.json` is written only when `--out` names it; without `--out` no file is
written, and the summary on stdout says so. When a journal refusal stops the run
midway, no results file is written either, and stdout carries a partial summary: the
ids tried up to the stop, `applications_confirmed/applications_attempted`, and the
records left in the journal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

HERE = Path(__file__).resolve().parent
# `journal.py`, `classify.py` and the outcomes plugin live next to this file and are
# imported from here, so a copy of this directory runs its own modules.
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import journal  # noqa: E402 -- resolved from the directory inserted above
from classify import IncoherentOutcomes, classify, validate_outcomes  # noqa: E402

EXIT_OK = 0
EXIT_INVALID = 3
EXIT_NOTHING_SELECTED = 4
EXIT_DIRTY_BEFORE = 5
EXIT_DIRTY_AFTER = 6
EXIT_EXPECTATION_NOT_MET = 7
EXIT_UNCONFIRMED = 10
EXIT_ALL_SURVIVED = 11

#: Among the exits the journal decides, the one reported when several appear in one chain.
_JOURNAL_EXIT_PRECEDENCE = (
    journal.EXIT_UNKNOWN_STATE,
    journal.EXIT_EXCHANGE_UNAVAILABLE,
    journal.EXIT_JOURNAL_BUSY,
)

VERDICTS = ("NOT_APPLIED", "KILLED", "KILLED_ELSEWHERE", "SURVIVED", "BROKEN", "BASELINE_RED")
DEFAULT_LAUNCHER = ("uv", "run", "--directory", "{tree}", "--no-sync", "pytest")

_TOP_LEVEL_KEYS = frozenset({"note", "launcher", "unmeasured", "mutants"})
_MUTANT_KEYS = frozenset(
    {
        "id",
        "property",
        "kind",
        "file",
        "old",
        "new",
        "plugin",
        "runner",
        "pkg",
        "suite",
        "expect_red",
        "expect_verdict",
        "property_red_is_crash",
        "direction",
    }
)
_KINDS = ("source", "plugin")
_RUNNERS = ("pytest", "vitest")
_MODULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
#: The `git status` line of the journal directory while it holds anything.
_JOURNAL_STATUS_LINE = f"?? {journal.JOURNAL_DIRNAME}/"
_VITEST_REPORT = re.compile(r"^vitest-outcomes-(?P<nonce>[0-9a-f]{32})\.json$")
#: A diagnostic of `tsc --pretty false` that rejects the source, such as
#: `src/revocation.ts(480,11): error TS2322: ...`. A configuration or invocation failure
#: (`error TS5058: The specified path does not exist: ...`) has no location before it.
_TSC_DIAGNOSTIC = re.compile(r": error TS(\d+):")
#: A record file in a journal, `NN-<slug>.json` or `NN-<slug>.orig`; `name` is the record's name.
_RECORD_FILE = re.compile(r"^(?P<name>[0-9]{2,}-.+)\.(?:json|orig)$")
_SUITE_TIMEOUT_SECONDS = 1800
_TYPECHECK_TIMEOUT_SECONDS = 900

TS_FORM_ERRORS = (
    "ReferenceError",
    "is not a function",
    "is not defined",
    "Cannot find module",
    "Failed to load",
    "Transform failed",
    "SyntaxError",
    "Cannot read properties of undefined",
)


class _UsageError(Exception):
    """The command line does not parse."""


class _Parser(argparse.ArgumentParser):
    """An argument parser whose errors exit through `main()` with the bench's exit 3."""

    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


@dataclass(frozen=True)
class SuiteRun:
    """One execution of a suite, and what the bench can prove about it.

    `outcomes` is the record the suite's outcomes were read into, as read; it is
    validated separately. `outcomes_path` names where that record was read from.
    `nonce_issued` is the nonce this run was given; `nonce_echoed` is the nonce the
    record carries back, or `None` when it carries none.

    `typecheck` is set only for a vitest run that `tsc` stopped before vitest ran:
    `{tsc_returncode, form_codes, output_sha256}`, computed from the output this run
    captured from `tsc`. Such a run echoes no nonce, and `typecheck` is the trace that
    measures it instead.
    """

    outcomes: Any
    outcomes_path: str
    nonce_issued: str
    nonce_echoed: str | None
    typecheck: dict[str, Any] | None = None


@dataclass
class _Progress:
    """What a run has done so far: the ids it tried, the rows it completed, its suite runs.

    An id is added when its mutant is started, a row when the mutant is finished; the
    mutant in progress when a journal refusal stops the run is tried and has no row.
    """

    tried: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    runs: list[SuiteRun] = field(default_factory=list)


# --- git and the tree ------------------------------------------------------------------------


def _git(tree: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run `git -C <tree> <args>` and capture its text output."""
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell
        ["git", "-C", str(tree), *args],  # noqa: S607 -- git from PATH
        capture_output=True,
        text=True,
        check=False,
    )


def _git_toplevel(directory: Path) -> Path | None:
    """`git rev-parse --show-toplevel` from `directory`, or `None` when git cannot answer."""
    result = _git(directory, "rev-parse", "--show-toplevel")
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return Path(result.stdout.strip())


def _porcelain(tree: Path) -> list[str] | None:
    """The lines of `git status --porcelain --untracked-files=normal`, or `None` if git fails."""
    result = _git(tree, "status", "--porcelain", "--untracked-files=normal")
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.split("\n") if line]


def _porcelain_during_mutation(tree: Path) -> list[str] | None:
    """`_porcelain()` without the line of the journal directory, which holds the record."""
    lines = _porcelain(tree)
    if lines is None:
        return None
    return [line for line in lines if line != _JOURNAL_STATUS_LINE]


def _resolve_tree(given: str | None) -> tuple[Path | None, str]:
    """The tree to work on, or `None` and the reason it cannot be used."""
    if given is None:
        toplevel = _git_toplevel(HERE)
        if toplevel is None:
            return None, f"no --tree given and {HERE} is not inside a git working tree"
        return toplevel.resolve(), ""
    candidate = Path(given).resolve()
    if not candidate.is_dir():
        return None, f"--tree {given} is not a directory"
    toplevel = _git_toplevel(candidate)
    if toplevel is None or toplevel.resolve() != candidate:
        return None, (
            f"--tree {given} is not the top level of a git working tree "
            f"(git answered {toplevel if toplevel is not None else 'nothing'})"
        )
    return candidate, ""


def _sha256_of_file(path: Path) -> str:
    """Hex SHA-256 of a file's bytes, or `absent`."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "absent"


# --- item 0: the spec against its schema and against the tree ---------------------------------


def _type_name(value: object) -> str:
    """The JSON name of a parsed value's type, for messages."""
    names = {
        bool: "boolean",
        int: "integer",
        float: "number",
        str: "string",
        list: "array",
        dict: "object",
        type(None): "null",
    }
    return names.get(type(value), type(value).__name__)


def _is_string_list(value: object) -> bool:
    """A JSON array whose every element is a string."""
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _tree_relative_problem(rel_path: str) -> str | None:
    """Why `rel_path` is not a normalized tree-relative path, or `None`."""
    pure = PurePosixPath(rel_path)
    if not rel_path or pure.is_absolute() or ".." in pure.parts or pure.as_posix() != rel_path:
        return f"{rel_path!r} is not a normalized path relative to the tree"
    return None


def _schema_problems(mutant: dict[str, Any], label: str) -> list[str]:
    """Each way one mutant departs from the schema, independently of the tree's contents."""
    problems: list[str] = []

    def problem(key: str, what: str) -> None:
        problems.append(f"item 0: mutant {label}: key {key}: {what}")

    for key in sorted(set(mutant) - _MUTANT_KEYS):
        problem(key, "is not a key of a mutant")

    def typed(key: str, check: bool, expected: str, *, required: bool) -> bool:
        if key not in mutant:
            if required:
                problem(key, "is missing")
            return False
        if not check:
            problem(key, f"must be {expected}, found {_type_name(mutant[key])}")
            return False
        return True

    typed("id", isinstance(mutant.get("id"), str), "a string", required=True)
    typed("property", isinstance(mutant.get("property"), str), "a string", required=True)

    kind: str | None = "source"
    if "kind" in mutant:
        if not isinstance(mutant["kind"], str):
            problem("kind", f"must be a string, found {_type_name(mutant['kind'])}")
            kind = None
        elif mutant["kind"] not in _KINDS:
            problem("kind", f"{mutant['kind']!r} is not one of {list(_KINDS)}")
            kind = None
        else:
            kind = mutant["kind"]

    runner: str | None = "pytest"
    if "runner" in mutant:
        if not isinstance(mutant["runner"], str):
            problem("runner", f"must be a string, found {_type_name(mutant['runner'])}")
            runner = None
        elif mutant["runner"] not in _RUNNERS:
            problem("runner", f"{mutant['runner']!r} is not one of {list(_RUNNERS)}")
            runner = None
        else:
            runner = mutant["runner"]

    typed("file", isinstance(mutant.get("file"), str), "a string", required=kind == "source")
    if kind == "plugin":
        for key in ("old", "new"):
            if key in mutant:
                problem(key, "is forbidden for kind plugin, which changes no file")
    else:
        has_old = typed(
            "old", isinstance(mutant.get("old"), str), "a string", required=kind == "source"
        )
        has_new = typed(
            "new", isinstance(mutant.get("new"), str), "a string", required=kind == "source"
        )
        if has_old and not mutant["old"]:
            problem("old", "must not be empty: an empty anchor names no place in the file")
        if has_old and has_new and mutant["old"] == mutant["new"]:
            problem("new", "equals old, so the mutation changes nothing")

    if typed(
        "plugin", isinstance(mutant.get("plugin"), str), "a string", required=kind == "plugin"
    ):
        if not _MODULE_NAME.match(mutant["plugin"]):
            problem("plugin", f"{mutant['plugin']!r} is not a module name")
    if kind == "plugin" and runner is not None and runner != "pytest":
        problem("kind", f"kind plugin requires runner pytest, found runner {runner!r}")

    typed("pkg", isinstance(mutant.get("pkg"), str), "a string", required=runner == "vitest")

    if typed("suite", _is_string_list(mutant.get("suite")), "an array of strings", required=True):
        if not mutant["suite"]:
            problem("suite", "must not be empty")
    typed(
        "expect_red",
        _is_string_list(mutant.get("expect_red")),
        "an array of strings",
        required=True,
    )
    if typed(
        "expect_verdict", isinstance(mutant.get("expect_verdict"), str), "a string", required=False
    ):
        if mutant["expect_verdict"] not in VERDICTS:
            problem(
                "expect_verdict", f"{mutant['expect_verdict']!r} is not one of {list(VERDICTS)}"
            )
    typed(
        "property_red_is_crash",
        isinstance(mutant.get("property_red_is_crash"), bool),
        "a boolean",
        required=False,
    )
    typed("direction", isinstance(mutant.get("direction"), str), "a string", required=False)
    return problems


def _tree_problems(mutant: dict[str, Any], label: str, tree: Path, tracked: set[str]) -> list[str]:
    """Each way one schema-valid mutant does not fit the tree as it is now.

    These are the checks a concurrent change to the tree can invalidate between
    validation and application, and the only ones `--skip-preflight` skips.
    """
    problems: list[str] = []

    def problem(key: str, what: str) -> None:
        problems.append(f"item 0: mutant {label}: key {key}: {what}")

    kind = mutant.get("kind", "source")
    runner = mutant.get("runner", "pytest")
    if kind == "source":
        rel_path: str = mutant["file"]
        relative = _tree_relative_problem(rel_path)
        if relative is not None:
            problem("file", relative)
        elif rel_path not in tracked or not (tree / rel_path).is_file():
            problem("file", f"{rel_path} is not a file tracked by git in {tree}")
        else:
            try:
                text = (tree / rel_path).read_bytes().decode("utf-8")
            except UnicodeDecodeError as exc:
                problem("file", f"{rel_path} is not UTF-8 ({exc})")
            else:
                old: str = mutant["old"]
                occurrences = text.count(old)
                if occurrences == 0:
                    problem("old", f"the anchor is absent from {rel_path}")
                elif occurrences > 1:
                    problem("old", f"the anchor occurs {occurrences} times in {rel_path}, need 1")
                else:
                    index = text.index(old)
                    if index != 0 and text[index - 1] != "\n":
                        problem("old", f"the anchor starts mid-line in {rel_path}")
    if kind == "plugin":
        module_path = Path(*mutant["plugin"].split("."))
        candidates = (tree / f"{module_path}.py", tree / module_path / "__init__.py")
        if not any(candidate.is_file() for candidate in candidates):
            problem("plugin", f"no file for module {mutant['plugin']} in {tree}")
    if runner == "vitest":
        bin_dir = tree / mutant["pkg"] / "node_modules" / ".bin"
        for tool in ("vitest", "tsc"):
            if not (bin_dir / tool).exists():
                problem("pkg", f"{bin_dir / tool} does not exist")
    return problems


def _top_level_problems(spec: dict[str, Any]) -> list[str]:
    """Each way the spec's top-level object departs from the schema."""
    problems: list[str] = []

    def problem(key: str, what: str) -> None:
        problems.append(f"item 0: spec: key {key}: {what}")

    for key in sorted(set(spec) - _TOP_LEVEL_KEYS):
        problem(key, "is not a key of a spec")
    if "note" in spec and not isinstance(spec["note"], str):
        problem("note", f"must be a string, found {_type_name(spec['note'])}")
    if "launcher" in spec:
        if not _is_string_list(spec["launcher"]):
            problem(
                "launcher", f"must be an array of strings, found {_type_name(spec['launcher'])}"
            )
        elif not spec["launcher"]:
            problem("launcher", "must not be empty")
    if "unmeasured" in spec:
        unmeasured = spec["unmeasured"]
        if not (
            isinstance(unmeasured, dict)
            and set(unmeasured) == {"why", "suites"}
            and isinstance(unmeasured["why"], str)
            and _is_string_list(unmeasured["suites"])
        ):
            problem("unmeasured", "must be an object {why: string, suites: [string]}")
    if "mutants" not in spec:
        problem("mutants", "is missing")
    elif not isinstance(spec["mutants"], list):
        problem("mutants", f"must be an array, found {_type_name(spec['mutants'])}")
    elif not spec["mutants"]:
        problem("mutants", "must not be empty")
    return problems


#: A JSON object of the spec and the keys it names more than once, in the order parsed.
_RepeatedKeys = list[tuple[dict[str, Any], list[str]]]


def _load_spec(spec_path: Path) -> tuple[Any, list[str], _RepeatedKeys]:
    """The parsed spec, or `None` and the reason it cannot be read.

    A JSON object that names a key twice parses to the last value without a word;
    every such object is returned with its repeated keys, for item 0 to refuse.
    """
    repeated: _RepeatedKeys = []

    def keep_repeated(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj = dict(pairs)
        if len(obj) != len(pairs):
            seen: set[str] = set()
            twice: list[str] = []
            for key, _value in pairs:
                if key in seen and key not in twice:
                    twice.append(key)
                seen.add(key)
            repeated.append((obj, twice))
        return obj

    try:
        return json.loads(spec_path.read_bytes(), object_pairs_hook=keep_repeated), [], repeated
    except OSError as exc:
        return None, [f"item 0: spec: {spec_path} cannot be read ({exc})"], []
    except (ValueError, UnicodeDecodeError) as exc:
        return None, [f"item 0: spec: {spec_path} is not valid JSON ({exc})"], []


def _repeated_key_problems(raw: Any, repeated: _RepeatedKeys) -> list[str]:
    """One violation per key a JSON object of the spec names more than once."""
    rows = raw.get("mutants") if isinstance(raw, dict) else None
    labels: list[tuple[object, str]] = [(raw, "spec")]
    for index, row in enumerate(rows if isinstance(rows, list) else []):
        if isinstance(row, dict):
            identifier = row.get("id")
            label = identifier if isinstance(identifier, str) else f"mutants[{index}]"
            labels.append((row, f"mutant {label}"))
    problems: list[str] = []
    for obj, keys in repeated:
        where = next((label for owner, label in labels if owner is obj), "spec: a nested object")
        problems += [
            f"item 0: {where}: key {key}: appears more than once in its JSON object, and JSON "
            "keeps only the last value"
            for key in keys
        ]
    return problems


def item_zero(raw: Any, tree: Path, *, tree_checks: bool) -> tuple[int, list[str]]:
    """Validate a parsed spec; return how many mutants it declares and every violation.

    Every violation names the mutant (its id, or `mutants[<index>]` when the id
    itself is unusable) and the key. With `tree_checks` false, the checks that read
    the tree -- a file tracked by git and UTF-8, an anchor present once at the
    start of a line, a plugin's file, a package's test tools -- are skipped; the
    schema is checked either way.
    """
    if not isinstance(raw, dict):
        return 0, [f"item 0: spec: must be a JSON object, found {_type_name(raw)}"]
    problems = _top_level_problems(raw)
    mutants = raw.get("mutants")
    if not isinstance(mutants, list):
        return 0, problems
    tracked: set[str] = set()
    if tree_checks:
        listing = _git(tree, "ls-files", "-z")
        if listing.returncode != 0:
            problems.append(f"item 0: spec: git cannot list the tracked files of {tree}")
            tree_checks = False
        else:
            tracked = {name for name in listing.stdout.split("\0") if name}
    first_index: dict[str, int] = {}
    for index, row in enumerate(mutants):
        if not isinstance(row, dict):
            problems.append(
                f"item 0: mutant mutants[{index}]: must be a JSON object, found {_type_name(row)}"
            )
            continue
        identifier = row.get("id")
        label = identifier if isinstance(identifier, str) else f"mutants[{index}]"
        row_problems = _schema_problems(row, label)
        if isinstance(identifier, str):
            if identifier in first_index:
                row_problems.append(
                    f"item 0: mutant {label}: key id: duplicate id, first used by "
                    f"mutants[{first_index[identifier]}]"
                )
            else:
                first_index[identifier] = index
        if tree_checks and not row_problems:
            row_problems += _tree_problems(row, label, tree, tracked)
        problems += row_problems
    return len(mutants), problems


# --- running a suite ----------------------------------------------------------------------------


def _launcher_argv(launcher: Sequence[str], tree: Path) -> list[str]:
    """The launcher with `{tree}` and `{python}` substituted."""
    return [
        part.replace("{tree}", str(tree)).replace("{python}", sys.executable) for part in launcher
    ]


def _unread_outcomes(returncode: int | None, reason: str) -> dict[str, Any]:
    """A coherent outcome record for a suite whose own record could not be read."""
    return {
        "exitstatus": returncode,
        "collected_and_run": 0,
        "n_passed": 0,
        "n_failed": 0,
        "failed": [],
        "why": {},
        "collect_errors": [reason],
    }


def run_pytest(
    tree: Path,
    launcher: Sequence[str],
    selectors: Sequence[str],
    *,
    plugin: str | None,
    tree_on_path: bool,
) -> SuiteRun:
    """Run one pytest suite in `tree` through `launcher`, with a fresh nonce.

    The outcomes plugin is imported from this file's directory, placed first on
    `PYTHONPATH`; `tree_on_path` puts the tree after it, for a mutant that loads a
    plugin from the tree. `plugin`, when given, is loaded with `-p`. Bytecode is
    not written, and `PYTHONPYCACHEPREFIX` is removed so no cache lands outside the
    tree where removing caches under the tree would not reach it.
    """
    nonce = secrets.token_hex(16)
    handle, outcomes_path = tempfile.mkstemp(prefix="ablation-outcomes-", suffix=".json")
    os.close(handle)
    env = dict(os.environ)
    env.pop("PYTHONPYCACHEPREFIX", None)
    env.pop("ABLATION_NONCE", None)
    env["ABLATION_OUTCOMES"] = outcomes_path
    # CI sets this so tests that would SKIP for a missing prerequisite fail
    # instead: a skipped test kills no mutant.
    env["ATTEST_CI_REQUIRED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["ABLATION_NONCE"] = nonce
    python_path = [str(HERE), *([str(tree)] if tree_on_path else [])]
    if env.get("PYTHONPATH"):
        python_path.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_path)
    command = [
        *_launcher_argv(launcher, tree),
        "-p",
        "outcomes_plugin",
        "-p",
        "no:cacheprovider",
        "--tb=no",
        "-q",
        *(["-p", plugin] if plugin is not None else []),
        *selectors,
    ]
    stdout = stderr = ""
    returncode: int | None = None
    try:
        proc = subprocess.run(  # noqa: S603 -- argv from the spec's launcher, no shell
            command,
            cwd=str(tree),
            env=env,
            capture_output=True,
            text=True,
            timeout=_SUITE_TIMEOUT_SECONDS,
            check=False,
        )
        stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        stderr = str(exc)
    outcomes: Any
    try:
        with open(outcomes_path, encoding="utf-8") as fh:
            outcomes = json.load(fh)
    except (OSError, ValueError):
        outcomes = _unread_outcomes(returncode, "<the outcomes plugin wrote nothing>")
    finally:
        Path(outcomes_path).unlink(missing_ok=True)
    echoed = outcomes.get("nonce") if isinstance(outcomes, dict) else None
    if isinstance(outcomes, dict):
        outcomes["returncode"] = returncode
        outcomes["stdout_tail"] = stdout[-3000:]
        outcomes["stderr_tail"] = stderr[-2000:]
    return SuiteRun(
        outcomes=outcomes,
        outcomes_path=outcomes_path,
        nonce_issued=nonce,
        nonce_echoed=echoed if isinstance(echoed, str) else None,
    )


def tsc_form_codes(output: str) -> list[str]:
    """The `TS<digits>` codes of the source diagnostics in the output of `tsc --pretty false`.

    Only a diagnostic in the form `: error TS<digits>:` counts -- the form `tsc` gives
    an error it located in a file. A code quoted in other text, or an error without a
    location, such as a missing configuration, does not. The codes are returned once
    each, in numeric order.
    """
    numbers = {int(match) for match in _TSC_DIAGNOSTIC.findall(output)}
    return [f"TS{number}" for number in sorted(numbers)]


def run_vitest(tree: Path, pkg: str, selectors: Sequence[str], *, typecheck: bool) -> SuiteRun:
    """Run one vitest package, type-checking first when asked, with a fresh nonce.

    vitest strips TypeScript types instead of checking them, so a type-invalid
    mutation still runs; `tsc --noEmit --pretty false` runs first. When it exits
    non-zero, vitest does not run: the failure is recorded as a collection error,
    and the run carries the `typecheck` trace, built from the output captured here,
    instead of a nonce. Otherwise the nonce names the report file vitest is told to
    write, and the nonce echoed is the one in the name of the report actually read.
    """
    nonce = secrets.token_hex(16)
    pkg_dir = tree / pkg
    report_dir = Path(tempfile.mkdtemp(prefix="ablation-vitest-"))
    report_path = report_dir / f"vitest-outcomes-{nonce}.json"
    result = _unread_outcomes(None, "<vitest wrote no json report>")
    result["collect_errors"] = []
    echoed: str | None = None
    try:
        if typecheck:
            tsc = subprocess.run(  # noqa: S603 -- the package's own binary, no shell
                [
                    str(pkg_dir / "node_modules/.bin/tsc"),
                    "--noEmit",
                    "--pretty",
                    "false",
                    "-p",
                    "tsconfig.json",
                ],
                cwd=str(pkg_dir),
                capture_output=True,
                text=True,
                timeout=_TYPECHECK_TIMEOUT_SECONDS,
                check=False,
            )
            if tsc.returncode != 0:
                output = tsc.stdout + tsc.stderr
                first = (output.strip().splitlines() or ["?"])[0]
                result["collect_errors"] = ["tsc: " + first[:200]]
                result.update(
                    exitstatus=tsc.returncode,
                    returncode=tsc.returncode,
                    stdout_tail=tsc.stdout[-2000:],
                    stderr_tail=tsc.stderr[-1000:],
                )
                stopped_by_tsc = {
                    "tsc_returncode": tsc.returncode,
                    "form_codes": tsc_form_codes(output),
                    "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
                }
                return SuiteRun(result, str(report_path), nonce, None, stopped_by_tsc)
        proc = subprocess.run(  # noqa: S603 -- the package's own binary, no shell
            [
                str(pkg_dir / "node_modules/.bin/vitest"),
                "run",
                "--reporter=json",
                f"--outputFile={report_path}",
                *selectors,
            ],
            cwd=str(pkg_dir),
            capture_output=True,
            text=True,
            timeout=_SUITE_TIMEOUT_SECONDS,
            check=False,
        )
        reports = [entry for entry in report_dir.iterdir() if _VITEST_REPORT.match(entry.name)]
        report: Any = None
        if len(reports) == 1:
            try:
                report = json.loads(reports[0].read_bytes())
            except (OSError, ValueError):
                report = None
            match = _VITEST_REPORT.match(reports[0].name)
            if report is not None and match is not None:
                echoed = match["nonce"]
        if not isinstance(report, dict):
            result.update(
                collect_errors=["<vitest wrote no json report>"],
                exitstatus=proc.returncode,
                returncode=proc.returncode,
                stdout_tail=proc.stdout[-3000:],
                stderr_tail=proc.stderr[-2000:],
            )
            return SuiteRun(result, str(report_path), nonce, None)
        failed: list[str] = []
        why: dict[str, str] = {}
        ran = 0
        for suite in report.get("testResults", []):
            assertions = suite.get("assertionResults", [])
            if not assertions and suite.get("status") == "failed":
                result["collect_errors"].append(
                    f"{suite.get('name', '?')}: file failed with no test results"
                )
            for assertion in assertions:
                ran += 1
                if assertion.get("status") == "failed":
                    name = assertion.get("fullName") or assertion.get("title") or "?"
                    failed.append(name)
                    messages = " ".join(assertion.get("failureMessages") or [])
                    kind = "AssertionError"
                    for marker in TS_FORM_ERRORS:
                        if marker in messages:
                            kind = marker if marker.endswith("Error") else f"FormError({marker})"
                            break
                    why[name] = kind
        result.update(
            exitstatus=proc.returncode,
            collected_and_run=ran,
            n_passed=ran - len(failed),
            n_failed=len(failed),
            failed=sorted(failed),
            why=why,
            returncode=proc.returncode,
            stdout_tail=proc.stdout[-3000:],
            stderr_tail=proc.stderr[-2000:],
        )
        return SuiteRun(result, str(report_path), nonce, echoed)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["collect_errors"] = [f"<vitest did not run: {exc}>"]
        return SuiteRun(result, str(report_path), nonce, None)
    finally:
        shutil.rmtree(report_dir, ignore_errors=True)


def _run_suite(
    tree: Path, launcher: Sequence[str], mutant: dict[str, Any], *, typecheck: bool, mutated: bool
) -> SuiteRun:
    """Run a mutant's suite: the baseline when `mutated` is false, the mutated run otherwise."""
    if mutant.get("runner", "pytest") == "vitest":
        return run_vitest(tree, mutant["pkg"], mutant["suite"], typecheck=typecheck and mutated)
    is_plugin = mutant.get("kind", "source") == "plugin"
    return run_pytest(
        tree,
        launcher,
        mutant["suite"],
        plugin=mutant["plugin"] if is_plugin and mutated else None,
        tree_on_path=is_plugin,
    )


def _measurement_problems(run: SuiteRun, label: str) -> list[str]:
    """Why a suite run does not count as measured, or nothing if it does.

    A run that `tsc` stopped is measured by its `typecheck` trace, and only by it: a
    non-zero exit and at least one source diagnostic code. Every other run is measured
    by its nonce, echoed back as issued. Either way the outcome record must be coherent.
    """
    problems: list[str] = []
    if run.typecheck is not None:
        if run.typecheck["tsc_returncode"] == 0 or not run.typecheck["form_codes"]:
            problems.append(
                f"typecheck: {label}: tsc exited {run.typecheck['tsc_returncode']} with source "
                f"diagnostic codes {run.typecheck['form_codes']} (output sha256 "
                f"{run.typecheck['output_sha256']}); a run stopped by tsc is measured only by a "
                "non-zero exit with at least one ': error TS<digits>:' diagnostic"
            )
    elif run.nonce_echoed != run.nonce_issued:
        problems.append(
            f"nonce: {label}: the outcomes read from {run.outcomes_path} carry nonce "
            f"{run.nonce_echoed!r}, but this run was issued {run.nonce_issued}"
        )
    try:
        validate_outcomes(run.outcomes, label=f"{label} ({run.outcomes_path})")
    except IncoherentOutcomes as exc:
        problems.append(f"outcomes: {exc}")
    return problems


def _nonce_trace(run: SuiteRun) -> dict[str, str | None]:
    """The `nonce` field of a row."""
    return {"issued": run.nonce_issued, "echoed": run.nonce_echoed}


def _ledger_of(record: journal.Record) -> dict[str, Any]:
    """The `ledger` field of a row, from the journal's record of the mutation."""
    return {
        "record": record.name,
        "sha_before": record.sha_before,
        "sha_after": record.sha_after,
        "confirmed_on_disk": record.confirmed_on_disk,
    }


def _named_reds(baseline: SuiteRun, mutated: SuiteRun, mutant: dict[str, Any]) -> dict[str, Any]:
    """For each name in `expect_red` that went red, the `why` of every red test it names.

    Which failed tests a name names is decided by `classify()` itself: the failed
    tests a single-name classification does not report as collateral.
    """
    failed: list[str] = mutated.outcomes["failed"]
    why: dict[str, str] = mutated.outcomes.get("why", {})
    named: dict[str, Any] = {}
    for name in mutant["expect_red"]:
        single = classify(baseline.outcomes, mutated.outcomes, [name])
        matched = sorted(set(failed) - set(single["collateral_red"]))
        if matched:
            named[name] = {test: why.get(test, "unknown") for test in matched}
    return named


# --- the run --------------------------------------------------------------------------------------


def _row_head(mutant: dict[str, Any]) -> dict[str, Any]:
    """The fields every row carries, before anything is run for it."""
    kind = mutant.get("kind", "source")
    row: dict[str, Any] = {
        "id": mutant["id"],
        "property": mutant["property"],
        "kind": kind,
        "runner": mutant.get("runner", "pytest"),
        "expect_verdict": mutant.get("expect_verdict"),
        "verdict": None,
        "why": "",
        "confirmed": False,
        "unmeasured": [],
        "ledger": None,
        "git_dirty_during": None,
        "nonce": None,
        "typecheck": None,
        "baseline_nonce": None,
        "named_reds": {},
    }
    if kind == "plugin":
        row["plugin"] = mutant["plugin"]
    else:
        row["file"] = mutant["file"]
    return row


def _run_mutants(
    owner: journal.JournalOwner,
    tree: Path,
    launcher: Sequence[str],
    mutants: list[dict[str, Any]],
    progress: _Progress,
    *,
    typecheck: bool,
) -> None:
    """Measure every mutant inside the held journal, recording into `progress` as it goes.

    `progress` is filled while the run advances, so a journal refusal that stops the
    run midway still leaves the ids tried and the rows completed for the caller to
    report.
    """
    rows = progress.rows
    runs = progress.runs
    baselines: dict[tuple[Any, ...], SuiteRun] = {}
    for mutant in mutants:
        mutant_id: str = mutant["id"]
        kind = mutant.get("kind", "source")
        progress.tried.append(mutant_id)
        print(f"[mutant] {mutant_id}", flush=True)
        row = _row_head(mutant)
        key = (
            mutant.get("runner", "pytest"),
            mutant.get("pkg"),
            tuple(mutant["suite"]),
            kind == "plugin",
        )
        if key not in baselines:
            baselines[key] = _run_suite(tree, launcher, mutant, typecheck=False, mutated=False)
            runs.append(baselines[key])
        baseline = baselines[key]
        row["baseline_nonce"] = _nonce_trace(baseline)
        baseline_problems = _measurement_problems(baseline, f"{mutant_id} baseline")
        if baseline_problems:
            row.update(unmeasured=baseline_problems, why="the baseline was not measured")
            rows.append(row)
            continue
        if baseline.outcomes["n_failed"] or baseline.outcomes["collect_errors"]:
            row.update(
                verdict="BASELINE_RED",
                why="the suite is not green before mutating",
                failed=baseline.outcomes["failed"],
                collect_errors=baseline.outcomes["collect_errors"],
            )
            rows.append(row)
            continue

        record: journal.Record | None = None
        if kind == "source":
            try:
                record = owner.apply_source(mutant["file"], mutant["old"], mutant["new"])
            except journal.MutationDidNotLand as exc:
                if exc.record is not None:
                    row["ledger"] = _ledger_of(exc.record)
                    # A refusal to put the record back is the journal's to report: it
                    # propagates and decides the exit.
                    owner.restore(exc.record)
                row.update(verdict="NOT_APPLIED", why=str(exc))
                rows.append(row)
                continue
            row["ledger"] = _ledger_of(record)
            expected_git: list[str] = [f" M {mutant['file']}"]
        else:
            plugin_path = Path(*mutant["plugin"].split("."))
            plugin_file = tree / f"{plugin_path}.py"
            if not plugin_file.is_file():
                plugin_file = tree / plugin_path / "__init__.py"
            row["ledger"] = {
                "plugin": mutant["plugin"],
                "sha_of_plugin_file": _sha256_of_file(plugin_file),
            }
            expected_git = []

        try:
            git_dirty_during = _porcelain_during_mutation(tree)
            mutated = _run_suite(tree, launcher, mutant, typecheck=typecheck, mutated=True)
        finally:
            if record is not None:
                owner.restore(record)
        runs.append(mutated)

        label = f"{mutant_id} mutated"
        problems: list[str] = []
        if kind == "source" and not (record is not None and record.confirmed_on_disk):
            problems.append(f"ledger: {label}: the record was not confirmed on disk")
        if kind == "plugin":
            if row["ledger"]["sha_of_plugin_file"] == "absent":
                problems.append(f"ledger: {label}: the plugin file is absent from {tree}")
            loaded = (
                mutated.outcomes.get("plugins_loaded")
                if isinstance(mutated.outcomes, dict)
                else None
            )
            if not (isinstance(loaded, list) and mutant["plugin"] in loaded):
                problems.append(
                    f"plugin: {label}: {mutant['plugin']} is not in the plugins_loaded of "
                    f"{mutated.outcomes_path}"
                )
        if git_dirty_during != expected_git:
            problems.append(
                f"git_dirty_during: {label}: git status showed {git_dirty_during}, "
                f"expected {expected_git}"
            )
        problems += _measurement_problems(mutated, label)
        row["git_dirty_during"] = git_dirty_during
        if mutated.typecheck is not None:
            row.update(typecheck=mutated.typecheck, nonce=None)
        else:
            row.update(typecheck=None, nonce=_nonce_trace(mutated))
        if problems:
            row.update(unmeasured=problems, why="the mutated run was not measured")
            rows.append(row)
            continue

        row.update(
            classify(
                baseline.outcomes,
                mutated.outcomes,
                mutant["expect_red"],
                red_is_crash=bool(mutant.get("property_red_is_crash")),
            )
        )
        row["confirmed"] = True
        row["named_reds"] = _named_reds(baseline, mutated, mutant)
        rows.append(row)


def _row_line(row: dict[str, Any]) -> str:
    """One row of the printed summary."""
    if row["verdict"] is None:
        return f"{row['id']}: UNMEASURED -- " + "; ".join(row["unmeasured"])
    if row["verdict"] in ("NOT_APPLIED", "BASELINE_RED"):
        return f"{row['id']}: {row['verdict']} -- {row['why']}"
    line = f"{row['id']}: {row['verdict']} ({row['n_failed']}/{row['n_collected']} red)"
    if row.get("expected_red_that_stayed_GREEN"):
        line += f"  MISSED={row['expected_red_that_stayed_GREEN']}"
    return line


def _journal_refusals(error: BaseException) -> list[journal.JournalError]:
    """Every journal refusal that decides an exit in the chain of `error`, the oldest first.

    A refusal raised while another one was propagating -- a holder that fails to put
    a record back while leaving the journal after an earlier refusal -- carries the
    earlier one only as its context; both are reported, and both count for the exit.
    """
    found: list[journal.JournalError] = []
    seen: set[int] = set()
    pending: list[BaseException] = [error]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, journal.JournalError) and current.exit_code is not None:
            found.append(current)
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                pending.append(linked)
    found.reverse()
    return found


def _journal_exit_code(refusals: Sequence[journal.JournalError]) -> int | None:
    """The exit the journal refusals decide, by `_JOURNAL_EXIT_PRECEDENCE`; `None` if none."""
    codes = {refusal.exit_code for refusal in refusals}
    for code in _JOURNAL_EXIT_PRECEDENCE:
        if code in codes:
            return code
    return None


def _restore(tree: Path) -> int:
    """`--restore`: replay a dead holder's journal; the journal prints the summary line."""
    summary = journal.restore_journal(tree)
    if summary.unknown_state > 0:
        return journal.EXIT_UNKNOWN_STATE
    if summary.exchange_unavailable > 0:
        return journal.EXIT_EXCHANGE_UNAVAILABLE
    return EXIT_OK


def _journal_entry_check(tree: Path) -> int | None:
    """The exit for a journal already under `tree` before anything starts, or `None`.

    A journal that is present means files of the tree may still hold a mutation, so
    what item 0 would read -- an anchor it finds absent -- would describe that
    mutation, not the tree. With `owner.json` the journal is held or left by a killed
    holder (8); without it, it is a directory nobody can vouch for (5). It is never
    touched.
    """
    journal_dir = tree / journal.JOURNAL_DIRNAME
    if os.path.lexists(journal_dir):
        if (journal_dir / journal.OWNER_FILENAME).exists():
            print(journal._busy_message(journal_dir), file=sys.stderr)
            return journal.EXIT_JOURNAL_BUSY
        print(
            f"REFUSING: {journal_dir} exists without {journal.OWNER_FILENAME} -- a process killed "
            "before writing it, or something else made it; not touching it: run --restore, "
            "which names the way out",
            file=sys.stderr,
        )
        return EXIT_DIRTY_BEFORE
    return None


def _print_partial_summary(tree: Path, progress: _Progress) -> None:
    """The summary of a run that a journal refusal stopped; no results file is written.

    It names the ids tried up to the stop, the one in progress included, how many of
    them were confirmed out of those attempted, and the records the journal still
    holds, read from the directory without touching it.
    """
    finished = {row["id"]: row for row in progress.rows}
    confirmed = sum(1 for row in progress.rows if row["confirmed"])
    attempted = sum(
        1
        for mutant_id in progress.tried
        if mutant_id not in finished or finished[mutant_id]["verdict"] != "BASELINE_RED"
    )
    print("=== PARTIAL SUMMARY: the run stopped on a journal refusal ===")
    print("mutant_ids: " + json.dumps(progress.tried))
    print(f"applications_confirmed={confirmed}/{attempted}")
    journal_dir = tree / journal.JOURNAL_DIRNAME
    try:
        entries = [entry.name for entry in journal_dir.iterdir()] if journal_dir.is_dir() else []
    except OSError as exc:
        print(f"records_left: the journal {journal_dir} cannot be listed ({exc})")
    else:
        names = {match["name"] for name in entries if (match := _RECORD_FILE.match(name))}
        print("records_left: " + json.dumps(sorted(names)))
    print(
        "results: not written (the run stopped on a journal refusal); this summary is the "
        "only record of the run"
    )


def _preflight(spec_path: Path, tree: Path) -> int:
    """`--preflight`: the entry checks up to item 0, then item 0 and nothing else."""
    journal_exit = _journal_entry_check(tree)
    if journal_exit is not None:
        return journal_exit
    raw, load_problems, repeated = _load_spec(spec_path)
    count, problems = (
        (0, load_problems) if load_problems else item_zero(raw, tree, tree_checks=True)
    )
    problems = [*_repeated_key_problems(raw, repeated), *problems]
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"preflight: {count} mutants, problems: {len(problems)}")
    return EXIT_INVALID if problems else EXIT_OK


def _run(args: argparse.Namespace, tree: Path, argv: Sequence[str]) -> int:
    """`ablate.py <spec>`: the entry checks in their order, the run, the summary and the exit."""
    entry_exit = _journal_entry_check(tree)
    if entry_exit is not None:
        return entry_exit

    spec_path = Path(args.spec)
    raw, load_problems, repeated = _load_spec(spec_path)
    count, problems = (
        (0, load_problems)
        if load_problems
        else item_zero(raw, tree, tree_checks=not args.skip_preflight)
    )
    problems = [*_repeated_key_problems(raw, repeated), *problems]
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"preflight: {count} mutants, problems: {len(problems)}")
        return EXIT_INVALID

    wanted = [part.strip() for part in (args.only or "").split(",") if part.strip()]
    all_mutants: list[dict[str, Any]] = raw["mutants"]
    unknown = sorted(set(wanted) - {m["id"] for m in all_mutants})
    if unknown:
        print(f"REFUSING: --only names ids that are not in the spec: {unknown}", file=sys.stderr)
        return EXIT_NOTHING_SELECTED
    mutants = [m for m in all_mutants if args.only is None or m["id"] in wanted]
    if not mutants:
        print("REFUSING: --only selects no mutant of the spec", file=sys.stderr)
        return EXIT_NOTHING_SELECTED

    dirty_before = _porcelain(tree)
    if dirty_before is None or dirty_before:
        print(
            f"REFUSING: {tree} is dirty before the run, or git cannot say "
            f"(git status --porcelain --untracked-files=normal): {dirty_before}",
            file=sys.stderr,
        )
        return EXIT_DIRTY_BEFORE

    launcher: list[str] = raw.get("launcher", list(DEFAULT_LAUNCHER))
    progress = _Progress()
    try:
        with journal.journal_owner(tree, ["ablate.py", *argv]) as owner:
            _run_mutants(owner, tree, launcher, mutants, progress, typecheck=not args.no_typecheck)
    except journal.JournalError as exc:
        if _journal_exit_code(_journal_refusals(exc)) is not None:
            _print_partial_summary(tree, progress)
        raise
    rows, runs = progress.rows, progress.runs
    tree_dirty_after = _porcelain(tree)

    confirmed = sum(1 for row in rows if row["confirmed"])
    attempted = sum(1 for row in rows if row["verdict"] != "BASELINE_RED")
    not_applied = sum(1 for row in rows if row["verdict"] == "NOT_APPLIED")
    survived = sum(1 for row in rows if row["verdict"] == "SURVIVED" and row["confirmed"])
    declared = [row for row in rows if row["expect_verdict"] is not None]
    expectations_unmeasured = [row for row in declared if row["verdict"] is None]
    mismatches = [
        (row["id"], row["expect_verdict"], row["verdict"])
        for row in declared
        if row["verdict"] is not None and row["verdict"] != row["expect_verdict"]
    ]
    summary: dict[str, Any] = {
        "n_mutants": len(rows),
        "killed": sum(1 for row in rows if row["verdict"] == "KILLED"),
        "killed_elsewhere": sum(1 for row in rows if row["verdict"] == "KILLED_ELSEWHERE"),
        "survived": survived,
        "broken": sum(1 for row in rows if row["verdict"] == "BROKEN"),
        "not_applied": not_applied,
        "baseline_red": sum(1 for row in rows if row["verdict"] == "BASELINE_RED"),
        "unmeasured": sum(1 for row in rows if row["verdict"] is None),
        "mutant_ids": [row["id"] for row in rows],
        "applications_confirmed": confirmed,
        "applications_attempted": attempted,
        "suite_runs": len(
            {run.nonce_issued for run in runs if run.nonce_echoed == run.nonce_issued}
        ),
        "expectations_declared": len(declared),
        "expectations_failed": len(mismatches),
        "expectations_unmeasured": len(expectations_unmeasured),
        "tree_dirty_after_run": tree_dirty_after,
        "nonce_of_run": os.environ.get("ABLATION_RUN_NONCE"),
    }

    print("=== SUMMARY ===")
    print("mutant_ids: " + json.dumps(summary["mutant_ids"]))
    print(f"applications_confirmed={confirmed}/{attempted}")
    print(f"suite_runs={summary['suite_runs']}")
    print(
        " ".join(
            f"{name}={summary[name]}"
            for name in (
                "n_mutants",
                "killed",
                "killed_elsewhere",
                "survived",
                "broken",
                "not_applied",
                "baseline_red",
                "unmeasured",
            )
        )
    )
    for row in rows:
        print(_row_line(row))
    if declared:
        met = len(declared) - len(mismatches) - len(expectations_unmeasured)
        print(
            f"expectations: {len(declared)} declared, {met} met, "
            f"{len(expectations_unmeasured)} unmeasured"
        )
    if args.out is not None:
        out_path = Path(args.out)
        payload = {"summary": summary, "results": rows}
        out_path.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
        print(f"results: written to {out_path}")
    else:
        print("results: not written (no --out given); this summary is the only record of the run")

    if tree_dirty_after is None or tree_dirty_after:
        print(
            f"REFUSING: {tree} is dirty after the run, or git cannot say: {tree_dirty_after} -- "
            "a restore failed somewhere, and no verdict above can be trusted",
            file=sys.stderr,
        )
        return EXIT_DIRTY_AFTER
    if mismatches:
        for mutant_id, want, got in mismatches:
            print(
                f"EXPECTATION FAILED {mutant_id}: the spec says {want}, the bench produced {got}",
                file=sys.stderr,
            )
        return EXIT_EXPECTATION_NOT_MET
    if confirmed != attempted - not_applied:
        print(
            f"REFUSING TO CERTIFY: applications_confirmed={confirmed}, but "
            f"{attempted - not_applied} mutations had to land with their three traces; the "
            "hypothesis to falsify first is the bench, not the suite",
            file=sys.stderr,
        )
        for row in rows:
            if row["verdict"] is None:
                print(_row_line(row), file=sys.stderr)
        return EXIT_UNCONFIRMED
    if len(rows) > 1 and survived == len(rows):
        print(
            f"ALL SURVIVED: {survived} of {len(rows)} mutants survived. Check the bench before "
            "believing this number; the three traces of each row:",
            file=sys.stderr,
        )
        for row in rows:
            print(
                f"  {row['id']}: ledger={json.dumps(row['ledger'])} "
                f"git_dirty_during={json.dumps(row['git_dirty_during'])} "
                f"nonce={json.dumps(row['nonce'])} typecheck={json.dumps(row['typecheck'])}",
                file=sys.stderr,
            )
        return EXIT_ALL_SURVIVED
    return EXIT_OK


def _parser() -> _Parser:
    """The command-line parser."""
    parser = _Parser(prog="ablate.py", description=(__doc__ or "").splitlines()[0], add_help=True)
    parser.add_argument("spec", nargs="?", help="the spec JSON file")
    parser.add_argument("--tree", help="top level of the git working tree to mutate")
    parser.add_argument("--only", help="comma-separated ids of the mutants to run")
    parser.add_argument("--out", help="where to write results.json; nothing is written without it")
    parser.add_argument(
        "--no-typecheck",
        action="store_true",
        help="skip the tsc gate of vitest mutants, to prove it is load-bearing",
    )
    parser.add_argument("--preflight", action="store_true", help="validate the spec and stop")
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="skip the checks of the spec against the tree (requires --tree)",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="put back what a killed run left in the journal, then exit",
    )
    return parser


def _invocation_problem(args: argparse.Namespace) -> str | None:
    """Why the parsed arguments do not form one of the two command lines, or `None`."""
    if args.restore:
        extras = [
            flag
            for flag, value in (
                ("<spec>", args.spec),
                ("--only", args.only),
                ("--out", args.out),
                ("--no-typecheck", args.no_typecheck or None),
                ("--preflight", args.preflight or None),
                ("--skip-preflight", args.skip_preflight or None),
            )
            if value is not None
        ]
        if extras:
            return f"--restore takes only --tree, found {extras}"
        return None
    if args.spec is None:
        return "a spec file is required unless --restore is given"
    if args.preflight and args.skip_preflight:
        return "--preflight and --skip-preflight exclude each other"
    if args.skip_preflight and args.tree is None:
        return "--skip-preflight is allowed only with an explicit --tree"
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the exit status."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _parser().parse_args(arguments)
    except _UsageError as exc:
        print(f"ablate.py: error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    problem = _invocation_problem(args)
    if problem is not None:
        print(f"ablate.py: error: {problem}", file=sys.stderr)
        return EXIT_INVALID
    tree, reason = _resolve_tree(args.tree)
    if tree is None:
        print(f"ablate.py: error: {reason}", file=sys.stderr)
        return EXIT_INVALID
    try:
        if args.restore:
            return _restore(tree)
        if args.preflight:
            return _preflight(Path(args.spec), tree)
        return _run(args, tree, arguments)
    except journal.JournalError as exc:
        refusals = _journal_refusals(exc)
        code = _journal_exit_code(refusals)
        if code is None:
            raise
        for refusal in refusals:
            print(refusal, file=sys.stderr)
        return code


if __name__ == "__main__":
    sys.exit(main())
