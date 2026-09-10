#!/usr/bin/env python3
"""Fail the build when a test file stops being collected, instead of lowering a total.

A suite that goes from 880 tests to 864 reports a bigger number than it did last month
and nobody reads it as a loss. That is not a hypothetical: `site/test/rail-state.property
.test.ts` imported `desktop/src/app.ts`, the `site` job installs `site/node_modules` and
not `desktop/node_modules`, so `attest-verifier` did not resolve, and vitest collected
ZERO tests from the file. Sixteen assertions ran on developer machines and in no CI job.
The transform error happened to be loud that day; a file that stops matching the include
glob, gets renamed, or has its `describe` skipped is silent, and the only trace is a
smaller total in a line nobody compares.

So the expected count is asserted rather than printed. This reads the JSON report vitest
writes, the census this repository commits, and the test files actually on disk, and it
demands the three agree:

  * every test file on disk was collected and ran at least one test;
  * every file the run reported is in the census, with the census's count;
  * the run's own total equals the sum of the census;
  * nothing was skipped or left todo -- a pending test is an absent test.

Usage, per suite (`site` and `desktop` are directory names):

    npm test --prefix site -- --reporter=default --reporter=json \\
        --outputFile.json="$RUNNER_TEMP/site-tests.json"
    python3 tools/check_test_census.py site --report "$RUNNER_TEMP/site-tests.json"

Adding or removing tests is expected to move these numbers; `--update` rewrites the
census from a report. It REFUSES to do so while a file on disk is missing from that
report, because blessing an absence is the one thing this file exists to prevent.

`--selftest` runs the comparison against synthetic inputs -- one healthy, four broken --
and checks it names each defect. A guard that has only ever been seen passing is not
known to catch anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CENSUS = REPO_ROOT / "tools" / "test-census.json"

# Mirrors vitest's default `include` and the `exclude` both shells configure: their
# vitest.config.ts adds only 'e2e/**' to configDefaults.exclude, and every suite keeps
# its files under <suite>/test/.
_TEST_MARKERS = (".test.", ".spec.")
_TEST_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_SKIP_DIRS = frozenset({"node_modules", "dist", "e2e", ".git", "coverage"})


def is_test_file(path: Path) -> bool:
    """True for a file vitest's default include pattern would pick up."""
    return path.suffix in _TEST_EXTENSIONS and any(m in path.name for m in _TEST_MARKERS)


def disk_files(suite_root: Path) -> set[str]:
    """Every test file under `suite_root`, as a path relative to it."""
    found: set[str] = set()
    for path in suite_root.rglob("*"):
        if not path.is_file() or not is_test_file(path):
            continue
        relative = path.relative_to(suite_root)
        if _SKIP_DIRS.intersection(relative.parts):
            continue
        found.add(relative.as_posix())
    return found


def _json_object(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member {key!r}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"non-JSON number {value}")

    try:
        data = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique,
            parse_constant=invalid_constant,
        )
    except ValueError as exc:
        raise SystemExit(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected an object")
    return data


def _count(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise SystemExit(f"{label}: expected a non-negative integer")
    return value


def read_report(report_path: Path, suite_root: Path) -> tuple[dict[str, int], int, int, int]:
    """Admit the report before comparing counts; never coerce malformed input."""
    report = _json_object(report_path)
    entries = report.get("testResults")
    if not isinstance(entries, list):
        raise SystemExit("testResults: expected an array")
    counts: dict[str, int] = {}
    statuses = dict.fromkeys(("passed", "failed", "pending", "todo"), 0)
    # vitest's own JsonReporter (site/node_modules/vitest/dist/chunks/index.*.js,
    # StatusMap + numPendingTests filter) emits the per-assertion status "skipped"
    # for a `.skip()`'d test, but counts that same test toward the aggregate
    # numPendingTests field -- "pending" and "skipped" are the same event under two
    # different names at two different levels of the same report. Recognize both,
    # bucket "skipped" under "pending" so the tie-check against numPendingTests below
    # holds for the report vitest actually produces.
    _STATUS_BUCKET = {
        "passed": "passed",
        "failed": "failed",
        "pending": "pending",
        "skipped": "pending",
        "todo": "todo",
    }
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise SystemExit("testResults: expected an object with a string name")
        name = Path(entry["name"])
        try:
            relative = name.relative_to(suite_root).as_posix()
        except ValueError:
            relative = name.as_posix()
        if relative in counts:
            raise SystemExit(f"duplicate test file {relative!r}")
        assertions = entry.get("assertionResults")
        if not isinstance(assertions, list):
            raise SystemExit(f"{relative}: assertionResults must be an array")
        for assertion in assertions:
            if not isinstance(assertion, dict):
                raise SystemExit(f"{relative}: an assertion must be an object")
            status = assertion.get("status")
            bucket = _STATUS_BUCKET.get(status) if isinstance(status, str) else None
            if bucket is None:
                raise SystemExit(f"{relative}: invalid assertion status")
            statuses[bucket] += 1
        counts[relative] = len(assertions)
    total = _count(report.get("numTotalTests"), "numTotalTests")
    if total != sum(counts.values()):
        raise SystemExit("numTotalTests disagrees with assertionResults")
    for status, field in (
        ("passed", "numPassedTests"),
        ("failed", "numFailedTests"),
        ("pending", "numPendingTests"),
        ("todo", "numTodoTests"),
    ):
        if _count(report.get(field), field) != statuses[status]:
            raise SystemExit(f"{field} disagrees with assertion statuses")
    return counts, total, statuses["pending"], statuses["todo"]


def compare(
    *,
    suite: str,
    disk: Iterable[str],
    run: dict[str, int],
    census: dict[str, int],
    run_total: int,
    pending: int,
    todo: int,
) -> list[str]:
    """Every disagreement between the files on disk, the run, and the census."""
    problems: list[str] = []
    disk_set = set(disk)
    run_files = set(run)
    census_files = set(census)

    for name in sorted(disk_set - run_files):
        problems.append(
            f"{suite}: {name} is on disk and the run collected NO tests from it. "
            "Either it stopped matching the include pattern, or it failed to load. "
            "This is the absence this check exists to turn red."
        )
    for name in sorted(name for name in disk_set & run_files if run[name] == 0):
        problems.append(
            f"{suite}: {name} was collected but ran 0 tests -- an empty file counts as absent."
        )
    for name in sorted(run_files - disk_set):
        problems.append(f"{suite}: the run reported {name}, which is not on disk.")
    for name in sorted(census_files - run_files):
        problems.append(
            f"{suite}: the census expects {census[name]} test(s) from {name} and the run "
            "reported none. If the file was deleted on purpose, regenerate the census."
        )
    for name in sorted(run_files - census_files):
        problems.append(
            f"{suite}: {name} ran {run[name]} test(s) and is not in the census. "
            "A new test file is registered, not inferred."
        )
    for name in sorted(run_files & census_files):
        if run[name] != census[name]:
            problems.append(
                f"{suite}: {name} ran {run[name]} test(s), the census records {census[name]}."
            )

    expected_total = sum(census.values())
    if run_total != expected_total:
        problems.append(
            f"{suite}: the run reports {run_total} test(s) in total, the census sums to "
            f"{expected_total}."
        )
    if pending or todo:
        problems.append(
            f"{suite}: the run left {pending} test(s) pending and {todo} todo. "
            "A skipped test is an absent test; unskip it or delete it."
        )
    return problems


def load_census(census_path: Path, suite: str) -> dict[str, int]:
    data = _json_object(census_path)
    suites = data.get("suites")
    if not isinstance(suites, dict) or suite not in suites:
        raise SystemExit(f"{census_path}: no census for suite {suite!r}")
    selected = suites[suite]
    if not isinstance(selected, dict) or set(selected) != {"total", "files"}:
        raise SystemExit(f"{suite}: expected exactly total and files")
    files = selected["files"]
    if not isinstance(files, dict):
        raise SystemExit(f"{suite}: files must be an object")
    counts = {name: _count(value, name) for name, value in files.items()}
    total = _count(selected["total"], f"{suite}.total")
    if total != sum(counts.values()):
        raise SystemExit(f"{suite}: census total {total} disagrees with its file counts")
    return counts


def write_census(census_path: Path, suite: str, run: dict[str, int], run_total: int) -> None:
    data = _json_object(census_path)
    data["suites"][suite] = {
        "total": run_total,
        "files": {name: run[name] for name in sorted(run)},
    }
    census_path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def selftest_cli() -> int:
    """Exercise discovery, report admission and the actual process exit status."""
    import subprocess
    from tempfile import TemporaryDirectory

    failures = 0
    with TemporaryDirectory(prefix="test-census-selftest-") as tmp:
        root = Path(tmp)
        suite = root / "suite"
        (suite / "test").mkdir(parents=True)
        counts = {"test/a.test.ts": 3, "test/b.test.ts": 5}
        for name in counts:
            (suite / name).write_text("// census fixture\n", encoding="utf-8")
        census_path = root / "census.json"
        census_path.write_text(
            json.dumps(
                {
                    "suites": {
                        str(suite): {"total": 8, "files": counts},
                    }
                }
            ),
            encoding="utf-8",
        )
        report_path = root / "report.json"

        def report(values: dict[str, int], skipped: bool = False) -> None:
            total = sum(values.values())
            entries: list[dict[str, Any]] = [
                {
                    "name": str(suite / name),
                    "assertionResults": [{"status": "passed"} for _ in range(n)],
                }
                for name, n in values.items()
            ]
            if skipped:
                entries[0]["assertionResults"][0]["status"] = "skipped"
            report_path.write_text(
                json.dumps(
                    {
                        "numTotalTests": total,
                        "numPassedTests": total - int(skipped),
                        "numFailedTests": 0,
                        "numPendingTests": int(skipped),
                        "numTodoTests": 0,
                        "testResults": entries,
                    }
                ),
                encoding="utf-8",
            )

        def check(label: str, code: int, expected: str) -> None:
            nonlocal failures
            result = subprocess.run(  # noqa: S603 -- own script and synthetic local fixtures
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    str(suite),
                    "--census",
                    str(census_path),
                    "--report",
                    str(report_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            output = result.stdout + result.stderr
            if result.returncode != code or expected not in output:
                failures += 1
                print(f"  FAIL CLI {label}: exit {result.returncode}; {output!r}")
            else:
                print(f"  ok   CLI {label}")

        report(counts)
        check("healthy", 0, "2 test file(s), 8 test(s) -- matches the census")
        for label, values, expected in (
            ("added test", {**counts, "test/b.test.ts": 6}, "ran 6 test(s)"),
            ("removed test", {**counts, "test/b.test.ts": 4}, "ran 4 test(s)"),
            ("uncollected file", {"test/a.test.ts": 3}, "collected NO tests"),
            ("empty file", {**counts, "test/b.test.ts": 0}, "ran 0 tests"),
            ("empty report", {}, "collected NO tests"),
        ):
            report(values)
            check(label, 1, expected)
        report(counts, skipped=True)
        check("skipped test", 1, "1 test(s) pending")
        report(counts)
        nested = suite / "test" / "nested"
        nested.mkdir()
        extra = nested / "new.test.ts"
        extra.write_text("// uncollected fixture\n", encoding="utf-8")
        check("new nested file not collected", 1, "test/nested/new.test.ts")
        extra.unlink()
        report_path.write_text("{", encoding="utf-8")
        check("malformed report", 1, str(report_path))
        report_path.unlink()
        check("missing report", 1, "FileNotFoundError")
        report(counts)
        suite.rename(root / "absent-suite")
        check("missing suite", 1, "no such suite directory")
    return 1 if failures else 0


def selftest() -> int:
    """Point the comparison at defects it must name, and report each case."""
    healthy = {
        "suite": "demo",
        "disk": {"test/a.test.ts", "test/b.test.ts"},
        "run": {"test/a.test.ts": 3, "test/b.test.ts": 5},
        "census": {"test/a.test.ts": 3, "test/b.test.ts": 5},
        "run_total": 8,
        "pending": 0,
        "todo": 0,
    }
    cases: list[tuple[str, dict[str, object], str]] = [
        (
            "a file on disk that the run never collected",
            {"run": {"test/a.test.ts": 3}, "run_total": 3},
            "test/b.test.ts",
        ),
        (
            "a file collected with zero tests",
            {"run": {"test/a.test.ts": 3, "test/b.test.ts": 0}, "run_total": 3},
            "ran 0 tests",
        ),
        (
            "a file whose count drifted",
            {"run": {"test/a.test.ts": 3, "test/b.test.ts": 4}, "run_total": 7},
            "the census records 5",
        ),
        (
            "a new file nobody registered",
            {
                "disk": {"test/a.test.ts", "test/b.test.ts", "test/c.test.ts"},
                "run": {"test/a.test.ts": 3, "test/b.test.ts": 5, "test/c.test.ts": 1},
                "run_total": 9,
            },
            "not in the census",
        ),
        ("a skipped test", {"pending": 1}, "pending"),
    ]

    failures = 0
    problems = compare(**healthy)  # type: ignore[arg-type]
    if problems:
        failures += 1
        print(f"  FAIL healthy input reported {problems}")
    else:
        print("  ok   healthy input reports nothing")
    for label, override, expected in cases:
        problems = compare(**{**healthy, **override})  # type: ignore[arg-type]
        if any(expected in p for p in problems):
            print(f"  ok   {label} -> named ({expected!r})")
        else:
            failures += 1
            print(f"  FAIL {label} -> {expected!r} not named; got {problems}")
    print(f"selftest: {6 - failures}/6")
    cli_failures = selftest_cli()
    return 1 if failures or cli_failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", nargs="?", help="suite directory name, e.g. site or desktop")
    parser.add_argument("--report", type=Path, help="vitest --reporter=json output file")
    parser.add_argument("--census", type=Path, default=DEFAULT_CENSUS)
    parser.add_argument("--update", action="store_true", help="rewrite the census from the report")
    parser.add_argument("--selftest", action="store_true", help="run the guard against defects")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.suite or not args.report:
        parser.error("a suite and --report are required unless --selftest is given")

    suite_root = REPO_ROOT / args.suite
    if not suite_root.is_dir():
        raise SystemExit(f"no such suite directory: {suite_root}")

    on_disk = disk_files(suite_root)
    run, run_total, pending, todo = read_report(args.report, suite_root)

    if args.update:
        problems = compare(
            suite=args.suite,
            disk=on_disk,
            run=run,
            census=run,
            run_total=run_total,
            pending=pending,
            todo=todo,
        )
        if problems:
            raise SystemExit("refusing to update the census: " + "; ".join(problems))
        write_census(args.census, args.suite, run, run_total)
        print(f"census updated for {args.suite}: {len(run)} file(s), {run_total} test(s)")
        return 0

    problems = compare(
        suite=args.suite,
        disk=on_disk,
        run=run,
        census=load_census(args.census, args.suite),
        run_total=run_total,
        pending=pending,
        todo=todo,
    )
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            f"\n{args.suite}: the census is tools/test-census.json. If the change is "
            "intended, regenerate it with --update (see this file's docstring).",
            file=sys.stderr,
        )
        return 1
    print(f"{args.suite}: {len(run)} test file(s), {run_total} test(s) -- matches the census")
    return 0


if __name__ == "__main__":
    sys.exit(main())
