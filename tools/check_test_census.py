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


def read_report(report_path: Path, suite_root: Path) -> tuple[dict[str, int], int, int, int]:
    """Per-file test counts, the run's own total, and its pending/todo counts."""
    report = json.loads(report_path.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    for entry in report["testResults"]:
        name = Path(entry["name"])
        try:
            relative = name.relative_to(suite_root).as_posix()
        except ValueError:
            relative = name.as_posix()
        counts[relative] = len(entry["assertionResults"])
    return (
        counts,
        int(report["numTotalTests"]),
        int(report.get("numPendingTests", 0)),
        int(report.get("numTodoTests", 0)),
    )


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
    data = json.loads(census_path.read_text(encoding="utf-8"))
    suites = data["suites"]
    if suite not in suites:
        raise SystemExit(f"{census_path}: no census for suite {suite!r}")
    return {str(k): int(v) for k, v in suites[suite]["files"].items()}


def write_census(census_path: Path, suite: str, run: dict[str, int], run_total: int) -> None:
    data = json.loads(census_path.read_text(encoding="utf-8"))
    data["suites"][suite] = {
        "total": run_total,
        "files": {name: run[name] for name in sorted(run)},
    }
    census_path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


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
    return 1 if failures else 0


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
        missing = sorted(on_disk - set(run))
        if missing:
            raise SystemExit(
                "refusing to update the census while these files were not collected: "
                + ", ".join(missing)
                + ". Fix the collection first -- recording an absence is what this check "
                "exists to prevent."
            )
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
