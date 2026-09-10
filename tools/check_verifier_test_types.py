#!/usr/bin/env python3
"""Census the verifier tests' type diagnostics, strictly in both directions.

The production build covers src/ and Vitest only transpiles test/. The separate
tsconfig.t3b-probe.json exposes existing test debt, so its exit status is already
nonzero before a regression: the observable is the diagnostic count per file.
An increase fails; a decrease also fails and requires an explicit --update.

This follows check_test_census.py, including its JSON shape, disk discovery,
strict JSON admission, --update refusal when a disk file was not compiled, and
synthetic --selftest. Zero-diagnostic files are registered too. Counts, rather
than error codes or source positions, keep the same census format and tolerate
diagnostic reclassification and line movement. A substitution of diagnostics
within one file that preserves its count is outside this census's guarantee.

The same tsc invocation produces diagnostics and --listFiles. That list supplies
the independent MEASURED marker: test files actually compiled, not error counts.
Empty or unrecognizable output, unexpected process status, and diagnostics outside
the test-file census cannot be blessed by --update. Indented diagnostic details
are continuations, not additional errors. Exit status is checked for coherence,
never used as the debt comparison.

Usage:
    python3 tools/check_verifier_test_types.py
    python3 tools/check_verifier_test_types.py --update
    python3 tools/check_verifier_test_types.py --selftest

Exits: 0 = matches / validated update / selftest passes; 1 = census disagreement,
invalid census, or refused update; 2 = unable to measure (also CLI usage errors);
78 = missing node_modules, tsc, or node prerequisite. --selftest needs none of them.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_test_census import disk_files, is_test_file, load_census, write_census

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE = "verifiers/ts"
DEFAULT_CENSUS = REPO_ROOT / "tools" / "verifier-test-types-census.json"
DEFAULT_TSC = REPO_ROOT / SUITE / "node_modules" / ".bin" / "tsc"
PROBE = REPO_ROOT / SUITE / "tsconfig.t3b-probe.json"
_DIAGNOSTIC = re.compile(r"^(.+)\([1-9]\d*,[1-9]\d*\): error TS\d+: .+")


class MeasurementError(ValueError):
    """The probe did not produce an interpretable measurement."""


def read_probe(output: str, returncode: int, suite_root: Path) -> tuple[dict[str, int], int]:
    """Read tsc --pretty false --listFiles, without inferring compilation from errors."""
    if not output.strip():
        raise MeasurementError("empty probe output; no compilation measured")
    compiled: set[Path] = set()
    diagnostics: Counter[Path] = Counter()
    continuation = False
    for line in output.splitlines():
        if not line.strip():
            continue
        match = _DIAGNOSTIC.match(line)
        if match:
            name = Path(match[1])
            if not name.is_absolute():
                name = REPO_ROOT / name
            diagnostics[name.resolve()] += 1
            continuation = True
        elif line.startswith((" ", "\t")) and continuation:
            continue
        elif Path(line).is_absolute() and Path(line).is_file():
            name = Path(line).resolve()
            if name in compiled:
                raise MeasurementError(f"duplicate compiled file: {line}")
            compiled.add(name)
            continuation = False
        else:
            raise MeasurementError(f"unrecognized probe output: {line}")

    total = sum(diagnostics.values())
    expected_status = 2 if total else 0
    if returncode != expected_status:
        raise MeasurementError(
            f"probe exited {returncode}; {total} diagnostics require tsc status {expected_status}"
        )
    run: dict[str, int] = {}
    test_paths: set[Path] = set()
    for path in sorted(compiled):
        if path.is_relative_to(suite_root) and is_test_file(path):
            run[path.relative_to(suite_root).as_posix()] = diagnostics[path]
            test_paths.add(path)
    for path in sorted(diagnostics.keys() - test_paths):
        raise MeasurementError(f"diagnostic outside compiled test-file census: {path}")
    return run, total


def compare(
    *,
    disk: Iterable[str],
    run: dict[str, int],
    census: dict[str, int],
    run_total: int,
) -> list[str]:
    """Every disagreement between disk, the compiled test files, and pinned debt."""
    problems: list[str] = []
    disk_set, run_files, census_files = set(disk), set(run), set(census)
    if not run:
        problems.append("unable to measure: no test files compiled")
    for name in sorted(disk_set - run_files):
        problems.append(f"{SUITE}: {name} is on disk but was NOT compiled by the probe.")
    for name in sorted(run_files - disk_set):
        problems.append(f"{SUITE}: compiled test {name} is not on disk.")
    for name in sorted(census_files - run_files):
        problems.append(f"{SUITE}: census file {name} was not compiled; update with --update.")
    for name in sorted(run_files - census_files):
        problems.append(f"{SUITE}: compiled test {name} is not in the census; use --update.")
    for name in sorted(run_files & census_files):
        if run[name] > census[name]:
            problems.append(
                f"{SUITE}: {name}: diagnostics increased to {run[name]}, "
                f"the census records {census[name]} (regression)."
            )
        if run[name] < census[name]:
            problems.append(
                f"{SUITE}: {name}: diagnostics decreased to {run[name]}, "
                f"the census records {census[name]}; update the census with --update."
            )
    expected_total = sum(census.values())
    if run_total != expected_total:
        problems.append(
            f"{SUITE}: total diagnostics {run_total}, the census records {expected_total}; "
            "an intended change requires --update."
        )
    return problems


def selftest() -> int:
    """Point the comparison at defects it must name, including during --update."""
    a, b, c = "test/a.test.ts", "test/b.test.ts", "test/c.test.ts"
    healthy: dict[str, Any] = {
        "disk": {a, b},
        "run": {a: 3, b: 0},
        "census": {a: 3, b: 0},
        "run_total": 3,
    }
    cases: list[tuple[str, dict[str, Any], str]] = [
        (
            "no test files compiled",
            {"disk": set(), "run": {}, "census": {}, "run_total": 0},
            "unable to measure: no test files compiled",
        ),
        (
            "disk file absent even during update",
            {"run": {a: 3}, "census": {a: 3}},
            f"{b} is on disk but was NOT compiled",
        ),
        ("compiled file absent from disk", {"disk": {a}}, f"compiled test {b} is not on disk"),
        (
            "pinned clean file deleted",
            {"disk": {a}, "run": {a: 3}},
            f"census file {b} was not compiled",
        ),
        (
            "new clean file unregistered",
            {"disk": {a, b, c}, "run": {a: 3, b: 0, c: 0}},
            f"compiled test {c} is not in the census",
        ),
        (
            "diagnostic increase",
            {"run": {a: 4, b: 0}, "run_total": 4},
            f"{a}: diagnostics increased to 4",
        ),
        (
            "diagnostic decrease requires update",
            {"run": {a: 2, b: 0}, "run_total": 2},
            f"{a}: diagnostics decreased to 2, the census records 3; "
            "update the census with --update",
        ),
        (
            "per-file drift despite unchanged total",
            {"run": {a: 2, b: 1}},
            f"{b}: diagnostics increased to 1",
        ),
        (
            "total drift",
            {"run": {a: 4, b: 0}, "run_total": 4},
            "total diagnostics 4, the census records 3",
        ),
    ]
    failures = 0
    problems = compare(**healthy)
    if problems:
        failures += 1
        print(f"  FAIL healthy input reported {problems}")
    else:
        print("  ok   healthy input, including a clean compiled file, reports nothing")
    for label, override, expected in cases:
        problems = compare(**{**healthy, **override})
        if any(expected in p for p in problems):
            print(f"  ok   {label} -> named ({expected!r})")
        else:
            failures += 1
            print(f"  FAIL {label} -> {expected!r} not named; got {problems}")
    count = len(cases) + 1
    print(f"selftest: {count - failures}/{count}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, default=DEFAULT_CENSUS)
    parser.add_argument("--tsc", type=Path, default=DEFAULT_TSC, help="path to the tsc executable")
    parser.add_argument("--update", action="store_true", help="rewrite from a complete probe run")
    parser.add_argument(
        "--selftest", action="store_true", help="run the comparison against defects"
    )
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()

    # A missing committed pin is a census failure, not a missing prerequisite.
    try:
        # This census counts diagnostics per file: there are no test names to pin,
        # so it declares the count-only contract rather than inheriting it.
        census, _ = load_census(args.census, SUITE, with_digests=False)
    except (OSError, SystemExit) as exc:
        print(f"invalid census: {exc}", file=sys.stderr)
        return 1

    suite_root = REPO_ROOT / SUITE
    for present, label in (
        ((suite_root / "node_modules").is_dir(), f"{SUITE}/node_modules"),
        (args.tsc.is_file(), f"tsc executable: {args.tsc}"),
        (shutil.which("node") is not None, "node executable on PATH"),
    ):
        if not present:
            print(
                f"unable to measure: missing prerequisite {label}; "
                "install Node.js and run npm ci --prefix verifiers/ts",
                file=sys.stderr,
            )
            return 78
    try:
        result = subprocess.run(  # noqa: S603
            [
                str(args.tsc.resolve()),
                "-p",
                str(PROBE),
                "--pretty",
                "false",
                "--noCheck",
                "false",
                "--listFiles",
                "--noEmit",
                "--incremental",
                "false",
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
        )
        run, total = read_probe(result.stdout, result.returncode, suite_root)
    except (OSError, UnicodeError, subprocess.TimeoutExpired, MeasurementError) as exc:
        print(f"unable to measure: {exc}", file=sys.stderr)
        return 2

    print(f"MEASURED: {len(run)} test file(s) compiled by the verifier probe", flush=True)
    problems = compare(
        disk=disk_files(suite_root),
        run=run,
        census=run if args.update else census,
        run_total=total,
    )
    if problems:
        if args.update:
            print("refusing to update the census:", file=sys.stderr)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if run else 2
    if args.update:
        write_census(args.census, SUITE, run, total, digests=None)
        print(f"census updated for {SUITE}: {len(run)} file(s), {total} diagnostic(s)")
    else:
        print(f"{SUITE}: {total} diagnostic(s) -- matches the census")
    return 0


if __name__ == "__main__":
    sys.exit(main())
