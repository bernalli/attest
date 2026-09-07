"""Compare two pytest report-log files by node ID and classify every test into
one of six outcomes: passed, failed, error, skipped, xfailed, xpassed.

WHY THIS EXISTS (F-05, measured)

The comparator this tool replaces read junit XML. junit does not carry a
seventh bit anywhere on a `<testcase>` element to say "this test is marked
xfail and it passed anyway": a `passed` testcase and an `xpassed` testcase
serialize to the same attributes, no child element, nothing distinguishing.
Two real runs of the identical node ID -- one where the test simply passes,
one where it is decorated `@pytest.mark.xfail(strict=False)` and the
assertion is still true -- produce indistinguishable junit records. A
comparator reading only junit reports `changed: []` for a change that
happened. See `tools/gates/g-compare.sh` for the executed proof.

pytest's own report-log format (the JSON Lines a TestReport serializes to,
either via the `pytest-reportlog` plugin or via the local plugin in
`tools/gates/reportlog_plugin.py` when that plugin is not installed) keeps
the bit: a `TestReport` has an `outcome` field of "passed" / "failed" /
"skipped", and gets a `wasxfail` attribute set by pytest's own skipping
plugin exactly when an xfail marker fired. That is the channel this
comparator reads.

OUTCOME DERIVATION

A single node ID produces one report per phase it runs through: `setup`,
`call`, and (if setup succeeded) `teardown`. This mirrors pytest's own
classification (see `_pytest/skipping.py` and `_pytest/terminal.py`):

  - a `failed` report at `setup` or `teardown` makes the node ID `error`,
    regardless of what `call` did (or whether `call` ran at all);
  - a `skipped` report at `setup` with no `call` report makes it `skipped`,
    or `xfailed` if `wasxfail` is present (an xfail marker with `run=False`
    skips the body without executing it);
  - otherwise the `call` phase decides: `passed` (`xpassed` if `wasxfail` is
    present), `failed`, or `skipped` (`xfailed` if `wasxfail` is present).

INPUT FORMAT

Each input file is JSON Lines. Only lines that parse as a JSON object
carrying `nodeid`, `when`, and `outcome` as top-level keys are read as test
reports; every other line (session markers, collect reports, warnings --
whatever `pytest-reportlog` or the local plugin also happens to write) is
ignored. This is deliberately not a `pytest-reportlog`-specific parser: the
local plugin's line shape is a subset of the real plugin's, so either
channel produces input this module can read the same way.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The six outcomes this comparator ever assigns to a node ID.
Outcome = str
OUTCOMES: tuple[Outcome, ...] = (
    "passed",
    "failed",
    "error",
    "skipped",
    "xfailed",
    "xpassed",
)


@dataclass(frozen=True)
class ReportRecord:
    """One phase report for one node ID, read from a report-log line."""

    nodeid: str
    when: str
    outcome: str
    wasxfail: bool


def iter_report_lines(path: Path) -> Iterator[dict[str, Any]]:
    """Yield the JSON objects in `path` that carry the fields a TestReport
    line always carries. Non-report lines (session markers, collect
    reports, anything else a report-log writer emits) are skipped, not
    errored on: this module only needs to recognize test reports, not parse
    the whole format.
    """
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: not valid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                continue
            if "nodeid" in obj and "when" in obj and "outcome" in obj:
                # A `nodeid` of the wrong type is a malformed report line, not a
                # line to read further and let fail somewhere downstream: it
                # gets the same treatment as an unrecognized `outcome` --
                # `MalformedRunError`, with the location and the observed type
                # in the message, instead of a bare TypeError once this value
                # reaches something that assumes a string (e.g. joining the
                # report into text).
                if not isinstance(obj["nodeid"], str):
                    raise MalformedRunError(
                        f"{path}:{line_no}: 'nodeid' is not a string "
                        f"(got {type(obj['nodeid']).__name__}): {obj['nodeid']!r}"
                    )
                yield obj


def load_report_records(path: Path) -> dict[str, dict[str, ReportRecord]]:
    """Read a report-log file into `{nodeid: {when: ReportRecord}}`.

    A node ID that reports the same `when` twice (should not happen in a
    single pytest invocation) keeps the LAST record for that phase -- the
    same "last write wins" pytest itself would apply if it re-emitted a
    phase.
    """
    by_nodeid: dict[str, dict[str, ReportRecord]] = {}
    for obj in iter_report_lines(path):
        nodeid = obj["nodeid"]
        when = obj["when"]
        outcome = obj["outcome"]
        record = ReportRecord(
            nodeid=nodeid,
            when=when,
            outcome=outcome,
            # `wasxfail` is read for TRUTH, not presence: a report-log line can
            # carry `"wasxfail": null` (pytest-reportlog serializes the
            # attribute whenever it exists on the TestReport, even when its
            # value is empty/None), and `null` is not an xfail that fired. A
            # presence check (`"wasxfail" in obj`) would classify that line as
            # xpassed/xfailed -- exactly the passed/xpassed distinction this
            # module exists to get right (see module docstring).
            wasxfail=obj.get("wasxfail") is not None,
        )
        by_nodeid.setdefault(nodeid, {})[when] = record
    return by_nodeid


class MalformedRunError(ValueError):
    """A node ID's reports do not resemble a pytest run this module knows how
    to classify (e.g. no `setup` failure/skip and no `call` report at all).
    """


def classify(phases: dict[str, ReportRecord]) -> Outcome:
    """Derive the final outcome for one node ID from its per-phase reports."""
    setup = phases.get("setup")
    call = phases.get("call")
    teardown = phases.get("teardown")

    if setup is not None and setup.outcome == "failed":
        return "error"
    if teardown is not None and teardown.outcome == "failed":
        return "error"
    if setup is not None and setup.outcome == "skipped" and call is None:
        return "xfailed" if setup.wasxfail else "skipped"

    if call is None:
        raise MalformedRunError("no 'call' report and setup neither failed nor skipped the test")
    if call.outcome == "passed":
        return "xpassed" if call.wasxfail else "passed"
    if call.outcome == "skipped":
        return "xfailed" if call.wasxfail else "skipped"
    if call.outcome == "failed":
        return "failed"
    raise MalformedRunError(f"unrecognized 'call' outcome: {call.outcome!r}")


def classify_run(by_nodeid: dict[str, dict[str, ReportRecord]]) -> dict[str, Outcome]:
    """Classify every node ID in a loaded report-log into one outcome."""
    return {nodeid: classify(phases) for nodeid, phases in by_nodeid.items()}


@dataclass(frozen=True)
class Comparison:
    """The result of comparing two classified runs."""

    baseline_counts: dict[Outcome, int]
    after_counts: dict[Outcome, int]
    baseline_only: tuple[str, ...]
    after_only: tuple[str, ...]
    changed: tuple[tuple[str, Outcome, Outcome], ...]
    compared: int


def _counts(outcomes: Iterable[Outcome]) -> dict[Outcome, int]:
    counts = dict.fromkeys(OUTCOMES, 0)
    for outcome in outcomes:
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts


def compare(baseline: dict[str, Outcome], after: dict[str, Outcome]) -> Comparison:
    """Compare two node-ID -> outcome mappings.

    `compared` counts node IDs present in BOTH runs -- the only ones an
    outcome-to-outcome comparison actually happened for. A baseline and an
    after run that share no node ID produce `compared == 0` even though
    `baseline_only` and `changed` are both empty; the caller must treat that
    as a failure of the comparator to compare anything, not as a pass. An
    empty set compares equal to an empty set for free.
    """
    baseline_ids = set(baseline)
    after_ids = set(after)
    common = baseline_ids & after_ids
    changed = sorted(
        (nodeid, baseline[nodeid], after[nodeid])
        for nodeid in common
        if baseline[nodeid] != after[nodeid]
    )
    return Comparison(
        baseline_counts=_counts(baseline.values()),
        after_counts=_counts(after.values()),
        baseline_only=tuple(sorted(baseline_ids - after_ids)),
        after_only=tuple(sorted(after_ids - baseline_ids)),
        changed=tuple(changed),
        compared=len(common),
    )


def format_report(result: Comparison) -> str:
    """Render a `Comparison` as the stdout text a shell gate reads."""
    lines: list[str] = []
    lines.append("=== outcome counts (baseline) ===")
    for outcome in OUTCOMES:
        lines.append(f"{outcome}: {result.baseline_counts[outcome]}")
    lines.append("=== outcome counts (after) ===")
    for outcome in OUTCOMES:
        lines.append(f"{outcome}: {result.after_counts[outcome]}")

    lines.append(f"=== baseline-only ({len(result.baseline_only)}) ===")
    for nodeid in result.baseline_only:
        lines.append(nodeid)

    lines.append(f"=== after-only ({len(result.after_only)}) ===")
    for nodeid in result.after_only:
        lines.append(nodeid)

    lines.append(f"=== changed ({len(result.changed)}) ===")
    for nodeid, before, now in result.changed:
        lines.append(f"{nodeid}: {before} -> {now}")

    if result.compared == 0:
        lines.append(
            "ERROR: compared 0 node id(s) -- nothing was compared "
            "(baseline and after share no node ID; an empty comparison is "
            "not a pass)"
        )
    else:
        lines.append(f"compared {result.compared} node id(s) across baseline and after")
    return "\n".join(lines) + "\n"


def run_status(result: Comparison) -> int:
    """0 when the property holds (no test vanished, no outcome changed and
    at least one node ID was actually compared), 1 otherwise.
    """
    if result.compared == 0:
        return 1
    if result.baseline_only or result.changed:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two pytest report-log files by node ID and classify "
            "each test into passed/failed/error/skipped/xfailed/xpassed."
        )
    )
    parser.add_argument("baseline", type=Path, help="report-log file from the baseline run")
    parser.add_argument("after", type=Path, help="report-log file from the after run")
    args = parser.parse_args(argv)

    try:
        baseline_records = load_report_records(args.baseline)
        after_records = load_report_records(args.after)
        baseline_outcomes = classify_run(baseline_records)
        after_outcomes = classify_run(after_records)
    except (ValueError, OSError) as exc:
        print(f"compare_runs: {exc}", file=sys.stderr)
        return 1

    result = compare(baseline_outcomes, after_outcomes)
    print(format_report(result), end="")
    return run_status(result)


if __name__ == "__main__":
    raise SystemExit(main())
