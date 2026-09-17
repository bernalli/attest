"""Pytest plugin that records per-test outcomes, and WHY each red is red.

Parsing the terminal summary is fragile: `-rf` drops ERRORs, and a collection
failure produces no runtest report at all.

The exception type is recorded because it is the discriminator this bench turns
on. A mutation is supposed to break a PROPERTY; if it instead breaks the FORM
(a name, an import, a type) the suite goes red before it ever reaches the
invariant, and that red says nothing about coverage. An `AssertionError` raised
by the test's own assertion is the red that means something; a `NameError` is
the red that means the mutation was badly built.
"""

from __future__ import annotations

import json
import os
from typing import Any

_calls: dict[str, str] = {}
_why: dict[str, str] = {}
_collect_errors: list[str] = []


def _exc_type(report: Any) -> str:
    """Best-effort exception class name for a failed report."""
    excinfo = getattr(getattr(report, "longrepr", None), "reprcrash", None)
    if excinfo is not None and getattr(excinfo, "message", None):
        message = str(excinfo.message)
        head = message.split(":", 1)[0].strip()
        # reprcrash.message is like "AssertionError: assert 'x' == 'y'" or a
        # bare "assert ..." for plain asserts.
        if head and (head[0].isupper() and head.replace("_", "").isalnum()):
            return head
        if message.startswith("assert"):
            return "AssertionError"
        return message[:60]
    return "unknown"


def pytest_runtest_logreport(report: Any) -> None:
    nodeid = report.nodeid
    if report.when == "call":
        if report.outcome == "failed":
            _calls[nodeid] = "failed"
            _why[nodeid] = _exc_type(report)
        else:
            _calls.setdefault(nodeid, report.outcome)
    elif report.outcome == "skipped":
        # A skipped test cannot kill a mutant. Counted so a suite that quietly
        # skips half of itself for a missing prerequisite is visible as such
        # rather than as a suite full of survivors.
        _calls.setdefault(nodeid, "skipped")
    elif report.outcome == "failed":
        _calls[nodeid] = "error"
        _why[nodeid] = f"{report.when}:{_exc_type(report)}"


def pytest_collectreport(report: Any) -> None:
    if report.outcome == "failed":
        _collect_errors.append(report.nodeid or "<root>")


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    path = os.environ.get("ABLATION_OUTCOMES")
    if not path:
        return
    failed = sorted(n for n, o in _calls.items() if o in ("failed", "error"))
    payload = {
        "exitstatus": int(exitstatus),
        "collected_and_run": len(_calls),
        "n_passed": sum(1 for o in _calls.values() if o == "passed"),
        "n_skipped": sum(1 for o in _calls.values() if o == "skipped"),
        "n_failed": len(failed),
        "failed": failed,
        "why": {n: _why.get(n, "unknown") for n in failed},
        "collect_errors": sorted(set(_collect_errors)),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1)
