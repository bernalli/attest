"""Local pytest plugin that writes a JSON-Lines report-log, for use when the
`pytest-reportlog` plugin is not installed.

WHY THIS EXISTS

`tools/gates/compare_runs.py` needs a channel that preserves the bit junit
XML drops: whether a passing/skipped report came from an xfail marker
(xpassed/xfailed) rather than an ordinary pass/skip. pytest's own
`TestReport` objects already carry that bit -- `report.outcome` plus a
`wasxfail` attribute that pytest's skipping plugin sets on the report when an
xfail marker fired (see `_pytest/skipping.py`). `pytest-reportlog` dumps
`report.__dict__` (which includes `wasxfail` when present) to JSON Lines;
this plugin does the same, deliberately writing a subset of that shape --
`nodeid`, `when`, `outcome`, and `wasxfail` when present -- so
`compare_runs.py` reads either channel identically without knowing which one
produced the file.

Adding a dependency here is out of scope for this front (a new dependency
goes through the SBOM/license/vulnerability gate, which this task does not
touch): this plugin adds no third-party import, only `pytest` itself, which
every gate that runs a test already depends on.

USAGE

Set `GATE_REPORTLOG_PATH` to the output file, then load the plugin by module
name with `sys.path` including this directory, e.g.:

    GATE_REPORTLOG_PATH=/tmp/out.jsonl \\
    PYTHONPATH=/path/to/tools/gates \\
    python -m pytest -p reportlog_plugin ...

`-p <name>` resolves `name` via `importlib.import_module`, which is why the
module needs to be importable from `sys.path` rather than referenced by
file path.
"""

from __future__ import annotations

import json
import os
from typing import IO, Any

import pytest

_OUTPUT_ENV = "GATE_REPORTLOG_PATH"
_out: IO[str] | None = None


def pytest_configure(config: pytest.Config) -> None:
    """Open the output file. Fails loudly if the env var is missing, rather
    than silently writing nowhere and leaving a downstream comparator to
    discover an empty file and misread that as "nothing changed".
    """
    global _out
    path = os.environ.get(_OUTPUT_ENV)
    if not path:
        raise pytest.UsageError(
            f"{_OUTPUT_ENV} must be set when tools/gates/reportlog_plugin.py is loaded"
        )
    _out = open(path, "w", encoding="utf-8")


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Write one JSON line per phase report (setup/call/teardown).

    `report.outcome` is pytest's raw per-phase outcome ("passed" / "failed" /
    "skipped"); `wasxfail` is set by pytest's skipping plugin exactly when an
    xfail marker fired for this phase -- present with outcome "passed" means
    xpassed, present with outcome "skipped" means xfailed. Recording the raw
    fields here and leaving that derivation to `compare_runs.py` keeps this
    plugin a transport, not a second place the classification can drift from.
    """
    if _out is None:
        return
    entry: dict[str, Any] = {
        "$report_type": "TestReport",
        "nodeid": report.nodeid,
        "when": report.when,
        "outcome": report.outcome,
    }
    if hasattr(report, "wasxfail"):
        entry["wasxfail"] = report.wasxfail
    _out.write(json.dumps(entry) + "\n")
    _out.flush()


def pytest_unconfigure(config: pytest.Config) -> None:
    global _out
    if _out is not None:
        _out.close()
        _out = None
