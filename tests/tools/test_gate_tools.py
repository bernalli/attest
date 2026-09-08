"""Negative-input tests for the gate tools in `tools/gates/` — the parsers that
decide whether a measurement counts (a report-log comparator, a plan-markdown
code extractor, a CI-workflow coverage checker).

Nothing here raises `assert` about how the tools SHOULD behave in the abstract:
every test drives one ill-formed or evasive input through the real module and
pins the diagnostic (or the silent-ignore, where that is the documented
behaviour) it actually produces. `tools/gates` carries no `__init__.py`, so
each module is loaded via `importlib.util.spec_from_file_location`, following
`tests/tools/test_test_census.py`'s discipline for tools that live outside a
package — no `sys.path` mutation anywhere in this file.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATES_DIR = REPO_ROOT / "tools" / "gates"


def _load_gate_tool(name: str) -> Any:
    """Load `tools/gates/<name>.py` as a standalone module.

    Registered in `sys.modules` before `exec_module`: `compare_runs.py`
    defines frozen dataclasses, and `dataclasses._process_class` resolves
    `cls.__module__` through `sys.modules` while building them — without the
    registration, loading the module raises `AttributeError` on the *first*
    dataclass, before a single test runs.
    """
    path = GATES_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"gate_tool_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


compare_runs = _load_gate_tool("compare_runs")
plan_code = _load_gate_tool("plan_code")
ci_coverage = _load_gate_tool("ci_coverage")


# ---------------------------------------------------------------------------
# compare_runs.py
# ---------------------------------------------------------------------------


def test_two_empty_report_logs_compare_nothing_and_fail(tmp_path: Path, capsys: Any) -> None:
    """Pins the existing property: an empty baseline and an empty after run
    share no node ID, `compared` is 0, and the comparator refuses to call
    that a pass — `run_status`/`format_report` say so explicitly rather than
    reporting an empty diff as clean.
    """
    baseline = tmp_path / "baseline.jsonl"
    after = tmp_path / "after.jsonl"
    baseline.write_text("", encoding="utf-8")
    after.write_text("", encoding="utf-8")

    rc = compare_runs.main([str(baseline), str(after)])
    out = capsys.readouterr().out

    assert rc != 0
    assert "compared 0 node id(s)" in out
    assert "nothing was compared" in out


def test_invalid_json_line_reports_path_and_line_not_a_traceback(
    tmp_path: Path, capsys: Any
) -> None:
    """A line that isn't valid JSON is a diagnostic (`path:line`), not an
    unhandled `json.JSONDecodeError` propagating out of `main`.
    """
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text("this is not json\n", encoding="utf-8")
    after = tmp_path / "after.jsonl"
    after.write_text("", encoding="utf-8")

    rc = compare_runs.main([str(baseline), str(after)])
    err = capsys.readouterr().err

    assert rc == 1
    assert f"{baseline}:1" in err
    assert "not valid JSON" in err


def test_lines_missing_report_shape_are_ignored_not_errored(tmp_path: Path) -> None:
    """Pins the existing property: a line that parses as JSON but lacks one of
    `nodeid`/`when`/`outcome` (a session marker, a collect report, anything
    else a report-log writer emits) is skipped in silence, not raised on —
    the module docstring's own contract for `iter_report_lines`.
    """
    path = tmp_path / "log.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"$report_type": "CollectReport", "nodeid": "irrelevant"}),
                json.dumps({"nodeid": "t.py::x", "when": "call", "outcome": "passed"}),
                json.dumps({"nodeid": "t.py::x", "when": "only-a-when-no-outcome"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    records = compare_runs.load_report_records(path)

    assert list(records.keys()) == ["t.py::x"]
    assert set(records["t.py::x"].keys()) == {"call"}


def test_unrecognized_call_outcome_raises_malformed_run_error(tmp_path: Path) -> None:
    """Pins the existing property: an `outcome` this module has never heard of
    (not `passed`/`failed`/`skipped`) is refused by name, not swallowed into
    one of the six buckets it does not belong to.
    """
    record = compare_runs.ReportRecord(
        nodeid="t.py::x", when="call", outcome="bogus", wasxfail=False
    )
    with pytest.raises(compare_runs.MalformedRunError, match="unrecognized 'call' outcome"):
        compare_runs.classify({"call": record})


def test_nodeid_wrong_type_raises_malformed_run_error_with_location_and_type(
    tmp_path: Path,
) -> None:
    """LOW-4, decision 1: a `nodeid` that is not a string is a malformed report
    line, given the SAME treatment as an unrecognized `outcome` --
    `MalformedRunError`, naming the file, the line, and the type observed --
    instead of running to completion and dying later as an unhandled
    `TypeError` once something (`format_report`, joining `baseline_only` into
    text) assumes every nodeid is a string.

    Verified red before the fix: on the unpatched module, this same input
    makes `load_report_records` return successfully (`{123: {...}}`, the int
    kept verbatim as a dict key) and the `TypeError` only surfaces two calls
    later, inside `format_report`, when a baseline/after mismatch puts that
    int nodeid into a list joined with `str.join`. Asserting `pytest.raises`
    around `load_report_records` itself is exactly the assertion that failed
    (nothing raised) against the unpatched module.
    """
    path = tmp_path / "log.jsonl"
    path.write_text(
        json.dumps({"nodeid": 123, "when": "call", "outcome": "passed"}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(compare_runs.MalformedRunError) as excinfo:
        compare_runs.load_report_records(path)

    message = str(excinfo.value)
    assert f"{path}:1" in message
    assert "int" in message


def test_nodeid_wrong_type_end_to_end_is_a_clean_error_not_a_traceback(tmp_path: Path) -> None:
    """The CLI-level view of the same defect: before the fix, `python
    tools/gates/compare_runs.py` on this input printed a Python traceback to
    stderr and exited 1 with no usable diagnostic. After the fix, `main`'s own
    `except (ValueError, OSError)` catches `MalformedRunError` (a `ValueError`
    subclass) and prints one clean line.
    """
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        json.dumps({"nodeid": 123, "when": "call", "outcome": "passed"}) + "\n",
        encoding="utf-8",
    )
    after = tmp_path / "after.jsonl"
    after.write_text(
        json.dumps({"nodeid": "t.py::y", "when": "call", "outcome": "passed"}) + "\n",
        encoding="utf-8",
    )

    proc = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [sys.executable, str(GATES_DIR / "compare_runs.py"), str(baseline), str(after)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert f"{baseline}:1" in proc.stderr
    assert "int" in proc.stderr


def test_wasxfail_null_is_not_treated_as_xfail(tmp_path: Path) -> None:
    """LOW-4, decision 2: `wasxfail` is read for TRUTH, not presence. A
    report-log line can carry `"wasxfail": null` -- and `null` is not an xfail
    that fired. A `passed` call report with `wasxfail: null` must classify as
    `passed`, not `xpassed`: it is precisely the passed/xpassed distinction
    this comparator was written to get right (module docstring, "WHY THIS
    EXISTS").

    Verified red before the fix: on the unpatched module (`"wasxfail" in
    obj`), the same input classifies as `xpassed`.
    """
    path = tmp_path / "log.jsonl"
    path.write_text(
        json.dumps({"nodeid": "t.py::x", "when": "call", "outcome": "passed", "wasxfail": None})
        + "\n",
        encoding="utf-8",
    )

    records = compare_runs.load_report_records(path)
    outcome = compare_runs.classify(records["t.py::x"])

    assert outcome == "passed"


def test_wasxfail_present_and_truthy_is_still_xpassed(tmp_path: Path) -> None:
    """Companion to the test above, on the branch the fix must NOT touch: a
    `wasxfail` that pytest actually set to a non-null value (its usual shape
    is the xfail reason string) still means xpassed. This is what tells apart
    "read for truth" from "always false" -- a fix that broke this the same
    way it fixed the null case would pass the test above and fail this one.
    """
    path = tmp_path / "log.jsonl"
    path.write_text(
        json.dumps(
            {
                "nodeid": "t.py::x",
                "when": "call",
                "outcome": "passed",
                "wasxfail": "reason given to the marker",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    records = compare_runs.load_report_records(path)
    outcome = compare_runs.classify(records["t.py::x"])

    assert outcome == "xpassed"


# ---------------------------------------------------------------------------
# plan_code.py
# ---------------------------------------------------------------------------


def test_fence_indented_up_to_three_spaces_is_extracted_and_linted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """CommonMark allows up to three leading spaces on a fence -- exactly how
    a code block nested in a list item is written. A checker matching only a
    fence starting at column zero would silently never look at this block
    (the evasion the module docstring/C-222 comment names); the fixed
    extractor finds it, strips the shared indent, and lints it clean.
    """
    plan = tmp_path / "plan.md"
    plan.write_text(
        "- an item with a nested block\n  ```python\n  x = 1\n  ```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(plan_code, "PLAN", plan)

    rc = plan_code.main()
    out = capsys.readouterr().out

    assert rc == 0
    assert "extracted 1 normative python block(s)" in out
    assert "PLAN_CODE_CLEAN" in out


def test_fence_without_language_is_named_and_fails_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """A fence that names no language is NOT a silent exemption: its body may
    be Python the executor transcribes and nobody would be checking it. Paired
    here with a genuine ```python block so the unrecognised-language branch of
    `main` actually runs (a document with ONLY an unlabeled fence exits
    non-zero for the unrelated "no python block found" reason, tested
    separately below, and never reaches the per-fence naming loop).
    """
    plan = tmp_path / "plan.md"
    plan.write_text(
        "```python\nx = 1\n```\n\n```\nclass Foo:\n    __slots__ = ('b', 'a')\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(plan_code, "PLAN", plan)

    rc = plan_code.main()
    out = capsys.readouterr().out

    assert rc == 1
    assert "extracted 1 normative python block(s)" in out
    assert "<no language>" in out
    assert "unrecognised language" in out


def test_fence_with_tilde_marker_is_extracted_and_linted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """CommonMark opens a fenced block with three backticks OR three tildes.
    A checker matching only backticks would silently never look at a tilde
    fence -- the second evasion the C-222 comment names.
    """
    plan = tmp_path / "plan.md"
    plan.write_text("~~~python\nx = 1\n~~~\n", encoding="utf-8")
    monkeypatch.setattr(plan_code, "PLAN", plan)

    rc = plan_code.main()
    out = capsys.readouterr().out

    assert rc == 0
    assert "extracted 1 normative python block(s)" in out
    assert "PLAN_CODE_CLEAN" in out


def test_plan_with_no_blocks_at_all_fails_instead_of_declaring_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """Green for absence: a plan carrying no fenced block whatsoever must not
    be reported as PLAN_CODE_CLEAN just because there was nothing to fail on.
    """
    plan = tmp_path / "plan.md"
    plan.write_text("Just prose. No code blocks anywhere in this document.\n", encoding="utf-8")
    monkeypatch.setattr(plan_code, "PLAN", plan)

    rc = plan_code.main()
    out = capsys.readouterr().out

    assert rc == 1
    assert "PLAN_CODE_CLEAN" not in out
    assert "no python block found" in out


# ---------------------------------------------------------------------------
# ci_coverage.py
# ---------------------------------------------------------------------------


def _write_workflow(tmp_path: Path, name: str, body: str) -> Path:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    path = workflows / name
    path.write_text(body, encoding="utf-8")
    return path


def test_composite_run_line_is_classified_per_fragment_not_per_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """A `run:` line is a shell LINE, not a command: classifying the whole
    line lets the first needle that matches anywhere absorb everything after
    it, hiding an uncovered command behind a covered/plumbing one that
    happens to come first. `mkdir -p out && python tools/unknown_tool.py
    --strict` must produce TWO fragments, and the unknown one must be named
    on its own -- not swallowed into the "runner plumbing" bucket the `mkdir`
    half belongs to.
    """
    _write_workflow(
        tmp_path,
        "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: mkdir -p out && python tools/unknown_tool.py --strict\n",
    )
    monkeypatch.setattr(ci_coverage, "TREE", tmp_path)

    rc = ci_coverage.main()
    out = capsys.readouterr().out

    assert rc == 1
    assert "parsed 2 CI commands" in out
    assert "python tools/unknown_tool.py --strict" in out
    # The whole composite line must never appear as a single classified unit --
    # that is precisely the per-line classification this test rules out.
    assert "mkdir -p out && python tools/unknown_tool.py --strict" not in out


def test_workflows_to_read_are_derived_and_named_exemption_is_excluded_unparsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """The list of workflows to check is derived from `.github/workflows/*.y*ml`
    on disk, not hand-maintained -- a workflow dropped in tomorrow is read by
    construction. `release.yml` is the one name the module itself declares out
    of F6's perimeter (`WORKFLOWS_OUT_OF_SCOPE`): it must be excluded BY NAME,
    before any YAML parsing happens, so a release workflow can carry content
    this checker would choke on and still not fail the gate. The unparsable
    body proves the exclusion happens before `yaml.safe_load` ever sees it.
    """
    _write_workflow(tmp_path, "release.yml", "this is : not [ valid yaml at all")
    _write_workflow(
        tmp_path,
        "ci.yml",
        "jobs:\n  test:\n    steps:\n      - run: mypy --strict src\n",
    )
    monkeypatch.setattr(ci_coverage, "TREE", tmp_path)

    rc = ci_coverage.main()
    out = capsys.readouterr().out

    # An exact-line check, not a substring one: "workflows parsed: ci.yml" is
    # also a substring of "workflows parsed: ci.yml, release.yml", which is
    # exactly the wrong answer this test exists to catch (release.yml parsed
    # alongside ci.yml instead of excluded).
    assert "workflows parsed: ci.yml" in out.splitlines()
    assert "workflow out of scope: release.yml" in out
    assert rc == 0
    assert "CI_COVERAGE_COMPLETE" in out
