"""Admission properties for the independent test census."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

_SPEC = importlib.util.spec_from_file_location(
    "census", Path(__file__).resolve().parents[2] / "tools/check_test_census.py"
)
assert _SPEC is not None and _SPEC.loader is not None
census = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(census)


def documents(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    expected: dict[str, Any] = {
        "suites": {"site": {"total": 3, "files": {"a.test.ts": 1, "b.test.ts": 2}}}
    }
    report = {
        "numTotalTests": 3,
        "numPassedTests": 3,
        "numFailedTests": 0,
        "numPendingTests": 0,
        "numTodoTests": 0,
        "testResults": [
            {"name": str(root / name), "assertionResults": [{"status": "passed"}] * n}
            for name, n in expected["suites"]["site"]["files"].items()
        ],
    }
    return expected, report


def load(root: Path, kind: str, value: Any) -> Any:
    path = root / "input.json"
    path.write_text(json.dumps(value))
    if kind == "census":
        return census.load_census(path, "site")
    return census.read_report(path, root)


BAD_COUNTS = st.one_of(
    st.none(),
    st.booleans(),
    st.text(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.integers(max_value=-1),
    st.lists(st.integers(), max_size=3),
    st.dictionaries(st.text(max_size=3), st.integers(), max_size=2),
)


@settings(max_examples=60, derandomize=True)
@given(BAD_COUNTS)
def test_counts_are_integers_without_coercion(value: Any) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        for field in (
            "total",
            "file",
            "numTotalTests",
            "numPassedTests",
            "numFailedTests",
            "numPendingTests",
            "numTodoTests",
        ):
            expected, report = documents(root)
            if field == "total":
                expected["suites"]["site"]["total"] = value
            elif field == "file":
                expected["suites"]["site"]["files"]["a.test.ts"] = value
            else:
                report[field] = value
            kind = "census" if field in {"total", "file"} else "report"
            with pytest.raises(SystemExit):
                load(root, kind, expected if kind == "census" else report)


@given(st.integers(min_value=1, max_value=10000))
def test_totals_are_bound_to_the_entries(delta: int) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, report = documents(root)
        expected["suites"]["site"]["total"] += delta
        report["numTotalTests"] += delta
        for kind, document in (("census", expected), ("report", report)):
            with pytest.raises(SystemExit):
                load(root, kind, document)


@given(st.permutations([0, 1]), st.booleans())
def test_order_is_irrelevant_but_duplicate_files_are_refused(order: list[int], first: bool) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, report = documents(root)
        entries = report["testResults"]
        report["testResults"] = [entries[i] for i in order]
        expected["suites"]["site"]["files"] = dict(
            reversed(list(expected["suites"]["site"]["files"].items()))
        )
        assert load(root, "report", report)[0] == load(root, "census", expected)
        duplicate = {"name": entries[0]["name"], "assertionResults": []}
        report["testResults"].insert(0 if first else 2, duplicate)
        with pytest.raises(SystemExit):
            load(root, "report", report)


@pytest.mark.parametrize("kind", ["census", "report"])
def test_duplicate_members_and_every_truncation_are_refused(kind: str) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, report = documents(root)
        raw = json.dumps(expected if kind == "census" else report)
        path = root / "input.json"

        def reader() -> Any:
            if kind == "census":
                return census.load_census(path, "site")
            return census.read_report(path, root)

        for end in range(len(raw)):
            path.write_text(raw[:end])
            with pytest.raises(SystemExit):
                reader()
        marker = '"total": 3' if kind == "census" else '"numTotalTests": 3'
        for replacement in (marker + ", " + marker, marker.replace("3", "NaN")):
            path.write_text(raw.replace(marker, replacement))
            with pytest.raises(SystemExit):
                reader()


@pytest.mark.parametrize("field", ["total", "files", "extra"])
def test_census_requires_its_exact_suite_fields(field: str) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, _ = documents(root)
        selected = expected["suites"]["site"]
        if field == "extra":
            selected[field] = 0
        else:
            del selected[field]
        with pytest.raises(SystemExit):
            load(root, "census", expected)


def test_report_requires_consumed_fields_and_typed_assertions() -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _, original = documents(root)
        for field in original:
            report = dict(original)
            del report[field]
            with pytest.raises(SystemExit):
                load(root, "report", report)
        bad_assertions: tuple[object, ...] = (
            None,
            1,
            True,
            "x",
            {},
            [None],
            [{"status": []}],
            [{}],
        )
        for value in bad_assertions:
            _, report = documents(root)
            report["testResults"][0]["assertionResults"] = value
            with pytest.raises(SystemExit):
                load(root, "report", report)
        original["extraReporterMetadata"] = {"version": 1}
        assert load(root, "report", original)[1] == 3


@pytest.mark.parametrize(
    "status,metric", [("pending", "numPendingTests"), ("todo", "numTodoTests")]
)
def test_update_refuses_skipped_transitions_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    metric: str,
) -> None:
    suite = tmp_path / "site"
    suite.mkdir()
    for name in ("a.test.ts", "b.test.ts"):
        (suite / name).write_text("// test fixture")
    expected, report = documents(suite)
    report["testResults"][0]["assertionResults"][0]["status"] = status
    # A status change cannot hide behind an unchanged aggregate.
    with pytest.raises(SystemExit):
        load(suite, "report", report)
    report["numPassedTests"] -= 1
    report[metric] += 1
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report))
    census_path = tmp_path / "census.json"
    census_path.write_text(json.dumps(expected))
    before = census_path.read_bytes()
    monkeypatch.setattr(census, "REPO_ROOT", tmp_path)
    with pytest.raises(SystemExit):
        census.main(
            ["site", "--report", str(report_path), "--census", str(census_path), "--update"]
        )
    assert census_path.read_bytes() == before
