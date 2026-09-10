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
    files = {"a.test.ts": 1, "b.test.ts": 2}
    # A real report carries a fullName on every assertion, so the fixture does too: a
    # fixture that omits a field production always sends measures a domain that does
    # not exist.
    titles = {name: [f"{name} case {i}" for i in range(n)] for name, n in files.items()}
    expected: dict[str, Any] = {
        "suites": {
            "site": {
                "total": 3,
                "files": files,
                "digests": {name: census.name_digest(names) for name, names in titles.items()},
            }
        }
    }
    report = {
        "numTotalTests": 3,
        "numPassedTests": 3,
        "numFailedTests": 0,
        "numPendingTests": 0,
        "numTodoTests": 0,
        "testResults": [
            {
                "name": str(root / name),
                "assertionResults": [
                    {"status": "passed", "fullName": title} for title in titles[name]
                ],
            }
            for name in files
        ],
    }
    return expected, report


def load(root: Path, kind: str, value: Any) -> Any:
    path = root / "input.json"
    path.write_text(json.dumps(value))
    if kind == "census":
        return census.load_census(path, "site", with_digests=True)
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
        run = load(root, "report", report)
        pinned = load(root, "census", expected)
        # Counts AND digests survive a permutation: the digest sorts the names, so
        # reordering a table is not a defect while substituting one is.
        assert run[0] == pinned[0]
        assert run[1] == pinned[1]
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
                return census.load_census(path, "site", with_digests=True)
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


@pytest.mark.parametrize("field", ["total", "files", "digests", "extra"])
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
            # A missing, empty or non-string fullName is refused the same way: the
            # digest is only worth what the field it hashes is worth.
            [{"status": "passed"}],
            [{"status": "passed", "fullName": ""}],
            [{"status": "passed", "fullName": 7}],
        )
        for value in bad_assertions:
            _, report = documents(root)
            report["testResults"][0]["assertionResults"] = value
            with pytest.raises(SystemExit):
                load(root, "report", report)
        original["extraReporterMetadata"] = {"version": 1}
        assert load(root, "report", original)[2] == 3


SCALAR_TITLES = st.text(
    alphabet=st.characters(exclude_categories=["Cs"], exclude_characters="\x00"),
    min_size=1,
    max_size=30,
)


@settings(max_examples=60, derandomize=True)
@given(st.lists(SCALAR_TITLES, min_size=2, max_size=8, unique=True))
def test_name_digest_pins_a_multiset_independently_of_input_order(names: list[str]) -> None:
    assert census.name_digest(names) == census.name_digest(list(reversed(names)))
    first, second = sorted(names)[:2]
    # Equal cardinality and equal set; only multiplicity changes.
    assert census.name_digest([first, first, second]) != census.name_digest([first, second, second])
    # Ordinary delimiter ambiguity must also stay distinct at an equal count.
    assert census.name_digest([first, first + "bc"]) != census.name_digest(
        [first + "b", first + "c"]
    )


JSON_VALUES = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=80),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=3), st.dictionaries(st.text(max_size=8), children, max_size=3)
    ),
    max_leaves=10,
)


@settings(max_examples=80, derandomize=True)
@given(JSON_VALUES.filter(lambda value: not isinstance(value, dict)))
def test_digest_map_refuses_every_non_object_family(value: Any) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, _ = documents(root)
        expected["suites"]["site"]["digests"] = value
        with pytest.raises(SystemExit, match="site: digests must be an object"):
            load(root, "census", expected)


@settings(max_examples=80, derandomize=True)
@given(JSON_VALUES)
def test_digest_values_obey_the_lowercase_sha256_grammar(value: Any) -> None:
    import re

    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, _ = documents(root)
        expected["suites"]["site"]["digests"]["a.test.ts"] = value
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
            assert load(root, "census", expected)[1]["a.test.ts"] == value
        else:
            with pytest.raises(SystemExit, match=r"site: a\.test\.ts: digest must"):
                load(root, "census", expected)


@pytest.mark.parametrize("value", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + "\n"])
def test_digest_grammar_boundaries(value: str, tmp_path: Path) -> None:
    expected, _ = documents(tmp_path)
    expected["suites"]["site"]["digests"]["a.test.ts"] = value
    with pytest.raises(SystemExit, match=r"site: a\.test\.ts: digest must"):
        load(tmp_path, "census", expected)


@given(st.text(alphabet="0123456789abcdef", min_size=64, max_size=64))
def test_well_formed_digest_is_preserved(value: str) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, _ = documents(root)
        expected["suites"]["site"]["digests"]["a.test.ts"] = value
        assert load(root, "census", expected)[1]["a.test.ts"] == value


@given(st.sampled_from(["missing", "extra", "renamed"]), st.integers(min_value=0))
def test_digest_keys_cover_exactly_the_counted_files(change: str, suffix: int) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, _ = documents(root)
        digests = expected["suites"]["site"]["digests"]
        if change != "extra":
            del digests["a.test.ts"]
        if change != "missing":
            digests[f"unexpected-{suffix}.test.ts"] = "0" * 64
        with pytest.raises(SystemExit, match="digests and files must cover the same test files"):
            load(root, "census", expected)


@pytest.mark.parametrize("kind", ["census", "report"])
@given(first=st.booleans())
def test_duplicate_identity_members_are_refused_even_if_one_value_is_valid(
    first: bool, kind: str
) -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        expected, report = documents(root)
        if kind == "census":
            good = json.dumps(expected["suites"]["site"]["digests"]["a.test.ts"])
            marker = f'"a.test.ts": {good}'
            bad = '"a.test.ts": null'
        else:
            marker = '"fullName": "a.test.ts case 0"'
            bad = '"fullName": null'
        raw = json.dumps(expected if kind == "census" else report)
        raw = raw.replace(marker, f"{marker}, {bad}" if first else f"{bad}, {marker}")
        path = root / "input.json"
        path.write_text(raw)
        with pytest.raises(SystemExit, match="duplicate JSON member"):
            if kind == "census":
                census.load_census(path, "site", with_digests=True)
            else:
                census.read_report(path, root)


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


@pytest.mark.parametrize(
    "titles,reason",
    [
        (["a\x00b", "c"], "NUL"),
        (["a", "b\x00c"], "NUL"),
        (["a", "\ud800"], "Unicode scalar values"),
        (["a", "\udfff"], "Unicode scalar values"),
    ],
)
def test_report_refuses_names_outside_digest_domain(
    tmp_path: Path, titles: list[str], reason: str
) -> None:
    _, report = documents(tmp_path)
    report["testResults"][1]["assertionResults"] = [
        {"status": "passed", "fullName": title} for title in titles
    ]
    with pytest.raises(SystemExit, match=rf"b\.test\.ts: fullName must .*{reason}"):
        load(tmp_path, "report", report)
