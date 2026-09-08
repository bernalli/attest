"""Independent expectations, schema admission, and completed execution accounting."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tools import importer_differential as d
from tools.prove_importer_census import DISABLED


@given(st.lists(st.text(min_size=1), min_size=2, max_size=12, unique=True))
def test_every_leaf_loss_and_same_count_rename_is_named(names: list[str]) -> None:
    expected = {"family": d.FamilyRun("archives", tuple(names))}
    for removed in names:
        remaining = tuple(n for n in names if n != removed)
        for updating in (False, True):
            problems = d.compare_census(
                {"family": d.FamilyRun("archives", remaining)}, expected, updating=updating
            )
            assert any(f"missing: {removed}" in problem for problem in problems)
        fresh = "fresh"
        while fresh in names:
            fresh += "x"
        problems = d.compare_census(
            {"family": d.FamilyRun("archives", (*remaining, fresh))}, expected
        )
        assert any(f"missing: {removed}" in problem for problem in problems)
        assert any(f"unregistered vectors: {fresh}" in problem for problem in problems)


@pytest.mark.parametrize("unit", d.UNITS)
def test_update_keeps_previous_expectations_and_admits_only_additions(unit: str) -> None:
    expected = {"pinned": d.FamilyRun(unit, ("a", "b"))}
    grown = {"pinned": d.FamilyRun(unit, ("a", "b", "c")), "new": d.FamilyRun(unit, ("n",))}
    assert not d.compare_census(grown, expected, updating=True)
    assert d.compare_census(grown, expected)
    renamed = {"renamed": expected["pinned"]}
    assert any(
        "pinned: the census expects" in p
        for p in d.compare_census(renamed, expected, updating=True)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "bool-count",
        "negative-count",
        "bad-unit",
        "missing-vectors",
        "duplicate-vector",
        "empty-families",
        "total-drift",
        "bad-recipe",
        "invocation-drift",
        "extra-field",
    ],
)
def test_malformed_census_is_a_schema_error(tmp_path: Path, mutation: str) -> None:
    document = json.loads(d.DEFAULT_CENSUS.read_text())
    family = document["families"]["out-of-range"]
    if mutation == "bool-count":
        family["count"] = True
    elif mutation == "negative-count":
        family["count"] = -1
    elif mutation == "bad-unit":
        family["unit"] = "cases"
    elif mutation == "missing-vectors":
        del family["vectors"]
    elif mutation == "duplicate-vector":
        family["vectors"][0] = family["vectors"][1]
    elif mutation == "empty-families":
        document["families"] = {}
    elif mutation == "total-drift":
        document["totals"]["archives"] += 1
    elif mutation == "bad-recipe":
        document["families"]["mutation"]["generated"] = "anything"
    elif mutation == "invocation-drift":
        document["invocation"]["count"] += 1
    else:
        family["extra"] = None
    path = tmp_path / "census.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        d.load_importer_census(path)
    assert d.main(["--census", str(path)]) == 3


@pytest.mark.parametrize("raw", ['{"why": 1, "why": 2}', '{"why": NaN}', "{"])
def test_json_duplicates_constants_and_truncation_are_refused(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "census.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        d.load_importer_census(path)


@pytest.mark.parametrize(
    "args",
    [
        ["--families", "baseline"],
        ["--families", ""],
        ["--count", "1"],
        ["--seed", "1"],
    ],
)
def test_scoped_update_cannot_write_or_start_a_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    path = tmp_path / "census.json"
    before = d.DEFAULT_CENSUS.read_bytes()
    path.write_bytes(before)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a scoped update started the measurement")

    monkeypatch.setattr(d, "run", forbidden)
    assert d.main(["--census", str(path), "--update-census", *args]) == 3
    assert path.read_bytes() == before


def test_absent_census_cannot_be_bootstrapped_by_update(tmp_path: Path) -> None:
    path = tmp_path / "absent.json"
    assert d.main(["--census", str(path), "--update-census"]) == 78
    assert not path.exists()


def test_bare_command_keeps_pinned_expectations_when_registry_or_defaults_shrink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected, count, seed = d.load_importer_census(d.DEFAULT_CENSUS)
    monkeypatch.setattr(d, "ALL_FAMILIES", ("baseline",))
    monkeypatch.setattr(d, "DEFAULT_COUNT", 1)

    def inspect_run(*args: Any, **kwargs: Any) -> int:
        assert args[:3] == (["baseline"], 1, seed)
        assert kwargs["expected"] == expected
        assert not kwargs["scoped"]
        return 3

    monkeypatch.setattr(d, "run", inspect_run)
    assert len(expected["mutation"].vectors) == count
    assert d.main([]) == 3


def test_pair_ledger_records_answers_even_on_divergence_and_never_just_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vector = replace(d.family_baseline()[0], family="pair-floor", private=b"private")
    monkeypatch.setattr(d, "pair_vectors", lambda: [vector])
    calls: list[object] = []

    def projection(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append(args)
        return {"outcome": d.MALFORMED}

    monkeypatch.setattr(d, "python_projection", projection)
    completed: list[d.ExecutedCase] = []
    assert len(d.run_pair_family(tmp_path, None, completed)) == 1
    assert len(calls) == 2
    assert completed == [d.ExecutedCase("archive pairs", "pair-floor", vector.name)]
    monkeypatch.setattr(d, "pair_vectors", lambda: [])
    completed.clear()
    assert d.run_pair_family(tmp_path, None, completed) == []
    assert completed == []


def test_unfinished_differential_cannot_report_or_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "census.json"
    before = d.DEFAULT_CENSUS.read_bytes()
    path.write_bytes(before)
    monkeypatch.setattr(d, "collect", lambda *args: d.family_baseline())
    monkeypatch.setattr(d, "build_ts_bundle", lambda work: work / "bundle")

    def fail(*args: Any) -> None:
        raise SystemExit("injected adapter failure")

    monkeypatch.setattr(d, "ts_projections", fail)
    with pytest.raises(SystemExit, match="injected adapter failure"):
        d.main(["--census", str(path), "--update-census"])
    assert path.read_bytes() == before
    assert "archives fed" not in capsys.readouterr().out


def test_roundtrip_preserves_units_and_every_identity(tmp_path: Path) -> None:
    expected, count, seed = d.load_importer_census(d.DEFAULT_CENSUS)
    before = copy.deepcopy(expected)
    path = tmp_path / "census.json"
    d.write_importer_census(path, expected, count, seed)
    assert d.load_importer_census(path) == (before, count, seed)
    assert expected == before


def test_selftest_is_executed_in_ci() -> None:
    import yaml

    workflow = yaml.safe_load((d.REPO_ROOT / ".github/workflows/ci.yml").read_text())
    runs = [step.get("run", "") for job in workflow["jobs"].values() for step in job["steps"]]
    assert "uv run --frozen python tools/importer_differential.py --selftest" in runs
    assert "uv run --frozen python tools/importer_differential.py" in runs
    assert d.main(["--selftest"]) == 0


@pytest.mark.parametrize("guard", DISABLED)
def test_selftest_loses_a_named_case_when_each_guard_is_disabled(guard: str) -> None:
    import subprocess
    import sys

    result = subprocess.run(  # noqa: S603 -- fixed local probe, no shell
        [sys.executable, str(d.REPO_ROOT / "tools/prove_importer_census.py"), "--disable", guard],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "  FAIL " in result.stdout
    assert "selftest:" in result.stdout
    assert "selftest: 19/19" not in result.stdout
