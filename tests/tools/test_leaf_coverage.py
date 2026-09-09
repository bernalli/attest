"""Coverage admission and the Markdown spellings the corpus actually uses."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import check_leaf_coverage as guard


def run(root: Path, leaves: list[str], index: str = "", spec: str = "") -> tuple[list[str], str]:
    vectors = root / "vectors"
    vectors.mkdir(exist_ok=True)
    for leaf in leaves:
        (vectors / leaf).mkdir(parents=True, exist_ok=True)
    index_path = root / "index.md"
    spec_path = root / "spec.md"
    index_path.write_text(index, encoding="utf-8")
    spec_path.write_text(spec, encoding="utf-8")
    return guard.check(vectors, index_path, spec_path)


def test_selftest(capsys: pytest.CaptureFixture[str]) -> None:
    assert guard.selftest() == 0
    assert "FAIL" not in capsys.readouterr().out


def test_existing_index_spellings_and_explicit_shared_rows(tmp_path: Path) -> None:
    leaves = [
        "01-single",
        "07-pair/a-first",
        "07-pair/b-second",
        "14-rotation",
        "14b-discontinuous",
        "19-review/a-one",
        "19-review/b-two",
        "29-limits/a-ceiling",
        "48-new/a-new",
    ]
    index = """### 1\u201311: format

| # | Name | Checks |
| --- | --- | --- |
| 01 | `single` | Accept. |
| 07 | `pair` | (a) Accept. (b) Refuse. |

### 12\u201318: lifecycle

| # | Name | Checks |
| --- | --- | --- |
| 14 | `rotation` | Accept. |
| 14b | `discontinuous` | Refuse. |

### 19\u201325: review

| # | Name | Checks |
| --- | --- | --- |
| 19a | `review/a-one` | Accept. |
| 19b | `review/b-two` | Refuse. |

### 29: limits

| Leaf | Name | Checks |
| --- | --- | --- |
| 29a | `limits/a-ceiling` | Refuse. |

## 48 — new

| Leaf | Name | Checks |
| --- | --- | --- |
| 48a | `a-new` | Accept. |
"""
    problems, summary = run(tmp_path, leaves, index)
    assert problems == []
    assert "9/9 leaves described, 8 rows, 7 groups" in summary
    # A group row is not a wildcard covering future children, even without expected.json.
    problems, _ = run(tmp_path, ["07-pair/c-added"], index)
    assert any("UNDESCRIBED 07-pair/c-added" in p for p in problems)
    problems, _ = run(tmp_path, [], index.replace("(b) Refuse.", "Refuse."))
    assert any("UNDESCRIBED 07-pair/b-second" in p for p in problems)


def test_normative_spellings_and_paired_rows(tmp_path: Path) -> None:
    leaves = ["26-hybrid/a-valid", "28-log/a-logged", "40-quorum/l-valid", "40-quorum/m-invalid"]
    spec = """## 6. Conformance

| Leaf | Checks |
| --- | --- |
| `a-valid` | Accept. |

### 16.1 Ceilings

| Leaf | Checks |
| --- | --- |
| `28a` | Logged. |

### 16.8 Quorum

| Leaf | Checks |
| --- | --- |
| `40l-valid` / `40m-invalid` | Inclusive boundary. |
"""
    problems, summary = run(tmp_path, leaves, spec=spec)
    assert problems == []
    assert "4/4 leaves described, 3 rows, 3 groups" in summary
    problems, _ = run(tmp_path, [], spec=spec.replace(" / `40m-invalid`", ""))
    assert any("UNDESCRIBED 40-quorum/m-invalid" in p for p in problems)


@pytest.mark.parametrize(
    "table",
    [
        "| Leaf | Checks |\n| not a separator | nope |\n| `41a-present` | Accept. |\n",
        "| Leaf | Example |\n| --- | --- |\n| `41a-present` | Accept. |\n",
        "Mention `41a-present` in prose.\n",
        "| Leaf | Checks |\n| --- | --- |\n\n## Other section\n| `41a-present` | Accept. |\n",
    ],
)
def test_a_mention_is_not_a_group_table_row(tmp_path: Path, table: str) -> None:
    problems, _ = run(tmp_path, ["41-demo/a-present"], spec="### 16.11 Compromise\n\n" + table)
    assert any("UNDESCRIBED 41-demo/a-present" in p for p in problems)


def test_wrong_index_group_cannot_supply_coverage(tmp_path: Path) -> None:
    index = """### 48: unrelated

| Leaf | Name | Checks |
| --- | --- | --- |
| 49a | `a-present` | Accept. |
"""
    problems, _ = run(tmp_path, ["49-new/a-present"], index)
    assert any("outside its group's table" in p for p in problems)
    assert any("UNDESCRIBED 49-new/a-present" in p for p in problems)


def test_deleted_group_is_not_ignored(tmp_path: Path) -> None:
    index = """### 48: removed

| Leaf | Name | Checks |
| --- | --- | --- |
| 48a | `a-absent` | Accept. |
"""
    problems, _ = run(tmp_path, ["49-other/a-present"], index)
    assert any("nonexistent group 48" in p for p in problems)


def test_rename_reports_both_absences_at_the_same_count(tmp_path: Path) -> None:
    spec = "### 16.11 Compromise\n\n| Leaf | Checks |\n| --- | --- |\n| `41a-old` | Accept. |\n"
    problems, _ = run(tmp_path, ["41-demo/a-renamed"], spec=spec)
    assert any("UNDESCRIBED 41-demo/a-renamed" in p for p in problems)
    assert any("nonexistent or ambiguous leaf 41-demo/41a-old" in p for p in problems)


def test_empty_or_missing_inputs_fail_the_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert guard.main(["--vectors", str(tmp_path / "missing")]) == 1
    assert "no such corpus directory" in capsys.readouterr().err
    assert guard.main(["--vectors", str(tmp_path)]) == 1
    assert "empty corpus" in capsys.readouterr().err
    (tmp_path / "01-single").mkdir()
    assert guard.main(["--vectors", str(tmp_path), "--spec", str(tmp_path / "missing.md")]) == 1
    assert "missing.md" in capsys.readouterr().err


def test_duplicate_table_is_refused(tmp_path: Path) -> None:
    spec = "### 16.11 Compromise\n\n| Leaf | Checks |\n| --- | --- |\n| `41a-present` | Accept. |\n"
    problems, _ = run(tmp_path, ["41-demo/a-present"], spec=spec + "\n" + spec)
    assert any("multiple group tables" in p for p in problems)


def test_ci_runs_selftest_then_guard_with_document_guards() -> None:
    import yaml

    workflow = yaml.safe_load((guard.REPO_ROOT / ".github/workflows/ci.yml").read_text())
    steps = [step.get("run", "") for step in workflow["jobs"]["python"]["steps"]]
    precedent = steps.index("uv run --frozen python tools/check_spec_docs.py")
    assert steps[precedent + 1 : precedent + 3] == [
        "python3 tools/check_leaf_coverage.py --selftest",
        "python3 tools/check_leaf_coverage.py",
    ]
