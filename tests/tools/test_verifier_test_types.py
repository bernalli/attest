"""Probe admission, strict update, and one-at-a-time selftest sensitivity."""

from __future__ import annotations

import inspect
import json
import subprocess
from pathlib import Path

import pytest

from tools import check_verifier_test_types as census


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    suite = tmp_path / "verifiers/ts"
    (suite / "test").mkdir(parents=True)
    for name in ("a.test.ts", "b.test.ts"):
        (suite / "test" / name).write_text("// fixture\n")
    tsc = suite / "node_modules/.bin/tsc"
    tsc.parent.mkdir(parents=True)
    tsc.touch()
    pin = tmp_path / "census.json"
    pin.write_text(
        json.dumps(
            {
                "suites": {
                    "verifiers/ts": {
                        "total": 1,
                        "files": {
                            "test/a.test.ts": 1,
                            "test/b.test.ts": 0,
                        },
                    }
                }
            }
        )
    )
    monkeypatch.setattr(census, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(census, "DEFAULT_CENSUS", pin)
    monkeypatch.setattr(census, "DEFAULT_TSC", tsc)
    monkeypatch.setattr(census.shutil, "which", lambda _: "/usr/bin/node")
    return suite


def output(tree: Path, count: int = 1, *, include_b: bool = True) -> str:
    diagnostic = "verifiers/ts/test/a.test.ts(1,1): error TS2322: incompatible types\n"
    return (
        diagnostic * count
        + ("  An indented detail is not another diagnostic.\n" if count else "")
        + str(tree / "test/a.test.ts")
        + "\n"
        + (str(tree / "test/b.test.ts") + "\n" if include_b else "")
    )


def probe(monkeypatch: pytest.MonkeyPatch, text: str, status: int) -> None:
    monkeypatch.setattr(
        census.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], status, stdout=text),
    )


@pytest.mark.parametrize("count", [0, 1, 2])
def test_parser_counts_headers_and_lists_clean_files(tree: Path, count: int) -> None:
    run, total = census.read_probe(output(tree, count), 2 if count else 0, tree)
    assert run == {"test/a.test.ts": count, "test/b.test.ts": 0}
    assert total == count


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("empty", "empty probe output"),
        ("whitespace", "empty probe output"),
        ("global", "error TS18003"),
        ("unknown", "unrecognized probe output"),
        ("orphan-detail", "unrecognized probe output"),
        ("duplicate", "duplicate compiled file"),
        ("unlisted-diagnostic", "outside compiled test-file census"),
        ("status-zero", "probe exited 0"),
        ("status-one", "probe exited 1"),
        ("status-two-without-errors", "probe exited 2"),
    ],
)
def test_unusable_output_is_not_a_census_verdict(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind: str,
    expected: str,
) -> None:
    good = output(tree)
    text, status = {
        "empty": ("", 0),
        "whitespace": (" \n\t", 0),
        "global": ("error TS18003: No inputs were found in config file.\n", 2),
        "unknown": ("unexpected runner output\n" + good, 2),
        "orphan-detail": ("  unowned continuation\n" + good, 2),
        "duplicate": (good + str(tree / "test/a.test.ts") + "\n", 2),
        "unlisted-diagnostic": (good.replace(str(tree / "test/a.test.ts") + "\n", ""), 2),
        "status-zero": (good, 0),
        "status-one": (good, 1),
        "status-two-without-errors": (output(tree, 0), 2),
    }[kind]
    before = census.DEFAULT_CENSUS.read_bytes()
    probe(monkeypatch, text, status)
    assert census.main(["--update"]) == 2
    captured = capsys.readouterr()
    assert "unable to measure" in captured.err and expected in captured.err
    assert "MEASURED:" not in captured.out
    assert census.DEFAULT_CENSUS.read_bytes() == before


def test_no_test_inputs_cannot_bless_an_empty_census(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tree / "source.ts"
    source.touch()
    probe(monkeypatch, str(source) + "\n", 0)
    assert census.main(["--update"]) == 2
    captured = capsys.readouterr()
    assert "MEASURED: 0 test file(s)" in captured.out
    assert "unable to measure: no test files compiled" in captured.err
    assert "refusing to update" in captured.err


def test_source_diagnostics_cannot_be_hidden_or_blessed(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tree / "helper.ts"
    source.touch()
    text = f"{source}(1,1): error TS2322: incompatible types\n{source}\n" + output(tree)
    probe(monkeypatch, text, 2)
    assert census.main(["--update"]) == 2
    assert "helper.ts" in capsys.readouterr().err


@pytest.mark.parametrize("count,status", [(0, 0), (1, 2), (2, 2)])
def test_main_uses_the_pin_and_update_admits_both_directions(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    count: int,
    status: int,
) -> None:
    probe(monkeypatch, output(tree, count), status)
    assert census.main([]) == (0 if count == 1 else 1)
    captured = capsys.readouterr()
    assert "MEASURED: 2 test file(s)" in captured.out
    if count != 1:
        assert "test/a.test.ts" in captured.err
        assert ("decreased" if count == 0 else "increased") in captured.err
        assert "--update" in captured.err
    assert census.main(["--update"]) == 0
    # This census pins diagnostic counts, not test names: it declares the count-only
    # contract, and gets an empty digest map back.
    assert census.load_census(census.DEFAULT_CENSUS, census.SUITE, with_digests=False) == (
        {"test/a.test.ts": count, "test/b.test.ts": 0},
        {},
    )
    assert census.main([]) == 0


def test_update_refuses_a_clean_file_absent_from_probe_without_writing(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    before = census.DEFAULT_CENSUS.read_bytes()
    probe(monkeypatch, output(tree, include_b=False), 2)
    assert census.main(["--update"]) == 1
    captured = capsys.readouterr()
    assert "MEASURED: 1 test file(s)" in captured.out
    assert "test/b.test.ts is on disk but was NOT compiled" in captured.err
    assert "refusing to update" in captured.err
    assert census.DEFAULT_CENSUS.read_bytes() == before


@pytest.mark.parametrize("missing", ["node_modules", "tsc", "node"])
def test_absent_prerequisite_exits_78_without_starting_probe(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing: str,
) -> None:
    if missing == "node_modules":
        (tree / "node_modules").rename(tree / "modules-backup")
    elif missing == "tsc":
        census.DEFAULT_TSC.rename(census.DEFAULT_TSC.with_name("tsc-backup"))
    else:
        monkeypatch.setattr(census.shutil, "which", lambda _: None)

    def must_not_start(*args: object, **kwargs: object) -> None:
        pytest.fail("probe started without its prerequisite")

    monkeypatch.setattr(census.subprocess, "run", must_not_start)
    assert census.main([]) == 78
    captured = capsys.readouterr()
    assert "missing prerequisite" in captured.err and missing in captured.err
    assert "MEASURED:" not in captured.out
    assert census.main(["--selftest"]) == 0


def test_present_but_unstartable_probe_is_unmeasured(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def cannot_start(*args: object, **kwargs: object) -> None:
        raise PermissionError("tsc is not executable")

    monkeypatch.setattr(census.subprocess, "run", cannot_start)
    assert census.main([]) == 2
    captured = capsys.readouterr()
    assert "unable to measure: tsc is not executable" in captured.err
    assert "MEASURED:" not in captured.out


@pytest.mark.parametrize("malformed", [None, "{}", '{"suites":{},"suites":{}}'])
def test_missing_or_invalid_pin_is_not_an_environment_failure(
    tree: Path,
    capsys: pytest.CaptureFixture[str],
    malformed: str | None,
) -> None:
    if malformed is None:
        census.DEFAULT_CENSUS.unlink()
    else:
        census.DEFAULT_CENSUS.write_text(malformed)
    assert census.main([]) == 1
    assert "invalid census" in capsys.readouterr().err


# Remove one property from the real comparison, never from a substitute oracle.
# The selftest must lose named cases, even when other guards still turn them red.
DISABLED = {
    "nonempty": ("if not run:", "if False:"),
    "disk-presence": ("sorted(disk_set - run_files)", "()"),
    "compiled-on-disk": ("sorted(run_files - disk_set)", "()"),
    "pinned-file": ("sorted(census_files - run_files)", "()"),
    "registered-file": ("sorted(run_files - census_files)", "()"),
    "increase": ("if run[name] > census[name]:", "if False:"),
    "decrease": ("if run[name] < census[name]:", "if False:"),
    "total": ("if run_total != expected_total:", "if False:"),
}


@pytest.mark.parametrize("guard", DISABLED)
def test_selftest_loses_cases_when_each_property_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    guard: str,
) -> None:
    assert census.selftest() == 0
    healthy_summary = capsys.readouterr().out.splitlines()[-1]
    source = inspect.getsource(census.compare)
    old, new = DISABLED[guard]
    assert source.count(old) == 1, f"{guard}: mutation no longer uniquely located"
    namespace = dict(vars(census))
    exec(compile(source.replace(old, new), f"<disabled {guard}>", "exec"), namespace)  # noqa: S102
    monkeypatch.setattr(census, "compare", namespace["compare"])
    assert census.selftest() == 1
    captured = capsys.readouterr().out
    summary = captured.splitlines()[-1]
    assert summary != healthy_summary
    assert "  FAIL " in captured
    print(f"disabled {guard}: {healthy_summary} -> {summary}; exit 1")
