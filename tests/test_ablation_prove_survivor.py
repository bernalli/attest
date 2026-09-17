"""Tests for the survivor prover: the readings it compares, and the journal it works under.

The prover is run as a subprocess against the fixture tree the ablation
self-test uses, because its exit status is the thing under test: a caller that
reads `POTENT`, `INERT`, "the probe never ran" or "the journal is held" off the
status has to get four different numbers. Running it in-process would also
install this process's `atexit` hook and signal handlers, which is what the
journal does for whoever holds it.

The probes live outside the tree. A probe written inside it would be an
untracked file, and every case here asserts on what `git status` says about the
tree before and after the measurement.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

_ABLATION_DIR = Path(__file__).resolve().parents[1] / "tools" / "gates" / "ablation"
_PROVER = _ABLATION_DIR / "prove_survivor.py"
_JOURNAL_PATH = _ABLATION_DIR / "journal.py"
_GENERATOR_PATH = _ABLATION_DIR / "selftest" / "make_fixture_tree.py"
_SPEC = _ABLATION_DIR / "selftest" / "spec_fixture.json"
_JOURNAL_DIRNAME = ".ablation-in-flight"

#: Reaches the value the fixture's target module holds: `VALUE = 2` becomes `VALUE = 0`.
_POTENT_MUTANT = "ST2-property-red"
#: Changes bytes without changing the value: a comment is appended to the same line.
_INERT_MUTANT = "ST6-inert"

#: Prints the target's value: the reading changes only if the mutation reaches it.
_PROBE_READS_VALUE = "import sample\n\nprint(sample.VALUE)\n"
#: Never runs, on any tree: it stands for a probe that is broken on its own.
_PROBE_NEVER_RUNS = "raise SystemExit('this probe refuses to run')\n"
#: Reads nothing of the tree: every run prints a different line, mutation or not.
_PROBE_NOT_A_FUNCTION_OF_THE_TREE = "import time\n\nimport sample\n\nprint(time.time_ns())\n"
#: Leaves the target holding bytes no record names, which a restore must refuse.
_PROBE_CLOBBERS_UNDER_MUTATION = (
    "import pathlib\n"
    "\n"
    "import sample\n"
    "\n"
    "print(sample.VALUE)\n"
    "if sample.VALUE == 0:\n"
    "    pathlib.Path('sample.py').write_text('VALUE = 5\\n', encoding='utf-8')\n"
)
#: Runs on the original value and refuses under the mutation, which is a form break.
_PROBE_NEEDS_ORIGINAL = (
    "import sample\n"
    "\n"
    "if sample.VALUE != 2:\n"
    "    raise SystemExit('this probe runs only on the original value')\n"
    "print(sample.VALUE)\n"
)


def _load_module(name: str, path: Path, *, register: bool = False) -> ModuleType:
    """Load a module of the bench by path.

    `register` puts it in `sys.modules` before it is executed, which a module
    defining dataclasses under string annotations needs: `dataclasses` resolves
    those annotations by looking its own module up there, and a module that is
    not registered makes that lookup fail while the class is being built.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fixture_tree(tmp_path: Path) -> Path:
    """A fresh fixture repository, built by the bench's own generator."""
    generator = _load_module("_prove_survivor_fixture_tree", _GENERATOR_PATH)
    tree: Path = generator.make_fixture_tree(tmp_path / "tree", sys.executable)
    return tree


@pytest.fixture
def journal() -> Iterator[ModuleType]:
    """The journal module, loaded by path and taken back out of `sys.modules` after."""
    name = "_prove_survivor_journal"
    module = _load_module(name, _JOURNAL_PATH, register=True)
    try:
        yield module
    finally:
        sys.modules.pop(name, None)


def _write_probe(tmp_path: Path, name: str, source: str) -> Path:
    """Write a probe outside the tree, so it never shows up in the tree's git status."""
    probes = tmp_path / "probes"
    probes.mkdir(exist_ok=True)
    probe = probes / name
    probe.write_text(source, encoding="utf-8")
    return probe


def _run_prover(tree: Path, mutant_id: str, probe: Path) -> subprocess.CompletedProcess[str]:
    """Run the prover against `tree` for one mutant of the fixture spec."""
    return subprocess.run(  # noqa: S603 -- the current interpreter on a file of this repository
        [sys.executable, str(_PROVER), str(_SPEC), mutant_id, str(probe), "--tree", str(tree)],
        capture_output=True,
        text=True,
        check=False,
    )


def _fields(stdout: str) -> dict[str, str]:
    """The prover's `name : value` lines, keyed by the name before the colon."""
    fields = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() and " " not in key.strip():
            fields[key.strip()] = value.strip()
    return fields


def _porcelain(tree: Path) -> str:
    """`git status --porcelain`, with untracked files shown whatever the global config says."""
    return subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],  # noqa: S607 -- git on PATH
        cwd=str(tree),
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _sha256(path: Path) -> str:
    """Hex SHA-256 of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(tree: Path, *args: str) -> None:
    """One git command in `tree`, with an identity of its own so a commit needs no global one."""
    identity = ["-c", "user.name=ablation", "-c", "user.email=ablation@localhost"]
    subprocess.run(  # noqa: S603 -- an argv built here, no shell
        ["git", *identity, *args],  # noqa: S607 -- git on PATH
        cwd=str(tree),
        check=True,
        capture_output=True,
    )


def test_a_mutant_the_probe_reads_differently_is_potent(fixture_tree: Path, tmp_path: Path) -> None:
    """P1: the two readings differ, the verdict is POTENT, and the tree is left as it was."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)

    result = _run_prover(fixture_tree, _POTENT_MUTANT, probe)

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    fields = _fields(result.stdout)
    assert fields["mutant"] == _POTENT_MUTANT
    assert fields["original"] == "2"
    assert fields["mutated"] == "0"
    assert fields["VERDICT"].startswith("POTENT")
    assert _porcelain(fixture_tree) == ""
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()


def test_a_mutant_the_probe_reads_the_same_is_inert(fixture_tree: Path, tmp_path: Path) -> None:
    """P2: bytes changed and the reading did not, which is what a false survivor looks like."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)

    result = _run_prover(fixture_tree, _INERT_MUTANT, probe)

    assert result.returncode == 1, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    fields = _fields(result.stdout)
    assert fields["mutant"] == _INERT_MUTANT
    assert fields["original"] == "2"
    assert fields["mutated"] == "2"
    assert fields["VERDICT"].startswith("INERT")
    assert _porcelain(fixture_tree) == ""
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()


def test_a_journal_already_under_the_tree_stops_the_prover_at_the_door(
    fixture_tree: Path, tmp_path: Path
) -> None:
    """P3: what a killed run left is not touched, and no mutation is applied over it."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)
    journal_dir = fixture_tree / _JOURNAL_DIRNAME
    journal_dir.mkdir()
    owner_file = journal_dir / "owner.json"
    owner_file.write_text(
        json.dumps({"pid": 4_000_000, "started_utc": "2026-01-01T00:00:00Z", "argv": []}),
        encoding="utf-8",
    )
    target = fixture_tree / "sample.py"
    target_before = _sha256(target)
    owner_before = owner_file.read_bytes()

    result = _run_prover(fixture_tree, _POTENT_MUTANT, probe)

    assert result.returncode == 8, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "REFUSING" in result.stderr
    assert str(journal_dir) in result.stderr
    assert "another ablation is running" in result.stderr
    assert _sha256(target) == target_before
    assert sorted(entry.name for entry in journal_dir.iterdir()) == ["owner.json"]
    assert owner_file.read_bytes() == owner_before


def test_a_probe_that_does_not_run_on_the_original_tree_mutates_nothing(
    fixture_tree: Path, tmp_path: Path
) -> None:
    """P4: a measurement that never started is not a verdict about the mutant."""
    probe = _write_probe(tmp_path, "never_runs.py", _PROBE_NEVER_RUNS)
    target = fixture_tree / "sample.py"
    target_before = _sha256(target)

    result = _run_prover(fixture_tree, _POTENT_MUTANT, probe)

    assert result.returncode == 2, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "PROBE BROKEN on the original tree, nothing was measured" in result.stdout
    assert _sha256(target) == target_before
    assert _porcelain(fixture_tree) == ""
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()


def test_a_probe_the_mutation_stops_is_broken_by_it_not_potent(
    fixture_tree: Path, tmp_path: Path
) -> None:
    """P5: the readings differ because the form broke, which says nothing about the property."""
    probe = _write_probe(tmp_path, "needs_original.py", _PROBE_NEEDS_ORIGINAL)

    result = _run_prover(fixture_tree, _POTENT_MUTANT, probe)

    assert result.returncode == 3, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    fields = _fields(result.stdout)
    assert fields["mutant"] == _POTENT_MUTANT
    assert fields["VERDICT"].startswith("BROKEN BY THE MUTATION")
    assert _porcelain(fixture_tree) == ""
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()


def test_a_mutation_asked_for_outside_the_held_journal_is_a_named_refusal(
    fixture_tree: Path, journal: ModuleType
) -> None:
    """P6: without the journal there is nowhere to record the mutation, so it is refused.

    The refusal has to name itself. A journal directory that was never created
    would otherwise surface as whatever error the first write to it raises, and
    a caller reading a traceback about an absent path cannot tell a refusal from
    a defect.
    """
    owner = journal.journal_owner(fixture_tree, ["prove_survivor.py"])

    with pytest.raises(journal.JournalNotHeld) as caught:
        owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")

    assert type(caught.value) is journal.JournalNotHeld
    assert "is not held by this process" in str(caught.value)
    assert "journal_owner()" in str(caught.value)
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()
    assert _porcelain(fixture_tree) == ""


def _run_prover_argv(
    argv: list[str], prover: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a copy of the prover on an argument list of the caller's own making."""
    return subprocess.run(  # noqa: S603 -- the current interpreter on a file of this repository
        [sys.executable, str(prover or _PROVER), *argv],
        capture_output=True,
        text=True,
        check=False,
    )


def _spec_with(tmp_path: Path, name: str, rows: object) -> Path:
    """A spec file holding `rows` under `mutants`, written where the test can point at it."""
    path = tmp_path / name
    path.write_text(json.dumps({"mutants": rows}), encoding="utf-8")
    return path


#: A well-formed source row of a spec, the shape every malformed one below departs from.
_SOURCE_ROW = {"id": "M1", "file": "sample.py", "old": "VALUE = 2", "new": "VALUE = 0"}


def test_a_probe_that_is_not_a_function_of_the_tree_measures_nothing(
    fixture_tree: Path, tmp_path: Path
) -> None:
    """P7: two readings of the unmutated tree that disagree cannot be compared with a third.

    The mutant here is the inert one, the reading changes anyway, and the verdict
    that would come out of comparing the two is `POTENT` -- a false survivor
    called real by the tool whose one job is to tell those apart.
    """
    probe = _write_probe(tmp_path, "not_a_function.py", _PROBE_NOT_A_FUNCTION_OF_THE_TREE)
    target = fixture_tree / "sample.py"
    target_before = _sha256(target)

    result = _run_prover(fixture_tree, _INERT_MUTANT, probe)

    assert result.returncode == 2, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "disagreed with itself" in result.stdout
    assert "VERDICT" not in result.stdout
    assert _sha256(target) == target_before
    assert _porcelain(fixture_tree) == ""
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()


def test_a_restore_the_journal_refuses_becomes_the_exit_status(
    fixture_tree: Path, tmp_path: Path
) -> None:
    """P8: a refused restore is reported by name and is not masked by a verdict about the mutant.

    The probe leaves the target holding bytes no record names, so putting it
    back is refused. The record stays, the file is left alone, and the exit
    status is the journal's, not the comparison's.
    """
    probe = _write_probe(tmp_path, "clobbers.py", _PROBE_CLOBBERS_UNDER_MUTATION)

    result = _run_prover(fixture_tree, _POTENT_MUTANT, probe)

    assert result.returncode == 9, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "is in an unknown state" in result.stderr
    assert "sample.py" in result.stderr
    assert "VERDICT" not in result.stdout
    assert (fixture_tree / _JOURNAL_DIRNAME / "01-sample.py.orig").is_file()
    assert (fixture_tree / "sample.py").read_text(encoding="utf-8") == "VALUE = 5\n"


def test_without_tree_the_prover_works_on_the_tree_holding_its_own_file(
    fixture_tree: Path, tmp_path: Path
) -> None:
    """P9: the default tree is the top level of the working tree this file sits in.

    The prover and the journal are carried into the fixture and committed there,
    so the default resolves to the fixture and the case never touches the tree
    this suite runs from.
    """
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)
    carried = fixture_tree / "bench"
    carried.mkdir()
    for module in (_PROVER, _JOURNAL_PATH):
        shutil.copy(module, carried / module.name)
    _git(fixture_tree, "add", "-A")
    _git(fixture_tree, "commit", "-q", "-m", "carry the prover")

    result = _run_prover_argv(
        [str(_SPEC), _POTENT_MUTANT, str(probe)], prover=carried / _PROVER.name
    )

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    fields = _fields(result.stdout)
    assert fields["original"] == "2"
    assert fields["mutated"] == "0"
    assert fields["VERDICT"].startswith("POTENT")
    assert _porcelain(fixture_tree) == ""


@pytest.mark.parametrize(
    ("case", "rows", "mutant_id", "expected"),
    [
        ("top-level-list", [], "M1", "has no mutant"),
        ("unknown-id", [_SOURCE_ROW], "ABSENT", "has no mutant 'ABSENT'"),
        ("repeated-id", [_SOURCE_ROW, _SOURCE_ROW], "M1", "2 mutants with the id 'M1'"),
        (
            "plugin-kind",
            [{"id": "M1", "kind": "plugin", "plugin": "tools.p"}],
            "M1",
            "which changes no file",
        ),
        (
            "missing-old",
            [{"id": "M1", "file": "sample.py", "new": "VALUE = 0"}],
            "M1",
            "missing the string keys",
        ),
        (
            "old-not-a-string",
            [{"id": "M1", "file": "sample.py", "old": 2, "new": "VALUE = 0"}],
            "M1",
            "missing the string keys",
        ),
    ],
)
def test_a_spec_the_prover_cannot_apply_is_refused_by_name(
    fixture_tree: Path, tmp_path: Path, case: str, rows: object, mutant_id: str, expected: str
) -> None:
    """P10: every shape of spec this tool cannot act on is a named refusal, never a traceback."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)
    spec = _spec_with(tmp_path, f"{case}.json", rows)
    target_before = _sha256(fixture_tree / "sample.py")

    result = _run_prover_argv([str(spec), mutant_id, str(probe), "--tree", str(fixture_tree)])

    assert result.returncode == 4, f"{case}: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert expected in result.stderr, f"{case}: {result.stderr!r}"
    assert "Traceback" not in result.stderr, f"{case}: {result.stderr!r}"
    assert _sha256(fixture_tree / "sample.py") == target_before
    assert _porcelain(fixture_tree) == ""


@pytest.mark.parametrize(
    ("case", "text", "expected"),
    [
        ("not-json", "this is not JSON", "is not valid JSON"),
        ("a-json-list", "[]", "has no 'mutants' array"),
        ("no-mutants-key", '{"launcher": []}', "has no 'mutants' array"),
        ("mutants-not-a-list", '{"mutants": {}}', "has no 'mutants' array"),
    ],
)
def test_a_spec_that_is_not_a_spec_is_refused_by_name(
    fixture_tree: Path, tmp_path: Path, case: str, text: str, expected: str
) -> None:
    """P11: a document that is not a spec is named as such, not parsed on hope."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)
    spec = tmp_path / f"{case}.json"
    spec.write_text(text, encoding="utf-8")

    result = _run_prover_argv([str(spec), "M1", str(probe), "--tree", str(fixture_tree)])

    assert result.returncode == 4, f"{case}: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert expected in result.stderr, f"{case}: {result.stderr!r}"
    assert "Traceback" not in result.stderr, f"{case}: {result.stderr!r}"
    assert _porcelain(fixture_tree) == ""


def test_a_spec_that_cannot_be_read_is_refused_by_name(fixture_tree: Path, tmp_path: Path) -> None:
    """P12: an absent spec names the file, and is not an unhandled `OSError`."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)

    result = _run_prover_argv(
        [str(tmp_path / "absent.json"), "M1", str(probe), "--tree", str(fixture_tree)]
    )

    assert result.returncode == 4, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "cannot be read" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("case", "old", "expected"),
    [
        ("anchor-absent", "VALUE = 99", "anchor text occurs 0 times"),
        ("anchor-empty", "", "anchor text is empty"),
    ],
)
def test_a_mutation_the_journal_will_not_land_is_refused_by_name(
    fixture_tree: Path, tmp_path: Path, case: str, old: str, expected: str
) -> None:
    """P13: the journal's own refusals reach the caller as a message and as exit 4.

    `MutationDidNotLand` carries no exit status of its own, so the prover has to
    give it one; a refusal that arrived as a traceback would be indistinguishable
    from a defect of this tool.
    """
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)
    rows = [{"id": "M1", "file": "sample.py", "old": old, "new": "VALUE = 0"}]
    spec = _spec_with(tmp_path, f"{case}.json", rows)
    target_before = _sha256(fixture_tree / "sample.py")

    result = _run_prover_argv([str(spec), "M1", str(probe), "--tree", str(fixture_tree)])

    assert result.returncode == 4, f"{case}: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert expected in result.stderr, f"{case}: {result.stderr!r}"
    assert "Traceback" not in result.stderr, f"{case}: {result.stderr!r}"
    assert _sha256(fixture_tree / "sample.py") == target_before
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()


def test_a_target_outside_the_tree_is_refused_by_name(fixture_tree: Path, tmp_path: Path) -> None:
    """P14: a spec that points out of the tree does not get to mutate anything."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)
    rows = [{"id": "M1", "file": "../outside.py", "old": "VALUE = 2", "new": "VALUE = 0"}]
    spec = _spec_with(tmp_path, "outside.json", rows)

    result = _run_prover_argv([str(spec), "M1", str(probe), "--tree", str(fixture_tree)])

    assert result.returncode == 4, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "Traceback" not in result.stderr, result.stderr
    assert _porcelain(fixture_tree) == ""


@pytest.mark.parametrize(
    ("case", "tree_of", "expected"),
    [
        ("not-a-directory", "file", "is not a directory"),
        ("not-a-repository", "plain-dir", "is not the top level of a git working tree"),
        ("below-the-top-level", "subdir", "is not the top level of a git working tree"),
    ],
)
def test_a_tree_that_is_not_a_working_tree_top_level_is_refused(
    fixture_tree: Path, tmp_path: Path, case: str, tree_of: str, expected: str
) -> None:
    """P15: the journal, the probe's imports and the mutation are all rooted at the top level."""
    probe = _write_probe(tmp_path, "reads_value.py", _PROBE_READS_VALUE)
    if tree_of == "file":
        given = tmp_path / "a-file"
        given.write_text("", encoding="utf-8")
    elif tree_of == "plain-dir":
        given = tmp_path / "plain"
        given.mkdir()
    else:
        given = fixture_tree / "below"
        given.mkdir()

    result = _run_prover_argv([str(_SPEC), _POTENT_MUTANT, str(probe), "--tree", str(given)])

    assert result.returncode == 4, f"{case}: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert expected in result.stderr, f"{case}: {result.stderr!r}"


def test_a_probe_that_is_not_a_file_is_refused_before_the_journal_is_taken(
    fixture_tree: Path, tmp_path: Path
) -> None:
    """P16: the probe is checked before the tree is held, so nothing has to be put back."""
    result = _run_prover_argv(
        [str(_SPEC), _POTENT_MUTANT, str(tmp_path / "absent.py"), "--tree", str(fixture_tree)]
    )

    assert result.returncode == 4, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "is not a file" in result.stderr
    assert not (fixture_tree / _JOURNAL_DIRNAME).exists()
    assert _porcelain(fixture_tree) == ""


def test_a_bad_invocation_never_exits_with_the_reading_of_a_broken_probe(tmp_path: Path) -> None:
    """P17: `argparse` exits 2 on a bad command line, and 2 already means something here."""
    result = _run_prover_argv([str(_SPEC)])

    assert result.returncode == 4, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr
