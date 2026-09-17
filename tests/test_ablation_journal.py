"""Tests for the ablation bench's write-ahead journal (`tools/gates/ablation/journal.py`).

Every test that lets the journal write runs against a fixture repository built
by the bench's own generator under pytest's temporary directory: the journal
rewrites files, and nothing here ever points it at this repository.

The module under test is loaded by path, under a name no other test uses. It
is registered in `sys.modules` before it runs, because its dataclasses resolve
their string annotations through that registry. Tests that need a process to
die in a way no Python code survives run the journal in a child interpreter and
kill it for real.

Expected hashes and bytes come from `git show HEAD:<path>` and from applying
the replacement to that blob here, never from values the journal reports about
itself.
"""

from __future__ import annotations

import atexit
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import py_compile
import signal
import stat
import struct
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

_ABLATION_DIR = Path(__file__).resolve().parents[1] / "tools" / "gates" / "ablation"
_JOURNAL_PATH = _ABLATION_DIR / "journal.py"
_GENERATOR_PATH = _ABLATION_DIR / "selftest" / "make_fixture_tree.py"
_JOURNAL_MODULE_NAME = "_ablation_journal_under_test"

JOURNAL_DIRNAME = ".ablation-in-flight"
SAMPLE_ORIGINAL = b"VALUE = 2\n"
SAMPLE_MUTATED = b"VALUE = 0\n"
FIXTURE_FILES = ("sample.py", "helper.py", "test_sample.py")
LEDGER_FIELDS = ("rel_path", "sha_before", "sha_after", "size_before", "size_after", "applied_utc")
PROBE_FILES = ("00-exchange-probe-a.tmp", "00-exchange-probe-b.tmp")

# Child interpreter: load the journal by path, hold the tree, apply the mutations
# given as JSON, then end the way argv[4] says -- SIGKILL, SIGTERM, a plain
# sys.exit() outside any `with` block (so only atexit can restore), or SIGKILL
# right after acquiring, before any mutation.
_CHILD_SCRIPT = """
import importlib.util, json, os, signal, sys, time
from pathlib import Path

spec = importlib.util.spec_from_file_location("ablation_journal_child", sys.argv[1])
journal = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = journal
spec.loader.exec_module(journal)

tree = Path(sys.argv[2])
mutations = json.loads(sys.argv[3])
ending = sys.argv[4]

if ending == "atexit":
    owner = journal.journal_owner(tree, sys.argv).__enter__()
    for rel_path, old, new in mutations:
        owner.apply_source(rel_path, old, new)
    sys.exit(3)

with journal.journal_owner(tree, sys.argv) as owner:
    for rel_path, old, new in mutations:
        owner.apply_source(rel_path, old, new)
    if ending == "sigkill":
        os.kill(os.getpid(), signal.SIGKILL)
    elif ending == "sigterm":
        os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(5)
    sys.exit(99)
"""


def _load_by_path(path: Path, name: str, *, register: bool) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def journal() -> Iterator[ModuleType]:
    module = _load_by_path(_JOURNAL_PATH, _JOURNAL_MODULE_NAME, register=True)
    try:
        yield module
    finally:
        sys.modules.pop(_JOURNAL_MODULE_NAME, None)


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_by_path(_GENERATOR_PATH, "_ablation_fixture_generator", register=False)


@pytest.fixture
def tree(tmp_path: Path, generator: ModuleType) -> Path:
    result: Path = generator.make_fixture_tree(tmp_path / "fixture", sys.executable)
    return result.resolve()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(tree: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell
        ["git", "-C", str(tree), *args],  # noqa: S607 -- git from PATH
        check=True,
        capture_output=True,
    )


def _head_blob(tree: Path, rel_path: str) -> bytes:
    return _git(tree, "show", f"HEAD:{rel_path}").stdout


def _porcelain(tree: Path) -> str:
    return _git(tree, "status", "--porcelain", "--untracked-files=normal").stdout.decode()


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("PYTHONPYCACHEPREFIX", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run_child(
    tree: Path, mutations: list[tuple[str, str, str]], ending: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [
            sys.executable,
            "-c",
            _CHILD_SCRIPT,
            str(_JOURNAL_PATH),
            str(tree),
            json.dumps(mutations),
            ending,
        ],
        cwd=str(tree.parent),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )


def _snapshot(directory: Path) -> dict[str, str]:
    """Every entry of `directory` by name, with the SHA-256 of each file's bytes."""
    return {
        entry.name: _sha(entry.read_bytes()) if entry.is_file() else "<dir>"
        for entry in sorted(directory.iterdir())
    }


def _record_files(tree: Path) -> list[str]:
    journal_dir = tree / JOURNAL_DIRNAME
    if not journal_dir.exists():
        return []
    return sorted(entry.name for entry in journal_dir.iterdir() if entry.name != "owner.json")


def _handlers() -> dict[int, Any]:
    return {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}


def _import_sample_value(tree: Path) -> str:
    result = subprocess.run(
        [sys.executable, "-c", "import sample; print(sample.VALUE)"],
        cwd=str(tree),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def _pyc_flags(pyc: Path) -> int:
    flags: int = struct.unpack("<I", pyc.read_bytes()[4:8])[0]
    return flags


def _sample_cache(tree: Path) -> Path:
    return tree / "__pycache__" / f"sample.{sys.implementation.cache_tag}.pyc"


# --- write-ahead: the record is on disk before the target changes ---------------------------


def test_record_is_on_disk_when_the_target_write_fails(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = _head_blob(tree, "sample.py")
    journal_dir = tree / JOURNAL_DIRNAME

    def failing_target_write(path: Path, data: bytes, staging: Path) -> None:
        raise OSError("injected: the target write fails")

    with journal.journal_owner(tree, ["test"]) as owner:
        monkeypatch.setattr(journal, "_write_target", failing_target_write)
        with pytest.raises(OSError, match="injected"):
            owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        monkeypatch.undo()

        records = _record_files(tree)
        target_now = (tree / "sample.py").read_bytes()
        assert records == ["01-sample.py.json", "01-sample.py.orig"], (
            f"record absent from {journal_dir} after the target write failed; "
            f"records={records}, sample.py sha={_sha(target_now)} (HEAD blob sha={_sha(head)})"
        )
        assert target_now == head, "sample.py changed although its write failed"

    assert (tree / "sample.py").read_bytes() == head
    assert not journal_dir.exists()
    assert _porcelain(tree) == ""


def test_target_is_still_original_when_the_record_is_written(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = _head_blob(tree, "sample.py")
    real_write_record = journal._write_record
    seen: list[bytes] = []

    def spying_write_record(journal_dir: Path, record: Any, original: bytes) -> None:
        seen.append((tree / "sample.py").read_bytes())
        real_write_record(journal_dir, record, original)

    monkeypatch.setattr(journal, "_write_record", spying_write_record)
    with journal.journal_owner(tree, ["test"]) as owner:
        owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")

    assert len(seen) == 1
    assert seen[0] == head, (
        f"record written with the target already mutated: sample.py sha={_sha(seen[0])} "
        f"when the record was written, HEAD blob sha={_sha(head)}"
    )


def test_record_carries_the_original_bytes_and_both_hashes(journal: ModuleType, tree: Path) -> None:
    head = _head_blob(tree, "sample.py")
    expected_after = head.replace(b"VALUE = 2", b"VALUE = 0", 1)
    journal_dir = tree / JOURNAL_DIRNAME

    with journal.journal_owner(tree, ["test"]) as owner:
        record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        entry = json.loads((journal_dir / "01-sample.py.json").read_bytes())
        orig = (journal_dir / "01-sample.py.orig").read_bytes()
        on_disk = (tree / "sample.py").read_bytes()
        owner.restore(record)

    assert set(entry) == set(LEDGER_FIELDS)
    assert entry["rel_path"] == "sample.py"
    assert entry["sha_before"] == _sha(head)
    assert entry["sha_after"] == _sha(expected_after)
    assert (entry["size_before"], entry["size_after"]) == (len(head), len(expected_after))
    assert isinstance(entry["applied_utc"], str) and entry["applied_utc"].endswith("Z")
    assert orig == head
    assert on_disk == expected_after
    assert record.name == "01-sample.py" and record.nn == 1 and record.confirmed_on_disk


def test_owner_file_names_this_process_tree_head_and_argv(journal: ModuleType, tree: Path) -> None:
    head_sha = _git(tree, "rev-parse", "HEAD").stdout.decode().strip()
    with journal.journal_owner(tree, ["ablate.py", "spec.json"]):
        owner = json.loads((tree / JOURNAL_DIRNAME / "owner.json").read_bytes())
    assert set(owner) == {"pid", "started_utc", "tree", "head_sha", "argv"}
    assert owner["pid"] == os.getpid()
    assert owner["tree"] == str(tree)
    assert owner["head_sha"] == head_sha
    assert owner["argv"] == ["ablate.py", "spec.json"]


def test_a_write_that_does_not_land_is_refused_with_the_record_held(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = _head_blob(tree, "sample.py")

    def lost_write(path: Path, data: bytes, staging: Path) -> None:
        return None

    with journal.journal_owner(tree, ["test"]) as owner:
        monkeypatch.setattr(journal, "_write_target", lost_write)
        with pytest.raises(journal.MutationDidNotLand) as refused:
            owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        monkeypatch.undo()
        record = refused.value.record
        assert record is not None and not record.confirmed_on_disk
        assert _record_files(tree) == ["01-sample.py.json", "01-sample.py.orig"]
        assert (tree / "sample.py").read_bytes() == head
        assert owner.restore(record) == "already_original"
        assert _record_files(tree) == []

    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


def test_a_write_that_lands_other_bytes_is_refused_with_the_record_held(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write_target = journal._write_target
    drifted = SAMPLE_MUTATED + b"# drift\n"

    def drifting_write(path: Path, data: bytes, staging: Path) -> None:
        real_write_target(path, data + b"# drift\n", staging)

    refusal: Any = None
    # The drifted bytes still contain the new text: only the hash of the re-read tells
    # that the file does not hold the mutation. Leaving the block then finds the file in
    # an unknown state, so the checks run after it.
    with pytest.raises(journal.UnknownState, match="is in an unknown state"):
        with journal.journal_owner(tree, ["test"]) as owner:
            monkeypatch.setattr(journal, "_write_target", drifting_write)
            try:
                owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            except journal.MutationDidNotLand as exc:
                refusal = exc
            monkeypatch.undo()
            records_after_refusal = _record_files(tree)

    assert refusal is not None, f"a write that landed {drifted!r} was confirmed as the mutation"
    assert "does not hold the mutation" in str(refusal)
    assert refusal.record is not None and not refusal.record.confirmed_on_disk
    assert records_after_refusal == ["01-sample.py.json", "01-sample.py.orig"]
    assert _record_files(tree) == ["01-sample.py.json", "01-sample.py.orig"]
    assert (tree / "sample.py").read_bytes() == drifted


# --- restore verifies what it wrote ----------------------------------------------------------

# In the tests below the block is left with a record in an unknown state, so leaving it
# raises `UnknownState`. An assertion failing inside the block would be replaced by that
# exception and swallowed by the outer `pytest.raises`: what the refusal said is captured
# inside and asserted after the block.


def test_restore_refuses_an_orig_that_is_not_sha_before(journal: ModuleType, tree: Path) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    with pytest.raises(journal.UnknownState):
        with journal.journal_owner(tree, ["test"]) as owner:
            record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            (journal_dir / "01-sample.py.orig").write_bytes(b"VALUE = 3\n")
            snapshot = _snapshot(journal_dir)
            with pytest.raises(journal.UnknownState) as refused:
                owner.restore(record)
            snapshot_after_refusal = _snapshot(journal_dir)
            target_after_refusal = (tree / "sample.py").read_bytes()

    assert refused.value.exit_code == 9
    assert "01-sample.py.orig" in str(refused.value)
    assert f"expected sha_before {_sha(SAMPLE_ORIGINAL)}" in str(refused.value)
    assert snapshot_after_refusal == snapshot
    assert target_after_refusal == SAMPLE_MUTATED
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == SAMPLE_MUTATED


def test_restore_refuses_bytes_that_do_not_read_back_as_sha_before(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    real_write_target = journal._write_target

    def drifting_write(path: Path, data: bytes, staging: Path) -> None:
        real_write_target(path, data + b"# drift\n", staging)

    with pytest.raises(journal.UnknownState):
        with journal.journal_owner(tree, ["test"]) as owner:
            record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            snapshot = _snapshot(journal_dir)
            monkeypatch.setattr(journal, "_write_target", drifting_write)
            with pytest.raises(journal.UnknownState) as refused:
                owner.restore(record)
            monkeypatch.undo()
            snapshot_after_refusal = _snapshot(journal_dir)

    assert refused.value.exit_code == 9
    drifted = SAMPLE_ORIGINAL + b"# drift\n"
    assert str(refused.value) == (
        "REFUSING: sample.py did not read back as its original bytes after the restore "
        f"(sha={_sha(drifted)}, expected {_sha(SAMPLE_ORIGINAL)}) — keeping record "
        "01-sample.py"
    )
    assert snapshot_after_refusal == snapshot
    assert _snapshot(journal_dir) == snapshot


# --- unknown state -------------------------------------------------------------------------


def test_unknown_state_is_refused_and_leaves_record_and_file(
    journal: ModuleType, tree: Path
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    head = _head_blob(tree, "sample.py")
    expected_after = head.replace(b"VALUE = 2", b"VALUE = 0", 1)
    handlers_before = _handlers()

    with pytest.raises(journal.UnknownState) as at_exit:
        with journal.journal_owner(tree, ["test"]) as owner:
            record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            (tree / "sample.py").write_bytes(b"VALUE = 5\n")
            snapshot = _snapshot(journal_dir)
            with pytest.raises(journal.UnknownState) as refused:
                owner.restore(record)
            snapshot_after_refusal = _snapshot(journal_dir)
            target_after_refusal = (tree / "sample.py").read_bytes()

    assert refused.value.exit_code == 9
    assert str(refused.value) == (
        f"REFUSING: sample.py is in an unknown state (sha={_sha(b'VALUE = 5\n')}, "
        f"expected {_sha(expected_after)} or {_sha(head)}) — not touching it"
    )
    assert snapshot_after_refusal == snapshot
    assert target_after_refusal == b"VALUE = 5\n"
    assert at_exit.value.exit_code == 9
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == b"VALUE = 5\n"
    assert _handlers() == handlers_before


def test_restore_journal_counts_an_unknown_state_and_keeps_everything(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -signal.SIGKILL, killed.stdout + killed.stderr
    (tree / "sample.py").write_bytes(b"VALUE = 5\n")
    snapshot = _snapshot(journal_dir)
    assert set(snapshot) == {"owner.json", "01-sample.py.json", "01-sample.py.orig"}

    summary = journal.restore_journal(tree)
    captured = capsys.readouterr()

    assert (summary.restored, summary.already_original, summary.unknown_state) == (0, 0, 1)
    assert captured.out.splitlines() == [
        "restored=0 already_original=0 unknown_state=1 tmp_removed=0 exchange_unavailable=0"
    ]
    assert "REFUSING: sample.py is in an unknown state" in captured.err
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == b"VALUE = 5\n"


# --- the process that does not hold the journal ------------------------------------------------


def test_a_process_refused_the_journal_registers_nothing_and_touches_nothing(
    journal: ModuleType, tree: Path
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -signal.SIGKILL, killed.stdout + killed.stderr
    owner = json.loads((journal_dir / "owner.json").read_bytes())
    snapshot = _snapshot(journal_dir)
    assert set(snapshot) == {"owner.json", "01-sample.py.json", "01-sample.py.orig"}

    # `_ncallbacks()` never decreases -- `atexit.unregister` leaves an empty slot behind --
    # so an unchanged count proves that nothing was registered, even briefly.
    callbacks_before = atexit._ncallbacks()
    handlers_before = _handlers()
    with pytest.raises(journal.JournalBusy) as refused:
        with journal.journal_owner(tree, ["test"]):
            pytest.fail("entered a journal that another process holds")

    assert atexit._ncallbacks() == callbacks_before
    assert _handlers() == handlers_before
    assert refused.value.exit_code == 8
    assert str(refused.value) == (
        f"REFUSING: {journal_dir} exists (owner pid={owner['pid']} "
        f"started={owner['started_utc']}) — another ablation is running, or a killed one "
        "left a mutation on disk; run --restore"
    )
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == SAMPLE_MUTATED


def test_the_holder_registers_handlers_inside_and_restores_them_on_exit(
    journal: ModuleType, tree: Path
) -> None:
    callbacks_before = atexit._ncallbacks()
    handlers_before = _handlers()
    with journal.journal_owner(tree, ["test"]):
        callbacks_inside = atexit._ncallbacks()
        handlers_inside = _handlers()
    assert callbacks_inside == callbacks_before + 1
    assert all(handlers_inside[s] != handlers_before[s] for s in handlers_before)
    assert _handlers() == handlers_before
    assert not (tree / JOURNAL_DIRNAME).exists()


# Child interpreter for the exit-hook probe: hold the tree, optionally leave the block
# (cleanly, or with a record in an unknown state), then swap the holder's replay for a
# function that writes a marker file, and exit normally. The marker exists afterwards only
# if the holder's `atexit` hook was still registered when the interpreter shut down.
_EXIT_HOOK_PROBE = """
import importlib.util, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("ablation_journal_child", sys.argv[1])
journal = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = journal
spec.loader.exec_module(journal)

tree, marker, mode = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
holder = journal.journal_owner(tree, sys.argv)
holder.__enter__()
if mode == "left-with-unknown-state":
    holder.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
    (tree / "sample.py").write_bytes(b"VALUE = 5\\n")
if mode != "never-left":
    try:
        holder.__exit__(None, None, None)
    except journal.UnknownState:
        pass
holder._restore_all = lambda: marker.write_text("exit hook ran", encoding="utf-8")
sys.exit(0)
"""


@pytest.mark.parametrize(
    ("mode", "hook_runs"),
    [("never-left", True), ("left-cleanly", False), ("left-with-unknown-state", False)],
)
def test_leaving_the_block_unregisters_the_exit_hook(
    tree: Path, tmp_path: Path, mode: str, hook_runs: bool
) -> None:
    marker = tmp_path / "exit-hook-ran"
    result = subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [sys.executable, "-c", _EXIT_HOOK_PROBE, str(_JOURNAL_PATH), str(tree), str(marker), mode],
        cwd=str(tree.parent),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.exists() is hook_runs, (
        f"mode={mode}: exit hook {'did not run' if hook_runs else 'still ran'}; "
        f"stderr={result.stderr!r}"
    )


def test_applying_outside_the_with_block_is_refused_by_name(
    journal: ModuleType, tree: Path
) -> None:
    holder = journal.journal_owner(tree, ["test"])
    with pytest.raises(journal.JournalNotHeld, match=r"REFUSING: .* is not held by this process"):
        holder.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert (tree / "sample.py").read_bytes() == SAMPLE_ORIGINAL


# --- a real SIGKILL, and the replay from another process ---------------------------------------


def test_sigkill_leaves_a_journal_that_restore_journal_replays(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    head = _head_blob(tree, "sample.py")

    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    after_kill = (tree / "sample.py").read_bytes()
    assert after_kill == SAMPLE_MUTATED, "the child did not leave sample.py mutated"
    records_after_kill = _record_files(tree)

    journal.restore_journal(tree)
    printed = capsys.readouterr().out
    restored = (tree / "sample.py").read_bytes()

    assert restored == head, (
        f"sample.py still mutated after restore_journal (sha={_sha(restored)}, HEAD blob "
        f"sha={_sha(head)}); it printed {printed.strip()!r}; records after the kill: "
        f"{records_after_kill}"
    )
    assert records_after_kill == ["01-sample.py.json", "01-sample.py.orig"]
    assert printed.splitlines() == [
        "restored=1 already_original=0 unknown_state=0 tmp_removed=0 exchange_unavailable=0"
    ]
    assert not journal_dir.exists()
    assert _porcelain(tree) == ""


def test_restore_journal_replays_records_newest_first(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    head = _head_blob(tree, "sample.py")
    killed = _run_child(
        tree,
        [("sample.py", "VALUE = 2", "VALUE = 0"), ("sample.py", "VALUE = 0", "VALUE = 7")],
        "sigkill",
    )
    assert killed.returncode == -9, killed.stdout + killed.stderr
    assert (tree / "sample.py").read_bytes() == b"VALUE = 7\n"
    assert _record_files(tree) == [
        "01-sample.py.json",
        "01-sample.py.orig",
        "02-sample.py.json",
        "02-sample.py.orig",
    ]

    journal.restore_journal(tree)

    assert capsys.readouterr().out.splitlines() == [
        "restored=2 already_original=0 unknown_state=0 tmp_removed=0 exchange_unavailable=0"
    ]
    assert (tree / "sample.py").read_bytes() == head
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


def test_restore_journal_counts_a_file_already_back_to_original(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    killed = _run_child(
        tree,
        [
            ("sample.py", "VALUE = 2", "VALUE = 0"),
            ("helper.py", "VALUE_NAME = 1", "VALUE_NAME = 4"),
        ],
        "sigkill",
    )
    assert killed.returncode == -9, killed.stdout + killed.stderr
    (tree / "helper.py").write_bytes(_head_blob(tree, "helper.py"))

    journal.restore_journal(tree)

    assert capsys.readouterr().out.splitlines() == [
        "restored=1 already_original=1 unknown_state=0 tmp_removed=0 exchange_unavailable=0"
    ]
    for rel_path in ("sample.py", "helper.py"):
        assert (tree / rel_path).read_bytes() == _head_blob(tree, rel_path)
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


def test_restore_journal_after_a_kill_before_any_mutation_removes_the_journal(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    killed = _run_child(tree, [], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    assert sorted(p.name for p in (tree / JOURNAL_DIRNAME).iterdir()) == ["owner.json"]

    journal.restore_journal(tree)

    assert capsys.readouterr().out.splitlines() == [
        "restored=0 already_original=0 unknown_state=0 tmp_removed=0 exchange_unavailable=0"
    ]
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


def test_restore_journal_without_a_journal_reports_nothing_and_creates_nothing(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = journal.restore_journal(tree)
    assert (summary.restored, summary.already_original, summary.unknown_state) == (0, 0, 0)
    assert capsys.readouterr().out.splitlines() == [
        "restored=0 already_original=0 unknown_state=0 tmp_removed=0 exchange_unavailable=0"
    ]
    assert not (tree / JOURNAL_DIRNAME).exists()


def test_restore_journal_refuses_while_the_owner_is_alive(journal: ModuleType, tree: Path) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    owner_path = journal_dir / "owner.json"
    owner = json.loads(owner_path.read_bytes())
    owner["pid"] = os.getpid()
    owner_path.write_text(json.dumps(owner), encoding="utf-8")
    snapshot = _snapshot(journal_dir)
    assert set(snapshot) == {"owner.json", "01-sample.py.json", "01-sample.py.orig"}

    with pytest.raises(journal.JournalBusy) as refused:
        journal.restore_journal(tree)

    assert refused.value.exit_code == 8
    assert str(refused.value) == f"REFUSING: owner pid={os.getpid()} is alive"
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == SAMPLE_MUTATED


@pytest.mark.parametrize(
    "owner_bytes",
    [None, b"{not json", b'{"pid": "123"}', b'{"pid": 0}', b'{"pid": true}', b"[]"],
    ids=["missing", "truncated", "pid-string", "pid-zero", "pid-bool", "not-an-object"],
)
def test_restore_journal_refuses_an_owner_file_it_cannot_read(
    journal: ModuleType, tree: Path, owner_bytes: bytes | None
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    owner_path = journal_dir / "owner.json"
    if owner_bytes is None:
        owner_path.unlink()
    else:
        owner_path.write_bytes(owner_bytes)
    snapshot = _snapshot(journal_dir)

    with pytest.raises(journal.JournalBusy, match="cannot establish that the owner is gone"):
        journal.restore_journal(tree)

    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == SAMPLE_MUTATED


# Child interpreter killed between creating the journal directory and writing its owner file.
_KILLED_BEFORE_OWNER = """
import importlib.util, os, signal, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("ablation_journal_child", sys.argv[1])
journal = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = journal
spec.loader.exec_module(journal)

real_create = journal._create_synced

def create(path, data):
    if path.name == journal.OWNER_FILENAME:
        os.kill(os.getpid(), signal.SIGKILL)
    real_create(path, data)

journal._create_synced = create
with journal.journal_owner(Path(sys.argv[2]), sys.argv):
    pass
"""


def test_restore_journal_names_the_way_out_of_a_journal_killed_before_its_owner_file(
    journal: ModuleType, tree: Path
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [sys.executable, "-c", _KILLED_BEFORE_OWNER, str(_JOURNAL_PATH), str(tree)],
        cwd=str(tree.parent),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert killed.returncode == -9, killed.stdout + killed.stderr
    assert list(journal_dir.iterdir()) == []
    # An empty directory is invisible to git: this journal does not make the tree dirty.
    assert _porcelain(tree) == ""

    with pytest.raises(journal.JournalBusy) as refused:
        journal.restore_journal(tree)

    assert "cannot establish that the owner is gone" in str(refused.value)
    assert f"remove it with: rmdir {journal_dir}" in str(refused.value)
    assert journal_dir.is_dir() and list(journal_dir.iterdir()) == []


def _truncate_json(journal_dir: Path) -> str:
    path = journal_dir / "01-sample.py.json"
    raw = path.read_bytes()
    path.write_bytes(raw[: len(raw) // 2])
    return "not valid JSON"


def _drop_field(field: str) -> Any:
    def damage(journal_dir: Path) -> str:
        path = journal_dir / "01-sample.py.json"
        entry = json.loads(path.read_bytes())
        del entry[field]
        path.write_text(json.dumps(entry), encoding="utf-8")
        return f"field {field} is missing"

    return damage


def _remove_part(part: str) -> Any:
    def damage(journal_dir: Path) -> str:
        (journal_dir / f"01-sample.py.{part}").unlink()
        return f"01-sample.py.{part} is missing"

    return damage


def _rewrite_json(rewrite: Any, reason: str) -> Any:
    def damage(journal_dir: Path) -> str:
        path = journal_dir / "01-sample.py.json"
        path.write_text(json.dumps(rewrite(json.loads(path.read_bytes()))), encoding="utf-8")
        return reason

    return damage


# Well-formed JSON that is not a ledger record: each names the rule of the ledger format it breaks.
_WRONG_RECORDS: dict[str, tuple[Any, str]] = {
    "not-an-object": (lambda entry: [entry], "the record is not a JSON object"),
    "sha-not-hex": (lambda entry: {**entry, "sha_before": "XYZ"}, "sha_before is not a hex SHA"),
    "sha-not-string": (lambda entry: {**entry, "sha_after": 7}, "sha_after is not a hex SHA"),
    "hashes-equal": (
        lambda entry: {**entry, "sha_after": entry["sha_before"]},
        "sha_before equals sha_after",
    ),
    "size-negative": (
        lambda entry: {**entry, "size_before": -1},
        "size_before is not a non-negative integer",
    ),
    "size-bool": (
        lambda entry: {**entry, "size_after": True},
        "size_after is not a non-negative integer",
    ),
    "time-not-string": (
        lambda entry: {**entry, "applied_utc": 5},
        "applied_utc is not a string",
    ),
    "extra-field": (lambda entry: {**entry, "note": "x"}, "field note is not a ledger field"),
    "path-not-string": (lambda entry: {**entry, "rel_path": 3}, "rel_path is not a string"),
    "path-of-another-file": (
        lambda entry: {**entry, "rel_path": "helper.py"},
        "the record name does not match its rel_path",
    ),
}


@pytest.mark.parametrize(
    "damage",
    [
        _truncate_json,
        *(_drop_field(field) for field in LEDGER_FIELDS),
        _remove_part("orig"),
        _remove_part("json"),
        *(_rewrite_json(rewrite, reason) for rewrite, reason in _WRONG_RECORDS.values()),
    ],
    ids=[
        "truncated-json",
        *(f"missing-{field}" for field in LEDGER_FIELDS),
        "orig-missing",
        "json-missing",
        *_WRONG_RECORDS,
    ],
)
def test_restore_journal_refuses_a_malformed_record_by_name_and_deletes_nothing(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str], damage: Any
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    assert _record_files(tree) == ["01-sample.py.json", "01-sample.py.orig"], (
        "the killed holder left no record on disk to damage"
    )
    reason = damage(journal_dir)
    snapshot = _snapshot(journal_dir)

    summary = journal.restore_journal(tree)
    captured = capsys.readouterr()

    assert (summary.restored, summary.already_original, summary.unknown_state) == (0, 0, 1)
    assert captured.out.splitlines() == [
        "restored=0 already_original=0 unknown_state=1 tmp_removed=0 exchange_unavailable=0"
    ]
    refusals = [line for line in captured.err.splitlines() if line.startswith("REFUSING:")]
    assert len(refusals) == 1, captured.err
    assert "record 01-sample.py is malformed" in refusals[0], refusals[0]
    assert reason in refusals[0], refusals[0]
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == SAMPLE_MUTATED


def test_restore_journal_refuses_an_entry_that_is_not_a_record(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    (journal_dir / "notes.txt").write_bytes(b"left here by hand\n")

    summary = journal.restore_journal(tree)
    captured = capsys.readouterr()

    assert (summary.restored, summary.unknown_state) == (1, 1)
    assert f"REFUSING: {journal_dir / 'notes.txt'} is not a journal record" in captured.err
    assert sorted(p.name for p in journal_dir.iterdir()) == ["notes.txt", "owner.json"]
    assert (tree / "sample.py").read_bytes() == _head_blob(tree, "sample.py")


@pytest.mark.parametrize("part", ["json", "orig"])
def test_restore_journal_refuses_a_record_file_it_cannot_read_by_name(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str], part: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    unreadable = journal_dir / f"01-sample.py.{part}"
    unreadable.unlink()
    unreadable.mkdir()
    snapshot = _snapshot(journal_dir)

    summary = journal.restore_journal(tree)
    captured = capsys.readouterr()

    # The directory counts once as an entry that is not a record, and the record whose
    # file it stands in for is refused by name.
    assert (summary.restored, summary.already_original, summary.unknown_state) == (0, 0, 2)
    assert f"record 01-sample.py is malformed (01-sample.py.{part} cannot be read" in captured.err
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == SAMPLE_MUTATED


@pytest.mark.parametrize(
    ("old", "new", "mutated"),
    [
        ("VALUE = 2", "VALUE = 0", SAMPLE_MUTATED),
        # The original bytes are the start of the mutated ones: only the hash tells them apart.
        ("VALUE = 2\n", "VALUE = 2\nEXTRA = 1\n", SAMPLE_ORIGINAL + b"EXTRA = 1\n"),
    ],
    ids=["replaced", "appended"],
)
def test_restore_journal_keeps_a_record_whose_orig_contradicts_the_file_it_calls_original(
    journal: ModuleType,
    tree: Path,
    capsys: pytest.CaptureFixture[str],
    old: str,
    new: str,
    mutated: bytes,
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", old, new)], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    assert (tree / "sample.py").read_bytes() == mutated
    record_path = journal_dir / "01-sample.py.json"
    entry = json.loads(record_path.read_bytes())
    entry["sha_before"], entry["sha_after"] = entry["sha_after"], entry["sha_before"]
    entry["size_before"], entry["size_after"] = entry["size_after"], entry["size_before"]
    record_path.write_text(json.dumps(entry), encoding="utf-8")
    snapshot = _snapshot(journal_dir)

    summary = journal.restore_journal(tree)
    captured = capsys.readouterr()

    # The file holds the mutation and the record now calls that `sha_before`; the `.orig`
    # still holds the original bytes. Deleting the record would leave the file mutated
    # and discard the only copy of the original.
    assert (summary.restored, summary.already_original, summary.unknown_state) == (0, 0, 1)
    assert "record 01-sample.py is malformed (01-sample.py.orig has sha=" in captured.err
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == mutated


@pytest.mark.parametrize("orig", ["absent", "half-written"])
def test_restore_journal_drops_a_record_cut_while_writing_its_orig_when_the_file_is_original(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str], orig: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    # What a kill or a full disk leaves between creating the `.json` and finishing the
    # `.orig`: the target was never written.
    orig_path = journal_dir / "01-sample.py.orig"
    if orig == "absent":
        orig_path.unlink()
    else:
        orig_path.write_bytes(orig_path.read_bytes()[:4])
    (tree / "sample.py").write_bytes(_head_blob(tree, "sample.py"))

    summary = journal.restore_journal(tree)

    assert (summary.restored, summary.already_original, summary.unknown_state) == (0, 1, 0)
    assert capsys.readouterr().out.splitlines() == [
        "restored=0 already_original=1 unknown_state=0 tmp_removed=0 exchange_unavailable=0"
    ]
    assert not journal_dir.exists()
    assert _porcelain(tree) == ""


# --- the holder puts things back on every exit that runs Python code ------------------------------


def test_leaving_the_block_restores_what_is_still_held(journal: ModuleType, tree: Path) -> None:
    with journal.journal_owner(tree, ["test"]) as owner:
        owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        owner.apply_source("helper.py", "VALUE_NAME = 1", "VALUE_NAME = 4")
        assert [record.name for record in owner.held_records] == ["01-sample.py", "02-helper.py"]
    for rel_path in ("sample.py", "helper.py"):
        assert (tree / rel_path).read_bytes() == _head_blob(tree, rel_path)
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


def test_the_holder_leaves_records_it_did_not_write_and_keeps_the_directory(
    journal: ModuleType, tree: Path
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    with journal.journal_owner(tree, ["test"]) as owner:
        owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        for part in ("json", "orig"):
            foreign = journal_dir / f"07-sample.py.{part}"
            foreign.write_bytes((journal_dir / f"01-sample.py.{part}").read_bytes())
        foreign_before = {
            name: sha for name, sha in _snapshot(journal_dir).items() if name.startswith("07-")
        }

    assert (tree / "sample.py").read_bytes() == _head_blob(tree, "sample.py")
    after = _snapshot(journal_dir)
    assert {name: sha for name, sha in after.items() if name.startswith("07-")} == foreign_before
    assert sorted(after) == ["07-sample.py.json", "07-sample.py.orig", "owner.json"]


@pytest.mark.parametrize(("ending", "returncode"), [("sigterm", 128 + 15), ("atexit", 3)])
def test_sigterm_and_atexit_restore_in_the_holder(tree: Path, ending: str, returncode: int) -> None:
    result = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], ending)
    assert result.returncode == returncode, result.stdout + result.stderr
    assert (tree / "sample.py").read_bytes() == _head_blob(tree, "sample.py")
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


# Child interpreter that receives SIGTERM while the new bytes are being written to the
# staging file, on the apply or on the restore (the `.orig` of the apply carries the
# original bytes too, so the restore's write is the second write of those bytes). The
# mask around `_write_target` spans the whole staging-write-then-exchange sequence,
# so this signal is always held until the sequence has either not started or finished:
# the target is never observed mid-write, and this scenario cannot be told apart, from the
# target's point of view, from a SIGTERM delivered right after the mutation lands (see
# `test_sigterm_and_atexit_restore_in_the_holder`). Kept because it still exercises the
# `_write_all` seam directly; not because it can still show a truncated target -- the
# staging design makes that structurally impossible regardless of the mask.
_SIGTERM_IN_TARGET_WRITE = """
import importlib.util, os, signal, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("ablation_journal_child", sys.argv[1])
journal = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = journal
spec.loader.exec_module(journal)

tree, which = Path(sys.argv[2]), sys.argv[3]
payload = b"VALUE = 0\\n" if which == "apply" else b"VALUE = 2\\n"
seen = [0]
real_write_all = journal._write_all

def write_all(fd, data):
    if data == payload:
        seen[0] += 1
        if which == "apply" or seen[0] == 2:
            os.kill(os.getpid(), signal.SIGTERM)
    real_write_all(fd, data)

journal._write_all = write_all
with journal.journal_owner(tree, sys.argv) as owner:
    record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
    owner.restore(record)
sys.exit(99)
"""


@pytest.mark.parametrize("which", ["apply", "restore"])
def test_sigterm_during_the_staging_write_leaves_no_partial_target(tree: Path, which: str) -> None:
    result = subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [sys.executable, "-c", _SIGTERM_IN_TARGET_WRITE, str(_JOURNAL_PATH), str(tree), which],
        cwd=str(tree.parent),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    target = (tree / "sample.py").read_bytes()
    assert result.returncode == 128 + signal.SIGTERM, (
        f"{which}: rc={result.returncode}, sample.py={target!r}, stderr={result.stderr[-400:]!r}"
    )
    assert target == _head_blob(tree, "sample.py")
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


# --- the target is exchanged with a staging file, never rewritten where it stands ---------------

_CHILD_PREAMBLE = """
import importlib.util, os, signal, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("ablation_journal_child", sys.argv[1])
journal = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = journal
spec.loader.exec_module(journal)
tree, point = Path(sys.argv[2]), sys.argv[3]
"""

# Killed while the mutated bytes are written and not yet the target's: the kill is sent from
# inside the write that carries those bytes, once all of them (or the first half) are written
# and flushed. That write exists whether the bytes go to a staging file or into the target
# itself, so the kill lands in both designs; exit 97 means it was never reached.
_KILLED_WHILE_THE_NEW_BYTES_ARE_WRITTEN = (
    _CHILD_PREAMBLE
    + """
real_write_all = journal._write_all

def write_all(fd, data):
    if data == b"VALUE = 0\\n":
        real_write_all(fd, data if point == "all-written-and-flushed" else data[: len(data) // 2])
        os.fsync(fd)
        os.kill(os.getpid(), signal.SIGKILL)
    real_write_all(fd, data)

journal._write_all = write_all
with journal.journal_owner(tree, sys.argv) as owner:
    owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
sys.exit(97)
"""
)

# Killed right after the exchange that puts the mutated bytes in place of the target, before
# the staging file -- now holding the original bytes -- is removed; exit 97 means no exchange
# happened. The seam is installed once the journal is held, so the acquisition's probe runs on
# the real exchange.
_KILLED_RIGHT_AFTER_THE_EXCHANGE = (
    _CHILD_PREAMBLE
    + """
real_exchange = journal._exchange

def exchange(first, second):
    real_exchange(first, second)
    os.kill(os.getpid(), signal.SIGKILL)

with journal.journal_owner(tree, sys.argv) as owner:
    journal._exchange = exchange
    owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
sys.exit(97)
"""
)

# The holder receives SIGTERM with its staging file complete and the exchange not yet called:
# the first exchange after acquiring for `apply`, the second one -- the owner's restore -- for
# `restore`. The seam is installed once the journal is held, after the probe's exchange.
_SIGTERM_RIGHT_BEFORE_THE_EXCHANGE = (
    _CHILD_PREAMBLE
    + """
calls = [0]
real_exchange = journal._exchange

def exchange(first, second):
    calls[0] += 1
    if calls[0] == (1 if point == "apply" else 2):
        os.kill(os.getpid(), signal.SIGTERM)
    real_exchange(first, second)

with journal.journal_owner(tree, sys.argv) as owner:
    journal._exchange = exchange
    record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
    owner.restore(record)
sys.exit(99)
"""
)

# Killed during the acquisition's exchange probe, with both probe files created and before
# they are exchanged; exit 97 means the probe never reached its exchange.
_KILLED_DURING_THE_EXCHANGE_PROBE = (
    _CHILD_PREAMBLE
    + """
def exchange(first, second):
    os.kill(os.getpid(), signal.SIGKILL)

journal._exchange = exchange
with journal.journal_owner(tree, sys.argv):
    pass
sys.exit(97)
"""
)


def _run_script(script: str, tree: Path, point: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [sys.executable, "-c", script, str(_JOURNAL_PATH), str(tree), point],
        cwd=str(tree.parent),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )


def _staging_files_beside_the_targets(tree: Path) -> list[str]:
    return sorted(entry.name for entry in tree.iterdir() if entry.name.endswith(".tmp"))


@pytest.mark.parametrize("point", ["all-written-and-flushed", "half-written"])
def test_a_kill_while_the_new_bytes_are_written_leaves_the_target_original(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str], point: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    head = _head_blob(tree, "sample.py")
    staged = SAMPLE_MUTATED if point == "all-written-and-flushed" else SAMPLE_MUTATED[:5]

    killed = _run_script(_KILLED_WHILE_THE_NEW_BYTES_ARE_WRITTEN, tree, point)
    target = (tree / "sample.py").read_bytes()

    assert killed.returncode == -9, (
        f"the kill point was not reached: rc={killed.returncode}, stderr={killed.stderr[-400:]!r}"
    )
    truncated = " (truncated)" if len(target) < min(len(head), len(SAMPLE_MUTATED)) else ""
    assert target == head, (
        f"sample.py after a kill with the new bytes {point}: {len(target)} bytes "
        f"{target!r}{truncated}, expected the HEAD blob, {len(head)} bytes {head!r}"
    )
    assert _record_files(tree) == ["01-sample.py.json", "01-sample.py.orig", "01-sample.py.tmp"]
    assert (journal_dir / "01-sample.py.tmp").read_bytes() == staged

    snapshot = _snapshot(journal_dir)
    with pytest.raises(journal.JournalBusy):
        with journal.journal_owner(tree, ["test"]):
            pytest.fail("entered a journal that a killed holder left")
    assert _snapshot(journal_dir) == snapshot

    summary = journal.restore_journal(tree)
    printed = capsys.readouterr()
    left = sorted(entry.name for entry in journal_dir.iterdir()) if journal_dir.exists() else []

    assert summary.tmp_removed == 1, (
        f"restore_journal removed {summary.tmp_removed} staging files; it printed "
        f"{printed.out.strip()!r}; the journal now holds {left}"
    )
    assert printed.out.splitlines() == [
        "restored=0 already_original=1 unknown_state=0 tmp_removed=1 exchange_unavailable=0"
    ]
    assert (tree / "sample.py").read_bytes() == head
    assert not journal_dir.exists(), f"journal left after restore_journal: {left}"
    assert _porcelain(tree) == ""


def test_a_kill_right_after_the_exchange_leaves_the_mutation_that_restore_journal_replays(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    head = _head_blob(tree, "sample.py")

    killed = _run_script(_KILLED_RIGHT_AFTER_THE_EXCHANGE, tree, "apply")

    assert killed.returncode == -9, (
        f"the exchange was not reached: rc={killed.returncode}, stderr={killed.stderr[-400:]!r}"
    )
    assert (tree / "sample.py").read_bytes() == head.replace(b"VALUE = 2", b"VALUE = 0", 1)
    assert _record_files(tree) == ["01-sample.py.json", "01-sample.py.orig", "01-sample.py.tmp"]
    # After the exchange the staging file holds what the target held: the original bytes,
    # which the record's `.orig` holds too.
    assert (journal_dir / "01-sample.py.tmp").read_bytes() == head

    summary = journal.restore_journal(tree)
    printed = capsys.readouterr().out
    restored = (tree / "sample.py").read_bytes()

    assert restored == head, (
        f"sample.py after restore_journal: sha={_sha(restored)}, HEAD blob sha={_sha(head)}; "
        f"it printed {printed.strip()!r}"
    )
    assert (summary.restored, summary.tmp_removed) == (1, 1)
    assert printed.splitlines() == [
        "restored=1 already_original=0 unknown_state=0 tmp_removed=1 exchange_unavailable=0"
    ]
    assert not journal_dir.exists()
    assert _porcelain(tree) == ""


def _commit_tracked(tree: Path, message: str) -> None:
    subprocess.run(  # noqa: S603 -- fixed argv, no shell
        [  # noqa: S607 -- git from PATH
            "git",
            "-C",
            str(tree),
            "-c",
            "user.name=ablation",
            "-c",
            "user.email=ablation@localhost",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--allow-empty",
            "--all",
            "--message",
            message,
        ],
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("mode", [0o644, 0o755], ids=["0o644", "0o755"])
def test_the_target_keeps_its_permission_bits_through_apply_and_restore(
    journal: ModuleType, tree: Path, mode: int
) -> None:
    target = tree / "sample.py"
    # git records the executable bit: the mode is committed, so the tree is clean before
    # the journal touches it and must be clean again after.
    os.chmod(target, mode)
    _commit_tracked(tree, f"sample.py with mode {mode:o}")
    committed = _git(tree, "ls-files", "--stage", "sample.py").stdout.decode().split()[0]
    assert committed == f"100{mode:o}"
    assert _porcelain(tree) == ""

    with journal.journal_owner(tree, ["test"]) as owner:
        record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        after_apply = stat.S_IMODE(os.stat(target).st_mode)
        owner.restore(record)
        after_restore = stat.S_IMODE(os.stat(target).st_mode)

    assert (oct(after_apply), oct(after_restore)) == (oct(mode), oct(mode)), (
        f"sample.py committed as {oct(mode)}: {oct(after_apply)} after apply, "
        f"{oct(after_restore)} after restore"
    )
    assert target.read_bytes() == _head_blob(tree, "sample.py")
    assert _porcelain(tree) == ""


def test_git_sees_only_the_target_and_the_journal_while_a_mutation_is_put_in_place(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, list[str]]] = []
    real_exchange = journal._exchange

    def observing_exchange(first: Path, second: Path) -> None:
        seen.append((f"right before exchanging {first.name}", _porcelain(tree).splitlines()))
        real_exchange(first, second)
        seen.append((f"right after exchanging {first.name}", _porcelain(tree).splitlines()))

    # Installed before acquiring, so the probe's exchange is observed too.
    monkeypatch.setattr(journal, "_exchange", observing_exchange)
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            seen.append(("with the mutation in place", _porcelain(tree).splitlines()))
            owner.restore(record)
    finally:
        monkeypatch.undo()

    journal_only = ["?? .ablation-in-flight/"]
    mutated = [" M sample.py", "?? .ablation-in-flight/"]
    assert seen == [
        (f"right before exchanging {PROBE_FILES[0]}", journal_only),
        (f"right after exchanging {PROBE_FILES[0]}", journal_only),
        ("right before exchanging 01-sample.py.tmp", journal_only),
        ("right after exchanging 01-sample.py.tmp", mutated),
        ("with the mutation in place", mutated),
        ("right before exchanging 01-sample.py.restore.tmp", mutated),
        ("right after exchanging 01-sample.py.restore.tmp", journal_only),
    ]
    assert _porcelain(tree) == ""


@pytest.mark.parametrize("point", ["apply", "restore"])
def test_sigterm_right_before_the_exchange_leaves_the_target_original_and_no_journal(
    tree: Path, point: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    result = _run_script(_SIGTERM_RIGHT_BEFORE_THE_EXCHANGE, tree, point)
    target = (tree / "sample.py").read_bytes()
    left = sorted(entry.name for entry in journal_dir.iterdir()) if journal_dir.exists() else []

    assert result.returncode == 128 + signal.SIGTERM, (
        f"{point}: rc={result.returncode}, sample.py={target!r}, journal={left}, "
        f"stderr={result.stderr[-400:]!r}"
    )
    assert target == _head_blob(tree, "sample.py")
    assert left == [], f"{point}: journal left after the handler: {left}"
    assert not journal_dir.exists()
    assert _staging_files_beside_the_targets(tree) == []
    assert _porcelain(tree) == ""


@pytest.fixture
def signal_mask_restored() -> Iterator[None]:
    """Put back this process's signal mask, whatever the test left blocked."""
    before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


def _apply_with_a_failing_exchange(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Exception | None, list[tuple[str, bytes]]]:
    """Apply one mutation while every exchange raises; return what the caller got, what was staged.

    The failing exchange is installed once the journal is held, so the acquisition's
    probe runs on the real exchange and the failure lands on the apply's.
    """
    staged: list[tuple[str, bytes]] = []

    def failing_exchange(first: Path, second: Path) -> None:
        staged.append((str(first.relative_to(tree)), first.read_bytes()))
        raise OSError(errno.EIO, "injected: the exchange fails")

    raised: Exception | None = None
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            monkeypatch.setattr(journal, "_exchange", failing_exchange)
            owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
    except Exception as exc:  # the type is what the tests assert
        raised = exc
    finally:
        monkeypatch.undo()
    return raised, staged


def test_a_failed_exchange_leaves_the_target_original_and_no_staging_file_or_journal(
    journal: ModuleType,
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    signal_mask_restored: None,
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    raised, staged = _apply_with_a_failing_exchange(journal, tree, monkeypatch)
    captured = capsys.readouterr()

    assert type(raised) is OSError and "injected: the exchange fails" in str(raised), (
        f"the caller got {raised!r}, not the OSError the exchange raised"
    )
    assert staged == [(f"{JOURNAL_DIRNAME}/01-sample.py.tmp", SAMPLE_MUTATED)]
    assert (tree / "sample.py").read_bytes() == _head_blob(tree, "sample.py")
    left = _record_files(tree)
    assert left == [], f"left in {journal_dir} after the failed exchange: {left}"
    assert not journal_dir.exists()
    assert "[journal] tmp_removed=1" in captured.err
    assert _porcelain(tree) == ""


def test_a_failed_exchange_puts_back_the_signal_mask_it_found(
    journal: ModuleType,
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_mask_restored: None,
) -> None:
    before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    raised, _staged = _apply_with_a_failing_exchange(journal, tree, monkeypatch)
    after = signal.pthread_sigmask(signal.SIG_BLOCK, [])

    assert type(raised) is OSError, f"the caller got {raised!r}"
    still_blocked = sorted(signal.Signals(signum).name for signum in after - before)
    assert after == before, f"blocked after the failed exchange and not before it: {still_blocked}"


def test_a_failed_restore_exchange_is_replayed_again_when_the_block_is_left(
    journal: ModuleType,
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_mask_restored: None,
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    exchanged: list[str] = []
    real_exchange = journal._exchange

    def exchange_failing_on_the_first_restore(first: Path, second: Path) -> None:
        exchanged.append(first.name)
        if len(exchanged) == 2:
            raise OSError(errno.EIO, "injected: the restore's exchange fails")
        real_exchange(first, second)

    raised: Exception | None = None
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            # Installed once the journal is held: the acquisition's probe is not counted.
            monkeypatch.setattr(journal, "_exchange", exchange_failing_on_the_first_restore)
            record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            owner.restore(record)
    except Exception as exc:  # the type is what the test asserts
        raised = exc
    finally:
        monkeypatch.undo()

    assert type(raised) is OSError and "injected: the restore's exchange fails" in str(raised), (
        f"the caller got {raised!r}, not the OSError the restore's exchange raised"
    )
    assert exchanged == [
        "01-sample.py.tmp",
        "01-sample.py.restore.tmp",
        "01-sample.py.restore.tmp",
    ]
    assert (tree / "sample.py").read_bytes() == _head_blob(tree, "sample.py")
    left = _record_files(tree)
    assert left == [], f"left in {journal_dir} after leaving the block: {left}"
    assert not journal_dir.exists()
    assert _porcelain(tree) == ""


def test_restore_journal_keeps_a_tmp_file_the_journal_does_not_write_as_a_stray(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    (journal_dir / "notes.tmp").write_bytes(b"left here by hand\n")

    summary = journal.restore_journal(tree)
    captured = capsys.readouterr()

    assert (summary.restored, summary.unknown_state, summary.tmp_removed) == (1, 1, 0)
    assert f"REFUSING: {journal_dir / 'notes.tmp'} is not a journal record" in captured.err
    assert sorted(p.name for p in journal_dir.iterdir()) == ["notes.tmp", "owner.json"]


def test_restore_journal_names_a_directory_blocking_a_restore_staging_file(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    # A restore's staging file would be created at this path; a directory already
    # sitting there makes the O_CREAT|O_EXCL of _create_synced raise FileExistsError,
    # a raw OSError that _restore_record does not wrap.
    (journal_dir / "01-sample.py.restore.tmp").mkdir()

    summary = journal.restore_journal(tree)
    captured = capsys.readouterr()

    assert summary.restored == 0, captured.err
    assert summary.unknown_state >= 1, captured.err
    refusals = [line for line in captured.err.splitlines() if line.startswith("REFUSING:")]
    assert any(
        "record 01-sample.py" in line and "could not be replayed" in line for line in refusals
    ), refusals
    assert (tree / "sample.py").read_bytes() == SAMPLE_MUTATED


# --- a target that vanishes while it is replaced is refused by name, never created --------------

# The two points inside a replacement where the target can be found absent: when its permission
# bits are read (right after the staging file is created), and at the exchange (right after the
# staging file is given those bits). The second hook sits on the `os.chmod` of the staging file,
# not on the exchange, so it is reached whatever call then puts the staging file in place: the
# exchange, or a rename in its stead.
_VANISHING_POINTS = ["before-its-mode-is-read", "before-the-exchange"]


def _remove_the_target_inside_the_replacement(
    journal: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    staging_name: str,
    point: str,
) -> list[str]:
    """Make `target` vanish at `point` of the replacement whose staging file is `staging_name`.

    Returns the list the hook appends `staging_name` to when it removes the target: a
    test asserts it first, so a hook that was never reached cannot pass for a refusal.
    """
    removed: list[str] = []
    if point == "before-its-mode-is-read":
        real_create = journal._create_synced

        def create_then_remove(path: Path, data: bytes) -> None:
            real_create(path, data)
            if path.name == staging_name:
                target.unlink()
                removed.append(path.name)

        monkeypatch.setattr(journal, "_create_synced", create_then_remove)
        return removed
    real_chmod = os.chmod

    def chmod_then_remove(path: Any, mode: int, **kwargs: Any) -> None:
        real_chmod(path, mode, **kwargs)
        if Path(path).name == staging_name:
            target.unlink()
            removed.append(Path(path).name)

    monkeypatch.setattr(journal.os, "chmod", chmod_then_remove)
    return removed


@pytest.mark.parametrize("point", _VANISHING_POINTS)
def test_a_target_that_vanishes_during_an_apply_is_refused_by_name_and_not_created(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    target = tree / "sample.py"
    refusal: Any = None
    leaving: Any = None
    after_apply: bytes | None = b""
    journal_after_apply: list[str] = []
    removed: list[str] = []
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            removed = _remove_the_target_inside_the_replacement(
                journal, monkeypatch, target, "01-sample.py.tmp", point
            )
            try:
                owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            except Exception as exc:  # the type is what the test asserts
                refusal = exc
            finally:
                monkeypatch.undo()
                after_apply = target.read_bytes() if target.exists() else None
                journal_after_apply = sorted(entry.name for entry in journal_dir.iterdir())
    except journal.UnknownState as exc:
        leaving = exc

    assert removed == ["01-sample.py.tmp"], (
        f"{point}: the hook never removed sample.py; the apply "
        f"{'raised ' + repr(refusal) if refusal else 'was confirmed'}"
    )
    assert after_apply is None, (
        f"{point}: sample.py was created after it vanished, holding {after_apply!r}; "
        f"the apply {'raised ' + repr(refusal) if refusal else 'was confirmed'}"
    )
    assert type(refusal) is journal.MutationDidNotLand, f"{point}: the apply raised {refusal!r}"
    assert str(refusal) == (
        "sample.py: the file is absent: it vanished before the mutation was put in place, "
        "and it was not created; record 01-sample.py is held"
    )
    assert refusal.record is not None and refusal.record.name == "01-sample.py"
    assert not refusal.record.confirmed_on_disk
    assert journal_after_apply == ["01-sample.py.json", "01-sample.py.orig", "owner.json"]
    # Leaving the block restores the held record, which finds the target absent and keeps it.
    assert leaving is not None and leaving.exit_code == 9, f"{point}: leaving raised {leaving!r}"
    assert "REFUSING: sample.py is in an unknown state (sha=absent" in str(leaving)
    assert not target.exists()
    assert _record_files(tree) == ["01-sample.py.json", "01-sample.py.orig"]
    assert _porcelain(tree).splitlines() == [" D sample.py", "?? .ablation-in-flight/"]


@pytest.mark.parametrize("point", ["before-the-restore", *_VANISHING_POINTS])
def test_a_target_that_vanishes_during_a_restore_is_refused_and_its_record_kept(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    target = tree / "sample.py"
    refused: Any = None
    leaving: Any = None
    after_restore: bytes | None = b""
    snapshot: dict[str, str] = {}
    snapshot_after_refusal: dict[str, str] = {}
    removed: list[str] = []
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            snapshot = _snapshot(journal_dir)
            if point == "before-the-restore":
                target.unlink()
                removed = ["01-sample.py.restore.tmp"]
            else:
                removed = _remove_the_target_inside_the_replacement(
                    journal, monkeypatch, target, "01-sample.py.restore.tmp", point
                )
            try:
                owner.restore(record)
            except Exception as exc:  # the type is what the test asserts
                refused = exc
            finally:
                monkeypatch.undo()
                after_restore = target.read_bytes() if target.exists() else None
                snapshot_after_refusal = _snapshot(journal_dir)
    except journal.UnknownState as exc:
        leaving = exc

    assert removed == ["01-sample.py.restore.tmp"], (
        f"{point}: the hook never removed sample.py; the restore "
        f"{'raised ' + repr(refused) if refused else 'completed'}"
    )
    assert after_restore is None, (
        f"{point}: sample.py was created by the restore, holding {after_restore!r}; "
        f"the restore {'raised ' + repr(refused) if refused else 'completed'}"
    )
    assert type(refused) is journal.UnknownState and refused.exit_code == 9, (
        f"{point}: the restore raised {refused!r}"
    )
    if point == "before-the-restore":
        assert str(refused).startswith("REFUSING: sample.py is in an unknown state (sha=absent")
    else:
        assert str(refused) == (
            "REFUSING: sample.py is absent: it vanished before its original bytes were put back, "
            "and it was not created — keeping record 01-sample.py"
        )
    assert set(snapshot) == {"owner.json", "01-sample.py.json", "01-sample.py.orig"}
    assert snapshot_after_refusal == snapshot
    assert leaving is not None and leaving.exit_code == 9, f"{point}: leaving raised {leaving!r}"
    assert _snapshot(journal_dir) == snapshot
    assert not target.exists()


# --- the exchange is probed while the journal is acquired ------------------------------------


def _c_library(renameat2: Callable[..., int] | None) -> Callable[..., Any]:
    """A stand-in for `ctypes.CDLL` whose library exports `renameat2` only when one is given."""

    def load(name: object, use_errno: bool = False) -> Any:
        return SimpleNamespace() if renameat2 is None else SimpleNamespace(renameat2=renameat2)

    return load


def _renameat2_failing_with(code: int) -> Callable[..., int]:
    """A `renameat2` that fails as the kernel does: `-1`, with `code` left in `errno`."""

    def renameat2(*args: object) -> int:
        ctypes.set_errno(code)
        return -1

    return renameat2


def _renameat2_renaming_without_swapping(
    old_dirfd: int, old: bytes, new_dirfd: int, new: bytes, flags: int
) -> int:
    """A `renameat2` that ignores its flags: a plain rename, reported as a success."""
    os.rename(old, new)
    return 0


_UNAVAILABLE_EXCHANGES: dict[str, tuple[Callable[..., int] | None, str]] = {
    "einval": (
        _renameat2_failing_with(errno.EINVAL),
        "renameat2(RENAME_EXCHANGE) failed with EINVAL",
    ),
    "enosys": (
        _renameat2_failing_with(errno.ENOSYS),
        "renameat2(RENAME_EXCHANGE) failed with ENOSYS",
    ),
    "symbol-absent": (None, "the C library does not export renameat2"),
    "renamed-without-swapping": (
        _renameat2_renaming_without_swapping,
        "renameat2(RENAME_EXCHANGE) reported success without swapping the two files",
    ),
}


def test_acquiring_exchanges_two_probe_files_after_the_owner_file_and_removes_them(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    created: list[str] = []
    exchanged: list[tuple[str, str]] = []
    real_create = journal._create_synced
    real_exchange = journal._exchange

    def recording_create(path: Path, data: bytes) -> None:
        created.append(str(path.relative_to(tree)))
        real_create(path, data)

    def recording_exchange(first: Path, second: Path) -> None:
        exchanged.append((str(first.relative_to(tree)), str(second.relative_to(tree))))
        real_exchange(first, second)

    monkeypatch.setattr(journal, "_create_synced", recording_create)
    monkeypatch.setattr(journal, "_exchange", recording_exchange)
    with journal.journal_owner(tree, ["test"]):
        inside = sorted(entry.name for entry in journal_dir.iterdir())
    monkeypatch.undo()

    in_journal = [f"{JOURNAL_DIRNAME}/{name}" for name in ("owner.json", *PROBE_FILES)]
    assert created == in_journal
    assert exchanged == [(in_journal[1], in_journal[2])]
    assert inside == ["owner.json"], f"left in the journal by a probe that succeeded: {inside}"
    assert not journal_dir.exists()


@pytest.mark.parametrize("failure", list(_UNAVAILABLE_EXCHANGES))
def test_an_unavailable_exchange_is_refused_with_12_before_any_record_or_target_is_written(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    renameat2, reason = _UNAVAILABLE_EXCHANGES[failure]
    journal_dir = tree / JOURNAL_DIRNAME
    before = {name: (tree / name).read_bytes() for name in FIXTURE_FILES}
    device = os.stat(tree).st_dev
    created: list[str] = []
    real_create = journal._create_synced

    def recording_create(path: Path, data: bytes) -> None:
        created.append(path.name)
        real_create(path, data)

    callbacks_before = atexit._ncallbacks()
    handlers_before = _handlers()
    raised: Exception | None = None
    monkeypatch.setattr(journal, "_create_synced", recording_create)
    monkeypatch.setattr(journal.ctypes, "CDLL", _c_library(renameat2))
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
    except Exception as exc:  # the type is what the test asserts
        raised = exc
    finally:
        monkeypatch.undo()

    written_after_the_probe = [name for name in created if name not in {"owner.json", *PROBE_FILES}]
    assert written_after_the_probe == [], (
        f"{failure}: written although the exchange is unavailable: {written_after_the_probe}; "
        f"the caller got {raised!r}"
    )
    assert type(raised) is journal.ExchangeUnavailable, f"{failure}: the caller got {raised!r}"
    assert raised is not None and getattr(raised, "exit_code", None) == 12
    assert str(raised) == (
        f"REFUSING: atomic exchange unavailable on device {os.major(device)}:{os.minor(device)} "
        f"(the filesystem of {journal_dir}): {reason}"
    )
    assert created == ["owner.json", *PROBE_FILES]
    assert {name: (tree / name).read_bytes() for name in FIXTURE_FILES} == before
    assert not journal_dir.exists()
    assert atexit._ncallbacks() == callbacks_before
    assert _handlers() == handlers_before
    assert _porcelain(tree) == ""


def test_a_kill_during_the_exchange_probe_leaves_files_that_restore_journal_removes(
    journal: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    killed = _run_script(_KILLED_DURING_THE_EXCHANGE_PROBE, tree, "probe")
    assert killed.returncode == -9, (
        f"the probe's exchange was not reached: rc={killed.returncode}, "
        f"stderr={killed.stderr[-400:]!r}"
    )
    left_by_the_kill = sorted(entry.name for entry in journal_dir.iterdir())
    assert len(left_by_the_kill) == 3, (
        f"the kill did not land after the probe files: {left_by_the_kill}"
    )

    summary = journal.restore_journal(tree)
    printed = capsys.readouterr()
    left = sorted(entry.name for entry in journal_dir.iterdir()) if journal_dir.exists() else []

    assert (summary.tmp_removed, summary.unknown_state) == (2, 0), (
        f"restore_journal removed {summary.tmp_removed} staging files and refused "
        f"{summary.unknown_state} entries; the journal now holds {left}; stderr: {printed.err!r}"
    )
    assert printed.out.splitlines() == [
        "restored=0 already_original=0 unknown_state=0 tmp_removed=2 exchange_unavailable=0"
    ]
    # A journal left holding only `owner.json` would stop every later run on this tree.
    assert not journal_dir.exists(), (
        f"the journal directory is still there after restore_journal, holding {left}"
    )
    assert left_by_the_kill == [*PROBE_FILES, "owner.json"]
    assert {name: (tree / name).read_bytes() for name in FIXTURE_FILES} == {
        name: _head_blob(tree, name) for name in FIXTURE_FILES
    }
    assert _porcelain(tree) == ""


# --- a target whose filesystem refuses the exchange, after the probe passed ---------------------

# The probe sees the journal's filesystem; a target can still refuse the exchange, and these are
# the answers that mean its filesystem cannot make it.
_TARGET_REFUSALS = {"EINVAL": errno.EINVAL, "ENOSYS": errno.ENOSYS, "EXDEV": errno.EXDEV}


def _renameat2_refusing(
    code: int, staging_name: str, write_into_target: bytes | None = None
) -> Callable[..., int]:
    """The real `renameat2`, except that exchanging the staging file `staging_name` fails.

    That exchange fails as the kernel does, `-1` with `code` in `errno`, after writing
    `write_into_target` into the target when it is given (a concurrent writer).
    """
    real = ctypes.CDLL(None, use_errno=True).renameat2
    real.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    real.restype = ctypes.c_int

    def renameat2(old_dirfd: int, old: bytes, new_dirfd: int, new: bytes, flags: int) -> int:
        if os.path.basename(old) == os.fsencode(staging_name):
            if write_into_target is not None:
                Path(os.fsdecode(new)).write_bytes(write_into_target)
            ctypes.set_errno(code)
            return -1
        status: int = real(old_dirfd, old, new_dirfd, new, flags)
        return status

    return renameat2


def _unavailable_message(directory: Path, detail: str) -> str:
    device = os.stat(directory).st_dev
    return (
        f"REFUSING: atomic exchange unavailable on device {os.major(device)}:{os.minor(device)} "
        f"(the filesystem of {directory}): {detail}"
    )


@pytest.mark.parametrize("answer", list(_TARGET_REFUSALS))
def test_an_apply_whose_target_refuses_the_exchange_stops_with_12_and_keeps_no_record(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    head = _head_blob(tree, "sample.py")
    raised: Exception | None = None
    target_after = b""
    journal_after: list[str] = []
    held_after: tuple[Any, ...] = ()
    with journal.journal_owner(tree, ["test"]) as owner:
        # Installed once the journal is held: the probe passed on the real exchange.
        monkeypatch.setattr(
            journal.ctypes,
            "CDLL",
            _c_library(_renameat2_refusing(_TARGET_REFUSALS[answer], "01-sample.py.tmp")),
        )
        try:
            owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        except Exception as exc:  # the type is what the test asserts
            raised = exc
        finally:
            monkeypatch.undo()
            target_after = (tree / "sample.py").read_bytes()
            journal_after = sorted(entry.name for entry in journal_dir.iterdir())
            held_after = owner.held_records

    assert type(raised) is journal.ExchangeUnavailable, f"{answer}: the apply raised {raised!r}"
    assert getattr(raised, "exit_code", None) == 12
    assert str(raised) == _unavailable_message(
        tree,
        f"sample.py: renameat2(RENAME_EXCHANGE) failed with {answer}; sample.py is untouched "
        "and its record 01-sample.py was removed",
    )
    assert target_after == head, f"{answer}: sample.py after the refusal: {target_after!r}"
    assert journal_after == ["owner.json"], f"{answer}: left in the journal: {journal_after}"
    assert held_after == ()
    assert not journal_dir.exists()
    assert _porcelain(tree) == ""


@pytest.mark.parametrize("answer", list(_TARGET_REFUSALS))
def test_restore_journal_keeps_a_record_whose_target_refuses_the_exchange_and_counts_it_apart(
    journal: ModuleType,
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answer: str,
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    mutated = _head_blob(tree, "sample.py").replace(b"VALUE = 2", b"VALUE = 0", 1)
    killed = _run_child(tree, [("sample.py", "VALUE = 2", "VALUE = 0")], "sigkill")
    assert killed.returncode == -9, killed.stdout + killed.stderr
    snapshot = _snapshot(journal_dir)
    assert set(snapshot) == {"owner.json", "01-sample.py.json", "01-sample.py.orig"}

    monkeypatch.setattr(
        journal.ctypes,
        "CDLL",
        _c_library(_renameat2_refusing(_TARGET_REFUSALS[answer], "01-sample.py.restore.tmp")),
    )
    try:
        summary = journal.restore_journal(tree)
    finally:
        monkeypatch.undo()
    captured = capsys.readouterr()
    refusals = [line for line in captured.err.splitlines() if line.startswith("REFUSING:")]

    counted = {
        "exchange_unavailable": summary.exchange_unavailable,
        "unknown_state": summary.unknown_state,
        "restored": summary.restored,
    }
    assert counted == {"exchange_unavailable": 1, "unknown_state": 0, "restored": 0}, (
        f"{answer}: counted {counted}; refusals: {refusals}"
    )
    assert captured.out.splitlines() == [
        "restored=0 already_original=0 unknown_state=0 tmp_removed=0 exchange_unavailable=1"
    ]
    assert refusals == [
        _unavailable_message(
            tree,
            f"sample.py: renameat2(RENAME_EXCHANGE) failed with {answer}; sample.py still holds "
            "the mutation and record 01-sample.py is kept",
        )
    ]
    assert (tree / "sample.py").read_bytes() == mutated
    assert _snapshot(journal_dir) == snapshot, "the record or the journal changed"


def test_the_holder_keeps_a_record_whose_target_refuses_the_exchange_and_restores_the_others(
    journal: ModuleType,
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    sample_head = _head_blob(tree, "sample.py")
    helper_mutated = _head_blob(tree, "helper.py").replace(b"VALUE_NAME = 1", b"VALUE_NAME = 4", 1)
    handlers_before = _handlers()
    leaving: Exception | None = None
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            owner.apply_source("helper.py", "VALUE_NAME = 1", "VALUE_NAME = 4")
            # Leaving the block replays newest first: the refused record comes before the other.
            monkeypatch.setattr(
                journal.ctypes,
                "CDLL",
                _c_library(_renameat2_refusing(errno.EXDEV, "02-helper.py.restore.tmp")),
            )
    except Exception as exc:  # the type is what the test asserts
        leaving = exc
    finally:
        monkeypatch.undo()
    captured = capsys.readouterr()
    left = sorted(entry.name for entry in journal_dir.iterdir()) if journal_dir.exists() else []

    assert (tree / "sample.py").read_bytes() == sample_head, (
        f"sample.py was not restored after the refusal on helper.py; leaving raised {leaving!r}"
    )
    expected = _unavailable_message(
        tree,
        "helper.py: renameat2(RENAME_EXCHANGE) failed with EXDEV; helper.py still holds the "
        "mutation and record 02-helper.py is kept",
    )
    assert type(leaving) is journal.ExchangeUnavailable, f"leaving raised {leaving!r}"
    assert getattr(leaving, "exit_code", None) == 12
    assert str(leaving) == expected
    assert expected in captured.err.splitlines()
    assert (tree / "helper.py").read_bytes() == helper_mutated
    assert left == ["02-helper.py.json", "02-helper.py.orig", "owner.json"]
    assert _handlers() == handlers_before


# Child interpreter: hold the tree, mutate sample.py then helper.py, make the exchange that would
# put helper.py back fail with EXDEV, then end with SIGTERM or with a plain exit that only the
# `atexit` hook handles. Both replay newest first, so the refused record comes before the other.
_REFUSED_EXCHANGE_ON_THE_WAY_OUT = (
    _CHILD_PREAMBLE
    + """
import ctypes, errno, time
from types import SimpleNamespace

real = ctypes.CDLL(None, use_errno=True).renameat2
real.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
real.restype = ctypes.c_int

def renameat2(old_dirfd, old, new_dirfd, new, flags):
    if os.path.basename(old) == b"02-helper.py.restore.tmp":
        ctypes.set_errno(errno.EXDEV)
        return -1
    return real(old_dirfd, old, new_dirfd, new, flags)

owner = journal.journal_owner(tree, sys.argv).__enter__()
owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
owner.apply_source("helper.py", "VALUE_NAME = 1", "VALUE_NAME = 4")
ctypes.CDLL = lambda name, use_errno=False: SimpleNamespace(renameat2=renameat2)
if point == "sigterm":
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(5)
    sys.exit(99)
sys.exit(3)
"""
)


@pytest.mark.parametrize(("ending", "returncode"), [("sigterm", 128 + 15), ("atexit", 3)])
def test_a_signal_or_exit_replay_keeps_a_refused_record_names_it_and_restores_the_others(
    tree: Path, ending: str, returncode: int
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    result = _run_script(_REFUSED_EXCHANGE_ON_THE_WAY_OUT, tree, ending)
    left = sorted(entry.name for entry in journal_dir.iterdir()) if journal_dir.exists() else []

    assert result.returncode == returncode, (
        f"{ending}: rc={result.returncode}, journal={left}, stderr={result.stderr[-600:]!r}"
    )
    assert (tree / "sample.py").read_bytes() == _head_blob(tree, "sample.py"), (
        f"{ending}: sample.py was not restored after the refusal on helper.py; "
        f"stderr={result.stderr[-600:]!r}"
    )
    expected = _unavailable_message(
        tree,
        "helper.py: renameat2(RENAME_EXCHANGE) failed with EXDEV; helper.py still holds the "
        "mutation and record 02-helper.py is kept",
    )
    assert expected in result.stderr.splitlines(), (
        f"{ending}: nothing named helper.py on the way out; stderr={result.stderr!r}"
    )
    assert (tree / "helper.py").read_bytes() == _head_blob(tree, "helper.py").replace(
        b"VALUE_NAME = 1", b"VALUE_NAME = 4", 1
    )
    assert left == ["02-helper.py.json", "02-helper.py.orig", "owner.json"]


@pytest.mark.parametrize("which", ["apply", "restore"])
def test_a_target_changed_under_a_refused_exchange_is_an_unknown_state_and_its_record_stays(
    journal: ModuleType, tree: Path, monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    target = tree / "sample.py"
    concurrent = b"VALUE = 9\n"
    head = _head_blob(tree, "sample.py")
    expected_sha = _sha(head if which == "apply" else SAMPLE_MUTATED)
    staging_name = "01-sample.py.tmp" if which == "apply" else "01-sample.py.restore.tmp"
    refused: Any = None
    leaving: Any = None
    records: dict[str, str] = {}
    try:
        with journal.journal_owner(tree, ["test"]) as owner:
            record = None
            if which == "restore":
                record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
            monkeypatch.setattr(
                journal.ctypes,
                "CDLL",
                _c_library(_renameat2_refusing(errno.EXDEV, staging_name, concurrent)),
            )
            try:
                if record is None:
                    owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
                else:
                    owner.restore(record)
            except Exception as exc:  # the type is what the test asserts
                refused = exc
            finally:
                monkeypatch.undo()
                records = {
                    name: sha
                    for name, sha in _snapshot(journal_dir).items()
                    if name.startswith("01-sample.py.") and name.endswith((".json", ".orig"))
                }
    except Exception as exc:  # the type is what the test asserts
        leaving = exc

    assert type(refused) is journal.UnknownState, f"{which}: raised {refused!r}"
    assert type(leaving) is journal.UnknownState, f"{which}: leaving raised {leaving!r}"
    assert str(refused) == (
        "REFUSING: sample.py is in an unknown state after its exchange was refused "
        f"(renameat2(RENAME_EXCHANGE) failed with EXDEV): sha={_sha(concurrent)}, "
        f"expected {expected_sha} — keeping record 01-sample.py"
    )
    assert sorted(records) == ["01-sample.py.json", "01-sample.py.orig"], (
        f"{which}: record files after the refusal: {records}"
    )
    assert _record_files(tree)[:2] == ["01-sample.py.json", "01-sample.py.orig"]
    assert (journal_dir / "01-sample.py.orig").read_bytes() == head
    assert target.read_bytes() == concurrent


# --- bytecode caches ---------------------------------------------------------------------------


def test_restored_source_is_imported_even_after_an_unchecked_cache_of_the_mutation(
    journal: ModuleType, tree: Path
) -> None:
    with journal.journal_owner(tree, ["test"]) as owner:
        record = owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        cache = _sample_cache(tree)
        cache.parent.mkdir(exist_ok=True)
        py_compile.compile(
            str(tree / "sample.py"),
            cfile=str(cache),
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            doraise=True,
        )
        assert _pyc_flags(cache) == 1
        owner.restore(record)

    assert _import_sample_value(tree) == "2"


def test_mutated_source_is_imported_even_with_the_fixtures_unchecked_cache(
    journal: ModuleType, tree: Path
) -> None:
    assert _pyc_flags(_sample_cache(tree)) == 1
    with journal.journal_owner(tree, ["test"]) as owner:
        owner.apply_source("sample.py", "VALUE = 2", "VALUE = 0")
        assert _import_sample_value(tree) == "0"


def test_caches_are_removed_except_under_venv_and_node_modules(
    journal: ModuleType, tmp_path: Path
) -> None:
    removed = [tmp_path / "__pycache__", tmp_path / "pkg" / "sub" / "__pycache__"]
    kept = [
        tmp_path / ".venv" / "lib" / "__pycache__",
        tmp_path / "pkg" / "node_modules" / "dep" / "__pycache__",
    ]
    for cache in removed + kept:
        cache.mkdir(parents=True)
        (cache / "module.cpython-312.pyc").write_bytes(b"\x00")

    journal.clear_bytecode_caches(tmp_path)

    assert [cache for cache in removed if cache.exists()] == []
    assert [cache for cache in kept if not cache.exists()] == []


# --- refused mutations write nothing -----------------------------------------------------------


@pytest.mark.parametrize(
    ("rel_path", "old", "new", "reason"),
    [
        ("sample.py", "VALUE = 99", "VALUE = 0", "occurs 0 times"),
        ("test_sample.py", "def test_", "def check_", "occurs 5 times"),
        ("sample.py", "= 2", "= 0", "starts mid-line"),
        ("sample.py", "VALUE = 2", "VALUE = 2", "old == new"),
        ("sample.py", "", "VALUE = 0", "anchor text is empty"),
        ("../outside.py", "VALUE = 2", "VALUE = 0", "not a normalized tree-relative path"),
        ("./sample.py", "VALUE = 2", "VALUE = 0", "not a normalized tree-relative path"),
        (".ablation-in-flight/owner.json", '"pid"', '"x"', "names the journal"),
        ("absent.py", "VALUE = 2", "VALUE = 0", "is not a regular file"),
    ],
    ids=[
        "absent",
        "repeated",
        "mid-line",
        "old-equals-new",
        "empty",
        "parent",
        "dot",
        "journal",
        "no-file",
    ],
)
def test_a_refused_mutation_writes_no_record_and_leaves_the_file(
    journal: ModuleType, tree: Path, rel_path: str, old: str, new: str, reason: str
) -> None:
    before = {name: (tree / name).read_bytes() for name in FIXTURE_FILES}
    with journal.journal_owner(tree, ["test"]) as owner:
        with pytest.raises(journal.MutationDidNotLand, match=reason) as refused:
            owner.apply_source(rel_path, old, new)
        assert refused.value.record is None
        assert _record_files(tree) == []
        assert owner.held_records == ()
    assert {name: (tree / name).read_bytes() for name in FIXTURE_FILES} == before
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


def test_record_name_slugs_a_nested_path(journal: ModuleType, tree: Path) -> None:
    nested = tree / "pkg" / "mod.py"
    nested.parent.mkdir()
    nested.write_bytes(b"LIMIT = 4\n")
    with journal.journal_owner(tree, ["test"]) as owner:
        record = owner.apply_source("pkg/mod.py", "LIMIT = 4", "LIMIT = 5")
        assert _record_files(tree) == ["01-pkg__mod.py.json", "01-pkg__mod.py.orig"]
        owner.restore(record)
    assert record.name == "01-pkg__mod.py"
    assert nested.read_bytes() == b"LIMIT = 4\n"


@settings(
    max_examples=40,
    deadline=None,
)
@given(data=st.data())
def test_an_anchor_is_applied_exactly_when_it_occurs_once_at_a_line_start(
    journal: ModuleType,
    generator: ModuleType,
    tmp_path_factory: pytest.TempPathFactory,
    data: st.DataObject,
) -> None:
    tree = generator.make_fixture_tree(tmp_path_factory.mktemp("anchor") / "fixture").resolve()
    head = _head_blob(tree, "test_sample.py")
    text = head.decode("utf-8")
    line_starts = [0, *(i + 1 for i, char in enumerate(text) if char == "\n" and i + 1 < len(text))]
    if data.draw(st.booleans(), label="from a line start"):
        start = data.draw(st.sampled_from(line_starts), label="start")
    else:
        start = data.draw(st.integers(0, len(text) - 1), label="start")
    old = text[start : start + data.draw(st.integers(0, 48), label="length")]
    new = data.draw(
        st.one_of(st.just(old), st.just(old + "  # m"), st.just(""), st.text(max_size=12)),
        label="new",
    )

    # The rule, restated from the ledger's specification rather than from the code under test.
    accepted = (
        old != ""
        and old != new
        and text.count(old) == 1
        and (text.index(old) == 0 or text[text.index(old) - 1] == "\n")
    )

    with journal.journal_owner(tree, ["test"]) as owner:
        if accepted:
            record = owner.apply_source("test_sample.py", old, new)
            expected = text.replace(old, new, 1).encode("utf-8")
            assert (tree / "test_sample.py").read_bytes() == expected
            assert _record_files(tree) == [
                "01-test_sample.py.json",
                "01-test_sample.py.orig",
            ]
            assert owner.restore(record) == "restored"
        else:
            with pytest.raises(journal.MutationDidNotLand) as refused:
                owner.apply_source("test_sample.py", old, new)
            assert refused.value.record is None
            assert _record_files(tree) == []
            assert (tree / "test_sample.py").read_bytes() == head

    assert (tree / "test_sample.py").read_bytes() == head
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""


@settings(
    max_examples=25,
    deadline=None,
)
@given(
    steps=st.lists(
        st.tuples(st.sampled_from(["apply", "restore"]), st.sampled_from(FIXTURE_FILES)),
        max_size=12,
    )
)
def test_sequences_of_applies_and_restores_leave_a_clean_tree(
    journal: ModuleType,
    generator: ModuleType,
    tmp_path_factory: pytest.TempPathFactory,
    steps: list[tuple[str, str]],
) -> None:
    tree = generator.make_fixture_tree(tmp_path_factory.mktemp("sequence") / "fixture").resolve()
    heads = {rel_path: _head_blob(tree, rel_path) for rel_path in FIXTURE_FILES}
    anchors = {rel_path: heads[rel_path].decode().split("\n", 1)[0] for rel_path in FIXTURE_FILES}
    for rel_path, anchor in anchors.items():
        assert heads[rel_path].decode().count(anchor) == 1, rel_path

    applied: list[Any] = []
    live: dict[str, list[Any]] = {rel_path: [] for rel_path in FIXTURE_FILES}
    with journal.journal_owner(tree, ["test"]) as owner:
        for action, rel_path in steps:
            if action == "apply":
                marker = f"  # m{len(applied) + 1}"
                record = owner.apply_source(rel_path, anchors[rel_path], anchors[rel_path] + marker)
                applied.append(record)
                live[rel_path].append(record)
            elif live[rel_path]:
                owner.restore(live[rel_path].pop())
            expected_files = sorted(
                f"{record.name}.{part}"
                for records in live.values()
                for record in records
                for part in ("json", "orig")
            )
            assert _record_files(tree) == expected_files

    assert [record.nn for record in applied] == list(range(1, len(applied) + 1))
    assert [record.name for record in applied] == [
        f"{index:02d}-{record.rel_path.replace('/', '__')}"
        for index, record in enumerate(applied, start=1)
    ]
    assert len({record.name for record in applied}) == len(applied)
    for rel_path in FIXTURE_FILES:
        assert (tree / rel_path).read_bytes() == heads[rel_path], rel_path
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == ""
