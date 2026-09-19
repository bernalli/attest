"""Tests for the ablation self-test's fixture-tree generator.

`tools/gates/ablation/selftest/` is not an importable package (it sits under
`tools/gates`, which is not on the collection path as a package either), so
the module under test is loaded by path rather than by a normal import. That
load deliberately does not register the module in `sys.modules`: nothing else
in the suite should observe it, and nothing here relies on other tests having
run first.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import ModuleType

_MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "gates"
    / "ablation"
    / "selftest"
    / "make_fixture_tree.py"
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_fixture_tree_under_test", _MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_FIVE_TESTS = (
    "test_sample.py::test_guard",
    "test_sample.py::test_unrelated",
    "test_sample.py::test_skips_when_mutated",
    "test_sample.py::test_helper",
    "test_sample.py::test_sibling_only",
)

#: Short-summary words of `pytest -rA`; a line starting with any of them is one outcome.
_OUTCOME_WORDS = frozenset({"PASSED", "FAILED", "ERROR", "SKIPPED", "XFAIL", "XPASS"})


def _porcelain(dest: Path) -> str:
    """`git status --porcelain`, with untracked files shown whatever the global config says."""
    return subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],  # noqa: S607
        cwd=str(dest),
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def test_tree_is_clean_and_tracks_exactly_the_four_named_files(tmp_path: Path) -> None:
    module = _load_module()
    dest = module.make_fixture_tree(tmp_path / "fixture")

    assert _porcelain(dest) == ""

    tracked = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 — git from PATH, as elsewhere here
        cwd=str(dest),
        check=True,
        capture_output=True,
        text=True,
    )
    assert sorted(tracked.stdout.splitlines()) == [
        "helper.py",
        "pytest.ini",
        "sample.py",
        "test_sample.py",
    ]


def test_sample_is_ten_bytes_at_the_fixed_mtime(tmp_path: Path) -> None:
    module = _load_module()
    dest = module.make_fixture_tree(tmp_path / "fixture")

    sample_path = dest / "sample.py"
    stat = sample_path.stat()
    assert stat.st_size == 10
    assert int(stat.st_mtime) == module.FIXED_MTIME


def test_bytecode_cache_is_precompiled_and_unchecked_hash_based(tmp_path: Path) -> None:
    module = _load_module()
    dest = module.make_fixture_tree(tmp_path / "fixture")

    cache_tag = sys.implementation.cache_tag
    pyc_path = dest / "__pycache__" / f"sample.{cache_tag}.pyc"
    assert pyc_path.exists(), f"expected a precompiled cache at {pyc_path}"

    # PEP 552 header: 4-byte magic, then a 4-byte little-endian flags field.
    # 1 means hash-based with source checking off (UNCHECKED_HASH) — the mode
    # this fixture's stale-cache trap depends on.
    header = pyc_path.read_bytes()[:8]
    flags = struct.unpack("<I", header[4:8])[0]
    assert flags == 1, f"expected an unchecked-hash cache (flags=1) at {pyc_path}, found {flags}"


def test_stale_cache_is_read_until_removed(tmp_path: Path) -> None:
    module = _load_module()
    dest = module.make_fixture_tree(tmp_path / "fixture")

    # Same byte length as the original, and the modification time is left
    # wherever the write leaves it: neither property is what keeps the cache
    # in play, which is exactly the point being exercised here.
    (dest / "sample.py").write_text("VALUE = 0\n", encoding="utf-8")

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    read_value_args = [sys.executable, "-c", "import sample; print(sample.VALUE)"]

    # The current interpreter on a file this test just wrote: no untrusted input.
    stale = subprocess.run(  # noqa: S603
        read_value_args,
        cwd=str(dest),
        capture_output=True,
        text=True,
        env=env,
    )
    assert stale.stdout.strip() == "2", stale.stdout + stale.stderr

    shutil.rmtree(dest / "__pycache__")

    fresh = subprocess.run(  # noqa: S603
        read_value_args,
        cwd=str(dest),
        capture_output=True,
        text=True,
        env=env,
    )
    assert fresh.stdout.strip() == "0", fresh.stdout + fresh.stderr


def test_tree_pins_untracked_files_visible_in_its_own_config(tmp_path: Path) -> None:
    """Consumers read `git status --porcelain` without flags; the repository config decides."""
    module = _load_module()
    dest = module.make_fixture_tree(tmp_path / "fixture")

    value = subprocess.run(
        ["git", "config", "--local", "--get", "status.showUntrackedFiles"],  # noqa: S607
        cwd=str(dest),
        capture_output=True,
        text=True,
    )
    assert value.stdout.strip() == "normal", value.stdout + value.stderr


def test_pristine_tree_passes_exactly_the_five_named_tests(tmp_path: Path) -> None:
    """Five tests, each passed: no sixth test, and none skipped, failed or erroring."""
    module = _load_module()
    dest = module.make_fixture_tree(tmp_path / "fixture")

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider"],
        cwd=str(dest),
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    outcomes = sorted(
        line for line in result.stdout.splitlines() if line.split(" ", 1)[0] in _OUTCOME_WORDS
    )
    assert outcomes == sorted(f"PASSED {node}" for node in _FIVE_TESTS), output


def test_tree_stays_clean_after_running_the_suite(tmp_path: Path) -> None:
    module = _load_module()
    dest = module.make_fixture_tree(tmp_path / "fixture")

    subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=str(dest),
        check=True,
        capture_output=True,
        text=True,
    )

    assert _porcelain(dest) == ""
