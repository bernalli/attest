"""Build the git fixture tree the ablation self-test runs its mutants against.

The tree is a tiny, self-contained repository: one target module, one sibling
module that shares no state with the target, a five-test pytest suite, and a
precompiled bytecode cache for the target module that CPython will read
unconditionally, without ever re-checking the source, until something removes
it.

That last part reproduces a stale-bytecode trap. Under the interpreter's
default (timestamp-based) invalidation, writing a new value into the target
module also changes its modification time, and the interpreter notices and
recompiles on the next import — even when the rewrite is the same number of
bytes, and even if the new mtime happens to be forced back to some earlier
value, as long as it no longer matches what the cache recorded. A cache
written as hash-based with source checking turned off behaves differently:
once it exists, importing the module reads it as-is, and no rewrite of the
source — same length or not, same mtime or not — makes the interpreter look
again. A tool that mutates a file and asks a fresh process to import it can
therefore observe a value that has nothing to do with what is currently on
disk, unless it clears bytecode caches around the mutation. The fixture
exists so that trap can be exercised on demand instead of only when the
coincidence happens to occur in the field.
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path

#: Modification time forced onto the target module so the fixture's file
#: metadata is reproducible across runs. It has no bearing on whether the
#: bytecode cache built from it is stale: that is decided by the source hash
#: recorded inside the cache (see `_compile_sample`), not by a timestamp
#: comparison. Any integer POSIX timestamp works here; this one has no
#: significance beyond being constant.
FIXED_MTIME = 1_700_000_000

#: `git` invoked with an explicit local identity: the fixture repository is
#: disposable and short-lived, and the machine running the self-test has no
#: reason to carry a global git identity for it.
_GIT_CONFIG = (
    "-c",
    "user.name=ablation",
    "-c",
    "user.email=ablation@localhost",
    "-c",
    "commit.gpgsign=false",
)

_SAMPLE_SOURCE = "VALUE = 2\n"

_HELPER_SOURCE = "VALUE_NAME = 1\n\n\ndef name_that_exists():\n    return VALUE_NAME\n"

_TEST_SOURCE = '''"""Tests exercised against the fixture tree by the ablation self-test."""

import pytest

import helper
import sample


def test_guard():
    assert sample.VALUE == 2


def test_unrelated():
    assert True


@pytest.mark.skipif(sample.VALUE == 0, reason="target mutated to the skip-inducing value")
def test_skips_when_mutated():
    assert True


def test_helper():
    assert helper.name_that_exists() == 1


def test_sibling_only():
    assert sample.VALUE != 3
'''

_PYTEST_INI = "[pytest]\npythonpath = .\n"

#: Compiled into a `python -c` subprocess so the fixture's bytecode cache is
#: produced by the interpreter under test, not by whichever interpreter is
#: running this generator. Invalidation mode is forced explicitly to
#: hash-based with source checking off (`UNCHECKED_HASH`): once such a cache
#: exists, the interpreter reads it unconditionally, which is the property
#: the fixture needs (see the module docstring). The explicit `cfile` is
#: printed back so the caller can read the cache's own header rather than
#: recomputing its path from scratch.
_COMPILE_SCRIPT = (
    "import importlib.util, py_compile, sys\n"
    "source = sys.argv[1]\n"
    "cfile = importlib.util.cache_from_source(source)\n"
    "py_compile.compile(\n"
    "    source,\n"
    "    cfile=cfile,\n"
    "    invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,\n"
    "    doraise=True,\n"
    ")\n"
    "print(cfile)\n"
)

#: Offset and width, in bytes, of the invalidation-mode flags field in a pyc
#: header: a 4-byte little-endian value right after the 4-byte magic number.
#: Bit 0 set means the cache is hash-based; bit 1 set on top of that means the
#: hash is also checked against the source at import time. `1` (bit 0 set,
#: bit 1 clear) is hash-based with checking off — the only mode under which
#: this fixture's stale-cache trap holds.
_FLAGS_OFFSET = 4
_FLAGS_SIZE = 4
_UNCHECKED_HASH_FLAGS = 1


def _git(*args: str, cwd: Path) -> None:
    """Run `git` with the fixture's local identity, raising on failure."""
    # The repo's own git on a path this function just created: no untrusted input.
    subprocess.run(  # noqa: S603
        ["git", *_GIT_CONFIG, *args],  # noqa: S607 — git from PATH, as elsewhere here
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


def _compile_sample(sample_path: Path, python: str) -> None:
    """Precompile `sample_path` with `python` into an unchecked, hash-based cache.

    Raises `RuntimeError`, naming the cache path and the flags value actually
    read, if the produced cache is not hash-based with checking off — for
    instance because the interpreter silently fell back to its default
    (timestamp) invalidation. A cache that runs to completion but was not
    written in the mode this fixture depends on would otherwise be discovered
    much later, and far from here, as a fixture that quietly stopped
    reproducing the trap it exists to reproduce.
    """
    # The caller-supplied interpreter compiling a file this function just wrote: no
    # untrusted input.
    result = subprocess.run(  # noqa: S603
        [python, "-c", _COMPILE_SCRIPT, str(sample_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    pyc_path = Path(result.stdout.strip())
    header = pyc_path.read_bytes()[: _FLAGS_OFFSET + _FLAGS_SIZE]
    flags = struct.unpack("<I", header[_FLAGS_OFFSET : _FLAGS_OFFSET + _FLAGS_SIZE])[0]
    if flags != _UNCHECKED_HASH_FLAGS:
        raise RuntimeError(
            f"expected an unchecked-hash bytecode cache (flags={_UNCHECKED_HASH_FLAGS}) "
            f"at {pyc_path}, found flags={flags}"
        )


def make_fixture_tree(dest: Path, python: str = sys.executable) -> Path:
    """Create the ablation self-test's fixture repository under `dest`.

    `dest` becomes a one-commit git repository (branch `main`) tracking
    exactly four files: `sample.py` (the mutation target), `helper.py` (a
    sibling module used to exercise a form-breaking mutation), `test_sample.py`
    (the five-test suite the self-test's mutants are scored against), and
    `pytest.ini`. `sample.py`'s modification time is pinned to `FIXED_MTIME`
    for reproducibility, and a bytecode cache for it is then compiled with
    `python` in the stale-cache-producing mode described in the module
    docstring.

    `__pycache__/` and `.pytest_cache/` are excluded via the repository's own
    `.git/info/exclude` rather than a tracked `.gitignore`, so the set of
    tracked files stays exactly the four named above.

    Returns `dest`.
    """
    dest.mkdir(parents=True, exist_ok=True)

    _git("init", "-b", "main", cwd=dest)
    # `git status --porcelain` is how this tree's consumers see that it is
    # clean, and a global `status.showUntrackedFiles=no` would hide every
    # untracked file from them. Pinned in the repository's own config.
    _git("config", "status.showUntrackedFiles", "normal", cwd=dest)

    exclude_path = dest / ".git" / "info" / "exclude"
    with exclude_path.open("a", encoding="utf-8") as fh:
        fh.write("__pycache__/\n.pytest_cache/\n")

    sample_path = dest / "sample.py"
    sample_path.write_text(_SAMPLE_SOURCE, encoding="utf-8")
    os.utime(sample_path, (FIXED_MTIME, FIXED_MTIME))

    (dest / "helper.py").write_text(_HELPER_SOURCE, encoding="utf-8")
    (dest / "test_sample.py").write_text(_TEST_SOURCE, encoding="utf-8")
    (dest / "pytest.ini").write_text(_PYTEST_INI, encoding="utf-8")

    _git("add", "sample.py", "helper.py", "test_sample.py", "pytest.ini", cwd=dest)
    _git("commit", "-m", "Add the fixture module, its sibling and the test suite", cwd=dest)

    _compile_sample(sample_path, python)

    return dest


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: `make_fixture_tree.py <dest> [--python PYTHON]`."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dest", type=Path, help="directory to create the fixture repository in")
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter used to compile the bytecode cache (defaults to the current one)",
    )
    args = parser.parse_args(argv)
    make_fixture_tree(args.dest, python=args.python)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
