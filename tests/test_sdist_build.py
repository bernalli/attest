"""Exercise the real build backend with tracked and local-only source files."""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- fixed build and Git commands below
        args, cwd=cwd, capture_output=True, text=True, check=False, timeout=120
    )


def test_sdist_excludes_local_files_and_rebuilds_a_wheel(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    git = shutil.which("git")
    if uv is None or git is None:
        if os.environ.get("ATTEST_CI_REQUIRED"):
            pytest.fail("the source-distribution build test requires uv and git")
        pytest.skip("the source-distribution build test requires uv and git")
    root = tmp_path / "checkout"
    root.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE", "uv.lock"):
        shutil.copy2(ROOT / name, root / name)
    for name in ("src", "bridge", "witness"):
        shutil.copytree(ROOT / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
    (root / "tools").mkdir()
    shutil.copy2(ROOT / "tools/sdist_files.py", root / "tools/sdist_files.py")
    assert run(git, "init", "-q", cwd=root).returncode == 0
    assert run(git, "add", ".", cwd=root).returncode == 0
    for name in ("local-note.txt", ".scratch/note.txt", "src/attest/local-note.txt"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not part of the distribution\n")
    # Local exclusions must not be necessary to keep any of these out.
    (root / ".git/info/exclude").write_text("local-note.txt\n.scratch/\n")
    result = run(uv, "build", "--sdist", cwd=root)
    assert result.returncode == 0, result.stderr
    archive = next((root / "dist").glob("*.tar.gz"))
    with tarfile.open(archive) as source:
        members = source.getnames()
        relative = {name.split("/", 1)[1] for name in members}
        assert not any("local-note" in name or ".scratch" in name for name in relative)
        assert not any(name.startswith(("bridge/", "witness/")) for name in relative)
        assert "src/attest/views.py" in relative
        assert "tools/sdist_files.py" in relative
        extracted = tmp_path / "extracted"
        source.extractall(extracted, filter="data")
    unpacked = next(extracted.iterdir())
    result = run(uv, "build", "--wheel", cwd=unpacked)
    assert result.returncode == 0, result.stderr
    assert len(list((unpacked / "dist").glob("*.whl"))) == 1
