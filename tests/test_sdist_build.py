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


def _small_checkout(parent: Path) -> Path:
    """Use the actual hook through the real backend, without adding a dependency."""
    root = parent / "checkout"
    root.mkdir()
    (root / "tools").mkdir()
    shutil.copy2(ROOT / "tools/sdist_files.py", root / "tools/sdist_files.py")
    (root / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["hatchling==1.31.0"]\n'
        'build-backend = "hatchling.build"\n'
        '[project]\nname = "sdist-selection-fixture"\nversion = "1.0.0"\n'
        '[tool.hatch.build.targets.sdist.hooks.custom]\npath = "tools/sdist_files.py"\n'
    )
    assert run("git", "init", "-q", cwd=root).returncode == 0
    assert run("git", "add", ".", cwd=root).returncode == 0
    return root


def _sdist(root: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["uv", "build", "--sdist"],  # noqa: S607
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_sdist_selection_properties(tmp_path: Path) -> None:
    """Membership depends on the index; every path component must be ordinary.

    Generate independent path depths, spellings and mutation positions. Each
    index starts valid; the mutation changes filesystem type, never membership.
    """
    import random

    rng = random.Random(128)  # noqa: S311 -- reproducible path generation, not cryptography
    for case in range(24):
        parent = tmp_path / str(case)
        parent.mkdir()
        root = _small_checkout(parent)
        parts = ["p" + "".join(rng.choices("abc XYZé_'-", k=8)) for _ in range(rng.randint(2, 6))]
        source = root.joinpath(*parts)
        source.parent.mkdir(parents=True)
        source.write_bytes(b"indexed bytes")
        assert run("git", "add", "--", "/".join(parts), cwd=root).returncode == 0
        # Adding any untracked sibling must never change membership.
        source.with_name(source.name + "-untracked").write_bytes(b"local bytes")
        result = _sdist(root)
        assert result.returncode == 0, result.stderr
        with tarfile.open(next((root / "dist").glob("*.tar.gz"))) as archive:
            names = {name.split("/", 1)[1] for name in archive.getnames()}
            assert "/".join(parts) in names
            assert "/".join(parts) + "-untracked" not in names
        mutation = case % 6
        if mutation == 0:
            source.unlink()
        elif mutation == 1:
            source.unlink()
            source.mkdir()
        elif mutation == 2:
            source.unlink()
            os.mkfifo(source)
        elif mutation == 3:
            source.unlink()
            source.symlink_to(parent / "absent")
        elif mutation == 4:
            source.unlink()
            target = parent / "outside.txt"
            target.write_bytes(b"outside bytes")
            source.symlink_to(target)
        else:
            # Relocate an ancestor, so the leaf remains a regular non-symlink.
            ancestor = root.joinpath(*parts[: rng.randint(1, len(parts) - 1)])
            target = parent / "outside"
            ancestor.rename(target)
            ancestor.symlink_to(target, target_is_directory=True)
            assert source.is_file() and not source.is_symlink()
        result = _sdist(root)
        assert result.returncode != 0, (mutation, parts, result.stderr)
        assert "Tracked source" in result.stderr


def test_sdist_refuses_unsafe_index_paths(tmp_path: Path) -> None:
    """Git normally excludes traversal; the hook must contain its output too."""
    import random
    import sys

    rng = random.Random(129)  # noqa: S311 -- reproducible path generation, not cryptography
    for case in range(20):
        parent = tmp_path / str(case)
        parent.mkdir()
        root = _small_checkout(parent)
        suffix = "".join(rng.choices("abcdef0123456789", k=12))
        outside = parent / suffix
        outside.write_bytes(b"outside bytes")
        candidates = [
            "../" + suffix,
            str(outside),
            "C:/" + suffix,
            "D:" + suffix,
            "./" + suffix,
            "nested//" + suffix,
            suffix + "\\" + suffix,
            suffix + chr(rng.randint(1, 31)),
            suffix + "\x7f",
            suffix + "\udcff",
        ]
        relative = candidates[case % len(candidates)]
        stubs = parent / "bin"
        stubs.mkdir()
        fake_git = stubs / "git"
        data = os.fsencode(relative) + b"\0"
        fake_git.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.buffer.write({data!r})\n")
        fake_git.chmod(0o755)
        result = _sdist(root, {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"})
        assert result.returncode != 0, relative
        assert "Unsafe tracked source path" in result.stderr or "not UTF-8" in result.stderr


def test_sdist_requires_git_and_nonempty_selection(tmp_path: Path) -> None:
    root = _small_checkout(tmp_path)
    (root / ".git").rename(tmp_path / "saved-index")
    result = _sdist(root)
    assert result.returncode != 0
    assert "requires a Git checkout" in result.stderr
    assert run("git", "init", "-q", cwd=root).returncode == 0
    result = _sdist(root)
    assert result.returncode != 0
    assert "no tracked files" in result.stderr
