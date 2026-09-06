"""Build source distributions from tracked files, preserving target exclusions.

VCS ignore patterns alone do not describe the published source: local excludes
and untracked files can differ between checkouts. The index defines membership;
the working files supply the bytes. Building a wheel from the resulting sdist
does not run this hook and needs no Git checkout.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path, PureWindowsPath
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def _source_path(root: Path, relative: str) -> Path:
    parts = relative.split("/")
    try:
        relative.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RuntimeError(f"Tracked source path is not UTF-8: {relative!r}") from exc
    if (
        any(part in ("", ".", "..") for part in parts)
        or PureWindowsPath(relative).drive
        or "\\" in relative
        or any(ord(char) < 32 or ord(char) == 127 for char in relative)
    ):
        raise RuntimeError(f"Unsafe tracked source path: {relative!r}")
    source = root
    for index, part in enumerate(parts):
        source = source / part
        try:
            mode = source.lstat().st_mode
        except OSError as exc:
            raise RuntimeError(f"Tracked source is unavailable: {relative!r}") from exc
        if stat.S_ISLNK(mode):
            raise RuntimeError(f"Tracked source traverses a symbolic link: {relative!r}")
        expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if not expected(mode):
            raise RuntimeError(f"Tracked source is not a regular file: {relative!r}")
    return source


class TrackedSourceFiles(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root).resolve()
        if not (root / ".git").exists():
            raise RuntimeError("Building an sdist requires a Git checkout; wheels do not")
        result = subprocess.run(
            ["git", "ls-files", "--cached", "-z"],  # noqa: S607
            cwd=root,
            check=True,
            capture_output=True,
        )
        selected = {}
        for raw in result.stdout.split(b"\0"):
            if not raw:
                continue
            relative = os.fsdecode(raw)
            if self.build_config.include_path(relative):
                source = _source_path(root, relative)
                selected[str(source)] = relative
        if not selected:
            raise RuntimeError("The source distribution has no tracked files")
        # Explicit file selection avoids recursively admitting untracked siblings.
        self.build_config.only_include.clear()
        self.build_config.only_include.update(selected)
