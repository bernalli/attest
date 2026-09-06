"""Build source distributions from tracked files, preserving target exclusions.

VCS ignore patterns alone do not describe the published source: local excludes
and untracked files can differ between checkouts. The index defines membership;
the working files supply the bytes. Building a wheel from the resulting sdist
does not run this hook and needs no Git checkout.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class TrackedSourceFiles(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root)
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
            source = root / relative
            if self.build_config.include_path(relative):
                if not source.is_file() or source.is_symlink():
                    raise RuntimeError(f"Tracked source is not a regular file: {relative}")
                selected[str(source)] = relative
        if not selected:
            raise RuntimeError("The source distribution has no tracked files")
        # Explicit file selection avoids recursively admitting untracked siblings.
        self.build_config.only_include.clear()
        self.build_config.only_include.update(selected)
