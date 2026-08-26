"""Dogfood tests for the Python conformance adapter and its end-to-end
self-certification through the PUBLIC runner.

Unlike `tests/tools/test_conformance_runner.py` (hermetic, fake adapters
only), this module is the ONE place the real Python reference verifier
(`attest.verify`/`attest.transfer`) meets `tools/conformance_runner.py` —
through its adapter, `tools/conformance_adapter_py.py`, always invoked as a
genuine subprocess (never in-process). Keeping the two suites separate means
a runner bug and a verifier regression can never be conflated (P1.6 plan,
Task 4 self-review note).
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PY = REPO_ROOT / "tools" / "conformance_adapter_py.py"
RUNNER = REPO_ROOT / "tools" / "conformance_runner.py"
_VECTORS = REPO_ROOT / "docs" / "spec" / "vectors"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def test_python_adapter_single_leaf() -> None:
    leaf = _VECTORS / "01-valid-minimal"
    proc = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [sys.executable, str(ADAPTER_PY), str(leaf)],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    assert data["signature"] == "valid"
    assert data["ok"] is True


def test_python_reference_self_certifies_v02(tmp_path: Path) -> None:
    """The phase's end-to-end conformance gate: the REAL Python reference
    verifier, driven through its adapter, driven through the PUBLIC runner
    (a subprocess spawning one adapter subprocess per leaf, one per corpus leaf) —
    self-certifies the full v0.2 corpus. Deliberately the slowest test in
    the suite; never mark, never skip: this IS the public conformance path,
    not a proxy for it."""
    report_path = tmp_path / "report.json"
    adapter_template = f"{shlex.quote(sys.executable)} {shlex.quote(str(ADAPTER_PY))} {{leaf}}"
    proc = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [
            sys.executable,
            str(RUNNER),
            "--adapter",
            adapter_template,
            "--subset",
            "v0.2",
            "--report",
            str(report_path),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["conformant"] is True
    assert report["passed"] == report["total"]
    # Pinned to the corpus on disk rather than to a floor: a floor stops
    # catching anything the moment the corpus outgrows it, which is how it
    # came to sit at 130 while the corpus reached 158.
    assert report["total"] == sum(1 for _ in _VECTORS.rglob("expected.json"))
    assert report["subset"] == "v0.2"
    assert _HEX64_RE.match(report["corpus_revision"]) is not None
