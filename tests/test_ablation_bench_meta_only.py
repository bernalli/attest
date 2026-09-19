"""The narrowed run of the ablation bench: what `ABLATION_BENCH_META_ONLY` selects, how it exits.

The gate's negative control is the only caller of this mode, and it exercises one
row and one exit status. The rest of the contract -- a selection that selects
nothing is refused, a row that was not measured never exits 0 or 1, the bench's
own marker is never printed -- is pinned here, where a regression is a named red
instead of a gate that stays green on a narrowed run nobody reads.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_BENCH = Path(__file__).resolve().parents[1] / "tools" / "gates" / "ablation" / "bench_ablate.py"
_BENCH_MARKER = "ABLATION_BENCH cases="
_NARROWED_LINE = "ABLATION_BENCH_META_ONLY id="


def _load_bench() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bench_ablate_meta_only_under_test", _BENCH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # The module defines dataclasses, which look their module up in sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BENCH = _load_bench()
VALID_IDS = [row.ident for row in BENCH.META_MUTANTS]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "MB99-nope",
        " " + VALID_IDS[0],
        VALID_IDS[0] + " ",
        VALID_IDS[0] + "\n",
        VALID_IDS[0].lower(),
        VALID_IDS[0] + "," + VALID_IDS[1],
        "*",
    ],
    ids=["empty", "unknown", "leading-space", "trailing-space", "newline", "case", "two", "glob"],
)
def test_a_value_that_names_no_row_is_refused_with_2_and_never_prints_a_marker(value: str) -> None:
    env = {**os.environ, BENCH.META_ONLY_VARIABLE: value}
    run = subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [sys.executable, "-B", str(_BENCH)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert run.returncode == BENCH.EXIT_META_ONLY_REFUSED == 2, run.stdout + run.stderr
    assert f"{BENCH.META_ONLY_VARIABLE}={value!r} selects no meta-mutant" in run.stderr
    assert "Valid ids: " + ", ".join(VALID_IDS) in run.stderr
    assert _BENCH_MARKER not in run.stdout + run.stderr
    assert _NARROWED_LINE not in run.stdout + run.stderr


def _case(name: str, ok: bool) -> Any:
    return BENCH.Case(name, ok, "detail")


_FAILING = (_case("A1", True), _case("A3", False))
_HOLDING = (_case("A1", True), _case("A2", True))


@pytest.mark.parametrize(
    ("refusal", "cases", "stopped", "want", "printed"),
    [
        ("ablate.py: the anchor is absent", (), "", 3, "anchor absent in copy -- ablate.py"),
        (None, _FAILING, "", 1, "copy_cases=2 copy_failures=1"),
        (None, _FAILING, "the part stopped with RuntimeError: x", 1, "the cases after that point"),
        (None, _HOLDING, "", 0, "copy_cases=2 copy_failures=0"),
        (None, _HOLDING, "the part stopped with RuntimeError: x", 3, "the cases after that point"),
        (None, (), "the part stopped with RuntimeError: x", 3, "copy_cases=0 copy_failures=0"),
        (None, (), "", 3, "copy_cases=0 copy_failures=0"),
    ],
    ids=[
        "anchor-absent",
        "failed",
        "failed-then-stopped",
        "held-to-the-end",
        "held-then-stopped",
        "stopped-with-no-case",
        "ran-no-case",
    ],
)
def test_the_exit_status_of_a_narrowed_run_follows_what_the_copy_did(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    refusal: str | None,
    cases: tuple[Any, ...],
    stopped: str,
    want: int,
    printed: str,
) -> None:
    def observe(bench: Any, mutant: Any, home: Path) -> Any:
        return BENCH.MetaObservation(refusal, cases, stopped)

    monkeypatch.setattr(BENCH, "observe_meta_mutant", observe)
    assert BENCH.meta_only(VALID_IDS[0]) == want
    out = capsys.readouterr().out
    assert printed in out
    assert f"{_NARROWED_LINE}{VALID_IDS[0]} " in out
    assert _BENCH_MARKER not in out
    if refusal is not None:
        assert "FAIL:" not in out
