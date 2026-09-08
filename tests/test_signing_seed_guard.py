"""Signing-key uniqueness applies to every corpus-generation entry point."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import FunctionType, ModuleType

import pytest
from hypothesis import given
from hypothesis import strategies as st

from attest import keys


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "tools" / "gen_vectors.py"
    spec = importlib.util.spec_from_file_location("seed_guard_generator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("entry", ["generate", "check", "main-generate", "main-check"])
def test_collision_fails_before_generation(
    generator: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entry: str
) -> None:
    monkeypatch.setattr(generator, "PLEDGE_PUBLISHER_KP", keys.from_seed(bytes([37]) * 32))

    def forbidden_generation(out: Path) -> int:
        raise RuntimeError("generation reached before signing-key validation")

    monkeypatch.setattr(generator, "_generate_all", forbidden_generation)
    previous = generator.VECTORS_DIR
    with pytest.raises(AssertionError) as failure:
        if entry == "generate":
            generator.generate(tmp_path)
        elif entry == "check":
            generator.check(tmp_path)
        else:
            args = ["--out", str(tmp_path)]
            if entry == "main-check":
                args.append("--check")
            generator.main(args)
    assert str(failure.value) == (
        "reused signing seed: CHAIN_HOLDER_2_KP and PLEDGE_PUBLISHER_KP share a public key"
    )
    assert generator.VECTORS_DIR == previous


@pytest.mark.parametrize("layout", ["list", "module-list", "arithmetic", "dict-tuple", "depth3"])
@given(seed=st.integers(min_value=0, max_value=255))
def test_duplicate_key_layouts(generator: ModuleType, layout: str, seed: int) -> None:
    first = keys.from_seed(bytes([seed]) * 32)
    second = keys.from_seed(bytes([seed]) * 32)
    cases = {
        "list": ({"A": [first, second]}, "A[0] and A[1]"),
        "module-list": ({"A": first, "B": [second]}, "A and B[0]"),
        "arithmetic": (
            {"A": first, "B": keys.from_seed(bytes([(seed + 256) % 256]) * 32)},
            "A and B",
        ),
        "dict-tuple": ({"A": {"slot": (first, second)}}, "A['slot'][0] and A['slot'][1]"),
        "depth3": ({"A": [[[first, second]]]}, "A[0][0][0] and A[0][0][1]"),
    }
    namespace, paths = cases[layout]
    guard = FunctionType(
        generator._assert_distinct_signing_keys.__code__, {"keys": keys, **namespace}
    )
    with pytest.raises(AssertionError) as failure:
        guard()
    assert str(failure.value) == f"reused signing seed: {paths} share a public key"


@given(seed=st.integers(min_value=0, max_value=255))
def test_distinct_keys_pass(generator: ModuleType, seed: int) -> None:
    first = keys.from_seed(bytes([seed]) * 32)
    second = keys.from_seed(bytes([(seed + 1) % 256]) * 32)
    guard = FunctionType(
        generator._assert_distinct_signing_keys.__code__,
        {"keys": keys, "A": [first, second]},
    )
    assert guard() is None


def test_empty_container_passes(generator: ModuleType) -> None:
    guard = FunctionType(generator._assert_distinct_signing_keys.__code__, {"keys": keys, "A": []})
    assert guard() is None


def test_optimized_python_still_rejects_collision(generator: ModuleType) -> None:
    code = """
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("optimized_generator", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.PLEDGE_PUBLISHER_KP = module.keys.from_seed(bytes([37]) * 32)
module._assert_distinct_signing_keys()
print("collision guard was bypassed")
"""
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repository-owned code
        [sys.executable, "-B", "-O", "-c", code, generator.__file__],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert (
        "reused signing seed: CHAIN_HOLDER_2_KP and PLEDGE_PUBLISHER_KP share a public key"
    ) in result.stderr
    assert "collision guard was bypassed" not in result.stdout
