"""Shared core predicates must not acquire new source definitions.

Scan recursively, including new and untracked modules and tools. Test oracles
retain independent expectations; dependencies and generated builds are excluded.
Counting occurrences also rejects a second declaration inside the owner itself.
"""

from __future__ import annotations

import ast
import os
import re
from collections import Counter
from pathlib import Path

import pytest

from tests.test_shared_predicate_parity import EXPECTED_BOUND, EXPECTED_ULID_PATTERN

REPO_ROOT = Path(__file__).resolve().parents[1]
_EXCLUDED_DIRS = {"node_modules", "dist", "__pycache__", "tests", "test", "e2e"}


def _sources(suffix: str) -> list[Path]:
    paths = []
    for directory, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in _EXCLUDED_DIRS)
        for name in sorted(files):
            if name.endswith(suffix) and not name.endswith((".test.ts", ".spec.ts")):
                paths.append(Path(directory) / name)
    return paths


def _python_literals(source: str) -> list[str | int]:
    tree = ast.parse(source)
    prose = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and id(node) not in prose
        and type(node.value) in (str, int)
    ]


@pytest.mark.parametrize("language", ["python", "typescript"])
@pytest.mark.parametrize("predicate", ["receipt_id", "timestamp"])
def test_shared_predicate_definitions_do_not_multiply(language: str, predicate: str) -> None:
    owners = {
        ("python", "receipt_id"): {"src/attest/ulid.py": 1},
        ("python", "timestamp"): {
            "src/attest/dates.py": 1,
            # Independent boundary inputs, not validator declarations.
            "tools/witness_parity_cases.py": 2,
        },
        ("typescript", "receipt_id"): {
            "verifiers/ts/src/ids.ts": 1,
            # Existing application guards: the package does not export its
            # internal predicate. Pin their locations and counts as well.
            "site/src/bundle.ts": 1,
            "site/src/intake.ts": 1,
            "desktop/src/card.ts": 1,
        },
        ("typescript", "timestamp"): {"verifiers/ts/src/dates.ts": 1},
    }
    found: Counter[str] = Counter()
    needle = EXPECTED_ULID_PATTERN.removeprefix("^").removesuffix("$")
    for path in _sources(".py" if language == "python" else ".ts"):
        source = path.read_text(encoding="utf-8")
        if language == "python":
            literals = _python_literals(source)
            count = sum(
                isinstance(value, str) and needle in value
                if predicate == "receipt_id"
                else value == EXPECTED_BOUND
                for value in literals
            )
        else:
            source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)
            if predicate == "receipt_id":
                count = source.count(needle)
            else:
                count = sum(
                    int(number.replace("_", "")) == EXPECTED_BOUND
                    for number in re.findall(r"(?<![\w.])\d[\d_]*(?![\w.])", source)
                )
        if count:
            found[path.relative_to(REPO_ROOT).as_posix()] = count
    assert dict(found) == owners[language, predicate], (
        f"{language} {predicate}: import the shared predicate instead of restating it; "
        f"found {dict(found)}"
    )
