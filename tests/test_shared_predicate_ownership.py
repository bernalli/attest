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
from decimal import Decimal
from pathlib import Path

import pytest

from tests.test_shared_predicate_parity import EXPECTED_BOUND, EXPECTED_ULID_PATTERN

REPO_ROOT = Path(__file__).resolve().parents[1]
_EXCLUDED_DIRS = {"node_modules", "dist", "__pycache__", "tests", "test", "e2e"}


def _sources(suffixes: tuple[str, ...]) -> list[Path]:
    paths = []
    for directory, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in _EXCLUDED_DIRS)
        for name in sorted(files):
            if name.endswith(suffixes) and not name.endswith(
                tuple(
                    f".{kind}{suffix}" for kind in ("test", "spec") for suffix in _SCRIPT_SUFFIXES
                )
            ):
                paths.append(Path(directory) / name)
    return paths


def _python_literals(source: str) -> list[str | int | float]:
    tree = ast.parse(source)
    prose = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }

    def literal(node: ast.AST) -> str | int | float | None:
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                return value
        if isinstance(node, ast.BinOp):
            left, right = literal(node.left), literal(node.right)
            if isinstance(node.op, ast.Add):
                if isinstance(left, str) and isinstance(right, str):
                    return left + right
                if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    return left + right
            if isinstance(node.op, ast.Sub):
                if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    return left - right
        return None

    values = []
    for node in ast.walk(tree):
        if id(node) not in prose and (value := literal(node)) is not None:
            values.append(value)
    return values


_SCRIPT_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
# Quoted text must win over comment delimiters: an URL is not a line comment.
_SCRIPT_COMMENTS = re.compile(
    r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)"
    r"|/\*.*?\*/|//[^\n]*",
    re.DOTALL,
)
# Every radix prefix needs a real digit before any separator: `0x_` is not a
# number in any of these languages, and `int("0x", 0)` would abort the scan.
_SCRIPT_NUMBERS = re.compile(
    r"(?<![\w.])(?:0[xX][0-9a-fA-F][0-9a-fA-F_]*n?|0[bB][01][01_]*n?|"
    r"0[oO][0-7][0-7_]*n?|"
    r"[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]+)?n?)(?![\w.])"
)


def _script_source(source: str) -> str:
    return _SCRIPT_COMMENTS.sub(lambda match: match.group(1) or " ", source)


def _script_numbers(source: str) -> list[int | Decimal]:
    values: list[int | Decimal] = []
    for token in _SCRIPT_NUMBERS.findall(source):
        token = token.replace("_", "").removesuffix("n")
        values.append(
            int(token, 0) if token.lower().startswith(("0x", "0b", "0o")) else Decimal(token)
        )
    return values


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
    for path in _sources((".py",) if language == "python" else _SCRIPT_SUFFIXES):
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
            source = _script_source(source)
            if predicate == "receipt_id":
                count = source.count(needle)
            else:
                count = sum(number == EXPECTED_BOUND for number in _script_numbers(source))
        if count:
            found[path.relative_to(REPO_ROOT).as_posix()] = count
    assert dict(found) == owners[language, predicate], (
        f"{language} {predicate}: import the shared predicate instead of restating it; "
        f"found {dict(found)}"
    )
