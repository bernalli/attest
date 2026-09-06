"""Independent mutations of the source ownership guard."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import test_shared_predicate_ownership as guard


@pytest.mark.parametrize(
    ("language", "predicate", "suffix", "source"),
    [
        ("python", "timestamp", ".py", "CAP = 253402300799"),
        ("python", "timestamp", ".py", "CAP = 253402300799.0"),
        ("python", "timestamp", ".py", "CAP = 0x3afff4417f"),
        ("python", "timestamp", ".py", "CAP = 253402300800 - 1"),
        (
            "python",
            "receipt_id",
            ".py",
            'import re\nID = re.compile(r"^[0-7]" + r"[0-9A-HJKMNP-TV-Z]{25}$")',
        ),
        ("typescript", "timestamp", ".ts", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".mjs", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".js", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".cjs", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".mts", "export const cap = 253402300799n"),
        ("typescript", "timestamp", ".cts", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".tsx", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".jsx", "const cap = 253402300799n"),
        ("typescript", "timestamp", ".ts", "export const cap = 0x3afff4417fn"),
        ("typescript", "timestamp", ".ts", "export const cap = 253402300799.0"),
        ("typescript", "timestamp", ".ts", "export const cap = 2.53402300799e11"),
        (
            "typescript",
            "timestamp",
            ".ts",
            'const url = "https://example.org"; export const cap = 253402300799n',
        ),
        (
            "typescript",
            "receipt_id",
            ".mjs",
            "export const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        ),
    ],
)
def test_guard_turns_red_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
    predicate: str,
    suffix: str,
    source: str,
) -> None:
    # Seed the permitted production locations; test inputs do not come from
    # the scanner's token definitions or from the implementation under test.
    owners = {
        "src/attest/ulid.py": 'ID = "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"',
        "src/attest/dates.py": "CAP = 253402300799",
        "tools/witness_parity_cases.py": "A = 253402300799\nB = 253402300799",
        "verifiers/ts/src/ids.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        "verifiers/ts/src/dates.ts": "const cap = 253402300799",
        "site/src/bundle.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        "site/src/intake.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
        "desktop/src/card.ts": "const id = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/",
    }
    for name, content in owners.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(guard, "REPO_ROOT", tmp_path)
    check = guard.test_shared_predicate_definitions_do_not_multiply
    check(language, predicate)
    probe = tmp_path / f"tools/new_adapter{suffix}"
    probe.write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="import the shared predicate"):
        check(language, predicate)
    probe.unlink()
    check(language, predicate)
