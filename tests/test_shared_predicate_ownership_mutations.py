"""Independent mutations of the source ownership guard."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

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
        (
            "typescript",
            "timestamp",
            ".ts",
            'const note = "0x_"; export const cap = 253402300799n',
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


@pytest.mark.parametrize("prefix", ["0x", "0X", "0b", "0B", "0o", "0O"])
@settings(max_examples=40, derandomize=True)
@given(
    separators=st.integers(min_value=1, max_value=12),
    tail=st.sampled_from(["", "n", "1", "1n"]),
    quote=st.sampled_from(['"', "'", "`"]),
    before=st.booleans(),
)
def test_malformed_radix_text_does_not_abort_or_hide_other_numbers(
    prefix: str, separators: int, tail: str, quote: str, before: bool
) -> None:
    # Mutate a radix spelling at the prefix/digit boundary. Quoted text is
    # valid source even when its contents are not a numeric literal.
    malformed = prefix + "_" * separators + tail
    note = f"const note = {quote}{malformed}{quote};"
    cap = "const cap = 253402300799n;"
    source = note + cap if before else cap + note
    assert guard._script_numbers(guard._script_source(source)) == [253402300799]


@pytest.mark.parametrize(("prefix", "format_code"), [("0x", "x"), ("0b", "b"), ("0o", "o")])
@settings(max_examples=40, derandomize=True)
@given(
    uppercase=st.booleans(),
    bigint=st.booleans(),
    cut=st.integers(min_value=1, max_value=9),
)
def test_valid_radix_spellings_still_expose_the_bound(
    prefix: str, format_code: str, uppercase: bool, bigint: bool, cut: int
) -> None:
    digits = format(253402300799, format_code)
    token = prefix + digits[:cut] + "_" + digits[cut:]
    if uppercase:
        token = token.upper()
    if bigint:
        token += "n"
    assert guard._script_numbers(f"const cap = {token};") == [253402300799]
