"""Two predicates live in more than one copy. Something executable must compare them.

Both cores must agree on which instants are representable and on what a receipt
id looks like. Neither property can be consolidated across the language
boundary — the packages ship separately — so the copies are a real constraint,
not laziness. What is NOT acceptable is that nothing checks them: a restated
predicate is owned by nobody, and the way it fails is silent.

That is not hypothetical here. The representable-time bound was written out
three times in the TypeScript tree, and the fourth call site that needed it —
the refund window — did not remember it existed, which is how one core came to
certify receipts the other rejected. The ULID pattern was declared four times
in Python and twice in TypeScript, and the revocation path imported neither TS
copy, which let a record naming no real receipt set the freshness anchor.

The TypeScript side has since been reduced to one definition each. Python still
declares its own, and this module is what keeps the two languages in step until
(and after) that changes. It reads sources as data rather than shelling out to
a build: the point is a red line in one second inside the ordinary suite.
"""

from __future__ import annotations

import re
from pathlib import Path

from attest import anchor, bundle, cli, revocation, transfer, views, witness

REPO_ROOT = Path(__file__).resolve().parents[1]
TS_SRC = REPO_ROOT / "verifiers" / "ts" / "src"

# 9999-12-31T23:59:59Z. Python's `datetime` stops at year 9999 while
# JavaScript's `Date` reaches 275760, so anything past this is accepted by one
# core and rejected by the other.
EXPECTED_BOUND = 253402300799
EXPECTED_ULID_PATTERN = r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
EXPECTED_UNREPRESENTABLE_ERROR = "refund window is outside the representable timestamp range"


def _ts_source(name: str) -> str:
    return (TS_SRC / name).read_text(encoding="utf-8")


def _sole_ts_declaration(pattern: str, name: str) -> str:
    """The single match of `pattern` in one TypeScript module.

    Asserting on the COUNT is half the test: a second declaration appearing in
    the same file is the drift this module exists to catch.
    """
    source = _ts_source(name)
    found = re.findall(pattern, source)
    assert len(found) == 1, f"expected exactly one declaration in {name}, found {len(found)}"
    return str(found[0])


def test_every_python_declaration_of_the_representable_bound_agrees() -> None:
    assert witness.MAX_COSIGNATURE_TIMESTAMP == EXPECTED_BOUND
    assert anchor._MAX_RENDERABLE_UNIX_TIME == EXPECTED_BOUND


def test_the_typescript_bound_is_declared_once_and_matches_python() -> None:
    declared = _sole_ts_declaration(
        r"export const MAX_REPRESENTABLE_UNIX_SECONDS = (\d+)", "dates.ts"
    )
    assert int(declared) == EXPECTED_BOUND


def test_no_typescript_module_restates_the_bound_as_a_literal() -> None:
    """The number may appear only where it is defined, and in prose about it.

    This is the check that would have failed before the fix, when three modules
    each carried their own copy.
    """
    offenders = [
        path.name
        for path in sorted(TS_SRC.glob("*.ts"))
        if path.name != "dates.ts" and str(EXPECTED_BOUND) in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def _receipt_id_pattern(module: object) -> str:
    """The module's ULID pattern, whatever it chose to call it.

    `revocation` exports it publicly and `views` imports that one; the rest
    still keep a private copy. Which name a module uses is its own business and
    changes over time — what this file guards is that the PATTERN is the same
    everywhere, so looking it up by exact name would make this test fail for a
    rename while staying silent on the drift it exists to catch.
    """
    pattern = getattr(module, "RECEIPT_ID_RE", None) or getattr(module, "_RECEIPT_ID_RE", None)
    assert pattern is not None, f"{module.__name__} declares no receipt-id pattern"
    return str(pattern.pattern)


def test_every_python_declaration_of_the_receipt_id_pattern_agrees() -> None:
    for module in (revocation, transfer, bundle, cli, views):
        assert _receipt_id_pattern(module) == EXPECTED_ULID_PATTERN, module.__name__


def test_the_typescript_receipt_id_pattern_is_declared_once_and_matches_python() -> None:
    declared = _sole_ts_declaration(r"export const RECEIPT_ID_RE = /(.+)/\n", "ids.ts")
    assert declared == EXPECTED_ULID_PATTERN


def test_no_typescript_module_restates_the_receipt_id_pattern() -> None:
    needle = "[0-7][0-9A-HJKMNP-TV-Z]{25}"
    offenders = [
        path.name
        for path in sorted(TS_SRC.glob("*.ts"))
        if path.name != "ids.ts" and needle in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_the_unrepresentable_window_error_is_byte_identical_across_cores() -> None:
    """Conformance vectors substring-match this literal, so a paraphrase on one
    side is a divergence even when both cores reach the same verdict."""
    python_source = (REPO_ROOT / "src" / "attest" / "verify.py").read_text(encoding="utf-8")
    assert f'"{EXPECTED_UNREPRESENTABLE_ERROR}"' in python_source
    declared = _sole_ts_declaration(
        r"export const REFUND_WINDOW_UNREPRESENTABLE = '(.+)'", "messages.ts"
    )
    assert declared == EXPECTED_UNREPRESENTABLE_ERROR
