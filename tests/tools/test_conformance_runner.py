"""Tests for tools/conformance_runner.py — the public conformance runner.

Hermetic by construction: the real Python/TS verifiers are NEVER invoked from
this module. Every test drives the runner through fake adapters (tiny Python
scripts written to ``tmp_path``, invoked via ``sys.executable``) or dict
literals, following ``tests/tools/test_check_formal.py``'s ``from tools
import ...`` idiom and injection discipline.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

import pytest

from tools import conformance_runner as cr

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_VECTORS = REPO_ROOT / "docs" / "spec" / "vectors"


# --------------------------------------------------------------------------
# Fake-adapter scripts (never the real verifiers)
# --------------------------------------------------------------------------


def _write_script(tmp_path: Path, name: str, body: str) -> str:
    """Write an executable Python fake-adapter script; return its command prefix."""
    script = tmp_path / name
    script.write_text(body, encoding="utf-8")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}"


def cat_adapter_template(tmp_path: Path) -> str:
    """Adapter that cats ``<leaf>/adapter_output.json`` verbatim to stdout."""
    body = (
        "import pathlib\n"
        "import sys\n"
        "leaf = pathlib.Path(sys.argv[1])\n"
        "sys.stdout.write((leaf / 'adapter_output.json').read_text(encoding='utf-8'))\n"
    )
    return _write_script(tmp_path, "cat_adapter.py", body) + " {leaf}"


def exit_code_adapter_template(tmp_path: Path, code: int = 3) -> str:
    """Adapter that always exits non-zero, ignoring its input."""
    body = f"import sys\nsys.stderr.write('boom\\n')\nsys.exit({code})\n"
    return _write_script(tmp_path, "exit_adapter.py", body) + " {leaf}"


def garbage_adapter_template(tmp_path: Path) -> str:
    """Adapter that prints non-JSON garbage to stdout."""
    body = "import sys\nsys.stdout.write('not json at all {\\n')\n"
    return _write_script(tmp_path, "garbage_adapter.py", body) + " {leaf}"


def sleepy_adapter_template(tmp_path: Path, seconds: float = 5.0) -> str:
    """Adapter that sleeps past a short timeout before ever printing anything."""
    body = f"import time\ntime.sleep({seconds!r})\nprint('{{}}')\n"
    return _write_script(tmp_path, "sleepy_adapter.py", body) + " {leaf}"


def echo_leaf_adapter_template(tmp_path: Path) -> str:
    """Adapter that reports back the argv tokens it actually received."""
    body = "import json\nimport sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    script_cmd = _write_script(tmp_path, "echo_adapter.py", body)
    return f'{script_cmd} "an arg with spaces" {{leaf}}'


# --------------------------------------------------------------------------
# Mini-corpus builder
# --------------------------------------------------------------------------


def _write_leaf(
    root: Path,
    rel: str,
    expected: dict[str, Any],
    *,
    chain: bool = False,
    adapter_output: dict[str, Any] | None = None,
) -> Path:
    leaf = root / rel
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "expected.json").write_text(json.dumps(expected), encoding="utf-8")
    if chain:
        (leaf / "chain.json").write_text(
            json.dumps({"payloads": [], "transfer_view": [], "revocation_view": []}),
            encoding="utf-8",
        )
    else:
        (leaf / "envelope.json").write_text(
            json.dumps({"payload": {}, "signatures": []}), encoding="utf-8"
        )
    if adapter_output is not None:
        (leaf / "adapter_output.json").write_text(json.dumps(adapter_output), encoding="utf-8")
    return leaf


@pytest.fixture
def mini_corpus(tmp_path: Path) -> Path:
    """The exact leaf set the plan's Task 3 Step 1 pins for subset/discovery coverage."""
    root = tmp_path / "vectors"
    _write_leaf(
        root, "01-a", {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    )
    _write_leaf(
        root, "14b-x", {"signature": "valid", "schema": "valid", "trust": "unverified_rotation"}
    )
    _write_leaf(
        root, "26-b", {"signature": "invalid", "schema": "valid", "trust": "unauthenticated_tofu"}
    )
    _write_leaf(
        root,
        "29-limits",
        {"signature": "invalid", "schema": "invalid", "trust": "unauthenticated_tofu"},
    )
    _write_leaf(
        root, "31-currency", {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    )
    _write_leaf(
        root,
        "35-transfer/i-v01-transferable-null-pubkey-ok",
        {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
    )
    _write_leaf(
        root,
        "35-transfer/j-other",
        {"signature": "invalid", "schema": "invalid", "trust": "unauthenticated_tofu"},
    )
    _write_leaf(
        root,
        "36-chain/a",
        {"chain_valid": True, "link_status": ["valid"], "errors_contains": [], "warnings": []},
        chain=True,
    )
    return root


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def test_find_leaf_dirs_discovers_nested_leaves_sorted(mini_corpus: Path) -> None:
    leaves = cr.find_leaf_dirs(mini_corpus)
    ids = [cr.leaf_id(mini_corpus, leaf) for leaf in leaves]
    assert ids == sorted(ids)
    assert "35-transfer/i-v01-transferable-null-pubkey-ok" in ids
    assert "36-chain/a" in ids
    assert len(ids) == 8


def test_leaf_id_is_posix_relative(mini_corpus: Path) -> None:
    leaf = mini_corpus / "35-transfer" / "j-other"
    assert cr.leaf_id(mini_corpus, leaf) == "35-transfer/j-other"


# --------------------------------------------------------------------------
# Subset rule
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lid", "expected"),
    [
        ("01-a/x", True),
        ("14b-x", True),
        ("25-y/a", True),
        ("26-b", False),
        ("29-limits/a", True),
        ("31-currency/e", True),
        ("33-z/a", False),
        ("35-transfer/i-v01-transferable-null-pubkey-ok", True),
        ("35-transfer/j-other", False),
        ("41-compromise-cutoff/f-stage1-fail-closed", True),
        ("41-compromise-cutoff/a-other", False),
        ("36-chain/a", False),
    ],
)
def test_in_v01_subset_rule(lid: str, expected: bool) -> None:
    assert cr.in_v01_subset(lid) is expected


def test_select_subset_v01_is_exactly_58_leaves_of_the_real_corpus() -> None:
    # 53 before the V-L guards (2026-08-26, v0.1 rev 10) added groups
    # 44-manifest-duplicate-kid (3 leaves) and 45-revocation-anchor-status (2),
    # both v0.1 conformance.
    leaves = cr.find_leaf_dirs(REAL_VECTORS)
    subset = cr.select_subset(leaves, REAL_VECTORS, "v0.1")
    assert len(subset) == 58


def test_select_subset_v02_is_the_full_real_corpus() -> None:
    leaves = cr.find_leaf_dirs(REAL_VECTORS)
    subset = cr.select_subset(leaves, REAL_VECTORS, "v0.2")
    # Both halves matter: the v0.2 subset is the whole corpus, and the whole
    # corpus is what is actually on disk. The second assertion was a constant
    # floor, which stops catching a truncated discovery the moment the corpus
    # outgrows it.
    on_disk = sum(1 for _root, _dirs, files in os.walk(REAL_VECTORS) if "expected.json" in files)
    assert on_disk > 0
    assert len(subset) == len(leaves) == on_disk


# --------------------------------------------------------------------------
# Diff rules — verify leaves
# --------------------------------------------------------------------------


def test_diff_verify_result_passes_on_full_match() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    actual = dict(expected)
    assert cr.diff_verify_result(expected, actual) == []


def test_diff_verify_result_required_exact_mismatch() -> None:
    expected = {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    actual = {"signature": "invalid", "schema": "valid", "trust": "authenticated_tls"}
    mismatches = cr.diff_verify_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("signature:")


def test_diff_verify_result_required_field_missing_from_actual() -> None:
    expected = {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    actual = {"schema": "valid", "trust": "authenticated_tls"}
    mismatches = cr.diff_verify_result(expected, actual)
    assert mismatches == ["signature: missing from adapter output"]


def test_diff_verify_result_conditional_field_ignored_when_absent_from_expected() -> None:
    expected = {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    actual = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "revocation": "revoked",
    }
    assert cr.diff_verify_result(expected, actual) == []


def test_diff_verify_result_conditional_field_mismatch_when_present_in_expected() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "revocation": "revoked",
    }
    actual = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "revocation": "invalid_revocation_ignored",
    }
    mismatches = cr.diff_verify_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("revocation:")


def test_diff_verify_result_conditional_field_missing_from_actual_is_a_mismatch() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "binding": "proven",
    }
    actual = {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    mismatches = cr.diff_verify_result(expected, actual)
    assert mismatches == ["binding: missing from adapter output"]


def test_diff_verify_result_exact_errors_list() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "errors": ["a"],
    }
    actual_ok = dict(expected)
    actual_bad = {**expected, "errors": ["b"]}
    assert cr.diff_verify_result(expected, actual_ok) == []
    mismatches = cr.diff_verify_result(expected, actual_bad)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("errors:")


def test_diff_verify_result_exact_warnings_list() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "warnings": ["w"],
    }
    actual_ok = dict(expected)
    actual_bad = {**expected, "warnings": []}
    assert cr.diff_verify_result(expected, actual_ok) == []
    mismatches = cr.diff_verify_result(expected, actual_bad)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("warnings:")


def test_diff_verify_result_errors_contains_pass_and_fail() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "errors_contains": ["boom"],
    }
    actual_pass = {**expected, "errors": ["a real boom happened"]}
    actual_fail = {**expected, "errors": ["nothing wrong"]}
    assert cr.diff_verify_result(expected, actual_pass) == []
    mismatches = cr.diff_verify_result(expected, actual_fail)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("errors_contains:")


def test_diff_verify_result_warnings_contains_pass_and_fail() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "warnings_contains": ["dep"],
    }
    actual_pass = {**expected, "warnings": ["deprecated key"]}
    actual_fail = {**expected, "warnings": []}
    assert cr.diff_verify_result(expected, actual_pass) == []
    mismatches = cr.diff_verify_result(expected, actual_fail)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("warnings_contains:")


def test_diff_verify_result_errors_contains_defaults_to_empty_list_when_absent() -> None:
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "errors_contains": ["x"],
    }
    actual = {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    mismatches = cr.diff_verify_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("errors_contains:")


def test_diff_verify_result_missing_errors_warnings_is_mismatch_not_empty_list() -> None:
    """RED for finding 1: an adapter that omits errors/warnings entirely must not
    silently pass just because expected pins them as empty lists — the real
    verifier never omits these fields."""
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "errors": [],
        "warnings": [],
    }
    actual = {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    mismatches = cr.diff_verify_result(expected, actual)
    assert mismatches == [
        "errors: missing from adapter output",
        "warnings: missing from adapter output",
    ]


def test_diff_verify_result_ok_bool_rejects_int_one_as_true() -> None:
    """RED for finding 2: ok: 1 (a JSON number) must not satisfy expected ok:
    true — the real verifier always emits a genuine bool."""
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "ok": True,
    }
    actual = {**expected, "ok": 1}
    mismatches = cr.diff_verify_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("ok:")


@pytest.mark.parametrize("field", cr._VERIFY_REQUIRED_EXACT + cr._VERIFY_CONDITIONAL_EXACT)
def test_diff_verify_result_wrong_value_for_each_exact_field_yields_named_mismatch(
    field: str,
) -> None:
    """Pins finding 4: deleting any member from _VERIFY_REQUIRED_EXACT /
    _VERIFY_CONDITIONAL_EXACT must redden this test."""
    base: dict[str, Any] = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "revocation": "not_revoked",
        "binding": "proven",
        "transparency": "logged",
        "corroboration": "corroborated",
        "manifest_freshness": "fresh",
        "grant": "dormant",
        "grant_trust": "verified",
        "ok": True,
    }
    expected = dict(base)
    actual = dict(base)
    actual[field] = False if field == "ok" else "definitely-a-wrong-value"
    mismatches = cr.diff_verify_result(expected, actual)
    assert any(m.startswith(f"{field}:") for m in mismatches)


def test_diff_verify_result_errors_contains_non_string_item_does_not_crash() -> None:
    """RED for finding 4: an adapter emitting a non-string `errors` item (e.g.
    a stray integer instead of a message string) must yield a mismatch, not
    raise TypeError from the substring-membership test -- adapter output is
    untrusted and may carry any valid-JSON shape."""
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "errors_contains": ["boom"],
    }
    actual = {**expected, "errors": [1]}
    mismatches = cr.diff_verify_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("errors_contains:")


def test_diff_verify_result_warnings_contains_non_string_item_does_not_crash() -> None:
    """RED for finding 4: same guard, `warnings_contains` side."""
    expected = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "warnings_contains": ["dep"],
    }
    actual = {**expected, "warnings": [None]}
    mismatches = cr.diff_verify_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("warnings_contains:")


def test_diff_verify_result_ignores_extra_actual_fields() -> None:
    expected = {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    actual = {
        "signature": "valid",
        "schema": "valid",
        "trust": "authenticated_tls",
        "extra_field_the_corpus_never_pinned": "whatever",
    }
    assert cr.diff_verify_result(expected, actual) == []


# --------------------------------------------------------------------------
# Diff rules — chain leaves
# --------------------------------------------------------------------------


def test_diff_chain_result_passes_on_full_match() -> None:
    expected = {
        "chain_valid": True,
        "link_status": ["valid", "valid"],
        "errors_contains": [],
        "warnings": [],
    }
    actual = {"valid": True, "link_status": ["valid", "valid"], "errors": [], "warnings": []}
    assert cr.diff_chain_result(expected, actual) == []


def test_diff_chain_result_valid_and_link_status_mismatch() -> None:
    expected = {"chain_valid": True, "link_status": ["valid"], "warnings": []}
    actual = {"valid": False, "link_status": ["invalid"], "warnings": []}
    mismatches = cr.diff_chain_result(expected, actual)
    assert any(m.startswith("valid:") for m in mismatches)
    assert any(m.startswith("link_status:") for m in mismatches)


def test_diff_chain_result_valid_missing_from_actual() -> None:
    expected = {"chain_valid": True, "link_status": [], "warnings": []}
    actual = {"link_status": [], "warnings": []}
    mismatches = cr.diff_chain_result(expected, actual)
    assert mismatches[0] == "valid: missing from adapter output"


def test_diff_chain_result_errors_contains_substring_pass_and_fail() -> None:
    expected = {
        "chain_valid": False,
        "link_status": ["invalid"],
        "errors_contains": ["floor"],
        "warnings": [],
    }
    actual_pass = {
        "valid": False,
        "link_status": ["invalid"],
        "errors": ["transferred before floor"],
        "warnings": [],
    }
    actual_fail = {
        "valid": False,
        "link_status": ["invalid"],
        "errors": ["something else"],
        "warnings": [],
    }
    assert cr.diff_chain_result(expected, actual_pass) == []
    mismatches = cr.diff_chain_result(expected, actual_fail)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("errors_contains:")


def test_diff_chain_result_missing_warnings_is_mismatch_not_empty_list() -> None:
    """RED for finding 1 (chain leaf): warnings is always present per the real
    verifier's contract; an adapter that omits it must fail, not default to []."""
    expected = {"chain_valid": True, "link_status": ["valid"], "warnings": []}
    actual = {"valid": True, "link_status": ["valid"]}
    mismatches = cr.diff_chain_result(expected, actual)
    assert mismatches == ["warnings: missing from adapter output"]


def test_diff_chain_result_valid_rejects_int_one_as_true() -> None:
    """RED for finding 2 (chain leaf): valid: 1 (a JSON number) must not
    satisfy expected chain_valid: true."""
    expected = {"chain_valid": True, "link_status": ["valid"], "warnings": []}
    actual = {"valid": 1, "link_status": ["valid"], "warnings": []}
    mismatches = cr.diff_chain_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("valid:")


def test_diff_chain_result_missing_link_status_is_mismatch_not_empty_list() -> None:
    """RED for finding 3: same bug class as the T3 fix for valid/warnings,
    not previously covered for this field -- an adapter that omits
    link_status entirely must not silently pass just because expected pins
    it as an empty list."""
    expected = {"chain_valid": True, "link_status": [], "warnings": []}
    actual = {"valid": True, "warnings": []}
    mismatches = cr.diff_chain_result(expected, actual)
    assert mismatches == ["link_status: missing from adapter output"]


def test_diff_chain_result_errors_contains_non_string_item_does_not_crash() -> None:
    """RED for finding 4: chain-leaf side of the same TypeError-crash guard."""
    expected = {
        "chain_valid": False,
        "link_status": ["invalid"],
        "errors_contains": ["floor"],
        "warnings": [],
    }
    actual = {
        "valid": False,
        "link_status": ["invalid"],
        "errors": [1],
        "warnings": [],
    }
    mismatches = cr.diff_chain_result(expected, actual)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("errors_contains:")


def test_diff_chain_result_warnings_exact_list() -> None:
    expected = {"chain_valid": True, "link_status": ["valid"], "warnings": ["w1"]}
    actual_ok = {"valid": True, "link_status": ["valid"], "warnings": ["w1"]}
    actual_bad = {"valid": True, "link_status": ["valid"], "warnings": []}
    assert cr.diff_chain_result(expected, actual_ok) == []
    mismatches = cr.diff_chain_result(expected, actual_bad)
    assert len(mismatches) == 1
    assert mismatches[0].startswith("warnings:")


# --------------------------------------------------------------------------
# Routing — chain.json leaves vs plain leaves, through run_corpus
# --------------------------------------------------------------------------


def test_run_corpus_routes_chain_and_plain_leaves_to_their_own_rules(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root,
        "10-plain/a",
        {
            "signature": "valid",
            "schema": "valid",
            "trust": "authenticated_tls",
            "ok": True,
            "errors": [],
            "warnings": [],
        },
        adapter_output={
            "signature": "valid",
            "schema": "valid",
            "trust": "authenticated_tls",
            "ok": True,
            "errors": [],
            "warnings": [],
        },
    )
    _write_leaf(
        root,
        "20-chain/a",
        {"chain_valid": True, "link_status": ["valid"], "errors_contains": [], "warnings": []},
        chain=True,
        adapter_output={"valid": True, "link_status": ["valid"], "errors": [], "warnings": []},
    )
    template = cat_adapter_template(tmp_path)
    report = cr.run_corpus(root, template, "v0.2", timeout=5.0)
    assert report.total == 2
    assert report.passed == 2
    assert report.conformant is True
    by_id = {leaf.id: leaf for leaf in report.leaves}
    assert by_id["10-plain/a"].status == "pass"
    assert by_id["20-chain/a"].status == "pass"


def test_run_corpus_a_plain_leaf_diffed_with_wrong_chain_shape_fails(tmp_path: Path) -> None:
    """A chain leaf whose adapter output is missing 'valid' must fail, not crash."""
    root = tmp_path / "vectors"
    _write_leaf(
        root,
        "20-chain/a",
        {"chain_valid": True, "link_status": ["valid"], "warnings": []},
        chain=True,
        adapter_output={"link_status": ["valid"], "errors": [], "warnings": []},
    )
    template = cat_adapter_template(tmp_path)
    report = cr.run_corpus(root, template, "v0.2", timeout=5.0)
    assert report.leaves[0].status == "fail"
    assert report.leaves[0].mismatches == ["valid: missing from adapter output"]


# --------------------------------------------------------------------------
# Adapter failure modes
# --------------------------------------------------------------------------


def test_run_adapter_exit_code_produces_error_outcome(tmp_path: Path) -> None:
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    template = exit_code_adapter_template(tmp_path, code=3)
    outcome = cr.run_adapter(template, leaf, timeout=5.0)
    assert outcome.ok is False
    assert outcome.data is None
    assert outcome.error is not None
    assert outcome.error.startswith("adapter: exit 3")


def test_run_adapter_garbage_stdout_produces_error_outcome(tmp_path: Path) -> None:
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    template = garbage_adapter_template(tmp_path)
    outcome = cr.run_adapter(template, leaf, timeout=5.0)
    assert outcome.ok is False
    assert outcome.error == "adapter: stdout is not valid JSON"


def test_run_adapter_rejects_nan_json_constant(tmp_path: Path) -> None:
    """RED for finding 3: NaN/Infinity are not standard JSON — stdout carrying
    them (even in an ignored extra member) must error, not parse."""
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    body = (
        "import sys\n"
        'sys.stdout.write(\'{"signature": "valid", "schema": "valid", '
        '"trust": "authenticated_tls", "diagnostic": NaN}\')\n'
    )
    template = _write_script(tmp_path, "nan_adapter.py", body) + " {leaf}"
    outcome = cr.run_adapter(template, leaf, timeout=5.0)
    assert outcome.ok is False
    assert outcome.error == "adapter: stdout is not valid JSON"


def test_run_adapter_timeout_produces_error_outcome(tmp_path: Path) -> None:
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    template = sleepy_adapter_template(tmp_path, seconds=5.0)
    outcome = cr.run_adapter(template, leaf, timeout=0.2)
    assert outcome.ok is False
    assert outcome.error is not None
    assert outcome.error.startswith("adapter: timeout after")


@pytest.mark.parametrize("template_fn", [exit_code_adapter_template, garbage_adapter_template])
def test_run_corpus_adapter_failure_yields_error_status_and_not_conformant(
    tmp_path: Path, template_fn: Any
) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root, "01-a", {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    )
    template = template_fn(tmp_path)
    report = cr.run_corpus(root, template, "v0.2", timeout=5.0)
    assert report.total == 1
    assert report.leaves[0].status == "error"
    assert report.conformant is False


def test_run_corpus_timeout_adapter_yields_error_status(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root, "01-a", {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    )
    template = sleepy_adapter_template(tmp_path, seconds=5.0)
    report = cr.run_corpus(root, template, "v0.2", timeout=0.2)
    assert report.leaves[0].status == "error"
    assert report.leaves[0].mismatches[0].startswith("adapter: timeout after")


# --------------------------------------------------------------------------
# Template hygiene
# --------------------------------------------------------------------------


def test_run_adapter_substitutes_leaf_placeholder_with_absolute_path_and_survives_shlex(
    tmp_path: Path,
) -> None:
    leaf = tmp_path / "some-leaf"
    leaf.mkdir()
    template = echo_leaf_adapter_template(tmp_path)
    outcome = cr.run_adapter(template, leaf, timeout=5.0)
    assert outcome.ok is True
    assert outcome.data is not None
    # The quoted multi-word arg survives shlex as ONE token; {leaf} becomes the
    # leaf's resolved absolute path as its own, separate token.
    assert outcome.data["argv"] == ["an arg with spaces", str(leaf.resolve())]


def test_main_returns_2_when_adapter_template_lacks_leaf_placeholder(mini_corpus: Path) -> None:
    rc = cr.main(["--adapter", "echo hi", "--subset", "v0.1", "--vectors", str(mini_corpus)])
    assert rc == 2


def test_main_returns_2_for_unknown_subset(mini_corpus: Path) -> None:
    rc = cr.main(["--adapter", "echo {leaf}", "--subset", "v0.3", "--vectors", str(mini_corpus)])
    assert rc == 2


def test_main_returns_2_for_missing_vectors_dir(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    rc = cr.main(["--adapter", "echo {leaf}", "--subset", "v0.1", "--vectors", str(missing)])
    assert rc == 2


def test_main_returns_2_for_empty_vectors_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty-vectors"
    empty.mkdir()
    rc = cr.main(["--adapter", "echo {leaf}", "--subset", "v0.1", "--vectors", str(empty)])
    assert rc == 2


def test_main_returns_2_when_adapter_argument_missing_entirely(mini_corpus: Path) -> None:
    rc = cr.main(["--subset", "v0.1", "--vectors", str(mini_corpus)])
    assert rc == 2


# --------------------------------------------------------------------------
# Corpus digest
# --------------------------------------------------------------------------


def test_corpus_revision_is_stable_across_two_calls(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root, "01-a", {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    )
    (root / "README.md").write_text("intro text", encoding="utf-8")
    first = cr.corpus_revision(root)
    second = cr.corpus_revision(root)
    assert first == second
    assert re.fullmatch(r"[0-9a-f]{64}", first)


def test_corpus_revision_changes_when_a_leaf_file_changes(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    leaf = _write_leaf(
        root, "01-a", {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    )
    before = cr.corpus_revision(root)
    (leaf / "envelope.json").write_text(
        '{"payload": {}, "signatures": [], "extra": 1}', encoding="utf-8"
    )
    after = cr.corpus_revision(root)
    assert before != after


def test_corpus_revision_unchanged_by_non_leaf_file_edits(tmp_path: Path) -> None:
    """Pins T5's later edit: a non-leaf file (e.g. a README next to the
    groups) changing must NOT shift the digest — only files INSIDE leaf dirs
    count."""
    root = tmp_path / "vectors"
    _write_leaf(
        root, "01-a", {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"}
    )
    (root / "README.md").write_text("v1", encoding="utf-8")
    before = cr.corpus_revision(root)
    (root / "README.md").write_text("a completely different README body", encoding="utf-8")
    after = cr.corpus_revision(root)
    assert before == after


# --------------------------------------------------------------------------
# Report shape
# --------------------------------------------------------------------------


def test_report_shape_exact_member_set_and_sorted_leaves(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root,
        "02-b",
        {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
        adapter_output={"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
    )
    _write_leaf(
        root,
        "01-a",
        {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
        adapter_output={"signature": "invalid", "schema": "valid", "trust": "authenticated_tls"},
    )
    template = cat_adapter_template(tmp_path)
    report = cr.run_corpus(root, template, "v0.2", timeout=5.0)
    report_dict = dataclasses.asdict(report)
    assert set(report_dict) == {
        "runner",
        "corpus_revision",
        "subset",
        "generated_at",
        "adapter",
        "total",
        "passed",
        "failed",
        "conformant",
        "leaves",
    }
    ids = [leaf["id"] for leaf in report_dict["leaves"]]
    assert ids == sorted(ids)
    assert report.total == 2
    assert report.passed == 1
    assert report.failed == 1
    assert report.total == report.passed + report.failed
    assert report.conformant is False
    assert report.runner == cr.RUNNER_NAME
    for leaf in report_dict["leaves"]:
        assert set(leaf) == {"id", "status", "mismatches"}
        assert leaf["status"] in ("pass", "fail", "error")


def test_main_exit_code_0_for_conformant_mini_corpus(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root,
        "01-a",
        {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
        adapter_output={"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
    )
    template = cat_adapter_template(tmp_path)
    rc = cr.main(["--adapter", template, "--subset", "v0.2", "--vectors", str(root)])
    assert rc == 0


def test_main_exit_code_1_for_failing_mini_corpus(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root,
        "01-a",
        {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
        adapter_output={"signature": "invalid", "schema": "valid", "trust": "authenticated_tls"},
    )
    template = cat_adapter_template(tmp_path)
    rc = cr.main(["--adapter", template, "--subset", "v0.2", "--vectors", str(root)])
    assert rc == 1


def test_main_writes_report_file_with_expected_shape(tmp_path: Path) -> None:
    root = tmp_path / "vectors"
    _write_leaf(
        root,
        "01-a",
        {"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
        adapter_output={"signature": "valid", "schema": "valid", "trust": "authenticated_tls"},
    )
    template = cat_adapter_template(tmp_path)
    report_path = tmp_path / "report.json"
    rc = cr.main(
        [
            "--adapter",
            template,
            "--subset",
            "v0.2",
            "--vectors",
            str(root),
            "--report",
            str(report_path),
        ]
    )
    assert rc == 0
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["conformant"] is True
    assert data["total"] == 1
    assert data["subset"] == "v0.2"
    assert re.fullmatch(r"[0-9a-f]{64}", data["corpus_revision"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", data["generated_at"])
