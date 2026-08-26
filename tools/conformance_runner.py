"""The public attest conformance runner — stdlib only, no third-party deps.

This is the public conformance gate: any implementation, in any language,
proves attest conformance by handing this script a one-line adapter command
(a template containing the literal placeholder ``{leaf}``); the runner
invokes that command once per corpus leaf directory, the adapter prints the
leaf's ``VerificationResult``/``ChainAuditResult`` as one JSON object on
stdout, and the runner diffs it against the leaf's ``expected.json`` with the
exact matching rules the in-repo Python/TS conformance harnesses already use.
See ``docs/conformance.md`` for the public process this implements and
``docs/spec/vectors/README.md`` for the corpus contract (leaf directories,
the ``chain.json`` routing, the v0.1/v0.2 subsets) this module replays.

Third parties run this file with a bare ``python3`` — stdlib only
(argparse, json, hashlib, shlex, subprocess, dataclasses, pathlib,
datetime, plus ``re``/``sys`` for CLI plumbing): no ``attest`` import, no
third-party dependency, ever.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RUNNER_NAME = "attest-conformance-runner"

# v0.1 subset rule (mirrors docs/spec/vectors/README.md verbatim): groups
# whose leading integer is <= V01_MAX_GROUP, or in V01_EXTRA_GROUPS, plus the
# extra leaf ids in V01_EXTRA_LEAF_IDS (35i and 37s: v0.1-shaped receipts
# living inside otherwise-v0.2-only groups).
V01_MAX_GROUP = 25
V01_EXTRA_GROUPS = frozenset({29, 31})
V01_EXTRA_LEAF_IDS = frozenset(
    {
        "35-transfer/i-v01-transferable-null-pubkey-ok",
        # 37s: §18.6's conditional is gated on `attest_version: "0.2"`, so a
        # v0.1 receipt carrying `license.preservation_pledge` stays schema-valid
        # and a v0.1-only verifier must reproduce it. Same mechanism as 35i.
        "37-preservation-pledge/s-v01-negative-control",
    }
)

# Diff-rule field sets (see docs/spec/vectors/README.md + tests/test_vectors.py
# / verifiers/ts/test/conformance.test.ts / site/test/conformance.test.ts,
# whose match semantics this module reproduces exactly).
_VERIFY_REQUIRED_EXACT = ("signature", "schema", "trust")
_QUORUM_EXACT = ("valid", "witness_time", "counting_control_groups")
_VERIFY_CONDITIONAL_EXACT = (
    "revocation",
    "binding",
    "transparency",
    "corroboration",
    "manifest_freshness",
    "grant",
    "grant_trust",
    "ok",
)
_REDEMPTION_EXACT = ("verified",)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_VECTORS_ROOT = _REPO_ROOT / "docs" / "spec" / "vectors"
_DEFAULT_TIMEOUT_S = 60.0

_LEADING_INT_RE = re.compile(r"^(\d+)")


# --------------------------------------------------------------------------
# Discovery and subset selection
# --------------------------------------------------------------------------


def find_leaf_dirs(vectors_root: Path) -> list[Path]:
    """Every directory under ``vectors_root`` containing ``expected.json``, sorted."""
    return sorted((p.parent for p in vectors_root.rglob("expected.json")), key=str)


def leaf_id(vectors_root: Path, leaf: Path) -> str:
    """The leaf's posix-style path relative to ``vectors_root`` (e.g. ``21-canon-strict/a-bom``)."""
    return leaf.relative_to(vectors_root).as_posix()


def in_v01_subset(lid: str) -> bool:
    """Whether leaf id ``lid`` belongs to the v0.1 conformance subset.

    Applies the leading-integer group rule (a leaf's top-level directory name
    may carry a letter suffix, e.g. ``14b-...`` -> group 14) plus the single
    pinned extra leaf id (``35i``, a v0.1-shaped receipt living inside the
    otherwise-v0.2-only ``35-transfer`` group).
    """
    if lid in V01_EXTRA_LEAF_IDS:
        return True
    top = lid.split("/", 1)[0]
    match = _LEADING_INT_RE.match(top)
    if match is None:
        return False
    group = int(match.group(1))
    return group <= V01_MAX_GROUP or group in V01_EXTRA_GROUPS


def select_subset(leaves: list[Path], vectors_root: Path, subset: str) -> list[Path]:
    """Filter ``leaves`` down to the named subset (``"v0.1"`` or ``"v0.2"``)."""
    if subset == "v0.2":
        return list(leaves)
    if subset == "v0.1":
        return [leaf for leaf in leaves if in_v01_subset(leaf_id(vectors_root, leaf))]
    raise ValueError(f"unknown subset: {subset!r}")


def corpus_revision(vectors_root: Path) -> str:
    """SHA-256 hex digest over every file INSIDE a leaf directory.

    Deliberately excludes files that sit alongside groups but outside any
    leaf (e.g. this directory's own ``README.md``) — editing prose docs must
    never shift the digest implementations pin in their conformance claims.
    """
    files: list[Path] = []
    for leaf in find_leaf_dirs(vectors_root):
        files.extend(p for p in leaf.rglob("*") if p.is_file())
    files.sort(key=lambda p: p.relative_to(vectors_root).as_posix())

    digest = hashlib.sha256()
    for path in files:
        rel = path.relative_to(vectors_root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Adapter invocation
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AdapterOutcome:
    """The result of invoking the adapter command once against one leaf."""

    ok: bool
    data: dict[str, Any] | None
    error: str | None


def _reject_json_constant(constant: str) -> Any:
    """``parse_constant`` hook that rejects ``NaN``/``Infinity``/``-Infinity``.

    ``json.loads`` accepts these non-standard constants by default; the real
    verifier's output is always standard JSON, so adapter stdout carrying
    them (even in an otherwise-ignored extra member) must be treated as
    invalid JSON, not silently parsed.
    """
    raise ValueError(f"non-standard JSON constant: {constant}")


def run_adapter(template: str, leaf: Path, timeout: float) -> AdapterOutcome:
    """Invoke the adapter command ``template`` against one leaf directory.

    ``template`` is split with :func:`shlex.split`; every argv token has each
    literal ``{leaf}`` occurrence replaced with the leaf's resolved, absolute
    path. Runs with a fixed argv list and ``shell=False`` — never a shell
    string, regardless of what the adapter template itself contains.
    """
    resolved_leaf = str(leaf.resolve())
    argv = [token.replace("{leaf}", resolved_leaf) for token in shlex.split(template)]

    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
            argv, shell=False, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return AdapterOutcome(ok=False, data=None, error=f"adapter: timeout after {timeout:g}s")
    except OSError as exc:
        return AdapterOutcome(ok=False, data=None, error=f"adapter: failed to launch: {exc}")

    if proc.returncode != 0:
        stderr_tail = proc.stderr[-2000:]
        return AdapterOutcome(
            ok=False, data=None, error=f"adapter: exit {proc.returncode}: {stderr_tail}"
        )

    try:
        data = json.loads(proc.stdout, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError):
        return AdapterOutcome(ok=False, data=None, error="adapter: stdout is not valid JSON")
    if not isinstance(data, dict):
        return AdapterOutcome(ok=False, data=None, error="adapter: stdout is not valid JSON")
    return AdapterOutcome(ok=True, data=data, error=None)


# --------------------------------------------------------------------------
# Diff rules
# --------------------------------------------------------------------------


def _fmt(value: Any) -> str:
    return json.dumps(value)


def _exact_eq(exp: object, act: object) -> bool:
    """Type-strict equality for exact-scalar comparisons.

    The real verifier emits genuine Python ``bool``s; ``bool`` is a subclass
    of ``int`` in Python, so plain ``==`` would let a JSON number like ``1``
    pass for ``true``. Requiring identical types (not just equal values)
    closes that gap while leaving str-vs-str and bool-vs-bool comparisons
    unaffected.
    """
    return type(exp) is type(act) and exp == act


def diff_verify_result(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Diff an adapter's verify-leaf output against ``expected.json``.

    Mirrors ``tests/test_vectors.py`` / ``verifiers/ts/test/conformance.test.ts``
    / ``site/test/conformance.test.ts`` exactly: ``_VERIFY_REQUIRED_EXACT`` is
    always compared; each ``_VERIFY_CONDITIONAL_EXACT`` member only when
    present in ``expected``; ``errors``/``warnings`` as exact lists only when
    present in ``expected``; each ``errors_contains``/``warnings_contains``
    entry must be a substring of at least one element of the adapter's
    ``errors``/``warnings`` (an absent list defaults to ``[]``; a non-string
    element in that list simply fails to match, it never raises -- adapter
    output is untrusted). Extra members in ``actual`` are ignored.
    """
    mismatches: list[str] = []

    for field in _VERIFY_REQUIRED_EXACT:
        exp_value = expected.get(field)
        if field not in actual:
            mismatches.append(f"{field}: missing from adapter output")
        elif not _exact_eq(exp_value, actual[field]):
            mismatches.append(f"{field}: expected {_fmt(exp_value)}, got {_fmt(actual[field])}")

    for field in _VERIFY_CONDITIONAL_EXACT:
        if field not in expected:
            continue
        exp_value = expected[field]
        if field not in actual:
            mismatches.append(f"{field}: missing from adapter output")
        elif not _exact_eq(exp_value, actual[field]):
            mismatches.append(f"{field}: expected {_fmt(exp_value)}, got {_fmt(actual[field])}")

    for field in ("errors", "warnings"):
        if field not in expected:
            continue
        exp_list = expected[field]
        if field not in actual:
            mismatches.append(f"{field}: missing from adapter output")
            continue
        act_list = actual[field]
        if act_list != exp_list:
            mismatches.append(f"{field}: expected {_fmt(exp_list)}, got {_fmt(act_list)}")

    for contains_field, base_field in (
        ("errors_contains", "errors"),
        ("warnings_contains", "warnings"),
    ):
        act_list = actual.get(base_field, [])
        for substr in expected.get(contains_field, []):
            if not any(isinstance(item, str) and substr in item for item in act_list):
                mismatches.append(
                    f"{contains_field}: expected a {base_field[:-1]} containing "
                    f"{_fmt(substr)}, got {_fmt(act_list)}"
                )

    return mismatches


def diff_witness_quorum_result(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Diff an adapter's quorum-leaf output against a ``witness-quorum.json`` leaf.

    Mirrors ``tests/test_vectors.py``'s ``test_witness_quorum_vectors`` and its
    TS/site mirrors: all three members of the result are compared EXACTLY and
    unconditionally, with no substring rule and no conditional member. This
    surface has no ``errors``/``warnings`` at all — §11.4's quorum reports
    standing and a time, and says nothing about why a vote did not count — so
    there is nothing here to match loosely.

    ``counting_control_groups`` is compared as an exact, ORDERED list: the
    reference sorts it, so an adapter that emits the same groups in another
    order is not conformant. ``witness_time`` is ``null`` whenever ``valid``
    is false; ``_exact_eq``'s type strictness is what stops a JSON ``0`` from
    passing for ``false`` here, exactly as in the verify diff.
    """
    mismatches: list[str] = []
    for field in _QUORUM_EXACT:
        exp_value = expected.get(field)
        if field not in actual:
            mismatches.append(f"{field}: missing from adapter output")
        elif not _exact_eq(exp_value, actual[field]):
            mismatches.append(f"{field}: expected {_fmt(exp_value)}, got {_fmt(actual[field])}")
    return mismatches


def diff_redemption_result(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Diff an adapter's redemption-leaf output against a ``redemption.json``
    leaf (v0.2 §18.7).

    One boolean, compared exactly. This surface deliberately has no
    ``errors``/``warnings`` and no conditional member: §18.7 forbids a gate
    that fronts the delivery of content from having an error path an attacker
    can tell apart from a refusal, so an adapter that distinguished "malformed"
    from "wrong" would be reporting something the specification says must not
    be observable. ``_exact_eq``'s type strictness is what stops a JSON ``0``
    from passing for ``false``.
    """
    mismatches: list[str] = []
    for field in _REDEMPTION_EXACT:
        exp_value = expected.get(field)
        if field not in actual:
            mismatches.append(f"{field}: missing from adapter output")
        elif not _exact_eq(exp_value, actual[field]):
            mismatches.append(f"{field}: expected {_fmt(exp_value)}, got {_fmt(actual[field])}")
    return mismatches


def diff_chain_result(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Diff an adapter's chain-leaf output against a ``chain.json`` leaf's ``expected.json``.

    Mirrors the chain-audit match rules of the three in-repo harnesses:
    ``expected["chain_valid"]`` <-> ``actual["valid"]`` exact; ``link_status``
    exact list, always present (missing from ``actual`` is a mismatch, never
    defaulted to ``[]``, mirroring the ``valid``/``warnings`` treatment
    below); ``errors_contains`` substring (a non-string element in
    ``actual["errors"]`` simply fails to match, it never raises -- adapter
    output is untrusted); ``warnings`` exact list (always present, never
    conditional).
    """
    mismatches: list[str] = []

    exp_valid = expected.get("chain_valid")
    if "valid" not in actual:
        mismatches.append("valid: missing from adapter output")
    elif not _exact_eq(exp_valid, actual["valid"]):
        mismatches.append(f"valid: expected {_fmt(exp_valid)}, got {_fmt(actual['valid'])}")

    exp_link_status = expected.get("link_status", [])
    if "link_status" not in actual:
        mismatches.append("link_status: missing from adapter output")
    else:
        act_link_status = actual["link_status"]
        if act_link_status != exp_link_status:
            mismatches.append(
                f"link_status: expected {_fmt(exp_link_status)}, got {_fmt(act_link_status)}"
            )

    act_errors = actual.get("errors", [])
    for substr in expected.get("errors_contains", []):
        if not any(isinstance(item, str) and substr in item for item in act_errors):
            mismatches.append(
                f"errors_contains: expected an error containing {_fmt(substr)}, "
                f"got {_fmt(act_errors)}"
            )

    exp_warnings = expected.get("warnings", [])
    if "warnings" not in actual:
        mismatches.append("warnings: missing from adapter output")
    else:
        act_warnings = actual["warnings"]
        if act_warnings != exp_warnings:
            mismatches.append(f"warnings: expected {_fmt(exp_warnings)}, got {_fmt(act_warnings)}")

    return mismatches


# --------------------------------------------------------------------------
# Corpus run + report
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LeafResult:
    """One leaf's outcome: ``status`` is ``"pass"``, ``"fail"``, or ``"error"``."""

    id: str
    status: str
    mismatches: list[str]


@dataclass(frozen=True, slots=True)
class Report:
    """The machine-readable conformance report (see ``--report``)."""

    runner: str
    corpus_revision: str
    subset: str
    generated_at: str
    adapter: str
    total: int
    passed: int
    failed: int
    conformant: bool
    leaves: list[LeafResult]


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_corpus(vectors_root: Path, template: str, subset: str, timeout: float) -> Report:
    """Replay ``subset`` of the corpus under ``vectors_root`` through the adapter ``template``."""
    leaves = select_subset(find_leaf_dirs(vectors_root), vectors_root, subset)
    results: list[LeafResult] = []

    for leaf in leaves:
        lid = leaf_id(vectors_root, leaf)
        expected = json.loads((leaf / "expected.json").read_text(encoding="utf-8"))
        outcome = run_adapter(template, leaf, timeout)

        if not outcome.ok:
            results.append(
                LeafResult(
                    id=lid, status="error", mismatches=[outcome.error or "adapter: unknown error"]
                )
            )
            continue

        actual = outcome.data or {}
        # Routing is by FILE PRESENCE, the contract `chain.json` established
        # and `witness-quorum.json`/`redemption.json` follow: the four surfaces
        # have disjoint result shapes, so the diff rule has to be chosen before
        # comparing.
        if (leaf / "chain.json").exists():
            mismatches = diff_chain_result(expected, actual)
        elif (leaf / "witness-quorum.json").exists():
            mismatches = diff_witness_quorum_result(expected, actual)
        elif (leaf / "redemption.json").exists():
            mismatches = diff_redemption_result(expected, actual)
        else:
            mismatches = diff_verify_result(expected, actual)
        results.append(
            LeafResult(id=lid, status="pass" if not mismatches else "fail", mismatches=mismatches)
        )

    results.sort(key=lambda r: r.id)
    total = len(results)
    passed = sum(1 for r in results if r.status == "pass")
    failed = total - passed

    return Report(
        runner=RUNNER_NAME,
        corpus_revision=corpus_revision(vectors_root),
        subset=subset,
        generated_at=_utc_now_iso(),
        adapter=template,
        total=total,
        passed=passed,
        failed=failed,
        conformant=failed == 0,
        leaves=results,
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="conformance_runner.py",
        description=(
            "Replay the attest conformance corpus through an adapter command and "
            "report pass/fail per leaf. See docs/conformance.md."
        ),
        epilog=(
            "example: python3 tools/conformance_runner.py "
            "--adapter '<command with {leaf}>' --subset v0.1"
        ),
    )
    parser.add_argument(
        "--adapter",
        required=True,
        help="adapter command template; must contain the literal {leaf} placeholder",
    )
    parser.add_argument("--subset", required=True, choices=("v0.1", "v0.2"))
    parser.add_argument("--vectors", type=Path, default=_DEFAULT_VECTORS_ROOT)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT_S)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint. Returns 0 (conformant), 1 (not conformant), 2 (usage error)."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    if "{leaf}" not in args.adapter:
        print("error: --adapter template must contain the {leaf} placeholder", file=sys.stderr)
        return 2

    vectors_root: Path = args.vectors
    if not vectors_root.is_dir():
        print(f"error: --vectors path is not a directory: {vectors_root}", file=sys.stderr)
        return 2

    if not find_leaf_dirs(vectors_root):
        print(f"error: no conformance leaves found under {vectors_root}", file=sys.stderr)
        return 2

    report = run_corpus(vectors_root, args.adapter, args.subset, args.timeout)

    for leaf_result in report.leaves:
        if leaf_result.status != "pass":
            print(f"FAIL {leaf_result.id}")
            for mismatch in leaf_result.mismatches:
                print(f"    {mismatch}")

    if report.conformant:
        print(
            f"CONFORMANT ({report.subset}): {report.passed}/{report.total} leaves pass "
            f"— corpus revision {report.corpus_revision[:12]}"
        )
    else:
        print(
            f"NOT CONFORMANT ({report.subset}): {report.passed}/{report.total} leaves pass "
            f"— {report.failed} failing"
        )

    if args.report is not None:
        report_json = json.dumps(dataclasses.asdict(report), indent=2)
        args.report.write_text(report_json + "\n", encoding="utf-8")

    return 0 if report.conformant else 1


if __name__ == "__main__":
    sys.exit(main())
