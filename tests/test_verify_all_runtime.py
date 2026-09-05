"""Exercise verify-all's outcome contract with deterministic external commands."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EARLY = "npm run build --prefix verifiers/ts"
E2E = "npm run e2e --prefix desktop"
LATE = "sha256sum desktop/dist/attest-verifier.html | tee desktop/dist/attest-verifier.html.sha256"
STUB = r"""#!/bin/bash
if [ "${0##*/}" = node ]; then
  case " ${ABSENT:-} " in *" ${PWD##*/}:${!#} "*) exit 1;; esac
  exit 0
fi
if [ "${0##*/}" != bash ]; then exit 0; fi
printf '%s\n' "${!#}" >> "$TRACE"
if [ "${!#}" = "${FAIL_COMMAND:-}" ]; then exit "${FAIL_RC:-7}"; fi
exit 0
"""


def probe(
    tmp_path: Path,
    mask: int = 4,
    site_missing: bool = False,
    fail: str = "",
    quick: bool = False,
    rc: int = 7,
) -> tuple[subprocess.CompletedProcess[str], list[tuple[str, str, str]], list[str]]:
    """Copy the real script; replace commands, never its state transitions."""
    root = tmp_path / "repo"
    for rel in ("tools", ".github/workflows", "site", "desktop", "verifiers/ts", "tmp"):
        (root / rel).mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "tools/verify-all.sh", root / "tools/verify-all.sh")
    shutil.copy2(ROOT / ".github/workflows/ci.yml", root / ".github/workflows/ci.yml")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name in (
        "bash",
        "node",
        "npm",
        "uv",
        "python3",
        "uvx",
        "syft",
        "grype",
        "grant",
        "maude",
        "tamarin-prover",
    ):
        p = binaries / name
        p.write_text(STUB)
        p.chmod(0o755)
    for name in ("dirname", "mktemp", "rm", "date", "awk", "env"):
        executable = shutil.which(name)
        assert executable, f"test prerequisite missing: {name}"
        (binaries / name).symlink_to(executable)
    absent = [
        f"desktop:{engine}"
        for bit, engine in enumerate(("chromium", "firefox", "webkit"))
        if mask & (1 << bit)
    ]
    if site_missing:
        absent.append("site:chromium")
    trace = tmp_path / "trace"
    trace.write_text("")
    env = {
        "PATH": str(binaries),
        "TMPDIR": str(root / "tmp"),
        "ABSENT": " ".join(absent),
        "TRACE": str(trace),
        "FAIL_COMMAND": fail,
        "FAIL_RC": str(rc),
    }
    result = subprocess.run(  # noqa: S603 -- isolated script and controlled command stubs
        ["/bin/bash", str(root / "tools/verify-all.sh"), *(["--quick"] if quick else [])],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    rows = re.findall(
        r"^(OK|FAIL|PARTIAL|SKIPPED|NOT RUN)\s+(\S+)\s+\d+\s+(.+)$",
        result.stdout,
        re.MULTILINE,
    )
    assert rows, result.stdout + result.stderr
    return result, rows, trace.read_text().splitlines()


def assert_report(
    result: subprocess.CompletedProcess[str], rows: list[tuple[str, str, str]]
) -> None:
    counts = {
        state: sum(row[0] == state for row in rows) for state in ("FAIL", "SKIPPED", "PARTIAL")
    }
    tally = re.search(r"(\d+) steps, (\d+) skipped, (\d+) partial", result.stdout)
    assert tally, result.stdout
    assert tuple(map(int, tally.groups())) == (len(rows), counts["SKIPPED"], counts["PARTIAL"])
    expected = 1 if counts["FAIL"] else 2 if counts["SKIPPED"] or counts["PARTIAL"] else 0
    assert result.returncode == expected, result.stdout
    if expected:
        assert "OK — every step both workflows run passed here." not in result.stdout
    after_failure = False
    for state, origin, _ in rows:
        if after_failure and origin != "verify-all:restore":
            assert state == "NOT RUN", rows
        after_failure |= state == "FAIL"


@pytest.mark.parametrize("mask", range(8))
@pytest.mark.parametrize("site_missing", (False, True))
@pytest.mark.parametrize("fail", ("", EARLY, E2E, LATE))
@pytest.mark.parametrize("quick", (False, True))
def test_state_model(tmp_path: Path, mask: int, site_missing: bool, fail: str, quick: bool) -> None:
    result, rows, trace = probe(tmp_path, mask, site_missing, fail, quick)
    assert_report(result, rows)
    available = not (mask & 3)
    if fail == EARLY:
        expected = "NOT RUN"
    elif not available:
        expected = "SKIPPED"
    elif fail == E2E:
        expected = "FAIL"
    elif mask & 4:
        expected = "PARTIAL"
    else:
        expected = "OK"
    assert [
        state for state, origin, command in rows if origin == "pages.yml:desktop" and command == E2E
    ] == [expected]
    assert trace.count(E2E) == int(expected in ("OK", "PARTIAL", "FAIL"))
    failed = fail == EARLY or fail == LATE or (fail == E2E and available)
    incomplete = bool(mask or site_missing or quick)
    assert result.returncode == (1 if failed else 2 if incomplete else 0)


def test_partial_contract(tmp_path: Path) -> None:
    result, rows, trace = probe(tmp_path)
    assert_report(result, rows)
    assert result.returncode == 2
    assert ("PARTIAL", "pages.yml:desktop", E2E) in rows
    assert trace.count(E2E) == 1


@pytest.mark.parametrize("rc", (1, 2, 64, 127, 137, 255))
def test_nonzero_child_status_is_failure_not_partial(tmp_path: Path, rc: int) -> None:
    result, rows, _ = probe(tmp_path, fail=E2E, rc=rc)
    assert_report(result, rows)
    assert result.returncode == 1
    assert ("FAIL", "pages.yml:desktop", E2E) in rows
    assert not any(state == "PARTIAL" for state, _, _ in rows)
