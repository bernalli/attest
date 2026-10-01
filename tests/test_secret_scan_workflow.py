"""The secret scan over each change: what it must look at, and that it can refuse.

`.github/workflows/secret-scan.yml` runs gitleaks over the commits a push or a
pull request adds. These tests read the workflow rather than copying it:

* the scanner binary is pinned by digest, like every other tool CI downloads;
* the job has read-only permissions, keeps no checkout credentials and
  receives no secrets, so it is safe on a pull request from a fork;
* event fields reach the script through `env:`, never through `${{ }}` inside
  `run:`, where a branch name or a title would become shell source;
* the scan refuses a commit that adds a credential and accepts one that does
  not. Those tests run `.github/scripts/secret-scan.sh` itself against
  throwaway repositories and need a gitleaks binary on PATH; without one they
  are skipped here, and the workflow's own `--selftest` step still runs the
  same negative control in CI before every scan.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import string
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "secret-scan.yml"
SCRIPT = REPO_ROOT / ".github" / "scripts" / "secret-scan.sh"
GITIGNORE = REPO_ROOT / ".gitignore"


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _job() -> dict[str, Any]:
    jobs = _workflow()["jobs"]
    assert list(jobs) == ["gitleaks"]
    return jobs["gitleaks"]  # type: ignore[no-any-return]


def _step(name_fragment: str) -> dict[str, Any]:
    found = [s for s in _job()["steps"] if name_fragment in str(s.get("name", ""))]
    assert len(found) == 1, f"expected one step named like {name_fragment!r}, found {len(found)}"
    return found[0]


def test_the_workflow_runs_on_pushes_and_pull_requests() -> None:
    triggers = _workflow()["on"]  # quoted in the file: a bare `on` reads as True
    assert "push" in triggers and "pull_request" in triggers
    assert "pull_request_target" not in triggers


def test_the_job_is_read_only_and_holds_no_secret() -> None:
    assert _workflow().get("permissions") == {"contents": "read"}
    assert _job().get("permissions") == {"contents": "read"}
    assert "secrets." not in WORKFLOW.read_text(encoding="utf-8")


def test_the_checkout_keeps_no_credentials_and_has_the_history() -> None:
    checkout = next(
        s for s in _job()["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["fetch-depth"] == 0


def test_no_run_step_interpolates_an_expression() -> None:
    for step in _job()["steps"]:
        assert "${{" not in str(step.get("run", "")), step.get("name")


def test_the_steps_run_the_script_and_its_selftest_comes_first() -> None:
    selftest = _step("Self-test")
    scan = _step("Scan the commits")
    assert selftest["run"].strip() == "bash .github/scripts/secret-scan.sh --selftest"
    assert scan["run"].strip() == "bash .github/scripts/secret-scan.sh"
    steps = _job()["steps"]
    assert steps.index(selftest) < steps.index(scan)
    assert set(scan["env"]) == {"SCAN_BASE", "SCAN_HEAD"}


def test_the_scanner_is_pinned_by_digest() -> None:
    env = _step("Install gitleaks")["env"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", str(env["GITLEAKS_VERSION"]))
    assert re.fullmatch(r"[0-9a-f]{64}", str(env["GITLEAKS_SHA256"]))
    assert "sha256sum -c" in str(_step("Install gitleaks")["run"])


def test_credential_files_are_ignored() -> None:
    patterns = set(GITIGNORE.read_text(encoding="utf-8").splitlines())
    assert {"*.seed", "*.pem", "*.key", ".npmrc", ".pypirc", ".netrc"} <= patterns


# --------------------------------------------------------------------------
# The scan step refuses, and accepts, on real repositories
# --------------------------------------------------------------------------
_GITLEAKS = shutil.which("gitleaks")
needs_gitleaks = pytest.mark.skipif(_GITLEAKS is None, reason="gitleaks is not on PATH")


def _git(repo: Path, *args: str) -> str:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(repo),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        ["git", "-C", str(repo), *args],  # noqa: S607 -- git from PATH, as elsewhere here
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()


def _repo_with_change(tmp_path: Path, added: str) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "README").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "README")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "config.txt").write_text(added, encoding="utf-8")
    _git(repo, "add", "config.txt")
    _git(repo, "commit", "-q", "-m", "change")
    return repo, base, _git(repo, "rev-parse", "HEAD")


def _scan(repo: Path, base: str, head: str) -> subprocess.CompletedProcess[str]:
    shutil.copy(REPO_ROOT / ".gitleaks.toml", repo / ".gitleaks.toml")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(repo),
        "SCAN_BASE": base,
        "SCAN_HEAD": head,
    }
    return subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        ["/bin/bash", str(SCRIPT)],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _fake_token() -> str:
    # Built at run time so that no credential-shaped string is ever committed.
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


@needs_gitleaks
def test_the_scan_refuses_a_change_that_adds_a_token(tmp_path: Path) -> None:
    repo, base, head = _repo_with_change(tmp_path, f"token = {_fake_token()}\n")
    result = _scan(repo, base, head)
    assert result.returncode != 0, result.stdout + result.stderr


@needs_gitleaks
def test_the_scan_accepts_a_change_without_one(tmp_path: Path) -> None:
    repo, base, head = _repo_with_change(tmp_path, "colour = blue\n")
    result = _scan(repo, base, head)
    assert result.returncode == 0, result.stdout + result.stderr


@needs_gitleaks
def test_the_scan_without_a_usable_base_still_scans_the_head(tmp_path: Path) -> None:
    repo, _, head = _repo_with_change(tmp_path, f"token = {_fake_token()}\n")
    for base in ("", "0" * 40, "1" * 40):
        result = _scan(repo, base, head)
        assert result.returncode != 0, (base, result.stdout + result.stderr)


@needs_gitleaks
def test_the_selftest_passes(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        ["/bin/bash", str(SCRIPT), "--selftest"],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@needs_gitleaks
def test_the_scan_looks_only_at_the_change(tmp_path: Path) -> None:
    # A token already in the base is outside this change's range: it is the
    # history's problem, not this commit's, and must not fail every later PR.
    repo, base, _ = _repo_with_change(tmp_path, f"token = {_fake_token()}\n")
    (repo / "other.txt").write_text("nothing\n", encoding="utf-8")
    _git(repo, "add", "other.txt")
    _git(repo, "commit", "-q", "-m", "clean")
    head = _git(repo, "rev-parse", "HEAD")
    result = _scan(repo, _git(repo, "rev-parse", "HEAD~1"), head)
    assert result.returncode == 0, result.stdout + result.stderr
    assert base != head
