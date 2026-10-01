"""Supply-chain properties every workflow must keep, not only the release one.

`tests/test_release_workflow_steps.py` proves that the release workflow's
installer step refuses tampered bytes. That proof covers one file. The same
three scanners were also installed by `ci.yml` and `pages.yml`, through
`curl ... | sh` against a mutable tag, on jobs that run on every push to `main`.
A job on `main` can write the Actions cache that a tag-push job later restores,
so the weakest install in any workflow bounds what the release build can trust.

The properties asserted here:

1. Every step that installs syft, grype and grant is byte-identical (script and
   env) to the release step, so the refusal tests in the release suite cover
   every copy. No step anywhere pipes a download into a shell.
2. Every `actions/checkout` sets `persist-credentials: false`. No job in this
   repository pushes, so a token left in `.git/config` serves only the
   dependency lifecycle scripts that run after the checkout.
3. The release workflow restores no package-manager cache. A cache entry
   written by a `main` job is readable from a tag push, and the release build
   produces the bytes that get published.
4. Every third-party action is pinned to a full commit SHA.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOWS_DIR.glob("*.yml"))
RELEASE = WORKFLOWS_DIR / "release.yml"

_SCANNERS = ("syft", "grype", "grant")


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _steps(path: Path) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for job_name, job in _load(path)["jobs"].items():
        for step in job.get("steps", []):
            out.append((f"{path.name}:{job_name}", step))
    return out


def _code(step: dict[str, Any]) -> str:
    """A step's script without its comment lines, which may quote what they forbid."""
    return "\n".join(
        line for line in str(step.get("run", "")).splitlines() if not line.lstrip().startswith("#")
    )


def _installs_scanners(step: dict[str, Any]) -> bool:
    script = str(step.get("run", ""))
    return all(
        f"anchore/{tool}" in script or f"install_pinned {tool}" in script for tool in _SCANNERS
    )


def _release_install_step() -> dict[str, Any]:
    found = [step for _, step in _steps(RELEASE) if _installs_scanners(step)]
    assert len(found) == 1, f"expected one scanner install step in release.yml, found {len(found)}"
    return found[0]


def test_the_workflow_directory_is_not_empty() -> None:
    # Control: every assertion below iterates over this list.
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "pages.yml", "release.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_step_pipes_a_download_into_a_shell(path: Path) -> None:
    offenders = [
        where
        for where, step in _steps(path)
        if re.search(r"\b(curl|wget)\b[^\n]*\|\s*(ba)?sh\b", _code(step))
    ]
    assert offenders == [], f"a piped installer cannot be checksummed before it runs: {offenders}"


def test_every_scanner_install_is_the_pinned_release_step() -> None:
    reference = _release_install_step()
    copies = [
        (where, step)
        for path in WORKFLOWS
        for where, step in _steps(path)
        if _installs_scanners(step)
    ]
    # Control: the release step itself plus at least the ci and pages copies.
    assert len(copies) >= 3, [where for where, _ in copies]
    for where, step in copies:
        assert step.get("run") == reference["run"], (
            f"{where}: install script differs from release.yml"
        )
        assert step.get("env") == reference["env"], (
            f"{where}: pinned versions/digests differ from release.yml"
        )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_checkout_drops_its_credentials(path: Path) -> None:
    checkouts = [
        (where, step)
        for where, step in _steps(path)
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    leaky = [
        where
        for where, step in checkouts
        if (step.get("with") or {}).get("persist-credentials") is not False
    ]
    assert leaky == [], f"checkout leaves the token in .git/config: {leaky}"


def test_the_release_workflow_restores_no_package_cache() -> None:
    for where, step in _steps(RELEASE):
        uses = str(step.get("uses", ""))
        with_ = step.get("with") or {}
        if uses.startswith("actions/setup-node@"):
            assert "cache" not in with_, f"{where}: setup-node restores an npm cache"
            assert with_.get("package-manager-cache") is False, (
                f"{where}: setup-node may enable a cache on its own"
            )
        if uses.startswith("astral-sh/setup-uv@"):
            assert with_.get("enable-cache") is False, f"{where}: setup-uv cache is not disabled"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path: Path) -> None:
    unpinned = [
        f"{where}: {step['uses']}"
        for where, step in _steps(path)
        if "uses" in step
        and not str(step["uses"]).startswith("./")
        and re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", str(step["uses"])) is None
    ]
    assert unpinned == []
