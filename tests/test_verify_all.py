"""`tools/verify-all.sh` claims to run what CI runs, and this is what checks the claim.

The script exists because the steps CI runs and the steps a developer runs had
drifted apart: three npm roots with separate scripts, no Makefile, and a
pre-push hook that looks at leaks and nothing else. The steps nobody types
locally are exactly the ones that break — the two end-to-end suites, and the
typecheck that `npm run build --prefix site` performs and `npm test` does not.

A one-off script would close that gap for a week. What keeps it closed is this
test: every `run:` command in `ci.yml` and `pages.yml` must appear in the
script, verbatim, or be named in `PROVISIONING` below with a reason. Add a step
to a workflow without adding it to the script and this turns red in the same
commit that added it.

The comparison is textual on purpose. Flags are the part that drifts —
`--count 500`, `--seed 20260902`, `--fail-on high`, `--frozen` — and a
comparison that matched on the program name alone would let every one of them
change unnoticed.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("ci.yml", "pages.yml")
VERIFY_ALL = REPO_ROOT / "tools" / "verify-all.sh"

#: Lines the script deliberately does not carry, each with the reason. A
#: hosted runner starts from nothing and installs its own toolchain; a
#: developer machine either has those tools or does not, and `verify-all`
#: reports which — it does not download a prover, a scanner or a browser
#: engine behind the operator's back. The last entry is not provisioning: it
#: is the matrix template, which the script expands by reading the same
#: `lemmas:` lists out of `ci.yml`.
PROVISIONING: tuple[tuple[str, str], ...] = (
    (
        r"^curl -sSfL \"https://raw\.githubusercontent\.com/anchore/",
        "installs syft/grype/grant; verify-all uses whatever is on PATH",
    ),
    (
        r"^curl -fsSL -o (maude\.zip|tamarin\.tar\.gz) ",
        "downloads the prover toolchain; verify-all uses whatever is on PATH",
    ),
    (r"^echo \"[0-9a-f]{64} ", "checksum of a download verify-all does not make"),
    (r"^unzip -q maude\.zip ", "unpacks a download verify-all does not make"),
    (r"^tar xzf tamarin\.tar\.gz ", "unpacks a download verify-all does not make"),
    (r"^chmod \+x \"\$HOME", "makes a download executable; verify-all does not download"),
    (r">> \"\$GITHUB_PATH\"$", "extends PATH for later runner steps; no local equivalent"),
    (
        r"npx playwright install --with-deps ",
        "installs browsers and their system packages with apt; verify-all "
        "reports a missing engine and prints this command instead of running it",
    ),
    (
        r"^python3 tools/check_formal\.py formal/attest\.spthy "
        r"--only \"\$\{\{ matrix\.lemmas \}\}\"",
        "matrix template; verify-all expands the shards from the same ci.yml lists",
    ),
)


def _logical_lines(script: str) -> list[str]:
    """Split a shell block into logical commands, whitespace collapsed."""
    joined = script.replace("\\\n", " ")
    lines = []
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(re.sub(r"\s+", " ", line))
    return lines


def _workflow_commands() -> list[tuple[str, str, dict[str, Any]]]:
    """(origin, command, env) for every `run:` line of the two workflows."""
    found: list[tuple[str, str, dict[str, Any]]] = []
    for name in WORKFLOWS:
        document = yaml.safe_load((REPO_ROOT / ".github/workflows" / name).read_text())
        for job, spec in document["jobs"].items():
            for index, step in enumerate(spec.get("steps", [])):
                if "run" not in step:
                    continue
                for command in _logical_lines(step["run"]):
                    found.append((f"{name}:{job}:{index}", command, step.get("env") or {}))
    return found


def _script_text() -> str:
    return "\n".join(_logical_lines(VERIFY_ALL.read_text()))


def _provisioning_reason(command: str) -> str | None:
    for pattern, reason in PROVISIONING:
        if re.search(pattern, command):
            return reason
    return None


COMMANDS = _workflow_commands()


def test_the_workflows_still_have_steps() -> None:
    """A parser that silently finds nothing would pass every test below."""
    assert len(COMMANDS) > 40, f"only {len(COMMANDS)} run-lines parsed out of two workflows"


@pytest.mark.parametrize(
    ("origin", "command"),
    [(origin, command) for origin, command, _ in COMMANDS],
    ids=[f"{origin} {command[:60]}" for origin, command, _ in COMMANDS],
)
def test_every_ci_command_is_in_verify_all(origin: str, command: str) -> None:
    if _provisioning_reason(command) is not None:
        pytest.skip(f"provisioning: {_provisioning_reason(command)}")
    assert command in _script_text(), (
        f"{origin} runs `{command}` and tools/verify-all.sh does not. "
        "Either add the step to the script or, if it provisions a toolchain "
        "rather than verifying anything, add it to PROVISIONING with a reason."
    )


@pytest.mark.parametrize(
    ("origin", "command", "env"),
    [(origin, command, env) for origin, command, env in COMMANDS if env],
    ids=[f"{origin} env" for origin, command, env in COMMANDS if env],
)
def test_step_environment_travels_with_the_command(
    origin: str, command: str, env: dict[str, Any]
) -> None:
    """A command run without the variable its job set is a different command."""
    if _provisioning_reason(command) is not None:
        pytest.skip(f"provisioning: {_provisioning_reason(command)}")
    text = _script_text()
    for name, value in env.items():
        assert f"{name}={value}" in text, (
            f"{origin} runs `{command}` with {name}={value}; tools/verify-all.sh does not set it"
        )


@pytest.mark.parametrize(("pattern", "reason"), PROVISIONING, ids=[p for p, _ in PROVISIONING])
def test_no_exemption_outlives_the_step_it_excuses(pattern: str, reason: str) -> None:
    """An exemption that matches nothing is a hole waiting for the next step."""
    assert any(re.search(pattern, command) for _, command, _ in COMMANDS), (
        f"nothing in ci.yml or pages.yml matches {pattern!r} any more "
        f"({reason}); remove the exemption before it excuses something else"
    )


def test_the_script_can_actually_be_run() -> None:
    """CONTRIBUTING tells a contributor to type this path; it has to work."""
    assert VERIFY_ALL.exists(), f"{VERIFY_ALL} is missing"
    assert VERIFY_ALL.read_text().startswith("#!"), "no interpreter line"
    assert VERIFY_ALL.stat().st_mode & stat.S_IXUSR, f"{VERIFY_ALL} is not executable"
