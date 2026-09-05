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

import collections
import re
import shlex
import shutil
import stat
import subprocess
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


#: The invocation `verify-all` uses for each step. Written as a pattern rather
#: than a constant so the flags are read from the script instead of asserted
#: about it: what this file pins is the BEHAVIOUR those flags produce.
_STEP_SHELL = re.compile(r"\bbash\s+(.*?)\s+-c\s+\"\$command\"")


def _step_shell_flags() -> list[list[str]]:
    return [shlex.split(match) for match in _STEP_SHELL.findall(VERIFY_ALL.read_text())]


def _probe(flags: list[str], script: str) -> int:
    bash = shutil.which("bash") or "bash"
    return subprocess.run([bash, *flags, "-c", script], check=False).returncode  # noqa: S603


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_a_workflow_step_fails_when_any_command_in_a_pipeline_fails(workflow: str) -> None:
    """`shell: bash` is what buys pipefail; the default shell does not have it.

    GitHub runs a step as `bash --noprofile --norc -eo pipefail {0}` when the
    shell is named, and as `bash -e {0}` when it is not (docs.github.com,
    "Workflow syntax for GitHub Actions", jobs.<job_id>.steps[*].shell). The
    difference is pipefail, and it is not cosmetic here: both workflows run
    `curl … | sh -s --`, where `sh` on empty stdin exits 0 and the step stays
    green having installed nothing, and one runs `sha256sum … | tee …`, where
    `tee` succeeds while writing an empty checksum file.
    """
    document = yaml.safe_load((REPO_ROOT / ".github/workflows" / workflow).read_text())
    declared = document.get("defaults", {}).get("run", {}).get("shell")
    assert declared == "bash", (
        f"{workflow} does not declare `defaults: run: shell: bash`, so its steps run "
        f"under `bash -e {{0}}` and a pipeline reports only its last command (got {declared!r})"
    )


def test_verify_all_runs_every_step_under_that_same_shell() -> None:
    """The two halves are one property: the workflows' shell and the script's.

    `verify-all` runs each logical line in its own shell, so `-e` is mostly
    moot — but pipefail is not, and a script that ran the same pipeline under
    a laxer shell than CI would report green on exactly the steps CI is now
    able to fail. Whichever half is missing, this is red.
    """
    call_sites = _step_shell_flags()
    assert call_sites, (
        'no `bash <flags> -c "$command"` step invocation found in tools/verify-all.sh — '
        "the parity between the workflows' shell and the script's cannot be checked"
    )
    for flags in call_sites:
        assert _probe(flags, "true") == 0, f"bash {flags} cannot run a successful command"
        assert _probe(flags, "exit 3") == 3, f"bash {flags} loses a command's exit status"
        assert _probe(flags, "false | true") != 0, (
            f"tools/verify-all.sh runs steps as `bash {' '.join(flags)} -c`, where a failing "
            "command in a pipeline is reported as success; both workflows declare "
            "`shell: bash`, which is `bash --noprofile --norc -eo pipefail {0}`"
        )


def test_the_script_can_actually_be_run() -> None:
    """CONTRIBUTING tells a contributor to type this path; it has to work."""
    assert VERIFY_ALL.exists(), f"{VERIFY_ALL} is missing"
    assert VERIFY_ALL.read_text().startswith("#!"), "no interpreter line"
    assert VERIFY_ALL.stat().st_mode & stat.S_IXUSR, f"{VERIFY_ALL} is not executable"


def _script_executions() -> dict[str, collections.Counter[str]]:
    """(origin -> {command: times}) for every step `verify-all` actually runs.

    `run` and `external` are the only two verbs that execute a workflow step;
    `_skip` records one that did not run, so it is deliberately not counted.
    """
    text = VERIFY_ALL.read_text().replace("\\\n", " ")
    found: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for line in text.splitlines():
        match = re.match(r"^\s*(run|external)\s+(.*)$", line)
        if not match:
            continue
        try:
            parts = shlex.split(match.group(2))
        except ValueError:
            continue
        if len(parts) >= 3:
            found[parts[0]][parts[2]] += 1
    return found


@pytest.mark.parametrize(
    ("origin", "command"),
    [(origin, command) for origin, command, _ in COMMANDS],
    ids=[f"{origin} {command[:60]}" for origin, command, _ in COMMANDS],
)
def test_every_ci_command_runs_at_its_own_origin(origin: str, command: str) -> None:
    """Existence is not parity: a command CI runs in four jobs has to run in four.

    `test_every_ci_command_is_in_verify_all` asks only whether the text appears
    somewhere in the script, so three of the four `npm ci --prefix verifiers/ts`
    executions could be deleted and every assertion stayed green — the workflow
    step vanished from the local run and nothing said so. This binds each
    execution to the job it belongs to and counts it. The comparison is `>=`
    rather than `==` because the script expands one workflow step into mutually
    exclusive branches (the desktop e2e runs with or without `CI=1` depending on
    which Playwright engines are installed), and only one of them ever runs.
    """
    if _provisioning_reason(command) is not None:
        pytest.skip(f"provisioning: {_provisioning_reason(command)}")
    workflow, job, _index = origin.split(":")
    where = f"{workflow}:{job}"
    wanted = sum(
        1
        for other, other_command, _ in COMMANDS
        if other.rsplit(":", 1)[0] == where and other_command == command
    )
    got = _script_executions().get(where, collections.Counter())[command]
    assert got >= wanted, (
        f"{where} runs `{command}` {wanted} time(s) and tools/verify-all.sh runs it "
        f"{got} time(s) at that origin. A step that disappears from the script is a "
        "step the local run stops covering, and membership alone cannot see it."
    )
