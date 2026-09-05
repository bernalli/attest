"""`tools/verify-all.sh` claims to run what CI runs, and this is what checks the claim.

The script exists because the steps CI runs and the steps a developer runs had
drifted apart: three npm roots with separate scripts, no Makefile, and a
pre-push hook that looks at leaks and nothing else. The steps nobody types
locally are exactly the ones that break — the two end-to-end suites, and the
typecheck that `npm run build --prefix site` performs and `npm test` does not.

A one-off script would close that gap for a week. What keeps it closed is this
file.

HOW THE CLAIM IS CHECKED, AND WHY NOT BY READING THE SCRIPT. An earlier version
of this file answered "does the script run what CI runs?" by counting `run` and
`external` lines in the script's SOURCE TEXT. A text count cannot tell a line
that executes from a line that does not, and six mutations proved it: replacing
the desktop end-to-end invocation with `:` left every assertion green while the
whole script, with every prerequisite present, still printed `OK — every step
both workflows run passed here` having never launched that suite; moving that
same line to another job's name was equally invisible; so were hiding an install
behind `if false; then`, duplicating a workflow step, moving a step's
environment variable onto a different command, and deleting the loop that
expands the formal shards. Every one of those breaks the property the script
promises while satisfying a count of occurrences, because occurrences in two
mutually exclusive branches read as two executions of one step.

So the script is RUN instead of read. `_trace` executes the real
`tools/verify-all.sh` with `/bin/bash` in a throwaway copy of the tree, with
every workflow command replaced by a stub on PATH and every prerequisite
declared present, and reads back what the script itself reports having
executed: the origin it attributes the step to, the environment it ran it with,
the command, and the order. Branch selection, `run`, `external`, `_skip`, the
formal expansion and the report are the script's own code. That trace is the
subject of every parity assertion below, so a step that does not execute cannot
satisfy one, whichever branch its text sits in.

The comparison of the command itself stays textual on purpose. Flags are the
part that drifts — `--count 500`, `--seed 20260902`, `--fail-on high`,
`--frozen` — and a comparison that matched on the program name alone would let
every one of them change unnoticed.

WHAT THIS DOES NOT CHECK. Two ways of changing what the script does are green
here, both measured rather than assumed, and both left green knowingly. The
first is the working directory: making the plain branch of `run` `cd` somewhere
else first sends every step whose call site passes no environment assignment
into a temporary directory, and the run still exits 0. The second is a
mandatory step demoted to an optional
one — turning `run pages.yml:test - "npm run build --prefix site"` into an
`external` guarded by a tool keeps it running wherever that tool is installed
and turns it into a SKIPPED with exit 2 wherever it is not, which is a
difference the report states rather than hides, but nothing here refuses the
change.

Beyond those two, the harness replaces commands, so it measures orchestration
and not the work; and instrumentation is in principle detectable — a line that
branched on `PATH` or on one of the `VERIFY_ALL_TEST_*` variables the stubs
read would run one way here and another on a developer's machine. These
assertions defend against drift, not against a script written to deceive them.
"""

from __future__ import annotations

import dataclasses
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

DESKTOP_E2E = "npm run e2e --prefix desktop"
SITE_E2E = "npm run e2e --prefix site"
PYTEST = "uv run --frozen pytest -q"
RUFF = "uv run --frozen ruff check ."
EARLY_STEP = "npm run build --prefix verifiers/ts"

#: Lines the script deliberately does not carry, each with the reason. A
#: hosted runner starts from nothing and installs its own toolchain; a
#: developer machine either has those tools or does not, and `verify-all`
#: reports which — it does not download a prover, a scanner or a browser
#: engine behind the operator's back. The last entry is not provisioning: it
#: is the matrix template, which the script expands by reading the same
#: `lemmas:` lists out of `ci.yml`. That expansion is not taken on trust —
#: `test_the_formal_matrix_is_expanded_shard_by_shard` executes it and
#: compares every shard with this file.
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


def _job(origin: str) -> str:
    """`ci.yml:python:7` is step 7 of the job `ci.yml:python`."""
    return origin.rsplit(":", 1)[0]


COMMANDS = _workflow_commands()


def _formal_shard_commands() -> tuple[tuple[str, str], ...]:
    """(origin, command) for every shard `ci.yml`'s formal matrix expands into.

    The workflow states the proof step once and lets the matrix run it five
    times; `verify-all` reads the same `lemmas:` lists out of `ci.yml` and runs
    the five itself. Expanding the template here is what makes those two
    expansions comparable — the alternative is exempting the template and
    checking nothing, which is what let the whole loop be deleted unnoticed.
    """
    document = yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text())
    job = document["jobs"]["formal"]
    templates = [
        command
        for step in job["steps"]
        if "run" in step
        for command in _logical_lines(step["run"])
        if "${{ matrix." in command
    ]
    assert len(templates) == 1, f"expected one matrix-templated run line, found {templates}"
    expanded: list[tuple[str, str]] = []
    for entry in job["strategy"]["matrix"]["include"]:
        command = templates[0]
        for key, value in entry.items():
            command = command.replace(f"${{{{ matrix.{key} }}}}", str(value))
        assert "${{" not in command, f"unsubstituted matrix reference in {command!r}"
        expanded.append((f"ci.yml:formal({entry['shard']})", command))
    return tuple(expanded)


FORMAL_SHARDS = _formal_shard_commands()

#: The only steps `verify-all` runs that no workflow runs: putting back the dev
#: toolchain the SBOM steps strip. Listed by name rather than exempted by origin
#: prefix, because an exemption keyed on `verify-all:` alone is one an invented
#: step can put on itself — measured green before this list existed.
LOCAL_HOUSEKEEPING: tuple[tuple[str, str], ...] = (
    ("verify-all:restore", "uv sync --locked --extra dev --all-packages"),
    ("verify-all:restore", "npm ci --prefix verifiers/ts"),
    ("verify-all:restore", "npm ci --prefix desktop"),
)

#: A hosted runner exports these to every step, so the script setting them is
#: not drift when the workflow does not name them: `CI` is what tells a suite it
#: runs unattended, `RUNNER_TEMP` is the scratch directory the Internet-Draft
#: step names. A name outside these two lists and outside the step's own `env:`
#: is read straight out of the child process, so where the script added it makes
#: no difference — at the top, or in either branch of `run`. Three mutations of
#: exactly those shapes were green while this assertion read the printed line.
RUNNER_PROVIDED = frozenset({"CI", "RUNNER_TEMP"})

#: What the harness itself puts in the environment, plus what bash exports on
#: its own. None of it comes from `verify-all.sh`, so none of it is drift.
#: Enumerated rather than inferred from a reference step, because a variable the
#: script exports once at the top reaches every step and would sit in any
#: inferred baseline — which is the mutation this list exists to leave visible.
HARNESS_PROVIDED = frozenset(
    {
        "PATH",
        "TMPDIR",
        "VERIFY_ALL_TEST_ABSENT",
        "VERIFY_ALL_TEST_TRACE",
        "VERIFY_ALL_TEST_FAIL",
        "PWD",
        "OLDPWD",
        "SHLVL",
    }
)


def test_the_workflows_still_have_steps() -> None:
    """A parser that silently finds nothing would pass every test below."""
    assert len(COMMANDS) > 40, f"only {len(COMMANDS)} run-lines parsed out of two workflows"


@pytest.mark.parametrize(
    ("origin", "command"),
    [(origin, command) for origin, command, _ in COMMANDS],
    ids=[f"{origin} {command[:60]}" for origin, command, _ in COMMANDS],
)
def test_every_ci_command_is_in_verify_all(origin: str, command: str) -> None:
    """Membership: necessary, not sufficient, and deliberately kept anyway.

    This reads the script's text, so it cannot tell a line that runs from a
    line that does not — `test_every_workflow_command_runs_at_its_own_job` is
    the assertion that decides parity. What this one buys is a first, blunt
    signal that needs no harness: add a step to a workflow and forget the
    script, and this names the step before anything has to be executed.
    """
    if _provisioning_reason(command) is not None:
        pytest.skip(f"provisioning: {_provisioning_reason(command)}")
    assert command in _script_text(), (
        f"{origin} runs `{command}` and tools/verify-all.sh does not. "
        "Either add the step to the script or, if it provisions a toolchain "
        "rather than verifying anything, add it to PROVISIONING with a reason."
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


# --------------------------------------------------------------- the trace
# What the script did, taken from the script, in one scenario at a time.

#: Replaced on PATH. `bash` is the one that matters: every workflow step is
#: run as `bash … -c "$command"`, so a stub records the step instead of doing
#: it. The rest exist so `command -v` finds them and the script takes the
#: branch it takes on a machine that has the whole toolchain.
_STUBBED = (
    "bash",
    "node",
    "npm",
    "uv",
    "uvx",
    "python3",
    "syft",
    "grype",
    "grant",
    "maude",
    "tamarin-prover",
)
#: Called by the script itself rather than by a workflow step, so they stay real.
_REAL = ("dirname", "mktemp", "rm", "date", "awk", "env")

_STUB = r"""#!/bin/bash
# `node` answers the Playwright engine probe. VERIFY_ALL_TEST_ABSENT lists the
# `<npm root>:<engine>` pairs to report as missing; anything else is installed.
if [ "${0##*/}" = node ]; then
  case " ${VERIFY_ALL_TEST_ABSENT:-} " in *" ${PWD##*/}:${!#} "*) exit 1;; esac
  exit 0
fi
if [ "${0##*/}" != bash ]; then exit 0; fi
# One line per step the script actually launched, carrying the environment the
# step's own process received — not the one the script printed. The last field
# is every variable name in that process: a variable the script exports at the
# top, or adds inside `run`, reaches the step without ever appearing in the line
# the script prints, and this is what makes it visible.
_exported=""
for _name in $(compgen -e); do _exported="$_exported $_name"; done
printf '%s\t%s\t%s\t%s\n' "${!#}" "CI=${CI-<unset>}" \
  "ATTEST_CI_REQUIRED=${ATTEST_CI_REQUIRED-<unset>}" "$_exported" \
  >> "$VERIFY_ALL_TEST_TRACE"
if [ "${!#}" = "${VERIFY_ALL_TEST_FAIL:-}" ]; then exit 9; fi
exit 0
"""

#: `=== <origin>  <env…> <command>`, printed by `run` before it launches a step.
_STARTED = re.compile(r"^=== (\S+) {2}(.*)$", re.MULTILINE)
#: `--- SKIP <origin>  <command>`, printed by `_skip` for a step that did not run.
_NOT_STARTED = re.compile(r"^--- SKIP (\S+) {2}(.*)$", re.MULTILINE)
#: A row of the final table: outcome, origin, milliseconds, command.
_REPORTED = re.compile(r"^(OK|FAIL|PARTIAL|SKIPPED|NOT RUN)\s+(\S+)\s+\d+\s+(.+)$", re.MULTILINE)
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _split_environment(shown: str) -> tuple[tuple[str, ...], str]:
    """`CI=1 npm run e2e --prefix desktop` -> `(("CI=1",), "npm run e2e …")`."""
    assignments: list[str] = []
    rest = shown
    while True:
        head, separator, tail = rest.partition(" ")
        if not separator or not _ASSIGNMENT.match(head):
            return tuple(assignments), rest
        assignments.append(head)
        rest = tail


@dataclasses.dataclass(frozen=True)
class Execution:
    """One workflow step the script actually launched."""

    origin: str
    env: tuple[str, ...]
    command: str


@dataclasses.dataclass(frozen=True)
class Trace:
    """Everything one run of the script says about itself."""

    root: Path
    returncode: int
    stdout: str
    #: Steps the script launched, in the order it launched them.
    executed: tuple[Execution, ...]
    #: (origin, command) for steps it reported as not run.
    not_started: tuple[tuple[str, str], ...]
    #: (outcome, origin, command) rows of the final table.
    reported: tuple[tuple[str, str, str], ...]
    #: (command, `CI=…`, `ATTEST_CI_REQUIRED=…`) as each child process saw it.
    child_environment: tuple[tuple[str, str, str], ...]
    #: (command, every variable name) as each child process saw it, same order.
    child_variables: tuple[tuple[str, frozenset[str]], ...]

    def count(self, origin: str, command: str) -> int:
        return sum(1 for run in self.executed if run.origin == origin and run.command == command)

    def commands_at(self, origin: str) -> list[str]:
        return [run.command for run in self.executed if run.origin == origin]

    def runs_of(self, command: str) -> list[Execution]:
        return [run for run in self.executed if run.command == command]

    def outcomes_of(self, command: str) -> list[tuple[str, str]]:
        return [(state, origin) for state, origin, ran in self.reported if ran == command]

    def environment_of(self, command: str) -> list[tuple[str, str]]:
        return [(ci, required) for ran, ci, required in self.child_environment if ran == command]


def _trace(
    workspace: Path,
    *,
    absent: tuple[str, ...] = (),
    fail: str = "",
    inherited: dict[str, str] | None = None,
    seed: tuple[str, ...] = (),
) -> Trace:
    """Run the real script against stub commands and read back what it ran.

    `absent` names `<npm root>:<engine>` pairs the Playwright probe should
    report as missing; everything else — every scanner, the prover, every
    browser — is present, so the script takes the branch it takes when a
    machine can run the whole of both workflows.
    """
    root = workspace / "repo"
    for relative in ("tools", ".github/workflows", "site", "desktop", "verifiers/ts", "tmp"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    shutil.copy2(VERIFY_ALL, root / "tools/verify-all.sh")
    for name in WORKFLOWS:
        shutil.copy2(REPO_ROOT / ".github/workflows" / name, root / ".github/workflows" / name)
    for relative in seed:
        (root / relative).write_text(SEEDED_CONTENT)

    binaries = workspace / "bin"
    binaries.mkdir(exist_ok=True)
    for name in _STUBBED:
        stub = binaries / name
        stub.write_text(_STUB)
        stub.chmod(0o755)
    for name in _REAL:
        executable = shutil.which(name)
        assert executable, f"test prerequisite missing: {name}"
        (binaries / name).symlink_to(executable)

    recorded = workspace / "child-environment.tsv"
    recorded.write_text("")
    environment = {
        "PATH": str(binaries),
        "TMPDIR": str(root / "tmp"),
        "VERIFY_ALL_TEST_ABSENT": " ".join(absent),
        "VERIFY_ALL_TEST_TRACE": str(recorded),
        "VERIFY_ALL_TEST_FAIL": fail,
        **(inherited or {}),
    }
    result = subprocess.run(  # noqa: S603 -- isolated copy of the script, stubbed commands
        ["/bin/bash", str(root / "tools/verify-all.sh")],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    executed = []
    for origin, shown in _STARTED.findall(result.stdout):
        env, command = _split_environment(shown)
        executed.append(Execution(origin=origin, env=env, command=command))
    rows = [line.split("\t") for line in recorded.read_text().splitlines()]
    child = tuple((row[0], row[1], row[2]) for row in rows)
    variables = tuple((row[0], frozenset(row[3].split())) for row in rows)
    return Trace(
        root=root,
        returncode=result.returncode,
        stdout=result.stdout,
        executed=tuple(executed),
        not_started=tuple(_NOT_STARTED.findall(result.stdout)),
        reported=tuple(_REPORTED.findall(result.stdout)),
        child_environment=child,
        child_variables=variables,
    )


SEEDED_CONTENT = "an artifact of the operator's that predates this run\n"


@pytest.fixture(scope="session")
def complete_run(tmp_path_factory: pytest.TempPathFactory) -> Trace:
    """Every prerequisite present: the run that has to cover the whole of both workflows."""
    return _trace(tmp_path_factory.mktemp("complete"))


@pytest.fixture(scope="session")
def webkit_missing_run(tmp_path_factory: pytest.TempPathFactory) -> Trace:
    """Chromium and Firefox installed, WebKit not: the reduced desktop path."""
    return _trace(tmp_path_factory.mktemp("webkit-missing"), absent=("desktop:webkit",))


@pytest.fixture(scope="session")
def webkit_missing_under_ci_run(tmp_path_factory: pytest.TempPathFactory) -> Trace:
    """The same, launched from a shell that already exports `CI=1`."""
    return _trace(
        tmp_path_factory.mktemp("webkit-missing-ci"),
        absent=("desktop:webkit",),
        inherited={"CI": "1"},
    )


@pytest.fixture(scope="session")
def engine_missing_run(tmp_path_factory: pytest.TempPathFactory) -> Trace:
    """Chromium absent: the desktop suite cannot run at all, reduced or otherwise."""
    return _trace(tmp_path_factory.mktemp("engine-missing"), absent=("desktop:chromium",))


@pytest.fixture(scope="session")
def site_engine_missing_run(tmp_path_factory: pytest.TempPathFactory) -> Trace:
    """The site suite's only browser absent: its one branch is the skip."""
    return _trace(tmp_path_factory.mktemp("site-engine-missing"), absent=("site:chromium",))


#: A scanner step, reached only after `uv sync --locked` has already stripped
#: the tree to runtime dependencies. Failing here is the case the restore exists
#: for, and the only one in which `run` would otherwise refuse to launch it.
SCAN_STEP = "syft dir:.venv -o cyclonedx-json=sbom-python.cdx.json"


@pytest.fixture(scope="session")
def failed_scan_run(tmp_path_factory: pytest.TempPathFactory) -> Trace:
    """A scan fails after the SBOM steps have stripped the dev toolchain out."""
    return _trace(tmp_path_factory.mktemp("failed-scan"), fail=SCAN_STEP)


def test_a_failure_after_the_environment_was_stripped_still_restores_it(
    failed_scan_run: Trace,
) -> None:
    """The restore has to outlive the failure it exists for.

    `run` refuses to launch anything once a step has failed, which is right for
    a verification step and wrong for this one: the run that most needs the dev
    toolchain put back is exactly the run that failed while it was stripped. So
    `restore` clears the flag for its own duration and puts it back — and the
    exit status is still 1, because a restore cannot un-fail a step.
    """
    assert failed_scan_run.returncode == 1, failed_scan_run.stdout
    assert ("FAIL", "ci.yml:supply-chain", SCAN_STEP) in failed_scan_run.reported
    assert [
        (state, command)
        for state, origin, command in failed_scan_run.reported
        if origin == "verify-all:restore"
    ] == [
        ("OK", "uv sync --locked --extra dev --all-packages"),
        ("OK", "npm ci --prefix verifiers/ts"),
    ], failed_scan_run.stdout


def test_the_complete_run_really_is_complete(complete_run: Trace) -> None:
    """Anchor for every parity assertion: they all read this one run.

    A harness that failed to start the script, or a parser that matched
    nothing, would make the assertions below vacuous instead of red. So this
    pins the shape of the run they read: it executed a workflow's worth of
    steps, skipped none of them, and reached the exit status the script
    reserves for a tree it fully verified.
    """
    assert complete_run.executed, complete_run.stdout
    assert len(complete_run.executed) > 40, (
        f"only {len(complete_run.executed)} steps executed:\n{complete_run.stdout}"
    )
    assert not complete_run.not_started, complete_run.not_started
    assert complete_run.returncode == 0, complete_run.stdout
    assert "OK — every step both workflows run passed here." in complete_run.stdout
    assert [(state, origin) for state, origin, _ in complete_run.reported if state != "OK"] == []
    assert len(complete_run.reported) == len(complete_run.executed)


def test_the_report_and_the_child_processes_agree(complete_run: Trace) -> None:
    """What the script says it launched is what a process actually received.

    The trace has two independent halves — the script's own stdout, and a line
    written by each child as it started — and this is the seam between them. It
    is what stops `run` printing one command and launching another.
    """
    assert [run.command for run in complete_run.executed] == [
        command for command, _, _ in complete_run.child_environment
    ]


@pytest.mark.parametrize(
    ("origin", "command"),
    [(origin, command) for origin, command, _ in COMMANDS],
    ids=[f"{origin} {command[:60]}" for origin, command, _ in COMMANDS],
)
def test_every_workflow_command_runs_at_its_own_job(
    origin: str, command: str, complete_run: Trace
) -> None:
    """Existence is not parity: a command CI runs in four jobs has to run in four.

    Counted on the trace, so the count is of EXECUTIONS. Text could not
    distinguish the two mutually exclusive desktop branches from two runs of
    one step, which is why the comparison here is `==` where a count of source
    lines had to settle for `>=` and let a deleted step hide behind its
    alternative.
    """
    if _provisioning_reason(command) is not None:
        pytest.skip(f"provisioning: {_provisioning_reason(command)}")
    where = _job(origin)
    wanted = sum(
        1
        for other, other_command, _ in COMMANDS
        if _job(other) == where and other_command == command
    )
    got = complete_run.count(where, command)
    assert got == wanted, (
        f"{where} runs `{command}` {wanted} time(s); with every prerequisite present "
        f"tools/verify-all.sh executed it {got} time(s) at that origin. "
        f"What it did execute there:\n  " + "\n  ".join(complete_run.commands_at(where))
    )


@pytest.mark.parametrize(
    ("origin", "command", "env"),
    [(origin, command, env) for origin, command, env in COMMANDS if env],
    ids=[f"{origin} env" for origin, command, env in COMMANDS if env],
)
def test_the_environment_of_a_step_travels_with_that_step(
    origin: str, command: str, env: dict[str, Any], complete_run: Trace
) -> None:
    """A command run without the variable its job set is a different command.

    Bound to the execution rather than looked for in the file: the variable has
    to be on THIS step, at THIS origin. Searching the script for the text
    `NAME=value` is satisfied by the assignment having moved to any other
    command in any other job.
    """
    if _provisioning_reason(command) is not None:
        pytest.skip(f"provisioning: {_provisioning_reason(command)}")
    where = _job(origin)
    carried = [run.env for run in complete_run.executed if run.origin == where]
    ran = [
        run.env for run in complete_run.executed if run.origin == where and run.command == command
    ]
    assert ran, f"{where} does not execute `{command}` at all (see the parity test above)"
    for name, value in env.items():
        assert all(f"{name}={value}" in env_of_run for env_of_run in ran), (
            f"{origin} runs `{command}` with {name}={value}; tools/verify-all.sh executed it "
            f"with {ran}. Environments seen at {where}: {carried}"
        )


def test_the_script_runs_nothing_the_workflows_do_not(complete_run: Trace) -> None:
    """The other direction: a local step CI does not have is not parity either.

    Without this, moving a step to the wrong job is only half visible — the job
    it left turns red, the job it arrived at stays silent — and a command
    invented locally is never seen at all. The script's own housekeeping —
    restoring the dev toolchain the SBOM steps strip — is allowed by name in
    `LOCAL_HOUSEKEEPING`, not by its origin: an exemption on the origin alone
    is one any invented step can claim by naming itself `verify-all:something`.
    """
    allowed = {(_job(origin), command) for origin, command, _ in COMMANDS}
    allowed |= set(FORMAL_SHARDS)
    allowed |= set(LOCAL_HOUSEKEEPING)
    strangers = [run for run in complete_run.executed if (run.origin, run.command) not in allowed]
    assert not strangers, (
        "tools/verify-all.sh executed steps no workflow job runs at that origin:\n  "
        + "\n  ".join(f"{run.origin}  {run.command}" for run in strangers)
    )


def test_the_only_local_steps_are_the_restores(complete_run: Trace) -> None:
    """Same list, the other way round: the housekeeping has to still happen.

    `test_the_script_runs_nothing_the_workflows_do_not` allows these three; this
    requires them. Without it, deleting a restore is invisible — a command whose
    job is to verify the tree leaves it stripped to runtime dependencies.
    """
    assert [
        (run.origin, run.command)
        for run in complete_run.executed
        if run.origin.startswith("verify-all:")
    ] == list(LOCAL_HOUSEKEEPING), complete_run.stdout


def test_no_step_carries_an_environment_variable_the_workflow_does_not(
    complete_run: Trace,
) -> None:
    """The other direction of the environment: extra is drift too.

    `test_the_environment_of_a_step_travels_with_that_step` asks whether every
    variable the workflow declares reached the step. The variable to catch here
    is the opposite one: handed to a step by the SCRIPT and never set by CI.
    `PYTEST_ADDOPTS=--ignore=...` makes the local run measure less than CI while
    every step still reports OK and the whole run still exits 0.

    Read in the child process, not in the line the script prints. An earlier
    version of this assertion read that line, and three ways of adding a
    variable were green against it: exporting it once at the top of the script,
    and adding it to either branch of `run`. None of the three appears in what
    the script prints, and all three reach every step.
    """
    declared: dict[tuple[str, str], set[str]] = {}
    for origin, command, workflow_env in COMMANDS:
        declared.setdefault((_job(origin), command), set()).update(workflow_env)
    extra = [
        (run.origin, run.command, sorted(names))
        for run, (_, carried) in zip(
            complete_run.executed, complete_run.child_variables, strict=True
        )
        if (
            names := carried
            - HARNESS_PROVIDED
            - RUNNER_PROVIDED
            - declared.get((run.origin, run.command), set())
        )
    ]
    assert not extra, (
        "tools/verify-all.sh runs steps with variables no workflow gives them, so "
        "those steps are not the steps CI runs:\n  "
        + "\n  ".join(f"{origin}  {command}  {names}" for origin, command, names in extra)
    )


def test_each_job_runs_its_steps_in_the_order_the_workflow_does(complete_run: Trace) -> None:
    """`npm run build --prefix verifiers/ts` before the site install is the point.

    Both workflows depend on the order inside a job — the site resolves
    verifiers/ts by relative path, and the desktop suite opens the artifact the
    build produces — so a script that ran the same commands in a different
    order would not be running what CI runs. Compared per job: the script
    groups the jobs its own way (the formal shards run last, where `ci.yml`
    declares them third), and that regrouping is deliberate.
    """
    jobs = dict.fromkeys(_job(origin) for origin, _, _ in COMMANDS)
    for where in jobs:
        wanted = [
            command
            for origin, command, _ in COMMANDS
            if _job(origin) == where and _provisioning_reason(command) is None
        ]
        assert complete_run.commands_at(where) == wanted, (
            f"{where} does not run its steps in the workflow's order.\n"
            f"  workflow: {wanted}\n  verify-all: {complete_run.commands_at(where)}"
        )


def test_the_formal_matrix_is_expanded_shard_by_shard(complete_run: Trace) -> None:
    """The proof step is one line in `ci.yml` and five runs; both have to be five.

    `verify-all` reads the shard lists out of `ci.yml` rather than copying
    them, which is right — one copy, not two — but it means the exemption that
    covers the matrix template covers the expansion as well. Deleting the whole
    loop left the suite green. This compares the expansion the script performs
    with the one the matrix declares, shard by shard.
    """
    assert len(FORMAL_SHARDS) > 1, FORMAL_SHARDS
    for origin, command in FORMAL_SHARDS:
        assert complete_run.count(origin, command) == 1, (
            f"ci.yml's formal matrix runs `{command}` as {origin}; tools/verify-all.sh "
            f"executed it {complete_run.count(origin, command)} time(s). "
            f"Formal steps it did execute: "
            f"{
                [
                    (run.origin, run.command)
                    for run in complete_run.executed
                    if run.origin.startswith('ci.yml:formal')
                ]
            }"
        )
    assert {
        run.origin for run in complete_run.executed if run.origin.startswith("ci.yml:formal")
    } == {origin for origin, _ in FORMAL_SHARDS}


def test_the_complete_desktop_suite_runs_the_way_ci_runs_it(complete_run: Trace) -> None:
    """Three engines, because `CI` is set: the branch that earns an exit 0.

    `desktop/playwright.config.ts` adds WebKit only when `CI` is set, so this
    branch's `CI=1` is the difference between the suite CI runs and a narrower
    one. Dropping it leaves the same command at the same origin and is
    invisible to a count; here it is the assertion.
    """
    assert [(run.origin, run.env) for run in complete_run.runs_of(DESKTOP_E2E)] == [
        ("pages.yml:desktop", ("CI=1",))
    ]
    assert complete_run.outcomes_of(DESKTOP_E2E) == [("OK", "pages.yml:desktop")]


def test_the_site_suite_runs_the_way_ci_runs_it(complete_run: Trace) -> None:
    """The site end-to-end suite has one branch, and it is the CI one."""
    assert [(run.origin, run.env) for run in complete_run.runs_of(SITE_E2E)] == [
        ("pages.yml:test", ("CI=1",))
    ]
    assert complete_run.outcomes_of(SITE_E2E) == [("OK", "pages.yml:test")]


def test_a_reduced_desktop_run_still_executes_the_step_it_calls_partial(
    webkit_missing_run: Trace,
) -> None:
    """PARTIAL has to be a step that RAN on less, not a step that did not run.

    The reduced branch is the script's other way of covering this workflow
    step, so it gets the same treatment as the complete one: executed once, at
    the desktop job, with the environment that branch promises — and labelled
    so the exit status carries the difference.
    """
    assert [(run.origin, run.env) for run in webkit_missing_run.runs_of(DESKTOP_E2E)] == [
        ("pages.yml:desktop", ("CI=",))
    ]
    assert webkit_missing_run.outcomes_of(DESKTOP_E2E) == [("PARTIAL", "pages.yml:desktop")]
    assert webkit_missing_run.returncode == 2, webkit_missing_run.stdout


def test_a_missing_engine_skips_the_desktop_suite_instead_of_reducing_it(
    engine_missing_run: Trace,
) -> None:
    """The third path: not run at all, and not counted as run.

    Chromium missing is not a narrower footing, it is no footing — and a branch
    that quietly ran the suite anyway would report a pass nobody earned.
    """
    assert engine_missing_run.runs_of(DESKTOP_E2E) == []
    assert engine_missing_run.outcomes_of(DESKTOP_E2E) == [("SKIPPED", "pages.yml:desktop")]
    assert ("pages.yml:desktop", DESKTOP_E2E) in engine_missing_run.not_started
    assert engine_missing_run.returncode == 2, engine_missing_run.stdout


def test_a_missing_engine_skips_the_site_suite_instead_of_running_it(
    site_engine_missing_run: Trace,
) -> None:
    """The same for the suite with only one branch, which is the easier one to forget.

    Every assertion above reads the run where nothing is missing, so a skip
    branch that launched the suite anyway — reporting SKIPPED for a step it had
    just run — would be reached by none of them. That is a report saying less
    than the truth rather than more, which is the quieter half of the same
    defect and needs its own scenario to be seen at all.
    """
    assert site_engine_missing_run.runs_of(SITE_E2E) == []
    assert site_engine_missing_run.outcomes_of(SITE_E2E) == [("SKIPPED", "pages.yml:test")]
    assert ("pages.yml:test", SITE_E2E) in site_engine_missing_run.not_started
    assert site_engine_missing_run.returncode == 2, site_engine_missing_run.stdout


def test_a_step_declares_the_environment_its_own_process_gets(complete_run: Trace) -> None:
    """Measured in the child, not in the script: `env NAME=v` or nothing.

    `ci.yml` sets `ATTEST_CI_REQUIRED` on pytest and on nothing else, and that
    variable is a promise about what the job installed. A run where it reached
    a different command, or reached every command, would be a different
    workflow.
    """
    assert complete_run.environment_of(PYTEST) == [("CI=<unset>", "ATTEST_CI_REQUIRED=1")]
    assert complete_run.environment_of(RUFF) == [("CI=<unset>", "ATTEST_CI_REQUIRED=<unset>")]
    assert complete_run.environment_of(DESKTOP_E2E) == [("CI=1", "ATTEST_CI_REQUIRED=<unset>")]
    carriers = [
        command
        for command, _, required in complete_run.child_environment
        if required != "ATTEST_CI_REQUIRED=<unset>"
    ]
    assert carriers == [PYTEST], carriers


def test_a_reduced_run_clears_an_inherited_ci_rather_than_passing_it_on(
    webkit_missing_under_ci_run: Trace,
) -> None:
    """`run …  -` does not clear the caller's environment; only an assignment does.

    Launched from a shell that exports `CI=1` with WebKit absent, the reduced
    branch would otherwise hand `CI=1` to Playwright, which then selects the
    engine this branch exists because the machine does not have. The empty
    assignment is what makes the promise in the note above it true.
    """
    assert webkit_missing_under_ci_run.environment_of(DESKTOP_E2E) == [
        ("CI=", "ATTEST_CI_REQUIRED=<unset>")
    ]
    assert webkit_missing_under_ci_run.outcomes_of(DESKTOP_E2E) == [
        ("PARTIAL", "pages.yml:desktop")
    ]


def test_a_failed_run_leaves_behind_the_files_it_did_not_create(tmp_path: Path) -> None:
    """Verification reports on the tree; it does not tidy the operator's tree.

    The SBOM names and `verifiers/ts/*.tgz` are ordinary paths a working copy
    may already hold, and a run that fails before any scanner has been reached
    has produced none of them. Deleting them by name and by glob deleted files
    that were there first — measured, all four of these.
    """
    seeded = (
        "sbom-python.cdx.json",
        "sbom-npm.cdx.json",
        "sbom-desktop.cdx.json",
        "verifiers/ts/user-owned.tgz",
    )
    run = _trace(tmp_path, fail=EARLY_STEP, seed=seeded)
    assert run.returncode == 1, run.stdout
    assert len(run.executed) < 5, "the failure was meant to stop the run early"
    survivors = {
        name: (run.root / name).read_text() for name in seeded if (run.root / name).exists()
    }
    assert survivors == dict.fromkeys(seeded, SEEDED_CONTENT), (
        f"a failed verification removed files it never created: "
        f"{sorted(set(seeded) - set(survivors))}"
    )
