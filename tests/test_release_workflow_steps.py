"""Every step of the release workflow that guards an irreversible publication
must be able to REFUSE, and this suite proves it by running the steps' own
scripts -- read out of `.github/workflows/release.yml`, never copied here --
against the failures they exist to catch.

A release path cannot be exercised on demand: the tag is pushed once and PyPI
never forgets. So the guarantee has to come from somewhere else, and the only
honest substitute is to feed each step the shape of artifact that would break it
and watch it exit non-zero. Where a step's protection depends on a value (an
installer's digest, a version in a filename), the test supplies a wrong one.

`test_the_old_move_step_would_have_accepted_a_renamed_wheel` is the control on
the controls: it runs the step this file replaced, against the same artifacts,
and asserts that it exits 0. Without it, a suite of green assertions proves only
that the assertions run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

# The step this file replaced, verbatim, kept only so the control test can show
# that these scenarios discriminate. It is not a fixture of anything current.
_SUPERSEDED_MOVE_STEP = """\
mkdir -p dist
mv attest_receipts-*.whl attest_receipts-*.tar.gz dist/ 2>/dev/null || true
ls dist/
"""


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _shell_argv() -> list[str]:
    """The argv GitHub uses for a `run:` step, derived from the workflow itself.

    With no `shell:` key a step runs as `bash -e {0}`: -e but no pipefail, which
    is what let a failing command inside a pipe pass unnoticed. The workflow now
    sets `shell: bash`, which is `bash --noprofile --norc -eo pipefail {0}`. This
    function refuses to guess: if that default is ever removed, every test that
    runs a script fails here rather than silently testing a weaker shell. It
    reads the WORKFLOW-level key only, and a job-level `defaults.run.shell`
    overrides that without touching it -- which is why
    `test_run_steps_default_to_a_shell_that_fails_on_a_broken_pipe` checks the
    jobs too, and not as a formality: without it that override is invisible here.
    """
    shell = _workflow().get("defaults", {}).get("run", {}).get("shell")
    assert shell == "bash", (
        f"expected `defaults.run.shell: bash` for pipefail, found {shell!r}: "
        "the scripts below would run under a shell that ignores failures in pipes"
    )
    bash = shutil.which("bash")
    assert bash is not None
    return [bash, "--noprofile", "--norc", "-eo", "pipefail"]


def _step(job: str, name_fragment: str) -> dict[str, Any]:
    steps = _workflow()["jobs"][job]["steps"]
    named = [s for s in steps if name_fragment in str(s.get("name", ""))]
    assert len(named) == 1, f"expected exactly 1 step matching {name_fragment!r} in {job}"
    return named[0]  # type: ignore[no-any-return]


def _continued_lines(script: str, needle: str) -> str:
    """Pull one assertion, with its backslash continuations, out of a step.

    Some steps cannot be run whole outside CI -- they call uv, npm or syft. The
    guard inside them still can, and running the real lines keeps this suite tied
    to the file instead of to a paraphrase of it.
    """
    lines = script.splitlines()
    starts = [i for i, line in enumerate(lines) if needle in line]
    assert len(starts) == 1, f"expected exactly 1 line containing {needle!r}"
    end = starts[0]
    while lines[end].rstrip().endswith("\\"):
        end += 1
    return "\n".join(lines[starts[0] : end + 1])


def _run(script: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    script_path = cwd / "_step.sh"
    script_path.write_text(script, encoding="utf-8")
    return subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [*_shell_argv(), str(script_path)],
        cwd=cwd,
        env={"PATH": "/usr/bin:/bin", "HOME": str(cwd), **env},
        capture_output=True,
        text=True,
        check=False,
    )


def _stub_bin(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / name
    stub.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    stub.chmod(0o755)


# --------------------------------------------------------------------------
# The shell every step runs under
# --------------------------------------------------------------------------


def test_run_steps_default_to_a_shell_that_fails_on_a_broken_pipe() -> None:
    workflow = _workflow()
    assert workflow["defaults"]["run"]["shell"] == "bash"
    for job_name, job in workflow["jobs"].items():
        job_shell = job.get("defaults", {}).get("run", {}).get("shell")
        assert job_shell in (None, "bash"), (
            f"{job_name} sets `defaults.run.shell: {job_shell!r}`, which WINS over the "
            "workflow default: every step in this job would run without pipefail while "
            "the workflow-level key still reads `bash` -- so `_shell_argv` stays happy "
            "and this suite goes on testing a stronger shell than the one CI uses"
        )
        for step in job["steps"]:
            if "run" not in step:
                continue
            declared = step.get("shell")
            assert declared in (None, "bash"), (
                f"{job_name}/{step.get('name')} overrides the shell with {declared!r}, "
                "which drops the pipefail the workflow default provides"
            )


def test_a_failing_command_in_a_pipe_fails_the_step(tmp_path: Path) -> None:
    """The property the default buys, stated as a test rather than as a comment."""
    result = _run("false | cat\necho reached\n", tmp_path, {})
    assert result.returncode != 0, "a pipe whose first command fails must fail the step"
    assert "reached" not in result.stdout


# --------------------------------------------------------------------------
# dist/ is asserted, not observed, before anything is published
# --------------------------------------------------------------------------


def _dist_script() -> str:
    return str(_step("pypi", "Assert dist/ holds")["run"])


def _seed_dist(tmp_path: Path, names: list[str]) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in names:
        (dist / name).write_bytes(b"not a real distribution")
    return dist


def test_dist_assertion_accepts_the_layout_a_release_really_produces(tmp_path: Path) -> None:
    _seed_dist(
        tmp_path,
        ["attest_receipts-9.9.9-py3-none-any.whl", "attest_receipts-9.9.9.tar.gz"],
    )
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "publishing" in result.stdout


def test_dist_assertion_refuses_a_wheel_renamed_by_one_character(tmp_path: Path) -> None:
    """The failure the old step could not see, and the reason this file exists.

    A wheel named with a hyphen instead of an underscore left the old `mv` with
    one glob unmatched: it moved the sdist, failed on the wheel into /dev/null,
    was absolved by `|| true`, and `ls` showed a directory that looked populated.
    PyPI would have received the sdist alone, irreversibly, with the run green.
    """
    _seed_dist(
        tmp_path,
        ["attest-receipts-9.9.9-py3-none-any.whl", "attest_receipts-9.9.9.tar.gz"],
    )
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0, "a renamed wheel must not reach the publish step"
    assert "expected exactly 1 wheel" in result.stdout


def test_dist_assertion_refuses_an_empty_directory(tmp_path: Path) -> None:
    _seed_dist(tmp_path, [])
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0
    assert "expected sdist" in result.stdout


def test_dist_assertion_refuses_a_missing_directory(tmp_path: Path) -> None:
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0


def test_dist_assertion_refuses_distributions_from_another_version(tmp_path: Path) -> None:
    """A stale artifact is the quiet way to publish the wrong bytes under a tag."""
    _seed_dist(
        tmp_path,
        ["attest_receipts-9.9.8-py3-none-any.whl", "attest_receipts-9.9.8.tar.gz"],
    )
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0
    assert "expected sdist dist/attest_receipts-9.9.9.tar.gz" in result.stdout


def test_dist_assertion_refuses_a_second_wheel(tmp_path: Path) -> None:
    _seed_dist(
        tmp_path,
        [
            "attest_receipts-9.9.9-py3-none-any.whl",
            "attest_receipts-9.9.9-py3-none-macosx_11_0_arm64.whl",
            "attest_receipts-9.9.9.tar.gz",
        ],
    )
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0
    assert "expected exactly 1 wheel" in result.stdout


def test_dist_assertion_refuses_anything_else_in_the_directory(tmp_path: Path) -> None:
    """`twine upload dist/*` uploads the directory, not the two files we checked."""
    _seed_dist(
        tmp_path,
        [
            "attest_receipts-9.9.9-py3-none-any.whl",
            "attest_receipts-9.9.9.tar.gz",
            "attest_receipts-9.9.9.tar.gz.asc",
        ],
    )
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0
    assert "nothing else" in result.stdout


def test_the_old_move_step_would_have_accepted_a_renamed_wheel(tmp_path: Path) -> None:
    """The control on the controls.

    Same artifacts as the renamed-wheel test, laid out as the superseded step
    expected them (in the workspace root, which is where it looked). It exits 0
    with one distribution staged for an irreversible upload. If this ever fails,
    the scenarios above stopped discriminating and the green above means nothing.
    """
    (tmp_path / "attest-receipts-9.9.9-py3-none-any.whl").write_bytes(b"x")
    (tmp_path / "attest_receipts-9.9.9.tar.gz").write_bytes(b"x")
    result = _run(_SUPERSEDED_MOVE_STEP, tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode == 0, "the superseded step could not fail -- that was the defect"
    staged = sorted(p.name for p in (tmp_path / "dist").iterdir())
    assert staged == ["attest_receipts-9.9.9.tar.gz"]


def test_the_move_step_is_gone(tmp_path: Path) -> None:
    """It moved nothing on every past release: the artifact already carries dist/.

    Kept as an assertion rather than a comment because a future edit that
    reintroduces the move would also reintroduce a step that cannot fail.
    """
    script = _dist_script()
    assert "|| true" not in script
    assert "2>/dev/null" not in script
    assert re.search(r"^\s*mv\s", script, re.MULTILINE) is None


# --------------------------------------------------------------------------
# An incomplete artifact must not leave the job that built it
# --------------------------------------------------------------------------


@pytest.mark.parametrize("job", ["build", "desktop"])
def test_uploads_refuse_a_wholly_empty_artifact(job: str) -> None:
    """`if-no-files-found` defaults to `warn`, which uploads nothing and stays
    green. `error` fixes only that, and no more: the key is AGGREGATE over every
    pattern -- v7.0.1 builds one globber from the whole `path` and tests
    `filesToUpload.length === 0` -- so it is not what makes an artifact complete.
    This test asserts the key; the one below asserts the guarantee."""
    uploads = [
        step
        for step in _workflow()["jobs"][job]["steps"]
        if "upload-artifact" in str(step.get("uses", ""))
    ]
    assert uploads, f"{job} uploads nothing"
    for step in uploads:
        assert step["with"]["if-no-files-found"] == "error"


def test_build_refuses_to_ship_an_artifact_missing_any_one_of_its_patterns(
    tmp_path: Path,
) -> None:
    """The guarantee the key does not give, asserted where it is actually made.

    Dropping each file in turn is the point: an aggregate check passes every one
    of these, because in each case four of the five patterns still match.
    """
    script = str(_step("build", "Assert the artifact is complete")["run"])
    tag = {"GITHUB_REF_NAME": "v9.9.9"}
    complete = [
        "dist/attest_receipts-9.9.9-py3-none-any.whl",
        "dist/attest_receipts-9.9.9.tar.gz",
        "sbom-python.cdx.json",
        "sbom-npm.cdx.json",
        "attest-verifier-9.9.9.tgz",
    ]
    (tmp_path / "dist").mkdir()
    for name in complete:
        (tmp_path / name).write_bytes(b"x")
    assert _run(script, tmp_path, tag).returncode == 0

    for dropped in complete:
        (tmp_path / dropped).unlink()
        result = _run(script, tmp_path, tag)
        assert result.returncode != 0, f"an artifact without {dropped} must not travel"
        assert "would leave this job without" in result.stdout
        (tmp_path / dropped).write_bytes(b"x")


def test_build_refuses_a_verifier_tarball_from_another_version(tmp_path: Path) -> None:
    """The npm job checks this too, but it runs concurrently with the PyPI
    publish: a refusal there cannot stop a half release. Here it can."""
    (tmp_path / "dist").mkdir()
    for name in (
        "dist/attest_receipts-9.9.9-py3-none-any.whl",
        "dist/attest_receipts-9.9.9.tar.gz",
        "sbom-python.cdx.json",
        "sbom-npm.cdx.json",
        "attest-verifier-9.9.8.tgz",
    ):
        (tmp_path / name).write_bytes(b"x")
    script = str(_step("build", "Assert the artifact is complete")["run"])
    result = _run(script, tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0, "a stale verifier tarball must not leave the build job"
    assert "attest-verifier-9.9.9.tgz" in result.stdout


def test_build_refuses_a_second_verifier_tarball(tmp_path: Path) -> None:
    """`sha256sum ... attest-verifier-*.tgz` globs, so two tarballs would both be
    recorded and both travel, with the wrong one still named in the manifest."""
    (tmp_path / "dist").mkdir()
    for name in (
        "dist/attest_receipts-9.9.9-py3-none-any.whl",
        "dist/attest_receipts-9.9.9.tar.gz",
        "sbom-python.cdx.json",
        "sbom-npm.cdx.json",
        "attest-verifier-9.9.9.tgz",
        "attest-verifier-9.9.8.tgz",
    ):
        (tmp_path / name).write_bytes(b"x")
    script = str(_step("build", "Assert the artifact is complete")["run"])
    result = _run(script, tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0
    assert "expected exactly 1 verifier tarball" in result.stdout


def test_build_refuses_python_distributions_from_another_version(tmp_path: Path) -> None:
    """Reject before npm can publish concurrently with the PyPI job's refusal."""
    (tmp_path / "dist").mkdir()
    for name in (
        "dist/attest_receipts-9.9.8-py3-none-any.whl",
        "dist/attest_receipts-9.9.8.tar.gz",
        "sbom-python.cdx.json",
        "sbom-npm.cdx.json",
        "attest-verifier-9.9.9.tgz",
    ):
        (tmp_path / name).write_bytes(b"x")
    script = str(_step("build", "Assert the artifact is complete")["run"])
    result = _run(script, tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0, "stale Python distributions must not leave the build job"
    assert "Python distributions must match" in result.stdout


def test_build_completeness_refuses_a_tag_it_cannot_read(tmp_path: Path) -> None:
    """An unset GITHUB_REF_NAME must not degrade into "any verifier will do"."""
    (tmp_path / "dist").mkdir()
    for name in (
        "dist/attest_receipts-9.9.9-py3-none-any.whl",
        "dist/attest_receipts-9.9.9.tar.gz",
        "sbom-python.cdx.json",
        "sbom-npm.cdx.json",
        "attest-verifier-9.9.9.tgz",
    ):
        (tmp_path / name).write_bytes(b"x")
    script = str(_step("build", "Assert the artifact is complete")["run"])
    result = _run(script, tmp_path, {})
    assert result.returncode != 0
    assert "would leave this job without" in result.stdout


# --------------------------------------------------------------------------
# The supply-chain gate cannot install itself silently
# --------------------------------------------------------------------------


def _install_step() -> dict[str, Any]:
    return _step("build", "Install syft, grype, grant")


def test_installers_are_fetched_to_a_file_and_pinned_by_digest() -> None:
    step = _install_step()
    script = str(step["run"])
    assert re.search(r"\|\s*sh(\s|$)", script) is None, (
        "piping an installer into a shell cannot be checksummed before it runs, "
        "and without pipefail it cannot even fail"
    )
    for tool in ("SYFT", "GRYPE", "GRANT"):
        digest = str(step["env"][f"{tool}_INSTALLER_SHA256"])
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{tool} digest is not a sha256: {digest!r}"


def _install_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = {str(k): str(v) for k, v in _install_step()["env"].items()}
    env.update(overrides)
    env["GITHUB_PATH"] = str(tmp_path / "github_path")
    env["PATH"] = f"{tmp_path / 'stubs'}:/usr/bin:/bin"
    return env


def test_install_step_fails_when_a_download_fails(tmp_path: Path) -> None:
    """A 404 used to install nothing and exit 0: the pipe reported sh's status,
    and sh on empty stdin succeeds."""
    _stub_bin(tmp_path / "stubs", "curl", "exit 22")
    result = _run(str(_install_step()["run"]), tmp_path, _install_env(tmp_path))
    assert result.returncode != 0, "a failed download must not leave the gate uninstalled and green"


def test_install_step_refuses_an_installer_whose_bytes_changed(tmp_path: Path) -> None:
    """The pin's reason for existing: a git tag can be repointed at other bytes
    while the version string stays the same. The installers verify the binary
    they fetch, so the installer itself was the last unverified link."""
    _stub_bin(
        tmp_path / "stubs",
        "curl",
        'out=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac\n'
        "done\n"
        'printf "%s\\n" "#!/bin/sh" "echo tampered" > "$out"',
    )
    result = _run(str(_install_step()["run"]), tmp_path, _install_env(tmp_path))
    assert result.returncode != 0
    assert "FAILED" in result.stdout + result.stderr


def test_install_step_fails_when_an_installer_leaves_no_binary(tmp_path: Path) -> None:
    """An installer can exit 0 and install nothing. Without the check below, the
    first job to notice is the scan, as a `command not found` that reads like a
    different failure entirely."""
    installer_body = "#!/bin/sh\nexit 0\n"
    installer = tmp_path / "fake-installer.sh"
    installer.write_text(installer_body, encoding="utf-8")
    digest = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        ["/usr/bin/sha256sum", str(installer)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()[0]
    _stub_bin(
        tmp_path / "stubs",
        "curl",
        'out=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac\n'
        "done\n"
        f'cp "{installer}" "$out"',
    )
    env = _install_env(
        tmp_path,
        SYFT_INSTALLER_SHA256=digest,
        GRYPE_INSTALLER_SHA256=digest,
        GRANT_INSTALLER_SHA256=digest,
    )
    result = _run(str(_install_step()["run"]), tmp_path, env)
    assert result.returncode != 0
    assert "left no executable" in result.stdout


def test_the_pinned_installer_is_not_allowed_to_re_fetch_itself(tmp_path: Path) -> None:
    """The digest covers the script this step downloads, and nothing more.

    All three anchore installers default DOWNLOAD_TAG_INSTALL_SCRIPT to true,
    and under that default their first act is to fetch install.sh again from
    get.anchore.io -- an origin no digest here covers -- pipe it into `sh` and
    exit with its status, so the bytes that ran would not be the bytes checked.
    Asserted by running the real step against an installer that records the
    value it was handed: the environment is what has to carry it, so reading it
    out of the environment is the assertion, not a paraphrase of the script.
    """
    seen = tmp_path / "seen"
    installer = tmp_path / "installer.sh"
    installer.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "${{DOWNLOAD_TAG_INSTALL_SCRIPT-<unset>}}" >> "{seen}"\n'
        'bindir="$2"\n'
        'mkdir -p "$bindir"\n'
        'for t in syft grype grant; do printf "#!/bin/sh\\ntrue\\n" > "$bindir/$t"; '
        'chmod 755 "$bindir/$t"; done\n',
        encoding="utf-8",
    )
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    _stub_bin(
        tmp_path / "stubs",
        "curl",
        'out=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac\n'
        "done\n"
        f'cp "{installer}" "$out"',
    )
    binary_digest = hashlib.sha256(b"#!/bin/sh\ntrue\n").hexdigest()
    env = _install_env(
        tmp_path,
        SYFT_INSTALLER_SHA256=digest,
        GRYPE_INSTALLER_SHA256=digest,
        GRANT_INSTALLER_SHA256=digest,
        SYFT_BINARY_SHA256=binary_digest,
        GRYPE_BINARY_SHA256=binary_digest,
        GRANT_BINARY_SHA256=binary_digest,
    )
    result = _run(str(_install_step()["run"]), tmp_path, env)
    assert result.returncode == 0, result.stdout + result.stderr
    recorded = seen.read_text(encoding="utf-8").split() if seen.exists() else []
    assert recorded == ["false", "false", "false"], (
        "every installer must be run with DOWNLOAD_TAG_INSTALL_SCRIPT=false, or the "
        f"script whose digest was just checked re-fetches itself unpinned: {recorded}"
    )


# --------------------------------------------------------------------------
# An empty SBOM is not a clean scan
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("job_step", "sbom_name"),
    [("Assert + scan Python", "sbom-python.cdx.json"), ("Assert + scan npm", "sbom-npm.cdx.json")],
)
def test_sbom_guard_refuses_an_inventory_with_no_components(
    tmp_path: Path, job_step: str, sbom_name: str
) -> None:
    """grype finds no vulnerability in nothing and grant finds no forbidden
    licence in nothing, so both gates pass on an empty SBOM -- which is then
    attached to the GitHub Release as evidence of having scanned something."""
    guard = _continued_lines(str(_step("build", job_step)["run"]), "jq -e '(.components")
    for empty in ({"components": []}, {"bomFormat": "CycloneDX"}):
        (tmp_path / sbom_name).write_text(json.dumps(empty), encoding="utf-8")
        result = _run(guard, tmp_path, {})
        assert result.returncode != 0, f"an SBOM shaped {empty} must not pass the gate"
        assert "no components" in result.stdout


@pytest.mark.parametrize(
    ("job_step", "sbom_name"),
    [("Assert + scan Python", "sbom-python.cdx.json"), ("Assert + scan npm", "sbom-npm.cdx.json")],
)
def test_sbom_guard_accepts_a_populated_inventory(
    tmp_path: Path, job_step: str, sbom_name: str
) -> None:
    guard = _continued_lines(str(_step("build", job_step)["run"]), "jq -e '(.components")
    (tmp_path / sbom_name).write_text(
        json.dumps({"components": [{"name": "cryptography", "version": "46.0.1"}]}),
        encoding="utf-8",
    )
    result = _run(guard, tmp_path, {})
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------
# The public announcement checks the registries it is announcing
# --------------------------------------------------------------------------


def _registry_script() -> str:
    return str(_step("github-release", "Assert both registries")["run"])


def _registry_env(tmp_path: Path) -> dict[str, str]:
    return {
        "GITHUB_REF_NAME": "v9.9.9",
        "REGISTRY_ATTEMPTS": "1",
        "REGISTRY_RETRY_SECONDS": "0",
        "PATH": f"{tmp_path / 'stubs'}:/usr/bin:/bin",
    }


def _stub_registries(
    tmp_path: Path, pypi: dict[str, Any] | None, npm: dict[str, Any] | None
) -> None:
    """A curl that answers for the two registries, or 404s the way curl -f does."""
    pypi_path = tmp_path / "pypi-canned.json"
    npm_path = tmp_path / "npm-canned.json"
    if pypi is not None:
        pypi_path.write_text(json.dumps(pypi), encoding="utf-8")
    if npm is not None:
        npm_path.write_text(json.dumps(npm), encoding="utf-8")
    _stub_bin(
        tmp_path / "stubs",
        "curl",
        'out=""; url=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in\n'
        '    -o) out="$2"; shift 2 ;;\n'
        "    -*) shift ;;\n"
        '    *) url="$1"; shift ;;\n'
        "  esac\n"
        "done\n"
        'case "$url" in\n'
        f'  *pypi.org*) src="{pypi_path}" ;;\n'
        f'  *registry.npmjs.org*) src="{npm_path}" ;;\n'
        "  *) exit 22 ;;\n"
        "esac\n"
        '[ -f "$src" ] || exit 22\n'
        'cp "$src" "$out"',
    )


_FULL_PYPI = {
    "urls": [
        {"packagetype": "bdist_wheel", "filename": "attest_receipts-9.9.9-py3-none-any.whl"},
        {"packagetype": "sdist", "filename": "attest_receipts-9.9.9.tar.gz"},
    ]
}


def test_release_is_announced_when_both_registries_serve_it(tmp_path: Path) -> None:
    _stub_registries(tmp_path, _FULL_PYPI, {"version": "9.9.9"})
    result = _run(_registry_script(), tmp_path, _registry_env(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "announcing it" in result.stdout


def test_release_is_not_announced_when_pypi_has_only_the_sdist(tmp_path: Path) -> None:
    """The same defect as the renamed wheel, seen from the public side: a partial
    publication that every earlier job called a success."""
    partial = {"urls": [{"packagetype": "sdist", "filename": "attest_receipts-9.9.9.tar.gz"}]}
    _stub_registries(tmp_path, partial, {"version": "9.9.9"})
    result = _run(_registry_script(), tmp_path, _registry_env(tmp_path))
    assert result.returncode != 0
    assert "without both a wheel and an sdist" in result.stdout


def test_release_is_not_announced_when_a_registry_does_not_serve_the_version(
    tmp_path: Path,
) -> None:
    _stub_registries(tmp_path, None, {"version": "9.9.9"})
    result = _run(_registry_script(), tmp_path, _registry_env(tmp_path))
    assert result.returncode != 0
    assert "does not serve" in result.stdout


def test_release_is_not_announced_when_npm_serves_another_version(tmp_path: Path) -> None:
    _stub_registries(tmp_path, _FULL_PYPI, {"version": "9.9.8"})
    result = _run(_registry_script(), tmp_path, _registry_env(tmp_path))
    assert result.returncode != 0
    assert "npm does not serve" in result.stdout


def test_registries_are_checked_before_the_release_is_created() -> None:
    """Order matters: a timeout after `gh release create` would leave a half-made
    public release for the re-run to trip over."""
    steps = _workflow()["jobs"]["github-release"]["steps"]
    names = [str(step.get("name", "")) for step in steps]
    check = next(i for i, name in enumerate(names) if "Assert both registries" in name)
    create = next(i for i, name in enumerate(names) if "Create GitHub Release" in name)
    assert check < create


# --------------------------------------------------------------------------
# Identity: the bytes that were gated are the bytes that get published
# --------------------------------------------------------------------------
def test_binary_digests_are_pinned_for_every_tool() -> None:
    env = _install_step()["env"]
    for tool in ("SYFT", "GRYPE", "GRANT"):
        d = str(env[f"{tool}_BINARY_SHA256"])
        assert len(d) == 64 and all(c in "0123456789abcdef" for c in d)


def test_install_step_refuses_a_binary_that_is_not_the_pinned_one(tmp_path: Path) -> None:
    """The link the installer pin does NOT close: the installers verify the binary
    against the release's own checksums.txt, an unsigned mutable release asset."""
    installer = tmp_path / "fake.sh"
    installer.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do case "$1" in -b) dir="$2"; shift 2 ;; *) shift ;; esac; done\n'
        'mkdir -p "$dir"\n'
        'for t in syft grype grant; do printf tampered > "$dir/$t"; chmod 755 "$dir/$t"; done\n',
        encoding="utf-8",
    )
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    _stub_bin(
        tmp_path / "stubs",
        "curl",
        'out=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac\n'
        "done\n"
        f'cp "{installer}" "$out"',
    )
    env = _install_env(
        tmp_path,
        SYFT_INSTALLER_SHA256=digest,
        GRYPE_INSTALLER_SHA256=digest,
        GRANT_INSTALLER_SHA256=digest,
    )
    result = _run(str(_install_step()["run"]), tmp_path, env)
    assert result.returncode != 0
    assert "FAILED" in result.stdout + result.stderr


def _npm_script() -> str:
    return str(_step("npm", "Publish with provenance")["run"])


def _seed_npm(tmp_path: Path, names: list[str]) -> None:
    d = tmp_path / "dist-and-sboms"
    d.mkdir(exist_ok=True)
    lines = []
    for n in names:
        (d / n).write_bytes(b"tgz")
        lines.append(f"{hashlib.sha256(b'tgz').hexdigest()}  {n}")
    (d / "gated-artifacts.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_npm_publish_refuses_a_tarball_from_another_version(tmp_path: Path) -> None:
    _seed_npm(tmp_path, ["attest-verifier-9.9.8.tgz"])
    script = _npm_script().replace("npm publish", "echo WOULD-PUBLISH")
    result = _run(script, tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0, "a stale tarball must not reach an irreversible npm publish"
    assert "WOULD-PUBLISH" not in result.stdout


def test_npm_publish_accepts_this_tag_s_tarball(tmp_path: Path) -> None:
    _seed_npm(tmp_path, ["attest-verifier-9.9.9.tgz"])
    script = _npm_script().replace("npm publish", "echo WOULD-PUBLISH")
    result = _run(script, tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WOULD-PUBLISH" in result.stdout


def _identity_script() -> str:
    return str(_step("github-release", "Assert the registries serve the bytes")["run"])


def _seed_identity(
    tmp_path: Path, *, pypi_wheel_digest: str | None = None, npm_integrity: str | None = None
) -> None:
    art = tmp_path / "artifacts"
    (art / "dist").mkdir(parents=True)
    wheel = art / "dist" / "attest_receipts-9.9.9-py3-none-any.whl"
    sdist = art / "dist" / "attest_receipts-9.9.9.tar.gz"
    tgz = art / "attest-verifier-9.9.9.tgz"
    wheel.write_bytes(b"W")
    sdist.write_bytes(b"S")
    tgz.write_bytes(b"T")
    sums = (
        "\n".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(art)}"
            for p in (wheel, sdist, tgz)
        )
        + "\n"
    )
    (art / "gated-artifacts.sha256").write_text(sums, encoding="utf-8")
    wd = pypi_wheel_digest or hashlib.sha256(b"W").hexdigest()
    (tmp_path / "pypi.json").write_text(
        json.dumps(
            {
                "urls": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": wheel.name,
                        "digests": {"sha256": wd},
                    },
                    {
                        "packagetype": "sdist",
                        "filename": sdist.name,
                        "digests": {"sha256": hashlib.sha256(b"S").hexdigest()},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    integ = npm_integrity or "sha512-" + base64.b64encode(hashlib.sha512(b"T").digest()).decode()
    (tmp_path / "npm.json").write_text(
        json.dumps({"version": "9.9.9", "dist": {"integrity": integ}}), encoding="utf-8"
    )


def test_identity_accepts_registries_serving_the_gated_bytes(tmp_path: Path) -> None:
    _seed_identity(tmp_path)
    r = _run(_identity_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "serve the bytes this run gated" in r.stdout


def test_identity_refuses_pypi_serving_other_bytes(tmp_path: Path) -> None:
    """What `skip-existing: true` makes reachable: the version was already there,
    the publish step skipped in silence, and presence alone cannot tell."""
    _seed_identity(tmp_path, pypi_wheel_digest="0" * 64)
    r = _run(_identity_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert r.returncode != 0
    assert "this run gated" in r.stdout


def test_identity_refuses_npm_serving_other_bytes(tmp_path: Path) -> None:
    _seed_identity(tmp_path, npm_integrity="sha512-AAAA")
    r = _run(_identity_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert r.returncode != 0
    assert "npm serves" in r.stdout


def test_identity_refuses_an_artifact_altered_in_transit(tmp_path: Path) -> None:
    _seed_identity(tmp_path)
    (tmp_path / "artifacts" / "dist" / "attest_receipts-9.9.9-py3-none-any.whl").write_bytes(
        b"EVIL"
    )
    r = _run(_identity_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert r.returncode != 0


def test_pypi_job_verifies_the_gated_digests_before_publishing() -> None:
    steps = _workflow()["jobs"]["pypi"]["steps"]
    names = [str(s.get("name", "")) for s in steps]
    verify = next(i for i, n in enumerate(names) if "bytes the build job gated" in n)
    publish = next(i for i, s in enumerate(steps) if "pypi-publish" in str(s.get("uses", "")))
    assert verify < publish


# --------------------------------------------------------------------------
# Not-well-formed input: properties, not the examples the author thought of
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        '{"components": {"a": 1}}',
        '{"components": "xx"}',
        '{"components": 7}',
        '{"components": true}',
        "TRUNCATED{",
    ],
)
@pytest.mark.parametrize(
    ("job_step", "sbom_name"),
    [("Assert + scan Python", "sbom-python.cdx.json"), ("Assert + scan npm", "sbom-npm.cdx.json")],
)
def test_sbom_guard_refuses_a_components_field_that_is_not_an_inventory(
    tmp_path: Path, job_step: str, sbom_name: str, body: str
) -> None:
    """`length` answers for objects, strings and numbers too, so before the type
    check a file that is not a CycloneDX document satisfied "the inventory is not
    empty" and was then attached to the Release as evidence of a scan."""
    guard = _continued_lines(str(_step("build", job_step)["run"]), "jq -e '(.components")
    (tmp_path / sbom_name).write_text(body, encoding="utf-8")
    result = _run(guard, tmp_path, {})
    assert result.returncode != 0, f"{body} is not an inventory and must not pass the gate"


@pytest.mark.parametrize("job_step", ["Assert + scan Python", "Assert + scan npm"])
def test_the_sbom_guard_runs_before_the_scans_it_gates(job_step: str) -> None:
    """`_continued_lines` runs the guard in isolation and cannot see where it
    sits. The comment claims the scans below would pass on an empty inventory;
    that sentence is only true while the guard is above them."""
    lines = str(_step("build", job_step)["run"]).splitlines()
    guard = next(i for i, line in enumerate(lines) if "jq -e '(.components" in line)
    for scanner in ("grype sbom:", "grant check"):
        scan = next(i for i, line in enumerate(lines) if scanner in line)
        assert guard < scan, f"the emptiness guard must precede {scanner}"


@pytest.mark.parametrize(
    "pypi_body",
    [
        "{}",
        '{"urls": null}',
        '{"urls": []}',
        '{"urls": {"a": {"packagetype": "sdist"}}}',
        '{"urls": [{"packagetype": "sdist"}, {"packagetype": "sdist"}]}',
        "TRUNCATED{",
    ],
)
def test_release_is_not_announced_on_a_malformed_pypi_answer(
    tmp_path: Path, pypi_body: str
) -> None:
    _stub_registries(tmp_path, None, {"version": "9.9.9"})
    _stub_bin(
        tmp_path / "stubs",
        "curl",
        'out=""; url=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac\n'
        "done\n"
        'case "$url" in\n'
        f"  *pypi.org*) printf '%s' {pypi_body!r} > \"$out\" ;;\n"
        '  *registry.npmjs.org*) printf \'{"version":"9.9.9"}\' > "$out" ;;\n'
        "  *) exit 22 ;;\n"
        "esac",
    )
    result = _run(_registry_script(), tmp_path, _registry_env(tmp_path))
    assert result.returncode != 0, f"a PyPI answer shaped {pypi_body} must not be announced"


@pytest.mark.parametrize(
    "npm_body",
    [{}, {"version": 9.9}, {"version": ["9.9.9"]}, {"version": "9.9.9 "}, {"version": None}],
)
def test_release_is_not_announced_on_a_malformed_npm_answer(
    tmp_path: Path, npm_body: dict[str, Any]
) -> None:
    _stub_registries(tmp_path, _FULL_PYPI, npm_body)
    result = _run(_registry_script(), tmp_path, _registry_env(tmp_path))
    assert result.returncode != 0, f"an npm answer shaped {npm_body} must not be announced"


@pytest.mark.parametrize("attempts", ["0", "-1", "abc", "1 ; touch INJECTED-MARKER"])
def test_no_retry_setting_can_turn_a_missing_package_into_a_release(
    tmp_path: Path, attempts: str
) -> None:
    """The knobs exist so the retry can be exercised without waiting. A value that
    skipped the loop, or that ran as a command, would announce nothing as success.

    The injection probe leaves a FILE rather than printing: the step echoes the
    value it was given inside its own failure message, so looking for a marker in
    stdout would find the echo and call it an execution. A test that cannot tell
    those apart is the defect it is meant to catch, one level up.
    """
    _stub_registries(tmp_path, None, None)
    env = {**_registry_env(tmp_path), "REGISTRY_ATTEMPTS": attempts}
    result = _run(_registry_script(), tmp_path, env)
    assert result.returncode != 0
    assert not (tmp_path / "INJECTED-MARKER").exists(), "the retry budget was executed as a command"


def test_dist_assertion_refuses_a_tag_it_cannot_read(tmp_path: Path) -> None:
    """An unset GITHUB_REF_NAME must not degrade into "any version will do"."""
    _seed_dist(
        tmp_path,
        ["attest_receipts-9.9.9-py3-none-any.whl", "attest_receipts-9.9.9.tar.gz"],
    )
    result = _run(_dist_script(), tmp_path, {})
    assert result.returncode != 0
    assert "expected sdist" in result.stdout


def test_dist_assertion_refuses_a_directory_among_the_distributions(tmp_path: Path) -> None:
    _seed_dist(
        tmp_path,
        ["attest_receipts-9.9.9-py3-none-any.whl", "attest_receipts-9.9.9.tar.gz"],
    )
    (tmp_path / "dist" / "leftover").mkdir()
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0
    assert "nothing else" in result.stdout


def test_dist_assertion_refuses_a_hidden_file_among_the_distributions(tmp_path: Path) -> None:
    """Without dotglob, `dist/*` skips dotfiles and "nothing else" would be a
    stronger sentence than the glob backing it."""
    _seed_dist(
        tmp_path,
        [
            "attest_receipts-9.9.9-py3-none-any.whl",
            "attest_receipts-9.9.9.tar.gz",
            ".hidden-extra",
        ],
    )
    result = _run(_dist_script(), tmp_path, {"GITHUB_REF_NAME": "v9.9.9"})
    assert result.returncode != 0
    assert "nothing else" in result.stdout


# --------------------------------------------------------------------------
# The gate names WHICH tool is missing, and a broken environment is not a pass
# --------------------------------------------------------------------------


def test_install_step_names_the_single_tool_whose_installer_left_nothing(tmp_path: Path) -> None:
    """Per-element, not aggregate: the earlier stub made all three installers
    fail at once, so it could not tell "one is missing" from "all are missing" --
    the same blindness as an aggregate check, moved from the code into the test.
    """
    for broken in ("syft", "grype", "grant"):
        work = tmp_path / broken
        (work / "stubs").mkdir(parents=True)
        digests = {}
        for tool in ("syft", "grype", "grant"):
            installer = work / f"{tool}.sh"
            if tool == broken:
                installer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            else:
                installer.write_text(
                    "#!/bin/sh\n"
                    'bindir="$2"\n'
                    'mkdir -p "$bindir"\n'
                    f'printf "#!/bin/sh\\necho {tool}\\n" > "$bindir/{tool}"\n'
                    f'chmod 755 "$bindir/{tool}"\n',
                    encoding="utf-8",
                )
            digests[tool] = hashlib.sha256(installer.read_bytes()).hexdigest()
        _stub_bin(
            work / "stubs",
            "curl",
            'out=""; url=""\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac\n'
            "done\n"
            'case "$url" in\n'
            f'  *anchore/syft*) cp "{work}/syft.sh" "$out" ;;\n'
            f'  *anchore/grype*) cp "{work}/grype.sh" "$out" ;;\n'
            f'  *anchore/grant*) cp "{work}/grant.sh" "$out" ;;\n'
            "  *) exit 22 ;;\n"
            "esac",
        )
        env = _install_env(
            work,
            SYFT_INSTALLER_SHA256=digests["syft"],
            GRYPE_INSTALLER_SHA256=digests["grype"],
            GRANT_INSTALLER_SHA256=digests["grant"],
        )
        env["PATH"] = f"{work / 'stubs'}:/usr/bin:/bin"
        result = _run(str(_install_step()["run"]), work, env)
        assert result.returncode != 0, f"a missing {broken} must fail the step"
        assert broken in result.stdout, f"the failure must name {broken}, not just fail"


def test_the_tools_this_bench_needs_are_present() -> None:
    """A negative test that asserts only an exit code cannot tell a refusal from a
    broken environment: with `jq` absent, every "must be rejected" case would pass
    on `command not found` while proving nothing. The positive cases would go red,
    but only as a side effect. This says it out loud instead.
    """
    for tool in ("bash", "jq", "sha256sum", "mktemp", "openssl", "base64"):
        assert shutil.which(tool) is not None, (
            f"{tool} is missing: the negative tests below would pass for the wrong reason"
        )


def test_the_retry_does_not_wait_after_its_final_attempt(tmp_path: Path) -> None:
    """Counted, not timed: a stub `sleep` records each call, so the assertion is
    about how many waits happen rather than about how long the test took."""
    _stub_registries(tmp_path, None, None)
    calls = tmp_path / "sleep-calls"
    _stub_bin(tmp_path / "stubs", "sleep", f'echo "$1" >> "{calls}"')
    env = {**_registry_env(tmp_path), "REGISTRY_ATTEMPTS": "3", "REGISTRY_RETRY_SECONDS": "7"}
    result = _run(_registry_script(), tmp_path, env)
    assert result.returncode != 0
    waits = calls.read_text(encoding="utf-8").split() if calls.exists() else []
    assert waits == ["7", "7"], (
        f"3 attempts should wait twice, between them, not after the last one: got {waits}"
    )


def test_the_install_step_leaves_no_temporary_files_behind(tmp_path: Path) -> None:
    """Each installer and the checksum list are fetched through `mktemp`. On a
    throwaway runner leaking them is harmless; leaving them is still the kind of
    thing that makes a later reader wonder which file is live."""
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    installer = tmp_path / "installer.sh"
    installer.write_text(
        "#!/bin/sh\n"
        'bindir="$2"\n'
        'mkdir -p "$bindir"\n'
        'for t in syft grype grant; do printf "#!/bin/sh\\ntrue\\n" > "$bindir/$t"; '
        'chmod 755 "$bindir/$t"; done\n',
        encoding="utf-8",
    )
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    _stub_bin(
        tmp_path / "stubs",
        "curl",
        'out=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac\n'
        "done\n"
        f'cp "{installer}" "$out"',
    )
    # The three fake binaries are identical, so one digest pins all of them. That
    # is what lets the step run to COMPLETION here. An earlier version of this
    # test truncated the script before `binary_sums=` -- and so never executed the
    # second temporary, the one whose cleanup this test's own docstring claims to
    # cover. Removing that `rm -f` left the suite green: a test that promised more
    # than it ran, which is the defect this whole file exists to hunt.
    binary_digest = hashlib.sha256(b"#!/bin/sh\ntrue\n").hexdigest()
    env = _install_env(
        tmp_path,
        SYFT_INSTALLER_SHA256=digest,
        GRYPE_INSTALLER_SHA256=digest,
        GRANT_INSTALLER_SHA256=digest,
        SYFT_BINARY_SHA256=binary_digest,
        GRYPE_BINARY_SHA256=binary_digest,
        GRANT_BINARY_SHA256=binary_digest,
    )
    env["TMPDIR"] = str(tmp)
    result = _run(str(_install_step()["run"]), tmp_path, env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert list(tmp.iterdir()) == [], f"temporary files left behind: {list(tmp.iterdir())}"
