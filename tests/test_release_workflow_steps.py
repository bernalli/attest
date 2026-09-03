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
    runs a script fails here rather than silently testing a weaker shell.
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
def test_uploads_refuse_to_publish_an_incomplete_artifact(job: str) -> None:
    """`if-no-files-found` defaults to `warn`: a pattern matching nothing is a
    warning and the step stays green, so an artifact can travel to the publishing
    jobs missing a wheel, an SBOM or the verifier."""
    uploads = [
        step
        for step in _workflow()["jobs"][job]["steps"]
        if "upload-artifact" in str(step.get("uses", ""))
    ]
    assert uploads, f"{job} uploads nothing"
    for step in uploads:
        assert step["with"]["if-no-files-found"] == "error"


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
