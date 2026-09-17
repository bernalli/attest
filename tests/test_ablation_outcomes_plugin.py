"""Tests for the extended keys of the ablation bench's outcomes plugin.

The plugin under test is a pytest plugin loaded into a *different* pytest
process (the one the bench spawns for each mutant). It cannot be exercised by
calling its hook functions directly with hand-built fake reports: that would
prove nothing about the plugin manager's own behavior (`list_name_plugin`,
plugin registration under `-p <module>`) or about how `pytest_sessionfinish`
sees the real environment of a *subprocess*.

So each test here builds a minimal, throwaway pytest project under
`tmp_path`, runs a real subprocess of pytest against it with the plugin
loaded via `-p outcomes_plugin`, and reads back the JSON file the plugin
writes. This never touches the machine outside `tmp_path` and never talks to
the network, so it is safe to run inside the repository's own suite.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "tools" / "gates" / "ablation"
PLUGIN_MODULE_NAME = "outcomes_plugin"


def _write_fixture_project(root: Path) -> None:
    """Create the smallest pytest project that can run and pass."""
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (root / "test_one.py").write_text(
        "def test_ok():\n    assert True\n",
        encoding="utf-8",
    )


def _run_fixture_pytest(
    root: Path,
    outcomes_path: Path,
    nonce: str | None,
    extra_args: Sequence[str] = (),
) -> dict[str, object]:
    """Run the fixture project in a subprocess with the plugin loaded.

    `nonce=None` means the caller's environment must NOT contain
    `ABLATION_NONCE` at all — the case the "absent" test asserts on. This is
    built by explicitly deleting the key from a copy of the current
    environment rather than relying on it being unset already: a value
    inherited from the CI environment would otherwise silently turn the
    "absent" case into a "present" one.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(PLUGIN_DIR), str(root)])
    env["ABLATION_OUTCOMES"] = str(outcomes_path)
    if nonce is None:
        env.pop("ABLATION_NONCE", None)
    else:
        env["ABLATION_NONCE"] = nonce

    result = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            PLUGIN_MODULE_NAME,
            *extra_args,
            ".",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"fixture pytest run failed: rc={result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert outcomes_path.exists(), (
        f"the plugin did not write {outcomes_path}\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    with outcomes_path.open(encoding="utf-8") as fh:
        return json.load(fh)


def test_nonce_key_carries_the_ablation_nonce_env_var(tmp_path: Path) -> None:
    _write_fixture_project(tmp_path)
    outcomes_path = tmp_path / "outcomes.json"
    payload = _run_fixture_pytest(tmp_path, outcomes_path, nonce="abc")
    assert payload["nonce"] == "abc"


def test_nonce_key_is_null_when_the_env_var_is_absent(tmp_path: Path) -> None:
    _write_fixture_project(tmp_path)
    outcomes_path = tmp_path / "outcomes.json"
    payload = _run_fixture_pytest(tmp_path, outcomes_path, nonce=None)
    assert payload["nonce"] is None


def test_nonce_key_is_an_empty_string_when_the_env_var_is_set_empty(tmp_path: Path) -> None:
    """An empty string is a PRESENT value, distinct from absence.

    `os.environ.get` already returns `""` (not `None`) when the variable is
    set to the empty string; this pins that the plugin does not collapse the
    two cases into the same JSON value.
    """
    _write_fixture_project(tmp_path)
    outcomes_path = tmp_path / "outcomes.json"
    payload = _run_fixture_pytest(tmp_path, outcomes_path, nonce="")
    assert payload["nonce"] == ""


def test_plugins_loaded_contains_the_outcomes_plugin_registration_name(tmp_path: Path) -> None:
    _write_fixture_project(tmp_path)
    outcomes_path = tmp_path / "outcomes.json"
    payload = _run_fixture_pytest(tmp_path, outcomes_path, nonce=None)
    plugins_loaded = payload["plugins_loaded"]
    assert isinstance(plugins_loaded, list)
    assert PLUGIN_MODULE_NAME in plugins_loaded
    assert None not in plugins_loaded


def test_plugins_loaded_omits_a_plugin_blocked_on_the_command_line(tmp_path: Path) -> None:
    """`-p no:cacheprovider` registers the name with no plugin behind it: it was never loaded."""
    _write_fixture_project(tmp_path)
    payload = _run_fixture_pytest(tmp_path, tmp_path / "outcomes.json", nonce=None)
    plugins_loaded = payload["plugins_loaded"]
    assert isinstance(plugins_loaded, list)
    assert "cacheprovider" not in plugins_loaded


def test_plugins_loaded_names_a_dotted_plugin_as_passed_and_only_when_loaded(
    tmp_path: Path,
) -> None:
    """`-p package.module` is listed under that dotted name; `-p no:package.module` is not."""
    _write_fixture_project(tmp_path)
    package = tmp_path / "mutpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    marker = tmp_path / "configured"
    (package / "mutant_plugin.py").write_text(
        "import pathlib\n\n\ndef pytest_configure(config):\n"
        f"    pathlib.Path({str(marker)!r}).write_text('x')\n",
        encoding="utf-8",
    )

    loaded = _run_fixture_pytest(
        tmp_path, tmp_path / "loaded.json", nonce=None, extra_args=("-p", "mutpkg.mutant_plugin")
    )
    assert marker.exists(), "the plugin passed with -p was not configured"
    loaded_names = loaded["plugins_loaded"]
    assert isinstance(loaded_names, list)
    assert "mutpkg.mutant_plugin" in loaded_names

    marker.unlink()
    blocked = _run_fixture_pytest(
        tmp_path,
        tmp_path / "blocked.json",
        nonce=None,
        extra_args=("-p", "no:mutpkg.mutant_plugin"),
    )
    assert not marker.exists(), "the plugin blocked with -p no: was configured"
    blocked_names = blocked["plugins_loaded"]
    assert isinstance(blocked_names, list)
    assert "mutpkg.mutant_plugin" not in blocked_names
