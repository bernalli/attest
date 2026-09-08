"""An absent environment must not impersonate a failed importer measurement."""

from pathlib import Path
from subprocess import CompletedProcess

import pytest

from tools import importer_differential as differential


@pytest.mark.parametrize("missing", ["esbuild", "node", "verifier build"])
def test_missing_prerequisite_has_its_own_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing: str,
) -> None:
    esbuild = tmp_path / "esbuild"
    if missing != "esbuild":
        esbuild.touch()
    monkeypatch.setattr(differential, "ESBUILD", esbuild)
    monkeypatch.setattr(differential, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        differential.shutil, "which", lambda _: None if missing == "node" else "node"
    )
    assert differential.main(["--families", "baseline"]) == 78
    captured = capsys.readouterr()
    assert "PRECONDITION ABSENT: missing" in captured.err
    assert missing in captured.err
    assert "archives fed" not in captured.out


def test_present_but_failing_bundler_is_a_failed_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    esbuild = tmp_path / "esbuild"
    esbuild.touch()
    built = tmp_path / "verifiers/ts/dist/index.js"
    built.parent.mkdir(parents=True)
    built.touch()
    monkeypatch.setattr(differential, "ESBUILD", esbuild)
    monkeypatch.setattr(differential, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(differential.shutil, "which", lambda _: "node")
    monkeypatch.setattr(
        differential.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess([], 1, "", "injected bundle failure"),
    )
    with pytest.raises(SystemExit, match="could not bundle") as error:
        differential.build_ts_bundle(tmp_path)
    # A string SystemExit is process status 1, as for a measured divergence.
    assert isinstance(error.value.code, str)
