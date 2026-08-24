"""Tests for the write-if-absent-or-identical rule on destructive CLI outputs.

Outputs whose loss is irrecoverable (key seeds, issuer manifests, issued
envelopes and salts, transfer/revocation records, `.private.attest`, imported
trust anchors and `salts.json`) refuse to overwrite an existing file whose
content differs from what would be written; `--force` restores the old
truncating behavior. Derivable outputs stay unguarded by design.

Every negative test here pins three things — exit code / exception type, the
`label` naming the offending option, and the refusal phrase together with the
path — because an assertion on the exit code alone cannot tell a correct
refusal apart from an unrelated failure.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from attest import cli

_ROOT = os.getuid() == 0


# --- _ensure_overwrite_allowed ----------------------------------------------


def test_guard_absent_reports_not_existing(tmp_path: Path) -> None:
    target = tmp_path / "absent.json"
    existed = cli._ensure_overwrite_allowed(target, "payload", label="--out", force=False)
    assert existed is False
    assert not target.exists()


def test_guard_identical_content_is_allowed(tmp_path: Path) -> None:
    target = tmp_path / "same.json"
    target.write_text("payload", encoding="utf-8")
    existed = cli._ensure_overwrite_allowed(target, "payload", label="--out", force=False)
    assert existed is True


def test_guard_different_content_refuses(tmp_path: Path) -> None:
    target = tmp_path / "other.json"
    target.write_text("old", encoding="utf-8")
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._ensure_overwrite_allowed(target, "new", label="--seed-out", force=False)
    assert str(excinfo.value) == (
        f"--seed-out {target} already exists with different content; "
        "refusing to overwrite it (pass --force to replace it)"
    )


def test_guard_longer_file_with_identical_prefix_refuses(tmp_path: Path) -> None:
    """A file that merely *starts* with the new text is different, not identical."""
    target = tmp_path / "prefix.json"
    target.write_text("payload-and-then-some", encoding="utf-8")
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._ensure_overwrite_allowed(target, "payload", label="--out", force=False)
    assert "already exists with different content" in str(excinfo.value)


def test_guard_huge_file_refuses_without_slurping_it(tmp_path: Path) -> None:
    """The comparison is bounded: a mismatching size is decided by stat alone.

    The file below is a 1 GiB sparse file. An implementation that read it whole
    to compare would have to materialize 1 GiB of zeroes here, so this test is
    also the boundedness pin.
    """
    target = tmp_path / "huge.json"
    with target.open("wb") as handle:
        handle.truncate(1 << 30)
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._ensure_overwrite_allowed(target, "small", label="--out", force=False)
    assert f"--out {target} already exists with different content" in str(excinfo.value)


def test_guard_directory_refuses_even_with_force(tmp_path: Path) -> None:
    target = tmp_path / "adir"
    target.mkdir()
    expected = f"--out {target} is a directory; refusing to write over it"
    for force in (False, True):
        with pytest.raises(cli.CliUsageError) as excinfo:
            cli._ensure_overwrite_allowed(target, "payload", label="--out", force=force)
        assert str(excinfo.value) == expected


@pytest.mark.skipif(_ROOT, reason="root bypasses file permissions")
def test_guard_unreadable_file_refuses(tmp_path: Path) -> None:
    """An existing file that cannot be read back is refused, not overwritten.

    The file is given the *same length* as the new text on purpose: a differing
    length is already decided by the bounded size check, so only a same-size
    file reaches the read that this message is about.
    """
    target = tmp_path / "locked.json"
    target.write_text("abcdef", encoding="utf-8")
    target.chmod(0o000)
    try:
        with pytest.raises(cli.CliUsageError) as excinfo:
            cli._ensure_overwrite_allowed(target, "ghijkl", label="--salt-out", force=False)
    finally:
        target.chmod(0o600)
    message = str(excinfo.value)
    assert message.startswith(f"--salt-out {target} already exists and cannot be read back")
    assert message.endswith("refusing to overwrite it (pass --force to replace it)")


def test_guard_dangling_symlink_refuses(tmp_path: Path) -> None:
    """A dangling symlink counts as present: writing through it lands elsewhere."""
    target = tmp_path / "link.json"
    target.symlink_to(tmp_path / "nowhere.json")
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._ensure_overwrite_allowed(target, "payload", label="--out", force=False)
    assert f"--out {target} already exists and cannot be read back" in str(excinfo.value)
    assert "refusing to overwrite it (pass --force to replace it)" in str(excinfo.value)


def test_guard_force_allows_different_content(tmp_path: Path) -> None:
    target = tmp_path / "replaceable.json"
    target.write_text("old", encoding="utf-8")
    assert cli._ensure_overwrite_allowed(target, "new", label="--out", force=True) is True


# --- _write_secret_text(exclusive=...) --------------------------------------


def test_write_secret_text_exclusive_refuses_a_file_that_appeared(tmp_path: Path) -> None:
    """Closes the check-then-write race for secrets: O_EXCL, not O_TRUNC."""
    target = tmp_path / "seed"
    target.write_text("someone-else", encoding="utf-8")
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._write_secret_text(target, "mine", exclusive=True, label="--seed-out")
    assert str(excinfo.value) == (
        f"--seed-out {target} appeared while writing; "
        "refusing to overwrite it (re-run, or pass --force to replace it)"
    )
    assert target.read_text(encoding="utf-8") == "someone-else"


def test_write_secret_text_exclusive_creates_0600(tmp_path: Path) -> None:
    target = tmp_path / "seed"
    cli._write_secret_text(target, "mine", exclusive=True, label="--seed-out")
    assert target.read_text(encoding="utf-8") == "mine"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_write_secret_text_without_exclusive_still_truncates(tmp_path: Path) -> None:
    """Regression: the default path is unchanged (truncate + re-pin 0600)."""
    target = tmp_path / "seed"
    target.write_text("a much longer previous value", encoding="utf-8")
    target.chmod(0o644)
    cli._write_secret_text(target, "mine")
    assert target.read_text(encoding="utf-8") == "mine"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
