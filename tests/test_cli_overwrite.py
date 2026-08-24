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

CapSys = pytest.CaptureFixture[str]

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


# --- keygen -----------------------------------------------------------------


def _keygen_argv(
    tmp_path: Path, name: str, *, hybrid: bool = False, force: bool = False
) -> list[str]:
    argv = [
        "keygen",
        "--seed-out",
        str(tmp_path / f"{name}.seed"),
        "--pub-out",
        str(tmp_path / f"{name}.pub"),
    ]
    if hybrid:
        argv += ["--hybrid", "--mldsa-out", str(tmp_path / f"{name}.mldsa")]
    if force:
        argv.append("--force")
    return argv


def test_keygen_refuses_an_existing_seed_out(tmp_path: Path, capsys: CapSys) -> None:
    """A seed is the issuer identity and every generated one is new, so a
    re-run always has different content: it always refuses without --force."""
    seed_out = tmp_path / "id.seed"
    assert cli.main(_keygen_argv(tmp_path, "id")) == 0
    first = seed_out.read_text(encoding="utf-8")
    capsys.readouterr()

    assert cli.main(_keygen_argv(tmp_path, "id")) == 2
    err = capsys.readouterr().err
    assert "--seed-out" in err
    assert str(seed_out) in err
    assert "refusing to overwrite" in err
    assert seed_out.read_text(encoding="utf-8") == first


def test_keygen_refuses_before_touching_any_output(tmp_path: Path, capsys: CapSys) -> None:
    """Two-phase: all guards run before the first write, so a refusal leaves
    no partial state behind."""
    seed_out = tmp_path / "taken.seed"
    pub_out = tmp_path / "fresh.pub"
    seed_out.write_text("previous-identity", encoding="utf-8")

    rc = cli.main(["keygen", "--seed-out", str(seed_out), "--pub-out", str(pub_out)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "--seed-out" in err
    assert str(seed_out) in err
    assert "refusing to overwrite" in err
    assert seed_out.read_text(encoding="utf-8") == "previous-identity"
    assert not pub_out.exists()


def test_keygen_refuses_an_existing_mldsa_out(tmp_path: Path, capsys: CapSys) -> None:
    mldsa_out = tmp_path / "hy.mldsa"
    seed_out = tmp_path / "hy.seed"
    mldsa_out.write_text("previous-ml-dsa-secret", encoding="utf-8")

    rc = cli.main(_keygen_argv(tmp_path, "hy", hybrid=True))
    err = capsys.readouterr().err
    assert rc == 2
    assert "--mldsa-out" in err
    assert str(mldsa_out) in err
    assert "refusing to overwrite" in err
    assert mldsa_out.read_text(encoding="utf-8") == "previous-ml-dsa-secret"
    assert not seed_out.exists()


def test_keygen_force_regenerates_and_keeps_0600(tmp_path: Path, capsys: CapSys) -> None:
    seed_out = tmp_path / "id.seed"
    pub_out = tmp_path / "id.pub"
    assert cli.main(_keygen_argv(tmp_path, "id")) == 0
    first_seed = seed_out.read_text(encoding="utf-8")
    first_pub = pub_out.read_text(encoding="utf-8")
    seed_out.chmod(0o644)
    capsys.readouterr()

    assert cli.main(_keygen_argv(tmp_path, "id", force=True)) == 0
    assert seed_out.read_text(encoding="utf-8") != first_seed
    assert pub_out.read_text(encoding="utf-8") != first_pub
    assert stat.S_IMODE(seed_out.stat().st_mode) == 0o600


def test_keygen_overwrites_an_existing_pub_out(tmp_path: Path, capsys: CapSys) -> None:
    """Classification pin: --pub-out is derivable from the seed, so it stays
    unguarded and a stale public key is silently replaced."""
    pub_out = tmp_path / "id.pub"
    pub_out.write_text("stale-public-key", encoding="utf-8")

    assert cli.main(_keygen_argv(tmp_path, "id")) == 0
    assert pub_out.read_text(encoding="utf-8") != "stale-public-key"


# --- manifest init / rotate -------------------------------------------------

_ISSUER = "store.example.com"
_KID = f"{_ISSUER}/keys/test-1#ed25519-1"
_VALID_FROM = "2026-01-01T00:00:00Z"


def _make_keypair(tmp_path: Path, name: str) -> Path:
    assert cli.main(_keygen_argv(tmp_path, name)) == 0
    return tmp_path / f"{name}.seed"


def _make_hybrid_keypair(tmp_path: Path, name: str) -> tuple[Path, Path]:
    assert cli.main(_keygen_argv(tmp_path, name, hybrid=True)) == 0
    return tmp_path / f"{name}.seed", tmp_path / f"{name}.mldsa"


def _manifest_init_argv(
    seed: Path,
    out: Path,
    *,
    issued_at: str = _VALID_FROM,
    mldsa_key: Path | None = None,
    force: bool = False,
) -> list[str]:
    argv = [
        "manifest",
        "init",
        "--issuer",
        _ISSUER,
        "--kid",
        _KID,
        "--seed",
        str(seed),
        "--valid-from",
        _VALID_FROM,
        "--issued-at",
        issued_at,
        "--out",
        str(out),
    ]
    if mldsa_key is not None:
        argv += ["--mldsa-key", str(mldsa_key)]
    if force:
        argv.append("--force")
    return argv


def test_manifest_init_refuses_a_different_manifest(tmp_path: Path, capsys: CapSys) -> None:
    """A published trust root is the anchor other people already pinned."""
    seed = _make_keypair(tmp_path, "issuer")
    out = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, out)) == 0
    first = out.read_text(encoding="utf-8")
    capsys.readouterr()

    rc = cli.main(_manifest_init_argv(seed, out, issued_at="2026-03-01T00:00:00Z"))
    err = capsys.readouterr().err
    assert rc == 2
    assert "--out" in err
    assert str(out) in err
    assert "refusing to overwrite" in err
    assert out.read_text(encoding="utf-8") == first


def test_manifest_init_reruns_identically_without_force(tmp_path: Path, capsys: CapSys) -> None:
    """Identity clause: Ed25519 signatures are deterministic and the JSON is
    sorted, so re-running with identical arguments rewrites the same bytes."""
    seed = _make_keypair(tmp_path, "issuer")
    out = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, out)) == 0
    first = out.read_text(encoding="utf-8")
    capsys.readouterr()

    assert cli.main(_manifest_init_argv(seed, out)) == 0
    assert out.read_text(encoding="utf-8") == first


def test_manifest_init_hybrid_rerun_refuses(tmp_path: Path, capsys: CapSys) -> None:
    """ML-DSA-65 signing is hedged (randomized), so even a byte-for-byte
    identical invocation produces a different signature and is refused."""
    seed, mldsa_key = _make_hybrid_keypair(tmp_path, "issuer")
    out = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, out, mldsa_key=mldsa_key)) == 0
    first = out.read_text(encoding="utf-8")
    capsys.readouterr()

    rc = cli.main(_manifest_init_argv(seed, out, mldsa_key=mldsa_key))
    err = capsys.readouterr().err
    assert rc == 2
    assert "--out" in err
    assert str(out) in err
    assert "refusing to overwrite" in err
    assert out.read_text(encoding="utf-8") == first


def test_manifest_init_force_replaces(tmp_path: Path, capsys: CapSys) -> None:
    seed = _make_keypair(tmp_path, "issuer")
    out = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, out)) == 0
    first = out.read_text(encoding="utf-8")
    capsys.readouterr()

    rc = cli.main(_manifest_init_argv(seed, out, issued_at="2026-03-01T00:00:00Z", force=True))
    assert rc == 0
    assert out.read_text(encoding="utf-8") != first


def test_manifest_rotate_refuses_an_existing_out(tmp_path: Path, capsys: CapSys) -> None:
    """A rotation is a link in the continuity chain v(N) -> v(N+1)."""
    seed = _make_keypair(tmp_path, "issuer")
    manifest = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, manifest)) == 0
    new_pub = tmp_path / "next.pub"
    assert cli.main(_keygen_argv(tmp_path, "next")) == 0
    rotated = tmp_path / "manifest.v2.json"
    rotated.write_text("a previously rotated manifest", encoding="utf-8")
    capsys.readouterr()

    argv = [
        "manifest",
        "rotate",
        "--in",
        str(manifest),
        "--signing-kid",
        _KID,
        "--signing-seed",
        str(seed),
        "--new-kid",
        f"{_ISSUER}/keys/test-2#ed25519-1",
        "--new-pub",
        str(new_pub),
        "--valid-from",
        "2026-02-01T00:00:00Z",
        "--issued-at",
        "2026-02-01T00:00:00Z",
        "--out",
        str(rotated),
    ]
    rc = cli.main(argv)
    err = capsys.readouterr().err
    assert rc == 2
    assert "--out" in err
    assert str(rotated) in err
    assert "refusing to overwrite" in err
    assert rotated.read_text(encoding="utf-8") == "a previously rotated manifest"

    assert cli.main([*argv, "--force"]) == 0
    assert rotated.read_text(encoding="utf-8") != "a previously rotated manifest"
