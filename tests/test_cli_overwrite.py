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

import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from attest import cli, keys, transfer
from tests.helpers import make_payload

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


def test_guard_refuses_hardlinked_file_even_with_force(tmp_path: Path) -> None:
    target = tmp_path / "seed"
    target.write_text("existing seed", encoding="utf-8")
    alias = tmp_path / "seed.alias"
    try:
        os.link(target, alias)
    except OSError:
        pytest.skip("hard links unsupported on this filesystem")

    for force in (False, True):
        with pytest.raises(cli.CliUsageError) as excinfo:
            cli._ensure_overwrite_allowed(target, "existing seed", label="--seed-out", force=force)
        message = str(excinfo.value)
        assert message.startswith(f"--seed-out {target} has multiple hard links")
        assert "refusing to overwrite" in message
        assert alias.read_text(encoding="utf-8") == "existing seed"


# --- _write_json_text(exclusive=...) ----------------------------------------


def test_write_json_text_exclusive_refuses_a_file_that_appeared(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    target.write_text("someone-else", encoding="utf-8")
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._write_json_text(target, "mine", exclusive=True, label="--out")
    assert str(excinfo.value) == (
        f"--out {target} appeared while writing; "
        "refusing to overwrite it (re-run, or pass --force to replace it)"
    )
    assert target.read_text(encoding="utf-8") == "someone-else"


def test_write_json_text_exclusive_refuses_a_symlink_that_appeared(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    victim = tmp_path / "victim.json"
    victim.write_text("keep me", encoding="utf-8")
    try:
        target.symlink_to(victim)
    except OSError:
        pytest.skip("symlinks unsupported on this filesystem")

    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._write_json_text(target, "replace", exclusive=True, label="--out")
    assert str(excinfo.value) == (
        f"--out {target} appeared while writing; "
        "refusing to overwrite it (re-run, or pass --force to replace it)"
    )
    assert victim.read_text(encoding="utf-8") == "keep me"


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


def test_write_secret_text_refuses_hardlinked_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "seed"
    target.write_text("existing seed", encoding="utf-8")
    alias = tmp_path / "seed.alias"
    try:
        os.link(target, alias)
    except OSError:
        pytest.skip("hard links unsupported on this filesystem")

    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._write_secret_text(target, "mine", label="--seed-out")
    message = str(excinfo.value)
    assert message.startswith(f"--seed-out {target} has multiple hard links")
    assert "refusing to overwrite" in message
    assert alias.read_text(encoding="utf-8") == "existing seed"


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


# --- issue ------------------------------------------------------------------

_NEW_HOLDER_PUB_B64U = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 32 zero bytes
_TRANSFERRED_AT = "2026-07-23T00:00:00Z"


def _write_payload(tmp_path: Path, name: str, **overrides: object) -> Path:
    payload = make_payload(issuer={"id": _ISSUER, "display_name": "Example Store"}, **overrides)
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _issue_argv(
    seed: Path,
    payload_path: Path,
    out: Path,
    *,
    salt: Path | None = None,
    salt_out: Path | None = None,
    force: bool = False,
) -> list[str]:
    argv = [
        "issue",
        "--payload",
        str(payload_path),
        "--seed",
        str(seed),
        "--kid",
        _KID,
        "--out",
        str(out),
    ]
    if salt is not None:
        argv += ["--salt", str(salt)]
    if salt_out is not None:
        argv += ["--salt-out", str(salt_out)]
    if force:
        argv.append("--force")
    return argv


def test_issue_refuses_a_different_envelope(tmp_path: Path, capsys: CapSys) -> None:
    """A logged receipt is pinned by core_sha256 over the signed core, signature
    included (spec v0.2 section 8): a replaced envelope orphans its inclusion proof."""
    seed = _make_keypair(tmp_path, "issuer")
    out = tmp_path / "envelope.json"
    first_payload = _write_payload(tmp_path, "a.json", receipt_id="01ARZ3NDEKTSV4RRFFQ69G5FAV")
    second_payload = _write_payload(tmp_path, "b.json", receipt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW")
    assert cli.main(_issue_argv(seed, first_payload, out)) == 0
    first = out.read_text(encoding="utf-8")
    capsys.readouterr()

    rc = cli.main(_issue_argv(seed, second_payload, out))
    err = capsys.readouterr().err
    assert rc == 2
    assert "--out" in err
    assert str(out) in err
    assert "refusing to overwrite" in err
    assert out.read_text(encoding="utf-8") == first

    assert cli.main(_issue_argv(seed, second_payload, out, force=True)) == 0
    assert out.read_text(encoding="utf-8") != first


def test_issue_reruns_identically_without_force(tmp_path: Path, capsys: CapSys) -> None:
    """An Ed25519-only re-issue of identical inputs is byte-identical, so the
    identity clause costs legitimate re-runs nothing."""
    seed = _make_keypair(tmp_path, "issuer")
    out = tmp_path / "envelope.json"
    payload = _write_payload(tmp_path, "a.json")
    assert cli.main(_issue_argv(seed, payload, out)) == 0
    first = out.read_text(encoding="utf-8")
    capsys.readouterr()

    assert cli.main(_issue_argv(seed, payload, out)) == 0
    assert out.read_text(encoding="utf-8") == first


def test_issue_refuses_a_different_salt_out(tmp_path: Path, capsys: CapSys) -> None:
    """The buyer-binding salt is a bearer secret with no other copy."""
    seed = _make_keypair(tmp_path, "issuer")
    payload = _write_payload(tmp_path, "a.json")
    salt = tmp_path / "salt.b64u"
    salt.write_text(keys.b64u(bytes(range(16))), encoding="utf-8")
    out = tmp_path / "envelope.json"
    salt_out = tmp_path / "salt-out.b64u"
    salt_out.write_text(keys.b64u(bytes(16)), encoding="utf-8")
    capsys.readouterr()

    rc = cli.main(_issue_argv(seed, payload, out, salt=salt, salt_out=salt_out))
    err = capsys.readouterr().err
    assert rc == 2
    assert "--salt-out" in err
    assert str(salt_out) in err
    assert "refusing to overwrite" in err
    assert salt_out.read_text(encoding="utf-8") == keys.b64u(bytes(16))
    # Two-phase: the guard on --salt-out ran before the envelope was written.
    assert not out.exists()


def test_issue_refuses_before_writing_the_salt(tmp_path: Path, capsys: CapSys) -> None:
    """Mirror of the above: a refusal on --out leaves --salt-out untouched."""
    seed = _make_keypair(tmp_path, "issuer")
    payload = _write_payload(tmp_path, "a.json")
    salt = tmp_path / "salt.b64u"
    salt.write_text(keys.b64u(bytes(range(16))), encoding="utf-8")
    out = tmp_path / "envelope.json"
    out.write_text("a previously issued envelope", encoding="utf-8")
    salt_out = tmp_path / "salt-out.b64u"
    capsys.readouterr()

    rc = cli.main(_issue_argv(seed, payload, out, salt=salt, salt_out=salt_out))
    err = capsys.readouterr().err
    assert rc == 2
    assert "--out" in err
    assert str(out) in err
    assert "refusing to overwrite" in err
    assert out.read_text(encoding="utf-8") == "a previously issued envelope"
    assert not salt_out.exists()


# --- transfer record --------------------------------------------------------


def _transfer_record_argv(
    tmp_path: Path,
    seed: Path,
    out: Path,
    *,
    revocation_out: Path | None = None,
    force: bool = False,
) -> list[str]:
    holder_kp = keys.generate()
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    payload_path = _write_payload(
        tmp_path,
        "old-payload.json",
        receipt_id=old_receipt_id,
        buyer={"pubkey": keys.b64u(holder_kp.pub)},
    )
    receipt_path = tmp_path / "old-envelope.json"
    assert cli.main(_issue_argv(seed, payload_path, receipt_path)) == 0
    sig = transfer.sign_authorization(
        old_receipt_id, _NEW_HOLDER_PUB_B64U, _TRANSFERRED_AT, holder_kp
    )
    authorization_path = tmp_path / "authorization.json"
    authorization_path.write_text(json.dumps({"sig": keys.b64u(sig)}), encoding="utf-8")

    argv = [
        "transfer",
        "record",
        "--receipt",
        str(receipt_path),
        "--new-receipt-id",
        "01ARZ3NDEKTSV4RRFFQ69G5FAW",
        "--new-holder-pubkey",
        _NEW_HOLDER_PUB_B64U,
        "--transferred-at",
        _TRANSFERRED_AT,
        "--holder-authorization",
        str(authorization_path),
        "--seed",
        str(seed),
        "--kid",
        _KID,
        "--out",
        str(out),
    ]
    if revocation_out is not None:
        argv += ["--revocation-out", str(revocation_out)]
    if force:
        argv.append("--force")
    return argv


def test_transfer_record_refuses_an_existing_out(tmp_path: Path, capsys: CapSys) -> None:
    """record_sha256 covers the whole signed record including its own signature
    (spec v0.2 section 8), and section 17.4 gives the earliest logged record the
    win forever: a lost record can never be regenerated into the same standing."""
    seed = _make_keypair(tmp_path, "issuer")
    out = tmp_path / "record.json"
    out.write_text("a previously logged transfer record", encoding="utf-8")
    argv = _transfer_record_argv(tmp_path, seed, out)
    capsys.readouterr()

    rc = cli.main(argv)
    err = capsys.readouterr().err
    assert rc == 2
    assert "--out" in err
    assert str(out) in err
    assert "refusing to overwrite" in err
    assert out.read_text(encoding="utf-8") == "a previously logged transfer record"

    assert cli.main([*argv, "--force"]) == 0
    assert out.read_text(encoding="utf-8") != "a previously logged transfer record"


def test_transfer_record_refuses_an_existing_revocation_out(tmp_path: Path, capsys: CapSys) -> None:
    """Same record_sha256 discipline, and for refund_window the effect depends
    on the log standing of that exact record (spec v0.2 section 15, item 5)."""
    seed = _make_keypair(tmp_path, "issuer")
    out = tmp_path / "record.json"
    revocation_out = tmp_path / "revocation.json"
    revocation_out.write_text("a previously logged revocation record", encoding="utf-8")
    argv = _transfer_record_argv(tmp_path, seed, out, revocation_out=revocation_out)
    capsys.readouterr()

    rc = cli.main(argv)
    err = capsys.readouterr().err
    assert rc == 2
    assert "--revocation-out" in err
    assert str(revocation_out) in err
    assert "refusing to overwrite" in err
    assert revocation_out.read_text(encoding="utf-8") == "a previously logged revocation record"
    # Two-phase: both guards ran before the transfer record itself was written.
    assert not out.exists()


# --- export -----------------------------------------------------------------

_BUNDLE_NAME = "mylibrary"


def _export_fixture(tmp_path: Path) -> tuple[list[str], Path]:
    """Build a minimal exportable set and return (argv, out_dir)."""
    seed = _make_keypair(tmp_path, "issuer")
    manifest_path = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, manifest_path)) == 0
    payload_path = _write_payload(tmp_path, "payload.json")
    envelope_path = tmp_path / "envelope.json"
    assert cli.main(_issue_argv(seed, payload_path, envelope_path)) == 0

    legal_text_path = tmp_path / "legal.txt"
    legal_text_path.write_bytes(b"attest-test-legal-text-v1")
    mirror_policy_path = tmp_path / "mirror-policy.txt"
    mirror_policy_path.write_bytes(b"attest-test-mirror-policy-v1")

    out_dir = tmp_path / "bundle_out"
    argv = [
        "export",
        "--receipt",
        str(envelope_path),
        "--key-manifest",
        str(manifest_path),
        "--legal-text",
        str(legal_text_path),
        "--legal-text",
        str(mirror_policy_path),
        "--out-dir",
        str(out_dir),
        "--name",
        _BUNDLE_NAME,
    ]
    return argv, out_dir


def test_export_refuses_an_existing_private_bundle(tmp_path: Path, capsys: CapSys) -> None:
    """`.private.attest` is excluded from the identity clause: a zip is not
    byte-reproducible even at identical logical content, so it is refused on
    mere existence rather than compared."""
    argv, out_dir = _export_fixture(tmp_path)
    private_path = out_dir / f"{_BUNDLE_NAME}.private.attest"
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(b"a previously exported private bundle")
    capsys.readouterr()

    rc = cli.main(argv)
    err = capsys.readouterr().err
    assert rc == 2
    assert err.strip() == (
        f"error: --out-dir already contains {private_path}; "
        "refusing to overwrite a .private.attest (pass --force to replace it)"
    )
    assert private_path.read_bytes() == b"a previously exported private bundle"


def test_export_force_replaces_the_private_bundle(tmp_path: Path, capsys: CapSys) -> None:
    argv, out_dir = _export_fixture(tmp_path)
    private_path = out_dir / f"{_BUNDLE_NAME}.private.attest"
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(b"a previously exported private bundle")
    capsys.readouterr()

    assert cli.main([*argv, "--force"]) == 0
    assert private_path.read_bytes() != b"a previously exported private bundle"


def test_export_force_refuses_hardlinked_private_bundle(tmp_path: Path, capsys: CapSys) -> None:
    argv, out_dir = _export_fixture(tmp_path)
    private_path = out_dir / f"{_BUNDLE_NAME}.private.attest"
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(b"a previously exported private bundle")
    alias = tmp_path / "private-alias.attest"
    try:
        os.link(private_path, alias)
    except OSError:
        pytest.skip("hard links unsupported on this filesystem")
    capsys.readouterr()

    rc = cli.main([*argv, "--force"])
    err = capsys.readouterr().err
    assert rc == 2
    assert ".private.attest" in err
    assert str(private_path) in err
    assert "refusing to overwrite" in err
    assert alias.read_bytes() == b"a previously exported private bundle"


def test_export_refuses_private_bundle_symlink_that_appears_after_guard(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv, out_dir = _export_fixture(tmp_path)
    private_path = out_dir / f"{_BUNDLE_NAME}.private.attest"
    victim = tmp_path / "victim.private.attest"
    victim.write_bytes(b"keep me")

    original_path_is_present = cli._path_is_present

    def swap_in_symlink(path: Path) -> bool:
        present = original_path_is_present(path)
        if path == private_path and not present:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path.symlink_to(victim)
            except OSError:
                pytest.skip("symlinks unsupported on this filesystem")
        return present

    monkeypatch.setattr(cli, "_path_is_present", swap_in_symlink)
    capsys.readouterr()

    rc = cli.main(argv)
    err = capsys.readouterr().err
    assert rc == 2
    assert ".private.attest" in err
    assert str(private_path) in err
    assert "refusing to overwrite" in err
    assert victim.read_bytes() == b"keep me"


def test_export_overwrites_the_shareable_bundle(tmp_path: Path, capsys: CapSys) -> None:
    """Classification pin: the shareable `.attest` is recomputable from inputs
    that all stay on local disk, so it is deliberately unguarded."""
    argv, out_dir = _export_fixture(tmp_path)
    attest_path = out_dir / f"{_BUNDLE_NAME}.attest"
    attest_path.parent.mkdir(parents=True, exist_ok=True)
    attest_path.write_bytes(b"a previously exported shareable bundle")
    capsys.readouterr()

    assert cli.main(argv) == 0
    assert attest_path.read_bytes() != b"a previously exported shareable bundle"


def test_export_guard_path_matches_the_path_bundle_export_returns(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Anti-drift pin: the guard precomputes the private bundle filename in
    cli.py while bundle.py builds it independently. If the bundle naming scheme
    changes, this fails loudly instead of silently unguarding the secrets."""
    argv, out_dir = _export_fixture(tmp_path)
    capsys.readouterr()

    assert cli.main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["private"] == str(out_dir / f"{_BUNDLE_NAME}.private.attest")
    assert report["attest"] == str(out_dir / f"{_BUNDLE_NAME}.attest")


# --- import -----------------------------------------------------------------


def _raw_manifest_bundle(
    tmp_path: Path, name: str, manifest_blobs: list[tuple[str, dict[str, object]]]
) -> Path:
    bundle_path = tmp_path / f"{name}.attest"
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member_name, blob in manifest_blobs:
            zf.writestr(f"manifests/{member_name}.json", json.dumps(blob))
    return bundle_path


def _manifest_blob(issuer: str, manifest_version: object) -> dict[str, object]:
    return {
        "issuer": issuer,
        "key_manifests": [
            {
                "issuer": issuer,
                "manifest_version": manifest_version,
                "keys": [],
            }
        ],
        "artifact_manifests": [],
    }


def _export_bundle(
    tmp_path: Path,
    manifest_path: Path,
    envelope_path: Path,
    name: str,
) -> tuple[Path, Path]:
    """Export one bundle into its own directory; return (shareable, private)."""
    legal_text_path = tmp_path / "legal.txt"
    legal_text_path.write_bytes(b"attest-test-legal-text-v1")
    mirror_policy_path = tmp_path / "mirror-policy.txt"
    mirror_policy_path.write_bytes(b"attest-test-mirror-policy-v1")
    out_dir = tmp_path / f"bundle_{name}"
    rc = cli.main(
        [
            "export",
            "--receipt",
            str(envelope_path),
            "--key-manifest",
            str(manifest_path),
            "--legal-text",
            str(legal_text_path),
            "--legal-text",
            str(mirror_policy_path),
            "--out-dir",
            str(out_dir),
            "--name",
            name,
        ]
    )
    assert rc == 0
    return out_dir / f"{name}.attest", out_dir / f"{name}.private.attest"


def test_import_refuses_a_conflicting_trust_anchor(tmp_path: Path, capsys: CapSys) -> None:
    """Trust anchors are pinned TOFU: a *different* bundle rewriting
    `<issuer>.vN.json` is exactly the attack this refusal blocks."""
    seed = _make_keypair(tmp_path, "issuer")
    manifest_a = tmp_path / "manifest-a.json"
    assert cli.main(_manifest_init_argv(seed, manifest_a)) == 0
    manifest_b = tmp_path / "manifest-b.json"
    assert cli.main(_manifest_init_argv(seed, manifest_b, issued_at="2026-03-01T00:00:00Z")) == 0

    payload_a = _write_payload(tmp_path, "pa.json", receipt_id="01ARZ3NDEKTSV4RRFFQ69G5FAV")
    envelope_a = tmp_path / "envelope-a.json"
    assert cli.main(_issue_argv(seed, payload_a, envelope_a)) == 0
    payload_b = _write_payload(tmp_path, "pb.json", receipt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW")
    envelope_b = tmp_path / "envelope-b.json"
    assert cli.main(_issue_argv(seed, payload_b, envelope_b)) == 0

    bundle_a, _ = _export_bundle(tmp_path, manifest_a, envelope_a, "a")
    bundle_b, _ = _export_bundle(tmp_path, manifest_b, envelope_b, "b")

    out_dir = tmp_path / "imported"
    assert cli.main(["import", "--bundle", str(bundle_a), "--out-dir", str(out_dir)]) == 0
    trust_file = out_dir / "trust" / f"{cli._safe_name(_ISSUER)}.v1.json"
    pinned = trust_file.read_text(encoding="utf-8")
    capsys.readouterr()

    rc = cli.main(["import", "--bundle", str(bundle_b), "--out-dir", str(out_dir)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "import: trust-store file" in err
    assert str(trust_file) in err
    assert "refusing to overwrite" in err
    assert trust_file.read_text(encoding="utf-8") == pinned
    # Two-phase: every guard ran before the first write, so the second bundle's
    # receipt was never extracted either.
    assert not (out_dir / "receipts" / "01ARZ3NDEKTSV4RRFFQ69G5FAW.attest.json").exists()

    assert (
        cli.main(["import", "--bundle", str(bundle_b), "--out-dir", str(out_dir), "--force"]) == 0
    )
    assert trust_file.read_text(encoding="utf-8") != pinned


def test_import_refuses_colliding_trust_store_paths_from_one_bundle(
    tmp_path: Path, capsys: CapSys
) -> None:
    bundle_path = _raw_manifest_bundle(
        tmp_path,
        "collision",
        [
            ("slash", _manifest_blob("store/example", 1)),
            ("underscore", _manifest_blob("store_example", 1)),
        ],
    )
    out_dir = tmp_path / "imported"
    trust_path = out_dir / "trust" / "store_example.v1.json"
    capsys.readouterr()

    rc = cli.main(["import", "--bundle", str(bundle_path), "--out-dir", str(out_dir)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "import: trust-store file" in err
    assert str(trust_path) in err
    assert "refusing to overwrite" in err
    assert not trust_path.exists()


@pytest.mark.parametrize("manifest_version", ["../escaped", True, 0])
def test_import_rejects_invalid_manifest_version_before_building_trust_path(
    tmp_path: Path, capsys: CapSys, manifest_version: object
) -> None:
    bundle_path = _raw_manifest_bundle(
        tmp_path, "bad-version", [("manifest", _manifest_blob("store.example", manifest_version))]
    )
    out_dir = tmp_path / "imported"
    capsys.readouterr()

    rc = cli.main(["import", "--bundle", str(bundle_path), "--out-dir", str(out_dir)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "import: trust-store file" in err
    assert "manifest_version" in err
    assert "refusing" in err
    assert not (out_dir / "escaped.json").exists()
    assert not (out_dir / "trust").exists()


def _salted_bundle(
    tmp_path: Path, seed: Path, manifest_path: Path, name: str, receipt_id: str, salt: bytes
) -> tuple[Path, Path]:
    payload = _write_payload(tmp_path, f"payload-{name}.json", receipt_id=receipt_id)
    salt_path = tmp_path / f"salt-{name}.b64u"
    salt_path.write_text(keys.b64u(salt), encoding="utf-8")
    envelope = tmp_path / f"envelope-{name}.json"
    assert cli.main(_issue_argv(seed, payload, envelope, salt=salt_path)) == 0
    return _export_bundle(tmp_path, manifest_path, envelope, name)


def test_import_refuses_a_conflicting_salts_file(tmp_path: Path, capsys: CapSys) -> None:
    """`salts.json` lives at a fixed path: a second, different bundle would
    destroy the first bundle's bearer secrets."""
    seed = _make_keypair(tmp_path, "issuer")
    manifest_path = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, manifest_path)) == 0
    bundle_a, private_a = _salted_bundle(
        tmp_path, seed, manifest_path, "a", "01ARZ3NDEKTSV4RRFFQ69G5FAV", bytes(range(16))
    )
    bundle_b, private_b = _salted_bundle(
        tmp_path, seed, manifest_path, "b", "01ARZ3NDEKTSV4RRFFQ69G5FAW", bytes(16)
    )

    out_dir = tmp_path / "imported"
    argv_a = [
        "import",
        "--bundle",
        str(bundle_a),
        "--private",
        str(private_a),
        "--out-dir",
        str(out_dir),
    ]
    assert cli.main(argv_a) == 0
    salts_file = out_dir / "salts.json"
    pinned = salts_file.read_text(encoding="utf-8")
    capsys.readouterr()

    argv_b = [
        "import",
        "--bundle",
        str(bundle_b),
        "--private",
        str(private_b),
        "--out-dir",
        str(out_dir),
    ]
    rc = cli.main(argv_b)
    err = capsys.readouterr().err
    assert rc == 2
    assert "import: salts file" in err
    assert str(salts_file) in err
    assert "refusing to overwrite" in err
    assert salts_file.read_text(encoding="utf-8") == pinned
    assert not (out_dir / "receipts" / "01ARZ3NDEKTSV4RRFFQ69G5FAW.attest.json").exists()

    assert cli.main([*argv_b, "--force"]) == 0
    assert salts_file.read_text(encoding="utf-8") != pinned


def test_reimporting_the_same_bundle_stays_idempotent(tmp_path: Path, capsys: CapSys) -> None:
    """The key regression: the documented recovery flow re-imports the same
    bundle pair, and the identity clause must let it through untouched."""
    seed = _make_keypair(tmp_path, "issuer")
    manifest_path = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, manifest_path)) == 0
    bundle_path, private_path = _salted_bundle(
        tmp_path, seed, manifest_path, "a", "01ARZ3NDEKTSV4RRFFQ69G5FAV", bytes(range(16))
    )

    out_dir = tmp_path / "imported"
    argv = [
        "import",
        "--bundle",
        str(bundle_path),
        "--private",
        str(private_path),
        "--out-dir",
        str(out_dir),
    ]
    assert cli.main(argv) == 0
    before = {
        path.relative_to(out_dir).as_posix(): path.read_bytes()
        for path in sorted(out_dir.rglob("*"))
        if path.is_file()
    }
    capsys.readouterr()

    assert cli.main(argv) == 0
    after = {
        path.relative_to(out_dir).as_posix(): path.read_bytes()
        for path in sorted(out_dir.rglob("*"))
        if path.is_file()
    }
    assert after == before
    assert stat.S_IMODE((out_dir / "salts.json").stat().st_mode) == 0o600


def test_import_rewrites_a_corrupted_receipt(tmp_path: Path, capsys: CapSys) -> None:
    """Classification pin: an imported receipt is re-extractable from the
    bundle the holder still has, so it stays unguarded and a re-import is a
    recovery path rather than a refusal."""
    seed = _make_keypair(tmp_path, "issuer")
    manifest_path = tmp_path / "manifest.json"
    assert cli.main(_manifest_init_argv(seed, manifest_path)) == 0
    receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    payload = _write_payload(tmp_path, "payload.json", receipt_id=receipt_id)
    envelope = tmp_path / "envelope.json"
    assert cli.main(_issue_argv(seed, payload, envelope)) == 0
    bundle_path, _ = _export_bundle(tmp_path, manifest_path, envelope, "a")

    out_dir = tmp_path / "imported"
    argv = ["import", "--bundle", str(bundle_path), "--out-dir", str(out_dir)]
    assert cli.main(argv) == 0
    receipt_file = out_dir / "receipts" / f"{receipt_id}.attest.json"
    intact = receipt_file.read_text(encoding="utf-8")
    receipt_file.write_text("corrupted", encoding="utf-8")
    capsys.readouterr()

    assert cli.main(argv) == 0
    assert receipt_file.read_text(encoding="utf-8") == intact


# --- the inode the guard authorized -----------------------------------------


def test_write_refuses_a_file_swapped_in_between_the_guard_and_the_write(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan authorizes an inode, not a name.

    `--force` authorizes replacing the file the guard looked at; it does not
    authorize replacing whatever happens to sit on that path a moment later.
    `_check_opened_write_target` compares the opened descriptor against the
    stat the plan recorded, so a file renamed over the target between the two
    is reported instead of truncated. Drop that comparison and this test
    silently writes a fresh seed over the swapped-in inode.
    """
    seed_out = tmp_path / "id.seed"
    seed_out.write_text("the previous identity", encoding="utf-8")
    decoy = tmp_path / "decoy"
    decoy.write_text("an unrelated file", encoding="utf-8")

    original_open = cli._open_text_output

    def swap_then_open(
        path: Path,
        *,
        exclusive: bool,
        label: str,
        mode: int,
        overwrite_plan: cli._OverwritePlan | None = None,
    ) -> int:
        if path == seed_out and decoy.exists():
            os.rename(decoy, seed_out)  # same name, different inode
        return original_open(
            path, exclusive=exclusive, label=label, mode=mode, overwrite_plan=overwrite_plan
        )

    monkeypatch.setattr(cli, "_open_text_output", swap_then_open)
    capsys.readouterr()

    rc = cli.main(_keygen_argv(tmp_path, "id", force=True))
    err = capsys.readouterr().err
    assert rc == 2
    assert "--seed-out" in err
    assert str(seed_out) in err
    assert "changed while writing" in err
    assert "refusing to overwrite" in err
    assert seed_out.read_text(encoding="utf-8") == "an unrelated file"


# --- disclose ---------------------------------------------------------------

_DISCLOSE_RECEIPT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
_DISCLOSE_SALT = bytes(range(16))


def _disclose_argv(tmp_path: Path, out: Path) -> list[str]:
    """Build a disclosable receipt and return `disclose --out <out>` argv."""
    seed = _make_keypair(tmp_path, "disclose-issuer")
    manifest_path = tmp_path / "disclose-manifest.json"
    assert cli.main(_manifest_init_argv(seed, manifest_path)) == 0
    payload_path = _write_payload(
        tmp_path, "disclose-payload.json", receipt_id=_DISCLOSE_RECEIPT_ID
    )
    salt_path = tmp_path / "disclose-salt.b64u"
    salt_path.write_text(keys.b64u(_DISCLOSE_SALT), encoding="utf-8")
    envelope_path = tmp_path / "disclose-envelope.json"
    assert cli.main(_issue_argv(seed, payload_path, envelope_path, salt=salt_path)) == 0
    return [
        "disclose",
        _DISCLOSE_RECEIPT_ID,
        "--receipt",
        str(envelope_path),
        "--key-manifest",
        str(manifest_path),
        "--salt",
        str(salt_path),
        "--out",
        str(out),
    ]


def test_disclose_refuses_a_symlinked_out(tmp_path: Path, capsys: CapSys) -> None:
    """The disclosure embeds `delivery.salt`: writing it through a link someone
    else planted hands that salt to them. Refused with no `--force` — the
    disclosure is recomputable, so the answer is to name another path."""
    victim = tmp_path / "victim.json"
    victim.write_text("keep me", encoding="utf-8")
    out = tmp_path / "disclosed.attest.json"
    try:
        out.symlink_to(victim)
    except OSError:
        pytest.skip("symlinks unsupported on this filesystem")
    argv = _disclose_argv(tmp_path, out)
    capsys.readouterr()

    rc = cli.main(argv)
    err = capsys.readouterr().err
    assert rc == 2
    assert f"disclose output {out} is a symlink" in err
    assert "refusing to overwrite" in err
    assert victim.read_text(encoding="utf-8") == "keep me"


def test_disclose_writes_a_hardlinked_out(tmp_path: Path, capsys: CapSys) -> None:
    """Classification pin: unlike every other secret output, a hard-linked
    disclose target is written. Its aliases are earlier disclosures of this
    same receipt, so they already hold this same salt."""
    out = tmp_path / "disclosed.attest.json"
    out.write_text("an earlier disclosure", encoding="utf-8")
    alias = tmp_path / "disclosed.alias.json"
    try:
        os.link(out, alias)
    except OSError:
        pytest.skip("hard links unsupported on this filesystem")
    argv = _disclose_argv(tmp_path, out)
    capsys.readouterr()

    rc = cli.main(argv)
    assert rc == 0
    disclosed = json.loads(out.read_text(encoding="utf-8"))
    assert disclosed["payload"]["receipt_id"] == _DISCLOSE_RECEIPT_ID
    assert disclosed["delivery"]["salt"] == keys.b64u(_DISCLOSE_SALT)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
