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


def test_transfer_record_refuses_an_existing_revocation_out(
    tmp_path: Path, capsys: CapSys
) -> None:
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
