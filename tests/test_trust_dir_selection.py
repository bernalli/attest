"""Trust-directory selection must never silently remove a compromise marking."""

from __future__ import annotations

import json
import os
from itertools import product
from pathlib import Path

import pytest

from attest import cli, issue, keys, manifests, verify
from tests.helpers import key_manifest, make_payload

ISSUER = "store.example.com"
OLD_KID = f"{ISSUER}/keys/test#old"
RECOVERY_KID = f"{ISSUER}/keys/test#recovery"
COMPROMISED = f"key {OLD_KID} is compromised"
CapSys = pytest.CaptureFixture[str]
TrustFixture = tuple[Path, Path, bytes]

# Exhaust every casing of the extension, independently of the loader's selector.
JSON_NAMES = ["x." + "".join(chars) for chars in product(*zip("json", "JSON", strict=True))]
JSON_NAMES += [".json", ".hidden.json"]


@pytest.fixture
def rotation(tmp_path: Path) -> TrustFixture:
    # Fixed test-only signing material, never production keys.
    old = keys.from_seed(bytes([41]) * 32)
    recovery = keys.from_seed(bytes([42]) * 32)
    valid_from = "2026-01-01T00:00:00Z"
    v1 = manifests.build_key_manifest(
        ISSUER,
        1,
        valid_from,
        [
            manifests.key_entry(OLD_KID, old.pub, valid_from, None, "active"),
            manifests.key_entry(RECOVERY_KID, recovery.pub, valid_from, None, "active"),
        ],
        old,
        OLD_KID,
    )
    v2 = manifests.rotate_key_manifest(
        v1, recovery, RECOVERY_KID, "2026-08-01T00:00:00Z", compromise_kids=[OLD_KID]
    )
    parsed_v1, parsed_v2 = key_manifest(v1), key_manifest(v2)
    assert manifests.verify_key_manifest(parsed_v1)
    assert manifests.verify_key_manifest(parsed_v2)
    assert manifests.check_continuity(parsed_v1, parsed_v2)
    assert manifests.find_key(parsed_v1, OLD_KID)["status"] == "active"
    assert manifests.find_key(parsed_v2, OLD_KID)["status"] == "compromised"

    envelope = tmp_path / "envelope.json"
    envelope.write_text(json.dumps(issue.issue(make_payload(), old, OLD_KID)), encoding="utf-8")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "base.json").write_text(json.dumps(v1), encoding="utf-8")
    return envelope, trust_dir, json.dumps(v2).encode()


def _assert_verdict(envelope: Path, trust_dir: Path, capsys: CapSys, *, denied: bool) -> None:
    result = verify.verify(envelope.read_bytes(), cli._load_trust_dir(trust_dir))
    assert isinstance(result, verify.VerificationResult)
    assert result.ok is (not denied)
    assert result.signature == ("invalid" if denied else "valid")
    assert result.errors == ((COMPROMISED,) if denied else ())

    rc = cli.main(["verify", str(envelope), "--trust-dir", str(trust_dir)])
    captured = capsys.readouterr()
    assert rc == (1 if denied else 0)
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["ok"] is (not denied)
    assert report["signature"] == ("invalid" if denied else "valid")
    assert report["errors"] == ([COMPROMISED] if denied else [])


def _assert_refused(
    envelope: Path, trust_dir: Path, entry: Path, reason: str, capsys: CapSys
) -> None:
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._load_trust_dir(trust_dir)
    message = str(excinfo.value)
    assert f"--trust-dir {trust_dir}" in message
    assert str(entry) in message
    assert reason in message

    rc = cli.main(["verify", str(envelope), "--trust-dir", str(trust_dir)])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert captured.err == f"error: {message}\n"


@pytest.mark.parametrize("name", ["x.JSON", "x.json.bak", "nested/x.json"])
def test_compromised_successor_never_disappears_silently(
    rotation: TrustFixture, capsys: CapSys, name: str
) -> None:
    """Either consume the authentic successor or refuse its directory by name."""
    envelope, trust_dir, v2 = rotation
    entry = trust_dir / name
    entry.parent.mkdir(exist_ok=True)
    entry.write_bytes(v2)

    try:
        trust_store = cli._load_trust_dir(trust_dir)
    except cli.CliUsageError as exc:
        # Pin the dispatch class and the offending entry, without prescribing
        # which selection policy supplies the diagnostic for this invariant.
        message = str(exc)
        assert f"--trust-dir {trust_dir}" in message
        assert str(trust_dir / Path(name).parts[0]) in message
        rc = cli.main(["verify", str(envelope), "--trust-dir", str(trust_dir)])
        captured = capsys.readouterr()
        assert rc == 2
        assert captured.out == ""
        assert captured.err == f"error: {message}\n"
    else:
        result = verify.verify(envelope.read_bytes(), trust_store)
        assert isinstance(result, verify.VerificationResult)
        assert result.ok is False, f"compromised successor {name} disappeared: {result}"
        assert result.signature == "invalid"
        assert result.errors == (COMPROMISED,)
        _assert_verdict(envelope, trust_dir, capsys, denied=True)


@pytest.mark.parametrize("name", JSON_NAMES)
@pytest.mark.parametrize("denied", [False, True], ids=["healthy-v1", "readable-compromise-v2"])
def test_json_files_preserve_the_verdict(
    rotation: TrustFixture, capsys: CapSys, name: str, denied: bool
) -> None:
    envelope, trust_dir, v2 = rotation
    if denied:
        (trust_dir / name).write_bytes(v2)
    else:
        (trust_dir / "base.json").rename(trust_dir / name)
    _assert_verdict(envelope, trust_dir, capsys, denied=denied)


@pytest.mark.parametrize("name", ["x.json.bak", "x.bak", "x.txt", "x", "x.json."])
def test_other_extensions_refuse_the_whole_directory(
    rotation: TrustFixture, capsys: CapSys, name: str
) -> None:
    envelope, trust_dir, v2 = rotation
    entry = trust_dir / name
    entry.write_bytes(v2)
    _assert_refused(envelope, trust_dir, entry, ".json extension", capsys)


@pytest.mark.parametrize("name", ["nested", "nested.json", "nested.JSON"])
def test_subdirectories_refuse_the_whole_directory(
    rotation: TrustFixture, capsys: CapSys, name: str
) -> None:
    envelope, trust_dir, v2 = rotation
    entry = trust_dir / name
    entry.mkdir()
    (entry / "x.json").write_bytes(v2)
    _assert_refused(envelope, trust_dir, entry, "not a regular file", capsys)


@pytest.mark.parametrize("dangling", [False, True], ids=["file-target", "missing-target"])
def test_symlinks_are_not_regular_directory_entries(
    rotation: TrustFixture, capsys: CapSys, dangling: bool
) -> None:
    envelope, trust_dir, v2 = rotation
    target = envelope.parent / "successor.json"
    if not dangling:
        target.write_bytes(v2)
    entry = trust_dir / "x.JSON"
    entry.symlink_to(target)
    _assert_refused(envelope, trust_dir, entry, "not a regular file", capsys)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
def test_fifo_is_refused_before_opening(rotation: TrustFixture, capsys: CapSys) -> None:
    envelope, trust_dir, _ = rotation
    entry = trust_dir / "x.JSON"
    os.mkfifo(entry)
    _assert_refused(envelope, trust_dir, entry, "not a regular file", capsys)


def test_inventory_error_is_a_usage_error(
    rotation: TrustFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, trust_dir, _ = rotation

    def cannot_list(path: Path) -> None:
        raise PermissionError("directory listing denied")

    monkeypatch.setattr(Path, "iterdir", cannot_list)
    with pytest.raises(cli.CliUsageError) as excinfo:
        cli._load_trust_dir(trust_dir)
    assert f"cannot read --trust-dir {trust_dir}" in str(excinfo.value)
    assert "directory listing denied" in str(excinfo.value)
