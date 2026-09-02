"""The container image's privilege contract, pinned where it can regress.

The bridge holds an issuer's signing key and parses bodies an attacker can
reach (webhooks, claim forms). Nothing it does needs privilege, so the
long-lived server process must not be uid 0 — and the deploy templates must
keep agreeing on WHICH unprivileged account that is, because a merchant who
bind-mounts their keys has to chown them to that exact number.

Three properties are pinned here, each of which goes red on its own if the
clause that carries it is deleted:

1. the image creates a fixed, unprivileged uid/gid and hands it the three
   directories the bridge reads and writes;
2. the entrypoint drops to that same uid before exec'ing the server, refuses
   to fall through as root if it cannot, and takes ownership of a freshly
   mounted (root-owned) volume on the way;
3. `deploy.md` names the same number the image creates — a merchant chowning
   to a stale uid gets a bridge that cannot read its own signing key.

The entrypoint's already-unprivileged branch is exercised for real: the
script is executed with a stubbed `attest-bridge` and a stubbed `setpriv` on
PATH, which is what makes the exec'd argv (config path, host, port) a tested
claim rather than a comment.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

_BRIDGE_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _BRIDGE_ROOT / "deploy" / "Dockerfile"
_ENTRYPOINT = _BRIDGE_ROOT / "deploy" / "docker-entrypoint.sh"
_DEPLOY_DOC = _BRIDGE_ROOT / "docs" / "deploy.md"

# Every path the bridge must be able to read or write inside the container.
_OWNED_PATHS = ("/etc/attest-bridge", "/secrets", "/var/lib/attest-bridge")

_SERVE_ARGV = [
    "attest-bridge",
    "serve",
    "--config",
    "/etc/attest-bridge/bridge.toml",
    "--host",
    "0.0.0.0",  # noqa: S104 — the argv the image promises, not a bind this test performs
    "--port",
    "8080",
]


def _image_uid() -> int:
    """The numeric uid the Dockerfile creates, read out of the Dockerfile."""
    match = re.search(r"useradd[^\n]*?--uid[ =](\d+)", _DOCKERFILE.read_text(), re.DOTALL)
    assert match is not None, "the Dockerfile must create an account with an explicit numeric uid"
    return int(match.group(1))


def _entrypoint_uid() -> int:
    """The numeric uid the entrypoint drops to, read out of the script."""
    text = _ENTRYPOINT.read_text()
    match = re.search(r"^BRIDGE_UID=(\d+)", text, re.MULTILINE)
    assert match is not None, "the entrypoint must name the uid it drops to"
    return int(match.group(1))


def test_the_image_creates_an_unprivileged_account_and_hands_it_every_path_it_uses() -> None:
    text = _DOCKERFILE.read_text()
    uid = _image_uid()
    assert uid != 0
    assert uid >= 1000, "a system account below 1000 collides with the base image's own users"
    assert re.search(rf"groupadd[^\n]*?--gid[ =]{uid}\b", text), (
        "the group must carry the same fixed number as the user: a merchant chowns to a "
        "number, not to a name that does not exist on their host"
    )
    for path in _OWNED_PATHS:
        assert re.search(rf"chown[^\n]*\battest\b[^\n]*{re.escape(path)}", text), (
            f"{path} must belong to the unprivileged account in the image"
        )


def test_the_entrypoint_drops_to_the_uid_the_image_created() -> None:
    # Drift between the two files is silent and total: the server would start
    # as a uid that owns none of its files.
    assert _entrypoint_uid() == _image_uid()


def test_the_entrypoint_drops_privileges_before_exec_ing_the_server() -> None:
    text = _ENTRYPOINT.read_text()
    assert re.search(r"setpriv[^\n]*--reuid=?[\"']?\$\{?BRIDGE_UID", text), (
        "the root branch must exec the server through a privilege drop, not directly"
    )
    assert re.search(r"--regid=?[\"']?\$\{?BRIDGE_GID", text)


def test_the_entrypoint_refuses_to_serve_as_root_when_it_cannot_drop_privileges() -> None:
    # Without this the missing-setpriv case degrades to "keep going as root",
    # which is the exact outcome the whole change exists to prevent.
    text = _ENTRYPOINT.read_text()
    assert "command -v setpriv" in text
    assert re.search(r"command -v setpriv.*?exit 1", text, re.DOTALL)


def test_the_entrypoint_takes_ownership_of_a_freshly_mounted_ledger_volume() -> None:
    # Fly volumes and Render disks arrive root-owned; without this the
    # unprivileged server cannot create the Ledger on the first boot.
    text = _ENTRYPOINT.read_text()
    assert re.search(r"chown[^\n]*\$\{?BRIDGE_UID[^\n]*\$\{?LEDGER_DIR", text)
    assert re.search(r"^LEDGER_DIR=/var/lib/attest-bridge", text, re.MULTILINE)


def test_the_entrypoint_hands_every_materialized_secret_to_that_account() -> None:
    # Files decoded from the *_B64 env vars are created 0600 by the root
    # entrypoint; unchowned, the account that will read them cannot.
    text = _ENTRYPOINT.read_text()
    materialize = text.split("materialize() {", 1)[1].split("\n}", 1)[0]
    assert re.search(r"chown[^\n]*\$\{?BRIDGE_UID", materialize), (
        "materialize() must hand each decoded file to the unprivileged account"
    )


def test_an_already_unprivileged_container_execs_the_server_directly(tmp_path: Path) -> None:
    """Run the real entrypoint: no privilege drop when there is none to drop.

    This also pins the argv the image promises — config path, host and port —
    which every deploy template and guide quotes.
    """
    assert os.getuid() != 0, "this test describes the non-root branch"
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    capture = tmp_path / "capture"
    for name in ("attest-bridge", "setpriv"):
        stub = stub_bin / name
        stub.write_text(f'#!/bin/sh\nprintf "{name} %s\\n" "$*" >> "$CAPTURE"\n')
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)

    result = subprocess.run(  # noqa: S603
        ["/bin/sh", str(_ENTRYPOINT)],
        env={"PATH": f"{stub_bin}:{os.environ['PATH']}", "CAPTURE": str(capture)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    lines = capture.read_text().splitlines()
    assert lines == [f"attest-bridge {' '.join(_SERVE_ARGV[1:])}"], (
        f"expected a direct exec of the server, got {lines!r}"
    )


def test_malformed_base64_aborts_without_a_file_or_temp_residue(tmp_path: Path) -> None:
    """Undecodable material must leave nothing behind, not even a temp name.

    `materialize` decodes into a `mktemp` sibling and renames, so a failed
    decode must abort with no file at the real path and no readable partial
    beside it — the temp carries secret bytes on the paths that succeed.
    """
    etc = tmp_path / "etc"
    secrets = tmp_path / "secrets"
    ledger = tmp_path / "ledger"
    script = tmp_path / "entrypoint.sh"
    script.write_text(
        _ENTRYPOINT.read_text()
        .replace("/etc/attest-bridge", str(etc))
        .replace("/secrets", str(secrets))
        .replace("/var/lib/attest-bridge", str(ledger))
    )
    script.chmod(0o700)

    result = subprocess.run(  # noqa: S603
        ["/bin/sh", str(script)],
        env={**os.environ, "BRIDGE_TOML_B64": "!!!!"},
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0
    assert not (etc / "bridge.toml").exists()
    assert list(etc.glob(".attest-bridge.*")) == []


def test_the_deploy_guide_names_the_uid_the_image_actually_creates() -> None:
    # A merchant bind-mounting keys chowns them to this number. If the image
    # moves and the guide does not, the bridge cannot read its signing key.
    assert str(_image_uid()) in _DEPLOY_DOC.read_text()


def test_ledger_permission_error_tells_the_operator_which_uid_needs_the_directory(
    tmp_path: Path,
) -> None:
    from attest_bridge import cli

    denied = tmp_path / "no-entry"
    denied.mkdir(mode=0o500)
    message = cli._ledger_open_error(
        denied / "ledger.sqlite3", PermissionError(13, "Permission denied")
    )
    assert str(denied) in message
    assert str(os.getuid()) in message, (
        "the operator has to chown to a number; the message has to carry it"
    )
    assert "chown" in message


if __name__ == "__main__":  # pragma: no cover
    sys.exit("run me with pytest")
