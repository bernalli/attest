"""Tests for attest.cli — the operator-facing command surface (design §10).

`cli.main([...])` is driven directly (no subprocess), per Task 14's brief.
Every verb is a thin wrapper around a single library call, so these tests
exercise CLI plumbing (argument parsing, file I/O, exit codes) rather than
re-testing crypto/schema logic already covered by the library's own suite.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attest import anchor, cli, keys, pq, revocation, tlog, transfer, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test-1#ed25519-1"
VALID_FROM = "2026-01-01T00:00:00Z"

CapSys = pytest.CaptureFixture[str]


# --- shared helpers (build a pipeline through the CLI itself) ---------------


def _keygen(tmp_path: Path, name: str) -> tuple[Path, Path]:
    seed_out = tmp_path / f"{name}.seed"
    pub_out = tmp_path / f"{name}.pub"
    rc = cli.main(["keygen", "--seed-out", str(seed_out), "--pub-out", str(pub_out)])
    assert rc == 0
    return seed_out, pub_out


def _keygen_hybrid(tmp_path: Path, name: str) -> tuple[Path, Path, Path]:
    seed_out = tmp_path / f"{name}.seed"
    pub_out = tmp_path / f"{name}.pub"
    mldsa_out = tmp_path / f"{name}.mldsa"
    rc = cli.main(
        [
            "keygen",
            "--seed-out",
            str(seed_out),
            "--pub-out",
            str(pub_out),
            "--hybrid",
            "--mldsa-out",
            str(mldsa_out),
        ]
    )
    assert rc == 0
    return seed_out, pub_out, mldsa_out


def _manifest_init(tmp_path: Path, seed: Path, out_name: str = "manifest.json") -> Path:
    out = tmp_path / out_name
    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    return out


def _write_artifacts(tmp_path: Path) -> Path:
    artifacts_path = tmp_path / "artifacts.json"
    artifacts_path.write_text(
        json.dumps(
            [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "game.exe",
                    "size_bytes": 123,
                    "sha256": "a" * 64,
                }
            ]
        ),
        encoding="utf-8",
    )
    return artifacts_path


def _write_payload(tmp_path: Path, name: str = "payload.json", **overrides: Any) -> Path:
    payload = make_payload(issuer={"id": ISSUER, "display_name": "Example Store"}, **overrides)
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_salt_file(tmp_path: Path, name: str, raw: bytes) -> Path:
    path = tmp_path / name
    path.write_text(keys.b64u(raw), encoding="utf-8")
    return path


def _issue(
    tmp_path: Path,
    seed: Path,
    payload_path: Path,
    out_name: str = "envelope.json",
    salt: Path | None = None,
    salt_out: Path | None = None,
) -> Path:
    out = tmp_path / out_name
    argv = [
        "issue",
        "--payload",
        str(payload_path),
        "--seed",
        str(seed),
        "--kid",
        KID,
        "--out",
        str(out),
    ]
    if salt is not None:
        argv += ["--salt", str(salt)]
    if salt_out is not None:
        argv += ["--salt-out", str(salt_out)]
    rc = cli.main(argv)
    assert rc == 0
    return out


def _trust_dir(tmp_path: Path, manifest_path: Path, name: str = "trust") -> Path:
    trust_dir = tmp_path / name
    trust_dir.mkdir()
    manifest_text = manifest_path.read_text(encoding="utf-8")
    (trust_dir / "issuer.json").write_text(manifest_text, encoding="utf-8")
    return trust_dir


# --- keygen ------------------------------------------------------------------


def test_keygen_writes_seed_file_with_0600_perms(tmp_path: Path) -> None:
    seed_out, pub_out = _keygen(tmp_path, "issuer")

    mode = stat.S_IMODE(seed_out.stat().st_mode)
    assert mode == 0o600
    assert pub_out.exists()


def test_keygen_never_prints_the_seed_to_stdout(tmp_path: Path, capsys: CapSys) -> None:
    seed_out, _pub_out = _keygen(tmp_path, "issuer")

    seed_text = seed_out.read_text(encoding="utf-8").strip()
    captured = capsys.readouterr().out
    assert seed_text not in captured


def test_keygen_prints_pub_key_json_to_stdout(tmp_path: Path, capsys: CapSys) -> None:
    _seed_out, pub_out = _keygen(tmp_path, "issuer")

    report = json.loads(capsys.readouterr().out)
    assert report["pub"] == pub_out.read_text(encoding="utf-8").strip()


# --- manifest init -------------------------------------------------------------


def test_manifest_init_writes_self_consistent_manifest(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["issuer"] == ISSUER
    assert manifest["manifest_version"] == 1
    assert manifest["keys"][0]["kid"] == KID


# --- full happy path: keygen -> manifest init -> issue -> verify -------------


def test_full_happy_path_verify_exits_0(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["ok"] is True
    assert result["signature"] == "valid"
    assert result["trust"] == "unauthenticated_tofu"


def test_verify_of_tampered_envelope_exits_1(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["payload"]["work"]["title"] = "Tampered Title"
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False
    assert result["signature"] == "invalid"


def test_verify_unknown_issuer_no_trust_dir_match_exits_1(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    empty_trust_dir = tmp_path / "empty_trust"
    empty_trust_dir.mkdir()

    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(empty_trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False


# --- verify: --revocations (security: must fail-closed on a mis-shaped file) --


def _policy_revoked_setup(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    """A `revocability: policy` receipt + a genuine revocation record for it,
    signed by the same active in-window key as the issuer manifest (mirrors
    design vector 15). Returns (envelope_path, trust_dir, record)."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path, license={"revocability": "policy"})
    envelope_path = _issue(tmp_path, seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    kp = keys.from_seed(keys.b64u_decode(seed.read_text(encoding="utf-8").strip()))
    receipt_id = json.loads(payload_path.read_text(encoding="utf-8"))["receipt_id"]
    record = revocation.build_record(receipt_id, "revoked", "2026-07-03T00:00:00Z", kp, KID)
    return envelope_path, trust_dir, record


def test_verify_revocations_array_with_authenticated_record_exits_1(
    tmp_path: Path, capsys: CapSys
) -> None:
    """A `--revocations` file with a proper JSON array [record] that
    authenticates against the issuer manifest revokes a policy receipt."""
    envelope_path, trust_dir, record = _policy_revoked_setup(tmp_path)
    recs_path = tmp_path / "revocations.json"
    recs_path.write_text(json.dumps([record]), encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--revocations",
            str(recs_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False
    assert result["revocation"] == "revoked"


def test_verify_revocations_bare_object_exits_2_not_ok_true(tmp_path: Path, capsys: CapSys) -> None:
    """The SAME record written as a bare OBJECT (not wrapped in a list) — the
    exact shape `revocation.build_record` returns — must be a usage error
    (exit 2), NEVER silently ignored into an `ok: true` pass of a genuinely
    revoked receipt (fail-closed on a mis-shaped security input)."""
    envelope_path, trust_dir, record = _policy_revoked_setup(tmp_path)
    recs_path = tmp_path / "revocations.json"
    recs_path.write_text(json.dumps(record), encoding="utf-8")  # bare object, not [record]

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--revocations",
            str(recs_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.err != ""
    # Critically: it must NOT have printed a passing verdict for a revoked receipt.
    assert '"ok": true' not in captured.out


# --- check-artifact ------------------------------------------------------------


def test_check_artifact_matching_sha256_exits_0(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    artifact_bytes = b"totally-a-game-installer"
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    payload_path = _write_payload(
        tmp_path,
        work={
            "artifacts": [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "game.exe",
                    "size_bytes": len(artifact_bytes),
                    "sha256": digest,
                }
            ]
        },
    )
    envelope_path = _issue(tmp_path, seed, payload_path)
    local_file = tmp_path / "game.exe"
    local_file.write_bytes(artifact_bytes)

    capsys.readouterr()
    rc = cli.main(["check-artifact", str(local_file), "--receipt", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["match"] is True
    assert result["sha256"] == digest


def test_check_artifact_mismatching_sha256_exits_nonzero(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    artifact_bytes = b"totally-a-game-installer"
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    payload_path = _write_payload(
        tmp_path,
        work={
            "artifacts": [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "game.exe",
                    "size_bytes": len(artifact_bytes),
                    "sha256": digest,
                }
            ]
        },
    )
    envelope_path = _issue(tmp_path, seed, payload_path)
    local_file = tmp_path / "game.exe"
    local_file.write_bytes(b"a completely different, corrupted file")

    capsys.readouterr()
    rc = cli.main(["check-artifact", str(local_file), "--receipt", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc != 0
    assert result["match"] is False


# --- inspect ---------------------------------------------------------------


def test_inspect_warns_on_delivery_salt_presence(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    salt_path = _write_salt_file(tmp_path, "salt.b64u", bytes(range(16)))
    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    capsys.readouterr()
    rc = cli.main(["inspect", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert any("salt" in w for w in result["warnings"])


def test_inspect_no_warning_when_no_salt_present(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    capsys.readouterr()
    rc = cli.main(["inspect", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["warnings"] == []


def test_inspect_redacts_the_salt_value_from_stdout(tmp_path: Path, capsys: CapSys) -> None:
    """The raw buyer-binding secret must never appear in `inspect` output —
    an operator pasting it into a ticket/Slack/shell-history would leak the
    very secret `inspect` warns about. The warning still fires; the value is
    replaced by a redaction placeholder, and the on-disk file is untouched."""
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_b64u = keys.b64u(raw_salt)
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)
    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    capsys.readouterr()
    rc = cli.main(["inspect", str(envelope_path)])
    stdout = capsys.readouterr().out
    result = json.loads(stdout)

    assert rc == 0
    # The raw secret must not be anywhere in what was printed.
    assert salt_b64u not in stdout
    assert result["envelope"]["delivery"]["salt"] != salt_b64u
    # ...but the warning about salt presence must still fire.
    assert any("salt" in w for w in result["warnings"])
    # ...and the on-disk file must be untouched (still carries the real salt).
    on_disk = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert on_disk["delivery"]["salt"] == salt_b64u


# --- issue: --salt / --salt-out ---------------------------------------------


def test_issue_embeds_supplied_salt_in_delivery(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)

    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert envelope["delivery"]["salt"] == keys.b64u(raw_salt)


def test_issue_salt_out_writes_the_same_salt_with_0600_perms(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)
    salt_out_path = tmp_path / "receipt-salt.out"

    _issue(tmp_path, seed, payload_path, salt=salt_path, salt_out=salt_out_path)

    assert salt_out_path.read_text(encoding="utf-8").strip() == keys.b64u(raw_salt)
    mode = stat.S_IMODE(salt_out_path.stat().st_mode)
    assert mode == 0o600


def test_issue_salt_bearing_envelope_out_file_is_0600(tmp_path: Path) -> None:
    """A `--out` envelope that embeds `delivery.salt` carries the same secret
    as the `--salt-out` copy and must be locked down identically (0600), not
    left world-readable at the default umask."""
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)

    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    assert oct(os.stat(envelope_path).st_mode)[-3:] == "600"


def test_issue_saltless_envelope_out_file_keeps_default_perms(tmp_path: Path) -> None:
    """A saltless envelope carries no secret, so it need not be 0600 — it
    should be created with normal (default-umask) permissions, i.e. NOT the
    restrictive owner-only mode a salt-bearing file gets."""
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)

    envelope_path = _issue(tmp_path, seed, payload_path)

    assert oct(os.stat(envelope_path).st_mode)[-3:] != "600"


def test_issue_salt_out_without_salt_is_usage_error(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(out),
            "--salt-out",
            str(tmp_path / "salt.out"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


# --- verify: disclosure (binding proof) -------------------------------------


def test_verify_with_matching_disclosure_proves_binding(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)

    from attest import commitment

    raw_salt = bytes(range(16))
    identifier = "buyer@example.com"
    identifier_type = "email"
    commit = commitment.compute(identifier, identifier_type, raw_salt)
    payload_path = _write_payload(
        tmp_path,
        buyer={
            "commitment": keys.b64u(commit),
            "identifier_type": identifier_type,
            "pubkey": None,
        },
    )
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)
    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--disclose-identifier",
            identifier,
            "--disclose-type",
            identifier_type,
            "--disclose-salt",
            str(salt_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["binding"] == "proven"


# --- disclose ----------------------------------------------------------------


def test_disclose_writes_into_a_not_yet_existing_directory(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)
    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    receipt_id = payload["receipt_id"]

    out_dir = tmp_path / "share"
    assert not out_dir.exists()

    capsys.readouterr()
    rc = cli.main(
        [
            "disclose",
            receipt_id,
            "--receipt",
            str(envelope_path),
            "--key-manifest",
            str(manifest_path),
            "--salt",
            str(salt_path),
            "--out",
            str(out_dir) + "/",
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    written = Path(result["out"])
    assert written == out_dir / f"{receipt_id}.attest.json"
    assert written.exists()

    disclosed = json.loads(written.read_text(encoding="utf-8"))
    assert disclosed["payload"]["receipt_id"] == receipt_id
    assert disclosed["delivery"]["salt"] == keys.b64u(raw_salt)


def test_disclose_writes_to_exact_file_path(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    receipt_id = payload["receipt_id"]
    exact_out = tmp_path / "my-receipt.attest.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "disclose",
            receipt_id,
            "--receipt",
            str(envelope_path),
            "--key-manifest",
            str(manifest_path),
            "--out",
            str(exact_out),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert Path(result["out"]) == exact_out
    assert exact_out.exists()


# --- export / import roundtrip via CLI ---------------------------------------


def test_export_then_import_then_verify_roundtrip(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    legal_text = (
        make_payload()["license"]["legal_text_sha256"],  # unused, just documents shape
    )
    del legal_text
    legal_text_bytes = b"attest-test-legal-text-v1"
    assert (
        hashlib.sha256(legal_text_bytes).hexdigest()
        == json.loads(payload_path.read_text(encoding="utf-8"))["license"]["legal_text_sha256"]
    )
    legal_text_path = tmp_path / "legal.txt"
    legal_text_path.write_bytes(legal_text_bytes)

    mirror_policy_bytes = b"attest-test-mirror-policy-v1"
    mirror_policy_path = tmp_path / "mirror-policy.txt"
    mirror_policy_path.write_bytes(mirror_policy_bytes)

    out_dir = tmp_path / "bundle_out"
    capsys.readouterr()
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
            "mylibrary",
        ]
    )
    export_report = json.loads(capsys.readouterr().out)
    assert rc == 0

    import_out_dir = tmp_path / "imported"
    rc = cli.main(
        [
            "import",
            "--bundle",
            export_report["attest"],
            "--out-dir",
            str(import_out_dir),
        ]
    )
    import_report = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert import_report["receipts"] == 1

    imported_trust_dir = import_out_dir / "trust"
    imported_receipt = next((import_out_dir / "receipts").glob("*.attest.json"))

    capsys.readouterr()
    rc = cli.main(["verify", str(imported_receipt), "--trust-dir", str(imported_trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["ok"] is True
    assert result["trust"] == "unauthenticated_tofu"


# --- manifest rotate / manifest artifacts -------------------------------------


def test_manifest_rotate_produces_version_2_signed_by_version_1_key(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    _new_seed, new_pub = _keygen(tmp_path, "issuer-2")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"

    rotated_out = tmp_path / "manifest-v2.json"
    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_path),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(rotated_out),
        ]
    )
    assert rc == 0

    from attest import manifests

    trusted = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidate = json.loads(rotated_out.read_text(encoding="utf-8"))
    assert candidate["manifest_version"] == 2
    assert manifests.check_continuity(trusted, candidate)


def test_manifest_artifacts_builds_signed_artifact_manifest(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    key_manifest_path = _manifest_init(tmp_path, seed)
    artifacts_path = _write_artifacts(tmp_path)
    out = tmp_path / "artifact-manifest.json"

    rc = cli.main(
        [
            "manifest",
            "artifacts",
            "--in",
            str(key_manifest_path),
            "--issuer",
            ISSUER,
            "--series",
            f"{ISSUER}/works/EXG-001",
            "--version",
            "1",
            "--manifest-version",
            "1",
            "--released-at",
            VALID_FROM,
            "--artifacts",
            str(artifacts_path),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--out",
            str(out),
        ]
    )
    assert rc == 0

    from attest import manifests

    key_manifest = json.loads(key_manifest_path.read_text(encoding="utf-8"))
    artifact_manifest = json.loads(out.read_text(encoding="utf-8"))
    assert artifact_manifest["manifest_version"] == 1
    assert manifests.verify_artifact_manifest(artifact_manifest, key_manifest)


def test_manifest_artifacts_rejects_nonpositive_manifest_version(capsys: CapSys) -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(
            [
                "manifest",
                "artifacts",
                "--in",
                "key-manifest.json",
                "--issuer",
                ISSUER,
                "--series",
                f"{ISSUER}/works/EXG-001",
                "--version",
                "1",
                "--manifest-version",
                "0",
                "--released-at",
                VALID_FROM,
                "--artifacts",
                "artifacts.json",
                "--signing-kid",
                KID,
                "--signing-seed",
                "issuer.seed",
                "--out",
                "artifact-manifest.json",
            ]
        )
    assert exc.value.code == 2
    assert "must be an integer >= 1" in capsys.readouterr().err


def test_load_trust_dir_scopes_artifact_chains_by_issuer_and_series(tmp_path: Path) -> None:
    series = "shared/works/EXG-001"
    for issuer in (ISSUER, "other.example.com"):
        (tmp_path / f"{issuer}.artifact.json").write_text(
            json.dumps({"issuer": issuer, "series": series, "version": 1}), encoding="utf-8"
        )
    trust_store = cli._load_trust_dir(tmp_path)
    assert set(trust_store.artifact_manifests) == {ISSUER, "other.example.com"}
    assert trust_store.artifact_manifests[ISSUER][series]["issuer"] == ISSUER
    assert (
        trust_store.artifact_manifests["other.example.com"][series]["issuer"] == "other.example.com"
    )


def test_manifest_artifacts_hybrid_roundtrips(tmp_path: Path) -> None:
    from attest import manifests

    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    key_manifest_path = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest.json")
    out = tmp_path / "artifact-manifest.json"

    rc = cli.main(
        [
            "manifest",
            "artifacts",
            "--in",
            str(key_manifest_path),
            "--issuer",
            ISSUER,
            "--series",
            f"{ISSUER}/works/EXG-001",
            "--version",
            "1",
            "--manifest-version",
            "1",
            "--released-at",
            VALID_FROM,
            "--artifacts",
            str(_write_artifacts(tmp_path)),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    key_manifest = json.loads(key_manifest_path.read_text(encoding="utf-8"))
    artifact_manifest = json.loads(out.read_text(encoding="utf-8"))
    assert "sig_ml_dsa_65" in artifact_manifest["manifest_signature"]
    assert manifests.verify_artifact_manifest(artifact_manifest, key_manifest)


def test_manifest_artifacts_hybrid_without_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    key_manifest_path = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest.json")
    out = tmp_path / "artifact-manifest.json"

    rc = cli.main(
        [
            "manifest",
            "artifacts",
            "--in",
            str(key_manifest_path),
            "--issuer",
            ISSUER,
            "--series",
            f"{ISSUER}/works/EXG-001",
            "--version",
            "1",
            "--manifest-version",
            "1",
            "--released-at",
            VALID_FROM,
            "--artifacts",
            str(_write_artifacts(tmp_path)),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert "is hybrid; --mldsa-key is required" in capsys.readouterr().err
    assert not out.exists()


def test_manifest_artifacts_ed_only_with_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    key_manifest_path = _manifest_init(tmp_path, seed)
    _other_seed, _other_pub, mldsa_key = _keygen_hybrid(tmp_path, "other")
    out = tmp_path / "artifact-manifest.json"

    rc = cli.main(
        [
            "manifest",
            "artifacts",
            "--in",
            str(key_manifest_path),
            "--issuer",
            ISSUER,
            "--series",
            f"{ISSUER}/works/EXG-001",
            "--version",
            "1",
            "--manifest-version",
            "1",
            "--released-at",
            VALID_FROM,
            "--artifacts",
            str(_write_artifacts(tmp_path)),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert "is Ed25519-only; --mldsa-key is not allowed" in capsys.readouterr().err
    assert not out.exists()


def test_manifest_artifacts_wrong_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    key_manifest_path = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest.json")
    _other_seed, _other_pub, wrong_mldsa_key = _keygen_hybrid(tmp_path, "other")
    out = tmp_path / "artifact-manifest.json"

    rc = cli.main(
        [
            "manifest",
            "artifacts",
            "--in",
            str(key_manifest_path),
            "--issuer",
            ISSUER,
            "--series",
            f"{ISSUER}/works/EXG-001",
            "--version",
            "1",
            "--manifest-version",
            "1",
            "--released-at",
            VALID_FROM,
            "--artifacts",
            str(_write_artifacts(tmp_path)),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(wrong_mldsa_key),
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert "does not match the signing key's ML-DSA-65 public key" in capsys.readouterr().err
    assert not out.exists()


# --- usage / IO errors exit 2 -------------------------------------------------


def test_verify_missing_envelope_file_exits_2(tmp_path: Path, capsys: CapSys) -> None:
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()

    rc = cli.main(["verify", str(tmp_path / "nope.json"), "--trust-dir", str(trust_dir)])

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_issue_invalid_payload_json_exits_2(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    bad_payload = tmp_path / "bad.json"
    bad_payload.write_text("{not valid json", encoding="utf-8")
    out = tmp_path / "envelope.json"

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(bad_payload),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_export_with_wrong_shaped_receipt_json_exits_2_not_traceback(
    tmp_path: Path, capsys: CapSys
) -> None:
    """A receipt file that is valid JSON but the wrong shape (a list instead
    of an envelope object) must fail as a clean usage error, not propagate
    the library's internal `AttributeError` (`list.get` does not exist) as
    an uncaught traceback."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    bad_receipt = tmp_path / "bad_receipt.json"
    bad_receipt.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    rc = cli.main(
        [
            "export",
            "--receipt",
            str(bad_receipt),
            "--key-manifest",
            str(manifest_path),
            "--out-dir",
            str(tmp_path / "out"),
            "--name",
            "mylibrary",
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


# --- --help surfaces -----------------------------------------------------------


def test_top_level_help_exits_0(capsys: CapSys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0


def test_verify_help_exits_0(capsys: CapSys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["verify", "--help"])
    assert exc_info.value.code == 0


def test_log_anchor_help_names_ots_convert_without_overclaiming(
    capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`log anchor --help` is read by exactly the operator who is holding a
    detached `.ots` file and wondering what to do with it next. Saying only
    that anchor material "is out of this CLI's scope" was true before `log
    ots-convert` existed and is still true -- ACQUIRING an attestation needs
    a calendar and a network this CLI never opens a socket to -- but it is
    now the wrong place for the help to stop: CONVERTING a proof the
    operator already holds is in scope, and offline. The help has to keep
    the truthful half and name the command.

    The three residual-truth assertions are the point of the pin, not
    decoration: this surface must never drift into promising more than the
    code does, so the sentence that scopes the command OUT of acquisition
    has to survive every future edit that adds a pointer to it.
    """
    # Pin the wrap width. argparse fills the description to the terminal
    # width and textwrap breaks on hyphens, so on a narrow console
    # `ots-convert` can be split across two lines and no substring check
    # would survive; at this width the description is emitted unwrapped.
    monkeypatch.setenv("COLUMNS", "2000")
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["log", "anchor", "--help"])
    assert exc_info.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())

    assert "ots-convert" in help_text
    # Residual truth, all three still required after the pointer lands:
    # the material comes from elsewhere, acquiring it is not this CLI's
    # job, and nothing here reaches the network.
    assert "OUTSIDE this process" in help_text
    assert "out of this CLI's scope" in help_text
    assert "never touches the network" in help_text


# --- manifest rotate: retirement / compromise flags --------------------------


def test_manifest_rotate_compromise_without_new_key(tmp_path: Path) -> None:
    """A key can be compromised without adding a new key, as long as the
    rotation is signed by another active key. Flow: init (KID) -> rotate to add
    KID2 -> rotate again compromising KID, signed by KID2, no new key."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_v1 = _manifest_init(tmp_path, seed)
    seed2, pub2 = _keygen(tmp_path, "issuer-2")
    kid2 = f"{ISSUER}/keys/test-2#ed25519-1"

    manifest_v2 = tmp_path / "manifest-v2.json"
    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--new-kid",
            kid2,
            "--new-pub",
            str(pub2),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(manifest_v2),
        ]
    )
    assert rc == 0

    manifest_v3 = tmp_path / "manifest-v3.json"
    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v2),
            "--signing-kid",
            kid2,
            "--signing-seed",
            str(seed2),
            "--compromise-kid",
            KID,
            "--issued-at",
            "2026-03-01T00:00:00Z",
            "--out",
            str(manifest_v3),
        ]
    )
    assert rc == 0

    from attest import manifests

    v2 = json.loads(manifest_v2.read_text(encoding="utf-8"))
    v3 = json.loads(manifest_v3.read_text(encoding="utf-8"))
    assert manifests.find_key(v3, KID)["status"] == "compromised"
    assert manifests.verify_key_manifest(v3)
    assert manifests.check_continuity(v2, v3)


def test_manifest_rotate_retire_flag(tmp_path: Path) -> None:
    """`--retire-kid` marks an existing key retired (signed by a second key)."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_v1 = _manifest_init(tmp_path, seed)
    seed2, pub2 = _keygen(tmp_path, "issuer-2")
    kid2 = f"{ISSUER}/keys/test-2#ed25519-1"

    manifest_v2 = tmp_path / "manifest-v2.json"
    assert (
        cli.main(
            [
                "manifest",
                "rotate",
                "--in",
                str(manifest_v1),
                "--signing-kid",
                KID,
                "--signing-seed",
                str(seed),
                "--new-kid",
                kid2,
                "--new-pub",
                str(pub2),
                "--valid-from",
                "2026-02-01T00:00:00Z",
                "--issued-at",
                "2026-02-01T00:00:00Z",
                "--out",
                str(manifest_v2),
            ]
        )
        == 0
    )

    manifest_v3 = tmp_path / "manifest-v3.json"
    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v2),
            "--signing-kid",
            kid2,
            "--signing-seed",
            str(seed2),
            "--retire-kid",
            KID,
            "--issued-at",
            "2026-03-01T00:00:00Z",
            "--out",
            str(manifest_v3),
        ]
    )
    assert rc == 0

    from attest import manifests

    v3 = json.loads(manifest_v3.read_text(encoding="utf-8"))
    assert manifests.find_key(v3, KID)["status"] == "retired"


def test_manifest_rotate_with_no_changes_exits_2(tmp_path: Path, capsys: CapSys) -> None:
    """A rotation that neither adds a key nor changes a status is a usage
    error (exit 2), not a silently re-signed duplicate."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_v1 = _manifest_init(tmp_path, seed)

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(tmp_path / "v2.json"),
        ]
    )
    assert rc == 2
    assert capsys.readouterr().err != ""


def test_manifest_rotate_compromising_signing_key_exits_2(tmp_path: Path, capsys: CapSys) -> None:
    """Guard surfaced through the CLI: compromising the very key you sign with
    is refused (exit 2)."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_v1 = _manifest_init(tmp_path, seed)

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--compromise-kid",
            KID,
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(tmp_path / "v2.json"),
        ]
    )
    assert rc == 2
    assert capsys.readouterr().err != ""


# --- hybrid (v0.2) CLI support -------------------------------------------------


def test_keygen_hybrid_writes_0600_mldsa_file(tmp_path: Path) -> None:
    _seed_out, _pub_out, mldsa_out = _keygen_hybrid(tmp_path, "issuer")

    mode = stat.S_IMODE(mldsa_out.stat().st_mode)
    assert mode == 0o600

    key_file = json.loads(mldsa_out.read_text(encoding="utf-8"))
    assert key_file["alg"] == "ML-DSA-65"
    assert len(keys.b64u_decode(key_file["sk"])) == pq.ML_DSA_65_SK_LEN
    assert len(keys.b64u_decode(key_file["pub"])) == pq.ML_DSA_65_PK_LEN


def test_issue_v02_roundtrips_through_verify(tmp_path: Path, capsys: CapSys) -> None:
    seed_out, _pub_out, mldsa_out = _keygen_hybrid(tmp_path, "issuer")

    manifest_path = tmp_path / "manifest.json"
    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed_out),
            "--mldsa-key",
            str(mldsa_out),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--out",
            str(manifest_path),
        ]
    )
    assert rc == 0

    payload_path = _write_payload(tmp_path, attest_version="0.2")
    envelope_path = tmp_path / "envelope.json"
    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed_out),
            "--mldsa-key",
            str(mldsa_out),
            "--attest-version",
            "0.2",
            "--kid",
            KID,
            "--out",
            str(envelope_path),
        ]
    )
    assert rc == 0

    trust_dir = _trust_dir(tmp_path, manifest_path)
    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["ok"] is True
    assert result["signature"] == "valid"


def test_issue_v02_without_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path, attest_version="0.2")
    out = tmp_path / "envelope.json"

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--attest-version",
            "0.2",
            "--kid",
            KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert not out.exists()


def test_issue_v01_with_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed_out, _pub_out, mldsa_out = _keygen_hybrid(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)  # default attest_version "0.1"
    out = tmp_path / "envelope.json"

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed_out),
            "--mldsa-key",
            str(mldsa_out),
            "--kid",
            KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert not out.exists()


# --- fix wave (Task 8 adversarial review): rotate must fail closed on shape --


def _manifest_init_hybrid(tmp_path: Path, seed: Path, mldsa_key: Path, out_name: str) -> Path:
    out = tmp_path / out_name
    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    return out


def test_manifest_rotate_hybrid_roundtrips(tmp_path: Path) -> None:
    from attest import manifests

    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest-v1.json")

    _new_seed, new_pub = _keygen(tmp_path, "issuer-2")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"

    rotated_out = tmp_path / "manifest-v2.json"
    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(rotated_out),
        ]
    )
    assert rc == 0

    rotated = json.loads(rotated_out.read_text(encoding="utf-8"))
    assert "sig_ml_dsa_65" in rotated["manifest_signature"]
    assert manifests.verify_key_manifest(rotated) is True


def test_manifest_rotate_hybrid_without_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest-v1.json")
    _new_seed, new_pub = _keygen(tmp_path, "issuer-2")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(tmp_path / "manifest-v2.json"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_manifest_rotate_ed_only_with_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_v1 = _manifest_init(tmp_path, seed, "manifest-v1.json")
    _seed2, _pub2, mldsa_key = _keygen_hybrid(tmp_path, "issuer-2")
    _new_seed, new_pub = _keygen(tmp_path, "issuer-3")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(tmp_path / "manifest-v2.json"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_manifest_rotate_wrong_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest-v1.json")
    _seed2, _pub2, wrong_mldsa_key = _keygen_hybrid(tmp_path, "other")
    _new_seed, new_pub = _keygen(tmp_path, "issuer-2")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(wrong_mldsa_key),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(tmp_path / "manifest-v2.json"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_keygen_hybrid_requires_mldsa_out(tmp_path: Path, capsys: CapSys) -> None:
    rc = cli.main(
        [
            "keygen",
            "--seed-out",
            str(tmp_path / "issuer.seed"),
            "--pub-out",
            str(tmp_path / "issuer.pub"),
            "--hybrid",
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_keygen_mldsa_out_requires_hybrid(tmp_path: Path, capsys: CapSys) -> None:
    rc = cli.main(
        [
            "keygen",
            "--seed-out",
            str(tmp_path / "issuer.seed"),
            "--pub-out",
            str(tmp_path / "issuer.pub"),
            "--mldsa-out",
            str(tmp_path / "issuer.mldsa"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_keygen_mldsa_out_aliased_errors(tmp_path: Path, capsys: CapSys) -> None:
    shared = tmp_path / "issuer.seed"

    rc = cli.main(
        [
            "keygen",
            "--seed-out",
            str(shared),
            "--pub-out",
            str(tmp_path / "issuer.pub"),
            "--hybrid",
            "--mldsa-out",
            str(shared),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_issue_v02_mldsa_key_aliased_with_out_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path, attest_version="0.2")

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--attest-version",
            "0.2",
            "--kid",
            KID,
            "--out",
            str(mldsa_key),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_load_mldsa_kp_rejects_malformed(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path, attest_version="0.2")

    wrong_alg = tmp_path / "wrong-alg.mldsa"
    wrong_alg.write_text(
        json.dumps(
            {"alg": "not-ML-DSA-65", "sk": keys.b64u(b"x" * 10), "pub": keys.b64u(b"y" * 10)}
        ),
        encoding="utf-8",
    )
    wrong_length = tmp_path / "wrong-length.mldsa"
    wrong_length.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(b"x" * 10),
                "pub": keys.b64u(b"y" * 10),
            }
        ),
        encoding="utf-8",
    )
    not_a_dict = tmp_path / "not-a-dict.mldsa"
    not_a_dict.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    for bad_file in (wrong_alg, wrong_length, not_a_dict):
        rc = cli.main(
            [
                "issue",
                "--payload",
                str(payload_path),
                "--seed",
                str(seed),
                "--mldsa-key",
                str(bad_file),
                "--attest-version",
                "0.2",
                "--kid",
                KID,
                "--out",
                str(tmp_path / "envelope.json"),
            ]
        )
        assert rc == 2, f"expected exit 2 for {bad_file.name}"
        err = capsys.readouterr().err
        assert err != ""
        assert "Traceback" not in err


# --- fix wave 2 (Task 8 adversarial re-review): salt-out alias + rotate self-verify --


def test_issue_v02_mldsa_key_aliased_with_salt_out_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path, attest_version="0.2")
    salt = _write_salt_file(tmp_path, "buyer.salt", b"s" * 16)

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--attest-version",
            "0.2",
            "--kid",
            KID,
            "--salt",
            str(salt),
            "--salt-out",
            str(mldsa_key),
            "--out",
            str(tmp_path / "envelope.json"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    # The ML-DSA secret file must still hold the key JSON, not the raw salt.
    assert json.loads(mldsa_key.read_text(encoding="utf-8"))["alg"] == pq.ML_DSA_65_ALG


def test_issue_mldsa_key_hardlinked_salt_out_errors(tmp_path: Path) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    salt_out = tmp_path / "mldsa-salt-link"
    try:
        os.link(mldsa_key, salt_out)
    except OSError:
        pytest.skip("hard links unsupported on this filesystem")
    payload_path = _write_payload(tmp_path, attest_version="0.2")
    salt = _write_salt_file(tmp_path, "buyer.salt", b"s" * 16)

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--attest-version",
            "0.2",
            "--kid",
            KID,
            "--salt",
            str(salt),
            "--salt-out",
            str(salt_out),
            "--out",
            str(tmp_path / "receipt.json"),
        ]
    )

    assert rc == 2
    assert json.loads(mldsa_key.read_text(encoding="utf-8"))["alg"] == pq.ML_DSA_65_ALG


def test_keygen_mldsa_out_aliased_with_pub_out_errors(tmp_path: Path, capsys: CapSys) -> None:
    shared = tmp_path / "issuer.pub"

    rc = cli.main(
        [
            "keygen",
            "--seed-out",
            str(tmp_path / "issuer.seed"),
            "--pub-out",
            str(shared),
            "--hybrid",
            "--mldsa-out",
            str(shared),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_keygen_seed_out_hardlinked_pub_out_errors(tmp_path: Path) -> None:
    seed_out = tmp_path / "issuer.seed"
    seed_out.write_text("existing seed", encoding="utf-8")
    pub_out = tmp_path / "issuer.pub"
    try:
        os.link(seed_out, pub_out)
    except OSError:
        pytest.skip("hard links unsupported on this filesystem")

    rc = cli.main(["keygen", "--seed-out", str(seed_out), "--pub-out", str(pub_out)])

    assert rc == 2


def test_manifest_init_mldsa_key_aliased_with_out_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")

    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--out",
            str(mldsa_key),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_manifest_rotate_wrong_signing_seed_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest-v1.json")
    wrong_seed, _wrong_pub = _keygen(tmp_path, "other")
    _new_seed, new_pub = _keygen(tmp_path, "issuer-2")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"
    out = tmp_path / "manifest-v2.json"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(wrong_seed),
            "--mldsa-key",
            str(mldsa_key),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert not out.exists()


def test_manifest_rotate_mldsa_pub_matches_but_sk_mismatched_errors(
    tmp_path: Path, capsys: CapSys
) -> None:
    seed_a, _pub_a, mldsa_a = _keygen_hybrid(tmp_path, "issuer-a")
    _seed_b, _pub_b, mldsa_b = _keygen_hybrid(tmp_path, "issuer-b")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed_a, mldsa_a, "manifest-v1.json")

    key_a = json.loads(mldsa_a.read_text(encoding="utf-8"))
    key_b = json.loads(mldsa_b.read_text(encoding="utf-8"))
    spliced = tmp_path / "spliced.mldsa"
    spliced.write_text(
        json.dumps({"alg": pq.ML_DSA_65_ALG, "sk": key_b["sk"], "pub": key_a["pub"]}),
        encoding="utf-8",
    )

    _new_seed, new_pub = _keygen(tmp_path, "issuer-2")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"
    out = tmp_path / "manifest-v2.json"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed_a),
            "--mldsa-key",
            str(spliced),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert not out.exists()


def test_manifest_rotate_unknown_signing_kid_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest-v1.json")
    unknown_kid = f"{ISSUER}/keys/unknown#ed25519-1"
    out = tmp_path / "manifest-v2.json"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            unknown_kid,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--retire-kid",
            KID,
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert not out.exists()


# --- hybrid rotation continuity and Ed25519 input/output alias guards -------


def test_manifest_init_spliced_mldsa_key_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed_a, _pub_a, mldsa_a = _keygen_hybrid(tmp_path, "issuer-a")
    _seed_b, _pub_b, mldsa_b = _keygen_hybrid(tmp_path, "issuer-b")
    key_a = json.loads(mldsa_a.read_text(encoding="utf-8"))
    key_b = json.loads(mldsa_b.read_text(encoding="utf-8"))
    spliced = tmp_path / "spliced.mldsa"
    spliced.write_text(
        json.dumps({"alg": pq.ML_DSA_65_ALG, "sk": key_b["sk"], "pub": key_a["pub"]}),
        encoding="utf-8",
    )
    out = tmp_path / "manifest.json"

    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed_a),
            "--mldsa-key",
            str(spliced),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert not out.exists()


def test_manifest_rotate_noncontinuous_signer_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed_a, _pub_a = _keygen(tmp_path, "issuer-a")
    manifest_v1 = _manifest_init(tmp_path, seed_a, "manifest-v1.json")
    seed_b, pub_b = _keygen(tmp_path, "issuer-b")
    kid_b = f"{ISSUER}/keys/test-2#ed25519-1"
    out = tmp_path / "manifest-v2.json"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            kid_b,
            "--signing-seed",
            str(seed_b),
            "--new-kid",
            kid_b,
            "--new-pub",
            str(pub_b),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert not out.exists()


def test_manifest_rotate_to_new_hybrid_key_roundtrips(tmp_path: Path) -> None:
    from attest import manifests

    seed_a, _pub_a, mldsa_a = _keygen_hybrid(tmp_path, "issuer-a")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed_a, mldsa_a, "manifest-v1.json")
    _seed_b, pub_b, mldsa_b = _keygen_hybrid(tmp_path, "issuer-b")
    kid_b = f"{ISSUER}/keys/test-2#ed25519-1"
    mldsa_pub_b = tmp_path / "issuer-b.mldsa.pub"
    mldsa_pub_b.write_text(json.loads(mldsa_b.read_text(encoding="utf-8"))["pub"], encoding="utf-8")
    out = tmp_path / "manifest-v2.json"

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed_a),
            "--mldsa-key",
            str(mldsa_a),
            "--new-kid",
            kid_b,
            "--new-pub",
            str(pub_b),
            "--new-mldsa-pub",
            str(mldsa_pub_b),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    candidate = json.loads(out.read_text(encoding="utf-8"))
    assert manifests.find_key(candidate, kid_b)["pub_ml_dsa_65"] == mldsa_pub_b.read_text(
        encoding="utf-8"
    )
    assert manifests.verify_key_manifest(candidate) is True
    assert manifests.check_continuity(
        json.loads(manifest_v1.read_text(encoding="utf-8")), candidate
    )


def test_manifest_rotate_new_mldsa_pub_requires_new_pub(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub, mldsa_key = _keygen_hybrid(tmp_path, "issuer")
    manifest_v1 = _manifest_init_hybrid(tmp_path, seed, mldsa_key, "manifest-v1.json")
    mldsa_pub = tmp_path / "new.mldsa.pub"
    mldsa_pub.write_text(json.loads(mldsa_key.read_text(encoding="utf-8"))["pub"], encoding="utf-8")

    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_v1),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--mldsa-key",
            str(mldsa_key),
            "--new-mldsa-pub",
            str(mldsa_pub),
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(tmp_path / "manifest-v2.json"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_manifest_init_seed_aliased_with_out_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    original_seed = seed.read_text(encoding="utf-8")

    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--out",
            str(seed),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert seed.read_text(encoding="utf-8") == original_seed


def test_issue_seed_aliased_with_out_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    original_seed = seed.read_text(encoding="utf-8")

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(seed),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert seed.read_text(encoding="utf-8") == original_seed


def test_issue_seed_aliased_with_salt_out_errors(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    salt = _write_salt_file(tmp_path, "buyer.salt", b"s" * 16)
    original_seed = seed.read_text(encoding="utf-8")

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--salt",
            str(salt),
            "--salt-out",
            str(seed),
            "--out",
            str(tmp_path / "envelope.json"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert seed.read_text(encoding="utf-8") == original_seed


# --- log: operator/holder commands + verify --transparency (Stage 2) --------
#
# The offline-signer split: `log append` is the CI-side step, holding no
# signing key, and only ever writes an UNSIGNED checkpoint.candidate. `log
# sign-checkpoint` is the ceremony-side step — the only command that may hold
# the log's signing keys — and refuses to sign unless its OWN recomputation
# from the entries file matches the candidate, and (once a prior signed
# checkpoint exists) unless the new tree is a verified consistency-proof
# extension of it.

LOG_ORIGIN = "attest-transparency-log.example/test"
LOG_NAME = "attest-test-log-2026"


def _log_init(tmp_path: Path, name: str = "log", origin: str = LOG_ORIGIN) -> Path:
    log_dir = tmp_path / name
    rc = cli.main(["log", "init", "--dir", str(log_dir), "--origin", origin])
    assert rc == 0
    return log_dir


def _log_append(
    tmp_path: Path, log_dir: Path, entry: dict[str, Any], name: str = "entry.json"
) -> Path:
    entry_path = tmp_path / name
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    entry_path.write_text(json.dumps(entry), encoding="utf-8")
    rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_path)])
    assert rc == 0
    return log_dir / "checkpoint.candidate"


def _log_sign_checkpoint(
    log_dir: Path, ed25519_key: Path, mldsa_key: Path, name: str = LOG_NAME
) -> Path:
    rc = cli.main(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--ed25519-key",
            str(ed25519_key),
            "--mldsa-key",
            str(mldsa_key),
            "--name",
            name,
        ]
    )
    assert rc == 0
    return log_dir / "checkpoint"


def _log_prove(
    tmp_path: Path, log_dir: Path, leaf_index: int, out_name: str = "evidence.json"
) -> Path:
    out = tmp_path / out_name
    out.parent.mkdir(parents=True, exist_ok=True)
    rc = cli.main(
        [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--leaf-index",
            str(leaf_index),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    return out


def _log_keys_file(
    tmp_path: Path,
    ed_pub_out: Path,
    mldsa_out: Path,
    origin: str = LOG_ORIGIN,
    name: str = LOG_NAME,
) -> Path:
    ed_pub_b64u = ed_pub_out.read_text(encoding="utf-8").strip()
    mldsa_key_file = json.loads(mldsa_out.read_text(encoding="utf-8"))
    path = tmp_path / "log-keys.json"
    path.write_text(
        json.dumps(
            [
                {
                    "origin": origin,
                    "name": name,
                    "ed25519_pub_b64u": ed_pub_b64u,
                    "mldsa_pub_b64u": mldsa_key_file["pub"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def _anchor_policy_file(
    tmp_path: Path,
    name: str = "anchor-policy.json",
    pinned_headers: dict[str, Any] | None = None,
    crqc_horizon: int | None = None,
) -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps({"pinned_headers": pinned_headers or {}, "crqc_horizon": crqc_horizon}),
        encoding="utf-8",
    )
    return path


def _receipt_entry(envelope_path: Path) -> dict[str, Any]:
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    return {
        "type": "receipt",
        "issuer": envelope["payload"]["issuer"]["id"],
        "core_sha256": tlog.receipt_core_hash(envelope),
    }


def _write_just_over_limit_file(path: Path, limit: int) -> None:
    """Create a sparse, just-over-limit input without allocating its payload."""
    with path.open("wb") as file:
        file.truncate(limit + 1)


def _minimal_anchor_evidence() -> dict[str, str]:
    """A structurally valid checkpoint is enough to reach anchor input reads."""
    checkpoint = "\n".join(
        [
            LOG_ORIGIN,
            "0",
            base64.b64encode(bytes(32)).decode("ascii"),
            "",
            "— test-signer AA==",
            "",
        ]
    )
    return {"checkpoint": checkpoint}


def _v2_ots_proof(checkpoint_text: str) -> dict[str, object]:
    """Build an `--ots-proof` file whose op-chain genuinely replays from
    `SHA256(signed_note_bytes)` (the signed-note-v2 seed) — the single
    `["sha256"]` op, so `header_merkle_root` is just `SHA256(that seed)`.
    Used by tests that only care about reaching code AFTER attachment-time
    seed validation (G4/I2), not about the op-chain's own shape."""
    signed_note_bytes = tlog.parse_checkpoint(checkpoint_text).signed_note_bytes
    seed = hashlib.sha256(signed_note_bytes).digest()
    return {
        "ops": [["sha256"]],
        "header_merkle_root": hashlib.sha256(seed).hexdigest(),
        "header_hash": "11" * 32,
        "header_time": 1700000000,
    }


def _v1_ots_proof(checkpoint_text: str) -> dict[str, object]:
    """Same as `_v2_ots_proof` but seeded from `SHA256(note_bytes)` (the
    legacy pre-G4 seed) — used to exercise the legacy-diagnostic error."""
    note_bytes = tlog.parse_checkpoint(checkpoint_text).note_bytes
    seed = hashlib.sha256(note_bytes).digest()
    return {
        "ops": [["sha256"]],
        "header_merkle_root": hashlib.sha256(seed).hexdigest(),
        "header_hash": "11" * 32,
        "header_time": 1700000000,
    }


@pytest.mark.parametrize(
    "flag", ["--transparency", "--log-keys", "--anchor-policy", "--witness-policy"]
)
def test_verify_rejects_oversized_stage2_json_input(
    tmp_path: Path, capsys: CapSys, flag: str
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    oversized = tmp_path / f"oversized-{flag.removeprefix('--')}.json"
    _write_just_over_limit_file(oversized, cli._MAX_STAGE2_INPUT_BYTES["json"])

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(_trust_dir(tmp_path, manifest_path)),
            flag,
            str(oversized),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert f"{flag} input exceeds" in captured.err


def test_log_anchor_rejects_oversized_ots_proof_input(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(_minimal_anchor_evidence()), encoding="utf-8")
    oversized = tmp_path / "oversized-ots-proof.json"
    _write_just_over_limit_file(oversized, cli._MAX_STAGE2_INPUT_BYTES["json"])

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(oversized),
            "--out",
            str(tmp_path / "anchored.json"),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "--ots-proof input exceeds" in captured.err


def test_log_anchor_rejects_oversized_rfc3161_token_input(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(_minimal_anchor_evidence()), encoding="utf-8")
    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text("{}", encoding="utf-8")
    oversized = tmp_path / "oversized-rfc3161.tsr"
    _write_just_over_limit_file(oversized, cli._MAX_STAGE2_INPUT_BYTES["rfc3161"])

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--rfc3161-token",
            str(oversized),
            "--out",
            str(tmp_path / "anchored.json"),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "--rfc3161-token input exceeds" in captured.err


def test_log_anchor_max_cap_rfc3161_token_stays_within_verifier_evidence_ceiling(
    tmp_path: Path, capsys: CapSys
) -> None:
    """A token accepted at the cap must never yield anchored evidence the
    verifier is forced to reject on its 10M-character total-evidence ceiling:
    the cap must leave room for the base64 expansion PLUS checkpoint and JSON
    overhead inside the same evidence object."""
    log_dir = _log_init(tmp_path)
    minimal_evidence = _minimal_anchor_evidence()
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(minimal_evidence), encoding="utf-8")
    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(
        json.dumps(_v2_ots_proof(minimal_evidence["checkpoint"])), encoding="utf-8"
    )
    max_cap_token = tmp_path / "max-cap-rfc3161.tsr"
    with max_cap_token.open("wb") as file:
        file.truncate(cli._MAX_STAGE2_INPUT_BYTES["rfc3161"])
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--rfc3161-token",
            str(max_cap_token),
            "--out",
            str(out_path),
        ]
    )
    capsys.readouterr()

    assert rc == 0
    written = out_path.read_text(encoding="utf-8")
    assert len(written) <= verify._MAX_TRANSPARENCY_EVIDENCE_LEN


def test_log_anchor_refuses_evidence_exceeding_verifier_ceiling(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    header = f"{LOG_ORIGIN}\n0\n" + base64.b64encode(bytes(32)).decode("ascii") + "\n"
    checkpoint = (
        header + "\n" + "— " + "n" * (tlog._MAX_NOTE_TEXT_LEN - len(header) - 10) + " AA==\n"
    )
    assert tlog.parse_checkpoint(checkpoint).origin == LOG_ORIGIN

    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps({"checkpoint": checkpoint}), encoding="utf-8")
    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(json.dumps(_v2_ots_proof(checkpoint)), encoding="utf-8")
    max_cap_token = tmp_path / "max-cap-rfc3161.tsr"
    with max_cap_token.open("wb") as file:
        file.truncate(cli._MAX_STAGE2_INPUT_BYTES["rfc3161"])
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--rfc3161-token",
            str(max_cap_token),
            "--out",
            str(out_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "verifier's evidence ceiling" in captured.err
    assert str(verify._MAX_TRANSPARENCY_EVIDENCE_LEN) in captured.err
    assert not out_path.exists()


def test_log_append_rejects_oversized_entry_json_input(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    oversized = tmp_path / "oversized-entry.json"
    _write_just_over_limit_file(oversized, cli._MAX_STAGE2_INPUT_BYTES["json"])

    capsys.readouterr()
    rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(oversized)])
    captured = capsys.readouterr()

    assert rc == 2
    assert "--entry-json input exceeds" in captured.err


def test_log_sign_checkpoint_rejects_oversized_candidate_input(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    candidate_path = log_dir / "checkpoint.candidate"
    _write_just_over_limit_file(candidate_path, cli._MAX_STAGE2_INPUT_BYTES["candidate"])

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--ed25519-key",
            str(tmp_path / "unused.seed"),
            "--mldsa-key",
            str(tmp_path / "unused.mldsa"),
            "--name",
            LOG_NAME,
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "checkpoint candidate input exceeds" in captured.err


def test_log_init_then_append_writes_unsigned_candidate(tmp_path: Path) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    candidate = _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))

    assert candidate.exists()
    candidate_text = candidate.read_text(encoding="utf-8")
    lines = candidate_text.split("\n")
    assert lines[0] == LOG_ORIGIN
    assert lines[1] == "1"
    # Genuinely unsigned: a real (hybrid-signed) checkpoint has signature
    # lines after a blank line, so a bare 3-line body must fail to parse.
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(candidate_text)


def test_log_append_rejects_malformed_entry_without_writing_candidate(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    bad_entry_path = tmp_path / "bad-entry.json"
    bad_entry_path.write_text(
        json.dumps({"type": "receipt", "issuer": "not a dns name"}), encoding="utf-8"
    )

    capsys.readouterr()
    rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(bad_entry_path)])
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.err != ""
    assert not (log_dir / "checkpoint.candidate").exists()
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""


def test_sign_checkpoint_refuses_when_candidate_root_mismatches_recomputation(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))

    candidate_path = log_dir / "checkpoint.candidate"
    lines = candidate_path.read_text(encoding="utf-8").split("\n")
    lines[2] = base64.b64encode(bytes(range(32))).decode("ascii")  # a different, wrong root
    candidate_path.write_text("\n".join(lines), encoding="utf-8")

    _ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    ed_seed = tmp_path / "log-signer.seed"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--ed25519-key",
            str(ed_seed),
            "--mldsa-key",
            str(mldsa_out),
            "--name",
            LOG_NAME,
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.err != ""
    assert not (log_dir / "checkpoint").exists()


def test_sign_checkpoint_refuses_on_history_rewrite_after_prior_checkpoint(
    tmp_path: Path,
) -> None:
    """The consistency check against the PRIOR signed checkpoint is a
    distinct security property from the candidate-recomputation check: here
    the candidate is self-consistent with a (silently rewritten) entries
    file, so only the prior-checkpoint consistency proof catches the
    equivocation."""
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")

    payload_a = _write_payload(tmp_path, "payload-a.json", receipt_id="01J1V5B4M9Z8QWERTY12345671")
    envelope_a = _issue(tmp_path, seed, payload_a, out_name="envelope-a.json")
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_a), name="entry-a.json")
    checkpoint_path = _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    signed_at_size_1 = checkpoint_path.read_text(encoding="utf-8")

    # Simulate a history rewrite: silently replace the already-signed entry.
    payload_b = _write_payload(tmp_path, "payload-b.json", receipt_id="01J1V5B4M9Z8QWERTY12345672")
    envelope_b = _issue(tmp_path, seed, payload_b, out_name="envelope-b.json")
    (log_dir / "entries.jsonl").write_text(
        json.dumps(_receipt_entry(envelope_b)) + "\n", encoding="utf-8"
    )

    payload_c = _write_payload(tmp_path, "payload-c.json", receipt_id="01J1V5B4M9Z8QWERTY12345673")
    envelope_c = _issue(tmp_path, seed, payload_c, out_name="envelope-c.json")
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_c), name="entry-c.json")

    rc = cli.main(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--ed25519-key",
            str(ed_seed),
            "--mldsa-key",
            str(mldsa_out),
            "--name",
            LOG_NAME,
        ]
    )

    assert rc == 2
    assert checkpoint_path.read_text(encoding="utf-8") == signed_at_size_1


def test_log_sign_checkpoint_rejects_aliased_signer_keys(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))

    ed_seed, _ed_pub, _mldsa_out = _keygen_hybrid(tmp_path, "log-signer")

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--ed25519-key",
            str(ed_seed),
            "--mldsa-key",
            str(ed_seed),
            "--name",
            LOG_NAME,
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.err != ""
    assert not (log_dir / "checkpoint").exists()


def test_log_sign_prove_verify_roundtrip_yields_transparency_logged(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")

    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    evidence_path = _log_prove(tmp_path, log_dir, 0)

    log_keys_path = _log_keys_file(tmp_path, ed_pub, mldsa_out)
    anchor_policy_path = _anchor_policy_file(tmp_path)

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--transparency",
            str(evidence_path),
            "--log-keys",
            str(log_keys_path),
            "--anchor-policy",
            str(anchor_policy_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["ok"] is True
    assert result["transparency"] == "logged"
    assert result["corroboration"] == "logged"


def test_verify_crqc_horizon_before_anchor_time_caps_transparency(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")

    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    checkpoint_path = _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    evidence_path = _log_prove(tmp_path, log_dir, 0)

    checkpoint_text = checkpoint_path.read_text(encoding="utf-8")
    # `attest log anchor` stamps `anchor_profile: "signed-note-v2"` on every
    # newly-attached anchor (G4, attest-v0.2.md §11.1), so the op-chain this
    # externally-obtained OTS proof replays must commit over the checkpoint's
    # FULL signed note (`signed_note_bytes`), not just its unsigned header.
    signed_note_bytes = tlog.parse_checkpoint(checkpoint_text).signed_note_bytes
    accumulator_start = hashlib.sha256(signed_note_bytes).digest()
    header_merkle_root = hashlib.sha256(accumulator_start).digest().hex()
    header_hash = hashlib.sha256(b"attest-cli-test-anchor-header-v1").hexdigest()
    header_time = 1700000000  # transparency.py's own documented KAT: -> 2023-11-14T22:13:20Z

    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(
        json.dumps(
            {
                "ops": [["sha256"]],
                "header_merkle_root": header_merkle_root,
                "header_hash": header_hash,
                "header_time": header_time,
            }
        ),
        encoding="utf-8",
    )
    anchored_path = tmp_path / "anchored-evidence.json"
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(anchored_path),
        ]
    )
    assert rc == 0

    log_keys_path = _log_keys_file(tmp_path, ed_pub, mldsa_out)
    anchor_policy_path = _anchor_policy_file(
        tmp_path,
        pinned_headers={
            header_hash: {
                "header_hash": header_hash,
                "merkle_root": header_merkle_root,
                "time": header_time,
            }
        },
    )

    # Sanity check the fixture: without a horizon, the anchor upgrades standing.
    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--transparency",
            str(anchored_path),
            "--log-keys",
            str(log_keys_path),
            "--anchor-policy",
            str(anchor_policy_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert result["transparency"] == "anchored_before:2023-11-14T22:13:20Z"

    # A horizon set BEFORE the anchor's own time caps standing back down: the
    # anchor must land strictly before the horizon to survive it.
    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--transparency",
            str(anchored_path),
            "--log-keys",
            str(log_keys_path),
            "--anchor-policy",
            str(anchor_policy_path),
            "--crqc-horizon",
            "2020-01-01T00:00:00Z",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert result["transparency"] == "not_checked"


# --------------------------------------------------------------------------
# I1 (attest-v0.2.md §11.1.1): single-profile rule — `log anchor` must
# refuse to append a v2 proof to a bundle whose retained proofs are v1, and
# must not silently relabel those retained proofs' profile.
# --------------------------------------------------------------------------


def test_log_anchor_refuses_to_append_v2_proof_to_existing_v1_bundle(
    tmp_path: Path, capsys: CapSys
) -> None:
    minimal_evidence = _minimal_anchor_evidence()
    checkpoint_text = minimal_evidence["checkpoint"]
    log_dir = _log_init(tmp_path, origin=LOG_ORIGIN)

    # First anchor attach: no prior proofs, so it succeeds and the tool
    # stamps `anchor_profile: "signed-note-v2"` on the (only) retained proof
    # — but simulate a pre-G4 bundle that already carries a `note-v1`-shaped
    # proof by hand-writing `anchors` directly, exactly the shape pre-fix
    # tooling could have produced (proofs present, no anchor_profile field).
    v1_evidence = dict(minimal_evidence)
    v1_evidence["anchors"] = {
        "checkpoint": checkpoint_text,
        "proofs": [{**_v1_ots_proof(checkpoint_text), "kind": "ots"}],
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(v1_evidence), encoding="utf-8")

    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(json.dumps(_v2_ots_proof(checkpoint_text)), encoding="utf-8")
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(out_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "note-v1" in captured.err
    assert "exactly one anchor_profile" in captured.err
    assert "fresh signed-note-v2 bundle" in captured.err
    assert not out_path.exists()


def test_log_anchor_refuses_to_append_to_existing_bundle_declaring_explicit_note_v1(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Same refusal when the retained bundle explicitly declares
    `anchor_profile: "note-v1"` rather than leaving it absent."""
    minimal_evidence = _minimal_anchor_evidence()
    checkpoint_text = minimal_evidence["checkpoint"]
    log_dir = _log_init(tmp_path, origin=LOG_ORIGIN)

    v1_evidence = dict(minimal_evidence)
    v1_evidence["anchors"] = {
        "checkpoint": checkpoint_text,
        "proofs": [{**_v1_ots_proof(checkpoint_text), "kind": "ots"}],
        "anchor_profile": "note-v1",
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(v1_evidence), encoding="utf-8")

    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(json.dumps(_v2_ots_proof(checkpoint_text)), encoding="utf-8")
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(out_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "note-v1" in captured.err
    assert not out_path.exists()


def test_log_anchor_permits_appending_a_second_v2_proof_to_a_v2_bundle(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The single-profile rule only refuses a MISMATCHED profile — appending
    another v2 proof to an already-v2 bundle stays allowed."""
    minimal_evidence = _minimal_anchor_evidence()
    checkpoint_text = minimal_evidence["checkpoint"]
    log_dir = _log_init(tmp_path, origin=LOG_ORIGIN)

    v2_evidence = dict(minimal_evidence)
    v2_evidence["anchors"] = {
        "checkpoint": checkpoint_text,
        "proofs": [{**_v2_ots_proof(checkpoint_text), "kind": "ots"}],
        "anchor_profile": "signed-note-v2",
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(v2_evidence), encoding="utf-8")

    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(json.dumps(_v2_ots_proof(checkpoint_text)), encoding="utf-8")
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(out_path),
        ]
    )
    capsys.readouterr()

    assert rc == 0
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(written["anchors"]["proofs"]) == 2
    assert written["anchors"]["anchor_profile"] == "signed-note-v2"


# --------------------------------------------------------------------------
# I2(a) (attest-v0.2.md §11.1.1): attachment-time seed validation — `log
# anchor` refuses an --ots-proof whose op-chain does not commit over the
# signed-note-v2 seed, with a dedicated diagnostic for the common mistake
# of supplying a pre-G4 (note_bytes-only) proof.
# --------------------------------------------------------------------------


def test_log_anchor_refuses_pre_g4_note_bytes_seeded_ots_proof(
    tmp_path: Path, capsys: CapSys
) -> None:
    minimal_evidence = _minimal_anchor_evidence()
    checkpoint_text = minimal_evidence["checkpoint"]
    log_dir = _log_init(tmp_path, origin=LOG_ORIGIN)

    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(minimal_evidence), encoding="utf-8")
    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(json.dumps(_v1_ots_proof(checkpoint_text)), encoding="utf-8")
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(out_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "pre-G4 tooling" in captured.err
    assert "note_bytes" in captured.err
    assert "signed-note-v2 requires the full signed note" in captured.err
    assert not out_path.exists()


def test_log_anchor_refuses_ots_proof_with_unrelated_seed(tmp_path: Path, capsys: CapSys) -> None:
    minimal_evidence = _minimal_anchor_evidence()
    log_dir = _log_init(tmp_path, origin=LOG_ORIGIN)

    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(minimal_evidence), encoding="utf-8")
    ots_proof_path = tmp_path / "ots-proof.json"
    bogus_seed = hashlib.sha256(b"not-derived-from-this-checkpoint-at-all").digest()
    ots_proof_path.write_text(
        json.dumps(
            {
                "ops": [["sha256"]],
                "header_merkle_root": hashlib.sha256(bogus_seed).hexdigest(),
                "header_hash": "11" * 32,
                "header_time": 1700000000,
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(out_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "does not replay to its own header_merkle_root" in captured.err
    assert "signed-note-v2 seed SHA256(signed_note_bytes)=" in captured.err
    assert not out_path.exists()


def test_log_anchor_reports_ots_total_operand_cap(tmp_path: Path, capsys: CapSys) -> None:
    """A cap refusal must name the cap, not read as a commitment mismatch."""
    minimal_evidence = _minimal_anchor_evidence()
    log_dir = _log_init(tmp_path, origin=LOG_ORIGIN)
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(minimal_evidence), encoding="utf-8")

    target = anchor._MAX_TOTAL_OP_HEX_LEN + 2
    ops: list[list[str]] = []
    remaining = target
    while remaining > 0:
        take = min(1024, remaining)
        ops.append(["append", "ab" * (take // 2)])
        ops.append(["sha256"])
        remaining -= take
    assert len(ops) <= anchor._MAX_OPS_PER_PROOF

    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(
        json.dumps(
            {
                "ops": ops,
                "header_merkle_root": "00" * 32,
                "header_hash": "11" * 32,
                "header_time": 1700000000,
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(out_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert (
        f"ots proof operands exceed {anchor._MAX_TOTAL_OP_HEX_LEN} total hex chars" in captured.err
    )
    assert "does not replay to its own header_merkle_root" not in captured.err
    assert not out_path.exists()


def test_log_anchor_accepts_v2_seeded_ots_proof(tmp_path: Path, capsys: CapSys) -> None:
    """Positive counterpart: a genuinely v2-seeded proof is still accepted
    (RED-first control for the two refusal tests above)."""
    minimal_evidence = _minimal_anchor_evidence()
    checkpoint_text = minimal_evidence["checkpoint"]
    log_dir = _log_init(tmp_path, origin=LOG_ORIGIN)

    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(minimal_evidence), encoding="utf-8")
    ots_proof_path = tmp_path / "ots-proof.json"
    ots_proof_path.write_text(json.dumps(_v2_ots_proof(checkpoint_text)), encoding="utf-8")
    out_path = tmp_path / "anchored.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_proof_path),
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written["anchors"]["anchor_profile"] == "signed-note-v2"


def test_export_import_carries_proofs_via_proof_dir(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")

    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    receipt_id = json.loads(payload_path.read_text(encoding="utf-8"))["receipt_id"]

    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)

    proof_dir = tmp_path / "proofs-in"
    proof_dir.mkdir()
    _log_prove(tmp_path, log_dir, 0, out_name=f"proofs-in/{receipt_id}.json")

    legal_text_path = tmp_path / "legal.txt"
    legal_text_path.write_bytes(b"attest-test-legal-text-v1")
    mirror_policy_path = tmp_path / "mirror-policy.txt"
    mirror_policy_path.write_bytes(b"attest-test-mirror-policy-v1")

    out_dir = tmp_path / "exported"
    capsys.readouterr()
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
            "--proof-dir",
            str(proof_dir),
            "--out-dir",
            str(out_dir),
            "--name",
            "mylibrary",
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)

    with zipfile.ZipFile(report["attest"]) as zf:
        assert f"proofs/{receipt_id}.json" in zf.namelist()

    import_out_dir = tmp_path / "imported"
    capsys.readouterr()
    rc = cli.main(["import", "--bundle", report["attest"], "--out-dir", str(import_out_dir)])
    assert rc == 0
    import_report = json.loads(capsys.readouterr().out)

    assert import_report["proofs"] == 1
    assert (import_out_dir / "proofs" / f"{receipt_id}.json").exists()


def test_export_refuses_traversal_receipt_id_before_reading_outside_proof_dir(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even a hostile, schema-bypassing receipt JSON cannot turn --proof-dir
    into an arbitrary-file read through its receipt_id."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["payload"]["receipt_id"] = "../victim"
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")

    proof_dir = tmp_path / "proofs"
    proof_dir.mkdir()
    outside = tmp_path / "victim.json"
    outside.write_text(json.dumps({"must_not_be_read": True}), encoding="utf-8")
    original_read_json = cli._read_json

    def reject_outside_read(path: Path) -> Any:
        if path.resolve() == outside.resolve():
            pytest.fail("attest export tried to read outside --proof-dir")
        return original_read_json(path)

    monkeypatch.setattr(cli, "_read_json", reject_outside_read)
    legal_text_path = tmp_path / "legal.txt"
    legal_text_path.write_bytes(b"attest-test-legal-text-v1")
    mirror_policy_path = tmp_path / "mirror-policy.txt"
    mirror_policy_path.write_bytes(b"attest-test-mirror-policy-v1")
    out_dir = tmp_path / "exported"

    capsys.readouterr()
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
            "--proof-dir",
            str(proof_dir),
            "--out-dir",
            str(out_dir),
            "--name",
            "mylibrary",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "not a valid ULID" in captured.err
    assert outside.read_text(encoding="utf-8") == json.dumps({"must_not_be_read": True})
    assert not (out_dir / "mylibrary.attest").exists()


def test_import_rejects_hostile_proof_member_without_writing_outside_out_dir(
    tmp_path: Path, capsys: CapSys
) -> None:
    out_dir = tmp_path / "imported"
    outside = (out_dir / "proofs" / ".." / ".." / ".." / "victim.json").resolve()
    hostile_bundle = tmp_path / "hostile-proofs.attest"
    with zipfile.ZipFile(hostile_bundle, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("proofs/../../../victim.json", "{}")

    capsys.readouterr()
    rc = cli.main(["import", "--bundle", str(hostile_bundle), "--out-dir", str(out_dir)])
    captured = capsys.readouterr()

    assert rc == 2
    assert "invalid proof member path" in captured.err
    assert not outside.exists()
    assert not (out_dir / "proofs").exists()


def test_log_append_tile_failure_preserves_entries_and_retry_does_not_duplicate(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_a = _issue(
        tmp_path,
        seed,
        _write_payload(tmp_path, "payload-a.json", receipt_id="01J1V5B4M9Z8QWERTY12345671"),
    )
    entry_a = _receipt_entry(envelope_a)
    _log_append(tmp_path, log_dir, entry_a, name="entry-a.json")
    entries_path = log_dir / "entries.jsonl"
    candidate_path = log_dir / "checkpoint.candidate"
    prior_entries = entries_path.read_text(encoding="utf-8")
    prior_candidate = candidate_path.read_text(encoding="utf-8")

    # Distinct --out from envelope_a: the second issuance was only ever
    # incidentally reusing the default path, and `issue --out` no longer
    # overwrites a different envelope (2026-08-24 destructive-output-paths
    # plan, triage rule in section 6).
    envelope_b = _issue(
        tmp_path,
        seed,
        _write_payload(tmp_path, "payload-b.json", receipt_id="01J1V5B4M9Z8QWERTY12345672"),
        out_name="envelope-b.json",
    )
    entry_b = _receipt_entry(envelope_b)
    entry_b_path = tmp_path / "entry-b.json"
    entry_b_path.write_text(json.dumps(entry_b), encoding="utf-8")
    original_write_bytes = Path.write_bytes

    def fail_tile_write(path: Path, data: bytes) -> int:
        raise OSError("simulated tile write failure")

    monkeypatch.setattr(Path, "write_bytes", fail_tile_write)
    capsys.readouterr()
    rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_b_path)])
    captured = capsys.readouterr()

    assert rc == 2
    assert "simulated tile write failure" in captured.err
    assert entries_path.read_text(encoding="utf-8") == prior_entries
    assert candidate_path.read_text(encoding="utf-8") == prior_candidate

    monkeypatch.setattr(Path, "write_bytes", original_write_bytes)
    assert (
        cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_b_path)]) == 0
    )
    entries = [json.loads(line) for line in entries_path.read_text(encoding="utf-8").splitlines()]
    assert entries == [entry_a, entry_b]


def test_log_append_deduplicates_canonical_entry_without_mutating_state(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    entry_a = {"type": "receipt", "issuer": ISSUER, "core_sha256": "a" * 64}
    entry_a_path = tmp_path / "entry-a.json"
    entry_a_path.write_text(json.dumps(entry_a), encoding="utf-8")

    assert (
        cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_a_path)]) == 0
    )
    after_first = {
        path.relative_to(log_dir): path.read_bytes()
        for path in log_dir.rglob("*")
        if path.is_file()
    }

    duplicate_path = tmp_path / "entry-a-reordered.json"
    duplicate_path.write_text(
        json.dumps({"core_sha256": "a" * 64, "issuer": ISSUER, "type": "receipt"}),
        encoding="utf-8",
    )
    capsys.readouterr()
    rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(duplicate_path)])
    duplicate_result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert duplicate_result["leaf_index"] == 0
    assert duplicate_result["duplicate"] is True
    assert {
        path.relative_to(log_dir): path.read_bytes()
        for path in log_dir.rglob("*")
        if path.is_file()
    } == after_first

    entry_b = {"type": "receipt", "issuer": ISSUER, "core_sha256": "b" * 64}
    entry_b_path = tmp_path / "entry-b.json"
    entry_b_path.write_text(json.dumps(entry_b), encoding="utf-8")
    capsys.readouterr()
    rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_b_path)])
    distinct_result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert distinct_result["leaf_index"] == 1
    assert "duplicate" not in distinct_result


def test_log_sign_checkpoint_replace_failure_preserves_existing_checkpoint_and_entries(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    checkpoint_path = _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    prior_checkpoint = checkpoint_path.read_text(encoding="utf-8")
    prior_entries = (log_dir / "entries.jsonl").read_text(encoding="utf-8")
    original_replace = cli.os.replace

    def fail_checkpoint_replace(source: Path | str, destination: Path | str) -> None:
        if Path(destination) == checkpoint_path:
            raise OSError("simulated checkpoint replace failure")
        original_replace(source, destination)

    monkeypatch.setattr(cli.os, "replace", fail_checkpoint_replace)
    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--ed25519-key",
            str(ed_seed),
            "--mldsa-key",
            str(mldsa_out),
            "--name",
            LOG_NAME,
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "simulated checkpoint replace failure" in captured.err
    assert checkpoint_path.read_text(encoding="utf-8") == prior_checkpoint
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == prior_entries


def test_log_state_files_are_published_with_umask_default_modes(tmp_path: Path) -> None:
    """LOG state files are public artifacts meant for static hosting: routing
    them through mkstemp/mkdtemp staging must not install owner-only modes."""
    previous_umask = os.umask(0o022)
    try:
        log_dir = _log_init(tmp_path)
        seed, _pub = _keygen(tmp_path, "issuer")
        envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
        _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
        ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
        _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    finally:
        os.umask(previous_umask)

    for state_file in ("entries.jsonl", "checkpoint.candidate", "checkpoint"):
        assert stat.S_IMODE((log_dir / state_file).stat().st_mode) == 0o644, state_file
    tile_dir = log_dir / "tile" / "0"
    assert stat.S_IMODE(tile_dir.stat().st_mode) == 0o755
    for tile in tile_dir.iterdir():
        assert stat.S_IMODE(tile.stat().st_mode) == 0o644, tile.name


# --- transfer authorize / record (v0.2 §17) ----------------------------------

NEW_HOLDER_PUB_B64U = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 32 zero bytes
TRANSFERRED_AT = "2026-07-23T00:00:00Z"


def _transfer_authorize(
    tmp_path: Path,
    receipt_path: Path,
    holder_seed: Path,
    out_name: str = "authorization.json",
    new_holder_pubkey: str = NEW_HOLDER_PUB_B64U,
    transferred_at: str = TRANSFERRED_AT,
) -> Path:
    out = tmp_path / out_name
    rc = cli.main(
        [
            "transfer",
            "authorize",
            "--receipt",
            str(receipt_path),
            "--new-holder-pubkey",
            new_holder_pubkey,
            "--transferred-at",
            transferred_at,
            "--holder-seed",
            str(holder_seed),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    return out


def test_transfer_authorize_writes_verifiable_holder_signature(tmp_path: Path) -> None:
    holder_seed, holder_pub = _keygen(tmp_path, "holder")
    issuer_seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(
        tmp_path, buyer={"pubkey": holder_pub.read_text(encoding="utf-8").strip()}
    )
    envelope_path = _issue(tmp_path, issuer_seed, payload_path)
    receipt_id = json.loads(payload_path.read_text(encoding="utf-8"))["receipt_id"]

    out = _transfer_authorize(tmp_path, envelope_path, holder_seed)

    authorization = json.loads(out.read_text(encoding="utf-8"))
    assert set(authorization) == {"sig"}
    holder_kp = keys.from_seed(keys.b64u_decode(holder_seed.read_text(encoding="utf-8").strip()))
    holder_pub_bytes = holder_kp.pub
    message = (
        b"Attest-transfer-authorization-v1\x00"
        + receipt_id.encode()
        + b"\x00"
        + NEW_HOLDER_PUB_B64U.encode()
        + b"\x00"
        + TRANSFERRED_AT.encode()
    )
    assert keys.verify_strict(message, keys.b64u_decode(authorization["sig"]), holder_pub_bytes)


def test_transfer_authorize_never_prints_the_signature_to_stdout(
    tmp_path: Path, capsys: CapSys
) -> None:
    holder_seed, holder_pub = _keygen(tmp_path, "holder")
    issuer_seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(
        tmp_path, buyer={"pubkey": holder_pub.read_text(encoding="utf-8").strip()}
    )
    envelope_path = _issue(tmp_path, issuer_seed, payload_path)

    capsys.readouterr()
    out = _transfer_authorize(tmp_path, envelope_path, holder_seed)
    captured = capsys.readouterr().out

    sig_text = json.loads(out.read_text(encoding="utf-8"))["sig"]
    assert sig_text not in captured


@pytest.mark.parametrize("aliased_input", ("receipt", "holder-seed"))
def test_transfer_authorize_rejects_out_aliased_with_input(
    tmp_path: Path, capsys: CapSys, aliased_input: str
) -> None:
    holder_seed, holder_pub = _keygen(tmp_path, "holder")
    issuer_seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(
        tmp_path, buyer={"pubkey": holder_pub.read_text(encoding="utf-8").strip()}
    )
    receipt_path = _issue(tmp_path, issuer_seed, payload_path)
    aliased_path = receipt_path if aliased_input == "receipt" else holder_seed
    original = aliased_path.read_text(encoding="utf-8")

    rc = cli.main(
        [
            "transfer",
            "authorize",
            "--receipt",
            str(receipt_path),
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-seed",
            str(holder_seed),
            "--out",
            str(aliased_path),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert aliased_path.read_text(encoding="utf-8") == original


def _write_authorization_sig(
    tmp_path: Path, receipt_id: str, holder_kp: keys.SigningKeyPair
) -> Path:
    sig = transfer.sign_authorization(receipt_id, NEW_HOLDER_PUB_B64U, TRANSFERRED_AT, holder_kp)
    out = tmp_path / "authorization.json"
    out.write_text(json.dumps({"sig": keys.b64u(sig)}), encoding="utf-8")
    return out


def _write_transfer_receipt(
    tmp_path: Path,
    issuer_seed: Path,
    holder_kp: keys.SigningKeyPair,
    receipt_id: str,
) -> Path:
    payload_path = _write_payload(
        tmp_path,
        name="old-payload.json",
        receipt_id=receipt_id,
        buyer={"pubkey": keys.b64u(holder_kp.pub)},
    )
    return _issue(tmp_path, issuer_seed, payload_path, out_name="old-envelope.json")


def test_transfer_record_writes_self_verifying_record(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    holder_kp = keys.generate()
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    new_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
    receipt_path = _write_transfer_receipt(tmp_path, seed, holder_kp, old_receipt_id)
    authorization_path = _write_authorization_sig(tmp_path, old_receipt_id, holder_kp)
    out = tmp_path / "record.json"

    rc = cli.main(
        [
            "transfer",
            "record",
            "--receipt",
            str(receipt_path),
            "--new-receipt-id",
            new_receipt_id,
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-authorization",
            str(authorization_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    record = json.loads(out.read_text(encoding="utf-8"))
    key_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(record) == {
        "receipt_id",
        "new_receipt_id",
        "new_holder_pubkey",
        "transferred_at",
        "holder_authorization",
        "signature",
    }
    assert transfer.verify_record(record, key_manifest) is True
    assert transfer.verify_authorization(record, keys.b64u(holder_kp.pub)) is True
    assert record["receipt_id"] == old_receipt_id
    assert record["new_receipt_id"] == new_receipt_id


def test_transfer_record_with_revocation_out_writes_transferred_revocation(
    tmp_path: Path,
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    holder_kp = keys.generate()
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    new_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
    receipt_path = _write_transfer_receipt(tmp_path, seed, holder_kp, old_receipt_id)
    authorization_path = _write_authorization_sig(tmp_path, old_receipt_id, holder_kp)
    record_out = tmp_path / "record.json"
    revocation_out = tmp_path / "revocation.json"

    rc = cli.main(
        [
            "transfer",
            "record",
            "--receipt",
            str(receipt_path),
            "--new-receipt-id",
            new_receipt_id,
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-authorization",
            str(authorization_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--revocation-out",
            str(revocation_out),
            "--out",
            str(record_out),
        ]
    )

    assert rc == 0
    revocation_record = json.loads(revocation_out.read_text(encoding="utf-8"))
    key_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert revocation_record["status"] == "transferred"
    assert revocation_record["receipt_id"] == old_receipt_id
    assert revocation.verify_record(revocation_record, key_manifest) is True


def test_transfer_record_hybrid_with_mldsa_seed(tmp_path: Path) -> None:
    seed, _pub, mldsa_out = _keygen_hybrid(tmp_path, "issuer")
    manifest_path = tmp_path / "manifest.json"
    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--mldsa-key",
            str(mldsa_out),
            "--out",
            str(manifest_path),
        ]
    )
    assert rc == 0
    holder_kp = keys.generate()
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    new_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
    receipt_path = _write_transfer_receipt(tmp_path, seed, holder_kp, old_receipt_id)
    authorization_path = _write_authorization_sig(tmp_path, old_receipt_id, holder_kp)
    out = tmp_path / "record.json"

    rc = cli.main(
        [
            "transfer",
            "record",
            "--receipt",
            str(receipt_path),
            "--new-receipt-id",
            new_receipt_id,
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-authorization",
            str(authorization_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--mldsa-seed",
            str(mldsa_out),
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    record = json.loads(out.read_text(encoding="utf-8"))
    assert "sig_ml_dsa_65" in record["signature"]
    key_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert transfer.verify_record(record, key_manifest) is True


def test_transfer_record_seed_and_out_same_path_exits_2(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    holder_kp = keys.generate()
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    receipt_path = _write_transfer_receipt(tmp_path, seed, holder_kp, old_receipt_id)
    authorization_path = _write_authorization_sig(tmp_path, old_receipt_id, holder_kp)

    rc = cli.main(
        [
            "transfer",
            "record",
            "--receipt",
            str(receipt_path),
            "--new-receipt-id",
            "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-authorization",
            str(authorization_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(seed),
        ]
    )

    assert rc == 2


@pytest.mark.parametrize(
    "collision",
    (
        "out-seed",
        "out-holder-authorization",
        "out-mldsa-seed",
        "out-receipt",
        "revocation-out-out",
        "revocation-out-seed",
        "revocation-out-holder-authorization",
        "revocation-out-mldsa-seed",
        "revocation-out-receipt",
    ),
)
def test_transfer_record_rejects_aliased_paths_before_writing(
    tmp_path: Path, capsys: CapSys, collision: str
) -> None:
    seed, _pub, mldsa_seed = _keygen_hybrid(tmp_path, "issuer")
    holder_kp = keys.generate()
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    receipt_path = _write_transfer_receipt(tmp_path, seed, holder_kp, old_receipt_id)
    authorization_path = _write_authorization_sig(tmp_path, old_receipt_id, holder_kp)
    record_out = tmp_path / "record.json"
    revocation_out = tmp_path / "revocation.json"
    expected_path: Path

    if collision == "out-seed":
        record_out = seed
        expected_path = seed
    elif collision == "out-holder-authorization":
        record_out = authorization_path
        expected_path = authorization_path
    elif collision == "out-mldsa-seed":
        record_out = mldsa_seed
        expected_path = mldsa_seed
    elif collision == "out-receipt":
        record_out = receipt_path
        expected_path = receipt_path
    elif collision == "revocation-out-out":
        record_out.write_text("record sentinel", encoding="utf-8")
        revocation_out = record_out
        expected_path = record_out
    elif collision == "revocation-out-seed":
        revocation_out = seed
        expected_path = seed
    elif collision == "revocation-out-holder-authorization":
        revocation_out = authorization_path
        expected_path = authorization_path
    elif collision == "revocation-out-receipt":
        revocation_out = receipt_path
        expected_path = receipt_path
    else:
        revocation_out = mldsa_seed
        expected_path = mldsa_seed
    original = expected_path.read_text(encoding="utf-8")

    rc = cli.main(
        [
            "transfer",
            "record",
            "--receipt",
            str(receipt_path),
            "--new-receipt-id",
            "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-authorization",
            str(authorization_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--mldsa-seed",
            str(mldsa_seed),
            "--revocation-out",
            str(revocation_out),
            "--out",
            str(record_out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""
    assert expected_path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("authorization_kind", ("forged", "mismatched"))
def test_transfer_record_rejects_invalid_holder_authorization_without_writing(
    tmp_path: Path, capsys: CapSys, authorization_kind: str
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    holder_kp = keys.generate()
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    receipt_path = _write_transfer_receipt(tmp_path, seed, holder_kp, old_receipt_id)
    signer = keys.generate() if authorization_kind == "forged" else holder_kp
    signed_new_holder = (
        NEW_HOLDER_PUB_B64U
        if authorization_kind == "forged"
        else "__________________________________________8"
    )
    authorization_path = _write_authorization_sig(tmp_path, old_receipt_id, signer)
    if authorization_kind == "mismatched":
        authorization_path.write_text(
            json.dumps(
                {
                    "sig": keys.b64u(
                        transfer.sign_authorization(
                            old_receipt_id, signed_new_holder, TRANSFERRED_AT, holder_kp
                        )
                    )
                }
            ),
            encoding="utf-8",
        )
    out = tmp_path / "record.json"
    revocation_out = tmp_path / "revocation.json"

    rc = cli.main(
        [
            "transfer",
            "record",
            "--receipt",
            str(receipt_path),
            "--new-receipt-id",
            "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-authorization",
            str(authorization_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--revocation-out",
            str(revocation_out),
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert "holder authorization" in capsys.readouterr().err
    assert not out.exists()
    assert not revocation_out.exists()


def test_transfer_record_rejects_receipt_without_holder_pubkey(
    tmp_path: Path, capsys: CapSys
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    old_receipt_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    payload_path = _write_payload(
        tmp_path,
        name="old-payload.json",
        receipt_id=old_receipt_id,
        buyer={"pubkey": None},
    )
    receipt_path = _issue(tmp_path, seed, payload_path, out_name="old-envelope.json")
    authorization_path = _write_authorization_sig(tmp_path, old_receipt_id, keys.generate())
    out = tmp_path / "record.json"

    rc = cli.main(
        [
            "transfer",
            "record",
            "--receipt",
            str(receipt_path),
            "--new-receipt-id",
            "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "--new-holder-pubkey",
            NEW_HOLDER_PUB_B64U,
            "--transferred-at",
            TRANSFERRED_AT,
            "--holder-authorization",
            str(authorization_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert "non-null buyer.pubkey" in capsys.readouterr().err
    assert not out.exists()


# --------------------------------------------------------------------------
# P1.1b (attest-v0.2.md §11.4): `--witness-policy` is trusted verifier
# configuration on the same rail as `--log-keys`. The reachable-`witnessed`
# path itself is pinned by conformance group 39, which is language-neutral;
# what belongs here is the CLI contract — the flag exists, a malformed
# document is a usage error, and a well-formed one changes nothing on its own.
# --------------------------------------------------------------------------


_CANONICAL_EMPTY_WITNESS_POLICY = '{"epochs":[],"schema":"attest-witness-policy-v1"}'


def test_verify_rejects_a_malformed_witness_policy(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    trust_dir = _trust_dir(tmp_path, manifest_path)
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    policy_path = tmp_path / "bad-witness-policy.json"
    policy_path.write_text('{"schema":"wrong","epochs":[]}', encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--witness-policy",
            str(policy_path),
        ]
    )
    assert rc == cli.EXIT_USAGE_ERROR
    assert "--witness-policy" in capsys.readouterr().err


def test_a_well_formed_witness_policy_alone_changes_nothing(tmp_path: Path, capsys: CapSys) -> None:
    """The packaged default is the canonical EMPTY policy: installing it
    authorizes no witness at all, so `witnessed` stays unreachable until a
    release pins real operators."""
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    trust_dir = _trust_dir(tmp_path, manifest_path)
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    policy_path = tmp_path / "empty-witness-policy.json"
    policy_path.write_text(_CANONICAL_EMPTY_WITNESS_POLICY, encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(trust_dir)])
    baseline = json.loads(capsys.readouterr().out)

    capsys.readouterr()
    rc_with_policy = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--witness-policy",
            str(policy_path),
        ]
    )
    assert (rc_with_policy, json.loads(capsys.readouterr().out)) == (rc, baseline)
