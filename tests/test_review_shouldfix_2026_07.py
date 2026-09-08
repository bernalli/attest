"""Regression tests for the 2026-07-13 review SHOULD-FIX batch (test-first).

(#20 entry-count preflight is intentionally deferred — the 100k-entry cap
already bounds it post-open.)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from attest import bundle, canon, cli, issue, keys, manifests, verify
from tests.helpers import key_manifest, make_payload, store

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"

KP = keys.from_seed(bytes([9]) * 32)
KP_ATTACKER = keys.from_seed(bytes([11]) * 32)


def _key_manifest(status: str = "active", valid_to: str | None = None) -> dict[str, Any]:
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", valid_to, status)]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def _trust_store(manifest: dict[str, Any], chains: Any = None) -> verify.TrustStore:
    return store({ISSUER: manifest}, {ISSUER: "tls"}, chains if chains is not None else {})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _export_bundle(tmp_path: Path) -> tuple[Path, Path]:
    env = issue.issue(make_payload(), KP, KID, salt=bytes(16))
    legal = {
        hashlib.sha256(b"attest-test-legal-text-v1").hexdigest(): b"attest-test-legal-text-v1",
        hashlib.sha256(
            b"attest-test-mirror-policy-v1"
        ).hexdigest(): b"attest-test-mirror-policy-v1",
    }
    return bundle.export([env], [_key_manifest()], [], legal, tmp_path, "b")


def _rewrite_zip(
    src: Path,
    dst: Path,
    transform: Callable[[str, bytes], tuple[str, bytes]] | None = None,
    drop: Callable[[str], bool] | None = None,
) -> None:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            if drop is not None and drop(name):
                continue
            data = zin.read(name)
            if transform is not None:
                name, data = transform(name, data)
            zout.writestr(name, data)


# --- #11: find_key must tolerate a malformed keys[] member ---


def test_find_key_tolerates_non_dict_entries() -> None:
    # `None`/`"x"` as `keys[]` members do not survive json.dumps + strict
    # parsing as a document a caller could hand the library (R3): this
    # exercises the corpus body, so it goes through the private twin.
    manifest = {"keys": [None, "x", {"kid": KID, "pub": "p"}]}
    assert manifests._find_key(manifest, KID) == {"kid": KID, "pub": "p"}
    assert manifests._find_key({"keys": [None]}, KID) is None


# --- #12: continuity must also honour the signer key's validity window ---


def test_continuity_rejects_candidate_outside_signer_validity_window() -> None:
    trusted = manifests.build_key_manifest(
        ISSUER,
        1,
        "2026-01-01T00:00:00Z",
        [
            manifests.key_entry(
                KID, KP.pub, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "active"
            )
        ],
        KP,
        KID,
    )
    # candidate issued AFTER the signer key's valid_to
    candidate = manifests.build_key_manifest(
        ISSUER,
        2,
        "2026-07-01T00:00:00Z",
        [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")],
        KP,
        KID,
    )
    assert manifests.check_continuity(key_manifest(trusted), key_manifest(candidate)) is False


# --- #8: continuity chain must lead to the manifest actually used ---


def test_verify_downgrades_trust_when_chain_tail_is_not_the_used_manifest() -> None:
    used = _key_manifest()
    unrelated = manifests.build_key_manifest(
        ISSUER,
        5,
        "2026-01-01T00:00:00Z",
        [manifests.key_entry(KID, KP_ATTACKER.pub, "2026-01-01T00:00:00Z", None, "active")],
        KP_ATTACKER,
        KID,
    )
    envelope = issue.issue(make_payload(), KP, KID)
    ts = _trust_store(used, chains={ISSUER: [unrelated]})
    result = verify.verify(_to_bytes(envelope), ts)
    assert result.signature == "valid"
    assert result.trust == "unverified_rotation"


# --- #9: bundle JSON must be parsed with the strict canonical parser ---


def test_import_rejects_duplicate_key_in_bundle_manifest(tmp_path: Path) -> None:
    attest_path, _ = _export_bundle(tmp_path)
    tampered = tmp_path / "tampered.attest"

    def _dupe(name: str, data: bytes) -> tuple[str, bytes]:
        if name.startswith("manifests/"):
            return name, b'{"issuer":"store.example.com","issuer":"evil","key_manifests":[]}'
        return name, data

    _rewrite_zip(attest_path, tampered, transform=_dupe)
    with pytest.raises((canon.CanonError, bundle.BundleError)):
        bundle.import_bundle(tampered)


# --- #10: import must enforce that every referenced legal text is present ---


def test_import_rejects_missing_referenced_legal_text(tmp_path: Path) -> None:
    attest_path, _ = _export_bundle(tmp_path)
    stripped = tmp_path / "stripped.attest"
    _rewrite_zip(attest_path, stripped, drop=lambda name: name.startswith("legal/"))
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(stripped)


# --- #15: issuance must reject a salt that is not exactly 16 bytes ---


def test_issue_rejects_wrong_length_salt() -> None:
    with pytest.raises(ValueError):
        issue.issue(make_payload(), KP, KID, salt=bytes(8))


# --- #16: issuance must reject a structurally malformed kid ---


def test_issue_rejects_malformed_kid() -> None:
    with pytest.raises(ValueError):
        issue.issue(make_payload(), KP, ISSUER)  # missing /keys/<label>#<name>


def test_issue_accepts_well_formed_kid() -> None:
    env = issue.issue(make_payload(), KP, KID)
    assert env["signatures"][0]["kid"] == KID


# --- #14: bundle-controlled names must not escape the output directory ---


def test_safe_name_neutralizes_separators_and_traversal() -> None:
    for hostile in ("../../etc", "..\\..\\x", "C:\\Windows", "a/b\\c"):
        safe = cli._safe_name(hostile)
        assert "/" not in safe
        assert "\\" not in safe
        assert ":" not in safe
        assert ".." not in safe


# --- #17: a half-supplied challenge disclosure must be rejected, not ignored ---


def test_build_disclosure_rejects_incomplete_challenge(tmp_path: Path) -> None:
    nonce = tmp_path / "nonce"
    nonce.write_text(keys.b64u(bytes(16)), encoding="utf-8")
    args = argparse.Namespace(
        disclose_salt=None,
        disclose_challenge_nonce=nonce,
        disclose_challenge_sig=None,
        disclose_identifier=None,
        disclose_type=None,
    )
    with pytest.raises(cli.CliUsageError):
        cli._build_disclosure(args)


# --- #18: colliding output paths must be rejected before any write ---


def test_keygen_rejects_colliding_output_paths(tmp_path: Path) -> None:
    same = tmp_path / "same"
    rc = cli.main(["keygen", "--seed-out", str(same), "--pub-out", str(same)])
    assert rc == cli.EXIT_USAGE_ERROR


# --- #13: check-artifact must signal that it does not authenticate ---


def test_check_artifact_marks_result_unauthenticated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = b"an-artifact"
    digest = hashlib.sha256(data).hexdigest()
    receipt = {
        "payload": {
            "work": {
                "artifacts": [
                    {
                        "role": "installer",
                        "platform": "x",
                        "filename": "f",
                        "size_bytes": len(data),
                        "sha256": digest,
                    }
                ]
            }
        }
    }
    receipt_path = tmp_path / "r.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    file_path = tmp_path / "artifact.bin"
    file_path.write_bytes(data)
    rc = cli.main(["check-artifact", str(file_path), "--receipt", str(receipt_path)])
    assert rc == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["match"] is True
    assert out["authenticated"] is False


# --- #19: accessing .private material must emit an explicit warning ---


def test_import_warns_on_private_material(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    attest_path, private_path = _export_bundle(tmp_path)
    rc = cli.main(
        [
            "import",
            "--bundle",
            str(attest_path),
            "--private",
            str(private_path),
            "--out-dir",
            str(tmp_path / "out"),
        ]
    )
    assert rc == cli.EXIT_OK
    assert "private" in capsys.readouterr().err.lower()
