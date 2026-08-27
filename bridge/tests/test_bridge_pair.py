"""The shared §14.1/§14.2 pair builder, extracted so every bridge surface
that hands a receipt to a buyer builds the SAME two files.

Before this module existed the mechanism lived inside `delivery.py` and only
the email path could reach it; the download routes and the itch dry-run each
served a bare salt-bearing envelope under the shareable `.attest` name. These
tests pin the mechanism itself, independently of any one caller.
"""

from __future__ import annotations

import io
import json
import stat
import zipfile
from pathlib import Path
from typing import Any

import pytest
from attest_bridge import pair as pair_mod
from attest_bridge.pair import BundlePair, build_pair
from conftest import ISSUER, LEGAL_TEXT, LEGAL_TEXT_SHA256

from attest import bundle

_SALT = "not-a-real-secret-but-treat-it-like-one"
_RECEIPT_ID = "01HZX0000000000000000000AA"
_SLUG = "merchant-example-com"
_ISSUER_MANIFEST: dict[str, Any] = {"issuer": ISSUER, "manifest_version": 1, "keys": []}

_ENVELOPE: dict[str, Any] = {
    "payload": {
        "receipt_id": _RECEIPT_ID,
        "issuer": {"id": ISSUER, "display_name": "Example Games Store"},
        "work": {"title": "Stardrift Chronicles"},
        "license": {"legal_text_sha256": LEGAL_TEXT_SHA256},
    },
    "delivery": {"salt": _SALT, "issuer_manifest": _ISSUER_MANIFEST},
    "signatures": {"ed25519": "deadbeef"},
}

_LEGAL_TEXTS: dict[str, bytes] = {LEGAL_TEXT_SHA256: LEGAL_TEXT}


def _envelope(**overrides: Any) -> dict[str, Any]:
    copy = json.loads(json.dumps(_ENVELOPE))
    copy.update(overrides)
    return copy


def test_build_pair_returns_the_named_shareable_and_private_halves() -> None:
    result = build_pair(_envelope(), _RECEIPT_ID, _LEGAL_TEXTS)

    assert isinstance(result, BundlePair)
    assert result.name == f"{_SLUG}-{_RECEIPT_ID}"

    with zipfile.ZipFile(io.BytesIO(result.shareable)) as shareable:
        assert set(shareable.namelist()) == {
            f"receipts/{_RECEIPT_ID}.attest.json",
            f"manifests/{ISSUER}.json",
            f"legal/{LEGAL_TEXT_SHA256}.txt",
            "README.html",
        }
        receipt = json.loads(shareable.read(f"receipts/{_RECEIPT_ID}.attest.json"))
        assert "salt" not in receipt.get("delivery", {})
        assert receipt["delivery"]["issuer_manifest"] == _ISSUER_MANIFEST

    with zipfile.ZipFile(io.BytesIO(result.private)) as private:
        assert private.namelist() == ["salts.json"]
        assert json.loads(private.read("salts.json")) == {_RECEIPT_ID: _SALT}


def test_shareable_half_carries_no_salt_in_any_decompressed_member() -> None:
    """A scan of the zip container's bytes would prove nothing: members are
    DEFLATE-compressed, so a salt inside one would not appear in the raw
    bytes. Every member is opened and decompressed."""
    result = build_pair(_envelope(), _RECEIPT_ID, _LEGAL_TEXTS)

    with zipfile.ZipFile(io.BytesIO(result.shareable)) as zf:
        members = zf.namelist()
        assert members
        for member in members:
            assert _SALT.encode() not in zf.read(member)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda e: e.__setitem__("payload", "not-an-object"), "no payload object"),
        (lambda e: e["delivery"].pop("issuer_manifest"), "no embedded manifest"),
        (lambda e: e["payload"]["issuer"].__setitem__("id", "..."), "empty slug"),
        (lambda e: e["payload"].pop("issuer"), "no issuer id"),
    ],
)
def test_precondition_misses_raise_bundle_error(mutate: Any, reason: str) -> None:
    envelope = _envelope()
    mutate(envelope)
    with pytest.raises(bundle.BundleError):
        build_pair(envelope, _RECEIPT_ID, _LEGAL_TEXTS)


@pytest.mark.parametrize("bad_id", ["../../evil", "a/b", "", "x" * 65, "we!rd"])
def test_unsafe_receipt_id_never_reaches_a_filename(bad_id: str) -> None:
    envelope = _envelope()
    envelope["payload"]["receipt_id"] = bad_id
    with pytest.raises(bundle.BundleError):
        build_pair(envelope, bad_id, _LEGAL_TEXTS)


def test_receipt_id_argument_must_match_the_envelope_payload() -> None:
    with pytest.raises(bundle.BundleError):
        build_pair(_envelope(), "01HZX0000000000000000000ZZ", _LEGAL_TEXTS)


def test_missing_legal_text_raises_bundle_error() -> None:
    with pytest.raises(bundle.BundleError):
        build_pair(_envelope(), _RECEIPT_ID, {})


def test_workdir_is_owner_only_while_it_lives_and_removed_afterwards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seam moved here with the mechanism: the pair exists as files only
    inside a 0700 directory that is gone on every exit path, success or not."""
    seen: list[tuple[Path, int]] = []
    real_factory = pair_mod._TMPDIR_FACTORY

    class _RecordingTmpDir:
        def __init__(self) -> None:
            self._inner = real_factory()

        def __enter__(self) -> str:
            path = Path(self._inner.__enter__())
            seen.append((path, stat.S_IMODE(path.stat().st_mode)))
            return str(path)

        def __exit__(self, *exc_info: object) -> None:
            self._inner.__exit__(*exc_info)

    monkeypatch.setattr(pair_mod, "_TMPDIR_FACTORY", _RecordingTmpDir)

    build_pair(_envelope(), _RECEIPT_ID, _LEGAL_TEXTS)

    assert len(seen) == 1
    path, mode = seen[0]
    assert mode == 0o700
    assert not path.exists()
