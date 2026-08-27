"""Adversarial properties for the v0.1 §14.1 unique-member requirement."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attest import bundle, issue, keys, manifests
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
KP = keys.from_seed(bytes([21]) * 32)
LEGAL_TEXT = b"attest-test-legal-text-v1"
MIRROR_POLICY_TEXT = b"attest-test-mirror-policy-v1"
LEGAL_TEXT_SHA256 = hashlib.sha256(LEGAL_TEXT).hexdigest()
MIRROR_POLICY_SHA256 = hashlib.sha256(MIRROR_POLICY_TEXT).hexdigest()
RECEIPT_A = "01HZX0000000000000000000AA"
RECEIPT_B = "01HZX0000000000000000000AB"


def key_manifest() -> dict[str, Any]:
    """Create the one key manifest needed by otherwise valid test bundles."""
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z")]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def legal_texts() -> dict[str, bytes]:
    """Return the legal texts referenced by the signed receipts."""
    return {
        LEGAL_TEXT_SHA256: LEGAL_TEXT,
        MIRROR_POLICY_SHA256: MIRROR_POLICY_TEXT,
    }


def envelope(receipt_id: str, salt: bytes) -> dict[str, Any]:
    """Issue a valid envelope whose bytes vary with the supplied delivery salt."""
    payload = make_payload(
        receipt_id=receipt_id,
        license={"legal_text_sha256": LEGAL_TEXT_SHA256},
        survivability={"mirror_policy_sha256": MIRROR_POLICY_SHA256},
    )
    return issue.issue(payload, KP, KID, salt=salt)


def envelope_with_receipt_id(receipt_id: str, salt: bytes) -> dict[str, Any]:
    """Return an envelope whose supplied identifier reaches export's member-naming boundary."""
    result = envelope(RECEIPT_A, salt)
    payload = result["payload"]
    assert isinstance(payload, dict)
    payload["receipt_id"] = receipt_id
    return result


def export_bundle(
    tmp_path: Path,
    name: str,
    receipts: list[dict[str, Any]],
    *,
    proofs: dict[str, dict[str, Any]] | None = None,
) -> tuple[Path, Path]:
    """Export a valid bundle fixture through the public exporter surface."""
    out_dir = tmp_path / name
    out_dir.mkdir()
    return bundle.export(
        receipts,
        [key_manifest()],
        [],
        legal_texts(),
        out_dir,
        "receipts",
        proofs=proofs,
    )


def copy_with_duplicate_member(
    source: Path,
    target: Path,
    member_name: str,
    duplicate_bytes: bytes | None = None,
) -> Path:
    """Copy an archive while appending a second central-directory record for one name."""
    with (
        zipfile.ZipFile(source) as source_zip,
        zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as target_zip,
    ):
        for member in source_zip.infolist():
            target_zip.writestr(member.filename, source_zip.read(member))
        original = source_zip.read(member_name)
        target_zip.writestr(member_name, original if duplicate_bytes is None else duplicate_bytes)
    return target


def member_named(source: Path, prefix: str) -> str:
    """Locate a member from an exported fixture without assuming issuer filenames."""
    with zipfile.ZipFile(source) as archive:
        return next(
            member.filename for member in archive.infolist() if member.filename.startswith(prefix)
        )


@pytest.mark.parametrize("copies", [2, 3])
def test_export_refuses_every_multiplicity_of_one_receipt_id_without_partial_files(
    tmp_path: Path, copies: int
) -> None:
    """A shared receipt_id must fail before either the public or private archive is created."""
    out_dir = tmp_path / f"duplicate-{copies}"
    out_dir.mkdir()
    receipts = [envelope(RECEIPT_A, bytes([ordinal]) * 16) for ordinal in range(1, copies + 1)]

    assert receipts[0] != receipts[-1]
    with pytest.raises(bundle.BundleError):
        bundle.export(receipts, [key_manifest()], [], legal_texts(), out_dir, "receipts")

    assert list(out_dir.iterdir()) == []


@pytest.mark.parametrize("broken", ["missing", "scalar"])
def test_export_refuses_receipts_without_an_object_payload(tmp_path: Path, broken: str) -> None:
    """A receipt that cannot supply an object payload cannot safely name a bundle member."""
    receipt = envelope(RECEIPT_A, bytes([1]) * 16)
    if broken == "missing":
        del receipt["payload"]
    else:
        receipt["payload"] = "not-an-object"
    out_dir = tmp_path / broken
    out_dir.mkdir()

    with pytest.raises(bundle.BundleError):
        bundle.export([receipt], [key_manifest()], [], legal_texts(), out_dir, "receipts")

    assert list(out_dir.iterdir()) == []


@pytest.mark.parametrize(
    ("first_id", "second_id"),
    [
        (RECEIPT_A, RECEIPT_A.lower()),
        ("r\u00e9ceipt", "re\u0301ceipt"),
    ],
)
def test_export_refuses_receipt_ids_that_are_not_ulids(
    tmp_path: Path, first_id: str, second_id: str
) -> None:
    """Case- and NFC/NFD-equivalent identifiers cannot safely create distinct members.

    This test asserted exactly this from the specification alone, and it was
    right where the first implementation was not: the amendment's equality test
    on `receipt_id` is not enough on its own, because the id is used as a path
    component on import. Export now refuses any id that is not the uppercase
    ULID the schema pins, which is what makes a case- or normalization-variant
    pair impossible to produce in the first place.
    """
    out_dir = tmp_path / "normalized-collision"
    out_dir.mkdir()
    receipts = [
        envelope_with_receipt_id(first_id, bytes([1]) * 16),
        envelope_with_receipt_id(second_id, bytes([2]) * 16),
    ]

    with pytest.raises(bundle.BundleError, match="invalid receipt_id"):
        bundle.export(receipts, [key_manifest()], [], legal_texts(), out_dir, "receipts")

    assert list(out_dir.iterdir()) == []


def test_import_rejects_duplicate_receipt_members_with_different_physical_content(
    tmp_path: Path,
) -> None:
    """Two receipt entries with one name must not be resolved to either physical entry."""
    public_path, private_path = export_bundle(
        tmp_path, "public-source", [envelope(RECEIPT_A, bytes([1]) * 16)]
    )
    receipt_member = member_named(public_path, "receipts/")
    with zipfile.ZipFile(public_path) as archive:
        different_bytes = archive.read(receipt_member) + b"\n"
    duplicate_path = copy_with_duplicate_member(
        public_path, tmp_path / "duplicate-receipt.attest", receipt_member, different_bytes
    )

    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(duplicate_path)
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(duplicate_path, private_path)


@pytest.mark.parametrize("family", ["manifests/", "proofs/"])
def test_import_rejects_duplicate_names_in_nonreceipt_public_member_families(
    tmp_path: Path, family: str
) -> None:
    """The uniqueness rule applies to manifests and proofs, not only receipt filenames."""
    proof = {"kind": "corroboration", "value": "untrusted"}
    public_path, _ = export_bundle(
        tmp_path,
        f"{family[0]}-source",
        [envelope(RECEIPT_A, bytes([1]) * 16)],
        proofs={RECEIPT_A: proof},
    )
    member = member_named(public_path, family)
    duplicate_path = copy_with_duplicate_member(
        public_path, tmp_path / f"duplicate-{family[0]}.attest", member
    )

    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(duplicate_path)


def test_import_rejects_duplicate_salts_in_the_private_archive(
    tmp_path: Path,
) -> None:
    """A private archive rejects repeated salts even when the public archive is sound."""
    public_path, private_path = export_bundle(
        tmp_path, "private-source", [envelope(RECEIPT_A, bytes([1]) * 16)]
    )
    salts_member = member_named(private_path, "salts")
    duplicate_private = copy_with_duplicate_member(
        private_path, tmp_path / "duplicate.private.attest", salts_member
    )

    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(public_path, duplicate_private)


def test_import_valid_unique_members_and_reports_the_distinct_receipt_count(tmp_path: Path) -> None:
    """A bundle with two distinct receipt members remains importable and reports two receipts."""
    public_path, private_path = export_bundle(
        tmp_path,
        "unique-source",
        [envelope(RECEIPT_A, bytes([1]) * 16), envelope(RECEIPT_B, bytes([2]) * 16)],
    )

    public_import = bundle.import_bundle(public_path)
    private_import = bundle.import_bundle(public_path, private_path)

    assert len(public_import.receipts) == 2
    assert len(private_import.receipts) == 2
