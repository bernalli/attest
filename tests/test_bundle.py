"""Tests for attest.bundle — export/import bundles and the single-receipt disclose unit (design §9).

Bundles are the "store dies, receipt survives" mechanism: `export()` produces
a shareable `.attest` (no secrets) plus a `.private.attest` (salts/keys), and
`import_bundle()` reconstructs a working `verify.TrustStore` from what
travelled inside the `.attest` alone — offline, no network. `disclose()` is the
single-receipt sharing unit for the email-attachment integration path.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attest import bundle, issue, keys, manifests, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"

# TEST ONLY — fixed seed, never use in production.
KP = keys.from_seed(bytes([21]) * 32)

_LEGAL_TEXT = b"attest-test-legal-text-v1"
_MIRROR_POLICY_TEXT = b"attest-test-mirror-policy-v1"
_EOL_COMMITMENT_TEXT = b"attest-test-eol-commitment-v1"
_LEGAL_TEXT_SHA256 = hashlib.sha256(_LEGAL_TEXT).hexdigest()
_MIRROR_POLICY_SHA256 = hashlib.sha256(_MIRROR_POLICY_TEXT).hexdigest()
_EOL_COMMITMENT_SHA256 = hashlib.sha256(_EOL_COMMITMENT_TEXT).hexdigest()

SALT_A = bytes([1]) * 16
SALT_B = bytes([2]) * 16


def _key_manifest() -> dict[str, Any]:
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z")]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def _legal_texts() -> dict[str, bytes]:
    return {
        _LEGAL_TEXT_SHA256: _LEGAL_TEXT,
        _MIRROR_POLICY_SHA256: _MIRROR_POLICY_TEXT,
    }


def _envelope(
    *,
    receipt_id: str,
    salt: bytes | None = SALT_A,
    snapshot: dict[str, Any] | None = None,
    with_eol: bool = False,
) -> dict[str, Any]:
    survivability: dict[str, Any] = {"mirror_policy_sha256": _MIRROR_POLICY_SHA256}
    if with_eol:
        survivability["eol_commitment_uri"] = "https://store.example.com/attest/eol-commitment-v1"
        survivability["eol_commitment_sha256"] = _EOL_COMMITMENT_SHA256
    payload = make_payload(
        receipt_id=receipt_id,
        license={"legal_text_sha256": _LEGAL_TEXT_SHA256},
        survivability=survivability,
    )
    return issue.issue(payload, KP, KID, salt=salt, manifest_snapshot=snapshot)


# --- export -> import roundtrip -----------------------------------------------


def test_export_import_roundtrip_verifies_green(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345678")

    attest_path, private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    imported = bundle.import_bundle(attest_path, private_path)

    assert len(imported.receipts) == 1
    receipt = imported.receipts[0]
    assert receipt["payload"]["receipt_id"] == "01J1V5B4M9Z8QWERTY12345678"

    result = verify.verify(json.dumps(receipt).encode("utf-8"), imported.trust_store)
    assert result.ok is True
    assert result.trust == "unauthenticated_tofu"
    assert imported.trust_store.provenance[ISSUER] == "bundle"


def test_import_without_private_file_has_empty_salts(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345679")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    imported = bundle.import_bundle(attest_path)
    assert imported.salts == {}


def test_private_file_recovers_the_original_salt(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345680", salt=SALT_A)

    attest_path, private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    imported = bundle.import_bundle(attest_path, private_path)
    assert imported.salts["01J1V5B4M9Z8QWERTY12345680"] == SALT_A


# --- shareable .attest carries no secrets -----------------------------------------


def test_attest_contains_no_salts_json(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345681")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        assert "salts.json" not in zf.namelist()


def test_attest_receipt_has_delivery_salt_stripped(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345682")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        stored = json.loads(zf.read("receipts/01J1V5B4M9Z8QWERTY12345682.attest.json"))
    assert "salt" not in stored.get("delivery", {})


def test_attest_receipt_drops_delivery_entirely_when_only_salt_was_present(tmp_path: Path) -> None:
    """A receipt whose only `delivery` member was `salt` must lose the whole
    `delivery` object once stripped — an empty `delivery: {}` is not the same
    shape as "no delivery member" and would confuse simpler consumers."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345683", salt=SALT_A, snapshot=None)
    assert list(envelope["delivery"].keys()) == ["salt"]  # sanity: nothing else in delivery

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        stored = json.loads(zf.read("receipts/01J1V5B4M9Z8QWERTY12345683.attest.json"))
    assert "delivery" not in stored


# --- preserve the deal: legal text hash checks at export time -------------------


def test_export_fails_when_legal_text_missing(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345684")
    incomplete_texts = {_MIRROR_POLICY_SHA256: _MIRROR_POLICY_TEXT}  # legal text missing

    with pytest.raises(bundle.BundleError):
        bundle.export([envelope], [_key_manifest()], [], incomplete_texts, tmp_path, "mylibrary")


def test_export_fails_when_legal_text_hash_does_not_match(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345685")
    wrong_texts = {
        _LEGAL_TEXT_SHA256: b"this is not the text that hashes to legal_text_sha256",
        _MIRROR_POLICY_SHA256: _MIRROR_POLICY_TEXT,
    }

    with pytest.raises(bundle.BundleError):
        bundle.export([envelope], [_key_manifest()], [], wrong_texts, tmp_path, "mylibrary")


def test_export_fails_when_mirror_policy_hash_does_not_match(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345686")
    wrong_texts = {
        _LEGAL_TEXT_SHA256: _LEGAL_TEXT,
        _MIRROR_POLICY_SHA256: b"this is not the mirror policy text either",
    }

    with pytest.raises(bundle.BundleError):
        bundle.export([envelope], [_key_manifest()], [], wrong_texts, tmp_path, "mylibrary")


def test_export_fails_when_eol_commitment_text_missing(tmp_path: Path) -> None:
    """§9: a non-null `survivability.eol_commitment_sha256` is a hash-bound
    term the bundle must preserve exactly like the license text and mirror
    policy — omit its bytes and export must fail closed."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY123456EA", with_eol=True)
    incomplete_texts = {
        _LEGAL_TEXT_SHA256: _LEGAL_TEXT,
        _MIRROR_POLICY_SHA256: _MIRROR_POLICY_TEXT,
        # eol commitment text deliberately missing
    }

    with pytest.raises(bundle.BundleError):
        bundle.export([envelope], [_key_manifest()], [], incomplete_texts, tmp_path, "mylibrary")


def test_export_fails_when_eol_commitment_hash_does_not_match(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY123456EB", with_eol=True)
    wrong_texts = {
        _LEGAL_TEXT_SHA256: _LEGAL_TEXT,
        _MIRROR_POLICY_SHA256: _MIRROR_POLICY_TEXT,
        _EOL_COMMITMENT_SHA256: b"this is not the eol commitment text",
    }

    with pytest.raises(bundle.BundleError):
        bundle.export([envelope], [_key_manifest()], [], wrong_texts, tmp_path, "mylibrary")


def test_export_succeeds_and_writes_eol_commitment_text(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY123456EC", with_eol=True)
    texts = {
        _LEGAL_TEXT_SHA256: _LEGAL_TEXT,
        _MIRROR_POLICY_SHA256: _MIRROR_POLICY_TEXT,
        _EOL_COMMITMENT_SHA256: _EOL_COMMITMENT_TEXT,
    }

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], texts, tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        assert zf.read(f"legal/{_EOL_COMMITMENT_SHA256}.txt") == _EOL_COMMITMENT_TEXT


def test_export_succeeds_and_writes_legal_texts_keyed_by_hash(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345687")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        assert zf.read(f"legal/{_LEGAL_TEXT_SHA256}.txt") == _LEGAL_TEXT
        assert zf.read(f"legal/{_MIRROR_POLICY_SHA256}.txt") == _MIRROR_POLICY_TEXT


# --- README.html ------------------------------------------------------------


def test_readme_present_and_warns_about_private_file(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345688")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        readme = zf.read("README.html").decode("utf-8")

    assert "mylibrary.private.attest" in readme
    assert "never" in readme.lower()


def test_readme_states_proofs_are_corroboration_not_authenticity(tmp_path: Path) -> None:
    """Stage 2 (design doc "Honest scope"): a proofs/ entry is corroborating
    evidence a receipt was logged/anchored, never a substitute for the
    receipt's own signature verification."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345689")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        readme = zf.read("README.html").decode("utf-8")

    assert "corroboration" in readme.lower()
    assert "proofs/" in readme


def test_readme_answers_a_buyer_before_it_explains_cryptography(tmp_path: Path) -> None:
    """The README's real reader is the buyer who opens the zip, not a
    cryptographer: it must open in plain language and only explain jargon
    like Ed25519/unauthenticated_tofu in a closing technical section, after
    the buyer-facing "what is this"/"how do I verify it" and the
    never-share warning."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY1234568K")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        readme = zf.read("README.html").decode("utf-8")

    assert "This file is a purchase receipt." in readme
    assert "If the store that sold you this is gone" in readme

    assert readme.index("Never share mylibrary.private.attest") < readme.index("Ed25519")
    assert readme.index("unauthenticated_tofu") > readme.index(
        "If the store that sold you this is gone"
    )


# --- proofs/ (Stage 2: transparency-log evidence travels with the bundle) ---


_EVIDENCE_A = {
    "entry": {"type": "receipt", "issuer": ISSUER, "core_sha256": "a" * 64},
    "leaf_index": 0,
    "tree_size": 1,
    "inclusion_proof": [],
    "checkpoint": "example.test/log/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n"
    "— k AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n",
}


def test_export_import_roundtrip_carries_proofs(tmp_path: Path) -> None:
    receipt_id = "01J1V5B4M9Z8QWERTY1234568F"
    envelope = _envelope(receipt_id=receipt_id)

    attest_path, _private_path = bundle.export(
        [envelope],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "mylibrary",
        proofs={receipt_id: _EVIDENCE_A},
    )

    with zipfile.ZipFile(attest_path) as zf:
        assert json.loads(zf.read(f"proofs/{receipt_id}.json")) == _EVIDENCE_A

    imported = bundle.import_bundle(attest_path)
    assert imported.proofs == {receipt_id: _EVIDENCE_A}


def test_export_drops_proof_for_a_receipt_not_in_the_bundle(tmp_path: Path) -> None:
    """A `proofs` entry keyed by a receipt_id that isn't actually being
    exported must never be written — it would be orphaned evidence for a
    receipt the recipient doesn't have."""
    receipt_id = "01J1V5B4M9Z8QWERTY1234568G"
    envelope = _envelope(receipt_id=receipt_id)

    attest_path, _private_path = bundle.export(
        [envelope],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "mylibrary",
        proofs={"some-other-receipt-id": _EVIDENCE_A},
    )

    with zipfile.ZipFile(attest_path) as zf:
        assert not any(name.startswith("proofs/") for name in zf.namelist())

    imported = bundle.import_bundle(attest_path)
    assert imported.proofs == {}


def test_import_defaults_proofs_to_empty_dict_when_bundle_has_none(tmp_path: Path) -> None:
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY1234568H")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    imported = bundle.import_bundle(attest_path)
    assert imported.proofs == {}


@pytest.mark.parametrize(
    "member_name",
    ["proofs//tmp/x.json", "proofs/../../../victim.json"],
)
def test_import_rejects_proof_member_paths_that_are_not_exact_ulid_basenames(
    tmp_path: Path, member_name: str
) -> None:
    """Proof member names later become output filenames, so imports accept
    only the schema's exact ULID basename shape before exposing them."""
    hostile = _make_raw_zip(tmp_path, {member_name: b"{}"}, "hostile-proofs.attest")

    with pytest.raises(bundle.BundleError, match="invalid proof member path"):
        bundle.import_bundle(hostile)


# --- disclose: the single-receipt sharing unit ----------------------------------


def test_disclose_output_contains_exactly_one_salt(tmp_path: Path) -> None:
    receipt_a = "01J1V5B4M9Z8QWERTY1234568A"
    receipt_b = "01J1V5B4M9Z8QWERTY1234568B"
    envelope_a = _envelope(receipt_id=receipt_a, salt=SALT_A)
    envelope_b = _envelope(receipt_id=receipt_b, salt=SALT_B)
    salts = {receipt_a: SALT_A, receipt_b: SALT_B}

    out_path = bundle.disclose(
        [envelope_a, envelope_b], [_key_manifest()], salts, receipt_a, tmp_path
    )

    disclosed = json.loads(out_path.read_text(encoding="utf-8"))
    assert disclosed["payload"]["receipt_id"] == receipt_a
    assert disclosed["delivery"]["salt"] == keys.b64u(SALT_A)
    # Never the whole map — only this receipt's own salt travels.
    assert disclosed["delivery"]["salt"] != keys.b64u(SALT_B)


def test_disclose_output_is_written_0600(tmp_path: Path) -> None:
    """The disclose output always embeds `delivery.salt` — a buyer-binding
    bearer secret — so it must be owner-only (0600), never the default
    world-readable 0644, matching the CLI's secret-file discipline."""
    receipt_id = "01J1V5B4M9Z8QWERTY1234568F"
    envelope = _envelope(receipt_id=receipt_id, salt=SALT_A)

    out_path = bundle.disclose(
        [envelope], [_key_manifest()], {receipt_id: SALT_A}, receipt_id, tmp_path
    )

    assert oct(os.stat(out_path).st_mode)[-3:] == "600"


def test_disclose_output_is_self_contained_and_verifies(tmp_path: Path) -> None:
    receipt_id = "01J1V5B4M9Z8QWERTY1234568C"
    envelope = _envelope(receipt_id=receipt_id, salt=SALT_A)
    salts = {receipt_id: SALT_A}

    out_path = bundle.disclose([envelope], [_key_manifest()], salts, receipt_id, tmp_path)

    disclosed_bytes = out_path.read_bytes()
    disclosed = json.loads(disclosed_bytes)
    manifest_snapshot = disclosed["delivery"]["issuer_manifest"]

    trust_store = verify.TrustStore(
        manifests={ISSUER: manifest_snapshot}, provenance={ISSUER: "bundle"}
    )
    result = verify.verify(disclosed_bytes, trust_store)
    assert result.ok is True
    assert result.trust == "unauthenticated_tofu"


# --- manifests/<issuer>.json grouping convention -------------------------------


def test_import_groups_artifact_manifests_by_series_and_picks_latest_key_manifest(
    tmp_path: Path,
) -> None:
    series = "store.example.com/works/EXG-001"
    artifact = {
        "role": "installer",
        "platform": "windows-x86_64",
        "filename": "example-game-1.1-setup.exe",
        "size_bytes": 1,
        "sha256": hashlib.sha256(b"attest-test-artifact-manifest-v1").hexdigest(),
    }
    artifact_manifest_v1 = manifests.build_artifact_manifest(
        ISSUER, series, 1, "2026-01-01T00:00:00Z", [artifact], KP, KID
    )
    artifact_manifest_v2 = manifests.build_artifact_manifest(
        ISSUER, series, 2, "2026-02-01T00:00:00Z", [artifact], KP, KID
    )
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY1234568E")

    attest_path, _private_path = bundle.export(
        [envelope],
        [_key_manifest()],
        [artifact_manifest_v2, artifact_manifest_v1],  # deliberately out of order
        _legal_texts(),
        tmp_path,
        "mylibrary",
    )

    imported = bundle.import_bundle(attest_path)

    assert [m["version"] for m in imported.artifact_manifests[series]] == [1, 2]
    # A single key-manifest version: it is both the "current" manifest and,
    # trivially, the whole (length-1) rotation chain.
    assert imported.trust_store.manifests[ISSUER]["manifest_version"] == 1
    assert [m["manifest_version"] for m in imported.trust_store.chains[ISSUER]] == [1]


def test_disclose_unknown_receipt_id_raises_bundle_error(tmp_path: Path) -> None:
    receipt_id = "01J1V5B4M9Z8QWERTY1234568D"
    envelope = _envelope(receipt_id=receipt_id, salt=SALT_A)

    with pytest.raises(bundle.BundleError):
        bundle.disclose(
            [envelope], [_key_manifest()], {receipt_id: SALT_A}, "nonexistent", tmp_path
        )


def test_disclose_raises_when_no_key_manifest_matches_signing_kid(tmp_path: Path) -> None:
    """§9: a disclosure must be self-contained ("one receipt + its manifests +
    its salt"). With no key manifest listing the receipt's signing kid, the
    emitted file could never verify standalone — `disclose()` must fail closed
    rather than return a success path to a non-verifiable file."""
    receipt_id = "01J1V5B4M9Z8QWERTY1234568E"
    envelope = _envelope(receipt_id=receipt_id, salt=SALT_A)

    with pytest.raises(bundle.BundleError):
        # No manifests at all -> nothing lists the signing kid.
        bundle.disclose([envelope], [], {receipt_id: SALT_A}, receipt_id, tmp_path)


def test_disclose_refuses_a_symlinked_out_path(tmp_path: Path) -> None:
    """`disclose()` is a library entry point, not only the CLI's callee: the
    symlink refusal has to live here too. `Path.is_dir()` follows links, so
    without the guard an `out` symlinked at a directory someone else controls
    would route the write to `<their dir>/<receipt_id>.attest.json` — a fresh
    leaf that no final-file check can catch — handing them `delivery.salt`."""
    receipt_id = "01J1V5B4M9Z8QWERTY1234568G"
    envelope = _envelope(receipt_id=receipt_id, salt=SALT_A)
    attacker_dir = tmp_path / "attacker-controlled"
    attacker_dir.mkdir()
    out = tmp_path / "share"
    out.symlink_to(attacker_dir, target_is_directory=True)

    with pytest.raises(bundle.BundleError, match="is a symlink"):
        bundle.disclose([envelope], [_key_manifest()], {receipt_id: SALT_A}, receipt_id, out)

    assert list(attacker_dir.iterdir()) == []


# --- import: decompression size-cap (zip-bomb hardening) ----------------------


def _make_raw_zip(tmp_path: Path, members: dict[str, bytes], name: str) -> Path:
    """Build a raw .attest-shaped zip with arbitrary members, bypassing export()
    — used to craft hostile bundles export() would never produce."""
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member_name, data in members.items():
            zf.writestr(member_name, data)
    return path


def test_import_rejects_member_over_per_member_cap(tmp_path: Path) -> None:
    """A single member that decompresses past max_member_bytes is refused.
    This verifies the per-member cap is enforced from bytes actually
    streamed out of the member, independent of the entry's declared
    `file_size` header — `zipfile.writestr` always writes a truthful header,
    so this test cannot construct a genuinely forged low-lying one; that
    case is out of scope here because stdlib `zipfile`'s writer has no way
    to emit it."""
    bomb = _make_raw_zip(
        tmp_path, {"receipts/bomb.attest.json": b"\0" * (2 * 1024 * 1024)}, "bomb.attest"
    )
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(bomb, max_member_bytes=1024, max_total_bytes=10 * 1024 * 1024)


def test_import_rejects_honestly_declared_oversize_via_early_gate(tmp_path: Path) -> None:
    """Members whose DECLARED uncompressed total exceeds the aggregate cap are
    rejected by the zero-cost early gate before any decompression."""
    z = _make_raw_zip(
        tmp_path,
        {
            "receipts/a.attest.json": b"\0" * (1024 * 1024),
            "receipts/b.attest.json": b"\0" * (1024 * 1024),
        },
        "aggregate.attest",
    )
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(z, max_member_bytes=10 * 1024 * 1024, max_total_bytes=1024)


def test_import_rejects_too_many_entries(tmp_path: Path) -> None:
    """A central directory with more entries than max_entries is refused
    before anything is read."""
    many = {f"receipts/{i:04d}.attest.json": b"{}" for i in range(50)}
    z = _make_raw_zip(tmp_path, many, "manyentries.attest")
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(z, max_entries=10)


def test_import_caps_private_salts_json(tmp_path: Path) -> None:
    """The .private.attest salts.json read is capped too — a valid .attest paired
    with a bomb private file is refused."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345691")
    attest_path, _private = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )
    evil_private = _make_raw_zip(
        tmp_path, {"salts.json": b"\0" * (2 * 1024 * 1024)}, "evil.private.attest"
    )
    with pytest.raises(bundle.BundleError):
        # 256 KiB cap: comfortably above every legit .attest member, far below the
        # 2 MiB salts bomb, so the failure is the salts file, not the .attest.
        bundle.import_bundle(attest_path, evil_private, max_member_bytes=256 * 1024)


def test_import_happy_path_unaffected_by_default_caps(tmp_path: Path) -> None:
    """Regression: a normal exported bundle imports fine under default caps —
    the caps are invisible to legitimate bundles."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345690")
    attest_path, private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )
    imported = bundle.import_bundle(attest_path, private_path)
    assert len(imported.receipts) == 1
