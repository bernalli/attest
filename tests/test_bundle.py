"""Tests for attest.bundle — export/import bundles and the single-receipt disclose unit (design §9).

Bundles are the "store dies, receipt survives" mechanism: `export()` produces
a shareable `.attest` (no secrets) plus a `.private.attest` (salts/keys), and
`import_bundle()` reconstructs a working `verify.TrustStore` from what
travelled inside the `.attest` alone — offline, no network. `disclose()` is the
single-receipt sharing unit for the email-attachment integration path.
"""

from __future__ import annotations

import errno
import hashlib
import html
import inspect
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import warnings as warnings_module
import zipfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from attest import bundle, buyer_surface, canon, container, issue, keys, manifests, verify
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


def test_readme_names_the_two_files_export_actually_wrote(tmp_path: Path) -> None:
    """The warning tells a buyer which file never to send and which one to send
    instead, by name — and both names must be the names of the files beside
    the README, not names the renderer believes export uses.

    Held to the paths `export` RETURNS rather than to a string built here: if
    the file naming in `export` moves and the warning's wording does not, a
    buyer is told to send a file that does not exist, and a test that checked
    the sentence against itself would stay green.
    """
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345689")

    attest_path, private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )
    with zipfile.ZipFile(attest_path) as zf:
        readme = zf.read("README.html").decode("utf-8")

    block = re.search(r'<div class="warning">(.*?)</div>', readme, re.S)
    assert block is not None
    headline = re.search(r"<h2>(.*?)</h2>", block.group(1), re.S)
    assert headline is not None
    paragraphs = re.findall(r"<p>(.*?)</p>", block.group(1), re.S)

    def files_named(text: str) -> list[str]:
        tokens = (token.lstrip("(").rstrip(".,:;)") for token in html.unescape(text).split())
        return [t for t in tokens if t.endswith(".attest") and not t.startswith(".")]

    assert files_named(headline.group(1)) == [private_path.name]
    assert files_named(paragraphs[-1]) == [attest_path.name]
    # And the one it says to send is a file that exists, and is not the secret.
    assert (tmp_path / files_named(paragraphs[-1])[0]).is_file()
    assert files_named(paragraphs[-1]) != [private_path.name]


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

    assert "This file is your receipt." in readme
    assert "If the store that sold you this is gone" in readme

    # The ordering property is what matters here, not the wording: the warning
    # must precede the cryptography. The warning text itself is now rendered
    # from buyer_surface, so locate it the same way every surface does.
    warning_heading = "Never send mylibrary.private.attest to anyone"
    assert warning_heading in readme
    assert readme.index(warning_heading) < readme.index("Ed25519")
    assert readme.index("unauthenticated_tofu") > readme.index(
        "If the store that sold you this is gone"
    )


def test_readme_is_self_contained_and_carries_its_own_styling(tmp_path: Path) -> None:
    """A bundle README is opened from a zip on someone else's disk, possibly
    years from now with no network at all. It must therefore reference nothing
    external — no stylesheet, no script, no font, no image — and carry whatever
    presentation it needs inline."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY1234568M")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        readme = zf.read("README.html").decode("utf-8")

    assert "<style>" in readme
    for external in ("<link", "<script", "@font-face", "http://", "https://", "url("):
        assert external not in readme, f"README reaches outside itself: {external}"

    # Both display situations a held page will actually meet.
    assert "prefers-color-scheme" in readme
    assert "@media print" in readme


def test_readme_stays_under_the_held_page_byte_ceiling(tmp_path: Path) -> None:
    """The README is injected into every exported bundle, so every byte here is
    paid again on every copy of every receipt. The ceiling is asserted rather
    than assumed: a budget nobody measures is a budget that gets exceeded."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY1234568N")

    attest_path, _private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )

    with zipfile.ZipFile(attest_path) as zf:
        readme_bytes = zf.read("README.html")

    assert len(readme_bytes) <= buyer_surface.MAX_HELD_PAGE_BYTES, (
        f"README.html is {len(readme_bytes)} bytes, over the "
        f"{buyer_surface.MAX_HELD_PAGE_BYTES}-byte ceiling for a held page. "
        "Shorten it, or decide deliberately to raise the ceiling."
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


def _minimal_receipt_members() -> dict[str, bytes]:
    receipt_id = "01HZX0000000000000000000AA"
    return {
        f"receipts/{receipt_id}.attest.json": canon.canonical_bytes(
            {"payload": {"receipt_id": receipt_id}}
        )
    }


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


def test_import_defaults_match_the_section_14_4_floor(tmp_path: Path) -> None:
    """The reference importer adopts the interoperable container floor."""
    members = {
        **_minimal_receipt_members(),
        **{f"unused/{index:05d}.bin": b"" for index in range(10_000)},
    }
    over_floor = _make_raw_zip(tmp_path, members, "over-floor.attest")

    with pytest.raises(bundle.BundleError, match="over 10000 entries"):
        bundle.import_bundle(over_floor)

    assert bundle._MAX_ENTRIES == 10_000
    assert bundle._MAX_MEMBER_BYTES == 64 * 1024 * 1024
    assert bundle._MAX_TOTAL_BYTES == 256 * 1024 * 1024
    assert bundle._MAX_CONTAINER_BYTES == 1024 * 1024 * 1024

    # The equalities above prove only that the module DECLARES the floor. They
    # say nothing about whether `import_bundle`'s own defaults are still wired
    # to those constants, and a default is resolved once, when the function is
    # defined: a signature that hardcoded a matching literal instead of naming
    # the constant would leave every assertion above green while the wiring
    # rotted underneath it. Only the entry count is reachable behaviourally
    # here — the other three bounds would each cost hundreds of megabytes to
    # cross — so the remaining three are tied to the signature instead of being
    # asserted twice against the same literal.
    defaults = inspect.signature(bundle.import_bundle).parameters
    assert defaults["max_entries"].default == bundle._MAX_ENTRIES
    assert defaults["max_member_bytes"].default == bundle._MAX_MEMBER_BYTES
    assert defaults["max_total_bytes"].default == bundle._MAX_TOTAL_BYTES
    assert defaults["max_container_bytes"].default == bundle._MAX_CONTAINER_BYTES


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


def test_the_snapshot_of_a_container_is_bounded(tmp_path: Path) -> None:
    """The snapshot is a copy, so it is bounded before it is written: an
    unbounded copy of an attacker-sized file is a new denial of service in
    place of the old one. The refusal names the size of the FILE, which is what
    the bound measures — see the test below for why borrowing another cap's
    sentence here was false."""
    oversized = tmp_path / "oversized.attest"
    oversized.write_bytes(b"x" * 65)

    with pytest.raises(bundle.BundleError, match="limit this importer will copy"):
        with bundle._open_container(oversized, bundle._SnapshotBudget(64)):
            pass  # pragma: no cover — the bound refuses before the body runs


def test_the_snapshot_bound_is_applied_to_each_container(
    tmp_path: Path,
) -> None:
    """Each container may independently reach the stored-size floor."""
    receipt_id = "01HZX0000000000000000000AA"
    public = _make_raw_zip(tmp_path, _minimal_receipt_members(), "snapshot-budget.attest")
    private = _make_raw_zip(
        tmp_path,
        {"salts.json": canon.canonical_bytes({receipt_id: keys.b64u(SALT_A)})},
        "snapshot-budget.private.attest",
    )
    limit = max(public.stat().st_size, private.stat().st_size)
    assert public.stat().st_size + private.stat().st_size > limit

    imported = bundle.import_bundle(public, private, max_container_bytes=limit)
    assert imported.salts[receipt_id] == SALT_A


def test_import_shares_the_aggregate_budget_with_the_private_sibling(
    tmp_path: Path,
) -> None:
    """One import, one aggregate cap, spent by both halves of a hostile pair.

    The receipt is padded with compressible content so the pair's stored bytes
    remain below the aggregate number while its inflated bytes cross that
    number. The stored-size ceiling is separate; this test measures only the
    decompression budget shared across both containers.
    """
    receipt_id = "01HZX0000000000000000000AA"
    receipt = canon.canonical_bytes({"payload": {"receipt_id": receipt_id, "note": "a" * 20_000}})
    salts = canon.canonical_bytes({receipt_id: keys.b64u(SALT_A)})
    limit = max(len(receipt), len(salts))
    assert len(receipt) + len(salts) > limit

    public = _make_raw_zip(
        tmp_path,
        {f"receipts/{receipt_id}.attest.json": receipt},
        "shared-budget.attest",
    )
    private = _make_raw_zip(
        tmp_path,
        {"salts.json": salts},
        "shared-budget.private.attest",
    )
    assert public.stat().st_size + private.stat().st_size < limit, (
        "stored bytes must stay below the number used for the aggregate cap"
    )

    with pytest.raises(bundle.BundleError, match="aggregate cap"):
        bundle.import_bundle(
            public,
            private,
            max_member_bytes=limit,
            max_total_bytes=limit,
        )


def test_import_happy_path_unaffected_by_default_caps(tmp_path: Path) -> None:
    """Regression: a normal exported bundle imports fine under default caps —
    the caps are invisible to legitimate bundles."""
    envelope = _envelope(receipt_id="01J1V5B4M9Z8QWERTY12345690")
    attest_path, private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )
    imported = bundle.import_bundle(attest_path, private_path)
    assert len(imported.receipts) == 1


def _deep_chain(levels: int) -> Any:
    nested: Any = "leaf"
    for _ in range(levels):
        nested = {"n": nested}
    return nested


# `disclose` is the SECOND reference emitter of a receipt envelope: it assembles
# a new object one level around the payload, plus `delivery`. A ceiling that
# lived only in `issue.issue` would leave this door open.


def test_disclose_refuses_a_disclosure_past_the_nesting_ceiling(tmp_path: Path) -> None:
    receipt_id = "01J1V5B4M9Z8QWERTY1234568G"
    envelope = _envelope(receipt_id=receipt_id, salt=SALT_A)
    # Hand-deepened: issuance can no longer emit this, but a hostile or legacy
    # envelope can still reach `disclose`.
    envelope["payload"]["_depth_probe"] = _deep_chain(canon.MAX_DEPTH - 1)

    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        bundle.disclose([envelope], [_key_manifest()], {receipt_id: SALT_A}, receipt_id, tmp_path)


def test_disclose_emits_only_what_the_strict_parser_accepts(tmp_path: Path) -> None:
    receipt_id = "01J1V5B4M9Z8QWERTY1234568H"
    envelope = _envelope(receipt_id=receipt_id, salt=SALT_A)
    envelope["payload"]["_depth_probe"] = _deep_chain(canon.MAX_DEPTH - 4)

    out_path = bundle.disclose(
        [envelope], [_key_manifest()], {receipt_id: SALT_A}, receipt_id, tmp_path
    )

    assert canon.loads_strict(out_path.read_bytes())


# --- V-L.2: member names are unique (v0.1 §14.1, 2026-08-26) ----------------


def test_export_refuses_duplicate_receipt_ids(tmp_path: Path) -> None:
    """Two receipts sharing one id would collide on `receipts/<id>.attest.json`."""
    dup_id = "01HZX0000000000000000000AA"
    envelopes = [_envelope(receipt_id=dup_id), _envelope(receipt_id=dup_id, salt=SALT_B)]

    with pytest.raises(bundle.BundleError, match="duplicate receipt_id"):
        bundle.export(envelopes, [_key_manifest()], [], _legal_texts(), tmp_path, "lib")

    # No partial bundle is left behind by a refusal.
    assert not (tmp_path / "lib.attest").exists()
    assert not (tmp_path / "lib.private.attest").exists()


def test_export_refuses_three_receipts_sharing_one_id(tmp_path: Path) -> None:
    """Ambiguity is a property of the set, not of a pair."""
    dup_id = "01HZX0000000000000000000AA"
    envelopes = [
        _envelope(receipt_id=dup_id),
        _envelope(receipt_id=dup_id, salt=SALT_B),
        _envelope(receipt_id=dup_id, salt=None),
    ]

    with pytest.raises(bundle.BundleError, match="duplicate receipt_id"):
        bundle.export(envelopes, [_key_manifest()], [], _legal_texts(), tmp_path, "lib")


def test_export_still_accepts_distinct_receipt_ids(tmp_path: Path) -> None:
    """Negative control: ids differing by one character are not duplicates."""
    envelopes = [
        _envelope(receipt_id="01HZX0000000000000000000AA"),
        _envelope(receipt_id="01HZX0000000000000000000AB", salt=SALT_B),
    ]

    attest_path, _ = bundle.export(
        envelopes, [_key_manifest()], [], _legal_texts(), tmp_path, "lib"
    )

    assert len(bundle.import_bundle(attest_path).receipts) == 2


def _duplicate_member(source: Path, target: Path, member: str, payload: bytes) -> None:
    """Copy `source` to `target`, appending a second entry under `member`.

    `zipfile` emits a `UserWarning: Duplicate name` here — that warning is the
    very symptom the export guard turns into a refusal, and it is expected in
    a fixture that builds the hostile archive on purpose.
    """
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(target, "w") as dst:
        for info in src.infolist():
            dst.writestr(info.filename, src.read(info.filename))
        with warnings_module.catch_warnings():
            warnings_module.simplefilter("ignore")
            dst.writestr(member, payload)


def test_import_rejects_duplicate_receipt_member_name(tmp_path: Path) -> None:
    """Name-based reads resolve every duplicate to one entry; import must refuse."""
    receipt_id = "01HZX0000000000000000000AA"
    ok_path, _ = bundle.export(
        [_envelope(receipt_id=receipt_id)], [_key_manifest()], [], _legal_texts(), tmp_path, "ok"
    )
    hostile = tmp_path / "dup.attest"
    _duplicate_member(ok_path, hostile, f"receipts/{receipt_id}.attest.json", b'{"payload": {}}')

    with pytest.raises(bundle.BundleError, match="repeats member name"):
        bundle.import_bundle(hostile)


def test_import_rejects_a_duplicate_in_any_member_family(tmp_path: Path) -> None:
    """A repeated `manifests/` name is two trust states for one issuer — same refusal."""
    ok_path, _ = bundle.export(
        [_envelope(receipt_id="01HZX0000000000000000000AA")],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "ok",
    )
    with zipfile.ZipFile(ok_path) as zf:
        manifest_member = next(n for n in zf.namelist() if n.startswith("manifests/"))
    hostile = tmp_path / "dup-manifest.attest"
    _duplicate_member(ok_path, hostile, manifest_member, b"{}")

    with pytest.raises(bundle.BundleError, match="repeats member name"):
        bundle.import_bundle(hostile)


def test_import_refuses_two_manifest_members_for_one_issuer(tmp_path: Path) -> None:
    manifest = canon.canonical_bytes(
        {"issuer": ISSUER, "key_manifests": [], "artifact_manifests": []}
    )
    hostile = _make_raw_zip(
        tmp_path,
        {
            **_minimal_receipt_members(),
            "manifests/a.json": manifest,
            "manifests/b.json": manifest,
        },
        "duplicate-issuer.attest",
    )

    with pytest.raises(bundle.BundleError, match="one issuer in more than one"):
        bundle.import_bundle(hostile)


def test_import_rejects_a_duplicate_whose_two_entries_are_byte_identical(tmp_path: Path) -> None:
    """Identical bytes are still an ambiguous central directory: refuse, never guess."""
    receipt_id = "01HZX0000000000000000000AA"
    ok_path, _ = bundle.export(
        [_envelope(receipt_id=receipt_id)], [_key_manifest()], [], _legal_texts(), tmp_path, "ok"
    )
    member = f"receipts/{receipt_id}.attest.json"
    with zipfile.ZipFile(ok_path) as zf:
        same_bytes = zf.read(member)
    hostile = tmp_path / "dup-identical.attest"
    _duplicate_member(ok_path, hostile, member, same_bytes)

    with pytest.raises(bundle.BundleError, match="repeats member name"):
        bundle.import_bundle(hostile)


def test_import_rejects_a_duplicate_in_the_private_archive(tmp_path: Path) -> None:
    """The private archive gets the same guard as the shareable one."""
    ok_path, private_path = bundle.export(
        [_envelope(receipt_id="01HZX0000000000000000000AA")],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "ok",
    )
    hostile_private = tmp_path / "dup.private.attest"
    _duplicate_member(private_path, hostile_private, "salts.json", b"{}")

    with pytest.raises(bundle.BundleError, match="repeats member name"):
        bundle.import_bundle(ok_path, hostile_private)


def test_import_refuses_a_receipt_id_that_would_escape_the_output_directory(
    tmp_path: Path,
) -> None:
    """A bundle is attacker-supplied and the CLI derives an on-disk filename
    from the payload's `receipt_id`, exactly as it does for `proofs/` members.
    A traversal component there must be refused at import, not written."""
    ok_path, _ = bundle.export(
        [_envelope(receipt_id="01HZX0000000000000000000AA")],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "ok",
    )
    member = "receipts/01HZX0000000000000000000AA.attest.json"
    # S108 is about a program USING a temp path; here it is hostile input the
    # importer must refuse, which is the opposite.
    hostile_absolute = "/tmp/escaped"  # noqa: S108
    for hostile_id in ("../../escaped", hostile_absolute, "01hzx0000000000000000000aa", ""):
        with zipfile.ZipFile(ok_path) as src:
            envelope = json.loads(src.read(member))
        envelope["payload"]["receipt_id"] = hostile_id
        hostile = tmp_path / f"hostile-{abs(hash(hostile_id))}.attest"
        with zipfile.ZipFile(ok_path) as src, zipfile.ZipFile(hostile, "w") as dst:
            for info in src.infolist():
                if info.filename == member:
                    dst.writestr(info.filename, json.dumps(envelope))
                else:
                    dst.writestr(info.filename, src.read(info.filename))

        with pytest.raises(bundle.BundleError, match="invalid receipt_id"):
            bundle.import_bundle(hostile)


def test_import_refuses_a_non_string_receipt_id(tmp_path: Path) -> None:
    """Parity with the browser importer, which has its own case for this: a
    `receipt_id` that is not a string at all never reaches the filename."""
    ok_path, _ = bundle.export(
        [_envelope(receipt_id="01HZX0000000000000000000AA")],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "ok",
    )
    member = "receipts/01HZX0000000000000000000AA.attest.json"
    for hostile_id in (7, True, None, ["01HZX0000000000000000000AA"], {}):
        with zipfile.ZipFile(ok_path) as src:
            envelope = json.loads(src.read(member))
        envelope["payload"]["receipt_id"] = hostile_id
        hostile = tmp_path / f"nonstring-{type(hostile_id).__name__}.attest"
        with zipfile.ZipFile(ok_path) as src, zipfile.ZipFile(hostile, "w") as dst:
            for info in src.infolist():
                payload = json.dumps(envelope) if info.filename == member else None
                dst.writestr(
                    info.filename,
                    payload if payload is not None else src.read(info.filename),
                )

        with pytest.raises(bundle.BundleError, match="invalid receipt_id"):
            bundle.import_bundle(hostile)


def test_import_refuses_two_members_carrying_the_same_payload_receipt_id(
    tmp_path: Path,
) -> None:
    """Distinct member names can still carry one `receipt_id`, which the
    member-name guard alone cannot see."""
    ok_path, _ = bundle.export(
        [_envelope(receipt_id="01HZX0000000000000000000AA")],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "ok",
    )
    member = "receipts/01HZX0000000000000000000AA.attest.json"
    hostile = tmp_path / "same-id-two-names.attest"
    with zipfile.ZipFile(ok_path) as src, zipfile.ZipFile(hostile, "w") as dst:
        for info in src.infolist():
            dst.writestr(info.filename, src.read(info.filename))
        dst.writestr("receipts/01HZX0000000000000000000AB.attest.json", src.read(member))

    with pytest.raises(bundle.BundleError, match="more than once"):
        bundle.import_bundle(hostile)


# --- import: the container is read canonically (v0.1 §14.1) -------------------

CONTAINER_CORPUS = Path(__file__).resolve().parents[1] / "tests" / "container-corpus"


def _corpus_bundle(tmp_path: Path, leaf: str, name: str) -> Path:
    """Copy a corpus archive under a `.attest` name, so the importer sees the
    exact bytes the shared corpus pins."""
    path = tmp_path / name
    path.write_bytes((CONTAINER_CORPUS / leaf / "archive.zip").read_bytes())
    return path


def test_import_refuses_an_archive_with_two_central_directories(tmp_path: Path) -> None:
    """The case no counter check can see: one file, two internally consistent
    directories, and two readers that each find a different receipt. Nothing
    inside either directory is a lie — the file is."""
    hostile = _corpus_bundle(tmp_path, "exhibit-D-prefix", "two-directories.attest")
    with pytest.raises(bundle.BundleError, match="canonical form"):
        bundle.import_bundle(hostile)


def test_import_refuses_an_archive_whose_entry_counters_disagree(tmp_path: Path) -> None:
    """One byte in the end record used to decide which members a verifier sees."""
    hostile = _corpus_bundle(tmp_path, "exhibit-B2-counter", "counter.attest")
    with pytest.raises(bundle.BundleError, match="counters disagree"):
        bundle.import_bundle(hostile)


def test_import_refuses_a_shareable_bundle_that_carries_private_material(
    tmp_path: Path,
) -> None:
    """A `.attest` listing `salts.json` is a `.private.attest` under the wrong
    name: it holds the buyer's binding secrets, and importing it as a shareable
    bundle is exactly the mistake the file naming exists to prevent. The browser
    verifier has always refused it; this importer now refuses it too."""
    hostile = _corpus_bundle(tmp_path, "exhibit-C-salts-honest", "with-salts.attest")
    with pytest.raises(bundle.BundleError, match=r"\.private\.attest"):
        bundle.import_bundle(hostile)


def test_import_refuses_a_shareable_bundle_that_carries_a_key(tmp_path: Path) -> None:
    """`keys/` is the other half of the same refusal."""
    hostile = tmp_path / "with-keys.attest"
    with zipfile.ZipFile(hostile, "w") as zf:
        zf.writestr("receipts/01HZX0000000000000000000AA.attest.json", b"{}")
        zf.writestr("keys/signing.json", b"{}")
    with pytest.raises(bundle.BundleError, match=r"\.private\.attest"):
        bundle.import_bundle(hostile)


def test_import_refuses_private_material_before_reading_any_member(tmp_path: Path) -> None:
    """The refusal is decided on the member LIST, so nothing beside the secrets
    is ever decompressed: the check now happens where the browser verifier's
    comment always claimed it did.

    The other member's deflate stream is deliberately corrupt. Reading members
    first would produce a complaint about that stream; refusing the list first
    produces the complaint about the secrets, which is the ordering under test.
    """
    hostile = tmp_path / "salts-and-garbage.attest"
    corrupt = (CONTAINER_CORPUS / "deflate-garbage" / "archive.zip").read_bytes()
    with zipfile.ZipFile(hostile, "w") as zf:
        zf.writestr("receipts/01HZX0000000000000000000AA.attest.json", corrupt)
        zf.writestr("salts.json", b"{}")
    with pytest.raises(bundle.BundleError, match=r"\.private\.attest"):
        bundle.import_bundle(hostile)


def test_import_refuses_a_member_only_one_decoder_would_accept(tmp_path: Path) -> None:
    """A stored deflate block whose length fields do not agree: this importer's
    decoder refuses it and the browser's never reads that field, so the verdict
    is made by shared code rather than by whichever library is running."""
    hostile = _corpus_bundle(tmp_path, "deflate-stored-block-bad-complement", "bad-deflate.attest")
    with pytest.raises(bundle.BundleError, match="not a valid deflate stream"):
        bundle.import_bundle(hostile)


def test_import_refuses_an_empty_file(tmp_path: Path) -> None:
    """An empty file cannot be memory-mapped; the verdict must still be a
    refusal about the container, not an OSError about the mapping."""
    empty = tmp_path / "empty.attest"
    empty.write_bytes(b"")
    with pytest.raises(bundle.BundleError, match="not a readable zip archive"):
        bundle.import_bundle(empty)


def test_import_refuses_a_canonical_bundle_with_zero_receipts(tmp_path: Path) -> None:
    empty_bundle = _make_raw_zip(tmp_path, {"README.html": b"<p>empty</p>"}, "zero-receipts.attest")
    with pytest.raises(bundle.BundleError, match="no receipts found"):
        bundle.import_bundle(empty_bundle)


def test_import_still_reads_the_private_sibling_for_salts(tmp_path: Path) -> None:
    """The private archive legitimately carries `salts.json`: the refusal above
    is about the SHAREABLE half, and this is the pair that must keep working."""
    receipt_id = "01J1V5B4M9Z8QWERTY12345699"
    envelope = _envelope(receipt_id=receipt_id)
    attest_path, private_path = bundle.export(
        [envelope], [_key_manifest()], [], _legal_texts(), tmp_path, "mylibrary"
    )
    imported = bundle.import_bundle(attest_path, private_path)
    assert imported.salts[receipt_id] == SALT_A


@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param(b'{"unfinished":', id="truncated"),
        pytest.param(b"\xef\xbb\xbf{}", id="bom"),
        pytest.param(b'{"float":1.5}', id="float"),
        pytest.param(b'{"duplicate":1,"duplicate":2}', id="duplicate-key"),
    ],
)
@pytest.mark.parametrize(
    "member_name",
    [
        "receipts/01HZX0000000000000000000AA.attest.json",
        "manifests/store.example.com.json",
        "proofs/01HZX0000000000000000000AA.json",
    ],
    ids=["receipt", "manifest", "proof"],
)
def test_import_normalizes_every_noncanonical_json_family(
    tmp_path: Path, member_name: str, malformed: bytes
) -> None:
    members = {} if member_name.startswith("receipts/") else _minimal_receipt_members()
    members[member_name] = malformed
    hostile = _make_raw_zip(tmp_path, members, "noncanonical-json.attest")

    with pytest.raises(bundle.BundleError, match="not valid canonical JSON"):
        bundle.import_bundle(hostile)


_JSON_TEXT = st.text(alphabet=st.characters(exclude_categories=("Cs",)), max_size=32)
_JSON_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
    _JSON_TEXT,
)
_NON_OBJECT_JSON = st.one_of(_JSON_SCALAR, st.lists(_JSON_SCALAR, max_size=4))
_NON_LIST_JSON = st.one_of(
    _JSON_SCALAR,
    st.dictionaries(_JSON_TEXT, _JSON_SCALAR, max_size=4),
)
_NON_INTEGER_JSON = st.one_of(
    st.none(),
    st.booleans(),
    _JSON_TEXT,
    st.lists(_JSON_SCALAR, max_size=4),
    st.dictionaries(_JSON_TEXT, _JSON_SCALAR, max_size=4),
)


@given(malformed=_NON_OBJECT_JSON)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_skips_every_non_object_manifest_shape(tmp_path: Path, malformed: object) -> None:
    members = _minimal_receipt_members()
    members["manifests/store.example.com.json"] = canon.canonical_bytes(malformed)
    hostile = _make_raw_zip(tmp_path, members, "manifest-top-level.attest")

    imported = bundle.import_bundle(hostile)

    assert imported.trust_store.manifests == {}
    assert imported.artifact_manifests == {}


@given(
    field_name=st.sampled_from(["key_manifests", "artifact_manifests"]),
    malformed=_NON_LIST_JSON,
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_skips_every_non_array_manifest_collection(
    tmp_path: Path, field_name: str, malformed: object
) -> None:
    members = _minimal_receipt_members()
    members["manifests/store.example.com.json"] = canon.canonical_bytes(
        {"issuer": ISSUER, field_name: malformed}
    )
    hostile = _make_raw_zip(tmp_path, members, "manifest-collection.attest")

    imported = bundle.import_bundle(hostile)

    assert imported.trust_store.manifests == {}
    assert imported.artifact_manifests == {}


@given(
    field_name=st.sampled_from(["key_manifests", "artifact_manifests"]),
    malformed=_NON_OBJECT_JSON,
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_filters_every_non_object_manifest_entry(
    tmp_path: Path, field_name: str, malformed: object
) -> None:
    members = _minimal_receipt_members()
    members["manifests/store.example.com.json"] = canon.canonical_bytes(
        {"issuer": ISSUER, field_name: [malformed]}
    )
    hostile = _make_raw_zip(tmp_path, members, "manifest-entry.attest")

    imported = bundle.import_bundle(hostile)

    assert imported.trust_store.manifests == {}
    assert imported.artifact_manifests == {}


@given(
    family=st.sampled_from(["key", "artifact"]),
    malformed_version=_NON_INTEGER_JSON,
)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_orders_every_non_integer_manifest_version_below_valid_versions(
    tmp_path: Path, family: str, malformed_version: object
) -> None:
    if family == "key":
        manifest_blob = {
            "issuer": ISSUER,
            "key_manifests": [
                {"manifest_version": 1, "marker": "valid"},
                {"manifest_version": malformed_version, "marker": "malformed"},
            ],
        }
    else:
        manifest_blob = {
            "issuer": ISSUER,
            "artifact_manifests": [
                {"series": "example", "version": 1, "marker": "valid"},
                {
                    "series": "example",
                    "version": malformed_version,
                    "marker": "malformed",
                },
            ],
        }
    members = _minimal_receipt_members()
    members["manifests/store.example.com.json"] = canon.canonical_bytes(manifest_blob)
    hostile = _make_raw_zip(tmp_path, members, "manifest-version.attest")

    imported = bundle.import_bundle(hostile)

    if family == "key":
        assert imported.trust_store.manifests[ISSUER]["marker"] == "valid"
    else:
        assert imported.artifact_manifests["example"][-1]["marker"] == "valid"


def _import_with_raw_salts(tmp_path: Path, raw_salts: bytes) -> bundle.ImportedBundle:
    public = _make_raw_zip(tmp_path, _minimal_receipt_members(), "salts-public.attest")
    private = _make_raw_zip(tmp_path, {"salts.json": raw_salts}, "salts-private.private.attest")
    return bundle.import_bundle(public, private)


def test_import_refuses_a_private_bundle_without_salts_json(tmp_path: Path) -> None:
    public = _make_raw_zip(tmp_path, _minimal_receipt_members(), "missing-salts.attest")
    private = _make_raw_zip(tmp_path, {"keys/placeholder": b""}, "missing-salts.private.attest")

    with pytest.raises(bundle.BundleError, match=r"missing salts\.json"):
        bundle.import_bundle(public, private)


@given(malformed=_NON_OBJECT_JSON)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_refuses_every_non_object_salts_shape(tmp_path: Path, malformed: object) -> None:
    with pytest.raises(bundle.BundleError, match="must be an object"):
        _import_with_raw_salts(tmp_path, canon.canonical_bytes(malformed))


@given(
    receipt_id=_JSON_TEXT.filter(
        lambda value: re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", value) is None
    )
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_refuses_every_non_ulid_salts_key(tmp_path: Path, receipt_id: str) -> None:
    raw_salts = canon.canonical_bytes({receipt_id: keys.b64u(SALT_A)})

    with pytest.raises(bundle.BundleError, match="uppercase ULID"):
        _import_with_raw_salts(tmp_path, raw_salts)


@given(
    malformed=st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
        st.lists(st.none()),
    )
)
@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_refuses_every_non_string_salt_value(tmp_path: Path, malformed: object) -> None:
    raw_salts = canon.canonical_bytes({"01HZX0000000000000000000AA": malformed})

    with pytest.raises(bundle.BundleError, match="base64url strings"):
        _import_with_raw_salts(tmp_path, raw_salts)


@given(raw_salt=st.binary(min_size=0, max_size=64).filter(lambda value: len(value) != 16))
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_refuses_every_canonically_encoded_salt_of_the_wrong_length(
    tmp_path: Path, raw_salt: bytes
) -> None:
    raw_salts = canon.canonical_bytes({"01HZX0000000000000000000AA": keys.b64u(raw_salt)})

    with pytest.raises(bundle.BundleError, match="non-16-byte salt"):
        _import_with_raw_salts(tmp_path, raw_salts)


@given(raw_salt=st.binary(min_size=16, max_size=16), padding=st.sampled_from(["=", "=="]))
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_import_refuses_every_padded_encoding_of_a_valid_salt(
    tmp_path: Path, raw_salt: bytes, padding: str
) -> None:
    raw_salts = canon.canonical_bytes({"01HZX0000000000000000000AA": keys.b64u(raw_salt) + padding})

    with pytest.raises(bundle.BundleError, match="non-canonical"):
        _import_with_raw_salts(tmp_path, raw_salts)


@pytest.mark.parametrize("encoded", ["!", "***", "é"])
def test_import_refuses_salt_text_outside_base64url(tmp_path: Path, encoded: str) -> None:
    raw_salts = canon.canonical_bytes({"01HZX0000000000000000000AA": encoded})

    with pytest.raises(bundle.BundleError, match=r"base64url|non-canonical"):
        _import_with_raw_salts(tmp_path, raw_salts)


def test_import_accepts_an_archive_with_a_gap_between_members(tmp_path: Path) -> None:
    """The canonical form does not require members to tile the archive: a gap
    between two members is not a second reading of the file, and refusing one
    would tighten the rule past what the divergence needs."""
    honest = _corpus_bundle(tmp_path, "honest-gap-between-members", "gap.attest")
    imported = bundle.import_bundle(honest)
    assert len(imported.receipts) == 1


def test_import_ignores_a_member_no_family_claims_even_when_it_is_corrupt(
    tmp_path: Path,
) -> None:
    """Members are read on demand, and an archive can carry something neither
    importer looks at. Reading every member eagerly would make such a file fatal
    on one side and invisible on the other — same bytes, two verdicts, which is
    the defect this whole change closes. The browser verifier has the twin of
    this test.
    """
    receipt_id = "01J1V5B4M9Z8QWERTY12345697"
    attest_path, _private = bundle.export(
        [_envelope(receipt_id=receipt_id)], [_key_manifest()], [], _legal_texts(), tmp_path, "lib"
    )
    marker = b"CORRUPT-ME-PLEASE-0123456789"
    hostile = tmp_path / "with-unknown.attest"
    with zipfile.ZipFile(attest_path) as src, zipfile.ZipFile(hostile, "w") as dst:
        for info in src.infolist():
            dst.writestr(info.filename, src.read(info.filename))
        dst.writestr("unknown.bin", marker)
    raw = bytearray(hostile.read_bytes())
    # Flip a byte of the member's DATA, leaving its CRC-32 record untouched: the
    # member is now unreadable, and nothing reads it.
    raw[raw.index(marker)] ^= 0xFF
    hostile.write_bytes(bytes(raw))

    imported = bundle.import_bundle(hostile)
    assert len(imported.receipts) == 1


def test_import_keeps_an_issuer_named_after_an_object_member(tmp_path: Path) -> None:
    """An issuer is a string a bundle chose, and this importer holds it as an
    ordinary key. The browser verifier's trust store is a JavaScript object, and
    an object member named `__proto__` is not a member there: it is the
    prototype. That asymmetry is a divergence of the same class as the container
    one — the same bytes, two lists of issuers — reachable without touching a
    single offset, so it is pinned on this side too."""
    attest_path, _private = bundle.export(
        [_envelope(receipt_id="01J1V5B4M9Z8QWERTY12345691")],
        [_key_manifest()],
        [],
        _legal_texts(),
        tmp_path,
        "mylibrary",
    )
    hostile = tmp_path / "proto-issuer.attest"
    blob = canon.dumps({"issuer": "__proto__", "key_manifests": [_key_manifest()]})
    with zipfile.ZipFile(attest_path) as src, zipfile.ZipFile(hostile, "w") as dst:
        for info in src.infolist():
            if info.filename.startswith("manifests/"):
                continue
            dst.writestr(info.filename, src.read(info.filename))
        dst.writestr("manifests/attacker.json", blob)

    imported = bundle.import_bundle(hostile)
    assert list(imported.trust_store.manifests) == ["__proto__"]
    # And nothing that issuer wrote reaches an issuer it did not name.
    assert imported.trust_store.manifests.get(ISSUER) is None


def test_import_refuses_every_corpus_archive_with_a_bundle_error(tmp_path: Path) -> None:
    """Whatever the shared corpus throws at the importer, the caller is told
    about the archive. An exception from the machinery underneath — the mapping,
    the decoder, the reader's own bookkeeping — reaching the caller instead
    sends whoever reads it to look in the wrong place, which is worse than a
    refusal that says nothing at all."""
    leaves = sorted(p for p in CONTAINER_CORPUS.iterdir() if p.is_dir())
    assert len(leaves) > 20
    for leaf in leaves:
        path = tmp_path / f"{leaf.name}.attest"
        path.write_bytes((leaf / "archive.zip").read_bytes())
        try:
            bundle.import_bundle(path)
        except bundle.BundleError:
            continue
        except Exception as unexpected:
            raise AssertionError(
                f"{leaf.name}: {type(unexpected).__name__} reached the caller "
                f"instead of a BundleError: {unexpected}"
            ) from unexpected


def test_a_refusal_survives_the_unmapping_of_the_container() -> None:
    """Unmapping is bookkeeping; the refusal is the answer the caller asked for.

    A memory map cannot be closed while anything still holds a view into it, and
    a view outlives its scope for as long as the traceback of the exception in
    flight does. If the close is allowed to raise there, its complaint about
    exported pointers arrives in place of the sentence explaining why the
    archive was refused — the caller is told the truth about the wrong thing.
    """
    with pytest.raises(bundle.BundleError, match="the refusal the caller asked for"):
        with bundle._open_container(Path(__file__)) as buf:
            held = memoryview(buf)  # noqa: F841 — an export alive at closing time
            raise bundle.BundleError("the refusal the caller asked for")


def test_a_concurrent_truncation_cannot_kill_the_import_process(
    tmp_path: Path,
) -> None:
    """The source is truncated by another process after its buffer is ready.

    The subprocess boundary is part of the assertion: mapping the caller's inode
    makes the access die from SIGBUS, which no in-process pytest assertion could
    observe safely. A stable snapshot either imports or raises BundleError; this
    fixture is complete before truncation, so it imports.
    """
    source = _make_raw_zip(tmp_path, _minimal_receipt_members(), "mutable.attest")
    program = """
import os
from pathlib import Path
import subprocess
import sys

from attest import bundle

source = Path(sys.argv[1])
original_members = bundle._members

def truncate_source_then_read_snapshot(buf, **kwargs):
    subprocess.run(
        [sys.executable, "-c", "import os,sys; os.truncate(sys.argv[1], 0)", str(source)],
        check=True,
    )
    return original_members(buf, **kwargs)

bundle._members = truncate_source_then_read_snapshot
imported = bundle.import_bundle(source)
print(f"IMPORTED {len(imported.receipts)}")
"""

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local fixture
        [sys.executable, "-c", program, str(source)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "IMPORTED 1"


def test_the_snapshot_bound_says_what_it_measures_and_not_what_it_does_not(
    tmp_path: Path,
) -> None:
    """An archive can cross the snapshot bound on FRAMING alone.

    The bound is on the bytes of the file; the aggregate cap is on the bytes
    members inflate to. Those are not the same quantity and they do not even
    stay close: a central directory holds a record per member and a member name
    may run to 65 535 bytes, none of which ever inflates. So an archive whose
    members inflate to a few hundred bytes — a fraction of a percent of the cap
    — can be a hundred times over the bound, and a refusal that named the
    aggregate cap there would be telling its holder to look at a quantity that
    is nowhere near its limit. It is measured here rather than argued, so the
    wording of that refusal cannot drift back.

    The bound is the cap the caller passed, so the cap is lowered for the test
    instead of putting a gigabyte on disk; the geometry is what is under test,
    and it does not depend on the scale.
    """
    cap = 64 * 1024
    hostile = tmp_path / "framing.attest"
    with zipfile.ZipFile(hostile, "w", zipfile.ZIP_STORED) as zf:
        for name, blob in _minimal_receipt_members().items():
            zf.writestr(name, blob)
        for index in range(60):
            zf.writestr(f"pad/{index:04d}{'n' * 1200}.bin", b"x")

    members = container.canonical_members(
        hostile.read_bytes(), max_entries=100_000, max_member_bytes=cap, max_total_bytes=cap
    )
    inflated = sum(member.uncompressed_size for member in members)
    assert inflated * 100 < cap, "the members must be far inside the aggregate cap"
    assert hostile.stat().st_size > cap, "and the file must be over the snapshot bound"

    with pytest.raises(bundle.BundleError) as refusal:
        bundle.import_bundle(hostile, max_container_bytes=cap)
    message = str(refusal.value)
    assert "will copy in order to read it" in message
    # The refusal must not name a quantity this archive is nowhere near.
    assert "decompression" not in message
    assert "inflated" not in message


class _FullTemporaryFile:
    """A temporary file on a filesystem with no room left for the copy.

    A full or quota-limited temporary filesystem is not something a test can
    arrange on the host it runs on, so the condition is arranged at the one
    place it is felt: the write.
    """

    def __enter__(self) -> _FullTemporaryFile:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def write(self, chunk: bytes) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    def flush(self) -> None:
        return None

    def tell(self) -> int:  # pragma: no cover — the write refuses first
        return 0


def test_a_snapshot_that_cannot_be_written_is_refused_as_a_copy_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copy that cannot be taken is a fact about this machine, not the archive.

    The importer reads a container by copying it into a private temporary file
    first, and that write can fail for reasons the archive knows nothing about:
    a temporary filesystem that is full, a quota, a size limit on the process.
    An OSError escaping from there would break the promise this module keeps
    everywhere else — whatever the input, the caller is told in this module's
    own error type — and, worse, would name an errno where a holder expects a
    verdict on their bundle. So the refusal says what actually happened, and
    says nothing about bytes it never read.
    """
    source = _make_raw_zip(tmp_path, _minimal_receipt_members(), "unwritable.attest")
    monkeypatch.setattr(bundle.tempfile, "TemporaryFile", _FullTemporaryFile)

    with pytest.raises(bundle.BundleError) as refusal:
        bundle.import_bundle(source)

    message = str(refusal.value)
    assert "could not copy the container" in message
    assert "No space left on device" in message
    # The archive was never read, so nothing in the refusal may describe it.
    assert "over the" not in message
    assert isinstance(refusal.value.__cause__, OSError)


def test_a_snapshot_that_cannot_be_created_is_refused_in_the_same_voice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The copy can fail before it starts, and it fails the same way.

    A temporary directory that is read-only, absent or out of inodes refuses at
    creation rather than at the write. It is the same fact — this importer could
    not take a copy — and a caller who gets an OSError here instead of there
    learns nothing except that the module's promise holds only sometimes.
    """
    source = _make_raw_zip(tmp_path, _minimal_receipt_members(), "uncreatable.attest")

    def _read_only(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(bundle.tempfile, "TemporaryFile", _read_only)

    with pytest.raises(bundle.BundleError) as refusal:
        bundle.import_bundle(source)

    message = str(refusal.value)
    assert "could not copy the container" in message
    assert "Read-only file system" in message
    assert isinstance(refusal.value.__cause__, OSError)


def test_the_snapshot_promises_a_bound_and_not_a_flight_from_memory() -> None:
    """The copy is bounded; it is not bounded away from memory, and saying so
    would be false on an ordinary Linux host.

    `tempfile` puts the snapshot in the platform's temporary directory, and that
    directory is routinely a tmpfs — where the file IS memory and the bound is a
    bound on RAM. A docstring promising the copy avoids an allocation of the
    attacker's choosing would tell a reader that the bound may be set as high as
    the disk is large. It may not, on such a host, and the reader deciding the
    number is exactly who must know that.
    """
    doc = bundle._open_container.__doc__ or ""
    assert "rather than to memory" not in doc
    assert "memory-backed" in doc
    # And the arrangement the docstring describes is the one that is measured:
    # nothing here chooses a directory, so the copy lands wherever tempfile does.
    assert Path(tempfile.gettempdir()).is_dir()


def test_the_snapshot_bound_honours_the_cap_its_caller_gave(tmp_path: Path) -> None:
    """An embedder who tightens `max_container_bytes` tightens the copy with it.

    A snapshot bound built from the module constant instead of from the
    argument leaves an embedder who asked for a few kilobytes copying up to a
    gigabyte, and reading the refusal for something else entirely — here, a
    verdict on a receipt inside an archive they never wanted read that far.
    """
    cap = 4096
    hostile = tmp_path / "over-the-callers-cap.attest"
    with zipfile.ZipFile(hostile, "w", zipfile.ZIP_STORED) as zf:
        for name, blob in _minimal_receipt_members().items():
            zf.writestr(name, blob)
        for index in range(40):
            zf.writestr(f"pad/{index:04d}{'n' * 1200}.bin", b"x")
    assert hostile.stat().st_size > cap
    assert hostile.stat().st_size < bundle._MAX_CONTAINER_BYTES, (
        "and comfortably inside the module default, so only the argument can refuse it"
    )

    # Under the default the archive is fine, which is what makes the refusal
    # below attributable to the argument and to nothing else about the file.
    assert len(bundle.import_bundle(hostile).receipts) == 1

    with pytest.raises(bundle.BundleError) as refusal:
        bundle.import_bundle(hostile, max_container_bytes=cap)

    # The number in the sentence is the caller's, which is how it is known the
    # caller's cap and not the module constant did the refusing.
    assert f"{cap}-byte limit this importer will copy" in str(refusal.value)


def test_a_container_path_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    """A path is not a file, and this one names what it found before reading.

    Opening a FIFO waits for a writer who need never arrive: the import stops
    there for as long as the process lives, with no exception to catch and no
    verdict to return. A character device is the same trap taken from the other
    side — it never ends either, and it would feed the copy up to the bound
    first. Neither is a fact about an archive, so the check is on what the
    handle IS, made before a byte is read and answered in this module's own
    error type.

    The alarm is the assertion that the check happens BEFORE the read: without
    it, a regression does not fail this test, it hangs it forever.
    """
    fifo = tmp_path / "pipe.attest"
    os.mkfifo(fifo)

    def _still_blocked(_signum: int, _frame: object) -> None:
        raise AssertionError("opening the container blocked: the FIFO was read, not refused")

    previous = signal.signal(signal.SIGALRM, _still_blocked)
    signal.setitimer(signal.ITIMER_REAL, 5.0)
    try:
        with pytest.raises(bundle.BundleError) as refusal:
            bundle.import_bundle(fifo)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous)

    message = str(refusal.value)
    assert "a named pipe, not a regular file" in message
    # It says what was found, never what the bytes held: none were read.
    assert "receipt" not in message


@pytest.mark.skipif(not Path("/proc/self/mem").exists(), reason="needs Linux procfs")
def test_a_container_that_cannot_be_read_is_refused_as_a_read_failure() -> None:
    """A regular file can still refuse to be read, and that is not a verdict.

    `/proc/self/mem` passes every check a container path can be given — it is a
    regular file, it is not over any bound — and its first read returns EIO. It
    stands here for the failing disk and the network mount that went away: the
    copy cannot be taken, nothing has been parsed, and an OSError leaving the
    module would name the wrong culprit as surely as one from the write does.
    """
    with pytest.raises(bundle.BundleError) as refusal:
        bundle.import_bundle(Path("/proc/self/mem"))

    message = str(refusal.value)
    assert "could not read the container in order to copy it" in message
    assert "Input/output error" in message
    assert isinstance(refusal.value.__cause__, OSError)


def test_a_copy_that_cannot_be_mapped_is_refused_as_a_mapping_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last move of the copy can fail too, and on the tightest hosts it will.

    The snapshot is inside its bound and written; mapping it still asks this
    machine for address space it may not have. The refusal is this module's,
    because a caller handed an ENOMEM has no way to tell it from a verdict on
    the archive — and the archive, at that point, has still not been read.
    """
    source = _make_raw_zip(tmp_path, _minimal_receipt_members(), "unmappable.attest")

    def _no_room(*args: object, **kwargs: object) -> None:
        raise OSError(errno.ENOMEM, "Cannot allocate memory")

    monkeypatch.setattr(bundle.mmap, "mmap", _no_room)

    with pytest.raises(bundle.BundleError) as refusal:
        bundle.import_bundle(source)

    message = str(refusal.value)
    assert "could not map the copy" in message
    assert "Cannot allocate memory" in message
    assert isinstance(refusal.value.__cause__, OSError)


def test_a_refusal_to_read_is_a_different_outcome_from_a_refusal_of_the_bytes(
    tmp_path: Path,
) -> None:
    """v0.1 §14.4: declining to read is not a verdict about the container.

    The two have opposite remedies — a container refused for its size may be
    readable on a machine with more room, one refused for its shape never will
    be — so a caller that cannot tell them apart either retries what can never
    succeed or gives up on what would. Reporting an unread container as corrupt
    says something about bytes nobody looked at.
    """
    corpus = CONTAINER_CORPUS

    # Refused for its shape: the reader looked and found the file could be
    # addressed two ways. Never a resource refusal, however much budget it gets.
    malformed = tmp_path / "two-directories.attest"
    malformed.write_bytes((corpus / "exhibit-D-prefix" / "archive.zip").read_bytes())
    with pytest.raises(bundle.BundleError) as shape:
        bundle.import_bundle(malformed)
    assert not isinstance(shape.value, bundle.BundleTooLargeError)

    # Refused for its size, by each of the two bounds that can say so: the
    # reader's own caps, and the copy this importer takes before reading.
    over_caps = _make_raw_zip(
        tmp_path,
        {**_minimal_receipt_members(), "extra.bin": b"x"},
        "too-many.attest",
    )
    with pytest.raises(bundle.BundleTooLargeError):
        bundle.import_bundle(over_caps, max_entries=1)

    oversized = tmp_path / "oversized.attest"
    oversized.write_bytes(b"x" * 65)
    with pytest.raises(bundle.BundleTooLargeError):
        bundle.import_bundle(oversized, max_container_bytes=64)

    # And a caller who does not care about the distinction is unaffected.
    assert issubclass(bundle.BundleTooLargeError, bundle.BundleError)


def test_a_container_over_the_bound_is_refused_without_being_copied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The metadata already settles it, so the copy never starts.

    Without this, a file over the bound costs a full `max_bytes` of temporary
    storage — memory, where that directory is a tmpfs — to reach a refusal its
    own size had already decided. The loop stays the authority for a file that
    grows after this point; this only spares the copy for one that is over the
    bound before it begins.

    Asserted by making the copy impossible: if a temporary file is opened at
    all, the test fails rather than passing for the wrong reason.
    """
    oversized = tmp_path / "oversized.attest"
    oversized.write_bytes(b"x" * 4096)

    def no_copies(*args: object, **kwargs: object) -> object:
        raise AssertionError("the snapshot was started for a file already over the bound")

    monkeypatch.setattr(bundle.tempfile, "TemporaryFile", no_copies)
    with pytest.raises(bundle.BundleTooLargeError, match="will copy in order to read it"):
        bundle.import_bundle(oversized, max_container_bytes=1024)
