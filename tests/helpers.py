"""Shared test payload builder for attest receipt payload tests."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from attest.keys import b64u
from attest.trust_material import KeyManifest, TrustStore

# Fixed 32 zero-bytes commitment/pubkey material — deterministic, test-only.
_COMMITMENT = b64u(bytes(32))

_LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-legal-text-v1").hexdigest()
_MIRROR_POLICY_SHA256 = hashlib.sha256(b"attest-test-mirror-policy-v1").hexdigest()
_ARTIFACT_SHA256 = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()


def _base_payload() -> dict[str, Any]:
    """The reference example payload (see docs/spec/attest-v0.1.md)."""
    return {
        "attest_version": "0.1",
        "receipt_id": "01J1V5B4M9Z8QWERTY12345678",
        "issued_at": "2026-07-02T14:30:00Z",
        "supersedes": None,
        "issuer": {
            "id": "store.example.com",
            "display_name": "Example Games Store",
        },
        "buyer": {
            "commitment": _COMMITMENT,
            "identifier_type": "issuer-account",
            "pubkey": None,
        },
        "work": {
            "title": "Example Game",
            "publisher": "Example Publisher srl",
            "edition": "Deluxe",
            "identifiers": {"issuer_sku": "EXG-001"},
            "artifact_series": "store.example.com/works/EXG-001",
            "artifacts": [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "example-game-1.0-setup.exe",
                    "size_bytes": 734003200,
                    "sha256": _ARTIFACT_SHA256,
                }
            ],
        },
        "license": {
            "grant": "perpetual",
            "revocability": "none",
            "transferable": False,
            "drm": "drm-free",
            "terms_uri": "https://store.example.com/attest/license-templates/standard-v1",
            "legal_text_sha256": _LEGAL_TEXT_SHA256,
            "jurisdiction_flags": {"eu_usedsoft_asserted": False},
        },
        "survivability": {
            "redownload_right": True,
            "mirror_policy_uri": "https://store.example.com/attest/mirror-policy-v1",
            "mirror_policy_sha256": _MIRROR_POLICY_SHA256,
            "end_of_life": "artifacts-remain-redownloadable",
            "eol_commitment_uri": None,
            "eol_commitment_sha256": None,
        },
    }


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def make_payload(**overrides: Any) -> dict[str, Any]:
    """Return the §3.1 example payload as a dict, deep-merged with `overrides`.

    Nested dict overrides (e.g. `license={"revocability": "policy"}`) merge into
    the corresponding base dict instead of replacing it wholesale; non-dict
    values (including lists) replace the base value outright.
    """
    return _deep_merge(_base_payload(), overrides)


# ---------------------------------------------------------------------------
# Trust material, built the way a caller builds it: as a serialized document.
#
# The three helpers below exist so that no test has to spell out the store
# document grammar (section 5.3) by hand, and so that the bytes a test feeds the
# library are produced by an ORACLE INDEPENDENT of the library: `json.dumps`
# from the standard library, never `canon.canonical_bytes` (D11). A fixture
# serialized by the same canonicalizer the parser reads back could agree with
# it for a reason neither side would reveal.
# ---------------------------------------------------------------------------


def store_bytes(
    manifests: dict[str, Any],
    provenance: dict[str, Any] | None = None,
    chains: dict[str, Any] | None = None,
    artifact_manifests: dict[str, Any] | None = None,
    artifact_manifest_chains: dict[str, Any] | None = None,
) -> bytes:
    """Serialize a trust store document (section 5.3) with the standard library.

    `None` and `{}` are DIFFERENT, and the difference is the whole point of
    D17: a member passed `None` is left ABSENT from the document, a member
    passed `{}` is PRESENT and empty. `to_bytes()` has to give absence back
    unchanged, so a helper that quietly wrote `"chains": {}` for an absent
    member would make the property untestable from here.

    `provenance` is the one asymmetry, and it is deliberate: the grammar
    REQUIRES it, so `None` cannot mean absent. It means "derive the obvious
    one" -- `tls` for every issuer in `manifests` -- which is what almost every
    test wants. A test that needs provenance absent has to say so by building
    the document itself; a test that needs it empty passes `{}`.
    """
    document: dict[str, Any] = {"manifests": manifests}
    document["provenance"] = (
        {issuer: "tls" for issuer in manifests} if provenance is None else provenance
    )
    for name, value in (
        ("chains", chains),
        ("artifact_manifests", artifact_manifests),
        ("artifact_manifest_chains", artifact_manifest_chains),
    ):
        if value is not None:
            document[name] = value
    return json.dumps(document).encode()


def store(
    manifests: dict[str, Any],
    provenance: dict[str, Any] | None = None,
    chains: dict[str, Any] | None = None,
    artifact_manifests: dict[str, Any] | None = None,
    artifact_manifest_chains: dict[str, Any] | None = None,
) -> TrustStore:
    """The snapshot a caller gets after handing the library those bytes."""
    return TrustStore.from_bytes(
        store_bytes(
            manifests,
            provenance,
            chains,
            artifact_manifests,
            artifact_manifest_chains,
        )
    )


def key_manifest(manifest: dict[str, Any]) -> KeyManifest:
    """The snapshot a caller gets after handing the library one manifest."""
    return KeyManifest.from_bytes(json.dumps(manifest).encode())
