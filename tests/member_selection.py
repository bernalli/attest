"""Fixtures for v0.1 section 14.1's reserved-root admission contract.

Names are generated from the specification, never from importer predicates.
Signed manifest history comes from the shared conformance corpus.
"""

from __future__ import annotations

import json
import zipfile
from itertools import product
from pathlib import Path
from typing import Any

from attest import issue, keys

VECTORS = Path(__file__).resolve().parents[1] / "docs/spec/vectors"
ISSUER = "store.example.com"
RID = "01JZ5PDHT0000G40R40M30E209"
NEW_RID = "01JZ5PDHT0000G40R40M30E20A"
LEGAL = b"attest-vectors-legal-text-v1"
DIGEST = "a9e875fe29704222a432410b0c160f5a2e5ef48effa8b51a5017c640e21c109c"
RECEIPT = f"receipts/{RID}.attest.json"
MANIFEST = f"manifests/{ISSUER}.json"
PROOF = f"proofs/{RID}.json"
LEGAL_NAME = f"legal/{DIGEST}.txt"
FORMS = {
    "receipts": (RID, ".attest.json", "receipts/*.attest.json"),
    "manifests": (ISSUER, ".json", "manifests/<issuer>.json"),
    "legal": (DIGEST, ".txt", "legal/<sha256>.txt"),
    "proofs": (RID, ".json", "proofs/<ULID>.json"),
}
AXES = ("prefix-case", "suffix-case", "absent", "appended", "combined")
# v0.1 rev 20: enumerate path prefixes and root separators from the spec,
# then combine each with every ASCII root case, independently of the guard.
SEPARATOR_FORMS = (
    ("", "\\"),
    ("/", "/"),
    ("./", "/"),
    ("/", "\\"),
    ("./", "\\"),
    ("\\", "/"),
    (".\\", "/"),
    ("\\", "\\"),
    (".\\", "\\"),
    ("/./", "/"),
    ("./\\./.\\", "\\"),
)
SUCCESSOR_NAMES = (
    f"MANIFESTS/{ISSUER}.JSON",
    f"manifests\\{ISSUER}.json",
    f"Manifests\\{ISSUER}.json",
    f"/manifests/{ISSUER}.json",
    f"./manifests/{ISSUER}.json",
)


def ascii_cases(text: str) -> list[str]:
    return [
        "".join(chars)
        for chars in product(*((c, c.upper()) if "a" <= c <= "z" else (c,) for c in text))
    ]


def invalid_names(family: str, axis: str) -> list[str]:
    stem, suffix, _ = FORMS[family]
    prefixes = ascii_cases(family)[1:]
    suffixes = ascii_cases(suffix)[1:]
    if axis == "prefix-case":
        return [f"{root}/{stem}{suffix}" for root in prefixes]
    if axis == "suffix-case":
        return [f"{family}/{stem}{ending}" for ending in suffixes]
    if axis == "absent":
        return [f"{family}/{stem}"]
    if axis == "appended":
        return [f"{family}/{stem}{suffix}.bak"]
    assert axis == "combined"
    # Every noncanonical prefix with absent/appended/uppercase suffix;
    # every noncanonical suffix with uppercase prefix and with .bak.
    # This covers each spelling, not the full Cartesian product of both axes.
    return sorted(
        {
            f"{root}/{stem}{ending}"
            for root in prefixes
            for ending in ("", suffix + ".bak", suffix.upper())
        }
        | {f"{family.upper()}/{stem}{ending}" for ending in suffixes}
        | {f"{family}/{stem}{ending}.bak" for ending in suffixes}
    )


def document(leaf: str, name: str) -> Any:
    return json.loads((VECTORS / leaf / name).read_bytes())


def manifest_history() -> tuple[dict[str, Any], dict[str, Any]]:
    old = document("41-compromise-cutoff/u-stale-pin-not-a-retraction", "manifests.json")
    successor = document("41-compromise-cutoff/a-rescued-anchored-before-cutoff", "manifests.json")
    return old["manifests"][ISSUER], successor["manifests"][ISSUER]


def wrapper(*versions: dict[str, Any]) -> bytes:
    return json.dumps(
        {"issuer": ISSUER, "key_manifests": versions, "artifact_manifests": []}
    ).encode()


def signed_receipt(
    rid: str = RID, legal_field: tuple[str, str] | None = None, digest: str = DIGEST
) -> bytes:
    payload = document("01-valid-minimal", "envelope.json")["payload"]
    payload["receipt_id"] = rid
    if legal_field is not None:
        section, field = legal_field
        payload[section][field] = digest
        if field == "eol_commitment_sha256":
            payload[section]["eol_commitment_uri"] = "https://store.example.com/eol"
    # Fixed corpus seed, test only. Re-sign changes so schema/signature are
    # independent controls, rather than invalid fixtures hiding selection loss.
    kp = keys.from_seed(bytes([1]) * 32)
    envelope = issue.issue(payload, kp, f"{ISSUER}/keys/2025-01#ed25519-1")
    return json.dumps(envelope).encode()


def members(*, two_receipts: bool = False) -> dict[str, bytes]:
    old, _ = manifest_history()
    result = {
        RECEIPT: signed_receipt(),
        MANIFEST: wrapper(old),
        LEGAL_NAME: LEGAL,
        "README.html": b"<p>Shareable receipt bundle; keep the private bundle private.</p>",
    }
    if two_receipts:
        result[f"receipts/{NEW_RID}.attest.json"] = signed_receipt(NEW_RID)
    return result


def archive(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as output:
        for name, data in entries.items():
            output.writestr(name, data)
    with zipfile.ZipFile(path) as check:
        assert check.namelist() == list(entries)
        assert check.testzip() is None
    return path


def renamed(entries: dict[str, bytes], source: str, target: str) -> dict[str, bytes]:
    assert target not in entries
    return {target if name == source else name: data for name, data in entries.items()}
