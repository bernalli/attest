"""The committed web-verifier sample bundle must be regenerable and genuine.

Loads tools/gen_site_sample.py by file path (tools/ is not a package) and
checks that a fresh generation produces a bundle that imports, verifies ok
at TOFU trust, proves its binding with the sidecar salt, and never leaks a
.private.attest into the output directory.

The second half of the file asks the same questions of the file actually
published — `site/public/sample/demo.attest`. A fresh generation says nothing
about the committed bytes: the sample is the artifact a first-time visitor
drops into the web verifier, so if it stops verifying, the demo lies. Until
these tests existed, only the TypeScript suite ever opened the committed
bundle, and only for its transparency evidence.
"""

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from attest import bundle, keys, verify

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "site" / "public" / "sample"
SAMPLE_BUNDLE = SAMPLE_DIR / "demo.attest"
SAMPLE_BINDING = SAMPLE_DIR / "demo-binding.json"


def _load_generator() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "tools" / "gen_site_sample.py"
    spec = importlib.util.spec_from_file_location("gen_site_sample", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_produces_verifiable_sample(tmp_path: Path) -> None:
    gen = _load_generator()
    report = gen.main(tmp_path)

    attest_path = Path(report["attest"])
    binding_path = Path(report["binding"])
    assert attest_path.name == "demo.attest" and attest_path.is_file()
    assert binding_path.name == "demo-binding.json" and binding_path.is_file()

    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    assert binding["identifier_type"] == "email"
    assert len(binding["salt_b64u"]) == 22  # 16 raw bytes, base64url unpadded

    check = report["self_check"]
    assert check["verify"]["ok"] is True
    assert check["verify"]["trust"] == "unauthenticated_tofu"
    assert check["verify_with_disclosure"]["binding"] == "proven"

    # The secrets file must never land in the published output directory.
    assert not list(tmp_path.glob("*.private.attest"))


def test_refresh_readme_rewrites_only_that_member(tmp_path: Path) -> None:
    """`--refresh-readme` exists so the committed sample can follow a wording
    change without minting a key or growing the public log. That is only safe
    if it touches nothing else: every other member — the signed receipt, the
    manifest, the legal text, any proof — must come out byte-identical, and
    the README must be exactly what a fresh export of the same name renders.
    """
    gen = _load_generator()
    attest_path = Path(gen.main(tmp_path)["attest"])

    # Age the committed README by hand, the way a rewording ages it.
    with zipfile.ZipFile(attest_path) as zf:
        before = {info.filename: zf.read(info) for info in zf.infolist()}
    stale = dict(before)
    stale["README.html"] = b"<!doctype html><p>an older README</p>"
    with zipfile.ZipFile(attest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member, data in stale.items():
            zf.writestr(member, data)

    assert gen.refresh_readme(attest_path) is True

    with zipfile.ZipFile(attest_path) as zf:
        after = {info.filename: zf.read(info) for info in zf.infolist()}
    assert list(after) == list(before)
    assert after["README.html"].decode("utf-8") == bundle._render_readme("demo")
    for member in before:
        if member != "README.html":
            assert after[member] == before[member], member
    # Already current: a second run is a no-op, and says so.
    assert gen.refresh_readme(attest_path) is False


def test_refresh_readme_refuses_anything_but_a_shareable_bundle(tmp_path: Path) -> None:
    gen = _load_generator()
    for name in ("demo.private.attest", "demo.zip", "demo"):
        path = tmp_path / name
        path.write_bytes(b"")
        with pytest.raises(RuntimeError):
            gen.refresh_readme(path)


# --- the bundle actually published, not a fresh one --------------------------


def _committed_receipt() -> tuple[bundle.ImportedBundle, dict[str, object]]:
    imported = bundle.import_bundle(SAMPLE_BUNDLE)
    assert len(imported.receipts) == 1, "the sample is meant to hold one receipt"
    return imported, imported.receipts[0]


def test_committed_sample_bundle_still_verifies() -> None:
    """The signature over the published receipt still checks out against the
    trust material published beside it, and the whole envelope still satisfies
    the schema. A README refresh, a re-zip, a stray editor save: any of those
    can leave a bundle that opens and no longer verifies."""
    imported, receipt = _committed_receipt()
    result = verify.verify(json.dumps(receipt).encode("utf-8"), imported.trust_store)
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.ok is True
    # Offline-imported manifests are TOFU by construction (design §5); a sample
    # that ever reported "verified" would be advertising trust it cannot have.
    assert result.trust == "unauthenticated_tofu"


def test_committed_sample_binding_sidecar_proves_the_buyer_commitment() -> None:
    """`demo-binding.json` is published so a visitor can reproduce the buyer
    binding, which is the step that shows the receipt is about a person and not
    just well-formed. Salt and commitment must still agree."""
    imported, receipt = _committed_receipt()
    sidecar = json.loads(SAMPLE_BINDING.read_text(encoding="utf-8"))
    disclosure = verify.Disclosure(
        identifier=sidecar["identifier"],
        identifier_type=sidecar["identifier_type"],
        salt=keys.b64u_decode(sidecar["salt_b64u"]),
    )
    result = verify.verify(
        json.dumps(receipt).encode("utf-8"), imported.trust_store, disclosure=disclosure
    )
    assert result.binding == "proven"
    assert result.ok is True


def test_committed_sample_carries_the_evidence_the_demo_promises() -> None:
    """The published bundle ships a legal text for every hash its terms bind,
    and a transparency proof for its receipt. Both are members a re-export can
    drop without the signature noticing — the receipt stays valid while the
    demo quietly stops demonstrating anything."""
    imported, receipt = _committed_receipt()
    payload = receipt["payload"]
    assert isinstance(payload, dict)
    receipt_id = payload["receipt_id"]
    assert isinstance(receipt_id, str)
    assert set(bundle._referenced_legal_hashes(payload)) <= set(imported.legal_texts)
    assert imported.legal_texts, "the sample must carry the licence text it binds"
    assert receipt_id in imported.proofs
