"""The committed web-verifier sample bundle must be regenerable and genuine.

Loads tools/gen_site_sample.py by file path (tools/ is not a package) and
checks that a fresh generation produces a bundle that imports, verifies ok
at TOFU trust, proves its binding with the sidecar salt, and never leaks a
.private.attest into the output directory.
"""

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from attest import bundle


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
