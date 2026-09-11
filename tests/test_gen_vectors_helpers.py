"""Unit tests for gen_vectors.py plumbing added by the regression-corpus work."""

import importlib.util
import sys
from pathlib import Path

import pytest

if importlib.util.find_spec("dilithium_py") is None:  # pragma: no cover - dev extra present
    # Importing the generator derives ML-DSA key material at module scope, so
    # without the dev-only oracle this file is a collection ERROR rather than a
    # skip — which turns "the gate cannot run here" into "the run is broken".
    pytest.skip(
        "the vector generator helpers need the dev-only dilithium-py oracle; "
        "install the dev extra (uv sync --extra dev) to run them",
        allow_module_level=True,
    )

_TOOLS = Path(__file__).resolve().parent.parent / "tools" / "gen_vectors.py"
_spec = importlib.util.spec_from_file_location("gen_vectors", _TOOLS)
assert _spec is not None and _spec.loader is not None
gen_vectors = importlib.util.module_from_spec(_spec)
sys.modules["gen_vectors"] = gen_vectors
_spec.loader.exec_module(gen_vectors)


def test_clear_leaf_dirs_removes_subdirs_but_preserves_readme(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("keep me", encoding="utf-8")
    leaf = tmp_path / "01-some-leaf"
    leaf.mkdir()
    (leaf / "expected.json").write_text("{}", encoding="utf-8")
    gen_vectors._clear_leaf_dirs(tmp_path)
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == "keep me"
    assert not leaf.exists()


def test_text_max_depth_counts_brackets_outside_strings_only() -> None:
    assert gen_vectors._text_max_depth('{"a": [1, [2]]}') == 3
    assert gen_vectors._text_max_depth('{"a": "ignore ] } [ { these"}') == 1
    assert gen_vectors._text_max_depth('{"a": "esc \\" ] "}') == 1


def test_live_key_entry_hands_back_the_live_entry_not_a_copy() -> None:
    """The whole reason the helper exists: `manifests.find_key` returns a COPY,
    and a generator that edits a fixture before re-signing it needs the
    opposite. A copy here drops the edit in silence, which is what leaf 35m's
    named control catches at generation time and nothing catches here."""
    manifest = {"keys": [{"kid": "a", "status": "compromised"}, {"kid": "b"}]}
    entry = gen_vectors._live_key_entry(manifest, "a")
    entry["status"] = "active"
    assert manifest["keys"][0]["status"] == "active"


def test_live_key_entry_refuses_an_ambiguous_kid() -> None:
    """Duplicate `keys[]` entries make array ORDER decide which one is edited --
    the same reason the library refuses to resolve an ambiguous kid. Raised,
    never asserted, so `python -O` cannot remove it."""
    manifest = {"keys": [{"kid": "a", "status": "compromised"}, {"kid": "a", "status": "active"}]}
    with pytest.raises(ValueError, match="expected exactly one"):
        gen_vectors._live_key_entry(manifest, "a")


def test_live_key_entry_refuses_an_absent_kid() -> None:
    manifest = {"keys": [{"kid": "a"}]}
    with pytest.raises(ValueError, match="expected exactly one"):
        gen_vectors._live_key_entry(manifest, "zz")
