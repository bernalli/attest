"""The committed conformance corpus must be what the generator produces today.

Every other vector test REPLAYS `docs/spec/vectors/`: it reads the committed
leaves and asks the two implementations to agree with `expected.json`. That
never re-runs the generator, and the generator is where a whole class of
invariants lives — the asserts it makes while minting a leaf (a revocation
record authenticates under the issuer manifest, a payload validates against the
schema, a depth-boundary leaf lands exactly on the boundary). Replay cannot see
those; only regeneration can. Until this file existed, nothing in the repo ran
`tools/gen_vectors.py` again after the corpus was committed, so the corpus that
pins the protocol was the one artifact with no link to the source that produced
it.

The corpus is minted with a dev-only ML-DSA oracle (`dilithium-py`, the `dev`
extra). Without it the gate cannot run at all, and it says so loudly rather
than disappearing from the run.
"""

from __future__ import annotations

import importlib.util
import sys
import warnings
from pathlib import Path
from types import ModuleType

import pytest
from hypothesis import given
from hypothesis import strategies as st

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED = REPO_ROOT / "docs" / "spec" / "vectors"

_MISSING_ORACLE = (
    "the vector regeneration gate needs the dev-only dilithium-py oracle that mints "
    "the ML-DSA leaves; install the dev extra (uv sync --extra dev) to run it"
)


def _load_generator() -> ModuleType:
    """Load `tools/gen_vectors.py` (tools/ is not a package), reusing the copy
    a sibling test may already have paid for — importing it derives every fixed
    keypair in the corpus."""
    cached = sys.modules.get("gen_vectors")
    if cached is not None:
        return cached
    path = REPO_ROOT / "tools" / "gen_vectors.py"
    spec = importlib.util.spec_from_file_location("gen_vectors", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_vectors"] = module
    spec.loader.exec_module(module)
    return module


if importlib.util.find_spec("dilithium_py") is None:  # pragma: no cover - dev extra present
    # A warning, not a bare skip: an absent gate that says nothing is
    # indistinguishable from a gate that passed.
    warnings.warn(_MISSING_ORACLE, stacklevel=1)
    pytest.skip(_MISSING_ORACLE, allow_module_level=True)

gen_vectors = _load_generator()


@pytest.fixture(scope="module")
def regenerated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """One full regeneration, shared by the file: minting the corpus is the
    expensive part, and every generator-time assert fires while it happens."""
    out = tmp_path_factory.mktemp("vectors") / "vectors"
    leaf_count = gen_vectors.generate(out)
    assert leaf_count > 0, "the generator wrote no leaves at all"
    # Everything the generator wrote, hand-authored names included: excluding
    # them here would make the test below unable to notice one being produced.
    return gen_vectors._tree(out, exclude_hand_authored=False)


def test_committed_corpus_is_what_the_generator_produces(regenerated: dict[str, bytes]) -> None:
    committed = gen_vectors._tree(COMMITTED)
    assert sorted(committed) == sorted(regenerated)
    differing = sorted(name for name in committed if committed[name] != regenerated[name])
    assert differing == []


def test_hand_authored_files_are_still_there(regenerated: dict[str, bytes]) -> None:
    """The generator preserves files it does not write (the corpus README), so
    a diff of generated output can never notice one going missing. Name them."""
    for name in gen_vectors.HAND_AUTHORED_FILES:
        assert (COMMITTED / name).is_file(), name
        assert name not in regenerated, f"{name} is generated after all — stop exempting it"


def test_drift_reports_a_leaf_edited_by_hand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate's own teeth, measured against the committed tree itself so the
    answer does not depend on regeneration agreeing: an edited byte, a missing
    leaf and an invented one must each come back named."""
    committed = gen_vectors._tree(COMMITTED)
    assert gen_vectors.drift(committed, committed) == []

    victim = sorted(name for name in committed if name.endswith("expected.json"))[0]
    edited = dict(committed)
    edited[victim] = edited[victim].replace(b'"ok": true', b'"ok": false')
    assert edited[victim] != committed[victim], f"{victim} did not change — pick another victim"
    assert gen_vectors.drift(edited, committed) == [victim]

    deleted = dict(committed)
    del deleted[victim]
    assert gen_vectors.drift(deleted, committed) == [victim]

    extra = dict(committed) | {"99-invented/expected.json": b"{}\n"}
    assert gen_vectors.drift(extra, committed) == ["99-invented/expected.json"]

    # A corpus directory that is not there at all is drift the cheap way:
    # `check` says so without minting a second corpus to compare against.
    assert gen_vectors.check(tmp_path / "absent") == 1

    # Exercise the boundary that matters to callers: a non-empty drift must
    # become a failing process status, not merely a diagnostic on stderr.
    committed_root = tmp_path / "committed"
    committed_leaf = committed_root / "01-valid-minimal"
    committed_leaf.mkdir(parents=True)
    (committed_root / "README.md").write_text("hand-authored\n", encoding="utf-8")
    (committed_leaf / "expected.json").write_bytes(b'{"ok":true}\n')

    def generate_different(fresh: Path) -> int:
        fresh_leaf = fresh / "01-valid-minimal"
        fresh_leaf.mkdir(parents=True)
        (fresh_leaf / "expected.json").write_bytes(b'{"ok":false}\n')
        return 1

    monkeypatch.setattr(gen_vectors, "generate", generate_different)
    assert gen_vectors.check(committed_root) == 1


_TREE = st.dictionaries(
    keys=st.text(min_size=1, max_size=12),
    values=st.binary(max_size=24),
    max_size=8,
)


@given(committed=_TREE, produced=_TREE)
def test_drift_is_empty_exactly_when_the_trees_are_equal(
    committed: dict[str, bytes], produced: dict[str, bytes]
) -> None:
    assert (gen_vectors.drift(committed, produced) == []) == (committed == produced)


def test_tree_refuses_symlinks_even_when_the_target_bytes_match(tmp_path: Path) -> None:
    """A leaf replaced by a link to another leaf with identical bytes is a
    different tree, and a comparison that resolves the link says otherwise."""
    target = tmp_path / "target.json"
    target.write_bytes(b"{}\n")
    alias = tmp_path / "alias.json"
    alias.symlink_to(target.name)

    with pytest.raises(ValueError, match=r"symlink: alias\.json$"):
        gen_vectors._tree(tmp_path)


def test_check_refuses_a_symlinked_vector_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "vectors"
    alias.symlink_to(real, target_is_directory=True)

    assert gen_vectors.check(alias) == 1
