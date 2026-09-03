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
    return gen_vectors._tree(out)


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


def test_drift_reports_a_leaf_edited_by_hand(tmp_path: Path) -> None:
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
