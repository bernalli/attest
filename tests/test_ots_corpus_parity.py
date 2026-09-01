"""Does the converter's own output survive the OTHER core?

`log ots-convert` turns a real detached OpenTimestamps attestation into the
anchor-proof shape `log anchor` accepts, and `tests/test_ots_convert.py`
follows that output all the way to a Python verdict. Python agreeing with
Python proves one implementation is self-consistent; the project's central
claim is that TWO implementations agree, and until now no test ever handed
the converter's output to the TypeScript verifier.

The corpus is where that claim is settled: `32-anchor-v2/d-converted-from-ots`
carries anchor evidence whose proof and pinned header were produced by
`ots.convert_ots` itself, so every core that replays the corpus — the Python
`tests/test_vectors.py`, `verifiers/ts/test/conformance.test.ts`, and any
third-party implementation running `tools/conformance_runner.py` — verifies
converter output rather than a hand-built imitation of it.

A committed leaf can go stale in silence, because `tools/gen_vectors.py` is
not re-run in CI: if the converter's output shape changed, the corpus would
keep asserting the OLD shape and the cross-core claim would quietly stop
covering what the converter actually emits. The test below is the pin that
makes that impossible — it re-derives the leaf's anchor material from the
LIVE converter and demands the committed bytes still match.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from attest import tlog

_REPO_ROOT = Path(__file__).resolve().parent.parent
_LEAF = _REPO_ROOT / "docs" / "spec" / "vectors" / "32-anchor-v2" / "d-converted-from-ots"

_TOOLS = _REPO_ROOT / "tools" / "gen_vectors.py"
_spec = importlib.util.spec_from_file_location("gen_vectors", _TOOLS)
assert _spec is not None and _spec.loader is not None
gen_vectors = importlib.util.module_from_spec(_spec)
sys.modules["gen_vectors"] = gen_vectors
_spec.loader.exec_module(gen_vectors)


def _leaf_json(name: str) -> dict[str, object]:
    loaded = json.loads((_LEAF / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_the_committed_leaf_carries_what_the_converter_emits_today() -> None:
    evidence = _leaf_json("transparency.json")
    anchors = evidence["anchors"]
    assert isinstance(anchors, dict)
    checkpoint = tlog.parse_checkpoint(str(anchors["checkpoint"]))

    proof, pinned_headers = gen_vectors.converted_ots_anchor_material(checkpoint.signed_note_bytes)

    assert anchors["proofs"] == [proof]
    assert _leaf_json("anchor-policy.json") == {
        "pinned_headers": pinned_headers,
        "crqc_horizon": None,
    }


def test_the_leaf_exercises_a_real_op_chain_and_not_the_hand_built_single_hash() -> None:
    """32a already pins the degenerate one-op chain built by hand.

    This leaf is worth its place only if the ops came out of an actual `.ots`
    tree — an operand-carrying step ahead of the hash — so that the TypeScript
    replay is exercised on the shape the converter really produces.
    """
    anchors = _leaf_json("transparency.json")["anchors"]
    assert isinstance(anchors, dict)
    proofs = anchors["proofs"]
    assert isinstance(proofs, list) and len(proofs) == 1
    ops = proofs[0]["ops"]
    assert [op[0] for op in ops] == ["append", "sha256"]
    assert len(ops[0]) == 2 and ops[0][1]
