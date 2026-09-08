#!/usr/bin/env bash
# gate-order: 45
# gate-order-why: pure static sweep, no build needed; runs before the suites
# G-PORT-CALLS: every trust-material port called from `tools/` is handed a
# parsed handle, never a tree.
#
# WHY THIS GATE EXISTS, AND WHAT IT REPLACES
#
# The tools under `tools/` are the one place where handing a port a plain tree
# is both possible and invisible. Inside the library `mypy --strict` catches it;
# in a test it goes red; here the generator simply asserts something that is
# false for a reason nobody expected, at the next corpus regeneration.
#
# It also closes a gap that cannot be closed at the call site. In `gen_vectors.py`
# the two NEGATIVE assertions of leaf 35l are insensitive to a missing admission:
# the port answers `False` both because the countersigning key is compromised --
# the intended reason -- and because it was handed a tree. Same colour, different
# reason, so mutating those two lines leaves `--check` green. Measured, one
# mutation at a time. Rather than reshape the shared corpus oracle to make two
# assertions provable, the class is closed upstream: no port call under `tools/`
# can lose its admission without this gate saying so.
GATE_ID="G-PORT-CALLS"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

SWEEP="$GATE_TREE/tools/gates/port_call_sweep.py"

gate_head

gate_need "python present in .venv" -- test -x "$GATE_PY"
gate_need "port_call_sweep.py present" -- test -f "$SWEEP"

gate_run "port_call_sweep.py" -- "$GATE_PY" "$SWEEP"
gate_expect_rc 0 "every port call under tools/ admits its trust material"

# The count is derived by the sweep itself and printed; assert it is not zero,
# because a sweep that found nothing agrees with every conclusion one could draw
# from it. This is the same "green for absence" guard the other gates carry.
gate_expect_marker '^port call sites under tools/: [1-9][0-9]* across [1-9]' \
  "the sweep actually found port call sites to judge"

# NEGATIVE CONTROL. A copy of the tools tree, outside the worktree, with ONE
# admission removed from a real call -- the defect this gate exists for, in the
# shape it actually arrives in. Asserting only "exit != 0" would not do: the
# marker requires the failure to name the file and the line, which is what
# separates "the sweep caught a bad call" from "the sweep crashed".
NEG_TREE="$(mktemp -d)"
mkdir -p "$NEG_TREE/tools/gates"
cp -r "$GATE_TREE/tools/." "$NEG_TREE/tools/"
"$GATE_PY" - "$NEG_TREE" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "tools" / "gen_vectors.py"
src = p.read_text()
anchor = "assert manifests.verify_key_manifest(_snapshot(manifest_l_v1)) is True"
assert src.count(anchor) == 1, src.count(anchor)
p.write_text(src.replace(anchor, "assert manifests.verify_key_manifest(manifest_l_v1) is True", 1))
PY
gate_negative "port_call_sweep.py against a copy with one admission removed" \
  --marker 'FAIL: tools/gen_vectors\.py:[0-9]+: manifests\.verify_key_manifest' -- \
  "$GATE_PY" "$NEG_TREE/tools/gates/port_call_sweep.py"
rm -rf "$NEG_TREE"

gate_verdict "every trust-material port called from tools/ receives a parsed handle, and the declared exceptions still match something"
