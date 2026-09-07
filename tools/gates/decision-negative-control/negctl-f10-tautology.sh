#!/usr/bin/env bash
# THIRD DUMMY — the class the ratified rules still do not close.
#
# The first two dummies asked whether F-06 and F-08 remained writable under D-G1.
# This one asks a different question: is there a defect that satisfies EVERY rule
# we ratified and is still vacuous?
#
# It is conformant on every count:
#   - an executable script, not a table row (D-G1);
#   - its outcome is produced by running it, transcript on file (D-G1);
#   - no count is written down: both sides are derived at run time (D-G2);
#   - the collection is asserted non-empty before anything is concluded (lib);
#   - the precondition is checked, 78 if absent (D-G1c);
#   - the negative control demands a marker, not just a non-zero exit (D-G1b).
#
# And it proves nothing, because the two sides of the invariant have the SAME
# provenance: both are derived from the same command. It compares the collector
# with itself. Every rule we wrote governs how a side is OBTAINED; none says the
# two sides must be obtained INDEPENDENTLY.
#
# It is `protocolli.md` point 10 -- a test whose oracle is the code under test is
# a tautology wearing the clothes of a verification -- arriving at the gates by a
# door the gate rules left open.
set -uo pipefail

GATE_ID="G-TAUTOLOGY"
GATE_TREE="<tree>"
source "$GATE_TREE/tools/gates/_lib.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gate_head
gate_need "python interpreter present" -- test -x "$GATE_PY"
gate_need "pytest importable" -- "$GATE_PY" -c "import pytest"

# The measurement: which files does the collector reach for this segment?
gate_run "collect the sub segment" -- env PYTHONDONTWRITEBYTECODE=1 \
  "$GATE_PY" -m pytest -p no:cacheprovider -q --collect-only "$GATE_TREE/tests/tools"

# Side A, derived at run time from the collector.
printf '%s\n' "$GATE_OUT" | sed -n 's/::.*//p' | sort -u > "$WORK/side-a"
# Side B, derived at run time... from the very same output.
printf '%s\n' "$GATE_OUT" | sed -n 's/::.*//p' | sort -u > "$WORK/side-b"

gate_expect_nonempty "$WORK/side-a" "the collector reached some files"
gate_expect_same_set "$WORK/side-a" "$WORK/side-b" \
  "every file the segment owns was collected"

# A negative control with a marker, exactly as D-G1b demands -- and just as vacuous.
gate_negative "a missing argument is caught" \
  --marker 'file or directory not found' \
  -- env PYTHONDONTWRITEBYTECODE=1 "$GATE_PY" -m pytest -p no:cacheprovider -q \
       --collect-only "$GATE_TREE/tests/test_nonexistent_probe.py"

gate_verdict "every file the sub segment owns is collected"
