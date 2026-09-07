#!/usr/bin/env bash
# G-CI-COVER — every CI command is covered by an F6 gate or declared out of scope.
#
# This gate exists because the plan carried the sentence "the F6 gates cover every
# `run:` line of the CI that F6 can influence" as prose. Nobody had run it, and it
# was already false: container_differential.py runs in the workflow and G-CONT-DIFF
# was missing from the list. Coverage claims are the easiest kind of claim to make
# and the hardest to notice going stale, so this one is derived from the workflow
# files each time instead of being asserted once.
GATE_ID="G-CI-COVER"
GATE_TREE="${GATE_TREE:-<tree>}"
source "$GATE_TREE/tools/gates/_lib.sh"

CHECKER="$GATE_TREE/tools/gates/ci_coverage.py"
TRANSCRIPTS="$GATE_TREE/tools/gates/transcripts"

gate_head

gate_need "python interpreter present" -- test -x "$GATE_PY"
gate_need "pyyaml importable" -- "$GATE_PY" -c "import yaml"
gate_need "coverage checker present" -- test -f "$CHECKER"
gate_need "ci.yml present" -- test -f "$GATE_TREE/.github/workflows/ci.yml"
gate_need "pages.yml present" -- test -f "$GATE_TREE/.github/workflows/pages.yml"

gate_run "classify every CI command" -- "$GATE_PY" "$CHECKER"
gate_expect_rc 0 "no CI command is left unclassified"
gate_expect_marker 'CI_COVERAGE_COMPLETE' "the checker reached its verdict"
# Guards the green-for-absence case: a parse that produced nothing would classify
# nothing, and nothing is trivially all-classified.
gate_expect_marker 'parsed [1-9][0-9]* CI commands' "commands were actually parsed"

# --- negative: a CI command the gate set does not cover must be named.
# The mutation lives on a copy: the real workflows are never touched. The observable
# is the unknown command appearing by name in the output, not a non-zero exit --
# an exit code alone would also be produced by a missing file or a YAML error,
# neither of which says anything about coverage.
NEG_TREE="$(mktemp -d)"
trap 'rm -rf "$NEG_TREE"' EXIT
mkdir -p "$NEG_TREE/.github/workflows"
cp "$GATE_TREE/.github/workflows/ci.yml" "$GATE_TREE/.github/workflows/pages.yml" \
   "$NEG_TREE/.github/workflows/"
"$GATE_PY" - "$NEG_TREE/.github/workflows/ci.yml" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
marker = "      - name: Injected step for the negative control\n        run: ./tools/a-command-no-gate-measures.sh --invented\n"
lines = text.splitlines(keepends=True)
for index, line in enumerate(lines):
    if line.lstrip().startswith("- name:"):
        lines.insert(index, marker)
        break
path.write_text("".join(lines), encoding="utf-8")
PY

gate_negative "an uncovered CI command is named" \
  --marker 'a-command-no-gate-measures\.sh' \
  -- env CI_COVERAGE_TREE="$NEG_TREE" "$GATE_PY" "$CHECKER"

gate_verdict "every CI command is measured by an F6 gate or declared out of scope with a reason"
