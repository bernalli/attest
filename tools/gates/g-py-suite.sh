#!/usr/bin/env bash
# G-PY-AH / G-PY-IZ / G-PY-SUB / G-PY-BW
#
# Property: the segment collects every file that belongs to it, and exits
# green. "Collects every file" is not read off a count written down here -
# both sides of the comparison (what the segment's own definition produces
# right now, and what pytest actually collected) are derived at runtime by
# g_py_expected_files() below, which is the SAME logic used to build the
# PYTEST_ARGS the run itself uses. See tools/gates/_lib.sh for the contract
# (gate_run never reads a status through a pipe; gate_expect_same_set never
# concludes anything from an empty set).
#
# Usage: g-py-suite.sh <ah|iz|sub|bw>
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_TREE="${GATE_TREE:-<tree>}"

SEGMENT="${1:-}"
case "$SEGMENT" in
  ah) GATE_ID="G-PY-AH" ;;
  iz) GATE_ID="G-PY-IZ" ;;
  sub) GATE_ID="G-PY-SUB" ;;
  bw) GATE_ID="G-PY-BW" ;;
  *)
    echo "usage: g-py-suite.sh <ah|iz|sub|bw>" >&2
    exit 2
    ;;
esac
export GATE_ID GATE_TREE

# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

TRANSCRIPTS="$HERE/transcripts"
mkdir -p "$TRANSCRIPTS"
TAG="$(date -u +%Y%m%dT%H%M%SZ)"

# The segment's own definition, derived now. This is the single place that
# names what belongs to each segment; the expected-set check below reruns it
# fresh rather than trusting a figure, and the collect-only step measures
# whether pytest agrees.
g_py_segment_args() {
  local seg="$1"
  case "$seg" in
    ah) find "$GATE_TREE/tests" -maxdepth 1 -name 'test_[a-h]*.py' | sort ;;
    iz) find "$GATE_TREE/tests" -maxdepth 1 -name 'test_[i-z]*.py' | sort ;;
    sub) printf '%s\n' "$GATE_TREE/tests/tools" ;;
    bw) printf '%s\n%s\n' "$GATE_TREE/bridge/tests" "$GATE_TREE/witness/tests" ;;
  esac
}

# What pytest would actually collect under a directory argument (recursive,
# default test_*.py glob) — used only to build the expected set for sub/bw,
# where the argument is a directory rather than an enumeration of files.
g_py_segment_expected_files() {
  local seg="$1"
  case "$seg" in
    ah|iz) g_py_segment_args "$seg" | sed "s#^$GATE_TREE/##" ;;
    sub) find "$GATE_TREE/tests/tools" -name 'test_*.py' | sed "s#^$GATE_TREE/##" | sort ;;
    bw)
      {
        find "$GATE_TREE/bridge/tests" -name 'test_*.py'
        find "$GATE_TREE/witness/tests" -name 'test_*.py'
      } | sed "s#^$GATE_TREE/##" | sort
      ;;
  esac
}

mapfile -t PYTEST_ARGS < <(g_py_segment_args "$SEGMENT")

gate_head
gate_say "segment: $SEGMENT"
gate_say "args:    ${PYTEST_ARGS[*]}"
gate_say ""

gate_need ".venv/bin/python exists" -- test -x "$GATE_PY"
gate_need "import pytest" -- "$GATE_PY" -c "import pytest"
gate_need "import attest (workspace member)" -- "$GATE_PY" -c "import attest"
gate_need "import attest_bridge (workspace member)" -- "$GATE_PY" -c "import attest_bridge"
gate_need "import attest_witness (workspace member)" -- "$GATE_PY" -c "import attest_witness"
if [ "$SEGMENT" = "bw" ]; then
  gate_need "verifiers/ts/dist/index.js present (bw needs the TS build first)" -- \
    test -f "$GATE_TREE/verifiers/ts/dist/index.js"
fi

JUNIT="$TRANSCRIPTS/${TAG}-${SEGMENT}.xml"
CENSUS="$TRANSCRIPTS/${TAG}-${SEGMENT}.files"
EXPECTED="$TRANSCRIPTS/${TAG}-${SEGMENT}.expected"

# --- Property 1: exit 0, never read through a pipe -------------------------
gate_run "pytest run ($SEGMENT)" -- \
  env PYTHONDONTWRITEBYTECODE=1 "$GATE_PY" -m pytest -p no:cacheprovider -q -ra \
    --junitxml="$JUNIT" "${PYTEST_ARGS[@]}"
RUN_OUT="$GATE_OUT"
gate_expect_rc 0 "pytest run ($SEGMENT) exits 0"

if [ "$SEGMENT" = "bw" ]; then
  # G-TS-B must precede this gate: the cross-core witness test skips (rather
  # than failing) when verifiers/ts/dist is missing, and a skip here is the
  # gate measuring less than it believes. -ra put the skip, if any, in
  # RUN_OUT's short test summary; absence of the test's own line there is
  # the marker that it actually ran and did not skip.
  if printf '%s\n' "$RUN_OUT" | grep -Eq 'SKIPPED.*test_the_lines_this_witness_produces_verify_in_both_cores'; then
    gate_say "FAIL: witness cross-core test was SKIPPED — verifiers/ts/dist is present but the test still skipped, or G-TS-B ran against a different tree"
    _gate_failures=$((_gate_failures + 1))
  else
    gate_say "ok: witness cross-core test not skipped (dist was in reach)"
  fi
fi

# --- Property 2 & 3: collected set non-empty and equal to the definition ---
gate_run "collect files ($SEGMENT)" -- \
  env PYTHONDONTWRITEBYTECODE=1 "$GATE_PY" -m pytest -p no:cacheprovider -q --collect-only \
    "${PYTEST_ARGS[@]}"
gate_expect_rc 0 "collect-only ($SEGMENT) exits 0"
printf '%s\n' "$GATE_OUT" | sed -n 's/::.*//p' | sort -u > "$CENSUS"
gate_expect_nonempty "$CENSUS" "collected files ($SEGMENT) non-empty"

g_py_segment_expected_files "$SEGMENT" > "$EXPECTED"
gate_expect_same_set "$EXPECTED" "$CENSUS" \
  "collected files ($SEGMENT) match the segment's own definition"

# --- Negative control: an argument that does not exist must be caught, and
# caught BY NAME, not just "exit != 0" — a bare exit code does not tell
# whether the failure reached pytest's collection at all. -----------------
gate_negative "nonexistent argument is reported by name, not silently absorbed" \
  --marker 'test_nonexistent\.py' -- \
  env PYTHONDONTWRITEBYTECODE=1 "$GATE_PY" -m pytest -p no:cacheprovider -q -ra \
    "$GATE_TREE/tests/test_nonexistent.py"

gate_verdict "the $SEGMENT segment collects every file that belongs to it and exits green"
