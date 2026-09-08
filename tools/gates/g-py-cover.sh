#!/usr/bin/env bash
# gate-order: 50
# gate-order-why: compares the union of the segments above
# G-PY-COVER
#
# Property: the union of the ah/iz/sub/bw segments covers every test file on
# disk, with no gap. "On disk" is derived from pyproject.toml's own
# [tool.pytest.ini_options] testpaths at runtime (tomllib), not from a
# directory list written down here — the three test trees the project
# actually declares are the only honest definition of "every test file".
#
# The census of what a segment collects comes from `pytest --collect-only`
# node IDs, never from the junit report: a <testcase> only carries
# `classname` (a dotted module path, absent entirely for tests inside a
# class) and no `file` attribute — measured. `--collect-only` prints node
# IDs, so the file is a datum, not a reconstruction.
#
# Three checks together, not any one alone (see tools/gates/_lib.sh): (1)
# collect-only exits 0, (2) each census is non-empty, (3) the union equals
# the disk-derived universe. A file with no tests and a glob that fails to
# expand leave the affected side with ZERO collected files, and an empty set
# compares equal to an empty set, so `comm -3` alone would be green for
# absence.
#
# A MISSING ARGUMENT is NOT in that family, and saying so here was wrong: a
# segment stripped of its arguments does not collect zero files, it falls back
# to `testpaths` and collects the WHOLE universe (measured; negative 2 below
# says the same thing 130 lines down). The union then still equals the
# universe and this gate stays GREEN. The per-segment invariant that does
# catch it — census(segment) == definition(segment) — lives in
# tools/gates/g-py-suite.sh, which runs alongside; this gate covers the gap
# between segments, not the identity of each one.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_ID="G-PY-COVER"
GATE_TREE="${GATE_TREE:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd))}"
export GATE_ID GATE_TREE

# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

TRANSCRIPTS="$HERE/transcripts"
mkdir -p "$TRANSCRIPTS"
TAG="$(date -u +%Y%m%dT%H%M%SZ)"

# Same segment definitions as g-py-suite.sh (tools/gates/g-py-suite.sh),
# duplicated rather than shared: both derive fresh from the filesystem at
# call time, so there is no figure here to drift out of sync — only the
# two glob patterns and two directory names the plan itself names in §7.0.
g_py_segment_args() {
  local seg="$1"
  case "$seg" in
    ah) find "$GATE_TREE/tests" -maxdepth 1 -name 'test_[a-h]*.py' | sort ;;
    iz) find "$GATE_TREE/tests" -maxdepth 1 -name 'test_[i-z]*.py' | sort ;;
    sub) printf '%s\n' "$GATE_TREE/tests/tools" ;;
    bw) printf '%s\n%s\n' "$GATE_TREE/bridge/tests" "$GATE_TREE/witness/tests" ;;
  esac
}

gate_head

gate_need ".venv/bin/python exists" -- test -x "$GATE_PY"
gate_need "import pytest" -- "$GATE_PY" -c "import pytest"
gate_need "import attest (workspace member)" -- "$GATE_PY" -c "import attest"
gate_need "import attest_bridge (workspace member)" -- "$GATE_PY" -c "import attest_bridge"
gate_need "import attest_witness (workspace member)" -- "$GATE_PY" -c "import attest_witness"
gate_need "pyproject.toml testpaths readable via tomllib" -- \
  "$GATE_PY" -c "import tomllib; d=tomllib.load(open('$GATE_TREE/pyproject.toml','rb')); d['tool']['pytest']['ini_options']['testpaths']"

# --- The universe: every test_*.py under every tree pytest itself declares,
# derived from pyproject.toml right now, not written down here. ------------
mapfile -t TEST_DIRS < <(
  "$GATE_PY" -c "
import tomllib
d = tomllib.load(open('$GATE_TREE/pyproject.toml', 'rb'))
for p in d['tool']['pytest']['ini_options']['testpaths']:
    print(p)
"
)
gate_say "testpaths (from pyproject.toml): ${TEST_DIRS[*]}"
gate_say ""

UNIVERSE="$TRANSCRIPTS/${TAG}-universe.files"
: > "$UNIVERSE"
for d in "${TEST_DIRS[@]}"; do
  find "$GATE_TREE/$d" -name 'test_*.py'
done | sed "s#^$GATE_TREE/##" | sort -u > "$UNIVERSE"
gate_expect_nonempty "$UNIVERSE" "disk-derived universe (testpaths) non-empty"

# --- Per-segment census: collect-only, never through a pipe for the status,
# never trusting an empty result. -------------------------------------------
declare -a SEGMENTS=(ah iz sub bw)
declare -a CENSUS_FILES=()

for seg in "${SEGMENTS[@]}"; do
  mapfile -t seg_args < <(g_py_segment_args "$seg")
  gate_run "collect files ($seg)" -- \
    env PYTHONDONTWRITEBYTECODE=1 "$GATE_PY" -m pytest -p no:cacheprovider -q --collect-only \
      "${seg_args[@]}"
  gate_expect_rc 0 "collect-only ($seg) exits 0"

  census="$TRANSCRIPTS/${TAG}-${seg}.files"
  printf '%s\n' "$GATE_OUT" | sed -n 's/::.*//p' | sort -u > "$census"
  gate_expect_nonempty "$census" "collected files ($seg) non-empty"
  CENSUS_FILES+=("$census")
done

UNION="$TRANSCRIPTS/${TAG}-union.files"
sort -u -- "${CENSUS_FILES[@]}" > "$UNION"

gate_expect_same_set "$UNIVERSE" "$UNION" \
  "the union of ah+iz+sub+bw covers every test file testpaths declares, no gap"

# --- Negative 1: a file with no test items is invisible to a node-ID census
# (no "::" line is ever printed for it) but is not invisible to `find` — the
# exact "green for absence" shape this gate exists to catch. Created and
# removed here; the trap covers early exit too. ------------------------------
PROBE="$GATE_TREE/tests/test_zz_probe_cover.py"
_probe_cleanup() { rm -f "$PROBE"; }
trap _probe_cleanup EXIT

gate_say "--- negative: a new, uncollectable-by-node-ID file must be reported by name"
: > "$PROBE"

probe_universe="$TRANSCRIPTS/${TAG}-probe-universe.files"
: > "$probe_universe"
for d in "${TEST_DIRS[@]}"; do
  find "$GATE_TREE/$d" -name 'test_*.py'
done | sed "s#^$GATE_TREE/##" | sort -u > "$probe_universe"

declare -a probe_census_files=()
for seg in "${SEGMENTS[@]}"; do
  mapfile -t seg_args < <(g_py_segment_args "$seg")
  GATE_OUT="$(env PYTHONDONTWRITEBYTECODE=1 "$GATE_PY" -m pytest -p no:cacheprovider -q --collect-only \
    "${seg_args[@]}" 2>&1)"
  pc="$TRANSCRIPTS/${TAG}-${seg}-with-probe.files"
  printf '%s\n' "$GATE_OUT" | sed -n 's/::.*//p' | sort -u > "$pc"
  probe_census_files+=("$pc")
done
probe_union="$TRANSCRIPTS/${TAG}-probe-union.files"
sort -u -- "${probe_census_files[@]}" > "$probe_union"

probe_diff="$(comm -3 <(sort -u "$probe_universe") <(sort -u "$probe_union"))"
rm -f "$PROBE"
trap - EXIT

# Here-string, same property as everywhere else in this directory: through a pipe,
# pipefail turns an early grep -q match into 141. Here it would be a false RED --
# harmless today only because probe_diff is short enough that printf finishes
# writing first, which is not a property anyone should rely on.
if grep -Eq -- 'test_zz_probe_cover\.py' <<< "$probe_diff"; then
  gate_say "ok: negative 'empty file uncollected by node ID' — the comparison names it:"
  printf '%s\n' "$probe_diff"
else
  gate_say "FAIL: negative 'empty file uncollected by node ID' — the file was created but did not surface in the comparison; the gate cannot catch this defect"
  _gate_failures=$((_gate_failures + 1))
fi

# --- Negative 2: a segment stripped of its arguments. Measured, not assumed:
# on this tree `pytest --collect-only` with NO arguments does not exit 4 or
# collect nothing — it falls back to `testpaths` and exits 0 having
# collected the WHOLE suite. A check that expected "exit 4, zero files" would
# be FALSE here. What actually makes the defect visible is that the degraded
# census for the "sub" segment no longer equals its own definition — it
# silently balloons to the entire universe. Neither figure is written here:
# both moved inside the commit that added a test file (118 -> 119 and 4 -> 5),
# and the line below derives them. --
gate_say "--- negative: a segment stripped of its own arguments (observed behaviour, not assumed)"

sub_expected="$TRANSCRIPTS/${TAG}-sub.expected"
find "$GATE_TREE/tests/tools" -name 'test_*.py' | sed "s#^$GATE_TREE/##" | sort -u > "$sub_expected"

GATE_OUT="$(env PYTHONDONTWRITEBYTECODE=1 "$GATE_PY" -m pytest -p no:cacheprovider -q --collect-only 2>&1)"
GATE_RC=$?
degraded_census="$TRANSCRIPTS/${TAG}-sub-degraded.files"
printf '%s\n' "$GATE_OUT" | sed -n 's/::.*//p' | sort -u > "$degraded_census"
gate_say "observed: collect-only with no arguments exits $GATE_RC and collects $(grep -c . "$degraded_census") files (testpaths fallback), not the $(grep -c . "$sub_expected") files 'sub' owns"

degraded_diff="$(comm -3 <(sort -u "$sub_expected") <(sort -u "$degraded_census"))"
if [ -n "$degraded_diff" ]; then
  gate_say "ok: negative 'sub stripped of its arguments' detected — its census no longer equals its own definition (excerpt):"
  printf '%s\n' "$degraded_diff" | head -5
  gate_say "  ... ($(printf '%s\n' "$degraded_diff" | grep -c .) lines total)"
else
  gate_say "FAIL: negative 'sub stripped of its arguments' — the same-set check would stay green despite the missing argument"
  _gate_failures=$((_gate_failures + 1))
fi

gate_verdict "the union of ah+iz+sub+bw covers every test file testpaths declares, no gap"
