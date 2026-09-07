#!/usr/bin/env bash
# G-CONT-DIFF: the two container readers (Python, TypeScript) never disagree,
# at the exact seed and count pages.yml uses.
#
# --count and --seed here are confirmed against .github/workflows/pages.yml
# by reading it, not by assuming the plan's prose is still current — 500 and
# 20260902 match exactly (2026-09-07).
GATE_ID="G-CONT-DIFF"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

CONT_DIFF="$GATE_TREE/tools/container_differential.py"
ESBUILD="$GATE_TREE/site/node_modules/.bin/esbuild"
CI_COUNT=500
CI_SEED=20260902
LINE_RE='^[0-9]+ archives, [0-9]+ accepted, [0-9]+ refused, [0-9]+ distinct codes, [0-9]+ divergences$'

gate_head

gate_need "container_differential.py present" -- test -f "$CONT_DIFF"
# container_differential.py bundles the browser reader with the SITE's own
# esbuild unconditionally (measured: it has no path that skips this, unlike
# conformance_runner which only needs it for one adapter choice). Same gap
# as G-CI-PY's importer_differential step, checked here again because this
# gate does not source that one's precondition.
gate_need "site/node_modules/.bin/esbuild present (container_differential's TS bundle)" \
  -- test -x "$ESBUILD"

# --- positive: the CI's own count and seed ----------------------------------
gate_run "container_differential.py --count $CI_COUNT --seed $CI_SEED (pages.yml's own numbers)" -- \
  "$GATE_PY" "$CONT_DIFF" --count "$CI_COUNT" --seed "$CI_SEED"
gate_expect_rc 0 "container_differential.py: zero divergences at the CI count/seed"
gate_expect_marker "$LINE_RE" \
  "container_differential.py prints its own archive/accept/refuse/divergence counts, not just an exit code"

FULL_LINE="$(printf '%s\n' "$GATE_OUT" | grep -E "$LINE_RE" | head -n1)"
FULL_ARCHIVES="$(printf '%s' "$FULL_LINE" | grep -Eo '^[0-9]+')"
FULL_DIVERGENCES="$(printf '%s' "$FULL_LINE" | grep -Eo '[0-9]+ divergences$' | grep -Eo '^[0-9]+')"
gate_say "container_differential.py (count=$CI_COUNT seed=$CI_SEED): $FULL_LINE"

if [ -z "$FULL_ARCHIVES" ] || [ -z "$FULL_DIVERGENCES" ]; then
  gate_run "container_differential.py summary line was parseable" -- false
  gate_expect_rc 0 "container_differential.py summary line was parseable"
else
  gate_run "container_differential.py archive count ($FULL_ARCHIVES) is > 0" -- \
    bash -c "[ '$FULL_ARCHIVES' -gt 0 ]"
  gate_expect_rc 0 "container_differential.py exercised at least one archive"

  gate_run "container_differential.py divergence count ($FULL_DIVERGENCES) is 0" -- \
    bash -c "[ '$FULL_DIVERGENCES' -eq 0 ]"
  gate_expect_rc 0 "container_differential.py: the Python and TypeScript readers agreed on every archive"
fi

# --- negative control, and it has a DIFFERENT SHAPE than every other one in
# this repo's gates — said here because it earns explaining, not assumed.
# `--count 1` is not expected to make the two readers disagree (one archive
# is not enough to provoke that on its own), so this cannot be phrased as
# "the command must fail" the way gate_negative demands: exit 0 here is not
# a defect, it is the expected case. What this negative proves instead is
# narrower and just as real: that --count is READ, not silently ignored in
# favour of some fixed internal default. The only way to see that from the
# outside is that the archive count in the summary line CHANGES when the
# argument changes — an observable difference stands in for the "reached
# the guarded path" marker gate_negative would otherwise demand.
gate_run "container_differential.py --count 1 --seed $CI_SEED (does --count get read, or ignored?)" -- \
  "$GATE_PY" "$CONT_DIFF" --count 1 --seed "$CI_SEED"
COUNT1_LINE="$(printf '%s\n' "$GATE_OUT" | grep -E "$LINE_RE" | head -n1)"
COUNT1_ARCHIVES="$(printf '%s' "$COUNT1_LINE" | grep -Eo '^[0-9]+')"
gate_say "container_differential.py --count 1: $COUNT1_LINE"

if [ -z "$COUNT1_ARCHIVES" ]; then
  gate_run "container_differential.py --count 1 summary line was parseable" -- false
  gate_expect_rc 0 "container_differential.py --count 1 summary line was parseable"
elif [ -z "$FULL_ARCHIVES" ]; then
  gate_run "cannot compare --count 1 against a full-run count that was never parsed" -- false
  gate_expect_rc 0 "the full-run archive count ($CI_COUNT) was available to compare against"
else
  gate_run "archive count under --count 1 ($COUNT1_ARCHIVES) differs from --count $CI_COUNT ($FULL_ARCHIVES)" -- \
    bash -c "[ '$COUNT1_ARCHIVES' -ne '$FULL_ARCHIVES' ]"
  gate_expect_rc 0 "container_differential.py reads --count instead of ignoring it"
fi

gate_verdict "container_differential.py reports zero divergences at pages.yml's own count/seed, over a nonzero number of archives, and --count is demonstrably read"
