#!/usr/bin/env bash
# gate-order: 110
# G-DESK: desktop's typecheck (src AND e2e) passes, the suite passes, the census names
# exactly what the run collected, and the build succeeds.
#
# Same structure as G-SITE (see that file's header for why the census is checked twice and
# why --selftest is asserted on exit 0 + names, never a count), with one addition: desktop's
# `npm run typecheck` is `tsc -p tsconfig.json && tsc -p tsconfig.e2e.json`
# (desktop/package.json:11) — two tsc invocations, not one, because tsconfig.e2e.json is a
# SEPARATE config (extends tsconfig.json, adds the Playwright types, includes only e2e/) so
# that the e2e helpers typecheck against @playwright/test's ambient types without polluting
# src/test's tsconfig. `npm run build` only runs the first of the two, so this typecheck step
# is not redundant with the build step further down.
#
# npm ci is a precondition (installs state), not this gate's job: gate_need, 78 if absent.
GATE_ID="G-DESK"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

DESK_DIR="$GATE_TREE/desktop"
CENSUS_JSON="$GATE_TREE/tools/test-census.json"
CHECK_CENSUS_PY="$GATE_TREE/tools/check_test_census.py"
TRANSCRIPTS="$SCRIPT_DIR/transcripts"
mkdir -p "$TRANSCRIPTS"
TAG="$(date -u +%Y%m%dT%H%M%SZ)"

gate_head

gate_need "desktop/node_modules present (run: npm ci --prefix $DESK_DIR)" -- test -d "$DESK_DIR/node_modules"
gate_need "npm available" -- command -v npm
gate_need "jq available" -- command -v jq
gate_need "tools/test-census.json present" -- test -f "$CENSUS_JSON"
gate_need "tools/check_test_census.py present" -- test -f "$CHECK_CENSUS_PY"

# --- Property 1: typecheck, both configs (src+test, then e2e) ------------------------------
gate_run "npm run typecheck (desktop: tsconfig.json then tsconfig.e2e.json)" -- \
  npm --prefix "$DESK_DIR" run typecheck
gate_expect_rc 0 "npm run typecheck (desktop) exits 0"

# --- Property 2: the suite runs and exits 0, status read directly, never through a pipe ----
REPORT="$TRANSCRIPTS/${TAG}-desktop.json"
gate_run "npm test (desktop, default + json reporters)" -- \
  npm --prefix "$DESK_DIR" test -- --reporter=default --reporter=json --outputFile.json="$REPORT"
gate_expect_rc 0 "npm test (desktop) exits 0"
gate_need "desktop test report was written: $REPORT" -- test -f "$REPORT"

# --- Property 3: the census names exactly what the run reports (the generic invariant) ----
CENSUS_SET="$TRANSCRIPTS/${TAG}-desktop.census-files"
REPORT_SET="$TRANSCRIPTS/${TAG}-desktop.report-files"
jq -r '.suites["desktop"].files | keys[]' "$CENSUS_JSON" | sort -u > "$CENSUS_SET"
jq -r '.testResults[].name' "$REPORT" | sed "s#^$DESK_DIR/##" | sort -u > "$REPORT_SET"
gate_expect_nonempty "$CENSUS_SET" "tools/test-census.json declares at least one file for suite desktop"
gate_expect_nonempty "$REPORT_SET" "the run's JSON report names at least one file"
gate_expect_same_set "$CENSUS_SET" "$REPORT_SET" \
  "the file set the census declares for desktop == the file set this run's report names"

# --- Property 4: the same comparison, plus per-file counts and pending/todo, via the tool
# this repo ships to enforce it in CI ---------------------------------------------------
gate_run "check_test_census.py desktop" -- \
  "$GATE_PY" "$CHECK_CENSUS_PY" desktop --report "$REPORT"
gate_expect_rc 0 "check_test_census.py desktop exits 0"

# --- D-G1b: same as G-SITE -- a guard only ever seen passing is not known to catch anything.
# Assert the census tool's --selftest exits 0 AND actually names its (five, not the
# docstring's stated four -- measured live) synthetic defects, never the count. -------------
gate_run "check_test_census.py --selftest" -- "$GATE_PY" "$CHECK_CENSUS_PY" --selftest
gate_expect_rc 0 "check_test_census.py --selftest exits 0"
gate_expect_marker 'a file on disk that the run never collected -> named' \
  "selftest names: a file on disk the run never collected"
gate_expect_marker 'a file collected with zero tests -> named' \
  "selftest names: a file collected with zero tests"
gate_expect_marker 'a file whose count drifted -> named' \
  "selftest names: a per-file count that drifted from the census"
gate_expect_marker 'a new file nobody registered -> named' \
  "selftest names: a file the run reports that is missing from the census"
gate_expect_marker 'a skipped test -> named' \
  "selftest names: a pending/skipped test"
gate_expect_marker 'a file whose test names changed at an unchanged count -> named' \
  "selftest names: a substituted test name at an unchanged per-file count"

# --- Property 5: the build succeeds -------------------------------------------------------
gate_run "npm run build (desktop)" -- npm --prefix "$DESK_DIR" run build
gate_expect_rc 0 "npm run build (desktop) exits 0 (tsc --noEmit, vite build, then the inliner)"

gate_verdict "desktop typechecks (src and e2e), its suite passes, the census names exactly what the run collected, and the build succeeds"
