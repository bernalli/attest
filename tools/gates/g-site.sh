#!/usr/bin/env bash
# gate-order: 100
# G-SITE: the site suite passes, the census names exactly the files the run collected, and
# the build (which typechecks site's tests too, since tsconfig.json's "include" covers "test")
# succeeds.
#
# npm ci is a precondition, not this gate's job: it INSTALLS state rather than measuring the
# tree as it stands, so it is a gate_need (missing -> 78), never a step run inside the gate.
#
# The census comparison happens TWICE on purpose. tools/check_test_census.py already ties
# disk/run/census together (file-by-file counts, pending/todo, a new file registered), and
# this gate runs it and demands 0. But the mandate for this gate additionally asks for the
# invariant expressed with this repo's own generic primitive (gate_expect_same_set) so the
# property that matters most here — "the file the census names is the file the run reports,
# nothing more, nothing less" — is visible without reading check_test_census.py's source.
# Both sides are derived from disk/the fresh JSON report at run time; neither is a number
# written down here.
GATE_ID="G-SITE"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

SITE_DIR="$GATE_TREE/site"
CENSUS_JSON="$GATE_TREE/tools/test-census.json"
CHECK_CENSUS_PY="$GATE_TREE/tools/check_test_census.py"
TRANSCRIPTS="$SCRIPT_DIR/transcripts"
mkdir -p "$TRANSCRIPTS"
TAG="$(date -u +%Y%m%dT%H%M%SZ)"

gate_head

gate_need "site/node_modules present (run: npm ci --prefix $SITE_DIR)" -- test -d "$SITE_DIR/node_modules"
gate_need "npm available" -- command -v npm
gate_need "jq available" -- command -v jq
gate_need "tools/test-census.json present" -- test -f "$CENSUS_JSON"
gate_need "tools/check_test_census.py present" -- test -f "$CHECK_CENSUS_PY"

# --- Property 1: the suite runs and exits 0, status read directly, never through a pipe ----
REPORT="$TRANSCRIPTS/${TAG}-site.json"
gate_run "npm test (site, default + json reporters)" -- \
  npm --prefix "$SITE_DIR" test -- --reporter=default --reporter=json --outputFile.json="$REPORT"
gate_expect_rc 0 "npm test (site) exits 0"
gate_need "site test report was written: $REPORT" -- test -f "$REPORT"

# --- Property 2: the census names exactly what the run reports (the generic invariant) ----
CENSUS_SET="$TRANSCRIPTS/${TAG}-site.census-files"
REPORT_SET="$TRANSCRIPTS/${TAG}-site.report-files"
jq -r '.suites["site"].files | keys[]' "$CENSUS_JSON" | sort -u > "$CENSUS_SET"
jq -r '.testResults[].name' "$REPORT" | sed "s#^$SITE_DIR/##" | sort -u > "$REPORT_SET"
gate_expect_nonempty "$CENSUS_SET" "tools/test-census.json declares at least one file for suite site"
gate_expect_nonempty "$REPORT_SET" "the run's JSON report names at least one file"
gate_expect_same_set "$CENSUS_SET" "$REPORT_SET" \
  "the file set the census declares for site == the file set this run's report names"

# --- Property 3: the same comparison, plus per-file counts and pending/todo, via the tool
# this repo ships to enforce it in CI ---------------------------------------------------
gate_run "check_test_census.py site" -- \
  "$GATE_PY" "$CHECK_CENSUS_PY" site --report "$REPORT"
gate_expect_rc 0 "check_test_census.py site exits 0"

# --- D-G1b: a guard only ever seen passing is not known to catch anything. The census
# tool's own --selftest points the comparison at five synthetic defects (one healthy input
# plus five broken ones, despite the module docstring's "four" -- measured live below) and
# demands each is named. Assert that it exits 0 AND that it actually named its cases, never
# the count of cases (that count is exactly the kind of figure this whole gate exists to
# stop trusting). ---------------------------------------------------------------------------
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

# --- Property 4: the build succeeds, which runs tsc --noEmit over site/tsconfig.json, and
# that tsconfig's "include" covers src, test AND e2e -- so this also typechecks site's tests
# (site/tsconfig.json:11, read at the time this gate was written). --------------------------
gate_run "npm run build (site)" -- npm --prefix "$SITE_DIR" run build
gate_expect_rc 0 "npm run build (site) exits 0 (tsc --noEmit over src+test+e2e, then vite build)"

gate_verdict "the site suite passes, the census names exactly what the run collected, and the build (typechecking site's tests too) succeeds"
