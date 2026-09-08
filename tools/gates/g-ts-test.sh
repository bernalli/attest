#!/usr/bin/env bash
# gate-order: 30
# G-TS: the vitest suite passes AND collects exactly the *.test.ts files present on disk.
#
# Plan reference: docs/plans/2026-09-08-trust-material-serialized-entry.md, §7.0 row G-TS.
# The plan's original text pinned "N = 51 a T0, 53 da T1" — a count that is exactly what
# C-208 warns against (a file not collected is a smaller N, and a smaller N reads as fewer
# tests rather than as a miss). This gate compares the SET vitest reports having run against
# the set `ls test/*.test.ts` finds now, never a number written down (D20/NV-11).
GATE_ID="G-TS"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

TS_DIR="$GATE_TREE/verifiers/ts"
TRANSCRIPT_DIR="$SCRIPT_DIR/transcripts"
JSON_OUT="$TRANSCRIPT_DIR/g-ts.vitest-full.json"
FILTER_JSON="$TRANSCRIPT_DIR/g-ts.vitest-filter.json"

gate_head
mkdir -p "$TRANSCRIPT_DIR"

gate_need "verifiers/ts/node_modules present" -- test -d "$TS_DIR/node_modules"
gate_need "GATE_PY available" -- test -x "$GATE_PY"

gate_run "vitest run (whole suite)" -- \
  npx --prefix "$TS_DIR" vitest run --root "$TS_DIR" \
    --reporter=default --reporter=json --outputFile.json="$JSON_OUT"
gate_expect_rc 0 "vitest run exits 0"

gate_need "vitest wrote its JSON report" -- test -s "$JSON_OUT"

RAN="$(mktemp)"
FOUND="$(mktemp)"
cleanup() { rm -f "$RAN" "$FOUND" "${FILTER_RAN:-}" "${EXPECT_ONE:-}" 2>/dev/null || true; }
trap cleanup EXIT

"$GATE_PY" -c "
import json
with open('$JSON_OUT') as fh:
    report = json.load(fh)
for result in report.get('testResults', []):
    print(result['name'])
" | sort -u > "$RAN"

ls "$TS_DIR"/test/*.test.ts 2>/dev/null | sort -u > "$FOUND"

gate_expect_nonempty "$FOUND" "there is at least one *.test.ts file on disk"
gate_expect_nonempty "$RAN" "vitest reports having run at least one test file"
gate_expect_same_set "$RAN" "$FOUND" \
  "files vitest's JSON report names == files 'ls test/*.test.ts' finds now"

# Negative control: filtering to a single file must run EXACTLY that file, not "exit 0 and
# who knows what ran" (D-G1b) — the assertion is on the reported set, not just the exit code.
gate_run "vitest run --root ... test/messages.test.ts (filter narrows the run)" -- \
  npx --prefix "$TS_DIR" vitest run --root "$TS_DIR" test/messages.test.ts \
    --reporter=default --reporter=json --outputFile.json="$FILTER_JSON"
gate_expect_rc 0 "filtered run exits 0"
gate_need "vitest wrote the filtered JSON report" -- test -s "$FILTER_JSON"

FILTER_RAN="$(mktemp)"
EXPECT_ONE="$(mktemp)"
"$GATE_PY" -c "
import json
with open('$FILTER_JSON') as fh:
    report = json.load(fh)
for result in report.get('testResults', []):
    print(result['name'])
" | sort -u > "$FILTER_RAN"
printf '%s\n' "$TS_DIR/test/messages.test.ts" > "$EXPECT_ONE"
gate_expect_same_set "$FILTER_RAN" "$EXPECT_ONE" \
  "the filtered run executed exactly {test/messages.test.ts}, nothing more and nothing less"

gate_verdict "the vitest suite passes and executes exactly the *.test.ts files present on disk"
