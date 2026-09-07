#!/usr/bin/env bash
# G-TS-TC: the typecheck of verifiers/ts/src passes AND covers exactly the sources on disk.
#
# Plan reference: docs/plans/2026-09-08-trust-material-serialized-entry.md, §7.0 row G-TS-TC.
# The plan's original text pinned the coverage to "21 file (tsconfig.json:16)" — a count that
# is stale the moment a file is added to src. This gate derives both sides at runtime instead
# (tsc --listFilesOnly vs find) and compares the SETS, never a number written down (D20/NV-11).
#
# This gate covers ONLY verifiers/ts/src, by design (tsconfig.json's "include" says so, and
# P-26 in the plan is explicit that the test-file typecheck is a separate gate, G-TS-TC-F6).
GATE_ID="G-TS-TC"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

TS_DIR="$GATE_TREE/verifiers/ts"
TSCONFIG="$TS_DIR/tsconfig.json"

gate_head

gate_need "verifiers/ts/node_modules present" -- test -d "$TS_DIR/node_modules"
gate_need "verifiers/ts/tsconfig.json present" -- test -f "$TSCONFIG"

gate_run "tsc --noEmit -p tsconfig.json" -- \
  npx --prefix "$TS_DIR" tsc --noEmit -p "$TSCONFIG"
gate_expect_rc 0 "typecheck of verifiers/ts/src exits 0"

LISTED="$(mktemp)"
FOUND="$(mktemp)"
NEG_DIR="$(mktemp -d)"
cleanup() { rm -f "$LISTED" "$FOUND"; rm -rf "$NEG_DIR"; }
trap cleanup EXIT

# Side A: what tsc says it read, filtered to files under verifiers/ts/src (--listFilesOnly also
# lists lib.*.d.ts and node_modules/@types — those are not part of the property being checked).
npx --prefix "$TS_DIR" tsc --noEmit -p "$TSCONFIG" --listFilesOnly 2>/dev/null \
  | grep -F "/verifiers/ts/src/" | sort -u > "$LISTED"
# Side B: what exists on disk right now.
find "$TS_DIR/src" -name '*.ts' | sort -u > "$FOUND"

gate_expect_nonempty "$FOUND" "verifiers/ts/src has at least one .ts file to typecheck"
gate_expect_same_set "$LISTED" "$FOUND" \
  "files tsc --listFilesOnly reports under src == files find(src -name '*.ts') finds now"

# Negative control: inject a real type error into an OUT-OF-TREE copy of verifiers/ts and
# typecheck the copy. The worktree itself is never touched — D-G1c/D-G1b: the failure must
# come from the guarded path (a type error tsc actually resolves), not from an argument or
# schema layer, so the marker is a real TSxxxx diagnostic.
cp -a "$TS_DIR" "$NEG_DIR/ts"
printf '\nexport const __gate_injected_type_error: number = "not-a-number";\n' \
  >> "$NEG_DIR/ts/src/b64u.ts"
gate_negative "type error injected into an out-of-tree copy of verifiers/ts/src" \
  --marker 'error TS[0-9]+' -- \
  npx --prefix "$NEG_DIR/ts" tsc --noEmit -p "$NEG_DIR/ts/tsconfig.json"

gate_verdict "verifiers/ts/src typechecks clean, and tsc reads exactly the .ts files find(src) finds now"
