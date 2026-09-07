#!/usr/bin/env bash
# G-TS-B: verifiers/ts/dist is built from the current verifiers/ts/src.
#
# Plan reference: docs/plans/2026-09-08-trust-material-serialized-entry.md, §7.0 row G-TS-B.
# Runs FIRST among the TS gates (P-32): everything downstream (G-TS-TC-F6's shape does not
# depend on dist, but G-PY-BW, G-SITE, G-DESK do) reads dist as it stands on disk, so a stale
# dist would let all of them describe code from hours before HEAD (C-209).
GATE_ID="G-TS-B"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

TS_DIR="$GATE_TREE/verifiers/ts"
DIST_ENTRY="$TS_DIR/dist/index.js"

gate_head

gate_need "verifiers/ts/node_modules present" -- test -d "$TS_DIR/node_modules"
gate_need "npm available" -- command -v npm

gate_run "npm run build" -- npm --prefix "$TS_DIR" run build
gate_expect_rc 0 "npm run build exits 0"

gate_need "dist/index.js exists after the build" -- test -f "$DIST_ENTRY"

STALE_LIST="$(mktemp)"
trap 'rm -f "$STALE_LIST"' EXIT
find "$TS_DIR/src" -name '*.ts' -newer "$DIST_ENTRY" > "$STALE_LIST"
# NOTE: not `grep -c . "$f" || echo 0` — on an empty/no-match file that idiom emits BOTH
# grep's own "0" and the fallback "0" (grep -c exits 1 on zero matches, so `||` fires too),
# giving a two-line count that breaks `-eq`/`-gt` with "integer expression expected". Measured
# live while building this gate: it is the same construct `_lib.sh`'s own gate_expect_nonempty
# uses, and there it happens to still fail-safe (a malformed `-gt 0` comparison evaluates
# false, which is the correct branch for "nothing collected") — but here 0 stale files is the
# GOOD outcome, so the same bug would flip this gate's verdict. `wc -l` does not have the
# double-output failure mode.
STALE_COUNT=$(wc -l < "$STALE_LIST")
gate_say "sources newer than dist/index.js (derived with find -newer, not written down): $STALE_COUNT"
if [ "$STALE_COUNT" -eq 0 ]; then
  gate_say "ok: no source in verifiers/ts/src is newer than dist/index.js"
else
  gate_say "FAIL: dist is stale relative to src — the following sources are newer than dist/index.js:"
  cat "$STALE_LIST"
  _gate_failures=$((_gate_failures + 1))
fi

gate_say ""
gate_say "sha256sum of dist/*.js (for the transcript, so a later gate can tell which build it read):"
sha256sum "$TS_DIR"/dist/*.js

gate_verdict "verifiers/ts/dist/*.js is not older than any file in verifiers/ts/src"
