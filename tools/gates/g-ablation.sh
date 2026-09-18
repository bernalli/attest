#!/usr/bin/env bash
# gate-order: 165
# gate-order-why: mutates production files under a journal; runs last so no other gate reads a tree it is mutating
# G-ABLATION — the ablation bench proves it measured: ledger, git, nonce.
#
# The ablation bench produces a count of survivors, and a count is worth what the
# bench's proof of having measured is worth. This gate runs that proof three ways:
# the bench of the bench (bench_ablate.py: a synthetic tree, a holder killed for
# real, and the tool's own meta-mutants); the self-test of ablate.py on this tree,
# which puts defects into production files and takes them out again; and a
# negative control that has to fail by name.
#
# The self-test runs pass `--tolerate-dirty tools/gates/transcripts`, and only that
# directory, because run-all.sh opens this gate's transcript there before the gate
# starts: without it the tree is dirty on entry and ablate.py refuses with 5. The
# directory is not ignored, it is compared: its lines of `git status` at the start
# of a run must be the same during and after it. And what git tracks under it must
# be transcripts, save its own .gitignore, and every line git status prints under it
# must name one (ablate.py's contract for a tolerated directory), which is why
# nothing this gate hands to ablate.py -- a spec, a launcher, a suite -- lives under
# it, and why the gate never reads a .log of that directory as data.
#
# The results files go to a scratch directory outside the tree: a file written next
# to a tracked spec would dirty the tree the next run checks. The gate is not wired
# into the workflows or into tools/verify-all.sh.
GATE_ID="G-ABLATION"
GATE_TREE="${GATE_TREE:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd))}"
# shellcheck source=./_lib.sh
source "$GATE_TREE/tools/gates/_lib.sh"

ABLATION="$GATE_TREE/tools/gates/ablation"
TOLERATED="tools/gates/transcripts"
TS_VITEST="$GATE_TREE/verifiers/ts/node_modules/.bin/vitest"

RESULTS="$(mktemp -d)"
PROBE_DIR=""
# Invoked indirectly, by the EXIT trap.
# shellcheck disable=SC2317
cleanup() {
  rm -rf "$RESULTS"
  if [ -n "$PROBE_DIR" ]; then rm -rf "$PROBE_DIR"; fi
}
trap cleanup EXIT

# The probe is the journal's own `_probe_exchange`, imported, not a copy: a copy would
# be an oracle restating the logic it has to vouch for. The name is private to
# journal.py and this gate calls it from outside the module; whoever renames it there
# renames it here.
#
# Only the journal's own refusal, `ExchangeUnavailable`, is read as an answer about
# the filesystem, and only that answer is a missing precondition (78). Anything else --
# journal.py that does not import, the private name renamed, an error the probe does
# not classify, a probe killed by a signal -- is red: read as 78, run-all.sh would
# list it as "did not measure" and still pass. An error the probe does not classify
# is red even when the environment caused it (a full disk): a false red, never a
# false 78.
#
# The limit: the gate takes the journal's word for which answer is which. A defect
# inside the journal's own classification still reads as a filesystem that cannot
# exchange, and exits 78: a wrong RENAME_EXCHANGE flag (the kernel answers EINVAL),
# an exchange that is never called (the files are not swapped), renameat2 looked up
# under a wrong name (not exported). tests/test_ablation_journal.py exercises the
# exchange itself, and on a filesystem that can exchange those defects turn it red;
# this gate does not tell them apart from a filesystem that cannot.
#
# It runs in a directory created directly under the tree, on the filesystem the
# journal will use, and the directory is removed before returning and again on exit.
# A leftover that holds files shows in `git status`, so the next run of ablate.py
# refuses with 5 and names it. An empty leftover does not show there, and ablate.py
# does not name it.
#
# Returns 0 when the journal's probe returned without refusing; 78 when the journal
# refused with `ExchangeUnavailable`, or no directory could be created under the tree;
# any other status when the probe broke in a way the journal does not classify.
exchange_probe() {
  local out rc
  # mktemp's own complaint is discarded, as gate_need discarded it: it names the tree
  # by its absolute path, and on stderr it would reach the committed transcript
  # without passing through gate_say, which replaces that path with a token.
  if ! PROBE_DIR="$(mktemp -d "$GATE_TREE/.ablation-probe-XXXXXX" 2>/dev/null)"; then
    PROBE_DIR=""
    gate_say "exchange probe: no directory could be created under the tree"
    return 78
  fi
  out="$("$GATE_PY" -B - "$ABLATION" "$PROBE_DIR" 2>&1 <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import journal

try:
    journal._probe_exchange(Path(sys.argv[2]))
except journal.ExchangeUnavailable as exc:
    print(exc)
    sys.exit(78)
PY
)"
  rc=$?
  rm -rf "$PROBE_DIR"
  PROBE_DIR=""
  if [ "$rc" -ne 0 ]; then
    gate_say "exchange probe answered with exit $rc:"
    gate_say "$out"
  fi
  return "$rc"
}

# Invoked indirectly, by gate_need through "$@".
# shellcheck disable=SC2317
results_dir_outside_tree() {
  local results tree
  [ -n "$RESULTS" ] && [ -d "$RESULTS" ] || return 1
  # Physical paths on both sides: a TMPDIR that reaches into the tree through a link
  # would otherwise pass a comparison of the two strings.
  results="$(cd "$RESULTS" 2>/dev/null && pwd -P)" || return 1
  tree="$(cd "$GATE_TREE" 2>/dev/null && pwd -P)" || return 1
  [ "$results" != "$tree" ] && [ "${results#"$tree"/}" = "$results" ]
}

gate_head

gate_need "python interpreter present" -- test -x "$GATE_PY"
gate_need "git present" -- git --version
gate_need "no stale ablation journal" -- test ! -d "$GATE_TREE/.ablation-in-flight"
probe_rc=0
exchange_probe || probe_rc=$?
if [ "$probe_rc" -ne 0 ] && [ "$probe_rc" -ne 78 ]; then
  gate_say "FAIL: the exchange probe broke (exit $probe_rc) instead of answering about the filesystem"
  _gate_failures=$((_gate_failures + 1))
  gate_verdict "the ablation bench proves it measured: ledger, git, nonce"
fi
gate_need "atomic exchange of two files on the tree's filesystem (journal._probe_exchange)" -- \
  test "$probe_rc" -eq 0
gate_need "a results directory outside the tree" -- results_dir_outside_tree

# The variable is removed, not trusted to be absent: set, it would turn this run into
# the narrowed one below, which does not print the bench's marker.
gate_run "bench of the bench" -- \
  env -u ABLATION_BENCH_META_ONLY "$GATE_PY" "$ABLATION/bench_ablate.py"
gate_expect_rc 0 "the bench and every meta-mutant hold"
gate_expect_marker 'ABLATION_BENCH cases=[1-9][0-9]* failures=0 meta_mutants=1[2-9] meta_died_elsewhere=0 applications_confirmed=[1-9]' \
  "the bench declares how much it measured"

# Anchored to the line: unanchored, `=2/2` would also match `=2/20`, and `not_applied=1`
# would match `not_applied=10`. The tolerated count is not pinned: it is 0 for the gate
# on its own and 1 under run-all.sh, whose transcript for this gate is untracked.
TOLERATED_LINE='^dirty tolerated: [0-9]+ line\(s\) under tools/gates/transcripts$'

gate_run "integration selftest on the real tree" -- \
  "$GATE_PY" "$ABLATION/ablate.py" "$ABLATION/selftest.json" \
  --tree "$GATE_TREE" --tolerate-dirty "$TOLERATED" --out "$RESULTS/selftest.json"
gate_expect_rc 0 "the selftest meets its expectations"
gate_expect_marker '^applications_confirmed=2/2$' "both mutations landed with their three traces"
gate_expect_marker '^expectations: 2 declared, 2 met,' "both expectations were measured and met"
gate_expect_marker "$TOLERATED_LINE" "the tolerated directory was read and declared"

# The absent-anchor row runs on its own: item 0 refuses an anchor that is not in the
# file, and this row exists to be one. --skip-preflight skips the checks of item 0
# that read the tree, the anchor among them; the schema and the checks against the
# tolerated directory still run.
gate_run "absent-anchor selftest on the real tree" -- \
  "$GATE_PY" "$ABLATION/ablate.py" "$ABLATION/selftest_st1.json" --skip-preflight \
  --tree "$GATE_TREE" --tolerate-dirty "$TOLERATED" --out "$RESULTS/selftest_st1.json"
gate_expect_rc 0 "the absent anchor reads as not applied"
gate_expect_marker '(^| )not_applied=1( |$)' "the row is counted as not applied"
gate_expect_marker '^applications_confirmed=0/1$' "nothing landed"
gate_expect_marker '^expectations: 1 declared, 1 met,' "its expectation was measured and met"
gate_expect_marker "$TOLERATED_LINE" "the tolerated directory was read and declared"

if [ -e "$TS_VITEST" ]; then
  gate_run "integration selftest on the real tree, vitest side" -- \
    "$GATE_PY" "$ABLATION/ablate.py" "$ABLATION/selftest-ts.json" \
    --tree "$GATE_TREE" --tolerate-dirty "$TOLERATED" --out "$RESULTS/selftest-ts.json"
  gate_expect_rc 0 "the vitest selftest meets its expectations"
  gate_expect_marker '^applications_confirmed=2/2$' "both mutations landed with their three traces"
  gate_expect_marker '^expectations: 2 declared, 2 met,' "both expectations were measured and met"
  gate_expect_marker "$TOLERATED_LINE" "the tolerated directory was read and declared"

  gate_run "absent-anchor selftest on the real tree, vitest side" -- \
    "$GATE_PY" "$ABLATION/ablate.py" "$ABLATION/selftest-ts_st1.json" --skip-preflight \
    --tree "$GATE_TREE" --tolerate-dirty "$TOLERATED" --out "$RESULTS/selftest-ts_st1.json"
  gate_expect_rc 0 "the absent anchor reads as not applied"
  gate_expect_marker '(^| )not_applied=1( |$)' "the row is counted as not applied"
  gate_expect_marker '^applications_confirmed=0/1$' "nothing landed"
  gate_expect_marker '^expectations: 1 declared, 1 met,' "its expectation was measured and met"
  gate_expect_marker "$TOLERATED_LINE" "the tolerated directory was read and declared"
else
  # Not 78: the Python side has been measured. The line stays visible.
  gate_say "ts selftest skipped: node_modules absent"
fi

# A copy of the tool whose mutation loop never runs, re-run through part A: the bench
# has to catch it by the case that names it, not merely exit non-zero.
gate_negative "a bench whose loop never runs is caught by name" --marker 'FAIL: A3' -- \
  env ABLATION_BENCH_META_ONLY=MB1-loop-skipped "$GATE_PY" "$ABLATION/bench_ablate.py"

gate_verdict "the ablation bench proves it measured: ledger, git, nonce"
