#!/usr/bin/env bash
# gate-order: none (a self-test, not a gate: run-all.sh does not collect it)
# Behavioural bench for the two pieces `_lib.sh` grew when T2 had to declare
# its staged CI reds: `gate_expect_staged_red` and `gate_divergence_signatures`.
#
# WHY A BENCH AND NOT A REVIEW OF THE CODE. A registration that says "this step
# is red on purpose" is the single most dangerous thing in a gate: it is an
# instruction to ignore a failure. The only evidence it is safe is that it still
# fails when it should, so every case below drives the REAL functions from
# `_lib.sh` and asserts on the failure counter they keep, positives and
# negatives alike. `gate_divergence_signatures` is called, never restated: an
# oracle that repeats the logic under test agrees with it by construction.
#
# The negatives are aimed at the PROPERTY, not the shape. Feeding malformed
# garbage would prove the parser; what is fed here is well-formed output that
# differs in the one respect the registration exists to notice -- a red that
# went green, a red carrying a different cause, a divergence on the in-range
# NEIGHBOUR of a pinned vector, and one of the four gone missing.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_ID="SELFTEST-staged-red"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

_bench_pass=0
_bench_fail=0

# check <case> <expected-new-failures> <command...>
# Runs one library call and asserts how many failures it ADDED to the counter.
check() {
  local case_name="$1" want="$2"; shift 2
  local before="$_gate_failures" got
  "$@" > /dev/null 2>&1
  got=$((_gate_failures - before))
  if [ "$got" -eq "$want" ]; then
    printf 'ok   %-58s (added %s failure(s), as expected)\n' "$case_name" "$got"
    _bench_pass=$((_bench_pass + 1))
  else
    printf 'FAIL %-58s (added %s, expected %s)\n' "$case_name" "$got" "$want"
    _bench_fail=$((_bench_fail + 1))
  fi
  _gate_failures="$before"
}

# --- gate_expect_staged_red -------------------------------------------------
GATE_RC=1
GATE_OUT='error: built manifest does not self-verify; check that --seed ...'
check "staged red, present and carrying its cause" 0 \
  gate_expect_staged_red 'built manifest does not self-verify' "T4b" "demo"

# The direction that a "more red is bad" expectation would miss entirely. A
# staged red that turns green is either the closing task having landed or the
# strict side having stopped refusing; both need a person, neither is a pass.
GATE_RC=0
GATE_OUT='everything fine'
check "staged red that went GREEN is a failure" 1 \
  gate_expect_staged_red 'built manifest does not self-verify' "T4b" "demo"

# THE CASE THAT DISCRIMINATES PROPERTY 3, and the reason the case above does
# not. Measured 2026-09-08: with the rc==0 branch of gate_expect_staged_red
# disabled, the bench above still scores 9/9 -- 'everything fine' carries no
# marker either, so the MARKER branch fires instead and adds the same one
# failure for a different reason, which a bench counting failures cannot see.
# Here the marker is PRESENT, so the green-direction branch is the only thing
# that can fail: original 10/10, mutant 9/10.
GATE_RC=0
GATE_OUT='error: built manifest does not self-verify; check that --seed ...'
check "green WITH the declared marker still present is a failure" 1 \
  gate_expect_staged_red 'built manifest does not self-verify' "T4b" "demo"

# Red for another reason wears the same exit code. Without the marker the
# registration would wave through an import error or a real regression.
GATE_RC=1
GATE_OUT='Traceback (most recent call last): ModuleNotFoundError: No module named "attest"'
check "red WITHOUT the declared cause is a failure" 1 \
  gate_expect_staged_red 'built manifest does not self-verify' "T4b" "demo"

# A red whose exit code differs but whose cause is the declared one still
# counts: the registration is about the cause, not about the number.
GATE_RC=2
GATE_OUT='error: built manifest does not self-verify; check that --seed ...'
check "staged red at a different non-zero exit code" 0 \
  gate_expect_staged_red 'built manifest does not self-verify' "T4b" "demo"

# --- gate_divergence_signatures + gate_expect_same_set ----------------------
DECLARED="$(mktemp)"
cat > "$DECLARED" <<'DECLARED_SET'
out-of-range/version-past-integer-boundary road=intake(library.attest) reference=malformed browser=accept
out-of-range/version-past-integer-boundary road=parseBundle reference=malformed browser=accept
out-of-range/version-past-negative-boundary road=intake(library.attest) reference=malformed browser=accept
out-of-range/version-past-negative-boundary road=parseBundle reference=malformed browser=accept
DECLARED_SET

# One divergence, in the shape the tool really prints it (three lines).
_divergence() {
  printf 'DIVERGENCE %s on outcome\n  reference importer: %s\n  browser %s: %s receipts=[01JB] issuers=[h.example]\n' \
    "$1" "$3" "$2" "$4"
}

_four_declared() {
  _divergence "out-of-range/version-past-integer-boundary"  "parseBundle"             "malformed" "accept"
  _divergence "out-of-range/version-past-integer-boundary"  "intake(library.attest)"  "malformed" "accept"
  _divergence "out-of-range/version-past-negative-boundary" "parseBundle"             "malformed" "accept"
  _divergence "out-of-range/version-past-negative-boundary" "intake(library.attest)"  "malformed" "accept"
}

_seen_file() {
  local f; f="$(mktemp)"
  gate_divergence_signatures "$1" > "$f"
  printf '%s' "$f"
}

SEEN="$(_seen_file "$(_four_declared)")"
check "the four declared divergences match" 0 \
  gate_expect_same_set "$SEEN" "$DECLARED" "set"
rm -f "$SEEN"

# THE CASE THE WHOLE PIN EXISTS FOR. `version-at-integer-boundary` is 2**53-1:
# inside the profile, accepted by both cores today, and its neighbour one unit
# away is pinned. A registration written by FAMILY ("out-of-range diverges")
# would swallow this; the count would even stay at four if one of the pinned
# vectors stopped diverging on the same run.
SEEN="$(_seen_file "$(_four_declared; _divergence 'out-of-range/version-at-integer-boundary' 'parseBundle' 'malformed' 'accept')")"
check "an in-range NEIGHBOUR diverging is a failure" 1 \
  gate_expect_same_set "$SEEN" "$DECLARED" "set"
rm -f "$SEEN"

# The other direction: the migration is over, or the strict side gave up.
SEEN="$(_seen_file "$(_divergence 'out-of-range/version-past-integer-boundary' 'parseBundle' 'malformed' 'accept')")"
check "three of the four gone missing is a failure" 1 \
  gate_expect_same_set "$SEEN" "$DECLARED" "set"
rm -f "$SEEN"

# Same vectors, same roads, importers swapped. "These two disagree" would hold;
# it is a different world, and the direction is in the signature to say so.
SEEN="$(_seen_file "$(
  _divergence 'out-of-range/version-past-integer-boundary'  'parseBundle'            'accept' 'malformed'
  _divergence 'out-of-range/version-past-integer-boundary'  'intake(library.attest)' 'accept' 'malformed'
  _divergence 'out-of-range/version-past-negative-boundary' 'parseBundle'            'accept' 'malformed'
  _divergence 'out-of-range/version-past-negative-boundary' 'intake(library.attest)' 'accept' 'malformed'
)")"
check "the same divergence in the OPPOSITE direction is a failure" 1 \
  gate_expect_same_set "$SEEN" "$DECLARED" "set"
rm -f "$SEEN"

# A run that produced nothing must not read as agreement: two empty sets
# coincide. `gate_expect_same_set` guards this, and it is asserted here because
# "the tool did not run" is the most likely way this gate goes quiet.
SEEN="$(_seen_file "no divergences at all")"
check "an empty observed set does not coincide with the declared one" 1 \
  gate_expect_same_set "$SEEN" "$DECLARED" "set"
rm -f "$SEEN" "$DECLARED"

printf '\n'
if [ "$_bench_fail" -eq 0 ]; then
  printf 'SELFTEST staged-red PASS %s/%s\n' "$_bench_pass" "$((_bench_pass + _bench_fail))"
  exit 0
fi
printf 'SELFTEST staged-red FAIL %s/%s\n' "$_bench_pass" "$((_bench_pass + _bench_fail))"
exit 1
