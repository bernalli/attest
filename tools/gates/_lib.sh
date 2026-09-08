# Shared contract for the gates under tools/gates/. Source it; do not run it.
#
# WHY THIS FILE EXISTS
#
# A gate used to be a cell in a table in a plan. A cell that says "-> red" costs
# one line and cannot fail, so the first time anyone executed those cells was a
# review: four rounds, and every round the design held while the gates fell. The
# gates are executables now. Sourcing this file buys three properties that the
# table could not have.
#
# 1. An exit status is never read through a pipe. `false | tail -1` exits 0, so a
#    watcher that observes a command THROUGH another command measures the
#    composition. gate_run keeps the real status.
#
# 2. A collection is asserted non-empty before anything is concluded from it. A
#    glob that does not expand leaves pytest without arguments; pytest without
#    arguments uses `testpaths` and exits 0 having collected the whole suite.
#    Measured on this tree: exit 0, and the WHOLE universe collected instead of
#    the segment. How many files that is is deliberately not written here: the
#    figure moved (118 -> 119) inside the very commit that added a test file, so
#    the number was false in the same diff that wrote it. The gates derive it;
#    see tools/gates/transcripts/g-py-cover.log for the count of any given run.
#    An empty set compares equal to an empty set, so a gate that skips this check
#    is green for absence.
#
# 3. A negative control asserts WHERE it fails, not just that it fails. Measured:
#    `conformance_runner.py --adapter false` exits 2 from the argument parser,
#    never reaching an adapter, and a script asserting only "exit != 0" calls
#    that a proof the gate can catch a failing adapter. A mutant that dies on the
#    schema proves schema validation, never the invariant behind it - so
#    gate_negative demands a marker that only the guarded path can emit.
#
# EXIT STATUS OF A GATE
#
#   0   the property holds
#   1   the property does not hold
#   78  a precondition is missing: the gate did not measure
#
# 78 is not a pass and not a failure of the property. The same script was green
# on an unbuilt environment and red on a built one, for the same reason and with
# the same text: without a distinct status "the transcript is on file" certifies
# some other system.

set -uo pipefail

GATE_ID="${GATE_ID:-unnamed}"
GATE_TREE="${GATE_TREE:-<tree>}"
GATE_PY="$GATE_TREE/.venv/bin/python"
_gate_failures=0

gate_say() { printf '%s\n' "$*"; }

gate_head() {
  gate_say "=== GATE $GATE_ID ==="
  gate_say "tree:  $GATE_TREE"
  gate_say "head:  $(git -C "$GATE_TREE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  gate_say "utc:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  gate_say ""
}

# gate_need <description> -- <command...>
# A precondition of the measurement, not the thing measured. Exits 78 when absent
# so that a missing environment can never be reported as either colour.
gate_need() {
  local desc="$1"; shift
  [ "${1:-}" = "--" ] && shift
  if "$@" >/dev/null 2>&1; then
    gate_say "precondition ok: $desc"
    return 0
  fi
  gate_say "PRECONDITION MISSING: $desc"
  gate_say "command: $*"
  gate_say "GATE $GATE_ID SKIPPED precondition=absent"
  exit 78
}

# gate_run <label> -- <command...>
# Runs without a pipe and publishes the real exit status in GATE_RC, the output
# in GATE_OUT. Never `cmd | tee`: the status would be tee's.
gate_run() {
  local label="$1"; shift
  [ "${1:-}" = "--" ] && shift
  gate_say "--- $label"
  gate_say "\$ $*"
  GATE_OUT="$("$@" 2>&1)"
  GATE_RC=$?
  printf '%s\n' "$GATE_OUT"
  gate_say "exit: $GATE_RC"
  return 0
}

# gate_expect_rc <expected> <label>
gate_expect_rc() {
  local want="$1" label="$2"
  if [ "$GATE_RC" -eq "$want" ]; then
    gate_say "ok: $label (exit $GATE_RC)"
  else
    gate_say "FAIL: $label — expected exit $want, observed $GATE_RC"
    _gate_failures=$((_gate_failures + 1))
  fi
}

# gate_expect_marker <regex> <label>
# The output must carry something only a completed measurement can print.
gate_expect_marker() {
  local re="$1" label="$2"
  # A here-string, never `printf ... | grep -q`. With `set -o pipefail` -- which
  # this file sets -- grep -q exits at the FIRST match and closes the pipe, printf
  # takes SIGPIPE, and the pipeline's status becomes 141: "marker absent" for a
  # marker that is present. It only bites when the output is long enough that
  # printf has not finished writing, and when the marker is near the TOP, so it
  # hides until a gate whose tool prints thousands of lines. Measured: G-VEC went
  # red on a negative whose marker sat on line 18 of ~1170.
  if grep -Eq -- "$re" <<< "$GATE_OUT"; then
    gate_say "ok: $label (marker /$re/ present)"
  else
    gate_say "FAIL: $label — marker /$re/ absent from output"
    _gate_failures=$((_gate_failures + 1))
  fi
}

# gate_expect_nonempty <file> <label>
# Guards the "green for absence" family: an empty collection satisfies almost any
# comparison you would make with it afterwards.
gate_expect_nonempty() {
  local f="$1" label="$2" n
  # `n=$(grep -c . "$f" || echo 0)` looks equivalent and is not: on an empty file
  # grep prints 0 AND exits 1, so the fallback also fires and n becomes the
  # two-line string "0\n0", which makes every later -gt/-eq an "integer
  # expression expected" error. Measured here after it inverted a verdict in a
  # caller where zero was the GOOD outcome. Assign first, default on failure.
  n=$(grep -c . "$f" 2>/dev/null) || n=0
  if [ "$n" -gt 0 ]; then
    gate_say "ok: $label ($n lines collected — derived, not written down)"
  else
    gate_say "FAIL: $label — collected nothing; nothing downstream of this can mean anything"
    _gate_failures=$((_gate_failures + 1))
  fi
}

# gate_expect_same_set <file-a> <file-b> <label>
# The invariant, never the figure: what the census names must equal what the
# collector actually reaches. Both sides are derived at runtime.
gate_expect_same_set() {
  local a="$1" b="$2" label="$3" diff_out side
  # Two empty sets coincide, and so do two unreadable ones: `sort` on a missing
  # path writes to stderr, which comm never sees, so a path typo in a gate reads
  # as "the two sets coincide". Measured on this library. The non-emptiness
  # property is the one the header claims, so it is enforced HERE rather than
  # left to the caller remembering a separate gate_expect_nonempty.
  for side in "$a" "$b"; do
    if [ ! -r "$side" ]; then
      gate_say "FAIL: $label — $side is not readable; an unreadable set coincides with anything"
      _gate_failures=$((_gate_failures + 1))
      return 0
    fi
  done
  if ! grep -q . "$a" && ! grep -q . "$b"; then
    gate_say "FAIL: $label — both sides are empty; an empty set compares equal to an empty set"
    _gate_failures=$((_gate_failures + 1))
    return 0
  fi
  diff_out=$(comm -3 <(sort -u "$a") <(sort -u "$b"))
  if [ -z "$diff_out" ]; then
    gate_say "ok: $label (the two sets coincide)"
  else
    gate_say "FAIL: $label — the two sets differ:"
    printf '%s\n' "$diff_out"
    _gate_failures=$((_gate_failures + 1))
  fi
}

# gate_negative <label> --marker <regex> -- <command...>
# A negative control must fail AFTER reaching the property it guards. The marker
# is how that is seen: without it, a command that dies in its own argument parser
# reports itself as proof that the guarded path can fail.
gate_negative() {
  local label="$1"; shift
  local re=""
  if [ "${1:-}" = "--marker" ]; then re="$2"; shift 2; fi
  [ "${1:-}" = "--" ] && shift
  gate_say "--- negative: $label"
  gate_say "\$ $*"
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "$out"
  gate_say "exit: $rc"
  if [ "$rc" -eq 0 ]; then
    gate_say "FAIL: negative '$label' did not fail — the gate cannot catch this defect"
    _gate_failures=$((_gate_failures + 1))
    return 0
  fi
  # Here-string, for the same reason as gate_expect_marker above: through a pipe,
  # pipefail turns an early grep -q match into 141 and reports the marker missing.
  if [ -n "$re" ] && ! grep -Eq -- "$re" <<< "$out"; then
    gate_say "FAIL: negative '$label' failed BEFORE reaching the guarded path"
    gate_say "      (marker /$re/ absent: this proves the argument/schema layer, not the property)"
    _gate_failures=$((_gate_failures + 1))
    return 0
  fi
  gate_say "ok: negative '$label' failed at the guarded path (exit $rc)"
}

gate_verdict() {
  local property="$1"
  gate_say ""
  if [ "$_gate_failures" -eq 0 ]; then
    gate_say "GATE $GATE_ID PASS property=$property"
    exit 0
  fi
  gate_say "GATE $GATE_ID FAIL property=$property failures=$_gate_failures"
  exit 1
}
