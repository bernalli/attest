#!/usr/bin/env bash
# G-LINT: lint, formatting and types pass on the whole tree, and mypy actually
# read the sources it claims to have checked.
#
# Four commands, four exit statuses, never concatenated with `&&`: chaining
# them would collapse "which of the four failed" into a single bit.
#
# mypy's own success line ("Success: no issues found in N source files") is
# the only place N is printed — the plan text once pinned it to 52, which is
# exactly the number this script would go stale against at the next merge
# that adds or removes a file. N is never written down here: it is compared,
# at run time, to `find src bridge/src witness/src -name '*.py' | wc -l`.
GATE_ID="G-LINT"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

RUFF="$GATE_TREE/.venv/bin/ruff"
MYPY="$GATE_TREE/.venv/bin/mypy"
MYPY_ROOTS=("$GATE_TREE/src" "$GATE_TREE/bridge/src" "$GATE_TREE/witness/src")

gate_head

gate_need "ruff present in .venv" -- test -x "$RUFF"
gate_need "mypy present in .venv" -- test -x "$MYPY"
gate_need "check_spec_docs.py present" -- test -f "$GATE_TREE/tools/check_spec_docs.py"

gate_run "ruff check" -- "$RUFF" check "$GATE_TREE"
gate_expect_rc 0 "ruff check: no findings on the tree"

gate_run "ruff format --check" -- "$RUFF" format --check "$GATE_TREE"
gate_expect_rc 0 "ruff format --check: nothing left to reformat"

gate_run "mypy --strict" -- "$MYPY" --strict "${MYPY_ROOTS[@]}"
gate_expect_rc 0 "mypy --strict: no findings"

# Derive, right now, how many source files mypy was obligated to have read.
# This is the "collection could be empty" guard from the family that made
# `--check` on an unbuilt corpus green for absence elsewhere in this repo:
# an empty MYPY_ROOTS would make the marker below trivially true.
FOUND_PY="$(mktemp)"
find "${MYPY_ROOTS[@]}" -name '*.py' | sort -u > "$FOUND_PY"
N_FOUND="$(grep -c . "$FOUND_PY")"
rm -f "$FOUND_PY"
gate_say "sources on disk under src/bridge/witness right now: $N_FOUND"

gate_expect_marker 'Success: no issues found in [0-9]+ source files' \
  "mypy prints how many source files it read"

MYPY_OUT_FOR_COUNT="$GATE_OUT"
MYPY_N="$(printf '%s\n' "$MYPY_OUT_FOR_COUNT" \
  | grep -Eo 'Success: no issues found in [0-9]+ source files' \
  | grep -Eo '[0-9]+')"

if [ -z "$MYPY_N" ]; then
  gate_say "FAIL: mypy's own source-file count could not be extracted from its output"
  gate_run "unresolved mypy count (forces a failure)" -- false
  gate_expect_rc 0 "mypy source-file count was extractable"
else
  gate_say "mypy reports it read $MYPY_N source files; find(src/bridge/witness) finds $N_FOUND now"
  gate_run "mypy read count ($MYPY_N) is not less than the derived count ($N_FOUND)" -- \
    bash -c "[ '$MYPY_N' -ge '$N_FOUND' ]"
  gate_expect_rc 0 "mypy did not silently skip sources that exist on disk"
fi

gate_run "check_spec_docs.py" -- "$GATE_TREE/.venv/bin/python" "$GATE_TREE/tools/check_spec_docs.py"
gate_expect_rc 0 "check_spec_docs.py: no drift between spec prose and its cross-references"

# --- negative control -------------------------------------------------------
# The mutant must die on the TYPE CHECK, not on an import the copy cannot
# resolve (that would prove mypy can fail on a missing module, never that it
# catches a real type error — D-G1b). One real source file, copied to a
# directory outside the worktree, with one line appended that mypy --strict
# cannot accept. Confirmed by hand before writing this script: mypy reports
# exactly one error, at the appended line, with no import noise.
#
# --no-incremental is not optional here, and it earned its way in by being
# measured wrong first: mypy caches by module name plus content hash, and a
# module named "injected" with byte-identical injected content across two
# DIFFERENT ephemeral tmp dirs is a cache HIT — the second run printed the
# error at the FIRST run's path, a directory already deleted, with no
# indication that it had reused anything. The diagnostic text still matched
# the marker (so this could pass unnoticed), but the run it named as evidence
# had not actually happened. --no-incremental was verified by hand to make
# every run name its own real path.
NEG_DIR="$(mktemp -d)"
cleanup() { rm -rf "$NEG_DIR"; }
trap cleanup EXIT

SEED_FILE="$(find "${MYPY_ROOTS[@]}" -name '*.py' | sort -u | head -n1)"
cp "$SEED_FILE" "$NEG_DIR/injected.py"
printf '\nx: int = "a"  # gate_negative: type error injected on purpose\n' >> "$NEG_DIR/injected.py"

gate_negative "mypy --strict against a copy of $(basename "$SEED_FILE") with an injected type error" \
  --marker 'error: Incompatible types' -- \
  "$MYPY" --strict --no-incremental "$NEG_DIR/injected.py"

gate_verdict "ruff check, ruff format --check, mypy --strict and check_spec_docs.py all pass, and mypy measured at least as many files as exist on disk"
