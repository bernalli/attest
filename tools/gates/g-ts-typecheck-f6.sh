#!/usr/bin/env bash
# gate-order: 160
# gate-order-why: last: its object is whatever the phase touched
# G-TS-TC-F6: the test files THIS PHASE touched typecheck cleanly, and their
# `// @ts-expect-error` directives are actually verified (they are not, under vitest/esbuild —
# C-215: the TS test suite has no typecheck of its own in this repo).
#
# Plan reference: docs/plans/2026-09-08-trust-material-serialized-entry.md, §7.0 row
# G-TS-TC-F6, and P-27 (the exact tsc invocation, measured 2026-09-07). The plan's original
# text pinned the file list per phase by name ("a T1 trust-material-parse.test.ts e
# helpers/trust.ts"; "da T3 anche index-surface.test.ts"). That list is exactly the kind of
# thing that goes stale the moment a phase's plan changes shape — so here it is DERIVED from
# the tree instead: the test files this phase has touched are whatever
# `git diff --name-only -- verifiers/ts/test` and
# `git ls-files --others --exclude-standard -- verifiers/ts/test` return RIGHT NOW, plus
# whatever paths are passed as arguments to this script (for helper files a test imports,
# which the two git commands above will not surface on their own).
#
# NOTE for whoever reads this back into the plan: `git diff` with no ref compares the working
# tree against the INDEX, i.e. unstaged changes only. A test file already `git add`-ed (staged
# but not committed) will not show up here unless it is also passed as an argument. This is a
# literal implementation of the derivation as specified; if a phase stages before running this
# gate, that gap is real and worth deciding on explicitly rather than silently trusting `git
# diff --cached` to have been meant.
#
# A phase that has not touched any TS test file (T0) has nothing for this gate to measure: it
# exits 78, not 0. A gate that reports green for an empty object measures nothing (D-G1c).
GATE_ID="G-TS-TC-F6"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

TS_DIR="$GATE_TREE/verifiers/ts"
TYPE_ROOTS="$TS_DIR/node_modules/@types"
# The pathspec this gate derives from, written ONCE. A guard that re-spells the path is
# asserting a DIFFERENT object from the one the derivation reads, so it cannot tell a
# healthy empty set from a broken derivation. Measured with the path spelled separately
# in the guard: the one-word typo in the `git diff` pathspec below still produced output
# byte-identical to a healthy T0, and the gate printed "the pathspec exists and is
# populated" about a path it was no longer reading.
TS_TEST_PATHSPEC="verifiers/ts/test"

gate_head

gate_need "verifiers/ts/node_modules present" -- test -d "$TS_DIR/node_modules"
gate_need "verifiers/ts/node_modules/@types present" -- test -d "$TYPE_ROOTS"
gate_need "git available on GATE_TREE" -- git -C "$GATE_TREE" rev-parse --is-inside-work-tree

mapfile -t _diffed < <(git -C "$GATE_TREE" diff --name-only -- "$TS_TEST_PATHSPEC")
mapfile -t _untracked < <(git -C "$GATE_TREE" ls-files --others --exclude-standard -- "$TS_TEST_PATHSPEC")
_extra_args=("$@")

declare -A _seen
FILES=()
for f in "${_diffed[@]}" "${_untracked[@]}" "${_extra_args[@]}"; do
  [ -z "$f" ] && continue
  case "$f" in
    /*) abs="$f" ;;
    *)  abs="$GATE_TREE/$f" ;;
  esac
  if [ -z "${_seen[$abs]:-}" ]; then
    _seen[$abs]=1
    FILES+=("$abs")
  fi
done

gate_say "test files in scope for this phase (diff + untracked + script args), derived now: ${#FILES[@]}"
for f in "${FILES[@]}"; do gate_say "  $f"; done
gate_say ""

if [ "${#FILES[@]}" -eq 0 ]; then
  # "No object" and "the derivation is broken" both produce an empty set, and
  # without this check they produce the SAME text and the SAME 78 — measured: a
  # single-character typo in the pathspec below yields output byte-identical to
  # a healthy T0. One reads as "nothing to do here yet" and resolves itself; the
  # other never becomes green and nobody is told. So the derivation's own input
  # is asserted before its empty output is believed (D-G1b applied to the 78).
  if [ ! -d "$GATE_TREE/$TS_TEST_PATHSPEC" ]; then
    gate_say "PRECONDITION MISSING: $TS_TEST_PATHSPEC is not a directory — the pathspec this gate derives from does not exist, so its empty result says nothing about the phase"
    gate_say "GATE $GATE_ID SKIPPED precondition=absent"
    exit 78
  fi
  if ! compgen -G "$GATE_TREE/$TS_TEST_PATHSPEC/*.test.ts" > /dev/null; then
    gate_say "PRECONDITION MISSING: $TS_TEST_PATHSPEC holds no *.test.ts — there is nothing this gate could ever derive"
    gate_say "GATE $GATE_ID SKIPPED precondition=absent"
    exit 78
  fi
  gate_say "NO TS TEST FILE TOUCHED IN THIS PHASE — there is no object for this gate to measure"
  gate_say "(the pathspec $TS_TEST_PATHSPEC exists and is populated, so this empty set is the phase's, not the derivation's)"
  gate_say "GATE $GATE_ID SKIPPED precondition=no-object"
  exit 78
fi

for f in "${FILES[@]}"; do
  gate_need "in-scope file exists: $f" -- test -f "$f"
done

# P-27, verbatim: tsc at explicit files typechecks a test file. --typeRoots is load-bearing —
# without it the run fails with TS2688 ("node" not found) before reaching any real diagnostic.
gate_run "tsc --noEmit on this phase's test files (P-27)" -- \
  npx --prefix "$TS_DIR" tsc --noEmit --strict --target ES2022 --module ESNext \
    --moduleResolution Bundler --skipLibCheck --types node \
    --typeRoots "$TYPE_ROOTS" --noUncheckedIndexedAccess --exactOptionalPropertyTypes \
    "${FILES[@]}"
gate_expect_rc 0 "typecheck of this phase's test files exits 0"
if [ -z "$GATE_OUT" ]; then
  gate_say "ok: no diagnostics printed — the // @ts-expect-error directives in scope were verified"
else
  gate_say "FAIL: expected empty output (no diagnostics), got the output shown above"
  _gate_failures=$((_gate_failures + 1))
fi

# Negative control (P-27, executable today regardless of phase): the same command shape,
# pointed at verifiers/ts/test/verify-unit.test.ts, which carries the pre-existing C-215 type
# errors. It must fail AFTER reaching the guarded path (a real tsc diagnostic), not before.
gate_negative "verify-unit.test.ts carries pre-existing type errors (C-215)" \
  --marker 'error TS[0-9]+' -- \
  npx --prefix "$TS_DIR" tsc --noEmit --strict --target ES2022 --module ESNext \
    --moduleResolution Bundler --skipLibCheck --types node \
    --typeRoots "$TYPE_ROOTS" --noUncheckedIndexedAccess --exactOptionalPropertyTypes \
    "$TS_DIR/test/verify-unit.test.ts"

gate_verdict "the TS test files this phase touched typecheck cleanly under P-27, // @ts-expect-error included"
