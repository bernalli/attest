#!/usr/bin/env bash
# gate-order: 70
# G-VEC: the vectors committed under docs/spec/vectors are exactly what
# gen_vectors.py produces — byte for byte, not "close enough".
#
# `gen_vectors.py --check` prints NOTHING on success (only `generate()`'s
# non-check path prints a leaf count, and only drift prints anything at all).
# An exit-0-with-no-output measurement is exactly the "green for absence"
# shape this file's gate_expect_nonempty exists for: a `--check` run against
# an empty corpus would ALSO exit 0 with nothing printed, having compared
# nothing against nothing. So before trusting the exit code, this gate
# derives — from the tree on disk, not from a number written down anywhere —
# how many committed vector leaves (directories containing expected.json)
# there are to compare, and asserts that set is non-empty.
GATE_ID="G-VEC"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

GEN_VECTORS="$GATE_TREE/tools/gen_vectors.py"
VECTORS_DIR="$GATE_TREE/docs/spec/vectors"

gate_head

gate_need "gen_vectors.py present" -- test -f "$GEN_VECTORS"
gate_need "docs/spec/vectors present" -- test -d "$VECTORS_DIR"

LEAVES="$(mktemp)"
find "$VECTORS_DIR" -name 'expected.json' | sort -u > "$LEAVES"
gate_expect_nonempty "$LEAVES" \
  "docs/spec/vectors has at least one committed leaf (a directory with expected.json) to compare"
N_LEAVES="$(grep -c . "$LEAVES")"
rm -f "$LEAVES"
gate_say "committed vector leaves found on disk right now: $N_LEAVES"
gate_say "(gen_vectors.py --check prints this number for NEITHER outcome — its only output is on drift; the leaf count above is the sole evidence, derived from the tree, that a nonempty corpus exists for --check to have compared)"

gate_run "gen_vectors.py --check" -- "$GATE_TREE/.venv/bin/python" "$GEN_VECTORS" --check
gate_expect_rc 0 "gen_vectors.py --check: no drift from the committed tree"

# --- negative control -------------------------------------------------------
# --check against an EMPTY directory still walks the real drift-detection
# path (committed == {} is compared against a freshly generated full tree),
# never the "directory does not exist" early return — confirmed by hand:
# check() only takes that branch when `out` is missing or a symlink, and
# mktemp -d always creates a real, existing directory. So this negative fails
# at the same comparison the positive path exercises, not before it (D-G1b).
NEG_DIR="$(mktemp -d)"
cleanup() { rm -rf "$NEG_DIR"; }
trap cleanup EXIT

gate_negative "gen_vectors.py --check --out <empty directory>" \
  --marker 'vector drift under' -- \
  "$GATE_TREE/.venv/bin/python" "$GEN_VECTORS" --check --out "$NEG_DIR"

gate_verdict "docs/spec/vectors matches gen_vectors.py's output byte for byte, over a nonempty corpus"
