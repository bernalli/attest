#!/usr/bin/env bash
# gate-order: 80
# gate-order-why: the TS conformance adapter needs dist
# G-CI-PY: the conformance and differential tools run, and their counts are > 0.
#
# Five commands from ci.yml:python and ci.yml:supply-chain, each with its own
# precondition checked right before it (not bundled at the top): a partial
# environment then still yields real measurements for the steps it supports,
# and a clean 78 — never a noisy FAIL — for the one step it does not, instead
# of collapsing "which precondition is missing" into one bit the way a single
# top-of-script gate_need block would.
#
# THE CENTRAL FINDING OF THIS GATE (measured 2026-09-07): the plan's negative
# control was `--adapter false` -> red. Measured: exit 2,
# "error: --adapter template must contain the {leaf} placeholder" — the
# argument parser rejects the template before any adapter runs, before any
# leaf is attempted, before the property this gate exists to guard is ever
# reached. A script asserting only "exit != 0" would call THAT a proof the
# gate catches a failing adapter; it proves nothing past the parser. The
# negative actually used here is `--adapter 'false {leaf}'`: a template that
# passes the placeholder check and then fails on every leaf, so the failure
# comes from 224 real, attempted, failed leaves — confirmed by hand before
# writing this script (see the report for the exact text observed).
GATE_ID="G-CI-PY"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

CORPUS_TOOL="$GATE_TREE/tools/gen_container_corpus.py"
CORPUS_DIR="$GATE_TREE/tests/container-corpus"
IMPORTER_DIFF="$GATE_TREE/tools/importer_differential.py"
CONF_RUNNER="$GATE_TREE/tools/conformance_runner.py"
TS_DIST="$GATE_TREE/verifiers/ts/dist/index.js"
ESBUILD="$GATE_TREE/site/node_modules/.bin/esbuild"

gate_head

gate_need "python present in .venv" -- test -x "$GATE_PY"
gate_need "'import attest' resolves" -- "$GATE_PY" -c "import attest"
gate_need "gen_container_corpus.py present" -- test -f "$CORPUS_TOOL"
gate_need "importer_differential.py present" -- test -f "$IMPORTER_DIFF"
gate_need "conformance_runner.py present" -- test -f "$CONF_RUNNER"

# --- 1. gen_container_corpus.py --check ------------------------------------
# Same shape as G-VEC's gen_vectors.py --check: nothing is printed on
# success, so an empty corpus would also be silently green. Derive the leaf
# count from disk before trusting the exit code.
CORPUS_FILES="$(mktemp)"
find "$CORPUS_DIR" -type f | sort -u > "$CORPUS_FILES"
gate_expect_nonempty "$CORPUS_FILES" \
  "tests/container-corpus has at least one committed file to compare"
rm -f "$CORPUS_FILES"

gate_run "gen_container_corpus.py --check" -- "$GATE_PY" "$CORPUS_TOOL" --check
gate_expect_rc 0 "gen_container_corpus.py --check: no drift from the committed corpus"

# --- 2 & 3. the two demo scripts --------------------------------------------
# Both resolve `demo.*` and `attest` off sys.path[0]/cwd (verified by hand:
# the same import fails from a directory other than the repo root), which is
# exactly why this uses env+PYTHONPATH and never `cd` inside a compound
# command.
#
# The two demos drive the real CLI end to end, so they were red for as long as
# `cli.py` handed a `dict` to a port that answers only to a parsed handle. T4b
# migrated the CLI and the staged registration that lived here is deleted with
# it -- kept past its cause, it would have gone on excusing a red the CLI
# earned later.
#
# The control below OUTLIVES the registration, and its meaning inverts with it:
# it used to prove the demos' red was the port refusing a type rather than a
# broken manifest, and it now pins that the port still refuses that type at
# all. Both directions are asserted, so this is the one place in the gate where
# a regression to the pre-T2 permissiveness shows up as itself rather than as
# some downstream verdict.
gate_run "the port refuses a live dict and admits the same document as a handle (D-A3)" -- \
  env PYTHONPATH="$GATE_TREE" "$GATE_PY" -c '
from attest import canon, keys, manifests, trust_material
kp = keys.from_seed(bytes(range(32)))
entry = manifests.key_entry("k1", kp.pub, "2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
built = manifests.build_key_manifest("h.example", 1, "2026-01-01T00:00:00Z", [entry], kp, "k1")
handle = trust_material.KeyManifest.from_bytes(canon.canonical_bytes(built))
as_dict = manifests.verify_key_manifest(built)
as_handle = manifests.verify_key_manifest(handle)
print("verify_key_manifest(dict, what cli.py used to hand it) ->", as_dict)
print("verify_key_manifest(handle, same document)             ->", as_handle)
raise SystemExit(0 if as_dict is False and as_handle is True else 1)
'
gate_expect_rc 0 \
  "the boundary still holds in both directions: dict refused, same document admitted as a handle"

gate_run "python -m demo.store_dies" -- \
  env PYTHONPATH="$GATE_TREE" "$GATE_PY" -m demo.store_dies
gate_expect_rc 0 "demo.store_dies: runs green through the migrated CLI"

gate_run "python -m demo.pledge_dies" -- \
  env PYTHONPATH="$GATE_TREE" "$GATE_PY" -m demo.pledge_dies
gate_expect_rc 0 "demo.pledge_dies: runs green through the migrated CLI"

# --- 4. conformance_runner.py, TS adapter, v0.2 subset ----------------------
gate_need "node present (conformance TS adapter)" -- command -v node
gate_need "verifiers/ts/dist/index.js present (conformance TS adapter)" -- test -f "$TS_DIST"

gate_run "conformance_runner.py --adapter <ts> --subset v0.2" -- \
  "$GATE_PY" "$CONF_RUNNER" \
  --adapter "node $GATE_TREE/tools/conformance_adapter_ts.mjs {leaf}" --subset v0.2
gate_expect_rc 0 "conformance_runner.py: CONFORMANT against the TS adapter"
gate_expect_marker '^CONFORMANT \(v0\.2\): [0-9]+/[0-9]+ leaves pass' \
  "conformance_runner.py prints how many leaves it ran, not just that it exited 0"

CONF_PASS_TOTAL="$(printf '%s\n' "$GATE_OUT" \
  | grep -Eo '^CONFORMANT \(v0\.2\): [0-9]+/[0-9]+ leaves pass' \
  | grep -Eo '[0-9]+/[0-9]+' | head -n1)"
CONF_PASS="${CONF_PASS_TOTAL%%/*}"
gate_say "conformance_runner.py (TS adapter): $CONF_PASS_TOTAL leaves pass"
if [ -z "$CONF_PASS" ]; then
  gate_run "conformance_runner.py leaf count was extractable" -- false
  gate_expect_rc 0 "conformance_runner.py leaf count was extractable"
else
  gate_run "conformance_runner.py leaves-passed count ($CONF_PASS) is > 0" -- \
    bash -c "[ '$CONF_PASS' -gt 0 ]"
  gate_expect_rc 0 "conformance_runner.py ran and passed at least one real leaf"
fi

# Negative control, WRONG form first (kept here as the documented false
# start, not as a passing assertion): the plan's prescribed negative.
gate_say "--- documenting the plan's prescribed negative BEFORE using the real one"
gate_run "conformance_runner.py --adapter false (the plan's original negative)" -- \
  "$GATE_PY" "$CONF_RUNNER" --adapter false --subset v0.2
gate_say "^ exit $GATE_RC: this dies in argparse (--adapter must contain {leaf}), never reaching an adapter or a leaf — asserting only \"exit != 0\" here would be exactly the F-06 defect (D-G1b)"

# Negative control, RIGHT form: a template that passes the placeholder check
# and then fails on every leaf — the failure comes from the guarded path.
gate_negative "conformance_runner.py --adapter 'false {leaf}' --subset v0.2 (adapter runs, fails on every leaf)" \
  --marker 'NOT CONFORMANT \(v0\.2\): 0/[0-9]+ leaves pass' -- \
  "$GATE_PY" "$CONF_RUNNER" --adapter 'false {leaf}' --subset v0.2

# --- 5. importer_differential.py --------------------------------------------
# PRECONDITION NOT ANTICIPATED BY THE PLAN (measured 2026-09-07): the plan's
# precondition list for this gate named only python/attest/node/dist/index.js.
# importer_differential.py in fact bundles the browser importer with the
# SITE's own esbuild (site/node_modules/.bin/esbuild) — the same binary
# container_differential.py needs unconditionally. Neither tool has an
# alternative path. At the moment this gate was written, this checkout did
# not have `npm ci --prefix site` run, and this gate never runs it itself —
# that write falls outside tools/gates/, which this gate is not permitted to
# touch, regardless of whether the binary happens to be present when it runs.
# Where the precondition is absent, this is a clean 78 (a fact about the
# environment, never a false PASS or a noisy FAIL on the property itself —
# D-G1c), not a workaround.
gate_need "site/node_modules/.bin/esbuild present (importer_differential's browser bundle)" \
  -- test -x "$ESBUILD"

# The staged red that lived here until B2 is deleted, and what it was staging
# is worth keeping in view: between T2 and now, recipe B1 canonicalized the
# store document on the Python side while the browser side did not, so a
# `manifest_version` of 2**53 failed the whole import on one road and landed
# quietly on the other. B2 in `site/src/bundle.ts` closed it; the four
# divergences are gone and the registration goes with them.
#
# What replaces it must not be `rc 0` on its own, and MEASURED (2026-09-08) it
# must not be the divergence line either: `importer_differential.py --families ''`
# prints "0 divergences across 0 families" and exits 0 having compared nothing.
# That line is also definitionally equal to the exit code -- run() returns 1 iff
# a non-advisory divergence exists, and the count printed IS that number -- so
# asserting both says one thing twice. It is kept below only as evidence that
# report() was reached at all, which is the little it proves.
#
# The measurement is the block after the archive count: every road the tool
# tallies must be present, and each must have answered for exactly as many
# archives as were fed. An empty comparison has no tally lines and fails the
# set; a road that quietly answered for fewer archives fails the sum. Both
# were verified against a doctored transcript before this was written.
gate_run "importer_differential.py" -- "$GATE_PY" "$IMPORTER_DIFF"
gate_expect_rc 0 "importer_differential.py: the two importers agree on every archive"
gate_expect_marker '^0 divergences across 0 families' \
  "importer_differential.py reached its report (this restates the exit code; it does not measure)"
gate_expect_marker '^[0-9]+ archives fed to both importers at their own defaults' \
  "importer_differential.py prints how many archives it fed both importers, not just that it exited 0"

# GATE_OUT belongs to the LAST gate_run, and every assertion below runs one --
# including the `> 0` comparison a few lines down, whose output is empty. Read
# through GATE_OUT after that point and the census reads an empty transcript,
# which is green for absence. Measured while writing this block: the tally check
# passed on nothing and only the set comparison caught it. Capture once, here.
IMPORTER_OUT="$GATE_OUT"

IMPORTER_ARCHIVES="$(printf '%s\n' "$IMPORTER_OUT" \
  | grep -Eo '^[0-9]+ archives fed to both importers at their own defaults' \
  | grep -Eo '^[0-9]+' | head -n1)"
gate_say "importer_differential.py: $IMPORTER_ARCHIVES archives fed to both importers"
if [ -z "$IMPORTER_ARCHIVES" ]; then
  gate_run "importer_differential.py archive count was extractable" -- false
  gate_expect_rc 0 "importer_differential.py archive count was extractable"
else
  gate_run "importer_differential.py archive count ($IMPORTER_ARCHIVES) is > 0" -- \
    bash -c "[ '$IMPORTER_ARCHIVES' -gt 0 ]"
  gate_expect_rc 0 "importer_differential.py fed at least one real archive to both importers"
fi

# The census the deleted registration used to carry, in the only form still
# available now that the declared set is empty: the roads are pinned BY NAME,
# and each is required to have answered for every archive fed. "> 0" alone
# cannot tell 462 archives from 1, and an agreement reached over one archive is
# not the property this step exists to assert.
SIDES_SEEN="$(mktemp)"
SIDES_DECLARED="$(mktemp)"
printf '%s\n' "$IMPORTER_OUT" | awk '
  /^[0-9]+ archives fed to both importers/ { inblock = 1; next }
  /^[0-9]+ divergences across [0-9]+ families/ { inblock = 0 }
  inblock && /^  [^:]+: [a-z-]+=[0-9]+/ { line = $0; sub(/: .*$/, "", line); sub(/^  /, "", line); print line }
' | sort -u > "$SIDES_SEEN"
printf 'browser intake\nbrowser parseBundle\nreference importer\n' > "$SIDES_DECLARED"
gate_expect_same_set "$SIDES_SEEN" "$SIDES_DECLARED" \
  "every road the tool tallies answered on this run, none missing and none new"
rm -f "$SIDES_SEEN" "$SIDES_DECLARED"

TALLY_BAD="$(mktemp)"
printf '%s\n' "$IMPORTER_OUT" | awk -v want="$IMPORTER_ARCHIVES" '
  /^[0-9]+ archives fed to both importers/ { inblock = 1; next }
  /^[0-9]+ divergences across [0-9]+ families/ { inblock = 0 }
  inblock && /^  [^:]+: [a-z-]+=[0-9]+/ {
    line = $0; sub(/^  [^:]+: /, "", line)
    n = split(line, parts, ", "); sum = 0
    for (i = 1; i <= n; i++) { split(parts[i], kv, "="); sum += kv[2] }
    if (sum != want) printf "%s sums to %d, not %d\n", $0, sum, want
  }' > "$TALLY_BAD"
[ -s "$TALLY_BAD" ] && gate_say "$(cat "$TALLY_BAD")"
gate_run "every road answered for all $IMPORTER_ARCHIVES archives" -- test ! -s "$TALLY_BAD"
gate_expect_rc 0 "each road tallied exactly as many outcomes as archives fed"
rm -f "$TALLY_BAD"

gate_verdict "gen_container_corpus, both demo scripts, conformance_runner (TS, v0.2) and importer_differential all run, every road answered for every archive, and the leaf/archive counts are > 0"
