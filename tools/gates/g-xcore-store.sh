#!/usr/bin/env bash
# gate-order: 75
# gate-order-why: after g-ts-build (it reads dist/) and after g-vec
# G-XCORE-STORE: the two TRUST STORE boundaries answer the same on the same bytes.
#
# One of two gates over one engine. `tools/trust_material_differential.py` is
# shared -- adapter, comparison, declared-divergence handling -- because two
# copies of the same comparison are two comparisons destined to disagree. The
# GATE is per surface, so that a red names the surface that gave way: a gate
# measuring two things says "red" without saying which, and that is how a gate
# stops being read. Share what must not diverge, separate what must stay
# legible.
#
# The property is not "the two cores say the same words" -- that is what
# tests/fixtures/trust-material-messages.json already pins, and pinning only
# that is what let a real divergence live: `issuers()` listed the same store in
# opposite orders in the two cores while both suites were green, because each
# suite used its own language's default sort as its oracle and so agreed with
# itself.
#
# Compared: admitted or refused, the refusal class, the member blamed, the
# issuer order. NOT the refusal text -- section 5.4 declares that M7 and M8
# carry the parser's own diagnostic and that the two cores need not word those
# alike, and a comparison reporting known-acceptable noise trains its reader to
# skip it.
#
# Two things this gate refuses to be green for:
#   * an empty or all-refused corpus: the runner prints how many documents it
#     fed and how many the Python core ADMITTED, and exits non-zero if nothing
#     was admitted, because a corpus nothing survives compares nothing;
#   * a declared divergence that stopped happening: the runner asserts each one
#     is STILL observed, so an allow-list cannot go quiet the day the thing it
#     excuses disappears.
GATE_ID="G-XCORE-STORE"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

DIFFERENTIAL="$GATE_TREE/tools/trust_material_differential.py"
ADAPTER="$GATE_TREE/tools/trust_material_adapter_ts.mjs"
DIST="$GATE_TREE/verifiers/ts/dist/trustMaterial.js"

gate_head

gate_need "python present" -- test -x "$GATE_PY"
gate_need "node present" -- command -v node
gate_need "the differential runner is present" -- test -f "$DIFFERENTIAL"
gate_need "the TypeScript adapter is present" -- test -f "$ADAPTER"
# dist/ and not src/: this measures what npm publishes. Without the build there
# is nothing to compare against, and that is a precondition failure (78), not a
# red -- a gate that could not measure is neither green nor broken.
gate_need "verifiers/ts/dist is built (npm run build)" -- test -f "$DIST"
# The differential imports `tests.test_trust_material_parse` for its corpus, and
# that module imports pytest and hypothesis at module level. Without the dev
# extras installed the import raises ModuleNotFoundError, the differential exits
# 1, and `gate_expect_rc 0` below would read that as "the two cores disagree" --
# a FAIL where the honest answer is 78. This repo has already met that exact
# shape once, from `uv sync` run without `--all-extras`.
gate_need "the differential's Python dependencies (pytest, hypothesis) are importable" -- \
  "$GATE_PY" -c "import pytest, hypothesis"

gate_run "trust_material_differential.py --surface store" -- \
  "$GATE_PY" "$DIFFERENTIAL" --surface store
gate_expect_rc 0 "the two trust-store boundaries agree on every document of the corpus"
gate_expect_marker '^surface: store$' \
  "the runner names the surface it measured, so a verdict cannot be read against the wrong one"
gate_expect_marker '^documents fed to both cores: [0-9]+$' \
  "the runner says how many documents it fed, not only that it exited 0"
gate_expect_marker '^of which admitted by the Python core: [1-9][0-9]*$' \
  "the corpus admits something: a comparison over refusals alone proves nothing"

# The negative control is PER SURFACE, and that is not tidiness: one injection
# covering two surfaces can be blind on one of them and green anyway, which is
# this differential's own defect class applied to the instrument built to find
# it. This one perturbs the issuer order, on the MEASURING side -- the adapter --
# so it proves the comparator sees an order divergence without touching a line
# of what ships. It is the exact shape of the defect that reached this repo.
gate_negative "an issuer order divergence is caught" \
  --marker 'issuers differ' \
  -- env TM_DIFF_INJECT=issuers-reversed "$GATE_PY" "$DIFFERENTIAL" --surface store

gate_verdict "the two trust-store boundaries answer alike on the same bytes"
