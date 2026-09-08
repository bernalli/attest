#!/usr/bin/env bash
# gate-order: 75
# gate-order-why: after g-ts-build (it reads dist/) and after g-vec
# G-XCORE: the two trust-material boundaries answer the SAME on the same bytes.
#
# The property is not "the two cores say the same words" -- that is what
# tests/fixtures/trust-material-messages.json already pins, and pinning only
# that is what let a real divergence live: `issuers()` listed the same store in
# opposite orders in the two cores while both suites were green, because each
# suite used its own language's default sort as its oracle and so agreed with
# itself.
#
# The property here is the OBSERVABLE ANSWER: admitted or refused, the refusal
# class, the member blamed, and the issuer order. The refusal TEXT is not
# compared -- section 5.4 declares that M7 and M8 carry the parser's own
# diagnostic and that the two cores need not word those alike -- because a
# comparison that reports known-acceptable noise trains its reader to skip it.
#
# Two things this gate refuses to be green for:
#   * an empty or all-refused corpus: the runner prints how many documents it
#     fed and how many the Python core ADMITTED, and exits non-zero if nothing
#     was admitted, because a corpus nothing survives compares nothing;
#   * a declared divergence that stopped happening: the runner asserts each one
#     is STILL observed, so an allow-list cannot go quiet the day the thing it
#     excuses disappears.
GATE_ID="G-XCORE"
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

gate_run "trust_material_differential.py" -- "$GATE_PY" "$DIFFERENTIAL"
gate_expect_rc 0 "the two cores agree on every document of the corpus"
gate_expect_marker '^documents fed to both cores: [0-9]+$' \
  "the runner says how many documents it fed, not only that it exited 0"
gate_expect_marker '^of which admitted by the Python core: [1-9][0-9]*$' \
  "the corpus admits something: a comparison over refusals alone proves nothing"

# The negative control mutates the MEASURING side -- the adapter reverses the
# issuer list it reports -- so it proves the comparator can see an order
# divergence without touching a line of what ships. This is the exact shape of
# the defect that reached this repo, so it is the one that must be caught.
gate_negative "an issuer order divergence is caught" \
  --marker 'issuers differ' \
  -- env TM_DIFF_INJECT=issuers-reversed "$GATE_PY" "$DIFFERENTIAL"

gate_verdict "the two trust-material boundaries answer alike on the same bytes"
