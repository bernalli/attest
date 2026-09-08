#!/usr/bin/env bash
# gate-order: 76
# gate-order-why: the manifest half of the cross-core differential, after the store half
# G-XCORE-MANIFEST: the two KEY MANIFEST boundaries answer the same on the same bytes.
#
# The second of two gates over one engine (see g-xcore-store.sh for why the
# engine is shared and the verdict is not).
#
# WHAT THIS SURFACE COMPARES, AND WHY IT EXISTS
# `duplicate_kids` returns the kids appearing on more than one `keys[]` entry,
# and `verify()` renders that list into an error a caller reads. Python sorted
# it by CODE POINT and the TypeScript twin by UTF-16 CODE UNIT, so the two cores
# answered the SAME manifest with the list in opposite orders -- measured
# end-to-end through `verify()` on both cores, from a real conformance vector
# mutated in its kids alone.
#
# Nothing caught it. The conformance vector for that case asserts the substring
# "duplicate kid", which does not include the list; and a unit test in either
# language would have used that language's own sort as its oracle, which is
# precisely the blindness that let the same defect live on the store surface.
# A differential is the only instrument that sees this class, because it
# compares the two cores instead of comparing each with itself.
#
# The input stays the DOCUMENT: `parseKeyManifest(bytes).data()` is what both
# cores derive the entries from. Comparing two `duplicate_kids` calls assembled
# separately would look like the same measurement and be a weaker one -- the
# same family as an oracle that calls the function under test.
#
# The manifest boundary has NO grammar (plan section 5.3), so most documents are
# admitted here that the store surface refuses. That is the contract, not a
# divergence, which is why the two surfaces are never compared against each
# other.
GATE_ID="G-XCORE-MANIFEST"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

DIFFERENTIAL="$GATE_TREE/tools/trust_material_differential.py"
ADAPTER="$GATE_TREE/tools/trust_material_adapter_ts.mjs"
DIST="$GATE_TREE/verifiers/ts/dist/trustMaterial.js"
MANIFESTS_DIST="$GATE_TREE/verifiers/ts/dist/manifests.js"

gate_head

gate_need "python present" -- test -x "$GATE_PY"
gate_need "node present" -- command -v node
gate_need "the differential runner is present" -- test -f "$DIFFERENTIAL"
gate_need "the TypeScript adapter is present" -- test -f "$ADAPTER"
gate_need "verifiers/ts/dist is built (npm run build)" -- test -f "$DIST"
# This surface reaches `duplicateKids`, which lives in a different built module
# than the boundary: naming it separately means a partial build is a precondition
# failure rather than a mysterious import error inside the adapter.
gate_need "verifiers/ts/dist/manifests.js is built" -- test -f "$MANIFESTS_DIST"
gate_need "the differential's Python dependencies (pytest, hypothesis) are importable" -- \
  "$GATE_PY" -c "import pytest, hypothesis"

gate_run "trust_material_differential.py --surface manifest" -- \
  "$GATE_PY" "$DIFFERENTIAL" --surface manifest
gate_expect_rc 0 "the two key-manifest boundaries agree on every document of the corpus"
gate_expect_marker '^surface: manifest$' \
  "the runner names the surface it measured, so a verdict cannot be read against the wrong one"
gate_expect_marker '^documents fed to both cores: [0-9]+$' \
  "the runner says how many documents it fed, not only that it exited 0"
gate_expect_marker '^of which admitted by the Python core: [1-9][0-9]*$' \
  "the corpus admits something: a comparison over refusals alone proves nothing"

# Per-surface negative control. Reusing the store surface's injection here would
# fire on a path THIS gate does not watch, and the gate would look proven while
# being blind -- the defect class this differential exists to catch, applied to
# the differential. This one perturbs the duplicate-kid order, on the adapter.
gate_negative "a duplicate-kid order divergence is caught" \
  --marker 'duplicate kids differ' \
  -- env TM_DIFF_INJECT=dupkids-reversed "$GATE_PY" "$DIFFERENTIAL" --surface manifest

gate_verdict "the two key-manifest boundaries answer alike on the same bytes"
