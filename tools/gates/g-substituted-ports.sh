#!/usr/bin/env bash
# gate-order: 77
# gate-order-why: reads the test tree only; independent of build and of the suites
# G-SUBST: every test that SUBSTITUTES a trust-material port still measures it.
#
# THE DEFECT THIS EXISTS FOR, AND WHY NOTHING ELSE CATCHES IT
#
# A test that replaces a port with a stand-in measures the stand-in. When the
# code under test stops calling the PUBLIC door and starts calling its private
# twin — which is exactly what T2 did — the stand-in is never invoked, and the
# test keeps passing. It did not fail. It went SILENT, and a silent test is
# indistinguishable from a passing one by every other gate in this directory.
#
# Measured on this tree: `tests/test_views.py` substituted
# `manifests.manifest_signature_is_authentic` to prove the preflight consults
# it; after the flip `views.py` reached the private twin, the stand-in stopped
# being called, and the test stayed green.
#
# HOW IT MEASURES, RATHER THAN INSPECTS
#
# For every file that carries the FORM, the file is run once with
# `substituted_ports_plugin.py`, which wraps every watched port in a counter
# that delegates to the real function and records which substituted names the
# code under test actually REACHES. A substituted name reached ZERO times is
# the defect: whatever the stand-in was for, it is filed at an address nobody
# visits.
#
# The first version of this gate neutralized the substitution and required the
# file to go red. That measures one half of the family — a stand-in that
# REPLACES a behaviour — and produces a FALSE POSITIVE on the other half: a
# sentinel that proves a NON-event (a function that raises if ever called)
# changes nothing when removed, by construction, so the file stays green and
# the gate accuses code that is fine. Measured on `tests/test_authority.py`.
# Counting asks the question both halves share, and it is the one that
# matters: is the name the test chose the name the code calls?
#
# Negative control, executed: aiming that file's sentinel back at the PUBLIC
# door — the state before this task fixed it — leaves the suite GREEN at 206
# passed and makes this gate print `UNREACHED`. That is the whole point of its
# existence: the defect is invisible to the suite and visible here.
#
# THE POPULATION IS DERIVED, NOT INHERITED
#
# The set of files is found by searching the FORM (`setattr` naming a port)
# across the whole test tree, right now — not by taking the "predicted red set"
# of another gate, and not from a list written next to this script. A control
# whose perimeter is another control's output inherits its blind spots: a file
# that substitutes a port and does nothing else satisfies none of the red-set
# criteria, so it would never be looked at. And the gate FAILS CLOSED on a form
# it cannot classify.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_TREE="${GATE_TREE:-<tree>}"
GATE_ID="G-SUBST"
export GATE_ID GATE_TREE

# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

gate_head

GATE_PY="${GATE_PY:-$GATE_TREE/.venv/bin/python}"
gate_need ".venv/bin/python exists" -- test -x "$GATE_PY"
gate_need "import pytest" -- "$GATE_PY" -c "import pytest"
gate_need "the neutralizing plugin imports" -- \
  env PYTHONPATH="$GATE_TREE" "$GATE_PY" -c "import tools.gates.substituted_ports_plugin"

# The port names come from the plugin, so the search and the neutralization
# cannot disagree about what a port is. Two copies of a list are two lists.
PORTS="$(env PYTHONPATH="$GATE_TREE" "$GATE_PY" -c \
  "from tools.gates.substituted_ports_plugin import PORT_NAMES; print('|'.join(sorted(PORT_NAMES)))")"
if [ -z "$PORTS" ]; then
  gate_say "PRECONDITION MISSING: the plugin exposes no port names"
  gate_say "GATE $GATE_ID SKIPPED precondition=no-ports"
  exit 78
fi
gate_say "ports watched: $(tr '|' ' ' <<< "$PORTS" | wc -w)"

# --- Derive the population, now ------------------------------------------
FOUND="$(mktemp)"
grep -rlnE "setattr\(([^)]*\b(${PORTS})\b|\"[^\"]*\.(${PORTS})\")" \
  "$GATE_TREE/tests" "$GATE_TREE/bridge/tests" "$GATE_TREE/witness/tests" \
  --include='*.py' 2>/dev/null | sort -u > "$FOUND"
gate_expect_nonempty "$FOUND" "at least one port substitution exists to measure"

gate_say ""
gate_say "files carrying the form:"
while read -r f; do gate_say "  ${f#"$GATE_TREE"/}"; done < "$FOUND"
gate_say ""

# --- Measure each one ------------------------------------------------------
while read -r file; do
  rel="${file#"$GATE_TREE"/}"

  gate_run "reachability: $rel" -- \
    env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$GATE_TREE" "$GATE_PY" -m pytest \
      -p no:cacheprovider -p tools.gates.substituted_ports_plugin -q "$file"
  RUN_OUT="$GATE_OUT"

  # The plugin says whether it intercepted anything. If it intercepted NOTHING
  # while the search found the form, the two disagree — the search matched
  # something the plugin does not recognise as a substitution — and that is a
  # gap in the gate itself, not a verdict about the file. Fail closed.
  if grep -Eq -- "NO substitution was intercepted" <<< "$RUN_OUT"; then
    gate_say "FAIL: $rel carries the form but the plugin intercepted no substitution"
    gate_say "      (the search and the counter disagree: classify the form or widen the plugin)"
    _gate_failures=$((_gate_failures + 1))
    continue
  fi

  if grep -Eq -- "^  UNREACHED: " <<< "$RUN_OUT"; then
    gate_say "FAIL: $rel substitutes a port the code under test never reaches"
    grep -E -- "^  UNREACHED: " <<< "$RUN_OUT" | while read -r line; do gate_say "      $line"; done
    gate_say "      A stand-in filed at an address nobody visits measures nothing. Point it at"
    gate_say "      the name the code actually calls, or delete it."
    _gate_failures=$((_gate_failures + 1))
  else
    gate_say "ok: $rel substitutes only ports the code under test reaches"
  fi
done < "$FOUND"

rm -f "$FOUND"

gate_verdict "every test that substitutes a trust-material port still measures it"
