#!/usr/bin/env bash
# gate-order: 130
# G-COMPARE: the property is "compare_runs.py sees a change that junit XML
# cannot see, never reports a comparison it did not perform, and names the
# node ID at the point where it fails" (F-05).
#
# Junit control, measured once and recorded rather than re-asserted here (a
# shell gate proving an XML *format* limitation on every run would be
# testing the format, not this tool): a `passed` testcase and an `xpassed`
# testcase serialize to byte-identical `<testcase .../>` elements (no child,
# no distinguishing attribute) once the timestamp is normalized away. See
# the front's report for the two files side by side. That is why this
# comparator reads a report-log instead.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_ID="G-COMPARE"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

gate_head

PLUGIN_DIR="$GATE_TREE/tools/gates"
COMPARE="$GATE_TREE/tools/gates/compare_runs.py"

gate_need "python present" -- test -x "$GATE_PY"
gate_need "pytest importable" -- "$GATE_PY" -c "import pytest"
# pytest-reportlog is not installed in this tree (measured at the start of
# this front: `pytest --help | grep report-log` finds nothing). The local
# plugin below is the channel this gate actually exercises; if IT stops
# being importable, the gate has no channel to measure through and must say
# so rather than silently falling back to nothing.
gate_need "local report-log channel importable" -- env PYTHONPATH="$PLUGIN_DIR" "$GATE_PY" -c "import reportlog_plugin"
gate_need "compare_runs.py present" -- test -f "$COMPARE"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# run_pytest <test-file> <out-jsonl>
# Runs one pytest invocation through the local report-log plugin. The exit
# status of pytest itself is not the signal here (a failing or an
# empty-collection run both write a legitimate, if different-shaped,
# report-log) -- gate_run/gate_negative below read the OUTPUT of
# compare_runs.py, not of this helper.
run_pytest() {
  local test_target="$1" out="$2"
  GATE_REPORTLOG_PATH="$out" PYTHONPATH="$PLUGIN_DIR" "$GATE_PY" -m pytest \
    -q -p reportlog_plugin -p no:cacheprovider "$test_target" >/dev/null 2>&1
}

compare() {
  "$GATE_PY" "$COMPARE" "$1" "$2"
}

# --- fixture: flip -- the prescribed proof of closure ------------------
# The node ID must be IDENTICAL across the two runs for a comparison to
# happen at all, so this is the same file path, overwritten in place
# between the two pytest invocations -- not two files with two node IDs.
# Same node ID, same body, the only difference is the xfail(strict=False)
# marker on the "after" side. The assertion stays true, so pytest calls it
# xpassed, not failed.
mkdir -p "$WORK/flip"
cat >"$WORK/flip/test_flip.py" <<'EOF'
def test_thing():
    assert True
EOF
run_pytest "$WORK/flip/test_flip.py" "$WORK/flip.base.jsonl"
cat >"$WORK/flip/test_flip.py" <<'EOF'
import pytest


@pytest.mark.xfail(strict=False)
def test_thing():
    assert True
EOF
run_pytest "$WORK/flip/test_flip.py" "$WORK/flip.after.jsonl"
gate_expect_nonempty "$WORK/flip.base.jsonl" "flip: baseline run produced report-log lines"
gate_expect_nonempty "$WORK/flip.after.jsonl" "flip: after run produced report-log lines"

gate_run "property: passed -> xpassed is visible" -- compare "$WORK/flip.base.jsonl" "$WORK/flip.after.jsonl"
gate_expect_rc 1 "flip: a passed->xpassed change is a gate failure"
gate_expect_marker 'test_flip\.py::test_thing: passed -> xpassed' "flip: changed entry names both outcomes"

# --- fixture: vanish -- a test disappears between baseline and after ----
mkdir -p "$WORK/vanish"
cat >"$WORK/vanish/test_vanish.py" <<'EOF'
def test_a():
    assert True


def test_b():
    assert True
EOF
run_pytest "$WORK/vanish/test_vanish.py" "$WORK/vanish.base.jsonl"
cat >"$WORK/vanish/test_vanish.py" <<'EOF'
def test_a():
    assert True
EOF
run_pytest "$WORK/vanish/test_vanish.py" "$WORK/vanish.after.jsonl"
gate_expect_nonempty "$WORK/vanish.base.jsonl" "vanish: baseline run produced report-log lines"
gate_expect_nonempty "$WORK/vanish.after.jsonl" "vanish: after run produced report-log lines"

gate_negative "vanished test id is named, and fails the gate" \
  --marker 'test_vanish\.py::test_b' \
  -- compare "$WORK/vanish.base.jsonl" "$WORK/vanish.after.jsonl"

# --- fixture: new -- a test appears; that alone must NOT fail the gate --
mkdir -p "$WORK/new"
cat >"$WORK/new/test_new.py" <<'EOF'
def test_a():
    assert True
EOF
run_pytest "$WORK/new/test_new.py" "$WORK/new.base.jsonl"
cat >"$WORK/new/test_new.py" <<'EOF'
def test_a():
    assert True


def test_c():
    assert True
EOF
run_pytest "$WORK/new/test_new.py" "$WORK/new.after.jsonl"
gate_expect_nonempty "$WORK/new.base.jsonl" "new: baseline run produced report-log lines"
gate_expect_nonempty "$WORK/new.after.jsonl" "new: after run produced report-log lines"

gate_run "property: a new test alone does not fail the gate" -- compare "$WORK/new.base.jsonl" "$WORK/new.after.jsonl"
gate_expect_rc 0 "new: only an after-only addition, no vanished/changed test"
gate_expect_marker 'test_new\.py::test_c' "new: the new node id is recorded in after-only"

# --- fixture: worse -- an outcome regresses, passed -> failed -----------
mkdir -p "$WORK/worse"
cat >"$WORK/worse/test_worse.py" <<'EOF'
def test_thing():
    assert True
EOF
run_pytest "$WORK/worse/test_worse.py" "$WORK/worse.base.jsonl"
cat >"$WORK/worse/test_worse.py" <<'EOF'
def test_thing():
    assert False
EOF
run_pytest "$WORK/worse/test_worse.py" "$WORK/worse.after.jsonl"
gate_expect_nonempty "$WORK/worse.base.jsonl" "worse: baseline run produced report-log lines"
gate_expect_nonempty "$WORK/worse.after.jsonl" "worse: after run produced report-log lines"

gate_negative "outcome regression is named, and fails the gate" \
  --marker 'test_worse\.py::test_thing: passed -> failed' \
  -- compare "$WORK/worse.base.jsonl" "$WORK/worse.after.jsonl"

# --- fixture: empty -- nothing collected on either side -----------------
# An empty directory: pytest collects zero tests, so the plugin's output
# file is opened and never written to. Two empty sets compare equal to each
# other for free; that must NOT read as a pass.
mkdir -p "$WORK/empty"
run_pytest "$WORK/empty" "$WORK/empty.base.jsonl"
run_pytest "$WORK/empty" "$WORK/empty.after.jsonl"

gate_negative "an empty comparison is a failure, not a pass by absence" \
  --marker 'compared 0 node id' \
  -- compare "$WORK/empty.base.jsonl" "$WORK/empty.after.jsonl"

gate_verdict "compare_runs.py classifies xfail/xpass through report-log and never passes on an empty comparison"
