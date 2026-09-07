#!/usr/bin/env bash
# G-PLAN-CODE — the plan's normative Python survives the repository's own linters.
#
# The plan hands the executor blocks to transcribe verbatim. One of them declared
# `__slots__` unsorted, which this repo's ruff configuration rejects (RUF023), so
# a faithful transcription would have turned G-LINT red inside T1 — a defect
# authored by the plan and discovered by the task, which is the ordering this
# whole front exists to invert. Found by running G-LINT over the probe that
# transcribes that block, not by reading the block.
#
# DO NOT ADD A FORMAT CHECK HERE. It is easy, it looks like an improvement, and it
# was tried: `ruff format --check` flags four of the five normative blocks (re-measured
# against this repo's own pyproject.toml: blocks at plan lines 455, 493, 520 and 564;
# 449 is already formatted), because a block written to stay readable in prose is not a
# block written by the formatter.
#
# The reason those four are tolerable is NOT that "the repository formats on commit":
# this repository has no .pre-commit-config.yaml and no commit hook that formats
# (core.hooksPath points at a leak scanner). What reformats a transcription is the
# editing harness's own post-write hook, which fires on a file WRITE and not on a
# `cat >` heredoc — so an executor that writes the file some other way will meet
# `ruff format --check` red inside the task. That failure costs one `ruff format` run,
# which is why the trade is still worth taking; a lint RULE is the thing no formatter
# fixes, and it is what this gate checks. Adding them
# would make this gate four parts noise to one part signal, and a gate that is
# mostly noise is a gate people learn to skim; at that point it stops protecting
# even the one line that mattered. What the executor genuinely cannot see coming is
# a lint RULE, which no formatter fixes. That is what this gate checks, and only that.
GATE_ID="G-PLAN-CODE"
GATE_TREE="${GATE_TREE:-<tree>}"
source "$GATE_TREE/tools/gates/_lib.sh"

CHECKER="$GATE_TREE/tools/gates/plan_code.py"
PLAN="$GATE_TREE/docs/plans/2026-09-08-trust-material-serialized-entry.md"

gate_head

gate_need "python interpreter present" -- test -x "$GATE_PY"
gate_need "ruff present" -- test -x "$GATE_TREE/.venv/bin/ruff"
gate_need "plan present" -- test -f "$PLAN"
gate_need "extractor present" -- test -f "$CHECKER"

gate_run "lint every normative python block" -- "$GATE_PY" "$CHECKER"
gate_expect_rc 0 "no normative block violates a lint rule the executor cannot see coming"
gate_expect_marker 'PLAN_CODE_CLEAN' "the checker reached its verdict"
# Green for absence: an extractor whose regex stopped matching would find no block,
# and no block trivially satisfies "every block is clean".
gate_expect_marker 'extracted [1-9][0-9]* normative python block' "blocks were actually extracted"

# --- negative: put the real defect back, on a copy.
# The observable is RUF023 named in the output -- not a non-zero exit, which a
# missing file or a broken regex would also produce while saying nothing about
# whether the linter ever looked at the block.
NEG_PLAN="$(mktemp -d)/plan-with-defect.md"
trap 'rm -rf "$(dirname "$NEG_PLAN")"' EXIT
"$GATE_PY" - "$PLAN" "$NEG_PLAN" <<'PY'
import sys
from pathlib import Path

source, target = Path(sys.argv[1]), Path(sys.argv[2])
text = source.read_text(encoding="utf-8")
sorted_slots = '__slots__ = ("_canonical", "_data")'
if sorted_slots not in text:
    raise SystemExit("the block this negative mutates is no longer in the plan")
# Exactly the defect the gate was born from: the same names, unsorted.
target.write_text(
    text.replace(sorted_slots, '__slots__ = ("_data", "_canonical")', 1),
    encoding="utf-8",
)
PY

gate_negative "an unsorted __slots__ in a normative block is caught" \
  --marker 'RUF023' \
  -- env PLAN_CODE_PLAN="$NEG_PLAN" "$GATE_PY" "$CHECKER"

# --- negative: a fence in a language nobody checks must stop the gate by name.
# C-222: a guard that recognises a SPELLING is blind to whoever reaches the object
# some other way. Matching only ```python would silently skip a block written
# ```py, and the gate would report a clean plan while nobody had looked at it. The
# observable is the language named in the output, not the exit code.
NEG_FENCE="$(dirname "$NEG_PLAN")/plan-unknown-fence.md"
{ cat "$PLAN"; printf '\n```ruby\nputs 1\n```\n'; } > "$NEG_FENCE"

gate_negative "a fence in an unchecked language is named" \
  --marker "unrecognised language \\('ruby'\\)" \
  -- env PLAN_CODE_PLAN="$NEG_FENCE" "$GATE_PY" "$CHECKER"

gate_verdict "every python block the executor transcribes verbatim passes the repo's lint rules"
