"""Extract the plan's normative Python blocks and lint them as the executor will see them.

The plan tells the executor to transcribe certain blocks verbatim. Nobody had ever
run a linter over them, and the repository's own `ruff` configuration rejected one:
`__slots__` was written unsorted, which RUF023 flags. The executor would have
transcribed it faithfully and G-LINT would have gone red on T1 — a red produced by
the plan, discovered in the task instead of before it.

So the blocks are checked here. They are fragments, not modules: names defined
elsewhere in the plan are undefined inside a single block, and imports are absent.
Rules that need a whole module are therefore not applicable, and the check runs the
subset that judges a statement on its own.

Formatting is deliberately NOT checked. The repository formats on commit, so a
block written for a document — a tuple laid out on two lines to stay readable in
prose — costs nothing: the transcription is reformatted before it is ever measured.
Checking it here would have reported four blocks out of five, and a gate that is
mostly noise is a gate people learn to ignore. What the executor genuinely cannot
see coming is a lint RULE, which no formatter fixes and which surfaces only when
G-LINT runs inside the task.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

TREE = Path(__file__).resolve().parents[2]
# Overridable so the gate's negative control can point this at a copy carrying the
# real defect back, without editing the plan.
PLAN = Path(
    os.environ.get(
        "PLAN_CODE_PLAN",
        TREE / "docs" / "plans" / "2026-09-08-trust-material-serialized-entry.md",
    )
)
RUFF = TREE / ".venv" / "bin" / "ruff"

# Rules that judge a statement on its own, so they mean the same thing on a
# fragment as on the finished module. F821 (undefined name) and friends do not
# qualify: a fragment legitimately refers to names the plan defines elsewhere.
FRAGMENT_RULES = "RUF023,UP,C4,SIM,PIE,RET,PLR,B"


# Fence languages this checker knows what to do with. Anything else is a fence
# whose content nobody is checking, so it stops the gate by name.
PYTHON_FENCES = {"python", "py", "python3"}
KNOWN_OTHER_FENCES = {"ts", "typescript", "js", "javascript", "sh", "bash", "json", "text", "diff"}

# CommonMark opens a fenced block with three backticks OR three tildes, and allows
# up to three leading spaces -- which is exactly what a code block nested in a list
# item looks like. Matching only a line that STARTS at column zero with three
# backticks is a guard that recognises one SPELLING of the object rather than the
# object (C-222). Measured on this plan: the very RUF023 defect this gate was born
# from survives green both under an indented python fence and under a fence that
# names no language at all, with the checker printing PLAN_CODE_CLEAN in each case.
_FENCE = re.compile(r"^(?P<indent> {0,3})(?P<mark>`{3,}|~{3,})(?P<info>.*)$")


def fenced(text: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """Split fenced blocks into (python blocks, blocks in an unrecognised language).

    Matching only ```python would be a guard that recognises a SPELLING rather
    than the object: a block written ```py, or ```python3, is Python that this
    checker would silently never look at. So every opening fence is enumerated and
    classified, and an unknown language fails the gate by name instead of being
    skipped. An exemption is legitimate only when the gate states it.
    """
    python: list[tuple[int, str]] = []
    unknown: list[tuple[int, str]] = []
    lines = text.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        opening = _FENCE.match(lines[index].rstrip("\n"))
        if opening is None:
            index += 1
            continue
        mark = opening.group("mark")[0]
        indent = len(opening.group("indent"))
        language = opening.group("info").strip().lower()
        body: list[str] = []
        opened_at = index + 1
        index += 1
        while index < len(lines):
            closing = _FENCE.match(lines[index].rstrip("\n"))
            if closing is not None and closing.group("mark")[0] == mark:
                break
            # An indented block is indented as a whole: strip the fence's own
            # indent so ruff sees the source, not an IndentationError.
            line = lines[index]
            body.append(line[indent:] if line[:indent].isspace() else line)
            index += 1
        index += 1  # step over the closing fence
        if language in PYTHON_FENCES:
            python.append((opened_at, "".join(body)))
        elif language not in KNOWN_OTHER_FENCES:
            # A fence with NO language is not an exemption either: its body may be
            # Python the executor transcribes, and nobody would be checking it. An
            # exemption is legitimate only when the gate names and motivates it.
            unknown.append((opened_at, language or "<no language>"))
    return python, unknown


def main() -> int:
    text = PLAN.read_text(encoding="utf-8")
    found, unknown = fenced(text)
    if not found:
        print("ERROR: no python block found in the plan -- the extractor matched nothing")
        return 1
    print(f"extracted {len(found)} normative python block(s) from {PLAN.name}")

    failures = 0
    for line_no, language in unknown:
        failures += 1
        print(
            f"  FAIL: fence at plan line {line_no} is in an unrecognised language "
            f"({language!r}) -- nobody is checking its contents"
        )
    with tempfile.TemporaryDirectory() as tmp:
        for line_no, source in found:
            path = Path(tmp) / f"block_line_{line_no}.py"
            path.write_text(source, encoding="utf-8")
            # The suppression below is justified, not a silencing. S603 warns
            # about executing untrusted input; neither element here is input --
            # RUFF is this repo's own
            # interpreter-relative binary and `path` is a file this function just
            # wrote inside its own TemporaryDirectory. The argument vector is a
            # list, never a shell string, so the plan's contents cannot become
            # arguments. What the plan DOES reach is ruff's stdin-equivalent (a
            # file it lints), which is the point of the gate.
            check = subprocess.run(  # noqa: S603
                [str(RUFF), "check", "--no-cache", "--select", FRAGMENT_RULES, str(path)],
                capture_output=True,
                text=True,
            )
            label = f"block at plan line {line_no} ({len(source.splitlines())} lines)"
            if check.returncode == 0:
                print(f"  ok: {label}")
                continue
            failures += 1
            print(f"  FAIL: {label}")
            for stream in (check.stdout, check.stderr):
                for line in stream.splitlines():
                    if line.strip():
                        print(f"      {line}")

    if failures:
        if unknown:
            print(f"\n{len(unknown)} fence(s) in a language this gate does not check")
        lint_failures = failures - len(unknown)
        if lint_failures:
            print(f"\n{lint_failures} normative block(s) would not survive the repo's own linters")
        return 1
    print("PLAN_CODE_CLEAN: every normative block passes the fragment-applicable rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
