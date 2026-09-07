# The negative control of the gate decision

These two scripts are not gates. They are the falsification test of the decision
that produced every gate in the directory above, kept executable so that the next
person to think "D-G1 was enough" can find out in thirty seconds instead of at the
next review.

## What was being asked

The decision moved the gates out of the plan and into `tools/gates/`, under one
rule (D-G1): *no outcome appears in the plan that was not produced by an execution
whose transcript is attached in the same commit.* Before applying it, the front was
required to try to falsify it — take two of the defects the decision claims to
dissolve, F-06 and F-08, and try to write them again under the new rules. A process
decision that cannot be falsified is a preference.

So each script is a **dummy**: formally conformant to D-G1 and D-G2 in every
respect — an executable file, an outcome produced by running it, a transcript on
file, no counts written down — with the defect still inside.

## What they measured

`negctl-f06.sh` runs the conformance runner's negative control exactly as the plan
prescribed it, `--adapter false`, and asserts only that the command fails. It exits
**0**, reporting `NEG-OK: il gate sa fallire su un adapter fallente`. The observed
failure is `error: --adapter template must contain the {leaf} placeholder`, exit 2 —
the argument parser, reached before any adapter is invoked and before any leaf is
executed. **F-06 survived D-G1 intact.** A negative control that asserts only "it
failed" is a conformant script, so the rule as written could not exclude it. This is
what D-G1b was added for: a negative control names the point at which it must fail
and demands the marker only the guarded path can emit.

`negctl-f08.sh` carries the plan's claim that pytest with no arguments exits 4
having collected nothing. On the first run it exited **0** — green, with the false
claim inside. The reason was not the claim: the tree's virtualenv had no workspace
members, `bridge/tests/conftest.py` died on `ModuleNotFoundError: attest_bridge`,
and pytest returned 4 for an import error rather than for the reason the claim
described. With the environment built (`uv sync --all-packages --all-extras` —
both flags; `--all-packages` alone uninstalls pytest, mypy and ruff), the same
unchanged script is **red on its first run**: exit 0, 118 files collected. So D-G1
does dissolve F-08 — but only when the execution happens in the environment the
gate will actually run in. This is what D-G1c was added for, and why a missing
precondition exits **78** rather than passing or failing.

## The part worth remembering

The second dummy confirmed the expectation on its first run and was wrong. A dummy
that tells you what you expected deserves the same suspicion as one that does not:
here it took a second run, in a different environment, to find out that a green and
a red had swapped places for a reason neither the rule nor the script mentioned.
