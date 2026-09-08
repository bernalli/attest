# The negative control of the gate decision

These three scripts are not gates. They are the falsification test of the decision
that produced every gate in the directory above, kept executable so that the next
person to think "D-G1 was enough" can find out in thirty seconds instead of at the
next review. The first two attack a named defect; the third (below) attacks the
rules themselves.

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
unchanged script is **red on its first run**: exit 0, with the whole universe
collected instead of nothing. The count is not repeated here: it moved (118 -> 119)
inside the commit that added a test file, which is the same lesson one level down.
So D-G1
does dissolve F-08 — but only when the execution happens in the environment the
gate will actually run in. This is what D-G1c was added for, and why a missing
precondition exits **78** rather than passing or failing.

## The third dummy: a defect that satisfies EVERY rule and still proves nothing

`negctl-f10-tautology.sh` asks a different question from the first two. They asked
whether a known defect survived a rule. This one asks whether the rules, all of
them together, are enough — and the answer is no.

It is conformant on every count: an executable rather than a table row, its outcome
produced by running it, no count written down (both sides derived at run time), the
collection asserted non-empty, the precondition checked with 78 on absence, and a
negative control that demands a marker rather than a bare non-zero exit. Run it:

```
ok: the collector reached some files (N lines collected — derived, not written down)
ok: every file the segment owns was collected (the two sets coincide)
ok: negative 'a missing argument is caught' failed at the guarded path (exit 4)
GATE G-TAUTOLOGY PASS
```

(`N` is literal here on purpose: the run prints the number it derived, and quoting it
would put a count in a README that the next added test file falsifies — which is
exactly what happened to the "118" above.)

That PASS is worth more than any explanation of the defect, because it is what the
defect looks like from outside: indistinguishable from a gate that works. The two
sides of its invariant come out of **the same command** — it compares the collector
with itself. Every rule governs how a side is OBTAINED; none said the two sides must
be obtained INDEPENDENTLY.

Hence the rule that closes it: *the two sides of an invariant have independent
provenances — one from the artefact that executes, the other from the structure that
declares it. An invariant is non-tautological only if a mutant exists that breaks one
side and not the other; if you cannot build that mutant, the two sides are the same
datum written twice.* The mutant clause is the part that makes it checkable rather
than wise: "independent" is something anyone will conclude about their own gate.

## The part worth remembering

The second dummy confirmed the expectation on its first run and was wrong. A dummy
that tells you what you expected deserves the same suspicion as one that does not:
here it took a second run, in a different environment, to find out that a green and
a red had swapped places for a reason neither the rule nor the script mentioned.

And the third was found by building something that obeys every rule, not by applying
one. A set of rules can be complete on each and incomplete together, and that gap is
only visible from a thing that satisfies them all.
