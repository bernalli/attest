# `tools/gates/` — the gates, as executables

A gate used to be a row in a table in `docs/plans/2026-09-08-trust-material-serialized-entry.md`:
a command, an expected outcome, and a negative control described in prose. Over four rounds of
review that table produced eight defects while the 829 lines of design around it produced one, and
none of the eight was an error of reasoning. They were all the same thing — **an observable outcome
declared without having been produced**. A cell that says "→ red" costs one line and cannot fail, so
the review was its first execution.

The section even opened by quoting the rule against that family, and two rows below the quotation sat
two of the defects. Knowing the rule was not the missing ingredient. The container was.

So the gates live here, and the plan keeps three things per gate: the **property** it imposes, the
**path** of the script, and the **marker** that only a completed measurement can print.

## Running one

```sh
tools/gates/g-ts-test.sh            # a gate takes no arguments unless its id is parameterised
tools/gates/g-py-suite.sh ah        # segment gates take the segment
tools/gates/g-e2e.sh site           # suite gates take the suite
```

Exit status:

| | |
|---|---|
| **0** | the property holds |
| **1** | the property does not hold |
| **78** | a precondition is missing — the gate did **not** measure |

78 exists because a gate that could not measure is neither green nor red. It was added after the
same unchanged script came out green on a tree whose virtualenv lacked the workspace members and red
on a built one: without a third status, "the transcript is on file" certifies some other system.

## Writing one

Source `_lib.sh` and use its primitives; it is where the contract lives, with the measurement behind
each rule in the comments. In short:

- **Never read an exit status through a pipe.** `false | tail -1` exits 0. `gate_run` keeps the real
  status in `GATE_RC`.
- **Assert a collection is non-empty before concluding anything from it.** A glob that fails to
  expand leaves pytest without arguments, and pytest without arguments uses `testpaths`: measured
  here, exit 0 and 118 files. An empty set satisfies almost any comparison you then make with it.
- **A negative control names where it must fail.** `gate_negative --marker <regex>` demands both a
  non-zero exit *and* the marker only the guarded path can emit. Measured: the conformance runner's
  prescribed negative, `--adapter false`, exits 2 from the argument parser without invoking any
  adapter — a script asserting only "it failed" calls that proof the gate catches a failing adapter.
  Where a negative is a *change* rather than a *failure* (an argument the tool must actually read),
  assert the change explicitly and say in a comment why the shape differs.
- **A count is never a criterion.** Derive both sides at runtime and assert the invariant with
  `gate_expect_same_set`. Counts as dated facts belong in the plan's premises, with the command
  beside them; counts as thresholds belong nowhere.
- **Pin the tree.** Absolute paths, `--prefix`/`--root`/`-p`/`--rootdir`, and no `cd` inside compound
  commands. A green that does not name the tree it ran on is not a measurement.

## Rerun a gate when the set it covers changes — including when you are the one changing it

`tools/gates/run-all.sh` runs them all in dependency order and reports three NAMED sets: green, red,
and *did not measure*. Use it. Running one gate is how the following happens.

Measured on this front, twice, one level apart. First: seven transcripts had been produced under an
earlier `_lib.sh`, and a transcript produced under a different library certifies a different system —
they were all redone. Then, later, `ruff check` came out red on a defect nobody had introduced,
because G-LINT's last green predated three Python files added to `tools/gates/` **while working on
the gates themselves**. The green was true and described a smaller tree than the one that existed.

Both are the same shape: the verdict is honest and its object has moved. The first is the library
under the transcript; the second is the covered set under the gate. Neither shows up as a failure —
they show up as a green that answers a question nobody is asking any more.

## Preconditions are not steps

If a gate needs `npm ci`, a built `dist`, or a synced virtualenv, it **checks** for it with
`gate_need` and exits 78 — it does not install it. A gate that installs its own dependencies is no
longer measuring the tree, it is changing it.

The Python environment is built with `uv sync --all-packages --all-extras` — **both** flags. Workspace
members are declared in `[tool.uv.workspace]`, the tools in `[project.optional-dependencies]`, and
`--all-packages` alone *uninstalls* pytest, mypy and ruff.

## Transcripts

`transcripts/*.log` holds the whole output of the run that produced each claim, never truncated —
a `| tail -4` on this project once hid 54 failures. Only the `.log` files are committed; the working
artefacts a gate writes on the way (junit, JSON reports, censuses) are regenerated by rerunning it.

## `decision-negative-control/`

Not gates: the falsification test of the decision that produced this directory, kept executable. See
its README.
