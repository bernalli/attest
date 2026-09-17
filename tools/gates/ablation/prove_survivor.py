#!/usr/bin/env python3
"""Prove a SURVIVOR is real: show the mutation changes behaviour on some input.

A mutation can land -- bytes changed, hash differs -- and still be semantically
INERT, and an inert mutation produces exactly the reading a genuine survivor
does: nothing goes red. The survivor count is the deliverable, so it is the
number that has to be defended: every survivor must come with an input on which
the mutated code and the original disagree. Without that, "the suite does not
cover this" and "nothing was really mutated" are the same observation.

Usage: prove_survivor.py <spec.json> <mutant-id> <probe.py> [--tree PATH]

The probe prints one line to stdout. It is run twice, on the original tree and
on the mutated tree; the mutant is potent iff the two lines differ.

The mutation goes through the journal. `journal_owner()` is entered before the
probe runs on the original tree and held for the whole measurement, so the
record naming the original bytes is on disk before the target is touched, and a
journal already under the tree stops this tool at the door instead of letting it
mutate a tree another run is mutating, or one a killed run left mutated. Nothing
here writes a target, removes a bytecode cache or puts a file back on its own:
the journal does all three, and its refusals are reported by name.

A probe that cannot run is measured separately on each tree, and the two cases
are different findings. On the original tree it means nothing was measured at
all, and its silence would read as "the mutant is inert" -- the wrong conclusion
about the wrong object -- so the mutation is not even applied. On the mutated
tree it means the probe never reached the property, because the mutation broke
the form; the two readings differ for the one reason that proves nothing.

Exit status, and no other: 0 the mutant is potent; 1 it is inert; 2 the probe
did not run on the original tree, or did not read it the same way twice, so
nothing was measured; 3 the probe did not run on the mutated tree, so the
difference is about the form, not the property;
4 the invocation, the spec or the mutation was refused; 8 the journal is held; 9
a journal record is in a state nobody wrote; 12 a filesystem of the tree cannot
exchange two files atomically.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn

HERE = Path(__file__).resolve().parent
# `journal.py` lives next to this file and is imported from here, so a copy of
# this directory runs its own journal.
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import journal  # noqa: E402 -- resolved from the directory inserted above

#: The two readings differ: the mutant changes behaviour on the probe's input.
EXIT_POTENT = 0
#: The two readings are the same: the mutant proves nothing and has to be rebuilt.
EXIT_INERT = 1
#: The probe did not run on the original tree, or did not read it twice alike.
EXIT_PROBE_BROKEN = 2
#: The probe did not run on the mutated tree: the difference is about the form.
EXIT_BROKEN_BY_MUTATION = 3
#: The invocation, the spec, or the mutation itself was refused by name.
EXIT_REFUSED = 4

#: How long a single probe run may take; the same ceiling the suite runs get.
_PROBE_TIMEOUT_SECONDS = 600
#: How much of a failed probe's standard error is quoted in the verdict.
_STDERR_TAIL = 400


class _UsageError(Exception):
    """An invalid command line, raised instead of `argparse`'s own exit.

    `argparse` exits 2 on a bad invocation, and 2 is this tool's reading for a
    probe that did not run: the two would be indistinguishable to a caller that
    only has the exit status.
    """


class _Parser(argparse.ArgumentParser):
    """`argparse.ArgumentParser` that raises `_UsageError` instead of exiting 2."""

    def error(self, message: str) -> NoReturn:
        """Raise `_UsageError` instead of printing usage and exiting."""
        raise _UsageError(message)


def _git_toplevel(directory: Path) -> Path | None:
    """`git rev-parse --show-toplevel` from `directory`, or `None` when git cannot answer."""
    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell
        ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],  # noqa: S607 -- git on PATH
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return Path(result.stdout.strip())


def _resolve_tree(given: str | None) -> tuple[Path | None, str]:
    """The tree to work on, or `None` and the reason it cannot be used.

    Without `--tree` the tree is the top level of the working tree this file is
    in, which is the default the bench uses. A given tree must itself be a top
    level: the journal, the probe's import path and the mutation are all rooted
    there, and a subdirectory would put the journal somewhere the tree's own
    guards do not look.
    """
    if given is None:
        toplevel = _git_toplevel(HERE)
        if toplevel is None:
            return None, f"no --tree given and {HERE} is not inside a git working tree"
        return toplevel.resolve(), ""
    candidate = Path(given).resolve()
    if not candidate.is_dir():
        return None, f"--tree {given} is not a directory"
    toplevel = _git_toplevel(candidate)
    if toplevel is None or toplevel.resolve() != candidate:
        return None, (
            f"--tree {given} is not the top level of a git working tree "
            f"(git answered {toplevel if toplevel is not None else 'nothing'})"
        )
    return candidate, ""


def _load_mutant(spec_path: Path, mutant_id: str) -> dict[str, Any]:
    """The row of `spec_path` with this id, checked for the keys a mutation needs.

    Raises `_UsageError`, naming the file and the id, when the spec cannot be
    read, holds no `mutants` array, has no row with that id, or has one this
    tool cannot apply: a row that loads a plugin changes no file, so there is
    nothing for a probe to read differently.
    """
    try:
        document = json.loads(spec_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise _UsageError(f"{spec_path}: cannot be read ({exc})") from None
    except json.JSONDecodeError as exc:
        raise _UsageError(f"{spec_path}: is not valid JSON ({exc})") from None
    if not isinstance(document, dict) or not isinstance(document.get("mutants"), list):
        raise _UsageError(f"{spec_path}: has no 'mutants' array")
    rows = [row for row in document["mutants"] if isinstance(row, dict)]
    found = [row for row in rows if row.get("id") == mutant_id]
    if not found:
        known = sorted(str(row.get("id")) for row in rows)
        raise _UsageError(f"{spec_path}: has no mutant {mutant_id!r}; it has {known}")
    if len(found) > 1:
        raise _UsageError(
            f"{spec_path}: has {len(found)} mutants with the id {mutant_id!r}; the bench "
            "refuses a spec with a repeated id, and which of the rows would be proved here "
            "is not this tool's to choose"
        )
    mutant = found[0]
    if mutant.get("kind", "source") != "source":
        raise _UsageError(
            f"{mutant_id}: is a {mutant['kind']!r} mutant, which changes no file; only a "
            "source mutant can be proved with a probe"
        )
    missing = [key for key in ("file", "old", "new") if not isinstance(mutant.get(key), str)]
    if missing:
        raise _UsageError(f"{mutant_id}: is missing the string keys {missing}")
    return mutant


def _run_probe(tree: Path, probe: Path) -> tuple[str, bool]:
    """Run `probe` against `tree` and return what it printed and whether it ran.

    The tree goes on `PYTHONPATH` so a probe can import the modules it mutates,
    bytecode is not written, and `PYTHONPYCACHEPREFIX` is removed so no cache
    lands outside the tree, where removing the caches under the tree would not
    reach it and a stale one would answer for the source.

    "It ran" is a clean exit with something on standard output: a probe that
    crashes or prints nothing has measured nothing, and its empty reading must
    not be compared with another.
    """
    env = dict(os.environ)
    env.pop("PYTHONPYCACHEPREFIX", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    python_path = [str(tree)]
    if env.get("PYTHONPATH"):
        python_path.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_path)
    stdout = stderr = ""
    returncode: int | None = None
    try:
        proc = subprocess.run(  # noqa: S603 -- the current interpreter on the given probe
            [sys.executable, str(probe)],
            cwd=str(tree),
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"<probe did not complete> {exc}", False
    stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode
    ran = returncode == 0 and stdout.strip() != ""
    if ran:
        return stdout.strip(), True
    return f"<rc={returncode}> {stderr.strip()[-_STDERR_TAIL:]}", False


def _report(mutant: dict[str, Any], before: str, after: str) -> None:
    """Print what was mutated and the two readings, before any verdict line."""
    print(f"mutant      : {mutant['id']}")
    print(f"target      : {mutant['file']}")
    print(f"replaced    : {json.dumps(mutant['old'])} -> {json.dumps(mutant['new'])}")
    print(f"original    : {before}")
    print(f"mutated     : {after}")


def _measure(owner: journal.JournalOwner, tree: Path, mutant: dict[str, Any], probe: Path) -> int:
    """Read the probe on the original tree and on the mutated one; return the exit status.

    The journal is already held when this is called. The mutation is applied
    only after the probe has been seen to run on the original tree twice and
    read it the same way both times -- a reading that is not a function of the
    tree would otherwise make any mutant look potent, which is the one verdict
    this tool must not hand out for free -- and the
    record is put back in a `finally`, so a probe that fails or raises under the
    mutation still leaves the tree as it was found. A restore the journal
    refuses is not swallowed: it replaces whatever this measurement would have
    returned.
    """
    before, ran = _run_probe(tree, probe)
    if not ran:
        print(f"PROBE BROKEN on the original tree, nothing was measured:\n{before}")
        return EXIT_PROBE_BROKEN
    again, ran_again = _run_probe(tree, probe)
    if not ran_again or again != before:
        print(
            "PROBE BROKEN on the original tree, nothing was measured: it read the unmutated "
            "tree twice and disagreed with itself, so a difference under the mutation would "
            f"not be the mutation's:\nfirst  : {before}\nsecond : {again}"
        )
        return EXIT_PROBE_BROKEN
    record = owner.apply_source(mutant["file"], mutant["old"], mutant["new"])
    try:
        after, ran_mutated = _run_probe(tree, probe)
    finally:
        owner.restore(record)
    if not ran_mutated:
        _report(mutant, before, after)
        print(
            "VERDICT     : BROKEN BY THE MUTATION -- the probe did not run on the mutated "
            "tree, so the difference is about the form, not the property"
        )
        return EXIT_BROKEN_BY_MUTATION
    _report(mutant, before, after)
    potent = before != after
    print(
        "VERDICT     : "
        + (
            "POTENT -- the survivor is real"
            if potent
            else "INERT -- this mutant proves nothing, rebuild it"
        )
    )
    return EXIT_POTENT if potent else EXIT_INERT


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point; returns the exit status."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _Parser(prog="prove_survivor.py", description=(__doc__ or "").splitlines()[0])
    parser.add_argument("spec", help="the spec JSON file holding the mutant")
    parser.add_argument("mutant_id", metavar="mutant-id", help="the id of the mutant to prove")
    parser.add_argument("probe", help="a script that prints one line about the mutated behaviour")
    parser.add_argument("--tree", help="top level of the git working tree to mutate")
    try:
        args = parser.parse_args(arguments)
        mutant = _load_mutant(Path(args.spec), args.mutant_id)
    except _UsageError as exc:
        print(f"prove_survivor.py: error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    tree, reason = _resolve_tree(args.tree)
    if tree is None:
        print(f"prove_survivor.py: error: {reason}", file=sys.stderr)
        return EXIT_REFUSED
    probe = Path(args.probe).resolve()
    if not probe.is_file():
        print(f"prove_survivor.py: error: probe {args.probe} is not a file", file=sys.stderr)
        return EXIT_REFUSED
    try:
        with journal.journal_owner(tree, ["prove_survivor.py", *arguments]) as owner:
            code = _measure(owner, tree, mutant, probe)
        return code
    except journal.JournalError as exc:
        # The journal's refusals are the only errors that reach a caller as a
        # message instead of a traceback: it is what tells a mutation nobody
        # recorded apart from one this run put back.
        print(exc, file=sys.stderr)
        return EXIT_REFUSED if exc.exit_code is None else exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
