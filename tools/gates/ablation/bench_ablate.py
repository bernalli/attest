"""The bench that measures the ablation bench, from outside and on the real thing.

`ablate.py` reports what it did to a tree: which mutants it ran, which ones landed,
and three independent traces per row. Those claims are worth exactly what an
independent check of them is worth, so this bench runs `ablate.py` against the
synthetic fixture tree and verifies the claims against the tree itself and against
the spec — never by asking `ablate.py` again.

Two properties decide the shape of everything below.

`ablate.py` runs as a **subprocess**, never imported. Importing it would register
this process as the one holding a journal: the `atexit` hook and the `SIGINT`/
`SIGTERM` handlers that a holder installs would live here, and a bench that holds
the journal it is measuring cannot observe a holder that dies with the journal in
its hands — which is the whole of part B.

Every subprocess is started with this interpreter directly rather than through a
launcher. A launcher that waits on the child reports a signal death as an exit
status (`128 + n`); a direct child reports it as a negative return code. Part B
needs to see `-9` to know a real `SIGKILL` landed, and `137` would not distinguish
a killed holder from a holder that chose to exit with that status.

Part A is positive: a full run on the fixture tree, plus the absent-anchor run and
a run whose expectation is wrong on purpose. Part B kills a holder for real and
checks what the journal then allows. Every assertion is a named case appended to a
list, and the count in the closing marker is derived from that list: the marker is
what declares how much this bench measured, and a constant would declare nothing.

Part C turns the same metre on the tool. Each of its mutants is applied to a *copy*
of the tool's modules, and part A or part B is re-run against that copy: a mutant
has to make the named cases fail, and nothing outside the set declared for it. Two
things make that measurement mean what it says. The parts reach the tool only
through a tool directory handed to them, so a run against a copy cannot silently
measure the original; and the cases of those re-runs are collected in a bench of
their own, because a failure part C *requires* is not a failure of this bench, and
counting it as one would make this bench red exactly when it is working.

`ABLATION_BENCH_META_ONLY=<id>` narrows a run to one row of part C: that meta-mutant
alone is applied to a copy of the tool, exactly as part C applies it, the part the
row belongs to is re-run against the copy, and the copy's cases are printed with
their label. It exists for a negative control, which needs a run that fails for a
named reason, and it is not a run of this bench: it never prints the
`ABLATION_BENCH` marker, which a partial run must not be able to satisfy, but a line
of its own, `ABLATION_BENCH_META_ONLY id=<id> copy_cases=<n> copy_failures=<m>`.
It exits 1 when, and only when, the copy has a failing case; 0 when it has none, the
part ran to its end and at least one case was checked; 2 when the variable is empty or
names no row, because a selection that selects nothing is not a green run; and 3 when
the row was not measured -- its edit did not land on the copy, refused as part C
refuses it, the part stopped before any case failed, or it checked no case at all.
Without the variable the bench runs as the paragraphs above describe.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SELFTEST = HERE / "selftest"

#: The fixture generator is always the real one. Part C measures the tool, not the
#: tree it works on, and a tree built by a mutated generator would no longer be the
#: tree the parts were written against.
MAKE_FIXTURE_TREE = SELFTEST / "make_fixture_tree.py"

#: The modules a copy of the tool has to carry. `ablate.py` and `prove_survivor.py`
#: put their own directory on `sys.path`, and `ablate.py` puts it on the suite's
#: `PYTHONPATH`, so a directory holding all of these runs its own code throughout
#: rather than reaching back to the one it was copied from.
TOOL_MODULES = (
    "ablate.py",
    "journal.py",
    "classify.py",
    "outcomes_plugin.py",
    "prove_survivor.py",
)

#: The spec files the parts hand to the tool, copied beside the modules so that a
#: copy is self-contained and a part run against it reads nothing of the original.
TOOL_SPECS = ("spec_fixture.json", "spec_fixture_st1.json")

JOURNAL_DIRNAME = ".ablation-in-flight"
OWNER_FILENAME = "owner.json"

#: The ids the main fixture spec declares, in the order it declares them. Written
#: out rather than read from the spec so that this bench pins the spec too: read
#: from the spec, the check would compare the spec with itself. The spec is read
#: as well, and the two are compared, so a spec that loses a row is a failure here
#: and not a silently smaller run.
EXPECTED_IDS = (
    "ST2-property-red",
    "ST3-form-red",
    "ST4-sibling-only",
    "ST5-skip-under-mutation",
    "ST6-inert",
)

#: The row of the main spec whose ledger is recomputed from the git blob.
LEDGER_ORACLE_ID = "ST2-property-red"

#: The value written into the target to put a record into a state no one recorded.
UNKNOWN_STATE_TEXT = "VALUE = 5\n"

#: The variable that narrows a run to one meta-mutant; see the module docstring.
META_ONLY_VARIABLE = "ABLATION_BENCH_META_ONLY"

#: Exit statuses of a narrowed run. `1` is the only one that says the copy was caught.
EXIT_META_ONLY_CAUGHT = 1
EXIT_META_ONLY_REFUSED = 2
EXIT_META_ONLY_UNMEASURED = 3


@dataclass(frozen=True)
class MetaMutant:
    """One mutant of the tool itself, and where its damage has to show.

    `edits` are applied to a copy of the tool, each one replacing the single
    line-start occurrence of its anchor. `part` is the part of this bench re-run
    against that copy. `named` are the cases that must fail, and `collateral` the
    ones that are allowed to fail as well: a mutant is killed when the named set is
    contained in what failed and what failed is contained in the two sets together.

    The two sets are fixed here, before anything runs. Deciding after reading an
    outcome which cases were "meant" would make every mutant killable.
    """

    ident: str
    part: str
    edits: tuple[tuple[str, str, str], ...]
    named: frozenset[str]
    collateral: frozenset[str] = frozenset()


#: Part C. Each row lands on the file named in its edit, and is re-run against the
#: part in its `part`. `MB10` carries `MB2`'s edit as well: with the write skipped,
#: a `git_dirty_during` built from the path instead of from git still cannot hide
#: the mutation that never landed, which is what the pair exists to show.
META_MUTANTS: tuple[MetaMutant, ...] = (
    MetaMutant(
        "MB1-loop-skipped",
        "A",
        (("ablate.py", "    for mutant in mutants:", "    for mutant in []:"),),
        frozenset({"A3", "A4"}),
        frozenset({"A5", "A6", "A8"}),
    ),
    MetaMutant(
        "MB2-write-skipped",
        "A",
        (
            (
                "journal.py",
                "            _write_target(target, mutated, staging)",
                "            pass",
            ),
        ),
        frozenset({"A4"}),
        frozenset({"A1", "A5", "A6", "A8"}),
    ),
    MetaMutant(
        "MB3-suite-not-run",
        "A",
        (
            (
                "ablate.py",
                "            mutated = _run_suite("
                "tree, launcher, mutant, typecheck=typecheck, mutated=True)",
                "            mutated = SuiteRun(\n"
                "                baseline.outcomes,\n"
                "                baseline.outcomes_path,\n"
                "                secrets.token_hex(16),\n"
                "                baseline.nonce_echoed,\n"
                "            )",
            ),
        ),
        frozenset({"A5"}),
        frozenset({"A1", "A4", "A8"}),
    ),
    MetaMutant(
        "MB4-expectations-ignored",
        "A",
        (("ablate.py", "    if mismatches:", "    if False:"),),
        frozenset({"A8"}),
    ),
    MetaMutant(
        "MB5-cache-kept",
        "A",
        (
            (
                "journal.py",
                "    for dirpath, dirnames, _filenames in os.walk(tree):",
                "    return\n    for dirpath, dirnames, _filenames in os.walk(tree):",
            ),
        ),
        frozenset({"A8"}),
        frozenset({"A1"}),
    ),
    MetaMutant(
        "MB6-rejected-wipes",
        "B",
        (
            (
                "journal.py",
                "            raise JournalBusy(_busy_message(self.journal_dir)) from None",
                '            for _leftover in sorted(self.journal_dir.glob("*.json")):\n'
                "                if _leftover.name != OWNER_FILENAME:\n"
                "                    _leftover.unlink()\n"
                "            raise JournalBusy(_busy_message(self.journal_dir)) from None",
            ),
        ),
        # This edit lands on the refusal branch of the journal's acquisition, which is
        # reached only by a process that enters that acquisition. `ablate.py` refuses an
        # already-held journal at its own entry check and returns before ever reaching
        # it, so B2 cannot observe this edit for any input at all; `prove_survivor.py`
        # has no equivalent early check and does reach the branch. B3 is therefore the
        # named case, and B4 follows from the records being gone by the time it runs.
        frozenset({"B3"}),
        frozenset({"B4"}),
    ),
    MetaMutant(
        "MB7-owner-check-removed",
        "B",
        (("journal.py", "        os.kill(pid, 0)", "        return False"),),
        frozenset({"B5"}),
    ),
    MetaMutant(
        "MB8-unknown-state-accepted",
        "B",
        (
            (
                "journal.py",
                "    raise UnknownState(",
                "    _unused_json, _orig_of_record = _record_paths(journal_dir, name)\n"
                "    target.write_bytes(_orig_of_record.read_bytes())\n"
                "    clear_bytecode_caches(tree)\n"
                "    _delete_record(journal_dir, name)\n"
                '    return "restored"\n'
                "    raise UnknownState(",
            ),
        ),
        frozenset({"B6"}),
    ),
    MetaMutant(
        "MB9-killed-elsewhere-removed",
        "A",
        (
            (
                "classify.py",
                '    if verdict == "KILLED" and expect_red and not hit:',
                "    if False:",
            ),
        ),
        frozenset({"A8"}),
        frozenset({"A1"}),
    ),
    MetaMutant(
        "MB10-git-snapshot-faked",
        "A",
        (
            (
                "journal.py",
                "            _write_target(target, mutated, staging)",
                "            pass",
            ),
            (
                "ablate.py",
                "            git_dirty_during = _porcelain_during_mutation(tree)",
                '            git_dirty_during = [" M " + mutant["file"]]',
            ),
        ),
        frozenset({"A4"}),
        frozenset({"A1", "A5", "A6", "A8"}),
    ),
    MetaMutant(
        "MB11-nonce-not-passed",
        "A",
        (("ablate.py", '    env["ABLATION_NONCE"] = nonce', "    pass"),),
        frozenset({"A5"}),
        frozenset({"A1", "A4", "A6", "A8"}),
    ),
    MetaMutant(
        "MB12-early-refusal-wipes",
        "B",
        (
            (
                "ablate.py",
                "            return journal.EXIT_JOURNAL_BUSY",
                '            for _leftover in sorted(journal_dir.glob("*.json")):\n'
                "                if _leftover.name != journal.OWNER_FILENAME:\n"
                "                    _leftover.unlink()\n"
                "            return journal.EXIT_JOURNAL_BUSY",
            ),
        ),
        # MB6's edit, carried to the other refusal of a held journal: this one lands on
        # the branch of `ablate.py`'s own entry check that refuses a journal holding
        # `owner.json`, which answers before the acquisition MB6 damages is ever reached.
        # B2 runs `ablate.py` over a held journal and requires that the refused run
        # touched nothing, so B2 is the named case. B3 and B4 follow from the records
        # being gone by the time they run.
        frozenset({"B2"}),
        frozenset({"B3", "B4"}),
    ),
)

#: A holder that takes the journal, lands one mutation and dies with it in hand.
#: Written to a file and run as its own process: nothing of it may execute here.
_HOLDER_SOURCE = '''\
"""Take the journal, land one mutation, and die without giving it back."""

import os
import signal
import sys

sys.path.insert(0, sys.argv[1])

import journal

with journal.journal_owner(sys.argv[2], ["in-flight holder"]) as owner:
    record = owner.apply_source(sys.argv[3], sys.argv[4], sys.argv[5])
    print(record.name, flush=True)
    os.kill(os.getpid(), signal.SIGKILL)
'''

#: A probe for `prove_survivor.py`. It has to be a file for the command line to be
#: accepted; part B never lets it run, because the journal refuses first.
_PROBE_SOURCE = '"""A probe that part B never reaches."""\n\nprint("probe")\n'


@dataclass(frozen=True)
class Tools:
    """The directory a part takes the tool from, and every path derived from it.

    Parts A and B reach the tool only through one of these, so the directory is the
    single thing that decides which copy of the tool a part measures. Held as a
    parameter rather than read from the module, because part C runs the same parts
    against a mutated copy: a path pinned to this module would make those runs
    measure the original while reporting on the copy.
    """

    root: Path

    @property
    def ablate(self) -> Path:
        """The `ablate.py` of this directory."""
        return self.root / "ablate.py"

    @property
    def prove_survivor(self) -> Path:
        """The `prove_survivor.py` of this directory."""
        return self.root / "prove_survivor.py"

    @property
    def spec_main(self) -> Path:
        """The five-row fixture spec of this directory."""
        return self.root / "selftest" / "spec_fixture.json"

    @property
    def spec_st1(self) -> Path:
        """The one-row absent-anchor spec of this directory."""
        return self.root / "selftest" / "spec_fixture_st1.json"


#: The tool as it is committed: what the bench proper measures.
REAL_TOOLS = Tools(HERE)


@dataclass(frozen=True)
class Case:
    """One named assertion of this bench and how it came out."""

    name: str
    ok: bool
    detail: str


class Bench:
    """The list of cases, and the marker derived from it."""

    def __init__(self, label: str = "") -> None:
        #: Printed in front of every line this bench emits. Part C runs the parts a
        #: second time against a mutated copy, and those runs are *expected* to fail:
        #: without a label their failures cannot be told apart in the log from this
        #: bench's own, and a reader of a red gate cannot see which list a line came
        #: from. The marker separates the counts; this separates the log.
        self.label = label
        self.cases: list[Case] = []
        self.died_elsewhere: list[str] = []
        self.meta_ran: list[str] = []
        self.applications_confirmed = 0

    def check(self, name: str, ok: bool, detail: str) -> bool:
        """Append a named case, print it, and report whether it held."""
        self.cases.append(Case(name, bool(ok), detail))
        print(f"{self.label}{'PASS' if ok else 'FAIL'}: {name} -- {detail}")
        return bool(ok)

    def say(self, line: str) -> None:
        """Print a line of the bench's own log; it is not a case."""
        print(f"{self.label}[bench] {line}")

    @property
    def failures(self) -> int:
        """How many cases did not hold."""
        return sum(1 for case in self.cases if not case.ok)

    def marker(self) -> str:
        """The closing line, with every count derived from what was measured.

        `meta_mutants` counts the ones that were actually run, not the length of the
        table: a part C that stopped early has to say a smaller number, and a zero
        has to mean that none ran rather than that a zero was written here.
        """
        return (
            f"ABLATION_BENCH cases={len(self.cases)} failures={self.failures} "
            f"meta_mutants={len(self.meta_ran)} meta_died_elsewhere={len(self.died_elsewhere)} "
            f"applications_confirmed={self.applications_confirmed}"
        )


# --- running things, and looking at trees -----------------------------------------------------


def run_tool(argv: list[str], *, run_nonce: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run one of the tool's scripts as a child of this process.

    `PYTHONPYCACHEPREFIX` is dropped so no bytecode cache lands outside the tree
    being mutated, where removing the tree's caches would not reach it.
    """
    env = dict(os.environ)
    env.pop("PYTHONPYCACHEPREFIX", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if run_nonce is not None:
        env["ABLATION_RUN_NONCE"] = run_nonce
    else:
        env.pop("ABLATION_RUN_NONCE", None)
    # This interpreter running scripts of this repository, with arguments built here.
    return subprocess.run(  # noqa: S603
        [sys.executable, *argv],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def build_fixture_tree(dest: Path) -> Path:
    """Build a fresh fixture tree at `dest`, with the generator run as its own process.

    The generator's directory is not an importable package, so it is invoked through
    its command line. A generator that refuses — because the bytecode cache it has to
    plant did not come out in the mode the tree depends on, for instance — exits
    non-zero, and that refusal is raised here rather than turning into a tree that
    quietly stopped reproducing what it exists to reproduce.
    """
    result = run_tool([str(MAKE_FIXTURE_TREE), str(dest)])
    if result.returncode != 0:
        raise RuntimeError(
            f"the fixture generator refused for {dest.name} (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return dest


def git_output(tree: Path, *args: str) -> str | None:
    """`git` in `tree`: stdout as text, or `None` when git could not answer.

    A failure is not an empty answer. `git` on a tree whose repository is gone or
    unreadable exits non-zero with nothing on stdout, and a caller that reads that
    as "no lines" reads a tree it cannot see as a tree it has seen and found clean.
    """
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(tree), *args],  # noqa: S607 -- git from PATH, as elsewhere here
        capture_output=True,
        text=True,
        check=False,
    )
    return None if result.returncode != 0 else result.stdout


def porcelain(tree: Path) -> list[str] | None:
    """`git status --porcelain --untracked-files=normal` of `tree`, as lines.

    `None` means git could not say, which is not the same as a clean tree. The
    tool under test makes exactly that distinction and refuses a run rather than
    trust a status it could not read; a bench that collapsed the two would
    certify a cleanup it never observed, and would do it silently.

    The untracked flag is explicit because a global `status.showUntrackedFiles=no`
    would otherwise hide every untracked file, and a stray file in the tree is
    exactly what the checks after a run are looking for.
    """
    out = git_output(tree, "status", "--porcelain", "--untracked-files=normal")
    if out is None:
        return None
    return [line for line in out.splitlines() if line]


def head_blob(tree: Path, rel_path: str) -> bytes:
    """The committed bytes of `rel_path`, read from git rather than from disk."""
    # Binary output: the committed bytes, not a decoded rendering of them.
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(tree), "show", f"HEAD:{rel_path}"],  # noqa: S607 -- git from PATH
        capture_output=True,
        check=True,
    )
    return result.stdout


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 of `data`."""
    return hashlib.sha256(data).hexdigest()


def replace_once_at_line_start(data: bytes, old: bytes, new: bytes) -> bytes:
    """Replace the single line-start occurrence of `old` with `new`.

    The substitution rule of the spec, implemented here so the expected hash of a
    mutation is computed from the committed bytes and the spec's own text. Raises
    `ValueError` unless exactly one occurrence starts a line: an oracle that
    guesses which occurrence was meant would prove nothing about the one the tool
    picked.
    """
    starts = [
        index
        for index in range(len(data) - len(old) + 1)
        if data[index : index + len(old)] == old
        and (index == 0 or data[index - 1 : index] == b"\n")
    ]
    if len(starts) != 1:
        raise ValueError(f"anchor {old!r} starts a line {len(starts)} times, need exactly 1")
    at = starts[0]
    return data[:at] + new + data[at + len(old) :]


def journal_records(tree: Path) -> list[str]:
    """The names of the records the journal under `tree` holds, sorted."""
    journal_dir = tree / JOURNAL_DIRNAME
    if not journal_dir.is_dir():
        return []
    return sorted(
        path.name[: -len(".json")]
        for path in journal_dir.glob("*.json")
        if path.name != OWNER_FILENAME
    )


def read_summary(path: Path) -> dict[str, Any]:
    """The `summary` of a results file, or an empty mapping if there is none."""
    if not path.is_file():
        return {}
    payload: Any = json.loads(path.read_text(encoding="utf-8"))
    summary = payload.get("summary") if isinstance(payload, dict) else None
    return summary if isinstance(summary, dict) else {}


def read_rows(path: Path) -> dict[str, dict[str, Any]]:
    """The rows of a results file, keyed by mutant id."""
    if not path.is_file():
        return {}
    payload: Any = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {}
    return {row["id"]: row for row in rows if isinstance(row, dict) and "id" in row}


def spec_rows(spec_path: Path) -> list[dict[str, Any]]:
    """The mutants a spec declares, in the order it declares them."""
    payload: Any = json.loads(spec_path.read_text(encoding="utf-8"))
    mutants = payload.get("mutants") if isinstance(payload, dict) else None
    return list(mutants) if isinstance(mutants, list) else []


def trace_problem(row: dict[str, Any], expected_dirty: list[str]) -> str | None:
    """Why a row's three traces do not hold, or `None` if they do.

    The third trace is the nonce for an ordinary row and the typecheck record for a
    row a type-checker stopped before its suite ever ran — one or the other, never
    both and never neither. A row carrying both would mean the tool recorded a run
    it did not do; a row carrying neither would mean it confirmed a mutation on two
    traces where three are required. Both are defects of the tool, and this says so
    instead of quietly picking whichever trace is present.
    """
    if row.get("git_dirty_during") != expected_dirty:
        return f"git_dirty_during={row.get('git_dirty_during')!r}, expected {expected_dirty!r}"
    typecheck = row.get("typecheck")
    nonce = row.get("nonce")
    if typecheck is not None and nonce is not None:
        return "carries a typecheck trace and a nonce trace; a row has exactly one third trace"
    if typecheck is not None:
        if "tsc_returncode" not in typecheck:
            return "typecheck carries no tsc_returncode; a stopped run is measured by that status"
        if typecheck.get("tsc_returncode") == 0:
            return (
                f"typecheck.tsc_returncode={typecheck.get('tsc_returncode')!r}, expected non-zero"
            )
        if not typecheck.get("form_codes"):
            return "typecheck.form_codes is empty; a stopped run is measured by its codes"
        return None
    # Reached only with `typecheck` absent, so a missing nonce here is the
    # neither-trace row. Checked in this order rather than up front so that the
    # reads below are on a mapping that has been shown to be present.
    if nonce is None:
        return "carries neither a typecheck trace nor a nonce trace"
    if nonce.get("issued") is None:
        return "nonce.issued is absent"
    if nonce.get("echoed") != nonce.get("issued"):
        return f"nonce echoed={nonce.get('echoed')!r}, issued={nonce.get('issued')!r}"
    return None


def forced_spec(source: Path, dest: Path, mutant_id: str, verdict: str) -> None:
    """Write a copy of `source` at `dest` with one row's expected verdict changed."""
    payload: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
    for mutant in payload["mutants"]:
        if mutant["id"] == mutant_id:
            mutant["expect_verdict"] = verdict
    dest.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")


# --- part A: the positive run, on the real bench -----------------------------------------------


def part_a(bench: Bench, workdir: Path, tools: Tools) -> None:
    """Run the fixture spec three ways and check what the results claim.

    Every path to the tool comes from `tools`, so this runs against whichever copy
    it names: the committed one for the bench proper, a mutated one for part C.
    """
    tree = build_fixture_tree(workdir / "tree-a")
    declared = spec_rows(tools.spec_main)
    target_of = {mutant["id"]: mutant["file"] for mutant in declared}

    main_out = workdir / "results.json"
    main_nonce = "bench-run-main"
    main = run_tool(
        [str(tools.ablate), str(tools.spec_main), "--tree", str(tree), "--out", str(main_out)],
        run_nonce=main_nonce,
    )
    bench.say(f"main run: rc={main.returncode}")
    bench.check("A1", main.returncode == 0, f"the main run exits 0: rc={main.returncode}")
    summary = read_summary(main_out)
    rows = read_rows(main_out)
    bench.applications_confirmed = int(summary.get("applications_confirmed", 0) or 0)

    bench.check(
        "A2",
        main_out.is_file() and summary.get("nonce_of_run") == main_nonce,
        f"the main results file was written by this run: exists={main_out.is_file()} "
        f"nonce_of_run={summary.get('nonce_of_run')!r} issued={main_nonce!r}",
    )
    bench.check(
        "A3",
        tuple(summary.get("mutant_ids", ())) == EXPECTED_IDS,
        f"the run executed the expected ids in order: {summary.get('mutant_ids')!r}",
    )
    bench.check(
        "A3",
        tuple(mutant["id"] for mutant in declared) == EXPECTED_IDS,
        f"the spec still declares those ids in that order: "
        f"{[mutant['id'] for mutant in declared]!r}",
    )
    bench.check(
        "A4",
        summary.get("applications_confirmed") == 5 and summary.get("applications_attempted") == 5,
        f"the main run confirms every attempt: "
        f"applications_confirmed={summary.get('applications_confirmed')!r} "
        f"applications_attempted={summary.get('applications_attempted')!r}",
    )

    for mutant_id in EXPECTED_IDS:
        row = rows.get(mutant_id)
        if row is None:
            bench.check("A5", False, f"{mutant_id}: no row in the results")
            continue
        expected_dirty = [f" M {target_of[mutant_id]}"]
        problem = trace_problem(row, expected_dirty)
        bench.check(
            "A5",
            problem is None,
            f"{mutant_id}: traces hold" if problem is None else f"{mutant_id}: {problem}",
        )

    oracle_row = next((m for m in declared if m["id"] == LEDGER_ORACLE_ID), None)
    if oracle_row is None:
        bench.check("A6", False, f"{LEDGER_ORACLE_ID}: the spec no longer declares this row")
        # Raised, not returned. Everything below this point -- A7, the absent-anchor
        # run and both of its cases, A8, and the forced-expectation run -- would go
        # unmeasured, and an observation that stopped early must never be read as a
        # complete one: part C catches this and reports the mutant as stopped, so it
        # cannot be called killed on a set of cases that were never run.
        raise RuntimeError(
            f"{LEDGER_ORACLE_ID}: the spec no longer declares this row, so part A "
            f"cannot measure the cases that follow"
        )
    committed = head_blob(tree, oracle_row["file"])
    mutated = replace_once_at_line_start(
        committed, oracle_row["old"].encode("utf-8"), oracle_row["new"].encode("utf-8")
    )
    expected_after = sha256_hex(mutated)
    ledger = (rows.get(LEDGER_ORACLE_ID) or {}).get("ledger") or {}
    bench.check(
        "A6",
        ledger.get("sha_after") == expected_after,
        f"{LEDGER_ORACLE_ID}: ledger.sha_after={ledger.get('sha_after')!r} against "
        f"{expected_after!r}, recomputed from the committed blob "
        f"(sha_before={ledger.get('sha_before')!r}, committed={sha256_hex(committed)!r})",
    )
    check_tree_is_clean(bench, tree, "after the main run")

    st1_out = workdir / "st1.json"
    st1_nonce = "bench-run-st1"
    st1 = run_tool(
        [
            str(tools.ablate),
            str(tools.spec_st1),
            "--tree",
            str(tree),
            "--skip-preflight",
            "--out",
            str(st1_out),
        ],
        run_nonce=st1_nonce,
    )
    bench.say(f"absent-anchor run: rc={st1.returncode}")
    bench.check("A1", st1.returncode == 0, f"the absent-anchor run exits 0: rc={st1.returncode}")
    st1_summary = read_summary(st1_out)
    bench.check(
        "A2",
        st1_out.is_file() and st1_summary.get("nonce_of_run") == st1_nonce,
        f"the absent-anchor results file was written by this run: exists={st1_out.is_file()} "
        f"nonce_of_run={st1_summary.get('nonce_of_run')!r} issued={st1_nonce!r}",
    )
    bench.check(
        "A4",
        st1_summary.get("applications_confirmed") == 0 and st1_summary.get("not_applied") == 1,
        f"the absent anchor lands nothing: "
        f"applications_confirmed={st1_summary.get('applications_confirmed')!r} "
        f"not_applied={st1_summary.get('not_applied')!r}",
    )
    check_tree_is_clean(bench, tree, "after the absent-anchor run")

    bench.check(
        "A8",
        summary.get("expectations_declared") == 5
        and summary.get("expectations_failed") == 0
        and summary.get("expectations_unmeasured") == 0,
        f"the main run meets every expectation: declared="
        f"{summary.get('expectations_declared')!r} failed="
        f"{summary.get('expectations_failed')!r} unmeasured="
        f"{summary.get('expectations_unmeasured')!r}",
    )
    bench.check(
        "A8",
        st1_summary.get("expectations_declared") == 1
        and st1_summary.get("expectations_failed") == 0
        and st1_summary.get("expectations_unmeasured") == 0,
        f"the absent-anchor run meets its one expectation: declared="
        f"{st1_summary.get('expectations_declared')!r} failed="
        f"{st1_summary.get('expectations_failed')!r} unmeasured="
        f"{st1_summary.get('expectations_unmeasured')!r}",
    )

    forced_path = workdir / "spec_forced.json"
    forced_out = workdir / "forced.json"
    forced_nonce = "bench-run-forced"
    forced_spec(tools.spec_main, forced_path, LEDGER_ORACLE_ID, "SURVIVED")
    forced = run_tool(
        [
            str(tools.ablate),
            str(forced_path),
            "--tree",
            str(tree),
            "--only",
            LEDGER_ORACLE_ID,
            "--out",
            str(forced_out),
        ],
        run_nonce=forced_nonce,
    )
    bench.say(f"forced-expectation run: rc={forced.returncode}")
    forced_summary = read_summary(forced_out)
    bench.check(
        "A2",
        forced_out.is_file() and forced_summary.get("nonce_of_run") == forced_nonce,
        f"the forced-expectation results file was written by this run: "
        f"exists={forced_out.is_file()} nonce_of_run={forced_summary.get('nonce_of_run')!r} "
        f"issued={forced_nonce!r}",
    )
    bench.check(
        "A8",
        forced.returncode == 7
        and forced_summary.get("expectations_failed") == 1
        and f"EXPECTATION FAILED {LEDGER_ORACLE_ID}" in forced.stderr,
        f"a wrong expectation is refused: rc={forced.returncode} expectations_failed="
        f"{forced_summary.get('expectations_failed')!r} names the row="
        f"{f'EXPECTATION FAILED {LEDGER_ORACLE_ID}' in forced.stderr}",
    )
    check_tree_is_clean(bench, tree, "after the forced-expectation run")


def check_tree_is_clean(bench: Bench, tree: Path, when: str) -> None:
    """Case A7: nothing of the run is left behind in the tree."""
    dirty = porcelain(tree)
    journal_left = (tree / JOURNAL_DIRNAME).exists()
    bench.check(
        "A7",
        dirty == [] and not journal_left,
        f"{when} the tree is clean and holds no journal: status={dirty!r} "
        f"journal_present={journal_left}",
    )


# --- part B: a holder killed for real ----------------------------------------------------------


def part_b(bench: Bench, workdir: Path, tools: Tools) -> None:
    """Kill a holder three times over, and check what the journal then allows.

    The holder imports `journal` from `tools.root`, and every refusal checked here
    is the refusal of that copy: part C re-runs this against a mutated one.
    """
    probe = workdir / "probe.py"
    probe.write_text(_PROBE_SOURCE, encoding="utf-8")

    # B1-B4 share one tree: each step is the state the previous one left.
    tree = make_killed_tree(bench, workdir, "tree-b1", "VALUE = 0", "B1", tools)
    target = tree / "sample.py"
    bench.check(
        "B1",
        target.read_text(encoding="utf-8") == "VALUE = 0\n",
        f"the mutation is on disk after the kill: sample.py={target.read_text(encoding='utf-8')!r}",
    )
    bench.check(
        "B1",
        journal_records(tree) == ["01-sample.py"],
        f"the journal holds exactly the one record: {journal_records(tree)!r}",
    )

    rerun = run_tool([str(tools.ablate), str(tools.spec_main), "--tree", str(tree)])
    bench.say(f"run over a held journal: rc={rerun.returncode}")
    bench.check("B2", rerun.returncode == 8, f"an ordinary run is refused: rc={rerun.returncode}")
    bench.check(
        "B2",
        journal_records(tree) == ["01-sample.py"]
        and target.read_text(encoding="utf-8") == "VALUE = 0\n",
        f"the refused run touched nothing: records={journal_records(tree)!r} "
        f"sample.py={target.read_text(encoding='utf-8')!r}",
    )

    proved = run_tool(
        [
            str(tools.prove_survivor),
            str(tools.spec_main),
            "ST6-inert",
            str(probe),
            "--tree",
            str(tree),
        ]
    )
    bench.say(f"survivor proof over a held journal: rc={proved.returncode}")
    bench.check("B3", proved.returncode == 8, f"the proof is refused: rc={proved.returncode}")
    bench.check(
        "B3",
        journal_records(tree) == ["01-sample.py"]
        and target.read_text(encoding="utf-8") == "VALUE = 0\n",
        f"the refused proof touched nothing: records={journal_records(tree)!r} "
        f"sample.py={target.read_text(encoding='utf-8')!r}",
    )

    restored = run_tool([str(tools.ablate), "--restore", "--tree", str(tree)])
    bench.say(f"restore: rc={restored.returncode}")
    bench.check(
        "B4",
        restored.returncode == 0 and "restored=1" in restored.stdout,
        f"the restore replays the one record: rc={restored.returncode} "
        f"marker={'restored=1' in restored.stdout}",
    )
    committed_sha = sha256_hex(head_blob(tree, "sample.py"))
    bench.check(
        "B4",
        sha256_hex(target.read_bytes()) == committed_sha,
        f"the target is the committed bytes again: sha={sha256_hex(target.read_bytes())!r} "
        f"against HEAD:sample.py={committed_sha!r}",
    )
    after_restore = porcelain(tree)
    bench.check(
        "B4",
        not (tree / JOURNAL_DIRNAME).exists() and after_restore == [],
        f"the journal is gone and the tree is clean: "
        f"journal_present={(tree / JOURNAL_DIRNAME).exists()} status={after_restore!r}",
    )

    # B5: a fresh tree, because the restore above emptied the first journal.
    tree5 = make_killed_tree(bench, workdir, "tree-b5", "VALUE = 0", "B5", tools)
    owner_path = tree5 / JOURNAL_DIRNAME / OWNER_FILENAME
    owner: dict[str, Any] = json.loads(owner_path.read_text(encoding="utf-8"))
    owner["pid"] = os.getpid()
    owner_path.write_text(json.dumps(owner), encoding="utf-8")
    bench.say(f"owner.json rewritten to name a live process: pid={os.getpid()}")
    live = run_tool([str(tools.ablate), "--restore", "--tree", str(tree5)])
    bench.check(
        "B5",
        live.returncode == 8,
        f"a restore against a live owner is refused: rc={live.returncode}",
    )
    bench.check(
        "B5",
        journal_records(tree5) == ["01-sample.py"]
        and (tree5 / "sample.py").read_text(encoding="utf-8") == "VALUE = 0\n",
        f"the refused restore touched nothing: records={journal_records(tree5)!r} "
        f"sample.py={(tree5 / 'sample.py').read_text(encoding='utf-8')!r}",
    )

    # B6: a fresh tree again, and a target in a state no record accounts for.
    tree6 = make_killed_tree(bench, workdir, "tree-b6", "VALUE = 0", "B6", tools)
    (tree6 / "sample.py").write_text(UNKNOWN_STATE_TEXT, encoding="utf-8")
    bench.say(f"target put into a state no record names: {UNKNOWN_STATE_TEXT!r}")
    unknown = run_tool([str(tools.ablate), "--restore", "--tree", str(tree6)])
    bench.check(
        "B6",
        unknown.returncode == 9,
        f"an unknown state is refused: rc={unknown.returncode}",
    )
    bench.check(
        "B6",
        journal_records(tree6) == ["01-sample.py"],
        f"the record is kept: records={journal_records(tree6)!r}",
    )
    bench.check(
        "B6",
        (tree6 / "sample.py").read_text(encoding="utf-8") == UNKNOWN_STATE_TEXT,
        f"the target was not touched: "
        f"sample.py={(tree6 / 'sample.py').read_text(encoding='utf-8')!r}",
    )


def make_killed_tree(
    bench: Bench, workdir: Path, name: str, new_text: str, case: str, tools: Tools
) -> Path:
    """A tree whose holder landed `new_text` and was killed, with the kill checked."""
    tree = build_fixture_tree(workdir / name)
    holder = workdir / "holder.py"
    if not holder.is_file():
        holder.write_text(_HOLDER_SOURCE, encoding="utf-8")
    result = run_tool([str(holder), str(tools.root), str(tree), "sample.py", "VALUE = 2", new_text])
    bench.say(
        f"in-flight holder on {name}: rc={result.returncode} record={result.stdout.strip()!r}"
    )
    bench.check(
        case,
        result.returncode == -9,
        f"the holder of {name} died of SIGKILL, not of an exit: rc={result.returncode}",
    )
    return tree


# --- part C: the mutants of the tool itself ----------------------------------------------------


def copy_tools(dest: Path) -> Tools:
    """Copy the tool's modules and specs into `dest` and name it as a tool directory.

    Every module is copied, not only the one a mutant lands on. `ablate.py` puts its
    own directory first on `sys.path` and on the suite's `PYTHONPATH`, so a copy
    carrying only some of them would import the rest from the original and the run
    would measure a mixture of the two.
    """
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "selftest").mkdir(exist_ok=True)
    for name in TOOL_MODULES:
        shutil.copy2(HERE / name, dest / name)
    for name in TOOL_SPECS:
        shutil.copy2(SELFTEST / name, dest / "selftest" / name)
    return Tools(dest)


def apply_meta_edits(bench: Bench, mutant: MetaMutant, tools: Tools) -> str | None:
    """Apply a meta-mutant's edits to a copy, or say why they could not be applied.

    Each edit is logged with its file, its anchor and the hash of the copy before and
    after, and the bytes are required to change: an edit that left the file as it was
    would make the run below measure the tool rather than a mutant of it.
    """
    for module, anchor, replacement in mutant.edits:
        path = tools.root / module
        before = path.read_bytes()
        try:
            after = replace_once_at_line_start(
                before, anchor.encode("utf-8"), replacement.encode("utf-8")
            )
        except ValueError as exc:
            return f"{module}: {exc}"
        if after == before:
            return f"{module}: the anchor was replaced by itself, the bytes did not change"
        path.write_bytes(after)
        bench.say(
            f"{mutant.ident}: {module} at anchor {anchor.strip()!r}: "
            f"{sha256_hex(before)} -> {sha256_hex(after)}"
        )
    return None


@dataclass(frozen=True)
class MetaObservation:
    """What one meta-mutant did to a copy of the tool.

    `refusal` says why its edits could not be applied to the copy; nothing ran then,
    and `cases` is empty. Otherwise `cases` are the cases of the part re-run against
    the copy, in the order they were checked, and `stopped` is empty unless the part
    raised before its end, in which case it says with what: the cases after that
    point were never run, so `cases` is not the whole of what the mutant did.
    """

    refusal: str | None
    cases: tuple[Case, ...]
    stopped: str

    @property
    def failed(self) -> frozenset[str]:
        """The names of the copy's cases that did not hold."""
        return frozenset(case.name for case in self.cases if not case.ok)


def anchor_absent_line(mutant: MetaMutant, refusal: str) -> str:
    """The refusal printed for a meta-mutant whose edits did not land on the copy."""
    return f"META-MUTANT {mutant.ident}: anchor absent in copy -- {refusal}"


def observe_meta_mutant(bench: Bench, mutant: MetaMutant, home: Path) -> MetaObservation:
    """Apply one meta-mutant to a fresh copy of the tool under `home`, and re-run its part.

    The one path from a meta-mutant to its observation: part C takes it for every row,
    and a narrowed run for the single row it selects, so the two cannot come to apply
    or observe a meta-mutant in different ways. The copy's cases are collected in a
    bench of their own, labelled with the mutant, and never in `bench`, which only
    logs the edits.
    """
    tools = copy_tools(home / "tool")
    refusal = apply_meta_edits(bench, mutant, tools)
    if refusal is not None:
        return MetaObservation(refusal, (), "")

    observed_bench = Bench(label=f"[{mutant.ident}] ")
    run_dir = home / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    stopped = ""
    try:
        if mutant.part == "A":
            part_a(observed_bench, run_dir, tools)
        else:
            part_b(observed_bench, run_dir, tools)
    # Broad on purpose: a mutated tool can break a part in any way at all, and a
    # part that stopped is reported as a mutant that was not measured, not as a
    # crash of this bench.
    except Exception as exc:
        stopped = f"the part stopped with {type(exc).__name__}: {exc}"
    return MetaObservation(None, tuple(observed_bench.cases), stopped)


def part_c(bench: Bench, workdir: Path) -> None:
    """Re-run a part against a mutated copy of the tool, once per meta-mutant.

    The cases of those re-runs are the *observation* of a meta-mutant, not results of
    this bench: they are collected in a separate bench, so a part C that works does
    not raise this bench's failure count. What comes back here is one verdict per
    meta-mutant, and the count of the ones that did not die where they had to.
    """
    for mutant in META_MUTANTS:
        observation = observe_meta_mutant(bench, mutant, workdir / "meta" / mutant.ident)
        if observation.refusal is not None:
            print(anchor_absent_line(mutant, observation.refusal))
            bench.died_elsewhere.append(mutant.ident)
            continue
        bench.meta_ran.append(mutant.ident)

        observed = observation.failed
        allowed = mutant.named | mutant.collateral
        stopped = f"; {observation.stopped}" if observation.stopped else ""
        # A part that stopped did not measure the cases after the point it stopped,
        # so its observed set is not the whole of what this mutant did.
        killed = not stopped and mutant.named <= observed and observed <= allowed
        tail = (
            f"expected {sorted(mutant.named)} (allowed {sorted(mutant.collateral)}), "
            f"observed {sorted(observed)}{stopped}"
        )
        if killed:
            print(f"META-MUTANT {mutant.ident} KILLED: {tail}")
        else:
            print(f"META-MUTANT {mutant.ident} DIED ELSEWHERE: {tail}")
            bench.died_elsewhere.append(mutant.ident)


# --- a narrowed run: one meta-mutant, for a negative control -------------------------------------


def meta_only(selected: str) -> int:
    """Run the one meta-mutant `selected` names, and print what its copy did.

    Exit status as the module docstring states it. A copy with a failing case exits 1
    even when its part stopped afterwards, because the failure was observed; a copy
    with none exits 0 only when its part ran to its end and checked at least one case,
    since a part that stopped early, or checked nothing, has not shown that nothing
    fails.
    """
    mutant = next((row for row in META_MUTANTS if row.ident == selected), None)
    if mutant is None:
        valid = ", ".join(row.ident for row in META_MUTANTS)
        print(
            f"REFUSING: {META_ONLY_VARIABLE}={selected!r} selects no meta-mutant; a selection "
            f"that selects nothing is not a green run. Valid ids: {valid}",
            file=sys.stderr,
        )
        return EXIT_META_ONLY_REFUSED

    bench = Bench()
    workdir = Path(tempfile.mkdtemp(prefix="ablation-bench-"))
    try:
        observation = observe_meta_mutant(bench, mutant, workdir / "meta" / mutant.ident)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if observation.refusal is not None:
        print(anchor_absent_line(mutant, observation.refusal))
    elif observation.stopped:
        print(
            f"META-MUTANT {mutant.ident}: {observation.stopped}; the cases after that point "
            f"were not run"
        )
    failures = sum(1 for case in observation.cases if not case.ok)
    print(
        f"{META_ONLY_VARIABLE} id={mutant.ident} copy_cases={len(observation.cases)} "
        f"copy_failures={failures}"
    )
    if failures:
        return EXIT_META_ONLY_CAUGHT
    if observation.refusal is not None or observation.stopped or not observation.cases:
        return EXIT_META_ONLY_UNMEASURED
    return 0


# --- entry point --------------------------------------------------------------------------------


def main() -> int:
    """Run parts A, B and C against fresh trees and print the marker; 0 only if nothing failed.

    With `ABLATION_BENCH_META_ONLY` in the environment, set even to the empty string,
    the run is the narrowed one instead (`meta_only`), and none of the above happens.
    """
    selected = os.environ.get(META_ONLY_VARIABLE)
    if selected is not None:
        return meta_only(selected)
    bench = Bench()
    workdir = Path(tempfile.mkdtemp(prefix="ablation-bench-"))
    try:
        part_a(bench, workdir, REAL_TOOLS)
        part_b(bench, workdir, REAL_TOOLS)
        part_c(bench, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    print(bench.marker())
    return 0 if bench.failures == 0 and not bench.died_elsewhere else 1


if __name__ == "__main__":
    sys.exit(main())
