"""Prove the five composite private twins are watched by something.

WHAT IS BEING PROVED, AND WHY IT NEEDED PROVING

T2 split five composite doors into a public door (which opens the handle) and a
private twin (which holds the body). Internal callers were moved onto the
twins. If one were left on the PUBLIC door, that door would receive a dict from
the snapshot's own tree and answer `False` — declaring a genuine manifest
INAUTHENTIC. Nothing raises, nothing warns; a receipt is refused for a reason
that does not exist.

A defect that silent is only caught if some test names it. So for each twin,
this script puts ONE internal caller back on the public door and requires the
suite to go RED. A twin whose regression produces no red is unwatched: the
defect can walk back in at the next refactor with every gate green.

The restore is followed by `touch` and a cache sweep: a mutation at equal byte
count inside the same second does not invalidate the `.pyc`, and Python would
keep running the mutated bytecode while the source on disk is already correct.

FOUR REGRESSIONS AND ONE PREMISE — NOT FIVE REGRESSIONS

`transfer._verify_record` has no internal caller: measured with the AST rather
than asserted, its only call site in the whole of `src/attest/` is the public
door directly above it. So the sentence this script proves — "a caller left on
the public door is noticed" — has no instance there, and the regression written
for it replaced the PUBLIC DOOR's own line with a call to itself. That turned
the suite red with a `RecursionError`, which says a stack overflow gets
noticed and says nothing whatever about the silent `False` this script exists
to catch. A mutant that dies on the shape proves the shape.

Deleting the entry would have been honest and would have left a hole: the day
someone gives that twin an internal caller, the regression becomes writable and
nothing would ask for it. So the ABSENCE is what gets watched instead. The
premise "no internal caller today" is measured on every run, and a second call
site is a failure whose message says what to do — write the regression that has
just become possible. An unwatched premise expires in silence; this one cannot.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

TREE = Path("<tree>")
PY = TREE / ".venv" / "bin" / "python"


@dataclass(frozen=True)
class Regression:
    twin: str
    file: str
    old: str
    new: str
    tests: tuple[str, ...]


REGRESSIONS: tuple[Regression, ...] = (
    Regression(
        twin="grant._verify_grant",
        file="src/attest/verify.py",
        old="grant_module._verify_grant(floor, manifest)",
        new="grant_module.verify_grant(floor, manifest)",
        tests=("tests/test_evaluate_grant.py",),
    ),
    Regression(
        twin="grant._verify_declaration",
        file="src/attest/verify.py",
        old="grant_module._verify_declaration(declaration, declaration_manifest)",
        new="grant_module.verify_declaration(declaration, declaration_manifest)",
        tests=("tests/test_evaluate_grant.py",),
    ),
    Regression(
        twin="authority._verify_authorization",
        file="src/attest/verify.py",
        old="authority_module._verify_authorization(",
        new="authority_module.verify_authorization(",
        tests=("tests/test_evaluate_authority.py",),
    ),
    Regression(
        twin="revocation._verify_record",
        file="src/attest/views.py",
        old="revocation._verify_record(record, manifest_data)",
        new="revocation.verify_record(record, manifest_data)",
        tests=("tests/test_views.py", "tests/test_trust_store_boundary.py"),
    ),
)


@dataclass(frozen=True)
class AbsentCaller:
    """A twin with no internal caller, so its regression cannot be written yet.

    What is watched here is the PREMISE, not a behaviour: as long as the only
    call site is the public door, there is nothing to put back on that door.
    The count is the whole assertion, and it is derived from the AST of every
    module under `src/attest/`, never from a list written alongside.
    """

    twin: str
    module: str
    name: str
    #: Call sites expected in the whole package. One: the public door.
    expected: int
    why: str


ABSENT: tuple[AbsentCaller, ...] = (
    AbsentCaller(
        twin="transfer._verify_record",
        module="transfer",
        name="_verify_record",
        expected=1,
        why=(
            "the public door `transfer.verify_record` is its only caller; the twin "
            "exists for symmetry with `revocation._verify_record`, which does have one"
        ),
    ),
)


def _call_sites(module: str, name: str) -> list[str]:
    """Every call to `<module>.<name>` in `src/attest/`, from the syntax tree.

    Two shapes count, and only these two can reach a module-private name: a
    bare `name(...)` inside the owning module, and a qualified
    `module.name(...)` anywhere. A grep would also match the definition, the
    docstrings that discuss it and `revocation._verify_record`, which shares the
    attribute name — the reason this reads the tree instead.

    `rglob`, not `glob`: `attest` has a subpackage (`schema`), and a sweep that
    stops at the top level would answer "no caller" for a package it never
    opened — the same narrower-population defect this script exists to catch,
    committed by the script itself. A caller reached through `getattr` would
    still be invisible here; nothing in this tree does that today, and this
    sentence is the record that it is not covered rather than not possible.
    """
    found: list[str] = []
    for path in sorted((TREE / "src" / "attest").rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        own = path.stem == module
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            hit = (own and isinstance(func, ast.Name) and func.id == name) or (
                isinstance(func, ast.Attribute)
                and func.attr == name
                and isinstance(func.value, ast.Name)
                and func.value.id == module
            )
            if hit:
                found.append(f"{path.name}:{node.lineno}")
    return found


def check_absent(premise: AbsentCaller) -> tuple[bool, str]:
    sites = _call_sites(premise.module, premise.name)
    if len(sites) == premise.expected:
        return True, f"call sites: {', '.join(sites)} — the public door, and nothing else"
    return False, (
        f"expected {premise.expected} call site, found {len(sites)}: {', '.join(sites)}.\n"
        f"An internal caller now exists, so the regression for {premise.twin} has become\n"
        "writable: move this entry back into REGRESSIONS with that caller put on the\n"
        "public door, and require the red."
    )


def _clear_caches() -> None:
    for cache in TREE.rglob("__pycache__"):
        if ".venv" not in str(cache):
            shutil.rmtree(cache, ignore_errors=True)


def run(reg: Regression) -> tuple[bool, str]:
    path = TREE / reg.file
    backup = path.with_suffix(".py.twin-backup")
    source = path.read_text()
    if source.count(reg.old) != 1:
        return False, f"anchor not unique ({source.count(reg.old)} matches) for {reg.twin}"
    shutil.copy2(path, backup)
    try:
        path.write_text(source.replace(reg.old, reg.new))
        _clear_caches()
        proc = subprocess.run(  # noqa: S603 — the repo's own interpreter on the repo's own tests: no untrusted input  # noqa: S603 — the repo's own interpreter on the repo's own tests: no untrusted input
            [str(PY), "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rf", *reg.tests],
            cwd=TREE,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            timeout=900,
        )
        tail = "\n".join(proc.stdout.splitlines()[-12:])
        return proc.returncode != 0, tail
    finally:
        shutil.copy2(backup, path)
        backup.unlink()
        path.touch()
        _clear_caches()


def main() -> int:
    wanted = sys.argv[1:]
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    scope = " ".join(wanted) if wanted else "all five (4 regressions + 1 watched premise)"
    log = [
        f"# composite twins, regression proof — {stamp}",
        f"# twins in scope for THIS run: {scope}",
        "",
    ]
    ok = True
    for premise in ABSENT:
        if wanted and premise.twin not in wanted:
            continue
        held, detail = check_absent(premise)
        ok = ok and held
        verdict = "PREMISE HOLDS (no internal caller)" if held else "PREMISE BROKEN"
        print(f"{premise.twin}: {verdict}", flush=True)
        log += [
            f"## {premise.twin}",
            "no regression is written for this twin, and that is the finding:",
            f"{premise.why}",
            "what is measured instead: the call sites of the twin, from the AST",
            f"result: {verdict}",
            detail,
            "",
        ]
    for reg in REGRESSIONS:
        if wanted and reg.twin not in wanted:
            continue
        red, tail = run(reg)
        ok = ok and red
        verdict = "RED (watched)" if red else "GREEN — UNWATCHED"
        print(f"{reg.twin}: {verdict}", flush=True)
        log += [
            f"## {reg.twin}",
            f"caller put back on the public door in {reg.file}",
            f"tests: {' '.join(reg.tests)}",
            "result: "
            + (
                "RED — the regression is named by a test"
                if red
                else "GREEN — NOTHING WATCHES THIS TWIN"
            ),
            tail,
            "",
        ]
    # A PARTIAL run writes its OWN file. This transcript is the only evidence
    # the regressions were executed, and `write_text` on one fixed path lets a
    # single-twin run silently replace the record of all five -- leaving a file
    # that documents one twin under a name that reads as five. A run that did
    # not cover every twin does not get to own the name.
    name = "composite-twins.log" if not wanted else "composite-twins-partial.log"
    (TREE / "tools" / "gates" / "transcripts" / name).write_text("\n".join(log) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
