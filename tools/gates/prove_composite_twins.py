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
"""

from __future__ import annotations

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
    Regression(
        twin="transfer._verify_record",
        file="src/attest/transfer.py",
        old="    return _verify_record(record, data)",
        new="    return verify_record(record, key_manifest)",
        tests=("tests/test_transfer.py", "tests/test_trust_store_boundary.py"),
    ),
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
    log = [f"# composite twins, regression proof — {stamp}", ""]
    ok = True
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
    (TREE / "tools" / "gates" / "transcripts" / "composite-twins.log").write_text(
        "\n".join(log) + "\n"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
