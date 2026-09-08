"""Run the four T2 mutants and record what each one actually kills.

WHY A SCRIPT AND NOT FOUR HAND EDITS

Each mutant is: back the file up, inject ONE defect, run the tests the plan
predicts go red, read the MESSAGE of each red (not the colour), restore, and
write a transcript named in advance. Doing that by hand four times is four
chances to leave a mutation on disk, and one chance in four to read "red" as
"covered" without looking at why.

TWO TRAPS THIS SCRIPT EXISTS TO AVOID, both measured on this repo:

* **A mutation at EQUAL BYTE COUNT does not invalidate the `.pyc`.** If the
  edit and the restore happen inside the same second and the size does not
  change, Python reuses the MUTATED bytecode while the source on disk is
  already correct. The symptom is that an import prints one thing and `grep`
  prints another. Every restore here is followed by an explicit `touch` and the
  caches are cleared.
* **A mutant that dies on the SCHEMA proves nothing about the PROPERTY.** A red
  that comes from a `KeyError` on a fixture, or from an import failing, means
  the injected defect broke the shape before reaching the invariant. So each
  mutant declares the marker its red must carry, and a red WITHOUT that marker
  is reported as "died elsewhere" — which is not a kill.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

TREE = Path("<tree>")
TRANSCRIPTS = TREE / "tools" / "gates" / "transcripts"
PY = TREE / ".venv" / "bin" / "python"


@dataclass(frozen=True)
class Mutant:
    tag: str
    file: Path
    old: str
    new: str
    tests: tuple[str, ...]
    marker: str
    what: str


MUTANTS: tuple[Mutant, ...] = (
    Mutant(
        tag="t2a",
        file=TREE / "src" / "attest" / "trust_material.py",
        old="    if type(store) is not TrustStore:\n        return None",
        new=(
            "    if type(store) is not TrustStore:\n"
            "        if type(store) is dict and set(store) == set(_StoreData._fields):\n"
            "            return _StoreData(**store)\n"
            "        return None"
        ),
        tests=(
            "tests/test_trust_store_boundary.py::test_verify_answers_a_verdict_for_anything_but_a_snapshot",
            "tests/test_trust_store_boundary.py::test_the_evaluators_raise_for_anything_but_a_snapshot",
        ),
        marker="five-member-dict",
        what="the brand check accepts a plain dict carrying the five member names",
    ),
    Mutant(
        tag="t2b",
        file=TREE / "src" / "attest" / "trust_material.py",
        old="        fields[name] = value\n\n    return _StoreFields(**fields)",
        new=(
            "        fields[name] = value\n"
            '    chains = fields.get("chains")\n'
            "    if chains:\n"
            '        fields["chains"] = {\n'
            "            key: members[1:] if isinstance(members, list) else members\n"
            "            for key, members in chains.items()\n"
            "        }\n\n"
            "    return _StoreFields(**fields)"
        ),
        tests=("tests/test_trust_material_parse.py", "tests/test_trust_store_boundary.py"),
        # The marker is NOT optional here, and an empty one is the defect this
        # runner exists to prevent: `marker_ok` is `(not marker) or ...`, so a
        # blank marker makes the kill criterion `rc != 0` and nothing else --
        # exactly the "looked only at the exit code" reading that would have
        # called t2d a kill when pytest exited 4 on a node ID that did not
        # exist. These two tests are scoped to whole FILES, so without a marker
        # ANY red anywhere in them counts.
        marker="test_an_unreadable_chain_is_refused_not_deleted",
        what="the first member of every chain is dropped at admission",
    ),
    Mutant(
        tag="t2c",
        file=TREE / "src" / "attest" / "trust_material.py",
        # ALIASING, not shape. The first version of this mutant made
        # `TrustStore.data()` return `{"manifests": self._manifests}` and killed
        # 93 tests -- which proved nothing about INV-5: it broke the SHAPE of the
        # document, so everything downstream failed on a missing member long
        # before anything mutated what `data()` handed back. A mutant that dies
        # on the schema proves the schema.
        #
        # This one returns the internal tree ITSELF. Same shape, same values,
        # same everything a shape check can see -- the only difference is that
        # it is the snapshot's own object. Only a test that MUTATES the returned
        # tree and then re-reads the snapshot can tell.
        old=(
            "        to end.\n"
            '        """\n'
            "        return cast(dict[str, Any], canon.loads_strict(self._canonical))"
        ),
        new=('        to end.\n        """\n        return self._data'),
        tests=("tests/test_trust_material_parse.py",),
        # See t2b: a blank marker degrades the criterion to the exit code. This
        # mutant in particular already died on the SCHEMA once, and the marker
        # is what would say so a second time instead of reporting a kill.
        marker="test_mutating_a_held_manifest_changes_neither_it_nor_the_store",
        what="KeyManifest.data() hands back its own tree instead of a fresh parse (aliasing)",
    ),
    Mutant(
        tag="t2d",
        file=TREE / "src" / "attest" / "trust_material.py",
        old="",  # applied through the plugin, not by editing the source
        new="",
        tests=(
            "tests/test_vectors.py::test_vector_matches_spec_intended_result[28-transparency/a-logged-trust-unchanged]",
            "tests/test_vectors.py::test_vector_matches_spec_intended_result[37-preservation-pledge/q-tofu-publisher]",
            "tests/test_vectors.py::test_vector_matches_spec_intended_result[37-preservation-pledge/x-trust-not-borrowed-from-signer]",
            "tests/test_vectors.py::test_vector_matches_spec_intended_result[43-publisher-authority/o-tofu-authorized]",
        ),
        marker="unauthenticated_tofu",
        what="every provenance entry is remapped to tls at the boundary",
    ),
)


def _run(args: list[str], env_extra: dict[str, str] | None = None) -> tuple[int, str]:
    import os

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env_extra:
        env.update(env_extra)
    # S603 is right to ask, and the answer is local: this runs the repo's own
    # interpreter on the repo's own test files, with no input from elsewhere.
    proc = subprocess.run(  # noqa: S603
        args, cwd=TREE, capture_output=True, text=True, env=env, timeout=1800
    )
    return proc.returncode, proc.stdout + proc.stderr


def _clear_caches() -> None:
    for cache in TREE.rglob("__pycache__"):
        if ".venv" not in str(cache):
            shutil.rmtree(cache, ignore_errors=True)


def run_one(mutant: Mutant) -> bool:
    transcript = TRANSCRIPTS / f"mutant-{mutant.tag}.log"
    lines: list[str] = [
        f"# mutant {mutant.tag}: {mutant.what}",
        f"# recorded {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
    ]
    backup = mutant.file.with_suffix(".py.mutant-backup")
    applied = False
    try:
        if mutant.old:
            source = mutant.file.read_text()
            if source.count(mutant.old) != 1:
                lines.append(f"ABORT: anchor not unique ({source.count(mutant.old)} matches)")
                transcript.write_text("\n".join(lines) + "\n")
                return False
            shutil.copy2(mutant.file, backup)
            mutant.file.write_text(source.replace(mutant.old, mutant.new))
            applied = True
            _clear_caches()
            lines.append(f"# injected into {mutant.file.relative_to(TREE)}")
        else:
            lines.append("# injected through tools/gates/mutant_d_plugin.py (no source edit)")

        args = [str(PY), "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rf"]
        env_extra = None
        if not mutant.old:
            args += ["-p", "tools.gates.mutant_d_plugin"]
            env_extra = {"PYTHONPATH": str(TREE)}
        args += list(mutant.tests)

        rc, out = _run(args, env_extra)
        lines.append(f"$ {' '.join(args)}")
        lines.append(out)
        lines.append(f"exit: {rc}")

        killed = rc != 0
        marker_ok = (not mutant.marker) or (mutant.marker in out)
        lines.append("")
        lines.append(f"RED: {killed}")
        if mutant.marker:
            lines.append(f"MARKER {mutant.marker!r} present: {marker_ok}")
            if killed and not marker_ok:
                lines.append(
                    "VERDICT: died elsewhere — the red does not carry the marker this "
                    "mutant's property would produce, so it proves the shape and not "
                    "the invariant."
                )
        lines.append(
            f"VERDICT: {'KILLED' if killed and marker_ok else 'SURVIVED OR DIED ELSEWHERE'}"
        )
        return killed and marker_ok
    finally:
        if applied:
            shutil.copy2(backup, mutant.file)
            backup.unlink()
            mutant.file.touch()  # equal-byte restore must not reuse the mutated .pyc
            _clear_caches()
        transcript.write_text("\n".join(lines) + "\n")


def main() -> int:
    wanted = sys.argv[1:] or [m.tag for m in MUTANTS]
    results = {}
    for mutant in MUTANTS:
        if mutant.tag not in wanted:
            continue
        print(f"--- mutant {mutant.tag}: {mutant.what}", flush=True)
        results[mutant.tag] = run_one(mutant)
        print(f"    -> {'KILLED' if results[mutant.tag] else 'NOT KILLED'}", flush=True)
    print("\nsummary:", {k: ("killed" if v else "NOT killed") for k, v in results.items()})
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
