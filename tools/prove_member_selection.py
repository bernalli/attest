#!/usr/bin/env python3
"""Exercise the member-selection gate with isolated, executable controls.

Run after building verifiers/ts and installing site dependencies. Mutants
leave source files unchanged: Python's predicate is replaced only in this
process, JavaScript's only in the freshly compiled temporary module. The real
importers still parse every archive and the real gate decides the exit code.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attest import bundle as py_importer
from tools import importer_differential as d


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mutant",
        default="healthy",
        choices=("healthy", "python", "javascript", "both", "empty", "registry"),
    )
    parser.add_argument(
        "--astral", action="store_true", help="measure only the pinned astral cases"
    )
    args = parser.parse_args()
    if args.astral and args.mutant != "healthy":
        parser.error("--astral measures the healthy cores only")
    print(f"CONTROL: member-selection / {args.mutant}", flush=True)

    if args.mutant in ("python", "both"):
        py_importer._validate_member_selection = lambda filename: None
    if args.mutant in ("javascript", "both"):
        original_build = d.build_ts_bundle

        def without_selection(out_dir: Path) -> Path:
            path = original_build(out_dir)
            source = path.read_text()
            anchor = "function validateMemberSelection(name) {\n"
            if source.count(anchor) != 1:
                raise RuntimeError("JavaScript predicate no longer uniquely located; probe invalid")
            path.write_text(source.replace(anchor, anchor + "  return;\n"))
            return path

        d.build_ts_bundle = without_selection
    if args.mutant == "empty":
        d.DETERMINISTIC_FAMILIES["member-selection"] = lambda: []
    if args.mutant == "registry":
        del d.DETERMINISTIC_FAMILIES["member-selection"]
        d.ALL_FAMILIES = (*d.DETERMINISTIC_FAMILIES, d.MUTATION_FAMILY, d.PAIR_FAMILY)
    if args.astral:
        expected, count, seed = d.load_importer_census(d.DEFAULT_CENSUS)
        pinned = expected["member-selection"]
        expected = {
            "member-selection": d.FamilyRun(
                pinned.unit, tuple(name for name in pinned.vectors if name.startswith("astral-"))
            )
        }
        original_family = d.DETERMINISTIC_FAMILIES["member-selection"]
        d.DETERMINISTIC_FAMILIES["member-selection"] = lambda: [
            v for v in original_family() if v.name.startswith("astral-")
        ]
        return d.run(["member-selection"], count, seed, None, expected=expected, scoped=True)
    # Empty/absent controls leave the other families running: a family can
    # disappear even from the registry while the remaining corpus stays green.
    return d.main(
        [] if args.mutant in ("empty", "registry") else ["--families", "member-selection"]
    )


if __name__ == "__main__":
    raise SystemExit(main())
