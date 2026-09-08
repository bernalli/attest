#!/usr/bin/env python3
"""Reproduce OL-13 controls, one isolated process at a time.

Mutations affect only this process's module. Every end-to-end probe invokes the
real main(), generators, browser adapter, Python importer and committed census.
--update-census uses a temporary copy and reports whether its bytes changed.
--disable removes one guard from the actual function source before --selftest;
no production bypass switch or substitute comparison is involved.
"""

from __future__ import annotations

import argparse
import inspect
import shutil
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import importer_differential as d

# Each replacement must match exactly once in the named production function.
DISABLED = {
    "nonempty-run": ("compare_census", "if not observed:", "if False:"),
    "missing-family": (
        "compare_census",
        "for family in sorted(expected.keys() - observed.keys()):",
        "for family in ():",
    ),
    "unique-identity": (
        "compare_census",
        "if len(set(entry.vectors)) != len(entry.vectors):",
        "if False:",
    ),
    "nonempty-family": ("compare_census", "if not entry.vectors:", "if False:"),
    "registered-family": ("compare_census", "if not updating:", "if False:"),
    "same-unit": ("compare_census", "if entry.unit != pinned.unit:", "if False:"),
    "missing-leaf": ("compare_census", "if missing:", "if False:"),
    "registered-leaf": ("compare_census", "if extra and not updating:", "if False:"),
    "derived-totals": (
        "compare_census",
        "if actual < pinned_total or (actual != pinned_total and not updating):",
        "if False:",
    ),
    "update-preserves-expectation": (
        "compare_census",
        "problems: list[str] = []",
        "expected = observed if updating else expected\n    problems: list[str] = []",
    ),
    "update-admits-additions": (
        "compare_census",
        "problems: list[str] = []",
        "updating = False\n    problems: list[str] = []",
    ),
    "update-full-selection": ("census_update_scope", "families is None", "True"),
    "update-default-count": ("census_update_scope", "count == pinned_count", "True"),
    "update-default-seed": ("census_update_scope", "seed == pinned_seed", "True"),
    "update-healthy-scope": (
        "census_update_scope",
        "families is None",
        "False",
    ),
}


def disable_guard(name: str) -> int:
    function, old, new = DISABLED[name]
    source = inspect.getsource(getattr(d, function))
    assert source.count(old) == 1, (name, "guard no longer uniquely located")
    # Compile the real function with just that guard removed; the selftest and
    # every other function remain untouched. Syntax errors are probe failures.
    exec(compile(source.replace(old, new), f"<disabled {name}>", "exec"), d.__dict__)  # noqa: S102
    print(f"DISABLED: {name}", flush=True)
    return d.main(["--selftest"])


def inject(name: str) -> None:
    original = d.DETERMINISTIC_FAMILIES["out-of-range"]
    if name == "leaf":
        d.DETERMINISTIC_FAMILIES["out-of-range"] = lambda: [
            v for v in original() if v.name != "version-past-integer-boundary"
        ]
    elif name == "registry":
        del d.DETERMINISTIC_FAMILIES["out-of-range"]
        d.ALL_FAMILIES = (*d.DETERMINISTIC_FAMILIES, d.MUTATION_FAMILY, d.PAIR_FAMILY)
        declared = set(d.ALL_FAMILIES) - {d.PAIR_FAMILY}
        observed = {
            v.family for v in d.collect(list(d.ALL_FAMILIES), d.DEFAULT_COUNT, d.DEFAULT_SEED)
        }
        print(f"circular archive-family comparison: {declared == observed}", flush=True)
    elif name == "family-rename":
        del d.DETERMINISTIC_FAMILIES["out-of-range"]
        d.DETERMINISTIC_FAMILIES["out-of-range-renamed"] = lambda: [
            replace(v, family="out-of-range-renamed") for v in original()
        ]
        d.ALL_FAMILIES = (*d.DETERMINISTIC_FAMILIES, d.MUTATION_FAMILY, d.PAIR_FAMILY)
    elif name == "pair-empty":
        d.pair_vectors = lambda: []
    elif name == "divergence":
        projection = d.python_projection

        def disagree(path: Path, private: Path | None = None, **caps: int) -> dict:
            answer = projection(path, private, **caps)
            return {"outcome": d.MALFORMED} if path.name == "000000.attest" else answer

        d.python_projection = disagree
    elif name == "additions":
        baseline = d.DETERMINISTIC_FAMILIES["baseline"]
        d.DETERMINISTIC_FAMILIES["baseline"] = lambda: [
            *baseline(),
            replace(baseline()[0], name="additional-sound-bundle"),
        ]
        d.DETERMINISTIC_FAMILIES["new-family"] = lambda: [
            replace(baseline()[0], family="new-family")
        ]
        d.ALL_FAMILIES = (*d.DETERMINISTIC_FAMILIES, d.MUTATION_FAMILY, d.PAIR_FAMILY)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--disable", choices=DISABLED)
    mode.add_argument(
        "--mutant",
        choices=[
            "healthy",
            "leaf",
            "registry",
            "family-rename",
            "pair-empty",
            "divergence",
            "additions",
        ],
    )
    parser.add_argument("--update-census", action="store_true")
    args = parser.parse_args()
    if args.disable:
        return disable_guard(args.disable)
    inject(args.mutant)
    with tempfile.TemporaryDirectory(prefix="ol13-probe-") as tmp:
        path = Path(tmp) / "importer-census.json"
        shutil.copyfile(d.DEFAULT_CENSUS, path)
        before = path.read_bytes()
        argv = ["--census", str(path)] + (["--update-census"] if args.update_census else [])
        print(f"PROBE: {args.mutant}; main({argv!r})", flush=True)
        result = d.main(argv)
        print(f"census bytes changed: {path.read_bytes() != before}")
        print(f"tool exit: {result}")
        return result


if __name__ == "__main__":
    raise SystemExit(main())
