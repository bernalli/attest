"""Check that every CI command is either covered by an F6 gate or declared out of scope.

The plan used to assert, in prose, that the F6 gates "cover every `run:` line of
the CI that F6 can influence". Nobody had executed that claim, and it was already
false: `container_differential.py` runs in the workflow and its gate was missing
from the list. An assertion about coverage is exactly the kind of thing that is
true when written and false when read.

So the claim is derived instead. The workflow files are parsed, every command is
extracted, and each one must fall into one of two named buckets: covered by a
gate, or out of F6's perimeter with a stated reason. A command matching neither
fails this check — which is what makes the mapping below safe to write down. It
is not a count and it is not a snapshot: a command added to the CI tomorrow lands
in no bucket and turns this red, instead of quietly leaving a hole.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path

import yaml  # type: ignore[import-untyped]  # dev-only; PyYAML ships no py.typed

# The tree is overridable so the gate's negative control can run this against a
# copy of the workflows carrying an unknown command, without touching the real
# ones. A checker that cannot be pointed at a mutated input cannot be shown to
# fail, and a check nobody has seen fail is a check nobody has tested.
TREE = Path(os.environ.get("CI_COVERAGE_TREE", Path(__file__).resolve().parents[2]))

# A workflow may be declared out of F6's perimeter AS A WHOLE, by name and with a
# reason -- but the LIST of workflows is never written down. Naming the two to read
# is the same defect one level up from the one this module prevents: a workflow
# added tomorrow would be exempt by construction (C-222). Measured: this tree holds
# THREE workflows, and release.yml was invisible to the pair named here.
WORKFLOWS_OUT_OF_SCOPE: dict[str, str] = {
    "release.yml": (
        "tag-triggered publish pipeline: builds, signs and publishes artefacts to "
        "PyPI/npm/GitHub Releases. F6 changes no packaging, no dependency and no "
        "released byte, and this workflow runs no test surface F6 can influence."
    ),
}


def workflow_files() -> tuple[list[Path], list[str]]:
    """(workflows to parse, workflows declared out of scope), derived now."""
    present = sorted((TREE / ".github" / "workflows").glob("*.y*ml"))
    parse, skipped = [], []
    for path in present:
        if path.name in WORKFLOWS_OUT_OF_SCOPE:
            skipped.append(path.name)
        else:
            parse.append(path)
    return parse, skipped


# substring -> the gate that measures the same thing locally
COVERED: dict[str, str] = {
    "npm ci --prefix verifiers/ts": "G-TS-B (precondition)",
    "npm run build --prefix verifiers/ts": "G-TS-B",
    "npm test --prefix verifiers/ts": "G-TS",
    "uv run --frozen pytest": "G-PY-AH/IZ/SUB/BW (segmented)",
    "ruff check": "G-LINT",
    "ruff format --check": "G-LINT",
    "mypy --strict": "G-LINT",
    "tools/check_spec_docs.py": "G-LINT",
    "tools/gen_container_corpus.py": "G-CI-PY",
    "tools/importer_differential.py": "G-CI-PY",
    "demo.store_dies": "G-CI-PY",
    "demo.pledge_dies": "G-CI-PY",
    "tools/conformance_runner.py": "G-CI-PY",
    "conformance_adapter_ts.mjs": "G-CI-PY",
    "--subset v0.2": "G-CI-PY",
    "tools/gen_vectors.py": "G-VEC",
    "tools/container_differential.py": "G-CONT-DIFF",
    "npm ci --prefix site": "G-SITE (precondition)",
    "npm test --prefix site": "G-SITE",
    "npm run build --prefix site": "G-SITE",
    "check_test_census.py site": "G-SITE",
    "check_test_census.py --selftest": "G-SITE (negative control)",
    "npm ci --prefix desktop": "G-DESK (precondition)",
    "npm run typecheck --prefix desktop": "G-DESK",
    "npm test --prefix desktop": "G-DESK",
    "npm run build --prefix desktop": "G-DESK",
    "check_test_census.py desktop": "G-DESK",
    "npm run e2e --prefix site": "G-E2E site",
    "npm run e2e --prefix desktop": "G-E2E desktop",
    "playwright install": "G-E2E (precondition)",
    "uv sync": "environment precondition (--all-packages --all-extras)",
}

# substring -> why F6 cannot influence it
OUT_OF_SCOPE: dict[str, str] = {
    "syft": "SBOM: F6 adds no dependency",
    "grype": "vulnerability scan: F6 adds no dependency",
    "grant ": "license policy: F6 adds no dependency",
    ".grant.yaml": "license policy: F6 adds no dependency",
    "uv build": "package artefacts: F6 changes no packaging",
    "tools/assert_artifacts.py": "package artefacts: F6 changes no packaging",
    "npm pack": "package artefacts: F6 changes no packaging",
    "npm ci --omit=dev": "SBOM input tree, not a test surface",
    "tools/check_formal.py": "formal shards: F6 touches no model",
    "maude": "formal shards toolchain",
    "tamarin": "formal shards toolchain",
    "xml2rfc": "Internet-Draft: F6 touches no spec text",
    "ietf/draft-": "Internet-Draft: F6 touches no spec text",
    "draft-martinalli": "Internet-Draft: F6 touches no spec text",
    "GITHUB_PATH": "runner PATH plumbing",
    "GITHUB_OUTPUT": "runner plumbing",
    "GITHUB_ENV": "runner plumbing",
    "curl ": "toolchain download",
    "sha256sum": "artefact digest, produced by steps already classified",
    "unzip ": "toolchain unpack",
    "tar xzf": "toolchain unpack",
    "chmod +x": "toolchain unpack",
    "mkdir ": "runner plumbing",
    "cp ": "runner plumbing",
    "test -s": "runner plumbing",
    "echo ": "runner plumbing",
    "cd ": "runner plumbing: directory change",
}

# A `run:` line is a shell LINE, not a command: `mkdir -p out && python tool.py` is
# two commands, and classifying the line as a whole lets the first needle that
# matches anywhere absorb everything after it. Measured: three gate-less steps
# injected into a copy of ci.yml, only ONE was named -- the other two carried
# `&& echo done` and `mkdir -p out &&`, and the plumbing bucket swallowed them
# silently while the out-of-scope COUNT moved. So the line is split into the simple
# commands it runs and EVERY fragment must classify. `|` is deliberately not a
# separator: `curl ... | sh -s -- -b ...` is one installation, and splitting it
# would report the `sh` half as unknown.
_SEPARATORS = re.compile(r"\s*(?:&&|\|\||;)\s*")


# A REDIRECTION is not a command either, and leaving it inside the fragment lets the
# same absorption happen one level down: `python tools/new.py --json >> $GITHUB_OUTPUT`
# is a NEW python surface whose OUTPUT goes to the runner's plumbing, and the
# GITHUB_OUTPUT needle swallows the surface. Measured after the split above was in
# place: of six ordinary gate-less steps injected into a copy of ci.yml, four were
# named and the two that stayed silent were this form and `... | sha256sum`. So a
# fragment is judged on the command that WRITES, with the redirection tail cut off; if
# cutting leaves nothing (a fragment that is only a redirection), it is judged whole.
_REDIRECTION = re.compile(r"\s\d?>>?")


def fragments(command: str) -> list[str]:
    """Split a run: line into the simple commands it actually executes."""
    simple: list[str] = []
    for part in _SEPARATORS.split(command):
        if not part.strip():
            continue
        head = _REDIRECTION.split(part, maxsplit=1)[0]
        simple.append(head if head.strip() else part)
    return simple


def commands() -> Iterator[tuple[str, str, str]]:
    """Yield (workflow, job, command) for every run: line, joining continuations."""
    for path in workflow_files()[0]:
        name = path.name
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job, spec in (data.get("jobs") or {}).items():
            for step in spec.get("steps") or []:
                if "run" not in step:
                    continue
                joined: list[str] = []
                buffer = ""
                for raw in str(step["run"]).splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    buffer = f"{buffer} {line}" if buffer else line
                    if line.endswith("\\"):
                        buffer = buffer[:-1].rstrip()
                        continue
                    joined.append(buffer)
                    buffer = ""
                if buffer:
                    joined.append(buffer)
                for command in joined:
                    yield name, job, command


def classify(command: str) -> tuple[str, str] | None:
    for needle, gate in COVERED.items():
        if needle in command:
            return "covered", gate
    for needle, reason in OUT_OF_SCOPE.items():
        if needle in command:
            return "out-of-scope", reason
    return None


def main() -> int:
    total = 0
    covered = 0
    unclassified: list[tuple[str, str, str]] = []
    parsed_workflows, skipped_workflows = workflow_files()
    print(f"workflows parsed: {', '.join(p.name for p in parsed_workflows) or '<none>'}")
    for name in skipped_workflows:
        print(f"workflow out of scope: {name} -- {WORKFLOWS_OUT_OF_SCOPE[name]}")
    if not parsed_workflows:
        print("ERROR: no workflow left to parse -- every workflow is declared out of scope")
        return 1
    for workflow, job, command in commands():
        for fragment in fragments(command):
            total += 1
            verdict = classify(fragment)
            if verdict is None:
                unclassified.append((workflow, job, fragment))
            elif verdict[0] == "covered":
                covered += 1
    if total == 0:
        print("ERROR: parsed 0 commands -- the workflows were not read")
        return 1
    print(
        f"parsed {total} CI commands: {covered} covered by an F6 gate, "
        f"{total - covered - len(unclassified)} out of scope, "
        f"{len(unclassified)} unclassified"
    )
    if unclassified:
        print("\nUNCLASSIFIED -- each one is a hole in the gate set or a missing reason:")
        for workflow, job, command in unclassified:
            print(f"  {workflow}:{job}: {command}")
        return 1
    print("CI_COVERAGE_COMPLETE: every CI command is covered or declared out of scope")
    return 0


if __name__ == "__main__":
    sys.exit(main())
