#!/usr/bin/env python3
"""Require a describing table row for every conformance leaf found on disk.

Authority: docs/conformance.md is a non-normative process document, not a leaf
index. vectors/README.md is the corpus index; where v0.2 has a dedicated leaf
table, that normative table takes precedence. In particular the index explicitly
delegates group 41 to v0.2 section 16.11. A mention elsewhere, or a row in the
index's partial duplicate, cannot fill a hole there. v0.1 section 15 is an early
group summary, not a complete leaf index.

The routing below records TABLE LOCATIONS, never leaves or expected counts. New
directories are always discovered, including singleton groups and directories
missing expected.json. Unknown groups must have an index table. An empty corpus,
missing table, undescribed leaf, duplicate description, or nonexistent row target
fails. Shared rows count for each explicitly named leaf; the early index uses
(a)/(b)/(c) markers and the quorum tables name boundary pairs on one row.

Like check_test_census.py, this is stdlib-only, reports each absence, and carries
a --selftest that must see defects. There is no saved census and no --update:
there is nothing to regenerate that could bless an absence. To check a COPY:

    python3 tools/check_leaf_coverage.py --spec /tmp/attest-v0.2.md

Coverage is not correctness. Descriptions are required to be nonempty, but their
meaning, expected.json contents, conformance execution, prose/count claims and
non-authoritative duplicate tables are outside this guard's scope. This parses
the repository's Markdown table conventions, not arbitrary Markdown/HTML.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
# Full leaf tables in attest-v0.2.md; the remaining groups use the corpus index.
# A removed/empty normative table MUST NOT fall back to the index.
SPEC_TABLES = {
    "26": "6",
    "28": "16.1",
    "32": "16.3",
    "33": "16.4",
    "35": "16.5",
    "36": "16.6",
    "37": "16.9",
    "38": "16.10",
    "39": "16.7",
    "40": "16.8",
    "41": "16.11",
    "42": "16.12",
    "43": "16.13",
}


class Table(NamedTuple):
    heading: str
    line: int
    header: list[str]
    rows: list[tuple[int, list[str]]]


def tables(text: str) -> list[Table]:
    """Read real tables only, with section boundaries and source line numbers."""
    # Preserve newlines so diagnostics still locate the original row.
    text = re.sub(r"<!--.*?(?:-->|\Z)", lambda m: "\n" * m[0].count("\n"), text, flags=re.S)
    lines = text.splitlines()
    result: list[Table] = []
    heading = ""
    fence = ""
    active: Table | None = None
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        marker = re.match(r"^(`{3,}|~{3,})", stripped)
        if fence:
            if re.fullmatch(re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*", stripped):
                fence = ""
            continue
        if marker:
            fence = marker[0]
            active = None
            continue
        title = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if title:
            heading = title[1]
            active = None
            continue
        if not stripped.startswith("|"):
            active = None
            continue
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", stripped.strip("|"))]
        if len(cells) >= 2 and all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
            if number >= 2 and lines[number - 2].strip().startswith("|"):
                header = [c.strip() for c in lines[number - 2].strip().strip("|").split("|")]
                if len(header) == len(cells):
                    active = Table(heading, number - 1, header, [])
                    result.append(active)
            continue
        if active:
            active.rows.append((number, cells))
    return result


def disk_groups(vectors: Path) -> dict[str, tuple[Path, list[Path]]]:
    """Walk directories, never a manifest or a list of expected leaf names."""
    if not vectors.is_dir():
        raise ValueError(f"no such corpus directory: {vectors}")
    groups: dict[str, tuple[Path, list[Path]]] = {}
    for group in sorted(p for p in vectors.iterdir() if p.is_dir()):
        code = group.name.partition("-")[0]
        if not re.fullmatch(r"[0-9]+[a-z]?", code) or code in groups:
            raise ValueError(f"invalid or ambiguous group directory: {group.name}")
        leaves: list[Path] = []

        def visit(directory: Path, found: list[Path]) -> None:
            if directory.is_symlink():
                raise ValueError(f"symlink is not a corpus directory: {directory}")
            children = sorted(p for p in directory.iterdir() if p.is_dir())
            if not children:
                found.append(directory)
            else:
                if (directory / "expected.json").is_file():
                    raise ValueError(f"leaf also contains directories: {directory}")
                for child in children:
                    visit(child, found)

        visit(group, leaves)
        groups[code] = (group, leaves)
    if not groups:
        raise ValueError(f"empty corpus: {vectors}")
    return groups


def index_range(heading: str) -> tuple[int, int] | None:
    match = re.match(r"^(\d+)(?:[\u2013-](\d+))?(?::|\s+\u2014)", heading)
    return (int(match[1]), int(match[2] or match[1])) if match else None


def check(vectors: Path, index: Path, spec: Path) -> tuple[list[str], str]:
    groups = disk_groups(vectors)
    sources = {
        index: tables(index.read_text(encoding="utf-8")),
        spec: tables(spec.read_text(encoding="utf-8")),
    }
    problems: list[str] = []
    covered: set[Path] = set()
    counted_rows: set[tuple[Path, int]] = set()
    group_tables: dict[str, list[tuple[Path, Table]]] = {code: [] for code in groups}

    # Admit every authoritative row, even when its entire group has disappeared.
    for source, parsed in sources.items():
        for table in parsed:
            if source == spec:
                section = table.heading.split(" ", 1)[0].rstrip(".")
                codes = [code for code, target in SPEC_TABLES.items() if target == section]
                if table.header != ["Leaf", "Checks"] or not codes:
                    continue
                code = codes[0]
                if code in groups:
                    group_tables[code].append((source, table))
            else:
                if table.header[:2] not in (["#", "Name"], ["Leaf", "Name"]):
                    continue
                scope = index_range(table.heading)
                if scope is None:
                    problems.append(f"{source}:{table.line}: leaf table has no group heading")
                    continue
                for candidate in groups:
                    digits = re.match(r"\d+", candidate)
                    assert digits is not None  # candidate matched [0-9]+[a-z]? in disk_groups
                    integer = int(digits[0])
                    if candidate not in SPEC_TABLES and scope[0] <= integer <= scope[1]:
                        group_tables[candidate].append((source, table))

            for line, cells in table.rows:
                location = f"{source}:{line}"
                if source == index:
                    # The singleton 14b is a group, not leaf b of group 14.
                    row_id = cells[0].strip("`")
                    id_match = re.fullmatch(r"(\d+)([a-z]?)(?:/\d+[a-z])*", row_id)
                    names = re.findall(r"`([^`]+)`", cells[1]) if len(cells) > 1 else []
                    if not id_match or not names:
                        problems.append(f"{location}: malformed leaf row")
                        continue
                    code = id_match[1]
                    if id_match[2] and len(names) == 1 and not re.match(r"[a-z]-|.*/", names[0]):
                        code += id_match[2]
                    if code in SPEC_TABLES:
                        continue  # An abbreviated duplicate is not the authority.
                    assert scope is not None  # this branch only runs after the scope-is-None
                    # continue above, in the same `else:` arm of the outer if/else
                    if not scope[0] <= int(id_match[1]) <= scope[1]:
                        problems.append(f"{location}: row {row_id} is outside its group's table")
                        continue
                    # The original 07/09/17 rows explicitly enumerate (a), (b), (c).
                    markers = re.findall(r"\(([a-z])\)", "|".join(cells[2:]))
                    tokens = [code + letter for letter in markers] if markers else names
                    description = cells[2:]
                else:
                    tokens = re.findall(r"`([^`]+)`", cells[0])
                    description = cells[1:]
                counted_rows.add((source, line))
                if not tokens or not any(c.strip() for c in description):
                    problems.append(f"{location}: empty leaf name or description")
                    continue
                if code not in groups:
                    problems.append(
                        f"{location}: row names nonexistent group {code}: {', '.join(tokens)}"
                    )
                    continue
                group, leaves = groups[code]
                aliases: dict[str, set[Path]] = {}
                for leaf in leaves:
                    relative = leaf.relative_to(group).as_posix()
                    if leaf == group:
                        alias_names = {group.name, group.name.partition("-")[2]}
                    else:
                        alias_names = {
                            relative,
                            group.name + "/" + relative,
                            group.name.partition("-")[2] + "/" + relative,
                            code + relative,
                            code + relative.partition("-")[0],
                        }
                    for name in alias_names:
                        aliases.setdefault(name, set()).add(leaf)
                for token in tokens:
                    matches = aliases.get(token, set())
                    if len(matches) != 1:
                        problems.append(
                            f"{location}: row names nonexistent or ambiguous leaf "
                            f"{group.name}/{token}"
                        )
                        continue
                    leaf = next(iter(matches))
                    if leaf in covered:
                        problems.append(
                            f"{location}: duplicate row for {leaf.relative_to(vectors)}"
                        )
                    covered.add(leaf)

    for code, (group, leaves) in groups.items():
        authority = (
            f"{spec} section {SPEC_TABLES[code]}"
            if code in SPEC_TABLES
            else f"{index} group {code}"
        )
        if not group_tables[code]:
            problems.append(f"{group.name}: no group table in {authority}")
        elif len(group_tables[code]) > 1:
            problems.append(f"{group.name}: multiple group tables in {authority}")
        for leaf in leaves:
            if leaf not in covered:
                problems.append(
                    f"UNDESCRIBED {leaf.relative_to(vectors)}: no describing row in {authority}"
                )
    total = sum(len(leaves) for _, leaves in groups.values())
    summary = (
        f"leaf coverage: {len(covered)}/{total} leaves described, "
        f"{len(counted_rows)} rows, {len(groups)} groups"
    )
    return problems, summary


def selftest() -> int:
    """Exercise the real CLI with temporary documents AND real leaf directories."""
    index_text = (
        "### 01: single\n\n| # | Name | Checks |\n| --- | --- | --- |\n"
        "| 01 | `single` | Accept. |\n"
    )
    spec_text = (
        "### 16.11 Compromise\n\n| Leaf | Checks |\n| --- | --- |\n"
        "| `41a-present` | Accept. |\n| `41b-present` | Refuse. |\n"
    )
    cases = [
        ("healthy input", index_text, spec_text, (), 0, ("3/3 leaves described",)),
        (
            "leaf on disk with no row",
            index_text,
            spec_text.replace("| `41b-present` | Refuse. |\n", ""),
            (),
            1,
            ("UNDESCRIBED 41-demo/b-present",),
        ),
        (
            "row with no leaf on disk",
            index_text,
            spec_text + "| `41c-absent` | Refuse. |\n",
            (),
            1,
            ("nonexistent or ambiguous leaf 41-demo/41c-absent",),
        ),
        (
            "group with no table",
            index_text,
            "### 16.11 Compromise\n",
            (),
            1,
            ("no group table", "UNDESCRIBED 41-demo/a-present", "UNDESCRIBED 41-demo/b-present"),
        ),
        (
            "new group with no table",
            index_text,
            spec_text,
            ("48-new/a-unregistered",),
            1,
            ("48-new: no group table", "UNDESCRIBED 48-new/a-unregistered"),
        ),
        (
            "index duplicate cannot hide missing spec row",
            index_text + "\n### 41: demo\n\n| Leaf | Name | Checks |\n| --- | --- | --- |\n"
            "| 41b | `b-present` | Refuse. |\n",
            spec_text.replace("| `41b-present` | Refuse. |\n", ""),
            (),
            1,
            ("UNDESCRIBED 41-demo/b-present",),
        ),
        (
            "fenced table is not coverage",
            index_text,
            "```markdown\n" + spec_text + "```\n",
            (),
            1,
            ("no group table", "UNDESCRIBED 41-demo/a-present"),
        ),
        (
            "commented table is not coverage",
            index_text,
            "<!--\n" + spec_text + "-->\n",
            (),
            1,
            ("no group table", "UNDESCRIBED 41-demo/a-present"),
        ),
        (
            "empty description",
            index_text,
            spec_text.replace("| Refuse. |", "| |"),
            (),
            1,
            ("empty leaf name or description", "UNDESCRIBED 41-demo/b-present"),
        ),
        (
            "duplicate row",
            index_text,
            spec_text + "| `41b-present` | Refuse. |\n",
            (),
            1,
            ("duplicate row for 41-demo/b-present",),
        ),
        (
            "row in the wrong group table",
            index_text,
            spec_text.replace("16.11", "16.10"),
            (),
            1,
            ("UNDESCRIBED 41-demo/a-present", "no group table"),
        ),
    ]
    failures = 0
    for label, index_data, spec_data, extra, status, expected in cases:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            vectors = root / "vectors"
            for leaf in ("01-single", "41-demo/a-present", "41-demo/b-present", *extra):
                (vectors / leaf).mkdir(parents=True)
            index = root / "index.md"
            spec = root / "spec.md"
            index.write_text(index_data, encoding="utf-8")
            spec.write_text(spec_data, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = main(
                    ["--vectors", str(vectors), "--index", str(index), "--spec", str(spec)]
                )
            if result == status and all(fragment in output.getvalue() for fragment in expected):
                print(f"  ok   {label}")
            else:
                failures += 1
                print(f"  FAIL {label}: exit {result}; {output.getvalue()}")
    print(f"selftest: {len(cases) - failures}/{len(cases)}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, default=REPO_ROOT / "docs/spec/vectors")
    parser.add_argument("--index", type=Path, default=REPO_ROOT / "docs/spec/vectors/README.md")
    parser.add_argument("--spec", type=Path, default=REPO_ROOT / "docs/spec/attest-v0.2.md")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    try:
        problems, summary = check(args.vectors, args.index, args.spec)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"leaf coverage: {exc}", file=sys.stderr)
        return 1
    for problem in problems:
        print(problem, file=sys.stderr)
    print(summary + (" -- FAIL" if problems else " -- PASS"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
