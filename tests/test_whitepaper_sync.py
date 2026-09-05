"""Keep `docs/whitepaper.md` in step with what it describes.

The whitepaper opens with a machine-readable marker naming the specification
revisions and the package version its text describes::

    <!-- @whitepaper-sync v0.1-rev=N v0.2-rev=M package=X.Y.Z -->

Two checks. First, every value in the marker must equal the live one: the
newest entry of each specification's `## Revision log` and `project.version`
in `pyproject.toml`. When a specification moves and the whitepaper does not,
this test fails with a message that says which sections to re-read, so the
document cannot fall behind silently. Second, every section (`§N` or `§N.M`)
and every threat-model entry (`TM-NN`) the whitepaper cites must exist in the
document it names, so a citation cannot outlive the heading it points at.

Stdlib only. The parsers are exercised on hostile fixtures (duplicate keys,
missing keys, malformed values, no marker, two markers) as well as on the real
files, because a checker that only ever sees a well-formed marker has not been
shown to refuse a malformed one.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WHITEPAPER_PATH = REPO_ROOT / "docs/whitepaper.md"
SPEC_V01_PATH = REPO_ROOT / "docs/spec/attest-v0.1.md"
SPEC_V02_PATH = REPO_ROOT / "docs/spec/attest-v0.2.md"
THREAT_MODEL_PATH = REPO_ROOT / "docs/spec/attest-threat-model.md"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# The marker must sit in the first lines of the file: a marker buried in the
# body is one nobody sees when they open the document to edit it.
MARKER_WINDOW_LINES = 5
MARKER_KEYS: tuple[str, ...] = ("v0.1-rev", "v0.2-rev", "package")

_MARKER_RE = re.compile(r"<!--\s*@whitepaper-sync\s+(?P<body>[^>]*?)\s*-->")
_PAIR_RE = re.compile(r"^(?P<key>[A-Za-z0-9.-]+)=(?P<value>\S+)$")
_REVISION_LOG_HEADING_RE = re.compile(r"^## Revision log$", re.MULTILINE)
_REVISION_ENTRY_RE = re.compile(r"^- \*\*\d{4}-\d{2}-\d{2} \(rev (?P<rev>\d+)\)\*\*:", re.MULTILINE)
_TOP_HEADING_RE = re.compile(r"^## (\d+)\.\s")
_SUB_HEADING_RE = re.compile(r"^### (\d+\.\d+)\s")
_TM_HEADING_RE = re.compile(r"^#### TM-(\d+)\b", re.MULTILINE)
# Citation tokens, scanned in document order within one paragraph. A version
# token (or a threat-model name) sets the document that later `§` references
# in the same paragraph belong to.
_CITATION_TOKEN_RE = re.compile(
    r"(?P<version>\bv0\.[12]\b)"
    r"|(?P<threat>attest-threat-model\.md|\bthreat model\b)"
    r"|§(?P<section>\d+(?:\.\d+)?)"
    r"|\bTM-(?P<tm>\d+)\b"
)
_PARAGRAPH_SPLIT_RE = re.compile(r"\n\s*\n")
_FENCED_BLOCK_RE = re.compile(r"^ {0,3}(```|~~~).*?^ {0,3}\1", re.MULTILINE | re.DOTALL)
# The working note at the end of the file is removed before publication and
# refers to the whitepaper's own sections with `§`; it is not part of the text.
_WORKING_NOTE_HEADING_RE = re.compile(r"^## Part C\b", re.MULTILINE)


class MarkerError(ValueError):
    """The sync marker is absent, duplicated, or malformed."""


def parse_marker(text: str, window_lines: int = MARKER_WINDOW_LINES) -> dict[str, str]:
    """Return the marker's key/value pairs, or raise `MarkerError` naming the defect."""
    head = "\n".join(text.splitlines()[:window_lines])
    matches = list(_MARKER_RE.finditer(head))
    if not matches:
        raise MarkerError(
            f"no `<!-- @whitepaper-sync ... -->` marker in the first {window_lines} lines"
        )
    if len(matches) > 1:
        raise MarkerError(f"{len(matches)} sync markers found; exactly one is allowed")
    pairs: dict[str, str] = {}
    for token in matches[0].group("body").split():
        pair = _PAIR_RE.match(token)
        if pair is None:
            raise MarkerError(f"malformed marker token {token!r}; expected key=value")
        key = pair.group("key")
        if key in pairs:
            raise MarkerError(f"duplicate marker key {key!r}")
        pairs[key] = pair.group("value")
    missing = [key for key in MARKER_KEYS if key not in pairs]
    if missing:
        raise MarkerError(f"marker is missing {missing}")
    extra = sorted(set(pairs) - set(MARKER_KEYS))
    if extra:
        raise MarkerError(f"marker carries unknown keys {extra}")
    for key in ("v0.1-rev", "v0.2-rev"):
        if not pairs[key].isdigit():
            raise MarkerError(f"marker value for {key!r} must be an integer, got {pairs[key]!r}")
    return pairs


def latest_revision(spec_text: str) -> int:
    """The highest `rev N` in the specification's `## Revision log`, which must lead the log."""
    heading = _REVISION_LOG_HEADING_RE.search(spec_text)
    if heading is None:
        raise ValueError("specification has no `## Revision log` heading")
    entries = [int(m.group("rev")) for m in _REVISION_ENTRY_RE.finditer(spec_text[heading.end() :])]
    if not entries:
        raise ValueError("revision log has no `- **YYYY-MM-DD (rev N)**:` entry")
    newest = max(entries)
    if entries[0] != newest:
        raise ValueError(
            f"revision log is not newest-first: leads with rev {entries[0]}, max {newest}"
        )
    return newest


def package_version(pyproject_text: str) -> str:
    """`project.version` from a pyproject document."""
    data = tomllib.loads(pyproject_text)
    project = data.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject has no [project] table")
    version = project.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject [project] has no string `version`")
    return version


def parse_headings(spec_text: str) -> set[str]:
    """Map `## N.` and `### N.M` headings to the `§N` / `§N.M` tokens a citation uses."""
    headings: set[str] = set()
    for line in spec_text.splitlines():
        top = _TOP_HEADING_RE.match(line)
        if top is not None:
            headings.add(top.group(1))
            continue
        sub = _SUB_HEADING_RE.match(line)
        if sub is not None:
            headings.add(sub.group(1))
    return headings


def parse_tm_ids(threat_model_text: str) -> set[int]:
    """Every `#### TM-NN` entry id in the threat model."""
    return {int(m.group(1)) for m in _TM_HEADING_RE.finditer(threat_model_text)}


def whitepaper_body(text: str) -> str:
    """The published text: everything before the working note, with code fences removed."""
    note = _WORKING_NOTE_HEADING_RE.search(text)
    body = text if note is None else text[: note.start()]
    return _FENCED_BLOCK_RE.sub("", body)


def _paragraphs(body: str) -> list[str]:
    """Blocks split on blank lines; inside a table, every row is its own block.

    A Markdown table has no blank lines between rows, so without this rule a
    document named in one row would scope the `§` citations of every row
    below it.
    """
    blocks: list[str] = []
    for block in _PARAGRAPH_SPLIT_RE.split(body):
        lines = block.splitlines()
        if lines and all(line.lstrip().startswith("|") for line in lines):
            blocks.extend(lines)
        else:
            blocks.append(block)
    return blocks


def find_dangling_citations(
    body: str,
    headings: dict[str, set[str]],
    tm_ids: set[int],
) -> list[str]:
    """Citations that name a section or TM entry the cited document does not have.

    `headings` maps a document key (`"v0.1"`, `"v0.2"`, `"threat model"`) to
    its section tokens. A `§` reference binds to the most recent document
    token in its paragraph; a paragraph that cites `§` without naming any
    document is reported, because an unscoped citation cannot be checked.
    """
    problems: list[str] = []
    for index, paragraph in enumerate(_paragraphs(body), start=1):
        scope: str | None = None
        for token in _CITATION_TOKEN_RE.finditer(paragraph):
            if token.group("version") is not None:
                scope = token.group("version")
            elif token.group("threat") is not None:
                scope = "threat model"
            elif token.group("tm") is not None:
                tm = int(token.group("tm"))
                if tm not in tm_ids:
                    problems.append(f"paragraph {index}: TM-{tm} is not in the threat model")
            else:
                section = token.group("section")
                if scope is None:
                    problems.append(
                        f"paragraph {index}: §{section} is cited without naming a document"
                    )
                elif section not in headings[scope]:
                    problems.append(f"paragraph {index}: {scope} has no §{section}")
    return problems


# --- parser property tests -------------------------------------------------


def test_parse_marker_accepts_well_formed() -> None:
    text = "<!-- @whitepaper-sync v0.1-rev=16 v0.2-rev=11 package=0.9.1 -->\n# Title\n"
    assert parse_marker(text) == {"v0.1-rev": "16", "v0.2-rev": "11", "package": "0.9.1"}


def test_parse_marker_accepts_any_key_order_and_spacing() -> None:
    text = "# Title\n<!--   @whitepaper-sync   package=1.0.0  v0.2-rev=2 v0.1-rev=1 -->\n"
    assert parse_marker(text) == {"v0.1-rev": "1", "v0.2-rev": "2", "package": "1.0.0"}


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("# Title\n\nbody only\n", "no `<!-- @whitepaper-sync"),
        (
            "<!-- @whitepaper-sync v0.1-rev=1 v0.2-rev=1 package=1 -->\n"
            "<!-- @whitepaper-sync v0.1-rev=1 v0.2-rev=1 package=1 -->\n",
            "2 sync markers",
        ),
        ("<!-- @whitepaper-sync v0.1-rev=1 v0.1-rev=2 v0.2-rev=1 package=1 -->\n", "duplicate"),
        ("<!-- @whitepaper-sync v0.1-rev=1 package=1 -->\n", "missing ['v0.2-rev']"),
        ("<!-- @whitepaper-sync v0.1-rev=1 v0.2-rev=1 package=1 extra=1 -->\n", "unknown keys"),
        ("<!-- @whitepaper-sync v0.1-rev=one v0.2-rev=1 package=1 -->\n", "must be an integer"),
        ("<!-- @whitepaper-sync v0.1-rev v0.2-rev=1 package=1 -->\n", "malformed marker token"),
        ("<!-- @whitepaper-sync v0.1-rev=1 v0.2-rev=1 package= -->\n", "malformed marker token"),
    ],
)
def test_parse_marker_refuses_malformed(text: str, fragment: str) -> None:
    with pytest.raises(MarkerError, match=re.escape(fragment)):
        parse_marker(text)


def test_parse_marker_ignores_marker_outside_window() -> None:
    marker = "<!-- @whitepaper-sync v0.1-rev=1 v0.2-rev=1 package=1 -->\n"
    text = "\n" * MARKER_WINDOW_LINES + marker
    with pytest.raises(MarkerError, match="no `<!-- @whitepaper-sync"):
        parse_marker(text)


def test_latest_revision_reads_newest_first_log() -> None:
    log = (
        "## Revision log\n\n"
        "- **2026-09-03 (rev 16)**: a — vectors: none\n"
        "- **2026-09-01 (rev 13)**: b — vectors: none\n"
    )
    assert latest_revision("# spec\n\n" + log) == 16


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("# spec\n\nno log here\n", "no `## Revision log`"),
        ("## Revision log\n\nprose only\n", "no `- **YYYY-MM-DD (rev N)**:` entry"),
        (
            "## Revision log\n\n- **2026-09-01 (rev 2)**: a\n- **2026-09-03 (rev 5)**: b\n",
            "not newest-first",
        ),
    ],
)
def test_latest_revision_refuses_malformed(text: str, fragment: str) -> None:
    with pytest.raises(ValueError, match=re.escape(fragment)):
        latest_revision(text)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ('[tool.x]\nname = "y"\n', "no [project] table"),
        ('[project]\nname = "y"\n', "no string `version`"),
        ("[project]\nversion = 1\n", "no string `version`"),
    ],
)
def test_package_version_refuses_malformed(text: str, fragment: str) -> None:
    with pytest.raises(ValueError, match=re.escape(fragment)):
        package_version(text)


def test_parse_headings_maps_top_and_sub_headings() -> None:
    spec = "## 2. Scope\n\n### 8.1 Commitment\n\n#### 8.1.1 not a section\n## Revision log\n"
    assert parse_headings(spec) == {"2", "8.1"}


def test_find_dangling_citations_scopes_by_paragraph() -> None:
    headings = {"v0.1": {"8", "8.1"}, "v0.2": {"17", "17.3"}, "threat model": {"7"}}
    body = (
        "Bound by v0.1 §8 and §8.1, then v0.2 §17.3.\n\n"
        "Out of scope: threat model §7 and TM-74.\n\n"
        "Bare §8 with no document.\n\n"
        "v0.2 §8.1 does not exist there.\n\n"
        "threat model TM-99 does not exist.\n\n"
        "| a | v0.1 §8 |\n"
        "| b | §17 without a document of its own |\n"
    )
    assert find_dangling_citations(body, headings, {74}) == [
        "paragraph 3: §8 is cited without naming a document",
        "paragraph 4: v0.2 has no §8.1",
        "paragraph 5: TM-99 is not in the threat model",
        "paragraph 7: §17 is cited without naming a document",
    ]


def test_whitepaper_body_drops_working_note_and_fences() -> None:
    text = "# T\n\nv0.1 §1\n\n```\nv0.2 §999\n```\n\n## Part C — note\n\n§5 of the whitepaper\n"
    assert whitepaper_body(text) == "# T\n\nv0.1 §1\n\n\n\n"


# --- the gate on the real files --------------------------------------------


def _real_marker() -> dict[str, str]:
    return parse_marker(WHITEPAPER_PATH.read_text(encoding="utf-8"))


def test_whitepaper_describes_the_current_specifications() -> None:
    """Fails when a specification moves and the whitepaper's marker does not."""
    marker = _real_marker()
    live = {
        "v0.1": latest_revision(SPEC_V01_PATH.read_text(encoding="utf-8")),
        "v0.2": latest_revision(SPEC_V02_PATH.read_text(encoding="utf-8")),
    }
    problems: list[str] = []
    for spec, current in live.items():
        described = int(marker[f"{spec}-rev"])
        if described != current:
            problems.append(
                f"the whitepaper describes {spec} rev {described} but the specification is "
                f"at rev {current}: re-read the sections that cite the changed material and "
                f"update the marker in docs/whitepaper.md"
            )
    assert not problems, "\n".join(problems)


def test_whitepaper_describes_the_current_package_version() -> None:
    marker = _real_marker()
    current = package_version(PYPROJECT_PATH.read_text(encoding="utf-8"))
    assert marker["package"] == current, (
        f"the whitepaper describes package version {marker['package']} but pyproject.toml is "
        f"at {current}: re-read the sections that describe shipped behaviour and update the "
        f"marker in docs/whitepaper.md"
    )


def test_whitepaper_citations_resolve() -> None:
    """Every `§N`, `§N.M` and `TM-NN` the whitepaper cites exists in the document it names."""
    headings = {
        "v0.1": parse_headings(SPEC_V01_PATH.read_text(encoding="utf-8")),
        "v0.2": parse_headings(SPEC_V02_PATH.read_text(encoding="utf-8")),
        "threat model": parse_headings(THREAT_MODEL_PATH.read_text(encoding="utf-8")),
    }
    tm_ids = parse_tm_ids(THREAT_MODEL_PATH.read_text(encoding="utf-8"))
    assert tm_ids, "threat model has no `#### TM-NN` entries"
    body = whitepaper_body(WHITEPAPER_PATH.read_text(encoding="utf-8"))
    problems = find_dangling_citations(body, headings, tm_ids)
    assert not problems, "\n".join(problems)
