"""The executable half of the retired-lexicon audit.

`tests/lexicon_audit.py` says which terms this family has retired and which
surviving occurrences are allowed to stay. This module is what makes that a
property of the tree rather than a note: it enumerates every occurrence across
every tracked text file and requires each one to be accounted for.

Three things it is careful about, each of them a way the two manual sweeps
before it failed:

- It reads the tree, not a list of files someone remembered. The occurrence that
  survived both sweeps was in `docs/spec/attest-transfer-economics.md`, an annex
  neither of them had opened.
- It matches on text with the whitespace collapsed. One occurrence in the
  Internet-Draft is split across two lines — `its consent` then `gate` — and no
  line-oriented search can see it.
- It can fail, and is shown failing. A guard that has only ever been seen
  passing is not known to catch anything, so the enumerator is pointed at a
  fixture carrying a planted occurrence and must name it.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.lexicon_audit import (
    ALLOWED_PATHS,
    AUDITED,
    CONTEXT,
    PATTERNS,
    TEXT_SUFFIXES,
    VERDICTS,
    Occurrence,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _tracked_files() -> list[str]:
    """The tree as git TRACKS it, in THIS repository.

    The same shape `test_every_surface_that_renders_a_buyer_page_is_accounted_for`
    uses, and for the same reasons: walking the working tree would count a
    nested worktree or someone's scratch copy, and inherited `GIT_*` overrides
    would point the enumeration at another index. A guard that enumerates the
    wrong tree passes while defending nothing.

    A FAIL rather than a skip when git is unavailable: covering everything is
    the whole of what this is worth.
    """
    git = shutil.which("git")
    assert git is not None, "git is not on PATH"
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("GIT_"):
            del env[name]
    try:
        top = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
            [git, "-C", str(REPO_ROOT), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            env=env,
        )
        assert Path(top.stdout.strip()).resolve() == REPO_ROOT, (
            f"the enumeration would cover {top.stdout.strip()}, not {REPO_ROOT}"
        )
        completed = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
            [git, "-C", str(REPO_ROOT), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=60,
            env=env,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        pytest.fail(f"cannot enumerate the tree with `git ls-files`: {exc}")
    return [name for name in completed.stdout.decode("utf-8").split("\0") if name]


def _excerpt(flat: str, start: int, end: int) -> str:
    return flat[max(0, start - CONTEXT) : min(len(flat), end + CONTEXT)]


def enumerate_occurrences(sources: dict[str, str]) -> list[tuple[str, str, str]]:
    """The pure half: given `{path: text}`, the occurrences as (path, sha, excerpt).

    Pure so the guard can be pointed at a fixture and SEEN to catch a planted
    occurrence, instead of being trusted.
    """
    found: list[tuple[str, str, str]] = []
    for path, text in sorted(sources.items()):
        views = [text]
        # Every audited file, not the two suffixes that happen to BE markup.
        # Markdown, TypeScript comments and JSON strings carry inline tags and
        # character entities exactly as HTML does, and `con<em>sent</em> gate`
        # is one claim wherever it is written. The rendered reading is taken
        # ALONGSIDE the raw text, never instead of it, so it can only add an
        # occurrence and never hide one.
        #
        # Two equivalences this does NOT close, named here so the next reader
        # takes the guard for what it is. Markdown's own emphasis —
        # `con*sent* gate` — stays invisible to a reader of HTML, and the third
        # view that would catch it is not additive: it re-excerpts occurrences
        # already registered, so closing it means either two verdicts for one
        # sentence or making a single view canonical and rehashing `AUDITED`.
        # Format characters — a zero-width space, written literally or as an
        # entity — walk through this and through the claim rule alike, in every
        # file type; that one predates the rendered reading and is the next door
        # open, not something this closed and lost.
        from tests.rendered_text import visible_text

        views.append(visible_text(text))
        for view in dict.fromkeys(views):
            flat = " ".join(view.split())
            # One occurrence, one row. The retired NAME contains a `consent` word,
            # so both patterns match the same text at different spans; hashing each
            # span separately would ask a reader to register the same sentence
            # twice, with two verdicts that cannot disagree. Spans are taken in
            # pattern order — the name first, since it is the more specific — and a
            # later match overlapping one already taken is the same occurrence.
            spans: list[tuple[int, int]] = []
            for pattern in PATTERNS:
                for match in pattern.finditer(flat):
                    if any(match.start() < end and start < match.end() for start, end in spans):
                        continue
                    spans.append((match.start(), match.end()))
            for start, end in sorted(spans):
                excerpt = _excerpt(flat, start, end)
                found.append((path, hashlib.sha256(excerpt.encode("utf-8")).hexdigest(), excerpt))
    return list(dict.fromkeys(found))


def _tree_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for name in _tracked_files():
        path = REPO_ROOT / name
        if path.suffix.lower() not in TEXT_SUFFIXES or name in ALLOWED_PATHS:
            continue
        try:
            sources[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            pytest.fail(f"cannot audit tracked text file {name}: {exc}")
    return sources


@pytest.mark.parametrize("missing", [False, True])
def test_unreadable_tracked_text_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: bool
) -> None:
    source = tmp_path / "annex.md"
    if not missing:
        source.write_bytes(b"The consent gate applies.\n\xff")
    monkeypatch.setattr(__import__(__name__, fromlist=["REPO_ROOT"]), "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        __import__(__name__, fromlist=["_tracked_files"]), "_tracked_files", lambda: ["annex.md"]
    )
    with pytest.raises(pytest.fail.Exception, match=r"annex\.md"):
        _tree_sources()


def test_every_occurrence_of_a_retired_term_is_audited() -> None:
    """No unregistered occurrence anywhere in the tree.

    This is the property `docs/spec/attest-v0.2.md` claims in its own revision
    log — the gate renamed "throughout, here and in every cross-reference that
    names it" — and the claim is only as true as this check.
    """
    audited = {(row.path, row.sha256) for row in AUDITED}
    unaudited = [
        f"{path} {sha}\n    …{excerpt}…"
        for path, sha, excerpt in enumerate_occurrences(_tree_sources())
        if (path, sha) not in audited
    ]
    assert unaudited == [], (
        "A retired term appears where nothing accounts for it. Either the text is a "
        "residue of the rename and must be corrected, or it is a legitimate use — a "
        "negated sentence, or a different consent entirely — and must be registered "
        "in tests/lexicon_audit.py with a verdict and a reason:\n" + "\n".join(unaudited)
    )


def test_no_audited_row_describes_text_that_is_gone() -> None:
    """A row whose text no longer exists is describing the tree of a year ago,
    and would keep vouching for whatever replaced it."""
    live = {(path, sha) for path, sha, _ in enumerate_occurrences(_tree_sources())}
    stale = [
        f"{row.path} {row.sha256}\n    …{row.excerpt}…"
        for row in AUDITED
        if (row.path, row.sha256) not in live
    ]
    assert stale == [], (
        "An audited occurrence is no longer in the tree. tests/lexicon_audit.py is "
        "describing text that no longer exists:\n" + "\n".join(stale)
    )


def test_the_guard_names_a_planted_occurrence(tmp_path: Path) -> None:
    """The negative self-test, and the reason the two above are worth reading.

    The planted text is the exact shape that survived both manual sweeps: the
    retired name split across a line break, which a line-oriented search cannot
    match and this one can.
    """
    planted = {
        "annex.md": "a reader who needs the exact mechanism, its consent\ngate, or its diagnostics",
        "clean.md": "the key-authorization gate, which establishes control of a key",
    }
    found = enumerate_occurrences(planted)

    assert [path for path, _, _ in found] == ["annex.md"]
    assert "consent gate" in found[0][2]


def test_retired_term_survives_inline_markup_and_entities() -> None:
    term = "consent gate"
    for suffix in ("html", "xml", "md", "ts", "json", "txt"):
        path = f"annex.{suffix}"
        for offset in range(len(term)):
            forms = [
                term[:offset] + f"&#{ord(term[offset])};" + term[offset + 1 :],
                term[:offset] + "<!-- x -->" + term[offset:],
            ]
            for tag in ("em", "strong", "span", "tt"):
                forms.append(term[:offset] + f"<{tag}>" + term[offset:] + f"</{tag}>")
            for form in forms:
                assert any(
                    "consent gate" in excerpt
                    for _, _, excerpt in enumerate_occurrences({path: form})
                ), f"{path}: {form!r} walked through the guard"


def test_every_audited_row_carries_a_verdict_from_the_closed_list() -> None:
    for row in AUDITED:
        assert row.verdict in VERDICTS, f"{row.path}: unknown verdict {row.verdict!r}"
        assert len(row.reason) > 20, f"{row.path}: the reason has to say why, not that"


def test_the_audit_registers_no_allowed_path() -> None:
    """`ALLOWED_PATHS` and `AUDITED` are two answers to the same question, and a
    path in both would be exempt for a reason nobody has to state."""
    overlap = sorted({row.path for row in AUDITED} & ALLOWED_PATHS)
    assert overlap == [], f"registered and allowed wholesale at once: {overlap}"


def test_an_audited_row_is_a_row(tmp_path: Path) -> None:
    """The dataclass is frozen: a row cannot be edited into vouching for text it
    was never read against."""
    row = Occurrence(path="p", sha256="s", excerpt="e", verdict="NEGATED", reason="r" * 21)
    with pytest.raises(AttributeError):
        row.verdict = "OTHER-SUBJECT"  # type: ignore[misc]


# --- the rule's three copies, kept in step by something executable ----------
#
# The same rule — a purchase-role word in the predicate of a possession claim —
# is asserted in three places: here in Python for the rendered pages, and in the
# two TypeScript packages for the browser and desktop shells. They cannot share
# an import: `site` and `desktop` are separate builds, and neither can reach a
# Python module.
#
# What they CAN share is a check. Kept in step "by hand" is exactly the form of
# defect the lexicon guard above exists to remove, and it is how the retired
# name survived two sweeps: three copies, one of them corrected, and nothing
# executable to notice. This is five lines and it notices.


TS_COPIES = ("site/test/intake.test.ts", "desktop/test/card.test.ts")

_TS_LITERAL = re.compile(r"ASSERTS_PURCHASE_ROLE\s*=\s*/(?P<body>.+?)/i", re.S)


def test_the_rule_reads_the_same_in_all_three_copies() -> None:
    """One rule, three languages, one expression."""
    from tests.test_buyer_surface import _ASSERTS_ROLE

    for path in TS_COPIES:
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        found = _TS_LITERAL.search(source)
        assert found is not None, f"{path}: no ASSERTS_PURCHASE_ROLE literal to compare"
        assert found.group("body") == _ASSERTS_ROLE.pattern, (
            f"{path} has drifted from tests/test_buyer_surface.py::_ASSERTS_ROLE.\n"
            f"  TypeScript: {found.group('body')}\n"
            f"  Python:     {_ASSERTS_ROLE.pattern}"
        )
