"""The buyer-facing surfaces say one thing, once.

Three hand-written copies of the same explanation drifted apart once already:
same facts, three wordings, and — worse — three different visual weights for
one identical risk, with the weakest emphasis on the surface where the risk is
most concrete. These tests hold the parts that must not diverge again.
"""

from __future__ import annotations

import html
import os
import re
import shutil
import string
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attest import buyer_surface

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import gen_buyer_pages

REPO_ROOT = Path(__file__).resolve().parent.parent


# --- Generated pages stay generated -----------------------------------------


#: The pages the generator is expected to own, pinned here rather than read
#: from the generator itself. Parametrizing off `generated_pages()` alone would
#: make this suite agree with the generator about an empty set: if the list ever
#: returned nothing, or pointed somewhere else, zero cases would run and the
#: suite would stay green while nothing was pinned at all.
EXPECTED_GENERATED = {
    "site/public/what-is-this.html",
    "site/public/start-here.html",
    "site/public/faq.html",
    "site/public/for-sellers.html",
    "site/public/lockup.svg",
}

#: The CSP and the navigation, written out here rather than read from the
#: generator. A test that iterates the generator's own list agrees with it
#: about a link that was deleted, and one that greps for a single directive
#: passes a policy widened with `script-src *`.
EXPECTED_PAGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "font-src 'self'; base-uri 'none'; form-action 'none'"
)
EXPECTED_NAV = (
    ("start-here.html", "Start here"),
    ("faq.html", "FAQ"),
    ("for-sellers.html", "For sellers"),
    ("https://github.com/bernalli/attest/tree/main/docs/spec", "Specification"),
    ("https://github.com/bernalli/attest", "Source"),
)


def test_the_generator_still_owns_every_page_it_is_supposed_to() -> None:
    """Guards the parametrized test below against silently having no cases."""
    produced = {str(path.relative_to(REPO_ROOT)) for path in gen_buyer_pages.generated_pages()}

    assert produced == EXPECTED_GENERATED


@pytest.mark.parametrize("path", sorted(gen_buyer_pages.generated_pages()))
def test_generated_page_matches_the_committed_file(path: Path) -> None:
    """A generated page edited by hand is a copy that has started to drift.

    Regenerating is the fix, not editing the output: `.venv/bin/python
    tools/gen_buyer_pages.py`.
    """
    expected = gen_buyer_pages.generated_pages()[path]
    assert path.exists(), f"{path} is missing; run tools/gen_buyer_pages.py"
    assert path.read_text(encoding="utf-8") == expected, (
        f"{path.relative_to(REPO_ROOT)} does not match what "
        "tools/gen_buyer_pages.py produces. Re-run the generator instead of "
        "editing the generated file."
    )


# --- One warning, one wording, everywhere -----------------------------------


def _text_of(html: str) -> str:
    """Strip tags so two surfaces can be compared on what a person reads."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html)).strip()


#: Where a reader can stand, expressed as the renderers' arguments. Named: the
#: pair exists and the surface knows its stem (bundle README, download page,
#: delivery email). Unnamed: the reader has a download this code never saw
#: (the explainer page). Undelivered: nothing has been sent yet (the itch
#: claim form), so there is no file on the reader's disk to point at.
READER_CONTEXTS: dict[str, dict[str, Any]] = {
    "named": {"bundle_name": "mylibrary"},
    "unnamed": {"bundle_name": None},
    "undelivered": {"bundle_name": None, "delivered": False},
}


def _headline_and_paragraphs(rendered: str) -> tuple[str, list[str]]:
    """The warning block as a person reads it: headline, then one paragraph
    per claim, entities resolved."""
    headline = re.search(r"<h2>(.*?)</h2>", rendered, re.S)
    assert headline is not None
    paragraphs = re.findall(r"<p>(.*?)</p>", rendered, re.S)
    return html.unescape(headline.group(1)), [html.unescape(p) for p in paragraphs]


def _files_named(text: str) -> list[str]:
    """Every token in `text` that reads as a file name ending in `.attest`.

    A bare suffix such as `.attest` or `.private.attest`, used to DESCRIBE a
    file by the rule its name follows, is not a file name and is not counted;
    a glob such as `*.attest` is, because a reader takes it for one.
    """
    names = []
    for token in text.split():
        token = token.lstrip("(").rstrip(".,:;)")
        if token.endswith(".attest") and not token.startswith("."):
            names.append(token)
    return names


def test_the_risk_is_stated_identically_wherever_the_reader_stands() -> None:
    """The bundle README, the explainer page and the claim form must carry the
    same warning about the same risk, word for word — the risk does not depend
    on what the reader holds. Only the private file's name may differ, and only
    between its concrete and generic forms."""
    risk: dict[str, list[str]] = {}
    for context, kwargs in READER_CONTEXTS.items():
        headline, paragraphs = _headline_and_paragraphs(
            buyer_surface.private_file_warning_html(**kwargs)
        )
        risk[context] = [
            sentence.replace("mylibrary.private.attest", "*.private.attest")
            for sentence in (headline, *paragraphs[:-1])
        ]

    assert risk["named"] == risk["unnamed"] == risk["undelivered"]
    # Every risk claim, on every surface — a context cannot drop one quietly.
    assert len(risk["named"]) == 1 + len(buyer_surface._WARNING_CLAIMS)


def test_only_the_answer_changes_and_it_changes_with_what_the_reader_holds() -> None:
    """The last claim answers "then what may I send?", and the honest answer
    depends on what the reader has when they read it. A surface met before
    anything is delivered may not point at a file as if it were on the
    reader's disk; a surface that knows the file names it; a surface that
    knows there is a file but not its name describes it by the rule its name
    follows. Three situations, three answers, and no more than that changes.
    """
    answers = {
        context: _headline_and_paragraphs(buyer_surface.private_file_warning_html(**kwargs))[1][-1]
        for context, kwargs in READER_CONTEXTS.items()
    }

    assert len(set(answers.values())) == len(READER_CONTEXTS)
    # Known name: the file, by the same suffix rule `bundle.export` uses.
    assert _files_named(answers["named"]) == ["mylibrary.attest"]
    # Unknown name, or no file yet: no file is named — neither a stand-in nor
    # a pattern — because the reader cannot be handed a name this code never
    # saw, and must not be told they hold something they do not.
    assert _files_named(answers["unnamed"]) == []
    assert _files_named(answers["undelivered"]) == []


def test_the_warning_names_all_three_facts_a_buyer_needs() -> None:
    """Whatever else the wording becomes, these three facts have to survive it:
    the file proves ownership, one file covers the whole library, and there is
    something safe to send in its place — named where the name is known,
    described where it is not."""
    for context, kwargs in READER_CONTEXTS.items():
        styled = buyer_surface.private_file_warning_html(**kwargs)
        plain = buyer_surface.private_file_warning_text(**kwargs)
        for read, answer in (
            (_claims_in_html(styled), _headline_and_paragraphs(styled)[1][-1]),
            (plain, plain.splitlines()[-1]),
        ):
            assert "proof" in read.lower(), context
            assert "whole library" in read.lower(), context
            if context == "named":
                assert _files_named(answer) == ["mylibrary.attest"]
            else:
                # Described by suffix, and the description has to tell the
                # two halves apart — `.attest` alone would describe both.
                assert ".attest" in answer and ".private.attest" in answer, context
                assert _files_named(answer) == [], context


@pytest.mark.parametrize("context", sorted(READER_CONTEXTS))
def test_no_surface_offers_a_pattern_that_also_matches_the_private_half(context: str) -> None:
    """`*.attest` is not a name for the shareable file: as a pattern it also
    matches `*.private.attest`, the one file the warning exists to keep at
    home. A reader who is told to send `*.attest` has been told to send both.
    """
    kwargs = READER_CONTEXTS[context]
    for rendered in (
        buyer_surface.private_file_warning_html(**kwargs),
        buyer_surface.private_file_warning_text(**kwargs),
    ):
        assert "*.attest" not in rendered
        assert "attest disclose" not in rendered


def test_a_named_bundle_cannot_be_rendered_as_undelivered() -> None:
    """A name is the name of a file the surface can hand over. A caller asking
    for a named pair that has not been delivered is confused about which
    surface it is, and the renderer refuses rather than guessing."""
    renderers = (buyer_surface.private_file_warning_html, buyer_surface.private_file_warning_text)
    for render in renderers:
        with pytest.raises(ValueError):
            render("mylibrary", delivered=False)


def test_the_plain_text_warning_carries_no_markup() -> None:
    """An email body is rendered by a client this project does not control, so
    the text form must read correctly with no styling at all.

    Nothing angle-bracketed is exempt: the warning names files, not commands,
    so there is no placeholder left for a reader to mistake for a tag.
    """
    rendered = buyer_surface.private_file_warning_text("mylibrary")

    assert "<" not in rendered
    assert "&" not in rendered


def test_the_delivery_email_uses_the_shared_warning() -> None:
    """The email is one of the three surfaces that used to reword this."""
    delivery = (REPO_ROOT / "bridge/src/attest_bridge/delivery.py").read_text(encoding="utf-8")

    assert "buyer_surface.private_file_warning_text(" in delivery


# --- Held pages carry everything they need ----------------------------------


def test_a_rendered_page_reaches_outside_itself_for_nothing() -> None:
    """Held or served, these pages must open with no network: a document that
    needs the network to look right contradicts what a receipt is for."""
    page = buyer_surface.render_page("t", "<p>body</p>")

    for external in ("<link", "<script", "@font-face", "http://", "https://", "url("):
        assert external not in page


def test_core_css_avoids_syntax_younger_than_the_documents_it_styles() -> None:
    """A held page may be opened by a browser far newer or far older than
    today's. Nothing load-bearing may be expressed in recent CSS: an unknown
    property must degrade to readable text, never to an unreadable page."""
    assert "color-mix(" not in buyer_surface.CORE_CSS
    assert ":has(" not in buyer_surface.CORE_CSS

    # The two display situations these pages actually meet.
    assert "prefers-color-scheme" in buyer_surface.CORE_CSS
    assert "@media print" in buyer_surface.CORE_CSS


def test_a_bundle_name_cannot_inject_markup_into_a_held_page() -> None:
    """The bundle name is written into the README in several places, and a
    README is opened in a browser by the person who bought something.

    Callers inside this repo pass a slug they built themselves, but `export()`
    is library API: a client that names a bundle after anything a person typed
    would otherwise be writing that person's markup into a file another person
    opens. Escaped at the point where the value becomes HTML, not by trusting
    every caller to have sanitised first.
    """
    hostile = 'x"><script>alert(1)</script>'

    warning = buyer_surface.private_file_warning_html(hostile)
    assert "<script>" not in warning
    assert "&lt;script&gt;" in warning

    page = buyer_surface.render_page(hostile, "<p>body</p>")
    assert "<script>" not in page

    from attest import bundle

    readme = bundle._render_readme(hostile)
    assert "<script>" not in readme
    assert "&lt;script&gt;" in readme


def test_a_bundle_name_containing_a_placeholder_does_not_rewrite_the_warning() -> None:
    """Substitution happens in one pass, so nothing already substituted is
    scanned again.

    With a naive sequence of `.replace()` calls, a bundle name containing the
    literal text of another placeholder gets substituted a second time inside
    the block that was just inserted — and the warning then names a private
    file that is not the one beside this bundle. A security warning that names
    the wrong file is worse than no warning.
    """
    from attest import bundle

    name = "a__BUNDLE_NAME__b"
    readme = bundle._render_readme(name)

    assert f"Never send {name}.private.attest to anyone" in readme

    name = "c__PRIVATE_WARNING__d"
    readme = bundle._render_readme(name)

    assert f"Never send {name}.private.attest to anyone" in readme
    assert readme.count('<div class="warning">') == 1


def test_the_generator_is_reproducible() -> None:
    """Running the generator twice must not produce a third state: it is run by
    hand, and a non-deterministic generator would show up as a phantom diff."""
    first = gen_buyer_pages.render_what_is_this()
    second = gen_buyer_pages.render_what_is_this()

    assert first == second


def test_start_here_carries_the_canonical_warning_for_a_reader_without_a_receipt() -> None:
    expected = buyer_surface.private_file_warning_html(delivered=False)
    assert expected in gen_buyer_pages.render_start_here()


def test_the_sample_bundle_carries_the_readme_the_template_produces_today() -> None:
    """The committed sample is what the site hands to anyone trying the
    verifier, and its README is the page a curious visitor opens. It is held
    to the template whole — not to a stylesheet and a byte budget, which is
    what this test used to check while the sample went on carrying a warning
    two rewrites old. Rewording the template is allowed; shipping a sample
    that does not say it is not. The fix is never a hand edit:
    `.venv/bin/python tools/gen_site_sample.py --refresh-readme` rewrites only
    that member and leaves the signed receipt and its proof exactly as they are.
    """
    from attest import bundle

    sample = REPO_ROOT / "site/public/sample/demo.attest"
    if not sample.exists():  # pragma: no cover - the sample is committed
        pytest.skip("sample bundle not present")

    with zipfile.ZipFile(sample) as zf:
        readme = zf.read("README.html").decode("utf-8")

    assert readme == bundle._render_readme("demo"), (
        "the committed sample's README.html is not what the current template "
        "renders; re-run .venv/bin/python tools/gen_site_sample.py --refresh-readme"
    )
    assert len(readme.encode("utf-8")) <= buyer_surface.MAX_HELD_PAGE_BYTES


def test_the_generator_runs_as_a_script() -> None:
    """It is documented as a command, so it has to work as one."""
    # Fixed argv: this interpreter and a path inside the repo, no external input.
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(REPO_ROOT / "tools/gen_buyer_pages.py")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "what-is-this.html" in result.stdout


# --- The FAQ page is derived from docs/faq.md, never transcribed -------------


def _reading_text(page: str) -> str:
    """What a reader sees, with the markup removed and nothing else changed.

    Tags are deleted rather than replaced by a space: an inline `<em>` sits
    tight against the words around it, so substituting a space would split
    `yours.` into `yours .` and make a present sentence look absent.
    """
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", page.split("<body>", 1)[1])))


def _fragment_text(fragment: str) -> str:
    """One rendered element, as a person reads it."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", fragment))).strip()


def _faq_rendered_blocks(page: str) -> list[str]:
    """Every prose block the FAQ page renders, in the order it renders them.

    A containment check answers a weaker question than the page has to satisfy:
    it cannot see a reordering, and it cannot see one lost copy of a paragraph
    that appears twice. This returns the sequence, so the comparison is on
    order and multiplicity as well as presence.
    """
    intro = re.search(r"<h1>FAQ</h1>\n(.*?)\n</section>", page, re.DOTALL)
    assert intro is not None
    rendered = [
        _fragment_text(value) for value in re.findall(r"<p>(.*?)</p>", intro.group(1), re.DOTALL)
    ]
    entries = re.findall(
        r'<section class="qa" id="[^"]+">\n(.*?)\n</section>',
        page,
        re.DOTALL,
    )
    for entry in entries:
        heading = re.search(r"<h2>(.*?)</h2>", entry, re.DOTALL)
        assert heading is not None
        rendered.append(_fragment_text(heading.group(1)))
        rendered.extend(
            _fragment_text(value) for value in re.findall(r"<p>(.*?)</p>", entry, re.DOTALL)
        )
    return rendered


def _as_read_in_markdown(block: str) -> str:
    """One source block, with its inline Markdown syntax stripped.

    The comparison is on what a person reads, because that is what the page
    has to preserve: `*yours*` and `<em>yours</em>` are the same sentence.
    """
    block = re.sub(r"`([^`]+)`", r"\1", block)
    block = re.sub(r"\*\*(.+?)\*\*", r"\1", block, flags=re.DOTALL)
    block = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"\1", block, flags=re.DOTALL)
    block = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", block)
    return re.sub(r"\s+", " ", block).strip()


def test_the_faq_page_carries_the_whole_faq() -> None:
    """Every question and every paragraph of `docs/faq.md` reaches the page.

    The page exists because a hand-made HTML copy of a document this long
    would be a second original that the first edit to the Markdown leaves
    behind. That argument only holds while the derivation is total: a
    converter that quietly dropped the paragraph it could not parse would give
    the same false confidence as the transcription it replaced, with nobody
    reading both to notice.
    """
    # Read from the file, NOT through `_faq_sections`. An oracle built out of
    # the parser under test agrees with it about what it dropped: measured, on
    # this very test — a parser mutated to discard one paragraph in three left
    # it green, because both sides of the comparison lost the same paragraphs.
    source = gen_buyer_pages.FAQ_SOURCE.read_text(encoding="utf-8")
    blocks = [b.strip() for b in re.split(r"\n[ \t]*\n", source) if b.strip()]
    blocks = [b.removeprefix("## ") for b in blocks if b != "# FAQ"]

    assert len(blocks) >= 60, "the FAQ source is far shorter than this page's reason to exist"
    expected = [_as_read_in_markdown(block) for block in blocks]
    assert _faq_rendered_blocks(gen_buyer_pages.render_faq()) == expected


def test_the_faq_page_keeps_the_answer_that_protects_the_private_file() -> None:
    """One sentence on this page is a safety instruction, not an answer.

    The other generated pages carry the private-file warning as a block; this
    one carries the same rule as prose, because it is the FAQ's own answer to
    the question a buyer asks. Pinned rather than assumed: a surface that lost
    it would still look complete, which is exactly how the itch claim form
    shipped without it.
    """
    page = _reading_text(gen_buyer_pages.render_faq())

    assert "Which file can I safely send to someone?" in page
    assert "The one without .private. in its name." in page
    assert "A real store or support agent will never need the second" in page
    # The second paragraph, and it is the sharper half: the shareable file's
    # name also ends in `.attest`, so the obvious wildcard ships the secret
    # with the rest. Pinned separately, because the completeness test cannot
    # protect it — that test derives what it expects from the same source
    # file, so a source edit that deletes this paragraph deletes the
    # expectation with it and the suite stays green.
    assert "Do not reach for a wildcard here" in page
    assert "*.attest matches casey-library.private.attest as well" in page


def test_markup_in_the_faq_source_reaches_the_page_inert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tag written into the source must be shown, never executed.

    `docs/faq.md` is prose reviewed as prose, and prose acquires angle
    brackets: the shipped file already contains `<receipt_id>` inside a code
    span. The byte-for-byte test on the committed page proves the page matches
    the generator; it cannot tell whether those bytes are safe. This can.
    """
    source = tmp_path / "faq.md"
    source.write_text(
        "# FAQ\n\n"
        "Intro with <script>alert(1)</script> and an & ampersand.\n\n"
        '## A <b onclick="alert(2)">bold</b> question?\n\n'
        "An answer holding `<receipt_id>`, a raw <img src=x onerror=alert(1)> tag, "
        'and [**safe <i>label</i>**](https://example.test/x" onmouseover="boom).\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(gen_buyer_pages, "FAQ_SOURCE", source)

    page = gen_buyer_pages.render_faq()
    rendered_body = page.split("<body>", 1)[1]

    assert "<script>" not in rendered_body
    assert "onerror" not in rendered_body.replace("&lt;img src=x onerror=alert(1)&gt;", "")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered_body
    assert '<b onclick="alert(2)">' not in rendered_body
    assert '&lt;b onclick="alert(2)"&gt;bold&lt;/b&gt;' in rendered_body
    assert "<i>label</i>" not in rendered_body
    assert 'href="https://example.test/x&quot; onmouseover=&quot;boom"' in rendered_body
    assert "<code>&lt;receipt_id&gt;</code>" in rendered_body
    # And the reader still gets the characters that were written, not entities.
    assert "<script>alert(1)</script>" in _reading_text(page)


@pytest.mark.parametrize(
    "target",
    ("threat-model.md", "javascript:alert(1)", "data:text/html,test"),
)
def test_a_link_target_the_page_must_not_emit_is_refused(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two different failures, refused by one rule.

    A relative target is relative to `docs/`, and the page is not served there:
    emitted as written it would 404 for every reader, and nothing in the
    byte-comparison test would notice — the generator and the committed file
    would agree perfectly about a broken page. A `javascript:` or `data:`
    target is the other end of the same hole, and the rule that catches the
    first has to be the rule that catches the second, or it is two rules and
    one of them will be forgotten.
    """
    source = tmp_path / "faq.md"
    source.write_text(
        f"# FAQ\n\n## A question?\n\nSee [the target]({target}).\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gen_buyer_pages, "FAQ_SOURCE", source)

    with pytest.raises(ValueError, match=re.escape(target)):
        gen_buyer_pages.render_faq()


@pytest.mark.parametrize(
    "block",
    (
        "- first item\n- second item",
        "1. first item\n2. second item",
        "> quotation",
        "```\ncode\n```",
        "    indented code",
        "Intro\n- list beginning on the second line",
        "## Question and answer share a block\nanswer",
    ),
)
def test_a_block_the_converter_cannot_render_stops_the_generator(
    block: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Structure the converter cannot render must fail loudly, not flatten.

    The converter implements headings and paragraphs, which is all the FAQ has
    ever been. Silently running a bulleted list together into one paragraph
    would keep every word and destroy the structure that made them readable —
    and the ways a block can do that are a family, not the one bullet list an
    author happens to think of. Two of these were accepted before this test
    existed: an indented block, because `strip()` ate the four spaces before
    the check could see them, and a list opening on a paragraph's second line,
    because the check only ever looked at the first.

    The message is not asserted: refusing is the property, and these blocks are
    refused by three different guards that word it three different ways.
    """
    source = tmp_path / "faq.md"
    source.write_text(
        f"# FAQ\n\nIntro.\n\n## A question?\n\nAnswer.\n\n{block}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gen_buyer_pages, "FAQ_SOURCE", source)

    with pytest.raises(ValueError):
        gen_buyer_pages.render_faq()


@pytest.mark.parametrize(
    "answer",
    (
        "***crossed***",
        "**unclosed",
        "`unclosed",
        "``code containing ` a backtick``",
        "[use `code`](https://example.test)",
    ),
)
def test_malformed_inline_markdown_is_refused(
    answer: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Emphasis this grammar does not implement must not reach a browser.

    `***x***` came out as `<strong><em>x</strong></em>`, which no browser
    parses as written: what a reader gets is whatever that browser's error
    recovery invents. A long code-span delimiter was split down the middle, and
    a link whose label held a code span stayed half-converted Markdown on the
    page. All of them are the same mistake — rendering an input the grammar
    cannot describe instead of refusing it.
    """
    source = tmp_path / "faq.md"
    source.write_text(f"# FAQ\n\n## A question?\n\n{answer}\n", encoding="utf-8")
    monkeypatch.setattr(gen_buyer_pages, "FAQ_SOURCE", source)

    with pytest.raises(ValueError, match="malformed inline Markdown"):
        gen_buyer_pages.render_faq()


@pytest.mark.parametrize(
    "document",
    (
        "# FAQ\n\n## Same?\n\nAnswer.\n\n## Same!\n\nAnswer.\n",
        "# FAQ\n\n## !!!\n\nAnswer.\n",
        "# FAQ\n\n## No answer?\n",
        "# FAQ\n\n## No answer?\n\n## Next?\n\nAnswer.\n",
    ),
)
def test_malformed_question_sequences_are_refused(
    document: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A question is a heading, a fragment id and an answer, or it is nothing.

    Two questions that slug to the same id would give the jump list two entries
    pointing at one place; a question of punctuation alone yields an empty id
    and a link to `#`; a question with no answer renders as a heading followed
    by the next heading. None of those is a page anybody meant to publish.
    """
    source = tmp_path / "faq.md"
    source.write_text(document, encoding="utf-8")
    monkeypatch.setattr(gen_buyer_pages, "FAQ_SOURCE", source)

    with pytest.raises(ValueError):
        gen_buyer_pages.render_faq()


def test_the_seller_page_states_what_a_seller_would_find_out_too_late() -> None:
    """Two facts a seller must meet before the install instructions, not after.

    Nobody issues these receipts yet, and the seller-side service is not
    published: `bridge/pyproject.toml` marks it `Private :: Do Not Upload` and
    its own setup guide says never to `pip install attest-bridge`, because that
    name could resolve to something else entirely. A page that reached the
    install step before saying either would be selling somebody a thing that
    does not exist on the index — so both are pinned, and both are pinned to
    appear ahead of the first install instruction.
    """
    rendered = gen_buyer_pages.render_for_sellers()
    page = _reading_text(rendered)

    # The closing block reads as a section: it must be named like one, or the
    # heading sequence steps over it and the section has no accessible name.
    assert '<h2 class="label label--accent">Where this honestly stands</h2>' in rendered
    assert "no seller issues attest receipts today" in page
    assert "No store issues attest receipts yet" in page
    assert "is not published" in page

    # Both orderings, not just the package one: a page that said "not
    # published" early and left adoption to the closing note would pass a test
    # that only checked the first. The adoption sentence the reader must meet
    # first is the lead's; the closing block restates it deliberately, at the
    # end, which is why the assertion names the lead's wording rather than the
    # closing block's.
    install = page.index("pip install")
    assert page.index("no seller issues attest receipts today") < install
    assert page.index("is not published") < install, (
        "the page offers an install before saying the package is not published"
    )


def test_the_wordmark_is_the_brand_file_with_only_its_colour_resolved() -> None:
    """The mark on these pages must be `logo/lockup.svg`, not a fork of it.

    The brand files are single-colour and paint with `currentColor`, so they
    take the colour of wherever they are placed. An `<img>` places them
    nowhere, so this one copy has to name a colour — and a hand-made copy with
    one value changed is a fork nobody notices has drifted. Derived, then, and
    held here to two things: that nothing but the fill changed, and that the
    fill is the same ink the stylesheet paints the text in.
    """
    brand = gen_buyer_pages.LOCKUP_SOURCE.read_text(encoding="utf-8")
    rendered = gen_buyer_pages.render_lockup()

    assert rendered == brand.replace('fill="currentColor"', f'fill="{gen_buyer_pages._INK}"')
    assert 'fill="currentColor"' not in rendered, "an <img> has no colour to inherit"
    assert f"--ink:{gen_buyer_pages._INK}" in gen_buyer_pages._PAPER_CSS, (
        "the wordmark and the text are no longer printed in the same ink"
    )


def test_a_brand_file_that_stopped_using_currentcolor_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Silently emitting some other colour is worse than failing to build."""
    source = tmp_path / "lockup.svg"
    source.write_text('<svg fill="#123456"><path d="M0 0"/></svg>', encoding="utf-8")
    monkeypatch.setattr(gen_buyer_pages, "LOCKUP_SOURCE", source)

    with pytest.raises(ValueError, match="currentColor"):
        gen_buyer_pages.render_lockup()


@pytest.mark.parametrize(
    "path", sorted(p for p in gen_buyer_pages.generated_pages() if p.suffix == ".html")
)
def test_every_generated_page_wears_the_same_chrome(path: Path) -> None:
    """The masthead, the navigation and the footer are shared or they drift.

    Four hand-kept copies of a stylesheet drift the way four hand-kept copies
    of a paragraph do, and a page that has quietly stopped matching the others
    is harder to spot than a sentence that has.
    """
    page = gen_buyer_pages.generated_pages()[path]

    assert '<header class="masthead">' in page
    # Held against constants written out above, not against the generator's own
    # values: iterating `_NAV` would agree with a `_NAV` that had lost a link,
    # `_FOOTER in page` is true of an empty `_FOOTER`, and grepping for one CSP
    # directive passes a policy widened with `script-src *`.
    assert gen_buyer_pages._NAV == EXPECTED_NAV
    assert (
        page.count(f'<meta http-equiv="Content-Security-Policy" content="{EXPECTED_PAGE_CSP}">')
        == 1
    )
    primary = re.search(r'<nav aria-label="Primary">\n(.*?)\n</nav>', page, re.DOTALL)
    assert primary is not None
    current = path.name if path.name in {href for href, _ in EXPECTED_NAV} else None
    marker = ' aria-current="page"'
    expected_links = "\n".join(
        f'<a href="{href}"{marker if href == current else ""}>{label}</a>'
        for href, label in EXPECTED_NAV
    )
    assert primary.group(1) == expected_links
    assert gen_buyer_pages._PAPER_CSS in page
    assert gen_buyer_pages._PAPER_CSS.count("@font-face") == 4
    assert "font-family:'Courier Prime'" in gen_buyer_pages._PAPER_CSS
    assert "@media print" in gen_buyer_pages._PAPER_CSS
    assert (
        "<span>Code Apache-2.0 &middot; Spec CC BY 4.0 &middot; "
        "Courier Prime under the SIL Open Font License</span>"
    ) in page
    assert '<nav aria-label="Elsewhere">' in page


def test_every_paper_text_colour_clears_wcag_aa_on_every_declared_ground() -> None:
    """The contrast argument is in a comment; this is what holds it up.

    Every ground these pages paint is flat — that is itself the decision, taken
    because the home page's texture layers make the worst case a thing you have
    to know the geometry to compute. Flat grounds can be composited exactly, so
    the claim can be a test rather than a paragraph somebody has to re-derive
    after changing a hex value.
    """
    css = gen_buyer_pages._PAPER_CSS

    def variable(name: str) -> tuple[float, ...]:
        match = re.search(rf"{re.escape(name)}:#([0-9a-fA-F]{{6}})", css)
        assert match is not None, name
        value = match.group(1)
        return tuple(int(value[index : index + 2], 16) / 255 for index in (0, 2, 4))

    def rgba(selector: str) -> tuple[tuple[float, ...], float]:
        rule = re.search(rf"{re.escape(selector)}\{{([^}}]+)\}}", css)
        assert rule is not None, selector
        value = re.search(r"background:rgba\((\d+),(\d+),(\d+),([.\d]+)\)", rule.group(1))
        assert value is not None, selector
        red, green, blue, alpha = value.groups()
        return (int(red) / 255, int(green) / 255, int(blue) / 255), float(alpha)

    def composite(
        foreground: tuple[float, ...], background: tuple[float, ...], alpha: float
    ) -> tuple[float, ...]:
        return tuple(
            front * alpha + back * (1 - alpha)
            for front, back in zip(foreground, background, strict=True)
        )

    def luminance(colour: tuple[float, ...]) -> float:
        linear = tuple(
            channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
            for channel in colour
        )
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    def contrast(first: tuple[float, ...], second: tuple[float, ...]) -> float:
        lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
        return (lighter + 0.05) / (darker + 0.05)

    paper = variable("--paper")
    grounds = [paper]
    for selector in ("code", ".warning", ".standing"):
        overlay, alpha = rgba(selector)
        grounds.append(composite(overlay, paper, alpha))

    text_colours = {
        name: variable(name)
        for name in ("--ink", "--ink-2", "--ink-3", "--ink-label", "--bordeaux", "--bordeaux-deep")
    }
    for name, foreground in text_colours.items():
        for ground in grounds:
            assert contrast(foreground, ground) >= 4.5, name

    # The one place the palette is used inverted: paper on the ink button, and
    # on the bordeaux it turns when hovered.
    assert contrast(paper, variable("--ink")) >= 4.5
    assert contrast(paper, variable("--bordeaux")) >= 4.5


def test_no_bundle_name_can_put_markup_in_the_styled_warning() -> None:
    """The styled form escapes the name and then formats — never the reverse.

    That order is safe only because the CLAIM is a constant: `str.format`
    substitutes arguments verbatim and never rescans them, so a brace arriving
    through `bundle_name` cannot become a replacement field. What this pins is
    the other half of the argument — that every tag in the block came from this
    module and none of them came from the name.
    """
    allowed = {
        '<div class="warning">',
        "</div>",
        "<h2>",
        "</h2>",
        "<p>",
        "</p>",
    }
    for bundle_name in HOSTILE_BUNDLE_NAMES:
        rendered = buyer_surface.private_file_warning_html(bundle_name)

        assert set(re.findall(r"<[^>]*>", rendered)) <= allowed, bundle_name
    undelivered = buyer_surface.private_file_warning_html(delivered=False)
    assert set(re.findall(r"<[^>]*>", undelivered)) <= allowed


def test_the_warning_templates_use_only_the_fields_the_renderers_supply() -> None:
    """Every hole in these templates is filled with an escaped value, never
    with markup, and that is a property worth a fence of its own.

    Whatever a field holds is spliced into the styled form AFTER the claim has
    been escaped, so anything markup-shaped in it renders as markup. Both
    fields here are filenames the renderers escape first, which is what makes
    the arrangement safe; a claim that interpolated trusted markup instead
    would be cross-site scripting the day its content stopped being a module
    constant — and nothing else in this suite would notice, because every
    other test feeds the renderers a bundle name, not a new claim.
    """

    def fields_of(template: str) -> set[str]:
        return {field for _, field, _, _ in string.Formatter().parse(template) if field is not None}

    for template in (buyer_surface._WARNING_HEADLINE, *buyer_surface._WARNING_CLAIMS):
        assert fields_of(template) <= {"name"}, template
    assert fields_of(buyer_surface._ANSWER_NAMED) <= {"name", "shareable"}
    # Without a name there is nothing to put in a `shareable` hole, and the
    # renderers supply none: a template that asked for one would raise, and
    # this pins that the templates never ask.
    for template in (buyer_surface._ANSWER_UNNAMED, buyer_surface._ANSWER_UNDELIVERED):
        assert fields_of(template) <= {"name"}, template
    assert set(buyer_surface._ANSWERS) == {
        buyer_surface._ANSWER_NAMED,
        buyer_surface._ANSWER_UNNAMED,
        buyer_surface._ANSWER_UNDELIVERED,
    }


def _claims_in_html(rendered: str) -> str:
    """What a person reads in the HTML form: tags dropped, entities resolved."""
    return _collapse(html.unescape(re.sub(r"<[^>]+>", " ", rendered)))


def _claims_in_text(rendered: str) -> str:
    """What a person reads in the plain form: exactly what is there.

    Deliberately NOT tag-stripped. Nothing angle-bracketed belongs in this
    form today, but stripping here would let one arrive unnoticed on one
    surface and not the other — a comparison that erases a difference is a
    test enforcing the very drift it exists to forbid.
    """
    return _collapse(rendered)


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


#: Bundle stems that exercise the shapes a renderer which escapes and then
#: formats can get wrong: braces (which `str.format` would read as fields if
#: the name were ever the template), markup, half-formed entities, whitespace,
#: and the generic `None` form the itch claim form and the explainer render.
HOSTILE_BUNDLE_NAMES = (
    None,
    "",
    "mylibrary",
    "a&b",
    "a<b>c",
    "it's",
    '"quoted"',
    "{name}",
    "{command}",
    "{",
    "}",
    "{0}",
    "{0.__class__}",
    "{name:>999999}",
    "&amp;",
    "&lt",
    "&#x27;",
    'x"><script>alert(1)</script>',
    "</p><p>injected",
    "<img src=x onerror=alert(1)>",
    "caf\u00e9\u2013\u00fcn\u00efcode",
    "line\nbreak\tand tab",
    "x" * 300,
)


def test_both_warning_forms_make_the_same_claims() -> None:
    """The two forms must say the same things — parity of claims, not bytes.

    This module exists to stop hand-written copies of buyer-facing text from
    drifting, and it held two of them. They had drifted: three statements
    lived only in the HTML form, among them "a real store or support agent
    will never need it" — the one sentence that makes a phishing request look
    wrong. The email uses the PLAIN form, so that sentence was present on
    every surface where nobody is deceiving the buyer, and absent from the
    only one an attacker can imitate.

    A parity test is what makes "one source" true instead of merely intended:
    two strings side by side in one module are two copies until something
    proves otherwise.
    """
    for bundle_name in HOSTILE_BUNDLE_NAMES:
        from_html = _claims_in_html(buyer_surface.private_file_warning_html(bundle_name))
        from_text = _claims_in_text(buyer_surface.private_file_warning_text(bundle_name))

        assert from_html == from_text, bundle_name
    # And the one context a name cannot express.
    from_html = _claims_in_html(buyer_surface.private_file_warning_html(delivered=False))
    from_text = _claims_in_text(buyer_surface.private_file_warning_text(delivered=False))
    assert from_html == from_text


#: Every place that renders a buyer-facing page, counted from the code rather
#: than remembered. The count per file matters: a second surface added to a
#: file already on this list is exactly how the itch claim form went a whole
#: release without the private-file warning while three other surfaces had it.
EXPECTED_RENDER_PAGE_CALL_SITES = {
    "src/attest/bundle.py": 1,
    "bridge/src/attest_bridge/http.py": 2,
    # One call per page it owns, deliberately not routed through a shared
    # helper: the count is what makes a fifth page visible here.
    "tools/gen_buyer_pages.py": 4,
}


def test_every_surface_that_renders_a_buyer_page_is_accounted_for() -> None:
    """A new buyer-facing page must be a decision, not a discovery.

    What this pins is that the list of surfaces is COUNTED from the code every
    time, never recalled. A remembered list is an incomplete list: the claim
    form was missing from the remembered one, and it is the first page an itch
    buyer ever sees. The same shape has cost this project twice before, both
    times by collapsing something the code knew into something a person
    remembered.

    If this fails because you added a surface: give it the private-file
    warning, give it a test that proves it carries it, then add it here.
    """
    # Files git TRACKS, not files that happen to sit on disk. Walking the
    # working tree counts whatever else lives under it — a nested worktree, a
    # build directory, someone's scratch copy — and then this guard fails for
    # a reason that has nothing to do with buyer surfaces. A test that can
    # fail for the wrong reason gets muted, and a muted guard defends nothing.
    git = shutil.which("git")
    assert git is not None, "git is not on PATH"
    # Repository selection is part of what this guard verifies. Inherited
    # Git overrides must not substitute another worktree, Git dir, or index.
    git_env = os.environ.copy()
    for name in tuple(git_env):
        if name.startswith("GIT_"):
            del git_env[name]
    # And the perimeter must be THIS repository's index. Asking a checkout
    # nested inside another repository would return someone else's file list
    # — or none at all — and a guard that counts zero surfaces passes while
    # defending nothing, which is worse than failing.
    top = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [git, "-C", str(REPO_ROOT), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env=git_env,
    )
    assert Path(top.stdout.rstrip("\n")).resolve() == REPO_ROOT.resolve()
    tracked_output = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [git, "-C", str(REPO_ROOT), "ls-files", "-z", "*.py"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env=git_env,
    ).stdout
    assert tracked_output, "git ls-files returned no tracked Python files"
    tracked = tracked_output.split("\0")

    found: dict[str, int] = {}
    for relative in sorted(name for name in tracked if name):
        path = REPO_ROOT / relative
        if any(part in {"tests", "node_modules"} for part in path.parts):
            continue  # a test that renders a page is not a surface a buyer meets
        if path.name.startswith("test_"):
            continue
        if path == REPO_ROOT / "src" / "attest" / "buyer_surface.py":
            continue  # where render_page is defined, not called
        source = path.read_text(encoding="utf-8")
        count = source.count("render_page(")
        if count:
            found[str(path.relative_to(REPO_ROOT))] = count
            # Counting the surfaces is half the guard: the claim form was on
            # nobody's list AND carried no warning, and only the second half is
            # what hurt a buyer. A file that renders a buyer page and never
            # names the warning is the same defect one rename away.
            assert "private_file_warning" in source, path

    assert found == EXPECTED_RENDER_PAGE_CALL_SITES


def test_the_surface_guard_reads_this_repository_and_not_an_inherited_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Which repository the guard interrogates is part of what it guards.

    `git` takes its index from `GIT_INDEX_FILE`, and `--show-toplevel` keeps
    answering with this checkout while `ls-files` answers from somewhere else
    entirely. A surface that exists only in the real index then goes uncounted
    and the guard passes — the exact silence it was written to break. Anything
    a caller inherited in the environment must not decide the answer.
    """
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "someone-elses-index"))
    test_every_surface_that_renders_a_buyer_page_is_accounted_for()
