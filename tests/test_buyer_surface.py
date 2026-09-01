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
EXPECTED_GENERATED = {"site/public/what-is-this.html"}


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


def test_the_private_file_warning_is_identical_across_surfaces() -> None:
    """The held bundle README and the served explainer page must carry the same
    warning, word for word — not merely the same message."""
    in_bundle = _text_of(buyer_surface.private_file_warning_html("mylibrary"))
    on_page = _text_of(buyer_surface.private_file_warning_html())

    # Only the file's name differs; everything a person reads after it matches.
    assert in_bundle.replace("mylibrary.private.attest", "*.private.attest") == on_page


def test_the_warning_names_all_three_facts_a_buyer_needs() -> None:
    """Whatever else the wording becomes, these three facts have to survive it:
    the file proves ownership, one file covers the whole library, and there is a
    safe way to prove a single purchase instead."""
    for rendered in (
        _text_of(buyer_surface.private_file_warning_html("mylibrary")),
        buyer_surface.private_file_warning_text("mylibrary"),
    ):
        assert "proof" in rendered.lower()
        assert "whole library" in rendered.lower()
        assert "attest disclose" in rendered


def test_the_plain_text_warning_carries_no_markup() -> None:
    """An email body is rendered by a client this project does not control, so
    the text form must read correctly with no styling at all."""
    rendered = buyer_surface.private_file_warning_text("mylibrary")

    assert "<" not in rendered.replace("<receipt_id>", "")
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


def test_the_sample_bundle_matches_the_current_template(tmp_path: Path) -> None:
    """The committed sample is what the site hands to anyone trying the
    verifier. When it drifts from the template, the page shows a receipt that
    no longer resembles the ones this code produces — which is exactly what had
    happened before this test existed."""
    sample = REPO_ROOT / "site/public/sample/demo.attest"
    if not sample.exists():  # pragma: no cover - the sample is committed
        pytest.skip("sample bundle not present")

    with zipfile.ZipFile(sample) as zf:
        readme = zf.read("README.html").decode("utf-8")

    assert "<style>" in readme, (
        "the committed sample bundle predates the current README template; "
        "re-run .venv/bin/python tools/gen_site_sample.py"
    )
    assert buyer_surface.CORE_CSS in readme
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
        "<code>",
        "</code>",
    }
    for bundle_name in HOSTILE_BUNDLE_NAMES:
        rendered = buyer_surface.private_file_warning_html(bundle_name)

        assert set(re.findall(r"<[^>]*>", rendered)) <= allowed, bundle_name


def test_the_warning_templates_use_only_the_fields_the_renderers_supply() -> None:
    """`{command}` is a hole for TRUSTED markup, and holes need a fence.

    Whatever `{command}` holds is spliced into the styled form AFTER escaping,
    so it renders as markup. That is correct for one module constant and is
    cross-site scripting the moment a claim interpolates something a merchant
    controls — and nothing else in this suite would notice, because every
    other test feeds the renderers a bundle name, not a new claim.
    """
    templates = (buyer_surface._WARNING_HEADLINE, *buyer_surface._WARNING_CLAIMS)

    for template in templates:
        fields = {
            field for _, field, _, _ in string.Formatter().parse(template) if field is not None
        }

        assert fields <= {"name", "command"}, template


def _claims_in_html(rendered: str) -> str:
    """What a person reads in the HTML form: tags dropped, entities resolved."""
    return _collapse(html.unescape(re.sub(r"<[^>]+>", " ", rendered)))


def _claims_in_text(rendered: str) -> str:
    """What a person reads in the plain form: exactly what is there.

    Deliberately NOT tag-stripped. The plain form legitimately contains
    `<receipt_id>` as literal text, and a comparison that stripped it would
    quietly demand that the two forms differ — a test enforcing the very
    drift it exists to forbid.
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


#: Every place that renders a buyer-facing page, counted from the code rather
#: than remembered. The count per file matters: a second surface added to a
#: file already on this list is exactly how the itch claim form went a whole
#: release without the private-file warning while three other surfaces had it.
EXPECTED_RENDER_PAGE_CALL_SITES = {
    "src/attest/bundle.py": 1,
    "bridge/src/attest_bridge/http.py": 2,
    "tools/gen_buyer_pages.py": 1,
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
