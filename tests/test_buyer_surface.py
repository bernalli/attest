"""The buyer-facing surfaces say one thing, once.

Three hand-written copies of the same explanation drifted apart once already:
same facts, three wordings, and — worse — three different visual weights for
one identical risk, with the weakest emphasis on the surface where the risk is
most concrete. These tests hold the parts that must not diverge again.
"""

from __future__ import annotations

import re
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
