"""The one source for what a buyer reads, and how it looks.

Every surface a buyer meets — the ``README.html`` inside a bundle, the delivery
email, the standalone explainer page — used to carry its own hand-written copy
of the same explanation. Three hand-written copies of one fact drift: they did,
and they also ended up giving the *same* risk three different visual weights,
with the weakest emphasis on the surface where the risk is most concrete.

So the text lives here once, and the styling lives here once. Callers render;
they do not rewrite.

Two constraints shape everything in this module, and both come from what a
receipt is meant to be:

* **A bundle README is held, not served.** It sits in a zip on someone else's
  disk and may be opened, offline, long after this project is gone. There is no
  stylesheet to fetch, no font to load, no network to reach: whatever it needs,
  it carries. That is why the CSS below is a string and not a file.
* **Every byte is paid on every copy.** The README is injected into each
  exported bundle, so bytes here multiply across a whole library. ``CORE_CSS``
  is deliberately small, and :func:`render_page` has a size ceiling enforced by
  a test rather than by good intentions.

The palette is the one documented for the project mark, which keeps text and
logo in agreement for free: the mark's SVGs paint with ``currentColor``.
"""

from __future__ import annotations

import html
from typing import Final

# --- Styling ----------------------------------------------------------------

#: Shared presentation for every held, offline-first HTML artifact.
#:
#: Kept to essentials on purpose: custom properties, one column, a heading
#: scale, monospace for code, the warning box, and print. No grid, no
#: components, no interaction states — an artifact that must open in an unknown
#: browser two decades from now is better served by a column that adapts than
#: by a system that adapts in steps.
#:
#: Deliberately avoids ``color-mix()`` and other recent CSS: a renderer that
#: does not understand a property here should still show readable text, so
#: nothing load-bearing is expressed in syntax younger than the format itself.
CORE_CSS: Final = """\
:root{--bg:#F1F0ED;--fg:#17191D;--bad:#B00020;--accent:#0757BA}
@media(prefers-color-scheme:dark){:root{--bg:#0D1117;--fg:#E6EDF3;--bad:#F85149;--accent:#58A6FF}}
body{margin:0 auto;max-width:38rem;padding:2rem 1.25rem 3rem;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
h1{margin:0 0 1rem;font-size:1.7rem;line-height:1.25}
h2{margin:2rem 0 .5rem;font-size:1.2rem}
a{color:var(--accent)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em;word-break:break-word}
.warning{margin:1.5rem 0;padding:.2rem 1.1rem 1rem;border:1px solid var(--bad);border-left-width:4px;border-radius:8px}
.warning h2{color:var(--bad)}
@media print{:root{--bg:#FFF;--fg:#000;--bad:#000;--accent:#000}
body{max-width:none;padding:0;font-size:11pt}
h2{page-break-after:avoid}
.warning{border-width:2px}}
"""

#: Ceiling for a rendered held page, in bytes. Enforced by a test, not by
#: convention: a budget nobody measures is a budget that gets exceeded, and
#: this one is paid on every exported copy of every receipt.
#:
#: What it protects, in numbers: the bundle README was 3400 bytes with no
#: styling at all, and a whole receipt bundle is a few kilobytes. The ceiling
#: is set where presentation stays a fraction of the page rather than half of
#: it — comfortably below the ~6800 that would mean the styling had doubled
#: the document. Headroom is deliberately a few hundred bytes: enough to add a
#: sentence, not enough to add a section without deciding to.
MAX_HELD_PAGE_BYTES: Final = 5000


def render_page(
    title: str,
    body: str,
    *,
    lang: str = "en",
    extra_head: str = "",
    extra_css: str = "",
) -> str:
    """Wrap ``body`` in a complete, self-contained HTML document.

    The result references nothing external — no stylesheet, no script, no font,
    no image — so it opens from a zip, from a disk, or from a decade-old backup
    with no network at all.

    Args:
        title: Document title as plain text; escaped here, so callers pass the
            raw value rather than pre-escaping it.
        body: Rendered body markup, without the surrounding ``<body>`` tags.
            This one is markup and is emitted as given: build it with the
            helpers in this module, which escape what they interpolate.
        lang: BCP 47 language tag for the root element.
        extra_head: Markup inserted into ``<head>`` before the title, for
            per-page metadata such as a Content-Security-Policy or a
            description. Must be complete tags.
        extra_css: Rules appended after :data:`CORE_CSS`, for presentation a
            single page needs and the shared core deliberately does not carry.

    Returns:
        A full HTML document as a string.
    """
    head_extra = f"{extra_head}\n" if extra_head else ""
    return (
        "<!doctype html>\n"
        f'<html lang="{lang}">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"{head_extra}"
        f"<title>{html.escape(title)}</title>\n"
        f"<style>{CORE_CSS}{extra_css}</style>\n"
        "</head>\n"
        "<body>\n"
        f"{body}\n"
        "</body>\n"
        "</html>\n"
    )


# --- The canonical explanation ----------------------------------------------

#: How to name the two files when the concrete name is not known (the explainer
#: page and the itch claim form are reached by people whose bundle this code
#: never saw — on the claim form, before any bundle exists at all).
_GENERIC_PRIVATE_NAME: Final = "*.private.attest"
_GENERIC_SHAREABLE_NAME: Final = "*.attest"


def _private_name(bundle_name: str | None) -> str:
    """Return the private file's name, or the generic pattern, unescaped.

    Escaping belongs to whichever renderer emits markup — the plain-text form
    must stay plain, or an email would show a buyer ``&amp;`` where their file
    name has an ``&``.
    """
    return _GENERIC_PRIVATE_NAME if bundle_name is None else f"{bundle_name}.private.attest"


def _shareable_name(bundle_name: str | None) -> str:
    """Return the shareable half's name, or the generic pattern, unescaped.

    The warning names it because it is the answer to the question the warning
    provokes: told never to send one file, a buyer needs to know what they may
    send. Same escaping rule as :func:`_private_name`.
    """
    return _GENERIC_SHAREABLE_NAME if bundle_name is None else f"{bundle_name}.attest"


#: The warning, as claims rather than as prose — ONE source, two renderings.
#:
#: This module exists to stop hand-written copies of buyer-facing text from
#: drifting, and it used to hold two of them: an HTML paragraph and a plain
#: one, written separately. They drifted, and the drift was not cosmetic.
#: Three statements survived only in the HTML — among them "a real store or
#: support agent will never need it", the one sentence that makes a phishing
#: request look wrong. The delivery email renders the PLAIN form, so that
#: sentence reached every surface except the only one an attacker imitates.
#:
#: Hence claims, not prose: both forms are generated from this tuple, so a
#: sentence cannot exist on one surface and not the other. Anything a buyer
#: must be told is added HERE, once.
#:
#: The last claim answers the question the headline provokes, and what it
#: answers with has to be within the reader's reach. It used to be
#: ``attest disclose <receipt_id>``, which is correct and useless: these words
#: are read on a claim form linked from a game page, by someone who has never
#: opened a terminal and never will. The alternative that was always true is
#: the other half of their own download — same purchases, no proof of
#: ownership — and it costs them nothing to find, because it is already on
#: their disk. Per-receipt granularity is a real thing the CLI does and the
#: spec documents (v0.1 §13); it is not what this paragraph is for.
_WARNING_HEADLINE: Final = "Never send {name} to anyone."

_WARNING_CLAIMS: Final = (
    "That file is the proof the purchase belongs to you: anyone holding it can "
    "claim to be the buyer.",
    "Because one private file covers your whole library, handing it over hands "
    "over proof for every purchase inside at once, not just the one you meant "
    "to show.",
    "A real store or support agent will never need it — they can already see your order.",
    "Keep it private, the way you would keep a paper receipt with your card number on it.",
    "If anyone needs to see what you bought, send them {shareable} instead: it "
    "shows the same purchases and gives no one a way to claim them.",
)


def private_file_warning_html(bundle_name: str | None = None) -> str:
    """The warning about the private file, as a styled block.

    This is the single most consequential thing a buyer can get wrong, so it
    gets the same emphasis everywhere it appears: same box, same colour, same
    weight. The risk does not change with the surface, so neither does its
    presentation.

    Rendered from :data:`_WARNING_CLAIMS`, the same source
    :func:`private_file_warning_text` renders — the two forms differ in markup
    and in nothing else.

    Args:
        bundle_name: Bundle stem, e.g. ``"mylibrary"``. ``None`` renders the
            generic form for contexts with no specific file in hand.

    Returns:
        A ``<div class="warning">`` block.
    """
    name = html.escape(_private_name(bundle_name))
    shareable = html.escape(_shareable_name(bundle_name))
    paragraphs = "\n".join(
        f"<p>{html.escape(claim).format(name=name, shareable=shareable)}</p>"
        for claim in _WARNING_CLAIMS
    )
    return (
        '<div class="warning">\n'
        f"<h2>{html.escape(_WARNING_HEADLINE).format(name=name)}</h2>\n"
        f"{paragraphs}\n"
        "</div>"
    )


def private_file_warning_text(bundle_name: str | None = None) -> str:
    """The same warning as plain text, for surfaces rendered by someone else.

    An email body is displayed by a client this project does not control and
    cannot verify, so it carries no markup at all — but it carries every claim
    the styled form carries. It is generated from the same
    :data:`_WARNING_CLAIMS`, because the surface an attacker can imitate is
    precisely the one that must not be missing a sentence.

    Args:
        bundle_name: Bundle stem. ``None`` renders the generic form.

    Returns:
        Plain text, no markup, one claim per line, no trailing newline.
    """
    name = _private_name(bundle_name)
    shareable = _shareable_name(bundle_name)
    sentences = [_WARNING_HEADLINE.format(name=name)]
    sentences += [claim.format(name=name, shareable=shareable) for claim in _WARNING_CLAIMS]
    # One claim per line. The email body around this breaks its own lines on
    # purpose, and the sentence that has to survive a phishing attempt is the
    # third of six: buried mid-paragraph in a single long run, it is present
    # without being read, which is the failure this text exists to prevent.
    return "\n".join(sentences)
