"""Generate the standalone pages under `site/public/`.

These pages explain the same things a bundle's own `README.html` explains, to
the same reader. When each surface kept its own hand-written copy of that
explanation, the copies drifted — same facts, three wordings, and three
different visual weights for one identical risk. So the shared parts now come
from `attest.buyer_surface`, and the pages are generated rather than edited.

Run it from the repo root: `.venv/bin/python tools/gen_buyer_pages.py`.
A test regenerates and compares, so a hand edit to a generated file fails CI
instead of silently diverging again.

Two things were added when the site was rebuilt as a document, and both are
here for the same anti-drift reason the module already existed for:

* **The paper skin.** The four pages share one masthead, one footer, one
  stylesheet and one navigation list, defined once below. Four hand-kept
  copies of a stylesheet drift exactly the way four hand-kept copies of a
  paragraph drift, and a page that has silently stopped matching the others is
  harder to notice than a sentence that has.
* **The FAQ page is derived from `docs/faq.md`,** not transcribed from it. The
  FAQ is the longest piece of prose the project publishes and it has already
  been reviewed once in its Markdown form; a hand-made HTML copy would be a
  second original, and the first edit to the Markdown would leave the page
  behind without anybody being told.

The skin is deliberately expressed as `extra_css` rather than folded into
`buyer_surface.CORE_CSS`. `CORE_CSS` travels inside every exported bundle,
where it is paid for on every copy and must open with no network at all; the
web font and the page furniture below belong to a page that is *served*, and
have no business inside a receipt somebody holds.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path
from typing import Final

from attest import buyer_surface

REPO_ROOT = Path(__file__).resolve().parent.parent
SITE_PUBLIC = REPO_ROOT / "site" / "public"
FAQ_SOURCE = REPO_ROOT / "docs" / "faq.md"
LOCKUP_SOURCE = REPO_ROOT / "logo" / "lockup.svg"

#: The ink these pages are printed in, as a literal. It is the same value the
#: skin binds to `--ink`, and the two are pinned to each other by a test: the
#: wordmark below cannot read it from a custom property, so a second copy of it
#: exists and has to be held against the first.
_INK: Final = "#241f18"

_GITHUB = "https://github.com/bernalli/attest"

# This page is served over the web, so it declares what it is allowed to reach:
# nothing, apart from its own icons and its own fonts. Unlike the verifier front
# page it does permit inline styles, because it carries its presentation with it
# — see the note in `buyer_surface.CORE_CSS` on why held-style pages inline
# everything. `font-src 'self'` is the one reach these pages have that a held
# page does not, and it is why the skin below may not be shared with one.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "font-src 'self'; base-uri 'none'; form-action 'none'"
)

_ICONS = """\
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="icon" href="favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">"""


def _head(description: str) -> str:
    """Per-page metadata: what this page may reach, and what it is about."""
    return (
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">\n'
        f'<meta name="description" content="{html.escape(description)}">\n'
        f"{_ICONS}"
    )


# --- The paper skin ---------------------------------------------------------

# Everything below lands after `CORE_CSS` in one <style>, so where the two
# disagree this wins on source order alone — including inside `CORE_CSS`'s
# dark-scheme and print blocks, which is deliberate: this document has one
# look, on screen and on paper, and a dark inversion of a page that is *about*
# being a paper receipt is not a second look worth carrying.
#
# Fonts are referenced relatively, not from the root, so a page still finds
# them when the built site is opened from a directory rather than served.
# The stack falls back to whatever monospace the reader has: nothing here is
# measured in Courier Prime's metrics, so a missing web font costs the texture
# and not the layout.
#
# Every colour is from the palette the home page uses. The ground is flat
# paper, with none of the home's texture layers, and that is a contrast
# decision rather than a stylistic one: composited at their stated alphas those
# layers darken the ground to about rgb(213, 197, 168), where `--ink-label` at
# 10.5px falls to 4.15:1 and misses the 4.5:1 it must clear. On flat `--paper`
# every text colour clears it. The conservative minimum is 4.97:1 for
# `--ink-label` over the standing tint; the current standing label is accented,
# so the minimum combination actually rendered is 5.68:1.
_PAPER_CSS: Final = """\
@font-face{font-family:'Courier Prime';font-style:normal;font-weight:400;font-display:swap;src:url('fonts/courier-prime-400.woff2') format('woff2')}
@font-face{font-family:'Courier Prime';font-style:normal;font-weight:700;font-display:swap;src:url('fonts/courier-prime-700.woff2') format('woff2')}
@font-face{font-family:'Courier Prime';font-style:italic;font-weight:400;font-display:swap;src:url('fonts/courier-prime-400i.woff2') format('woff2')}
@font-face{font-family:'Courier Prime';font-style:italic;font-weight:700;font-display:swap;src:url('fonts/courier-prime-700i.woff2') format('woff2')}
:root{--paper:#f0e6d2;--paper-card:#f8f2e2;--edge:#d3c3a2;--rule:#dccdb0;--ink:#241f18;--ink-2:#4a4132;--ink-3:#5c5241;--ink-label:#65573e;--bordeaux:#7a2231;--bordeaux-deep:#571620;--bordeaux-tint:#d8b3ad;--measure:64ch;--bg:#f0e6d2;--fg:#241f18;--bad:#7a2231;--accent:#7a2231}
*{box-sizing:border-box}
body{margin:0;max-width:none;padding:0;background:var(--paper);color:var(--ink);font-family:'Courier Prime','Courier New',Courier,monospace;font-size:15px;line-height:1.8}
a{color:var(--bordeaux);text-decoration:none;border-bottom:1px solid var(--bordeaux-tint)}
a:hover,a:focus-visible{color:var(--bordeaux-deep);border-bottom-color:var(--bordeaux)}
code{font-family:inherit;font-size:1em;word-break:normal;overflow-wrap:anywhere;background:rgba(122,34,49,.07);padding:0 .2em}
strong{font-weight:700}
.masthead{display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap;padding:26px 40px;border-bottom:1px solid var(--rule)}
.masthead__home{border:0;display:block;line-height:0}
.lockup{height:22px;width:auto;display:block}
.masthead nav{display:flex;gap:26px;flex-wrap:wrap}
.masthead nav a{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--bordeaux);border-bottom-color:transparent;padding-bottom:2px}
.masthead nav a:hover,.masthead nav a:focus-visible{border-bottom-color:var(--bordeaux)}
.masthead nav a[aria-current=page]{color:var(--ink);border-bottom-color:var(--ink)}
main{max-width:740px;margin:0 auto;padding:48px 24px 60px;display:flex;flex-direction:column;gap:34px}
main>section{display:flex;flex-direction:column;gap:16px}
h1{margin:0;font-size:clamp(26px,4.6vw,37px);font-weight:700;line-height:1.28;letter-spacing:-.035em;text-wrap:pretty}
h2{margin:0;font-size:22px;font-weight:700;letter-spacing:-.03em;color:var(--ink)}
h3{margin:0;font-size:14.5px;font-weight:700;letter-spacing:-.02em}
p{margin:0;max-width:var(--measure);color:var(--ink-2);text-wrap:pretty}
.lead{font-size:15px}
.label{font-size:10.5px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-label)}
.label--accent{color:var(--bordeaux)}
hr{border:0;height:1px;background:var(--rule);margin:0}
ul{margin:0;padding-left:1.4em;max-width:var(--measure);color:var(--ink-2);display:flex;flex-direction:column;gap:11px}
li{text-wrap:pretty}
li::marker{color:var(--bordeaux)}
.cta{display:inline-block;align-self:flex-start;margin:0;padding:10px 20px;border:1px solid var(--ink);border-radius:0;background:var(--ink);color:var(--paper);font-size:12.5px;font-weight:700;border-bottom:1px solid var(--ink)}
.cta:hover,.cta:focus-visible{background:var(--bordeaux);border-color:var(--bordeaux);color:var(--paper)}
.warning{margin:0;padding:20px 24px;border:1px solid var(--bordeaux);border-left-width:3px;border-radius:0;background:rgba(216,179,173,.22);display:flex;flex-direction:column;gap:12px}
.warning h2{margin:0;font-size:16px;color:var(--bordeaux);letter-spacing:-.02em}
.warning p{color:var(--ink-2);font-size:13.5px;line-height:1.75}
.register{display:flex;flex-direction:column;gap:13px}
.register>div{display:grid;grid-template-columns:186px 1fr;gap:20px;font-size:13.5px;line-height:1.75;color:var(--ink-2)}
.register .term{font-weight:700;color:var(--ink)}
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:26px}
.steps>div{display:flex;flex-direction:column;gap:7px}
.steps .n{font-size:12px;font-weight:700;color:var(--bordeaux)}
.steps p{font-size:12.5px;line-height:1.75;color:var(--ink-3)}
.standing{background:rgba(213,196,160,.42);border-left:3px solid var(--bordeaux);padding:20px 24px;display:flex;flex-direction:column;gap:10px}
.standing p{font-size:14px}
.contents{display:flex;flex-direction:column;gap:9px;counter-reset:q}
.contents a{display:grid;grid-template-columns:34px 1fr;gap:12px;font-size:13.5px;line-height:1.7;border-bottom:0;color:var(--ink-2);align-items:baseline}
.contents a::before{counter-increment:q;content:counter(q,decimal-leading-zero);font-size:12px;font-weight:700;color:var(--bordeaux)}
.contents a:hover span,.contents a:focus-visible span{border-bottom:1px solid var(--bordeaux);color:var(--bordeaux-deep)}
.qa{display:flex;flex-direction:column;gap:14px;scroll-margin-top:24px}
.qa h2{font-size:19px;line-height:1.4}
.qa p{font-size:14px}
.crosslinks{font-size:12.5px;color:var(--ink-3);line-height:1.8}
footer{border-top:1px solid var(--rule);padding:22px 40px 30px;margin:0;display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;font-size:11.5px;color:var(--ink-3);opacity:1}
footer nav{display:flex;gap:22px;flex-wrap:wrap}
@media(max-width:720px){.masthead,footer{padding-left:20px;padding-right:20px}.register>div{grid-template-columns:1fr;gap:4px}}
@media print{body{background:#fff;color:#000;font-size:11pt}.masthead nav,footer nav,.contents{display:none}main{max-width:none;padding:0}a{color:#000;border-bottom:0}h2{page-break-after:avoid}.warning{border-width:2px;background:none}code{background:none}.cta{background:none;color:#000;border:1px solid #000}}
"""

# One navigation list for every page, in one order. A link that exists on three
# of four pages is the kind of difference nobody sees and everybody inherits.
_NAV: Final = (
    ("start-here.html", "Start here"),
    ("faq.html", "FAQ"),
    ("for-sellers.html", "For sellers"),
    (f"{_GITHUB}/tree/main/docs/spec", "Specification"),
    (_GITHUB, "Source"),
)


def _masthead(current: str | None) -> str:
    """The wordmark and the primary navigation, with the current page marked.

    Args:
        current: `href` of the page being rendered, so its own entry is marked
            rather than offered as somewhere to go. `None` for a page that is
            not in the navigation at all.
    """
    links = "\n".join(
        f'<a href="{href}"{' aria-current="page"' if href == current else ""}>{label}</a>'
        for href, label in _NAV
    )
    return (
        '<header class="masthead">\n'
        '<a class="masthead__home" href="./" aria-label="attest — home">'
        '<img class="lockup" src="lockup.svg" alt="attest" width="165" height="22">'
        "</a>\n"
        '<nav aria-label="Primary">\n'
        f"{links}\n"
        "</nav>\n"
        "</header>"
    )


_FOOTER: Final = f"""\
<footer>
<span>Code Apache-2.0 &middot; Spec CC BY 4.0 &middot; Courier Prime under the SIL Open Font License</span>
<nav aria-label="Elsewhere">
<a href="{_GITHUB}">github.com/bernalli/attest</a>
<a href="{_GITHUB}/discussions">Discussions</a>
</nav>
</footer>"""


def _document(main: str, *, current: str | None) -> str:
    """Wrap a page's own content in the chrome every page shares.

    Returns the body markup only. Each page still calls
    :func:`buyer_surface.render_page` itself, rather than routing through one
    helper here: `tests/test_buyer_surface.py` counts those call sites per file
    so that adding a buyer-facing surface is a visible decision, and a single
    shared call would let a fifth page appear without moving that count.
    """
    return f"{_masthead(current)}\n<main>\n{main}\n</main>\n{_FOOTER}"


# --- What is this file? -----------------------------------------------------

_WHAT_IS_THIS_DESCRIPTION = (
    "What the .attest and .private.attest files in your download are, and how to check one is real."
)

_BODY = """\
<section>
<p class="label">For a reader holding a file</p>
<h1>What is this file?</h1>

<p class="lead">You bought something online, and your download included one or two extra
files ending in <code>.attest</code> or <code>.private.attest</code>. This page
explains what they are.</p>

<p>Each file is a small, signed <strong>receipt</strong> from the store you
bought from. It's yours: proof that you paid for what's listed inside, signed by
the seller so anyone can check it's genuine. Keep it the way you'd keep an
important paper receipt — it doesn't live in any account. It survives the shop
closing. It does not survive the seller declaring the key that signed it
compromised: the standard describes a shield against that, but no store tool
offers it yet and this page cannot check it.</p>
</section>

<hr>

<section>
<h2>You can check it yourself, without the store</h2>

<p>You don't need to trust this page, or the store, or take anyone's word for
it. Anyone can verify the receipt directly — including you, right now, in your
browser, with the file never leaving your machine.</p>

<p><a class="cta" href="./">Verify a receipt →</a></p>
</section>

__PRIVATE_WARNING__

<section>
<h2>What if the store is gone?</h2>

<p>That's the whole point of this format: the receipt still works. It doesn't
call home, it doesn't need the store's servers to be running, and it doesn't
expire when a shop closes down. A verifier can check it entirely offline, months
or years later, using nothing but the file itself and the seller's published
signing key. If a store you bought from shuts down, your receipt still proves
you bought what it lists — it isn't the thing itself, but it's the part of your
purchase that survives the store.</p>
</section>

<hr>

<p class="crosslinks">
Never heard of any of this? <a href="start-here.html">Start here</a>.
Curious about the cryptography behind this? See the
<a href="{github}/tree/main/docs/spec">attest specification</a>
and the <a href="{github}">project on GitHub</a>.
</p>""".replace("{github}", _GITHUB)


def render_what_is_this() -> str:
    """Render the standalone explainer page served next to the web verifier."""
    main = _BODY.replace("__PRIVATE_WARNING__", buyer_surface.private_file_warning_html())
    return buyer_surface.render_page(
        "What is this file? — attest",
        _document(main, current=None),
        extra_head=_head(_WHAT_IS_THIS_DESCRIPTION),
        extra_css=_PAPER_CSS,
    )


# --- Start here -------------------------------------------------------------

_START_HERE_DESCRIPTION = (
    "A plain-language guide to the receipt a signed purchase gives you: what it "
    "does, what it does not protect, and what to do with it."
)

_START_HERE_BODY = """\
<section>
<p class="label">For a reader with no receipt yet</p>
<h1>Start here</h1>

<p class="lead">You bought a game, a film, an album or a book online. What you actually got is
permission to use it, kept on the store's computers. If the store closes, or your
account is shut, or a licensing deal expires, that permission can vanish — and
with it the thing you paid for.</p>

<p>attest gives you one piece of that purchase to keep. When a store uses it, your
download comes with a small extra file: a receipt, signed by the seller. "Signed"
means the receipt carries a seal made with the seller's signing key. Anyone can
detect a later change, and only someone holding that key can make a receipt pass
the check — which is why a stolen or compromised signing key still matters. You
don't have to understand how the seal works. You only have to keep the file.</p>
</section>

<hr>

<section>
<h2>What you can do with it</h2>
<ul>
<li><strong>Keep it anywhere.</strong> On your disk, in a backup, on a USB stick. It
doesn't live in an account, so no account can lose it for you.</li>
<li><strong>Check it whenever you like.</strong> With a free tool, on your own
computer, with the internet switched off, without asking the store.
<a href="./">Try it on a sample receipt →</a></li>
<li><strong>Prove what you bought years from now</strong> — even if the store no
longer exists.</li>
</ul>
</section>

<hr>

<section>
<h2>What it does not do</h2>
<ul>
<li><strong>It is not the game, film or book.</strong> If you never downloaded the
file and the store is gone, no receipt can bring it back. Download what you buy,
and keep it next to the receipt.</li>
<li><strong>It protects you from a store that disappears, not from one that is still
open and turns on you.</strong> A live seller can declare one of its own signing
keys compromised, and that cancels the receipts signed with that key. The standard
describes a shield against this — a receipt publicly logged and anchored before the
declaration — and the verifiers already honour it when they are shown one. But
nothing makes such a receipt yet: no store logs or anchors what it signs, and the
verifier on this site holds no anchor to check against. So for now there is nothing
you can do about it.</li>
<li><strong>It doesn't unlock anything</strong> and it doesn't remove copy protection.</li>
<li><strong>Almost no store issues one yet.</strong> Stores that sell files without copy
protection can start today. Closed platforms are a longer road: when you buy from
them online, the law in the EU already makes them confirm the purchase on something
you can keep — Article 8(7) of the Consumer Rights Directive (2011/83/EU, 25 October
2011) — and a receipt like this is one thing that confirmation could come with, not
a replacement for it. If your store doesn't offer it, that is the thing to ask for.</li>
</ul>
</section>

__PRIVATE_WARNING__

<hr>

<p class="crosslinks">
Already have a receipt in hand? <a href="what-is-this.html">What is this file?</a> &middot;
Curious how the seal works? See the
<a href="{github}/tree/main/docs/spec">attest specification</a>.
</p>""".replace("{github}", _GITHUB)


def render_start_here() -> str:
    """Render the plain-language landing page for a reader with no receipt yet."""
    main = _START_HERE_BODY.replace(
        "__PRIVATE_WARNING__",
        buyer_surface.private_file_warning_html(delivered=False),
    )
    return buyer_surface.render_page(
        "Start here — attest",
        _document(main, current="start-here.html"),
        extra_head=_head(_START_HERE_DESCRIPTION),
        extra_css=_PAPER_CSS,
    )


# --- FAQ, derived from docs/faq.md ------------------------------------------

_FAQ_DESCRIPTION = (
    "Answers to the questions people ask about attest receipts: what a receipt "
    "proves, what it does not, and where the shipped code falls short of the design."
)

#: Relative links inside `docs/faq.md` are relative to `docs/`, and this page is
#: not served from there. Each one is rewritten to where a reader of the page
#: can actually follow it. Anything not in this map is REFUSED rather than
#: emitted: a silently broken link is the failure this whole module exists to
#: prevent, arriving through a different door.
_FAQ_LINK_REWRITES: Final = {
    "../README.md": f"{_GITHUB}/blob/main/README.md",
}

_MD_CODE_SPAN = re.compile(r"(`[^`]+`)")
_MD_STRONG = re.compile(r"\*\*(.+?)\*\*", re.DOTALL)
_MD_EM = re.compile(r"(?<!\*)\*([^*]+?)\*(?!\*)", re.DOTALL)
_MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
#: The only link targets this page may emit. A rewritten target is checked
#: against it too: the map is data, and data that has never been validated is
#: the shape a `javascript:` URL arrives in.
_ALLOWED_LINK_PREFIXES: Final = ("https://", "http://", "#")
#: Block openers this converter does not implement. `docs/faq.md` is headings
#: and paragraphs today; the day somebody adds a list to it, this must say so
#: out loud rather than flatten it into a run-on paragraph.
#:
#: Searched over the RAW block, not the stripped one, and over every line
#: rather than the first: `block.strip()` eats the four spaces that make an
#: indented code block, and a list that starts on a paragraph's second line
#: would otherwise be joined into the sentence above it — both silent losses
#: of structure, which is the one thing this converter promises not to do.
_MD_UNSUPPORTED = re.compile(
    r"^(?: {4}|\t| {0,3}(?:[-+*][ \t]+|\d+[.)][ \t]+|>[ \t]?|\||```|~~~|"
    r"(?:---+|===+)[ \t]*$))",
    re.MULTILINE,
)
_MD_HEADING = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+|$)", re.MULTILINE)


def _inline_error(text: str) -> None:
    raise ValueError(
        f"{FAQ_SOURCE.name} contains unsupported or malformed inline Markdown: {text!r}"
    )


def _validate_emphasis(text: str) -> None:
    # Triple delimiters and crossing/unclosed runs are outside this deliberately
    # small grammar. Refuse them instead of relying on browser error recovery.
    if "***" in text:
        _inline_error(text)
    remainder = _MD_STRONG.sub("", text)
    remainder = _MD_EM.sub("", remainder)
    if "*" in remainder:
        _inline_error(text)


def _validate_inline_text(text: str) -> None:
    if "![" in text:
        _inline_error(text)
    links = list(_MD_LINK.finditer(text))
    for match in links:
        label, target = match.group(1), match.group(2)
        if any(char in label for char in "[]`"):
            _inline_error(text)
        if any(char in target for char in "*`[]()"):
            _inline_error(text)
        _validate_emphasis(label)
    remainder = _MD_LINK.sub("link", text)
    if "[" in remainder or "]" in remainder:
        _inline_error(text)
    _validate_emphasis(remainder)


def _md_inline(text: str) -> str:
    """Convert one paragraph's inline Markdown to HTML.

    Code spans are lifted out first, so their contents are escaped and never
    read as emphasis: `*.attest` is a filename pattern, not the start of an
    italic run.
    """
    out: list[str] = []
    parts = _MD_CODE_SPAN.split(text)
    for index, part in enumerate(parts):
        if index % 2:  # the capture group: a code span, delimiters included
            out.append(f"<code>{html.escape(part[1:-1], quote=False)}</code>")
            continue
        # A backtick left over here is an unclosed span, or a ``long`` delimiter
        # this grammar does not implement — either way the source says something
        # this converter would render as something else.
        if "`" in part:
            _inline_error(text)
        _validate_inline_text(part)
        # `quote=False`: these become text nodes, never attribute values, and
        # escaping the quotation marks in prose would show them to the reader.
        escaped = html.escape(part, quote=False)
        escaped = _MD_STRONG.sub(r"<strong>\1</strong>", escaped)
        escaped = _MD_EM.sub(r"<em>\1</em>", escaped)
        out.append(_MD_LINK.sub(_md_link, escaped))
    return "".join(out)


def _md_link(match: re.Match[str]) -> str:
    """Render one Markdown link, refusing a relative target with no rewrite."""
    label, target = match.group(1), match.group(2)
    if not target.startswith(_ALLOWED_LINK_PREFIXES):
        try:
            target = _FAQ_LINK_REWRITES[target]
        except KeyError:
            raise ValueError(
                f"{FAQ_SOURCE.name} links to {target!r}, which is relative to docs/ "
                "and would be broken on the published page. Add it to "
                "_FAQ_LINK_REWRITES with the URL a reader of the page can follow."
            ) from None
    if not target.startswith(_ALLOWED_LINK_PREFIXES):
        raise ValueError(f"{FAQ_SOURCE.name} rewrites a link to unsafe target {target!r}")
    return f'<a href="{html.escape(target)}">{label}</a>'


def _slug(question: str) -> str:
    """A stable, readable fragment id for one question."""
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", question.lower())).strip("-")


def _faq_sections() -> tuple[list[str], list[tuple[str, list[str]]]]:
    """Parse `docs/faq.md` into its preamble paragraphs and its questions.

    Returns:
        The paragraphs before the first question, and one `(question,
        paragraphs)` pair per question, in document order.

    Raises:
        ValueError: on anything the converter does not implement, on a
            duplicate question, or if the document does not start with its
            title. Refusing beats emitting a page that silently lost a
            paragraph — this page must carry the FAQ whole.
    """
    text = FAQ_SOURCE.read_text(encoding="utf-8")
    raw_blocks = [block for block in re.split(r"\n[ \t]*\n", text) if block.strip()]
    blocks = [block.strip() for block in raw_blocks]

    if not blocks or blocks[0] != "# FAQ":
        raise ValueError(f"{FAQ_SOURCE.name} no longer starts with '# FAQ'")

    preamble: list[str] = []
    questions: list[tuple[str, list[str]]] = []
    seen: set[str] = set()
    for raw_block, block in zip(raw_blocks[1:], blocks[1:], strict=True):
        # A hard break is two trailing spaces or a backslash: the line joiner
        # below would delete it, turning a deliberate line break into nothing.
        if _MD_UNSUPPORTED.search(raw_block) or re.search(r"(?: {2,}|\\)\n", raw_block):
            raise ValueError(
                f"{FAQ_SOURCE.name} contains a block this converter does not "
                f"implement: {block.splitlines()[0]!r}"
            )
        if block.startswith("## "):
            if len(block.splitlines()) != 1:
                raise ValueError(
                    f"question and answer share one block in {FAQ_SOURCE.name}: {block!r}"
                )
            question = block[3:].strip()
            if re.search(r"[ \t]+#+[ \t]*$", question):
                raise ValueError(
                    f"closing heading markers are unsupported in {FAQ_SOURCE.name}: {question!r}"
                )
            slug = _slug(question)
            if not slug:
                raise ValueError(
                    f"question in {FAQ_SOURCE.name} yields an empty fragment id: {question!r}"
                )
            if questions and not questions[-1][1]:
                raise ValueError(
                    f"question in {FAQ_SOURCE.name} has no answer: {questions[-1][0]!r}"
                )
            if slug in seen:
                raise ValueError(f"two questions in {FAQ_SOURCE.name} share the id {slug!r}")
            seen.add(slug)
            questions.append((question, []))
            continue
        if _MD_HEADING.search(raw_block) or block.startswith("#"):
            raise ValueError(f"unexpected heading level in {FAQ_SOURCE.name}: {block!r}")
        paragraph = " ".join(line.strip() for line in block.splitlines())
        (questions[-1][1] if questions else preamble).append(paragraph)

    if not questions:
        raise ValueError(f"{FAQ_SOURCE.name} yielded no questions")
    if not questions[-1][1]:
        raise ValueError(f"question in {FAQ_SOURCE.name} has no answer: {questions[-1][0]!r}")
    return preamble, questions


def render_faq() -> str:
    """Render `docs/faq.md` as a page, whole.

    Derived, never transcribed: the Markdown is the original, and every
    paragraph in it reaches the page or the conversion fails.
    """
    preamble, questions = _faq_sections()

    intro = "\n\n".join(f"<p>{_md_inline(p)}</p>" for p in preamble)
    contents = "\n".join(
        f'<a href="#{_slug(question)}"><span>{_md_inline(question)}</span></a>'
        for question, _ in questions
    )
    entries = "\n\n".join(
        '<section class="qa" id="{slug}">\n<h2>{question}</h2>\n{paragraphs}\n</section>'.format(
            slug=_slug(question),
            question=_md_inline(question),
            paragraphs="\n".join(f"<p>{_md_inline(p)}</p>" for p in paragraphs),
        )
        for question, paragraphs in questions
    )

    main = f"""\
<section>
<p class="label">For a skeptical reader</p>
<h1>FAQ</h1>
{intro}
</section>

<hr>

<nav class="contents" aria-label="Questions on this page">
{contents}
</nav>

<hr>

{entries}

<hr>

<p class="crosslinks">
Holding a receipt already? <a href="what-is-this.html">What is this file?</a> &middot;
New to all of it? <a href="start-here.html">Start here</a> &middot;
Selling something? <a href="for-sellers.html">For sellers</a> &middot;
The normative text is the <a href="{_GITHUB}/tree/main/docs/spec">specification</a>.
</p>"""

    return buyer_surface.render_page(
        "FAQ — attest",
        _document(main, current="faq.html"),
        extra_head=_head(_FAQ_DESCRIPTION),
        extra_css=_PAPER_CSS,
    )


# --- For sellers ------------------------------------------------------------

_FOR_SELLERS_DESCRIPTION = (
    "What a seller installs, signs and hands to the buyer in order to issue "
    "attest receipts, what is not asked of them, and where this stands: no "
    "seller signs yet."
)

_FOR_SELLERS_BODY = """\
<section>
<p class="label">For whoever would sign</p>
<h1>For sellers</h1>
<p class="lead">This page is for whoever sells files without DRM — a publisher, a developer on itch.io, a small ebook shop, a musician — and wants to know what signing a receipt would take. It says what you install, what you sign, what your buyer receives, and what is not asked of you. It says the missing part first, because you need it to decide: no seller issues attest receipts today. The standard, two independent implementations and the conformance suite are done and free to use. What is missing is the first seller who signs, and this page is meant to let you work out whether that could be you.</p>
</section>

<hr>

<section>
<h2>What you would be signing</h2>
<p>A receipt is a small JSON document you sign at the moment of sale. It names you by your domain, names the work, points at the licence terms by URI and by the hash of their text, and binds the purchase to the buyer through a salted commitment to their email address rather than the address itself. Your signature is Ed25519; when the bridge signs, it adds an ML-DSA-65 signature beside it, so the same receipt carries a post-quantum leg. Once signed, the receipt does not change. Refunds, revocations and key changes live in separate signed documents, never inside it.</p>

<p>The buyer receives two files. The shareable one, named after your domain and the receipt id and ending in <code>.attest</code>, carries the receipt with its salt stripped, your key manifest exactly as it was when you signed, the licence text the receipt's hash points at, and a generated page explaining how to check the receipt once your store is gone. The other, ending in <code>.private.attest</code>, holds the salt that lets the buyer prove the receipt is theirs; the name is deliberate, because the web verifier refuses that file on sight, and it is the one file they must never send to anyone. Anyone holding the shareable file can verify it offline — on this site, with the <code>attest</code> command, or with the npm package — and none of that needs you, your server or your bridge to still exist.</p>
</section>

<hr>

<section>
<h2>What you install</h2>
<p>Two packages, and only one of them is published. <code>attest-receipts</code> is on PyPI and gives you the <code>attest</code> command: <code>keygen</code>, <code>manifest</code>, <code>issue</code>, <code>export</code>, <code>verify</code>, <code>import</code>, <code>inspect</code>, <code>check-artifact</code> and <code>disclose</code>, plus the <code>transfer</code>, <code>grant</code>, <code>authority</code> and <code>log</code> families for the parts of the standard beyond a plain sale. <code>attest-bridge</code>, the service that turns a paid order into a signed receipt, is not published. Its package metadata is marked <code>Private :: Do Not Upload</code>, and its own setup guide tells you never to run <code>pip install attest-bridge</code>, because that name could resolve to something unrelated. You clone the repository and install from the checkout with <code>pip install ./bridge</code>, which pulls in <code>attest-receipts</code> as a dependency. Both need Python 3.12 or newer.</p>

<p>The bridge runs wherever you can run a container. A Dockerfile builds it from the checkout, and the deployment guide writes out Docker Compose on a machine you own, Fly.io and Render. TLS is not optional on any of them: a webhook body and a downloaded receipt both carry a buyer's binding salt. The bridge keeps a Ledger, an SQLite file recording every receipt it has issued, and runs as one process per Ledger; that file holds each receipt with its salt, so it is a secret, created with owner-only permissions and backed up encrypted or not at all.</p>
</section>

<hr>

<section>
<h2>The key and the manifest</h2>
<p><code>attest keygen --hybrid</code> writes your signing keys — an Ed25519 seed and an ML-DSA-65 key, both secret — and the public half. The bridge refuses to start without the ML-DSA key. <code>attest manifest init</code> then writes your key manifest: a self-signed document naming your domain, your key identifier and the window in which the key is valid. You choose the window, and the bridge refuses to sign outside it. Rotation exists, as <code>attest manifest rotate</code>, and it requires the old key to sign the new manifest. That is the point of it, and it is also why a lost key cannot be rotated out of.</p>

<p>The specification says an issuer should publish that manifest at <code>https://&lt;your-domain&gt;/.well-known/attest.json</code>, and you should. Be clear about what it does today: nothing, for anyone verifying. The specification reserves its strongest trust level, <code>verified</code>, for key material fetched over TLS from the issuer's own domain, and no tool published today performs that fetch. Every receipt you issue carries a copy of your manifest inside it, so every verification anyone can actually run reports <code>unauthenticated_tofu</code>: the arithmetic is checked, and nobody confirms that the key belongs to the domain. Publishing at the well-known path is what would let a future verifier close that gap. Nothing you can hand a buyer closes it now.</p>
</section>

<hr>

<section>
<h2>Where the purchase comes from</h2>
<p>The bridge signs when your payment platform says a purchase is paid, and it takes the platform's word only in the form the platform signs.</p>
<div class="register">
<div><span class="term">Stripe</span><span>Stripe sends <code>checkout.session.completed</code> (and its asynchronous-payment sibling) to the bridge, which verifies the <code>Stripe-Signature</code> header with your webhook secret and issues only for a session whose payment status is <code>paid</code>. With your Stripe secret key configured, the bridge reads the session's line items itself to learn which price was bought; without it, you set the product key in the session's metadata yourself. A session with more than one purchasable line item is refused: one receipt per purchase.</span></div>
<div><span class="term">Shopify</span><span>Shopify sends an <code>orders/paid</code> webhook, checked against <code>X-Shopify-Hmac-Sha256</code>. The order carries its own line items, so there is no API token to configure and no follow-up request. Unpaid or cancelled orders are acknowledged without issuing, and an order with more than one line item is set aside rather than signed.</span></div>
<div><span class="term">itch.io</span><span>Not a webhook, because itch.io exposes none. The bridge runs a claim queue: a buyer, through a form the bridge serves, or you, from a CSV of past sales, enqueues an email address and a game id, and a poller asks the itch API whether that address bought that game. Only the API's answer issues a receipt; a claim by itself never does. itch receipts are bound to email only and reach the buyer only by email, so this rail requires a mail server.</span></div>
<div><span class="term">Your own checkout</span><span>If your checkout is code you wrote, the Python library exposes the two calls the bridge itself uses to build and sign a payload, and the <code>attest</code> command can sign a payload you write by hand and package it as the same two files. There is no guide for that path; the setup guides cover the platforms above.</span></div>
</div>
</section>

<hr>

<section>
<h2>What you decide, per product</h2>
<p>The bridge signs nothing it has not been told about. For every item you sell you write a table in <code>bridge.toml</code>, keyed by the platform's identifier for it — a Stripe price id, a Shopify variant id, an itch game id — with the title, the publisher, an identifier of your own, a URI for the licence terms, the SHA-256 of the licence text and the path to that text. The bridge reads the text at startup, hashes it, and refuses to start if the hash does not match what you declared. A purchase of anything not in the file is refused and set aside rather than issued with guessed terms. The text itself ships inside every buyer's bundle, so the deal travels with the signature.</p>

<p>The defaults are not modest, and you should read them before you accept them: a perpetual grant, DRM-free, irrevocable, with a right to re-download. The specification allows an irrevocable receipt only for a DRM-free sale with a redownload right and a named artifact series or list of files, and it treats such a receipt as evidence that a sale falls under laws like California's AB 2426 or Maryland's HB 208 — evidence, it says, not a compliance determination, and your storefront language stays your own duty. It also means a refund does not take the receipt back: a revocation record aimed at an irrevocable receipt is ignored by every conforming verifier. If you want refunds to reach the receipt, set <code>revocability = "refund_window"</code> with a number of days, and know what that buys you today: no shipped command signs a stand-alone revocation record — the library can, and you would be writing code — and the record then has to reach the buyer as a file, because no shipped tool fetches a revocation feed.</p>
</section>

<hr>

<section>
<h2>How the buyer receives it</h2>
<p>By email or by link, and you choose by configuration. With a <code>[delivery]</code> section the bridge sends the two files as attachments over SMTP, TLS only — there is no code path that sends in clear — with a body that names which file is safe to share and which is not, and a link to a page explaining what the files are. That page is this site's unless you point <code>info_url</code> at your own. Without <code>[delivery]</code>, the download link is the delivery: every receipt has a token link on your bridge, and Stripe's success URL can land the buyer directly on a page offering both files. Delivery is at-least-once — a crash between the mail server accepting and the Ledger recording can send the same email twice — and it never issues twice. On itch.io there is no link path; email is the only delivery.</p>

<p>One consequence for your customers, worth knowing before you sign: the buyer's address is sealed, not encrypted. Whoever holds the private file together with the receipt — the buyer, or anyone they hand both to — can test candidate email addresses against the receipt's commitment offline. Your Ledger holds the same salts, which is one more reason it is a secret.</p>
</section>

<hr>

<section>
<h2>What stays with you afterwards</h2>
<p>The signing key. It lives only where your bridge runs; the bridge reads it to sign and never exports, logs or writes it back. There is no attest portal, no authority and no company holding a copy that can restore it, and that is by design: an authority able to hand your identity back to you could hand it to someone else. Back the seed up where a disk failure on the issuing machine cannot take it, never next to what it signs, and read the incident runbook before you need it. Its two cases differ in a way worth knowing now. A lost key leaves your old receipts valid and leaves a permanent, visible gap in your key history. A stolen key, once you declare it compromised, invalidates every receipt it signed. The standard defines a rescue for receipts logged and anchored before such a declaration, but the bridge does not log what it issues and no shipped command does, so today that declaration is final for every receipt the bridge signs.</p>

<p>The Ledger. It is your memory of which purchases already have a receipt and the source of every download link. Losing it does not touch receipts already delivered, but a redeploy without it can issue a second receipt for a retried webhook.</p>

<p>Uptime, while you sell. Stripe and Shopify retry a webhook that fails transiently, and the bridge answers a transient failure with a 500 precisely so that they do. After the sale, nothing: a receipt in the buyer's hands verifies with no dependency on the bridge, its database or its uptime ever again.</p>
</section>

<hr>

<section>
<h2>What is not asked of you</h2>
<div class="register">
<div><span class="term">No blockchain</span><span>A conforming implementation must not require blockchain infrastructure to issue or verify a receipt. The bridge issues a signed file.</span></div>
<div><span class="term">No fee, no licence to buy</span><span>The code is Apache-2.0 and the specification CC BY 4.0; nothing charges a fee to implement attest. The documents say what they cover and stop short of the words "royalty-free".</span></div>
<div><span class="term">No registration, no certification</span><span>There is no central attest authority. An implementation claims conformance by running the public runner against the corpus and publishing the result.</span></div>
<div><span class="term">No account with this project, and no traffic to it</span><span>The bridge speaks to your payment platform and to your mail server. Neither verifier contains an HTTP client. The only reference to this site in the bridge is the default link in the receipt email, which you can replace.</span></div>
<div><span class="term">No change to how you sell</span><span>The bridge sits beside your checkout and reacts to its events. It is not a payment processor, a store, or a source of truth for your orders; on Shopify, the app that delivers the file keeps delivering it, and the bridge only issues the receipt.</span></div>
<div><span class="term">No copy of what you sell</span><span>A receipt names the work and the terms. It never carries, hosts or indexes the content, and the specification forbids implementations from doing so.</span></div>
<div><span class="term">No custody handed to anyone</span><span>Your key stays where your bridge runs. No buyer key material passes through the bridge beyond a public key a buyer chooses to bind their receipt to.</span></div>
<div><span class="term">No DRM, and no promise about it</span><span>A receipt records whether the sale was DRM-free or DRM-bound and never changes which. The standard forbids using attest to strip or bypass DRM.</span></div>
</div>
</section>

<section class="standing">
<h2 class="label label--accent">Where this honestly stands</h2>
<p>No store issues attest receipts yet, and no regulator mandates them. The standard, two independent implementations and the conformance suite are done and free to use. What is missing is the first seller who signs. On this page that sentence has concrete edges: the bridge is unreleased and installs from a checkout; the manifest you publish at the well-known path is fetched by no shipped tool; the log-and-anchor rescue that would let a receipt outlive a later compromise of your key is not wired into what the bridge issues. None of it stops a receipt signed today from verifying later, offline, with nothing of yours still running. If something on this page would stop you, say so in the project's Discussions. A first seller is worth more to this project than another feature.</p>
</section>

<hr>

<p class="crosslinks">
Buying rather than selling? <a href="start-here.html">Start here</a> &middot;
The questions people ask are in the <a href="faq.html">FAQ</a> &middot;
The normative text is the <a href="{github}/tree/main/docs/spec">specification</a>, and the seller-side service lives in
<a href="{github}/tree/main/bridge">bridge/</a>.
</p>""".replace("{github}", _GITHUB)


def render_for_sellers() -> str:
    """Render the page for a seller deciding whether to start signing.

    The one page here whose reader is not a buyer, and the one whose first
    paragraph has to state the thing that would otherwise be discovered
    halfway down: nothing issues these receipts yet, and the seller-side
    service is not published. A page that let a seller reach the install
    instructions before saying so would be selling them something.
    """
    return buyer_surface.render_page(
        "For sellers — attest",
        _document(_FOR_SELLERS_BODY, current="for-sellers.html"),
        extra_head=_head(_FOR_SELLERS_DESCRIPTION),
        extra_css=_PAPER_CSS,
    )


# --- The wordmark, as a file the pages share --------------------------------


def render_lockup() -> str:
    """Return `logo/lockup.svg` in the one ink these pages are printed in.

    The pages reference the mark with `<img>` rather than inlining it, which
    buys one cached asset instead of four copies of the same six kilobytes of
    path data. The cost is that an SVG loaded that way has no `currentColor`
    to inherit — the brand files are all single-colour and take the colour of
    wherever they are placed, and an `<img>` places them nowhere — so the fill
    has to become a literal.

    Hence derived, not copied. A second SVG sitting beside the first with one
    value changed by hand is a fork that nobody notices has drifted; this way
    `logo/lockup.svg` stays the original, this is a rendering of it, and the
    test that compares generated files to what is committed covers the mark
    exactly as it covers the pages.

    Raises:
        ValueError: if the brand file no longer paints with `currentColor`,
            which would mean this is silently emitting some other colour.
    """
    source = LOCKUP_SOURCE.read_text(encoding="utf-8")
    if source.count('fill="currentColor"') != 1:
        raise ValueError(
            f"{LOCKUP_SOURCE.name} no longer carries exactly one "
            'fill="currentColor"; this renderer cannot say what colour it would emit'
        )
    return source.replace('fill="currentColor"', f'fill="{_INK}"', 1)


# --- Output -----------------------------------------------------------------


def generated_pages() -> dict[Path, str]:
    """Return every generated page, keyed by the path it belongs at."""
    return {
        SITE_PUBLIC / "what-is-this.html": render_what_is_this(),
        SITE_PUBLIC / "start-here.html": render_start_here(),
        SITE_PUBLIC / "faq.html": render_faq(),
        SITE_PUBLIC / "for-sellers.html": render_for_sellers(),
        SITE_PUBLIC / "lockup.svg": render_lockup(),
    }


def main() -> int:
    """Write every generated page, reporting what changed."""
    changed = 0
    for path, content in generated_pages().items():
        previous = path.read_text(encoding="utf-8") if path.exists() else None
        if previous == content:
            print(f"unchanged: {path.relative_to(REPO_ROOT)}")
            continue
        path.write_text(content, encoding="utf-8")
        print(f"written:   {path.relative_to(REPO_ROOT)} ({len(content.encode('utf-8'))} bytes)")
        changed += 1
    if changed:
        print(f"\n{changed} page(s) regenerated. Commit them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
