"""Generate the standalone buyer-facing pages under `site/public/`.

These pages explain the same things a bundle's own `README.html` explains, to
the same reader. When each surface kept its own hand-written copy of that
explanation, the copies drifted — same facts, three wordings, and three
different visual weights for one identical risk. So the shared parts now come
from `attest.buyer_surface`, and the pages are generated rather than edited.

Run it from the repo root: `.venv/bin/python tools/gen_buyer_pages.py`.
A test regenerates and compares, so a hand edit to a generated file fails CI
instead of silently diverging again.
"""

from __future__ import annotations

import sys
from pathlib import Path

from attest import buyer_surface

REPO_ROOT = Path(__file__).resolve().parent.parent
SITE_PUBLIC = REPO_ROOT / "site" / "public"

# This page is served over the web, so it declares what it is allowed to reach:
# nothing, apart from its own icons. Unlike the verifier front page it does
# permit inline styles, because it carries its presentation with it — see the
# note in `buyer_surface.CORE_CSS` on why held-style pages inline everything.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'"
)

_HEAD = f"""\
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="description" content="What the .attest and .private.attest files \
in your download are, and how to check one is real.">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="icon" href="favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">"""

# Presentation this page needs and the shared core deliberately does not carry:
# a call-to-action and a footer exist here and nowhere a buyer *holds*, so the
# rules live here instead of costing bytes inside every exported receipt.
_PAGE_CSS = """\
.cta{display:inline-block;margin-top:.5rem;padding:.6rem 1.1rem;border:1px solid var(--accent);border-radius:8px;text-decoration:none;font-weight:600}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--fg);opacity:.75;font-size:.9rem}
"""

_BODY = """\
<h1>What is this file?</h1>

<p>You bought something online, and your download included one or two extra
files ending in <code>.attest</code> or <code>.private.attest</code>. This page
explains what they are.</p>

<p>Each file is a small, signed <strong>receipt</strong> from the store you
bought from. It's yours: proof that you paid for what's listed inside, signed by
the seller so anyone can check it's genuine. Keep it the way you'd keep an
important paper receipt — it doesn't live in any account. It survives the shop
closing. It does not survive the seller declaring the key that signed it
compromised, unless your receipt was logged and anchored first.</p>

<h2>You can check it yourself, without the store</h2>

<p>You don't need to trust this page, or the store, or take anyone's word for
it. Anyone can verify the receipt directly — including you, right now, in your
browser, with the file never leaving your machine.</p>

<p><a class="cta" href="./">Verify a receipt →</a></p>

__PRIVATE_WARNING__

<h2>What if the store is gone?</h2>

<p>That's the whole point of this format: the receipt still works. It doesn't
call home, it doesn't need the store's servers to be running, and it doesn't
expire when a shop closes down. A verifier can check it entirely offline, months
or years later, using nothing but the file itself and the seller's published
signing key. If a store you bought from shuts down, your receipt still proves
you bought what it lists — it isn't the thing itself, but it's the part of your
purchase that survives the store.</p>

<footer>
Curious about the cryptography behind this? See the
<a href="https://github.com/bernalli/attest/tree/main/docs/spec">attest specification</a>
and the <a href="https://github.com/bernalli/attest">project on GitHub</a>.
</footer>"""


def render_what_is_this() -> str:
    """Render the standalone explainer page served next to the web verifier."""
    body = _BODY.replace("__PRIVATE_WARNING__", buyer_surface.private_file_warning_html())
    return buyer_surface.render_page(
        "What is this file? — attest",
        body,
        extra_head=_HEAD,
        extra_css=_PAGE_CSS,
    )


# Same reach as `_HEAD`: no network, own icons only — this page is meant for a
# reader who does not have a receipt in hand yet, so its description says so.
_START_HERE_HEAD = f"""\
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="description" content="A plain-language guide to the receipt a signed purchase \
gives you: what it does, what it does not protect, and what to do with it.">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="icon" href="favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">"""

_START_HERE_BODY = """\
<h1>Start here</h1>

<p>You bought a game, a film, an album or a book online. What you actually got is
permission to use it, kept on the store's computers. If the store closes, or your
account is shut, or a licensing deal expires, that permission can vanish — and
with it the thing you paid for.</p>

<p>attest gives you one piece of that purchase to keep. When a store uses it, your
download comes with a small extra file: a receipt, signed by the seller. "Signed"
means the seller has stamped it in a way nobody else can imitate and nobody can
alter afterwards — think of a wax seal only that store can press, which breaks if
anyone tampers with it. You don't have to understand how the seal works. You only
have to keep the file.</p>

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

<h2>What it does not do</h2>
<ul>
<li><strong>It is not the game, film or book.</strong> If you never downloaded the
file and the store is gone, no receipt can bring it back. Download what you buy,
and keep it next to the receipt.</li>
<li><strong>It protects you from a store that disappears, not from one that is still
open and turns on you.</strong> A live seller can declare one of its own signing
keys compromised, and that cancels every receipt signed with that key — unless
yours was recorded in a public log first. Where that option exists, use it.</li>
<li><strong>It doesn't unlock anything</strong> and it doesn't remove copy protection.</li>
<li><strong>Almost no store issues one yet.</strong> Stores that sell files without copy
protection can start today. For the closed platforms, it is the same purchase
confirmation the law already requires them to send you — in the EU, Article 8(7)
of the Consumer Rights Directive (2011/83/EU) — in a form a machine can check.
If your store doesn't offer it, that is the thing to ask for.</li>
</ul>

<h2>One file must stay private</h2>
<p>If your download also contains a file ending in <code>.private.attest</code>,
never send it to anyone: it is what proves the purchase is <em>yours</em>. A real
store or support agent will never need it.</p>

<footer>
Already have a receipt in hand? <a href="what-is-this.html">What is this file?</a> ·
Curious how the seal works? See the
<a href="https://github.com/bernalli/attest/tree/main/docs/spec">attest specification</a>.
</footer>"""


def render_start_here() -> str:
    """Render the plain-language landing page for a reader with no receipt yet."""
    return buyer_surface.render_page(
        "Start here — attest",
        _START_HERE_BODY,
        extra_head=_START_HERE_HEAD,
        extra_css=_PAGE_CSS,
    )


def generated_pages() -> dict[Path, str]:
    """Return every generated page, keyed by the path it belongs at."""
    return {
        SITE_PUBLIC / "what-is-this.html": render_what_is_this(),
        SITE_PUBLIC / "start-here.html": render_start_here(),
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
