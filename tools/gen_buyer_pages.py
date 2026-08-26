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
important paper receipt — it doesn't live in any account, and nobody can take it
away with a click.</p>

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
purchase nobody can take away.</p>

<footer>
Curious about the cryptography behind this? See the
<a href="https://github.com/bernalli/attest/blob/main/docs/spec/attest-v0.1.md">attest specification</a>
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


def generated_pages() -> dict[Path, str]:
    """Return every generated page, keyed by the path it belongs at."""
    return {SITE_PUBLIC / "what-is-this.html": render_what_is_this()}


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
