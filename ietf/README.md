# attest Internet-Draft — build toolchain

This directory carries the IETF Internet-Draft source for attest:
`draft-bernalli-open-purchase-receipts.xml` (docname
`draft-bernalli-open-purchase-receipts-00`). This document is a
**snapshot profile**: it distills the core receipt format and hybrid
signature profile from the living, normative specification
(`docs/spec/attest-v0.1.md`, `docs/spec/attest-v0.2.md`) into Internet-Draft
form. The living specification remains the normative source of truth; the
draft's own "Relationship to the living specification" subsection (§1.1)
declares exactly which revision of each file it mirrors.

## Toolchain decision: xml2rfc v3 XML, hand-authored (fallback path)

The plan's primary path was `kramdown-rfc` (Ruby) generating xml2rfc v3 XML,
which `xml2rfc` then builds to text/HTML. That path was **unavailable in the
authoring environment**: the system Ruby is `2.6.10` (`ruby -v`) and
`gem install` could not reach a package index, so `kramdown-rfc` could not be
installed there. Per the plan's own fallback clause, the draft is
therefore **hand-authored directly as xml2rfc v3 XML**
(`draft-bernalli-open-purchase-receipts.xml`), and only the `xml2rfc` pin
remains in the toolchain. There is no `.md` source for this draft; the `.xml`
file is authoritative.

**Pinned builder: `xml2rfc==3.34.0`**, run via `uvx` (no separate install
step; `uvx` resolves and caches the pinned version on first use). Verified
live end-to-end, twice — see "Build" below.

## Inline references, not `xi:include` — deliberately

Every citation in the draft (`RFC2119`, `RFC8174`, `RFC8785`, `RFC8032`,
`RFC4648`, `RFC9334`, `RFC9943`, `RFC7515`, `RFC9052`, `FIPS204`,
`W3C.VC-DATA-MODEL`, `C2PA`, `ATTEST-REPO`) is a full inline `<reference>`
element inside `<references>` — never an `xi:include` pulling from
`bib.ietf.org`. That host is not reachable from every environment this draft
has to build in, and inline references make the RENDER step deterministic
and reproducible
with no network access at all, in any environment — distinct from the
one-time pinned-toolchain install above (`uvx --from xml2rfc==3.34.0`),
which MAY fetch the package from PyPI the first time it runs in a given
environment (cached thereafter, per `uv`'s own resolver, and not repeated
on a subsequent invocation). The build command below passes `--no-network`
to the `xml2rfc` render step itself to make that narrower claim a verified
property, not an assumption: both local builds below completed with
`--no-network` and zero network calls made *by xml2rfc's own reference
resolution* — the property inline references exist to guarantee.

## Build

Where the default `uv` tool/cache directory is not writable ("Operation not
permitted"), export these before every `uvx` call — not needed on a CI runner
with a normal writable home, see the CI step below:

```sh
export UV_CACHE_DIR="$TMPDIR/uv-cache" UV_TOOL_DIR="$TMPDIR/uv-tools"
```

**The build command** (produces both `.txt` and `.html`):

```sh
mkdir -p ietf/build
cp ietf/draft-bernalli-open-purchase-receipts.xml \
   ietf/build/draft-bernalli-open-purchase-receipts-00.xml
uvx --from xml2rfc==3.34.0 xml2rfc \
    ietf/build/draft-bernalli-open-purchase-receipts-00.xml \
    --text --html --path ietf/build --no-network
```

This produces `ietf/build/draft-bernalli-open-purchase-receipts-00.txt`
and `...-00.html` (git-ignored; `ietf/build/` is not committed).

### The document date is deliberately unset

The front matter carries a bare `<date/>` with no attributes, so every render
stamps the day it was built and recomputes the expiry line from it. This is
not an oversight. The Datatracker refuses a submission whose document date is
more than three days from the submission date, and `xml2rfc` warns about the
same gap at build time ("The document date (...) is more than 3 days away from
today's date"); the check is a hard validation error, not advice — it blocks
automatic posting, leaving only a manual-posting request. A hard-coded date
goes stale on its own between the day the draft is written and the day it is
uploaded, which is exactly what happened to this draft between July and
August 2026.

An empty element removes the drift between writing the draft and building it.
What is left depends on the route. Uploading the **XML** hands the stamping to
the Datatracker, which resolves the element while processing the submission
and renders the plaintext itself. Uploading a locally built `.txt` freezes the
date of *its own build*, so an upload more than three days later is stale —
**on that route, build and upload in the same sitting.** If a fixed date is
ever wanted (a resubmission dated to match an announcement, say), put the
attributes back for that one build.

### Why the `cp` step: a naming quirk in xml2rfc 3.34.0

`xml2rfc`'s output filename tracks the **source file's own basename**, not
the `docName` attribute declared inside the `<rfc>` element — building
`draft-bernalli-open-purchase-receipts.xml` directly (the committed
source's actual name, with no `-00` suffix) produces
`draft-bernalli-open-purchase-receipts.txt`, not the `-00`-suffixed name
the docname implies. The CLI's own `-b`/`--basename` flag, which the
`--help` text describes as "specify the base name for output files", does
**not** do that in this pinned version: reading the installed
`xml2rfc/run.py`, `--basename` is aliased directly to `--path`
(`options.output_path = options.basename`) — a real quirk/regression in
3.34.0, not a documentation issue on our end. `-o`/`--out` sets an exact
filename but only for a single output format, so it cannot produce both
`.txt` and `.html` from one invocation either.

The one clean way to get the correctly-named files from the
committed source (which is deliberately named without `-00`, matching the
plan's fixed literal path) in a single `xml2rfc` invocation is the `cp` step
above: copy the source to a `-00`-suffixed name in the build directory
first, then build that copy with `--path`. This was verified live, twice
(see below), and is exactly what the CI step
(`.github/workflows/ci.yml`, `python` job) does with `$RUNNER_TEMP` in place
of `ietf/build/`.

### Verification (local, twice)

Both runs below completed cleanly (`--no-network`, zero warnings or errors)
and produced a non-empty `.txt` with zero `ERROR`/`TODO` occurrences:

```sh
grep -c 'ERROR\|TODO' ietf/build/draft-bernalli-open-purchase-receipts-00.txt
# 0
```

## Snapshot-profile drift detection

The draft's §1.1 ("Relationship to the living specification") states, in
two dedicated sentences, exactly which revision of each living-spec file it
mirrors:

- `attest-v0.1.md` at **revision 5**
- `attest-v0.2.md` at **revision 6** (hybrid signature profile only —
  Stage 2/Stage 3 material is a non-normative pointer only, §12)

`tools/check_spec_docs.py`'s `check_internet_draft_snapshot()` (wired into
`main()`, CI-gated) parses those two declarations and asserts each declared
revision integer **exists** as `(rev N)` in the corresponding spec's own
`## Revision log` section — existence, not latest-equality, so a later spec
revision landing on `main` does **not** by itself turn this check red. To
detect drift, a reader (or reviewer) compares the declared revision against
the *latest* entry in the living file's revision log: if they differ, this
draft has fallen behind the living specification and should be refreshed
(a new `-01` draft, an updated `-00` before submission, or a superseding
note) before being treated as current.

## Submission — done on 2026-08-06

A snapshot-profile mirror of this specification was submitted to the IETF
Datatracker on 2026-08-06 and accepted as an individual submission
(Informational, expires 2027-02-07). It went out under an earlier document
name; the source here carries the current one. The next revision has not been
submitted yet: when it goes out, it will declare the first as the document it
**replaces**, which the Datatracker tracks as a first-class relationship. An
I-D's base name is fixed for the life of a document, so a new name always
starts again at `-00` — that is expected, not a loss of standing.

How it was done, for whoever does the next revision. Submission is a **manual
action** for the maintainer and is not automated by anything here — the CI step
only proves the draft **builds cleanly**, never that it was submitted. No
Datatracker account is required: the tool accepts the upload unauthenticated
and mails a confirmation link to the authors listed in the document, which is
why the `bernalli@proton.me` address in the front matter has to be a mailbox
that actually receives mail. Uploading the **XML** is the better route — the
Datatracker renders the text itself, and it stamps the date while processing
(see "The document date is deliberately unset" above). Leave *Replaces* empty
for a fresh `-00`. Check the submission window live first: cut-offs are tied to
IETF meeting dates, and submissions close for the days around each meeting.

The idnits report for the `-00` came back **0 errors, 0 flaws, 1 warning**. The
warning counts the lines carrying non-ASCII characters: informational, and not
a defect to chase — RFC 7997 admits non-ASCII in RFCs and drafts under its own
rules, and nothing in this document failed validation. The lines the same report
flags as over-long are the ones carrying an em dash: idnits applies the
72-column limit in **bytes** (it runs under `LC_ALL=C`), and an em dash costs
three of them. Counted in characters — measured directly on the rendered
text, which is more than the report itself establishes — every line is
within 72. Neither is worth fixing.
