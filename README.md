<img src="logo/banner.png" alt="attest">

**Own what you buy.** The seller signs a receipt, you hold the file, anyone can
verify it offline — even after the store is gone.

You don't own your movies. Not your games, your music or your ebooks either. You
clicked "buy", you paid real money, and what you got is a permission slip that
lives on someone else's server and can be revoked at any moment. The store folds,
an algorithm flags your account, a licensing deal expires — and a library you
spent years paying for evaporates. Nobody broke into your house. One click on a
machine you'll never see, and it's gone.

None of this was ever a secret: it's in the terms of service nobody reads. But
with physical media all but gone, the fine print is starting to bite. Sony
spelled it out this August: your PlayStation purchases are a "license, not
owned". Users across Europe and the UK had already been told what that means in
practice: on September 1st, 551 movies they had bought — *Terminator 2*,
*Paddington*, *Apocalypse Now* — disappear from their libraries, because a
licensing deal expired. No refunds. Who gives me back the money I paid for those
movies? Who decides whether I keep watching what I legitimately bought? Today the
answer is: they do. And Sony is no exception. Weeks earlier, Xbox had pulled
three games not just from the store but from the libraries of everyone who'd
bought them. Microsoft shut its ebook store in 2019: refunds went out, and every
book it had ever sold stopped opening anyway. Amazon once deleted *1984*, of all
titles, straight off people's Kindles. When Yahoo closed its music store in 2008
it switched off the DRM servers, and songs people had paid for stopped working on
any new device. Different store, different medium, same click.

Digital was supposed to set content free. A handful of stores sell honest,
DRM-free files; everywhere else it got rebuilt into an instrument of control.
attest is the counterattack. It can't win back the libraries already lost;
nothing can. But it's built so the next purchase doesn't end the same way: every
future purchase gets the one thing every physical purchase always had, a piece
that's yours — on your own disk, cryptographically provable, out of reach of
anyone's click. Here's how:

## What attest is

When you buy something digital, the seller signs a receipt and hands it to you.
That's the whole mechanism. The receipt is a small file: keep it on a disk, in
cloud storage, in a backup — anywhere you keep files that matter. Anyone can
check it's genuine with free
tools, offline, no account needed. If the store closes tomorrow, the receipt
still verifies twenty years from now. It's the part of your purchase nobody can
take away.

This works today wherever files are sold without DRM: GOG-style stores, itch.io,
independent publishers selling directly. A seller could start signing this
afternoon, without asking anyone's permission. Buy there, download, and keep the
file next to the receipt: content plus proof, both in your hands. No store does
it yet. The standard, two implementations and the conformance suite exist; the
first pilot doesn't.

Closed platforms are the second track. In the EU they're already required to
confirm every purchase on a durable medium; today that's the receipt email in
your inbox. attest is that same confirmation in a form a machine can verify and
you can take with you, still valid when the seller is no longer around to ask.
That gives regulators a concrete format to point to, and the standard is built
for exactly that.

Where this goes: receipts you can pass on to someone else where the rights holder
allows it; transfer authority that can outlive the original seller, the hardest
open problem on the roadmap; records witnessed by independent parties, so nobody
can quietly rewrite them; and publishers signing a pledge, today, that if they
ever shut down, their content becomes redistributable and your receipt proves
you'd bought it. Owning digital things the way you own physical ones. That's the
destination. The receipt is the first brick.

One thing a receipt is not, and this matters: it is not a backup. If a store dies
and you never downloaded the DRM-free file, no signature can conjure it back off
a dead server. What survives is the proof — see the
[FAQ](docs/faq.md) for exactly what that's worth in each case.

There is a way to change that answer, and it now runs rather than being planned:
a rights holder can sign a preservation pledge when they sell, and once that
pledge fires, an archive holding its own copy can hand the file to whoever proves
the receipt is theirs — and to nobody else. `python -m demo.pledge_dies` does
exactly that, end to end, on your machine. What is missing is not the mechanism:
it is a publisher who has signed one, an archive that holds anything, and prose
written by a lawyer instead of the placeholder the demo carries. The archive
gate the demo runs against is a non-normative reference, not a production gate;
it names the three things it does not do in [`demo/README.md`](demo/README.md).

`attest-receipts` on PyPI (issue and verify) and `attest-verifier` on npm (verify
only) are independent Python and TypeScript implementations. Their published
self-certification claims are recorded in [`docs/conformance.md`](docs/conformance.md);
the corpus now contains 215 leaves, and a release may claim the §20-expanded corpus
only once both implementations reproduce all 215. **Try it in your browser:**
<https://attest-receipts.org/> — drop a `.attest` bundle (or the built-in
sample) and watch it verify entirely client-side. Be clear about the status: no
store issues attest receipts in production yet, and there are no external reviews.
The package version and the wire format are different things — receipts declare
`attest_version` 0.1 or 0.2, and old receipts keep verifying under every later
release, by design.

**If you sell digital files, this is the part that concerns you:** signing
receipts costs one small self-hosted service next to your existing checkout, and
it gives your customers something no competitor offers — proof of purchase that
outlives your shop. Start with [`bridge/`](bridge/README.md), or tell me what
would stop you: [GitHub Discussions](https://github.com/bernalli/attest/discussions)
or `bernalli@proton.me`. A first seller is worth more to this project than
another feature.

## Start here

Depending on why you landed on this page:

- **You want to see whether it actually works.** Open the
  [verifier](https://attest-receipts.org/) and drop the built-in sample on it.
  It takes about thirty seconds, installs nothing, and you can disconnect from the
  network first — that is the whole point of the thing.
- **You want to know whether any of this concerns you.** Read the
  [FAQ](docs/faq.md). It answers the questions a sceptical person asks first,
  including the ones where the answer is no.
- **You want the standard.**
  [`docs/spec/attest-v0.1.md`](docs/spec/attest-v0.1.md) is the normative
  specification, [`attest-v0.2.md`](docs/spec/attest-v0.2.md) the additive delta,
  and [`docs/spec/vectors/`](docs/spec/vectors/) the conformance corpus every
  implementation is measured against.
- **You might be the person this was built for** — an archive, a successor, an
  escrow, anyone who could end up deciding who is entitled to something after the
  seller is gone. The question at the top of this page is a real one, and
  [Discussions](https://github.com/bernalli/attest/discussions) is where to answer
  it.

## How it works, for humans

At checkout, the store signs a receipt and hands the buyer an `.attest` bundle —
a small file the buyer keeps anywhere: disk, cloud, USB, wherever. There is no
account to keep alive and nothing to sync. Later, anyone with a verifier — a
friend, a marketplace, the buyer themself — can check that bundle's signature
offline against the issuer's published key material and confirm it is genuine;
whether it has since been revoked is only as good as the status material that
verifier has, and with none it reports revocation as unknown rather than
guessing. If the buyer needs to prove the receipt is specifically *theirs* (not
just a copy that has floated around), they can do so by disclosing a salt or
answering a key challenge, without exposing their identity to the verifier.
Nothing in this loop requires a server: there is no central attest authority, no
registry that must exist, and no phone-home — a verifier needs only the receipt
bytes, the issuer's key material, and, optionally, a revocation feed.

## What it is / is not

attest is a normative specification for a signed receipt envelope, a restricted
JSON canonicalization profile, a pinned Ed25519 signing/verification ruleset,
issuer key/artifact manifests with rotation and compromise handling — including a
compromise that is absorbing for whoever has seen it, and time-boxed against
anchored evidence rather than retroactive without limit — a layered
offline verification algorithm, revocation-by-class semantics, and buyer-binding
proof — plus a Python reference implementation and an independent TypeScript
verifier.

It is **not** a DRM-stripping tool, a content host, an index of content, a
marketplace, a general resale right (v0.1 defines no transfer at all; v0.2 §17
adds it only where the issuer mediates it), a blockchain or NFT product, or a
payment instrument. A receipt is evidence of a license grant, not the artifact
itself and not the transaction that paid for it.

None of this bypasses an unwilling seller: a receipt is issuer-signed, and
attest cannot conjure a valid one out of a store that refuses to sign. A seller
that never issues receipts leaves nothing for a later gate to check, and no
amount of protocol fixes that.

## Status

Spec v0.1 is complete and v0.2 is specified, with two independent
implementations — a Python reference implementation and a TypeScript verifier —
measured by the shared conformance corpus, now 215 leaves across 46 groups: 63
of them the v0.1 corpus, the rest exercising v0.2's hybrid signature profile,
transparency/anchoring behaviour, the upgrade-policy hardening (mixed-keyset
prohibition, artifact-manifest currency, anchor profile v2, logged revocation
deadlines), Stage 3 issuer-mediated transfer, Stage 4 preservation pledge, the
time-boxed compromise rescue, and publisher authorization. (A v0.1-only verifier is
required to reject v0.2 envelopes, so it is measured against the 63-leaf
subset.) There are also two end-to-end demos: one deletes a store's entire
infrastructure mid-lifecycle and proves the receipt still verifies, and one
carries that a step further — a rights holder's preservation pledge fires and
an archive hands the file back, but only against the receipt.

The published packages ship all of v0.2: Stages 1 and 2 (hybrid signatures;
transparency and anchoring), Stage 3 issuer-mediated transfer (§17), Stage 4
the preservation pledge (§18), the time-boxed compromise rescue (§19) and
publisher authority (§20).

Seven pieces of work go beyond what a test suite can show. All of them are on
`main`, and they are linked here rather than left invisible:

- **[Formal verification](formal/attest.spthy).** A Tamarin model of the wire
  protocol: machine-checked theorems that acceptance implies an issuer signature,
  that a rotation is accepted only when the previous active key signed it or it
  carries an explicit compromise flag, and that the reason a revoked key is
  rejected cannot itself be forged — soundness, not liveness
  — plus attack exhibits proved *reachable* rather than argued in prose, plus
  negative controls that must falsify. Each theorem states its own scope in the
  theory file; nothing is claimed more broadly there than the prover checked, and
  a CI checker pins those statements so the claims cannot drift from the proofs.
- **[Threat model](docs/spec/attest-threat-model.md).** 77 attacks catalogued
  across the whole receipt lifecycle, each either mitigated or recorded as out of
  scope with a reason, a traceability matrix, and the protocol gaps the exercise
  found left tracked in the open instead of quietly fixed.
- **[Privacy considerations](docs/spec/attest-privacy.md).** Every field
  classified by what it reveals to which observer, twenty testable privacy claims,
  and a GDPR annex covering what a receipt deliberately does not record.
- **[Transfer economics](docs/spec/attest-transfer-economics.md)**
  (non-normative). The market and legal context behind Stage 3's transfer profile
  — resale velocity, the issuer-royalty incentive, and the CJEU case law
  (*UsedSoft*, *Tom Kabinet*) that makes transfer issuer-mediated rather than a
  general resale right.
- **Internet-Draft.** A snapshot-profile mirror of this specification was
  submitted to the IETF Datatracker on 2026-08-06 and accepted as an individual
  submission (Informational, expires 2027-02-07) — it declares that it mirrors
  v0.1 revision 5 and v0.2 revision 6, so the specification in this repository,
  not the draft, remains normative, and the published snapshot is several
  amendments behind it. On the Datatracker that first submission is filed as
  `draft-martinalli-open-purchase-receipts-00`. The
  [XML source](ietf/draft-bernalli-open-purchase-receipts.xml) lives here under
  the maintainer's current handle and builds clean to txt/html in CI; the next
  revision will go out under that name, declaring the first as the document it
  replaces. Being an I-D means the
  document exists and can be cited as work in progress, nothing more: it is not
  endorsed by the IETF and has no formal standing in the standards process.
- **[Standards-relationship annex](docs/spec/attest-standards-relationship.md).**
  Documents attest's boundary against every adjacent standard people compare it to
  — W3C Verifiable Credentials, eIDAS 2.0/the EUDI Wallet, JOSE/JWS and COSE, RFC
  8785 (JCS), C2PA, SCITT/RFC 9943, and RATS (RFC 9334) — so each comparison is
  answered once instead of re-argued per issue.
- **[Conformance program](docs/conformance.md).** One documented command, run with
  a third party's own adapter against the vector corpus, produces a pass/fail
  report and a self-certification claim; the recorded pass counts live in that
  document and must be updated only from a fresh runner report.

## Quickstart

Install the reference implementation from PyPI (the distribution is named
`attest-receipts`; the import package and the CLI are both `attest`):

```sh
pip install attest-receipts
attest --help
```

The TypeScript verifier is on npm as
[`attest-verifier`](https://www.npmjs.com/package/attest-verifier):

```sh
npm install attest-verifier
```

Or work from a checkout of this repo:

```sh
uv venv --python 3.12 .venv && uv pip install --python .venv -e '.[dev]'
# or: pip install -e .
```

```sh
.venv/bin/attest --help
```

```sh
.venv/bin/python -m demo.store_dies
.venv/bin/python -m demo.pledge_dies
```

```sh
.venv/bin/pytest --cov=attest --cov-report=term-missing
```

and a TypeScript verifier quickstart:

```sh
cd verifiers/ts && npm install && npm test
```

See [demo/README.md](demo/README.md) for what each step of the demos proves, and
[docs/spec/attest-v0.1.md](docs/spec/attest-v0.1.md) plus its companion
[JSON Schema](docs/spec/schema/attest-receipt.schema.json) for the normative
specification. [docs/spec/vectors/](docs/spec/vectors/) holds the conformance
corpus every implementation is checked against.

For merchants who'd rather not hand-sign anything, see [bridge/README.md](bridge/README.md).

For anyone wanting to run a witness — the component that cosigns a log's
checkpoints so a verifier can tell that somebody else saw the same tree — see
[witness/README.md](witness/README.md). Like the bridge, it is a reference
implementation for operators and is not published to any package registry.

[docs/spec/attest-v0.2.md](docs/spec/attest-v0.2.md) is an additive delta
specification defining the v0.2 hybrid Ed25519+ML-DSA-65 signature profile
(post-quantum-resistant receipts, `attest_version: "0.2"`); v0.1 receipts
remain valid and verifiable forever. That profile was Stage 1; Stage 2 — issuer
key transparency and timestamp anchoring, where a log corroborates a receipt's
existence without ever being able to make an unsigned receipt look authentic —
is specified in the same document. Stage 3 — issuer-mediated transfer, giving
`license.transferable` its first real meaning, layered on top of the Stage 2 log
— is specified there too (§17); business economics around resale are
deliberately out of protocol and live in the non-normative
[transfer-economics annex](docs/spec/attest-transfer-economics.md).

[docs/spec/attest-versioning.md](docs/spec/attest-versioning.md) is the
normative upgrade policy governing both specifications above: the additive
pattern new extensions must follow, the eternal-verifiability guarantee
(deprecation may degrade how a conforming receipt's result is classified,
never the ability to verify its bytes — verifiable forever is not valid
forever), the three-state algorithm lifecycle (`active` / `deprecated` /
`unsafe`), the amendment procedure, and the signature-suite, payload-field,
revocation-class, log-entry-type, and transfer-type registries.

[docs/spec/attest-threat-model.md](docs/spec/attest-threat-model.md) is the
maintained threat model behind the two specifications above — a living
normative companion that analyzes their mechanisms rather than imposing
requirements of its own — and
[docs/spec/attest-privacy.md](docs/spec/attest-privacy.md) is its
privacy-considerations sibling.

The core protocol properties are machine-checked in Tamarin: [formal/](formal/)
holds the model, the property↔lemma↔spec map, and the honest scope of what is
and is not proved, gated in CI by a statement-pinning checker.

[docs/spec/attest-standards-relationship.md](docs/spec/attest-standards-relationship.md)
(non-normative) is the boundary annex: in terms an expert in each standard
would accept, it states attest's relationship to W3C Verifiable Credentials,
eIDAS 2.0/the EUDI Wallet, JOSE/JWS and COSE, RFC 8785 (JCS), C2PA, SCITT
(RFC 9943), and RATS (RFC 9334) — including what a future bridge to one of
them could look like, where one exists.

## Roadmap / north star

Non-normative, and deliberately undated — these are directions, not commitments:

The authorized preservation escrow described at the top of this page is not
listed here: it is the case this project is aimed at, not a future direction.
What follows is genuinely speculative.

- **Evidence capture for non-cooperating stores.** A research track into
  TLS-session-proof techniques (the zkTLS/TLSNotary class) that could let a buyer
  capture their own evidence of a purchase from a store that never signs anything,
  at weaker-than-issuer-signed trust. Legal review is required before any of this
  is built.
- **Registry / replication layer.** An optional layer for replicating verification
  material, with optional Merkle-root transparency anchoring — separate from the
  shipped §17.5 chain-of-title audit surface, and still strictly optional.

## Licensing, contributing, contact

**License.** Code is licensed [Apache-2.0](LICENSE); the specification and other
documentation are licensed [CC BY 4.0](LICENSE-docs) — reuse and derivatives of
the spec must credit the original author, since attribution is a condition of
that license, not a courtesy. [`NOTICE`](NOTICE) and [`AUTHORS`](AUTHORS) carry
the required attribution.

**Naming.** The name *attest* identifies this project and implementations that
actually conform to it; forks are welcome to use the technology but not the name
for a divergent derivative. This paragraph is a naming norm, not a trademark
registration — real trademark enforcement would require actually registering the
mark, which has not happened. Conformance claims follow the self-certification
process in [docs/conformance.md](docs/conformance.md).

**Contributing.** See [`CONTRIBUTING.md`](CONTRIBUTING.md). Implementation pull
requests must pass all 215 conformance vector leaves and keep both the Python and
TypeScript suites green.

**Contact.** Use GitHub Issues for technical bugs, GitHub Discussions for
everything else, or email `bernalli@proton.me`.
Security issues follow a different path — see [`SECURITY.md`](SECURITY.md), and
do not open a public issue for a vulnerability.

Skeptical about any of this? [docs/faq.md](docs/faq.md) answers the first
questions a reasonable person asks.
