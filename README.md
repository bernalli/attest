<img src="logo/banner.png" alt="attest">

**When the store is gone, someone still has to decide who was entitled.**

An archive holds an offline copy of a digital good it is authorized to release,
but only to the people who bought it — a game, an album, a film, an ebook, a
piece of software. The store that sold it has shut down, and its customer
database went with it. The archive still has to decide, with no human in the
loop, which claimants may download the file. That decision is the one attest was
built to make possible.

attest is an open standard and reference implementation for signed purchase
receipts the *buyer* holds. The seller signs one at checkout, the buyer keeps the
file, and a gate can check it offline afterwards with nothing to contact: the
bundle carries the issuer's key and artifact manifests. Carrying them is not the
same as trusting them — key material that only ever arrived inside a bundle is
reported as unauthenticated, so the anchor has to be issuer key material somebody
pinned while the issuer still existed. Every receipt also carries a commitment to
a buyer identifier — an email address or an issuer account — and may bind a buyer
public key, so a claimant can show a receipt is *theirs* rather than a copy that
floated around. What that costs in privacy depends on which path is used:
disclosing the salt is a bearer proof that hands the identifier to the verifier
and can be replayed, while a challenge answered with a bound buyer key proves
possession without disclosing either. What the receipt cannot do is decide:
whether the grant it describes still qualifies is the operator's policy, not
attest's.

Most of the time none of this is needed. While a seller or a successor still
holds usable records, it can answer the question itself. Where a human weighs the
evidence — a refund desk, a dispute, a judge — a bank statement and an order
confirmation are what actually get used. And where the store simply hands over a
durable DRM-free installer, GOG's answer and a better one, there is no later gate
to operate at all: delivery beats evidence whenever delivery is available.

What is left is narrow, and it has four conditions that must hold together.
Authorized content survives somewhere. Some legitimate operator may distribute
it. Distribution is restricted to a defined entitled class rather than published
openly. And the seller's usable entitlement records do not survive. If any one of
them fails, nothing here is needed.

`attest-receipts` 0.4.0 on PyPI (issue and verify) and `attest-verifier` 0.4.0 on
npm (verify only) are independent Python and TypeScript implementations that
agree on all 130 conformance vector leaves. **Try it in your browser:**
<https://bernalli.github.io/attest/> — drop a `.attest` bundle (or the built-in
sample) and watch it verify entirely client-side. Nothing in production uses it:
no archive runs such a gate today, there are no issuers and no external reviews,
no law I know of asks for portable receipts, and the wire format is frozen at
`attest_version` 0.1 and 0.2 — 0.4.0 is the package release, not the protocol
version — until an operator with this problem appears.

**The question, for archives, successors and escrow providers:** if you run — or
expect one day to run — a service that must release an authorized digital good
only to the people who bought it, after the seller and its records are gone,
what evidence would that gate accept, and who decides the policy behind it?
Answers in [GitHub Discussions](https://github.com/bernalli/attest/discussions) or
to `bernalli@proton.me` are worth more to this project than another feature.

## Start here

Depending on why you landed on this page:

- **You want to see whether it actually works.** Open the
  [verifier](https://bernalli.github.io/attest/) and drop the built-in sample on it.
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
issuer key/artifact manifests with rotation and compromise handling, a layered
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

Spec v0.1 is complete and v0.2 is specified and implemented on `main`, with two
independent implementations — a Python reference implementation and a TypeScript
verifier — that agree on all 130 conformance vector leaves across 38 groups: 51
of them the v0.1 corpus, the rest exercising v0.2's hybrid signature profile,
transparency/anchoring behaviour, the upgrade-policy hardening (mixed-keyset
prohibition, artifact-manifest currency, anchor profile v2, logged revocation
deadlines), and Stage 3 issuer-mediated transfer. (A v0.1-only verifier is
required to reject v0.2 envelopes, so it is measured against the 51-leaf
subset.) There is also an end-to-end demo that deletes a store's entire
infrastructure mid-lifecycle and proves the receipt still verifies.

The published packages are `0.4.0`, which ships all of v0.2 — Stages 1 and 2
(hybrid signatures; transparency and anchoring) and Stage 3, issuer-mediated
transfer, this document's own §17.

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
- **[Threat model](docs/spec/attest-threat-model.md).** 67 attacks catalogued
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
  not the draft, remains normative. The [XML source](ietf/draft-bernalli-open-purchase-receipts.xml)
  lives here and builds clean to txt/html in CI; the next revision goes out
  under the name it now carries and replaces the first. Being an I-D means the
  document exists and can be cited as work in progress, nothing more: it is not
  endorsed by the IETF and has no formal standing in the standards process.
- **[Standards-relationship annex](docs/spec/attest-standards-relationship.md).**
  Documents attest's boundary against every adjacent standard people compare it to
  — W3C Verifiable Credentials, eIDAS 2.0/the EUDI Wallet, JOSE/JWS and COSE, RFC
  8785 (JCS), C2PA, SCITT/RFC 9943, and RATS (RFC 9334) — so each comparison is
  answered once instead of re-argued per issue.
- **[Conformance program](docs/conformance.md).** One documented command, run with
  a third party's own adapter against the vector corpus, produces a pass/fail
  report and a self-certification claim; both in-repo verifiers pass 130/130 through
  that exact path.

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
.venv/bin/python demo/store_dies.py
```

```sh
.venv/bin/pytest --cov=attest --cov-report=term-missing
```

and a TypeScript verifier quickstart:

```sh
cd verifiers/ts && npm install && npm test
```

See [demo/README.md](demo/README.md) for what each step of the demo proves, and
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
pattern new extensions must follow, the eternal-verifiability guarantee, the
three-state algorithm lifecycle (`active` / `deprecated` / `unsafe`), the
amendment procedure, and the signature-suite, payload-field, revocation-class,
log-entry-type, and transfer-type registries.

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
requests must pass all 130 conformance vector leaves and keep both the Python and
TypeScript suites green.

**Contact.** Use GitHub Issues for technical bugs, GitHub Discussions for
everything else, or email `bernalli@proton.me`.
Security issues follow a different path — see [`SECURITY.md`](SECURITY.md), and
do not open a public issue for a vulnerability.

Skeptical about any of this? [docs/faq.md](docs/faq.md) answers the first
questions a reasonable person asks.
