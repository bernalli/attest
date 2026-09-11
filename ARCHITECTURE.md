# Architecture

This document describes how attest is built, not what it is for — `README.md` and
`docs/faq.md` cover that. It exists for someone who has read the README, wants to change
code, and needs to know where a given piece of behavior lives before touching it.

## The shape of the system, in one paragraph

attest defines a signed receipt envelope and an offline verification algorithm
(`docs/spec/attest-v0.1.md`, extended additively by `docs/spec/attest-v0.2.md`), and ships
two independent implementations of that algorithm, intended to agree on canonical bytes
and protocol-defined verdicts within the specified resource limits: a Python reference
implementation (`src/attest/`) that both issues and verifies receipts, and a TypeScript
verifier (`verifiers/ts/`) that only ever reads them. A shared, language-neutral
conformance corpus (`docs/spec/vectors/`, 47 groups, 227 leaf test cases — counted with
`find docs/spec/vectors -name expected.json | wc -l`) is the contract both cores are held
to; a set of differential tools (`tools/*_differential.py`) additionally compares selected
observable outcomes on generated inputs, with scope and permitted differences defined
by each tool. Around those two cores sit
four things that are not the protocol itself: a merchant-run issuing service (`bridge/`), a
reference transparency-log witness (`witness/`), a browser verifier
(`site/`, deployed as attest-receipts.org) and a single-file offline verifier built from the
same TypeScript source (`desktop/`). Two more pieces measure claims the conformance suite
cannot: a Tamarin model of the wire protocol (`formal/attest.spthy`) and a maintained threat
model (`docs/spec/attest-threat-model.md`).

## Repository map

| Path | What it is | Normative? |
| --- | --- | --- |
| `docs/spec/attest-v0.1.md` | The base specification: envelope, payload fields, canonicalization, key manifests, revocation, verification algorithm. | Yes |
| `docs/spec/attest-v0.2.md` | Additive delta: hybrid signatures, transparency/anchoring, issuer-mediated transfer, the preservation pledge, the compromise rescue, publisher authority. | Yes |
| `docs/spec/attest-versioning.md` | The upgrade policy both specs above answer to: how an extension may be added, the eternal-verifiability guarantee, the algorithm lifecycle. | Yes |
| `docs/spec/schema/attest-receipt.schema.json` | JSON Schema for the receipt payload, used by `validate.py` for the schema dimension of verification. | Yes |
| `docs/spec/vectors/` | The conformance corpus: 47 groups, 227 leaves, each with fixed inputs and expected assertions under the corpus's matching rules. Generated, not hand-edited (see below). | Yes (as a corpus) |
| `docs/spec/attest-threat-model.md` | Living companion: attacks catalogued against the two specs, each mitigated or recorded out of scope. | Non-normative but maintained |
| `docs/spec/attest-privacy.md` | Field-by-field privacy classification and GDPR annex. | Non-normative |
| `docs/spec/attest-transfer-economics.md`, `docs/spec/attest-standards-relationship.md` | Market/legal context for transfer; boundary against adjacent standards (VC, eIDAS, JOSE/COSE, C2PA, SCITT, RATS). | Non-normative |
| `src/attest/` | The Python reference implementation: issues and verifies receipts, manifests, revocation, transfer, grant, and authority documents. | — |
| `verifiers/ts/` | The independent TypeScript verifier. Verification only; no issuance. Published to npm as `attest-verifier`. | — |
| `bridge/` | `attest_bridge`: the merchant-run service that turns a paid order (Stripe, Shopify, itch.io, Paddle, PayPal) into a signed receipt. Never published. | — |
| `witness/` | `attest_witness`: the reference C2SP tlog-witness implementation for v0.2 §11.4. Never published. | — |
| `site/` | The browser verifier at attest-receipts.org: parses `.attest` bundles client-side and renders a human-readable verdict. Depends on `verifiers/ts` by relative path. | — |
| `desktop/` | Builds `site/` + `verifiers/ts` into one offline HTML file with an enforced no-network content security policy. | — |
| `demo/` | Two end-to-end demonstrations: a store's entire infrastructure dying mid-lifecycle, and a preservation pledge firing and handing a file back. Not part of the protocol. | — |
| `formal/attest.spthy` | Tamarin model of the wire protocol; 45 lemmas, gated by sha256-pinned statement digests. | — |
| `ietf/` | Internet-Draft snapshot mirroring a pinned revision of the specs, built with a pinned xml2rfc toolchain. | — |
| `tools/` | Generators, differential/parity checkers, and CI-support scripts shared by every component above. | — |
| `tests/` | The Python reference implementation's test suite, plus the hostile-container corpus (`tests/container-corpus/`, generated). | — |

## The wire format: envelope, canonicalization, signing

A receipt on the wire is a JSON **envelope**: a signed `payload` object (issuer, buyer
commitment, work identifiers, license terms, survivability terms) plus a `signatures` block
and an optional `delivery` member (§4 of `attest-v0.1.md`). What gets signed is never the
JSON text as typed — it is the payload's **canonical** serialization.

`canon.py` (and its byte-for-byte twin `verifiers/ts/src/canon.ts`) implements RFC 8785 (JCS)
restricted to an integer-only profile: floats are rejected at both serialization and parse
time, and integers must satisfy `|n| < 2**53` (the I-JSON safe range), which removes
ECMAScript's `Number::toString` from the trust boundary entirely. The parser
(`canon.loads_strict`) is strict in the direction JCS requires and attest tightens further:
duplicate object members are rejected (not silently last-wins), lone UTF-16 surrogates are
rejected, and whole-document nesting depth is capped at `MAX_DEPTH = 256` — enforced
symmetrically at parse *and* at serialize, so a conforming issuer can never sign something no
conforming verifier could parse back. `CONTRIBUTING.md` documents the one place this profile
is easy to get wrong across languages: JCS orders object member names by UTF-16 **code unit**,
which disagrees with Python's and Go's/Rust's default string sort the moment an astral
character (outside the Basic Multilingual Plane) appears next to a private-use character.
`canon.canonical_key_order` is the single place that ordering is defined, and every reader
that needs to answer "which member comes first" — including `trust_material.py`'s refusal
message for an unknown store member — calls it rather than the language's default sort.

Signing is Ed25519 under a **pinned** ruleset (`keys.py`, backed by PyNaCl/libsodium, whose
native SUF-CMA and small-order checks are why that backend was chosen over a hand-rolled one):
non-canonical `S` encodings and small-order `A`/`R` points are rejected, not merely
tolerated. `alg` is read from the signature block only to confirm it is the literal string
`"Ed25519"` — it is never used to *select* an algorithm; there is exactly one algorithm and no
downgrade path. v0.2 (`docs/spec/attest-v0.2.md` §2) adds a **hybrid** profile,
`ed25519+ml-dsa-65`: both an Ed25519 leg and an ML-DSA-65 (FIPS 204) leg sign the same
canonical bytes, and acceptance is AND-semantics — both must verify. `pq.py` is the ML-DSA-65
primitive; its module docstring is explicit that the pure-Python `dilithium-py` package is a
**dev-only test oracle** for deterministic vector generation and must never be imported from
runtime code, which is why `dilithium-py` sits in `pyproject.toml`'s `dev` extra, not in
`dependencies`.

The JSON side-documents — key manifests, artifact manifests, revocation records,
transfer records, sunset grants, cessation declarations and publisher authorization
manifests — use Ed25519, or hybrid signatures where required, over their canonical
JSON body. The excluded signature member is `manifest_signature` for key and artifact
manifests and `signature` for the other listed JSON documents.

Transparency checkpoints use a different preimage: both log signature legs cover the
UTF-8 text `origin + "\n" + decimal_tree_size + "\n" + base64_root + "\n"`.
The separating blank line and the signature lines are excluded. This is the C2SP
signed-note format implemented by `tlog.py`, not canonical JSON.

## Two cores, one parity contract

`src/attest/` issues and verifies; `verifiers/ts/` (published as `attest-verifier`) only
verifies — its own README states this as an independence claim, not a limitation: "This
package is the verifier — it reads receipts and never issues them," and it shares no code,
no runtime, and no crypto library with the Python side (`@noble/curves`/`@noble/hashes`/
`@noble/post-quantum`, not libsodium). Counted directly: `src/attest/` holds 28 Python
modules; `verifiers/ts/src/` holds 21 TypeScript modules (`find src/attest -name '*.py' |
wc -l`; `find verifiers/ts/src -maxdepth 1 -name '*.ts' | wc -l`). The TypeScript side has no
`issue.ts`, `keys.ts`-as-signer, or `cli.ts` — issuance is a Python-only surface by design,
and the gap is visible in the file lists, not just stated in prose.

Two mechanisms hold the cores to the same answers:

- **The conformance corpus** (`docs/spec/vectors/`) is the *specification*-level contract:
  each of 227 leaves supplies inputs and assertions for a `VerificationResult`,
  `ChainAuditResult`, witness quorum result, or redemption result.
  Receipt-result matching combines exact fields, fields checked only when present in
  `expected.json`, and `errors_contains`/`warnings_contains` substring checks; extra
  output members are ignored. The other result shapes have their own matching rules.
  Passing therefore establishes those assertions, not identity of the complete output.
  `docs/conformance.md` describes the public runner:
  `tools/conformance_runner.py --adapter '<cmd> {leaf}' --subset v0.1|v0.2`.
  A v0.1-only verifier is measured against 67 leaves (63 base-group leaves plus
  `35i`, `37s`, `41f`, and `41v`); v0.2 uses all 227. One mismatch fails the subset.
  Separately, the Python and TypeScript conformance suites compare canonical payload
  bytes against `canonical.json` wherever supplied; the public runner does not perform
  that direct byte comparison.
- **The differential tools** measure bounded cross-implementation properties:
  `tools/container_differential.py` compares container acceptance, rejection codes,
  member metadata and content hashes; `tools/importer_differential.py` compares importer
  outcome classes and projections of receipts, trust material, proofs and legal text,
  with declared advisory differences and resource-limit differences above the normative
  floors. `tools/trust_material_differential.py` compares admission, refusal classes,
  blamed members and ordered results, not complete diagnostic text, and explicitly
  accounts for a declared M7/M8 difference on a 4,301-digit integer token.
  `tools/witness_parity_cases.py` supplies shared witness cases to its Python and
  TypeScript consumers; `tools/gen_container_corpus.py` generates container fixtures
  and seeded mutations. The `test` job in `pages.yml` runs
  `container_differential.py --count 500 --seed 20260902`.
  These checks cover the cases and projections they execute, not all remaining inputs.
  Container divergences are retained automatically; importer and trust-material inputs
  are retained when `--keep` is supplied. The runners accumulate disagreements rather
  than universally stopping at the first one.

Byte-for-byte agreement extends past the receipt itself: the `.attest` container reader
(`container.py` / `site/src/container.ts`) and the DEFLATE-stream validator (`deflate.py` /
`site/src/deflate.ts`) are commented line-for-line (`# S1`…`# S23` in Python, `// S1`…`// S23`
in TypeScript) precisely because two conforming ZIP or DEFLATE libraries can legally disagree
about a hostile input — see "The bundle and container layer" below.

## The trust boundary: a snapshot, never a live object

`verify()` takes a `TrustStore` — the caller's local trust material: which issuer key
manifests are pinned, how each was obtained, and (optionally) each issuer's manifest history.
`trust_material.py` (and its parity twin `verifiers/ts/src/trustMaterial.ts`) exists because
that object crosses a trust boundary that a plain `dict`/object does not close on its own.

The module's own docstring states the concern precisely: `verify.py` and `manifests.py`
answer questions like "is this key still active" by reading fields off whatever the embedding
application handed in — an ORM row, a lazy wrapper, a database proxy. Such an object can
**answer a question differently depending on when it is asked**, while still serializing to
the exact bytes the issuer signed — so its self-authenticity gate is satisfied, and the lie
only surfaces at the point of decision. `trustMaterial.ts`'s docstring records a measurement,
not a hypothetical: on the published 0.9.3 core, a getter (or `Proxy` trap) that answers
truthfully for the first two reads and lies afterward makes a receipt signed by a key the
manifest itself marks `compromised` come back `signature: "valid"` — silently, with no error
and no warning.

The fix is structural rather than a coding convention. Python's `TrustStore.from_bytes`
and `KeyManifest.from_bytes`, and TypeScript's `parseTrustStore` and `parseKeyManifest`,
admit serialized bytes and produce library-owned snapshots; direct public construction
is refused. The library parses the bytes strictly and checks canonical representability.
Trust-store admission additionally checks the allowed top-level members and their
container nesting. Key-manifest admission requires only a JSON object: neither boundary
validates manifest contents, provenance values, or agreement between a store's manifest
and its chain. Those semantic and authenticity checks remain the consumers' responsibility.

The parsed Python trees consist of exact built-in types, so downstream reads do not call
the original object's overridden methods. Public `data()` exports are fresh trees, not
the internal trees used by verification. The Python module explains why this replaced
live-object materialization: copying a live object still asks that object questions,
and successive reads can disagree. The snapshot boundary removes those reads; admission
does not establish that the supplied trust material is authentic or correctly configured.

## The verification pipeline

`verify()` (`verify.py`, `verifiers/ts/src/verify.ts`) implements attest-v0.1.md §6, "steps
0-7," and the module docstring states the pipeline invariant plainly: `canon.loads_strict`
parses the raw envelope bytes exactly once (step 0), and every later step operates on that
one parsed object — never on the raw bytes again, never on a re-serialization of it. Steps 6
(revocation) and 7 (binding) run only once the receipt already has a valid signature *and* a
valid schema; an already-invalid receipt keeps `revocation: "unknown"` and
`binding: "not_checked"` rather than getting a verdict computed against material that was
never trustworthy to begin with.

The result is a `VerificationResult` dataclass whose own docstring states the design
principle: "each dimension of trust is reported independently so a caller can degrade
gracefully instead of getting a single opaque true/false." The core dimensions are
`signature`, `schema`, `revocation`, `binding`, and `trust` (verified / TOFU /
unverified-rotation); `ok` is a computed property, not a stored field, and it is
**deliberately not** a function of `trust` — v0.1 §11.1's vector 14b pins that a receipt
reached through a discontinuous key rotation still verifies `ok: true`, because trust and
validity answer different questions. A caller that needs identity assurance reads `trust`
alongside `ok`; the CLI exposes the distinction directly as `attest verify --reject-trust`.

Every v0.2 capability layers onto this result additively, never touching the five v0.1
fields:

- **Stage 2 — transparency and anchoring** (`transparency.py`, `tlog.py`, `anchor.py`):
  `verify()` evaluates one supplied claim, either for the receipt's signed core or for
  the issuer key manifest resolved from its own trust store. `transparency` reports
  logging and optional Bitcoin anchoring of that claim; `corroboration` reports logged
  or witnessed standing, with additional rotation-chain requirements for a rotated
  key-manifest claim. `manifest_freshness` is populated for qualifying key-manifest
  claims. An anchored manifest does not establish when the receipt existed.
  These reporting fields are informational; supplying `log_keys` and `anchor_policy`
  also enables the separately specified validity exceptions. Callers supplying none
  of this Stage 2 configuration retain the existing behavior.
- **§19 — the compromise rescue**, one of a small, explicitly enumerated set of *exceptions*
  to "Stage 2 is informational": a receipt whose own transparency evidence proves it was
  anchored strictly before the earliest anchored `compromised` declaration for its signing
  key can still verify, even though v0.1 §7.3's unconditional rule would otherwise reject any
  receipt from a compromised key. `ok` never reflects `trust` in isolation; this exception
  lives in `signature`, decided from `compromise_view`.
- **Stage 3 — issuer-mediated transfer** (`transfer.py`, `docs/spec/attest-v0.2.md` §17): a
  BACKED `status: "transferred"` revocation record extinguishes the old receipt exactly as
  effectively as a plain revocation, reported as `revocation: "transferred"` (distinct from
  `"revoked"` so a caller can tell "sold" from "revoked" on the same feed) and capping `ok`
  the same way. Reachable only when the caller supplies `transfer_view`.
- **Stage 4 — the preservation pledge** (`grant.py`, `docs/spec/attest-v0.2.md` §18): `grant`
  and `grant_trust` report whether a sunset grant has activated. `grant_view`'s presence is
  its own capability gate — a leaf that ships none gets `not_checked`/`not_checked` — and by
  design (D6 in the spec) it takes **no exception at all**: a grant is a permission that
  becomes exercisable, never a validity property of the receipt, so it never touches
  `signature`/`schema`/`revocation`/`binding`/`trust`/`ok`.
- **§20 — publisher authority** (`authority.py`): `publisher_authority` and
  `publisher_authority_trust`, gated the same additive way by `authority_view`.

`revocation_view`, `transfer_view`, and `compromise_view` are untrusted lists the caller
passes in (typically read from a bundle's `proofs/` member or fetched separately);
`log_keys`, `anchor_policy`, and `witness_policy` are the verifier's own **trusted**
configuration and must never be taken from the bundle being checked — `verifiers/ts/README.md`
states this distinction explicitly, because conflating the two would let a hostile bundle
supply the very trust anchors used to judge it.

## The side-document family

Seven JSON document types besides the receipt payload use canonical-body signing:
key manifests and artifact manifests (`manifests.py`), revocation records
(`revocation.py`), transfer records (`transfer.py`, v0.2 §17), sunset grants and
cessation declarations (`grant.py`, v0.2 §18), and publisher authorization manifests
(`authority.py`, v0.2 §20). Key and artifact manifests exclude `manifest_signature`;
the other five exclude `signature`.

Their member-admission rules are not identical. Transfer records, sunset grants,
cessation declarations and publisher authorization manifests reject unknown members.
The key-manifest, artifact-manifest and revocation-record verifiers do not impose that
same closed-member check; additional members remain part of the canonical signed body.
The receipt payload tolerates unknown top-level fields with warnings for forward
compatibility per v0.1 §11.2.

`views.py` exists because the side-document evidence shapes consumed through
`verify()`'s `revocation_view`, `transfer_view`, and `compromise_view` parameters
had consumers and no producer: callers, tests, and tooling were assembling them
by hand. Its `build_revocation_view`, `build_transfer_view`, and
`build_compromise_view` functions assemble those shapes. It does not provide
a builder for `grant_view`.

## Transparency, anchoring, and witnessing

Stage 2's substrate is a documented subset of C2SP tlog-tiles (`docs/spec/attest-v0.2.md`
§7.2): `tlog.py` implements RFC 6962 Merkle-tree inclusion/consistency proofs and six
CLOSED log-entry schemas (`key-manifest`, `receipt`, `revocation-record`,
`transfer-record`, `cessation-declaration`, `publisher-authorization`), plus hybrid
(Ed25519 + ML-DSA-65) signed-note checkpoints — `Checkpoint`/`LogKey`/
`verify_checkpoint`, with AND-semantics between the two signature legs. `anchor.py` layers OpenTimestamps-style Bitcoin
block-header anchoring on top of a checkpoint, gated by a `passes_horizon` check against a
CRQC cutoff the verifier's own `AnchorPolicy` pins. `witness.py` defines `WitnessPolicy`: a
CLOSED, **trusted** verifier-configuration document (packaged with the verifier release,
never read off an evidence bundle — the same "trusted configuration never comes from the
bundle" rule as `log_keys`/`anchor_policy`) used to evaluate activation-witness quorums for
v0.2 §11.4. `witness/` is the separate, runnable reference implementation of the *witness
role* itself — a C2SP tlog-witness service that cosigns checkpoints so a verifier can tell
that somebody else observed the same tree. Its own README is explicit about what a single
witness does not give you: "Ruling out split views needs several [witnesses], run by parties
that are genuinely independent," which is why every witnessed verdict also carries
`witness_independence_not_established`.

## The bundle and container layer

A `.attest` file (the shareable bundle a buyer actually holds) is a ZIP archive, and
`container.py`'s own docstring states the problem it exists to close: "which members does
this archive hold" has more than one legal answer, because two widely used ZIP readers
resolve the central directory differently on a hostile input — one trusts the
end-of-central-directory record's declared offset and 16-bit entry counter, the other walks
backward from the end of the file and ignores both. The same archive bytes can therefore
present a different member list to two conforming readers. `container.py` (and its
line-numbered twin `site/src/container.ts`) removes the ambiguity instead of picking a side:
it refuses every archive whose two models could disagree — single-disk only, no ZIP64, the
two entry counters must agree, the central directory must occupy exactly the bytes ending
where the end-of-central-directory record begins, and every central-directory record must be
backed by a matching local file header. `deflate.py` (and `site/src/deflate.ts`) applies the
same discipline one layer down, to the DEFLATE decompression of each member's bytes: it
validates the compressed stream against RFC 1951 itself, rather than trusting whichever
platform decompressor is on hand, because two real decoders were measured (2026-09-02, per the
module docstring) to accept different bytes for the same malformed stream — a stored block
with an inconsistent length field, and a reserved literal/length code that one library
silently gives a working meaning to. `tests/container-corpus/` (generated by
`tools/gen_container_corpus.py`, never hand-edited — see below) is the shared hostile-input
corpus both readers are checked against.

`bundle.py` is the layer above the container: `export()` assembles a shareable `.attest` (or
a `.private.attest` carrying secrets like the buyer's binding salt), `import_bundle()` reads
one back with its own budget/selection/legal-text checks, and `disclose()` produces the
single-receipt buyer-binding disclosure unit. This layer exists only on the Python side —
`verifiers/ts/` verifies envelope bytes the caller already extracted; bundle/container parsing
is reimplemented independently in `site/src/bundle.ts` and `site/src/container.ts`, shared by
the browser site and (via `desktop/tsconfig.json`'s dependency on `../site/src`) the desktop
verifier.

## Components around the core

- **`bridge/`** (`attest_bridge`) is how a store becomes an issuer without writing signing
  code. It reacts to platform webhooks (Stripe, Shopify, PayPal, Paddle) or a claim-queue
  poller (itch.io, which exposes neither), and its `IssuingCore` (`core.py`) reuses
  `issue.build_payload`/`issue.issue` directly rather than re-implementing payload assembly —
  its own docstring calls this "Global Constraint 3." `ledger.py` is explicit that its
  sqlite3-backed operational state (webhook idempotency, issued-receipt store) is **not**
  part of the trust model — nothing `attest.verify` depends on it — but it is still a secret
  store, because it holds issued envelopes verbatim including the buyer-binding salt, and its
  file is created at mode `0600` before the first byte is written. `signing.py` loads and
  cross-checks the merchant's signing key against its own manifest at startup, fail-fast,
  rather than at the first receipt. **`attest-bridge` is never published**: its own README
  says explicitly not to `pip install attest-bridge`, since an unrelated package could claim
  that name — a checkout is installed with `pip install ./bridge`, and its package metadata is
  marked `Private :: Do Not Upload`.
- **`witness/`** (`attest_witness`) is the runnable reference witness described above. Also
  never published, for a related but distinct reason: `witness/README.md` states its source
  "describes a deployment" and its example config names key files, and the release gate
  asserts its exclusion from the built PyPI/npm artifacts.
- **`site/`** is the browser verifier deployed to attest-receipts.org (the `deploy` job in
  `.github/workflows/pages.yml`, gated on `main`). It drops a `.attest` bundle, parses it
  entirely client-side with `attest-verifier` (installed as `file:../verifiers/ts`), and
  renders a plain-language verdict (`explain.ts`, `render.ts`).
- **`desktop/`** builds the same verifier (site + `verifiers/ts`) into one self-contained HTML
  file with no external references. Its own README states the guarantee and how it is
  enforced: the build refuses to write the artifact unless every tag/attribute/link matches an
  explicit allowlist, refuses a content security policy whose hashes don't match the bundled
  bytes, and refuses any request-making API found in the output; an end-to-end suite
  separately watches every network request the page makes while running every scenario and
  fails on a single one with a scheme other than `file:`. It is built, never committed
  (`dist/` is gitignored).
- **`demo/`** holds two runnable, non-normative demonstrations, not test fixtures dressed up:
  `store_dies.py` issues a receipt, then deletes the issuing store's entire infrastructure,
  then proves the receipt still verifies; `pledge_dies.py` carries that further — a rights
  holder signs a preservation pledge, the store dies, the pledge fires, and a non-normative
  `custodian.py` archive gate hands the file back only to whoever proves possession of the
  receipt's binding secret. `demo/README.md` is explicit that neither demo is part of the
  protocol and that `custodian.py` is a reference, not a production gate.
- **`formal/attest.spthy`** is a Tamarin model of the wire protocol's trust, rotation,
  revocation, and hybrid-acceptance behavior: 45 lemmas (`grep -c '^lemma ' formal/attest.spthy`),
  gated by `tools/check_formal.py`, which pins every lemma **statement** by sha256 digest of
  its normalized text — so a renamed, weakened, or trait-flipped lemma fails the gate even if
  the prover still reports it `verified`. The five CI shards in `.github/workflows/ci.yml`'s `formal` job explicitly list
  their assigned lemmas. `tests/tools/test_check_formal.py` checks that those lists
  are pairwise disjoint and that their union equals the checker's contract;
  `tools/verify-all.sh` reads the shard matrix from the workflow.
  `formal/README.md` pins the exact prover toolchain (`tamarin-prover` 1.12.0,
  `maude` 3.5.1) required to reproduce them.
- **`ietf/`** builds an Internet-Draft snapshot mirroring a pinned revision of the specs
  (currently v0.1 rev 5 / v0.2 rev 6, per `README.md`'s Status section), with the repository's
  own specification text remaining normative — the draft is stated to be behind it.

## How this repository measures itself

`tools/verify-all.sh` is the single local entry point: `CONTRIBUTING.md` describes it as
running "every `run:` step of `.github/workflows/ci.yml` and `.github/workflows/pages.yml`,
in the order the jobs run them, with the same flags," reading the formal-verification shard
matrix directly out of `ci.yml` rather than duplicating it, and refusing to run at all if that
matrix isn't in the one shape it knows how to read. `tests/test_verify_all.py` holds the
script itself to that promise by running it against stubbed commands and comparing what it
**actually executed** against both workflow files — command text, flags, attributed job,
invocation count, environment, shell, and order — so a step added to a workflow and forgotten
in the script (or vice versa) fails a test rather than silently diverging.

CI itself is three workflows:

- **`ci.yml`** — a `python` job (the full pytest suite with `ATTEST_CI_REQUIRED=1`, ruff
  check + format, `mypy --strict` across `src bridge/src witness/src`, the leaf-coverage,
  vector-generation, and container-corpus-generation checks run in `--check` mode, both
  demos run as scripts, and the Internet-Draft build with the pinned xml2rfc toolchain); a
  `supply-chain` job (builds both packages, asserts their contents, runs the TS conformance
  adapter through the *public* runner as a dogfood check, generates SBOMs with syft, and
  gates on vulnerabilities/licenses with grype/grant); and the `formal` job's five Tamarin
  shards described above.
- **`pages.yml`** — typechecks and builds the site, runs its suite and Playwright e2e
  (Chromium), separately builds and tests the desktop artifact across Chromium/Firefox/WebKit
  (WebKit only in CI, per a comment noting the real Safari check stays manual), asserts test
  **census** files (`tools/check_test_census.py`) so a runner silently collecting fewer tests
  from the same files fails loudly rather than reporting a smaller green number, and deploys
  to GitHub Pages only on a push to `main`.
- **`release.yml`** — `build`, `desktop`, `pypi`, `npm`, `github-release` jobs (not opened in
  depth for this document; see the file directly for release mechanics).

## What is generated — do not hand-edit

- **`docs/spec/vectors/`** — produced by `tools/gen_vectors.py`, which is deterministic by
  construction (every keypair, salt, timestamp, and ULID source is a fixed constant, never a
  clock or CSPRNG read). CI runs it with `--check` and fails on any drift between what's
  committed and what the generator produces today.
- **`tests/container-corpus/`** — produced by `tools/gen_container_corpus.py`, checked the
  same way (`--check` in CI).
- **`tools/test-census.json`, `tools/importer-census.json`,
  `tools/verifier-test-types-census.json`** — committed measurement baselines.
  `check_test_census.py` compares test counts and test-name digests with a fresh Vitest
  report; `check_verifier_test_types.py` compares per-file TypeScript diagnostic counts
  with a fresh compiler probe. Their `--update` modes require a complete measurement.
  `importer_differential.py` owns `importer-census.json`, which pins executed archive
  and archive-pair identities. Its `--update-census` admits additions after a successful
  full run; removals and renames require an explicit edit of the committed census.
- **`verifiers/ts/dist/`, `site/dist/`, `desktop/dist/`, any `node_modules/`** — build output,
  excluded by `.gitignore`'s blanket `dist/`/`node_modules/` rules. `desktop/README.md` states
  its artifact explicitly: "It is built, never committed."

## Where NOT to look for the contract

`docs/conformance.md` says this about itself and it generalizes: process documents describe
*how* to check a claim, they are not themselves the claim. The normative contract is always
`docs/spec/attest-v0.1.md` / `attest-v0.2.md` plus the vector corpus; `docs/conformance.md`,
`docs/spec/vectors/README.md`'s prose, and this file are all guides to that contract, not
substitutes for reading it when a specific behavior is in question. Where a leaf's
`expected.json` and a piece of prose disagree, the leaf wins — `CONTRIBUTING.md` states this
directly: "The conformance vectors — not any single implementation's wording — are the
contract."

## What I could not verify from inside this worktree

`release.yml`'s five jobs were read only at the job-name level, not opened line by line — the
document above does not describe PyPI/npm publishing mechanics, trusted-publisher
configuration, or how `github-release` assembles release notes. `AUTHORS`, `NOTICE`, and
`PATENTS.md` were not opened; they are attribution/legal surfaces, not architecture. The
full text of `docs/spec/attest-v0.1.md` and `attest-v0.2.md` was read by section heading and
targeted excerpt, not cover to cover — this document's spec citations are accurate to what
was read, but a normative question about a specific field should still go to the spec text
itself, not to this summary.
