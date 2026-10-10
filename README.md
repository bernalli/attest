<img src="https://raw.githubusercontent.com/bernalli/attest/main/logo/banner.png" alt="attest">

**Own what you buy.** The seller signs a receipt, you hold the file, anyone can verify it offline — even after the store is gone.

attest is an open format for signed purchase receipts. Each receipt is a small
JSON file whose signature is checked against the seller's published key material.
This repository contains the
specification, the Python reference implementation (`attest-receipts` on PyPI,
issue and verify), and an independent TypeScript verifier (`attest-verifier`
on npm, verification only).

> Looking for the CI step that signs build artifacts? That is
> [`actions/attest`](https://github.com/actions/attest), an unrelated project. This attest is about
> what you buy, not what you build.

## Why it exists

A receipt held only in a store account depends on that store remaining
available. attest puts the signed record in the buyer's hands: keep the receipt
and the issuer's key material, and checking what the seller signed does not
require the seller to stay online. There is no central attest authority,
account, registry or phone-home needed for verification.

The [whitepaper](docs/whitepaper.md) documents concrete cases of stores removing
purchased content or ending access to it. It also examines the EU legal context,
including durable-medium requirements for contract confirmation and why an attest
receipt alone is not that confirmation.

A receipt is evidence of a license grant, not a backup of the content or proof
of the payment transaction. It cannot recover a file you never downloaded,
remove DRM, make an unwilling seller sign, or grant a general resale right.
attest is not a content host, index, marketplace, blockchain, NFT product or
payment instrument. Revocation and key-compromise evidence can still make a
receipt invalid; being able to verify its bytes does not mean it stays valid.

No store issues attest receipts in production yet, and there are no external reviews.

To see a receipt before using the terminal, open the
[browser verifier](https://attest-receipts.org/) and try the built-in sample
or drop an `.attest` bundle, the format for sharing receipts and their supporting material;
verification runs client-side. If someone sent you a receipt, the
[buyer introduction](https://attest-receipts.org/start-here.html) explains it
without a terminal. The [FAQ](docs/faq.md) covers what a receipt can and cannot
prove.

## Quickstart: issue and verify a receipt

Use Python 3.12 or newer. In an empty directory, create and activate a virtual
environment, then install the reference implementation:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install attest-receipts
```

The distribution is `attest-receipts`; the Python import package and command
are both `attest`. The commands below use a POSIX shell.

Create a signing key and the key manifest a store would publish at
`https://<its domain>/.well-known/attest.json`. This example uses a fictional
store and creates a v0.1 receipt; it does not contact that domain.

```sh
attest keygen --seed-out issuer.seed --pub-out issuer.pub
mkdir trust
attest manifest init --issuer store.example.com \
  --kid 'store.example.com/keys/2026-10#ed25519-1' --seed issuer.seed \
  --valid-from 2026-10-01T00:00:00Z --issued-at 2026-10-01T00:00:00Z \
  --out trust/store.example.com.json
```

Describe the purchase. Save this as `make_payload.py`:

```python
import hashlib
import json
import os
from pathlib import Path

from attest.issue import build_payload
from attest.keys import b64u

salt = os.urandom(16)  # buyer-binding secret, delivered inside the receipt
payload = build_payload(
    issuer_id="store.example.com",
    display_name="Example Store",
    buyer_identifier="buyer@example.com",
    buyer_identifier_type="email",
    buyer_salt=salt,
    title="Example Game",
    publisher="Example Publisher",
    identifiers={"issuer_sku": "EXG-001"},
    artifact_series="store.example.com/works/EXG-001",
    terms_uri="https://store.example.com/terms/standard-v1",
    legal_text_sha256=hashlib.sha256(b"Example licence text").hexdigest(),
)
Path("payload.json").write_text(json.dumps(payload, indent=2))
Path("buyer.salt").write_text(b64u(salt))
```

Then sign the receipt and verify it, offline:

```sh
python make_payload.py
attest issue --payload payload.json --seed issuer.seed \
  --kid 'store.example.com/keys/2026-10#ed25519-1' --salt buyer.salt \
  --out receipt.json
attest verify --trust-dir trust receipt.json
```

`attest verify` prints the full result and exits 0; among its fields are
`"ok": true`, `"signature": "valid"` and `"trust": "unauthenticated_tofu"`.
The trust result means the manifest came from a local directory, not from the
store's own domain over TLS, and `ok` never includes `trust`, so read it alongside
`ok`. Changing the title inside `receipt.json` makes the same command report
`"signature": "invalid"` and exit 1. Keep the original for the examples below.

## Reading a verification result

Verification reports separate results for the signature, schema, trust,
revocation and buyer binding. Without authenticated revocation material,
revocation is `unknown`; an offline check cannot discover a later revocation
that you have not supplied. Buyer binding proves possession of issuer-recorded
material through a salt disclosure or a key challenge, not the buyer's identity
or participation in the purchase.

`ok` excludes `trust` (v0.1 §11.1, conformance vector 14b). If your policy must
reject particular trust results, `attest verify --reject-trust` takes a
comma-separated list of exact values, not a threshold. For example, adding
`--reject-trust unverified_rotation` rejects discontinuous rotation histories.
Rejecting `unauthenticated_tofu` rejects every receipt verified through this
CLI's local `--trust-dir`, including the quickstart receipt.

A known signing-key compromise normally invalidates receipts signed with that
key; a later manifest cannot undo a compromise already observed by the verifier.
Both verifiers implement v0.2 §19's rescue for receipts with qualifying
anchored evidence: either no qualifying anchored compromise cutoff is established,
or the receipt's anchored time is strictly earlier than the earliest such cutoff.
The cutoff dates a compromise declaration, not the key theft; forgeries anchored
between the theft and that cutoff can also be rescued (§19.6). Unlogged receipts have
no such protection. Evaluation requires trusted log keys and an anchor policy,
plus the receipt's evidence; the project's log configuration is in
[docs/trust/](docs/trust/README.md).

`attest issue --log-dir` appends the receipt's entry to the issuer's log while
signing. For an existing receipt, `attest log entry --type receipt` derives the
entry by rehashing the signed document, then `attest log append` adds it. The
log commands can produce an inclusion proof under a signed checkpoint, by
receipt or index. An operator must still obtain an external timestamp and
supply the evidence and matching trusted keys and anchors to a capable verifier.
The bridge does not automate logging or anchoring, and the browser and desktop
currently pin no block headers.
Logging corroborates existence; it does not authenticate an unsigned receipt
or upgrade `trust`.

## Verify the same receipt in TypeScript

With Node 20.19 or newer, install the verification-only package:

```sh
npm install attest-verifier
```

Save this as `verify.mjs` beside the quickstart files, then run
`node verify.mjs` against the unchanged receipt:

```js
import { readFileSync } from 'node:fs'
import { verify, isOk, parseTrustStore } from 'attest-verifier'

// Trust material enters as bytes. "bundle" = a manifest you were handed;
// only a manifest fetched from the issuer's own domain over TLS is "tls".
const manifest = readFileSync('trust/store.example.com.json', 'utf8')
const store = parseTrustStore(new TextEncoder().encode(
  `{"manifests":{"store.example.com":${manifest}},` +
  `"provenance":{"store.example.com":"bundle"}}`,
))

const result = verify(readFileSync('receipt.json'), store)
console.log(isOk(result) ? 'valid' : 'rejected', result.trust, result.errors)
```

It prints `valid unauthenticated_tofu []`.

See the [TypeScript README](verifiers/ts/README.md) for the full API and browser
usage.

## Specification and conformance

The package version and wire format are separate. Receipts declare
`attest_version` as `"0.1"` or `"0.2"`; the specifications and
[JSON Schema](docs/spec/schema/attest-receipt.schema.json) define those formats.

- [v0.1](docs/spec/attest-v0.1.md) defines the signed envelope, restricted JSON
  canonicalization, pinned Ed25519 rules, issuer key and artifact manifests,
  rotation and compromise handling, revocation classes, buyer binding and
  layered offline verification.
- [v0.2](docs/spec/attest-v0.2.md) is the additive delta implemented by both
  packages: hybrid Ed25519 + ML-DSA-65 signatures (Stage 1), transparency and
  timestamp anchoring (Stage 2), issuer-mediated transfer (Stage 3, §17),
  preservation pledges (Stage 4, §18), time-boxed compromise rescue (§19), and
  publisher authority (§20). v0.1 defines no transfer; v0.2 transfer depends on
  the issuer, rather than granting a general resale right.
- [Versioning](docs/spec/attest-versioning.md) governs additive amendments,
  the `active` / `deprecated` / `unsafe` algorithm lifecycle, and the
  signature-suite, payload-field, revocation-class, log-entry-type and
  transfer-type registries. Deprecation may change the result classification,
  never the ability to verify the bytes of a receipt that conformed when issued.

The [conformance corpus](docs/spec/vectors/) contains 231 leaves across 47
groups. The v0.1 subset has 70 leaves; a v0.1-only verifier must reject v0.2
envelopes. The full corpus also covers mixed-keyset prohibition, artifact-manifest
currency, anchor profile v2 and logged revocation deadlines.
[Conformance instructions and recorded self-certification claims](docs/conformance.md)
explain how to run a third-party adapter and produce a pass/fail report. A release
may claim the full corpus only when both implementations reproduce every leaf;
published claims must be updated from a fresh runner report.

## Stability

This repository holds many components, and they are not equal promises. The
contract is the specification; the two published packages implement it; the
rest serves it, measures it or demonstrates it. Each status below is the one the
repository itself records: in the spec's own status line, in package metadata,
in the release workflow, or in the component's own README.

| Component | What it is | Status |
| --- | --- | --- |
| [`docs/spec/attest-v0.1.md`](docs/spec/attest-v0.1.md), [`docs/spec/attest-v0.2.md`](docs/spec/attest-v0.2.md) | The receipt format and verification algorithm; v0.2 is an additive delta on v0.1 | Normative. Changed only by amendment under the versioning policy: by addition, never by replacement, and no amendment may make a receipt that conformed when issued unverifiable |
| [`docs/spec/attest-versioning.md`](docs/spec/attest-versioning.md) | The upgrade policy and extension registries both specifications answer to | Normative |
| [`docs/spec/vectors/`](docs/spec/vectors/) | The conformance corpus every implementation is measured against | Normative as a corpus; generated, not hand-edited |
| `attest-receipts` ([`src/attest/`](src/attest/)) | Python reference implementation: issues and verifies, provides the `attest` command | Published on PyPI. Classified `Development Status :: 4 - Beta`; versioned under Semantic Versioning per [`CHANGELOG.md`](CHANGELOG.md) |
| `attest-verifier` ([`verifiers/ts/`](verifiers/ts/README.md)) | Independent TypeScript verifier; verification only | Published on npm; versioned under Semantic Versioning per [`verifiers/ts/CHANGELOG.md`](verifiers/ts/CHANGELOG.md) |
| [`site/`](site/) | The browser verifier | Deployed from `main` as <https://attest-receipts.org/>; not a package |
| [`desktop/`](desktop/README.md) | The same verifier as one offline HTML file | Attached to each GitHub Release as `attest-verifier.html` with its `.sha256`; built, never committed; not on any package registry |
| [`bridge/`](bridge/README.md) | The merchant-run service that turns a paid order into a signed receipt | Not published (`Private :: Do Not Upload`); install from a checkout with `pip install ./bridge` |
| [`witness/`](witness/README.md) | The reference transparency-log witness for v0.2 §11.4 | A reference implementation for operators; never published. Independent witness operators are still outstanding (v0.2 §15 item 1) |
| [`demo/`](demo/README.md) | Three end-to-end demonstrations | Not part of the protocol; `custodian.py` and `witness_client.py` are non-normative references, not production components |
| [`formal/`](formal/README.md) | Tamarin model of the wire protocol | Verification evidence, gated in CI; each theorem states its own scope |
| [`ietf/`](ietf/README.md) | Internet-Draft snapshot of the specification | Not normative: it mirrors a pinned revision and is behind the specification in this repository; no formal standing in the standards process |
| `tools/`, `tests/` | Generators, checkers and test suites | Internal development material, included in the Python source distribution; not installed by the Python wheel or shipped in the npm package |

Both packages are at a 0.x version, and Semantic Versioning, which their
changelogs say they follow, does not treat a 0.x public API as stable. The
package version and the wire format are different things: what stays verifiable
across releases is a receipt's bytes, under the policy above. And, as stated
earlier, no store issues attest receipts in production yet, and there are no
external reviews.

## Sellers, archives and witness operators

For a service that turns paid orders into signed receipts, start with the
[merchant bridge](bridge/README.md). It requires Python 3.12 or newer and is
installed from a repository checkout:

```sh
pip install ./bridge
```

This installs `attest-receipts` as a dependency. Do not run
`pip install attest-bridge`: that distribution is not published, and the name
could resolve to something unrelated.

A preservation pledge lets a rights holder authorize an archive that holds a
copy to deliver it when the pledge activates, subject to proof of possession
of the private key named in the receipt. The [pledge demo](demo/README.md)
runs this end to end. A production publisher, an archive service and final
license prose are still missing; the demo uses placeholder prose and a
non-normative archive gate whose production gaps are documented there.

The [reference witness](witness/README.md) cosigns log checkpoints so a verifier
can tell that another observer saw that head. A witness does not by itself
establish independent protection against split views.

Sellers, marketplaces, successor services and archives can describe what they
need from the format in [Discussions](https://github.com/bernalli/attest/discussions)
or by email at `bernalli@proton.me`.

## Supporting documents

- [Formal verification](formal/README.md): the Tamarin model, property-to-lemma
  map, theorem scopes, reachable attack exhibits and negative controls. CI pins
  theorem statements. These are scoped soundness results, not liveness claims.
- [Threat model](docs/spec/attest-threat-model.md): 81 attacks catalogued across
  the receipt lifecycle, mitigations or explicit out-of-scope reasons,
  traceability and tracked gaps. It analyzes the specification rather than
  imposing protocol requirements of its own.
- [Incident runbook](docs/incident-runbook.md): stolen versus lost signing keys,
  securing the domain, seed backups and the limits of using a key per period.
- [Privacy considerations](docs/spec/attest-privacy.md): field and observer
  analysis, testable privacy claims and a GDPR annex.
- [Transfer economics](docs/spec/attest-transfer-economics.md): non-normative
  market and legal context for issuer-mediated resale.
- [Standards relationships](docs/spec/attest-standards-relationship.md):
  non-normative comparisons with W3C Verifiable Credentials, eIDAS 2.0 / EUDI
  Wallet, JOSE/JWS, COSE, RFC 8785 (JCS), C2PA, SCITT (RFC 9943) and RATS
  (RFC 9334).
- [Internet-Draft](ietf/README.md): submission record and XML build instructions.
  The snapshot mirrors v0.1 revision 5 and v0.2 revision 6 and is behind the
  repository specification. It is work in progress, not IETF endorsement or a
  normative replacement for the repository specification.

## Develop and run the demos

From a checkout, install all Python workspace packages and development dependencies:

```sh
uv venv --python 3.12 .venv
uv sync --locked --extra dev --all-packages
.venv/bin/attest --help
```

The [three demos](demo/README.md) check receipt survival after a store disappears,
archive delivery under an activated preservation pledge, and witness cosigning:

```sh
.venv/bin/python -m demo.store_dies
.venv/bin/python -m demo.pledge_dies
.venv/bin/python -m demo.witness_cosigns
```

Run the Python and TypeScript suites:

```sh
.venv/bin/pytest --cov=attest --cov-report=term-missing
cd verifiers/ts && npm install && npm test
```

## Future directions

These are non-normative, undated directions, not commitments. Preservation
pledges already belong to the specification and run in the demo above.

- Transfer authority that can outlive the original seller remains an open problem.
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
that license, not a courtesy. [`PATENTS.md`](PATENTS.md) — a royalty-free
patent non-assertion covenant covering implementations of the specification.
[`NOTICE`](NOTICE) and [`AUTHORS`](AUTHORS) carry the required attribution.

**Naming.** The name *attest* identifies this project and implementations that
actually conform to it; forks are welcome to use the technology but not the name
for a divergent derivative. This paragraph is a naming norm, not a trademark
registration — real trademark enforcement would require actually registering the
mark, which has not happened. Conformance claims follow the self-certification
process in [docs/conformance.md](docs/conformance.md).

**Contributing.** See [`CONTRIBUTING.md`](CONTRIBUTING.md). Implementation pull
requests must pass all 231 conformance vector leaves and keep both the Python and
TypeScript suites green.

**Contact.** Use GitHub Issues for technical bugs, GitHub Discussions for
everything else, or email `bernalli@proton.me`.
Security issues follow a different path — see [`SECURITY.md`](SECURITY.md), and
do not open a public issue for a vulnerability.
