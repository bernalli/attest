# attest — Relationship to Existing Standards (non-normative)

**Non-normative.** This document imposes no requirements and uses no RFC 2119
keywords (MUST, SHOULD, MAY, and their negatives, as fixed in `attest-v0.1.md`
§1) with conformance force. For each of seven adjacent standards it states
where attest's boundary lies against it — in terms an expert in *that*
standard would recognize as an accurate description of their own standard's
concepts, not a simplified restatement built to be easy to dismiss. Where a
concrete future bridge between attest and a given standard is plausible, the
entry says what it could look like; where none is, the entry says that
instead.

This document exists in part because several of the standards below define a
concept that sounds like, or is literally named, something attest also
defines — most pointedly SCITT's "receipt" (entry 6) and RATS's "attestation"
(entry 7). Each entry states the actual relationship precisely enough that
the collision cannot be mistaken for equivalence, or for one standard being a
redundant reinvention of the other.

## 1. W3C Verifiable Credentials

The W3C Verifiable Credentials Data Model describes a claim as three
cooperating roles: an `issuer`, a `credentialSubject` carrying the claimed
attributes, and one or more securing mechanisms — embedded Data Integrity
proofs or an enveloping JOSE/COSE wrapper — that establish who signed the
credential and that it has not been altered. The claim shape itself is
open-world and extensible: a credential's properties are defined by whatever
vocabulary its `@context` brings in — VC Data Model 2.0 requires `@context`
on every credential, including one processed under a fixed, type-specific
JSON Schema, because `@context` is what fixes the JSON-LD term-to-IRI
mapping those properties resolve against, not an indirection a plain-JSON
credential can skip. Which contexts, document shapes, issuers, or types a
given verifier actually honors is left to that verifier's own
application-defined trust policy — a data model that supports open
vocabularies is not the same claim as consumers accepting arbitrary
issuer/type combinations automatically; nothing in the data model defers
that decision to a registry on a verifier's behalf. Proof formats are
deliberately plural by design, not a single pinned mechanism — a verifier
that speaks the data model still has to implement whichever proof suite a
given credential actually used.

attest's payload takes the opposite position on both axes. Its schema
(`docs/spec/schema/attest-receipt.schema.json`) declares a fixed required
core with no `@context` indirection and no remote vocabulary to resolve —
but it is not a closed field set: the schema sets `additionalProperties:
true`, and v0.1 §11.2 requires a conforming verifier to accept a signed
unknown top-level payload field as valid-with-warning, never as a schema
error. The closedness is in canonicalization and semantics, not in what
fields a payload may carry: attest's signing step is not a choice among
proof suites but one mandatory canonicalization profile, attest-JCS (v0.1
§9), whose output is byte-exact across the Python and TypeScript reference
implementations by construction of the 213-leaf conformance corpus — a
verifier that does not reproduce attest-JCS exactly cannot verify an attest
receipt at all. Choosing a purpose-built envelope over a Verifiable
Credential is choosing that fixed-core, single-canonicalization,
no-remote-context determinism over the VC model's open-world extensibility,
`@context`-driven semantics, and proof-suite plurality; the two are trading
in opposite directions on purpose, not one failing to be the other.

What a future bridge could look like: an attest envelope (`payload` plus
`signatures`) could be embedded as an opaque, independently-verifiable object
inside a `credentialSubject`, letting a wallet that already speaks the VC
ecosystem carry a receipt as one more presentable claim. That would be
carriage, not equivalence — the VC's own proof would establish
wallet-presentation trust, while the embedded attest signature would still be
verified on its own terms by an attest-aware verifier. Nothing in v0.1 or
v0.2 defines such a wrapper, and attest depends on none existing.

## 2. eIDAS 2.0 and the EUDI Wallet

eIDAS 2.0 (Regulation (EU) 2024/1183) builds the European Digital Identity
Wallet framework around Person Identification Data and Electronic
Attestations of Attributes (EAAs) presented to relying parties through a
wallet, itself subject to Member State conformity assessment as a wallet
solution. The Regulation does not treat every EAA alike: a **qualified**
EAA (QEAA) is, by definition, issued by a qualified trust service provider
operating under that provider's qualified-status obligations and the
trust-list apparatus that vouches for its certificate, while the EUDI
architecture separately recognizes a public-sector EAA — issued by or on
behalf of a public-sector body responsible for an authentic source of
attributes (Art. 3(46)), which the Regulation grants legal effect
equivalent to a QEAA (Art. 45b(2)) and subjects to its own statutory regime
of reliability equivalent to a qualified trust service provider, conformity
assessment, notification, and public listing (Art. 45f(2)–(3)) in place of
a qualified-trust-service-provider dependency — and a non-qualified EAA
(issued by any other attestation provider, without either apparatus). An
EAA's evidentiary weight therefore depends on which of the three it is: a
QEAA rests on its qualified provider and trust-list-anchored certificate; a
public-sector EAA rests on the designated public-sector body and the
equivalent statutory regime the Regulation places over it; a non-qualified
EAA rests on whatever authority or reputation its issuing provider otherwise
has.

attest issues merchant purchase evidence with none of that apparatus present
anywhere in its verification path: an issuer-signed record of a license
grant (v0.1 §4), verified entirely offline against a trust-on-first-use or
TLS-rooted key manifest (v0.1 §7.4), with no wallet, no attestation
provider, no qualified trust service, and no Member State supervision
involved in producing or checking one. A receipt's evidentiary weight comes
from the issuer's own signature and reputation — v0.1 §2 is explicit that a
receipt is evidence of a license grant, not a claim of ownership or of any
seller's regulatory compliance, and the threat model's TM-05/TM-06 note that
a dishonest issuer's receipts are cryptographically indistinguishable from an
honest one's. The two frameworks attest to different kinds of fact for
different kinds of relying party, and neither depends on the other existing.

What a future bridge could look like: an attest receipt could be carried as
one of the attributes a (Q)EAA attests to (a wallet holding "this identity
purchased title X" as a wallet-presentable attestation), or the buyer-side
binding proof attest already defines (v0.1 §8) could someday be satisfied by
a wallet-mediated presentation instead of a bare public-key challenge.
Either direction is potential future carriage; attest depends on neither.

## 3. JOSE/JWS and COSE

This is the objection an expert in either format will raise first: why not
just sign a detached JWS or a COSE_Sign1 structure over the payload? Both
formats sign the payload's own producer-chosen serialization rather than a
canonical re-derivation from a parsed object — but what each actually
protects is represented differently, and neither matches the simplified
picture of "the transmitted wire form is the trust anchor." JWS Compact
Serialization classically signs `base64url(header).base64url(payload)`
(RFC 7515), but RFC 7797 lets a JWS carry an unencoded, detached payload —
the base64url wrapping is a convention modern JWS tooling can and does skip,
not something the signature scheme requires. COSE_Sign1's signature input is
not the transmitted `COSE_Sign1` structure's own wire bytes either: RFC 9052
§4.4 defines it over a deterministically-encoded `Sig_structure` built from
the protected header and payload, which a verifier reconstructs and
re-encodes rather than re-verifying the outer envelope's bytes verbatim.
What both formats share, and what distinguishes them from attest, is that
whichever exact bytes get signed, they are the *producer's own serialization*
of the payload — the octets that party actually produced (or a
deterministic re-encoding derived from them) — preserved and signed as
transmitted, not recomputed independently from a parsed object by whoever
verifies later. That is precisely why detached content is a first-class,
well-used feature of both formats: the payload can be stripped from the
envelope and carried separately, because the signature was never over a
canonical re-derivation of a parsed object, only over the producer's own
serialized bytes.

attest inverts that relationship. The signature input is `JCS(payload)`
(v0.1 §9) — the RFC 8785-canonical serialization of the *parsed* payload
object, computed fresh from its content rather than preserved from the wire.
Anyone holding the parsed `payload` as a JSON object, in any language, can
recompute the exact bytes that were signed by re-running the canonicalizer;
there is no side channel, no detached segment, and no particular wire
encoding a holder must preserve to keep a receipt verifiable. That is what
offline determinism buys: a receipt's signed bytes are a pure function of
its parsed content, so an exported bundle re-serialized by a different tool
years later (v0.1 §14) still verifies. The cost is the mirror image of that
benefit and is stated here plainly: every implementation must canonicalize
identically — UTF-16BE member-name ordering, the integer-only number
restriction with `|n| < 2^53` that v0.1 §9 layers on top of RFC 8785's own
I-JSON number rule, duplicate-member rejection, lone-surrogate rejection —
and a canonicalizer bug is a silent signature mismatch, not a loud parse
error. JOSE and COSE need no such canonicalization step at all, because
each preserves and signs the producer's own serialized payload octets
rather than recomputing a canonical form from a parsed object; attest's bet
is that trading that no-canonicalization simplicity for a strict, narrow,
corpus-enforced canonicalizer is the safer engineering trade-off when the
signed bytes must be recoverable from a parsed JSON object in any language,
rather than preserved from whichever producer happened to serialize the
wire form — and the 213-leaf conformance corpus, exercised byte-identically
by the Python and TypeScript reference verifiers, is what makes that bet
checkable rather than merely asserted.

What is given up is real and worth naming: JOSE's mature multi-language
tooling ecosystem (JWK sets, negotiable `alg`/`kid` headers, broad library
support) and COSE's constrained-device profile (compact binary framing with
no *payload* canonicalization pass required on a small embedded verifier —
COSE_Sign1 still deterministically encodes a `Sig_structure` from the
protected header and payload per RFC 9052 §4.4, as stated above; what it
avoids is canonicalizing a parsed JSON payload the way attest-JCS does).
attest's
own `kid` and `alg` fields (v0.1 §4.1) borrow JOSE's vocabulary for
readability without adopting JOSE's negotiation model: `alg` is pinned per
`attest_version` and is never used for verifier-side algorithm dispatch — the
opposite of JOSE's negotiable `alg` header, and stated as a MUST NOT in v0.1
§4.1 for exactly that reason.

What a future bridge could look like: a COSE_Sign1 wrapper carrying an
unmodified attest envelope as an opaque payload is a plausible
constrained-device transport profile — it would carry attest inside COSE's
framing for a small-device transport hop without adopting COSE's own model
of signing the producer's serialized payload octets directly for the
receipt itself. Nothing in v0.1 or v0.2 defines this today.

## 4. RFC 8785 (JCS)

attest builds directly on RFC 8785, not beside it. Taken verbatim from JCS:
object-member ordering by sorting each member name's UTF-16 code-unit
sequence; number serialization via the ECMAScript `Number::toString`
algorithm for any number JCS accepts; RFC 8785's string-escaping rules; and
the underlying I-JSON (RFC 7493) constraint that the input already carry no
duplicate object members and no non-finite numeric values. v0.1 §9 states
this relationship explicitly: every attest-JCS output is also a valid JCS
output, because the profile is a restriction of RFC 8785, never an
incompatible extension to it.

What v0.1 §9 layers on top, and RFC 8785 itself leaves unresolved: full JCS
permits any I-JSON number and requires every implementation's
`Number::toString` to reproduce IEEE-754 double rounding identically to stay
interoperable — a genuine cross-language risk that RFC 8785 does not close
on its own. attest-JCS closes it by restricting numbers to integers only,
with `|n| < 2^53`, rejecting any float, `NaN`/`Infinity`/`-Infinity`
construct, or over-range integer outright at canonicalization time — before
schema validation or signature verification ever run (v0.1 §9's "Correction"
paragraph walks the exact failure path). Layered alongside that restriction:
outright rejection of a duplicate object member name as a parse failure (RFC
8785 requires rejection, never silent last-value-wins deduplication, and
attest-JCS enforces that literally), a profile nesting-depth ceiling enforced
both while parsing and while producing canonical bytes (v0.1 §11.3), and
rejection of lone UTF-16 surrogates whether they arrive as literal bytes or as
`\uXXXX` escapes. None of this competes with JCS; each rule narrows the
accepted input set within RFC 8785's own envelope, and the serializer-side
depth ceiling prevents attest-JCS from emitting a document its own parser
would reject, so any attest-JCS-canonical document remains a valid RFC 8785
document that a general-purpose JCS canonicalizer would reproduce unchanged.

## 5. C2PA

A C2PA manifest is a signed, structured record of assertions about an
asset's provenance — actions describing how it was produced or edited,
ingredient assertions chaining in the manifests of source assets it was
derived from, and hash-binding assertions tying the manifest to the exact
asset bytes it describes. A Manifest Store commonly travels embedded in or
alongside the asset, but C2PA does not require that carriage: a Manifest
Store may instead be hosted externally (a repository or manifest-serving
endpoint) and referenced rather than embedded, and manifests still
accumulate as the asset passes through further C2PA-aware tools regardless
of which carriage a given store uses. A C2PA manifest answers what an asset
is and how it came to be.

attest answers an adjacent but different question about a different
relationship to the same asset: not what the asset is or how it was made,
but that a license to hold or use a copy of it was granted, by whom, to
whom, and under what terms — a signed side-document (the receipt envelope,
v0.1 §4) that references an artifact by hash (`work.artifacts[].sha256` and
related fields) rather than describing the asset's own provenance. The
honest boundary is not that a manifest is structurally incapable of
carrying licensing information — C2PA permits externally-defined and custom
assertion types, and nothing stops one from encoding license-adjacent data
in a custom assertion — it is that C2PA does not standardize purchase or
license evidence as a first-class concept: no assertion type in the core
C2PA specification defines issuer, buyer, license terms, revocability, or
any of the other fields v0.1 §5 fixes as normative and required. attest is a
purpose-built specification for exactly that content; C2PA is not, whatever
an ad hoc custom assertion could in principle be made to hold.

The two standardize different things and were designed to be checkable from
opposite directions against the same object: a game binary could ship with
an embedded or externally-hosted C2PA manifest recording its build
provenance, sold to a buyer who separately holds an attest receipt recording
the license grant for that exact binary, both referencing the same
underlying artifact hash. Nothing in either specification requires the
other's presence, and nothing prevents both existing side by side for one
artifact today — that coexistence is not a hypothetical future bridge, it is
how the two already compose without any new mechanism in either
specification.

## 6. SCITT and RFC 9943

The name collision here is the first thing an expert in either protocol
will notice, so it is defused precisely rather than left for someone else to
frame. A SCITT "receipt," per RFC 9943 (the SCITT architecture), is a
transparency service's proof that a signed statement was registered —
cryptographic evidence of *inclusion* in an append-only log, returned to
whoever registered the statement. An attest "receipt" is not that: it is the
signed purchase statement itself, the `payload`-plus-`signatures` envelope a
buyer holds as evidence of a license grant (v0.1 §4). The two protocols use
one word for two different things — a proof of registration, and the thing
being registered.

The structures underneath the naming collision are close to isomorphic, and
mapping them explicitly is the point of this entry:

| SCITT (RFC 9943) | attest |
| --- | --- |
| Statement | Payload (`payload`, v0.1 §5) |
| Signed statement | Signed envelope (`payload` + `signatures`, v0.1 §4) |
| Transparency service | Stage 2 log (`entries.jsonl` / tlog-tiles substrate, v0.2 §7) |
| Receipt | Stage 2 evidence bundle — signed checkpoint + `inclusion_proof` (v0.2 §10.2) |

Why attest is not "already SCITT," despite that structural overlap: SCITT
standardizes the registration and inclusion layer itself — how a
transparency service admits a COSE-signed statement, what a conforming
receipt (in SCITT's sense) must contain, how a relying party verifies one
against a service's key — as a general-purpose substrate for arbitrary
signed statements from arbitrary issuers, with registration as the
trust-establishing act for a statement's discoverability inside that
ecosystem. attest standardizes the purchase-evidence statement's own content
and verification semantics first, and treats its log as strictly
corroborative, never authoritative: v0.2 §10 states as Stage 2's central
correctness property that log evidence never upgrades `trust` and can never
make an unsigned or invalidly-signed receipt authentic — a receipt that
fails signature verification stays failed regardless of what the log says
about it (conformance vector 28i pins exactly this: a receipt rejected for a
compromised signing key still honestly reports `transparency: "logged"` for
its own genuinely-logged evidence). One shared property is genuine: RFC 9943
§9.2 is explicit that registration proves only that an issuer produced a
statement, never that its contents are accurate, and neither system lets
transparency evidence turn an invalidly-signed statement into a valid one.
But where signature verification sits is NOT shared. A SCITT transparency
service MUST verify and authenticate a signed statement *before* it registers
it (RFC 9943 §§5.1.1.1, 6.3); attest's log append validates only the closed
log-entry shape (v0.2 §8), a receipt entry's `issuer` is an unauthenticated
hint, and no receipt-signature check gates admission — which is precisely why
conformance vector 28i can log an invalidly-signed receipt at all. On that
axis attest's log is *more* purely corroborative than SCITT's, not less. The
relying-party end differs too, though less starkly than a bare "requires"
would suggest: SCITT's security guidance treats a discoverable receipt from a
trusted transparency service as important to a statement's standing
(RFC 9943 §9.3) while leaving post-verification acceptance policy to the
relying party (§7.1); attest consults no transparency evidence anywhere in
its own acceptance path. A receipt's `ok` verdict turns on `signature`,
`schema`, non-`revoked` status, and the absence of errors (v0.1 §11.1), and
its `trust: "verified"` value comes from TLS-rooted key provenance (§7.4) —
neither reads the log. Stage 2's `transparency`/`corroboration` components are
additive corroboration that affect `ok` only in the two narrowly scoped cases
v0.2 §10 calls out (a `refund_window` revocation record's effectiveness under
Stage-2 evidence, and an honored `transferred`-class record under Stage 3),
never as a general gate. That is the true difference in trust models — not
that attest inverts SCITT's registration-centric design, but that attest
centers no transparency receipt in its own acceptance path the way SCITT's
architecture centers one — and it is not a claim that SCITT's model is the
wrong one for its own purpose.

Where Stage 2 genuinely does touch SCITT's territory, stated honestly rather
than as a concession: the C2SP tlog-tiles log substrate and inclusion-proof
machinery (v0.2 §7–§9 — an RFC 6962 Merkle tree, leaf hashing, hybrid signed
checkpoints, consistency proofs) solve the same append-only-registration
problem a SCITT transparency service solves. That overlap is real and does
not undermine the boundary drawn above: attest's log substrate is built from
the same class of transparency-log machinery SCITT's architecture
describes, applied to a narrower, purchase-evidence-specific evidence model
with the log kept deliberately out of the trust decision.

This entry closes the corresponding item on the standards-engagement
checklist. Per the standing decision to keep outbound contacts frozen for
this phase, nothing in this entry has been or is being sent to the SCITT
mailing list — it is preparatory material only.

## 7. RATS (RFC 9334): a terminology note

"attest" is this project's name, chosen with no relationship intended to the
IETF Remote Attestation Procedures (RATS) architecture (RFC 9334), and the
protocol defined in `attest-v0.1.md`/`attest-v0.2.md` makes no RATS claims of
any kind: there is no Attester, no RATS-sense Verifier (attest's own
"verifier," v0.1 §3, is simply any software executing the algorithm in v0.1
§11 against a receipt, not a RATS Verifier evaluating Evidence against
Reference Values), and no Relying Party role mapping anywhere in either
specification; no Evidence, Attestation Results, or Endorsement semantics;
and no claim, implicit or explicit, about the integrity or trustworthiness of
any execution environment, TEE, or hardware root of trust. A reader arriving
from a RATS background should treat the project name as a false cognate and
read no remote-attestation semantics into any attest document.

## Revision log

- **2026-07-23 (rev 1)**: initial annex — vectors: none
- **2026-08-26 (rev 2)**: corrected a stale corpus size — the annex said 130 leaves in two places while the corpus has held 158 since rev 8 of v0.2; no claim of this document changes — vectors: none
