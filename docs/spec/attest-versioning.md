# attest-versioning — Normative Upgrade Policy and Extension Registries

- **Status**: Normative. Governs [`attest-v0.1.md`](attest-v0.1.md), [`attest-v0.2.md`](attest-v0.2.md), and every future revision of the attest specification family.
- **Date**: 2026-07-22
- **Grounding**: this document states no requirement the two specifications it governs do not already exemplify. It names the pattern already followed by v0.1 §11.2 (unknown-field forward compatibility) and by v0.2 (an additive delta specification, v0.2 §1) as binding policy for every future amendment.

## 1. Scope and authority

This document governs `attest-v0.1.md`, `attest-v0.2.md`, and every future revision of the attest specification family. It states the policy by which the specification evolves: which changes are permitted without breaking a conforming verifier, how algorithms and other extension points move through their lifecycle, how a normative amendment is proposed and recorded, and how extension registries are maintained. Every rule below binds both the existing specifications and every specification document that succeeds them.

This document is not itself versioned by `attest_version`. `attest_version` (v0.1 §5.1) versions the payload/wire-format shape a receipt claims to conform to; this document versions the *policy* governing how that shape, and everything else the specification family defines, is permitted to change over time. A future `attest_version` bump does not require a change to this document, and a change to this document never itself requires a new `attest_version`.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119, as clarified by RFC 8174, when, and only when, they appear in all capitals. Passages introduced with **Non-normative note:** are explanatory or historical context; they carry no conformance weight.

## 2. The additive pattern

attest evolves by addition, not by replacement. Extensions enter as OPTIONAL registered fields, values, entry types, or suites. A change that would make a previously-conforming verifier reject a previously-conforming artifact, or worsen a result classification on unchanged inputs, is breaking and REQUIRES a new `attest_version`.

One exception exists: a result-classification downgrade mandated by an algorithm lifecycle transition (§4) is NOT a breaking change and does not require a new `attest_version`. A lifecycle transition records newly established cryptanalytic reality about an algorithm; the protocol semantics are unchanged, and eternal verifiability (§3) is preserved because the artifact remains verifiable — the result simply reports what its signature is worth today.

Amendments MAY additionally introduce rules that apply only to artifacts produced after the amendment's revision date, and MAY introduce verifier behavior that bounds resources or demands newly-available evidence in response to a newly-recognized hazard. Such security-strengthening behavior is not breaking in the §2 sense even where it changes a capable verifier's outcome on unchanged inputs: the artifact remains verifiable, and the changed outcome reflects the new hazard, not new protocol semantics. The resource-guard rejections above the §11.3 acceptance floors (v0.1 rev 3), the deadline-evidence requirement for `refund_window` revocation under Stage-2-capable verification (v0.2 rev 5), and the holder-binding schema conditional for transferable receipts (v0.2 rev 6, attest-v0.2.md §17.8 — `license.transferable: true` with no `buyer.pubkey` becomes a schema error, a combination that never had assigned meaning) are the three instances this revision sanctions.

v0.1 §11.2 is the forward-compatibility substrate this pattern generalizes: an unrecognized top-level payload field is signed, carried through verification, and reported only as a warning — never as an error. That rule is the payload-field instance of a general principle that binds every extension point registered in §6 (signature suites, payload fields, revocation classes, log entry types, transfer types): a verifier that predates a given extension MUST continue to accept and correctly classify artifacts that do not use it, and MUST NOT be required to reject artifacts that do, unless a new `attest_version` explicitly changes that baseline.

**Non-normative note:** v0.2 is the worked example. It adds a hybrid signature suite, a transparency/corroboration result vocabulary, and an anchoring mechanism, all reachable only under `attest_version: "0.2"`, while leaving every v0.1 receipt's verification behavior byte-for-byte unchanged (v0.2 §1).

## 3. Eternal verifiability

No amendment may render unverifiable an artifact that was conforming when issued. Deprecation degrades the result classification, never the ability to verify the bytes.

This is the constraint that makes attest evidence durable. A receipt's evidentiary value MAY be downgraded by a later amendment — a suite MAY move from `active` to `deprecated` to `unsafe` (§4), a result classification MAY be capped by a declared policy (e.g. the `crqc_horizon` gate, v0.2 §11.2–§11.3) — but the cryptographic operations a conforming verifier performs to determine `signature`, `schema`, `trust`, `revocation`, and `binding` for that artifact MUST remain defined, and MUST remain performable by an implementation of the `attest_version` the artifact declares. An amendment MUST NOT remove a signature suite, payload field, revocation class, log entry type, or transfer type once it has been registered (§6) with state `active` or `deprecated`. Such an entry's lifecycle state (§4) MAY move to `unsafe`; the entry itself, and the verification algorithm that reads it, are never removed from the specification that defines them.

## 4. Algorithm lifecycle

Every signature suite registered in §6.1 carries exactly one of three states:

| State | Issue | Verify | Verifier obligation |
| --- | --- | --- | --- |
| `active` | MAY issue | MUST verify | No downgrade. |
| `deprecated` | MUST NOT issue | MUST verify | SHOULD warn. |
| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | MUST cap the result classification (e.g. `trust`, `ok`) — a warning alone is insufficient. |

A suite is never removed. Moving a suite from `active` to `deprecated`, or from `deprecated` to `unsafe`, is a normative amendment (§5) to this document's §6.1 registry and falls under the §2 exception; it is not an amendment to the specification that defines the suite's cryptographic mechanics, which stay defined forever (§3). Only the issuance and verification obligations around a suite change; the suite's own bytes-on-the-wire meaning does not.

v0.2's `crqc_horizon` gate (v0.2 §11.2–§11.3) is the first instance of this pattern in the specification family, even though no suite in §6.1 currently carries state `unsafe`: a verifier policy MAY declare a horizon date past which classical-only anchoring evidence no longer contributes post-quantum-surviving weight, capping the result classification (v0.2 §11.1 step 7) the same way a suite moving to `unsafe` caps `trust` or `ok`. When a cryptographically-relevant quantum computer first renders classical-only issuance unsafe for new receipts, §6.1's `ed25519` entry moves to `unsafe` under this exact mechanism — it is not removed, and every receipt issued while it was `active` remains verifiable (§3).

## 5. Amendment procedure

A normative amendment to any document this policy governs is recorded in that document's own `## Revision log` section, one entry per amendment, in this exact format:

`- **2026-07-DD (rev N)**: <one line> — vectors: <group>`

`N` is the amendment's ordinal within that document's own revision log, starting at 1. `<group>` names the conformance vector group(s) the amendment added or touched, or `none` when the amendment adds or touches no vector group.

Every normative amendment MUST land with at least one conformance vector distinguishing pre/post behavior where behavior changed. An amendment that changes no observable verification behavior (an editorial clarification, a registry entry with no algorithmic consequence) is not required to add a vector, but its revision-log entry MUST say `vectors: none` explicitly rather than omitting the note.

Every vector group's entry in [`docs/spec/vectors/README.md`](vectors/README.md) MUST record the revision that introduced it, so a reader can trace any conformance leaf back to the amendment that required it.

## 6. Registries

The tables below are the extension points named by §2. Registration policy is **Specification Required** (RFC 8126 §4.6): a new entry requires a normative amendment to the registry's governing document — this document for §6.1 and §6.3–§6.5, v0.1 §5 for §6.2 — following the procedure in §5. This repository is the registry's home. Should attest's specification move to an IETF Internet-Draft, that document becomes the registry's authoritative home and this section is amended to say so; until then, registration IS spec amendment — there is no separate registration process to follow.

### 6.1 Signature suites

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `ed25519` | active | v0.1 | v0.1 §10 |
| `ed25519+ml-dsa-65` | active | v0.2 | v0.2 §2 |

**Non-normative note:** `ed25519`'s `active` state is qualified by the CRQC-cutoff mechanism named in §4 — a future cryptographically-relevant quantum computer moves it to `unsafe` under §4's lifecycle rule, not by removing it from this table.

### 6.1.1 C2SP signature-type identifiers

| Identifier | Type | State | Introduced | Reference |
| --- | ---: | --- | --- | --- |
| `attest-cosignature-ml-dsa-65-v1` | `0xff` | active | v0.2 rev 7 | v0.2 §9.2, §11.4 |

This identifier is the namespaced ML-DSA-65 witness-cosignature leg, not the checkpoint identifier `attest-ml-dsa-65`; C2SP `0x06` is excluded by v0.2 §9.2 and is not an alias or successor.

WitnessPolicy epochs are immutable release-controlled verifier policy. An installed release may add a future epoch or add/tighten a pin's compromise information, but it MUST NOT rewrite or delete the membership, keys, roles, control groups, threshold, validity interval, or contents of a prior epoch. Evidence identifies an epoch but never authorizes policy contents or updates.

### 6.2 Payload fields

v0.1 §5 is the authoritative payload-field registry: its per-object tables (§5.1–§5.6) list every defined field, its type, and its required-ness. This section is a pointer to that registry, not a duplicate of it, to keep a single source of truth. A new payload field, or a new required-ness/type constraint on an existing field that would change verifier behavior on unchanged inputs, is a normative amendment under §5 above and MUST be recorded in the governing specification's own `## Revision log`. New fields enter OPTIONAL, per the additive pattern (§2): an unrecognized field remains signed-and-warned (v0.1 §11.2) until a registry amendment recognizes it.

### 6.3 Revocation classes

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `none` | active | v0.1 | v0.1 §5.5, §6.1, §12.2 |
| `refund_window` | active | v0.1 | v0.1 §5.5, §12.2 |
| `policy` | active | v0.1 | v0.1 §5.5, §12.2 |
| `transferred` | active | v0.2 (§17 amendment, rev 6) | v0.2 §17.3 — honored for all revocability classes only with §17.1/§17.2 backing |

Key lifecycle statuses — `active`, `retired`, `compromised` (v0.1 §7.3) — are a SEPARATE vocabulary, governed by v0.1 §7.3, and are not `license.revocability` classes; `compromised` describes a KEY's state, never a license's revocability, and does not belong in this registry (2026-07-23 fix — an earlier revision of this table listed it here in error).

### 6.4 Log entry types

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `key-manifest` | active | v0.2 | v0.2 §8 |
| `receipt` | active | v0.2 | v0.2 §8 |
| `revocation-record` | active | v0.2 (§8/§15 amendment, rev 5) | v0.2 §8, §15 item 5 — G5/TM-47: a `refund_window` revocation record's effectiveness gains a deadline-effectiveness rule once a verifier evaluates this entry type's transparency evidence for it. |
| `transfer-record` | active | v0.2 (§8/§17 amendment, rev 6) | v0.2 §8, §17.2 |

### 6.5 Transfer types

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `issuer-mediated-v1` | active | v0.2 (§17, rev 6) | v0.2 §17 |

This registry's first entry is populated by the receipt-transfer profile named as out of scope for v0.1 (v0.1 §2) and shipped as v0.2's Stage 3 (v0.2 §17), the remaining stage of v0.2's roadmap this registry named empty at its introduction.

### 6.6 Warning literals

| Literal | State | Introduced | Reference |
| --- | --- | --- | --- |
| `witness_independence_not_established` | active | v0.2 rev 7 | v0.2 §10.1, §11.4, §15 item 1 |

This is the sole P1.1b warning literal. It records that timestamped witness observation does not establish organizational independence; it is not a positive independence inference.

## Revision log

- **2026-07-28 (rev 4)**: §6.1.1 registers `attest-cosignature-ml-dsa-65-v1` at C2SP type `0xff` and distinguishes it from the checkpoint identifier; immutable WitnessPolicy epoch/update lifecycle is recorded; §6.6 registers the sole P1.1b warning `witness_independence_not_established`; revision provenance is groups 39 and 40. — vectors: 39-witness-corroboration, 40-witness-quorum
- **2026-07-23 (rev 3)**: §6.3 `transferred` row assigned `active` state by v0.2 §17 (Stage 3, was `reserved`); §6.4 gains `transfer-record`, `active`, introduced by v0.2 §8/§17; §6.5 receives its first entry, `issuer-mediated-v1`, `active` — the transfer-type registry named empty at this document's introduction now has its first registrant. **Amended same-day, still rev 3 (unpublished):** §2's sanctioned newly-recognized-hazard instances extended from two to three with the v0.2 rev 6 holder-binding schema conditional (attest-v0.2.md §17.8). — vectors: 35-transfer, 36-transfer-chain
- **2026-07-22 (rev 2)**: §6.4 `revocation-record` row assigned `active` state by v0.2 rev 5 (was `reserved`); §2 amendment rule restored — the security-strengthening exception (resource guards above §11.3's floors, the `refund_window` deadline-evidence requirement) was omitted from an earlier revision of this document and is now stated; §6.3 registry corrected — the `compromised` row is dropped (it names a key lifecycle STATUS, v0.1 §7.3, not a `license.revocability` class, v0.1 §5.5) and a clarifying sentence distinguishes the two vocabularies. — vectors: none
- **2026-07-22 (rev 1)**: document introduced — vectors: none

## References

- RFC 2119 / RFC 8174 — normative key words.
- RFC 8126 — Guidelines for Writing an IANA Considerations Section; §6's "Specification Required" registration policy.
- [`docs/spec/attest-v0.1.md`](attest-v0.1.md) — the base specification this document governs; §5 (payload field registry), §10 (Ed25519 ruleset), §11.2 (forward-compatibility substrate).
- [`docs/spec/attest-v0.2.md`](attest-v0.2.md) — the additive delta specification this document governs; §1 (additive-delta framing), §2 (hybrid signature profile), §11 (`AnchorPolicy` and the `crqc_horizon` gate).
