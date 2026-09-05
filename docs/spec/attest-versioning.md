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

Amendments MAY additionally introduce rules that apply only to artifacts produced after the amendment's revision date, MAY introduce verifier behavior that bounds resources or demands newly-available evidence in response to a newly-recognized hazard, and MAY introduce verifier behavior that re-resolves evidence already in the verifier's possession more severely in response to a newly-recognized hazard — where the prior resolution was unsound in that it let the party a rule constrains erase that rule's effect at will. Such security-strengthening behavior is not breaking in the §2 sense even where it changes a capable verifier's outcome on unchanged inputs: the artifact remains verifiable, and the changed outcome reflects the new hazard, not new protocol semantics. The resource-guard rejections above the §11.3 acceptance floors (v0.1 rev 3), the deadline-evidence requirement for `refund_window` revocation under Stage-2-capable verification (v0.2 rev 5), the holder-binding schema conditional for transferable receipts (v0.2 rev 6, attest-v0.2.md §17.8 — `license.transferable: true` with no `buyer.pubkey` becomes a schema error, a combination that never had assigned meaning), and the holder-binding schema conditional for pledge-bearing receipts (v0.2 rev 8, attest-v0.2.md §18.6 — `license.preservation_pledge` present with no `buyer.pubkey`, no `work.publisher_id`, or without `survivability.end_of_life == "sunset-grant"` becomes a schema error, likewise a combination that never had assigned meaning) are the first four instances this revision sanctions. The fifth instance is the anchored-cutoff compromise rescue (v0.2 rev 9, attest-v0.2.md §19): a Stage-2-capable verifier's outcome on a compromised-key receipt changes from rejection to acceptance exactly when newly-available anchored existence evidence proves the signature predates the declaring key manifest's anchored time; the artifact remains verifiable, no previously-conforming verifier rejects a previously-conforming artifact, and no result classification worsens on unchanged inputs. The sixth instance is separate and runs in the tightening direction: the monotone `compromised` status floor (v0.1 rev 8, attest-v0.1.md §7.3) means a verifier holding an issuer's manifest chain or authenticated compromise-declaration evidence now resolves a key declared `compromised` in that evidence as `compromised`, so a receipt that such a verifier previously accepted after the issuer re-listed the key `active` may now be rejected. This specification does not pretend the rejected input was already non-conforming: until this revision, rotation continuity constrained only the signer of the successor manifest, so a status regression conformed to what was written. The floor is sanctioned as a newly-recognized hazard: the prior rule was unsound because it let the party the compromise rule constrains erase the rule's effect at will. The direction of the change is toward rejecting signatures, never toward accepting them, and no receipt whose issuer never exposed such a `compromised` marking to the verifier changes outcome. Eternal verifiability (§3) is untouched. The seventh, eighth and ninth are the V-L issuance/verification guards, all in the tightening direction: the duplicate-`kid` key-manifest rejection (v0.1 rev 10, attest-v0.1.md §7.1 — an ambiguous manifest that formerly resolved by array position now fails closed), the statement-status restriction on the revocation freshness anchor (v0.1 rev 10, attest-v0.1.md §12.3 — a non-statement record no longer inflates `T`), and the duplicate-member-name bundle-import rejection (v0.1 rev 10, attest-v0.1.md §14.1 — an importer no longer silently shadows a duplicated member). The tenth also tightens: the oversized-`revocation_view` rule now fails closed for `license.revocability: "none"` as well (v0.1 rev 13, attest-v0.1.md §12.4 — a receipt of that class whose over-ceiling view carries a backed `status: "transferred"` record was certified before and is refused now). Its prior text was sound when written and was unsounded by a later revision rather than by a newly-recognized hazard: v0.2 §17.3 extended the transfer key-authorization gate to every revocability class, `none` included, which ended the reasoning — "a revocation record can never affect `ok`" — that made the non-fatal treatment safe, and those records ride that same view. The direction is toward rejecting, never toward accepting, and a verifier whose views stay under the ceiling changes no outcome at all. The eleventh runs in the same direction as the first and is its container-level twin: the `resource-limit` refusals above the container resource floor (v0.1 rev 14, attest-v0.1.md §14.4 — an importer MAY decline an honest archive larger than the bound it applies, provided it reports the refusal as a resource outcome and never as invalidity). The floor itself — the profile every importer MUST accept — is an obligation on verifiers that this section does not classify, since it makes no artifact rejectable. The twelfth is the container resource floor gaining a fourth axis (v0.1 rev 15, attest-v0.1.md §14.4 — the size of the container as stored joins the three decompression bounds). It runs in the direction of permitting rather than requiring: an archive that stays inside the three decompression bounds while occupying more than the stored-size floor was within the floor before and is above it now, so an importer MAY decline it as a resource refusal where previously it was obliged to accept. No importer is required to change: one that accepted such an archive still may, and no artifact is made invalid — only declinable, under the same outcome class the eleventh instance governs. The floor was unsound as written in the direction this specification cares about: it obliged every importer to accept a container whose cost it did not measure, so an importer bounding what it copies was non-conforming for a reason the section never stated. These are the twelve instances this revision sanctions.

v0.1 §11.2 is the forward-compatibility substrate this pattern generalizes: an unrecognized top-level payload field is signed, carried through verification, and reported only as a warning — never as an error. That rule is the payload-field instance of a general principle that binds every extension point registered in §6 (signature suites, payload fields, revocation classes, log entry types, transfer types): a verifier that predates a given extension MUST continue to accept and correctly classify artifacts that do not use it, and MUST NOT be required to reject artifacts that do, unless a new `attest_version` explicitly changes that baseline.

**Non-normative note:** v0.2 is the worked example. It adds a hybrid signature suite, a transparency/corroboration result vocabulary, and an anchoring mechanism, all reachable only under `attest_version: "0.2"`, while leaving v0.1 receipt verification byte-for-byte unchanged for verifiers that hold neither an issuer manifest-version chain nor authenticated compromise-declaration evidence; v0.1 rev 8 deliberately changes chain-holding or declaration-holding verifiers only in the tightening direction described above.

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
| `cessation-declaration` | active | v0.2 (§8/§18 amendment, rev 8) | v0.2 §8, §18.4 — logging a declaration is RECOMMENDED and never required for validity, unlike `transfer-record` (§17.2) |

### 6.5 Transfer types

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `issuer-mediated-v1` | active | v0.2 (§17, rev 6) | v0.2 §17 |

This registry's first entry is populated by the receipt-transfer profile named as out of scope for v0.1 (v0.1 §2) and shipped as v0.2's Stage 3 (v0.2 §17), the remaining stage of v0.2's roadmap this registry named empty at its introduction.

### 6.6 Warning literals

| Literal | State | Introduced | Reference |
| --- | --- | --- | --- |
| `witness_independence_not_established` | active | v0.2 rev 7 | v0.2 §10.1, §11.4, §15 item 1 |
| `compromise_rescue_applied` | active | v0.2 rev 9 | v0.2 §19 |
| `compromise_cutoff_unanchored` | active | v0.2 rev 9 | v0.2 §19 |
| `compromise_rescue_requires_anchored_receipt` | active | v0.2 rev 9 | v0.2 §19 |
| `compromise_rescue_receipt_after_cutoff` | active | v0.2 rev 9 | v0.2 §19 |
| `compromise_cutoff_claim_ignored` | active | v0.2 rev 9 | v0.2 §19 |
| `compromise_marking_retracted` | active | v0.1 rev 8 | v0.1 §7.3 |

The `witness_independence_not_established` row is the sole P1.1b warning literal. It records that timestamped witness observation does not establish organizational independence; it is not a positive independence inference.

### 6.7 End-of-life commitment values

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `artifacts-remain-redownloadable` | active | v0.1 | v0.1 §5.6 |
| `escrow` | active | v0.1 | v0.1 §5.6 |
| `none` | active | v0.1 | v0.1 §5.6 |
| `sunset-grant` | active | v0.2 (§18 amendment, rev 8) | v0.2 §18 — the label a Stage 4 receipt carries; the binding itself lives in `license.preservation_pledge` (§18.2) |

The vocabulary stays OPEN: v0.1 §5.6 classifies an unrecognized `end_of_life` value as valid-with-warning, never a schema error, and that discipline is unchanged. Registering a value here assigns it meaning to a Stage-4-capable verifier; it does not close the field.

### 6.8 Grant permissions

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `deliver-to-holder` | active | v0.2 (§18, rev 8) | v0.2 §18.2 — REQUIRED in every grant's `permissions` |
| `redistribute-among-holders` | active | v0.2 (§18, rev 8) | v0.2 §18.2 — OPTIONAL; a permission the rights holder grants, never a distribution channel this specification defines |

### 6.9 Activation modes

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `publisher-declaration` | active | v0.2 (§18, rev 8) | v0.2 §18.4 — a signed cessation declaration from the publisher or a designated successor |
| `fixed-date` | active | v0.2 (§18, rev 8) | v0.2 §18.4 — an anchored proof that chain time has reached the grant's own `fixed_date` |
| `heartbeat-absence` | reserved | v0.2 (§18, rev 8) | v0.2 §18.4 — registered, deliberately unreachable: a mode that reads meaning into the ABSENCE of a recent record cannot be sound until a verifier can establish freshness, which no transparency log alone provides |

`heartbeat-absence` is reserved rather than omitted so that the gap it names stays visible. Promoting it to `active` is a normative amendment in its own right, not an editorial change, and requires the freshness mechanism it waits on.

### 6.10 Preservation pledge types

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `sunset-grant-v1` | active | v0.2 (§18, rev 8) | v0.2 §18.2 — the sole pledge profile this revision defines |

The vocabulary is open and versioned: an unrecognized `license.preservation_pledge.pledge` value is valid-with-warning, following §6.7's discipline, never a schema error.

### 6.11 Authorization permissions

| Name | State | Introduced | Reference |
| --- | --- | --- | --- |
| `issue` | active | v0.2 (§20, rev 10) | v0.2 §20.2, §20.4 step 9 — the permission a receipt's issuer must hold |
| `delegate` | reserved | v0.2 (§20, rev 10) | v0.2 §20.6 item 2 — registered so the sub-licensing gap stays visible; promoting it requires the delegation-chain machinery this revision deliberately excludes |

The vocabulary follows §18.2's directional rule: unregistered values are carried, never fatal.

## Revision log

- **2026-09-03 (rev 10)**: §2's closed list gains a twelfth instance — v0.1 §14.4's container resource floor gains a fourth axis, the size of the container as stored, so an archive inside the three decompression bounds that occupies more than the stored-size floor moves from within the floor to above it and becomes declinable as a resource refusal rather than obligatory to accept. It permits rather than requires: no importer must change, no artifact becomes invalid, and the refusal falls under the outcome class the eleventh instance already governs. — vectors: none

- **2026-09-03 (rev 9)**: §2's closed list of sanctioned instances gains an eleventh, the container-level twin of the first — `resource-limit` refusals above v0.1 §14.4's container resource floor, where an importer declines an honest archive larger than the bound it applies and reports a resource outcome rather than invalidity; the floor itself is an obligation on importers, makes no artifact rejectable, and is not an instance. — vectors: none

- **2026-08-29 (rev 8)**: §6.11 added — authorization permissions (`issue` `active`, `delegate` `reserved`), the vocabulary v0.2 §20.2's `authorized_issuers` entries draw on; unregistered values are carried, never fatal, following §18.2's directional rule. — vectors: pending 43-publisher-authority
- **2026-08-26 (rev 7)**: §2's closed list of sanctioned instances gains a seventh, an eighth and a ninth, all running in the tightening direction and all from the V-L review of v0.1 rev 10 — the duplicate-`kid` key-manifest rejection (attest-v0.1.md §7.1), the statement-status restriction on the revocation freshness anchor (attest-v0.1.md §12.3), and the duplicate-member-name bundle-import rejection (attest-v0.1.md §14.1). The third carries no conformance vector because the corpus has no bundle surface, the same posture as the `artifacts[]` ceiling of v0.1 rev 3; the first two do. The issuance-side guards of the same revision — refusing to sign a manifest with a duplicated `kid`, and refusing a rotation that would leave zero active keys — change no verification classification and are therefore not §2 instances at all. — vectors: 44-manifest-duplicate-kid, 45-revocation-anchor-status

- **2026-08-26 (rev 6)**: §2's chapeau gains a third admitted form of security-strengthening amendment — verifier behavior that re-resolves evidence already in the verifier's possession more severely in response to a newly-recognized hazard, where the prior resolution was unsound in that it let the party a rule constrains erase that rule's effect at will; without it the sixth instance below would be unsanctioned, since the monotone status floor neither bounds resources nor demands newly-available evidence. §2's closed list of sanctioned instances gains a fifth — the anchored-cutoff compromise rescue (v0.2 rev 9, attest-v0.2.md §19), which runs in the loosening direction — and a separate sixth, the monotone `compromised` status floor (v0.1 rev 8, attest-v0.1.md §7.3), which runs in the tightening direction and is sanctioned as a newly-recognized hazard rather than by pretending the rejected input was already non-conforming. §2's non-normative note is scoped to verifiers holding neither an issuer manifest-version chain nor authenticated compromise-declaration evidence. §6.6 registers six warning literals — `compromise_rescue_applied`, `compromise_cutoff_unanchored`, `compromise_rescue_requires_anchored_receipt`, `compromise_rescue_receipt_after_cutoff`, `compromise_cutoff_claim_ignored` — active, introduced by v0.2 rev 9, reference v0.2 §19 — and `compromise_marking_retracted`, active, introduced by v0.1 rev 8, reference v0.1 §7.3. — vectors: 41-compromise-cutoff

- **2026-08-25 (rev 5)**: §6.4 gains `cessation-declaration`, `active`, introduced by v0.2 §8/§18 — with the posture difference that logging one is RECOMMENDED and never load-bearing, unlike `transfer-record`; four new registries carry Stage 4's own vocabularies — §6.7 end-of-life commitment values (v0.1's three seed values recorded, plus `sunset-grant` `active`, the field's open-vocabulary discipline unchanged), §6.8 grant permissions (`deliver-to-holder` and `redistribute-among-holders`, both `active`), §6.9 activation modes (`publisher-declaration` and `fixed-date` `active`; `heartbeat-absence` deliberately `reserved`, because reading meaning into the absence of a record is unsound until freshness can be established), and §6.10 preservation pledge types (`sunset-grant-v1`, `active`); §2's sanctioned newly-recognized-hazard instances extended from three to four with the v0.2 rev 8 pledge-bearing holder-binding schema conditional (attest-v0.2.md §18.6). — vectors: 37-preservation-pledge, 38-redemption
- **2026-07-28 (rev 4)**: §6.1.1 registers `attest-cosignature-ml-dsa-65-v1` at C2SP type `0xff` and distinguishes it from the checkpoint identifier; immutable WitnessPolicy epoch/update lifecycle is recorded; §6.6 registers the sole P1.1b warning `witness_independence_not_established`; revision provenance is groups 39 and 40. — vectors: 39-witness-corroboration, 40-witness-quorum
- **2026-07-23 (rev 3)**: §6.3 `transferred` row assigned `active` state by v0.2 §17 (Stage 3, was `reserved`); §6.4 gains `transfer-record`, `active`, introduced by v0.2 §8/§17; §6.5 receives its first entry, `issuer-mediated-v1`, `active` — the transfer-type registry named empty at this document's introduction now has its first registrant. **Amended same-day, still rev 3 (unpublished):** §2's sanctioned newly-recognized-hazard instances extended from two to three with the v0.2 rev 6 holder-binding schema conditional (attest-v0.2.md §17.8). — vectors: 35-transfer, 36-transfer-chain
- **2026-07-22 (rev 2)**: §6.4 `revocation-record` row assigned `active` state by v0.2 rev 5 (was `reserved`); §2 amendment rule restored — the security-strengthening exception (resource guards above §11.3's floors, the `refund_window` deadline-evidence requirement) was omitted from an earlier revision of this document and is now stated; §6.3 registry corrected — the `compromised` row is dropped (it names a key lifecycle STATUS, v0.1 §7.3, not a `license.revocability` class, v0.1 §5.5) and a clarifying sentence distinguishes the two vocabularies. — vectors: none
- **2026-07-22 (rev 1)**: document introduced — vectors: none

## References

- RFC 2119 / RFC 8174 — normative key words.
- RFC 8126 — Guidelines for Writing an IANA Considerations Section; §6's "Specification Required" registration policy.
- [`docs/spec/attest-v0.1.md`](attest-v0.1.md) — the base specification this document governs; §5 (payload field registry), §10 (Ed25519 ruleset), §11.2 (forward-compatibility substrate).
- [`docs/spec/attest-v0.2.md`](attest-v0.2.md) — the additive delta specification this document governs; §1 (additive-delta framing), §2 (hybrid signature profile), §11 (`AnchorPolicy` and the `crqc_horizon` gate).
