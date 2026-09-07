# attest Patent Non-Assertion Covenant

**Version 1.0 — 2026-09-05**

This document is an irrevocable, royalty-free promise not to assert patents against anyone who
implements the attest specification. It grants rights and takes none away; the single condition is
in Section 4, which ends the promise for a party who brings patent litigation of their own
claiming that attest infringes. If you only use the Apache-2.0 licensed code in this repository,
you do not need to read further — the Apache License already covers you.

## 1. Why this file exists

attest is published under two licenses, and neither of them makes a patent commitment to an
independent implementer:

- The code in this repository is licensed under the Apache License, Version 2.0. Its Section 3
  grants a patent license, but only for patent claims "necessarily infringed by their
  Contribution(s) alone or by combination of their Contribution(s) with the Work" — that is, for
  the code itself. It does not reach an implementation written independently from the
  specification.
- The specification and the other documentation are licensed under Creative Commons Attribution
  4.0 International, whose Section 2(b)(2) states plainly: "Patent and trademark rights are not
  licensed under this Public License."

attest is a protocol, and the Specification is where it is written down. It is meant to be
implemented independently, from that text, by parties who never copy a line of this repository's
code — the conformance suite exists to make exactly that possible. This covenant closes the gap
those two licenses leave open, so that implementing the Specification carries no patent risk from
its author.

## 2. Definitions

**"the Project"** means attest as published in the attest source repository at
<https://github.com/bernalli/attest>, taken as a whole: the Specification, the implementations of
it published in that repository, and the name under which they are published. Where this document
uses the lower-case word "attest" outside this definition, it names the project informally and
adds nothing to the terms defined here.

**"Specification"** means the attest specification as published in the attest source repository at
<https://github.com/bernalli/attest>, including `docs/spec/attest-v0.1.md`,
`docs/spec/attest-v0.2.md`, `docs/spec/attest-privacy.md`, `docs/spec/attest-threat-model.md`,
`docs/spec/attest-standards-relationship.md`, `docs/spec/attest-transfer-economics.md`,
`docs/spec/attest-versioning.md`, the JSON Schema and conformance vectors under `docs/spec/`,
every later revision and version of those documents, the Internet-Draft
`draft-martinalli-open-purchase-receipts` and its successor drafts, and any RFC published from
them.

**"Implementation"** means any software, hardware, service, or system that implements any part of
the Specification, whether in whole or in part, whether or not it is conformant, and whether or
not it is derived from any code in the attest repository.

**"Described in Detail"** means set out in the Specification with enough particularity that an
implementer working from the Specification alone, and making no independent design choice on the
point, would arrive at the functionality in question. Functionality is not Described in Detail
where the Specification only names it, cites it, recommends it, or incorporates it by reference to
another document, without stating how it works.

**"Covered Claims"** means those claims of patents and patent applications, in any jurisdiction,
now or hereafter owned or controlled by the Author, that would be infringed by a Permitted Use,
but only where the functionality causing the infringement is Described in Detail.

**"Permitted Use"** means making, having made, using, offering to sell, selling, importing,
transferring, distributing, running, modifying, and otherwise propagating an Implementation.

**"Author"** means Samuele Martinalli, the author and copyright holder of attest, together with
any successors in interest and any assignees of the patents concerned.

**"You"** means any person or legal entity exercising a Permitted Use.

## 3. The covenant

The Author irrevocably promises not to assert any Covered Claims against You for Your Permitted
Uses.

This promise is perpetual, worldwide, non-exclusive, no-charge, and royalty-free. It requires no
signature, no registration, no notice to the Author, and no agreement of any kind: it takes effect
automatically in favour of anyone who makes a Permitted Use, whether or not they are aware of this
document. No fee has ever been charged to implement the Specification, and under this covenant
none can be.

The promise covers every version of the Specification, including versions published after the date
of this document.

## 4. Defensive termination

This covenant terminates as to You, and only as to You, if You institute or voluntarily join
patent litigation (including a cross-claim or counterclaim) alleging that the Project, the
Specification, or the implementation of any part of the Specification infringes a patent.

What matters is what the action alleges, not who it is brought against. Suing a party over a
patent that has nothing to do with attest does not engage this Section, and does not begin to
engage it because that party happens to publish an Implementation.

This Section does not apply where Your action is a direct response to earlier patent litigation
of the same kind brought against You — that is, litigation alleging that the Project, the
Specification, or the implementation of any part of the Specification infringes a patent. Both
conditions must hold: the other action must have come first, and it must have made an allegation
of that same kind. Answering an unrelated patent suit by counterclaiming that the other side's
Implementation infringes is not within this exception.

This trigger and the one in Apache-2.0 Section 3 turn on the same thing: what the action alleges
infringes, rather than who is being sued. They differ in three respects where this one reaches
further — it covers an action You join as well as one You bring, its subject is the Project and
the Specification rather than a single repository's code, and it is not confined to allegations of
direct or contributory infringement — and in one where it reaches less far, since Apache-2.0
exempts no defensive action at all.

Nothing You do outside the subject matter of attest can cost You the rights promised here.

## 5. Relationship to the licenses of this project

This covenant is purely additive. It does not modify, condition, limit, suspend, or terminate any
right granted by the Apache License 2.0 (`LICENSE`) or by CC BY 4.0 (`LICENSE-docs`), and nothing
in it may be read as imposing an additional obligation on a recipient of either license. Where
this document and either license could be read as inconsistent, the license governs and this
covenant adds only what the license does not address.

Accepting anything in this document is not a condition of using the Project, including its code
and the Specification.

## 6. Successors, assigns, and transferees

This covenant is irrevocable and binds the Author, the Author's successors, and any assignee or
other transferee of a Covered Claim. The Author will not transfer a Covered Claim except subject
to this covenant, and will require each transferee to make the same commitment with respect to any
onward transfer. Anyone making a Permitted Use is entitled to rely on this covenant whether or not
a Covered Claim has since been transferred to a third party.

## 7. Contributors

Contributions to the Specification are governed by `CONTRIBUTING.md`, under which each contributor
makes their own non-assertion commitment for their own patent claims. It has the same purpose as
the Author's and is narrower in its terms. `CONTRIBUTING.md` is the governing text for what a
contributor has promised; this Section describes that promise and does not enlarge it. It differs
from Sections 3, 4, 6 and 10 in the following respects:

- **Claims.** It reaches only claims infringed by implementing the part of the Specification that
  contributor's own contribution describes in detail — the phrase carrying the meaning Section 2
  gives to Described in Detail — and not the Specification as a whole.
- **Beneficiaries.** It is made to those who implement the Specification. Section 3 runs further,
  to anyone exercising a Permitted Use, so someone who distributes, sells, imports or runs an
  Implementation without implementing anything themselves has the Author's promise and does not,
  on the face of `CONTRIBUTING.md`, have a contributor's.
- **Time.** It speaks of patent claims a contributor owns or controls, without the words "now or
  hereafter" and without naming patent applications, so it does not expressly reach a patent a
  contributor acquires or is granted afterwards — which is the reach Section 9 relies on for the
  Author's own claims.
- **Termination.** It carries no defensive-termination clause of its own.
- **Continuity.** It does not bind a contributor's successors or transferees as Section 6 binds
  the Author's, and it is not versioned as Section 10 versions this document.

Contributions of code remain governed by the patent grant in Section 3 of the Apache License 2.0.

This covenant speaks only for the Author. It does not, and cannot, speak for any contributor's
patents beyond the commitment that contributor has made.

## 8. What this covenant does not do

- It says nothing about patents held by third parties. The Author has made no patent search, makes
  no representation that implementing the Specification infringes no patent of anyone else, and
  could not give such an assurance if asked. Functionality that is not Described in Detail —
  including anything reached only through the normative references the Specification cites to
  other standards — is outside the definition of Covered Claims.
- It grants no trademark rights and no copyright rights. Copyright in the code and in the
  documentation is licensed separately; see `LICENSE`, `LICENSE-docs`, and the naming note in
  `README.md`.
- It is a promise, not a warranty. The Project is provided without warranty of any kind, as stated
  in its licenses.

## 9. Current holdings

As of the date of this version, the Author holds no patents and has filed no patent applications
relating to the Project or to any technology described in the Specification. This statement is a
statement of present fact, not a limit on the covenant: Section 2 defines Covered Claims as those
"now or hereafter owned or controlled by the Author", and Section 3 promises not to assert them,
so any patent the Author might obtain in the future is bound from the moment it exists.

## 10. Changes to this document

This covenant may be republished in a later version to broaden it, to clarify it, or to correct an
error. A later version cannot narrow or withdraw the commitment made by an earlier one: every
version, once published, remains in force for all Permitted Uses, and You may rely on whichever
version is most favourable to You. Each version carries its own version number and date, and the
history of this file is public in the repository.

## 11. Standards bodies

This covenant is published unilaterally by the Author and is not made under the patent policy of
any standards organisation. Where material from the Project is submitted to the IETF, the Author's
obligations under BCP 79 (RFC 8179) apply independently of this document, and any disclosure
required there will be filed through the IETF's own disclosure facility at
<https://datatracker.ietf.org/ipr/>. This covenant is intended to correspond to the licensing
option described in BCP 79 Section 5.5.A(c) — implementation "without the need to obtain a license
from the IPR holder (e.g., a covenant not to sue with or without defensive suspension)".

---

Samuele Martinalli
attest — <https://github.com/bernalli/attest>
Version 1.0, 2026-09-05
