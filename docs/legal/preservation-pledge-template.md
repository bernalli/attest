# Sunset grant — prose template (DRAFT, for counsel)

> **This is not legal advice, and it is not a finished instrument.** It is a
> drafting aid: a structured starting point a rights holder takes to their own
> qualified lawyer, in their own jurisdiction, before signing anything. The
> people who wrote attest are not lawyers. Nothing here has been reviewed by
> one. A publisher who signs a grant pointing at this text as it stands is
> committing themselves to language nobody qualified has read.
>
> The specification is explicit about this dependency (attest-v0.2.md §18.2,
> "The prose dependency"): `legal_text_uri` and `legal_text_sha256` are
> REQUIRED members precisely so the machinery is exercisable end to end, but
> **the specification gives that text its structure and does not write it.**

## What this document is for

attest's Stage 4 (v0.2 §18) lets a rights holder sign a *sunset grant*: a
machine-readable commitment that, once a verifiable trigger fires, the holder
of a valid receipt may obtain an unprotected copy of the work. The grant
document carries the machine-checkable half — scope, permissions, trigger,
dates. It also carries two members, `legal_text_uri` and
`legal_text_sha256`, that hash-bind **this** text: the half a machine cannot
read and must not pretend to.

The division matters and is worth stating plainly to whoever drafts the final
version:

- A verifier decides only whether the grant **authenticates**, whether it
  **covers** the buyer's artifacts, and whether the trigger has **fired**. It
  never interprets a word of the prose.
- Everything about what the permission actually means as an undertaking —
  who may enforce it, against whom, under which law, with what remedy —
  lives here, and only here.
- Under §18.3's ratchet, a later version of the grant may widen the
  machine-checkable members and may never narrow them. **The prose is
  deliberately outside that test**, because no comparison of hashes can tell a
  clarification from a restriction. The text that binds a given buyer is
  therefore always the one their own receipt hash-bound at purchase. A drafter
  should read that as: this text will be opposable for as long as any receipt
  citing it exists, and it cannot be quietly improved afterwards.

## The clauses the machine expects prose for

Each section below corresponds to a member of the signed grant document. The
placeholders in `[BRACKETS]` are for the publisher and their counsel. The
commentary under each is what the specification actually requires the clause
to be consistent with — not suggested wording.

### 1. The parties and the work

> `[RIGHTS HOLDER LEGAL NAME]`, of `[REGISTERED ADDRESS]`, controlling the
> rights described below in `[JURISDICTION]`, makes the undertaking set out in
> this document in respect of the works identified by the accompanying signed
> grant document, whose SHA-256 over its canonical form is
> `[GRANT_SHA256]`.

The grant's `publisher` member is a DNS domain, not a legal person. Counsel
should decide how the domain and the legal entity are tied together, and
whether that tie needs to survive a sale of the domain.

### 2. The undertaking

> Upon the occurrence of a Trigger Event as defined in section 4, and for so
> long as `[RIGHTS HOLDER]` or its successors control the rights in the Works,
> `[RIGHTS HOLDER]` undertakes that any person able to present a valid attest
> receipt covering a Work, together with proof that they hold the private key
> committed to in that receipt, may obtain a copy of that Work free of
> technological protection measures, and may exercise the permissions listed
> in section 3.

Two constraints from §18 that this clause must not contradict:

- The grant's `unprotected_build` member is a REQUIRED boolean. If it is
  `true` — and a grant over a DRM-bound artifact is close to meaningless if it
  is not — the undertaking above is what gives that boolean its content.
- §18.7 requires the holder to prove possession of the receipt's own
  `buyer.pubkey` against a specific custodian's audience. "Holder" is a
  cryptographic fact here, not a claim; counsel should be aware that the
  undertaking is therefore enforceable by a determinate person rather than by
  the public at large.

### 3. The permissions

> The permissions granted are those enumerated in the `permissions` member of
> the signed grant document, construed as follows:
>
> - `deliver-to-holder` — `[RIGHTS HOLDER]` does not object to any person
>   delivering a copy of a Work to a holder who satisfies section 2.
> - `redistribute-among-holders` — where present, holders who satisfy
>   section 2 may additionally supply copies of that Work to one another.

`deliver-to-holder` is mandatory in every conforming grant;
`redistribute-among-holders` is optional. Neither is a licence to publish the
work at large, and the prose should say so explicitly: the permission is
bounded by the set of people who can produce a valid receipt.

Note also that the registries for these values are open (§18.2): a value this
document does not name is carried by a verifier and grants nothing. Counsel
should decide whether the prose enumerates the permissions exhaustively or
defers to the signed document — the two readings differ if the publisher later
signs a widened version.

### 4. The trigger

> A Trigger Event occurs when either of the following can be demonstrated:
>
> (a) a cessation declaration in the form specified by attest v0.2 §18.4 has
>     been signed by `[RIGHTS HOLDER]` or by a successor named in the grant's
>     `activation.successor_ids`; or
>
> (b) the date given in the grant's `activation.fixed_date` has passed, as
>     evidenced by an anchored attestation over the grant's own canonical
>     bytes.

Three things counsel should be told, because they are properties of the
mechanism rather than choices of drafting:

- Activation follows from **positive evidence only**. There is no clause that
  fires from the absence of something, and the specification explains at
  length why the earlier "dead man's switch" design was abandoned as unsound.
- A publisher who simply vanishes — signing nothing, naming no successor,
  setting no date — leaves the grant closed forever. Naming successors and
  setting a backstop date are the only two mitigations, and both are decisions
  taken at issuance. Naming successors also enlarges the set of people who
  could be coerced into declaring; that trade is the rights holder's to make.
- A declaration signed under a key later marked `compromised` stops
  authenticating, and a grant activated on it returns to dormant. Activation
  is not strictly irreversible, and the cost of a reversal falls on the buyer.

### 5. Governing law

> This undertaking is governed by the law of `[JURISDICTION]`, matching the
> `jurisdiction` member of the signed grant document.

The signed document carries `jurisdiction` as a free-form REQUIRED string. It
is not validated against any registry, and a verifier does nothing with it. The
two must agree, and keeping them in step is a drafting discipline, not
something the software enforces.

### 6. Limitations to state rather than hide

The specification's own threat model names three residuals that a drafter
should decide how to address, or decide to leave addressed by nothing:

- **Insolvency.** Every cryptographic check can pass while the permission has
  no force against an administrator or a purchaser of the assets. Whether this
  undertaking survives insolvency, and how, is a question for counsel in the
  relevant jurisdiction — the software cannot answer it and does not pretend
  to (TM-71).
- **Coerced declaration.** A cessation declaration signed under duress is
  indistinguishable from a free one (TM-69).
- **Silent death.** See section 4 (TM-68).

## Before this is used

1. Have it drafted properly, by a lawyer, in the jurisdiction it names.
2. Publish the final text at a stable URI and hash it with SHA-256.
3. Put that URI and that hash into the grant's `legal_text_uri` and
   `legal_text_sha256`, then sign the grant.
4. Remember that a later version may widen the machine-checkable members and
   may never narrow them — and that moving the prose to a new URI, even with
   an unchanged hash, is reported to holders as a change (`grant_legal_text_changed`).
