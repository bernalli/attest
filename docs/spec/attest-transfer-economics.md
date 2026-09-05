# attest — Transfer Economics (non-normative)

**Non-normative.** This document imposes no requirements and uses no RFC 2119 keywords
(MUST, SHOULD, MAY, and their negatives, as fixed in `attest-v0.1.md` §1) with
conformance force. It explains the market and legal context behind the one in-protocol
business knob Stage 3 defines — `license.not_transferable_before` (v0.2 §17.7) — and
states, explicitly, what this profile deliberately does not attempt to regulate.
Nothing here is legal advice; §3 describes case law as a technical constraint the
protocol's design responds to, not as counsel for any particular deployment.

## 1. The velocity problem

A perpetual, unrestricted, instantly-resellable digital license changes the economics of
a sale in a way a physical good's resale does not. A physical copy takes time to change
hands — shipping, a used-goods storefront, a private sale — and degrades with use. A
digital copy resells at zero marginal cost, instantly, without degradation, and the
buyer's copy can be extinguished the same instant the new one is issued. Push resale
velocity high enough and a single unit of inventory can satisfy a large multiple of the
demand a rights holder priced for: a stylized way of stating the concern is that seven
willing buyers become one paying customer and six resales, with the rights holder priced
for seven. This is not a claim about any measured rate for any specific market — it is
the reason a rights holder rational about revenue treats "instant, frictionless, digital
resale" as qualitatively different from "a receipt exists and could theoretically be
sold," and it is why v0.1 left `license.transferable` reserved rather than meaningful
from the start (v0.1 §2): shipping a transfer mechanism without also giving rights
holders a lever over its economics would have made the reserved field a liability the
moment it was activated.

## 2. Issuer incentives and the royalty lever

Robot Cache — a PC game resale marketplace co-founded by developer Brian Fargo — is one
public precedent that a resale-royalty mechanism has been offered to publishers:
publishers who opt in keep the large majority of a new sale (reported at 95% for the
first 90 days after release, tapering afterward) and, distinctively, still receive a
majority share of each subsequent resale (reported as roughly 70% to the publisher, with
the remainder split between the reselling player and the platform). That precedent shows
the mechanism can be proposed and structured; it does not establish that royalties
convert cannibalization into revenue or cause voluntary adoption. The hypothesis for a
deployment is that a resale share may make an issuer more willing to permit transfers;
whether it does is a market question outside this protocol and this annex.

attest's transfer profile (v0.2 §17) is deliberately silent on how, or whether, an
issuer prices a resale, splits a royalty, or structures any such arrangement. What it
supplies is the precondition every such arrangement needs: a verifiable record that a
specific receipt moved from one holder to another, at a specific time, with the outgoing
holder's key authorization and the issuer's cooperation — a signature by the key the issuer
recorded, never consent by the holder (v0.2 §17.3) — and a chain of title a verifier can
audit (v0.2 §17.5). The royalty lever itself — and any pricing, revenue split, or resale-window
policy built on top of that record — is a business decision the protocol makes possible
without making mandatory, prescribed, or even visible: no receipt field records a
royalty, a price, or a split (§4).

## 3. The legal frame

Two CJEU judgments define the legal terrain this profile was designed against, and they
point in different directions for different kinds of works.

**UsedSoft GmbH v. Oracle International Corp. (C-128/11, 3 July 2012).** The Court of
Justice held that a copyright holder's exclusive distribution right in a computer
program is exhausted on first sale of that program or a license to it, regardless of
whether it was supplied by download or on physical media — provided the original
acquirer's own usable copy is made unusable at the time of resale, and a license bundle
is not split into pieces sold separately. For software specifically, EU law can require
a rights holder to tolerate resale: exhaustion under the Software Directive does not
depend on the rights holder's cooperation.

**Nederlands Uitgeversverbond v. Tom Kabinet Internet BV (C-263/18, 19 December 2019).**
The Court declined to extend that reasoning to e-books. It held that supplying an
e-book by permanent download is an act of "communication to the public" under the
InfoSoc Directive (2001/29/EC), not "distribution" of a copy under Article 4 — and the
right of communication to the public does not exhaust. The Court distinguished UsedSoft
expressly: software is governed by its own directive with its own first-sale
jurisprudence; e-books, and by the same reasoning other non-software digital works
(music, film, and comparably delivered content), are not. Absent the rights holder's
authorization, secondary transfer of such a work is an infringement, not an exercise of
a statutory exhaustion right.

Read together, these two judgments are the reason attest's transfer profile is
issuer-mediated by design rather than a general buyer-to-buyer resale right (v0.2 §17,
introductory paragraph; design decision D2). For non-software works, Tom Kabinet means
there is no EU statutory right to resell regardless of what the protocol does — a
transfer happens only where the issuer signs both the extinguishment of the old receipt
and the issuance of the new one, exactly as an issuer that wishes to permit resale, and
only such an issuer, would need. The issuer is the gate, not because the protocol
chooses to make it so, but because for the works this protocol most commonly describes,
EU law already does. For software, where UsedSoft's exhaustion doctrine can apply on its
own stated conditions independent of the vendor's cooperation, the protocol still routes
transfer through the issuer — attest does not adjudicate whether a given sale meets
UsedSoft's conditions, and an issuer-mediated record is required infrastructure for a
verifiable chain of title regardless of which legal theory ultimately entitles a
particular resale.

This is the relationship the `jurisdiction_flags.eu_usedsoft_asserted` field captures
(v0.1 §5.5, registered attest-versioning.md §6.2). It is the issuer's own signed
assertion that a specific sale met the *UsedSoft* conditions — perpetual software license,
fee corresponding to economic value, no license splitting — not a determination this
protocol makes or a fact a verifier can independently check. Transfer-time conditions
(for example, disabling the seller's own copy) are out of receipt scope. Setting it, or `false`, or
omitting it, has no bearing on whether `license.transferable` gates transfer honoring
under §17.8: the schema-level gate is the presence of a non-null `buyer.pubkey`, and
`transferable: false` never overrides a statutory exhaustion right that in fact applies.
The flag exists so that where UsedSoft's conditions genuinely are met, the issuer has
somewhere to say so on the record — and so that where they are not, or where the work is
not software at all, nothing in the schema implies a legal entitlement the issuer never
asserted.

## 4. Explicitly out of scope

The following are deliberately absent from both the transfer profile (v0.2 §17) and this
annex, and no future revision of either is anticipated to add them without a separate
design process of its own:

- **Marketplaces.** attest defines a verifiable record of a transfer an issuer already
  mediated; it defines no listing, discovery, matching, or storefront for finding a
  counterparty to transfer to.
- **Payments.** No defined receipt field, and no defined transfer-record field, carries a
  price, a currency, a payment method, or a transaction reference (attest-privacy.md §2.16). A transfer
  record proves a receipt moved; it says nothing about what, if anything, changed hands
  for it to move.
- **Escrow of funds.** attest holds no funds, defines no escrow mechanism, and is not a
  payment instrument for the underlying sale or any resale (v0.1 §2).
- **Royalty mechanics.** Whether a resale carries a royalty at all, who it is paid to,
  its rate, and how it is collected or enforced are entirely deployment decisions. The
  protocol supplies the verifiable event a royalty arrangement could be conditioned on;
  it implements no such arrangement itself.

An issuer, marketplace, or platform is free to build any of the above around the
transfer records this profile produces. None of it is, or is intended to become, part of
the attest specifications.
