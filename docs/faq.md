# FAQ

Honest answers to the questions a skeptical first visitor asks. Same register as
the [README](../README.md): where the answer is "no," this says why, and what the
real lever is instead.

## What is attest?

A way to hold on to what you buy digitally. When you buy a game, a movie, an
album or a book, the seller signs a receipt at checkout and hands it to you
as a small file. That file is yours. Keep it on your disk, in cloud
storage, on a USB stick. Anyone can check it's genuine without asking the seller: the
check runs offline, on your own machine, and it keeps working after the store
shuts down or your account disappears.

Today this works where sellers ship DRM-free files and choose to sign —
think GOG-style stores, itch.io, publishers selling directly. The longer-term
aim is that closed platforms hand you one too. In the EU, sellers are
already required to confirm every purchase on a durable medium — that's the
receipt email in your inbox. attest is that same confirmation in a format a
machine can verify and you can take with you. No
store issues attest receipts yet. The standard, the tools and the test suite
are done and free to use; what's missing is the first seller who signs.

## How is this different from the receipt I already get by email?

The email attests the same thing. The difference is who can verify it, and when.

That confirmation email is a PDF anyone can forge in five minutes. It lives in
an inbox, or behind the very account you're worried about losing. Every store
formats it differently, so no machine can rely on it. And if you need to prove
it's real twenty years from now, you need the store alive to ask — or a human
willing to weigh the evidence for you.

An attest receipt is signed with the seller's cryptographic key: faking one
means breaking the signature, not editing a document. It's one standard
format, so one free verifier works for every store that signs. Anyone can
check it offline, on their own machine, trusting nobody and contacting nobody.
It's bound to you: someone who copies your receipt can't prove it's theirs.
And it carries machine-readable rules for revocation, and for transfer where
the seller allows it. Same fact attested. Completely different lifespan.

## Nobody forces a seller to adopt this. So what's the point?

Nobody forces them, true. That's why there are two routes, and neither is a
fantasy.

For a DRM-free seller, the cost is close to zero and the reason is
commercial. attest-bridge runs as one small self-hosted service next to the
existing checkout — Stripe, itch.io or Shopify today — and turns every paid
order into a signed receipt, automatically. What the seller gets for that is
trust: "what you buy from me stays yours, even if I disappear" is a selling
argument, the same one GOG built a whole brand on. An independent publisher
can offer this tomorrow, and nobody can stop them.

For everyone who won't sign voluntarily, the route is legal, not technical.
EU law already obliges every online seller to confirm your purchase on a
durable medium; that's why confirmation emails exist at all. attest is that
same confirmation in a format a machine can verify and you can carry away. A
regulator doesn't have to invent a new obligation, only require a usable
format for one that already exists. The standard is written for exactly that
moment: open and royalty-free, with two independent implementations, a
conformance suite and an active IETF draft behind it.

And the open bet is adoption itself. No store signs attest receipts today,
and no regulator mandates them. If that never changes, attest stays a
well-tested spec. The work right now is getting the first DRM-free sellers
signing; everything else follows from there, or not at all.

## The store that signed my receipts shut down years ago. What do I actually do with them?

Two cases, and they're different.

You have the file, because the store sold DRM-free and you downloaded it.
Then the content is already yours, and the receipt keeps doing its job: it
verifies offline against the store's published keys, forever, with nobody's
permission, and it proves to anyone who needs to know — a successor honoring
old purchases, an archive authorized to serve them, a buyer if resale was
authorized — that your copy is legitimate. Two limits, both named. Transfers are
countersigned by the issuer, so today they stop when the issuer does; making
them survive the issuer has a name too, transfer-authority succession, and
it's on the roadmap. And "forever" holds against the store disappearing, not
against the store declaring its own signing key compromised: that declaration
still destroys receipts that were never logged and anchored. A receipt whose
signature was anchored in a public log before the store's own compromise
declaration was anchored survives it — that one the store cannot take back.
Anchor what you buy, and the second limit stops applying to you. So the rule on any DRM-free store is simple: download
what you buy, and keep the file next to the receipt. Content plus proof, both
in your hands.

You don't have the file. Then the receipt alone doesn't bring it back. It
proves you bought the thing; it isn't the thing, and no signature can conjure
a file out of a dead server. What closes this gap is the Preservation Pledge,
the piece of the standard in design right now: a license term the publisher
signs at the moment of sale, committing that when they cease distribution the
content becomes redistributable to valid receipt holders. The pledge
activates on a signed end-of-life declaration from the publisher or from a
successor they named, or when a backstop date passes. From that moment, any
archive holding the content can hand you your copy against your receipt. One
hole stays open: a publisher that vanishes silently, never having named a
successor or a date. That case is tracked as an open problem in the threat
model, and only a witnessed heartbeat scheme will close it.

## Is this centralized?

No. There is no central attest authority, no registry that must exist, and no
phone-home. A verifier needs only three things to check a receipt: the receipt
bytes, the issuer's published key material, and, optionally, a revocation feed.
None of those requires a server attest itself operates — the issuer publishes its
own keys, and a future registry layer for replicating verification material is
explicitly optional (see the roadmap in the README).

## Where is my license / receipt stored?

The buyer holds it. At checkout the store signs a receipt and hands over an
`.attest` bundle — a small file the buyer keeps anywhere: local disk, cloud
storage, a USB drive, wherever. It is not locked inside a platform's account
system, and there is nothing to keep synced or alive for the receipt to still be
checkable later.

## Who validates it?

Anyone, offline. Validation is a signature check plus the layered verification
algorithm in the spec (§11): resolve the issuer's key material, check the
signature and canonicalization, then layer in trust provenance and any
revocation status. Two independent implementations — a Python reference
implementation and a TypeScript verifier, built separately — already agree on
every conformance vector, which is strong evidence that the algorithm itself is
unambiguous rather than tied to one codebase's interpretation.

## Does this save my existing Steam / PlayStation / Kindle library?

No. Be clear about why: attest verifies a receipt that a store *chooses to sign*.
It cannot retroactively produce a valid signed receipt for a past purchase made
on a platform that never signs anything, and it cannot forge one for a store
that refuses to participate — that would break the entire cryptographic premise
the standard is built on. Existing libraries stay exactly as revocable as they
are today until the store that holds them decides to issue attest receipts for
them. The lever for an unwilling incumbent isn't a workaround — it's regulation
and market pressure: disclosure laws already on the books (California's AB 2426,
Maryland's HB 208) and forums like the EU's end-of-life industry code of conduct
due by the end of 2026. attest is the technical standard those pressures could
point an incumbent toward adopting; it is not a way around an incumbent that
declines.

## Why not blockchain / NFT?

Because the problem doesn't need one. A signed receipt held by the buyer and
checkable offline requires no consensus mechanism, no token, and no chain — a
verifier just checks a signature against a key the issuer published. Consensus
exists to solve double-spend and ordering among mutually distrusting parties
maintaining a shared ledger; a buyer proving they hold a receipt to a verifier
they choose is a different, simpler problem.

There is now a transparency layer, and it is worth being precise about what it
is, because "append-only log" and "blockchain" get used interchangeably and they
are not the same thing. v0.2 Stage 2 adds an optional Merkle-tree transparency
log (the C2SP tlog-tiles format, served as static files) plus timestamp
anchoring. No consensus, no token, no miners, no shared ledger between
distrusting parties — the same family of construction used for TLS certificate
transparency.

It **corroborates**, it never authenticates. What a verifier checks is a
log-signed checkpoint plus an inclusion proof, which shows the artifact is in
that log's Merkle tree; an anchor can further bound when the checkpoint existed.
It can never make an unsigned or untrusted receipt look genuine — the trust
result stays domain control, and inclusion evidence is reported separately so the
two are never confused.

And it is worth being equally precise about the limit, because it is the honest
answer to "so who audits the log?": **witness cosignatures are not
anti-equivocation**. An unwitnessed operator can serve one view to you and a
different one to someone else and stay internally consistent in both; a verifier
catches that only if it already holds two conflicting validly-signed checkpoints.
Since v0.2 revision 7 the verdict `corroboration: "witnessed"` is reachable — one
cosignature from a witness you have pinned yourself is enough to emit it — but
what it says is that a second party saw a given head at a given time, not that
the party is independent of the log and not that no second branch exists. Every
witnessed result carries `witness_independence_not_established` for that reason.
What is missing now is not the format but the operators: no independently run
witness is published today, and the witness policy shipped inside the verifier
packages is deliberately empty, so `witnessed` stays out of reach until you pin
a policy of your own. The spec states this in its own scope section rather than
burying it.

None of which is load-bearing for the core promise: a receipt verifies offline
from its bytes and the issuer's key material, with no log reachable, exactly as
before.

## What happens if the issuer dies?

The receipt still verifies, straight from the buyer-held bundle — the project's
own demo deletes a store's entire infrastructure mid-lifecycle and shows the
receipt verifying anyway. What changes is the trust level reported alongside
that result: without the issuer's live key material to independently confirm
provenance over TLS, verification degrades gracefully from `verified` to
`unauthenticated_tofu` (trust-on-first-use) rather than failing outright or
silently claiming a trust level it can't back up. A future registry layer could
replicate verification material to keep more receipts at full `verified` trust
after an issuer disappears, but nothing in the spec's conformance requirements
depends on such a registry existing.

## Is attest a DRM system, a store, or a way to pirate games?

None of those. attest is content-free: a receipt is evidence that a license was
granted, and it never touches, wraps, hosts, or indexes the underlying work
itself. It doesn't strip or bypass DRM, and it isn't a marketplace or
distribution channel. It does support transfer, but only issuer-mediated: a
signed transfer moves a receipt to a new holder with the issuer's
countersignature, and today that stops working once the issuer is gone —
making the transfer authority survive the issuer is unfinished work
(transfer-authority succession, tracked on the roadmap). Having a valid attest
receipt says only that an issuer signed a claim that a license was granted — it
carries no copy of the work and grants no access to one.
