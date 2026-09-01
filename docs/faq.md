# FAQ

Honest answers to the questions people actually asked — collected from a round of
hostile questioning, not invented for the page. Same register as the
[README](../README.md): where the answer is "no," this says why, and what the real
lever is instead.

One rule runs through all of it. Every answer below describes what the shipped code
does today, not what the design permits. Several of them name a gap between the two,
because a document that describes the design and lets you assume it is the product is
how this FAQ got things wrong before.

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
It carries machine-readable rules for revocation, and for transfer where the
seller allows it. And it names you — though what that is worth takes a longer
answer, and it is the next one. Same fact attested. Completely different lifespan.

The obligation this rides on is Article 8(7) of Directive 2011/83/EU: a trader
must confirm a distance contract on a durable medium, and a durable medium is
defined as one that keeps the information accessible for future reference and
lets it be reproduced unchanged. That is why confirmation emails exist at all,
and it is the sentence a regulator would be pointing at.

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
moment: published in the open, with two independent implementations, a
conformance suite and an active IETF draft behind it. The reference code is
Apache-2.0, whose patent grant reaches that code and no further, and the
specification is CC BY 4.0, which states outright that patent rights are not
licensed under it. Nothing here charges a fee to implement attest, and nothing
here is yet a patent commitment to anyone implementing the specification
independently of that code — the documents say what they cover, and stop short
of "royalty-free".

And the open bet is adoption itself. No store signs attest receipts today,
and no regulator mandates them. If that never changes, attest stays a
well-tested spec. The work right now is getting the first DRM-free sellers
signing; everything else follows from there, or not at all.

## If the receipt is just a file, what stops ten people from using the same one?

Nothing stops ten people from *holding* it, and nothing is meant to. The receipt is
a file you are supposed to copy: back it up, mail it to yourself, keep a second copy
on another disk. A receipt that resisted copying would be DRM again, and would fail
for the same reasons DRM fails.

What copying does not hand over is the ability to prove the purchase is *yours*.
When a store exports your receipts you get two files, and only one of them is meant
to leave your hands. The shareable one carries the receipts, the store's key
material and the licence texts, with the binding secret deliberately stripped out.
The other one carries that secret. Someone who copies the shareable file has a
receipt that verifies perfectly and names somebody else.

Now the uncomfortable half, because it is the part that decides how much this is
worth. The secret in the second file is a **bearer** secret. The specification says
so in its own words: disclosing it is "a replayable bearer proof." Whoever holds it
can claim to be the buyer, and once you have shown it to someone, that someone can
show it to a third person and be believed. No cryptography here distinguishes you
from a person you handed your secret to, and nothing expires the proof after one
use. Worth knowing before you ever hand it over: one private file covers your whole
library, so showing it to prove a single purchase proves every purchase in it at
once. That is why `attest disclose <receipt_id>` exists — it shares one receipt and
nothing else.

And the sharper limit, the one that decides real cases: **nothing obliges anyone to
ask.** Whether a receipt verifies and whether it belongs to you are two separate
results, and the first does not depend on the second. A verifier that never requests
the binding proof gains nothing from the two files being separate. So a copied
receipt, presented to somebody who does not ask, looks exactly like the real thing.

There is a stronger path in the standard, and it is implemented: instead of a shared
secret, a key of yours is signed into the receipt, and you prove ownership by
answering a fresh challenge, which cannot be replayed. It is optional, and it needs
software that holds a key on your behalf. Nobody has solved key custody for ordinary
buyers, and this project has not either. Until somebody does, the honest answer to
"what stops them" is: you do, by not handing the private file over.

## Which file can I safely send to someone?

The one **without** `.private.` in its name. If your bundle exported as
`casey-library.attest`, that is the shareable file; `casey-library.private.attest` is
the secret one. A real store or support agent will never need the second — they can
already see your order, and anyone who asks for it is not who they say they are.

Do not reach for a wildcard here, and this is the one piece of shell advice in the
whole page. `*.attest` matches `casey-library.private.attest` as well, because the
private file's name also ends in `.attest`. A command written to share "all my
receipts" that way quietly ships the secret with them. Name the file you mean.

## My cousin says this is pointless — anyone can copy the game anyway.

Your cousin is right about the copying, and stopping it was never attest's job.
attest is content-free by design: it never touches the work, does not host or index
it, and the specification forbids implementations from being built or marketed as a
way around DRM. Preventing copying on a computer somebody else controls is a problem
nobody has solved, and the attempts at it are what produced the mess in the first
place — the licence server that goes dark, the book that stops opening, the film
that leaves the library because a deal expired.

attest answers a different question. Not "who can copy this?" but "who bought this,
and can they still show it once the shop is gone?" DRM's answer to a shutdown is a
dead server. The receipt's answer is a file that keeps verifying without anybody's
permission.

The one place the two touch is integrity, not control. A receipt can list the files
you bought with their sizes and SHA-256 hashes, and `attest check-artifact` hashes a
file on your disk against that list, so you can tell whether the copy you have is the
copy the seller sold. That is a snapshot of what existed at the moment of purchase,
not a live index — and the command is blunt about its own limits: it compares hashes
only, it does not verify the receipt's signature, and it reports the comparison as
unauthenticated. It can tell you the bytes match. It cannot stop you sending them to
anyone.

Nor does the receipt improve a bad deal. It records whether the work was sold
DRM-free or DRM-bound, and a receipt for a DRM-bound work verifies normally with a
`drm-bound` warning attached. The receipt describes what you were sold. It does not
change it.

## What does "verify offline" actually check, and what can't it tell me?

Verification needs two things, and both travel inside the bundle: the receipt bytes
and the issuer's key material. Neither implementation contains an HTTP client at
all — there is no network code in the Python package or the TypeScript verifier, and
the browser verifier never contacts anything. So offline is not a mode you switch on.
It is the only mode there is.

What you get from it is real and permanent: the signature is valid or it is not, the
receipt's shape is valid or it is not. Nothing that happens to the store afterwards
changes either answer. Two independently built implementations — the Python reference
and the TypeScript verifier — agree on every vector in the shared conformance corpus,
which is the evidence that the algorithm is unambiguous rather than one codebase's
private interpretation.

Four things offline verification cannot tell you, and they matter.

**Whether the keys are really that store's.** The specification reserves its strongest
trust level, `verified`, for key material fetched over TLS from the issuer's own
domain. No tool published today performs that fetch — not the command line, not the
browser verifier, not importing a bundle. Every verification you can actually run
reports `unauthenticated_tofu`: trust on first use. The mathematics is exactly as
sound either way; what is absent is anybody confirming who published those keys. If a
stranger sends you a bundle from a shop you have never heard of, a green result is
not evidence that the shop is real.

**Whether it has since been revoked.** With no revocation feed in hand the answer is
`unknown`, and `unknown` does not fail the receipt. A green verdict means "the
signature is genuine and nothing I was shown says otherwise." That is the honest
reading, and it is not the same sentence as "this receipt is valid today." The
browser verifier does not consult a revocation feed at all.

**Whether the feed you do have is stale.** A revocation feed two years out of date is
not flagged as old. The verifier reports the most recent date it found *inside the
feed*, never a comparison against today's clock, and deciding that a feed is too old
to rely on is left to whoever is relying on it.

**Whether the receipt has already been sold on.** A transfer retires the old receipt
through a record that is only honoured when the countersigned transfer evidence is
supplied alongside it — and the packaged `attest verify` command has no option for
supplying that evidence. From the command line, a receipt that has already changed
hands still reports as valid. Reading that case correctly today means writing code
against the library rather than running the tool.

## Who can revoke my receipt, and what would I see?

The store that issued it, and only within limits the receipt itself fixes. Every
receipt carries a revocability class chosen at the moment of sale and sealed inside
the signed payload, so it cannot be widened afterwards.

`none` means irrevocable, and the verifier enforces it rather than trusting anyone to
behave: a perfectly valid revocation record aimed at a `none` receipt is refused, a
warning says so out loud, and the receipt stays good. A receipt may only claim `none`
if the work was sold DRM-free and carried a redownload right.

`refund_window` means revocable for a fixed number of days after issue. The verifier
checks the record's own signed timestamp against that window — never your computer's
clock, which the buyer or the seller could set to anything. A record that arrives
after the window is ignored.

`policy` means revocable under whatever terms the receipt points at. Here the verifier
does not read those terms and cannot judge them; it checks the store's signature and
reports the receipt as revoked.

What you see is one of a small set of words: `unknown`, `not_revoked_as_of` with a
date, `revoked`, `transferred`, or `invalid_revocation_ignored` for a record that
matched your receipt but was refused. Only `revoked` and `transferred` make a receipt
fail.

Two things the protocol does not give you. There is **no appeal**: no dispute step,
no arbitration, no contest. A revocation record states what happened and never why,
and the only remedy written down anywhere is that the issuer *should* re-issue — a
recommendation to them, not a right you can exercise. And revocation does not reach
your disk. A DRM-free game you already downloaded is byte-for-byte the same file the
day after its receipt is revoked. What changed is what a verifier will say about the
licence, not what you are holding.

## I lost the file. What happens?

Two different losses, and they are not the same size.

**You lost the private file but still have the receipt.** The receipt keeps verifying,
because proving it is yours was never part of the verdict. What you lose is
exclusivity: from that point on, anyone else holding a copy of that receipt is no less
able to present it than you are.

**You lost the receipt itself.** Then, honestly: nothing in the protocol brings it
back. There is no backup service, no escrow, no recovery scheme, and the threat model
says so in as many words — buyer-secret custody after delivery is listed as out of
scope, with no backup, escrow, rotation or recovery mechanism defined. If the store is
still alive you can ask them to issue a fresh one; the standard has a field for
pointing a new receipt at the one it replaces, and it recommends that issuers do this
after a loss. It is a recommendation and a commercial favour, not a right, and no
command performs it: a human at the store decides. If the store is gone, the receipt
is gone, and the threat model's verdict on that case is two words: out of scope.

Which makes the practical advice dull, and it really is the whole of it. The receipt
is a small file. Keep more than one copy, in more than one place, the way you would
with a photograph you cannot take again.

One case deserves its own warning, because there the loss is silent until the moment
it matters. The preservation pledge — the licence term that lets an archive hand your
file back after the publisher stops distributing — can only be redeemed by signing a
fresh challenge with a key named inside the receipt. Disclosing the salt is
*normatively forbidden* as redemption proof, and a receipt cannot carry a pledge at
all unless it names such a key. So a receipt bound only to your email address cannot
carry a pledge and cannot redeem one, and whoever inherits your receipts inherits that
limit: without the key, the pledge does not fire for them. The only fix is to be
re-issued with a key while the issuer is still there to do it.

## Can I sell what I bought, or pass it on?

Sometimes, and never without the seller in the room. Transfer is real, shipped code
and has been since version 0.4.0 — this page used to say it was reserved and not
implemented, which was true once and then quietly stopped being true.

The shape of it: you sign an authorization naming the receipt, the new holder's key
and the moment; the issuer verifies your signature and countersigns a transfer record;
the old receipt is retired by a record on the revocation feed that is honoured only
when it is backed by that countersigned transfer and the transfer appears in the
issuer's public log. Your consent is what makes the retirement legitimate — it is the
only thing that can retire even an irrevocable receipt, which is why it is required
rather than polite.

Every one of those steps is somewhere it can stop. The issuer's countersignature is
structural, not a courtesy: no path in the code completes a transfer without it, there
is no timeout after which you can finish alone, and there is no successor to ask. An
issuer may refuse, may charge for the privilege, and when the issuer is gone transfers
stop with them — making that authority outlive the seller is on the roadmap and is not
written yet. It also only works for receipts that name a key of yours: a receipt bound
only to an email address cannot be transferred whatever its `transferable` flag says,
because the key, not the flag, is the gate the verifier actually applies.

There is no private, seller-free resale, and that is a decision rather than a missing
feature. Handing your bundle to somebody is not a transfer: you keep exactly the
ability to prove the receipt is yours that you had before, so the person paying you
receives nothing exclusive. The legal ground runs the same direction — for e-books and
most works that are not software, EU case law does not treat a digital sale as
exhausting the rights holder's control, so a resale without their cooperation is not a
right this protocol could grant even if the code allowed it.

One thing a receipt does not do is settle the law. It can carry the seller's assertion
that a particular sale met the conditions for statutory resale in some jurisdiction.
That is an assertion, signed by the seller, that no verifier checks — the reference
implementation does not so much as read the field.

## Why not blockchain / NFT?

Because the problem doesn't need one. A signed receipt held by the buyer and
checkable offline requires no consensus mechanism, no token, and no chain — a
verifier just checks a signature against a key the issuer published. Consensus
exists to solve double-spend and ordering among mutually distrusting parties
maintaining a shared ledger; a buyer proving they hold a receipt to a verifier
they choose is a different, simpler problem.

There is a transparency layer, and it is worth being precise about what it is,
because "append-only log" and "blockchain" get used interchangeably and they are not
the same thing. v0.2 adds an optional Merkle-tree transparency log (the C2SP
tlog-tiles format, served as static files) plus timestamp anchoring. No consensus, no
token, no miners, no shared ledger between distrusting parties — the same family of
construction used for TLS certificate transparency.

It **corroborates**, it never authenticates. What a verifier checks is a log-signed
checkpoint plus an inclusion proof, showing the artifact is in that log's Merkle tree;
an anchor can further bound when the checkpoint existed. It can never make an unsigned
or untrusted receipt look genuine — the trust result stays domain control, and
inclusion evidence is reported separately so the two are never confused.

And the honest answer to "so who audits the log?" is that **witness cosignatures are
not anti-equivocation**. An unwitnessed operator can serve one view to you and a
different one to somebody else and stay internally consistent in both; a verifier
catches that only if it already holds two conflicting validly-signed checkpoints. The
verdict `corroboration: "witnessed"` is reachable — one cosignature from a witness you
have pinned yourself is enough to emit it — but what it says is that a second party
saw a given head at a given time, not that the party is independent of the log and not
that no second branch exists. Every witnessed result carries
`witness_independence_not_established` for that reason. What is missing is not the
format but the operators: no independently run witness is published today, and the
witness policy shipped inside the verifier packages is deliberately empty, so
`witnessed` stays out of reach until you pin a policy of your own.

None of which is load-bearing for the core promise: a receipt verifies offline from
its bytes and the issuer's key material, with no log reachable, exactly as before.

## Then why does Bitcoin turn up at all?

Because of a hole that only a clock can fill, and it takes a paragraph to see it.

Every date inside a receipt is a date the seller typed. A signature proves who wrote
something; it never proves when. That is harmless right up to the day a store
announces that its signing key was stolen. The only safe response to a stolen key is
to stop trusting everything it ever signed — and everything it ever signed includes
your receipt. You would like to say "mine came before the theft." You cannot, because
the only record of when it was made is a line the store wrote itself.

What settles that argument is a clock neither side controls and neither side can wind
back. Bitcoin is used as exactly that, and as nothing else. No money moves, no token
is created, and nothing about your purchase is published anywhere: a short fingerprint
of a public log entry is folded, through OpenTimestamps, into the arithmetic of a
Bitcoin block. Because those blocks are dated and ruinously expensive to rewrite, the
block works as a receipt for "this already existed by then." Your verifier re-does
that arithmetic against a short list of block summaries it already has on disk. It
never asks Bitcoin anything; there is no network step, and there is nothing to keep
alive.

Now the honest part, and it is large. **As things ship today, nothing is anchored.**
The list of block summaries in the browser verifier is empty. Both libraries default
to no anchoring policy at all, which means the rescue is switched off and a key
declared compromised sinks every receipt it signed, without exception. Issuing a
receipt has no anchoring option; putting one in a log and anchoring it is a separate
sequence of commands, with the timestamp itself obtained from tools outside this
project. So "anchor what you buy" is advice almost nobody can currently follow. The
mechanism is specified and exercised by the conformance suite. It is not yet a
protection real buyers have — and until it is, the limit stated in the next answer is
the plain truth about how far "forever" reaches.

## The store that signed my receipts is gone. What do I actually do with them?

Two cases, and they're different.

You have the file, because the store sold DRM-free and you downloaded it.
Then the content is already yours, and the receipt keeps doing its job: it
verifies offline against the store's published keys, with nobody's
permission, and it proves to anyone who needs to know — a successor honoring
old purchases, an archive authorized to serve them, a buyer if resale was
authorized — that your copy is legitimate. The project's own demo deletes a
store's entire infrastructure mid-lifecycle and shows the receipt verifying
afterwards. What changes is the trust level reported alongside that result:
with no live key material to confirm provenance, verification degrades from
`verified` to `unauthenticated_tofu` rather than failing outright or claiming a
level it cannot back up — and since no shipped tool reaches `verified` in the
first place, that degradation costs you less than it sounds like.

Two limits, both named. Transfers are countersigned by the issuer, so today they stop
when the issuer does; making them survive has a name too, transfer-authority
succession, and it is on the roadmap rather than in the code. And "forever" holds
against the store disappearing, not against a live store declaring its own signing key
compromised: that declaration still destroys receipts that were never logged and
anchored before it. A receipt anchored before the declaration survives it — but see
the previous answer for how little anchoring is switched on today. So the rule on any
DRM-free store is simple and unglamorous: download what you buy, and keep the file
next to the receipt. Content plus proof, both in your hands.

You don't have the file. Then the receipt alone doesn't bring it back. It proves you
bought the thing; it isn't the thing, and no signature can conjure a file out of a
dead server. What closes this gap is the Preservation Pledge: a licence term the
publisher signs at the moment of sale, committing that when they cease distribution
the content becomes redistributable to valid receipt holders. It is not a sketch — it
is specified in v0.2, implemented in both packages with its own commands, covered by
the conformance corpus, and `python -m demo.pledge_dies` runs the whole sequence
end to end on your machine: pledge signed, publisher dies, trigger fires, archive
hands the file back to somebody who can prove the receipt is theirs, and to nobody
else. What is missing is not the mechanism. It is a publisher who has signed one, an
archive that holds anything, and licence prose written by a lawyer rather than the
placeholder the demo carries.

Two holes stay open, and both are worth knowing before you rely on it. A publisher
that vanishes silently — signing nothing, naming no successor, setting no backstop
date — leaves the pledge dormant forever; the threat model calls that the largest risk
this feature carries. And the pledge can only be redeemed with a key, so a receipt
bound only to an email address is outside it entirely, as the earlier answer about
losing the file explains.

## Is this centralized?

No. There is no central attest authority, no registry that must exist, and no
phone-home. A verifier needs only three things to check a receipt: the receipt
bytes, the issuer's published key material, and, optionally, a revocation feed.
None of those requires a server attest itself operates — the issuer publishes its
own keys, and a future registry layer for replicating verification material is
explicitly optional.

The honest caveat is about practice rather than protocol. A verifier that wanted the
stronger evidence — pinned log keys, a witness policy, Bitcoin block summaries — would
need somebody to curate and publish those pins, and curation is a soft centre even
when the protocol has no centre. Today the question has not bitten, for the plain
reason that the shipped verifiers pin none of them.

## Does this save my existing Steam / PlayStation / Kindle library?

No. Be clear about why: attest verifies a receipt that a store *chooses to sign*.
It cannot retroactively produce a valid signed receipt for a past purchase made
on a platform that never signs anything, and it cannot forge one for a store
that refuses to participate — that would break the entire cryptographic premise
the standard is built on. Existing libraries stay exactly as revocable as they
are today until the store that holds them decides to issue attest receipts for
them.

The lever for an unwilling incumbent isn't a workaround — it's regulation and market
pressure: disclosure laws already on the books (California's AB 2426, Maryland's
HB 208), and, in the EU, a conversation that has only just been agreed to. Responding
to the *Stop Destroying Videogames* citizens' initiative, the Commission declined to
propose binding obligations and committed instead to opening a discussion with the
industry, by the end of 2026, about a voluntary code of conduct. What is due by then is
the start of that discussion, not a code — and a voluntary code is a weaker instrument
than the framing it is often given. attest is the technical standard those pressures
could point an incumbent toward adopting; it is not a way around an incumbent that
declines.

## Is attest a DRM system, a store, or a way to pirate games?

None of those. attest is content-free: a receipt is evidence that a licence was
granted, and it never touches, wraps, hosts, or indexes the underlying work. It
doesn't strip or bypass DRM — the specification forbids that outright — and it isn't a
marketplace or a distribution channel. It supports transfer, but only where the issuer
mediates it, as the resale answer above sets out. Holding a valid attest receipt says
one thing and no more: that an issuer signed a claim that a licence was granted. It
carries no copy of the work and grants access to none.
