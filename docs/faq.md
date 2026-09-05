# FAQ

Answers to the questions people actually asked, in the order they tend to ask them.
Same register as the [README](../README.md): where the answer is "no," this says why,
and what the real lever is instead.

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
aim is that closed platforms hand you one too. No store issues attest receipts
yet. The standard, the tools and the test suite are done and free to use;
what's missing is the first seller who signs.

## How is this different from the receipt I already get by email?

The email attests the same thing. The difference is who can verify it, and when.

That confirmation email is a PDF anyone can forge in five minutes. It lives in
an inbox, or behind the very account you're worried about losing. Every store
formats it differently, so no machine can rely on it. And if you need to prove
it's real twenty years from now, you need the store alive to ask — or a human
willing to weigh the evidence for you.

An attest receipt is signed with a cryptographic key named for the seller: editing
its signed contents without that key breaks the signature. It uses one standard
format, so one free verifier works for every store that signs. Anyone can perform
that check offline, without contacting the seller. The check does not by itself
authenticate the supplied key as belonging to that seller: every shipped tool reports
TOFU rather than verified domain provenance, as the offline-verification answer below
explains. It carries machine-readable rules for revocation, and for transfer where
the seller allows it. And it carries a commitment to an identifier the seller
recorded — sealed into the receipt rather than written in the clear — though what
that binding is worth takes a longer answer, and it is the next one. Same fact
attested. Completely different lifespan.

## If the receipt is just a file, what stops ten people from using the same one?

Nothing stops ten people from holding the shareable file, and nothing is meant to.
All ten copies verify identically: buyer binding is reported separately and is not
a component of `ok`. The receipt is a file you are supposed to copy: back it up,
mail it to yourself, keep a second copy on another disk. A receipt that resisted
copying would be DRM again, and would fail for the same reasons DRM fails.

What copying does not hand over is the ability to show you hold the receipt's binding
secret.
When a store exports your receipts you get two files, and only one of them is meant
to leave your hands. The shareable one carries the receipts, the store's key
material and the licence texts, with the binding secret stripped from every receipt
inside it. The other file carries that secret. Someone who copies the shareable file
has a receipt that verifies perfectly and, if anyone asks, cannot produce that
secret.

Now the uncomfortable half, because it is the part that decides how much this is
worth. The secret in the second file is a bearer secret. The specification says so in
its own words: revealing it is "a replayable bearer proof." Whoever holds it can
reproduce the same binding result, and once you have shown it to someone, that person
can reproduce that result for a third party. The result proves possession of the
secret, not buyer status. No cryptography here distinguishes you from a person you
handed your secret to, and nothing expires the proof after one use. One private file
covers your whole library, so showing it for one receipt exposes the binding secret
for every receipt in the private bundle at once. That is why `attest disclose
<receipt_id>` exists: it shares one receipt, with its own salt, and nothing else.

And the sharper limit, the one that decides real cases: nothing obliges anyone to
ask. Whether a receipt verifies and whether anyone has checked its binding are two
separate results, and the first does not depend on the second. A verifier that never
requests the binding proof gains nothing from the two files being separate. So a
copied receipt, presented to somebody who does not ask, looks exactly like the real
thing. Custody distinguishes a presenter who can answer the binding check from one
who cannot; it does not distinguish the real buyer from an issuer or another holder
of the secret.

There is a stronger path in the standard, and it is implemented: instead of a shared
secret, a public key is signed into the receipt, and you show you hold the matching
private one by signing a challenge the verifier just invented, so a recorded answer
is no use to anyone later. Three things keep it from being the answer today. It is
optional, and the key is absent by default: a receipt from a checkout with no client
software carries no key at all. It needs software that holds a key on your behalf,
which nobody has solved for ordinary buyers, this project included. And the seller is
the one who writes that key into the receipt, along with the identifier, so answering
the challenge shows who holds the binding secret the seller recorded — not that the
seller recorded the person who actually bought. The library also checks only the
signature on the challenge; making sure each challenge is fresh is the verifier's
own job. Until that path is the ordinary one, the honest answer to "what stops them"
is: you do, by not handing the private file over.

## Which file can I safely send to someone?

The one **without** `.private.` in its name. If your bundle exported as
`casey-library.attest`, that is the shareable file; `casey-library.private.attest` is
the secret one. A real store or support agent will never need the second — they can
already see your order.

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

attest answers a different question. Not "who can copy this?" but "what did the
seller sign, and can that evidence still be checked once the shop is gone?" DRM's
answer to a shutdown is a dead server. The receipt's answer is a file that keeps
verifying without anybody's permission.

The one place the two touch is integrity, not control. A receipt can list the files
you bought with their sizes and SHA-256 hashes, and `attest check-artifact` hashes a
file on your disk against that list, so you can tell whether the copy you have is the
copy the seller sold. That is a snapshot of what existed at the moment of purchase,
not a live index, and the command says on every run that it has compared hashes only
and has not verified the receipt's signature. It can tell you the bytes match. It
cannot stop you sending them to anyone.

Nor does the receipt improve a bad deal. It records whether the work was sold
DRM-free or DRM-bound, and a receipt for a DRM-bound work verifies normally with a
warning attached. The receipt describes what you were sold. It does not change it.

## Nobody forces a seller to adopt this. So what's the point?

Nobody forces them, true, and nothing here could. What the protocol offers is
a single route, open only to sellers who already have a reason to take it.

For a DRM-free seller the cost is one small service to run and one signing key to
keep — this project has not measured it more closely than that, so this page puts no
figure on it — and the reason is commercial. The service is `attest-bridge`. It runs
self-hosted next to the existing checkout — Stripe, itch.io or Shopify — and signs a
receipt when the platform confirms a paid order; the key it signs with stays where
the seller runs it. It is not published: its package metadata is marked
`Private :: Do Not Upload`, and its own setup guide says never to run
`pip install attest-bridge`, because that name could resolve to something unrelated.
You clone the repository and install from that clone with `pip install ./bridge`; the
[page for sellers](https://attest-receipts.org/for-sellers.html) walks through the
rest. What the seller gets for that is trust: "what you buy from me stays yours, even
if I disappear" is a selling argument, the same one GOG built a whole brand on. Any
independent publisher can do that today, without asking anyone's permission. None
has yet.

For everyone who will not sign voluntarily, there is no technical mechanism
here that compels adoption. Any regulatory route is external to the protocol.
The standard is published in the open, with two independent implementations,
a conformance suite and an active IETF draft behind it. The reference code is
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

## What does "verify offline" actually check, and what can't it tell me?

Verification needs two things, and both travel inside the bundle: the receipt bytes
and the issuer's key material. Neither implementation contains an HTTP client —
there is no network code in the Python package or the TypeScript verifier, and the
browser verifier fetches nothing beyond its own demo sample from its own site. So
offline is not a mode you switch on. It is the only mode there is.

With the same receipt bytes and the same local verification material, the signature
and schema checks are reproducible. A later trusted manifest can change the signing
key's status and therefore change the signature verdict, so the result is not
immutable with respect to every future input. The Python and TypeScript
implementations were built separately and are both exercised against the same shared
conformance corpus. Anyone can run the verifier; nobody has to be asked.

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
browser verifier does not consult a revocation feed at all, so on that page the
revocation answer is always `unknown`.

**Whether the feed you do have is stale.** A revocation feed two years out of date is
not flagged as old. The verifier reports the most recent date it found inside the
feed, never a comparison against today's clock, and deciding that a feed is too old
to rely on is left to whoever is relying on it.

**Whether the receipt has already been sold on.** A transfer retires the old receipt
through a record that is honoured only when the countersigned transfer evidence is
supplied alongside it, and the packaged `attest verify` command has no option for
supplying that evidence. From the command line, a receipt that has already changed
hands still reports as valid. Reading that case correctly today means writing code
against the library rather than running the tool.

## Who can revoke my receipt, and what would I see?

The store that issued it, and only within limits the receipt itself fixes. Every
receipt carries a revocability class chosen at the moment of sale and sealed inside
the signed payload, so it cannot be widened afterwards.

`none` means irrevocable, and the verifier enforces it rather than trusting anyone to
behave: a correctly signed revocation record aimed at a `none` receipt is refused, a
warning says so, and the receipt stays good. A receipt may only claim `none` if the
work was sold DRM-free, carried a redownload right, and lists what was delivered.

`refund_window` means revocable for a fixed number of days after issue. The verifier
checks the record's own signed timestamp against that window — never your computer's
clock, which the buyer or the seller could set to anything. A record whose signed
time falls after the window is ignored with a warning.

`policy` means revocable under whatever terms the receipt points at. Here the verifier
does not read those terms and cannot judge them; it checks the store's signature and
reports the receipt as revoked.

What you see is one of a small set of words: `unknown`, `not_revoked_as_of` with a
date, `revoked`, `transferred`, or `invalid_revocation_ignored` for a record that
matched your receipt but was refused. Those words describe the revocation component:
`revoked` and `transferred` directly cap `ok`, but the overall receipt can also fail
because its signature or schema is invalid, or because verification reported another
error.

Two things the protocol does not give you. There is no appeal: no dispute step, no
arbitration, no contest. A revocation record states what happened and never why, and
the only remedy written down anywhere is that the issuer *should* re-issue — a
recommendation to them, not a right you can exercise. And revocation does not reach
your disk. A DRM-free game you already downloaded is byte-for-byte the same file the
day after its receipt is revoked. What changed is what a verifier will say about the
licence, not what you are holding.

Revocation is also not the only way a receipt stops verifying. A store declaring its
own signing key compromised is a different mechanism with a different reach, and the
answer about Bitcoin below is where that case lives.

## I lost the file. What happens?

Two different losses, and they are not the same size.

**You lost the private file but still have the receipt.** The receipt keeps verifying,
because proving it is yours was never part of the verdict. What you lose is
exclusivity: from that point on, anyone else holding a copy of that receipt is no less
able to present it than you are.

**You lost the receipt itself.** Then nothing in the protocol brings it back. There is
no backup service, no escrow, no recovery scheme, and the threat model says so in as
many words: buyer-secret custody after delivery is out of scope, with no backup,
escrow, rotation or recovery mechanism defined. If the store is still alive you can
ask them to issue a fresh receipt; the standard has a field for pointing a new
receipt at the one it replaces, and it names re-issue as the only remedy for a loss.
It is a recommendation to the store and a commercial favour, not a right, and no
command performs it: a human at the store decides. If the store is gone, the receipt
is gone, and the threat model's verdict on that case is two words: out of scope.

Which makes the practical advice dull, and it really is the whole of it. The receipt
is a small file. Keep more than one copy, in more than one place, the way you would
with a photograph you cannot take again.

One case deserves its own warning, because there the loss is silent until the moment
it matters. The preservation pledge — the licence term that lets an archive hand your
file back after the publisher stops distributing — can only be redeemed by signing a
fresh challenge with a key named inside the receipt. Disclosing the salt is forbidden
as redemption proof, as a rule and not a recommendation, and a receipt cannot carry a
pledge at all unless it names such a key. So a receipt bound only to your email
address cannot carry a pledge. Whoever inherits a pledge-bearing receipt without its
corresponding private key cannot redeem the pledge after it activates. The only fix
is to be re-issued with a key while the issuer is still there to do it.

## Can I sell what I bought, or pass it on?

Sometimes, and never without the seller in the room. Transfer is shipped code and has
been since version 0.4.0; this page used to say it was reserved and not implemented,
which was true once and then stopped being true without the page noticing.

The shape of it: a signature made by the private key corresponding to the old receipt's
`buyer.pubkey` authorizes a transfer record naming the receipt, the new key and the
moment; the issuer verifies that signature and countersigns; the old receipt is
retired only when the transfer is also logged. This proves control of the
issuer-recorded key, not consent by the person who bought. The issuer may have minted
that key itself, so the gate is exactly as strong as the key provenance described in
v0.1 §8 and TM-78.

Every one of those steps is somewhere it can stop. The issuer's countersignature is
structural, not a courtesy: no path in the code completes a transfer without it, there
is no timeout after which you can finish alone, and there is no successor to ask. An
issuer may refuse, may charge for it, and an issuer that runs no transparency log
cannot mediate a transfer at all, because the log is where the evidence has to live.
When the issuer is gone, transfers stop with them; transfer authority that outlives
the seller is on the roadmap, as the README says, and is not written. It also only
works for receipts that name a non-null key recorded by the issuer: a receipt bound
only to an email address
cannot be transferred whatever its `transferable` flag says, because the key, not the
flag, is the gate the verifier actually applies.

There is no private, seller-free resale, and that is a decision rather than a
missing feature. Handing your bundle to somebody is not a transfer: you keep
exactly the ability to answer the receipt's binding proof that you had before, so the
person paying you receives nothing exclusive. The protocol defines an
issuer-mediated transfer path; it does not create a seller-free resale right.

One thing a receipt does not do is settle the law. It can carry the seller's assertion
that a particular sale met the conditions for statutory resale in some jurisdiction.
Neither verifier determines whether that assertion is legally correct: both validate
`jurisdiction_flags` only as an object whose values are booleans, as part of ordinary
schema validation.

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

## Then why does Bitcoin turn up at all?

Because of a hole that only a clock can fill, and it takes a paragraph to see it.

Every date inside a receipt is a date the seller typed. A signature proves who wrote
something; it never proves when. That is harmless right up to the day a store
announces that its signing key was stolen. The only safe response to a stolen key is
to stop trusting everything it ever signed, and everything it ever signed includes
your receipt. You would like to say "mine came before the theft." You cannot, because
the only record of when it was made is a line the store wrote itself.

What settles that argument is a clock neither side controls and neither side can wind
back. Bitcoin is used as exactly that, and as nothing else. No money moves, no token
is created, and nothing about your purchase is published anywhere: a short fingerprint
of a public log entry is folded, through OpenTimestamps, into the arithmetic of a
Bitcoin block. Because those blocks are dated and expensive to rewrite, the block
works as a receipt for "this already existed by then." Your verifier re-does that
arithmetic against a short list of block summaries it already has on disk. It never
asks Bitcoin anything; there is no network step, and there is nothing to keep alive.

Now the part that limits it, and it is large. As things ship today, nothing is
anchored, and not even this project's own verifier has the clock switched on. The
list of block summaries in the browser verifier is empty. Both libraries default to
no anchoring policy at all, and with no policy the rescue is off: a key declared
compromised sinks every receipt it signed, without exception. Issuing a receipt has
no anchoring option; putting one in a log and anchoring it is a separate sequence of
commands, with the timestamp itself obtained from tools outside this project. So
"anchor what you buy" is advice almost nobody can currently follow. The mechanism is
specified and exercised by the conformance suite. It is not yet a protection real
buyers have, and until it is, the limit stated in the next answer is the plain truth
about how far "forever" reaches.

## The store that signed my receipts is gone. What do I actually do with them?

Two cases, and they're different.

You have the file, because the store sold DRM-free and you downloaded it. Then the
content is already yours, and the receipt keeps doing its job: it verifies offline
against the store's key material in your bundle, with nobody's permission, and it
shows anyone who needs to know — a successor honouring old purchases, an archive
authorised to serve them — exactly what the seller signed about that copy. The
project's own demo deletes a store's entire infrastructure mid-lifecycle and shows
the receipt verifying afterwards. The trust level reported alongside that result is
`unauthenticated_tofu`, the same level every verification you can run today reports
while the store is alive, since no shipped tool reaches `verified` in the first
place; the store's disappearance changes nothing there, and closes off nothing you
had.

Two limits, both named. Transfers are countersigned by the issuer, so they stop when
the issuer does; the resale answer above says what is and is not written about that.
And "forever" holds against the store disappearing, not against a live store
declaring its own signing key compromised: that declaration invalidates the receipts
signed with that key. The standard defines a rescue for a receipt logged and anchored
before the declaration, and both implementations evaluate it: shown a receipt with
that standing, they let it survive; the command line has options for the evidence
and for the log keys and block headers it is checked against; and the conformance
corpus carries a rescued receipt to hold them to it. What is missing is the evidence
itself, and an anchor to check it against. No shipped tool produces it for you — the
bridge does not log what it issues, and though the command line can run a log, no
command turns a receipt into an entry for it — and nothing pins an anchor by
default: the browser verifier pins no Bitcoin block header, and the command line and
both libraries run with no anchoring policy at all unless you hand them one, as the
answer about Bitcoin above spells out. So for a receipt you hold today the
declaration is final, and the rule on any DRM-free store is simple and unglamorous:
download what you buy, and keep the file next to the receipt. Content plus proof,
both in your hands.

You don't have the file. Then the receipt alone doesn't bring it back. It proves that
the seller signed the receipt's claims; it isn't the thing, and no signature can
conjure a file out of a dead server. The specified mechanism for addressing this gap
is the preservation pledge: a licence term the publisher signs at the moment of sale,
committing that when they cease distribution the content becomes redistributable to
valid receipt holders. Grant evaluation and redemption verification are implemented
in both verifier cores; only the Python package exposes `grant` commands. In the
default `python -m demo.pledge_dies` scenario, the store is deleted, the pledge
initially stays dormant, the surviving rights holder signs a cessation declaration,
and a non-normative demo custodian delivers after checking the holder proof. What is
missing is a production publisher who has signed such a pledge, a production archive
service, and final licence prose rather than the demo placeholder.

Two holes stay open, and both are worth knowing before you rely on it. A publisher
that vanishes silently — signing nothing, naming no successor, setting no backstop
date — leaves the pledge dormant forever; the threat model calls that the largest
residual risk this feature carries. And the pledge can only be redeemed with a key,
so a receipt bound only to an email address is outside it entirely, as the answer
about losing the file explains.

## Is this centralized?

No. There is no central attest authority, no registry that must exist, and no
phone-home. A verifier needs only three things to check a receipt: the receipt
bytes, the issuer's published key material, and, optionally, a revocation feed.
None of those requires a server attest itself operates — the issuer publishes its
own keys, and a future registry layer for replicating verification material is
explicitly optional (see the roadmap in the README).

The caveat is about practice rather than protocol. A verifier that wanted stronger
evidence would need curated pins, and curation is a soft centre even when the
protocol has no centre. The browser verifier already ships one pinned log key and
passes it into verification. It ships no pinned Bitcoin block headers and supplies
no witness policy; the Python and TypeScript library entry points otherwise depend
on configuration supplied by their caller.

## Does this save my existing Steam / PlayStation / Kindle library?

No. Be clear about why: attest verifies a receipt that a store *chooses to sign*.
It cannot retroactively produce a valid signed receipt for a past purchase made
on a platform that never signs anything, and it cannot forge one for a store
that refuses to participate — that would break the entire cryptographic premise
the standard is built on. Existing libraries stay exactly as revocable as they
are today until the store that holds them decides to issue attest receipts for
them.

The lever for an unwilling incumbent isn't a workaround — it's regulation and
market pressure. In the United States, the specification names California's
AB 2426 and Maryland's HB 208 as the kind of law an irrevocable receipt is
built to be evidence under — evidence, it is careful to say, not a compliance
determination. attest is the technical standard those pressures could point an
incumbent toward adopting; it is not a way around an incumbent that declines.

## Is attest a DRM system, a store, or a way to pirate games?

None of those. attest is content-free: a receipt is evidence that a licence was
granted, and it never touches, wraps, hosts, or indexes the underlying work. It
doesn't strip or bypass DRM — the specification forbids that outright, as the answer
about copying says — and it isn't a marketplace or a distribution channel. It supports
transfer only where the issuer mediates it, as the resale answer sets out. Holding a
valid attest receipt says one thing and no more: that an issuer signed a claim that a
licence was granted. It carries no copy of the work and grants access to none.
