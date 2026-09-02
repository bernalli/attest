# Own what you buy

*A whitepaper on durable digital ownership: the seller signs a receipt, you hold the file, anyone
can verify it offline — even after the store is gone.*

> **Status: draft, first round (September 2026).** This file contains three things: the outline of
> the finished document (Part A); three sections written in full so that the register can be judged
> before the rest is written (Part B); and a short note listing the decisions the author had to take
> and wants confirmed or overturned (Part C, to be removed before publication). Every factual claim
> in Part B was checked against the specification, the code and the running demonstrations on the
> day of writing; the sources are named inline or in the outline. Nothing in this document is a
> promise the repository cannot keep.

---

## Part A — Outline of the finished document

Conventions that hold for every section:

- **Lexicon.** "Two tracks, one standard." The word is *track*, never *rail*. "Durable, portable,
  user-held" is the fixed description of what attest is. "Eternal verifiability" never appears
  without the gloss *always readable, not always valid*.
- **Numbers.** No package versions, test counts or corpus sizes in the body: those live in the
  repository and on the registries, where they cannot go stale. External facts (dates, court
  cases, statutes) are allowed because they carry their own date.
- **Limits sit next to the promise they limit**, in the section where the promise is made, and are
  then gathered once, in full, in section 8. The whitepaper never says "nobody can take it away
  with a click".
- **Register.** The reader is assumed to buy digital content and to have never heard of a
  cryptographic signature. Every technical term is explained by what it *does*, in the sentence
  where it first appears. Sections that need a technical register carry it in an "In detail" box
  the reader can skip.
- **Every claim about a law or a regulator's act cites the article and the date, or is not made.**

| # | Section | The reader's question it answers | Where the facts come from | Length |
|---|---|---|---|---|
| 0 | Front matter | How do I read this, and how long is it? | this outline | 2 paragraphs |
| 1 | **The thesis** (written, Part B) | What is this, in one sentence — and why should I care? | canonical project sentence; `README.md` opening; `docs/faq.md` "What is attest?"; the named limit from `docs/faq.md` "The store that signed my receipts shut down" | 9 paragraphs |
| 2 | Someone paid, and has nothing | Has this actually happened to people like me? | four verified cases, one per market — Amazon/*1984* (2009), Microsoft ebook store (2019), Sony/StudioCanal on PlayStation (1 September 2026, seller's own notice), Ubisoft/*The Crew* (2023–24); `README.md` opening; the verified case notes of 1 September | 10 paragraphs |
| 3 | What you actually bought | What exactly is the thing I am missing? | `README.md` "What attest is"; v0.1 §2 "What a receipt is" | 7 paragraphs |
| 4 | How it works | What does the seller give me, and how does a stranger check it? | `README.md` "How it works, for humans"; `docs/faq.md` "Who validates it?", "Is this centralized?"; v0.1 §7 (keys), §8 (buyer binding), §12 (revocation records), §14 (the two files); `site/index.html` CSP and `site/e2e/site.spec.ts` for the browser verifier. Revocation is described as a mechanism the verifier evaluates, never as something a seller can do today: the command-line tool on `main` has no `revoke` verb (its verbs are `keygen`, `issue`, `verify`, `export`, `import`, `inspect`, `disclose`, `check-artifact`, plus `transfer` and `grant` groups), and the bridge has no refund handling | 9 paragraphs + In detail |
| 5 | The trilemma | If a file can be copied perfectly, how can it be *mine*? | the internal analysis of duplication and the sharing/exclusivity/survival contradiction (research notes of 24 August); v0.2 §17 (issuer-mediated transfer, first-logged-wins); `docs/faq.md` "Is attest a DRM system…" | 8 paragraphs |
| 6 | **The clock** (written, Part B) | Why is Bitcoin in here, if this is not a blockchain thing? | v0.2 §11.1–§11.3 (anchoring), §19 (the anchored-cutoff rescue); `src/attest/cli.py` (no anchoring flag on `issue`), `src/attest/verify.py` and `verifiers/ts/src/verify.ts` (anchoring off by default), `site/src/trusted-log.ts` (empty header set); `docs/faq.md` "Why not blockchain / NFT?" | 13 paragraphs + In detail |
| 7 | Two tracks, one standard | Who would ever issue one of these? | `README.md` "What attest is" (both tracks); `docs/faq.md` "Nobody forces a seller…"; Directive 2011/83/EU Article 8(7) and Article 2(10); the European Commission's reply of 16 June 2026 to the *Stop Destroying Videogames* citizens' initiative; California AB 2426 (in force 1 January 2025) | 10 paragraphs + In detail |
| 8 | **What it does not do** (written, Part B) | Where is the catch? | v0.1 §7.3, §7.4; v0.2 §15, §18.6, §18.7, §19.5, §19.6, §20; `docs/spec/attest-threat-model.md` §6.2, §7, TM-44, TM-68, TM-74; measured behaviour of `demo/store_dies.py`; `docs/faq.md` limits paragraph | 20 paragraphs + In detail |
| 9 | Copying, piracy, and what this is not for | Is this DRM? Does it stop piracy? Does it help pirates? | v0.1 §2 (out of scope: DRM, hosting, resale); `docs/faq.md` "Is attest a DRM system, a store, or a way to pirate games?"; the evidence review on second-hand markets and piracy in the September paper (hostile studies first, then the applicability limit, then the ceiling, then the unmeasured gap) | 7 paragraphs |
| 10 | Why it is worth having anyway | What does each party actually gain? | `README.md` seller paragraph; `docs/faq.md` "Nobody forces a seller…"; v0.1 §6.1 (the irrevocable-goods conditional and AB 2426); v0.2 §18 (the preservation pledge as a zero-cost signature) | 7 paragraphs |
| 11 | After the store is gone | Practically, what do I do with the receipt on the day it matters? | `docs/faq.md` "The store that signed my receipts shut down…"; v0.2 §18 (preservation pledge, activation modes); `demo/README.md`; both demonstrations, run. Every seller-side act named here (revoking, declaring a compromise, re-issuing) is stated with whether a shipped tool performs it — today only issuing and transfer are | 8 paragraphs |
| 12 | Where this actually is | What exists today, and what is only designed? | `README.md` "Status"; `docs/conformance.md`; the IETF Datatracker entry (individual submission, no standing) | 4 paragraphs |
| 13 | Open problems | What is still unsolved, with a name? | `docs/spec/attest-threat-model.md` §6.3; TM-68; the adversarial question list of 1 September (long-term custody of block headers; re-attestation with no signer; the domain as a lease); and the general fact, measured on the command-line tool and the bridge: **the defences exist in the specification and in the verifier; the tools that would let a seller exercise most of them are not shipped** — no revocation command, no packaged compromise declaration, no anchoring flow | 8 paragraphs |
| 14 | What is needed now, and colophon | What should I do, and on what terms is all this offered? | `README.md` seller and contact paragraphs; `LICENSE`, `LICENSE-docs`; `docs/faq.md` on the patent boundary | 5 paragraphs |
| 15 | Notes | Where does each external fact come from? | numbered sources for sections 2, 7, 8, 9 only; internal facts link to the live surface instead | as needed |

Order of writing after this round: 5 (trilemma) and 7 (two tracks) next, because they are the two
remaining places where the document can lose a hostile reader; then 2, 3, 4; then 9–14; the front
matter last, when the body is stable.

---

## Part B — Three sections written in full

### 1. The thesis

attest is the durable, portable, user-held layer of ownership for digital content. When you buy a
game, a film, an album or a book, the seller signs a receipt and hands it to you as a small file.
You keep it — on a disk, in a backup, anywhere you keep files that matter. Anyone can check that it
is genuine without asking the seller, offline, on their own machine. And it keeps working after the
store is gone.

That is the whole idea, and each part of it was chosen against something you have already
experienced. *The seller signs it*, so that it cannot be forged and cannot be quietly edited. *You
hold it*, so that it does not live in an account someone else can close. *Anyone verifies it
offline*, so that no server has to stay alive for your proof to be checked — not the seller's, and
not one run by the people who wrote this. *It keeps working after the store is gone*, because the
day the store is gone is the day you need it.

Notice what the receipt is and is not. It is not the film. It does not contain it, lock it, or make
it harder to copy. It is the piece of a purchase that every physical purchase always had and every
digital purchase so far has lacked: durable evidence, in your possession, that this seller granted
this licence for this work on this date, and that it was granted to you. A deed, not a lock.

Two things are true today and this document will keep saying both. First: this works right now
wherever files are sold without digital locks — the DRM-free catalogues, the marketplaces that hand
over a plain download, publishers selling direct. A seller there could start signing this
afternoon, without asking anyone's permission, and every buyer would walk away with content plus
proof, both in their hands. Second: no store does it yet. The standard, two independent
implementations and a public test suite exist and are free to use. The first seller who signs does
not. Every sentence in this document about receipts being issued describes what the mechanism does,
not an ecosystem that is running.

The stores that will never sign voluntarily — the closed platforms, where the seller keeps the file
and you keep a permission — are the second track, and it does not run on persuasion. In the
European Union a trader is already required to confirm every distance contract on a *durable
medium* (Directive 2011/83/EU, Article 8(7)); a durable medium is defined as something that lets you
store the information, keep it accessible for as long as you need it, and reproduce it unchanged
(Article 2(10)). That obligation is why confirmation emails exist. attest is that same confirmation
in a form a machine can check and you can carry away. What a regulator would be asked for is not a
new obligation but a usable format for one that already exists. No regulator has asked for it. Two
tracks, one standard.

One limit belongs in the first page rather than the last, because it qualifies the promise most
people take from the project. "Forever" holds against the store *disappearing*. It does not hold
against a live store *declaring its own signing key compromised*: that declaration is one click, it
is available to the seller exactly as it is to a thief, and it destroys every receipt that key ever
signed unless the receipt was logged and timestamped in public before the declaration was. Section
8 explains why the rule has to be that way and how narrow the rescue is. For now the short version
is enough: what you hold survives the seller's absence, not the seller's hostility.

A few things this is not, so that the wrong picture never forms. There is no blockchain, no wallet,
no token and nothing to buy; the project uses the Bitcoin block chain in exactly one role, as a
public clock that nobody controls, read from a local copy — section 6 is entirely about that. There
is no attest company in the middle: no account, no registry of purchases, no fee, nothing to join.
It is not a backup: if the store dies and you never downloaded the file, no signature brings it back.
And it does not stop anyone from copying a file, and does not try to.

The rest of this document is written so that you never need another one. It says what the
mechanism is, what it is not, what it costs, where it is honest about being unfinished, and what
you can do — as a buyer, a seller, a regulator or an engineer — if you decide it is worth having.
The section on what it does not do comes *before* the section on why it is worth having, on
purpose.

---

### 6. The clock

A signature proves *who* and *what*. It cannot prove *when*.

That gap matters more here than it looks, because of the limit named on the first page. A
receipt's worst day is the day the seller announces that its signing key was stolen. From that
moment every signature the key ever made is suspect, the honest ones included, and the only thing
that separates your genuine receipt from a forgery made with the stolen key is *order*: yours
existed before the announcement, the forgery came after. The date written inside a receipt cannot
settle that, because whoever holds the key writes the date. If the order cannot be proven by
something outside the seller's control, the announcement takes your receipt down with the
forger's, and the standard says so plainly rather than pretending otherwise.

So the question is whose clock to trust. Not the seller's: it is the party whose key is in
question. Not ours: a standard that asks you to trust its authors has already failed. Not a
timestamping company's either, and that one deserves a sentence because it is the obvious answer.
Such a company signs a statement saying "this existed at 14:03" — but that signature is built with
the same kind of mathematics as ordinary digital signatures, the kind that a sufficiently advanced
future computer is expected to be able to break. A proof of date that expires is a poor foundation
for a receipt meant to outlive the shop. The standard accepts that kind of timestamp only as a
courtesy, and gives it no weight at all against that future.

What is needed is a public event that everyone can see, that nobody can arrange after the fact, and
that goes on being checkable after the people who made it are gone.

#### The newspaper trick

This problem was solved before anyone had heard of a blockchain. From 1995 a company called Surety
bought a small classified advertisement in the Sunday *New York Times*, once a week. The
advertisement was a meaningless-looking string of characters: a cryptographic summary of every
document its customers had asked it to timestamp that week. Anyone who kept that Sunday's paper
could later prove that a document had existed by that date — without trusting Surety, without the
newspaper knowing anything about the documents, and without owning any part of either. Nobody can
reprint last week's *Times*.

attest uses the chain of Bitcoin block headers as that column of newsprint. Bitcoin is, among other
things, a public record that many independent computers all over the world copy and extend, roughly
every ten minutes, with a new block that is mathematically chained to the one before it; each block
carries the time it was made, and altering an old block would break every block after it, in every
copy. That is the property being borrowed, and the only one: a dated, public, widely copied wall of
stamps that nobody can go back and reprint. Periodically, a summary of the project's transparency
log is folded into one of those blocks, and the arithmetic connecting the two can be re-checked by
anyone, forever.

#### What is not there

The word "Bitcoin" carries a great deal of luggage that does not apply here, so here is the
inventory. There is no wallet. No token. No coin is spent, held or represented. Nothing is bought.
Verifying a receipt costs no fee, needs no account, and involves no transaction of any kind. No node
runs. Your purchase is not recorded on the chain, and nobody could look it up there if they tried:
what is folded into a block is a summary of the log, a fixed-length fingerprint from which nothing
can be read back.

Most importantly, nothing is asked of the network at the moment you check a receipt. The block
headers a verifier needs are carried inside the verifier itself, the way a dictionary carries its
words. It never goes and fetches one, and it will not accept one offered by whoever handed you the
file: the standard requires the headers to be pinned in the verifier's own configuration and never
taken from the evidence being checked. Bitcoin does not know your receipt exists, cannot make it
valid, and cannot make it invalid. In the words the project uses elsewhere: it corroborates, it
never authenticates.

That answers the obvious objection. If Bitcoin stopped existing tomorrow, every receipt would keep
verifying exactly as it does today, and every timestamp already established would still hold,
because the evidence needed to check it is already in your copy of the software and not out on a
network. What would be lost is the ability to establish *new* timestamps of this kind. So when this
project says it is not built on a blockchain, this is what the sentence means: no chain decides who
owns what, no consensus is consulted, and nothing is asked of a network for your receipt to be good.
Using the newspaper for its date does not put you in the newspaper business.

There is a real cost, and it is not the one people expect. The trust does not rest on the Bitcoin
network. It rests on the chain of custody of those block headers: on somebody continuing to curate
and distribute an honest set of them, verifier after verifier, for as long as the receipts are meant
to last. That is a genuinely unsolved problem, and it is listed among the open ones later in this
document rather than buried here.

#### What the clock is for

The clock exists for one rule, and the rule is worth stating in plain words because it is the
project's answer to the limit on the first page. A verifier that holds pinned headers and sees a
receipt whose signed core was timestamped *before* the seller's compromise declaration was itself
timestamped must not reject that receipt on the strength of the declaration. The seller does not
hold the pen on that cutoff: the cutoff is the time of the block in which the declaration's own log
entry landed, not a date the seller writes. Equal times fail closed. A declaration that was never
timestamped cannot invalidate a receipt that was.

Read the rule's edges as carefully as its centre, because the standard does. It protects only
receipts that were actually logged and timestamped; a receipt that never was gets nothing from it,
however old, however strong its signature. A thief who steals a key and timestamps forgeries *before*
the seller's declaration is timestamped gets the same protection honest buyers get; that window is
bounded by how fast the seller declares, and by keeping each signing key in use for a short period,
and it is never zero. And the rule covers the signature on the receipt itself and nothing that sits
beside it — a transfer made before the declaration falls with the key, and the receipt reverts to
its previous holder. None of that is hidden in the specification. It is written there as a numbered
list of limitations that any conforming implementation is forbidden to overstate.

#### Nobody has wound it

Now the part a reader who opens the repository would find within the hour, so it is better read
here first.

This clock is built and specified, and implemented in both independent implementations — and it is
running for essentially nobody. Timestamping is optional at three separate points, and switching it
on requires clearing all three. The command that issues a receipt has no option for it: the log
entry, the proof and the timestamp have to be produced afterwards by hand, in a sequence of separate
commands, with the Bitcoin attestation obtained outside the tool. The verifying libraries in both
languages ship with the check switched off unless the caller supplies log keys and a header policy.
And the block headers a verifier would need in order to check a timestamp are not distributed with
anything: no curated set of pinned headers ships in either package.

That includes ours. The verifier on this project's own website — the one anyone can drop a file
into — is wired for the check and carries an empty set of headers, so it cannot establish a
timestamp either.

There is a further gap on the seller's side. To use the rule above, a verifier has to be shown the
seller's compromise declaration in a particular authenticated form. Both implementations know how to
consume that form. No tool this project ships knows how to produce it. So a seller who discovers a
theft and publishes the declaration has, today, no way of packaging it so that a verifier can turn
it into the cutoff the rule needs. And the order in which these gaps are closed matters: honouring
timestamped receipts before anyone has timestamped a declaration would not protect buyers, it would
protect everyone whose receipt carries a timestamp, a thief's forgeries included, because no cutoff
would exist to stop them. The declaration has to be timestamped first.

The summary is this. The clock exists, matches its specification in both implementations, and the
defence it provides — the one that saves your receipt on the seller's worst day — currently protects
no one who has not assembled the whole apparatus themselves. Since no store issues receipts yet, the
number of real receipts it protects is zero. That is a gap in tooling and adoption rather than in
the design, which makes it fixable, and it is not fixed.

> **In detail: how the timestamp is checked.** A timestamp proof is an OpenTimestamps attestation: a
> short chain of hash operations that starts from the SHA-256 of the log's full signed checkpoint
> text and is replayed step by step until it lands on the Merkle root recorded in a Bitcoin block
> header. The verifier accepts the proof only if that header — identified by its hash — is present in
> its own pinned set (`AnchorPolicy.pinned_headers`), and it takes the time from the pinned header,
> never from anything in the proof. A receipt's standing is then `anchored_before:<T>`, where `T` is
> the *earliest* pinned header time across all proofs that verify: an upper bound on when the
> checkpoint first existed, not a lower bound. Because the whole path is hash-based rather than
> signature-based, no future advance against classical signature schemes disturbs it, which is why
> the specification requires this kind of anchor — and not an RFC 3161 token, which it accepts only
> as opaque classical corroboration — for any standing that must outlast that horizon (v0.2 §11.1,
> §11.2, §11.3). The rescue rule itself, its decision table and its six stated limitations are v0.2
> §19.

---

### 8. What it does not do

This section comes before the argument for why any of this is worth having. Every limit in it is one
a reader with the specification open would find in an afternoon, and several are written into the
specification as normative limits — which is why some sentences below are quotations rather than
paraphrase.

#### The strongest promise has a named limit

The promise most people take from this project — a receipt that keeps working after the shop is gone
— holds against the shop **disappearing**. It does not hold against a live shop **declaring its own
signing key compromised**.

That declaration is absorbing, by design. A key that has genuinely been stolen must be stoppable in
a single move, or the theft is unstoppable instead. The price is that the same move invalidates
every signature *that key* ever made, the honest ones included — not the seller's other keys, if it
has several — and it is available to the seller exactly as easily as to the thief. It is one click,
and it reaches backwards. It reaches even the
class of receipt the standard otherwise allows nobody to revoke: a receipt marked irrevocable is
immune to every revocation record, and not to this.

There is a rescue, and it is narrow. A receipt whose signed core was recorded in a public log and
timestamped before the shop's own declaration was timestamped survives that declaration — section 6
is about the clock that makes this possible. The specification states the bound itself, and forbids
anyone implementing it from claiming more:

> the store cannot take back a receipt whose signed-receipt-core was anchored before the store's
> own anchored compromise declaration. Un-logged and un-anchored stock remains destructible by a
> compromise marking, exactly as before.

Four things follow from that paragraph.

Logging is the seller's decision, not the buyer's. A receipt that was never submitted to a log gets
no existence-before-a-date guarantee at all, *"no matter how old it is or how strong its original
signature was"*, and the specification requires that any claim about protecting "the stock" be
scoped, every time, to *logged-and-anchored receipts*. An unqualified claim is non-conforming, not
merely optimistic.

No shop issues attest receipts today. So the number of real receipts the rescue covers is zero, and
it stays zero until a first shop both signs and logs.

Getting there is opt-in at every step, and nothing is switched on by default — the issuing command
has no option for it, the verifying libraries ship with the check disabled in both languages, no
pinned block headers are distributed with anything, and the verifier on this project's own website
carries an empty set of them. The evidence a verifier would need in order to learn that a key was
declared compromised is consumed by both implementations and produced by neither. The defence is
built and specified. It is not running.

And the rescue applies to the signature on **the receipt**, and to nothing else. A genuine transfer
made *before* the declaration stops authenticating too, and the receipt reverts to whoever held it
before; that is deliberate and specified, because extending the cutoff to transfers would open the
door to resurrected and doubly-assigned transfers. What is not deliberate is that nothing in the
result tells the person holding the receipt why it happened.

#### The seller's own levers are specified, not shipped

Several things this document says a seller *can* do are things the specification defines and the
verifier evaluates — and no shipped tool performs. Say it once, plainly, because it is the
difference between a protocol and a product.

A seller cannot revoke a receipt today. The specification defines revocation records, the classes
they act on — a refund window, a stated policy — and exactly how a verifier must treat them, and
both implementations evaluate them correctly. But the command-line tool on the project's main
branch has no command that produces one: the only place it writes a revocation record is inside a
transfer, where the record says "transferred", never "revoked". The merchant bridge, which turns a
paid order into a signed receipt, has no refund handling at all. So when this document says that an
irrevocable receipt is immune to every revocation record, it is describing a rule the verifier
enforces against a document nobody can currently issue.

The same is true of the compromise declaration in the form a verifier needs to compute a cutoff
(above), and of the whole anchoring flow (section 6). The pattern is general and it is measured, not
inferred: of the defences the project's own adversarial review classifies as "known design", none
today has a complete, shipped producer on the seller's side. What is shipped is issuing, verifying,
transfer, and the preservation-pledge documents. Everything else in this document that begins "the
seller can" should be read as "the specification lets the seller, and the verifier will honour it,
once a tool exists".

#### The root of trust is a domain name, and a domain is a lease

An issuer's identity **is** its internet domain, and the strongest trust level the specification
defines is a key manifest fetched over TLS from that same domain. Nothing else, in the
specification's words, suffices, ever.

Read that against the scenario the whole project is built for. The shop closes. Two years later the
domain lapses; someone else registers it, obtains a certificate for it — now legitimately theirs —
and publishes a key manifest listing their own keys. A verifier meeting that issuer for the first
time has no way to tell. The old receipts cannot be forged; the keys are different. But the newcomer
can issue new receipts in the dead shop's name, and can publish a manifest declaring the real shop's
keys compromised, which is the move described above. In an insolvency the same two assets, the
signing key and the domain, are sold together, to a buyer under no obligation to be friendly.

The exposure is narrower than it sounds, and the narrow version is the one to hold. Someone who
obtained the shop's key material while the shop was alive, and kept it, is unaffected: their
verifier already knows what the real manifest said, and a later manifest that re-lists or drops a
key that was declared compromised breaks the chain visibly. The window is against verifiers meeting
a dead issuer for the first time — an heir, an archive, an acquirer's refund desk, a court — which
are exactly the parties this document has been arguing should be able to check. The mitigation
exists on paper: a manifest recorded and timestamped while the shop was alive beats a newer one. It
needs the timestamping that the previous limit just said is running for nobody. A domain is not a
freehold, and the protocol treats it as one.

#### Freshness and non-equivocation are a format, not yet a service

A transparency log that nobody watches can show one version of history to one person and a different
version to another, and stay internally consistent in both. The defence against that is independent
observers who co-sign what they saw.

The format for it shipped. The service did not. No independently operated witness is published
today, and the witness policy packaged inside the released verifiers is deliberately empty, so the
strongest corroboration verdict is out of reach for anyone who has not pinned observers of their
own. The specification is careful about the words, and so is this document: a split view is
**detectable** when a verifier already holds two conflicting signed checkpoints, and **observed** by
whichever parties a verifier has itself chosen to pin. It is never prevented. Even a witnessed
result carries, permanently attached to it, the statement that the witness's independence has not
been established. Until operators exist, everything in the transparency layer should be read in the
conditional.

#### Offline verification is real. The strong verdict is not reachable at all

Offline verification works, and that is not a simplification: the bytes plus the issuer's key
material are genuinely enough, with no server in the trust model. But the *level of trust* that
result reports is the weaker of the two the specification defines. The strong one requires the
manifest fetched over TLS from a living issuer's domain, and no tool this project ships performs
that fetch — not the command-line tool, not the browser verifier, not the downloadable one. So the
strong level is not expensive, or slow, or online-only. It is unreachable with what we give you.
Every verification anyone can perform today reports the weaker one: trust on first use.

Run the demonstration this project ships, the one that deletes a shop's entire infrastructure and
then checks the receipt. On a receipt that is perfectly genuine, it reports:

- signature: valid
- schema: valid
- who controls the signing key: not established (trust on first use)
- whether the receipt was revoked: unknown
- whether it appears in any log: not checked

and, at the top, the line most people will read and stop at: *ok*.

That headline has two states in the browser verifier. The state almost every buyer is actually in
is a third one, which the downloadable verifier now shows separately and the browser page does not
yet. A reader who stops at the headline is told *valid* where the accurate words are
*self-consistent, and unvouched-for*.

Two consequences are worth stating plainly. A valid signature, on its own, does not establish that
the issuer is who the file says it is: under trust on first use the same party can supply both the
file and the key that checks it. And nothing a verifier displays should be read as an assertion by
the verifier unless the signature covers it and the verifier has checked its form. A file can carry
text chosen by whoever made it, and text can be shaped to be read as a verdict.

#### Losing your side of it has no recovery

The receipt proves a purchase. Proving that the purchase was **yours** takes something only you
hold, and if you lose it there is no recovery inside the protocol: the commitment is one-way, no
escrow or backup is defined, and the one remedy — asking the issuer to re-issue — requires the
issuer to still exist, which is the situation this project exists because you cannot count on. The
receipt keeps verifying. What is lost is exclusivity: anyone else holding a copy of that receipt is
thereafter no less able to present it than you are.

There is a sharper version. Where a publisher has signed a preservation pledge, an heir who inherits
the receipt but not the buyer's key cannot redeem it — not with difficulty, but **by construction**.
The specification forbids the easier proof outright, as a normative prohibition rather than a
recommendation, because that proof is replayable and hands over the buyer's identifier; and it
requires the harder proof, a buyer key, to have been set up at the time of sale. Both
implementations enforce it, closed. Paper and QR export of a buyer's key is a stated need and does
not exist in code.

#### And the ordinary list

The remaining limits are shorter.

It is not a backup, and it delivers nothing: if the shop dies and you never downloaded the file, no
signature conjures it off a dead server, and what survives is the proof. It does not rescue the
library you already have: a receipt is something a seller issues, so it cannot reach backwards into
purchases made on platforms that never issued one. It cannot stop a copy from being played: on an
open platform a receipt check is something software chooses to honour, and any modified or
independently written player can leave it out — which is structurally weaker than every DRM that has
ever been broken, because there is nothing to break. "DRM-free" does not mean "freely
redistributable": the shops where this works today sell files without locks *to the people who buy
them*. It does not create a right to resell. In the EU, *Tom Kabinet* (Court of Justice, C-263/18,
2019) holds that supplying an ebook by download is not a distribution that exhausts the right;
software is the exception, under a different directive, following *UsedSoft* (C-128/11, 2012); in
the US, *ReDigi* (Second Circuit, 2018) held that reselling a purchased file necessarily makes a new
copy and that the remedy, if any, lies with Congress. A file format does not restore first-sale
doctrine to digital goods, and a lawyer will say so in one sentence. It cannot force an unwilling
seller: a shop that never issues a receipt leaves nothing for anyone to check. Transfers stop when
the issuer does, because every transfer is counter-signed by the issuer; making them outlive the
issuer has a name in the specification's own open work and is not built. A publisher's word about
who was authorised to sell never touches the verdict, and nothing distinguishes a publisher who
refuses to participate from one who simply never has. It does no forensic tracking, and it does not
extend to streaming.

> **In detail: the limits with the names they have.**
>
> - **Compromise marking is absorbing** (v0.1 §7.3; threat model TM-74). It invalidates every
>   signature made with that key, including the `revocability: "none"` class that §6.2 otherwise
>   treats as invalidable by nothing else. v0.2 §19.6 item 1 states the narrowed promise verbatim,
>   and §15 item 2 makes the scoping mandatory: a conforming implementation and its documentation
>   "MUST NOT claim to protect 'the stock' unqualified".
> - **The rescue covers the receipt's own signature and nothing else** (v0.2 §19.5). Revocation
>   records, artifact manifests, transfer records, grant documents and cessation declarations keep
>   v0.1's fail-closed rule — a side-document signed by a key that is not `active` is unauthenticated
>   and ignored — and extending the cutoff to them is named as a distinct design with its own hazards,
>   transfer resurrection and double assignment. Neither specification restricts *which* keys may
>   publish a compromise marking.
> - **The trust root is domain control** (v0.1 §7.1, §7.4). "An issuer's identity is its DNS domain";
>   `trust: "verified"` requires a manifest fetched over TLS from it, everything else is
>   `unauthenticated_tofu` and is "never silently upgraded"; and no value of transparency or
>   corroboration ever changes that (v0.2 §15 item 4, "the single most important non-goal").
> - **Proving you are the buyer costs something** (v0.1 §8). Redeeming the commitment by disclosing
>   the identifier and its salt is a replayable bearer proof that burns that receipt's binding
>   secrecy toward that verifier; the non-revealing path — a challenge-response against a buyer
>   public key — is the strong one, and it is optional and absent by default wherever there is no
>   buyer-side client.
> - **The heir's case is closed by construction** (v0.2 §18.6, §18.7; threat model TM-44). A pledge
>   receipt must carry a non-null `buyer.pubkey`, and "Salt disclosure MUST NOT be accepted as a
>   redemption proof … This is a normative prohibition, not a recommendation."
> - **Publisher authority never touches the verdict** (v0.2 §20): "this machinery takes NO
>   exception: neither component ever affects `signature`, `schema`, `revocation`, `binding`,
>   `trust`, or `ok`, under any value."
> - **Silence and refusal are indistinguishable** (v0.2 §20.6): a publisher that never participates
>   leaves its works permanently `unattested`, and "nothing distinguishes 'does not participate' from
>   'does not authorize'".
> - **The preservation pledge does not cover silent death** (v0.2 §18.4; threat model TM-68, named
>   there as the largest residual risk the mechanism carries). Both activation modes are
>   presence-based and neither can fire without a positive artifact; the absence-based mode that
>   would cover it is registered as reserved and "cannot be made sound by any amount of drafting".
> - **Witnessing does not prove independence** (v0.2 §10.1, §15 item 1). A witnessed result "MUST
>   NOT be described as proof of organizational independence or split-view prevention" and carries
>   `witness_independence_not_established` on every instance.
> - **"Eternal verifiability" means always readable, not always valid.** The versioning guarantee is
>   that "no amendment may render unverifiable an artifact that was conforming when issued.
>   Deprecation degrades the result classification, never the ability to verify the bytes." After a
>   compromise marking a receipt still verifies perfectly, and what it verifies is that its
>   signature is worth nothing.

---

## Part C — Working note for this round (not part of the text; remove before publication)

*In italiano, perché è rivolta a chi decide. Elenca le scelte che ho dovuto prendere e su cui chiedo
conferma o ribaltamento. Nessuna è nascosta nel testo: dove ho scelto, il testo dice ciò che ho
scelto.*

1. **Esiste lavoro precedente, e questo giro ci si appoggia invece di ricominciare.** Il 1° settembre
   sono stati prodotti, nella cartella privata di lavoro, una struttura in 14 sezioni (con le
   premesse verificate, i gate lessicali e la scelta del caso d'apertura) e una bozza con 8 sezioni
   scritte, corredate di tabelle di verifica claim per claim. Le tre sezioni qui in Parte B sono
   riscritte da capo nel registro richiesto, ma **riusano i fatti già verificati** di quel lavoro,
   ricontrollati oggi sul codice e sulla spec di `main`; l'outline in Parte A ne conserva l'ossatura
   con una differenza (punto 3). **Da confermare**: che questo file sia la sede unica da qui in poi e
   che bozza e struttura del 1° settembre valgano come archivio di verifica, non come testo.
2. **Il caso d'apertura (sezione 2) non è ancora una tua decisione.** La scelta «Amazon/*1984* del
   2009, poi gli stessi fatti in quattro mercati» ha sostituito Sony/StudioCanal e *The Crew* dopo
   due bocciature, ma risulta approvata in tua vece, non da te. L'outline la porta così; la sezione
   non è scritta in questo giro proprio per questo. **Da confermare o cambiare** prima che si scriva.
3. **La sezione anti-pirateria è una sezione a sé (9), non un paragrafo dentro «perché vale la
   pena».** Il brief la elenca fra le cose che il documento deve contenere; la struttura del 1°
   settembre la teneva come sottosezione. L'ho promossa perché la domanda «è DRM? aiuta i pirati?»
   è una delle prime che un lettore fa, e merita un titolo che si trovi scorrendo l'indice.
   **Da confermare.**
4. **Lessico: «track», mai «rail».** Il README pubblico dice «second track»; la frase canonica rev 2
   (non ratificata) chiude con «Two rails, one standard». Ho seguito il README e la proposta di
   emendamento già registrata. Se ratifichi la rev 2 così com'è, i due documenti collidono: la via
   pulita è emendarla a «tracks» nello stesso atto.
5. **La clausola del manifesto sulla catena va tolta quando il manifesto va in pensione.** Il
   manifesto dice che tutto ciò che una catena farebbe qui «è già fatto da log e firme, o è una
   liability»; la spec (v0.2 §11.1) dice l'opposto: l'ancoraggio a un header Bitcoin è *richiesto*
   per ogni standing che deve sopravvivere a un computer quantistico, e i checkpoint firmati non
   possono darlo. La sezione 6 scrive la posizione vera («niente blockchain nel modello; Bitcoin
   in un solo ruolo, come orologio letto da una copia locale») e non ripete quella frase. **Da
   confermare** che il whitepaper prevalga e che quella frase non sopravviva altrove.
6. **Due difetti vivi sono deliberatamente fuori dalla sezione 8**, perché la sequenza decisa è
   «fix → release letta sui registri → advisory», e scriverli nel whitepaper pubblicherebbe il
   meccanismo prima del rimedio. Il testo ne dice la *famiglia* («l'evidenza è consumata da
   entrambe le implementazioni e prodotta da nessuna») e tace meccanismo e soglia. Se il whitepaper
   atterra *dopo* l'advisory, le due voci rientrano e la sezione si riapre. **La sequenza è tua.**
7. **Ho corretto un errore della bozza precedente, e lo segnalo perché non si propaghi.** La bozza
   del 1° settembre affermava che un verificatore «accetterà ancora un record di revoca firmato con
   la chiave compromessa». È falso: v0.1 §7.3 e §12.1 impongono che un record firmato da una chiave
   non `active` — compromessa o ritirata — sia trattato come non autenticato e ignorato. Il limite
   vero di §19.5 è un altro, ed è quello scritto: un trasferimento genuino *anteriore* alla
   dichiarazione cade con la chiave, e in silenzio.
8. **Il verdetto a due stati non è più vero ovunque.** L'app di verifica scaricabile, mergiata oggi,
   distingue il caso trust-on-first-use; la pagina web no. La sezione 8 lo dice così. **Da
   confermare** che il documento possa citare l'app scaricabile come cosa esistente.
9. **Fatti esterni che ho citato per nome**: Surety e il *New York Times* dal 1995 (verificato oggi
   su fonti secondarie concordanti; la fonte primaria sarebbe una pagina del giornale — se vuoi
   solo fonti primarie, l'immagine si riscrive come ipotetica senza perdere nulla); le tre sentenze
   sulla rivendita con numero di causa e anno (fatti stabili, da rileggere alla fonte nel giro delle
   Note); la direttiva 2011/83/UE art. 8(7) e 2(10) (testo verificato; è il vincolo registrato oggi
   sulle claim UE, e la sezione 7 lo svilupperà per esteso, con la risposta della Commissione del
   16 giugno 2026 detta
   con precisione: ha *declinato* l'obbligo e si è impegnata ad *avviare* un confronto per un codice
   volontario entro fine 2026).
10. **Titolo e sottotitolo.** «Own what you buy» è la tagline già ratificata; il sottotitolo è la
    frase canonica in forma P+M+S. **Da confermare.**
11. **Lunghezza.** La sezione 8 da sola pesa quanto tre sezioni normali. Il tetto proposto per il
    documento intero resta ~11.000 parole; se lo si vuole più corto, la scelta è *quale* limite
    dichiarato esce, e non è una scelta di stesura.
12. **Il nome dell'Internet-Draft non compare**, e non comparirà finché il nome nel repository e
    quello sul Datatracker non coincidono: oggi divergono, e qualunque dei due manderebbe il lettore
    su un errore.
13. **Vincolo sui produttori mancanti, applicato.** Dopo la prima stesura è arrivata la misura che
    `attest revoke` non esiste (i verbi della CLI su `main` sono `keygen`, `issue`, `verify`,
    `export`, `import`, `inspect`, `disclose`, `check-artifact` più i gruppi `transfer` e `grant`;
    l'unico chiamante di `revocation.build_record` è il ramo `transfer --revocation-out`, che emette
    `status: "transferred"`; il bridge non gestisce i refund). Riverificato oggi sul codice. La
    sezione 8 ha ora una sottosezione dedicata («The seller's own levers are specified, not
    shipped»), la frase sulla marcatura è stretta a «quella chiave», e le righe 4, 11 e 13
    dell'outline portano il vincolo. **Da confermare**: la frase generale «nessuna delle difese
    classificate "design noto" ha oggi un produttore completo spedito» è scritta come misura del
    progetto, senza numeri.
14. **Collocazione.** Questo giro salva in `docs/whitepaper.md` su un branch dedicato, come
    richiesto; la struttura del 1° settembre prevedeva la bozza in cartella privata e l'atterraggio
    pubblico solo a fine lavoro. Se questo file deve restare privato fino alla ratifica, va detto
    ora, prima che il branch si accumuli.
