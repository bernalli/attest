<!-- @whitepaper-sync v0.1-rev=18 v0.2-rev=13 package=0.9.3 -->
# Own what you buy

*A whitepaper on durable digital possession: the seller signs a receipt, you hold the file, anyone
can verify it offline — even after the store is gone.*

> **Status: complete draft, fifth round (September 2026).** Every section of the outline in
> Part A is written in full in Part B. Part C is a short note for the project's owner, listing
> the decisions that remain genuinely theirs, each with the text chosen in the meantime; it is
> removed before publication. Every factual claim in Part B was checked against the specification,
> the code and the running demonstrations on the day of writing, and every claim about a law or a
> regulator's act against the published text of that act; sources are named inline, in the notes
> of section 15, or in the outline. Nothing in this document is a promise the repository cannot
> keep. The comment at the top of this file names the specification revisions and the package
> version the text describes; a test in the repository fails when they move, so the document
> cannot fall behind what it describes without someone noticing. It did move, and the test did
> fail: the fifth round exists because the tooling this document reports on changed under it, and
> several sentences that were true when they were written had stopped being true. They are marked
> nowhere, because a document that annotates its own corrections is harder to read than one that
> is simply correct; what is annotated instead is the repository, whose history holds both states.

---

## Part A — Outline of the finished document

Conventions that hold for every section:

- **Lexicon.** "Two tracks, one standard." The word is *track*, never *rail*. "Durable, portable,
  user-held" is the fixed description of what attest is. "Eternal verifiability" never appears
  without the gloss *always readable, not always valid*. What attest gives a buyer is
  *possession* of evidence, never "ownership" of a work: the specification says a receipt is not
  a claim of ownership, and the document uses the word only in its argumentative sense (what
  standing gives you). A binding result of `proven` means that the presenter holds a secret that
  reproduces a value the seller wrote into the receipt — a salt or a key — and the document never
  renders it as the buyer's participation or identity, because every input to that proof is the
  seller's. One image for what a receipt opens: *a key to a door, never to a file*.
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
| 1 | **The thesis** | What is this, in one sentence — and why should I care? | canonical project sentence; `README.md` opening; `docs/faq.md` "What is attest?"; the named limit from `docs/faq.md` "The store that signed my receipts shut down" | 9 paragraphs |
| 2 | Someone paid, and has nothing | Has this actually happened to people like me? | four verified cases, one per market — Amazon/*1984* (2009), Microsoft ebook store (2019), Sony/StudioCanal on PlayStation (1 September 2026, seller's own notice), Ubisoft/*The Crew* (2023–24); `README.md` opening; the verified case notes of 1 September | 10 paragraphs |
| 3 | **What you actually bought** | What exactly is the thing I am missing? | `README.md` "What attest is"; v0.1 §2 "What a receipt is" (quoted), §4–§6 (the envelope, the fields, immutability and the irrevocability conditional), §8.1 (the commitment), §14 (the two files) | 7 paragraphs |
| 4 | **How it works** | What does the seller give me, and how does a stranger check it? | `README.md` "How it works, for humans"; `docs/faq.md` "What does 'verify offline' actually check, and what can't it tell me?", "Who can revoke my receipt, and what would I see?", "Is this centralized?"; v0.1 §7 (keys), §8 (buyer binding), §11 (the algorithm and its vocabulary), §12 (revocation records), §13–§14 (disclose and the two files); `site/index.html` CSP and `site/e2e/site.spec.ts` for the browser verifier, `desktop/README.md` for the downloadable one. Revocation is described as a mechanism the verifier evaluates and a seller can now perform: the command-line tool's top-level verbs, read from the tool's own definition, are `authority`, `binding`, `check-artifact`, `disclose`, `export`, `grant`, `import`, `inspect`, `issue`, `keygen`, `log`, `manifest`, `revocation-view`, `revoke`, `transfer`, `verify`, and the `revoke` → `revocation-view` → `verify` chain was run end to end before the paragraph was written (the verifier reports `revocation: "revoked"`, `ok: false`). The checkout service declines an order already marked refunded and does nothing about a refund arriving after issuance; the web and downloadable verifiers fetch no revocation feed, though both read one a visitor drops on them, and pin no block headers. Every input `verify` accepts is listed with its producer, or the absence of one (`src/attest/cli.py`, `src/attest/verify.py`, `site/src/trusted-log.ts`) | 13 paragraphs + In detail |
| 5 | **The trilemma** | If a file can be copied perfectly, how can it be *mine*? | the internal analysis of duplication and the free-copying/exclusivity/survival contradiction (research notes of 24 August, formalised in the research record of 5 September: the three poles named precisely, the two arguments for why the triple fails, the verdict "not resolvable as stated, declare the perimeter, no specification change"); v0.1 §8 (the two bindings); v0.2 §17 (issuer-mediated transfer, log-required honouring, earliest-logged-wins, holder binding); `docs/faq.md` "Is attest a DRM system…"; `src/attest/cli.py` for which side of each mechanism has a shipped command (the holder's transfer authorization, the issuer's transfer record, its packaging for a verifier, pledge redemption and the ordinary binding challenge all do; what the last one lacks is a receipt carrying a buyer key to run against); the two measured limits on transfer — a record authenticates only while its key is `active`, so a retirement or a compromise marking un-honours it and leaves one purchase with two green receipts (threat model TM-80, pinned by a leaf of the corpus), and `license.transferable` is read only as a schema cross-check, never on the honouring path — stated as limits, not guarantees | 12 paragraphs + In detail |
| 6 | **The clock** | Why is Bitcoin in here, if this is not a blockchain thing? | v0.2 §11.1–§11.3 (anchoring), §19 (the anchored-cutoff rescue); `src/attest/cli.py` (`issue --log-dir` enters a receipt in the seller's log as it signs it; there is still no anchoring flag on `issue`, and `log anchor` attaches material obtained outside the tool, which never touches a network), `src/attest/verify.py` and `verifiers/ts/src/verify.ts` (anchoring off by default), `site/src/trusted-log.ts` (`pinnedHeaders: {}`); `docs/faq.md` "Why not blockchain / NFT?" | 13 paragraphs + In detail |
| 7 | **Two tracks, one standard** | Who would ever issue one of these? | `README.md` "What attest is" (both tracks); `docs/faq.md` "Nobody forces a seller…"; `bridge/src/attest_bridge/` (the three checkout adapters; refunded orders skipped); Directive 2011/83/EU of 25 October 2011, Article 8(7) and Article 2(10), read on the published text; the European Commission's reply of 16 June 2026 to the *Stop Destroying Videogames* citizens' initiative, read on press release IP/26/1369; California AB 2426 (Chapter 513, Statutes of 2024; in force 1 January 2025), Business and Professions Code section 17500.6 read on the codified text | 12 paragraphs + In detail |
| 8 | **What it does not do** | Where is the catch? | v0.1 §7.3, §7.4; v0.2 §15, §18.6, §18.7, §19.5, §19.6, §20; `docs/spec/attest-threat-model.md` §6.2, §7, TM-44, TM-68, TM-74, TM-78, TM-80; measured behaviour of `demo/store_dies.py`; `docs/faq.md` limits paragraph | 20 paragraphs + In detail |
| 9 | Copying, piracy, and what this is not for | Is this DRM? Does it stop piracy? Does it help pirates? | v0.1 §2 (out of scope: DRM, hosting, resale); `docs/faq.md` "Is attest a DRM system, a store, or a way to pirate games?"; the evidence review on second-hand markets and piracy in the September paper (hostile studies first, then the applicability limit, then the ceiling, then the unmeasured gap) | 7 paragraphs |
| 10 | Why it is worth having anyway | What does each party actually gain? | `README.md` seller paragraph; `docs/faq.md` "Nobody forces a seller…"; v0.1 §6.1 (the irrevocable-goods conditional and AB 2426); v0.2 §18 (the preservation pledge as a zero-cost signature) | 7 paragraphs |
| 11 | After the store is gone | Practically, what do I do with the receipt on the day it matters? | `docs/faq.md` "The store that signed my receipts shut down…"; v0.2 §18 (preservation pledge, activation modes); `demo/README.md`; both demonstrations, run. Every seller-side act named here (revoking, declaring a compromise, re-issuing) is stated with whether a shipped tool performs it — today all of them do, and dating any of them does not | 8 paragraphs |
| 12 | Where this actually is | What exists today, and what is only designed? | `README.md` "Status"; `docs/conformance.md`; the IETF Datatracker entry for `draft-martinalli-open-purchase-receipts-00` (individual submission, Informational, no standing), read on the Datatracker; the name is given because the repository's `ietf/` source and the Datatracker now carry the same one | 4 paragraphs |
| 13 | Open problems | What is still unsolved, with a name? | `docs/spec/attest-threat-model.md` §6.3; TM-68; the adversarial question list of 1 September (long-term custody of block headers; re-attestation with no signer; the domain as a lease); the provenance of the buyer's key (research record of 5 September); the two measured transfer limits; and the general fact, measured on the command-line tool and the checkout service: **the defences exist in the specification and in the verifier, and the seller's tools for all but one of them now exist too** — revocation, a receipt's log entry and a packaged compromise declaration all ship; *dating* any of them does not, because the attestation is obtained outside these tools by design and no curated block headers ship with anything | 9 paragraphs |
| 14 | What is needed now, and colophon | What should I do, and on what terms is all this offered? | `README.md` seller and contact paragraphs; `LICENSE`, `LICENSE-docs`; `docs/faq.md` on the patent boundary | 5 paragraphs |
| 15 | Notes | Where does each external fact come from? | numbered sources for the external facts of sections 2, 5, 6, 7, 8, 9, 10 and 11; internal facts link to the live surface instead | as needed |

Every section is written. Section 0 is the front matter and section 15 the notes; the order in
which the sections were drafted no longer matters, and each round's verification lives in the
project's research record, not in this file.

---

## Part B — Sections written in full

### 0. How to read this

This document is written for someone who buys digital content and has never heard of a
cryptographic signature. It explains each technical term by what it does, in the sentence where
it first appears, and puts the technical detail in boxes headed "In detail" that can be skipped
without losing the argument. Sections 1 to 4 say what attest is and how it works. Sections 5 to 7
answer the three objections that decide whether the idea is worth anything: a file copies, a
signature cannot tell the time, and nobody is obliged to sign. Section 8 is the list of what it
does not do, and it comes before section 10, the case for having it anyway, on purpose. Section 9
answers the three questions about copying and piracy that arrive together. Sections 11 to 14 are
practical: what to do on the day the store is gone, what exists today, what is unsolved, and what
you can do. Section 15 holds the sources for every external fact.

Two conventions hold throughout. No package version, test count or corpus size appears in the
body: those numbers live in the repository and on the registries, where they cannot go stale in a
document, while a dated external fact is allowed because it carries its own date. And every limit
is stated next to the promise it limits, in the section where the promise is made, and then
gathered once more, in full, in section 8. Read whole, the document is meant to leave no question
that needs another document; read in part, each section says which of the others it leans on.

---

### 1. The thesis

attest is the durable, portable, user-held layer of possession for digital content. When you buy a
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
this licence for this work on this date, and to whom the seller says it granted it. A key to a
door, never to a file; section 5 says why it can be nothing else.

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
(Article 2(10)). That obligation is why confirmation emails exist. attest is not that confirmation
— a receipt carries the purchase, not everything a trader must confirm — but it is a format that
confirmation could travel in: one a machine can check and you can carry away. What a regulator
would be asked for is not a new obligation but a usable format for one that already exists. No regulator has asked for it. Two
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

### 2. Someone paid, and has nothing

In July 2009, Amazon reached into Kindles that people owned and deleted books those people had
bought. The books were *1984* and *Animal Farm*.

Nobody behaved badly. The copies had been uploaded to Amazon's self-service publishing platform
by a company that did not hold the rights to them. The rights holder noticed and said so. Amazon
did what a lawful marketplace is supposed to do when it discovers it has been selling something
it had no right to sell: it pulled the listings, removed the copies, and refunded every buyer. An
authorised edition of *1984* stayed on sale throughout. In the narrow sense that matters to a
lawyer, the system worked.

In the sense that matters to the person who had paid, something else happened. A book they had
bought disappeared from a device in their house, overnight, without their being asked. A student
who had been annotating one of them for a summer assignment woke up to a book that was no longer
there and notes that pointed at nothing. Amazon's spokesman described the mechanism plainly:
"When we were notified of this by the rights holder, we removed the illegal copies from our
systems and from customers' devices, and refunded customers." Six days later the company's
founder wrote, on Amazon's own forum, that the company's solution to the problem had been
"stupid, thoughtless, and painfully out of line with our principles". The apology was real, and
so was what followed: the student's lawsuit was settled for $150,000, and Amazon undertook not to
delete purchased books from devices again except with the customer's consent, on refund, under a
court order, or to remove malware.

Seventeen years later nothing about the underlying arrangement has changed. Only the companies
and the file formats have. The same sentence has since been said in four different markets, and
it is worth hearing it four times, because the point is not any one case.

**Books, again, ten years on.** Microsoft closed the Books category of its store in April 2019.
Its email to customers did not dress it up: "Unfortunately, this means you will no longer have
access to your current ebooks as of July 2019, but you'll get a full refund if you paid for your
ebook download." The refund was real and generous by the standards of the industry: the full
purchase price, automatically, on the original payment method, regardless of how much of the
book anyone had read, plus $25 in store credit for customers who had left notes in the margins.
In early July 2019 the books stopped opening. Microsoft never published a technical explanation
of why a purchased file becomes unreadable when a store closes; the trade press attributed it to
licence validation, and that attribution is theirs, not the company's. Look at what the refund
settled and what it did not. Money returned: one hundred per cent. Books returned: none.
Annotations returned: none — a flat $25, spendable in the shop that was closing. Money is
fungible. The note you wrote in the margin of a particular book is not.

**Film, this year.** From 1 September 2026, Sony's own legal page for PlayStation video content
in the United Kingdom tells customers: "From September 1, 2026, due to our content licensing
agreements, you will no longer be able to access your previously purchased content from Studio
Canal, and it will be removed from your video library." The page lists the affected titles by
name; there are 551 of them, counted from the rows of the table the seller published rather than
estimated — an automated reading of the same page returns a different and larger number, because
it counts series seasons and page furniture along with the titles. The notice does not mention a
refund. This document says what the notice says: whether anyone is compensated in the end is a
different question, and it does not have the answer. Sony had removed purchased StudioCanal
content once before, in August 2022, on the same grounds, and that removal was never reversed
either. Every other case in this section has a second half that softens it. This one, so far, has
none.

**Software, and one step further.** Ubisoft delisted the racing game *The Crew* on 14 December
2023 and said, in its own words: "The game will remain playable until March 31st, 2024, for all
The Crew 1 owners. After this date, the servers will be shut down." In April 2024 something
further happened, and it deserves to be separated from the first two events because the evidence
for it is of a different kind. Buyers found the game gone from their libraries entirely, moved to
a section labelled inactive, no longer installable. For the delisting and the shutdown there is a
dated announcement in the seller's own words. For the revocation of the licences there is a short
message inside the client, photographed by the people it happened to, and no public statement. A
class action followed in California and settled: a fund of two million dollars, seven dollars in
cash or fifteen in store credit per claimant, no admission of wrongdoing, the final approval
hearing set for November 2026. So it is not true that nobody was compensated. It is true that the
compensation took two years and a lawsuit, and arrives at roughly the price of a sandwich. One
thing this paragraph does not say, because its own organisers have said the opposite on the
record: that the European citizens' initiative on the end of life of video games, launched in the
months after that shutdown, would have protected these buyers. It targets games yet to be
developed, not those already sold. Section 7 returns to it on its own terms.

Four markets: books, books again, film, software. Four companies with four different reasons,
some of them good ones. One outcome, repeated: the thing you bought was in someone else's custody
the whole time, and you found out when it left.

That is not a story about video games, or about a bad company, or about digital rights
management. It is a story about a missing object. Every one of those purchases produced an entry
in someone else's database and, at most, an email in your inbox. None of them produced anything
you held. A refund is what a seller offers when the buyer was never holding anything that worked
on its own; it is the remedy for a rental, and most of the people who paid believed they were
buying.

There is one more thing the four cases have in common, and it is the reason the rest of this
document exists. In each of them the buyer's remedy — refund, reversal, settlement — depended on
the seller still being there to grant it, or on a court being able to reach it. The one party
never in a position to establish anything on its own was the person who had paid. What follows
is a way of putting a small, durable piece of evidence in that person's hands.

---

### 3. What you actually bought

When you buy a book in a shop you leave with two things, and rarely notice the second. The first is
the book. The second is the evidence of the deal: a till receipt, a line on a card statement, the
shop's name on the bag, a friend who watched you pay. Nobody thinks of these as part of the
purchase, because the book is its own proof — it is on your shelf, and taking it would mean breaking
in. A digital purchase separates those two things and then keeps both of them. The file, if you are
given one at all, sits behind an account. The evidence that you bought it is a row in the seller's
database, and the confirmation email is a copy of that row, formatted for you, that only the seller
can vouch for. On the day the seller is gone, or disagrees with you, the row is gone and the email
is a document anyone could have written.

What attest gives you is the second thing, made durable and put in your hands. The specification
defines it in one sentence: a receipt "is evidence of a license grant and its terms, signed by the
issuer identified in the receipt". In plain words, it is a small file in which the seller states, in
a form that cannot be altered without the alteration showing, that on this date it granted this
licence, for this work, on these terms, and sealed into it a secret it handed to the buyer. *Signed* means
exactly that: the seller has applied to the file a mark that only the seller can make and that
anyone can check, so that changing a single character inside the file breaks the mark. How the mark
is made and how a stranger checks it is the next section. This section is about what the file says.

Everything inside a receipt is there to answer, years later, a question the seller may no longer be
around to answer. *Who granted it?* The seller, named by its internet domain — the identity that
every key and every check hangs on — and by a display name that carries no weight of its own. *What
was granted?* The title and publisher of the work, the seller's own identifiers for it and, for a
download, a snapshot of what was delivered: each file's name, size and fingerprint, a fingerprint
being a short string computed from a file's contents that changes if a single byte does, so that the
copy on your disk can be matched against the copy you were sold. *On what terms?* Whether the
licence is perpetual or a subscription; whether the seller kept the right to withdraw it, and if so
under which of three fixed classes — never, within a refund window of a stated number of days, or
under a policy the receipt points at; whether it may be passed on; whether the file was sold free of
digital locks; and the licence text itself, which travels beside the receipt and is fixed inside it
by its fingerprint, so that the terms you agreed to cannot be rewritten afterwards. *What happens if
the seller stops?* Whether you were promised the right to download again, and what the seller
committed to at the end of the product's life. *When?* The date of issue, written by the seller. And
*to whom?* — which is the one field that is deliberately not readable, and has its own paragraph
below.

Now the sentence that draws the boundary around all of this, quoted because the specification chose
its words with care: "A receipt is not a claim of 'ownership'; it does not promise access 'forever'
— it promises that the *evidence* verifies indefinitely and that the referenced *terms* remain
producible." Read that against the title on the cover of this document. *Own what you buy* is the
aim; the receipt is the instrument, and the instrument is narrower than the aim. It records what the
seller granted — a licence, with its terms — and it does not turn a licence into anything else. A
seller cannot sign away rights it never had, and a receipt cannot confer them. What the receipt puts
in your possession is the evidence: a thing you hold, that says what the deal was, and keeps saying
it after everyone else has stopped. "Durable, portable, user-held", the three words this document
uses for attest throughout, describe that evidence, not the content it refers to.

Two properties of the file follow from its job. It is immutable: once signed, nothing inside a
receipt ever changes. Everything about a purchase that *can* change afterwards — whether it was
withdrawn, whether the delivered files were updated, whether the seller's keys are still in use —
lives in separate documents that the seller signs and publishes on its own, and that a verifier may
or may not have been shown. That split is what lets a receipt be checked in twenty years without
asking anyone: the receipt is complete in itself. It is also the receipt's blind spot: on its own,
it cannot tell you what happened after it was signed. And the receipt is honest about its own reach.
One for a file sold under a digital lock is allowed, because a receipt is still better than nothing,
but a verifier is required to warn on it and forbidden to present it as something you could use
anywhere else. A receipt never removes a lock, and the specification never claims it does. A receipt
may claim the strongest class, "never withdrawn", only if the file was sold without locks, with a
right to download again, and lists what was delivered — and the specification says of such a receipt
that it is evidence, not a determination that the seller complied with any law; section 7 is where
the law comes in.

The field that names the buyer names nobody. Instead of your email address or account name, the
receipt carries a *commitment*: a fingerprint computed over that identifier together with a secret
the seller generates for that one receipt and hands to you separately. From the fingerprint alone
nobody can recover who you are — the computation is deliberately slow, so that guessing email
addresses against it is not practical — and yet you, holding the secret, can show anyone that you
hold the secret the receipt was sealed with, which is what "proven" means and all it means, as
the next section says. That is why the receipt can be shown to a stranger, posted on a forum or
handed to an archive without exposing you: the shareable file says *someone* bought this; the
secret, kept in a second file, is what says that the holder of that secret is at the door. A
receipt may also carry a public key the seller writes in as yours, for a stronger proof; today,
wherever a purchase happens without an app on the buyer's side, that field is empty by design.
What proving it is yours costs, and what it does not prove, is in the next section.

So what you actually bought, on any store that signs, is two things again, both in your hands. Where
files are sold without locks: the file and the receipt, content plus proof. Where the platform keeps
the file, the receipt would be the same document, and what differs is whether you hold the thing it
refers to — the receipt does not deliver it and is not a backup of it. The difference from today is
not that the file is more yours. It is that the evidence exists, in a form that outlives the counter
it was issued at, and that anyone can read.

---

### 4. How it works

#### What the seller has

A seller who wants to sign receipts needs one thing it probably does not have yet: a **key pair**.
It is two halves of a single mathematical object. The private half stays with the seller and is the
only thing in the world that can produce the seller's signature on a file; the public half can be
given to anyone and lets them check such a signature without being able to make one. A signature is
a short string computed from the private half and the exact bytes of a file, and it checks out only
against that public half and those exact bytes: change the file, or use a different key, and the
check fails. The seller publishes its public half on its own website, at a fixed address every
verifier knows to look at — `/.well-known/attest.json` under the seller's domain — inside a **key
manifest**: a signed list of the seller's keys, each with a name, a period of validity and a status.
The manifest is signed too, so nothing about a key's life can be altered without breaking that
signature. And the seller's identity, throughout, is its domain: every key's name begins with it,
and a key published for one domain can never validate a receipt that claims to come from another.
There is no registry to be listed in and nobody to ask permission from; controlling the domain is
the whole credential — a strength on the day the seller signs, and a limit on the day the domain
changes hands, which section 8 states in full.

Keys are meant to change. A seller retires a key and adds a new one by publishing a new manifest,
numbered one higher than the last, and a verifier that trusted the old manifest accepts the new one
only if it was signed by a key that was in use in the old one — an unbroken chain, so that a
stranger cannot slip in a manifest of their own. A retired key keeps every receipt it ever signed
valid. It does not keep valid the smaller documents it signed beside them — a withdrawal, a
transfer record — which a verifier honours only from a key still in use; section 5 says what that
costs a transfer. A key declared **compromised** — stolen — does the opposite: every signature it ever made is
rejected from then on, and the marking, once seen by a verifier, cannot be unseen or reversed.
Declaring one is a shipped command (`attest manifest rotate --compromise-kid`), and it is the
seller's one lever that reaches backwards; sections 6 and 8 say how far it reaches, and why the
rescue that would bound it stops one step short — the declaration can now be packaged in the form
a verifier reads, and it still cannot be dated.

#### What you get

At checkout, the seller's tools sign a receipt for the purchase and deliver it to you. Both shipped
issuing tools — the command-line `attest issue`, and the bridge that runs beside a Stripe, itch.io
or Shopify checkout and signs on each paid order — can write a copy of the seller's key manifest
into the receipt's unsigned delivery block, so that a single receipt file carries enough to be
verified on its own. Beyond that you get a **bundle**: a `.attest` file, an ordinary zip archive,
containing your receipts, the seller's key and artifact manifests, the licence texts every receipt
refers to — each checked against the fingerprint the receipt fixes it with, at the moment of export,
because a receipt whose terms can no longer be produced is a signature without a deal — and a
README, generated in plain language, explaining what the bundle is, how to verify it even if the
store no longer exists, and which file must not be shared. That file is yours to copy, back up and
hand around.

Beside it is a second file, `<name>.private.attest`, and the name is the warning. It carries the
secrets that bind each receipt to you — the salt for every receipt, and any buyer keys — and nothing
else; the shareable bundle has those secrets stripped from every receipt inside it. Share the first
file with anyone. Keep the second with your own things: a conforming tool must warn you every time
it reads it, and the shipped one does. To show one purchase to one party, `attest disclose` writes a
single receipt with its own salt and manifests — never your whole library, because a library's
secrets, disclosed together, prove every purchase in it at once.

#### What a stranger checks

Now the other side of the counter: a marketplace honouring old purchases, an archive, a court, your
own future self. A **verifier** takes the receipt bytes and the seller's key material and answers
five questions, separately and in a fixed order — never one yes-or-no, because the five are
different kinds of fact and collapsing them is how a green tick lies. *Is the signature genuine?*
Did the seller's key, and no other, sign exactly these bytes. *Is the receipt well-formed?* Does it
carry every field the standard requires, in the form it requires. *Has it been withdrawn?* As far as
the verifier has been shown: shown nothing, it answers "unknown", and unknown does not fail the
receipt. *Has anyone proved they hold the secret it was sealed with?* Only if someone tried;
otherwise "not checked". *Where
did the keys come from?* The question that decides how much the first answer is worth. From those
the verifier states one summary word, `ok`, which means: signature genuine, receipt well-formed,
nothing shown says it was withdrawn or passed on, and no error. Binding and key provenance are
reported beside it and never folded into it. The honest reading of a green result, in the project's
own words elsewhere, is "the signature is genuine and nothing I was shown says otherwise" — which is
not the sentence "this receipt is valid today".

Offline is not a mode you switch on; it is the only mode there is. Neither implementation contains
any code for talking to a network: the verification libraries in both languages and the command-line
tool cannot fetch anything. The verifier on the project's website is a page that runs entirely
inside your browser. Its content-security policy — the instruction a page gives the browser about
what it may connect to — forbids every host but the one the page came from, so the receipt you drop
on it never leaves the tab, and a test in the project's suite fails if a single request goes
anywhere else. Load the page, cut the network, verify. The same verifier ships as a single
downloadable file that opens in a browser from your disk, with the same policy and the same test.
Whichever you use, nothing about your purchase is sent to anyone, including the people who wrote
this.

#### Nobody in the middle

Who validates a receipt, then? Nobody in particular, and that is the design rather than a gap in it.
There is no attest authority, no registry that has to exist, no phone-home. A verifier needs three
things and no server: the receipt bytes, the seller's published key material and, optionally, a feed
of the seller's withdrawal records. The seller publishes its own keys; the tools are free; the
standard is open. The one soft centre is curation. A verifier that wants stronger evidence than the
file in front of it has to have chosen, in advance, which public log keys, which observers and which
block headers it trusts, and somebody has to curate those. The browser verifier ships with one
pinned log key, no pinned block headers and no observer policy, which is why the stronger verdicts
described in section 6 are out of its reach.

That brings the limit that sits beside this whole section, and it is the one to carry away. The
standard reserves its strongest trust level, "verified", for key material fetched over an encrypted
connection from the seller's own domain — proof that whoever controls the domain published these
keys. No tool this project ships performs that fetch: not the command-line tool, not the browser
page, not the downloadable file. Every verification anyone can run today reports the other level,
**trust on first use**: the keys came from inside the file you were handed, or from a manifest you
supplied yourself. The mathematics is exactly as sound either way. What is absent is anyone
confirming who published those keys — so if a stranger sends you a bundle from a shop you have never
heard of, a green result is evidence that the file is consistent with itself, not evidence that the
shop is real. The page says as much beside every result, and section 8 returns to it.

#### Proving it is yours, and what "proven" proves

A copy of the shareable file verifies exactly as the original does, and it is meant to. What a
copy cannot do is answer the question *is this yours?*, and the standard defines two ways to
answer it. The everyday way uses the secret from the private file: you disclose your identifier
and that receipt's salt, the verifier recomputes the commitment and compares it with the one
sealed in the receipt, and the answer is "proven" or "not proven". It works with the shipped
tools — the command-line verifier takes it as options, the browser page has a panel for it, and
the project's own sample demonstrates it. It is also, in the standard's words, "a replayable
bearer proof": whoever you show it to can show it to someone else and be believed, and it hands
over your identifier. Per-receipt salts keep the damage to one receipt, and a verifier is
required to treat the disclosed identifier as personal data not to be kept. The strong way needs
a key signed into the receipt at the time of sale: a verifier invents a fresh challenge, you sign
it with the private half of that key, and the signed answer proves you hold the key without
revealing anything and without being reusable, because the next challenge will be different.
Both implementations know how to check such an answer, and the command-line tool now runs both
halves of the exchange: one command mints a fresh challenge, another signs it with the buyer's
key. What has not moved is the key. It is empty by default on every receipt issued without an app
on the buyer's side, and today that is every receipt. So the exchange is shipped and has nothing
to run against, which is a different problem from the one this document used to report: the proof
a buyer can actually perform is still the disclosure, and the stronger one is specified, checked,
executable, and waiting on a receipt that carries a key. Nothing obliges a verifier to ask for either; one that
never asks sees a copy and an original as the same file.

Now the sentence this document is careful about everywhere, because it is the one a green result
invites you to misread. "Proven" means that whoever is presenting the receipt holds a secret that
reproduces a value the seller wrote into it — the salt, or the private half of the key. It does
not mean that the person the receipt names took part in the purchase. Every input to both proofs
is chosen by the seller: the seller generated the salt, received the identifier, and wrote the
public key into the receipt it then signed. A seller that wanted to say "this person bought this"
could mint a key of its own, write it in as the buyer's, and later hand any verifier a disclosure
that reads "proven"; the mathematics would be flawless and the statement false. The specification
places a dishonest seller outside its scope — attest proves what a seller signed, not that the
seller is honest — and it already forbids a verifier from treating the same key on two receipts
as proof that the same person bought both. What this document adds is the plain reading: a
binding proof establishes possession of a secret, and the seller's word is what connects that
secret to a person. The standard now says exactly that in its own text, and goes one step further
than a reader of an earlier draft of this document would expect. v0.1 §8 closes by stating what a
proven binding establishes — possession, by the party presenting the disclosure, of a secret that
reproduces a value the issuer wrote into the payload — and what it does not: the buyer's
participation at the moment of sale. v0.1 §11.1 then turns that into a rule a *display* must obey:
a conforming rendering surface must not present "proven" as evidence that the person the receipt
names made the purchase, nor "not proven" as evidence that whoever is presenting the receipt is
not the buyer. Nothing on the wire moved with either sentence — no field, no algorithm step, no
result value — because both state a property the two mechanisms already had and bound what may be
claimed from it. The project's threat model catalogues the case as TM-78, and its verdict is
honest about the shape of the fix: the claim is narrowed, the fabrication is not prevented. A
further addition is planned and not yet specified: a buyer's own signature over the terms of the offer,
carried inside the receipt, so that a seller whose key was stolen, or who was coerced, could not
issue a receipt in a buyer's name without that buyer's key having agreed to the deal. No receipt
carries it today, it would remain optional, and section 13 says what it would and would not
close.

#### Withdrawing a receipt

A receipt can be withdrawn only within the class the seller sealed into it at the moment of sale,
and the instrument is a **revocation record**: a separate, small, signed document naming the
receipt, saying "revoked" and carrying its own signed time. A verifier honours such a record only if
it was signed by a key currently in use — a record from a retired or a stolen key is ignored, with a
warning, never obeyed — and then applies the class. "Never" means the record is refused and the
receipt stays good, however genuine the signature: the verifier enforces the seller's promise
against the seller. "Refund window" means the record counts only if its own signed time falls within
the stated number of days after issue; the verifier never consults its own clock, which the seller
or the buyer could set to anything. "Policy" means a correctly signed record is honoured as it
stands, because the verifier cannot read the terms it refers to. Shown no records, a verifier says
"unknown"; shown records that name other receipts, it reports the date of the freshest one it could
authenticate, so that you know how current its picture is. There is no appeal inside the protocol
and no reason is ever recorded; and a withdrawal does not reach your disk, a point section 9 comes
back to.

That is the mechanism as the verifier evaluates it, and it is complete in both implementations. For
most of this project's life it was also a mechanism no seller could carry out, and earlier drafts of
this document said so. That has changed, and the change is recent enough that it is worth being
exact about what it did and did not fix. The command-line tool now signs a revocation record —
`attest revoke` — and refuses to sign one a verifier would only ignore: against a receipt the seller
sealed as irrevocable, with a date outside the window it declared, or with a key no longer in use.
A second command, `attest revocation-view`, packages signed records into the array a verifier reads.
That second one matters as much as the first, because a record nobody can hand over in the shape the
standard expects is a signature in a drawer. Read off the tool's own definition rather than off a
list of what one would expect to find, its top-level verbs are now `authority`, `binding`,
`check-artifact`, `disclose`, `export`, `grant`, `import`, `inspect`, `issue`, `keygen`, `log`,
`manifest`, `revocation-view`, `revoke`, `transfer` and `verify`.

What has not changed is where a withdrawal actually bites, and the tool is the one that says so.
Sign a refund-window record and it prints a warning before it writes the file: a verifier that
weighs log evidence will disregard this record unless the record was itself logged and timestamped
before the deadline — and the warning names the command that would log it. The last link in that
chain is the subject of the next paragraph and of section 6. Beside the tool, the service that runs
next to a checkout refuses to issue for an order already marked refunded or cancelled, which is the
easy half of a refund; it has no path at all for a refund that arrives *after* a receipt has gone
out, which is the half that would need the command above. And on the verifier's side: the browser
page and the downloadable file never go and *fetch* a seller's withdrawal records, and could not —
the policy described earlier in this section forbids them any host but the one the page came from
— though either will consult a revocation file you drop onto it yourself. Unless somebody hands one
over, the answer there stays "unknown"; and even handed one, a
verifier configured as those two are — one public log key pinned, no block headers pinned — could
not honour a refund-window withdrawal, for exactly the reason the tool's own warning gives. Read
every sentence about revocation in this document, then, as a rule the verifier enforces and a seller
can now perform, on receipts that nobody has yet issued.

One more producer used to be missing under the two above, and it has arrived. The standard lets a
receipt's existence be recorded in a public, append-only log, so that it can later be dated by the
clock section 6 describes; it is what the rescue against a stolen key, and the logged refund window
just mentioned, both start from. The log commands used to be the log operator's alone — create a
log, append an entry handed over as a file, sign a checkpoint, emit a proof — and none of them
computed the entry a receipt would need; the only code that did was the generator of the project's
own test fixtures. Two things now do. One command computes the entry for a signed document, a
receipt among them, ready to be appended. And the issuing command takes an option that appends the
receipt's own entry to the seller's log in the same act that signs it, without either half touching
a network.

The step after that one is where the gap now sits, and it is worth naming precisely rather than
inheriting the older, larger complaint. Turning a log into a *date* needs the public attestation
section 6 describes, obtained outside the tool, and a set of block headers to check it against that
nothing ships with anything. So a receipt can be logged today and still cannot be dated by anyone
who has not assembled that last part alone. Everything built on logging — the rescue on the
seller's worst day, the logged refund window — waits on that step and on nothing else.

What can and cannot be done today, in one place. A buyer can receive a receipt, keep it, verify it
offline at trust on first use, show they hold its binding secret by disclosure, answer a fresh
challenge with the buyer key where the receipt carries one, sign the authorization that starts a
transfer, and share a single receipt safely. A seller can generate keys, publish and rotate a
manifest, declare a key stolen and package that declaration in the form a verifier reads, issue
receipts by hand or from a checkout and enter them in its own log as it signs them, withdraw one
and hand the record over in the shape a verifier expects, export bundles, counter-sign a transfer,
and sign a preservation pledge.

What neither can do is put a *date* on any of it. That is now the single missing link, and naming
it as one link rather than as a list is the honest description of where this project stands: the
public attestation has to be obtained outside these tools, and no curated set of block headers to
check it against ships with anything. Every defence in this document that turns on *order* rather
than on signature — the rescue on the seller's worst day, the logged refund window, an old
manifest beating an opportunistic new one — waits on that link and on nothing else. There is one
further absence, and it is a fetch rather than a command: no tool here goes to a seller's own
domain for its key material, so the strongest trust level stays out of reach, as the paragraph
before last said. The rest of this document keeps what is shipped and what is specified apart, and
from here the second list is short enough to hold in mind.

> **In detail: the algorithm, the vocabulary, the two files, and each input's producer.** A
> conforming verifier runs v0.1 §11 in order and stops at the first rejection: (0) parse the bytes
> once, under the restricted canonical JSON profile, and use that one object everywhere; (1)
> envelope well-formedness — a supported `attest_version`, exactly one entry in `signatures`, `alg`
> equal to `"Ed25519"`; (2) issuer binding — the signing key is resolved *only* from the trust
> store's manifest for `payload.issuer.id`, and both the key's domain prefix and the manifest's own
> `issuer` must equal it; (3) key checks — the key is present, its status is not `compromised`
> (unconditional for a verifier that cannot evaluate log evidence; the v0.2 §19 cutoff applies only
> to one that can), `issued_at` lies inside the key's validity window, and a `retired` key continues
> with a warning; (4) the Ed25519 signature over the canonical payload; (5) the JSON Schema; (6)
> revocation, only if a view was supplied; (7) binding, only if a disclosure was supplied. The
> result is five components with fixed literals (v0.1 §11.1): `signature` valid/invalid; `schema`
> valid/invalid/not_checked; `revocation` unknown, `not_revoked_as_of:<T>`, revoked,
> invalid_revocation_ignored, and, under v0.2 §17.3, transferred; `binding`
> proven/not_proven/not_checked; `trust` verified/unauthenticated_tofu/unverified_rotation. `ok` is
> signature valid *and* schema valid *and* revocation neither revoked nor transferred *and* no
> errors; `trust` is resolved as soon as the issuer can be read and is never reset by a later
> failure, and it is `verified` only when the trust store's provenance for that issuer is `"tls"`. A
> key manifest (v0.1 §7.1) carries `issuer`, a monotonically increasing `manifest_version`, `issued_at`,
> the `keys[]` entries — `kid` of the form `<domain>/keys/<label>#<name>`, `pub`, `valid_from`,
> `valid_to`, `status` in active/retired/compromised — and a `manifest_signature` over the rest;
> continuity (§7.3) requires manifest N+1 to be signed by a key active in N, and `compromised` is
> absorbing. The `.attest` bundle (v0.1 §14.1) holds `receipts/*.attest.json` with `delivery.salt`
> stripped, `manifests/<issuer>.json`, `legal/<sha256>.txt` verified against each receipt's hash
> bindings at export, an optional `proofs/` member (v0.2 §14), and `README.html`; the
> `.private.attest` sibling (v0.1 §14.2) holds `salts.json` and, if used, `keys/`. A receipt's `delivery`
> member (v0.1 §4.2) is unsigned, may carry the salt and a manifest snapshot, and cannot forge or
> invalidate anything. Now the completeness check this document applies to every defence: for each
> input the shipped `attest verify` accepts, who produces it. `--trust-dir`: manifests from
> `manifest init`/`rotate` or an imported bundle — shipped, and the tool records their provenance as
> `bundle` unconditionally, so `verified` is unreachable from it. `--revocations`: the array a
> verifier reads — `revocation-view`, shipped; `transfer record --revocation-out` still emits the
> `status: "transferred"` member of the same family. `--transfer-view`: `transfer view` — shipped.
> `--compromise-view`: `manifest compromise-view` — shipped, and for every claim and every key it
> marks stolen it reports whether the claim establishes the status floor, whether its signer could
> date a cutoff, whether it carries any anchor material, and whether a cutoff is established — the
> last answerable only by a caller who supplies log keys and a header policy. `--disclose-identifier`,
> `--disclose-type`, `--disclose-salt`: the salt comes from `issue --salt-out` or the exported
> `salts.json` — shipped. `--disclose-challenge-nonce`, `--disclose-challenge-sig`: `binding
> challenge` and `binding respond` — shipped, the second being the buyer's side of the exchange
> that used to exist only as a library call with no caller.
> `--transparency` and `--revocation-evidence`: `log entry` computes the entry for a signed
> document, a receipt among them; `issue --log-dir` appends a receipt's own entry in the act that
> signs it; `log append` and `log sign-checkpoint` advance the log; and `log prove` emits the
> evidence bundle, finding a receipt by its core hash rather than by an index the caller would have
> to know. `--log-keys`,
> `--anchor-policy`, `--crqc-horizon`, `--witness-policy`: verifier configuration the caller
> supplies; no pinned block headers ship with anything. `--grant-view`: `grant issue`, `grant
> declare` — shipped. `--authority-view`: `authority issue` — shipped. `--reject-trust`: the
> caller's own policy, not a document anyone signs. One producer is left without a shipped source,
> and the tool says so in its own help rather than leaving it to be discovered: `log anchor`
> attaches anchor material *obtained outside this process*, because acquiring a Bitcoin attestation
> is out of the tool's scope and it never touches a network, and `log ots-convert` converts a path
> only against a block header the caller already holds. The browser verifier passes one pinned log
> key, an anchor policy whose set of pinned headers is empty, and as its revocation view whatever
> the visitor has dropped on the page — `null` when nothing has been;
> its page-level policy is `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'
> data:; connect-src 'self'; base-uri 'none'; form-action 'none'`, and its end-to-end suite asserts
> that verifying the sample produces no request to any host but its own, that the sample reports
> `unauthenticated_tofu`, that salt disclosure reaches `proven`, and that a tampered receipt is
> refused.

---

### 5. The trilemma

A file copies perfectly. Every copy of a film is the film, and every copy of a receipt file is,
byte for byte, the receipt. So the question a careful reader asks at this point is the right one:
if the receipt can be duplicated as easily as the thing it is a receipt for, in what sense is it
*mine*?

Physical goods answer that question with scarcity. There is one copy of the book; it is in one
place at a time; handing it to someone means no longer having it. Nobody enforces this. It is
simply what objects are like. Digital goods have no such property, and every attempt to give it to
them has been an attempt to build the scarcity back in by force.

To see what such an attempt costs, name the three things people want at once from a digital
purchase — precisely, because loose names are how this argument slides. **It copies freely**: the
file and the proof are plain data, copying them is no offence against anything, checking them
needs nobody's permission, and no lock sits on the work. **It is theirs and not everyone's**: one
buyer, one copy in use, which is what makes paying for it sensible. **It outlives the shop**: the
bookshop closing does not empty the shelf at home — and in the strict sense this project has
always used, it outlives the log, the network, and the people who wrote the standard too. Free
copying, exclusivity, survival. A physical purchase gives all three without trying. A digital
purchase cannot give all three at full strength, and the reason is not a missing piece of
engineering. Notice that the first property is not "you can pass it on". Passing something on is
an exclusive handover, in which one holder loses what another gains, and a design can be
perfectly transferable and still be a lock — that is what the market in enterprise licence
transfers is. The property in question here is that the proof duplicates without loss.

Any two of the three are easy, and each pair has a shipped example. Free copying and survival,
without exclusivity, is attest today: a signed file, no lock, no arbiter. Exclusivity and
survival, without free copying, is the encrypted work whose key travels with the licence; it runs,
in content-addressed stores and in the ebook trade, and the price is that the work is locked.
Free copying and exclusivity, without survival, is the live arbiter — a server that answers "may
this run now" — which is how the only concurrency control ever shipped at scale works, and it
dies with its operator. The triple fails, and it fails for two reasons that no better signature
scheme, no better log and no different substrate changes.

The first is that a verifier working offline, from signed documents and an append-only record,
can decide only facts that stay true once they are true. *This key signed these bytes.* *This
transfer was recorded before that one.* *This receipt was timestamped before that declaration.*
Every mechanism in this standard manufactures more facts of that kind. "Nobody else is using this
right now" is not a fact of that kind: it can turn false and true again without any document
being created, because what would have to be recorded is a non-event, and no quantity of signed
history records a non-event. A public log makes such facts faster to establish, never a current
one; consulting a chain at the moment of use is consulting a live arbiter under another name. So
the corner that gives is exclusivity, never survival. The literature on payments made without a
network reached the same place decades ago: the classic construction for digital cash spent
offline does not prevent a coin being spent twice, it honours the second spend and then unmasks
the spender. A receipt whose exclusivity is a term of the licence, backed by a recorded transfer
chain that anyone can audit, is in that family, not short of it.

The second reason is the one that decides the matter, and it is about repair. The weaker half of
exclusivity — the work is unusable without a receipt — *is* buildable with nobody alive: encrypt
the work, and put the key where only the receipt's holder can reach it. But a lock has exactly
one known repair when its secret leaks: somebody still alive changes the secret. The one
published scheme that turns a purchase into a decryption key is candid about this. It promises
that a book still opens years after the bookshop is gone, and it keeps that promise by keeping a
certification authority alive to reissue its cryptographic material — which it has already had
to do once, after that material was breached. A receipt built to still work when *everyone* is
gone has nobody left to do that. The first holder who extracts the plaintext ends the lock for
that work, for everyone, permanently, because there is no channel left to reach the copies
already in circulation; what remains is no protection in fact, and a lock on every copy whose
standing an independent player would then have to worry about. Survivability does not merely
conflict with enforcement. It removes the only known repair for a broken lock. That is why the
standard defines no encryption, carries no copy of a work, and forbids being used or marketed as
a way to strip protection from one: not as a preference, but because a lock of that kind is a
promise this project could never keep.

attest's choice follows from that and holds throughout the document. Survival is not negotiable.
Exclusivity is weakened, deliberately, from a physical fact into a term of the licence that can
be checked and refused. That sentence needs unpacking, because the difference is the whole
design.

Two things make the weakened form more than words. The first is that a receipt can carry a key
the seller writes in as the buyer's, so that a copy of the receipt file, on its own, proves
nothing about who holds that key: when it matters, a verifier can put a fresh question that only
the holder of the key's private half can answer, and the answer is useless for any other
question. Who the key belongs to is, today, the seller's word, as section 4 said. The second is
that the holder can change only through a **transfer**, and a transfer is not something two
buyers do between themselves. You sign an authorization with the key in your receipt; the seller
counter-signs it, retires your receipt, issues a new one to the new holder, and records the
transfer in its public log. If two transfers of the same receipt ever appear, the one recorded
first wins and the second is reported as a conflict. So a duplicated receipt fails exactly where
a copy would otherwise be useful — at resale, at a successor's desk, at an archive that hands out
files only to buyers, at a support counter — because none of those parties will accept a receipt
whose holder cannot answer for it or whose transfer was never recorded.

And here is the limit, next to the promise it limits. The key is a file too, and it copies. Two
people who share a receipt and its key share access, the way two people share a password: attest
does not prevent that and does not try to. Using a duplicated receipt in two places at once is a
breach of the licence that an honest player or marketplace can detect and decline to honour; it
is not an impossibility, and this document will not call it one. Detection itself is conditional
today: it rests on the seller's log being one log, seen the same by everyone, and that guarantee
is not yet backed by independent observers (section 8). And a transfer needs the seller alive to
counter-sign it, which is the trilemma biting back on the very corner attest chose to protect:
today, when the seller goes, transfers stop, and every receipt holds to its last recorded holder.
Making transfer authority outlive the seller is the hardest open problem on the project's list,
and it is named there rather than promised here.

Two further limits on transfer are measured on the code, not inferred, and they are stated here
because a reader would otherwise take more from the paragraphs above than they give. The seller's
terms say whether a receipt may be passed on, and that field is a signed statement the verifier
that honours a transfer never reads: the gate it applies is the holder's key and the log, so
"transferable where the seller allows it" is, today, a term the seller signs and the parties
honour, not a rule the verifier enforces. And a transfer, once counter-signed and recorded, is
only as durable as the seller's signing key is *current*: a verifier honours a transfer record
only while the key that signed it is still in use, so the ordinary act of retiring a key and
adding a new one — routine, section 4 said — silently un-honours every transfer that key
counter-signed, and the old receipt reverts to its previous holder while the new one stays valid.
Marking that key stolen rather than retiring it does the same thing, and needs no thief: anyone
holding any still-current key of the same seller can do it. Say plainly what that leaves, because
it is worse than "a transfer that stops holding". Both people end up with a receipt that verifies
and reports `ok`: the one who sold and the one who bought. Nothing either of them can see in
their own file says otherwise, and only an audit of the recorded chain of title, or the seller
re-issuing the transfer under a current key, tells them apart. The project's threat model
catalogues this as TM-80, and — this is the part worth pausing on — the outcome is now pinned by
a case in the public conformance corpus as the *intended* one, so that a verifier cannot quietly
"repair" it. The reason for pinning it is a lesson about verification itself: two independent
implementations agreeing is not a safety net when both can reach the same wrong answer by
different routes, and a behaviour that no document declares is indistinguishable from an
accident. The rule that would close it — judge a transfer record against the key's validity
window at the moment the transfer was signed, not against the key's status today — is declared
work in the specification's own record, and until it is written this document does not say that a
transfer holds.

So the right picture is this: a receipt is a key to a door, never to a file. It does not open
anything on your disk; a player that ignores your receipt still plays your file. What it opens is
a door with someone behind it who checks. The archive that owes you a copy under a publisher's
pledge checks it before handing one over. The seller checks it before moving your entitlement to
someone else. A court, a successor, a support desk check it before taking your word. One receipt,
one legitimate holder is a term of the licence and a record anyone can audit — not a law of
physics, and this document does not pretend otherwise. Delivery gives you the bytes. It does not
give you standing, and standing is what evaporates today. None of this solves the trilemma, and
no solution is promised: it is the corner of it this project chose to stand in, with the reason
written down.

> **In detail: the two bindings, the transfer rule, and which tools exist.** A receipt binds to
> its buyer in one of two ways (v0.1 §8). The default, for sales with no buyer-side app, is a
> *commitment*: a one-way fingerprint computed over an identifier such as an email address and a
> secret salt, so that the receipt names nobody in the clear. Proving it means disclosing both
> identifier and salt (`attest disclose`), and that proof is a bearer proof: whoever sees it can
> replay it (§8.1). The strong form is an Ed25519 public key in the signed receipt, `buyer.pubkey`,
> proven by challenge-response over a fresh nonce (§8.2) — non-replayable, and optional, `null` by
> default where there is no client. The key is written into the payload by the issuer, so
> `binding: "proven"` establishes possession of the key's private half and never the buyer's
> participation (section 4). Transfer requires the strong form: a v0.2 receipt that claims
> `license.transferable: true` with no `buyer.pubkey` is a schema error (v0.2 §17.8). Transfer is
> issuer-mediated by design, never buyer-to-buyer (§17); the outgoing holder's authorization is a
> signature by that key over a domain-separated preimage (§17.1) — control of the key the issuer
> recorded, never the consent of the person, which is why the specification renamed the gate it
> feeds from "consent gate" to *key-authorization gate*, the old name having asserted what the
> mechanism does not establish — and it is what permits
> extinguishing even an otherwise irrevocable receipt (§17.3); a transfer record is honoured only
> when its inclusion in the issuer's transparency log is proven (§17.2); two logged records for the
> same receipt are a double assignment and the earliest log index wins (§17.4); walking the chain
> of title is a separate audit surface with fixed, byte-identical diagnostics (§17.5). What is
> shipped, on the command-line tool: the holder's side of a transfer (`transfer
> authorize`, which signs the outgoing holder's authorization with the buyer's own key), the
> issuer's side (`transfer record`), the packaging that lets a verifier be handed the result
> (`transfer view`), the log operator's commands (`log`), and the redemption
> challenge for a preservation pledge (`grant challenge`, `grant respond`, `grant verify`, §18.7).
> The ordinary binding challenge for a receipt — the "prove this is yours" exchange described in
> section 4 — has both its halves as commands now, `binding challenge` and `binding respond`, and
> the second refuses a seed that is not the key the receipt names rather than producing a proof
> that verifies against nothing; what the exchange lacks is not a command but a receipt carrying a
> non-null `buyer.pubkey`, and that field is null by default wherever there is no buyer-side app,
> which is everywhere. "One legitimate holder at a time" is therefore a licence term enforced by honest
> clients, and by issuers and markets refusing a receipt that fails it; the protocol supplies the
> evidence and never the enforcement. Two measured facts bound the profile as shipped:
> `license.transferable` is not read on the path that honours a transfer record (every combination
> of receipt version and flag with a non-null `buyer.pubkey` yields `transferred`), and a transfer
> record authenticates only while its signing `kid` is `active` (§17.1 mirrors v0.1 §12.1), so a
> `retired` — or `compromised` — key un-honours it and the old receipt returns to
> `revocation: "unknown"` with `ok: true`, while the new receipt keeps `ok: true` of its own: one
> purchase, two green receipts, invisible to any verification of a single receipt and visible only
> to a chain-of-title audit (v0.2 §17.5). The two markings are one mechanism, threat model TM-80 says
> so, and neither one's consequence for a completed transfer has been decided; a rule that
> judges the record against the key's validity window at `transferred_at` is declared work and not
> yet specified. The corpus pins the compromised variant as intended rather than accidental, so an
> implementation that honours the record anyway is non-conforming and not improved. The three
> properties named above, the two arguments for why
> the triple fails, and the recommendation that no specification change follow from them are the
> subject of the project's research record of 5 September 2026; the door the receipt opens is the
> normative precondition a custodian checks before serving bytes (v0.2 §18.7) and the
> key-authorization gate a transfer passes through (§17.3), both shipped.

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
on means clearing all three. The first has recently become easy: the command that issues a receipt
now takes an option that enters that receipt in the seller's own log in the same act that signs it,
so the log entry is no longer a separate operation performed by hand afterwards. The second has not
moved, and it is the one that decides the matter: the attestation that turns a log into a *date* is
obtained outside these tools. The tool says so in its own help and never touches a network — what
it does is attach the material once someone has gone and got it. The third sits on the reader's
side of the counter: the verifying libraries in both languages ship with the check switched off
unless the caller supplies log keys and a header policy, and the block headers a verifier would
need in order to check a timestamp are distributed with nothing. No curated set of pinned headers
ships in either package.

That includes ours. The verifier on this project's own website — the one anyone can drop a file
into — is wired for the check and carries an empty set of headers, so it cannot establish a
timestamp either.

There used to be a further gap on the seller's side, and it has closed — which sharpens the
remaining one rather than removing it. To use the rule above, a verifier has to be shown the
seller's compromise declaration in a particular authenticated form. Both implementations know how
to consume that form, and a shipped command now produces it: it pairs the declaring manifest with
its log evidence and reports, for every claim and every key that claim marks stolen, what that
claim is actually capable of — whether it sets the status floor, whether its signer could date a
cutoff, whether it carries any anchor material at all, and whether a cutoff is in fact
established. Those four are independent on purpose, and the fourth is answerable only by a caller
who supplies log keys and a header policy; without them the command answers three questions out of
four, and the fourth is not a question anyone can answer today. Which is the same missing link: a
seller who discovers a
theft can package the declaration and cannot date it, so the cutoff the rule needs never comes into
existence. And the order in which these gaps are closed matters: honouring
timestamped receipts before anyone has timestamped a declaration would not protect buyers, it would
protect everyone whose receipt carries a timestamp, a thief's forgeries included, because no cutoff
would exist to stop them. The declaration has to be timestamped first.

The summary is this. The clock exists, matches its specification in both implementations, and the
defence it provides — the one that saves your receipt on the seller's worst day — currently protects
no one who has not gone and fetched the last piece of it themselves. Since no store issues receipts yet, the
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

### 7. Two tracks, one standard

Nobody forces a seller to issue one of these. That is true, and it is the reason there are two
routes rather than one — and why neither of them is a hope.

**The first track works today and needs nobody's permission.** Wherever files are sold without
locks — the DRM-free catalogues, itch.io, publishers selling direct from their own site — the
buyer already walks away with the file. A seller there can add the receipt this afternoon. The
project ships a small service that runs beside an existing checkout — Stripe, itch.io and Shopify
are the ones it speaks to — and turns each paid order into a signed receipt delivered to the buyer.
No platform has to agree, no regulator has to act, and there is no central service to join. The
seller's reason is commercial: "what you buy from me stays yours, even if I disappear" is a selling
argument, and a whole DRM-free brand was built on the first half of it.

Two limits sit next to that. No seller does this yet: the service exists, and the first store that
runs it does not. And the service handles only the easy half of a refund — an order already marked
refunded or cancelled is skipped, so no receipt is issued for it, but nothing in the service reacts
to a refund that arrives after a receipt has gone out. The seller would have to withdraw that
receipt by hand, with the command-line tool, which can now do it; joining the two is work nobody
has done, because nobody is running either (section 8).

What the receipt adds to a file you already hold is what section 5 said the file lacks. A
DRM-free download is anonymous. The receipt makes the purchase itself something that can be
referred to, years later, without the seller's help: when the licence is meant to be passed on;
when a publisher's preservation pledge fires and buyers have to be told apart from the general
public; when a seller's successor, or a court, asks who bought what. Delivery gives you the bytes.
The receipt gives you standing.

**Closed platforms are the second track.** On a console, a locked storefront, a streaming library,
you cannot download the thing and keep it; the platform holds it, and that will not change because
someone published a file format. What can change is what the platform hands you at the moment of
purchase, and what it must honour when a service ends. This track does not run on persuasion. It
runs on a law that already exists.

You already know that law from its effect. The confirmation email after every online purchase is
not a courtesy. In the European Union, a trader who sells at a distance must give the consumer
confirmation of the contract concluded, on a *durable medium*, within a reasonable time and at the
latest when the goods are delivered or the service begins: Directive 2011/83/EU of 25 October 2011,
Article 8(7). A durable medium, in Article 2(10) of the same Directive, is any instrument that lets
you store information addressed personally to you, keep it accessible for future reference for as
long as the information is needed, and reproduce it unchanged. That definition is why the
confirmation arrives as something you can keep, rather than as a page that vanishes when you
close it.

An attest receipt is not that confirmation, and this document does not claim it is. The
confirmation the law requires must carry the information the trader owed you before the sale
(Article 6(1)); a receipt carries the purchase — same seller, same date, the terms of the licence
— and not the trader's terms of business. What a receipt is, is a form that confirmation could
include or travel in: one a machine can check and you can carry away. What a regulator would be
asked for is not a new obligation but a usable format for one that already exists.

The objection to make here is the honest one, and it deserves a straight answer: the email already
satisfies Article 8(7), so this is a solution looking for a problem. The email does satisfy it.
Nobody in this document claims otherwise, and a receipt on its own does not discharge the
Article, as the paragraph above said. What the format adds
is a requirement on the *form* of an existing obligation, not a new duty — that the confirmation be
checkable by someone other than the sender. The reason that is worth asking for is the whole of
section 2: a confirmation only the sender can authenticate is worth exactly nothing on the day it
is needed, which is the day the sender is gone, or disputes it. The test the format is written to
pass is this. After the trader has ceased to exist, a third party holding nothing but the file and
the trader's published key can establish, offline, that this trader issued it, to whom, for what,
and on what date.

The other objection arrives at the same point every time, and it is a good one: *if a client is
open, a receipt check can simply be left out; if a client is closed, you cannot make the platform
do anything.* The first half is true, and section 5 conceded it in full. The second half misreads
what is being asked. A closed platform already checks who is entitled to what, millions of times a
day, and is extremely good at it. What is missing there is not enforcement. It is portability and
survivability — the fact that what you bought lives only inside that platform's account system and
dies with it. The ask is therefore much smaller than "open your platform". It is: sign what you
already confirm, in a format that outlives you. No lock has to be removed, no catalogue opened,
nothing run by anyone after the sale.

Now the state of play, told at the low end and with dates, because a reader who is promised a
regulator will go and check.

In Brussels, the European Commission replied on 16 June 2026 to the citizens' initiative *Stop
Destroying Videogames*, which had gathered over 1.29 million valid signatures and met the threshold
in 24 member states. The Commission said that at this stage it cannot propose a legal obligation
to keep video games playable after they stop being sold, citing among other things existing
intellectual property rights. What it committed to, by the end of 2026, is to start an exchange
with the games industry and consumer representatives with the aim of drawing up an industry code
of conduct on the end of life of games; to work with consumer organisations on awareness of the
rights that already exist; and to report on the application of the Digital Content Directive
before the end of the year. What is due by the end of 2026 is the beginning of a conversation, not
a code and not a rule. The press release announcing the reply does not mention proof of purchase.

In California, Assembly Bill 2426 — signed on 24 September 2024 as Chapter 513 of the Statutes of
2024, in force since 1 January 2025 — is the closest thing on the books to the concern this
document is about, and it is a disclosure law. A seller who advertises a digital good with the
words "buy" or "purchase" must either obtain the buyer's acknowledgment, at the time of purchase,
that what they are getting is a licence, with its restrictions listed, and that the seller may
withdraw access if it loses the right to the work — or state clearly and conspicuously that
"buying" it means buying a licence, with a link to the terms. The law exempts
any digital good the seller cannot revoke access to after the transaction, and it says what that
includes: making the good available at the time of purchase for permanent offline download to an
external storage source, to be used without a connection to the internet. Two things in that are
worth noticing. A legislature, on its own, drew the same line this document draws between the two
tracks: the download is what the law treats as beyond revocation. And the law changes what a
seller must *say*, not what a buyer gets to *keep*. Neither the Commission's reply nor the
California statute asks for a receipt. No regulator has asked for this format.

One standard serves both tracks because the receipt is the same file on both. On the first, a
seller signs it because it sells. On the second, a platform would issue it at purchase and honour
it at the end of a service's life, the way it honours its own entitlements now — under an
obligation, not out of goodwill. The parts the second track needs are paper: an open
specification, two independent implementations, a public conformance suite, a draft before the
standards body. They are cheap to keep ready, and they are ready. Whether anyone points at them is
not up to this project. The second track runs on a slower clock, and nobody here sets it.

> **In detail: the texts, and what is and is not claimed from them.** Article 2(10) of Directive
> 2011/83/EU defines "durable medium" as "any instrument which enables the consumer or the trader
> to store information addressed personally to him in a way accessible for future reference for a
> period of time adequate for the purposes of the information and which allows the unchanged
> reproduction of the information stored". Article 8(7) requires the trader to "provide the
> consumer with the confirmation of the contract concluded, on a durable medium within a reasonable
> time after the conclusion of the distance contract, and at the latest at the time of the delivery
> of the goods or before the performance of the service begins", and that confirmation must include
> all the information listed in Article 6(1) unless already given on a durable medium — which is why
> this document does not claim that a receipt alone discharges the Article. The Commission's reply
> to *Stop Destroying Videogames* is press release IP/26/1369 of 16 June 2026 ("the Commission
> considers that at this stage it cannot propose a legal obligation to keep video games playable
> after they stop being provided commercially"); the three commitments are quoted from the same
> release. California AB 2426 added section 17500.6 to the Business and Professions Code; the
> exemption is subdivision (b)(4)(C), and its wording on "permanent offline download to an external
> storage source to be used without a connection to the internet" is quoted from the codified
> text. On the seller's side, the first track is exercised with the shipped issuing tools (`attest
> issue` and the bridge's Stripe, itch.io and Shopify adapters) and the shipped transfer commands;
> declaring a key compromised is a shipped command too (`manifest rotate --compromise-kid`);
> revoking a receipt, packaging a compromise declaration in the form a verifier needs for a cutoff,
> and anchoring are not (sections 6 and 8). Nothing on the second track is a tool: it is a
> conformance profile and an argument, and this document says so.

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

Getting there is opt-in at every step, and nothing is switched on by default. The issuing command
will enter a receipt in the seller's own log if it is asked to; nothing here will go and fetch the
public attestation that dates that log, which is obtained outside these tools by design. The
verifying libraries ship with the check disabled in both languages. No pinned block headers are
distributed with anything, and the verifier on this project's own website carries an empty set of
them. The evidence a verifier needs in order to learn that a key was declared compromised is now
produced as well as consumed — and with no headers to date it, being produced is not enough. The
defence is built and specified. It is not running.

And the rescue applies to the signature on **the receipt**, and to nothing else. A genuine transfer
made *before* the declaration stops authenticating too, and the receipt reverts to whoever held it
before; that is deliberate and specified, because extending the cutoff to transfers would open the
door to resurrected and doubly-assigned transfers. What is not deliberate is that nothing in the
result tells the person holding the receipt why it happened.

#### The seller's levers exist now. What sits under them does not

Several things this document says a seller *can* do were, for most of this project's life, things
the specification defined, the verifier evaluated, and no shipped tool performed. That list has
largely emptied, and saying so is more useful than repeating a complaint that has been answered.

A seller can withdraw a receipt, within the class it sealed the receipt with, and hand the record
over in the shape a verifier reads — and the tool refuses to sign a record the verifier would only
throw away. A seller can enter a receipt in its own log in the act of signing it, and compute the
log entry for the documents that travel beside it. A seller can package a compromise declaration
together with its evidence, and be told, before the file is written, exactly what that package can
and cannot do. A holder can answer a binding challenge. The merchant service is the laggard: it
declines to issue for an order already refunded, and does nothing at all about a refund that
arrives after a receipt has gone out — a gap in that service, not in the tool beside it.

What has not arrived is the one thing all of those wait on. None of these documents can be
**dated**. The attestation that would date them comes from outside these tools by design, and the
block headers a verifier would check it against ship with nothing. So a revocation record can be
signed and packaged and still be disregarded by a verifier that weighs log evidence; a compromise
declaration can be published in exactly the right form and still establish no cutoff; a receipt can
be logged and gain nothing from having been. Everything in this document that turns on *when*
rather than on *who* stops at that line — and everything that turns on who works, and worked
before. That is a narrower and more precise statement than the one this section used to make, and
it is the one the tooling now supports.

There is a second absence, of a different kind: no tool here fetches a seller's key material from
the seller's own domain, so the strongest trust level is unreachable. The next limit is about that.

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
issuer has a name in the specification's own open work and is not built. Whether the seller's
terms allow a transfer at all is a signed statement that the verifier honouring one never reads,
and a transfer is honoured only while the key that counter-signed it is still in use, so a routine
rotation — or a compromise marking — un-honours it and leaves one purchase with two green
receipts; both measured, both stated in section 5 as limits and not as guarantees. A publisher's word about
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
>   and ignored, which is also why a routine rotation that retires the signing key un-honours every
>   transfer record that key signed (section 5) — and extending the cutoff to them is named as a
>   distinct design with its own hazards, transfer resurrection and double assignment. Neither
>   specification restricts *which* keys may publish a compromise marking, so marking the
>   counter-signing key stolen reaches a completed transfer the same way retiring it does, and
>   leaves both parties holding a green receipt for one purchase; threat model TM-80 catalogues
>   that outcome, and a case in the conformance corpus pins it, so that a verifier meeting it
>   cannot mistake it for a defect to be repaired. It is the price of refusing the alternative,
>   not one of the hazards that alternative carries.
> - **The trust root is domain control** (v0.1 §7.1, §7.4). "An issuer's identity is its DNS domain";
>   `trust: "verified"` requires a manifest fetched over TLS from it, everything else is
>   `unauthenticated_tofu` and is "never silently upgraded"; and no value of transparency or
>   corroboration ever changes that (v0.2 §15 item 4, "the single most important non-goal").
> - **Proving you hold the binding secret costs something, and proves possession, not
>   participation** (v0.1 §8). Redeeming the commitment by disclosing the identifier and its salt
>   is a replayable bearer proof that burns that receipt's binding secrecy toward that verifier;
>   the non-revealing path — a challenge-response against a buyer public key — is the strong one,
>   and it is optional and absent by default wherever there is no buyer-side client. Every input to
>   either proof is issuer-chosen, so `proven` never establishes that the named buyer took part.
>   §8 now states that limit in the specification's own text and §11.1 binds a rendering surface
>   to it, forbidding any conforming display from presenting the two results as evidence about a
>   person; threat model TM-78 catalogues the residual, with the claim narrowed and the
>   fabrication not prevented. A `buyer.acceptance` member carrying the buyer's own signature over
>   the offer remains a planned, OPTIONAL addition, not yet specified.
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

### 9. Copying, piracy, and what this is not for

Three questions arrive together at this point, and they deserve separate answers because they
are different questions. Is this DRM? Does it stop piracy? Does it help pirates?

It is not DRM, and the specification says so in the form of a prohibition rather than a
preference: attest defines no functionality for stripping or bypassing a lock, and a conforming
implementation must not be built, marketed or used as a means of circumventing one. The receipt
never touches the work. It does not contain it, wrap it, host it or index it; a conforming
implementation is forbidden from hosting or indexing the works receipts refer to. What the
receipt records is that a licence was granted, on stated terms, by a named seller, and a file on
your disk can be matched against the fingerprints it carries. That is all. A receipt for a work
sold under a lock is permitted, verifies with a warning attached, and removes nothing: the
receipt describes what you were sold and does not change it. Nothing in this document rests on a
right to unlock what you bought, and it takes no position on when removing a lock is lawful; a
signed receipt is an *additional* thing the seller hands you, and it never picks a lock. Section
5 said why the standard will never turn a receipt into one.

Does it stop piracy? No, and it does not try. A pirated file and a lawfully bought file without
locks are the same bytes; that is not a weakness of the design, it is its premise. Section 5 said
what a receipt adds to bytes that copy freely — standing, not scarcity — and section 8 said what
that is worth on an open platform, where any player can leave the check out. Nobody who
understands the mechanism will claim it prevents copying, and this document does not.

Does it help pirates, then, by making second-hand copies cheap and lawful? Here the honest answer
is that the question has never been studied, and the research that comes nearest to it is not on
the seller's side. Two structural studies of the video-game market model what happens when a
used market is removed, and both find that it raises producer profit. In the published Japanese
study, eliminating the used market raises publisher profit by 7.3 per cent at unchanged prices,
with a small net loss of social welfare, and by 26.8 per cent once prices are re-optimised, at
which point consumer welfare rises too and the authors conclude that removing resale improves
welfare overall. A study of the United States market estimates that prohibiting resale outright
raises producer profit substantially. The one result in the other direction comes from a
different market — only about 16 per cent of used-book sales on a large marketplace cannibalised
new sales, with a positive net effect — and books are not games: a digital used copy is a far
closer substitute for a new one than a second-hand paperback is. This document does not hide
those studies; it puts them first. What it says in reply is a limit of applicability, not a
rebuttal. Both hostile studies model a used market with no royalty to the publisher and no
transaction cost the publisher controls. The transfer of section 5 is issuer-mediated by
construction — the seller counter-signs every transfer and may attach conditions to it — which is
a regime neither study represents. That is a real answer, and a smaller one than "they are
wrong".

What the evidence does support is only the first link of the chain that the optimistic version
of the argument would need. Affordable and available legal offers demonstrably move consumption
towards legal channels. In the 2023 perception study of the European Union's own
intellectual-property office, 80 per cent of respondents said they prefer legal sources where an
affordable option is available, and among the minority who use pirated content, 65 per cent
called doing so acceptable when the content is not on a service they subscribe to — availability,
not only price, shapes behaviour even for people already outside the legal market. The office's
executive director has said that the causes of piracy "often stem from a lack of access to
affordable legal content". Quasi-experimental work commissioned by the United States Patent and
Trademark Office points the same way: adding a broadcaster's series to a legal streaming service
cut piracy of those shows by a quarter, adding catalogue films to a download store cut it by 12
per cent, and removing a network's content from that store raised piracy of it by 12 per cent.

And those effects have a ceiling, which the same review states plainly: no such strategy has
ever been shown to reduce piracy by more than about 25 per cent, and the great majority of the
peer-reviewed literature — 29 of the 33 studies in that review — finds that piracy does displace
legal sales. A natural experiment on a 14 per cent cut in e-book prices found no statistically
significant change in total piracy; the effect was concentrated, as a 27 per cent drop, among
people who search for pirate sources, and was absent among those who go straight to them. Price
and availability reach the marginal consumer, not the committed one. The most recent European
data cut against the optimistic reading as well: the same office finds that piracy in the Union
has stopped falling and settled at around ten accesses per internet user per month, with software
piracy up 6 per cent in 2023, even as legal offers proliferated.

Finally the hole, stated rather than hidden. There is no empirical literature measuring the effect
of a *legal, digital* second-hand market on piracy — not contested, simply never tested, because
no such market has existed in a form anyone could observe. That makes it a research question,
not a claim, and this document does not make the claim. What it does say is narrower and can be
defended in front of anyone. A verifiable, portable record of purchase is a precondition for any
lawful second-hand market in digital goods to exist at all; such a market is one of several ways
of narrowing the affordability gap that the Union's own office identifies as a driver of piracy;
and its net effect on primary sales is an open question that the existing studies answer only for
markets — physical, frictionless, without royalties — that differ from the design described here.
The evidence closest to attest's own mechanism is not about resale at all. It is that when a
large music download store removed its locks, legal sales were estimated to have risen by about
10 per cent, most strongly for less well-known albums: making a lawfully purchased copy less
restricted made the legal channel more competitive. That is the effect a receipt beside a file
without locks is built to serve.

---

### 10. Why it is worth having anyway

Everything in section 8 is true, and the case still stands, because the case was never that
attest makes copying impossible or access eternal. It is that it makes *paying* leave something
behind. This section says what each party actually gains, in terms each would recognise as its
own interest, and it names the law where a law is involved.

**For a buyer** the obvious gain is that the proof outlives the shop, and section 11 says what
that is worth on the day it matters. The less obvious gain is that proof is what turns rights you
already have into rights you can use. The European Commission's reply of 16 June 2026 to the
citizens' initiative on the end of life of video games created no new right; it restated
existing ones, and both of the readings it offered — that withdrawing a digital service earlier
than a consumer could reasonably expect may be a lack of conformity under the digital-content
rules, with a proportionate refund, and that competition law is available against a dominant
publisher that shuts something down without objective justification — require the consumer to
show what they bought and on what terms. That is exactly the thing that does not survive today.
The press release announcing the reply does not mention proof of purchase anywhere.

**For a seller of files without locks** the reason is commercial, not moral, and the cost is the
one section 7 stated: a signing key to look after and a small key file to publish, at the moment
a confirmation email already goes out, with nothing new that has to keep running afterwards. What
the seller gets is a sentence competitors cannot say — "what you buy from me stays yours, even if
I disappear" — and a whole DRM-free brand was built on the first half of it. There is also a
compliance argument with teeth, stated here precisely because it is easy to overstate.
California's Business and Professions Code section 17500.6, added by Assembly Bill 2426 and in
force since 1 January 2025, forbids advertising a digital good with the words "buy" or "purchase"
unless the seller either obtains the buyer's acknowledgment that what they are getting is a
licence, with its restrictions listed, or states clearly and conspicuously that "buying" it means
buying a licence. It then exempts a digital good "that the seller cannot revoke access to after
the transaction, which includes making the digital good available at the time of purchase for
permanent offline download to an external storage source to be used without a connection to the
internet". The legislature is not ordering anyone to preserve anything. It is relieving of a
warning the sellers who hand over something the buyer keeps. A file without locks plus a receipt
whose terms say it cannot be withdrawn is exactly the shape of that exemption — and the
specification, which allows a receipt to claim that class only when the file was sold without
locks, with a right to download again, and lists what was delivered, says of such a receipt that
it is evidence, not a determination that the seller complied. Maryland adopted the same carve-out
in 2025; a New York bill filed in January 2026 mirrors it. There is even indirect evidence that
less restrictive selling sells more, cited at the end of section 9. What no seller should read
into any of this is a promise that a receipt discharges a legal duty: the storefront's language
and funnel remain the seller's own responsibility.

**For a publisher or rights holder** there are two arguments, both self-interested. The
preservation pledge described in section 11 costs nothing at signing time and only ever activates
on a market that has stopped existing: the publisher gives up revenue it is by definition no
longer earning, and gives it up to named people who already paid, not to the public. That
distinction is the whole reason the scholarly-publishing model it is borrowed from has held for
two decades. And where a work is transferable at all, the design routes every transfer through
the issuer, which means a publisher keeps control of whether resale happens and can attach
conditions to it — a materially different regime from the frictionless, royalty-free used market
that the economics literature in section 9 models against it.

**For a regulator** the gap in the toolkit is evidentiary, and the technique that works is
already visible on the statute books. Transparent labelling, which the Commission's reply also
floats, informs a buyer at the moment of purchase; a verifiable receipt proves what happened
afterwards, which is when disputes occur. They are complementary, and only one of them exists in
law today. The United States state laws just cited do not mandate preservation, which would run
into federal copyright; they regulate what a seller may *claim*, and exempt sellers who hand over
something they cannot revoke. A published receipt format that anyone can implement without asking
permission or paying anyone gives that approach something concrete to name. It is worth seeing
the alternative: a Californian bill that would have required notice before ending the services a
game needs, plus an offline version, a patch, a refund or the release of server software, failed
in a Senate committee on 29 June 2026 — not voted down, but stalled: the motion drew four ayes to
three noes and still fell short of the majority of the committee's membership it needed, with
four members not voting. Reconsideration was granted, and no further vote has followed.
Voluntary formats that already work are the cheaper path, and the one available now.

**For an engineer**, finally, the gain is a problem stated with its edges visible. The
specification is open, both implementations are published, the conformance corpus is
language-neutral, the threat model keeps its unsolved rows in the open, and section 13 lists what
remains. A format that does not exist cannot be adopted in the week it is needed; this one
exists, and it does not spoil while it waits.

---

### 11. After the store is gone

Two cases, and they are so different that answering them together is where most proposals in
this area go wrong.

In the first, you have the file, because the shop sold without locks and you downloaded it. Then
the content is already yours, and the receipt goes on doing its job exactly as it did the day
before. It verifies from its own bytes against the shop's key material carried in your bundle,
with nobody's permission, and it shows whoever needs to know — a successor honouring old
purchases, an archive authorised to serve them, a court — that your copy was bought, on which
date and on what terms. The level of trust it reports is the same one every verification you can
run today reports, trust on first use, because no shipped tool reaches the strong level while a
store is alive either: the store's disappearance changes nothing there and closes off nothing you
had. Two limits apply, both already named. A transfer needs the issuer to counter-sign it, so
transfers stop when the issuer does; and "forever" holds against the shop disappearing, not
against a live shop declaring its own key compromised — and for a receipt you hold today, section
6 explained, that declaration is final, because nothing anyone can install today logs and
timestamps a receipt. The rule on any store that sells without locks is therefore simple and
unglamorous: download what you buy, and keep the file next to the receipt. Content plus proof,
both in your hands.

In the second case you do not have the file. Then the receipt does not bring it back. It proves
you bought the thing; it is not the thing, and no signature conjures a file off a dead server.

There is a mechanism designed for exactly this case, specified, implemented in both
implementations, demonstrated, and used by nobody. It brings in a party the story has not needed
until now: not the shop that sold you the file, but the publisher or studio that owns the work,
which is often still there when the shop is not. A rights holder can sign a **preservation
pledge** at the time of sale — a conditional licence, dormant while the product is on sale, that
authorises delivery of the work to holders of a valid receipt and to nobody else. The pledge is a
signed document of the rights holder's, fixed into the receipt by its fingerprint, so that its
terms cannot be rewritten afterwards any more than the receipt's can. It needs no transparency
log and no timestamping to exist, so a small publisher with no infrastructure at all can sign one
on the first day; and it commits the publisher to delivering a copy without locks, because a
pledge over a locked file would promise the holder something they still could not open.

Two things about the pledge are the difference between a mechanism and a wish. It does not wake
up by itself when a shop closes: either somebody signs — the rights holder, or a successor named
in the pledge in advance — a declaration that distribution has ended, or a backstop date written
into the pledge arrives and is proved to have arrived by the clock of section 6. Silence is
deliberately not read as an answer. An earlier design activated the pledge when a publisher's
proof of distribution stopped appearing, and it was abandoned because it cannot be made sound: a
public log proves that something was present, never that something is absent, and a rule that
fires on silence is defeated by re-timestamping an old but genuine record. That leaves the
publisher who simply vanishes — signing nothing, naming no successor, setting no date —
uncovered, and the project's threat model names that as the largest residual risk the mechanism
carries. The two mitigations available are inside the pledge itself, and both are the rights
holder's decision at signing: name successors, and set a backstop date. The other thing is that
the pledge costs the rights holder nothing at signing time, because it can only ever fire on a
market that has already ceased to exist.

The idea is not new. Scholarly publishing has protected itself this way for two decades, through
dark archives jointly governed by publishers and libraries that open content when a publisher
dies or a title is withdrawn — one of them to the public, another only to the libraries that take
part. Both have fired, more than once, and the one that releases to a named group rather than to
the world has the broader list of triggers, including a publisher's delivery platform being down
for more than ninety days. That is the lesson worth carrying across: a release restricted to the
people who already paid is far easier to get agreed than a release to the world. A verifiable
receipt is what makes the restricted version possible, because it is what tells an archive which
of the strangers at the door already paid.

And it is what makes the archive's door a real door. The demonstration this project ships walks a
pledge from signature through activation to delivery, and the archive gate in it refuses, by
construction, everything but the holder: a pledge that has not fired, a receipt with a byte
changed, a receipt that was withdrawn or transferred away, a proof made for a different archive
and replayed here, a proof already used once, and — refused even when everything else is in
order — the buyer's salt offered as proof, because handing the salt to an archive is exactly how a
holder gives away the ability to be impersonated everywhere. Redemption therefore requires a key
of the buyer's to have been written into the receipt at the time of sale, and the specification
forbids the easier proof as a normative prohibition; section 8 said what that costs an heir.
The pledge was for a time the one place where a buyer-side key had a shipped command on both sides
— the archive minting the challenge, the buyer's tool answering it — and the ordinary binding
challenge of section 4 has since caught up. What neither has is a receipt in the world carrying a
buyer key to be challenged over.

Every seller-side and publisher-side act in this section is stated with whether a shipped tool
performs it. Issuing a receipt, signing a pledge, declaring a cessation, minting and answering the
redemption challenge, counter-signing a transfer, withdrawing a receipt, logging one, and packaging
a compromise declaration all have shipped commands. Putting a date on any of them does not, and
that single absence is what section 6 is about: it is why a backstop date written into a pledge
cannot yet be proved to have arrived. What is missing from the pledge, above all, is not the mechanism: it is a publisher
who has signed one, an archive that holds anything, and licence prose written by a lawyer instead
of the placeholder the demonstration carries — which says of itself that it is a reference gate,
not a production one, and lists the three things it does not do. One detail from running both
demonstrations belongs here rather than in a note. On a receipt that is entirely genuine, both
report that nobody has established who controls the signing key. That is the honest state of the
system today, visible in its own demonstrations.

---

### 12. Where this actually is

Everything described in this document exists and can be read, run and attacked by anyone.
Nothing described in it is in production.

What exists is this. The specification, in two published parts: a complete version 0.1, and an
additive 0.2 that adds the hybrid post-quantum signature profile, the transparency and
timestamping layer, issuer-mediated transfer, the preservation pledge, the compromise rescue and
publisher authority, without changing any verdict 0.1 already gave. Two independent
implementations, one in Python and one in TypeScript, published on their respective package
registries at the same version and measured against a single public corpus of conformance
vectors that both must reproduce leaf for leaf; the corpus and its current size live in the
repository, where they cannot go stale in a document, and the conformance program lets a third
implementation run the same corpus with one command and publish its own claim. A verifier that
runs in a browser and cannot contact any outside host, and the same verifier as a single
downloadable file. Two demonstrations that run end to end on an ordinary machine in seconds: one
deletes a shop's entire infrastructure and checks the receipt afterwards, the other walks a
preservation pledge from signature to delivery. A formal model of the trust, rotation and
compromise core of the protocol, machine-checked, with a gate that refuses a proof whose
statement has been edited; the transfer profile is deliberately outside it, and the repository
says so. A threat model that catalogues the attacks across the receipt's whole life and keeps the
ones that are not stopped in a section of their own rather than in a footnote. A privacy analysis
of what each field reveals to whom. And an Internet-Draft on the IETF Datatracker,
`draft-martinalli-open-purchase-receipts-00`, published on 6 August 2026 as an individual
submission with Informational intended status and expiring on 7 February 2027 — which means the
document exists and can be cited as work in progress, nothing more: it is not the product of any
working group, carries no IETF endorsement and has no formal standing. It mirrors an earlier
revision of the specification; the specification in the repository, not the draft, is normative.

What does not exist is a shorter list, and it matters more. No store issues attest receipts in
production. No publisher has signed a preservation pledge. No archive holds anything. There are
no external reviews. The clock of section 6 is switched on for nobody, this project's own
verifier included, and no independently operated witness co-signs the log. The strong trust
level is unreachable with the tools anyone can install. And of the defences the specification
writes for the seller — withdrawing a receipt, logging one, timestamping one, packaging a
compromise declaration so that a verifier can bound it — all but the third now have a shipped
producer, as section 4 measured. The third is the one the others lean on, and it heads the list in
section 13.

The absence of a first adopter is a fact about adoption. It is not a measure of whether the
standard is finished or worth building, and the work does not wait on it: a format that does not
exist cannot be adopted in the week it is needed, and the week it is needed keeps arriving.

---

### 13. Open problems

These are stated as problems, not as roadmap promises. Each has a name, none has a date, and the
first is the one a reader of this document has already met several times.

**Nothing can be dated.** This is a fact about tooling, measured on the command-line tool and the
checkout service rather than inferred, and it is listed first because it qualifies most of the
others. The specification defines, and both implementations evaluate, revocation records, log
entries for receipts, timestamp proofs, and the authenticated form of a compromise declaration.
Three of those four now have a shipped producer. The fourth does not, and it is the one the other
three lean on: a timestamp needs a public attestation obtained outside these tools — deliberately
so, because a tool that went and fetched one would be a tool that touches a network — and a
curated set of block headers to check it against, which nothing distributes. Until that link
exists, every defence that turns on the order of two events protects nobody, and every sentence in
this document that begins "the seller can" should be read with "and cannot prove when" after it.

**Witness federation.** Until parties independent of the log co-sign what they have seen, an
unwitnessed operator can maintain divergent views of history, and detection of a duplicated
receipt (section 5) is not guaranteed. The format for co-signature shipped; no independent
operator exists, and no specification can supply one.

**Transfer-authority succession.** Transfers are counter-signed by the issuer, which is what
keeps them lawful and what gives a publisher control over whether resale happens at all. It also
means they stop when the issuer does. Making a transfer outlive its issuer — an issuer, while
alive, delegating that authority to a successor in advance — is unsolved, and it is the hardest
problem on the project's list. Nearer at hand, and measured: a transfer today is honoured only
while the key that counter-signed it is still in use, so a routine key rotation un-honours it, and
so does marking that key stolen, which anyone holding any current key of the same seller can do
(section 5). What the two leave behind is one purchase with two receipts that both verify, seen by
neither holder and only by an audit of the recorded chain. The threat model catalogues it as
TM-80, treats the two markings as one mechanism whose consequence for a completed transfer has not
been decided, and the conformance corpus pins the outcome so that nobody patches it away in a
verifier instead of deciding it in the standard. The rule that would judge the record against the
key's validity window at the time of the transfer is declared and not yet written, and the flag in
the licence that says whether a receipt may be passed on is not read by the verifier that honours
the transfer at all.

**Silent death of a publisher.** A publisher who vanishes without signing anything and without
naming a successor leaves a preservation pledge dormant for ever. The mode that would cover it,
reading meaning into an absence rather than a presence, cannot be made sound by drafting, for the
reason section 11 gave.

**Who the buyer's key belongs to.** The strong binding of section 4 proves that the presenter
holds the private half of a key the seller wrote into the receipt. Nothing in the protocol today
establishes that the key was the buyer's: the seller chose it, and a compromised or coerced
seller could choose one of its own. The planned addition described in section 4 — a buyer's
signature over the offer, carried inside the receipt — would close that against a compromised or
coerced seller for buyers who hold a key, and would close nothing against a seller that simply
lies, which the specification places outside its scope. Whether a buyer can have a key whose
provenance depends on no seller at all is a further design, with a privacy cost, and it has not
been decided.

**Key custody for ordinary people.** A buyer's binding secret, lost after the issuer is gone, is
lost. Optional custody is possible because a receipt is inert data with no lock-in, and nothing
about it is built; a buyer's key today lives in a file, and the tools to carry it any other way
do not exist.

**Cryptographic ageing**, with a sharper edge than the usual version of this problem. Signatures
made today have to still mean something in decades, and the standard answer is to re-attest old
material under newer schemes. Re-attesting requires a signer. In the case this project exists
for, the issuer is gone and there is nobody to sign, so the only route is a trusted third party
attesting that a receipt was valid under the older scheme while that scheme still held. That is a
role nobody has designed. The hybrid signature profile that pairs the classical signature with a
post-quantum one buys time; it does not answer the question.

**Long-term custody of the block headers.** The clock of section 6 works by comparing a proof
against block headers a verifier already holds, never by asking a network. That moves the
question rather than answering it: somebody has to curate and distribute an honest set of those
headers, verifier after verifier, for as long as the receipts are meant to last. The trust does
not rest on the network; it rests on that chain of custody, and nothing about it is designed
today.

**The domain as a lease.** A dead shop's domain name can be re-registered by anyone. The
direction of work is to make historical key material provable — recorded and timestamped while
the shop was alive, so that an older, anchored manifest beats a newer, opportunistic one — which
returns to the two problems above.

---

### 14. What is needed now, and colophon

If you sell files without locks, you are the shortest path, and you can start without asking
anyone. Signing a receipt is one operation at the moment you already send a confirmation email;
the buyer has to do nothing; nothing about how you sell has to change. What you take on is real
and worth knowing first: a signing key, a small key file published on your own domain, and the
duty to keep that key safe for as long as the receipts matter. Declaring it compromised is the
one act that reaches back and invalidates what you have already signed. You can withdraw a single
receipt, and you can enter one in your own log as you sign it; what you cannot do with these tools
is prove *when* you did either, and section 12 said why that is the one gap left. A seller
who cannot carry a key is a seller this does not work for. Start there, and say where it hurts.

If you buy digital content, download what you buy and keep the file. Where a receipt exists,
keep it beside the file, and keep the private file where you keep secrets. And when a platform
tells you that you have *purchased* something, ask what you would still hold if that platform
stopped existing tomorrow.

If you write the rules, the confirmation on a durable medium is already owed. The ask is that it
be issuable in a portable, machine-checkable form: a requirement about format, on an obligation
that already exists, with an openly licensed specification to point at. Section 7 said, with
dates, how far that conversation has got, and it is not far.

If you build software, the most useful thing you can produce is an implementation that does not
trust ours. The conformance corpus is public and language-neutral, and a verifier written from
the specification alone and checked against the same fixtures is evidence of a kind this project
cannot produce for itself. Adversarial review is the second most useful thing, and section 8 is
where to start.

**Colophon.** The specification, both implementations, the conformance corpus, the threat model,
the privacy analysis, the formal model and the demonstrations are in one public repository,
`github.com/bernalli/attest`, and a receipt can be verified in a browser with nothing installed
at `attest-receipts.org`. The reference code is licensed Apache-2.0, whose patent grant reaches
that code and no further; the specification and its documentation are CC BY 4.0, which states
outright that it licenses no patent rights. Nothing here charges a fee to implement any of it,
and nothing here is yet a patent commitment to someone implementing the specification
independently of that code: the licences say what they cover, and stop short of the words
"royalty-free". There is nothing to join and no permission of ours to ask. Corrections to
anything in this document are more welcome than agreement with it; section 8 exists because a
hostile reading of an earlier text was right.

---

### 15. Notes

External facts only; internal facts link to the live surface — the specification, the code and
the demonstrations in the repository — rather than to a note. Sources were read at their primary
text on the dates given. Where a primary text could not be reached from where this document was
written, the note says so.

**Section 2.**

1. Amazon and *1984*: the deletion is reported by *The Guardian*, 17 July 2009; the spokesman's
   statement is quoted identically across contemporary reports; the founder's post on Amazon's
   Kindle forum of 23 July 2009 no longer resolves at its original address after the forum was
   reorganised, and its wording is preserved identically by three independent publications of the
   same day; the settlement of $150,000 and the undertaking limited to consent, refund, court order
   and malware are reported by Reuters, 30 September 2009. An authorised edition of the book
   remained on sale throughout. Verified at those sources on 1 September 2026.
2. Microsoft Books: the customer notice on the closure of the Books category, announced 2 April
   2019, quoted in the *Los Angeles Times*, 2 July 2019, and reported by Forbes and CNET. No source
   gives an exact day in July 2019 on which the books stopped opening, so none is asserted; no
   Microsoft statement on the mechanism exists, and the attribution to licence validation is the
   trade press's. Verified 1 September 2026.
3. Sony and StudioCanal: PlayStation's legal page for video content, United Kingdom edition
   (`playstation.com/en-gb/legal/psvideocontent/`), read verbatim on 1 and 3 September 2026; the
   figure of 551 is the number of rows in the table of titles on that page, counted from the page's
   own structure on both dates, all distinct. The page carries the effective date and not the
   announcement date, which press coverage places in late June 2026 without agreeing on the day;
   the Europe-and-UK scope is from that coverage. The August 2022 removal is reported by
   GamesIndustry.biz.
4. *The Crew*: Ubisoft's announcement of 14 December 2023, in its own words; the removal of the
   licences from buyers' accounts in April 2024 is documented by an in-client message photographed
   by buyers and reported by the trade press, with no seller statement. The settlement of *Cassell
   v. Ubisoft* (Sacramento County Superior Court, No. 25CV014305) — a fund of two million dollars,
   seven dollars in cash or fifteen in store credit — received preliminary approval on 2 April
   2026, with the final approval hearing set for 13 November 2026 and not yet held as of 3
   September 2026. The organisers' statement that the European citizens' initiative targets games
   yet to be developed, not those already sold, is on the record of their meeting with the
   Commission of 23 February 2026 and of the European Parliament hearing of 16 April 2026.

**Section 5.**

5. The offline digital-cash construction that honours a double-spend and unmasks the spender
   afterwards is the detect-after-the-fact scheme described in the 1993 exposition "Detecting
   Double-Spending", read on a public mirror on 5 September 2026. The published scheme that turns
   a purchase into a decryption key is Readium LCP: its principles page promises that a book still
   opens after the bookseller has disappeared, and its encryption-profiles page records that the
   production profile was breached in 2022 and that replacement profiles were issued afterwards;
   both read on 5 September 2026. No formal impossibility result for offline double-spend
   prevention without trusted hardware was found; the argument in section 5 is an argument, not a
   theorem, and the document says so.

**Section 6.**

6. Surety and the *New York Times*: the weekly hash published as a classified advertisement from
   1995 is reported consistently by secondary sources; the primary source would be a printed page
   of the newspaper, which this document has not examined. If only primary sources are wanted, the
   image can be rewritten as hypothetical without loss.

**Section 7.**

7. Directive 2011/83/EU of 25 October 2011, Articles 2(10), 6(1) and 8(7), read on the published
   text.
8. European Commission press release IP/26/1369 of 16 June 2026, read in full on 5 September
   2026: "The Commission considers that at this stage it cannot propose a legal obligation to keep
   video games playable after they stop being provided commercially"; the commitments to engage
   with consumers and publishers by the end of 2026 and to report on the digital-content directive
   before the end of the year are quoted from it; it contains neither "proof of purchase" nor
   "receipt". The signature count and the number of member states are from the initiative's entry
   on the Commission's register of citizens' initiatives. The Commission's formal Communication is
   C(2026) 4110 final; the readings of the digital-content and competition rules in section 10 are
   from that text, read in full on 1 September 2026 and re-checked on 3 September 2026.
9. California AB 2426 (Chapter 513, Statutes of 2024), codified as Business and Professions Code
   section 17500.6, effective 1 January 2025; the prohibition, the two alternatives in subdivision
   (b)(1)(A) and (B), and the exemption in subdivision (b)(4)(C) are quoted from the codified text
   on the California Legislative Information site, read on 5 September 2026. Maryland HB 208
   (Chapter 206 of 2025, in force 1 October 2025) carries an almost identical exemption, read on
   the enrolled bill; New York S8952, filed 21 January 2026, mirrors it and was in committee when
   last checked on 3 September 2026.

**Section 8.**

10. CJEU, Case C-263/18 *Tom Kabinet*, judgment of 19 December 2019, ECLI:EU:C:2019:1111; CJEU,
    Case C-128/11 *UsedSoft v Oracle*, judgment of 3 July 2012; *Capitol Records v. ReDigi*, United
    States Court of Appeals for the Second Circuit, No. 16-2321, 12 December 2018.

**Section 9.**

11. Ishihara and Ching, "Dynamic Demand for New and Used Durable Goods without Physical
    Depreciation: The Case of Japanese Video Games", *Marketing Science* 38(3):392–416, 2019, DOI
    10.1287/mksc.2018.1142; the figures are those of the published abstract, read on 3 September
    2026. A 2016 working-paper draft of the same title circulates with much larger figures; those
    describe an earlier version of the model, not the peer-reviewed result, and are not used.
12. Shiller, "Digital Distribution and the Prohibition of Resale Markets for Information Goods",
    Brandeis working paper 59, 2012–2013, read 3 September 2026.
13. Ghose, Smith and Telang, "Internet Exchanges for Used Books", *Information Systems Research*
    17(1), 2006.
14. EUIPO, *IP Perception Study 2023*: stated preferences from a survey, not observed behaviour.
    The 80 per cent figure is across all respondents; the 65 per cent figure is among users of
    pirated content and is read in the full report, not on the summary page, which renders it
    misleadingly; 14 per cent admit having intentionally used illegal sources in the previous
    twelve months, 33 per cent among those aged 15 to 24. Read 3 September 2026.
15. EUIPO, *Online Copyright Infringement in the EU 2017–2023*, 2024, and the executive director's
    statement in the accompanying release; read 3 September 2026.
16. Danaher, Smith and Telang, *Piracy Landscape Study*, commissioned by the United States Patent
    and Trademark Office, 2020: the three quasi-experimental results, the ceiling of about 25 per
    cent, the count of 29 of 33 studies, and, as summarised there from Zhang (2017), the estimated
    10 per cent rise in legal sales after a music download store removed its locks. Read 3
    September 2026.
17. Rajavi, Danaher and Newby, "Price, Piracy, and Search", *MIS Quarterly* 48(4):1537–1558,
    2024; the authors' own terms are "direct" and "indirect" pirates.

**Section 10.**

18. The Commission's Communication C(2026) 4110 final, as in note 8; the refund reading rests on
    Articles 14 to 16 of Directive (EU) 2019/770 and the competition lever on Article 102 TFEU.
19. California AB 1921 ("Digital games: ordinary use"): passed the Assembly on 29 May 2026; on 29
    June 2026 the Senate Business, Professions and Economic Development Committee's motion drew
    four ayes, three noes and four not voting, and failed for want of a majority of the
    membership; reconsideration granted. Vote record read on the Legislature's site on 3 September
    2026, with no later vote recorded.

**Section 11.**

20. The two scholarly dark archives are CLOCKSS, which releases triggered content to the public,
    and Portico, which releases to its participants and states its trigger conditions — a
    publisher ceasing operations, a title discontinued, back issues no longer offered, or a
    delivery platform down for longer than ninety days — on its own site; both read on 3 September
    2026. Their tallies of activations are counted in different units and are deliberately not
    compared here.

---

## Part C — Nota per il proprietario (non fa parte del testo; si toglie prima della pubblicazione)

*Elenco corto: solo le decisioni che restano davvero tue, dove due letture ragionevoli portano a
testo diverso. Per ciascuna, la mia raccomandazione e il testo scelto nel frattempo. Le decisioni
prese e chiuse in questo giro stanno in coda, una riga ciascuna, perché nessuno le ridomandi.*

1. ~~**Il marcatore descrive due revisioni che su questo branch non ci sono ancora.**~~ **Chiusa,
   e il modo in cui si è chiusa merita due righe.** Il giro precedente aveva messo il marcatore a
   v0.1 rev 17 / v0.2 rev 12 su un branch che stava a 16/11, di proposito, per costringere
   l'ordine di merge: prima le spec, poi il whitepaper che le descrive. La previsione allegata —
   «diventa verde senza altre modifiche appena il branch è rebasato sopra quelle due revisioni» —
   **non si è avverata**, ed è la stessa famiglia di errore che il gate esiste per intercettare.
   `main` non si è fermato a 17/12: è arrivato a **18/13**, e il pacchetto da 0.9.1 a **0.9.3**.
   Dopo il rebase il gate segnava tre disallineamenti, non zero. Alzare il marcatore non era
   quindi un adempimento ma un'affermazione — dire che il testo descrive quelle revisioni e quel
   pacchetto — e il grosso di questo giro è stato renderla vera. La parte cara non erano le due
   revisioni di spec ma la 0.9.3: ha spedito le leve del venditore che il documento dichiarava
   assenti, e la tesi «specificate, non spedite» reggeva otto sezioni. Ora il marcatore è a
   18/13/0.9.3 e il gate è verde. **Niente da decidere qui.**
2. **Titolo e sottotitolo.** «Own what you buy» resta (tagline ratificata). Il sottotitolo dice
   ora «durable digital possession» e la tesi «layer of possession»: la spec dice testualmente che
   una ricevuta «is not a claim of "ownership"». **Raccomando così.** Alternativa: un sottotitolo
   senza il sostantivo («a whitepaper on keeping what you buy»).
3. **I due difetti vivi restano fuori da §8** (il canale della dichiarazione di compromissione; i
   punti ciechi dei tetti), perché la sequenza decisa è fix → release → advisory e il whitepaper li
   pubblicherebbe prima. Il testo ne dice la famiglia. **La sequenza è tua**: se il whitepaper esce
   dopo l'advisory, le due voci rientrano in §8.
   **Nota di questo giro, che rende la voce più pesante di prima e non la cambia**: §6 e §8 ora
   dicono che la dichiarazione di compromissione *si può impacchettare*, perché il comando esiste
   e l'ho verificato. Il documento è quindi più affermativo su quel percorso di quanto fosse
   quando questa decisione è stata presa, mentre i difetti vivi stanno proprio lì. Non ho cambiato
   la decisione — non è mia — ma la finestra fra pubblicazione e advisory è ora meno innocua:
   prima il documento diceva «non spedito» e nessuno andava a guardare.
4. **Nomi di prodotti e di archivi.** Il corpo nomina le tre integrazioni del servizio di checkout
   (Stripe, itch.io, Shopify) perché la FAQ pubblica lo fa già; i due archivi accademici sono
   descritti nel corpo e nominati solo nelle note (§15, nota 20). **Raccomando così.** Alternativa:
   «i checkout più comuni» nel corpo e i nomi nelle note; oppure nominare gli archivi anche nel
   corpo.
5. **Il manifesto V-F.1 è assorbito e va ritirato, non pubblicato accanto.** Ne ho ripreso
   struttura e frasi dove reggevano. La sua clausola sulla catena («tutto ciò che una catena
   farebbe è già fatto da log e firme, o è una liability») contraddice v0.2 §11.1 e non
   sopravvive qui: §6 scrive la posizione vera. **Raccomando che il whitepaper prevalga e il
   manifesto sia archiviato.** Alternativa: pubblicarlo come testo breve emendato nel lessico di
   §5–§6.
6. **Titolo di §5.** «The trilemma» (il testo lo tratta come argomento, non come teorema).
   **Raccomando di tenerlo.** Alternativa: «A key to a door, not to a file» come titolo, lasciando
   la parola nel corpo.
7. **Lunghezza di §4 e §8.** §4 ha tredici paragrafi contro i nove previsti; il di più è il
   criterio di completezza (ogni difesa accanto al suo produttore o alla sua assenza). Tagliare
   vuol dire scegliere quale produttore mancante tacere. **Raccomando di non tagliare.**
8. **Pubblicità di questo file.** Il branch non è pushato. Il documento è pronto per la lettura
   e porta ancora questa Part C: la pubblicazione (PR, sito, `docs/`) è un gesto tuo, e la Part C
   va tolta nello stesso atto.

*Decisioni prese in questo giro, chiuse (una riga ciascuna):*

- **La superficie spedita è stata rimisurata, non riletta**, ed è il grosso del giro: la 0.9.3 ha
  aggiunto `revoke`, `revocation-view`, `binding {challenge,respond}`, `log entry`,
  `manifest compromise-view`, `transfer view` e `issue --log-dir`, più un flag di `verify` per
  ciascuno dei tre input che non ne avevano. Le catene che il testo ora afferma sono state
  ESEGUITE, non lette da un help: revoca fino a `revocation: "revoked"`/`ok: false`; i due rifiuti
  di `revoke` (ricevuta irrevocabile, data fuori finestra); la sfida di binding fino a
  `"binding": "proven"` con controllo negativo; `issue --log-dir` fino a `leaf_index 0`; e
  `log prove --receipt` fino al bundle `{checkpoint, entry, inclusion_proof, leaf_index,
  tree_size}` — che è la forma richiesta **meno** il membro `anchors`. Il link mancante è quindi
  mostrato, non asserito, ed è uno solo: la datazione.
- **Tre difetti miei, trovati dal mandato d'attacco e non dalla rilettura**, tutti nella stessa
  direzione: correggendo un documento troppo negativo l'ho reso, in tre punti, più affermativo
  dell'evidenza (una frase sulla rete che contraddiceva il documento stesso; un «te lo dice in
  tante parole» su un testo che non avevo letto; una verità vacua). Tutti e tre corretti. Il
  dettaglio delle quattordici domande e del loro esito sta nel registro di ricerca del progetto,
  fuori da questo repo.

- **B2: perimetro dichiarato, nessun cambio di spec.** Il fronte B1 ha chiuso il 5 settembre con
  verdetto «non risolvibile come posto»; §5 rende i due argomenti (i fatti che restano veri; la
  serratura senza chi la ripari), con un'immagine sola — «a key to a door, never to a file» — e i
  tre poli rinominati (free copying, non transferability). Nessuna promessa di soluzione futura;
  l'argomento anti-elusione è detto perché è in v0.1 §2; la caratterizzazione legale del dossier
  non entra: una frase neutra, nessuna norma citata.
- D24, entrambe le parti: §4, §5 e §8 scrivono `proven` come possesso di un segreto, mai
  partecipazione; `buyer.acceptance` è «planned and not yet specified», mai esistente.
- Trasferimento, due vincoli misurati il 5 settembre e resi in §5 e §13 come limiti, non come
  garanzie: un transfer record autentica solo con la chiave `active`, quindi una rotazione
  ordinaria lo annulla (la regola della finestra a `transferred_at` è lavoro dichiarato); e
  `license.transferable` non è letto dal verificatore che onora un trasferimento (è una
  dichiarazione firmata, non una regola applicata). Il testo non dice mai che un trasferimento
  «resta» né che il venditore «permette» tramite il flag.
- Sezione 2: apertura con Amazon/*1984* (2009), poi Microsoft, Sony/StudioCanal, *The Crew*, coi
  vincoli di formulazione verificati alla fonte; il nesso *The Crew* → iniziativa europea è smentito
  nel testo stesso, con la fonte in nota.
- Sezione 9 a sé, nella sola forma difendibile: primo anello (accesso legale accessibile sposta
  consumo), tetto dichiarato, studi ostili citati per primi, e la dichiarazione che nessuno studio
  esiste sull'usato digitale legale ↔ pirateria. Nessuna citazione di norme anti-elusione.
- Art. 8(7): il whitepaper non dice che la ricevuta «è» la conferma né che la assolve; allineato al
  README ratificato («un formato in cui la conferma può viaggiare»).
- Il nome dell'Internet-Draft compare in §12: repo e Datatracker ora coincidono
  (`ietf/draft-martinalli-open-purchase-receipts.xml`; Datatracker letto il 5 settembre).
- `attest transfer authorize` è del compratore (firma l'autorizzazione dell'holder uscente con la
  chiave del compratore): il draft precedente lo attribuiva al venditore; corretto in §4 e §5.
- La verifica del 1° settembre (struttura, bozza a otto sezioni, tabelle claim per claim) vale
  come archivio di verifica, non come testo.
- I nomi dei due file sono quelli spediti (`.attest` e `.private.attest`); nessuna denominazione
  non ratificata compare.
- Surety e il *New York Times* restano, con la nota che dichiara il grado della fonte (nota 6).
- La frase sull'esenzione di AB 2426 e il testo di §17500.6 sono stati riletti sul sito legislativo
  della California il 5 settembre, da qui: la riserva del giro precedente («fonte primaria non
  raggiungibile») è chiusa.
