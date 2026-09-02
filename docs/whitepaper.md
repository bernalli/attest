# Own what you buy

*A whitepaper on durable digital ownership: the seller signs a receipt, you hold the file, anyone
can verify it offline — even after the store is gone.*

> **Status: draft, third round (September 2026).** This file contains three things: the outline of
> the finished document (Part A); seven of its sections written in full — the thesis, what you
> actually bought, how it works, the trilemma, the clock, the two tracks, and what it does not do —
> so that the register can be judged before the rest is written (Part B); and a short note listing
> the decisions the author had to take and wants confirmed or overturned (Part C, to be removed
> before publication). Every factual claim in Part B was checked against the specification, the code
> and the running demonstrations on the day of writing, and every claim about a law or a regulator's
> act against the text of that act; the sources are named inline or in the outline. Nothing in this
> document is a promise the repository cannot keep.

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
| 3 | **What you actually bought** (written, Part B) | What exactly is the thing I am missing? | `README.md` "What attest is"; v0.1 §2 "What a receipt is" (quoted), §4–§6 (the envelope, the fields, immutability and the irrevocability conditional), §8.1 (the commitment), §14 (the two files) | 7 paragraphs |
| 4 | **How it works** (written, Part B) | What does the seller give me, and how does a stranger check it? | `README.md` "How it works, for humans"; `docs/faq.md` "What does 'verify offline' actually check, and what can't it tell me?", "Who can revoke my receipt, and what would I see?", "Is this centralized?"; v0.1 §7 (keys), §8 (buyer binding), §11 (the algorithm and its vocabulary), §12 (revocation records), §13–§14 (disclose and the two files); `site/index.html` CSP and `site/e2e/site.spec.ts` for the browser verifier, `desktop/README.md` for the downloadable one. Revocation is described as a mechanism the verifier evaluates, never as something a seller can do today: the command-line tool on `main` has no `revoke` verb at any level (its top-level verbs, read from the tool's own definition, are `authority`, `check-artifact`, `disclose`, `export`, `grant`, `import`, `inspect`, `issue`, `keygen`, `log`, `manifest`, `transfer`, `verify`), the bridge has no refund handling, and the web and downloadable verifiers consult no revocation feed and pin no block headers. Every input `verify` accepts is listed with its producer, or the absence of one (`src/attest/cli.py`, `src/attest/verify.py`, `site/src/trusted-log.ts`) | 13 paragraphs + In detail |
| 5 | **The trilemma** (written, Part B) | If a file can be copied perfectly, how can it be *mine*? | the internal analysis of duplication and the sharing/exclusivity/survival contradiction (research notes of 24 August); v0.1 §8 (the two bindings); v0.2 §17 (issuer-mediated transfer, log-required honouring, earliest-logged-wins, holder binding); `docs/faq.md` "Is attest a DRM system…"; `src/attest/cli.py` on `main` for which side of each mechanism has a shipped command (transfer and pledge redemption do; the ordinary binding challenge does not) | 10 paragraphs + In detail |
| 6 | **The clock** (written, Part B) | Why is Bitcoin in here, if this is not a blockchain thing? | v0.2 §11.1–§11.3 (anchoring), §19 (the anchored-cutoff rescue); `src/attest/cli.py` (no anchoring flag on `issue`), `src/attest/verify.py` and `verifiers/ts/src/verify.ts` (anchoring off by default), `site/src/trusted-log.ts` (empty header set); `docs/faq.md` "Why not blockchain / NFT?" | 13 paragraphs + In detail |
| 7 | **Two tracks, one standard** (written, Part B) | Who would ever issue one of these? | `README.md` "What attest is" (both tracks); `docs/faq.md` "Nobody forces a seller…"; `bridge/src/attest_bridge/` (the three checkout adapters; refunded orders skipped); Directive 2011/83/EU of 25 October 2011, Article 8(7) and Article 2(10), read on the published text; the European Commission's reply of 16 June 2026 to the *Stop Destroying Videogames* citizens' initiative, read on press release IP/26/1369; California AB 2426 (Chapter 513, Statutes of 2024; in force 1 January 2025), Business and Professions Code §17500.6 read on the codified text | 12 paragraphs + In detail |
| 8 | **What it does not do** (written, Part B) | Where is the catch? | v0.1 §7.3, §7.4; v0.2 §15, §18.6, §18.7, §19.5, §19.6, §20; `docs/spec/attest-threat-model.md` §6.2, §7, TM-44, TM-68, TM-74; measured behaviour of `demo/store_dies.py`; `docs/faq.md` limits paragraph | 20 paragraphs + In detail |
| 9 | Copying, piracy, and what this is not for | Is this DRM? Does it stop piracy? Does it help pirates? | v0.1 §2 (out of scope: DRM, hosting, resale); `docs/faq.md` "Is attest a DRM system, a store, or a way to pirate games?"; the evidence review on second-hand markets and piracy in the September paper (hostile studies first, then the applicability limit, then the ceiling, then the unmeasured gap) | 7 paragraphs |
| 10 | Why it is worth having anyway | What does each party actually gain? | `README.md` seller paragraph; `docs/faq.md` "Nobody forces a seller…"; v0.1 §6.1 (the irrevocable-goods conditional and AB 2426); v0.2 §18 (the preservation pledge as a zero-cost signature) | 7 paragraphs |
| 11 | After the store is gone | Practically, what do I do with the receipt on the day it matters? | `docs/faq.md` "The store that signed my receipts shut down…"; v0.2 §18 (preservation pledge, activation modes); `demo/README.md`; both demonstrations, run. Every seller-side act named here (revoking, declaring a compromise, re-issuing) is stated with whether a shipped tool performs it — today only issuing and transfer are | 8 paragraphs |
| 12 | Where this actually is | What exists today, and what is only designed? | `README.md` "Status"; `docs/conformance.md`; the IETF Datatracker entry (individual submission, no standing) | 4 paragraphs |
| 13 | Open problems | What is still unsolved, with a name? | `docs/spec/attest-threat-model.md` §6.3; TM-68; the adversarial question list of 1 September (long-term custody of block headers; re-attestation with no signer; the domain as a lease); and the general fact, measured on the command-line tool and the bridge: **the defences exist in the specification and in the verifier; the tools that would let a seller exercise most of them are not shipped** — no revocation command, no packaged compromise declaration, no anchoring flow | 8 paragraphs |
| 14 | What is needed now, and colophon | What should I do, and on what terms is all this offered? | `README.md` seller and contact paragraphs; `LICENSE`, `LICENSE-docs`; `docs/faq.md` on the patent boundary | 5 paragraphs |
| 15 | Notes | Where does each external fact come from? | numbered sources for sections 2, 7, 8, 9 only; internal facts link to the live surface instead | as needed |

Order of writing after this round: 2 next (the opening case is gated on the decision recorded in
Part C, point 2); then 9–14; the front matter last, when the body is stable. Sections 5 and 7 were
written in the second round, because they were the two remaining places where the document could
lose a hostile reader; sections 3 and 4 in the third, because they are where every term the later
sections rely on is first explained.

---

## Part B — Sections written in full

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
licence, for this work, on these terms, to the person this receipt is bound to. *Signed* means
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
addresses against it is not practical — and yet you, holding the secret, can show anyone that the
receipt was issued to you. That is why the receipt can be shown to a stranger, posted on a forum or
handed to an archive without exposing you: the shareable file says *someone* bought this; the
secret, kept in a second file, is what says it was you. A receipt may also carry a public key of
yours, for a stronger proof; today, wherever a purchase happens without an app on the buyer's side,
that field is empty by design. What proving it is yours costs, and what it does not prove, is in the
next section.

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
valid. A key declared **compromised** — stolen — does the opposite: every signature it ever made is
rejected from then on, and the marking, once seen by a verifier, cannot be unseen or reversed.
Declaring one is a shipped command (`attest manifest rotate --compromise-kid`), and it is the
seller's one lever that reaches backwards; sections 6 and 8 say how far it reaches, and why the
rescue that would bound it has evidence no shipped tool can package.

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
receipt. *Has anyone proved it is theirs?* Only if someone tried; otherwise "not checked". *Where
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

#### Proving it is yours

A copy of the shareable file verifies exactly as the original does, and it is meant to. What a copy
cannot do is answer the question *is this yours?*, and the standard defines two ways to answer it.
The everyday way uses the secret from the private file: you disclose your identifier and that
receipt's salt, the verifier recomputes the commitment and compares it with the one sealed in the
receipt, and the answer is "proven" or "not proven". It works with the shipped tools — the
command-line verifier takes it as options, the browser page has a panel for it, and the project's
own sample demonstrates it. It is also, in the standard's words, "a replayable bearer proof":
whoever you show it to can show it to someone else and be believed, and it hands over your
identifier. Per-receipt salts keep the damage to one receipt, and a verifier is required to treat
the disclosed identifier as personal data not to be kept. The strong way needs a key of yours signed
into the receipt at the time of sale: a verifier invents a fresh challenge, you sign it with the
private half of your key, and the signed answer proves you hold that key without revealing anything
and without being reusable, because the next challenge will be different. Both implementations know
how to check such an answer, and the command-line verifier even has inputs for the challenge and the
response. No shipped tool produces the answer: the buyer's side of that exchange exists only as a
library call, and the key it needs is empty by default on every receipt issued without an app on the
buyer's side — which today is every receipt. So the proof a buyer can actually perform with what
ships is the disclosure, and the stronger one is specified, checked and not yet in anyone's hands.
Nothing obliges a verifier to ask for either; one that never asks sees a copy and an original as the
same file.

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

That is the mechanism as the verifier evaluates it, and it is complete in both implementations. It
is not something a seller can do today, and this document says so in the same breath. The
command-line tool on the project's main branch has no command that produces a revocation record. Its
top-level verbs are `authority`, `check-artifact`, `disclose`, `export`, `grant`, `import`,
`inspect`, `issue`, `keygen`, `log`, `manifest`, `transfer` and `verify` — read off the tool's own
definition rather than off a list of what one would expect to find — and the only place it writes a
record of this shape is inside a transfer, where the record says "transferred". The bridge skips a
refunded order and issues nothing for it. On the verifier's side the picture is narrower still. The
browser page and the downloadable file consult no revocation feed at all, so there the answer is
always "unknown". And even handed a record, a verifier configured as those two are — one public log
key pinned, no block headers pinned — could not honour a refund-window withdrawal, because for a
verifier that evaluates log evidence the standard also requires proof that the record was publicly
logged and timestamped inside the window, and with no headers pinned no timestamp can be
established. Read every sentence about revocation in this document, then, as a rule the verifier
enforces, exercised today by nobody.

One more producer is missing, and it sits under the two above. The standard lets a receipt's
existence be recorded in a public, append-only log, so that it can later be dated by the clock
section 6 describes; it is what the rescue against a stolen key, and the logged refund window just
mentioned, both start from. The shipped log commands are the log operator's — create a log, append
an entry supplied as a file, sign a checkpoint, emit a proof — and none of them computes the entry a
receipt would need; the only code that does is the generator of the project's own test corpus. No
receipt issued with the shipped tools can be entered in a log today, so nothing built on logging
protects any receipt today. The gap is in tooling, it is known, and it is listed among the open
problems rather than left for a reader to discover.

What can and cannot be done today, in one place. A buyer can receive a receipt, keep it, verify it
offline at trust on first use, prove it theirs by disclosure, and share one receipt safely. A seller
can generate keys, publish and rotate a manifest, declare a key stolen, issue receipts by hand or
from a checkout, export bundles, counter-sign a transfer, and sign a preservation pledge. Neither
can, with what ships: withdraw a receipt, enter one in a log, package a compromise declaration so
that a verifier can bound it, or answer a binding challenge. The verifier evaluates all four. The
rest of this document keeps the two lists apart.

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
> result is five components with fixed literals (§11.1): `signature` valid/invalid; `schema`
> valid/invalid/not_checked; `revocation` unknown, `not_revoked_as_of:<T>`, revoked,
> invalid_revocation_ignored, and, under v0.2 §17.3, transferred; `binding`
> proven/not_proven/not_checked; `trust` verified/unauthenticated_tofu/unverified_rotation. `ok` is
> signature valid *and* schema valid *and* revocation neither revoked nor transferred *and* no
> errors; `trust` is resolved as soon as the issuer can be read and is never reset by a later
> failure, and it is `verified` only when the trust store's provenance for that issuer is `"tls"`. A
> key manifest (§7.1) carries `issuer`, a monotonically increasing `manifest_version`, `issued_at`,
> the `keys[]` entries — `kid` of the form `<domain>/keys/<label>#<name>`, `pub`, `valid_from`,
> `valid_to`, `status` in active/retired/compromised — and a `manifest_signature` over the rest;
> continuity (§7.3) requires manifest N+1 to be signed by a key active in N, and `compromised` is
> absorbing. The `.attest` bundle (§14.1) holds `receipts/*.attest.json` with `delivery.salt`
> stripped, `manifests/<issuer>.json`, `legal/<sha256>.txt` verified against each receipt's hash
> bindings at export, an optional `proofs/` member (v0.2 §14), and `README.html`; the
> `.private.attest` sibling (§14.2) holds `salts.json` and, if used, `keys/`. A receipt's `delivery`
> member (§4.2) is unsigned, may carry the salt and a manifest snapshot, and cannot forge or
> invalidate anything. Now the completeness check this document applies to every defence: for each
> input the shipped `attest verify` accepts, who produces it. `--trust-dir`: manifests from
> `manifest init`/`rotate` or an imported bundle — shipped, and the tool records their provenance as
> `bundle` unconditionally, so `verified` is unreachable from it. `--revocations`: a JSON array of
> records — no shipped producer; the only call to `revocation.build_record` in the tool sits in
> `transfer record --revocation-out` and emits `status: "transferred"`. `--disclose-identifier`,
> `--disclose-type`, `--disclose-salt`: the salt comes from `issue --salt-out` or the exported
> `salts.json` — shipped. `--disclose-challenge-nonce`, `--disclose-challenge-sig`: consumed, and
> the buyer-side signer (`commitment.sign_challenge`) has no caller in the tool — no producer.
> `--transparency`: `log prove` emits evidence for an entry already in a log, but the `receipt`
> entry itself (`tlog.receipt_core_hash`) is computed nowhere in the tool or the bridge; `log
> append` takes the entry as a file the operator wrote — no producer for receipts. `--log-keys`,
> `--anchor-policy`, `--crqc-horizon`, `--witness-policy`: verifier configuration the caller
> supplies; no pinned block headers ship with anything. `--grant-view`: `grant issue`, `grant
> declare` — shipped. `--authority-view`: `authority issue` — shipped. Three of `verify()`'s inputs
> have no command-line flag at all: `transfer_view` (the record exists — `transfer record` writes it
> — but the packaged verifier cannot be handed it), `compromise_view` (no flag, and no producer
> anywhere) and `revocation_evidence` (no flag). The browser verifier passes `null` as its
> revocation view, one pinned log key, and an anchor policy whose set of pinned headers is empty;
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

To see what such an attempt costs, name the three things people mean when they say they *own*
something they bought. They can **pass it on**: lend it, sell it, leave it to someone. It is
**theirs and not everyone's**: one buyer, one copy in use, which is what makes paying for it
sensible. And it **outlives the shop**: the bookshop closing does not empty the shelf at home.
Sharing, exclusivity, survival. A physical purchase gives all three without trying. A digital
purchase cannot give all three at full strength, and the reason is not a missing piece of
engineering.

Here is the reason, in one sentence. To enforce "one user at a time" for something that copies
freely, someone alive has to know, at the moment of use, who the current holder is — a server, a
network, a chip — and has to be consulted. To survive the death of every platform, nothing alive
can be required. Those two demands point in opposite directions, and a design has to choose which
of them gives way.

Every existing answer is such a choice, and each one is visible in the market. Digital rights
management chooses exclusivity: the file is locked, and the store's server is the arbiter that
decides whether your copy may open. Exclusivity holds exactly as long as the arbiter does; when the
store closes, so does the file, which is the story of every case in section 2. The plain DRM-free
download chooses survival: the file on your disk needs nobody's permission and opens forever, and
in exchange it says nothing — not who bought it, when, from whom, or on what terms. A DRM-free file
is anonymous. A blockchain promises an arbiter that never dies, a public ledger in which the
receipt is a token that can sit in only one wallet at a time; it pays for that promise with fees,
with a bet on that one network's longevity, with a player that has to consult the network at the
moment of use, and with a permanent public record of everyone's purchases. Locked hardware — a chip
that holds the key and will not give it up — buys exclusivity by rebuilding the closed platform
inside your own device, and chips die too.

attest's choice is stated once here and holds throughout the document. Survival is not
negotiable. Exclusivity is weakened, deliberately, from a physical fact into a term of the licence
that can be checked and refused. That sentence needs unpacking, because the difference is the
whole design.

Two things make the weakened form more than words. The first is that a receipt can be tied to a
key that only you hold, so that a copy of the receipt file, on its own, proves nothing about who
holds it: when it matters, a verifier can put a fresh question to you that only the holder of that
key can answer, and the answer is useless for any other question. The second is that the holder can
change only through a **transfer**, and a transfer is not something two buyers do between
themselves. The seller counter-signs it, retires your receipt, issues a new one to the new holder,
and records the transfer in its public log. If two transfers of the same receipt ever appear, the
one recorded first wins and the second is reported as a conflict. So a duplicated receipt fails
exactly where a copy would otherwise be useful — at resale, at a successor's desk, at an archive
that hands out files only to buyers, at a support counter — because none of those parties will
accept a receipt whose holder cannot answer for it or whose transfer was never recorded.

And here is the limit, next to the promise it limits. The key is a file too, and it copies. Two
people who share a receipt and its key share access, the way two people share a password: attest
does not prevent that and does not try to. Using a duplicated receipt in two places at once is a
breach of the licence that an honest player or marketplace can detect and decline to honour; it is
not an impossibility, and this document will not call it one. Detection itself is conditional
today: it rests on the seller's log being one log, seen the same by everyone, and that guarantee
is not yet backed by independent observers (section 8). And a transfer needs the seller alive to
counter-sign it, which is the trilemma biting back on the very corner attest chose to protect:
today, when the seller goes, transfers stop, and every receipt holds to its last recorded holder.
Making transfer authority outlive the seller is the hardest open problem on the project's list,
and it is named there rather than promised here.

The right picture is a deed, not a lock. A deed to a house does not stop anyone walking through
the door; a lock does that, and locks get changed, picked, and eventually rusted. What the deed
does is establish whose house it is, prove it to anyone who asks, and go on doing so after the
notary who drew it up is dead. The objection to the picture is obvious — if it cannot prevent
copying, it is not ownership — and it proves too much, because physical possession does not
prevent theft either. What ownership gives you is *standing*: the ability to show a stranger, on a
bad day, that this is yours. Delivery gives you the bytes. It does not give you standing, and
standing is what evaporates today.

> **In detail: the two bindings, the transfer rule, and which tools exist.** A receipt binds to
> its buyer in one of two ways (v0.1 §8). The default, for sales with no buyer-side app, is a
> *commitment*: a one-way fingerprint computed over an identifier such as an email address and a
> secret salt, so that the receipt names nobody in the clear. Proving it means disclosing both
> identifier and salt (`attest disclose`), and that proof is a bearer proof: whoever sees it can
> replay it (§8.1). The strong form is an Ed25519 public key in the signed receipt, `buyer.pubkey`,
> proven by challenge-response over a fresh nonce (§8.2) — non-replayable, and optional, `null` by
> default where there is no client. Transfer requires the strong form: a v0.2 receipt that claims
> `license.transferable: true` with no `buyer.pubkey` is a schema error (v0.2 §17.8). Transfer is
> issuer-mediated by design, never buyer-to-buyer (§17); a transfer record is honoured only when its
> inclusion in the issuer's transparency log is proven (§17.2); two logged records for the same
> receipt are a double assignment and the earliest log index wins (§17.4); walking the chain of
> title is a separate audit surface with fixed, byte-identical diagnostics (§17.5). What is
> shipped, on the command-line tool on `main`: the seller's side of a transfer (`transfer
> authorize`, `transfer record`) and the log operator's commands (`log`), and the redemption
> challenge for a preservation pledge (`grant challenge`, `grant respond`, `grant verify`, §18.7).
> The ordinary binding challenge for a receipt — the "prove this is yours" exchange described
> above — is verified by both implementations as a library call, and no shipped command runs that
> exchange. "One legitimate holder at a time" is therefore a licence term enforced by honest
> clients, and by issuers and markets refusing a receipt that fails it; the protocol supplies the
> evidence and never the enforcement.

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
runs it does not. And the service does not yet handle refunds — a refunded order is skipped, and
there is no command a seller can run today to withdraw a receipt already issued. The standard
defines how a withdrawal works and every verifier honours it; the tool that would let a seller
perform one is not shipped (section 8).

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

An attest receipt is that same confirmation — same seller, same purchase, same date — in a form a
machine can check and you can carry away. What a regulator would be asked for is not a new
obligation but a usable format for one that already exists.

The objection to make here is the honest one, and it deserves a straight answer: the email already
satisfies Article 8(7), so this is a solution looking for a problem. The email does satisfy it.
Nobody in this document claims otherwise, and a receipt on its own is not claimed to discharge the
Article either: the confirmation the law requires must carry the information the trader owed you
before the sale, and a receipt carries the purchase, not the trader's terms. What the format adds
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
    **Nota di correzione (secondo giro)**: l'elenco dei verbi qui sopra è incompleto. Misurato su
    `main` leggendo `src/attest/cli.py` con una ricerca che copre anche le chiamate spezzate su più
    righe (una ricerca a riga singola ne perde circa la metà): i verbi di primo livello sono
    `keygen manifest issue transfer grant authority log verify disclose export import inspect
    check-artifact`; sotto `manifest` stanno `init rotate artifacts`, sotto `transfer` `authorize
    record`, sotto `grant` `issue declare challenge respond verify`, sotto `log` `init append
    sign-checkpoint prove anchor ots-convert`. Nessun `revoke`, a nessun livello. La conclusione
    del punto non cambia; cambia il metodo: l'insieme si legge dal posto che lo definisce, non da
    una lista attesa. La riga 4 dell'outline porta ancora l'elenco corto e va allineata nel giro
    in cui si scrive la sezione 4.
14. **Collocazione.** Questo giro salva in `docs/whitepaper.md` su un branch dedicato, come
    richiesto; la struttura del 1° settembre prevedeva la bozza in cartella privata e l'atterraggio
    pubblico solo a fine lavoro. Se questo file deve restare privato fino alla ratifica, va detto
    ora, prima che il branch si accumuli.

*Voci aggiunte nel secondo giro (sezioni 5 e 7):*

15. **La posizione sul trilemma è quella del gate N5, e non sta ancora su nessuna superficie
    pubblica.** La sezione 5 scrive: sopravvivenza non negoziabile; esclusività indebolita da
    fatto fisico a termine di licenza verificabile e rifiutabile; prezzo dichiarato, nessuna
    prevenzione della copia. È la scelta convergente dei due verdetti del 24 agosto e della sintesi
    ratificata al gate (nota N6), ma README, FAQ e spec non la enunciano; il manifesto che la
    porta non è ratificato. **Da confermare** che il whitepaper sia la prima sede pubblica di quella
    posizione, e che «trilemma» resti il titolo (il testo lo tratta come argomento, non come
    teorema). Alternativa: intitolare «Deed, not lock» e lasciare la parola trilemma al corpo.
16. **Un fatto nuovo della famiglia C-127, trovato scrivendo la sezione 5, da registrare nei
    vincoli.** Lo scambio challenge-response che prova il binding di una ricevuta ordinaria (v0.1
    §8.2) è consumato da `verify()` in entrambe le implementazioni (`verify.py`, parametro
    `challenge=(nonce, sig)`), ma **nessun comando spedito lo esegue**: i soli `challenge`/
    `respond`/`verify` della CLI sono quelli del riscatto del pledge (§18.7, gruppo `grant`).
    Quindi la frase della FAQ «someone who copies your receipt can't prove it's theirs» è vera
    solo per ricevute con `buyer.pubkey`, e oggi solo come chiamata di libreria. La sezione 5 lo
    dice nell'«In detail». **Da decidere** se aprire un task (un verbo di challenge per il
    binding ordinario) e se la FAQ va stretta.
17. **Limite nuovo sull'art. 8(7), più cauto del README e della FAQ.** Entrambi dicono che attest
    «è la stessa conferma». La sezione 7 aggiunge che **una ricevuta da sola non è pretesa
    assolvere l'articolo**: l'art. 8(7)(a) impone che la conferma contenga le informazioni
    dell'art. 6(1) salvo già fornite su supporto durevole, e una ricevuta porta l'acquisto, non le
    condizioni del professionista. È la formulazione difendibile davanti a un giurista; se si
    preferisce quella corta, il rischio è l'obiezione «non soddisfa nemmeno la norma che invoca».
    **Da confermare**, e da propagare a README/FAQ quando E3 e #92 le riscrivono (C-125).
18. **AB 2426: la fonte primaria non è raggiungibile da qui.** `leginfo.legislature.ca.gov` non
    risolve dall'ambiente di stesura (due canali provati). Il testo di §17500.6 — divieto e le due
    vie (b)(1)(A)-(B), la clausola di separazione (b)(2), la (b)(3) e le esenzioni (b)(4)(A)-(C), con la frase
    «permanent offline download to an external storage source to be used without a connection to
    the internet» — è verificato su una riproduzione del codice che cita leginfo con data di
    accesso; data di firma e capitolo (24 settembre 2024, cap. 513 Stats. 2024) dalla scheda
    Digital Democracy di CalMatters; vigenza dal 1° gennaio 2025 da una nota di studio legale
    concorde. Tre fonti secondarie concordanti, nessuna primaria: **prima della pubblicazione va
    riletta su leginfo** da una macchina che lo raggiunge. Le sezioni 8 e 10 dell'outline la
    citano di nuovo: stessa verifica.
19. **Risposta della Commissione: verificata sul comunicato, non sulla Comunicazione.** Il testo
    cita il comunicato IP/26/1369 del 16 giugno 2026 (letto per intero) e la pagina dell'ICE
    (1,29 milioni di firme valide, 24 Stati membri). La Comunicazione formale — nel dossier
    interno indicata come C(2026) 4110 — non è stata letta; per questo la frase «non menziona la
    prova d'acquisto» è **circoscritta al comunicato**. Se si vuole l'affermazione sull'atto
    intero, va letta la Comunicazione. Corollario già noto (C-125): `docs/faq.md` su `main` dice
    ancora «code of conduct due by the end of 2026», che è più di quanto la Commissione abbia
    detto — la sezione 7 dice il contrario e la FAQ va allineata.
20. **Nomi di prodotti nel corpo.** La sezione 7 nomina le tre integrazioni del bridge (Stripe,
    itch.io, Shopify): sono nomi, non numeri, ma invecchiano allo stesso modo. Tenuti perché la
    FAQ pubblica li nomina già e perché «il bridge esiste» senza dire con cosa parla è una claim
    vuota. Alternativa: «i checkout più comuni» e il dettaglio nelle Note.
21. **La sezione 7 dice che il bridge salta gli ordini rimborsati.** Misurato in
    `bridge/src/attest_bridge/itch_adapter.py` e nei test (`refunded` e `canceled` saltati, nessun
    record emesso). È la conseguenza concreta di C-127 per un venditore reale, ed è scritta come
    limite accanto alla promessa del track 1. **Da confermare** che si possa dire in pubblico prima
    che A11 chiuda.
22. **L'immagine «deed, not lock» e la frase «Delivery gives you the bytes. It does not give you
    standing»** vengono dall'essay del 1° settembre (non pubblicato): la sezione 5 le riusa, la 7
    le richiama. Se l'essay va pubblicato a sua volta, i due testi si citeranno a vicenda; se
    muore, il whitepaper è la sede. Decisione di collocazione, non di stesura.

*Voci aggiunte nel terzo giro (sezioni 3 e 4):*

23. **La sezione 1 e il sottotitolo portano ancora «ownership» come descrizione di attest, e
    collidono con C-132.** La sezione 1 apre con «layer of ownership» e il sottotitolo dice «durable
    digital ownership»; la spec dice testualmente che una ricevuta «is not a claim of "ownership"»,
    e la resa fedele della tesi ratificata è «possession». Non li ho corretti perché sono fuori dal
    perimetro di questo giro (sezioni 3 e 4 soltanto): la sezione 3 cita la frase della spec per
    intero e usa «possession»/«evidence»; finché la 1 resta com'è, il documento si contraddice a
    distanza di due pagine. La sezione 5 usa «ownership» in senso argomentativo («what ownership
    gives you is standing»), che è un'altra cosa e non l'ho toccata. **Da correggere nello stesso
    atto in cui si ratifica la resa inglese.**
24. **L'outline citava una voce della FAQ che su `main` non esiste** («Who validates it?»). Le voci
    realmente usate per la sezione 4 sono «What does "verify offline" actually check, and what can't
    it tell me?», «Who can revoke my receipt, and what would I see?» e «Is this centralized?»; la
    riga 4 dell'outline è allineata.
25. **Lunghezza della sezione 4: 13 paragrafi contro i 9 previsti.** Il di più è tutto il criterio
    di completezza (C-129): ogni difesa descritta porta accanto il suo produttore, o la sua assenza
    — revoca, log, cutoff, challenge di binding — e la sottosezione «Withdrawing a receipt» da sola
    ne assorbe tre. Tagliare significa scegliere *quale* produttore mancante tacere. **Da confermare
    o tagliare.**
26. **La sezione 4 è la prima superficie che dice, in questi termini, che nessuna ricevuta emessa
    con gli strumenti spediti è loggabile (C-130).** README e FAQ dicono «no shipped tool logs a
    receipt yet», che è coerente; la sezione aggiunge che `log append` esiste ma prende la entry da
    un file scritto dall'operatore, e che l'unico codice che calcola la entry di una ricevuta è il
    generatore del corpus. Misurato oggi.
27. **La sezione 3 non nomina la legge per la condizione di irrevocabilità (§6.1).** La spec
    appoggia quella ricevuta a esenzioni come AB 2426; la sezione 3 dice solo che la spec la chiama
    «evidence, not a compliance determination» e rimanda alla 7, dove AB 2426 è citata con capitolo,
    data e articolo (C-125). Ripeterla in 3 avrebbe voluto la citazione intera due volte.
28. **Un fatto di contorno su C-131, verificato scrivendo**: la pagina web e l'app scaricabile
    passano `null` come vista di revoca, quindi lì la risposta è sempre `unknown` prima ancora che
    il vincolo dei pin vuoti entri in gioco. La sezione 4 dice entrambe le cose in quest'ordine —
    «non consultano alcun feed» e poi «e anche con un record in mano, configurate così, non
    potrebbero onorare una finestra di rimborso» — perché la seconda vale per chiunque copi quella
    configurazione, non solo per le due superfici.
