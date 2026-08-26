# The two demos

Two questions, in the order people actually ask them.

**`store_dies.py` — the store dies, the receipt survives.** When you buy
something digital, the seller signs a receipt and hands it to you: that is
the part of the purchase that is actually yours. An attest receipt is not a
database row the issuing store keeps alive for you. It is a self-verifying
object. Delete the store — its signing keys, its manifests, its whole
infrastructure — and the receipt it issued still verifies, still proves who
it belongs to, and still points at an artifact that still matches.

**`pledge_dies.py` — the pledge fires, and the file comes back.** Which
answers the question that always follows: *and how do I get my file back?*
A rights holder signs a preservation pledge at the time of sale. The store
later dies. The pledge's trigger fires. An archive that has held its own
copy all along hands that copy over — but only to someone who can prove,
right there and then, that the receipt is theirs.

Neither demo is part of the protocol. attest defines a receipt format and a
verifier; it does not distribute content, and there is no `attest custodian`
command. The archive gate in the second demo is `custodian.py`, a
non-normative reference that lives here in `demo/`, outside the installed
package and outside the conformance surface.

## `store_dies.py`

Runs a fake store, `store.dies.example`, through a full purchase lifecycle,
then kills it, then proves the receipt outlived it:

1. The store generates its Ed25519 signing key and publishes its first key
   manifest.
2. It publishes a DRM-free game — a real file with real bytes — and signs
   an artifact manifest for it.
3. It issues an irrevocable (`revocability: "none"`) receipt to a buyer,
   Casey (`casey@example.com`), as a single self-contained `.attest.json`
   (the buyer-binding salt travels inside the receipt's `delivery` member).
   Casey's copy of that salt is also saved separately, so it survives
   independently of both the receipt file and the store.
4. The store exports a shareable bundle: `casey-library.attest` (safe to
   share — no secrets) and `casey-library.private.attest` (Casey's secrets).
5. **The store's entire directory is deleted** — `shutil.rmtree`, keys,
   manifests, everything. Nothing in the rest of the demo ever reads from
   it again.
6. Casey imports the bundle completely offline and verifies the receipt
   using nothing but what the bundle contained. The result: `ok: true`,
   `trust: "unauthenticated_tofu"` (this bundle was never fetched fresh
   over TLS, so trust is reported honestly, not upgraded to `"verified"`),
   and `revocation: "unknown"` (no revocation feed was ever consulted —
   the demo never claims "not revoked" when the honest answer is "no
   data").
7. Casey proves the receipt is actually theirs by disclosing the salt they
   saved in step 3 — `binding: "proven"`.
8. A *mirror* copy of the game file — held independently of the now-dead
   store, byte-identical to the original — is hashed and checked against
   the surviving receipt's artifact list. It matches.

## `pledge_dies.py`

Same world, one act further on. The rights holder is a *separate* party from
the store, with its own keys — which is the whole reason a cessation can
still be signed once the store is gone.

1–3. The rights holder and the store each publish a key manifest; the store
publishes the work; and an archive, `archive.holders.example`, keeps its own
independent copy of the file. No network anywhere: the archive is a
directory.

4. The rights holder signs a **sunset grant** — the promise, as a document,
   hash-bound to prose that a lawyer has to write for real. (The prose in
   this demo is a placeholder marked DRAFT. That part is not done.)
5. The store issues the receipt. Casey holds a signing key of their own:
   without it there is nobody the archive could later answer to.
6. **The store dies.** Casey's bundle carries the grant itself, because the
   receipt commits to it and a bundle must hold every hash-bound document
   its receipts depend on.
7. Offline verification with the grant as evidence: the pledge is there, and
   it is `dormant`. Nothing is owed yet.
8. **Refused.** Casey turns up at the archive anyway.
9. The trigger fires. Two passes, differing in this one step:
   - `publisher-declaration` — the rights holder signs a cessation
     declaration. The store is gone; the person who made the promise is not.
   - `fixed-date` — nobody signs anything, because nobody is left to. The
     backstop date the grant named has been reached, proved by an anchor
     rather than asserted by a party.
10. **Refused four more times**, at an *active* grant (below).
11. A fresh challenge, Casey's own signature over it, and the file crosses —
    then `check-artifact` confirms the delivered bytes against the receipt
    that outlived the store.

The challenge in steps 8 and 11 is the **archive's**, not Casey's: the gate
mints it, keeps it, and spends it on the first request that uses it, so an
answer to it is worth exactly one attempt whether that attempt succeeds or
fails. A request never brings a challenge of its own.

### What the gate turns away

An activated pledge is a promise to the **holder**, not to whoever turns up.

| Request | Outcome |
| --- | --- |
| The grant has not fired yet | `grant_not_activated` |
| A receipt with a byte flipped in the signed payload | `receipt_not_ok` |
| A receipt that has been revoked | `revocation_blocked` |
| A receipt that has been transferred away | `revocation_blocked` |
| A proof signed by someone holding the public bundle but not Casey's seed | `redemption_proof_invalid` |
| A proof Casey legitimately made **for a different archive**, replayed here | `redemption_proof_invalid` |
| A response Casey already used here, presented a second time | `redemption_proof_invalid` |
| The buyer-binding salt offered as proof | `salt_disclosure_rejected` |
| An archived copy that does not match the receipt, or falls outside the grant's scope | `artifact_out_of_scope` |

Two of these are worth pausing on. The **replay** is refused twice over: an
answer is only ever checked against a challenge this archive minted and has
not yet spent, and the custodian's own domain is inside the preimage the
holder signs, so an answer produced for one archive means nothing at
another. And the **salt** is refused even when everything else about the
request is valid: it would work on a verifier, and handing it to a custodian
is exactly how a holder gives away the ability to be impersonated
everywhere. That is a prohibition, not a fallback, so the gate checks it
first.

The **transfer** arrives by a side door and is worth a line of its own.
`attest verify` still has no transfer-view flag, so the verdict's
`revocation` member never reads `transferred`; what it does carry, when an
issuer-signed record says this very receipt was transferred and there is no
transfer view to resolve the claim against, is the warning
`transferred_revocation_unbacked`. Only the issuer can produce that warning,
and only for that receipt id, so the gate reads it and refuses: whoever is
owed the copy, it is no longer certainly the party at the door.

Two things the gate deliberately does **not** do. It does not distinguish
bad redemption proofs: a wrong key, a replayed response, or an answer to
another archive's challenge all give the same proof answer. Other refusal
classes remain distinct in this demo because `Decision` is a narration
object, not a wire protocol; a real gate would decide separately how much of
that reason to tell the requester. And it does not treat a *bogus* revocation
record as a reason to refuse — against an irrevocable receipt the verifier
reports such a record as ignored, and a gate that read "something was
ignored" as a refusal would hand any passer-by a denial-of-service against a
holder they have no relationship with. (The transferred-record warning above
is the opposite case, and the difference is who can produce it.)

### What this gate does not cover

Three gaps a production gate would close, stated plainly because a reference
that hides them teaches the wrong thing.

A receipt id is not a secret — it travels in the shareable bundle — and this
archive keeps at most one outstanding challenge per receipt, spent by use.
So anyone holding a copy of the public bundle can **burn** the challenge a
legitimate holder is about to answer, by answering it wrongly first or by
asking for a fresh one that supersedes it. Nobody gets bytes and nothing is
disclosed; the holder simply has to ask again, and an attacker who keeps
doing it keeps them asking. A production gate would key its challenges by
nonce rather than by receipt, and let several stand at once.

It also serves the file with a `shutil.copy` **by path**, after verifying the
bytes at that path. Anyone with write access *inside* the archive directory
can substitute the file between the check and the copy, and the delivery
would carry bytes that were never verified. A real gate opens the file once
and serves from that descriptor, so the thing it checked is the thing it
sends.

And containment is decided on the **resolved** path, so a symlink inside the
archive pointing outside it is refused. That is the safe direction, but it
rules out a content-addressed archive that keeps its blobs on another volume
and links to them — a shape common enough that a production gate would need
an explicit allowlist of roots rather than a single directory.

### Why this is lawful, in this story

The delivery happens because the **rights holder granted it**, in a signed
document, in advance, naming this exact work — and it is restricted to
someone holding a receipt for that work. Neither half is decoration: without
the grant there is no permission, and without the receipt there is no
restriction. What people holding the same permission may then do among
themselves is a consequence of the licence they were granted, not a
component of attest, and nothing in this repository implements it.

## How to run them

From the repository root, with narration printed to stdout:

```
.venv/bin/python -m demo.store_dies
.venv/bin/python -m demo.pledge_dies
```

As integration tests:

```
.venv/bin/pytest tests/test_demo_e2e.py tests/test_demo_pledge_e2e.py -v
```

Both are fully offline and hermetic — everything happens inside a fresh
temporary directory (`tempfile.TemporaryDirectory` for the manual run,
pytest's `tmp_path` for the tests), and each demo only ever deletes its own
`store/` subdirectory, never anything outside that workspace. A test asserts
that boundary directly, with a canary file placed just outside it.

Every step of both demos is asserted programmatically, not eyeballed: the
pytest wrappers check each verb's exit code and JSON result against the
exact values the design promises, and the second one additionally pins that
the dormant refusal is recorded **while the declaration does not yet exist
on disk**. A refusal narrated after the trigger has already been minted
would be theatre.

## The files you must never share

Now two of them.

**`casey-library.private.attest`** holds Casey's buyer-binding salt, which is
what proves a receipt belongs to them. `casey-library.attest` (no `.private`
in the name) is safe to share or publish: `export()` strips every salt from
it before writing it out.

**The buyer's signing seed** (`buyer/buyer.seed`) is the second, and in the
pledge story it is the more consequential of the two: losing it means losing
the ability to redeem at all, and giving it away means someone else can. It
is what Casey signs the archive's challenge with.

Both are written owner-only (`0600`) from creation, exactly like the CLI's
own secret-writing paths — they are real secret material, not scaffolding,
and a test checks the mode on both.
