# The three demos

Three questions, in the order people actually ask them.

**`store_dies.py` — the store dies, the receipt survives.** When you buy
something digital, the seller signs a receipt and hands it to you: that is
the part of the purchase that is actually yours. An attest receipt is not a
database row the issuing store keeps alive for you. It is a self-verifying
object. Delete the store — its signing keys, its manifests, its whole
infrastructure — and the receipt it issued still verifies, still proves
possession by whoever holds its binding secret, and still points at an
artifact that still matches.

**`pledge_dies.py` — the pledge fires, and the file comes back.** Which
answers the question that always follows: *and how do I get my file back?*
A rights holder signs a preservation pledge at the time of sale. The store
later dies. The pledge's trigger fires. An archive that has held its own
copy all along hands that copy over — but only to someone who can prove,
right there and then, that they hold the receipt's binding secret.

**`witness_cosigns.py` — somebody else saw the same head.** Which answers
the question underneath both of the others: *how do I know the log is showing
me the same tree it shows everyone?* A signature says who signed; it never
says how many different things they signed. A log that holds its own keys can
publish two self-consistent branches, and every proof from either verifies.
A witness reads the log's head, refuses to sign one that is not an extension
of the head it signed last, and cosigns the rest — so a verifier can tell a
head somebody observed from a head nobody did.

None of the three is part of the protocol. attest defines a receipt format
and a verifier; it does not distribute content, and there is no `attest
custodian` command, nor an `attest log cosign` one. The archive gate in the
second demo is `custodian.py`, and the submission client in the third is
`witness_client.py` — both non-normative references that live here in
`demo/`, outside the installed package and outside the conformance surface.

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
7. Casey proves possession of the receipt's binding secret by disclosing
   the salt they saved in step 3 — `binding: "proven"`.
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
everywhere. That is a prohibition, not a fallback, so once the receipt input
has been frozen, the gate checks it before the authenticity and proof work.

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
So anyone holding a copy of the public bundle can **burn** the challenge the
holder of the private key named by the issuer is about to answer, by
answering it wrongly first or by asking for a fresh one that supersedes it.
Nobody gets bytes and nothing is disclosed; the holder simply has to ask
again, and an attacker who keeps doing it keeps them asking. A production
gate would key its challenges by nonce rather than by receipt, and let
several stand at once.

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

## `witness_cosigns.py`

Three parties this time, and they are separate on purpose: a store, a
transparency-log operator, and a witness. A witness that shared the log's
keys would observe nothing.

1. Each generates its own key pair — the log and the witness hybrid, because
   checkpoint authentication and cosignature both have an ML-DSA-65 leg.
2. The store publishes its key manifest; the log operator creates an empty
   log.
3. The store issues Casey's receipt **into** the log (`issue --log-dir`). The
   entry is the one the CLI computes from the receipt it has just signed —
   not a row written by hand beside it.
4. The log's offline signer signs the checkpoint. That step holds the log's
   keys; the appending step never does.
5. The witness is configured with that one log pinned, and served over real
   HTTP on a loopback port. Its allowlist is the whole of what it trusts:
   there is no default and no wildcard.
6. The checkpoint is submitted with C2SP's `add-checkpoint` body. The witness
   answers `200` with two signature lines — the interoperable Ed25519 `0x04`
   leg and attest's namespaced ML-DSA-65 one — which are **appended** to the
   note, never substituted for it. Its monitoring endpoint then serves that
   cosigned note to anyone who asks.
7. `attest log prove` writes the inclusion evidence, which is re-pointed at
   the cosigned note and told which witness-policy epoch to read.
8. `attest verify` runs **twice**, over the same receipt, the same pinned log
   keys and the same witness policy. Without the cosignature lines:
   `corroboration: "logged"`. With them: `corroboration: "witnessed"`, plus
   `witness_independence_not_established` — which every witnessed verdict
   carries, because one witness is one observer and nothing here establishes
   that it is independent of the log. The demo runs both.
9. **The fork.** The log signs a second, different tree of the same size: a
   genuine signature over dishonest contents, which is precisely what a log
   holding its own keys can do. The witness refuses it — C2SP `422`, the
   consistency proof does not verify — and goes on serving the head it
   actually saw.

Step 8 is the whole demo, and step 9 is why it is worth anything. Two joins
this chain needs had no usable implementation before: a C2SP submission body
was built only by test-local helpers under `witness/tests/`, which nothing
outside that package can import, and nothing at all carried a returned
cosignature back into the evidence a verifier reads. Both live in `witness_client.py`, which also
refuses the one substitution that would make "add a cosignature" mean
something else — a cosigned note whose body is a different checkpoint from
the one the evidence's inclusion proof is about.

Two traps an operator meets here, stated because both cost a wrong answer
rather than an error. `attest verify` needs `--anchor-policy` to be supplied
even when there is no anchor to evaluate: with `--transparency` and
`--log-keys` alone the verdict comes back `transparency: "not_checked"` and
the warning `transparency_config_missing`. And a missing
`witness_policy_epoch` in the evidence reports `corroboration: "logged"` and
names no condition at all — step 8's silence is normative (v0.2 §11.4), so
an omitted member is indistinguishable from a witness that did not count.

## How to run them

From the repository root, with narration printed to stdout:

```
.venv/bin/python -m demo.store_dies
.venv/bin/python -m demo.pledge_dies
.venv/bin/python -m demo.witness_cosigns
```

As integration tests:

```
.venv/bin/pytest tests/test_demo_e2e.py tests/test_demo_pledge_e2e.py \
                 tests/test_demo_witness_e2e.py -v
```

All three are hermetic — everything happens inside a fresh temporary
directory (`tempfile.TemporaryDirectory` for the manual run, pytest's
`tmp_path` for the tests) — and each has a test that proves that boundary
directly, with a canary file placed just outside it. The first two only ever
delete their own `store/` subdirectory and nothing outside their workspace;
the third deletes nothing at all.

Only the third touches a socket, and that is the point of it: it binds a
witness on `127.0.0.1` with an ephemeral port and submits over real HTTP,
because a demo that called the WSGI app in-process while narrating
"submitted to the witness" would be narrating something that did not happen.
The server is closed on the way out, including on the error path, and a test
checks the port is no longer answering once the run returns. Nothing leaves
the loopback interface.

Every step of all three demos is asserted programmatically, not eyeballed:
the pytest wrappers check each verb's exit code and JSON result against the
exact values the design promises. The second additionally pins that the
dormant refusal is recorded **while the declaration does not yet exist on
disk** — a refusal narrated after the trigger has already been minted would
be theatre. The third judges the witness's cosignature against an oracle
re-derived from v0.2 §9.2 — the key id, the signed payload, the blob layout
and the line framing written out from the specification, with the signatures
checked by the raw primitives — because an oracle built out of the code that
produces a cosignature agrees with a wrong implementation as readily as with
a right one.

## The files you must never share

Now two of them.

**`casey-library.private.attest`** holds Casey's buyer-binding salt, which
is what proves possession of the receipt's binding secret.
`casey-library.attest` (no `.private` in the name) is safe to share or
publish: `export()` strips every salt from it before writing it out.

**The buyer's signing seed** (`buyer/buyer.seed`) is the second, and in the
pledge story it is the more consequential of the two: losing it means losing
the ability to redeem at all, and giving it away means someone else can. It
is what Casey signs the archive's challenge with.

Both are written owner-only (`0600`) from creation, exactly like the CLI's
own secret-writing paths — they are real secret material, not scaffolding,
and a test checks the mode on both.

The third demo adds none of the buyer's, and two of somebody else's: the
log's signing keys and the witness's. Both are written by `attest keygen`,
which is where their `0600` comes from, and both are online keys by the
nature of the role — a witness signs on every accepted submission. In a real
deployment the log's signer is the one that is not: `attest log append` never
holds it, and only `attest log sign-checkpoint`, run separately, does.
