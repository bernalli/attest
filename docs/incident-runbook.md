# Incident runbook — when your signing key is stolen or lost

This is for the person who sells things and signs receipts. Not for a
cryptographer. If you have just found out that someone got into your server,
start at step 1 of the case that matches and work down the list in order. The
order is the important part.

Your signing key is the thing that makes your receipts yours. It is a small
secret file — the one you passed to `--seed` when you set up. Everything below
is about what to do when that file ends up somewhere it should not be, or
nowhere at all.

**If nothing has happened yet**, read [Before it happens](#6-before-it-happens)
now, today. One decision in there — where you keep the backup of your key —
decides which of the two cases below you get to have. You cannot make that
decision during an incident.

---

## 1. Which incident is this?

Two very different things get called "we lost the key". Tell them apart before
you touch anything.

**Theft.** Somebody else has a copy of your key. You probably still have yours
too — a key is a file, and files get copied, not carried off. Signs: an
intrusion on the machine that held the seed, a leaked backup, a stolen laptop, a
seed file that turns up in a repository or a log, a contractor who kept a copy.

**Loss.** The key is gone and, as far as you can tell, gone for everyone. Signs:
a dead disk with no backup, a wiped machine, a password manager you can no
longer open, an employee who left with the only copy and cannot be reached.

**If you cannot tell which one it is, treat it as theft.** Theft is the case
where waiting costs you something. Loss is the case where the damage is already
final and an hour will not change it.

---

## 2. Case A — the key was stolen or copied

### Step 1. Get your domain back first. Before anything else.

Your identity in attest is your domain name. Verifiers trust the key file you
publish at `https://your-domain/.well-known/attest.json`, fetched over TLS from
your own domain. That is the whole root of trust.

So the thief with your key does not just get to sign fake receipts. If they also
control your domain or your hosting, they get to publish their own key file at
your address — and then it is *their* version of the truth that reaches your
customers, not yours. Everything else in this runbook is you publishing a new
key file. If the thief can replace it five minutes later, you have done nothing.

Concretely, before you rotate anything:

1. Change the password on your domain registrar account and turn on two-factor
   authentication.
2. Change the password on your DNS provider and your web host. Same again.
3. Check the DNS records for your domain against what you expect. Look for name
   servers you did not set and records you did not create.
4. Check who has access to the server or bucket that serves
   `/.well-known/attest.json`. Revoke API tokens, deploy keys, and SSH keys you
   do not recognise.
5. Only when you are sure you are the only one who can change what that URL
   serves, go on to step 2.

This is the step people skip because it does not feel technical enough. It is
the one that decides whether the rest works.

### Step 2. Stop signing new receipts.

Turn off the service that issues receipts, or take its key away from it. Every
receipt you sign from now on with the stolen key is one more thing you will have
to reissue in step 7.

### Step 3. Make a new key.

```sh
attest keygen --seed-out new.seed --pub-out new.pub
```

`new.seed` is the secret. Treat it the way you should have treated the last one
— see [Before it happens](#6-before-it-happens). `new.pub` is public and safe to
share.

Give the new key a label that is not the old one. The format is
`<your-domain>/keys/<label>#<name>`, for example
`store.example.com/keys/2026-q3#ed25519-1`.

### Step 4. Rotation one — add the new key.

```sh
attest manifest rotate \
  --in key-manifest.json \
  --signing-kid 'store.example.com/keys/2026-q1#ed25519-1' \
  --signing-seed old.seed \
  --new-kid 'store.example.com/keys/2026-q3#ed25519-1' \
  --new-pub new.pub \
  --valid-from 2026-09-01T00:00:00Z \
  --issued-at 2026-09-01T00:00:00Z \
  --out key-manifest.v2.json
```

`--signing-kid` and `--signing-seed` are the *old* key. You still have it, so
you can still sign with it. This step only adds the new key alongside the old
one; it does not yet say anything is wrong.

### Step 5. Rotation two — mark the old key compromised.

```sh
attest manifest rotate \
  --in key-manifest.v2.json \
  --signing-kid 'store.example.com/keys/2026-q3#ed25519-1' \
  --signing-seed new.seed \
  --compromise-kid 'store.example.com/keys/2026-q1#ed25519-1' \
  --issued-at 2026-09-01T00:05:00Z \
  --out key-manifest.v3.json
```

Note what changed: `--signing-seed` is now the **new** key.

**Why this is two commands and not one.** You might expect to mark the old key
compromised and sign that statement with the old key, since you still have it.
The tool refuses:

```
error: signing kid 'store.example.com/keys/2026-q1#ed25519-1' cannot be in the
compromised set — sign the recovery manifest with a different, still-active key
```

The reason is simple once you see it. The thief has that key too. If a statement
signed by the stolen key were enough to declare an emergency, the thief could
sign one about *your* keys just as easily. So the declaration has to come from a
key the thief does not have. If the stolen key was the only one you had, you have
to create the new one and put it in the key file first — which is exactly what
step 4 does. Two rotations, in this order, always.

### Step 6. Publish the new key file.

Put `key-manifest.v3.json` at `https://your-domain/.well-known/attest.json`,
replacing what was there. Any static hosting works; this is one public file.

Keep every earlier version of the file. Do not delete them. Buyers who hold your
older key files use them to check that your key history is unbroken, and a gap
in that history is something their verifier will tell them about.

**If you use the transparency log**, submit and anchor this new key file as fast
as you can. A receipt that was anchored in the log *before* your compromise
declaration was anchored keeps its standing with verifiers that check anchors —
including receipts the thief anchored. The longer you wait, the more of the
thief's work survives your declaration. If you do not run a log, skip this; it
changes nothing else in this runbook.

### Step 7. Reissue the affected receipts.

Every receipt signed with the compromised key now fails verification. Not
"shows a warning" — fails. This is what a buyer sees after step 6:

```json
{
  "ok": false,
  "signature": "invalid",
  "errors": ["key store.example.com/keys/2026-q1#ed25519-1 is compromised"]
}
```

That is the system working correctly. The alternative would be trusting
signatures that your attacker can also produce, and there is no way to tell the
two apart from the outside.

So: sign a fresh receipt for every affected purchase, with the new key, and send
it out.

```sh
attest issue --payload payload.json --seed new.seed \
  --kid 'store.example.com/keys/2026-q3#ed25519-1' --out receipt-new.json
```

If you set the `supersedes` field in the new receipt's payload to the old
receipt's `receipt_id`, it records that the new one replaces the old. That is a
bookkeeping note only — it does not cancel the old receipt and verifiers are
required not to read it that way.

### Step 8. Tell your buyers.

Use the theft text in [section 5](#5-what-to-tell-your-buyers). Do it in the
same working day. Their receipts have stopped verifying and they will notice.

---

## 3. Case B — the key is lost

Read this even if your key is safe. The part that matters is a decision you make
before an incident, not during one.

### What you can no longer do

Rotation is how you keep a chain of trust unbroken: the new key file has to be
signed by a key that was already good in the old one. That is the whole point —
it proves the new file came from the same person as the old one.

So `attest manifest rotate` requires `--signing-seed`. Without the old key there
is no command to run:

```
attest manifest rotate: error: the following arguments are required: --signing-seed
```

There is no flag for "I lost it". There cannot be one. A way to publish a new
key file without proving you held the old one is exactly the capability a thief
would want.

### What actually happens to your buyers

**Your old receipts keep verifying** — but only while your old key file stays
reachable. Nothing has marked the lost key compromised, so the signatures it
made are still good. What a verifier needs is the key itself, and that lives in
the old key file. If you replace it with a new one that does not list the old
key, verification fails with `no key '<kid>' in issuer manifest`.

So: **keep the old key file, and keep serving it.** This is the single most
useful thing you can do after losing a key.

**Anything new you publish is not connected to the old history.** You can create
a fresh key file with `attest manifest init` and a new key, but it cannot be
signed by the key you lost, so nothing links it to the file that came before.
Buyers who hold both see a break, and their verifier reports it:

```json
{ "trust": "unverified_rotation" }
```

Be honest with yourself about what that is. It is a permanent mark in your key
history. It does not go away when you rotate again later, because it is a fact
about a gap, and the gap stays. Every buyer who checks carefully will see that
at some point your chain of custody broke and you asked them to take the new key
on faith. That is the price of the lost backup, and you pay it once, forever.

### What to do

1. Do not delete or overwrite the old key file. Serve it, keep a copy, and
   include it in the bundles you hand to buyers.
2. Make a new key, and this time write down where the backup lives —
   [section 6](#6-before-it-happens).
3. Tell your buyers, using the loss text in
   [section 5](#5-what-to-tell-your-buyers). For them this is much better news
   than theft, and you should say so plainly.
4. Sign new purchases with the new key from now on.

---

## 4. There is no help desk

There is no attest portal. No support address that can restore your identity. No
registry, no certificate authority, no company holding a copy of your key, no
recovery code, no "verify your business documents and we'll reissue it". Not
because nobody built it yet. Because it must not exist.

An authority able to hand your identity back to you is an authority able to hand
it to somebody else. It could be tricked, subpoenaed, bought, or breached — and
on that day every receipt you ever signed would be worth exactly as much as that
authority's judgement. The reason your receipts still verify after your store
closes is that no such body sits between them and the person checking. You
cannot have both.

The same rule runs all the way down. There is no un-compromise. Once a key is
marked compromised, no later key file can walk that back — the tool refuses
(`compromised kid(s) cannot change status`) and verifiers are required to keep
treating it as compromised. If the marking was made in error, or by an attacker
holding another of your keys, the remedy is the same as everything else here: a
new key, and reissued receipts. There is no button, and there is no appeal.

What you get instead of a help desk is this: nobody can take your identity
either. Every recovery path this document does not offer you is also a path that
does not exist for anyone attacking you.

---

## 5. What to tell your buyers

Two incidents, two opposite messages. Do not mix them up: telling loss-case
buyers that their receipts are void causes damage you cannot undo, and telling
theft-case buyers that nothing changed is worse.

### If the key was stolen — their receipts have stopped working

> **Subject: Your receipt from [store] needs replacing — action taken on our side**
>
> Hello,
>
> On [date] we discovered that the signing key we use to issue your purchase
> receipts had been copied by someone outside our company. We have secured our
> systems, replaced the key, and published a signed notice that the old key is no
> longer to be trusted.
>
> **What this means for you.** The receipt file we gave you for your purchase
> will now fail verification. Your purchase is not affected — our records of what
> you bought are unchanged, and so are your rights to it. What stopped working is
> the signature on the receipt file, and it stopped working on purpose: we had to
> declare the old key untrustworthy so that nobody could use the stolen copy to
> forge receipts in our name.
>
> **What you need to do.** Attached (or at [link]) is a replacement receipt for
> the same purchase, signed with our new key. Keep it in place of the old one.
> You can delete the old file, or keep it — it does no harm, it simply no longer
> verifies.
>
> **What we do not know.** We cannot rule out that receipts were issued in our
> name using the stolen key between [date of compromise, or your best estimate]
> and [date you published the new key]. If you were sent a receipt from us in
> that period that you did not expect, please tell us.
>
> We are sorry. [Name], [store]

### If the key was lost — nothing changes for them

> **Subject: A note about our receipt signing key — no action needed**
>
> Hello,
>
> A short technical notice, so you hear it from us rather than noticing it later.
>
> We have lost access to the key we used to sign purchase receipts up to [date].
> It was not stolen or exposed — we simply no longer have our copy of it.
>
> **What this means for you: nothing.** Your receipt still verifies, exactly as
> before. The signature on it is still valid and will stay valid. You do not need
> to replace anything, do anything, or keep anything you were not already
> keeping. We will continue to publish the old key file so that your receipt
> keeps checking out.
>
> **What changes on our side.** Receipts for new purchases will be signed with a
> new key. Because we cannot sign the new key with the old one, tools that check
> carefully will show that our key history has a gap at this point. That is
> accurate, and we would rather you saw it than not.
>
> Nothing you bought is affected. [Name], [store]

---

## 6. Before it happens

This is the part that decides which of the two cases above you get.

**Back up the seed file, properly.** It is a tiny file. Put it somewhere that
survives the machine it lives on, encrypted, and where more than one person can
reach it — a password manager with a shared vault, a printed copy in a safe, a
hardware token. If your only copy is on the server that issues receipts, then one
disk failure moves you into case B and its permanent gap. This is the decision
this whole document exists to make you take early.

**Never store the seed next to what it signs.** Not in the repository, not in the
container image, not in a backup that anybody with read access to your website can
fetch. The tools refuse to write a seed and a manifest to the same path for
exactly this reason.

**Have a second key before you need one.** If your key file lists two active keys,
then on the day one is stolen you already have the still-good key that step 5
requires, and you can declare the compromise immediately instead of scrambling
through step 4 first.

**Use one key per period.** Instead of signing everything you ever sell with one
key, issue a new one on a schedule — quarterly, say, with a label that names the
quarter (`store.example.com/keys/2026-q3#ed25519-1`). The specification
recommends this, and it is worth understanding exactly what it buys you and what
it does not.

What it buys you: it bounds **forgery**. A thief who steals your Q3 key can only
produce convincing fakes that fit inside Q3. They cannot reach back and forge
something dated to a period whose key they never had.

What it does not buy you, and you should know this before you rely on it: it does
**not** bound how far a compromise marking reaches. Any key that is still active
can publish a key file marking *any* of your other keys compromised — that is the
mechanism you use in step 5, and it does not care about periods. So a thief who
takes an active key can, in principle, declare your whole key history
compromised, and there is no un-compromise to undo it. Per-period keys shrink the
forgery window. They do not make a theft survivable on their own. What makes it
survivable is step 1: keeping control of your domain.

**Never leave yourself with no active key.** A rotation that would retire or
compromise your last active key is refused, and it should be — a key file with
nothing active in it is a dead end you cannot rotate out of. If you are closing
down, that is a different procedure, not a rotation.

**Never drop a key from a later key file.** Once a key has appeared in your
published key file, keep listing it, whatever its status. Removing it is treated
as a break in your history.

**Practise this once.** Run through case A on a throwaway domain and a throwaway
key, end to end, before you need it. It takes twenty minutes on a quiet
afternoon. Steps 4 and 5 in the middle of a real incident are not where you want
to be reading a document for the first time.

---

## Quick reference

| Situation | Old receipts | Command | What buyers see |
| --- | --- | --- | --- |
| Key stolen — declared compromised | **Stop verifying** | `manifest rotate --compromise-kid` (twice, see §2) | `"ok": false`, `key ... is compromised` |
| Key retired normally, end of its period | Stay valid | `manifest rotate --retire-kid` | `"ok": true` with a warning that the key is retired |
| Key lost, old key file still served | Stay valid | none possible | `"ok": true` |
| Key lost, old key file taken down | **Stop verifying** | none possible | `no key '<kid>' in issuer manifest` |
| New key file with no link to the old one | Unaffected by itself | `manifest init` | `"trust": "unverified_rotation"` |

A key that was retired earlier can still be marked compromised later, if you
find out after the fact that it had been copied. Retirement is not a shield.

## Where to read more

- [`docs/spec/attest-v0.1.md`](spec/attest-v0.1.md) §7.1, §7.3 and §7.4 — key
  files, rotation, compromise, and where trust comes from. Normative; this
  runbook is not.
- [`docs/faq.md`](faq.md) — what a receipt is worth in each situation, including
  after a store is gone.
- [`SECURITY.md`](../SECURITY.md) — how to report a vulnerability in attest
  itself. Not for your own incident; that is what this document is for.
