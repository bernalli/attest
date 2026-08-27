# attest transparency log

This is the log itself, served as static files. Its origin — the name signed into
every checkpoint — is:

    attest-receipts.org/log

## What is here

- `entries.jsonl` — **the sole source of truth.** One JSON entry per line, append-only.
  Everything else in this directory is recomputable from it.
- `checkpoint` — a [C2SP signed note](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md):
  origin, tree size, RFC 6962 tree root, and two signatures over them — Ed25519 and
  ML-DSA-65 together, so the log keeps its standing if either primitive falls.
- `tile/0/...` — level-0 leaf-hash tiles. A cache for readers, nothing more: no
  attest command reads them back, and the tree root is always recomputed from
  `entries.jsonl`.
- `config.json` — the operator's record of the origin.

## Mirroring it

Copy `entries.jsonl` and `checkpoint`. That is the whole log. Anyone may republish
them anywhere, and a mirror's copy is worth exactly what this copy is worth: the
signatures are checked against pinned keys, never against where the bytes came from.

Verification never contacts this log at all. A `.attest` bundle can carry each
receipt's evidence as a `proofs/<receipt_id>.json` member, so a buyer checks a
receipt with no network and no permission from anyone — including from us.

## What a proof from this log does and does not tell you

It tells you a receipt was **observable in this log** at a point in its history, and
that the log's own history has not been rewritten since: a signed checkpoint commits
to every entry before it, and a new one is only ever signed after proving it extends
the last.

It does **not** tell you the receipt is genuine. That is what the issuer's own
signature is for, and no amount of logging changes it.

It does **not** rule out this log equivocating — showing one history to you and a
different one to someone else. Ruling that out takes independent witnesses
co-signing the checkpoints, and this log has none: attest operates it alone. Every
result it can support therefore stops at `logged`, and never reaches `witnessed`.
We would rather say that here than let the word "transparency" imply it.

## Trusting it

The public keys that verify these checkpoints are **not published in this directory,
on purpose**. A verifier must pin log keys out of band — taking them from the log
they are meant to check would be circular. They ship inside each verifier, and are
listed in the project's documentation.

## If this log stops

Nothing already issued breaks. Proofs stay verifiable offline forever, because a
proof carries the checkpoint it was issued under. An anchor taken from this log
does one more thing than prove existence: it can also SAVE a receipt from a
compromise declaration the issuer publishes later, since a signature anchored
strictly before that declaration was anchored is one the issuer cannot take back
(spec v0.2 §19). What stops is growth: no new
entries, no successor checkpoints. That is the honest failure mode, and it is why
the evidence travels inside the bundle rather than living only here.
