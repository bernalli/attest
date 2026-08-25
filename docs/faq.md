# FAQ

Honest answers to the questions a skeptical first visitor asks. Same register as
the [README](../README.md): where the answer is "no," this says why, and what the
real lever is instead.

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
itself. It doesn't strip or bypass DRM, it isn't a marketplace or distribution
channel, and it isn't a resale or transfer mechanism in this version (the
`transferable` field is reserved, not implemented). Having a valid attest
receipt says only that an issuer signed a claim that a license was granted — it
carries no copy of the work and grants no access to one.
