# itch.io setup: zero to a verified receipt

Read [setup-stripe.md](setup-stripe.md) first if you haven't — steps 1–2
(keypair + key manifest) and 5 (deploy) are identical regardless of platform;
this page only covers what's itch-specific: configuration, and how buyers
actually get their receipt.

## The honest limitation, up front

itch.io has no purchase webhook and no purchase-list/pagination API at all —
this is source-verified against `api.itch.io`'s documented surface
(`credentials/info`, `profile`, `profile/games`,
`games/{id}/purchases?email=|user_id=`, `games/{id}/download_keys`,
`wharf/latest`; nothing else). So issuance here can never be push-driven the
way Stripe's webhook is. Instead, this bridge runs a **claim-queue poller**:
something (a buyer, or your own CSV backfill) enqueues an `(email, game_id)`
claim, and a background poller drains due claims by calling
`GET /games/{game_id}/purchases?email=...` on the real itch API — **that API
response is the sole issuance authority**. A claim by itself never issues
anything; only an itch-API-confirmed purchase does. This also means: itch
receipts are **email-bound only** — itch has no metadata/custom-field
carrier like Stripe's Checkout Session, so there is no way for a buyer to
attach a public key at purchase time (upgrading an itch receipt to a
transferable, pubkey-bound one later is a separate re-issue flow, out of
scope for this bridge).

## 1. Get your itch.io API key

itch.io Dashboard → your account → **API keys** (or directly
`https://itch.io/user/settings/api-keys`) → generate one. This is the key
`attest-bridge` uses to confirm purchases against the live API — it is a
secret; never commit it.

## 2. Configure the bridge

In your `bridge.toml` (see [setup-stripe.md](setup-stripe.md) step 3 for the
rest of the file):

```toml
[itch]
api_key_env = "ITCH_API_KEY"
poll_interval_seconds = 60
max_attempts = 10
```

Set `ITCH_API_KEY` in your deploy environment to the key from step 1
(alongside `STRIPE_WEBHOOK_SECRET` etc. — see [deploy.md](deploy.md)).

itch claims are delivery-only-via-email, so an itch configuration also
requires a working `[delivery]` SMTP table. The bridge rejects a config with
`[itch]` but no delivery settings rather than accepting claims it could not
safely deliver.

Add one `[products.itch_<game_id>]` table per game you sell — the product
key is always `itch_` followed by the itch game id (the numeric id in your
game's itch.io URL/dashboard, not the game's slug):

```toml
[products.itch_123456]
title = "Nebula Drifters"
publisher = "Example Games Store"
artifact_series = "store.example.com/works/nebula-drifters"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
[products.itch_123456.identifiers]
itch_game_id = "123456"
```

`legal_text_sha256` must be exactly 64 lowercase hex characters (the schema
rejects anything else, including a placeholder like `"…"` — every issuance
for a product table with a malformed hash fails before signing, not after).
The all-zeros value above is a format-valid placeholder, matching the
shipped [`bridge/examples/bridge.toml`](../examples/bridge.toml); replace it
with the real SHA-256 of your license terms text:

```sh
shasum -a 256 license.txt | cut -d' ' -f1      # macOS/BSD
sha256sum license.txt | cut -d' ' -f1          # Linux
```

Point `legal_text_path` at that same `license.txt`, wherever your deploy
target mounts it — it's the file you just hashed, not a new artifact:

```toml
legal_text_path = "/etc/attest-bridge/licences/nebula-drifters.txt"
```

The bridge reads and re-hashes this file **at startup**: it does not start
(naming this product key) if the file is missing, unreadable, or its hash
doesn't match `legal_text_sha256` above — the field alone was never enough,
since the signed hash and the file on disk could otherwise drift apart
unnoticed.

`poll_interval_seconds` is how often the poller checks due claims;
`max_attempts` is how many times a single claim retries (with exponential
backoff) against the itch API before it's marked `exhausted` and needs a
fresh claim to try again — a claim never issues on its own, so a merchant
with a lot of one-off failures is not at risk of double-issuing, only of a
buyer needing to re-submit their claim.

## 3. The two ways a claim gets enqueued

**Buyer self-service.** Point a "Get your signed receipt" link on your
game's page (or in the itch download/thank-you page) at:

```
https://<your-bridge-host>/itch/claim
```

`GET` on that URL serves a plain HTML form (email + a dropdown of your
configured games); submitting it (`POST` to the same URL) enqueues the claim.
There is nothing to poll: if the live itch API finds a matching purchase, the
receipt is sent to the submitted mailbox. The claim API never returns a token,
receipt URL, or other receipt-derived information.

**CSV backfill**, for buyers who purchased before you set the bridge up, or
in bulk: export your buyer list from the itch.io dashboard (Analytics/Sales
→ export CSV) and run:

```sh
attest-bridge itch-import --config bridge.toml --game-id 123456 purchases.csv
```

Only the CSV's `email` column is read (any other columns are ignored, and
the header match is case-insensitive) — every unique email in the file gets
one claim enqueued for that game id. Exactly like the buyer-facing form
above, enqueuing here **never issues a receipt by itself**: the poller still
has to confirm each one against the live itch API before anything is
signed. A CSV row for someone who never actually bought the game simply
never resolves (its claim keeps retrying, then exhausts).

## 4. Dry run: a verified receipt on your own machine first

Unlike the Stripe and Shopify rails, itch has no webhook you can replay
locally — so without this step your first real test would be production. Run:

```sh
attest-bridge itch-dry-run --config bridge.toml
```

This enqueues a claim for `itch-dry-run@example.invalid`, ticks a local
poller against an in-process fake itch API, normalizes a synthetic *settled*
purchase, signs a receipt for your real `[products.itch_<game_id>]` mapping,
records it in a throwaway Ledger, and writes the receipt file mode `0600`.
Your configured `ledger_path` is never opened, and the fake API exists only
inside this command — no config key or environment variable can point the
`serve` poller at it.

The signed buyer identity is always `itch-dry-run@example.invalid`, and it is
not configurable: `--email` is only an SMTP recipient, and only together with
`--send-email`:

```sh
attest-bridge itch-dry-run --config bridge.toml --send-email --email you@your-domain.example
```

Verify the receipt offline:

```sh
attest verify itch-dry-run-receipt.attest --trust-dir <dir-containing-key-manifest.json>
```

What this proves: your catalog mapping, key loading, signing, verifier
compatibility, claim draining, and — with `--send-email` — your SMTP
transport. What it cannot prove: that your real `ITCH_API_KEY` is accepted by
the live API, or that it can see real buyer purchases. Only the live test
below proves those.

## 5. Test it live

Once the poller has run (within `poll_interval_seconds` of enqueuing), a
matching purchase's receipt arrives by email — itch claims are
delivery-only-via-email (step 2), so this is the only path here, unlike
Stripe and Shopify's optional download link. It arrives as **two
attachments**, not one: `<issuer-slug>-<receipt_id>.attest` (shareable — the
receipt with its salt removed, plus your key manifest and the licence text,
so it verifies even after your store is gone) and
`<issuer-slug>-<receipt_id>.private.attest` (the buyer's own secret,
carrying `delivery.salt`; the web verifier refuses a file with that name on
sight). Save both with restrictive creation permissions. A buyer verifies by
dragging the shareable half into the web verifier your `info_url` points at;
from this CLI, reconstruct it first:

```sh
umask 077
chmod 600 *.attest   # both halves arrive 0600 already; this just matches on re-save
attest import --bundle <issuer-slug>-<receipt_id>.attest \
  --private <issuer-slug>-<receipt_id>.private.attest --out-dir ./imported
attest verify ./imported/receipts/<receipt_id>.attest.json --trust-dir ./imported/trust
```

`"ok": true` closes the loop. See [setup-stripe.md](setup-stripe.md)'s
notice boxes (salt tradeoff, the Ledger database is a secret, Stage 2 is
opt-in) — they apply here identically; itch changes nothing about the
receipt's trust properties, only how a purchase gets confirmed.
