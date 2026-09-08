# Paddle setup: zero to a verified receipt

Read [setup-stripe.md](setup-stripe.md) first if you haven't — steps 1–2
(keypair + key manifest) and the deploy step are identical regardless of
platform; this page covers what is Paddle-specific.

## What this rail is, in one paragraph

Paddle **Billing** sends your bridge a signed `transaction.completed`
notification when a payment has finished settling. The bridge verifies the
signature, then makes exactly one call back to Paddle's API to fetch the
buyer's email: a Billing transaction payload carries a `customer_id` but no
address, so unlike the Shopify rail this one cannot issue from the delivery
alone. That is why it needs two secrets rather than one.

This rail is Paddle **Billing** only. If your account is on **Paddle
Classic**, the alerts you receive are form-encoded bodies containing a
`p_signature` field and an RSA signature — a different scheme entirely, which
this bridge does not verify. Classic deliveries will be rejected, not
mis-issued. Check which you are on before configuring anything, and check it
on a **delivery** rather than on a screen, because that is the thing this
bridge actually reads: a Billing notification arrives as a JSON body with a
`Paddle-Signature` header, a Classic alert as form-encoded fields including
`p_signature`. If you have never seen one, the synthetic delivery in step 4
is what a Billing one looks like.

Only `transaction.completed` is acted on. `transaction.paid` fires earlier,
before Paddle has finished processing, and is ignored. A transaction with a
non-null `subscription_id` is acknowledged **without** a receipt: a
subscription renewal is not the one-time perpetual purchase this bridge
models. If you sell perpetual access through a Paddle subscription, this rail
will not issue for it — say so before you rely on it.

## 1. Keypair and key manifest

Identical to [setup-stripe.md](setup-stripe.md) steps 1 and 2. Do those first.

## 2. Create the notification destination and the API key

You need two values out of Paddle. This page says what each one is and what
it has to be able to do — **not** where the dashboard currently keeps it.
Paddle's navigation is Paddle's to document and it changes; a menu path
printed here would be wrong on some future Tuesday, and wrong in the way that
is hardest to notice, because it would still look authoritative.

**1. A notification destination, and its secret.** Create a destination that
delivers your notifications over HTTP to
`https://<your-bridge-host>/paddle/webhook`, subscribed to
`transaction.completed`. The bridge ignores every other event type, so a wider
subscription costs you nothing but deliveries that end in a `200` and no
receipt.

That destination has a **secret**, of the form `pdl_ntfset_...`. It is what
every signature is checked against. Put it in your deploy environment as
`PADDLE_WEBHOOK_SECRET`.

**2. An API key with `customer.read`.** Of the form `pdl_live_apikey_...`, or
`pdl_sdbx_apikey_...` on sandbox. Put it in your deploy environment as
`PADDLE_API_KEY`.

Grant it `customer.read` and nothing else.

This is the only secret in the bridge that is used to *make* a request rather
than to check one, so it is worth being narrow: `customer.read` is the whole
permission the bridge needs, and a key with more is a key that can do more if
your bridge host is ever compromised.

> **Sandbox keys and live keys are not interchangeable**, and the failure is
> not obvious: the live API refuses a sandbox key with a 4xx, and the bridge
> treats `400`, `401`, `403` and `404` alike — permanent, dead-lettered, never
> retried. If you are testing
> against Paddle's sandbox, set `environment = "sandbox"` in the table below
> so the bridge talks to `sandbox-api.paddle.com` instead of
> `api.paddle.com`.

## 3. Configure the bridge

In your `bridge.toml` (see [setup-stripe.md](setup-stripe.md) step 3 for the
rest of the file):

```toml
[paddle]
webhook_secret_env = "PADDLE_WEBHOOK_SECRET"
api_key_env = "PADDLE_API_KEY"
# environment = "sandbox"      # omit for live
```

- Drop `[stripe]`, `[shopify]`, `[itch]` and `[paypal]` from `bridge.toml`
  if you don't sell through them — a table left behind makes the bridge
  refuse to start over its unset environment variable.

Then one `[products.paddle_<price_id>]` table per item you sell. The product
key is `paddle_` followed by the **price id**, which is Paddle's unit of sale
— not the product id. If you are unsure which identifier you are holding,
read it off a delivery instead of off a screen: it is the value the bridge
takes from `data.items[].price.id` of the `transaction.completed` body, and it
looks like `pri_01h8xce4qz2m3n4p5q6r7s8t9v`. The synthetic delivery in step 4
below shows exactly where it sits.

```toml
[products.paddle_pri_01h8xce4qz2m3n4p5q6r7s8t9v]
title = "The Long Dusk"
publisher = "Example Games Store"
artifact_series = "store.example.com/works/the-long-dusk"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[products.paddle_pri_01h8xce4qz2m3n4p5q6r7s8t9v.identifiers]
paddle_price_id = "pri_01h8xce4qz2m3n4p5q6r7s8t9v"
```

`legal_text_sha256` must be exactly 64 lowercase hex characters — replace the
placeholder with the real hash of your licence terms text:

```sh
shasum -a 256 license.txt | cut -d' ' -f1      # macOS/BSD
sha256sum license.txt | cut -d' ' -f1          # Linux
```

You already have `license.txt` open to hash it — point `legal_text_path` at
that same file, wherever your deploy target mounts it:

```toml
legal_text_path = "/etc/attest-bridge/licences/the-long-dusk.txt"
```

The bridge reads this file and re-hashes it **at startup**: it does not start
(naming this product key) if the file is missing, unreadable, or its hash
doesn't match `legal_text_sha256` above — the config field alone was never
enough, because the signed hash and the actual terms text could silently
drift apart.

A purchase whose price has no matching table is refused (`UnmappedProduct`)
and dead-lettered — never issued with guessed terms.

Validate before serving:

```sh
attest-bridge check-config --config bridge.toml
```

The summary line `paddle: configured` confirms the section was read.

## 4. Test locally, before touching your live account

A Paddle webhook is a signed body, so this rail can be exercised on your own
machine. Start the bridge:

```sh
attest-bridge serve --config bridge.toml --port 8080
```

Paddle signs the timestamp and the body together, not the body alone: each
`h1` candidate is an HMAC-SHA256 of `<timestamp>:<raw body>` under the
destination secret. Reproduce it:

```sh
SECRET="$PADDLE_WEBHOOK_SECRET"
TS=$(date +%s)
BODY='{"event_id":"evt_01h123456789abcdefghijklm","event_type":"transaction.completed",
"data":{"id":"txn_01h123456789abcdefghijklm","status":"completed",
"customer_id":"ctm_01j4k7m2p9r5t8v3w6y1z0a2b4","subscription_id":null,
"items":[{"price":{"id":"pri_01h8xce4qz2m3n4p5q6r7s8t9v"}}],
"billed_at":"2026-09-05T10:00:00Z",
"details":{"totals":{"grand_total":"1999","currency_code":"EUR"}}}}'
BODY=$(printf '%s' "$BODY" | tr -d '\n')
SIG=$(printf '%s' "$TS:$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= *//')

curl -sS -X POST http://127.0.0.1:8080/paddle/webhook \
  -H "Content-Type: application/json" \
  -H "Paddle-Signature: ts=$TS;h1=$SIG" \
  --data "$BODY"
```

Change one byte of `BODY` without re-signing and you must get
`400 invalid signature` — that failure is the test that the trust boundary
works, so it is worth doing once. Signing an old `TS` is worth doing too: the
bridge accepts a five-minute window either side and rejects anything further
out.

One thing this synthetic delivery does **not** fake: the customer lookup. The
bridge will call Paddle's real API with your real key to turn that
`customer_id` into an email. Either use a sandbox key with
`environment = "sandbox"` and a `ctm_` id that exists in your sandbox, or
expect a `200` and a dead letter whose reason names `paddle.api_key_env`.
That dead letter is not a failure of the test — it proves the signature was
accepted, the event deduplicated, and the trust boundary held right up to the
one call this rail cannot avoid. Replay it with
`attest-bridge retry-failed --config bridge.toml` once the key is right.

Then verify the receipt offline. The download link (`/r/<token>`) is a page
offering the two files the receipt is made of; append `?part=receipt` or
`?part=private` to fetch either half straight from a script:

```sh
umask 077
curl "http://127.0.0.1:8080/r/<token>?part=receipt" -o receipt.attest
curl "http://127.0.0.1:8080/r/<token>?part=private" -o receipt.private.attest
chmod 600 receipt.private.attest   # this half carries delivery.salt, a buyer-binding secret
attest import --bundle receipt.attest --private receipt.private.attest --out-dir ./imported
attest verify ./imported/receipts/<receipt_id>.attest.json --trust-dir ./imported/trust
```

Re-running `attest import` on the same bundle pair is idempotent; importing
a *different* bundle into the same `--out-dir` refuses if it would change
your pinned trust store or `salts.json` (pass `--force` to replace them).

`"ok": true` closes the loop.

> **If instead you configured `[delivery]`**, the same pair arrives by
> email as two attachments, whether you download it or receive it:
> `<issuer-slug>-<receipt_id>.attest`
> (shareable — the receipt with its salt removed, plus your key manifest and
> the licence text, so anyone can verify it even after your store is gone)
> and `<issuer-slug>-<receipt_id>.private.attest` (the buyer's own secret —
> it carries `delivery.salt`, the buyer-binding value, and the web verifier
> refuses a file with that name on sight). A buyer verifies by dragging the
> shareable half into the web verifier your `info_url` points at; from this
> CLI, reconstruct it first:
>
> ```sh
> attest import --bundle <issuer-slug>-<receipt_id>.attest \
>   --private <issuer-slug>-<receipt_id>.private.attest --out-dir ./imported
> attest verify ./imported/receipts/<receipt_id>.attest.json --trust-dir ./imported/trust
> ```
>
> Re-running `attest import` on the same bundle pair is idempotent;
> importing a *different* bundle into the same `--out-dir` refuses if it
> would change your pinned trust store or `salts.json` (pass `--force` to
> replace them).

## What the bridge does and does not trust

Worth knowing, because it shapes what can go wrong:

- The HMAC covers **the timestamp and the request body together**
  (`<ts>:<body>`), so neither can be changed without invalidating the
  signature. `Paddle-Signature` is the only header that gates an *issuing*
  decision — no other header can change what gets attested, or for whom. The
  one other header the bridge reads at all is `Content-Length`, and only to
  bound the request before touching it (the 1 MiB row below) and to decide how
  many bytes of body to read.
- **The timestamp window is 300 seconds**, not the five seconds Paddle's own
  SDKs default to. Five seconds turns ordinary delivery latency into a
  rejection, and a rejection into a retry; replay protection is the Ledger's
  job, not the clock's. The consequence is deliberate: a genuine delivery
  that took four minutes to arrive is still issued.
- **Replay is the Ledger's job.** The same genuine body and signature verify
  every time; the bridge deduplicates the signed `event_id` and, separately,
  the transaction `data.id`. A redelivery is acknowledged without issuing
  twice, and two different events for the same transaction still produce one
  receipt.
- **The buyer's email comes from Paddle's API, not from the event.** It is
  fetched once per issuance with your `customer.read` key. Every structural
  check on the event runs *before* that call, so a malformed signed body
  costs you no Paddle request.
- `custom_data` **cannot name the product** — the price id decides, always.
  A merchant's checkout can put anything in `custom_data`, and honouring an
  `attest_product_key` there would let whoever controls the checkout choose
  which of your products gets attested. The one key the bridge does read is
  `attest_buyer_pubkey` (see below).
- **One item per transaction.** A transaction with more than one item is
  dead-lettered rather than issued: one receipt per purchase is a protocol
  invariant, not a bridge limitation.
- **Refunds do not revoke anything yet.** `adjustment.*` events are not
  handled: a refunded purchase keeps its receipt until refund-driven
  revocation ships.
- **A delivery larger than 1 MiB is refused with `413`**, before the
  signature is even checked. A `transaction.completed` event is nowhere near
  that; a body that is means something is wrong upstream, and the bridge
  declines to hash it.
- A transient failure answers `500` so Paddle redelivers — up to 60 times over
  three days on live, but only **3 times within 15 minutes on sandbox**, so a
  sandbox test has far less room to recover than production does. Paddle also
  wants its `200` within **five seconds**, and this is the one rail that spends
  a synchronous Paddle API call before it can answer; a slower delivery is
  retried, and the deduplication above is what keeps that retry from issuing a
  second receipt. A permanently-bad event answers `200` and lands in the
  dead-letter queue, replayable with `attest-bridge retry-failed` once you have
  fixed the cause.

## Buyer-held keys (optional)

If a buyer wants a transferable receipt bound to their own key rather than
their email, carry the base64url public key in the transaction's
`custom_data` under `attest_buyer_pubkey` — a JSON object your checkout sets
when it creates the transaction. A malformed key fails before signing, never
after.

This is the one thing `custom_data` may carry, and the asymmetry is
deliberate: a key there binds the receipt to whoever set it, which is the
buyer's own choice to make about their own purchase. Naming the *product* is
not, which is why that override does not exist.
