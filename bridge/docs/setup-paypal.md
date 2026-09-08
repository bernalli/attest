# PayPal setup: zero to a verified receipt

Read [setup-stripe.md](setup-stripe.md) first if you haven't — steps 1–2
(keypair + key manifest) and the deploy step are identical regardless of
platform; this page covers what is PayPal-specific.

## What this rail is, in one paragraph

This rail listens for PayPal **REST** webhooks — specifically
`PAYMENT.CAPTURE.COMPLETED`, the Payments v2 event that says a capture on an
Orders v2 order has settled. The bridge asks PayPal to authenticate each
delivery, then fetches the order to read the buyer's email and the item's
`sku`: the capture event carries neither.

It is **not** for the legacy stack. Old-style **Buy Now / Add to Cart
buttons**, **IPN** and the deprecated `PAYMENT.SALE.*` events belong to
Payments v1 and are not handled. The quickest way to tell which you are on:
the REST integration is the one where you created an **app** in the
[Developer Dashboard](https://developer.paypal.com/dashboard/) and where the
Dashboard lets you create a **webhook**. If your checkout is an HTML button
you pasted into a page years ago and your notifications arrive as IPN posts,
this rail will not see your sales.

## 1. Keypair and key manifest

Identical to [setup-stripe.md](setup-stripe.md) steps 1 and 2. Do those first.

## 2. Create the app and the webhook

Both live in the [Developer Dashboard](https://developer.paypal.com/dashboard/).
Its menu wording moves between revisions, so what follows names each step by
what it does rather than by the label it currently carries.

**The app** — create an app on your account. Copy the two values it shows you
into your deploy environment:

- **Client ID** → `PAYPAL_CLIENT_ID`
- **Secret** → `PAYPAL_CLIENT_SECRET`

Sandbox and live credentials are separate, and they are not interchangeable:
the pair you copy has to match the `environment` you set in the table below,
which is what decides whether the bridge talks to `api-m.sandbox.paypal.com`
or `api-m.paypal.com`. Copying a sandbox pair while leaving `environment`
unset points sandbox credentials at the live API.

**The webhook** — create one on that same app:

- **URL**: `https://<your-bridge-host>/paypal/webhook`
- **Event types**: subscribe to `PAYMENT.CAPTURE.COMPLETED` and nothing else.
  That constant is what the bridge matches on; the dashboard shows it under a
  human-readable name next to it.

After saving, PayPal shows the webhook's **own ID** — a value like
`8PT597110X687430LKGECATA`. Copy it: unlike the two credentials above it is
not a secret and goes straight into `bridge.toml` as `webhook_id`. It is how
PayPal knows *which* subscription a delivery claims to belong to, so a
delivery signed for somebody else's webhook does not authenticate against
yours.

## 3. Configure the bridge

In your `bridge.toml` (see [setup-stripe.md](setup-stripe.md) step 3 for the
rest of the file):

```toml
[paypal]
client_id_env = "PAYPAL_CLIENT_ID"
client_secret_env = "PAYPAL_CLIENT_SECRET"
webhook_id = "8PT597110X687430LKGECATA"
# environment = "sandbox"      # omit for live
```

- Drop `[stripe]`, `[shopify]`, `[itch]` and `[paddle]` from `bridge.toml`
  if you don't sell through them — a table left behind makes the bridge
  refuse to start over its unset environment variable.

Then one `[products.paypal_<sku>]` table per item you sell. The product key is
`paypal_` followed by the **`sku` your server puts on the order's line item** —
PayPal has no catalogue of its own here, so this is a value you choose and
your checkout sends.

```toml
[products.paypal_SDC-STD-001]
title = "Stardrift Chronicles"
publisher = "Example Games Store"
artifact_series = "store.example.com/works/stardrift-chronicles"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[products.paypal_SDC-STD-001.identifiers]
sku = "SDC-STD-001"
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
legal_text_path = "/etc/attest-bridge/licences/stardrift-chronicles.txt"
```

The bridge reads this file and re-hashes it **at startup**: it does not start
(naming this product key) if the file is missing, unreadable, or its hash
doesn't match `legal_text_sha256` above — the config field alone was never
enough, because the signed hash and the actual terms text could silently
drift apart.

A purchase whose `sku` has no matching table is refused (`UnmappedProduct`)
and dead-lettered — never issued with guessed terms.

Validate before serving:

```sh
attest-bridge check-config --config bridge.toml
```

The summary line `paypal: configured` confirms the section was read.

## 4. Create your orders server-side — read this before you sell

This is the one step on this rail that decides whether the receipts are worth
anything, and it is about **your** code, not the bridge's.

The bridge reads the buyer's email and the item's `sku` from the order PayPal
returns. An order is whatever the code that created it said it was. With the
JavaScript SDK's client-side `createOrder`, that code is **the buyer's
browser**: anyone who can open your checkout can choose the `sku`, and the
bridge would faithfully issue a signed receipt for the product they named
rather than the one they paid for.

So create orders from your server:

```
POST /v2/checkout/orders
{
  "intent": "CAPTURE",
  "purchase_units": [{
    "amount": { "currency_code": "EUR", "value": "19.99",
                "breakdown": { "item_total": { "currency_code": "EUR", "value": "19.99" } } },
    "items": [{ "name": "Stardrift Chronicles", "sku": "SDC-STD-001",
                "quantity": "1",
                "unit_amount": { "currency_code": "EUR", "value": "19.99" } }]
  }]
}
```

and let the browser only approve the order id your server returns. This is
exactly how a Stripe Checkout Session is created server-side, and for exactly
the same reason. A receipt is only ever as trustworthy as the step that said
what was bought.

**One purchase unit, one item, a non-empty `sku`.** More than one of either is
dead-lettered rather than issued: one receipt per purchase is a protocol
invariant.

## 5. Test locally, then in the sandbox

Unlike every other rail, a PayPal delivery **cannot be signed locally**: the
signature is PayPal's own, and it is PayPal that checks it. There is no secret
on your side to sign with. So the local test is narrower and the real one runs
in the sandbox.

What you can prove on your own machine is that the endpoint is up and fails
closed. Start the bridge:

```sh
attest-bridge serve --config bridge.toml --port 8080
```

then post without the five transmission headers PayPal sends:

```sh
curl -sS -i -X POST http://127.0.0.1:8080/paypal/webhook \
  -H "Content-Type: application/json" \
  --data '{"event_type":"PAYMENT.CAPTURE.COMPLETED"}'
```

Expected: `400` and `missing signature`. The bridge refuses before it calls
PayPal at all. Note carefully what that does *not* mean: once the five headers
are present and well-formed, the body **is** sent to PayPal verbatim, because on
this rail the postback *is* the authentication — the outbound call necessarily
precedes it, and no local check can come first. Anyone who can reach this
endpoint with five plausible headers and a non-empty body can make your bridge
spend one PayPal round-trip. That is the surface the rate limit below exists to
bound, and the reason this endpoint has one when the HMAC rails do not.

Then the sandbox, which is the real test: either use **Send test** on the
webhook you created in the Dashboard, or make a sandbox purchase through your
own checkout. A genuine sandbox delivery for a `sku` in your catalogue gives
`{"ok": true}`; PayPal's synthetic "Send test" payload will not match your
catalogue, so expect a `200` and a dead letter naming the cause — that is the
correct outcome and proves the authentication path works against PayPal's own
sender. Replay it with `attest-bridge retry-failed --config bridge.toml` once
the catalogue matches.

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

- **Deliveries are authenticated by asking PayPal.** The bridge posts the
  five `PAYPAL-*` transmission headers and the **original body bytes,
  verbatim**, to PayPal's `verify-webhook-signature` endpoint and accepts the
  delivery only when the answer is exactly `SUCCESS`. The alternative —
  verifying the RSA signature locally — would mean adding an RSA/X.509
  dependency the bridge does not otherwise need, fetching a certificate per
  delivery and validating its chain. This design adds no cryptographic
  surface; what it costs is one API round-trip per delivery to authenticate it
  — two when the cached OAuth token has expired — plus a second call to fetch
  the order for a delivery that is actually issued for, and a `500` (which
  PayPal retries) whenever PayPal's own API is unreachable.
- The body is **never re-serialised** before being sent for verification.
  PayPal's signature covers the exact bytes it sent; re-encoding an authentic
  delivery is enough to make it fail.
- If any of the five headers is missing or empty the answer is
  `400 missing signature`. A header that is present but whitespace-only, too
  long, non-ASCII, or that carries an `auth_algo` other than `SHA256withRSA`
  or a `cert_url` outside `*.paypal.com`, is `400 invalid signature` instead.
  Both are decided locally, before any call to PayPal.
- **Replay is the Ledger's job.** A genuine delivery verifies again when
  PayPal retries it; the bridge deduplicates the signed envelope `id` and,
  separately, the related order id. Two capture events for the same order
  still produce one receipt.
- **The order id is the purchase id**, because one order is one purchase. A
  **partial capture** (`final_capture: false`) is therefore acknowledged
  without issuing: there is no such thing as issuing half a receipt.
- **The order is fetched, and its id is cross-checked** against the
  authenticated capture. An order that comes back naming a different id is
  rejected rather than used.
- `custom_id` is **ignored**. It is a free-text field on the purchase unit,
  and honouring a product name there would let whoever created the order
  choose which of your products gets attested. The `sku` on the line item
  decides.
- **Receipts on this rail are email-bound.** There is no buyer-public-key
  carrier yet, so a PayPal receipt is bound to the payer's email address, not
  to a key the buyer holds. Adding a carrier later is additive and will not
  invalidate anything issued now.
- **Refunds and reversals do not revoke anything yet.**
  `PAYMENT.CAPTURE.REFUNDED` and `PAYMENT.CAPTURE.REVERSED` are not handled:
  a refunded purchase keeps its receipt until refund-driven revocation ships.
- **A delivery larger than 1 MiB is refused with `413`** — the same cap the
  Paddle rail applies — and, uniquely to this rail, no more than **60 formally
  complete deliveries per minute** are admitted; the rest get `429`. Both sit
  *before* authentication, and only this rail needs the second one: every
  delivery this endpoint accepts costs an outbound call to PayPal, so an
  unauthenticated flood would spend your API budget rather than the sender's,
  while the HMAC rails can refuse a forgery locally and for free. Sixty a
  minute leaves PayPal's own retry bursts room. Both numbers are compiled-in
  defaults today, not `bridge.toml` fields: if your store genuinely sells
  faster than sixty a minute, say so — raising it is a change to the bridge,
  not to your config.
- A transient failure answers `500` so PayPal redelivers — up to 25 times
  over three days, and note that PayPal retries a `400` too, unlike Stripe. A
  permanently-bad event answers `200` and lands in the dead-letter queue,
  replayable with `attest-bridge retry-failed` once you have fixed the cause.
