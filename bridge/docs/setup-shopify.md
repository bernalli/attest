# Shopify setup: zero to a verified receipt

Read [setup-stripe.md](setup-stripe.md) first if you haven't — steps 1–2
(keypair + key manifest) and the deploy step are identical regardless of
platform; this page covers what is Shopify-specific.

## What this rail is, in one paragraph

Shopify sends your bridge a signed `orders/paid` webhook the moment an order is
paid. The order already contains its line items, so the bridge issues from the
delivery itself: there is no follow-up API call, no Shopify access token to
configure, and none of the failure modes that come with one. Compared with the
Stripe rail this is strictly less machinery — the only secret is the webhook
signing secret.

Selling digital files on Shopify normally means a delivery app (Shopify's own
Digital Downloads, or a third party) attaches the file to the order. attest sits
beside that, not in place of it: the app delivers the file, the bridge issues the
receipt. Nothing about your checkout, catalogue, pricing or delivery changes.

## 1. Keypair and key manifest

Identical to [setup-stripe.md](setup-stripe.md) steps 1 and 2. Do those first.

## 2. Create the webhook and copy its secret

Shopify admin → **Settings → Notifications → Webhooks** → *Create webhook*:

- **Event**: `Order payment` (topic `orders/paid`). Do not subscribe to
  `Order creation`: it fires before payment settles, and the bridge ignores it.
- **Format**: JSON
- **URL**: `https://<your-bridge-host>/shopify/webhook`
- **API version**: the current stable one

After saving, Shopify shows the **signing secret** for your webhooks once.
That value — not your admin password, not an API token — is what the bridge
verifies against. Put it in your deploy environment as `SHOPIFY_WEBHOOK_SECRET`.

> If your store's webhooks were created by a custom app rather than in the admin,
> the signing secret is that app's **client secret** instead. Either way it is a
> single value, and the bridge only ever reads it from an environment variable.

## 3. Configure the bridge

In your `bridge.toml` (see [setup-stripe.md](setup-stripe.md) step 3 for the
rest of the file):

```toml
[shopify]
webhook_secret_env = "SHOPIFY_WEBHOOK_SECRET"
```

Then one `[products.shopify_<variant_id>]` table per item you sell. The product
key is `shopify_` followed by the **variant id** — the variant is Shopify's unit
of sale, the equivalent of a Stripe price id. Find it in the admin: open the
product, select the variant, and read the last number in the URL
(`.../products/1234567890/variants/49148385` → `49148385`).

```toml
[products.shopify_49148385]
title = "The Long Dusk"
publisher = "Example Games Store"
artifact_series = "store.example.com/works/the-long-dusk"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[products.shopify_49148385.identifiers]
shopify_variant_id = "49148385"
```

`legal_text_sha256` must be exactly 64 lowercase hex characters — replace the
placeholder with the real hash of your licence terms text:

```sh
shasum -a 256 license.txt | cut -d' ' -f1      # macOS/BSD
sha256sum license.txt | cut -d' ' -f1          # Linux
```

A purchase whose variant has no matching table is refused
(`UnmappedProduct`) and dead-lettered — never issued with guessed terms.

Validate before serving:

```sh
attest-bridge check-config --config bridge.toml
```

The summary line `shopify: configured` confirms the section was read.

## 4. Test it locally, before touching your live store

Unlike the itch rail, this one can be exercised end to end on your own machine,
because a Shopify webhook is just a signed body. Start the bridge:

```sh
attest-bridge serve --config bridge.toml --port 8080
```

Then send a synthetic delivery, signed with the same secret the bridge has:

```sh
SECRET="$SHOPIFY_WEBHOOK_SECRET"
BODY='{"id":820982911946154508,"email":"buyer@example.com","financial_status":"paid",
"created_at":"2026-08-24T11:15:00-05:00","currency":"EUR","total_price":"12.00",
"line_items":[{"variant_id":49148385,"title":"The Long Dusk","quantity":1}]}'
BODY=$(printf '%s' "$BODY" | tr -d '\n')
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)

curl -sS -X POST http://127.0.0.1:8080/shopify/webhook \
  -H "Content-Type: application/json" \
  -H "X-Shopify-Topic: orders/paid" \
  -H "X-Shopify-Webhook-Id: local-test-1" \
  -H "X-Shopify-Hmac-Sha256: $SIG" \
  --data "$BODY"
```

Expected: `{"ok": true}`. Change one byte of `BODY` without re-signing and you
must get `400 invalid signature` — that failure is the test that the trust
boundary works, so it is worth doing once.

Then verify the receipt offline:

```sh
umask 077
# Save the receipt from your delivery mailbox, or fetch it from the download link.
chmod 600 receipt.attest   # the envelope carries delivery.salt, a buyer-binding secret
attest verify receipt.attest --trust-dir <dir-containing-key-manifest.json>
```

`"ok": true` closes the loop.

You can also use Shopify's **Send test notification** button on the webhook you
created. It posts a sample order that will not match your catalogue, so expect a
`200` and a dead letter rather than a receipt — that is the correct outcome and
proves the signature path works against Shopify's own sender.

## What the bridge does and does not trust

Worth knowing, because it shapes what can go wrong:

- The HMAC covers the **request body only**. `X-Shopify-Topic`,
  `X-Shopify-Shop-Domain` and `X-Shopify-Webhook-Id` are not signed, so **no
  decision reads them at all** — not even to filter. An unsigned value that can
  suppress issuance loses a receipt just as surely as one that can cause a false
  issuance: relabel a genuine paid delivery to another topic and, if the topic
  gated anything, its receipt would be quietly dropped. Every gate reads the
  signed body: `financial_status == "paid"`, `cancelled_at` absent, and the line
  items that name the product.
- **The dedup key is the order id from the signed body**, not the delivery id.
  A redelivery is acknowledged without issuing twice, and a tampered delivery id
  changes nothing.
- An order **cancelled after payment** keeps `financial_status: "paid"` until it
  is refunded. Those are acknowledged without issuing — a cancelled order is not
  a purchase to attest to.
- An order with more than one line item is dead-lettered rather than issued: one
  receipt per purchase is a protocol invariant, not a bridge limitation.
  There is deliberately **no `note_attributes` override for the product key**,
  unlike the Stripe rail's `metadata.attest_product_key`. Stripe's metadata is
  written by your own server when it creates the Checkout Session; Shopify's
  `note_attributes` comes from cart attributes a theme, an installed app or the
  buyer's browser can set, so honouring one would let whoever controls the cart
  choose which of your products gets attested. The variant that was sold
  decides. If you need a different mapping, write it in your catalogue — that is
  a file only you can edit.
- A transient failure answers `500` so Shopify redelivers. A permanently-bad
  order answers `200` and lands in the dead-letter queue, replayable with
  `attest-bridge retry-failed` once you have fixed the cause.

## Buyer-held keys (optional)

If a buyer wants a transferable receipt bound to their own key rather than their
email, carry the base64url public key in the order's `note_attributes` under
`attest_buyer_pubkey` — a list of `{"name": ..., "value": ...}` pairs your
checkout or an app can set. A malformed key fails before signing, never after.

This is the one thing `note_attributes` may carry, and the asymmetry is
deliberate: a key there binds the receipt to whoever set it, which is the
buyer's own choice to make about their own purchase. Naming the *product* is
not, which is why that override does not exist.
