# Stripe setup: zero to a verified receipt

This is the whole path from nothing to a real, offline-verifiable attest
receipt issued automatically at the moment of sale, for a merchant selling
through Stripe Checkout or Payment Links. Every command below is
copy-pasteable and runs exactly as written — nothing here requires reading
this repo's source.

You will need: a terminal with Python 3.12+, a Stripe account (test mode is
enough to complete every step here), and somewhere to run the bridge itself
once it's configured (see [deploy.md](deploy.md) for that half — the deploy
image already has `attest`/`attest-bridge` installed for running `serve`;
you still need both CLIs on your own machine too, for steps 1, 2, 3, 4, and 9
below).

`attest-bridge` is **not published on PyPI** (`Private :: Do Not Upload` —
it is unreleased); never run `pip install attest-bridge` — that name may
resolve to an unrelated package. Install it from a source checkout instead:

```sh
git clone https://github.com/bernalli/attest.git
cd attest
pip install ./bridge
```

`pip install ./bridge` pulls in `attest-receipts` (the published PyPI
package that provides the `attest` CLI used in steps 1–2, 4, and 9) as its
declared dependency, so this one command gives you both `attest` and
`attest-bridge` locally.

## 1. Generate your issuer keypair

```sh
attest keygen --hybrid --seed-out issuer.seed --pub-out issuer.pub --mldsa-out issuer.mldsa.json
```

This writes three files: `issuer.seed` and `issuer.mldsa.json` are secrets
(written 0600 — back them up somewhere encrypted, never commit them, never
send them anywhere); `issuer.pub` is public. `--hybrid` is required for the
bridge specifically — it signs every receipt with both an Ed25519 and an
ML-DSA-65 (post-quantum) signature, and the bridge refuses to start without
the ML-DSA leg (see step 2).

The bridge's own handling of these files, once deployed, is the same
guarantee: your signing key is read into memory only to sign a receipt, and
is never exported, logged, or written back out by the bridge — the on-disk
copies you mounted (or backed up) are the only copies that exist.

One deployment-plumbing exception: on platforms that can't mount a file
before first boot (Render), you supply the key as a base64 environment
variable and the container entrypoint decodes it to a `0600` file at startup,
then unsets the variable before starting the server — so the running bridge
still holds the key only on disk, and the base64 value's only persistent source
is your platform's secret store (it is present in the entrypoint's environment
only transiently, until that unset; see the Render section of
[deploy.md](deploy.md)).
Prefer a real mounted file (Compose bind mount, Fly `[[files]]`) when you can.

## 2. Create and publish your key manifest

```sh
attest manifest init \
  --issuer store.example.com \
  --kid store.example.com/keys/2026-07#hybrid-1 \
  --seed issuer.seed \
  --mldsa-key issuer.mldsa.json \
  --valid-from 2026-07-24T00:00:00Z \
  --issued-at 2026-07-24T00:00:00Z \
  --out key-manifest.json
```

Replace `store.example.com` with your own domain — `--issuer` is your DNS
domain, and `--kid` must start with that same domain (`attest-bridge`
rejects a mismatch at startup). The `#hybrid-1` suffix is just a label you
choose; the grammar is `<your-domain>/keys/<label>#<name>`. `--valid-from` is
when this key starts being valid (an ISO-8601 UTC timestamp,
`YYYY-MM-DDTHH:MM:SSZ`); there's also an optional `--valid-to` if you want a
hard expiry (omit it for none).

`key-manifest.json` is public — it's how anyone verifying a receipt learns
your public key. Publish it at:

```
https://store.example.com/.well-known/attest.json
```

(any static hosting works — GitHub Pages, S3, Cloudflare Pages, your existing
web server; "publish one key" is the entire distribution mechanism, no
registry or CA involved).

## 3. Configure the bridge

```sh
cp bridge/examples/bridge.toml ./bridge.toml
```

Edit it:

- `[issuer]`: `id` = your domain, `kid` = the exact `--kid` from step 2,
  `seed_path` / `mldsa_key_path` / `manifest_path` = wherever your deploy
  target mounts `issuer.seed` / `issuer.mldsa.json` / `key-manifest.json`
  (see [deploy.md](deploy.md) — the shipped example already uses the
  Docker/Fly/Render convention, `/secrets/...` and `/etc/attest-bridge/...`).
- `[stripe]`: `webhook_secret_env = "STRIPE_WEBHOOK_SECRET"` (step 4 exports
  a throwaway local value to test with; step 6 sets the real one from your
  Stripe webhook). Also set `api_key_env = "STRIPE_API_KEY"` and point it
  at an env var holding your Stripe **secret** key (Dashboard → Developers →
  API keys) — with this set, the bridge resolves which product was bought by
  calling Stripe's API for you, so you never have to touch Checkout Session
  metadata. Without an API key, you must set `metadata.attest_product_key`
  yourself on every Checkout Session/Payment Link (advanced; not covered
  here).
- `[products.<price_id>]`: one table per SKU you sell, keyed by the Stripe
  **Price ID** (Dashboard → Product catalog → your product → the price →
  looks like `price_1Pxy...`). A purchase for a price with no matching table
  is refused, never issued with guessed terms — this is deliberate.
  Alongside `legal_text_sha256`, each product table also needs
  `legal_text_path`: a path to the licence text file that hash was taken
  from. Read and re-hashed **at startup**, a mismatch (or a missing,
  unreadable file) means the bridge does not start, naming the offending
  product key — the hash alone was never enough, since the signed digest and
  the terms text on disk could otherwise drift apart unnoticed.
- A Checkout Session must contain exactly one purchasable line item. If the
  bridge has an API key, it fetches line items and rejects more than one even
  when `attest_product_key` metadata supplies the product mapping. Without an
  API key, the count is unknowable: setting `attest_product_key` asserts that
  the Checkout Session has exactly one purchasable line item.
- Drop the `[itch]` table if you don't also sell on itch.io (see
  [setup-itch.md](setup-itch.md)), and the `[delivery]` table if you're happy
  with download-link-only (no receipt emails — see step 8).

`seed_path`, `mldsa_key_path`, and `manifest_path` above point at wherever
your deploy target mounts these files — `/secrets/...` and
`/etc/attest-bridge/...`, the convention every target in
[deploy.md](deploy.md) shares — which don't exist on this machine yet. Step 4
validates a local copy of this same config against the actual files sitting
in your current directory, before you deploy anything at all.

## 4. Test locally before you deploy

Steps 1–3 all happened on your own machine; step 5 deploys the *bridge
itself* somewhere else — a container, a VM, a platform. Before that,
exercise the whole pipeline locally: same commands, same code, just pointed
at the files already sitting in your current directory instead of wherever
your deploy target eventually mounts them.

Copy the config, and point the copy's key/manifest/ledger paths at your
local files instead of the deploy paths above:

```sh
cp bridge.toml bridge.local.toml
```

Edit `bridge.local.toml`:

- `seed_path` → `./issuer.seed`
- `mldsa_key_path` → `./issuer.mldsa.json`
- `manifest_path` → `./key-manifest.json`
- `ledger_path` → `./ledger.sqlite3` (a fresh local Ledger — the bridge
  creates this file itself, 0600, the first time it starts)
- **comment out `api_key_env` under `[stripe]`** for this local run. With an
  API key configured, the bridge always calls Stripe's real API to enforce the
  single-line-item invariant (step 3) — even when `attest_product_key`
  metadata already supplies the product — and the synthetic event below is not
  a real Checkout Session, so a throwaway key gets a `401` and the webhook is
  dead-lettered instead of issuing. The synthetic event carries the metadata
  key, which is all this local run needs. Put `api_key_env` back before
  step 5; from step 6 on, real sessions and a real key make the fetch work.

`bridge.toml` itself stays untouched, ready for step 5.

Set the Stripe env vars this config references. `check-config` only verifies
a variable is *set*, not that it holds a real Stripe credential, so a
throwaway value passes it — but `STRIPE_WEBHOOK_SECRET`'s exact value is what
the synthetic webhook test below signs with, so it has to match what you
export here:

```sh
export STRIPE_WEBHOOK_SECRET=whsec_testsecret123
export STRIPE_API_KEY=sk_test_dummy   # only for check-config; unused once api_key_env is commented out
```

Keep `STRIPE_API_KEY` exported if you want `check-config` to report
`stripe: configured` against the untouched `bridge.toml` from step 3; with
`api_key_env` commented out of `bridge.local.toml`, the local run below never
reads it.

Now validate config, keys, and product catalog in one shot — this catches a
typo'd path or a malformed product table before it becomes a 500 on your
first real webhook:

```sh
attest-bridge check-config --config bridge.local.toml
```

A clean config prints a short summary and exits `0`:

```
issuer: store.example.com (kid=store.example.com/keys/2026-07#hybrid-1)
public_base_url: https://receipts.example.com
products: price_1PxYzEXAMPLE
stripe: configured
delivery: download-link-only
```

Anything wrong is reported as a `config error:` naming the exact field,
instead. This step never touches the network or creates the Ledger — it's
pure local validation, safe to run as many times as you like while editing.

Now exercise the full issue-and-verify path with a synthetic Stripe event —
you don't need a real Stripe account for this part, just the Python standard
library. Start the bridge against your local config:

```sh
attest-bridge serve --config bridge.local.toml --host 127.0.0.1 --port 8080
```

Then, in another terminal, save this as `send_test_webhook.py` and run it —
it builds the `Stripe-Signature` header exactly the way Stripe's own webhook
sender does (`t=<epoch>,v1=<hex hmac>`, keyed by `STRIPE_WEBHOOK_SECRET`,
signed over `f"{t}." + <raw body bytes>`):

```python
import hashlib
import hmac
import json
import time
import urllib.request

BRIDGE_URL = "http://127.0.0.1:8080"
WEBHOOK_SECRET = "whsec_testsecret123"  # must match STRIPE_WEBHOOK_SECRET


def sign_stripe(payload: bytes, secret: str, ts: int) -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


event = {
    "id": "evt_test_1",
    "type": "checkout.session.completed",
    "created": int(time.time()),
    "data": {
        "object": {
            "id": "cs_test_1",
            "payment_status": "paid",
            "customer_details": {"email": "buyer@example.com"},
            "metadata": {"attest_product_key": "price_1PxYzEXAMPLE"},
            "amount_total": 1999,
            "currency": "usd",
            "custom_fields": [],
        }
    },
}

body = json.dumps(event).encode()
ts = int(time.time())
header = sign_stripe(body, WEBHOOK_SECRET, ts)

req = urllib.request.Request(
    f"{BRIDGE_URL}/stripe/webhook",
    data=body,
    headers={"Stripe-Signature": header, "Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    print(resp.status, resp.read().decode())
```

```sh
python3 send_test_webhook.py
```

A `200 {"ok": true}` means the bridge accepted and processed it. Download the
receipt it just issued (the synthetic event above used session id
`cs_test_1`) and verify it, entirely offline:

```sh
umask 077
curl "http://127.0.0.1:8080/stripe/receipt?session_id=cs_test_1" -o receipt.attest
chmod 600 receipt.attest   # the envelope carries delivery.salt, a buyer-binding secret
attest verify receipt.attest --trust-dir .
```

`"ok": true` closes the loop entirely offline: a signed receipt, issued by
your own bridge, verified against the manifest you published in step 2 —
nothing above required reading this repo's source, only the commands
themselves.

## 5. Deploy

See [deploy.md](deploy.md) for the three deploy targets (Docker Compose,
Fly.io, Render — plus a caution on why Cloud Run isn't a safe fourth) and
the four secret env vars (`STRIPE_WEBHOOK_SECRET`, `STRIPE_API_KEY`,
`ITCH_API_KEY`, `SMTP_PASSWORD` — set only the ones your `bridge.toml`
references).

## 6. Wire up the Stripe webhook

Stripe Dashboard → Developers → Webhooks → **Add endpoint**:

- Endpoint URL: `https://<your-bridge-host>/stripe/webhook`
- Events to send: `checkout.session.completed` and
  `checkout.session.async_payment_succeeded`
- After creating it, reveal the **Signing secret** (`whsec_...`) and set it
  as your deploy's `STRIPE_WEBHOOK_SECRET`.

## 7. (Optional) Transfer-ready receipts

By default a receipt is bound to the buyer's email only — perfectly valid
forever, just not transferable. To let a buyer bind their receipt to a
public key instead (making it eligible for a future issuer-mediated
transfer), give Stripe a way to carry it: add a Checkout/Payment-Link custom
field with key `attest_pubkey`, type `text`, marked optional — or set
`metadata.attest_buyer_pubkey` yourself if you create Checkout Sessions
programmatically. A buyer who leaves it blank gets an email-bound,
non-transferable receipt: exactly as designed, not an error.

## 8. (Optional) Zero-config buyer download

Point your Checkout Session's `success_url` at:

```
https://<your-bridge-host>/stripe/receipt?session_id={CHECKOUT_SESSION_ID}
```

Stripe substitutes `{CHECKOUT_SESSION_ID}` itself; the buyer lands on a page
that downloads their `.attest` receipt directly, with no email step needed.

## 9. Test it

Make a real test-mode purchase (Stripe test card `4242 4242 4242 4242`), let
the webhook fire, and get the resulting receipt. Two paths give you different
things: step 8's URL (or your own lookup against the Ledger) downloads the
single `receipt-<receipt_id>.attest` envelope — verify it directly:

```sh
attest verify receipt.attest --trust-dir <dir-containing-key-manifest.json>
```

should print `"ok": true`. That's the whole loop: a real Stripe purchase, a
signed receipt, verified offline with nothing but the file you just
downloaded and the manifest you published in step 2.

The email from the `[delivery]` you configured in step 3 instead attaches a
**pair**: `<issuer-slug>-<receipt_id>.attest` (shareable — salt removed, plus
your key manifest and the licence text, so it verifies even after your store
is gone) and `<issuer-slug>-<receipt_id>.private.attest` (the buyer's own
secret, carrying `delivery.salt`; the web verifier refuses a file with that
name on sight). A buyer verifies by dragging the shareable half into the web
verifier your `info_url` points at; from this CLI, reconstruct it first:

```sh
attest import --bundle <issuer-slug>-<receipt_id>.attest \
  --private <issuer-slug>-<receipt_id>.private.attest --out-dir ./imported
attest verify ./imported/receipts/<receipt_id>.attest.json --trust-dir ./imported/trust
```

---

## Three things worth knowing before you go live

> **The salt tradeoff.** Every receipt embeds its own buyer-binding salt —
> that's what makes the file self-contained and verifiable forever, with no
> server to ask. The flip side: anyone holding the file can test candidate
> emails against the buyer commitment offline (it's a commitment, not
> encryption). If you need to keep the salt separate from the receipt file
> itself, the underlying `attest issue` CLI supports `--salt-out` for
> hand-issuance — the bridge always embeds the salt inline, by design, since
> it has no separate channel to hand a buyer their salt out-of-band.

> **The Ledger database is a secret.** `ledger_path` (a sqlite3 file) stores
> every issued envelope verbatim, salt included, and is created 0600. Back it
> up **encrypted**. It is not part of the trust model — nothing `attest
> verify` depends on it — but losing it loses your replay-dedup memory and
> buyers' download-token links; a receipt already delivered to a buyer stays
> valid forever regardless of what happens to this file.

> **Stage 2 transparency is opt-in and off.** Everything this bridge issues
> is a Stage 1 hybrid-signed receipt (Ed25519 + ML-DSA-65) — strong on its
> own, but not logged to a public transparency log. If you want Stage 2
> (an issuer key-transparency log a receipt can be corroborated against),
> that's the separate `attest log` CLI (`init` / `append` /
> `sign-checkpoint`), run out-of-band; the bridge doesn't wire it up for you.

> **A rotated or wrong API key fails loudly, not silently.** If
> `stripe.api_key_env` holds a key Stripe rejects — specifically a `400`,
> `401`, `403` or `404` — the event is dead-lettered with the reason `stripe
> api returned <code> fetching line items…: check stripe.api_key_env` and the
> webhook answers 200, so Stripe stops redelivering something that would fail
> identically every time. Fix the key, then replay it with `attest-bridge
> retry-failed`; nothing was issued and nothing was lost. Every other status —
> `408`, `409`, `424`, `429`, any `5xx`, or a network failure — is treated as
> transient and surfaces as a 500 instead, so Stripe redelivers on its own
> schedule and the receipt still gets issued without anyone intervening.

The local synthetic-webhook test that exercises this same pipeline
end-to-end — no real Stripe account needed — is step 4, above, not repeated
here.
