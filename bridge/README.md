# attest-bridge

attest-bridge is how a store becomes an issuer without writing code. It's a
small service the merchant deploys and runs themselves, next to the existing
checkout — Stripe, itch.io or Shopify. A paid order comes in as a platform
event; a signed attest receipt goes out to the buyer, automatically, at the
moment of sale. From then on the receipt belongs to the buyer: a plain attest
file that verifies offline no matter what happens to the bridge, the
platform, or the store. For a DRM-free seller this is the entire cost of
giving customers ownership that outlives the shop: run one small service and
keep a signing key.

It is NOT a hosted service attest operates on a merchant's behalf, and it
never holds or transmits a third-party's keys: the merchant's issuer signing
key lives only where the merchant's bridge instance runs, and no buyer key
material ever passes through it beyond the buyer's own public key used to
bind a receipt. It is not a payment processor, a store, or a source of truth
for purchase history — those remain the platform's job; the bridge only
reacts to their events.

Every receipt the bridge issues survives the bridge's own death: it is a
plain attest v0.1/v0.2 envelope, offline-verifiable with nothing but the
issuer's public key manifest, with no dependency on the bridge process, its
database, or its uptime ever again.

Receipt email delivery is at-least-once. If the bridge crashes after SMTP has
accepted a message but before the Ledger records it as delivered, its retry
sweep sends the same already-issued receipt again; it never creates a second
receipt. Sweeps are serialized across every process that shares one Ledger —
a `retry-failed` run waits for a sweep already in flight instead of doubling
it — so the delivery-attempt cap is a real bound per receipt, and that crash
window is the only way the same email goes out twice.

## Get started

- [`docs/setup-stripe.md`](docs/setup-stripe.md) — zero to a verified
  receipt selling through Stripe Checkout or Payment Links, including a
  local synthetic-webhook test you can run before touching a real account.
- [`docs/setup-itch.md`](docs/setup-itch.md) — the same, for itch.io (a
  claim-queue poller, not a webhook — itch.io exposes neither).
- [`docs/setup-shopify.md`](docs/setup-shopify.md) — the same, for Shopify
  order webhooks (keypair, manifest and deploy are shared with the Stripe
  guide; this covers what differs).
- [`docs/deploy.md`](docs/deploy.md) — the three deploy targets (Docker
  Compose, Fly.io, Render), all built from
  [`deploy/Dockerfile`](deploy/Dockerfile), plus why Cloud Run isn't a safe
  fourth, and the TLS requirement common
  to all of them.
- [`examples/bridge.toml`](examples/bridge.toml) — the annotated config
  template every setup guide above starts from.
