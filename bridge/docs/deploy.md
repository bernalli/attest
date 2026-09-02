# Deploying attest-bridge

Three working targets, all built from the same
[`bridge/deploy/Dockerfile`](../deploy/Dockerfile). Pick one; you don't need
more than one. Docker Compose, Fly.io, and Render are each a single
command/Blueprint. If you have no reason to prefer one, take **Fly.io**: it
is the shortest path from here to a bridge answering a real webhook. Take
**Docker Compose** if you would rather own the machine — it is the sovereign
option, not the fallback, and the TLS step it needs is written out below in
full. Render is the third, equally supported. A fourth platform, Cloud Run,
is covered too, but only as
a caution — read [its section](#cloud-run-not-recommended) before you
consider it; it is not a safe target for this particular service. Every
target needs the same four things somewhere on the machine/container it
runs on:

The container installs the published `attest-receipts` package, not this
checkout's workspace override. It requires `attest-receipts>=0.4.0`; pin a
published version explicitly in your own deployment if reproducibility across
image rebuilds matters.

- `bridge.toml` and `key-manifest.json` (config + the public key manifest —
  not secret, but private to your deployment; the container's `ENTRYPOINT`
  always reads these from `/etc/attest-bridge/`, whether they arrive as a
  read-only mount — Docker Compose, Fly.io — or are written there at boot
  from an env var — Render; see that target's section for which)
- `issuer.seed` and `issuer.mldsa.json` (your signing keys — genuinely
  secret; same deal, always read from `/secrets/`)
- the four env vars your `bridge.toml` references via `*_env`:
  `STRIPE_WEBHOOK_SECRET`, `STRIPE_API_KEY`, `ITCH_API_KEY`, `SMTP_PASSWORD`
  (only set the ones you actually use)
- a writable persistent directory containing `ledger_path` and SQLite's WAL
  sidecars — the Ledger is a logical database, not one independently copyable
  file — that **survives restarts**. This is the one requirement that's easy to get
  wrong: an ephemeral/scratch disk here doesn't lose already-delivered
  receipts (those are safe with the buyer forever), but it does lose your
  replay-dedup memory, so a redeploy right after a webhook retry could
  double-issue. The bridge refuses to start when the directory holding
  `ledger_path` does not exist, naming it — it never creates it, precisely
  so that a volume which failed to mount stops the deploy instead of quietly
  starting an empty Ledger that has forgotten every webhook it handled.

**TLS is not optional.** Fly and Render terminate TLS for you; on Docker
Compose you put a proxy in front of the bridge, and
[the Compose section](#tls-for-compose-end-to-end) has the whole thing —
install, config file, one command — rather than leaving you the exercise.
Never expose the bridge directly on plain HTTP: a webhook body and a
downloaded receipt both carry a buyer-binding salt, and that salt is a secret
in transit, not just at rest.

## The bridge runs unprivileged (uid `10001`)

The image creates an account `attest`, uid and gid **`10001`**, and the
server runs as it — never as root. That matters here more than it does for a
static site: this process holds your signing key and parses bodies anyone on
the internet can send it.

The container's `ENTRYPOINT` still starts as root, for two steps and no
others: decoding the `*_B64` material on targets that need it (Render), and
taking ownership of the Ledger volume, which arrives root-owned the first
time a platform mounts it. Then it drops to `10001` with `setpriv` and
`exec`s the server. If it cannot drop — `setpriv` missing from a rebuilt
image — it refuses to start rather than keep going as root.

What this costs you: **nothing on Fly.io or Render**, where the volume is
handed over automatically. On Docker Compose the Ledger is a named volume and
is likewise handled for you, but `etc/` and `secrets/` are **bind mounts from
your host**, and your host has no `attest` account — so give them to the
number:

```sh
sudo chown -R 10001:10001 bridge/deploy/etc bridge/deploy/secrets
```

Do that before the first `up` (and again after you replace a key file). Skip
it and the bridge starts, cannot read `issuer.seed`, and says so. The same
goes for a Ledger directory you mount yourself: if it is not writable, the
bridge refuses to start and names the uid to chown to, rather than starting
without a memory of which purchases it has already issued.

## One writer per Ledger

The bridge runs **one `serve` process per Ledger file**. That is a
correctness requirement, not a preference, and the three targets satisfy it
by construction: a Fly volume attaches to exactly one Machine, a Render disk
is reachable from one instance and Render does not overlap instances across a
deploy, and the Compose file starts a single container. Do not scale the
bridge horizontally against one Ledger.

The commands you run *beside* a live `serve` — `retry-failed`, `itch-import`,
exactly as the setup guides tell you to — are a second process on that same
file, and they are safe. Three separate things make them safe:

- **Issuance.** Two writers recording the same purchase cannot both win: the
  `(platform, purchase_id)` primary key refuses the second, and the second
  responds by re-reading the row and returning the stored receipt as a
  duplicate. One purchase keeps one receipt and one buyer-binding salt.
- **Delivery.** The retry sweep takes an exclusive file lock on the Ledger's
  own inode (plus a compatibility lock beside it, so a process still running
  an older build serializes too), so a `retry-failed` run waits for a sweep
  already in flight instead of emailing the same receipt a second time.
  Keying the lock on the inode rather than on the path is what makes a
  symlink, a relative path or a second hard link resolve to one lock instead
  of two.
- **The journal.** The Ledger is opened in WAL with a declared busy timeout,
  so a reader never blocks a writer and a second writer gets a clean "database
  is locked" — never a damaged file.

Two limits are stated here rather than papered over:

- `MAX_PENDING_CLAIMS`, the itch claim-queue cap, stays best-effort across
  processes: two processes can each admit the thousandth claim. Claim *dedup*
  is not best-effort — a unique index enforces it in the database — and the
  cap is a resource guard, not a security boundary.
- In WAL the Ledger is **three files** (`ledger.sqlite3`, `-wal`, `-shm`), and
  recently committed rows live in the `-wal` until checkpointed. Do not copy
  those files one by one while the bridge is running: they can change between
  copies. Use SQLite's online-backup API or an atomic filesystem/volume
  snapshot. The simplest safe procedure is to stop the bridge, wait for
  shutdown, and copy the main database after SQLite has closed and
  checkpointed it.

**Reach the Ledger the same way from every process.** Give each process the
same absolute `ledger_path`, and when you mount it into a container mount the
**whole directory**, never the database file on its own. Opening one WAL
database through a hard link, or through a bind mount of just the file, is
not supported: SQLite derives `-wal` and `-shm` from the name it was opened
with, so a second name means a second pair of sidecars in a second place, and
the two processes stop sharing the journal that keeps them consistent. The
delivery lock survives those spellings; the journal does not.

About the file lock, precisely: it was measured on a local filesystem, which
is what all three targets provide — Fly volumes and Render disks are block
devices, and Compose runs on your own. It has not been measured on a Fly
volume or a Render disk specifically. If you run the bridge somewhere else,
the question to ask about that filesystem is whether POSIX file locking works
on it; if the answer is "no" or "not sure", it is not a place for this Ledger.

## Health checks: `/healthz` and `/readyz`

Two endpoints answering two different questions.

`/healthz` is **liveness**: it returns `200 {"ok": true}` as long as the
process can answer an HTTP request, and checks nothing else. This is what
the platform targets below health-check on (`fly.toml`, `render.yaml`), and
deliberately so — see the paragraph after next.

`/readyz` is **readiness**: `200 {"ready": true}` when a purchase arriving
right now could become a receipt, `503 {"ready": false}` when it could not.
It checks the three things issuance requires, all locally: the Ledger
answers a query, the signing key is inside its validity window, and at least
one product is configured. The expired-key case is the one worth wiring an
alert to — a bridge whose key has aged out keeps answering `/healthz` with a
200 while rejecting every purchase, and the merchant otherwise learns this
from their customers. The response never says *which* check failed: the
route is unauthenticated, so the reason goes to the service log, where the
operator can read it and nobody else can.

`/readyz` deliberately does **not** touch SMTP, the itch API, or the Stripe
API. Delivery is not on the issuing path — a receipt is signed, recorded and
downloadable before any email is attempted, and a failed send is retried by
the delivery sweep — so a dead mail relay does not make this bridge unable
to do its job, and reporting otherwise would invite you to restart a service
that is working. A probe that opened an SMTP session on every check (every
15s, on Fly) would also be an efficient way to get rate-limited by your own
relay.

Point monitoring and alerting at `/readyz`; leave the platform's own health
check on `/healthz`. Wiring the platform to `/readyz` would pull an instance
out of routing whenever it cannot *issue* — but a bridge with an expired key
still serves buyers their existing receipt downloads on `/r/<token>`, and
taking it out of rotation would break the one thing still working.

## Docker Compose (self-hosted: a VPS, a home server, ...)

```sh
mkdir -p bridge/deploy/etc bridge/deploy/secrets
cp bridge.toml key-manifest.json bridge/deploy/etc/
cp issuer.seed issuer.mldsa.json bridge/deploy/secrets/
printf 'STRIPE_WEBHOOK_SECRET=whsec_...\n' > bridge/deploy/.env   # + STRIPE_API_KEY / ITCH_API_KEY / SMTP_PASSWORD as needed
chmod 600 bridge/deploy/.env
sudo chown -R 10001:10001 bridge/deploy/etc bridge/deploy/secrets
docker compose -f bridge/deploy/docker-compose.yml up -d
```

Run from the repo root — see [`docker-compose.yml`](../deploy/docker-compose.yml)
for the exact mounts (two read-only, one named volume for the Ledger). The
`chown` is the one step that has no equivalent on the other two targets: those
two directories come from your host, and the bridge reads them as uid `10001`
(see [above](#the-bridge-runs-unprivileged-uid-10001)).

### TLS for Compose, end to end

Fly and Render terminate TLS for you. Here you do it, and you should not skip
it: a webhook body and a downloaded receipt both carry a buyer-binding salt.
The compose file publishes port 8080 on loopback only, so the bridge is not
reachable from outside until a proxy is in front of it. Caddy gets and renews
a Let's Encrypt certificate on its own, which makes this three commands and a
four-line file.

You need a DNS `A` (or `AAAA`) record for your domain pointing at this
machine, and ports 80 and 443 reachable on it — Caddy uses both.

Install it (Debian/Ubuntu, from Caddy's own repository; other systems are on
[caddyserver.com/docs/install](https://caddyserver.com/docs/install)):

```sh
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | gpg --dearmor | sudo tee /usr/share/keyrings/caddy-stable-archive-keyring.gpg > /dev/null
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

Then `/etc/caddy/Caddyfile`, in full — replace the hostname with yours:

```
# /etc/caddy/Caddyfile
receipts.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

```sh
sudo systemctl reload caddy
curl https://receipts.example.com/healthz    # {"ok": true}
```

That last line is the whole check: a `200` over `https` means the certificate
is in place and the proxy reaches the bridge. Use the same hostname for
`public_base_url` in `bridge.toml` and for the webhook URL you register with
the platform.

## Fly.io

A Fly Machine can mount only **one** volume, so only the Ledger (a real,
growing SQLite database — its main file plus the WAL sidecars, which is why
the volume holds the whole directory) uses one; `bridge.toml`, `key-manifest.json`,
`issuer.seed`, and `issuer.mldsa.json` ride in as base64-encoded secrets
that Fly writes to disk at boot (the `[[files]]` blocks in
[`fly.toml`](../deploy/fly.toml)):

```sh
fly apps create attest-bridge
fly volumes create attest_bridge_data --region iad --size 1
fly secrets set \
  BRIDGE_TOML="$(base64 < bridge.toml | tr -d '\n')" \
  KEY_MANIFEST="$(base64 < key-manifest.json | tr -d '\n')" \
  ISSUER_SEED="$(base64 < issuer.seed | tr -d '\n')" \
  ISSUER_MLDSA="$(base64 < issuer.mldsa.json | tr -d '\n')" \
  STRIPE_WEBHOOK_SECRET=whsec_... STRIPE_API_KEY=sk_... ITCH_API_KEY=... SMTP_PASSWORD=...
fly deploy --config bridge/deploy/fly.toml
```

The double quotes and `tr -d '\n'` matter and are not optional style: GNU
coreutils `base64` (the default on Linux) line-wraps its output every 76
characters, and an unquoted `$(...)` lets a POSIX shell field-split those
embedded newlines into dozens of stray arguments, breaking the command
outright; macOS/BSD `base64` doesn't wrap, so `tr -d '\n'` is a harmless
no-op there. Run this from the repo root (the build context
[`fly.toml`](../deploy/fly.toml) expects), and set the secrets **before**
the first deploy — the files they back are written at boot, so the Machine
needs them to exist as secrets first. The one volume (`attest_bridge_data`)
starts empty and needs no manual population: it only ever holds the Ledger,
which the bridge creates itself on first run. Fly terminates TLS at its edge
and health-checks `/healthz` automatically (see `fly.toml`).

## Render

Render dashboard → **New +** → **Blueprint** → point at this repo → pick
`bridge/deploy/render.yaml` as the Blueprint file. Render prompts you for
every `sync: false` env var the Blueprint declares **during creation, before
the first deploy ever runs** (confirmed against Render's own docs) — fill in
all eight right there:

- `BRIDGE_TOML_B64`, `KEY_MANIFEST_B64`, `ISSUER_SEED_B64`, `ISSUER_MLDSA_B64`
  — base64 of `bridge.toml`, `key-manifest.json`, `issuer.seed`, and
  `issuer.mldsa.json` respectively (`base64 < bridge.toml`, etc.) — paste the
  whole, possibly multi-line, output straight into the dashboard field; it
  doesn't need to be single-line here the way Fly's shell command above does
- `STRIPE_WEBHOOK_SECRET`, `STRIPE_API_KEY`, `ITCH_API_KEY`, `SMTP_PASSWORD`
  — whichever your `bridge.toml` actually references

There is no shell/SCP step and no crash loop here, on purpose: Render's
**Secret Files** always land at a fixed `/etc/secrets/<filename>` (not the
`/etc/attest-bridge/...`/`/secrets/...` paths this image's pinned `ENTRYPOINT`
reads, and not configurable — confirmed against Render's own docs), and a
Render persistent **Disk** starts empty with no documented way to seed it
except shelling into an already-running instance (SCP or `magic-wormhole`) —
which doesn't exist yet if the `ENTRYPOINT` refuses to start without that
same config already present. Rather than ship that deadlock, this image's
`ENTRYPOINT` is [`docker-entrypoint.sh`](../deploy/docker-entrypoint.sh): it
decodes the four `*_B64` env vars above to
`/etc/attest-bridge/bridge.toml`, `/etc/attest-bridge/key-manifest.json`,
`/secrets/issuer.seed`, and `/secrets/issuer.mldsa.json` fresh on every boot,
*before* `attest-bridge serve` starts — a regular env var, unlike a Secret
File, has no fixed path to fight with. So the very first deploy comes up
healthy on `/healthz`, with nothing to populate afterward.

There is deliberately no `dockerCommand` override in `render.yaml`: Render's
`dockerCommand` overrides the Dockerfile's `CMD`, not its `ENTRYPOINT`, and
this image sets no `CMD` at all — anything set as `dockerCommand` would be
appended as extra argv to `docker-entrypoint.sh` and simply ignored (the
script takes no arguments), so there is nothing useful `dockerCommand` could
do here. Leave it unset.

Render allows only **one** persistent disk per service; it holds the Ledger
alone, mounted at `/var/lib/attest-bridge` — the shipped example config's
default `ledger_path` already points there, so no per-target path override
is needed the way earlier drafts of this doc required. Config and keys need
no disk at all now, since they're re-materialized from the `*_B64` env vars
on every boot; the Ledger is the one thing that must actually survive a
restart, so it's the one thing that gets the disk.

Render terminates TLS and health-checks `/healthz` automatically.

## Cloud Run (not recommended)

**Cloud Run is not a working deploy target for attest-bridge — this section
is a caution, not a recipe. There is no `gcloud run deploy` command below on
purpose.**

[One writer per Ledger](#one-writer-per-ledger) above explains what the
bridge does about concurrency and where the limits are. Cloud Run breaks the
argument in both halves at once.

First, the single-writer requirement: a rolling deploy briefly runs the old
and new revisions side by side, and `--min-instances 1 --max-instances 1` is
a *soft* target, not a hard exclusivity guarantee — Cloud Run can run two
instances against the same mounted file. Where the CLI commands beside
`serve` are an occasional second writer you invoke on purpose, this is a
systematic one you cannot prevent, and the webhook dedup lock in `http.py` is
process-local, so two instances would both admit the same event.

Second, the file locking those protections rest on. Cloud Run's volume
options do not provide it: Cloud Storage FUSE has weaker POSIX semantics and
no file locking at all, and Filestore (NFS) — Cloud Run's other volume option
— is documented by Google itself as mounted in **no-lock mode**. Without
working locks, the sweep lock cannot serialize, sqlite cannot enforce one
writer, and a second writer really can leave a damaged file rather than the
clean "database is locked" you would get on a block device. That is the case
where "silent corruption" is the accurate description — not a crash you would
notice, a correctness bug you might not.

Serverless/autoscaling platforms generally share this problem — it isn't
Cloud-Run-specific, just most visible there. Pick a target with a real
local or network-attached block device tied to exactly one running
instance instead: Fly.io or Render's built-in persistent disks, or a small
VPS via Docker Compose, all covered above.
