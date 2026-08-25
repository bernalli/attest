# `store_dies.py` — the store dies, the receipt survives

**Thesis:** when you buy something digital, the seller signs a receipt and
hands it to you — that's the part of the purchase that's actually yours. An
attest receipt is not a database row the issuing store keeps alive for you.
It is a self-verifying object. Delete the store — its signing keys, its
manifests, its whole infrastructure — and the receipt it issued still
verifies, still proves who it belongs to, and still points at an artifact
that still matches.

## What the demo proves

`store_dies.py` runs a fake store, `store.dies.example`, through a full
purchase lifecycle, then kills it, then proves the receipt outlived it:

1. The store generates its Ed25519 signing key and publishes its first key
   manifest.
2. It publishes a DRM-free game — a real file with real bytes — and signs
   an artifact manifest for it.
3. It issues an irrevocable (`revocability: "none"`) receipt to a buyer,
   Casey (`casey@example.com`), as a single self-contained `.attest.json`
   (the buyer-binding salt travels inside the receipt's `delivery` member).
   Casey's copy of that salt is also saved separately, so it survives
   independently of both the receipt file and the store.
4. The store exports a shareable bundle: `casey-library.attest` (safe to
   share — no secrets) and `casey-library.private.attest` (Casey's secrets).
5. **The store's entire directory is deleted** — `shutil.rmtree`, keys,
   manifests, everything. Nothing in the rest of the demo ever reads from
   it again.
6. Casey imports the bundle completely offline and verifies the receipt
   using nothing but what the bundle contained. The result: `ok: true`,
   `trust: "unauthenticated_tofu"` (this bundle was never fetched fresh
   over TLS, so trust is reported honestly, not upgraded to `"verified"`),
   and `revocation: "unknown"` (no revocation feed was ever consulted —
   the demo never claims "not revoked" when the honest answer is "no
   data").
7. Casey proves the receipt is actually theirs by disclosing the salt they
   saved in step 3 — `binding: "proven"`.
8. A *mirror* copy of the game file — held independently of the now-dead
   store, byte-identical to the original — is hashed and checked against
   the surviving receipt's artifact list. It matches.

Every step is asserted programmatically by `tests/test_demo_e2e.py`, not
just eyeballed: the pytest wrapper checks each verb's exit code and JSON
result (`ok`, `trust`, `revocation`, `binding`, `match`) against the exact
values the design promises.

## How to run it

Manually, with narration printed to stdout:

```
.venv/bin/python demo/store_dies.py
```

As an integration test:

```
.venv/bin/pytest tests/test_demo_e2e.py -v
```

Both are fully offline and hermetic — everything happens inside a fresh
temporary directory (`tempfile.TemporaryDirectory` for the manual run,
pytest's `tmp_path` for the test), and the demo only ever deletes its own
store subdirectory, never anything outside that workspace.

## The one file you must never share

Of the two files `export` produces, **`casey-library.private.attest` is the
secret one** — it holds Casey's buyer-binding salt, which is what proves a
receipt belongs to them. `casey-library.attest` (no `.private` in the name)
is safe to share or publish: `export()` strips every salt from it before
writing it out. This is also why the demo writes Casey's salt file
(`buyer/receipt.salt`) with owner-only `0600` permissions, exactly like the
CLI's own secret-writing paths (`attest keygen`'s seed, `attest issue
--salt-out`) — it is real secret material, not scaffolding.
