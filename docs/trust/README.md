# Verifier trust material

This directory holds the configuration an attest verifier is **given**, one
subdirectory per transparency log. `attest-receipts.org-log/` is the trust
material for the log at `attest-receipts.org/log`.

## What these files are

They are trust material, not evidence. A verifier checks evidence; it is
*handed* these. The log does not serve a copy of them next to itself, and it
must not: spec v0.2 §7.3 requires log keys to be pinned out of band and forbids
a conforming verifier from taking them from a bundle, and v0.2 §11.2 says the
same for pinned Bitcoin headers. Taking either from the material under
examination would be circular.

- `attest-receipts.org-log/log-keys.json` — the log's Ed25519 and ML-DSA-65
  **public** keys, passed with `--log-keys`. The private halves live outside
  this repository and are seen only by the signing ceremony.
- `attest-receipts.org-log/anchor-policy.json` — the pinned Bitcoin block
  headers and the CRQC horizon, passed with `--anchor-policy`.
- `attest-receipts.org-log/pinned-headers.source.json` — the raw 80-byte header
  each pinned entry was derived from. No verifier reads it; it exists so that
  every field of a pinned entry can be recomputed from bytes instead of taken
  on faith.

Pass the two a verifier reads like this:

```
attest verify … \
  --log-keys docs/trust/attest-receipts.org-log/log-keys.json \
  --anchor-policy docs/trust/attest-receipts.org-log/anchor-policy.json
```

Supplying `--anchor-policy` at all is half of the capability gate: without it,
anchor evidence is not looked at.

## What is pinned today

No Bitcoin block header is pinned yet: `anchor-policy.json` ships `pinned_headers: {}`. A header is pinned here only after an anchor that lands on it is published under `site/public/log/anchors/`.

## Byte order

A pinned entry states three fields, and two of them have a byte order that is
easy to get backwards. Getting it wrong produces an entry that looks plausible
and matches nothing — so the convention is written down here rather than left
to whichever tool an operator happened to use.

- **`header_hash`** — as block explorers print it: the byte-reversed sha256d of
  the 80-byte header. For the genesis block,
  `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`.
- **`merkle_root`** — the header's **own** byte order, bytes 36-68 of the raw
  header, which is what an OpenTimestamps op-chain replays onto. For the
  genesis block,
  `3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a`.
  `bitcoin-cli getblockheader` prints `merkleroot` byte-reversed
  (`4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b` for the genesis
  block): derive `merkle_root` from the raw header, never copy that field.
- **`time`** — the header's uint32, little-endian at bytes 68-72. For the
  genesis block, `1231006505`.

The two spellings of the merkle root are reverses of one another, so copying
the printed one yields an entry whose `header_hash` is right and whose
`merkle_root` never matches a replay.

## How a header gets pinned

1. Only the log operator proposes a header, and only as the output of
   `attest log ots-convert` on an `.ots` file that has already been upgraded and
   that lands on a **signed** checkpoint of `attest-receipts.org/log`.
2. One pull request per header, carrying together: the entry in
   `anchor-policy.json`, the source entry with the raw header, the `.ots` file,
   the converted proof, the anchored evidence published under
   `site/public/log/anchors/<tree_size>/` (evidence, not trust — anyone can
   replay `ots-convert` against it), and a regenerated `site/src/trusted-log.ts`.
3. A reviewer who is not the operator compares `header_hash`, `merkle_root` and
   `time` against a second source independent of the operator's node — a second
   node, or two distinct block explorers — and writes that comparison in the
   pull request. **That comparison is the only step that establishes the header is
   a real block.** The repository's own checks recompute the three fields from
   `raw_header_hex` and require a published anchor that names the block, which
   catches a mistyped, truncated or wrongly ordered field — but they take the raw
   80 bytes themselves on faith. A self-consistent invention passes them: the
   arithmetic proves the entry was transcribed faithfully, not that it was
   transcribed from Bitcoin.
4. Add-only. A header is not removed while published evidence lands on it:
   removing one takes standing away from real receipts. Rotating or
   compromising the log's signing keys does not touch the pinned headers — they
   are Bitcoin hashes, not signatures.
5. No header is pinned ahead of time. There is no entry without a published
   anchor that lands on it.
6. `crqc_horizon` stays `null` until a separate decision sets it.

Each entry in `pinned-headers.source.json` has this shape:

```
{
  "height": <int>,
  "header_hash": <64 hex chars>,
  "raw_header_hex": <160 hex chars — the 80-byte header>,
  "source": "<how it was obtained>",
  "anchored_checkpoint_tree_size": <int>,
  "ots_proof": "<path under site/public/log/anchors/>"
}
```

## Regenerating the browser and desktop copy

`site/src/trusted-log.ts` is **generated** from the files in this directory, so
that the browser verifier and the desktop build compile in exactly what is
pinned here. Editing it by hand is how two copies of trust material drift
apart. Regenerate it with:

```
uv run --frozen python tools/gen_trusted_log.py
```

The suite runs the same tool with `--check` — `tests/test_gen_trusted_log.py` — which
fails if the committed `site/src/trusted-log.ts` is not what the generator produces
from these files. `.github/workflows/ci.yml` has no separate step for it, deliberately:
the workflow and `tools/verify-all.sh` are kept a single writer. Whoever moves that
check into the workflow should move it, not copy it.
