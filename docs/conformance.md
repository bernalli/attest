# attest — Conformance Program

**Non-normative process document.** This page describes how to check any
implementation — in any language — against the attest conformance corpus, and
how to make and read a conformance claim. It imposes no requirements of its
own; the requirements are `docs/spec/attest-v0.1.md` / `attest-v0.2.md` and
the corpus itself (`docs/spec/vectors/`).

## 1. What conformance means

`docs/spec/vectors/README.md` states the corpus's own definition: each vector
is a leaf directory holding the raw inputs to feed the verification algorithm
(or, for a `chain.json` leaf, to `audit_chain`) and the exact result a
conformant implementation must produce. An implementation is attest-conformant
for a given subset iff it reproduces **every** leaf's `expected.json` in that
subset — a single mismatch fails the whole subset. There is no partial credit
and no central certifying authority: conformance is measured by running the
public runner below against your own implementation and reporting the result.

## 2. Run it: one command

```
python3 tools/conformance_runner.py --adapter '<command with {leaf}>' --subset v0.1|v0.2 [--report FILE]
```

`tools/conformance_runner.py` is stdlib-only **Python 3.12+** (no `attest`
import, no third-party dependency) — any machine with a bare Python 3.12-or-newer
interpreter can run it, regardless of what language the implementation under
test is written in. (The runner uses `datetime.UTC`, which requires Python
3.11+, and the project standardizes on 3.12; an older interpreter fails at
import, before any leaf is checked.)

- `--adapter` is a command **template** containing the literal placeholder
  `{leaf}`. For each corpus leaf directory, the runner substitutes `{leaf}`
  with that leaf's absolute path in every argv token, splits the template with
  `shlex.split`, and invokes it as a fixed argv list (`shell=False` — never a
  shell string).
- `--subset` selects `v0.1` (52 leaves) or `v0.2` (all leaves, currently 156) —
  see §4.
- `--report FILE` additionally writes the machine-readable JSON report (§6)
  to `FILE`.
- `--vectors DIR` overrides the corpus location (defaults to this repo's own
  `docs/spec/vectors`); `--timeout SECONDS` bounds each adapter invocation
  (default 60).

The runner prints one `FAIL <leaf-id>` block (with its mismatches) per
non-passing leaf, then exactly one summary line:

```
CONFORMANT (v0.2): 157/157 leaves pass — corpus revision <hex12>
NOT CONFORMANT (v0.1): 49/52 leaves pass — 3 failing
```

Exit code: `0` if conformant, `1` if not, `2` on a usage/environment error
(missing `{leaf}` in the template, unknown `--subset`, missing/empty
`--vectors` directory).

## 3. The adapter contract

Your adapter is any executable the `--adapter` template invokes once per leaf.
It receives the leaf's absolute directory path as an argument (wherever
`{leaf}` appears in the template) and must:

1. Read the leaf's input files. `docs/spec/vectors/README.md`'s "Vector
   format" section is the canonical description of every input file
   (`envelope.json`/`envelope.raw.json`, `manifests.json`, `disclosure.json`,
   `revocation.json`, `transparency.json`, `log-keys.json`,
   `anchor-policy.json`, `revocation-evidence.json`, `transfer-view.json`,
   `witness-policy.json`, `grant-view.json`, `chain.json`,
   `witness-quorum.json`, `redemption.json`) — not duplicated here.
2. Route the leaf **by file presence**, which is the whole routing rule: a
   directory containing `chain.json` goes to your chain-of-title audit
   entrypoint (v0.2 §17.5), one containing `witness-quorum.json` to your
   activation-quorum entrypoint (v0.2 §11.4), one containing
   `redemption.json` to your redemption check (v0.2 §18.7), and every other
   leaf to your ordinary receipt-verification entrypoint (v0.1 §11). The four
   surfaces have disjoint result shapes, so the routing has to happen before
   anything is printed.
3. Print **exactly one JSON object to stdout, and nothing else on stdout**.
   Diagnostics, logs, and stack traces go to stderr. A non-zero exit code, a
   timeout, or stdout that fails to parse as one JSON object all count as a
   failing leaf (`status: "error"`), regardless of what was printed.

The four output shapes (verbatim member names):

- **Verify-leaf output** (every leaf routed to receipt verification):
  ```json
  {
    "signature": "...", "schema": "...", "trust": "...",
    "revocation": "...", "binding": "...", "transparency": "...",
    "corroboration": "...", "manifest_freshness": "...",
    "grant": "...", "grant_trust": "...",
    "ok": true, "errors": [], "warnings": []
  }
  ```
- **Chain-leaf output** (a leaf whose directory contains `chain.json`):
  ```json
  { "valid": true, "link_status": ["valid", "valid"], "errors": [], "warnings": [] }
  ```
- **Quorum-leaf output** (`witness-quorum.json`):
  ```json
  { "valid": true, "witness_time": 1730000000, "counting_control_groups": ["..."] }
  ```
- **Redemption-leaf output** (`redemption.json`):
  ```json
  { "verified": true }
  ```
  One boolean, and deliberately nothing else: v0.2 §18.7 forbids a gate that
  fronts the delivery of content from having an error path an attacker can
  tell apart from a refusal, so an adapter that distinguished "malformed"
  from "wrong" would be reporting something the specification says must not
  be observable.

Extra members in your output are ignored — a richer result than the
`expected.json` schema requires still passes. Reference implementations of
both adapters (Python and TypeScript) live in this repo at
`tools/conformance_adapter_py.py` and `tools/conformance_adapter_ts.mjs`; read
either as a worked example of the contract above.

## 4. Subsets

- **v0.2** — every leaf in the corpus (currently 157). Measures conformance
  against `docs/spec/attest-v0.2.md`.
- **v0.1** — the 52-leaf subset: every leaf whose top-level group directory's
  leading integer is ≤ 25, plus groups `29-limits` and
  `31-manifest-currency`, plus two pinned leaf ids,
  `35-transfer/i-v01-transferable-null-pubkey-ok` (`35i`) and
  `37-preservation-pledge/s-v01-negative-control` (`37s`). Both are included
  because each is itself an `attest_version: "0.1"` receipt — a v0.1-shaped
  negative control for a v0.2-only schema conditional, living inside an
  otherwise-v0.2-only group — see `docs/spec/vectors/README.md` for the full
  membership rationale. A v0.1-only implementation (one that never accepts v0.2's hybrid
  profile) is measured against this subset, not against all 157.

## 5. The claim process

There is no central conformance authority for attest: an implementation
proves conformance by **self-certification** — running the command in §2
against its own adapter and publishing the result. A conformance claim is
what licenses use of the *attest* name for an implementation (see README's
Naming paragraph) — an implementation that has not run and published this
process has no basis to call itself attest-conformant.

Claim sentence template:

```
<implementation> <version> is attest conformant (v0.1 | v0.2), corpus revision <corpus_revision>, verified <YYYY-MM-DD>.
```

`corpus_revision` is the 64-hex-character SHA-256 digest the runner computes
over every file inside every leaf directory (from the machine report, §6) —
it changes if and only if a leaf's own input/expected files change, so a
claim naming a specific `corpus_revision` is falsifiable: re-run the exact
command against the corpus at that revision and compare.

## 6. The machine report (`--report`)

With `--report FILE`, the runner writes a machine-readable JSON object with
exactly these members:

```
{
  "runner":         "attest-conformance-runner",
  "corpus_revision": "<64-hex SHA-256 over every file inside every leaf dir>",
  "subset":         "v0.1" | "v0.2",
  "generated_at":   "<YYYY-MM-DDTHH:MM:SSZ, UTC>",
  "adapter":        "<the --adapter template, verbatim>",
  "total":          <leaves in the selected subset>,
  "passed":         <leaves that matched expected>,
  "failed":         <total - passed>,
  "conformant":     <true iff every leaf passed>,
  "leaves": [
    { "id": "<group/leaf>", "status": "pass" | "fail" | "error",
      "mismatches": ["<field>: expected <x>, got <y>", "..."] }
  ]
}
```

`conformant` is `true` only when every leaf of the subset is `pass`; a single
`fail` (a diff mismatch) or `error` (adapter crash, non-JSON stdout, or
timeout) sets it `false`. `corpus_revision` is the same digest the claim
sentence (§5) names.

## 7. Self-certification table

The first two entries are attest's own reference implementations,
self-certified through this exact public path (never a special internal
shortcut). These rows are a CURRENT claim, not a changelog: a corpus revision
is a digest over the leaf files, so it changes whenever the corpus grows, and
a row naming a digest that no longer exists on any branch cannot be re-run by
anyone. They are re-measured and replaced whenever the corpus changes.

| Implementation | Subset | Leaves passed | Corpus revision | Date | Command |
| --- | --- | --- | --- | --- | --- |
| attest (Python reference) 0.6.0 | v0.2 | 130/130 | `55f751acdfd05861517d7f7a14b5fca07d6e4cd399af5a7bc530965302ddb79d` | 2026-08-25 | `uv run --frozen python tools/conformance_runner.py --adapter ".venv/bin/python tools/conformance_adapter_py.py {leaf}" --subset v0.2` |
| attest (Python reference) 0.6.0 | v0.1 | 51/51 | `55f751acdfd05861517d7f7a14b5fca07d6e4cd399af5a7bc530965302ddb79d` | 2026-08-25 | `uv run --frozen python tools/conformance_runner.py --adapter ".venv/bin/python tools/conformance_adapter_py.py {leaf}" --subset v0.1` |
| attest-verifier (TypeScript) 0.6.0 | v0.2 | 130/130 | `55f751acdfd05861517d7f7a14b5fca07d6e4cd399af5a7bc530965302ddb79d` | 2026-08-25 | `npm run build --prefix verifiers/ts && python3 tools/conformance_runner.py --adapter "node tools/conformance_adapter_ts.mjs {leaf}" --subset v0.2` |
| attest-verifier (TypeScript) 0.6.0 | v0.1 | 51/51 | `55f751acdfd05861517d7f7a14b5fca07d6e4cd399af5a7bc530965302ddb79d` | 2026-08-25 | `npm run build --prefix verifiers/ts && python3 tools/conformance_runner.py --adapter "node tools/conformance_adapter_ts.mjs {leaf}" --subset v0.1` |

A third-party implementation adds a row here (or in its own repo/README,
linking back to this process) the same way: run §2's command, record the
subset, leaves passed, `corpus_revision`, date, and the exact command used.
