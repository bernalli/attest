# attest reference witness

A C2SP [tlog-witness](https://c2sp.org/tlog-witness) implementation that cosigns
checkpoints for the logs it has been configured to know about. It is the
reference for attest v0.2 §11.4, and it exists so that "a witness" is something
that can be run and read rather than only specified.

**This package is never published.** It is `Private :: Do Not Upload`, carries
no release tag of its own, and is excluded from the `attest-receipts` sdist and
the `attest-verifier` npm tarball — an exclusion the release gate asserts on the
built artifacts, because its source describes a deployment and its example
config names key files.

## What a witness does, in one paragraph

A transparency log can prove that an entry exists in a tree it published. It
cannot, by itself, prove that it published only ONE tree: a log with the keys
could maintain two self-consistent branches and show a different one to each
person. A witness reads a checkpoint, checks it against the last one it
cosigned for that log, and — if the new tree genuinely extends the old one —
signs it with a timestamp. From then on, anyone holding that cosignature knows
this log's head was observed by somebody who would have refused to sign a fork
of it.

## What it does not do

- **It does not deliver anti-equivocation on its own.** One witness is one
  observer. Ruling out split views needs several, run by parties that are
  genuinely independent, and attest's policy layer deliberately has no way to
  *prove* independence: every witnessed verdict carries
  `witness_independence_not_established`.
- **It does not authenticate its callers.** The protocol's admission check is
  the pinned log signature on the checkpoint, and adding a second gate would
  break interoperability while protecting nothing.
- **It does not hold keys offline.** Cosigning is an online operation; these
  keys are online keys. That is a property of the role, stated rather than
  worked around.
- **It is not a log.** It stores one row per log — the head it last cosigned —
  and serves it back. Nothing else.

## Endpoints

```
POST <submission_prefix>/add-checkpoint
GET  <monitoring_prefix>/<sha256(origin) in lowercase hex>/checkpoint
```

The submission body is C2SP's: `old <decimal size>`, then zero or more
base64 consistency-proof lines, then a blank line, then the checkpoint note.
Responses follow the specification's status assignments — `200` with the
signature lines, `400` malformed or an old size past the tree size, `403` the
checkpoint does not authenticate against the pinned key, `404` unknown origin,
`409` old-size mismatch or a different checkpoint at an equal size (the body is
the size we hold, media type `text/x.tlog.size`), `422` the consistency proof
does not verify. C2SP's optional `sign-subtree` is not implemented.

## Running it

```bash
# 1. Generate the witness's hybrid key pair with the project's own tool.
attest keygen --seed-out ed25519.seed --pub-out ed25519.pub --mldsa-out mldsa65.json
chmod 600 ed25519.seed mldsa65.json

# 2. Write a configuration. Start from examples/witness.toml — every field is
#    documented there, and there is no default allowlist.
$EDITOR witness.toml

# 3. Check it before serving anything. This is the command that fails when a
#    key file is missing, a public key is the wrong length, an origin is
#    duplicated, or the ML-DSA secret and public halves are not the same pair.
attest-witness check-config --config witness.toml

# 4. Serve. Binds to 127.0.0.1 by default: putting it on a network is a
#    decision somebody has to type, and TLS belongs to whatever is in front.
attest-witness serve --config witness.toml --port 8080
```

Give the operator account exclusive read access to the key files and the state
database. The database is not secret — checkpoints are public — but it is the
record of what this witness has attested to, and nothing else on the host needs
it.

## Design notes worth knowing before changing anything

**No cryptographic or Merkle primitive is implemented here.** Checkpoint
parsing and hybrid authentication come from `attest.tlog.verify_checkpoint`,
consistency from `attest.tlog.verify_consistency`, the cosignature payload and
key ids from `attest.witness`, the signatures from `attest.keys` and
`attest.pq`. What this package owns is the protocol, the state, and the
configuration. Its tests judge its output through the core — including the
TypeScript core — rather than against constants written beside it.

**The compare and the write are one transaction.** C2SP requires it, and the
reason is concrete: two submissions racing on one log must not both read the
same stored size and both be accepted, or the witness has cosigned two heads.
`BEGIN IMMEDIATE` takes the write lock before the first read, so a second
writer — in this process or another — waits rather than reads stale state.

**State is durable before a cosignature is released.** `synchronous=FULL`, and
the lines are returned only after the commit has returned. A witness that
signed first and crashed would wake with a signature in the world for a head it
has no record of, and would cosign a fork of it without hesitation.

**No origin and no log key is hardcoded.** The allowlist is the configuration.
A one-log deployment and a fifty-log deployment run the same code, and an
unknown origin is refused before any state or key is touched.

## Tests

```bash
uv run --frozen pytest witness/tests -q
uv run --frozen mypy --strict witness/src
```

One test shells out to `node` to check this witness's lines against the
TypeScript verifier; it skips if `verifiers/ts/dist` has not been built. One
binds a loopback socket to speak real HTTP to the served app; it skips where a
sandbox forbids that. Both run in CI.
