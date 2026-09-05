# Contributing to attest

attest is the durable, portable, user-held layer of possession for digital content: the seller
signs a purchase receipt, the buyer holds the file, and anyone can verify it offline long after
the store is gone. It ships as an open standard with a Python reference implementation and an
independent TypeScript verifier. Contributions are welcome — bug reports, spec clarifications,
new conformance vectors, and additional independent implementations.

## Ground rules

- Code is licensed Apache-2.0; documentation and the specification are licensed
  CC BY 4.0 (see `LICENSE` and `LICENSE-docs`). By contributing you agree your
  contribution is offered under those licenses.
- Be precise about security: this is a crypto project. If a change could affect
  verification, canonicalization, key handling, or revocation, say so explicitly.

## Reporting issues

- **Bugs / questions:** open a GitHub Issue with a minimal reproduction.
- **Security vulnerabilities:** do NOT open an issue — follow `SECURITY.md`.

## Proposing a specification change

Normative changes follow: **Issue → Discussion → PR against the spec _and_ the
conformance vectors**. A spec change without a matching vector change (or vice
versa) will not be merged. Explain the compatibility impact on existing v0.1
receipts.

## Implementation pull requests

Any implementation PR (reference or a new independent implementation) MUST pass
the full conformance suite before review:

- reproduce the expected `VerificationResult` for **every** vector under
  `docs/spec/vectors/` — 221 leaf vectors across 47 groups, zero skipped;
- keep both existing suites green: `.venv/bin/pytest -q` (Python) and `npm test`
  in `verifiers/ts/` (TypeScript, which runs the full conformance corpus);
- `ruff` + `mypy` clean for Python, `tsc --noEmit` clean for TypeScript;
- run `./tools/verify-all.sh` before opening the PR — the three bullets above
  are a subset of what CI gates on, and the difference is where PRs go red.

A **new independent implementation** proves conformance by running the public
conformance runner against its own adapter command — see
[`docs/conformance.md`](docs/conformance.md) for the one documented invocation
and the report format — and including the resulting report in the PR.

The conformance vectors — not any single implementation's wording — are the
contract.

## Verifying locally

```sh
./tools/verify-all.sh
```

One command runs what CI runs: every `run:` step of `.github/workflows/ci.yml`
and `.github/workflows/pages.yml`, in the order the jobs run them, with the same
flags. It stops at the first failure and prints a table of what passed, what
failed, and what it could not run.

It is not a convenience wrapper around `pytest`. The steps that break are the
ones nobody types: over the last ninety-nine runs of each workflow the `site`
workflow failed twelve times against `ci`'s one, and none of the twelve was
flaky. They were the two end-to-end suites, which are slow, and the typecheck
inside `npm run build --prefix site` — `npm test` is the command people know,
and it is green while `tsc` is red.

Some steps need a toolchain CI installs and a working copy usually does not: the
Tamarin/Maude proof shards, the syft/grype/grant supply-chain scans, the
Internet-Draft build, and the Playwright browser engines. The script installs
none of them. It names each step it had to skip, prints the command that would
provide the missing piece, and exits **2** — nothing failed, but the tree is
unverified rather than verified. `--quick` skips that whole class on purpose. A
failure exits 1; a run in which everything executed and passed exits 0.

Add or change a step in either workflow and it belongs in `tools/verify-all.sh`
in the same commit: `tests/test_verify_all.py` compares the two command by
command and flag by flag, and turns red otherwise.
