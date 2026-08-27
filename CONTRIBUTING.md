# Contributing to attest

attest is an open standard for seller-signed purchase receipts that a buyer
holds and anyone can verify offline, with a Python reference implementation
and an independent TypeScript verifier. Contributions are welcome — bug
reports, spec clarifications, new conformance vectors, and additional
independent implementations.

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
  `docs/spec/vectors/` — 184 leaf vectors across 43 groups, zero skipped;
- keep both existing suites green: `.venv/bin/pytest -q` (Python) and `npm test`
  in `verifiers/ts/` (TypeScript, which runs the full conformance corpus);
- `ruff` + `mypy` clean for Python, `tsc --noEmit` clean for TypeScript.

A **new independent implementation** proves conformance by running the public
conformance runner against its own adapter command — see
[`docs/conformance.md`](docs/conformance.md) for the one documented invocation
and the report format — and including the resulting report in the PR.

The conformance vectors — not any single implementation's wording — are the
contract.
