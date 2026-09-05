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
failed, what it could not run, and what it ran on less than CI runs it.

It is not a convenience wrapper around `pytest`. The steps that break are the
ones nobody types, and two shapes explain why they escape. The end-to-end
suites are slow, so they are the first thing left out of a local run. And the
typecheck lives inside `npm run build --prefix site` rather than inside
`npm test` — `npm test` is the command people know, so it is the one that gets
typed, and it stays green while `tsc` is red.

Some steps need toolchains CI installs: Maude/Tamarin, syft/grype/grant,
xml2rfc, and Playwright browsers. The script does not provision the prover,
scanners, or browsers. It reports missing command-line tools by name and
prints installation hints for missing browsers. The Internet-Draft step uses
`uvx` to obtain pinned xml2rfc; its first invocation may download that package.

A successful desktop end-to-end run with Chromium and Firefox available but
WebKit missing is reported `PARTIAL`. If Chromium or Firefox is missing, the
whole desktop end-to-end step is `SKIPPED`. A failed step stays `FAIL`, even
when it ran with reduced browser coverage; subsequent verification steps are
`NOT RUN`. Environment restoration still runs after a failure.

`--quick` skips the prover, scanner, and Internet-Draft steps. It still runs
the end-to-end suites when their required browsers are available, so it may
also report `PARTIAL`. A failure exits 1, including a failed restoration.
With no failures, any `SKIPPED` or `PARTIAL` step makes the exit status 2;
only a complete successful run exits 0. Invalid options or a missing base
tool (`uv`, `node`, `npm`, or `python3`) exit 64 before verification completes.

Add or change a step in either workflow and it belongs in `tools/verify-all.sh`
in the same commit: `tests/test_verify_all.py` runs the script against stubbed
commands and compares what it ACTUALLY EXECUTED with both workflows — the
command text with its flags, the job it is attributed to, how many times it
runs there, the order within that job, the environment the step's own process
receives, and the five proof shards the formal matrix expands into. A step
still present in the file but no longer reached, or reached under another job's
name, is red exactly like a step that was deleted; so is a local step no
workflow runs, and so is a variable handed to a step that CI never sets.

Three things it does not check, and they are limits rather than oversights. It
does not compare the order of the JOBS: the script groups those its own way,
running the proof shards last where `ci.yml` declares them third. It does not
check the directory a step runs in. And it does not refuse a step CI always
runs being made conditional on a tool this machine may lack — where the tool is
absent that step is reported `SKIPPED` and the run exits **2**, so the
difference is stated rather than hidden, but nothing turns red.
