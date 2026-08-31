<!--
Say what changes and why. If it changes behaviour a verifier can observe, say
which specification section governs it — and if none does, that is itself worth
saying, because it usually means the spec needs the change too.
-->

## What this changes

## Why

## Checks

- [ ] Both suites are green: `uv run --frozen pytest -q` and `npm test --prefix verifiers/ts`
- [ ] Every conformance vector leaf still passes, in both implementations, with none skipped
- [ ] `ruff check`, `ruff format --check` and `mypy --strict src` are clean
- [ ] If any spec document changed: `python tools/check_spec_docs.py` passes and the revision log
      and section counts were updated
- [ ] If observable behaviour changed: a vector covers it, or there is a stated reason why not

<!--
Receipts can carry a buyer commitment. Do not attach one you would not publish.
-->
