# OL-19 — verifier test type-diagnostic reduction

## Frozen base and scope

The work started only after this check:

```text
$ git rev-parse HEAD
11cf4c1bcea18156b8dfa3582bf34b6a4a7237be
```

No rebase was performed. No production source and no probe configuration were
changed. The work is limited to verifier tests, the verifier test type census,
and this report.

## Before and after

The same census command produced both numbers.

Before the changes:

```text
$ python3 tools/check_verifier_test_types.py
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: 57 diagnostic(s) -- matches the census
exit 0
```

The underlying project-local compiler was also run directly:

```text
$ verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json --pretty false --noEmit --incremental false
exit 2
```

After updating the census:

```text
$ python3 tools/check_verifier_test_types.py
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: 0 diagnostic(s) -- matches the census
exit 0
```

The compiler itself now emits no diagnostics:

```text
$ verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json --pretty false --noEmit --incremental false
exit 0
```

Result: **57 -> 0 diagnostics**, with all 55 test files still measured.

## What changed

The 57 diagnostics split into four mechanical families.

1. Exact JSON rail shapes: 39 diagnostics.
   - Array-shaped transfer and revocation fixtures now pass through a
     `parseArray` helper which calls `loadsStrict`, checks `Array.isArray`, and
     returns `JsonValue[]`.
   - Sparse authority arrays are genuine `JsonValue[]`; the holes remain present
     at runtime, so the hostile-shape test still exercises the sparse array.
   - Stage-2 evidence passed to `verify` is constructed as `JsonObject`, with the
     public-boundary integers represented as `bigint`.
   - The max-scale transparency operations are `JsonValue[][]`, matching the
     JSON values actually inserted.

2. Complete domain fixtures: 7 diagnostics.
   - The empty verifier store is built with the real parsed-store helper.
   - The authority assertion helper accepts the `TrustStore` every caller already
     constructs.
   - The `isOk` tests use a complete `VerificationResult` builder and vary only
     the field each assertion is about. This preserves the isolation of the
     `revoked`, `transferred`, and trust-independence cases.

3. Explicit indexed guards: 8 diagnostics.
   - Byte-corruption tests first prove the target byte exists and throw if their
     non-empty fixture invariant is false; only then do they flip the byte.
   - The NFD test retains both the exact-string and code-unit-length assertions.
   - The duplicate-kid order test names the forward and reversed results instead
     of comparing two unchecked indexed lookups. Two missing values can no
     longer compare equal vacuously.

4. Parameterized rows and Proxy delivery: 3 diagnostics.
   - The hostile anchor-kind callback now receives both columns in each row.
   - The duplicate compromised-entry rows are wrapped as the one argument the
     callback requires; both entry orders now reach `manifest` as arrays.
   - The Proxy uses one explicit `deliver` function from both traps. Descriptor
     reads and value deliveries remain separately counted by the assertions.

No `as any`, `@ts-expect-error`, broad cast, widened production type, or probe
relaxation was added to reduce the count.

## Census red before update

After the test fixes and before `--update`, the gate rejected the tree as
required:

```text
$ python3 tools/check_verifier_test_types.py
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: test/anchor.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/authority.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/blind-authority-evaluation.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/blind-integer-representation.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/canon-parse.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/compromise-retraction-provenance.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/index.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/transfer.test.ts: diagnostics decreased to 0, the census records 9; update the census with --update.
verifiers/ts: test/transparency.test.ts: diagnostics decreased to 0, the census records 14; update the census with --update.
verifiers/ts: test/verify-unit.test.ts: diagnostics decreased to 0, the census records 21; update the census with --update.
verifiers/ts: test/vl3-duplicate-kid.test.ts: diagnostics decreased to 0, the census records 2; update the census with --update.
verifiers/ts: test/witness-cosignature.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/witness-quorum-cost.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: test/witness-quorum.test.ts: diagnostics decreased to 0, the census records 2; update the census with --update.
verifiers/ts: total diagnostics 0, the census records 57; an intended change requires --update.
exit 1
```

The explicit update then measured the complete suite and rewrote the pin:

```text
$ python3 tools/check_verifier_test_types.py --update
MEASURED: 55 test file(s) compiled by the verifier probe
census updated for verifiers/ts: 55 file(s), 0 diagnostic(s)
exit 0
```

The post-update accepting output is the zero-diagnostic census command shown in
“Before and after”.

## Assertion mutation red: downstream requirement

This environment cannot execute Vitest: Vite attempts to compile its
configuration into a temporary file beside the configuration, where the
filesystem rejects the write with `EROFS`. The mandate explicitly forbids
working around that boundary. Therefore no Vitest result, green or red, is
claimed here.

This means the requested runtime mutation red remains a downstream acceptance
step. A targeted check of the negative identity guard is:

1. In `verifiers/ts/test/index.test.ts`, temporarily replace
   `flipped[0] = first ^ 0x01` with `flipped[0] = first`.
2. Run, from `verifiers/ts`:

   ```text
   node_modules/.bin/vitest run test/index.test.ts -t "hashes bytes, not text: one flipped bit changes the digest"
   ```

3. Require a nonzero result at the `not.toBe` assertion, restore the XOR, and
   rerun the same target successfully.

The mutation makes the two byte arrays identical, so the two SHA-256 values are
identical and the negative assertion is logically capable of failing. That is
not presented as executed output; the downstream Vitest run is still required.
A temporary attempt to substitute a wrong-typed matcher expectation confirmed
that `tsc` cannot stand in for this proof: the Vitest matcher typing accepted
it, so the typecheck remained green.

## Files changed

- `verifiers/ts/test/anchor.test.ts`
- `verifiers/ts/test/authority.test.ts`
- `verifiers/ts/test/blind-authority-evaluation.test.ts`
- `verifiers/ts/test/blind-integer-representation.test.ts`
- `verifiers/ts/test/canon-parse.test.ts`
- `verifiers/ts/test/compromise-retraction-provenance.test.ts`
- `verifiers/ts/test/index.test.ts`
- `verifiers/ts/test/transfer.test.ts`
- `verifiers/ts/test/transparency.test.ts`
- `verifiers/ts/test/verify-unit.test.ts`
- `verifiers/ts/test/vl3-duplicate-kid.test.ts`
- `verifiers/ts/test/witness-cosignature.test.ts`
- `verifiers/ts/test/witness-quorum-cost.test.ts`
- `verifiers/ts/test/witness-quorum.test.ts`
- `tools/verifier-test-types-census.json`
- `docs/plans/ol19-verifier-test-types-reduction.md`

## Non-mechanical cases left open

None of the 57 diagnostics required a design decision. All were removed by
constructing the existing intended value, aligning a parameterized row with its
callback, or making a precondition explicit. The only open acceptance item is
the downstream Vitest mutation run described above; it is an environment
limitation, not an unresolved type diagnostic.

## quello che so io e non è scritto altrove

- The largest source of debt was not production typing: two local `parse`
  helpers promised `JsonObject` even at call sites that deliberately parsed
  arrays. A runtime-checked array helper removed 24 diagnostics across the
  transfer and verifier-unit files without changing the measured boundary.
- The duplicate compromised-entry `it.each` case was more than a type annotation
  mismatch. Vitest spreads an inner row into callback arguments, so the old
  callback received one entry where `manifest` needed an entry array. The extra
  tuple layer repairs the runtime shape as well as the type.
- The negative digest identity assertion remains meaningful because the fixture
  must contain a first byte and the XOR necessarily changes that byte. Removing
  the XOR is the minimal downstream mutation that should turn the test red.
- A successful zero-diagnostic `tsc` run is not evidence that a Vitest matcher
  can fail. The matcher types are permissive enough to accept a deliberately
  wrong-typed expected value; only the prohibited-in-this-environment runtime
  test can close that acceptance item.
- `verifiers/ts/tsconfig.t3b-probe.json` was not changed, so the set and strictness
  of what the census measures did not move during the reduction.
