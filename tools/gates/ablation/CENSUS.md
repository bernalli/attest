# The ablation bench for the adversarial suites

---

## The number

Measured at `86fa91220876c4cbc5ae0570eba852cdfa954b85`, one spec at a time, each run
exiting 0 on a tree that `git status` showed clean before and after it. The unit
counted is the **row**: one mutant id of a spec, run against the suite that row names.

| spec | rows | applications_confirmed | suite runs | KILLED | KILLED_ELSEWHERE | SURVIVED | BROKEN |
|---|---|---|---|---|---|---|---|
| `spec_hostile.json` | 4 | 4/4 | 6 | 1 | 2 | 1 | 0 |
| `spec_py1.json` | 16 | 16/16 | 19 | 14 | 2 | 0 | 0 |
| `spec_py2.json` | 21 | 21/21 | 22 | 19 | 2 | 0 | 0 |
| `spec_site.json` | 12 | 12/12 | 16 | 11 | 1 | 0 | 0 |
| the four specs | 53 | 53/53 | 63 | 45 | 7 | 1 | 0 |

No row read `NOT_APPLIED` or `BASELINE_RED`, and none was left unmeasured. Each
`applications_confirmed` above is the one written by the run, in
`results/spec_hostile-86fa91220876c4cbc5ae0570eba852cdfa954b85.json`,
`results/spec_py1-86fa91220876c4cbc5ae0570eba852cdfa954b85.json`,
`results/spec_py2-86fa91220876c4cbc5ae0570eba852cdfa954b85.json` and
`results/spec_site-86fa91220876c4cbc5ae0570eba852cdfa954b85.json`.

The 45 `KILLED` rows are not all counted as killed:

```
33 killed
12 KILLED, not guaranteed   -> see the section of that name
 7 KILLED_ELSEWHERE         -> see "Where the remeasurement differs from the text below"
 1 SURVIVED                 -> HOST-S2-view-nesting-headroom
 0 BROKEN
53 rows
```

The four specs hold 53 rows, 52 distinct edits `(file, old, new)` and 50 distinct
anchors `(file, old)`. The two rows that share an edit are HOST-S2 and HOST-P1, one
change to the nesting headroom run against two different suites; the two other
shared anchors carry different edits (VL34-P1 and VL34-P5, SITE-P2 and SITE-P3).

A property here is a **production guard**, not a test: the census found several
cases where three or four differently-named tests all die to one mutation, and
counting those separately would measure how wide the suite is rather than how
many invariants it holds. The per-suite headings below count properties, one per
distinct edit, 52 of them.

When the census was taken, seven of those properties survived their own ablation,
and the fixtures in `39fe3c2` were written for them. The seven are eight rows today:
seven read `KILLED_ELSEWHERE` and one, HOST-S2, still reads `SURVIVED`.

**Why 9 ablated and not 17.** Seventeen tracked test files carry `adversarial` or
`hostile` in their name; the four specs here ablate nine of them. The eight unmeasured suites are listed in spec_hostile.json's unmeasured field; that list contains no mutation anchors or proposed edits.
Five of the eight are in `verifiers/ts` (`authority`, `canon-depth-profile`,
`compromise`, `vl3-duplicate-kid`, `vl5-anchor-status`), two are Python
(`test_canon_depth_profile_adversarial.py`, `test_compromise_adversarial.py`) and one
is `desktop/test/card-hostile.test.ts`. None of their properties has been measured —
declared, not silent. About the code under the `verifiers/ts` five there is an
impression from reading, **not a count**: exported functions there wrap their body in
`try { } catch { return false }`, so a mutation that removes a null guard would be
swallowed and the test would stay green *for the wrong reason*. How many functions
do so has not been counted. It is a prediction, and predictions in this work have a
poor record — two of five were wrong when measured. It should be measured, not
quoted.

## KILLED, not guaranteed

A `KILLED` row is not counted as killed when no test its spec names went red by
`AssertionError`, or when a red test id carries `::` inside its parameter brackets,
where the bench can lose the test's name. The second criterion matched none of the
134 red test ids of the four runs, 77 of which carry parameters. The first matches
twelve rows; for each, the `why` of every named red as its outcome record gives it:

| row | named reds, by `why` | declared in the spec |
|---|---|---|
| VL2-P1-container-duplicate-name | 4 `Failed` | |
| VL2-P2-export-duplicate-receipt-id | 2 `Failed` | |
| VL2-P3-export-receipt-id-shape | 2 `Failed` | |
| VL2-P5-import-distinct-ids-not-overtight | 1 `attest.bundle.BundleError: bundle lists receipt_id '01HZX000` | `direction` |
| VL34-P3-rotation-keeps-an-active-key | 4 `Failed` | |
| VL34-P4-non-dict-entries-ignored-not-crash | 3 `AttributeError` | `property_red_is_crash` |
| VL34-P5-kid-type-strictness | 1 `AttributeError` | `property_red_is_crash` |
| VL34-P6-rotation-appends-replacement | 1 `ValueError` | `direction`, `property_red_is_crash` |
| VL5-P2-anchor-status-type-guard | 2 `TypeError` | `property_red_is_crash` |
| AU-P13-successor-version-strictly-increases | 1 `Failed` | |
| AU-P14-entry-deletion-refused | 3 `Failed` | |
| AU-P15-valid-from-immutable | 1 `Failed` | |

`Failed` is what pytest raises when a `pytest.raises` block ends without the
exception it expects, and every named test of the seven `Failed` rows asserts through
`pytest.raises`. The other five rows carry a declaration in their spec: four
`property_red_is_crash`, a red that is meant to be a crash, and two
`direction: "tightening"`, a mutation that makes the code refuse what it should
accept (VL34-P6 carries both). Neither observation promotes a row: the twelve stay
out of the killed count until each has been looked at.

On the vitest side the `why` of a red is `AssertionError` whenever its failure
message carries none of the bench's form markers: the label is inferred by
exclusion, not read from the exception. The eleven `KILLED` rows of
`spec_site.json` pass the first criterion on that inference.

## Where the remeasurement differs from the text below

The section *Per suite* further down records the census, taken before the fixtures
in `39fe3c2`, and calls these eight rows' properties survivors. Remeasured:

| row | verdict | red | named by the spec, still green |
|---|---|---|---|
| VL2-P4-export-payload-is-object | `KILLED_ELSEWHERE` | `test_export_names_the_payload_guard_and_not_the_one_after_it`, both cases | `test_export_refuses_receipts_without_an_object_payload` |
| VL5-P4-anchor-is-order-independent-max | `KILLED_ELSEWHERE` | `test_t_is_the_later_of_two_genuine_statements[True]` | `test_only_authenticated_registered_statement_statuses_determine_t` |
| AU-S1-trust-material-door | `KILLED_ELSEWHERE` | `test_an_unbranded_manifest_dict_is_refused_even_when_it_would_otherwise_verify` | `test_verify_authorization_fails_closed_on_malformed_key_manifest` |
| AU-S2-entry-for-issuer-string-lookup | `KILLED_ELSEWHERE` | `test_entry_for_issuer_refuses_a_lookup_key_that_merely_claims_equality` | `test_entry_for_issuer_fails_closed_on_non_string_lookup_keys` |
| SITE-S2-token-character-class | `KILLED_ELSEWHERE` | the two token cases, a space and a dot with an `@` | `pins the token-shape residual exactly as it was decided` |
| HOST-S1-admission-byte-ceiling | `KILLED_ELSEWHERE` | `test_the_admission_byte_ceiling_actually_refuses_an_oversized_member` | `test_over_byte_ceiling_grant_view_returns`, `test_over_byte_ceiling_authority_view_returns` |
| HOST-P1-view-nesting-headroom-elsewhere | `KILLED_ELSEWHERE` | `test_admission_reserves_the_nesting_a_reconstructed_view_costs` | `test_grant_view_reconstruction_always_canonicalizes`, `test_authority_view_reconstruction_always_canonicalizes` |
| HOST-S2-view-nesting-headroom | `SURVIVED` | none, 0 of 55 | the spec names none |

Each `KILLED_ELSEWHERE` row goes red on the fixture this document names for it and
on nothing else: the fixture holds the property, and the test whose name claims it
still does not.

HOST-S2 runs `test_blind_hostile_evidence_views.py` alone, and no fixture for the
nesting headroom was added to that file: it still cannot see the edit, as the section
on that file below says of its assertions. The edit itself is not inert — HOST-P1
applies the same bytes (both ledger records end at the same `sha_after`), and
`test_admission_reserves_the_nesting_a_reconstructed_view_costs`, in
`test_hostile_view_content.py`, goes red on them.

## What each verdict had to survive to be believed

The survivor count is the deliverable, so the count is what had to be defended.
Five readings were refused, each because the opposite one was observed while
building the bench:

| refused reading | what actually happened | how it is now caught |
|---|---|---|
| the mutation happened | an anchor matched **mid-line** and spliced into an indented line; the file stopped parsing and it read as a broken mutant, a fact about the spec dressed as a fact about the code | before anything is mutated, the spec is checked against the tree and an anchor that is absent, occurs more than once or starts mid-line is refused (exit 3). Each mutation that lands then leaves three traces the classification does not produce: the journal record, written and flushed before the target is touched, with the re-read that finds the mutated bytes on disk; `git status`, taken after that re-read and before the suite, naming exactly the mutated file; and a fresh nonce per suite run, which the classified outcome record must carry back. `applications_confirmed` counts the rows where all three hold, and a count below the mutations that had to land exits 10 |
| the red is the red that was intended | a `NameError` mutant produced **17 red against a good mutant's 12** — the wrong mutation looked like better coverage | the outcome record carries each red's exception type; a red made only of form errors is `BROKEN`, never `KILLED`, unless the spec declares the crash to be the property (`property_red_is_crash`); a red on none of the tests the spec names is `KILLED_ELSEWHERE`, not `KILLED` |
| a type-invalid change is inert | vitest strips types, so `const status: number = o['status']` **runs green**; without a typecheck it reads `SURVIVED` | `tsc --noEmit` runs before vitest on every mutated run; when it exits non-zero vitest does not run, the row carries the `typecheck` trace (the exit status, the `TS` codes, the hash of the output) in place of a nonce, a trace that holds only when `tsc` named at least one `TS` code, and it reads `BROKEN`. `selftest-ts.json` pins that reading for this mutant (TS-ST3); the `SURVIVED` reading with the gate off (`--no-typecheck`) was observed when the gate was added and no test re-runs it |
| a restored file is the file imported | `VIEW_ARRAY_ELEMENT_NESTING = 2`, restored and verified byte-identical, **imported as 0** | the journal removes every `__pycache__` under the tree, outside `.venv` and `node_modules`, when it applies a mutation and when it restores one, and touches the target after writing its original bytes back; the suites run with `PYTHONDONTWRITEBYTECODE=1` and without `PYTHONPYCACHEPREFIX`, so they write no cache inside the tree or outside it |
| a survivor is real | two mutants landed and changed nothing; an inert mutation is indistinguishable from an uncovered property | `prove_survivor.py` runs a probe on the original tree and on the mutated one, holding the same journal; it exits 0 only when the two outputs differ, 2 when the probe does not run on the original tree and 3 when it does not run on the mutated one, so a probe that measured nothing cannot report a mutant as inert |

The fourth is the one worth carrying elsewhere. Bytecode is invalidated by source
**mtime and size**, so a constant replaced by one of the *same length* — `2` for
`0`, `4096` for `4097` — can leave a cache the interpreter still trusts after the
restore. `tools/gates/run_t2_mutants.py` guarded this before it was removed (`.touch()` plus a
cache sweep, with a comment naming it); this bench did not, and paid for it. The
symptom was a fixture failing on a clean tree for a reason that could not be read
off the source.

## Per suite

Outcome column: `killed` = the guard's removal turns the suite red from the right
assertion. `SURVIVED` = it stayed green, and the fixture that closes it is named.

The outcomes and survivor counts in this section are those of the census, taken
before the fixtures in `39fe3c2`. The eight rows whose remeasured verdict differs
are listed under *Where the remeasurement differs from the text below*, and twelve of
the rows this section calls killed are listed under *KILLED, not guaranteed*: for
those, the red on the named tests is not an `AssertionError`.

### `tests/test_vl2_bundle_duplicate_members_adversarial.py` — 5 properties, 1 survivor

| property | assertion that kills the mutant | outcome |
|---|---|---|
| a container refuses a repeated central-directory member name | `pytest.raises(BundleError)` in the three import cases | killed (4 red) |
| export refuses two receipts sharing a `receipt_id` before touching disk | `pytest.raises` + `out_dir` empty | killed |
| export refuses a `receipt_id` that is not the exact ULID shape | `pytest.raises(match="invalid receipt_id")` | killed |
| **export refuses a receipt whose payload is not an object** | `pytest.raises(BundleError)`, **no message match** | **SURVIVED** |
| the uniqueness guards do not over-trigger on distinct receipts | `len(receipts) == 2` | killed |

The survivor: both guards raise `BundleError`, and a receipt with no object
payload fails the *next* check too — `payload.get("receipt_id")` is then `None`,
which is not a ULID. Replacing the guard with a silent `payload = {}` only
changes which one fires. Measured before the fixture: the message went from
`receipt envelope missing object member 'payload'` to
`receipt payload has invalid receipt_id`, suite green.
Fixture: `test_export_names_the_payload_guard_and_not_the_one_after_it`.

### `tests/test_vl34_issuance_guards_adversarial.py` — 7 properties, 0 survivors

All seven killed: duplicate-kid detection, `_find_key`'s own ambiguity guard
(a **second, independent** implementation of the same idea — neither mutation
kills the other's tests), the rotation active-key guard, non-dict entries
ignored without raising, kid type strictness, replacement installation, and
`verify()`'s own duplicate preflight.

Two of these were **bad mutants first**, and both would have been reported as
survivors by a bench that only checked the file changed. `entry = {}` in place of
`continue` falls through to the same skip — inert. A 4-space anchor matched
inside a 12-space line — broken. Rebuilt, both kill.

One measurement corrects the census: `test_rotation_applies_duplicate_and_zero_active_guards_together`
stays green when the zero-active guard is removed, so of the two guards its name
claims it exercises, it is reaching the *other* one. Both guards are covered
elsewhere, so this is a mis-named test, not a gap.

### `tests/test_vl5_anchor_status_adversarial.py` — 4 properties, 1 survivor

| property | outcome |
|---|---|
| only a registered statement status may drive the freshness anchor | killed (12 red) |
| a non-string status cannot crash the anchor scan | killed |
| `transferred` is in the vocabulary, not only `revoked` | killed |
| **T is the order-independent maximum over genuine statements** | **SURVIVED** |

The survivor is the sharpest finding in the Python tree. The test is *named*
`test_only_authenticated_registered_statement_statuses_determine_t` and its
docstring says "order-independent maximum" — but its view holds one genuine
record and one unregistered decoy, and the decoy is dropped by the status filter
*before* the comparison. Only one timestamp ever reaches the running maximum, so
the branch that chooses between two is never executed. Replacing that comparison
with "the newest record always wins" left the whole suite green before the fixture.
Proven: with two genuine records the original answers `2026-08-01`, the mutated
`2026-07-05`.
Fixture: `test_t_is_the_later_of_two_genuine_statements`.

### `tests/test_authority_adversarial.py` — 21 properties, 2 survivors

Nineteen killed, covering the hybrid AND-rule, hash coverage, manifest
self-consistency, retired signers, the version predicate, ordering, the 4096
ceiling, window inclusivity, the issue permission, the vacuous-artifact
quantifier, duplicate entries, and six successor-discipline guards.

Both survivors are the same shape, and the census predicted both:

- **the `KeyManifest` brand check.** Its test feeds six malformed values and
  asserts `False` for each — which holds with the check removed, because none of
  the six carries a resolvable key anyway. Proven: widening the door admits a
  plain dict the original refuses.
  Fixture: `test_an_unbranded_manifest_dict_is_refused_even_when_it_would_otherwise_verify`.
- **`entry_for_issuer`'s non-string lookup refusal.** Its test passes `None`,
  `[]`, `{}`, `True`, `0`, `""` — every one of which compares unequal to a real
  `issuer_id` regardless, so the type check is invisible to it. Proven: an object
  whose `__eq__` answers `True` resolves an entry once the check is removed.
  Fixture: `test_entry_for_issuer_refuses_a_lookup_key_that_merely_claims_equality`.

### `site/test/` — 12 properties, 1 survivor

Eleven killed across the three suites: quoting, format-character neutralisation,
clipping at three separate caps, the signed-id label, the ULID grammar,
default-deny on unrecognised diagnostics, and own-property warning attribution.

**The survivor is the one to look at.** `diagnostic-rendering-adversarial.test.ts`
contains a case whose own comment says, verbatim, that widening the token shape
"turns this red instead of passing unnoticed". It does not: its fixture is
`this_receipt_is_verified_and_genuine`, entirely `[a-z0-9_]`, so admitting a
space, a dot or an `@` leaves it matching. Measured before the fixture — with
`TOKEN_RE` widened to `[a-z0-9_ .@]` the whole suite stayed green. The characters a
widening admits are exactly the ones that let a token spell a sentence or an
address, and a token renders as **unquoted page prose** rather than a quoted
citation. That is the property the suite exists for.
Fixture: two cases pinning that `this receipt is verified and genuine` and
`email refunds@evil.example` are cited in a `<q>`, not rendered as `code`.

A second result worth recording without calling it a survivor: the vl6 case
`rejects two receipt entries with one name and different physical content`
**stays green** when the container dedup is removed. Its two receipt bodies
canonicalize to the same `receipt_id`, so an unrelated downstream guard is what
fires. The guard is genuinely covered by the manifest and proof cases in the
same file, so the property is not exposed — but that case does not test what it
says it tests.

### `tests/test_hostile_view_content.py` + `tests/test_blind_hostile_evidence_views.py` — 3 properties, 2 survivors

`test_blind_hostile_evidence_views.py` asserts, in ten places, only
`assert verdict is not None`. Both evaluators are typed to return a verdict and
never `None`, so that assertion is true for **every input short of an escaping
exception** — and the properties around it fail by admitting, not by raising.

| property | outcome |
|---|---|
| **an untrusted member above the admission byte ceiling is refused** | **SURVIVED** |
| **admission reserves the nesting a reconstructed view costs** | **SURVIVED** |
| collapsing keys refuse the whole admission unit | killed |

Before the fixture, the byte ceiling could be **deleted outright** and nothing went
red. Proven: an over-ceiling value reads `admitted=False` originally and
`admitted=True` mutated. That left a 10MB bound on attacker-supplied input with no
regression coverage.
Fixture: `test_the_admission_byte_ceiling_actually_refuses_an_oversized_member`.

The nesting headroom is the one the census rated a high-confidence kill and was
wrong about. Setting `VIEW_ARRAY_ELEMENT_NESTING` from 2 to 0 leaves both
`test_*_view_reconstruction_always_canonicalizes` green, in the file that
*asserts canonicalizability*. Proven by sweeping the boundary: at depth 255 the
original refuses admission and the mutated one **admits a value that then cannot
be canonicalized in the reconstructed view** — precisely the state the headroom
exists to prevent, reached while the test that names it passes.
Fixture: `test_admission_reserves_the_nesting_a_reconstructed_view_costs`.

## The other thing in the perimeter: `tools/gates/run_t2_mutants.py` (REMOVED)

This section is history. The runner and its four transcripts were removed when
the four T2 mutants migrated into `spec_t2.json`; the commands below no longer
run, and are kept because the failure mode they record is the point.

This gate could pass without measuring anything: it could exit 0 having run no mutant.
`main()` took its tags from `argv` and filtered the table; a tag matching no
mutant left the results mapping empty, and `all()` of an empty mapping is true —
so the run printed `summary: {}` and **exited 0**, having applied no mutant,
edited no file and run no test. Measured directly before touching it:

```
$ uv run python tools/gates/run_t2_mutants.py t2-typo-that-matches-nothing
summary: {}
EXIT=0
```

Fixed at the time: the selection was validated before any work started, an empty
selection aborted, and the run printed how many mutants it applied out of how many
existed — a count taken from the loop that ran, not derived from the status it was
about to return, so the two could disagree and be seen to. `bench_run_t2_selection.py`
(REMOVED before the runner) checked it without applying a mutant, and was itself
ablated: with the validation removed it reported three failures and exited
non-zero.

Two adjacent facts, measured at the time and left alone as out of scope: that
gate was **not wired into CI** (`run-all.sh` discovers `g-*.sh`, and it was a
`.py`), and its four committed transcripts under `tools/gates/transcripts/` were
**read by nothing** — no code in the tree compared a fresh run against them.

## Next

- Ablate the eight suites listed in `spec_hostile.json`'s `unmeasured` field, in
  this same directory. The field names the suites and holds no anchors or edits, so
  their mutations are still to be written. The `try/catch` impression about
  `verifiers/ts` is the thing to test first.
- The `verdict is not None` assertion shape in `test_blind_hostile_evidence_views.py`
  is unchanged beyond the one fixture. Its ten uses cannot fail for any input
  that does not raise; the five `_Lying*` variants in each parametrize list are
  unfalsifiable by construction.
