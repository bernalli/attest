# The ablation bench for the adversarial suites

---

## The number

```
17 suites censused
 9 suites ablated
52 distinct properties measured
 7 survived their own ablation   -> 0 after the fixtures in 43ae152
```

A property here is a **production guard**, not a test: the census found several
cases where three or four differently-named tests all die to one mutation, and
counting those separately would measure how wide the suite is rather than how
many invariants it holds.

**Why 9 ablated and not 17.** The `verifiers/ts` five (`authority`, `canon-depth-profile`,
`compromise`, `vl3-duplicate-kid`, `vl5-anchor-status`) are censused with exact
anchors and proposed mutations but **not ablated** — declared, not silent. The
census of those five is the largest single finding still unmeasured: nearly every
exported function there wraps its body in `try { } catch { return false }`, so a
mutation that removes a null guard is swallowed and the test stays green *for the
wrong reason*. That is a prediction, and predictions in this work have a poor
record — two of five were wrong when measured. It should be measured, not quoted.

## What each verdict had to survive to be believed

The survivor count is the deliverable, so the count is what had to be defended.
Five readings were refused, each because the opposite one was observed while
building the bench:

| refused reading | what actually happened | how it is now caught |
|---|---|---|
| the mutation happened | an anchor matched **mid-line** and spliced into an indented line; the file stopped parsing and it read as a broken mutant, a fact about the spec dressed as a fact about the code | preflight refuses absent, ambiguous and mid-line anchors; the edit is confirmed by hashing before and after |
| the red is the red that was intended | a `NameError` mutant produced **17 red against a good mutant's 12** — the wrong mutation looked like better coverage | the exception type is recorded; an all-form red is `BROKEN`, never `KILLED` |
| a type-invalid change is inert | vitest strips types, so `const status: number = o['status']` **runs green**; without a typecheck it reads `SURVIVED` | `tsc --noEmit` runs before the suite; proven in both directions — the same mutant reads `SURVIVED` with the gate off and `BROKEN` with it on |
| a restored file is the file imported | `VIEW_ARRAY_ELEMENT_NESTING = 2`, restored and verified byte-identical, **imported as 0** | caches dropped on apply and restore; runs write none |
| a survivor is real | two mutants landed and changed nothing; an inert mutation is indistinguishable from an uncovered property | every survivor carries an input on which mutated and original disagree; the prover refuses a probe that fails on the unmutated tree |

The fourth is the one worth carrying elsewhere. Bytecode is invalidated by source
**mtime and size**, so a constant replaced by one of the *same length* — `2` for
`0`, `4096` for `4097` — can leave a cache the interpreter still trusts after the
restore. `tools/gates/run_t2_mutants.py` already guards this (`.touch()` plus a
cache sweep, with a comment naming it); this bench did not, and paid for it. The
symptom was a fixture failing on a clean tree for a reason that could not be read
off the source.

## Per suite

Outcome column: `killed` = the guard's removal turns the suite red from the right
assertion. `SURVIVED` = it stayed green, and the fixture that closes it is named.

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
changes which one fires. Measured: message goes from
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
with "the newest record always wins" leaves the whole suite green.
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
space, a dot or an `@` leaves it matching. Measured — with `TOKEN_RE` widened to
`[a-z0-9_ .@]` the whole suite stays green. The characters a widening admits are
exactly the ones that let a token spell a sentence or an address, and a token
renders as **unquoted page prose** rather than a quoted citation. That is the
property the suite exists for.
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

The byte ceiling can be **deleted outright** and nothing goes red. Proven: an
over-ceiling value reads `admitted=False` originally and `admitted=True` mutated.
That is a 10MB bound on attacker-supplied input with no regression coverage.
Fixture: `test_the_admission_byte_ceiling_actually_refuses_an_oversized_member`.

The nesting headroom is the one the census rated a high-confidence kill and was
wrong about. Setting `VIEW_ARRAY_ELEMENT_NESTING` from 2 to 0 leaves both
`test_*_view_reconstruction_always_canonicalizes` green, in the file that
*asserts canonicalizability*. Proven by sweeping the boundary: at depth 255 the
original refuses admission and the mutated one **admits a value that then cannot
be canonicalized in the reconstructed view** — precisely the state the headroom
exists to prevent, reached while the test that names it passes.
Fixture: `test_admission_reserves_the_nesting_a_reconstructed_view_costs`.

## The other thing in the perimeter: `tools/gates/run_t2_mutants.py`

The mandate names this gate, and it had the failure mode the mandate warns about.
`main()` took its tags from `argv` and filtered the table; a tag matching no
mutant left the results mapping empty, and `all()` of an empty mapping is true —
so the run printed `summary: {}` and **exited 0**, having applied no mutant,
edited no file and run no test. Measured directly before touching it:

```
$ uv run python tools/gates/run_t2_mutants.py t2-typo-that-matches-nothing
summary: {}
EXIT=0
```

Fixed: the selection is validated before any work starts, an empty
selection aborts, and the run prints how many mutants it applied out of how many
exist — a count taken from the loop that ran, not derived from the status it is
about to return, so the two can disagree and be seen to. `bench_run_t2_selection.py`
checks it without applying a mutant, and was itself ablated: with the validation
removed it reports three failures and exits non-zero.

Two adjacent facts, measured and left alone as out of scope: this gate is **not
wired into CI** (`run-all.sh` discovers `g-*.sh`, and this is a `.py`), and the
four committed transcripts under `tools/gates/transcripts/` are **read by
nothing** — no code in the tree compares a fresh run against them.

## Next

- Ablate the five `verifiers/ts` suites. Their exact anchors and proposed
  mutations are censused in `spec_hostile.json`'s `unmeasured` field, in this
  same directory. The `try/catch` prediction is the thing to test first.
- The `verdict is not None` assertion shape in `test_blind_hostile_evidence_views.py`
  is unchanged beyond the one fixture. Its ten uses cannot fail for any input
  that does not raise; the five `_Lying*` variants in each parametrize list are
  unfalsifiable by construction.
- `run_t2_mutants.py` is still outside CI, and its transcripts are still compared
  against nothing.
