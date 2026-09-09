# OL-13: executed importer census — author validation

Base: `2d295ae`. Worktree: `wt-ol13/.codex-wt/3033201`; branch: `fix/ol13-importer-census`.

This is execution evidence from the implementation slot, not an independent review or merge approval. The first mandate and the second-round approvals govern this change. The study was read in full after checking SHA-256 `07e2cb2d8163337c5263badfb6eb5ad11bf63346b8ec7bb80a595819e6a5340a`.

## Contract and changed files

- `tools/importer_differential.py`: compares completed executions against a separate committed census. Differential cases enter the ledger after the reference and both browser answers; pair cases enter after both reference-importer calls. The report keeps archives and archive pairs separate. It derives its marker from execution identities, independently of divergence status.
- `tools/importer-census.json`: pins every deterministic and pair identity; mutation identities expand the pinned seed/count recipe. The default expectation is never filtered through the live registry. The initial candidate was generated from the current generators, then verified and rewritten by a complete successful `--update-census` run before committing.
- `.github/workflows/ci.yml`: exactly one additional run step, `uv run --frozen python tools/importer_differential.py --selftest`. The existing bare command remains the enforcement point. No gate file was modified.
- `tools/verify-all.sh`: mirrors the new CI selftest command in the existing local CI orchestrator; its executable workflow-parity tests require the same command at the same job. Enforcement remains in the importer tool, and no `tools/gates/` file changes.
- `tools/prove_importer_census.py`: reproducible isolated process mutations and one-at-a-time selftest guard removal. It calls the real tool and real importers; update probes write only a temporary census copy. It neither edits production sources nor other worktrees.
- `tests/tools/test_importer_prerequisites.py`: distinguishes absent prerequisites from a present but failing bundler.
- `tests/tools/test_importer_census.py`: identity loss and rename properties, schema rejection, update scope and preservation, completed pair accounting, unfinished-run refusal, independent default expectations, workflow wiring and selftest sensitivity.
- This report records the actual probes and suite results. The prerequisite change has its own commit, `677fbd6`.

Updates require a full default invocation and compare the completed run with the existing file. New families and leaves may be admitted. A missing family or vector, including a rename, is refused; an intentional removal requires an explicit edit of the versioned expectation. Missing census files cannot be bootstrapped through `--update-census`. Divergences also prevent writing. Serialization is replaced atomically after validation.

A removed leaf leaves its family present and nonempty, so presence checks cannot catch it. Removing a registry entry drops the declared and observed sets together, so their agreement is circular. These distinct reasons are documented in `compare_census()`.

Explicit `--families`, `--count`, and `--seed` runs are labelled with their selected scope. They do not claim full default coverage. Empty execution fails. Default constants drifting in code do not silently adapt the committed mutation expectation; only explicit CLI parameters select an alternate recipe invocation.

Exit contract: **0** agreement and matching census (or validated additive update); **1** divergence or failed adapter/bundler measurement; **3** census mismatch/schema failure or refused update scope; **78** absent prerequisite. Invalid CLI arguments use argparse status **2**. Census mismatch takes precedence over divergence; both diagnostics remain visible.

## End-to-end property mutants

Every command below runs in a fresh process in this worktree. Mutations preserve the corpus schema and leave the importers executable. Each default mutant produces exactly two `CENSUS:` diagnostics, no `CENSUS SCHEMA` error, zero importer divergences and exit 3. The report excerpts below are copied from the actual command output. Full local transcripts are in `/tmp/ol13-evidence/`.

### leaf: PROPERTY, not schema

Remove only `version-past-integer-boundary`; the family still executes 13 archives.

```sh
.venv/bin/python tools/prove_importer_census.py --mutant leaf
```

```text
CENSUS: out-of-range: 13 archives, the census records 14; missing: version-past-integer-boundary
CENSUS: total archives: run 461, census 462
461 archives fed to both importers at their own defaults
0 divergences across 0 families
461 archives across 18 families completed
1 archive pairs across 1 families completed
462 cases across 19 families (case count; archives and archive pairs are distinct units)
census (full default invocation): DIFFERS
census bytes changed: False
tool exit: 3
```

### registry: PROPERTY, not schema

Delete `out-of-range` from the live registry and reconstruct `ALL_FAMILIES` from it. The circular declared/observed comparison remains True.

```sh
.venv/bin/python tools/prove_importer_census.py --mutant registry
```

```text
circular archive-family comparison: True
CENSUS: out-of-range: the census expects 14 archives; the run completed none
CENSUS: total archives: run 448, census 462
448 archives fed to both importers at their own defaults
0 divergences across 0 families
448 archives across 17 families completed
1 archive pairs across 1 families completed
449 cases across 18 families (case count; archives and archive pairs are distinct units)
census (full default invocation): DIFFERS
census bytes changed: False
tool exit: 3
```

### family-rename: PROPERTY, not schema

Rename both the registry key and generated vector family to `out-of-range-renamed`, retaining all 14 vector identities and archive counts.

```sh
.venv/bin/python tools/prove_importer_census.py --mutant family-rename
```

```text
CENSUS: out-of-range: the census expects 14 archives; the run completed none
CENSUS: out-of-range-renamed: unregistered family (14 archives)
462 archives fed to both importers at their own defaults
0 divergences across 0 families
462 archives across 18 families completed
1 archive pairs across 1 families completed
463 cases across 19 families (case count; archives and archive pairs are distinct units)
census (full default invocation): DIFFERS
census bytes changed: False
tool exit: 3
```

### pair-empty: PROPERTY, not schema

Make `pair_vectors()` return an empty list; differential archives remain unchanged.

```sh
.venv/bin/python tools/prove_importer_census.py --mutant pair-empty
```

```text
CENSUS: pair-floor: the census expects 1 archive pairs; the run completed none
CENSUS: total archive pairs: run 0, census 1
462 archives fed to both importers at their own defaults
0 divergences across 0 families
462 archives across 18 families completed
0 archive pairs across 0 families completed
462 cases across 18 families (case count; archives and archive pairs are distinct units)
census (full default invocation): DIFFERS
census bytes changed: False
tool exit: 3
```

## Update refusal and additive positive control

The same four property mutants were also executed with `--update-census`:

```sh
.venv/bin/python tools/prove_importer_census.py --mutant leaf --update-census
.venv/bin/python tools/prove_importer_census.py --mutant registry --update-census
.venv/bin/python tools/prove_importer_census.py --mutant family-rename --update-census
.venv/bin/python tools/prove_importer_census.py --mutant pair-empty --update-census
```

| Mutant | Tool exit | Census bytes changed |
|---|---:|---|
| leaf | 3 | False |
| registry | 3 | False |
| family-rename | 3 | False |
| pair-empty | 3 | False |

Each named the missing expectation and printed `refusing to update the census: expected cases are absent or invalid`. The rename update reports only the lost original family: additions are admissible during update, but cannot compensate for a missing expected identity.

The additive control introduces one new leaf in `baseline` and one new family, both carrying a real sound bundle:

```sh
.venv/bin/python tools/prove_importer_census.py --mutant additions --update-census
```

```text
464 archives across 19 families completed
1 archive pairs across 1 families completed
465 cases across 20 families (case count; archives and archive pairs are distinct units)
census (full default invocation): MATCHES
census updated from the completed run
census bytes changed: True
tool exit: 0
```

## Marker independent of exit status

The divergence probe executes the real baseline import, then substitutes one reference outcome with `malformed`. The two browser comparisons disagree on that single archive; execution identities stay intact. This is an outcome-property injection, not a malformed adapter protocol.

```sh
.venv/bin/python tools/prove_importer_census.py --mutant divergence
```

```text
DIVERGENCE baseline/sound-bundle on outcome
DIVERGENCE baseline/sound-bundle on outcome
462 archives fed to both importers at their own defaults
2 divergences across 1 families
462 archives across 18 families completed
1 archive pairs across 1 families completed
463 cases across 19 families (case count; archives and archive pairs are distinct units)
census (full default invocation): MATCHES
tool exit: 1
```

The healthy run has the same execution marker and census MATCHES with exit 0. The same divergence probe with `--update-census` returns 1 and `census bytes changed: False`; it prints `refusing to update the census: importer measurement failed`.

## Selftest sensitivity

The unmodified `--selftest` reports **19/19**. The predecessor was re-executed and reports **6/6** (five negative cases plus its healthy input). Every guard removal below compiles the real production function with exactly one predicate disabled; the selftest code is unchanged. All probes returned **1**, with a named failed case and a reduced count. Other remaining diagnostics cannot mask the loss because each case requires its specific diagnostic.

Reproduce one guard at a time:

```sh
.venv/bin/python tools/prove_importer_census.py --disable <guard>
```

| Disabled guard | Measured selftest |
|---|---:|
| `derived-totals` | 18/19 |
| `missing-family` | 16/19 |
| `missing-leaf` | 16/19 |
| `nonempty-family` | 18/19 |
| `nonempty-run` | 18/19 |
| `registered-family` | 18/19 |
| `registered-leaf` | 18/19 |
| `same-unit` | 18/19 |
| `unique-identity` | 18/19 |
| `update-admits-additions` | 18/19 |
| `update-default-count` | 18/19 |
| `update-default-seed` | 18/19 |
| `update-full-selection` | 18/19 |
| `update-healthy-scope` | 18/19 |
| `update-preserves-expectation` | 17/19 |

These 15 sensitivity probes also run as parametrized pytest cases. Schema tests are reported separately: changing a JSON count type, unit, recipe, totals or shape proves admission only, and is not counted as end-to-end property evidence.

## Positive gate and segmented suite

Environment prepared in this worktree only:

```sh
UV_CACHE_DIR=/tmp/ol13-uv-cache uv sync --all-packages --all-extras
npm ci --prefix verifiers/ts --cache /tmp/ol13-npm-cache --no-audit --no-fund
npm run build --prefix verifiers/ts
npm ci --prefix site --cache /tmp/ol13-npm-cache --no-audit --no-fund
```

The bare CI command and the existing local gate were both executed successfully:

```sh
uv run --frozen python tools/importer_differential.py
bash tools/gates/g-ci-py.sh
```

```text
462 archives fed to both importers at their own defaults
462 archives across 18 families completed
1 archive pairs across 1 families completed
463 cases across 19 families (case count; archives and archive pairs are distinct units)
census (full default invocation): MATCHES
GATE G-CI-PY PASS property=gen_container_corpus, both demo scripts, conformance_runner (TS, v0.2) and importer_differential all run, every road answered for every archive, and the leaf/archive counts are > 0
```

Both commands returned **0**. `pair-floor` alone and no selected families now have different output and different exit status:

| Command suffix | Executed archive pairs | Census | Exit |
|---|---:|---|---:|
| `--families pair-floor` | 1 | MATCHES, selected invocation | 0 |
| `--families ''` | 0 | DIFFERS: the run completed no cases | 3 |

Missing-precondition control, on the final implementation:

```sh
PATH='' .venv/bin/python tools/importer_differential.py
```

```text
PRECONDITION ABSENT: missing node on PATH
exit: 78
```

The original absent-esbuild check also returned 78. Both lack an execution marker. The completed divergence control above returns 1 with the full marker present, separating inability to measure from a failed measurement.

### Foreground suite completeness

All four segments ran sequentially as blocking subprocesses, never two at once, with `ATTEST_CI_REQUIRED=1`, local Node dependencies and the rebuilt verifier. Each completed before the next started. Commands (expanded pathspecs recorded from the actual invocations):

```sh
.venv/bin/python -m pytest --collect-only -q
.venv/bin/python -m pytest -q -ra --junitxml=/tmp/ol13-evidence/ah.xml tests/test_anchor.py tests/test_anchor_seeded.py tests/test_assert_artifacts.py tests/test_authority.py tests/test_authority_adversarial.py tests/test_blind_audit_chain_admission.py tests/test_blind_canon_admission.py tests/test_blind_evidence_sinks.py tests/test_blind_hostile_evidence_views.py tests/test_blind_revocation_admission.py tests/test_bundle.py tests/test_buyer_surface.py tests/test_canon.py tests/test_canon_depth_profile_adversarial.py tests/test_check_spec_docs.py tests/test_ci_required.py tests/test_cli.py tests/test_cli_authority.py tests/test_cli_authority_blind.py tests/test_cli_binding_properties.py tests/test_cli_grant.py tests/test_cli_issue_log_dir.py tests/test_cli_overwrite.py tests/test_cli_revoke_properties.py tests/test_cli_views_builder_properties.py tests/test_cli_views_properties.py tests/test_commitment.py tests/test_compromise_adversarial.py tests/test_compromise_retraction_provenance.py tests/test_container.py tests/test_container_corpus.py tests/test_container_differential_smoke.py tests/test_dates.py tests/test_deflate.py tests/test_demo_e2e.py tests/test_demo_pledge_e2e.py tests/test_evaluate_authority.py tests/test_evaluate_authority_blind.py tests/test_evaluate_grant.py tests/test_gen_container_corpus.py tests/test_gen_site_sample.py tests/test_gen_vectors.py tests/test_gen_vectors_helpers.py tests/test_grant.py tests/test_hostile_view_content.py
.venv/bin/python -m pytest -q -ra --junitxml=/tmp/ol13-evidence/iz.xml tests/test_issue.py tests/test_issue_hybrid.py tests/test_keys.py tests/test_lexicon_guard.py tests/test_manifest_mutation_properties.py tests/test_manifests.py tests/test_manifests_hybrid.py tests/test_nonstring_kid_resolution.py tests/test_offer_projection_order_independence.py tests/test_ots.py tests/test_ots_convert.py tests/test_ots_corpus_parity.py tests/test_pq.py tests/test_release_workflow_steps.py tests/test_review_fixes_2026_07.py tests/test_review_shouldfix_2026_07.py tests/test_revocation.py tests/test_revocation_view_bound.py tests/test_schema.py tests/test_sdist_build.py tests/test_shared_predicate_artifact_mutations.py tests/test_shared_predicate_ownership.py tests/test_shared_predicate_ownership_mutations.py tests/test_shared_predicate_parity.py tests/test_sibling_hybrid_sidedocs.py tests/test_smoke.py tests/test_tlog.py tests/test_transfer.py tests/test_transparency.py tests/test_trust_material_messages.py tests/test_trust_material_parse.py tests/test_trust_store_boundary.py tests/test_trusted_manifest_gate.py tests/test_vectors.py tests/test_verify.py tests/test_verify_all.py tests/test_verify_all_runtime.py tests/test_verify_compromise.py tests/test_verify_hybrid.py tests/test_verify_transfer.py tests/test_version_parity.py tests/test_views.py tests/test_views_properties.py tests/test_vl2_bundle_duplicate_members_adversarial.py tests/test_vl34_issuance_guards_adversarial.py tests/test_vl5_anchor_status_adversarial.py tests/test_witness.py tests/test_witness_cosignature.py tests/test_witness_quorum.py
.venv/bin/python -m pytest -q -ra --junitxml=/tmp/ol13-evidence/sub.xml tests/tools
.venv/bin/python -m pytest -q -ra --junitxml=/tmp/ol13-evidence/bw.xml bridge/tests witness/tests
```

| Segment | Cases | Passed | Skipped | Xfail | Exit |
|---|---:|---:|---:|---:|---:|
| ah | 2744 | 2743 | 0 | 1 | 0 |
| iz | 2899 | 2849 | 50 | 0 | 0 |
| sub | 231 | 231 | 0 | 0 | 0 |
| bw | 1249 | 1244 | 5 | 0 | 0 |

**7123 segment cases = 7123 collected**, with no overlap between segment case identities. Totals: **7067 passed, 55 skipped, 1 xfailed; zero failures or errors**.

The initial collection was 7,075. The increase of 48 is accounted for by 45 new OL-13 pytest cases (4 prerequisite cases and 41 census/sensitivity cases) plus 3 cases dynamically derived by the existing workflow-parity tests from the new CI step. Parameter IDs containing generated UUIDs change between collections; they do not change their file counts.

Skipped cases are explicit existing exclusions: 50 provisioning checks in `test_verify_all.py` and 5 bridge documentation checks for pages without a check-config summary. The xfail is the existing chameleon-refund revocation case in `test_blind_revocation_admission.py`. No missing browser prerequisite was excused by a skip.

Other verification: repository-wide `ruff check .` and `ruff format --check .` passed; `mypy --strict src bridge/src witness/src` passed on 54 source files; `bash -n tools/verify-all.sh` and `git diff --check` passed. `tools/check_spec_docs.py` passed.

An additional standalone `mypy --strict tools/importer_differential.py` check reports three argument-type diagnostics in the imported `tools/gen_container_corpus.py:1608`, and none in the changed importer tool. That file is byte-identical to base `2d295ae`; these existing diagnostics were left outside this change. This optional check is distinct from the passing CI mypy invocation above.

### Artifact digests

```text
f95debf98b83212ef9bcd74f40d66abc4e5de9e627a9f4d9c6bc40f0de15da69  tools/importer_differential.py
b7c8ddc1207bc4c0eec9b7cfa4ca19b27a21303d66c09ca675cc290a12c48ff4  tools/importer-census.json
ae96648421c44a4c04cbbe918c7b9fb7f700ab0e59b22d69c86ef6fb492d43d2  tools/prove_importer_census.py
```

## Premises and limits

The approved corrections are reflected explicitly: 462 differential archives on 18 families plus one pair case; the committed expectation controls update refusal; the predecessor selftest is 6/6. No further false premise requiring a design change was found.

The generated corpus has no independent filesystem census. The versioned file pins execution identities, not the content bytes or correctness of the generators. Pair-floor remains a scaled reference-importer property, not a browser differential. These are the existing measurement boundaries, stated in the tool output.

`tools/sdist_files.py` selects tracked files while excluding bridge/witness sources; the new census travels with the tracked tools without a packaging change. The library wheel still contains `src/attest` only.
