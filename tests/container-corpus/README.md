# Container corpus

Archives that make the question "which members does this file hold?" hard, and
the answer the canonical container reader MUST give for each of them. The same
leaves are read by `tests/test_container_corpus.py` and by
`site/test/container-corpus.test.ts`: one bench, two implementations, so a
disagreement between them is a failing test rather than a field report.

Each leaf is a directory holding `archive.zip` and `expected.json`:

    {"caps": {"max_entries": …, "max_member_bytes": …, "max_total_bytes": …},
     "verdict": "accept",
     "members": [{"name": …, "method": 0|8, "size": …, "sha256": …}]}

    {"caps": {…}, "verdict": "reject", "code": "<code>", "member": "<name>|null"}

`codes.json` carries the closed error taxonomy — the code list in the order the
reader checks for it, and the message each code renders. Both implementations
assert their own tables against that file, which is how the three copies stay
one table.

Leaves are named after the field the archive lies about, never after the check
that catches it: a rename of a check must not silently orphan its case.

## Regenerating

    python3 tools/gen_container_corpus.py --out tests/container-corpus
    python3 tools/gen_container_corpus.py --check      # exits 1 on any drift

`--check` regenerates into a temporary directory and compares byte for byte, so
an edit made by hand inside this directory is a failure, not a surprise. The
generator never imports `attest`: a bench derived from the code it judges
shares that code's blind spots, and this corpus exists precisely where those
blind spots were.

## Fuzzing

    python3 tools/gen_container_corpus.py --fuzz 500 --seed 20260902 --out /tmp/f

writes archives only — random models carrying random lies, with no expectation
attached, for `tools/container_differential.py` to feed to both readers and
compare. The enumerated leaves above are a floor and share their author's blind
spots; the fuzzer and the in-language property suites exist because of that.
