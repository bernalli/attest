"""Property coverage for the four producers A11 T4 adds to the CLI.

The example-based tests in `test_cli.py` pin the cases a human thought of: the
six corpus documents, the two corpus views, the incident chain end to end.
These pin the PROPERTIES those commands owe on input nobody enumerated.

Two invariants, one per family, and neither admits a third outcome:

- `attest log entry` either refuses with exit 2, writing no file and printing a
  clean `error:` line, or exits 0 with an entry that `tlog.encode_entry` and
  `attest log append` both accept. An entry a log would reject is worse than no
  entry: it is a file whose only use is to be refused, discovered later.
- The three view producers either refuse with exit 2 and write nothing, or
  write a view the builder re-accepts and rebuilds to the SAME canonical bytes.
  Idempotence is the honest test of a producer: a view that changes when it is
  rebuilt is a view whose readers and writer disagree.

No traceback ever reaches the operator, whatever the input was.

Boundaries are checked on BOTH sides throughout, because a ceiling tested only
from above never proves the value below it is admitted — and a producer that
refuses everything would pass a one-sided test of every rule it has.

`capsys` cannot be used here: it is function-scoped and Hypothesis refuses the
combination outright. `capturing()` from `test_cli_revoke_properties` redirects
the streams inside the call instead, which also keeps every example isolated.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from attest import canon, cli, revocation, tlog, transfer, validate, views
from tests.strategies.malformed_manifests import malformed_manifests
from tests.test_cli import (
    ENTRY_CASES,
    ENTRY_TYPES,
    LEAF_15,
    LEAF_35A,
    LEAF_41A,
    _corpus_head,
)
from tests.test_cli_revoke_properties import Captured, capturing

# Mirrors `test_cli_revoke_properties`: enough examples to explore the mutation
# space, deterministic so a failure reproduces from the id alone, and no
# per-example deadline (several examples verify signatures).
PROPERTY_SETTINGS = settings(max_examples=24, deadline=None, derandomize=True)

# Values that are legal JSON and wrong for every member that carries meaning.
# `2**53` is deliberately at the edge of the attest-JCS integer profile, and
# the two dict/list values reach the containers a scalar reader does not expect.
WRONG_TYPES: tuple[Any, ...] = (None, True, 0, -1, 2**53, "", "x", [], {}, [{}], {"k": "v"})

# Member names an attacker adds: one plain, one colliding with a member the
# ENTRY carries, one prototype-shaped, one numeric-looking, one differing from
# a real member only by case.
UNKNOWN_MEMBERS: tuple[str, ...] = ("extra", "type", "__proto__", "0", "Issuer")


# --- shared plumbing ---------------------------------------------------------


class Env:
    """A fresh directory per generated example.

    Module-scoped: the corpus documents these tests mutate are read once, and
    no property below depends on fresh key material.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.counter = 0

    def scratch(self) -> Path:
        self.counter += 1
        path = self.root / f"case-{self.counter:05d}"
        path.mkdir(parents=True, exist_ok=True)
        return path


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Env:
    return Env(tmp_path_factory.mktemp("views-builder-properties"))


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run(argv: list[str]) -> tuple[int, Captured]:
    with capturing() as sink:
        try:
            rc = cli.main(argv)
        except SystemExit as exc:  # argparse refusals surface this way
            rc = int(exc.code or 0)
    return rc, sink[0]


def _corpus(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


CLAIM_41A: dict[str, Any] = _corpus(LEAF_41A / "compromise-view.json")[0]
CLAIM_35A: dict[str, Any] = _corpus(LEAF_35A / "transfer-view.json")[0]
RECORD_15: dict[str, Any] = _corpus(LEAF_15 / "revocation.json")


# --- generic document mutators ----------------------------------------------
#
# `tests/strategies/malformed_manifests.py` covers a key manifest, which is one
# of the six documents these verbs read. The other five — an envelope, three
# record shapes and an evidence bundle — have no strategy module of their own,
# so the classes are spelled generically here: remove a member, add one,
# retype one, cut a string short. Each class is a separate strategy so a caller
# composes exactly the ones it wants, which is the same discipline the manifest
# module states.


def _string_paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """Every path in `value` that lands on a non-empty string."""
    found: list[tuple[Any, ...]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.extend(_string_paths(child, (*prefix, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_string_paths(child, (*prefix, index)))
    elif isinstance(value, str) and value:
        found.append(prefix)
    return found


def _at(value: Any, path: tuple[Any, ...]) -> Any:
    for step in path:
        value = value[step]
    return value


@st.composite
def missing_member(draw: st.DrawFn, document: dict[str, Any]) -> dict[str, Any]:
    """One top-level member removed, one at a time."""
    mutated = copy.deepcopy(document)
    del mutated[draw(st.sampled_from(sorted(mutated)))]
    return mutated


@st.composite
def extra_member(draw: st.DrawFn, document: dict[str, Any]) -> dict[str, Any]:
    """An unknown top-level member appears."""
    mutated = copy.deepcopy(document)
    mutated[draw(st.sampled_from(UNKNOWN_MEMBERS))] = draw(st.sampled_from(WRONG_TYPES))
    return mutated


@st.composite
def retyped_member(draw: st.DrawFn, document: dict[str, Any]) -> dict[str, Any]:
    """One top-level member carries the wrong JSON type."""
    mutated = copy.deepcopy(document)
    mutated[draw(st.sampled_from(sorted(mutated)))] = draw(st.sampled_from(WRONG_TYPES))
    return mutated


@st.composite
def truncated_string(draw: st.DrawFn, document: dict[str, Any]) -> dict[str, Any]:
    """A string ends before it should, at any depth.

    Reaches a base64url signature that no longer decodes to its fixed length, a
    hex digest one character short, and a timestamp missing its `Z` — all with
    the same class.
    """
    mutated = copy.deepcopy(document)
    paths = _string_paths(mutated)
    assume(paths)
    path = draw(st.sampled_from(paths))
    original = _at(mutated, path)
    cut = draw(st.integers(min_value=0, max_value=len(original) - 1))
    _at(mutated, path[:-1])[path[-1]] = original[:cut]
    return mutated


def malformed_documents(document: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    return st.one_of(
        missing_member(document),
        extra_member(document),
        retyped_member(document),
        truncated_string(document),
    )


# --- raw-byte mutators (what a parsed dict cannot express) -------------------


def _objects_in(value: Any) -> list[dict[str, Any]]:
    """Every non-empty object in `value`, at any depth."""
    found: list[dict[str, Any]] = []
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node:
                found.append(node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return found


def _dumps_with_duplicate(value: Any, target: dict[str, Any], key: str, replacement: Any) -> str:
    """`json.dumps`, except `target` emits `key` a second time.

    A duplicate member cannot exist in a parsed dict, so the only way to test
    that every input reads through `canon.loads_strict` (D11) is to build the
    bytes directly. The second value differs from the first, so a parser that
    kept either copy would produce a different document — which is exactly the
    ambiguity a strict reader exists to refuse rather than resolve by position.
    """
    if isinstance(value, dict):
        parts = [
            f"{json.dumps(k)}:{_dumps_with_duplicate(v, target, key, replacement)}"
            for k, v in value.items()
        ]
        if value is target:
            parts.append(f"{json.dumps(key)}:{json.dumps(replacement)}")
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        return (
            "["
            + ",".join(_dumps_with_duplicate(item, target, key, replacement) for item in value)
            + "]"
        )
    return json.dumps(value)


@st.composite
def duplicated_key_text(draw: st.DrawFn, document: Any) -> str:
    """The document's JSON text, with one member duplicated at any depth."""
    objects = _objects_in(document)
    assume(objects)
    target = objects[draw(st.integers(min_value=0, max_value=len(objects) - 1))]
    key = draw(st.sampled_from(sorted(target)))
    return _dumps_with_duplicate(document, target, key, draw(st.sampled_from(WRONG_TYPES)))


def _nested_object(depth: int) -> Any:
    """An object nested exactly `depth` levels deep."""
    node: Any = {}
    for _ in range(depth - 1):
        node = {"a": node}
    return node


# --- T4.0-bis: the six `log entry` validators -------------------------------


def _log_entry(case: Path, entry_type: str, document_text: str) -> tuple[int, Path, Captured]:
    document = _write_text(case / "document.json", document_text)
    out = case / "entry.json"
    rc, captured = _run(
        ["log", "entry", "--type", entry_type, "--in", str(document), "--out", str(out)]
    )
    return rc, out, captured


def assert_entry_outcome(case: Path, rc: int, out: Path, captured: Captured, kind: str) -> None:
    """Refused with nothing written, or an entry the LOG itself accepts.

    The second half is checked by running the real consumer, not by re-reading
    the schema: `log append` is what an operator does next, and an entry it
    refuses is the failure this whole verb exists to prevent.
    """
    assert "Traceback" not in captured.err
    if rc == cli.EXIT_USAGE_ERROR:
        assert "error:" in captured.err
        assert not out.exists()
        return
    assert rc == cli.EXIT_OK
    entry = json.loads(out.read_text(encoding="utf-8"))
    assert entry["type"] == kind
    tlog.encode_entry(entry)
    log_dir = case / "log"
    assert (
        _run(["log", "init", "--dir", str(log_dir), "--origin", "attest-props.example/log"])[0]
        == cli.EXIT_OK
    )
    assert (
        _run(["log", "append", "--dir", str(log_dir), "--entry-json", str(out)])[0] == cli.EXIT_OK
    )


@pytest.mark.parametrize("entry_type", ENTRY_TYPES)
def test_a_mutated_document_never_yields_an_entry_the_log_refuses(
    env: Env, entry_type: str
) -> None:
    """Members missing, added, retyped or cut short: every one of them either
    stops the verb or produces an entry the log stores. This is the property
    the six per-type validators exist to hold, and the one a closed list of
    hand-picked rejections cannot establish."""

    @PROPERTY_SETTINGS
    @given(document=malformed_documents(ENTRY_CASES[entry_type][0]))
    def check(document: dict[str, Any]) -> None:
        case = env.scratch()
        rc, out, captured = _log_entry(case, entry_type, json.dumps(document))
        assert_entry_outcome(case, rc, out, captured, entry_type)

    check()


def test_a_mutated_key_manifest_never_yields_an_entry_the_log_refuses(env: Env) -> None:
    """The same property under the manifest-specific strategies, which reach
    malformations a generic top-level mutator cannot: a duplicate kid, a
    non-integer `manifest_version`, an unknown member inside a key entry."""

    @PROPERTY_SETTINGS
    @given(manifest=malformed_manifests(ENTRY_CASES["key-manifest"][0]))
    def check(manifest: dict[str, Any]) -> None:
        case = env.scratch()
        rc, out, captured = _log_entry(case, "key-manifest", json.dumps(manifest))
        assert_entry_outcome(case, rc, out, captured, "key-manifest")

    check()


@pytest.mark.parametrize("entry_type", ENTRY_TYPES)
def test_a_duplicate_member_is_always_refused_by_log_entry(env: Env, entry_type: str) -> None:
    """D11 on every one of the six types: a document whose meaning depends on
    which duplicate a parser happened to keep is refused, never resolved by
    position."""

    @PROPERTY_SETTINGS
    @given(text=duplicated_key_text(ENTRY_CASES[entry_type][0]))
    def check(text: str) -> None:
        case = env.scratch()
        rc, out, captured = _log_entry(case, entry_type, text)
        assert rc == cli.EXIT_USAGE_ERROR
        assert not out.exists()
        assert "duplicate" in captured.err.lower()
        assert "Traceback" not in captured.err

    check()


@pytest.mark.parametrize("entry_type", ENTRY_TYPES)
def test_a_truncated_file_is_always_refused_by_log_entry(env: Env, entry_type: str) -> None:
    """Truncation at every offset, not just at a plausible one."""
    text = json.dumps(ENTRY_CASES[entry_type][0])

    @PROPERTY_SETTINGS
    @given(cut=st.integers(min_value=0, max_value=len(text) - 1))
    def check(cut: int) -> None:
        case = env.scratch()
        rc, out, captured = _log_entry(case, entry_type, text[:cut])
        assert rc == cli.EXIT_USAGE_ERROR
        assert not out.exists()
        assert "Traceback" not in captured.err

    check()


@pytest.mark.parametrize("entry_type", ENTRY_TYPES)
def test_log_entry_admits_the_depth_ceiling_and_refuses_one_level_more(
    env: Env, entry_type: str
) -> None:
    """Both sides of `canon.MAX_DEPTH`. At the ceiling the document is read and
    refused for its SHAPE; one level deeper it never reaches a shape check at
    all, and the refusal says so. A one-sided test would pass against a reader
    that refused every depth."""
    at_limit = _log_entry(env.scratch(), entry_type, json.dumps(_nested_object(canon.MAX_DEPTH)))
    over_limit = _log_entry(
        env.scratch(), entry_type, json.dumps(_nested_object(canon.MAX_DEPTH + 1))
    )

    assert at_limit[0] == cli.EXIT_USAGE_ERROR
    assert "nesting depth" not in at_limit[2].err
    assert over_limit[0] == cli.EXIT_USAGE_ERROR
    assert "nesting depth" in over_limit[2].err
    assert not at_limit[1].exists()
    assert not over_limit[1].exists()


@pytest.mark.parametrize("entry_type", ENTRY_TYPES)
def test_log_entry_admits_a_document_at_the_byte_ceiling_and_refuses_one_more(
    env: Env, entry_type: str
) -> None:
    """Both sides of the input ceiling, which is not the same number for every
    type: a `receipt` names an envelope and is bounded by the envelope's own
    limit, because an envelope above it is one no conforming verifier parses.
    The document is padded with trailing whitespace, so at the ceiling it is
    still the valid document and must still produce its entry."""
    document, expected = ENTRY_CASES[entry_type]
    ceiling = (
        validate.MAX_ENVELOPE_BYTES
        if entry_type == "receipt"
        else cli._MAX_STAGE2_INPUT_BYTES["json"]
    )
    text = json.dumps(document)
    padded = text + " " * (ceiling - len(text))

    at_limit = _log_entry(env.scratch(), entry_type, padded)
    over_limit = _log_entry(env.scratch(), entry_type, padded + " ")

    assert at_limit[0] == cli.EXIT_OK
    assert json.loads(at_limit[1].read_text(encoding="utf-8")) == expected
    assert over_limit[0] == cli.EXIT_USAGE_ERROR
    assert "--in input exceeds" in over_limit[2].err
    assert not over_limit[1].exists()


def test_log_entry_writes_nothing_when_the_document_is_rejected(env: Env) -> None:
    """Ordering, stated as a property rather than assumed: validation happens
    before the output is opened, so a pre-existing `--out` is left byte-identical
    by a refused run."""
    case = env.scratch()
    out = case / "entry.json"
    out.write_text("sentinel", encoding="utf-8")
    document = _write_text(case / "document.json", json.dumps({"not": "a record"}))

    rc, captured = _run(
        [
            "log",
            "entry",
            "--type",
            "revocation-record",
            "--in",
            str(document),
            "--out",
            str(out),
        ]
    )

    assert rc == cli.EXIT_USAGE_ERROR
    assert "Traceback" not in captured.err
    assert out.read_text(encoding="utf-8") == "sentinel"


def test_the_transfer_record_shape_agrees_with_the_transfer_module(env: Env) -> None:
    """`_transfer_record_log_entry` composes the SHAPE half of
    `transfer.verify_record_signature`, whose other half needs a key manifest a
    producer holding only a record does not have. The two must not drift, so
    the property is checked directly: for a mutated record, the verb accepts it
    exactly when the module's own shape predicates all hold."""

    @PROPERTY_SETTINGS
    @given(record=malformed_documents(CLAIM_35A["record"]))
    def check(record: dict[str, Any]) -> None:
        shape_ok = (
            set(record) == transfer._TRANSFER_RECORD_MEMBERS
            and isinstance(record["receipt_id"], str)
            and transfer._RECEIPT_ID_RE.fullmatch(record["receipt_id"]) is not None
            and isinstance(record["new_receipt_id"], str)
            and transfer._RECEIPT_ID_RE.fullmatch(record["new_receipt_id"]) is not None
            and transfer._strict_b64u_decode(record["new_holder_pubkey"], 32) is not None
            and transfer._valid_utc_timestamp(record["transferred_at"])
            and transfer._valid_holder_authorization_shape(record["holder_authorization"])
            and isinstance(record.get("signature"), dict)
        )
        case = env.scratch()
        rc, out, captured = _log_entry(case, "transfer-record", json.dumps(record))
        assert "Traceback" not in captured.err
        if not shape_ok:
            assert rc == cli.EXIT_USAGE_ERROR
            assert not out.exists()

    check()


def test_log_entry_never_reads_the_hash_off_the_document(env: Env) -> None:
    """A document that DECLARES its own hash must not be believed. The record
    below carries a `record_sha256` member of its own; the entry must either be
    refused (the member is not in §8's closed record shape) or carry the hash
    recomputed from the bytes — never the one the document supplied."""
    poisoned = copy.deepcopy(RECORD_15)
    poisoned["record_sha256"] = "0" * 64
    case = env.scratch()

    rc, out, captured = _log_entry(case, "revocation-record", json.dumps(poisoned))

    assert rc == cli.EXIT_USAGE_ERROR
    assert not out.exists()
    assert "Traceback" not in captured.err
    # And the honest record still produces the hash of its own bytes.
    rc_ok, out_ok, _ = _log_entry(env.scratch(), "revocation-record", json.dumps(RECORD_15))
    assert rc_ok == cli.EXIT_OK
    assert json.loads(out_ok.read_text(encoding="utf-8"))["record_sha256"] == (
        revocation.record_hash(RECORD_15)
    )


# --- T4.3-bis: the three view producers over mutated FILES -------------------


def _compromise_view(
    case: Path,
    *,
    manifest: str | None = None,
    evidence: str | None = None,
    trusted: str | None = None,
    append: str | None = None,
    extra_pairs: list[tuple[str, str]] | None = None,
) -> tuple[int, Path, Captured]:
    out = case / "compromise-view.json"
    argv = [
        "manifest",
        "compromise-view",
        "--trusted-manifest",
        str(
            _write_text(
                case / "trusted.json",
                trusted if trusted is not None else json.dumps(_corpus_head(LEAF_41A)),
            )
        ),
        "--manifest",
        str(
            _write_text(
                case / "declaration.json",
                manifest if manifest is not None else json.dumps(CLAIM_41A["manifest"]),
            )
        ),
        "--evidence",
        str(
            _write_text(
                case / "evidence.json",
                evidence if evidence is not None else json.dumps(CLAIM_41A["evidence"]),
            )
        ),
    ]
    for index, (extra_manifest, extra_evidence) in enumerate(extra_pairs or []):
        argv += [
            "--manifest",
            str(_write_text(case / f"declaration-{index}.json", extra_manifest)),
            "--evidence",
            str(_write_text(case / f"evidence-{index}.json", extra_evidence)),
        ]
    if append is not None:
        argv += ["--append", str(_write_text(case / "append.json", append))]
    argv += ["--out", str(out)]
    rc, captured = _run(argv)
    return rc, out, captured


def _transfer_view(
    case: Path, *, record: str | None = None, evidence: str | None = None, append: str | None = None
) -> tuple[int, Path, Captured]:
    out = case / "transfer-view.json"
    argv = [
        "transfer",
        "view",
        "--record",
        str(
            _write_text(
                case / "record.json",
                record if record is not None else json.dumps(CLAIM_35A["record"]),
            )
        ),
        "--evidence",
        str(
            _write_text(
                case / "evidence.json",
                evidence if evidence is not None else json.dumps(CLAIM_35A["evidence"]),
            )
        ),
    ]
    if append is not None:
        argv += ["--append", str(_write_text(case / "append.json", append))]
    argv += ["--out", str(out)]
    rc, captured = _run(argv)
    return rc, out, captured


def _revocation_view(
    case: Path, *, record: str | None = None, append: str | None = None
) -> tuple[int, Path, Captured]:
    out = case / "revocation-view.json"
    argv = [
        "revocation-view",
        "--record",
        str(
            _write_text(
                case / "record.json", record if record is not None else json.dumps(RECORD_15)
            )
        ),
    ]
    if append is not None:
        argv += ["--append", str(_write_text(case / "append.json", append))]
    argv += ["--out", str(out)]
    rc, captured = _run(argv)
    return rc, out, captured


def assert_view_outcome(
    rc: int, out: Path, captured: Captured, rebuild: Any, *, expect_kind: type
) -> None:
    """Refused with nothing written, or a view the builder rebuilds unchanged.

    Idempotence is the honest test of a producer: a written view that changes
    when it is fed back to its own builder is a view whose reader and writer
    disagree about what was published.
    """
    assert "Traceback" not in captured.err
    if rc == cli.EXIT_USAGE_ERROR:
        assert "error:" in captured.err
        assert not out.exists()
        return
    assert rc == cli.EXIT_OK
    view = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(view, expect_kind)
    assert canon.canonical_bytes(rebuild(view)) == canon.canonical_bytes(view)


def test_a_mutated_declaration_never_yields_a_view_the_builder_rejects(env: Env) -> None:
    @PROPERTY_SETTINGS
    @given(manifest=malformed_manifests(CLAIM_41A["manifest"]))
    def check(manifest: dict[str, Any]) -> None:
        rc, out, captured = _compromise_view(env.scratch(), manifest=json.dumps(manifest))
        assert_view_outcome(rc, out, captured, views.build_compromise_view, expect_kind=list)

    check()


def test_a_mutated_evidence_bundle_never_yields_a_view_the_builder_rejects(env: Env) -> None:
    @PROPERTY_SETTINGS
    @given(evidence=malformed_documents(CLAIM_41A["evidence"]))
    def check(evidence: dict[str, Any]) -> None:
        rc, out, captured = _compromise_view(env.scratch(), evidence=json.dumps(evidence))
        assert_view_outcome(rc, out, captured, views.build_compromise_view, expect_kind=list)

    check()


def test_a_mutated_transfer_record_never_yields_a_view_the_builder_rejects(env: Env) -> None:
    @PROPERTY_SETTINGS
    @given(record=malformed_documents(CLAIM_35A["record"]))
    def check(record: dict[str, Any]) -> None:
        rc, out, captured = _transfer_view(env.scratch(), record=json.dumps(record))
        assert_view_outcome(rc, out, captured, views.build_transfer_view, expect_kind=list)

    check()


def test_a_mutated_revocation_record_never_yields_a_view_the_builder_rejects(env: Env) -> None:
    @PROPERTY_SETTINGS
    @given(record=malformed_documents(RECORD_15))
    def check(record: dict[str, Any]) -> None:
        rc, out, captured = _revocation_view(env.scratch(), record=json.dumps(record))
        assert_view_outcome(rc, out, captured, views.build_revocation_view, expect_kind=list)

    check()


def test_a_hostile_element_in_append_never_yields_a_view_the_builder_rejects(env: Env) -> None:
    """`--append` is the obvious vector for a poisoned view: it is the one
    input an operator does not re-read, because it is 'the file from last
    time'. Every element of it is rebuilt, so a claim that would not be built
    today cannot survive in it."""

    @PROPERTY_SETTINGS
    @given(
        element=st.one_of(
            st.sampled_from(WRONG_TYPES),
            malformed_documents(CLAIM_41A),
            st.builds(
                lambda m: {"manifest": m, "evidence": CLAIM_41A["evidence"]},
                malformed_manifests(CLAIM_41A["manifest"]),
            ),
        )
    )
    def check(element: Any) -> None:
        rc, out, captured = _compromise_view(env.scratch(), append=json.dumps([element]))
        assert_view_outcome(rc, out, captured, views.build_compromise_view, expect_kind=list)

    check()


@pytest.mark.parametrize("flag", ["--trusted-manifest", "--manifest", "--evidence", "--append"])
def test_a_duplicate_member_in_any_view_input_is_refused(env: Env, flag: str) -> None:
    """D11 across every input of the compromise producer, including the one
    that is merely 'the file from last time'."""
    source: Any = {
        "--trusted-manifest": _corpus_head(LEAF_41A),
        "--manifest": CLAIM_41A["manifest"],
        "--evidence": CLAIM_41A["evidence"],
        "--append": [CLAIM_41A],
    }[flag]

    @PROPERTY_SETTINGS
    @given(text=duplicated_key_text(source))
    def check(text: str) -> None:
        case = env.scratch()
        kwargs = {
            "--trusted-manifest": {"trusted": text},
            "--manifest": {"manifest": text},
            "--evidence": {"evidence": text},
            "--append": {"append": text},
        }[flag]
        rc, out, captured = _compromise_view(case, **kwargs)
        assert rc == cli.EXIT_USAGE_ERROR
        assert not out.exists()
        assert "duplicate" in captured.err.lower()
        assert "Traceback" not in captured.err

    check()


def test_a_truncated_view_input_is_always_refused(env: Env) -> None:
    text = json.dumps(CLAIM_41A["evidence"])

    @PROPERTY_SETTINGS
    @given(cut=st.integers(min_value=0, max_value=len(text) - 1))
    def check(cut: int) -> None:
        rc, out, captured = _compromise_view(env.scratch(), evidence=text[:cut])
        assert rc == cli.EXIT_USAGE_ERROR
        assert not out.exists()
        assert "Traceback" not in captured.err

    check()


def _second_transfer_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    """A second, genuinely different transfer claim built from the corpus one.

    The corpus has exactly one transfer claim, and the two 41-group leaves that
    look like two claims share one declaration manifest — so a swap test built
    on them would swap a document with itself and pass against a producer that
    never checked the pairing at all (measured 2026-09-03). The second record
    below differs in `new_receipt_id`, which changes `record_hash` while
    keeping the record shape-valid, and its evidence names that new hash. The
    builder verifies no signature and no proof, so this is a claim it accepts
    on exactly the terms it accepts the corpus one.
    """
    record = copy.deepcopy(CLAIM_35A["record"])
    record["new_receipt_id"] = "01J1V5B4M9Z8QWERTY12345679"
    evidence = copy.deepcopy(CLAIM_35A["evidence"])
    evidence["entry"] = {
        "type": "transfer-record",
        "issuer": evidence["entry"]["issuer"],
        "record_sha256": transfer.record_hash(record),
    }
    evidence["leaf_index"] = evidence["leaf_index"] + 1
    evidence["tree_size"] = evidence["tree_size"] + 1
    return record, evidence


def test_two_pairs_are_matched_by_position_and_a_swap_is_refused(env: Env) -> None:
    """Pairs match by POSITION. Two claims that each build on their own are
    both refused once their evidence is swapped, because evidence names the
    document it commits to (§19.3 item 4, applied to §17). Without the positive
    half this would pass against a producer that refused every pair."""
    second_record, second_evidence = _second_transfer_pair()
    case = env.scratch()
    paths = {
        "r1": _write_text(case / "record-1.json", json.dumps(CLAIM_35A["record"])),
        "e1": _write_text(case / "evidence-1.json", json.dumps(CLAIM_35A["evidence"])),
        "r2": _write_text(case / "record-2.json", json.dumps(second_record)),
        "e2": _write_text(case / "evidence-2.json", json.dumps(second_evidence)),
    }

    def run(order: tuple[str, str, str, str], out_name: str) -> tuple[int, Path, Captured]:
        out = case / out_name
        rc, captured = _run(
            [
                "transfer",
                "view",
                "--record",
                str(paths[order[0]]),
                "--evidence",
                str(paths[order[1]]),
                "--record",
                str(paths[order[2]]),
                "--evidence",
                str(paths[order[3]]),
                "--out",
                str(out),
            ]
        )
        return rc, out, captured

    paired = run(("r1", "e1", "r2", "e2"), "paired.json")
    swapped = run(("r1", "e2", "r2", "e1"), "swapped.json")

    assert paired[0] == cli.EXIT_OK
    assert len(json.loads(paired[1].read_text(encoding="utf-8"))) == 2
    assert swapped[0] == cli.EXIT_USAGE_ERROR
    assert "does not commit to this document" in swapped[2].err
    assert not swapped[1].exists()


def test_no_output_is_written_until_every_pair_has_been_validated(env: Env) -> None:
    """The first pair is the corpus claim and would build; the second is
    rubbish. Nothing may reach disk, because a view containing only the claims
    that happened to come first is a view its operator never asked for."""
    case = env.scratch()

    rc, out, captured = _compromise_view(
        case, extra_pairs=[(json.dumps({"not": "a manifest"}), json.dumps({"not": "evidence"}))]
    )

    assert rc == cli.EXIT_USAGE_ERROR
    assert not out.exists()
    assert "Traceback" not in captured.err


def test_a_valid_claim_beside_another_is_never_dropped(env: Env) -> None:
    """The mutation §5 names for T4.3-bis: losing a valid claim adjacent to
    another. Two distinct claims go in and two come out, in the order given."""
    claim_m = _corpus(LEAF_41A.parent / "m-uncompromise-view-floor" / "compromise-view.json")[0]
    case = env.scratch()

    rc, out, _captured = _compromise_view(
        case,
        trusted=json.dumps(_corpus_head(LEAF_41A)),
        extra_pairs=[
            (json.dumps(claim_m["manifest"]), json.dumps(claim_m["evidence"])),
        ],
    )

    assert rc == cli.EXIT_OK
    view = json.loads(out.read_text(encoding="utf-8"))
    assert len(view) == 2
    assert canon.canonical_bytes(view[0]) == canon.canonical_bytes(CLAIM_41A)
    assert canon.canonical_bytes(view[1]) == canon.canonical_bytes(claim_m)


def test_the_append_ceiling_admits_the_last_claim_and_refuses_one_more(env: Env) -> None:
    """Both sides of the compromise view's ceiling. The number is read from
    `verify`, where it is defined, so this test cannot pass against a producer
    that invented a ceiling of its own."""
    ceiling = views._MAX_COMPROMISE_CLAIMS
    # `_deduplicated` refuses canonically identical claims, so the filler has to
    # be distinct: `leaf_index`/`tree_size` move together, which keeps every
    # claim well-formed while making each one different from its neighbours.
    # The offset matters — starting at 0 would recreate the corpus claim's own
    # (1, 2) and the run would fail as a duplicate rather than at the ceiling,
    # which is a different test passing for the wrong reason.
    base = CLAIM_41A["evidence"]["tree_size"] + 1
    filler = []
    for index in range(ceiling):
        claim = copy.deepcopy(CLAIM_41A)
        claim["evidence"]["leaf_index"] = base + index
        claim["evidence"]["tree_size"] = base + index + 1
        filler.append(claim)

    at_limit = _compromise_view(
        env.scratch(),
        append=json.dumps(filler[: ceiling - 1]),
    )
    over_limit = _compromise_view(env.scratch(), append=json.dumps(filler))

    assert at_limit[0] == cli.EXIT_OK
    assert len(json.loads(at_limit[1].read_text(encoding="utf-8"))) == ceiling
    assert over_limit[0] == cli.EXIT_USAGE_ERROR
    assert str(ceiling) in over_limit[2].err
    assert not over_limit[1].exists()


def test_a_view_producer_leaves_a_pre_existing_output_untouched_when_it_refuses(
    env: Env,
) -> None:
    case = env.scratch()
    out = case / "compromise-view.json"
    out.write_text("sentinel", encoding="utf-8")

    rc, _out, captured = _compromise_view(case, evidence=json.dumps({"not": "evidence"}))

    assert rc == cli.EXIT_USAGE_ERROR
    assert "Traceback" not in captured.err
    assert out.read_text(encoding="utf-8") == "sentinel"
