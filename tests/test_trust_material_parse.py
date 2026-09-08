"""The serialized entry to the verifier's local trust material (front F6, T1).

Written BEFORE `src/attest/trust_material.py` grows `TrustStore.from_bytes` /
`KeyManifest.from_bytes`, so what is pinned here is what the boundary MUST do,
not what some implementation happens to do.

WHAT THIS FILE MEASURES
-----------------------
INV-1   conservation: a well-formed document goes in and comes back out of the
        snapshot unchanged, INCLUDING which optional members were present. An
        absent member is not an empty member, and the two must stay apart all
        the way to `to_bytes()`.
INV-1b  admissibility: an oracle written from the FORMAT — plain `json`, this
        file's own walkers, this file's own transcription of the container
        grammar — decides for every mutant whether the boundary must accept or
        refuse. The oracle never calls the code under test and never calls
        `attest.canon`, so it can contradict them. An importer that refuses a
        document the format admits is red whatever its message says.
INV-3   refusal of the whole unit: a defective document yields ONE error, of
        the class the evaluation order prescribes, naming the member at fault,
        and no half-built snapshot.
INV-4   contract refusal before any hook: an object presented in place of the
        bytes is refused with a constant message and WITHOUT a single dunder of
        that object running. The empty registry is the evidence that the
        refusal happened before the object was touched; the exception alone
        would not prove it.
INV-5   no aliasing: `data()` hands back a fresh tree every call, and mutating
        what it handed back changes nothing.
D15     custody: the snapshot classes are built by their factories or not at
        all.
D18     selectors: a lookup key that is not exactly `str` is answered before
        any hash or comparison of it happens.

WHY THE ORACLE IS SEPARATE FROM THE MESSAGES
--------------------------------------------
The message prefix CLASSIFIES a refusal, it does not JUSTIFY one. Every test
that expects a refusal therefore asks two independent questions: does the
oracle say this document is inadmissible, and does the boundary refuse it in
the class the evaluation order predicts. A test that only compared messages
would pass just as happily against an importer that refuses everything.

THE ONE PLACE THIS FILE READS THE IMPLEMENTATION
------------------------------------------------
The message TEMPLATES are read from the module under test (`_message`), never
retyped here: a test that carries its own copy of a message pins the copy. What
is transcribed here instead is the GRAMMAR (section 5.3 of the plan) and the
format's numeric limits, because those are the specification the importer is
answerable to.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from attest import trust_material

# Hypothesis budget: every example here is pure parsing, so the examples are
# cheap, but the suite runs on every push and derandomize keeps a failure
# reproducible from the report alone.
PROPERTY_SETTINGS = settings(
    max_examples=40,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow],
)

# The two `what` values the boundary formats into its messages (section 5.1.2).
WHAT_STORE = "trust store"
WHAT_MANIFEST = "key manifest"

# The custody message of section 5.1.2, which is normative text of the plan and
# NOT one of the `_MSG_*` constants, so it is transcribed with its shape rather
# than read from the module.
CUSTODY_MESSAGE = "{name} is built by {name}.from_bytes(data)"

# The format's own numbers, transcribed from the specification so this file can
# contradict the library. `test_the_libraries_limits_are_the_numbers_this_file_assumes`
# pins them against `attest.canon`, which is the only place canon is consulted.
CEILING_BYTES = 10_000_000
MAX_DEPTH = 256
INT_LIMIT = 2**53  # exclusive on both sides: |n| < 2**53


# ---------------------------------------------------------------------------
# The container grammar (plan section 5.3), transcribed once and DERIVED from
# thereafter. The expected-shape phrase of M6 is computed from the kind path,
# not enumerated: a phrase written by hand next to the path it describes is a
# second copy that drifts.
# ---------------------------------------------------------------------------

MEMBER_KINDS: dict[str, tuple[str, ...]] = {
    "manifests": ("object", "object"),
    "provenance": ("object", "string"),
    "chains": ("object", "array", "object"),
    "artifact_manifests": ("object", "object", "object"),
    "artifact_manifest_chains": ("object", "object", "array", "object"),
}
# The order M6 is evaluated in, which is the order of the table.
MEMBER_ORDER: tuple[str, ...] = tuple(MEMBER_KINDS)
REQUIRED_MEMBERS = ("manifests", "provenance")
OPTIONAL_MEMBERS = ("chains", "artifact_manifests", "artifact_manifest_chains")


def expected_phrase(member: str) -> str:
    """The `expected` half of M6 for `member`, derived from its kind path."""
    kinds = MEMBER_KINDS[member]
    return "an " + kinds[0] + "".join(f" of {kind}s" for kind in kinds[1:])


def shape_ok(value: object, kinds: Sequence[str]) -> bool:
    """True iff `value` satisfies the kind path `kinds` of section 5.3."""
    kind = kinds[0]
    rest = kinds[1:]
    if kind == "string":
        return type(value) is str
    if kind == "object":
        if type(value) is not dict:
            return False
        return all(shape_ok(item, rest) for item in value.values()) if rest else True
    if kind == "array":
        if type(value) is not list:
            return False
        return all(shape_ok(item, rest) for item in value) if rest else True
    raise AssertionError(f"unknown kind in the transcribed grammar: {kind!r}")


def grammar_refusal(document: object) -> tuple[str, str | None] | None:
    """The refusal the grammar prescribes, or None if the document is well formed.

    Returns `(message id, member)`. The evaluation order is the one section 5.3
    fixes: the document is an object, then the FIRST unknown member in document
    order, then the five members in table order.
    """
    if type(document) is not dict:
        return ("M4", None)
    for name in document:
        if name not in MEMBER_KINDS:
            return ("M5", name)
    for member in MEMBER_ORDER:
        if member not in document:
            if member in REQUIRED_MEMBERS:
                return ("M6", member)
            continue
        if not shape_ok(document[member], MEMBER_KINDS[member]):
            return ("M6", member)
    return None


# ---------------------------------------------------------------------------
# Reaching the boundary under test.
# ---------------------------------------------------------------------------


def store_class() -> Any:
    """`trust_material.TrustStore`, resolved at CALL time.

    Resolved at import time instead, today's absence would be a COLLECTION
    error — which is exactly what an invalid test file produces, so it would
    prove nothing about the parser. Resolved here, the absence surfaces inside
    each test: the module imported (the environment is built), the name is not
    there (the boundary is not written yet).
    """
    return trust_material.TrustStore


def manifest_class() -> Any:
    """`trust_material.KeyManifest`, resolved at call time. See `store_class`."""
    return trust_material.KeyManifest


def message(name: str) -> str:
    """A message TEMPLATE read from the module under test, never retyped here."""
    return str(getattr(trust_material, name))


def rendered(constant: str, /, **fields: object) -> str:
    """The full message named by `constant`, with `fields` substituted.

    Positional-only, because one of the message templates has a `{name}` slot:
    with an ordinary parameter called `name`, `rendered("_MSG_UNKNOWN_MEMBER",
    name=...)` collides on the same argument and raises TypeError before the
    assertion is ever evaluated. The collision is with the TEMPLATE's own
    vocabulary, so renaming the parameter would only move the problem to the
    next template that reuses the word.
    """
    return message(constant).format(**fields)


MESSAGE_IDS: tuple[tuple[str, str], ...] = (
    ("M1", "_MSG_NOT_BYTES"),
    ("M2", "_MSG_TOO_LARGE"),
    ("M4", "_MSG_NOT_OBJECT"),
    ("M5", "_MSG_UNKNOWN_MEMBER"),
    ("M6", "_MSG_MEMBER_SHAPE"),
    ("M7", "_MSG_UNPARSABLE"),
    ("M8", "_MSG_NOT_CANONICAL"),
)


def message_prefix(identifier: str, what: str) -> str:
    """The constant head of message `identifier`, derived from its template.

    M7 and M8 carry a declared tail (the parser's own text), and M5/M6 carry
    rendered names, so a test cannot compare them whole without transcribing
    somebody else's wording. It compares the head, which the template owns.
    """
    template = message(dict(MESSAGE_IDS)[identifier])
    if identifier in ("M1", "M2", "M4"):
        return template.format(what=what)
    if identifier == "M5":
        return template.split("{name}")[0]
    if identifier == "M6":
        return template.split("{member}")[0]
    return template.format(what=what, reason="")


def classify(exc: BaseException, what: str = WHAT_STORE) -> str:
    """The section 5.4 message id `exc` belongs to."""
    text = str(exc)
    for identifier, _ in MESSAGE_IDS:
        if text.startswith(message_prefix(identifier, what)):
            return identifier
    raise AssertionError(f"refusal matches no message template: {text!r}")


def refusal(call: Callable[[], object]) -> trust_material.TrustMaterialError:
    """Run `call`, require a `TrustMaterialError`, hand it back for inspection."""
    with pytest.raises(trust_material.TrustMaterialError) as caught:
        call()
    return caught.value


def refused_as(
    call: Callable[[], object],
    identifier: str,
    *,
    what: str = WHAT_STORE,
    member: str | None = None,
) -> trust_material.TrustMaterialError:
    """Require that `call` is refused as `identifier`, naming `member`."""
    exc = refusal(call)
    assert classify(exc, what) == identifier, f"expected {identifier}, got {str(exc)!r}"
    assert exc.member == member, f"expected member {member!r}, got {exc.member!r}"
    return exc


def parse_store(payload: object) -> Any:
    return store_class().from_bytes(payload)


def parse_manifest(payload: object) -> Any:
    return manifest_class().from_bytes(payload)


# ---------------------------------------------------------------------------
# Ground truth documents. Built as Python trees FIRST, serialized second: the
# tree is the truth the snapshot is compared against, and it exists before the
# library has seen anything.
# ---------------------------------------------------------------------------

PUBLIC_MATERIAL = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

PLAIN_ISSUERS = ("store.example.com", "shop.example.org", "market.example.net")
# Names that mean something to an object system and nothing to a JSON document.
SPECIAL_ISSUERS = ("__proto__", "", "toString", "constructor", "hasOwnProperty")
ALL_ISSUER_IDS = PLAIN_ISSUERS + SPECIAL_ISSUERS + ("café.example.com",)


def key_manifest_tree(issuer: str, version: int) -> dict[str, Any]:
    return {
        "manifest_version": version,
        "issuer": issuer,
        "keys": [
            {
                "kid": f"{issuer}/keys/manifest#ed25519-{version}",
                "alg": "ed25519",
                "public_key": PUBLIC_MATERIAL,
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": None,
            }
        ],
    }


def artifact_manifest_tree(issuer: str, version: int) -> dict[str, Any]:
    return {
        "manifest_version": version,
        "series": f"{issuer}/works/EXG-001",
        "artifacts": [{"role": "installer", "sha256": PUBLIC_MATERIAL}],
    }


def document(
    issuers: Sequence[str],
    *,
    chain_length: int = 1,
    artifacts: bool = True,
    absent: Iterable[str] = (),
    empty: Iterable[str] = (),
) -> dict[str, Any]:
    """A well-formed trust-store document over `issuers`."""
    series = "works/EXG-001"
    tree: dict[str, Any] = {
        "manifests": {issuer: key_manifest_tree(issuer, 1) for issuer in issuers},
        "provenance": {issuer: "tls" for issuer in issuers},
        "chains": {
            issuer: [key_manifest_tree(issuer, v) for v in range(1, chain_length + 1)]
            for issuer in issuers
        },
    }
    if artifacts:
        tree["artifact_manifests"] = {
            issuer: {series: artifact_manifest_tree(issuer, 1)} for issuer in issuers
        }
        tree["artifact_manifest_chains"] = {
            issuer: {series: [artifact_manifest_tree(issuer, 1)]} for issuer in issuers
        }
    for name in absent:
        tree.pop(name, None)
    for name in empty:
        tree[name] = {}
    return tree


SMALL_DOCUMENT = document(PLAIN_ISSUERS[:1], chain_length=1, artifacts=False)
RICH_DOCUMENT = document(PLAIN_ISSUERS[:1], chain_length=1, artifacts=True)


def conservation_corpus() -> list[tuple[str, dict[str, Any]]]:
    """The documents INV-1 is measured on: shape sweep plus the absent/empty matrix."""
    corpus: list[tuple[str, dict[str, Any]]] = []
    for family, pool in (("plain", PLAIN_ISSUERS), ("special", SPECIAL_ISSUERS)):
        for count in (1, 3):
            for chain_length in (0, 1, 2, 3):
                for artifacts in (False, True):
                    name = f"{family}-{count}issuer-chain{chain_length}-artifacts{int(artifacts)}"
                    corpus.append(
                        (
                            name,
                            document(
                                pool[:count],
                                chain_length=chain_length,
                                artifacts=artifacts,
                            ),
                        )
                    )
    for mask in range(2 ** len(OPTIONAL_MEMBERS)):
        absent = [name for bit, name in enumerate(OPTIONAL_MEMBERS) if mask >> bit & 1]
        empty = [name for name in OPTIONAL_MEMBERS if name not in absent]
        corpus.append(
            (
                "absent:" + ("+".join(absent) or "none"),
                document(PLAIN_ISSUERS, absent=absent, empty=empty),
            )
        )
    return corpus


CONSERVATION_CORPUS = conservation_corpus()


def deep_document(total_depth: int) -> dict[str, Any]:
    """A valid document whose deepest container sits at `total_depth`.

    The builder VERIFIES its own construction with this file's depth walker
    before handing the document over: a depth fixture that is off by one turns
    a boundary test into a test of the interior, silently.
    """
    chain_length = total_depth - 3
    assert chain_length >= 1
    node: Any = {}
    for _ in range(chain_length - 1):
        node = {"n": node}
    tree = {"manifests": {"i": {"deep": node}}, "provenance": {"i": "tls"}}
    assert depth_of(tree) == total_depth, "the depth fixture does not have the depth it claims"
    return tree


def document_with_literal(literal: str) -> bytes:
    """A valid document whose one manifest carries `literal` verbatim as a value.

    Written as TEXT because the cases that matter — `-0`, a float spelling, a
    4301-digit token — do not survive a Python tree.
    """
    return (
        '{"manifests":{"i":{"issuer":"i","probe":' + literal + '}},"provenance":{"i":"tls"}}'
    ).encode()


# ---------------------------------------------------------------------------
# Serialization and the comparison oracle. Neither touches the library.
# ---------------------------------------------------------------------------


def serialize(tree: object) -> bytes:
    return json.dumps(tree, separators=(",", ":"), ensure_ascii=False).encode()


def ordered(tree: object) -> str:
    """A canonical-enough rendering for comparison: sorted keys, no whitespace."""
    return json.dumps(tree, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def depth_of(node: object) -> int:
    """Container nesting depth of a parsed tree, walked by this file."""
    stack: list[tuple[object, int]] = [(node, 1)]
    deepest = 0
    while stack:
        current, depth = stack.pop()
        if type(current) is dict:
            deepest = max(deepest, depth)
            stack.extend((value, depth + 1) for value in current.values())
        elif type(current) is list:
            deepest = max(deepest, depth)
            stack.extend((item, depth + 1) for item in current)
    return deepest


# ---------------------------------------------------------------------------
# INV-1b: the admissibility oracle. Stdlib and this file only. It must be able
# to say "the format admits this" about a document the importer refuses.
# ---------------------------------------------------------------------------


class _OracleRejection(ValueError):
    pass


def _no_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for name, value in pairs:
        if name in seen:
            raise _OracleRejection(f"duplicate member {name!r}")
        seen[name] = value
    return seen


def _no_floats(_text: str) -> Any:
    raise _OracleRejection("the profile admits no floats and no JSON constants")


def _walk(node: object) -> Iterable[object]:
    stack: list[object] = [node]
    while stack:
        current = stack.pop()
        yield current
        if type(current) is dict:
            stack.extend(current.keys())
            stack.extend(current.values())
        elif type(current) is list:
            stack.extend(current)


def _has_lone_surrogate(node: object) -> bool:
    return any(
        type(item) is str and any(0xD800 <= ord(ch) <= 0xDFFF for ch in item)
        for item in _walk(node)
    )


def _integer_out_of_range(node: object) -> bool:
    return any(type(item) is int and not -INT_LIMIT < item < INT_LIMIT for item in _walk(node))


def oracle(payload: bytes) -> tuple[str | None, object]:
    """`(refusal id, parsed tree)` for `payload`, decided from the FORMAT.

    The order mirrors section 5.1.1 — ceiling, parse, container grammar,
    canonical representability — because a document with two defects must be
    predicted by the same order the importer applies. Written without `attest`,
    so it can disagree with it.
    """
    if len(payload) > CEILING_BYTES:
        return ("M2", None)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return ("M7", None)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_no_duplicate_members,
            parse_float=_no_floats,
            parse_constant=_no_floats,
        )
    except (ValueError, RecursionError):
        return ("M7", None)
    if depth_of(parsed) > MAX_DEPTH or _has_lone_surrogate(parsed):
        return ("M7", None)
    violation = grammar_refusal(parsed)
    if violation is not None:
        return violation[0], parsed
    if _integer_out_of_range(parsed):
        return ("M8", parsed)
    return (None, parsed)


def admissible(payload: bytes) -> bool:
    return oracle(payload)[0] is None


# ---------------------------------------------------------------------------
# The hostile corpus of section 6.2: mutations of a valid document's BYTES.
# ---------------------------------------------------------------------------

DUPLICATE_KEY_DOCUMENTS: tuple[tuple[str, bytes], ...] = (
    (
        "duplicate top-level member",
        b'{"manifests":{},"provenance":{},"chains":{},"chains":{}}',
    ),
    (
        "duplicate top-level member spelled with an escape",
        b'{"manifests":{},"provenance":{},"chains":{},"\\u0063hains":{}}',
    ),
    (
        "duplicate issuer inside manifests",
        b'{"manifests":{"i":{},"i":{}},"provenance":{"i":"tls"}}',
    ),
    (
        "duplicate field inside a manifest",
        b'{"manifests":{"i":{"issuer":"a","issuer":"b"}},"provenance":{"i":"tls"}}',
    ),
    (
        "duplicate field inside a keys entry",
        b'{"manifests":{"i":{"keys":[{"status":"active","status":"compromised"}]}},'
        b'"provenance":{"i":"tls"}}',
    ),
)

UNKNOWN_MEMBER_NAMES = (
    "Manifests",
    "manifests ",
    "__proto__",
    "constructor",
    "toString",
    "hasOwnProperty",
    "",
    "it's",
)

LEXICAL_MUTANTS: tuple[tuple[str, bytes, str | None], ...] = (
    ("byte order mark", b"\xef\xbb\xbf" + serialize(SMALL_DOCUMENT), "M7"),
    (
        "lone surrogate in an issuer id",
        b'{"manifests":{"\\ud800":{}},"provenance":{}}',
        "M7",
    ),
    ("float 1.5", document_with_literal("1.5"), "M7"),
    ("float 1e3", document_with_literal("1e3"), "M7"),
    ("float -0.0", document_with_literal("-0.0"), "M7"),
    ("float 1e400", document_with_literal("1e400"), "M7"),
    ("constant NaN", document_with_literal("NaN"), "M7"),
    ("constant Infinity", document_with_literal("Infinity"), "M7"),
    ("negative zero integer", document_with_literal("-0"), None),
    ("largest safe integer", document_with_literal(str(INT_LIMIT - 1)), None),
    ("smallest safe integer", document_with_literal(str(-(INT_LIMIT - 1))), None),
    ("one past the largest safe integer", document_with_literal(str(INT_LIMIT)), "M8"),
    ("one past the smallest safe integer", document_with_literal(str(-INT_LIMIT)), "M8"),
    ("4300 digit integer token", document_with_literal("1" * 4300), "M8"),
    ("4301 digit integer token", document_with_literal("1" * 4301), "M7"),
    ("invalid utf-8 in a member name", b'{"manifests":{"\xff":{}},"provenance":{}}', "M7"),
)


def type_matrix_cases() -> list[tuple[str, dict[str, Any], str, bool]]:
    """Every (member, depth, substitute) of section 6.2, with the grammar's verdict.

    The verdict is DERIVED by `shape_ok` from the kind path. Enumerated by hand
    it would share the blind spots of whoever wrote it down.
    """
    substitutes: tuple[tuple[str, Any], ...] = (
        ("null", None),
        ("true", True),
        ("one", 1),
        ("string", "s"),
        ("empty array", []),
        ("empty object", {}),
        ("array of one", [1]),
        ("array of an object", [{}]),
        ("object of one", {"k": 1}),
    )
    cases: list[tuple[str, dict[str, Any], str, bool]] = []
    for member, kinds in MEMBER_KINDS.items():
        for depth in range(len(kinds)):
            for label, value in substitutes:
                mutated_member = substitute_at(RICH_DOCUMENT[member], kinds, depth, value)
                mutant = dict(RICH_DOCUMENT)
                mutant[member] = mutated_member
                cases.append(
                    (
                        f"{member}@{depth}={label}",
                        mutant,
                        member,
                        shape_ok(mutated_member, kinds),
                    )
                )
    return cases


def substitute_at(node: object, kinds: Sequence[str], depth: int, value: object) -> Any:
    """Replace every node `depth` levels under `node` along `kinds` with `value`."""
    if depth == 0:
        return value
    kind = kinds[0]
    if kind == "object" and type(node) is dict:
        return {k: substitute_at(v, kinds[1:], depth - 1, value) for k, v in node.items()}
    if kind == "array" and type(node) is list:
        return [substitute_at(v, kinds[1:], depth - 1, value) for v in node]
    return node


def byte_mutant_corpus() -> list[tuple[str, bytes]]:
    """Every section 6.2 mutant that is cheap enough to run under the oracle."""
    valid = serialize(SMALL_DOCUMENT)
    corpus: list[tuple[str, bytes]] = [("the unmutated document", valid)]
    corpus.extend((f"truncated at {offset}", valid[:offset]) for offset in range(len(valid)))
    for offset in range(len(valid)):
        for mask in (0x01, 0x20, 0x80):
            corpus.append(
                (
                    f"byte {offset} flipped with {mask:#04x}",
                    valid[:offset] + bytes([valid[offset] ^ mask]) + valid[offset + 1 :],
                )
            )
    corpus.extend((name, payload) for name, payload in DUPLICATE_KEY_DOCUMENTS)
    corpus.extend((name, payload) for name, payload, _ in LEXICAL_MUTANTS)
    for name in UNKNOWN_MEMBER_NAMES:
        mutant = dict(SMALL_DOCUMENT)
        mutant[name] = {}
        corpus.append((f"unknown member {name!r}", serialize(mutant)))
    for label, mutant, _, _ in type_matrix_cases():
        corpus.append((f"type matrix {label}", serialize(mutant)))
    for member in REQUIRED_MEMBERS:
        corpus.append(
            (
                f"missing required member {member}",
                serialize(document(PLAIN_ISSUERS[:1], absent=[member])),
            )
        )
    corpus.append(("the empty document", b"{}"))
    corpus.extend(
        (f"top level {label}", payload)
        for label, payload in (
            ("array", b"[]"),
            ("string", b'"a document"'),
            ("number", b"1"),
            ("null", b"null"),
            ("boolean", b"true"),
            ("array wrapping the document", b'[{"manifests":{},"provenance":{}}]'),
        )
    )
    for member in MEMBER_ORDER:
        nulled = dict(RICH_DOCUMENT)
        nulled[member] = None
        corpus.append((f"member {member} present as null", serialize(nulled)))
    for total_depth in (255, 256, 257):
        corpus.append((f"document of depth {total_depth}", serialize(deep_document(total_depth))))
    return corpus


BYTE_MUTANT_CORPUS = byte_mutant_corpus()


# ---------------------------------------------------------------------------
# The hostile corpus of section 6.1: objects that present themselves AS bytes,
# AS a snapshot, or AS a selector. Every one carries a registry, and the empty
# registry is the property under test.
# ---------------------------------------------------------------------------


class Recorder:
    """Notes every dunder of a hostile object that the library ran."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def note(self, name: str) -> None:
        self.calls.append(name)


class RecordingBytes(bytes):
    """A `bytes` SUBCLASS: `isinstance` says yes, `type() is bytes` says no."""

    def __new__(cls, payload: bytes, recorder: Recorder) -> RecordingBytes:
        obj = super().__new__(cls, payload)
        obj._recorder = recorder  # type: ignore[attr-defined]
        obj._payload = payload  # type: ignore[attr-defined]
        return obj

    def __repr__(self) -> str:
        self._recorder.note("__repr__")
        return "<recording bytes>"

    def __len__(self) -> int:
        self._recorder.note("__len__")
        return bytes.__len__(self)

    def __iter__(self) -> Any:
        self._recorder.note("__iter__")
        return bytes.__iter__(self)

    def __eq__(self, other: object) -> Any:
        self._recorder.note("__eq__")
        return bytes.__eq__(self, other)

    def __hash__(self) -> int:
        self._recorder.note("__hash__")
        return bytes.__hash__(self)

    def __bytes__(self) -> bytes:
        self._recorder.note("__bytes__")
        return self._payload


class BytesImpostor:
    def __init__(self, recorder: Recorder, payload: bytes) -> None:
        self._recorder = recorder
        self._payload = payload

    def __bytes__(self) -> bytes:
        self._recorder.note("__bytes__")
        return self._payload

    def __repr__(self) -> str:
        self._recorder.note("__repr__")
        return "<bytes impostor>"


class BufferImpostor:
    """PEP 688: a buffer is what a `memoryview` would take, not what `type` says."""

    def __init__(self, recorder: Recorder, payload: bytes) -> None:
        self._recorder = recorder
        self._payload = payload

    def __buffer__(self, flags: int) -> memoryview:
        self._recorder.note("__buffer__")
        return memoryview(self._payload)

    def __repr__(self) -> str:
        self._recorder.note("__repr__")
        return "<buffer impostor>"


class ClassLiar:
    """Answers `bytes` (or `str`) to `__class__`, which is what `isinstance` asks."""

    def __init__(self, recorder: Recorder, pretend: type) -> None:
        object.__setattr__(self, "_recorder", recorder)
        object.__setattr__(self, "_pretend", pretend)

    @property  # type: ignore[misc]
    def __class__(self) -> Any:  # type: ignore[override]
        object.__getattribute__(self, "_recorder").note("__class__")
        return object.__getattribute__(self, "_pretend")

    def __repr__(self) -> str:
        object.__getattribute__(self, "_recorder").note("__repr__")
        return "<class liar>"


class PathImpostor:
    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    def __fspath__(self) -> str:
        self._recorder.note("__fspath__")
        return "trust-store.json"

    def __repr__(self) -> str:
        self._recorder.note("__repr__")
        return "<path impostor>"


class IndexImpostor:
    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    def __index__(self) -> int:
        self._recorder.note("__index__")
        return 8

    def __repr__(self) -> str:
        self._recorder.note("__repr__")
        return "<index impostor>"


class HostileText(str):
    """A `str` SUBCLASS whose comparison and hashing are the caller's code."""

    def __new__(cls, value: str, recorder: Recorder) -> HostileText:
        obj = super().__new__(cls, value)
        obj._recorder = recorder  # type: ignore[attr-defined]
        return obj

    def __eq__(self, other: object) -> Any:
        self._recorder.note("__eq__")
        return str.__eq__(self, other)

    def __hash__(self) -> int:
        self._recorder.note("__hash__")
        return str.__hash__(self)

    def __str__(self) -> str:
        self._recorder.note("__str__")
        return str.__str__(self)

    def __repr__(self) -> str:
        self._recorder.note("__repr__")
        return "<hostile text>"


def old_shape_mapping() -> dict[str, Any]:
    """The trust store as callers spell it TODAY: a live mapping of five members."""
    return {name: {} for name in MEMBER_KINDS}


ByteImpostorFactory = Callable[[Recorder, bytes], object]

BYTE_IMPOSTORS: tuple[tuple[str, ByteImpostorFactory], ...] = (
    ("a bytes subclass", lambda rec, doc: RecordingBytes(doc, rec)),
    ("a bytearray", lambda rec, doc: bytearray(doc)),
    ("a memoryview", lambda rec, doc: memoryview(doc)),
    ("the document as str", lambda rec, doc: doc.decode()),
    ("an object with __bytes__", lambda rec, doc: BytesImpostor(rec, doc)),
    ("an object with __buffer__", lambda rec, doc: BufferImpostor(rec, doc)),
    ("an object whose __class__ says bytes", lambda rec, doc: ClassLiar(rec, bytes)),
    ("an int", lambda rec, doc: 42),
    ("None", lambda rec, doc: None),
    ("a dict in the old live shape", lambda rec, doc: old_shape_mapping()),
    (
        "a SimpleNamespace in the old live shape",
        lambda rec, doc: SimpleNamespace(**old_shape_mapping()),
    ),
    ("an object with __fspath__", lambda rec, doc: PathImpostor(rec)),
    ("an object with __index__", lambda rec, doc: IndexImpostor(rec)),
)

SelectorFactory = Callable[[Recorder], object]

HOSTILE_SELECTORS: tuple[tuple[str, SelectorFactory], ...] = (
    ("a str subclass", lambda rec: HostileText("store.example.com", rec)),
    ("an object whose __class__ says str", lambda rec: ClassLiar(rec, str)),
    ("bytes", lambda rec: b"store.example.com"),
    ("an int", lambda rec: 0),
    ("None", lambda rec: None),
    ("an object with __index__", lambda rec: IndexImpostor(rec)),
)


# ---------------------------------------------------------------------------
# The transcription pins: this file's copy of the specification, checked
# against the specification it copies.
# ---------------------------------------------------------------------------


def test_the_expected_shape_phrases_derive_to_the_wording_the_grammar_fixes() -> None:
    """The derived M6 phrase equals the table's own words, member by member."""
    assert {member: expected_phrase(member) for member in MEMBER_KINDS} == {
        "manifests": "an object of objects",
        "provenance": "an object of strings",
        "chains": "an object of arrays of objects",
        "artifact_manifests": "an object of objects of objects",
        "artifact_manifest_chains": "an object of objects of arrays of objects",
    }


def test_the_libraries_limits_are_the_numbers_this_file_assumes() -> None:
    """The one place `canon` is consulted: a pin, never a source of expectations.

    The oracle must be able to contradict the library, so it carries the
    format's numbers itself. If the library's numbers move, this test says so
    instead of the oracle silently drifting into agreement.
    """
    from attest import canon

    assert canon.MAX_ADMISSION_BYTES == CEILING_BYTES
    assert canon.MAX_DEPTH == MAX_DEPTH


# ---------------------------------------------------------------------------
# INV-1: conservation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "tree"), CONSERVATION_CORPUS, ids=[n for n, _ in CONSERVATION_CORPUS]
)
def test_a_well_formed_document_survives_the_snapshot_unchanged(
    name: str, tree: dict[str, Any]
) -> None:
    store = parse_store(serialize(tree))
    assert ordered(store.data()) == ordered(tree)


@pytest.mark.parametrize(
    ("name", "tree"), CONSERVATION_CORPUS, ids=[n for n, _ in CONSERVATION_CORPUS]
)
def test_an_absent_member_stays_absent_and_an_empty_member_stays_empty(
    name: str, tree: dict[str, Any]
) -> None:
    """Absence and emptiness are different documents and must stay different.

    They are the pair the whole front exists for: for an OPTIONAL member,
    absence is the direction that SKIPS a check, so a boundary that turns an
    empty member into an absent one hands the verifier more authority than it
    was given.
    """
    store = parse_store(serialize(tree))
    assert set(store.data()) == set(tree)
    exported = store.to_bytes()
    for member in MEMBER_ORDER:
        marker = f'"{member}"'.encode()
        assert (marker in exported) is (member in tree), member


def test_the_issuer_list_comes_from_the_manifests_member_sorted() -> None:
    tree = document(PLAIN_ISSUERS, chain_length=2)
    store = parse_store(serialize(tree))
    assert store.issuers() == tuple(sorted(tree["manifests"]))


def test_every_selector_hands_back_what_the_document_carried() -> None:
    tree = document(SPECIAL_ISSUERS, chain_length=2)
    store = parse_store(serialize(tree))
    for issuer in SPECIAL_ISSUERS:
        held = store.manifest_for(issuer)
        assert ordered(held.data()) == ordered(tree["manifests"][issuer])
        chain = store.chain_for(issuer)
        assert [ordered(link.data()) for link in chain] == [
            ordered(link) for link in tree["chains"][issuer]
        ]
        assert store.provenance_for(issuer) == tree["provenance"][issuer]
    assert store.manifest_for("nobody.example.com") is None
    assert store.chain_for("nobody.example.com") == ()
    assert store.provenance_for("nobody.example.com") is None


def test_a_store_without_chains_answers_the_empty_chain_like_one_with_empty_chains() -> None:
    absent = parse_store(serialize(document(PLAIN_ISSUERS[:1], absent=["chains"])))
    empty = parse_store(serialize(document(PLAIN_ISSUERS[:1], empty=["chains"])))
    issuer = PLAIN_ISSUERS[0]
    assert absent.chain_for(issuer) == ()
    assert empty.chain_for(issuer) == ()
    assert absent.to_bytes() != empty.to_bytes()


@given(tree=st.deferred(lambda: GENERATED_DOCUMENTS))
@PROPERTY_SETTINGS
def test_conservation_holds_for_every_generated_document(tree: dict[str, Any]) -> None:
    store = parse_store(serialize(tree))
    assert ordered(store.data()) == ordered(tree)
    assert set(store.data()) == set(tree)


@st.composite
def _generated_documents(draw: st.DrawFn) -> dict[str, Any]:
    issuers = draw(st.lists(st.sampled_from(ALL_ISSUER_IDS), min_size=1, max_size=3, unique=True))
    chain_length = draw(st.integers(min_value=0, max_value=3))
    artifacts = draw(st.booleans())
    absent: list[str] = []
    empty: list[str] = []
    for member in OPTIONAL_MEMBERS:
        choice = draw(st.sampled_from(("present", "empty", "absent")))
        if choice == "absent":
            absent.append(member)
        elif choice == "empty":
            empty.append(member)
    return document(
        issuers, chain_length=chain_length, artifacts=artifacts, absent=absent, empty=empty
    )


GENERATED_DOCUMENTS = _generated_documents()


@st.composite
def _permuted_encodings(draw: st.DrawFn, tree: object) -> bytes:
    """`tree` serialized with every object's members in a drawn order."""

    def encode(node: object) -> str:
        if type(node) is dict:
            members = draw(st.permutations(list(node.items())))
            body = ",".join(f"{json.dumps(k, ensure_ascii=False)}:{encode(v)}" for k, v in members)
            return "{" + body + "}"
        if type(node) is list:
            return "[" + ",".join(encode(item) for item in node) + "]"
        return json.dumps(node, ensure_ascii=False)

    return encode(tree).encode()


@given(tree=st.deferred(lambda: GENERATED_DOCUMENTS), data=st.data())
@PROPERTY_SETTINGS
def test_the_snapshot_does_not_depend_on_the_order_members_arrived_in(
    tree: dict[str, Any], data: st.DataObject
) -> None:
    """Member ORDER is not information; array order is, and INV-1 keeps it."""
    first = parse_store(data.draw(_permuted_encodings(tree)))
    second = parse_store(data.draw(_permuted_encodings(tree)))
    assert first.to_bytes() == second.to_bytes()
    assert ordered(first.data()) == ordered(tree)
    assert ordered(second.data()) == ordered(tree)


# ---------------------------------------------------------------------------
# INV-1b: the oracle decides, the message only classifies.
# ---------------------------------------------------------------------------


def test_the_boundary_admits_exactly_what_the_format_admits() -> None:
    """Over every byte mutant: the oracle rules, the importer must agree.

    Two failures are possible and both are red: refusing a document the format
    admits, and accepting one it does not. The message id is reported for the
    refusals so a disagreement says WHICH gate fired, but the id never decides
    the verdict.
    """
    disagreements: list[str] = []
    for name, payload in BYTE_MUTANT_CORPUS:
        expected, parsed = oracle(payload)
        if expected is None:
            try:
                store = parse_store(payload)
            except trust_material.TrustMaterialError as exc:
                disagreements.append(f"{name}: admissible but refused as {str(exc)!r}")
                continue
            if ordered(store.data()) != ordered(parsed):
                disagreements.append(f"{name}: admitted but not conserved")
            continue
        try:
            parse_store(payload)
        except trust_material.TrustMaterialError as exc:
            found = classify(exc)
            if found != expected:
                disagreements.append(f"{name}: expected {expected}, refused as {found}")
            continue
        disagreements.append(f"{name}: inadmissible ({expected}) but accepted")
    assert not disagreements, "\n".join(disagreements[:40])


@pytest.mark.parametrize(
    ("name", "payload", "expected"),
    LEXICAL_MUTANTS,
    ids=[name for name, _, _ in LEXICAL_MUTANTS],
)
def test_the_lexical_boundary_cases_land_in_the_class_the_format_predicts(
    name: str, payload: bytes, expected: str | None
) -> None:
    if expected is None:
        store = parse_store(payload)
        assert ordered(store.data()) == ordered(json.loads(payload))
        return
    refused_as(lambda: parse_store(payload), expected)


def test_the_integer_ceiling_is_refused_with_the_wording_both_cores_share() -> None:
    """The M8 tail on the integer case is fixed across implementations (P-23)."""
    exc = refused_as(lambda: parse_store(document_with_literal(str(INT_LIMIT))), "M8")
    assert str(exc) == rendered(
        "_MSG_NOT_CANONICAL",
        what=WHAT_STORE,
        reason=f"integer out of I-JSON safe range: {INT_LIMIT}",
    )


@pytest.mark.parametrize("total_depth", [255, 256])
def test_a_document_at_or_under_the_nesting_ceiling_is_admitted(total_depth: int) -> None:
    tree = deep_document(total_depth)
    store = parse_store(serialize(tree))
    assert ordered(store.data()) == ordered(tree)


def test_a_document_one_level_over_the_nesting_ceiling_is_refused() -> None:
    refused_as(lambda: parse_store(serialize(deep_document(MAX_DEPTH + 1))), "M7")


def test_a_document_of_exactly_the_admission_ceiling_is_admitted() -> None:
    """The ceiling is inclusive, and whitespace is a legal way to reach it."""
    body = serialize(SMALL_DOCUMENT)
    payload = body[:-1] + b" " * (CEILING_BYTES - len(body)) + b"}"
    assert len(payload) == CEILING_BYTES
    store = parse_store(payload)
    assert ordered(store.data()) == ordered(SMALL_DOCUMENT)


def test_a_document_one_byte_over_the_admission_ceiling_is_refused_by_size() -> None:
    """M2, not M7: the size gate answers before anything is decoded or parsed."""
    payload = b"{" * (CEILING_BYTES + 1)
    refused_as(lambda: parse_store(payload), "M2")


def test_an_oversized_live_object_is_refused_as_a_live_object_not_as_a_size() -> None:
    """M1 precedes M2: what the caller HANDED OVER is decided before its length."""
    payload = bytearray(b"{" * (CEILING_BYTES + 1))
    refused_as(lambda: parse_store(payload), "M1")


def test_every_truncation_of_a_valid_document_is_refused_as_unparsable() -> None:
    """No prefix of a document is a document, at any offset.

    Collected rather than asserted one offset at a time: the interesting answer
    is WHICH offsets survive, and a test that stops at the first one hides the
    shape of the hole.
    """
    valid = serialize(SMALL_DOCUMENT)
    survivors: list[str] = []
    for offset in range(len(valid)):
        try:
            parse_store(valid[:offset])
        except trust_material.TrustMaterialError as exc:
            if classify(exc) != "M7":
                survivors.append(f"{offset}: refused as {str(exc)!r}")
            continue
        survivors.append(f"{offset}: accepted")
    assert not survivors, "\n".join(survivors[:20])


# ---------------------------------------------------------------------------
# INV-3: the whole unit is refused, and the refusal names the right member.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "payload"),
    DUPLICATE_KEY_DOCUMENTS,
    ids=[name for name, _ in DUPLICATE_KEY_DOCUMENTS],
)
def test_a_duplicated_member_is_refused_at_every_level_never_resolved(
    name: str, payload: bytes
) -> None:
    """Neither last-wins nor first-wins: a document that says two things is refused."""
    refused_as(lambda: parse_store(payload), "M7")


@pytest.mark.parametrize(
    "unknown", UNKNOWN_MEMBER_NAMES, ids=[repr(n) for n in UNKNOWN_MEMBER_NAMES]
)
def test_an_unknown_member_is_refused_and_named_as_the_caller_spelled_it(unknown: str) -> None:
    mutant = dict(SMALL_DOCUMENT)
    mutant[unknown] = {}
    exc = refused_as(lambda: parse_store(serialize(mutant)), "M5")
    assert str(exc) == rendered("_MSG_UNKNOWN_MEMBER", name=ascii(unknown))


def test_the_container_grammar_decides_every_type_substitution() -> None:
    """The whole (member, depth, substitute) matrix, judged by the grammar itself."""
    disagreements: list[str] = []
    for label, mutant, member, should_pass in type_matrix_cases():
        payload = serialize(mutant)
        if should_pass:
            try:
                store = parse_store(payload)
            except trust_material.TrustMaterialError as exc:
                disagreements.append(f"{label}: refused as {str(exc)!r}")
                continue
            if ordered(store.data()) != ordered(mutant):
                disagreements.append(f"{label}: admitted but not conserved")
            continue
        try:
            parse_store(payload)
        except trust_material.TrustMaterialError as exc:
            if classify(exc) != "M6":
                disagreements.append(f"{label}: expected M6, got {str(exc)!r}")
            elif exc.member != member:
                disagreements.append(f"{label}: blamed {exc.member!r} instead of {member!r}")
            elif str(exc) != rendered(
                "_MSG_MEMBER_SHAPE", member=ascii(member), expected=expected_phrase(member)
            ):
                disagreements.append(f"{label}: unexpected wording {str(exc)!r}")
            continue
        disagreements.append(f"{label}: accepted a document the grammar refuses")
    assert not disagreements, "\n".join(disagreements[:40])


@pytest.mark.parametrize("member", MEMBER_ORDER)
def test_a_member_present_as_null_is_not_treated_as_an_absent_member(member: str) -> None:
    mutant = dict(RICH_DOCUMENT)
    mutant[member] = None
    refused_as(lambda: parse_store(serialize(mutant)), "M6", member=member)


@pytest.mark.parametrize("member", REQUIRED_MEMBERS)
def test_a_missing_required_member_is_refused_and_named(member: str) -> None:
    mutant = document(PLAIN_ISSUERS[:1], absent=[member])
    refused_as(lambda: parse_store(serialize(mutant)), "M6", member=member)


def test_the_empty_document_is_refused_naming_the_first_member_of_the_order() -> None:
    refused_as(lambda: parse_store(b"{}"), "M6", member=MEMBER_ORDER[0])


@pytest.mark.parametrize(
    "payload",
    [b"[]", b'"a document"', b"1", b"null", b"true", b'[{"manifests":{}}]'],
    ids=["array", "string", "number", "null", "boolean", "array of the document"],
)
def test_a_document_that_is_not_an_object_is_refused_before_the_grammar(payload: bytes) -> None:
    refused_as(lambda: parse_store(payload), "M4")


# The defects of section 5.1.1's order, each with the rank of the gate that
# catches it. A document carrying several must be refused by the LOWEST rank
# present -- which is the property, not a list of pairs someone wrote down.
DOCUMENT_DEFECTS: tuple[tuple[str, int, str, Callable[[Any], Any]], ...] = (
    ("out of range integer", 10, "document", lambda d: _with_probe(d, INT_LIMIT)),
    (
        "malformed artifact_manifest_chains",
        9,
        "document",
        lambda d: {**d, "artifact_manifest_chains": 1},
    ),
    ("malformed artifact_manifests", 8, "document", lambda d: {**d, "artifact_manifests": 1}),
    ("malformed chains", 7, "document", lambda d: {**d, "chains": 1}),
    ("malformed provenance", 6, "document", lambda d: {**d, "provenance": 1}),
    ("malformed manifests", 5, "document", lambda d: {**d, "manifests": 1}),
    ("unknown member", 4, "document", lambda d: {**d, "Manifests": {}}),
    ("not an object", 3, "document", lambda d: [d]),
    ("byte order mark", 2, "text", lambda b: b"\xef\xbb\xbf" + b),
    ("truncated", 2, "text", lambda b: b[: len(b) // 2]),
    ("handed over as str", 0, "delivery", lambda b: b.decode()),
)
DEFECT_CLASS = {
    10: "M8",
    9: "M6",
    8: "M6",
    7: "M6",
    6: "M6",
    5: "M6",
    4: "M5",
    3: "M4",
    2: "M7",
    0: "M1",
}


def _with_probe(tree: dict[str, Any], value: object) -> dict[str, Any]:
    issuer = next(iter(tree["manifests"]))
    manifests = dict(tree["manifests"])
    manifests[issuer] = {**manifests[issuer], "probe": value}
    return {**tree, "manifests": manifests}


def _apply_defects(names: Sequence[str]) -> object:
    """Apply the named defects to a valid document, deepest gate applied first.

    Applied in DESCENDING rank order so a defect that subsumes another (a
    replaced member, a document that is no longer an object) is applied after
    the one it swallows: the survivor is then always the lowest-ranked defect,
    which is exactly what the order predicts.
    """
    chosen = [defect for defect in DOCUMENT_DEFECTS if defect[0] in names]
    chosen.sort(key=lambda defect: defect[1], reverse=True)
    tree: Any = RICH_DOCUMENT
    for _, _, layer, apply in chosen:
        if layer == "document":
            tree = apply(tree)
    payload: Any = serialize(tree)
    for _, _, layer, apply in chosen:
        if layer == "text":
            payload = apply(payload)
    for _, _, layer, apply in chosen:
        if layer == "delivery":
            payload = apply(payload)
    return payload


@given(
    names=st.lists(
        st.sampled_from([d[0] for d in DOCUMENT_DEFECTS]), min_size=2, max_size=4, unique=True
    )
)
@PROPERTY_SETTINGS
def test_a_document_with_several_defects_is_refused_by_the_first_gate_only(
    names: list[str],
) -> None:
    ranks = [defect[1] for defect in DOCUMENT_DEFECTS if defect[0] in names]
    expected = DEFECT_CLASS[min(ranks)]
    exc = refusal(lambda: parse_store(_apply_defects(names)))
    assert classify(exc) == expected, f"{sorted(names)} -> {str(exc)!r}"


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        (("malformed chains", "out of range integer"), "M6"),
        (("unknown member", "malformed manifests"), "M5"),
        (("malformed manifests", "malformed chains"), "M6"),
        (("not an object", "out of range integer"), "M4"),
        (("byte order mark", "unknown member"), "M7"),
        (("handed over as str", "byte order mark"), "M1"),
    ],
    ids=[
        "chains-before-int",
        "unknown-before-shape",
        "manifests-before-chains",
        "object-before-int",
        "parse-before-unknown",
        "contract-before-parse",
    ],
)
def test_the_named_two_defect_documents_pin_the_evaluation_order(
    names: tuple[str, ...], expected: str
) -> None:
    exc = refusal(lambda: parse_store(_apply_defects(names)))
    assert classify(exc) == expected, str(exc)


def test_the_member_blamed_for_a_shape_failure_is_the_member_at_fault() -> None:
    """One document per member, each malformed alone, each accusing itself."""
    for member in MEMBER_ORDER:
        mutant = dict(RICH_DOCUMENT)
        mutant[member] = 1
        exc = refused_as(lambda: parse_store(serialize(mutant)), "M6", member=member)  # noqa: B023
        assert ascii(member) in str(exc)


# ---------------------------------------------------------------------------
# INV-4: refused before the object is touched.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "factory"), BYTE_IMPOSTORS, ids=[name for name, _ in BYTE_IMPOSTORS]
)
def test_an_object_offered_in_place_of_the_bytes_is_refused_untouched(
    name: str, factory: ByteImpostorFactory
) -> None:
    """The empty registry is the property; the exception alone would not prove it.

    A boundary that refuses AFTER calling `len()`, `bytes()` or `__class__` has
    already run the caller's code, and that is the whole class of defect this
    front exists to close.
    """
    for parse, what in ((parse_store, WHAT_STORE), (parse_manifest, WHAT_MANIFEST)):
        recorder = Recorder()
        impostor = factory(recorder, serialize(SMALL_DOCUMENT))
        exc = refusal(lambda: parse(impostor))  # noqa: B023
        witnessed = list(recorder.calls)
        assert str(exc) == rendered("_MSG_NOT_BYTES", what=what)
        assert exc.member is None
        assert witnessed == [], f"{name} ran {witnessed} before being refused"


def test_the_factory_takes_one_argument_and_says_so() -> None:
    with pytest.raises(TypeError):
        store_class().from_bytes(serialize(SMALL_DOCUMENT), "extra")
    with pytest.raises(TypeError):
        manifest_class().from_bytes(serialize(RICH_DOCUMENT["manifests"]), "extra")


def test_exact_bytes_are_admitted_however_they_were_built() -> None:
    payload = serialize(SMALL_DOCUMENT)
    from_literal = parse_store(payload)
    from_buffer = parse_store(bytes(bytearray(payload)))
    assert from_literal.to_bytes() == from_buffer.to_bytes()


# ---------------------------------------------------------------------------
# D15: custody of the snapshot classes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("which", ["store", "manifest"])
def test_a_snapshot_cannot_be_built_by_calling_its_class(which: str) -> None:
    """Only the factory admits data, and the refusal never touches what it refused."""
    cls = store_class() if which == "store" else manifest_class()
    recorder = Recorder()
    live = BytesImpostor(recorder, b"{}")

    with pytest.raises(TypeError):
        cls(live)
    with pytest.raises(TypeError):
        cls(object(), live)
    with pytest.raises(TypeError) as caught:
        cls(object(), live, b"{}")
    assert str(caught.value) == CUSTODY_MESSAGE.format(name=cls.__name__)
    assert recorder.calls == [], f"the refused object ran {recorder.calls}"


def test_the_old_keyword_shape_no_longer_builds_a_store() -> None:
    """The pre-F6 spelling is refused by argument binding, which is Python's message."""
    with pytest.raises(TypeError):
        store_class()(manifests={}, provenance={})


@pytest.mark.parametrize("which", ["store", "manifest"])
def test_a_snapshot_smuggled_past_the_factory_has_nothing_to_export(which: str) -> None:
    """A documented residue, pinned so it stays a residue and not a silent success.

    `__new__` still hands back an instance with no slots filled. The point is
    that it cannot ANSWER: an empty handle raises instead of exporting an empty
    document, which would be a store that lost everything it was given.
    """
    cls = store_class() if which == "store" else manifest_class()
    orphan = cls.__new__(cls)
    with pytest.raises(AttributeError):
        orphan.to_bytes()


def test_a_snapshot_carries_no_instance_dictionary() -> None:
    store = parse_store(serialize(SMALL_DOCUMENT))
    with pytest.raises(AttributeError):
        _ = store.__dict__


# ---------------------------------------------------------------------------
# INV-5: nothing is shared with the caller, and nothing is shared between calls.
# ---------------------------------------------------------------------------


def test_the_snapshot_hands_back_a_fresh_tree_every_time() -> None:
    store = parse_store(serialize(RICH_DOCUMENT))
    first = store.data()
    second = store.data()
    assert first is not second
    assert first["manifests"] is not second["manifests"]
    assert ordered(first) == ordered(second)


def test_mutating_what_the_snapshot_handed_back_changes_nothing() -> None:
    store = parse_store(serialize(RICH_DOCUMENT))
    before = store.to_bytes()
    handed = store.data()
    handed["manifests"].clear()
    handed["provenance"]["injected"] = "operator"
    handed["chains"] = None
    assert store.to_bytes() == before
    assert ordered(store.data()) == ordered(RICH_DOCUMENT)


def test_mutating_a_held_manifest_changes_neither_it_nor_the_store() -> None:
    store = parse_store(serialize(RICH_DOCUMENT))
    issuer = PLAIN_ISSUERS[0]
    held = store.manifest_for(issuer)
    first = held.data()
    assert first is not held.data()
    first["keys"] = []
    assert ordered(held.data()) == ordered(RICH_DOCUMENT["manifests"][issuer])
    assert ordered(store.data()) == ordered(RICH_DOCUMENT)


def test_the_exported_bytes_are_stable_across_calls() -> None:
    store = parse_store(serialize(RICH_DOCUMENT))
    assert store.to_bytes() == store.to_bytes()


# ---------------------------------------------------------------------------
# D18: selectors answer before they hash.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "factory"), HOSTILE_SELECTORS, ids=[name for name, _ in HOSTILE_SELECTORS]
)
def test_a_selector_that_is_not_exactly_str_is_answered_before_it_is_touched(
    name: str, factory: SelectorFactory
) -> None:
    store = parse_store(serialize(document(PLAIN_ISSUERS)))
    recorder = Recorder()
    selector = factory(recorder)
    assert store.manifest_for(selector) is None
    assert store.chain_for(selector) == ()
    assert store.provenance_for(selector) is None
    assert recorder.calls == [], f"{name} ran {recorder.calls} during the lookup"


@given(
    selector=st.one_of(
        st.integers(),
        st.none(),
        st.booleans(),
        st.binary(),
        st.floats(allow_nan=True),
        st.lists(st.integers()),
        st.dictionaries(st.text(), st.integers()),
        st.tuples(st.text()),
    )
)
@PROPERTY_SETTINGS
def test_no_value_that_is_not_a_string_ever_selects_anything(selector: object) -> None:
    store = parse_store(serialize(document(PLAIN_ISSUERS)))
    assert store.manifest_for(selector) is None
    assert store.chain_for(selector) == ()
    assert store.provenance_for(selector) is None


def test_an_object_shaped_name_selects_only_when_the_document_carried_it() -> None:
    """`__proto__` is a member name here, never a way into the mapping's machinery."""
    without = parse_store(serialize(document(PLAIN_ISSUERS)))
    for name in SPECIAL_ISSUERS:
        assert without.manifest_for(name) is None
        assert without.chain_for(name) == ()
        assert without.provenance_for(name) is None
    carried = parse_store(serialize(document(SPECIAL_ISSUERS)))
    for name in SPECIAL_ISSUERS:
        assert carried.manifest_for(name) is not None
        assert carried.provenance_for(name) == "tls"


# ---------------------------------------------------------------------------
# The key-manifest snapshot: the same entry, one grammar rule only.
# ---------------------------------------------------------------------------


def test_a_key_manifest_document_survives_the_snapshot_unchanged() -> None:
    tree = key_manifest_tree(PLAIN_ISSUERS[0], 1)
    held = parse_manifest(serialize(tree))
    assert ordered(held.data()) == ordered(tree)
    assert held.data() is not held.data()
    assert held.to_bytes() == held.to_bytes()


@pytest.mark.parametrize(
    "payload",
    [b"[]", b'"m"', b"1", b"null", b"true"],
    ids=["array", "string", "number", "null", "boolean"],
)
def test_a_key_manifest_that_is_not_an_object_is_refused(payload: bytes) -> None:
    refused_as(lambda: parse_manifest(payload), "M4", what=WHAT_MANIFEST)


def test_a_key_manifest_is_refused_for_the_same_lexical_reasons_as_a_store() -> None:
    refused_as(lambda: parse_manifest(b'{"a":1.5}'), "M7", what=WHAT_MANIFEST)
    refused_as(
        lambda: parse_manifest(b'{"a":' + str(INT_LIMIT).encode() + b"}"),
        "M8",
        what=WHAT_MANIFEST,
    )
    refused_as(lambda: parse_manifest(b"{" * (CEILING_BYTES + 1)), "M2", what=WHAT_MANIFEST)


def test_the_key_manifest_boundary_applies_no_container_grammar() -> None:
    """Only "it is an object": the contents of a manifest are not this gate's business."""
    tree = {"anything": [1, {"nested": True}], "": None}
    held = parse_manifest(serialize(tree))
    assert ordered(held.data()) == ordered(tree)


# ---------------------------------------------------------------------------
# Section 5.6(d): custody of construction, proved on the module's syntax tree
# -- not by counting substrings. NEW-DEFECT-01 (section 4.1) was a substring
# count and pinned nothing: it could not name the containing function, could
# not see an alias or a `Reflect.construct` equivalent, and stayed unchanged
# when a call site's ARGUMENTS changed -- which is exactly the edit that would
# reopen the custody hole. It also had the wrong numbers: the factories write
# `cls(_ADMIT, ...)`, so a literal count of `KeyManifest(_ADMIT`/`TrustStore(_ADMIT`
# does not even match the source it was meant to pin.
#
# What the runtime custody tests earlier in this file prove
# (`test_a_snapshot_cannot_be_built_by_calling_its_class` and neighbors) is
# that the PUBLIC constructor rejects an outside caller. They cannot prove
# that every construction INSIDE the module supplies the token in the
# required form: none of those tests can reach a call site that used an
# alias, a reduced expression, or `__new__` directly, because none of those
# forms are reachable from outside the module. That is the residue section
# 4.1 names in its own words: "the token proves the constructor was called BY
# the module, not that the module calls it only FROM the parser." This
# section closes it, statically, by reading the module's own syntax tree.
#
# `import ast`/`import inspect`/`import pathlib` are LOCAL to each function
# below, not at the top of this file: the two test files this front may touch
# are append-only (a shared writer edits `verifiers/ts/**` in the same
# worktree), so a module-level import here is not available, and keeping the
# checker self-contained in one function avoids needing one.
# ---------------------------------------------------------------------------


def custody_violations(tree: Any) -> tuple[list[str], frozenset[tuple[str, str | None]]]:
    """Read `tree`'s constructions of `KeyManifest`/`TrustStore`, and judge them.

    Returns `(violations, constructions_found)`. `constructions_found` is
    `{(handle, qualified_function), ...}` for every construction the walk
    resolved, whether it passed custody or not -- the non-vacuity test below
    asserts against it, so a checker that silently finds nothing cannot pass
    by reporting no violations for the wrong reason.

    Checked, per construction: (a) the containing function is one of the four
    factories this file declares by name; (b) the first positional argument
    is exactly the module's token, by identity of the AST node
    (`ast.Name(id="_ADMIT")`), never an equivalent expression; (c) the
    construction is not reached through a bound alias of the constructor, and
    the module contains no direct `__new__` call on either handle -- both are
    treated as violations regardless of which function they sit in, since
    neither is a "call site" a factory list could ever legitimize.

    Reusable by design: the four prove-negative tests below run this SAME
    function against a MUTATED copy of the real module's source, never only
    against the module as written -- section 5.6(d)'s own words are "senza
    queste il test e' una decorazione" (without these the test is a prop).
    """
    import ast

    handle_names = ("KeyManifest", "TrustStore")
    sentinel_name = "_ADMIT"
    allowed_factories = frozenset(
        {
            "KeyManifest.from_bytes",
            "TrustStore.from_bytes",
            "TrustStore.manifest_for",
            "TrustStore.chain_for",
        }
    )

    # Pass 1: every name bound directly to a handle class -- `_K = KeyManifest`,
    # at any scope. Binding a FACTORY (`_K = KeyManifest.from_bytes`) is not
    # this: its value is an `Attribute`, not the bare class name, so it cannot
    # forge the constructor.
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            if node.value.id in handle_names:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        aliases[target.id] = node.value.id

    constructions: list[tuple[str, str | None, int, list[Any]]] = []
    reflect_violations: list[str] = []
    class_stack: list[str] = []
    function_stack: list[str] = []

    def handle_of_name(name: str) -> tuple[str, bool] | None:
        """The handle a bare NAME refers to: itself, `cls`, or a bound alias.

        The second element is True iff the name is an alias, which is itself
        the violation D5's Reflect-equivalent rule refuses -- reported by the
        caller regardless of which function the call sits in.
        """
        if name in handle_names:
            return (name, False)
        current = class_stack[-1] if class_stack else None
        if name == "cls" and current in handle_names:
            return (current, False)
        if name in aliases:
            return (aliases[name], True)
        return None

    def qualified_function() -> str | None:
        if not function_stack:
            return None
        current = class_stack[-1] if class_stack else None
        name = function_stack[-1]
        return f"{current}.{name}" if current is not None else name

    class _Visitor(ast.NodeVisitor):
        """Walks the tree tracking the innermost class/function by hand.

        `ast` gives no parent pointers, and both the containing FACTORY name
        and whether `cls`/`type(self)` resolves to a handle class depend on
        that context.
        """

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            class_stack.append(node.name)
            self.generic_visit(node)
            class_stack.pop()

        def _enter_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._enter_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._enter_function(node)

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            resolved: tuple[str, bool] | None = None
            if isinstance(func, ast.Name):
                resolved = handle_of_name(func.id)
            elif (
                isinstance(func, ast.Call)
                and isinstance(func.func, ast.Name)
                and func.func.id == "type"
                and len(func.args) == 1
                and isinstance(func.args[0], ast.Name)
                and func.args[0].id == "self"
            ):
                # `type(self)(...)`, the plan's fourth callee shape.
                current = class_stack[-1] if class_stack else None
                if current in handle_names:
                    resolved = (current, False)
            if resolved is not None:
                handle, is_alias = resolved
                if is_alias:
                    reflect_violations.append(
                        f"line {node.lineno}: {handle} constructed through an alias "
                        "of its constructor"
                    )
                else:
                    constructions.append(
                        (handle, qualified_function(), node.lineno, list(node.args))
                    )
            if isinstance(func, ast.Attribute) and func.attr == "__new__":
                base = func.value
                if isinstance(base, ast.Name):
                    found = handle_of_name(base.id)
                    if found is not None:
                        reflect_violations.append(
                            f"line {node.lineno}: {found[0]}.__new__ called directly"
                        )
            self.generic_visit(node)

    _Visitor().visit(tree)

    violations = list(reflect_violations)
    for handle, qualified, lineno, args in constructions:
        if qualified not in allowed_factories:
            violations.append(
                f"line {lineno}: {handle} constructed in {qualified!r}, "
                "which is not a declared factory"
            )
            continue
        if not args or not (isinstance(args[0], ast.Name) and args[0].id == sentinel_name):
            got = ast.dump(args[0]) if args else "<no arguments>"
            violations.append(
                f"line {lineno}: {handle} in {qualified!r} does not pass "
                f"{sentinel_name} as the first argument (got {got})"
            )
    found = frozenset((handle, qualified) for handle, qualified, _, _ in constructions)
    return violations, found


def cross_module_constructions(package_dir: Any, *, exclude: str) -> list[str]:
    """Every `Call` in another module under `package_dir` naming a handle class.

    Cheaper than `custody_violations`: no module outside `trust_material` is
    inside the handle classes, so there is no `cls`/alias context to resolve
    -- only every spelling a caller could use at a call site, bare
    (`TrustStore(...)`) or qualified (`verify.TrustStore(...)`).
    """
    import ast
    import pathlib

    handle_names = ("KeyManifest", "TrustStore")
    hits: list[str] = []
    root = pathlib.Path(package_dir)
    for path in sorted(root.rglob("*.py")):
        if path.name == exclude:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name: str | None = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in handle_names:
                hits.append(f"{path.name}:{node.lineno}")
    return hits


def _trust_material_tree() -> Any:
    """A fresh `ast.parse` of the module's own current source."""
    import ast
    import inspect

    return ast.parse(inspect.getsource(trust_material))


def test_every_construction_in_trust_material_passes_the_token_from_a_declared_factory() -> None:
    """5.6(d), positive half: the module's OWN constructions hold custody today.

    The runtime tests above prove the constructor rejects an outside caller;
    they never exercise the module's own call sites, which is the residue
    section 4.1 names. This is that residue, closed: every `Call` inside
    `trust_material` that builds a `KeyManifest`/`TrustStore` is read from a
    declared factory and hands over the module token by name, never through
    an alias, a reduced expression, or `__new__`.
    """
    violations, _ = custody_violations(_trust_material_tree())
    assert violations == []


def test_the_custody_checker_is_not_vacuous_on_the_real_module() -> None:
    """Non-vacuity: a checker that finds zero constructions passes for the
    wrong reason. Pinned against the four call sites section 5.1.2 writes
    today, by name -- an edit that adds or removes one fails this test and
    says which changed, instead of the positive test above passing on an
    empty walk.
    """
    _, found = custody_violations(_trust_material_tree())
    assert found == {
        ("KeyManifest", "KeyManifest.from_bytes"),
        ("TrustStore", "TrustStore.from_bytes"),
        ("KeyManifest", "TrustStore.manifest_for"),
        ("KeyManifest", "TrustStore.chain_for"),
    }


def _mutated_trust_material_source(old: str, new: str) -> str:
    """`inspect.getsource(trust_material)` with `old` replaced by `new`, once.

    Fails loudly if `old` is not found exactly once: a mutation whose target
    silently stopped matching would otherwise pin nothing while looking green,
    which is precisely the failure mode section 5.6(d) warns against for the
    checker itself -- the same discipline applies to the mutations that
    exercise it.
    """
    import inspect

    source = inspect.getsource(trust_material)
    count = source.count(old)
    assert count == 1, f"mutation target found {count} times, expected exactly 1: {old!r}"
    mutated = source.replace(old, new, 1)
    assert mutated != source, "the mutation did not change the source"
    return mutated


def test_a_construction_from_an_undeclared_factory_fails_custody() -> None:
    """Prove-negative (1/4): a factory this test never declared must fail the pin.

    The injected method is a syntactically ordinary one, sentinel and all --
    if the checker did not look at WHICH function contains the call, this
    would slip past as just another well-formed construction.
    """
    import ast

    marker = "    def chain_for(self, issuer_id: object) -> tuple[KeyManifest, ...]:"
    rogue_factory = (
        "    def _rogue_factory(self, data: object) -> KeyManifest:\n"
        "        return KeyManifest(_ADMIT, data, b'{}')\n\n"
    )
    mutant = _mutated_trust_material_source(marker, rogue_factory + marker)
    violations, _ = custody_violations(ast.parse(mutant))
    assert any("not a declared factory" in v and "_rogue_factory" in v for v in violations), (
        violations
    )


def test_a_token_reduced_through_a_local_variable_fails_custody() -> None:
    """Prove-negative (2/4): the first argument must be the token BY NAME.

    `token = _ADMIT; cls(token, ...)` still passes the very same object at
    runtime -- `token is _ADMIT` holds -- so only a check that reads the AST
    node itself, not the value it would evaluate to, can tell this apart from
    the real factory shape.
    """
    import ast

    old = (
        '        canonical = _canonical(parsed, what="key manifest")\n'
        "        return cls(_ADMIT, parsed, canonical)"
    )
    new = (
        '        canonical = _canonical(parsed, what="key manifest")\n'
        "        token = _ADMIT\n"
        "        return cls(token, parsed, canonical)"
    )
    mutant = _mutated_trust_material_source(old, new)
    violations, _ = custody_violations(ast.parse(mutant))
    assert any(
        "does not pass _ADMIT as the first argument" in v and "KeyManifest.from_bytes" in v
        for v in violations
    ), violations


def test_a_constructor_bound_to_an_alias_and_called_fails_custody() -> None:
    """Prove-negative (3/4): `_K = KeyManifest; _K(_ADMIT, ...)` is a
    Reflect-equivalent under a different name, and must be refused regardless
    of which function it sits in or what it passes as its first argument.
    """
    import ast

    sentinel_decl = "_ADMIT: Final = object()"
    alias_bound = _mutated_trust_material_source(
        sentinel_decl, sentinel_decl + "\n_K = KeyManifest"
    )
    call_site = "        return KeyManifest(_ADMIT, found, canon.canonical_bytes(found))"
    assert alias_bound.count(call_site) == 1, "the call site to alias moved"
    mutant = alias_bound.replace(
        call_site, "        return _K(_ADMIT, found, canon.canonical_bytes(found))", 1
    )
    assert mutant != alias_bound
    violations, _ = custody_violations(ast.parse(mutant))
    assert any("constructed through an alias of its constructor" in v for v in violations), (
        violations
    )


def test_a_direct_dunder_new_construction_fails_custody() -> None:
    """Prove-negative (4/4): `KeyManifest.__new__(KeyManifest)` never goes
    through `__init__`, so it never sees the token check at all -- the
    checker must catch the SHAPE of the call, not rely on the runtime guard.
    """
    import ast

    call_site = "        return KeyManifest(_ADMIT, found, canon.canonical_bytes(found))"
    mutant = _mutated_trust_material_source(
        call_site, "        return KeyManifest.__new__(KeyManifest)"
    )
    violations, _ = custody_violations(ast.parse(mutant))
    assert any("__new__ called directly" in v for v in violations), violations


@pytest.mark.xfail(
    strict=True,
    reason=(
        "T1 residue, closed at T2 (plan section 5.1.3): verify.TrustStore is still the "
        "live dataclass at T1, and four call sites construct it directly instead of "
        "going through trust_material's handle -- measured 2026-09-08 on this worktree: "
        "bundle.py:932 (import_bundle), cli.py:656 (_load_trust_dir), cli.py:1430 "
        "(revoke), and verify.py:336 (_materialized_trust_store, where the bare name "
        "`TrustStore` resolves to verify.py's own dataclass, not trust_material's). "
        "T2 removes the dataclass and every one of these constructions; this pin turns "
        "green on its own when it does, which is the point of leaving it xfail rather "
        "than skipped."
    ),
)
def test_no_other_module_in_attest_constructs_a_handle_directly() -> None:
    """5.6(d), cross-module half: "negli altri moduli di attest non esiste
    alcun Call a quei due nomi."
    """
    import pathlib

    package_dir = pathlib.Path(trust_material.__file__).parent
    hits = cross_module_constructions(package_dir, exclude="trust_material.py")
    assert hits == []
