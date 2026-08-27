"""Hypothesis strategies that mutate a well-formed v0.1 §7.1 key manifest.

The group-41 conformance vectors are a CLOSED list of hand-picked examples, so
they share the blind spots of whoever wrote them. These strategies exist to
cover by PROPERTY what an example list cannot: each named strategy takes one
well-formed key manifest and returns mutated versions of it, one malformation
class per strategy so a caller composes exactly the classes it needs.

Nothing here re-signs the mutated manifest. A mutation is a hostile edit, and
whether the result should be re-signed (a hostile issuer publishing an
ambiguity) or left with the original, now-stale signature (a hostile relay
editing bytes in flight) is the caller's question, not the strategy's.

Every generated value is JSON-representable, but NOT every value is inside the
attest-JCS profile (`attest.canon` rejects floats and integers outside
±2**53): `noninteger_manifest_version` deliberately generates both, because
"what a conforming verifier does with a manifest whose `manifest_version` is
2.5" is precisely the question a closed vector list leaves unanswered.
"""

from __future__ import annotations

import copy
from typing import Any

from hypothesis import strategies as st

# --- §7.1 field inventories --------------------------------------------------

MANIFEST_REQUIRED_FIELDS: tuple[str, ...] = (
    "issuer",
    "manifest_version",
    "issued_at",
    "keys",
    "manifest_signature",
)

# §7.1 marks `valid_to` OPTIONAL ("absent or null = open-ended"), so it is not
# a removal target — it IS a wrong-type target, since the code reads it.
KEY_ENTRY_REQUIRED_FIELDS: tuple[str, ...] = ("kid", "pub", "valid_from", "status")

SIGNATURE_BLOCK_REQUIRED_FIELDS: tuple[str, ...] = ("kid", "sig")

KEY_STATUSES: tuple[str, ...] = ("active", "retired", "compromised")

LEVELS: tuple[str, ...] = ("manifest", "key_entry", "manifest_signature")

# The fields the reference implementation actually READS off a manifest, with
# the level each one lives at. Mutating anything else is noise; mutating these
# is how a wrong-typed member reaches a comparison or a parser.
TYPED_FIELD_TARGETS: tuple[tuple[str, str], ...] = (
    ("key_entry", "status"),
    ("key_entry", "kid"),
    ("key_entry", "pub"),
    ("key_entry", "valid_from"),
    ("key_entry", "valid_to"),
    ("manifest", "issued_at"),
    ("manifest", "issuer"),
)

# --- mutation value pools ----------------------------------------------------

# `manifest_version` is an integer by §7.1. `True`/`False` are the dangerous
# ones: `bool` subclasses `int`, so a naive `isinstance(v, int)` accepts them
# and `True + 1 == 2` makes a boolean look like a version bump.
NON_INTEGER_MANIFEST_VERSIONS: tuple[object, ...] = (
    True,
    False,
    "1",
    "2",
    "two",
    "",
    None,
    1.0,
    2.0,
    2.5,
    -1.5,
    2**53,
    2**53 + 1,
    -(2**53) - 1,
    2**64,
    [2],
    {"n": 2},
)

WRONG_TYPE_VALUES: tuple[object, ...] = (
    None,
    True,
    False,
    0,
    1,
    -1,
    2**53 + 1,
    1.5,
    "",
    " ",
    [],
    {},
    ["active"],
    {"status": "active"},
)

# Names no §7.1 member uses. Two of them differ from a real member by case
# only, and two are the prototype-pollution pair a JS verifier has to survive.
UNKNOWN_FIELD_NAMES: tuple[str, ...] = (
    "alg",
    "note",
    "comment",
    "__proto__",
    "constructor",
    "x-attest-extra",
    "0",
    "",
    " ",
    "Issuer",
    "KEYS",
)

EXTRA_FIELD_VALUES: tuple[object, ...] = (
    None,
    True,
    0,
    "x",
    "compromised",
    [],
    {},
    {"nested": [1, 2]},
)

NON_LIST_KEYS: tuple[object, ...] = (None, True, 0, "", "[]", {}, {"0": {}})

NON_DICT_ENTRIES: tuple[object, ...] = (None, True, False, 0, -1, "", "kid", [], ["kid"])

# Strings whose truncation is interesting: a base64url payload cut in half no
# longer decodes to 32 (or 64) bytes, and a timestamp cut in half no longer
# parses — both must be refusals, not exceptions.
CUTTABLE_TARGETS: tuple[tuple[str, str], ...] = (
    ("key_entry", "pub"),
    ("key_entry", "kid"),
    ("key_entry", "valid_from"),
    ("manifest_signature", "sig"),
    ("manifest_signature", "kid"),
    ("manifest", "issuer"),
    ("manifest", "issued_at"),
)

TRUNCATION_SHAPES: tuple[str, ...] = (
    "empty_keys",
    "keys_not_a_list",
    "entry_not_a_dict",
    "cut_string",
)

# Every value here is `!= "compromised"` under Python equality, which is the
# comparison `manifests._check_keyset_preservation` and
# `manifests._preserves_absorbing_compromises` both make.
NON_COMPROMISED_STATUSES: tuple[object, ...] = (
    "active",
    "retired",
    "revoked",
    "Compromised",
    "COMPROMISED",
    "compromised ",
    " compromised",
    "",
    None,
    True,
    0,
    ["compromised"],
    {"status": "compromised"},
)

# Malformed-but-dict `keys[]` members, used as unrelated noise around the
# entry under test.
JUNK_ENTRIES: tuple[dict[str, Any], ...] = (
    {},
    {"kid": None, "status": "active"},
    {"kid": 12345, "status": "compromised"},
    {"status": "compromised"},
    {"kid": "other.example/keys/x#ed25519-9", "status": "active"},
)


# --- helpers -----------------------------------------------------------------


def _entries_of(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """The `keys[]` array of a manifest these strategies assume WELL-FORMED.

    Malformation is what the strategies produce, never what they consume: a
    caller handing in an already-broken base manifest gets a `TypeError` here
    rather than silently thinner coverage.
    """
    entries = manifest.get("keys")
    if not isinstance(entries, list) or not entries:
        raise TypeError("base manifest must carry a non-empty keys[] array")
    if not all(isinstance(entry, dict) for entry in entries):
        raise TypeError("base manifest keys[] must hold only objects")
    return entries


def _container(manifest: dict[str, Any], level: str, entry_index: int) -> dict[str, Any]:
    if level == "manifest":
        return manifest
    if level == "manifest_signature":
        block = manifest["manifest_signature"]
        if not isinstance(block, dict):
            raise TypeError("base manifest_signature must be an object")
        return block
    return _entries_of(manifest)[entry_index]


def _index_of_kid(entries: list[dict[str, Any]], kid: str) -> int:
    for index, entry in enumerate(entries):
        if entry.get("kid") == kid:
            return index
    raise ValueError(f"base manifest holds no entry for kid {kid!r}")


# --- one named strategy per malformation class -------------------------------


@st.composite
def duplicate_kid(draw: st.DrawFn, manifest: dict[str, Any]) -> dict[str, Any]:
    """The same `kid` appears two or more times, at freely drawn positions.

    Position is the whole point: an implementation that reads the FIRST entry
    and one that reads the LAST must be able to disagree about the key's
    status, which is what makes a duplicate a security question rather than a
    tidiness one. Statuses are drawn independently, so equal-status duplicates
    (harmless-looking) and conflicting ones both occur.
    """
    mutated = copy.deepcopy(manifest)
    entries = _entries_of(mutated)
    source = draw(st.integers(min_value=0, max_value=len(entries) - 1))
    template = copy.deepcopy(entries[source])

    for _ in range(draw(st.integers(min_value=1, max_value=2))):
        duplicate = copy.deepcopy(template)
        duplicate["status"] = draw(st.sampled_from(KEY_STATUSES))
        entries.insert(draw(st.integers(min_value=0, max_value=len(entries))), duplicate)
    return mutated


def noninteger_manifest_version(manifest: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """`manifest_version` is anything but the §7.1 integer."""

    def _apply(value: object) -> dict[str, Any]:
        mutated = copy.deepcopy(manifest)
        mutated["manifest_version"] = value
        return mutated

    return st.sampled_from(NON_INTEGER_MANIFEST_VERSIONS).map(_apply)


@st.composite
def extra_field(draw: st.DrawFn, manifest: dict[str, Any]) -> dict[str, Any]:
    """An unknown member appears at one of the three levels a manifest has.

    Unknown members must be carried, not choked on: they are inside the signed
    body, so rejecting them would break eternal verifiability, and honouring
    them would let an attacker add meaning the spec never gave them.
    """
    mutated = copy.deepcopy(manifest)
    entries = _entries_of(mutated)
    level = draw(st.sampled_from(LEVELS))
    entry_index = draw(st.integers(min_value=0, max_value=len(entries) - 1))
    container = _container(mutated, level, entry_index)
    container[draw(st.sampled_from(UNKNOWN_FIELD_NAMES))] = draw(
        st.sampled_from(EXTRA_FIELD_VALUES)
    )
    return mutated


@st.composite
def missing_field(draw: st.DrawFn, manifest: dict[str, Any]) -> dict[str, Any]:
    """One §7.1 REQUIRED field removed, one at a time, at every level."""
    mutated = copy.deepcopy(manifest)
    entries = _entries_of(mutated)
    level = draw(st.sampled_from(LEVELS))
    entry_index = draw(st.integers(min_value=0, max_value=len(entries) - 1))
    container = _container(mutated, level, entry_index)
    if level == "manifest":
        removable = MANIFEST_REQUIRED_FIELDS
    elif level == "manifest_signature":
        removable = SIGNATURE_BLOCK_REQUIRED_FIELDS
    else:
        removable = KEY_ENTRY_REQUIRED_FIELDS
    container.pop(draw(st.sampled_from(removable)), None)
    return mutated


@st.composite
def truncated(draw: st.DrawFn, manifest: dict[str, Any]) -> dict[str, Any]:
    """Something ends before it should: the array, an entry, or a string.

    `cut_string` halves a value at a drawn offset, so a base64url `pub`/`sig`
    that no longer decodes to its fixed length, and a timestamp missing its
    `Z`, are both reachable.
    """
    mutated = copy.deepcopy(manifest)
    entries = _entries_of(mutated)
    shape = draw(st.sampled_from(TRUNCATION_SHAPES))

    if shape == "empty_keys":
        mutated["keys"] = []
        return mutated
    if shape == "keys_not_a_list":
        mutated["keys"] = draw(st.sampled_from(NON_LIST_KEYS))
        return mutated
    if shape == "entry_not_a_dict":
        index = draw(st.integers(min_value=0, max_value=len(entries) - 1))
        entries[index] = draw(st.sampled_from(NON_DICT_ENTRIES))  # type: ignore[call-overload]
        return mutated

    level, field = draw(st.sampled_from(CUTTABLE_TARGETS))
    entry_index = draw(st.integers(min_value=0, max_value=len(entries) - 1))
    container = _container(mutated, level, entry_index)
    original = container.get(field)
    if not isinstance(original, str):
        return mutated
    cut = draw(st.integers(min_value=0, max_value=max(len(original) - 1, 0)))
    container[field] = original[:cut]
    return mutated


@st.composite
def wrong_typed_field(draw: st.DrawFn, manifest: dict[str, Any]) -> dict[str, Any]:
    """A field the code READS carries the wrong JSON type.

    Restricted to the fields that actually drive a decision — `status`, `kid`,
    `pub`, `valid_from`, `valid_to`, `issued_at`, `issuer` — because those are
    where a wrong type turns into a comparison against the wrong thing rather
    than into ignored noise.
    """
    mutated = copy.deepcopy(manifest)
    entries = _entries_of(mutated)
    level, field = draw(st.sampled_from(TYPED_FIELD_TARGETS))
    entry_index = draw(st.integers(min_value=0, max_value=len(entries) - 1))
    container = _container(mutated, level, entry_index)
    container[field] = draw(st.sampled_from(WRONG_TYPE_VALUES))
    return mutated


def malformed_manifests(manifest: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """Every malformation class above, drawn from uniformly."""
    return st.one_of(
        duplicate_kid(manifest),
        noninteger_manifest_version(manifest),
        extra_field(manifest),
        missing_field(manifest),
        truncated(manifest),
        wrong_typed_field(manifest),
    )


# --- compromise-targeted strategies -----------------------------------------


@st.composite
def manifests_marking_kid_compromised(
    draw: st.DrawFn, manifest: dict[str, Any], kid: str
) -> dict[str, Any]:
    """Mutations that always leave AT LEAST ONE `keys[]` entry marking `kid`
    compromised, whatever else they do.

    Two shapes. `replace` is the unambiguous one — a single entry, and it says
    compromised — which is the honest reading of the marking and must survive
    every decoration below. `duplicate` re-statuses the existing entry freely
    and inserts a compromised twin at a drawn position, before or after it, so
    a first-value and a last-value reading of the array disagree.

    The optional decoration is restricted to mutations that cannot un-mark the
    kid, so the invariant this strategy's name promises holds by construction
    rather than by filtering.
    """
    mutated = copy.deepcopy(manifest)
    entries = _entries_of(mutated)
    index = _index_of_kid(entries, kid)
    template = copy.deepcopy(entries[index])

    if draw(st.sampled_from(("replace", "duplicate"))) == "replace":
        entries[index]["status"] = "compromised"
    else:
        entries[index]["status"] = draw(st.sampled_from(KEY_STATUSES))
        compromised = copy.deepcopy(template)
        compromised["status"] = "compromised"
        entries.insert(draw(st.integers(min_value=0, max_value=len(entries))), compromised)

    decoration = draw(
        st.sampled_from(("none", "extra_manifest_field", "noninteger_version", "cut_signature"))
    )
    if decoration == "extra_manifest_field":
        mutated[draw(st.sampled_from(UNKNOWN_FIELD_NAMES))] = draw(
            st.sampled_from(EXTRA_FIELD_VALUES)
        )
    elif decoration == "noninteger_version":
        mutated["manifest_version"] = draw(st.sampled_from(NON_INTEGER_MANIFEST_VERSIONS))
    elif decoration == "cut_signature":
        block = mutated["manifest_signature"]
        sig = block.get("sig")
        if isinstance(sig, str):
            block["sig"] = sig[: draw(st.integers(min_value=0, max_value=max(len(sig) - 1, 0)))]
    return mutated


@st.composite
def entries_resurrecting_kid(
    draw: st.DrawFn, entries: list[dict[str, Any]], kid: str
) -> list[dict[str, Any]]:
    """A successor `keys[]` array in which AT LEAST ONE entry for `kid` is not
    `compromised` — the resurrection §7.3 forbids.

    Two shapes: `rewrite` flips the single entry's status outright, while
    `duplicate` keeps the honest `compromised` entry AND adds a resurrecting
    twin, so neither a first-value nor a last-value read of the array is a way
    through. Statuses include wrong-typed and near-miss spellings
    (`"Compromised"`, `"compromised "`), which are all `!= "compromised"` and
    must therefore all count as resurrections.
    """
    mutated = copy.deepcopy(list(entries))
    index = _index_of_kid(mutated, kid)
    template = copy.deepcopy(mutated[index])
    status = draw(st.sampled_from(NON_COMPROMISED_STATUSES))

    if draw(st.sampled_from(("rewrite", "duplicate"))) == "rewrite":
        mutated[index]["status"] = status
    else:
        resurrected = copy.deepcopy(template)
        resurrected["status"] = status
        mutated.insert(draw(st.integers(min_value=0, max_value=len(mutated))), resurrected)

    decoration = draw(st.sampled_from(("none", "extra_field", "junk_entry")))
    if decoration == "extra_field":
        target = mutated[draw(st.integers(min_value=0, max_value=len(mutated) - 1))]
        target[draw(st.sampled_from(UNKNOWN_FIELD_NAMES))] = draw(
            st.sampled_from(EXTRA_FIELD_VALUES)
        )
    elif decoration == "junk_entry":
        junk = copy.deepcopy(draw(st.sampled_from(JUNK_ENTRIES)))
        mutated.insert(draw(st.integers(min_value=0, max_value=len(mutated))), junk)
    return mutated
