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

from attest.dates import is_strict_utc
from tests.helpers import non_canonical_spellings

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

# The timestamps the code PARSES to reach a verdict. `valid_to` is optional and
# may be absent or null, so a target is only a target when it actually holds a
# canonical string — which the strategy checks rather than assumes.
TIMESTAMP_TARGETS: tuple[tuple[str, str], ...] = (
    ("manifest", "issued_at"),
    ("key_entry", "valid_from"),
    ("key_entry", "valid_to"),
)

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


@st.composite
def non_canonical_timestamp(draw: st.DrawFn, manifest: dict[str, Any]) -> dict[str, Any]:
    """A parsed timestamp is spelled in a way `strptime` accepts and the
    canonical wire shape does not.

    This class is not "a wrong type" and not "a truncation": the value is a
    string, it parses, and it names the right instant — it simply is not the
    spelling the format defines. That is what made it dangerous: the mutation
    survives every shape check and only the parser can refuse it. Because the
    TypeScript core refuses these spellings outright, a Python path that
    accepts one is a cross-core disagreement on a signed field, not a cosmetic
    difference.

    DELIBERATELY OUT OF `malformed_manifests()`. It was in the union, and the
    green it produced there proved nothing about the parser. Measured
    2026-09-07, driving every mutant this class can build (each
    `TIMESTAMP_TARGETS` field that actually carries a canonical timestamp, on
    each entry, in each spelling of the shared corpus) through exactly what each
    consumer calls, with `attest.dates.parse_strict_utc` instrumented:

        test_views_properties (build_compromise_claim)          none parsed
        test_cli_views_builder_properties (ENTRY_CASES)         none parsed
        test_cli_views_builder_properties (CLAIM_41A)           none parsed
        test_manifest_mutation_properties (five entry points)   none parsed

    Zero, everywhere, and for a reason that does not depend on how many
    spellings there are: the signature this module deliberately leaves stale
    stops every mutant before any timestamp is read, so the class was only ever
    a seventh spelling of "a manifest whose signature no longer matches" —
    diluting the six classes that do discriminate by a seventh of every
    consumer's example budget.

    The absolute counts of that measurement are deliberately NOT restated here.
    `non_canonical_spellings` derives the corpus from what the installed
    CPython's `strptime` accepts, so its size is an output, not a constant, and
    a count written down in prose goes stale the next time it moves — which it
    did, on 2026-09-08.

    And re-signing would not rescue it here. Measured the same day:
    `manifests.verify_key_manifest` parses NO timestamp at all, signature valid
    or not — it checks shape and signature, never windows. Through
    `verify.verify()` a re-signed mutant reaches the parser only through
    `key_entry.valid_from` on the entry that actually signs the receipt — one
    of the four (entry, field) pairs a two-entry manifest offers. The rest stay
    `signature=valid`, correctly, because `manifest.issued_at` and a
    non-signing entry's bounds are not window bounds for that receipt. Two of
    the three `TIMESTAMP_TARGETS` are therefore not targets of this property at
    all, by construction.

    WHERE THE PARSING PATH IS ACTUALLY COVERED — deterministically, by name,
    so nobody has to rediscover this:

        tests/test_verify.py::test_non_canonical_valid_from_never_admits_a_receipt
        tests/test_verify.py::test_non_canonical_valid_to_never_admits_a_receipt
        tests/test_verify.py::test_non_canonical_revoked_at_never_authenticates_a_record
        tests/test_manifests.py::test_within_window_refuses_a_non_canonical_lower_bound
        tests/test_manifests.py::test_within_window_refuses_a_non_canonical_upper_bound
        tests/test_manifests.py::test_within_window_refuses_a_non_canonical_issued_at
        tests/test_revocation.py::test_non_canonical_revoked_at_does_not_verify
        tests/test_transfer.py::test_non_canonical_transferred_at_does_not_verify
        tests/test_dates.py  (the owner, plus the corpus-completeness sweep)

    Keep the class: it names a real malformation and a caller that DOES re-sign
    (a hostile issuer publishing an ambiguity, rather than a hostile relay
    editing bytes in flight) can compose it deliberately. Putting it back into
    the union without such a caller re-creates a vacuous green.
    """
    mutated = copy.deepcopy(manifest)
    entries = _entries_of(mutated)
    entry_index = draw(st.integers(min_value=0, max_value=len(entries) - 1))
    targets = [
        (level, field)
        for level, field in TIMESTAMP_TARGETS
        if is_strict_utc(_container(mutated, level, entry_index).get(field))
    ]
    if not targets:
        raise TypeError("base manifest must carry at least one canonical timestamp")
    level, field = draw(st.sampled_from(targets))
    container = _container(mutated, level, entry_index)
    _, spelling = draw(st.sampled_from(non_canonical_spellings(container[field])))
    container[field] = spelling
    return mutated


def malformed_manifests(manifest: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """Every malformation class that DISCRIMINATES here, drawn from uniformly.

    `non_canonical_timestamp` is deliberately absent — see its docstring for
    the measurement (no mutant this class can build reaches the parser through
    any consumer, and two of its three targets are not targets of this property
    at all). No absolute count is restated here, for the same reason it is not
    restated there: the corpus size is an output of the installed CPython, so
    `0/68` was a true measurement on 2026-09-07 and a false one on 2026-09-08,
    when the same class began building 120 mutants on the same base manifest.

    The real consumers of this union are three, not the five the Task 2 plan
    lists at `docs/plans/2026-09-07-timestamp-predicate-owner.md:480-482`:

        tests/test_manifest_mutation_properties.py   yes
        tests/test_views_properties.py               yes
        tests/test_cli_views_builder_properties.py   yes  (3 call sites)
        tests/test_manifests.py                      NO — uses only the
                                                     NON_DICT_ENTRIES and
                                                     NON_LIST_KEYS constants
        tests/test_views.py                          NO — imports nothing here

    The miscount mattered: it sized the plan's Gate B, so the "before" numbers
    were read partly off two files this fixture never touches.
    """
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
