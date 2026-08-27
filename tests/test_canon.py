import math
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from attest import canon

# RFC 8785-style expectations (integer-only attest profile)


def test_sorts_keys_by_utf16_code_units() -> None:
    # From RFC 8785 §3.2.3 ordering semantics: literal "\r" (0x0D) sorts before
    # "1" (0x31), "10" before "2", "é" (0xE9) after ASCII, emoji (surrogates) last.
    obj = {"é": 1, "10": 2, "1": 3, "2": 4, "\r": 5, "😀": 6}
    assert canon.dumps(obj) == '{"\\r":5,"1":3,"10":2,"2":4,"é":1,"😀":6}'


def test_string_escapes_match_rfc8785() -> None:
    assert canon.dumps({"a": '\b\t\n\f\r"\\\x01'}) == '{"a":"\\b\\t\\n\\f\\r\\"\\\\\\u0001"}'


def test_no_whitespace_and_stable_nesting() -> None:
    obj = {"b": [1, None, True, False], "a": {"x": "y"}}
    assert canon.dumps(obj) == '{"a":{"x":"y"},"b":[1,null,true,false]}'


def test_bool_is_not_int() -> None:
    assert canon.dumps(True) == "true"
    assert canon.dumps({"k": False}) == '{"k":false}'


def test_int_boundaries() -> None:
    assert canon.dumps(2**53 - 1) == "9007199254740991"
    with pytest.raises(canon.CanonError):
        canon.dumps(2**53)
    with pytest.raises(canon.CanonError):
        canon.dumps(-(2**53))


def test_rejects_floats_and_nonjson() -> None:
    with pytest.raises(canon.CanonError):
        canon.dumps(1.5)
    with pytest.raises(canon.CanonError):
        canon.dumps(math.nan)
    with pytest.raises(canon.CanonError):
        canon.dumps({1: "non-string-key"})
    with pytest.raises(canon.CanonError):
        canon.dumps({"k": b"bytes"})


def test_loads_strict_rejects_duplicates() -> None:
    with pytest.raises(canon.DuplicateKeyError):
        canon.loads_strict(b'{"a":1,"a":2}')


def test_loads_strict_rejects_floats_and_bad_utf8() -> None:
    with pytest.raises(canon.CanonError):
        canon.loads_strict(b'{"a":1.5}')
    with pytest.raises(canon.CanonError):
        canon.loads_strict(b'{"a":NaN}')
    with pytest.raises(canon.CanonError):
        canon.loads_strict(b'\xff{"a":1}')


def test_dumps_rejects_lone_surrogate_value() -> None:
    with pytest.raises(canon.CanonError):
        canon.dumps({"a": "\ud800"})


def test_canonical_bytes_rejects_lone_surrogate_value() -> None:
    # Signing path: must raise CanonError, never a raw UnicodeEncodeError.
    with pytest.raises(canon.CanonError):
        canon.canonical_bytes({"a": "\ud800"})


def test_dumps_rejects_lone_surrogate_key() -> None:
    with pytest.raises(canon.CanonError):
        canon.dumps({"\ud800": 1})


def test_loads_strict_rejects_escaped_lone_surrogate() -> None:
    with pytest.raises(canon.CanonError):
        canon.loads_strict(b'{"a":"\\ud800"}')


@given(
    st.recursive(
        st.none()
        | st.booleans()
        | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
        | st.text(),
        lambda children: st.lists(children) | st.dictionaries(st.text(), children),
        max_leaves=20,
    )
)
def test_roundtrip_and_idempotence(obj: object) -> None:
    s = canon.dumps(obj)
    parsed = canon.loads_strict(s.encode())
    assert canon.dumps(parsed) == s


def _nest(levels: int) -> Any:
    nested: Any = []
    for _ in range(levels):
        nested = [nested]
    return nested


def test_canonical_bytes_reports_unserializable_depth_as_canon_error() -> None:
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.canonical_bytes(_nest(20_000))


def test_canonical_bytes_reports_a_cycle_as_canon_error() -> None:
    cyclic: dict[str, Any] = {}
    cyclic["self"] = cyclic
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.canonical_bytes(cyclic)


def test_canonical_bytes_still_accepts_the_deepest_parsable_document() -> None:
    assert canon.canonical_bytes(_nest(canon.MAX_DEPTH - 1))


def test_loads_strict_reports_an_oversized_integer_literal_as_canon_error() -> None:
    with pytest.raises(canon.CanonError, match="invalid JSON: "):
        canon.loads_strict(b'{"n":' + b"9" * 4400 + b"}")


def test_loads_strict_leaves_this_modules_own_errors_untouched() -> None:
    """Taxonomy pinning for the generic `ValueError` net in `loads_strict`:
    `CanonError` is a `ValueError` subclass, so a bare net there would catch the
    errors `_pairs_hook` and `_reject_float` raise from inside `json.loads`,
    demoting `DuplicateKeyError` to its base class and re-prefixing a message
    `tools/gen_vectors.py` documents."""
    with pytest.raises(canon.DuplicateKeyError) as duplicate:
        canon.loads_strict(b'{"a":1,"a":2}')
    assert str(duplicate.value) == "duplicate object key: 'a'"

    with pytest.raises(canon.CanonError) as bad_float:
        canon.loads_strict(b'{"a":1.5}')
    assert str(bad_float.value) == "floats are not allowed in the attest-JCS profile"


def _nest_dicts(levels: int) -> Any:
    nested: Any = {}
    for _ in range(levels):
        nested = {"k": nested}
    return nested


def _nest_mixed(levels: int) -> Any:
    nested: Any = {}
    for i in range(levels):
        nested = [nested] if i % 2 else {"k": nested}
    return nested


# The ceiling is a property of the attest-JCS profile, not of the parser: the
# serializer refuses one level past it with the parser's own literal, so no
# conforming issuer can sign a document no conforming parser will accept.
# `_nest*(levels)` builds a tree of depth `levels + 1`, so `MAX_DEPTH` levels is
# one past the ceiling and `MAX_DEPTH - 1` sits exactly on it.


def test_canonical_bytes_rejects_lists_one_level_past_the_ceiling() -> None:
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.canonical_bytes(_nest(canon.MAX_DEPTH))


def test_canonical_bytes_accepts_dicts_at_the_ceiling() -> None:
    assert canon.canonical_bytes(_nest_dicts(canon.MAX_DEPTH - 1))


def test_canonical_bytes_rejects_dicts_one_level_past_the_ceiling() -> None:
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.canonical_bytes(_nest_dicts(canon.MAX_DEPTH))


def test_canonical_bytes_accepts_mixed_containers_at_the_ceiling() -> None:
    assert canon.canonical_bytes(_nest_mixed(canon.MAX_DEPTH - 1))


def test_canonical_bytes_rejects_mixed_containers_one_level_past_the_ceiling() -> None:
    # The count must not depend on the container type: alternating dict/list
    # nesting has to hit the ceiling at exactly the same depth as either alone.
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.canonical_bytes(_nest_mixed(canon.MAX_DEPTH))


@given(
    levels=st.integers(min_value=canon.MAX_DEPTH - 6, max_value=canon.MAX_DEPTH + 6),
    shape=st.sampled_from(("list", "dict", "mixed")),
    leaf=st.one_of(st.none(), st.booleans(), st.integers(-(2**53) + 1, 2**53 - 1), st.text()),
    key=st.sampled_from(("k", "\r", "10", "2", "é", "😀", "")),
)
def test_whatever_the_serializer_emits_the_strict_parser_accepts(
    levels: int, shape: str, leaf: Any, key: str
) -> None:
    # Direction (1) of the profile's boundary contract, which was FALSE before
    # the ceiling reached the serializer: a document deeper than the ceiling
    # used to serialize and then fail to parse. Probed around the boundary
    # rather than on random shallow trees, because that is where it broke.
    builders = {
        "list": lambda n: _nest(n),
        "dict": lambda n: _nest_dicts(n),
        "mixed": lambda n: _nest_mixed(n),
    }
    tree = builders[shape](levels)
    payload = {key: tree, "leaf": leaf}
    try:
        raw = canon.canonical_bytes(payload)
    except canon.CanonError:
        return  # refused at serialization: the contract says nothing more
    assert canon.loads_strict(raw) == payload


# `check_object_depth` is the guard the issuance path uses on an ASSEMBLED
# envelope. It is deliberately iterative: the object arrives from the caller,
# and a recursive walk would die with RecursionError -- outside the CanonError
# family that every fail-closed boundary in this package catches.


def test_check_object_depth_accepts_the_deepest_representable_document() -> None:
    canon.check_object_depth(_nest(canon.MAX_DEPTH - 1))
    canon.check_object_depth(_nest_dicts(canon.MAX_DEPTH - 1))
    canon.check_object_depth(_nest_mixed(canon.MAX_DEPTH - 1))


def test_check_object_depth_rejects_one_level_past_the_ceiling() -> None:
    for build in (_nest, _nest_dicts, _nest_mixed):
        with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
            canon.check_object_depth(build(canon.MAX_DEPTH))


def test_check_object_depth_is_iterative_not_recursive() -> None:
    # Far past any interpreter recursion limit: the profile error must win, and
    # the failure must NOT be a RecursionError leaking out of the guard.
    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.check_object_depth(_nest(50_000))


def test_check_object_depth_rejects_a_cycle_deterministically() -> None:
    direct: dict[str, Any] = {}
    direct["self"] = direct
    indirect_a: dict[str, Any] = {}
    indirect_b: dict[str, Any] = {"a": indirect_a}
    indirect_a["b"] = indirect_b
    for cyclic in (direct, indirect_a):
        with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
            canon.check_object_depth(cyclic)


def test_check_object_depth_accepts_sharing_that_is_not_a_cycle() -> None:
    # A shared subtree is legitimate and repeats no level: rejecting it would
    # refuse documents the profile represents perfectly well.
    shared = {"x": [1, 2, 3]}
    canon.check_object_depth({"a": shared, "b": shared, "c": [shared, shared]})
