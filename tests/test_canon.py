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
