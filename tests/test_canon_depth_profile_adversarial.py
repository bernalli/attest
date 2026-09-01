from __future__ import annotations

# NOTE on the expected exception type. These four cases were written against
# `issue.IssueError` / `bundle.BundleError`, the modules' own error types. The
# implementation raises `canon.CanonError`, the PROFILE's error, deliberately:
# `issue.issue` already propagates `CanonError` when the payload alone crosses
# the ceiling (it canonicalizes the payload), so raising a different type for
# the envelope would split one failure class across two types at the same entry
# point. `CanonError` and `IssueError` are both `ValueError` subclasses, and
# `cli.py` catches `canon.CanonError` and `bundle.BundleError` side by side, so
# every existing caller already handles it. The literal is pinned either way.
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, Phase, example, given, settings
from hypothesis import strategies as st

from attest import bundle, canon, issue, keys, manifests, verify
from tests.helpers import make_payload

DEPTH_MESSAGE = "maximum nesting depth exceeded"
ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/depth#ed25519-1"
KP = keys.from_seed(bytes([91]) * 32)


def _object_chain(depth: int, leaf: object = "leaf") -> dict[str, Any]:
    value: object = leaf
    for index in range(depth):
        value = {f"k{depth - index}": value}
    assert isinstance(value, dict)
    return value


def _array_chain(depth: int, leaf: object = "leaf") -> list[Any]:
    value: object = leaf
    for _ in range(depth):
        value = [value]
    assert isinstance(value, list)
    return value


def _alternating_chain(depth: int, leaf: object = "leaf") -> object:
    value = leaf
    for index in range(depth):
        value = [value] if index % 2 else {f"k{index}": value}
    return value


CHAIN_BUILDERS: tuple[tuple[str, Callable[[int], object]], ...] = (
    ("objects", _object_chain),
    ("arrays", _array_chain),
    ("alternating", _alternating_chain),
)


@pytest.mark.parametrize("depth", [255, 256])
@pytest.mark.parametrize(("shape", "builder"), CHAIN_BUILDERS)
def test_parser_and_serializer_accept_the_exact_depth_ceiling(
    shape: str, builder: Callable[[int], object], depth: int
) -> None:
    del shape
    value = builder(depth)

    encoded = canon.canonical_bytes(value)

    assert canon.loads_strict(encoded) == value


@pytest.mark.parametrize("depth", [257, 258])
@pytest.mark.parametrize(("shape", "builder"), CHAIN_BUILDERS)
def test_parser_and_serializer_reject_just_past_the_depth_ceiling_with_the_profile_literal(
    shape: str, builder: Callable[[int], object], depth: int
) -> None:
    del shape
    text = json.dumps(builder(depth), separators=(",", ":"))

    with pytest.raises(canon.CanonError, match=f"^{DEPTH_MESSAGE}$"):
        canon.loads_strict(text.encode("utf-8"))
    with pytest.raises(canon.CanonError, match=f"^{DEPTH_MESSAGE}$"):
        canon.canonical_bytes(builder(depth))


HOSTILE_CHARS = ["a", "b", "0", "\n", "\r", "\t", '"', "\\", "[", "]", "{", "}"]
HOSTILE_KEY = st.text(alphabet=HOSTILE_CHARS, min_size=0, max_size=12)
SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
    st.text(alphabet=HOSTILE_CHARS, max_size=16),
)


class GeneratedTree:
    __slots__ = ("depth", "value")

    def __init__(self, value: object, depth: int) -> None:
        self.value = value
        self.depth = depth

    def __repr__(self) -> str:
        return f"GeneratedTree(depth={self.depth})"


@st.composite
def representable_json_trees(draw: st.DrawFn) -> GeneratedTree:
    value: object = draw(SCALAR)
    depth = draw(st.integers(min_value=0, max_value=270))
    for index in range(depth):
        if draw(st.booleans()):
            value = [value, draw(SCALAR)]
        else:
            key = draw(HOSTILE_KEY)
            if key == "":
                key = f"\n{index}"
            value = {key: value, f"side{index}": draw(SCALAR)}
    return GeneratedTree(value, depth)


@example(GeneratedTree(_alternating_chain(canon.MAX_DEPTH + 1), canon.MAX_DEPTH + 1))
@given(representable_json_trees())
@settings(
    max_examples=80,
    deadline=None,
    phases=[Phase.explicit, Phase.generate],
    suppress_health_check=[HealthCheck.too_slow],
)
def test_any_successful_canonical_serialization_is_parseable_by_the_same_profile(
    generated: GeneratedTree,
) -> None:
    value = generated.value
    try:
        encoded = canon.canonical_bytes(value)
    except canon.CanonError:
        return

    canon.loads_strict(encoded)


def test_direct_cycle_is_rejected_as_profile_depth_not_runtime_recursion() -> None:
    value: list[Any] = []
    value.append(value)

    with pytest.raises(canon.CanonError, match=f"^{DEPTH_MESSAGE}$"):
        canon.canonical_bytes(value)


def test_indirect_cycle_is_rejected_as_profile_depth_not_runtime_recursion() -> None:
    first: dict[str, Any] = {}
    second: dict[str, Any] = {"next": first}
    first["next"] = second

    with pytest.raises(canon.CanonError, match=f"^{DEPTH_MESSAGE}$"):
        canon.canonical_bytes(first)


def test_shared_but_acyclic_substructure_is_still_representable() -> None:
    shared = _alternating_chain(32)
    value = {"left": shared, "right": shared}

    encoded = canon.canonical_bytes(value)

    assert canon.loads_strict(encoded) == value


@pytest.mark.parametrize(("shape", "builder"), CHAIN_BUILDERS)
def test_extreme_iterative_depth_uses_profile_error_not_runtime_recursion(
    shape: str, builder: Callable[[int], object]
) -> None:
    del shape
    value = builder(20_000)

    with pytest.raises(canon.CanonError, match=f"^{DEPTH_MESSAGE}$"):
        canon.canonical_bytes(value)


def test_out_of_safe_range_integer_is_parseable_but_not_canonicalizable() -> None:
    parsed = canon.loads_strict(b'{"n":9007199254740992}')

    assert parsed == {"n": 9007199254740992}
    with pytest.raises(canon.CanonError, match="integer out of I-JSON safe range"):
        canon.canonical_bytes(parsed)


def test_verify_rejects_uncanonicalizable_parsed_payload_inside_its_boundary() -> None:
    payload = make_payload(
        extra_out_of_range=9_007_199_254_740_992,
    )
    envelope = {"payload": payload, "signatures": [{"kid": KID, "alg": "Ed25519", "sig": ""}]}
    trust_store = verify.TrustStore(manifests={ISSUER: _key_manifest_with_extra({})}, provenance={})

    result = verify.verify(json.dumps(envelope).encode("utf-8"), trust_store)

    assert result.signature == "invalid"
    assert any("integer out of I-JSON safe range" in error for error in result.errors)


def test_issue_rejects_payload_that_is_profile_representable_only_before_enveloping() -> None:
    payload = make_payload(extra_profile_depth=_object_chain(canon.MAX_DEPTH - 1))
    assert canon.loads_strict(canon.canonical_bytes(payload)) == payload

    with pytest.raises(canon.CanonError, match=DEPTH_MESSAGE):
        issue.issue(payload, KP, KID)


def test_issue_rejects_over_depth_assembled_envelope_when_delivery_salt_is_present() -> None:
    payload = make_payload(extra_profile_depth=_array_chain(canon.MAX_DEPTH - 1))
    assert canon.loads_strict(canon.canonical_bytes(payload)) == payload

    with pytest.raises(canon.CanonError, match=DEPTH_MESSAGE):
        issue.issue(payload, KP, KID, salt=bytes(range(16)))


def test_issue_rejects_delivery_manifest_that_pushes_the_assembled_envelope_over_depth() -> None:
    manifest_snapshot = {
        "issuer": ISSUER,
        "manifest_version": 1,
        "issued_at": "2026-01-01T00:00:00Z",
        "extra_profile_depth": _object_chain(canon.MAX_DEPTH - 2),
    }

    with pytest.raises(canon.CanonError, match=DEPTH_MESSAGE):
        issue.issue(make_payload(), KP, KID, manifest_snapshot=manifest_snapshot)


def test_issue_allows_salt_at_the_depth_ceiling_without_false_rejection() -> None:
    payload = make_payload(extra_profile_depth=_array_chain(canon.MAX_DEPTH - 2))

    envelope = issue.issue(payload, KP, KID, salt=bytes(range(16)))

    assert canon.loads_strict(canon.canonical_bytes(envelope)) == envelope


def _key_manifest_with_extra(extra: object) -> dict[str, Any]:
    """A trusted manifest carrying an extra member, still signed over it.

    The extra member goes in BEFORE the signature: the receipt path now
    authenticates the trusted manifest before reading any key out of it, so
    a manifest mutated after signing is refused there and never reaches the
    check these tests are about, which is a property of the PAYLOAD. Where
    `extra` is itself outside the JCS profile the manifest cannot be signed
    at all — that is the case the caller is asserting on, so it is left
    unsigned and the CanonError surfaces where the test expects it.
    """
    entry = manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z")
    manifest = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", [entry], KP, KID)
    manifest["extra_profile_depth"] = extra
    body = {key: value for key, value in manifest.items() if key != "manifest_signature"}
    try:
        manifest["manifest_signature"] = manifests.sign_signature_block(
            canon.canonical_bytes(body), KP, KID
        )
    except canon.CanonError:
        pass
    return manifest


def test_disclose_rejects_manifest_snapshot_that_pushes_output_envelope_over_depth(
    tmp_path: Path,
) -> None:
    receipt_id = "01J1V5B4M9Z8QWERTY12345678"
    receipt = issue.issue(make_payload(receipt_id=receipt_id), KP, KID)
    manifest = _key_manifest_with_extra(_object_chain(canon.MAX_DEPTH - 2))
    target = tmp_path / "receipt.attest.json"

    with pytest.raises(canon.CanonError, match=DEPTH_MESSAGE):
        bundle.disclose([receipt], [manifest], {}, receipt_id, target)
    assert not target.exists()
