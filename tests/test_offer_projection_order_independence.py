"""Pin premise P17: offer hashes ignore object-member insertion order.

This is not yet the conformance test for the future buyer acceptance member;
it pins the canonicalization premise on which that member's design depends.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from hypothesis import given, settings
from hypothesis import strategies as st

from attest.canon import canonical_bytes, loads_strict

JsonObject = dict[str, Any]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_VALID_PAYLOAD_PATHS = (
    _REPO_ROOT / "docs/spec/vectors/01-valid-minimal/payload.json",
    _REPO_ROOT / "docs/spec/vectors/07-unicode-canon/a-nfd-and-int-boundary-accepted/payload.json",
)


def _load_payload(path: Path) -> JsonObject:
    payload = loads_strict(path.read_bytes())
    if not isinstance(payload, dict):
        raise TypeError(f"valid receipt payload must be an object: {path}")
    return cast(JsonObject, payload)


_VALID_PAYLOADS = tuple(_load_payload(path) for path in _VALID_PAYLOAD_PATHS)


def _offer_projection(payload: JsonObject) -> JsonObject:
    """Build the exact offer projection defined by design section 4.2."""
    issuer = payload["issuer"]
    if not isinstance(issuer, dict):
        raise TypeError("payload issuer must be an object")
    return {
        "attest_version": payload["attest_version"],
        "issuer": issuer["id"],
        "work": payload["work"],
        "license": payload["license"],
        "survivability": payload["survivability"],
    }


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _offer_sha256(payload: JsonObject) -> str:
    return _canonical_sha256(_offer_projection(payload))


@st.composite
def _recursively_permuted(draw: st.DrawFn, value: Any) -> Any:
    if isinstance(value, dict):
        permuted_values = {
            key: draw(_recursively_permuted(member)) for key, member in value.items()
        }
        key_order = draw(st.permutations(tuple(value)))
        return {key: permuted_values[key] for key in key_order}
    if isinstance(value, list):
        return [draw(_recursively_permuted(element)) for element in value]
    return value


@st.composite
def _payload_and_recursive_permutation(
    draw: st.DrawFn,
) -> tuple[JsonObject, JsonObject]:
    payload = draw(st.sampled_from(_VALID_PAYLOADS))
    permuted = dict(payload)
    for member in ("work", "license", "survivability"):
        permuted[member] = draw(_recursively_permuted(payload[member]))
    return payload, permuted


@given(pair=_payload_and_recursive_permutation())
@settings(max_examples=200, deadline=None)
def test_offer_sha256_ignores_recursive_object_member_order(
    pair: tuple[JsonObject, JsonObject],
) -> None:
    payload, permuted = pair

    assert _offer_projection(permuted) == _offer_projection(payload)
    assert _offer_sha256(permuted) == _offer_sha256(payload)


def test_default_json_digest_exposes_member_order_negative_control() -> None:
    payload: JsonObject = {
        "attest_version": "0.1",
        "issuer": {"id": "merchant.example"},
        "work": {"title": "Example Game", "publisher": "Example Publisher srl"},
        "license": {"grant": "perpetual"},
        "survivability": {"redownload_right": True},
    }
    permuted: JsonObject = {
        **payload,
        "work": {"publisher": "Example Publisher srl", "title": "Example Game"},
    }
    offer = _offer_projection(payload)
    permuted_offer = _offer_projection(permuted)
    work = offer["work"]
    permuted_work = permuted_offer["work"]
    assert isinstance(work, dict)
    assert isinstance(permuted_work, dict)
    assert tuple(work) != tuple(permuted_work)

    assert _offer_sha256(payload) == _offer_sha256(permuted)
    default_digest = hashlib.sha256(json.dumps(offer).encode()).hexdigest()
    permuted_default_digest = hashlib.sha256(json.dumps(permuted_offer).encode()).hexdigest()
    assert default_digest != permuted_default_digest


def test_array_order_inside_offer_changes_digest() -> None:
    first_artifact: JsonObject = {
        "role": "installer",
        "platform": "windows-x86_64",
        "filename": "example-game-setup.exe",
        "size_bytes": 10,
        "sha256": "0" * 64,
    }
    second_artifact: JsonObject = {
        "role": "manual",
        "platform": "any",
        "filename": "example-game-manual.pdf",
        "size_bytes": 20,
        "sha256": "1" * 64,
    }
    payload: JsonObject = {
        "attest_version": "0.1",
        "issuer": {"id": "merchant.example"},
        "work": {
            "title": "Example Game",
            "publisher": "Example Publisher srl",
            "identifiers": {"issuer_sku": "EXG-001"},
            "artifacts": [first_artifact, second_artifact],
        },
        "license": {"grant": "perpetual"},
        "survivability": {"redownload_right": True},
    }
    swapped: JsonObject = {
        **payload,
        "work": {
            **cast(JsonObject, payload["work"]),
            "artifacts": [second_artifact, first_artifact],
        },
    }

    assert _offer_sha256(payload) != _offer_sha256(swapped)


_GOLDEN_OFFER: JsonObject = {
    "attest_version": "0.1",
    "issuer": "merchant.example",
    "work": {
        "artifact_series": "store.example.com/works/EXG-001",
        "identifiers": {"issuer_sku": "EXG-001"},
        "publisher": "Example Publisher srl",
        "title": "Example Game",
    },
    "license": {
        "drm": "drm-free",
        "grant": "perpetual",
        "legal_text_sha256": "a9e875fe29704222a432410b0c160f5a2e5ef48effa8b51a5017c640e21c109c",
        "revocability": "none",
        "terms_uri": "https://store.example.com/attest/license-templates/standard-v1",
        "transferable": False,
    },
    "survivability": {
        "end_of_life": "artifacts-remain-redownloadable",
        "eol_commitment_sha256": None,
        "eol_commitment_uri": None,
        "redownload_right": True,
    },
}

# This value is the pin the JavaScript implementation will have to reproduce
# when the offer projection is specified.
_GOLDEN_OFFER_SHA256 = "bfa8bb9e126dd595c689e8556edb217eb6c18c66c5c3274eaae28446a92da649"


def test_offer_projection_golden_and_top_level_order_independence() -> None:
    reordered_offer: JsonObject = {
        "survivability": _GOLDEN_OFFER["survivability"],
        "license": _GOLDEN_OFFER["license"],
        "work": _GOLDEN_OFFER["work"],
        "issuer": _GOLDEN_OFFER["issuer"],
        "attest_version": _GOLDEN_OFFER["attest_version"],
    }

    assert reordered_offer == _GOLDEN_OFFER
    assert _canonical_sha256(_GOLDEN_OFFER) == _GOLDEN_OFFER_SHA256
    assert _canonical_sha256(reordered_offer) == _GOLDEN_OFFER_SHA256
