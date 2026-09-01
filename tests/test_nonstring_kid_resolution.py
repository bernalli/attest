"""A key is never resolved from a manifest by a kid that is not a string.

`find_key` compares `entry["kid"] == kid` with no type check, and
`duplicate_kids` skips entries whose kid is not a string (it guards
`isinstance(kid, str)` before comparing). Together those two facts let a
manifest carry an entry keyed by the integer 5 — or by `null`, `true`, an
array, an object — and be resolved by it: the ambiguity guard is blind to
the entry, so nothing refuses it. The kid inside a signature block is not
covered by the signature either (`_signable` drops `manifest_signature`),
so such a manifest re-signs without friction.

`revocation.verify_record_signature` has always typed its kid; nothing else
in Python did, while the TypeScript verifier types it on every path. These
tests pin the property on each Python path that resolves a key, so that the
defence cannot be removed by a refactor without a test going red.

Each case carries its own POSITIVE control: the same construction with a
string kid must still verify. Without it a green test proves only that the
fixture was broken — which is exactly how the non-string kid hid until now.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any

import pytest

from attest import grant, keys, manifests, revocation, transfer

ISSUER = "store.example.com"
KP = keys.from_seed(bytes([82]) * 32)
HOLDER_KP = keys.from_seed(bytes([83]) * 32)

STRING_KID = f"{ISSUER}/keys/test#ed25519-a"
OLD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
NEW_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
AT = "2026-07-23T00:00:00Z"
DECLARED_AT = "2031-03-01T00:00:00Z"

# Every JSON-representable non-string. A float cannot reach these paths at
# all: the attest-JCS profile refuses to serialize one, so the manifest
# cannot be signed in the first place.
NON_STRING_KIDS: list[Any] = [5, None, True, ["a"], {"k": "v"}]


def _key_manifest(kid: Any) -> dict[str, Any]:
    """A manifest whose only entry is keyed by `kid`, signed under that kid."""
    entry = manifests.key_entry("placeholder", KP.pub, "2020-01-01T00:00:00Z", None, "active")
    entry["kid"] = kid
    return manifests.build_key_manifest(ISSUER, 1, "2026-06-01T00:00:00Z", [entry], KP, kid)


def _artifact_manifest(kid: Any) -> dict[str, Any]:
    return manifests.build_artifact_manifest(
        ISSUER, f"{ISSUER}/works/W", 1, "2026-06-02T00:00:00Z", [], KP, kid
    )


def _transfer_record(kid: Any) -> dict[str, Any]:
    holder_pub = keys.b64u(HOLDER_KP.pub)
    authorization = transfer.sign_authorization(OLD_ID, holder_pub, AT, HOLDER_KP)
    return transfer.build_record(OLD_ID, NEW_ID, holder_pub, AT, authorization, KP, kid)


def _revocation_record(kid: Any) -> dict[str, Any]:
    return revocation.build_record(OLD_ID, "policy", AT, KP, kid)


def _cessation_declaration(kid: Any) -> dict[str, Any]:
    scope = {
        "artifact_series": f"{ISSUER}/works/W",
        "artifacts": sorted([sha256(b"artifact-a").hexdigest(), sha256(b"artifact-b").hexdigest()]),
    }
    return grant.build_declaration(ISSUER, scope, DECLARED_AT, KP, kid)


# Each entry: name, and a callable taking the kid and returning the verdict.
PATHS = [
    ("verify_key_manifest", lambda kid: manifests.verify_key_manifest(_key_manifest(kid))),
    (
        "manifest_signature_is_authentic",
        lambda kid: manifests.manifest_signature_is_authentic(_key_manifest(kid)),
    ),
    (
        "verify_artifact_manifest",
        lambda kid: manifests.verify_artifact_manifest(_artifact_manifest(kid), _key_manifest(kid)),
    ),
    (
        "transfer.verify_record_signature",
        lambda kid: transfer.verify_record_signature(_transfer_record(kid), _key_manifest(kid)),
    ),
    (
        "grant.verify_declaration_signature",
        lambda kid: grant.verify_declaration_signature(
            _cessation_declaration(kid), _key_manifest(kid)
        ),
    ),
    (
        "revocation.verify_record_signature",
        lambda kid: revocation.verify_record_signature(_revocation_record(kid), _key_manifest(kid)),
    ),
]


@pytest.mark.parametrize("name,verify", PATHS, ids=[name for name, _ in PATHS])
def test_string_kid_still_verifies(name: str, verify: Any) -> None:
    """Positive control: the type gate must not cost an honest document its verdict."""
    assert verify(STRING_KID) is True


@pytest.mark.parametrize("name,verify", PATHS, ids=[name for name, _ in PATHS])
@pytest.mark.parametrize("kid", NON_STRING_KIDS, ids=lambda k: type(k).__name__)
def test_non_string_kid_never_resolves_a_key(name: str, verify: Any, kid: Any) -> None:
    """A kid that is not a string resolves nothing, on every path."""
    assert verify(kid) is False


def test_duplicate_kids_is_blind_to_non_string_entries() -> None:
    """The reason the property needs pinning at every path.

    `duplicate_kids` is the ambiguity guard, and it only ever compares
    strings. Two entries keyed by the same integer are invisible to it, so
    it cannot be the place this is fixed: each resolver has to refuse the
    type itself.
    """
    entry = manifests.key_entry("placeholder", KP.pub, "2020-01-01T00:00:00Z", None, "active")
    entry["kid"] = 5
    assert manifests.duplicate_kids([dict(entry), dict(entry)]) == []
