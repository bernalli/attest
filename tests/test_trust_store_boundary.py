"""The trust store is caller-supplied data, and until it is materialized it is
a caller-supplied OBJECT.

`verify()` reads the embedder's key manifests through `.get`, `==` and `in`.
Those are all shadowable, so an application that builds its trust store from
its own objects — an ORM row, a lazy wrapper, a proxy over a database record —
can hand the verifier a value whose ANSWERS differ from its own DATA. The
manifest still canonicalizes to the bytes the issuer signed (the serializer
takes a string's own data and a mapping's own members), so the manifest's
self-authenticity gate is satisfied by construction: the lie only shows up at
the point of DECISION.

Two decisions are load-bearing enough to be security properties, and each has
its own test below:

* the key validity window (v0.1 §7.1) — a `.get` that denies `valid_to`
  reports "this key never expires", and a receipt issued long after the key
  died verifies green;
* the absorbing `compromised` floor (v0.1 §7.3) — a `status` that answers
  `== "active"` True and `== "compromised"` False is read as compromised by
  neither the floor nor the usability check, and a key the issuer publicly
  buried signs valid receipts again.

Each test states its own non-vacuity precondition first: the SAME manifest
with a plain `dict`/`str` in that one position must produce the safe verdict.
A test that would pass without the defect measures nothing.
"""

from __future__ import annotations

import json
from typing import Any, cast

from attest import issue, keys, manifests, trust_material, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
COMPROMISED_KID = f"{ISSUER}/keys/test#ed25519-compromised"

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([9]) * 32)
COMPROMISED_KP = keys.from_seed(bytes([15]) * 32)

# `make_payload()` issues at 2026-07-02; the expiring key dies 2026-03-01.
_ISSUED_AT = "2026-07-02T14:30:00Z"
_VALID_FROM = "2026-01-01T00:00:00Z"
_EXPIRED_AT = "2026-03-01T00:00:00Z"


class HidesValidTo(dict):  # type: ignore[type-arg]
    """A key entry whose `.get` denies `valid_to` while its own data keeps it.

    Nothing else is shadowed: `__getitem__`, iteration and the member count all
    answer from the entry's own data, so the manifest canonicalizes — and its
    signature verifies — exactly as the plain entry does.
    """

    def get(self, key: Any, default: Any = None) -> Any:
        if key == "valid_to":
            return default
        return dict.get(self, key, default)


class TwoFacedStatus(str):
    """A `status` whose own data is `compromised` and whose answers are `active`.

    `__eq__`/`__ne__` are the whole trick: `_manifest_marks_kid_compromised`
    asks `== "compromised"` and is told no, the usability check asks
    `in ("active", "retired")` and is told yes. `str.__str__` still returns
    `compromised`, so the canonical form the issuer signed is unchanged.
    """

    def __eq__(self, other: object) -> bool:
        return other == "active"

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return str.__hash__(self)


def _expiring_manifest() -> dict[str, Any]:
    """Self-signed manifest whose only key expired before the receipt was issued."""
    entries = [manifests.key_entry(KID, KP.pub, _VALID_FROM, _EXPIRED_AT, "active")]
    return manifests.build_key_manifest(ISSUER, 1, _VALID_FROM, entries, KP, KID)


def _key_manifest_active() -> dict[str, Any]:
    """Self-signed manifest with one active, never-expiring key — the shape
    every "nothing should change" assertion is made against."""
    entries = [manifests.key_entry(KID, KP.pub, _VALID_FROM, None, "active")]
    return manifests.build_key_manifest(ISSUER, 1, _VALID_FROM, entries, KP, KID)


def _compromised_signer_manifest() -> dict[str, Any]:
    """Self-signed by the active KID; the receipt's signer is marked compromised."""
    entries = [
        manifests.key_entry(KID, KP.pub, _VALID_FROM, None, "active"),
        manifests.key_entry(COMPROMISED_KID, COMPROMISED_KP.pub, _VALID_FROM, None, "compromised"),
    ]
    return manifests.build_key_manifest(ISSUER, 1, _VALID_FROM, entries, KP, KID)


def _entry_index(manifest: dict[str, Any], kid: str) -> int:
    for index, entry in enumerate(manifest["keys"]):
        if entry["kid"] == kid:
            return index
    raise AssertionError(f"no entry for {kid!r}")


def _trust_store(manifest: dict[str, Any]) -> verify.TrustStore:
    return verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def test_entry_hiding_valid_to_cannot_outlive_the_key_it_describes() -> None:
    """A receipt issued four months after the key expired must not verify."""
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))

    # Non-vacuity: with a plain dict in that position the verdict is the safe one.
    plain = _expiring_manifest()
    baseline = verify.verify(envelope, _trust_store(plain))
    assert baseline.signature == "invalid"
    assert baseline.ok is False
    assert any("outside key validity window" in error for error in baseline.errors)

    hostile = _expiring_manifest()
    index = _entry_index(hostile, KID)
    hostile["keys"][index] = HidesValidTo(hostile["keys"][index])
    # The lie is in the ANSWER, not in the data: the entry still carries
    # `valid_to`, which is why the manifest signature is unaffected.
    assert hostile["keys"][index]["valid_to"] == _EXPIRED_AT
    assert hostile["keys"][index].get("valid_to") is None
    assert manifests.manifest_signature_is_authentic(hostile)

    result = verify.verify(envelope, _trust_store(hostile))
    assert result.signature == "invalid", "expired key resurrected by a shadowed .get"
    assert result.ok is False
    assert any("outside key validity window" in error for error in result.errors)


def test_two_faced_status_cannot_resurrect_a_compromised_key() -> None:
    """v0.1 §7.3's absorbing floor must not be steered by the status's answers."""
    envelope = _to_bytes(issue.issue(make_payload(), COMPROMISED_KP, COMPROMISED_KID))

    # Non-vacuity: with a plain str in that position the compromised key is dead.
    plain = _compromised_signer_manifest()
    baseline = verify.verify(envelope, _trust_store(plain))
    assert baseline.signature == "invalid"
    assert baseline.ok is False
    assert any("is compromised" in error for error in baseline.errors)

    hostile = _compromised_signer_manifest()
    index = _entry_index(hostile, COMPROMISED_KID)
    hostile["keys"][index]["status"] = TwoFacedStatus("compromised")
    # Own data unchanged — the manifest the issuer signed still says compromised.
    assert str.__str__(hostile["keys"][index]["status"]) == "compromised"
    assert manifests.manifest_signature_is_authentic(hostile)

    result = verify.verify(envelope, _trust_store(hostile))
    assert result.signature == "invalid", "compromised key resurrected by a shadowed __eq__"
    assert result.ok is False
    assert any("is compromised" in error for error in result.errors)


# --------------------------------------------------------------------------
# The closure is a PROPERTY, not two receipts. Everything below asserts what
# the boundary guarantees, rather than re-running the two attacks above with
# the details changed.
# --------------------------------------------------------------------------


class WorstEntry(dict):  # type: ignore[type-arg]
    """Every read a caller's mapping can shadow, shadowed at once.

    `.get` lies, `__getitem__` answers differently on every call, `__contains__`
    denies membership, `keys()`/`__iter__` never terminate, `__len__` lies. Only
    the OWN data — what `dict.items`/`dict.__len__` see — is truthful, and own
    data is all the boundary reads.
    """

    def __init__(self, source: dict[str, Any]) -> None:
        super().__init__(source)
        self.calls = 0

    def get(self, key: Any, default: Any = None) -> Any:
        return default

    def __getitem__(self, key: Any) -> Any:
        self.calls += 1
        return f"answer-{self.calls}"

    def __contains__(self, key: object) -> bool:
        return False

    def __iter__(self) -> Any:
        while True:
            yield "kid"

    def keys(self) -> Any:
        return self.__iter__()

    def __len__(self) -> int:
        return 0


class RaisingStr(str):
    """A `str` subclass that refuses to behave as a string in every dunder a
    reader might reach for. `str.__str__` still yields its own data."""

    def __eq__(self, other: object) -> bool:
        raise RuntimeError("equality refused")

    def __ne__(self, other: object) -> bool:
        raise RuntimeError("inequality refused")

    def __hash__(self) -> int:
        return 0

    def __len__(self) -> int:
        raise RuntimeError("length refused")

    def __iter__(self) -> Any:
        raise RuntimeError("iteration refused")


def _exact_types(value: Any, seen: list[type]) -> None:
    """Record the EXACT type of every value reachable from `value`."""
    seen.append(type(value))
    if type(value) is dict:
        for key, item in value.items():
            _exact_types(key, seen)
            _exact_types(item, seen)
    elif type(value) is list:
        for item in value:
            _exact_types(item, seen)


def test_boundary_returns_own_data_in_exact_built_in_types() -> None:
    """The worst object I can write survives only as its own data.

    `isinstance` is not the property being asserted and would not be enough:
    every hostile class here passes `isinstance`. `type(x) is ...` is the test.
    """
    manifest = _compromised_signer_manifest()
    index = _entry_index(manifest, COMPROMISED_KID)
    manifest["keys"][index] = WorstEntry(manifest["keys"][index])
    manifest["issuer"] = RaisingStr(ISSUER)
    store = verify.TrustStore(
        manifests={ISSUER: manifest},
        provenance={ISSUER: "tls"},
        chains={ISSUER: [manifest]},
    )

    materialized = verify._materialized_trust_store(store)
    assert materialized is not None

    entry = materialized.manifests[ISSUER]["keys"][index]
    assert type(entry) is dict
    assert entry["status"] == "compromised"  # own data, not `answer-N`
    assert entry["kid"] == COMPROMISED_KID
    assert type(materialized.manifests[ISSUER]["issuer"]) is str
    assert materialized.manifests[ISSUER]["issuer"] == ISSUER

    seen: list[type] = []
    _exact_types(materialized.manifests, seen)
    _exact_types(materialized.provenance, seen)
    _exact_types(materialized.chains, seen)
    assert set(seen) <= {dict, list, str, int, bool, type(None)}, sorted({t.__name__ for t in seen})


def test_boundary_refuses_material_that_is_not_expressible_as_data() -> None:
    """Fail-closed, explicitly: an unmaterializable store is a verification
    error naming itself, never a silent pass and never a positive verdict."""
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))

    unrepresentable: tuple[tuple[str, str, Any], ...] = (
        ("float", "manifest_version", 1.0),
        ("object", "issuer", object()),
        ("bytes", "issuer", b"store.example.com"),
    )
    for label, member, value in unrepresentable:
        manifest = _key_manifest_active()
        manifest[member] = value
        result = verify.verify(envelope, _trust_store(manifest))
        assert result.signature == "invalid", label
        assert result.ok is False, label
        assert any("could not be materialized" in error for error in result.errors), label


def test_boundary_refuses_keys_that_collapse_onto_one_member() -> None:
    """Two keys whose own data is the same name leave one member behind, and
    which one survives would be the attacker's choice. Refuse instead."""
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))

    class ShadowKey(str):
        def __hash__(self) -> int:
            return hash("issuer")

        def __eq__(self, other: object) -> bool:
            return False

        def __ne__(self, other: object) -> bool:
            return True

    manifest = _key_manifest_active()
    manifest[ShadowKey("issuer")] = "evil.example.com"
    assert len(manifest) == len(_key_manifest_active()) + 1

    result = verify.verify(envelope, _trust_store(manifest))
    assert result.signature == "invalid"
    assert result.ok is False
    assert any("could not be materialized" in error for error in result.errors)


def test_boundary_terminates_on_endless_iteration() -> None:
    """A container whose iteration never ends must not hang the verifier: the
    boundary reads `dict.items`/`list.__len__`, never `__iter__`."""

    class EndlessKeys(list):  # type: ignore[type-arg]
        def __iter__(self) -> Any:
            while True:
                yield {}

    manifest = _key_manifest_active()
    manifest["keys"] = EndlessKeys(manifest["keys"])

    fields = trust_material.trust_store_fields(
        verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})
    )
    assert type(fields["manifests"][ISSUER]["keys"]) is list
    assert len(fields["manifests"][ISSUER]["keys"]) == 1


def test_boundary_covers_the_sites_that_already_read_own_data() -> None:
    """The `manifest_signature` block is read with `dict.get(...)` at three
    sites in `manifests.py` — the only three of that module's fifty-three
    `.get(` lines that read own data.

    Aiming the same hostile object at them was MEASURED, not reasoned about:
    with the boundary removed the two verdict assertions below still hold, so
    those three sites really are immune, and for the right reason. What the
    boundary adds is the last assertion — the block arrives as an exact
    `dict`, so the two spellings can no longer disagree and the property stops
    depending on which one the next line happens to use.
    """
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    manifest = _key_manifest_active()
    manifest["manifest_signature"] = HidesValidTo(manifest["manifest_signature"])

    result = verify.verify(envelope, _trust_store(manifest))
    assert result.signature == "valid"
    assert result.ok is True

    materialized = verify._materialized_trust_store(
        verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})
    )
    assert materialized is not None
    assert type(materialized.manifests[ISSUER]["manifest_signature"]) is dict


def test_well_formed_trust_store_is_unchanged_by_the_boundary() -> None:
    """Zero behavior change on the wire path: the same receipt, the same
    manifest, the same green verdict, and the materialized store equal to the
    one supplied."""
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    manifest = _key_manifest_active()
    store = verify.TrustStore(
        manifests={ISSUER: manifest},
        provenance={ISSUER: "tls"},
        chains={ISSUER: [manifest]},
    )

    result = verify.verify(envelope, store)
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.ok is True
    assert result.trust == "verified"
    assert result.warnings == ()

    materialized = verify._materialized_trust_store(store)
    assert materialized is not None
    assert materialized.manifests == store.manifests
    assert materialized.provenance == store.provenance
    assert materialized.chains == store.chains
    assert materialized.artifact_manifests == store.artifact_manifests
    assert materialized.artifact_manifest_chains == store.artifact_manifest_chains


def test_trust_store_with_a_hostile_attribute_is_refused_not_raised() -> None:
    """A store object whose field refuses to answer fails closed, and does so
    as a verdict — an embedder's request handler must not crash."""

    class RefusingStore:
        """A store-shaped object — what an embedder wiring a lazy trust store
        onto its own persistence layer actually hands the verifier."""

        def __init__(self) -> None:
            self.manifests = {ISSUER: _key_manifest_active()}
            self.provenance = {ISSUER: "tls"}
            self.artifact_manifests: dict[str, Any] = {}
            self.artifact_manifest_chains: dict[str, Any] = {}

        @property
        def chains(self) -> Any:
            raise RuntimeError("the database is gone")

    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))

    result = verify.verify(envelope, cast("verify.TrustStore", RefusingStore()))
    assert result.signature == "invalid"
    assert result.ok is False
    assert any("could not be materialized" in error for error in result.errors)
