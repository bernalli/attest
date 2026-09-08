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

import pytest

from attest import (
    anchor,
    canon,
    issue,
    keys,
    manifests,
    pq,
    revocation,
    tlog,
    transfer,
    trust_material,
    verify,
)
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
    # The NAMED reason moved after F1 and the move is the improvement: a `dict`
    # subclass is now refused as a container before anything reads it, so the
    # shadowed `.get` never reaches the validity window at all. The property
    # this test defends — an expired key cannot certify a later receipt — is
    # unchanged and is what the plain-dict baseline above still measures.
    assert any("could not be materialized" in error for error in result.errors)


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
    # SCALAR subtypes keep §18.4's tolerance and are the case this test walks:
    # a `str` subclass carries its own data, the copy recovers it, and nothing
    # is lost. A CONTAINER subtype is a different case and is refused outright
    # — see `test_a_container_subclass_is_refused_not_copied` below, which is
    # where `WorstEntry` moved after F1.
    manifest["issuer"] = RaisingStr(ISSUER)
    manifest["keys"][index]["status"] = RaisingStr("compromised")
    store = verify.TrustStore(
        manifests={ISSUER: manifest},
        provenance={ISSUER: "tls"},
        chains={ISSUER: [manifest]},
    )

    materialized, _ = verify._materialized_trust_store(store)
    assert materialized is not None

    entry = materialized.manifests[ISSUER]["keys"][index]
    assert type(entry) is dict
    assert entry["status"] == "compromised"  # own data, recovered from the subclass
    assert type(entry["status"]) is str
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
    """A container whose iteration never ends must not hang the verifier.

    The refusal is what changed after F1 — a `list` subclass is a container
    subtype and is refused rather than copied — but the property being
    defended is the same one and is the harder half: the walk that reaches
    that refusal uses `list.__len__`/`list.__getitem__`, never `__iter__`, so
    it TERMINATES on this value instead of following it forever. A boundary
    that can hang is not fail-closed.
    """

    class EndlessKeys(list):  # type: ignore[type-arg]
        def __iter__(self) -> Any:
            while True:
                yield {}

    manifest = _key_manifest_active()
    manifest["keys"] = EndlessKeys(manifest["keys"])

    with pytest.raises(trust_material.TrustMaterialError):
        trust_material.trust_store_fields(
            verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})
        )


def test_a_container_subclass_is_refused_not_copied() -> None:
    """F1: copying a container that stores nothing DELETES it.

    `WorstEntry` shadows every mapping read at once. Before F1 the copy read
    its own data and the verdict was right for the wrong reason — the class
    happened to STORE its members. A sibling that stores nothing and answers
    from elsewhere was emptied instead, which on an optional member is the
    direction that skips the check. The container rule replaces "read the
    stored data" with "refuse anything that might not be storing it".
    """
    manifest = _key_manifest_active()
    index = _entry_index(manifest, KID)
    manifest["keys"][index] = WorstEntry(manifest["keys"][index])
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))

    result = verify.verify(envelope, _trust_store(manifest))
    assert result.signature == "invalid"
    assert result.ok is False
    assert any("could not be materialized" in error for error in result.errors)


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
    # Built on a PLAIN dict: after F1 a container subclass is refused outright,
    # so aiming one at the signature block would measure the container rule
    # instead of the own-data rule this test is about.
    manifest = _key_manifest_active()
    result = verify.verify(envelope, _trust_store(manifest))
    assert result.signature == "valid"
    assert result.ok is True

    materialized, _ = verify._materialized_trust_store(
        verify.TrustStore(manifests={ISSUER: manifest}, provenance={ISSUER: "tls"})
    )
    assert materialized is not None
    assert type(materialized.manifests[ISSUER]["manifest_signature"]) is dict
    # The three `dict.get(sig_block, "kid")` sites read own data, and the block
    # they read is now an exact `dict`, so the two spellings cannot disagree.
    assert manifests.manifest_signature_is_authentic(materialized.manifests[ISSUER])


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

    materialized, _ = verify._materialized_trust_store(store)
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


# --------------------------------------------------------------------------
# The trust store is not the only rail that carries TRUSTED material as an
# OBJECT. `revocation` and `transfer` take a `key_manifest` directly, and
# `transfer.audit_chain` calls itself "a SECOND public entry point" in its own
# docstring. Closing the class on `verify()` and leaving those open would
# publish a fix that is true of one door and false of another.
# --------------------------------------------------------------------------

_REV_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_REV_ID2 = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
_SIGNED_AT = "2026-07-02T14:30:00Z"  # four months after `_EXPIRED_AT`
HOLDER_KP = keys.from_seed(bytes([21]) * 32)
NEW_HOLDER_KP = keys.from_seed(bytes([22]) * 32)
# Trusted, pinned verifier configuration: `audit_chain` refuses an empty
# `log_keys` as a config bug, so the audits below need a real one. The log
# it names holds nothing, which is exactly what these tests want — the link
# fails on log standing either way, and the assertion is about WHICH error
# appears alongside it.
_LOG_HK = pq.HybridSigningKeys(ed=keys.from_seed(bytes([23]) * 32), mldsa=pq.generate())
_LOG_KEYS = [
    tlog.LogKey(
        origin="transfer-log.attest.example/2026",
        name="attest-transfer-log-1",
        ed25519_pub=_LOG_HK.ed.pub,
        mldsa_pub=_LOG_HK.mldsa.pub,
    )
]
_NO_HORIZON = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


def _live_manifest() -> dict[str, Any]:
    """Same signing key, window still open — the fixture that proves a `False`
    below comes from the expiry and not from a broken record."""
    return _key_manifest_active()


def _hostile_expiring_manifest() -> dict[str, Any]:
    manifest = _expiring_manifest()
    index = _entry_index(manifest, KID)
    manifest["keys"][index] = HidesValidTo(manifest["keys"][index])
    return manifest


def _revocation_record() -> dict[str, Any]:
    return revocation.build_record(_REV_ID, "revoked", _SIGNED_AT, KP, KID)


def _transfer_record() -> dict[str, Any]:
    new_holder_pubkey = keys.b64u(NEW_HOLDER_KP.pub)
    sig = transfer.sign_authorization(_REV_ID, new_holder_pubkey, _SIGNED_AT, HOLDER_KP)
    return transfer.build_record(_REV_ID, _REV_ID2, new_holder_pubkey, _SIGNED_AT, sig, KP, KID)


def test_revocation_record_cannot_outlive_the_key_that_signed_it() -> None:
    """`revocation.verify_record` / `verify_record_signature` are public entry
    points for TRUSTED material, and were reading it as an object."""
    record = _revocation_record()

    # Non-vacuity, both directions: the record is genuinely well-formed and
    # authenticates while the key is in window, and a plain expired manifest
    # is what refuses it — so the refusal below is the window, not the fixture.
    assert revocation.verify_record(record, _live_manifest()) is True
    assert revocation.verify_record_signature(record, _live_manifest()) is True
    assert revocation.verify_record(record, _expiring_manifest()) is False

    hostile = _hostile_expiring_manifest()
    assert manifests.manifest_signature_is_authentic(hostile), "the lie must stay authentic"
    assert revocation.verify_record(record, hostile) is False
    assert revocation.verify_record_signature(record, hostile) is False


def test_transfer_record_cannot_outlive_the_key_that_signed_it() -> None:
    """Same class, same shape, the other side-document rail."""
    record = _transfer_record()

    assert transfer.verify_record(record, _live_manifest()) is True
    assert transfer.verify_record_signature(record, _live_manifest()) is True
    assert transfer.verify_record(record, _expiring_manifest()) is False

    hostile = _hostile_expiring_manifest()
    assert manifests.manifest_signature_is_authentic(hostile)
    assert transfer.verify_record(record, hostile) is False
    assert transfer.verify_record_signature(record, hostile) is False


def test_audit_chain_reads_its_key_manifest_as_data() -> None:
    """§17.5's audit surface — the second public entry point, in its own words."""
    record = _transfer_record()
    payloads = [
        {"receipt_id": _REV_ID, "buyer": {"pubkey": keys.b64u(HOLDER_KP.pub)}},
        {"receipt_id": _REV_ID2, "buyer": {"pubkey": keys.b64u(NEW_HOLDER_KP.pub)}},
    ]
    view = [{"record": record, "evidence": {}}]
    signature_invalid = "chain link 1: issuer signature invalid"

    def audit(manifest: dict[str, Any]) -> tuple[str, ...]:
        return transfer.audit_chain(payloads, view, [], manifest, _LOG_KEYS, _NO_HORIZON).errors

    # Non-vacuity: with the key in window the issuer signature is NOT the
    # thing that fails (the link still fails on log standing, which is fine —
    # this test is about which error appears, not about a valid chain).
    assert signature_invalid not in audit(_live_manifest())
    # Baseline: a plain expired manifest makes it fail, and says so.
    assert signature_invalid in audit(_expiring_manifest())
    # The attack.
    assert signature_invalid in audit(_hostile_expiring_manifest())


def test_side_document_rails_refuse_a_manifest_that_is_not_data() -> None:
    """Fail-closed on the same rails: material that cannot be materialized
    authenticates nothing, and an audit reports every link invalid."""
    record = _revocation_record()
    unreadable = _live_manifest()
    unreadable["manifest_version"] = 1.0  # a float has no canonical form here

    assert revocation.verify_record(record, unreadable) is False
    assert revocation.verify_record_signature(record, unreadable) is False
    assert transfer.verify_record(_transfer_record(), unreadable) is False

    payloads = [
        {"receipt_id": _REV_ID, "buyer": {"pubkey": keys.b64u(HOLDER_KP.pub)}},
        {"receipt_id": _REV_ID2, "buyer": {"pubkey": keys.b64u(NEW_HOLDER_KP.pub)}},
    ]
    result = transfer.audit_chain(
        payloads,
        [{"record": _transfer_record(), "evidence": {}}],
        [],
        unreadable,
        _LOG_KEYS,
        _NO_HORIZON,
    )
    assert result.valid is False
    assert result.link_status == ("invalid",)
    assert result.errors == ("chain link 1: issuer signature invalid",)


# --------------------------------------------------------------------------
# F1 (security review 2026-09-08, CRITICAL). The copy reads what a container
# STORES. A container that stores nothing and answers from somewhere else is
# not neutralized by that copy — it is EMPTIED. On `manifests` the emptying is
# caught downstream by the manifest's own signature; on `chains` there is no
# container-level guard, and ABSENCE IS MORE PERMISSIVE THAN PRESENCE: an
# absent rotation history is a history the verifier never walks, so deleting
# it resurrects a key a held manifest marks `compromised`.
# --------------------------------------------------------------------------


class LazyMapping(dict):  # type: ignore[type-arg]
    """A mapping that STORES nothing and answers from somewhere else.

    The shape `trust_material`'s own docstring names — "an ORM row, a lazy
    wrapper, a proxy over a database record". Its own data is empty, so a copy
    that reads own data does not correct it, it deletes it.
    """

    def __init__(self, real: dict[str, Any]) -> None:
        super().__init__()  # deliberately empty own data
        self._real = dict(real)

    def get(self, key: Any, default: Any = None) -> Any:
        return self._real.get(key, default)

    def __getitem__(self, key: Any) -> Any:
        return self._real[key]

    def __len__(self) -> int:
        return len(self._real)


def test_an_unreadable_chain_is_refused_not_deleted() -> None:
    """Deleting an OPTIONAL member is not the safe direction.

    Measured against 98f9d04 before this test existed: with `chains` supplied
    as a mapping whose own data is empty, the held rotation history came back
    with zero members and a receipt signed by a key a chain member marks
    `compromised` verified `ok=True` — v0.1 §7.3's absorbing floor deleted
    along with the chain. Non-vacuity: the same chain as a plain dict kills
    the receipt.
    """
    entries_v1 = [manifests.key_entry(KID, KP.pub, _VALID_FROM, None, "compromised")]
    entries_v2 = [manifests.key_entry(KID, KP.pub, _VALID_FROM, None, "active")]
    v1 = manifests.build_key_manifest(ISSUER, 1, _VALID_FROM, entries_v1, KP, KID)
    v2 = manifests.build_key_manifest(ISSUER, 2, _VALID_FROM, entries_v2, KP, KID)
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))

    plain = verify.TrustStore(
        manifests={ISSUER: v2}, provenance={ISSUER: "tls"}, chains={ISSUER: [v1, v2]}
    )
    baseline = verify.verify(envelope, plain)
    assert baseline.ok is False
    assert any("is compromised" in error for error in baseline.errors)

    lazy = verify.TrustStore(
        manifests={ISSUER: v2},
        provenance={ISSUER: "tls"},
        chains=LazyMapping({ISSUER: [v1, v2]}),
    )
    result = verify.verify(envelope, lazy)
    assert result.ok is False, "a chain the boundary could not read was deleted, not refused"
    assert any("could not be materialized" in error for error in result.errors)


def test_a_lazy_mapping_never_reaches_the_verifier_as_an_empty_one() -> None:
    """The property behind the test above, stated on the boundary itself."""
    supplied = LazyMapping({ISSUER: [_key_manifest_active()]})
    assert len(supplied) == 1
    try:
        trust_material.materialize(supplied)
    except trust_material.TrustMaterialError:
        return
    raise AssertionError("a container that stores nothing must be refused, not emptied")


# --------------------------------------------------------------------------
# The hang that the boundary must not have, and the blind spot that hid it.
#
# `canon.own_data_copy` builds its result with `copied[own_data_copy(key)] = ...`,
# and that assignment HASHES the key. A key whose own data is not a string is
# returned unchanged by the copy's permissive tail, so the caller's `__hash__`
# runs INSIDE the boundary — and a `__hash__` that never returns hangs the
# verifier. `canon.dumps` does refuse a non-string key, but only AFTER the hash.
#
# The blind spot: every hostile key class in this file and in the wider suite is
# a subclass of `str`, whose hash is a string's and is therefore harmless. The
# case that does not look like a key at all had never been written down.
# --------------------------------------------------------------------------


class HostileHashKey:
    """A key that is not a string and whose hash is the caller's code.

    `armed` is False while the fixture is being built — putting the key into a
    dict hashes it — and True for the measurement, so the test can assert that
    the boundary refused the value WITHOUT ever reaching this method.
    """

    armed = False
    called = False

    def __hash__(self) -> int:
        if HostileHashKey.armed:
            HostileHashKey.called = True
            raise AssertionError("the caller's __hash__ ran inside the boundary")
        return 0

    def __eq__(self, other: object) -> bool:
        return self is other


def test_a_non_string_key_is_refused_before_its_hash_is_ever_run() -> None:
    """A boundary that can hang is not fail-closed."""
    manifest = _key_manifest_active()
    HostileHashKey.armed = False
    HostileHashKey.called = False
    manifest["keys"][0][HostileHashKey()] = "value"
    HostileHashKey.armed = True
    try:
        with pytest.raises(trust_material.TrustMaterialError):
            trust_material.materialize(manifest)
        assert HostileHashKey.called is False, "the key was hashed before being refused"
    finally:
        HostileHashKey.armed = False


def test_hostile_material_is_refused_on_every_store_member_not_only_manifests() -> None:
    """`manifests` is the only member whose emptying a signature would catch.

    The other three have no container-level guard downstream, which is exactly
    why F1 was reachable through `chains`. Each member is given the same
    unreadable container and each must refuse the whole store.
    """
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    live = _key_manifest_active()
    unreadable = LazyMapping({ISSUER: {}})

    for member in ("chains", "artifact_manifests", "artifact_manifest_chains"):
        store = verify.TrustStore(
            manifests={ISSUER: live},
            provenance={ISSUER: "tls"},
            **{member: unreadable},
        )
        result = verify.verify(envelope, store)
        assert result.signature == "invalid", member
        assert result.ok is False, member
        assert any("could not be materialized" in error for error in result.errors), member


def test_a_store_nested_past_the_depth_ceiling_fails_closed() -> None:
    """The ceilings are ceilings, not a slowdown."""
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    deep: Any = {}
    for _ in range(canon.MAX_DEPTH + 8):
        deep = {"n": deep}
    manifest = _key_manifest_active()
    manifest["deep"] = deep

    result = verify.verify(envelope, _trust_store(manifest))
    assert result.signature == "invalid"
    assert result.ok is False
    assert any("could not be materialized" in error for error in result.errors)


def test_a_store_shaped_object_missing_an_optional_member_is_read_as_absent() -> None:
    """The docstring says an absent member stays absent; this measures it."""

    class MinimalStore:
        """Only the two required members — what a small embedder writes."""

        def __init__(self) -> None:
            self.manifests = {ISSUER: _key_manifest_active()}
            self.provenance = {ISSUER: "tls"}

    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    result = verify.verify(envelope, cast("verify.TrustStore", MinimalStore()))
    assert result.signature == "invalid"
    assert result.ok is False
    assert any("could not be materialized" in error for error in result.errors), (
        "a store missing an optional member is refused via getattr, and the "
        "message must say which member — see the reason-naming test"
    )


def test_the_refusal_names_the_member_that_actually_failed() -> None:
    """A refusal that accuses the wrong thing is worse than a vague one.

    It is actionable AND wrong: an embedder whose artifact manifests are
    malformed was being sent to debug their key manifests.
    """
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    live = _key_manifest_active()

    for member in ("chains", "artifact_manifests", "artifact_manifest_chains"):
        store = verify.TrustStore(
            manifests={ISSUER: live},
            provenance={ISSUER: "tls"},
            **{member: LazyMapping({ISSUER: {}})},
        )
        result = verify.verify(envelope, store)
        assert any(repr(member) in error for error in result.errors), (
            f"the refusal for {member} does not name it: {result.errors}"
        )
        assert not any("its manifests" in error for error in result.errors)

    # And the manifests case still names `manifests`.
    broken = _key_manifest_active()
    broken["issued_at"] = object()
    result = verify.verify(envelope, _trust_store(broken))
    assert any("'manifests'" in error for error in result.errors)


# ---------------------------------------------------------------------------
# Section 5.6(c): export and meta-closure, pinned by test (F6, T1).
#
# WHAT THIS PROVES: no PUBLIC parameter named for trusted material, anywhere
# in `attest.*`, accepts anything but the new handle types -- judged by
# parameter NAME (the closed set D19 fixes) and by the RESOLVED annotation
# object, never its spelling. `verify.py` keeps a dataclass literally called
# `TrustStore` at T1 (it is what `trust_material.TrustStore` replaces), so a
# check that compared annotation STRINGS would call `verify.evaluate_grant`
# closed today for the wrong reason -- section 5.6(c) requires
# `typing.get_type_hints`, and this is why.
#
# WHAT THIS DOES NOT PROVE, stated because section 5.6(c) requires it stated:
# that the ports which DO carry the right annotation actually EXECUTE the
# handle correctly -- open it once with `_store_data`/`_manifest_data` and
# read nothing else off a caller's object. That is INV-4 (section 6.4), a
# runtime property no static signature check can see, and this file does not
# attempt it.
#
# Both pins below are `xfail(strict=True)`: at T1 neither holds, by design --
# `trust_material.__all__` still carries the T0 materialization family and no
# public signature has migrated. T2/T3 close them, and `strict=True` is the
# promise that they turn green on their own the moment that happens, and
# fail loudly (XPASS) if this file's own numbers drift from the code first.
#
# `importlib`/`inspect`/`pkgutil`/`typing`/`attest` are LOCAL to the one
# function below that needs them, not at the top of this file: the two test
# files this front may touch are append-only (a shared writer edits
# `verifiers/ts/**` in the same worktree), so a module-level import here is
# not available.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason=(
        "measured 2026-09-08 on this worktree: trust_material.__all__ is still "
        "['TRUST_STORE_FIELDS', 'TrustMaterialError', 'materialize', "
        "'materialized_key_manifest', 'trust_store_fields'] -- the T0 materialization "
        "family the module's own docstring says falls in T2 ('_reads_as_own_data, "
        "materialize, materialized_key_manifest, trust_store_fields, TRUST_STORE_FIELDS "
        "restano (cadono in T2)'). T2 drops the export list to the three names this "
        "pin fixes."
    ),
)
def test_trust_material_all_is_the_serialized_boundarys_three_names() -> None:
    """5.6(c): the export surface, pinned by the exact list rather than
    membership -- a total kept alongside a growing list is the copy that
    ages first, so there is none here: just the list itself.
    """
    assert trust_material.__all__ == ["TrustMaterialError", "KeyManifest", "TrustStore"]


def meta_closure_violations() -> list[str]:
    """Every public `attest.*` function whose parameter, by NAME, should
    carry a trust handle but does not, by RESOLVED annotation identity.

    Watched parameter names (section 5.6(c)'s closed set): `trust_store`,
    `key_manifest`, `trusted_manifest`, `previous`, `candidate`. Excluded by
    name (the closed list of evidence builders section 5.6(c) names):
    `views.build_compromise_claim`, `views.key_manifest_log_entry` -- neither
    currently has a watched parameter (both take `manifest`), so the
    exclusion is a no-op today and a guard against a future rename, exactly
    as written.

    `typing.get_type_hints`, never the raw `__annotations__` string:
    `attest` uses `from __future__ import annotations` throughout, so a bare
    string compare against `"TrustStore"` would call `verify.evaluate_grant`
    closed today -- its parameter IS spelled `TrustStore`, and resolves to
    `verify.py`'s OWN dataclass of that name, not `trust_material.TrustStore`.
    Only identity with the module under test's two handles counts.
    """
    import importlib
    import inspect
    import pkgutil
    import typing

    import attest

    watched_names = {"trust_store", "key_manifest", "trusted_manifest", "previous", "candidate"}
    excluded = {("views", "build_compromise_claim"), ("views", "key_manifest_log_entry")}
    handles = (trust_material.TrustStore, trust_material.KeyManifest)

    violations: list[str] = []
    for info in pkgutil.iter_modules(attest.__path__, attest.__name__ + "."):
        module = importlib.import_module(info.name)
        stem = info.name.rsplit(".", 1)[-1]
        for name, func in inspect.getmembers(module, inspect.isfunction):
            if name.startswith("_") or func.__module__ != module.__name__:
                continue
            if (stem, name) in excluded:
                continue
            matched = watched_names & inspect.signature(func).parameters.keys()
            if not matched:
                continue
            try:
                hints = typing.get_type_hints(func)
            except Exception as exc:  # a forward ref this walk cannot resolve
                violations.append(f"{stem}.{name}: get_type_hints failed: {exc}")
                continue
            for param_name in sorted(matched):
                annotation = hints.get(param_name)
                if annotation not in handles:
                    violations.append(
                        f"{stem}.{name}({param_name}: {annotation}) is not a trust handle"
                    )
    return violations


@pytest.mark.xfail(
    strict=True,
    reason=(
        "measured 2026-09-08 on this worktree: 22 public signatures across "
        "authority.py, grant.py, manifests.py, revocation.py, transfer.py, "
        "trust_material.py, verify.py and views.py carry one of the five watched "
        "parameter names and NONE resolves to trust_material.TrustStore/KeyManifest "
        "today. Three of the 22 (verify.evaluate_grant, "
        "verify.evaluate_publisher_authority, verify.verify) are already annotated "
        "`TrustStore` BY NAME but resolve to verify.py's own dataclass of that name, "
        "not the new handle -- the case get_type_hints exists to catch. T2/T3 migrate "
        "these signatures to the new handles; this pin turns green as they do, one "
        "violation fewer at a time."
    ),
)
def test_no_public_signature_takes_a_trusted_dict_where_a_handle_belongs() -> None:
    """5.6(c): meta-closure over every public signature in `attest.*`.

    PROVES that no public parameter named for trusted material accepts
    anything but the new handle types, by resolved annotation.

    Does NOT prove that the ports which DO carry the right annotation
    actually EXECUTE the handle correctly -- open it once and read nothing
    else off a caller's live object. That is INV-4 (section 6.4), a runtime
    property this static signature check cannot see and does not attempt.
    """
    assert meta_closure_violations() == []
