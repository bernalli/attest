"""Trust material enters this library as BYTES, and the doors take snapshots.

WHAT THIS FILE MEASURES, AND WHAT IT DELIBERATELY DOES NOT

`verify()` reads the embedder's key manifests through `.get`, `==` and `in`.
Those are all shadowable, so an application that builds its trust store from
its own objects — an ORM row, a lazy wrapper, a proxy over a database record —
used to be able to hand the verifier a value whose ANSWERS differ from its own
DATA. The manifest still canonicalizes to the bytes the issuer signed, so the
self-authenticity gate was satisfied by construction: the lie only showed up at
the point of DECISION. Two decisions were load-bearing enough to be security
properties, and each still has its own test below:

* the key validity window (v0.1 §7.1) — a `.get` that denies `valid_to`
  reports "this key never expires", and a receipt issued long after the key
  died verifies green;
* the absorbing `compromised` floor (v0.1 §7.3) — a `status` that answers
  `== "active"` True and `== "compromised"` False is read as compromised by
  neither the floor nor the usability check, and a key the issuer publicly
  buried signs valid receipts again.

The class is now closed at the ENTRANCE rather than survived at the exit, and
that changes what these tests can assert. Each hostile object is measured
TWICE, because the boundary makes two different promises:

1. **Through the bytes.** The object is serialized like any other value, and
   what reaches the verifier is the honest document — the lie lives in the
   object's ANSWERS, and a serializer writes its DATA. The verdict must be the
   safe one, identical to the plain fixture's.
2. **At the door.** The same object handed straight to a port is refused
   because it is not a snapshot this library parsed, and refused WITHOUT BEING
   TOUCHED: no `.get`, no `__eq__`, no `__hash__`, nothing. That is INV-4, and
   it is the property a static signature check cannot see.

The second half is why the imposters below carry a REGISTER. A port that
refuses an object after asking it three questions has not closed the class; it
has moved it. The register is asserted EMPTY, not small.

What this file does not do: the parser's own admission rules (M1-M8, the
document grammar, truncation, duplicate members, the ceilings) live in
`test_trust_material_parse.py`, and the AST custody check (5.6d) lives there
too. Here the subject is the DOORS.
"""

from __future__ import annotations

import json
import uuid
from collections import OrderedDict, defaultdict
from types import MappingProxyType, SimpleNamespace
from typing import Any, cast

import pytest

from attest import (
    anchor,
    authority,
    canon,
    grant,
    issue,
    keys,
    manifests,
    pq,
    revocation,
    tlog,
    transfer,
    trust_material,
    verify,
    views,
)
from tests.helpers import key_manifest, make_payload, store, store_bytes

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

# The refusal a door reports when it is handed something that is not a snapshot
# (M3). Read from the library rather than spelled out here: a literal copy of a
# message is a second owner of it, and the two drift.
_NOT_PARSED_STORE = trust_material._MSG_NOT_PARSED.format(what="trust store")
_NOT_PARSED_MANIFEST = trust_material._MSG_NOT_PARSED.format(what="key manifest")


# ---------------------------------------------------------------------------
# The register: what a door touched. Asserted EMPTY, never merely short.
#
# Every imposter below writes into `_TOUCHED` from every method a door could
# plausibly call. A door that refuses an object AFTER asking it questions has
# not closed the class — an object gets to run code inside the verifier's trust
# decision either way, and the refusal is then a property of what it happened
# to answer rather than of what it is.
# ---------------------------------------------------------------------------

_TOUCHED: list[str] = []


def _clear() -> None:
    _TOUCHED.clear()


def _leak_marker() -> str:
    """A string no message may echo back.

    A refusal that formats the rejected value into its text is a channel out of
    the refusal: an attacker chooses what the verifier prints, and prints it
    wherever those errors are collected. Fresh per call so a stale assertion
    cannot pass on last test's marker.
    """
    return f"LEAKED-{uuid.uuid4()}"


class HidesValidTo(dict):  # type: ignore[type-arg]
    """A key entry whose `.get` denies `valid_to` while its own data keeps it.

    Nothing else is shadowed: `__getitem__`, iteration and the member count all
    answer from the entry's own data, so the manifest canonicalizes — and its
    signature verifies — exactly as the plain entry does. That is the whole
    point: through the bytes this object is INVISIBLE, and it is only a door
    taking a live object that could ever have consulted its `.get`.
    """

    def get(self, key: Any, default: Any = None) -> Any:
        _TOUCHED.append(f"HidesValidTo.get({key!r})")
        if key == "valid_to":
            return default
        return dict.get(self, key, default)


class TwoFacedStatus(str):
    """A `status` whose own data is `compromised` and whose answers are `active`.

    `__eq__`/`__ne__` are the whole trick: the absorbing floor asks
    `== "compromised"` and is told no, the usability check asks
    `in ("active", "retired")` and is told yes. `str.__str__` still returns
    `compromised`, so the canonical form the issuer signed is unchanged.
    """

    def __eq__(self, other: object) -> bool:
        _TOUCHED.append(f"TwoFacedStatus.__eq__({other!r})")
        return other == "active"

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        _TOUCHED.append("TwoFacedStatus.__hash__")
        return str.__hash__(self)


class LazyMapping(dict):  # type: ignore[type-arg]
    """A mapping that STORES nothing and answers from somewhere else.

    The old boundary copied what a container stores, so this one was not
    neutralized by the copy — it was EMPTIED, and an emptied `chains` is a
    rotation history the verifier never walks. Through the bytes it serializes
    as what it stores, which is nothing; at a door it is not a snapshot at all.
    """

    def __init__(self, hidden: dict[str, Any]) -> None:
        super().__init__()
        self._hidden = hidden

    def get(self, key: Any, default: Any = None) -> Any:
        _TOUCHED.append(f"LazyMapping.get({key!r})")
        return self._hidden.get(key, default)

    def __getitem__(self, key: Any) -> Any:
        _TOUCHED.append(f"LazyMapping.__getitem__({key!r})")
        return self._hidden[key]

    def __contains__(self, key: object) -> bool:
        _TOUCHED.append(f"LazyMapping.__contains__({key!r})")
        return key in self._hidden


class HostileHashKey:
    """A mapping key that runs the caller's code from inside `__hash__`.

    A door that looks something up before checking that the selector is exactly
    a string runs this. `type(x) is str` runs nothing (D18), which is why every
    selector is checked before any lookup.
    """

    def __hash__(self) -> int:  # pragma: no cover - reaching it is the failure
        _TOUCHED.append("HostileHashKey.__hash__")
        raise AssertionError("a non-string selector was hashed")

    def __eq__(self, other: object) -> bool:  # pragma: no cover - same
        _TOUCHED.append("HostileHashKey.__eq__")
        raise AssertionError("a non-string selector was compared")


class RecordingStore:
    """An object that answers to everything a door might ask of a snapshot.

    It has the five member names as attributes, and every access is registered.

    It does NOT fake `__class__`, and an earlier version of this docstring said
    it did: `__class__` is found by ordinary lookup, so it never reaches
    `__getattr__`, and nothing here can make it answer `TrustStore`. What tells
    `type(x) is TrustStore` apart from `isinstance(x, TrustStore)` is the
    `subclass-built-past-the-factory` imposter below, not this one -- and the
    distinction matters, because a subclass that skipped the factory is the
    shape `isinstance` would let through.
    """

    def __init__(self, marker: str) -> None:
        object.__setattr__(self, "_marker", marker)

    def __getattr__(self, name: str) -> Any:
        _TOUCHED.append(f"RecordingStore.{name}")
        if name in ("manifests", "provenance", "chains"):
            return {ISSUER: {"issuer": object.__getattribute__(self, "_marker")}}
        return {}

    def __repr__(self) -> str:
        _TOUCHED.append("RecordingStore.__repr__")
        return f"<store {object.__getattribute__(self, '_marker')}>"


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


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


# ---------------------------------------------------------------------------
# The two security properties, measured through the bytes.
#
# Each of these used to be a test about SURVIVING a hostile object. It is now a
# test about the object never arriving: the document the verifier reads is the
# one the serializer wrote, and a serializer writes DATA. The hostile object's
# answers have nowhere to be asked.
# ---------------------------------------------------------------------------


def test_entry_hiding_valid_to_cannot_outlive_the_key_it_describes() -> None:
    """A receipt issued four months after the key expired must not verify."""
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))

    # Non-vacuity: with a plain dict in that position the verdict is the safe one.
    plain = _expiring_manifest()
    baseline = verify.verify(envelope, store({ISSUER: plain}))
    assert baseline.signature == "invalid"
    assert baseline.ok is False
    assert any("outside key validity window" in error for error in baseline.errors)

    hostile = _expiring_manifest()
    index = _entry_index(hostile, KID)
    hostile["keys"][index] = HidesValidTo(hostile["keys"][index])
    # The lie is in the ANSWER, not in the data: the entry still carries
    # `valid_to`, which is why the manifest signature is unaffected and why the
    # serialized document is byte-identical to the plain one.
    assert hostile["keys"][index]["valid_to"] == _EXPIRED_AT
    assert hostile["keys"][index].get("valid_to") is None
    assert store_bytes({ISSUER: hostile}) == store_bytes({ISSUER: plain})

    _clear()
    result = verify.verify(envelope, store({ISSUER: hostile}))
    assert result.signature == "invalid", "expired key resurrected by a shadowed .get"
    assert result.ok is False
    # The SAME named reason as the plain fixture, and that is the point: the
    # object did not survive the boundary, it never crossed it. Under the old
    # boundary this assertion read "could not be materialized" — a refusal of
    # the container — and the difference is the whole task: a document that
    # serializes honestly is now simply verified honestly.
    assert any("outside key validity window" in error for error in result.errors)
    assert _TOUCHED == [], f"the verifier consulted the hostile entry: {_TOUCHED}"


def test_two_faced_status_cannot_resurrect_a_compromised_key() -> None:
    """v0.1 §7.3's absorbing floor must not be steered by the status's answers."""
    envelope = _to_bytes(issue.issue(make_payload(), COMPROMISED_KP, COMPROMISED_KID))

    # Non-vacuity: with a plain str in that position the compromised key is dead.
    plain = _compromised_signer_manifest()
    baseline = verify.verify(envelope, store({ISSUER: plain}))
    assert baseline.signature == "invalid"
    assert baseline.ok is False
    assert any("is compromised" in error for error in baseline.errors)

    hostile = _compromised_signer_manifest()
    index = _entry_index(hostile, COMPROMISED_KID)
    hostile["keys"][index]["status"] = TwoFacedStatus("compromised")
    # Own data unchanged — the manifest the issuer signed still says compromised,
    # and so do the bytes.
    assert str.__str__(hostile["keys"][index]["status"]) == "compromised"
    assert store_bytes({ISSUER: hostile}) == store_bytes({ISSUER: plain})

    _clear()
    result = verify.verify(envelope, store({ISSUER: hostile}))
    assert result.signature == "invalid", "compromised key resurrected by a shadowed __eq__"
    assert result.ok is False
    assert any("is compromised" in error for error in result.errors)
    assert _TOUCHED == [], f"the verifier consulted the two-faced status: {_TOUCHED}"


# ---------------------------------------------------------------------------
# INV-4: every door refuses a non-snapshot, in its own declared way, WITHOUT
# TOUCHING IT.
#
# The imposters are section 6.1's: the old shape (a dict with the five member
# names), an object answering to every member name, a SUBCLASS built past the
# factory (the one that separates `type(x) is` from `isinstance`), the
# containers the old boundary used to tolerate, a handle of the WRONG kind, and
# `None`. Each is
# measured against every door, and the refusal class comes from section 5.5:
# `V` verdict, `F` false/none, `CA` chain audit, `TE` TypeError, `X` ViewError.
# ---------------------------------------------------------------------------


def _store_imposters() -> list[tuple[str, object]]:
    marker = _leak_marker()
    subclass = type("SpoofedStore", (trust_material.TrustStore,), {})
    return [
        ("old-keyword-shape", {"manifests": {}, "provenance": {}}),
        ("five-member-dict", {name: {} for name in trust_material._StoreData._fields}),
        ("simple-namespace", SimpleNamespace(manifests={}, provenance={}, chains={})),
        ("subclass-built-past-the-factory", object.__new__(subclass)),
        ("recording-object", RecordingStore(marker)),
        ("lazy-mapping", LazyMapping({"manifests": {ISSUER: _key_manifest_active()}})),
        ("mapping-proxy", MappingProxyType({"manifests": {}, "provenance": {}})),
        ("ordered-dict", OrderedDict(manifests={}, provenance={})),
        ("default-dict", defaultdict(dict, manifests={}, provenance={})),
        ("a-key-manifest-where-a-store-belongs", key_manifest(_key_manifest_active())),
        ("none", None),
    ]


def _manifest_imposters() -> list[tuple[str, object]]:
    marker = _leak_marker()
    subclass = type("SpoofedManifest", (trust_material.KeyManifest,), {})
    return [
        ("plain-dict", _key_manifest_active()),
        ("hostile-dict", HidesValidTo(_key_manifest_active())),
        ("subclass-built-past-the-factory", object.__new__(subclass)),
        ("recording-object", RecordingStore(marker)),
        ("lazy-mapping", LazyMapping(_key_manifest_active())),
        ("a-store-where-a-key-manifest-belongs", store({ISSUER: _key_manifest_active()})),
        ("none", None),
    ]


@pytest.mark.parametrize("label,imposter", _manifest_imposters(), ids=lambda v: str(v)[:40])
def test_no_boolean_manifest_door_accepts_anything_but_a_snapshot(
    label: str, imposter: object
) -> None:
    """Section 5.5 class `F`: the predicate doors answer False, and touch nothing.

    `False` and not an exception: these doors are predicates whose True is a
    PERMISSION, so the fail-closed answer is the one that authorizes nothing.
    That makes the refusal a weak migration signal on purpose — the strong one
    is the annotation, which mypy reads — and it is why this test exists at
    all: a weak signal that also happened to be WRONG (True, or a crash) would
    be undetectable from a type check.
    """
    record = revocation.build_record("01J1V5B4M9Z8QWERTY12345678", "revoked", _ISSUED_AT, KP, KID)
    doors = [
        ("manifests.verify_key_manifest", lambda m: manifests.verify_key_manifest(m)),
        (
            "manifests.manifest_signature_is_authentic",
            lambda m: manifests.manifest_signature_is_authentic(m),
        ),
        ("manifests.check_continuity/1", lambda m: manifests.check_continuity(m, m)),
        (
            "manifests.verify_artifact_manifest",
            lambda m: manifests.verify_artifact_manifest({}, m),
        ),
        ("revocation.verify_record", lambda m: revocation.verify_record(record, m)),
        (
            "revocation.verify_record_signature",
            lambda m: revocation.verify_record_signature(record, m),
        ),
        ("transfer.verify_record", lambda m: transfer.verify_record(record, m)),
        (
            "transfer.verify_record_signature",
            lambda m: transfer.verify_record_signature(record, m),
        ),
        ("grant.verify_grant", lambda m: grant.verify_grant({}, m)),
        ("grant.verify_grant_signature", lambda m: grant.verify_grant_signature({}, m)),
        ("grant.verify_declaration", lambda m: grant.verify_declaration({}, m)),
        (
            "grant.verify_declaration_signature",
            lambda m: grant.verify_declaration_signature({}, m),
        ),
        ("authority.verify_authorization", lambda m: authority.verify_authorization({}, m)),
        (
            "authority.verify_authorization_signature",
            lambda m: authority.verify_authorization_signature({}, m),
        ),
    ]
    for name, door in doors:
        _clear()
        assert door(cast("Any", imposter)) is False, f"{name} accepted {label}"
        assert _TOUCHED == [], f"{name} consulted {label}: {_TOUCHED}"


@pytest.mark.parametrize("label,imposter", _manifest_imposters(), ids=lambda v: str(v)[:40])
def test_find_key_resolves_nothing_for_anything_but_a_snapshot(
    label: str, imposter: object
) -> None:
    """`find_key` answers `None` — the same answer as an absent kid.

    Deliberately the same: a lookup the library cannot trust has nothing to
    hand back, and inventing a distinct sentinel would give callers a third
    state to forget to handle.
    """
    _clear()
    assert manifests.find_key(cast("Any", imposter), KID) is None, label
    assert _TOUCHED == [], f"find_key consulted {label}: {_TOUCHED}"


@pytest.mark.parametrize("label,imposter", _store_imposters(), ids=lambda v: str(v)[:40])
def test_verify_answers_a_verdict_for_anything_but_a_snapshot(label: str, imposter: object) -> None:
    """Section 5.5 class `V`: `verify()` ANSWERS, it does not raise.

    This entry point already answers a malformed envelope with `ok: false` and
    a named reason; an embedder's request handler should not start crashing
    because the trust material it was handed is of the wrong kind. The
    evaluators are the opposite case (below) and the asymmetry is deliberate.
    """
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    _clear()
    result = verify.verify(envelope, cast("Any", imposter))
    assert result.ok is False, label
    assert _NOT_PARSED_STORE in result.errors, f"{label}: {result.errors}"
    assert _TOUCHED == [], f"verify() consulted {label}: {_TOUCHED}"
    # No refusal echoes the rejected object back: `RecordingStore` carries a
    # fresh marker precisely so this assertion cannot pass on a stale one.
    joined = " ".join(result.errors) + " ".join(result.warnings)
    assert "LEAKED-" not in joined, f"{label} leaked into the verdict: {joined}"


@pytest.mark.parametrize("label,imposter", _store_imposters(), ids=lambda v: str(v)[:40])
def test_the_evaluators_raise_for_anything_but_a_snapshot(label: str, imposter: object) -> None:
    """Section 5.5 class `TE`: `evaluate_*` raise, and this is not a detail.

    `not_checked` is a VERDICT — it says "you did not ask me to check this" —
    and a policy that reads it as "no objection" would treat malformed trusted
    configuration as an absent question. A `TypeError` cannot be read that way
    by anybody, because there is no verdict object to misread. The test below
    (`test_no_policy_can_read_the_refusal_as_an_omitted_check`) is the same
    property from the caller's side.
    """
    payload = make_payload()
    _clear()
    with pytest.raises(TypeError) as grant_exc:
        verify.evaluate_grant(payload, cast("Any", imposter), {})
    assert str(grant_exc.value) == _NOT_PARSED_STORE, label
    with pytest.raises(TypeError) as authority_exc:
        verify.evaluate_publisher_authority(payload, cast("Any", imposter), {})
    assert str(authority_exc.value) == _NOT_PARSED_STORE, label
    assert _TOUCHED == [], f"an evaluator consulted {label}: {_TOUCHED}"
    assert "LEAKED-" not in str(grant_exc.value) + str(authority_exc.value)


@pytest.mark.parametrize("label,imposter", _store_imposters(), ids=lambda v: str(v)[:40])
def test_claim_capabilities_refuses_anything_but_a_snapshot(label: str, imposter: object) -> None:
    """Section 5.5 class `X`: a view builder raises `ViewError`."""
    _clear()
    with pytest.raises(views.ViewError) as exc:
        views.claim_capabilities({}, cast("Any", imposter), ISSUER)
    assert str(exc.value) == _NOT_PARSED_STORE, label
    assert _TOUCHED == [], f"claim_capabilities consulted {label}: {_TOUCHED}"
    assert "LEAKED-" not in str(exc.value)


@pytest.mark.parametrize(
    "label,imposter",
    [pair for pair in _manifest_imposters() if pair[0] != "none"],
    ids=lambda v: str(v)[:40],
)
def test_build_revocation_view_refuses_anything_but_a_snapshot(
    label: str, imposter: object
) -> None:
    """`ViewError`, not a silent downgrade to a shape check.

    The caller ASKED for authentication by passing the argument at all. Reading
    an unusable manifest as "no manifest given" would answer a question they
    did not ask, and would do it in the permissive direction.
    """
    _clear()
    with pytest.raises(views.ViewError) as exc:
        views.build_revocation_view([], cast("Any", imposter))
    assert str(exc.value) == _NOT_PARSED_MANIFEST, label
    assert _TOUCHED == [], f"build_revocation_view consulted {label}: {_TOUCHED}"


def test_build_revocation_view_without_a_manifest_still_checks_shape() -> None:
    """`None` is the DEFAULT, not an imposter: it means "I cannot authenticate
    these yet", which is the right posture for a holder assembling a view out
    of records they were handed. The records are still shape-checked."""
    assert views.build_revocation_view([]) == []
    with pytest.raises(views.ViewError):
        views.build_revocation_view([{"receipt_id": "not-a-ulid"}])


@pytest.mark.parametrize("label,imposter", _manifest_imposters(), ids=lambda v: str(v)[:40])
def test_audit_chain_is_invalid_at_zero_links_for_anything_but_a_snapshot(
    label: str, imposter: object
) -> None:
    """Section 5.5 class `CA`, and D6's exception: `valid=False` even at ZERO links.

    A chain audit with no links and a manifest it cannot open must not report
    `valid=True`. "I audited nothing successfully" is exactly the sentence a
    caller must not be able to read out of a contract failure — and at zero
    links it is the sentence the natural implementation writes, because a loop
    over an empty list finds no failures.

    That is NOT the same as a manifest which IS a snapshot and fails its own
    self-verify: that is a verdict on real data, and at zero links it keeps
    answering `valid=True` (P-15). The next test pins that difference.
    """
    _clear()
    result = transfer.audit_chain([], [], [], cast("Any", imposter), [], _NO_HORIZON)
    assert result.valid is False, label
    assert result.link_status == ()
    assert result.errors == (_NOT_PARSED_MANIFEST,), label
    assert result.warnings == ()
    assert _TOUCHED == [], f"audit_chain consulted {label}: {_TOUCHED}"


@pytest.mark.parametrize("label,imposter", _manifest_imposters(), ids=lambda v: str(v)[:40])
def test_audit_chain_marks_every_link_invalid_for_anything_but_a_snapshot(
    label: str, imposter: object
) -> None:
    """The contract branch WITH links, which nothing else reaches.

    Every other imposter test hands `audit_chain` an empty `payloads`, so
    `link_count` is 0 and the per-link half of the refusal -- the `link_status`
    tuple and one named error per link -- is never built. A branch that only
    ever runs with its loop bound at zero is a branch no test has executed.
    """
    payloads = [{"receipt_id": _REV_ID}, {"receipt_id": _REV_ID2}]
    _clear()
    result = transfer.audit_chain(payloads, [], [], cast("Any", imposter), [], _NO_HORIZON)
    assert result.valid is False, label
    assert result.link_status == ("invalid",), label
    assert result.errors == (
        _NOT_PARSED_MANIFEST,
        "chain link 1: issuer signature invalid",
    ), label
    assert result.warnings == ()
    assert _TOUCHED == [], f"audit_chain consulted {label}: {_TOUCHED}"


def test_audit_chain_separates_a_contract_failure_from_a_verdict_on_real_data() -> None:
    """The two refusals of `audit_chain` are different, and the difference shows
    at zero links — the only place it CAN show.

    * not a snapshot  -> `valid=False`, errors == (M3,)          [contract]
    * a snapshot that fails its own self-verify -> `valid=True`  [verdict, P-15]

    Collapsing them would be the easy reading of "both are bad manifests", and
    it would change a published behaviour (P-15) for no reason. Keeping them
    apart is what lets a caller tell "you handed me the wrong kind of thing"
    from "the thing you handed me does not check out".
    """
    honest = key_manifest(_key_manifest_active())
    assert transfer.audit_chain([], [], [], honest, [], _NO_HORIZON).valid is True

    broken = _key_manifest_active()
    broken["manifest_signature"]["sig"] = keys.b64u(bytes(64))
    unverifiable = key_manifest(broken)

    # The fixture has to BE the case it stands for, and this is the assertion
    # that says so. At zero links `valid=True, errors=()` is ALSO what a
    # manifest whose self-verify PASSES answers -- measured: both branches
    # return exactly that -- so without these two lines the P-15 half of this
    # test is satisfied by a perfectly good manifest and pins nothing at all.
    assert manifests.verify_key_manifest(honest) is True
    assert manifests.verify_key_manifest(unverifiable) is False

    verdict = transfer.audit_chain([], [], [], unverifiable, [], _NO_HORIZON)
    assert verdict.valid is True, "a snapshot that fails its self-verify keeps P-15"
    assert verdict.errors == ()

    contract = transfer.audit_chain([], [], [], cast("Any", {}), [], _NO_HORIZON)
    assert contract.valid is False
    assert contract.errors == (_NOT_PARSED_MANIFEST,)


# ---------------------------------------------------------------------------
# The side-document rails: the same property, on the surfaces a HOLDER reaches
# without going through `verify()`.
# ---------------------------------------------------------------------------

_REV_ID = "01J1V5B4M9Z8QWERTY12345678"
_REV_ID2 = "01J1V5B4M9Z8QWERTY12345679"
_SIGNED_AT = "2026-07-03T10:00:00Z"
HOLDER_KP = keys.from_seed(bytes([11]) * 32)
NEW_HOLDER_KP = keys.from_seed(bytes([12]) * 32)
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


def _revocation_record() -> dict[str, Any]:
    return revocation.build_record(_REV_ID, "revoked", _SIGNED_AT, KP, KID)


def _transfer_record() -> dict[str, Any]:
    new_holder_pubkey = keys.b64u(NEW_HOLDER_KP.pub)
    sig = transfer.sign_authorization(_REV_ID, new_holder_pubkey, _SIGNED_AT, HOLDER_KP)
    return transfer.build_record(_REV_ID, _REV_ID2, new_holder_pubkey, _SIGNED_AT, sig, KP, KID)


def test_revocation_record_cannot_outlive_the_key_that_signed_it() -> None:
    """`revocation.verify_record` / `verify_record_signature` are public entry
    points for TRUSTED material, and they now take a snapshot of it."""
    record = _revocation_record()
    live = key_manifest(_key_manifest_active())
    expired = key_manifest(_expiring_manifest())

    # Non-vacuity, both directions: the record is genuinely well-formed and
    # authenticates while the key is in window, and an expired manifest is what
    # refuses it — so the refusal is the window, not the fixture.
    assert revocation.verify_record(record, live) is True
    assert revocation.verify_record_signature(record, live) is True
    assert revocation.verify_record(record, expired) is False

    # The hostile entry serializes to the honest document, so the snapshot it
    # produces is the expired one and the answer is the expired one's.
    hostile = _expiring_manifest()
    hostile["keys"][_entry_index(hostile, KID)] = HidesValidTo(
        hostile["keys"][_entry_index(hostile, KID)]
    )
    _clear()
    assert revocation.verify_record(record, key_manifest(hostile)) is False
    assert revocation.verify_record_signature(record, key_manifest(hostile)) is False
    assert _TOUCHED == []


def test_transfer_record_cannot_outlive_the_key_that_signed_it() -> None:
    """Same class, same shape, the other side-document rail."""
    record = _transfer_record()
    live = key_manifest(_key_manifest_active())
    expired = key_manifest(_expiring_manifest())

    assert transfer.verify_record(record, live) is True
    assert transfer.verify_record_signature(record, live) is True
    assert transfer.verify_record(record, expired) is False

    hostile = _expiring_manifest()
    hostile["keys"][_entry_index(hostile, KID)] = HidesValidTo(
        hostile["keys"][_entry_index(hostile, KID)]
    )
    _clear()
    assert transfer.verify_record(record, key_manifest(hostile)) is False
    assert _TOUCHED == []


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
        return transfer.audit_chain(
            payloads, view, [], key_manifest(manifest), _LOG_KEYS, _NO_HORIZON
        ).errors

    # Non-vacuity: with the key in window the issuer signature is NOT the thing
    # that fails (the link still fails on log standing, which is fine — this
    # test is about which error appears, not about a valid chain).
    assert signature_invalid not in audit(_key_manifest_active())
    # Baseline: an expired manifest makes it fail, and says so.
    assert signature_invalid in audit(_expiring_manifest())
    # The hostile entry produces the same document, hence the same error.
    hostile = _expiring_manifest()
    hostile["keys"][_entry_index(hostile, KID)] = HidesValidTo(
        hostile["keys"][_entry_index(hostile, KID)]
    )
    assert signature_invalid in audit(hostile)


def test_side_document_rails_refuse_a_manifest_that_is_not_data() -> None:
    """A document outside the canonical profile is refused AT THE PARSER, so
    the rails never see it — the refusal moved one step earlier than it used
    to be, and the caller now learns about it when they build the snapshot."""
    unreadable = _key_manifest_active()
    unreadable["manifest_version"] = 1.0  # a float has no canonical form here

    with pytest.raises(trust_material.TrustMaterialError):
        key_manifest(unreadable)


def test_an_unreadable_chain_is_refused_not_deleted() -> None:
    """F1 (security review 2026-09-08): absence is MORE PERMISSIVE than presence.

    A rotation history the verifier never walks cannot mark anything
    discontinuous, so a `chains` member that quietly became empty resurrects a
    key a held manifest marks compromised. The old boundary COPIED what a
    container stores, and a container that stores nothing was emptied rather
    than refused. Through bytes there is nothing to empty: a document either
    carries the chain or does not, and `to_bytes()` gives back what arrived.
    """
    v1 = _key_manifest_active()
    document = store_bytes({ISSUER: v1}, chains={ISSUER: [v1]})
    snapshot = trust_material.TrustStore.from_bytes(document)
    assert snapshot.to_bytes() == canon.canonical_bytes(json.loads(document))
    assert [m.data() for m in snapshot.chain_for(ISSUER)] == [v1]

    # A lazy mapping cannot even become a document: it serializes as what it
    # STORES, which is nothing, and the grammar refuses a chain member that is
    # not an array of objects. The refusal names the member.
    with pytest.raises(trust_material.TrustMaterialError) as exc:
        trust_material.TrustStore.from_bytes(
            json.dumps(
                {"manifests": {ISSUER: v1}, "provenance": {ISSUER: "tls"}, "chains": 1}
            ).encode()
        )
    assert exc.value.member == "chains"


def test_a_lazy_mapping_never_reaches_the_verifier_as_an_empty_one() -> None:
    """The same object, at the door instead of in the document: refused, untouched."""
    hidden = {"manifests": {ISSUER: _key_manifest_active()}, "provenance": {ISSUER: "tls"}}
    _clear()
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    result = verify.verify(envelope, cast("Any", LazyMapping(hidden)))
    assert result.ok is False
    assert _NOT_PARSED_STORE in result.errors
    assert _TOUCHED == [], f"the lazy mapping was consulted: {_TOUCHED}"


def test_a_non_string_key_is_refused_before_its_hash_is_ever_run() -> None:
    """D18: a selector that is not exactly a string selects nothing, and is not
    hashed, compared or coerced on the way to that answer.

    `HostileHashKey` raises from `__hash__`, so a door that looks up before
    checking fails LOUDLY here rather than silently doing the wrong thing.
    """
    snapshot = store({ISSUER: _key_manifest_active()}, chains={ISSUER: [_key_manifest_active()]})
    hostile = HostileHashKey()
    _clear()
    assert snapshot.manifest_for(cast("Any", hostile)) is None
    assert snapshot.chain_for(cast("Any", hostile)) == ()
    assert snapshot.provenance_for(cast("Any", hostile)) is None
    assert manifests.find_key(key_manifest(_key_manifest_active()), cast("Any", hostile)) is None
    with pytest.raises(views.ViewError):
        views.claim_capabilities({}, snapshot, cast("Any", hostile))
    assert _TOUCHED == [], f"a non-string selector was consulted: {_TOUCHED}"


def test_a_subclass_of_str_selects_nothing_even_when_it_answers_like_the_real_one() -> None:
    """`type(x) is str`, never `isinstance`: a subclass answers `==` one way to
    the lookup and can answer another way to whoever reads the result."""

    class Chameleon(str):
        def __eq__(self, other: object) -> bool:
            _TOUCHED.append("Chameleon.__eq__")
            return True

        def __hash__(self) -> int:
            _TOUCHED.append("Chameleon.__hash__")
            return str.__hash__(self)

    snapshot = store({ISSUER: _key_manifest_active()})
    _clear()
    assert snapshot.manifest_for(cast("Any", Chameleon(ISSUER))) is None
    assert snapshot.provenance_for(cast("Any", Chameleon(ISSUER))) is None
    assert _TOUCHED == []
    # ... while the exact string still selects, so the refusal above is the
    # subclass and not a broken lookup.
    assert snapshot.manifest_for(ISSUER) is not None


# ---------------------------------------------------------------------------
# The store document: what the boundary refuses, and how it says so.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "member",
    ["manifests", "provenance", "chains", "artifact_manifests", "artifact_manifest_chains"],
)
def test_hostile_material_is_refused_on_every_store_member_not_only_manifests(
    member: str,
) -> None:
    """Every member, not just the one the first bug was found in.

    A boundary that guards `manifests` and trusts the other four is a boundary
    with four holes: `chains` steers rotation continuity, `provenance` steers
    the trust ladder, and the two artifact members steer currency.
    """
    document: dict[str, Any] = {
        "manifests": {ISSUER: _key_manifest_active()},
        "provenance": {ISSUER: "tls"},
    }
    document[member] = 1  # not the shape the grammar names for this member
    with pytest.raises(trust_material.TrustMaterialError) as exc:
        trust_material.TrustStore.from_bytes(json.dumps(document).encode())
    assert exc.value.member == member, f"blamed {exc.value.member!r} for {member!r}"


def test_the_refusal_names_the_member_that_actually_failed() -> None:
    """An embedder whose artifact manifests are malformed must not be sent to
    debug their key manifests. The message NAMES the member at fault."""
    document = {
        "manifests": {ISSUER: _key_manifest_active()},
        "provenance": {ISSUER: "tls"},
        "artifact_manifests": {ISSUER: "not an object of objects"},
    }
    with pytest.raises(trust_material.TrustMaterialError) as exc:
        trust_material.TrustStore.from_bytes(json.dumps(document).encode())
    assert exc.value.member == "artifact_manifests"
    assert "artifact_manifests" in str(exc.value)
    assert "manifests'" not in str(exc.value).replace("artifact_manifests", "")


def test_a_store_nested_past_the_depth_ceiling_fails_closed() -> None:
    """The ceiling is a refusal, not a truncation: a document one level too
    deep is refused whole, never accepted with the deep part dropped."""
    deep: Any = {}
    node = deep
    for _ in range(canon.MAX_DEPTH + 2):
        node["k"] = {}
        node = node["k"]
    document = {"manifests": {ISSUER: deep}, "provenance": {ISSUER: "tls"}}
    with pytest.raises(trust_material.TrustMaterialError):
        trust_material.TrustStore.from_bytes(json.dumps(document).encode())


def test_trust_store_with_a_hostile_attribute_is_refused_not_raised() -> None:
    """An object whose attributes raise is refused by the door, and the
    exception it wanted to throw never escapes into the caller's code path."""

    class Exploding:
        @property
        def manifests(self) -> dict[str, Any]:  # pragma: no cover - reaching it is the failure
            raise RuntimeError("attribute read reached the verifier")

    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    result = verify.verify(envelope, cast("Any", Exploding()))
    assert result.ok is False
    assert _NOT_PARSED_STORE in result.errors


# ---------------------------------------------------------------------------
# The consumers (section 6.4): a refusal must stay recognisable AS a refusal.
# ---------------------------------------------------------------------------


def test_an_absent_question_and_a_refused_one_are_different_answers() -> None:
    """The capability gate answers FIRST, and that ordering is the contract.

    `evaluate_grant(payload, anything, None)` is `not_checked` because the
    caller supplied no Stage 4 evidence — even when `anything` is not a
    snapshot. Only a caller who DID supply evidence gets the `TypeError`. If
    the store check came first, a caller with no evidence would start seeing
    exceptions for trusted material they never asked to be read.
    """
    payload = make_payload()
    honest = store({ISSUER: _key_manifest_active()})

    assert verify.evaluate_grant(payload, honest, None).grant == "not_checked"
    assert verify.evaluate_grant(payload, cast("Any", {}), None).grant == "not_checked"
    with pytest.raises(TypeError):
        verify.evaluate_grant(payload, cast("Any", {}), {})

    assert (
        verify.evaluate_publisher_authority(payload, honest, None).publisher_authority
        == "not_checked"
    )
    assert (
        verify.evaluate_publisher_authority(payload, cast("Any", {}), None).publisher_authority
        == "not_checked"
    )
    with pytest.raises(TypeError):
        verify.evaluate_publisher_authority(payload, cast("Any", {}), {})


def test_no_policy_can_read_the_refusal_as_an_omitted_check() -> None:
    """The caller's side of the same property, written as a policy would write it.

    A plausible authorization policy reads "the grant was not checked" as "no
    objection from that rail". Feed it a non-snapshot: the point is that it
    cannot REACH its own decision — the exception propagates and there is no
    verdict object to read a field off. This is what an error being an
    exception buys over an error being a verdict.
    """
    payload = make_payload()
    reached = []

    def policy(store_like: object) -> bool:
        verdict = verify.evaluate_grant(payload, cast("Any", store_like), {})
        reached.append(verdict.grant)
        return verdict.grant != "revoked"

    with pytest.raises(TypeError):
        policy({"manifests": {}, "provenance": {}})
    assert reached == [], "the policy reached a verdict it should never have seen"


def test_the_same_material_gives_the_same_verdict_through_every_origin() -> None:
    """Section 6.4: one fixture, two origins, one verdict.

    The corpus origin (V1) hands the library the FILE's bytes; a caller
    assembling a document from its own parts (recipe S1/B1 shape) hands it
    bytes it built. Same material, same verdict, and `to_bytes()` agrees
    because both produced the same document.
    """
    envelope = _to_bytes(issue.issue(make_payload(), KP, KID))
    manifest = _key_manifest_active()

    document = json.dumps({"manifests": {ISSUER: manifest}, "provenance": {ISSUER: "tls"}}).encode()
    from_bytes = trust_material.TrustStore.from_bytes(document)
    from_helper = store({ISSUER: manifest})

    assert from_bytes.to_bytes() == from_helper.to_bytes()
    assert verify.verify(envelope, from_bytes).ok == verify.verify(envelope, from_helper).ok
    assert verify.verify(envelope, from_bytes).trust == verify.verify(envelope, from_helper).trust


# ---------------------------------------------------------------------------
# The helper itself. Tested HERE and not through a caller: a property verified
# on one caller holds until that caller changes.
# ---------------------------------------------------------------------------


def test_the_helper_leaves_an_absent_member_absent() -> None:
    """D17: `None` means ABSENT, and `{}` means present-and-empty.

    `json.dumps` on a dict carrying `"chains": None` writes `"chains":null`,
    which the grammar refuses with M6 — not "absent". The distinction is what
    all of T1 exists to keep, so the helper that builds test documents has to
    make it too, or every test written on top of it measures the wrong thing.
    """
    manifest = {ISSUER: _key_manifest_active()}
    assert b'"chains"' not in store_bytes(manifest)
    assert b'"chains"' not in store_bytes(manifest, chains=None)
    assert b'"chains"' in store_bytes(manifest, chains={})
    assert b'"artifact_manifests"' not in store_bytes(manifest)
    assert b'"artifact_manifest_chains"' not in store_bytes(manifest)

    # Absence survives the round trip, which is the property the helper exists
    # to let tests state.
    assert b'"chains"' not in store(manifest).to_bytes()
    assert b'"chains"' in store(manifest, chains={}).to_bytes()

    # `provenance` is the declared asymmetry: required by the grammar, so
    # `None` derives it rather than omitting it.
    assert b'"provenance"' in store_bytes(manifest)
    assert json.loads(store_bytes(manifest))["provenance"] == {ISSUER: "tls"}


# ---------------------------------------------------------------------------
# 5.6(c) — the export surface and the meta-closure over every public signature.
#
# Both pins carried `xfail(strict=True)` until this commit: at T1 neither held,
# by design. They hold now, so the markers are GONE rather than relaxed — a
# strict xfail is an alarm that rings on success, and when it rings you remove
# it. The observable of that removal is the suite's xfail count, which drops
# from 4 to 2 (the cross-module pin falls at T4b, and one pin predates F6).
#
# `importlib`/`inspect`/`pkgutil`/`typing` are LOCAL to the function that needs
# them rather than at the top of this file: this front shares the worktree, and
# a module-level import here is a wider change than it looks.
# ---------------------------------------------------------------------------


def test_trust_material_all_is_the_serialized_boundarys_three_names() -> None:
    """5.6(c): the export surface, pinned by the exact list rather than
    membership -- a total kept alongside a growing list is the copy that ages
    first, so there is none here: just the list itself.

    The ORDER is alphabetical because `RUF022` is on in this repo and sorts
    `__all__`, not because anything about the boundary prefers it. Section 5.1
    of the plan writes the three names in a different order; that text was
    written without the linter in mind, and a pin that fought the formatter
    would be re-broken by the next `ruff --fix` anyone runs. What the pin
    actually guards is the SET -- three names, these three -- and the order is
    whatever the tool that owns it says.
    """
    assert trust_material.__all__ == ["KeyManifest", "TrustMaterialError", "TrustStore"]


# The closed list of exclusions section 5.6(c) provides for, one entry per
# reason. It is per (module, function, PARAMETER) and not per function name:
# a `build_key_manifest` that tomorrow grew a genuinely trusted `key_manifest`
# argument would be watched again, because only the parameter named here is
# excused.
#
# Measured 2026-09-08 before the flip: the meta-closure reported 22 violations,
# and three of them were never doors. Section 5.5 does not list them, and the
# reason is the same for all three — the parameter is a DOCUMENT the caller is
# building or examining, not trusted material the verifier reasons from.
_EXCLUDED: dict[tuple[str, str, str], str] = {
    ("authority", "build_authorization", "previous"): (
        "builder: `previous` is the author's OWN previous authorization, read to "
        "build its successor. Nothing is trusted from it -- it is the document "
        "being written, and the author already has it as data."
    ),
    ("manifests", "build_key_manifest", "previous"): (
        "builder: same shape, the author's own previous key manifest. Requiring a "
        "snapshot here would mean an issuer had to parse a document they just wrote."
    ),
    ("manifests", "check_artifact_continuity", "candidate"): (
        "both sides are ARTIFACT manifests -- documents under examination, exactly "
        "as in the sibling door `verify_artifact_manifest`, whose section 5.5 row "
        "keeps the artifact `manifest` a dict for this same reason. The key "
        "manifest that authenticates them is a separate argument elsewhere."
    ),
    ("manifests", "check_artifact_continuity", "trusted"): (
        "the other side of the same door, for the same reason: an ARTIFACT "
        "manifest under examination. Watched by NAME since `trusted` joined the "
        "closed set, so it needs its own entry instead of inheriting one."
    ),
    ("views", "build_compromise_claim", "manifest"): (
        "evidence builder named by section 5.6(c) itself: the manifest is the "
        "document the claim is built ABOUT, admitted on the section 18.4 rail."
    ),
    ("views", "key_manifest_log_entry", "manifest"): (
        "evidence builder named by section 5.6(c) itself, same reason."
    ),
}


def _is_handle(annotation: object) -> bool:
    """Does this resolved annotation carry one of the two trust handles?

    Module scope rather than a closure inside `meta_closure_violations`, so the
    non-vacuity test can call the REAL predicate instead of restating it.
    `typing`/`types` stay local, for the reason given above this section.

    A Union counts only when it is exactly {handle, NoneType}: section 5.5
    prescribes `KeyManifest | None` for `views.build_revocation_view`, while
    `KeyManifest | dict` must stay a violation -- that is the case that would
    actually matter.
    """
    import types
    import typing

    handles = (trust_material.TrustStore, trust_material.KeyManifest)
    if annotation in handles:
        return True
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        args = set(typing.get_args(annotation))
        return len(args) == 2 and type(None) in args and bool(args & set(handles))
    return False


def meta_closure_violations() -> list[str]:
    """Every public `attest.*` function whose parameter, by NAME, should carry a
    trust handle but does not, by RESOLVED annotation.

    Watched parameter names (section 5.6(c)'s closed set): `trust_store`,
    `key_manifest`, `trusted_manifest`, `previous`, `candidate`. Excluded: the
    entries of `_EXCLUDED`, each with its reason.

    `typing.get_type_hints`, never the raw `__annotations__` string: `attest`
    uses `from __future__ import annotations` throughout, so a bare string
    compare against "TrustStore" would call `verify.evaluate_grant` closed
    while it still resolved to `verify.py`'s OWN dataclass of that name. Only
    identity with the module under test's two handles counts.

    `KeyManifest | None` COUNTS as a handle, and that is a correction the flip
    forced: section 5.5 prescribes exactly that annotation for
    `views.build_revocation_view`, and an identity check reads a Union as
    neither of its members -- so the pin declared the prescribed signature a
    violation. The pin could not see this before the flip, because until then
    no signature carried an Optional handle to get wrong. A Union is accepted
    only when it is exactly {handle, NoneType}: `KeyManifest | dict` stays a
    violation, which is the case that would actually matter.
    """
    import importlib
    import inspect
    import pkgutil
    import typing

    import attest

    # `trusted` is in this set because `manifests.check_continuity(trusted,
    # candidate)` is a section 5.5 door whose FIRST argument was invisible
    # here: 5.6(c) names the pair `previous`/`candidate`, but the code calls
    # them `trusted`/`candidate`, so one of the two arguments of a migrated
    # door went unwatched -- and, not being watched, it never appeared in the
    # exclusion list either, which is where the accounting would have shown it.
    watched_names = {
        "trust_store",
        "key_manifest",
        "trusted_manifest",
        "trusted",
        "previous",
        "candidate",
    }

    violations: list[str] = []
    for info in pkgutil.iter_modules(attest.__path__, attest.__name__ + "."):
        module = importlib.import_module(info.name)
        stem = info.name.rsplit(".", 1)[-1]
        for name, func in inspect.getmembers(module, inspect.isfunction):
            if name.startswith("_") or func.__module__ != module.__name__:
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
                if (stem, name, param_name) in _EXCLUDED:
                    continue
                annotation = hints.get(param_name)
                if not _is_handle(annotation):
                    violations.append(
                        f"{stem}.{name}({param_name}: {annotation}) is not a trust handle"
                    )
    return violations


def test_no_public_signature_takes_a_trusted_dict_where_a_handle_belongs() -> None:
    """5.6(c): meta-closure over every public signature in `attest.*`.

    PROVES that no public parameter named for trusted material accepts anything
    but the new handle types, by resolved annotation.

    Does NOT prove that the doors which DO carry the right annotation actually
    EXECUTE the handle correctly -- open it once and read nothing else off a
    caller's live object. That is INV-4, measured at the top of this file by
    execution, and no static signature check can see it.
    """
    assert meta_closure_violations() == []


def test_the_meta_closure_is_not_vacuous() -> None:
    """The pin above is only worth its green if it can go red.

    Two ways it could be vacuous and neither is caught by the assertion itself:
    the walk could find no functions at all, or every watched parameter could
    be excluded. Both are checked here, on the real module list.
    """
    import inspect
    import typing

    watched = 0
    for func in (
        manifests.find_key,
        manifests.verify_key_manifest,
        revocation.verify_record,
        transfer.audit_chain,
        verify.verify,
    ):
        params = inspect.signature(func).parameters
        assert {"key_manifest", "trust_store"} & params.keys(), func.__name__
        watched += 1
    assert watched == 5

    # And the Optional correction is exercised on the PREDICATE, both ways. The
    # assertion that used to stand here was `annotation not in (KeyManifest,
    # TrustStore)`, which is true of the Union that must be REFUSED and equally
    # true of the Optional that must be ACCEPTED -- so it could not tell them
    # apart, and a broken normalization would have left it green. Measured.
    def refused(key_manifest: trust_material.KeyManifest | dict[str, Any]) -> bool:
        return True

    def accepted(key_manifest: trust_material.KeyManifest | None) -> bool:
        return True

    globalns = {"trust_material": trust_material, "Any": Any}
    refused_ann = typing.get_type_hints(refused, globalns=globalns)["key_manifest"]
    accepted_ann = typing.get_type_hints(accepted, globalns=globalns)["key_manifest"]
    assert _is_handle(refused_ann) is False
    assert _is_handle(accepted_ann) is True
    assert _is_handle(trust_material.TrustStore) is True
    assert _is_handle(dict) is False


def test_build_revocation_view_accepts_a_record_its_manifest_authenticates() -> None:
    """The POSITIVE half, and it was missing.

    Every existing test of this surface asserts a REFUSAL — a bad record, an
    unusable manifest, a signature that does not verify. Nothing asserted that
    a good record against a good manifest comes back. That gap is not
    cosmetic: it is exactly the shape of hole that hides a door answering
    `False` for the wrong reason, because a door that refuses EVERYTHING
    satisfies every refusal test in the file.

    Measured (2026-09-08): with `views.py` put back on the public door — which,
    holding a tree rather than a handle, answers `False` for everything —
    `tests/test_views.py` stayed GREEN. This test is what makes that
    regression red.
    """
    record = _revocation_record()
    manifest = key_manifest(_key_manifest_active())
    assert views.build_revocation_view([record], manifest) == [record]

    # Non-vacuity in the other direction: the manifest is genuinely doing the
    # work, so the acceptance above is not "this function accepts anything".
    with pytest.raises(views.ViewError, match="does not verify"):
        views.build_revocation_view([record], key_manifest(_expiring_manifest()))
