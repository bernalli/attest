"""The one place the verifier's local trust material stops being the
embedder's OBJECT and becomes the verifier's DATA.

The module is named for the phrase `verify.TrustStore`'s own docstring uses —
"the verifier's local trust material" — because `trust_store` is already the
parameter name every consumer binds, and a module that shadows it inside the
functions that use it is a footgun waiting for the first careless import.

WHY A BOUNDARY AND NOT A SPELLING RULE
--------------------------------------
`verify.py` and `manifests.py` reach conclusions about a key by asking the
entry: `entry.get("valid_to")`, `entry.get("status") == "compromised"`,
`status not in ("active", "retired")`. Every one of those is shadowable. The
trust store is not wire data — `canon.loads_strict` never touches it — it is
whatever the embedding application put there: an ORM row, a lazy wrapper, a
proxy, a mapping subclass over a database record. Such a value can ANSWER
differently from the data it SERIALIZES, and the serializer takes own data
(`str.__str__`, `dict.__len__`), so the manifest still canonicalizes to the
bytes the issuer signed and its self-authenticity gate is satisfied by
construction. The lie surfaces only at the point of decision, where it turns
an expired key into an immortal one and a `compromised` key back into an
`active` one — v0.1 §7.3's absorbing floor, which is a security property of
the protocol.

Writing the defence at each read site was rejected deliberately. 132 lines of
`verify.py` and 53 of `manifests.py` read a member with `.get(`, and only
THREE of those 53 use the unshadowable `dict.get(x, k)` spelling: a convention
that has to hold at every one of them is re-opened by every line anyone adds,
and the count says it is not holding. This is the same shape of remedy C-211
settled on for the evidence rails: ONE owner, not N copies kept consistent by
good will.

WHAT "MATERIALIZED" MEANS HERE
------------------------------
Every value reachable from the returned structure is of EXACT built-in type:
`type(x) is dict / list / str / int / bool / NoneType`. `isinstance` is not
the test and would not be enough — a `dict` subclass passes `isinstance` and
still rewrites `.get`; a `str` subclass passes `isinstance` and still rewrites
`__eq__`. The guarantee comes from `canon.admit_value`, whose output is
`canon.loads_strict`'s output and therefore consists of nothing else: this
module contributes the POLICY (what is admitted, and what a refusal means),
never a second copy of the HOW.

Fail-closed: material that cannot be expressed in those types raises
`TrustMaterialError`. Callers turn that into an explicit refusal — never a
silent pass, and never a positive verdict.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Final, NamedTuple, cast

from attest import canon

__all__ = [
    "TRUST_STORE_FIELDS",
    "TrustMaterialError",
    "materialize",
    "materialized_key_manifest",
    "trust_store_fields",
]


class TrustMaterialError(ValueError):
    """Trust material that cannot be materialized into exact built-in types.

    Raised, not returned: a trust store the verifier cannot read as data is a
    condition no verdict may be reached from, and the callers that catch it
    each answer with their own explicit refusal.

    `member` names the trust-store field that failed, when the failure happened
    inside one. A refusal that accuses the wrong member sends whoever receives
    it to debug the wrong half of their configuration, so the name travels with
    the exception instead of being guessed by the caller.
    """

    def __init__(self, message: str, member: str | None = None) -> None:
        super().__init__(message)
        self.member = member


# CONTAINERS whose STORED data is their whole content — the criterion, not a
# taxonomy. `canon.own_data_copy` reads what a container STORES, so a container
# that stores nothing and answers from somewhere else is not NEUTRALIZED by the
# copy, it is EMPTIED. Measured against 98f9d04: with `chains` supplied as a
# mapping whose own storage is empty, the member came back with zero members,
# the held rotation history vanished, and a receipt signed by a key a chain
# member marks `compromised` went from `ok=False` to `ok=True` — with `trust`
# rising to `verified` on a store the verifier could not read. For an OPTIONAL
# member absence is not the safe direction: it is the direction that SKIPS the
# check, because `verify._resolve_key_status` calls a key compromised only when
# some held manifest says so.
#
# THE RULE FOR ADDING A TYPE HERE: a container is admitted when it can only
# STORE its members, and refused when it can INVENT or HIDE them. `OrderedDict`
# only stores, and `dict.items` sees exactly its contents, so it is in.
# `defaultdict` answers for keys it does not store — the "answers from
# somewhere else" family this boundary exists to refuse — so it stays out, and
# would stay out even though the copy happens to neutralize it, because the
# contract is about what the type CAN do, not about what one code path
# currently survives.
#
# SCALARS keep §18.4's subtype tolerance: a `str`/`int` subclass carries its own
# data and the copy recovers it, so nothing is lost and refusing would buy
# nothing. Containers are the asymmetric case, and only containers are refused.
_EXACT_MAPPINGS = (dict, OrderedDict)
_EXACT_SEQUENCES = (list,)


def _reads_as_own_data(value: object, budget: list[int]) -> bool:
    """True iff every CONTAINER reachable from `value` stores its own content.

    Walked with the same unshadowable accessors `canon.own_data_copy` uses, and
    under the same node budget, so a container whose iteration never ends is
    refused rather than followed. A value that is neither a mapping nor a
    sequence is left to `canon.admit_value`, which already refuses everything it
    cannot express (measured: `MappingProxyType`, `tuple`, `set`, `float`,
    `bytes` and a bare object all come back inadmissible).

    Mapping KEYS are required to be strings here, one step before
    `canon.own_data_copy` would use them as dict keys. That is not a new rule —
    `canon.dumps` already refuses a non-string key — but it is enforced in a new
    PLACE, and the place is the point: the copy builds its result with
    `copied[own_data_copy(key)] = ...`, which HASHES the key, so a key that is
    not a string reaches the caller's own `__hash__` INSIDE the boundary. A
    `__hash__` that never returns hangs the verifier, and a boundary that can
    hang is not fail-closed. A `str` SUBCLASS is still admitted: the copy takes
    its own data and hashes the exact string.
    """
    budget[0] -= 1
    if budget[0] < 0:
        return False
    if isinstance(value, dict):
        if type(value) not in _EXACT_MAPPINGS:
            return False
        for key, item in dict.items(value):
            if not isinstance(key, str):
                return False
            if not _reads_as_own_data(item, budget):
                return False
        return True
    if isinstance(value, list):
        if type(value) not in _EXACT_SEQUENCES:
            return False
        for index in range(list.__len__(value)):
            if not _reads_as_own_data(list.__getitem__(value, index), budget):
                return False
        return True
    return True


# The `verify.TrustStore` fields this boundary owns, in the order that
# dataclass declares them. Named here so the boundary enumerates what it
# admits instead of walking whatever attributes the object happens to expose:
# a store that grows a sixth field has to be added here, and until it is, the
# field simply never reaches the verifier.
TRUST_STORE_FIELDS = (
    "manifests",
    "provenance",
    "chains",
    "artifact_manifests",
    "artifact_manifest_chains",
)


def materialize(value: object) -> Any:
    """Return `value`'s own data as exact built-in types, or raise.

    Delegates the whole of the work to `canon.admit_value`, the ratified
    reconstruction boundary: it copies own data through unshadowable accessors
    under a node budget, canonicalizes the copy, and re-parses it with
    `loads_strict`. What comes back is a parser's output, so it holds exact
    `dict`/`list`/`str`/`int`/`bool`/`None` and nothing else — the instance the
    caller supplied does not survive, and neither does any subtype of it.

    A SCALAR subtype is never refused for BEING a subtype (§18.4's rule,
    inherited here): its own data is copied out and the copy is what the
    verifier reads, so the copy loses nothing. A CONTAINER subtype that can
    invent or hide members IS refused, and the asymmetry is the point — see
    `_reads_as_own_data`: copying a container that stores nothing does not
    correct it, it deletes it, and a deleted `chains` is a rotation history the
    verifier never walks. Refusal is otherwise for material whose own data
    cannot be expressed at all — a float, an arbitrary object, keys that
    collapse onto one member, a structure past the admission ceilings.

    Nothing is ever DROPPED: a member this function cannot express makes the
    whole value unmaterializable, so a caller never receives a structure
    smaller than the one supplied. That is the property F1 was missing, and it
    is why the failure is an exception rather than a best-effort copy.
    """
    if not _reads_as_own_data(value, [canon.MAX_ADMISSION_NODES]):
        raise TrustMaterialError("trust material is not plain data")
    admitted, materialized = canon.admit_value(value)
    if not admitted:
        raise TrustMaterialError("trust material could not be read as data")
    return materialized


def materialized_key_manifest(key_manifest: object) -> dict[str, Any] | None:
    """One key manifest as DATA, or `None` if it cannot be read as data.

    The trust store is not the only rail that carries TRUSTED material as a
    caller's object: `revocation` and `transfer` take a `key_manifest`
    directly, and `transfer.audit_chain` is a second public entry point in its
    own words. Their predicates decide with `entry.get("status") != "active"`
    and `entry.get("valid_to")` while the signature check reads the entry's
    own data, so the same object is authentic and lying at once, and a record
    signed months after the key expired verifies. Measured, not reasoned
    about: with a `.get` that denies `valid_to`, `revocation.verify_record`
    and `transfer.verify_record` both went from `False` to `True`.

    It lives here rather than in either of those modules so the boundary keeps
    exactly ONE spelling — the property C-211 settled and the reason this
    module exists. `None` is the only failure, never a partial read.
    """
    try:
        materialized = materialize(key_manifest)
    except TrustMaterialError:
        return None
    # `type(...) is not dict`, never `isinstance`: the exact type IS the
    # property — a subclass satisfies `isinstance` and still rewrites `.get`.
    return materialized if type(materialized) is dict else None


def trust_store_fields(store: object) -> dict[str, Any]:
    """Materialize a trust store's five fields, keyed by field name.

    The caller rebuilds its own `TrustStore` from the result; this module
    deliberately does not import `verify` (that cycle is why the dataclass
    stays where it is) and does not construct the object itself.

    Each field is admitted as ONE unit rather than per issuer. The trust store
    is the verifier's own configuration, not adversarial evidence: there is no
    §18.4-style requirement to set one bad element aside on its own, and a
    store the verifier cannot fully read is a store it should not reason from
    at all. Per-issuer admission would not help anyway: the read set is not
    known in advance — the grant rail resolves manifests by grant signer and
    publisher, not only by the receipt's issuer.

    The cost is proportional to the store and each public entry point pays it
    once; an embedder holding a very large store should hand in the part it
    means the verifier to trust.
    """
    fields: dict[str, Any] = {}
    for name in TRUST_STORE_FIELDS:
        try:
            supplied = getattr(store, name)
        except Exception as exc:  # a property/descriptor that refuses to answer
            raise TrustMaterialError(
                f"trust store member {name!r} is unreadable", member=repr(name)
            ) from exc
        try:
            materialized = materialize(supplied)
        except TrustMaterialError as exc:
            # Re-raised carrying the MEMBER NAME: an embedder whose artifact
            # manifests are malformed must not be sent to debug their key
            # manifests.
            raise TrustMaterialError(f"{exc} ({name!r})", member=repr(name)) from exc
        # `type(...) is not dict`, never `isinstance`: the point of the
        # boundary is the EXACT type, and a subclass satisfies `isinstance`
        # while still rewriting `.get`. (After `materialize` nothing else can
        # come back; the check states the postcondition the callers rely on.)
        if type(materialized) is not dict:
            raise TrustMaterialError(
                f"trust store member {name!r} is not an object", member=repr(name)
            )
        fields[name] = materialized
    return fields


# ---------------------------------------------------------------------------
# The serialized boundary (T1): trust material enters as bytes, never as a live
# object. Everything above this line is the materialization family, which the
# doors still use and which falls in T2.
#
# The one thing this boundary buys, and the reason it is a boundary at all: a
# caller hands over bytes, so nothing of the caller's runs while we read them.
# The materialization family had to walk a live object and ask it questions,
# and every question is a place where an attacker's code executes inside the
# verifier's trust decision.
# ---------------------------------------------------------------------------

_ADMIT: Final = object()
"""Module sentinel. Never exported, never stored on any reachable object.

Identity is the whole mechanism: `token is not _ADMIT` runs no `__eq__`, so a
caller cannot forge admission by handing something that compares equal.
"""

# Messages (plan section 5.4). Byte-identical to messages.ts on M1-M8; the
# `{what}` slot is "trust store" or "key manifest". Nothing about the rejected
# value is formatted in: the text is a constant, so a hostile document cannot
# choose what the verifier prints.
_MSG_NOT_BYTES: Final = "{what} must be supplied as serialized bytes; a live object is not accepted"
_MSG_TOO_LARGE: Final = "{what} exceeds the admission ceiling"
# M3 belongs to the DOORS, not to this module's own refusals: it is what a port
# answers when it is handed something that is not a snapshot this library
# parsed. It lives here because the text is owned by the boundary that defines
# what a snapshot is, and because a message defined next to its siblings cannot
# drift from them. The first caller arrives in T2; until then it is text with
# no reader, pinned by the parity fixture like every other message.
_MSG_NOT_PARSED: Final = (
    "{what} must be a parsed snapshot produced by this library; a live object is not accepted"
)
_MSG_NOT_OBJECT: Final = "{what} document must be a JSON object"
_MSG_UNKNOWN_MEMBER: Final = "trust store document has an unknown member {name}"
_MSG_MEMBER_SHAPE: Final = "trust store member {member} must be {expected}"
_MSG_UNPARSABLE: Final = "{what} could not be parsed: {reason}"
_MSG_NOT_CANONICAL: Final = "{what} is outside the canonical profile: {reason}"


def _document_bytes(data: object, *, what: str) -> bytes:
    """Return `data` unchanged iff it is EXACTLY `bytes` and under the ceiling.

    `type(data) is bytes`, never `isinstance`: measured, `isinstance` runs a
    caller's `__class__` property and answers True for a spoof; `type()` reads
    the real class and runs nothing. A `bytes` SUBCLASS is refused too, because
    a subclass can override anything the reader might touch later.

    The ceiling is applied to the INPUT BYTES, while `canon` measures its own
    limit in code points of canonical text. That is deliberate and errs safe:
    UTF-8 spends at least one byte per code point, so anything passing here is
    under canon's ceiling too, and anything over it is refused before being
    decoded -- which is the point of a pre-parse gate.
    """
    if type(data) is not bytes:
        raise TrustMaterialError(_MSG_NOT_BYTES.format(what=what))
    if len(data) > canon.MAX_ADMISSION_BYTES:
        raise TrustMaterialError(_MSG_TOO_LARGE.format(what=what))
    return data


def _parse_document(data: object, *, what: str) -> object:
    """Bytes in, parsed tree out. M1, M2, then M7."""
    raw = _document_bytes(data, what=what)
    try:
        return canon.loads_strict(raw)
    except canon.CanonError as exc:
        raise TrustMaterialError(_MSG_UNPARSABLE.format(what=what, reason=str(exc))) from exc


def _canonical(parsed: object, *, what: str) -> bytes:
    """The admitted domain is what the snapshot can export without loss (D16)."""
    try:
        return canon.canonical_bytes(parsed)
    except canon.CanonError as exc:
        raise TrustMaterialError(_MSG_NOT_CANONICAL.format(what=what, reason=str(exc))) from exc


class _StoreFields(NamedTuple):
    """The five member trees of an admitted store document.

    Absent optional members become a fresh empty dict per instance, never
    shared and never exposed: absence has to survive in `_canonical`, so the
    empty dict is a reading convenience and not a document member (D17).
    """

    manifests: dict[str, Any]
    provenance: dict[str, Any]
    chains: dict[str, Any]
    artifact_manifests: dict[str, Any]
    artifact_manifest_chains: dict[str, Any]


_STORE_MEMBERS: Final = (
    "manifests",
    "provenance",
    "chains",
    "artifact_manifests",
    "artifact_manifest_chains",
)

# Shape of each member, as the grammar of section 5.3 states it: the nesting
# path from the member down to the leaves, and the phrase the refusal uses.
# Derived from one place so the check and the message cannot drift apart -- two
# copies of the same rule are two rules that will disagree eventually.
_MEMBER_SHAPES: Final = {
    "manifests": (("object", "object"), "an object of objects"),
    "provenance": (("object", "string"), "an object of strings"),
    "chains": (("object", "array", "object"), "an object of arrays of objects"),
    "artifact_manifests": (
        ("object", "object", "object"),
        "an object of objects of objects",
    ),
    "artifact_manifest_chains": (
        ("object", "object", "array", "object"),
        "an object of objects of arrays of objects",
    ),
}
_REQUIRED_MEMBERS: Final = ("manifests", "provenance")


def _matches_shape(value: object, path: tuple[str, ...]) -> bool:
    """Whether `value` has the nesting the grammar names for a member.

    Exact types throughout: `type(x) is dict`, never `isinstance`. The whole
    point of the boundary is that the 15 reading sites downstream find the type
    they read, and a subclass is not that type -- it is that type plus whatever
    the caller decided to override.
    """
    kind, rest = path[0], path[1:]
    if kind == "object":
        if type(value) is not dict:
            return False
        return all(_matches_shape(item, rest) for item in value.values()) if rest else True
    if kind == "array":
        if type(value) is not list:
            return False
        return all(_matches_shape(item, rest) for item in value) if rest else True
    return type(value) is str


def _validated_store_document(parsed: object) -> _StoreFields:
    """The grammar of section 5.3, in its stated order: M4, M5, M6, and nothing else.

    The order is part of the contract, not an implementation detail: a document
    with two defects must be refused for the FIRST one, so that a caller fixing
    what the message names makes progress instead of meeting a different
    complaint about the same document.

    What this does NOT validate is as deliberate as what it does: manifest
    contents, the agreement between `manifests[i]` and `chains[i][-1]`, the
    values of `provenance`, empty issuer ids. The boundary guarantees exact
    types, container shape and canonical representability -- that the readers
    find what they read and that `data()`/`to_bytes()` are total. Everything
    else belongs to whoever knows what it means.
    """
    if type(parsed) is not dict:
        raise TrustMaterialError(_MSG_NOT_OBJECT.format(what="trust store"))

    # M5 before M6. WHICH unknown member gets named is the minimum in CANONICAL
    # key order, never the first in document order -- and that is a correction,
    # not a preference. Document order is not a rule a conforming core can
    # implement in both languages: `JSON.parse` hands back an ordinary object,
    # and JavaScript enumerates integer-like keys first whatever the document
    # said, so the order is gone before any boundary can read it (measured
    # 2026-09-08: on `{"manifests":{},"provenance":{},"zz":{},"0":{}}` Python
    # named 'zz' and TypeScript named '0'). Canonical order is the order the
    # protocol already signs on, it is identical in both cores by construction,
    # and it is read from `canon` rather than restated here.
    unknown = [name for name in parsed if name not in _MEMBER_SHAPES]
    if unknown:
        first = min(unknown, key=canon.canonical_key_order)
        raise TrustMaterialError(_MSG_UNKNOWN_MEMBER.format(name=ascii(first)))

    fields: dict[str, dict[str, Any]] = {}
    for name in _STORE_MEMBERS:
        path, expected = _MEMBER_SHAPES[name]
        if name not in parsed:
            if name in _REQUIRED_MEMBERS:
                raise TrustMaterialError(
                    _MSG_MEMBER_SHAPE.format(member=ascii(name), expected=expected),
                    member=name,
                )
            # Absent: read as empty, exported as absent. A member present with
            # value `null` is NOT this case and falls to the shape check below.
            fields[name] = {}
            continue
        value = parsed[name]
        if not _matches_shape(value, path):
            raise TrustMaterialError(
                _MSG_MEMBER_SHAPE.format(member=ascii(name), expected=expected),
                member=name,
            )
        fields[name] = value

    return _StoreFields(**fields)


class KeyManifest:
    """A key manifest that was parsed from bytes by this library, and nothing else.

    There is no public constructor. Holding one of these is the proof that the
    bytes went through `from_bytes`, which is what every door downstream needs
    to know and what it could not learn from a live object.
    """

    __slots__ = ("_canonical", "_data")

    def __init__(self, token: object, data: dict[str, Any], canonical: bytes) -> None:
        if token is not _ADMIT:
            raise TypeError("KeyManifest is built by KeyManifest.from_bytes(data)")
        self._data = data
        self._canonical = canonical

    @classmethod
    def from_bytes(cls, data: object) -> KeyManifest:
        parsed = _parse_document(data, what="key manifest")
        if type(parsed) is not dict:
            raise TrustMaterialError(_MSG_NOT_OBJECT.format(what="key manifest"))
        canonical = _canonical(parsed, what="key manifest")
        return cls(_ADMIT, parsed, canonical)

    def to_bytes(self) -> bytes:
        """The canonical bytes computed at import. `bytes` is immutable: no copy needed."""
        return self._canonical

    def data(self) -> dict[str, Any]:
        """A fresh tree of exact types, every call.

        Re-parsed rather than returned: handing back the internal tree would let
        a caller mutate what a later reader sees, and two readers of the same
        snapshot disagreeing is the whole class of defect this boundary exists
        to end.
        """
        return cast(dict[str, Any], canon.loads_strict(self._canonical))


class TrustStore:
    """A trust store parsed from bytes: five member trees plus the bytes they came from."""

    __slots__ = (
        "_artifact_manifest_chains",
        "_artifact_manifests",
        "_canonical",
        "_chains",
        "_manifests",
        "_provenance",
    )

    def __init__(self, token: object, fields: _StoreFields, canonical: bytes) -> None:
        if token is not _ADMIT:
            raise TypeError("TrustStore is built by TrustStore.from_bytes(data)")
        (
            self._manifests,
            self._provenance,
            self._chains,
            self._artifact_manifests,
            self._artifact_manifest_chains,
        ) = fields
        self._canonical = canonical

    @classmethod
    def from_bytes(cls, data: object) -> TrustStore:
        parsed = _parse_document(data, what="trust store")
        fields = _validated_store_document(parsed)
        # On the document AS RECEIVED (D17): an absent member stays absent in
        # what `to_bytes()` gives back, which is not the same document as one
        # carrying an empty member.
        canonical = _canonical(parsed, what="trust store")
        return cls(_ADMIT, fields, canonical)

    def to_bytes(self) -> bytes:
        return self._canonical

    def data(self) -> dict[str, Any]:
        return cast(dict[str, Any], canon.loads_strict(self._canonical))

    def issuers(self) -> tuple[str, ...]:
        return tuple(sorted(self._manifests))

    def manifest_for(self, issuer_id: object) -> KeyManifest | None:
        # D18: the type check comes BEFORE any hash or lookup, so a hostile
        # object's __hash__/__eq__ never runs. `type() is not str` also refuses
        # a str subclass, which is the shape that gets past a lookup by
        # colliding with a real key.
        if type(issuer_id) is not str:
            return None
        found = self._manifests.get(issuer_id)
        if found is None:
            return None
        return KeyManifest(_ADMIT, found, canon.canonical_bytes(found))

    def chain_for(self, issuer_id: object) -> tuple[KeyManifest, ...]:
        if type(issuer_id) is not str:
            return ()
        return tuple(
            KeyManifest(_ADMIT, m, canon.canonical_bytes(m))
            for m in self._chains.get(issuer_id, ())
        )

    def provenance_for(self, issuer_id: object) -> str | None:
        if type(issuer_id) is not str:
            return None
        return self._provenance.get(issuer_id)


class _StoreData(NamedTuple):
    manifests: dict[str, Any]
    provenance: dict[str, Any]
    chains: dict[str, Any]
    artifact_manifests: dict[str, Any]
    artifact_manifest_chains: dict[str, Any]


def _store_data(store: object) -> _StoreData | None:
    """The snapshot's internal trees, or None if `store` is not a parsed TrustStore."""
    if type(store) is not TrustStore:
        return None
    return _StoreData(
        store._manifests,
        store._provenance,
        store._chains,
        store._artifact_manifests,
        store._artifact_manifest_chains,
    )


def _manifest_data(manifest: object) -> dict[str, Any] | None:
    if type(manifest) is not KeyManifest:
        return None
    return manifest._data
