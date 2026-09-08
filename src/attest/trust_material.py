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

from typing import Any, Final, NamedTuple, cast

from attest import canon

__all__ = ["KeyManifest", "TrustMaterialError", "TrustStore"]


class TrustMaterialError(ValueError):
    """Trust material this library cannot read as a document.

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


# ---------------------------------------------------------------------------
# The serialized boundary: trust material enters as bytes, never as a live
# object.
#
# WHAT WAS HERE, AND WHY IT IS GONE
#
# Above this line used to sit the materialization family — `materialize`,
# `materialized_key_manifest`, `trust_store_fields`, `TRUST_STORE_FIELDS`,
# `_reads_as_own_data` — which took the caller's LIVE object and copied its
# own data out of it. It worked, and it could not be made safe: copying is a
# read, every read is a question put to the caller's object, and an object
# that answers two questions differently is the whole class (C-216). The
# family is not deprecated, it is deleted; the doors take snapshots now, and
# there is no second way in for a live object to be tolerated by.
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
        """The issuer ids, in the order the SIGNED BYTES put them in.

        `sorted()` on `str` orders by CODE POINT. JCS -- and therefore
        `canon.canonical_key_order`, and therefore the bytes `to_bytes()`
        returns -- orders by UTF-16 CODE UNIT. The two rules disagree on any
        store that mixes an astral issuer id with one in U+E000-U+FFFF, because
        a surrogate code unit sorts BELOW U+E000 while an astral code point
        sorts above U+FFFF. Measured 2026-09-08 on the same document: this core
        answered ('\ue000', '\U00010000') and the TypeScript core answered the
        reverse, so two conforming verifiers listed the same store differently.

        One definition of "which of these names comes first", read from `canon`
        and not restated here, is the entire reason `canonical_key_order` is
        public -- and `_validated_store_document` already uses it to pick which
        unknown member to name.
        """
        return tuple(sorted(self._manifests, key=canon.canonical_key_order))

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
