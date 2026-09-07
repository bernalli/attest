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
from typing import Any

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
