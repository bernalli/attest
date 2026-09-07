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

from typing import Any

from attest import canon

__all__ = ["TRUST_STORE_FIELDS", "TrustMaterialError", "materialize", "trust_store_fields"]


class TrustMaterialError(ValueError):
    """Trust material that cannot be materialized into exact built-in types.

    Raised, not returned: a trust store the verifier cannot read as data is a
    condition no verdict may be reached from, and the callers that catch it
    each answer with their own explicit refusal.
    """


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

    A subtype is never refused for BEING a subtype (§18.4's rule, inherited
    here): its own data is copied out and the copy is what the verifier reads.
    Refusal is for material whose own data cannot be expressed at all — a
    float, an arbitrary object, keys that collapse onto one member, a
    structure past the admission ceilings.
    """
    admitted, materialized = canon.admit_value(value)
    if not admitted:
        raise TrustMaterialError("trust material could not be read as data")
    return materialized


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
            raise TrustMaterialError(f"trust store member {name!r} is unreadable") from exc
        materialized = materialize(supplied)
        # `type(...) is not dict`, never `isinstance`: the point of the
        # boundary is the EXACT type, and a subclass satisfies `isinstance`
        # while still rewriting `.get`. (After `materialize` nothing else can
        # come back; the check states the postcondition the callers rely on.)
        if type(materialized) is not dict:
            raise TrustMaterialError(f"trust store member {name!r} is not an object")
        fields[name] = materialized
    return fields
