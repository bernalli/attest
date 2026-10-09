"""The section 18.4 admission boundary for caller-supplied evidence rails.

Binds the vocabulary the verifier reads to the one spelling in `canon`, and
admits the grant, authority and compromise views member by member.
"""

from __future__ import annotations

from typing import Any

from attest import authority as authority_module
from attest import canon
from attest import grant as grant_module
from attest.verify.constants import _MAX_COMPROMISE_CLAIMS

# §18.4's admission boundary has exactly ONE spelling, in `canon` — the leaf
# module both public entry points that admit caller rails can import
# (`verify()` here, `transfer.audit_chain()` there, which cannot import this
# module without closing the cycle `verify -> transfer`). These names are the
# vocabulary the rest of this package reads; they bind to that one boundary
# rather than restating it, because a boundary with two spellings is a boundary
# that will diverge.
_MAX_EVIDENCE_NODES = canon.MAX_ADMISSION_NODES
_own_data_copy = canon.own_data_copy
_admit_evidence_value = canon.admit_value
_materialize_evidence_value = canon.materialize_value
_own_view_member = canon.own_view_member
_materialize_evidence_array = canon.materialize_array
_VIEW_MEMBER_NESTING = canon.VIEW_MEMBER_NESTING
_VIEW_ARRAY_ELEMENT_NESTING = canon.VIEW_ARRAY_ELEMENT_NESTING
_VIEW_MEMBER_ABSENT = canon.VIEW_MEMBER_ABSENT
_VIEW_MEMBER_COLLAPSED = canon.VIEW_MEMBER_COLLAPSED


def _admit_single_view_member(
    view: dict[str, Any], reconstructed: dict[str, Any], member: str
) -> None:
    supplied = _own_view_member(view, member)
    if supplied is _VIEW_MEMBER_ABSENT or supplied is _VIEW_MEMBER_COLLAPSED:
        return
    admitted, materialized = _admit_evidence_value(supplied, _VIEW_MEMBER_NESTING)
    if admitted:
        reconstructed[member] = materialized


def _materialize_grant_view(grant_view: dict[str, Any]) -> dict[str, Any] | None:
    """Admit `grant_view` MEMBER BY MEMBER, over the members §18.4 enumerates.

    The view is never reconstructed as one indivisible value: a single
    unencodable value would then discard the publisher's whole signed evidence
    where §18.4 requires it to be set aside on its own, and anyone able to
    append one member — a relay, a mirror, an aggregating cache — would buy
    `not_checked` for a few hundred bytes of nesting.

    The members are the ones the RAIL defines, never the ones the value
    supplies: `grant` and `anchor` are admitted as single values (one that is
    not admissible is ABSENT), `later_grants` and `declarations` per element. A
    member the rail does not define is not admitted at all — never
    reconstructed, never read, and never a reason to refuse the view or any
    other member. Every read of the caller's object goes through an
    unshadowable `dict` accessor, so a subclass is not refused for BEING a
    subclass either.
    """
    try:
        reconstructed: dict[str, Any] = {}
        later_grants = _own_view_member(grant_view, "later_grants")
        if later_grants is not _VIEW_MEMBER_ABSENT and later_grants is not _VIEW_MEMBER_COLLAPSED:
            materialized_later = _materialize_evidence_array(
                later_grants, grant_module._MAX_GRANT_LATER_VERSIONS
            )
            if materialized_later is not None:
                reconstructed["later_grants"] = materialized_later
        declarations = _own_view_member(grant_view, "declarations")
        if declarations is not _VIEW_MEMBER_ABSENT and declarations is not _VIEW_MEMBER_COLLAPSED:
            materialized_declarations = _materialize_evidence_array(
                declarations, grant_module._MAX_GRANT_DECLARATIONS
            )
            if materialized_declarations is not None:
                reconstructed["declarations"] = materialized_declarations
        _admit_single_view_member(grant_view, reconstructed, "grant")
        _admit_single_view_member(grant_view, reconstructed, "anchor")
    except Exception:
        return None
    return reconstructed


def _materialize_authority_view(authority_view: dict[str, Any]) -> dict[str, Any] | None:
    """Admit `authority_view` MEMBER BY MEMBER, over the members §20.3 enumerates.

    Same rule as `_materialize_grant_view`: `authorizations` is admitted per
    element, `current_authorization_version` as a single value, and a member
    the rail does not define is never read.
    """
    try:
        reconstructed: dict[str, Any] = {}
        authorizations = _own_view_member(authority_view, "authorizations")
        if (
            authorizations is not _VIEW_MEMBER_ABSENT
            and authorizations is not _VIEW_MEMBER_COLLAPSED
        ):
            materialized_authorizations = _materialize_evidence_array(
                authorizations, authority_module.MAX_AUTHORITY_DOCUMENTS
            )
            if materialized_authorizations is not None:
                reconstructed["authorizations"] = materialized_authorizations
        _admit_single_view_member(authority_view, reconstructed, "current_authorization_version")
    except Exception:
        return None
    return reconstructed


def _materialize_compromise_view(
    compromise_view: list[dict[str, Any]] | None,
) -> list[Any] | None:
    if compromise_view is None:
        return None
    try:
        count = list.__len__(compromise_view)
        if count > _MAX_COMPROMISE_CLAIMS:
            return None
        return [
            _materialize_evidence_value(
                list.__getitem__(compromise_view, index),
                _VIEW_MEMBER_NESTING,
            )
            for index in range(count)
        ]
    except Exception:
        return None
