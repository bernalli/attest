"""Stage 5: publisher authority evaluation (v0.2 section 20.4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from attest import authority as authority_module
from attest import grant as grant_module
from attest import transfer, trust_material
from attest.verify.chains import _grant_trust_ladder
from attest.verify.constants import (
    _AUTHORITY_AUTHORIZED,
    _AUTHORITY_NO_CLAIM,
    _AUTHORITY_NOT_CHECKED,
    _AUTHORITY_SELF,
    _AUTHORITY_TRUST_SIGNER_MISMATCH,
    _AUTHORITY_UNATTESTED,
    _AUTHORITY_UNAUTHORIZED,
    _TRUST_UNVERIFIED_ROTATION,
    _WARN_AUTHORIZATION_INVALID_IGNORED,
    _WARN_AUTHORIZATION_SIGNER_NOT_PUBLISHER,
    _WARN_PUBLISHER_NOT_AUTHORIZING_ISSUER,
)
from attest.verify.evidence import _materialize_authority_view
from attest.verify.helpers import _append_warning_once, _member_equals, _own_member
from attest.verify.results import TrustStore

# --- Stage 5: publisher authority evaluation (v0.2 section 20.4) ------------


@dataclass(frozen=True)
class AuthorityVerdict:
    """Section 20.5's authority components plus warnings produced by section
    20.4's ordered evaluation."""

    publisher_authority: str
    publisher_authority_trust: str
    warnings: tuple[str, ...] = ()


def _authorization_hash_or_none(candidate: object, warnings: list[str]) -> str | None:
    try:
        return authority_module.authorization_hash(cast(dict[str, Any], candidate))
    except Exception:
        _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
        return None


def _admitted_authorizations(
    authorizations: list[Any],
    store: trust_material._StoreData,
    publisher_id: str,
    authority_trust: str,
    warnings: list[str],
) -> tuple[dict[str, dict[str, Any]], str]:
    admitted: dict[str, dict[str, Any]] = {}
    seen_hashes: set[str] = set()
    for candidate in authorizations:
        document_hash = _authorization_hash_or_none(candidate, warnings)
        if document_hash is None or document_hash in seen_hashes:
            continue
        seen_hashes.add(document_hash)

        if not isinstance(candidate, dict):
            _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
            continue
        document = candidate
        signer = grant_module.signer_domain(document)
        manifest = store.manifests.get(signer) if isinstance(signer, str) else None
        if not isinstance(manifest, dict) or not authority_module._verify_authorization(
            document, manifest
        ):
            _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
            continue
        if not _member_equals(manifest, "issuer", signer) or not _member_equals(
            document, "publisher", publisher_id
        ):
            _append_warning_once(warnings, _WARN_AUTHORIZATION_INVALID_IGNORED)
            continue
        if signer != publisher_id:
            _append_warning_once(warnings, _WARN_AUTHORIZATION_SIGNER_NOT_PUBLISHER)
            authority_trust = _AUTHORITY_TRUST_SIGNER_MISMATCH
            continue
        admitted[document_hash] = document
    return admitted, authority_trust


def _entries_by_issuer(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = cast(list[dict[str, Any]], document["authorized_issuers"])
    return {entry["issuer_id"]: entry for entry in entries}


def _window_shortens(previous_valid_to: str | None, valid_to: str | None) -> bool:
    if valid_to is None:
        return False
    if previous_valid_to is None:
        return True
    return transfer._parse_date(valid_to) < transfer._parse_date(previous_valid_to)


def _restriction_outside_bounds(
    predecessor_issued_at: str, successor_issued_at: str, valid_to: str
) -> bool:
    endpoint = transfer._parse_date(valid_to)
    return endpoint < transfer._parse_date(
        predecessor_issued_at
    ) or endpoint > transfer._parse_date(successor_issued_at)


def _breaks_successor_discipline(predecessor: dict[str, Any], successor: dict[str, Any]) -> bool:
    try:
        successor_entries = _entries_by_issuer(successor)
        successor_issued_at = cast(str, successor["issued_at"])
        predecessor_issued_at = cast(str, predecessor["issued_at"])
        for predecessor_entry in cast(list[dict[str, Any]], predecessor["authorized_issuers"]):
            issuer_id = predecessor_entry["issuer_id"]
            successor_entry = successor_entries.get(issuer_id)
            if successor_entry is None:
                return True
            if successor_entry["valid_from"] != predecessor_entry["valid_from"]:
                return True

            predecessor_valid_to = cast(str | None, predecessor_entry["valid_to"])
            valid_to = cast(str | None, successor_entry["valid_to"])
            if authority_module.window_spent_at(predecessor_valid_to, successor_issued_at):
                if not authority_module.same_instant(predecessor_valid_to, valid_to):
                    return True
                continue

            if (
                _window_shortens(predecessor_valid_to, valid_to)
                and valid_to is not None
                and _restriction_outside_bounds(
                    predecessor_issued_at, successor_issued_at, valid_to
                )
            ):
                return True
    except Exception:
        return True
    return False


def _effective_authorization(
    admitted: dict[str, dict[str, Any]], authority_trust: str
) -> tuple[dict[str, Any] | None, str]:
    by_version: dict[int, int] = {}
    for document in admitted.values():
        version = int(cast(int, dict.get(document, "authorization_version")))
        by_version[version] = by_version.get(version, 0) + 1

    equivocating = {version for version, count in by_version.items() if count > 1}
    if equivocating:
        authority_trust = _TRUST_UNVERIFIED_ROTATION

    survivors = {
        document_hash: document
        for document_hash, document in admitted.items()
        if int(cast(int, dict.get(document, "authorization_version"))) not in equivocating
    }
    excluded: set[str] = set()
    for predecessor_hash, predecessor in survivors.items():
        predecessor_version = int(cast(int, dict.get(predecessor, "authorization_version")))
        for successor_hash, successor in survivors.items():
            if predecessor_hash == successor_hash:
                continue
            if predecessor_version >= int(cast(int, dict.get(successor, "authorization_version"))):
                continue
            if _breaks_successor_discipline(predecessor, successor):
                excluded.add(successor_hash)

    if excluded:
        authority_trust = _TRUST_UNVERIFIED_ROTATION

    effective_candidates = [
        document for document_hash, document in survivors.items() if document_hash not in excluded
    ]
    if not effective_candidates:
        return None, authority_trust
    return (
        max(
            effective_candidates,
            key=lambda document: int(cast(int, dict.get(document, "authorization_version"))),
        ),
        authority_trust,
    )


def evaluate_publisher_authority(
    payload: dict[str, Any],
    trust_store: TrustStore,
    authority_view: dict[str, Any] | None,
) -> AuthorityVerdict:
    """Section 20.4's deterministic, short-circuiting evaluation order."""
    if authority_view is not None and not isinstance(authority_view, dict):
        raise TypeError("authority_view must be an evidence object or None")

    warnings: list[str] = []
    if authority_view is None:
        return AuthorityVerdict(_AUTHORITY_NOT_CHECKED, _AUTHORITY_NOT_CHECKED)
    # Same boundary, same placement rule, same refusal as `evaluate_grant`
    # above: under the capability gate, and a non-snapshot raises rather than
    # answering `not_checked`.
    store = trust_material._store_data(trust_store)
    if store is None:
        raise TypeError(trust_material._MSG_NOT_PARSED.format(what="trust store"))
    materialized_authority_view = _materialize_authority_view(authority_view)

    # --- Step 1.
    work = _own_member(payload, "work")
    publisher_id = _own_member(work, "publisher_id")
    if not isinstance(publisher_id, str):
        return AuthorityVerdict(_AUTHORITY_NO_CLAIM, _AUTHORITY_NOT_CHECKED)

    # --- Step 2.
    issuer = _own_member(payload, "issuer")
    issuer_id = _own_member(issuer, "id")
    if not isinstance(issuer_id, str):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)

    # --- Step 3.
    if publisher_id == issuer_id:
        return AuthorityVerdict(_AUTHORITY_SELF, _AUTHORITY_NOT_CHECKED)

    # --- Step 4.
    if not isinstance(materialized_authority_view, dict):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)
    authorizations = _own_member(materialized_authority_view, "authorizations")
    if not isinstance(authorizations, list):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)
    if not authority_module.within_structural_ceiling(authorizations):
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)
    if len(authorizations) == 0:
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, _AUTHORITY_NOT_CHECKED)

    # --- Step 5. The ladder is keyed to the RECEIPT's publisher claim, never
    # to any domain named by a supplied document's kid; the document is still
    # attacker-supplied bytes at this point.
    authority_trust = _grant_trust_ladder(store, publisher_id, store.manifests.get(publisher_id))

    # --- Step 6.
    admitted, authority_trust = _admitted_authorizations(
        authorizations, store, publisher_id, authority_trust, warnings
    )

    # --- Step 7.
    effective, authority_trust = _effective_authorization(admitted, authority_trust)
    if effective is None:
        return AuthorityVerdict(_AUTHORITY_UNATTESTED, authority_trust, tuple(warnings))

    # --- Step 8 is the `effective` selection above.

    # --- Step 9.
    entry = authority_module.entry_for_issuer(effective, issuer_id)
    if entry is not None and authority_module.entry_authorizes_receipt(entry, payload):
        return AuthorityVerdict(_AUTHORITY_AUTHORIZED, authority_trust, tuple(warnings))

    # --- Step 10.
    assertion = _own_member(materialized_authority_view, "current_authorization_version")
    if authority_module.is_authorization_version(assertion) and assertion == dict.get(
        effective, "authorization_version"
    ):
        warnings.append(_WARN_PUBLISHER_NOT_AUTHORIZING_ISSUER)
        return AuthorityVerdict(_AUTHORITY_UNAUTHORIZED, authority_trust, tuple(warnings))
    return AuthorityVerdict(_AUTHORITY_UNATTESTED, authority_trust, tuple(warnings))
