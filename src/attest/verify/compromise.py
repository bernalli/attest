"""Key compromise: authenticating compromise declarations, resolving a key's
status, and the anchored compromise cutoff (v0.1 rev 8 section 7.3, v0.2
section 19)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from attest import anchor, canon, keys, manifests, tlog
from attest import transparency as transparency_module
from attest.verify.constants import (
    _ANCHORED_BEFORE_PREFIX,
    _CLAIM_TYPE_KEY_MANIFEST,
    _STATUS_ACTIVE,
    _STATUS_COMPROMISED,
    _STATUS_RETIRED,
    _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED,
)
from attest.verify.helpers import _append_warning_once, _parse_iso, _within_validity
from attest.verify.transparency_claims import _resolve_log_origin, _validated_transparency_entry


@dataclass(frozen=True)
class _CompromiseClaim:
    manifest: dict[str, Any]
    evidence: object
    signer_kid: str
    vouching_signers: tuple[dict[str, Any], ...]


def _held_issuer_manifests(
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
) -> list[dict[str, Any]]:
    held = [trusted_manifest]
    if chain is not None:
        held.extend(member for member in chain if isinstance(member, dict))
    return [member for member in held if member.get("issuer") == issuer_id]


def _b64u_bytes_equal(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return keys.b64u_decode(left) == keys.b64u_decode(right)
    except (TypeError, ValueError):
        return False


def _compromise_key_material_matches(
    claim_entry: dict[str, Any], trusted_entry: dict[str, Any]
) -> bool:
    if not _b64u_bytes_equal(claim_entry.get("pub"), trusted_entry.get("pub")):
        return False
    if "pub_ml_dsa_65" not in trusted_entry:
        return True
    return _b64u_bytes_equal(claim_entry.get("pub_ml_dsa_65"), trusted_entry.get("pub_ml_dsa_65"))


def _entries_for_kid(manifest: dict[str, Any], kid: str) -> tuple[dict[str, Any], ...]:
    entries = manifest.get("keys", [])
    if not isinstance(entries, list):
        return ()
    return tuple(entry for entry in entries if isinstance(entry, dict) and entry.get("kid") == kid)


def _manifest_marks_kid_compromised(manifest: dict[str, Any], kid: str) -> bool:
    return any(
        entry.get("status") == _STATUS_COMPROMISED for entry in _entries_for_kid(manifest, kid)
    )


def _vouching_signers(
    claim_manifest: dict[str, Any],
    held_manifests: list[dict[str, Any]],
) -> tuple[str | None, tuple[dict[str, Any], ...]]:
    sig_block = claim_manifest.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return None, ()
    signer_kid = sig_block.get("kid")
    if not isinstance(signer_kid, str):
        return None, ()
    try:
        signable = manifests._signable(claim_manifest)
    except (TypeError, canon.CanonError):
        return signer_kid, ()

    issued_at = claim_manifest.get("issued_at")
    if not isinstance(issued_at, str):
        return signer_kid, ()
    signers: list[dict[str, Any]] = []
    for held_manifest in held_manifests:
        for signer_entry in _entries_for_kid(held_manifest, signer_kid):
            if not _within_validity(issued_at, signer_entry):
                continue
            if manifests.verify_signature_block(signable, sig_block, signer_entry):
                signers.append(signer_entry)
    return signer_kid, tuple(signers)


def _authenticated_compromise_claims(
    compromise_claims: list[Any] | None,
    trusted_manifest: dict[str, Any],
    trusted_entry: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
    kid: str,
    warnings: list[str],
) -> tuple[_CompromiseClaim, ...]:
    if not compromise_claims:
        return ()

    held_manifests = _held_issuer_manifests(trusted_manifest, chain, issuer_id)
    authenticated: list[_CompromiseClaim] = []
    for claim in compromise_claims:
        if not isinstance(claim, dict):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        claim_manifest = claim.get("manifest")
        if not isinstance(claim_manifest, dict) or claim_manifest.get("issuer") != issuer_id:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        manifest_version = claim_manifest.get("manifest_version")
        if not isinstance(manifest_version, int) or isinstance(manifest_version, bool):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        # v0.1 §7.3 (rev 8): the claimed compromised entry may match ANY trusted
        # entry for the kid, not only the one `find_key` happened to return
        # first. With duplicate entries a first-match comparison lets the
        # array's ORDER decide whether a genuine declaration authenticates.
        trusted_entries_for_kid = _entries_for_kid(trusted_manifest, kid) or (trusted_entry,)
        if not any(
            claim_entry.get("status") == _STATUS_COMPROMISED
            and any(
                _compromise_key_material_matches(claim_entry, candidate)
                for candidate in trusted_entries_for_kid
            )
            for claim_entry in _entries_for_kid(claim_manifest, kid)
        ):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        signer_kid, signers = _vouching_signers(claim_manifest, held_manifests)
        if signer_kid is None or not signers:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        authenticated.append(
            _CompromiseClaim(
                manifest=claim_manifest,
                evidence=claim.get("evidence"),
                signer_kid=signer_kid,
                vouching_signers=signers,
            )
        )
    return tuple(authenticated)


def _held_manifest_marks_signer_compromised_at_or_before(
    held_manifests: list[dict[str, Any]], signer_kid: str, declaration_version: int
) -> bool:
    for held_manifest in held_manifests:
        version = held_manifest.get("manifest_version")
        if not isinstance(version, int) or isinstance(version, bool):
            continue
        if version > declaration_version:
            continue
        if _manifest_marks_kid_compromised(held_manifest, signer_kid):
            return True
    return False


def _trusted_manifest_vouches_for_member(
    member: dict[str, Any], trusted_manifest: dict[str, Any]
) -> bool:
    """Does the TRUSTED manifest itself stand behind this held chain member?

    v0.2 §19.3 item 3b lets a held manifest DENY the cutoff, and denial is the
    direction that WIDENS: a receipt §19.1 would have rejected survives. §19's
    own principle — evidence that can only narrow is admitted under weaker
    conditions than evidence that can widen it — therefore asks more of a
    member used this way than the letter of item 3b spells out. This predicate
    is deliberately STRICTER than that letter; the spec is not amended here,
    the code is knowingly the tighter of the two.

    What it requires: the member's `manifest_signature` kid resolves IN THE
    TRUSTED MANIFEST to an entry that is `active` or `retired`, the member's
    `issued_at` falls inside that entry's validity window, and the signature
    verifies under THAT entry's material, hybrid AND rule included.

    Why the trusted manifest and not the member's own `keys[]`: a thief
    holding the stolen key satisfies a self-check by construction — he signs
    the doctored member with the stolen key and it verifies against the copy
    of that key he placed inside it. Only the manifest the verifier already
    trusts can say whether the signing key was still the issuer's to sign
    with. A predicate checking a member against itself closes the
    broken-signature case and leaves this one wide open.

    Never raises; every malformed shape fails closed, and the `keys[]` ceiling
    is checked BEFORE canonicalizing, so a hostile array cannot buy unbounded
    work here (same order as `verify_key_manifest`).
    """
    entries_for_ceiling = member.get("keys")
    if (
        isinstance(entries_for_ceiling, list)
        and len(entries_for_ceiling) > manifests.MAX_MANIFEST_KEYS
    ):
        return False
    sig_block = member.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return False
    signer_kid = sig_block.get("kid")
    if not isinstance(signer_kid, str):
        return False
    issued_at = member.get("issued_at")
    if not isinstance(issued_at, str):
        return False
    signer_entry = manifests._find_key(trusted_manifest, signer_kid)
    if signer_entry is None:
        return False
    if signer_entry.get("status") not in (_STATUS_ACTIVE, _STATUS_RETIRED):
        return False
    if not _within_validity(issued_at, signer_entry):
        return False
    try:
        signable = manifests._signable(member)
    except (TypeError, canon.CanonError):
        return False
    return manifests.verify_signature_block(signable, sig_block, signer_entry)


def _cutoff_denying_manifests(
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
) -> list[dict[str, Any]]:
    """The held manifests allowed to DENY a §19.3 cutoff.

    The trusted manifest is always in: it is the trust anchor, admitted by the
    store's own provenance (v0.1 §7.4) and already self-authenticated by
    `verify()`'s preflight, never by a signature check against itself — `41p`
    and `41r` are the leaves where it legitimately denies the cutoff. Every
    CHAIN MEMBER has to be vouched for by that anchor instead.

    The scope is deliberately this one clause, and the boundary was measured
    rather than chosen. The absorbing status floor (v0.1 §7.3), item 3a's
    vouching set, the retraction warning and the `trust` label all keep
    reading the UNFILTERED held set: extending this predicate to item 3a
    flips `41s` from `ok: false` to `ok: true`, because there every member is
    signed by a key the head marks `compromised`, and without their entries
    to date the signer the cutoff falls and the forgeries survive. `41l` gets
    its floor from a discontinuous chain for the same reason. On this
    perimeter a filter that looks stricter widens who survives.
    """
    held = [trusted_manifest]
    if chain is not None:
        held.extend(
            member
            for member in chain
            if isinstance(member, dict)
            and _trusted_manifest_vouches_for_member(member, trusted_manifest)
        )
    return [member for member in held if member.get("issuer") == issuer_id]


def _claim_has_cutoff_signer(claim: _CompromiseClaim, held_manifests: list[dict[str, Any]]) -> bool:
    declaration_version = claim.manifest.get("manifest_version")
    if not isinstance(declaration_version, int) or isinstance(declaration_version, bool):
        return False
    for signer_entry in claim.vouching_signers:
        if signer_entry.get("status") not in (_STATUS_ACTIVE, _STATUS_RETIRED):
            continue
        if _held_manifest_marks_signer_compromised_at_or_before(
            held_manifests, claim.signer_kid, declaration_version
        ):
            continue
        return True
    return False


def _resolve_compromise_cutoff(
    authenticated_claims: tuple[_CompromiseClaim, ...],
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    issuer_id: str,
    log_keys: list[tlog.LogKey],
    anchor_policy: anchor.AnchorPolicy,
    warnings: list[str],
) -> datetime | None:
    """v0.2 §19.3: minimum anchored declaration time for a kid, or None."""
    if not authenticated_claims:
        return None

    origin = _resolve_log_origin(log_keys)
    transparency_module._validate_policy(anchor_policy)
    # Only manifests the TRUSTED manifest vouches for may deny the cutoff
    # (§19.3 item 3b). Every other consumer of the held set is unchanged.
    held_manifests = _cutoff_denying_manifests(trusted_manifest, chain, issuer_id)
    best: datetime | None = None
    for claim in authenticated_claims:
        if not _claim_has_cutoff_signer(claim, held_manifests):
            continue
        try:
            manifest_sha256 = hashlib.sha256(canon.canonical_bytes(claim.manifest)).hexdigest()
        except (TypeError, canon.CanonError):
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        expected_entry = _validated_transparency_entry(
            {
                "type": _CLAIM_TYPE_KEY_MANIFEST,
                "issuer": claim.manifest.get("issuer"),
                "manifest_version": claim.manifest.get("manifest_version"),
                "manifest_sha256": manifest_sha256,
            }
        )
        if expected_entry is None:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED)
            continue
        result = transparency_module.evaluate_transparency(
            cast(dict[str, Any], claim.evidence),
            log_keys=log_keys,
            expected_origin=origin,
            policy=anchor_policy,
            expected_entry=expected_entry,
        )
        for warning in result.warnings:
            _append_warning_once(warnings, warning)
        if not result.transparency.startswith(_ANCHORED_BEFORE_PREFIX):
            continue
        cutoff = _parse_iso(result.transparency[len(_ANCHORED_BEFORE_PREFIX) :])
        if cutoff is None:
            continue
        if best is None:
            best = cutoff
            continue
        try:
            if cutoff < best:
                best = cutoff
        except TypeError:
            continue
    return best


def _integer_manifest_version(manifest: dict[str, Any]) -> int | None:
    """`manifest_version` only when it is a genuine integer.

    `bool` is excluded explicitly: it subclasses `int`, and a `true` on the
    wire must not be allowed to order versions.
    """
    version = manifest.get("manifest_version")
    if isinstance(version, bool) or not isinstance(version, int):
        return None
    return version


def _marking_provenance_is_a_retraction(
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    authenticated_claims: tuple[_CompromiseClaim, ...],
    kid: str,
) -> bool:
    """v0.1 §7.3 (rev 8): did the issuer take its own marking back?

    True only when the trusted manifest carries an integer version, does NOT
    mark the kid compromised on ANY of its entries, and some held source that
    does mark it carries an integer version strictly lower. Provenance, never a
    verdict: the floor has already decided by the time this runs.

    Every entry for the kid is consulted in every manifest (via
    `_manifest_marks_kid_compromised`): reading the first matching entry would
    let the array's ORDER decide whether the issuer rewrote its history.
    """
    trusted_version = _integer_manifest_version(trusted_manifest)
    if trusted_version is None:
        return False
    if _manifest_marks_kid_compromised(trusted_manifest, kid):
        return False
    sources: list[dict[str, Any]] = []
    if chain is not None:
        sources.extend(manifest for manifest in chain if isinstance(manifest, dict))
    sources.extend(claim.manifest for claim in authenticated_claims)
    for source in sources:
        if not _manifest_marks_kid_compromised(source, kid):
            continue
        source_version = _integer_manifest_version(source)
        if source_version is not None and source_version < trusted_version:
            return True
    return False


def _resolve_key_status(
    trusted_entry: dict[str, Any],
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    authenticated_claims: tuple[_CompromiseClaim, ...],
    kid: str,
) -> object:
    if _manifest_marks_kid_compromised(trusted_manifest, kid):
        return _STATUS_COMPROMISED
    if chain is not None:
        for manifest in chain:
            if not isinstance(manifest, dict):
                continue
            if _manifest_marks_kid_compromised(manifest, kid):
                return _STATUS_COMPROMISED
    if authenticated_claims:
        return _STATUS_COMPROMISED
    return trusted_entry.get("status")
