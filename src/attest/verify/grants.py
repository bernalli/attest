"""Stage 4: grant evaluation (v0.2 section 18.4), the preservation pledge's
ordered, short-circuiting evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from typing import Any, cast

from attest import anchor, canon, manifests, trust_material
from attest import grant as grant_module
from attest.verify.chains import _grant_trust_ladder
from attest.verify.constants import (
    _GRANT_ACTIVATED,
    _GRANT_DORMANT,
    _GRANT_INVALID_IGNORED,
    _GRANT_NONE,
    _GRANT_NOT_CHECKED,
    _GRANT_TRUST_NOT_CHECKED,
    _GRANT_TRUST_SIGNER_MISMATCH,
    _HEX_LOWER,
    _KNOWN_PLEDGE_TYPES,
    _PLEDGE_MEMBERS,
    _TRUST_TOFU,
    _TRUST_UNVERIFIED_ROTATION,
    _WARN_GRANT_ACTIVATED_BY_SUCCESSOR,
    _WARN_GRANT_COMMITMENT_DIVERGENCE,
    _WARN_GRANT_COMMITMENT_MISMATCH,
    _WARN_GRANT_DECLARATION_IGNORED,
    _WARN_GRANT_LEGAL_TEXT_CHANGED,
    _WARN_GRANT_NARROWING_IGNORED,
    _WARN_GRANT_PLEDGE_TYPE_UNKNOWN,
    _WARN_GRANT_SCOPE_UNCOVERED,
    _WARN_GRANT_SIGNER_NOT_PUBLISHER,
    _WARN_GRANT_UNANCHORED,
)
from attest.verify.evidence import _materialize_grant_view
from attest.verify.helpers import _member_equals, _own_member, _parse_date
from attest.verify.results import TrustStore

# --- Stage 4: grant evaluation (v0.2 §18.4) ----------------------------------


@dataclass(frozen=True)
class GrantVerdict:
    """The outcome of `evaluate_grant` over one receipt and one evidence view:
    §18.5's two purely informational components plus the warnings §18.4's
    ordered steps emitted along the way.

    Kept separate from `VerificationResult` so the evaluation is callable on
    its own — a custodian checking §18.7's preconditions asks this question
    without re-verifying a receipt it has already verified — and so the
    ordered steps stay testable one at a time."""

    grant: str
    grant_trust: str
    warnings: tuple[str, ...] = ()


def _pledge_or_none(payload: object) -> dict[str, Any] | None:
    """`license.preservation_pledge` when it is readable as an object carrying
    the three REQUIRED members of §18.2 with their declared types, else `None`
    (§18.4 step 1's "absent, or unreadable as an object with the three required
    members").

    The object is deliberately NOT closed: it lives inside the payload, whose
    posture toward unrecognized members is tolerant (v0.1 §11.2), and a future
    pledge profile that needs a fourth member must not be a schema error on a
    verifier that predates it.
    """
    if not isinstance(payload, dict):
        return None
    license_block = payload.get("license")
    if not isinstance(license_block, dict):
        return None
    pledge = license_block.get("preservation_pledge")
    if not isinstance(pledge, dict):
        return None
    if not all(isinstance(pledge.get(member), str) for member in _PLEDGE_MEMBERS):
        return None
    if not pledge["pledge"] or not pledge["grant_uri"]:
        return None
    grant_sha256 = pledge["grant_sha256"]
    if len(grant_sha256) != 64 or not set(grant_sha256) <= _HEX_LOWER:
        return None
    return pledge


def _fixed_date_reached(
    evidence: object,
    effective: dict[str, Any],
    fixed_date: str,
    anchor_policy: anchor.AnchorPolicy | None,
) -> bool:
    """§18.4's `fixed-date` proof: an anchored attestation over the EFFECTIVE
    grant's own canonical bytes whose proven chain time `T` satisfies
    `T >= fixed_date`, verified under §11 with the caller's own `AnchorPolicy`
    including the CRQC horizon check.

    `T` is the MAXIMUM over the verified proofs (`AnchorVerdict.anchored_after`),
    deliberately the opposite reduction from §11's `anchored_before`: the two
    answer opposite questions, and taking the minimum here would let one old
    genuine proof hold a grant closed the moment a second, newer one is
    presented.

    A verifier with no `AnchorPolicy` is not anchor-capable at all, so the
    proof cannot be evaluated and the grant stays closed — the direction
    §18.4's failure asymmetry requires. Every malformed input degrades to
    `False`; only a malformed POLICY raises, and that is trusted verifier
    config, not evidence.
    """
    if anchor_policy is None or not isinstance(evidence, dict):
        return False
    seed = canon.canonical_bytes(effective)
    verdict = anchor.verify_seeded_anchor(evidence, seed, anchor_policy)
    if not verdict.anchored or verdict.anchored_after is None:
        return False
    if not anchor.passes_horizon(verdict, anchor_policy):
        return False
    try:
        deadline = int(_parse_date(fixed_date).replace(tzinfo=UTC).timestamp())
    except (TypeError, ValueError):
        return False
    return verdict.anchored_after >= deadline


def evaluate_grant(
    payload: dict[str, Any],
    trust_store: TrustStore,
    grant_view: dict[str, Any] | None,
    *,
    anchor_policy: anchor.AnchorPolicy | None = None,
) -> GrantVerdict:
    """§18.4's deterministic, short-circuiting evaluation order, steps 1-11.

    `grant_view` is Stage 4's evidence channel and its capability gate at once,
    exactly as `transfer_view` is Stage 3's: `None` means the caller is not
    Stage-4-capable and NOTHING is evaluated — `not_checked`/`not_checked`, no
    warnings, which is byte-for-byte what every pre-Stage-4 caller already
    implicitly gets. Supplying the channel AT ALL — even as `{}` — opts into
    the ordered evaluation, whose first three steps then read only the signed
    payload and run BEFORE step 4's "no evidence supplied" short circuit, so a
    defect visible in the receipt itself is never masked by missing evidence.

    The view's four members, all optional:

    - `grant`: the FLOOR grant document the receipt hash-binds (§18.2).
    - `later_grants`: versions the verifier additionally holds, each evaluated
      independently AGAINST THE FLOOR (§18.3).
    - `declarations`: cessation declarations (§18.4), scanned in full.
    - `anchor`: ONE §11 evidence bundle for the `fixed-date` proof. One bundle,
      not a list: §18.4's maximum reduction is over the PROOFS inside a bundle,
      which `anchor.verify_seeded_anchor` already computes, and a list would be
      a third attacker-supplied array with no ceiling of its own.

    Per D6 the verdict takes no exception: neither component ever affects
    `signature`, `schema`, `revocation`, `binding`, `trust` or `ok`.

    Which way this fails is normative (§18.4): a false `activated` authorizes
    distribution of a work that is still on sale, a false `dormant` only means
    a buyer cannot yet redeem. Every missing, unverifiable, malformed or
    ambiguous input therefore resolves to `dormant` or `not_checked`, never to
    `activated`. Hostile evidence never raises; only malformed TRUSTED config
    (an `AnchorPolicy`) does.
    """
    if grant_view is not None and not isinstance(grant_view, dict):
        raise TypeError("grant_view must be an evidence object or None")

    warnings: list[str] = []
    if grant_view is None:
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED)
    # The trust-store boundary for the callers who enter HERE (§18.7's
    # custodian asks this question without re-verifying the receipt). Below
    # the capability gate, so a caller that supplies no Stage 4 evidence pays
    # nothing — and that ORDER is the contract, not an optimization: a caller
    # that supplies no evidence gets `not_checked` even when the store is not a
    # snapshot, because the gate above answered first.
    #
    # Opening the snapshot RAISES rather than answering `not_checked`. The two
    # are not interchangeable: `not_checked` says "you did not ask me to check
    # this", and a policy that reads it as "no objection" would treat malformed
    # trusted configuration as an absent question. A `TypeError` cannot be read
    # that way by anybody — there is no verdict object to misread.
    #
    # The flag this used to carry (`_already_materialized`, set by `verify()`)
    # is gone with the pass it protected: opening a snapshot is a type check
    # and a five-field tuple, not a copy linear in the size of the store, so
    # there is nothing left worth skipping.
    store = trust_material._store_data(trust_store)
    if store is None:
        raise TypeError(trust_material._MSG_NOT_PARSED.format(what="trust store"))
    materialized_grant_view = _materialize_grant_view(grant_view)

    # --- Step 1: the pledge itself, from the signed payload alone.
    pledge = _pledge_or_none(payload)
    if pledge is None:
        return GrantVerdict(_GRANT_NONE, _GRANT_TRUST_NOT_CHECKED)

    # --- Step 2: an unrecognized profile is valid-with-warning as SCHEMA, but
    # MUST NOT be evaluated under `sunset-grant-v1`'s rules — a later profile
    # may attach different meaning to the same members, and guessing is exactly
    # how two conforming implementations reach different verdicts.
    if pledge["pledge"] not in _KNOWN_PLEDGE_TYPES:
        warnings.append(_WARN_GRANT_PLEDGE_TYPE_UNKNOWN)
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))

    # --- Step 3: the issuer's own inconsistency, visible in the signed payload
    # alone, so it is reported whether or not any evidence was supplied. The
    # license term governs and evaluation CONTINUES: the two fields have
    # different authorities, and silently preferring one would hide the
    # inconsistency from the person holding the receipt.
    survivability = payload.get("survivability")
    eol_commitment = (
        survivability.get("eol_commitment_sha256") if isinstance(survivability, dict) else None
    )
    if isinstance(eol_commitment, str) and eol_commitment != pledge["grant_sha256"]:
        warnings.append(_WARN_GRANT_COMMITMENT_DIVERGENCE)

    # --- Step 4: the structural ceilings, then the evidence itself. The
    # ceilings run BEFORE any signature is verified, or they are not ceilings.
    if not isinstance(materialized_grant_view, dict):
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))
    later_grants = cast("list[Any] | None", _own_member(materialized_grant_view, "later_grants"))
    declarations = cast("list[Any] | None", _own_member(materialized_grant_view, "declarations"))
    if not grant_module.within_structural_ceilings(later_grants, declarations):
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))
    floor = _own_member(materialized_grant_view, "grant")
    if not isinstance(floor, dict):
        return GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED, tuple(warnings))

    # --- Step 5: authenticate the floor, then the triple domain binding.
    # `grant_trust` starts at TOFU the moment evidence exists and is reported
    # at its best-available value from here on, even when the evaluation later
    # rejects the document — it MUST NOT be silently reset on failure (§18.5).
    work = payload.get("work")
    publisher_id = work.get("publisher_id") if isinstance(work, dict) else None
    signer = grant_module.signer_domain(floor)
    manifest = store.manifests.get(signer) if isinstance(signer, str) else None
    # The ladder is scoped to the RECEIPT's declared `work.publisher_id` (§18.5,
    # "the trust store's provenance for the resolved `work.publisher_id`"), and
    # NEVER to whatever domain a supplied document happens to name in its `kid`.
    # The document is attacker-supplied and has not authenticated yet at this
    # point: keying the ladder on its signer would let a blob that authenticates
    # against nothing pick any TLS domain the verifier happens to know and buy
    # `grant_trust: "verified"` for the price of appending bytes to an evidence
    # object. The SIGNER's manifest is still what the signature resolves
    # against, below — the two are the same domain in every case that gets past
    # the binding check, and where they differ the answer is `signer_mismatch`,
    # not a trust value borrowed from a stranger.
    grant_trust = (
        _grant_trust_ladder(store, publisher_id, store.manifests.get(publisher_id))
        if isinstance(publisher_id, str)
        else _TRUST_TOFU
    )

    if not isinstance(manifest, dict) or not grant_module._verify_grant(floor, manifest):
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))
    # §18.1: the signer's `kid` DNS prefix MUST equal the resolving manifest's
    # own `issuer`. A trust store that maps one domain to another domain's
    # manifest is a misconfiguration, not a rights-holder mismatch, so it is
    # rejected plainly rather than reported as `signer_mismatch`.
    if manifest.get("issuer") != signer:
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))
    if not isinstance(publisher_id, str) or signer != publisher_id:
        # The marketplace-signing-a-grant-it-has-no-rights-to-concede case,
        # named. Reachable only for a document that ALREADY authenticated
        # (§18.1): an unsigned blob from a foreign domain is a plain rejection,
        # so hostile evidence cannot force a trust value on its own. A receipt
        # with no `publisher_id` at all has no declared rights holder for the
        # signer to mismatch, so that one is a plain rejection too.
        if isinstance(publisher_id, str):
            warnings.append(_WARN_GRANT_SIGNER_NOT_PUBLISHER)
            return GrantVerdict(
                _GRANT_INVALID_IGNORED, _GRANT_TRUST_SIGNER_MISMATCH, tuple(warnings)
            )
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))
    if not _member_equals(floor, "publisher", publisher_id):
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))

    # --- Step 6: the receipt binding. One canonical form, never a second one.
    floor_hash = _grant_hash_or_none(floor)
    if floor_hash is None or floor_hash != pledge["grant_sha256"]:
        warnings.append(_WARN_GRANT_COMMITMENT_MISMATCH)
        return GrantVerdict(_GRANT_INVALID_IGNORED, grant_trust, tuple(warnings))

    # --- Step 7: the floor-relative ratchet (§18.3).
    effective, grant_trust = _resolve_effective_grant(
        floor, floor_hash, later_grants, manifest, grant_trust, warnings
    )

    # --- Step 8: scope coverage, and it is a GATE. Reporting `activated` on an
    # uncovered receipt would tell the holder they may redeem something the
    # grant never spoke about, and would contradict §18.7's own custodian
    # precondition — so neither activation path is evaluated.
    if not grant_module.grant_covers_receipt(effective, payload):
        warnings.append(_WARN_GRANT_SCOPE_UNCOVERED)
        return GrantVerdict(_GRANT_DORMANT, grant_trust, tuple(warnings))

    # --- Step 9: the declaration path, scanned in FULL.
    if _honor_declarations(declarations, effective, store, warnings):
        return GrantVerdict(_GRANT_ACTIVATED, grant_trust, tuple(warnings))

    # --- Step 10: the fixed-date path, reached ONLY because step 9 did not
    # activate. A missing backstop proof says nothing about a grant that is
    # already open, so `grant_unanchored` is not emitted there — that is what
    # keeps the warning set from depending on which spare evidence a caller
    # happened to attach.
    activation = dict.get(effective, "activation")
    modes = dict.get(activation, "modes") if isinstance(activation, dict) else None
    fixed_date = dict.get(activation, "fixed_date") if isinstance(activation, dict) else None
    if isinstance(modes, list) and grant_module.MODE_FIXED_DATE in modes and fixed_date is not None:
        if isinstance(fixed_date, str) and _fixed_date_reached(
            _own_member(materialized_grant_view, "anchor"), effective, fixed_date, anchor_policy
        ):
            return GrantVerdict(_GRANT_ACTIVATED, grant_trust, tuple(warnings))
        warnings.append(_WARN_GRANT_UNANCHORED)

    # --- Step 11.
    return GrantVerdict(_GRANT_DORMANT, grant_trust, tuple(warnings))


def _resolve_effective_grant(
    floor: dict[str, Any],
    floor_hash: str,
    later_grants: object,
    manifest: dict[str, Any],
    grant_trust: str,
    warnings: list[str],
) -> tuple[dict[str, Any], str]:
    """§18.3 step 7: the effective grant is the MAXIMUM `grant_version` over
    the later versions that independently pass both criteria against the FLOOR
    — a maximum over a floor-relative filter, never a sequential fold that
    mutates as candidates are processed, which is what keeps the result
    independent of `later_grants`' presentation order.

    Three ways a supplied version is set aside, deliberately distinguished:

    - It does not AUTHENTICATE against the publisher's manifest: ignored with
      no effect at all. Unauthenticated bytes are free for anyone to produce,
      so letting them move `grant_trust` would hand an attacker a downgrade for
      the price of appending garbage to an array.
    - Its `publisher` differs from the floor's: INADMISSIBLE — §18.3 says such
      a document "is not a later version of this grant at all; it is a
      different grant". It says nothing about this grant's currency, so it is
      ignored with no effect either. (`grant_module.is_non_narrowing` enforces
      the same precondition independently, so a caller holding only that
      predicate cannot be widened into someone else's grant.)
    - It is authenticated, same-publisher, and its `grant_version` is not
      strictly greater than the floor's, or two DISTINCT authenticated
      documents share one `grant_version`: rollback-or-equivocation, rejected
      and reported `grant_trust: "unverified_rotation"` — the same value and
      posture v0.1 §7.3 already uses for manifests. Both are genuine
      publisher-signed artifacts, so an inconsistency among them is a real
      currency signal rather than something an attacker manufactured.

    A byte-identical duplicate of a document already seen is deduplicated
    rather than treated as equivocation: "two DISTINCT authenticated grants" is
    what §18.3 rejects, and a replayed copy is not a second document.
    """
    candidates: dict[str, dict[str, Any]] = {floor_hash: floor}
    # `verify_key_manifest` is hoisted out of the loop and the signature check
    # uses the MATERIALIZED variant: `manifest` came from the already
    # materialized trust store, and the public `verify_grant` would repeat both
    # halves — including a fresh materialization — once per later grant.
    # `isinstance` first: the public `verify_grant` wrapped BOTH halves in a
    # try/except returning False, and hoisting the manifest check out of the
    # loop took it out of that guard. The caller does validate `manifest`
    # before reaching here, so this is belt rather than fix — but a hoist that
    # silently narrows a fail-closed path is the kind of change that is only
    # noticed later, by something else.
    manifest_ok = isinstance(manifest, dict) and manifests._verify_key_manifest(manifest)
    for later in later_grants if isinstance(later_grants, list) else []:
        if (
            not manifest_ok
            or not isinstance(later, dict)
            or not grant_module._verify_grant_signature(later, manifest)
        ):
            continue
        if not _member_equals(later, "publisher", _own_member(floor, "publisher")):
            continue
        later_hash = _grant_hash_or_none(later)
        if later_hash is None:
            continue
        candidates.setdefault(later_hash, later)

    by_version: dict[int, int] = {}
    for document in candidates.values():
        version = document["grant_version"]
        by_version[version] = by_version.get(version, 0) + 1
    equivocating = {version for version, count in by_version.items() if count > 1}
    if equivocating:
        grant_trust = _TRUST_UNVERIFIED_ROTATION

    floor_version = floor["grant_version"]
    passing: list[dict[str, Any]] = []
    narrowing_seen = False
    for document_hash, document in candidates.items():
        if document_hash == floor_hash:
            continue
        version = document["grant_version"]
        if version in equivocating:
            continue
        if version <= floor_version:
            grant_trust = _TRUST_UNVERIFIED_ROTATION
            continue
        if not grant_module.is_non_narrowing(floor, document):
            narrowing_seen = True
            continue
        passing.append(document)

    if narrowing_seen:
        warnings.append(_WARN_GRANT_NARROWING_IGNORED)
    if not passing:
        return floor, grant_trust

    effective = max(passing, key=lambda document: int(document["grant_version"]))
    if grant_module.prose_differs(floor, effective):
        # The structural members of the later version govern; the prose that
        # binds this buyer stays the one their own receipt hash-bound. All
        # three prose-bearing members count, the URI included: a document
        # served from a new location is a new document to the person who has
        # to go read it, even when the hash is unchanged.
        warnings.append(_WARN_GRANT_LEGAL_TEXT_CHANGED)
    return effective, grant_trust


def _honor_declarations(
    declarations: object,
    effective: dict[str, Any],
    store: trust_material._StoreData,
    warnings: list[str],
) -> bool:
    """§18.4 step 9: EVERY supplied declaration is examined; the step never
    stops at the first one that succeeds.

    The full scan is required rather than a short circuit precisely so that the
    warning set is a function of the evidence and not of its arrangement: with
    a mixed set, an implementation that stopped at the first valid declaration
    would report a different result than one that did not, and both would be
    conforming — which is how two honest implementations end up disagreeing in
    front of a user. Both warnings are emitted at most once each.
    """
    honored = False
    by_successor = False
    ignored = False
    for declaration in declarations if isinstance(declarations, list) else []:
        role = grant_module.declaration_signer_role(declaration, effective)
        domain = grant_module.signer_domain(declaration)
        # A successor's manifest is resolved exactly like the publisher's
        # (§18.1) — same shape, same TOFU/TLS ladder, same `compromised`
        # fail-closed. A declaration signed under a key later marked
        # `compromised` ceases to authenticate, and a grant that had activated
        # on it returns to `dormant`: the safe direction, stated in §18.4
        # rather than left to be discovered.
        declaration_manifest = store.manifests.get(domain) if isinstance(domain, str) else None
        if (
            role is None
            or not isinstance(declaration_manifest, dict)
            or declaration_manifest.get("issuer") != domain
            or not grant_module._verify_declaration(declaration, declaration_manifest)
            or not grant_module.declaration_covers_grant(declaration, effective)
        ):
            ignored = True
            continue
        honored = True
        by_successor = by_successor or role == grant_module.SIGNER_ROLE_SUCCESSOR

    if ignored:
        warnings.append(_WARN_GRANT_DECLARATION_IGNORED)
    if honored and by_successor:
        # Informational, never a downgrade: the caller can see that the
        # cessation was declared by a designated third party rather than by
        # the rights holder itself.
        warnings.append(_WARN_GRANT_ACTIVATED_BY_SUCCESSOR)
    return honored


def _grant_hash_or_none(candidate: object) -> str | None:
    """`grant_hash` behind the same fail-closed boundary
    `_authorization_hash_or_none` puts around `authorization_hash`.

    Canonicalization walks a mapping with `__iter__` and `__getitem__`, both of
    which caller-supplied content can override, so hashing a document that
    arrived on an evidence rail is one of the few places §18.4's never-raise
    promise can still be broken after every member read has been made an
    own-item read. The builder-side helpers stay loud on purpose; the boundary
    belongs at the verifier's call site, exactly as §20.4's does.
    """
    try:
        return grant_module.grant_hash(cast(dict[str, Any], candidate))
    except Exception:
        return None
