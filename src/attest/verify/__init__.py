"""Receipt verification core — §6 steps 0-7 (the security heart of attest).

Decides whether a receipt's signature is valid, from which issuer, whether
it is schema-conformant, whether it has been effectively revoked, and
whether a buyer-binding disclosure proves possession of a secret reproducing
an issuer-recorded binding value.

Pipeline invariant: `canon.loads_strict` parses the raw envelope bytes
exactly once (step 0); every later step operates on that single parsed
object, never on the raw bytes or on any re-serialization of it. `alg` is
read from the signature block only to reject anything that is not the
literal string "Ed25519" — it is never used to select a verification
algorithm.

Steps 6 (revocation) and 7 (binding) only run once the receipt already has
a valid signature AND a valid schema (§6: "on the parsed object from step
0" pipeline continues only on success) — an already-invalid receipt never
gets a revocation/binding verdict computed against it; both dimensions stay
at their safe stub values (`revocation: "unknown"`, `binding:
"not_checked"`) exactly like the rest of an invalid result.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from attest import (
    anchor,
    canon,
    commitment,
    keys,
    manifests,
    pq,
    revocation,
    tlog,
    transfer,
    trust_material,
    validate,
)
from attest import (
    authority as authority_module,
)
from attest import grant as grant_module
from attest import transparency as transparency_module
from attest.dates import parse_strict_utc
from attest.verify.binding import _check_binding_challenge, _check_binding_salt, _classify_binding
from attest.verify.chains import (
    _artifact_chain_continuous,
    _chain_continuous,
    _grant_trust_ladder,
    _rotation_chain_verified,
)
from attest.verify.compromise import (
    _authenticated_compromise_claims,
    _b64u_bytes_equal,
    _claim_has_cutoff_signer,
    _compromise_key_material_matches,
    _CompromiseClaim,
    _cutoff_denying_manifests,
    _entries_for_kid,
    _held_issuer_manifests,
    _held_manifest_marks_signer_compromised_at_or_before,
    _integer_manifest_version,
    _manifest_marks_kid_compromised,
    _marking_provenance_is_a_retraction,
    _resolve_compromise_cutoff,
    _resolve_key_status,
    _trusted_manifest_vouches_for_member,
    _vouching_signers,
)
from attest.verify.constants import (
    _ALG,
    _ANCHOR_STATUSES,
    _ANCHORED_BEFORE_PREFIX,
    _AUTHORITY_AUTHORIZED,
    _AUTHORITY_NO_CLAIM,
    _AUTHORITY_NOT_CHECKED,
    _AUTHORITY_SELF,
    _AUTHORITY_TRUST_SIGNER_MISMATCH,
    _AUTHORITY_UNATTESTED,
    _AUTHORITY_UNAUTHORIZED,
    _BINDING_NOT_CHECKED,
    _BINDING_NOT_PROVEN,
    _BINDING_PROVEN,
    _CLAIM_TYPE_KEY_MANIFEST,
    _CLAIM_TYPE_RECEIPT,
    _CLAIM_TYPE_REVOCATION_RECORD,
    _CORROBORATION_NONE,
    _GRANT_ACTIVATED,
    _GRANT_DORMANT,
    _GRANT_INVALID_IGNORED,
    _GRANT_NONE,
    _GRANT_NOT_CHECKED,
    _GRANT_TRUST_NOT_CHECKED,
    _GRANT_TRUST_SIGNER_MISMATCH,
    _HEX_LOWER,
    _KNOWN_EOL_VALUES,
    _KNOWN_PLEDGE_TYPES,
    _MANIFEST_FRESHNESS_NOT_CHECKED,
    _MAX_COMPROMISE_CLAIMS,
    _MAX_REVOCATION_RECORDS,
    _MAX_TRANSFER_CLAIMS,
    _MAX_TRANSPARENCY_EVIDENCE_LEN,
    _PLEDGE_MEMBERS,
    _PROVENANCE_TLS,
    _RECORD_STATUS_REVOKED,
    _REVOCABILITY_NONE,
    _REVOCABILITY_POLICY,
    _REVOCABILITY_REFUND_WINDOW,
    _REVOCATION_INVALID_IGNORED,
    _REVOCATION_NOT_REVOKED_PREFIX,
    _REVOCATION_REVOKED,
    _REVOCATION_TRANSFERRED,
    _REVOCATION_UNKNOWN,
    _SCHEMA_INVALID,
    _SCHEMA_NOT_CHECKED,
    _SCHEMA_VALID,
    _SIG_INVALID,
    _SIG_VALID,
    _STATUS_ACTIVE,
    _STATUS_COMPROMISED,
    _STATUS_RETIRED,
    _SUPPORTED_ATTEST_VERSIONS,
    _TRANSPARENCY_NOT_CHECKED,
    _TRUST_TOFU,
    _TRUST_UNVERIFIED_ROTATION,
    _TRUST_VERIFIED,
    _WARN_ARTIFACT_MANIFEST_ISSUER_MISMATCH,
    _WARN_ARTIFACT_MANIFEST_UNAUTHENTICATED,
    _WARN_ARTIFACT_MANIFEST_UNVERSIONED,
    _WARN_AUTHORIZATION_INVALID_IGNORED,
    _WARN_AUTHORIZATION_SIGNER_NOT_PUBLISHER,
    _WARN_COMPROMISE_CUTOFF_CLAIM_IGNORED,
    _WARN_COMPROMISE_CUTOFF_UNANCHORED,
    _WARN_COMPROMISE_MARKING_RETRACTED,
    _WARN_COMPROMISE_RESCUE_APPLIED,
    _WARN_COMPROMISE_RESCUE_RECEIPT_AFTER_CUTOFF,
    _WARN_COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT,
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
    _WARN_MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING,
    _WARN_PUBLISHER_CLAIM_UNATTESTED,
    _WARN_PUBLISHER_NOT_AUTHORIZING_ISSUER,
    _WARN_REVOCATION_UNLOGGED_DEADLINE,
    _WARN_ROTATION_CHAIN_REQUIRED,
    _WARN_TRANSFER_DOUBLE_ASSIGNMENT,
    _WARN_TRANSFER_NOT_YET_TRANSFERABLE,
    _WARN_TRANSFER_RECORD_UNLOGGED,
    _WARN_TRANSFERRED_REVOCATION_UNBACKED,
    _WARN_TRANSPARENCY_CLAIM_UNRESOLVABLE,
    _WARN_TRANSPARENCY_CONFIG_MISSING,
)
from attest.verify.content import _content_warnings
from attest.verify.evidence import (
    _MAX_EVIDENCE_NODES,
    _VIEW_ARRAY_ELEMENT_NESTING,
    _VIEW_MEMBER_ABSENT,
    _VIEW_MEMBER_COLLAPSED,
    _VIEW_MEMBER_NESTING,
    _admit_evidence_value,
    _admit_single_view_member,
    _materialize_authority_view,
    _materialize_compromise_view,
    _materialize_evidence_array,
    _materialize_evidence_value,
    _materialize_grant_view,
    _own_data_copy,
    _own_view_member,
)
from attest.verify.grants import (
    GrantVerdict,
    _fixed_date_reached,
    _grant_hash_or_none,
    _honor_declarations,
    _pledge_or_none,
    _resolve_effective_grant,
    evaluate_grant,
)
from attest.verify.helpers import (
    _append_warning_once,
    _member_equals,
    _own_member,
    _parse_date,
    _parse_iso,
    _within_validity,
)
from attest.verify.publisher_authority import (
    AuthorityVerdict,
    _admitted_authorizations,
    _authorization_hash_or_none,
    _breaks_successor_discipline,
    _effective_authorization,
    _entries_by_issuer,
    _restriction_outside_bounds,
    _window_shortens,
    evaluate_publisher_authority,
)
from attest.verify.results import Disclosure, TrustStore, VerificationResult
from attest.verify.revocation_status import (
    _classify_revocation,
    _max_revoked_at,
    _not_revoked_or_unknown,
    _refund_window_end,
    _revocation_deadline_satisfied,
    _within_refund_window,
)
from attest.verify.transfer_backing import _resolve_transfer_backing
from attest.verify.transparency_claims import (
    _evaluate_transparency_claim,
    _resolve_log_origin,
    _resolve_transparency_claim,
    _validated_transparency_entry,
)


def verify(
    envelope_bytes: bytes,
    trust_store: TrustStore,
    revocation_view: list[dict[str, Any]] | None = None,
    disclosure: Disclosure | None = None,
    max_revocation_records: int = _MAX_REVOCATION_RECORDS,
    *,
    transparency: dict[str, Any] | None = None,
    log_keys: list[tlog.LogKey] | None = None,
    anchor_policy: anchor.AnchorPolicy | None = None,
    revocation_evidence: dict[str, Any] | None = None,
    transfer_view: list[dict[str, Any]] | None = None,
    compromise_view: list[dict[str, Any]] | None = None,
    witness_policy: object = None,
    grant_view: dict[str, Any] | None = None,
    authority_view: dict[str, Any] | None = None,
) -> VerificationResult:
    """§6 steps 0-7. `max_revocation_records` bounds the untrusted revocation
    view: a larger view is not evaluated (revocation `"unknown"`). It fails
    closed for revocable receipts (`policy`/`refund_window`: an error, so
    `ok` is false) and warns for irrevocable `none` receipts.

    `transparency`/`log_keys`/`anchor_policy` are Stage 2 additions (design
    doc "transparency/corroboration layer"), all keyword-only and defaulting
    to `None` — an existing caller who never passes them sees ZERO behavior
    change: `signature`/`schema`/`revocation`/`binding`/`trust`/`ok` are
    entirely unaffected by these three, which only ever populate the new
    `transparency`/`corroboration`/`manifest_freshness` result components.
    `transparency` carries one untrusted evidence bundle (see
    `attest.transparency.evaluate_transparency`); `log_keys`/`anchor_policy`
    are the verifier's trusted, pinned configuration for evaluating it. A
    malformed `log_keys`/`anchor_policy` raises `attest.transparency.
    TransparencyError` (a config bug); malformed/absent `transparency`
    evidence never raises, only degrades the three new components.

    `revocation_evidence` is G5's (v0.2 §8/§15, TM-47) one exception to the
    "Stage 2 is purely informational" rule: it carries one untrusted
    transparency evidence bundle for a SPECIFIC `refund_window` revocation
    record in `revocation_view`, reusing the SAME `log_keys`/`anchor_policy`
    configuration. Once a verifier is Stage-2 capable (`log_keys` AND
    `anchor_policy` both supplied — the same gate that already governs
    `transparency`), a `refund_window` record is honored only if this
    evidence proves it was logged and anchored no later than the receipt's
    own refund-window deadline; see `_revocation_deadline_satisfied` and
    `_classify_revocation`. A verifier that supplies neither `log_keys` nor
    `anchor_policy` is not Stage-2 capable at all, so this rule never
    engages and v0.1 semantics are unchanged — this is what keeps every
    pre-G5 caller's behavior byte-for-byte identical. `policy`/`compromised`/
    `none` revocability classes are entirely unaffected by this parameter.

    `transfer_view` is v0.2 Stage 3's (§17) evidence channel — the SECOND
    sanctioned exception to "Stage 2 is purely informational", after G5's
    `revocation_evidence`: an untrusted list of claims, each `{"record": <a
    transfer.py transfer record>, "evidence": <§10.2 evidence bundle>}`,
    reusing the SAME `log_keys`/`anchor_policy` Stage-2-capability gate
    (both supplied). A `status: "transferred"` record in `revocation_view`
    is honored — `revocation: "transferred"`, capping `ok` the same way
    `"revoked"` already does — only when this channel proves a BACKED
    transfer record for the same `receipt_id`; see
    `_resolve_transfer_backing` and `_classify_revocation`. A caller that
    never supplies `transfer_view` sees ZERO behavior change, exactly like
    every other Stage 2/3 addition.

    `grant_view` is v0.2 Stage 4's (§18) evidence channel and its capability
    gate at once — see `evaluate_grant`, which this delegates to whole. It is
    NOT a third exception to "Stage 2 is purely informational": per D6, Stage 4
    takes no exception at all, so `grant`/`grant_trust` never touch
    `signature`, `schema`, `revocation`, `binding`, `trust` or `ok`. A caller
    that never supplies it gets `not_checked`/`not_checked` and a byte-for-byte
    unchanged result, exactly like every Stage 2/3 addition before it.

    `authority_view` is v0.2 section 20's caller-supplied evidence channel for
    publisher authorization. It is informational only: `publisher_authority`
    and `publisher_authority_trust` never affect receipt validity or issuer
    trust. A caller that never supplies it gets `not_checked`/`not_checked`;
    the existing publisher-claim warning is then stratified from that verdict.

    `compromise_view` is v0.1 rev 8 / v0.2 §19's fourth sanctioned exception
    to the Stage 2 informational rule: a caller-supplied list of key-manifest
    compromise declarations. Authenticated declarations only ever strengthen
    one status, `compromised`; a Stage-2-capable verifier may then spare a
    receipt whose own receipt claim was anchored strictly before the earliest
    anchored compromise declaration for the signing key.

    `trust_store` is MATERIALIZED before it is read (see
    `_materialized_trust_store`): the verifier decides from the store's own
    DATA, in exact built-in types, never from an embedder's object whose
    `.get`/`__eq__` can answer differently from what it serializes. A store
    that cannot be read as data is a verification error naming itself, not an
    exception; a well-formed store is unaffected.
    """
    # Caller-contract enforcement (security): a non-list `revocation_view`
    # must fail loud. If a lone record OBJECT slipped through here,
    # `_classify_revocation` would iterate its string keys, authenticate
    # nothing, and report `revocation: "unknown"` / `ok: true` for a receipt
    # genuinely revoked under `policy`/`refund_window` — a silent pass on a
    # security check. `None` (no view) stays valid.
    if revocation_view is not None and not isinstance(revocation_view, list):
        raise TypeError("revocation_view must be a list of records or None")
    # Same caller-contract enforcement, extended to the Stage 3 channel: a
    # lone claim OBJECT must fail loud rather than be silently iterated as
    # dict keys by `_resolve_transfer_backing`.
    if transfer_view is not None and not isinstance(transfer_view, list):
        raise TypeError("transfer_view must be a list of claims or None")
    if compromise_view is not None and not isinstance(compromise_view, list):
        raise TypeError("compromise_view must be a list of claims or None")
    # Same caller-contract enforcement for Stage 4's channel: a lone grant
    # DOCUMENT passed where the evidence object belongs would otherwise be
    # read member by member and resolve to `not_checked`, silently reporting
    # "no grant evidence" to a caller who supplied some. Hostile CONTENT
    # inside a well-shaped view never raises — only the wrong container does.
    if grant_view is not None and not isinstance(grant_view, dict):
        raise TypeError("grant_view must be an evidence object or None")
    if authority_view is not None and not isinstance(authority_view, dict):
        raise TypeError("authority_view must be an evidence object or None")

    errors: list[str] = []
    warnings: list[str] = []
    # Conservative default: never claim "verified" trust until we've resolved
    # a manifest whose provenance is actually "tls".
    trust = _TRUST_TOFU
    # Stage 2 defaults — the ZERO-behavior-change values (updated below, once,
    # right after trust is resolved; see the module docstring on
    # `_evaluate_transparency_claim` for why this runs before any pass/fail
    # branching).
    transparency_state = _TRANSPARENCY_NOT_CHECKED
    corroboration_state = _CORROBORATION_NONE
    manifest_freshness_state = _MANIFEST_FRESHNESS_NOT_CHECKED
    transparency_claim_type: str | None = None
    materialized_compromise_view = _materialize_compromise_view(compromise_view)
    # v0.2 §19.2's 64-claim acceptance floor, given the fail-closed effect §6.3
    # requires the owning section to define. Discarding an over-ceiling view in
    # silence is the compromise rail's version of the revocation-view padding
    # attack `_revocation_state` already refuses below: an attacker who can feed
    # this channel — one §19.2 itself blesses for untrusted transport — appends
    # junk claims until a genuine declaration falls off the end, and the receipt
    # that declaration would have killed verifies green with no warning at all.
    # We cannot rule out a declaration, so we cannot certify the signing key.
    compromise_view_supplied = 0
    compromise_view_oversized = False
    if compromise_view is not None:
        try:
            compromise_view_supplied = list.__len__(compromise_view)
        except Exception:
            compromise_view_supplied = _MAX_COMPROMISE_CLAIMS + 1
        compromise_view_oversized = compromise_view_supplied > _MAX_COMPROMISE_CLAIMS

    def _invalid(message: str, *, schema: str = _SCHEMA_NOT_CHECKED) -> VerificationResult:
        errors.append(message)
        return VerificationResult(
            signature=_SIG_INVALID,
            schema=schema,
            revocation=_REVOCATION_UNKNOWN,
            binding=_BINDING_NOT_CHECKED,
            trust=trust,
            transparency=transparency_state,
            corroboration=corroboration_state,
            manifest_freshness=manifest_freshness_state,
            warnings=tuple(warnings),
            errors=tuple(errors),
        )

    def _compromised_key_disposition(
        kid: str,
        entry: dict[str, Any],
        trusted_manifest: dict[str, Any],
        chain: list[dict[str, Any]] | None,
        authenticated_claims: tuple[_CompromiseClaim, ...],
    ) -> VerificationResult | None:
        if log_keys is None or anchor_policy is None:
            return _invalid(f"key {kid} is compromised")
        if transparency_claim_type != _CLAIM_TYPE_RECEIPT or not transparency_state.startswith(
            _ANCHORED_BEFORE_PREFIX
        ):
            _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT)
            return _invalid(f"key {kid} is compromised")
        receipt_anchor = _parse_iso(transparency_state[len(_ANCHORED_BEFORE_PREFIX) :])
        if receipt_anchor is None:
            _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT)
            return _invalid(f"key {kid} is compromised")

        cutoff = _resolve_compromise_cutoff(
            authenticated_claims,
            trusted_manifest,
            chain,
            issuer_id if isinstance(issuer_id, str) else "",
            log_keys,
            anchor_policy,
            warnings,
        )
        if cutoff is None:
            _append_warning_once(warnings, _WARN_COMPROMISE_CUTOFF_UNANCHORED)
            return None
        try:
            if receipt_anchor < cutoff:
                _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_APPLIED)
                return None
        except TypeError:
            pass
        _append_warning_once(warnings, _WARN_COMPROMISE_RESCUE_RECEIPT_AFTER_CUTOFF)
        return _invalid(f"key {kid} is compromised")

    # --- G1 normative ceiling (attest-versioning.md §5 amendment; v0.1 §11/
    # §15, v0.2 §6/§16): the raw envelope MUST NOT exceed MAX_ENVELOPE_BYTES.
    # Checked on the undecoded bytes, before ANY parsing work — the cheapest
    # possible check on input a hostile sender fully controls the size of.
    # Reported as `schema: "invalid"` (not the "not_checked" default every
    # other precondition failure below uses): this ceiling is conformance-
    # surface, not a parse-shape failure.
    size_violations = validate.validate_envelope_size(envelope_bytes)
    if size_violations:
        return _invalid(size_violations[0], schema=_SCHEMA_INVALID)

    # --- Step 0: preconditions — parse once, strictly. All later steps and
    # all downstream consumers operate on this single parsed object, never
    # on the raw bytes (kills sign-vs-parse splits).
    #
    # G1 normative ceiling (attest-versioning.md §5 amendment; v0.1 §11.3):
    # the parsed envelope tree's nesting depth MUST NOT exceed
    # `validate.MAX_JSON_DEPTH` (== `canon.MAX_DEPTH`, 256). Enforced entirely
    # by `canon.loads_strict` itself during parsing (`CanonError`, "maximum
    # nesting depth exceeded") — there is deliberately no separate walk of
    # the parsed tree here (2026-07-22 fix wave): the parser's own structural
    # safety cap already IS this ceiling, so a second, redundant check could
    # never fire (see `validate.py`'s `MAX_JSON_DEPTH` docstring). A receipt
    # that trips it never produces a parsed object at all, so it is reported
    # the same way every other malformed-envelope failure is, `schema:
    # "not_checked"` — unlike the byte-size/manifest-array ceilings below,
    # which run AFTER a successful parse and are conformance-surface checks.
    try:
        parsed = canon.loads_strict(envelope_bytes)
    except canon.CanonError as exc:
        return _invalid(str(exc))

    if not isinstance(parsed, dict):
        return _invalid("envelope is not a JSON object")
    envelope: dict[str, Any] = parsed

    payload_obj = envelope.get("payload")
    if not isinstance(payload_obj, dict):
        return _invalid("envelope missing object member 'payload'")
    payload: dict[str, Any] = payload_obj

    signatures_obj = envelope.get("signatures")
    if not isinstance(signatures_obj, list):
        return _invalid("envelope missing array member 'signatures'")

    # --- The trust-store boundary, immediately before the FIRST read of it.
    # Placed here and not earlier so that every envelope refusal above keeps
    # the verdict and the message it has always had: a snapshot opens, so no
    # existing outcome moves, and something that is not a snapshot is refused
    # before one bit of it has steered a decision.
    #
    # `verify()` ANSWERS rather than raising, unlike `evaluate_*`: this entry
    # point already answers a malformed envelope with `ok: false` and a named
    # reason, and an embedder's request handler should not start crashing
    # because the trust material it was handed is of the wrong kind. The
    # evaluators are the other case — there `not_checked` would be a verdict
    # a policy could misread, so they raise.
    store = trust_material._store_data(trust_store)
    if store is None:
        return _invalid(trust_material._MSG_NOT_PARSED.format(what="trust store"))

    # Resolve trust as soon as we can identify the claimed issuer, even if a
    # later step rejects the receipt — a failed verification still reports
    # the trust level of the manifest that was consulted (or the safe
    # default if none could be identified/resolved). A discontinuous
    # manifest chain (design §5) overrides provenance-based trust entirely:
    # verifiers MUST NOT auto-accept a rotation they can't chain to a root.
    issuer_block = payload.get("issuer")
    issuer_id = issuer_block.get("id") if isinstance(issuer_block, dict) else None
    issuer_manifest: dict[str, Any] | None = None
    if isinstance(issuer_id, str):
        provenance = store.provenance.get(issuer_id)
        trust = _TRUST_VERIFIED if provenance == _PROVENANCE_TLS else _TRUST_TOFU
        issuer_manifest = store.manifests.get(issuer_id)

        # G1 ceiling + G6 detection preflight — ABOVE the chain handling, for
        # structural parity with verify.ts (2026-07-22 fix wave 2 round 2,
        # finding I1 residual: the TS chain tail compare canonicalizes the
        # manifest, so its preflight had to precede the chain block; Python's
        # chain compare is plain equality, but the two verifiers keep the
        # same order so trust in an early-rejection result matches). See the
        # block comment below.
        if isinstance(issuer_manifest, dict):
            issuer_manifest_keys = issuer_manifest.get("keys")
            if (
                isinstance(issuer_manifest_keys, list)
                and len(issuer_manifest_keys) > manifests.MAX_MANIFEST_KEYS
            ):
                return _invalid(
                    f"issuer manifest exceeds {manifests.MAX_MANIFEST_KEYS} keys",
                    schema=_SCHEMA_INVALID,
                )

            # V-L.3 (v0.1 §7.1, 2026-08-26 amendment) — an ambiguous trusted
            # manifest is refused whole, before any key is resolved. Without
            # this, a duplicate on a kid the signature does NOT use left the
            # receipt certifiable: step 3 resolves the signing key with
            # `find_key` directly and never passes through
            # `verify_key_manifest`.
            dup_kids = manifests.duplicate_kids(issuer_manifest_keys)
            if dup_kids:
                return _invalid(
                    f"issuer manifest lists duplicate kid(s): {dup_kids}",
                    schema=_SCHEMA_INVALID,
                )

            if payload.get("attest_version") == "0.2" and manifests.has_active_ed_only_sibling(
                issuer_manifest
            ):
                warnings.append(_WARN_MIXED_KEYSET_ACTIVE_ED_ONLY_SIBLING)

            # V-J.7 — the trusted manifest must authenticate ITSELF before any
            # key is read out of it. The side-document paths have always asked
            # (`transfer`/`revocation` hoist the same call); the receipt path
            # never did, so a manifest edited after it was trusted certified
            # receipts signed by the edit: a swapped `pub` forges a receipt
            # without the issuer's private key, and a `compromised` status
            # flipped back to `active` resurrects signatures §7.3 declares
            # dead. Hoisted here, at the ONE place the manifest is resolved,
            # so both receipt paths (v0.2 hybrid and v0.1) inherit it.
            # Deliberately last in this preflight: the keys ceiling above
            # bounds the work this check does, and running it after the
            # existing refusals leaves their verdicts and messages unchanged.
            if not manifests._manifest_signature_is_authentic(issuer_manifest):
                return _invalid(
                    f"issuer manifest for {issuer_id!r} is not self-consistent: "
                    "its own signature does not verify"
                )

        chain = store.chains.get(issuer_id)
        # v0.1 §7.1 (2026-08-26 amendment): an ambiguous key manifest fails its
        # self-consistency check WHEREVER it is consumed. A held chain member is
        # consumed — by rotation continuity (§7.3) and by v0.2 §19.3's floor and
        # cutoff authentication — so it is refused here on the same terms as the
        # trusted manifest above, before any status or signer is read out of it.
        if chain:
            for member in chain:
                if not isinstance(member, dict):
                    continue
                member_dups = manifests.duplicate_kids(member.get("keys"))
                if member_dups:
                    return _invalid(
                        f"issuer manifest chain lists duplicate kid(s): {member_dups}",
                        schema=_SCHEMA_INVALID,
                    )
        if chain and (not _chain_continuous(chain) or chain[-1] != issuer_manifest):
            # A chain that does not actually end at the manifest being used proves
            # nothing about it — treat it as a discontinuous rotation (2026-07-13
            # review, finding 8).
            trust = _TRUST_UNVERIFIED_ROTATION

    # --- G2/G3 manifest currency (attest-versioning.md rev 4; v0.1 §7.2/§7.3
    # amendment): resolve currency state per (issuer, series), authenticate
    # the pinned manifest and every chain member before touching any currency
    # metadata, then warn legacy manifests or evaluate continuity.
    work_block = payload.get("work")
    artifact_series = work_block.get("artifact_series") if isinstance(work_block, dict) else None
    if isinstance(issuer_id, str) and isinstance(artifact_series, str):
        issuer_artifact_manifests = store.artifact_manifests.get(issuer_id, {})
        candidate_artifact_manifest = issuer_artifact_manifests.get(artifact_series)
        if isinstance(candidate_artifact_manifest, dict):
            am_chain = store.artifact_manifest_chains.get(issuer_id, {}).get(artifact_series)
            members = [candidate_artifact_manifest]
            if am_chain:
                members.extend(am_chain)
            # `_verify_artifact_manifest`, the MATERIALIZED variant: this
            # `all(...)` runs once per chain member against ONE manifest, and
            # `issuer_manifest` came out of `_materialized_trust_store` above.
            # The public door would re-materialize it per member. The boundary
            # is hoisted, not skipped — same shape as the transfer and
            # revocation loops.
            authenticated = (
                isinstance(issuer_manifest, dict)
                and all(
                    manifests._verify_artifact_manifest(member, issuer_manifest)
                    for member in members
                    if isinstance(member, dict)
                )
                and not any(not isinstance(member, dict) for member in members)
            )
            if candidate_artifact_manifest.get("issuer") != issuer_id:
                warnings.append(_WARN_ARTIFACT_MANIFEST_ISSUER_MISMATCH)
            elif not authenticated:
                warnings.append(_WARN_ARTIFACT_MANIFEST_UNAUTHENTICATED)
            else:
                if any("manifest_version" not in member for member in members):
                    # Any legacy member makes currency non-evaluable: warn and
                    # SKIP both continuity and the tail compare — a legacy
                    # manifest must never trigger the currency downgrade
                    # (v0.1 §7.3, warn-only; round-2 review residual).
                    warnings.append(_WARN_ARTIFACT_MANIFEST_UNVERSIONED)
                elif am_chain and (
                    not _artifact_chain_continuous(am_chain)
                    or am_chain[-1] != candidate_artifact_manifest
                ):
                    trust = _TRUST_UNVERIFIED_ROTATION

    # --- G1 normative ceiling, hoisted (attest-versioning.md §5 amendment;
    # v0.1 §11.3): the issuer manifest's `keys[]` array MUST NOT exceed
    # manifests.MAX_MANIFEST_KEYS — checked the moment the manifest is
    # resolved from the trust store, BEFORE any canonicalization/hash/
    # signature/transparency use of it. This MUST run before the transparency
    # block below: `_evaluate_transparency_claim` canonicalizes and SHA-256s
    # `issuer_manifest` whole (via `_resolve_transparency_claim`) to check a
    # key-manifest claim, which is exactly the unbounded work a structural
    # ceiling exists to prevent on a hostile array (2026-07-22 fix wave 2,
    # review finding I1 — this check used to live only after Step 1/2 below,
    # letting transparency/signature work run on an oversized manifest first).
    #
    # G6 mixed-keyset detection is hoisted alongside it (review finding I2):
    # the warning must fire for every v0.2 resolution of a mixed manifest,
    # independent of whether the receipt's signatures go on to verify (v0.2
    # §13/§2.3 amendment) — it used to live only after both signature legs
    # verified, so a tampered/failed receipt never carried it. Detection only
    # depends on the manifest's own keyset and the payload's claimed
    # `attest_version`, neither of which requires any of the crypto/schema
    # work Step 1-4 below still gate their OWN errors on.
    #
    # Round 2 (finding I1 residual): the check itself now lives INSIDE the
    # trust-resolution block above, before the chain handling — mirroring
    # verify.ts, whose chain tail compare canonicalizes the manifest.

    # --- Transparency/corroboration (Stage 2, informational only): resolved
    # here, before any pass/fail branching below, so a receipt that later
    # turns out invalid (e.g. a compromised key) still reports whatever
    # standing the evidence actually earns. Corroboration must never be able
    # to rescue an otherwise-rejected receipt, and demonstrating that
    # requires computing it regardless of the eventual verdict (design fix 6
    # / vector 28i's property) — see `_evaluate_transparency_claim`.
    (
        transparency_state,
        corroboration_state,
        manifest_freshness_state,
        transparency_claim_type,
    ) = _evaluate_transparency_claim(
        envelope,
        issuer_id if isinstance(issuer_id, str) else None,
        issuer_manifest,
        _rotation_chain_verified(
            store.chains.get(issuer_id) if isinstance(issuer_id, str) else None,
            issuer_manifest,
        ),
        transparency,
        log_keys,
        anchor_policy,
        warnings,
        witness_policy,
    )

    # --- Step 1: envelope well-formed; attest_version supported; signatures
    # length == 1 (v0.1) or exactly the hybrid pair (v0.2); alg checked against
    # the literal expected string(s) (read only to reject, never to select).
    attest_version = payload.get("attest_version")
    if not isinstance(attest_version, str) or attest_version not in _SUPPORTED_ATTEST_VERSIONS:
        return _invalid(f"unsupported attest_version: {attest_version!r}")

    if attest_version == "0.2":
        # --- v0.2 hybrid path: AND semantics — both the Ed25519 leg AND the
        # ML-DSA-65 leg must verify, or the receipt is invalid. Every failure
        # below fails closed via `_invalid`, never raising.
        if len(signatures_obj) != 2:
            return _invalid("hybrid envelope requires exactly two signatures")

        sig0, sig1 = signatures_obj
        if not isinstance(sig0, dict) or not isinstance(sig1, dict):
            return _invalid("malformed signature block")

        if sig0.get("alg") != _ALG or sig1.get("alg") != pq.ML_DSA_65_ALG:
            return _invalid("hybrid envelope requires algs Ed25519 and ML-DSA-65 in order")

        kid0 = sig0.get("kid")
        kid1 = sig1.get("kid")
        if kid0 != kid1:
            return _invalid("hybrid envelope signatures must share a single kid")
        if not isinstance(kid0, str):
            return _invalid("malformed signature block: 'kid' must be a string")
        kid = kid0

        ed_sig_b64 = sig0.get("sig")
        mldsa_sig_b64 = sig1.get("sig")
        if not isinstance(ed_sig_b64, str) or not isinstance(mldsa_sig_b64, str):
            return _invalid("malformed signature block: 'sig' must be a string")

        # --- Step 2 (shared with v0.1): issuer binding — resolve the key
        # ONLY from the manifest of payload.issuer.id; the shared kid's
        # DNS-domain prefix and the manifest's own `issuer` field must both
        # equal it, or reject (issuer_mismatch).
        if not isinstance(issuer_id, str):
            return _invalid("malformed payload: missing issuer.id")

        # The SAME object the manifest gate authenticated above. Re-resolving
        # would authenticate one read and verify against another. The
        # isinstance also closes a crash: a trust store mapping an issuer to
        # a non-dict used to raise AttributeError out of the library, while
        # the TypeScript verifier failed closed on the same input.
        manifest = issuer_manifest
        if not isinstance(manifest, dict):
            return _invalid(f"no trusted manifest for issuer {issuer_id!r}")

        # G1's manifest-keys ceiling and G6's mixed-keyset detection are both
        # handled above, hoisted immediately after `issuer_manifest` (== this
        # same `manifest`) is resolved from the trust store — see the comment
        # there (2026-07-22 fix wave 2, findings I1/I2).

        if kid.split("/")[0] != issuer_id or manifest.get("issuer") != issuer_id:
            return _invalid("issuer_mismatch: kid domain does not match payload issuer.id")

        # --- Step 3 (shared with v0.1): key checks — present, not
        # compromised (fail-closed regardless of issued_at), issued_at within
        # the key's validity window.
        entry = manifests._find_key(manifest, kid)
        if entry is None:
            return _invalid(f"no key {kid!r} in issuer manifest")

        chain = store.chains.get(issuer_id)
        authenticated_claims = _authenticated_compromise_claims(
            materialized_compromise_view,
            manifest,
            entry,
            chain,
            issuer_id,
            kid,
            warnings,
        )
        status = _resolve_key_status(entry, manifest, chain, authenticated_claims, kid)
        if compromise_view_oversized and status != _STATUS_COMPROMISED:
            return _invalid(
                f"compromise view exceeds {_MAX_COMPROMISE_CLAIMS} claims "
                f"({compromise_view_supplied} supplied), cannot certify the signing key"
            )
        compromised_rescued = False
        if status == _STATUS_COMPROMISED:
            # Emitted at the point of RESOLUTION and before the §19 disposition,
            # so it reads identically in the kill branch and the rescue branch
            # and its position in the array is deterministic.
            if _marking_provenance_is_a_retraction(manifest, chain, authenticated_claims, kid):
                _append_warning_once(warnings, _WARN_COMPROMISE_MARKING_RETRACTED)
            disposition = _compromised_key_disposition(
                kid, entry, manifest, chain, authenticated_claims
            )
            if disposition is not None:
                return disposition
            compromised_rescued = True
        if not compromised_rescued and status not in (_STATUS_ACTIVE, _STATUS_RETIRED):
            return _invalid(f"key {kid} has unusable status {status!r}")

        issued_at = payload.get("issued_at")
        if not isinstance(issued_at, str) or not _within_validity(issued_at, entry):
            return _invalid(f"issued_at {issued_at!r} outside key validity window")

        if status == _STATUS_RETIRED:
            warnings.append(f"key {kid} is retired")

        # --- Hybrid-only: the resolved key entry must itself carry an
        # ML-DSA-65 public key, or there is nothing to verify the second leg
        # against.
        if "pub_ml_dsa_65" not in entry:
            return _invalid(f"key entry for kid {kid!r} has no ML-DSA-65 public key")

        try:
            ed_pub = keys.b64u_decode(entry["pub"])
            mldsa_pub = keys.b64u_decode(entry["pub_ml_dsa_65"])
            ed_sig = keys.b64u_decode(ed_sig_b64)
            mldsa_sig = keys.b64u_decode(mldsa_sig_b64)
        except (KeyError, TypeError, ValueError) as exc:
            return _invalid(f"malformed key material: {exc}")

        try:
            canonical = canon.canonical_bytes(payload)
            ed_ok = keys.verify_strict(canonical, ed_sig, ed_pub)
        except ValueError as exc:
            return _invalid(f"malformed signature material: {exc}")
        if not ed_ok:
            return _invalid("signature verification failed")

        if not pq.verify_strict(canonical, mldsa_sig, mldsa_pub):
            return _invalid("ML-DSA-65 signature verification failed")
    else:
        if len(signatures_obj) != 1:
            return _invalid(f"signatures must contain exactly one entry, got {len(signatures_obj)}")

        sig_block = signatures_obj[0]
        if not isinstance(sig_block, dict):
            return _invalid("malformed signature block")

        raw_kid = sig_block.get("kid")
        alg = sig_block.get("alg")
        sig_b64 = sig_block.get("sig")
        if not isinstance(raw_kid, str) or not isinstance(sig_b64, str):
            return _invalid("malformed signature block: 'kid'/'sig' must be strings")
        kid = raw_kid

        if alg != _ALG:
            return _invalid(f"unsupported signature algorithm: {alg!r}")

        # --- Step 2: issuer binding — resolve the key ONLY from the manifest
        # of payload.issuer.id; kid's DNS-domain prefix and the manifest's
        # own `issuer` field must both equal it, or reject (issuer_mismatch).
        # This kills cross-issuer impersonation: a valid manifest for
        # evil.example.com can never validate a receipt claiming issuer.id
        # "store.example.com".
        if not isinstance(issuer_id, str):
            return _invalid("malformed payload: missing issuer.id")

        # The SAME object the manifest gate authenticated above. Re-resolving
        # would authenticate one read and verify against another. The
        # isinstance also closes a crash: a trust store mapping an issuer to
        # a non-dict used to raise AttributeError out of the library, while
        # the TypeScript verifier failed closed on the same input.
        manifest = issuer_manifest
        if not isinstance(manifest, dict):
            return _invalid(f"no trusted manifest for issuer {issuer_id!r}")

        # G1's manifest-keys ceiling is handled above, hoisted immediately
        # after `issuer_manifest` (== this same `manifest`) is resolved from
        # the trust store — see the comment there (2026-07-22 fix wave 2,
        # finding I1).

        if kid.split("/")[0] != issuer_id or manifest.get("issuer") != issuer_id:
            return _invalid("issuer_mismatch: kid domain does not match payload issuer.id")

        # --- Step 3: key checks — present, not compromised (fail-closed
        # regardless of issued_at), issued_at within the key's validity window.
        entry = manifests._find_key(manifest, kid)
        if entry is None:
            return _invalid(f"no key {kid!r} in issuer manifest")

        chain = store.chains.get(issuer_id)
        authenticated_claims = _authenticated_compromise_claims(
            materialized_compromise_view,
            manifest,
            entry,
            chain,
            issuer_id,
            kid,
            warnings,
        )
        status = _resolve_key_status(entry, manifest, chain, authenticated_claims, kid)
        if compromise_view_oversized and status != _STATUS_COMPROMISED:
            return _invalid(
                f"compromise view exceeds {_MAX_COMPROMISE_CLAIMS} claims "
                f"({compromise_view_supplied} supplied), cannot certify the signing key"
            )
        compromised_rescued = False
        if status == _STATUS_COMPROMISED:
            # Emitted at the point of RESOLUTION and before the §19 disposition,
            # so it reads identically in the kill branch and the rescue branch
            # and its position in the array is deterministic.
            if _marking_provenance_is_a_retraction(manifest, chain, authenticated_claims, kid):
                _append_warning_once(warnings, _WARN_COMPROMISE_MARKING_RETRACTED)
            disposition = _compromised_key_disposition(
                kid, entry, manifest, chain, authenticated_claims
            )
            if disposition is not None:
                return disposition
            compromised_rescued = True
        if not compromised_rescued and status not in (_STATUS_ACTIVE, _STATUS_RETIRED):
            # Fail closed on missing/unknown status instead of validating
            # like an active key (2026-07-13 review, finding 4).
            return _invalid(f"key {kid} has unusable status {status!r}")

        issued_at = payload.get("issued_at")
        if not isinstance(issued_at, str) or not _within_validity(issued_at, entry):
            return _invalid(f"issued_at {issued_at!r} outside key validity window")

        if status == _STATUS_RETIRED:
            warnings.append(f"key {kid} is retired")

        # --- Hybrid AND rule, v0.1 side (v0.2 §13 side-document rule applied
        # to receipts): a key entry that carries `pub_ml_dsa_65` is a hybrid
        # key, and the reference issuer refuses to sign v0.1 with one
        # (`issue.issue`). `attest_version` is signed, but by the FORGER: an
        # attacker who breaks Ed25519 alone does not strip a v0.2 leg, they mint
        # a fresh "0.1" receipt under the hybrid kid. Without this refusal the
        # PQ leg protects nothing that a v0.1 receipt can say.
        if "pub_ml_dsa_65" in entry:
            return _invalid(
                f"key entry for kid {kid!r} is hybrid; a v0.1 receipt cannot verify under it"
            )

        # --- Step 4: Ed25519.verify(JCS(payload), sig, pub) under the pinned
        # ruleset. canon.canonical_bytes(payload) is the only signature input.
        try:
            pub = keys.b64u_decode(entry["pub"])
            sig = keys.b64u_decode(sig_b64)
        except (KeyError, TypeError, ValueError) as exc:
            return _invalid(f"malformed key material: {exc}")

        try:
            signature_ok = keys.verify_strict(canon.canonical_bytes(payload), sig, pub)
        except ValueError as exc:
            return _invalid(f"malformed signature material: {exc}")

        if not signature_ok:
            return _invalid("signature verification failed")

    # --- Step 5: schema validation of the parsed payload from step 0.
    violations = validate.validate_payload(payload)
    schema_result = _SCHEMA_VALID if not violations else _SCHEMA_INVALID
    errors.extend(violations)

    warnings.extend(_content_warnings(payload))

    # --- Steps 6-7: revocation-by-class and buyer binding. Only evaluated
    # once signature (guaranteed above) AND schema are both valid — see
    # module docstring.
    if schema_result == _SCHEMA_VALID:
        revocation_result = _classify_revocation(
            payload,
            revocation_view,
            manifest,
            warnings,
            errors,
            max_records=max_revocation_records,
            log_keys=log_keys,
            anchor_policy=anchor_policy,
            revocation_evidence=revocation_evidence,
            transfer_view=transfer_view,
        )
        binding_result = (
            _classify_binding(payload, disclosure)
            if disclosure is not None
            else _BINDING_NOT_CHECKED
        )
        # Stage 4 (§18.4). Gated on a valid schema for the same reason
        # revocation and binding are: §18.6's holder-binding conditional makes
        # a pledge-bearing v0.2 receipt without `buyer.pubkey`,
        # `work.publisher_id` or the `sunset-grant` label a SCHEMA ERROR, and
        # evaluating a grant against a payload that failed that conditional
        # would be reasoning about a receipt the verifier has already rejected.
        grant_verdict = evaluate_grant(
            payload,
            trust_store,
            grant_view,
            anchor_policy=anchor_policy,
        )
        authority_verdict = evaluate_publisher_authority(payload, trust_store, authority_view)
    else:
        revocation_result = _REVOCATION_UNKNOWN
        binding_result = _BINDING_NOT_CHECKED
        grant_verdict = GrantVerdict(_GRANT_NOT_CHECKED, _GRANT_TRUST_NOT_CHECKED)
        authority_verdict = AuthorityVerdict(_AUTHORITY_NOT_CHECKED, _AUTHORITY_NOT_CHECKED)

    warnings.extend(authority_verdict.warnings)

    work_block = payload.get("work")
    publisher_id = work_block.get("publisher_id") if isinstance(work_block, dict) else None
    if (
        isinstance(publisher_id, str)
        and isinstance(issuer_id, str)
        and publisher_id != issuer_id
        and authority_verdict.publisher_authority in (_AUTHORITY_NOT_CHECKED, _AUTHORITY_UNATTESTED)
    ):
        warnings.append(_WARN_PUBLISHER_CLAIM_UNATTESTED)
    warnings.extend(grant_verdict.warnings)

    return VerificationResult(
        signature=_SIG_VALID,
        schema=schema_result,
        revocation=revocation_result,
        binding=binding_result,
        trust=trust,
        transparency=transparency_state,
        corroboration=corroboration_state,
        manifest_freshness=manifest_freshness_state,
        warnings=tuple(warnings),
        errors=tuple(errors),
        grant=grant_verdict.grant,
        grant_trust=grant_verdict.grant_trust,
        publisher_authority=authority_verdict.publisher_authority,
        publisher_authority_trust=authority_verdict.publisher_authority_trust,
    )
