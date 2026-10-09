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

Layout. This package is the reference verifier, split by concern; every name
below is re-exported here, so `attest.verify.<name>` resolves to the same
object it always has. Imports between the modules only point up this list:

- `constants`: result values, wire warning literals and ceilings.
- `results`: `TrustStore`, `Disclosure`, `VerificationResult`.
- `helpers`: shared fail-closed predicates (dates, validity windows, members).
- `content`: non-fatal payload-content warnings.
- `chains`: manifest chain continuity and the provenance trust ladder.
- `evidence`: the section 18.4 admission boundary for caller evidence rails.
- `transparency_claims`: Stage 2 transparency/corroboration of one claim.
- `compromise`: compromise declarations, key status, the anchored cutoff.
- `transfer_backing`: Stage 3 backing of a `transferred` revocation record.
- `revocation_status`: step 6, revocation-by-class.
- `binding`: step 7, buyer binding.
- `grants`: Stage 4, `evaluate_grant`.
- `publisher_authority`: Stage 5, `evaluate_publisher_authority`.
- `pipeline`: `verify()`, the ordered steps 0-7 over one receipt.
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

# The imports above are the ones the single-module `verify.py` made, kept so
# that every module attribute it had still resolves; the ones below re-export
# every name the sibling modules define. This file uses none of them itself,
# hence its ruff F401 and mypy `implicit_reexport` entries in pyproject.toml.
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
from attest.verify.pipeline import verify
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
