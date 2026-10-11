"""The verifier's public result and input types: `TrustStore`, `Disclosure`
and the layered `VerificationResult`."""

from __future__ import annotations

from dataclasses import dataclass, field

from attest import trust_material
from attest.verify.constants import (
    _AUTHORITY_NOT_CHECKED,
    _CORROBORATION_NONE,
    _GRANT_NOT_CHECKED,
    _GRANT_TRUST_NOT_CHECKED,
    _MANIFEST_FRESHNESS_NOT_CHECKED,
    _REVOCATION_REVOKED,
    _REVOCATION_TRANSFERRED,
    _SCHEMA_VALID,
    _SIG_VALID,
    _TRANSPARENCY_NOT_CHECKED,
)

# `verify.TrustStore` is the NAME callers have always imported; what it names
# is now the snapshot `trust_material` parses from bytes. Keeping the name is
# not politeness — it is what makes the old call site fail LOUDLY instead of
# silently: `verify.TrustStore(manifests=..., provenance=...)` raises
# `TypeError: TrustStore.__init__() got an unexpected keyword argument
# 'manifests'` at argument binding, before the constructor body runs. Deleting
# the name would have produced `AttributeError: module has no attribute`,
# which reads like a bad import rather than like a contract that changed.
TrustStore = trust_material.TrustStore


@dataclass(frozen=True)
class Disclosure:
    """§3.2 buyer-binding disclosure — exactly one path is meant to be populated.

    Salt path: `identifier` + `identifier_type` + `salt` recompute the
    commitment and compare it against `payload.buyer.commitment`. Challenge
    path: `challenge = (nonce, sig)` verifies an Ed25519 challenge-response
    transcript against `payload.buyer.pubkey`.

    The salt path takes precedence: if all three salt fields are populated,
    `verify()` evaluates it (returning `proven`/`not_proven`) even when a
    `challenge` is also supplied — a fully-specified salt disclosure is a
    legitimate proof, so a stray extra field never downgrades it. A partial
    path (e.g. `salt` without `identifier`, or neither path complete) is a
    malformed disclosure and fails closed to `binding: "not_proven"` rather
    than raising — never trust an under-specified proof.
    """

    identifier: str | None = None
    identifier_type: str | None = None
    salt: bytes | None = None
    challenge: tuple[bytes, bytes] | None = None  # (nonce, sig)


@dataclass(frozen=True)
class VerificationResult:
    """Layered, never boolean (design §6): each dimension of trust is reported
    independently so a caller can degrade gracefully instead of getting a
    single opaque true/false."""

    signature: str  # "valid" | "invalid" (with v0.2 §19's anchored rescue carve-out)
    schema: str  # "valid" | "invalid" | "not_checked"
    revocation: (
        str  # "unknown" | "not_revoked_as_of:<T>" | "revoked" | "invalid_revocation_ignored"
        # | "transferred" (v0.2 §17.3, Stage 3: a BACKED status:"transferred"
        # revocation record extinguishes the old receipt — reachable only
        # under Stage-3-capable verification, i.e. a caller that evaluates
        # `transfer_view`)
    )
    binding: str  # "proven" | "not_proven" | "not_checked"
    trust: str  # "verified" | "unauthenticated_tofu" | "unverified_rotation"
    # Stage 2, informational only (never affect `ok`/`trust`/key-status — see
    # `verify()`'s module-level constants and `_evaluate_transparency_claim`):
    transparency: str = _TRANSPARENCY_NOT_CHECKED
    # "not_checked" | "logged" | "anchored_before:<T>" | "equivocation_detected"
    corroboration: str = _CORROBORATION_NONE  # "none" | "logged" | "witnessed"
    manifest_freshness: str = (
        _MANIFEST_FRESHNESS_NOT_CHECKED  # "not_checked" | "verified_as_of:<N>"
    )
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    # v0.2 Stage 4 (§18.5), informational only and taking NO exception (D6):
    # neither ever affects `signature`, `schema`, `revocation`, `binding`,
    # `trust` or `ok` — a grant is a permission that becomes exercisable, never
    # a validity property of the receipt. Declared LAST so every existing
    # positional construction keeps working, and defaulted to the values every
    # pre-Stage-4 caller already implicitly gets.
    grant: str = _GRANT_NOT_CHECKED
    # "not_checked" | "none" | "dormant" | "activated" | "invalid_grant_ignored"
    grant_trust: str = _GRANT_TRUST_NOT_CHECKED
    # "not_checked" | "verified" | "unauthenticated_tofu" | "unverified_rotation"
    # | "signer_mismatch"
    # v0.2 section 20.5, informational only. Declared after Stage 4 for the
    # same additive-construction reason as `grant`/`grant_trust`.
    publisher_authority: str = _AUTHORITY_NOT_CHECKED
    # "not_checked" | "no_publisher_claim" | "self" | "authorized"
    # | "unauthorized" | "unattested"
    publisher_authority_trust: str = _AUTHORITY_NOT_CHECKED
    # "not_checked" | "verified" | "unauthenticated_tofu" | "unverified_rotation"
    # | "signer_mismatch"

    @property
    def ok(self) -> bool:
        """Design §3.1/§6: an effective revocation record makes a receipt not
        `ok` ("Effective record ⇒ revocation='revoked' (receipt not ok)").
        `invalid_revocation_ignored` and `unknown`/`not_revoked_as_of:<T>` do
        NOT affect `ok` — an ignored-by-class or unverified revocation record
        must never degrade a receipt's validity (that would defeat the
        revocability:none irrevocability guarantee, design vector 16).

        v0.2 Stage 3 (design doc §4): `revocation == "transferred"` caps `ok`
        the same way `"revoked"` already does — a BACKED transfer record
        extinguishes the old receipt exactly as effectively as a plain
        revocation, it is simply reported on a distinct value so a caller can
        tell "sold" from "revoked" on the same feed. Reachable only under
        Stage-3-capable verification (a caller that evaluates
        `transfer_view`); a verifier that never does keeps v0.1's `ok`
        formula unchanged.

        `trust` is deliberately NOT a component: a receipt reached through a
        discontinuous rotation or with no provenance still reports `ok:
        true`. Callers that need identity assurance read `trust` alongside
        `ok`; the CLI exposes this as `--reject-trust`."""
        return (
            self.signature == _SIG_VALID
            and self.schema == _SCHEMA_VALID
            and self.revocation not in (_REVOCATION_REVOKED, _REVOCATION_TRANSFERRED)
            and not self.errors
        )
