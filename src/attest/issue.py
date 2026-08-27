"""Receipt issuance: assemble a payload, sign it, wrap it in an envelope (§3).

`issue()` is the "mint a receipt" path. `build_payload()` is a convenience
assembler for the §3.1 payload shape; callers may also hand-build a payload
dict and pass it straight to `issue()`. `receipt_hash()` is the §4 receipt
hash used for bundles/dedup.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from attest import canon, commitment, keys, pq, ulid, validate

ALG_ED25519 = "Ed25519"  # hard-coded — never selected from any field, see §3
ALG_ML_DSA_65 = "ML-DSA-65"
_ATTEST_VERSIONS = ("0.1", "0.2")
# kid structure per spec: <issuer-domain>/keys/<label>#<name>
_KID_RE = re.compile(r"^[^/]+/keys/[^/#]+#[^/#]+$")


class IssueError(ValueError):
    """Payload/kid combination cannot be issued as a receipt.

    `violations` carries the schema errors from `validate.validate_payload`
    when the failure was a schema violation; empty otherwise.
    """

    def __init__(self, message: str, violations: list[str] | None = None) -> None:
        super().__init__(message)
        self.violations = violations if violations is not None else []


def issue(
    payload: dict[str, Any],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str,
    *,
    salt: bytes | None = None,
    manifest_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Sign `payload` and return a receipt envelope.

    Order of checks (per spec): schema validity, then kid-domain match
    against `payload["issuer"]["id"]`. Only then is anything signed.

    `attest_version` "0.1" requires a plain `keys.SigningKeyPair` (single
    Ed25519 signature); "0.2" requires `pq.HybridSigningKeys` (two ordered
    signatures, Ed25519 then ML-DSA-65, same kid, over the same canonical
    payload bytes).
    """
    violations = validate.validate_payload(payload)
    if violations:
        raise IssueError("payload failed schema validation: " + "; ".join(violations), violations)

    issuer_id = payload["issuer"]["id"]
    kid_domain = kid.split("/")[0]
    if kid_domain != issuer_id:
        raise IssueError(
            f"kid domain {kid_domain!r} does not match payload issuer.id {issuer_id!r}"
        )
    if not _KID_RE.match(kid):
        # Reject a structurally malformed kid at issuance (2026-07-13 review,
        # finding 16).
        raise IssueError(f"malformed kid {kid!r}: expected '<issuer-domain>/keys/<label>#<name>'")
    if salt is not None and len(salt) != 16:
        # The buyer commitment is over a 16-byte salt; a wrong length would make
        # binding permanently unprovable (2026-07-13 review, finding 15).
        raise IssueError("buyer-binding salt must be exactly 16 bytes")

    attest_version = payload["attest_version"]
    is_hybrid = isinstance(signing_kp, pq.HybridSigningKeys)
    if attest_version == "0.1" and is_hybrid:
        raise IssueError("attest_version 0.1 requires an Ed25519-only signing key")
    if attest_version == "0.2" and not is_hybrid:
        raise IssueError("attest_version 0.2 requires hybrid signing keys")

    payload_bytes = canon.canonical_bytes(payload)
    signatures: list[dict[str, Any]]
    if isinstance(signing_kp, pq.HybridSigningKeys):
        ed_sig = keys.sign(payload_bytes, signing_kp.ed)
        mldsa_sig = pq.sign(payload_bytes, signing_kp.mldsa)
        signatures = [
            {"kid": kid, "alg": ALG_ED25519, "sig": keys.b64u(ed_sig)},
            {"kid": kid, "alg": ALG_ML_DSA_65, "sig": keys.b64u(mldsa_sig)},
        ]
    else:
        sig = keys.sign(payload_bytes, signing_kp)
        signatures = [{"kid": kid, "alg": ALG_ED25519, "sig": keys.b64u(sig)}]

    envelope: dict[str, Any] = {
        "payload": payload,
        "signatures": signatures,
    }

    delivery: dict[str, Any] = {}
    if salt is not None:
        delivery["salt"] = keys.b64u(salt)
    if manifest_snapshot is not None:
        delivery["issuer_manifest"] = manifest_snapshot
    if delivery:
        envelope["delivery"] = delivery

    # The payload was canonicalized above, but the ENVELOPE wraps it in one more
    # level -- and `delivery.salt`/`delivery.issuer_manifest` can push it over on
    # their own. A conforming issuer MUST NOT emit a receipt no conforming
    # verifier can parse (v0.1 §11.3), so the assembled object is checked here,
    # after assembly and before it leaves this function.
    canon.check_object_depth(envelope)

    return envelope


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_payload(
    *,
    issuer_id: str,
    display_name: str,
    buyer_identifier: str,
    buyer_identifier_type: str,
    buyer_salt: bytes,
    title: str,
    publisher: str,
    identifiers: dict[str, str],
    artifact_series: str,
    terms_uri: str,
    legal_text_sha256: str,
    buyer_pubkey: bytes | None = None,
    edition: str | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    grant: str = "perpetual",
    revocability: str = "none",
    revocation_window_days: int | None = None,
    transferable: bool = False,
    drm: str = "drm-free",
    jurisdiction_flags: dict[str, bool] | None = None,
    redownload_right: bool = True,
    mirror_policy_uri: str | None = None,
    mirror_policy_sha256: str | None = None,
    end_of_life: str = "artifacts-remain-redownloadable",
    eol_commitment_uri: str | None = None,
    eol_commitment_sha256: str | None = None,
    publisher_id: str | None = None,
    preservation_pledge: dict[str, Any] | None = None,
    issued_at: str | None = None,
    supersedes: str | None = None,
    receipt_id: str | None = None,
    attest_version: str = "0.1",
) -> dict[str, Any]:
    """Assemble a §3.1 payload.

    Defaults are chosen so that, with only the required kwargs supplied, the
    result is a schema-valid `revocability: "none"` receipt: `drm-free`,
    `redownload_right: true`, and `artifact_series` (required, no default)
    together satisfy that class's conditional requirements. Optional string
    fields with no null in their schema type (`edition`, `mirror_policy_uri`,
    `mirror_policy_sha256`, `revocation_window_days`, `jurisdiction_flags`)
    are omitted entirely when not supplied, rather than set to `None`.
    """
    if attest_version not in _ATTEST_VERSIONS:
        raise IssueError(
            f"unknown attest_version {attest_version!r}: expected one of {_ATTEST_VERSIONS!r}"
        )
    commitment_bytes = commitment.compute(buyer_identifier, buyer_identifier_type, buyer_salt)
    buyer: dict[str, Any] = {
        "commitment": keys.b64u(commitment_bytes),
        "identifier_type": buyer_identifier_type,
        "pubkey": keys.b64u(buyer_pubkey) if buyer_pubkey is not None else None,
    }

    work: dict[str, Any] = {
        "title": title,
        "publisher": publisher,
        "identifiers": identifiers,
        "artifact_series": artifact_series,
    }
    if edition is not None:
        work["edition"] = edition
    if artifacts is not None:
        work["artifacts"] = artifacts
    # v0.2 §18.1: the rights holder's domain. Absent under v0.1 alone, where it
    # carries no meaning; schema-REQUIRED once `license.preservation_pledge` is
    # present (§18.6), which is why the two arrive as separate kwargs rather
    # than one — an issuer may name a publisher without pledging anything.
    if publisher_id is not None:
        work["publisher_id"] = publisher_id

    license_fields: dict[str, Any] = {
        "grant": grant,
        "revocability": revocability,
        "transferable": transferable,
        "drm": drm,
        "terms_uri": terms_uri,
        "legal_text_sha256": legal_text_sha256,
    }
    if revocation_window_days is not None:
        license_fields["revocation_window_days"] = revocation_window_days
    if jurisdiction_flags is not None:
        license_fields["jurisdiction_flags"] = jurisdiction_flags
    # v0.2 §18.2: `{pledge, grant_uri, grant_sha256}`, hash-binding the signed
    # sunset grant. Passed through whole rather than as three kwargs: the object
    # is deliberately NOT closed (a future profile may need a fourth member),
    # and a builder that enumerated its members would have to be edited before
    # an issuer could carry one.
    if preservation_pledge is not None:
        license_fields["preservation_pledge"] = preservation_pledge

    survivability: dict[str, Any] = {
        "redownload_right": redownload_right,
        "end_of_life": end_of_life,
        "eol_commitment_uri": eol_commitment_uri,
        "eol_commitment_sha256": eol_commitment_sha256,
    }
    if mirror_policy_uri is not None:
        survivability["mirror_policy_uri"] = mirror_policy_uri
    if mirror_policy_sha256 is not None:
        survivability["mirror_policy_sha256"] = mirror_policy_sha256

    return {
        "attest_version": attest_version,
        "receipt_id": receipt_id if receipt_id is not None else ulid.generate(),
        "issued_at": issued_at if issued_at is not None else _now_iso(),
        "supersedes": supersedes,
        "issuer": {"id": issuer_id, "display_name": display_name},
        "buyer": buyer,
        "work": work,
        "license": license_fields,
        "survivability": survivability,
    }


def receipt_hash(payload: dict[str, Any]) -> str:
    """`SHA-256(JCS(payload))` lowercase hex (§4) — never a hash of the envelope."""
    return hashlib.sha256(canon.canonical_bytes(payload)).hexdigest()
