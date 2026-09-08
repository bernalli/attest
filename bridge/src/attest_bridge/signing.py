"""Startup loader for the merchant's hybrid signing key + key manifest — fail-fast.

Contract: load the Ed25519 + ML-DSA-65 signing key material an
`IssuerConfig` points at, in the exact on-disk shapes `attest keygen` writes, then
cross-check the loaded key material against its own key manifest. Every failure —
missing/unreadable file, malformed seed/ML-DSA material, a self-inconsistent
manifest, a kid absent from the manifest, or a manifest entry whose declared pub
does not match the loaded key — is caught HERE, at startup, never at the first
webhook's signature. Key material is never logged, re-written, or returned except
inside `pq.HybridSigningKeys`; error messages name the file path and/or kid, never
decoded key bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attest import canon, keys, manifests, pq, trust_material
from attest import verify as verifier
from attest_bridge.config import IssuerConfig
from attest_bridge.model import ConfigError


@dataclass(frozen=True, slots=True)
class IssuerIdentity:
    issuer_id: str
    display_name: str
    kid: str
    # repr=False on all three: SigningKeyPair.seed / MLDSAKeyPair.sk are secret,
    # and the manifest carries (public but byte-encoded) key material — none
    # belongs in repr()/"%r" output. field(repr=False) sets no default, so these
    # stay required positional fields.
    signing_keys: pq.HybridSigningKeys = field(repr=False)
    # TWO fields for one manifest, because it plays two roles and the roles do
    # not accept the same type. `manifest_snapshot` is the DOCUMENT: it is
    # copied verbatim into every envelope this bridge issues
    # (`delivery.issuer_manifest`), so it has to stay an ordinary tree that
    # serializes. `manifest_handle` is the same manifest as trust material,
    # parsed by the library, and it is what the ports take.
    #
    # Collapsing them was tried and is wrong in both directions: give the
    # document to a port and the port refuses it; put the handle in an envelope
    # and there is nothing to serialize. The two names say which is which at
    # every call site.
    manifest_snapshot: dict[str, Any] = field(repr=False)
    manifest_handle: trust_material.KeyManifest = field(repr=False)

    def __post_init__(self) -> None:
        """The two fields are ONE manifest, and until now nothing said so.

        `core.can_issue` decides key validity from `manifest_handle`, while
        `core.issue_for` copies `manifest_snapshot` verbatim into every
        envelope. Built from different documents, this bridge would authorize
        against one manifest and publish another -- and no test of either half
        could notice, because each half is self-consistent. Splitting one field
        into two created the invariant; this is the only place both are in
        scope, so it is the only place it can be stated.
        """
        try:
            document = canon.canonical_bytes(self.manifest_snapshot)
        except canon.CanonError as exc:
            raise ConfigError(f"issuer key manifest is not canonicalizable: {exc}") from exc
        if document != self.manifest_handle.to_bytes():
            raise ConfigError(
                "issuer key manifest disagrees with its parsed handle: the document "
                "copied into envelopes and the trust material the ports read must be "
                "the same manifest"
            )


def _load_seed(path: Path) -> keys.SigningKeyPair:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError) as exc:
        # ValueError subsumes UnicodeDecodeError (non-UTF-8 file) and the plain
        # ValueError("embedded null byte") read_text raises for a NUL in the path
        # (a NUL can reach seed_path via TOML config). Every read -> ConfigError.
        raise ConfigError(f"cannot read seed file {path}: {exc}") from exc
    try:
        return keys.from_seed(keys.b64u_decode(text))
    except ValueError as exc:
        raise ConfigError(f"seed file {path} is malformed: {exc}") from exc


def _load_mldsa(path: Path) -> pq.MLDSAKeyPair:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:  # see _load_seed: NUL-in-path / non-UTF-8
        raise ConfigError(f"cannot read ML-DSA-65 key file {path}: {exc}") from exc
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError) as exc:
        # ValueError covers json.JSONDecodeError AND plain ValueError (a JSON
        # integer beyond CPython's int-string conversion limit); RecursionError
        # covers pathologically nested input. Every corruption -> ConfigError.
        raise ConfigError(f"ML-DSA-65 key file {path} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict) or obj.get("alg") != pq.ML_DSA_65_ALG:
        raise ConfigError(
            f"ML-DSA-65 key file {path} has wrong alg (expected {pq.ML_DSA_65_ALG!r})"
        )
    try:
        sk = keys.b64u_decode(obj["sk"])
        pub = keys.b64u_decode(obj["pub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"ML-DSA-65 key file {path} has malformed sk/pub fields") from exc
    if len(sk) != pq.ML_DSA_65_SK_LEN or len(pub) != pq.ML_DSA_65_PK_LEN:
        raise ConfigError(f"ML-DSA-65 key file {path} has wrong-length key material")
    return pq.MLDSAKeyPair(sk=sk, pub=pub)


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:  # see _load_seed: NUL-in-path / non-UTF-8
        raise ConfigError(f"cannot read key manifest {path}: {exc}") from exc
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError) as exc:
        # See _load_mldsa: ValueError also covers the overlong-integer ValueError,
        # RecursionError covers pathological nesting. Every corruption -> ConfigError.
        raise ConfigError(f"key manifest {path} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ConfigError(f"key manifest {path} must be a JSON object")
    return obj


def load_issuer(config: IssuerConfig) -> IssuerIdentity:
    """Load and cross-check the issuer's hybrid signing key + key manifest.

    Raises `ConfigError` fail-fast on any corruption in the contract (see
    module docstring) — this is meant to run once at startup so a
    mis-configured key/manifest pair is caught before the first webhook.
    """
    ed = _load_seed(config.seed_path)
    mldsa = _load_mldsa(config.mldsa_key_path)
    manifest = _load_manifest(config.manifest_path)
    # Trust material reaches the library as BYTES: the manifest is read from
    # disk and handed over as the document it is, rather than as the dict this
    # module happens to be holding. `canonical_bytes` and not `json.dumps`:
    # `_load_manifest` may have produced integers a re-serializer would widen,
    # and the refusal for one of those belongs HERE, where the file that
    # carried it is still the thing being blamed.
    try:
        snapshot = trust_material.KeyManifest.from_bytes(canon.canonical_bytes(manifest))
    except (trust_material.TrustMaterialError, canon.CanonError) as exc:
        raise ConfigError(f"key manifest {config.manifest_path} could not be read: {exc}") from exc

    try:
        manifest_ok = manifests.verify_key_manifest(snapshot)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        # A parseable-but-malformed manifest makes verification RAISE rather than
        # return False (e.g. a float, forbidden by the attest-JCS profile, reaches
        # canonicalization -> canon.CanonError, a ValueError; deep nesting ->
        # RecursionError). Normalize to the pinned fail-closed contract: every
        # corruption -> ConfigError.
        raise ConfigError(
            f"key manifest {config.manifest_path} could not be verified: {exc}"
        ) from exc
    if not manifest_ok:
        raise ConfigError(
            f"key manifest {config.manifest_path} failed self-consistency verification"
        )

    if manifest.get("issuer") != config.id:
        raise ConfigError(
            f"key manifest {config.manifest_path} belongs to issuer "
            f"{manifest.get('issuer')!r}, not configured issuer {config.id!r}"
        )

    entry = manifests.find_key(snapshot, config.kid)
    if entry is None:
        raise ConfigError(f"kid {config.kid!r} not found in key manifest {config.manifest_path}")

    try:
        manifest_ed_pub = keys.b64u_decode(entry["pub"])
        manifest_mldsa_pub = keys.b64u_decode(entry["pub_ml_dsa_65"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(
            f"key manifest entry for kid {config.kid!r} in {config.manifest_path} is malformed"
        ) from exc

    if manifest_ed_pub != ed.pub:
        raise ConfigError(
            f"key/manifest mismatch for kid {config.kid!r}: the manifest's Ed25519 pub does "
            f"not match the key loaded from {config.seed_path}"
        )
    if manifest_mldsa_pub != mldsa.pub:
        raise ConfigError(
            f"key/manifest mismatch for kid {config.kid!r}: the manifest's ML-DSA-65 pub does "
            f"not match the key loaded from {config.mldsa_key_path}"
        )

    # Prove that each public half actually belongs to its loaded secret half.
    # Length and manifest comparisons alone accept A.sk paired with B.pub.
    pairing_message = b"attest-bridge signing-key pairing self-test v1"
    try:
        ed_ok = keys.verify_strict(pairing_message, keys.sign(pairing_message, ed), ed.pub)
    except Exception:
        ed_ok = False
    if not ed_ok:
        raise ConfigError(f"Ed25519 signing-key pairing self-test failed for {config.seed_path}")
    try:
        mldsa_ok = pq.verify_strict(pairing_message, pq.sign(pairing_message, mldsa), mldsa.pub)
    except Exception:
        mldsa_ok = False
    if not mldsa_ok:
        raise ConfigError(
            f"ML-DSA-65 signing-key pairing self-test failed for {config.mldsa_key_path}"
        )

    status = entry.get("status")
    if status not in (verifier._STATUS_ACTIVE, verifier._STATUS_RETIRED):
        raise ConfigError(f"key {config.kid!r} has unusable status {status!r}")
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not verifier._within_validity(now, entry):
        raise ConfigError(f"key {config.kid!r} is outside its validity window at startup")

    return IssuerIdentity(
        issuer_id=config.id,
        display_name=config.display_name,
        kid=config.kid,
        signing_keys=pq.HybridSigningKeys(ed=ed, mldsa=mldsa),
        manifest_snapshot=manifest,
        manifest_handle=snapshot,
    )
