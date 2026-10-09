"""Manifest chain continuity and the provenance trust ladder (v0.1 sections
7.3 and 11.1, v0.2 section 18.5)."""

from __future__ import annotations

from typing import Any

from attest import manifests, trust_material
from attest.verify.constants import (
    _PROVENANCE_TLS,
    _TRUST_TOFU,
    _TRUST_UNVERIFIED_ROTATION,
    _TRUST_VERIFIED,
)


def _chain_continuous(chain: list[dict[str, Any]]) -> bool:
    """True iff every consecutive pair in `chain` passes `manifests.check_continuity`.

    A chain of fewer than 2 entries has nothing to validate (no recorded
    history, or a single trusted root with no successor yet) and is treated
    as continuous — this is what keeps a `TrustStore` with no `chains` entry
    for an issuer behaving exactly like Task 8.
    """
    if len(chain) < 2:
        return True
    return all(manifests._check_continuity(chain[i], chain[i + 1]) for i in range(len(chain) - 1))


def _artifact_chain_continuous(chain: list[dict[str, Any]]) -> bool:
    """True iff every consecutive pair in `chain` passes
    `manifests.check_artifact_continuity` — the artifact-manifest analog of
    `_chain_continuous` (G2/G3, attest-versioning.md rev 4)."""
    if len(chain) < 2:
        return True
    return all(
        manifests.check_artifact_continuity(chain[i], chain[i + 1]) for i in range(len(chain) - 1)
    )


def _rotation_chain_verified(
    chain: list[dict[str, Any]] | None, manifest: dict[str, Any] | None
) -> bool:
    """True iff `chain` is a validated, gapless rotation history from
    manifest_version 1 through `manifest` itself, held in the verifier's OWN
    trust store (design fix 6).

    Deliberately STRICTER than `_chain_continuous`'s use for `trust`: an
    ABSENT chain is fine for `trust` (Task-8 behavior — nothing to validate)
    but is NOT fine here. Corroborating a rotated key-manifest requires the
    verifier to already hold every intermediate version itself; the log
    merely saying "this manifest existed" is not proof of a legitimate
    rotation history, only of publication. `trust` semantics are untouched
    by this function — it feeds `corroboration` only.
    """
    if not chain or manifest is None:
        return False
    if chain[-1] != manifest:
        return False
    if chain[0].get("manifest_version") != 1:
        return False
    return _chain_continuous(chain)


def _grant_trust_ladder(store: trust_material._StoreData, domain: str, manifest: object) -> str:
    """§18.5's ladder for the PUBLISHER's manifest — v0.1 §11.1's discipline
    for `trust`, applied verbatim to a different domain and reported ONLY in
    `grant_trust`. The receipt's own `trust` component is untouched: it remains
    a statement about the issuer, and a publisher the verifier happens to know
    less well must never downgrade it."""
    level = _TRUST_VERIFIED if store.provenance.get(domain) == _PROVENANCE_TLS else _TRUST_TOFU
    chain = store.chains.get(domain)
    if chain and (not _chain_continuous(chain) or chain[-1] != manifest):
        return _TRUST_UNVERIFIED_ROTATION
    return level
