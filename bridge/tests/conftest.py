"""Shared bridge test fixtures: one hybrid issuer, its manifest, a trust store."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from attest_bridge.catalog import ProductCatalog, ProductTemplate
from attest_bridge.core import IssuingCore
from attest_bridge.ledger import Ledger
from attest_bridge.signing import IssuerIdentity

from attest import keys, manifests, pq
from attest import verify as verify_mod

ISSUER = "merchant.example.com"
KID = f"{ISSUER}/keys/2026-07#hybrid-1"
DISPLAY_NAME = "Example Games Store"
VALID_FROM = "2026-07-01T00:00:00Z"

# A realistic-looking legal-text digest — the schema requires 64 lowercase hex
# chars (`license.legal_text_sha256`), never a hand-typed placeholder string.
_LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-bridge-test-license-terms-v1").hexdigest()


@pytest.fixture(scope="session")
def hybrid_keys() -> pq.HybridSigningKeys:
    # Deterministic Ed25519 leg (TEST ONLY); ML-DSA generated once per session (cost).
    return pq.HybridSigningKeys(ed=keys.from_seed(bytes([9]) * 32), mldsa=pq.generate())


@pytest.fixture(scope="session")
def key_manifest(hybrid_keys: pq.HybridSigningKeys) -> dict[str, object]:
    entry = manifests.key_entry(
        KID, hybrid_keys.ed.pub, VALID_FROM, pub_ml_dsa_65=hybrid_keys.mldsa.pub
    )
    return manifests.build_key_manifest(ISSUER, 1, VALID_FROM, [entry], hybrid_keys, KID)


@pytest.fixture(scope="session")
def trust_store(key_manifest: dict[str, object]) -> verify_mod.TrustStore:
    return verify_mod.TrustStore(manifests={ISSUER: key_manifest}, provenance={ISSUER: "tls"})


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger(tmp_path / "ledger.sqlite3")


@pytest.fixture
def catalog() -> ProductCatalog:
    return ProductCatalog(
        {
            "price_TEST": ProductTemplate(
                title="Stardrift Chronicles",
                publisher="Example Games Store",
                identifiers={"sku": "SDC-STD-001"},
                artifact_series=f"{ISSUER}/works/stardrift-chronicles",
                terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
                legal_text_sha256=_LEGAL_TEXT_SHA256,
            ),
            "itch_123456": ProductTemplate(
                title="Nebula Drifters",
                publisher="Example Games Store",
                identifiers={"itch_game_id": "123456"},
                artifact_series=f"{ISSUER}/works/nebula-drifters",
                terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
                legal_text_sha256=_LEGAL_TEXT_SHA256,
            ),
            "shopify_49148385": ProductTemplate(
                title="The Long Dusk",
                publisher="Example Games Store",
                identifiers={"shopify_variant_id": "49148385"},
                artifact_series=f"{ISSUER}/works/the-long-dusk",
                terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
                legal_text_sha256=_LEGAL_TEXT_SHA256,
            ),
        }
    )


@pytest.fixture
def issuer_identity(
    hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> IssuerIdentity:
    return IssuerIdentity(ISSUER, DISPLAY_NAME, KID, hybrid_keys, key_manifest)


@pytest.fixture
def core(catalog: ProductCatalog, issuer_identity: IssuerIdentity, ledger: Ledger) -> IssuingCore:
    return IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
    )
