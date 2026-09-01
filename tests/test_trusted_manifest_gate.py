"""The receipt path must authenticate the trusted key manifest itself.

`verify()` resolves the issuer's key manifest from the trust store and then
verifies the receipt signature against the keys it lists. Until this gate
existed, nothing ever asked whether that manifest was self-consistent: the
side-document paths call `manifests.verify_key_manifest()` (transfer,
revocation), the receipt path did not. A manifest whose own signature does
not check out is not evidence of anything, and a verifier that reads keys
out of it is trusting an attacker's edit of a file it never authenticated.

Each test tampers with a manifest WITHOUT re-signing it, so
`verify_key_manifest` is false by construction, and asserts the receipt is
refused. The honest controls prove the tampering is what makes the
difference and that the gate does not reject good manifests.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from attest import issue, keys, manifests, pq, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"

KPA = keys.from_seed(bytes([70]) * 32)
KPB = keys.from_seed(bytes([71]) * 32)
KP_ATTACKER = keys.from_seed(bytes([72]) * 32)

KID_A = f"{ISSUER}/keys/test#ed25519-a"
KID_B = f"{ISSUER}/keys/test#ed25519-b"


def _entry(kid: str, kp: keys.SigningKeyPair, status: str = "active") -> dict[str, Any]:
    return manifests.key_entry(kid, kp.pub, "2026-01-01T00:00:00Z", None, status)


def _manifest(version: int, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return manifests.build_key_manifest(
        ISSUER, version, "2026-06-01T00:00:00Z", entries, KPB, KID_B
    )


def _honest_manifest() -> dict[str, Any]:
    return _manifest(1, [_entry(KID_A, KPA), _entry(KID_B, KPB)])


def _receipt(kp: keys.SigningKeyPair = KPA, kid: str = KID_A) -> bytes:
    payload = make_payload(issuer={"id": ISSUER, "display_name": "Example Store"})
    return json.dumps(issue.issue(payload, kp, kid)).encode("utf-8")


def _store(manifest: dict[str, Any], provenance: str = "tls") -> verify.TrustStore:
    return verify.TrustStore(
        manifests={ISSUER: manifest}, provenance={ISSUER: provenance}, chains={}
    )


def test_honest_manifest_still_certifies_its_own_receipt() -> None:
    """Control: the gate must not cost a good manifest its verdict."""
    manifest = _honest_manifest()
    assert manifests.verify_key_manifest(manifest) is True
    result = verify.verify(_receipt(), _store(manifest))
    assert result.ok is True
    assert result.signature == "valid"


@pytest.mark.parametrize("provenance", ["tls", "bundle"])
def test_manifest_with_a_broken_self_signature_is_refused(provenance: str) -> None:
    """A manifest whose own signature fails is not a trust anchor.

    It reaches `trust: verified` under `provenance="tls"` — the level that
    claims the strongest guarantee in the protocol — so the refusal must not
    depend on the provenance the caller declares.
    """
    manifest = _honest_manifest()
    manifest["manifest_signature"]["sig"] = keys.b64u(bytes(64))
    assert manifests.verify_key_manifest(manifest) is False

    result = verify.verify(_receipt(), _store(manifest, provenance))

    assert result.ok is False
    assert result.signature != "valid"


@pytest.mark.parametrize("provenance", ["tls", "bundle"])
def test_swapped_public_key_cannot_certify_a_forged_receipt(provenance: str) -> None:
    """The forgery this gate exists to stop.

    The attacker never touches the issuer's private key: they replace the
    `pub` of an entry with their own and sign a receipt under the unchanged
    kid. The manifest's signature no longer covers its own keys, and without
    the gate the forged receipt verifies against the attacker's key.
    """
    manifest = _honest_manifest()
    for entry in manifest["keys"]:
        if entry["kid"] == KID_A:
            entry["pub"] = keys.b64u(KP_ATTACKER.pub)
    assert manifests.verify_key_manifest(manifest) is False

    result = verify.verify(_receipt(KP_ATTACKER, KID_A), _store(manifest, provenance))

    assert result.ok is False
    assert result.signature != "valid"


def test_a_compromised_key_cannot_be_resurrected_by_editing_its_status() -> None:
    """The absorbing key-status floor must not be undone by a text edit.

    v0.1 §7.3 makes `compromised` absorbing, and the honest control below
    shows the receipt is refused while the manifest says so. Flipping that
    one word back to `active` — no re-signature, no key material touched —
    must not bring the dead key's signatures back to life.
    """
    compromised = _manifest(2, [_entry(KID_A, KPA, "compromised"), _entry(KID_B, KPB)])
    assert manifests.verify_key_manifest(compromised) is True
    refused = verify.verify(_receipt(), _store(compromised))
    assert refused.ok is False

    resurrected = copy.deepcopy(compromised)
    for entry in resurrected["keys"]:
        if entry["kid"] == KID_A:
            entry["status"] = "active"
    assert manifests.verify_key_manifest(resurrected) is False

    result = verify.verify(_receipt(), _store(resurrected))

    assert result.ok is False
    assert result.signature != "valid"


# --- the carve-out, pinned in both directions ---------------------------------
#
# The hybrid tolerance is the single most security-relevant decision in this
# gate, and it had no test in either direction: an exception nothing pins is
# one the next hand widens or "fixes" blind. A present-but-wrong PQ leg was
# accepted here while `verify_key_manifest` refused it, which certified a
# receipt while every revocation record the issuer signed was dropped.

KID_H = f"{ISSUER}/keys/test#hybrid-1"
HK = pq.HybridSigningKeys(ed=keys.from_seed(bytes([73]) * 32), mldsa=pq.generate())


def _hybrid_manifest() -> dict[str, Any]:
    entry = manifests.key_entry(
        KID_H, HK.ed.pub, "2026-01-01T00:00:00Z", None, "active", pub_ml_dsa_65=HK.mldsa.pub
    )
    return manifests.build_key_manifest(ISSUER, 1, "2026-06-01T00:00:00Z", [entry], HK, KID_H)


def _v02_receipt() -> bytes:
    payload = make_payload(
        attest_version="0.2", issuer={"id": ISSUER, "display_name": "Example Store"}
    )
    return json.dumps(issue.issue(payload, HK, KID_H)).encode("utf-8")


def test_v02_hybrid_receipt_path_inherits_the_gate() -> None:
    """The gate is hoisted so BOTH receipt paths get it — pin the v0.2 one."""
    tampered = _hybrid_manifest()
    tampered["manifest_signature"]["sig"] = keys.b64u(bytes(64))

    result = verify.verify(_v02_receipt(), _store(tampered))

    assert result.ok is False
    assert result.signature != "valid"


def test_absent_pq_leg_is_the_one_downgrade_the_gate_accepts() -> None:
    """The carve-out, pinned in the ACCEPTING direction.

    The rotation chain answers a hybrid signer's Ed25519-only manifest
    signature, and `26-hybrid/h-manifest-downgraded-continuity` pins
    `ok: true` for it. A gate that rejected it would break a verdict the
    spec intends, so this tolerance must not be tightened by accident.
    """
    downgraded = _hybrid_manifest()
    del downgraded["manifest_signature"]["sig_ml_dsa_65"]

    assert manifests.verify_key_manifest(downgraded) is False
    assert manifests.manifest_signature_is_authentic(downgraded) is True
    assert verify.verify(_v02_receipt(), _store(downgraded)).signature == "valid"


def test_a_present_pq_leg_that_does_not_verify_is_not_a_downgrade() -> None:
    """`manifest_signature` sits OUTSIDE the signed bytes, so its members are
    unauthenticated: anyone can graft a PQ leg on with no key at all. An
    ABSENT leg is the downgrade the corpus blesses; a PRESENT one that fails
    is an edit, and v0.2 §2.3's AND rule calls it invalid."""
    grafted = _hybrid_manifest()
    grafted["manifest_signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(pq.ML_DSA_65_SIG_LEN))

    assert manifests.manifest_signature_is_authentic(grafted) is False


def test_a_stray_pq_leg_on_a_non_hybrid_signer_is_refused() -> None:
    """v0.2 §2.3: an Ed25519-only signer's manifest signature carrying a stray
    `sig_ml_dsa_65` MUST likewise be treated as invalid.

    The gate must not disagree with `verify_key_manifest` here, or the same
    manifest certifies receipts while every revocation record the issuer
    signs is dropped as unverifiable — a revoked receipt reading `ok: true`.
    """
    kp = keys.from_seed(bytes([75]) * 32)
    kid = f"{ISSUER}/keys/test#ed25519-stray"
    manifest = manifests.build_key_manifest(
        ISSUER,
        1,
        "2026-06-01T00:00:00Z",
        [manifests.key_entry(kid, kp.pub, "2026-01-01T00:00:00Z")],
        kp,
        kid,
    )
    manifest["manifest_signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(pq.ML_DSA_65_SIG_LEN))

    assert manifests.verify_key_manifest(manifest) is False
    assert manifests.manifest_signature_is_authentic(manifest) is False


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda m: m.update(keys={"not": "a list"}), id="keys-not-a-list"),
        pytest.param(lambda m: m.update(keys=[None]), id="keys-member-not-a-dict"),
        pytest.param(lambda m: m.update(manifest_signature=[]), id="sig-block-not-a-dict"),
        pytest.param(lambda m: m["manifest_signature"].pop("sig"), id="sig-absent"),
        pytest.param(lambda m: m["manifest_signature"].update(sig=7), id="sig-not-a-string"),
        pytest.param(
            lambda m: m["manifest_signature"].update(sig=keys.b64u(bytes(32))), id="sig-short"
        ),
        pytest.param(lambda m: m["keys"][0].pop("pub"), id="pub-absent"),
        pytest.param(lambda m: m["keys"][0].update(pub="@@@@"), id="pub-not-b64u"),
        pytest.param(lambda m: m.update(extra=1.5), id="body-outside-the-jcs-profile"),
        pytest.param(lambda m: m["keys"].append({"kid": KID_H}), id="duplicate-kid"),
    ],
)
def test_hostile_manifests_fail_closed_without_raising(mutate: Any) -> None:
    """The docstring promises "Never raises — untrusted input fails closed".

    A promise in a docstring that no test drives is a promise the next
    refactor is free to break silently.
    """
    manifest = _hybrid_manifest()
    mutate(manifest)

    assert manifests.manifest_signature_is_authentic(manifest) is False
