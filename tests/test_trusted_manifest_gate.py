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

from attest import issue, keys, manifests, verify
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
