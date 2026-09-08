"""SigningKeyProvider: load the merchant's hybrid signing key + key manifest, fail-fast.

Contract under test: `load_issuer` reads the exact on-disk
formats `attest keygen`/`manifest init` write, cross-checks the loaded key
material against its own key manifest, and raises `ConfigError` — naming the
file path and/or kid, NEVER decoded key bytes — on any corruption. The
cross-check (manifest entry `pub`/`pub_ml_dsa_65` must match the loaded
Ed25519/ML-DSA-65 public keys) exists so a mis-configured key/manifest pair is
caught at startup, before the first webhook.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from attest_bridge.config import IssuerConfig
from attest_bridge.model import ConfigError
from attest_bridge.signing import IssuerIdentity, load_issuer
from conftest import DISPLAY_NAME, ISSUER, KID, VALID_FROM

from attest import keys, manifests, pq, trust_material


@pytest.fixture(scope="module")
def decoy_mldsa() -> pq.MLDSAKeyPair:
    """A second, independently generated ML-DSA-65 keypair — used only to build
    a manifest entry whose declared pub differs from the loaded signing key's
    pub while the manifest stays self-consistent (signed by this decoy)."""
    return pq.generate()


def _write_issuer_files(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    manifest: dict[str, object],
    *,
    kid: str = KID,
) -> IssuerConfig:
    seed_path = tmp_path / "issuer.seed"
    seed_path.write_text(keys.b64u(hybrid_keys.ed.seed) + "\n", encoding="utf-8")

    mldsa_path = tmp_path / "issuer.mldsa.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    manifest_path = tmp_path / "key-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    return IssuerConfig(
        id=ISSUER,
        display_name=DISPLAY_NAME,
        kid=kid,
        seed_path=seed_path,
        mldsa_key_path=mldsa_path,
        manifest_path=manifest_path,
    )


def test_load_issuer_happy_path(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)

    identity = load_issuer(config)

    assert isinstance(identity, IssuerIdentity)
    assert identity.issuer_id == ISSUER
    assert identity.display_name == DISPLAY_NAME
    assert identity.kid == KID
    assert identity.signing_keys.ed.pub == hybrid_keys.ed.pub
    assert identity.signing_keys.mldsa.pub == hybrid_keys.mldsa.pub
    assert identity.manifest_snapshot == key_manifest


def test_load_issuer_rejects_mldsa_secret_public_pairing_mismatch(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, decoy_mldsa: pq.MLDSAKeyPair
) -> None:
    # The manifest and public half agree on B, while the file's secret half is
    # A. Only the empirical sign/verify self-test can catch this configuration.
    entry = manifests.key_entry(KID, hybrid_keys.ed.pub, VALID_FROM, pub_ml_dsa_65=decoy_mldsa.pub)
    manifest = manifests.build_key_manifest(
        ISSUER, 1, VALID_FROM, [entry], pq.HybridSigningKeys(hybrid_keys.ed, decoy_mldsa), KID
    )
    config = _write_issuer_files(tmp_path, hybrid_keys, manifest)
    config.mldsa_key_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(decoy_mldsa.pub),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="ML-DSA-65 signing-key pairing"):
        load_issuer(config)


def test_load_issuer_rejects_manifest_for_a_different_issuer(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys
) -> None:
    entry = manifests.key_entry(
        KID, hybrid_keys.ed.pub, VALID_FROM, pub_ml_dsa_65=hybrid_keys.mldsa.pub
    )
    manifest = manifests.build_key_manifest(
        "other.example.com", 1, VALID_FROM, [entry], hybrid_keys, KID
    )
    config = _write_issuer_files(tmp_path, hybrid_keys, manifest)

    with pytest.raises(ConfigError, match="configured issuer"):
        load_issuer(config)


@pytest.mark.parametrize("status", ["compromised", "revoked", "unknown"])
def test_load_issuer_rejects_unusable_signing_key_status(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, status: str
) -> None:
    entry = manifests.key_entry(
        KID, hybrid_keys.ed.pub, VALID_FROM, status=status, pub_ml_dsa_65=hybrid_keys.mldsa.pub
    )
    manifest = manifests.build_key_manifest(ISSUER, 1, VALID_FROM, [entry], hybrid_keys, KID)

    with pytest.raises(ConfigError, match="unusable status"):
        load_issuer(_write_issuer_files(tmp_path, hybrid_keys, manifest))


def test_load_issuer_rejects_expired_signing_key(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys
) -> None:
    entry = manifests.key_entry(
        KID,
        hybrid_keys.ed.pub,
        "2020-01-01T00:00:00Z",
        "2020-01-02T00:00:00Z",
        pub_ml_dsa_65=hybrid_keys.mldsa.pub,
    )
    manifest = manifests.build_key_manifest(ISSUER, 1, VALID_FROM, [entry], hybrid_keys, KID)

    with pytest.raises(ConfigError, match="validity window"):
        load_issuer(_write_issuer_files(tmp_path, hybrid_keys, manifest))


def test_truncated_seed_raises_config_error_without_key_bytes(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.seed_path.write_text(keys.b64u(hybrid_keys.ed.seed[:16]) + "\n", encoding="utf-8")

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    message = str(exc_info.value)
    assert str(config.seed_path) in message
    # the value ACTUALLY written to disk (the 16-byte truncation) must not leak,
    # not merely the original seed — a regression echoing the corrupt bytes would
    # otherwise slip past an assertion checking only the untruncated seed.
    assert keys.b64u(hybrid_keys.ed.seed[:16]) not in message
    assert keys.b64u(hybrid_keys.ed.seed) not in message


def test_mldsa_wrong_alg_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.mldsa_key_path.write_text(
        json.dumps(
            {
                "alg": "X",
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    message = str(exc_info.value)
    assert str(config.mldsa_key_path) in message
    assert keys.b64u(hybrid_keys.mldsa.sk) not in message


def test_mldsa_wrong_length_sk_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    short_sk = hybrid_keys.mldsa.sk[:100]
    config.mldsa_key_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(short_sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    message = str(exc_info.value)
    assert str(config.mldsa_key_path) in message
    assert keys.b64u(short_sk) not in message


def test_missing_seed_file_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.seed_path.unlink()

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.seed_path) in str(exc_info.value)


def test_self_inconsistent_manifest_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    tampered = dict(key_manifest)
    tampered["issued_at"] = "2020-01-01T00:00:00Z"  # invalidates the manifest's own signature
    config = _write_issuer_files(tmp_path, hybrid_keys, tampered)

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.manifest_path) in str(exc_info.value)


def test_kid_absent_from_manifest_raises_config_error_naming_kid(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    missing_kid = f"{ISSUER}/keys/2027-01#missing"
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest, kid=missing_kid)

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert missing_kid in str(exc_info.value)


def test_manifest_ed25519_pub_mismatch_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys
) -> None:
    # Manifest entry for KID carries a DIFFERENT Ed25519 pub than the one the
    # seed file on disk decodes to — self-consistent (signed by the decoy leg
    # that matches the entry), but a key/manifest mismatch against the loaded key.
    decoy_ed = keys.from_seed(bytes([7]) * 32)
    entry = manifests.key_entry(KID, decoy_ed.pub, VALID_FROM, pub_ml_dsa_65=hybrid_keys.mldsa.pub)
    mismatched_manifest = manifests.build_key_manifest(
        ISSUER,
        1,
        VALID_FROM,
        [entry],
        pq.HybridSigningKeys(ed=decoy_ed, mldsa=hybrid_keys.mldsa),
        KID,
    )
    config = _write_issuer_files(tmp_path, hybrid_keys, mismatched_manifest)

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    message = str(exc_info.value)
    assert KID in message
    assert keys.b64u(hybrid_keys.ed.pub) not in message
    assert keys.b64u(decoy_ed.pub) not in message


def test_manifest_mldsa_pub_mismatch_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, decoy_mldsa: pq.MLDSAKeyPair
) -> None:
    # Same idea, ML-DSA-65 leg: entry's pub_ml_dsa_65 belongs to a different,
    # independently generated key than the one the mldsa file on disk holds.
    entry = manifests.key_entry(KID, hybrid_keys.ed.pub, VALID_FROM, pub_ml_dsa_65=decoy_mldsa.pub)
    mismatched_manifest = manifests.build_key_manifest(
        ISSUER,
        1,
        VALID_FROM,
        [entry],
        pq.HybridSigningKeys(ed=hybrid_keys.ed, mldsa=decoy_mldsa),
        KID,
    )
    config = _write_issuer_files(tmp_path, hybrid_keys, mismatched_manifest)

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    message = str(exc_info.value)
    assert KID in message
    assert keys.b64u(hybrid_keys.mldsa.pub) not in message
    assert keys.b64u(decoy_mldsa.pub) not in message


def test_issuer_identity_repr_does_not_leak_key_material(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    # Constraint 10: key material is never emitted by repr()/"%r". The nested
    # dataclasses render bytes as Python byte literals (b'...'), NOT base64, so
    # assert on the real repr form and that the secret/bulky fields are absent
    # from the repr entirely (field(repr=False)) — a b64u-only assertion would
    # have passed against the pre-fix repr despite the leak.
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    identity = load_issuer(config)

    rendered = f"{identity!r}"
    # the secret/bulky fields must not appear in the repr at all
    assert "signing_keys=" not in rendered
    assert "manifest_snapshot=" not in rendered
    # private key material in its actual repr form (byte literals) and as base64
    assert repr(hybrid_keys.ed.seed) not in rendered
    assert repr(hybrid_keys.mldsa.sk) not in rendered
    assert keys.b64u(hybrid_keys.ed.seed) not in rendered
    assert keys.b64u(hybrid_keys.mldsa.sk) not in rendered
    # manifest public-key bytes (would surface if manifest_snapshot were in repr)
    assert keys.b64u(hybrid_keys.ed.pub) not in rendered
    assert keys.b64u(hybrid_keys.mldsa.pub) not in rendered
    # the useful, non-leaky identifier fields are still present
    assert identity.kid in rendered


def test_mldsa_wrong_length_pub_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    short_pub = hybrid_keys.mldsa.pub[:100]
    config.mldsa_key_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(short_pub),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    message = str(exc_info.value)
    assert str(config.mldsa_key_path) in message
    assert keys.b64u(short_pub) not in message


def test_missing_mldsa_file_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.mldsa_key_path.unlink()

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.mldsa_key_path) in str(exc_info.value)


def test_missing_manifest_file_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.manifest_path.unlink()

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.manifest_path) in str(exc_info.value)


def test_invalid_utf8_seed_file_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    # A non-UTF-8 seed file makes read_text raise UnicodeDecodeError (a ValueError,
    # not an OSError) — it must still normalize to ConfigError, not escape.
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.seed_path.write_bytes(b"\xff\xfe not valid utf-8")

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.seed_path) in str(exc_info.value)


def test_manifest_verification_raise_is_mapped_to_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    # A float in the manifest body is rejected by the attest-JCS canonicalizer
    # (CanonError) INSIDE verify_key_manifest — the loader must map that raise to
    # ConfigError, not let it escape (every corruption -> ConfigError).
    tampered = dict(key_manifest)
    tampered["unexpected_float"] = 1.5
    config = _write_issuer_files(tmp_path, hybrid_keys, tampered)

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.manifest_path) in str(exc_info.value)


def test_manifest_overlong_integer_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    # A JSON integer beyond CPython's int-string conversion limit makes json.loads
    # raise a plain ValueError (NOT JSONDecodeError) — the loader must still map it
    # to ConfigError, not let it escape.
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.manifest_path.write_text('{"n": ' + "9" * 5000 + "}", encoding="utf-8")

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.manifest_path) in str(exc_info.value)


def test_malformed_unclosed_manifest_json_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    # Deeply unclosed JSON — a distinct corruption from the well-formed cases —
    # must normalize to ConfigError, never escape as a raw traceback.
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config.manifest_path.write_text("[" * 5000, encoding="utf-8")

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.manifest_path) in str(exc_info.value)


def test_nul_byte_in_seed_path_raises_config_error(
    tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, key_manifest: dict[str, object]
) -> None:
    # A NUL byte can reach seed_path via TOML config; Path.read_text raises a plain
    # ValueError("embedded null byte") (neither OSError nor UnicodeDecodeError),
    # which must still normalize to ConfigError rather than escape.
    valid = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)
    config = IssuerConfig(
        id=valid.id,
        display_name=valid.display_name,
        kid=valid.kid,
        seed_path=Path("bad\x00path"),
        mldsa_key_path=valid.mldsa_key_path,
        manifest_path=valid.manifest_path,
    )

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert "seed file" in str(exc_info.value)


def test_manifest_verification_recursion_error_is_mapped_to_config_error(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Sufficiently deep manifest nesting makes attest-JCS canonicalization recurse
    # past the interpreter limit (RecursionError) inside verify_key_manifest; that
    # must normalize to ConfigError. Triggered deterministically via monkeypatch
    # rather than with a fragile, env-dependent nesting depth.
    config = _write_issuer_files(tmp_path, hybrid_keys, key_manifest)

    def _raise_recursion(_manifest: trust_material.KeyManifest) -> bool:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr("attest_bridge.signing.manifests.verify_key_manifest", _raise_recursion)

    with pytest.raises(ConfigError) as exc_info:
        load_issuer(config)

    assert str(config.manifest_path) in str(exc_info.value)
