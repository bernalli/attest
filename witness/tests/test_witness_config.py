"""The witness's trusted configuration is the whole of its trust: the allowlist
of log origins it will cosign for, the public keys those logs are pinned to,
and its own secret key material. Everything here is about failing at STARTUP,
loudly, rather than at the first submission -- and about never letting secret
material reach a repr, a log line, or an error message.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from attest_witness.config import ConfigError, load_config
from witness_support import (
    log_keys,  # noqa: F401  -- imported for pytest fixture discovery
    log_table,
    other_log_keys,  # noqa: F401
    render_toml,
    witness_keys,  # noqa: F401
    write_config,
    write_key_files,
)

from attest import keys, pq

ORIGIN = "log.example"
OTHER_ORIGIN = "other-log.example/2026"


def test_single_origin_config_loads(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
    )
    config = load_config(config_path)
    assert list(config.logs) == [ORIGIN]
    assert config.logs[ORIGIN].name == "log.example"
    assert config.logs[ORIGIN].ed25519_pub == log_keys.ed.pub
    assert config.logs[ORIGIN].mldsa_pub == log_keys.mldsa.pub
    assert config.identity.signing_keys.ed.pub == witness_keys.ed.pub


def test_multi_origin_config_loads_every_origin(
    tmp_path: Path,
    witness_keys: pq.HybridSigningKeys,
    log_keys: pq.HybridSigningKeys,
    other_log_keys: pq.HybridSigningKeys,
) -> None:
    """One origin and many origins are the same code path (v0.2 §11.4)."""
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[
            log_table(ORIGIN, "log.example", log_keys),
            log_table(OTHER_ORIGIN, "other-log.example", other_log_keys),
        ],
    )
    config = load_config(config_path)
    assert sorted(config.logs) == sorted([ORIGIN, OTHER_ORIGIN])
    assert config.logs[OTHER_ORIGIN].ed25519_pub == other_log_keys.ed.pub


def test_arbitrary_origin_string_is_accepted_nothing_is_hardcoded(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """No origin is baked into the source: whatever the operator pins, works."""
    exotic = "a-log-nobody-anticipated.invalid/shard-7"
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(exotic, "shard-7", log_keys)],
    )
    assert list(load_config(config_path).logs) == [exotic]


def test_absent_allowlist_fails_startup(tmp_path: Path, witness_keys: pq.HybridSigningKeys) -> None:
    config_path = write_config(tmp_path, witness_signing_keys=witness_keys, logs=[])
    with pytest.raises(ConfigError, match="at least one"):
        load_config(config_path)


def test_declared_but_empty_allowlist_fails_startup(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys
) -> None:
    """`log = []` is a DIFFERENT config from one with no `[[log]]` at all, and
    a check that only rejects the missing key lets this one start: a witness
    that answers every submission 404 while looking healthy."""
    config_path = write_config(tmp_path, witness_signing_keys=witness_keys, logs=[])
    # Top of the file on purpose: after a [table] header, a bare `log = []`
    # would belong to THAT table and the root key would still be absent —
    # which is the other config, and not what this test is about.
    config_path.write_text("log = []\n" + config_path.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ConfigError, match="at least one"):
        load_config(config_path)


def test_duplicate_origin_fails_startup(
    tmp_path: Path,
    witness_keys: pq.HybridSigningKeys,
    log_keys: pq.HybridSigningKeys,
    other_log_keys: pq.HybridSigningKeys,
) -> None:
    """Two pins for one origin is an ambiguity, not a preference order."""
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[
            log_table(ORIGIN, "log.example", log_keys),
            log_table(ORIGIN, "log.example.duplicate", other_log_keys),
        ],
    )
    with pytest.raises(ConfigError, match="duplicate origin"):
        load_config(config_path)


def test_wrong_length_log_public_key_fails_startup(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    table = log_table(ORIGIN, "log.example", log_keys)
    table["ed25519_pub_b64u"] = keys.b64u(b"\x01" * 31)
    config_path = write_config(tmp_path, witness_signing_keys=witness_keys, logs=[table])
    with pytest.raises(ConfigError, match="ed25519_pub_b64u"):
        load_config(config_path)


def test_missing_log_public_key_fails_startup(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """A hybrid pin is BOTH legs: an Ed25519-only pin cannot authenticate a
    checkpoint at all (v0.2 §9.3), so it is a configuration error, not a
    degraded mode."""
    table = log_table(ORIGIN, "log.example", log_keys)
    del table["mldsa_65_pub_b64u"]
    config_path = write_config(tmp_path, witness_signing_keys=witness_keys, logs=[table])
    with pytest.raises(ConfigError, match="mldsa_65_pub_b64u"):
        load_config(config_path)


def test_missing_seed_file_names_the_path_not_the_bytes(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
        seed_path=str(tmp_path / "absent.seed"),
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(config_path)
    message = str(excinfo.value)
    assert "absent.seed" in message
    assert keys.b64u(witness_keys.ed.seed) not in message


def test_malformed_mldsa_key_file_fails_startup(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps({"alg": "ML-DSA-44", "sk": "AAAA", "pub": "AAAA"}), "utf-8")
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
        mldsa_key_path=str(broken),
    )
    with pytest.raises(ConfigError, match="alg"):
        load_config(config_path)


def test_secret_material_never_appears_in_repr(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """`repr(config)` is what a stray logging.debug() would print."""
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
    )
    config = load_config(config_path)
    rendered = repr(config) + repr(config.identity)
    for secret in (witness_keys.ed.seed, witness_keys.mldsa.sk):
        # All three renderings a repr could plausibly carry. The bytes repr is
        # the one that actually leaks when `repr=False` is dropped: a
        # dataclass renders `seed=b'\x9f...'`, neither base64url nor hex, so a
        # test checking only the encoded forms passes while the key is on
        # screen.
        assert repr(secret) not in rendered
        assert keys.b64u(secret) not in rendered
        assert secret.hex() not in rendered


def test_witness_name_must_follow_the_signed_note_grammar(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """A name with a space would produce an unparseable signature line, so it
    is refused where it is declared rather than where it is signed."""
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
        name="witness example",
    )
    with pytest.raises(ConfigError, match="name"):
        load_config(config_path)


def test_prefixes_must_be_absolute_paths(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
        server={"submission_prefix": "witness/v0", "monitoring_prefix": "/witness/v0/monitoring"},
    )
    with pytest.raises(ConfigError, match="submission_prefix"):
        load_config(config_path)


def test_proof_line_bound_cannot_exceed_the_c2sp_ceiling(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """C2SP tlog-witness: a client MUST NOT send more than 63 proof lines. An
    operator may lower that bound; raising it would accept what the protocol
    forbids."""
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
        server={
            "submission_prefix": "/witness/v0",
            "monitoring_prefix": "/witness/v0/monitoring",
            "max_proof_lines": 64,
        },
    )
    with pytest.raises(ConfigError, match="max_proof_lines"):
        load_config(config_path)


def test_bounds_have_defaults_so_a_minimal_config_is_still_bounded(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
    )
    config = load_config(config_path)
    assert config.server.max_proof_lines == 63
    assert config.server.max_request_bytes > 0


def test_malformed_toml_fails_startup(tmp_path: Path) -> None:
    config_path = tmp_path / "witness.toml"
    config_path.write_text("this is not = = toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="TOML"):
        load_config(config_path)


def test_missing_witness_section_fails_startup(
    tmp_path: Path, log_keys: pq.HybridSigningKeys
) -> None:
    config_path = tmp_path / "witness.toml"
    config_path.write_text(
        render_toml({"log": [log_table(ORIGIN, "log.example", log_keys)]}), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match=r"\[witness\]"):
        load_config(config_path)


def test_diagnostics_render_the_allowlist_without_any_secret(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """`attest-witness check-config` prints this: it must be safe to paste."""
    from attest_witness.config import describe

    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
    )
    rendered = describe(load_config(config_path))
    assert ORIGIN in rendered
    assert keys.b64u(witness_keys.ed.seed) not in rendered
    assert keys.b64u(witness_keys.mldsa.sk) not in rendered


def test_seed_and_key_files_are_read_in_the_shapes_attest_keygen_writes(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys
) -> None:
    """Pinned deliberately: an operator generates witness keys with `attest
    keygen`, so a shape change in either file is a break in this loader too."""
    seed_path, mldsa_path = write_key_files(tmp_path, witness_keys)
    assert seed_path.read_text(encoding="utf-8") == keys.b64u(witness_keys.ed.seed)
    document = json.loads(mldsa_path.read_text(encoding="utf-8"))
    assert document["alg"] == pq.ML_DSA_65_ALG
    assert keys.b64u_decode(document["sk"]) == witness_keys.mldsa.sk


def test_mismatched_mldsa_secret_and_public_key_fails_startup(
    tmp_path: Path,
    witness_keys: pq.HybridSigningKeys,
    other_log_keys: pq.HybridSigningKeys,
    log_keys: pq.HybridSigningKeys,
) -> None:
    """A well-formed key file can still hold two halves of different pairs.

    It loads, it signs, and every cosignature it produces is unverifiable —
    a failure that would show up in somebody else's verifier, not here. So the
    loader signs a probe and checks it against the declared public key.
    """
    crossed = tmp_path / "crossed.json"
    crossed.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(witness_keys.mldsa.sk),
                "pub": keys.b64u(other_log_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
        mldsa_key_path=str(crossed),
    )
    with pytest.raises(ConfigError, match="not the same key pair"):
        load_config(config_path)


def test_the_shipped_example_config_is_a_valid_config(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """`examples/witness.toml` is the first thing an operator copies. Loading
    it here — with the placeholders filled in and nothing else changed — is
    what stops it drifting into a file that documents field names this loader
    no longer has.
    """
    example = (Path(__file__).resolve().parents[1] / "examples" / "witness.toml").read_text(
        encoding="utf-8"
    )
    seed_path, mldsa_path = write_key_files(tmp_path, witness_keys)
    filled = (
        example.replace("/etc/attest-witness/ed25519.seed", str(seed_path))
        .replace("/etc/attest-witness/mldsa65.json", str(mldsa_path))
        .replace("/var/lib/attest-witness/state.sqlite3", str(tmp_path / "state.sqlite3"))
        .replace("REPLACE-WITH-THE-LOG-ED25519-PUBLIC-KEY-BASE64URL", keys.b64u(log_keys.ed.pub))
        .replace(
            "REPLACE-WITH-THE-LOG-ML-DSA-65-PUBLIC-KEY-BASE64URL",
            keys.b64u(log_keys.mldsa.pub),
        )
    )
    config_path = tmp_path / "from-example.toml"
    config_path.write_text(filled, encoding="utf-8")

    config = load_config(config_path)
    assert list(config.logs) == ["log.example"]
    assert config.server.max_proof_lines == 63
    assert config.identity.name == "witness.example/w1"
