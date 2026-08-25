"""Startup loader for the witness's trusted configuration — fail-fast.

Contract: everything this witness will ever trust is declared HERE, in one
file, and is verified before the first request is served. That is: the
allowlist of log origins it will cosign for, the hybrid public key each of
those logs is pinned to, its own hybrid signing key material, and the bounds
it enforces on every request.

Three properties this module exists to guarantee (v0.2 §11.4):

- **No origin and no log key is hardcoded.** A one-origin deployment and a
  fifty-origin deployment take the same code path; the only difference is how
  many `[[log]]` tables the operator wrote.
- **Empty or malformed trusted configuration fails startup**, never a request.
  A witness that starts with no pinned log would answer every submission with
  404 and look healthy while cosigning nothing.
- **Secret values are never printed.** Secret-bearing fields carry
  `field(repr=False)`, error messages name the FILE, never its contents, and
  `describe()` — what `attest-witness check-config` prints — renders the
  allowlist and the public key fingerprints only.

Secret material lives in files, in the exact on-disk shapes `attest keygen`
writes (a base64url seed; a JSON `{"alg","sk","pub"}` document), never inline
in this TOML. That is the bridge's precedent and it is deliberate: an operator
generates witness keys with the same tool that generates issuer keys.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from attest import keys, pq, tlog
from attest import witness as witness_policy

# C2SP tlog-witness: "The client MUST NOT send more than 63 consistency proof
# lines." An operator may lower this; raising it would accept what the
# protocol forbids, so the config ceiling is the protocol's own.
C2SP_MAX_PROOF_LINES: Final = 63
DEFAULT_MAX_REQUEST_BYTES: Final = 262_144
DEFAULT_SUBMISSION_PREFIX: Final = "/witness/v0"
DEFAULT_MONITORING_PREFIX: Final = "/witness/v0/monitoring"

# v0.2 §9.2's signed-note key-name grammar: non-empty printable ASCII
# 0x21-0x7e, no "+". The core applies this again when it parses or produces a
# signature line, so a drift here cannot yield a malformed signature — it
# would raise at signing time instead. Checking it at startup turns that into
# a config error the operator sees before serving anything.
_KEY_NAME_RE: Final = re.compile(r"\A[\x21-\x2a\x2c-\x7e]+\Z")
# v0.2 §9.2's checkpoint origin grammar: non-empty printable ASCII 0x20-0x7e.
_ORIGIN_RE: Final = re.compile(r"\A[\x20-\x7e]+\Z")


class ConfigError(ValueError):
    """The trusted configuration is missing, malformed, or self-inconsistent."""


@dataclass(frozen=True, slots=True)
class WitnessIdentity:
    """The witness's own name and hybrid signing keys.

    `signing_keys` carries both secret keys, so it is `repr=False`: this
    object reaches log lines and tracebacks, and a `%r` of it must not be the
    thing that leaks an online signing key.
    """

    name: str
    signing_keys: pq.HybridSigningKeys = field(repr=False)


@dataclass(frozen=True, slots=True)
class ServerConfig:
    submission_prefix: str
    monitoring_prefix: str
    max_request_bytes: int
    max_proof_lines: int


@dataclass(frozen=True, slots=True)
class WitnessConfig:
    identity: WitnessIdentity
    server: ServerConfig
    database_path: Path
    # origin -> pinned hybrid log key. The allowlist IS this mapping: an
    # origin absent from it is unknown, and unknown origins are refused before
    # any checkpoint or consistency work (v0.2 §11.4).
    logs: dict[str, tlog.LogKey]


def _require_table(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"config: [{key}] table is required")
    return value


def _optional_table(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"config: [{key}] must be a table")
    return value


def _require_str(table: dict[str, Any], key: str, *, context: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{context}: {key} must be a non-empty string")
    return value


def _optional_int(table: dict[str, Any], key: str, *, context: str, default: int) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{context}: {key} must be a positive integer")
    return value


def _load_seed(path: Path) -> keys.SigningKeyPair:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError) as exc:
        # ValueError subsumes UnicodeDecodeError and the "embedded null byte"
        # ValueError a NUL in a TOML-supplied path produces.
        raise ConfigError(f"cannot read seed file {path}: {exc}") from exc
    try:
        return keys.from_seed(keys.b64u_decode(text))
    except ValueError as exc:
        # The message names the file, never the decoded bytes.
        raise ConfigError(f"seed file {path} is malformed: {exc}") from exc


def _load_mldsa(path: Path) -> pq.MLDSAKeyPair:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read ML-DSA-65 key file {path}: {exc}") from exc
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ConfigError(f"ML-DSA-65 key file {path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("alg") != pq.ML_DSA_65_ALG:
        raise ConfigError(
            f"ML-DSA-65 key file {path} has wrong alg (expected {pq.ML_DSA_65_ALG!r})"
        )
    try:
        secret = keys.b64u_decode(document["sk"])
        public = keys.b64u_decode(document["pub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"ML-DSA-65 key file {path} has malformed sk/pub fields") from exc
    if len(secret) != pq.ML_DSA_65_SK_LEN or len(public) != pq.ML_DSA_65_PK_LEN:
        raise ConfigError(f"ML-DSA-65 key file {path} has wrong-length key material")
    return pq.MLDSAKeyPair(sk=secret, pub=public)


def _self_test(signing_keys: pq.HybridSigningKeys, *, mldsa_path: Path) -> None:
    """Prove the loaded ML-DSA secret key and public key are the same key.

    A mismatched pair loads cleanly, signs cleanly, and produces cosignatures
    no verifier can check — a failure that would surface only in somebody
    else's verifier, months later. Ed25519 needs no equivalent: its public key
    is derived from the seed, so it cannot disagree with itself.
    """
    probe = b"attest-witness key self-test"
    if not pq.verify_strict(probe, pq.sign(probe, signing_keys.mldsa), signing_keys.mldsa.pub):
        raise ConfigError(f"ML-DSA-65 key file {mldsa_path}: sk and pub are not the same key pair")


def _load_identity(table: dict[str, Any]) -> WitnessIdentity:
    context = "[witness]"
    name = _require_str(table, "name", context=context)
    if not _KEY_NAME_RE.match(name):
        raise ConfigError(
            f"{context}: name must be non-empty printable ASCII without '+' (v0.2 §9.2)"
        )
    seed_path = Path(_require_str(table, "seed_path", context=context))
    mldsa_path = Path(_require_str(table, "mldsa_key_path", context=context))
    signing_keys = pq.HybridSigningKeys(ed=_load_seed(seed_path), mldsa=_load_mldsa(mldsa_path))
    _self_test(signing_keys, mldsa_path=mldsa_path)
    return WitnessIdentity(name=name, signing_keys=signing_keys)


def _load_server(table: dict[str, Any]) -> ServerConfig:
    context = "[server]"
    submission_prefix = table.get("submission_prefix", DEFAULT_SUBMISSION_PREFIX)
    monitoring_prefix = table.get("monitoring_prefix", DEFAULT_MONITORING_PREFIX)
    for label, prefix in (
        ("submission_prefix", submission_prefix),
        ("monitoring_prefix", monitoring_prefix),
    ):
        if not isinstance(prefix, str) or not prefix.startswith("/") or prefix.endswith("/"):
            raise ConfigError(f"{context}: {label} must be an absolute path with no trailing slash")
    max_proof_lines = _optional_int(
        table, "max_proof_lines", context=context, default=C2SP_MAX_PROOF_LINES
    )
    if max_proof_lines > C2SP_MAX_PROOF_LINES:
        raise ConfigError(
            f"{context}: max_proof_lines must not exceed the C2SP ceiling of {C2SP_MAX_PROOF_LINES}"
        )
    return ServerConfig(
        submission_prefix=submission_prefix,
        monitoring_prefix=monitoring_prefix,
        max_request_bytes=_optional_int(
            table, "max_request_bytes", context=context, default=DEFAULT_MAX_REQUEST_BYTES
        ),
        max_proof_lines=max_proof_lines,
    )


def _load_logs(entries: object) -> dict[str, tlog.LogKey]:
    if not isinstance(entries, list) or not entries:
        raise ConfigError("config: at least one [[log]] table is required")
    logs: dict[str, tlog.LogKey] = {}
    for index, entry in enumerate(entries):
        context = f"[[log]] #{index}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{context}: must be a table")
        origin = _require_str(entry, "origin", context=context)
        if not _ORIGIN_RE.match(origin):
            raise ConfigError(f"{context}: origin must be non-empty printable ASCII (v0.2 §9.2)")
        if origin in logs:
            raise ConfigError(f"{context}: duplicate origin {origin!r}")
        name = _require_str(entry, "name", context=context)
        if not _KEY_NAME_RE.match(name):
            raise ConfigError(
                f"{context}: name must be non-empty printable ASCII without '+' (v0.2 §9.2)"
            )
        logs[origin] = tlog.LogKey(
            origin=origin,
            name=name,
            ed25519_pub=_pub(entry, "ed25519_pub_b64u", 32, context=context),
            # A hybrid pin is BOTH legs (v0.2 §9.3): checkpoint authentication
            # is a fail-closed AND, so a pin without its ML-DSA-65 leg could
            # never authenticate anything. That is a config error, not a
            # degraded mode the witness silently runs in.
            mldsa_pub=_pub(entry, "mldsa_65_pub_b64u", pq.ML_DSA_65_PK_LEN, context=context),
        )
    return logs


def _pub(table: dict[str, Any], key: str, expected_len: int, *, context: str) -> bytes:
    encoded = _require_str(table, key, context=context)
    try:
        raw = keys.b64u_decode(encoded)
    except ValueError as exc:
        raise ConfigError(f"{context}: {key} is not valid base64url: {exc}") from exc
    if len(raw) != expected_len:
        raise ConfigError(f"{context}: {key} must decode to {expected_len} bytes, got {len(raw)}")
    return raw


def load_config(path: Path) -> WitnessConfig:
    """Read and fully validate `path`. Every failure raises `ConfigError`."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"config {path} is not valid TOML: {exc}") from exc
    # Order matters for the operator, not for correctness: identity first, so
    # a config missing everything reports the section it is most likely to
    # have got wrong rather than whichever one happens to be checked first.
    identity = _load_identity(_require_table(document, "witness"))
    server = _load_server(_optional_table(document, "server"))
    storage = _require_table(document, "storage")
    return WitnessConfig(
        identity=identity,
        server=server,
        database_path=Path(_require_str(storage, "database_path", context="[storage]")),
        logs=_load_logs(document.get("log")),
    )


def describe(config: WitnessConfig) -> str:
    """Render the loaded configuration for `attest-witness check-config`.

    Safe to paste into an issue: public keys appear as their C2SP key-id
    prefix (4 bytes, hex) rather than in full, and no secret-bearing value is
    reachable from here at all.
    """
    lines = [
        f"witness name: {config.identity.name}",
        f"ed25519 key id: {_key_id_hex(config.identity.name, config.identity.signing_keys)}",
        f"database: {config.database_path}",
        f"submission: POST {config.server.submission_prefix}/add-checkpoint",
        f"monitoring: GET {config.server.monitoring_prefix}/<sha256(origin)>/checkpoint",
        f"bounds: max_request_bytes={config.server.max_request_bytes} "
        f"max_proof_lines={config.server.max_proof_lines}",
        f"pinned logs ({len(config.logs)}):",
    ]
    for origin in sorted(config.logs):
        log_key = config.logs[origin]
        ed_id = tlog.key_hash(log_key.name, tlog.ED25519_SIG_TYPE, log_key.ed25519_pub)
        lines.append(f"  {origin} — key name {log_key.name}, ed25519 key id {ed_id.hex()}")
    return "\n".join(lines)


def _key_id_hex(name: str, signing_keys: pq.HybridSigningKeys) -> str:
    return witness_policy.cosignature_key_id(name, signing_keys.ed.pub).hex()
