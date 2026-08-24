"""Merchant configuration loader: single `bridge.toml` + env-referenced secrets.

Contract: a secret NEVER appears inline in `bridge.toml`.
Sections reference the environment variable that holds the secret via a
`*_env` key (`webhook_secret_env`, `api_key_env`, `smtp_password_env`);
`load_config` resolves the named variable at startup and raises
`ConfigError` naming the MISSING VARIABLE — never the resolved value. The
secret-bearing dataclass fields below (`StripeConfig.webhook_secret`,
`StripeConfig.api_key`, `ItchConfig.api_key`, `DeliveryConfig.smtp_password`)
are declared with `field(repr=False)` so a resolved value can never leak via
`repr()`/`logging.debug(config)` either — only an explicit attribute access
exposes it.
"""

from __future__ import annotations

import hashlib
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attest_bridge.catalog import ProductTemplate
from attest_bridge.model import ConfigError

# Merchants are not going to write a good "what is this file" explainer
# themselves, and most won't write one at all. Absent an explicit `info_url`,
# every receipt email links here instead of failing config load.
_DEFAULT_INFO_URL = "https://bernalli.github.io/attest/what-is-this.html"


@dataclass(frozen=True, slots=True)
class IssuerConfig:
    id: str
    display_name: str
    kid: str
    seed_path: Path
    mldsa_key_path: Path
    manifest_path: Path


@dataclass(frozen=True, slots=True)
class StripeConfig:
    webhook_secret: str = field(repr=False)
    api_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ShopifyConfig:
    webhook_secret: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ItchConfig:
    api_key: str = field(repr=False)
    poll_interval_seconds: int = 60
    max_attempts: int = 10


@dataclass(frozen=True, slots=True)
class DeliveryConfig:
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str = field(repr=False)
    from_address: str
    info_url: str


@dataclass(frozen=True, slots=True)
class BridgeConfig:
    public_base_url: str
    ledger_path: Path
    issuer: IssuerConfig
    products: dict[str, ProductTemplate]
    stripe: StripeConfig | None
    itch: ItchConfig | None
    delivery: DeliveryConfig | None
    # Default None so every existing `BridgeConfig(...)` construction site keeps
    # working unchanged — purely additive, mirroring how `itch` was introduced.
    shopify: ShopifyConfig | None = None
    # Licence texts keyed by their verified SHA-256, ready to be shipped inside
    # the buyer's bundle (spec §14.1). `repr=False` for size, not secrecy.
    legal_texts: dict[str, bytes] = field(default_factory=dict, repr=False)


def _require_table(data: Mapping[str, Any], key: str, *, context: str) -> dict[str, Any]:
    if key not in data:
        raise ConfigError(f"{context}: missing required table [{key}]")
    value = data[key]
    if not isinstance(value, dict):
        raise ConfigError(f"{context}: [{key}] must be a table")
    return value


def _optional_table(data: Mapping[str, Any], key: str, *, context: str) -> dict[str, Any] | None:
    if key not in data:
        return None
    value = data[key]
    if not isinstance(value, dict):
        raise ConfigError(f"{context}: [{key}] must be a table")
    return value


def _require_str(table: Mapping[str, Any], key: str, *, context: str) -> str:
    if key not in table:
        raise ConfigError(f"{context}: missing required field {key!r}")
    value = table[key]
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{context}: field {key!r} must be a non-empty string")
    return value


def _optional_str(table: Mapping[str, Any], key: str, default: str, *, context: str) -> str:
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{context}: field {key!r} must be a non-empty string")
    return value


def _require_int(table: Mapping[str, Any], key: str, *, context: str) -> int:
    if key not in table:
        raise ConfigError(f"{context}: missing required field {key!r}")
    value = table[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{context}: field {key!r} must be an integer")
    return value


def _optional_int(table: Mapping[str, Any], key: str, default: int, *, context: str) -> int:
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{context}: field {key!r} must be an integer")
    return value


def _optional_str_or_none(table: Mapping[str, Any], key: str, *, context: str) -> str | None:
    """Absent -> None; present must be a non-empty string, else ConfigError.

    Unlike `_optional_str` (which substitutes a default), a genuinely optional
    field with no default: absence is legal (None), but a PRESENT malformed or
    empty value is a config error, never a silent drop to None.
    """
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{context}: field {key!r} must be a non-empty string")
    return value


def _env(env: Mapping[str, str], table: Mapping[str, Any], key: str, *, context: str) -> str:
    """Resolve the secret named by `table[f"{key}_env"]` against `env`.

    Only the environment variable NAME ever reaches a `ConfigError` message —
    never the value it resolves to.
    """
    env_key = f"{key}_env"
    var_name = _require_str(table, env_key, context=context)
    if var_name not in env or not env[var_name]:
        raise ConfigError(f"{context}: environment variable {var_name!r} is not set")
    return env[var_name]


def _load_issuer(table: Mapping[str, Any]) -> IssuerConfig:
    context = "[issuer]"
    issuer_id = _require_str(table, "id", context=context)
    kid = _require_str(table, "kid", context=context)
    # Mirrors `attest.issue.issue`'s own kid-domain check (§3): the part of the
    # kid before the first "/" must equal the issuer id it will sign for, or
    # every receipt this bridge instance mints would fail issuance anyway —
    # better to fail at config load than at the first webhook.
    kid_domain = kid.split("/", 1)[0]
    if kid_domain != issuer_id:
        raise ConfigError(
            f"{context}: kid domain {kid_domain!r} does not match issuer.id {issuer_id!r}"
        )
    return IssuerConfig(
        id=issuer_id,
        display_name=_require_str(table, "display_name", context=context),
        kid=kid,
        seed_path=Path(_require_str(table, "seed_path", context=context)),
        mldsa_key_path=Path(_require_str(table, "mldsa_key_path", context=context)),
        manifest_path=Path(_require_str(table, "manifest_path", context=context)),
    )


def _load_product(key: str, value: Any) -> ProductTemplate:
    if not isinstance(value, dict):
        raise ConfigError(f"[products.{key}]: must be a table")
    context = f"[products.{key}]"

    # `identifiers` is a required field (no default on ProductTemplate): a missing
    # table must fail closed, not silently load an empty identifier set.
    if "identifiers" not in value:
        raise ConfigError(f"{context}: missing required field 'identifiers'")
    identifiers_raw = value["identifiers"]
    if (
        not isinstance(identifiers_raw, dict)
        or not identifiers_raw
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in identifiers_raw.items())
    ):
        raise ConfigError(f"{context}: field 'identifiers' must be a non-empty table of strings")

    return ProductTemplate(
        title=_require_str(value, "title", context=context),
        publisher=_require_str(value, "publisher", context=context),
        identifiers=dict(identifiers_raw),
        artifact_series=_require_str(value, "artifact_series", context=context),
        terms_uri=_require_str(value, "terms_uri", context=context),
        legal_text_sha256=_require_str(value, "legal_text_sha256", context=context),
        grant=_optional_str(value, "grant", "perpetual", context=context),
        revocability=_optional_str(value, "revocability", "none", context=context),
        revocation_window_days=(
            _optional_int(value, "revocation_window_days", 0, context=context)
            if "revocation_window_days" in value
            else None
        ),
        drm=_optional_str(value, "drm", "drm-free", context=context),
        edition=_optional_str_or_none(value, "edition", context=context),
    )


def _load_legal_texts(
    products_table: Mapping[str, Any], products: Mapping[str, ProductTemplate]
) -> dict[str, bytes]:
    """Read each product's licence text and cross-check it against its declared digest.

    `legal_text_sha256` enters the SIGNED payload of every receipt, so the file
    on disk is deliberately NOT the source of truth: it is verified against the
    declaration, and a drift between the two fails the bridge at startup instead
    of silently changing the terms every future receipt is signed against. The
    same posture `load_issuer` takes when a manifest and a key both claim to
    describe the same identity.

    Reading here — not at sale time — means a merchant can never discover a
    missing or stale licence file while a buyer is waiting for a receipt.
    `ConfigError` messages name the product key and the path, never the text.
    """
    legal_texts: dict[str, bytes] = {}
    for key, template in products.items():
        context = f"[products.{key}]"
        raw = products_table[key]
        path = Path(_require_str(raw, "legal_text_path", context=context))
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ConfigError(f"{context}: cannot read legal_text_path {path}: {exc}") from exc
        digest = hashlib.sha256(content).hexdigest()
        if digest != template.legal_text_sha256:
            raise ConfigError(
                f"{context}: {path} hashes to {digest}, but legal_text_sha256 "
                f"declares {template.legal_text_sha256}"
            )
        legal_texts[digest] = content
    return legal_texts


def _load_stripe(table: Mapping[str, Any], env: Mapping[str, str]) -> StripeConfig:
    context = "[stripe]"
    api_key = _env(env, table, "api_key", context=context) if "api_key_env" in table else None
    return StripeConfig(
        webhook_secret=_env(env, table, "webhook_secret", context=context),
        api_key=api_key,
    )


def _load_shopify(table: Mapping[str, Any], env: Mapping[str, str]) -> ShopifyConfig:
    context = "[shopify]"
    return ShopifyConfig(webhook_secret=_env(env, table, "webhook_secret", context=context))


def _load_itch(table: Mapping[str, Any], env: Mapping[str, str]) -> ItchConfig:
    context = "[itch]"
    return ItchConfig(
        api_key=_env(env, table, "api_key", context=context),
        poll_interval_seconds=_optional_int(table, "poll_interval_seconds", 60, context=context),
        max_attempts=_optional_int(table, "max_attempts", 10, context=context),
    )


def _load_delivery(table: Mapping[str, Any], env: Mapping[str, str]) -> DeliveryConfig:
    context = "[delivery]"
    return DeliveryConfig(
        smtp_host=_require_str(table, "smtp_host", context=context),
        smtp_port=_require_int(table, "smtp_port", context=context),
        smtp_username=_require_str(table, "smtp_username", context=context),
        smtp_password=_env(env, table, "smtp_password", context=context),
        from_address=_require_str(table, "from_address", context=context),
        info_url=_optional_str(table, "info_url", _DEFAULT_INFO_URL, context=context),
    )


def load_config(path: Path, env: Mapping[str, str] | None = None) -> BridgeConfig:
    """Parse and validate `path` into a `BridgeConfig`, resolving `*_env` secrets against `env`.

    `env` defaults to `os.environ` (the real process environment); tests pass
    an explicit mapping so secret resolution never depends on ambient state.
    Raises `ConfigError` on any structural problem or missing secret,
    fail-fast, before the bridge starts serving webhooks.
    """
    resolved_env: Mapping[str, str] = env if env is not None else os.environ

    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"malformed TOML in {path}: {exc}") from exc

    public_base_url = _require_str(data, "public_base_url", context="config")
    if not public_base_url.startswith("https://"):
        raise ConfigError(
            f"config: public_base_url must start with 'https://', got {public_base_url!r}"
        )
    ledger_path = Path(_require_str(data, "ledger_path", context="config"))

    issuer = _load_issuer(_require_table(data, "issuer", context="config"))

    products_table = _optional_table(data, "products", context="config") or {}
    products = {key: _load_product(key, value) for key, value in products_table.items()}
    legal_texts = _load_legal_texts(products_table, products)

    stripe_table = _optional_table(data, "stripe", context="config")
    shopify_table = _optional_table(data, "shopify", context="config")
    itch_table = _optional_table(data, "itch", context="config")
    delivery_table = _optional_table(data, "delivery", context="config")

    # itch claim resolution attaches a salt-bearing receipt and is deliberately
    # delivery-only-via-email. A download-link-only deployment must therefore
    # fail before it can accept any itch claims.
    if itch_table is not None and delivery_table is None:
        raise ConfigError("[itch] requires a usable [delivery] SMTP section")

    return BridgeConfig(
        public_base_url=public_base_url,
        ledger_path=ledger_path,
        issuer=issuer,
        products=products,
        stripe=_load_stripe(stripe_table, resolved_env) if stripe_table is not None else None,
        shopify=_load_shopify(shopify_table, resolved_env) if shopify_table is not None else None,
        itch=_load_itch(itch_table, resolved_env) if itch_table is not None else None,
        delivery=(
            _load_delivery(delivery_table, resolved_env) if delivery_table is not None else None
        ),
        legal_texts=legal_texts,
    )
