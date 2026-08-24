"""BridgeConfig TOML loader: env-referenced secrets, fail-fast validation.

Contract under test: secrets never live in bridge.toml —
sections reference environment variables via `*_env` keys, and `load_config`
resolves them at startup. A missing variable must be named in the
`ConfigError`; a resolved secret VALUE must never appear in any exception
message or `repr()`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from attest_bridge import config as config_mod
from attest_bridge.config import (
    BridgeConfig,
    DeliveryConfig,
    IssuerConfig,
    ItchConfig,
    StripeConfig,
    load_config,
)
from attest_bridge.model import ConfigError
from conftest import LEGAL_TEXT, LEGAL_TEXT_SHA256

# Every products table below points at the licence file `_write` materialises
# in the same tmp dir; `load_config` reads it and cross-checks its digest
# against the declared `legal_text_sha256`, so both must come from one source.
_LEGAL_TEXT_PATH_PLACEHOLDER = "__LEGAL_TEXT_PATH__"

_VALID_TOML = f"""
public_base_url = "https://receipts.example.com"
ledger_path = "/var/lib/attest-bridge/ledger.sqlite3"

[issuer]
id = "store.example.com"
display_name = "Example Games Store"
kid = "store.example.com/keys/2026-07#hybrid-1"
seed_path = "/secrets/issuer.seed"
mldsa_key_path = "/secrets/issuer.mldsa.json"
manifest_path = "/etc/attest-bridge/key-manifest.json"

[stripe]
webhook_secret_env = "STRIPE_WEBHOOK_SECRET"
api_key_env = "STRIPE_API_KEY"

[itch]
api_key_env = "ITCH_API_KEY"
poll_interval_seconds = 60
max_attempts = 10

[delivery]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "receipts@example.com"
smtp_password_env = "SMTP_PASSWORD"
from_address = "receipts@example.com"
info_url = "https://store.example.com/what-is-this-file"

[products.price_1PxYzEXAMPLE]
title = "Example Game"
publisher = "Example Publisher srl"
artifact_series = "store.example.com/works/EXG-001"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{LEGAL_TEXT_SHA256}"
legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"
[products.price_1PxYzEXAMPLE.identifiers]
issuer_sku = "EXG-001"
"""

# Sections omitted entirely to prove [stripe]/[itch]/[delivery] are each optional.
_MINIMAL_TOML = f"""
public_base_url = "https://receipts.example.com"
ledger_path = "/var/lib/attest-bridge/ledger.sqlite3"

[issuer]
id = "store.example.com"
display_name = "Example Games Store"
kid = "store.example.com/keys/2026-07#hybrid-1"
seed_path = "/secrets/issuer.seed"
mldsa_key_path = "/secrets/issuer.mldsa.json"
manifest_path = "/etc/attest-bridge/key-manifest.json"

[products.price_1PxYzEXAMPLE]
title = "Example Game"
publisher = "Example Publisher srl"
artifact_series = "store.example.com/works/EXG-001"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{LEGAL_TEXT_SHA256}"
legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"
[products.price_1PxYzEXAMPLE.identifiers]
issuer_sku = "EXG-001"
"""

_SECRET_ENV = {
    "STRIPE_WEBHOOK_SECRET": "whsec_test_value",
    "STRIPE_API_KEY": "sk_test_value",
    "ITCH_API_KEY": "itch_test_value",
    "SMTP_PASSWORD": "smtp_test_value",
}


def _legal_file(tmp_path: Path, content: bytes = LEGAL_TEXT, name: str = "license.txt") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _write(tmp_path: Path, content: str) -> Path:
    """Write `content` as bridge.toml, materialising the licence file it points at."""
    legal_path = _legal_file(tmp_path)
    path = tmp_path / "bridge.toml"
    path.write_text(content.replace(_LEGAL_TEXT_PATH_PLACEHOLDER, str(legal_path)))
    return path


def test_full_round_trip_parses_every_section(tmp_path: Path) -> None:
    path = _write(tmp_path, _VALID_TOML)

    config = load_config(path, env=_SECRET_ENV)

    assert isinstance(config, BridgeConfig)
    assert config.public_base_url == "https://receipts.example.com"
    assert config.ledger_path == Path("/var/lib/attest-bridge/ledger.sqlite3")

    assert isinstance(config.issuer, IssuerConfig)
    assert config.issuer.id == "store.example.com"
    assert config.issuer.display_name == "Example Games Store"
    assert config.issuer.kid == "store.example.com/keys/2026-07#hybrid-1"
    assert config.issuer.seed_path == Path("/secrets/issuer.seed")
    assert config.issuer.mldsa_key_path == Path("/secrets/issuer.mldsa.json")
    assert config.issuer.manifest_path == Path("/etc/attest-bridge/key-manifest.json")

    assert isinstance(config.stripe, StripeConfig)
    assert config.stripe.webhook_secret == "whsec_test_value"  # noqa: S105 - test fixture value
    assert config.stripe.api_key == "sk_test_value"

    assert isinstance(config.itch, ItchConfig)
    assert config.itch.api_key == "itch_test_value"
    assert config.itch.poll_interval_seconds == 60
    assert config.itch.max_attempts == 10

    assert isinstance(config.delivery, DeliveryConfig)
    assert config.delivery.smtp_host == "smtp.example.com"
    assert config.delivery.smtp_port == 587
    assert config.delivery.smtp_username == "receipts@example.com"
    assert config.delivery.smtp_password == "smtp_test_value"  # noqa: S105 - test fixture value
    assert config.delivery.from_address == "receipts@example.com"
    assert config.delivery.info_url == "https://store.example.com/what-is-this-file"

    assert config.products.keys() == {"price_1PxYzEXAMPLE"}
    template = config.products["price_1PxYzEXAMPLE"]
    assert template.title == "Example Game"
    assert template.publisher == "Example Publisher srl"
    assert template.artifact_series == "store.example.com/works/EXG-001"
    assert template.identifiers == {"issuer_sku": "EXG-001"}
    assert template.grant == "perpetual"


def test_load_config_reads_env_from_process_environment_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path, _VALID_TOML)
    for key, value in _SECRET_ENV.items():
        monkeypatch.setenv(key, value)

    config = load_config(path)

    assert config.stripe is not None
    assert config.stripe.webhook_secret == "whsec_test_value"  # noqa: S105 - test fixture value


def test_missing_env_var_raises_config_error_naming_the_variable_not_the_value(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _VALID_TOML)
    env = dict(_SECRET_ENV)
    del env["STRIPE_WEBHOOK_SECRET"]

    with pytest.raises(ConfigError) as exc_info:
        load_config(path, env=env)

    message = str(exc_info.value)
    assert "STRIPE_WEBHOOK_SECRET" in message
    assert "whsec_test_value" not in message


def test_kid_domain_issuer_id_mismatch_raises_config_error(tmp_path: Path) -> None:
    content = _VALID_TOML.replace(
        'kid = "store.example.com/keys/2026-07#hybrid-1"',
        'kid = "other.example.com/keys/2026-07#hybrid-1"',
    )
    path = _write(tmp_path, content)

    with pytest.raises(ConfigError, match="kid"):
        load_config(path, env=_SECRET_ENV)


def test_http_base_url_raises_config_error(tmp_path: Path) -> None:
    content = _VALID_TOML.replace(
        'public_base_url = "https://receipts.example.com"',
        'public_base_url = "http://receipts.example.com"',
    )
    path = _write(tmp_path, content)

    with pytest.raises(ConfigError, match="https://"):
        load_config(path, env=_SECRET_ENV)


def test_stripe_itch_delivery_tables_are_all_optional(tmp_path: Path) -> None:
    path = _write(tmp_path, _MINIMAL_TOML)

    config = load_config(path, env={})

    assert config.stripe is None
    assert config.itch is None
    assert config.delivery is None


def test_info_url_defaults_to_the_canonical_page(tmp_path: Path) -> None:
    # A merchant who never wrote an `info_url` still gets a usable link in every
    # receipt email, instead of a bare field the loader would otherwise reject.
    content = _VALID_TOML.replace('info_url = "https://store.example.com/what-is-this-file"\n', "")
    path = _write(tmp_path, content)

    config = load_config(path, env=_SECRET_ENV)

    assert config.delivery is not None
    assert config.delivery.info_url == config_mod._DEFAULT_INFO_URL


def test_default_info_url_page_ships_with_the_site() -> None:
    page = Path(__file__).parents[2] / "site/public/what-is-this.html"

    assert page.exists()
    text = page.read_text()

    assert "attest" in text.lower()
    # (1) what the file is
    assert "receipt" in text.lower()
    # (2) it can be checked without the store, and (2a) how — a link to the verifier
    assert 'href="./"' in text or 'href="/"' in text
    # (3) the .private.attest file must never be shared
    assert ".private.attest" in text
    assert "never" in text.lower()
    # (4) what to do if the store is gone
    assert "gone" in text.lower() or "no longer" in text.lower() or "closed" in text.lower()

    assert config_mod._DEFAULT_INFO_URL.startswith("https://bernalli.github.io/attest/")
    assert config_mod._DEFAULT_INFO_URL.rsplit("/", 1)[-1] == page.name


def test_itch_requires_smtp_delivery_at_config_load(tmp_path: Path) -> None:
    delivery_section = """[delivery]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "receipts@example.com"
smtp_password_env = "SMTP_PASSWORD"
from_address = "receipts@example.com"
info_url = "https://store.example.com/what-is-this-file"

"""
    content = _VALID_TOML.replace(delivery_section, "")
    with pytest.raises(ConfigError, match=r"\[itch\].*\[delivery\]"):
        load_config(_write(tmp_path, content), env=_SECRET_ENV)


def test_missing_required_product_field_raises_config_error_naming_key_and_field(
    tmp_path: Path,
) -> None:
    content = _VALID_TOML.replace(f'legal_text_sha256 = "{LEGAL_TEXT_SHA256}"\n', "")
    path = _write(tmp_path, content)

    with pytest.raises(ConfigError) as exc_info:
        load_config(path, env=_SECRET_ENV)

    message = str(exc_info.value)
    assert "price_1PxYzEXAMPLE" in message
    assert "legal_text_sha256" in message


def test_missing_identifiers_raises_config_error_naming_key_and_field(tmp_path: Path) -> None:
    content = _VALID_TOML.replace(
        '[products.price_1PxYzEXAMPLE.identifiers]\nissuer_sku = "EXG-001"\n', ""
    )
    path = _write(tmp_path, content)
    with pytest.raises(ConfigError) as exc_info:
        load_config(path, env=_SECRET_ENV)
    message = str(exc_info.value)
    assert "price_1PxYzEXAMPLE" in message
    assert "identifiers" in message


def test_non_string_edition_raises_config_error_naming_key_and_field(tmp_path: Path) -> None:
    # A present-but-malformed optional field must fail closed, not silently drop to None.
    content = _VALID_TOML.replace(
        "[products.price_1PxYzEXAMPLE.identifiers]",
        "edition = 123\n[products.price_1PxYzEXAMPLE.identifiers]",
    )
    path = _write(tmp_path, content)
    with pytest.raises(ConfigError) as exc_info:
        load_config(path, env=_SECRET_ENV)
    message = str(exc_info.value)
    assert "price_1PxYzEXAMPLE" in message
    assert "edition" in message


def test_empty_edition_raises_config_error(tmp_path: Path) -> None:
    content = _VALID_TOML.replace(
        "[products.price_1PxYzEXAMPLE.identifiers]",
        'edition = ""\n[products.price_1PxYzEXAMPLE.identifiers]',
    )
    path = _write(tmp_path, content)
    with pytest.raises(ConfigError, match="edition"):
        load_config(path, env=_SECRET_ENV)


def test_empty_itch_secret_is_rejected_at_config_load(tmp_path: Path) -> None:
    env = dict(_SECRET_ENV)
    env["ITCH_API_KEY"] = ""
    with pytest.raises(ConfigError, match="ITCH_API_KEY"):
        load_config(_write(tmp_path, _VALID_TOML), env=env)


def test_product_exposes_revocation_window_days(tmp_path: Path) -> None:
    content = _VALID_TOML.replace(
        "[products.price_1PxYzEXAMPLE.identifiers]",
        'revocability = "refund_window"\n'
        "revocation_window_days = 30\n"
        "[products.price_1PxYzEXAMPLE.identifiers]",
    )
    config = load_config(_write(tmp_path, content), env=_SECRET_ENV)
    assert config.products["price_1PxYzEXAMPLE"].revocation_window_days == 30


def test_resolved_secret_value_never_appears_in_repr_or_error_messages(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _VALID_TOML)

    config = load_config(path, env=_SECRET_ENV)

    assert config.stripe is not None
    assert config.itch is not None
    assert config.delivery is not None
    blob = " ".join([repr(config), repr(config.stripe), repr(config.itch), repr(config.delivery)])
    for secret_value in _SECRET_ENV.values():
        assert secret_value not in blob


# -- per-product licence text, verified at load ----------------------------
#
# A receipt's `license.legal_text_sha256` enters the SIGNED payload, but the
# text itself never did: when the store dies the buyer is left with a hash that
# resolves to nothing readable. The bridge therefore holds the text and ships it
# inside the bundle (spec §14.1). It is loaded and hash-verified at startup, so
# a merchant can never discover at sale time that the file is missing or that it
# no longer matches the terms every receipt has been signing for.


def test_load_config_reads_and_verifies_product_legal_text(tmp_path: Path) -> None:
    path = _write(tmp_path, _VALID_TOML)

    config = load_config(path, env=_SECRET_ENV)

    assert config.legal_texts == {LEGAL_TEXT_SHA256: LEGAL_TEXT}


def test_missing_legal_text_path_is_a_config_error_naming_the_product(tmp_path: Path) -> None:
    content = _VALID_TOML.replace(f'legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"\n', "")

    with pytest.raises(ConfigError) as exc_info:
        load_config(_write(tmp_path, content), env=_SECRET_ENV)

    message = str(exc_info.value)
    assert "price_1PxYzEXAMPLE" in message
    assert "legal_text_path" in message


def test_missing_legal_text_file_is_a_config_error(tmp_path: Path) -> None:
    missing = tmp_path / "nowhere" / "license.txt"
    content = _VALID_TOML.replace(_LEGAL_TEXT_PATH_PLACEHOLDER, str(missing))

    with pytest.raises(ConfigError) as exc_info:
        load_config(_write(tmp_path, content), env=_SECRET_ENV)

    message = str(exc_info.value)
    assert "price_1PxYzEXAMPLE" in message
    assert str(missing) in message


def test_legal_text_hash_mismatch_is_a_config_error_naming_the_product(tmp_path: Path) -> None:
    tampered = b"these are not the terms every receipt was signed against"
    other = _legal_file(tmp_path, tampered, name="tampered.txt")
    content = _VALID_TOML.replace(_LEGAL_TEXT_PATH_PLACEHOLDER, str(other))

    with pytest.raises(ConfigError) as exc_info:
        load_config(_write(tmp_path, content), env=_SECRET_ENV)

    message = str(exc_info.value)
    assert "price_1PxYzEXAMPLE" in message
    # The error names the product and the path — never the terms themselves,
    # neither the file on disk nor the text the declared digest stands for.
    assert tampered.decode() not in message
    assert LEGAL_TEXT.decode() not in message


def test_two_products_may_share_one_legal_text_file(tmp_path: Path) -> None:
    second_product = f"""
[products.price_SECOND]
title = "Second Example Game"
publisher = "Example Publisher srl"
artifact_series = "store.example.com/works/EXG-002"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{LEGAL_TEXT_SHA256}"
legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"
[products.price_SECOND.identifiers]
issuer_sku = "EXG-002"
"""
    config = load_config(_write(tmp_path, _VALID_TOML + second_product), env=_SECRET_ENV)

    assert config.products.keys() == {"price_1PxYzEXAMPLE", "price_SECOND"}
    assert config.legal_texts == {LEGAL_TEXT_SHA256: LEGAL_TEXT}
