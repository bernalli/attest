"""CLI tests: `check-config` and `retry-failed`.

`check-config` is exercised against a real `bridge.toml` pointing at real T3
key/manifest files (the exact on-disk shapes `attest keygen`/`manifest init`
write) — a passing test here is evidence the whole config -> issuer ->
catalog chain works end to end, not just that `ConfigError` propagates from
a synthetic stand-in.
"""

from __future__ import annotations

import json
import os
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest
from attest_bridge import cli
from attest_bridge.catalog import ProductCatalog, ProductTemplate
from attest_bridge.delivery import DeliveryResult
from attest_bridge.itch_adapter import ItchAdapter, ItchApiError
from attest_bridge.ledger import Ledger
from attest_bridge.model import ConfigError
from conftest import DISPLAY_NAME, ISSUER, KID, LEGAL_TEXT, LEGAL_TEXT_SHA256
from test_bridge_stripe_adapter import make_session_completed_event

from attest import bundle, keys, pq
from attest import verify as verify_mod

_STRIPE_ENV_VAR = "STRIPE_WEBHOOK_SECRET_T8_CLI_TEST"  # env var NAME, not a secret
# `_write_config` materialises the licence file every products table points at,
# and substitutes its absolute path for this placeholder: `load_config` reads it
# and cross-checks its digest against the declared `legal_text_sha256`.
_LEGAL_TEXT_PATH_PLACEHOLDER = "__LEGAL_TEXT_PATH__"

_PRICE_TEST_PRODUCT = f"""
[products.price_TEST]
title = "Stardrift Chronicles"
publisher = "Example Games Store"
artifact_series = "merchant.example.com/works/stardrift-chronicles"
terms_uri = "https://merchant.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{LEGAL_TEXT_SHA256}"
legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"
[products.price_TEST.identifiers]
sku = "SDC-STD-001"
"""

_SHOPIFY_ENV_VAR = "SHOPIFY_WEBHOOK_SECRET_CLI_TEST"  # env var NAME, not a secret
_SHOPIFY_VARIANT_PRODUCT = f"""
[products.shopify_49148385]
title = "The Long Dusk"
publisher = "Example Games Store"
artifact_series = "merchant.example.com/works/the-long-dusk"
terms_uri = "https://merchant.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{LEGAL_TEXT_SHA256}"
legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"
[products.shopify_49148385.identifiers]
shopify_variant_id = "49148385"
"""


def _write_issuer_key_files(tmp_path: Path, hybrid_keys: pq.HybridSigningKeys) -> tuple[Path, Path]:
    seed_path = tmp_path / "issuer.seed"
    seed_path.write_text(keys.b64u(hybrid_keys.ed.seed) + "\n", encoding="utf-8")

    mldsa_path = tmp_path / "issuer.mldsa.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    return seed_path, mldsa_path


def _write_config(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    *,
    products_toml: str = "",
    extra_toml: str = "",
) -> Path:
    seed_path, mldsa_path = _write_issuer_key_files(tmp_path, hybrid_keys)
    manifest_path = tmp_path / "key-manifest.json"
    manifest_path.write_text(json.dumps(key_manifest), encoding="utf-8")
    ledger_path = tmp_path / "ledger.sqlite3"
    legal_path = tmp_path / "license.txt"
    legal_path.write_bytes(LEGAL_TEXT)

    config_text = f"""
public_base_url = "https://receipts.example.com"
ledger_path = "{ledger_path}"

[issuer]
id = "{ISSUER}"
display_name = "{DISPLAY_NAME}"
kid = "{KID}"
seed_path = "{seed_path}"
mldsa_key_path = "{mldsa_path}"
manifest_path = "{manifest_path}"

[stripe]
webhook_secret_env = "{_STRIPE_ENV_VAR}"

{products_toml}
{extra_toml}
"""
    config_path = tmp_path / "bridge.toml"
    config_path.write_text(
        config_text.replace(_LEGAL_TEXT_PATH_PLACEHOLDER, str(legal_path)), encoding="utf-8"
    )
    return config_path


# -- check-config ---------------------------------------------------------


def test_check_config_rc_0_on_valid_config_with_real_key_files(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )

    rc = cli.main(["check-config", "--config", str(config_path)])

    assert rc == 0
    out = capsys.readouterr().out
    assert ISSUER in out
    assert "price_TEST" in out
    assert "stripe: configured" in out


def test_check_config_rc_2_on_missing_env_var(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(_STRIPE_ENV_VAR, raising=False)
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )

    rc = cli.main(["check-config", "--config", str(config_path)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "config error" in err
    assert _STRIPE_ENV_VAR in err


def test_check_config_rc_2_on_corrupt_key_file(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )
    (tmp_path / "issuer.seed").write_text("not-a-valid-seed", encoding="utf-8")

    rc = cli.main(["check-config", "--config", str(config_path)])

    assert rc == 2
    assert "config error" in capsys.readouterr().err


def test_check_config_rejects_product_the_real_receipt_schema_cannot_issue(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    # A grant the loader accepts (any non-empty string) but the receipt schema
    # rejects (enum: perpetual|subscription) — the product is only unissuable
    # once it reaches the real payload builder, which is what this gate is for.
    invalid = _PRICE_TEST_PRODUCT.replace(
        "[products.price_TEST.identifiers]",
        'grant = "rental"\n[products.price_TEST.identifiers]',
    )

    assert (
        cli.main(
            [
                "check-config",
                "--config",
                str(_write_config(tmp_path, hybrid_keys, key_manifest, products_toml=invalid)),
            ]
        )
        == 2
    )
    err = capsys.readouterr().err
    assert "price_TEST" in err
    # Pin the REASON, not just the exit code: this must fail at the payload
    # schema, never at an earlier config check that happens to also reject it.
    assert "grant" in err


# -- retry-failed -----------------------------------------------------------


def test_retry_failed_resolves_dead_letter_after_catalog_gains_the_mapping(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")

    # A dead letter recorded when `price_TEST` had no catalog mapping yet —
    # `raw_json` is the whole raw event, exactly what a real webhook handler
    # would have dead-lettered on UnmappedProduct.
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = Ledger(ledger_path)
    event = make_session_completed_event(
        session_id="cs_retry_1", metadata={"attest_product_key": "price_TEST"}
    )
    ledger.add_dead_letter(
        "stripe",
        "cs_retry_1",
        "no product mapping for 'price_TEST'",
        json.dumps(event),
        now="2026-07-24T10:00:00Z",
    )
    assert len(ledger.unresolved_dead_letters()) == 1

    # The merchant fixes the catalog: the config now maps price_TEST.
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )

    rc = cli.main(["retry-failed", "--config", str(config_path)])

    assert rc == 0
    assert "undelivered: 0" in capsys.readouterr().out
    assert ledger.unresolved_dead_letters() == []
    stored = ledger.get_receipt("stripe", "cs_retry_1")
    assert stored is not None


def test_retry_failed_replays_a_shopify_dead_letter(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Shopify dead letter has to be recoverable, or acknowledging one with
    200 quietly discards a paid purchase. The stored `raw_json` is the whole
    signed order, so the replay re-drives the same path the webhook took."""
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    monkeypatch.setenv(_SHOPIFY_ENV_VAR, "shpss_real_test_secret")

    ledger = Ledger(tmp_path / "ledger.sqlite3")
    order = {
        "id": 820982911946154508,
        "email": "buyer@example.com",
        "financial_status": "paid",
        "created_at": "2026-08-24T11:15:00-05:00",
        "currency": "EUR",
        "total_price": "12.00",
        "line_items": [{"variant_id": 49148385}],
    }
    ledger.add_dead_letter(
        "shopify",
        "820982911946154508",
        "no product mapping for 'shopify_49148385'",
        json.dumps(order),
        now="2026-08-24T10:00:00Z",
    )

    # The merchant fixes the catalog, exactly as in the Stripe case above.
    config_path = _write_config(
        tmp_path,
        hybrid_keys,
        key_manifest,
        products_toml=_SHOPIFY_VARIANT_PRODUCT,
        extra_toml=f'[shopify]\nwebhook_secret_env = "{_SHOPIFY_ENV_VAR}"\n',
    )

    rc = cli.main(["retry-failed", "--config", str(config_path)])

    assert rc == 0
    assert ledger.unresolved_dead_letters() == []
    assert ledger.get_receipt("shopify", "820982911946154508") is not None


def test_retry_failed_leaves_a_shopify_multi_item_dead_letter_unresolved(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cart of three cannot become one receipt however many times it is
    replayed — the invariant does not bend on retry."""
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    monkeypatch.setenv(_SHOPIFY_ENV_VAR, "shpss_real_test_secret")

    ledger = Ledger(tmp_path / "ledger.sqlite3")
    order = {
        "id": 999000111,
        "email": "buyer@example.com",
        "financial_status": "paid",
        "created_at": "2026-08-24T11:15:00-05:00",
        "line_items": [{"variant_id": 49148385}, {"variant_id": 2}, {"variant_id": 3}],
    }
    ledger.add_dead_letter(
        "shopify", "999000111", "3 line items", json.dumps(order), now="2026-08-24T10:00:00Z"
    )

    config_path = _write_config(
        tmp_path,
        hybrid_keys,
        key_manifest,
        products_toml=_SHOPIFY_VARIANT_PRODUCT,
        extra_toml=f'[shopify]\nwebhook_secret_env = "{_SHOPIFY_ENV_VAR}"\n',
    )

    rc = cli.main(["retry-failed", "--config", str(config_path)])

    assert rc == 1  # incomplete: a dead letter is still unresolved
    assert len(ledger.unresolved_dead_letters()) == 1
    assert ledger.get_receipt("shopify", "999000111") is None


def test_retry_failed_leaves_still_unmapped_dead_letter_unresolved(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")

    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = Ledger(ledger_path)
    event = make_session_completed_event(
        session_id="cs_still_unmapped", metadata={"attest_product_key": "price_STILL_UNKNOWN"}
    )
    ledger.add_dead_letter(
        "stripe",
        "cs_still_unmapped",
        "no product mapping for 'price_STILL_UNKNOWN'",
        json.dumps(event),
        now="2026-07-24T10:00:00Z",
    )

    # No products.* added this time -- the mapping is still missing.
    config_path = _write_config(tmp_path, hybrid_keys, key_manifest, products_toml="")

    rc = cli.main(["retry-failed", "--config", str(config_path)])

    assert rc == 1
    assert len(ledger.unresolved_dead_letters()) == 1
    assert ledger.get_receipt("stripe", "cs_still_unmapped") is None


def test_retry_failed_never_issues_an_unpaid_dead_letter_without_event_id(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    event = make_session_completed_event(
        session_id="cs_unpaid_retry",
        payment_status="unpaid",
        metadata={"attest_product_key": "price_TEST"},
    )
    event.pop("id")
    ledger.add_dead_letter(
        "stripe", "cs_unpaid_retry", "missing id", json.dumps(event), now="2026-07-24T10:00:00Z"
    )

    assert (
        cli.main(
            [
                "retry-failed",
                "--config",
                str(
                    _write_config(
                        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
                    )
                ),
            ]
        )
        == 0
    )
    assert ledger.get_receipt("stripe", "cs_unpaid_retry") is None
    assert ledger.unresolved_dead_letters() == []


def test_retry_failed_reenqueues_itch_dead_letter_without_replaying_purchase(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    monkeypatch.setenv("ITCH_API_KEY", "itch-test")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-test")
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    ledger.add_dead_letter(
        "itch",
        None,
        "abandoned",
        json.dumps({"email": "buyer@example.com", "game_id": "123456"}),
        now="2026-07-24T10:00:00Z",
    )
    extra = """
[itch]
api_key_env = "ITCH_API_KEY"
[delivery]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "merchant"
smtp_password_env = "SMTP_PASSWORD"
from_address = "receipts@example.com"
info_url = "https://merchant.example.com/info"
"""
    assert (
        cli.main(
            [
                "retry-failed",
                "--config",
                str(_write_config(tmp_path, hybrid_keys, key_manifest, extra_toml=extra)),
            ]
        )
        == 0
    )
    assert ledger.unresolved_dead_letters() == []
    claims = ledger.due_claims("2100-01-01T00:00:00Z")
    assert [(claim.email, claim.game_id) for claim in claims] == [("buyer@example.com", "123456")]


def test_retry_failed_rc_2_on_config_error(tmp_path: Path) -> None:
    missing_config = tmp_path / "does-not-exist.toml"
    rc = cli.main(["retry-failed", "--config", str(missing_config)])
    assert rc == 2


def test_retry_failed_returns_nonzero_for_configured_delivery_with_undelivered_receipt(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-test")
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    ledger.record_receipt(
        "stripe",
        "cs_undelivered",
        "receipt_undelivered",
        {},
        "buyer@example.com",
        "download-token-undelivered",
        "2026-07-24T10:00:00Z",
    )
    monkeypatch.setattr(cli, "_sweep_deliveries", lambda deps: (0, 0))
    extra = """
[delivery]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "merchant"
smtp_password_env = "SMTP_PASSWORD"
from_address = "receipts@example.com"
info_url = "https://merchant.example.com/info"
"""
    config_path = _write_config(tmp_path, hybrid_keys, key_manifest, extra_toml=extra)

    assert cli.main(["retry-failed", "--config", str(config_path)]) == 1
    assert "undelivered: 1" in capsys.readouterr().out


# -- serve (fail-fast only -- serve_forever() is not exercised here) --------


def test_serve_fails_fast_with_rc_2_on_config_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_config = tmp_path / "does-not-exist.toml"
    rc = cli.main(["serve", "--config", str(missing_config)])
    assert rc == 2
    assert "config error" in capsys.readouterr().err


def test_serve_installs_sanitized_request_handler(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    installed_handler: type[object] | None = None

    class FakeServer:
        def __enter__(self) -> FakeServer:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def serve_forever(self) -> None:
            return None

    def fake_make_server(*args: object, **kwargs: object) -> FakeServer:
        nonlocal installed_handler
        installed_handler = kwargs["handler_class"]  # type: ignore[assignment,index]
        return FakeServer()

    monkeypatch.setattr(cli, "make_server", fake_make_server)
    config_path = _write_config(tmp_path, hybrid_keys, key_manifest)

    assert cli.main(["serve", "--config", str(config_path)]) == 0
    assert installed_handler is cli._SanitizedRequestHandler


# -- access-log token redaction (2026-07 security review, fix 4) ------------


def test_redact_tokens_hides_download_tokens() -> None:
    # /r/<download-token> is an unguessable receipt capability, so the
    # default WSGI access log must never write it.
    assert cli._redact_tokens("GET /r/abc123 HTTP/1.1") == "GET /r/<redacted> HTTP/1.1"
    assert cli._redact_tokens("GET /healthz HTTP/1.1") == "GET /healthz HTTP/1.1"


def test_redact_tokens_hides_stripe_session_capability_from_access_log() -> None:
    for key in ("session_id", "session%5Fid"):
        request = f"GET /stripe/receipt?{key}=cs_live_secret HTTP/1.1"
        redacted = cli._redact_tokens(request)
        assert "cs_live_secret" not in redacted
        assert "session_id=<redacted>" in redacted


# -- itch-dry-run helpers (V-A.1-bis) --------------------------------------


def test_itch_dry_run_purchase_normalizes_to_the_fixed_invalid_buyer() -> None:
    # The dry run signs a receipt with the merchant's real key, so the buyer
    # identity it commits to must never be a real address: it is pinned to the
    # reserved `.invalid` TLD and is not configurable.
    raw = cli._itch_dry_run_purchase("123456", now=datetime(2026, 8, 24, 12, 0, tzinfo=UTC))
    normalized = ItchAdapter(api_key="itch-key").normalize(raw, email=cli._DRY_RUN_BUYER_EMAIL)

    assert normalized.platform == "itch"
    assert normalized.platform_purchase_id == cli._DRY_RUN_PURCHASE_ID
    assert normalized.product_key == "itch_123456"
    assert normalized.buyer_identifier == cli._DRY_RUN_BUYER_EMAIL
    assert cli._DRY_RUN_BUYER_EMAIL.endswith(".invalid")
    assert normalized.buyer_pubkey is None
    assert normalized.purchased_at == "2026-08-24T12:00:00Z"


def _itch_catalog(*game_ids: str) -> ProductCatalog:
    return ProductCatalog(
        {
            f"itch_{game_id}": ProductTemplate(
                title=f"Nebula Drifters {game_id}",
                publisher="Example Games Store",
                identifiers={"itch_game_id": game_id},
                artifact_series="merchant.example.com/works/nebula-drifters",
                terms_uri="https://merchant.example.com/attest/license-templates/standard-v1",
                legal_text_sha256=LEGAL_TEXT_SHA256,
            )
            for game_id in game_ids
        }
    )


def test_resolve_itch_dry_run_product_picks_the_only_itch_product() -> None:
    assert cli._resolve_itch_dry_run_product(_itch_catalog("123456"), None) == "itch_123456"


def test_resolve_itch_dry_run_product_rejects_no_itch_product() -> None:
    catalog = ProductCatalog({})
    with pytest.raises(ConfigError):
        cli._resolve_itch_dry_run_product(catalog, None)


def test_resolve_itch_dry_run_product_requires_game_id_when_ambiguous() -> None:
    catalog = _itch_catalog("123456", "654321")
    with pytest.raises(ConfigError) as excinfo:
        cli._resolve_itch_dry_run_product(catalog, None)
    # The merchant must be told which keys exist, never given a guess.
    assert "itch_123456" in str(excinfo.value)
    assert "itch_654321" in str(excinfo.value)


def test_resolve_itch_dry_run_product_selects_and_validates_explicit_game_id() -> None:
    catalog = _itch_catalog("123456", "654321")
    assert cli._resolve_itch_dry_run_product(catalog, "654321") == "itch_654321"
    with pytest.raises(ConfigError):
        cli._resolve_itch_dry_run_product(catalog, "999999")


def test_dry_run_fake_api_validates_game_id_buyer_email_and_authorization() -> None:
    # A fake that answers every request would keep the happy path green even if
    # the poller asked for the wrong game or the wrong buyer: the fake is part
    # of the assertion, not scenery.
    raw = cli._itch_dry_run_purchase("123456", now=datetime(2026, 8, 24, 12, 0, tzinfo=UTC))
    http_get = cli._dry_run_http_get(
        raw, game_id="123456", buyer_email=cli._DRY_RUN_BUYER_EMAIL, api_key="itch-key"
    )
    adapter = ItchAdapter(api_key="itch-key", http_get=http_get)

    assert adapter.fetch_purchases("123456", cli._DRY_RUN_BUYER_EMAIL) == [raw]

    with pytest.raises(ItchApiError):
        adapter.fetch_purchases("999999", cli._DRY_RUN_BUYER_EMAIL)
    with pytest.raises(ItchApiError):
        adapter.fetch_purchases("123456", "someone-else@example.invalid")
    wrong_key = ItchAdapter(api_key="wrong-key", http_get=http_get)
    with pytest.raises(ItchApiError):
        wrong_key.fetch_purchases("123456", cli._DRY_RUN_BUYER_EMAIL)


def test_guard_dry_run_out_rejects_production_ledger_path_and_symlink(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    Ledger(ledger_path)

    with pytest.raises(ConfigError):
        cli._guard_dry_run_out_path(ledger_path, ledger_path=ledger_path)

    link_path = tmp_path / "receipt-link.attest"
    link_path.symlink_to(ledger_path)
    with pytest.raises(ConfigError):
        cli._guard_dry_run_out_path(link_path, ledger_path=ledger_path)

    ok_path = tmp_path / "receipt.attest"
    assert cli._guard_dry_run_out_path(ok_path, ledger_path=ledger_path) == ok_path.resolve()


def test_write_receipt_file_no_follow_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.attest"
    target.write_bytes(b"original")
    link = tmp_path / "link.attest"
    link.symlink_to(target)

    with pytest.raises(ConfigError):
        cli._write_receipt_file_no_follow(
            link, b"replacement", ledger_path=tmp_path / "ledger.sqlite3"
        )

    assert target.read_bytes() == b"original"


def test_write_receipt_file_no_follow_writes_mode_0600(tmp_path: Path) -> None:
    out = tmp_path / "receipt.attest"
    cli._write_receipt_file_no_follow(out, b"envelope", ledger_path=tmp_path / "ledger.sqlite3")

    assert out.read_bytes() == b"envelope"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_write_receipt_file_no_follow_is_never_world_readable_while_holding_the_salt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Tightening the mode AFTER writing leaves a window where an existing 0644
    # file already holds the buyer-binding salt. The mode must be right before
    # the first byte is written, not after the last.
    out = tmp_path / "receipt.attest"
    out.write_bytes(b"stale")
    out.chmod(0o644)
    observed: list[int] = []
    real_fdopen = os.fdopen

    def recording_fdopen(fd: int, mode: str) -> Any:
        observed.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return real_fdopen(fd, mode)

    monkeypatch.setattr(cli.os, "fdopen", recording_fdopen)

    cli._write_receipt_file_no_follow(out, b"envelope", ledger_path=tmp_path / "ledger.sqlite3")

    assert observed == [0o600]
    assert out.read_bytes() == b"envelope"


def test_write_receipt_file_no_follow_refuses_a_path_that_became_the_ledger(
    tmp_path: Path,
) -> None:
    # Simulates the TOCTOU the path guard alone cannot close: by the time the
    # file is opened, `path` is a hard link to the production Ledger. The check
    # must happen on the open file descriptor, and before truncation.
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger_path.write_bytes(b"SQLite format 3\x00production")
    hardlink = tmp_path / "receipt.attest"
    os.link(ledger_path, hardlink)

    with pytest.raises(ConfigError):
        cli._write_receipt_file_no_follow(hardlink, b"envelope", ledger_path=ledger_path)

    assert ledger_path.read_bytes() == b"SQLite format 3\x00production"


def test_write_receipt_file_no_follow_leaves_the_ledger_mode_untouched(tmp_path: Path) -> None:
    # Refusing to WRITE the ledger is not enough if we have already changed its
    # permissions on the way: prove identity before touching the descriptor.
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger_path.write_bytes(b"production")
    ledger_path.chmod(0o644)
    hardlink = tmp_path / "receipt.attest"
    os.link(ledger_path, hardlink)

    with pytest.raises(ConfigError):
        cli._write_receipt_file_no_follow(hardlink, b"envelope", ledger_path=ledger_path)

    assert stat.S_IMODE(ledger_path.stat().st_mode) == 0o644


def test_write_receipt_file_no_follow_closes_the_descriptor_when_fdopen_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "receipt.attest"
    opened_fds: list[int] = []
    real_open = os.open

    def recording_open(path: Any, flags: int, mode: int = 0o777) -> int:
        fd = real_open(path, flags, mode)
        opened_fds.append(fd)
        return fd

    def failing_fdopen(fd: int, mode: str) -> Any:
        raise OSError("fdopen refused")

    monkeypatch.setattr(cli.os, "open", recording_open)
    monkeypatch.setattr(cli.os, "fdopen", failing_fdopen)

    with pytest.raises(OSError):
        cli._write_receipt_file_no_follow(out, b"envelope", ledger_path=tmp_path / "ledger.sqlite3")

    assert len(opened_fds) == 1
    with pytest.raises(OSError):
        os.fstat(opened_fds[0])  # a leaked descriptor would still be valid here


# -- itch-dry-run command --------------------------------------------------

_ITCH_ENV_VAR = "ITCH_API_KEY_DRY_RUN_TEST"  # env var NAME, not a secret
_SMTP_ENV_VAR = "SMTP_PASSWORD_DRY_RUN_TEST"  # env var NAME, not a secret

_ITCH_GAME_PRODUCT = f"""
[products.itch_123456]
title = "Nebula Drifters"
publisher = "Example Games Store"
artifact_series = "merchant.example.com/works/nebula-drifters"
terms_uri = "https://merchant.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{LEGAL_TEXT_SHA256}"
legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"
[products.itch_123456.identifiers]
itch_game_id = "123456"
"""

_SECOND_ITCH_GAME_PRODUCT = f"""
[products.itch_654321]
title = "Nebula Drifters II"
publisher = "Example Games Store"
artifact_series = "merchant.example.com/works/nebula-drifters-ii"
terms_uri = "https://merchant.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{LEGAL_TEXT_SHA256}"
legal_text_path = "{_LEGAL_TEXT_PATH_PLACEHOLDER}"
[products.itch_654321.identifiers]
itch_game_id = "654321"
"""

_ITCH_AND_DELIVERY_TOML = f"""
[itch]
api_key_env = "{_ITCH_ENV_VAR}"

[delivery]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "receipts@merchant.example.com"
smtp_password_env = "{_SMTP_ENV_VAR}"
from_address = "receipts@merchant.example.com"
info_url = "https://merchant.example.com/what-is-this-file"
"""


def _write_itch_dry_run_config(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    *,
    products_toml: str = _ITCH_GAME_PRODUCT,
    extra_toml: str = _ITCH_AND_DELIVERY_TOML,
) -> Path:
    monkeypatch.setenv(_ITCH_ENV_VAR, "itch-api-key-value")
    monkeypatch.setenv(_SMTP_ENV_VAR, "smtp-password-value")
    # `_write_config` always emits a [stripe] section; its secret must resolve.
    monkeypatch.setenv(_STRIPE_ENV_VAR, "stripe-webhook-secret-value")
    return _write_config(
        tmp_path,
        hybrid_keys,
        key_manifest,
        products_toml=products_toml,
        extra_toml=extra_toml,
    )


def _ledger_path_of(config_path: Path) -> Path:
    for line in config_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("ledger_path"):
            return Path(line.split("=", 1)[1].strip().strip('"'))
    raise AssertionError("config has no ledger_path")


def test_itch_dry_run_writes_the_pair_and_the_shareable_half_is_salt_free(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    trust_store: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    ledger_path = _ledger_path_of(config_path)
    assert not ledger_path.exists()
    out_path = tmp_path / "dry-run.attest"
    private_path = tmp_path / "dry-run.private.attest"

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)])

    assert rc == 0
    stdout = capsys.readouterr().out
    assert "ledger: throwaway" in stdout
    # The whole point of the command: the merchant's real Ledger is never opened.
    assert not ledger_path.exists()
    assert out_path.exists()
    assert private_path.exists()
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600

    receipt, salt, salt_b64u = _dry_run_pair(out_path, private_path)
    receipt_bytes = json.dumps(receipt).encode("utf-8")
    assert verify_mod.verify(receipt_bytes, trust_store).ok is True

    proven = verify_mod.verify(
        receipt_bytes,
        trust_store,
        disclosure=verify_mod.Disclosure(
            identifier=cli._DRY_RUN_BUYER_EMAIL, identifier_type="email", salt=salt
        ),
    )
    assert proven.binding == "proven"
    # A real address can never be the signed identity of a dry-run receipt.
    not_proven = verify_mod.verify(
        receipt_bytes,
        trust_store,
        disclosure=verify_mod.Disclosure(
            identifier="merchant@example.com", identifier_type="email", salt=salt
        ),
    )
    assert not_proven.binding == "not_proven"

    # The salt may live only in the private half. Scanning the shareable
    # container's bytes would prove nothing — members are DEFLATE-compressed —
    # so every member is decompressed and searched.
    with zipfile.ZipFile(out_path) as zf:
        members = zf.namelist()
        assert members
        for member in members:
            content = zf.read(member)
            assert salt_b64u.encode() not in content
            assert salt not in content


# -- itch-dry-run: the §14.1/§14.2 pair ------------------------------------
#
# The dry run used to write the stored envelope — salt and all — to
# `itch-dry-run-receipt.attest`, a name §14.1 reserves for the salt-free half.
# It now writes the pair, and `--out` names the SHAREABLE one.


def _dry_run_pair(out_path: Path, private_path: Path) -> tuple[dict[str, Any], bytes, str]:
    """Import the pair the dry run wrote; return (receipt, salt bytes, salt b64u)."""
    imported = bundle.import_bundle(out_path, private_path)
    assert len(imported.receipts) == 1
    receipt = imported.receipts[0]
    receipt_id = receipt["payload"]["receipt_id"]
    with zipfile.ZipFile(private_path) as zf:
        salt_b64u = json.loads(zf.read("salts.json"))[receipt_id]
    return receipt, imported.salts[receipt_id], salt_b64u


def test_itch_dry_run_out_ending_in_private_attest_is_refused(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`--out` is the shareable half. A `--out` already wearing the private
    suffix would make the two halves swap names, and the name is the only
    guard the web verifier has — so it is refused, not silently renamed."""
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "confused.private.attest"

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)])

    assert rc == 2
    assert "config error" in capsys.readouterr().err
    assert not out_path.exists()


def test_itch_dry_run_stdout_names_both_files_and_the_import_verify_flow(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"
    private_path = tmp_path / "dry-run.private.attest"

    assert cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)]) == 0

    stdout = capsys.readouterr().out
    resolved_out = str(out_path.resolve())
    resolved_private = str(private_path.resolve())
    assert resolved_out in stdout
    private_at = stdout.index(resolved_private)
    # The merchant is told which of the two must never leave their machine,
    # after the path it refers to.
    assert "never share" in stdout[private_at:].lower()

    # The verify hint is the real import+verify flow the guides document, not
    # a `attest verify <bundle>` that would fail on a zip.
    assert f"attest import --bundle {resolved_out}" in stdout
    assert f"--private {resolved_private}" in stdout
    assert "--out-dir" in stdout
    assert "attest verify" in stdout
    assert "--trust-dir" in stdout


def test_itch_dry_run_settled_purchase_is_processed_by_the_poller(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Regression on the poller's status filter: this runs the real tick, so it
    # goes red if "settled" ever starts being skipped.
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)])

    assert rc == 0
    assert "claim: confirmed (receipts issued: 1)" in capsys.readouterr().out


def test_itch_dry_run_rejects_out_equal_to_or_symlinked_to_production_ledger(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    ledger_path = _ledger_path_of(config_path)

    assert cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(ledger_path)]) == 2

    Ledger(ledger_path)
    before = ledger_path.read_bytes()
    link_path = tmp_path / "ledger-link.attest"
    link_path.symlink_to(ledger_path)

    assert cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(link_path)]) == 2
    assert ledger_path.read_bytes() == before

    # The private half is DERIVED from `--out`, so it never passes under the
    # guard on its own name — it has to be guarded too, or a symlink planted
    # at the derived path would write the salt straight through to the Ledger.
    derived_out = tmp_path / "derived.attest"
    derived_private = tmp_path / "derived.private.attest"
    derived_private.symlink_to(ledger_path)

    assert cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(derived_out)]) == 2
    assert ledger_path.read_bytes() == before


def test_itch_dry_run_rejects_hardlinked_shareable_and_private_paths(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"
    private_path = tmp_path / "dry-run.private.attest"
    preexisting = tmp_path / "preexisting"
    preexisting.write_bytes(b"do not replace with private salt")
    os.link(preexisting, out_path)
    os.link(preexisting, private_path)

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)])

    stderr = capsys.readouterr().err
    assert rc == 2
    assert str(out_path.resolve()) in stderr
    assert str(private_path.resolve()) in stderr
    assert "same file" in stderr
    assert preexisting.read_bytes() == b"do not replace with private salt"


def test_itch_dry_run_rejects_private_path_hardlinked_to_a_third_file(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"
    private_path = tmp_path / "dry-run.private.attest"
    third_path = tmp_path / "public-alias.attest"
    third_path.write_bytes(b"third file must not receive salts.json")
    os.link(third_path, private_path)

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)])

    stderr = capsys.readouterr().err
    assert rc == 2
    assert str(private_path.resolve()) in stderr
    assert "hard link" in stderr
    assert "salt-bearing" in stderr
    assert not out_path.exists()
    assert third_path.read_bytes() == b"third file must not receive salts.json"


def test_itch_dry_run_removes_new_shareable_when_private_write_fails(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"
    private_path = tmp_path / "dry-run.private.attest"
    real_write = cli._write_receipt_file_no_follow

    def fail_private_write(path: Path, data: bytes, *, ledger_path: Path) -> None:
        if path == private_path.resolve():
            raise ConfigError(f"cannot write receipt to {str(path)!r}: simulated private failure")
        real_write(path, data, ledger_path=ledger_path)

    monkeypatch.setattr(cli, "_write_receipt_file_no_follow", fail_private_write)

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)])

    assert rc == 2
    assert "simulated private failure" in capsys.readouterr().err
    assert not out_path.exists()
    assert not private_path.exists()


def test_itch_dry_run_default_does_not_construct_delivery(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)

    def exploding_delivery(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Delivery must not be constructed without --send-email")

    monkeypatch.setattr(cli, "Delivery", exploding_delivery)

    rc = cli.main(
        ["itch-dry-run", "--config", str(config_path), "--out", str(tmp_path / "d.attest")]
    )

    assert rc == 0


def test_itch_dry_run_uses_only_throwaway_ledger_instances(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    ledger_path = _ledger_path_of(config_path)
    opened: list[Path] = []
    real_ledger = cli.Ledger

    def recording_ledger(path: Path) -> Any:
        opened.append(Path(path))
        return real_ledger(path)

    monkeypatch.setattr(cli, "Ledger", recording_ledger)

    rc = cli.main(
        ["itch-dry-run", "--config", str(config_path), "--out", str(tmp_path / "d.attest")]
    )

    assert rc == 0
    assert opened
    resolved_ledger = ledger_path.resolve()
    assert all(path.resolve() != resolved_ledger for path in opened)


# -- itch-dry-run: fail-closed modes and SMTP opt-in ------------------------


def test_itch_dry_run_rc_2_without_itch_section(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(
        tmp_path, hybrid_keys, key_manifest, monkeypatch, extra_toml=""
    )

    assert cli.main(["itch-dry-run", "--config", str(config_path)]) == 2


def test_itch_dry_run_rc_2_when_catalog_has_no_itch_product(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(
        tmp_path, hybrid_keys, key_manifest, monkeypatch, products_toml=_PRICE_TEST_PRODUCT
    )

    assert cli.main(["itch-dry-run", "--config", str(config_path)]) == 2


def test_itch_dry_run_rc_2_on_unknown_game_id_names_what_exists(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--game-id", "999999"])

    assert rc == 2
    assert "itch_123456" in capsys.readouterr().err


def test_itch_dry_run_requires_game_id_when_config_maps_two_games(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(
        tmp_path,
        hybrid_keys,
        key_manifest,
        monkeypatch,
        products_toml=_ITCH_GAME_PRODUCT + _SECOND_ITCH_GAME_PRODUCT,
    )

    assert cli.main(["itch-dry-run", "--config", str(config_path)]) == 2
    assert (
        cli.main(
            [
                "itch-dry-run",
                "--config",
                str(config_path),
                "--game-id",
                "654321",
                "--out",
                str(tmp_path / "d.attest"),
            ]
        )
        == 0
    )


def test_itch_dry_run_email_without_send_email_is_rc_2(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `--email` is not a buyer-identity override, and refusing it says so.
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--email", "merchant@example.com"])

    assert rc == 2


def test_itch_dry_run_send_email_requires_explicit_recipient(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)

    assert cli.main(["itch-dry-run", "--config", str(config_path), "--send-email"]) == 2


def test_itch_dry_run_reports_actual_dead_letter_reason_when_issuance_fails(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"
    real_core = cli.IssuingCore

    def failing_core(**kwargs: Any) -> Any:
        core = real_core(**kwargs)

        def boom(purchase: object) -> None:
            raise RuntimeError("simulated signing failure")

        core.process = boom  # type: ignore[method-assign]
        return core

    monkeypatch.setattr(cli, "IssuingCore", failing_core)

    rc = cli.main(["itch-dry-run", "--config", str(config_path), "--out", str(out_path)])

    assert rc == 1
    stderr = capsys.readouterr().err
    assert "no receipt issued" in stderr
    # Not just "it failed": the merchant must read WHY.
    assert "simulated signing failure" in stderr
    assert not out_path.exists()


class _RecordingDelivery:
    sent: ClassVar[list[dict[str, Any]]] = []
    result: ClassVar[DeliveryResult] = DeliveryResult(status="sent", detail=None)

    legal_texts: ClassVar[dict[str, bytes]] = {}

    def __init__(self, config: Any, *, legal_texts: dict[str, bytes] | None = None) -> None:
        self.config = config
        # Recorded so the command is shown to hand delivery the verified
        # licence texts, not an empty map that would fail every bundle build.
        _RecordingDelivery.legal_texts = dict(legal_texts or {})

    def send(self, **kwargs: Any) -> DeliveryResult:
        _RecordingDelivery.sent.append(kwargs)
        return _RecordingDelivery.result


def test_itch_dry_run_send_email_delivers_to_recipient_not_signed_buyer(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    trust_store: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"
    _RecordingDelivery.sent = []
    _RecordingDelivery.result = DeliveryResult(status="sent", detail=None)
    monkeypatch.setattr(cli, "Delivery", _RecordingDelivery)

    rc = cli.main(
        [
            "itch-dry-run",
            "--config",
            str(config_path),
            "--out",
            str(out_path),
            "--send-email",
            "--email",
            "merchant@example.com",
        ]
    )

    assert rc == 0
    assert len(_RecordingDelivery.sent) == 1
    assert _RecordingDelivery.sent[0]["to_email"] == "merchant@example.com"
    # The dry run must hand delivery the licence text the config verified, or
    # the bundle it ships to the merchant could never be built.
    assert _RecordingDelivery.legal_texts == {LEGAL_TEXT_SHA256: LEGAL_TEXT}

    # The SMTP recipient is not the signed identity: the receipt still commits
    # to the synthetic `.invalid` buyer. Read back through the pair, which is
    # what the dry run now writes.
    receipt, salt, _ = _dry_run_pair(out_path, tmp_path / "dry-run.private.attest")
    receipt_bytes = json.dumps(receipt).encode("utf-8")
    assert (
        verify_mod.verify(
            receipt_bytes,
            trust_store,
            disclosure=verify_mod.Disclosure(
                identifier=cli._DRY_RUN_BUYER_EMAIL, identifier_type="email", salt=salt
            ),
        ).binding
        == "proven"
    )
    assert (
        verify_mod.verify(
            receipt_bytes,
            trust_store,
            disclosure=verify_mod.Disclosure(
                identifier="merchant@example.com", identifier_type="email", salt=salt
            ),
        ).binding
        == "not_proven"
    )


def test_itch_dry_run_send_email_failure_is_rc_1_but_receipt_file_survives(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    trust_store: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _write_itch_dry_run_config(tmp_path, hybrid_keys, key_manifest, monkeypatch)
    out_path = tmp_path / "dry-run.attest"
    _RecordingDelivery.sent = []
    _RecordingDelivery.result = DeliveryResult(status="failed", detail="smtp auth failed")
    monkeypatch.setattr(cli, "Delivery", _RecordingDelivery)

    rc = cli.main(
        [
            "itch-dry-run",
            "--config",
            str(config_path),
            "--out",
            str(out_path),
            "--send-email",
            "--email",
            "merchant@example.com",
        ]
    )

    assert rc == 1
    assert "email: FAILED (smtp auth failed)" in capsys.readouterr().out
    # A failed SMTP test must not cost the merchant the receipt they just
    # proved — and that receipt is two files now, not one.
    private_path = tmp_path / "dry-run.private.attest"
    assert out_path.exists()
    assert private_path.exists()
    receipt, _, _ = _dry_run_pair(out_path, private_path)
    assert verify_mod.verify(json.dumps(receipt).encode("utf-8"), trust_store).ok is True


# -- itch-dry-run: docs and OI-4 wording -----------------------------------


def test_setup_itch_docs_include_local_dry_run_before_live_test() -> None:
    text = (Path(__file__).parents[1] / "docs" / "setup-itch.md").read_text(encoding="utf-8")

    dry_run_heading = text.index("## 4. Dry run")
    live_heading = text.index("## 5. Test it live")
    assert dry_run_heading < live_heading

    assert "attest-bridge itch-dry-run --config bridge.toml" in text
    assert "--send-email --email" in text
    assert cli._DRY_RUN_BUYER_EMAIL in text
    # The guide must not let a merchant read the dry run as proof of their key.
    assert "ITCH_API_KEY" in text[dry_run_heading:live_heading]


def test_itch_adapter_docstring_names_dry_run_without_weakening_live_serve() -> None:
    from attest_bridge import itch_adapter

    doc = itch_adapter.__doc__ or ""
    assert "itch-dry-run" in doc
    assert "http_get" in doc
    assert "production `serve`" in doc
    # The live-API sole-authority statement must survive, scoped to production.
    assert "SOLE ISSUANCE AUTHORITY" in doc


def test_cli_docstring_names_itch_dry_run_as_throwaway_ledger_command() -> None:
    doc = cli.__doc__ or ""
    assert "itch-dry-run" in doc
    assert "throwaway Ledger" in doc
    assert "does NOT use `_build_deps`" in doc


# -- setup guides: legal_text_path and the §14.1/§14.2 bundle pair ---------


@pytest.mark.parametrize("guide_name", ["setup-stripe.md", "setup-itch.md", "setup-shopify.md"])
def test_setup_guides_document_legal_text_path_and_bundle_delivery(guide_name: str) -> None:
    text = (Path(__file__).parents[1] / "docs" / guide_name).read_text(encoding="utf-8")

    # The config field a merchant now has to set, and the fail-closed
    # consequence of leaving it out.
    assert "legal_text_path" in text
    assert "legal_text_sha256" in text
    lowered = text.lower()
    assert "won't start" in lowered or "does not start" in lowered or "never starts" in lowered

    # The two-attachment bundle pair, and which one is the buyer's secret.
    assert ".private.attest" in text
    assert "shareable" in lowered or "share" in lowered
    assert "secret" in lowered


def test_example_config_declares_legal_text_path() -> None:
    text = (Path(__file__).parents[1] / "examples" / "bridge.toml").read_text(encoding="utf-8")

    products_section = text[text.index("[products.") :]
    assert "legal_text_path" in products_section

    delivery_section = text[text.index("[delivery]") : text.index("[products.")]
    assert "info_url" in delivery_section
    assert "optional" in delivery_section.lower()
