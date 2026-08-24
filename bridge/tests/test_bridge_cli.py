"""CLI tests: `check-config` and `retry-failed`.

`check-config` is exercised against a real `bridge.toml` pointing at real T3
key/manifest files (the exact on-disk shapes `attest keygen`/`manifest init`
write) — a passing test here is evidence the whole config -> issuer ->
catalog chain works end to end, not just that `ConfigError` propagates from
a synthetic stand-in.
"""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from attest_bridge import cli
from attest_bridge.catalog import ProductCatalog, ProductTemplate
from attest_bridge.itch_adapter import ItchAdapter, ItchApiError
from attest_bridge.ledger import Ledger
from attest_bridge.model import ConfigError
from conftest import DISPLAY_NAME, ISSUER, KID
from test_bridge_stripe_adapter import make_session_completed_event

from attest import keys, pq

_STRIPE_ENV_VAR = "STRIPE_WEBHOOK_SECRET_T8_CLI_TEST"  # env var NAME, not a secret
_LEGAL_TEXT_SHA256 = "0" * 64

_PRICE_TEST_PRODUCT = f"""
[products.price_TEST]
title = "Stardrift Chronicles"
publisher = "Example Games Store"
artifact_series = "merchant.example.com/works/stardrift-chronicles"
terms_uri = "https://merchant.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{_LEGAL_TEXT_SHA256}"
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
legal_text_sha256 = "{_LEGAL_TEXT_SHA256}"
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
    config_path.write_text(config_text, encoding="utf-8")
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
    invalid = _PRICE_TEST_PRODUCT.replace(_LEGAL_TEXT_SHA256, "x")

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
    assert "price_TEST" in capsys.readouterr().err


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
                legal_text_sha256=_LEGAL_TEXT_SHA256,
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
        cli._write_receipt_file_no_follow(link, b"replacement")

    assert target.read_bytes() == b"original"


def test_write_receipt_file_no_follow_writes_mode_0600(tmp_path: Path) -> None:
    out = tmp_path / "receipt.attest"
    cli._write_receipt_file_no_follow(out, b"envelope")

    assert out.read_bytes() == b"envelope"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
