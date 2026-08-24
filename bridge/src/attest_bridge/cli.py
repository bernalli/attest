"""attest-bridge CLI: `serve`, `check-config`, `retry-failed`, `itch-import`.

`check-config` deliberately stops at config + issuer + catalog validation —
it never touches the Ledger (no sqlite file is created just to validate a
config) and never contacts a platform. `serve`/`retry-failed`/`itch-import`
need the full runtime (Ledger, Delivery, IssuingCore, the platform adapters),
assembled by `_build_deps`. `serve` additionally starts the itch
`ItchPoller` on its own daemon thread when `[itch]` is configured (T9) — see
`itch_adapter.py`'s module docstring for why that poller, not this CLI's
`itch-import` or `http.py`'s `/itch/claim`, is the only code path that can
ever issue an itch receipt.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import socketserver
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from attest import issue, validate
from attest_bridge.catalog import ProductCatalog, ProductTemplate
from attest_bridge.config import load_config
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import DELIVERY_SWEEP_SECONDS, Delivery, sweep_undelivered
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.itch_adapter import ItchAdapter, ItchPoller
from attest_bridge.ledger import Ledger
from attest_bridge.model import ClaimQueueFull, ConfigError
from attest_bridge.shopify_adapter import ShopifyAdapter
from attest_bridge.signing import load_issuer
from attest_bridge.stripe_adapter import StripeAdapter

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
_RC_OK = 0
_RC_CONFIG_ERROR = 2
_RC_INCOMPLETE = 1

_TOKEN_PATH_RE = re.compile(r"/r/[^ /?]+")
_SESSION_CAPABILITY_RE = re.compile(r"([?&]session_id=)[^&\s]+")


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime(_RFC3339)


def _redact_tokens(text: str) -> str:
    """Redact receipt capabilities from access logs after URL-decoding keys."""
    decoded = unquote(text)
    return _SESSION_CAPABILITY_RE.sub(r"\1<redacted>", _TOKEN_PATH_RE.sub("/r/<redacted>", decoded))


class _SanitizedRequestHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        redacted = tuple(_redact_tokens(a) if isinstance(a, str) else a for a in args)
        super().log_message(format, *redacted)


class _ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
    """WSGI server that dispatches each request to its own thread.

    Concurrency rests on TWO distinct, both-load-bearing locks — do not remove
    either:
    1. `Ledger` (T4) serializes every individual access — reads and writes
       alike — under its own connection lock, so no single statement races.
    2. `make_app` (`http.py`) holds a per-app lock across the webhook
       check-then-act critical section (`seen_event` -> issue/record ->
       deliver -> `mark_event`). The Ledger lock makes each statement atomic
       but NOT that whole workflow, so without this second lock two concurrent
       deliveries of the same event would both pass `seen_event` and
       double-issue / double-deliver.

    The itch `ItchPoller` (T9), when running, adds a THIRD thread (its own
    daemon thread, started in `_cmd_serve`) but needs no additional lock:
    it is the only code path that ever processes `platform="itch"`
    purchases (no itch webhook exists), so it can never race the webhook
    lock above, which only ever guards webhook-delivered work — today
    `platform="stripe"` and `platform="shopify"`. All three platforms are
    disjoint in the Ledger's `(platform, purchase_id)` key space, and the two
    webhook rails share the single app lock, so they serialize against each
    other as well. See `itch_adapter.py`'s `ItchPoller` docstring for the full
    argument.
    """

    daemon_threads = True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attest-bridge")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_parser = sub.add_parser("serve", help="run the webhook bridge")
    serve_parser.add_argument("--config", required=True)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8080)

    check_parser = sub.add_parser("check-config", help="validate config, keys, and catalog")
    check_parser.add_argument("--config", required=True)

    retry_parser = sub.add_parser("retry-failed", help="re-drive unresolved dead letters")
    retry_parser.add_argument("--config", required=True)

    itch_import_parser = sub.add_parser(
        "itch-import", help="CSV backfill: enqueue itch claims for a merchant's buyer list"
    )
    itch_import_parser.add_argument("--config", required=True)
    itch_import_parser.add_argument("--game-id", required=True)
    itch_import_parser.add_argument("csv_path")

    return parser


def _build_deps(config_path: Path, *, log: logging.Logger) -> BridgeDeps:
    """Assemble the full runtime: config, issuer, ledger, delivery, core, adapters.

    Raises `ConfigError` fail-fast — never partially wires a bridge with a
    bad key or missing secret.
    """
    config = load_config(config_path)
    issuer = load_issuer(config.issuer)
    catalog = ProductCatalog(config.products)
    ledger = Ledger(config.ledger_path)
    delivery = Delivery(config.delivery)
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer,
        ledger=ledger,
        public_base_url=config.public_base_url,
        delivery=delivery,
    )
    stripe = (
        StripeAdapter(webhook_secret=config.stripe.webhook_secret, api_key=config.stripe.api_key)
        if config.stripe is not None
        else None
    )
    shopify = (
        ShopifyAdapter(webhook_secret=config.shopify.webhook_secret)
        if config.shopify is not None
        else None
    )
    itch = ItchAdapter(api_key=config.itch.api_key) if config.itch is not None else None
    return BridgeDeps(
        config=config,
        core=core,
        ledger=ledger,
        stripe=stripe,
        log=log,
        itch=itch,
        delivery=delivery,
        shopify=shopify,
    )


def _catalog_payload_errors(key: str, template: ProductTemplate) -> list[str]:
    """Validate one product through the same payload builder/schema as issuance."""
    payload = issue.build_payload(
        attest_version="0.2",
        issuer_id="check-config.invalid",
        display_name="check-config",
        buyer_identifier="buyer@example.invalid",
        buyer_identifier_type="email",
        buyer_salt=b"\x00" * 16,
        title=template.title,
        publisher=template.publisher,
        identifiers=dict(template.identifiers),
        artifact_series=template.artifact_series,
        terms_uri=template.terms_uri,
        legal_text_sha256=template.legal_text_sha256,
        grant=template.grant,
        revocability=template.revocability,
        revocation_window_days=template.revocation_window_days,
        drm=template.drm,
        edition=template.edition,
        issued_at="2026-01-01T00:00:00Z",
    )
    return validate.validate_payload(payload)


def _sweep_deliveries(deps: BridgeDeps) -> tuple[int, int]:
    """Run the shared, crash-tolerant at-least-once delivery retry sweep."""
    delivery = deps.delivery if deps.delivery is not None else Delivery(deps.config.delivery)
    return sweep_undelivered(
        ledger=deps.ledger, delivery=delivery, public_base_url=deps.config.public_base_url
    )


def _run_delivery_sweeper(stop: threading.Event, deps: BridgeDeps, log: logging.Logger) -> None:
    """Keep retry delivery alive even if an iteration unexpectedly raises."""
    while not stop.is_set():
        try:
            _sweep_deliveries(deps)
        except Exception:
            log.exception("delivery sweep failed; continuing")
        stop.wait(DELIVERY_SWEEP_SECONDS)


def _cmd_serve(args: argparse.Namespace) -> int:
    log = logging.getLogger("attest_bridge")
    logging.basicConfig(level=logging.INFO)
    try:
        deps = _build_deps(Path(args.config), log=log)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    app = make_app(deps)
    host: str = args.host
    port: int = args.port

    # itch has no webhook (see itch_adapter.py) -- when [itch] is configured,
    # the ONLY thing that ever drains its claim queue is this single daemon
    # thread's ItchPoller, ticking against the live API on its own schedule.
    stop_event = threading.Event()
    poller_thread: threading.Thread | None = None
    sweeper_thread: threading.Thread | None = None
    if deps.config.delivery is not None:
        sweeper_thread = threading.Thread(
            target=_run_delivery_sweeper,
            args=(stop_event, deps, log),
            daemon=True,
            name="delivery-sweeper",
        )
        sweeper_thread.start()
        log.info("delivery sweeper started (interval=%ds)", DELIVERY_SWEEP_SECONDS)
    if deps.itch is not None and deps.config.itch is not None:
        poller = ItchPoller(
            adapter=deps.itch,
            ledger=deps.ledger,
            core=deps.core,
            max_attempts=deps.config.itch.max_attempts,
        )
        poller_thread = threading.Thread(
            target=poller.run_forever,
            args=(stop_event, deps.config.itch.poll_interval_seconds),
            daemon=True,
            name="itch-poller",
        )
        poller_thread.start()
        log.info(
            "itch poller started (interval=%ds, max_attempts=%d)",
            deps.config.itch.poll_interval_seconds,
            deps.config.itch.max_attempts,
        )

    try:
        with make_server(
            host,
            port,
            app,
            server_class=_ThreadingWSGIServer,
            handler_class=_SanitizedRequestHandler,
        ) as httpd:
            log.info("attest-bridge serving on %s:%d", host, port)
            httpd.serve_forever()
    finally:
        stop_event.set()
        if poller_thread is not None:
            poller_thread.join(timeout=5)
        if sweeper_thread is not None:
            sweeper_thread.join(timeout=5)
    return _RC_OK


def _cmd_check_config(args: argparse.Namespace) -> int:
    try:
        config = load_config(Path(args.config))
        issuer = load_issuer(config.issuer)
        catalog = ProductCatalog(config.products)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    product_errors = {
        key: _catalog_payload_errors(key, config.products[key]) for key in catalog.keys()
    }
    failed = {key: errors for key, errors in product_errors.items() if errors}
    if failed:
        for key, errors in failed.items():
            print(f"config error: product {key}: {'; '.join(errors)}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    print(f"issuer: {issuer.issuer_id} (kid={issuer.kid})")
    print(f"public_base_url: {config.public_base_url}")
    print(f"products: {', '.join(catalog.keys()) or '(none)'}")
    print(f"stripe: {'configured' if config.stripe is not None else 'not configured'}")
    print(f"shopify: {'configured' if config.shopify is not None else 'not configured'}")
    print(f"itch: {'configured' if config.itch is not None else 'not configured'}")
    print(f"delivery: {'smtp' if config.delivery is not None else 'download-link-only'}")
    return _RC_OK


def _cmd_retry_failed(args: argparse.Namespace) -> int:
    log = logging.getLogger("attest_bridge")
    try:
        deps = _build_deps(Path(args.config), log=log)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    resolved = 0
    for dead_letter in deps.ledger.unresolved_dead_letters():
        if dead_letter.platform == "itch":
            try:
                data = json.loads(dead_letter.raw_json)
                claim = data.get("claim", data) if isinstance(data, dict) else None
                email = claim.get("email") if isinstance(claim, dict) else None
                game_id = claim.get("game_id") if isinstance(claim, dict) else None
                if deps.itch is None or not isinstance(email, str) or not isinstance(game_id, str):
                    raise ValueError("itch dead letter has no re-enqueueable claim")
                deps.ledger.enqueue_claim(email, game_id, now=_now_rfc3339())
            except Exception as exc:
                log.warning(
                    "retry-failed: itch dead letter %d still failing: %s", dead_letter.id, exc
                )
                continue
            deps.ledger.resolve_dead_letter(dead_letter.id, now=_now_rfc3339())
            resolved += 1
            continue
        if dead_letter.platform != "stripe" or deps.stripe is None:
            log.warning(
                "retry-failed: dead letter %d has no configured recovery path", dead_letter.id
            )
            continue
        try:
            event = json.loads(dead_letter.raw_json)
            if not deps.stripe.wants(event):
                deps.log.info(
                    "retry-failed: stripe dead letter %d is not actionable", dead_letter.id
                )
                deps.ledger.resolve_dead_letter(dead_letter.id, now=_now_rfc3339())
                resolved += 1
                continue
            purchase = deps.stripe.normalize(event)
            deps.core.process(purchase)
        except Exception:  # still bad input, or a transient failure — leave unresolved
            log.warning("retry-failed: dead letter %d still failing", dead_letter.id)
            continue
        deps.ledger.resolve_dead_letter(dead_letter.id, now=_now_rfc3339())
        resolved += 1

    delivered, delivery_failures = _sweep_deliveries(deps)
    unresolved = len(deps.ledger.unresolved_dead_letters())
    # Download-link-only deployments deliberately leave `delivered_at` NULL:
    # their receipt capability is the delivery, not an unresolved SMTP task.
    undelivered = len(deps.ledger.undelivered()) if deps.config.delivery is not None else 0
    print(
        f"resolved: {resolved}, unresolved: {unresolved}, deliveries retried: {delivered}, "
        f"delivery failures: {delivery_failures}, undelivered: {undelivered}"
    )
    return _RC_OK if unresolved == 0 and undelivered == 0 else _RC_INCOMPLETE


def _cmd_itch_import(args: argparse.Namespace) -> int:
    """CSV backfill: enqueue an itch claim per unique buyer email.

    OI-4: intake is never issuance — this command only ever calls
    `Ledger.enqueue_claim`. Actual issuance still requires
    `ItchPoller.tick` to confirm each purchase against the live itch API
    (T9's `ItchAdapter.fetch_purchases`), same as a buyer-submitted claim.
    """
    log = logging.getLogger("attest_bridge")
    try:
        deps = _build_deps(Path(args.config), log=log)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    csv_path = Path(args.csv_path)
    try:
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            fieldnames = reader.fieldnames or []
            email_field = next(
                (name for name in fieldnames if name.strip().lower() == "email"), None
            )
            if email_field is None:
                print("itch-import: CSV has no 'email' column", file=sys.stderr)
                return _RC_CONFIG_ERROR

            now = _now_rfc3339()
            seen_emails: set[str] = set()
            enqueued = 0
            for row in reader:
                email = (row.get(email_field) or "").strip()
                if not email or email in seen_emails:
                    continue
                seen_emails.add(email)
                try:
                    deps.ledger.enqueue_claim(email, args.game_id, now=now)
                except ClaimQueueFull:
                    print(
                        f"itch-import: imported: {enqueued}; queue is full",
                        file=sys.stderr,
                    )
                    return _RC_CONFIG_ERROR
                enqueued += 1
    except OSError as exc:
        print(f"itch-import: cannot read {csv_path}: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    print(f"enqueued: {enqueued}")
    return _RC_OK


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "check-config":
        return _cmd_check_config(args)
    if args.command == "retry-failed":
        return _cmd_retry_failed(args)
    if args.command == "itch-import":
        return _cmd_itch_import(args)
    parser.error(
        f"unknown command: {args.command}"
    )  # pragma: no cover - argparse exits before this
    return _RC_CONFIG_ERROR  # pragma: no cover - unreachable, parser.error raises SystemExit
