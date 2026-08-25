"""attest-bridge CLI: `serve`, `check-config`, `retry-failed`, `itch-import`,
`itch-dry-run`.

`check-config` deliberately stops at config + issuer + catalog validation —
it never touches the Ledger (no sqlite file is created just to validate a
config) and never contacts a platform. `serve`/`retry-failed`/`itch-import`
need the full runtime (Ledger, Delivery, IssuingCore, the platform adapters),
assembled by `_build_deps`. `serve` additionally starts the itch
`ItchPoller` on its own daemon thread when `[itch]` is configured (T9) — see
`itch_adapter.py`'s module docstring for why that poller, not this CLI's
`itch-import` or `http.py`'s `/itch/claim`, is the only code path that can
ever issue an itch receipt.

`itch-dry-run` is the merchant's local pre-production test and deliberately
does NOT use `_build_deps`: `_build_deps` opens `config.ledger_path`, while
this command assembles its own throwaway Ledger in a temporary directory and
an in-process fake itch API injected through `ItchAdapter(http_get=...)`. It
signs with the real key, but the buyer identity it commits to is always the
reserved-TLD `itch-dry-run@example.invalid`.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import secrets
import socketserver
import stat
import sys
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from attest import bundle, issue, validate
from attest_bridge.catalog import ProductCatalog, ProductTemplate
from attest_bridge.config import load_config
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import DELIVERY_SWEEP_SECONDS, Delivery, sweep_undelivered
from attest_bridge.http import BridgeDeps, make_app
from attest_bridge.itch_adapter import ItchAdapter, ItchPoller
from attest_bridge.ledger import Ledger
from attest_bridge.model import ClaimQueueFull, ConfigError
from attest_bridge.pair import build_pair
from attest_bridge.shopify_adapter import ShopifyAdapter
from attest_bridge.signing import load_issuer
from attest_bridge.stripe_adapter import StripeAdapter

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
_RC_OK = 0
_SHAREABLE_SUFFIX = ".attest"
_PRIVATE_SUFFIX = ".private.attest"
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

    dry_run_parser = sub.add_parser(
        "itch-dry-run",
        help="local itch dry run: a real receipt from a fake API, in a throwaway Ledger",
    )
    dry_run_parser.add_argument("--config", required=True)
    dry_run_parser.add_argument("--game-id")
    dry_run_parser.add_argument("--send-email", action="store_true")
    dry_run_parser.add_argument("--email")
    dry_run_parser.add_argument("--out", default=_DRY_RUN_DEFAULT_OUT)

    return parser


# -- itch-dry-run helpers --------------------------------------------------
#
# A fixed, clearly-synthetic purchase id: real itch purchase ids are numeric,
# so a dry-run artifact is identifiable at a glance and can never collide with
# a real purchase in the `(platform, purchase_id)` key space.
_DRY_RUN_PURCHASE_ID = "itch-dry-run-1"
# Reserved TLD (RFC 2606): non-deliverable by construction. This is the buyer
# identity the receipt COMMITS TO, and it is not configurable — `--email` is
# only ever an SMTP recipient, never a signed identity.
_DRY_RUN_BUYER_EMAIL = "itch-dry-run@example.invalid"
_DRY_RUN_DEFAULT_OUT = "itch-dry-run-receipt.attest"
_ITCH_PRODUCT_PREFIX = "itch_"


def _resolve_itch_dry_run_product(catalog: ProductCatalog, game_id: str | None) -> str:
    """Pick which `[products.itch_<game_id>]` the dry run issues for.

    Never guesses: zero itch products, an unknown `--game-id`, or an ambiguous
    catalog without `--game-id` are all `ConfigError`, naming what exists.
    """
    itch_keys = [key for key in catalog.keys() if key.startswith(_ITCH_PRODUCT_PREFIX)]
    if not itch_keys:
        raise ConfigError(
            "no [products.itch_<game_id>] mapping in this config — "
            "the dry run issues for a real catalog entry, never a guessed one"
        )
    if game_id is not None:
        product_key = f"{_ITCH_PRODUCT_PREFIX}{game_id}"
        if product_key not in itch_keys:
            raise ConfigError(
                f"no product mapping for {product_key!r}; configured: {', '.join(itch_keys)}"
            )
        return product_key
    if len(itch_keys) > 1:
        raise ConfigError(f"--game-id is required: this config maps {', '.join(itch_keys)}")
    return itch_keys[0]


def _itch_dry_run_purchase(game_id: str, *, now: datetime) -> dict[str, Any]:
    """One synthetic itch purchase row, in the API's documented shape.

    `status` is `"settled"` on purpose: the poller skips only `refunded` and
    `canceled` (`itch_adapter._SKIP_STATUSES`), so this row must be one the
    real filter processes.
    """
    return {
        "id": _DRY_RUN_PURCHASE_ID,
        "game_id": game_id,
        "email": _DRY_RUN_BUYER_EMAIL,
        "status": "settled",
        "created_at": now.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        "price": "$0.00",
        "currency": "USD",
    }


def _dry_run_http_get(
    purchase: dict[str, Any], *, game_id: str, buyer_email: str, api_key: str
) -> Callable[[str, dict[str, str]], bytes]:
    """The in-process fake itch API, injected through `ItchAdapter(http_get=…)`.

    It validates the request instead of answering everything: a fake that
    returned the purchase for any URL would leave the happy path green even if
    the poller asked for the wrong game, the wrong buyer, or with the wrong
    key. `ItchAdapter.fetch_purchases` wraps whatever this raises in
    `ItchApiError`, exactly as a live non-200 response would be.
    """

    def http_get(url: str, headers: dict[str, str]) -> bytes:
        parsed = urlparse(url)
        if parsed.path != f"/games/{game_id}/purchases":
            raise ValueError(f"dry-run fake API: unexpected path {parsed.path!r}")
        if parse_qs(parsed.query).get("email") != [buyer_email]:
            raise ValueError("dry-run fake API: unexpected buyer email in query")
        if headers.get("Authorization") != f"Bearer {api_key}":
            raise ValueError("dry-run fake API: unexpected Authorization header")
        return json.dumps({"purchases": [purchase]}).encode("utf-8")

    return http_get


def _guard_dry_run_out_path(out_path: Path, *, ledger_path: Path) -> Path:
    """Refuse any `--out` that could clobber the merchant's production Ledger.

    Containment of the Ledger on the constructor side is not enough: the
    receipt writer opens `--out` for truncation, so a path that IS the ledger
    — or a symlink resolving to it — would destroy it.
    """
    resolved_out = out_path.expanduser().resolve(strict=False)
    resolved_ledger = ledger_path.expanduser().resolve(strict=False)
    if resolved_out == resolved_ledger:
        raise ConfigError(
            f"--out {str(out_path)!r} is the configured ledger_path — refusing to overwrite it"
        )
    if out_path.is_symlink():
        raise ConfigError(
            f"--out {str(out_path)!r} is a symlink — refusing to write the receipt through it"
        )
    if out_path.exists() and ledger_path.exists() and out_path.samefile(ledger_path):
        raise ConfigError(
            f"--out {str(out_path)!r} is the same file as ledger_path — refusing to overwrite it"
        )
    return resolved_out


def _guard_dry_run_out_pair(out_path: Path, private_path: Path) -> None:
    """Refuse output pairs whose filesystem aliases could hide the private half."""
    if out_path.exists() and private_path.exists():
        try:
            same_output_file = out_path.samefile(private_path)
        except OSError as exc:
            raise ConfigError(
                f"cannot compare --out {str(out_path)!r} with derived private path "
                f"{str(private_path)!r}: {exc}"
            ) from exc
        if same_output_file:
            raise ConfigError(
                f"--out {str(out_path)!r} and derived private path {str(private_path)!r} "
                "are the same file — refusing to write the salt-bearing private bundle "
                "through the shareable path"
            )
    if private_path.exists():
        try:
            private_stat = private_path.stat()
        except OSError as exc:
            raise ConfigError(
                f"cannot inspect derived private path {str(private_path)!r}: {exc}"
            ) from exc
        if stat.S_ISREG(private_stat.st_mode) and private_stat.st_nlink > 1:
            raise ConfigError(
                f"derived private path {str(private_path)!r} has multiple hard links — "
                "refusing to write the salt-bearing private bundle through an aliased file"
            )


def _private_dry_run_out_path(out_path: Path) -> Path:
    """Derive the private half's path from `--out`, which names the SHAREABLE one.

    `foo.attest` -> `foo.private.attest`; a `--out` with no `.attest` suffix
    just gains one. A `--out` that ALREADY ends in `.private.attest` is
    refused rather than quietly renamed: the suffix is the only guard the web
    verifier has, and a run that produced `x.private.attest` (shareable) next
    to `x.private.private.attest` (secret) would invert exactly the signal the
    buyer is taught to read.
    """
    text = str(out_path)
    if text.endswith(_PRIVATE_SUFFIX):
        raise ConfigError(
            f"--out {text!r} ends in {_PRIVATE_SUFFIX} — that suffix names the private half, "
            "which this command derives on its own; pass the shareable path instead"
        )
    stem = text[: -len(_SHAREABLE_SUFFIX)] if text.endswith(_SHAREABLE_SUFFIX) else text
    return Path(stem + _PRIVATE_SUFFIX)


def _write_receipt_file_no_follow(path: Path, data: bytes) -> None:
    """Write the receipt at mode 0600 through a fresh temp file and an atomic rename.

    Predicates on the destination — is it a symlink, does it alias the other
    half, how many hard links does it have — all photograph an instant: an
    adversary who can write in the output directory reorganises the names
    after the last syscall that could have checked them. So this writer never
    writes to the destination at all:
    1. `os.open` a `.<final-name>.<pid>.<random>.tmp` sibling with
       `O_CREAT|O_EXCL|O_NOFOLLOW` — the inode is fresh BY CONSTRUCTION, so it
       cannot be the Ledger, cannot be an alias of anything, and has exactly
       one link. Same directory, so the rename below stays within a filesystem;
    2. `fchmod` 0600 on the descriptor — `O_CREAT`'s mode argument is filtered
       by the umask, and the bytes about to land include `delivery.salt`, the
       buyer-binding secret, so the file must never be readable by anyone else,
       not even for an instant;
    3. write, flush, `fsync`, close;
    4. `os.rename` onto the final path: rename REPLACES the directory entry
       atomically and never writes THROUGH an existing one, so an alias planted
       by a third party is dropped, never fed.
    Any failure unlinks the temp file (best effort) and raises `ConfigError`.

    Declared residue: nothing here — nor any other write strategy — stops an
    adversary who can write in that directory from hard-linking the finished
    files at rest, afterwards, under any name of their choosing. The defences
    against that are the directory's own permissions (the setup guides call for
    `umask 077`) and the web verifier's by-CONTENT guard, which flags a
    salt-bearing bundle whatever name it arrives under.
    """
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:  # pragma: no cover - POSIX-only platforms in CI
        raise ConfigError("O_NOFOLLOW is unavailable on this platform — refusing to write")
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o600)
    except OSError as exc:
        raise ConfigError(
            f"cannot create the temporary file for receipt {str(path)!r}: {exc}"
        ) from exc
    try:
        try:
            os.fchmod(fd, 0o600)
            handle = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(temp_path, path)
    except OSError as exc:
        _unlink_quietly(temp_path)
        raise ConfigError(f"cannot write receipt to {str(path)!r}: {exc}") from exc
    except BaseException:
        _unlink_quietly(temp_path)
        raise


def _unlink_quietly(path: Path) -> None:
    """Drop a half-written temp file; a failure here must not mask the real error."""
    try:
        path.unlink()
    except OSError:
        pass


def _write_dry_run_pair_no_follow(
    out_path: Path,
    shareable: bytes,
    private_path: Path,
    private: bytes,
) -> None:
    """Write the shareable/private pair without leaving a newly created orphan half."""
    out_existed = out_path.exists()
    _write_receipt_file_no_follow(out_path, shareable)
    try:
        # The identity of what the rename just put there, so the cleanup below
        # removes THIS file and not whatever took its name in the meantime.
        out_stat = None if out_existed else os.lstat(out_path)
    except OSError as exc:
        raise ConfigError(
            f"cannot inspect the shareable receipt just written {str(out_path)!r}: {exc}"
        ) from exc
    try:
        _write_receipt_file_no_follow(private_path, private)
    except Exception as exc:
        if out_stat is not None:
            try:
                current: os.stat_result | None = os.lstat(out_path)
            except OSError:
                current = None
            if current is not None and (current.st_dev, current.st_ino) == (
                out_stat.st_dev,
                out_stat.st_ino,
            ):
                try:
                    out_path.unlink()
                except OSError as cleanup_exc:
                    raise ConfigError(
                        f"cannot remove incomplete shareable receipt {str(out_path)!r}: "
                        f"{cleanup_exc} (after the private write failed: {exc})"
                    ) from exc
        raise


def _build_deps(config_path: Path, *, log: logging.Logger) -> BridgeDeps:
    """Assemble the full runtime: config, issuer, ledger, delivery, core, adapters.

    Raises `ConfigError` fail-fast — never partially wires a bridge with a
    bad key or missing secret.
    """
    config = load_config(config_path)
    issuer = load_issuer(config.issuer)
    catalog = ProductCatalog(config.products)
    ledger = Ledger(config.ledger_path)
    delivery = Delivery(config.delivery, legal_texts=config.legal_texts)
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
    delivery = (
        deps.delivery
        if deps.delivery is not None
        else Delivery(deps.config.delivery, legal_texts=deps.config.legal_texts)
    )
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
        if dead_letter.platform == "shopify":
            # The stored `raw_json` is the whole signed order, so replay
            # re-drives the same `wants`/`normalize` path the webhook took —
            # no signature to re-verify, because the body was already
            # authenticated when it was stored.
            if deps.shopify is None:
                log.warning(
                    "retry-failed: shopify dead letter %d needs a [shopify] section to replay",
                    dead_letter.id,
                )
                continue
            try:
                order = json.loads(dead_letter.raw_json)
                if not deps.shopify.wants(order):
                    log.info(
                        "retry-failed: shopify dead letter %d is not actionable", dead_letter.id
                    )
                    deps.ledger.resolve_dead_letter(dead_letter.id, now=_now_rfc3339())
                    resolved += 1
                    continue
                deps.core.process(deps.shopify.normalize(order))
            except Exception:  # still bad input, or a transient failure — leave unresolved
                log.warning("retry-failed: shopify dead letter %d still failing", dead_letter.id)
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


def _cmd_itch_dry_run(args: argparse.Namespace) -> int:
    """Exercise the real itch chain locally: claim -> tick -> normalize ->
    sign -> record, against an in-process fake API and a throwaway Ledger.

    Deliberately does NOT use `_build_deps`, which would open the merchant's
    production Ledger. Nothing here ever constructs an object carrying
    `config.ledger_path`, and `--out` is refused if it could clobber it.
    """
    try:
        config = load_config(Path(args.config))
        if config.itch is None:
            raise ConfigError("this config has no [itch] section — nothing to dry-run")
        if args.email is not None and not args.send_email:
            raise ConfigError(
                "--email is only the SMTP recipient for --send-email; "
                "the signed buyer identity is always "
                f"{_DRY_RUN_BUYER_EMAIL} and cannot be overridden"
            )
        if args.send_email and args.email is None:
            raise ConfigError("--send-email requires an explicit --email <your-address>")
        issuer = load_issuer(config.issuer)
        catalog = ProductCatalog(config.products)
        product_key = _resolve_itch_dry_run_product(catalog, args.game_id)
        template = catalog.resolve(product_key)
        requested_out = Path(args.out)
        # Both paths get the same guard: the private one is DERIVED, so it
        # never passes under a guard on its own name, and a symlink planted
        # there would write the salt straight through to the Ledger.
        private_requested = _private_dry_run_out_path(requested_out)
        out_path = _guard_dry_run_out_path(requested_out, ledger_path=config.ledger_path)
        private_path = _guard_dry_run_out_path(private_requested, ledger_path=config.ledger_path)
        _guard_dry_run_out_pair(out_path, private_path)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return _RC_CONFIG_ERROR

    game_id = product_key.removeprefix(_ITCH_PRODUCT_PREFIX)
    now = datetime.now(UTC)
    # ONE clock read for the whole dry run. `enqueue_claim` used to take its
    # own, and between the two this function builds a Ledger — a file touch, a
    # connect, a schema script — so on a loaded machine the second read could
    # land in the next whole second. `next_attempt_at` would then sit one
    # second ahead of the `now` the poller queries with, `due_claims` would
    # return nothing, and the claim would never be drained: no receipt, and no
    # dead letter either, because nothing entered the loop that records one.
    # ledger.py's own contract says timestamps are caller-supplied and it never
    # reads a clock; supplying two unsynchronized ones broke that from here.
    now_rfc3339 = now.strftime(_RFC3339)
    with tempfile.TemporaryDirectory() as tmp_dir:
        ledger = Ledger(Path(tmp_dir) / "dry-run-ledger.sqlite3")
        token = ledger.enqueue_claim(_DRY_RUN_BUYER_EMAIL, game_id, now=now_rfc3339)
        purchase = _itch_dry_run_purchase(game_id, now=now)
        adapter = ItchAdapter(
            api_key=config.itch.api_key,
            http_get=_dry_run_http_get(
                purchase,
                game_id=game_id,
                buyer_email=_DRY_RUN_BUYER_EMAIL,
                api_key=config.itch.api_key,
            ),
        )
        core = IssuingCore(
            catalog=catalog,
            issuer=issuer,
            ledger=ledger,
            public_base_url=config.public_base_url,
            delivery=None,
        )
        ItchPoller(adapter=adapter, ledger=ledger, core=core, max_attempts=1).tick(now=now)

        stored = ledger.get_receipt("itch", _DRY_RUN_PURCHASE_ID)
        if stored is None:
            print("no receipt issued", file=sys.stderr)
            for dead_letter in ledger.unresolved_dead_letters():
                print(f"  reason: {dead_letter.reason}", file=sys.stderr)
            return _RC_INCOMPLETE

        try:
            # `config.legal_texts` is always populated (V-A.2 made
            # `legal_text_path` mandatory), so a BundleError here is a real
            # defect in the envelope, not a missing-config accident. Its
            # message is a hardcoded precondition string, never payload text.
            pair = build_pair(
                json.loads(stored.envelope_json), stored.receipt_id, config.legal_texts
            )
        except bundle.BundleError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return _RC_CONFIG_ERROR

        try:
            # Shareable first: if the second write fails, the wrapper removes
            # a newly created shareable half. Both go through the same 0600
            # temp-then-rename writer — stricter than the shareable half needs,
            # which is the safe direction to be wrong in.
            _write_dry_run_pair_no_follow(out_path, pair.shareable, private_path, pair.private)
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return _RC_CONFIG_ERROR

        rc = _RC_OK
        email_line = "email: skipped (re-run with --send-email --email <your-address> to test SMTP)"
        if args.send_email:
            # Delivery is driven from here, not through `core.process`: the core
            # sends to `stored.buyer_email`, which must stay the synthetic signed
            # identity. The SMTP recipient is a separate thing on purpose.
            result = Delivery(config.delivery, legal_texts=config.legal_texts).send(
                to_email=args.email,
                receipt_id=stored.receipt_id,
                work_title=template.title,
                envelope=json.loads(stored.envelope_json),
                download_url=f"{config.public_base_url}/r/{stored.download_token}",
                info_url=config.delivery.info_url if config.delivery is not None else None,
            )
            if result.status == "sent":
                ledger.mark_delivered("itch", _DRY_RUN_PURCHASE_ID, at=_now_rfc3339())
                email_line = (
                    f"email: sent to {args.email} (signed buyer remains {_DRY_RUN_BUYER_EMAIL})"
                )
            elif result.status == "failed":
                detail = result.detail if result.detail is not None else "delivery failed"
                ledger.record_delivery_failure("itch", _DRY_RUN_PURCHASE_ID, detail)
                email_line = f"email: FAILED ({detail}); receipt file kept"
                rc = _RC_INCOMPLETE
            else:
                email_line = f"email: skipped ({result.status})"

        claim = ledger.get_claim(token)
        issued = claim.receipts_issued if claim is not None else 0
        status = claim.status if claim is not None else "unknown"

        print(f"issuer: {issuer.issuer_id} (kid={issuer.kid})")
        print(f"product: {product_key} ({template.title})")
        print(f"buyer: {_DRY_RUN_BUYER_EMAIL} (signed synthetic identity)")
        print(f"claim: {status} (receipts issued: {issued})")
        print(f"receipt: {out_path} (mode 0600 - safe to share)")
        print(
            f"private: {private_path} (mode 0600 - carries the buyer-binding salt, never share it)"
        )
        print(email_line)
        print("ledger: throwaway, deleted on exit - the production Ledger was never opened")
        print("verify offline:")
        print(f"  attest import --bundle {out_path} --private {private_path} --out-dir ./imported")
        print(
            f"  attest verify ./imported/receipts/{stored.receipt_id}.attest.json "
            "--trust-dir ./imported/trust"
        )
    return rc


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
    if args.command == "itch-dry-run":
        return _cmd_itch_dry_run(args)
    parser.error(
        f"unknown command: {args.command}"
    )  # pragma: no cover - argparse exits before this
    return _RC_CONFIG_ERROR  # pragma: no cover - unreachable, parser.error raises SystemExit
