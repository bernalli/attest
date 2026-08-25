"""`attest-witness` — check a configuration, or serve the witness.

Two subcommands, deliberately:

    attest-witness check-config --config witness.toml
    attest-witness serve --config witness.toml [--host H] [--port P]

`check-config` exists because every failure this program can have that is
worth having is a configuration failure, and an operator should be able to
provoke it on purpose, at a moment of their choosing, rather than discover it
when a log submits its first checkpoint. Its output is safe to paste: key
material never reaches it (see `config.describe`).

`serve` binds to 127.0.0.1 by default. A witness signs with online keys, and
this reference implementation has no opinion about TLS, rate limiting or
authentication — the deployment in front of it does. Binding to localhost by
default means putting it on a network is a decision somebody has to type.
"""

from __future__ import annotations

import argparse
import socketserver
from pathlib import Path
from typing import Final
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from attest_witness.config import ConfigError, WitnessConfig, describe, load_config
from attest_witness.http import make_app
from attest_witness.service import WitnessService
from attest_witness.store import WitnessStore

_RC_OK: Final = 0
_RC_CONFIG_ERROR: Final = 2


class _QuietRequestHandler(WSGIRequestHandler):
    """No reverse DNS, and no request line echoed to the log.

    `WSGIRequestHandler.address_string()` resolves the client address for
    every access log line — work an unauthenticated caller can ask for, on a
    resolver this process does not control. The request line is dropped with
    it: it is client-controlled text, and an operator reading logs is exactly
    who a crafted path would be aimed at.
    """

    def address_string(self) -> str:
        return str(self.client_address[0])

    def log_message(self, format: str, *args: object) -> None:
        return None


class _ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
    """One thread per request.

    Safe because the state that matters is guarded twice over: the store holds
    one lock around its single connection, and `BEGIN IMMEDIATE` serialises
    the compare-and-advance even against another process sharing the database.
    """

    daemon_threads = True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attest-witness")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check-config", help="validate the configuration and print it")
    check.add_argument("--config", type=Path, required=True)

    serve = sub.add_parser("serve", help="serve the witness")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def _load(path: Path) -> WitnessConfig:
    return load_config(path)


def _cmd_check_config(args: argparse.Namespace) -> int:
    config = _load(args.config)
    print(describe(config))
    return _RC_OK


def _cmd_serve(args: argparse.Namespace) -> int:
    config = _load(args.config)
    store = WitnessStore(config.database_path)
    try:
        app = make_app(WitnessService(config, store), config)
        with make_server(
            args.host,
            args.port,
            app,
            server_class=_ThreadingWSGIServer,
            handler_class=_QuietRequestHandler,
        ) as httpd:
            print(
                f"attest-witness {config.identity.name} listening on "
                f"{args.host}:{args.port} for {len(config.logs)} log(s)"
            )
            httpd.serve_forever()
    finally:
        store.close()
    return _RC_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "check-config":
            return _cmd_check_config(args)
        return _cmd_serve(args)
    except ConfigError as exc:
        # The one failure mode an operator should see as a sentence rather
        # than a traceback.
        print(f"configuration error: {exc}")
        return _RC_CONFIG_ERROR
    except KeyboardInterrupt:
        return _RC_OK
