"""The HTTP surface of the reference witness: stdlib WSGI, no framework.

Contract: route two endpoints, bound the request body, and translate the
service's typed refusals into the statuses C2SP tlog-witness assigns them.
This module makes NO protocol decisions of its own — every status it returns
was decided in `service.py`, which is what lets the protocol be tested without
a socket.

    POST <submission-prefix>/add-checkpoint
    GET  <monitoring-prefix>/<sha256(origin) in lowercase hex>/checkpoint

The status table, from the C2SP specification:

    200  every check passed; the body is our signature lines
    400  malformed body, or an old size beyond the checkpoint's tree size
    403  no signature verifies against the trusted log key
    404  unknown checkpoint origin
    409  old size mismatch, or a different checkpoint at an equal size.
         The body is the tree size we hold, in decimal, with the media type
         `text/x.tlog.size` — a client resynchronises from it in one round
         trip, which is the whole reason the number is in the response.
    422  the consistency proof does not verify

Two things this deliberately does NOT do. It adds no authentication beyond the
pinned log signatures the protocol already requires — a witness's audience is
"anyone with a valid checkpoint", and inventing a second gate would break
interoperability while protecting nothing. And it never echoes any part of a
request back: the diagnostics are fixed strings, so this endpoint cannot be
used as a reflector.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Final

from attest_witness.config import WitnessConfig
from attest_witness.service import Conflict, ProtocolError, WitnessService

WSGIApp = Callable[[dict[str, Any], Callable[..., Any]], Iterable[bytes]]

_PLAIN: Final = "text/plain; charset=utf-8"
# C2SP tlog-witness names this media type for the 409 body.
_TLOG_SIZE: Final = "text/x.tlog.size"
_STATUS_TEXT: Final = {
    200: "200 OK",
    400: "400 Bad Request",
    403: "403 Forbidden",
    404: "404 Not Found",
    405: "405 Method Not Allowed",
    411: "411 Length Required",
    409: "409 Conflict",
    413: "413 Payload Too Large",
    422: "422 Unprocessable Entity",
    500: "500 Internal Server Error",
}


def _response(
    start_response: Callable[..., Any],
    status: int,
    body: bytes,
    *,
    content_type: str = _PLAIN,
    extra_headers: list[tuple[str, str]] | None = None,
) -> list[bytes]:
    headers = [("Content-Type", content_type), ("Content-Length", str(len(body)))]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(_STATUS_TEXT[status], headers)
    return [body]


def _read_body(environ: dict[str, Any], limit: int) -> bytes:
    """Read exactly `CONTENT_LENGTH` bytes, refusing anything past `limit`.

    Exactly, not "up to": on a real server `wsgi.input` is the connection
    itself, and a keep-alive client sends no EOF — so reading one byte more
    than was declared blocks until the socket times out. That is not a
    theoretical concern; it is what an in-process test with a BytesIO cannot
    see, and what the end-to-end test over a socket found.

    A missing or non-decimal length is refused (411) rather than treated as
    zero: with no length there is no way to know where this request's body
    ends, and guessing is how a request smuggling bug starts. A body shorter
    than declared is refused too — the client stopped mid-request.
    """
    declared = environ.get("CONTENT_LENGTH", "")
    if not isinstance(declared, str) or not declared.isdigit():
        raise _LengthRequired
    length = int(declared)
    if length > limit:
        raise _TooLarge
    stream = environ.get("wsgi.input")
    if stream is None:
        return b""
    body: bytes = stream.read(length)
    if len(body) != length:
        raise _Truncated
    return body


class _LengthRequired(Exception):
    """The request declared no usable Content-Length."""


class _Truncated(Exception):
    """The client sent fewer bytes than it declared."""


class _TooLarge(Exception):
    """The request body exceeds the configured bound."""


def make_app(service: WitnessService, config: WitnessConfig) -> WSGIApp:
    submission_path = f"{config.server.submission_prefix}/add-checkpoint"
    monitoring_prefix = config.server.monitoring_prefix
    limit = config.server.max_request_bytes

    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")

        if path == submission_path:
            if method != "POST":
                return _response(
                    start_response,
                    405,
                    b"method not allowed\n",
                    extra_headers=[("Allow", "POST")],
                )
            try:
                body = _read_body(environ, limit)
            except _TooLarge:
                return _response(start_response, 413, b"request body too large\n")
            except _LengthRequired:
                return _response(start_response, 411, b"content-length required\n")
            except _Truncated:
                return _response(start_response, 400, b"request body is shorter than declared\n")
            try:
                lines = service.add_checkpoint(body)
            except Conflict as exc:
                # The size, and nothing else: this body has a media type of
                # its own precisely so a client can parse it without guessing.
                return _response(
                    start_response,
                    409,
                    f"{exc.stored_size}\n".encode(),
                    content_type=_TLOG_SIZE,
                )
            except ProtocolError as exc:
                return _response(start_response, exc.status, f"{exc}\n".encode())
            return _response(start_response, 200, lines.encode("utf-8"))

        monitored = _monitoring_target(path, monitoring_prefix)
        if monitored is not None:
            if method != "GET":
                return _response(
                    start_response,
                    405,
                    b"method not allowed\n",
                    extra_headers=[("Allow", "GET")],
                )
            try:
                text = service.monitoring(monitored)
            except ProtocolError as exc:
                return _response(start_response, exc.status, f"{exc}\n".encode())
            return _response(start_response, 200, text.encode("utf-8"))

        return _response(start_response, 404, b"not found\n")

    return app


def _monitoring_target(path: str, prefix: str) -> str | None:
    """The hashed origin in `<prefix>/<hash>/checkpoint`, or None.

    The shape is checked here rather than in the service: a path that is not
    this shape is not a monitoring request at all, and should 404 as an
    unknown route rather than reach the lookup.
    """
    if not path.startswith(prefix + "/") or not path.endswith("/checkpoint"):
        return None
    middle = path[len(prefix) + 1 : -len("/checkpoint")]
    if not middle or "/" in middle:
        # Defence in depth: a segment containing a slash could never match a
        # hex digest, so the lookup would refuse it anyway. Refusing it as a
        # ROUTE keeps "what is a monitoring request" answerable without
        # knowing what is configured.
        return None
    return middle
