"""The HTTP surface: statuses, media types, bounds, routing.

The WSGI app is called in-process with a hand-built environ — no socket, no
server, no client library — which is the bridge's precedent and keeps these
tests about the protocol rather than about a networking stack.

The status codes are not ours to choose: every one of them is assigned by the
C2SP tlog-witness specification, and the 409's media type and body shape are
what a client needs to resynchronise. So they are pinned here literally.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest
from attest_witness.config import ServerConfig, WitnessConfig, WitnessIdentity
from attest_witness.http import make_app
from attest_witness.service import WitnessService, origin_hash
from attest_witness.store import WitnessStore
from witness_support import (
    WITNESS_NAME,
    FakeLog,
    log_keys,  # noqa: F401
    other_log_keys,  # noqa: F401
    witness_keys,  # noqa: F401
)

from attest import pq, tlog

ORIGIN = "log.example"
TIMESTAMP = 1_700_000_000
SUBMISSION = "/witness/v0/add-checkpoint"
MONITORING = "/witness/v0/monitoring"


def call_app(
    app: Any,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    content_length: str | None = None,
) -> tuple[str, dict[str, str], bytes]:
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    import io

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(body),
        "CONTENT_LENGTH": str(len(body)) if content_length is None else content_length,
    }
    chunks = app(environ, start_response)
    return captured["status"], captured["headers"], b"".join(chunks)


@pytest.fixture
def log(log_keys: pq.HybridSigningKeys) -> FakeLog:
    return FakeLog(ORIGIN, log_keys)


@pytest.fixture
def app(tmp_path: Path, witness_keys: pq.HybridSigningKeys, log: FakeLog) -> Any:
    config = WitnessConfig(
        identity=WitnessIdentity(name=WITNESS_NAME, signing_keys=witness_keys),
        server=ServerConfig(
            submission_prefix="/witness/v0",
            monitoring_prefix=MONITORING,
            max_request_bytes=65_536,
            max_proof_lines=63,
        ),
        database_path=tmp_path / "state.sqlite3",
        logs={ORIGIN: log.log_key},
    )
    service = WitnessService(
        config, WitnessStore(config.database_path), clock=lambda: float(TIMESTAMP)
    )
    return make_app(service, config)


def _body(old_size: int, proof: list[bytes], checkpoint_text: str) -> bytes:
    lines = [f"old {old_size}"]
    lines.extend(base64.b64encode(node).decode("ascii") for node in proof)
    return ("\n".join(lines) + "\n\n" + checkpoint_text).encode("utf-8")


def test_a_valid_submission_returns_200_and_the_signature_lines(app: Any, log: FakeLog) -> None:
    log.append(4)
    text = log.checkpoint_text()
    status, headers, body = call_app(app, "POST", SUBMISSION, body=_body(0, [], text))
    assert status == "200 OK"
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    assert headers["Content-Length"] == str(len(body))
    # Parsed by the core, not by eye: two lines under this witness's name.
    names = [name for name, _ in tlog.note_signatures(text + body.decode("utf-8"))]
    assert names.count(WITNESS_NAME) == 2


def test_a_malformed_body_is_400(app: Any) -> None:
    status, _, _ = call_app(app, "POST", SUBMISSION, body=b"nonsense")
    assert status == "400 Bad Request"


def test_an_unknown_origin_is_404(app: Any, other_log_keys: pq.HybridSigningKeys) -> None:
    stranger = FakeLog("stranger.example", other_log_keys)
    stranger.append(2)
    status, _, _ = call_app(app, "POST", SUBMISSION, body=_body(0, [], stranger.checkpoint_text()))
    assert status == "404 Not Found"


def test_an_unauthentic_checkpoint_is_403(app: Any, other_log_keys: pq.HybridSigningKeys) -> None:
    impostor = FakeLog(ORIGIN, other_log_keys)
    impostor.append(2)
    status, _, _ = call_app(app, "POST", SUBMISSION, body=_body(0, [], impostor.checkpoint_text()))
    assert status == "403 Forbidden"


def test_an_old_size_beyond_the_tree_size_is_400(app: Any, log: FakeLog) -> None:
    log.append(2)
    status, _, _ = call_app(app, "POST", SUBMISSION, body=_body(9, [], log.checkpoint_text()))
    assert status == "400 Bad Request"


def test_a_conflict_is_409_with_the_stored_size_and_its_media_type(app: Any, log: FakeLog) -> None:
    """The one response whose BODY a client is required to understand: it is
    the tree size we hold, in decimal, so a desynchronised client can retry
    correctly on its next attempt instead of guessing."""
    log.append(4)
    call_app(app, "POST", SUBMISSION, body=_body(0, [], log.checkpoint_text()))
    log.append(3)
    status, headers, body = call_app(
        app, "POST", SUBMISSION, body=_body(1, log.consistency_proof_from(4), log.checkpoint_text())
    )
    assert status == "409 Conflict"
    assert headers["Content-Type"] == "text/x.tlog.size"
    assert body == b"4\n"


def test_an_invalid_consistency_proof_is_422(app: Any, log: FakeLog) -> None:
    log.append(4)
    call_app(app, "POST", SUBMISSION, body=_body(0, [], log.checkpoint_text()))
    log.append(3)
    status, _, _ = call_app(
        app, "POST", SUBMISSION, body=_body(4, [bytes(32)], log.checkpoint_text())
    )
    assert status == "422 Unprocessable Entity"


def test_a_body_over_the_bound_is_413_and_is_never_parsed(app: Any) -> None:
    status, _, _ = call_app(app, "POST", SUBMISSION, body=b"old 0\n\n" + b"A" * 70_000)
    assert status == "413 Payload Too Large"


def test_only_the_declared_length_is_read(app: Any, log: FakeLog) -> None:
    """A client that understates Content-Length gets exactly what it declared
    parsed as its request — the rest is not this request's body and is not
    ours to interpret. Reading past the declared length is also what hangs a
    keep-alive connection until it times out.

    The body is a VALID submission truncated by the declared length, so the
    origin line still arrives and the request reaches the checkpoint parser:
    the 400 is the truncation being seen, not a bad body being rejected before
    anything was decided.
    """
    log.append(4)
    body = _body(0, [], log.checkpoint_text())
    status, _, _ = call_app(app, "POST", SUBMISSION, body=body, content_length=str(len(body) - 200))
    assert status == "400 Bad Request"


def test_a_declared_length_over_the_bound_is_413_before_a_byte_is_read(app: Any) -> None:
    status, _, _ = call_app(app, "POST", SUBMISSION, body=b"old 0\n\nx", content_length="999999")
    assert status == "413 Payload Too Large"


def test_a_body_shorter_than_declared_is_400(app: Any, log: FakeLog) -> None:
    """The body is an OTHERWISE VALID submission, sent with an inflated
    Content-Length. Without the length check it would be cosigned — 200 —
    which is why a malformed body cannot prove this: that one is refused
    either way, for the wrong reason."""
    log.append(4)
    body = _body(0, [], log.checkpoint_text())
    status, _, _ = call_app(app, "POST", SUBMISSION, body=body, content_length=str(len(body) + 100))
    assert status == "400 Bad Request"


def test_a_request_without_a_content_length_is_411(app: Any) -> None:
    """No length, no way to know where the body ends. Guessing zero would make
    every such request a silent no-op; guessing "read everything" is how a
    keep-alive connection hangs."""
    status, _, _ = call_app(app, "POST", SUBMISSION, body=b"old 0\n\nx", content_length="")
    assert status == "411 Length Required"


def test_get_on_the_submission_endpoint_is_405(app: Any) -> None:
    status, headers, _ = call_app(app, "GET", SUBMISSION)
    assert status == "405 Method Not Allowed"
    assert headers["Allow"] == "POST"


def test_monitoring_returns_the_cosigned_note(app: Any, log: FakeLog) -> None:
    log.append(4)
    text = log.checkpoint_text()
    _, _, lines = call_app(app, "POST", SUBMISSION, body=_body(0, [], text))
    status, headers, body = call_app(app, "GET", f"{MONITORING}/{origin_hash(ORIGIN)}/checkpoint")
    assert status == "200 OK"
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    assert body == text.encode("utf-8") + lines


def test_monitoring_for_an_unknown_hash_is_404(app: Any) -> None:
    status, _, _ = call_app(app, "GET", f"{MONITORING}/{origin_hash('nobody.example')}/checkpoint")
    assert status == "404 Not Found"


def test_post_on_the_monitoring_endpoint_is_405(app: Any) -> None:
    status, headers, _ = call_app(app, "POST", f"{MONITORING}/{origin_hash(ORIGIN)}/checkpoint")
    assert status == "405 Method Not Allowed"
    assert headers["Allow"] == "GET"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/witness/v0",
        "/witness/v0/add-checkpoints",
        f"{MONITORING}/{origin_hash(ORIGIN)}",
        f"{MONITORING}/{origin_hash(ORIGIN)}/checkpoint/extra",
        f"{MONITORING}//checkpoint",
        f"{MONITORING}/checkpoint",
    ],
)
def test_unrouted_paths_are_404(app: Any, path: str) -> None:
    status, _, _ = call_app(app, "GET", path)
    assert status == "404 Not Found"


def test_the_monitoring_suffix_must_be_exactly_checkpoint(app: Any, log: FakeLog) -> None:
    """Not "eleven characters at the end", which is what a suffix check
    written as arithmetic instead of a comparison degrades into: the route
    would then accept the hash followed by any eleven bytes and serve the log
    to a path nobody defined.

    A checkpoint has to be cosigned FIRST, or the service answers 404 for want
    of state and the test passes without ever reaching the routing decision it
    is about.
    """
    log.append(4)
    call_app(app, "POST", SUBMISSION, body=_body(0, [], log.checkpoint_text()))
    status, _, _ = call_app(app, "GET", f"{MONITORING}/{origin_hash(ORIGIN)}0123456789a")
    assert status == "404 Not Found"


def test_no_response_body_echoes_the_request(app: Any) -> None:
    """A diagnostic that quoted the request would make this endpoint a
    reflector for whatever a caller wants to put in front of somebody else's
    eyes. Every refusal here is a fixed string."""
    marker = b"MARKER-e6f1a2b3-DO-NOT-ECHO"
    for path in (SUBMISSION, f"{MONITORING}/{marker.decode()}/checkpoint"):
        _, _, body = call_app(app, "POST", path, body=b"old 0\n" + marker + b"\n\nx")
        assert marker not in body


def test_a_signing_failure_is_500_not_400(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log: FakeLog
) -> None:
    """The status a client acts on: 500 means retry, 400 means do not. A
    witness that cannot sign has not been sent a bad request."""
    from attest import witness as witness_policy

    config = WitnessConfig(
        identity=WitnessIdentity(name=WITNESS_NAME, signing_keys=witness_keys),
        server=ServerConfig(
            submission_prefix="/witness/v0",
            monitoring_prefix=MONITORING,
            max_request_bytes=65_536,
            max_proof_lines=63,
        ),
        database_path=tmp_path / "state.sqlite3",
        logs={ORIGIN: log.log_key},
    )
    broken = make_app(
        WitnessService(
            config,
            WitnessStore(config.database_path),
            clock=lambda: float(witness_policy.MAX_COSIGNATURE_TIMESTAMP + 1),
        ),
        config,
    )
    log.append(4)
    status, _, _ = call_app(broken, "POST", SUBMISSION, body=_body(0, [], log.checkpoint_text()))
    assert status == "500 Internal Server Error"
