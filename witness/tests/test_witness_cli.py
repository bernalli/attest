"""The command line: a configuration an operator can check on purpose, and a
server that actually serves.

The serve test binds a real socket on an ephemeral port and speaks real HTTP
to it. That is heavier than calling the WSGI app in-process, and it is the
point: everything else in this suite would still pass if `serve` wired the app
to nothing.
"""

from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest
from attest_witness.cli import _ThreadingWSGIServer, main
from attest_witness.config import load_config
from attest_witness.http import make_app
from attest_witness.service import WitnessService, origin_hash
from attest_witness.store import WitnessStore
from witness_support import (
    FakeLog,
    log_keys,  # noqa: F401
    log_table,
    witness_keys,  # noqa: F401
    write_config,
)

from attest import keys, pq
from tools.ci_required import ci_prerequisites_required

ORIGIN = "log.example"
TIMESTAMP = 1_700_000_000


def test_check_config_prints_the_allowlist_and_returns_zero(
    tmp_path: Path,
    witness_keys: pq.HybridSigningKeys,
    log_keys: pq.HybridSigningKeys,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
    )
    assert main(["check-config", "--config", str(config_path)]) == 0
    printed = capsys.readouterr().out
    assert ORIGIN in printed
    assert keys.b64u(witness_keys.ed.seed) not in printed
    assert keys.b64u(witness_keys.mldsa.sk) not in printed


def test_check_config_reports_a_broken_config_as_a_sentence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An operator gets a line they can act on, and a non-zero exit their
    deployment script can act on — not a traceback."""
    config_path = tmp_path / "witness.toml"
    config_path.write_text("this is not = = toml", encoding="utf-8")
    assert main(["check-config", "--config", str(config_path)]) == 2
    assert "configuration error" in capsys.readouterr().out


def test_check_config_names_a_missing_key_file_without_its_contents(
    tmp_path: Path,
    witness_keys: pq.HybridSigningKeys,
    log_keys: pq.HybridSigningKeys,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, "log.example", log_keys)],
        seed_path=str(tmp_path / "gone.seed"),
    )
    assert main(["check-config", "--config", str(config_path)]) == 2
    printed = capsys.readouterr().out
    assert "gone.seed" in printed
    assert keys.b64u(witness_keys.ed.seed) not in printed


def test_a_served_witness_answers_a_real_http_submission(
    tmp_path: Path, witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    """End to end over a socket: submit, get 200 and the signature lines back,
    then read the same note out of the monitoring endpoint."""
    log = FakeLog(ORIGIN, log_keys)
    log.append(4)
    config_path = write_config(
        tmp_path,
        witness_signing_keys=witness_keys,
        logs=[log_table(ORIGIN, ORIGIN, log_keys)],
    )
    config = load_config(config_path)
    store = WitnessStore(config.database_path)
    app = make_app(WitnessService(config, store, clock=lambda: float(TIMESTAMP)), config)

    try:
        # The THREADING server, not the plain one: a request that hangs the
        # handler would otherwise hang `shutdown()` too, turning a failing
        # test into a test that never finishes. (Measured, while mutating the
        # body reader to over-read a keep-alive socket.)
        httpd = make_server("127.0.0.1", 0, app, server_class=_ThreadingWSGIServer)
    except PermissionError:  # pragma: no cover - depends on the runner's permissions
        reason = "binding a loopback socket is not permitted for this process"
        # Same contract as the two cross-implementation gates: where a job
        # promised the environment, an absent prerequisite is that job's
        # defect and not a reason for the test to step aside. Any spelling but
        # an explicitly negative one arms it, for the reason measured there.
        if ci_prerequisites_required():
            pytest.fail(f"{reason}; the required CI gate cannot run")
        pytest.skip(f"{reason}; the test runs wherever it is")
    with httpd:
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            text = log.checkpoint_text()
            body = f"old 0\n\n{text}".encode()

            # `http.client` rather than urllib: urllib honours the proxy
            # environment, and a proxied request to a loopback test server
            # goes nowhere and times out.
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            connection.request("POST", "/witness/v0/add-checkpoint", body=body)
            response = connection.getresponse()
            assert response.status == 200
            lines = response.read().decode("utf-8")

            connection.request("GET", f"/witness/v0/monitoring/{origin_hash(ORIGIN)}/checkpoint")
            response = connection.getresponse()
            assert response.status == 200
            assert response.read().decode("utf-8") == text + lines

            connection.request("POST", "/witness/v0/add-checkpoint", body=body)
            response = connection.getresponse()
            assert response.status == 409
            assert response.getheader("Content-Type") == "text/x.tlog.size"
            assert response.read() == b"4\n"
            connection.close()
        finally:
            httpd.shutdown()
            thread.join(timeout=10)
            store.close()


def test_the_console_script_is_wired_to_the_cli() -> None:
    """The packaging claim, checked rather than assumed: `attest-witness` is
    declared as `attest_witness.cli:main` and that target has to exist."""
    metadata = json.loads(json.dumps({"script": "attest_witness.cli:main"}))
    module_path, _, attribute = metadata["script"].partition(":")
    module = __import__(module_path, fromlist=[attribute])
    assert callable(getattr(module, attribute))
